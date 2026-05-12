//! [`HintHandler`] for the [`SingleChainHost`].

use crate::{
    HintHandler, OnlineHostBackendCfg, backend::util::store_ordered_trie, kv::SharedKeyValueStore,
    single::cfg::SingleChainHost,
};
use alloy_consensus::Header;
use alloy_eips::{eip2718::Encodable2718, eip4844::FIELD_ELEMENTS_PER_BLOB};
use alloy_primitives::{Address, B256, Bytes, keccak256};
use alloy_provider::Provider;
use alloy_rlp::Decodable;
use alloy_rpc_types::{Block, debug::ExecutionWitness};
use alloy_transport::{RpcError, TransportErrorKind};
use anyhow::{Result, anyhow, ensure};
use ark_ff::{BigInteger, PrimeField};
use async_trait::async_trait;
use kona_preimage::{PreimageKey, PreimageKeyType};
use kona_proof::{Hint, HintType, l1::ROOTS_OF_UNITY};
use kona_protocol::{BlockInfo, OutputRoot, Predeploys};
use kona_providers_alloy::BlobWithCommitmentAndProof;
use op_alloy_network::Ethereum;
use op_alloy_rpc_types_engine::OpPayloadAttributes;
use tracing::{info, warn};

/// Parses a blob hint into `(hash, timestamp)`. Supports 40-byte (hash + timestamp) and
/// 48-byte legacy (hash + index + timestamp) formats; the legacy index field is ignored.
pub fn parse_blob_hint(hint_data: &[u8]) -> Result<(B256, u64)> {
    match hint_data.len() {
        48 => {
            // Legacy format: hash (32) + index (8) + timestamp (8)
            let hash_data_bytes: [u8; 32] = hint_data[0..32].try_into()?;
            let _index_data_bytes: [u8; 8] = hint_data[32..40].try_into()?; // index no longer used
            let timestamp_data_bytes: [u8; 8] = hint_data[40..48].try_into()?;

            let hash: B256 = hash_data_bytes.into();
            let timestamp = u64::from_be_bytes(timestamp_data_bytes);
            Ok((hash, timestamp))
        }
        40 => {
            // New format: hash (32) + timestamp (8)
            let hash_data_bytes: [u8; 32] = hint_data[0..32].try_into()?;
            let timestamp_data_bytes: [u8; 8] = hint_data[32..40].try_into()?;

            let hash: B256 = hash_data_bytes.into();
            let timestamp = u64::from_be_bytes(timestamp_data_bytes);
            Ok((hash, timestamp))
        }
        _ => {
            anyhow::bail!(
                "Invalid blob hint length: expected 40 or 48 bytes, got {}",
                hint_data.len()
            );
        }
    }
}

/// Returns `true` if the RPC error indicates the node does not support the requested method
/// (JSON-RPC error code -32601: Method not found).
const fn is_rpc_method_not_found(e: &RpcError<TransportErrorKind>) -> bool {
    matches!(e, RpcError::ErrorResp(p) if p.code == -32601)
}

/// The [`HintHandler`] for the [`SingleChainHost`].
#[derive(Debug, Clone, Copy)]
pub struct SingleChainHintHandler;

/// Individual hint handler functions, one per [`HintType`] variant.
pub mod hint {
    use super::*;
    use kona_providers_alloy::{OnlineBeaconClient, OnlineBlobProvider};
    use op_alloy_network::Optimism;

    /// Fetches an L1 block header by hash and stores its RLP encoding in the KV store.
    pub async fn l1_block_header(
        data: Bytes,
        l1: impl Provider<Ethereum>,
        kv: SharedKeyValueStore,
    ) -> Result<()> {
        ensure!(data.len() == 32, "Invalid hint data length");
        let hash: B256 = data.as_ref().try_into()?;
        let raw_header: Bytes = l1.client().request("debug_getRawHeader", [hash]).await?;
        let mut kv_lock = kv.write().await;
        kv_lock.set(PreimageKey::new_keccak256(*hash).into(), raw_header.into())?;
        Ok(())
    }

    /// Fetches L1 block transactions and stores them as an ordered MPT trie in the KV store.
    pub async fn l1_transactions(
        data: Bytes,
        l1: impl Provider<Ethereum>,
        kv: SharedKeyValueStore,
    ) -> Result<()> {
        ensure!(data.len() == 32, "Invalid hint data length");
        let hash: B256 = data.as_ref().try_into()?;
        let Block { transactions, .. } =
            l1.get_block_by_hash(hash).full().await?.ok_or_else(|| anyhow!("Block not found"))?;
        let encoded_transactions =
            transactions.into_transactions().map(|tx| tx.inner.encoded_2718()).collect::<Vec<_>>();
        store_ordered_trie(kv.as_ref(), encoded_transactions.as_slice()).await?;
        Ok(())
    }

    /// Fetches L1 block receipts and stores them as an ordered MPT trie in the KV store.
    pub async fn l1_receipts(
        data: Bytes,
        l1: impl Provider<Ethereum>,
        kv: SharedKeyValueStore,
    ) -> Result<()> {
        ensure!(data.len() == 32, "Invalid hint data length");
        let hash: B256 = data.as_ref().try_into()?;
        let raw_receipts: Vec<Bytes> = l1.client().request("debug_getRawReceipts", [hash]).await?;
        store_ordered_trie(kv.as_ref(), raw_receipts.as_slice()).await?;
        Ok(())
    }

    /// Fetches a blob by versioned hash and timestamp, storing the commitment, all 4096 field
    /// elements, and the KZG proof in the KV store.
    pub async fn l1_blob(
        data: Bytes,
        blobs: &OnlineBlobProvider<OnlineBeaconClient>,
        kv: SharedKeyValueStore,
    ) -> Result<()> {
        let (hash, timestamp) = parse_blob_hint(&data)?;
        let partial_block_ref = BlockInfo { timestamp, ..Default::default() };

        // Fetch the blobs from the blob provider.
        let mut fetched_blobs = blobs
            .fetch_blobs_with_proofs(&partial_block_ref, &[hash])
            .await
            .map_err(|e| anyhow!("Failed to fetch blobs with proofs: {e}"))?;
        if fetched_blobs.len() != 1 {
            anyhow::bail!("Expected 1 blob, got {}", fetched_blobs.len());
        }
        let BlobWithCommitmentAndProof { blob, kzg_proof: proof, kzg_commitment: commitment } =
            fetched_blobs.pop().expect("Expected 1 blob");

        let mut kv_lock = kv.write().await;

        // Set the preimage for the blob commitment.
        kv_lock
            .set(PreimageKey::new(*hash, PreimageKeyType::Sha256).into(), commitment.to_vec())?;

        // Write all the field elements to the key-value store. There should be 4096.
        // The preimage oracle key for each field element is the keccak256 hash of
        // `abi.encodePacked(sidecar.KZGCommitment, bytes32(ROOTS_OF_UNITY[i]))`.
        let mut blob_key = [0u8; 80];
        blob_key[..48].copy_from_slice(commitment.as_ref());
        for i in 0..FIELD_ELEMENTS_PER_BLOB {
            blob_key[48..]
                .copy_from_slice(ROOTS_OF_UNITY[i as usize].into_bigint().to_bytes_be().as_ref());
            let blob_key_hash = keccak256(blob_key.as_ref());
            kv_lock.set(PreimageKey::new_keccak256(*blob_key_hash).into(), blob_key.into())?;
            kv_lock.set(
                PreimageKey::new(*blob_key_hash, PreimageKeyType::Blob).into(),
                blob[(i as usize) << 5..(i as usize + 1) << 5].to_vec(),
            )?;
        }

        // Write the KZG Proof as the 4096th element.
        // Note: This is not associated with a root of unity, as to be backwards compatible
        // with ZK users of kona that use this proof for the overall blob.
        blob_key[72..].copy_from_slice(FIELD_ELEMENTS_PER_BLOB.to_be_bytes().as_ref());
        let blob_key_hash = keccak256(blob_key.as_ref());
        kv_lock.set(PreimageKey::new_keccak256(*blob_key_hash).into(), blob_key.into())?;
        kv_lock
            .set(PreimageKey::new(*blob_key_hash, PreimageKeyType::Blob).into(), proof.to_vec())?;
        Ok(())
    }

    /// Executes a precompile locally and stores its input and result in the KV store.
    pub async fn l1_precompile(data: Bytes, kv: SharedKeyValueStore) -> Result<()> {
        ensure!(data.len() >= 28, "Invalid hint data length");
        let address = Address::from_slice(&data.as_ref()[..20]);
        let gas = u64::from_be_bytes(data.as_ref()[20..28].try_into()?);
        let input = data[28..].to_vec();
        let input_hash = keccak256(data.as_ref());

        let result = crate::eth::execute(address, input, gas).map_or_else(
            |_| vec![0u8; 1],
            |raw_res| {
                let mut res = Vec::with_capacity(1 + raw_res.len());
                res.push(0x01);
                res.extend_from_slice(&raw_res);
                res
            },
        );

        let mut kv_lock = kv.write().await;
        kv_lock.set(PreimageKey::new_keccak256(*input_hash).into(), data.into())?;
        kv_lock.set(PreimageKey::new(*input_hash, PreimageKeyType::Precompile).into(), result)?;
        Ok(())
    }

    /// Fetches an L2 block header by hash and stores its RLP encoding in the KV store.
    pub async fn l2_block_header(
        data: Bytes,
        l2: impl Provider<Optimism>,
        kv: SharedKeyValueStore,
    ) -> Result<()> {
        ensure!(data.len() == 32, "Invalid hint data length");
        let hash: B256 = data.as_ref().try_into()?;
        let raw_header: Bytes = l2.client().request("debug_getRawHeader", [hash]).await?;
        let mut kv_lock = kv.write().await;
        kv_lock.set(PreimageKey::new_keccak256(*hash).into(), raw_header.into())?;
        Ok(())
    }

    /// Fetches L2 block transactions and stores them as an ordered MPT trie in the KV store.
    pub async fn l2_transactions(
        data: Bytes,
        l2: impl Provider<Optimism>,
        kv: SharedKeyValueStore,
    ) -> Result<()> {
        ensure!(data.len() == 32, "Invalid hint data length");
        let hash: B256 = data.as_ref().try_into()?;
        let Block { transactions, .. } =
            l2.get_block_by_hash(hash).full().await?.ok_or_else(|| anyhow!("Block not found."))?;
        let encoded_transactions = transactions
            .into_transactions()
            .map(|tx| tx.inner.inner.encoded_2718())
            .collect::<Vec<_>>();
        store_ordered_trie(kv.as_ref(), encoded_transactions.as_slice()).await?;
        Ok(())
    }

    /// Recomputes the output root from the agreed L2 head (header + `L2ToL1MessagePasser` storage),
    /// asserts it matches `agreed_l2_output_root`, then stores the encoded output root in the KV
    /// store.
    pub async fn starting_l2_output(
        data: Bytes,
        l2: impl Provider<Optimism>,
        kv: SharedKeyValueStore,
        agreed_l2_head_hash: B256,
        agreed_l2_output_root: B256,
    ) -> Result<()> {
        ensure!(data.len() == 32, "Invalid hint data length");

        let raw_header: Bytes =
            l2.client().request("debug_getRawHeader", &[agreed_l2_head_hash]).await?;
        let header = Header::decode(&mut raw_header.as_ref())?;

        let l2_to_l1_message_passer = l2
            .get_proof(Predeploys::L2_TO_L1_MESSAGE_PASSER, Default::default())
            .block_id(agreed_l2_head_hash.into())
            .await?;

        let output_root = OutputRoot::from_parts(
            header.state_root,
            l2_to_l1_message_passer.storage_hash,
            agreed_l2_head_hash,
        );
        let output_root_hash = output_root.hash();

        ensure!(output_root_hash == agreed_l2_output_root, "Output root does not match L2 head.");

        let mut kv_write_lock = kv.write().await;
        kv_write_lock.set(
            PreimageKey::new_keccak256(*output_root_hash).into(),
            output_root.encode().into(),
        )?;
        Ok(())
    }

    /// Fetches L2 contract code by code hash and stores it in the KV store.
    /// First tries with the geth hashdb scheme prefix (`b'c'`); falls back to the bare hash.
    pub async fn l2_code(
        data: Bytes,
        l2: impl Provider<Optimism>,
        kv: SharedKeyValueStore,
    ) -> Result<()> {
        // geth hashdb scheme code hash key prefix
        const CODE_PREFIX: u8 = b'c';

        ensure!(data.len() == 32, "Invalid hint data length");
        let hash: B256 = data.as_ref().try_into()?;

        let code_key = [&[CODE_PREFIX], hash.as_slice()].concat();
        let code =
            l2.client().request::<&[Bytes; 1], Bytes>("debug_dbGet", &[code_key.into()]).await;

        // If the prefixed lookup fails, retry without the geth hashdb scheme prefix.
        let code = match code {
            Ok(code) => code,
            Err(_) => l2
                .client()
                .request::<&[B256; 1], Bytes>("debug_dbGet", &[hash])
                .await
                .map_err(|e| anyhow!("Error fetching code hash preimage: {e}"))?,
        };

        let mut kv_lock = kv.write().await;
        kv_lock.set(PreimageKey::new_keccak256(*hash).into(), code.into())?;
        Ok(())
    }

    /// Fetches an L2 state trie node and stores it in the KV store.
    /// Warns on each call — this hint only appears when `debug_executePayload` returns an
    /// incomplete witness.
    pub async fn l2_state_node(
        data: Bytes,
        l2: impl Provider<Optimism>,
        kv: SharedKeyValueStore,
    ) -> Result<()> {
        ensure!(data.len() == 32, "Invalid hint data length");
        let hash: B256 = data.as_ref().try_into()?;

        warn!(target: "single_hint_handler", "L2StateNode hint was sent for node hash: {}", hash);
        warn!(
            target: "single_hint_handler",
            "`debug_executePayload` failed to return a complete witness."
        );

        let preimage: Bytes = l2.client().request("debug_dbGet", &[hash]).await?;
        let mut kv_write_lock = kv.write().await;
        kv_write_lock.set(PreimageKey::new_keccak256(*hash).into(), preimage.into())?;
        Ok(())
    }

    /// Fetches the Merkle proof for an L2 account and stores each node in the KV store.
    pub async fn l2_account_proof(
        data: Bytes,
        l2: impl Provider<Optimism>,
        kv: SharedKeyValueStore,
    ) -> Result<()> {
        ensure!(data.len() == 8 + 20, "Invalid hint data length");
        let block_number = u64::from_be_bytes(data.as_ref()[..8].try_into()?);
        let address = Address::from_slice(&data.as_ref()[8..28]);

        let proof_response =
            l2.get_proof(address, Default::default()).block_id(block_number.into()).await?;

        let mut kv_lock = kv.write().await;
        proof_response.account_proof.into_iter().try_for_each(|node| {
            let node_hash = keccak256(node.as_ref());
            kv_lock.set(PreimageKey::new_keccak256(*node_hash).into(), node.into())?;
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }

    /// Fetches the Merkle proof for an L2 account storage slot and stores each node in the KV
    /// store.
    pub async fn l2_account_storage_proof(
        data: Bytes,
        l2: impl Provider<Optimism>,
        kv: SharedKeyValueStore,
    ) -> Result<()> {
        ensure!(data.len() == 8 + 20 + 32, "Invalid hint data length");
        let block_number = u64::from_be_bytes(data.as_ref()[..8].try_into()?);
        let address = Address::from_slice(&data.as_ref()[8..28]);
        let slot = B256::from_slice(&data.as_ref()[28..]);

        let mut proof_response =
            l2.get_proof(address, vec![slot]).block_id(block_number.into()).await?;

        let mut kv_lock = kv.write().await;

        proof_response.account_proof.into_iter().try_for_each(|node| {
            let node_hash = keccak256(node.as_ref());
            kv_lock.set(PreimageKey::new_keccak256(*node_hash).into(), node.into())?;
            Ok::<(), anyhow::Error>(())
        })?;

        let storage_proof = proof_response.storage_proof.remove(0);
        storage_proof.proof.into_iter().try_for_each(|node| {
            let node_hash = keccak256(node.as_ref());
            kv_lock.set(PreimageKey::new_keccak256(*node_hash).into(), node.into())?;
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }

    /// Calls `debug_executePayload` on the L2 node and stores all returned witness preimages.
    /// No-ops if the method is not found on the node.
    pub async fn l2_payload_witness(
        data: Bytes,
        l2: impl Provider<Optimism>,
        kv: SharedKeyValueStore,
    ) -> Result<()> {
        ensure!(data.len() >= 32, "Invalid hint data length");
        let parent_block_hash = B256::from_slice(&data.as_ref()[..32]);
        let payload_attributes: OpPayloadAttributes = serde_json::from_slice(&data[32..])?;

        let execute_payload_response = match l2
            .client()
            .request::<(B256, OpPayloadAttributes), ExecutionWitness>(
                "debug_executePayload",
                (parent_block_hash, payload_attributes),
            )
            .await
        {
            Ok(response) => response,
            Err(e) => {
                info!(
                    target: "single_hint_handler",
                    err = %e,
                    method_not_found = super::is_rpc_method_not_found(&e),
                    "debug_executePayload unavailable, skipping witness preimage collection"
                );
                return Ok(());
            }
        };

        let preimages = execute_payload_response
            .state
            .into_iter()
            .chain(execute_payload_response.codes)
            .chain(execute_payload_response.keys);

        let mut kv_lock = kv.write().await;
        for preimage in preimages {
            let computed_hash = keccak256(preimage.as_ref());
            kv_lock.set(PreimageKey::new_keccak256(*computed_hash).into(), preimage.into())?;
        }
        Ok(())
    }
}

#[async_trait]
impl HintHandler for SingleChainHintHandler {
    type Cfg = SingleChainHost;

    async fn fetch_hint(
        hint: Hint<<Self::Cfg as OnlineHostBackendCfg>::HintType>,
        cfg: &Self::Cfg,
        providers: &<Self::Cfg as OnlineHostBackendCfg>::Providers,
        kv: SharedKeyValueStore,
    ) -> Result<()> {
        match hint.ty {
            HintType::L1BlockHeader => hint::l1_block_header(hint.data, &providers.l1, kv).await?,
            HintType::L1Transactions => hint::l1_transactions(hint.data, &providers.l1, kv).await?,
            HintType::L1Receipts => hint::l1_receipts(hint.data, &providers.l1, kv).await?,
            HintType::L1Blob => hint::l1_blob(hint.data, &providers.blobs, kv).await?,
            HintType::L1Precompile => hint::l1_precompile(hint.data, kv).await?,
            HintType::L2BlockHeader => hint::l2_block_header(hint.data, &providers.l2, kv).await?,
            HintType::L2Transactions => hint::l2_transactions(hint.data, &providers.l2, kv).await?,
            HintType::StartingL2Output => {
                hint::starting_l2_output(
                    hint.data,
                    &providers.l2,
                    kv,
                    cfg.agreed_l2_head_hash,
                    cfg.agreed_l2_output_root,
                )
                .await?
            }
            HintType::L2Code => hint::l2_code(hint.data, &providers.l2, kv).await?,
            HintType::L2StateNode => hint::l2_state_node(hint.data, &providers.l2, kv).await?,
            HintType::L2AccountProof => {
                hint::l2_account_proof(hint.data, &providers.l2, kv).await?
            }
            HintType::L2AccountStorageProof => {
                hint::l2_account_storage_proof(hint.data, &providers.l2, kv).await?
            }
            HintType::L2PayloadWitness => {
                if !cfg.enable_experimental_witness_endpoint {
                    warn!(
                        target: "single_hint_handler",
                        "L2PayloadWitness hint was sent, but payload witness is disabled. Skipping hint."
                    );
                    return Ok(());
                }
                hint::l2_payload_witness(hint.data, &providers.l2, kv).await?
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_json_rpc::ErrorPayload;
    use alloy_transport::TransportErrorKind;

    #[test]
    fn test_is_rpc_method_not_found_true() {
        let e = RpcError::<TransportErrorKind>::ErrorResp(ErrorPayload {
            code: -32601,
            message: "method not found".into(),
            data: None,
        });
        assert!(is_rpc_method_not_found(&e));
    }

    #[test]
    fn test_is_rpc_method_not_found_false_wrong_code() {
        let e = RpcError::<TransportErrorKind>::ErrorResp(ErrorPayload {
            code: -32600,
            message: "invalid request".into(),
            data: None,
        });
        assert!(!is_rpc_method_not_found(&e));
    }

    #[test]
    fn test_is_rpc_method_not_found_false_null_resp() {
        let e = RpcError::<TransportErrorKind>::NullResp;
        assert!(!is_rpc_method_not_found(&e));
    }

    const TEST_HASH: B256 = B256::new([0x42u8; 32]);
    const TEST_TIMESTAMP: u64 = 1234567890;

    // Legacy format: hash (32 bytes) + index (8 bytes) + timestamp (8 bytes) = 48 bytes
    const LEGACY_HINT: [u8; 48] = [
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, // Hash (32 bytes):
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFA, 0xCA, // Index (8 bytes, ignored)
        0x00, 0x00, 0x00, 0x00, 0x49, 0x96, 0x02, 0xD2, // Timestamp (8 bytes): 1234567890
    ];

    // New format: hash (32 bytes) + timestamp (8 bytes) = 40 bytes
    const NEW_HINT: [u8; 40] = [
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, // Hash (32 bytes)
        0x00, 0x00, 0x00, 0x00, 0x49, 0x96, 0x02, 0xD2, // Timestamp (8 bytes): 1234567890
    ];

    #[test]
    fn test_parse_blob_hint_formats() {
        let (legacy_hash, legacy_timestamp) = parse_blob_hint(&LEGACY_HINT).unwrap();
        let (new_hash, new_timestamp) = parse_blob_hint(&NEW_HINT).unwrap();

        assert_eq!(legacy_hash, TEST_HASH);
        assert_eq!(legacy_timestamp, TEST_TIMESTAMP);
        assert_eq!(new_hash, TEST_HASH);
        assert_eq!(new_timestamp, TEST_TIMESTAMP);
    }

    #[test]
    fn test_parse_blob_hint_invalid_length() {
        let hint_data = vec![0u8; 35];
        let result = parse_blob_hint(&hint_data);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Invalid blob hint length"));
        assert!(err_msg.contains("expected 40 or 48 bytes"));
        assert!(err_msg.contains("got 35"));
    }
}
