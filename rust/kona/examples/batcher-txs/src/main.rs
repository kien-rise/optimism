//! Scans a range of L1 blocks for OP Stack batcher transactions and decodes
//! them to show which L2 block range each batcher transaction covers.
//!
//! # Usage
//!
//! ```sh
//! cargo run -p example-batcher-txs -- \
//!   --l1-rpc https://mainnet.infura.io/v3/<key> \
//!   --l1-start 21000000 \
//!   --l1-end 21000010 \
//!   --chain-id 10
//! ```
//!
//! # How it works
//!
//! Batcher transactions carry compressed L2 batch data to L1.  The data is
//! split into **frames**, which are collected into **channels**, which are then
//! decompressed to yield one or more **batches**.  Each batch specifies the
//! timestamp of one or more L2 blocks, from which the block numbers can be
//! derived using the rollup config's genesis information.
//!
//! A single channel may span several batcher transactions across several L1
//! blocks, so this tool accumulates frames as it scans and reports the L2
//! block range once a channel is complete.
//!
//! Blob transactions (EIP-4844) are detected and skipped because decoding
//! their payload requires a beacon-chain API not available here.

#![warn(unused_crate_dependencies)]

use std::collections::HashMap;

use alloy_consensus::Transaction as TxTrait;
use alloy_network_primitives::{BlockTransactions, TransactionResponse};
use alloy_primitives::{Address, B256, hex};
use alloy_provider::{Provider, RootProvider};
use alloy_transport_http::reqwest;
use anyhow::{Context as _, anyhow};
use clap::Parser;
use kona_genesis::{MAX_RLP_BYTES_PER_CHANNEL_BEDROCK, MAX_RLP_BYTES_PER_CHANNEL_FJORD};
use kona_protocol::{Batch, BatchReader, ChannelId, Frame};
use kona_registry::ROLLUP_CONFIGS;

/// Accumulates frames from multiple batcher transactions until the channel is
/// complete and can be decoded.
struct Channel {
    id: ChannelId,
    /// Map from frame number to frame data bytes.
    frames: HashMap<u16, Vec<u8>>,
    /// The frame number marked as last, once we have seen it.
    last_frame_num: Option<u16>,
    /// All (l1_block_number, tx_hash) pairs that contributed frames to this
    /// channel, in order of first appearance.
    contributors: Vec<(u64, B256)>,
}

impl Channel {
    fn new(id: ChannelId) -> Self {
        Self { id, frames: HashMap::new(), last_frame_num: None, contributors: Vec::new() }
    }

    fn add_frame(&mut self, frame: Frame, l1_block: u64, tx_hash: B256) {
        if !self.contributors.iter().any(|(_, h)| h == &tx_hash) {
            self.contributors.push((l1_block, tx_hash));
        }
        if frame.is_last {
            self.last_frame_num = Some(frame.number);
        }
        self.frames.insert(frame.number, frame.data);
    }

    /// Returns true once we have every frame 0..=last_frame_num.
    fn is_complete(&self) -> bool {
        self.last_frame_num
            .is_some_and(|last| self.frames.len() == last as usize + 1)
    }

    /// Concatenate frames in order to get the raw compressed channel data.
    /// Returns None if any frame is missing.
    fn assemble(&self) -> Option<Vec<u8>> {
        let last = self.last_frame_num?;
        let mut data = Vec::new();
        for i in 0..=last {
            data.extend_from_slice(self.frames.get(&i)?);
        }
        Some(data)
    }
}

/// Compute the L2 block number for a given L2 timestamp using the rollup
/// genesis config.  Returns None if the timestamp predates genesis or is not
/// aligned to block boundaries.
fn timestamp_to_l2_block(
    timestamp: u64,
    genesis_l2_num: u64,
    genesis_l2_ts: u64,
    block_time: u64,
) -> Option<u64> {
    let delta = timestamp.checked_sub(genesis_l2_ts)?;
    if block_time == 0 || delta % block_time != 0 {
        return None;
    }
    Some(genesis_l2_num + delta / block_time)
}

/// Decode all batches from a complete channel's assembled data and return a
/// human-readable summary of the L2 block range they cover.
fn decode_channel(
    data: Vec<u8>,
    cfg: &kona_genesis::RollupConfig,
    genesis_l2_num: u64,
    genesis_l2_ts: u64,
    block_time: u64,
) -> (u64, u64) {
    // Use the larger Fjord limit unconditionally.  For older blocks the data
    // will decompress to less than the Bedrock limit anyway; using the larger
    // ceiling just means we accept channels that predate Fjord too.
    let max_rlp = MAX_RLP_BYTES_PER_CHANNEL_FJORD as usize;
    let _ = MAX_RLP_BYTES_PER_CHANNEL_BEDROCK; // keep the import used

    let mut reader = BatchReader::new(data, max_rlp);
    let mut batch_idx = 0u32;
    let mut first_l2 = u64::MAX;
    let mut last_l2 = 0u64;

    while let Some(batch) = reader.next_batch(cfg) {
        batch_idx += 1;
        match &batch {
            Batch::Single(sb) => {
                match timestamp_to_l2_block(sb.timestamp, genesis_l2_num, genesis_l2_ts, block_time) {
                    Some(num) => {
                        println!(
                            "    Batch #{batch_idx} (single): L2 block {num} \
                             (ts {}, L1 epoch {})",
                            sb.timestamp, sb.epoch_num
                        );
                        first_l2 = first_l2.min(num);
                        last_l2 = last_l2.max(num);
                    }
                    None => {
                        println!(
                            "    Batch #{batch_idx} (single): timestamp {} \
                             (cannot derive L2 block number)",
                            sb.timestamp
                        );
                    }
                }
            }
            Batch::Span(span) => {
                let start_ts = span.starting_timestamp();
                let end_ts = span.final_timestamp();
                let count = span.batches.len();
                let start_l2 = timestamp_to_l2_block(start_ts, genesis_l2_num, genesis_l2_ts, block_time);
                let end_l2 = timestamp_to_l2_block(end_ts, genesis_l2_num, genesis_l2_ts, block_time);
                match (start_l2, end_l2) {
                    (Some(s), Some(e)) => {
                        println!(
                            "    Batch #{batch_idx} (span): L2 blocks {s}–{e} \
                             ({count} blocks, ts {start_ts}–{end_ts})"
                        );
                        first_l2 = first_l2.min(s);
                        last_l2 = last_l2.max(e);
                    }
                    _ => {
                        println!(
                            "    Batch #{batch_idx} (span): {count} blocks, \
                             ts {start_ts}–{end_ts} (cannot derive L2 block numbers)"
                        );
                    }
                }
            }
        }
    }

    if batch_idx == 0 {
        println!("    [warning] no batches decoded from this channel");
    }

    (first_l2, last_l2)
}

#[derive(Parser, Debug)]
#[command(
    name = "batcher-txs",
    about = "Scan L1 blocks for OP Stack batcher transactions and show L2 coverage"
)]
struct Args {
    /// L1 Ethereum RPC URL (HTTP or HTTPS)
    #[arg(long, env = "L1_RPC_URL")]
    l1_rpc: String,

    /// First L1 block number to scan (inclusive)
    #[arg(long)]
    l1_start: u64,

    /// Last L1 block number to scan (inclusive)
    #[arg(long)]
    l1_end: u64,

    /// L2 chain ID (10 = OP Mainnet, 8453 = Base, etc.)
    #[arg(long, default_value = "10")]
    chain_id: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("example_batcher_txs=info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();

    let cfg = ROLLUP_CONFIGS.get(&args.chain_id).with_context(|| {
        format!(
            "unknown chain ID {}; supported IDs: {:?}",
            args.chain_id,
            {
                let mut ids: Vec<u64> = ROLLUP_CONFIGS.keys().copied().collect();
                ids.sort_unstable();
                ids
            }
        )
    })?;

    let genesis_l2_num = cfg.genesis.l2.number;
    let genesis_l2_ts = cfg.genesis.l2_time;
    let block_time = cfg.block_time;
    let batch_inbox = cfg.batch_inbox_address;
    let batcher_addr: Option<Address> = cfg.genesis.system_config.map(|sc| sc.batcher_address);

    println!(
        "Scanning L1 blocks {}..={} for chain {} (block time {}s)",
        args.l1_start, args.l1_end, args.chain_id, block_time
    );
    println!("  Batch inbox:  {batch_inbox}");
    match batcher_addr {
        Some(addr) => println!("  Batcher addr: {addr}"),
        None => println!("  Batcher addr: unknown (filtering by batch inbox only)"),
    }
    println!("  L2 genesis:   block {genesis_l2_num}, timestamp {genesis_l2_ts}");
    println!();

    let url = args.l1_rpc.parse::<reqwest::Url>().context("invalid L1 RPC URL")?;
    let provider: RootProvider = RootProvider::new_http(url);

    // Channel bank: accumulates frames from batcher txs until a channel is
    // complete.  Uses ChannelId ([u8; 16]) as key.
    let mut channel_bank: HashMap<ChannelId, Channel> = HashMap::new();

    for block_num in args.l1_start..=args.l1_end {
        let block = provider
            .get_block_by_number(block_num.into())
            .full()
            .await
            .with_context(|| format!("RPC call failed for block {block_num}"))?
            .with_context(|| format!("L1 block {block_num} not found"))?;

        let BlockTransactions::Full(txs) = block.transactions else {
            anyhow::bail!("expected full transactions for block {block_num}");
        };

        // Filter to batcher transactions: `to` must be the batch inbox address.
        // If we know the batcher address, also check `from`.
        let batcher_txs: Vec<_> = txs
            .iter()
            .filter(|tx| {
                tx.to() == Some(batch_inbox)
                    && batcher_addr.map_or(true, |b| tx.from() == b)
            })
            .collect();

        if batcher_txs.is_empty() {
            continue;
        }

        println!("=== L1 block {block_num} ({} batcher tx(s)) ===", batcher_txs.len());

        // Channels that became complete while processing this L1 block.
        let mut newly_complete: Vec<ChannelId> = Vec::new();

        for tx in &batcher_txs {
            let tx_hash = tx.tx_hash();
            let input = tx.input();

            // EIP-4844 blob transactions carry their data in blobs, not calldata.
            // Decoding blobs requires a beacon-chain RPC, which is not available
            // here, so we skip them with an informational message.
            if tx.ty() == 3 {
                println!(
                    "  TX {}: blob transaction — blob data decoding not supported",
                    &hex::encode_prefixed(tx_hash)[..12]
                );
                continue;
            }

            let frames = match Frame::parse_frames(input) {
                Ok(f) => f,
                Err(e) => {
                    println!(
                        "  TX {}: failed to parse frames: {e}",
                        &hex::encode_prefixed(tx_hash)[..12]
                    );
                    continue;
                }
            };

            // Summarise which channels and frames this tx carries.
            // In practice a tx usually carries frames for a single channel.
            let frame_summary = frames
                .iter()
                .map(|f| {
                    let last = if f.is_last { "*" } else { "" };
                    format!("{}{}", f.number, last)
                })
                .collect::<Vec<_>>()
                .join(", ");

            // Collect distinct channel IDs from this tx's frames.
            let mut channel_ids: Vec<ChannelId> = Vec::new();
            for f in &frames {
                if !channel_ids.contains(&f.id) {
                    channel_ids.push(f.id);
                }
            }
            let chan_ids_str = channel_ids
                .iter()
                .map(|id| format!("[{}…{}]", hex::encode(&id[..2]), hex::encode(&id[14..])))
                .collect::<Vec<_>>()
                .join(", ");

            println!(
                "  TX {}: {} frame(s) [{}] -> channel(s) {}",
                &hex::encode_prefixed(tx_hash)[..12],
                frames.len(),
                frame_summary,
                chan_ids_str,
            );

            // Add frames to the channel bank.
            for frame in frames {
                let channel = channel_bank
                    .entry(frame.id)
                    .or_insert_with(|| Channel::new(frame.id));
                channel.add_frame(frame, block_num, tx_hash);
                if channel.is_complete() && !newly_complete.contains(&channel.id) {
                    newly_complete.push(channel.id);
                }
            }
        }

        // Report and decode any channels that completed in this block.
        for channel_id in newly_complete {
            let channel = channel_bank.remove(&channel_id).expect("just inserted");
            let id_str = format!(
                "[{}…{}]",
                hex::encode(&channel_id[..2]),
                hex::encode(&channel_id[14..])
            );

            println!();
            println!("  Channel {id_str} complete ({} contributing tx(s)):", channel.contributors.len());
            for (l1_num, tx_hash) in &channel.contributors {
                println!(
                    "    L1 block {l1_num}, TX {}",
                    &hex::encode_prefixed(tx_hash)[..12]
                );
            }

            match channel.assemble() {
                None => println!("    [error] could not assemble channel data (missing frames)"),
                Some(data) => {
                    let (first_l2, last_l2) =
                        decode_channel(data, cfg, genesis_l2_num, genesis_l2_ts, block_time);

                    if first_l2 != u64::MAX && last_l2 >= first_l2 {
                        let count = last_l2 - first_l2 + 1;
                        println!(
                            "  => L2 blocks {first_l2}–{last_l2} ({count} block(s))"
                        );
                    }
                }
            }
            println!();
        }
    }

    if channel_bank.is_empty() {
        println!("Scan complete. All channels fully decoded.");
    } else {
        println!(
            "Scan complete. {} channel(s) still incomplete \
             (frames span beyond the scanned L1 range).",
            channel_bank.len()
        );
    }

    Ok(())
}
