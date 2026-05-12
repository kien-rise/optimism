//! Sync Start

use crate::errors::OracleProviderError;
use alloc::sync::Arc;
use alloy_consensus::{Header, Sealed};
use alloy_primitives::B256;
use core::fmt::Debug;
use kona_derive::ChainProvider;
use kona_driver::{PipelineCursor, TipCursor};
use kona_protocol::BatchValidationProvider;
use kona_registry::RollupConfig;
use spin::RwLock;

/// Constructs a [`PipelineCursor`] from the caching oracle, boot info, and providers.
pub async fn new_oracle_pipeline_cursor<L1, L2>(
    rollup_config: &RollupConfig,
    safe_header: Sealed<Header>,
    agreed_l2_output_root: B256,
    chain_provider: &mut L1,
    l2_chain_provider: &mut L2,
) -> Result<Arc<RwLock<PipelineCursor>>, OracleProviderError>
where
    L1: ChainProvider + Send + Sync + Debug + Clone,
    L2: BatchValidationProvider + Send + Sync + Debug + Clone,
    OracleProviderError:
        From<<L1 as ChainProvider>::Error> + From<<L2 as BatchValidationProvider>::Error>,
{
    // Fetches L2 block info + parses the L1 info deposit tx inside the block body — multiple
    // oracle reads in sequence, likely the most expensive step.
    tracing::debug!(target: "sync", l2_block_number = safe_header.number, "fetching l2 block info");
    let safe_head_info = l2_chain_provider.l2_block_info_by_number(safe_header.number).await?;
    tracing::debug!(target: "sync", l1_origin_number = safe_head_info.l1_origin.number, "l2 block info fetched");

    tracing::debug!(target: "sync", l1_block_number = safe_head_info.l1_origin.number, "fetching l1 origin block info");
    let l1_origin = chain_provider.block_info_by_number(safe_head_info.l1_origin.number).await?;
    tracing::debug!(target: "sync", ?l1_origin, "l1 origin block info fetched");

    // Walk back the starting L1 block by `channel_timeout` to ensure that the full channel is
    // captured.
    let channel_timeout = rollup_config.channel_timeout(safe_head_info.block_info.timestamp);
    let mut l1_origin_number = l1_origin.number.saturating_sub(channel_timeout);
    if l1_origin_number < rollup_config.genesis.l1.number {
        l1_origin_number = rollup_config.genesis.l1.number;
    }
    tracing::debug!(
        target: "sync",
        l1_origin_number,
        channel_timeout,
        "fetching channel-timeout-adjusted l1 origin"
    );
    let origin = chain_provider.block_info_by_number(l1_origin_number).await?;
    tracing::debug!(target: "sync", ?origin, "channel-timeout-adjusted l1 origin fetched");

    // Construct the cursor.
    let mut cursor = PipelineCursor::new(channel_timeout, origin);
    let tip = TipCursor::new(safe_head_info, safe_header, agreed_l2_output_root);
    cursor.advance(origin, tip);

    // Wrap the cursor in a shared read-write lock
    Ok(Arc::new(RwLock::new(cursor)))
}
