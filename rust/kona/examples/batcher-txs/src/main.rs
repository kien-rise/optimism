//! Scans a range of L1 blocks for OP Stack batcher transactions and decodes
//! them to show which L2 block range each batch covers.
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
//! This tool wires up a partial kona derivation pipeline to decode batches from
//! L1 batcher transactions without requiring an L2 node or attributes builder:
//!
//! ```text
//! PollingTraversal → L1Retrieval → FrameQueue → ChannelProvider → ChannelReader
//! ```
//!
//! The pipeline is driven by repeatedly calling `next_batch()` on the
//! `ChannelReader` and advancing the L1 origin whenever the current block's
//! data is exhausted.  Each complete channel is decompressed and decoded into
//! one or more batches; from each batch's timestamp(s) the corresponding L2
//! block number(s) are derived using the rollup genesis config.
//!
//! Blob transactions (EIP-4844) carry their payload in blobs, not calldata.
//! `CalldataSource` extracts the calldata portion of blob transactions, so
//! pre-Ecotone calldata-only batcher txs are handled.  Post-Ecotone blob
//! batcher txs will yield empty calldata and are effectively skipped.

#![warn(unused_crate_dependencies)]

use std::sync::Arc;

use anyhow::{Context as _, anyhow};
use clap::Parser;
use kona_derive::{
    BatchStreamProvider, CalldataSource, ChannelProvider, ChannelReader, ChainProvider,
    FrameQueue, L1Retrieval, OriginAdvancer, OriginProvider, PipelineErrorKind, PollingTraversal,
};
use kona_genesis::SystemConfig;
use kona_protocol::Batch;
use kona_providers_alloy::AlloyChainProvider;
use kona_registry::ROLLUP_CONFIGS;

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

/// Compute the L2 block number for a given L2 timestamp.
///
/// Returns `None` if the timestamp predates genesis or is not aligned to a
/// block boundary.
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

/// Print a human-readable summary of the L2 coverage of a decoded batch.
fn print_batch(
    batch: &Batch,
    l1_block: u64,
    genesis_l2_num: u64,
    genesis_l2_ts: u64,
    block_time: u64,
) {
    match batch {
        Batch::Single(sb) => {
            match timestamp_to_l2_block(sb.timestamp, genesis_l2_num, genesis_l2_ts, block_time) {
                Some(num) => println!(
                    "L1 {l1_block}: single batch → L2 block {num} (ts {}, epoch {})",
                    sb.timestamp, sb.epoch_num,
                ),
                None => println!(
                    "L1 {l1_block}: single batch, timestamp {} (L2 block unknown)",
                    sb.timestamp,
                ),
            }
        }
        Batch::Span(span) => {
            let start_ts = span.starting_timestamp();
            let end_ts = span.final_timestamp();
            let count = span.batches.len();
            let start_l2 =
                timestamp_to_l2_block(start_ts, genesis_l2_num, genesis_l2_ts, block_time);
            let end_l2 =
                timestamp_to_l2_block(end_ts, genesis_l2_num, genesis_l2_ts, block_time);
            match (start_l2, end_l2) {
                (Some(s), Some(e)) => println!(
                    "L1 {l1_block}: span batch → L2 blocks {s}–{e} ({count} blocks, ts {start_ts}–{end_ts})",
                ),
                _ => println!(
                    "L1 {l1_block}: span batch, {count} blocks, ts {start_ts}–{end_ts} (L2 blocks unknown)",
                ),
            }
        }
    }
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
    let cfg = Arc::new(cfg.clone());

    let genesis_l2_num = cfg.genesis.l2.number;
    let genesis_l2_ts = cfg.genesis.l2_time;
    let block_time = cfg.block_time;

    let system_config: SystemConfig = cfg
        .genesis
        .system_config
        .ok_or_else(|| anyhow!("chain {} has no genesis system config", args.chain_id))?;

    println!(
        "Scanning L1 blocks {}..={} for chain {} (block time {}s)",
        args.l1_start, args.l1_end, args.chain_id, block_time,
    );
    println!("  Batch inbox:   {}", cfg.batch_inbox_address);
    println!("  Batcher addr:  {}", system_config.batcher_address);
    println!("  L2 genesis:    block {genesis_l2_num}, timestamp {genesis_l2_ts}");
    println!();

    let url = args
        .l1_rpc
        .parse::<alloy_transport_http::reqwest::Url>()
        .context("invalid L1 RPC URL")?;

    let mut chain_provider = AlloyChainProvider::new_http(url, 128);

    // Fetch the BlockInfo for the starting L1 block to seed the traversal stage.
    let start_block = chain_provider
        .block_info_by_number(args.l1_start)
        .await
        .with_context(|| format!("failed to fetch L1 block {}", args.l1_start))?;

    // Build the stage chain (bottom to top):
    //   PollingTraversal → L1Retrieval(CalldataSource) → FrameQueue → ChannelProvider → ChannelReader
    //
    // Two separate AlloyChainProvider instances are needed because PollingTraversal
    // and CalldataSource each need exclusive mutable access to a provider.
    let mut traversal = PollingTraversal::new(chain_provider.clone(), Arc::clone(&cfg));
    traversal.block = Some(start_block);
    // Seed the batcher address so CalldataSource filters correctly.
    traversal.system_config = system_config;

    let calldata_source = CalldataSource::new(chain_provider, cfg.batch_inbox_address);
    let l1_retrieval = L1Retrieval::new(traversal, calldata_source);
    let frame_queue = FrameQueue::new(l1_retrieval, Arc::clone(&cfg));
    let channel_provider = ChannelProvider::new(Arc::clone(&cfg), frame_queue);
    let mut channel_reader = ChannelReader::new(channel_provider, Arc::clone(&cfg));

    // Drive the pipeline: pull batches and advance the L1 origin on exhaustion.
    loop {
        match channel_reader.next_batch().await {
            Ok(batch) => {
                let l1_num = channel_reader.origin().map(|b| b.number).unwrap_or(0);
                print_batch(&batch, l1_num, genesis_l2_num, genesis_l2_ts, block_time);
            }
            Err(PipelineErrorKind::Critical(e)) => {
                return Err(anyhow!("critical pipeline error: {e:?}"));
            }
            Err(_) => {
                // Temporary or reset error: no more data at the current L1 origin.
                // If we've already scanned the last block in range, we're done.
                let current =
                    channel_reader.origin().map(|b| b.number).unwrap_or(args.l1_start);
                if current >= args.l1_end {
                    break;
                }
                if let Err(e) = channel_reader.advance_origin().await {
                    eprintln!("advance_origin failed at L1 block {current}: {e:?}");
                    break;
                }
            }
        }
    }

    Ok(())
}
