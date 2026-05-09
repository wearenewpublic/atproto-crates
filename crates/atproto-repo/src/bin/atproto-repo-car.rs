//! CAR file operations CLI tool.
//!
//! Provides commands for inspecting and manipulating CAR files.
//!
//! # Usage
//!
//! ```bash
//! # List blocks in a CAR file
//! atproto-repo-car ls repo.car
//!
//! # Show root CIDs
//! atproto-repo-car roots repo.car
//!
//! # Extract a specific block
//! atproto-repo-car get repo.car <cid>
//!
//! # Verify CAR file integrity
//! atproto-repo-car verify repo.car
//! ```

use anyhow::Result;
use atproto_repo::CarReader;
use atproto_repo::RepoConfig;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tokio::fs::File;

#[derive(Parser)]
#[command(
    name = "atproto-repo-car",
    version,
    about = "CAR file operations",
    long_about = "Inspect and manipulate Content Addressable aRchive (CAR) files used by AT Protocol."
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List blocks in a CAR file
    Ls {
        /// Path to CAR file
        path: PathBuf,

        /// Show block sizes
        #[arg(long)]
        size: bool,

        /// Show only first N blocks
        #[arg(long, short = 'n')]
        limit: Option<usize>,
    },

    /// Show CAR file roots
    Roots {
        /// Path to CAR file
        path: PathBuf,
    },

    /// Extract a specific block by CID
    Get {
        /// Path to CAR file
        path: PathBuf,

        /// CID of block to extract
        cid: String,

        /// Output file (stdout if not specified)
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },

    /// Verify CAR file integrity
    Verify {
        /// Path to CAR file
        path: PathBuf,

        /// Skip CID verification
        #[arg(long)]
        no_verify_cids: bool,
    },

    /// Show CAR file statistics
    Stats {
        /// Path to CAR file
        path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Ls { path, size, limit } => cmd_ls(&path, size, limit).await,
        Command::Roots { path } => cmd_roots(&path).await,
        Command::Get { path, cid, output } => cmd_get(&path, &cid, output).await,
        Command::Verify {
            path,
            no_verify_cids,
        } => cmd_verify(&path, !no_verify_cids).await,
        Command::Stats { path } => cmd_stats(&path).await,
    }
}

async fn cmd_ls(path: &PathBuf, show_size: bool, limit: Option<usize>) -> Result<()> {
    let file = File::open(path).await?;
    let mut reader = CarReader::new(file).await?;

    let mut count = 0;
    while let Some(block) = reader.next_block().await? {
        if let Some(max) = limit
            && count >= max
        {
            break;
        }

        if show_size {
            println!("{}\t{}", block.cid, block.data.len());
        } else {
            println!("{}", block.cid);
        }

        count += 1;
    }

    Ok(())
}

async fn cmd_roots(path: &PathBuf) -> Result<()> {
    let file = File::open(path).await?;
    let reader = CarReader::new(file).await?;

    for root in reader.roots() {
        println!("{}", root);
    }

    Ok(())
}

async fn cmd_get(path: &PathBuf, cid_str: &str, output: Option<PathBuf>) -> Result<()> {
    use std::io::Write;

    let target_cid: cid::Cid = cid_str.parse()?;

    let file = File::open(path).await?;
    let mut reader = CarReader::new(file).await?;

    while let Some(block) = reader.next_block().await? {
        if block.cid == target_cid {
            match output {
                Some(out_path) => {
                    tokio::fs::write(&out_path, &block.data).await?;
                    eprintln!("Wrote {} bytes to {:?}", block.data.len(), out_path);
                }
                None => {
                    std::io::stdout().write_all(&block.data)?;
                }
            }
            return Ok(());
        }
    }

    anyhow::bail!("Block not found: {}", cid_str);
}

async fn cmd_verify(path: &PathBuf, verify_cids: bool) -> Result<()> {
    let config = if verify_cids {
        RepoConfig::default()
    } else {
        RepoConfig::no_verification()
    };

    let file = File::open(path).await?;
    let mut reader = CarReader::with_config(file, config.into()).await?;

    let mut count = 0;
    let mut total_bytes = 0u64;

    while let Some(block) = reader.next_block().await? {
        count += 1;
        total_bytes += block.data.len() as u64;
    }

    println!("CAR file is valid");
    println!("  Blocks: {}", count);
    println!("  Total data: {} bytes", total_bytes);
    println!("  Roots: {}", reader.header().roots.len());

    if verify_cids {
        println!("  CID verification: enabled");
    } else {
        println!("  CID verification: disabled");
    }

    Ok(())
}

async fn cmd_stats(path: &PathBuf) -> Result<()> {
    let file = File::open(path).await?;
    let mut reader = CarReader::new(file).await?;

    let mut count = 0;
    let mut total_bytes = 0u64;
    let mut min_size = usize::MAX;
    let mut max_size = 0usize;

    while let Some(block) = reader.next_block().await? {
        count += 1;
        let size = block.data.len();
        total_bytes += size as u64;
        min_size = min_size.min(size);
        max_size = max_size.max(size);
    }

    println!("CAR Statistics:");
    println!("  File: {:?}", path);
    println!("  Roots: {}", reader.header().roots.len());
    println!("  Blocks: {}", count);
    println!("  Total data: {} bytes", total_bytes);

    if count > 0 {
        println!("  Avg block size: {} bytes", total_bytes / count as u64);
        println!("  Min block size: {} bytes", min_size);
        println!("  Max block size: {} bytes", max_size);
    }

    Ok(())
}
