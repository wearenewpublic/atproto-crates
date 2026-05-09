//! MST inspection and operations CLI tool.
//!
//! Provides commands for inspecting Merkle Search Trees in AT Protocol repositories.
//!
//! # Usage
//!
//! ```bash
//! # List all keys in an MST
//! atproto-repo-mst ls repo.car
//!
//! # Get value for a specific key
//! atproto-repo-mst get repo.car "app.bsky.feed.post/abc123"
//!
//! # Show MST structure
//! atproto-repo-mst tree repo.car
//!
//! # Calculate height for a key
//! atproto-repo-mst height "app.bsky.feed.post/abc123"
//! ```

use anyhow::Result;
use atproto_repo::RepoConfig;
use atproto_repo::mst::key_height;
use atproto_repo::repo::MemoryRepository;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tokio::fs::File;

#[derive(Parser)]
#[command(
    name = "atproto-repo-mst",
    version,
    about = "MST inspection and operations",
    long_about = "Inspect Merkle Search Trees (MST) in AT Protocol repositories."
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List all keys in an MST
    Ls {
        /// Path to CAR file containing repository
        path: PathBuf,

        /// Filter by collection prefix
        #[arg(long)]
        collection: Option<String>,

        /// Show only first N keys
        #[arg(long, short = 'n')]
        limit: Option<usize>,
    },

    /// Get value CID for a specific key
    Get {
        /// Path to CAR file
        path: PathBuf,

        /// Key to look up (collection/rkey)
        key: String,
    },

    /// Show MST structure
    Tree {
        /// Path to CAR file
        path: PathBuf,

        /// Maximum depth to display
        #[arg(long, default_value = "3")]
        depth: usize,
    },

    /// Calculate height for a key
    Height {
        /// Key to calculate height for
        key: String,
    },

    /// Show repository information
    Info {
        /// Path to CAR file
        path: PathBuf,
    },

    /// List collections in the repository
    Collections {
        /// Path to CAR file
        path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Ls {
            path,
            collection,
            limit,
        } => cmd_ls(&path, collection, limit).await,
        Command::Get { path, key } => cmd_get(&path, &key).await,
        Command::Tree { path, depth } => cmd_tree(&path, depth).await,
        Command::Height { key } => cmd_height(&key),
        Command::Info { path } => cmd_info(&path).await,
        Command::Collections { path } => cmd_collections(&path).await,
    }
}

async fn cmd_ls(path: &PathBuf, collection: Option<String>, limit: Option<usize>) -> Result<()> {
    let file = File::open(path).await?;
    let config = RepoConfig::no_verification();
    let repo = MemoryRepository::from_car(file, config).await?;

    let entries = match collection {
        Some(coll) => repo.list_collection(&coll).await?,
        None => {
            let all_entries = repo.mst().entries().await?;
            all_entries
                .into_iter()
                .filter_map(|(key, cid)| {
                    atproto_repo::RecordPath::from_mst_key(&key)
                        .ok()
                        .map(|path| (path, cid))
                })
                .collect()
        }
    };

    for (count, (path, cid)) in entries.into_iter().enumerate() {
        if let Some(max) = limit
            && count >= max
        {
            break;
        }
        println!("{}\t{}", path, cid);
    }
    Ok(())
}

async fn cmd_get(path: &PathBuf, key: &str) -> Result<()> {
    let file = File::open(path).await?;
    let config = RepoConfig::no_verification();
    let repo = MemoryRepository::from_car(file, config).await?;

    let cid = repo.mst().get(key).await?;

    match cid {
        Some(c) => println!("{}", c),
        None => anyhow::bail!("Key not found: {}", key),
    }

    Ok(())
}

async fn cmd_tree(path: &PathBuf, _max_depth: usize) -> Result<()> {
    let file = File::open(path).await?;
    let config = RepoConfig::no_verification();
    let repo = MemoryRepository::from_car(file, config).await?;

    println!("MST Root: {:?}", repo.mst().root());
    println!();

    let entries = repo.mst().entries().await?;
    println!("Total entries: {}", entries.len());

    // Show height distribution
    let mut heights = [0u32; 10];
    for (key, _) in &entries {
        let h = key_height(key) as usize;
        if h < 10 {
            heights[h] += 1;
        }
    }

    println!("\nHeight distribution:");
    for (h, count) in heights.iter().enumerate() {
        if *count > 0 {
            let pct = (*count as f64 / entries.len() as f64) * 100.0;
            println!("  Height {}: {} ({:.1}%)", h, count, pct);
        }
    }

    Ok(())
}

fn cmd_height(key: &str) -> Result<()> {
    let height = key_height(key);
    println!("Key: {}", key);
    println!("Height: {}", height);
    Ok(())
}

async fn cmd_info(path: &PathBuf) -> Result<()> {
    let file = File::open(path).await?;
    let config = RepoConfig::no_verification();
    let repo = MemoryRepository::from_car(file, config).await?;

    println!("Repository Information:");
    println!("  DID: {}", repo.did());
    println!("  Rev: {}", repo.rev());
    println!("  Version: {}", repo.commit().version);

    if let Some(ref prev) = repo.commit().prev {
        println!("  Previous: {}", prev);
    }

    let record_count = repo.record_count().await?;
    println!("  Records: {}", record_count);

    let collections = repo.list_collections().await?;
    println!("  Collections: {}", collections.len());

    Ok(())
}

async fn cmd_collections(path: &PathBuf) -> Result<()> {
    let file = File::open(path).await?;
    let config = RepoConfig::no_verification();
    let repo = MemoryRepository::from_car(file, config).await?;

    let collections = repo.list_collections().await?;

    for collection in collections {
        let count = repo.list_collection(&collection).await?.len();
        println!("{}\t{}", collection, count);
    }

    Ok(())
}
