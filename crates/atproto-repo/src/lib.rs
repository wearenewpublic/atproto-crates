//! Pure Rust implementation of AT Protocol repository structures.
//!
//! This crate provides:
//! - **MST** (Merkle Search Tree) encoding/decoding
//! - **Repository** structures for commits, records, and operations
//!
//! CAR v1 serialization, block storage, and varint encoding have been moved
//! to the `atproto-dasl` crate. Types are re-exported here for backward
//! compatibility.
//!
//! # Features
//!
//! - Pure Rust implementation (no external MST dependencies)
//! - Built on `atproto-dasl` for DAG-CBOR encoding, CAR, and storage
//! - Async-first streaming design using tokio
//! - Configurable CID and signature verification
//! - Memory limits for DoS prevention
//! - Pluggable storage backends (memory, disk, hybrid)
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use atproto_repo::{CarReader, RepoConfig, MemoryStorage};
//! use tokio::fs::File;
//!
//! async fn example() -> anyhow::Result<()> {
//!     // Read a CAR file
//!     let file = File::open("repo.car").await?;
//!     let reader = CarReader::new(file).await?;
//!
//!     println!("Roots: {:?}", reader.roots());
//!
//!     // Stream blocks into storage
//!     let mut storage = MemoryStorage::new();
//!     reader.stream_to_storage(&mut storage).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Specifications
//!
//! - [CAR v1](https://ipld.io/specs/transport/car/carv1/)
//! - [AT Protocol Repository](https://atproto.com/specs/repository)
//! - [AT Protocol Data Repos](https://atproto.com/guides/data-repos)

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod config;
pub mod errors;
pub mod mst;
pub mod repo;

// Re-export CAR types from atproto-dasl for backward compatibility
pub use atproto_dasl::car::{CarBlock, CarConfig, CarHeader, CarReader, CarWriter, LimitsConfig};

// Re-export storage types from atproto-dasl for backward compatibility
pub use atproto_dasl::storage::{
    BlockStorage, DiskStorage, MemoryStorage, SpillableBuffer, SpillableReader,
};

// Re-export error types from atproto-dasl for backward compatibility
pub use atproto_dasl::{CarError, StorageError, VarintError};

// Re-export CID utilities from atproto-dasl for backward compatibility
pub use atproto_dasl::cid::{DAG_CBOR_CODEC, SHA256_CODE, compute_cid};

// Re-export config types
pub use config::RepoConfig;

// Re-export error types defined in this crate
pub use errors::{MstError, RepoError};

// Re-export MST types
pub use mst::{Mst, MstDiff, MstNode, RepoOp, RepoOpAction, TreeEntry, ops_with_prev_cids};

// Re-export repository types
pub use repo::{
    Commit, DiskRepository, InductiveVerification, MemoryRepository, RecordPath, Repository,
    SignatureVerification, UnsignedCommit, verify_inductive,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_cid() {
        let data = b"hello world";
        let cid = compute_cid(data);

        // Verify it is CIDv1 with the correct codec
        assert_eq!(cid.version(), cid::Version::V1);
        assert_eq!(cid.codec(), DAG_CBOR_CODEC);
    }

    #[test]
    fn test_cid_deterministic() {
        let data = b"test data";
        let cid1 = compute_cid(data);
        let cid2 = compute_cid(data);
        assert_eq!(cid1, cid2);
    }
}
