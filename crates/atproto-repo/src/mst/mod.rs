//! Merkle Search Tree (MST) implementation.
//!
//! The MST is a deterministic, self-balancing search tree used by AT Protocol
//! to store key-value pairs where keys are record paths and values are CIDs.
//!
//! # Key Properties
//!
//! - **Deterministic**: Same set of keys always produces the same tree structure
//! - **Self-balancing**: Height is determined by SHA-256 hash of keys
//! - **Efficient diffing**: Can compute differences between tree versions
//! - **Fanout of 4**: Two bits per level (from leading zeros)
//!
//! # Key Format
//!
//! Keys are UTF-8 strings in the format `collection/rkey`:
//! - `app.bsky.feed.post/3jui7kd2z2y2e`
//! - `app.bsky.graph.follow/did:plc:xyz`
//!
//! # Example
//!
//! ```rust,ignore
//! use atproto_repo::mst::Mst;
//! use atproto_repo::storage::MemoryStorage;
//!
//! async fn example() -> anyhow::Result<()> {
//!     let storage = MemoryStorage::new();
//!     let mut mst = Mst::new(storage);
//!
//!     // Insert records
//!     let cid = compute_cid(b"record data");
//!     mst.insert("app.bsky.feed.post/abc123", cid.into()).await?;
//!
//!     // Lookup
//!     let value = mst.get("app.bsky.feed.post/abc123").await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Specification
//!
//! See [AT Protocol Repository](https://atproto.com/specs/repository)

mod diff;
mod entry;
mod key;
mod node;
mod serialize;
mod tree;

pub use diff::{DiffStats, MstDiff, RepoOp, RepoOpAction, diff_entries, ops_with_prev_cids};
pub use entry::TreeEntry;
pub use node::MstNode;
pub use tree::Mst;

// Re-export key utilities
pub use key::{compare_keys, key_height};
