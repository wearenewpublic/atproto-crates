//! AT Protocol repository structures.
//!
//! This module provides types for working with AT Protocol repositories,
//! including commits, records, and full repository operations.
//!
//! # Repository Structure
//!
//! An AT Protocol repository is a CAR file containing:
//! - A signed commit object (the root)
//! - An MST containing key-value pairs
//! - Record blocks referenced by the MST
//!
//! # Example
//!
//! ```rust,ignore
//! use atproto_repo::repo::Repository;
//! use atproto_repo::RepoConfig;
//! use tokio::fs::File;
//!
//! async fn example() -> anyhow::Result<()> {
//!     let file = File::open("repo.car").await?;
//!     let repo = Repository::from_car(file, RepoConfig::default()).await?;
//!
//!     println!("DID: {}", repo.commit().did);
//!     println!("Rev: {}", repo.commit().rev);
//!
//!     // List all posts
//!     for (path, _cid) in repo.list_collection("app.bsky.feed.post").await? {
//!         println!("Post: {}", path.rkey);
//!     }
//!
//!     Ok(())
//! }
//! ```

mod commit;
mod types;

pub use commit::{Commit, SignatureVerification, UnsignedCommit};
pub use types::RecordPath;

use crate::config::RepoConfig;
use crate::errors::RepoError;
use crate::mst::Mst;
use atproto_dasl::CarReader;
use atproto_dasl::Cid;
use atproto_dasl::storage::{BlockStorage, DiskStorage, MemoryStorage};
use tokio::io::AsyncRead;

/// Read-only view of a repository backed by pluggable storage.
///
/// Supports both in-memory and disk-backed storage for efficient
/// processing in low-resource environments.
pub struct Repository<S: BlockStorage> {
    /// Commit at the root of this repo.
    commit: Commit,
    /// MST tree structure.
    mst: Mst<S>,
    /// Configuration with verification settings.
    config: RepoConfig,
    /// Signature verification result (if verification was enabled).
    signature_verified: Option<SignatureVerification>,
}

impl<S: BlockStorage> Repository<S> {
    /// Load repository from storage with existing commit.
    #[must_use]
    pub fn new(commit: Commit, mst: Mst<S>, config: RepoConfig) -> Self {
        Self {
            commit,
            mst,
            config,
            signature_verified: None,
        }
    }

    /// Get the commit.
    #[must_use]
    pub fn commit(&self) -> &Commit {
        &self.commit
    }

    /// Get the repository DID.
    #[must_use]
    pub fn did(&self) -> &str {
        &self.commit.did
    }

    /// Get the revision string.
    #[must_use]
    pub fn rev(&self) -> &str {
        &self.commit.rev
    }

    /// Get signature verification result.
    ///
    /// Returns `None` if verification was disabled or not yet performed.
    #[must_use]
    pub fn signature_verification(&self) -> Option<&SignatureVerification> {
        self.signature_verified.as_ref()
    }

    /// Get a record by path.
    ///
    /// # Errors
    ///
    /// Returns `RepoError` if the record cannot be retrieved.
    pub async fn get_record(
        &self,
        path: &RecordPath,
    ) -> Result<Option<serde_json::Value>, RepoError> {
        let key = path.to_mst_key();

        // Get CID from MST
        let cid = match self.mst.get(&key).await? {
            Some(cid) => cid,
            None => return Ok(None),
        };

        // Get record data from storage
        let data = match self.mst.storage().get(&cid.into()).await? {
            Some(data) => data,
            None => return Ok(None),
        };

        // Decode as JSON
        let value: serde_json::Value =
            atproto_dasl::from_slice(&data).map_err(|e| RepoError::Car(e.into()))?;

        Ok(Some(value))
    }

    /// Get raw record bytes by path.
    ///
    /// # Errors
    ///
    /// Returns `RepoError` if the record cannot be retrieved.
    pub async fn get_record_bytes(&self, path: &RecordPath) -> Result<Option<Vec<u8>>, RepoError> {
        let key = path.to_mst_key();

        let cid = match self.mst.get(&key).await? {
            Some(cid) => cid,
            None => return Ok(None),
        };

        let data = self.mst.storage().get(&cid.into()).await?;
        Ok(data)
    }

    /// Get a record's CID.
    ///
    /// # Errors
    ///
    /// Returns `RepoError` if the lookup fails.
    pub async fn get_record_cid(&self, path: &RecordPath) -> Result<Option<Cid>, RepoError> {
        let key = path.to_mst_key();
        let cid = self.mst.get(&key).await?;
        Ok(cid)
    }

    /// List all records in a collection.
    ///
    /// # Errors
    ///
    /// Returns `RepoError` if the listing fails.
    pub async fn list_collection(
        &self,
        collection: &str,
    ) -> Result<Vec<(RecordPath, Cid)>, RepoError> {
        let entries = self.mst.list_collection(collection).await?;

        let paths: Result<Vec<_>, _> = entries
            .into_iter()
            .map(|(key, cid)| RecordPath::from_mst_key(&key).map(|path| (path, cid)))
            .collect();

        paths
    }

    /// List all collections in the repository.
    ///
    /// # Errors
    ///
    /// Returns `RepoError` if the listing fails.
    pub async fn list_collections(&self) -> Result<Vec<String>, RepoError> {
        let entries = self.mst.entries().await?;

        let mut collections: Vec<String> = entries
            .iter()
            .filter_map(|(key, _)| key.split('/').next().map(|s| s.to_string()))
            .collect();

        collections.sort();
        collections.dedup();

        Ok(collections)
    }

    /// Get reference to underlying MST.
    #[must_use]
    pub fn mst(&self) -> &Mst<S> {
        &self.mst
    }

    /// Get reference to underlying storage.
    #[must_use]
    pub fn storage(&self) -> &S {
        self.mst.storage()
    }

    /// Get the configuration.
    #[must_use]
    pub fn config(&self) -> &RepoConfig {
        &self.config
    }

    /// Load repository from an async CAR reader into pre-built storage.
    async fn from_car_with_storage<R: AsyncRead + Unpin>(
        reader: R,
        config: RepoConfig,
        mut storage: S,
    ) -> Result<Self, RepoError> {
        let car_reader = CarReader::with_config(reader, config.car_config()).await?;

        let root_cid = car_reader
            .root()
            .ok_or_else(|| RepoError::InvalidCommit {
                reason: "CAR has no root".to_string(),
            })?
            .clone();

        let _header = car_reader.stream_to_storage(&mut storage).await?;

        let commit_bytes = storage
            .get(&root_cid.clone().into())
            .await?
            .ok_or_else(|| RepoError::InvalidCommit {
                reason: "root block not found".to_string(),
            })?;

        let commit: Commit =
            atproto_dasl::from_slice(&commit_bytes).map_err(|e| RepoError::InvalidCommit {
                reason: format!("failed to decode commit: {}", e),
            })?;

        if commit.version != 3 {
            return Err(RepoError::UnsupportedCommitVersion {
                version: commit.version,
            });
        }

        let mst = Mst::from_root(commit.data.clone().into(), storage, config.clone());

        Ok(Self {
            commit,
            mst,
            config,
            signature_verified: None,
        })
    }
}

/// Convenience type for in-memory repository.
pub type MemoryRepository = Repository<MemoryStorage>;

impl MemoryRepository {
    /// Load repository from an async CAR reader into memory.
    ///
    /// # Errors
    ///
    /// Returns `RepoError` if loading fails.
    pub async fn from_car<R: AsyncRead + Unpin>(
        reader: R,
        config: RepoConfig,
    ) -> Result<Self, RepoError> {
        let storage = MemoryStorage::with_limits(config.limits.clone());
        Self::from_car_with_storage(reader, config, storage).await
    }

    /// Get the total number of records in the repository.
    ///
    /// # Errors
    ///
    /// Returns `RepoError` if counting fails.
    pub async fn record_count(&self) -> Result<usize, RepoError> {
        let entries = self.mst.entries().await?;
        Ok(entries.len())
    }
}

/// Convenience type for disk-backed repository.
pub type DiskRepository = Repository<DiskStorage>;

impl DiskRepository {
    /// Load repository from an async CAR reader with disk-backed storage.
    ///
    /// # Errors
    ///
    /// Returns `RepoError` if loading or storage initialization fails.
    pub async fn from_car<R: AsyncRead + Unpin>(
        reader: R,
        config: RepoConfig,
    ) -> Result<Self, RepoError> {
        let storage = DiskStorage::new(config.limits.clone()).await?;
        Self::from_car_with_storage(reader, config, storage).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_path() {
        let path = RecordPath::new("app.bsky.feed.post", "abc123");
        assert_eq!(path.collection, "app.bsky.feed.post");
        assert_eq!(path.rkey, "abc123");
        assert_eq!(path.to_mst_key(), "app.bsky.feed.post/abc123");
    }

    #[test]
    fn test_record_path_from_mst_key() {
        let path = RecordPath::from_mst_key("app.bsky.feed.post/abc123").unwrap();
        assert_eq!(path.collection, "app.bsky.feed.post");
        assert_eq!(path.rkey, "abc123");
    }

    #[test]
    fn test_record_path_invalid() {
        assert!(RecordPath::from_mst_key("invalid").is_err());
        assert!(RecordPath::from_mst_key("/rkey").is_err());
        assert!(RecordPath::from_mst_key("collection/").is_err());
    }
}
