//! Per-account `ActorStore` trait and profile dispatch.
//!
//! Concrete impls:
//!
//! - **SQLite** (`actor_store::sql`) — per-actor SQLite files; all four
//!   public-realm trait impls + the Spaces tables.
//! - **fjall** (`actor_store::fjall`, gated `fjall` feature) — single
//!   keyspace per data-dir with per-table Ramjet-style partitions.
//!   Both the Spaces subset and the public-realm writer + reader +
//!   import + CAR + outbox paths route through the trait dispatch.
//!

#[cfg(feature = "fjall")]
pub mod fjall;
#[cfg(feature = "sqlite")]
pub mod sql;
pub mod traits;

pub use traits::{
    AtomicCommitWriter, BlobRefRow, BlobRow, BlobStorage, CommitBatch, CommitObjStorage, CommitRow,
    OutboxRow, OutboxStorage, RecordRow, RepoRecordStorage,
};

use crate::errors::PdsResult;
use async_trait::async_trait;

/// Storage profile chosen at compile time.
///
/// Mutually exclusive at compile time per;
/// each profile is a separate `cargo install` build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageProfile {
    /// Per-actor SQLite (default).
    Sqlite,
    /// Single-keyspace fjall (Ramjet-style partitions).
    Fjall,
}

impl StorageProfile {
    /// The profile compiled into this binary, derived from the active Cargo features.
    pub const fn compiled() -> Self {
        // When `sqlite` and `fjall` are both off (e.g., during bare
        // `cargo check`), default to SQLite. The runtime profile-mismatch
        // check is done at startup via `PDS_STORAGE_PROFILE`.
        #[cfg(feature = "fjall")]
        {
            StorageProfile::Fjall
        }
        #[cfg(not(feature = "fjall"))]
        {
            StorageProfile::Sqlite
        }
    }

    /// String form for config validation and logging.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            StorageProfile::Sqlite => "sqlite",
            StorageProfile::Fjall => "fjall",
        }
    }

    /// Parse from the `PDS_STORAGE_PROFILE` env-var value.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "sqlite" => Some(StorageProfile::Sqlite),
            "fjall" => Some(StorageProfile::Fjall),
            _ => None,
        }
    }

    /// Read `PDS_STORAGE_PROFILE` from the process environment and validate
    /// it against the profile compiled into this binary.
    ///
    /// Returns the configured profile when the env var matches the compiled
    /// profile, or [`PdsError::StorageProfileMismatch`] when they disagree.
    /// Falls back to [`Self::compiled`] when the env var is unset or empty.
    /// Unrecognized profile strings (e.g. `"postgres"`) surface as a
    /// [`PdsError::Config`] with a helpful message.
    pub fn from_env() -> PdsResult<Self> {
        let raw = std::env::var("PDS_STORAGE_PROFILE").unwrap_or_default();
        Self::resolve(&raw, Self::compiled())
    }

    /// Internal resolution helper, factored out of [`Self::from_env`] for
    /// hermetic testability (env-var mutation requires `unsafe` and races
    /// across threads).
    pub(crate) fn resolve(raw: &str, compiled: Self) -> PdsResult<Self> {
        if raw.trim().is_empty() {
            return Ok(compiled);
        }
        let configured =
            Self::parse(raw.trim()).ok_or_else(|| crate::errors::PdsError::Config {
                issues: vec![format!(
                    "PDS_STORAGE_PROFILE={raw:?} is not recognized; expected `sqlite` or `fjall`"
                )],
            })?;
        if configured != compiled {
            return Err(crate::errors::PdsError::StorageProfileMismatch {
                configured: configured.as_str().to_string(),
                compiled: compiled.as_str().to_string(),
            });
        }
        Ok(configured)
    }
}

/// Per-account store trait.
///
/// Each account has its own `ActorStore` instance (under SQLite, that's a
/// dedicated DB file; under fjall, it's prefix-scoped within the shared
/// keyspace). Holds both the public realm (commits, MST blocks, records,
/// outbox) and any spaces realm (the eight Spaces tables) for one DID.
///
/// Public-realm methods are stable; Spaces methods delegate to the
/// `SpaceRepoStorage` and `SpaceMembersStorage` traits from
/// `atproto-space`.
#[async_trait]
pub trait ActorStore: Send + Sync {
    /// The DID this store is bound to.
    fn did(&self) -> &str;

    /// Open a transaction. Mutations within the closure run atomically.
    /// (The richer `ActorTransactor` type is a future expansion; this
    /// skeleton returns `Ok(())` to let the trait surface compile.)
    async fn ping(&self) -> PdsResult<()>;
}

// ---------------------------------------------------------------------------
//  Public-realm backend dispatch.
// ---------------------------------------------------------------------------

use std::sync::Arc;

/// A `Clone`-able container holding the four public-realm storage trait
/// objects that the high-level `RepoReader` / `RepoWriter` /
/// `OutboxReader` / blob layer dispatch through.
///
/// Two factory variants — `sql(data_dir)` and `fjall(store)` — wire up
/// the corresponding backend per-trait. At runtime `bin/pds.rs` picks
/// based on `PDS_STORAGE_PROFILE`. Test code can construct either form
/// directly to exercise both backends end-to-end.
///
/// The trait objects are wrapped in `Arc<dyn …>` so this whole struct
/// is cheap to clone and pass through `HttpState`.
#[derive(Clone)]
pub struct PublicRealmBackend {
    /// `commit_obj` storage.
    pub commit_obj: Arc<dyn CommitObjStorage>,
    /// `repo_record` storage.
    pub repo_record: Arc<dyn RepoRecordStorage>,
    /// `outbox` storage.
    pub outbox: Arc<dyn OutboxStorage>,
    /// `repo_blob` + `repo_blob_ref` storage.
    pub blob: Arc<dyn BlobStorage>,
    /// Atomic-commit dispatcher — used by `RepoWriter::apply_writes`
    /// to persist commit + records + outbox in a single backend-native
    /// transaction (sqlx `Transaction` for SQL, `fjall::WriteBatch`
    /// for fjall).
    pub atomic: Arc<dyn AtomicCommitWriter>,
    /// Tag describing which backend constructed this (for `tracing`
    /// breadcrumbs and operator-visible diagnostics).
    pub backend_label: &'static str,
    /// Backend-specific handle factory used by the writer to open a
    /// per-actor `BlockStorage` for the MST read/write path. The MST
    /// requires a concrete owned `BlockStorage` instance (it takes
    /// `&mut self`), so we go through the variant rather than through
    /// an `Arc<dyn ...>` field.
    kind: BackendKind,
}

/// Internal marker for the backend variant. Used to dispatch writes
/// that need typed access to the underlying handle (atomic batches,
/// per-actor `BlockStorage` factory).
#[derive(Clone)]
enum BackendKind {
    #[cfg(feature = "sqlite")]
    Sqlite { data_dir: std::path::PathBuf },
    #[cfg(feature = "fjall")]
    Fjall {
        store: crate::actor_store::fjall::FjallActorStore,
    },
}

/// Per-actor block-storage handle returned by
/// [`PublicRealmBackend::open_block_storage`]. Owned (not behind
/// `Arc<dyn …>`) because the MST builder requires `&mut` access. The
/// concrete variants live in their respective modules; callers that
/// need read+write access pass this around by value.
pub enum ActorBlockStorage {
    /// SQL-backed per-actor blockstore.
    #[cfg(feature = "sqlite")]
    Sqlite(Box<crate::actor_store::sql::SqlBlockStorage>),
    /// Fjall-backed per-actor blockstore.
    #[cfg(feature = "fjall")]
    Fjall(Box<crate::actor_store::fjall::FjallBlockStorage>),
}

impl atproto_dasl::storage::BlockStorage for ActorBlockStorage {
    async fn put(
        &mut self,
        cid: &cid::Cid,
        data: Vec<u8>,
    ) -> std::result::Result<(), atproto_dasl::StorageError> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::Sqlite(s) => s.put(cid, data).await,
            #[cfg(feature = "fjall")]
            Self::Fjall(s) => s.put(cid, data).await,
        }
    }
    async fn get(
        &self,
        cid: &cid::Cid,
    ) -> std::result::Result<Option<Vec<u8>>, atproto_dasl::StorageError> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::Sqlite(s) => s.get(cid).await,
            #[cfg(feature = "fjall")]
            Self::Fjall(s) => s.get(cid).await,
        }
    }
    async fn contains(
        &self,
        cid: &cid::Cid,
    ) -> std::result::Result<bool, atproto_dasl::StorageError> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::Sqlite(s) => s.contains(cid).await,
            #[cfg(feature = "fjall")]
            Self::Fjall(s) => s.contains(cid).await,
        }
    }
    async fn remove(
        &mut self,
        cid: &cid::Cid,
    ) -> std::result::Result<Option<Vec<u8>>, atproto_dasl::StorageError> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::Sqlite(s) => s.remove(cid).await,
            #[cfg(feature = "fjall")]
            Self::Fjall(s) => s.remove(cid).await,
        }
    }
    fn memory_usage(&self) -> usize {
        match self {
            #[cfg(feature = "sqlite")]
            Self::Sqlite(s) => s.memory_usage(),
            #[cfg(feature = "fjall")]
            Self::Fjall(s) => s.memory_usage(),
        }
    }
    fn block_count(&self) -> usize {
        match self {
            #[cfg(feature = "sqlite")]
            Self::Sqlite(s) => s.block_count(),
            #[cfg(feature = "fjall")]
            Self::Fjall(s) => s.block_count(),
        }
    }
    fn cids(&self) -> Box<dyn Iterator<Item = cid::Cid> + '_> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::Sqlite(s) => s.cids(),
            #[cfg(feature = "fjall")]
            Self::Fjall(s) => s.cids(),
        }
    }
    async fn clear(&mut self) -> std::result::Result<(), atproto_dasl::StorageError> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::Sqlite(s) => s.clear().await,
            #[cfg(feature = "fjall")]
            Self::Fjall(s) => s.clear().await,
        }
    }
}

impl PublicRealmBackend {
    /// Construct a SQL-backed `PublicRealmBackend` rooted at `data_dir`.
    /// Each trait impl opens per-actor `SqlActorStore`s on demand.
    #[cfg(feature = "sqlite")]
    #[must_use]
    pub fn sql(data_dir: std::path::PathBuf) -> Self {
        Self {
            commit_obj: Arc::new(crate::actor_store::sql::SqlCommitObjStorage::new(
                data_dir.clone(),
            )),
            repo_record: Arc::new(crate::actor_store::sql::SqlRepoRecordStorage::new(
                data_dir.clone(),
            )),
            outbox: Arc::new(crate::actor_store::sql::SqlOutboxStorage::new(
                data_dir.clone(),
            )),
            blob: Arc::new(crate::actor_store::sql::SqlBlobStorage::new(
                data_dir.clone(),
            )),
            atomic: Arc::new(crate::actor_store::sql::SqlAtomicCommitWriter::new(
                data_dir.clone(),
            )),
            backend_label: "sqlite",
            kind: BackendKind::Sqlite { data_dir },
        }
    }

    /// Construct a fjall-backed `PublicRealmBackend` over an already-open
    /// `FjallActorStore`. Available only when the `fjall` feature is on.
    #[cfg(feature = "fjall")]
    #[must_use]
    pub fn fjall(store: crate::actor_store::fjall::FjallActorStore) -> Self {
        Self {
            commit_obj: Arc::new(crate::actor_store::fjall::FjallCommitObjStorage::new(
                store.clone(),
            )),
            repo_record: Arc::new(crate::actor_store::fjall::FjallRepoRecordStorage::new(
                store.clone(),
            )),
            outbox: Arc::new(crate::actor_store::fjall::FjallOutboxStorage::new(
                store.clone(),
            )),
            blob: Arc::new(crate::actor_store::fjall::FjallBlobStorage::new(
                store.clone(),
            )),
            atomic: Arc::new(crate::actor_store::fjall::FjallAtomicCommitWriter::new(
                store.clone(),
            )),
            backend_label: "fjall",
            kind: BackendKind::Fjall { store },
        }
    }

    /// Open a per-actor `BlockStorage` handle for the writer's MST
    /// read/write path. Returns an owned handle (not `Arc<dyn …>`)
    /// because the MST builder takes the storage by value.
    pub async fn open_block_storage(&self, did: &str) -> PdsResult<ActorBlockStorage> {
        match &self.kind {
            #[cfg(feature = "sqlite")]
            BackendKind::Sqlite { data_dir } => {
                let store = crate::actor_store::sql::SqlActorStore::open(data_dir, did).await?;
                let bs = crate::actor_store::sql::SqlBlockStorage::open(store.pool().clone())
                    .await
                    .map_err(|e| crate::errors::PdsError::Storage {
                        reason: format!("open sql block storage: {e}"),
                    })?;
                Ok(ActorBlockStorage::Sqlite(Box::new(bs)))
            }
            #[cfg(feature = "fjall")]
            BackendKind::Fjall { store } => {
                let bs = crate::actor_store::fjall::FjallBlockStorage::open(store, did).map_err(
                    |e| crate::errors::PdsError::Storage {
                        reason: format!("open fjall block storage: {e}"),
                    },
                )?;
                Ok(ActorBlockStorage::Fjall(Box::new(bs)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_profile_round_trip() {
        assert_eq!(
            StorageProfile::parse("sqlite"),
            Some(StorageProfile::Sqlite)
        );
        assert_eq!(StorageProfile::parse("fjall"), Some(StorageProfile::Fjall));
        assert_eq!(
            StorageProfile::parse("SQLITE"),
            Some(StorageProfile::Sqlite)
        );
        assert!(StorageProfile::parse("postgres").is_none());
    }

    #[test]
    fn storage_profile_as_str() {
        assert_eq!(StorageProfile::Sqlite.as_str(), "sqlite");
        assert_eq!(StorageProfile::Fjall.as_str(), "fjall");
    }

    #[test]
    fn resolve_empty_returns_compiled() {
        for compiled in [StorageProfile::Sqlite, StorageProfile::Fjall] {
            assert_eq!(StorageProfile::resolve("", compiled).unwrap(), compiled);
            assert_eq!(StorageProfile::resolve("   ", compiled).unwrap(), compiled);
        }
    }

    #[test]
    fn resolve_matching_profile_succeeds() {
        assert_eq!(
            StorageProfile::resolve("sqlite", StorageProfile::Sqlite).unwrap(),
            StorageProfile::Sqlite
        );
        assert_eq!(
            StorageProfile::resolve("FJALL", StorageProfile::Fjall).unwrap(),
            StorageProfile::Fjall
        );
    }

    #[test]
    fn resolve_unrecognized_is_config_error() {
        let err = StorageProfile::resolve("postgres", StorageProfile::Sqlite).unwrap_err();
        assert!(matches!(err, crate::errors::PdsError::Config { .. }));
    }

    #[test]
    fn resolve_mismatch_returns_profile_mismatch() {
        let err = StorageProfile::resolve("fjall", StorageProfile::Sqlite).unwrap_err();
        match err {
            crate::errors::PdsError::StorageProfileMismatch {
                configured,
                compiled,
            } => {
                assert_eq!(configured, "fjall");
                assert_eq!(compiled, "sqlite");
            }
            other => panic!("expected StorageProfileMismatch, got {other:?}"),
        }
    }
}
