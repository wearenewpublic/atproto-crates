//! Public realm repository operations.
//!
//! Backed by `actor_store::sql::SqlActorStore` and
//! `actor_store::sql::SqlBlockStorage`:
//! - `reader` — `getRecord`, `listRecords`, `describeRepo`, `getLatestCommit`,
//!   `getRepoStatus`, `getRepo` (CAR streaming via `atproto-repo`'s
//!   `Repository` over `SqlBlockStorage`), `getRepo?since=<rev>`.
//! - `writer` — `createRecord` / `putRecord` / `deleteRecord` /
//!   `applyWrites` / `uploadBlob` with Sync 1.1 `#commit` event emission.
//! - `import` — CAR ingest with inductive verification + per-commit
//!   signature verification against historical PLC keys.

pub mod car_export;
#[cfg(feature = "sqlite")]
/// Lexicon resolution, for deciding whether a record's schema is *known* --
/// the distinction `validate` in the repo-write lexicons turns on.
pub mod lexicon;

pub mod prepare;

/// CARv1 slices for the firehose `blocks` field.
pub mod commit_car;

#[cfg(feature = "sqlite")]
pub mod import;

#[cfg(feature = "sqlite")]
pub mod reader;

#[cfg(feature = "sqlite")]
pub mod writer;

#[cfg(feature = "sqlite")]
pub use car_export::{export_blocks_car, export_repo_car};
pub use commit_car::{RecordingBlockStorage, build_commit_car, build_sync_car};

#[cfg(feature = "sqlite")]
pub use import::{ImportOutcome, RepoImporter};

#[cfg(feature = "sqlite")]
pub use reader::{
    DescribeRepoResponse, ListRecordsItem, ListRecordsResponse, RecordResponse, RepoReader,
    RepoStatusResponse,
};

#[cfg(feature = "sqlite")]
pub use writer::{CommitResult, RepoWriter, WriteAction, WriteOp, WriteResult};
