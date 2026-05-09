//! Storage trait surfaces and shared row types.
//!
//! Two traits — `SpaceRepoStorage` and `SpaceMembersStorage` — abstract the
//! per-actor storage that backs `SpaceRepo` / `SpaceMembers`. `atproto-pds`
//! provides concrete impls (SQLite under default profile; fjall under the
//! `fjall` Cargo feature). In-memory impls live in [`crate::space_repo::memory`]
//! and [`crate::space_members::memory`] for testing.

use crate::errors::SpaceResult;
use crate::types::SpaceUri;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Current per-space record commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoState {
    /// Current SetHash digest. `None` if no commits have been applied (empty space).
    pub set_hash: Option<Vec<u8>>,
    /// Current rev (TID) of the most recent commit. `None` if empty.
    pub rev: Option<String>,
}

impl RepoState {
    /// Construct an empty state.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            set_hash: None,
            rev: None,
        }
    }
}

/// Current member-list commitment (owner-only).
pub type MemberState = RepoState;

/// A single record row in a per-space store.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordRow {
    /// NSID collection.
    pub collection: String,
    /// Record key.
    pub rkey: String,
    /// CID of the record value (DAG-CBOR-encoded).
    pub cid: String,
    /// DAG-CBOR-encoded record value bytes.
    pub value: Vec<u8>,
    /// `repo_rev` at write time.
    pub repo_rev: String,
    /// ISO-8601 timestamp of indexing.
    pub indexed_at: String,
}

/// A page of records returned by [`SpaceRepoStorage::list_records`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordPage {
    /// The records on this page.
    pub records: Vec<RecordRow>,
    /// Cursor for the next page (usually the last `rkey`).
    pub cursor: Option<String>,
}

/// A single oplog entry persisted by `apply_commit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OplogEntry {
    /// Rev (TID) shared by all entries in the same atomic batch.
    pub rev: String,
    /// Monotonic index within the batch (0..n-1).
    pub idx: u32,
    /// Action: `"create"` | `"update"` | `"delete"` (for records) or
    /// `"add"` | `"remove"` (for members).
    pub action: String,
    /// NSID collection (records only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection: Option<String>,
    /// Record key (records only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rkey: Option<String>,
    /// New record CID (records only; `None` for delete).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    /// Prior record CID (records only; `None` for create).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    /// DID being added/removed (members only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
}

/// A page of oplog entries returned by `read_oplog`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OplogPage {
    /// Ops in `(rev, idx)` order.
    pub ops: Vec<OplogEntry>,
    /// Current state at read time.
    pub state: RepoState,
}

/// A single member-row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRow {
    /// DID of the member.
    pub did: String,
    /// Rev (TID) at which this member was added.
    pub member_rev: String,
    /// ISO-8601 timestamp at which this member was added.
    pub added_at: String,
}

/// A page of members.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberPage {
    /// The members on this page.
    pub members: Vec<MemberRow>,
    /// Cursor for the next page.
    pub cursor: Option<String>,
}

/// A prepared commit ready to be persisted by storage.
///
/// Constructed by `SpaceRepo::format_commit` / `SpaceMembers::format_commit`,
/// consumed by `apply_commit`. The storage impl writes the commit record-row
/// or member-row updates and the oplog entries in a single atomic transaction.
#[derive(Debug, Clone)]
pub struct PreparedCommitRecords {
    /// New `set_hash` after applying this commit.
    pub new_set_hash: Vec<u8>,
    /// Rev (TID) for this commit.
    pub rev: String,
    /// Per-op record changes to apply.
    pub record_changes: Vec<RecordChange>,
    /// Oplog entries to append (one per op in `record_changes`).
    pub oplog_entries: Vec<OplogEntry>,
}

/// A single record change inside a prepared commit.
#[derive(Debug, Clone)]
pub enum RecordChange {
    /// Insert a new record.
    Create(RecordRow),
    /// Replace an existing record.
    Update {
        /// The new row.
        row: RecordRow,
        /// Prior CID for safety (storage may verify before overwrite).
        prior_cid: String,
    },
    /// Delete a record by primary key.
    Delete {
        /// NSID collection.
        collection: String,
        /// Record key.
        rkey: String,
        /// Prior CID for safety.
        prior_cid: String,
    },
}

/// A prepared member-commit ready to be persisted.
#[derive(Debug, Clone)]
pub struct PreparedCommitMembers {
    /// New member-list `set_hash`.
    pub new_set_hash: Vec<u8>,
    /// Rev for this commit.
    pub rev: String,
    /// Per-op member changes.
    pub member_changes: Vec<MemberChange>,
    /// Oplog entries to append.
    pub oplog_entries: Vec<OplogEntry>,
}

/// A single member change inside a prepared commit.
#[derive(Debug, Clone)]
pub enum MemberChange {
    /// Add a member.
    Add(MemberRow),
    /// Remove a member by DID.
    Remove(String),
}

/// Storage trait for a per-(user, space) record commitment + oplog.
///
/// Implementations must be transactional within `apply_commit`: all of
/// `record_changes`, `oplog_entries`, and the commitment update succeed or
/// none do.
#[async_trait]
pub trait SpaceRepoStorage: Send + Sync {
    /// Get current `{set_hash, rev}` for this `(user, space)` pair.
    async fn current_state(&self, space: &SpaceUri) -> SpaceResult<RepoState>;

    /// Read a single record by `(collection, rkey)`.
    async fn get_record(
        &self,
        space: &SpaceUri,
        collection: &str,
        rkey: &str,
    ) -> SpaceResult<Option<RecordRow>>;

    /// List records in a collection. Cursor is the last `rkey` from the prior page (`None` = first page).
    async fn list_records(
        &self,
        space: &SpaceUri,
        collection: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> SpaceResult<RecordPage>;

    /// List all collections present in this space's record store.
    async fn list_collections(&self, space: &SpaceUri) -> SpaceResult<Vec<String>>;

    /// Atomically apply a prepared commit: write changes, append oplog, update commitment.
    async fn apply_commit(
        &self,
        space: &SpaceUri,
        commit: PreparedCommitRecords,
    ) -> SpaceResult<()>;

    /// Read oplog entries since the given rev (exclusive). `None` = from the start.
    ///
    /// If `since` predates the retained range, returns [`SpaceError::OplogGap`].
    async fn read_oplog(
        &self,
        space: &SpaceUri,
        since: Option<&str>,
        limit: u32,
    ) -> SpaceResult<OplogPage>;
}

/// Storage trait for owner-only member-list commitment + oplog.
#[async_trait]
pub trait SpaceMembersStorage: Send + Sync {
    /// Get current `{set_hash, rev}` for the member-list of this space.
    async fn current_state(&self, space: &SpaceUri) -> SpaceResult<MemberState>;

    /// Check whether a DID is in the member list.
    async fn is_member(&self, space: &SpaceUri, did: &str) -> SpaceResult<bool>;

    /// List members.
    async fn list_members(
        &self,
        space: &SpaceUri,
        cursor: Option<&str>,
        limit: u32,
    ) -> SpaceResult<MemberPage>;

    /// Atomically apply a prepared member-commit.
    async fn apply_commit(
        &self,
        space: &SpaceUri,
        commit: PreparedCommitMembers,
    ) -> SpaceResult<()>;

    /// Read member-oplog entries since the given rev.
    async fn read_oplog(
        &self,
        space: &SpaceUri,
        since: Option<&str>,
        limit: u32,
    ) -> SpaceResult<OplogPage>;
}
