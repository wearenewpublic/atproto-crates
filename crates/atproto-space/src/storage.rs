//! Storage trait surfaces and shared row types.
//!
//! Two traits — `SpaceRepoStorage` and `SpaceMembersStorage` — abstract the
//! per-actor storage that backs `SpaceRepo` / `SpaceMembers`. `atproto-pds`
//! provides concrete impls (SQLite under default profile; fjall under the
//! `fjall` Cargo feature). In-memory impls live in [`crate::space_repo::memory`]
//! and [`crate::space_members::memory`] for testing.

use crate::errors::{SpaceError, SpaceResult};
use crate::types::SpaceUri;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// A `(rev, idx)`-granular oplog cursor.
///
/// The oplog `since` cursor must be `(rev, idx)`-granular rather than
/// rev-granular: an atomic batch (entries sharing a `rev`) can exceed a single
/// page's `limit`, so paging by bare `rev` would skip the batch's tail. The
/// cursor names the last op delivered, and the next page resumes strictly after
/// it (`(rev, idx) > (cursor.rev, cursor.idx)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OplogCursor {
    /// Rev (TID) of the last delivered op.
    pub rev: String,
    /// Index of the last delivered op within its `rev` batch.
    pub idx: u32,
}

impl OplogCursor {
    /// Construct a cursor from a `rev` and `idx`.
    #[must_use]
    pub fn new(rev: String, idx: u32) -> Self {
        Self { rev, idx }
    }

    /// Encode as an opaque wire token `"<rev>__<idx>"`.
    #[must_use]
    pub fn to_token(&self) -> String {
        format!("{}__{}", self.rev, self.idx)
    }

    /// Decode a `since` token: either the composite `"<rev>__<idx>"` this
    /// server emits, or a bare rev.
    ///
    /// `com.atproto.space.listRepoOps` declares `since` as *"operations after
    /// this revision"* and declares no separate `cursor` **input**, so the
    /// `cursor` its output carries has nowhere to go except back into `since`.
    /// A conformant client therefore sends both forms, and refusing the bare
    /// one made this server unreachable from a client that had only ever read
    /// the lexicon.
    ///
    /// A bare rev decodes to `(rev, 0)`, not to "everything strictly after
    /// `rev`". The two differ only for an atomic batch that spans a page
    /// boundary: `(rev, 0)` re-delivers that batch's remaining ops, where the
    /// stricter reading would skip them. Re-delivery is safe — a syncer
    /// applies ops by `(collection, rkey, cid)` — and a dropped tail is the
    /// batch-tail-drop bug latent in the draft itself.
    ///
    /// The two forms are unambiguous: a rev is a TID, thirteen
    /// base32-sortable characters, and cannot contain `__`.
    ///
    /// Returns [`SpaceError::InvalidCursor`] if the token is malformed.
    pub fn from_token(token: &str) -> SpaceResult<Self> {
        let Some((rev, idx)) = token.rsplit_once("__") else {
            if token.is_empty() {
                return Err(SpaceError::InvalidCursor {
                    token: token.to_string(),
                });
            }
            return Ok(Self {
                rev: token.to_string(),
                idx: 0,
            });
        };
        let idx: u32 = idx.parse().map_err(|_| SpaceError::InvalidCursor {
            token: token.to_string(),
        })?;
        if rev.is_empty() {
            return Err(SpaceError::InvalidCursor {
                token: token.to_string(),
            });
        }
        Ok(Self {
            rev: rev.to_string(),
            idx,
        })
    }
}

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
    /// DAG-CBOR-encoded value of the record **as it currently stands**, for
    /// create and update ops.
    ///
    /// `None` for deletes, for member ops, and — the case worth naming — when
    /// this op has been *superseded* by a later one on the same
    /// `(collection, rkey)`. The lexicon requires that omission, and the
    /// implementation gets it by matching the op's own `cid` against the current
    /// record's: a superseded op's CID is no longer current, so it finds
    /// nothing. Matching on `(collection, rkey)` alone would inline the *new*
    /// value against an *old* op, which is worse than omitting it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Vec<u8>>,
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

    /// List records in a collection. Cursor is the last `rkey` from the prior
    /// page (`None` = first page).
    ///
    /// `reverse` walks descending `rkey` order, per the lexicon's `reverse`
    /// parameter. The cursor is still the last `rkey` delivered, so paging
    /// composes with either direction.
    async fn list_records(
        &self,
        space: &SpaceUri,
        collection: &str,
        cursor: Option<&str>,
        limit: u32,
        reverse: bool,
    ) -> SpaceResult<RecordPage>;

    /// List all collections present in this space's record store.
    async fn list_collections(&self, space: &SpaceUri) -> SpaceResult<Vec<String>>;

    /// Atomically apply a prepared commit: write changes, append oplog, update commitment.
    async fn apply_commit(
        &self,
        space: &SpaceUri,
        commit: PreparedCommitRecords,
    ) -> SpaceResult<()>;

    /// Read oplog entries strictly after the given `(rev, idx)` cursor. `None` =
    /// from the start.
    ///
    /// The predicate is `(rev, idx) > (since.rev, since.idx)`, ordered by
    /// `(rev, idx)`. This keeps atomic batches (entries sharing a `rev`)
    /// coherent across paging even when a batch exceeds `limit`.
    ///
    /// If `since` predates the retained range, returns [`SpaceError::OplogGap`].
    async fn read_oplog(
        &self,
        space: &SpaceUri,
        since: Option<&OplogCursor>,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oplog_cursor_token_round_trip() {
        let cur = OplogCursor::new("3kabc".to_string(), 5);
        let token = cur.to_token();
        assert_eq!(token, "3kabc__5");
        assert_eq!(OplogCursor::from_token(&token).unwrap(), cur);
    }

    #[test]
    fn oplog_cursor_token_round_trip_idx_zero() {
        let cur = OplogCursor::new("3kabc".to_string(), 0);
        assert_eq!(OplogCursor::from_token(&cur.to_token()).unwrap(), cur);
    }

    /// The lexicon describes `since` as "operations after this revision" and
    /// declares no separate `cursor` input, so a bare rev is what a client
    /// written against the lexicon alone will send. Refusing it made this
    /// endpoint unreachable from such a client.
    #[test]
    fn a_bare_rev_is_accepted_as_the_start_of_its_batch() {
        assert_eq!(
            OplogCursor::from_token("3kabc").unwrap(),
            OplogCursor::new("3kabc".to_string(), 0)
        );
    }

    /// `(rev, 0)` rather than "strictly after rev": the two differ only for a
    /// batch spanning a page boundary, where `(rev, 0)` re-delivers the tail
    /// and the stricter reading drops it. Re-delivery is safe; loss is not.
    #[test]
    fn a_bare_rev_resolves_to_index_zero_not_past_the_batch() {
        let cur = OplogCursor::from_token("3kabc").unwrap();
        assert_eq!(cur.idx, 0);
        // Which is to say it decodes to exactly the composite form's `__0`.
        assert_eq!(cur, OplogCursor::from_token("3kabc__0").unwrap());
    }

    /// A rev is a TID — thirteen base32-sortable characters — so it can never
    /// contain the separator, and the two forms cannot be confused.
    #[test]
    fn the_composite_form_still_wins_when_a_separator_is_present() {
        assert_eq!(
            OplogCursor::from_token("3kabc__7").unwrap(),
            OplogCursor::new("3kabc".to_string(), 7)
        );
    }

    #[test]
    fn oplog_cursor_rejects_malformed() {
        // Empty.
        assert!(matches!(
            OplogCursor::from_token(""),
            Err(SpaceError::InvalidCursor { .. })
        ));
        // Non-numeric idx.
        assert!(matches!(
            OplogCursor::from_token("3kabc__x"),
            Err(SpaceError::InvalidCursor { .. })
        ));
        // Empty rev.
        assert!(matches!(
            OplogCursor::from_token("__3"),
            Err(SpaceError::InvalidCursor { .. })
        ));
    }
}
