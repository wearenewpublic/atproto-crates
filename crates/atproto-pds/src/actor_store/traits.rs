//! Public-realm storage traits.
//!
//! Each trait factors out the storage operations one of the SQLite
//! `actor_store::sql` tables exposes today, so a fjall (or future
//! Postgres) backend can ship a parallel implementation. The traits are
//! the API contract `RepoReader` / `RepoWriter` / `OutboxReader` will
//! eventually dispatch through; today those callers go through `sqlx`
//! directly and the SQL flavor of each trait is therefore not yet
//! implemented.
//!
//! All operations are per-DID — the storage layer is shared across
//! actors, with each row keyed under a `<did>\0<...>` prefix. Whether
//! that prefix is a logical column (SQLite) or a literal byte prefix
//! (fjall) is a backend concern; the trait surface is uniform.

use crate::errors::PdsResult;
use async_trait::async_trait;

// ---------------------------------------------------------------------------
//  Common DTOs.
// ---------------------------------------------------------------------------

/// One row from `commit_obj` — a signed atproto commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitRow {
    /// Commit CID (DAG-CBOR encoded).
    pub cid: String,
    /// Commit rev (TID).
    pub rev: String,
    /// CID of the MST root the commit attests to.
    pub data_cid: String,
    /// `Some(cid)` of the prior commit (None for genesis).
    pub prev_cid: Option<String>,
    /// `Some(cid)` of the prior commit's `data_cid` (Sync 1.1 `prevData`).
    pub prev_data_cid: Option<String>,
    /// ECDSA signature over the commit's signing-bytes.
    pub signature: Vec<u8>,
    /// ISO-8601 ingest timestamp.
    pub created_at: String,
}

/// One row from `repo_record` — an indexed AT-URI record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordRow {
    /// Full AT-URI (`at://did/collection/rkey`).
    pub uri: String,
    /// CID of the record's DAG-CBOR-encoded value.
    pub cid: String,
    /// NSID collection.
    pub collection: String,
    /// Record key.
    pub rkey: String,
    /// Rev (TID) at which the record was last written.
    pub rev: String,
    /// ISO-8601 ingest timestamp.
    pub indexed_at: String,
}

/// One row from `outbox` — a Sync 1.1 firehose event awaiting fan-out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRow {
    /// Per-DID monotonic sequence number (1-indexed).
    pub seq: u64,
    /// Event-type discriminator (`commit` | `account` | `identity` | `sync` | ...).
    pub event_type: String,
    /// DAG-CBOR-encoded event body.
    pub payload: Vec<u8>,
    /// ISO-8601 emission timestamp.
    pub created_at: String,
}

/// One row from `repo_blob` — a content-addressed binary uploaded by an
/// account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRow {
    /// Blob CID (CIDv1 raw sha256).
    pub cid: String,
    /// MIME type as declared at upload.
    pub mime_type: String,
    /// Size in bytes.
    pub size: u64,
    /// Raw bytes.
    pub data: Vec<u8>,
    /// ISO-8601 ingest timestamp.
    pub created_at: String,
}

/// One row from `repo_blob_ref` — a record→blob reference (ref-count entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRefRow {
    /// AT-URI of the referencing record.
    pub record_uri: String,
    /// CID of the referenced blob.
    pub blob_cid: String,
    /// MIME type echoed from the upload.
    pub mime_type: String,
    /// Size echoed from the upload.
    pub size: u64,
}

// ---------------------------------------------------------------------------
//  Storage traits.
// ---------------------------------------------------------------------------

/// Per-DID signed-commit storage.
///
/// Mirrors the `commit_obj` SQLite table — atomically `insert` a new
/// commit, `latest` for "head of the chain", and `get_by_cid` /
/// `get_by_rev` for arbitrary lookups.
#[async_trait]
pub trait CommitObjStorage: Send + Sync {
    /// Append a new commit. The implementation must enforce that
    /// `cid` and `rev` are both unique within `did`.
    async fn insert(&self, did: &str, row: &CommitRow) -> PdsResult<()>;

    /// Get the most-recent commit for `did` (highest rev), or `None`
    /// when the DID has no commits yet.
    async fn latest(&self, did: &str) -> PdsResult<Option<CommitRow>>;

    /// Look up a commit by its CID.
    async fn get_by_cid(&self, did: &str, cid: &str) -> PdsResult<Option<CommitRow>>;

    /// Look up a commit by its rev.
    async fn get_by_rev(&self, did: &str, rev: &str) -> PdsResult<Option<CommitRow>>;
}

/// Per-DID record-index storage.
///
/// Mirrors the `repo_record` SQLite table — `upsert` on (did, collection,
/// rkey), `get_by_uri` for AT-URI dispatch, `delete`, and
/// `list_by_collection` for paginated listings.
#[async_trait]
pub trait RepoRecordStorage: Send + Sync {
    /// Insert or replace a record row. Replacement is keyed on
    /// `(did, collection, rkey)` (matching the SQLite UNIQUE constraint).
    async fn upsert(&self, did: &str, row: &RecordRow) -> PdsResult<()>;

    /// Remove the row at `(did, collection, rkey)`. Returns `true` if a
    /// row was removed; `false` when nothing matched.
    async fn delete(&self, did: &str, collection: &str, rkey: &str) -> PdsResult<bool>;

    /// Look up a single record by AT-URI.
    async fn get_by_uri(&self, did: &str, uri: &str) -> PdsResult<Option<RecordRow>>;

    /// List records in a collection, ordered ascending by rkey.
    /// `cursor` is the rkey to start *after* (exclusive); `limit` caps
    /// the page size.
    async fn list_by_collection(
        &self,
        did: &str,
        collection: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> PdsResult<Vec<RecordRow>>;

    /// List the distinct collections present for `did`, ordered
    /// ascending. Used by `describeRepo`.
    async fn list_collections(&self, did: &str) -> PdsResult<Vec<String>>;
}

/// Atomic-commit batch — the lockstep payload that
/// `RepoWriter::apply_writes` emits for one signed commit. Carries the
/// commit row, the commit-block bytes, and the indexed `repo_record`
/// upserts + deletes. Implementations of
/// [`AtomicCommitWriter`] persist all of these atomically using their
/// native primitive (sqlx `Transaction` for SQL,
/// `fjall::WriteBatch` for fjall) so a partial failure can't leave
/// the repo in an inconsistent state.
///
/// The firehose event is deliberately not part of this batch. `seq`
/// numbers the whole stream, so the event log is server-global and
/// lives in the accounts database — a per-actor transaction cannot
/// reach it. [`crate::sequencer::Sequencer`] records the event once
/// this batch is durable.
///
/// Field references are borrowed by the caller because it already
/// owns them.
#[derive(Debug)]
pub struct CommitBatch<'a> {
    /// Signed commit metadata to append to `commit_obj`.
    pub commit: &'a CommitRow,
    /// CID of the commit block (matches `commit.cid`; carried
    /// separately so the caller doesn't have to re-parse it).
    pub commit_block_cid: &'a str,
    /// DAG-CBOR-encoded bytes of the signed commit, persisted in the
    /// same atomic step as the index rows.
    pub commit_block_bytes: &'a [u8],
    /// Records to insert/update (`Create` + `Update` op outcomes).
    pub record_upserts: &'a [RecordRow],
    /// Records to delete by `(collection, rkey)` (`Delete` op outcomes).
    pub record_deletes: &'a [(String, String)],
}

/// Atomic-commit dispatcher — implementations persist a [`CommitBatch`]
/// atomically using their backend's native transaction primitive.
///
/// SQL: opens a single sqlx `Transaction` covering `commit_obj`,
/// `repo_block` (commit block) and `repo_record` (upserts +
/// deletes). Fjall: builds a single `WriteBatch` against the
/// matching keyspaces and commits it in one shot. Either way the
/// caller sees an all-or-nothing semantic.
#[async_trait]
pub trait AtomicCommitWriter: Send + Sync {
    /// Apply the batch atomically.
    async fn apply_atomic_commit(&self, did: &str, batch: CommitBatch<'_>) -> PdsResult<()>;
}

/// Per-DID firehose outbox storage.
///
/// Mirrors the per-actor `outbox` table. **No longer the firehose source** —
/// `seq` numbers the stream rather than a repository, so subscribers read
/// [`crate::sequencer::Sequencer`] instead. Retained so that dropping the
/// table is a separate change from redirecting the stream.
#[async_trait]
pub trait OutboxStorage: Send + Sync {
    /// Append a new event. Returns the assigned seq number.
    async fn append(&self, did: &str, event_type: &str, payload: Vec<u8>) -> PdsResult<u64>;

    /// Read up to `limit` rows whose seq is strictly greater than
    /// `after`. `None` for `after` starts at the beginning of the DID's
    /// stream.
    async fn read_after(
        &self,
        did: &str,
        after: Option<u64>,
        limit: u32,
    ) -> PdsResult<Vec<OutboxRow>>;

    /// Highest-issued seq for `did`, or `None` when the DID has no
    /// events yet.
    async fn latest_seq(&self, did: &str) -> PdsResult<Option<u64>>;
}

/// Per-DID blob storage.
///
/// Mirrors `repo_blob` (content-addressed binaries) plus `repo_blob_ref`
/// (record→blob ref-counts). The split between the two reflects the
/// production-default deduplication: many records can reference the same
/// blob, so the bytes live once per actor and refs are decoupled.
#[async_trait]
pub trait BlobStorage: Send + Sync {
    /// Idempotently store blob bytes. Re-uploading the same `(did, cid)` is
    /// a no-op (first MIME type wins).
    async fn put(&self, did: &str, row: &BlobRow) -> PdsResult<()>;

    /// Retrieve blob bytes + MIME type by CID. `Ok(None)` when absent.
    async fn get(&self, did: &str, cid: &str) -> PdsResult<Option<(Vec<u8>, String)>>;

    /// Append a record→blob reference. Idempotent on
    /// `(did, record_uri, blob_cid)`.
    async fn add_ref(&self, did: &str, row: &BlobRefRow) -> PdsResult<()>;

    /// Drop ALL refs for `record_uri` and return the list of blob CIDs whose
    /// ref-count fell to zero (caller GCs the blob bytes).
    async fn drop_refs_for_record(&self, did: &str, record_uri: &str) -> PdsResult<Vec<String>>;

    /// Delete a blob's bytes — typically called only after a `drop_refs_for_record`
    /// reports the CID as orphaned.
    async fn delete_blob(&self, did: &str, cid: &str) -> PdsResult<bool>;

    /// List ALL stored blob CIDs in `did`'s namespace, paginated.
    /// `cursor` is the CID to start *after* (exclusive); rows are sorted
    /// ascending by CID. `limit` is clamped to [1, 1000].
    async fn list_all_cids(
        &self,
        did: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> PdsResult<Vec<String>>;

    /// List referenced-but-absent blob refs (`repo_blob_ref` rows whose
    /// `blob_cid` is missing from `repo_blob`). Used by
    /// `com.atproto.repo.listMissingBlobs`.
    async fn list_missing_refs(
        &self,
        did: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> PdsResult<Vec<BlobRefRow>>;
}
