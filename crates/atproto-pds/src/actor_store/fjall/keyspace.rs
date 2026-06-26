//! `FjallActorStore` — top-level fjall database for the PDS.
//!
//! Holds one `Database` per data-dir. (G18), this is the
//! co-equal alternative to `SqlActorStore` selected at compile time via the
//! `fjall` Cargo feature.
//!
//! Fjall 3.x renamed "keyspace" → "Database" and "partition" → "Keyspace",
//! so the public API uses `Database::keyspace(name)` to get a typed handle.
//! We reserve one keyspace per logical table (G3 partition split) so the
//! Spaces tables can be opened/recovered independently of the public-realm
//! tables.

use crate::errors::{PdsError, PdsResult};
use fjall::{Config, Database, Keyspace, KeyspaceCreateOptions};
use std::path::Path;
use std::sync::Arc;

/// Logical-table names (one fjall keyspace each, per G3).
pub const PART_SPACE_REPO: &str = "space_repo";
pub const PART_SPACE_RECORD: &str = "space_record";
pub const PART_SPACE_RECORD_OPLOG: &str = "space_record_oplog";
pub const PART_SPACE_MEMBER: &str = "space_member";
pub const PART_SPACE_MEMBER_STATE: &str = "space_member_state";
pub const PART_SPACE_MEMBER_OPLOG: &str = "space_member_oplog";

// §1.2 — public-realm partitions, mirroring the SQL schema in
// `migrations/actor/20260501000001_init.sql`. The keying schemes are
// documented per-helper below.
pub const PART_COMMIT_OBJ: &str = "commit_obj";
pub const PART_COMMIT_BY_REV: &str = "commit_by_rev";
pub const PART_REPO_BLOCK: &str = "repo_block";
pub const PART_REPO_RECORD: &str = "repo_record";
pub const PART_REPO_RECORD_BY_COLLECTION: &str = "repo_record_by_collection";
pub const PART_REPO_BLOB_REF: &str = "repo_blob_ref";
pub const PART_REPO_BLOB: &str = "repo_blob";
pub const PART_OUTBOX: &str = "outbox";
pub const PART_OUTBOX_META: &str = "outbox_meta";

/// Fjall-backed actor store.
///
/// One database per data-dir; keyspaces opened lazily on first access.
/// Cheap to clone — internal state is `Arc`-wrapped.
#[derive(Clone)]
pub struct FjallActorStore {
    db: Database,
    keyspaces: Arc<Keyspaces>,
}

struct Keyspaces {
    // Spaces realm.
    pub space_repo: Keyspace,
    pub space_record: Keyspace,
    pub space_record_oplog: Keyspace,
    pub space_member: Keyspace,
    pub space_member_state: Keyspace,
    pub space_member_oplog: Keyspace,
    // Public realm.
    pub commit_obj: Keyspace,
    pub commit_by_rev: Keyspace,
    pub repo_block: Keyspace,
    pub repo_record: Keyspace,
    pub repo_record_by_collection: Keyspace,
    pub repo_blob_ref: Keyspace,
    pub repo_blob: Keyspace,
    pub outbox: Keyspace,
    pub outbox_meta: Keyspace,
}

impl FjallActorStore {
    /// Open (or create) the fjall database at the given path.
    ///
    /// All keyspaces are opened up-front so subsequent operations don't need
    /// to acquire global locks for keyspace discovery.
    pub fn open(path: &Path) -> PdsResult<Self> {
        let db = Database::open(Config::new(path)).map_err(map_fjall)?;
        let opts = KeyspaceCreateOptions::default;
        let keyspaces = Keyspaces {
            space_repo: db.keyspace(PART_SPACE_REPO, opts).map_err(map_fjall)?,
            space_record: db.keyspace(PART_SPACE_RECORD, opts).map_err(map_fjall)?,
            space_record_oplog: db
                .keyspace(PART_SPACE_RECORD_OPLOG, opts)
                .map_err(map_fjall)?,
            space_member: db.keyspace(PART_SPACE_MEMBER, opts).map_err(map_fjall)?,
            space_member_state: db
                .keyspace(PART_SPACE_MEMBER_STATE, opts)
                .map_err(map_fjall)?,
            space_member_oplog: db
                .keyspace(PART_SPACE_MEMBER_OPLOG, opts)
                .map_err(map_fjall)?,
            commit_obj: db.keyspace(PART_COMMIT_OBJ, opts).map_err(map_fjall)?,
            commit_by_rev: db.keyspace(PART_COMMIT_BY_REV, opts).map_err(map_fjall)?,
            repo_block: db.keyspace(PART_REPO_BLOCK, opts).map_err(map_fjall)?,
            repo_record: db.keyspace(PART_REPO_RECORD, opts).map_err(map_fjall)?,
            repo_record_by_collection: db
                .keyspace(PART_REPO_RECORD_BY_COLLECTION, opts)
                .map_err(map_fjall)?,
            repo_blob_ref: db.keyspace(PART_REPO_BLOB_REF, opts).map_err(map_fjall)?,
            repo_blob: db.keyspace(PART_REPO_BLOB, opts).map_err(map_fjall)?,
            outbox: db.keyspace(PART_OUTBOX, opts).map_err(map_fjall)?,
            outbox_meta: db.keyspace(PART_OUTBOX_META, opts).map_err(map_fjall)?,
        };
        Ok(Self {
            db,
            keyspaces: Arc::new(keyspaces),
        })
    }

    /// Persist all in-memory writes to disk synchronously.
    pub fn persist(&self) -> PdsResult<()> {
        self.db
            .persist(fjall::PersistMode::SyncAll)
            .map_err(map_fjall)?;
        Ok(())
    }

    pub(super) fn space_repo(&self) -> &Keyspace {
        &self.keyspaces.space_repo
    }

    pub(super) fn space_record(&self) -> &Keyspace {
        &self.keyspaces.space_record
    }

    pub(super) fn space_record_oplog(&self) -> &Keyspace {
        &self.keyspaces.space_record_oplog
    }

    pub(super) fn space_member(&self) -> &Keyspace {
        &self.keyspaces.space_member
    }

    pub(super) fn space_member_state(&self) -> &Keyspace {
        &self.keyspaces.space_member_state
    }

    pub(super) fn space_member_oplog(&self) -> &Keyspace {
        &self.keyspaces.space_member_oplog
    }

    /// Public-realm: signed commit chain (key = `<did>\0<cid>`).
    pub(super) fn commit_obj(&self) -> &Keyspace {
        &self.keyspaces.commit_obj
    }

    /// Public-realm: secondary commit index by rev (key = `<did>\0<rev>` →
    /// commit CID). Lets the writer's "find latest commit" query stay
    /// O(1) — match the SQL `idx_commit_rev` index.
    pub(super) fn commit_by_rev(&self) -> &Keyspace {
        &self.keyspaces.commit_by_rev
    }

    /// Public-realm: blockstore — DAG-CBOR-encoded MST nodes + record bytes
    /// addressed by their CIDs. Key = `<did>\0<cid_str>`; value = raw bytes.
    pub(super) fn repo_block(&self) -> &Keyspace {
        &self.keyspaces.repo_block
    }

    /// Public-realm: record index. Key = `<did>\0<at_uri>`; value = CBOR
    /// `{cid, collection, rkey, rev, indexed_at}`.
    pub(super) fn repo_record(&self) -> &Keyspace {
        &self.keyspaces.repo_record
    }

    /// Public-realm: secondary record index for `(did, collection, rkey)`
    /// lookup. Key = `<did>\0<collection>\0<rkey>`; value = the at_uri.
    pub(super) fn repo_record_by_collection(&self) -> &Keyspace {
        &self.keyspaces.repo_record_by_collection
    }

    /// Public-realm: blob ref-counting. Key = `<did>\0<record_uri>\0<blob_cid>`;
    /// value = CBOR `{mime_type, size}`.
    pub(super) fn repo_blob_ref(&self) -> &Keyspace {
        &self.keyspaces.repo_blob_ref
    }

    /// Public-realm: blob bytes (content-addressed binaries).
    /// Key = `<did>\0<cid_str>`; value = CBOR
    /// `{mime_type, size, data, created_at}`.
    pub(super) fn repo_blob(&self) -> &Keyspace {
        &self.keyspaces.repo_blob
    }

    /// Public-realm: durable firehose outbox. Key = `<did>\0<seq_be_u64>`;
    /// value = CBOR `{event_type, payload, created_at}`. Per-actor seq
    /// counter lives in `outbox_meta`.
    pub(super) fn outbox(&self) -> &Keyspace {
        &self.keyspaces.outbox
    }

    /// Public-realm: outbox metadata (current seq counter per DID).
    /// Key = `<did>`; value = u64 big-endian.
    pub(super) fn outbox_meta(&self) -> &Keyspace {
        &self.keyspaces.outbox_meta
    }

    pub(super) fn db(&self) -> &Database {
        &self.db
    }
}

fn map_fjall(e: fjall::Error) -> PdsError {
    PdsError::Storage {
        reason: format!("fjall: {e}"),
    }
}

/// Build the row-key for a per-actor `space_record` entry.
///
/// Layout: `<space_uri>\0<collection>\0<rkey>` — null-byte-separated so range
/// scans by `(space_uri, collection)` work as a prefix scan.
#[must_use]
pub fn record_key(space_uri: &str, collection: &str, rkey: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(space_uri.len() + collection.len() + rkey.len() + 2);
    buf.extend_from_slice(space_uri.as_bytes());
    buf.push(0);
    buf.extend_from_slice(collection.as_bytes());
    buf.push(0);
    buf.extend_from_slice(rkey.as_bytes());
    buf
}

/// Prefix for a range scan over `(space_uri, collection)`.
#[must_use]
pub fn record_prefix(space_uri: &str, collection: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(space_uri.len() + collection.len() + 2);
    buf.extend_from_slice(space_uri.as_bytes());
    buf.push(0);
    buf.extend_from_slice(collection.as_bytes());
    buf.push(0);
    buf
}

/// Build the row-key for a `space_repo` (commitment) entry: `<space_uri>`.
#[must_use]
pub fn repo_state_key(space_uri: &str) -> Vec<u8> {
    space_uri.as_bytes().to_vec()
}

/// Build the row-key for a `space_member` entry.
///
/// Layout: `<space_uri>\0<did>` — prefix-scannable by space.
#[must_use]
pub fn member_key(space_uri: &str, did: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(space_uri.len() + did.len() + 1);
    buf.extend_from_slice(space_uri.as_bytes());
    buf.push(0);
    buf.extend_from_slice(did.as_bytes());
    buf
}

/// Prefix for a range scan over members of a single space.
#[must_use]
pub fn member_prefix(space_uri: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(space_uri.len() + 1);
    buf.extend_from_slice(space_uri.as_bytes());
    buf.push(0);
    buf
}

/// Oplog row-key: `<space_uri>\0<rev>\0<idx-zero-padded>`.
///
/// Zero-padded `idx` ensures lexicographic order matches numeric order
/// within a rev. Revs are TIDs (already lex-sortable + monotonic).
#[must_use]
pub fn oplog_key(space_uri: &str, rev: &str, idx: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(space_uri.len() + rev.len() + 12);
    buf.extend_from_slice(space_uri.as_bytes());
    buf.push(0);
    buf.extend_from_slice(rev.as_bytes());
    buf.push(0);
    buf.extend_from_slice(format!("{idx:010}").as_bytes());
    buf
}

/// Prefix scan for oplog by space.
#[must_use]
pub fn oplog_prefix_by_space(space_uri: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(space_uri.len() + 1);
    buf.extend_from_slice(space_uri.as_bytes());
    buf.push(0);
    buf
}

// ---------------------------------------------------------------------------
//  Public-realm key encodings (§1.2). Each row keys a per-DID prefix so
//  range scans by DID are cheap and a single fjall keyspace can hold all
//  actors without cross-DID interference.
// ---------------------------------------------------------------------------

/// Build a `<did>\0<suffix>` key. Used by every public-realm helper below.
fn did_prefixed(did: &str, suffix: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(did.len() + 1 + suffix.len());
    buf.extend_from_slice(did.as_bytes());
    buf.push(0);
    buf.extend_from_slice(suffix);
    buf
}

/// `commit_obj` row-key: `<did>\0<cid_str>`.
#[must_use]
pub fn commit_obj_key(did: &str, cid_str: &str) -> Vec<u8> {
    did_prefixed(did, cid_str.as_bytes())
}

/// `commit_by_rev` row-key: `<did>\0<rev>`. Value is the commit CID.
#[must_use]
pub fn commit_by_rev_key(did: &str, rev: &str) -> Vec<u8> {
    did_prefixed(did, rev.as_bytes())
}

/// `repo_block` row-key: `<did>\0<cid_str>`. Value is raw block bytes.
#[must_use]
pub fn repo_block_key(did: &str, cid_str: &str) -> Vec<u8> {
    did_prefixed(did, cid_str.as_bytes())
}

/// Prefix for "all blocks for this DID."
#[must_use]
pub fn repo_block_prefix(did: &str) -> Vec<u8> {
    did_prefixed(did, b"")
}

/// `repo_record` row-key: `<did>\0<at_uri>`.
#[must_use]
pub fn repo_record_key(did: &str, at_uri: &str) -> Vec<u8> {
    did_prefixed(did, at_uri.as_bytes())
}

/// `repo_record_by_collection` row-key: `<did>\0<collection>\0<rkey>`.
/// Value is the at-uri so a `(collection, rkey)` lookup is one read +
/// one indirection into `repo_record`.
#[must_use]
pub fn repo_record_by_collection_key(did: &str, collection: &str, rkey: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(did.len() + collection.len() + rkey.len() + 2);
    buf.extend_from_slice(did.as_bytes());
    buf.push(0);
    buf.extend_from_slice(collection.as_bytes());
    buf.push(0);
    buf.extend_from_slice(rkey.as_bytes());
    buf
}

/// Prefix for "all records in `<collection>` for `<did>`."
#[must_use]
pub fn repo_record_by_collection_prefix(did: &str, collection: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(did.len() + collection.len() + 2);
    buf.extend_from_slice(did.as_bytes());
    buf.push(0);
    buf.extend_from_slice(collection.as_bytes());
    buf.push(0);
    buf
}

/// `repo_blob_ref` row-key: `<did>\0<record_uri>\0<blob_cid>`.
///
/// Currently unused — staged for the future `BlobStorage` trait impl.
#[allow(dead_code)]
#[must_use]
pub fn repo_blob_ref_key(did: &str, record_uri: &str, blob_cid: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(did.len() + record_uri.len() + blob_cid.len() + 2);
    buf.extend_from_slice(did.as_bytes());
    buf.push(0);
    buf.extend_from_slice(record_uri.as_bytes());
    buf.push(0);
    buf.extend_from_slice(blob_cid.as_bytes());
    buf
}

/// Prefix scan for "all blob refs for this DID's record" — matches all
/// `<did>\0<record_uri>\0...` keys.
#[must_use]
pub fn repo_blob_ref_prefix_for_record(did: &str, record_uri: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(did.len() + record_uri.len() + 2);
    buf.extend_from_slice(did.as_bytes());
    buf.push(0);
    buf.extend_from_slice(record_uri.as_bytes());
    buf.push(0);
    buf
}

/// Prefix scan for "all blob refs for this DID."
#[must_use]
pub fn repo_blob_ref_prefix(did: &str) -> Vec<u8> {
    did_prefixed(did, b"")
}

/// `repo_blob` row-key: `<did>\0<cid_str>`. Stores the bytes themselves,
/// content-addressed by CIDv1-raw-sha256.
#[must_use]
pub fn repo_blob_key(did: &str, cid_str: &str) -> Vec<u8> {
    did_prefixed(did, cid_str.as_bytes())
}

/// Prefix scan for "all blobs for this DID."
#[must_use]
pub fn repo_blob_prefix(did: &str) -> Vec<u8> {
    did_prefixed(did, b"")
}

/// `outbox` row-key: `<did>\0<seq_be_u64>`. The big-endian encoding gives
/// the natural lexicographic-equals-numeric ordering that the SQL
/// `INTEGER PRIMARY KEY AUTOINCREMENT` provides.
#[must_use]
pub fn outbox_key(did: &str, seq: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(did.len() + 1 + 8);
    buf.extend_from_slice(did.as_bytes());
    buf.push(0);
    buf.extend_from_slice(&seq.to_be_bytes());
    buf
}

/// Prefix for "all outbox rows for this DID."
#[must_use]
pub fn outbox_prefix(did: &str) -> Vec<u8> {
    did_prefixed(did, b"")
}

/// Strict-greater outbox cursor: `<did>\0<seq_be_u64>\xFF`. Combined with
/// a forward range scan this matches the SQL `WHERE seq > ?`.
#[must_use]
pub fn outbox_after_seq(did: &str, seq: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(did.len() + 1 + 9);
    buf.extend_from_slice(did.as_bytes());
    buf.push(0);
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.push(0xFF);
    buf
}

/// `outbox_meta` row-key: `<did>`. Value is a `u64` big-endian counter
/// holding the last-issued `seq` for that DID.
#[must_use]
pub fn outbox_meta_key(did: &str) -> Vec<u8> {
    did.as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn database_roundtrip_open_persist_close() {
        let tmp = TempDir::new().unwrap();
        let store = FjallActorStore::open(tmp.path()).unwrap();
        store.space_repo().insert("k", "v").expect("write");
        store.persist().unwrap();
        drop(store);
        let store2 = FjallActorStore::open(tmp.path()).unwrap();
        let v = store2.space_repo().get("k").unwrap().unwrap();
        assert_eq!(&*v, b"v");
    }

    #[test]
    fn record_key_layout_is_prefix_scannable() {
        let k = record_key("ats://did:plc:o/t/k", "c", "rkey-1");
        let prefix = record_prefix("ats://did:plc:o/t/k", "c");
        assert!(k.starts_with(&prefix));
    }

    #[test]
    fn oplog_key_within_rev_orders_by_idx() {
        let k0 = oplog_key("ats://x/y/z", "abc", 0);
        let k1 = oplog_key("ats://x/y/z", "abc", 1);
        let k10 = oplog_key("ats://x/y/z", "abc", 10);
        assert!(k0 < k1);
        assert!(k1 < k10);
    }

    #[test]
    fn oplog_key_orders_across_revs() {
        // A composite `(rev, idx)` cursor resumes at the exact op key, so the
        // last idx of one rev sorts before the first idx of the next rev.
        let rev_a_last = oplog_key("ats://x/y/z", "abc", 99);
        let rev_b_first = oplog_key("ats://x/y/z", "abd", 0);
        assert!(rev_a_last < rev_b_first);
    }
}
