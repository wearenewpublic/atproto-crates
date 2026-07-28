//! Fjall implementations of the public-realm storage traits.
//!
//! Each impl wraps a single fjall partition (or, for `OutboxStorage`,
//! two — the events themselves plus a per-DID seq counter). Every row's
//! key is `<did>\0<...>` so range scans by DID are cheap and a single
//! partition can hold all actors without cross-DID interference.
//!
//! The serialization format is DAG-CBOR via `atproto_dasl` to match the
//! payload shapes used elsewhere in the PDS.

use super::keyspace::{
    FjallActorStore, commit_by_rev_key, commit_obj_key, outbox_after_seq, outbox_key,
    outbox_meta_key, outbox_prefix, repo_blob_key, repo_blob_prefix, repo_blob_ref_key,
    repo_blob_ref_prefix, repo_blob_ref_prefix_for_record, repo_block_key,
    repo_record_by_collection_key, repo_record_by_collection_prefix, repo_record_key,
};
use crate::actor_store::traits::{
    AtomicCommitWriter, BlobRefRow, BlobRow, BlobStorage, CommitBatch, CommitObjStorage, CommitRow,
    OutboxRow, OutboxStorage, RecordRow, RepoRecordStorage,
};
use crate::errors::{PdsError, PdsResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

fn fjall_err(what: &'static str) -> impl FnOnce(fjall::Error) -> PdsError {
    move |e| PdsError::Storage {
        reason: format!("fjall {what}: {e}"),
    }
}

fn cbor_err(what: &'static str) -> impl FnOnce(atproto_dasl::EncodeError) -> PdsError {
    move |e| PdsError::Storage {
        reason: format!("cbor encode {what}: {e}"),
    }
}

fn cbor_decode_err(what: &'static str) -> impl FnOnce(atproto_dasl::DecodeError) -> PdsError {
    move |e| PdsError::Storage {
        reason: format!("cbor decode {what}: {e}"),
    }
}

// ---------------------------------------------------------------------------
//  CommitObjStorage.
// ---------------------------------------------------------------------------

/// Fjall-backed `CommitObjStorage`. Cheap to clone — wraps two partition
/// handles (the primary `commit_obj` partition and the `commit_by_rev`
/// secondary index).
#[derive(Clone)]
pub struct FjallCommitObjStorage {
    store: FjallActorStore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CommitValue {
    rev: String,
    data_cid: String,
    prev_cid: Option<String>,
    prev_data_cid: Option<String>,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
    created_at: String,
}

impl FjallCommitObjStorage {
    /// Construct over an already-open `FjallActorStore`.
    #[must_use]
    pub fn new(store: FjallActorStore) -> Self {
        Self { store }
    }

    fn decode(cid: String, value: &[u8]) -> PdsResult<CommitRow> {
        let v: CommitValue = atproto_dasl::from_slice(value).map_err(cbor_decode_err("commit"))?;
        Ok(CommitRow {
            cid,
            rev: v.rev,
            data_cid: v.data_cid,
            prev_cid: v.prev_cid,
            prev_data_cid: v.prev_data_cid,
            signature: v.signature,
            created_at: v.created_at,
        })
    }
}

#[async_trait]
impl CommitObjStorage for FjallCommitObjStorage {
    async fn insert(&self, did: &str, row: &CommitRow) -> PdsResult<()> {
        let value = CommitValue {
            rev: row.rev.clone(),
            data_cid: row.data_cid.clone(),
            prev_cid: row.prev_cid.clone(),
            prev_data_cid: row.prev_data_cid.clone(),
            signature: row.signature.clone(),
            created_at: row.created_at.clone(),
        };
        let bytes = atproto_dasl::to_vec(&value).map_err(cbor_err("commit"))?;
        let mut batch = self.store.db().batch();
        let primary = self.store.commit_obj();
        let by_rev = self.store.commit_by_rev();
        batch.insert(primary, commit_obj_key(did, &row.cid), bytes);
        batch.insert(by_rev, commit_by_rev_key(did, &row.rev), row.cid.as_bytes());
        batch.commit().map_err(fjall_err("commit_obj insert"))?;
        Ok(())
    }

    async fn latest(&self, did: &str) -> PdsResult<Option<CommitRow>> {
        let by_rev = self.store.commit_by_rev();
        // Reverse-iterate the per-DID prefix range to find the highest rev.
        // TIDs are lex-sortable, so the largest key in lex order is the
        // newest commit.
        let mut prefix = did.as_bytes().to_vec();
        prefix.push(0);
        let mut latest_rev: Option<(Vec<u8>, Vec<u8>)> = None;
        for kv in by_rev.prefix(&prefix) {
            let (k, v) = kv.into_inner().map_err(fjall_err("commit_by_rev scan"))?;
            let kv_pair = (k.to_vec(), v.to_vec());
            match latest_rev.as_ref() {
                Some((existing_k, _)) if existing_k.as_slice() >= kv_pair.0.as_slice() => {}
                _ => latest_rev = Some(kv_pair),
            }
        }
        let Some((_k, cid_bytes)) = latest_rev else {
            return Ok(None);
        };
        let cid = String::from_utf8(cid_bytes).map_err(|e| PdsError::Storage {
            reason: format!("commit cid utf-8: {e}"),
        })?;
        self.get_by_cid(did, &cid).await
    }

    async fn get_by_cid(&self, did: &str, cid: &str) -> PdsResult<Option<CommitRow>> {
        let primary = self.store.commit_obj();
        let key = commit_obj_key(did, cid);
        let value = primary.get(&key).map_err(fjall_err("commit_obj get"))?;
        match value {
            Some(slice) => Self::decode(cid.to_string(), &slice).map(Some),
            None => Ok(None),
        }
    }

    async fn get_by_rev(&self, did: &str, rev: &str) -> PdsResult<Option<CommitRow>> {
        let by_rev = self.store.commit_by_rev();
        let key = commit_by_rev_key(did, rev);
        let cid_bytes = by_rev.get(&key).map_err(fjall_err("commit_by_rev get"))?;
        match cid_bytes {
            Some(slice) => {
                let cid = String::from_utf8(slice.to_vec()).map_err(|e| PdsError::Storage {
                    reason: format!("commit cid utf-8: {e}"),
                })?;
                self.get_by_cid(did, &cid).await
            }
            None => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
//  RepoRecordStorage.
// ---------------------------------------------------------------------------

/// Fjall-backed `RepoRecordStorage`. Wraps the primary `repo_record`
/// partition + the `(collection, rkey)` secondary index.
#[derive(Clone)]
pub struct FjallRepoRecordStorage {
    store: FjallActorStore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecordValue {
    cid: String,
    collection: String,
    rkey: String,
    rev: String,
    indexed_at: String,
}

impl FjallRepoRecordStorage {
    /// Construct over an already-open `FjallActorStore`.
    #[must_use]
    pub fn new(store: FjallActorStore) -> Self {
        Self { store }
    }

    fn decode(uri: String, value: &[u8]) -> PdsResult<RecordRow> {
        let v: RecordValue = atproto_dasl::from_slice(value).map_err(cbor_decode_err("record"))?;
        Ok(RecordRow {
            uri,
            cid: v.cid,
            collection: v.collection,
            rkey: v.rkey,
            rev: v.rev,
            indexed_at: v.indexed_at,
        })
    }
}

#[async_trait]
impl RepoRecordStorage for FjallRepoRecordStorage {
    async fn upsert(&self, did: &str, row: &RecordRow) -> PdsResult<()> {
        // If a prior row exists for this (collection, rkey), drop the old
        // primary key (which may have been a different uri). We don't
        // expect this in practice — the AT-URI is derived from
        // (collection, rkey) — but the SQLite UNIQUE constraint is on
        // (collection, rkey), so we mirror that here.
        let by_coll = self.store.repo_record_by_collection();
        let by_coll_key = repo_record_by_collection_key(did, &row.collection, &row.rkey);
        if let Some(prior_uri_bytes) = by_coll
            .get(&by_coll_key)
            .map_err(fjall_err("record_by_collection get"))?
        {
            let prior_uri =
                String::from_utf8(prior_uri_bytes.to_vec()).map_err(|e| PdsError::Storage {
                    reason: format!("prior uri utf-8: {e}"),
                })?;
            if prior_uri != row.uri {
                let primary = self.store.repo_record();
                primary
                    .remove(repo_record_key(did, &prior_uri))
                    .map_err(fjall_err("record drop prior"))?;
            }
        }

        let value = RecordValue {
            cid: row.cid.clone(),
            collection: row.collection.clone(),
            rkey: row.rkey.clone(),
            rev: row.rev.clone(),
            indexed_at: row.indexed_at.clone(),
        };
        let bytes = atproto_dasl::to_vec(&value).map_err(cbor_err("record"))?;

        let mut batch = self.store.db().batch();
        let primary = self.store.repo_record();
        batch.insert(primary, repo_record_key(did, &row.uri), bytes);
        batch.insert(by_coll, by_coll_key, row.uri.as_bytes());
        batch.commit().map_err(fjall_err("record upsert"))?;
        Ok(())
    }

    async fn delete(&self, did: &str, collection: &str, rkey: &str) -> PdsResult<bool> {
        let by_coll = self.store.repo_record_by_collection();
        let by_coll_key = repo_record_by_collection_key(did, collection, rkey);
        let uri_bytes = by_coll
            .get(&by_coll_key)
            .map_err(fjall_err("record_by_collection get for delete"))?;
        let Some(uri_bytes) = uri_bytes else {
            return Ok(false);
        };
        let uri = String::from_utf8(uri_bytes.to_vec()).map_err(|e| PdsError::Storage {
            reason: format!("uri utf-8: {e}"),
        })?;
        let primary = self.store.repo_record();
        let mut batch = self.store.db().batch();
        batch.remove(primary, repo_record_key(did, &uri));
        batch.remove(by_coll, by_coll_key);
        batch.commit().map_err(fjall_err("record delete"))?;
        Ok(true)
    }

    async fn get_by_uri(&self, did: &str, uri: &str) -> PdsResult<Option<RecordRow>> {
        let primary = self.store.repo_record();
        let key = repo_record_key(did, uri);
        let value = primary.get(&key).map_err(fjall_err("record get_by_uri"))?;
        match value {
            Some(slice) => Self::decode(uri.to_string(), &slice).map(Some),
            None => Ok(None),
        }
    }

    async fn list_by_collection(
        &self,
        did: &str,
        collection: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> PdsResult<Vec<RecordRow>> {
        let by_coll = self.store.repo_record_by_collection();
        let primary = self.store.repo_record();
        let prefix = repo_record_by_collection_prefix(did, collection);
        let cursor_key = cursor.map(|c| repo_record_by_collection_key(did, collection, c));
        let mut out = Vec::with_capacity(limit as usize);
        for kv in by_coll.prefix(&prefix) {
            let (k, v) = kv.into_inner().map_err(fjall_err("record list scan"))?;
            if let Some(cur) = cursor_key.as_ref()
                && k.as_ref() <= cur.as_slice()
            {
                continue;
            }
            let uri = String::from_utf8(v.to_vec()).map_err(|e| PdsError::Storage {
                reason: format!("uri utf-8: {e}"),
            })?;
            let primary_value = primary
                .get(repo_record_key(did, &uri))
                .map_err(fjall_err("record primary fetch"))?;
            if let Some(slice) = primary_value {
                out.push(Self::decode(uri, &slice)?);
            }
            if out.len() >= limit as usize {
                break;
            }
        }
        Ok(out)
    }

    async fn list_collections(&self, did: &str) -> PdsResult<Vec<String>> {
        // The by-collection index keys are `<did>\0<collection>\0<rkey>`.
        // Scan the prefix matching `did` and pick up every distinct
        // collection — same shape as the SQLite `SELECT DISTINCT
        // collection FROM repo_record` path, just one row at a time
        // through the iterator.
        let by_coll = self.store.repo_record_by_collection();
        let mut prefix = did.as_bytes().to_vec();
        prefix.push(0);
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for kv in by_coll.prefix(&prefix) {
            let (k, _v) = kv
                .into_inner()
                .map_err(fjall_err("record collections scan"))?;
            // Strip the `<did>\0` prefix, then take everything up to the
            // next `\0` — that's the collection name.
            let after_did = &k[prefix.len()..];
            let end = after_did
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(after_did.len());
            let coll = std::str::from_utf8(&after_did[..end]).map_err(|e| PdsError::Storage {
                reason: format!("collection utf-8: {e}"),
            })?;
            seen.insert(coll.to_string());
        }
        Ok(seen.into_iter().collect())
    }
}

// ---------------------------------------------------------------------------
//  OutboxStorage.
// ---------------------------------------------------------------------------

/// Fjall-backed `OutboxStorage`. Wraps the events partition + a per-DID
/// seq-counter partition. The counter is updated atomically with each
/// append via a `WriteBatch`.
#[derive(Clone)]
pub struct FjallOutboxStorage {
    store: FjallActorStore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OutboxValue {
    event_type: String,
    #[serde(with = "serde_bytes")]
    payload: Vec<u8>,
    created_at: String,
}

impl FjallOutboxStorage {
    /// Construct over an already-open `FjallActorStore`.
    #[must_use]
    pub fn new(store: FjallActorStore) -> Self {
        Self { store }
    }

    fn decode_seq(slice: &[u8]) -> PdsResult<u64> {
        if slice.len() != 8 {
            return Err(PdsError::Storage {
                reason: format!("outbox_meta value not 8 bytes: got {}", slice.len()),
            });
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(slice);
        Ok(u64::from_be_bytes(buf))
    }

    fn key_to_seq(key: &[u8], did_len: usize) -> PdsResult<u64> {
        if key.len() != did_len + 1 + 8 {
            return Err(PdsError::Storage {
                reason: format!("outbox key has unexpected length {}", key.len()),
            });
        }
        let seq_bytes = &key[did_len + 1..];
        let mut buf = [0u8; 8];
        buf.copy_from_slice(seq_bytes);
        Ok(u64::from_be_bytes(buf))
    }
}

#[async_trait]
impl OutboxStorage for FjallOutboxStorage {
    async fn append(&self, did: &str, event_type: &str, payload: Vec<u8>) -> PdsResult<u64> {
        let meta = self.store.outbox_meta();
        let outbox = self.store.outbox();
        let meta_key = outbox_meta_key(did);
        let prior = meta.get(&meta_key).map_err(fjall_err("outbox_meta get"))?;
        let next_seq = match prior {
            Some(slice) => Self::decode_seq(&slice)? + 1,
            None => 1,
        };
        let value = OutboxValue {
            event_type: event_type.to_string(),
            payload,
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        let bytes = atproto_dasl::to_vec(&value).map_err(cbor_err("outbox"))?;
        let mut batch = self.store.db().batch();
        batch.insert(outbox, outbox_key(did, next_seq), bytes);
        batch.insert(meta, meta_key, next_seq.to_be_bytes().to_vec());
        batch.commit().map_err(fjall_err("outbox append"))?;
        Ok(next_seq)
    }

    async fn read_after(
        &self,
        did: &str,
        after: Option<u64>,
        limit: u32,
    ) -> PdsResult<Vec<OutboxRow>> {
        let outbox = self.store.outbox();
        let did_len = did.len();
        let mut out = Vec::with_capacity(limit as usize);
        let prefix = outbox_prefix(did);
        let cursor = after.map(|seq| outbox_after_seq(did, seq));
        for kv in outbox.prefix(&prefix) {
            let (k, v) = kv.into_inner().map_err(fjall_err("outbox scan"))?;
            if let Some(c) = cursor.as_ref()
                && k.as_ref() < c.as_slice()
            {
                continue;
            }
            let seq = Self::key_to_seq(k.as_ref(), did_len)?;
            let value: OutboxValue =
                atproto_dasl::from_slice(&v).map_err(cbor_decode_err("outbox row"))?;
            out.push(OutboxRow {
                seq,
                event_type: value.event_type,
                payload: value.payload,
                created_at: value.created_at,
            });
            if out.len() >= limit as usize {
                break;
            }
        }
        Ok(out)
    }

    async fn latest_seq(&self, did: &str) -> PdsResult<Option<u64>> {
        let meta = self.store.outbox_meta();
        let value = meta
            .get(outbox_meta_key(did))
            .map_err(fjall_err("outbox_meta latest"))?;
        match value {
            Some(slice) => Self::decode_seq(&slice).map(Some),
            None => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
//  BlobStorage.
// ---------------------------------------------------------------------------

/// Fjall-backed `BlobStorage`. Wraps the `repo_blob` partition (bytes
/// content-addressed by CID) and the `repo_blob_ref` partition
/// (record→blob ref-counts).
#[derive(Clone)]
pub struct FjallBlobStorage {
    store: FjallActorStore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlobValue {
    mime_type: String,
    size: u64,
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
    created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlobRefValue {
    mime_type: String,
    size: u64,
}

impl FjallBlobStorage {
    /// Construct over an already-open `FjallActorStore`.
    #[must_use]
    pub fn new(store: FjallActorStore) -> Self {
        Self { store }
    }

    /// Helper: count the rows in `repo_blob_ref` that reference a given
    /// `(did, blob_cid)` — used by `drop_refs_for_record` to detect
    /// orphaned blobs after a record's refs are dropped.
    fn ref_count(&self, did: &str, blob_cid: &str) -> PdsResult<usize> {
        let prefix = repo_blob_ref_prefix(did);
        let mut count = 0usize;
        for kv in self.store.repo_blob_ref().prefix(&prefix) {
            let (k, _v) = kv.into_inner().map_err(fjall_err("blob_ref scan"))?;
            // Key shape: <did>\0<record_uri>\0<blob_cid>. Trailing field
            // after the second NUL is the blob CID — match it.
            let bytes: &[u8] = &k;
            // skip past did + null
            let mut idx = did.len() + 1;
            // find next null
            let after_record = match bytes[idx..].iter().position(|b| *b == 0) {
                Some(i) => idx + i + 1,
                None => continue,
            };
            idx = after_record;
            let candidate = &bytes[idx..];
            if candidate == blob_cid.as_bytes() {
                count += 1;
            }
        }
        Ok(count)
    }
}

#[async_trait]
impl BlobStorage for FjallBlobStorage {
    async fn put(&self, did: &str, row: &BlobRow) -> PdsResult<()> {
        let key = repo_blob_key(did, &row.cid);
        let parts = self.store.repo_blob();
        // Idempotent: if a row already exists, leave the original
        // mime_type / data in place — matches `INSERT OR IGNORE`
        // semantics on the SQL side.
        if parts
            .get(&key)
            .map_err(fjall_err("blob get-for-idempotent"))?
            .is_some()
        {
            return Ok(());
        }
        let value = BlobValue {
            mime_type: row.mime_type.clone(),
            size: row.size,
            data: row.data.clone(),
            created_at: row.created_at.clone(),
        };
        let bytes = atproto_dasl::to_vec(&value).map_err(cbor_err("blob value"))?;
        parts.insert(&key, bytes).map_err(fjall_err("blob put"))?;
        Ok(())
    }

    async fn get(&self, did: &str, cid: &str) -> PdsResult<Option<(Vec<u8>, String)>> {
        let key = repo_blob_key(did, cid);
        let parts = self.store.repo_blob();
        let raw = parts.get(&key).map_err(fjall_err("blob get"))?;
        match raw {
            None => Ok(None),
            Some(bytes) => {
                let v: BlobValue =
                    atproto_dasl::from_slice(&bytes).map_err(cbor_decode_err("blob value"))?;
                Ok(Some((v.data, v.mime_type)))
            }
        }
    }

    async fn add_ref(&self, did: &str, row: &BlobRefRow) -> PdsResult<()> {
        let key = repo_blob_ref_key(did, &row.record_uri, &row.blob_cid);
        let parts = self.store.repo_blob_ref();
        // Idempotent: if a row already exists, leave it alone.
        if parts
            .get(&key)
            .map_err(fjall_err("blob_ref get-for-idempotent"))?
            .is_some()
        {
            return Ok(());
        }
        let value = BlobRefValue {
            mime_type: row.mime_type.clone(),
            size: row.size,
        };
        let bytes = atproto_dasl::to_vec(&value).map_err(cbor_err("blob_ref value"))?;
        parts
            .insert(&key, bytes)
            .map_err(fjall_err("blob_ref put"))?;
        Ok(())
    }

    async fn drop_refs_for_record(&self, did: &str, record_uri: &str) -> PdsResult<Vec<String>> {
        let prefix = repo_blob_ref_prefix_for_record(did, record_uri);
        // First pass — collect the keys + CIDs that match the record.
        let mut victims: Vec<(Vec<u8>, String)> = Vec::new();
        for kv in self.store.repo_blob_ref().prefix(&prefix) {
            let (k, _v) = kv.into_inner().map_err(fjall_err("blob_ref scan"))?;
            let bytes: &[u8] = &k;
            let mut idx = did.len() + 1;
            let after_record = match bytes[idx..].iter().position(|b| *b == 0) {
                Some(i) => idx + i + 1,
                None => continue,
            };
            idx = after_record;
            let cid_bytes = &bytes[idx..];
            let cid = String::from_utf8_lossy(cid_bytes).into_owned();
            victims.push((bytes.to_vec(), cid));
        }
        // Second pass — delete each ref row.
        let parts = self.store.repo_blob_ref();
        for (k, _) in &victims {
            parts.remove(k).map_err(fjall_err("blob_ref delete"))?;
        }
        // Third pass — for each unique CID in `victims`, count remaining
        // refs; orphans get returned for caller-side blob deletion.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut orphans: Vec<String> = Vec::new();
        for (_, cid) in victims {
            if !seen.insert(cid.clone()) {
                continue;
            }
            if self.ref_count(did, &cid)? == 0 {
                orphans.push(cid);
            }
        }
        Ok(orphans)
    }

    async fn delete_blob(&self, did: &str, cid: &str) -> PdsResult<bool> {
        let key = repo_blob_key(did, cid);
        let parts = self.store.repo_blob();
        let existed = parts
            .get(&key)
            .map_err(fjall_err("blob get-pre-delete"))?
            .is_some();
        if existed {
            parts.remove(&key).map_err(fjall_err("blob delete"))?;
        }
        Ok(existed)
    }

    async fn list_all_cids(
        &self,
        did: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> PdsResult<Vec<String>> {
        let limit = limit.clamp(1, 1000) as usize;
        let prefix = repo_blob_prefix(did);
        let parts = self.store.repo_blob();
        let mut out: Vec<String> = Vec::new();
        for kv in parts.prefix(&prefix) {
            let (k, _v) = kv.into_inner().map_err(fjall_err("blob list scan"))?;
            let bytes: &[u8] = &k;
            // Skip past `<did>\0`
            let cid_bytes = &bytes[did.len() + 1..];
            let cid = String::from_utf8_lossy(cid_bytes).into_owned();
            if let Some(c) = cursor
                && cid.as_str() <= c
            {
                continue;
            }
            out.push(cid);
            if out.len() >= limit {
                break;
            }
        }
        // Underlying iteration order matches lex-key order (ascending)
        // which equals lex-CID order under our `<did>\0<cid>` keying.
        Ok(out)
    }

    async fn list_missing_refs(
        &self,
        did: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> PdsResult<Vec<BlobRefRow>> {
        let limit = limit.clamp(1, 1000) as usize;
        let prefix = repo_blob_ref_prefix(did);
        let mut out: Vec<BlobRefRow> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for kv in self.store.repo_blob_ref().prefix(&prefix) {
            let (k, v) = kv.into_inner().map_err(fjall_err("blob_ref scan"))?;
            let bytes: &[u8] = &k;
            let mut idx = did.len() + 1;
            let after_record = match bytes[idx..].iter().position(|b| *b == 0) {
                Some(i) => idx + i + 1,
                None => continue,
            };
            let record_uri =
                String::from_utf8_lossy(&bytes[did.len() + 1..after_record - 1]).into_owned();
            idx = after_record;
            let cid = String::from_utf8_lossy(&bytes[idx..]).into_owned();
            if !seen.insert(cid.clone()) {
                continue;
            }
            if let Some(c) = cursor
                && cid.as_str() <= c
            {
                continue;
            }
            // Check whether the blob is actually present.
            let blob_key = repo_blob_key(did, &cid);
            let present = self
                .store
                .repo_blob()
                .get(&blob_key)
                .map_err(fjall_err("blob existence check"))?
                .is_some();
            if present {
                continue;
            }
            let v: BlobRefValue =
                atproto_dasl::from_slice(&v).map_err(cbor_decode_err("blob_ref value"))?;
            out.push(BlobRefRow {
                record_uri,
                blob_cid: cid,
                mime_type: v.mime_type,
                size: v.size,
            });
            if out.len() >= limit {
                break;
            }
        }
        // Sort ascending by blob_cid to match the SQL `ORDER BY blob_cid ASC`.
        out.sort_by(|a, b| a.blob_cid.cmp(&b.blob_cid));
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
//  AtomicCommitWriter — single fjall WriteBatch across commit_obj /
//  commit_by_rev / repo_block (commit block) / repo_record /
//  repo_record_by_collection / outbox / outbox_meta.
// ---------------------------------------------------------------------------

/// Fjall-backed [`AtomicCommitWriter`].
///
/// Wraps the actor store and runs the writer's atomic-commit lockstep
/// using `Database::batch().commit()` so every keyspace write lands or
/// none does. Mirrors the SQL flavor's transaction semantic across the
/// fjall partition surface.
#[derive(Clone)]
pub struct FjallAtomicCommitWriter {
    store: FjallActorStore,
}

impl FjallAtomicCommitWriter {
    /// Construct over an already-open `FjallActorStore`.
    #[must_use]
    pub fn new(store: FjallActorStore) -> Self {
        Self { store }
    }
}

#[async_trait]
impl AtomicCommitWriter for FjallAtomicCommitWriter {
    async fn apply_atomic_commit(&self, did: &str, batch: CommitBatch<'_>) -> PdsResult<()> {
        let now = chrono::Utc::now().to_rfc3339();

        // Encode the commit row payload.
        let commit_value = CommitValue {
            rev: batch.commit.rev.clone(),
            data_cid: batch.commit.data_cid.clone(),
            prev_cid: batch.commit.prev_cid.clone(),
            prev_data_cid: batch.commit.prev_data_cid.clone(),
            signature: batch.commit.signature.clone(),
            created_at: now.clone(),
        };
        let commit_bytes = atproto_dasl::to_vec(&commit_value).map_err(cbor_err("commit"))?;

        // Pre-encode all the record-row payloads so the batch step is
        // failure-free.
        let mut record_payloads: Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> =
            Vec::with_capacity(batch.record_upserts.len());
        for row in batch.record_upserts {
            let rv = RecordValue {
                cid: row.cid.clone(),
                collection: row.collection.clone(),
                rkey: row.rkey.clone(),
                rev: row.rev.clone(),
                indexed_at: row.indexed_at.clone(),
            };
            let bytes = atproto_dasl::to_vec(&rv).map_err(cbor_err("record"))?;
            record_payloads.push((
                repo_record_key(did, &row.uri),
                bytes,
                repo_record_by_collection_key(did, &row.collection, &row.rkey),
                row.uri.clone().into_bytes(),
            ));
        }

        // For deletes we need to look up the URI from the
        // by-collection index so we can drop the primary row too.
        let by_coll = self.store.repo_record_by_collection();
        let primary_record = self.store.repo_record();
        let mut delete_pairs: Vec<(Vec<u8>, Vec<u8>)> =
            Vec::with_capacity(batch.record_deletes.len());
        for (collection, rkey) in batch.record_deletes {
            let by_coll_key = repo_record_by_collection_key(did, collection, rkey);
            let uri_bytes = by_coll
                .get(&by_coll_key)
                .map_err(fjall_err("record_by_collection get for delete"))?;
            if let Some(slice) = uri_bytes {
                let uri = String::from_utf8(slice.to_vec()).map_err(|e| PdsError::Storage {
                    reason: format!("uri utf-8: {e}"),
                })?;
                delete_pairs.push((repo_record_key(did, &uri), by_coll_key));
            }
        }

        // Build + commit the atomic batch.
        let commit_obj = self.store.commit_obj();
        let by_rev = self.store.commit_by_rev();
        let repo_block = self.store.repo_block();
        let mut wb = self.store.db().batch();

        wb.insert(
            commit_obj,
            commit_obj_key(did, &batch.commit.cid),
            commit_bytes,
        );
        wb.insert(
            by_rev,
            commit_by_rev_key(did, &batch.commit.rev),
            batch.commit.cid.as_bytes(),
        );
        wb.insert(
            repo_block,
            repo_block_key(did, batch.commit_block_cid),
            batch.commit_block_bytes.to_vec(),
        );
        for (primary_key, payload, by_coll_key, uri_bytes) in record_payloads {
            wb.insert(primary_record, primary_key, payload);
            wb.insert(by_coll, by_coll_key, uri_bytes);
        }
        for (primary_key, by_coll_key) in delete_pairs {
            wb.remove(primary_record, primary_key);
            wb.remove(by_coll, by_coll_key);
        }
        wb.commit().map_err(fjall_err("atomic commit batch"))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, FjallActorStore) {
        let tmp = TempDir::new().unwrap();
        let store = FjallActorStore::open(tmp.path()).unwrap();
        (tmp, store)
    }

    fn test_commit(rev: &str, cid: &str) -> CommitRow {
        CommitRow {
            cid: cid.to_string(),
            rev: rev.to_string(),
            data_cid: format!("data-{rev}"),
            prev_cid: None,
            prev_data_cid: None,
            signature: vec![0u8; 64],
            created_at: "2026-05-06T00:00:00Z".to_string(),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn commit_round_trip() {
        let (_tmp, store) = fresh_store();
        let cs = FjallCommitObjStorage::new(store);
        let row = test_commit("3kmev1", "bafyrei-c1");
        cs.insert("did:plc:alice", &row).await.unwrap();

        let by_cid = cs.get_by_cid("did:plc:alice", "bafyrei-c1").await.unwrap();
        assert_eq!(by_cid, Some(row.clone()));
        let by_rev = cs.get_by_rev("did:plc:alice", "3kmev1").await.unwrap();
        assert_eq!(by_rev, Some(row.clone()));
        let latest = cs.latest("did:plc:alice").await.unwrap();
        assert_eq!(latest, Some(row));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn commit_latest_picks_max_rev() {
        let (_tmp, store) = fresh_store();
        let cs = FjallCommitObjStorage::new(store);
        // TIDs are lex-sortable; "3kmev2" > "3kmev1".
        cs.insert("did:plc:alice", &test_commit("3kmev1", "c1"))
            .await
            .unwrap();
        cs.insert("did:plc:alice", &test_commit("3kmev2", "c2"))
            .await
            .unwrap();
        let latest = cs.latest("did:plc:alice").await.unwrap();
        assert_eq!(latest.unwrap().rev, "3kmev2");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn commits_are_did_isolated() {
        let (_tmp, store) = fresh_store();
        let cs = FjallCommitObjStorage::new(store);
        cs.insert("did:plc:alice", &test_commit("3a", "c-alice"))
            .await
            .unwrap();
        cs.insert("did:plc:bob", &test_commit("3b", "c-bob"))
            .await
            .unwrap();
        assert_eq!(
            cs.latest("did:plc:alice").await.unwrap().unwrap().cid,
            "c-alice"
        );
        assert_eq!(
            cs.latest("did:plc:bob").await.unwrap().unwrap().cid,
            "c-bob"
        );
    }

    fn test_record(uri: &str, collection: &str, rkey: &str) -> RecordRow {
        RecordRow {
            uri: uri.to_string(),
            cid: format!("cid-of-{rkey}"),
            collection: collection.to_string(),
            rkey: rkey.to_string(),
            rev: "3kmev1".to_string(),
            indexed_at: "2026-05-06T00:00:00Z".to_string(),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn record_upsert_get_delete() {
        let (_tmp, store) = fresh_store();
        let rs = FjallRepoRecordStorage::new(store);
        let r = test_record("at://did:plc:alice/c/k1", "c", "k1");
        rs.upsert("did:plc:alice", &r).await.unwrap();
        let got = rs
            .get_by_uri("did:plc:alice", "at://did:plc:alice/c/k1")
            .await
            .unwrap();
        assert_eq!(got, Some(r));
        let removed = rs.delete("did:plc:alice", "c", "k1").await.unwrap();
        assert!(removed);
        let after = rs
            .get_by_uri("did:plc:alice", "at://did:plc:alice/c/k1")
            .await
            .unwrap();
        assert!(after.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn record_list_by_collection_paginates() {
        let (_tmp, store) = fresh_store();
        let rs = FjallRepoRecordStorage::new(store);
        for k in ["k1", "k2", "k3"] {
            let uri = format!("at://did:plc:alice/c/{k}");
            rs.upsert("did:plc:alice", &test_record(&uri, "c", k))
                .await
                .unwrap();
        }
        let page = rs
            .list_by_collection("did:plc:alice", "c", None, 2)
            .await
            .unwrap();
        let keys: Vec<_> = page.iter().map(|r| r.rkey.clone()).collect();
        assert_eq!(keys, vec!["k1".to_string(), "k2".to_string()]);
        let page2 = rs
            .list_by_collection("did:plc:alice", "c", Some("k2"), 10)
            .await
            .unwrap();
        let keys2: Vec<_> = page2.iter().map(|r| r.rkey.clone()).collect();
        assert_eq!(keys2, vec!["k3".to_string()]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn outbox_append_assigns_monotonic_seq() {
        let (_tmp, store) = fresh_store();
        let ob = FjallOutboxStorage::new(store);
        let s1 = ob
            .append("did:plc:alice", "commit", b"a".to_vec())
            .await
            .unwrap();
        let s2 = ob
            .append("did:plc:alice", "commit", b"b".to_vec())
            .await
            .unwrap();
        let s3 = ob
            .append("did:plc:alice", "account", b"c".to_vec())
            .await
            .unwrap();
        assert_eq!((s1, s2, s3), (1, 2, 3));
        assert_eq!(ob.latest_seq("did:plc:alice").await.unwrap(), Some(3));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn outbox_read_after_paginates() {
        let (_tmp, store) = fresh_store();
        let ob = FjallOutboxStorage::new(store);
        for i in 0..5 {
            ob.append("did:plc:alice", "commit", format!("e-{i}").into_bytes())
                .await
                .unwrap();
        }
        let head = ob.read_after("did:plc:alice", None, 3).await.unwrap();
        assert_eq!(head.len(), 3);
        assert_eq!(head[0].seq, 1);
        assert_eq!(head[2].seq, 3);
        let tail = ob.read_after("did:plc:alice", Some(3), 10).await.unwrap();
        let tail_seqs: Vec<_> = tail.iter().map(|r| r.seq).collect();
        assert_eq!(tail_seqs, vec![4, 5]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn outbox_isolates_dids() {
        let (_tmp, store) = fresh_store();
        let ob = FjallOutboxStorage::new(store);
        ob.append("did:plc:alice", "commit", b"a".to_vec())
            .await
            .unwrap();
        ob.append("did:plc:bob", "commit", b"b".to_vec())
            .await
            .unwrap();
        let alice = ob.read_after("did:plc:alice", None, 100).await.unwrap();
        let bob = ob.read_after("did:plc:bob", None, 100).await.unwrap();
        assert_eq!(alice.len(), 1);
        assert_eq!(bob.len(), 1);
        assert_eq!(alice[0].payload, b"a");
        assert_eq!(bob[0].payload, b"b");
        assert_eq!(ob.latest_seq("did:plc:alice").await.unwrap(), Some(1));
        assert_eq!(ob.latest_seq("did:plc:bob").await.unwrap(), Some(1));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn blob_round_trip_and_orphan_gc() {
        let (_tmp, store) = fresh_store();
        let bs = FjallBlobStorage::new(store);
        let did = "did:plc:alice";
        let blob = BlobRow {
            cid: "bafkreig000000000000000000000000000000000000000000000aaaaaa".to_string(),
            mime_type: "text/plain".to_string(),
            size: 5,
            data: b"hello".to_vec(),
            created_at: "2026-05-06T00:00:00Z".to_string(),
        };
        bs.put(did, &blob).await.unwrap();
        // Idempotent.
        bs.put(did, &blob).await.unwrap();

        let (data, mime) = bs.get(did, &blob.cid).await.unwrap().unwrap();
        assert_eq!(data, b"hello");
        assert_eq!(mime, "text/plain");

        // Two refs from different records.
        let r1 = BlobRefRow {
            record_uri: "at://did:plc:alice/c/k1".to_string(),
            blob_cid: blob.cid.clone(),
            mime_type: blob.mime_type.clone(),
            size: blob.size,
        };
        let r2 = BlobRefRow {
            record_uri: "at://did:plc:alice/c/k2".to_string(),
            blob_cid: blob.cid.clone(),
            mime_type: blob.mime_type.clone(),
            size: blob.size,
        };
        bs.add_ref(did, &r1).await.unwrap();
        bs.add_ref(did, &r2).await.unwrap();

        // Drop k1 — k2 still refs the blob, so 0 orphans.
        let orphans = bs
            .drop_refs_for_record(did, "at://did:plc:alice/c/k1")
            .await
            .unwrap();
        assert!(orphans.is_empty());
        assert!(bs.get(did, &blob.cid).await.unwrap().is_some());

        // Drop k2 — now orphaned.
        let orphans = bs
            .drop_refs_for_record(did, "at://did:plc:alice/c/k2")
            .await
            .unwrap();
        assert_eq!(orphans, vec![blob.cid.clone()]);
        let dropped = bs.delete_blob(did, &blob.cid).await.unwrap();
        assert!(dropped);
        assert!(bs.get(did, &blob.cid).await.unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn blob_list_all_cids_and_missing_refs() {
        let (_tmp, store) = fresh_store();
        let bs = FjallBlobStorage::new(store);
        let did = "did:plc:alice";

        // Two stored blobs.
        for cid in ["bafkreig111", "bafkreig222"] {
            let row = BlobRow {
                cid: cid.to_string(),
                mime_type: "text/plain".to_string(),
                size: 1,
                data: vec![0u8],
                created_at: "2026-05-06T00:00:00Z".to_string(),
            };
            bs.put(did, &row).await.unwrap();
        }
        // One ref to a CID that hasn't been uploaded.
        bs.add_ref(
            did,
            &BlobRefRow {
                record_uri: "at://did:plc:alice/c/k".to_string(),
                blob_cid: "bafkreig999".to_string(),
                mime_type: "image/png".to_string(),
                size: 42,
            },
        )
        .await
        .unwrap();

        let listed = bs.list_all_cids(did, None, 100).await.unwrap();
        assert_eq!(listed, vec!["bafkreig111", "bafkreig222"]);

        let missing = bs.list_missing_refs(did, None, 100).await.unwrap();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].blob_cid, "bafkreig999");
        assert_eq!(missing[0].mime_type, "image/png");
        assert_eq!(missing[0].size, 42);
    }
}
