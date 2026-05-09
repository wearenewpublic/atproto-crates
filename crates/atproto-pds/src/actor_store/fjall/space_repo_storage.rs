//! `FjallSpaceRepoStorage` — `SpaceRepoStorage` impl over fjall partitions.
//!
//!  the fjall profile
//! is the LSM-backed alternative to SQLite. This impl uses the partitions
//! created by [`super::FjallActorStore`] and persists writes via fjall's
//! native `WriteBatch` so commits are atomic across partitions (G36).
//!
//! Key layouts: see [`super::keyspace`].

use super::keyspace::{
    FjallActorStore, oplog_after_rev, oplog_key, oplog_prefix_by_space, record_key, record_prefix,
    repo_state_key,
};
use async_trait::async_trait;
use atproto_space::SpaceError;
use atproto_space::errors::SpaceResult;
use atproto_space::storage::{
    OplogEntry, OplogPage, PreparedCommitRecords, RecordChange, RecordPage, RecordRow, RepoState,
    SpaceRepoStorage,
};
use atproto_space::types::SpaceUri;
use serde::{Deserialize, Serialize};

/// Wire shape of a `space_repo` (commitment) value in fjall.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RepoStateRow {
    set_hash: Vec<u8>,
    rev: String,
}

/// Wire shape of a `space_record` value in fjall.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecordValue {
    cid: String,
    value: Vec<u8>,
    repo_rev: String,
    indexed_at: String,
}

/// Wire shape of a `space_record_oplog` value.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OplogRow {
    action: String,
    collection: Option<String>,
    rkey: Option<String>,
    cid: Option<String>,
    prev: Option<String>,
}

/// Fjall-backed `SpaceRepoStorage`.
pub struct FjallSpaceRepoStorage {
    store: FjallActorStore,
}

impl FjallSpaceRepoStorage {
    /// Construct.
    #[must_use]
    pub fn new(store: FjallActorStore) -> Self {
        Self { store }
    }
}

fn fjall_err(msg: String) -> SpaceError {
    SpaceError::Storage { reason: msg }
}

fn encode<T: Serialize>(value: &T) -> SpaceResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| fjall_err(format!("encode: {e}")))
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> SpaceResult<T> {
    serde_json::from_slice(bytes).map_err(|e| fjall_err(format!("decode: {e}")))
}

#[async_trait]
impl SpaceRepoStorage for FjallSpaceRepoStorage {
    async fn current_state(&self, space: &SpaceUri) -> SpaceResult<RepoState> {
        let key = repo_state_key(&space.to_string());
        let part = self.store.space_repo();
        match part
            .get(&key)
            .map_err(|e| fjall_err(format!("get state: {e}")))?
        {
            None => Ok(RepoState::empty()),
            Some(bytes) => {
                let row: RepoStateRow = decode(&bytes)?;
                Ok(RepoState {
                    set_hash: Some(row.set_hash),
                    rev: Some(row.rev),
                })
            }
        }
    }

    async fn get_record(
        &self,
        space: &SpaceUri,
        collection: &str,
        rkey: &str,
    ) -> SpaceResult<Option<RecordRow>> {
        let key = record_key(&space.to_string(), collection, rkey);
        let part = self.store.space_record();
        match part
            .get(&key)
            .map_err(|e| fjall_err(format!("get record: {e}")))?
        {
            None => Ok(None),
            Some(bytes) => {
                let v: RecordValue = decode(&bytes)?;
                Ok(Some(RecordRow {
                    collection: collection.to_string(),
                    rkey: rkey.to_string(),
                    cid: v.cid,
                    value: v.value,
                    repo_rev: v.repo_rev,
                    indexed_at: v.indexed_at,
                }))
            }
        }
    }

    async fn list_records(
        &self,
        space: &SpaceUri,
        collection: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> SpaceResult<RecordPage> {
        let limit = limit.clamp(1, 100) as usize;
        let prefix = record_prefix(&space.to_string(), collection);
        let part = self.store.space_record();

        let cursor_key = cursor.map(|c| {
            let mut buf = prefix.clone();
            buf.extend_from_slice(c.as_bytes());
            buf.push(0); // strict-greater than the cursor row
            buf
        });

        let mut records = Vec::with_capacity(limit);
        for kv in part.prefix(&prefix) {
            let (k, v) = kv
                .into_inner()
                .map_err(|e| fjall_err(format!("scan record: {e}")))?;
            if let Some(c) = cursor_key.as_ref()
                && k.as_ref() <= c.as_slice()
            {
                continue;
            }
            // Decode the rkey from the trailing segment of the key.
            let suffix = &k[prefix.len()..];
            let rkey =
                std::str::from_utf8(suffix).map_err(|e| fjall_err(format!("rkey utf-8: {e}")))?;
            let value: RecordValue = decode(&v)?;
            records.push(RecordRow {
                collection: collection.to_string(),
                rkey: rkey.to_string(),
                cid: value.cid,
                value: value.value,
                repo_rev: value.repo_rev,
                indexed_at: value.indexed_at,
            });
            if records.len() >= limit {
                break;
            }
        }
        let cursor = records.last().map(|r| r.rkey.clone());
        Ok(RecordPage { records, cursor })
    }

    async fn list_collections(&self, space: &SpaceUri) -> SpaceResult<Vec<String>> {
        let prefix = {
            let mut p = space.to_string().into_bytes();
            p.push(0);
            p
        };
        let part = self.store.space_record();
        let mut collections: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for kv in part.prefix(&prefix) {
            let (k, _) = kv
                .into_inner()
                .map_err(|e| fjall_err(format!("scan collections: {e}")))?;
            // Layout is `<space_uri>\0<collection>\0<rkey>` — find the
            // collection between the first and second null.
            let suffix = &k[prefix.len()..];
            if let Some(end) = suffix.iter().position(|b| *b == 0)
                && let Ok(c) = std::str::from_utf8(&suffix[..end])
            {
                collections.insert(c.to_string());
            }
        }
        Ok(collections.into_iter().collect())
    }

    async fn apply_commit(
        &self,
        space: &SpaceUri,
        commit: PreparedCommitRecords,
    ) -> SpaceResult<()> {
        let space_uri = space.to_string();
        let mut batch = self.store.db().batch();

        for change in commit.record_changes {
            match change {
                RecordChange::Create(row) => {
                    let key = record_key(&space_uri, &row.collection, &row.rkey);
                    let value = encode(&RecordValue {
                        cid: row.cid,
                        value: row.value,
                        repo_rev: row.repo_rev,
                        indexed_at: row.indexed_at,
                    })?;
                    batch.insert(self.store.space_record(), &key, &value);
                }
                RecordChange::Update { row, .. } => {
                    let key = record_key(&space_uri, &row.collection, &row.rkey);
                    let value = encode(&RecordValue {
                        cid: row.cid,
                        value: row.value,
                        repo_rev: row.repo_rev,
                        indexed_at: row.indexed_at,
                    })?;
                    batch.insert(self.store.space_record(), &key, &value);
                }
                RecordChange::Delete {
                    collection, rkey, ..
                } => {
                    let key = record_key(&space_uri, &collection, &rkey);
                    batch.remove(self.store.space_record(), &key);
                }
            }
        }

        for entry in commit.oplog_entries {
            let key = oplog_key(&space_uri, &entry.rev, entry.idx);
            let value = encode(&OplogRow {
                action: entry.action,
                collection: entry.collection,
                rkey: entry.rkey,
                cid: entry.cid,
                prev: entry.prev,
            })?;
            batch.insert(self.store.space_record_oplog(), &key, &value);
        }

        let state_key = repo_state_key(&space_uri);
        let state_value = encode(&RepoStateRow {
            set_hash: commit.new_set_hash,
            rev: commit.rev,
        })?;
        batch.insert(self.store.space_repo(), &state_key, &state_value);

        batch
            .commit()
            .map_err(|e| fjall_err(format!("commit batch: {e}")))?;
        Ok(())
    }

    async fn read_oplog(
        &self,
        space: &SpaceUri,
        since: Option<&str>,
        limit: u32,
    ) -> SpaceResult<OplogPage> {
        let space_uri = space.to_string();
        let limit = limit.clamp(1, 1000) as usize;
        let part = self.store.space_record_oplog();

        let cursor = since.map(|s| oplog_after_rev(&space_uri, s));
        let prefix = oplog_prefix_by_space(&space_uri);

        let mut ops = Vec::with_capacity(limit);
        for kv in part.prefix(&prefix) {
            let (k, v) = kv
                .into_inner()
                .map_err(|e| fjall_err(format!("scan oplog: {e}")))?;
            if let Some(c) = cursor.as_ref()
                && k.as_ref() <= c.as_slice()
            {
                continue;
            }
            // Decode rev + idx from the key.
            let suffix = &k[prefix.len()..];
            let null_pos = suffix
                .iter()
                .position(|b| *b == 0)
                .ok_or_else(|| fjall_err("oplog key missing rev separator".to_string()))?;
            let rev = std::str::from_utf8(&suffix[..null_pos])
                .map_err(|e| fjall_err(format!("rev utf-8: {e}")))?
                .to_string();
            let idx_str = std::str::from_utf8(&suffix[null_pos + 1..])
                .map_err(|e| fjall_err(format!("idx utf-8: {e}")))?;
            let idx: u32 = idx_str
                .parse()
                .map_err(|e| fjall_err(format!("idx parse: {e}")))?;

            let row: OplogRow = decode(&v)?;
            ops.push(OplogEntry {
                rev,
                idx,
                action: row.action,
                collection: row.collection,
                rkey: row.rkey,
                cid: row.cid,
                prev: row.prev,
                did: None,
            });
            if ops.len() >= limit {
                break;
            }
        }
        let state = self.current_state(space).await?;
        Ok(OplogPage { ops, state })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_space::set_hash::XorSha256SetHash;
    use atproto_space::space_repo::{Op, OpAction, SpaceRepo};
    use atproto_space::types::{SpaceKey, SpaceType};
    use tempfile::TempDir;

    fn test_space() -> SpaceUri {
        SpaceUri::new(
            "did:plc:owner".to_string(),
            SpaceType::new("app.bsky.group").unwrap(),
            SpaceKey::new("default").unwrap(),
        )
    }

    type TestRepo = SpaceRepo<FjallSpaceRepoStorage, XorSha256SetHash>;

    fn fresh_storage() -> (FjallSpaceRepoStorage, TempDir) {
        let tmp = TempDir::new().unwrap();
        let store = FjallActorStore::open(tmp.path()).unwrap();
        (FjallSpaceRepoStorage::new(store), tmp)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_then_read_record_round_trip() {
        let (storage, _tmp) = fresh_storage();
        let space = test_space();
        let repo: TestRepo = SpaceRepo::new(space.clone(), storage);
        repo.apply_commit(
            repo.format_commit(&[Op {
                action: OpAction::Create,
                collection: "c".to_string(),
                rkey: "k".to_string(),
                cid: Some("cid_1".to_string()),
                value: Some(vec![1, 2, 3]),
            }])
            .await
            .unwrap(),
        )
        .await
        .unwrap();
        let row = repo.get_record("c", "k").await.unwrap().unwrap();
        assert_eq!(row.cid, "cid_1");
        let st = repo.current_state().await.unwrap();
        assert!(st.set_hash.is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn list_records_paginates() {
        let (storage, _tmp) = fresh_storage();
        let space = test_space();
        let repo: TestRepo = SpaceRepo::new(space.clone(), storage);
        for r in ["a", "b", "c", "d"] {
            repo.apply_commit(
                repo.format_commit(&[Op {
                    action: OpAction::Create,
                    collection: "c".to_string(),
                    rkey: r.to_string(),
                    cid: Some(format!("cid_{r}")),
                    value: Some(vec![]),
                }])
                .await
                .unwrap(),
            )
            .await
            .unwrap();
        }
        let page = repo.list_records("c", None, 2).await.unwrap();
        assert_eq!(page.records.len(), 2);
        let next = repo
            .list_records("c", page.cursor.as_deref(), 10)
            .await
            .unwrap();
        assert_eq!(next.records.len(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn batch_atomic_commit() {
        let (storage, _tmp) = fresh_storage();
        let space = test_space();
        let repo: TestRepo = SpaceRepo::new(space.clone(), storage);
        repo.apply_commit(
            repo.format_commit(&[
                Op {
                    action: OpAction::Create,
                    collection: "c".to_string(),
                    rkey: "a".to_string(),
                    cid: Some("cid_a".to_string()),
                    value: Some(vec![]),
                },
                Op {
                    action: OpAction::Create,
                    collection: "c".to_string(),
                    rkey: "b".to_string(),
                    cid: Some("cid_b".to_string()),
                    value: Some(vec![]),
                },
            ])
            .await
            .unwrap(),
        )
        .await
        .unwrap();
        let oplog = repo.read_oplog(None, 100).await.unwrap();
        assert_eq!(oplog.ops.len(), 2);
        assert_eq!(oplog.ops[0].rev, oplog.ops[1].rev);
        assert_eq!(oplog.ops[0].idx, 0);
        assert_eq!(oplog.ops[1].idx, 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn delete_then_read_returns_none() {
        let (storage, _tmp) = fresh_storage();
        let space = test_space();
        let repo: TestRepo = SpaceRepo::new(space.clone(), storage);
        repo.apply_commit(
            repo.format_commit(&[Op {
                action: OpAction::Create,
                collection: "c".to_string(),
                rkey: "k".to_string(),
                cid: Some("cid".to_string()),
                value: Some(vec![]),
            }])
            .await
            .unwrap(),
        )
        .await
        .unwrap();
        repo.apply_commit(
            repo.format_commit(&[Op {
                action: OpAction::Delete,
                collection: "c".to_string(),
                rkey: "k".to_string(),
                cid: None,
                value: None,
            }])
            .await
            .unwrap(),
        )
        .await
        .unwrap();
        assert!(repo.get_record("c", "k").await.unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn since_filter_excludes_prior_revs() {
        let (storage, _tmp) = fresh_storage();
        let space = test_space();
        let repo: TestRepo = SpaceRepo::new(space.clone(), storage);
        let first = repo
            .format_commit(&[Op {
                action: OpAction::Create,
                collection: "c".to_string(),
                rkey: "a".to_string(),
                cid: Some("cid_a".to_string()),
                value: Some(vec![]),
            }])
            .await
            .unwrap();
        let first_rev = first.rev.clone();
        repo.apply_commit(first).await.unwrap();
        repo.apply_commit(
            repo.format_commit(&[Op {
                action: OpAction::Create,
                collection: "c".to_string(),
                rkey: "b".to_string(),
                cid: Some("cid_b".to_string()),
                value: Some(vec![]),
            }])
            .await
            .unwrap(),
        )
        .await
        .unwrap();
        let oplog = repo.read_oplog(Some(&first_rev), 100).await.unwrap();
        assert_eq!(oplog.ops.len(), 1);
        assert_eq!(oplog.ops[0].rkey.as_deref(), Some("b"));
    }
}
