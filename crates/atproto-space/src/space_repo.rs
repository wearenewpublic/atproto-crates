//! `SpaceRepo` orchestrator — formats commits and applies them via storage.
//!
//! This struct wraps a `SpaceRepoStorage` impl and exposes the user-facing API
//! for record CRUD on a permissioned-data space:
//!
//! - `format_commit(ops)` — compute new SetHash, build oplog entries, sign commit.
//! - `apply_commit(commit_data)` — persist via the storage trait atomically.
//! - `get_record`, `list_records`, `list_collections` — pass-through reads.

use crate::errors::{SpaceError, SpaceResult};
use crate::set_hash::{SetHash, record_element_bytes};
use crate::storage::{
    OplogEntry, OplogPage, PreparedCommitRecords, RecordChange, RecordPage, RecordRow, RepoState,
    SpaceRepoStorage,
};
use crate::types::SpaceUri;
use atproto_record::tid::Tid;
use chrono::Utc;

/// Action kind for record CRUD ops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpAction {
    /// Create a new record.
    Create,
    /// Update an existing record.
    Update,
    /// Delete a record.
    Delete,
}

impl OpAction {
    fn as_str(self) -> &'static str {
        match self {
            OpAction::Create => "create",
            OpAction::Update => "update",
            OpAction::Delete => "delete",
        }
    }
}

/// One record op inside a batch.
#[derive(Debug, Clone)]
pub struct Op {
    /// Action kind.
    pub action: OpAction,
    /// NSID collection.
    pub collection: String,
    /// Record key.
    pub rkey: String,
    /// CID of the new value (`None` for delete).
    pub cid: Option<String>,
    /// New record value bytes (DAG-CBOR), `None` for delete.
    pub value: Option<Vec<u8>>,
}

/// A pre-applied commit ready for `apply_commit`.
///
/// Returned by `format_commit`; contains everything the storage layer needs
/// to atomically persist the change set.
#[derive(Debug, Clone)]
pub struct PreparedCommit<H: SetHash> {
    /// New SetHash digest.
    pub set_hash: H,
    /// Rev (TID) for this commit.
    pub rev: String,
    /// Storage-layer prepared commit (pass to `apply_commit`).
    pub storage_commit: PreparedCommitRecords,
}

/// Per-(user, space) record-set orchestrator.
///
/// Holds a reference to the configured storage backend; all reads/writes
/// dispatch through it.
pub struct SpaceRepo<S: SpaceRepoStorage, H: SetHash> {
    space: SpaceUri,
    storage: S,
    /// Ghost — captures the chosen `SetHash` impl at construction.
    _set_hash: std::marker::PhantomData<H>,
}

impl<S: SpaceRepoStorage, H: SetHash> SpaceRepo<S, H> {
    /// Construct a new orchestrator.
    pub fn new(space: SpaceUri, storage: S) -> Self {
        Self {
            space,
            storage,
            _set_hash: std::marker::PhantomData,
        }
    }

    /// Get the bound space URI.
    #[must_use]
    pub fn space(&self) -> &SpaceUri {
        &self.space
    }

    /// Read current `{set_hash, rev}`.
    pub async fn current_state(&self) -> SpaceResult<RepoState> {
        self.storage.current_state(&self.space).await
    }

    /// Read a record.
    pub async fn get_record(&self, collection: &str, rkey: &str) -> SpaceResult<Option<RecordRow>> {
        self.storage.get_record(&self.space, collection, rkey).await
    }

    /// List records in a collection.
    pub async fn list_records(
        &self,
        collection: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> SpaceResult<RecordPage> {
        self.storage
            .list_records(&self.space, collection, cursor, limit)
            .await
    }

    /// List collections.
    pub async fn list_collections(&self) -> SpaceResult<Vec<String>> {
        self.storage.list_collections(&self.space).await
    }

    /// Format a batch of ops into a `PreparedCommit`. Does NOT persist — call
    /// `apply_commit` to persist atomically.
    pub async fn format_commit(&self, ops: &[Op]) -> SpaceResult<PreparedCommit<H>> {
        // Load current state to derive the new SetHash incrementally.
        let state = self.storage.current_state(&self.space).await?;
        let mut set_hash = match state.set_hash {
            Some(bytes) => H::from_digest(&bytes)?,
            None => H::empty(),
        };

        // Generate a single rev for this batch.
        let rev = Tid::new().to_string();
        let now_iso = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        let mut record_changes = Vec::with_capacity(ops.len());
        let mut oplog_entries = Vec::with_capacity(ops.len());

        for (idx, op) in ops.iter().enumerate() {
            let prior = self
                .storage
                .get_record(&self.space, &op.collection, &op.rkey)
                .await?;

            match op.action {
                OpAction::Create => {
                    if prior.is_some() {
                        return Err(SpaceError::RecordAlreadyExists {
                            collection: op.collection.clone(),
                            rkey: op.rkey.clone(),
                        });
                    }
                    let cid = op.cid.clone().ok_or_else(|| SpaceError::ContextEncoding {
                        reason: "create requires cid".to_string(),
                    })?;
                    let value = op
                        .value
                        .clone()
                        .ok_or_else(|| SpaceError::ContextEncoding {
                            reason: "create requires value".to_string(),
                        })?;

                    set_hash.add(&record_element_bytes(&op.collection, &op.rkey, &cid));

                    record_changes.push(RecordChange::Create(RecordRow {
                        collection: op.collection.clone(),
                        rkey: op.rkey.clone(),
                        cid: cid.clone(),
                        value,
                        repo_rev: rev.clone(),
                        indexed_at: now_iso.clone(),
                    }));
                    oplog_entries.push(OplogEntry {
                        rev: rev.clone(),
                        idx: idx as u32,
                        action: op.action.as_str().to_string(),
                        collection: Some(op.collection.clone()),
                        rkey: Some(op.rkey.clone()),
                        cid: Some(cid),
                        prev: None,
                        did: None,
                    });
                }
                OpAction::Update => {
                    let prior_row = prior.ok_or_else(|| SpaceError::RecordNotFound {
                        collection: op.collection.clone(),
                        rkey: op.rkey.clone(),
                    })?;
                    let new_cid = op.cid.clone().ok_or_else(|| SpaceError::ContextEncoding {
                        reason: "update requires cid".to_string(),
                    })?;
                    let value = op
                        .value
                        .clone()
                        .ok_or_else(|| SpaceError::ContextEncoding {
                            reason: "update requires value".to_string(),
                        })?;

                    set_hash.remove(&record_element_bytes(
                        &op.collection,
                        &op.rkey,
                        &prior_row.cid,
                    ));
                    set_hash.add(&record_element_bytes(&op.collection, &op.rkey, &new_cid));

                    record_changes.push(RecordChange::Update {
                        row: RecordRow {
                            collection: op.collection.clone(),
                            rkey: op.rkey.clone(),
                            cid: new_cid.clone(),
                            value,
                            repo_rev: rev.clone(),
                            indexed_at: now_iso.clone(),
                        },
                        prior_cid: prior_row.cid.clone(),
                    });
                    oplog_entries.push(OplogEntry {
                        rev: rev.clone(),
                        idx: idx as u32,
                        action: op.action.as_str().to_string(),
                        collection: Some(op.collection.clone()),
                        rkey: Some(op.rkey.clone()),
                        cid: Some(new_cid),
                        prev: Some(prior_row.cid),
                        did: None,
                    });
                }
                OpAction::Delete => {
                    let prior_row = prior.ok_or_else(|| SpaceError::RecordNotFound {
                        collection: op.collection.clone(),
                        rkey: op.rkey.clone(),
                    })?;

                    set_hash.remove(&record_element_bytes(
                        &op.collection,
                        &op.rkey,
                        &prior_row.cid,
                    ));

                    record_changes.push(RecordChange::Delete {
                        collection: op.collection.clone(),
                        rkey: op.rkey.clone(),
                        prior_cid: prior_row.cid.clone(),
                    });
                    oplog_entries.push(OplogEntry {
                        rev: rev.clone(),
                        idx: idx as u32,
                        action: op.action.as_str().to_string(),
                        collection: Some(op.collection.clone()),
                        rkey: Some(op.rkey.clone()),
                        cid: None,
                        prev: Some(prior_row.cid),
                        did: None,
                    });
                }
            }
        }

        let new_digest = set_hash.digest();
        Ok(PreparedCommit {
            set_hash,
            rev: rev.clone(),
            storage_commit: PreparedCommitRecords {
                new_set_hash: new_digest,
                rev,
                record_changes,
                oplog_entries,
            },
        })
    }

    /// Persist a `PreparedCommit` atomically.
    pub async fn apply_commit(&self, prepared: PreparedCommit<H>) -> SpaceResult<()> {
        self.storage
            .apply_commit(&self.space, prepared.storage_commit)
            .await
    }

    /// Read oplog entries since the given rev (exclusive). `None` = from start.
    pub async fn read_oplog(&self, since: Option<&str>, limit: u32) -> SpaceResult<OplogPage> {
        self.storage.read_oplog(&self.space, since, limit).await
    }
}

/// In-memory `SpaceRepoStorage` implementation for testing and AppView consumers.
pub mod memory {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// In-memory store. Not for production — does not persist.
    pub struct InMemorySpaceRepoStorage {
        inner: Mutex<Inner>,
    }

    struct Inner {
        // Per-space record map: `(collection, rkey)` → RecordRow.
        records: BTreeMap<(SpaceUri, String, String), RecordRow>,
        // Per-space state.
        states: BTreeMap<SpaceUri, RepoState>,
        // Per-space oplog: `(space, rev, idx)` → OplogEntry.
        oplog: BTreeMap<(SpaceUri, String, u32), OplogEntry>,
    }

    impl InMemorySpaceRepoStorage {
        /// Construct a fresh in-memory store.
        pub fn new() -> Self {
            Self {
                inner: Mutex::new(Inner {
                    records: BTreeMap::new(),
                    states: BTreeMap::new(),
                    oplog: BTreeMap::new(),
                }),
            }
        }
    }

    impl Default for InMemorySpaceRepoStorage {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait::async_trait]
    impl SpaceRepoStorage for InMemorySpaceRepoStorage {
        async fn current_state(&self, space: &SpaceUri) -> SpaceResult<RepoState> {
            let inner = self.inner.lock().unwrap();
            Ok(inner
                .states
                .get(space)
                .cloned()
                .unwrap_or_else(RepoState::empty))
        }

        async fn get_record(
            &self,
            space: &SpaceUri,
            collection: &str,
            rkey: &str,
        ) -> SpaceResult<Option<RecordRow>> {
            let inner = self.inner.lock().unwrap();
            Ok(inner
                .records
                .get(&(space.clone(), collection.to_string(), rkey.to_string()))
                .cloned())
        }

        async fn list_records(
            &self,
            space: &SpaceUri,
            collection: &str,
            cursor: Option<&str>,
            limit: u32,
        ) -> SpaceResult<RecordPage> {
            let inner = self.inner.lock().unwrap();
            let mut rows: Vec<RecordRow> = inner
                .records
                .iter()
                .filter(|((s, c, _), _)| s == space && c == collection)
                .filter(|((_, _, rkey), _)| match cursor {
                    Some(cur) => rkey.as_str() > cur,
                    None => true,
                })
                .map(|(_, row)| row.clone())
                .collect();
            rows.sort_by(|a, b| a.rkey.cmp(&b.rkey));
            let cursor_out = if rows.len() > limit as usize {
                rows.truncate(limit as usize);
                rows.last().map(|r| r.rkey.clone())
            } else {
                None
            };
            Ok(RecordPage {
                records: rows,
                cursor: cursor_out,
            })
        }

        async fn list_collections(&self, space: &SpaceUri) -> SpaceResult<Vec<String>> {
            let inner = self.inner.lock().unwrap();
            let mut cols: Vec<String> = inner
                .records
                .keys()
                .filter(|(s, _, _)| s == space)
                .map(|(_, c, _)| c.clone())
                .collect();
            cols.sort();
            cols.dedup();
            Ok(cols)
        }

        async fn apply_commit(
            &self,
            space: &SpaceUri,
            commit: PreparedCommitRecords,
        ) -> SpaceResult<()> {
            let mut inner = self.inner.lock().unwrap();
            for change in commit.record_changes {
                match change {
                    RecordChange::Create(row) => {
                        inner.records.insert(
                            (space.clone(), row.collection.clone(), row.rkey.clone()),
                            row,
                        );
                    }
                    RecordChange::Update { row, .. } => {
                        inner.records.insert(
                            (space.clone(), row.collection.clone(), row.rkey.clone()),
                            row,
                        );
                    }
                    RecordChange::Delete {
                        collection, rkey, ..
                    } => {
                        inner.records.remove(&(space.clone(), collection, rkey));
                    }
                }
            }
            for entry in commit.oplog_entries {
                inner
                    .oplog
                    .insert((space.clone(), entry.rev.clone(), entry.idx), entry);
            }
            inner.states.insert(
                space.clone(),
                RepoState {
                    set_hash: Some(commit.new_set_hash),
                    rev: Some(commit.rev),
                },
            );
            Ok(())
        }

        async fn read_oplog(
            &self,
            space: &SpaceUri,
            since: Option<&str>,
            limit: u32,
        ) -> SpaceResult<OplogPage> {
            let inner = self.inner.lock().unwrap();
            let mut ops: Vec<OplogEntry> = inner
                .oplog
                .iter()
                .filter(|((s, rev, _), _)| {
                    s == space
                        && match since {
                            Some(cur) => rev.as_str() > cur,
                            None => true,
                        }
                })
                .map(|(_, e)| e.clone())
                .collect();
            ops.sort_by(|a, b| (a.rev.as_str(), a.idx).cmp(&(b.rev.as_str(), b.idx)));
            ops.truncate(limit as usize);
            let state = inner
                .states
                .get(space)
                .cloned()
                .unwrap_or_else(RepoState::empty);
            Ok(OplogPage { ops, state })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::memory::InMemorySpaceRepoStorage;
    use super::*;
    use crate::set_hash::XorSha256SetHash;
    use crate::types::{SpaceKey, SpaceType};

    fn test_space() -> SpaceUri {
        SpaceUri::new(
            "did:plc:owner".to_string(),
            SpaceType::new("app.bsky.group").unwrap(),
            SpaceKey::new("default").unwrap(),
        )
    }

    type TestRepo = SpaceRepo<InMemorySpaceRepoStorage, XorSha256SetHash>;

    #[tokio::test]
    async fn create_then_read() {
        let space = test_space();
        let repo: TestRepo = SpaceRepo::new(space.clone(), InMemorySpaceRepoStorage::new());

        let ops = vec![Op {
            action: OpAction::Create,
            collection: "app.bsky.feed.post".to_string(),
            rkey: "3jui7kd2z2y2e".to_string(),
            cid: Some("bafy123".to_string()),
            value: Some(vec![1, 2, 3]),
        }];

        let prepared = repo.format_commit(&ops).await.unwrap();
        repo.apply_commit(prepared).await.unwrap();

        let row = repo
            .get_record("app.bsky.feed.post", "3jui7kd2z2y2e")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.cid, "bafy123");
    }

    #[tokio::test]
    async fn create_then_update_then_delete() {
        let space = test_space();
        let repo: TestRepo = SpaceRepo::new(space.clone(), InMemorySpaceRepoStorage::new());

        let create = vec![Op {
            action: OpAction::Create,
            collection: "c".to_string(),
            rkey: "k".to_string(),
            cid: Some("cid_v1".to_string()),
            value: Some(vec![1]),
        }];
        repo.apply_commit(repo.format_commit(&create).await.unwrap())
            .await
            .unwrap();

        let update = vec![Op {
            action: OpAction::Update,
            collection: "c".to_string(),
            rkey: "k".to_string(),
            cid: Some("cid_v2".to_string()),
            value: Some(vec![2]),
        }];
        repo.apply_commit(repo.format_commit(&update).await.unwrap())
            .await
            .unwrap();
        let row = repo.get_record("c", "k").await.unwrap().unwrap();
        assert_eq!(row.cid, "cid_v2");

        let delete = vec![Op {
            action: OpAction::Delete,
            collection: "c".to_string(),
            rkey: "k".to_string(),
            cid: None,
            value: None,
        }];
        repo.apply_commit(repo.format_commit(&delete).await.unwrap())
            .await
            .unwrap();
        assert!(repo.get_record("c", "k").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn duplicate_create_rejected() {
        let space = test_space();
        let repo: TestRepo = SpaceRepo::new(space.clone(), InMemorySpaceRepoStorage::new());

        let op = Op {
            action: OpAction::Create,
            collection: "c".to_string(),
            rkey: "k".to_string(),
            cid: Some("x".to_string()),
            value: Some(vec![]),
        };
        repo.apply_commit(repo.format_commit(std::slice::from_ref(&op)).await.unwrap())
            .await
            .unwrap();

        let result = repo.format_commit(&[op]).await;
        assert!(matches!(
            result,
            Err(SpaceError::RecordAlreadyExists { .. })
        ));
    }

    #[tokio::test]
    async fn update_missing_rejected() {
        let space = test_space();
        let repo: TestRepo = SpaceRepo::new(space, InMemorySpaceRepoStorage::new());

        let op = Op {
            action: OpAction::Update,
            collection: "c".to_string(),
            rkey: "absent".to_string(),
            cid: Some("x".to_string()),
            value: Some(vec![]),
        };
        let result = repo.format_commit(&[op]).await;
        assert!(matches!(result, Err(SpaceError::RecordNotFound { .. })));
    }

    /// Atomic batch: a single `format_commit` over multiple ops shares a `rev`
    /// with monotonic `idx` values.
    #[tokio::test]
    async fn atomic_batch_shared_rev() {
        let space = test_space();
        let repo: TestRepo = SpaceRepo::new(space, InMemorySpaceRepoStorage::new());

        let ops = vec![
            Op {
                action: OpAction::Create,
                collection: "c".to_string(),
                rkey: "k1".to_string(),
                cid: Some("x1".to_string()),
                value: Some(vec![]),
            },
            Op {
                action: OpAction::Create,
                collection: "c".to_string(),
                rkey: "k2".to_string(),
                cid: Some("x2".to_string()),
                value: Some(vec![]),
            },
        ];
        let prepared = repo.format_commit(&ops).await.unwrap();
        repo.apply_commit(prepared).await.unwrap();

        let page = repo.read_oplog(None, 100).await.unwrap();
        assert_eq!(page.ops.len(), 2);
        assert_eq!(page.ops[0].rev, page.ops[1].rev, "shared rev");
        assert_eq!(page.ops[0].idx, 0);
        assert_eq!(page.ops[1].idx, 1);
    }
}
