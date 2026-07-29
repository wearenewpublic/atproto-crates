//! `SqlSpaceRepoStorage` — `SpaceRepoStorage` impl over per-actor SQLite.
//!
//! Backs the per-(user, space) record commitment + oplog using the
//! `space_record`, `space_repo`, and `space_record_oplog` tables. All
//! mutating operations apply atomically inside a single SQL transaction.

use async_trait::async_trait;
use atproto_space::SpaceError;
use atproto_space::errors::SpaceResult;
use atproto_space::storage::{
    OplogCursor, OplogEntry, OplogPage, PreparedCommitRecords, RecordChange, RecordPage, RecordRow,
    RepoState, SpaceRepoStorage,
};
use atproto_space::types::SpaceUri;
use sqlx::SqlitePool;

/// SQLite-backed `SpaceRepoStorage`.
pub struct SqlSpaceRepoStorage {
    pool: SqlitePool,
}

impl SqlSpaceRepoStorage {
    /// Construct over a per-actor pool (e.g., `SqlActorStore::pool().clone()`).
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

fn sql_err(reason: String) -> SpaceError {
    SpaceError::Storage { reason }
}

async fn ensure_space_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    space: &SpaceUri,
) -> SpaceResult<()> {
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT OR IGNORE INTO space (uri, is_owner, is_member, created_at) VALUES (?, 0, 0, ?)",
    )
    .bind(space.to_string())
    .bind(&now)
    .execute(&mut **tx)
    .await
    .map_err(|e| sql_err(format!("ensure_space_row: {e}")))?;
    Ok(())
}

#[async_trait]
impl SpaceRepoStorage for SqlSpaceRepoStorage {
    async fn current_state(&self, space: &SpaceUri) -> SpaceResult<RepoState> {
        let row: Option<(Option<Vec<u8>>, Option<String>)> =
            sqlx::query_as("SELECT set_hash, rev FROM space_repo WHERE space = ?")
                .bind(space.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| sql_err(format!("current_state: {e}")))?;
        Ok(match row {
            Some((set_hash, rev)) => RepoState { set_hash, rev },
            None => RepoState::empty(),
        })
    }

    async fn get_record(
        &self,
        space: &SpaceUri,
        collection: &str,
        rkey: &str,
    ) -> SpaceResult<Option<RecordRow>> {
        let row: Option<(String, Vec<u8>, String, String)> = sqlx::query_as(
            "SELECT cid, value, repo_rev, indexed_at FROM space_record
             WHERE space = ? AND collection = ? AND rkey = ?",
        )
        .bind(space.to_string())
        .bind(collection)
        .bind(rkey)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| sql_err(format!("get_record: {e}")))?;
        Ok(row.map(|(cid, value, repo_rev, indexed_at)| RecordRow {
            collection: collection.to_string(),
            rkey: rkey.to_string(),
            cid,
            value,
            repo_rev,
            indexed_at,
        }))
    }

    async fn list_records(
        &self,
        space: &SpaceUri,
        collection: &str,
        cursor: Option<&str>,
        limit: u32,
        reverse: bool,
    ) -> SpaceResult<RecordPage> {
        let limit = limit.clamp(1, 100);
        // Direction flips both the ordering and the cursor comparison; getting
        // one without the other returns the first page forever.
        let (order, cmp) = if reverse { ("DESC", "<") } else { ("ASC", ">") };
        let rows: Vec<(String, String, Vec<u8>, String, String)> = match cursor {
            Some(cur) => {
                sqlx::query_as(&format!(
                    "SELECT rkey, cid, value, repo_rev, indexed_at FROM space_record
                 WHERE space = ? AND collection = ? AND rkey {cmp} ?
                 ORDER BY rkey {order} LIMIT ?"
                ))
                .bind(space.to_string())
                .bind(collection)
                .bind(cur)
                .bind(limit as i64)
                .fetch_all(&self.pool)
                .await
            }
            None => {
                sqlx::query_as(&format!(
                    "SELECT rkey, cid, value, repo_rev, indexed_at FROM space_record
                 WHERE space = ? AND collection = ?
                 ORDER BY rkey {order} LIMIT ?"
                ))
                .bind(space.to_string())
                .bind(collection)
                .bind(limit as i64)
                .fetch_all(&self.pool)
                .await
            }
        }
        .map_err(|e| sql_err(format!("list_records: {e}")))?;
        let cursor = rows.last().map(|(rkey, _, _, _, _)| rkey.clone());
        let records = rows
            .into_iter()
            .map(|(rkey, cid, value, repo_rev, indexed_at)| RecordRow {
                collection: collection.to_string(),
                rkey,
                cid,
                value,
                repo_rev,
                indexed_at,
            })
            .collect();
        Ok(RecordPage { records, cursor })
    }

    async fn list_collections(&self, space: &SpaceUri) -> SpaceResult<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT DISTINCT collection FROM space_record
             WHERE space = ? ORDER BY collection ASC",
        )
        .bind(space.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| sql_err(format!("list_collections: {e}")))?;
        Ok(rows.into_iter().map(|(c,)| c).collect())
    }

    async fn apply_commit(
        &self,
        space: &SpaceUri,
        commit: PreparedCommitRecords,
    ) -> SpaceResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| sql_err(format!("apply_commit begin: {e}")))?;
        ensure_space_row(&mut tx, space).await?;

        for change in commit.record_changes {
            match change {
                RecordChange::Create(row) => {
                    sqlx::query(
                        "INSERT INTO space_record (space, collection, rkey, cid, value, repo_rev, indexed_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?)",
                    )
                    .bind(space.to_string())
                    .bind(&row.collection)
                    .bind(&row.rkey)
                    .bind(&row.cid)
                    .bind(&row.value)
                    .bind(&row.repo_rev)
                    .bind(&row.indexed_at)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| sql_err(format!("apply_commit insert: {e}")))?;
                }
                RecordChange::Update { row, .. } => {
                    sqlx::query(
                        "UPDATE space_record SET cid = ?, value = ?, repo_rev = ?, indexed_at = ?
                         WHERE space = ? AND collection = ? AND rkey = ?",
                    )
                    .bind(&row.cid)
                    .bind(&row.value)
                    .bind(&row.repo_rev)
                    .bind(&row.indexed_at)
                    .bind(space.to_string())
                    .bind(&row.collection)
                    .bind(&row.rkey)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| sql_err(format!("apply_commit update: {e}")))?;
                }
                RecordChange::Delete {
                    collection, rkey, ..
                } => {
                    sqlx::query(
                        "DELETE FROM space_record WHERE space = ? AND collection = ? AND rkey = ?",
                    )
                    .bind(space.to_string())
                    .bind(&collection)
                    .bind(&rkey)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| sql_err(format!("apply_commit delete: {e}")))?;
                }
            }
        }

        for entry in commit.oplog_entries {
            sqlx::query(
                "INSERT INTO space_record_oplog (space, rev, idx, action, collection, rkey, cid, prev)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(space.to_string())
            .bind(&entry.rev)
            .bind(entry.idx as i64)
            .bind(&entry.action)
            .bind(entry.collection.unwrap_or_default())
            .bind(entry.rkey.unwrap_or_default())
            .bind(entry.cid)
            .bind(entry.prev)
            .execute(&mut *tx)
            .await
            .map_err(|e| sql_err(format!("apply_commit oplog: {e}")))?;
        }

        sqlx::query(
            "INSERT INTO space_repo (space, set_hash, rev) VALUES (?, ?, ?)
             ON CONFLICT(space) DO UPDATE SET set_hash = excluded.set_hash, rev = excluded.rev",
        )
        .bind(space.to_string())
        .bind(&commit.new_set_hash)
        .bind(&commit.rev)
        .execute(&mut *tx)
        .await
        .map_err(|e| sql_err(format!("apply_commit space_repo: {e}")))?;

        tx.commit()
            .await
            .map_err(|e| sql_err(format!("apply_commit commit: {e}")))?;
        Ok(())
    }

    async fn read_oplog(
        &self,
        space: &SpaceUri,
        since: Option<&OplogCursor>,
        limit: u32,
    ) -> SpaceResult<OplogPage> {
        let limit = limit.clamp(1, 1000);
        let rows: Vec<(
            String,
            i64,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<Vec<u8>>,
        )> =
            match since {
                Some(cur) => {
                    // `(rev, idx) > (since.rev, since.idx)` so an atomic batch
                    // (entries sharing a rev) that exceeds `limit` pages fully.
                    sqlx::query_as(
                    "SELECT o.rev, o.idx, o.action, o.collection, o.rkey, o.cid, o.prev, r.value
                     FROM space_record_oplog o
                     LEFT JOIN space_record r
                       ON r.space = o.space AND r.collection = o.collection
                      AND r.rkey = o.rkey AND r.cid = o.cid
                     WHERE o.space = ? AND (o.rev > ? OR (o.rev = ? AND o.idx > ?))
                     ORDER BY o.rev ASC, o.idx ASC LIMIT ?",
                )
                .bind(space.to_string())
                .bind(&cur.rev)
                .bind(&cur.rev)
                .bind(cur.idx as i64)
                .bind(limit as i64)
                .fetch_all(&self.pool)
                .await
                }
                None => sqlx::query_as(
                    "SELECT o.rev, o.idx, o.action, o.collection, o.rkey, o.cid, o.prev, r.value
                     FROM space_record_oplog o
                     LEFT JOIN space_record r
                       ON r.space = o.space AND r.collection = o.collection
                      AND r.rkey = o.rkey AND r.cid = o.cid
                     WHERE o.space = ?
                     ORDER BY o.rev ASC, o.idx ASC LIMIT ?",
                )
                .bind(space.to_string())
                .bind(limit as i64)
                .fetch_all(&self.pool)
                .await,
            }
            .map_err(|e| sql_err(format!("read_oplog: {e}")))?;
        let ops = rows
            .into_iter()
            .map(
                |(rev, idx, action, collection, rkey, cid, prev, value)| OplogEntry {
                    rev,
                    idx: idx as u32,
                    action,
                    collection: Some(collection).filter(|s| !s.is_empty()),
                    rkey: Some(rkey).filter(|s| !s.is_empty()),
                    cid,
                    prev,
                    did: None,
                    // The join matched on the op's own CID, so this is `None`
                    // for a delete (no cid) and for an op superseded by a
                    // later write (cid no longer current) — exactly the two
                    // omissions the lexicon requires, with no bookkeeping.
                    value,
                },
            )
            .collect();
        let state = self.current_state(space).await?;
        Ok(OplogPage { ops, state })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor_store::sql::SqlActorStore;
    use atproto_space::set_hash::{LtHash, SetHash};
    use atproto_space::space_repo::{Op, OpAction, SpaceRepo};
    use atproto_space::types::{SpaceKey, SpaceType};

    fn test_space() -> SpaceUri {
        SpaceUri::new(
            "did:plc:owner".to_string(),
            SpaceType::new("app.bsky.group").unwrap(),
            SpaceKey::new("default").unwrap(),
        )
    }

    async fn fresh_storage() -> SqlSpaceRepoStorage {
        let store = SqlActorStore::open_memory("did:plc:test").await.unwrap();
        SqlSpaceRepoStorage::new(store.pool().clone())
    }

    type TestRepo = SpaceRepo<SqlSpaceRepoStorage, LtHash>;

    #[tokio::test(flavor = "multi_thread")]
    async fn create_and_read_record() {
        let space = test_space();
        let repo: TestRepo = SpaceRepo::new(space.clone(), fresh_storage().await);
        let prepared = repo
            .format_commit(&[Op {
                action: OpAction::Create,
                collection: "app.bsky.feed.post".to_string(),
                rkey: "abc".to_string(),
                cid: Some("bafy123".to_string()),
                value: Some(vec![1, 2, 3]),
            }])
            .await
            .unwrap();
        repo.apply_commit(prepared).await.unwrap();

        let row = repo
            .get_record("app.bsky.feed.post", "abc")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.cid, "bafy123");
        let state = repo.current_state().await.unwrap();
        assert!(state.set_hash.is_some());
        assert!(state.rev.is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn batch_atomic_commit() {
        let space = test_space();
        let repo: TestRepo = SpaceRepo::new(space.clone(), fresh_storage().await);
        let prepared = repo
            .format_commit(&[
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
            .unwrap();
        repo.apply_commit(prepared).await.unwrap();
        let page = repo.read_oplog(None, 100).await.unwrap();
        assert_eq!(page.ops.len(), 2);
        assert_eq!(page.ops[0].rev, page.ops[1].rev);
        assert_eq!(page.ops[0].idx, 0);
        assert_eq!(page.ops[1].idx, 1);
    }

    /// Regression: a single atomic batch larger than the page `limit` pages
    /// fully via the SQL `(rev > ? OR (rev = ? AND idx > ?))` predicate, with no
    /// tail skipped. A bare-rev `rev > ?` cursor would skip ops `limit..N`.
    #[tokio::test(flavor = "multi_thread")]
    async fn batch_larger_than_limit_pages_fully() {
        let space = test_space();
        let repo: TestRepo = SpaceRepo::new(space.clone(), fresh_storage().await);

        const N: usize = 7;
        const LIMIT: u32 = 3;

        let ops: Vec<Op> = (0..N)
            .map(|i| Op {
                action: OpAction::Create,
                collection: "c".to_string(),
                rkey: format!("k{i}"),
                cid: Some(format!("cid{i}")),
                value: Some(vec![]),
            })
            .collect();
        let prepared = repo.format_commit(&ops).await.unwrap();
        repo.apply_commit(prepared).await.unwrap();

        let mut seen: Vec<(String, u32)> = Vec::new();
        let mut cursor: Option<OplogCursor> = None;
        loop {
            let page = repo.read_oplog(cursor.as_ref(), LIMIT).await.unwrap();
            for op in &page.ops {
                seen.push((op.rev.clone(), op.idx));
            }
            let caught_up = (page.ops.len() as u32) < LIMIT;
            cursor = page
                .ops
                .last()
                .map(|o| OplogCursor::new(o.rev.clone(), o.idx));
            if caught_up {
                break;
            }
        }

        assert_eq!(seen.len(), N, "all batch ops delivered, none skipped");
        let rev = &seen[0].0;
        for (i, (r, idx)) in seen.iter().enumerate() {
            assert_eq!(r, rev, "all ops share the batch rev");
            assert_eq!(*idx as usize, i, "idx is dense and monotonic");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn list_records_paginates() {
        let space = test_space();
        let repo: TestRepo = SpaceRepo::new(space.clone(), fresh_storage().await);
        for r in ["a", "b", "c"] {
            let p = repo
                .format_commit(&[Op {
                    action: OpAction::Create,
                    collection: "c".to_string(),
                    rkey: r.to_string(),
                    cid: Some(format!("cid_{r}")),
                    value: Some(vec![]),
                }])
                .await
                .unwrap();
            repo.apply_commit(p).await.unwrap();
        }
        let page = repo.list_records("c", None, 2, false).await.unwrap();
        assert_eq!(page.records.len(), 2);
        assert!(page.cursor.is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn empty_state_returns_none() {
        let space = test_space();
        let storage = fresh_storage().await;
        let state = storage.current_state(&space).await.unwrap();
        assert!(state.set_hash.is_none());
        assert!(state.rev.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn delete_then_read_returns_none() {
        let space = test_space();
        let repo: TestRepo = SpaceRepo::new(space.clone(), fresh_storage().await);
        repo.apply_commit(
            repo.format_commit(&[Op {
                action: OpAction::Create,
                collection: "c".to_string(),
                rkey: "k".to_string(),
                cid: Some("cid".to_string()),
                value: Some(vec![1, 2]),
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

    /// The persisted lattice state round-trips through
    /// `state_bytes()`/`from_state_bytes()`, preserving both state and digest.
    #[test]
    fn set_hash_state_round_trips() {
        let mut h = LtHash::empty();
        h.add(b"x");
        let state = h.state_bytes();
        let rehydrated = LtHash::from_state_bytes(&state).unwrap();
        assert_eq!(rehydrated.state_bytes(), state);
        assert_eq!(rehydrated.digest(), h.digest());
    }
}
