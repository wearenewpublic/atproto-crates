//! SQL implementations of the public-realm storage traits.
//!
//! Each impl wraps a `SqlitePool` opened against the per-actor DB. `did`
//! is accepted on every call so a single backend handle can serve all
//! actors — at runtime the dispatch wires per-DID `SqlActorStore`s into
//! short-lived backend instances.
//!
//! These types mirror the parallel `actor_store::fjall::public_realm`
//! impls. The same trait surface lets the high-level `RepoReader` /
//! `RepoWriter` / `OutboxReader` (and the future blob-layer refactor)
//! dispatch through `Arc<dyn TraitName>` without caring which backend
//! is in use.

use crate::actor_store::sql::SqlActorStore;
use crate::actor_store::traits::{
    AtomicCommitWriter, BlobRefRow, BlobRow, BlobStorage, CommitBatch, CommitObjStorage, CommitRow,
    OutboxRow, OutboxStorage, RecordRow, RepoRecordStorage,
};
use crate::errors::{PdsError, PdsResult};
use async_trait::async_trait;
use sqlx::SqlitePool;

/// Open a per-actor SQLite pool for `did`. Each backend impl calls this
/// on every operation — the pool itself is small and SQLite's
/// connection cache amortizes the cost. Future optimization: a
/// `DashMap<did, SqlitePool>` cache; today we accept the open cost
/// because the SqlActorStore migration runner already gates the
/// hot-path overhead on first-use.
async fn open_pool(data_dir: &std::path::Path, did: &str) -> PdsResult<SqlitePool> {
    Ok(SqlActorStore::open(data_dir, did).await?.pool().clone())
}

// ---------------------------------------------------------------------------
//  CommitObjStorage.
// ---------------------------------------------------------------------------

/// SQL-backed `CommitObjStorage`.
#[derive(Clone)]
pub struct SqlCommitObjStorage {
    data_dir: std::path::PathBuf,
}

impl SqlCommitObjStorage {
    /// Construct over the PDS data directory; the impl opens per-actor
    /// stores on demand.
    #[must_use]
    pub fn new(data_dir: std::path::PathBuf) -> Self {
        Self { data_dir }
    }
}

#[async_trait]
impl CommitObjStorage for SqlCommitObjStorage {
    async fn insert(&self, did: &str, row: &CommitRow) -> PdsResult<()> {
        let pool = open_pool(&self.data_dir, did).await?;
        sqlx::query(
            "INSERT INTO commit_obj
                (cid, rev, data_cid, prev_cid, prev_data_cid, signature_blob, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&row.cid)
        .bind(&row.rev)
        .bind(&row.data_cid)
        .bind(&row.prev_cid)
        .bind(&row.prev_data_cid)
        .bind(&row.signature)
        .bind(&row.created_at)
        .execute(&pool)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("commit_obj insert: {e}"),
        })?;
        Ok(())
    }

    async fn latest(&self, did: &str) -> PdsResult<Option<CommitRow>> {
        let pool = open_pool(&self.data_dir, did).await?;
        let row: Option<(
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Vec<u8>,
            String,
        )> = sqlx::query_as(
            "SELECT cid, rev, data_cid, prev_cid, prev_data_cid, signature_blob, created_at
                 FROM commit_obj ORDER BY rev DESC LIMIT 1",
        )
        .fetch_optional(&pool)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("commit_obj latest: {e}"),
        })?;
        Ok(row.map(row_into_commit))
    }

    async fn get_by_cid(&self, did: &str, cid: &str) -> PdsResult<Option<CommitRow>> {
        let pool = open_pool(&self.data_dir, did).await?;
        let row: Option<(
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Vec<u8>,
            String,
        )> = sqlx::query_as(
            "SELECT cid, rev, data_cid, prev_cid, prev_data_cid, signature_blob, created_at
                 FROM commit_obj WHERE cid = ? LIMIT 1",
        )
        .bind(cid)
        .fetch_optional(&pool)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("commit_obj get_by_cid: {e}"),
        })?;
        Ok(row.map(row_into_commit))
    }

    async fn get_by_rev(&self, did: &str, rev: &str) -> PdsResult<Option<CommitRow>> {
        let pool = open_pool(&self.data_dir, did).await?;
        let row: Option<(
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Vec<u8>,
            String,
        )> = sqlx::query_as(
            "SELECT cid, rev, data_cid, prev_cid, prev_data_cid, signature_blob, created_at
                 FROM commit_obj WHERE rev = ? LIMIT 1",
        )
        .bind(rev)
        .fetch_optional(&pool)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("commit_obj get_by_rev: {e}"),
        })?;
        Ok(row.map(row_into_commit))
    }
}

fn row_into_commit(
    row: (
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Vec<u8>,
        String,
    ),
) -> CommitRow {
    let (cid, rev, data_cid, prev_cid, prev_data_cid, signature, created_at) = row;
    CommitRow {
        cid,
        rev,
        data_cid,
        prev_cid,
        prev_data_cid,
        signature,
        created_at,
    }
}

// ---------------------------------------------------------------------------
//  RepoRecordStorage.
// ---------------------------------------------------------------------------

/// SQL-backed `RepoRecordStorage`.
#[derive(Clone)]
pub struct SqlRepoRecordStorage {
    data_dir: std::path::PathBuf,
}

impl SqlRepoRecordStorage {
    /// Construct over the PDS data directory.
    #[must_use]
    pub fn new(data_dir: std::path::PathBuf) -> Self {
        Self { data_dir }
    }
}

#[async_trait]
impl RepoRecordStorage for SqlRepoRecordStorage {
    async fn upsert(&self, did: &str, row: &RecordRow) -> PdsResult<()> {
        let pool = open_pool(&self.data_dir, did).await?;
        sqlx::query(
            "INSERT INTO repo_record (uri, cid, collection, rkey, rev, indexed_at)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(collection, rkey) DO UPDATE SET
                 uri        = excluded.uri,
                 cid        = excluded.cid,
                 rev        = excluded.rev,
                 indexed_at = excluded.indexed_at",
        )
        .bind(&row.uri)
        .bind(&row.cid)
        .bind(&row.collection)
        .bind(&row.rkey)
        .bind(&row.rev)
        .bind(&row.indexed_at)
        .execute(&pool)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("repo_record upsert: {e}"),
        })?;
        Ok(())
    }

    async fn delete(&self, did: &str, collection: &str, rkey: &str) -> PdsResult<bool> {
        let pool = open_pool(&self.data_dir, did).await?;
        let result = sqlx::query("DELETE FROM repo_record WHERE collection = ? AND rkey = ?")
            .bind(collection)
            .bind(rkey)
            .execute(&pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("repo_record delete: {e}"),
            })?;
        Ok(result.rows_affected() > 0)
    }

    async fn get_by_uri(&self, did: &str, uri: &str) -> PdsResult<Option<RecordRow>> {
        let pool = open_pool(&self.data_dir, did).await?;
        let row: Option<(String, String, String, String, String, String)> = sqlx::query_as(
            "SELECT uri, cid, collection, rkey, rev, indexed_at
             FROM repo_record WHERE uri = ? LIMIT 1",
        )
        .bind(uri)
        .fetch_optional(&pool)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("repo_record get_by_uri: {e}"),
        })?;
        Ok(row.map(row_into_record))
    }

    async fn list_by_collection(
        &self,
        did: &str,
        collection: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> PdsResult<Vec<RecordRow>> {
        let pool = open_pool(&self.data_dir, did).await?;
        let limit = limit.clamp(1, 1000);
        let rows: Vec<(String, String, String, String, String, String)> = match cursor {
            Some(c) => {
                sqlx::query_as(
                    "SELECT uri, cid, collection, rkey, rev, indexed_at
                 FROM repo_record WHERE collection = ? AND rkey > ?
                 ORDER BY rkey ASC LIMIT ?",
                )
                .bind(collection)
                .bind(c)
                .bind(limit as i64)
                .fetch_all(&pool)
                .await
            }
            None => {
                sqlx::query_as(
                    "SELECT uri, cid, collection, rkey, rev, indexed_at
                 FROM repo_record WHERE collection = ?
                 ORDER BY rkey ASC LIMIT ?",
                )
                .bind(collection)
                .bind(limit as i64)
                .fetch_all(&pool)
                .await
            }
        }
        .map_err(|e| PdsError::Storage {
            reason: format!("repo_record list_by_collection: {e}"),
        })?;
        Ok(rows.into_iter().map(row_into_record).collect())
    }

    async fn list_collections(&self, did: &str) -> PdsResult<Vec<String>> {
        let pool = open_pool(&self.data_dir, did).await?;
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT DISTINCT collection FROM repo_record ORDER BY collection ASC")
                .fetch_all(&pool)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("repo_record list_collections: {e}"),
                })?;
        Ok(rows.into_iter().map(|(c,)| c).collect())
    }
}

fn row_into_record(row: (String, String, String, String, String, String)) -> RecordRow {
    let (uri, cid, collection, rkey, rev, indexed_at) = row;
    RecordRow {
        uri,
        cid,
        collection,
        rkey,
        rev,
        indexed_at,
    }
}

// ---------------------------------------------------------------------------
//  OutboxStorage.
// ---------------------------------------------------------------------------

/// SQL-backed `OutboxStorage`.
#[derive(Clone)]
pub struct SqlOutboxStorage {
    data_dir: std::path::PathBuf,
}

impl SqlOutboxStorage {
    /// Construct over the PDS data directory.
    #[must_use]
    pub fn new(data_dir: std::path::PathBuf) -> Self {
        Self { data_dir }
    }
}

#[async_trait]
impl OutboxStorage for SqlOutboxStorage {
    async fn append(&self, did: &str, event_type: &str, payload: Vec<u8>) -> PdsResult<u64> {
        let pool = open_pool(&self.data_dir, did).await?;
        let now = chrono::Utc::now().to_rfc3339();
        let result =
            sqlx::query("INSERT INTO outbox (event_type, payload, created_at) VALUES (?, ?, ?)")
                .bind(event_type)
                .bind(&payload)
                .bind(&now)
                .execute(&pool)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("outbox append: {e}"),
                })?;
        Ok(result.last_insert_rowid().max(0) as u64)
    }

    async fn read_after(
        &self,
        did: &str,
        after: Option<u64>,
        limit: u32,
    ) -> PdsResult<Vec<OutboxRow>> {
        let pool = open_pool(&self.data_dir, did).await?;
        let limit = limit.clamp(1, 1000);
        let rows: Vec<(i64, String, Vec<u8>, String)> = match after {
            Some(c) => {
                sqlx::query_as(
                    "SELECT seq, event_type, payload, created_at
                 FROM outbox WHERE seq > ?
                 ORDER BY seq ASC LIMIT ?",
                )
                .bind(c as i64)
                .bind(limit as i64)
                .fetch_all(&pool)
                .await
            }
            None => {
                sqlx::query_as(
                    "SELECT seq, event_type, payload, created_at
                 FROM outbox ORDER BY seq ASC LIMIT ?",
                )
                .bind(limit as i64)
                .fetch_all(&pool)
                .await
            }
        }
        .map_err(|e| PdsError::Storage {
            reason: format!("outbox read_after: {e}"),
        })?;
        Ok(rows
            .into_iter()
            .map(|(seq, event_type, payload, created_at)| OutboxRow {
                seq: seq.max(0) as u64,
                event_type,
                payload,
                created_at,
            })
            .collect())
    }

    async fn latest_seq(&self, did: &str) -> PdsResult<Option<u64>> {
        let pool = open_pool(&self.data_dir, did).await?;
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT MAX(seq) FROM outbox WHERE seq IS NOT NULL")
                .fetch_optional(&pool)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("outbox latest_seq: {e}"),
                })?;
        Ok(row.and_then(|(s,)| if s == 0 { None } else { Some(s as u64) }))
    }
}

// ---------------------------------------------------------------------------
//  BlobStorage.
// ---------------------------------------------------------------------------

/// SQL-backed `BlobStorage`. Wraps `repo_blob` (bytes) + `repo_blob_ref`
/// (record→blob references).
#[derive(Clone)]
pub struct SqlBlobStorage {
    data_dir: std::path::PathBuf,
}

impl SqlBlobStorage {
    /// Construct over the PDS data directory.
    #[must_use]
    pub fn new(data_dir: std::path::PathBuf) -> Self {
        Self { data_dir }
    }
}

#[async_trait]
impl BlobStorage for SqlBlobStorage {
    async fn put(&self, did: &str, row: &BlobRow) -> PdsResult<()> {
        let pool = open_pool(&self.data_dir, did).await?;
        sqlx::query(
            "INSERT OR IGNORE INTO repo_blob (cid, mime_type, size, data, created_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&row.cid)
        .bind(&row.mime_type)
        .bind(row.size as i64)
        .bind(&row.data)
        .bind(&row.created_at)
        .execute(&pool)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("repo_blob put: {e}"),
        })?;
        Ok(())
    }

    async fn get(&self, did: &str, cid: &str) -> PdsResult<Option<(Vec<u8>, String)>> {
        let pool = open_pool(&self.data_dir, did).await?;
        let row: Option<(Vec<u8>, String)> =
            sqlx::query_as("SELECT data, mime_type FROM repo_blob WHERE cid = ?")
                .bind(cid)
                .fetch_optional(&pool)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("repo_blob get: {e}"),
                })?;
        Ok(row)
    }

    async fn add_ref(&self, did: &str, row: &BlobRefRow) -> PdsResult<()> {
        let pool = open_pool(&self.data_dir, did).await?;
        sqlx::query(
            "INSERT OR IGNORE INTO repo_blob_ref (record_uri, blob_cid, mime_type, size)
             VALUES (?, ?, ?, ?)",
        )
        .bind(&row.record_uri)
        .bind(&row.blob_cid)
        .bind(&row.mime_type)
        .bind(row.size as i64)
        .execute(&pool)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("repo_blob_ref add: {e}"),
        })?;
        Ok(())
    }

    async fn drop_refs_for_record(&self, did: &str, record_uri: &str) -> PdsResult<Vec<String>> {
        let pool = open_pool(&self.data_dir, did).await?;
        let candidates: Vec<(String,)> =
            sqlx::query_as("SELECT blob_cid FROM repo_blob_ref WHERE record_uri = ?")
                .bind(record_uri)
                .fetch_all(&pool)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("drop_refs select: {e}"),
                })?;
        sqlx::query("DELETE FROM repo_blob_ref WHERE record_uri = ?")
            .bind(record_uri)
            .execute(&pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("drop_refs delete: {e}"),
            })?;
        let mut orphans: Vec<String> = Vec::new();
        for (cid,) in candidates {
            let row: (i64,) =
                sqlx::query_as("SELECT COUNT(*) FROM repo_blob_ref WHERE blob_cid = ?")
                    .bind(&cid)
                    .fetch_one(&pool)
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("orphan count: {e}"),
                    })?;
            if row.0 == 0 {
                orphans.push(cid);
            }
        }
        Ok(orphans)
    }

    async fn delete_blob(&self, did: &str, cid: &str) -> PdsResult<bool> {
        let pool = open_pool(&self.data_dir, did).await?;
        let result = sqlx::query("DELETE FROM repo_blob WHERE cid = ?")
            .bind(cid)
            .execute(&pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("repo_blob delete: {e}"),
            })?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_all_cids(
        &self,
        did: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> PdsResult<Vec<String>> {
        let pool = open_pool(&self.data_dir, did).await?;
        let limit = limit.clamp(1, 1000);
        let rows: Vec<(String,)> = match cursor {
            Some(c) => {
                sqlx::query_as("SELECT cid FROM repo_blob WHERE cid > ? ORDER BY cid ASC LIMIT ?")
                    .bind(c)
                    .bind(limit as i64)
                    .fetch_all(&pool)
                    .await
            }
            None => {
                sqlx::query_as("SELECT cid FROM repo_blob ORDER BY cid ASC LIMIT ?")
                    .bind(limit as i64)
                    .fetch_all(&pool)
                    .await
            }
        }
        .map_err(|e| PdsError::Storage {
            reason: format!("repo_blob list_all_cids: {e}"),
        })?;
        Ok(rows.into_iter().map(|(c,)| c).collect())
    }

    async fn list_missing_refs(
        &self,
        did: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> PdsResult<Vec<BlobRefRow>> {
        let pool = open_pool(&self.data_dir, did).await?;
        let limit = limit.clamp(1, 1000);
        use sqlx::Row;
        let sql = match cursor {
            Some(_) => {
                "SELECT DISTINCT r.blob_cid, r.mime_type, r.size, r.record_uri
                 FROM repo_blob_ref r
                 LEFT JOIN repo_blob b ON b.cid = r.blob_cid
                 WHERE b.cid IS NULL AND r.blob_cid > ?
                 ORDER BY r.blob_cid ASC
                 LIMIT ?"
            }
            None => {
                "SELECT DISTINCT r.blob_cid, r.mime_type, r.size, r.record_uri
                 FROM repo_blob_ref r
                 LEFT JOIN repo_blob b ON b.cid = r.blob_cid
                 WHERE b.cid IS NULL
                 ORDER BY r.blob_cid ASC
                 LIMIT ?"
            }
        };
        let mut q = sqlx::query(sql);
        if let Some(c) = cursor {
            q = q.bind(c);
        }
        q = q.bind(limit as i64);
        let rows = q.fetch_all(&pool).await.map_err(|e| PdsError::Storage {
            reason: format!("repo_blob list_missing_refs: {e}"),
        })?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(BlobRefRow {
                blob_cid: row.try_get::<String, _>("blob_cid").unwrap_or_default(),
                mime_type: row.try_get::<String, _>("mime_type").unwrap_or_default(),
                size: row.try_get::<i64, _>("size").unwrap_or(0).max(0) as u64,
                record_uri: row.try_get::<String, _>("record_uri").unwrap_or_default(),
            });
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
//  AtomicCommitWriter — single sqlx transaction across commit_obj /
//  repo_block (commit block) / repo_record / outbox.
// ---------------------------------------------------------------------------

/// SQL-backed [`AtomicCommitWriter`].
///
/// Opens a per-actor `SqlitePool` on demand and runs one sqlx
/// `Transaction` covering every write the writer's apply_writes
/// emits. Either every row lands or none do.
#[derive(Clone)]
pub struct SqlAtomicCommitWriter {
    data_dir: std::path::PathBuf,
}

impl SqlAtomicCommitWriter {
    /// Construct over the PDS data directory.
    #[must_use]
    pub fn new(data_dir: std::path::PathBuf) -> Self {
        Self { data_dir }
    }
}

#[async_trait]
impl AtomicCommitWriter for SqlAtomicCommitWriter {
    async fn apply_atomic_commit(&self, did: &str, batch: CommitBatch<'_>) -> PdsResult<()> {
        let pool = open_pool(&self.data_dir, did).await?;
        let now = chrono::Utc::now().to_rfc3339();
        let mut tx = pool.begin().await.map_err(|e| PdsError::Storage {
            reason: format!("atomic commit begin tx: {e}"),
        })?;

        // commit_obj
        sqlx::query(
            "INSERT INTO commit_obj (cid, rev, data_cid, prev_cid, prev_data_cid, signature_blob, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&batch.commit.cid)
        .bind(&batch.commit.rev)
        .bind(&batch.commit.data_cid)
        .bind(&batch.commit.prev_cid)
        .bind(&batch.commit.prev_data_cid)
        .bind(&batch.commit.signature)
        .bind(&now)
        .execute(&mut *tx)
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("atomic commit insert commit_obj: {e}"),
        })?;

        // repo_block (commit block bytes)
        sqlx::query("INSERT OR IGNORE INTO repo_block (cid, data, indexed_at) VALUES (?, ?, ?)")
            .bind(batch.commit_block_cid)
            .bind(batch.commit_block_bytes)
            .bind(&now)
            .execute(&mut *tx)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("atomic commit insert repo_block: {e}"),
            })?;

        // repo_record upserts
        for row in batch.record_upserts {
            sqlx::query(
                "INSERT INTO repo_record (uri, cid, collection, rkey, rev, indexed_at)
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON CONFLICT (collection, rkey) DO UPDATE SET cid = excluded.cid, rev = excluded.rev, indexed_at = excluded.indexed_at",
            )
            .bind(&row.uri)
            .bind(&row.cid)
            .bind(&row.collection)
            .bind(&row.rkey)
            .bind(&row.rev)
            .bind(&row.indexed_at)
            .execute(&mut *tx)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("atomic commit upsert repo_record: {e}"),
            })?;
        }

        // repo_record deletes
        for (collection, rkey) in batch.record_deletes {
            sqlx::query("DELETE FROM repo_record WHERE collection = ? AND rkey = ?")
                .bind(collection)
                .bind(rkey)
                .execute(&mut *tx)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("atomic commit delete repo_record: {e}"),
                })?;
        }

        tx.commit().await.map_err(|e| PdsError::Storage {
            reason: format!("atomic commit tx commit: {e}"),
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh_dir() -> TempDir {
        TempDir::new().unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn commit_storage_round_trip() {
        let tmp = fresh_dir();
        let storage = SqlCommitObjStorage::new(tmp.path().to_path_buf());
        let did = "did:plc:alice";
        let row = CommitRow {
            cid: "bafycommit".to_string(),
            rev: "3kmev".to_string(),
            data_cid: "bafymst".to_string(),
            prev_cid: None,
            prev_data_cid: None,
            signature: vec![1, 2, 3, 4],
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        storage.insert(did, &row).await.unwrap();
        let got = storage.latest(did).await.unwrap().unwrap();
        assert_eq!(got.cid, "bafycommit");
        assert_eq!(got.rev, "3kmev");
        let by_cid = storage.get_by_cid(did, "bafycommit").await.unwrap();
        assert!(by_cid.is_some());
        let by_rev = storage.get_by_rev(did, "3kmev").await.unwrap();
        assert!(by_rev.is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn record_storage_round_trip_and_delete() {
        let tmp = fresh_dir();
        let storage = SqlRepoRecordStorage::new(tmp.path().to_path_buf());
        let did = "did:plc:alice";
        let row = RecordRow {
            uri: "at://did:plc:alice/app.bsky.feed.post/k1".to_string(),
            cid: "bafyrec".to_string(),
            collection: "app.bsky.feed.post".to_string(),
            rkey: "k1".to_string(),
            rev: "3kmev".to_string(),
            indexed_at: chrono::Utc::now().to_rfc3339(),
        };
        storage.upsert(did, &row).await.unwrap();
        let got = storage
            .get_by_uri(did, "at://did:plc:alice/app.bsky.feed.post/k1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.cid, "bafyrec");
        let page = storage
            .list_by_collection(did, "app.bsky.feed.post", None, 10)
            .await
            .unwrap();
        assert_eq!(page.len(), 1);
        let removed = storage
            .delete(did, "app.bsky.feed.post", "k1")
            .await
            .unwrap();
        assert!(removed);
        let again = storage
            .delete(did, "app.bsky.feed.post", "k1")
            .await
            .unwrap();
        assert!(!again);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn outbox_storage_append_then_read() {
        let tmp = fresh_dir();
        let storage = SqlOutboxStorage::new(tmp.path().to_path_buf());
        let did = "did:plc:alice";
        let s1 = storage.append(did, "commit", b"a".to_vec()).await.unwrap();
        let s2 = storage.append(did, "sync", b"b".to_vec()).await.unwrap();
        assert!(s2 > s1);
        let all = storage.read_after(did, None, 10).await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].event_type, "commit");
        assert_eq!(all[1].event_type, "sync");
        assert_eq!(storage.latest_seq(did).await.unwrap(), Some(s2));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn blob_storage_put_get_and_ref_gc() {
        let tmp = fresh_dir();
        let storage = SqlBlobStorage::new(tmp.path().to_path_buf());
        let did = "did:plc:alice";
        let blob = BlobRow {
            cid: "bafkreig000000000000000000000000000000000000000000000aaaaaa".to_string(),
            mime_type: "text/plain".to_string(),
            size: 5,
            data: b"hello".to_vec(),
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        storage.put(did, &blob).await.unwrap();
        let (data, mime) = storage.get(did, &blob.cid).await.unwrap().unwrap();
        assert_eq!(data, b"hello");
        assert_eq!(mime, "text/plain");

        // Add two refs from different records, then drop the first → 0 orphans.
        let r1 = BlobRefRow {
            record_uri: "at://x/c/k1".to_string(),
            blob_cid: blob.cid.clone(),
            mime_type: blob.mime_type.clone(),
            size: blob.size,
        };
        let r2 = BlobRefRow {
            record_uri: "at://x/c/k2".to_string(),
            blob_cid: blob.cid.clone(),
            mime_type: blob.mime_type.clone(),
            size: blob.size,
        };
        storage.add_ref(did, &r1).await.unwrap();
        storage.add_ref(did, &r2).await.unwrap();
        let orphans = storage
            .drop_refs_for_record(did, "at://x/c/k1")
            .await
            .unwrap();
        assert!(orphans.is_empty(), "blob still has a ref via k2");
        let orphans = storage
            .drop_refs_for_record(did, "at://x/c/k2")
            .await
            .unwrap();
        assert_eq!(orphans, vec![blob.cid.clone()]);
        // The bytes still exist until the caller calls `delete_blob`.
        assert!(storage.get(did, &blob.cid).await.unwrap().is_some());
        let dropped = storage.delete_blob(did, &blob.cid).await.unwrap();
        assert!(dropped);
        assert!(storage.get(did, &blob.cid).await.unwrap().is_none());
    }
}
