//! `SqlBlockStorage` — `BlockStorage` impl backed by a per-actor SQLite pool.
//!
//! Implements `atproto_dasl::storage::BlockStorage` over the `repo_block`
//! table, which stores DAG-CBOR-encoded MST nodes and record bytes addressed
//! by their CIDs. Wire-compatible with the in-memory and disk-backed block
//! stores from `atproto-dasl` (same trait), so repo reader/writer code can
//! swap backends transparently.

use atproto_dasl::StorageError;
use atproto_dasl::cid::compute_cid;
use atproto_dasl::storage::BlockStorage;
use chrono::Utc;
use cid::Cid;
use sqlx::SqlitePool;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// SQLite-backed BlockStorage for one actor's per-actor DB.
pub struct SqlBlockStorage {
    pool: SqlitePool,
    block_count: Arc<AtomicUsize>,
    memory_usage: Arc<AtomicUsize>,
}

impl SqlBlockStorage {
    /// Construct over a per-actor pool. Internal counters are seeded by
    /// querying the table; subsequent mutations keep them in sync.
    ///
    /// # Errors
    ///
    /// Returns the underlying `StorageError` on SQL failure.
    pub async fn open(pool: SqlitePool) -> Result<Self, StorageError> {
        let row: (i64, i64) =
            sqlx::query_as("SELECT COUNT(*), COALESCE(SUM(LENGTH(data)), 0) FROM repo_block")
                .fetch_one(&pool)
                .await
                .map_err(sql_err_io("open count"))?;
        Ok(Self {
            pool,
            block_count: Arc::new(AtomicUsize::new(row.0 as usize)),
            memory_usage: Arc::new(AtomicUsize::new(row.1 as usize)),
        })
    }

    /// Get the underlying pool for direct queries (used by `repo::reader`,
    /// `repo::writer`, etc.).
    #[must_use]
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

fn sql_err_io(what: &'static str) -> impl FnOnce(sqlx::Error) -> StorageError {
    move |e| StorageError::Io(std::io::Error::other(format!("sql {what}: {e}")))
}

impl BlockStorage for SqlBlockStorage {
    async fn put(&mut self, cid: &Cid, data: Vec<u8>) -> Result<(), StorageError> {
        let cid_str = cid.to_string();
        let now = Utc::now().to_rfc3339();
        let len = data.len();
        let result = sqlx::query(
            "INSERT OR IGNORE INTO repo_block (cid, data, indexed_at) VALUES (?, ?, ?)",
        )
        .bind(&cid_str)
        .bind(&data)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(sql_err_io("put"))?;
        if result.rows_affected() == 1 {
            self.block_count.fetch_add(1, Ordering::Relaxed);
            self.memory_usage.fetch_add(len, Ordering::Relaxed);
        }
        Ok(())
    }

    async fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StorageError> {
        let cid_str = cid.to_string();
        let row: Option<(Vec<u8>,)> = sqlx::query_as("SELECT data FROM repo_block WHERE cid = ?")
            .bind(&cid_str)
            .fetch_optional(&self.pool)
            .await
            .map_err(sql_err_io("get"))?;
        Ok(row.map(|(data,)| data))
    }

    async fn contains(&self, cid: &Cid) -> Result<bool, StorageError> {
        let cid_str = cid.to_string();
        let row: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM repo_block WHERE cid = ? LIMIT 1")
            .bind(&cid_str)
            .fetch_optional(&self.pool)
            .await
            .map_err(sql_err_io("contains"))?;
        Ok(row.is_some())
    }

    async fn remove(&mut self, cid: &Cid) -> Result<Option<Vec<u8>>, StorageError> {
        let existing = self.get(cid).await?;
        if let Some(ref data) = existing {
            let cid_str = cid.to_string();
            let result = sqlx::query("DELETE FROM repo_block WHERE cid = ?")
                .bind(&cid_str)
                .execute(&self.pool)
                .await
                .map_err(sql_err_io("remove"))?;
            if result.rows_affected() == 1 {
                self.block_count.fetch_sub(1, Ordering::Relaxed);
                self.memory_usage.fetch_sub(data.len(), Ordering::Relaxed);
            }
        }
        Ok(existing)
    }

    fn memory_usage(&self) -> usize {
        self.memory_usage.load(Ordering::Relaxed)
    }

    fn block_count(&self) -> usize {
        self.block_count.load(Ordering::Relaxed)
    }

    fn cids(&self) -> Box<dyn Iterator<Item = Cid> + '_> {
        // Synchronous iteration is satisfied by an upfront blocking query.
        // Acceptable for typical PDS sizes (per-actor blockstores are bounded);
        // production users with very large repos should iterate via a dedicated
        // streaming SQL query — not exposed via this trait method.
        let pool = self.pool.clone();
        let cids: Vec<Cid> = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let rows: Vec<(String,)> = sqlx::query_as("SELECT cid FROM repo_block")
                    .fetch_all(&pool)
                    .await
                    .unwrap_or_default();
                rows.into_iter()
                    .filter_map(|(s,)| Cid::from_str(&s).ok())
                    .collect()
            })
        });
        Box::new(cids.into_iter())
    }

    async fn clear(&mut self) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM repo_block")
            .execute(&self.pool)
            .await
            .map_err(sql_err_io("clear"))?;
        self.block_count.store(0, Ordering::Relaxed);
        self.memory_usage.store(0, Ordering::Relaxed);
        Ok(())
    }
}

/// Sanity helper: confirm a stored block's bytes content-address to its claimed CID.
///
/// Returns `Ok(true)` if a block exists for the CID and matches; `Ok(false)` if
/// absent or mismatched; `Err` on storage failure.
///
/// # Errors
///
/// Forwards storage errors.
#[allow(dead_code)] // diagnostic-only helper; surfaces in admin tooling later.
async fn verify_block(storage: &SqlBlockStorage, cid: &Cid) -> Result<bool, StorageError> {
    match storage.get(cid).await? {
        Some(data) => {
            let computed = compute_cid(&data);
            Ok(&computed == cid)
        }
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor_store::sql::SqlActorStore;

    async fn fresh_storage() -> SqlBlockStorage {
        let store = SqlActorStore::open_memory("did:plc:test").await.unwrap();
        SqlBlockStorage::open(store.pool().clone()).await.unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn put_get_roundtrip() {
        let mut storage = fresh_storage().await;
        let data = b"hello".to_vec();
        let cid = compute_cid(&data);
        storage.put(&cid, data.clone()).await.unwrap();
        let got = storage.get(&cid).await.unwrap();
        assert_eq!(got.as_deref(), Some(data.as_slice()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn missing_block_is_none() {
        let storage = fresh_storage().await;
        let cid = compute_cid(b"absent");
        assert!(storage.get(&cid).await.unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn put_is_idempotent() {
        let mut storage = fresh_storage().await;
        let data = b"twice".to_vec();
        let cid = compute_cid(&data);
        storage.put(&cid, data.clone()).await.unwrap();
        storage.put(&cid, data.clone()).await.unwrap();
        assert_eq!(storage.block_count(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn contains_and_remove() {
        let mut storage = fresh_storage().await;
        let data = b"x".to_vec();
        let cid = compute_cid(&data);
        assert!(!storage.contains(&cid).await.unwrap());
        storage.put(&cid, data.clone()).await.unwrap();
        assert!(storage.contains(&cid).await.unwrap());
        let removed = storage.remove(&cid).await.unwrap();
        assert_eq!(removed, Some(data));
        assert!(!storage.contains(&cid).await.unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn clear_empties() {
        let mut storage = fresh_storage().await;
        for s in ["a", "b", "c"] {
            let data = s.as_bytes().to_vec();
            let cid = compute_cid(&data);
            storage.put(&cid, data).await.unwrap();
        }
        assert_eq!(storage.block_count(), 3);
        storage.clear().await.unwrap();
        assert_eq!(storage.block_count(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn memory_usage_tracks_bytes() {
        let mut storage = fresh_storage().await;
        assert_eq!(storage.memory_usage(), 0);
        let data = vec![0u8; 1024];
        let cid = compute_cid(&data);
        storage.put(&cid, data).await.unwrap();
        assert_eq!(storage.memory_usage(), 1024);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_block_known_data() {
        let mut storage = fresh_storage().await;
        let data = b"real".to_vec();
        let cid = compute_cid(&data);
        storage.put(&cid, data).await.unwrap();
        assert!(verify_block(&storage, &cid).await.unwrap());

        let missing = compute_cid(b"missing");
        assert!(!verify_block(&storage, &missing).await.unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cids_iterates_inserted() {
        let mut storage = fresh_storage().await;
        let mut expected = Vec::new();
        for s in ["a", "b", "c"] {
            let data = s.as_bytes().to_vec();
            let cid = compute_cid(&data);
            expected.push(cid);
            storage.put(&cid, data).await.unwrap();
        }
        let mut got: Vec<_> = storage.cids().collect();
        got.sort();
        expected.sort();
        assert_eq!(got, expected);
    }
}
