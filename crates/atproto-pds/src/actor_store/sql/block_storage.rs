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

/// Seeded counters, one pair per actor database.
///
/// The counters are shared rather than per-handle, which is what lets the
/// seeding happen once. Every handle for an actor increments the same atomics,
/// so a count seeded on the first open stays accurate for the life of the
/// process however many `SqlBlockStorage` values are constructed.
///
/// Not bounded. An entry is two `Arc<AtomicUsize>` and a path; one per actor
/// this process has touched is not a growth vector worth the eviction logic,
/// and unlike a pool it holds no file descriptor.
///
/// The fjall backend has the same defect -- a synchronous scan reading every
/// value, on whatever thread the caller runs on -- and deliberately does not
/// get this treatment. Its keyspace is one store for the whole process, so
/// the only key available is the DID, and two stores over different paths
/// would then share counters. `counters_recover_after_reopen` also requires
/// that reopening rescans, which is a property this cache exists to remove.
/// A SQLite pool names its own file, so the SQL backend has an identity to
/// key on and fjall does not.
type Counters = (Arc<AtomicUsize>, Arc<AtomicUsize>);
static COUNTERS: std::sync::OnceLock<dashmap::DashMap<std::path::PathBuf, Counters>> =
    std::sync::OnceLock::new();

/// How many times the seeding query has run, for tests to observe that it does
/// not run per operation.
#[cfg(test)]
static SEEDS_RUN: std::sync::OnceLock<dashmap::DashMap<std::path::PathBuf, usize>> =
    std::sync::OnceLock::new();

impl SqlBlockStorage {
    /// Construct over a per-actor pool.
    ///
    /// The counters are seeded once per actor database and shared by every
    /// handle after that; subsequent mutations keep them in sync.
    ///
    /// Seeding used to happen here, on every construction, as
    /// `SELECT COUNT(*), COALESCE(SUM(LENGTH(data)), 0) FROM repo_block`.
    /// `SUM(LENGTH(data))` walks the whole `repo_block` b-tree, and this runs
    /// on `getRecord`, `listRecords`, `getRepo`, `getBlocks`, `sync.getRecord`
    /// -- twice in that one -- and both writer paths. An O(log N) point lookup
    /// was therefore preceded by an O(N) scan, so read latency grew linearly
    /// with everything the account had ever written.
    ///
    /// Caching the pool did not fix it: the pool is per actor, but this query
    /// was per *construction*, and a handle is constructed per operation.
    ///
    /// # Errors
    ///
    /// Returns the underlying `StorageError` on SQL failure.
    pub async fn open(pool: SqlitePool) -> Result<Self, StorageError> {
        let key = pool.connect_options().get_filename().to_path_buf();
        let cache = COUNTERS.get_or_init(dashmap::DashMap::new);

        if let Some(existing) = cache.get(&key) {
            let (block_count, memory_usage) = existing.clone();
            return Ok(Self {
                pool,
                block_count,
                memory_usage,
            });
        }

        let row: (i64, i64) =
            sqlx::query_as("SELECT COUNT(*), COALESCE(SUM(LENGTH(data)), 0) FROM repo_block")
                .fetch_one(&pool)
                .await
                .map_err(sql_err_io("open count"))?;
        #[cfg(test)]
        {
            *SEEDS_RUN
                .get_or_init(dashmap::DashMap::new)
                .entry(key.clone())
                .or_insert(0) += 1;
        }

        // Another handle may have seeded the same actor while this one was
        // querying. Both counts are correct, so take whichever landed first
        // and let every handle share one pair.
        let counters = cache
            .entry(key)
            .or_insert_with(|| {
                (
                    Arc::new(AtomicUsize::new(row.0 as usize)),
                    Arc::new(AtomicUsize::new(row.1 as usize)),
                )
            })
            .clone();

        Ok(Self {
            pool,
            block_count: counters.0,
            memory_usage: counters.1,
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
    /// The seed is per actor, not per handle.
    ///
    /// `SUM(LENGTH(data))` walks the whole `repo_block` b-tree, and a handle
    /// is constructed on `getRecord`, `listRecords`, `getRepo`, `getBlocks`,
    /// `sync.getRecord` -- twice there -- and both writer paths. Caching the
    /// pool did not help: the pool is per actor, this query was per
    /// construction.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_seed_scan_runs_once_per_actor() {
        let tmp = tempfile::tempdir().unwrap();
        let store = crate::actor_store::sql::SqlActorStore::open(tmp.path(), "did:plc:seed")
            .await
            .unwrap();
        let key = store.pool().connect_options().get_filename().to_path_buf();

        for _ in 0..10 {
            SqlBlockStorage::open(store.pool().clone())
                .await
                .expect("open should succeed");
        }

        let seeds = SEEDS_RUN
            .get_or_init(dashmap::DashMap::new)
            .get(&key)
            .map_or(0, |n| *n);
        assert_eq!(seeds, 1, "ten handles for one actor should seed once");
    }

    /// A shared counter is what makes seeding once correct: a block written
    /// through one handle is counted by the next.
    #[tokio::test(flavor = "multi_thread")]
    async fn handles_for_one_actor_share_their_counters() {
        use atproto_dasl::storage::BlockStorage;

        let tmp = tempfile::tempdir().unwrap();
        let store = crate::actor_store::sql::SqlActorStore::open(tmp.path(), "did:plc:shared")
            .await
            .unwrap();

        let mut first = SqlBlockStorage::open(store.pool().clone()).await.unwrap();
        let before = first.block_count();

        let cid = Cid::try_from("bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a")
            .expect("a valid cid");
        first.put(&cid, vec![1, 2, 3]).await.expect("put");

        let second = SqlBlockStorage::open(store.pool().clone()).await.unwrap();
        assert_eq!(
            second.block_count(),
            before + 1,
            "a later handle must see what an earlier one wrote"
        );
    }

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
