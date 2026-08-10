//! `SqlActorStore` — SQLite-backed per-actor store.
//!
//! One SQLite file per account at
//! `PDS_DATA_DIRECTORY/actors/<sha256(did)>.sqlite`. Holds the public-realm
//! repository state plus the eight Spaces tables.

use crate::actor_store::ActorStore;
use crate::errors::{PdsError, PdsResult};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Compute the per-actor DB filename for a DID.
///
/// Uses `sha256(did)` so DIDs of arbitrary length and character set produce a
/// stable, filesystem-safe filename. The `.sqlite` suffix is appended.
#[must_use]
pub fn did_filename(did: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(did.as_bytes());
    let hex = hex::encode(hasher.finalize());
    format!("{hex}.sqlite")
}

/// Build the full per-actor DB path under `data_dir`.
#[must_use]
pub fn actor_db_path(data_dir: &Path, did: &str) -> PathBuf {
    data_dir.join("actors").join(did_filename(did))
}

/// SQLite-backed `ActorStore` for one account.
///
/// Holds the connection pool to that actor's per-actor DB. Applies migrations
/// on construction (idempotent — sqlx's migrate runner skips already-applied
/// versions).
pub struct SqlActorStore {
    did: String,
    pool: SqlitePool,
}

/// How many per-actor pools stay open.
///
/// A pool is a ceiling on connections, not a reservation -- sqlx opens them on
/// demand and reaps them when idle -- so a cached pool for an actor nobody is
/// touching costs a map entry. The cap exists because file descriptors are
/// finite, not because pools are expensive to hold.
const POOL_CACHE_CAPACITY: usize = 256;

/// Per-actor pools, keyed on the database path.
///
/// Keyed on the path rather than the DID so two data directories -- which is
/// what every test with its own `TempDir` is -- cannot collide, and so
/// `open_memory` shares nothing with anything.
///
/// One caveat, recorded because it is the way this goes wrong: nothing in this
/// server deletes a per-actor database today. If something ever does, it has
/// to evict the entry here as well. SQLite keeps working against an unlinked
/// inode, so a stale cached pool would not error -- it would quietly read and
/// write a file that no longer has a name.
static POOL_CACHE: std::sync::OnceLock<std::sync::Mutex<lru::LruCache<PathBuf, SqlitePool>>> =
    std::sync::OnceLock::new();

/// How many pools have been constructed per database, for tests to observe
/// that the cache is doing something.
///
/// Per database rather than a single counter because the test binary runs
/// these concurrently in one process: a global count would see every other
/// test's pools and measure nothing. Nothing reads this in production.
#[cfg(test)]
static POOLS_BUILT: std::sync::OnceLock<dashmap::DashMap<PathBuf, usize>> =
    std::sync::OnceLock::new();

fn pool_cache() -> &'static std::sync::Mutex<lru::LruCache<PathBuf, SqlitePool>> {
    POOL_CACHE.get_or_init(|| {
        std::sync::Mutex::new(lru::LruCache::new(
            std::num::NonZeroUsize::new(POOL_CACHE_CAPACITY).expect("capacity is not zero"),
        ))
    })
}

/// How many pools have been constructed for `db_path`.
#[cfg(test)]
fn pools_built_for(db_path: &Path) -> usize {
    POOLS_BUILT
        .get_or_init(dashmap::DashMap::new)
        .get(db_path)
        .map_or(0, |n| *n)
}

#[cfg(test)]
fn record_pool_built(db_path: &Path) {
    *POOLS_BUILT
        .get_or_init(dashmap::DashMap::new)
        .entry(db_path.to_path_buf())
        .or_insert(0) += 1;
}

impl SqlActorStore {
    /// Open (and migrate) the per-actor DB for `did` under `data_dir`.
    ///
    /// Creates the parent `actors/` directory if missing. The DB file itself
    /// is created on first connection. Migrations from `migrations/actor/`
    /// are applied.
    ///
    /// # Errors
    ///
    /// Returns [`PdsError::Storage`] on filesystem or SQLite failure;
    /// [`PdsError::Storage`] forwarded for migration failures.
    pub async fn open(data_dir: &Path, did: &str) -> PdsResult<Self> {
        let db_path = actor_db_path(data_dir, did);

        // Every trait method on the storage backends called this, so a single
        // `getRecord` opened three pools and `createRecord` with a blob ref
        // about five -- each one a `create_dir_all`, a fresh SQLite handle,
        // WAL and pragma setup, and a full run of the migration table. The
        // work was per *operation* where the thing it produces is per *actor*
        // and lives as long as the process.
        if let Some(pool) = pool_cache()
            .lock()
            .ok()
            .and_then(|mut cache| cache.get(&db_path).cloned())
        {
            return Ok(Self {
                did: did.to_string(),
                pool,
            });
        }

        if let Some(parent) = db_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("create_dir_all({}): {e}", parent.display()),
                })?;
        }

        let conn_str = format!("sqlite://{}", db_path.display());
        let opts = SqliteConnectOptions::from_str(&conn_str)
            .map_err(|e| PdsError::Storage {
                reason: format!("SqliteConnectOptions::from_str({conn_str}): {e}"),
            })?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            // mmap and busy-timeout settings are conservative defaults; a
            // production deployment may tune these via PdsConfig.
            .pragma("mmap_size", "67108864") // 64 MiB
            // Stated rather than inherited. sqlx turns this on by default, so
            // it changes nothing today -- but the schema's foreign keys are
            // only enforced because of it, and a driver swap or an options
            // refactor that dropped the default would disable every one of
            // them silently.
            .pragma("foreign_keys", "ON")
            .busy_timeout(std::time::Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("connect_with({db_path:?}): {e}"),
            })?;

        super::migrations::run_actor_migrations(&pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("actor migrations failed for {did}: {e}"),
            })?;
        #[cfg(test)]
        record_pool_built(&db_path);

        // Two tasks reaching an actor for the first time can both build a
        // pool. Both are valid -- they address the same file, and sqlx
        // serialises the migration run -- so the loser simply drops its own
        // and takes the cached one, leaving one pool per actor rather than
        // whichever arrived last.
        let pool = match pool_cache().lock() {
            Ok(mut cache) => {
                if let Some(existing) = cache.get(&db_path) {
                    existing.clone()
                } else {
                    cache.put(db_path, pool.clone());
                    pool
                }
            }
            // A poisoned cache is not a reason to refuse the request; it costs
            // this caller the pool it just built and nothing else.
            Err(_) => pool,
        };

        Ok(Self {
            did: did.to_string(),
            pool,
        })
    }

    /// Open an in-memory store for testing — no file is created.
    ///
    /// # Errors
    ///
    /// Returns [`PdsError::Storage`] if SQLite or migrations fail.
    pub async fn open_memory(did: &str) -> PdsResult<Self> {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")
            .map_err(|e| PdsError::Storage {
                reason: format!("memory opts: {e}"),
            })?
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1) // in-memory dbs are per-connection
            .connect_with(opts)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("memory connect: {e}"),
            })?;
        super::migrations::run_actor_migrations(&pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("memory migrations: {e}"),
            })?;
        Ok(Self {
            did: did.to_string(),
            pool,
        })
    }

    /// Get the underlying pool for direct queries (used by `repo::reader`,
    /// `repo::writer`, etc.).
    #[must_use]
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

#[async_trait]
impl ActorStore for SqlActorStore {
    fn did(&self) -> &str {
        &self.did
    }

    async fn ping(&self) -> PdsResult<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("ping: {e}"),
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_filename_is_deterministic() {
        assert_eq!(did_filename("did:plc:alice"), did_filename("did:plc:alice"));
        assert_ne!(did_filename("did:plc:alice"), did_filename("did:plc:bob"));
    }

    #[test]
    fn did_filename_is_filesystem_safe() {
        let f = did_filename("did:plc:abc/../etc");
        assert!(!f.contains('/'));
        assert!(!f.contains('\\'));
        assert!(!f.contains(':'));
        assert!(f.ends_with(".sqlite"));
    }

    /// Opening the same actor repeatedly builds one pool.
    ///
    /// Every storage trait method called `open`, so a single `getRecord`
    /// opened three and `createRecord` with a blob ref about five -- each a
    /// `create_dir_all`, a fresh SQLite handle, WAL and pragma setup, and a
    /// full migration-table run.
    #[tokio::test(flavor = "multi_thread")]
    async fn opening_one_actor_repeatedly_builds_one_pool() {
        let tmp = tempfile::tempdir().unwrap();
        let did = "did:plc:poolcache";

        for _ in 0..20 {
            SqlActorStore::open(tmp.path(), did)
                .await
                .expect("open should succeed");
        }
        assert_eq!(
            pools_built_for(&actor_db_path(tmp.path(), did)),
            1,
            "twenty opens of one actor should build one pool"
        );
    }

    /// Distinct actors still get distinct pools -- the cache is a cache, not a
    /// single shared connection.
    #[tokio::test(flavor = "multi_thread")]
    async fn distinct_actors_get_distinct_pools() {
        let tmp = tempfile::tempdir().unwrap();
        SqlActorStore::open(tmp.path(), "did:plc:one")
            .await
            .unwrap();
        SqlActorStore::open(tmp.path(), "did:plc:two")
            .await
            .unwrap();
        assert_eq!(
            pools_built_for(&actor_db_path(tmp.path(), "did:plc:one")),
            1
        );
        assert_eq!(
            pools_built_for(&actor_db_path(tmp.path(), "did:plc:two")),
            1
        );
    }

    /// A cached pool is usable, not merely present: a row written through one
    /// handle is readable through the next.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_cached_pool_still_reads_what_was_written_through_it() {
        let tmp = tempfile::tempdir().unwrap();
        let did = "did:plc:roundtrip";

        let first = SqlActorStore::open(tmp.path(), did).await.unwrap();
        sqlx::query("INSERT INTO repo_block (cid, data, indexed_at) VALUES (?, ?, ?)")
            .bind("bafytest")
            .bind(vec![1u8, 2, 3])
            .bind(chrono::Utc::now().to_rfc3339())
            .execute(first.pool())
            .await
            .expect("write through the first handle");

        let second = SqlActorStore::open(tmp.path(), did).await.unwrap();
        let found: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM repo_block WHERE cid = ?")
            .bind("bafytest")
            .fetch_one(second.pool())
            .await
            .expect("read through the second handle");
        assert_eq!(found.0, 1);
    }

    /// Two data directories are two databases, however the DID reads. Every
    /// test with its own `TempDir` depends on this.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_same_did_under_two_data_dirs_is_two_pools() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        SqlActorStore::open(a.path(), "did:plc:same").await.unwrap();
        SqlActorStore::open(b.path(), "did:plc:same").await.unwrap();
        assert_eq!(
            pools_built_for(&actor_db_path(a.path(), "did:plc:same")),
            1,
            "the cache must key on the database, not the DID"
        );
        assert_eq!(
            pools_built_for(&actor_db_path(b.path(), "did:plc:same")),
            1,
            "the cache must key on the database, not the DID"
        );
    }

    #[test]
    fn actor_db_path_composes() {
        let p = actor_db_path(Path::new("/var/lib/pds"), "did:plc:alice");
        let s = p.to_string_lossy();
        assert!(s.contains("actors/"));
        assert!(s.ends_with(".sqlite"));
    }

    #[tokio::test]
    async fn open_memory_runs_migrations() {
        let store = SqlActorStore::open_memory("did:plc:test").await.unwrap();
        store.ping().await.unwrap();
        // Confirm the schema landed by checking one of the tables exists.
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM repo_block")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(row.0, 0);
    }

    #[tokio::test]
    async fn spaces_tables_present_after_migration() {
        let store = SqlActorStore::open_memory("did:plc:test").await.unwrap();
        // Verify all 8 Spaces tables exist.
        for table in [
            "space",
            "space_member_state",
            "space_repo",
            "space_record",
            "space_member",
            "space_record_oplog",
            "space_member_oplog",
            "space_credential_recipient",
        ] {
            let row: (i64,) = sqlx::query_as(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(store.pool())
                .await
                .unwrap_or_else(|e| panic!("table {table} missing: {e}"));
            assert_eq!(row.0, 0);
        }
    }
}
