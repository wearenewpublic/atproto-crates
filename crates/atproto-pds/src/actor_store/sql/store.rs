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
