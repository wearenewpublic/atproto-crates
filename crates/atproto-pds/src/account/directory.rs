#![allow(clippy::type_complexity)] // SQL 9-tuple row types are clearer inline than as named aliases.
//! `AccountDirectory` — open and query the shared accounts DB.
//!
//! Opens + migrates the accounts DB; lookup by handle/email/DID;
//! list accounts. The `AccountManager` builds on top for createAccount,
//! sessions, and app-password lifecycle.
//!
//! The directory holds an [`AccountPool`] internally so a single
//! `AccountDirectory` instance serves both SQLite and Postgres
//! deployments uniformly. Bootstrap helpers `open` / `open_memory`
//! produce SQLite directories; `open_postgres` produces a Postgres
//! directory. Per-method query dispatch picks the right SQL flavor
//! at runtime.
//!
//! Compatibility shim: `pool()` keeps returning `&SqlitePool` for
//! call sites still binding to it directly. On a Postgres-backed
//! directory the accessor panics; existing call sites are
//! incrementally migrated to `account_pool()` and per-helper-method
//! dispatch.
use crate::account::state::AccountState;
use crate::account::{AccountPool, AccountPoolKind};
#[cfg(feature = "sqlite")]
use crate::actor_store::sql::run_accounts_migrations;
use crate::errors::{PdsError, PdsResult};
use serde::{Deserialize, Serialize};
#[cfg(feature = "sqlite")]
use sqlx::SqlitePool;
#[cfg(feature = "sqlite")]
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use std::path::Path;
#[cfg(feature = "sqlite")]
use std::str::FromStr;

/// One row from the `account` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRow {
    /// DID (primary key).
    pub did: String,
    /// Handle (DNS-name format).
    pub handle: String,
    /// Email address (`None` if not set).
    pub email: Option<String>,
    /// `Some(timestamp)` when email was confirmed.
    pub email_confirmed_at: Option<String>,
    /// Argon2id password hash.
    pub password_hash: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// Lifecycle state.
    pub state: AccountState,
    /// Reference into the `KeyStore` for this account's signing key.
    pub signing_key_ref: String,
    /// Whether the PDS holds the rotation key for this account's `did:plc`.
    pub pds_managed_rotation: bool,
}

/// Shared accounts DB handle.
pub struct AccountDirectory {
    pool: AccountPool,
}

impl AccountDirectory {
    /// Open (and migrate) a SQLite accounts DB.
    ///
    /// `path` may be a filesystem path or `:memory:` for in-memory testing.
    /// The DB file is created on first connection if missing.
    ///
    /// # Errors
    ///
    /// Returns [`PdsError::Storage`] on filesystem or SQLite failure;
    /// migration errors are forwarded.
    #[cfg(feature = "sqlite")]
    pub async fn open(path: &Path) -> PdsResult<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("create_dir_all({}): {e}", parent.display()),
                })?;
        }
        let conn_str = format!("sqlite://{}", path.display());
        Self::open_with_url(&conn_str).await
    }

    /// Open an in-memory SQLite accounts DB for testing.
    ///
    /// # Errors
    ///
    /// Returns [`PdsError::Storage`] on SQLite or migration failure.
    #[cfg(feature = "sqlite")]
    pub async fn open_memory() -> PdsResult<Self> {
        Self::open_with_url("sqlite::memory:").await
    }

    #[cfg(feature = "sqlite")]
    async fn open_with_url(url: &str) -> PdsResult<Self> {
        let opts = SqliteConnectOptions::from_str(url)
            .map_err(|e| PdsError::Storage {
                reason: format!("SqliteConnectOptions: {e}"),
            })?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .pragma("mmap_size", "67108864")
            // Stated rather than inherited. sqlx turns this on by default, so
            // this changes nothing today -- but the schema's fifteen foreign
            // keys are only enforced because of it, and a driver swap or an
            // options refactor that dropped the default would disable every
            // one of them silently.
            .pragma("foreign_keys", "ON");
        let pool = SqlitePoolOptions::new()
            .max_connections(if url == "sqlite::memory:" { 1 } else { 8 })
            .connect_with(opts)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("connect: {e}"),
            })?;
        run_accounts_migrations(&pool)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("accounts migrations: {e}"),
            })?;
        Ok(Self {
            pool: AccountPool::Sqlite(pool),
        })
    }

    /// Open (and migrate) a PostgreSQL accounts DB.
    ///
    /// `dsn` is a libpq URL like `postgres://user:pass@host:5432/dbname`.
    /// Runs the bundled `migrations/postgres/*.sql` schema on connect.
    #[cfg(feature = "postgres")]
    pub async fn open_postgres(dsn: &str, max_connections: u32) -> PdsResult<Self> {
        let store = super::postgres::PostgresAccountStore::connect(dsn, max_connections).await?;
        Ok(Self {
            pool: store.account_pool(),
        })
    }

    /// Construct from an already-built [`AccountPool`]. Skips the
    /// bootstrap migration step — caller is responsible for ensuring
    /// the schema is in place. Used by composing constructors and
    /// tests that share a pre-opened pool.
    #[must_use]
    pub fn from_pool(pool: AccountPool) -> Self {
        Self { pool }
    }

    /// Get the underlying SQLite pool. **Panics** when the directory
    /// is Postgres-backed; legacy call sites that need raw SQL access
    /// should migrate to [`Self::account_pool`] + the per-helper
    /// dispatch.
    #[cfg(feature = "sqlite")]
    #[must_use]
    pub fn pool(&self) -> &SqlitePool {
        self.pool.as_sqlite()
    }

    /// Wrap the underlying pool in the runtime-dispatch
    /// [`AccountPool`] enum.
    #[must_use]
    pub fn account_pool(&self) -> AccountPool {
        self.pool.clone()
    }

    /// Look up an account by DID. Returns `None` if not found.
    pub async fn lookup_did(&self, did: &str) -> PdsResult<Option<AccountRow>> {
        match self.pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                let row: Option<(
                    String,
                    String,
                    Option<String>,
                    Option<String>,
                    String,
                    String,
                    String,
                    String,
                    i64,
                )> = sqlx::query_as(
                    "SELECT did, handle, email, email_confirmed_at, password_hash, created_at, state, signing_key_ref, pds_managed_rotation
                     FROM account WHERE did = ?",
                )
                .bind(did)
                .fetch_optional(self.pool.as_sqlite())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("lookup_did: {e}"),
                })?;
                Ok(row.map(map_row_sqlite))
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                let row: Option<(
                    String,
                    String,
                    Option<String>,
                    Option<String>,
                    String,
                    String,
                    String,
                    String,
                    bool,
                )> = sqlx::query_as(
                    "SELECT did, handle, email, email_confirmed_at, password_hash, created_at, state, signing_key_ref, pds_managed_rotation
                     FROM account WHERE did = $1",
                )
                .bind(did)
                .fetch_optional(self.pool.as_postgres())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("lookup_did: {e}"),
                })?;
                Ok(row.map(map_row_pg))
            }
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        }
    }

    /// Look up an account by handle. Returns `None` if not found.
    pub async fn lookup_handle(&self, handle: &str) -> PdsResult<Option<AccountRow>> {
        match self.pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                let row: Option<(
                    String,
                    String,
                    Option<String>,
                    Option<String>,
                    String,
                    String,
                    String,
                    String,
                    i64,
                )> = sqlx::query_as(
                    "SELECT did, handle, email, email_confirmed_at, password_hash, created_at, state, signing_key_ref, pds_managed_rotation
                     FROM account WHERE handle = ?",
                )
                .bind(handle)
                .fetch_optional(self.pool.as_sqlite())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("lookup_handle: {e}"),
                })?;
                Ok(row.map(map_row_sqlite))
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                let row: Option<(
                    String,
                    String,
                    Option<String>,
                    Option<String>,
                    String,
                    String,
                    String,
                    String,
                    bool,
                )> = sqlx::query_as(
                    "SELECT did, handle, email, email_confirmed_at, password_hash, created_at, state, signing_key_ref, pds_managed_rotation
                     FROM account WHERE handle = $1",
                )
                .bind(handle)
                .fetch_optional(self.pool.as_postgres())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("lookup_handle: {e}"),
                })?;
                Ok(row.map(map_row_pg))
            }
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        }
    }

    /// List accounts, paginated by `did` (cursor is the last DID from the prior page).
    pub async fn list_accounts(
        &self,
        cursor: Option<&str>,
        limit: u32,
    ) -> PdsResult<Vec<AccountRow>> {
        match self.pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                let rows: Vec<(
                    String,
                    String,
                    Option<String>,
                    Option<String>,
                    String,
                    String,
                    String,
                    String,
                    i64,
                )> = match cursor {
                    Some(c) => sqlx::query_as(
                        "SELECT did, handle, email, email_confirmed_at, password_hash, created_at, state, signing_key_ref, pds_managed_rotation
                         FROM account WHERE did > ? ORDER BY did ASC LIMIT ?",
                    )
                    .bind(c)
                    .bind(limit as i64)
                    .fetch_all(self.pool.as_sqlite())
                    .await,
                    None => sqlx::query_as(
                        "SELECT did, handle, email, email_confirmed_at, password_hash, created_at, state, signing_key_ref, pds_managed_rotation
                         FROM account ORDER BY did ASC LIMIT ?",
                    )
                    .bind(limit as i64)
                    .fetch_all(self.pool.as_sqlite())
                    .await,
                }
                .map_err(|e| PdsError::Storage {
                    reason: format!("list_accounts: {e}"),
                })?;
                Ok(rows.into_iter().map(map_row_sqlite).collect())
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                let rows: Vec<(
                    String,
                    String,
                    Option<String>,
                    Option<String>,
                    String,
                    String,
                    String,
                    String,
                    bool,
                )> = match cursor {
                    Some(c) => sqlx::query_as(
                        "SELECT did, handle, email, email_confirmed_at, password_hash, created_at, state, signing_key_ref, pds_managed_rotation
                         FROM account WHERE did > $1 ORDER BY did ASC LIMIT $2",
                    )
                    .bind(c)
                    .bind(limit as i64)
                    .fetch_all(self.pool.as_postgres())
                    .await,
                    None => sqlx::query_as(
                        "SELECT did, handle, email, email_confirmed_at, password_hash, created_at, state, signing_key_ref, pds_managed_rotation
                         FROM account ORDER BY did ASC LIMIT $1",
                    )
                    .bind(limit as i64)
                    .fetch_all(self.pool.as_postgres())
                    .await,
                }
                .map_err(|e| PdsError::Storage {
                    reason: format!("list_accounts: {e}"),
                })?;
                Ok(rows.into_iter().map(map_row_pg).collect())
            }
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        }
    }

    /// Search accounts by handle/email substring (case-insensitive). Used
    /// by the admin `searchAccounts` endpoint. Cursor is opaque (last DID).
    pub async fn search_accounts(
        &self,
        query: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> PdsResult<Vec<AccountRow>> {
        let pattern = format!("%{}%", query.to_lowercase());
        match self.pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                let rows: Vec<(
                    String,
                    String,
                    Option<String>,
                    Option<String>,
                    String,
                    String,
                    String,
                    String,
                    i64,
                )> = match cursor {
                    Some(c) => sqlx::query_as(
                        "SELECT did, handle, email, email_confirmed_at, password_hash, created_at, state, signing_key_ref, pds_managed_rotation
                         FROM account
                         WHERE (LOWER(handle) LIKE ? OR LOWER(IFNULL(email, '')) LIKE ?)
                           AND did > ?
                         ORDER BY did ASC LIMIT ?",
                    )
                    .bind(&pattern)
                    .bind(&pattern)
                    .bind(c)
                    .bind(limit as i64)
                    .fetch_all(self.pool.as_sqlite())
                    .await,
                    None => sqlx::query_as(
                        "SELECT did, handle, email, email_confirmed_at, password_hash, created_at, state, signing_key_ref, pds_managed_rotation
                         FROM account
                         WHERE LOWER(handle) LIKE ? OR LOWER(IFNULL(email, '')) LIKE ?
                         ORDER BY did ASC LIMIT ?",
                    )
                    .bind(&pattern)
                    .bind(&pattern)
                    .bind(limit as i64)
                    .fetch_all(self.pool.as_sqlite())
                    .await,
                }
                .map_err(|e| PdsError::Storage {
                    reason: format!("search_accounts: {e}"),
                })?;
                Ok(rows.into_iter().map(map_row_sqlite).collect())
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                let rows: Vec<(
                    String,
                    String,
                    Option<String>,
                    Option<String>,
                    String,
                    String,
                    String,
                    String,
                    bool,
                )> = match cursor {
                    Some(c) => sqlx::query_as(
                        "SELECT did, handle, email, email_confirmed_at, password_hash, created_at, state, signing_key_ref, pds_managed_rotation
                         FROM account
                         WHERE (LOWER(handle) LIKE $1 OR LOWER(COALESCE(email, '')) LIKE $2)
                           AND did > $3
                         ORDER BY did ASC LIMIT $4",
                    )
                    .bind(&pattern)
                    .bind(&pattern)
                    .bind(c)
                    .bind(limit as i64)
                    .fetch_all(self.pool.as_postgres())
                    .await,
                    None => sqlx::query_as(
                        "SELECT did, handle, email, email_confirmed_at, password_hash, created_at, state, signing_key_ref, pds_managed_rotation
                         FROM account
                         WHERE LOWER(handle) LIKE $1 OR LOWER(COALESCE(email, '')) LIKE $2
                         ORDER BY did ASC LIMIT $3",
                    )
                    .bind(&pattern)
                    .bind(&pattern)
                    .bind(limit as i64)
                    .fetch_all(self.pool.as_postgres())
                    .await,
                }
                .map_err(|e| PdsError::Storage {
                    reason: format!("search_accounts: {e}"),
                })?;
                Ok(rows.into_iter().map(map_row_pg).collect())
            }
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        }
    }

    /// Insert a new account row. Low-level helper — production
    /// `createAccount` flow goes through `AccountManager::create_account`
    /// which also generates the signing key and seeds the per-actor
    /// store.
    pub async fn insert_account(&self, row: &AccountRow) -> PdsResult<()> {
        match self.pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                sqlx::query(
                    "INSERT INTO account (did, handle, email, email_confirmed_at, password_hash, created_at, state, signing_key_ref, pds_managed_rotation)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&row.did)
                .bind(&row.handle)
                .bind(&row.email)
                .bind(&row.email_confirmed_at)
                .bind(&row.password_hash)
                .bind(&row.created_at)
                .bind(row.state.as_str())
                .bind(&row.signing_key_ref)
                .bind(if row.pds_managed_rotation { 1i64 } else { 0i64 })
                .execute(self.pool.as_sqlite())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("insert_account: {e}"),
                })?;
                Ok(())
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                sqlx::query(
                    "INSERT INTO account (did, handle, email, email_confirmed_at, password_hash, created_at, state, signing_key_ref, pds_managed_rotation)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                )
                .bind(&row.did)
                .bind(&row.handle)
                .bind(&row.email)
                .bind(&row.email_confirmed_at)
                .bind(&row.password_hash)
                .bind(&row.created_at)
                .bind(row.state.as_str())
                .bind(&row.signing_key_ref)
                .bind(row.pds_managed_rotation)
                .execute(self.pool.as_postgres())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("insert_account: {e}"),
                })?;
                Ok(())
            }
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        }
    }
}

#[cfg(feature = "sqlite")]
fn map_row_sqlite(
    row: (
        String,
        String,
        Option<String>,
        Option<String>,
        String,
        String,
        String,
        String,
        i64,
    ),
) -> AccountRow {
    let (
        did,
        handle,
        email,
        email_confirmed_at,
        password_hash,
        created_at,
        state,
        signing_key_ref,
        pds_managed_rotation,
    ) = row;
    AccountRow {
        did,
        handle,
        email,
        email_confirmed_at,
        password_hash,
        created_at,
        state: AccountState::parse(&state).unwrap_or(AccountState::Active),
        signing_key_ref,
        pds_managed_rotation: pds_managed_rotation != 0,
    }
}

#[cfg(feature = "postgres")]
fn map_row_pg(
    row: (
        String,
        String,
        Option<String>,
        Option<String>,
        String,
        String,
        String,
        String,
        bool,
    ),
) -> AccountRow {
    let (
        did,
        handle,
        email,
        email_confirmed_at,
        password_hash,
        created_at,
        state,
        signing_key_ref,
        pds_managed_rotation,
    ) = row;
    AccountRow {
        did,
        handle,
        email,
        email_confirmed_at,
        password_hash,
        created_at,
        state: AccountState::parse(&state).unwrap_or(AccountState::Active),
        signing_key_ref,
        pds_managed_rotation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_row(did: &str, handle: &str) -> AccountRow {
        AccountRow {
            did: did.to_string(),
            handle: handle.to_string(),
            email: Some(format!(
                "{}@example.com",
                handle.split('.').next().unwrap_or("u")
            )),
            email_confirmed_at: None,
            password_hash: "$argon2id$dummy".to_string(),
            created_at: "2026-05-01T00:00:00Z".to_string(),
            state: AccountState::Active,
            signing_key_ref: format!("file:{}", did),
            pds_managed_rotation: true,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn open_memory_runs_migrations() {
        let dir = AccountDirectory::open_memory().await.unwrap();
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM account")
            .fetch_one(dir.pool())
            .await
            .unwrap();
        assert_eq!(count.0, 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn insert_lookup_round_trip() {
        let dir = AccountDirectory::open_memory().await.unwrap();
        let row = sample_row("did:plc:alice", "alice.example");
        dir.insert_account(&row).await.unwrap();

        let found = dir.lookup_did("did:plc:alice").await.unwrap().unwrap();
        assert_eq!(found, row);

        let found = dir.lookup_handle("alice.example").await.unwrap().unwrap();
        assert_eq!(found, row);

        assert!(dir.lookup_did("did:plc:absent").await.unwrap().is_none());
        assert!(dir.lookup_handle("absent.example").await.unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn list_paginates() {
        let dir = AccountDirectory::open_memory().await.unwrap();
        for did in ["did:plc:a", "did:plc:b", "did:plc:c", "did:plc:d"] {
            let mut row = sample_row(did, &format!("{}.example", did));
            row.handle = format!("{}.example", did);
            dir.insert_account(&row).await.unwrap();
        }
        let page1 = dir.list_accounts(None, 2).await.unwrap();
        assert_eq!(page1.len(), 2);
        assert_eq!(page1[0].did, "did:plc:a");
        let page2 = dir.list_accounts(Some(&page1[1].did), 2).await.unwrap();
        assert_eq!(page2.len(), 2);
        assert_eq!(page2[0].did, "did:plc:c");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn search_handle_substring() {
        let dir = AccountDirectory::open_memory().await.unwrap();
        for did in ["did:plc:a", "did:plc:b"] {
            dir.insert_account(&sample_row(did, &format!("{}.example", did)))
                .await
                .unwrap();
        }
        let rows = dir.search_accounts("plc", None, 10).await.unwrap();
        assert_eq!(rows.len(), 2);
        let rows = dir.search_accounts("nope", None, 10).await.unwrap();
        assert!(rows.is_empty());
    }

    /// Account-pool kind exposed via `account_pool()` matches the
    /// constructor used.
    #[tokio::test(flavor = "multi_thread")]
    async fn account_pool_kind_matches_constructor() {
        let dir = AccountDirectory::open_memory().await.unwrap();
        assert_eq!(dir.account_pool().kind(), AccountPoolKind::Sqlite);
    }
}
