//! `AccountManager` — orchestrates account creation, password verification,
//! lifecycle transitions, and signing-key handling.
//!
//! Surface:
//! - `create_account` — generate signing key, persist via KeyStore, insert
//!   account row, create per-actor SQLite file.
//! - `verify_password` — Argon2id check against stored hash.
//! - `set_state` — lifecycle transitions with validation.

use crate::account::{AccountPool, AccountPoolKind, AccountRow, AccountState};
use crate::actor_store::sql::SqlActorStore;
use crate::errors::{PdsError, PdsResult};
use crate::keys::{KeyStore, generate_account_signing_key};
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core,
};
use argon2::{Algorithm, Argon2, Params, Version};
use atproto_identity::key::KeyType;
#[cfg(feature = "sqlite")]
use sqlx::SqlitePool;
use std::path::PathBuf;

/// Account manager.
///
/// Bundles the accounts-DB pool, the data directory (for per-actor files),
/// and the configured `KeyStore`. Held by the HTTP layer so handlers can
/// route through it. The accounts pool is the runtime-dispatch
/// [`AccountPool`] enum so the same `AccountManager` instance serves
/// both SQLite and Postgres deployments uniformly.
pub struct AccountManager {
    accounts_pool: AccountPool,
    data_dir: PathBuf,
    key_store: std::sync::Arc<dyn KeyStore>,
    signing_key_type: KeyType,
}

impl AccountManager {
    /// Construct from a SQLite pool. Wraps the pool in
    /// [`AccountPool::Sqlite`] internally so existing call sites that
    /// pass a `SqlitePool` keep compiling.
    #[cfg(feature = "sqlite")]
    pub fn new(
        accounts_pool: SqlitePool,
        data_dir: PathBuf,
        key_store: std::sync::Arc<dyn KeyStore>,
        signing_key_type: KeyType,
    ) -> Self {
        Self::with_pool(
            AccountPool::Sqlite(accounts_pool),
            data_dir,
            key_store,
            signing_key_type,
        )
    }

    /// Construct from an explicit [`AccountPool`]. Use this when wiring
    /// a Postgres-backed accounts DB.
    pub fn with_pool(
        accounts_pool: AccountPool,
        data_dir: PathBuf,
        key_store: std::sync::Arc<dyn KeyStore>,
        signing_key_type: KeyType,
    ) -> Self {
        Self {
            accounts_pool,
            data_dir,
            key_store,
            signing_key_type,
        }
    }

    /// Create a new account.
    ///
    /// Pipeline:
    /// 1. Generate a fresh signing key.
    /// 2. Persist via KeyStore → get `key_ref`.
    /// 3. Hash password via Argon2id.
    /// 4. Insert `account` and `signing_key` rows.
    /// 5. Open the per-actor SQLite file (creates + migrates).
    ///
    /// # Errors
    ///
    /// - [`PdsError::AuthDenied`] if the handle or DID is already taken.
    /// - [`PdsError::Storage`] for any backend failure.
    pub async fn create_account(&self, params: CreateAccountParams<'_>) -> PdsResult<AccountRow> {
        // 0. Pre-flight uniqueness checks (handle + did).
        let existing: Option<(String,)> = match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                sqlx::query_as("SELECT did FROM account WHERE did = ? OR handle = ? LIMIT 1")
                    .bind(params.did)
                    .bind(params.handle)
                    .fetch_optional(self.accounts_pool.as_sqlite())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("uniqueness check: {e}"),
                    })?
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                sqlx::query_as("SELECT did FROM account WHERE did = $1 OR handle = $2 LIMIT 1")
                    .bind(params.did)
                    .bind(params.handle)
                    .fetch_optional(self.accounts_pool.as_postgres())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("uniqueness check: {e}"),
                    })?
            }
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => {
                unreachable!("AccountPool::Sqlite without `sqlite` feature")
            }
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        };
        if existing.is_some() {
            return Err(PdsError::AuthDenied {
                reason: format!("did or handle already exists: {}", params.handle),
            });
        }

        // 1. Resolve signing-key ref: reuse what the caller pre-allocated
        //    (PLC-genesis path) or generate + persist a fresh one.
        let signing_key_ref = if let Some(r) = params.signing_key_ref {
            r.to_string()
        } else {
            let signing_key = generate_account_signing_key(self.signing_key_type.clone())?;
            self.key_store.put(&signing_key).await?
        };
        let key_ref = signing_key_ref;

        // 2. Hash password.
        let password_hash = hash_password(params.password)?;

        // 3. Insert rows in a transaction.
        let now = chrono::Utc::now().to_rfc3339();
        let signing_key_id = format!("sk-{}", chrono::Utc::now().timestamp_millis());
        match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                let pool = self.accounts_pool.as_sqlite();
                let mut tx = pool.begin().await.map_err(|e| PdsError::Storage {
                    reason: format!("begin tx: {e}"),
                })?;
                sqlx::query(
                    "INSERT INTO account (did, handle, email, email_confirmed_at, password_hash, created_at, state, signing_key_ref, pds_managed_rotation, rotation_key_ref)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(params.did)
                .bind(params.handle)
                .bind(params.email)
                .bind(Option::<String>::None)
                .bind(&password_hash)
                .bind(&now)
                .bind(AccountState::Active.as_str())
                .bind(&key_ref)
                .bind(if params.pds_managed_rotation { 1i64 } else { 0i64 })
                .bind(params.rotation_key_ref)
                .execute(&mut *tx)
                .await
                .map_err(|e| PdsError::Storage { reason: format!("insert account: {e}") })?;

                sqlx::query(
                    "INSERT INTO signing_key (id, did, algorithm, key_ref, created_at) VALUES (?, ?, ?, ?, ?)",
                )
                .bind(&signing_key_id)
                .bind(params.did)
                .bind(format!("{:?}", self.signing_key_type))
                .bind(&key_ref)
                .bind(&now)
                .execute(&mut *tx)
                .await
                .map_err(|e| PdsError::Storage { reason: format!("insert signing_key: {e}") })?;

                tx.commit().await.map_err(|e| PdsError::Storage {
                    reason: format!("commit: {e}"),
                })?;
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                let pool = self.accounts_pool.as_postgres();
                let mut tx = pool.begin().await.map_err(|e| PdsError::Storage {
                    reason: format!("begin tx: {e}"),
                })?;
                sqlx::query(
                    "INSERT INTO account (did, handle, email, email_confirmed_at, password_hash, created_at, state, signing_key_ref, pds_managed_rotation, rotation_key_ref)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                )
                .bind(params.did)
                .bind(params.handle)
                .bind(params.email)
                .bind(Option::<String>::None)
                .bind(&password_hash)
                .bind(&now)
                .bind(AccountState::Active.as_str())
                .bind(&key_ref)
                .bind(params.pds_managed_rotation)
                .bind(params.rotation_key_ref)
                .execute(&mut *tx)
                .await
                .map_err(|e| PdsError::Storage { reason: format!("insert account: {e}") })?;

                sqlx::query(
                    "INSERT INTO signing_key (id, did, algorithm, key_ref, created_at) VALUES ($1, $2, $3, $4, $5)",
                )
                .bind(&signing_key_id)
                .bind(params.did)
                .bind(format!("{:?}", self.signing_key_type))
                .bind(&key_ref)
                .bind(&now)
                .execute(&mut *tx)
                .await
                .map_err(|e| PdsError::Storage { reason: format!("insert signing_key: {e}") })?;

                tx.commit().await.map_err(|e| PdsError::Storage {
                    reason: format!("commit: {e}"),
                })?;
            }
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => {
                unreachable!("AccountPool::Sqlite without `sqlite` feature")
            }
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        }

        // 5. Open per-actor file (creates + migrates).
        let _ = SqlActorStore::open(&self.data_dir, params.did).await?;

        Ok(AccountRow {
            did: params.did.to_string(),
            handle: params.handle.to_string(),
            email: params.email.map(str::to_string),
            email_confirmed_at: None,
            password_hash,
            created_at: now,
            state: AccountState::Active,
            signing_key_ref: key_ref,
            pds_managed_rotation: params.pds_managed_rotation,
        })
    }

    /// Verify a password against the stored Argon2id hash.
    pub async fn verify_password(&self, did: &str, password: &str) -> PdsResult<bool> {
        let row: Option<(String,)> = match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                sqlx::query_as("SELECT password_hash FROM account WHERE did = ?")
                    .bind(did)
                    .fetch_optional(self.accounts_pool.as_sqlite())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("fetch hash: {e}"),
                    })?
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                sqlx::query_as("SELECT password_hash FROM account WHERE did = $1")
                    .bind(did)
                    .fetch_optional(self.accounts_pool.as_postgres())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("fetch hash: {e}"),
                    })?
            }
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => {
                unreachable!("AccountPool::Sqlite without `sqlite` feature")
            }
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        };
        let Some((hash,)) = row else {
            return Ok(false);
        };
        Ok(verify_password(password, &hash))
    }

    /// Read an account's current state.
    ///
    /// `None` when no such account exists. An unrecognised state string in the
    /// database also yields `None` rather than a guess, so a caller gating on
    /// a specific state never mistakes an unknown value for a known one.
    ///
    /// # Errors
    ///
    /// Returns [`PdsError::Storage`] if the query fails.
    pub async fn account_state(&self, did: &str) -> PdsResult<Option<AccountState>> {
        let row: Option<(String,)> = match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => sqlx::query_as("SELECT state FROM account WHERE did = ?")
                .bind(did)
                .fetch_optional(self.accounts_pool.as_sqlite())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("fetch state: {e}"),
                })?,
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => sqlx::query_as("SELECT state FROM account WHERE did = $1")
                .bind(did)
                .fetch_optional(self.accounts_pool.as_postgres())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("fetch state: {e}"),
                })?,
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => {
                unreachable!("AccountPool::Sqlite without `sqlite` feature")
            }
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        };
        Ok(row.and_then(|(state,)| AccountState::parse(&state)))
    }

    /// Transition an account's state. Validates the transition.
    pub async fn set_state(&self, did: &str, new_state: AccountState) -> PdsResult<()> {
        let row: Option<(String,)> = match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => sqlx::query_as("SELECT state FROM account WHERE did = ?")
                .bind(did)
                .fetch_optional(self.accounts_pool.as_sqlite())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("fetch state: {e}"),
                })?,
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => sqlx::query_as("SELECT state FROM account WHERE did = $1")
                .bind(did)
                .fetch_optional(self.accounts_pool.as_postgres())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("fetch state: {e}"),
                })?,
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => {
                unreachable!("AccountPool::Sqlite without `sqlite` feature")
            }
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        };
        let (current_str,) = row.ok_or_else(|| PdsError::NotFound {
            what: format!("account {did}"),
        })?;
        let current = AccountState::parse(&current_str).unwrap_or(AccountState::Active);

        if !valid_transition(current, new_state) {
            return Err(PdsError::InvalidAccountTransition {
                from: current.to_string(),
                to: new_state.to_string(),
            });
        }

        match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                sqlx::query("UPDATE account SET state = ? WHERE did = ?")
                    .bind(new_state.as_str())
                    .bind(did)
                    .execute(self.accounts_pool.as_sqlite())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("update state: {e}"),
                    })?;
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                sqlx::query("UPDATE account SET state = $1 WHERE did = $2")
                    .bind(new_state.as_str())
                    .bind(did)
                    .execute(self.accounts_pool.as_postgres())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("update state: {e}"),
                    })?;
            }
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => {
                unreachable!("AccountPool::Sqlite without `sqlite` feature")
            }
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        }

        // Emit a `#account` firehose event into the per-actor outbox so
        // subscribers see the state change. Best-effort: a failure here is
        // logged but does not roll back the state transition.
        if let Err(e) = self.emit_account_event(did, new_state).await {
            tracing::warn!(did, ?e, "failed to emit #account event");
        }
        Ok(())
    }

    /// Append a `#account` outbox row reflecting the new state.
    async fn emit_account_event(&self, did: &str, new_state: AccountState) -> PdsResult<()> {
        let store = crate::actor_store::sql::SqlActorStore::open(&self.data_dir, did).await?;
        let outbox = crate::sequencer::OutboxReader::new(store.pool().clone());
        let payload = serde_json::json!({
            "did": did,
            "active": matches!(new_state, AccountState::Active),
            "status": match new_state {
                AccountState::Active => "active",
                AccountState::Deactivated => "deactivated",
                AccountState::Takendown => "takendown",
                AccountState::Suspended => "suspended",
                AccountState::Deleted => "deleted",
            },
        });
        let bytes = serde_json::to_vec(&payload).map_err(|e| PdsError::Storage {
            reason: format!("encode account event: {e}"),
        })?;
        outbox
            .append(crate::sequencer::EventType::Account, bytes)
            .await?;
        Ok(())
    }

    /// Get the data-dir root (used by handlers that need to spawn
    /// per-actor stores outside the manager — e.g. account migration,
    /// CAR import).
    #[must_use]
    pub fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }

    /// Get the underlying SQLite accounts pool. **Panics** when the
    /// manager is Postgres-backed; legacy call sites that need raw
    /// SQL access should migrate to [`Self::account_pool`] + the
    /// per-helper dispatch.
    #[cfg(feature = "sqlite")]
    #[must_use]
    pub fn pool(&self) -> &SqlitePool {
        self.accounts_pool.as_sqlite()
    }

    /// Get the runtime-dispatched accounts pool. The high-level
    /// helpers (`invite`, `app_password`, `denylist`,
    /// `service_auth_blacklist`) accept `&AccountPool`; this accessor
    /// is the bridge. Borrow-shaped variant of [`Self::cloned_account_pool`]
    /// for callers that just need to pass `&pool` along.
    #[must_use]
    pub fn account_pool(&self) -> AccountPool {
        self.accounts_pool.clone()
    }

    /// Get a borrow of the accounts pool — same as
    /// [`Self::account_pool`] without the clone for callers that hold
    /// the manager by reference.
    #[must_use]
    pub fn account_pool_ref(&self) -> &AccountPool {
        &self.accounts_pool
    }

    /// Get the configured KeyStore.
    pub fn key_store(&self) -> &dyn KeyStore {
        &*self.key_store
    }

    /// Update an account's email address (set or clear).
    ///
    /// Used by `confirmEmailUpdate`. Dispatches per backend.
    pub async fn set_email(&self, did: &str, email: Option<&str>) -> PdsResult<()> {
        match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                sqlx::query("UPDATE account SET email = ? WHERE did = ?")
                    .bind(email)
                    .bind(did)
                    .execute(self.accounts_pool.as_sqlite())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("set_email: {e}"),
                    })?;
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                sqlx::query("UPDATE account SET email = $1 WHERE did = $2")
                    .bind(email)
                    .bind(did)
                    .execute(self.accounts_pool.as_postgres())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("set_email: {e}"),
                    })?;
            }
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => {
                unreachable!("AccountPool::Sqlite without `sqlite` feature")
            }
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        }
        Ok(())
    }

    /// Set or clear `account.email_confirmed_at`.
    pub async fn set_email_confirmed_at(
        &self,
        did: &str,
        confirmed_at: Option<&str>,
    ) -> PdsResult<()> {
        match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                sqlx::query("UPDATE account SET email_confirmed_at = ? WHERE did = ?")
                    .bind(confirmed_at)
                    .bind(did)
                    .execute(self.accounts_pool.as_sqlite())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("set_email_confirmed_at: {e}"),
                    })?;
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                sqlx::query("UPDATE account SET email_confirmed_at = $1 WHERE did = $2")
                    .bind(confirmed_at)
                    .bind(did)
                    .execute(self.accounts_pool.as_postgres())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("set_email_confirmed_at: {e}"),
                    })?;
            }
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => {
                unreachable!("AccountPool::Sqlite without `sqlite` feature")
            }
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        }
        Ok(())
    }

    /// Replace the stored Argon2id password hash.
    pub async fn set_password_hash(&self, did: &str, hash: &str) -> PdsResult<()> {
        match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                sqlx::query("UPDATE account SET password_hash = ? WHERE did = ?")
                    .bind(hash)
                    .bind(did)
                    .execute(self.accounts_pool.as_sqlite())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("set_password_hash: {e}"),
                    })?;
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                sqlx::query("UPDATE account SET password_hash = $1 WHERE did = $2")
                    .bind(hash)
                    .bind(did)
                    .execute(self.accounts_pool.as_postgres())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("set_password_hash: {e}"),
                    })?;
            }
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => {
                unreachable!("AccountPool::Sqlite without `sqlite` feature")
            }
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        }
        Ok(())
    }

    /// Set or clear `account.delete_after` (the operator-requested
    /// hard-delete deadline).
    pub async fn set_delete_after(&self, did: &str, delete_after: Option<&str>) -> PdsResult<()> {
        match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                sqlx::query("UPDATE account SET delete_after = ? WHERE did = ?")
                    .bind(delete_after)
                    .bind(did)
                    .execute(self.accounts_pool.as_sqlite())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("set_delete_after: {e}"),
                    })?;
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                sqlx::query("UPDATE account SET delete_after = $1 WHERE did = $2")
                    .bind(delete_after)
                    .bind(did)
                    .execute(self.accounts_pool.as_postgres())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("set_delete_after: {e}"),
                    })?;
            }
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => {
                unreachable!("AccountPool::Sqlite without `sqlite` feature")
            }
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        }
        Ok(())
    }

    /// Counts of accounts grouped by lifecycle state. Backs the admin
    /// dashboard's "Accounts" summary pane. Output is sorted by state
    /// for deterministic rendering.
    pub async fn counts_by_state(&self) -> PdsResult<Vec<(String, i64)>> {
        match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                sqlx::query_as("SELECT state, COUNT(*) FROM account GROUP BY state ORDER BY state")
                    .fetch_all(self.accounts_pool.as_sqlite())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("counts_by_state: {e}"),
                    })
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                sqlx::query_as("SELECT state, COUNT(*) FROM account GROUP BY state ORDER BY state")
                    .fetch_all(self.accounts_pool.as_postgres())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("counts_by_state: {e}"),
                    })
            }
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => {
                unreachable!("AccountPool::Sqlite without `sqlite` feature")
            }
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        }
    }

    /// Look up an account's DID by email, restricted to `state =
    /// 'active'`. Returns `None` when no active account matches.
    /// Used by `requestPasswordReset` (§9.2) — silent 200 on miss
    /// keeps the endpoint from leaking existence to enumeration probes.
    pub async fn lookup_did_by_active_email(&self, email: &str) -> PdsResult<Option<String>> {
        let row: Option<(String,)> = match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                sqlx::query_as("SELECT did FROM account WHERE email = ? AND state = 'active'")
                    .bind(email)
                    .fetch_optional(self.accounts_pool.as_sqlite())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("lookup_did_by_active_email: {e}"),
                    })?
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                sqlx::query_as("SELECT did FROM account WHERE email = $1 AND state = 'active'")
                    .bind(email)
                    .fetch_optional(self.accounts_pool.as_postgres())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("lookup_did_by_active_email: {e}"),
                    })?
            }
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => {
                unreachable!("AccountPool::Sqlite without `sqlite` feature")
            }
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        };
        Ok(row.map(|(did,)| did))
    }

    /// Look up the account's `rotation_key_ref` (NULL when the account
    /// has no PDS-managed rotation key, or when the account does not
    /// exist). Both cases collapse to `Ok(None)` — callers convert to a
    /// `NoRotationKey` precondition error uniformly.
    pub async fn lookup_rotation_key_ref(&self, did: &str) -> PdsResult<Option<String>> {
        let row: Option<(Option<String>,)> = match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                sqlx::query_as("SELECT rotation_key_ref FROM account WHERE did = ?")
                    .bind(did)
                    .fetch_optional(self.accounts_pool.as_sqlite())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("lookup_rotation_key_ref: {e}"),
                    })?
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                sqlx::query_as("SELECT rotation_key_ref FROM account WHERE did = $1")
                    .bind(did)
                    .fetch_optional(self.accounts_pool.as_postgres())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("lookup_rotation_key_ref: {e}"),
                    })?
            }
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => {
                unreachable!("AccountPool::Sqlite without `sqlite` feature")
            }
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        };
        Ok(row.and_then(|(opt,)| opt))
    }

    /// Read `(handle, signing_key_ref, rotation_key_ref)` for `did`.
    /// Returns `None` when no account row exists. Backs
    /// `getRecommendedDidCredentials` — combining the three reads in
    /// one round-trip avoids an extra DB hop per request.
    pub async fn lookup_did_credentials(
        &self,
        did: &str,
    ) -> PdsResult<Option<(String, String, Option<String>)>> {
        match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => sqlx::query_as(
                "SELECT handle, signing_key_ref, rotation_key_ref FROM account WHERE did = ?",
            )
            .bind(did)
            .fetch_optional(self.accounts_pool.as_sqlite())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("lookup_did_credentials: {e}"),
            }),
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => sqlx::query_as(
                "SELECT handle, signing_key_ref, rotation_key_ref FROM account WHERE did = $1",
            )
            .bind(did)
            .fetch_optional(self.accounts_pool.as_postgres())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("lookup_did_credentials: {e}"),
            }),
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => {
                unreachable!("AccountPool::Sqlite without `sqlite` feature")
            }
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        }
    }

    /// Read just the `handle` for `did`. Used by `refreshIdentity` so
    /// the comparator only fetches the column it needs. Returns `None`
    /// when the row doesn't exist.
    pub async fn lookup_handle(&self, did: &str) -> PdsResult<Option<String>> {
        let row: Option<(String,)> = match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => sqlx::query_as("SELECT handle FROM account WHERE did = ?")
                .bind(did)
                .fetch_optional(self.accounts_pool.as_sqlite())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("lookup_handle: {e}"),
                })?,
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                sqlx::query_as("SELECT handle FROM account WHERE did = $1")
                    .bind(did)
                    .fetch_optional(self.accounts_pool.as_postgres())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("lookup_handle: {e}"),
                    })?
            }
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => {
                unreachable!("AccountPool::Sqlite without `sqlite` feature")
            }
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        };
        Ok(row.map(|(h,)| h))
    }

    /// Update `account.handle` for `did`. Returns `true` when a row
    /// was updated, `false` when the DID didn't match any row.
    pub async fn set_handle(&self, did: &str, handle: &str) -> PdsResult<bool> {
        let rows_affected = match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => sqlx::query("UPDATE account SET handle = ? WHERE did = ?")
                .bind(handle)
                .bind(did)
                .execute(self.accounts_pool.as_sqlite())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("set_handle: {e}"),
                })?
                .rows_affected(),
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                sqlx::query("UPDATE account SET handle = $1 WHERE did = $2")
                    .bind(handle)
                    .bind(did)
                    .execute(self.accounts_pool.as_postgres())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("set_handle: {e}"),
                    })?
                    .rows_affected()
            }
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => {
                unreachable!("AccountPool::Sqlite without `sqlite` feature")
            }
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        };
        Ok(rows_affected > 0)
    }

    /// Read `account.can_issue_invites`. `None` for missing accounts;
    /// `Some(true)` when issuance is enabled, `Some(false)` when
    /// disabled. SQLite stores the column as `INTEGER` (0/1); Postgres
    /// stores it as `BOOLEAN` — both are coerced here.
    pub async fn lookup_can_issue_invites(&self, did: &str) -> PdsResult<Option<bool>> {
        match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                let row: Option<(i64,)> =
                    sqlx::query_as("SELECT can_issue_invites FROM account WHERE did = ?")
                        .bind(did)
                        .fetch_optional(self.accounts_pool.as_sqlite())
                        .await
                        .map_err(|e| PdsError::Storage {
                            reason: format!("lookup_can_issue_invites: {e}"),
                        })?;
                Ok(row.map(|(flag,)| flag != 0))
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                let row: Option<(bool,)> =
                    sqlx::query_as("SELECT can_issue_invites FROM account WHERE did = $1")
                        .bind(did)
                        .fetch_optional(self.accounts_pool.as_postgres())
                        .await
                        .map_err(|e| PdsError::Storage {
                            reason: format!("lookup_can_issue_invites: {e}"),
                        })?;
                Ok(row.map(|(flag,)| flag))
            }
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => {
                unreachable!("AccountPool::Sqlite without `sqlite` feature")
            }
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        }
    }

    /// Set `account.can_issue_invites` for `did`. Returns `true` when
    /// a row was updated, `false` when the DID didn't match any row.
    pub async fn set_can_issue_invites(&self, did: &str, flag: bool) -> PdsResult<bool> {
        let rows_affected = match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                sqlx::query("UPDATE account SET can_issue_invites = ? WHERE did = ?")
                    .bind(if flag { 1i64 } else { 0i64 })
                    .bind(did)
                    .execute(self.accounts_pool.as_sqlite())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("set_can_issue_invites: {e}"),
                    })?
                    .rows_affected()
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                sqlx::query("UPDATE account SET can_issue_invites = $1 WHERE did = $2")
                    .bind(flag)
                    .bind(did)
                    .execute(self.accounts_pool.as_postgres())
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("set_can_issue_invites: {e}"),
                    })?
                    .rows_affected()
            }
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => {
                unreachable!("AccountPool::Sqlite without `sqlite` feature")
            }
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        };
        Ok(rows_affected > 0)
    }

    /// List DIDs of `Deactivated` accounts whose `delete_after`
    /// deadline is in the past (i.e. ready for hard-deletion). Backs
    /// the deletion-GC loop in `bin/pds.rs`. The caller passes its own
    /// "now" so tests can drive the cutoff deterministically.
    pub async fn list_pending_deletions(&self, now: &str) -> PdsResult<Vec<String>> {
        let rows: Vec<(String,)> = match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => sqlx::query_as(
                "SELECT did FROM account
                 WHERE state = 'deactivated' AND delete_after IS NOT NULL
                   AND delete_after <= ?",
            )
            .bind(now)
            .fetch_all(self.accounts_pool.as_sqlite())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("list_pending_deletions: {e}"),
            })?,
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => sqlx::query_as(
                "SELECT did FROM account
                 WHERE state = 'deactivated' AND delete_after IS NOT NULL
                   AND delete_after <= $1",
            )
            .bind(now)
            .fetch_all(self.accounts_pool.as_postgres())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("list_pending_deletions: {e}"),
            })?,
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => {
                unreachable!("AccountPool::Sqlite without `sqlite` feature")
            }
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        };
        Ok(rows.into_iter().map(|(d,)| d).collect())
    }

    /// Reserve a signing-key row in the `signing_key` table. Idempotent
    /// — if `id` already exists the call is a no-op. Used by
    /// `reserveSigningKey` (§4.5) so the same physical key can be
    /// returned on retried calls for the same DID.
    pub async fn reserve_signing_key(
        &self,
        id: &str,
        did: &str,
        algorithm: &str,
        key_ref: &str,
        created_at: &str,
    ) -> PdsResult<()> {
        match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                sqlx::query(
                    "INSERT OR IGNORE INTO signing_key (id, did, algorithm, key_ref, created_at)
                     VALUES (?, ?, ?, ?, ?)",
                )
                .bind(id)
                .bind(did)
                .bind(algorithm)
                .bind(key_ref)
                .bind(created_at)
                .execute(self.accounts_pool.as_sqlite())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("reserve_signing_key: {e}"),
                })?;
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                sqlx::query(
                    "INSERT INTO signing_key (id, did, algorithm, key_ref, created_at)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (id) DO NOTHING",
                )
                .bind(id)
                .bind(did)
                .bind(algorithm)
                .bind(key_ref)
                .bind(created_at)
                .execute(self.accounts_pool.as_postgres())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("reserve_signing_key: {e}"),
                })?;
            }
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => {
                unreachable!("AccountPool::Sqlite without `sqlite` feature")
            }
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        }
        Ok(())
    }
}

/// Inputs for `create_account`.
///
/// Use the builder-style accessors: `CreateAccountParams::new(did, handle,
/// password)` then `.with_email(...)` / `.with_pds_managed_rotation(true)`
/// / `.with_keys(rotation_ref, signing_ref)` to opt into PLC-genesis-supplied
/// keys. Optional fields default to None.
#[derive(Debug, Default)]
pub struct CreateAccountParams<'a> {
    /// DID for the new account.
    pub did: &'a str,
    /// Handle (DNS-name).
    pub handle: &'a str,
    /// Optional email.
    pub email: Option<&'a str>,
    /// Plaintext password (will be Argon2id-hashed before persistence).
    pub password: &'a str,
    /// Whether the PDS holds the rotation key.
    pub pds_managed_rotation: bool,
    /// Optional pre-allocated rotation-key ref. When `Some`, the manager skips
    /// signing-key generation/persistence in favor of the supplied refs (used
    /// by the createAccount-with-PLC-genesis path so the same keys land in
    /// the account row that were used to sign the genesis op).
    pub rotation_key_ref: Option<&'a str>,
    /// Optional pre-allocated signing-key ref. See `rotation_key_ref`.
    pub signing_key_ref: Option<&'a str>,
}

impl<'a> CreateAccountParams<'a> {
    /// Construct with the three required fields. All optional fields default
    /// to None / false / etc.
    #[must_use]
    pub fn new(did: &'a str, handle: &'a str, password: &'a str) -> Self {
        Self {
            did,
            handle,
            email: None,
            password,
            pds_managed_rotation: false,
            rotation_key_ref: None,
            signing_key_ref: None,
        }
    }
    /// Set email.
    #[must_use]
    pub fn with_email(mut self, email: Option<&'a str>) -> Self {
        self.email = email;
        self
    }
    /// Set pds_managed_rotation.
    #[must_use]
    pub fn with_pds_managed_rotation(mut self, v: bool) -> Self {
        self.pds_managed_rotation = v;
        self
    }
    /// Pre-allocated key refs from PLC genesis.
    #[must_use]
    pub fn with_keys(
        mut self,
        rotation_key_ref: Option<&'a str>,
        signing_key_ref: Option<&'a str>,
    ) -> Self {
        self.rotation_key_ref = rotation_key_ref;
        self.signing_key_ref = signing_key_ref;
        self
    }
}

/// Hash a password with Argon2id default parameters.
pub fn hash_password(password: &str) -> PdsResult<String> {
    let salt = SaltString::generate(&mut rand_core::OsRng);
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default());
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| PdsError::Storage {
            reason: format!("argon2 hash: {e}"),
        })?;
    Ok(hash.to_string())
}

/// Verify a password against an Argon2 hash. Returns `false` on mismatch or
/// invalid hash format.
#[must_use]
pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(p) => p,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

fn valid_transition(from: AccountState, to: AccountState) -> bool {
    use AccountState::*;
    match (from, to) {
        // No-op identity transitions are valid.
        (a, b) if a == b => true,
        // Active can go anywhere except back from Deleted.
        (Active, Deactivated) | (Active, Takendown) | (Active, Suspended) | (Active, Deleted) => {
            true
        }
        // Deactivated can be reactivated, taken down, suspended, or deleted.
        (Deactivated, Active)
        | (Deactivated, Takendown)
        | (Deactivated, Suspended)
        | (Deactivated, Deleted) => true,
        // Takedown/suspension can be lifted (admin) or escalated to delete.
        (Takendown, Active) | (Takendown, Suspended) | (Takendown, Deleted) => true,
        (Suspended, Active) | (Suspended, Takendown) | (Suspended, Deleted) => true,
        // Deleted is terminal.
        (Deleted, _) => false,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountDirectory;
    use crate::actor_store::sql::did_filename;
    use crate::keys::MemoryKeyStore;
    use std::sync::Arc;
    use tempfile::TempDir;

    async fn fresh_manager() -> (AccountManager, AccountDirectory, TempDir) {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
            .await
            .unwrap();
        let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
        let manager = AccountManager::new(
            accounts.pool().clone(),
            dir,
            key_store,
            KeyType::K256Private,
        );
        (manager, accounts, tmp)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_account_round_trip() {
        let (manager, dir, _tmp) = fresh_manager().await;
        let row = manager
            .create_account(CreateAccountParams {
                did: "did:plc:alice",
                handle: "alice.example",
                email: Some("alice@example.com"),
                password: "correct horse battery staple",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(row.handle, "alice.example");
        assert_eq!(row.state, AccountState::Active);

        // Lookup roundtrip.
        let looked_up = dir.lookup_did("did:plc:alice").await.unwrap().unwrap();
        assert_eq!(looked_up.email, Some("alice@example.com".to_string()));

        // Per-actor file exists.
        let actor_path = manager
            .data_dir
            .join("actors")
            .join(did_filename("did:plc:alice"));
        assert!(actor_path.exists());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_account_duplicate_handle_rejected() {
        let (manager, _dir, _tmp) = fresh_manager().await;
        manager
            .create_account(CreateAccountParams {
                did: "did:plc:alice",
                handle: "alice.example",
                email: None,
                password: "pw",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let result = manager
            .create_account(CreateAccountParams {
                did: "did:plc:bob",
                handle: "alice.example",
                email: None,
                password: "pw",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await;
        assert!(matches!(result, Err(PdsError::AuthDenied { .. })));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_password_correct_and_wrong() {
        let (manager, _dir, _tmp) = fresh_manager().await;
        manager
            .create_account(CreateAccountParams {
                did: "did:plc:alice",
                handle: "alice.example",
                email: None,
                password: "correct horse",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await
            .unwrap();

        assert!(
            manager
                .verify_password("did:plc:alice", "correct horse")
                .await
                .unwrap()
        );
        assert!(
            !manager
                .verify_password("did:plc:alice", "wrong")
                .await
                .unwrap()
        );
        assert!(
            !manager
                .verify_password("did:plc:absent", "anything")
                .await
                .unwrap()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn set_state_transitions() {
        let (manager, _dir, _tmp) = fresh_manager().await;
        manager
            .create_account(CreateAccountParams {
                did: "did:plc:alice",
                handle: "alice.example",
                email: None,
                password: "pw",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await
            .unwrap();

        // Active → Deactivated → Active is fine.
        manager
            .set_state("did:plc:alice", AccountState::Deactivated)
            .await
            .unwrap();
        manager
            .set_state("did:plc:alice", AccountState::Active)
            .await
            .unwrap();

        // Active → Deleted is fine; Deleted → anything is rejected.
        manager
            .set_state("did:plc:alice", AccountState::Deleted)
            .await
            .unwrap();
        let err = manager
            .set_state("did:plc:alice", AccountState::Active)
            .await;
        assert!(matches!(
            err,
            Err(PdsError::InvalidAccountTransition { .. })
        ));
    }

    #[test]
    fn valid_transitions_match_design_spec() {
        use AccountState::*;
        // Identity transitions
        assert!(valid_transition(Active, Active));
        // Forward transitions from Active
        assert!(valid_transition(Active, Deactivated));
        assert!(valid_transition(Active, Takendown));
        // Deleted is terminal
        assert!(!valid_transition(Deleted, Active));
        assert!(!valid_transition(Deleted, Takendown));
    }

    #[test]
    fn argon2_hash_verify_round_trip() {
        let hash = hash_password("hello").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("hello", &hash));
        assert!(!verify_password("wrong", &hash));
    }

    #[test]
    fn argon2_unique_salts_produce_different_hashes() {
        let h1 = hash_password("same").unwrap();
        let h2 = hash_password("same").unwrap();
        assert_ne!(h1, h2);
    }
}
