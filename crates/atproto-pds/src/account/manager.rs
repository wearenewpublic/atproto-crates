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

    /// Reject a signup whose DID, handle or email already belongs to an
    /// account here, naming the column that collided.
    ///
    /// `create_account` runs this itself, so a caller that only creates
    /// accounts need not. The `com.atproto.server.createAccount` handler runs
    /// it a second time, *before* PLC genesis, because minting a `did:plc`
    /// publishes an operation to the directory's append-only log and nothing
    /// can withdraw it: discovering the conflict afterwards would strand a
    /// fresh identity in a permanent public log on every duplicate signup.
    ///
    /// Pass `None` for `did` when the identifier has not been minted yet. A
    /// NULL bind makes `did = ?` evaluate to NULL rather than true, so no row
    /// matches on that column and the handle and email are checked alone; the
    /// same is true of a `None` email, which is why an account created without
    /// one never collides.
    ///
    /// This is a read with nothing holding it against the later INSERT, so it
    /// narrows the window rather than closing it. `account_insert_conflict`
    /// classifies whatever still reaches the constraint.
    ///
    /// # Errors
    ///
    /// One error per unique column, because the remedies differ and
    /// `com.atproto.server.createAccount` maps them to different names:
    ///
    /// - [`PdsError::AccountAlreadyExists`] if the DID is already hosted here.
    /// - [`PdsError::HandleNotAvailable`] if the handle is taken.
    /// - [`PdsError::EmailNotAvailable`] if the email belongs to another account.
    /// - [`PdsError::Storage`] if the read itself fails.
    pub async fn ensure_available(
        &self,
        did: Option<&str>,
        handle: &str,
        email: Option<&str>,
    ) -> PdsResult<()> {
        // `did`, `handle` and `email` each carry their own UNIQUE constraint,
        // and the caller has to be told which one it collided with: they map to
        // three different XRPC errors and three different remedies. The old
        // query selected only `did`, tested `did OR handle`, and reported both
        // as one message — and never looked at `email` at all, so an email
        // collision escaped as a constraint violation from the INSERT.
        //
        // `LIMIT 3` bounds the read while still allowing each of the three
        // columns to be reported by a distinct existing row.
        let existing: Vec<(String, String, Option<String>)> = match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => sqlx::query_as(
                "SELECT did, handle, email FROM account WHERE did = ? OR handle = ? OR email = ? LIMIT 3",
            )
            .bind(did)
            .bind(handle)
            .bind(email)
            .fetch_all(self.accounts_pool.as_sqlite())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("uniqueness check: {e}"),
            })?,
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => sqlx::query_as(
                "SELECT did, handle, email FROM account WHERE did = $1 OR handle = $2 OR email = $3 LIMIT 3",
            )
            .bind(did)
            .bind(handle)
            .bind(email)
            .fetch_all(self.accounts_pool.as_postgres())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("uniqueness check: {e}"),
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
        // Precedence runs did → handle → email. A DID collision subsumes the
        // other two: the identity is already hosted here, so reporting a
        // taken handle would send the caller off to rename an account they
        // already own.
        if let Some(did) = did
            && existing.iter().any(|(taken, _, _)| taken == did)
        {
            return Err(PdsError::AccountAlreadyExists {
                did: did.to_string(),
            });
        }
        if existing.iter().any(|(_, taken, _)| taken == handle) {
            return Err(PdsError::HandleNotAvailable {
                handle: handle.to_string(),
            });
        }
        if let Some(email) = email
            && existing
                .iter()
                .any(|(_, _, taken)| taken.as_deref() == Some(email))
        {
            return Err(PdsError::EmailNotAvailable {
                email: email.to_string(),
            });
        }
        Ok(())
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
    /// One error per unique column, because the remedies differ and
    /// `com.atproto.server.createAccount` maps them to different names:
    ///
    /// - [`PdsError::AccountAlreadyExists`] if the DID is already hosted here.
    /// - [`PdsError::HandleNotAvailable`] if the handle is taken.
    /// - [`PdsError::EmailNotAvailable`] if the email belongs to another account.
    /// - [`PdsError::Storage`] for any backend failure.
    pub async fn create_account(&self, params: CreateAccountParams<'_>) -> PdsResult<AccountRow> {
        // 0. Pre-flight uniqueness checks. See `ensure_available` — the DID is
        //    known here, so all three columns are checked.
        self.ensure_available(Some(params.did), params.handle, params.email)
            .await?;

        // 1. Resolve signing-key ref: reuse what the caller pre-allocated
        //    (PLC-genesis path) or generate + persist a fresh one.
        let signing_key_ref = if let Some(r) = params.signing_key_ref {
            r.to_string()
        } else {
            let signing_key = generate_account_signing_key(self.signing_key_type.clone())?;
            self.key_store.put(&signing_key).await?
        };
        let key_ref = signing_key_ref;

        // 1b. Same for the rotation key, and for the same reason.
        //
        // PLC genesis pre-allocates one; every other path — inbound account
        // migration above all — arrives with `None` and previously got no
        // rotation key at all, while still recording
        // `pds_managed_rotation = true`. The row then said this server managed
        // a rotation key it did not have.
        //
        // That is unrecoverable for a migrating account rather than merely
        // untidy. Without a rotation key, `getRecommendedDidCredentials`
        // returns `rotationKeys: []`, so the PLC operation built from it would
        // list no rotation keys and leave the DID permanently unupdatable by
        // anyone. `submitPlcOperation` refuses it — correctly — and the
        // migration cannot complete: the destination can never take over the
        // identity.
        //
        // The reference has no equivalent gap because it recommends one
        // service-wide rotation key (`ctx.plcRotationKey.did()`,
        // packages/pds/src/api/com/atproto/identity/
        // getRecommendedDidCredentials.ts) and so always returns at least one.
        // This implementation keeps its per-account model and mints the key
        // here instead.
        //
        // P-256 to match what genesis mints (`PlcConfig::rotation_key_type`).
        let rotation_key_ref: Option<String> = if let Some(r) = params.rotation_key_ref {
            Some(r.to_string())
        } else if params.pds_managed_rotation {
            let rotation_key = generate_account_signing_key(KeyType::P256Private)?;
            Some(self.key_store.put(&rotation_key).await?)
        } else {
            None
        };

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
                .bind(params.state.as_str())
                .bind(&key_ref)
                .bind(if params.pds_managed_rotation { 1i64 } else { 0i64 })
                .bind(rotation_key_ref.as_deref())
                .execute(&mut *tx)
                .await
                .map_err(|e| account_insert_conflict(&e, &params)
                    .unwrap_or_else(|| PdsError::Storage { reason: format!("insert account: {e}") }))?;

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
                .bind(params.state.as_str())
                .bind(&key_ref)
                .bind(params.pds_managed_rotation)
                .bind(rotation_key_ref.as_deref())
                .execute(&mut *tx)
                .await
                .map_err(|e| account_insert_conflict(&e, &params)
                    .unwrap_or_else(|| PdsError::Storage { reason: format!("insert account: {e}") }))?;

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

        // 6. Tell the network the account exists.
        //
        // A relay or appview learns that an account exists from `#identity` and
        // `#account`; without them a new account is invisible until it happens
        // to write a record, and a consumer that indexes identity separately
        // never learns its handle at all. The reference sequences both as part
        // of account creation.
        //
        // Emitted here rather than in the `createAccount` handler because this
        // is the choke point every creation path passes through — the handler,
        // account migration, and fixtures alike. Announcing from one caller
        // would leave the others silent.
        //
        // Only for accounts that land active. A verified inbound migration
        // lands deactivated on purpose: until the DID document points here the
        // repository must not be publicly readable or emit firehose events, and
        // announcing it would contradict that. `set_account_state` already
        // emits `#account` when such an account is later activated.
        //
        // NOT emitted: `#commit` and `#sync`, which the reference also
        // sequences at this point. It can, because it creates an empty
        // repository with a genesis commit; this server defers the first commit
        // to the first write, so `getLatestCommit` answers `RepoNotFound` until
        // then and there is no commit to name. Emitting either would mean
        // inventing one. A genesis commit at signup is separate work.
        //
        // Best-effort, matching `set_account_state`: the account is durable by
        // this point, and a consumer that misses the announcement recovers by
        // resolving the identity. Failing the creation would be worse.
        if matches!(params.state, AccountState::Active) {
            if let Err(e) = self
                .emit_identity_event(params.did, Some(params.handle))
                .await
            {
                tracing::warn!(
                    did = params.did,
                    ?e,
                    "failed to emit #identity for a new account"
                );
            }
            if let Err(e) = self
                .emit_account_event(params.did, AccountState::Active)
                .await
            {
                tracing::warn!(
                    did = params.did,
                    ?e,
                    "failed to emit #account for a new account"
                );
            }
        }

        Ok(AccountRow {
            did: params.did.to_string(),
            handle: params.handle.to_string(),
            email: params.email.map(str::to_string),
            email_confirmed_at: None,
            password_hash,
            created_at: now,
            state: params.state,
            signing_key_ref: key_ref,
            pds_managed_rotation: params.pds_managed_rotation,
        })
    }

    /// Set the account password, creating the implicit "primary" app-password
    /// row on first use and replacing it thereafter.
    ///
    /// `createSession` verifies against an app-password row, never against
    /// `account.password_hash` directly, so an account without this row exists
    /// but cannot log in. Account creation therefore has two steps, and having
    /// them inline in the handler meant every other caller — tests included —
    /// had to know that and repeat it.
    ///
    /// # One password, two stores
    ///
    /// The same secret is held twice: `account.password_hash`, which
    /// `verify_password` reads and the OAuth consent form falls back to, and
    /// the `__primary__` row, which `createSession` and the portal read. Both
    /// have to move together or the account has two passwords — and since
    /// neither reader consults the other, the one left behind is a live
    /// credential that no screen mentions and no revocation touches.
    ///
    /// Writing them together here is what makes that true for every caller,
    /// rather than being something each of `createAccount`, `resetPassword` and
    /// the portal has to remember separately. The password is hashed once and
    /// the hash used for both.
    ///
    /// Returns the app-password row id, which a session is issued against.
    ///
    /// # Errors
    ///
    /// Returns [`PdsError::Storage`] if either write fails.
    pub async fn set_primary_password(&self, did: &str, password: &str) -> PdsResult<String> {
        let hash = crate::account::hash_password(password)?;
        self.set_password_hash(did, &hash).await?;
        crate::account::app_password::upsert_primary(&self.account_pool(), did, &hash).await
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

        // Emit a `#account` event onto the firehose stream so subscribers see
        // the state change. Best-effort: a failure here is logged but does not
        // roll back the state transition.
        if let Err(e) = self.emit_account_event(did, new_state).await {
            tracing::warn!(did, ?e, "failed to emit #account event");
        }
        Ok(())
    }

    /// Append an `#identity` event announcing a DID and its handle.
    ///
    /// Mirrors `crate::http::identity_handlers::emit_identity_event`, which
    /// serves the handle-change paths; this one exists so account creation does
    /// not have to reach into the HTTP layer.
    async fn emit_identity_event(&self, did: &str, handle: Option<&str>) -> PdsResult<()> {
        let bytes = crate::sequencer::payload::encode(&crate::sequencer::payload::IdentityBody {
            did: did.to_string(),
            handle: handle.map(str::to_string),
        })?;
        self.sequencer()
            .append(did, crate::sequencer::EventType::Identity.as_str(), bytes)
            .await?;
        Ok(())
    }

    /// Append an `#account` event to the firehose stream reflecting the new
    /// state.
    async fn emit_account_event(&self, did: &str, new_state: AccountState) -> PdsResult<()> {
        // `status` is optional, not nullable: an active account carries none.
        // Emitting `status: "active"` alongside `active: true` says the same
        // thing twice and is not a value the lexicon lists.
        let active = matches!(new_state, AccountState::Active);
        let bytes = crate::sequencer::payload::encode(&crate::sequencer::payload::AccountBody {
            did: did.to_string(),
            active,
            status: (!active).then(|| new_state.as_str().to_string()),
        })?;
        self.sequencer()
            .append(did, crate::sequencer::EventType::Account.as_str(), bytes)
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

    /// Handle on the firehose stream.
    ///
    /// The stream log lives in the accounts database, so every holder of the
    /// accounts pool can append to it without extra plumbing.
    #[must_use]
    pub fn sequencer(&self) -> crate::sequencer::Sequencer {
        crate::sequencer::Sequencer::new(self.accounts_pool.clone())
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
    /// Used by `confirmEmailUpdate` and the portal. Dispatches per backend.
    ///
    /// `account.email` is `UNIQUE`, so moving onto an address another account
    /// already holds fails here. That is a caller error and reports as
    /// [`PdsError::EmailNotAvailable`]; letting it through as a storage fault
    /// told the account holder their server was broken when what they needed to
    /// hear was that the address was taken.
    pub async fn set_email(&self, did: &str, email: Option<&str>) -> PdsResult<()> {
        match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                sqlx::query("UPDATE account SET email = ? WHERE did = ?")
                    .bind(email)
                    .bind(did)
                    .execute(self.accounts_pool.as_sqlite())
                    .await
                    .map_err(|e| {
                        email_update_conflict(&e, email).unwrap_or(PdsError::Storage {
                            reason: format!("set_email: {e}"),
                        })
                    })?;
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                sqlx::query("UPDATE account SET email = $1 WHERE did = $2")
                    .bind(email)
                    .bind(did)
                    .execute(self.accounts_pool.as_postgres())
                    .await
                    .map_err(|e| {
                        email_update_conflict(&e, email).unwrap_or(PdsError::Storage {
                            reason: format!("set_email: {e}"),
                        })
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

    /// The key ref of an existing signing-key reservation for `did`, if any.
    ///
    /// `reserve_signing_key` stores the first reservation and ignores later
    /// ones, so without this lookup the endpoint handed out a fresh key on
    /// every call while the stored row kept the original — the returned key and
    /// the reserved key diverged after the first request.
    ///
    /// # Errors
    ///
    /// Returns [`PdsError::Storage`] if the query fails.
    pub async fn lookup_reserved_signing_key(&self, did: &str) -> PdsResult<Option<String>> {
        let row: Option<(String,)> = match self.accounts_pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => {
                sqlx::query_as("SELECT key_ref FROM signing_key WHERE did = ? LIMIT 1")
                    .bind(did)
                    .fetch_optional(self.accounts_pool.as_sqlite())
                    .await
            }
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => {
                sqlx::query_as("SELECT key_ref FROM signing_key WHERE did = $1 LIMIT 1")
                    .bind(did)
                    .fetch_optional(self.accounts_pool.as_postgres())
                    .await
            }
            #[allow(unreachable_patterns)]
            _ => Ok(None),
        }
        .map_err(|e| PdsError::Storage {
            reason: format!("lookup_reserved_signing_key: {e}"),
        })?;
        Ok(row.map(|(r,)| r))
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

/// Classify a failed `INSERT INTO account` as a uniqueness conflict, naming
/// the column that collided.
///
/// The pre-flight check in `create_account` is a read followed by a write with
/// nothing holding the gap, so two concurrent signups for the same handle or
/// email can both pass it and one of them still reaches this INSERT. Left
/// alone that loser becomes [`PdsError::Storage`] — a 500 carrying the storage
/// engine's own wording — for what is squarely a client-side conflict.
///
/// Returns `None` for anything this function cannot name as a client-side
/// conflict, so the caller keeps reporting genuine backend faults as backend
/// faults.
/// Map a `UNIQUE` violation on `account.email` from an `UPDATE` to the error
/// that names it.
///
/// The insert path has [`account_insert_conflict`], which reads the whole
/// create request to say which column collided. An update touches one column,
/// so the address is the one that was passed in.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
fn email_update_conflict(error: &sqlx::Error, email: Option<&str>) -> Option<PdsError> {
    let db = error.as_database_error()?;
    if !db.is_unique_violation() {
        return None;
    }
    // Same reasoning as `account_insert_conflict`: SQLite and Postgres word the
    // violation differently but both name the column, so match on that.
    let detail = format!("{} {}", db.constraint().unwrap_or_default(), db.message());
    if !detail.contains("email") {
        return None;
    }
    // A NULL email violates a UNIQUE index on neither engine, so a clear cannot
    // be what collided. `map` keeps the engine's own wording on the way to a
    // storage fault if it somehow did.
    email.map(|email| PdsError::EmailNotAvailable {
        email: email.to_string(),
    })
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
fn account_insert_conflict(
    error: &sqlx::Error,
    params: &CreateAccountParams<'_>,
) -> Option<PdsError> {
    let db = error.as_database_error()?;
    if !db.is_unique_violation() {
        return None;
    }
    // SQLite reports `UNIQUE constraint failed: account.email`; Postgres
    // reports `duplicate key value violates unique constraint
    // "account_email_key"` and also exposes the constraint name directly.
    // The column name is the one token both spellings share, so match on it
    // rather than on either backend's phrasing.
    let detail = format!("{} {}", db.constraint().unwrap_or_default(), db.message());
    if detail.contains("email") {
        // The message names a column, never a value, so the address has to come
        // from the request — and only a request that carried one can have
        // collided, since a NULL email violates a UNIQUE index on neither
        // engine. `map` rather than `unwrap_or_default` because the alternative
        // renders as "the email address  is already registered": if the request
        // had no email this is not the conflict it claims to be, and `None`
        // keeps the engine's own wording on the way to a backend fault where it
        // can be diagnosed.
        return params.email.map(|email| PdsError::EmailNotAvailable {
            email: email.to_string(),
        });
    }
    if detail.contains("handle") {
        return Some(PdsError::HandleNotAvailable {
            handle: params.handle.to_string(),
        });
    }
    // The remaining unique column is the primary key on `did`, whose
    // violation Postgres names `account_pkey` and SQLite names
    // `account.did` — neither mentions a column this function can match, so
    // it is the fallback rather than a third arm.
    Some(PdsError::AccountAlreadyExists {
        did: params.did.to_string(),
    })
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
    /// Lifecycle state the account is created in.
    ///
    /// An inbound migration lands [`AccountState::Deactivated`]: the canonical
    /// sequence is create → import → `submitPlcOperation` → activate, and until
    /// the DID document points here the repository must not be publicly
    /// readable or emitting firehose events. Landing `Active` also left
    /// `activateAccount` with nothing to gate.
    pub state: AccountState,
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
            state: AccountState::Active,
        }
    }

    /// Set the lifecycle state the account is created in.
    #[must_use]
    pub fn with_state(mut self, state: AccountState) -> Self {
        self.state = state;
        self
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

    /// An account that opts into PDS-managed rotation gets a rotation key
    /// even when the caller pre-allocated none.
    ///
    /// This is the inbound-migration shape: `createAccount` with a
    /// caller-supplied DID skips PLC genesis, so nothing pre-allocates a
    /// rotation key, and the account previously landed with
    /// `pds_managed_rotation = true` and `rotation_key_ref = NULL`. That
    /// combination made the migration unfinishable —
    /// `getRecommendedDidCredentials` returned an empty `rotationKeys`, so the
    /// PLC operation built from it would have left the DID unupdatable and
    /// `submitPlcOperation` refused it.
    #[tokio::test(flavor = "multi_thread")]
    async fn create_account_mints_a_rotation_key_when_none_was_preallocated() {
        let (manager, _dir, _tmp) = fresh_manager().await;
        manager
            .create_account(CreateAccountParams {
                did: "did:plc:migrated",
                handle: "migrated.example",
                email: Some("migrated@example.com"),
                password: "correct horse battery staple",
                pds_managed_rotation: true,
                rotation_key_ref: None,
                ..Default::default()
            })
            .await
            .unwrap();

        let key_ref = manager
            .lookup_rotation_key_ref("did:plc:migrated")
            .await
            .unwrap()
            .expect("a PDS-managed account must have a rotation key to manage");
        // Resolvable, not merely non-NULL: a dangling ref would fail at
        // signPlcOperation instead of here.
        manager.key_store().get(&key_ref).await.unwrap();
    }

    /// The mirror: an account that did not opt in gets no key. Minting one
    /// unconditionally would claim rotation authority this server was never
    /// given.
    #[tokio::test(flavor = "multi_thread")]
    async fn create_account_without_managed_rotation_gets_no_rotation_key() {
        let (manager, _dir, _tmp) = fresh_manager().await;
        manager
            .create_account(CreateAccountParams {
                did: "did:plc:external",
                handle: "external.example",
                email: Some("external@example.com"),
                password: "correct horse battery staple",
                pds_managed_rotation: false,
                ..Default::default()
            })
            .await
            .unwrap();

        assert!(
            manager
                .lookup_rotation_key_ref("did:plc:external")
                .await
                .unwrap()
                .is_none(),
        );
    }

    /// A taken handle has to arrive as `HandleNotAvailable`: it is the name
    /// `com.atproto.server.createAccount` declares, and clients switch on the
    /// name. This asserted `AuthDenied` before, which reached the wire as a
    /// 403 `Forbidden` that the lexicon does not list.
    #[tokio::test(flavor = "multi_thread")]
    async fn create_account_duplicate_handle_rejected() {
        let (manager, _dir, _tmp) = fresh_manager().await;
        manager
            .create_account(CreateAccountParams {
                did: "did:plc:alice",
                handle: "alice.example",
                email: Some("alice@example.com"),
                password: "pw",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await
            .unwrap();
        // A fresh DID and a fresh email, so only the handle can be the
        // conflict being reported.
        let result = manager
            .create_account(CreateAccountParams {
                did: "did:plc:bob",
                handle: "alice.example",
                email: Some("bob@example.com"),
                password: "pw",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await;
        assert!(
            matches!(result, Err(PdsError::HandleNotAvailable { ref handle }) if handle == "alice.example"),
            "got {result:?}"
        );
    }

    /// A taken email used to reach the INSERT and come back as a storage
    /// fault — a 500 quoting SQLite's constraint text at the caller.
    #[tokio::test(flavor = "multi_thread")]
    async fn create_account_duplicate_email_rejected() {
        let (manager, _dir, _tmp) = fresh_manager().await;
        manager
            .create_account(CreateAccountParams {
                did: "did:plc:alice",
                handle: "alice.example",
                email: Some("shared@example.com"),
                password: "pw",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let result = manager
            .create_account(CreateAccountParams {
                did: "did:plc:bob",
                handle: "bob.example",
                email: Some("shared@example.com"),
                password: "pw",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await;
        assert!(
            matches!(result, Err(PdsError::EmailNotAvailable { ref email }) if email == "shared@example.com"),
            "got {result:?}"
        );
        let Err(err) = result else { unreachable!() };
        assert!(
            !err.to_string().contains("UNIQUE constraint"),
            "storage-engine wording escaped: {err}"
        );
    }

    /// Accounts without an email do not collide with each other: `NULL = ?`
    /// is not true, so the pre-flight check must not treat two `NULL` emails
    /// as a match.
    #[tokio::test(flavor = "multi_thread")]
    async fn create_account_without_email_does_not_collide() {
        let (manager, _dir, _tmp) = fresh_manager().await;
        for (did, handle) in [
            ("did:plc:alice", "alice.example"),
            ("did:plc:bob", "bob.example"),
        ] {
            manager
                .create_account(CreateAccountParams {
                    did,
                    handle,
                    email: None,
                    password: "pw",
                    pds_managed_rotation: true,
                    ..Default::default()
                })
                .await
                .expect("emailless accounts must not collide");
        }
    }

    /// A DID already hosted here is its own case: the handle and the email
    /// may both be free, and telling the caller to pick another handle would
    /// point them at the wrong remedy.
    #[tokio::test(flavor = "multi_thread")]
    async fn create_account_duplicate_did_rejected() {
        let (manager, _dir, _tmp) = fresh_manager().await;
        manager
            .create_account(CreateAccountParams {
                did: "did:plc:alice",
                handle: "alice.example",
                email: Some("alice@example.com"),
                password: "pw",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let result = manager
            .create_account(CreateAccountParams {
                did: "did:plc:alice",
                handle: "alice-again.example",
                email: Some("alice-again@example.com"),
                password: "pw",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await;
        assert!(
            matches!(result, Err(PdsError::AccountAlreadyExists { ref did }) if did == "did:plc:alice"),
            "got {result:?}"
        );
    }

    /// The pre-flight check is a read followed by a write, so a concurrent
    /// signup can still reach the INSERT. Drive the table directly to produce
    /// the constraint violation that race produces and assert it is
    /// classified rather than reported as a backend fault.
    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn insert_unique_violations_are_classified_by_column() {
        let (manager, _dir, _tmp) = fresh_manager().await;
        manager
            .create_account(CreateAccountParams {
                did: "did:plc:alice",
                handle: "alice.example",
                email: Some("alice@example.com"),
                password: "pw",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let pool = manager.accounts_pool.as_sqlite();

        for (did, handle, email) in [
            ("did:plc:bob", "bob.example", "alice@example.com"),
            ("did:plc:bob", "alice.example", "bob@example.com"),
            ("did:plc:alice", "bob.example", "bob@example.com"),
        ] {
            let err = sqlx::query(
                "INSERT INTO account (did, handle, email, password_hash, created_at, state, signing_key_ref, pds_managed_rotation)
                 VALUES (?, ?, ?, 'x', 'x', 'active', 'x', 1)",
            )
            .bind(did)
            .bind(handle)
            .bind(email)
            .execute(pool)
            .await
            .expect_err("the UNIQUE constraint must reject this row");

            let params = CreateAccountParams::new(did, handle, "pw").with_email(Some(email));
            let classified = account_insert_conflict(&err, &params);
            match (did, handle) {
                ("did:plc:bob", "bob.example") => assert!(
                    matches!(classified, Some(PdsError::EmailNotAvailable { .. })),
                    "got {classified:?}"
                ),
                ("did:plc:bob", _) => assert!(
                    matches!(classified, Some(PdsError::HandleNotAvailable { .. })),
                    "got {classified:?}"
                ),
                _ => assert!(
                    matches!(classified, Some(PdsError::AccountAlreadyExists { .. })),
                    "got {classified:?}"
                ),
            }
        }
    }

    /// A failure that is not a uniqueness violation must keep reporting as
    /// one: silently reclassifying every insert error would hide real backend
    /// faults behind a 400.
    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn non_unique_insert_failures_are_not_reclassified() {
        let (manager, _dir, _tmp) = fresh_manager().await;
        let err = sqlx::query("INSERT INTO account (did) VALUES (?)")
            .bind("did:plc:alice")
            .execute(manager.accounts_pool.as_sqlite())
            .await
            .expect_err("NOT NULL columns have no defaults");
        let params = CreateAccountParams::new("did:plc:alice", "alice.example", "pw");
        assert!(account_insert_conflict(&err, &params).is_none());
    }

    /// A violation naming the email column cannot arise from a request that
    /// carried no email — `NULL` violates a UNIQUE index on neither engine —
    /// so pairing the two is the only way to reach that arm. It must decline
    /// rather than render *"the email address  is already registered"* with the
    /// address missing and a double space where it should have been.
    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn email_conflict_without_an_email_in_the_request_is_declined() {
        let (manager, _dir, _tmp) = fresh_manager().await;
        manager
            .create_account(CreateAccountParams {
                did: "did:plc:alice",
                handle: "alice.example",
                email: Some("alice@example.com"),
                password: "pw",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let err = sqlx::query(
            "INSERT INTO account (did, handle, email, password_hash, created_at, state, signing_key_ref, pds_managed_rotation)
             VALUES (?, ?, ?, 'x', 'x', 'active', 'x', 1)",
        )
        .bind("did:plc:bob")
        .bind("bob.example")
        .bind("alice@example.com")
        .execute(manager.accounts_pool.as_sqlite())
        .await
        .expect_err("the UNIQUE constraint on account.email must reject this row");

        // The same error, attributed to a request that carried no email.
        let params = CreateAccountParams::new("did:plc:bob", "bob.example", "pw");
        let classified = account_insert_conflict(&err, &params);
        assert!(
            classified.is_none(),
            "an email conflict with no email to name must stay a backend fault: {classified:?}"
        );
    }

    /// `createAccount` runs the check before PLC genesis, when no DID exists
    /// yet. A `None` DID must match no row — not even the one whose handle and
    /// email are being tested against — while the other two columns are still
    /// enforced.
    #[tokio::test(flavor = "multi_thread")]
    async fn ensure_available_without_a_did_checks_handle_and_email() {
        let (manager, _dir, _tmp) = fresh_manager().await;
        manager
            .create_account(CreateAccountParams {
                did: "did:plc:alice",
                handle: "alice.example",
                email: Some("alice@example.com"),
                password: "pw",
                pds_managed_rotation: true,
                ..Default::default()
            })
            .await
            .unwrap();

        let taken_handle = manager
            .ensure_available(None, "alice.example", Some("bob@example.com"))
            .await;
        assert!(
            matches!(taken_handle, Err(PdsError::HandleNotAvailable { ref handle }) if handle == "alice.example"),
            "got {taken_handle:?}"
        );
        let taken_email = manager
            .ensure_available(None, "bob.example", Some("alice@example.com"))
            .await;
        assert!(
            matches!(taken_email, Err(PdsError::EmailNotAvailable { ref email }) if email == "alice@example.com"),
            "got {taken_email:?}"
        );
        manager
            .ensure_available(None, "bob.example", Some("bob@example.com"))
            .await
            .expect("a free handle and a free email are available");
        manager
            .ensure_available(None, "bob.example", None)
            .await
            .expect("a signup with no email collides on nothing");
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

    /// Changing the password has to retire the old one.
    ///
    /// It did not. `set_primary_password` inserted a `__primary__` row instead
    /// of replacing one, and `verify` returns the first row whose hash matches,
    /// so the superseded hash kept opening the account. The portal reported
    /// success and revoked every session, which is the part that made this hard
    /// to notice: the holder is shown a change that worked.
    ///
    /// Both readers are asserted because the secret is stored twice.
    /// `verify_password` reads `account.password_hash`, which the OAuth consent
    /// form falls back to; `app_password::verify` reads the row, which
    /// `createSession` and the portal use. Only the second was ever written.
    #[tokio::test(flavor = "multi_thread")]
    async fn changing_the_password_retires_the_old_one() {
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
        manager
            .set_primary_password("did:plc:alice", "correct horse")
            .await
            .unwrap();

        manager
            .set_primary_password("did:plc:alice", "battery staple")
            .await
            .unwrap();

        let pool = manager.account_pool();
        assert!(
            crate::account::app_password::verify(&pool, "did:plc:alice", "correct horse")
                .await
                .unwrap()
                .is_none(),
            "the old password still opens the account"
        );
        assert!(
            !manager
                .verify_password("did:plc:alice", "correct horse")
                .await
                .unwrap(),
            "the old password still verifies against account.password_hash"
        );

        // And the new one works through both readers.
        let matched =
            crate::account::app_password::verify(&pool, "did:plc:alice", "battery staple")
                .await
                .unwrap()
                .expect("the new password must open the account");
        assert_eq!(matched.name, "__primary__");
        assert!(
            manager
                .verify_password("did:plc:alice", "battery staple")
                .await
                .unwrap()
        );

        // Replaced, not appended.
        let primaries = crate::account::app_password::list(&pool, "did:plc:alice")
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.name == "__primary__")
            .count();
        assert_eq!(primaries, 1, "a password change added a second primary row");
    }

    /// The row id is what a session is minted against, so replacing the
    /// password in place keeps it answerable. Revoking the sessions is the
    /// password change's own job -- it bumps the epoch -- and not something to
    /// get as a side effect of orphaning a row.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_primary_row_id_survives_a_password_change() {
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

        let first = manager
            .set_primary_password("did:plc:alice", "correct horse")
            .await
            .unwrap();
        let second = manager
            .set_primary_password("did:plc:alice", "battery staple")
            .await
            .unwrap();

        assert_eq!(
            first, second,
            "the primary row was replaced rather than updated"
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
