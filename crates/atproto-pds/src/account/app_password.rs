//! App-password lifecycle.
//!
//! App passwords mint long-lived JWT sessions with restricted scope (`privileged: false`
//! excludes chat etc.). They are deprecated for new clients; OAuth is the
//! future. We still ship them so existing AT Protocol clients keep working.
//!
//! Flow:
//! 1. Authenticated user calls `createAppPassword {name, privileged?}`.
//! 2. Server generates a fresh password (high-entropy, base32), hashes via
//!    Argon2id, stores in `app_password` table, returns the plaintext to the
//!    user **once** (it is never retrievable again).
//! 3. Client uses the returned password as the `password` argument to
//!    `createSession`, getting back a JWT session token.
//!
//! All functions accept `&AccountPool` and dispatch to the correct
//! backend at runtime.

use crate::account::manager::{hash_password, verify_password};
use crate::account::{AccountPool, AccountPoolKind};
use crate::errors::{PdsError, PdsResult};
use chrono::Utc;
use rand::RngExt;
use serde::{Deserialize, Serialize};

/// One row from the `app_password` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppPasswordRow {
    /// Opaque app-password identifier.
    pub id: String,
    /// Owning DID.
    pub did: String,
    /// User-facing name (e.g., "Phone client").
    pub name: String,
    /// Whether this password has access to privileged endpoints (chat etc.).
    pub privileged: bool,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// When a session was last minted from this password, if ever.
    ///
    /// Stamped at sign-in rather than on every authenticated request: the
    /// question the portal answers is "is this credential still in use, and
    /// do I recognise it", which a per-session granularity answers without
    /// putting a write in front of every read.
    pub last_used_at: Option<String>,
}

/// Result of `create` — the plaintext password is included exactly once.
#[derive(Debug, Clone)]
pub struct CreatedAppPassword {
    /// The persisted row.
    pub row: AppPasswordRow,
    /// Plaintext password — **shown to the user once**, never retrievable.
    pub plaintext: String,
}

/// Record that a session was just minted from this app password.
///
/// Best-effort by design: the sign-in has already succeeded by the time this
/// runs, and failing to write a display timestamp is not a reason to refuse
/// the session. Errors are logged and swallowed.
pub async fn touch_last_used(pool: &AccountPool, id: &str) {
    let now = Utc::now().to_rfc3339();
    let result = match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query("UPDATE app_password SET last_used_at = ? WHERE id = ?")
                .bind(&now)
                .bind(id)
                .execute(pool.as_sqlite())
                .await
                .map(|_| ())
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query("UPDATE app_password SET last_used_at = $1 WHERE id = $2")
                .bind(&now)
                .bind(id)
                .execute(pool.as_postgres())
                .await
                .map(|_| ())
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature")
        }
    };
    if let Err(e) = result {
        tracing::warn!(error = ?e, app_password_id = id, "could not record app-password use");
    }
}

/// Mint a new app password for `did`.
///
/// The plaintext is a 24-character base32-lower string (entropy ~120 bits),
/// returned exactly once. Storage holds only the Argon2id hash.
///
/// # Errors
///
/// Forwards SQL errors as [`PdsError::Storage`].
pub async fn create(
    pool: &AccountPool,
    did: &str,
    name: &str,
    privileged: bool,
) -> PdsResult<CreatedAppPassword> {
    let id = format!("ap-{}", new_id());
    let plaintext = new_plaintext();
    let hash = hash_password(&plaintext)?;
    let now = Utc::now().to_rfc3339();

    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query(
                "INSERT INTO app_password (id, did, name, password_hash, privileged, created_at)
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(&id)
            .bind(did)
            .bind(name)
            .bind(&hash)
            .bind(if privileged { 1i64 } else { 0i64 })
            .bind(&now)
            .execute(pool.as_sqlite())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("create app_password: {e}"),
            })?;
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query(
                "INSERT INTO app_password (id, did, name, password_hash, privileged, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(&id)
            .bind(did)
            .bind(name)
            .bind(&hash)
            .bind(privileged)
            .bind(&now)
            .execute(pool.as_postgres())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("create app_password: {e}"),
            })?;
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature")
        }
    }

    Ok(CreatedAppPassword {
        row: AppPasswordRow {
            id,
            did: did.to_string(),
            name: name.to_string(),
            privileged,
            created_at: now,
            last_used_at: None,
        },
        plaintext,
    })
}

/// List app passwords for a DID (does not include hashes).
pub async fn list(pool: &AccountPool, did: &str) -> PdsResult<Vec<AppPasswordRow>> {
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            let rows: Vec<(String, String, String, i64, String, Option<String>)> = sqlx::query_as(
                "SELECT id, did, name, privileged, created_at, last_used_at
                 FROM app_password WHERE did = ? ORDER BY created_at DESC",
            )
            .bind(did)
            .fetch_all(pool.as_sqlite())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("list app_password: {e}"),
            })?;
            Ok(rows
                .into_iter()
                .map(
                    |(id, did, name, privileged, created_at, last_used_at)| AppPasswordRow {
                        id,
                        did,
                        name,
                        privileged: privileged != 0,
                        created_at,
                        last_used_at,
                    },
                )
                .collect())
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            let rows: Vec<(String, String, String, bool, String, Option<String>)> = sqlx::query_as(
                "SELECT id, did, name, privileged, created_at, last_used_at
                 FROM app_password WHERE did = $1 ORDER BY created_at DESC",
            )
            .bind(did)
            .fetch_all(pool.as_postgres())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("list app_password: {e}"),
            })?;
            Ok(rows
                .into_iter()
                .map(
                    |(id, did, name, privileged, created_at, last_used_at)| AppPasswordRow {
                        id,
                        did,
                        name,
                        privileged,
                        created_at,
                        last_used_at,
                    },
                )
                .collect())
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature")
        }
    }
}

/// Count the app passwords belonging to `did`. Used by
/// `checkAccountStatus` for the `privateStateValues` reporting field.
pub async fn count_for_did(pool: &AccountPool, did: &str) -> PdsResult<i64> {
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM app_password WHERE did = ?")
                .bind(did)
                .fetch_one(pool.as_sqlite())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("count_for_did app_password: {e}"),
                })?;
            Ok(row.0)
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM app_password WHERE did = $1")
                .bind(did)
                .fetch_one(pool.as_postgres())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("count_for_did app_password: {e}"),
                })?;
            Ok(row.0)
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature")
        }
    }
}

/// Update the `password_hash` on a specific `app_password` row by id.
/// Used by `createAccount` so the implicit `__primary__` row's hash
/// matches the password the user supplied (lets `createSession`
/// authenticate against either the row's hash or the account-row hash).
pub async fn update_hash_by_id(pool: &AccountPool, id: &str, hash: &str) -> PdsResult<()> {
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query("UPDATE app_password SET password_hash = ? WHERE id = ?")
                .bind(hash)
                .bind(id)
                .execute(pool.as_sqlite())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("update_hash_by_id app_password: {e}"),
                })?;
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query("UPDATE app_password SET password_hash = $1 WHERE id = $2")
                .bind(hash)
                .bind(id)
                .execute(pool.as_postgres())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("update_hash_by_id app_password: {e}"),
                })?;
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature")
        }
    }
    Ok(())
}

/// Revoke an app password by name. Returns `true` if a row was deleted.
pub async fn revoke(pool: &AccountPool, did: &str, name: &str) -> PdsResult<bool> {
    let rows_affected = match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query("DELETE FROM app_password WHERE did = ? AND name = ?")
                .bind(did)
                .bind(name)
                .execute(pool.as_sqlite())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("revoke app_password: {e}"),
                })?
                .rows_affected()
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query("DELETE FROM app_password WHERE did = $1 AND name = $2")
                .bind(did)
                .bind(name)
                .execute(pool.as_postgres())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("revoke app_password: {e}"),
                })?
                .rows_affected()
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature")
        }
    };
    Ok(rows_affected > 0)
}

/// Update the password hash on the account's `__primary__` app
/// password row. Used by `resetPassword` (§9.2) so the user can log
/// in via either the OAuth `password` form or the legacy
/// `createSession` form after a reset. Ignores the result count —
/// idempotent on accounts without a `__primary__` row.
pub async fn update_primary_hash(pool: &AccountPool, did: &str, hash: &str) -> PdsResult<()> {
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query(
                "UPDATE app_password SET password_hash = ?
                 WHERE did = ? AND name = '__primary__'",
            )
            .bind(hash)
            .bind(did)
            .execute(pool.as_sqlite())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("update __primary__ app_password: {e}"),
            })?;
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query(
                "UPDATE app_password SET password_hash = $1
                 WHERE did = $2 AND name = '__primary__'",
            )
            .bind(hash)
            .bind(did)
            .execute(pool.as_postgres())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("update __primary__ app_password: {e}"),
            })?;
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature")
        }
    }
    Ok(())
}

/// Point the account's `__primary__` row at `hash`, creating it if absent.
///
/// Returns the row id, which is what a session is minted against.
///
/// This replaces the account password rather than adding one. The distinction
/// is the whole point: `verify` accepts the first row whose hash matches, so a
/// second `__primary__` row holding a superseded hash is a credential that
/// still opens the account, and the holder who just changed their password has
/// been told the old one no longer works.
///
/// The `UPDATE` deliberately matches every `__primary__` row for the account
/// rather than one. A database written before the unique index landed may
/// carry duplicates, and rewriting all of them is what stops one of those
/// keeping a superseded hash alive.
///
/// # Errors
///
/// Forwards SQL errors as [`PdsError::Storage`].
pub async fn upsert_primary(pool: &AccountPool, did: &str, hash: &str) -> PdsResult<String> {
    let updated = match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => sqlx::query(
            "UPDATE app_password SET password_hash = ?
             WHERE did = ? AND name = '__primary__'",
        )
        .bind(hash)
        .bind(did)
        .execute(pool.as_sqlite())
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("upsert __primary__ app_password: {e}"),
        })?
        .rows_affected(),
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => sqlx::query(
            "UPDATE app_password SET password_hash = $1
             WHERE did = $2 AND name = '__primary__'",
        )
        .bind(hash)
        .bind(did)
        .execute(pool.as_postgres())
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("upsert __primary__ app_password: {e}"),
        })?
        .rows_affected(),
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature")
        }
    };

    if updated > 0 {
        // The oldest row is the one live sessions were minted against, so it is
        // the id to keep answering with.
        let row: Option<(String,)> = match pool.kind() {
            #[cfg(feature = "sqlite")]
            AccountPoolKind::Sqlite => sqlx::query_as(
                "SELECT id FROM app_password WHERE did = ? AND name = '__primary__'
                 ORDER BY created_at ASC, id ASC LIMIT 1",
            )
            .bind(did)
            .fetch_optional(pool.as_sqlite())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("read __primary__ app_password: {e}"),
            })?,
            #[cfg(feature = "postgres")]
            AccountPoolKind::Postgres => sqlx::query_as(
                "SELECT id FROM app_password WHERE did = $1 AND name = '__primary__'
                 ORDER BY created_at ASC, id ASC LIMIT 1",
            )
            .bind(did)
            .fetch_optional(pool.as_postgres())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("read __primary__ app_password: {e}"),
            })?,
            #[cfg(not(feature = "sqlite"))]
            AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
            #[cfg(not(feature = "postgres"))]
            AccountPoolKind::Postgres => {
                unreachable!("AccountPool::Postgres without `postgres` feature")
            }
        };
        if let Some((id,)) = row {
            return Ok(id);
        }
    }

    // No primary row yet: this is account creation. Insert with the real hash
    // rather than going through `create`, which would mint and hash a random
    // plaintext nobody will ever present just to overwrite it a moment later.
    let id = format!("ap-{}", new_id());
    let now = Utc::now().to_rfc3339();
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query(
                "INSERT INTO app_password (id, did, name, password_hash, privileged, created_at)
                 VALUES (?, ?, '__primary__', ?, 1, ?)",
            )
            .bind(&id)
            .bind(did)
            .bind(hash)
            .bind(&now)
            .execute(pool.as_sqlite())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("create __primary__ app_password: {e}"),
            })?;
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query(
                "INSERT INTO app_password (id, did, name, password_hash, privileged, created_at)
                 VALUES ($1, $2, '__primary__', $3, true, $4)",
            )
            .bind(&id)
            .bind(did)
            .bind(hash)
            .bind(&now)
            .execute(pool.as_postgres())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("create __primary__ app_password: {e}"),
            })?;
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature")
        }
    }
    Ok(id)
}

/// Verify a presented plaintext password against an account's stored app
/// passwords. Returns `Some(row)` if any matches, `None` otherwise.
///
/// Note: this iterates and Argon2-verifies against every row — fine for the
/// expected ≤10 app passwords per account, but document the bound.
pub async fn verify(
    pool: &AccountPool,
    did: &str,
    presented: &str,
) -> PdsResult<Option<AppPasswordRow>> {
    let rows: Vec<(String, String, String, String, bool, String)> = match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            let raw: Vec<(String, String, String, String, i64, String)> = sqlx::query_as(
                "SELECT id, did, name, password_hash, privileged, created_at
                 FROM app_password WHERE did = ?",
            )
            .bind(did)
            .fetch_all(pool.as_sqlite())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("verify app_password: {e}"),
            })?;
            raw.into_iter()
                .map(|(id, d, n, h, p, c)| (id, d, n, h, p != 0, c))
                .collect()
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => sqlx::query_as(
            "SELECT id, did, name, password_hash, privileged, created_at
             FROM app_password WHERE did = $1",
        )
        .bind(did)
        .fetch_all(pool.as_postgres())
        .await
        .map_err(|e| PdsError::Storage {
            reason: format!("verify app_password: {e}"),
        })?,
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature")
        }
    };
    for (id, row_did, name, hash, privileged, created_at) in rows {
        if verify_password(presented, &hash) {
            return Ok(Some(AppPasswordRow {
                id,
                did: row_did,
                name,
                privileged,
                created_at,
                // `verify` is on the sign-in path and reads only what it
                // needs to check the secret; the portal's list is where this
                // is actually shown.
                last_used_at: None,
            }));
        }
    }
    Ok(None)
}

fn new_id() -> String {
    let mut bytes = [0u8; 8];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

fn new_plaintext() -> String {
    // 24 chars base32-lower (5 bits each → 120 bits entropy).
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bytes = [0u8; 24];
    rand::rng().fill(&mut bytes);
    bytes
        .iter()
        .map(|b| ALPHABET[(*b as usize) & 0x1f] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountDirectory;

    async fn fresh_pool_with_account(did: &str) -> AccountPool {
        let dir = AccountDirectory::open_memory().await.unwrap();
        // Insert a stub account so FK is satisfied.
        sqlx::query(
            "INSERT INTO account (did, handle, password_hash, created_at, state, signing_key_ref, pds_managed_rotation)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(did)
        .bind(format!("{}.example", did.replace([':'], "_")))
        .bind("$argon2id$x")
        .bind(Utc::now().to_rfc3339())
        .bind("active")
        .bind("file:stub")
        .bind(1i64)
        .execute(dir.pool())
        .await
        .unwrap();
        dir.account_pool()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn create_and_verify_round_trip() {
        let pool = fresh_pool_with_account("did:plc:alice").await;
        let created = create(&pool, "did:plc:alice", "phone", false)
            .await
            .unwrap();
        assert!(!created.plaintext.is_empty());
        let found = verify(&pool, "did:plc:alice", &created.plaintext)
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "phone");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wrong_password_returns_none() {
        let pool = fresh_pool_with_account("did:plc:alice").await;
        let _ = create(&pool, "did:plc:alice", "phone", false)
            .await
            .unwrap();
        let found = verify(&pool, "did:plc:alice", "obviously-wrong")
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn list_returns_minted_passwords() {
        let pool = fresh_pool_with_account("did:plc:alice").await;
        create(&pool, "did:plc:alice", "phone", false)
            .await
            .unwrap();
        create(&pool, "did:plc:alice", "laptop", true)
            .await
            .unwrap();
        let rows = list(&pool, "did:plc:alice").await.unwrap();
        assert_eq!(rows.len(), 2);
        // Hashes must NOT be exposed in the listing rows.
        // (AppPasswordRow has no password_hash field, so this is structural.)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn revoke_by_name_removes_one() {
        let pool = fresh_pool_with_account("did:plc:alice").await;
        let created = create(&pool, "did:plc:alice", "phone", false)
            .await
            .unwrap();
        let removed = revoke(&pool, "did:plc:alice", "phone").await.unwrap();
        assert!(removed);
        let found = verify(&pool, "did:plc:alice", &created.plaintext)
            .await
            .unwrap();
        assert!(found.is_none());
        // Idempotent re-revoke returns false.
        let removed_again = revoke(&pool, "did:plc:alice", "phone").await.unwrap();
        assert!(!removed_again);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn each_plaintext_unique() {
        let pool = fresh_pool_with_account("did:plc:alice").await;
        let a = create(&pool, "did:plc:alice", "p1", false).await.unwrap();
        let b = create(&pool, "did:plc:alice", "p2", false).await.unwrap();
        assert_ne!(a.plaintext, b.plaintext);
        assert_ne!(a.row.id, b.row.id);
    }
}
