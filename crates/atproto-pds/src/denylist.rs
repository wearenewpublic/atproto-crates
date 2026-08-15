//! Privacy-preserving denylist for handles + email addresses.
//!
//! the denylist stores only an
//! 8-byte hash of each blocked identifier. Operators can ban a handle or
//! email without leaving the plaintext value in the SQLite file. The hash
//! is one-way: no enumeration of the denylist by an attacker who steals
//! the DB.
//!
//! The hash is a **keyed** HMAC-SHA256 truncated to 8 bytes, under a
//! process-wide pepper derived from the server secret ([`set_pepper`], called at
//! boot). Keying is what actually delivers the "no enumeration on DB theft"
//! property the module promises: handles and email addresses are low-entropy,
//! so an *unkeyed* hash is confirmable by dictionary attack on a stolen table.
//! Without the pepper an attacker cannot compute a row's value to compare
//! against. When no pepper is configured (tests, or a library embedding that
//! skips `set_pepper`) the hash falls back to unkeyed SHA-256. Both forms are
//! 64-bit; consumers who pull blocked ids from another deployment must re-hash
//! with the local key.
//!
//! All functions accept `&AccountPool` and dispatch to the correct
//! backend at runtime.

use crate::account::{AccountPool, AccountPoolKind};
use crate::errors::{PdsError, PdsResult};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Process-wide pepper keying the denylist hash. Set once at boot from the
/// server secret; absent in a process that never configured one.
static DENYLIST_PEPPER: OnceLock<Vec<u8>> = OnceLock::new();

/// Configure the process-wide denylist pepper from the server secret.
///
/// Derives a domain-separated key so the same secret used elsewhere (JWT
/// signing) cannot be cross-correlated with denylist rows, and stores it once —
/// the first call wins, later calls are ignored. Call at boot, before serving.
///
/// Changing the pepper, or upgrading a deployment whose rows were stored
/// unkeyed, changes every stored value: existing denylist entries no longer
/// match and must be re-added. This is unavoidable — only the hashes were
/// stored, so old rows cannot be re-keyed.
pub fn set_pepper(server_secret: &[u8]) {
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(server_secret).expect("HMAC accepts a key of any length");
    mac.update(b"atproto-pds:denylist-pepper:v1");
    let pepper = mac.finalize().into_bytes().to_vec();
    let _ = DENYLIST_PEPPER.set(pepper);
}

/// Identifier kind (`"handle"` or `"email"`). Stored alongside the hash so
/// we can scope a query to the right namespace without expanding the index.
pub const KIND_HANDLE: &str = "handle";

/// Identifier kind for email addresses.
pub const KIND_EMAIL: &str = "email";

/// Hash an identifier to its 8-byte denylist signature.
///
/// Keyed HMAC-SHA256 under the process pepper, truncated to the first 8 bytes.
/// The key is what makes a stolen table unenumerable: without it a dictionary
/// pass over candidate handles/emails cannot confirm a row. Falls back to plain
/// SHA-256 when no pepper is configured (see the module docs).
#[must_use]
pub fn hash_identifier(value: &str) -> [u8; 8] {
    let normalized = value.trim().to_ascii_lowercase();
    let digest = match DENYLIST_PEPPER.get() {
        Some(pepper) => {
            let mut mac =
                <Hmac<Sha256>>::new_from_slice(pepper).expect("HMAC accepts a key of any length");
            mac.update(normalized.as_bytes());
            mac.finalize().into_bytes()
        }
        None => Sha256::digest(normalized.as_bytes()),
    };
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// `true` when the supplied identifier is on the denylist.
pub async fn contains(pool: &AccountPool, kind: &str, identifier: &str) -> PdsResult<bool> {
    let hash = hash_identifier(identifier);
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            let row: Option<(i64,)> = sqlx::query_as(
                "SELECT 1 FROM denylist WHERE hash_metro64 = ? AND kind = ? LIMIT 1",
            )
            .bind(hash.as_slice())
            .bind(kind)
            .fetch_optional(pool.as_sqlite())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("denylist contains: {e}"),
            })?;
            Ok(row.is_some())
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            let row: Option<(i32,)> = sqlx::query_as(
                "SELECT 1 FROM denylist WHERE hash_metro64 = $1 AND kind = $2 LIMIT 1",
            )
            .bind(hash.as_slice())
            .bind(kind)
            .fetch_optional(pool.as_postgres())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("denylist contains: {e}"),
            })?;
            Ok(row.is_some())
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature")
        }
    }
}

/// Add an identifier to the denylist. Idempotent on `(hash, kind)`.
pub async fn add(
    pool: &AccountPool,
    kind: &str,
    identifier: &str,
    note: Option<&str>,
) -> PdsResult<()> {
    let hash = hash_identifier(identifier);
    let now = chrono::Utc::now().to_rfc3339();
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query(
                "INSERT OR IGNORE INTO denylist (hash_metro64, kind, created_at, note)
                 VALUES (?, ?, ?, ?)",
            )
            .bind(hash.as_slice())
            .bind(kind)
            .bind(&now)
            .bind(note)
            .execute(pool.as_sqlite())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("denylist add: {e}"),
            })?;
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query(
                "INSERT INTO denylist (hash_metro64, kind, created_at, note)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (hash_metro64) DO NOTHING",
            )
            .bind(hash.as_slice())
            .bind(kind)
            .bind(&now)
            .bind(note)
            .execute(pool.as_postgres())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("denylist add: {e}"),
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

/// Remove an identifier from the denylist. Idempotent — returns `Ok(())`
/// even when nothing was removed.
pub async fn remove(pool: &AccountPool, kind: &str, identifier: &str) -> PdsResult<()> {
    let hash = hash_identifier(identifier);
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query("DELETE FROM denylist WHERE hash_metro64 = ? AND kind = ?")
                .bind(hash.as_slice())
                .bind(kind)
                .execute(pool.as_sqlite())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("denylist remove: {e}"),
                })?;
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query("DELETE FROM denylist WHERE hash_metro64 = $1 AND kind = $2")
                .bind(hash.as_slice())
                .bind(kind)
                .execute(pool.as_postgres())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("denylist remove: {e}"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountDirectory;

    async fn fresh_pool() -> AccountPool {
        AccountDirectory::open_memory()
            .await
            .unwrap()
            .account_pool()
    }

    #[test]
    fn hash_is_case_insensitive_and_trimmed() {
        let a = hash_identifier("Alice@example.com");
        let b = hash_identifier("  alice@example.com  ");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_distinct_for_different_inputs() {
        assert_ne!(hash_identifier("alice"), hash_identifier("bob"));
    }

    #[tokio::test]
    async fn add_then_contains() {
        let pool = fresh_pool().await;
        assert!(!contains(&pool, KIND_HANDLE, "alice.example").await.unwrap());
        add(&pool, KIND_HANDLE, "alice.example", Some("test"))
            .await
            .unwrap();
        assert!(contains(&pool, KIND_HANDLE, "alice.example").await.unwrap());
        // Different kind — independent namespace.
        assert!(!contains(&pool, KIND_EMAIL, "alice.example").await.unwrap());
    }

    #[tokio::test]
    async fn add_is_idempotent() {
        let pool = fresh_pool().await;
        add(&pool, KIND_HANDLE, "alice.example", None)
            .await
            .unwrap();
        add(&pool, KIND_HANDLE, "alice.example", None)
            .await
            .unwrap();
        assert!(contains(&pool, KIND_HANDLE, "alice.example").await.unwrap());
    }

    #[tokio::test]
    async fn remove_clears_entry() {
        let pool = fresh_pool().await;
        add(&pool, KIND_HANDLE, "alice.example", None)
            .await
            .unwrap();
        remove(&pool, KIND_HANDLE, "alice.example").await.unwrap();
        assert!(!contains(&pool, KIND_HANDLE, "alice.example").await.unwrap());
    }
}
