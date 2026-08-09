//! Access tokens revoked before they expire.
//!
//! `/oauth/revoke` answered 200 and did nothing to an access token. It put the
//! token's `jti` into the JTI replay guard, and nothing reads that value: the
//! guard is consulted for the *DPoP proof's* jti -- a different claim, from a
//! different JWT, with a different lifetime -- and a token presented as
//! `Bearer` never reaches the guard at all. Revoking a lost device's token
//! returned success while the token kept authenticating every call until it
//! expired on its own.
//!
//! The replay guard was also the wrong home. It is memory-backed by default
//! and evicts by insertion order once over cap, and it fails open when storage
//! errors. Both are defensible for replay detection, where a miss costs one
//! duplicated request. Neither is acceptable for revocation, where forgetting
//! an entry silently restores a credential the user asked to destroy.
//!
//! So revocation is durable and checked on every OAuth authentication.
//! [`is_revoked`] fails *closed*: a storage error refuses the request rather
//! than admitting it. That costs no availability that was not already spent --
//! `require_current_epoch` queries the same database on the same path and
//! propagates its errors too, so a database this server cannot reach is
//! already a database that cannot authenticate anyone.
//!
//! Rows live only until the token would be refused for age anyway, so
//! `expires_at` is the token's own `exp` and the GC sweep drops what is past
//! it.

use crate::account::{AccountPool, AccountPoolKind};
use crate::errors::{PdsError, PdsResult};

/// Add a JTI to the blacklist with an expiration time. Idempotent.
pub async fn revoke(pool: &AccountPool, jti: &str, expires_at: &str) -> PdsResult<()> {
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query(
                "INSERT OR REPLACE INTO oauth_revoked_token (jti, expires_at)
                 VALUES (?, ?)",
            )
            .bind(jti)
            .bind(expires_at)
            .execute(pool.as_sqlite())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("oauth_revoked_token add: {e}"),
            })?;
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query(
                "INSERT INTO oauth_revoked_token (jti, expires_at)
                 VALUES ($1, $2)
                 ON CONFLICT (jti) DO UPDATE SET expires_at = excluded.expires_at",
            )
            .bind(jti)
            .bind(expires_at)
            .execute(pool.as_postgres())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("oauth_revoked_token add: {e}"),
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

/// `true` when the JTI is on the blacklist (not yet expired). Receiving
/// services should call this on each presentation of a service-auth
/// token.
pub async fn is_revoked(pool: &AccountPool, jti: &str) -> PdsResult<bool> {
    let now = chrono::Utc::now().to_rfc3339();
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            let row: Option<(i64,)> = sqlx::query_as(
                "SELECT 1 FROM oauth_revoked_token WHERE jti = ? AND expires_at > ? LIMIT 1",
            )
            .bind(jti)
            .bind(&now)
            .fetch_optional(pool.as_sqlite())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("oauth_revoked_token contains: {e}"),
            })?;
            Ok(row.is_some())
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            let row: Option<(i32,)> = sqlx::query_as(
                "SELECT 1 FROM oauth_revoked_token WHERE jti = $1 AND expires_at > $2 LIMIT 1",
            )
            .bind(jti)
            .bind(&now)
            .fetch_optional(pool.as_postgres())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("oauth_revoked_token contains: {e}"),
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

/// Drop expired rows. Best-effort GC — call periodically or
/// opportunistically on each `add`.
pub async fn gc(pool: &AccountPool) -> PdsResult<u64> {
    let now = chrono::Utc::now().to_rfc3339();
    let rows_affected = match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query("DELETE FROM oauth_revoked_token WHERE expires_at <= ?")
                .bind(&now)
                .execute(pool.as_sqlite())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("oauth_revoked_token gc: {e}"),
                })?
                .rows_affected()
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query("DELETE FROM oauth_revoked_token WHERE expires_at <= $1")
                .bind(&now)
                .execute(pool.as_postgres())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("oauth_revoked_token gc: {e}"),
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
    Ok(rows_affected)
}
