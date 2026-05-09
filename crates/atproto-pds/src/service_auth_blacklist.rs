//! Admin-revoked service-auth JTIs.
//!
//! the PDS hands out short-lived
//! service-auth JWTs (`com.atproto.server.getServiceAuth`). Operators can
//! revoke a specific `jti` ahead of its natural expiry by writing it to
//! this table; receiving services that consult the table reject any
//! presentation of the matching jti.
//!
//! The table is GC'd by row expiration: once `expires_at` is in the past
//! the entry is no longer needed (the underlying JWT is also expired).
//!
//! All functions accept `&AccountPool` and dispatch to the correct
//! backend at runtime.

use crate::account::{AccountPool, AccountPoolKind};
use crate::errors::{PdsError, PdsResult};

/// Add a JTI to the blacklist with an expiration time. Idempotent.
pub async fn add(pool: &AccountPool, jti: &str, expires_at: &str) -> PdsResult<()> {
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query(
                "INSERT OR REPLACE INTO service_auth_blacklist (jti, expires_at)
                 VALUES (?, ?)",
            )
            .bind(jti)
            .bind(expires_at)
            .execute(pool.as_sqlite())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("service_auth_blacklist add: {e}"),
            })?;
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query(
                "INSERT INTO service_auth_blacklist (jti, expires_at)
                 VALUES ($1, $2)
                 ON CONFLICT (jti) DO UPDATE SET expires_at = excluded.expires_at",
            )
            .bind(jti)
            .bind(expires_at)
            .execute(pool.as_postgres())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("service_auth_blacklist add: {e}"),
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
pub async fn contains(pool: &AccountPool, jti: &str) -> PdsResult<bool> {
    let now = chrono::Utc::now().to_rfc3339();
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            let row: Option<(i64,)> = sqlx::query_as(
                "SELECT 1 FROM service_auth_blacklist WHERE jti = ? AND expires_at > ? LIMIT 1",
            )
            .bind(jti)
            .bind(&now)
            .fetch_optional(pool.as_sqlite())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("service_auth_blacklist contains: {e}"),
            })?;
            Ok(row.is_some())
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            let row: Option<(i32,)> = sqlx::query_as(
                "SELECT 1 FROM service_auth_blacklist WHERE jti = $1 AND expires_at > $2 LIMIT 1",
            )
            .bind(jti)
            .bind(&now)
            .fetch_optional(pool.as_postgres())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("service_auth_blacklist contains: {e}"),
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
            sqlx::query("DELETE FROM service_auth_blacklist WHERE expires_at <= ?")
                .bind(&now)
                .execute(pool.as_sqlite())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("service_auth_blacklist gc: {e}"),
                })?
                .rows_affected()
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query("DELETE FROM service_auth_blacklist WHERE expires_at <= $1")
                .bind(&now)
                .execute(pool.as_postgres())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("service_auth_blacklist gc: {e}"),
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

    fn future(secs: i64) -> String {
        (chrono::Utc::now() + chrono::Duration::seconds(secs)).to_rfc3339()
    }

    #[tokio::test]
    async fn add_then_contains() {
        let pool = fresh_pool().await;
        assert!(!contains(&pool, "jti-1").await.unwrap());
        add(&pool, "jti-1", &future(3600)).await.unwrap();
        assert!(contains(&pool, "jti-1").await.unwrap());
    }

    #[tokio::test]
    async fn expired_rows_dont_match() {
        let pool = fresh_pool().await;
        add(&pool, "jti-old", &future(-3600)).await.unwrap();
        assert!(!contains(&pool, "jti-old").await.unwrap());
    }

    #[tokio::test]
    async fn gc_drops_expired() {
        let pool = fresh_pool().await;
        add(&pool, "jti-old", &future(-3600)).await.unwrap();
        add(&pool, "jti-new", &future(3600)).await.unwrap();
        let dropped = gc(&pool).await.unwrap();
        assert_eq!(dropped, 1);
        assert!(!contains(&pool, "jti-old").await.unwrap());
        assert!(contains(&pool, "jti-new").await.unwrap());
    }
}
