//! Durable process-level settings.
//!
//! A small keyed store for values the PDS generates for itself and must find
//! again on the next boot. The occupant that motivated it is the PDS-level
//! OAuth signing key reference; see [`PDS_SIGNING_KEY_REF`].

use crate::account::pool::{AccountPool, AccountPoolKind};
use crate::errors::{PdsError, PdsResult};

/// Setting key holding the `KeyStore` reference for the PDS-level OAuth
/// signing key.
///
/// [`crate::keys::KeyStore::put`] returns an opaque, content-addressed
/// `key_ref`; nothing about it is derivable from a label, so the only way to
/// get the same key back later is to have written the ref down. This is where
/// the PDS-level one is written down, the way `account.signing_key_ref` is for
/// each account's.
pub const PDS_SIGNING_KEY_REF: &str = "pds_signing_key_ref";

/// Read a setting, or `None` if it has never been written.
pub async fn get_setting(pool: &AccountPool, key: &str) -> PdsResult<Option<String>> {
    let row: Option<(String,)> = match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query_as("SELECT value FROM pds_setting WHERE key = ?")
                .bind(key)
                .fetch_optional(pool.as_sqlite())
                .await
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query_as("SELECT value FROM pds_setting WHERE key = $1")
                .bind(key)
                .fetch_optional(pool.as_postgres())
                .await
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature")
        }
    }
    .map_err(|e| PdsError::Storage {
        reason: format!("get setting {key}: {e}"),
    })?;
    Ok(row.map(|(value,)| value))
}

/// Write a setting, replacing any previous value.
pub async fn put_setting(pool: &AccountPool, key: &str, value: &str) -> PdsResult<()> {
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => sqlx::query(
            "INSERT INTO pds_setting (key, value) VALUES (?, ?)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(pool.as_sqlite())
        .await
        .map(|_| ()),
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => sqlx::query(
            "INSERT INTO pds_setting (key, value) VALUES ($1, $2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(pool.as_postgres())
        .await
        .map(|_| ()),
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature")
        }
    }
    .map_err(|e| PdsError::Storage {
        reason: format!("put setting {key}: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountDirectory;

    #[tokio::test]
    async fn a_setting_survives_being_read_back() {
        let dir = AccountDirectory::open_memory().await.unwrap();
        let pool = AccountPool::Sqlite(dir.pool().clone());

        assert_eq!(get_setting(&pool, PDS_SIGNING_KEY_REF).await.unwrap(), None);

        put_setting(&pool, PDS_SIGNING_KEY_REF, "file:abc123")
            .await
            .unwrap();
        assert_eq!(
            get_setting(&pool, PDS_SIGNING_KEY_REF).await.unwrap(),
            Some("file:abc123".to_string())
        );
    }

    #[tokio::test]
    async fn writing_a_setting_twice_replaces_it() {
        let dir = AccountDirectory::open_memory().await.unwrap();
        let pool = AccountPool::Sqlite(dir.pool().clone());

        put_setting(&pool, PDS_SIGNING_KEY_REF, "file:first")
            .await
            .unwrap();
        put_setting(&pool, PDS_SIGNING_KEY_REF, "file:second")
            .await
            .unwrap();

        assert_eq!(
            get_setting(&pool, PDS_SIGNING_KEY_REF).await.unwrap(),
            Some("file:second".to_string())
        );
    }
}
