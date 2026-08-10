//! Whether an account's handle still resolves to it.
//!
//! A handle is a claim in two halves. The DID document says `alsoKnownAs`,
//! and the domain says — over DNS `_atproto` or HTTPS
//! `/.well-known/atproto-did` — which DID it belongs to. `createAccount` and
//! `updateHandle` prove both halves through
//! `http::identity_handlers::prove_handle_ownership`, and that was the last
//! time anyone looked.
//!
//! The second half can stop being true without this server doing anything: a
//! DNS record expires, a domain changes hands, a host is rebuilt without its
//! `.well-known`. Consumers that check will see the handle no longer resolve
//! and show `handle.invalid`; this server went on serving it as live, and
//! `describeRepo` answered `handleIsCorrect: true` on the strength of a proof
//! that might be months stale.
//!
//! Three states, and the distinction between the first two matters: never
//! checked is not the same as checked and found wanting. Only the third is
//! served as [`INVALID_HANDLE`].

use crate::account::pool::{AccountPool, AccountPoolKind};
use crate::errors::{PdsError, PdsResult};

/// The handle to serve in place of one that no longer resolves.
///
/// Not a real handle and not resolvable — it is the network's agreed way of
/// saying "this account's handle cannot be confirmed right now". The account
/// keeps its stored handle throughout: this is what callers are told, not
/// what the server believes the handle to be.
pub const INVALID_HANDLE: &str = "handle.invalid";

/// What the last check of a handle concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleValidity {
    /// Never checked since the account was created. Served as live, because
    /// the handle was proven once and nothing has contradicted it.
    Unchecked,
    /// The last check resolved the handle to this account.
    Valid,
    /// The last check did not. Served as [`INVALID_HANDLE`].
    Invalid,
}

impl HandleValidity {
    /// Whether callers should be told the stored handle or [`INVALID_HANDLE`].
    #[must_use]
    pub fn is_invalid(self) -> bool {
        matches!(self, Self::Invalid)
    }

    /// The handle to serve, given the one on the account row.
    #[must_use]
    pub fn serve(self, stored: &str) -> &str {
        if self.is_invalid() {
            INVALID_HANDLE
        } else {
            stored
        }
    }
}

/// Read what the last check concluded.
///
/// # Errors
///
/// Returns [`PdsError::Storage`] if the accounts database cannot be read.
pub async fn validity(pool: &AccountPool, did: &str) -> PdsResult<HandleValidity> {
    let row: Option<(Option<String>,)> = match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query_as("SELECT invalidated_at FROM handle_validation WHERE did = ?")
                .bind(did)
                .fetch_optional(pool.as_sqlite())
                .await
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query_as("SELECT invalidated_at FROM handle_validation WHERE did = $1")
                .bind(did)
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
        reason: format!("handle validity for {did}: {e}"),
    })?;

    Ok(match row {
        None => HandleValidity::Unchecked,
        Some((None,)) => HandleValidity::Valid,
        Some((Some(_),)) => HandleValidity::Invalid,
    })
}

/// Record what a check saw.
///
/// `invalidated_at` is set on the transition into invalid and cleared when the
/// handle resolves again, so the column answers "since when" rather than
/// "as of the last check" — the two differ for a handle that has been broken
/// for a week, and the first is the useful one.
///
/// # Errors
///
/// Returns [`PdsError::Storage`] if the accounts database cannot be written.
pub async fn record(pool: &AccountPool, did: &str, resolved: bool) -> PdsResult<()> {
    let now = chrono::Utc::now().to_rfc3339();
    // Written as one statement so a check cannot read its own row, decide, and
    // race another check writing between the two.
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => sqlx::query(
            "INSERT INTO handle_validation (did, checked_at, invalidated_at)
             VALUES (?, ?, CASE WHEN ? THEN NULL ELSE ? END)
             ON CONFLICT(did) DO UPDATE SET
                 checked_at = excluded.checked_at,
                 invalidated_at = CASE
                     WHEN excluded.invalidated_at IS NULL THEN NULL
                     ELSE COALESCE(handle_validation.invalidated_at, excluded.invalidated_at)
                 END",
        )
        .bind(did)
        .bind(&now)
        .bind(resolved)
        .bind(&now)
        .execute(pool.as_sqlite())
        .await
        .map(|_| ()),
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => sqlx::query(
            "INSERT INTO handle_validation (did, checked_at, invalidated_at)
             VALUES ($1, $2, CASE WHEN $3 THEN NULL ELSE $4 END)
             ON CONFLICT(did) DO UPDATE SET
                 checked_at = excluded.checked_at,
                 invalidated_at = CASE
                     WHEN excluded.invalidated_at IS NULL THEN NULL
                     ELSE COALESCE(handle_validation.invalidated_at, excluded.invalidated_at)
                 END",
        )
        .bind(did)
        .bind(&now)
        .bind(resolved)
        .bind(&now)
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
        reason: format!("record handle validity for {did}: {e}"),
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool() -> AccountPool {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep().join("accounts.sqlite");
        let accounts = crate::account::AccountDirectory::open(&path).await.unwrap();
        let pool = accounts.pool().clone();
        sqlx::query(
            "INSERT INTO account (did, handle, password_hash, created_at, state, signing_key_ref)
             VALUES ('did:plc:hv', 'hv.example', 'x', '2026-01-01T00:00:00Z', 'active', 'k')",
        )
        .execute(&pool)
        .await
        .unwrap();
        AccountPool::Sqlite(pool)
    }

    /// An account nobody has checked is not an account with a broken handle.
    ///
    /// Every account starts here, so serving `handle.invalid` for the
    /// unchecked state would invalidate every handle on the server the moment
    /// this shipped.
    #[tokio::test(flavor = "multi_thread")]
    async fn never_checked_is_not_invalid() {
        let pool = pool().await;
        let seen = validity(&pool, "did:plc:hv").await.unwrap();
        assert_eq!(seen, HandleValidity::Unchecked);
        assert!(!seen.is_invalid());
        assert_eq!(seen.serve("hv.example"), "hv.example");
    }

    /// A failed check is served as `handle.invalid`, and a later success
    /// takes it back.
    ///
    /// The recovery direction is the one worth pinning: a handle broken by an
    /// expired DNS record comes back when the record does, and an account
    /// that stayed invalid after its handle started resolving again would
    /// need operator intervention to fix something that fixed itself.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_check_is_recorded_and_can_be_undone() {
        let pool = pool().await;

        record(&pool, "did:plc:hv", false).await.unwrap();
        let seen = validity(&pool, "did:plc:hv").await.unwrap();
        assert_eq!(seen, HandleValidity::Invalid);
        assert_eq!(seen.serve("hv.example"), INVALID_HANDLE);

        record(&pool, "did:plc:hv", true).await.unwrap();
        let seen = validity(&pool, "did:plc:hv").await.unwrap();
        assert_eq!(seen, HandleValidity::Valid);
        assert_eq!(seen.serve("hv.example"), "hv.example");
    }

    /// `invalidated_at` is when it broke, not when it was last looked at.
    ///
    /// A second failing check must not push the timestamp forward, or an
    /// operator asking how long a handle has been broken gets the age of the
    /// last check instead.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_invalidation_timestamp_is_when_it_broke() {
        let pool = pool().await;

        record(&pool, "did:plc:hv", false).await.unwrap();
        let first: (String,) =
            sqlx::query_as("SELECT invalidated_at FROM handle_validation WHERE did = 'did:plc:hv'")
                .fetch_one(pool.as_sqlite())
                .await
                .unwrap();

        record(&pool, "did:plc:hv", false).await.unwrap();
        let second: (String, String) = sqlx::query_as(
            "SELECT invalidated_at, checked_at FROM handle_validation WHERE did = 'did:plc:hv'",
        )
        .fetch_one(pool.as_sqlite())
        .await
        .unwrap();

        assert_eq!(
            first.0, second.0,
            "a repeated failure must not restate when the handle broke"
        );
        assert!(
            second.1 >= first.0,
            "the check time does move: {} then {}",
            first.0,
            second.1
        );
    }
}
