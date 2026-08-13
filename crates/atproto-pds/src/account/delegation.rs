//! Storage for account delegation: which identities may act as an account.
//!
//! # A delegation is a name, not a credential
//!
//! Everything else that can reach an account is something somebody holds -- an
//! app password, an OAuth refresh token, a portal session cookie. Each one can
//! be stolen, and each one works for whoever ends up with it.
//!
//! A row here is different in kind. It holds no secret; it names a DID. The
//! delegate proves that DID against their own PDS, by OAuth, and this table
//! answers one question afterwards: is that identity on the list. There is
//! nothing in it to leak, and a copy of the accounts database tells an attacker
//! who may act as whom without handing them any way to do it.
//!
//! That is also why [`add`] is unilateral and needs no acceptance from the
//! delegate. Naming somebody grants them nothing they can use without first
//! proving they are them.
//!
//! # The handle is display, the DID is authority
//!
//! [`DelegationRow::delegate_handle`] is what the handle was when the
//! delegation was made, kept so the portal has something to render before it
//! has resolved anything. It is never what [`is_delegate`] checks. Handles
//! move between DIDs -- that is the point of them -- and a check against a
//! string the delegate's DNS controls would let a handle change hand this
//! account to a stranger.

use crate::account::{AccountPool, AccountPoolKind};
use crate::errors::{PdsError, PdsResult};

/// One identity permitted to act as an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationRow {
    /// The account being acted for.
    pub core_did: String,
    /// The identity permitted to act.
    pub delegate_did: String,
    /// The delegate's handle when the delegation was made. Display only.
    pub delegate_handle: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
}

/// Every delegation an account has made, oldest first.
///
/// Oldest first rather than newest: this is a list somebody curates over time,
/// and a stable order means a row does not move when another is added.
///
/// # Errors
///
/// [`PdsError::Storage`] if the rows cannot be read.
pub async fn list(pool: &AccountPool, core_did: &str) -> PdsResult<Vec<DelegationRow>> {
    let rows: Vec<(String, String, String)> = match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query_as(
                "SELECT delegate_did, delegate_handle, created_at FROM account_delegation
                 WHERE core_did = ? ORDER BY created_at ASC, delegate_did ASC",
            )
            .bind(core_did)
            .fetch_all(pool.as_sqlite())
            .await
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query_as(
                "SELECT delegate_did, delegate_handle, created_at FROM account_delegation
                 WHERE core_did = $1 ORDER BY created_at ASC, delegate_did ASC",
            )
            .bind(core_did)
            .fetch_all(pool.as_postgres())
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
        reason: format!("list delegations: {e}"),
    })?;

    Ok(rows
        .into_iter()
        .map(
            |(delegate_did, delegate_handle, created_at)| DelegationRow {
                core_did: core_did.to_string(),
                delegate_did,
                delegate_handle,
                created_at,
            },
        )
        .collect())
}

/// Name an identity as a delegate of an account.
///
/// Returns `false` when the pair already existed, so a double-clicked button
/// can be reported as "already delegated" rather than as a fresh grant the
/// holder did not make. The insert is conditional in SQL rather than a read
/// followed by a write: two clicks arriving together would both see nothing
/// and the second would fail on the primary key.
///
/// # Errors
///
/// [`PdsError::Storage`] on write failure.
pub async fn add(
    pool: &AccountPool,
    core_did: &str,
    delegate_did: &str,
    delegate_handle: &str,
) -> PdsResult<bool> {
    let created_at = chrono::Utc::now().to_rfc3339();
    let affected = match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => sqlx::query(
            "INSERT OR IGNORE INTO account_delegation
                (core_did, delegate_did, delegate_handle, created_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(core_did)
        .bind(delegate_did)
        .bind(delegate_handle)
        .bind(&created_at)
        .execute(pool.as_sqlite())
        .await
        .map(|r| r.rows_affected()),
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => sqlx::query(
            "INSERT INTO account_delegation
                (core_did, delegate_did, delegate_handle, created_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (core_did, delegate_did) DO NOTHING",
        )
        .bind(core_did)
        .bind(delegate_did)
        .bind(delegate_handle)
        .bind(&created_at)
        .execute(pool.as_postgres())
        .await
        .map(|r| r.rows_affected()),
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature")
        }
    }
    .map_err(|e| PdsError::Storage {
        reason: format!("add delegation: {e}"),
    })?;
    Ok(affected > 0)
}

/// Withdraw a delegation.
///
/// Returns how many rows went, so the caller can tell "removed" from "there
/// was nothing to remove". Ending the grants the delegate already obtained is
/// a separate step -- see
/// [`revoke_oauth_grants_for_delegate`](crate::account::portal::revoke_oauth_grants_for_delegate)
/// -- because this row and those tokens are different things, and a caller
/// that wants only one of them should be able to say so.
///
/// # Errors
///
/// [`PdsError::Storage`] on delete failure.
pub async fn remove(pool: &AccountPool, core_did: &str, delegate_did: &str) -> PdsResult<u64> {
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query("DELETE FROM account_delegation WHERE core_did = ? AND delegate_did = ?")
                .bind(core_did)
                .bind(delegate_did)
                .execute(pool.as_sqlite())
                .await
                .map(|r| r.rows_affected())
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query("DELETE FROM account_delegation WHERE core_did = $1 AND delegate_did = $2")
                .bind(core_did)
                .bind(delegate_did)
                .execute(pool.as_postgres())
                .await
                .map(|r| r.rows_affected())
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature")
        }
    }
    .map_err(|e| PdsError::Storage {
        reason: format!("remove delegation: {e}"),
    })
}

/// Whether `delegate_did` may act as `core_did`.
///
/// The one question the authentication path asks, and the only place the
/// answer may come from. Both arguments are DIDs, compared exactly: no
/// handles, no case folding, nothing resolved on the way past.
///
/// # Errors
///
/// [`PdsError::Storage`] if the row cannot be read.
pub async fn is_delegate(
    pool: &AccountPool,
    core_did: &str,
    delegate_did: &str,
) -> PdsResult<bool> {
    let row: Option<(String,)> = match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query_as(
                "SELECT delegate_did FROM account_delegation
             WHERE core_did = ? AND delegate_did = ?",
            )
            .bind(core_did)
            .bind(delegate_did)
            .fetch_optional(pool.as_sqlite())
            .await
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query_as(
                "SELECT delegate_did FROM account_delegation
             WHERE core_did = $1 AND delegate_did = $2",
            )
            .bind(core_did)
            .bind(delegate_did)
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
        reason: format!("read delegation: {e}"),
    })?;
    Ok(row.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountDirectory;
    use chrono::Utc;

    async fn pool_with_accounts(dids: &[&str]) -> AccountPool {
        let dir = AccountDirectory::open_memory().await.unwrap();
        for did in dids {
            sqlx::query(
                "INSERT INTO account (did, handle, password_hash, created_at, state, signing_key_ref, pds_managed_rotation)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(did)
            .bind(format!("{}.example", did.replace([':'], "_")))
            .bind("$argon2id$x")
            .bind(Utc::now().to_rfc3339())
            .bind("active")
            .bind("key-1")
            .bind(1)
            .execute(dir.pool())
            .await
            .unwrap();
        }
        AccountPool::Sqlite(dir.pool().clone())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_delegation_round_trips() {
        let pool = pool_with_accounts(&["did:plc:core"]).await;
        assert!(
            add(&pool, "did:plc:core", "did:plc:alice", "alice.example")
                .await
                .unwrap()
        );

        let rows = list(&pool, "did:plc:core").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].delegate_did, "did:plc:alice");
        assert_eq!(rows[0].delegate_handle, "alice.example");
        assert!(
            is_delegate(&pool, "did:plc:core", "did:plc:alice")
                .await
                .unwrap()
        );
    }

    /// Adding the same pair twice is the same request arriving twice, not two
    /// delegations.
    #[tokio::test(flavor = "multi_thread")]
    async fn adding_the_same_delegate_twice_reports_it_and_lists_once() {
        let pool = pool_with_accounts(&["did:plc:core"]).await;
        assert!(
            add(&pool, "did:plc:core", "did:plc:alice", "alice.example")
                .await
                .unwrap()
        );
        assert!(
            !add(&pool, "did:plc:core", "did:plc:alice", "alice.moved")
                .await
                .unwrap(),
            "a repeat add reported itself as a fresh delegation"
        );
        assert_eq!(list(&pool, "did:plc:core").await.unwrap().len(), 1);
    }

    /// One account's delegates are not another's, and a delegate of nobody is
    /// a delegate of nobody.
    #[tokio::test(flavor = "multi_thread")]
    async fn delegation_does_not_leak_between_accounts() {
        let pool = pool_with_accounts(&["did:plc:core", "did:plc:other"]).await;
        add(&pool, "did:plc:core", "did:plc:alice", "alice.example")
            .await
            .unwrap();

        assert!(
            !is_delegate(&pool, "did:plc:other", "did:plc:alice")
                .await
                .unwrap()
        );
        assert!(
            !is_delegate(&pool, "did:plc:core", "did:plc:mallory")
                .await
                .unwrap()
        );
        assert!(list(&pool, "did:plc:other").await.unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn removing_reports_whether_there_was_anything_to_remove() {
        let pool = pool_with_accounts(&["did:plc:core"]).await;
        add(&pool, "did:plc:core", "did:plc:alice", "alice.example")
            .await
            .unwrap();

        assert_eq!(
            remove(&pool, "did:plc:core", "did:plc:alice")
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            remove(&pool, "did:plc:core", "did:plc:alice")
                .await
                .unwrap(),
            0
        );
        assert!(
            !is_delegate(&pool, "did:plc:core", "did:plc:alice")
                .await
                .unwrap()
        );
    }

    /// Deleting the account takes its delegations with it. A delegation to an
    /// account that no longer exists names nothing to act as.
    #[tokio::test(flavor = "multi_thread")]
    async fn deleting_the_account_removes_its_delegations() {
        let pool = pool_with_accounts(&["did:plc:core"]).await;
        add(&pool, "did:plc:core", "did:plc:alice", "alice.example")
            .await
            .unwrap();

        sqlx::query("DELETE FROM account WHERE did = ?")
            .bind("did:plc:core")
            .execute(pool.as_sqlite())
            .await
            .unwrap();

        assert!(list(&pool, "did:plc:core").await.unwrap().is_empty());
    }
}
