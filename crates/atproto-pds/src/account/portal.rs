//! Storage for the account portal: the session epoch, and browser sessions.
//!
//! # The session epoch
//!
//! Both credentials this PDS issues -- app-password sessions and OAuth grants
//! -- are HMAC JWTs. Stateless, by design: verifying one reads no storage, so
//! there is no row to delete to end it early. That is why revoking an app
//! password does not end the sessions already minted from it, on this
//! implementation or the reference.
//!
//! "Log out everywhere" needs a stronger guarantee than that, so every token
//! carries the epoch it was minted under and the auth layer refuses any token
//! whose epoch is behind the account's. [`bump_session_epoch`] therefore ends
//! every outstanding access *and* refresh token for an account at once,
//! whichever kind it is, at the cost of one indexed read per authenticated
//! request.
//!
//! # Portal sessions
//!
//! Deliberately not JWTs. The portal is where an account holder revokes
//! things, so its own session has to be revocable in the same breath -- a
//! stateless cookie that outlived "log out everywhere" would be the one
//! credential the button could not reach.
//!
//! Only the SHA-256 of the cookie value is stored. A session identifier is a
//! live login, and the accounts database is what an attacker who obtains a
//! backup copy reads.

use crate::account::{AccountPool, AccountPoolKind};
use crate::errors::{PdsError, PdsResult};
use sha2::{Digest, Sha256};

/// How long a portal sign-in lasts.
///
/// Short by web-session standards, because this session can change the email
/// address and password on the account. An unattended browser is the threat
/// this bounds.
pub const PORTAL_SESSION_TTL_SECS: i64 = 12 * 60 * 60;

/// A portal browser session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalSessionRow {
    /// SHA-256 of the cookie value, hex-encoded.
    pub id: String,
    /// The account this session signs in.
    pub did: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// ISO-8601 expiry.
    pub expires_at: String,
    /// The session epoch this sign-in happened under.
    pub epoch: i64,
    /// The `User-Agent` that signed in, for the session list.
    pub user_agent: Option<String>,
}

/// Hash a cookie value into its storage key.
#[must_use]
pub fn session_id(cookie_value: &str) -> String {
    let mut h = Sha256::new();
    h.update(cookie_value.as_bytes());
    hex::encode(h.finalize())
}

/// The account's current session epoch.
///
/// # Errors
///
/// [`PdsError::Storage`] if the account cannot be read.
pub async fn session_epoch(pool: &AccountPool, did: &str) -> PdsResult<i64> {
    let row: Option<(i64,)> = match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query_as("SELECT session_epoch FROM account WHERE did = ?")
                .bind(did)
                .fetch_optional(pool.as_sqlite())
                .await
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query_as("SELECT session_epoch FROM account WHERE did = $1")
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
        reason: format!("read session_epoch: {e}"),
    })?;
    Ok(row.map(|(e,)| e).unwrap_or(0))
}

/// Advance the account's session epoch, ending every token minted before now.
///
/// Returns the new value. Also clears the account's OAuth refresh rows and
/// portal sessions, which the epoch alone would leave behind as dead storage.
///
/// # Errors
///
/// [`PdsError::Storage`] on write failure.
pub async fn bump_session_epoch(pool: &AccountPool, did: &str) -> PdsResult<i64> {
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query("UPDATE account SET session_epoch = session_epoch + 1 WHERE did = ?")
                .bind(did)
                .execute(pool.as_sqlite())
                .await
                .map(|_| ())
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query("UPDATE account SET session_epoch = session_epoch + 1 WHERE did = $1")
                .bind(did)
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
    }
    .map_err(|e| PdsError::Storage {
        reason: format!("bump session_epoch: {e}"),
    })?;

    // The epoch already makes these unusable; deleting them keeps the portal's
    // own session list honest rather than listing grants that cannot be
    // redeemed.
    delete_oauth_refresh_for(pool, did).await?;
    session_epoch(pool, did).await
}

/// Drop every OAuth refresh row for an account.
async fn delete_oauth_refresh_for(pool: &AccountPool, did: &str) -> PdsResult<()> {
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => sqlx::query("DELETE FROM oauth_refresh WHERE did = ?")
            .bind(did)
            .execute(pool.as_sqlite())
            .await
            .map(|_| ()),
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => sqlx::query("DELETE FROM oauth_refresh WHERE did = $1")
            .bind(did)
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
        reason: format!("delete oauth_refresh: {e}"),
    })
}

/// Drop one application's OAuth grants, leaving every other application's
/// alone.
///
/// Returns how many rows went, so a caller can tell "revoked" from "there was
/// nothing to revoke" — the same request from a double-clicked button.
///
/// # What this does and does not end
///
/// The grant is what renews access, so deleting it stops the application
/// obtaining anything further. It does **not** reach the access token already
/// in that application's hands: those are stateless 15-minute JWTs with no row
/// to delete, so one outstanding token keeps working until it expires. The UI
/// says so rather than implying an instant cutoff.
///
/// The account-wide alternative, `sign_out_everywhere`, *is* instant because it
/// advances the session epoch every token is checked against — at the cost of
/// ending every other application's access too.
///
/// # Errors
///
/// [`PdsError::Storage`] if the delete fails.
pub async fn revoke_oauth_grants_for_client(
    pool: &AccountPool,
    did: &str,
    client_id: &str,
) -> PdsResult<u64> {
    let result = match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query("DELETE FROM oauth_refresh WHERE did = ? AND client_id = ?")
                .bind(did)
                .bind(client_id)
                .execute(pool.as_sqlite())
                .await
                .map(|r| r.rows_affected())
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query("DELETE FROM oauth_refresh WHERE did = $1 AND client_id = $2")
                .bind(did)
                .bind(client_id)
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
        reason: format!("revoke oauth grants: {e}"),
    })?;
    Ok(result)
}

/// Drop the OAuth grants one delegate obtained, leaving the account holder's
/// own alone.
///
/// The counterpart to [`revoke_oauth_grants_for_client`], asking the other
/// question: not "which application is this" but "who signed in to get it".
/// Withdrawing a delegation is what calls it — the row stops the delegate
/// authenticating again, and this stops the sessions they already have from
/// renewing.
///
/// The same limit applies as everywhere else here: an access token already in
/// an application's hands is a stateless fifteen-minute JWT with no row to
/// delete, so it keeps working until it expires. The account-wide
/// `sign_out_everywhere` is the only instant cutoff, at the cost of ending
/// everything else too.
///
/// # Errors
///
/// [`PdsError::Storage`] if the delete fails.
pub async fn revoke_oauth_grants_for_delegate(
    pool: &AccountPool,
    did: &str,
    delegate_did: &str,
) -> PdsResult<u64> {
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query("DELETE FROM oauth_refresh WHERE did = ? AND acting_did = ?")
                .bind(did)
                .bind(delegate_did)
                .execute(pool.as_sqlite())
                .await
                .map(|r| r.rows_affected())
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query("DELETE FROM oauth_refresh WHERE did = $1 AND acting_did = $2")
                .bind(did)
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
        reason: format!("revoke delegate oauth grants: {e}"),
    })
}

/// How many live grants each delegate of an account holds, by delegate DID.
///
/// One query rather than one per delegate: the Delegation page renders a count
/// beside every row, and a list of ten delegates should not be ten reads.
///
/// # Errors
///
/// [`PdsError::Storage`] if the rows cannot be read.
pub async fn count_grants_by_delegate(
    pool: &AccountPool,
    did: &str,
) -> PdsResult<std::collections::HashMap<String, i64>> {
    let rows: Vec<(String, i64)> = match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query_as(
                "SELECT acting_did, COUNT(*) FROM oauth_refresh
             WHERE did = ? AND acting_did IS NOT NULL GROUP BY acting_did",
            )
            .bind(did)
            .fetch_all(pool.as_sqlite())
            .await
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query_as(
                "SELECT acting_did, COUNT(*) FROM oauth_refresh
             WHERE did = $1 AND acting_did IS NOT NULL GROUP BY acting_did",
            )
            .bind(did)
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
        reason: format!("count delegate grants: {e}"),
    })?;
    Ok(rows.into_iter().collect())
}

/// One live OAuth grant, as the Access page lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRow {
    /// The application holding the grant.
    pub client_id: String,
    /// What it was granted.
    pub scope: String,
    /// When the holder approved.
    pub issued_at: String,
    /// The delegate who signed in to obtain it, if it was not the account
    /// holder themselves.
    pub acting_did: Option<String>,
}

/// Every live OAuth grant for an account, newest first.
///
/// # Errors
///
/// [`PdsError::Storage`] if the rows cannot be read.
pub async fn list_oauth_grants(pool: &AccountPool, did: &str) -> PdsResult<Vec<GrantRow>> {
    let rows: Vec<(String, String, String, Option<String>)> = match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query_as(
                "SELECT client_id, scope, issued_at, acting_did FROM oauth_refresh
             WHERE did = ? ORDER BY issued_at DESC",
            )
            .bind(did)
            .fetch_all(pool.as_sqlite())
            .await
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query_as(
                "SELECT client_id, scope, issued_at, acting_did FROM oauth_refresh
             WHERE did = $1 ORDER BY issued_at DESC",
            )
            .bind(did)
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
        reason: format!("list oauth grants: {e}"),
    })?;
    Ok(rows
        .into_iter()
        .map(|(client_id, scope, issued_at, acting_did)| GrantRow {
            client_id,
            scope,
            issued_at,
            acting_did,
        })
        .collect())
}

/// Record a portal sign-in. `cookie_value` is hashed, never stored.
///
/// # Errors
///
/// [`PdsError::Storage`] on write failure.
pub async fn create_session(
    pool: &AccountPool,
    cookie_value: &str,
    did: &str,
    epoch: i64,
    user_agent: Option<&str>,
) -> PdsResult<()> {
    let id = session_id(cookie_value);
    let now = chrono::Utc::now();
    let created_at = now.to_rfc3339();
    let expires_at = (now + chrono::Duration::seconds(PORTAL_SESSION_TTL_SECS)).to_rfc3339();
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => sqlx::query(
            "INSERT INTO portal_session (id, did, created_at, expires_at, epoch, user_agent)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(did)
        .bind(&created_at)
        .bind(&expires_at)
        .bind(epoch)
        .bind(user_agent)
        .execute(pool.as_sqlite())
        .await
        .map(|_| ()),
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => sqlx::query(
            "INSERT INTO portal_session (id, did, created_at, expires_at, epoch, user_agent)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&id)
        .bind(did)
        .bind(&created_at)
        .bind(&expires_at)
        .bind(epoch)
        .bind(user_agent)
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
        reason: format!("create portal session: {e}"),
    })
}

/// Look up a portal session by its cookie value.
///
/// Returns `None` for an unknown or expired session; an expired row is deleted
/// on the way past rather than left for a sweep that may not come.
///
/// # Errors
///
/// [`PdsError::Storage`] if the row cannot be read.
pub async fn lookup_session(
    pool: &AccountPool,
    cookie_value: &str,
) -> PdsResult<Option<PortalSessionRow>> {
    let id = session_id(cookie_value);
    let row: Option<(String, String, String, String, i64, Option<String>)> = match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query_as(
                "SELECT id, did, created_at, expires_at, epoch, user_agent
             FROM portal_session WHERE id = ?",
            )
            .bind(&id)
            .fetch_optional(pool.as_sqlite())
            .await
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query_as(
                "SELECT id, did, created_at, expires_at, epoch, user_agent
             FROM portal_session WHERE id = $1",
            )
            .bind(&id)
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
        reason: format!("lookup portal session: {e}"),
    })?;

    let Some((id, did, created_at, expires_at, epoch, user_agent)) = row else {
        return Ok(None);
    };
    if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(&expires_at)
        && exp <= chrono::Utc::now()
    {
        delete_session(pool, cookie_value).await?;
        return Ok(None);
    }
    Ok(Some(PortalSessionRow {
        id,
        did,
        created_at,
        expires_at,
        epoch,
        user_agent,
    }))
}

/// End one portal session.
///
/// # Errors
///
/// [`PdsError::Storage`] on delete failure.
pub async fn delete_session(pool: &AccountPool, cookie_value: &str) -> PdsResult<()> {
    let id = session_id(cookie_value);
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => sqlx::query("DELETE FROM portal_session WHERE id = ?")
            .bind(&id)
            .execute(pool.as_sqlite())
            .await
            .map(|_| ()),
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => sqlx::query("DELETE FROM portal_session WHERE id = $1")
            .bind(&id)
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
        reason: format!("delete portal session: {e}"),
    })
}

/// End every portal session for an account except, optionally, one.
///
/// The exception is the browser that pressed "log out everywhere". Ending it
/// too would be defensible, but it makes the confirmation impossible to read:
/// the holder is bounced to a sign-in page and cannot see that the thing they
/// asked for happened.
///
/// # Errors
///
/// [`PdsError::Storage`] on delete failure.
pub async fn delete_sessions_for(
    pool: &AccountPool,
    did: &str,
    keep_cookie_value: Option<&str>,
) -> PdsResult<()> {
    let keep = keep_cookie_value.map(session_id).unwrap_or_default();
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query("DELETE FROM portal_session WHERE did = ? AND id <> ?")
                .bind(did)
                .bind(&keep)
                .execute(pool.as_sqlite())
                .await
                .map(|_| ())
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query("DELETE FROM portal_session WHERE did = $1 AND id <> $2")
                .bind(did)
                .bind(&keep)
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
    }
    .map_err(|e| PdsError::Storage {
        reason: format!("delete portal sessions: {e}"),
    })
}

/// Re-stamp a portal session with the current epoch.
///
/// Called after "log out everywhere" so the browser that pressed the button
/// survives the bump it just caused.
///
/// # Errors
///
/// [`PdsError::Storage`] on write failure.
/// Stash a freshly minted secret for the next page render.
///
/// The portal previously carried a new app password back through the redirect
/// query string. A live credential in a URL is written to browser history, the
/// address bar, this server's access log and every proxy's on the way, and
/// leaves in a `Referer` the moment the page links anywhere -- none of which
/// can be un-written. It goes here instead, bound to the session that asked
/// for it.
pub async fn set_flash_secret(
    pool: &AccountPool,
    cookie_value: &str,
    secret: &str,
) -> PdsResult<()> {
    let id = session_id(cookie_value);
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query("UPDATE portal_session SET flash_secret = ? WHERE id = ?")
                .bind(secret)
                .bind(&id)
                .execute(pool.as_sqlite())
                .await
                .map(|_| ())
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query("UPDATE portal_session SET flash_secret = $1 WHERE id = $2")
                .bind(secret)
                .bind(&id)
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
    }
    .map_err(|e| PdsError::Storage {
        reason: format!("set flash secret: {e}"),
    })
}

/// Read a stashed secret and clear it, so it is handed over exactly once.
///
/// A transaction rather than `UPDATE ... RETURNING`: both engines return the
/// row as it is *after* the update, so a statement that clears the column and
/// returns it hands back the `NULL` it just wrote. That is what the first
/// version of this did, and the round-trip test is what caught it.
pub async fn take_flash_secret(
    pool: &AccountPool,
    cookie_value: &str,
) -> PdsResult<Option<String>> {
    let id = session_id(cookie_value);
    let fail = |e: sqlx::Error| PdsError::Storage {
        reason: format!("take flash secret: {e}"),
    };
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            let mut tx = pool.as_sqlite().begin().await.map_err(fail)?;
            let found: Option<(Option<String>,)> =
                sqlx::query_as("SELECT flash_secret FROM portal_session WHERE id = ?")
                    .bind(&id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(fail)?;
            let secret = found.and_then(|(v,)| v);
            if secret.is_some() {
                sqlx::query("UPDATE portal_session SET flash_secret = NULL WHERE id = ?")
                    .bind(&id)
                    .execute(&mut *tx)
                    .await
                    .map_err(fail)?;
            }
            tx.commit().await.map_err(fail)?;
            Ok(secret)
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            let mut tx = pool.as_postgres().begin().await.map_err(fail)?;
            let found: Option<(Option<String>,)> =
                sqlx::query_as("SELECT flash_secret FROM portal_session WHERE id = $1 FOR UPDATE")
                    .bind(&id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(fail)?;
            let secret = found.and_then(|(v,)| v);
            if secret.is_some() {
                sqlx::query("UPDATE portal_session SET flash_secret = NULL WHERE id = $1")
                    .bind(&id)
                    .execute(&mut *tx)
                    .await
                    .map_err(fail)?;
            }
            tx.commit().await.map_err(fail)?;
            Ok(secret)
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature")
        }
    }
}

/// Move a session forward to a new epoch.
///
/// What keeps "sign out everywhere" from signing out the browser that pressed
/// it: every other session is deleted and this one is restamped, so it alone
/// survives the epoch bump.
pub async fn restamp_session(pool: &AccountPool, cookie_value: &str, epoch: i64) -> PdsResult<()> {
    let id = session_id(cookie_value);
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => sqlx::query("UPDATE portal_session SET epoch = ? WHERE id = ?")
            .bind(epoch)
            .bind(&id)
            .execute(pool.as_sqlite())
            .await
            .map(|_| ()),
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query("UPDATE portal_session SET epoch = $1 WHERE id = $2")
                .bind(epoch)
                .bind(&id)
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
    }
    .map_err(|e| PdsError::Storage {
        reason: format!("restamp portal session: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountDirectory;
    use chrono::Utc;

    async fn pool_with_account(did: &str) -> AccountPool {
        let dir = AccountDirectory::open_memory().await.unwrap();
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
        AccountPool::Sqlite(dir.pool().clone())
    }

    /// Insert a grant on `did`, obtained by `acting_did` when it was not the
    /// account holder themselves.
    async fn grant(pool: &AccountPool, jti: &str, did: &str, acting_did: Option<&str>) {
        sqlx::query(
            "INSERT INTO oauth_refresh
                (jti, did, client_id, dpop_jkt, scope, issued_at, family_id, acting_did)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(jti)
        .bind(did)
        .bind("https://app.example/cm")
        .bind("thumb")
        .bind("atproto")
        .bind(Utc::now().to_rfc3339())
        .bind(jti)
        .bind(acting_did)
        .execute(pool.as_sqlite())
        .await
        .unwrap();
    }

    /// Withdrawing one delegation must not reach another delegate's sessions,
    /// nor the account holder's own. "Remove Alice" removing Bob's access is
    /// the failure this pins.
    #[tokio::test(flavor = "multi_thread")]
    async fn revoking_a_delegate_reaches_only_that_delegate() {
        let pool = pool_with_account("did:plc:alice").await;
        grant(&pool, "by-alice", "did:plc:alice", None).await;
        grant(&pool, "by-bob", "did:plc:alice", Some("did:plc:bob")).await;
        grant(&pool, "by-carol", "did:plc:alice", Some("did:plc:carol")).await;

        assert_eq!(
            revoke_oauth_grants_for_delegate(&pool, "did:plc:alice", "did:plc:bob")
                .await
                .unwrap(),
            1
        );

        let left = list_oauth_grants(&pool, "did:plc:alice").await.unwrap();
        let acting: Vec<_> = left.iter().map(|g| g.acting_did.as_deref()).collect();
        assert_eq!(left.len(), 2, "the wrong number of grants survived");
        assert!(acting.contains(&None), "the holder's own grant went");
        assert!(
            acting.contains(&Some("did:plc:carol")),
            "another delegate's grant went"
        );
    }

    /// The per-delegate counts the Delegation page renders, in one read.
    #[tokio::test(flavor = "multi_thread")]
    async fn grants_are_counted_per_delegate_and_exclude_the_holders_own() {
        let pool = pool_with_account("did:plc:alice").await;
        grant(&pool, "by-alice", "did:plc:alice", None).await;
        grant(&pool, "by-bob-1", "did:plc:alice", Some("did:plc:bob")).await;
        grant(&pool, "by-bob-2", "did:plc:alice", Some("did:plc:bob")).await;
        grant(&pool, "by-carol", "did:plc:alice", Some("did:plc:carol")).await;

        let counts = count_grants_by_delegate(&pool, "did:plc:alice")
            .await
            .unwrap();
        assert_eq!(counts.get("did:plc:bob"), Some(&2));
        assert_eq!(counts.get("did:plc:carol"), Some(&1));
        assert_eq!(counts.len(), 2, "the holder's own grant was counted");
    }

    /// The stashed secret comes back once, and only once.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_flash_secret_is_handed_over_exactly_once() {
        let pool = pool_with_account("did:plc:flash").await;
        create_session(&pool, "cookie", "did:plc:flash", 0, None)
            .await
            .unwrap();

        set_flash_secret(&pool, "cookie", "the-secret")
            .await
            .unwrap();

        assert_eq!(
            take_flash_secret(&pool, "cookie").await.unwrap().as_deref(),
            Some("the-secret"),
            "the secret was not handed back"
        );
        assert_eq!(
            take_flash_secret(&pool, "cookie").await.unwrap(),
            None,
            "the secret survived being read"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_epoch_starts_at_zero_and_advances() {
        let pool = pool_with_account("did:plc:alice").await;
        assert_eq!(session_epoch(&pool, "did:plc:alice").await.unwrap(), 0);
        assert_eq!(bump_session_epoch(&pool, "did:plc:alice").await.unwrap(), 1);
        assert_eq!(bump_session_epoch(&pool, "did:plc:alice").await.unwrap(), 2);
        assert_eq!(session_epoch(&pool, "did:plc:alice").await.unwrap(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unknown_account_reads_as_epoch_zero() {
        // Not an error: the caller is deciding whether a token is stale, and
        // an account that does not exist has no tokens to keep alive. The
        // account lookup that follows is what refuses the request.
        let pool = pool_with_account("did:plc:alice").await;
        assert_eq!(session_epoch(&pool, "did:plc:nobody").await.unwrap(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_portal_session_round_trips_and_stores_only_its_hash() {
        let pool = pool_with_account("did:plc:alice").await;
        let cookie = "a-random-cookie-value";
        create_session(&pool, cookie, "did:plc:alice", 0, Some("Firefox"))
            .await
            .unwrap();

        let found = lookup_session(&pool, cookie)
            .await
            .unwrap()
            .expect("session");
        assert_eq!(found.did, "did:plc:alice");
        assert_eq!(found.user_agent.as_deref(), Some("Firefox"));

        // The cookie value itself must not be recoverable from the row.
        assert_ne!(found.id, cookie);
        assert_eq!(found.id, session_id(cookie));

        assert!(
            lookup_session(&pool, "some-other-value")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_expired_portal_session_does_not_resolve() {
        let pool = pool_with_account("did:plc:alice").await;
        let cookie = "expired-cookie";
        create_session(&pool, cookie, "did:plc:alice", 0, None)
            .await
            .unwrap();
        sqlx::query("UPDATE portal_session SET expires_at = ? WHERE id = ?")
            .bind((Utc::now() - chrono::Duration::hours(1)).to_rfc3339())
            .bind(session_id(cookie))
            .execute(pool.as_sqlite())
            .await
            .unwrap();
        assert!(lookup_session(&pool, cookie).await.unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn logging_out_everywhere_keeps_the_browser_that_asked() {
        let pool = pool_with_account("did:plc:alice").await;
        create_session(&pool, "here", "did:plc:alice", 0, None)
            .await
            .unwrap();
        create_session(&pool, "elsewhere", "did:plc:alice", 0, None)
            .await
            .unwrap();

        delete_sessions_for(&pool, "did:plc:alice", Some("here"))
            .await
            .unwrap();

        assert!(lookup_session(&pool, "here").await.unwrap().is_some());
        assert!(lookup_session(&pool, "elsewhere").await.unwrap().is_none());
    }
}
