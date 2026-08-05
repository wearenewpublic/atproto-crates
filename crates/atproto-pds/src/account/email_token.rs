//! Email-confirmation token lifecycle.
//!
//! The `email_token` table backs five user-facing flows that need a
//! one-time bearer-token round trip:
//!
//! - **`requestEmailUpdate` / `confirmEmailUpdate`** — change the
//!   account's email; carries the new address in `new_email`.
//! - **`requestEmailConfirmation` / `confirmEmail`** — confirm the
//!   account's existing email.
//! - **`requestPasswordReset` / `resetPassword`** — anonymous reset
//!   when the user is locked out; `new_email` is NULL.
//! - **`requestAccountDelete` / `deleteAccount`** — second-factor
//!   confirmation for account deletion; `new_email` is NULL.
//! - **`requestPlcOperationSignature` / `signPlcOperation`** — second
//!   factor for signing a PLC operation with the account's rotation key;
//!   `new_email` is NULL and the TTL is 15 minutes rather than an hour.
//!
//! All five flows share the same `(token, did, purpose, expires_at,
//! new_email)` row shape. The `purpose` column is the discriminator so
//! a token issued for one flow can't be redeemed in another.
//!
//! Functions accept `&AccountPool` and dispatch to the correct
//! backend at runtime.

use crate::account::{AccountPool, AccountPoolKind};
use crate::errors::{PdsError, PdsResult};

/// Purpose discriminator for an `email_token` row.
pub const PURPOSE_UPDATE_EMAIL: &str = "update_email";
/// Email confirmation purpose.
pub const PURPOSE_CONFIRM_EMAIL: &str = "confirm_email";
/// Password-reset purpose.
pub const PURPOSE_RESET_PASSWORD: &str = "reset_password";
/// Account-deletion confirmation purpose.
pub const PURPOSE_DELETE_ACCOUNT: &str = "delete_account";
/// PLC-operation-signing purpose.
///
/// `requestPlcOperationSignature` issues one of these and mails it; the
/// second factor for having this server sign a key-rotation operation with
/// the account's rotation key.
pub const PURPOSE_PLC_OPERATION: &str = "plc_operation";

/// One row from the `email_token` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailTokenRow {
    /// DID of the account this token is bound to.
    pub did: String,
    /// Flow discriminator (one of the `PURPOSE_*` constants).
    pub purpose: String,
    /// ISO-8601 expiration timestamp.
    pub expires_at: String,
    /// New email address (only set for `update_email` flow).
    pub new_email: Option<String>,
}

/// Insert a new email token. Returns the assigned token unchanged.
///
/// # Errors
///
/// Returns [`PdsError::Storage`] on backend failure.
pub async fn insert(
    pool: &AccountPool,
    token: &str,
    did: &str,
    purpose: &str,
    expires_at: &str,
    new_email: Option<&str>,
) -> PdsResult<()> {
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query(
                "INSERT INTO email_token (token, did, purpose, expires_at, new_email)
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(token)
            .bind(did)
            .bind(purpose)
            .bind(expires_at)
            .bind(new_email)
            .execute(pool.as_sqlite())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("email_token insert: {e}"),
            })?;
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query(
                "INSERT INTO email_token (token, did, purpose, expires_at, new_email)
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(token)
            .bind(did)
            .bind(purpose)
            .bind(expires_at)
            .bind(new_email)
            .execute(pool.as_postgres())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("email_token insert: {e}"),
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

/// Look up an email-token row by its bearer token. Returns `None` if
/// the token is unknown.
pub async fn lookup(pool: &AccountPool, token: &str) -> PdsResult<Option<EmailTokenRow>> {
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            let row: Option<(String, String, String, Option<String>)> = sqlx::query_as(
                "SELECT did, purpose, expires_at, new_email FROM email_token WHERE token = ?",
            )
            .bind(token)
            .fetch_optional(pool.as_sqlite())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("email_token lookup: {e}"),
            })?;
            Ok(
                row.map(|(did, purpose, expires_at, new_email)| EmailTokenRow {
                    did,
                    purpose,
                    expires_at,
                    new_email,
                }),
            )
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            let row: Option<(String, String, String, Option<String>)> = sqlx::query_as(
                "SELECT did, purpose, expires_at, new_email FROM email_token WHERE token = $1",
            )
            .bind(token)
            .fetch_optional(pool.as_postgres())
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("email_token lookup: {e}"),
            })?;
            Ok(
                row.map(|(did, purpose, expires_at, new_email)| EmailTokenRow {
                    did,
                    purpose,
                    expires_at,
                    new_email,
                }),
            )
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature")
        }
    }
}

/// Delete an email-token row by token. Idempotent — returns `Ok(())`
/// even if no row matched.
pub async fn delete(pool: &AccountPool, token: &str) -> PdsResult<()> {
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            sqlx::query("DELETE FROM email_token WHERE token = ?")
                .bind(token)
                .execute(pool.as_sqlite())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("email_token delete: {e}"),
                })?;
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query("DELETE FROM email_token WHERE token = $1")
                .bind(token)
                .execute(pool.as_postgres())
                .await
                .map_err(|e| PdsError::Storage {
                    reason: format!("email_token delete: {e}"),
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

/// Why a token was refused.
///
/// The lexicons that take an email token -- `confirmEmail`, `resetPassword`,
/// `deleteAccount`, `updateEmail` -- each declare `InvalidToken` **and**
/// `ExpiredToken` as separate errors, and clients switch on the name: an
/// expired token means "ask for another one", an invalid one means "that is
/// not a token for this account". Collapsing both into one denial made the
/// difference unavailable to callers, so it is carried here.
#[derive(Debug)]
pub enum TokenRejected {
    /// No such token, or it belongs to another account or another flow. The
    /// three are deliberately indistinguishable to the caller: telling a
    /// stranger which of them applies confirms that a token exists.
    Invalid,
    /// The token was this account's and for this flow, but its window has
    /// closed.
    Expired,
    /// The store could not be read. Not a judgement about the token.
    Storage(PdsError),
}

impl From<PdsError> for TokenRejected {
    fn from(e: PdsError) -> Self {
        TokenRejected::Storage(e)
    }
}

/// Verify and spend a token that identifies its own account.
///
/// `resetPassword` and `deleteAccount` are reached without a session -- the
/// token *is* the credential -- so there is no DID to bind against and the row
/// supplies it. Everything else is checked exactly as [`consume`] does.
///
/// # Errors
///
/// [`TokenRejected`].
pub async fn consume_any(
    pool: &AccountPool,
    token: &str,
    purpose: &str,
) -> Result<EmailTokenRow, TokenRejected> {
    let row = verify_any(pool, token, purpose).await?;
    delete(pool, token).await?;
    Ok(row)
}

/// Check a self-identifying token without spending it.
///
/// `deleteAccount` needs this: it has a second factor -- the account password
/// -- still to verify, and spending the token first means a single mistyped
/// password destroys a one-time code the user then has to request again. Worse,
/// anyone holding the token but not the password could burn codes at will.
/// Callers must [`delete`] the token once every factor has passed.
///
/// An *expired* token is still deleted here. It has no remaining use, and
/// leaving it for the GC sweep only keeps a dead row addressable.
///
/// # Errors
///
/// [`TokenRejected`].
pub async fn verify_any(
    pool: &AccountPool,
    token: &str,
    purpose: &str,
) -> Result<EmailTokenRow, TokenRejected> {
    let row = lookup(pool, token).await?.ok_or(TokenRejected::Invalid)?;
    if row.purpose != purpose {
        return Err(TokenRejected::Invalid);
    }
    let expires =
        chrono::DateTime::parse_from_rfc3339(&row.expires_at).map_err(|e| PdsError::Storage {
            reason: format!("email_token expires_at is not RFC-3339: {e}"),
        })?;
    if expires <= chrono::Utc::now() {
        delete(pool, token).await?;
        return Err(TokenRejected::Expired);
    }
    Ok(row)
}

/// Verify a token for `did` and `purpose`, then consume it.
///
/// Checks all four properties a one-time token needs -- it exists, it is for
/// this flow, it is bound to this account, and it has not expired -- and
/// deletes it so it cannot be replayed. Returns the row for callers that need
/// `new_email`.
///
/// # Errors
///
/// [`TokenRejected`], which the HTTP layer maps to the error name the relevant
/// lexicon declares.
pub async fn consume(
    pool: &AccountPool,
    token: &str,
    purpose: &str,
    did: &str,
) -> Result<EmailTokenRow, TokenRejected> {
    let row = lookup(pool, token).await?.ok_or(TokenRejected::Invalid)?;
    if row.purpose != purpose || row.did != did {
        return Err(TokenRejected::Invalid);
    }
    let expires =
        chrono::DateTime::parse_from_rfc3339(&row.expires_at).map_err(|e| PdsError::Storage {
            reason: format!("email_token expires_at is not RFC-3339: {e}"),
        })?;
    if expires <= chrono::Utc::now() {
        // Consume it anyway; an expired token has no further use and leaving
        // it behind only waits for the GC sweep.
        delete(pool, token).await?;
        return Err(TokenRejected::Expired);
    }
    delete(pool, token).await?;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountDirectory;
    use chrono::Utc;

    async fn fresh_pool_with_account(did: &str) -> AccountPool {
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
        .bind("file:stub")
        .bind(1i64)
        .execute(dir.pool())
        .await
        .unwrap();
        dir.account_pool()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn insert_lookup_round_trip() {
        let pool = fresh_pool_with_account("did:plc:alice").await;
        insert(
            &pool,
            "tok-123",
            "did:plc:alice",
            PURPOSE_UPDATE_EMAIL,
            "2030-01-01T00:00:00Z",
            Some("new@example.com"),
        )
        .await
        .unwrap();
        let row = lookup(&pool, "tok-123").await.unwrap().unwrap();
        assert_eq!(row.did, "did:plc:alice");
        assert_eq!(row.purpose, PURPOSE_UPDATE_EMAIL);
        assert_eq!(row.new_email, Some("new@example.com".to_string()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lookup_unknown_returns_none() {
        let pool = fresh_pool_with_account("did:plc:alice").await;
        assert!(lookup(&pool, "tok-nosuch").await.unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn delete_consumes_row() {
        let pool = fresh_pool_with_account("did:plc:alice").await;
        insert(
            &pool,
            "tok-1",
            "did:plc:alice",
            PURPOSE_RESET_PASSWORD,
            "2030-01-01T00:00:00Z",
            None,
        )
        .await
        .unwrap();
        delete(&pool, "tok-1").await.unwrap();
        assert!(lookup(&pool, "tok-1").await.unwrap().is_none());
        // Idempotent re-delete.
        delete(&pool, "tok-1").await.unwrap();
    }
}
