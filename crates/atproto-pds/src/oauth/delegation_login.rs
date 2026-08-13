//! Storage for a delegated sign-in that is part-way through.
//!
//! # Why the authorization request has to move
//!
//! A delegate authenticates against *their own* PDS, which means leaving this
//! server, signing in somewhere else, and coming back. That takes as long as
//! it takes a person to type a password on another site -- minutes, sometimes.
//!
//! The authorization request they are in the middle of lives in `oauth_par`
//! with a sixty-second TTL ([`PAR_TTL_SECS`](crate::oauth::state::PAR_TTL_SECS)),
//! which is right for its own purpose and hopeless for this one. So the
//! request is taken out of that table and parked here, keyed by the OAuth
//! `state` this server sends to the delegate's authorization server -- the one
//! thing the callback is guaranteed to carry back.
//!
//! Consuming the PAR row on the way out settles the race for free: it can only
//! be taken once, so a second click on the same authorization starts nothing.
//!
//! # What is stored, and why some of it is sensitive
//!
//! The PKCE verifier and the DPoP private key are per-flow secrets generated
//! before the redirect and needed again at the callback -- a different request,
//! and in a multi-process deployment a different process. There is nowhere else
//! for them to live.
//!
//! They are bounded three ways rather than trusted: they exist only for
//! [`LOGIN_TTL_SECS`], [`take`] deletes the row in the same transaction that
//! reads it so a replayed callback finds nothing, and neither secret grants
//! anything on its own -- the exchange also needs the authorization code, which
//! is single-use at the delegate's server.

use crate::account::{AccountPool, AccountPoolKind};
use crate::errors::{PdsError, PdsResult};
use crate::oauth::state::OAuthRequest;

/// How long a delegated sign-in may stay in flight.
///
/// Long enough for someone to sign in on another server, including finding a
/// password manager and a second factor; short enough that an abandoned flow
/// stops being a row holding a private key within the hour. Ten minutes is
/// also comfortably longer than the DPoP proof and client assertion lifetimes
/// involved, so nothing else expires underneath it.
pub const LOGIN_TTL_SECS: i64 = 10 * 60;

/// A delegated sign-in waiting for its callback.
#[derive(Debug, Clone)]
pub struct ParkedLogin {
    /// The account being acted for, decided before the redirect.
    pub core_did: String,
    /// The DID the flow was begun for. The token response's `sub` must equal
    /// it.
    pub delegate_did: String,
    /// Issuer identifier the callback's `iss` must match (RFC 9207).
    pub issuer: String,
    /// The delegate authorization server's token endpoint.
    pub token_endpoint: String,
    /// The authorization request this sign-in will complete.
    pub request: OAuthRequest,
    /// Nonce sent with the authorization request.
    pub nonce: String,
    /// PKCE verifier for the token exchange.
    pub pkce_verifier: String,
    /// Hex-encoded private DPoP key bound to this flow.
    pub dpop_private_key: String,
    /// SHA-256 of the cookie set on the browser that began this sign-in.
    ///
    /// See [`binding_id`] for what this is for. Compared, never disclosed:
    /// [`take`] returns it so the callback can check, and nothing renders it.
    pub browser_binding: String,
}

/// Hash a delegation cookie value into what is stored beside the flow.
///
/// The same treatment [`crate::account::portal::session_id`] gives a portal
/// cookie, and for the same reason: the stored form must not be usable if the
/// database is read.
#[must_use]
pub fn binding_id(cookie_value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(cookie_value.as_bytes());
    hex::encode(h.finalize())
}

/// Park a sign-in against the `state` value sent to the delegate's server.
///
/// # Errors
///
/// [`PdsError::Storage`] on serialization or write failure.
pub async fn park(pool: &AccountPool, state: &str, login: &ParkedLogin) -> PdsResult<()> {
    let request_json = serde_json::to_string(&login.request).map_err(|e| PdsError::Storage {
        reason: format!("serialize parked authorization request: {e}"),
    })?;
    let now = chrono::Utc::now();
    let created_at = now.to_rfc3339();
    let expires_at = (now + chrono::Duration::seconds(LOGIN_TTL_SECS)).to_rfc3339();

    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => sqlx::query(
            "INSERT INTO delegation_login
                (state, core_did, delegate_did, issuer, token_endpoint, request_json,
                 nonce, pkce_verifier, dpop_private_key, browser_binding,
                 created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(state)
        .bind(&login.core_did)
        .bind(&login.delegate_did)
        .bind(&login.issuer)
        .bind(&login.token_endpoint)
        .bind(&request_json)
        .bind(&login.nonce)
        .bind(&login.pkce_verifier)
        .bind(&login.dpop_private_key)
        .bind(&login.browser_binding)
        .bind(&created_at)
        .bind(&expires_at)
        .execute(pool.as_sqlite())
        .await
        .map(|_| ()),
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => sqlx::query(
            "INSERT INTO delegation_login
                (state, core_did, delegate_did, issuer, token_endpoint, request_json,
                 nonce, pkce_verifier, dpop_private_key, browser_binding,
                 created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(state)
        .bind(&login.core_did)
        .bind(&login.delegate_did)
        .bind(&login.issuer)
        .bind(&login.token_endpoint)
        .bind(&request_json)
        .bind(&login.nonce)
        .bind(&login.pkce_verifier)
        .bind(&login.dpop_private_key)
        .bind(&login.browser_binding)
        .bind(&created_at)
        .bind(&expires_at)
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
        reason: format!("park delegated login: {e}"),
    })
}

/// Read a parked sign-in and delete it, so it completes exactly once.
///
/// Returns `None` for an unknown, already-redeemed or expired `state`. All
/// three are the same answer on purpose: the callback refuses uniformly, and
/// distinguishing them would tell a caller which of their guesses had once
/// been a real flow.
///
/// A transaction rather than `DELETE ... RETURNING`: this must be single-use
/// even when two callbacks arrive together, and the delete is what decides
/// which one wins.
///
/// # Errors
///
/// [`PdsError::Storage`] on read, delete or deserialization failure.
pub async fn take(pool: &AccountPool, state: &str) -> PdsResult<Option<ParkedLogin>> {
    type Row = (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    );
    let fail = |e: sqlx::Error| PdsError::Storage {
        reason: format!("take delegated login: {e}"),
    };
    let found: Option<Row> = match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => {
            let mut tx = pool.as_sqlite().begin().await.map_err(fail)?;
            let found: Option<Row> = sqlx::query_as(
                "SELECT core_did, delegate_did, issuer, token_endpoint,
                        request_json, nonce, pkce_verifier, dpop_private_key,
                        browser_binding, expires_at
                 FROM delegation_login WHERE state = ?",
            )
            .bind(state)
            .fetch_optional(&mut *tx)
            .await
            .map_err(fail)?;
            if found.is_some() {
                sqlx::query("DELETE FROM delegation_login WHERE state = ?")
                    .bind(state)
                    .execute(&mut *tx)
                    .await
                    .map_err(fail)?;
            }
            tx.commit().await.map_err(fail)?;
            found
        }
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            let mut tx = pool.as_postgres().begin().await.map_err(fail)?;
            let found: Option<Row> = sqlx::query_as(
                "SELECT core_did, delegate_did, issuer, token_endpoint,
                        request_json, nonce, pkce_verifier, dpop_private_key,
                        browser_binding, expires_at
                 FROM delegation_login WHERE state = $1 FOR UPDATE",
            )
            .bind(state)
            .fetch_optional(&mut *tx)
            .await
            .map_err(fail)?;
            if found.is_some() {
                sqlx::query("DELETE FROM delegation_login WHERE state = $1")
                    .bind(state)
                    .execute(&mut *tx)
                    .await
                    .map_err(fail)?;
            }
            tx.commit().await.map_err(fail)?;
            found
        }
        #[cfg(not(feature = "sqlite"))]
        AccountPoolKind::Sqlite => unreachable!("AccountPool::Sqlite without `sqlite` feature"),
        #[cfg(not(feature = "postgres"))]
        AccountPoolKind::Postgres => {
            unreachable!("AccountPool::Postgres without `postgres` feature")
        }
    };

    let Some((
        core_did,
        delegate_did,
        issuer,
        token_endpoint,
        request_json,
        nonce,
        pkce_verifier,
        dpop_private_key,
        browser_binding,
        expires_at,
    )) = found
    else {
        return Ok(None);
    };

    // Expiry is checked after the delete rather than before it. A flow that
    // ran out of time is finished either way, and leaving the row behind for a
    // sweep that may be a day off keeps a private key on disk for no reason.
    if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(&expires_at)
        && exp <= chrono::Utc::now()
    {
        tracing::info!(core_did, "a delegated sign-in expired before its callback");
        return Ok(None);
    }

    let request: OAuthRequest =
        serde_json::from_str(&request_json).map_err(|e| PdsError::Storage {
            reason: format!("parse parked authorization request: {e}"),
        })?;

    Ok(Some(ParkedLogin {
        core_did,
        delegate_did,
        issuer,
        token_endpoint,
        request,
        nonce,
        pkce_verifier,
        dpop_private_key,
        browser_binding,
    }))
}

/// Drop every sign-in whose window has closed.
///
/// Called from the daily sweep in [`crate::gc`]. [`take`] already removes the
/// row it reads, so this only ever collects flows that were abandoned -- the
/// browser closed, the delegate changed their mind -- which is exactly the
/// case where a private DPoP key would otherwise sit in the table forever.
///
/// # Errors
///
/// [`PdsError::Storage`] on delete failure.
pub async fn purge_expired(pool: &AccountPool) -> PdsResult<u64> {
    let now = chrono::Utc::now().to_rfc3339();
    match pool.kind() {
        #[cfg(feature = "sqlite")]
        AccountPoolKind::Sqlite => sqlx::query("DELETE FROM delegation_login WHERE expires_at < ?")
            .bind(&now)
            .execute(pool.as_sqlite())
            .await
            .map(|r| r.rows_affected()),
        #[cfg(feature = "postgres")]
        AccountPoolKind::Postgres => {
            sqlx::query("DELETE FROM delegation_login WHERE expires_at < $1")
                .bind(&now)
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
        reason: format!("purge delegated logins: {e}"),
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
        .bind("core.example")
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

    fn a_login() -> ParkedLogin {
        ParkedLogin {
            core_did: "did:plc:core".to_string(),
            delegate_did: "did:plc:alice".to_string(),
            issuer: "https://delegate.example".to_string(),
            token_endpoint: "https://delegate.example/oauth/token".to_string(),
            request: OAuthRequest {
                client_id: "https://app.example/client-metadata.json".to_string(),
                redirect_uri: "https://app.example/callback".to_string(),
                scope: "atproto transition:generic".to_string(),
                state: "client-state".to_string(),
                code_challenge: "challenge".to_string(),
                code_challenge_method: "S256".to_string(),
                dpop_jkt: Some("thumbprint".to_string()),
                login_hint: Some("core.example".to_string()),
                created_at: Utc::now(),
            },
            nonce: "nonce".to_string(),
            pkce_verifier: "verifier".to_string(),
            dpop_private_key: "deadbeef".to_string(),
            browser_binding: binding_id("the-cookie-value"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_parked_login_comes_back_with_its_request_intact() {
        let pool = pool_with_account("did:plc:core").await;
        park(&pool, "our-state", &a_login()).await.unwrap();

        let found = take(&pool, "our-state").await.unwrap().expect("login");
        assert_eq!(found.core_did, "did:plc:core");
        assert_eq!(found.delegate_did, "did:plc:alice");
        assert_eq!(found.issuer, "https://delegate.example");
        assert_eq!(found.token_endpoint, "https://delegate.example/oauth/token");
        assert_eq!(found.pkce_verifier, "verifier");
        assert_eq!(found.dpop_private_key, "deadbeef");
        // The hash, and nothing that could be replayed as the cookie itself.
        assert_eq!(found.browser_binding, binding_id("the-cookie-value"));
        assert_ne!(found.browser_binding, "the-cookie-value");
        // The parked request is the whole point: what comes back has to be
        // what the client pushed, or the code issued at the end authorizes
        // something else.
        assert_eq!(found.request.scope, "atproto transition:generic");
        assert_eq!(found.request.state, "client-state");
        assert_eq!(found.request.redirect_uri, "https://app.example/callback");
        assert_eq!(found.request.dpop_jkt.as_deref(), Some("thumbprint"));
    }

    /// A callback that arrives twice must find the flow gone the second time.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_parked_login_is_single_use() {
        let pool = pool_with_account("did:plc:core").await;
        park(&pool, "our-state", &a_login()).await.unwrap();

        assert!(take(&pool, "our-state").await.unwrap().is_some());
        assert!(
            take(&pool, "our-state").await.unwrap().is_none(),
            "a delegated sign-in survived being completed"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unknown_state_resolves_to_nothing() {
        let pool = pool_with_account("did:plc:core").await;
        assert!(take(&pool, "never-issued").await.unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_expired_login_does_not_complete_and_leaves_no_row() {
        let pool = pool_with_account("did:plc:core").await;
        park(&pool, "our-state", &a_login()).await.unwrap();
        sqlx::query("UPDATE delegation_login SET expires_at = ? WHERE state = ?")
            .bind((Utc::now() - chrono::Duration::minutes(1)).to_rfc3339())
            .bind("our-state")
            .execute(pool.as_sqlite())
            .await
            .unwrap();

        assert!(take(&pool, "our-state").await.unwrap().is_none());

        let remaining: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM delegation_login")
            .fetch_one(pool.as_sqlite())
            .await
            .unwrap();
        assert_eq!(remaining.0, 0, "an expired flow left its DPoP key behind");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_sweep_collects_abandoned_flows_and_leaves_live_ones() {
        let pool = pool_with_account("did:plc:core").await;
        park(&pool, "abandoned", &a_login()).await.unwrap();
        park(&pool, "live", &a_login()).await.unwrap();
        sqlx::query("UPDATE delegation_login SET expires_at = ? WHERE state = ?")
            .bind((Utc::now() - chrono::Duration::hours(1)).to_rfc3339())
            .bind("abandoned")
            .execute(pool.as_sqlite())
            .await
            .unwrap();

        assert_eq!(purge_expired(&pool).await.unwrap(), 1);
        assert!(take(&pool, "live").await.unwrap().is_some());
    }
}
