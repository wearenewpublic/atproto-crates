//! `POST /oauth/revoke` — RFC 7009 OAuth 2.0 Token Revocation.
//!
//! Per [RFC 7009 §2.1](https://datatracker.ietf.org/doc/html/rfc7009#section-2.1):
//!
//! - Accept `application/x-www-form-urlencoded` or JSON with `token` +
//!   optional `token_type_hint`.
//! - Always return 200 OK on success (even if the token is unknown — leaks
//!   no information).
//! - Successful revocation is idempotent.
//!
//! On a refresh token, drop the rotation handle from `OAuthState`. On an
//! access token, mark its `jti` in the JTI replay guard with the token's
//! remaining TTL so subsequent presentations are rejected.

use crate::http::errors::XrpcError;
use crate::http::state::HttpState;
use crate::oauth::token::{TYP_ACCESS, TYP_REFRESH, verify_oauth_jwt};
use axum::Form;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Deserialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Form-encoded inputs for `/oauth/revoke`.
#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    /// The token (refresh or access) to revoke.
    pub token: String,
    /// Optional hint: `"refresh_token"` or `"access_token"`.
    #[serde(rename = "token_type_hint")]
    pub token_type_hint: Option<String>,
}

/// `POST /oauth/revoke`.
///
/// Always returns 200 OK on completion (per RFC 7009 §2.2 — to avoid
/// leaking validity information about the token). The actual revocation
/// status is logged at `tracing::debug` for diagnostic purposes.
pub async fn revoke_handler(
    State(state): State<HttpState>,
    Form(input): Form<RevokeForm>,
) -> Result<StatusCode, XrpcError> {
    // Try the hint first, then fall back to the other shape.
    let typ_order: [&str; 2] = match input.token_type_hint.as_deref() {
        Some("access_token") => [TYP_ACCESS, TYP_REFRESH],
        _ => [TYP_REFRESH, TYP_ACCESS],
    };
    for typ in typ_order {
        if try_revoke_one(typ, &input.token, &state).await {
            return Ok(StatusCode::OK);
        }
    }
    // Unknown token: still return 200 per RFC 7009.
    tracing::debug!("revoke: token not recognized; returning 200 per RFC 7009");
    Ok(StatusCode::OK)
}

async fn try_revoke_one(typ: &str, token: &str, state: &HttpState) -> bool {
    let claims = match verify_oauth_jwt(token, typ, &state.jwt_secret) {
        Ok(c) => c,
        Err(_) => return false,
    };
    match typ {
        TYP_REFRESH => {
            let removed = state
                .oauth
                .revoke_refresh(&claims.jti)
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!(jti = %claims.jti, error = ?e, "revoke_refresh storage error");
                    false
                });
            tracing::debug!(jti = %claims.jti, removed, "revoke: refresh token");
        }
        TYP_ACCESS => {
            // Mark the access JTI as replayed for the remainder of its
            // lifetime so its bearer can no longer present it.
            let now = now_secs();
            let ttl = Duration::from_secs(claims.exp.saturating_sub(now));
            let _ = state.jti_guard.check_and_insert(&claims.jti, ttl).await;
            tracing::debug!(jti = %claims.jti, "revoke: access token marked replayed");
        }
        _ => return false,
    }
    true
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    //! Unit tests for the revoke logic. Full HTTP-roundtrip coverage lives in
    //! `tests/http_phase4_oauth.rs`; here we exercise the core path against a
    //! lightweight `OAuthState` + `JtiReplayGuard` pair so we don't need a
    //! full `HttpState` (which requires an async-opened SQLite file).

    use super::*;
    use crate::oauth::state::{OAuthState, RefreshHandle};
    use crate::oauth::token::{OAuthClaims, mint_oauth_jwt_for_test};
    use crate::security::JtiReplayGuard;

    fn jwt_secret() -> Vec<u8> {
        b"a-32-byte-test-only-jwt-secret!!".to_vec()
    }

    fn synth_claims(jti: &str, ttl_secs: u64) -> OAuthClaims {
        let now = now_secs();
        OAuthClaims {
            sub: "did:plc:alice".to_string(),
            iss: "did:web:test.example".to_string(),
            aud: "did:web:test.example".to_string(),
            client_id: "client".to_string(),
            scope: "atproto".to_string(),
            cnf: None,
            iat: now,
            exp: now + ttl_secs,
            jti: jti.to_string(),
        }
    }

    /// Stand-in for `try_revoke_one` that takes `oauth` + `jti_guard` directly
    /// rather than a full `HttpState`. This is the same logic as
    /// `try_revoke_one` would execute.
    async fn revoke_into(
        typ: &str,
        token: &str,
        oauth: &OAuthState,
        jti_guard: &JtiReplayGuard,
        secret: &[u8],
    ) -> bool {
        let claims = match crate::oauth::token::verify_oauth_jwt(token, typ, secret) {
            Ok(c) => c,
            Err(_) => return false,
        };
        match typ {
            TYP_REFRESH => {
                let _ = oauth.revoke_refresh(&claims.jti).await;
            }
            TYP_ACCESS => {
                let now = now_secs();
                let ttl = Duration::from_secs(claims.exp.saturating_sub(now));
                let _ = jti_guard.check_and_insert(&claims.jti, ttl).await;
            }
            _ => return false,
        }
        true
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unknown_token_does_not_revoke() {
        let oauth = OAuthState::new();
        let guard = JtiReplayGuard::new(64);
        let removed =
            revoke_into(TYP_REFRESH, "not-a-real-jwt", &oauth, &guard, &jwt_secret()).await;
        assert!(!removed);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn refresh_token_revoke_removes_rotation_handle() {
        let oauth = OAuthState::new();
        let guard = JtiReplayGuard::new(64);
        let secret = jwt_secret();
        let claims = synth_claims("refresh-jti-xyz", 3600);
        oauth
            .register_refresh(
                claims.jti.clone(),
                RefreshHandle {
                    did: claims.sub.clone(),
                    client_id: claims.client_id.clone(),
                    dpop_jkt: String::new(),
                    scope: claims.scope.clone(),
                    issued_at: chrono::Utc::now(),
                },
            )
            .await
            .unwrap();
        assert_eq!(oauth.refresh_count().await.unwrap(), 1);

        let token = mint_oauth_jwt_for_test(TYP_REFRESH, &claims, &secret);
        let removed = revoke_into(TYP_REFRESH, &token, &oauth, &guard, &secret).await;
        assert!(removed);
        assert_eq!(oauth.refresh_count().await.unwrap(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn access_token_revoke_blocks_replay() {
        let oauth = OAuthState::new();
        let guard = JtiReplayGuard::new(64);
        let secret = jwt_secret();
        let claims = synth_claims("access-jti-abc", 600);
        let token = mint_oauth_jwt_for_test(TYP_ACCESS, &claims, &secret);
        let removed = revoke_into(TYP_ACCESS, &token, &oauth, &guard, &secret).await;
        assert!(removed);

        // Second insert collides => replay rejected.
        let second = guard
            .check_and_insert(&claims.jti, Duration::from_secs(60))
            .await;
        assert!(second.is_err());
    }
}
