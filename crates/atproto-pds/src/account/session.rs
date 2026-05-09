//! App-password session JWTs.
//!
//! app-password sessions
//! are HMAC-signed JWTs issued by `createSession`, refreshable via
//! `refreshSession`. Distinct from OAuth — these tokens are
//! symmetric-keyed by `PDS_JWT_SECRET`, scoped to one DID + one
//! app-password id, with a short access TTL and longer refresh TTL.
//!
//! Wire format: standard compact JWT (`b64url(header).b64url(payload).b64url(sig)`),
//! `alg: HS256`, `typ: JWT`.

use crate::errors::{PdsError, PdsResult};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Default access-token TTL: 2 hours.
pub const DEFAULT_ACCESS_TTL_SECS: u64 = 7200;

/// Default refresh-token TTL: 90 days.
pub const DEFAULT_REFRESH_TTL_SECS: u64 = 7_776_000;

/// `typ` for an app-password access token.
pub const TYP_ACCESS: &str = "at-pp-access";

/// `typ` for an app-password refresh token.
pub const TYP_REFRESH: &str = "at-pp-refresh";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

/// Decoded app-password session payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionClaims {
    /// Subject — the account DID.
    pub sub: String,
    /// Issuer — the PDS service DID.
    pub iss: String,
    /// App-password row id.
    pub apw: String,
    /// `true` if this session can access privileged endpoints.
    pub privileged: bool,
    /// Issued-at (seconds since epoch).
    pub iat: u64,
    /// Expiration (seconds since epoch).
    pub exp: u64,
    /// JWT identifier (random 16-byte hex).
    pub jti: String,
}

/// A minted session pair: access + refresh tokens.
#[derive(Debug, Clone)]
pub struct SessionTokens {
    /// Compact JWT for normal API access.
    pub access_jwt: String,
    /// Compact JWT for refreshing.
    pub refresh_jwt: String,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn random_jti() -> String {
    let mut bytes = [0u8; 16];
    use rand::RngExt;
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

fn mint(typ: &str, claims: &SessionClaims, secret: &[u8]) -> PdsResult<String> {
    let header = JwtHeader {
        alg: "HS256".to_string(),
        typ: typ.to_string(),
    };
    let header_json = serde_json::to_vec(&header).map_err(|e| PdsError::Storage {
        reason: format!("session header: {e}"),
    })?;
    let payload_json = serde_json::to_vec(claims).map_err(|e| PdsError::Storage {
        reason: format!("session payload: {e}"),
    })?;
    let signing_input = format!(
        "{}.{}",
        B64URL.encode(&header_json),
        B64URL.encode(&payload_json)
    );
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(secret).map_err(|e| PdsError::Storage {
            reason: format!("HMAC key: {e}"),
        })?;
    mac.update(signing_input.as_bytes());
    let sig = mac.finalize().into_bytes();
    Ok(format!("{}.{}", signing_input, B64URL.encode(sig)))
}

fn verify(token: &str, expected_typ: &str, secret: &[u8]) -> PdsResult<SessionClaims> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(PdsError::AuthDenied {
            reason: "malformed JWT".to_string(),
        });
    }
    let header_bytes = B64URL.decode(parts[0]).map_err(|e| PdsError::AuthDenied {
        reason: format!("header b64: {e}"),
    })?;
    let header: JwtHeader =
        serde_json::from_slice(&header_bytes).map_err(|e| PdsError::AuthDenied {
            reason: format!("header json: {e}"),
        })?;
    if header.alg != "HS256" {
        return Err(PdsError::AuthDenied {
            reason: format!("unsupported alg: {}", header.alg),
        });
    }
    if header.typ != expected_typ {
        return Err(PdsError::AuthDenied {
            reason: format!("expected typ {expected_typ}, got {}", header.typ),
        });
    }
    // Re-MAC and constant-time compare.
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(secret).map_err(|e| PdsError::Storage {
            reason: format!("HMAC key: {e}"),
        })?;
    mac.update(signing_input.as_bytes());
    let sig_bytes = B64URL.decode(parts[2]).map_err(|e| PdsError::AuthDenied {
        reason: format!("sig b64: {e}"),
    })?;
    mac.verify_slice(&sig_bytes)
        .map_err(|_| PdsError::AuthDenied {
            reason: "signature mismatch".to_string(),
        })?;
    let payload_bytes = B64URL.decode(parts[1]).map_err(|e| PdsError::AuthDenied {
        reason: format!("payload b64: {e}"),
    })?;
    let claims: SessionClaims =
        serde_json::from_slice(&payload_bytes).map_err(|e| PdsError::AuthDenied {
            reason: format!("payload json: {e}"),
        })?;
    if claims.exp <= now_secs() {
        return Err(PdsError::AuthDenied {
            reason: "token expired".to_string(),
        });
    }
    Ok(claims)
}

/// Issue an access+refresh token pair for a freshly-validated app-password sign-in.
///
/// `service_did` is the PDS's own DID (e.g., `did:web:pds.example.com`).
/// `secret` is the symmetric `PDS_JWT_SECRET` (length-flexible; HS256 uses any byte string).
pub fn issue_pair(
    service_did: &str,
    account_did: &str,
    app_password_id: &str,
    privileged: bool,
    secret: &[u8],
    access_ttl_secs: u64,
    refresh_ttl_secs: u64,
) -> PdsResult<SessionTokens> {
    let iat = now_secs();
    let common = SessionClaims {
        sub: account_did.to_string(),
        iss: service_did.to_string(),
        apw: app_password_id.to_string(),
        privileged,
        iat,
        exp: iat + access_ttl_secs,
        jti: random_jti(),
    };
    let access_jwt = mint(TYP_ACCESS, &common, secret)?;
    let refresh_claims = SessionClaims {
        exp: iat + refresh_ttl_secs,
        jti: random_jti(),
        ..common.clone()
    };
    let refresh_jwt = mint(TYP_REFRESH, &refresh_claims, secret)?;
    Ok(SessionTokens {
        access_jwt,
        refresh_jwt,
    })
}

/// Verify an access JWT and return its claims.
pub fn verify_access(token: &str, secret: &[u8]) -> PdsResult<SessionClaims> {
    verify(token, TYP_ACCESS, secret)
}

/// Verify a refresh JWT and return its claims.
pub fn verify_refresh(token: &str, secret: &[u8]) -> PdsResult<SessionClaims> {
    verify(token, TYP_REFRESH, secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> &'static [u8] {
        b"test-secret-do-not-use-in-prod-32bytes!"
    }

    #[test]
    fn round_trip_access_token() {
        let pair = issue_pair(
            "did:web:pds.example",
            "did:plc:alice",
            "ap-1",
            false,
            secret(),
            DEFAULT_ACCESS_TTL_SECS,
            DEFAULT_REFRESH_TTL_SECS,
        )
        .unwrap();
        let claims = verify_access(&pair.access_jwt, secret()).unwrap();
        assert_eq!(claims.sub, "did:plc:alice");
        assert_eq!(claims.apw, "ap-1");
        assert!(!claims.privileged);
    }

    #[test]
    fn refresh_token_distinct_from_access() {
        let pair = issue_pair(
            "did:web:pds.example",
            "did:plc:alice",
            "ap-1",
            true,
            secret(),
            DEFAULT_ACCESS_TTL_SECS,
            DEFAULT_REFRESH_TTL_SECS,
        )
        .unwrap();
        assert_ne!(pair.access_jwt, pair.refresh_jwt);
        let r = verify_refresh(&pair.refresh_jwt, secret()).unwrap();
        assert_eq!(r.sub, "did:plc:alice");
        // Refresh has longer expiration.
        let a = verify_access(&pair.access_jwt, secret()).unwrap();
        assert!(r.exp > a.exp);
    }

    #[test]
    fn access_jwt_rejected_as_refresh_and_vice_versa() {
        let pair = issue_pair(
            "did:web:pds.example",
            "did:plc:alice",
            "ap-1",
            false,
            secret(),
            DEFAULT_ACCESS_TTL_SECS,
            DEFAULT_REFRESH_TTL_SECS,
        )
        .unwrap();
        assert!(verify_access(&pair.refresh_jwt, secret()).is_err());
        assert!(verify_refresh(&pair.access_jwt, secret()).is_err());
    }

    #[test]
    fn wrong_secret_rejected() {
        let pair = issue_pair(
            "did:web:pds.example",
            "did:plc:alice",
            "ap-1",
            false,
            secret(),
            DEFAULT_ACCESS_TTL_SECS,
            DEFAULT_REFRESH_TTL_SECS,
        )
        .unwrap();
        assert!(verify_access(&pair.access_jwt, b"different-secret").is_err());
    }

    #[test]
    fn expired_token_rejected() {
        let pair = issue_pair(
            "did:web:pds.example",
            "did:plc:alice",
            "ap-1",
            false,
            secret(),
            0, // immediate expiration
            DEFAULT_REFRESH_TTL_SECS,
        )
        .unwrap();
        // Sleep past expiration — exp is now-secs which already lapses with TTL=0.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(verify_access(&pair.access_jwt, secret()).is_err());
    }

    #[test]
    fn malformed_jwt_rejected() {
        assert!(verify_access("not.a.jwt", secret()).is_err());
        assert!(verify_access("not-a-jwt-at-all", secret()).is_err());
    }
}
