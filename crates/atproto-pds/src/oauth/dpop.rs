//! DPoP (Demonstrating Proof-of-Possession) verification middleware.
//!
//! Per [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449), every
//! DPoP-bound access token must be presented along with a single-use DPoP
//! proof JWT in the `DPoP` request header. The proof:
//!
//! - Is signed by the same key whose JWK thumbprint is bound to the access
//!   token's `cnf.jkt`.
//! - Carries `htm` (HTTP method), `htu` (request URL), `iat` (issuance
//!   timestamp; ≤ 60s old), and `jti` (single-use nonce).
//! - For resource requests, includes `ath` = `base64url(SHA-256(access_token))`.
//!
//! This module provides a single helper, [`verify_dpop_proof`], that unwraps
//! the `DPoP` header against an `OAuthClaims` `cnf.jkt` and the JTI replay
//! guard. Return on success: `()`. Returns [`XrpcError`] with a 401
//! `InvalidDpopProof` on any mismatch.
//!
//! Bind-only (no proof) tokens — those without a `cnf.jkt` — are accepted
//! unchanged so app-password / refresh paths that don't use DPoP still work.

use crate::http::errors::XrpcError;
use crate::oauth::token::OAuthClaims;
use crate::security::JtiReplayGuard;
use atproto_oauth::dpop::{DpopValidationConfig, validate_dpop_jwt};
use axum::http::StatusCode;
use axum::http::header::HeaderMap;
use std::time::Duration;

/// HTTP header carrying the DPoP proof JWT.
pub const DPOP_HEADER: &str = "DPoP";

/// DPoP proof max-age (seconds). RFC 9449 recommends ~60s.
pub const DPOP_MAX_AGE_SECS: u64 = 60;

/// Verify the DPoP proof against the OAuth access token's `cnf.jkt` binding.
///
/// - When `claims.cnf.jkt` is `None`, no proof is required (legacy / app-password path).
/// - Otherwise the `DPoP` header MUST be present, MUST verify against the
///   bound thumbprint, and the proof's `jti` is recorded in the replay guard.
///
/// `htm` is the HTTP method (e.g. `"POST"`); `htu` is the canonical request
/// URL (scheme + host + path; query/fragment stripped per RFC 9449 §4.2).
/// `access_token` is the raw bearer string the proof must `ath`-bind to.
pub async fn verify_dpop_proof(
    headers: &HeaderMap,
    claims: &OAuthClaims,
    htm: &str,
    htu: &str,
    access_token: &str,
    jti_guard: &JtiReplayGuard,
) -> Result<(), XrpcError> {
    let bound_jkt = match claims.cnf.as_ref().map(|c| &c.jkt) {
        Some(jkt) => jkt.clone(),
        None => return Ok(()),
    };
    let proof = headers.get(DPOP_HEADER).ok_or_else(|| {
        XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "InvalidDpopProof",
            "missing DPoP header",
        )
    })?;
    let proof = proof.to_str().map_err(|_| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidDpopProof",
            "DPoP header is not valid UTF-8",
        )
    })?;

    let mut config = DpopValidationConfig::for_resource_request(htm, htu, access_token);
    config.max_age_seconds = DPOP_MAX_AGE_SECS;
    let proof_jkt = validate_dpop_jwt(proof, &config).map_err(|e| {
        XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "InvalidDpopProof",
            format!("DPoP proof invalid: {e}"),
        )
    })?;

    if proof_jkt != bound_jkt {
        return Err(XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "InvalidDpopProof",
            format!("DPoP key thumbprint mismatch: bound={bound_jkt}, proof={proof_jkt}"),
        ));
    }

    // Record the proof's jti for replay-protection (single-use per RFC 9449).
    let jti = extract_jti(proof).ok_or_else(|| {
        XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "InvalidDpopProof",
            "DPoP proof missing jti",
        )
    })?;
    jti_guard
        .check_and_insert(&jti, Duration::from_secs(DPOP_MAX_AGE_SECS * 2))
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::UNAUTHORIZED,
                "InvalidDpopProof",
                format!("DPoP proof replay: {e}"),
            )
        })?;

    Ok(())
}

/// Verify a DPoP proof presented at the token endpoint and return its JWK
/// thumbprint.
///
/// Distinct from [`verify_dpop_proof`] in two ways that matter. There is no
/// access token yet, so the proof carries no `ath` claim (RFC 9449 §5) and the
/// validator must not demand one. And there is no bound thumbprint to compare
/// against — the thumbprint is the *output*, to be checked by the caller
/// against whatever the authorization request pinned, and then written into the
/// issued token's `cnf`.
///
/// Taking the thumbprint from a signed proof rather than from a request
/// parameter is the point: a `dpop_jkt` in the request body is an assertion by
/// whoever sent the request, which anyone holding a stolen code can make. A
/// proof is a demonstration that the sender holds the private key.
///
/// # Errors
///
/// Returns a 400 `invalid_dpop_proof` when the header is missing, malformed,
/// fails validation, or replays a previously seen `jti`. The token endpoint
/// uses OAuth-style error codes rather than the XRPC-style names used on
/// resource requests.
pub async fn verify_token_endpoint_dpop(
    headers: &HeaderMap,
    htu: &str,
    jti_guard: &JtiReplayGuard,
) -> Result<String, XrpcError> {
    let invalid =
        |message: String| XrpcError::new(StatusCode::BAD_REQUEST, "invalid_dpop_proof", message);

    let proof = headers
        .get(DPOP_HEADER)
        .ok_or_else(|| invalid("missing DPoP header".to_string()))?
        .to_str()
        .map_err(|_| invalid("DPoP header is not valid UTF-8".to_string()))?;

    let mut config = DpopValidationConfig::for_authorization("POST", htu);
    config.max_age_seconds = DPOP_MAX_AGE_SECS;
    let jkt = validate_dpop_jwt(proof, &config)
        .map_err(|e| invalid(format!("DPoP proof invalid: {e}")))?;

    let jti = extract_jti(proof).ok_or_else(|| invalid("DPoP proof missing jti".to_string()))?;
    jti_guard
        .check_and_insert(&jti, Duration::from_secs(DPOP_MAX_AGE_SECS * 2))
        .await
        .map_err(|e| invalid(format!("DPoP proof replay: {e}")))?;

    Ok(jkt)
}

/// Decode the `jti` claim from a DPoP proof's payload (no signature check —
/// the caller has already done that via `validate_dpop_jwt`).
fn extract_jti(proof: &str) -> Option<String> {
    use base64::{Engine as _, engine::general_purpose};
    let payload_b64 = proof.split('.').nth(1)?;
    let payload_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64.as_bytes())
        .ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    payload.get("jti")?.as_str().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_jti_pulls_value() {
        use base64::{Engine as _, engine::general_purpose};
        let payload = serde_json::json!({"jti": "abc123", "htm": "POST"});
        let payload_b64 =
            general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let proof = format!("header.{}.signature", payload_b64);
        assert_eq!(extract_jti(&proof), Some("abc123".to_string()));
    }

    #[test]
    fn extract_jti_returns_none_for_malformed() {
        assert_eq!(extract_jti("not.a.jwt"), None);
        assert_eq!(extract_jti(""), None);
        assert_eq!(extract_jti("a.b"), None);
    }
}
