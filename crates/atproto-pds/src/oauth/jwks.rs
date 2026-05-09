//! `/oauth/jwks` — JSON Web Key Set publication.
//!
//! Per [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) the PDS
//! publishes the public form of every key it uses to sign OAuth-adjacent
//! JWTs (service-auth tokens, future ES256K access tokens, etc.). The
//! current OAuth access/refresh tokens are HS256-signed and so do not
//! appear here, but service-auth tokens and any account-level signing keys
//! the PDS holds are surfaced via the `account.signing_key_ref` mechanism
//! (each user's atproto signing key is published via their DID document,
//! not via this JWKS).
//!
//! The PDS-level signing key (used for federation, including the upcoming
//! ES256K-signed access tokens) is configured via `PDS_OAUTH_KEY_JWK` or
//! generated at first startup and cached under the `__pds_oauth__` key in
//! the [`KeyStore`](crate::keys::KeyStore). When present, this handler
//! publishes its public form; when absent, returns an empty `keys` array
//! (RFC 7517 §5 permits this and OAuth metadata still validates).

use crate::http::state::HttpState;
use atproto_identity::key::{KeyData, to_public};
use axum::Json;
use axum::extract::State;
use elliptic_curve::JwkEcKey;
use serde::Serialize;

/// JWKS shape per RFC 7517.
#[derive(Debug, Serialize)]
pub struct Jwks {
    /// Set of published JWKs.
    pub keys: Vec<serde_json::Value>,
}

/// Handler for `GET /oauth/jwks`.
///
/// Publishes the PDS service signing key plus any rotated historical keys
/// in JWK form. The current signer (`pds_signing_key`)
/// is published first; historical signers (`pds_extra_signing_keys`) follow
/// so consumers verifying tokens issued before a rotation still find the
/// matching `kid`. Each entry includes `use=sig`, an `alg` derived from the
/// key type (`ES256` for P-256, `ES256K` for K-256, `ES384` for P-384), and
/// a `kid` (key ID) derived from the JWK thumbprint so consumers can pin.
pub async fn jwks_handler(State(state): State<HttpState>) -> Json<Jwks> {
    let mut keys: Vec<serde_json::Value> = Vec::new();
    let mut seen_kids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut publish = |key: &KeyData| match key_to_jwk_value(key) {
        Ok(value) => {
            let kid = value
                .get("kid")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if seen_kids.insert(kid) {
                keys.push(value);
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "JWKS: failed to publish a PDS signing key");
        }
    };
    if let Some(signing_key) = state.pds_signing_key.as_deref() {
        publish(signing_key);
    }
    for extra in &state.pds_extra_signing_keys {
        publish(extra.as_ref());
    }
    Json(Jwks { keys })
}

/// Convert a private/public KeyData into a JWK with `use=sig`, `alg`, `kid`.
///
/// If the input is a private key, only the public component is published.
fn key_to_jwk_value(key: &KeyData) -> Result<serde_json::Value, String> {
    let public = to_public(key).map_err(|e| format!("derive pub: {e}"))?;
    let jwk: JwkEcKey = (&public).try_into().map_err(|e| format!("to jwk: {e}"))?;
    let mut value: serde_json::Value =
        serde_json::to_value(&jwk).map_err(|e| format!("serialize jwk: {e}"))?;

    let alg = atproto_identity::key::jws_alg(&public);
    value["use"] = serde_json::Value::String("sig".to_string());
    value["alg"] = serde_json::Value::String(alg.to_string());
    value["kid"] = serde_json::Value::String(thumbprint_kid(&value));
    Ok(value)
}

/// Compute the JWK thumbprint per RFC 7638 to use as the `kid`. The
/// thumbprint is `base64url(SHA256(canonical JSON of {crv, kty, x, y}))`.
fn thumbprint_kid(jwk: &serde_json::Value) -> String {
    use base64::{Engine as _, engine::general_purpose};
    use sha2::{Digest, Sha256};
    let canonical = serde_json::json!({
        "crv": jwk.get("crv").cloned().unwrap_or(serde_json::Value::Null),
        "kty": jwk.get("kty").cloned().unwrap_or(serde_json::Value::Null),
        "x":   jwk.get("x").cloned().unwrap_or(serde_json::Value::Null),
        "y":   jwk.get("y").cloned().unwrap_or(serde_json::Value::Null),
    });
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    let digest = Sha256::digest(&bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_to_jwk_value_for_p256() {
        use atproto_identity::key::{KeyType, generate_key};
        let priv_key = generate_key(KeyType::P256Private).unwrap();
        let value = key_to_jwk_value(&priv_key).unwrap();
        assert_eq!(value["use"], "sig");
        assert_eq!(value["alg"], "ES256");
        assert!(value["kid"].as_str().unwrap().len() > 10);
        assert_eq!(value["kty"], "EC");
        assert_eq!(value["crv"], "P-256");
        // Private-component fields must NOT be present.
        assert!(value.get("d").is_none(), "JWK must publish public-only");
    }

    #[test]
    fn key_to_jwk_value_for_k256() {
        use atproto_identity::key::{KeyType, generate_key};
        let priv_key = generate_key(KeyType::K256Private).unwrap();
        let value = key_to_jwk_value(&priv_key).unwrap();
        assert_eq!(value["alg"], "ES256K");
        assert_eq!(value["crv"], "secp256k1");
    }

    #[test]
    fn thumbprint_is_url_safe_base64() {
        let v = serde_json::json!({
            "crv": "P-256",
            "kty": "EC",
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
        });
        let kid = thumbprint_kid(&v);
        assert!(!kid.contains('+'));
        assert!(!kid.contains('/'));
        assert!(!kid.contains('='));
        // SHA-256 is 32 bytes → 43 chars in url-safe base64 no-pad.
        assert_eq!(kid.len(), 43);
    }
}
