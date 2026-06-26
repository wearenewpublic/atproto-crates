//! Inter-PDS service-auth JWTs for the Spaces notify path.
//!
//! `notifyWrite` and `notifySpaceDeleted` are authenticated with AT Protocol
//! **service auth** (the same short-lived bearer the reference's
//! `authVerifier.serviceAuth` accepts): a compact JWS signed by the issuer's
//! `#atproto` signing key with `iss` / `aud` / `lxm` / `iat` / `exp` / `jti`
//! claims.
//!
//! This module provides:
//! - [`mint_service_auth`] — sign a service-auth JWT with a local account's
//!   private signing key (writer side, before POSTing notifyWrite to the owner
//!   PDS).
//! - [`verify_service_auth`] — verify an inbound service-auth bearer by
//!   resolving the `iss` DID document's `#atproto` key, checking the signature,
//!   `aud`, `lxm`, and `exp`.

use crate::errors::{PdsError, PdsResult};
use atproto_identity::key::{
    KeyData, identify_key, jws_alg, sign as identity_sign, validate as identity_validate,
};
use atproto_identity::model::VerificationMethod;
use base64::{Engine as _, engine::general_purpose};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// `typ` header value for service-auth JWTs.
pub const TYP_SERVICE_AUTH: &str = "at+jwt";

/// Default TTL for a minted notify service-auth token (60s).
pub const NOTIFY_SERVICE_AUTH_TTL_SECS: u64 = 60;

/// Service-auth JWT header.
#[derive(Debug, Serialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

/// Service-auth JWT claims. `iss`/`aud` are DIDs; `lxm` scopes the token to a
/// single XRPC method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAuthClaims {
    /// Issuer DID (the signer).
    pub iss: String,
    /// Audience DID (the receiving service).
    pub aud: String,
    /// NSID of the lexicon method this token is scoped to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lxm: Option<String>,
    /// Issued-at (epoch seconds).
    pub iat: u64,
    /// Expiry (epoch seconds).
    pub exp: u64,
    /// Random nonce.
    pub jti: String,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn b64url(bytes: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn random_jti() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    b64url(&bytes)
}

/// Mint a service-auth JWT signed by `signing_key` (a private atproto signing
/// key), bound to `iss` / `aud` / `lxm`, valid for `ttl_secs`.
///
/// # Errors
/// Returns [`PdsError::Storage`] on a JSON-encode or signing failure.
pub fn mint_service_auth(
    signing_key: &KeyData,
    iss: &str,
    aud: &str,
    lxm: &str,
    ttl_secs: u64,
) -> PdsResult<String> {
    let iat = now_secs();
    let header = JwtHeader {
        alg: jws_alg(signing_key).to_string(),
        typ: TYP_SERVICE_AUTH.to_string(),
    };
    let claims = ServiceAuthClaims {
        iss: iss.to_string(),
        aud: aud.to_string(),
        lxm: Some(lxm.to_string()),
        iat,
        exp: iat + ttl_secs,
        jti: random_jti(),
    };
    let header_bytes = serde_json::to_vec(&header).map_err(|e| PdsError::Storage {
        reason: format!("encode service-auth header: {e}"),
    })?;
    let claims_bytes = serde_json::to_vec(&claims).map_err(|e| PdsError::Storage {
        reason: format!("encode service-auth claims: {e}"),
    })?;
    let signing_input = format!("{}.{}", b64url(&header_bytes), b64url(&claims_bytes));
    let sig =
        identity_sign(signing_key, signing_input.as_bytes()).map_err(|e| PdsError::Storage {
            reason: format!("sign service-auth token: {e}"),
        })?;
    Ok(format!("{}.{}", signing_input, b64url(&sig)))
}

/// Verify an inbound service-auth `token`. Resolves the `iss` DID document's
/// `#atproto` signing key, checks the signature over `header.payload`, then
/// validates `aud == expected_aud`, `lxm == expected_lxm` (when the token
/// carries one), and `exp` in the future.
///
/// Returns the verified claims on success.
///
/// # Errors
/// Returns [`PdsError::AuthDenied`] for any verification failure (bad shape,
/// unknown issuer, bad signature, wrong audience/method, or expiry).
pub async fn verify_service_auth(
    http: &reqwest::Client,
    token: &str,
    plc_directory_hostname: Option<&str>,
    expected_aud: &str,
    expected_lxm: &str,
) -> PdsResult<ServiceAuthClaims> {
    let mut parts = token.split('.');
    let (Some(header_b64), Some(payload_b64), Some(sig_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(deny("malformed service-auth token"));
    };
    let payload_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64.as_bytes())
        .map_err(|_| deny("service-auth payload not base64url"))?;
    let claims: ServiceAuthClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|_| deny("service-auth payload not JSON"))?;

    // Claim checks before the (more expensive) DID-document resolution.
    if claims.aud != expected_aud {
        return Err(deny(&format!(
            "service-auth aud mismatch: token={}, expected={}",
            claims.aud, expected_aud
        )));
    }
    if let Some(lxm) = claims.lxm.as_deref()
        && lxm != expected_lxm
    {
        return Err(deny(&format!(
            "service-auth lxm mismatch: token={lxm}, expected={expected_lxm}"
        )));
    }
    if claims.exp <= now_secs() {
        return Err(deny("service-auth token expired"));
    }

    let key = atproto_signing_key(http, &claims.iss, plc_directory_hostname)
        .await
        .map_err(|e| deny(&format!("resolve issuer signing key: {e}")))?;
    let sig = general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64.as_bytes())
        .map_err(|_| deny("service-auth signature not base64url"))?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    identity_validate(&key, &sig, signing_input.as_bytes())
        .map_err(|_| deny("service-auth signature invalid"))?;
    Ok(claims)
}

fn deny(reason: &str) -> PdsError {
    PdsError::AuthDenied {
        reason: reason.to_string(),
    }
}

/// Resolve a DID's `#atproto` Multikey signing key via its DID document.
async fn atproto_signing_key(
    http: &reqwest::Client,
    did: &str,
    plc_directory_hostname: Option<&str>,
) -> anyhow::Result<KeyData> {
    use atproto_identity::plc::query as plc_query;
    use atproto_identity::web::query as web_query;
    let document = if did.starts_with("did:plc:") {
        let host = plc_directory_hostname.unwrap_or("plc.directory");
        plc_query(http, host, did).await?
    } else if did.starts_with("did:web:") {
        web_query(http, did).await?
    } else {
        anyhow::bail!("unsupported DID method for service-auth verification: {did}");
    };
    for method in &document.verification_method {
        if let VerificationMethod::Multikey {
            id,
            public_key_multibase,
            ..
        } = method
            && id.ends_with("#atproto")
        {
            let did_key = if public_key_multibase.starts_with("did:key:") {
                public_key_multibase.clone()
            } else {
                format!("did:key:{public_key_multibase}")
            };
            return Ok(identify_key(&did_key)?);
        }
    }
    anyhow::bail!("DID document for {did} has no #atproto Multikey verification method")
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_identity::key::{KeyType, generate_key};

    #[test]
    fn mint_then_decode_round_trip() {
        let key = generate_key(KeyType::P256Private).unwrap();
        let token = mint_service_auth(
            &key,
            "did:plc:writer",
            "did:plc:owner",
            "com.atproto.space.notifyWrite",
            60,
        )
        .unwrap();
        // 3 segments.
        assert_eq!(token.split('.').count(), 3);
        // Payload decodes with the expected claims.
        let payload_b64 = token.split('.').nth(1).unwrap();
        let bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64.as_bytes())
            .unwrap();
        let claims: ServiceAuthClaims = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(claims.iss, "did:plc:writer");
        assert_eq!(claims.aud, "did:plc:owner");
        assert_eq!(claims.lxm.as_deref(), Some("com.atproto.space.notifyWrite"));
        assert!(claims.exp > claims.iat);
    }
}
