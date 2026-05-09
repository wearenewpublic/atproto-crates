//! `MemberGrant` and `SpaceCredential` JWTs.
//!
//!  a syncing app obtains a
//! `SpaceCredential` via a two-step flow:
//!
//! 1. App with OAuth on a member's PDS calls `getMemberGrant {space, clientId}`.
//!    The member's PDS returns a `MemberGrant` JWT signed with the member's
//!    atproto signing key, scoped to `clientId`, `aud=owner_did`,
//!    `lxm=com.atproto.space.getSpaceCredential`. ~5 minute TTL.
//! 2. App calls `getSpaceCredential {grant}` against the owner's PDS. Owner
//!    verifies the grant (resolving member's DID doc, checking signature,
//!    `lxm`, `clientId`, expiration), then mints a `SpaceCredential` JWT
//!    signed with the owner's atproto signing key. 2–4h TTL (default 3h).
//!
//! Both JWTs use the same compact-form encoding: `b64url(header).b64url(payload).b64url(sig)`,
//! signed with ECDSA over the user's atproto signing key (P-256 → ES256, K-256 → ES256K).

use crate::errors::{SpaceError, SpaceResult};
use crate::types::SpaceUri;
use atproto_identity::key::{KeyData, sign as identity_sign, validate as identity_validate};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// `typ` header value for MemberGrant.
pub const TYP_MEMBER_GRANT: &str = "space_member_grant";

/// `typ` header value for SpaceCredential.
pub const TYP_SPACE_CREDENTIAL: &str = "space_credential";

/// `lxm` value required on MemberGrant for use at `getSpaceCredential`.
pub const LXM_GET_SPACE_CREDENTIAL: &str = "com.atproto.space.getSpaceCredential";

/// MemberGrant default TTL: 5 minutes.
pub const MEMBER_GRANT_TTL_SECS: u64 = 300;

/// SpaceCredential default TTL: 3 hours (within spec's 2–4h window).
pub const SPACE_CREDENTIAL_TTL_SECS: u64 = 10800;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

/// Decoded MemberGrant payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberGrant {
    /// Issuer DID — the member.
    pub iss: String,
    /// Audience DID — the space owner.
    pub aud: String,
    /// Space URI.
    pub space: String,
    /// OAuth `client_id` of the requesting app.
    #[serde(rename = "clientId")]
    pub client_id: String,
    /// Lexicon method this grant is good for.
    pub lxm: String,
    /// Issued-at timestamp (seconds since epoch).
    pub iat: u64,
    /// Expiration timestamp (seconds since epoch).
    pub exp: u64,
}

/// Decoded SpaceCredential payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceCredential {
    /// Issuer DID — the space owner.
    pub iss: String,
    /// Space URI.
    pub space: String,
    /// OAuth `client_id` the credential is bound to.
    #[serde(rename = "clientId")]
    pub client_id: String,
    /// Issued-at timestamp.
    pub iat: u64,
    /// Expiration timestamp.
    pub exp: u64,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Re-export of the shared `jws_alg` helper. Keeps existing call sites
/// inside this module unchanged when they delegate via the alias.
fn jws_alg(key: &KeyData) -> &'static str {
    atproto_identity::key::jws_alg(key)
}

fn b64url_encode(bytes: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_decode(s: &str) -> SpaceResult<Vec<u8>> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|e| SpaceError::JwtDecoding {
            reason: format!("base64: {}", e),
        })
}

fn mint_jwt<P: Serialize>(typ: &str, payload: &P, signing_key: &KeyData) -> SpaceResult<String> {
    let header = JwtHeader {
        alg: jws_alg(signing_key).to_string(),
        typ: typ.to_string(),
    };
    let header_json = serde_json::to_vec(&header).map_err(|e| SpaceError::JwtEncoding {
        reason: e.to_string(),
    })?;
    let payload_json = serde_json::to_vec(payload).map_err(|e| SpaceError::JwtEncoding {
        reason: e.to_string(),
    })?;
    let signing_input = format!(
        "{}.{}",
        b64url_encode(&header_json),
        b64url_encode(&payload_json)
    );
    let sig = identity_sign(signing_key, signing_input.as_bytes()).map_err(|e| {
        SpaceError::Signature {
            reason: e.to_string(),
        }
    })?;
    Ok(format!("{}.{}", signing_input, b64url_encode(&sig)))
}

fn verify_jwt<P: for<'de> Deserialize<'de>>(
    token: &str,
    expected_typ: &str,
    verifying_key: &KeyData,
) -> SpaceResult<P> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(SpaceError::JwtDecoding {
            reason: "expected three '.'-separated parts".to_string(),
        });
    }
    let header_bytes = b64url_decode(parts[0])?;
    let header: JwtHeader =
        serde_json::from_slice(&header_bytes).map_err(|e| SpaceError::JwtDecoding {
            reason: format!("header json: {}", e),
        })?;

    if header.typ != expected_typ {
        return Err(SpaceError::JwtClaimMismatch {
            field: "typ".to_string(),
            expected: expected_typ.to_string(),
            actual: header.typ,
        });
    }
    let expected_alg = jws_alg(verifying_key);
    if header.alg != expected_alg {
        return Err(SpaceError::JwtClaimMismatch {
            field: "alg".to_string(),
            expected: expected_alg.to_string(),
            actual: header.alg,
        });
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = b64url_decode(parts[2])?;
    identity_validate(verifying_key, &sig, signing_input.as_bytes())
        .map_err(|_| SpaceError::JwtSignatureInvalid)?;

    let payload_bytes = b64url_decode(parts[1])?;
    let payload: P =
        serde_json::from_slice(&payload_bytes).map_err(|e| SpaceError::JwtDecoding {
            reason: format!("payload json: {}", e),
        })?;
    Ok(payload)
}

fn check_exp(exp: u64) -> SpaceResult<()> {
    let now = now_secs();
    if exp <= now {
        return Err(SpaceError::JwtExpired { exp, now });
    }
    Ok(())
}

/// Mint a MemberGrant signed by the member's atproto signing key.
///
/// # Errors
///
/// Returns [`SpaceError::JwtEncoding`] / [`SpaceError::Signature`] on failure.
pub fn create_member_grant(
    member_did: &str,
    owner_did: &str,
    space: &SpaceUri,
    client_id: &str,
    member_signing_key: &KeyData,
    ttl_secs: u64,
) -> SpaceResult<String> {
    let iat = now_secs();
    let exp = iat + ttl_secs;
    let payload = MemberGrant {
        iss: member_did.to_string(),
        aud: owner_did.to_string(),
        space: space.to_string(),
        client_id: client_id.to_string(),
        lxm: LXM_GET_SPACE_CREDENTIAL.to_string(),
        iat,
        exp,
    };
    mint_jwt(TYP_MEMBER_GRANT, &payload, member_signing_key)
}

/// Verify a MemberGrant against the member's verifying key and expected claims.
///
/// Checks: signature, `typ`, `alg`, `aud=owner_did`, `space`, `lxm`, `clientId`, `exp`.
///
/// # Errors
///
/// Returns the relevant `SpaceError` on any check failure.
pub fn verify_member_grant(
    token: &str,
    expected_owner_did: &str,
    expected_space: &SpaceUri,
    expected_client_id: &str,
    member_verifying_key: &KeyData,
) -> SpaceResult<MemberGrant> {
    let payload: MemberGrant = verify_jwt(token, TYP_MEMBER_GRANT, member_verifying_key)?;

    if payload.aud != expected_owner_did {
        return Err(SpaceError::JwtClaimMismatch {
            field: "aud".to_string(),
            expected: expected_owner_did.to_string(),
            actual: payload.aud,
        });
    }
    let expected_space_str = expected_space.to_string();
    if payload.space != expected_space_str {
        return Err(SpaceError::JwtClaimMismatch {
            field: "space".to_string(),
            expected: expected_space_str,
            actual: payload.space,
        });
    }
    if payload.lxm != LXM_GET_SPACE_CREDENTIAL {
        return Err(SpaceError::JwtClaimMismatch {
            field: "lxm".to_string(),
            expected: LXM_GET_SPACE_CREDENTIAL.to_string(),
            actual: payload.lxm,
        });
    }
    if payload.client_id != expected_client_id {
        return Err(SpaceError::JwtClaimMismatch {
            field: "clientId".to_string(),
            expected: expected_client_id.to_string(),
            actual: payload.client_id,
        });
    }
    check_exp(payload.exp)?;
    Ok(payload)
}

/// Mint a SpaceCredential signed by the space owner's atproto signing key.
pub fn create_space_credential(
    owner_did: &str,
    space: &SpaceUri,
    client_id: &str,
    owner_signing_key: &KeyData,
    ttl_secs: u64,
) -> SpaceResult<String> {
    let iat = now_secs();
    let exp = iat + ttl_secs;
    let payload = SpaceCredential {
        iss: owner_did.to_string(),
        space: space.to_string(),
        client_id: client_id.to_string(),
        iat,
        exp,
    };
    mint_jwt(TYP_SPACE_CREDENTIAL, &payload, owner_signing_key)
}

/// Verify a SpaceCredential against the owner's verifying key and expected claims.
pub fn verify_space_credential(
    token: &str,
    expected_owner_did: &str,
    expected_space: &SpaceUri,
    owner_verifying_key: &KeyData,
) -> SpaceResult<SpaceCredential> {
    let payload: SpaceCredential = verify_jwt(token, TYP_SPACE_CREDENTIAL, owner_verifying_key)?;

    if payload.iss != expected_owner_did {
        return Err(SpaceError::JwtClaimMismatch {
            field: "iss".to_string(),
            expected: expected_owner_did.to_string(),
            actual: payload.iss,
        });
    }
    let expected_space_str = expected_space.to_string();
    if payload.space != expected_space_str {
        return Err(SpaceError::JwtClaimMismatch {
            field: "space".to_string(),
            expected: expected_space_str,
            actual: payload.space,
        });
    }
    check_exp(payload.exp)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SpaceKey, SpaceType};
    use atproto_identity::key::{KeyType, generate_key, to_public};

    fn test_space() -> SpaceUri {
        SpaceUri::new(
            "did:plc:owner".to_string(),
            SpaceType::new("app.bsky.group").unwrap(),
            SpaceKey::new("default").unwrap(),
        )
    }

    fn keypair() -> (KeyData, KeyData) {
        let private = generate_key(KeyType::P256Private).unwrap();
        let public = to_public(&private).unwrap();
        (private, public)
    }

    #[test]
    fn member_grant_round_trip() {
        let (member_priv, member_pub) = keypair();
        let space = test_space();
        let token = create_member_grant(
            "did:plc:alice",
            "did:plc:owner",
            &space,
            "https://app.example/client-metadata.json",
            &member_priv,
            MEMBER_GRANT_TTL_SECS,
        )
        .unwrap();

        let payload = verify_member_grant(
            &token,
            "did:plc:owner",
            &space,
            "https://app.example/client-metadata.json",
            &member_pub,
        )
        .unwrap();
        assert_eq!(payload.iss, "did:plc:alice");
        assert_eq!(payload.aud, "did:plc:owner");
    }

    #[test]
    fn member_grant_wrong_aud_rejected() {
        let (member_priv, member_pub) = keypair();
        let space = test_space();
        let token = create_member_grant(
            "did:plc:alice",
            "did:plc:owner",
            &space,
            "client",
            &member_priv,
            MEMBER_GRANT_TTL_SECS,
        )
        .unwrap();
        let result =
            verify_member_grant(&token, "did:plc:other-owner", &space, "client", &member_pub);
        assert!(matches!(result, Err(SpaceError::JwtClaimMismatch { .. })));
    }

    #[test]
    fn member_grant_wrong_client_rejected() {
        let (member_priv, member_pub) = keypair();
        let space = test_space();
        let token = create_member_grant(
            "did:plc:alice",
            "did:plc:owner",
            &space,
            "client-A",
            &member_priv,
            MEMBER_GRANT_TTL_SECS,
        )
        .unwrap();
        let result = verify_member_grant(&token, "did:plc:owner", &space, "client-B", &member_pub);
        assert!(matches!(result, Err(SpaceError::JwtClaimMismatch { .. })));
    }

    #[test]
    fn member_grant_expired_rejected() {
        let (member_priv, member_pub) = keypair();
        let space = test_space();
        let token = create_member_grant(
            "did:plc:alice",
            "did:plc:owner",
            &space,
            "client",
            &member_priv,
            0,
        )
        .unwrap();
        // Sleep one second to force expiration.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let result = verify_member_grant(&token, "did:plc:owner", &space, "client", &member_pub);
        assert!(matches!(result, Err(SpaceError::JwtExpired { .. })));
    }

    #[test]
    fn member_grant_tampered_payload_rejected() {
        let (member_priv, member_pub) = keypair();
        let space = test_space();
        let token = create_member_grant(
            "did:plc:alice",
            "did:plc:owner",
            &space,
            "client",
            &member_priv,
            MEMBER_GRANT_TTL_SECS,
        )
        .unwrap();
        // Flip a character in the payload portion.
        let mut parts: Vec<String> = token.split('.').map(String::from).collect();
        parts[1] = parts[1].chars().rev().collect::<String>();
        let tampered = parts.join(".");
        let result = verify_member_grant(&tampered, "did:plc:owner", &space, "client", &member_pub);
        assert!(result.is_err());
    }

    #[test]
    fn space_credential_round_trip() {
        let (owner_priv, owner_pub) = keypair();
        let space = test_space();
        let token = create_space_credential(
            "did:plc:owner",
            &space,
            "client",
            &owner_priv,
            SPACE_CREDENTIAL_TTL_SECS,
        )
        .unwrap();
        let payload = verify_space_credential(&token, "did:plc:owner", &space, &owner_pub).unwrap();
        assert_eq!(payload.iss, "did:plc:owner");
    }

    #[test]
    fn space_credential_wrong_space_rejected() {
        let (owner_priv, owner_pub) = keypair();
        let space = test_space();
        let other_space = SpaceUri::new(
            "did:plc:owner".to_string(),
            SpaceType::new("app.bsky.group").unwrap(),
            SpaceKey::new("other").unwrap(),
        );
        let token = create_space_credential(
            "did:plc:owner",
            &space,
            "client",
            &owner_priv,
            SPACE_CREDENTIAL_TTL_SECS,
        )
        .unwrap();
        let result = verify_space_credential(&token, "did:plc:owner", &other_space, &owner_pub);
        assert!(matches!(result, Err(SpaceError::JwtClaimMismatch { .. })));
    }
}
