//! `DelegationToken` and `SpaceCredential` JWTs (0016 Permissioned Data).
//!
//! A syncing app obtains a `SpaceCredential` via a two-step flow, per the
//! 0016 spec "Credential flow" (README lines 232-254):
//!
//! 1. An app holding an OAuth session on a member's PDS calls
//!    [`com.atproto.space.getDelegationToken`]. The member's PDS mints a
//!    **delegation token** (spec "Delegation token", lines 147-176): a JWT with
//!    header `typ=atproto-space-delegation+jwt`, `kid="#atproto"`, signed by
//!    the member's atproto signing key. Claims: `iss` (member DID),
//!    `aud=<spaceDid>#atproto_space_host`, `sub` (the space `at://` URI),
//!    `iat`, `exp=iat+60`, `jti`. It carries no `lxm` claim and says nothing
//!    about the app. Single-use, default 60-second TTL.
//! 2. The app presents that delegation token (in the `Authorization: Bearer`
//!    header) plus an optional client attestation to the space authority at
//!    [`com.atproto.space.getSpaceCredential`]. The authority verifies it and
//!    mints a **space credential** (spec "Space credential", lines 200-230): a
//!    JWT with header `typ=atproto-space-credential+jwt`,
//!    `kid="#atproto_space"`, signed by the authority's space signing key.
//!    Claims: `iss` (authority DID), `sub` (the space `at://` URI),
//!    `client_id` (the attested app, omitted when no attestation), `iat`,
//!    `exp=iat+7200`, `jti`. It has no `aud`. Default 2-hour TTL.
//!
//! Both JWTs use the same compact-form encoding:
//! `b64url(header).b64url(payload).b64url(sig)`, signed with ECDSA over an
//! atproto signing key (P-256 → ES256, K-256 → ES256K).
//!
//! [`com.atproto.space.getDelegationToken`]: https://atproto.com
//! [`com.atproto.space.getSpaceCredential`]: https://atproto.com

use crate::errors::{SpaceError, SpaceResult};
use crate::types::SpaceUri;
use atproto_identity::key::{KeyData, sign as identity_sign, validate as identity_validate};
use base64::{Engine as _, engine::general_purpose};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// `typ` header value for a delegation token (spec line 152).
pub const TYP_DELEGATION_TOKEN: &str = "atproto-space-delegation+jwt";

/// `typ` header value for a space credential (spec line 206).
pub const TYP_SPACE_CREDENTIAL: &str = "atproto-space-credential+jwt";

/// `kid` header value a delegation token MUST carry (spec line 162).
pub const KID_DELEGATION_TOKEN: &str = "#atproto";

/// `kid` header value a space credential MUST carry (spec line 216).
pub const KID_SPACE_CREDENTIAL: &str = "#atproto_space";

/// Delegation-token default TTL: 60 seconds (spec lines 149, 169).
pub const DELEGATION_TOKEN_TTL_SECS: u64 = 60;

/// SpaceCredential default TTL: 2 hours / 7200 seconds (spec line 223).
pub const SPACE_CREDENTIAL_TTL_SECS: u64 = 7200;

/// The `aud` of a delegation token: the space host service fragment of the
/// authority DID (`<spaceDid>#atproto_space_host`, spec line 166).
#[must_use]
pub fn space_host_audience(space_did: &str) -> String {
    format!("{space_did}#atproto_space_host")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
    kid: String,
}

/// Decoded delegation-token payload (spec lines 164-171).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationToken {
    /// Issuer DID — the member (user) delegating to the app.
    pub iss: String,
    /// Audience — the space host service fragment
    /// (`<spaceDid>#atproto_space_host`).
    pub aud: String,
    /// Subject — the space being requested, an `at://…/space/…` URI.
    pub sub: String,
    /// Issued-at timestamp (seconds since epoch).
    pub iat: u64,
    /// Expiration timestamp (seconds since epoch).
    pub exp: u64,
    /// Random nonce (UUIDv4) for single-use enforcement.
    pub jti: String,
}

/// Decoded SpaceCredential payload (spec lines 218-225).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceCredential {
    /// Issuer DID — the space authority.
    pub iss: String,
    /// Subject — the space the credential reads, an `at://…/space/…` URI.
    pub sub: String,
    /// Attested application identity (the verified client attestation's
    /// `iss`). Omitted on the wire when the request carried no attestation
    /// (spec lines 221, 228).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub client_id: Option<String>,
    /// Issued-at timestamp.
    pub iat: u64,
    /// Expiration timestamp.
    pub exp: u64,
    /// Random nonce (UUIDv4).
    pub jti: String,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Generate a random UUIDv4-shaped nonce for the `jti` claim.
///
/// `jti` is an opaque nonce (it is never parsed), so we mint a v4-formatted
/// string from the OS RNG without a dedicated UUID dependency.
fn random_jti() -> String {
    let mut b = [0u8; 16];
    rand::rng().fill(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

/// Resolve the JWS `alg` header for `key`, restricted to the two algorithms
/// the spec permits in space-token headers (ES256 / ES256K, spec lines 161,
/// 215). Other key types (P-384, Ed25519) are rejected here so the minted
/// header can never carry a non-conformant `alg`.
fn space_jws_alg(key: &KeyData) -> SpaceResult<&'static str> {
    match atproto_identity::key::jws_alg(key) {
        alg @ ("ES256" | "ES256K") => Ok(alg),
        other => Err(SpaceError::Signature {
            reason: format!("space tokens require an ES256 or ES256K signing key; got alg {other}"),
        }),
    }
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

fn mint_jwt<P: Serialize>(
    typ: &str,
    kid: &str,
    payload: &P,
    signing_key: &KeyData,
) -> SpaceResult<String> {
    let header = JwtHeader {
        alg: space_jws_alg(signing_key)?.to_string(),
        typ: typ.to_string(),
        kid: kid.to_string(),
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
    expected_kid: &str,
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
    if header.kid != expected_kid {
        return Err(SpaceError::JwtClaimMismatch {
            field: "kid".to_string(),
            expected: expected_kid.to_string(),
            actual: header.kid,
        });
    }
    let expected_alg = space_jws_alg(verifying_key)?;
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

/// Mint a delegation token signed by the member's atproto signing key.
///
/// The token's `aud` is set to the space host service fragment
/// (`<spaceDid>#atproto_space_host`) and `sub` to the space `at://` URI, per
/// spec lines 166-167. The header carries `kid="#atproto"`.
///
/// # Errors
///
/// Returns [`SpaceError::JwtEncoding`] / [`SpaceError::Signature`] on failure,
/// including when `member_signing_key` is not an ES256/ES256K key.
pub fn create_delegation_token(
    member_did: &str,
    space: &SpaceUri,
    member_signing_key: &KeyData,
    ttl_secs: u64,
) -> SpaceResult<String> {
    let iat = now_secs();
    let exp = iat + ttl_secs;
    let payload = DelegationToken {
        iss: member_did.to_string(),
        aud: space_host_audience(&space.space_did),
        sub: space.to_string(),
        iat,
        exp,
        jti: random_jti(),
    };
    mint_jwt(
        TYP_DELEGATION_TOKEN,
        KID_DELEGATION_TOKEN,
        &payload,
        member_signing_key,
    )
}

/// Verify a delegation token against the member's verifying key and expected
/// claims.
///
/// Checks: signature, header `typ`/`kid`/`alg`, `aud` (the space host service
/// fragment of the authority DID), `sub` (the space URI), and `exp`. The
/// caller is responsible for enforcing single-use via `jti`.
///
/// # Errors
///
/// Returns the relevant `SpaceError` on any check failure.
pub fn verify_delegation_token(
    token: &str,
    expected_authority_did: &str,
    expected_space: &SpaceUri,
    member_verifying_key: &KeyData,
) -> SpaceResult<DelegationToken> {
    let payload: DelegationToken = verify_jwt(
        token,
        TYP_DELEGATION_TOKEN,
        KID_DELEGATION_TOKEN,
        member_verifying_key,
    )?;

    let expected_aud = space_host_audience(expected_authority_did);
    if payload.aud != expected_aud {
        return Err(SpaceError::JwtClaimMismatch {
            field: "aud".to_string(),
            expected: expected_aud,
            actual: payload.aud,
        });
    }
    let expected_sub = expected_space.to_string();
    if payload.sub != expected_sub {
        return Err(SpaceError::JwtClaimMismatch {
            field: "sub".to_string(),
            expected: expected_sub,
            actual: payload.sub,
        });
    }
    check_exp(payload.exp)?;
    Ok(payload)
}

/// Mint a space credential signed by the space authority's `#atproto_space`
/// signing key.
///
/// `client_id` is the attested application identity (the verified client
/// attestation's `iss`); pass `None` when the request carried no attestation,
/// in which case the claim is omitted (spec lines 221, 228). The header
/// carries `kid="#atproto_space"` and the payload has no `aud`.
///
/// # Errors
///
/// Returns [`SpaceError::JwtEncoding`] / [`SpaceError::Signature`] on failure.
pub fn create_space_credential(
    authority_did: &str,
    space: &SpaceUri,
    client_id: Option<&str>,
    authority_signing_key: &KeyData,
    ttl_secs: u64,
) -> SpaceResult<String> {
    let iat = now_secs();
    let exp = iat + ttl_secs;
    let payload = SpaceCredential {
        iss: authority_did.to_string(),
        sub: space.to_string(),
        client_id: client_id.map(str::to_string),
        iat,
        exp,
        jti: random_jti(),
    };
    mint_jwt(
        TYP_SPACE_CREDENTIAL,
        KID_SPACE_CREDENTIAL,
        &payload,
        authority_signing_key,
    )
}

/// Verify a space credential against the authority's verifying key and
/// expected claims.
///
/// Checks: signature, header `typ`/`kid`/`alg`, `iss` (the authority DID),
/// `sub` (the space URI), and `exp`.
///
/// # Errors
///
/// Returns the relevant `SpaceError` on any check failure.
pub fn verify_space_credential(
    token: &str,
    expected_authority_did: &str,
    expected_space: &SpaceUri,
    authority_verifying_key: &KeyData,
) -> SpaceResult<SpaceCredential> {
    let payload: SpaceCredential = verify_jwt(
        token,
        TYP_SPACE_CREDENTIAL,
        KID_SPACE_CREDENTIAL,
        authority_verifying_key,
    )?;

    if payload.iss != expected_authority_did {
        return Err(SpaceError::JwtClaimMismatch {
            field: "iss".to_string(),
            expected: expected_authority_did.to_string(),
            actual: payload.iss,
        });
    }
    let expected_sub = expected_space.to_string();
    if payload.sub != expected_sub {
        return Err(SpaceError::JwtClaimMismatch {
            field: "sub".to_string(),
            expected: expected_sub,
            actual: payload.sub,
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
    fn delegation_token_round_trip() {
        let (member_priv, member_pub) = keypair();
        let space = test_space();
        let token = create_delegation_token(
            "did:plc:alice",
            &space,
            &member_priv,
            DELEGATION_TOKEN_TTL_SECS,
        )
        .unwrap();

        let payload =
            verify_delegation_token(&token, "did:plc:owner", &space, &member_pub).unwrap();
        assert_eq!(payload.iss, "did:plc:alice");
        assert_eq!(payload.aud, "did:plc:owner#atproto_space_host");
        assert_eq!(payload.sub, space.to_string());
    }

    #[test]
    fn delegation_token_header_is_spec_exact() {
        let (member_priv, _) = keypair();
        let space = test_space();
        let token = create_delegation_token(
            "did:plc:alice",
            &space,
            &member_priv,
            DELEGATION_TOKEN_TTL_SECS,
        )
        .unwrap();
        let header_b64 = token.split('.').next().unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&b64url_decode(header_b64).unwrap()).unwrap();
        assert_eq!(header["typ"], "atproto-space-delegation+jwt");
        assert_eq!(header["kid"], "#atproto");
        assert_eq!(header["alg"], "ES256");
    }

    #[test]
    fn delegation_token_has_no_lxm_or_client_id() {
        let (member_priv, _) = keypair();
        let space = test_space();
        let token = create_delegation_token(
            "did:plc:alice",
            &space,
            &member_priv,
            DELEGATION_TOKEN_TTL_SECS,
        )
        .unwrap();
        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&b64url_decode(payload_b64).unwrap()).unwrap();
        assert!(payload.get("lxm").is_none());
        assert!(payload.get("clientId").is_none());
        assert!(payload.get("client_id").is_none());
        assert!(payload.get("space").is_none());
        assert!(payload.get("sub").is_some());
    }

    #[test]
    fn delegation_token_default_ttl_is_60s() {
        let (member_priv, _) = keypair();
        let space = test_space();
        let token = create_delegation_token(
            "did:plc:alice",
            &space,
            &member_priv,
            DELEGATION_TOKEN_TTL_SECS,
        )
        .unwrap();
        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload: DelegationToken =
            serde_json::from_slice(&b64url_decode(payload_b64).unwrap()).unwrap();
        assert_eq!(payload.exp - payload.iat, 60);
    }

    #[test]
    fn delegation_token_wrong_authority_rejected() {
        let (member_priv, member_pub) = keypair();
        let space = test_space();
        let token = create_delegation_token(
            "did:plc:alice",
            &space,
            &member_priv,
            DELEGATION_TOKEN_TTL_SECS,
        )
        .unwrap();
        let result = verify_delegation_token(&token, "did:plc:other-owner", &space, &member_pub);
        assert!(matches!(result, Err(SpaceError::JwtClaimMismatch { .. })));
    }

    #[test]
    fn delegation_token_expired_rejected() {
        let (member_priv, member_pub) = keypair();
        let space = test_space();
        let token = create_delegation_token("did:plc:alice", &space, &member_priv, 0).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let result = verify_delegation_token(&token, "did:plc:owner", &space, &member_pub);
        assert!(matches!(result, Err(SpaceError::JwtExpired { .. })));
    }

    #[test]
    fn delegation_token_tampered_payload_rejected() {
        let (member_priv, member_pub) = keypair();
        let space = test_space();
        let token = create_delegation_token(
            "did:plc:alice",
            &space,
            &member_priv,
            DELEGATION_TOKEN_TTL_SECS,
        )
        .unwrap();
        let mut parts: Vec<String> = token.split('.').map(String::from).collect();
        parts[1] = parts[1].chars().rev().collect::<String>();
        let tampered = parts.join(".");
        let result = verify_delegation_token(&tampered, "did:plc:owner", &space, &member_pub);
        assert!(result.is_err());
    }

    #[test]
    fn space_credential_round_trip_with_client_id() {
        let (owner_priv, owner_pub) = keypair();
        let space = test_space();
        let token = create_space_credential(
            "did:plc:owner",
            &space,
            Some("https://app.example/client-metadata.json"),
            &owner_priv,
            SPACE_CREDENTIAL_TTL_SECS,
        )
        .unwrap();
        let payload = verify_space_credential(&token, "did:plc:owner", &space, &owner_pub).unwrap();
        assert_eq!(payload.iss, "did:plc:owner");
        assert_eq!(payload.sub, space.to_string());
        assert_eq!(
            payload.client_id.as_deref(),
            Some("https://app.example/client-metadata.json")
        );
    }

    #[test]
    fn space_credential_header_is_spec_exact() {
        let (owner_priv, _) = keypair();
        let space = test_space();
        let token = create_space_credential(
            "did:plc:owner",
            &space,
            None,
            &owner_priv,
            SPACE_CREDENTIAL_TTL_SECS,
        )
        .unwrap();
        let header_b64 = token.split('.').next().unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&b64url_decode(header_b64).unwrap()).unwrap();
        assert_eq!(header["typ"], "atproto-space-credential+jwt");
        assert_eq!(header["kid"], "#atproto_space");
    }

    #[test]
    fn space_credential_omits_client_id_when_absent() {
        let (owner_priv, _) = keypair();
        let space = test_space();
        let token = create_space_credential(
            "did:plc:owner",
            &space,
            None,
            &owner_priv,
            SPACE_CREDENTIAL_TTL_SECS,
        )
        .unwrap();
        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&b64url_decode(payload_b64).unwrap()).unwrap();
        assert!(payload.get("client_id").is_none());
        assert!(payload.get("clientId").is_none());
        assert!(payload.get("aud").is_none());
        assert_eq!(payload["sub"], space.to_string());
    }

    #[test]
    fn space_credential_uses_snake_case_client_id() {
        let (owner_priv, _) = keypair();
        let space = test_space();
        let token = create_space_credential(
            "did:plc:owner",
            &space,
            Some("https://app.example/cm"),
            &owner_priv,
            SPACE_CREDENTIAL_TTL_SECS,
        )
        .unwrap();
        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&b64url_decode(payload_b64).unwrap()).unwrap();
        assert_eq!(payload["client_id"], "https://app.example/cm");
        assert!(payload.get("clientId").is_none());
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
            None,
            &owner_priv,
            SPACE_CREDENTIAL_TTL_SECS,
        )
        .unwrap();
        let result = verify_space_credential(&token, "did:plc:owner", &other_space, &owner_pub);
        assert!(matches!(result, Err(SpaceError::JwtClaimMismatch { .. })));
    }
}
