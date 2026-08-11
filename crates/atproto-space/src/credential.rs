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
//!    header), the `dpopJkt` thumbprint of a key it holds, and an optional
//!    client attestation to the space authority at
//!    [`com.atproto.space.getSpaceCredential`]. The authority verifies it and
//!    mints a **space credential** (spec "Space credential", lines 200-230): a
//!    JWT with header `typ=atproto-space-credential+jwt`,
//!    `kid="#atproto_space"`, signed by the authority's space signing key.
//!    Claims: `iss` (authority DID), `sub` (the space `at://` URI),
//!    `cnf.jkt` (the requested thumbprint), `client_id` (the attested app,
//!    omitted when no attestation), `iat`, `exp=iat+7200`, `jti`. It has no
//!    `aud`. Default 2-hour TTL.
//!
//! A credential reads *every* repo in its space and is presented to each of
//! their hosts in turn, so as a bearer token it would be a shared secret: any
//! host handed one to serve its own repo could replay it against the others.
//! Every credential is therefore **DPoP-bound** at issuance to a key the
//! requesting app holds — the `cnf.jkt` claim (RFC 9449 §6.1) names that key
//! by its RFC 7638 thumbprint, and a holder proves possession per request.
//! Minting one without a thumbprint is not expressible: [`Cnf`] is not
//! optional, and [`create_space_credential`] takes the thumbprint by value.
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

/// `typ` header value for a delegation token (the spec's "Delegation token" section).
pub const TYP_DELEGATION_TOKEN: &str = "atproto-space-delegation+jwt";

/// `typ` header value for a space credential (the spec's "Space credential" section).
pub const TYP_SPACE_CREDENTIAL: &str = "atproto-space-credential+jwt";

/// `kid` header value a delegation token MUST carry (the spec's "Delegation token" section).
pub const KID_DELEGATION_TOKEN: &str = "#atproto";

/// `kid` header value a space credential MUST carry (the spec's "Space credential" section).
pub const KID_SPACE_CREDENTIAL: &str = "#atproto_space";

/// Delegation-token default TTL: 60 seconds (the spec's "Delegation token" section).
pub const DELEGATION_TOKEN_TTL_SECS: u64 = 60;

/// SpaceCredential default TTL: 2 hours / 7200 seconds (the spec's "Space credential" section).
pub const SPACE_CREDENTIAL_TTL_SECS: u64 = 7200;

/// Shortest SpaceCredential TTL a host may configure, in seconds.
///
/// Below this a credential expires inside the round trip that fetched it,
/// which reads to a client as an unreliable server rather than as a policy.
pub const SPACE_CREDENTIAL_TTL_MIN_SECS: u64 = 60;

/// Longest SpaceCredential TTL a host may configure, in seconds (24 hours).
///
/// A SpaceCredential has no revocation path — removing a member does not
/// invalidate one already minted. The ceiling bounds how long a revoked member
/// keeps access. DPoP binding narrows *who* can present a leaked credential,
/// not how long it lives, so the ceiling is unaffected by it.
pub const SPACE_CREDENTIAL_TTL_MAX_SECS: u64 = 86_400;

// The default must sit inside the configurable range, or the host's own
// out-of-the-box setting would be clamped away.
const _: () = assert!(SPACE_CREDENTIAL_TTL_MIN_SECS <= SPACE_CREDENTIAL_TTL_SECS);
const _: () = assert!(SPACE_CREDENTIAL_TTL_SECS <= SPACE_CREDENTIAL_TTL_MAX_SECS);

/// The `aud` of a delegation token: the space host service fragment of the
/// authority DID (`<spaceDid>#atproto_space_host`, the spec's "Delegation token" section).
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

/// Decoded delegation-token payload (the spec's "Delegation token" section).
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

/// Length of an RFC 7638 thumbprint: SHA-256 (32 bytes) in unpadded base64url.
const JKT_LEN: usize = 43;

/// Check that `jkt` has the shape of an RFC 7638 JWK thumbprint.
///
/// RFC 9449 §6.1 fixes the `cnf.jkt` hash at SHA-256, so a well-formed
/// thumbprint is always 43 unpadded base64url characters. Anything else — a
/// whole JWK, a hex digest, a padded encoding — cannot match the thumbprint a
/// host computes from a presented proof, so accepting it would mint a
/// credential that nothing can ever present. Refusing it here turns that into
/// an error the requesting app can read.
///
/// # Errors
///
/// Returns [`SpaceError::InvalidDpopJkt`] describing which check failed.
pub fn validate_dpop_jkt(jkt: &str) -> SpaceResult<()> {
    if jkt.is_empty() {
        return Err(SpaceError::InvalidDpopJkt {
            reason: "empty".to_string(),
        });
    }
    if jkt.len() != JKT_LEN {
        return Err(SpaceError::InvalidDpopJkt {
            reason: format!(
                "expected {JKT_LEN} base64url characters (unpadded SHA-256), got {}",
                jkt.len()
            ),
        });
    }
    if let Some(bad) = jkt
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && *c != '-' && *c != '_')
    {
        return Err(SpaceError::InvalidDpopJkt {
            reason: format!("contains {bad:?}, which is not a base64url character"),
        });
    }
    Ok(())
}

/// `cnf` claim of a SpaceCredential: the key the credential is bound to
/// (RFC 9449 §6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cnf {
    /// RFC 7638 JWK thumbprint of the public key the holder proves possession
    /// of on every request.
    pub jkt: String,
}

/// Decoded SpaceCredential payload (the spec's "Space credential" section).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceCredential {
    /// Issuer DID — the space authority.
    pub iss: String,
    /// Subject — the space the credential reads, an `at://…/space/…` URI.
    pub sub: String,
    /// Confirmation claim binding this credential to the holder's DPoP key.
    ///
    /// Not optional: a credential is a whole-space capability presented to
    /// hosts that do not trust each other, so one that named no key would be a
    /// bearer token any of them could replay. A credential decoding without
    /// `cnf` is refused rather than treated as unbound.
    pub cnf: Cnf,
    /// Attested application identity (the verified client attestation's
    /// `iss`). Omitted on the wire when the request carried no attestation
    /// (the spec's "Space credential" section).
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
/// the spec permits in space-token headers (ES256 / ES256K, the spec's token sections). Other key types (P-384, Ed25519) are rejected here so the minted
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

/// Clock skew tolerated when checking `iat` and `exp`, in seconds.
///
/// Delegation tokens live 60 seconds and are minted by a *different* host from
/// the one verifying them. Without tolerance, two servers a few seconds apart
/// reject each other's freshly minted tokens — a distributed protocol cannot
/// assume synchronised clocks.
pub const CLOCK_SKEW_SECS: u64 = 60;

/// Check `iat`/`exp` against the wall clock, allowing [`CLOCK_SKEW_SECS`] of
/// drift in either direction.
///
/// A token whose `iat` is further ahead than the tolerance is refused: an
/// issuer that can date tokens forward can extend their life without bound,
/// which is the same as having no expiry at all.
fn check_time_claims(iat: u64, exp: u64) -> SpaceResult<()> {
    let now = now_secs();
    if exp.saturating_add(CLOCK_SKEW_SECS) <= now {
        return Err(SpaceError::JwtExpired { exp, now });
    }
    if iat > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(SpaceError::JwtIssuedInFuture { iat, now });
    }
    Ok(())
}

/// Mint a delegation token signed by the member's atproto signing key.
///
/// The token's `aud` is set to the space host service fragment
/// (`<spaceDid>#atproto_space_host`) and `sub` to the space `at://` URI, per
/// the spec's "Delegation token" section. The header carries `kid="#atproto"`.
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
    check_time_claims(payload.iat, payload.exp)?;
    Ok(payload)
}

/// Mint a space credential signed by the space authority's `#atproto_space`
/// signing key.
///
/// `dpop_jkt` is the RFC 7638 thumbprint the requesting app sent as the
/// `dpopJkt` parameter; it is copied verbatim into `cnf.jkt`, binding the
/// credential to that key. The authority never sees the key itself and nothing
/// is registered — the thumbprint is the whole binding.
///
/// `client_id` is the attested application identity (the verified client
/// attestation's `iss`); pass `None` when the request carried no attestation,
/// in which case the claim is omitted (the spec's "Space credential" section). The header
/// carries `kid="#atproto_space"` and the payload has no `aud`.
///
/// # Errors
///
/// Returns [`SpaceError::InvalidDpopJkt`] when `dpop_jkt` is not a
/// well-formed thumbprint, or [`SpaceError::JwtEncoding`] /
/// [`SpaceError::Signature`] on failure.
pub fn create_space_credential(
    authority_did: &str,
    space: &SpaceUri,
    dpop_jkt: &str,
    client_id: Option<&str>,
    authority_signing_key: &KeyData,
    ttl_secs: u64,
) -> SpaceResult<String> {
    validate_dpop_jkt(dpop_jkt)?;
    let iat = now_secs();
    let exp = iat + ttl_secs;
    let payload = SpaceCredential {
        iss: authority_did.to_string(),
        sub: space.to_string(),
        cnf: Cnf {
            jkt: dpop_jkt.to_string(),
        },
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
/// `sub` (the space URI), and `exp`. A credential carrying no `cnf` fails to
/// decode, so an unbound one cannot pass here.
///
/// This establishes that the authority issued the credential and which key it
/// was bound to. It does **not** check that the presenter holds that key: the
/// caller compares `cnf.jkt` against the thumbprint of a verified DPoP proof,
/// since only the caller sees the request the proof is bound to.
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
    check_time_claims(payload.iat, payload.exp)?;
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
        // Dated well past the skew window. `create_delegation_token` can only
        // mint `exp = now + ttl`, so the payload is built directly; a
        // zero-TTL token plus a short sleep now lands inside the tolerance.
        let now = now_secs();
        let payload = DelegationToken {
            iss: "did:plc:alice".to_string(),
            aud: space_host_audience(&space.space_did),
            sub: space.to_string(),
            iat: now - 600,
            exp: now - 600 + DELEGATION_TOKEN_TTL_SECS,
            jti: random_jti(),
        };
        let token = mint_jwt(
            TYP_DELEGATION_TOKEN,
            KID_DELEGATION_TOKEN,
            &payload,
            &member_priv,
        )
        .unwrap();
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

    /// A syntactically valid RFC 7638 thumbprint: 43 unpadded base64url
    /// characters, the shape of a base64url-encoded SHA-256 digest.
    const TEST_JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

    #[test]
    fn space_credential_round_trip_with_client_id() {
        let (owner_priv, owner_pub) = keypair();
        let space = test_space();
        let token = create_space_credential(
            "did:plc:owner",
            &space,
            TEST_JKT,
            Some("https://app.example/client-metadata.json"),
            &owner_priv,
            SPACE_CREDENTIAL_TTL_SECS,
        )
        .unwrap();
        let payload = verify_space_credential(&token, "did:plc:owner", &space, &owner_pub).unwrap();
        assert_eq!(payload.iss, "did:plc:owner");
        assert_eq!(payload.sub, space.to_string());
        assert_eq!(payload.cnf.jkt, TEST_JKT);
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
            TEST_JKT,
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

    /// The wire shape of the binding, asserted on the encoded payload rather
    /// than the round-tripped struct: a verifier on another host reads
    /// `cnf.jkt` out of the JSON, so a rename or a flattening that still
    /// round-trips through our own type would break it.
    #[test]
    fn space_credential_carries_the_requested_thumbprint_as_cnf_jkt() {
        let (owner_priv, _) = keypair();
        let space = test_space();
        let token = create_space_credential(
            "did:plc:owner",
            &space,
            TEST_JKT,
            None,
            &owner_priv,
            SPACE_CREDENTIAL_TTL_SECS,
        )
        .unwrap();
        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&b64url_decode(payload_b64).unwrap()).unwrap();
        assert_eq!(payload["cnf"]["jkt"], TEST_JKT);
        assert!(payload.get("jkt").is_none(), "jkt must be nested under cnf");
    }

    /// A credential minted before the binding existed names no key, so nothing
    /// can prove possession of one — it is a bearer token, which is what the
    /// binding removes. Decoding must refuse it rather than read it as
    /// unbound.
    #[test]
    fn a_credential_without_cnf_is_refused() {
        let (owner_priv, owner_pub) = keypair();
        let space = test_space();
        let unbound = serde_json::json!({
            "iss": "did:plc:owner",
            "sub": space.to_string(),
            "iat": now_secs(),
            "exp": now_secs() + SPACE_CREDENTIAL_TTL_SECS,
            "jti": "f47ac10b58cc4372a5670e02b2c3d479",
        });
        let token = mint_jwt(
            TYP_SPACE_CREDENTIAL,
            KID_SPACE_CREDENTIAL,
            &unbound,
            &owner_priv,
        )
        .unwrap();

        let result = verify_space_credential(&token, "did:plc:owner", &space, &owner_pub);
        assert!(
            matches!(result, Err(SpaceError::JwtDecoding { .. })),
            "expected a decode refusal, got {result:?}"
        );
    }

    #[test]
    fn a_thumbprint_that_is_not_a_thumbprint_is_refused_at_mint() {
        let (owner_priv, _) = keypair();
        let space = test_space();
        for bad in [
            "",
            "short",
            // Padded base64, as `base64::encode` would produce.
            "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I=",
            // A hex digest: right entropy, wrong encoding.
            "9f8e7d6c5b4a3210fedcba98765432109f8e7d6c5b4a3210fedcba9876543210",
            // Correct length, but `+/` rather than `-_`.
            "0ZcOCORZNYy+DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
        ] {
            let result = create_space_credential(
                "did:plc:owner",
                &space,
                bad,
                None,
                &owner_priv,
                SPACE_CREDENTIAL_TTL_SECS,
            );
            assert!(
                matches!(result, Err(SpaceError::InvalidDpopJkt { .. })),
                "{bad:?} should not mint a credential, got {result:?}"
            );
        }
        assert!(validate_dpop_jkt(TEST_JKT).is_ok());
    }

    #[test]
    fn space_credential_omits_client_id_when_absent() {
        let (owner_priv, _) = keypair();
        let space = test_space();
        let token = create_space_credential(
            "did:plc:owner",
            &space,
            TEST_JKT,
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
            TEST_JKT,
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
            TEST_JKT,
            None,
            &owner_priv,
            SPACE_CREDENTIAL_TTL_SECS,
        )
        .unwrap();
        let result = verify_space_credential(&token, "did:plc:owner", &other_space, &owner_pub);
        assert!(matches!(result, Err(SpaceError::JwtClaimMismatch { .. })));
    }

    #[test]
    fn a_token_expired_inside_the_skew_window_is_still_accepted() {
        // The minting host and the verifying host are different machines.
        // Without tolerance, a few seconds of clock drift rejects a token that
        // was valid when it was issued.
        let now = now_secs();
        assert!(check_time_claims(now - 10, now - 5).is_ok());
        assert!(check_time_claims(now - 10, now - CLOCK_SKEW_SECS + 5).is_ok());
    }

    #[test]
    fn a_token_expired_beyond_the_skew_window_is_rejected() {
        let now = now_secs();
        let result = check_time_claims(now - 600, now - CLOCK_SKEW_SECS - 5);
        assert!(matches!(result, Err(SpaceError::JwtExpired { .. })));
    }

    #[test]
    fn an_iat_far_in_the_future_is_rejected() {
        // An issuer that can date tokens forward can extend their life
        // without bound, which is the same as having no expiry at all.
        let now = now_secs();
        let result = check_time_claims(now + CLOCK_SKEW_SECS + 60, now + 7200);
        assert!(matches!(result, Err(SpaceError::JwtIssuedInFuture { .. })));
    }

    #[test]
    fn an_iat_slightly_ahead_is_tolerated() {
        let now = now_secs();
        assert!(check_time_claims(now + 5, now + 7200).is_ok());
    }
}
