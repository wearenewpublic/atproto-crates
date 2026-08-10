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
pub const TYP_SERVICE_AUTH: &str = crate::http::service_auth_handlers::TYP_SERVICE_AUTH;

/// Default TTL for a minted notify service-auth token (60s).
pub const NOTIFY_SERVICE_AUTH_TTL_SECS: u64 = 60;

/// Service-auth JWT header.
#[derive(Debug, Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
    /// Which verification method in the issuer's DID document signed this.
    ///
    /// Proposal 0014: "The `kid` JWT header field will be allowed to identify
    /// a signing key ('verification method') from the issuer DID document
    /// (including the `#` character), with a default value of `#atproto`."
    ///
    /// Optional, so absent decodes as the default rather than as an error --
    /// a peer that predates the field is not malformed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
}

/// The only verification method this server will verify a service-auth token
/// against.
///
/// Proposal 0014 is explicit that a verifier should not take the issuer's word
/// for which key to use: "Receiving services should _not_ accept arbitrary key
/// types (`kid` values): they should only accept key types relevant to their
/// use-case. A safe default for SDKs and services is to only accept
/// `#atproto`." Service auth is the atproto signing key's use-case and no
/// other, so this is that default rather than a limitation to be widened
/// later.
const SERVICE_AUTH_KID: &str = "#atproto";

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

/// Clock drift allowed between this server and a peer.
///
/// Only the `iat` sanity check consults it. `exp` is compared exactly, because
/// a token that has expired by any margin has expired.
const CLOCK_SKEW_SECS: u64 = 60;

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
        // Stated rather than left to the default. A verifier that resolves
        // `kid` and one that assumes `#atproto` then agree explicitly instead
        // of by coincidence.
        kid: Some(SERVICE_AUTH_KID.to_string()),
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
    revocations: Option<&crate::account::AccountPool>,
) -> PdsResult<ServiceAuthClaims> {
    verify_inner(
        http,
        token,
        plc_directory_hostname,
        Some(expected_aud),
        expected_lxm,
        revocations,
    )
    .await
}

/// Verify a service-auth token without deciding its audience.
///
/// Everything [`verify_service_auth`] checks except `aud`: signature against the
/// issuer's published key, `lxm`, expiry, revocation. The caller is then holding
/// *verified* claims and can decide whether the audience is one it will act on.
///
/// This exists for the case where the set of audiences a server accepts is not a
/// single known string. The alternative -- reading `aud` out of the unverified
/// payload and passing it back in as the expected value -- compares the claim to
/// itself, so it always passes and reads in the code as a binding that is not
/// there. If a caller has one audience in mind, it should use
/// [`verify_service_auth`] and let the comparison happen where a mismatch is an
/// error.
///
/// # Errors
///
/// As [`verify_service_auth`], minus the audience mismatch.
pub async fn verify_service_auth_unaudienced(
    http: &reqwest::Client,
    token: &str,
    plc_directory_hostname: Option<&str>,
    expected_lxm: &str,
    revocations: Option<&crate::account::AccountPool>,
) -> PdsResult<ServiceAuthClaims> {
    verify_inner(
        http,
        token,
        plc_directory_hostname,
        None,
        expected_lxm,
        revocations,
    )
    .await
}

/// The verification both entry points share.
///
/// `expected_aud` is `None` when the caller decides the audience itself. It is
/// checked here rather than after the fact so a token addressed elsewhere is
/// still refused before the issuer's DID document is fetched -- the claim checks
/// are ordered ahead of that resolution on purpose, and an audience the server
/// already knows it will not accept should not buy a network round trip.
async fn verify_inner(
    http: &reqwest::Client,
    token: &str,
    plc_directory_hostname: Option<&str>,
    expected_aud: Option<&str>,
    expected_lxm: &str,
    revocations: Option<&crate::account::AccountPool>,
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
    if let Some(expected_aud) = expected_aud
        && claims.aud != expected_aud
    {
        return Err(deny(&format!(
            "service-auth aud mismatch: token={}, expected={}",
            claims.aud, expected_aud
        )));
    }
    // A token with no `lxm` is scoped to nothing, which means it satisfies
    // every method the receiving service gates by one. Accepting it here made
    // any service-auth token a wildcard credential at this endpoint, so an
    // absent claim is a failure rather than a pass.
    match claims.lxm.as_deref() {
        Some(lxm) if lxm == expected_lxm => {}
        Some(lxm) => {
            return Err(deny(&format!(
                "service-auth lxm mismatch: token={lxm}, expected={expected_lxm}"
            )));
        }
        None => {
            return Err(deny(&format!(
                "service-auth token has no lxm; must match: {expected_lxm}"
            )));
        }
    }
    // The header was decoded for nothing but its bytes until now: `kid` was
    // never read, so a token naming any other key was verified against
    // `#atproto` regardless of what it claimed to be signed with. That fails
    // closed -- the signature would not match -- but it fails with "signature
    // invalid", which says nothing about the actual disagreement.
    //
    // Absent is the specified default and stays acceptable.
    let header: JwtHeader = general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64.as_bytes())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| deny("service-auth header not JSON"))?;
    if let Some(kid) = header.kid.as_deref()
        && !is_atproto_kid(kid, &claims.iss)
    {
        return Err(deny(&format!(
            "service-auth kid {kid} is not {SERVICE_AUTH_KID}"
        )));
    }

    let now = now_secs();
    if claims.exp <= now {
        return Err(deny("service-auth token expired"));
    }

    // A token issued in the future is not a token whose lifetime can be
    // reasoned about: the ceiling below is measured from `iat`, so an `iat`
    // the issuer is free to place anywhere makes the ceiling free too. Some
    // slack for honest clock drift between peers, and no more.
    if claims.iat > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(deny("service-auth token issued in the future"));
    }

    // Hold a peer to the same lifetime this server holds itself to.
    //
    // `exp > now` was the only bound, so a peer could mint a token good for a
    // decade and this server would take it -- while its own `getServiceAuth`
    // clamps to an hour. A leaked token then stayed valid until an operator
    // found it and blacklisted that exact `jti`, which requires knowing it
    // leaked. The ceiling is what makes the credential short-lived whether or
    // not anyone notices.
    if claims.exp.saturating_sub(claims.iat)
        > crate::http::service_auth_handlers::MAX_SERVICE_AUTH_LIFETIME_SECS
    {
        return Err(deny(&format!(
            "service-auth token lifetime {}s exceeds the {}s ceiling",
            claims.exp.saturating_sub(claims.iat),
            crate::http::service_auth_handlers::MAX_SERVICE_AUTH_LIFETIME_SECS
        )));
    }

    // The `jti` is checked against revocations and deliberately *not* against
    // a replay guard.
    //
    // Single-use would be the stronger posture and it is wrong here: this
    // server's own notifier mints one token per queued delivery, stores it on
    // the `notify_attempt` row, and presents that same token on every retry.
    // Enforcing single-use inbound would therefore reject every retry after
    // the first attempt that reached the peer -- the delivery would fail, back
    // off, retry with a token the receiver had already burned, and fail again
    // until it hit `max_attempts`. A replay defence that breaks the retry path
    // it shares a codebase with is not a defence, it is an outage with a
    // security rationale.
    //
    // What bounds replay instead is the lifetime ceiling above, which is now
    // enforced rather than assumed. Making these single-use would mean minting
    // per attempt rather than per delivery, which is a change to the notifier,
    // not to this check.
    //
    // `com.atproto.admin.revokeServiceAuth` writes the jti here. Until this
    // check existed the endpoint returned 200 OK and did nothing, so an
    // operator revoking a leaked token was told it had worked and it had not —
    // a security control that reads as working is worse than an absent one.
    if let Some(pool) = revocations
        && crate::service_auth_blacklist::contains(pool, &claims.jti).await?
    {
        tracing::warn!(
            jti = %claims.jti,
            iss = %claims.iss,
            "rejected a revoked service-auth token"
        );
        return Err(deny("service-auth token has been revoked"));
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

/// Whether a verification-method identifier names *this* issuer's `#atproto`
/// key.
///
/// A DID document may write a method id in full (`did:plc:abc#atproto`) or
/// relative to itself (`#atproto`), and both mean the same key.
///
/// What it must not do is match on the fragment alone. `ends_with("#atproto")`
/// accepted `did:web:somebody-else#atproto`, so a document listing a method
/// belonging to another DID -- which a hostile `did:web` document is free to
/// do, since it is served by whoever controls the domain -- supplied the key
/// that service-auth tokens were then verified against. The identifier has to
/// be the issuer's own.
fn is_atproto_kid(id: &str, issuer_did: &str) -> bool {
    id == SERVICE_AUTH_KID || id == format!("{issuer_did}{SERVICE_AUTH_KID}")
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
            && is_atproto_kid(id, did)
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

    /// Build a compact token carrying `claims` with a placeholder signature.
    ///
    /// The claim checks below all run before the issuer's key is resolved, so
    /// no network and no valid signature are needed to exercise them.
    fn unsigned_token(claims: &ServiceAuthClaims) -> String {
        let header = general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256K","typ":"JWT"}"#);
        let payload = general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        format!("{header}.{payload}.c2ln")
    }

    fn claims_with_lxm(lxm: Option<&str>) -> ServiceAuthClaims {
        ServiceAuthClaims {
            iss: "did:plc:writer".to_string(),
            aud: "did:plc:owner".to_string(),
            lxm: lxm.map(str::to_string),
            iat: now_secs(),
            exp: now_secs() + 60,
            jti: "test-jti".to_string(),
        }
    }

    /// A verification method belonging to somebody else is not this issuer's
    /// key, however its fragment reads.
    ///
    /// The match was `ends_with("#atproto")`, so a document listing
    /// `did:web:somebody-else#atproto` supplied the key that this issuer's
    /// tokens were verified against -- and a `did:web` document is served by
    /// whoever controls the domain, so listing another DID's method is
    /// something a hostile one is free to do.
    #[test]
    fn a_method_belonging_to_another_did_is_not_this_issuers_key() {
        let issuer = "did:plc:writer";
        assert!(is_atproto_kid("did:plc:writer#atproto", issuer));
        // The relative form means the same key.
        assert!(is_atproto_kid("#atproto", issuer));

        assert!(
            !is_atproto_kid("did:web:somebody-else#atproto", issuer),
            "a method under another DID must not satisfy this issuer"
        );
    }

    /// Proposal 0014: receiving services "should only accept key types
    /// relevant to their use-case. A safe default ... is to only accept
    /// `#atproto`". Service auth has exactly one use-case.
    #[test]
    fn only_the_atproto_key_is_accepted() {
        let issuer = "did:plc:writer";
        assert!(!is_atproto_kid("did:plc:writer#signing", issuer));
        assert!(!is_atproto_kid("#some-other-key", issuer));
    }

    /// A token naming a key other than `#atproto` is refused for naming it,
    /// rather than falling through to a signature check against a key it did
    /// not claim and failing as "signature invalid".
    #[tokio::test]
    async fn verify_rejects_a_token_naming_another_key() {
        let claims = claims_with_lxm(Some("com.atproto.space.notifyWrite"));
        let header = general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "alg": "ES256K",
                "typ": TYP_SERVICE_AUTH,
                "kid": "#some-other-key",
            }))
            .unwrap(),
        );
        let payload = general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let token = format!("{header}.{payload}.c2ln");

        let err = verify_service_auth(
            &reqwest::Client::new(),
            &token,
            None,
            "did:plc:owner",
            "com.atproto.space.notifyWrite",
            None,
        )
        .await
        .expect_err("a token naming another key must be refused");
        assert!(
            err.to_string().contains("kid"),
            "expected a kid-specific denial, got: {err}"
        );
    }

    /// A token with no `kid` is the specified default, not a malformed token.
    #[tokio::test]
    async fn verify_accepts_a_token_with_no_kid() {
        let token = unsigned_token(&claims_with_lxm(Some("com.atproto.space.notifyWrite")));
        let err = verify_service_auth(
            &reqwest::Client::new(),
            &token,
            None,
            "did:plc:owner",
            "com.atproto.space.notifyWrite",
            None,
        )
        .await
        .expect_err("the unsigned fixture cannot pass signature verification");
        assert!(
            !err.to_string().contains("kid"),
            "an absent kid is the default and must not be refused: {err}"
        );
    }

    /// What this server mints names the key it signed with, so a verifier that
    /// resolves `kid` and one that assumes the default agree explicitly.
    #[test]
    fn a_minted_token_names_the_atproto_key() {
        let key = generate_key(KeyType::P256Private).unwrap();
        let token = mint_service_auth(
            &key,
            "did:plc:writer",
            "did:plc:owner",
            "com.atproto.space.notifyWrite",
            60,
        )
        .unwrap();
        let header_b64 = token.split('.').next().unwrap();
        let header: serde_json::Value = serde_json::from_slice(
            &general_purpose::URL_SAFE_NO_PAD
                .decode(header_b64.as_bytes())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(header["kid"], SERVICE_AUTH_KID);
    }

    /// A peer must be held to the lifetime this server holds itself to.
    ///
    /// `exp > now` was the only bound, so a peer could mint a token good for a
    /// decade and this server would take it -- while its own `getServiceAuth`
    /// clamps to an hour. The refusal happens before the issuer's DID document
    /// is fetched, like the other claim checks.
    #[tokio::test]
    async fn verify_rejects_a_token_that_outlives_the_ceiling() {
        let mut claims = claims_with_lxm(Some("com.atproto.space.notifyWrite"));
        claims.exp =
            claims.iat + crate::http::service_auth_handlers::MAX_SERVICE_AUTH_LIFETIME_SECS + 1;
        let token = unsigned_token(&claims);
        let err = verify_service_auth(
            &reqwest::Client::new(),
            &token,
            None,
            "did:plc:owner",
            "com.atproto.space.notifyWrite",
            None,
        )
        .await
        .expect_err("a token outliving the ceiling must be refused");
        assert!(
            err.to_string().contains("ceiling"),
            "expected a lifetime-specific denial, got: {err}"
        );
    }

    /// A token exactly at the ceiling is fine -- the bound is a ceiling, not a
    /// margin, and refusing at it would make the documented maximum unusable.
    #[tokio::test]
    async fn verify_accepts_a_token_at_the_ceiling() {
        let mut claims = claims_with_lxm(Some("com.atproto.space.notifyWrite"));
        claims.exp =
            claims.iat + crate::http::service_auth_handlers::MAX_SERVICE_AUTH_LIFETIME_SECS;
        let token = unsigned_token(&claims);
        let err = verify_service_auth(
            &reqwest::Client::new(),
            &token,
            None,
            "did:plc:owner",
            "com.atproto.space.notifyWrite",
            None,
        )
        .await
        .expect_err("the unsigned fixture cannot pass signature verification");
        assert!(
            !err.to_string().contains("ceiling"),
            "a token at the ceiling must clear the lifetime check, got: {err}"
        );
    }

    /// An `iat` in the future makes the ceiling meaningless, because the
    /// ceiling is measured from it.
    #[tokio::test]
    async fn verify_rejects_a_token_issued_in_the_future() {
        let mut claims = claims_with_lxm(Some("com.atproto.space.notifyWrite"));
        claims.iat = now_secs() + CLOCK_SKEW_SECS + 120;
        claims.exp = claims.iat + 60;
        let token = unsigned_token(&claims);
        let err = verify_service_auth(
            &reqwest::Client::new(),
            &token,
            None,
            "did:plc:owner",
            "com.atproto.space.notifyWrite",
            None,
        )
        .await
        .expect_err("a token issued in the future must be refused");
        assert!(
            err.to_string().contains("issued in the future"),
            "expected an iat-specific denial, got: {err}"
        );
    }

    /// Ordinary clock drift between peers is not an attack.
    #[tokio::test]
    async fn verify_tolerates_a_little_clock_drift() {
        let mut claims = claims_with_lxm(Some("com.atproto.space.notifyWrite"));
        claims.iat = now_secs() + CLOCK_SKEW_SECS / 2;
        claims.exp = claims.iat + 60;
        let token = unsigned_token(&claims);
        let err = verify_service_auth(
            &reqwest::Client::new(),
            &token,
            None,
            "did:plc:owner",
            "com.atproto.space.notifyWrite",
            None,
        )
        .await
        .expect_err("the unsigned fixture cannot pass signature verification");
        assert!(
            !err.to_string().contains("issued in the future"),
            "a peer a few seconds fast must still be served, got: {err}"
        );
    }

    /// A token with no `lxm` must be refused, not treated as satisfying
    /// whatever method it is presented against.
    ///
    /// This is the whole point of the claim: an unscoped token satisfies every
    /// `lxm`-gated method at every peer that only compares when the claim is
    /// present, which makes it a wildcard cross-service bearer.
    #[tokio::test]
    async fn verify_rejects_a_token_with_no_lxm() {
        let token = unsigned_token(&claims_with_lxm(None));
        let err = verify_service_auth(
            &reqwest::Client::new(),
            &token,
            None,
            "did:plc:owner",
            "com.atproto.space.notifyWrite",
            None,
        )
        .await
        .expect_err("a token with no lxm must be refused");
        assert!(
            err.to_string().contains("no lxm"),
            "expected an lxm-specific denial, got: {err}"
        );
    }

    /// A mismatched audience is still refused, and still before the issuer's
    /// DID document is fetched.
    ///
    /// The ordering is the part worth pinning. Splitting the audience check out
    /// so one caller could skip it is an easy way to end up doing it after the
    /// signature, which turns a token addressed elsewhere into a network round
    /// trip against a DID the sender chose.
    #[tokio::test]
    async fn verify_rejects_a_token_addressed_elsewhere() {
        let token = unsigned_token(&claims_with_lxm(Some("com.atproto.space.notifyWrite")));
        let err = verify_service_auth(
            &reqwest::Client::new(),
            &token,
            None,
            "did:plc:someoneelse",
            "com.atproto.space.notifyWrite",
            None,
        )
        .await
        .expect_err("a token for another audience must be refused");
        assert!(
            err.to_string().contains("aud mismatch"),
            "expected an aud-specific denial before key resolution, got: {err}"
        );
    }

    /// The unaudienced entry point does not gate on `aud` -- that is its whole
    /// purpose -- but still applies every other check.
    ///
    /// It exists because reading `aud` out of the unverified payload and passing
    /// it back as the expected value compares a claim to itself: it cannot fail,
    /// and it reads in the code as a binding that is not there. A caller that
    /// cannot name its audience up front should say so and decide afterwards on
    /// claims that have been verified.
    #[tokio::test]
    async fn the_unaudienced_entry_point_still_enforces_lxm() {
        let token = unsigned_token(&claims_with_lxm(Some("com.atproto.repo.createRecord")));
        let err = verify_service_auth_unaudienced(
            &reqwest::Client::new(),
            &token,
            None,
            "com.atproto.space.notifySpaceDeleted",
            None,
        )
        .await
        .expect_err("a mismatched lxm must be refused whoever the audience is");
        assert!(
            err.to_string().contains("lxm mismatch"),
            "expected an lxm mismatch denial, got: {err}"
        );

        // And an audience it was never given is not a reason to refuse: this
        // token gets past every claim check and dies at the signature.
        let token = unsigned_token(&claims_with_lxm(Some(
            "com.atproto.space.notifySpaceDeleted",
        )));
        let err = verify_service_auth_unaudienced(
            &reqwest::Client::new(),
            &token,
            None,
            "com.atproto.space.notifySpaceDeleted",
            None,
        )
        .await
        .expect_err("the placeholder signature cannot verify");
        assert!(
            !err.to_string().contains("aud"),
            "the unaudienced path must not refuse on audience, got: {err}"
        );
    }

    /// A token scoped to a different method is refused.
    #[tokio::test]
    async fn verify_rejects_a_token_scoped_to_another_method() {
        let token = unsigned_token(&claims_with_lxm(Some("com.atproto.repo.createRecord")));
        let err = verify_service_auth(
            &reqwest::Client::new(),
            &token,
            None,
            "did:plc:owner",
            "com.atproto.space.notifyWrite",
            None,
        )
        .await
        .expect_err("a mismatched lxm must be refused");
        assert!(
            err.to_string().contains("lxm mismatch"),
            "expected an lxm mismatch denial, got: {err}"
        );
    }
}
