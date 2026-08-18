//! Inter-PDS service-auth JWTs for the Spaces notify path.
//!
//! `notifyWrite` and `notifySpaceDeleted` are authenticated with AT Protocol
//! **service auth**: a compact JWS signed by the issuer's `#atproto` signing
//! key with `iss` / `aud` / `lxm` / `iat` / `exp` / `jti` claims.
//!
//! The verifier itself lives in `atproto-xrpcs`. What stays here is the three
//! things that are this server's rather than the protocol's: how a DID becomes
//! a document, where the revocation list lives, and how a refusal becomes a
//! [`PdsError`]. Everything else -- the `lxm` requirement, the `kid` check,
//! the `iat` sanity check, the lifetime ceiling, the fragment-tolerant
//! audience match -- was written here and was unreachable by any other service
//! in the ecosystem, which is why it moved.

use crate::errors::{PdsError, PdsResult};
use atproto_identity::key::KeyData;
use atproto_identity::model::Document;
use atproto_identity::traits::IdentityResolver;
use atproto_xrpcs::errors::ServiceAuthError;
use atproto_xrpcs::service_auth::{self, RevocationCheck, ServiceAuthPolicy};
use std::time::Duration;

pub use atproto_xrpcs::service_auth::{
    SERVICE_AUTH_KID, ServiceAuthClaims, audience_matches, is_atproto_kid,
};

/// `typ` header value for service-auth JWTs.
pub const TYP_SERVICE_AUTH: &str = service_auth::TYP_SERVICE_AUTH;

/// Default TTL for a minted notify service-auth token (60s).
pub const NOTIFY_SERVICE_AUTH_TTL_SECS: u64 = 60;

/// Clock drift allowed between this server and a peer.
///
/// Only the `iat` sanity check consults it. `exp` is compared exactly, because
/// a token that has expired by any margin has expired.
const CLOCK_SKEW_SECS: u64 = 60;

/// The policy this server verifies inbound service-auth tokens against.
///
/// The lifetime ceiling is the same one `getServiceAuth` clamps this server's
/// own tokens to. Holding a peer to a longer one would mean accepting a
/// credential this server would not issue.
fn policy<'a>(expected_lxm: &'a str, expected_aud: Option<&'a str>) -> ServiceAuthPolicy<'a> {
    ServiceAuthPolicy {
        lxm: expected_lxm,
        aud: expected_aud,
        max_lifetime: Duration::from_secs(
            crate::http::service_auth_handlers::MAX_SERVICE_AUTH_LIFETIME_SECS,
        ),
        clock_skew: Duration::from_secs(CLOCK_SKEW_SECS),
    }
}

/// Resolves a DID to its document the way this server does: the PLC directory
/// for `did:plc`, the domain itself for `did:web`.
///
/// An `IdentityResolver` rather than a free function because that is the seam
/// the shared verifier takes, and because it is the seam a cache would go
/// behind.
struct PdsDidResolver<'a> {
    http: &'a reqwest::Client,
    plc_directory_hostname: Option<&'a str>,
}

#[async_trait::async_trait]
impl IdentityResolver for PdsDidResolver<'_> {
    async fn resolve(&self, subject: &str) -> anyhow::Result<Document> {
        use atproto_identity::plc::query as plc_query;
        use atproto_identity::web::query as web_query;

        if subject.starts_with("did:plc:") {
            let host = self.plc_directory_hostname.unwrap_or("plc.directory");
            Ok(plc_query(self.http, host, subject).await?)
        } else if subject.starts_with("did:web:") {
            Ok(web_query(self.http, subject).await?)
        } else {
            anyhow::bail!("unsupported DID method for service-auth verification: {subject}")
        }
    }
}

/// The `com.atproto.admin.revokeServiceAuth` list, as the shared verifier's
/// revocation seam.
///
/// Revocation and single-use are deliberately different things here. This
/// server's notifier mints one token per queued delivery and presents it again
/// on every retry, so enforcing single-use inbound would reject every retry
/// after the first attempt that reached the peer: the delivery fails, backs
/// off, retries with a token the receiver already burned, and fails again
/// until `max_attempts`. What bounds replay instead is the lifetime ceiling in
/// [`policy`].
struct PoolRevocations<'a>(&'a crate::account::AccountPool);

#[async_trait::async_trait]
impl RevocationCheck for PoolRevocations<'_> {
    async fn is_revoked(&self, jti: &str) -> Result<bool, String> {
        crate::service_auth_blacklist::contains(self.0, jti)
            .await
            .map_err(|error| error.to_string())
    }
}

/// Turn a verification failure into this server's denial.
///
/// Every cause becomes [`PdsError::AuthDenied`], which is what the endpoints
/// answer with, but the reason string keeps the shared verifier's identifier
/// so a log line still names which check refused.
fn deny_from(error: ServiceAuthError) -> PdsError {
    if let ServiceAuthError::Revoked { jti } = &error {
        tracing::warn!(jti = %jti, "rejected a revoked service-auth token");
    }
    PdsError::AuthDenied {
        reason: error.to_string(),
    }
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
    service_auth::mint_service_auth(signing_key, iss, aud, lxm, Duration::from_secs(ttl_secs))
        .map_err(|error| PdsError::Storage {
            reason: error.to_string(),
        })
}

/// Verify an inbound service-auth `token` against an expected audience and
/// method.
///
/// # Errors
/// Returns [`PdsError::AuthDenied`] for any verification failure.
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
/// Everything [`verify_service_auth`] checks except `aud`. The caller is then
/// holding *verified* claims and can decide whether the audience is one it
/// will act on.
///
/// This exists for the case where the set of audiences a server accepts is not
/// a single known string. The alternative -- reading `aud` out of the
/// unverified payload and passing it back in as the expected value -- compares
/// the claim to itself, so it always passes and reads in the code as a binding
/// that is not there.
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

async fn verify_inner(
    http: &reqwest::Client,
    token: &str,
    plc_directory_hostname: Option<&str>,
    expected_aud: Option<&str>,
    expected_lxm: &str,
    revocations: Option<&crate::account::AccountPool>,
) -> PdsResult<ServiceAuthClaims> {
    let resolver = PdsDidResolver {
        http,
        plc_directory_hostname,
    };
    let revocations = revocations.map(PoolRevocations);

    service_auth::verify_service_auth(
        token,
        &resolver,
        &policy(expected_lxm, expected_aud),
        revocations
            .as_ref()
            .map(|check| check as &dyn RevocationCheck),
    )
    .await
    .map_err(deny_from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_identity::key::{KeyType, generate_key};
    use base64::{Engine as _, engine::general_purpose};

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

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
            err.to_string().contains("service-auth-5"),
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
            !err.to_string().contains("service-auth-5"),
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
            err.to_string().contains("service-auth-8"),
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
            !err.to_string().contains("service-auth-8"),
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
            err.to_string().contains("service-auth-7"),
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
            !err.to_string().contains("service-auth-7"),
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
            err.to_string().contains("service-auth-4"),
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
            err.to_string().contains("service-auth-2"),
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
            err.to_string().contains("service-auth-3"),
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
            !err.to_string().contains("service-auth-2"),
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
            err.to_string().contains("service-auth-3"),
            "expected an lxm mismatch denial, got: {err}"
        );
    }

    /// A token addressed to one of a service's DID-document entries is
    /// addressed to that service.
    ///
    /// A forwarded `notifyWrite` is minted for the identifier its subscriber
    /// registered, which may name a fragment
    /// (`did:web:syncer.example#atproto_space_syncer`). The receiver knows its
    /// own DID; it does not necessarily know which of its fragments the sender
    /// picked. What is never relaxed is the DID.
    #[test]
    fn a_fragment_bearing_audience_reaches_the_did_that_owns_it() {
        assert!(audience_matches("did:web:x", "did:web:x"));
        assert!(audience_matches(
            "did:web:x#atproto_space_syncer",
            "did:web:x"
        ));

        // A different DID is a different service, fragment or not.
        assert!(!audience_matches(
            "did:web:y#atproto_space_syncer",
            "did:web:x"
        ));
        assert!(!audience_matches("did:web:x", "did:web:y"));

        // An expectation that names a fragment must be met exactly: a token
        // for one of a service's entries is not a token for another.
        assert!(audience_matches("did:web:x#a", "did:web:x#a"));
        assert!(!audience_matches("did:web:x#b", "did:web:x#a"));
        assert!(!audience_matches("did:web:x", "did:web:x#a"));

        // And the relaxation is not a prefix match on the DID itself.
        assert!(!audience_matches("did:web:xyz#a", "did:web:x"));
    }
}
