//! Inter-service auth: minting and verifying AT Protocol service-auth JWTs.
//!
//! A service-auth token is a compact JWS signed by the issuer's `#atproto`
//! signing key, carrying `iss` / `aud` / `lxm` / `iat` / `exp` / `jti`. It is
//! how one AT Protocol service proves to another that it is who it says and
//! that this request is the one it was authorized to make.
//!
//! # What a verifier has to check, and what usually gets missed
//!
//! Checking the signature against the issuer's published key is the part
//! everybody writes. Five more decide whether the token means anything:
//!
//! * **`lxm` present and matching.** A token scoped to *no* method satisfies
//!   every method that gates on one, which makes any service-auth token in
//!   existence a wildcard credential. [`ServiceAuthPolicy`] has no "any
//!   method" option for that reason.
//! * **`kid` naming this issuer's own `#atproto`.** A `did:web` document is
//!   served by whoever controls the domain, so it can list a verification
//!   method belonging to a different DID. Matching the fragment alone hands
//!   over somebody else's key.
//! * **`iat` not in the future.** The lifetime ceiling below is measured from
//!   `iat`, so an `iat` the issuer places anywhere makes the ceiling free too.
//! * **A ceiling on `exp - iat`.** Without one a peer mints a token good for a
//!   decade and it stays good until somebody notices it leaked. The ceiling is
//!   what makes the credential short-lived whether or not anyone notices.
//! * **Revocation.** Optional, because the store is the caller's, but an
//!   endpoint that accepts a revoked token while an admin API reports success
//!   is a security control that reads as working and is not.
//!
//! # Ordering
//!
//! The claim checks run **before** the DID-document resolution. A token
//! addressed elsewhere or scoped to another method should not buy a network
//! round trip, and a verifier that resolves first turns every malformed token
//! into load on somebody else's host.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use atproto_identity::key::{KeyData, identify_key, jws_alg, sign, validate};
use atproto_identity::traits::IdentityResolver;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::errors::ServiceAuthError;

/// `typ` header value for service-auth JWTs.
///
/// `JWT`, which is what the AT Protocol service-auth specification says and
/// what every implementation in this ecosystem emits. Not `at+jwt`: that is
/// the OAuth access-token media type, a different credential with a different
/// verifier.
pub const TYP_SERVICE_AUTH: &str = "JWT";

/// The only verification method a service-auth token is verified against.
///
/// Proposal 0014: "Receiving services should _not_ accept arbitrary key types
/// (`kid` values): they should only accept key types relevant to their
/// use-case. A safe default for SDKs and services is to only accept
/// `#atproto`." Service auth is the atproto signing key's use-case and no
/// other, so this is that default rather than a limitation to widen later.
pub const SERVICE_AUTH_KID: &str = "#atproto";

/// A sane ceiling on how long a service-auth token may be valid for.
///
/// One hour, which is what the reference implementation's `getServiceAuth`
/// clamps its own tokens to.
pub const DEFAULT_MAX_LIFETIME: Duration = Duration::from_secs(60 * 60);

/// Tolerance for honest clock drift between peers.
pub const DEFAULT_CLOCK_SKEW: Duration = Duration::from_secs(60);

/// Service-auth JWT header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAuthHeader {
    /// Signature algorithm.
    pub alg: String,
    /// Token type.
    pub typ: String,
    /// Which verification method in the issuer's DID document signed this.
    ///
    /// Proposal 0014: "The `kid` JWT header field will be allowed to identify
    /// a signing key ('verification method') from the issuer DID document
    /// (including the `#` character), with a default value of `#atproto`."
    ///
    /// Optional, so absent decodes as the default rather than as an error --
    /// a peer that predates the field is not malformed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// Service-auth JWT claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAuthClaims {
    /// Issuer DID: who signed this.
    pub iss: String,
    /// Audience: the service this token is for. May carry a `#fragment`
    /// naming which of that service's entries the request is addressed to.
    pub aud: String,
    /// NSID of the single method this token authorizes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lxm: Option<String>,
    /// Issued-at, epoch seconds.
    pub iat: u64,
    /// Expiry, epoch seconds.
    pub exp: u64,
    /// Nonce, and the handle a revocation names.
    pub jti: String,
}

/// What a verifier will accept.
#[derive(Debug, Clone)]
pub struct ServiceAuthPolicy<'a> {
    /// The method this token must be scoped to.
    ///
    /// Required. A token with no `lxm`, or a different one, is refused. There
    /// is deliberately no "any method" option: a token scoped to nothing
    /// satisfies every method that gates on one, which makes any service-auth
    /// token in existence a wildcard credential here.
    pub lxm: &'a str,

    /// The audience this token must name.
    ///
    /// `None` when the caller decides the audience itself -- it is then
    /// holding *verified* claims and can inspect `aud` safely. **Never pass
    /// the token's own `aud` here**: that compares the claim to itself, so it
    /// always passes and reads in the code as a binding that is not there.
    pub aud: Option<&'a str>,

    /// Ceiling on `exp - iat`, which bounds a leaked token's usefulness
    /// without anyone having to notice it leaked.
    pub max_lifetime: Duration,

    /// Tolerance for honest clock drift on `iat`.
    ///
    /// `exp` is compared exactly, because a token that has expired by any
    /// margin has expired.
    pub clock_skew: Duration,
}

impl<'a> ServiceAuthPolicy<'a> {
    /// A policy scoped to `lxm` and `aud`, with the default lifetime ceiling
    /// and clock skew.
    #[must_use]
    pub fn new(lxm: &'a str, aud: &'a str) -> Self {
        Self {
            lxm,
            aud: Some(aud),
            max_lifetime: DEFAULT_MAX_LIFETIME,
            clock_skew: DEFAULT_CLOCK_SKEW,
        }
    }

    /// A policy that leaves the audience to the caller.
    ///
    /// For the case where the set of audiences a service accepts is not a
    /// single known string -- a delivery legitimately addressed to either a
    /// registered service identifier or the authority's own DID, say. The
    /// caller inspects `aud` on the *verified* claims, where the comparison is
    /// against something it decided rather than against the token itself.
    #[must_use]
    pub fn unaudienced(lxm: &'a str) -> Self {
        Self {
            lxm,
            aud: None,
            max_lifetime: DEFAULT_MAX_LIFETIME,
            clock_skew: DEFAULT_CLOCK_SKEW,
        }
    }

    /// Set the lifetime ceiling.
    #[must_use]
    pub fn max_lifetime(mut self, max_lifetime: Duration) -> Self {
        self.max_lifetime = max_lifetime;
        self
    }

    /// Set the clock-skew tolerance.
    #[must_use]
    pub fn clock_skew(mut self, clock_skew: Duration) -> Self {
        self.clock_skew = clock_skew;
        self
    }
}

/// The revocation list, as a trait so the storage stays the caller's.
#[async_trait]
pub trait RevocationCheck: Send + Sync {
    /// Whether this `jti` has been revoked.
    ///
    /// Returning `Err` refuses the token. A revocation list that cannot be
    /// read is not a list that said no, but it is also not one that said yes,
    /// and the safe reading of "I could not check" is to refuse.
    async fn is_revoked(&self, jti: &str) -> Result<bool, String>;
}

#[async_trait]
impl<T: RevocationCheck + ?Sized> RevocationCheck for std::sync::Arc<T> {
    async fn is_revoked(&self, jti: &str) -> Result<bool, String> {
        (**self).is_revoked(jti).await
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Whether a verification-method identifier names *this* issuer's `#atproto`
/// key.
///
/// A DID document may write a method id in full (`did:plc:abc#atproto`) or
/// relative to itself (`#atproto`), and both mean the same key.
///
/// What it must not do is match on the fragment alone.
/// `ends_with("#atproto")` accepts `did:web:somebody-else#atproto`, so a
/// document listing a method belonging to another DID -- which a hostile
/// `did:web` document is free to do, since it is served by whoever controls
/// the domain -- supplies the key that service-auth tokens are then verified
/// against. The identifier has to be the issuer's own.
#[must_use]
pub fn is_atproto_kid(id: &str, issuer_did: &str) -> bool {
    id == SERVICE_AUTH_KID || id == format!("{issuer_did}{SERVICE_AUTH_KID}")
}

/// Whether a token's `aud` satisfies an expected audience, allowing the token
/// to name a service fragment the expectation leaves open.
///
/// `did:web:x#atproto_space_syncer` satisfies an expectation of `did:web:x`,
/// because the fragment selects which of the receiver's service entries the
/// request is for and the receiver is the same either way. It does **not**
/// satisfy `did:web:y`, and an expectation that names a fragment must be met
/// exactly -- a token for one of a service's entries is not a token for
/// another.
#[must_use]
pub fn audience_matches(token_aud: &str, expected: &str) -> bool {
    if token_aud == expected {
        return true;
    }
    // Only the token may carry the extra fragment, never the expectation.
    !expected.contains('#')
        && token_aud
            .split_once('#')
            .is_some_and(|(did, _)| did == expected)
}

/// Mint a service-auth JWT signed with a local private signing key.
///
/// # Errors
///
/// Returns [`ServiceAuthError::Minting`] if the claims cannot be encoded or
/// the token cannot be signed.
pub fn mint_service_auth(
    signing_key: &KeyData,
    iss: &str,
    aud: &str,
    lxm: &str,
    ttl: Duration,
) -> Result<String, ServiceAuthError> {
    let iat = now_secs();
    let header = ServiceAuthHeader {
        alg: jws_alg(signing_key).to_string(),
        typ: TYP_SERVICE_AUTH.to_string(),
        // Stated rather than left to the default, so a verifier that resolves
        // `kid` and one that assumes `#atproto` agree explicitly instead of by
        // coincidence.
        kid: Some(SERVICE_AUTH_KID.to_string()),
    };
    let claims = ServiceAuthClaims {
        iss: iss.to_string(),
        aud: aud.to_string(),
        lxm: Some(lxm.to_string()),
        iat,
        exp: iat + ttl.as_secs(),
        jti: random_jti(),
    };

    let mint = |reason: String| ServiceAuthError::Minting { reason };
    let header_bytes = serde_json::to_vec(&header).map_err(|e| mint(e.to_string()))?;
    let claims_bytes = serde_json::to_vec(&claims).map_err(|e| mint(e.to_string()))?;
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&header_bytes),
        URL_SAFE_NO_PAD.encode(&claims_bytes)
    );
    let signature = sign(signing_key, signing_input.as_bytes()).map_err(|e| mint(e.to_string()))?;

    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(&signature)
    ))
}

fn random_jti() -> String {
    use rand::RngExt as _;
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Verify an inbound service-auth bearer.
///
/// Claim checks run before the DID-document resolution, deliberately: a token
/// addressed elsewhere or scoped to another method should not buy a network
/// round trip.
///
/// Returns the verified claims. A caller holding them may inspect `aud`
/// safely; a caller that inspects an *unverified* payload and passes the
/// result back in as the expected audience has compared the claim to itself.
///
/// # Errors
///
/// Returns the [`ServiceAuthError`] naming what did not check out.
pub async fn verify_service_auth(
    token: &str,
    resolver: &dyn IdentityResolver,
    policy: &ServiceAuthPolicy<'_>,
    revoked: Option<&dyn RevocationCheck>,
) -> Result<ServiceAuthClaims, ServiceAuthError> {
    let mut parts = token.split('.');
    let (Some(header_b64), Some(payload_b64), Some(sig_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ServiceAuthError::Malformed {
            reason: "expected three dot-separated segments".to_string(),
        });
    };

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64.as_bytes())
        .map_err(|_| ServiceAuthError::Malformed {
            reason: "payload is not base64url".to_string(),
        })?;
    let claims: ServiceAuthClaims =
        serde_json::from_slice(&payload_bytes).map_err(|_| ServiceAuthError::Malformed {
            reason: "payload is not service-auth claims".to_string(),
        })?;

    // ---- Claim checks, before any resolution. ----

    if let Some(expected) = policy.aud
        && !audience_matches(&claims.aud, expected)
    {
        return Err(ServiceAuthError::Audience {
            token: claims.aud,
            expected: expected.to_string(),
        });
    }

    match claims.lxm.as_deref() {
        Some(lxm) if lxm == policy.lxm => {}
        Some(lxm) => {
            return Err(ServiceAuthError::Method {
                token: lxm.to_string(),
                expected: policy.lxm.to_string(),
            });
        }
        None => {
            return Err(ServiceAuthError::Unscoped {
                expected: policy.lxm.to_string(),
            });
        }
    }

    let header: ServiceAuthHeader = URL_SAFE_NO_PAD
        .decode(header_b64.as_bytes())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| ServiceAuthError::Malformed {
            reason: "header is not a service-auth header".to_string(),
        })?;

    // Absent `kid` is the specified default and stays acceptable. Present and
    // naming anything but this issuer's own `#atproto` is refused here rather
    // than left to fail as "signature invalid", which says nothing about the
    // actual disagreement -- and which would not fail at all if the key it
    // named happened to be one the attacker controls.
    if let Some(kid) = header.kid.as_deref()
        && !is_atproto_kid(kid, &claims.iss)
    {
        return Err(ServiceAuthError::KeyIdentifier {
            kid: kid.to_string(),
            iss: claims.iss.clone(),
        });
    }

    let now = now_secs();
    if claims.exp <= now {
        return Err(ServiceAuthError::Expired {
            exp: claims.exp,
            now,
        });
    }

    if claims.iat > now.saturating_add(policy.clock_skew.as_secs()) {
        return Err(ServiceAuthError::IssuedInTheFuture {
            iat: claims.iat,
            now,
        });
    }

    let lifetime = claims.exp.saturating_sub(claims.iat);
    if lifetime > policy.max_lifetime.as_secs() {
        return Err(ServiceAuthError::LifetimeTooLong {
            lifetime,
            ceiling: policy.max_lifetime.as_secs(),
        });
    }

    if let Some(revoked) = revoked {
        let is_revoked = revoked
            .is_revoked(&claims.jti)
            .await
            .map_err(|reason| ServiceAuthError::RevocationUnavailable { reason })?;
        if is_revoked {
            return Err(ServiceAuthError::Revoked {
                jti: claims.jti.clone(),
            });
        }
    }

    // ---- And only now, the network. ----

    let document = resolver.resolve(&claims.iss).await.map_err(|error| {
        ServiceAuthError::IssuerUnresolved {
            iss: claims.iss.clone(),
            reason: error.to_string(),
        }
    })?;

    let multibase = document
        .verification_method_multibase("atproto")
        .ok_or_else(|| ServiceAuthError::NoSigningKey {
            iss: claims.iss.clone(),
        })?;
    let did_key = if multibase.starts_with("did:key:") {
        multibase.to_string()
    } else {
        format!("did:key:{multibase}")
    };
    let key = identify_key(&did_key).map_err(|error| ServiceAuthError::IssuerUnresolved {
        iss: claims.iss.clone(),
        reason: error.to_string(),
    })?;

    let signature =
        URL_SAFE_NO_PAD
            .decode(sig_b64.as_bytes())
            .map_err(|_| ServiceAuthError::Malformed {
                reason: "signature is not base64url".to_string(),
            })?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    validate(&key, &signature, signing_input.as_bytes()).map_err(|_| {
        ServiceAuthError::Signature {
            iss: claims.iss.clone(),
        }
    })?;

    Ok(claims)
}
