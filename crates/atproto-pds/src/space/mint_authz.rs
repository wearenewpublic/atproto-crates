//! Mint-time authorization for `com.atproto.space.getSpaceCredential`.
//!
//! A space credential is minted only when **both** axes of the space's
//! `com.atproto.simplespace.defs#spaceConfig` authorize the request:
//!
//! - **USER axis** ([`MintPolicy`]): `public` authorizes anyone; `member-list`
//!   (the default) requires the requesting member DID to be in the space's
//!   member list; `managing-app` delegates the decision to the configured
//!   `managingApp` via [`com.atproto.simplespace.checkUserAccess`].
//! - **APP axis** ([`AppAccess`]): `#open` authorizes any app; `#allowList`
//!   requires the *attested* OAuth `client_id` to be in the `allowed` list.
//!
//! The attested `client_id` is established by verifying the optional
//! `clientAttestation` JWT presented on the request: its `iss`/`sub` is the
//! client-metadata URL, which is fetched, its JWKS resolved, and the key
//! selected by `kid` to verify the JWT signature. When `appAccess` is
//! `#allowList` and no valid attestation is presented the mint is refused with
//! [`MintDenial::AppNotAuthorized`]; under `#open` an attestation is optional.
//!
//! The pure decision helpers ([`user_axis_local`] and [`app_axis`]) carry the
//! decision matrix and are unit-tested directly; the async helpers
//! ([`verify_client_attestation`], [`check_user_access`]) perform the network
//! I/O for the managing-app and attestation paths.

use crate::space::config::{AppAccess, MintPolicy};
use atproto_identity::key::{KeyData, validate as identity_validate};
use atproto_oauth::jwk::WrappedJsonWebKeySet;
use atproto_space::types::SpaceUri;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// Why a credential mint was refused. Each variant maps to one of the
/// documented `getSpaceCredential` lexicon errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintDenial {
    /// `UserNotAuthorized` — refused on the basis of the requesting user
    /// (`member-list` miss, or `managing-app` returned `authorized=false`).
    UserNotAuthorized {
        /// Human-readable reason for diagnostics.
        reason: String,
    },
    /// `AppNotAuthorized` — refused on the basis of the requesting app
    /// (`#allowList` miss, or no/invalid attestation under `#allowList`).
    AppNotAuthorized {
        /// Human-readable reason for diagnostics.
        reason: String,
    },
    /// `InvalidClientAttestation` — a `clientAttestation` was presented but
    /// could not be verified.
    InvalidClientAttestation {
        /// Human-readable reason for diagnostics.
        reason: String,
    },
    /// `NotAuthorized` — refused for a reason not attributable to a single
    /// axis (e.g. the managing-app could not be reached).
    NotAuthorized {
        /// Human-readable reason for diagnostics.
        reason: String,
    },
}

impl MintDenial {
    /// The lexicon error name to surface to clients.
    #[must_use]
    pub fn error_name(&self) -> &'static str {
        match self {
            Self::UserNotAuthorized { .. } => "UserNotAuthorized",
            Self::AppNotAuthorized { .. } => "AppNotAuthorized",
            Self::InvalidClientAttestation { .. } => "InvalidClientAttestation",
            Self::NotAuthorized { .. } => "NotAuthorized",
        }
    }

    /// The diagnostic reason carried alongside the error name.
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::UserNotAuthorized { reason }
            | Self::AppNotAuthorized { reason }
            | Self::InvalidClientAttestation { reason }
            | Self::NotAuthorized { reason } => reason,
        }
    }
}

/// USER-axis decision for the locally-evaluable policies (`public` and
/// `member-list`). The `managing-app` policy is *not* decided here — it
/// requires a network call ([`check_user_access`]) and is signalled by an
/// `Ok(None)` return so the caller knows to consult the managing app.
///
/// - `public` → authorized (returns `Ok(Some(()))`).
/// - `member-list` → authorized iff `is_member`, else
///   [`MintDenial::UserNotAuthorized`].
/// - `managing-app` → `Ok(None)` (defer to [`check_user_access`]).
///
/// # Errors
/// Returns [`MintDenial::UserNotAuthorized`] when a `member-list` space does
/// not contain the requesting member.
pub fn user_axis_local(policy: MintPolicy, is_member: bool) -> Result<Option<()>, MintDenial> {
    match policy {
        MintPolicy::Public => Ok(Some(())),
        MintPolicy::MemberList => {
            if is_member {
                Ok(Some(()))
            } else {
                Err(MintDenial::UserNotAuthorized {
                    reason: "requesting member is not in the space member list".to_string(),
                })
            }
        }
        MintPolicy::ManagingApp => Ok(None),
    }
}

/// APP-axis decision. `attested_client_id` is the *verified* client_id from a
/// validated client attestation, or `None` when no valid attestation was
/// presented.
///
/// - `#open` → authorized regardless of attestation.
/// - `#allowList` → authorized iff a verified `client_id` was presented and is
///   in `allowed`; otherwise [`MintDenial::AppNotAuthorized`].
///
/// # Errors
/// Returns [`MintDenial::AppNotAuthorized`] when an `#allowList` space is not
/// satisfied by the attested client_id.
pub fn app_axis(access: &AppAccess, attested_client_id: Option<&str>) -> Result<(), MintDenial> {
    match access {
        AppAccess::Open => Ok(()),
        AppAccess::AllowList { allowed } => match attested_client_id {
            Some(client_id) if allowed.iter().any(|c| c == client_id) => Ok(()),
            Some(client_id) => Err(MintDenial::AppNotAuthorized {
                reason: format!("attested client_id {client_id} is not on the allow list"),
            }),
            None => Err(MintDenial::AppNotAuthorized {
                reason: "space gates on app identity (#allowList) but no valid client \
                         attestation was presented"
                    .to_string(),
            }),
        },
    }
}

/// `typ` header value a client attestation MUST carry (spec line 184).
pub const TYP_CLIENT_ATTESTATION: &str = "atproto-client-attestation+jwt";

/// Header of a client-attestation JWT (spec lines 183-187). We read `typ`
/// (to reject token-type confusion) and `kid` (to select the verifying key
/// from the resolved JWKS).
#[derive(Debug, Deserialize)]
struct AttestationHeader {
    /// Token type — MUST be `atproto-client-attestation+jwt`.
    #[serde(default)]
    typ: Option<String>,
    /// Key id used to select the JWK from the client's JWKS.
    kid: Option<String>,
}

/// Payload of a client-attestation JWT (spec lines 188-195). Per the spec,
/// `iss == sub == client_id` (the client-metadata URL) and `aud` identifies
/// the space host. `iat`/`exp`/`jti` provide freshness and replay protection.
#[derive(Debug, Deserialize)]
struct AttestationPayload {
    /// Issuer — the OAuth client_id (a client-metadata URL).
    iss: String,
    /// Subject — must equal `iss`.
    sub: String,
    /// Audience — the space host identifier
    /// (`<spaceDid>#atproto_space_host`).
    #[serde(default)]
    aud: Option<String>,
    /// Issued-at (epoch seconds).
    #[serde(default)]
    iat: Option<u64>,
    /// Expiry (epoch seconds).
    #[serde(default)]
    exp: Option<u64>,
    /// Random nonce for replay protection.
    #[serde(default)]
    jti: Option<String>,
}

/// Minimal view of an OAuth client-metadata document — we only need the
/// inline `jwks` or the `jwks_uri` to locate verifying keys.
#[derive(Deserialize)]
struct ClientMetadata {
    #[serde(default)]
    jwks: Option<WrappedJsonWebKeySet>,
    #[serde(default)]
    jwks_uri: Option<String>,
}

/// The audience a client attestation (and delegation token) must target: the
/// space host service fragment derived from the space DID
/// (`<spaceDid>#atproto_space_host`, spec line 166/191).
#[must_use]
pub fn space_host_audience(space_did: &str) -> String {
    atproto_space::credential::space_host_audience(space_did)
}

/// Maximum accepted lifetime of a client attestation. The spec calls the
/// attestation "short-lived" (example `exp = iat + 60`); we reject any
/// attestation whose stated lifetime exceeds five minutes to bound the replay
/// window even before the `jti` guard records it.
const MAX_ATTESTATION_LIFETIME_SECS: u64 = 300;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Verify a client-attestation compact JWT and return the verified
/// `client_id` (its `iss`/`sub`).
///
/// Checks the header `typ` is `atproto-client-attestation+jwt`, that
/// `iss == sub == client_id` (an HTTPS client-metadata URL), that `aud`
/// targets this space host, that `iat`/`exp` are present and the attestation
/// is unexpired and not over-long-lived, and that `jti` is present and unseen
/// (consumed via `jti_guard` for replay protection). It then resolves the
/// issuer's client-metadata document → JWKS → key by `kid` and verifies the
/// JWS signature.
///
/// # Errors
/// Returns [`MintDenial::InvalidClientAttestation`] for any malformed,
/// unresolvable, mis-targeted, replayed, or signature-invalid attestation.
pub async fn verify_client_attestation(
    http: &reqwest::Client,
    jti_guard: &crate::security::JtiReplayGuard,
    attestation: &str,
    space: &SpaceUri,
) -> Result<String, MintDenial> {
    let invalid = |reason: String| MintDenial::InvalidClientAttestation { reason };

    let parts: Vec<&str> = attestation.split('.').collect();
    if parts.len() != 3 {
        return Err(invalid("attestation is not a compact JWS".to_string()));
    }
    let header_bytes = B64URL
        .decode(parts[0].as_bytes())
        .map_err(|e| invalid(format!("header not base64url: {e}")))?;
    let header: AttestationHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| invalid(format!("header not JSON: {e}")))?;
    let payload_bytes = B64URL
        .decode(parts[1].as_bytes())
        .map_err(|e| invalid(format!("payload not base64url: {e}")))?;
    let payload: AttestationPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| invalid(format!("payload not JSON: {e}")))?;

    // typ header MUST be the client-attestation token type.
    match header.typ.as_deref() {
        Some(TYP_CLIENT_ATTESTATION) => {}
        Some(other) => {
            return Err(invalid(format!(
                "header typ {other} is not {TYP_CLIENT_ATTESTATION}"
            )));
        }
        None => return Err(invalid("attestation header missing typ".to_string())),
    }

    // iss == sub == client_id, both an HTTPS client-metadata URL.
    if payload.iss != payload.sub {
        return Err(invalid("iss != sub".to_string()));
    }
    let client_id = payload.iss.clone();
    if !client_id.starts_with("https://") {
        return Err(invalid(format!(
            "client_id is not an https client-metadata URL: {client_id}"
        )));
    }

    // aud must target this space host.
    let expected_aud = space_host_audience(&space.space_did);
    match payload.aud.as_deref() {
        Some(aud) if aud == expected_aud => {}
        Some(aud) => {
            return Err(invalid(format!(
                "aud {aud} does not target space host {expected_aud}"
            )));
        }
        None => return Err(invalid("attestation missing aud".to_string())),
    }

    // iat and exp are required; the attestation must be unexpired and bounded
    // to a short lifetime (spec lines 192-193).
    let now = now_secs();
    let iat = payload
        .iat
        .ok_or_else(|| invalid("attestation missing iat".to_string()))?;
    let exp = payload
        .exp
        .ok_or_else(|| invalid("attestation missing exp".to_string()))?;
    if exp <= now {
        return Err(invalid("attestation expired".to_string()));
    }
    if exp <= iat || exp - iat > MAX_ATTESTATION_LIFETIME_SECS {
        return Err(invalid(format!(
            "attestation lifetime exceeds {MAX_ATTESTATION_LIFETIME_SECS}s"
        )));
    }

    // jti is required and single-use (spec line 194). Consume it before the
    // signature is checked so a replayed nonce is rejected regardless.
    let jti = payload
        .jti
        .as_deref()
        .ok_or_else(|| invalid("attestation missing jti".to_string()))?;
    let ttl = std::time::Duration::from_secs(exp.saturating_sub(now));
    jti_guard
        .check_and_insert(jti, ttl)
        .await
        .map_err(|_| invalid("attestation jti already used (replay)".to_string()))?;

    // Resolve the client-metadata document.
    let metadata: ClientMetadata = http
        .get(&client_id)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| invalid(format!("fetch client-metadata {client_id}: {e}")))?
        .error_for_status()
        .map_err(|e| invalid(format!("client-metadata {client_id} status: {e}")))?
        .json()
        .await
        .map_err(|e| invalid(format!("parse client-metadata {client_id}: {e}")))?;

    // Resolve the JWKS (inline `jwks` wins; else fetch `jwks_uri`).
    let jwks: WrappedJsonWebKeySet = match (metadata.jwks, metadata.jwks_uri) {
        (Some(jwks), _) => jwks,
        (None, Some(uri)) => http
            .get(&uri)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| invalid(format!("fetch jwks_uri {uri}: {e}")))?
            .error_for_status()
            .map_err(|e| invalid(format!("jwks_uri {uri} status: {e}")))?
            .json()
            .await
            .map_err(|e| invalid(format!("parse jwks_uri {uri}: {e}")))?,
        (None, None) => {
            return Err(invalid(
                "client-metadata has neither jwks nor jwks_uri".to_string(),
            ));
        }
    };

    // Select the verifying key by kid (or the sole key when no kid is given).
    let wrapped = match header.kid.as_deref() {
        Some(kid) => jwks
            .keys
            .iter()
            .find(|k| k.kid.as_deref() == Some(kid))
            .ok_or_else(|| invalid(format!("no JWK with kid {kid}")))?,
        None if jwks.keys.len() == 1 => &jwks.keys[0],
        None => {
            return Err(invalid(
                "attestation header has no kid and JWKS has multiple keys".to_string(),
            ));
        }
    };
    let verifying_key: KeyData = wrapped
        .try_into()
        .map_err(|e| invalid(format!("JWK is not a usable verifying key: {e}")))?;

    // Verify the JWS signature over `header.payload`.
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = B64URL
        .decode(parts[2].as_bytes())
        .map_err(|e| invalid(format!("signature not base64url: {e}")))?;
    identity_validate(&verifying_key, &sig, signing_input.as_bytes())
        .map_err(|e| invalid(format!("attestation signature invalid: {e}")))?;

    Ok(client_id)
}

/// Output of `com.atproto.simplespace.checkUserAccess`.
#[derive(Debug, Deserialize)]
struct CheckUserAccessOutput {
    authorized: bool,
}

/// Ask the space's `managingApp` whether to authorize the requesting user, by
/// calling `com.atproto.simplespace.checkUserAccess` on the managing-app
/// service with a service-auth bearer issued by the space authority
/// (`iss=owner_did`, `aud=managing_app`).
///
/// The `service_endpoint` is the base URL of the managing-app service (already
/// resolved by the caller from the `managingApp` service identifier);
/// `managing_app` is the service identifier used as the JWT audience.
///
/// # Errors
/// Returns [`MintDenial::UserNotAuthorized`] when the managing app answers
/// `authorized=false`, or [`MintDenial::NotAuthorized`] when the call could
/// not be completed (network/sign failure) — the latter is not attributable
/// to a single axis.
#[allow(clippy::too_many_arguments)]
pub async fn check_user_access(
    http: &reqwest::Client,
    service_endpoint: &str,
    managing_app: &str,
    owner_signing_key: &KeyData,
    owner_did: &str,
    space: &SpaceUri,
    user_did: &str,
    attested_client_id: Option<&str>,
) -> Result<(), MintDenial> {
    let token = mint_check_user_access_service_auth(owner_did, managing_app, owner_signing_key)
        .map_err(|reason| MintDenial::NotAuthorized { reason })?;

    let endpoint = format!(
        "{base}/xrpc/com.atproto.simplespace.checkUserAccess",
        base = service_endpoint.trim_end_matches('/')
    );
    let mut query: Vec<(&str, String)> =
        vec![("space", space.to_string()), ("user", user_did.to_string())];
    if let Some(client_id) = attested_client_id {
        query.push(("clientId", client_id.to_string()));
    }

    let response = http
        .get(&endpoint)
        .query(&query)
        .bearer_auth(&token)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| MintDenial::NotAuthorized {
            reason: format!("checkUserAccess request to {endpoint} failed: {e}"),
        })?
        .error_for_status()
        .map_err(|e| MintDenial::NotAuthorized {
            reason: format!("checkUserAccess {endpoint} returned error status: {e}"),
        })?;

    let output: CheckUserAccessOutput =
        response
            .json()
            .await
            .map_err(|e| MintDenial::NotAuthorized {
                reason: format!("parse checkUserAccess response: {e}"),
            })?;

    if output.authorized {
        Ok(())
    } else {
        Err(MintDenial::UserNotAuthorized {
            reason: "managing app refused (checkUserAccess authorized=false)".to_string(),
        })
    }
}

/// Service-auth JWT header.
#[derive(serde::Serialize)]
struct ServiceAuthHeader {
    alg: String,
    typ: &'static str,
}

/// Service-auth JWT claims, scoped to the `checkUserAccess` lexicon method.
#[derive(serde::Serialize)]
struct ServiceAuthClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    lxm: &'a str,
    iat: u64,
    exp: u64,
    jti: String,
}

/// Mint a 60-second `at+jwt` service-auth token signed by the owner's signing
/// key, scoped to `com.atproto.simplespace.checkUserAccess`.
fn mint_check_user_access_service_auth(
    owner_did: &str,
    managing_app: &str,
    signing_key: &KeyData,
) -> Result<String, String> {
    let iat = now_secs();
    let exp = iat + 60;
    let jti = {
        let mut bytes = [0u8; 16];
        use rand::RngExt;
        rand::rng().fill(&mut bytes);
        B64URL.encode(bytes)
    };
    let header = ServiceAuthHeader {
        alg: atproto_identity::key::jws_alg(signing_key).to_string(),
        typ: "at+jwt",
    };
    let payload = ServiceAuthClaims {
        iss: owner_did,
        aud: managing_app,
        lxm: "com.atproto.simplespace.checkUserAccess",
        iat,
        exp,
        jti,
    };
    let header_bytes =
        serde_json::to_vec(&header).map_err(|e| format!("serialize service-auth header: {e}"))?;
    let payload_bytes =
        serde_json::to_vec(&payload).map_err(|e| format!("serialize service-auth payload: {e}"))?;
    let signing_input = format!(
        "{}.{}",
        B64URL.encode(&header_bytes),
        B64URL.encode(&payload_bytes)
    );
    let sig = atproto_identity::key::sign(signing_key, signing_input.as_bytes())
        .map_err(|e| format!("sign service-auth: {e}"))?;
    Ok(format!("{}.{}", signing_input, B64URL.encode(&sig)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow_list(ids: &[&str]) -> AppAccess {
        AppAccess::AllowList {
            allowed: ids.iter().map(|s| s.to_string()).collect(),
        }
    }

    // --- USER axis ---------------------------------------------------------

    #[test]
    fn user_axis_public_authorizes_anyone() {
        assert_eq!(user_axis_local(MintPolicy::Public, false), Ok(Some(())));
        assert_eq!(user_axis_local(MintPolicy::Public, true), Ok(Some(())));
    }

    #[test]
    fn user_axis_member_list_allows_member() {
        assert_eq!(user_axis_local(MintPolicy::MemberList, true), Ok(Some(())));
    }

    #[test]
    fn user_axis_member_list_denies_non_member() {
        let r = user_axis_local(MintPolicy::MemberList, false);
        assert!(matches!(r, Err(MintDenial::UserNotAuthorized { .. })));
        assert_eq!(r.unwrap_err().error_name(), "UserNotAuthorized");
    }

    #[test]
    fn user_axis_managing_app_defers() {
        assert_eq!(user_axis_local(MintPolicy::ManagingApp, false), Ok(None));
        assert_eq!(user_axis_local(MintPolicy::ManagingApp, true), Ok(None));
    }

    // --- APP axis ----------------------------------------------------------

    #[test]
    fn app_axis_open_allows_with_or_without_attestation() {
        assert_eq!(app_axis(&AppAccess::Open, None), Ok(()));
        assert_eq!(
            app_axis(&AppAccess::Open, Some("https://app.example")),
            Ok(())
        );
    }

    #[test]
    fn app_axis_allow_list_allows_listed_client() {
        let access = allow_list(&["https://a.example", "https://b.example"]);
        assert_eq!(app_axis(&access, Some("https://b.example")), Ok(()));
    }

    #[test]
    fn app_axis_allow_list_denies_unlisted_client() {
        let access = allow_list(&["https://a.example"]);
        let r = app_axis(&access, Some("https://evil.example"));
        assert!(matches!(r, Err(MintDenial::AppNotAuthorized { .. })));
        assert_eq!(r.unwrap_err().error_name(), "AppNotAuthorized");
    }

    #[test]
    fn app_axis_allow_list_denies_when_no_attestation() {
        let access = allow_list(&["https://a.example"]);
        let r = app_axis(&access, None);
        assert!(matches!(r, Err(MintDenial::AppNotAuthorized { .. })));
    }

    // --- combined matrix ---------------------------------------------------

    #[test]
    fn matrix_public_open_allows() {
        assert!(user_axis_local(MintPolicy::Public, false).is_ok());
        assert!(app_axis(&AppAccess::Open, None).is_ok());
    }

    #[test]
    fn matrix_member_list_allow_list_requires_both() {
        // member + listed app -> ok on both axes
        assert!(user_axis_local(MintPolicy::MemberList, true).is_ok());
        let access = allow_list(&["https://app.example"]);
        assert!(app_axis(&access, Some("https://app.example")).is_ok());

        // non-member fails user axis even with a listed app
        assert!(user_axis_local(MintPolicy::MemberList, false).is_err());

        // member but unlisted app fails app axis
        assert!(app_axis(&access, Some("https://other.example")).is_err());
    }

    #[test]
    fn denial_reasons_are_populated() {
        let d = user_axis_local(MintPolicy::MemberList, false).unwrap_err();
        assert!(!d.reason().is_empty());
    }

    #[test]
    fn space_host_audience_format() {
        assert_eq!(
            space_host_audience("did:plc:owner"),
            "did:plc:owner#atproto_space_host"
        );
    }

    #[test]
    fn attestation_rejects_non_compact_jws() {
        // Build a client that will never be used (decode fails first).
        let http = reqwest::Client::new();
        let space = SpaceUri::new(
            "did:plc:owner".to_string(),
            atproto_space::types::SpaceType::new("app.bsky.group").unwrap(),
            atproto_space::types::SpaceKey::new("k").unwrap(),
        );
        let guard = crate::security::JtiReplayGuard::new(16);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let r = rt.block_on(verify_client_attestation(
            &http,
            &guard,
            "not-a-jwt",
            &space,
        ));
        assert!(matches!(
            r,
            Err(MintDenial::InvalidClientAttestation { .. })
        ));
    }
}
