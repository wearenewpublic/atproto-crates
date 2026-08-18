//! The 0016 credential chain: three hops across two servers.

use atproto_client::client::DpopPresentation;
use atproto_identity::key::KeyData;
use atproto_space::SpaceUri;
use atproto_space::credential::SpaceCredential;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::Method;
use serde::Deserialize;

use crate::errors::SpaceClientError;
use crate::methods;
use crate::transport::{Call, method_url};

/// The two servers a subscription talks to.
///
/// **A struct rather than two more `&str` parameters.** Here that is not a
/// hypothetical hazard: the bug this type exists to prevent is one that
/// shipped, where a single host stood in for both and two of the three hops
/// went to a server that had never heard of the space. It was invisible for as
/// long as every space was the account's own, because there the member *is*
/// the authority and the two strings are equal. Swapping them now requires
/// writing the field names the wrong way round.
#[derive(Debug, Clone, Copy)]
pub struct SpaceHosts<'a> {
    /// The subscribing identity's own personal data server. Hop 1 only.
    pub member_pds: &'a str,
    /// The space's host -- the authority's. Hops 2 and 3.
    pub authority: &'a str,
}

/// Where `notifyWrite` should be delivered.
#[derive(Debug, Clone, Copy)]
pub enum Delivery<'a> {
    /// A service identifier: a DID with an optional service fragment naming
    /// the entry in its DID document to deliver to, e.g.
    /// `did:web:syncer.example#atproto_space_syncer`.
    ///
    /// The preferred shape, and the reason is that `notifyWrite` is delivered
    /// with service auth *addressed to* this identifier. A bare URL cannot be
    /// an audience, so a subscriber that registers one leaves every delivery
    /// unverifiable by whoever receives it.
    Service(&'a str),

    /// A bare endpoint URL.
    ///
    /// The pre-lexicon shape, kept because deployed subscribers use it.
    /// Superseded by [`Delivery::Service`], which supplies both the audience
    /// and the endpoint.
    Endpoint(&'a str),
}

impl Delivery<'_> {
    /// The target as the server will see it.
    fn target(&self) -> &str {
        match self {
            Delivery::Service(service) => service,
            Delivery::Endpoint(endpoint) => endpoint,
        }
    }

    /// Whether this is something a subscription can be registered for.
    ///
    /// Checked before hop 0. Hops 1 and 2 spend a single-use grant, so
    /// discovering at hop 3 that the target was never registrable means the
    /// grant was burnt to learn a fact that was knowable before hop 1 ran.
    fn validate(&self) -> Result<(), SpaceClientError> {
        let invalid = |reason: &str| SpaceClientError::InvalidDelivery {
            target: self.target().to_string(),
            reason: reason.to_string(),
        };

        match self {
            Delivery::Service(service) => {
                let did = service.split('#').next().unwrap_or_default();
                if !did.starts_with("did:") {
                    return Err(invalid("a service identifier must be a DID"));
                }
                if did.split(':').count() < 3 {
                    return Err(invalid("a DID needs a method and a method-specific id"));
                }
                Ok(())
            }
            Delivery::Endpoint(endpoint) => {
                let url = url::Url::parse(endpoint)
                    .map_err(|error| invalid(&format!("not a URL: {error}")))?;
                if url.scheme() != "https" {
                    return Err(invalid("a delivery endpoint must be https"));
                }
                if !url.has_host() {
                    return Err(invalid("a delivery endpoint must name a host"));
                }
                Ok(())
            }
        }
    }
}

/// Output of `getDelegationToken`.
#[derive(Debug, Deserialize)]
struct DelegationTokenResponse {
    token: String,
}

/// Output of `getSpaceCredential`.
#[derive(Debug, Deserialize)]
struct SpaceCredentialResponse {
    credential: String,
}

/// Output of `registerNotify`.
#[derive(Debug, Deserialize)]
struct RegisterNotifyResponse {
    #[serde(rename = "expiresAt")]
    expires_at: String,
}

/// A space credential as it came back from the authority.
#[derive(Debug, Clone)]
pub struct SpaceCredentialGrant {
    /// The credential in its compact form. This is what goes on the wire.
    pub token: String,

    /// The credential's claims, **decoded and not verified**.
    ///
    /// The signature is not checked here, and the reason is worth stating
    /// rather than leaving to be discovered: checking it means resolving the
    /// authority's `#atproto_space` verification method, which is a second
    /// network call and a key-caching policy this function has no business
    /// choosing. What the claims are for here is `exp` and `sub` -- when to
    /// re-mint, and which space this is -- read from a document that arrived
    /// over TLS in direct answer to a request this client made.
    ///
    /// A caller that passes the credential onward, or that does not trust the
    /// path it arrived over, should check it with
    /// [`atproto_space::verify_space_credential`] and the authority's key.
    pub claims: SpaceCredential,
}

impl SpaceCredentialGrant {
    /// Decode a compact credential's claims without verifying its signature.
    fn decode(host: &str, token: String) -> Result<Self, SpaceClientError> {
        let invalid = |reason: String| SpaceClientError::InvalidCredential {
            host: host.to_string(),
            reason,
        };

        let payload = token
            .split('.')
            .nth(1)
            .ok_or_else(|| invalid("not a compact JWS".to_string()))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(payload.as_bytes())
            .map_err(|error| invalid(format!("payload is not base64url: {error}")))?;
        let claims: SpaceCredential = serde_json::from_slice(&bytes)
            .map_err(|error| invalid(format!("payload is not a space credential: {error}")))?;

        Ok(Self { token, claims })
    }
}

/// A registered subscription and the credential that made it.
#[derive(Debug, Clone)]
pub struct Subscription {
    /// The credential, still usable for reads until it expires.
    pub credential: SpaceCredentialGrant,
    /// When the *registration* expires, as the authority stated it.
    ///
    /// Read from the answer and never assumed. `atproto-pds` takes this from
    /// `PDS_SPACE_REGISTER_NOTIFY_TTL_SECONDS`, default 60 days, clamped to
    /// 60s..365d -- a four-order-of-magnitude range, so a client that assumed
    /// 24 hours would silently stop receiving deliveries on most of it.
    pub expires_at: String,
}

/// Hops 1 and 2: a DPoP-bound credential for reading a space.
///
/// `access_token` is the member's OAuth access token, bound to `dpop_key`.
///
/// # Errors
///
/// Returns [`SpaceClientError::Refused`] when either server refuses. Hop 1 is
/// refused for an app-password session -- the delegation token asserts that an
/// application is acting for this user, which a password session cannot
/// express -- and hop 2 for a member the space does not admit.
///
/// A missing or malformed DPoP proof at hop 2 answers `InvalidDpopProof` and
/// never reaches the part of the exchange that would say anything about
/// membership: the proof is verified *before* the delegation token,
/// deliberately, so a caller with a bad proof does not burn its single-use
/// grant finding out.
pub async fn space_read_credential(
    http: &reqwest::Client,
    hosts: SpaceHosts<'_>,
    dpop_key: &KeyData,
    access_token: &str,
    space: &SpaceUri,
) -> Result<SpaceCredentialGrant, SpaceClientError> {
    let space_uri = space.to_string();

    // Hop 1, at the member's own PDS. A bound token: this is an ordinary
    // authenticated read of the member's own session.
    let url = method_url(
        hosts.member_pds,
        methods::GET_DELEGATION_TOKEN,
        &[("space", &space_uri)],
    )?;
    let delegation: DelegationTokenResponse = Call {
        host: hosts.member_pds,
        method: methods::GET_DELEGATION_TOKEN,
        key: dpop_key,
        presentation: DpopPresentation::Bound(access_token),
        http_method: Method::GET,
        url,
        body: None,
    }
    .send_json(http)
    .await?;

    // Hop 2, at the authority. A *grant*: the delegation token is an
    // authorization grant rather than an access token, so it goes out as a
    // `Bearer` and the proof carries no `ath`.
    //
    // Note what the body does not carry. The thumbprint the credential is
    // bound to used to travel as a `dpopJkt` field, which is an assertion
    // anyone holding a delegation token can make about a key somebody else
    // controls. The authority takes it from the verified proof's own `jwk`
    // instead -- a demonstration rather than a claim -- so there is nothing to
    // send.
    let url = method_url(hosts.authority, methods::GET_SPACE_CREDENTIAL, &[])?;
    let minted: SpaceCredentialResponse = Call {
        host: hosts.authority,
        method: methods::GET_SPACE_CREDENTIAL,
        key: dpop_key,
        presentation: DpopPresentation::Grant(&delegation.token),
        http_method: Method::POST,
        url,
        body: Some(serde_json::json!({ "space": space_uri })),
    }
    .send_json(http)
    .await?;

    SpaceCredentialGrant::decode(hosts.authority, minted.credential)
}

/// Hops 1, 2 and 3: a credential plus a delivery registration.
///
/// `repo` narrows the subscription to one member's repository; `None`
/// subscribes to the whole space.
///
/// # Errors
///
/// Returns [`SpaceClientError::InvalidDelivery`] **before any request is
/// issued** when the delivery target is not registrable, and otherwise as
/// [`space_read_credential`].
pub async fn subscribe_to_space(
    http: &reqwest::Client,
    hosts: SpaceHosts<'_>,
    dpop_key: &KeyData,
    access_token: &str,
    space: &SpaceUri,
    delivery: Delivery<'_>,
    repo: Option<&str>,
) -> Result<Subscription, SpaceClientError> {
    // Before hop 0, on purpose. See `Delivery::validate`.
    delivery.validate()?;

    let credential = space_read_credential(http, hosts, dpop_key, access_token, space).await?;

    // Hop 3, at the authority. The credential is bound to this key, so it goes
    // out under the `DPoP` scheme with a proof over it. Offering it as a
    // `Bearer` is refused: the scheme cannot be used to opt out of the
    // binding.
    let url = method_url(hosts.authority, methods::REGISTER_NOTIFY, &[])?;
    let mut body = serde_json::Map::new();
    body.insert("space".to_string(), space.to_string().into());
    match delivery {
        Delivery::Service(service) => {
            body.insert("service".to_string(), service.into());
        }
        Delivery::Endpoint(endpoint) => {
            body.insert("endpoint".to_string(), endpoint.into());
        }
    }
    if let Some(repo) = repo {
        body.insert("repo".to_string(), repo.into());
    }
    let body = serde_json::Value::Object(body);

    let registered: RegisterNotifyResponse = Call {
        host: hosts.authority,
        method: methods::REGISTER_NOTIFY,
        key: dpop_key,
        presentation: DpopPresentation::Bound(&credential.token),
        http_method: Method::POST,
        url,
        body: Some(body),
    }
    .send_json(http)
    .await?;

    Ok(Subscription {
        credential,
        expires_at: registered.expires_at,
    })
}

/// Cancel a subscription.
///
/// # Errors
///
/// As [`subscribe_to_space`], minus the hops it does not make.
pub async fn unsubscribe_from_space(
    http: &reqwest::Client,
    authority: &str,
    dpop_key: &KeyData,
    credential_token: &str,
    space: &SpaceUri,
    delivery: Delivery<'_>,
    repo: Option<&str>,
) -> Result<(), SpaceClientError> {
    delivery.validate()?;

    let url = method_url(authority, methods::UNREGISTER_NOTIFY, &[])?;
    let mut body = serde_json::Map::new();
    body.insert("space".to_string(), space.to_string().into());
    match delivery {
        Delivery::Service(service) => {
            body.insert("service".to_string(), service.into());
        }
        Delivery::Endpoint(endpoint) => {
            body.insert("endpoint".to_string(), endpoint.into());
        }
    }
    if let Some(repo) = repo {
        body.insert("repo".to_string(), repo.into());
    }

    Call {
        host: authority,
        method: methods::UNREGISTER_NOTIFY,
        key: dpop_key,
        presentation: DpopPresentation::Bound(credential_token),
        http_method: Method::POST,
        url,
        body: Some(serde_json::Value::Object(body)),
    }
    .send(http)
    .await
    .map(|_| ())
}
