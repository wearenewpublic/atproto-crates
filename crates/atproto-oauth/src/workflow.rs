//! OAuth workflow for AT Protocol authorization.
//!
//! Complete OAuth 2.0 authorization code flow with PAR, DPoP, PKCE,
//! and client assertion support for AT Protocol authentication.
//! - **`OAuthClient`**: Client configuration with credentials and signing keys
//! - **`OAuthRequest`**: Tracking structure for ongoing authorization requests
//! - **`OAuthRequestState`**: Security parameters including state, nonce, and PKCE challenge
//!
//! ## Security Features
//!
//! - **PKCE**: Proof Key for Code Exchange protection against authorization code interception
//! - **DPoP**: Demonstration of Proof-of-Possession for token binding
//! - **Client Assertions**: JWT-based client authentication using private key signatures
//! - **State Parameters**: CSRF protection using random state values
//! - **Nonce Values**: Additional replay protection
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use atproto_oauth::workflow::{oauth_init, oauth_complete, OAuthClient, OAuthRequestState};
//! use atproto_oauth::pkce::generate;
//! use atproto_identity::key::generate_key;
//!
//! // Generate security parameters
//! let signing_key = generate_key(KeyType::P256Private)?;
//! let dpop_key = generate_key(KeyType::P256Private)?;
//! let (pkce_verifier, code_challenge) = generate();
//!
//! // Configure OAuth client
//! let oauth_client = OAuthClient {
//!     redirect_uri: "https://app.example.com/callback".to_string(),
//!     client_id: "https://app.example.com/client-metadata.json".to_string(),
//!     private_signing_key_data: signing_key,
//! };
//!
//! // Create request state
//! let oauth_state = OAuthRequestState {
//!     state: "random-state-value".to_string(),
//!     nonce: "random-nonce-value".to_string(),
//!     code_challenge,
//!     scope: "atproto transition:generic".to_string(),
//! };
//!
//! // Initiate OAuth flow
//! let par_response = oauth_init(
//!     &http_client,
//!     &oauth_client,
//!     &dpop_key,
//!     "user.bsky.social",
//!     &authorization_server,
//!     &oauth_state,
//! ).await?;
//!
//! // Build authorization URL
//! let auth_url = format!(
//!     "{}?client_id={}&request_uri={}",
//!     authorization_server.authorization_endpoint,
//!     oauth_client.client_id,
//!     par_response.request_uri
//! );
//!
//! // After user authorization and callback. The expected subject is the DID
//! // the flow began for; the token endpoint's `sub` claim must match it.
//! let token_response = oauth_complete(
//!     &http_client,
//!     &oauth_client,
//!     &dpop_key,
//!     "authorization_code_from_callback",
//!     &oauth_request.subject,
//!     &oauth_request,
//!     &authorization_server,
//! ).await?;
//! ```

use atproto_identity::key::KeyData;
use chrono::{DateTime, Utc};
use rand::distr::{Alphanumeric, SampleString};
use reqwest_chain::ChainMiddleware;
use reqwest_middleware::ClientBuilder;
use serde::Deserialize;
use std::collections::HashMap;

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    dpop::{DpopRetry, auth_dpop},
    errors::OAuthClientError,
    jwt::{Claims, Header, JoseClaims, mint},
    resources::{AuthorizationServer, pds_resources},
};

/// Lifetime applied to minted client assertion JWTs, in seconds.
///
/// RFC 7523 section 3 requires an `exp` claim on client assertions. 60 seconds
/// matches the service token lifetime used elsewhere in this crate and is well
/// above the DPoP proof lifetime, so it tolerates a slow token endpoint.
const CLIENT_ASSERTION_LIFETIME_SECONDS: i64 = 60;

/// Builds the JOSE claims for a client assertion JWT.
///
/// The assertion is issued now and expires after
/// [`CLIENT_ASSERTION_LIFETIME_SECONDS`], as required by RFC 7523 section 3.
fn client_assertion_claims(client_id: &str, audience: &str, json_web_token_id: String) -> Claims {
    let issued_at = chrono::Utc::now();
    let expiration = issued_at + chrono::Duration::seconds(CLIENT_ASSERTION_LIFETIME_SECONDS);

    Claims::new(JoseClaims {
        issuer: Some(client_id.to_string()),
        subject: Some(client_id.to_string()),
        audience: Some(audience.to_string()),
        json_web_token_id: Some(json_web_token_id),
        issued_at: Some(issued_at.timestamp().cast_unsigned()),
        expiration: Some(expiration.timestamp().cast_unsigned()),
        ..Default::default()
    })
}

/// Binds a token endpoint response to the DID the authorization flow began for.
///
/// Returns an error when `expected_subject` is empty, when the response has no
/// `sub` claim, or when `sub` is not byte-for-byte equal to `expected_subject`.
/// DIDs are compared exactly; no case folding or trimming is applied.
///
/// # Arguments
/// * `expected_subject` - The AT Protocol DID the authorization flow began for
/// * `token_response` - The parsed token endpoint response to check
///
/// # Errors
/// Returns [`OAuthClientError::MissingExpectedSubject`],
/// [`OAuthClientError::TokenResponseMissingSubject`], or
/// [`OAuthClientError::TokenSubjectMismatch`].
pub fn bind_token_subject(
    expected_subject: &str,
    token_response: &TokenResponse,
) -> Result<(), OAuthClientError> {
    if expected_subject.is_empty() {
        return Err(OAuthClientError::MissingExpectedSubject);
    }

    let actual = token_response
        .sub
        .as_deref()
        .ok_or(OAuthClientError::TokenResponseMissingSubject)?;

    if actual != expected_subject {
        tracing::warn!(
            expected = %expected_subject,
            actual = %actual,
            "Token endpoint returned a subject other than the DID the flow began for"
        );
        return Err(OAuthClientError::TokenSubjectMismatch {
            expected: expected_subject.to_string(),
            actual: actual.to_string(),
        });
    }

    Ok(())
}

/// Response from a Pushed Authorization Request (PAR) endpoint.
///
/// Contains the request URI and expiration time returned by the authorization
/// server after successfully processing a pushed authorization request.
#[derive(Clone, Deserialize)]
pub struct ParResponse {
    /// The request URI to use in the authorization request.
    pub request_uri: String,
    /// The lifetime of the request URI in seconds.
    pub expires_in: u64,

    /// Additional fields returned by the authorization server.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// OAuth request state containing security parameters for the authorization flow.
///
/// This struct holds the security parameters needed to maintain state
/// and prevent attacks during the OAuth authorization code flow.
pub struct OAuthRequestState {
    /// Random state parameter to prevent CSRF attacks.
    pub state: String,
    /// Random nonce value for additional security.
    pub nonce: String,
    /// PKCE code challenge derived from the code verifier.
    pub code_challenge: String,
    /// The scope of access requested for the authorization.
    pub scope: String,
}

/// OAuth client configuration containing essential client credentials.
///
/// This struct holds the client configuration needed for OAuth authorization flows,
/// including the redirect URI, client identifier, and signing key.
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct OAuthClient {
    /// The redirect URI where the authorization server will send the user after authorization.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub redirect_uri: String,

    /// The unique client identifier for this OAuth client.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub client_id: String,

    /// The private key data used for signing client assertions.
    pub private_signing_key_data: KeyData,
}

/// OAuth request tracking information for ongoing authorization flows.
///
/// This struct contains all the necessary information to track and complete
/// an OAuth authorization request, including security parameters and timing.
#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct OAuthRequest {
    /// The OAuth state parameter used to prevent CSRF attacks.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub oauth_state: String,

    /// The AT Protocol DID the authorization flow was initiated for.
    ///
    /// This must be a DID, not a handle: [`oauth_complete`] requires the token
    /// endpoint's `sub` claim to equal this value exactly, and a mismatch means
    /// the authorization server tried to authenticate a different account.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub subject: String,

    /// The authorization server issuer identifier.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub issuer: String,

    /// The authorization server identifier.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub authorization_server: String,

    /// The nonce value for additional security.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub nonce: String,

    /// The PKCE code verifier for this authorization request.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub pkce_verifier: String,

    /// The public key used for signing (serialized).
    pub signing_public_key: String,

    /// The DPoP private key (serialized).
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub dpop_private_key: String,

    /// When this OAuth request was created.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub created_at: DateTime<Utc>,

    /// When this OAuth request expires.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for OAuthRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthRequest")
            .field("oauth_state", &self.oauth_state)
            .field("subject", &self.subject)
            .field("issuer", &self.issuer)
            .field("authorization_server", &self.authorization_server)
            .field("nonce", &self.nonce)
            .field("pkce_verifier", &"[REDACTED]")
            .field("signing_public_key", &self.signing_public_key)
            .field("dpop_private_key", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Response from the OAuth token endpoint containing access credentials.
///
/// This struct represents the successful response from an OAuth token exchange,
/// containing the access token and related metadata.
#[derive(Clone, Deserialize)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct TokenResponse {
    /// The access token that can be used to access protected resources.
    pub access_token: String,

    /// The type of token, typically "Bearer" or "DPoP".
    pub token_type: String,

    /// The refresh token that can be used to obtain new access tokens.
    /// Not all token responses include a refresh token.
    pub refresh_token: Option<String>,

    /// The scope of access granted by the access token.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub scope: String,

    /// The lifetime of the access token in seconds.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub expires_in: u32,

    /// The subject identifier (usually the user's DID).
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub sub: Option<String>,

    /// Additional fields returned by the authorization server.
    #[serde(flatten)]
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Initiates the OAuth authorization flow by making a Pushed Authorization Request (PAR).
///
/// This function creates a PAR request to the authorization server with the necessary
/// OAuth parameters, DPoP proof, and client assertion. It handles the complete setup
/// for the AT Protocol OAuth flow including PKCE and DPoP security mechanisms.
///
/// # Arguments
/// * `http_client` - The HTTP client to use for making requests
/// * `private_signing_key_data` - The private key for signing client assertions
/// * `dpop_key_data` - The key data for creating DPoP proofs
/// * `handle` - The user's handle for the login hint
/// * `authorization_server` - The authorization server configuration
/// * `oauth_request_state` - The OAuth state parameters for this request
///
/// # Returns
/// A `ParResponse` containing the request URI and expiration time on success.
///
/// # Errors
/// Returns `OAuthClientError` if the PAR request fails or response parsing fails.
pub async fn oauth_init(
    http_client: &reqwest::Client,
    oauth_client: &OAuthClient,
    dpop_key_data: &KeyData,
    login_hint: Option<&str>,
    authorization_server: &AuthorizationServer,
    oauth_request_state: &OAuthRequestState,
) -> Result<ParResponse, OAuthClientError> {
    oauth_init_with_prompt(
        http_client,
        oauth_client,
        dpop_key_data,
        login_hint,
        None,
        authorization_server,
        oauth_request_state,
    )
    .await
}

/// Some docs.
pub async fn oauth_init_with_prompt(
    http_client: &reqwest::Client,
    oauth_client: &OAuthClient,
    dpop_key_data: &KeyData,
    login_hint: Option<&str>,
    prompt: Option<&str>,
    authorization_server: &AuthorizationServer,
    oauth_request_state: &OAuthRequestState,
) -> Result<ParResponse, OAuthClientError> {
    let par_url = authorization_server
        .pushed_authorization_request_endpoint
        .clone();

    let scope = &oauth_request_state.scope;

    let client_assertion_header: Header = (oauth_client.private_signing_key_data.clone())
        .try_into()
        .map_err(OAuthClientError::JWTHeaderCreationFailed)?;

    let client_assertion_jti = Alphanumeric.sample_string(&mut rand::rng(), 30);
    let client_assertion_claims = client_assertion_claims(
        &oauth_client.client_id,
        &authorization_server.issuer,
        client_assertion_jti,
    );

    let client_assertion_token = mint(
        &oauth_client.private_signing_key_data,
        &client_assertion_header,
        &client_assertion_claims,
    )
    .map_err(OAuthClientError::MintTokenFailed)?;

    let (dpop_token, dpop_header, dpop_claims) = auth_dpop(dpop_key_data, "POST", &par_url)
        .map_err(OAuthClientError::DpopTokenCreationFailed)?;

    let dpop_retry = DpopRetry::new(dpop_header, dpop_claims, dpop_key_data.clone(), true);

    let dpop_retry_client = ClientBuilder::new(http_client.clone())
        .with(ChainMiddleware::new(dpop_retry.clone()))
        .build();

    let mut params = vec![
        ("response_type", "code"),
        ("code_challenge", &oauth_request_state.code_challenge),
        ("code_challenge_method", "S256"),
        ("client_id", oauth_client.client_id.as_str()),
        ("state", oauth_request_state.state.as_str()),
        ("redirect_uri", oauth_client.redirect_uri.as_str()),
        ("scope", scope),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", client_assertion_token.as_str()),
    ];
    if let Some(value) = login_hint {
        params.push(("login_hint", value));
    }

    if let Some(value) = prompt {
        params.push(("prompt", value));
    }

    let response = dpop_retry_client
        .post(par_url)
        .header("DPoP", dpop_token.as_str())
        .form(&params)
        .send()
        .await
        .map_err(OAuthClientError::PARHttpRequestFailed)?
        .json()
        .await
        .map_err(OAuthClientError::PARResponseJsonParsingFailed)?;

    Ok(response)
}

/// Completes the OAuth authorization flow by exchanging the authorization code for tokens.
///
/// This function performs the final step of the OAuth authorization code flow by
/// exchanging the authorization code received from the callback for access and refresh tokens.
/// It handles DPoP proof generation and client assertion creation for secure token exchange.
///
/// # Arguments
/// * `http_client` - The HTTP client to use for making requests
/// * `oauth_client` - The OAuth client configuration
/// * `dpop_key_data` - The key data for creating DPoP proofs
/// * `callback_code` - The authorization code received from the callback
/// * `expected_subject` - The AT Protocol DID the flow began for, normally
///   `oauth_request.subject`. The token endpoint's `sub` claim must equal it.
/// * `oauth_request` - The original OAuth request state
/// * `authorization_server` - The authorization server configuration
///
/// # Returns
/// A `TokenResponse` containing the access token, refresh token, and metadata on success.
///
/// # Errors
/// Returns `OAuthClientError` if the token exchange fails, the response cannot
/// be parsed, or the returned `sub` claim is missing or does not match
/// `expected_subject`. A mismatch means the authorization server tried to
/// authenticate a different account than the one the flow began for.
pub async fn oauth_complete(
    http_client: &reqwest::Client,
    oauth_client: &OAuthClient,
    dpop_key_data: &KeyData,
    callback_code: &str,
    expected_subject: &str,
    oauth_request: &OAuthRequest,
    authorization_server: &AuthorizationServer,
) -> Result<TokenResponse, OAuthClientError> {
    // Reject an unusable expected subject before doing any network work so the
    // binding below can never be a silent no-op.
    if expected_subject.is_empty() {
        return Err(OAuthClientError::MissingExpectedSubject);
    }

    let client_assertion_header: Header = (oauth_client.private_signing_key_data.clone())
        .try_into()
        .map_err(OAuthClientError::JWTHeaderCreationFailed)?;

    let client_assertion_jti = Alphanumeric.sample_string(&mut rand::rng(), 30);
    let client_assertion_claims = client_assertion_claims(
        &oauth_client.client_id,
        &authorization_server.issuer,
        client_assertion_jti,
    );

    let client_assertion_token = mint(
        &oauth_client.private_signing_key_data,
        &client_assertion_header,
        &client_assertion_claims,
    )
    .map_err(OAuthClientError::MintTokenFailed)?;

    let params = [
        ("client_id", oauth_client.client_id.as_str()),
        ("redirect_uri", oauth_client.redirect_uri.as_str()),
        ("grant_type", "authorization_code"),
        ("code", callback_code),
        ("code_verifier", &oauth_request.pkce_verifier),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", client_assertion_token.as_str()),
    ];

    let token_endpoint = authorization_server.token_endpoint.clone();

    let (dpop_token, dpop_header, dpop_claims) = auth_dpop(dpop_key_data, "POST", &token_endpoint)
        .map_err(OAuthClientError::DpopTokenCreationFailed)?;

    let dpop_retry = DpopRetry::new(dpop_header, dpop_claims, dpop_key_data.clone(), true);

    let dpop_retry_client = ClientBuilder::new(http_client.clone())
        .with(ChainMiddleware::new(dpop_retry.clone()))
        .build();

    let token_response: TokenResponse = dpop_retry_client
        .post(token_endpoint)
        .header("DPoP", dpop_token.as_str())
        .form(&params)
        .send()
        .await
        .map_err(OAuthClientError::TokenHttpRequestFailed)?
        .json()
        .await
        .map_err(OAuthClientError::TokenResponseJsonParsingFailed)?;

    bind_token_subject(expected_subject, &token_response)?;

    Ok(token_response)
}

/// Refreshes OAuth access tokens using a refresh token.
///
/// This function exchanges a refresh token for new access and refresh tokens.
/// It handles DPoP proof generation and client assertion creation for secure
/// token refresh operations according to AT Protocol OAuth requirements.
///
/// # Arguments
/// * `http_client` - The HTTP client to use for making requests
/// * `oauth_client` - The OAuth client configuration
/// * `dpop_key_data` - The key data for creating DPoP proofs
/// * `refresh_token` - The refresh token to exchange for new tokens
/// * `document` - The identity document containing PDS endpoints. Its `id` is
///   the expected subject: the refreshed token's `sub` claim must equal it.
///
/// # Returns
/// A `TokenResponse` containing the new access token, refresh token, and metadata on success.
///
/// # Errors
/// Returns `OAuthClientError` if the token refresh fails, the response cannot
/// be parsed, or the returned `sub` claim is missing or does not match
/// `document.id`.
pub async fn oauth_refresh(
    http_client: &reqwest::Client,
    oauth_client: &OAuthClient,
    dpop_key_data: &KeyData,
    refresh_token: &str,
    document: &atproto_identity::model::Document,
) -> Result<TokenResponse, OAuthClientError> {
    let expected_subject = document.id.clone();

    let pds_endpoints = document.pds_endpoints();
    let pds_endpoint = pds_endpoints
        .first()
        .ok_or(OAuthClientError::InvalidOAuthProtectedResource)?;
    let (_, authorization_server) = pds_resources(http_client, pds_endpoint).await?;

    let client_assertion_header: Header = (oauth_client.private_signing_key_data.clone())
        .try_into()
        .map_err(OAuthClientError::JWTHeaderCreationFailed)?;

    let client_assertion_jti = Alphanumeric.sample_string(&mut rand::rng(), 30);
    let client_assertion_claims = client_assertion_claims(
        &oauth_client.client_id,
        &authorization_server.issuer,
        client_assertion_jti,
    );

    let client_assertion_token = mint(
        &oauth_client.private_signing_key_data,
        &client_assertion_header,
        &client_assertion_claims,
    )
    .map_err(OAuthClientError::MintTokenFailed)?;

    let params = [
        ("client_id", oauth_client.client_id.as_str()),
        ("redirect_uri", oauth_client.redirect_uri.as_str()),
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", client_assertion_token.as_str()),
    ];

    let token_endpoint = authorization_server.token_endpoint.clone();

    let (dpop_token, dpop_header, dpop_claims) = auth_dpop(dpop_key_data, "POST", &token_endpoint)
        .map_err(OAuthClientError::DpopTokenCreationFailed)?;

    let dpop_retry = DpopRetry::new(dpop_header, dpop_claims, dpop_key_data.clone(), true);

    let dpop_retry_client = ClientBuilder::new(http_client.clone())
        .with(ChainMiddleware::new(dpop_retry.clone()))
        .build();

    let token_response: TokenResponse = dpop_retry_client
        .post(token_endpoint)
        .header("DPoP", dpop_token.as_str())
        .form(&params)
        .send()
        .await
        .map_err(OAuthClientError::TokenHttpRequestFailed)?
        .json()
        .await
        .map_err(OAuthClientError::TokenResponseJsonParsingFailed)?;

    bind_token_subject(&expected_subject, &token_response)?;

    Ok(token_response)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The confirmed attack payload: a hostile authorization server returns a
    /// victim DID as `sub` for a flow the attacker started for their own DID.
    const ATTACK_TOKEN_RESPONSE: &str = r#"{"access_token":"attacker-minted","token_type":"DPoP","refresh_token":"r","scope":"atproto transition:generic","expires_in":3600,"sub":"did:plc:victim000000000000000000"}"#;

    /// The downgrade variant: `sub` omitted entirely so a caller with an
    /// `unwrap_or(session_did)` fallback authenticates the wrong account.
    const ATTACK_TOKEN_RESPONSE_NO_SUB: &str = r#"{"access_token":"attacker-minted","token_type":"DPoP","refresh_token":"r","scope":"atproto transition:generic","expires_in":3600}"#;

    fn token_response(json: &str) -> TokenResponse {
        serde_json::from_str(json).expect("token response deserializes")
    }

    #[test]
    fn test_bind_token_subject_rejects_victim_impersonation() {
        let response = token_response(ATTACK_TOKEN_RESPONSE);

        let err = bind_token_subject("did:plc:attacker00000000000000", &response)
            .expect_err("victim subject must be rejected");

        assert!(matches!(err, OAuthClientError::TokenSubjectMismatch { .. }));

        let message = err.to_string();
        assert!(
            message.contains("error-atproto-oauth-client-16"),
            "{message}"
        );
        assert!(
            message.contains("did:plc:victim000000000000000000"),
            "{message}"
        );
    }

    #[test]
    fn test_bind_token_subject_rejects_missing_sub() {
        let response = token_response(ATTACK_TOKEN_RESPONSE_NO_SUB);
        assert!(response.sub.is_none());

        let err = bind_token_subject("did:plc:attacker00000000000000", &response)
            .expect_err("missing subject must be rejected");

        assert!(matches!(err, OAuthClientError::TokenResponseMissingSubject));
        assert!(
            err.to_string().contains("error-atproto-oauth-client-15"),
            "{err}"
        );
    }

    #[test]
    fn test_bind_token_subject_rejects_empty_expected_subject() {
        let response = token_response(ATTACK_TOKEN_RESPONSE);

        let err =
            bind_token_subject("", &response).expect_err("empty expected subject must be rejected");

        assert!(matches!(err, OAuthClientError::MissingExpectedSubject));
        assert!(
            err.to_string().contains("error-atproto-oauth-client-17"),
            "{err}"
        );
    }

    #[test]
    fn test_bind_token_subject_accepts_exact_match() {
        let response = token_response(ATTACK_TOKEN_RESPONSE);

        bind_token_subject("did:plc:victim000000000000000000", &response)
            .expect("an exactly matching subject is accepted");
    }

    #[test]
    fn test_bind_token_subject_is_exact_comparison() {
        let expected = "did:plc:victim000000000000000000";

        for actual in [
            "did:plc:VICTIM000000000000000000",
            " did:plc:victim000000000000000000",
            "did:plc:victim000000000000000000 ",
        ] {
            let json = format!(
                r#"{{"access_token":"a","token_type":"DPoP","scope":"atproto","expires_in":3600,"sub":"{actual}"}}"#
            );
            let response = token_response(&json);

            let err = bind_token_subject(expected, &response)
                .expect_err("subjects are compared byte-for-byte");
            assert!(matches!(err, OAuthClientError::TokenSubjectMismatch { .. }));
        }
    }

    #[test]
    fn test_client_assertion_claims_carry_expiration() {
        let claims = client_assertion_claims(
            "https://app.example.com/client-metadata.json",
            "https://pds.example.com",
            "jti-value".to_string(),
        );

        let issued_at = claims.jose.issued_at.expect("iat is set");
        let expiration = claims.jose.expiration.expect("exp is set");

        assert_eq!(
            expiration,
            issued_at + CLIENT_ASSERTION_LIFETIME_SECONDS.cast_unsigned()
        );
        assert_eq!(
            claims.jose.issuer.as_deref(),
            Some("https://app.example.com/client-metadata.json")
        );
        assert_eq!(
            claims.jose.audience.as_deref(),
            Some("https://pds.example.com")
        );
    }
}
