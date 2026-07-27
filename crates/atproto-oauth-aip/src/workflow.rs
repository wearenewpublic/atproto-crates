//! OAuth 2.0 workflow for AT Protocol identity providers.
//!
//! Complete authorization code flow implementation with PAR initialization,
//! code exchange, and AT Protocol session establishment.
//! 1. **Initialization (`oauth_init`)**: Creates a Pushed Authorization Request (PAR)
//!    and returns the authorization URL for user consent
//! 2. **Completion (`oauth_complete`)**: Exchanges the authorization code for access tokens
//! 3. **Session Exchange (`session_exchange`)**: Converts OAuth tokens to AT Protocol sessions
//!
//! ## Security Features
//!
//! - **Pushed Authorization Requests (PAR)**: Enhanced security by storing authorization
//!   parameters server-side rather than in redirect URLs
//! - **PKCE (Proof Key for Code Exchange)**: Protection against authorization code
//!   interception attacks
//! - **DPoP (Demonstration of Proof-of-Possession)**: Cryptographic binding of tokens
//!   to specific keys for enhanced security
//! - **Subject binding**: `oauth_complete` requires the token endpoint's `sub`
//!   claim to equal the DID the flow began for, so a hostile authorization server
//!   cannot return a victim DID and have the caller mint a session for it
//!
//! ## Usage Example
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use atproto_oauth_aip::workflow::{oauth_init, oauth_complete, session_exchange, OAuthClient};
//! use atproto_oauth::resources::{AuthorizationServer, OAuthProtectedResource};
//! use atproto_oauth::workflow::{OAuthRequestState, OAuthRequest};
//!
//! let http_client = reqwest::Client::new();
//!
//! // 1. Initialize OAuth flow
//! let oauth_client = OAuthClient {
//!     redirect_uri: "https://myapp.com/callback".to_string(),
//!     client_id: "my_client_id".to_string(),
//!     client_secret: "my_client_secret".to_string(),
//! };
//!
//! # let authorization_server = AuthorizationServer {
//! #     issuer: "https://auth.example.com".to_string(),
//! #     authorization_endpoint: "https://auth.example.com/authorize".to_string(),
//! #     token_endpoint: "https://auth.example.com/token".to_string(),
//! #     pushed_authorization_request_endpoint: "https://auth.example.com/par".to_string(),
//! #     introspection_endpoint: "".to_string(),
//! #     scopes_supported: vec!["atproto".to_string(), "transition:generic".to_string()],
//! #     response_types_supported: vec!["code".to_string()],
//! #     grant_types_supported: vec!["authorization_code".to_string(), "refresh_token".to_string()],
//! #     token_endpoint_auth_methods_supported: vec!["none".to_string(), "private_key_jwt".to_string()],
//! #     token_endpoint_auth_signing_alg_values_supported: vec!["ES256".to_string()],
//! #     require_pushed_authorization_requests: true,
//! #     request_parameter_supported: false,
//! #     code_challenge_methods_supported: vec!["S256".to_string()],
//! #     authorization_response_iss_parameter_supported: true,
//! #     dpop_signing_alg_values_supported: vec!["ES256".to_string()],
//! #     client_id_metadata_document_supported: true,
//! # };
//!
//! let oauth_request_state = OAuthRequestState {
//!     state: "random-state".to_string(),
//!     nonce: "random-nonce".to_string(),
//!     code_challenge: "code-challenge".to_string(),
//!     scope: "atproto transition:generic".to_string(),
//! };
//!
//! let par_response = oauth_init(
//!     &http_client,
//!     &oauth_client,
//!     Some("user.bsky.social"),
//!     &authorization_server.pushed_authorization_request_endpoint,
//!     &oauth_request_state
//! ).await?;
//!
//! // User visits auth_url and grants consent, returns with authorization code
//!
//! // 2. Complete OAuth flow
//! # let oauth_request = OAuthRequest {
//! #     oauth_state: "state".to_string(),
//! #     subject: "did:plc:example123".to_string(),
//! #     issuer: "https://auth.example.com".to_string(),
//! #     authorization_server: "https://auth.example.com".to_string(),
//! #     nonce: "nonce".to_string(),
//! #     signing_public_key: "public_key".to_string(),
//! #     pkce_verifier: "verifier".to_string(),
//! #     dpop_private_key: "private_key".to_string(),
//! #     created_at: chrono::Utc::now(),
//! #     expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
//! # };
//! let token_response = oauth_complete(
//!     &http_client,
//!     &oauth_client,
//!     &authorization_server.token_endpoint,
//!     "received_auth_code",
//!     &oauth_request
//! ).await?;
//!
//! // 3. Exchange for AT Protocol session
//! # let protected_resource = OAuthProtectedResource {
//! #     resource: "https://pds.example.com".to_string(),
//! #     scopes_supported: vec!["atproto".to_string()],
//! #     bearer_methods_supported: vec!["header".to_string()],
//! #     authorization_servers: vec!["https://auth.example.com".to_string()],
//! # };
//! let session = session_exchange(
//!     &http_client,
//!     &protected_resource.resource,
//!     &token_response.access_token
//! ).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Error Handling
//!
//! All functions return `Result<T, OAuthWorkflowError>` with detailed error information
//! for each phase of the OAuth flow including network failures, parsing errors,
//! and protocol violations.

use anyhow::Result;
use atproto_identity::url::build_url;
use atproto_oauth::{
    errors::OAuthClientError,
    jwk::WrappedJsonWebKey,
    workflow::{OAuthRequest, OAuthRequestState, ParResponse, TokenResponse, bind_token_subject},
};
use serde::Deserialize;
use std::iter;

use crate::errors::OAuthWorkflowError;

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// OAuth client configuration containing essential client credentials.
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct OAuthClient {
    /// The redirect URI where the authorization server will send the user after authorization.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub redirect_uri: String,

    /// The unique client identifier for this OAuth client.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub client_id: String,

    /// The client secret used for authenticating with the authorization server.
    pub client_secret: String,
}

#[derive(Clone, Deserialize)]
#[serde(untagged)]
enum WrappedParResponse {
    ParResponse(ParResponse),
    Error {
        error: String,
        error_description: Option<String>,
    },
}

/// Represents an authenticated AT Protocol session.
///
/// This structure contains all the information needed to make authenticated
/// requests to AT Protocol services after a successful OAuth flow.
#[derive(Clone, Deserialize)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct ATProtocolSession {
    /// The Decentralized Identifier (DID) of the authenticated user.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub did: String,

    /// The handle (username) of the authenticated user.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub handle: String,

    /// The OAuth access token for making authenticated requests.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub access_token: String,

    /// The type of token (typically "Bearer").
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub token_type: String,

    /// The list of OAuth scopes granted to this session.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub scopes: Vec<String>,

    /// The Personal Data Server (PDS) endpoint URL for this user.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub pds_endpoint: String,

    /// The DPoP (Demonstration of Proof-of-Possession) key in string serialized format.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub dpop_key: Option<String>,

    /// The DPoP (Demonstration of Proof-of-Possession) key in JWK format.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub dpop_jwk: Option<WrappedJsonWebKey>,

    /// Unix timestamp indicating when this session expires.
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    pub expires_at: i64,
}

#[derive(Deserialize, Clone)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
#[serde(untagged)]
enum WrappedATProtocolSession {
    ATProtocolSession(Box<ATProtocolSession>),

    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    Error {
        error: String,
        error_description: Option<String>,
    },
}

/// Initiates an OAuth authorization flow using Pushed Authorization Request (PAR).
///
/// This function starts the OAuth flow by sending a PAR request to the authorization
/// server. PAR allows the client to push the authorization request parameters to the
/// authorization server before redirecting the user, providing enhanced security.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for making requests
/// * `oauth_client` - OAuth client configuration with credentials
/// * `handle` - Optional user handle to pre-fill in the login form
/// * `authorization_server` - Authorization server metadata
/// * `oauth_request_state` - OAuth request state including PKCE challenge and state
///
/// # Returns
///
/// Returns a `ParResponse` containing the request URI to redirect the user to,
/// or an error if the PAR request fails.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use atproto_oauth_aip::workflow::{oauth_init, OAuthClient};
/// use atproto_oauth::workflow::OAuthRequestState;
/// # let http_client = reqwest::Client::new();
/// let oauth_client = OAuthClient {
///     redirect_uri: "https://example.com/callback".to_string(),
///     client_id: "client123".to_string(),
///     client_secret: "secret456".to_string(),
/// };
/// # let authorization_server = "https://auth.example.com/par";
/// let oauth_request_state = OAuthRequestState {
///     state: "random-state".to_string(),
///     nonce: "random-nonce".to_string(),
///     code_challenge: "code-challenge".to_string(),
///     scope: "atproto transition:generic".to_string(),
/// };
/// let par_response = oauth_init(
///     &http_client,
///     &oauth_client,
///     Some("alice.bsky.social"),
///     authorization_server,
///     &oauth_request_state,
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub async fn oauth_init(
    http_client: &reqwest::Client,
    oauth_client: &OAuthClient,
    login_hint: Option<&str>,
    par_url: &str,
    oauth_request_state: &OAuthRequestState,
) -> Result<ParResponse> {
    let scope = &oauth_request_state.scope;

    let mut params = vec![
        ("client_id", oauth_client.client_id.as_str()),
        ("code_challenge_method", "S256"),
        ("code_challenge", &oauth_request_state.code_challenge),
        ("redirect_uri", oauth_client.redirect_uri.as_str()),
        ("response_type", "code"),
        ("scope", scope),
        ("state", oauth_request_state.state.as_str()),
    ];
    if let Some(value) = login_hint {
        params.push(("login_hint", value));
    }

    let response: WrappedParResponse = http_client
        .post(par_url)
        .form(&params)
        .basic_auth(
            oauth_client.client_id.as_str(),
            Some(oauth_client.client_secret.as_str()),
        )
        .send()
        .await
        .map_err(OAuthWorkflowError::ParRequestFailed)?
        .json()
        .await
        .map_err(OAuthWorkflowError::ParResponseParseFailed)?;

    match response {
        WrappedParResponse::ParResponse(value) => Ok(value),
        WrappedParResponse::Error {
            error,
            error_description,
        } => {
            let error_message = if let Some(value) = error_description {
                format!("{error}: {value}")
            } else {
                error.to_string()
            };
            Err(OAuthWorkflowError::ParResponseInvalid {
                message: error_message,
            }
            .into())
        }
    }
}

/// Completes the OAuth authorization flow by exchanging the authorization code for tokens.
///
/// After the user has authorized the application and been redirected back with an
/// authorization code, this function exchanges that code for access tokens using
/// the token endpoint.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for making requests
/// * `oauth_client` - OAuth client configuration with credentials
/// * `authorization_server` - Authorization server metadata
/// * `callback_code` - The authorization code received in the callback
/// * `oauth_request` - The original OAuth request containing the PKCE verifier
///
/// # Returns
///
/// Returns a `TokenResponse` containing the access token and other token information,
/// or an error if the token exchange fails.
///
/// # Errors
///
/// Returns [`OAuthWorkflowError::TokenSubjectBindingFailed`] when
/// `oauth_request.subject` is empty, when the token endpoint omitted the `sub`
/// claim, or when `sub` is not byte-for-byte equal to `oauth_request.subject`.
/// A mismatch means the authorization server tried to authenticate a different
/// account than the one the flow began for.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use atproto_oauth_aip::workflow::oauth_complete;
/// # let http_client = reqwest::Client::new();
/// # let oauth_client = todo!();
/// # let token_endpoint = "https://auth.example.com/token";
/// # let oauth_request = todo!();
/// let token_response = oauth_complete(
///     &http_client,
///     &oauth_client,
///     token_endpoint,
///     "auth_code_from_callback",
///     &oauth_request,
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub async fn oauth_complete(
    http_client: &reqwest::Client,
    oauth_client: &OAuthClient,
    token_endpoint: &str,
    callback_code: &str,
    oauth_request: &OAuthRequest,
) -> Result<TokenResponse> {
    // Reject an unusable expected subject before any network work so the binding
    // below can never silently pass.
    if oauth_request.subject.is_empty() {
        return Err(OAuthWorkflowError::TokenSubjectBindingFailed(
            OAuthClientError::MissingExpectedSubject,
        )
        .into());
    }

    let params = [
        ("client_id", oauth_client.client_id.as_str()),
        ("redirect_uri", oauth_client.redirect_uri.as_str()),
        ("grant_type", "authorization_code"),
        ("code", callback_code),
        ("code_verifier", &oauth_request.pkce_verifier),
    ];

    let token_response: TokenResponse = http_client
        .post(token_endpoint)
        .basic_auth(
            oauth_client.client_id.as_str(),
            Some(oauth_client.client_secret.as_str()),
        )
        .form(&params)
        .send()
        .await
        .map_err(OAuthWorkflowError::TokenRequestFailed)?
        .json()
        .await
        .map_err(OAuthWorkflowError::TokenResponseParseFailed)?;

    bind_response_subject(&oauth_request.subject, &token_response)?;

    Ok(token_response)
}

/// Binds a token endpoint response to the DID the authorization flow began for.
///
/// Delegates to [`atproto_oauth::workflow::bind_token_subject`] and maps its
/// failure onto [`OAuthWorkflowError::TokenSubjectBindingFailed`].
fn bind_response_subject(
    expected_subject: &str,
    token_response: &TokenResponse,
) -> Result<(), OAuthWorkflowError> {
    bind_token_subject(expected_subject, token_response)
        .map_err(OAuthWorkflowError::TokenSubjectBindingFailed)
}

/// Exchanges an OAuth access token for an AT Protocol session.
///
/// This function takes an OAuth access token and exchanges it for a full
/// AT Protocol session, which includes additional information like the user's
/// DID, handle, and PDS endpoint. This is specific to AT Protocol's OAuth
/// implementation.
///
/// This is a convenience function that calls `session_exchange_with_options`
/// with no additional options.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for making requests
/// * `protected_resource_base` - The base URL of the protected resource (PDS)
/// * `access_token` - The OAuth access token to exchange
///
/// # Returns
///
/// Returns an `ATProtocolSession` with full session information,
/// or an error if the session exchange fails.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use atproto_oauth_aip::workflow::session_exchange;
/// # let http_client = reqwest::Client::new();
/// # let protected_resource = "https://pds.example.com";
/// # let access_token = "example_token";
/// let session = session_exchange(
///     &http_client,
///     protected_resource,
///     access_token,
/// ).await?;
/// println!("Authenticated as {} ({})", session.handle, session.did);
/// println!("PDS endpoint: {}", session.pds_endpoint);
/// # Ok(())
/// # }
/// ```
pub async fn session_exchange(
    http_client: &reqwest::Client,
    protected_resource_base: &str,
    access_token: &str,
) -> Result<ATProtocolSession> {
    session_exchange_with_options(
        http_client,
        protected_resource_base,
        access_token,
        &None,
        &None,
    )
    .await
}

/// Exchanges an OAuth access token for an AT Protocol session with additional options.
///
/// This function takes an OAuth access token and exchanges it for a full
/// AT Protocol session, which includes additional information like the user's
/// DID, handle, and PDS endpoint. This version allows specifying additional
/// options for the session exchange.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for making requests
/// * `protected_resource_base` - The base URL of the protected resource (PDS)
/// * `access_token` - The OAuth access token to exchange
/// * `access_token_type` - Optional token type ("oauth_session", "app_password_session", or "best")
/// * `subject` - Optional subject (DID) to specify which user's session to retrieve
///
/// # Returns
///
/// Returns an `ATProtocolSession` with full session information,
/// or an error if the session exchange fails.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use atproto_oauth_aip::workflow::session_exchange_with_options;
/// # let http_client = reqwest::Client::new();
/// # let protected_resource = "https://pds.example.com";
/// # let access_token = "example_token";
/// // Basic usage without options
/// let session = session_exchange_with_options(
///     &http_client,
///     protected_resource,
///     access_token,
///     &None,
///     &None,
/// ).await?;
/// # Ok(())
/// # }
/// ```
///
/// # Example with access_token_type
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use atproto_oauth_aip::workflow::session_exchange_with_options;
/// # let http_client = reqwest::Client::new();
/// # let protected_resource = "https://pds.example.com";
/// # let access_token = "example_token";
/// // Specify the token type
/// let session = session_exchange_with_options(
///     &http_client,
///     protected_resource,
///     access_token,
///     &Some("oauth_session"),
///     &None,
/// ).await?;
/// # Ok(())
/// # }
/// ```
///
/// # Example with subject
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use atproto_oauth_aip::workflow::session_exchange_with_options;
/// # let http_client = reqwest::Client::new();
/// # let protected_resource = "https://pds.example.com";
/// # let access_token = "example_token";
/// # let user_did = "did:plc:example123";
/// // Specify both token type and subject
/// let session = session_exchange_with_options(
///     &http_client,
///     protected_resource,
///     access_token,
///     &Some("app_password_session"),
///     &Some(user_did),
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub async fn session_exchange_with_options(
    http_client: &reqwest::Client,
    protected_resource_base: &str,
    access_token: &str,
    access_token_type: &Option<&str>,
    subject: &Option<&str>,
) -> Result<ATProtocolSession> {
    let mut url = build_url(
        protected_resource_base,
        "/api/atprotocol/session",
        iter::empty::<(&str, &str)>(),
    )?;
    {
        let mut pairs = url.query_pairs_mut();
        if let Some(value) = access_token_type {
            pairs.append_pair("access_token_type", value);
        }

        if let Some(value) = subject {
            pairs.append_pair("sub", value);
        }
    }

    let url: String = url.into();

    let response = http_client
        .get(&url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(OAuthWorkflowError::SessionRequestFailed)?
        .json()
        .await
        .map_err(OAuthWorkflowError::SessionResponseParseFailed)?;

    match response {
        WrappedATProtocolSession::ATProtocolSession(ref value) => Ok(*value.clone()),
        WrappedATProtocolSession::Error {
            ref error,
            ref error_description,
        } => {
            let error_message = if let Some(value) = error_description {
                format!("{error}: {value}")
            } else {
                error.to_string()
            };
            Err(OAuthWorkflowError::SessionResponseInvalid {
                message: error_message,
            }
            .into())
        }
    }
}

/// Obtains an access token using OAuth client credentials grant.
///
/// This function implements the OAuth 2.0 client credentials flow for obtaining
/// service-to-service access tokens. This is typically used when a service needs
/// to authenticate itself rather than acting on behalf of a user.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for making requests
/// * `aip_hostname` - The hostname of the AT Protocol Identity Provider (AIP)
/// * `aip_client_id` - The client ID for authenticating with the AIP
/// * `aip_client_secret` - The client secret for authenticating with the AIP
///
/// # Returns
///
/// Returns a `TokenResponse` containing the access token and metadata,
/// or an error if the token request fails.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use atproto_oauth_aip::workflow::client_credentials_token;
/// use atproto_oauth::workflow::TokenResponse;
/// # let http_client = reqwest::Client::new();
/// # let aip_hostname = "auth.example.com";
/// # let client_id = "service-client-id";
/// # let client_secret = "service-client-secret";
///
/// let token = client_credentials_token(
///     &http_client,
///     aip_hostname,
///     client_id,
///     client_secret,
/// ).await?;
///
/// println!("Access token: {}", token.access_token);
/// println!("Token type: {}", token.token_type);
/// println!("Expires in: {} seconds", token.expires_in);
/// # Ok(())
/// # }
/// ```
pub async fn client_credentials_token(
    http_client: &reqwest::Client,
    aip_hostname: &str,
    aip_client_id: &str,
    aip_client_secret: &str,
) -> Result<atproto_oauth::workflow::TokenResponse> {
    // Construct the token endpoint URL
    let token_url = format!("https://{}/oauth/token", aip_hostname);

    // Prepare the form data for client credentials grant
    let params = [("grant_type", "client_credentials")];

    // Send the request with Basic authentication
    let response = http_client
        .post(&token_url)
        .basic_auth(aip_client_id, Some(aip_client_secret))
        .form(&params)
        .send()
        .await
        .map_err(OAuthWorkflowError::TokenRequestFailed)?;

    // Check if the request was successful
    if !response.status().is_success() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(OAuthWorkflowError::TokenResponseInvalid {
            message: format!(
                "Token request failed with status {}: {}",
                status, error_text
            ),
        }
        .into());
    }

    // Parse the response
    response
        .json::<atproto_oauth::workflow::TokenResponse>()
        .await
        .map_err(|e| OAuthWorkflowError::TokenResponseParseFailed(e).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The confirmed attack payload: a hostile AIP authorization server returns a
    /// victim DID as `sub` for a flow the attacker started for their own DID.
    const ATTACK_TOKEN_RESPONSE: &str = r#"{"access_token":"attacker-minted","token_type":"DPoP","refresh_token":"r","scope":"atproto transition:generic","expires_in":3600,"sub":"did:plc:victim000000000000000000"}"#;

    /// The downgrade variant: `sub` omitted entirely so a caller with a fallback
    /// to the pending session DID authenticates the wrong account.
    const ATTACK_TOKEN_RESPONSE_NO_SUB: &str = r#"{"access_token":"attacker-minted","token_type":"DPoP","refresh_token":"r","scope":"atproto transition:generic","expires_in":3600}"#;

    fn token_response(json: &str) -> TokenResponse {
        serde_json::from_str(json).expect("token response deserializes")
    }

    fn oauth_request(subject: &str) -> OAuthRequest {
        OAuthRequest {
            oauth_state: "state".to_string(),
            subject: subject.to_string(),
            issuer: "https://auth.example.com".to_string(),
            authorization_server: "https://auth.example.com".to_string(),
            nonce: "nonce".to_string(),
            signing_public_key: "public-key".to_string(),
            pkce_verifier: "verifier".to_string(),
            dpop_private_key: "private-key".to_string(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        }
    }

    #[test]
    fn test_bind_response_subject_rejects_victim_impersonation() {
        let response = token_response(ATTACK_TOKEN_RESPONSE);

        let err = bind_response_subject("did:plc:attacker00000000000000", &response)
            .expect_err("victim subject must be rejected");

        assert!(matches!(
            err,
            OAuthWorkflowError::TokenSubjectBindingFailed(
                OAuthClientError::TokenSubjectMismatch { .. }
            )
        ));

        let message = err.to_string();
        assert!(
            message.contains("error-atproto-oauth-aip-workflow-10"),
            "{message}"
        );
        assert!(
            message.contains("did:plc:victim000000000000000000"),
            "{message}"
        );
    }

    #[test]
    fn test_bind_response_subject_rejects_missing_sub() {
        let response = token_response(ATTACK_TOKEN_RESPONSE_NO_SUB);
        assert!(response.sub.is_none());

        let err = bind_response_subject("did:plc:attacker00000000000000", &response)
            .expect_err("missing subject must be rejected");

        assert!(matches!(
            err,
            OAuthWorkflowError::TokenSubjectBindingFailed(
                OAuthClientError::TokenResponseMissingSubject
            )
        ));
    }

    #[test]
    fn test_bind_response_subject_accepts_exact_match() {
        let response = token_response(ATTACK_TOKEN_RESPONSE);

        bind_response_subject("did:plc:victim000000000000000000", &response)
            .expect("an exactly matching subject is accepted");
    }

    #[test]
    fn test_bind_response_subject_is_exact_comparison() {
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

            let err = bind_response_subject(expected, &response)
                .expect_err("subjects are compared byte-for-byte");
            assert!(matches!(
                err,
                OAuthWorkflowError::TokenSubjectBindingFailed(
                    OAuthClientError::TokenSubjectMismatch { .. }
                )
            ));
        }
    }

    /// An empty `OAuthRequest::subject` must fail before any request is sent, so
    /// the binding can never degrade into a no-op. The token endpoint below is
    /// unroutable: reaching it would surface as a request failure instead.
    #[tokio::test]
    async fn test_oauth_complete_rejects_empty_subject_before_network() {
        let oauth_client = OAuthClient {
            redirect_uri: "https://app.example.com/callback".to_string(),
            client_id: "client-id".to_string(),
            client_secret: "client-secret".to_string(),
        };

        let result = oauth_complete(
            &reqwest::Client::new(),
            &oauth_client,
            "http://127.0.0.1:1/token",
            "auth-code",
            &oauth_request(""),
        )
        .await;

        let err = match result {
            Ok(_) => panic!("an empty expected subject must be rejected"),
            Err(err) => err,
        };

        let workflow_error = err
            .downcast_ref::<OAuthWorkflowError>()
            .expect("error is an OAuthWorkflowError");
        assert!(matches!(
            workflow_error,
            OAuthWorkflowError::TokenSubjectBindingFailed(OAuthClientError::MissingExpectedSubject)
        ));
    }
}
