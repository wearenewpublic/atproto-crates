//! OAuth AIP (Identity Provider) implementation for AT Protocol.
//!
//! Complete OAuth 2.0 authorization code flow with PAR, PKCE, token exchange,
//! and AT Protocol session management for identity providers.
//! ```rust,no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use atproto_oauth_aip::workflow::{oauth_init, oauth_complete, session_exchange, OAuthClient};
//! use atproto_oauth::resources::AuthorizationServer;
//! use atproto_oauth::workflow::OAuthRequestState;
//!
//! let http_client = reqwest::Client::new();
//! let oauth_client = OAuthClient {
//!     redirect_uri: "https://redirect.example.com/callback".to_string(),
//!     client_id: "client123".to_string(),
//!     client_secret: "secret456".to_string(),
//! };
//!
//! let authorization_server = AuthorizationServer {
//!     issuer: "https://auth.example.com".to_string(),
//!     authorization_endpoint: "https://auth.example.com/authorize".to_string(),
//!     token_endpoint: "https://auth.example.com/token".to_string(),
//!     pushed_authorization_request_endpoint: "https://auth.example.com/par".to_string(),
//!     introspection_endpoint: "".to_string(),
//!     scopes_supported: vec!["atproto".to_string(), "transition:generic".to_string()],
//!     response_types_supported: vec!["code".to_string()],
//!     grant_types_supported: vec!["authorization_code".to_string(), "refresh_token".to_string()],
//!     token_endpoint_auth_methods_supported: vec!["none".to_string(), "private_key_jwt".to_string()],
//!     token_endpoint_auth_signing_alg_values_supported: vec!["ES256".to_string()],
//!     require_pushed_authorization_requests: true,
//!     request_parameter_supported: false,
//!     code_challenge_methods_supported: vec!["S256".to_string()],
//!     authorization_response_iss_parameter_supported: true,
//!     dpop_signing_alg_values_supported: vec!["ES256".to_string()],
//!     client_id_metadata_document_supported: true,
//! };
//!
//! let oauth_request_state = OAuthRequestState {
//!     state: "random-state".to_string(),
//!     nonce: "random-nonce".to_string(),
//!     code_challenge: "code-challenge".to_string(),
//!     scope: "atproto transition:generic".to_string(),
//! };
//!
//! // Initialize OAuth flow with PAR
//! let par_response = oauth_init(
//!     &http_client,
//!     &oauth_client,
//!     Some("user_handle"),
//!     &authorization_server.pushed_authorization_request_endpoint,
//!     &oauth_request_state
//! ).await?;
//!
//! // Complete OAuth flow with authorization code
//! # let oauth_request = atproto_oauth::workflow::OAuthRequest {
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
//!     "authorization_code",
//!     &oauth_request
//! ).await?;
//!
//! // Exchange tokens for AT Protocol session
//! # let protected_resource = atproto_oauth::resources::OAuthProtectedResource {
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
//! All operations use structured error types with descriptive messages following
//! the project's error convention format.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Error types for OAuth workflow operations.
pub mod errors;
/// Resource definitions for OAuth operations.
pub mod resources;
/// OAuth workflow implementation.
pub mod workflow;
