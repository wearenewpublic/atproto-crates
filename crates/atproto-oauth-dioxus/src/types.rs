use serde::{Deserialize, Serialize};

/// Response returned after initiating the OAuth authorization flow.
///
/// Contains the URL that the user should be redirected to for
/// authenticating with their AT Protocol provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthInitResponse {
    /// The authorization URL to redirect the user to.
    pub authorization_url: String,
}

/// Session data returned after successful OAuth token exchange.
///
/// Contains the authenticated user's identity and access credentials
/// needed to make authorized API calls to their PDS.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionData {
    /// The user's decentralized identifier (DID).
    pub did: String,
    /// The user's AT Protocol handle.
    pub handle: String,
    /// The endpoint URL of the user's Personal Data Server.
    pub pds_endpoint: String,
    /// The OAuth access token for authenticated API calls.
    pub access_token: String,
}

/// OAuth client metadata published at `client-metadata.json`.
///
/// Served as a well-known endpoint for the AT Protocol authorization
/// server to discover client configuration including JWKS and redirect URIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientMetadata {
    /// The OAuth client identifier.
    pub client_id: String,
    /// Whether DPoP-bound access tokens are supported.
    pub dpop_bound_access_tokens: bool,
    /// The application type (always `web`).
    pub application_type: String,
    /// Allowed redirect URIs after authorization.
    pub redirect_uris: Vec<String>,
    /// Supported OAuth grant types.
    pub grant_types: Vec<String>,
    /// Supported OAuth response types.
    pub response_types: Vec<String>,
    /// Requested OAuth scope.
    pub scope: String,
    /// Authentication method for the token endpoint.
    pub token_endpoint_auth_method: String,
    /// Subject type for the client.
    pub subject_type: String,
    /// Signing algorithm for token endpoint authentication.
    pub token_endpoint_auth_signing_alg: String,
    /// JSON Web Key Set containing the client's public signing key.
    pub jwks: serde_json::Value,
}

/// Reactive session state used on the client side.
///
/// Stored in Dioxus context and persisted to localStorage so the
/// session survives page reloads.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SessionState {
    /// Whether the user is currently authenticated.
    pub is_authenticated: bool,
    /// The user's decentralized identifier (DID).
    pub did: String,
    /// The user's AT Protocol handle.
    pub handle: String,
    /// The endpoint URL of the user's Personal Data Server.
    pub pds_endpoint: String,
    /// The OAuth access token.
    pub access_token: String,
}
