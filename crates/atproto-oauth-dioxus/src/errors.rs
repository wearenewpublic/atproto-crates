use thiserror::Error;

/// Error type for OAuth Dioxus integration operations.
///
/// Follows the convention `error-atproto-oauth-dioxus-{domain}-{number}`.
#[derive(Debug, Error)]
pub enum DioxusOAuthError {
    /// Failed to resolve an AT Protocol handle to a DID.
    #[error("error-atproto-oauth-dioxus-resolve-1 Failed to resolve handle: {0}")]
    HandleResolutionFailed(String),

    /// Failed to discover PDS OAuth resources.
    #[error("error-atproto-oauth-dioxus-resolve-2 Failed to discover PDS OAuth resources: {0}")]
    PdsResourceDiscoveryFailed(String),

    /// Failed to resolve DID to a PDS endpoint.
    #[error("error-atproto-oauth-dioxus-resolve-3 Failed to resolve DID to PDS: {0}")]
    PdsResolutionFailed(String),

    /// The OAuth authorization initiation failed.
    #[error("error-atproto-oauth-dioxus-init-1 OAuth authorization initiation failed: {0}")]
    OAuthInitFailed(String),

    /// Invalid or expired OAuth state during callback.
    #[error("error-atproto-oauth-dioxus-callback-1 Invalid or expired OAuth state")]
    InvalidOAuthState,

    /// The token exchange failed.
    #[error("error-atproto-oauth-dioxus-callback-2 Token exchange failed: {0}")]
    TokenExchangeFailed(String),

    /// The token response is missing the `sub` (DID) field.
    #[error("error-atproto-oauth-dioxus-callback-3 Token response missing 'sub' (DID) field")]
    MissingSubField,

    /// Failed to generate or load the OAuth signing key.
    #[error("error-atproto-oauth-dioxus-key-1 Failed to initialize OAuth signing key: {0}")]
    KeyInitializationFailed(String),

    /// The OAUTH_KEY_SEED environment variable has an invalid format.
    #[error("error-atproto-oauth-dioxus-key-2 Invalid OAUTH_KEY_SEED: {0}")]
    InvalidKeySeed(String),

    /// Failed to derive the public key from the private signing key.
    #[error("error-atproto-oauth-dioxus-key-3 Failed to derive public key: {0}")]
    PublicKeyDerivationFailed(String),

    /// Failed to generate a JWK from the signing key.
    #[error("error-atproto-oauth-dioxus-key-4 Failed to generate JWK: {0}")]
    JwkGenerationFailed(String),

    /// Configuration error.
    #[error("error-atproto-oauth-dioxus-config-1 Configuration error: {0}")]
    ConfigurationError(String),
}
