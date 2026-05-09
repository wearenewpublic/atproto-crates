//! OAuth resource discovery for AT Protocol identity providers.

use atproto_oauth::{
    errors::OAuthClientError,
    resources::{AuthorizationServer, OAuthProtectedResource},
};

/// Fetch OAuth protected resource metadata from an AIP server.
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for making the request
/// * `aip_server` - The base URL of the AIP server (e.g., "<https://example.com>")
///
/// # Returns
///
/// Returns the OAuth protected resource metadata on success, or an error if:
/// - The HTTP request fails
/// - The response cannot be parsed as valid OAuth protected resource metadata
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let http_client = reqwest::Client::new();
/// use atproto_oauth_aip::resources::oauth_protected_resource;
/// let resource = oauth_protected_resource(&http_client, "https://bsky.social").await?;
/// # Ok(())
/// # }
/// ```
pub async fn oauth_protected_resource(
    http_client: &reqwest::Client,
    aip_server: &str,
) -> Result<OAuthProtectedResource, OAuthClientError> {
    let destination = format!("{}/.well-known/oauth-protected-resource", aip_server);

    let resource: OAuthProtectedResource = http_client
        .get(destination)
        .send()
        .await
        .map_err(OAuthClientError::OAuthProtectedResourceRequestFailed)?
        .json()
        .await
        .map_err(OAuthClientError::MalformedOAuthProtectedResourceResponse)?;

    Ok(resource)
}

/// Fetches OAuth authorization server metadata from an AIP server.
///
/// This function retrieves the OAuth authorization server configuration from
/// the well-known endpoint of an AT Protocol Identity Provider (AIP) server.
/// The metadata includes essential information such as:
/// - Authorization endpoint URL
/// - Token endpoint URL
/// - Pushed Authorization Request (PAR) endpoint URL
/// - Supported OAuth flows and capabilities
/// - JWKS (JSON Web Key Set) endpoint
///
/// # Arguments
///
/// * `http_client` - The HTTP client to use for making the request
/// * `aip_server` - The base URL of the AIP server (e.g., "<https://example.com>")
///
/// # Returns
///
/// Returns the OAuth authorization server metadata on success, or an error if:
/// - The HTTP request fails
/// - The response cannot be parsed as valid OAuth authorization server metadata
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let http_client = reqwest::Client::new();
/// use atproto_oauth_aip::resources::oauth_authorization_server;
/// let auth_server = oauth_authorization_server(&http_client, "https://bsky.social").await?;
/// println!("Authorization endpoint: {}", auth_server.authorization_endpoint);
/// println!("Token endpoint: {}", auth_server.token_endpoint);
/// # Ok(())
/// # }
/// ```
pub async fn oauth_authorization_server(
    http_client: &reqwest::Client,
    aip_server: &str,
) -> Result<AuthorizationServer, OAuthClientError> {
    let destination = format!("{}/.well-known/oauth-authorization-server", aip_server);

    let resource: AuthorizationServer = http_client
        .get(destination)
        .send()
        .await
        .map_err(OAuthClientError::AuthorizationServerRequestFailed)?
        .json()
        .await
        .map_err(OAuthClientError::MalformedAuthorizationServerResponse)?;

    Ok(resource)
}
