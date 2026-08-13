//! OAuth resource discovery and validation.
//!
//! Discover and validate OAuth 2.0 configuration from AT Protocol
//! PDS servers using RFC 8414 well-known endpoints.

use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::errors::{AuthServerValidationError, OAuthClientError, ResourceValidationError};

/// The most either well-known document may be.
///
/// Both are small, fixed-shape metadata documents: a handful of URLs and a few
/// lists of algorithm names. A real one runs to a couple of kilobytes, and the
/// largest plausible one — every optional field present, every list long — does
/// not approach this. 256 KiB is chosen to be obviously beyond any correct
/// server rather than to be tight.
const MAX_DISCOVERY_BYTES: usize = 256 * 1024;

/// Read a discovery document, refusing to buffer more than
/// [`MAX_DISCOVERY_BYTES`].
///
/// # Why this is not `.json()`
///
/// `Response::json` buffers the entire body before it parses anything, and
/// discovery is by definition a request to a server whose behaviour has not
/// been established — the caller is asking who it is. A hostile or broken peer
/// answering with an endless body therefore took the caller's memory with it,
/// and one request per connection was enough to do it.
///
/// `Content-Length` is not consulted, because a chunked response has none and
/// a hostile one may lie. The body is read chunk by chunk and abandoned the
/// moment it goes past the ceiling, so the peak held is bounded by the limit
/// plus one chunk regardless of what the sender claims.
async fn read_capped<T: DeserializeOwned>(
    response: reqwest::Response,
    url: &str,
) -> Result<T, OAuthClientError> {
    let mut response = response;
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(OAuthClientError::DiscoveryReadFailed)?
    {
        if body.len() + chunk.len() > MAX_DISCOVERY_BYTES {
            return Err(OAuthClientError::DiscoveryDocumentTooLarge {
                url: url.to_string(),
                limit: MAX_DISCOVERY_BYTES,
            });
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(OAuthClientError::DiscoveryParseFailed)
}

/// OAuth 2.0 protected resource metadata from RFC 8414 oauth-protected-resource endpoint.
///
/// AT Protocol requires that the authorization_servers array contains exactly one URL.
#[derive(Clone, Deserialize)]
pub struct OAuthProtectedResource {
    /// The protected resource URI, must match the PDS base URL.
    pub resource: String,
    /// Authorization server URLs that can issue tokens for this resource.
    /// AT Protocol requires exactly one authorization server URL.
    pub authorization_servers: Vec<String>,
    /// OAuth 2.0 scopes supported by this protected resource.
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    /// Bearer token methods supported (e.g., "header", "body", "query").
    #[serde(default)]
    pub bearer_methods_supported: Vec<String>,
}

/// OAuth 2.0 authorization server metadata from RFC 8414 oauth-authorization-server endpoint.
///
/// AT Protocol requires specific grant types, scopes, authentication methods, and security features.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct AuthorizationServer {
    /// URL of the authorization server's token introspection endpoint (optional).
    #[serde(default)]
    pub introspection_endpoint: String,
    /// URL of the authorization server's authorization endpoint.
    pub authorization_endpoint: String,
    /// Whether the authorization response `iss` parameter is supported (required for AT Protocol).
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
    /// Whether client ID metadata document is supported (required for AT Protocol).
    #[serde(default)]
    pub client_id_metadata_document_supported: bool,
    /// PKCE code challenge methods supported, must include "S256" for AT Protocol.
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    /// DPoP proof JWT signing algorithms supported, must include "ES256" for AT Protocol.
    #[serde(default)]
    pub dpop_signing_alg_values_supported: Vec<String>,
    /// OAuth 2.0 grant types supported, must include "authorization_code" and "refresh_token".
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    /// The authorization server's issuer identifier, must match PDS URL.
    pub issuer: String,
    /// URL of the authorization server's pushed authorization request endpoint (required for AT Protocol).
    #[serde(default)]
    pub pushed_authorization_request_endpoint: String,
    /// Whether the `request` parameter is supported (optional).
    #[serde(default)]
    pub request_parameter_supported: bool,
    /// Whether pushed authorization requests are required (required for AT Protocol).
    #[serde(default)]
    pub require_pushed_authorization_requests: bool,
    /// OAuth 2.0 response types supported, must include "code" for AT Protocol.
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    /// OAuth 2.0 scopes supported, must include "atproto" and "transition:generic" for AT Protocol.
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    /// Client authentication methods supported, must include "none" and "private_key_jwt".
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// JWT signing algorithms for client authentication, must include "ES256" for AT Protocol.
    #[serde(default)]
    pub token_endpoint_auth_signing_alg_values_supported: Vec<String>,
    /// URL of the authorization server's token endpoint.
    pub token_endpoint: String,
}

/// Retrieves and validates OAuth configuration from a Personal Data Server (PDS).
///
/// Fetches both the protected resource metadata and authorization server metadata
/// from the PDS's well-known OAuth endpoints, returning the first authorization server.
pub async fn pds_resources(
    http_client: &reqwest::Client,
    pds: &str,
) -> Result<(OAuthProtectedResource, AuthorizationServer), OAuthClientError> {
    let protected_resource = oauth_protected_resource(http_client, pds).await?;

    let first_authorization_server = protected_resource
        .authorization_servers
        .first()
        .ok_or(OAuthClientError::InvalidOAuthProtectedResource)?;

    let authorization_server =
        oauth_authorization_server(http_client, first_authorization_server).await?;
    Ok((protected_resource, authorization_server))
}

/// Fetches and validates protected resource metadata from a PDS's well-known endpoint.
///
/// Retrieves OAuth 2.0 protected resource configuration from `/.well-known/oauth-protected-resource`
/// and validates that the resource URI matches the PDS URL and has exactly one authorization server
/// as required by AT Protocol specification.
pub async fn oauth_protected_resource(
    http_client: &reqwest::Client,
    pds: &str,
) -> Result<OAuthProtectedResource, OAuthClientError> {
    let destination = format!("{}/.well-known/oauth-protected-resource", pds);

    let response = http_client
        .get(&destination)
        .send()
        .await
        .map_err(OAuthClientError::OAuthProtectedResourceRequestFailed)?;
    let resource: OAuthProtectedResource = read_capped(response, &destination).await?;

    if resource.resource != pds {
        return Err(OAuthClientError::InvalidOAuthProtectedResourceResponse(
            ResourceValidationError::ResourceMustMatchPds.into(),
        ));
    }

    if resource.authorization_servers.len() != 1 {
        return Err(OAuthClientError::InvalidOAuthProtectedResourceResponse(
            ResourceValidationError::AuthorizationServersMustContainExactlyOne.into(),
        ));
    }

    Ok(resource)
}

/// Fetches and validates authorization server metadata from a PDS's well-known endpoint.
///
/// Retrieves OAuth 2.0 authorization server configuration from `/.well-known/oauth-authorization-server`
/// and validates AT Protocol requirements including:
/// - Required grant types: authorization_code, refresh_token
/// - Required scopes: atproto, transition:generic
/// - Required security features: PKCE (S256), DPoP (ES256), PAR
/// - Required authentication methods: none, private_key_jwt
pub async fn oauth_authorization_server(
    http_client: &reqwest::Client,
    pds: &str,
) -> Result<AuthorizationServer, OAuthClientError> {
    let destination = format!("{}/.well-known/oauth-authorization-server", pds);

    let response = http_client
        .get(&destination)
        .send()
        .await
        .map_err(OAuthClientError::AuthorizationServerRequestFailed)?;
    let resource: AuthorizationServer = read_capped(response, &destination).await?;

    // Validate AT Protocol requirements for authorization server metadata

    // Validate required fields are not empty
    if resource.issuer.is_empty() {
        return Err(OAuthClientError::InvalidAuthorizationServerResponse(
            AuthServerValidationError::IssuerMustMatchPds.into(),
        ));
    }
    if resource.authorization_endpoint.is_empty() {
        return Err(OAuthClientError::InvalidAuthorizationServerResponse(
            AuthServerValidationError::RequiredServerFeaturesMustBeSupported.into(),
        ));
    }
    if resource.token_endpoint.is_empty() {
        return Err(OAuthClientError::InvalidAuthorizationServerResponse(
            AuthServerValidationError::RequiredServerFeaturesMustBeSupported.into(),
        ));
    }

    if resource.issuer != pds {
        return Err(OAuthClientError::InvalidAuthorizationServerResponse(
            AuthServerValidationError::IssuerMustMatchPds.into(),
        ));
    }

    resource
        .response_types_supported
        .iter()
        .find(|&x| x == "code")
        .ok_or(OAuthClientError::InvalidAuthorizationServerResponse(
            AuthServerValidationError::ResponseTypesSupportMustIncludeCode.into(),
        ))?;

    resource
        .grant_types_supported
        .iter()
        .find(|&x| x == "authorization_code")
        .ok_or(OAuthClientError::InvalidAuthorizationServerResponse(
            AuthServerValidationError::GrantTypesSupportMustIncludeAuthorizationCode.into(),
        ))?;
    resource
        .grant_types_supported
        .iter()
        .find(|&x| x == "refresh_token")
        .ok_or(OAuthClientError::InvalidAuthorizationServerResponse(
            AuthServerValidationError::GrantTypesSupportMustIncludeRefreshToken.into(),
        ))?;
    resource
        .code_challenge_methods_supported
        .iter()
        .find(|&x| x == "S256")
        .ok_or(OAuthClientError::InvalidAuthorizationServerResponse(
            AuthServerValidationError::CodeChallengeMethodsSupportedMustIncludeS256.into(),
        ))?;
    resource
        .token_endpoint_auth_methods_supported
        .iter()
        .find(|&x| x == "none")
        .ok_or(OAuthClientError::InvalidAuthorizationServerResponse(
            AuthServerValidationError::TokenEndpointAuthMethodsSupportedMustIncludeNone.into(),
        ))?;
    resource
        .token_endpoint_auth_methods_supported
        .iter()
        .find(|&x| x == "private_key_jwt")
        .ok_or(OAuthClientError::InvalidAuthorizationServerResponse(
            AuthServerValidationError::TokenEndpointAuthMethodsSupportedMustIncludePrivateKeyJwt
                .into(),
        ))?;
    resource
        .token_endpoint_auth_signing_alg_values_supported
        .iter()
        .find(|&x| x == "ES256")
        .ok_or(OAuthClientError::InvalidAuthorizationServerResponse(
            AuthServerValidationError::TokenEndpointAuthSigningAlgValuesMustIncludeES256.into(),
        ))?;
    resource
        .scopes_supported
        .iter()
        .find(|&x| x == "atproto")
        .ok_or(OAuthClientError::InvalidAuthorizationServerResponse(
            AuthServerValidationError::ScopesSupportedMustIncludeAtProto.into(),
        ))?;
    resource
        .scopes_supported
        .iter()
        .find(|&x| x == "transition:generic")
        .ok_or(OAuthClientError::InvalidAuthorizationServerResponse(
            AuthServerValidationError::ScopesSupportedMustIncludeTransitionGeneric.into(),
        ))?;
    resource
        .dpop_signing_alg_values_supported
        .iter()
        .find(|&x| x == "ES256")
        .ok_or(OAuthClientError::InvalidAuthorizationServerResponse(
            AuthServerValidationError::DpopSigningAlgValuesSupportedMustIncludeES256.into(),
        ))?;

    if !(resource.authorization_response_iss_parameter_supported
        && resource.require_pushed_authorization_requests
        && resource.client_id_metadata_document_supported)
    {
        return Err(OAuthClientError::InvalidAuthorizationServerResponse(
            AuthServerValidationError::RequiredServerFeaturesMustBeSupported.into(),
        ));
    }

    Ok(resource)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `reqwest::Response` over a body, without a server to serve it.
    fn response_of(body: Vec<u8>) -> reqwest::Response {
        reqwest::Response::from(http::Response::new(body))
    }

    #[tokio::test]
    async fn a_metadata_document_of_ordinary_size_is_read() {
        let body = br#"{"resource":"https://pds.example","authorization_servers":["https://pds.example"]}"#;
        let parsed: OAuthProtectedResource =
            read_capped(response_of(body.to_vec()), "https://pds.example")
                .await
                .expect("an ordinary document should parse");
        assert_eq!(parsed.resource, "https://pds.example");
    }

    /// The point of the cap: a peer answering a request for a few hundred
    /// bytes with something enormous is refused rather than buffered.
    #[tokio::test]
    async fn an_oversized_document_is_refused_rather_than_buffered() {
        let body = vec![b' '; MAX_DISCOVERY_BYTES + 1];
        let outcome: Result<OAuthProtectedResource, _> =
            read_capped(response_of(body), "https://hostile.example").await;

        match outcome {
            Err(OAuthClientError::DiscoveryDocumentTooLarge { url, limit }) => {
                assert_eq!(url, "https://hostile.example");
                assert_eq!(limit, MAX_DISCOVERY_BYTES);
            }
            Err(other) => panic!("an oversized document was refused for the wrong reason: {other}"),
            Ok(_) => panic!("an oversized document was buffered and parsed"),
        }
    }

    /// A body that is within the cap but is not the document it claims to be
    /// fails as a parse error, not as a size one.
    #[tokio::test]
    async fn a_malformed_document_is_reported_as_a_parse_failure() {
        let outcome: Result<OAuthProtectedResource, _> = read_capped(
            response_of(b"not json at all".to_vec()),
            "https://pds.example",
        )
        .await;
        assert!(matches!(
            outcome,
            Err(OAuthClientError::DiscoveryParseFailed(_))
        ));
    }
}
