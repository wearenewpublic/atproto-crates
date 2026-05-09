//! OAuth resource discovery and validation.
//!
//! Discover and validate OAuth 2.0 configuration from AT Protocol
//! PDS servers using RFC 8414 well-known endpoints.

use serde::Deserialize;

use crate::errors::{AuthServerValidationError, OAuthClientError, ResourceValidationError};

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
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, Deserialize, Default)]
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

    let resource: OAuthProtectedResource = http_client
        .get(destination)
        .send()
        .await
        .map_err(OAuthClientError::OAuthProtectedResourceRequestFailed)?
        .json()
        .await
        .map_err(OAuthClientError::MalformedOAuthProtectedResourceResponse)?;

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

    let resource: AuthorizationServer = http_client
        .get(destination)
        .send()
        .await
        .map_err(OAuthClientError::AuthorizationServerRequestFailed)?
        .json()
        .await
        .map_err(OAuthClientError::MalformedAuthorizationServerResponse)?;

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
