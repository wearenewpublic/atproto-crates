//! `.well-known/oauth-authorization-server` (RFC 8414) and
//! `.well-known/oauth-protected-resource` (RFC 9728).

use crate::http::state::HttpState;
use axum::Json;
use axum::extract::State;
use serde::Serialize;

/// RFC 8414 Authorization Server Metadata document.
#[derive(Debug, Serialize)]
pub struct AuthorizationServerMetadata {
    /// Issuer identifier.
    pub issuer: String,
    /// Authorization endpoint.
    pub authorization_endpoint: String,
    /// Token endpoint.
    pub token_endpoint: String,
    /// PAR endpoint.
    pub pushed_authorization_request_endpoint: String,
    /// Whether PAR is required (always true for atproto OAuth).
    pub require_pushed_authorization_requests: bool,
    /// Revocation endpoint.
    pub revocation_endpoint: String,
    /// JWKS URI.
    pub jwks_uri: String,
    /// Supported response types.
    pub response_types_supported: Vec<String>,
    /// Supported grant types.
    pub grant_types_supported: Vec<String>,
    /// Supported PKCE challenge methods.
    pub code_challenge_methods_supported: Vec<String>,
    /// Supported scopes.
    pub scopes_supported: Vec<String>,
    /// Supported DPoP signing alg values (per RFC 9449).
    pub dpop_signing_alg_values_supported: Vec<String>,
    /// Whether the AS requires DPoP-bound access tokens.
    pub require_dpop_bound_access_tokens: bool,
    /// Supported client authentication methods.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// Whether a `client_id` may be the URL of a client metadata document.
    ///
    /// Not advisory in AT Protocol: clients are identified by the URL their
    /// metadata lives at rather than by pre-registration, so a client library
    /// reads this flag to decide whether it can use the server at all.
    /// `@atproto/oauth-client` throws when it is not `true`, before issuing any
    /// request.
    pub client_id_metadata_document_supported: bool,
}

/// RFC 9728 Protected Resource Metadata.
#[derive(Debug, Serialize)]
pub struct ProtectedResourceMetadata {
    /// The resource identifier (PDS URL).
    pub resource: String,
    /// Authorization servers that protect this resource.
    pub authorization_servers: Vec<String>,
}

/// Handler for `GET /.well-known/oauth-authorization-server`.
pub async fn oauth_authorization_server(
    State(state): State<HttpState>,
) -> Json<AuthorizationServerMetadata> {
    let issuer = issuer_url(&state.service_did);
    Json(AuthorizationServerMetadata {
        issuer: issuer.clone(),
        authorization_endpoint: format!("{issuer}/oauth/authorize"),
        token_endpoint: format!("{issuer}/oauth/token"),
        pushed_authorization_request_endpoint: format!("{issuer}/oauth/par"),
        require_pushed_authorization_requests: true,
        revocation_endpoint: format!("{issuer}/oauth/revoke"),
        jwks_uri: format!("{issuer}/oauth/jwks"),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        code_challenge_methods_supported: vec!["S256".to_string()],
        scopes_supported: vec![
            "atproto".to_string(),
            "transition:generic".to_string(),
            "transition:chat.bsky".to_string(),
        ],
        dpop_signing_alg_values_supported: vec!["ES256".to_string(), "ES256K".to_string()],
        require_dpop_bound_access_tokens: true,
        token_endpoint_auth_methods_supported: vec![
            "none".to_string(),
            "private_key_jwt".to_string(),
        ],
        // AT Protocol has no client pre-registration; the client_id IS the
        // metadata URL, and this is how a client discovers that.
        client_id_metadata_document_supported: true,
    })
}

/// Handler for `GET /.well-known/oauth-protected-resource`.
pub async fn oauth_protected_resource(
    State(state): State<HttpState>,
) -> Json<ProtectedResourceMetadata> {
    let issuer = issuer_url(&state.service_did);
    Json(ProtectedResourceMetadata {
        resource: issuer.clone(),
        authorization_servers: vec![issuer],
    })
}

pub(crate) fn issuer_url(service_did: &str) -> String {
    if let Some(host) = service_did.strip_prefix("did:web:") {
        format!("https://{host}")
    } else {
        format!("https://{service_did}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_url_from_did_web() {
        assert_eq!(
            issuer_url("did:web:pds.example.com"),
            "https://pds.example.com"
        );
    }
}
