//! OAuth client metadata endpoint handler.
//!
//! RFC 7591 compliant client metadata for dynamic registration
//! and authorization server discovery.

use atproto_identity::key::to_public;
use axum::{Json, response::IntoResponse};
use serde::Serialize;

use crate::state::OAuthClientConfig;
use atproto_oauth::jwk::{WrappedJsonWebKeySet, generate};

// See also: https://atproto.com/specs/oauth#client-id-metadata-document
#[derive(Serialize, Default)]
struct AuthMetadata<'a> {
    client_id: String,
    dpop_bound_access_tokens: bool,
    application_type: &'a str,
    redirect_uris: Vec<String>,
    grant_types: Vec<&'a str>,
    response_types: Vec<&'a str>,
    scope: String,
    token_endpoint_auth_method: &'a str,
    subject_type: &'a str,
    token_endpoint_auth_signing_alg: &'a str,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    jwks_uri: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    jwks: Option<WrappedJsonWebKeySet>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    client_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    client_uri: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    logo_uri: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    tos_uri: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    policy_uri: Option<String>,
}

/// Handles requests for OAuth client metadata.
///
/// Returns RFC 7591 compliant client metadata for dynamic client registration.
pub async fn handle_oauth_metadata(oauth_client_config: OAuthClientConfig) -> impl IntoResponse {
    // Determine jwks_uri and jwks based on configuration
    let (jwks_uri, jwks) = if let Some(ref uri) = oauth_client_config.jwks_uri {
        // If jwks_uri is provided, use it and don't include inline jwks
        (Some(uri.clone()), None)
    } else {
        // If no jwks_uri, build inline jwks from signing keys
        let mut jwks_keys = Vec::new();
        for key_data in &oauth_client_config.signing_keys {
            if let Ok(public_key_data) = to_public(key_data)
                && let Ok(jwk) = generate(&public_key_data)
            {
                jwks_keys.push(jwk);
            }
        }
        (None, Some(WrappedJsonWebKeySet { keys: jwks_keys }))
    };

    let resp = AuthMetadata {
        application_type: "web",
        client_id: oauth_client_config.client_id.clone(),
        dpop_bound_access_tokens: true,
        grant_types: vec!["authorization_code", "refresh_token"],
        redirect_uris: vec![oauth_client_config.redirect_uris.clone()],
        response_types: vec!["code"],
        scope: oauth_client_config.scope().to_string(),
        token_endpoint_auth_method: "private_key_jwt",
        token_endpoint_auth_signing_alg: "ES256",
        subject_type: "public",
        jwks_uri,
        jwks,
        client_name: oauth_client_config.client_name.clone(),
        client_uri: oauth_client_config.client_uri.clone(),
        logo_uri: oauth_client_config.logo_uri.clone(),
        tos_uri: oauth_client_config.tos_uri.clone(),
        policy_uri: oauth_client_config.policy_uri.clone(),
    };
    Json(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_identity::key::{KeyType, generate_key};

    /// The private key types a confidential client can be configured with.
    const PRIVATE_KEY_TYPES: [KeyType; 3] = [
        KeyType::P256Private,
        KeyType::P384Private,
        KeyType::K256Private,
    ];

    /// Render a handler response the way a peer receives it: as bytes.
    async fn served_body(response: impl IntoResponse) -> String {
        let body = response.into_response().into_body();
        let bytes = axum::body::to_bytes(body, usize::MAX)
            .await
            .expect("read response body");
        String::from_utf8(bytes.to_vec()).expect("response body is UTF-8")
    }

    #[tokio::test]
    async fn inline_jwks_never_carries_a_private_scalar() {
        // This handler was already correct. The assertion exists so it stays
        // that way — it is the same disclosure that `handle_oauth_jwks` had.
        for key_type in PRIVATE_KEY_TYPES {
            let signing_key = generate_key(key_type.clone()).expect("generate signing key");
            let config = OAuthClientConfig {
                client_id: "https://example.com/oauth/client-metadata.json".to_string(),
                redirect_uris: "https://example.com/oauth/callback".to_string(),
                signing_keys: vec![signing_key],
                ..Default::default()
            };

            let served = served_body(handle_oauth_metadata(config).await).await;

            assert!(
                !served.contains("\"d\""),
                "client metadata for {key_type:?} published a private scalar: {served}"
            );
            assert!(
                served.contains("\"jwks\""),
                "client metadata for {key_type:?} published no inline jwks: {served}"
            );
        }
    }

    #[tokio::test]
    async fn jwks_uri_replaces_the_inline_key_set() {
        let signing_key = generate_key(KeyType::P256Private).expect("generate signing key");
        let config = OAuthClientConfig {
            client_id: "https://example.com/oauth/client-metadata.json".to_string(),
            redirect_uris: "https://example.com/oauth/callback".to_string(),
            jwks_uri: Some("https://example.com/oauth/jwks".to_string()),
            signing_keys: vec![signing_key],
            ..Default::default()
        };

        let served = served_body(handle_oauth_metadata(config).await).await;

        assert!(!served.contains("\"d\""), "{served}");
        assert!(served.contains("\"jwks_uri\""), "{served}");
        assert!(!served.contains("\"jwks\":"), "{served}");
    }
}
