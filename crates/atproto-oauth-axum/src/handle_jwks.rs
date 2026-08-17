//! JSON Web Key Set (JWKS) endpoint handler.
//!
//! Serve OAuth client public keys for JWT signature verification
//! by authorization servers.

use atproto_identity::key::to_public;
use atproto_oauth::jwk::{WrappedJsonWebKey, generate};
use axum::{Json, response::IntoResponse};
use serde::Serialize;

use crate::state::OAuthClientConfig;

/// JSON Web Key Set response structure.
///
/// Contains a collection of public keys for JWT signature verification.
#[derive(Serialize)]
pub struct WrappedJsonWebKeySet {
    /// Array of JSON Web Keys
    pub keys: Vec<WrappedJsonWebKey>,
}

/// Handles requests for the OAuth JWKS (JSON Web Key Set) endpoint.
///
/// Returns the public keys used by this OAuth client for JWT signature
/// verification. `signing_keys` normally holds *private* keys — signing client
/// assertions for `private_key_jwt` requires them — so each one is reduced to
/// its public form before it is published. A key that cannot be converted is
/// skipped rather than served in whatever form it happens to be in, and rather
/// than failing the whole document: one unusable key should not take the other
/// keys' endpoint down with it.
pub async fn handle_oauth_jwks(oauth_client_config: OAuthClientConfig) -> impl IntoResponse {
    let mut jwks = Vec::new();
    for key_data in &oauth_client_config.signing_keys {
        let published = to_public(key_data)
            .map_err(anyhow::Error::from)
            .and_then(|public_key_data| generate(&public_key_data));
        match published {
            Ok(jwk) => jwks.push(jwk),
            Err(error) => {
                tracing::warn!(error = ?error, "JWKS: skipping a signing key that could not be published");
            }
        }
    }
    Json(WrappedJsonWebKeySet { keys: jwks })
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
    async fn jwks_document_never_carries_a_private_scalar() {
        for key_type in PRIVATE_KEY_TYPES {
            let signing_key = generate_key(key_type.clone()).expect("generate signing key");
            let config = OAuthClientConfig {
                client_id: "https://example.com/oauth/client-metadata.json".to_string(),
                signing_keys: vec![signing_key],
                ..Default::default()
            };

            let served = served_body(handle_oauth_jwks(config).await).await;

            // Assert on the serialized document rather than on a field: the
            // inner JWK is `#[serde(flatten)]`ed, so a field-level assertion
            // can pass while `d` still reaches the wire.
            assert!(
                !served.contains("\"d\""),
                "JWKS for {key_type:?} published a private scalar: {served}"
            );
            assert!(
                served.contains("\"kty\"") && served.contains("\"x\""),
                "JWKS for {key_type:?} published no usable key: {served}"
            );
        }
    }

    #[tokio::test]
    async fn jwks_document_publishes_the_public_form_of_each_signing_key() {
        let first = generate_key(KeyType::P256Private).expect("generate first key");
        let second = generate_key(KeyType::K256Private).expect("generate second key");
        let expected: Vec<String> = [&first, &second]
            .into_iter()
            .map(|key| to_public(key).expect("derive public key").to_string())
            .collect();

        let config = OAuthClientConfig {
            client_id: "https://example.com/oauth/client-metadata.json".to_string(),
            signing_keys: vec![first, second],
            ..Default::default()
        };

        let served = served_body(handle_oauth_jwks(config).await).await;
        let document: serde_json::Value = serde_json::from_str(&served).expect("parse JWKS");
        let keys = document["keys"].as_array().expect("keys array");

        assert_eq!(keys.len(), 2, "every signing key should be published");
        for (key, expected_kid) in keys.iter().zip(expected) {
            // `kid` is the public did:key, so a private kid would be visible here too.
            assert_eq!(key["kid"], serde_json::Value::String(expected_kid));
            assert!(key.get("d").is_none(), "published key carries `d`: {key}");
        }
    }

    #[tokio::test]
    async fn jwks_document_is_empty_when_no_keys_are_configured() {
        let served = served_body(handle_oauth_jwks(OAuthClientConfig::default()).await).await;
        assert_eq!(served, r#"{"keys":[]}"#);
    }
}
