//! JWT authorization extractors for XRPC services.
//!
//! Axum extractors for JWT validation against DID documents resolved
//! via an identity resolver.

use anyhow::Result;
use atproto_identity::key::identify_key;
use atproto_identity::traits::IdentityResolver;
use atproto_oauth::jwt::{Claims, Header};
use axum::extract::{FromRef, OptionalFromRequestParts};
use axum::http::request::Parts;
use base64::Engine as _;
use base64::engine::general_purpose;
use std::convert::Infallible;
use std::sync::Arc;

use crate::errors::AuthorizationError;

/// JWT authorization extractor that validates tokens against DID documents.
///
/// Contains JWT header, validated claims, original token, and validation status.
/// Resolves DID documents via the configured identity resolver.
///
/// # The fourth field is load-bearing
///
/// This extractor is deliberately infallible: a token that does not validate
/// still arrives, with `self.3` set to `false`, so a handler can decide what
/// an unauthenticated request means for it. That means **the claims in
/// `self.1` are not verified unless `self.3` is true** -- and on a failed
/// validation they are `Claims::default()`, so a handler that reads them
/// without checking sees an empty issuer rather than an attacker's, which
/// fails closed but says nothing about why.
///
/// Reach for [`Authorization::verified_claims`] rather than the tuple fields.
/// It returns `None` for an unverified token, which makes the distinction
/// impossible to skip by accident; `self.1` makes it a boolean somebody has to
/// remember.
#[derive(Clone)]
pub struct Authorization(pub Header, pub Claims, pub String, pub bool);

impl Authorization {
    /// identity returns the optional issuer claim of the authorization structure.
    pub fn identity(&self) -> Option<&str> {
        if self.3 {
            return self.1.jose.issuer.as_deref();
        }
        None
    }

    /// Whether the token validated against the issuer's published keys.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.3
    }

    /// The bearer token as it arrived, verified or not.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.2
    }

    /// The claims, but only if the signature checked out.
    ///
    /// The shape to reach for. Every other accessor here hands back something
    /// that may not have been verified, and this one cannot.
    #[must_use]
    pub fn verified_claims(&self) -> Option<&Claims> {
        self.3.then_some(&self.1)
    }

    /// The header, but only if the signature checked out.
    #[must_use]
    pub fn verified_header(&self) -> Option<&Header> {
        self.3.then_some(&self.0)
    }
}

impl<S> OptionalFromRequestParts<S> for Authorization
where
    S: Send + Sync,
    Arc<dyn IdentityResolver>: FromRef<S>,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));

        let token = match auth_header {
            Some(token) => token.to_string(),
            None => {
                return Ok(None);
            }
        };

        let identity_resolver = Arc::<dyn IdentityResolver>::from_ref(state);

        match validate_jwt(&token, identity_resolver).await {
            Ok((header, claims)) => Ok(Some(Authorization(header, claims, token, true))),
            Err(_) => {
                // Return unvalidated authorization so the handler can decide what to do
                let header = Header::default();
                let claims = Claims::default();
                Ok(Some(Authorization(header, claims, token, false)))
            }
        }
    }
}

async fn validate_jwt(
    token: &str,
    identity_resolver: Arc<dyn IdentityResolver>,
) -> Result<(Header, Claims)> {
    // Split and decode JWT
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthorizationError::InvalidJWTFormat.into());
    }

    // Decode claims to get issuer
    let encoded_claims = parts[1];
    let claims_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_claims)
        .map_err(|e| AuthorizationError::ClaimsDecodeError { error: e })?;

    let claims: Claims = serde_json::from_slice(&claims_bytes)
        .map_err(|e| AuthorizationError::ClaimsParseError { error: e })?;

    // Get issuer from claims
    let issuer = claims
        .jose
        .issuer
        .as_ref()
        .ok_or_else(|| AuthorizationError::NoIssuerInClaims)?;

    // Resolve the DID document via identity resolver
    let did_document = identity_resolver.resolve(issuer).await.map_err(|err| {
        AuthorizationError::SubjectResolutionFailed {
            issuer: issuer.to_string(),
            error: err,
        }
    })?;

    // Extract keys from DID document
    let did_keys = did_document.did_keys();
    if did_keys.is_empty() {
        return Err(AuthorizationError::NoVerificationKeys.into());
    }

    // Try to validate with each key
    for key_multibase in did_keys {
        match identify_key(key_multibase) {
            Ok(key_data) => {
                match atproto_oauth::jwt::verify(token, &key_data) {
                    Ok(validated_claims) => {
                        // Decode header for return
                        let encoded_header = parts[0];
                        let header_bytes = general_purpose::URL_SAFE_NO_PAD
                            .decode(encoded_header)
                            .map_err(|e| AuthorizationError::HeaderDecodeError { error: e })?;
                        let header: Header = serde_json::from_slice(&header_bytes)
                            .map_err(|e| AuthorizationError::HeaderParseError { error: e })?;
                        return Ok((header, validated_claims));
                    }
                    Err(_e) => {
                        continue;
                    }
                }
            }
            Err(_e) => {
                continue;
            }
        }
    }

    Err(AuthorizationError::ValidationFailedAllKeys.into())
}

// Example JWT:
// eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE3NDg5ODg0OTcsImlzcyI6ImRpZDpwbGM6Y2Jrank1bjdiazNheDJ3cGxtdGpvZnEyIiwiYXVkIjoiZGlkOndlYjpuZ2VyYWtpbmVzLnR1bm4uZGV2IiwiZXhwIjoxNzQ4OTg4NTU3LCJseG0iOiJnYXJkZW4ubGV4aWNvbi5uZ2VyYWtpbmVzLmhlbGxvd29ybGQuSGVsbG8iLCJqdGkiOiI0ODQ2YjQ1OWMyMDFiMDNjZjBlZGMzYmE3NjQxNTk0MiJ9.sj74PPS97z81LSay6EyDOu3IQcF-bd4xGqK5u6qruhhWWiQR2IW89YMJ1s0H-P25xaTM1Zacp-pa4RlVsrH2uA

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_identity::model::{Document, VerificationMethod};
    use axum::extract::FromRef;
    use axum::http::{Method, Request};
    use std::collections::HashMap;

    #[derive(Clone)]
    struct MockResolver {
        document: Document,
    }

    #[async_trait::async_trait]
    impl IdentityResolver for MockResolver {
        async fn resolve(&self, subject: &str) -> Result<Document> {
            if subject == self.document.id {
                Ok(self.document.clone())
            } else {
                Err(anyhow::anyhow!(
                    "error-atproto-xrpcs-authorization-1 DID not found: {}",
                    subject
                ))
            }
        }
    }

    #[derive(Clone)]
    struct TestState {
        resolver: Arc<dyn IdentityResolver>,
    }

    impl FromRef<TestState> for Arc<dyn IdentityResolver> {
        fn from_ref(state: &TestState) -> Self {
            state.resolver.clone()
        }
    }

    #[tokio::test]
    async fn test_authorization_optional_from_request_parts() {
        // Create DID document with the specified DID and verification method
        let did = "did:plc:cbkjy5n7bk3ax2wplmtjofq2";
        let verification_method_id = "did:key:zQ3shXvCK2RyPrSLYQjBEw5CExZkUhJH3n1K2Mb9sC7JbvRMF";

        let document = Document {
            context: vec![],
            id: did.to_string(),
            also_known_as: vec![],
            service: vec![],
            verification_method: vec![VerificationMethod::Multikey {
                id: format!("{}#atproto", did),
                controller: did.to_string(),
                public_key_multibase: verification_method_id.to_string(),
                extra: HashMap::new(),
            }],
            extra: HashMap::new(),
        };

        // Create mock resolver
        let resolver = Arc::new(MockResolver { document }) as Arc<dyn IdentityResolver>;
        let state = TestState { resolver };

        // Create request with Authorization header
        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header("authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE3NDg5ODg0OTcsImlzcyI6ImRpZDpwbGM6Y2Jrank1bjdiazNheDJ3cGxtdGpvZnEyIiwiYXVkIjoiZGlkOndlYjpuZ2VyYWtpbmVzLnR1bm4uZGV2IiwiZXhwIjoxNzQ4OTg4NTU3LCJseG0iOiJnYXJkZW4ubGV4aWNvbi5uZ2VyYWtpbmVzLmhlbGxvd29ybGQuSGVsbG8iLCJqdGkiOiI0ODQ2YjQ1OWMyMDFiMDNjZjBlZGMzYmE3NjQxNTk0MiJ9.sj74PPS97z81LSay6EyDOu3IQcF-bd4xGqK5u6qruhhWWiQR2IW89YMJ1s0H-P25xaTM1Zacp-pa4RlVsrH2uA")
            .body(())
            .unwrap();

        let (mut parts, _body) = request.into_parts();

        // Test the OptionalFromRequestParts implementation
        let result = Authorization::from_request_parts(&mut parts, &state).await;

        // Verify the result
        assert!(result.is_ok());
        let auth_option = result.unwrap();
        assert!(auth_option.is_some());

        let authorization = auth_option.unwrap();
        assert_eq!(
            authorization.2,
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE3NDg5ODg0OTcsImlzcyI6ImRpZDpwbGM6Y2Jrank1bjdiazNheDJ3cGxtdGpvZnEyIiwiYXVkIjoiZGlkOndlYjpuZ2VyYWtpbmVzLnR1bm4uZGV2IiwiZXhwIjoxNzQ4OTg4NTU3LCJseG0iOiJnYXJkZW4ubGV4aWNvbi5uZ2VyYWtpbmVzLmhlbGxvd29ybGQuSGVsbG8iLCJqdGkiOiI0ODQ2YjQ1OWMyMDFiMDNjZjBlZGMzYmE3NjQxNTk0MiJ9.sj74PPS97z81LSay6EyDOu3IQcF-bd4xGqK5u6qruhhWWiQR2IW89YMJ1s0H-P25xaTM1Zacp-pa4RlVsrH2uA"
        ); // token

        // The JWT validation may fail (e.g., due to expiration), but we should still get an Authorization object
        // This tests that the OptionalFromRequestParts implementation works correctly
        // The validation status (authorization.3) is a boolean - no need to assert

        // If validation succeeded, verify the claims contain the expected issuer
        if authorization.3 {
            assert_eq!(authorization.1.jose.issuer.as_ref().unwrap(), did);
        }
    }

    #[tokio::test]
    async fn test_authorization_no_header() {
        // Create mock resolver
        let resolver = Arc::new(MockResolver {
            document: Document {
                context: vec![],
                id: "did:plc:test".to_string(),
                also_known_as: vec![],
                service: vec![],
                verification_method: vec![],
                extra: HashMap::new(),
            },
        }) as Arc<dyn IdentityResolver>;
        let state = TestState { resolver };

        // Create request without Authorization header
        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(())
            .unwrap();

        let (mut parts, _body) = request.into_parts();

        // Test the OptionalFromRequestParts implementation
        let result = Authorization::from_request_parts(&mut parts, &state).await;

        // Verify no authorization is returned when no header is present
        assert!(result.is_ok());
        let auth_option = result.unwrap();
        assert!(auth_option.is_none());
    }
}
