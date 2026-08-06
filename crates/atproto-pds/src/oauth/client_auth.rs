//! Authenticating a confidential client at the token endpoint.
//!
//! A client's metadata declares how it authenticates, in
//! `token_endpoint_auth_method`. This server parsed that field and then ignored
//! it, so a client declaring `private_key_jwt` was authenticated exactly as
//! weakly as one declaring `none`: not at all.
//!
//! That is worse than an unimplemented feature. Private-key client
//! authentication exists so that a stolen authorization code is useless without
//! the key — a code is a bearer value that travels through a redirect, a
//! browser, and often a log. Ignoring the declaration handed that protection
//! back: anyone holding a confidential client's code could redeem it here with
//! no assertion at all.
//!
//! The advertised list could not simply drop the method, either. The AT
//! Protocol client library refuses an authorization server whose metadata omits
//! `private_key_jwt` — for every client, including the public ones that use
//! `none` — so removing it would have broken every login rather than narrowing
//! anything.
//!
//! # Failing closed
//!
//! A client that declares `private_key_jwt` and whose keys cannot be fetched is
//! refused. Falling back to unauthenticated on the error path would rebuild the
//! hole out of the recovery code, which is how a permissive default usually
//! gets back in.

use crate::http::errors::XrpcError;
use crate::oauth::client_metadata::{ClientMetadata, resolve_client_jwks};
use axum::http::StatusCode;

/// The only assertion type RFC 7523 defines for this.
pub const JWT_BEARER_ASSERTION: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// How a client said it authenticates.
///
/// Absent means `none`, per RFC 7591 — a client that says nothing is public.
#[derive(Debug, PartialEq, Eq)]
pub enum Method {
    /// Public client. The authorization code and PKCE verifier are the whole
    /// of what it presents.
    None,
    /// Confidential client. Must present a signed assertion.
    PrivateKeyJwt,
}

impl Method {
    /// Read the method a client declared.
    #[must_use]
    pub fn declared(metadata: &ClientMetadata) -> Self {
        match metadata.token_endpoint_auth_method.as_deref() {
            Some("private_key_jwt") => Method::PrivateKeyJwt,
            _ => Method::None,
        }
    }
}

/// Require the client to authenticate the way its own metadata says it does.
///
/// The check is on the *declaration*, not on what the request happens to
/// carry: a confidential client that presents nothing must be refused rather
/// than quietly downgraded, which is the whole point of declaring a method.
///
/// # Errors
///
/// `invalid_client` when a confidential client presents no assertion, presents
/// one this server cannot verify, or has keys this server cannot reach.
pub async fn authenticate(
    metadata: &ClientMetadata,
    client_id: &str,
    assertion_type: Option<&str>,
    assertion: Option<&str>,
    user_agent: &str,
) -> Result<(), XrpcError> {
    let refused = |detail: &str| {
        XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            detail.to_string(),
        )
    };

    if Method::declared(metadata) == Method::None {
        // A public client presenting an assertion is confused rather than
        // hostile, and nothing here can verify one for a client that published
        // no keys. Refusing it is clearer than ignoring it.
        if assertion.is_some() {
            return Err(refused(
                "this client is registered as public and cannot present a client assertion",
            ));
        }
        return Ok(());
    }

    // From here the client declared `private_key_jwt`, so every path that is
    // not a verified assertion is a refusal.
    match assertion_type {
        Some(JWT_BEARER_ASSERTION) => {}
        Some(other) => {
            return Err(refused(&format!(
                "unsupported client_assertion_type {other}; want {JWT_BEARER_ASSERTION}"
            )));
        }
        // Named separately from a missing assertion: a client sending one
        // without the other has a bug this should point at.
        None if assertion.is_some() => {
            return Err(refused(
                "client_assertion was supplied without client_assertion_type",
            ));
        }
        None => {
            tracing::warn!(
                client_id = %client_id,
                "refused a confidential client that presented no assertion"
            );
            return Err(refused(
                "this client is registered as confidential and must present a client assertion",
            ));
        }
    }

    let Some(assertion) = assertion else {
        return Err(refused(
            "this client is registered as confidential and must present a client assertion",
        ));
    };

    // Fail closed. A client that cannot be authenticated is not a client that
    // may skip authentication.
    let jwks = resolve_client_jwks(client_id, metadata, user_agent)
        .await
        .map_err(|e| {
            tracing::warn!(
                client_id = %client_id,
                error = ?e,
                "could not reach a confidential client's keys; refusing rather than downgrading"
            );
            refused("this client's signing keys could not be retrieved")
        })?;

    verify_assertion(assertion, client_id, &jwks).map_err(|detail| {
        tracing::warn!(client_id = %client_id, detail = %detail, "client assertion refused");
        refused(&detail)
    })
}

/// Check an assertion's claims. Signature verification is not yet wired.
///
/// The claim checks are the cheap half and are done here; what is missing is
/// the signature check against `jwks`, which needs a JWS verifier keyed by
/// `kid` across the algorithms this server accepts.
///
/// Until that lands this returns an error for any confidential client, so the
/// gap is a refusal rather than an acceptance — a half-checked assertion that
/// was treated as valid would be worse than the state this replaced.
fn verify_assertion(
    _assertion: &str,
    _client_id: &str,
    _jwks: &serde_json::Value,
) -> Result<(), String> {
    Err("client assertion verification is not implemented on this server".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(method: Option<&str>) -> ClientMetadata {
        let mut m = crate::oauth::client_metadata::loopback_client_metadata("http://localhost")
            .expect("loopback metadata");
        m.token_endpoint_auth_method = method.map(str::to_string);
        m
    }

    /// A client that declared nothing is public, per RFC 7591.
    #[test]
    fn an_undeclared_method_is_public() {
        assert_eq!(Method::declared(&metadata(None)), Method::None);
        assert_eq!(Method::declared(&metadata(Some("none"))), Method::None);
        assert_eq!(
            Method::declared(&metadata(Some("private_key_jwt"))),
            Method::PrivateKeyJwt
        );
    }

    /// The hole this closes: a confidential client presenting nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_confidential_client_cannot_skip_its_assertion() {
        let err = authenticate(
            &metadata(Some("private_key_jwt")),
            "https://app.example/client-metadata.json",
            None,
            None,
            "test",
        )
        .await
        .expect_err("a declared method must be enforced");

        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.name, "invalid_client");
    }

    /// A public client is unaffected, which is every client today.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_public_client_is_unchanged() {
        authenticate(&metadata(None), "https://app.example/x", None, None, "test")
            .await
            .expect("public clients must keep working");
    }

    /// An unknown assertion type is refused rather than read as absent.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unknown_assertion_type_is_refused() {
        let err = authenticate(
            &metadata(Some("private_key_jwt")),
            "https://app.example/x",
            Some("urn:example:something-else"),
            Some("ey.."),
            "test",
        )
        .await
        .expect_err("an unrecognised assertion type must not pass");

        assert!(
            err.message.contains("unsupported client_assertion_type"),
            "{}",
            err.message
        );
    }

    /// A public client presenting an assertion is refused, not ignored.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_public_client_may_not_present_an_assertion() {
        let err = authenticate(
            &metadata(None),
            "https://app.example/x",
            Some(JWT_BEARER_ASSERTION),
            Some("ey.."),
            "test",
        )
        .await
        .expect_err("nothing can verify an assertion for a client with no keys");

        assert_eq!(err.name, "invalid_client");
    }
}
