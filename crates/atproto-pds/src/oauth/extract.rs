//! Request-body extractor accepting both form and JSON encodings.
//!
//! RFC 9126 §2 (PAR) and RFC 6749 §4.1.3 (token) both specify
//! `application/x-www-form-urlencoded` request bodies, and that is what every
//! standard AT Protocol OAuth client sends. Accepting only JSON makes the
//! authorization server unreachable: the client receives HTTP 415 before any
//! handler logic runs.
//!
//! [`JsonOrForm`] dispatches on `Content-Type` so form-encoded requests — the
//! canonical shape — work, while JSON continues to be accepted for callers
//! that already send it. A body with neither content type is rejected as form,
//! since that is what the specification requires.

use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::{Form, Json};
use serde::de::DeserializeOwned;

use crate::http::errors::XrpcError;

/// Extracts `T` from either an `application/x-www-form-urlencoded` body (the
/// specified encoding) or an `application/json` body.
///
/// Rejections surface as [`XrpcError`] with the OAuth-canonical
/// `invalid_request` error code rather than axum's default plain-text 415/422,
/// so a malformed request reads the same as any other OAuth error.
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonOrForm<T>(pub T);

impl<S, T> FromRequest<S> for JsonOrForm<T>
where
    S: Send + Sync,
    T: DeserializeOwned + 'static,
{
    type Rejection = XrpcError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let is_json = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("application/json")
            });

        if is_json {
            let Json(value) = Json::<T>::from_request(req, state).await.map_err(|err| {
                XrpcError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    format!("malformed JSON request body: {}", decoder_detail(&err)),
                )
            })?;
            return Ok(Self(value));
        }

        let Form(value) = Form::<T>::from_request(req, state).await.map_err(|err| {
            XrpcError::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!(
                    "malformed form-encoded request body: {}",
                    decoder_detail(&err)
                ),
            )
        })?;
        Ok(Self(value))
    }
}

/// The part of an axum rejection that is safe to relay.
///
/// axum's own wrapper text names the Rust type the body was being decoded into
/// — *"Failed to deserialize the JSON body into the target type: …"* — which is
/// this server's private detail: it is in no specification, a client cannot
/// look it up, and renaming the struct would change the message without
/// changing the wire contract. The decoder's explanation one level below is the
/// actionable half, so prefer it, and fall back to the rejection's own text for
/// the variants that carry no source (a wrong `Content-Type`, which names no
/// type and explains itself).
fn decoder_detail(err: &(dyn std::error::Error + 'static)) -> String {
    crate::http::extract::source_detail(err).unwrap_or_else(|| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Sample {
        client_id: String,
        #[serde(default)]
        scope: Option<String>,
    }

    async fn extract(content_type: Option<&str>, body: &'static str) -> Result<Sample, XrpcError> {
        let mut builder = HttpRequest::builder().method("POST").uri("/");
        if let Some(ct) = content_type {
            builder = builder.header(CONTENT_TYPE, ct);
        }
        let req = builder.body(Body::from(body)).unwrap();
        JsonOrForm::<Sample>::from_request(req, &())
            .await
            .map(|v| v.0)
    }

    #[tokio::test]
    async fn accepts_form_encoding() {
        let parsed = extract(
            Some("application/x-www-form-urlencoded"),
            "client_id=https%3A%2F%2Fapp.example%2Fc.json&scope=atproto",
        )
        .await
        .expect("form body should extract");
        assert_eq!(parsed.client_id, "https://app.example/c.json");
        assert_eq!(parsed.scope.as_deref(), Some("atproto"));
    }

    /// The charset parameter standard clients append must not defeat the match.
    #[tokio::test]
    async fn accepts_json_with_charset_parameter() {
        let parsed = extract(
            Some("application/json; charset=utf-8"),
            r#"{"client_id":"https://app.example/c.json"}"#,
        )
        .await
        .expect("JSON body should extract");
        assert_eq!(parsed.client_id, "https://app.example/c.json");
        assert_eq!(parsed.scope, None);
    }

    #[tokio::test]
    async fn accepts_plain_json() {
        let parsed = extract(
            Some("application/json"),
            r#"{"client_id":"https://app.example/c.json","scope":"atproto"}"#,
        )
        .await
        .expect("JSON body should extract");
        assert_eq!(parsed.scope.as_deref(), Some("atproto"));
    }

    #[tokio::test]
    async fn rejects_malformed_body_as_invalid_request() {
        let err = extract(Some("application/json"), "{not json")
            .await
            .expect_err("malformed JSON should be rejected");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.name, "invalid_request");
    }

    /// The OAuth endpoints are not XRPC, but the type name is no more a client's
    /// business here than it is there.
    #[tokio::test]
    async fn rejection_never_names_a_rust_type() {
        let err = extract(Some("application/json"), "[]")
            .await
            .expect_err("an array body should be rejected");
        assert!(!err.message.contains("Sample"), "{}", err.message);
        assert!(!err.message.contains("target type"), "{}", err.message);
    }

    /// The rejections that carry no source still have to say something: a form
    /// body sent with no content type is the common client mistake here and
    /// the explanation is the whole value of the reply.
    #[tokio::test]
    async fn wrong_content_type_keeps_its_explanation() {
        let err = extract(Some("text/plain"), "client_id=x")
            .await
            .expect_err("a non-form, non-JSON body should be rejected");
        assert_eq!(err.name, "invalid_request");
        assert!(
            err.message.contains("x-www-form-urlencoded"),
            "{}",
            err.message
        );
    }
}
