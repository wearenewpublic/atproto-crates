//! Request extractors that reject in the XRPC error shape.
//!
//! axum rejects a request it cannot decode with a bare `text/plain` body: HTTP
//! 422 when a syntactically valid JSON body does not fit the target type, HTTP
//! 400 for a query string that does not, HTTP 415 for a missing content type.
//! None of those are XRPC. The protocol defines exactly one failure shape —
//! HTTP 400 with `{"error": …, "message": …}` — and a client that only knows
//! how to read that gets nothing it can act on from a plain-text 422. axum's
//! text also names the Rust type the body was being deserialized into, which is
//! this server's private detail rather than anything a caller can look up.
//!
//! [`XrpcJson`] and [`XrpcQuery`] wrap the axum extractors and translate the
//! rejection into [`XrpcError`]. Both are drop-in replacements for the axum
//! types — `XrpcJson` is a response as well as an extractor, so a handler can
//! keep one name in both positions — and the handler modules import them under
//! the axum names. That is deliberate: it means writing `Json` or `Query` in a
//! new handler signature picks up the XRPC rejection by default, so the fix
//! does not have to be remembered.
//!
//! Translating the shape is not the same as flattening the status. An
//! over-sized body is a 413 and stays one — see [`json_rejection`] — because
//! "send less" is a different remedy from "fix your JSON" and a caller that
//! only ever sees 400 cannot tell them apart.
//!
//! The success path is untouched. These types decode exactly what axum decodes;
//! only the failure branch differs.

use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts, OptionalFromRequest, Request};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::http::errors::XrpcError;

/// `Json<T>`, but a body that cannot be decoded becomes a 400 `InvalidRequest`
/// in the XRPC envelope.
///
/// Also serializes as a JSON response body, identically to [`axum::Json`], so
/// handlers can use the one type for both the input and the output position.
#[derive(Debug, Clone, Copy, Default)]
pub struct XrpcJson<T>(pub T);

impl<S, T> FromRequest<S> for XrpcJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = XrpcError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let axum::Json(value) = <axum::Json<T> as FromRequest<S>>::from_request(req, state)
            .await
            .map_err(|rejection| json_rejection(&rejection))?;
        Ok(Self(value))
    }
}

/// Mirrors axum's own optional-body behaviour: a request with no `Content-Type`
/// at all yields `None` rather than an error, which is what
/// `com.atproto.sync.requestCrawl` relies on to accept an empty body.
impl<S, T> OptionalFromRequest<S> for XrpcJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = XrpcError;

    async fn from_request(req: Request, state: &S) -> Result<Option<Self>, Self::Rejection> {
        let extracted = <axum::Json<T> as OptionalFromRequest<S>>::from_request(req, state)
            .await
            .map_err(|rejection| json_rejection(&rejection))?;
        Ok(extracted.map(|axum::Json(value)| Self(value)))
    }
}

impl<T> IntoResponse for XrpcJson<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

impl<T> std::ops::Deref for XrpcJson<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for XrpcJson<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// `Query<T>`, but a query string that cannot be decoded becomes a 400
/// `InvalidRequest` in the XRPC envelope.
#[derive(Debug, Clone, Copy, Default)]
pub struct XrpcQuery<T>(pub T);

impl<S, T> FromRequestParts<S> for XrpcQuery<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = XrpcError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let axum::extract::Query(value) =
            axum::extract::Query::<T>::from_request_parts(parts, state)
                .await
                .map_err(|rejection| query_rejection(&rejection))?;
        Ok(Self(value))
    }
}

/// Translate an axum body rejection into the XRPC envelope.
///
/// A body that could not be decoded is 400 `InvalidRequest`; 415 and 422 are
/// not statuses XRPC defines, and the variant chooses only the wording, which
/// is what tells the caller whether to fix its serializer, its payload or its
/// headers.
///
/// A body that was never read because it was too long is different, and keeps
/// its 413. axum wraps every request body in `http_body_util::Limited` — 2 MiB
/// by default, and nothing in this crate installs a `DefaultBodyLimit` to say
/// otherwise — so `BytesRejection` carrying a `LengthLimitError` is reachable
/// on every endpoint here, not a theoretical branch. Folding it into 400 would
/// leave a caller unable to distinguish "too big", whose remedy is to split
/// the batch, from "malformed", whose remedy is to fix the encoder. XRPC has
/// room for this: [`crate::http::write_handlers`] already answers 413 with the
/// named errors `BlobTooLarge` and `RepoTooLarge` inside this same envelope,
/// and `RequestTooLarge` is the sibling of those two for a JSON body.
fn json_rejection(rejection: &JsonRejection) -> XrpcError {
    let detail = source_detail(rejection);
    match rejection {
        JsonRejection::JsonSyntaxError(_) => {
            invalid_request(with_detail("request body is not valid JSON", detail))
        }
        JsonRejection::JsonDataError(_) => invalid_request(with_detail(
            "request body does not match the expected shape",
            detail,
        )),
        JsonRejection::MissingJsonContentType(_) => {
            invalid_request("request body must be sent with Content-Type: application/json")
        }
        // Asking the rejection for its own status rather than matching the
        // nested `FailedToBufferBody::LengthLimitError` keeps this correct if
        // axum adds another over-long-body variant: both types are
        // `#[non_exhaustive]`, so a nested match would need a wildcard that
        // silently swallowed the new one.
        JsonRejection::BytesRejection(bytes) if bytes.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            XrpcError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "RequestTooLarge",
                "request body exceeds this server's limit for JSON request bodies",
            )
        }
        // Any other buffering failure — and anything a future axum adds — means
        // the body never arrived intact, so there is no detail worth relaying.
        _ => invalid_request("request body could not be read"),
    }
}

/// Translate an axum query-string rejection into the XRPC envelope.
fn query_rejection(rejection: &QueryRejection) -> XrpcError {
    invalid_request(with_detail(
        "invalid query parameters",
        source_detail(rejection),
    ))
}

/// The XRPC refusal for a request this server could not decode.
fn invalid_request(message: impl Into<String>) -> XrpcError {
    XrpcError::new(StatusCode::BAD_REQUEST, "InvalidRequest", message)
}

/// Append the decoder's own explanation when there is one.
fn with_detail(summary: &str, detail: Option<String>) -> String {
    match detail {
        Some(detail) => format!("{summary}: {detail}"),
        None => summary.to_string(),
    }
}

/// The decoder's message, one level below axum's own wrapper text.
///
/// Taking the immediate source rather than walking to the root keeps the field
/// path serde records for a nested failure (`writes.0.collection: …`), which is
/// the part a caller needs to locate the offending value.
pub(crate) fn source_detail(error: &(dyn std::error::Error + 'static)) -> Option<String> {
    std::error::Error::source(error).map(|source| strip_type_names(&source.to_string()))
}

/// Replacements for the serde phrasings that name a Rust type.
///
/// serde spells the expected shape out of the derive's `expecting` string, so
/// the phrasing depends on how the target is declared: a plain struct, a unit,
/// tuple or newtype struct, or an enum in any of its four representations
/// (external, internal, adjacent, untagged). Each entry pairs the phrase that
/// precedes the type name with what to say instead; the name itself is the
/// token that follows and is dropped by [`strip_type_names`].
///
/// The tagged-enum phrasings are not hypothetical. `ApplyWritesEntry`
/// (`write_handlers.rs`) and `SubjectRef` (`admin/subject.rs`) are both
/// `#[serde(tag = "$type")]` and both sit behind body fields, so
/// `com.atproto.repo.applyWrites` with a non-object in `writes` produces
/// `expected internally tagged enum ApplyWritesEntry` — which reached the wire
/// until this entry existed.
const TYPE_NAMED_PHRASES: [(&str, &str); 8] = [
    (
        "data did not match any variant of untagged enum ",
        "request body matches none of the accepted shapes",
    ),
    ("expected struct ", "expected an object"),
    ("expected unit struct ", "expected an object"),
    ("expected tuple struct ", "expected an array"),
    ("expected newtype struct ", "expected a single value"),
    ("expected internally tagged enum ", "expected an object"),
    ("expected adjacently tagged enum ", "expected an object"),
    ("expected enum ", "expected an object"),
];

/// Drop Rust type names from a decoder message.
///
/// When the top level of the body has the wrong shape serde says
/// `invalid type: sequence, expected struct CreateAccountInput`. That name is
/// internal: it appears in no lexicon, a caller cannot look it up, and a
/// refactor changes it without the wire contract changing at all. The rest of
/// the message — which field, which position, what was found — is what makes
/// the error actionable and is kept verbatim.
///
/// The substitution is textual and runs over the whole message, including any
/// caller-supplied value serde echoed back, so a value that itself contains one
/// of [`TYPE_NAMED_PHRASES`] loses the token after it. That is cosmetic damage
/// to an echo, not a leak, and the alternative — parsing serde's message
/// structure — would be guessing at an unspecified format.
fn strip_type_names(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;

    loop {
        let earliest = TYPE_NAMED_PHRASES
            .iter()
            .filter_map(|(phrase, replacement)| {
                rest.find(phrase).map(|at| (at, *phrase, *replacement))
            })
            .min_by_key(|(at, _, _)| *at);

        let Some((at, phrase, replacement)) = earliest else {
            break;
        };

        out.push_str(&rest[..at]);
        out.push_str(replacement);

        // Everything up to the next space is the type name; drop it and keep
        // whatever trailing context serde appended (`at line 1 column 1`).
        let after = &rest[at + phrase.len()..];
        rest = match after.find(char::is_whitespace) {
            Some(end) => &after[end..],
            None => "",
        };
    }

    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use axum::http::header::CONTENT_TYPE;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Sample {
        handle: String,
        #[serde(default)]
        email: Option<String>,
    }

    async fn extract_body(
        content_type: Option<&str>,
        body: impl Into<Body>,
    ) -> Result<Sample, XrpcError> {
        let mut builder = HttpRequest::builder().method("POST").uri("/");
        if let Some(value) = content_type {
            builder = builder.header(CONTENT_TYPE, value);
        }
        let req = builder.body(body.into()).unwrap();
        <XrpcJson<Sample> as FromRequest<()>>::from_request(req, &())
            .await
            .map(|value| value.0)
    }

    async fn extract_query(query: &str) -> Result<Sample, XrpcError> {
        let req = HttpRequest::builder()
            .uri(format!("/?{query}"))
            .body(Body::empty())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        XrpcQuery::<Sample>::from_request_parts(&mut parts, &())
            .await
            .map(|value| value.0)
    }

    #[tokio::test]
    async fn decodes_a_well_formed_body() {
        let parsed = extract_body(Some("application/json"), r#"{"handle":"a.example"}"#)
            .await
            .expect("valid body should decode");
        assert_eq!(parsed.handle, "a.example");
        assert_eq!(parsed.email, None);
    }

    #[tokio::test]
    async fn syntactically_invalid_body_is_invalid_request() {
        let err = extract_body(Some("application/json"), "{not json")
            .await
            .expect_err("malformed JSON should be rejected");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.name, "InvalidRequest");
        assert!(err.message.contains("not valid JSON"), "{}", err.message);
    }

    #[tokio::test]
    async fn missing_required_field_is_invalid_request() {
        let err = extract_body(Some("application/json"), "{}")
            .await
            .expect_err("a missing required field should be rejected");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.name, "InvalidRequest");
        assert!(
            err.message.contains("missing field `handle`"),
            "{}",
            err.message
        );
    }

    /// Asserted on the exact string, not on a substring: the rejection this
    /// replaced was also 400 `InvalidRequest` and also mentioned
    /// `application/json` (*"malformed request body: Expected request with
    /// `Content-Type: application/json`"*), so anything looser passes against
    /// the code this test exists to discriminate from.
    #[tokio::test]
    async fn missing_content_type_is_invalid_request() {
        let err = extract_body(None, r#"{"handle":"a.example"}"#)
            .await
            .expect_err("a body without a content type should be rejected");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.name, "InvalidRequest");
        assert_eq!(
            err.message,
            "request body must be sent with Content-Type: application/json"
        );
    }

    /// An over-long body is the one rejection here that is not a 400. axum
    /// caps every body at 2 MiB unless a `DefaultBodyLimit` says otherwise and
    /// this crate installs none, so this is the live default — and "send less"
    /// is a remedy a caller can only act on if the status still says so.
    #[tokio::test]
    async fn oversized_body_stays_payload_too_large() {
        let mut body = String::from(r#"{"handle":""#);
        body.push_str(&"a".repeat(3 * 1024 * 1024));
        body.push_str(r#""}"#);

        let err = extract_body(Some("application/json"), body)
            .await
            .expect_err("a body past the limit should be rejected");
        assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(err.name, "RequestTooLarge");
        assert!(err.message.contains("exceeds"), "{}", err.message);
    }

    #[tokio::test]
    async fn bad_query_string_is_invalid_request() {
        let err = extract_query("email=a%40example.test")
            .await
            .expect_err("a missing required parameter should be rejected");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.name, "InvalidRequest");
        assert!(
            err.message.starts_with("invalid query parameters"),
            "{}",
            err.message
        );
    }

    /// The whole point of the wrapper: none of the serde phrasings that carry a
    /// Rust type name may reach the wire, and `strip_type_names` is the only
    /// thing standing between serde and the client.
    ///
    /// The guarantee is scoped to the phrasings enumerated in
    /// [`TYPE_NAMED_PHRASES`]. serde's message format is not a stable API, so
    /// a phrasing nobody has listed is not covered — which is why the
    /// speculative cases below are tested alongside the reachable ones.
    #[test]
    fn type_names_are_stripped() {
        assert_eq!(
            strip_type_names(
                "invalid type: sequence, expected struct CreateAccountInput at line 1 column 1"
            ),
            "invalid type: sequence, expected an object at line 1 column 1"
        );
        assert_eq!(
            strip_type_names("invalid type: string, expected enum WriteOp"),
            "invalid type: string, expected an object"
        );
        assert_eq!(
            strip_type_names("invalid type: string, expected unit struct Marker"),
            "invalid type: string, expected an object"
        );
        assert_eq!(
            strip_type_names("invalid type: map, expected tuple struct Pair"),
            "invalid type: map, expected an array"
        );
        // Reachable today: ApplyWritesEntry and SubjectRef are both
        // `#[serde(tag = "$type")]` and both sit behind body fields, so this is
        // the phrasing a client gets from applyWrites with a non-object entry.
        assert_eq!(
            strip_type_names(
                "invalid type: string \"x\", expected internally tagged enum ApplyWritesEntry at line 1 column 25"
            ),
            "invalid type: string \"x\", expected an object at line 1 column 25"
        );
        assert_eq!(
            strip_type_names("invalid type: string, expected adjacently tagged enum Tagged"),
            "invalid type: string, expected an object"
        );
        assert_eq!(
            strip_type_names("invalid type: map, expected newtype struct Wrapper"),
            "invalid type: map, expected a single value"
        );
        // The phrasing serde uses for `#[serde(untagged)]`, which no handler
        // input has today. The guard has to already cover it: the first one
        // added would otherwise put a type name on the wire with nothing
        // failing.
        assert_eq!(
            strip_type_names(
                "data did not match any variant of untagged enum WriteOp at line 1 column 9"
            ),
            "request body matches none of the accepted shapes at line 1 column 9"
        );
        assert_eq!(
            strip_type_names("missing field `handle` at line 1 column 2"),
            "missing field `handle` at line 1 column 2"
        );
    }

    #[tokio::test]
    async fn rejection_never_names_a_rust_type() {
        let err = extract_body(Some("application/json"), "[]")
            .await
            .expect_err("an array body should be rejected");
        assert!(!err.message.contains("Sample"), "{}", err.message);
        assert!(!err.message.contains("target type"), "{}", err.message);
    }
}
