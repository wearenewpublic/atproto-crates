//! Request-body extractor that rejects in the XRPC error shape.
//!
//! axum's [`Json`] rejects a malformed body with HTTP 422 and a `text/plain`
//! message. XRPC has exactly one error shape — HTTP 400 with
//! `{"error": …, "message": …}` — and a client that only knows how to read
//! that gets nothing it can act on from a 422.
//!
//! This matters most where the body carries an **open union**. A moderation
//! service sending a subject type this build has not been taught should learn
//! `InvalidRequest` and why, not a status code that is not part of the
//! protocol.
//!
//! Only the handlers that take a union use this today; the rest of the surface
//! still returns axum's default. Converting the whole surface is a mechanical
//! change worth doing on its own rather than inside a behavioural fix.

use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;

use crate::http::errors::XrpcError;

/// `Json<T>`, but a deserialization failure becomes a 400 `InvalidRequest`
/// carrying serde's message.
#[derive(Debug, Clone, Copy, Default)]
pub struct XrpcJson<T>(pub T);

impl<S, T> FromRequest<S> for XrpcJson<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned + 'static,
{
    type Rejection = XrpcError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let axum::Json(value) = axum::Json::<T>::from_request(req, state)
            .await
            .map_err(|err| {
                XrpcError::new(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    format!("malformed request body: {err}"),
                )
            })?;
        Ok(Self(value))
    }
}
