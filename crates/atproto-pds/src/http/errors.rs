//! Error → HTTP-response conversion.
//!
//! Per AT Protocol XRPC convention: HTTP 400/401/403/404/500 with JSON body
//! `{"error": "ErrorName", "message": "Human description"}`.

use crate::errors::PdsError;
use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// XRPC error response wrapper.
#[derive(Debug)]
pub struct XrpcError {
    /// HTTP status to return.
    pub status: StatusCode,
    /// Spec-defined error name (e.g., "RecordNotFound").
    pub name: String,
    /// Human-readable message.
    pub message: String,
}

impl XrpcError {
    /// Construct a new XRPC error.
    pub fn new(status: StatusCode, name: &str, message: impl Into<String>) -> Self {
        Self {
            status,
            name: name.to_string(),
            message: message.into(),
        }
    }
}

impl IntoResponse for XrpcError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "error": self.name,
                "message": self.message,
            })),
        )
            .into_response()
    }
}

impl From<PdsError> for XrpcError {
    fn from(err: PdsError) -> Self {
        match err {
            PdsError::NotFound { what } => {
                XrpcError::new(StatusCode::BAD_REQUEST, "NotFound", what)
            }
            PdsError::AuthDenied { reason } => {
                XrpcError::new(StatusCode::FORBIDDEN, "Forbidden", reason)
            }
            PdsError::InvalidAccountTransition { from, to } => XrpcError::new(
                StatusCode::BAD_REQUEST,
                "InvalidAccountState",
                format!("invalid transition: {from} -> {to}"),
            ),
            PdsError::Storage { reason } => {
                tracing::error!(error = %reason, "internal storage error");
                XrpcError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "internal error",
                )
            }
            PdsError::Config { issues } => {
                tracing::error!(?issues, "config error");
                XrpcError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "configuration error",
                )
            }
            PdsError::StorageProfileMismatch {
                configured,
                compiled,
            } => XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("storage profile mismatch: {configured} vs {compiled}"),
            ),
            PdsError::PlcRotationKey { reason } => XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("PLC rotation key: {reason}"),
            ),
            PdsError::NotifierDelivery { reason } => XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("notifier: {reason}"),
            ),
            PdsError::Space(e) => {
                tracing::warn!(error = %e, "space error");
                XrpcError::new(StatusCode::BAD_REQUEST, "SpaceError", e.to_string())
            }
            PdsError::Repo(e) => {
                tracing::warn!(error = %e, "repo error");
                XrpcError::new(StatusCode::BAD_REQUEST, "RepoError", e.to_string())
            }
            PdsError::Dasl(e) => {
                tracing::warn!(error = %e, "dasl error");
                XrpcError::new(StatusCode::BAD_REQUEST, "InvalidData", e.to_string())
            }
            PdsError::Io(e) => {
                tracing::error!(error = %e, "io error");
                XrpcError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "I/O error",
                )
            }
        }
    }
}

impl IntoResponse for PdsError {
    fn into_response(self) -> Response {
        XrpcError::from(self).into_response()
    }
}
