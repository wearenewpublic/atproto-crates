//! Error types for the Walking Club AppView.
//!
//! `ConfigError` covers environment/configuration loading; `WebError` is the
//! HTTP-facing error that implements `IntoResponse`; `AppError` is the broad
//! domain error used by background workers and the space pipeline.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

/// Configuration / environment loading errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// A required environment variable was missing.
    #[error("error-walking-club-config-1 Missing required environment variable: {0}")]
    MissingEnv(String),

    /// An environment variable held an invalid value.
    #[error("error-walking-club-config-2 Invalid value for {0}: {1}")]
    InvalidValue(String, String),

    /// A signing key could not be parsed.
    #[error("error-walking-club-config-3 Invalid key material: {0}")]
    InvalidKey(String),

    /// The cookie secret could not be decoded to 32 bytes.
    #[error("error-walking-club-config-4 Invalid cookie secret: {0}")]
    InvalidCookieSecret(String),
}

/// HTTP-facing error returned by request handlers.
#[derive(Debug, Error)]
pub enum WebError {
    /// An internal server error wrapping any anyhow error.
    #[error("error-walking-club-web-1 Internal server error")]
    Internal(#[from] anyhow::Error),

    /// The requested resource was not found.
    #[error("error-walking-club-web-2 Not found")]
    NotFound,

    /// The request was malformed.
    #[error("error-walking-club-web-3 Bad request: {0}")]
    BadRequest(String),

    /// The request was unauthenticated or the session was invalid.
    #[error("error-walking-club-web-4 Unauthorized")]
    Unauthorized,

    /// A database error occurred.
    #[error("error-walking-club-web-5 Database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        let status = match &self {
            WebError::NotFound => StatusCode::NOT_FOUND,
            WebError::BadRequest(_) => StatusCode::BAD_REQUEST,
            WebError::Unauthorized => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        tracing::error!(error = ?self, "HTTP error");

        (status, self.to_string()).into_response()
    }
}

impl From<serde_json::Error> for WebError {
    fn from(err: serde_json::Error) -> Self {
        WebError::Internal(anyhow::Error::from(err))
    }
}

/// Broad domain error used by background workers and the space pipeline.
#[derive(Debug, Error)]
pub enum AppError {
    /// A configuration error.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// A database error.
    #[error("error-walking-club-app-1 Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// A space-protocol error (commit/credential/verification).
    #[error("error-walking-club-app-2 Space error: {0}")]
    Space(String),

    /// A firehose decode or transport error.
    #[error("error-walking-club-app-3 Firehose error: {0}")]
    Firehose(String),

    /// Any other error.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Convenience result alias for AppView domain operations.
pub type AppResult<T> = Result<T, AppError>;
