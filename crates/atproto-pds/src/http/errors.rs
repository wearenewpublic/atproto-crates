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
            // `com.atproto.repo.getRecord` declares this name and no other, and
            // the reference implementation raises it as an `InvalidRequestError`
            // — hence 400 rather than 404, matching every other named XRPC
            // error on the repo surface.
            PdsError::RecordNotFound { uri } => XrpcError::new(
                StatusCode::BAD_REQUEST,
                "RecordNotFound",
                format!("could not locate record: {uri}"),
            ),
            // The identity lexicons name these, and a client acts on which one
            // it got: correct the handle, pick another, or go fix DNS.
            PdsError::InvalidRecord { reason } => {
                XrpcError::new(StatusCode::BAD_REQUEST, "InvalidRecord", reason)
            }
            // Named rather than folded into `InvalidRequest`: the caller asked
            // for something this server cannot do, which is a different remedy
            // from a malformed request.
            PdsError::ValidationUnavailable => XrpcError::new(
                StatusCode::BAD_REQUEST,
                "ValidationUnavailable",
                "Lexicon schema validation is not implemented on this server; omit `validate` or set it to false",
            ),
            PdsError::InvalidHandle { handle, reason } => XrpcError::new(
                StatusCode::BAD_REQUEST,
                "InvalidHandle",
                format!("{handle}: {reason}"),
            ),
            PdsError::HandleNotAvailable { handle } => XrpcError::new(
                StatusCode::BAD_REQUEST,
                "HandleNotAvailable",
                format!("the handle {handle} is not available"),
            ),
            // `createAccount` declares no error for either of these, so they
            // report as `InvalidRequest` rather than as a name a client cannot
            // find in the lexicon. Both are still 400: the request conflicts
            // with state this server already holds, which is the caller's to
            // resolve, not a fault on our side.
            PdsError::AccountAlreadyExists { did } => XrpcError::new(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                format!("an account for {did} already exists on this server"),
            ),
            PdsError::EmailNotAvailable { email } => XrpcError::new(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                format!("the email address {email} is already registered"),
            ),
            PdsError::HandleOwnershipUnproven {
                handle,
                did,
                resolved,
            } => XrpcError::new(
                StatusCode::BAD_REQUEST,
                "UnsupportedDomain",
                format!(
                    "{handle} must resolve to {did} before it can be claimed; it resolved to {resolved}"
                ),
            ),
            PdsError::InvalidPlcOperation { reason } => {
                XrpcError::new(StatusCode::BAD_REQUEST, "InvalidRequest", reason)
            }
            PdsError::InvalidSubject { reason } => {
                XrpcError::new(StatusCode::BAD_REQUEST, "InvalidRequest", reason)
            }
            PdsError::SpaceNotFound { uri } => XrpcError::new(
                StatusCode::BAD_REQUEST,
                "SpaceNotFound",
                format!("no such space {uri}"),
            ),
            PdsError::NotSpaceOwner { uri } => XrpcError::new(
                StatusCode::FORBIDDEN,
                "NotSpaceOwner",
                format!("not the owner of {uri}"),
            ),
            // The lexicons name one error per state and a caller acts on
            // which it got: a deactivated repo may come back, a taken-down one
            // is a moderation decision. `Deleted` reports as not-found rather
            // than confirming the DID was ever hosted here.
            PdsError::RepoUnavailable { did, state } => {
                let name = match state.as_str() {
                    "takendown" => "RepoTakendown",
                    "suspended" => "RepoSuspended",
                    "deactivated" => "RepoDeactivated",
                    _ => "RepoNotFound",
                };
                XrpcError::new(StatusCode::BAD_REQUEST, name, format!("{did} is {state}"))
            }
            // The lexicons declare `InvalidSwap` by name on all four write
            // methods, and a client is expected to act on it — re-read, rebase
            // its decision, retry. A generic 400 tells it nothing.
            PdsError::InvalidSwap { expected, actual } => XrpcError::new(
                StatusCode::BAD_REQUEST,
                "InvalidSwap",
                format!("swapCommit {expected} does not match the current commit {actual}"),
            ),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The names a signup conflict can produce are contractual: a client
    /// switches on `error`, and `com.atproto.server.createAccount` declares
    /// `HandleNotAvailable` but nothing for a DID or an email collision. All
    /// three are 400 — a conflict with state the server already holds is the
    /// caller's to resolve.
    #[test]
    fn account_conflicts_report_as_declared_client_errors() {
        let handle = XrpcError::from(PdsError::HandleNotAvailable {
            handle: "alice.example".to_string(),
        });
        assert_eq!(handle.status, StatusCode::BAD_REQUEST);
        assert_eq!(handle.name, "HandleNotAvailable");
        assert!(handle.message.contains("alice.example"));

        let did = XrpcError::from(PdsError::AccountAlreadyExists {
            did: "did:plc:alice".to_string(),
        });
        assert_eq!(did.status, StatusCode::BAD_REQUEST);
        assert_eq!(did.name, "InvalidRequest");
        assert!(did.message.contains("did:plc:alice"));

        let email = XrpcError::from(PdsError::EmailNotAvailable {
            email: "alice@example.com".to_string(),
        });
        assert_eq!(email.status, StatusCode::BAD_REQUEST);
        assert_eq!(email.name, "InvalidRequest");
        assert!(email.message.contains("alice@example.com"));
    }

    /// The email collision reached clients as `500 InternalError` carrying
    /// SQLite's own constraint text. Neither may come back.
    #[test]
    fn email_conflict_is_not_a_server_fault() {
        let err = XrpcError::from(PdsError::EmailNotAvailable {
            email: "alice@example.com".to_string(),
        });
        assert_ne!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_ne!(err.name, "InternalError");
        assert!(!err.message.to_lowercase().contains("constraint"));
        assert!(!err.message.to_lowercase().contains("sqlite"));
    }
}
