//! # Structured Error Types for OAuth AIP Workflow
//!
//! Comprehensive error handling for AT Protocol OAuth AIP (Identity Provider) workflow operations
//! using structured error types with the `thiserror` library. All errors follow the project
//! convention of prefixed error codes with descriptive messages.
//!
//! ## Error Categories
//!
//! - **`OAuthWorkflowError`** (workflow-1 to workflow-10): OAuth workflow operations including PAR, token exchange, subject binding, and session management
//!
//! ## Error Format
//!
//! All errors use the standardized format: `error-atproto-oauth-aip-{domain}-{number} {message}: {details}`

use thiserror::Error;

/// Errors that can occur during OAuth workflow operations.
///
/// These errors represent failures in the complete OAuth authentication flow
/// for AT Protocol Identity Provider integration, including authorization
/// request initiation, token exchange, and session establishment.
#[derive(Debug, Error)]
pub enum OAuthWorkflowError {
    /// Failed to send PAR HTTP request.
    #[error("error-atproto-oauth-aip-workflow-1 PAR HTTP request failed: {0}")]
    ParRequestFailed(#[source] reqwest::Error),

    /// Failed to parse PAR response JSON.
    #[error("error-atproto-oauth-aip-workflow-2 PAR HTTP request parse failed: {0}")]
    ParResponseParseFailed(#[source] reqwest::Error),

    /// PAR response contained an error.
    #[error("error-atproto-oauth-aip-workflow-3 PAR HTTP response invalid: {message}")]
    ParResponseInvalid {
        /// Error message from the PAR response.
        message: String,
    },

    /// Failed to send token exchange HTTP request.
    #[error("error-atproto-oauth-aip-workflow-4 Token request failed: {0}")]
    TokenRequestFailed(#[source] reqwest::Error),

    /// Failed to parse token response JSON.
    #[error("error-atproto-oauth-aip-workflow-5 Token response json parsing failed: {0}")]
    TokenResponseParseFailed(#[source] reqwest::Error),

    /// Token response contained an error.
    #[error("error-atproto-oauth-aip-workflow-6 Token response invalid: {message}")]
    TokenResponseInvalid {
        /// Error message from the token response.
        message: String,
    },

    /// Failed to send session exchange HTTP request.
    #[error("error-atproto-oauth-aip-workflow-7 Session request failed: {0}")]
    SessionRequestFailed(#[source] reqwest::Error),

    /// Failed to parse session response JSON.
    #[error("error-atproto-oauth-aip-workflow-8 Session json parsing failed: {0}")]
    SessionResponseParseFailed(#[source] reqwest::Error),

    /// Session response contained an error.
    #[error("error-atproto-oauth-aip-workflow-9 Session response invalid: {message}")]
    SessionResponseInvalid {
        /// Error message from the session response.
        message: String,
    },

    /// The token response could not be bound to the DID the flow began for.
    ///
    /// Raised when the expected subject is empty, when the token endpoint
    /// omitted the `sub` claim, or when `sub` names a different account than the
    /// one the authorization flow was started for.
    #[error("error-atproto-oauth-aip-workflow-10 Token subject binding failed: {0}")]
    TokenSubjectBindingFailed(#[source] atproto_oauth::errors::OAuthClientError),
}
