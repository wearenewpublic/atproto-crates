//! # Structured Error Types
//!
//! Comprehensive error handling for AT Protocol client operations using structured error types
//! with the `thiserror` library. All errors follow the project convention of prefixed error codes
//! with descriptive messages.
//!
//! ## Error Categories
//!
//! - **`ClientError`** (http-1 to http-2): HTTP client operation errors including request failures and parsing errors
//! - **`DPoPError`** (auth-1 to auth-3): DPoP authentication related errors
//! - **`CliError`** (cli-1 to cli-4): Command-line interface specific errors including file I/O and resolution failures
//!
//! ## Error Format
//!
//! All errors use the standardized format: `error-atproto-client-{domain}-{number} {message}: {details}`

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Simple error response structure for AT Protocol APIs.
///
/// This structure represents the standard error response format used by AT Protocol
/// services, allowing for flexible error reporting with optional fields and
/// extension points for additional error context.
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, Serialize, Deserialize)]
pub struct SimpleError {
    /// The error code identifier
    pub error: Option<String>,
    /// Human-readable description of the error
    pub error_description: Option<String>,
    /// Additional error message details
    pub message: Option<String>,

    /// Additional error fields that don't fit standard structure
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl SimpleError {
    /// Combines all available error information into a single message.
    ///
    /// Concatenates the error code, description, and message fields with
    /// colons to provide a comprehensive error description.
    pub fn error_message(&self) -> String {
        [&self.error, &self.error_description, &self.message]
            .iter()
            .filter_map(|v| (*v).clone())
            .collect::<Vec<String>>()
            .join(": ")
    }
}

/// Error types that can occur during HTTP client operations.
///
/// These errors represent failures in basic HTTP operations such as
/// making requests and parsing responses for unauthenticated operations.
#[derive(Debug, Error)]
pub enum ClientError {
    /// Occurs when an HTTP request fails
    #[error("error-atproto-client-http-1 HTTP request failed: {url} {error}")]
    HttpRequestFailed {
        /// The URL that was requested
        url: String,
        /// The underlying HTTP error
        error: reqwest::Error,
    },

    /// Occurs when JSON parsing from HTTP response fails
    #[error("error-atproto-client-http-2 JSON parsing failed: {url} {error}")]
    JsonParseFailed {
        /// The URL that was requested
        url: String,
        /// The underlying parse error
        error: reqwest::Error,
    },

    /// Occurs when streaming response bytes fails
    #[error("error-atproto-client-http-3 Failed to stream response bytes: {url} {error}")]
    ByteStreamFailed {
        /// The URL that was requested
        url: String,
        /// The underlying streaming error
        error: reqwest::Error,
    },

    /// Occurs when an invalid authentication method is used for an operation
    #[error("error-atproto-client-http-4 Invalid authentication method: {method}")]
    InvalidAuthMethod {
        /// Description of the authentication requirement
        method: String,
    },
}

/// Error types that can occur during DPoP authentication operations.
///
/// These errors represent failures in authenticated HTTP operations using
/// DPoP (Demonstration of Proof-of-Possession) for client authentication.
#[derive(Debug, Error)]
pub enum DPoPError {
    /// Occurs when DPoP proof generation fails
    #[error("error-atproto-client-auth-1 DPoP proof generation failed: {error}")]
    ProofGenerationFailed {
        /// The underlying error from DPoP operations
        error: anyhow::Error,
    },

    /// Occurs when DPoP authenticated HTTP request fails
    #[error("error-atproto-client-auth-2 DPoP HTTP request failed: {url} {error}")]
    HttpRequestFailed {
        /// The URL that was requested
        url: String,
        /// The underlying HTTP error from middleware
        error: reqwest_middleware::Error,
    },

    /// Occurs when JSON parsing from DPoP authenticated response fails
    #[error("error-atproto-client-auth-3 DPoP JSON parsing failed: {url} {error}")]
    JsonParseFailed {
        /// The URL that was requested
        url: String,
        /// The underlying parse error
        error: reqwest::Error,
    },
}

/// Error types that can occur in CLI tools.
///
/// These errors represent failures specific to command-line interface operations
/// such as file I/O, JSON parsing from files, and DID document resolution.
#[derive(Debug, Error)]
pub enum CliError {
    /// Occurs when reading a file fails
    #[error("error-atproto-client-cli-1 Failed to read file: {path}")]
    FileReadFailed {
        /// The file path that failed to read
        path: String,
    },

    /// Occurs when parsing JSON from a file fails
    #[error("error-atproto-client-cli-2 Failed to parse JSON from file: {path}")]
    JsonParseFromFileFailed {
        /// The file path containing invalid JSON
        path: String,
    },

    /// Occurs when no PDS endpoint is found in DID document
    #[error("error-atproto-client-cli-3 No PDS endpoint found in DID document for: {did}")]
    NoPdsEndpointFound {
        /// The DID that was resolved
        did: String,
    },

    /// Occurs when no JSON data is provided for a procedure call
    #[error("error-atproto-client-cli-4 No JSON data provided for procedure call")]
    NoJsonDataProvided,
}
