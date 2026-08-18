//! # Structured Error Types
//!
//! Comprehensive error handling for AT Protocol client operations using structured error types
//! with the `thiserror` library. All errors follow the project convention of prefixed error codes
//! with descriptive messages.
//!
//! ## Error Categories
//!
//! - **`ClientError`** (http-1 to http-5): HTTP client operation errors including request failures and parsing errors
//! - **`DPoPError`** (auth-1 to auth-7): DPoP authentication related errors
//! - **`XrpcError`** (xrpc-1 to xrpc-5): An XRPC response classified by status and error code
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Occurs when a response body was expected to be JSON and was not.
    ///
    /// Carries the status, because the usual cause is a server or a proxy
    /// answering an error in some other format, and the status is the part
    /// that says what happened.
    #[error("error-atproto-client-http-5 Response body was not JSON: {url} {status}")]
    ResponseNotJson {
        /// The URL that was requested
        url: String,
        /// The HTTP status the server answered with
        status: u16,
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

    /// Occurs when DPoP authenticated HTTP request fails.
    ///
    /// No longer produced by this crate: [`crate::client::dpop_call`] issues
    /// its requests directly and reports a transport failure as
    /// [`DPoPError::RequestFailed`]. Kept so existing matches still compile.
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

    /// Occurs when a DPoP authenticated request could not be sent.
    ///
    /// Distinct from [`DPoPError::HttpRequestFailed`], which carries a
    /// `reqwest_middleware::Error` because it comes from a middleware stack.
    /// [`crate::client::dpop_call`] issues its requests directly, so its
    /// transport failures are plain `reqwest` errors.
    #[error("error-atproto-client-auth-4 DPoP request failed: {url} {error}")]
    RequestFailed {
        /// The URL that was requested
        url: String,
        /// The underlying HTTP error
        error: reqwest::Error,
    },

    /// Occurs when the response body could not be read off the socket.
    ///
    /// This is a transport failure, not a parse failure: a body that arrives
    /// intact but is not JSON is reported as an absent body rather than as an
    /// error, because a proxy answering HTML is a response the caller still
    /// needs to see the status of.
    #[error("error-atproto-client-auth-5 DPoP response body could not be read: {url} {error}")]
    BodyReadFailed {
        /// The URL that was requested
        url: String,
        /// The underlying streaming error
        error: reqwest::Error,
    },

    /// Occurs when a request body could not be serialized to JSON.
    #[error("error-atproto-client-auth-6 DPoP request body serialization failed: {error}")]
    BodySerializationFailed {
        /// The underlying serialization error
        error: serde_json::Error,
    },

    /// Occurs when a header this transport sets cannot be encoded.
    ///
    /// Reached when an access token or a content type carries a byte a header
    /// value may not hold. Refused rather than dropped: a request that went
    /// out without its `Authorization` header would be answered with a 401
    /// naming nothing.
    #[error("error-atproto-client-auth-7 DPoP header value is not valid: {name}")]
    InvalidHeaderValue {
        /// The header that could not be set
        name: String,
    },
}

/// Why an upstream response could not be read as an AT Protocol error.
///
/// Both variants mean the same thing to a caller -- the server did not answer
/// in the protocol -- and they are kept apart because the retry decision is
/// different. A 5xx is worth trying again; a status outside every range this
/// classifier models is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamReason {
    /// The server answered 5xx.
    ServerError,
    /// The server answered a status this classifier does not model.
    UnexpectedStatus,
}

impl std::fmt::Display for UpstreamReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpstreamReason::ServerError => write!(f, "server error"),
            UpstreamReason::UnexpectedStatus => write!(f, "unexpected status"),
        }
    }
}

/// An unsuccessful XRPC response, classified.
///
/// XRPC reports failures as a status code plus a `{"error", "message"}` body,
/// and the two together carry more than either alone: a `400` is a client
/// mistake, an `InvalidSwap` `400` is a compare-and-swap race that a correct
/// writer retries, and a `403 ScopeMissingError` is a grant that needs
/// widening. Callers that only see the body cannot tell these apart, which is
/// why [`crate::client::XrpcResponse`] keeps the status line and this type
/// reads both halves.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum XrpcError {
    /// The server is shedding load.
    ///
    /// `retry_after_secs` is absent when the server sent no `Retry-After`, or
    /// sent it in the HTTP-date form; see
    /// [`crate::client::XrpcResponse::retry_after_secs`].
    #[error("error-atproto-client-xrpc-1 Rate limited: retry after {}", match .retry_after_secs { Some(secs) => format!("{secs}s"), None => "an unstated interval".to_string() })]
    RateLimited {
        /// Seconds to wait before retrying, when the server said.
        retry_after_secs: Option<u64>,
    },

    /// The credential was refused, or does not reach this method.
    ///
    /// Covers `401` and `403`, and the `400 ExpiredToken` / `400 InvalidToken`
    /// pair that some deployments answer instead of a `401`.
    #[error("error-atproto-client-xrpc-2 Not authorized: {code} {message}")]
    Unauthorized {
        /// The XRPC error code, empty when the server sent none.
        code: String,
        /// The XRPC error message, empty when the server sent none.
        message: String,
    },

    /// A compare-and-swap failed: the record moved under the write.
    ///
    /// Modelled separately because it is the one error every correct writer
    /// has to handle, and handling it means re-reading and retrying rather
    /// than reporting a failure.
    #[error("error-atproto-client-xrpc-3 Compare-and-swap failed: {message}")]
    InvalidSwap {
        /// The XRPC error message, empty when the server sent none.
        message: String,
    },

    /// A method-specific error named by the lexicon.
    #[error("error-atproto-client-xrpc-4 XRPC error: {status} {code} {message}")]
    Lexicon {
        /// The HTTP status the server answered with.
        status: u16,
        /// The XRPC error code.
        code: String,
        /// The XRPC error message, empty when the server sent none.
        message: String,
    },

    /// The server did not answer in the protocol.
    #[error("error-atproto-client-xrpc-5 Upstream failure: {status} {reason}: {detail}")]
    Upstream {
        /// The HTTP status the server answered with.
        status: u16,
        /// Whether this is a 5xx or an unmodelled status.
        reason: UpstreamReason,
        /// Whatever the server said, for a log line.
        detail: String,
    },
}

impl XrpcError {
    /// Classify an unsuccessful response.
    ///
    /// Returns `None` for a 2xx, so a caller can write
    /// `if let Some(error) = XrpcError::from_response(&response)`.
    pub fn from_response(response: &crate::client::XrpcResponse) -> Option<Self> {
        if response.status.is_success() {
            return None;
        }
        let (code, message) = response.xrpc_error_fields();
        Some(Self::classify(
            response.status.as_u16(),
            &code,
            &message,
            response.retry_after_secs(),
        ))
    }

    /// The failure table, as a pure function.
    ///
    /// Separated from [`XrpcError::from_response`] so it can be exercised
    /// without a socket, which is the only way a table like this stays
    /// checked.
    pub fn classify(status: u16, code: &str, message: &str, retry_after_secs: Option<u64>) -> Self {
        let detail = match (code.is_empty(), message.is_empty()) {
            (true, true) => String::new(),
            (true, false) => message.to_string(),
            (false, true) => code.to_string(),
            (false, false) => format!("{code}: {message}"),
        };

        match status {
            429 => XrpcError::RateLimited { retry_after_secs },
            401 | 403 => XrpcError::Unauthorized {
                code: code.to_string(),
                message: message.to_string(),
            },
            400 if code == "InvalidSwap" => XrpcError::InvalidSwap {
                message: message.to_string(),
            },
            // Some deployments answer an expired credential with a 400 naming
            // the token rather than a 401. The caller's response is the same
            // either way -- refresh and retry -- so the classification is too.
            400 if code == "ExpiredToken" || code == "InvalidToken" => XrpcError::Unauthorized {
                code: code.to_string(),
                message: message.to_string(),
            },
            // `RateLimitExceeded` occasionally arrives with a 5xx from a proxy
            // that did not preserve the status. Trusting the code here keeps
            // the call from being reported as a transport failure the caller
            // would retry too fast.
            500..=599 if code == "RateLimitExceeded" => XrpcError::RateLimited { retry_after_secs },
            500..=599 => XrpcError::Upstream {
                status,
                reason: UpstreamReason::ServerError,
                detail,
            },
            // Any other 4xx that named an error code is the lexicon speaking:
            // a `404 RecordNotFound` and a `409 ConflictingWrite` are both
            // method-specific errors, and flattening them into `Upstream`
            // would throw away the only field that says which.
            400..=499 if !code.is_empty() => XrpcError::Lexicon {
                status,
                code: code.to_string(),
                message: message.to_string(),
            },
            _ => XrpcError::Upstream {
                status,
                reason: UpstreamReason::UnexpectedStatus,
                detail,
            },
        }
    }
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
