//! Structured error types for the atpxrpc CLI tool.
//!
//! All errors follow the project convention of prefixed error codes
//! with descriptive messages using the format `error-atpxrpc-{domain}-{number}`.

use thiserror::Error;

/// Error types specific to the atpxrpc CLI tool.
#[derive(Debug, Error)]
pub enum XrpcCliError {
    /// Occurs when the config directory cannot be determined
    #[error("error-atpxrpc-config-1 Cannot determine config directory")]
    ConfigDirNotFound,

    /// Occurs when reading the config file fails
    #[error("error-atpxrpc-config-2 Failed to read config file: {path}")]
    ConfigReadFailed {
        /// The config file path
        path: String,
    },

    /// Occurs when writing the config file fails
    #[error("error-atpxrpc-config-3 Failed to write config file: {path}")]
    ConfigWriteFailed {
        /// The config file path
        path: String,
    },

    /// Occurs when no accounts are configured
    #[error("error-atpxrpc-account-1 No accounts configured, run 'atpxrpc login' first")]
    NoAccountsConfigured,

    /// Occurs when the specified handle is not found in config
    #[error("error-atpxrpc-account-2 Account not found: {handle}")]
    AccountNotFound {
        /// The handle that was not found
        handle: String,
    },

    /// Occurs when multiple accounts exist but no --handle was specified
    #[error(
        "error-atpxrpc-account-3 Multiple accounts configured, use --handle to specify which account"
    )]
    AmbiguousAccount,

    /// Occurs when re-authentication with app password fails
    #[error("error-atpxrpc-session-1 Re-authentication failed: {error}")]
    ReAuthFailed {
        /// The underlying error
        error: String,
    },

    /// Occurs when stdin JSON parsing fails
    #[error("error-atpxrpc-input-1 Failed to parse JSON from stdin: {error}")]
    StdinJsonParseFailed {
        /// The parse error details
        error: String,
    },

    /// Occurs when reading raw bytes from stdin fails
    #[error("error-atpxrpc-input-2 Failed to read bytes from stdin: {error}")]
    StdinBytesReadFailed {
        /// The read error details
        error: String,
    },

    /// Occurs when no PDS endpoint is found in DID document
    #[error("error-atpxrpc-resolve-1 No PDS endpoint found in DID document for: {did}")]
    NoPdsEndpointFound {
        /// The DID that was resolved
        did: String,
    },

    /// Occurs when getting a service auth token fails
    #[error("error-atpxrpc-session-2 Failed to get service auth token: {error}")]
    ServiceAuthFailed {
        /// The underlying error
        error: String,
    },

    /// Occurs when no matching service endpoint is found in a DID document
    #[error(
        "error-atpxrpc-resolve-2 No service endpoint found for {service_id} in DID document for: {did}"
    )]
    NoServiceEndpointFound {
        /// The DID that was resolved
        did: String,
        /// The service ID that was not found
        service_id: String,
    },
}
