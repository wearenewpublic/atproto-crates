//! Structured error types for the space client.
//!
//! ## Error categories
//!
//! - **`SpaceClientError`** (client-1 to client-8): the credential exchange
//!   and the XRPC calls built on it

use thiserror::Error;

/// Why a space call did not succeed.
#[derive(Debug, Error)]
pub enum SpaceClientError {
    /// A host could not be turned into a URL.
    #[error("error-atproto-space-client-client-1 Host is not a URL: {host} {reason}")]
    InvalidHost {
        /// The host as given.
        host: String,
        /// Why it could not be used.
        reason: String,
    },

    /// The delivery target is not one a subscription can be registered for.
    ///
    /// Refused before any hop runs. Hops 1 and 2 spend a single-use grant, and
    /// discovering at hop 3 that the target was never registrable means the
    /// grant was burnt to learn a fact known before hop 1.
    #[error(
        "error-atproto-space-client-client-2 Delivery target is not registrable: {target} {reason}"
    )]
    InvalidDelivery {
        /// The target as given.
        target: String,
        /// Why it cannot be registered.
        reason: String,
    },

    /// The request could not be sent, or the response could not be read.
    #[error("error-atproto-space-client-client-3 Space call to {url} failed: {reason}")]
    Transport {
        /// The URL that was called.
        url: String,
        /// The transport failure.
        reason: String,
    },

    /// The server refused the call.
    #[error("error-atproto-space-client-client-4 {method} refused by {host}: {error}")]
    Refused {
        /// The XRPC method that was called.
        method: String,
        /// The host that refused.
        host: String,
        /// The classified XRPC error.
        #[source]
        error: atproto_client::errors::XrpcError,
    },

    /// The answer did not have the shape the lexicon says.
    #[error("error-atproto-space-client-client-5 {method} answered an unexpected shape: {reason}")]
    UnexpectedResponse {
        /// The XRPC method that was called.
        method: String,
        /// What was wrong with the answer.
        reason: String,
    },

    /// A credential the server minted could not be read.
    #[error(
        "error-atproto-space-client-client-6 Credential from {host} could not be decoded: {reason}"
    )]
    InvalidCredential {
        /// The host that minted it.
        host: String,
        /// Why it could not be read.
        reason: String,
    },

    /// A space URI could not be parsed.
    #[error("error-atproto-space-client-client-7 Space URI is not valid: {uri} {reason}")]
    InvalidSpaceUri {
        /// The URI as given.
        uri: String,
        /// Why it is not valid.
        reason: String,
    },

    /// A request body could not be built.
    #[error("error-atproto-space-client-client-8 Request body could not be encoded: {reason}")]
    InvalidRequest {
        /// Why.
        reason: String,
    },
}
