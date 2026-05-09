//! Structured error types for atpmcp MCP server operations.
//!
//! All errors follow the project convention of prefixed error codes
//! with descriptive messages: `error-atpmcp-{domain}-{number}`

use thiserror::Error;

#[allow(clippy::enum_variant_names)] // each variant ends in *Failed by domain convention.
/// Errors that can occur during tool operations.
#[derive(Debug, Error)]
pub enum ToolError {
    /// DAG-CBOR serialization of the JSON value failed.
    #[error("error-atpmcp-tool-1 Failed to serialize record to DAG-CBOR: {reason}")]
    SerializationFailed {
        /// Description of the serialization failure.
        reason: String,
    },

    /// Lexicon schema validation failed.
    #[error("error-atpmcp-tool-2 Lexicon schema validation failed: {reason}")]
    ValidationFailed {
        /// Description of the validation failure.
        reason: String,
    },

    /// Handle resolution failed.
    #[error("error-atpmcp-tool-3 Handle resolution failed: {reason}")]
    HandleResolutionFailed {
        /// Description of the resolution failure.
        reason: String,
    },

    /// Identity resolution failed.
    #[error("error-atpmcp-tool-4 Identity resolution failed: {reason}")]
    IdentityResolutionFailed {
        /// Description of the resolution failure.
        reason: String,
    },

    /// Facet parsing failed.
    #[error("error-atpmcp-tool-5 Facet parsing failed: {reason}")]
    FacetParsingFailed {
        /// Description of the parsing failure.
        reason: String,
    },

    /// Record retrieval failed.
    #[error("error-atpmcp-tool-6 Record retrieval failed: {reason}")]
    RecordRetrievalFailed {
        /// Description of the retrieval failure.
        reason: String,
    },

    /// Lexicon retrieval failed.
    #[error("error-atpmcp-tool-7 Lexicon retrieval failed: {reason}")]
    LexiconRetrievalFailed {
        /// Description of the retrieval failure.
        reason: String,
    },

    /// XRPC request failed.
    #[error("error-atpmcp-tool-8 XRPC request failed: {reason}")]
    XrpcRequestFailed {
        /// Description of the request failure.
        reason: String,
    },

    /// XRPC parameter validation failed.
    #[error("error-atpmcp-tool-9 XRPC validation failed: {reason}")]
    XrpcValidationFailed {
        /// Description of the validation failure.
        reason: String,
    },

    /// Record transmogrification failed.
    #[error("error-atpmcp-tool-10 Transmogrification failed: {reason}")]
    TransmogrifyFailed {
        /// Description of the transmogrification failure.
        reason: String,
    },
}
