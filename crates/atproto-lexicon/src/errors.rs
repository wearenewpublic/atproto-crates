//! Error types for the atproto-lexicon crate.
//!
//! This module defines all error types for lexicon operations including resolution,
//! validation, and schema processing. All errors follow the project's error naming
//! convention using globally unique identifiers.
//!
//! ## Error Categories
//!
//! - **`LexiconResolveError`** (lexicon-resolve-1 to lexicon-resolve-6): Errors during lexicon resolution
//! - **`LexiconValidationError`** (lexicon-validation-1 to lexicon-validation-8): Validation errors for NSIDs and schemas
//! - **`LexiconSchemaError`** (lexicon-schema-1 to lexicon-schema-4): Schema parsing and structure errors
//! - **`TransmogrifyError`** (lexicon-transmogrify-1 to lexicon-transmogrify-6): Record transmogrification errors
//! - **`CompatibilityError`** (lexicon-compat-1 to lexicon-compat-2): Schema compatibility analysis errors
//!
//! ## Error Format
//!
//! All errors follow the format: `error-atproto-lexicon-<domain>-<number> <message>: <details>`

use atproto_identity::errors::ResolveError;
use thiserror::Error;

/// Errors that can occur during lexicon resolution operations.
#[derive(Debug, Error)]
pub enum LexiconResolveError {
    /// No DIDs found when resolving a handle or identifier.
    #[error("error-atproto-lexicon-resolve-1 No DIDs found for resolution")]
    NoDIDsFound,

    /// Multiple DIDs found when expecting exactly one.
    #[error("error-atproto-lexicon-resolve-2 Multiple DIDs found: expected single DID")]
    MultipleDIDsFound,

    /// Invalid DID format encountered during resolution.
    #[error("error-atproto-lexicon-resolve-3 Invalid DID format: {did}")]
    InvalidDIDFormat {
        /// The invalid DID string
        did: String,
    },

    /// No PDS endpoint found in DID document.
    #[error("error-atproto-lexicon-resolve-4 No PDS endpoint found in DID document")]
    NoPDSEndpoint,

    /// Failed to fetch lexicon from PDS.
    #[error("error-atproto-lexicon-resolve-5 Failed to fetch lexicon from PDS: {details}")]
    PDSFetchFailed {
        /// Details about the fetch failure
        details: String,
    },

    /// Error response from PDS when fetching lexicon.
    #[error("error-atproto-lexicon-resolve-6 Error fetching lexicon for {nsid}: {message}")]
    PDSErrorResponse {
        /// The NSID being fetched
        nsid: String,
        /// Error message from PDS
        message: String,
    },

    /// Invalid NSID provided for resolution.
    #[error("error-atproto-lexicon-resolve-7 Invalid NSID: {nsid}")]
    InvalidNsid {
        /// The invalid NSID string
        nsid: String,
    },
}

/// Errors that can occur during lexicon validation.
#[derive(Debug, Error)]
pub enum LexiconValidationError {
    /// Invalid NSID format.
    #[error("error-atproto-lexicon-validation-1 Invalid NSID format: {details}")]
    InvalidNsidFormat {
        /// Details about what makes the NSID invalid
        details: String,
    },

    /// Invalid reference format.
    #[error("error-atproto-lexicon-validation-2 Invalid reference format: {details}")]
    InvalidReferenceFormat {
        /// Details about what makes the reference invalid
        details: String,
    },

    /// NSID has insufficient parts (requires at least 3).
    #[error("error-atproto-lexicon-validation-3 NSID must have at least 3 parts: {nsid}")]
    InsufficientNsidParts {
        /// The NSID with insufficient parts
        nsid: String,
    },

    /// Cannot convert NSID to DNS name.
    #[error("error-atproto-lexicon-validation-4 Cannot convert NSID to DNS name: {nsid}")]
    InvalidDnsNameConversion {
        /// The NSID that couldn't be converted
        nsid: String,
    },

    /// Empty NSID provided.
    #[error("error-atproto-lexicon-validation-5 Empty NSID provided")]
    EmptyNsid,

    /// NSID contains empty parts.
    #[error("error-atproto-lexicon-validation-6 NSID contains empty parts: {nsid}")]
    EmptyNsidParts {
        /// The NSID with empty parts
        nsid: String,
    },

    /// Invalid NSID character.
    #[error("error-atproto-lexicon-validation-7 Invalid character in NSID: {details}")]
    InvalidNsidCharacter {
        /// Details about the invalid character
        details: String,
    },

    /// Invalid NSID in schema ID field.
    #[error("error-atproto-lexicon-validation-8 Invalid NSID in schema ID field: {id}")]
    InvalidSchemaId {
        /// The invalid ID from the schema
        id: String,
    },
}

/// Errors that can occur when processing lexicon schemas.
#[derive(Debug, Error)]
pub enum LexiconSchemaError {
    /// Lexicon schema must be an object.
    #[error("error-atproto-lexicon-schema-1 Lexicon schema must be an object")]
    NotAnObject,

    /// Missing required 'lexicon' version field.
    #[error("error-atproto-lexicon-schema-2 Missing 'lexicon' version field")]
    MissingLexiconVersion,

    /// Missing or invalid 'id' field.
    #[error("error-atproto-lexicon-schema-3 Missing or invalid 'id' field")]
    MissingOrInvalidId,

    /// Missing or invalid 'defs' field.
    #[error("error-atproto-lexicon-schema-4 Missing or invalid 'defs' field")]
    MissingOrInvalidDefs,
}

/// Errors specific to recursive lexicon resolution.
#[derive(Debug, Error)]
pub enum LexiconRecursiveError {
    /// Failed to resolve any lexicons during recursive resolution.
    #[error("error-atproto-lexicon-recursive-1 Failed to resolve any lexicons")]
    NoLexiconsResolved,
}

/// Errors that can occur during record transmogrification.
#[derive(Debug, Error)]
pub enum TransmogrifyError {
    /// Source schema parsing failed.
    #[error("error-atproto-lexicon-transmogrify-1 Failed to parse source schema: {0}")]
    ParseFrom(String),

    /// Destination schema parsing failed.
    #[error("error-atproto-lexicon-transmogrify-2 Failed to parse destination schema: {0}")]
    ParseTo(String),

    /// No morphism found between source and destination schemas.
    #[error(
        "error-atproto-lexicon-transmogrify-3 No morphism found between source and destination schemas"
    )]
    NoMorphismFound,

    /// Failed to compile migration between schemas.
    #[error("error-atproto-lexicon-transmogrify-4 Failed to compile migration: {0}")]
    CompileFailed(String),

    /// Failed to parse record against source schema.
    #[error("error-atproto-lexicon-transmogrify-5 Failed to parse record: {0}")]
    ParseRecord(String),

    /// Failed to lift record to destination schema.
    #[error(
        "error-atproto-lexicon-transmogrify-6 Failed to lift record to destination schema: {0}"
    )]
    LiftFailed(String),

    /// Failed to resolve a lexicon schema during transmogrification.
    #[error(
        "error-atproto-lexicon-transmogrify-7 Schema resolution failed for '{nsid}': {details}"
    )]
    SchemaResolveFailed {
        /// The NSID that failed to resolve.
        nsid: String,
        /// Details about the failure.
        details: String,
    },
}

/// Errors that can occur during schema compatibility analysis.
#[derive(Debug, Error)]
pub enum CompatibilityError {
    /// Failed to parse the source ('from') schema.
    #[error("error-atproto-lexicon-compat-1 Failed to parse source schema: {0}")]
    ParseFrom(String),

    /// Failed to parse the destination ('to') schema.
    #[error("error-atproto-lexicon-compat-2 Failed to parse destination schema: {0}")]
    ParseTo(String),
}

// Re-export the validation error for backwards compatibility during migration
pub use LexiconValidationError as ValidationError;

/// Implement conversion from ResolveError to LexiconResolveError.
impl From<ResolveError> for LexiconResolveError {
    fn from(err: ResolveError) -> Self {
        match err {
            ResolveError::NoDIDsFound => LexiconResolveError::NoDIDsFound,
            ResolveError::MultipleDIDsFound => LexiconResolveError::MultipleDIDsFound,
            _ => LexiconResolveError::PDSFetchFailed {
                details: format!("DNS resolution error: {:?}", err),
            },
        }
    }
}
