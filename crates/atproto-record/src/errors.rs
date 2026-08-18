//! Structured error types for AT Protocol record operations.
//!
//! This module provides comprehensive error handling for all AT Protocol record operations
//! using type-safe error enums powered by the `thiserror` library. All errors follow the
//! project's standardized naming convention for consistent error reporting and debugging.
//!
//! ## Error Categories
//!
//! ### `VerificationError` (Domain: verification)
//! Errors related to cryptographic signature creation and verification operations.
//! Error codes: verification-1 through verification-11
//!
//! ### `AturiError` (Domain: aturi)
//! Errors occurring during AT-URI parsing and validation.
//! Error codes: aturi-1 through aturi-9
//!
//! ### `TidError` (Domain: tid)
//! Errors occurring during TID (Timestamp Identifier) parsing and decoding.
//! Error codes: tid-1 through tid-3
//!
//! ### `CliError` (Domain: cli)
//! Command-line interface specific errors for file I/O, argument parsing, and DID validation.
//! Error codes: cli-1 through cli-10
//!
//! ## Error Format
//!
//! All errors follow the standardized format:
//! ```text
//! error-atproto-record-{domain}-{number} {message}: {details}
//! ```
//!
//! ## Example Usage
//!
//! ```ignore
//! use atproto_record::errors::VerificationError;
//!
//! fn verify_signature() -> Result<(), VerificationError> {
//!     // Verification logic
//!     Err(VerificationError::NoSignaturesField)
//! }
//! ```

use thiserror::Error;

/// Errors that can occur during record signature creation and verification.
///
/// This enum covers all failure modes in the signature lifecycle, from creating
/// signatures with missing metadata fields to verifying signatures with invalid
/// cryptographic proofs or serialization failures.
#[derive(Debug, Error)]
pub enum VerificationError {
    /// Error when no signatures field is found in the record.
    ///
    /// This error occurs when a record does not contain either a "signatures"
    /// or "sigs" field, which is required for signature verification.
    #[error("error-atproto-record-verification-1 No signatures field found in record")]
    NoSignaturesField,

    /// Error when issuer field is missing from a signature object.
    ///
    /// This error occurs when a signature object in the signatures array
    /// does not contain the required "issuer" field.
    #[error("error-atproto-record-verification-2 Missing issuer field in signature object")]
    MissingIssuerField,

    /// Error when signature field is missing from a signature object.
    ///
    /// This error occurs when a signature object in the signatures array
    /// does not contain the required "signature" field.
    #[error("error-atproto-record-verification-3 Missing signature field in signature object")]
    MissingSignatureField,

    /// Error when record serialization fails.
    ///
    /// This error occurs when the signed record cannot be serialized
    /// to IPLD CBOR format for signature verification. Requires the `resolve`
    /// feature, which is what brings the DAG-CBOR encoder into the tree.
    #[cfg(feature = "resolve")]
    #[error("error-atproto-record-verification-4 Record serialization failed: {error}")]
    RecordSerializationFailed {
        /// The underlying serialization error
        #[from]
        error: atproto_dasl::EncodeError,
    },

    /// Error when signature verification fails.
    ///
    /// This error occurs when the cryptographic verification of the
    /// signature against the signed record fails, indicating the
    /// signature is invalid for the given data and public key.
    #[error("error-atproto-record-verification-5 Signature verification failed: {error}")]
    SignatureVerificationFailed {
        /// The underlying verification error
        error: anyhow::Error,
    },

    /// Error when no valid signature is found for the specified issuer.
    ///
    /// This error occurs when none of the signatures in the record
    /// belong to the specified issuer, or when all signatures from
    /// the issuer fail verification.
    #[error("error-atproto-record-verification-6 No valid signature found for issuer: {issuer}")]
    NoValidSignatureForIssuer {
        /// The issuer DID for which no valid signature was found
        issuer: String,
    },

    /// Error when signature object is not a valid JSON object.
    ///
    /// This error occurs when the provided signature object parameter
    /// is not a JSON object type, which is required for signature creation.
    #[error("error-atproto-record-verification-7 Signature object must be a JSON object")]
    InvalidSignatureObjectType,

    /// Error when signature object is missing required fields.
    ///
    /// This error occurs when the signature object is missing fields that are
    /// necessary during signature creation, such as 'issuer'.
    #[error("error-atproto-record-verification-8 Signature object missing field: {field}")]
    SignatureObjectMissingField {
        /// The name of the missing field
        field: String,
    },

    /// Error when cryptographic key operations fail.
    ///
    /// This error occurs when key-related operations such as signing
    /// or key parsing fail during signature creation or verification.
    #[error("error-atproto-record-verification-9 Key operation failed: {error}")]
    KeyOperationFailed {
        /// The underlying key operation error
        #[from]
        error: atproto_identity::errors::KeyError,
    },

    /// Error when signature decoding fails.
    ///
    /// This error occurs when the multibase-encoded signature cannot
    /// be decoded, typically due to invalid encoding format.
    #[error("error-atproto-record-verification-10 Signature decoding failed: {error}")]
    SignatureDecodingFailed {
        /// The underlying multibase decoding error
        error: base64::DecodeError,
    },

    /// Error when cryptographic signature validation fails.
    ///
    /// This error occurs when the cryptographic validation of the signature
    /// fails, indicating either an invalid signature or mismatched key/data.
    #[error("error-atproto-record-verification-11 Cryptographic validation failed: {error}")]
    CryptographicValidationFailed {
        /// The underlying validation error
        error: atproto_identity::errors::KeyError,
    },
}

/// Errors that can occur during AT-URI parsing and validation.
///
/// This enum covers all validation failures when parsing AT-URIs, including
/// format violations, missing components, and invalid authority types.
#[derive(Debug, Error)]
pub enum AturiError {
    /// Error when AT-URI does not start with the required "at://" prefix.
    ///
    /// This error occurs when the input string does not begin with the
    /// required AT-URI scheme identifier.
    #[error("error-atproto-record-aturi-1 Invalid AT-URI format: missing 'at://' prefix")]
    MissingPrefix,

    /// Error when AT-URI ends with a trailing slash.
    ///
    /// This error occurs when the AT-URI string ends with a forward slash,
    /// which is not permitted in valid AT-URI format.
    #[error("error-atproto-record-aturi-2 Invalid AT-URI format: trailing slash not permitted")]
    TrailingSlash,

    /// Error when authority component is missing from AT-URI.
    ///
    /// This error occurs when the AT-URI does not contain a valid authority
    /// component after the "at://" prefix.
    #[error("error-atproto-record-aturi-3 Authority component missing from AT-URI")]
    AuthorityMissing,

    /// Error when authority is a handle instead of a DID.
    ///
    /// This error occurs when the authority component is a handle rather
    /// than a DID, which is not supported for AT-URI operations.
    #[error("error-atproto-record-aturi-4 Unsupported authority type: handle not permitted")]
    HandleNotSupported,

    /// Error when authority component cannot be parsed as a valid DID.
    ///
    /// This error occurs when the authority component is not a valid
    /// handle or DID, or when DID parsing fails.
    #[error("error-atproto-record-aturi-5 Authority parsing failed: {error}")]
    AuthorityParsingFailed {
        /// The underlying parsing error
        #[from]
        error: atproto_identity::errors::ResolveError,
    },

    /// Error when collection (NSID) component is missing from AT-URI.
    ///
    /// This error occurs when the AT-URI does not contain a collection
    /// component after the authority.
    #[error("error-atproto-record-aturi-6 Collection component missing from AT-URI")]
    CollectionMissing,

    /// Error when record key component is missing from AT-URI.
    ///
    /// This error occurs when the AT-URI does not contain a record key
    /// component after the collection.
    #[error("error-atproto-record-aturi-7 Record key component missing from AT-URI")]
    RecordKeyMissing,

    /// Error when collection (NSID) component is empty in AT-URI.
    ///
    /// This error occurs when the AT-URI contains an empty or whitespace-only
    /// collection component, which is not valid.
    #[error("error-atproto-record-aturi-8 Collection component cannot be empty")]
    EmptyCollection,

    /// Error when record key component is empty in AT-URI.
    ///
    /// This error occurs when the AT-URI contains an empty or whitespace-only
    /// record key component, which is not valid.
    #[error("error-atproto-record-aturi-9 Record key component cannot be empty")]
    EmptyRecordKey,
}

/// Errors that can occur during TID (Timestamp Identifier) operations.
///
/// This enum covers all validation failures when parsing and decoding TIDs,
/// including format violations, invalid characters, and encoding errors.
#[derive(Debug, Error)]
pub enum TidError {
    /// Error when TID string length is invalid.
    ///
    /// This error occurs when a TID string is not exactly 13 characters long,
    /// which is required by the TID specification.
    #[error("error-atproto-record-tid-1 Invalid TID length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Expected length (always 13)
        expected: usize,
        /// Actual length of the provided string
        actual: usize,
    },

    /// Error when TID contains an invalid character.
    ///
    /// This error occurs when a TID string contains a character outside the
    /// base32-sortable character set (234567abcdefghijklmnopqrstuvwxyz).
    #[error("error-atproto-record-tid-2 Invalid character '{character}' at position {position}")]
    InvalidCharacter {
        /// The invalid character
        character: char,
        /// Position in the string (0-indexed)
        position: usize,
    },

    /// Error when TID format is invalid.
    ///
    /// This error occurs when the TID violates structural requirements,
    /// such as having the top bit set (which must always be 0).
    #[error("error-atproto-record-tid-3 Invalid TID format: {reason}")]
    InvalidFormat {
        /// Reason for the format violation
        reason: String,
    },
}

/// Errors specific to command-line interface operations.
///
/// This enum covers failures in CLI argument parsing, file I/O operations,
/// JSON processing, and DID validation that occur in the binary tools.
#[derive(Debug, Error)]
pub enum CliError {
    /// Occurs when DID method is not supported
    #[error("error-atproto-record-cli-1 Unsupported DID method: {method}")]
    UnsupportedDidMethod {
        /// The unsupported DID method
        method: String,
    },

    /// Occurs when DID parsing fails
    #[error("error-atproto-record-cli-2 Failed to parse DID: {did}")]
    DidParseFailed {
        /// The DID that failed to parse
        did: String,
    },

    /// Occurs when reading from stdin fails
    #[error("error-atproto-record-cli-3 Failed to read from stdin")]
    StdinReadFailed,

    /// Occurs when parsing JSON from stdin fails
    #[error("error-atproto-record-cli-4 Failed to parse JSON from stdin")]
    StdinJsonParseFailed,

    /// Occurs when reading a file fails
    #[error("error-atproto-record-cli-5 Failed to read file: {path}")]
    FileReadFailed {
        /// The file path that failed to read
        path: String,
    },

    /// Occurs when parsing JSON from a file fails
    #[error("error-atproto-record-cli-6 Failed to parse JSON from file: {path}")]
    FileJsonParseFailed {
        /// The file path containing invalid JSON
        path: String,
    },

    /// Occurs when an unexpected argument is provided
    #[error("error-atproto-record-cli-7 Unexpected argument: {argument}")]
    UnexpectedArgument {
        /// The unexpected argument
        argument: String,
    },

    /// Occurs when a required value is missing
    #[error("error-atproto-record-cli-8 Missing required value: {name}")]
    MissingRequiredValue {
        /// The name of the missing value
        name: String,
    },

    /// Occurs when record serialization to DAG-CBOR fails
    #[error("error-atproto-record-cli-9 Failed to serialize record to DAG-CBOR: {error}")]
    RecordSerializationFailed {
        /// The underlying serialization error
        error: String,
    },

    /// Occurs when CID generation fails
    #[error("error-atproto-record-cli-10 Failed to generate CID: {error}")]
    CidGenerationFailed {
        /// The underlying CID generation error
        error: String,
    },
}
