//! # Structured Error Types
//!
//! Comprehensive error handling for AT Protocol identity operations using structured error types
//! with the `thiserror` library. All errors follow the project convention of prefixed error codes
//! with descriptive messages.
//!
//! ## Error Categories
//!
//! - **`WebDIDError`** (web-1 to web-5): Errors specific to `did:web` operations including URL conversion and document fetching
//! - **`ConfigError`** (config-1 to config-3): Configuration and environment variable related errors
//! - **`ResolveError`** (resolve-1 to resolve-8): Handle and DID resolution errors including DNS/HTTP failures and conflicts
//! - **`PLCDIDError`** (plc-1 to plc-2): PLC directory communication and document parsing errors
//! - **`KeyError`** (key-1 to key-12): Cryptographic key operations including generation, parsing, signing, and validation
//! - **`WebVHDIDError`** (webvh-1 to webvh-27): `did:webvh` log resolution, verification, and target validation errors
//! - **`DidHostError`** (host-1 to host-8): Host extraction and validation for `did:web` and `did:webvh` targets
//! - **`EndpointError`** (endpoint-1 to endpoint-8): Untrusted service endpoint URL policy violations
//! - **`StorageError`** (storage-1 to storage-3): Storage operations including cache lock failures and data access errors
//!
//! ## Error Format
//!
//! All errors use the standardized format: `error-atproto-identity-{domain}-{number} {message}: {details}`

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error types that can occur when working with Web DIDs
#[derive(Debug, Error)]
pub enum WebDIDError {
    /// Occurs when the DID is missing the 'did:web:' prefix
    #[error("error-atproto-identity-web-1 Invalid DID format: missing 'did:web:' prefix")]
    InvalidDIDPrefix,

    /// Occurs when the DID is missing a hostname component
    #[error("error-atproto-identity-web-2 Invalid DID format: missing hostname component")]
    MissingHostname,

    /// Occurs when the HTTP request to fetch the DID document fails
    #[error("error-atproto-identity-web-3 HTTP request failed: {url} {error}")]
    HttpRequestFailed {
        /// The URL that was requested
        url: String,
        /// The underlying HTTP error
        error: reqwest::Error,
    },

    /// Occurs when the DID document cannot be parsed from the HTTP response
    #[error("error-atproto-identity-web-4 Failed to parse DID document: {url} {error}")]
    DocumentParseFailed {
        /// The URL that was requested
        url: String,
        /// The underlying parse error
        error: reqwest::Error,
    },

    /// Occurs when the did:web target host or path fails validation
    #[error("error-atproto-identity-web-5 Rejected did:web target: {source}")]
    InvalidHost {
        /// The underlying host-extraction failure
        #[from]
        source: DidHostError,
    },
}

/// Error types that can occur when extracting a network host from a DID.
///
/// Produced by [`crate::host::did_host`] when a `did:web` or `did:webvh` DID
/// does not encode a safe, syntactically valid HTTPS target.
#[derive(Debug, Error)]
pub enum DidHostError {
    /// Occurs when the DID method does not encode a network host
    #[error("error-atproto-identity-host-1 Unsupported DID method for host extraction: {did}")]
    UnsupportedMethod {
        /// The DID that was supplied
        did: String,
    },

    /// Occurs when the DID has no hostname component
    #[error("error-atproto-identity-host-2 Invalid DID format: missing hostname component: {did}")]
    MissingHostname {
        /// The DID that was supplied
        did: String,
    },

    /// Occurs when a `did:webvh` DID has no SCID component
    #[error("error-atproto-identity-host-3 Invalid DID format: missing SCID component: {did}")]
    MissingScid {
        /// The DID that was supplied
        did: String,
    },

    /// Occurs when the host is a network address literal rather than a DNS name
    #[error("error-atproto-identity-host-4 Host is a network address literal: {host}")]
    IpLiteralHost {
        /// The rejected host
        host: String,
    },

    /// Occurs when the host is not a syntactically valid DNS hostname
    #[error("error-atproto-identity-host-5 Invalid hostname syntax: {host}")]
    InvalidHostname {
        /// The rejected host
        host: String,
    },

    /// Occurs when the percent-decoded authority carries an unusable port
    #[error("error-atproto-identity-host-6 Invalid port: {port}")]
    InvalidPort {
        /// The rejected port text
        port: String,
    },

    /// Occurs when a colon-separated path segment contains unsafe characters
    #[error("error-atproto-identity-host-7 Invalid path segment: {segment}")]
    InvalidPathSegment {
        /// The rejected path segment
        segment: String,
    },

    /// Occurs when IDNA normalization of the host fails
    #[error("error-atproto-identity-host-8 IDNA normalization failed: {host}")]
    IdnaFailed {
        /// The host that could not be normalized
        host: String,
    },
}

/// Error types produced when an untrusted service endpoint URL fails policy validation.
///
/// Produced by [`crate::validation::validate_service_endpoint`].
#[derive(Debug, Error)]
pub enum EndpointError {
    /// Occurs when the endpoint cannot be parsed as an absolute URL
    #[error(
        "error-atproto-identity-endpoint-1 Endpoint is not an absolute URL: {endpoint} {details}"
    )]
    NotAbsoluteUrl {
        /// The endpoint that was supplied
        endpoint: String,
        /// Details about the parse failure
        details: String,
    },

    /// Occurs when the endpoint uses a scheme other than https
    #[error("error-atproto-identity-endpoint-2 Endpoint scheme must be https: {scheme}")]
    InvalidScheme {
        /// The rejected scheme
        scheme: String,
    },

    /// Occurs when the endpoint URL has no host component
    #[error("error-atproto-identity-endpoint-3 Endpoint is missing a host: {endpoint}")]
    MissingHost {
        /// The endpoint that was supplied
        endpoint: String,
    },

    /// Occurs when the endpoint host is a network address literal
    #[error("error-atproto-identity-endpoint-4 Endpoint host is a network address literal: {host}")]
    IpLiteralHost {
        /// The rejected host
        host: String,
    },

    /// Occurs when the endpoint hostname fails DNS name validation
    #[error("error-atproto-identity-endpoint-5 Endpoint hostname is invalid: {host}")]
    InvalidHostname {
        /// The rejected host
        host: String,
    },

    /// Occurs when the endpoint embeds userinfo credentials
    #[error("error-atproto-identity-endpoint-6 Endpoint contains embedded credentials: {endpoint}")]
    EmbeddedCredentials {
        /// The endpoint that was supplied
        endpoint: String,
    },

    /// Occurs when the endpoint specifies a port other than the https default
    #[error("error-atproto-identity-endpoint-7 Endpoint uses a non-default port: {port}")]
    NonDefaultPort {
        /// The rejected port
        port: u16,
    },

    /// Occurs when the endpoint carries a query string or fragment
    #[error(
        "error-atproto-identity-endpoint-8 Endpoint contains a query string or fragment: {endpoint}"
    )]
    QueryOrFragment {
        /// The endpoint that was supplied
        endpoint: String,
    },
}

/// Error types that can occur when working with configuration
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Occurs when a required environment variable is not set
    #[error("error-atproto-identity-config-1 Required environment variable not found: {name}")]
    MissingEnvironmentVariable {
        /// The name of the missing environment variable
        name: String,
    },

    /// Occurs when parsing an IP address from nameserver configuration fails
    #[error("error-atproto-identity-config-2 Unable to parse nameserver IP: {value}")]
    InvalidNameserverIP {
        /// The invalid IP address value that could not be parsed
        value: String,
    },

    /// Occurs when version information cannot be determined
    #[error(
        "error-atproto-identity-config-3 Version information not available: GIT_HASH or CARGO_PKG_VERSION must be set"
    )]
    VersionNotAvailable,
}

/// Error types that can occur when resolving AT Protocol identities
#[derive(Debug, Error)]
pub enum ResolveError {
    /// Occurs when multiple different DIDs are found via DNS TXT record lookup
    #[error(
        "error-atproto-identity-resolve-1 Multiple DIDs resolved for handle: expected single DID"
    )]
    MultipleDIDsFound,

    /// Occurs when no DIDs are found via either DNS or HTTP resolution methods
    #[error(
        "error-atproto-identity-resolve-2 No DIDs resolved for handle: no resolution methods succeeded"
    )]
    NoDIDsFound,

    /// Occurs when DNS and HTTP resolution return different DIDs for the same handle
    #[error(
        "error-atproto-identity-resolve-3 Conflicting DIDs found for handle: DNS and HTTP resolution returned different results"
    )]
    ConflictingDIDsFound,

    /// Occurs when DNS TXT record lookup fails
    #[cfg(feature = "hickory-dns")]
    #[error("error-atproto-identity-resolve-4 DNS resolution failed: {error:?}")]
    DNSResolutionFailed {
        /// The underlying DNS resolution error
        error: hickory_resolver::ResolveError,
    },

    /// Occurs when DNS TXT record lookup fails (generic version for when hickory-dns is not enabled)
    #[cfg(not(feature = "hickory-dns"))]
    #[error("error-atproto-identity-resolve-4 DNS resolution failed")]
    DNSResolutionFailed,

    /// Occurs when HTTP request to .well-known/atproto-did endpoint fails
    #[error("error-atproto-identity-resolve-5 HTTP resolution failed: {error:?}")]
    HTTPResolutionFailed {
        /// The underlying HTTP error
        error: reqwest::Error,
    },

    /// Occurs when HTTP response from .well-known/atproto-did doesn't start with "did:"
    #[error(
        "error-atproto-identity-resolve-6 Invalid HTTP resolution response: expected DID format"
    )]
    InvalidHTTPResolutionResponse,

    /// Occurs when input cannot be parsed as a valid handle or DID
    #[error("error-atproto-identity-resolve-7 Invalid input format: expected valid handle or DID")]
    InvalidInput,

    /// Occurs when subject resolution results in a handle instead of expected DID
    #[error("error-atproto-identity-resolve-8 Subject resolved to handle instead of DID")]
    SubjectResolvedToHandle,
}

/// Error types that can occur when working with PLC DIDs
#[derive(Debug, Error)]
pub enum PLCDIDError {
    /// Occurs when the HTTP request to the PLC directory fails
    #[error("error-atproto-identity-plc-1 HTTP request failed: {url} {error}")]
    HttpRequestFailed {
        /// The URL that was requested
        url: String,
        /// The underlying HTTP error
        error: reqwest::Error,
    },

    /// Occurs when the DID document cannot be parsed from the PLC directory response
    #[error("error-atproto-identity-plc-2 Failed to parse DID document: {url} {error}")]
    DocumentParseFailed {
        /// The URL that was requested
        url: String,
        /// The underlying parse error
        error: reqwest::Error,
    },

    /// Occurs when a DID string cannot be parsed as a valid did:plc identifier
    #[error("error-atproto-identity-plc-3 Invalid DID format: {details}")]
    InvalidDidFormat {
        /// Details about the format violation
        details: String,
    },

    /// Occurs when base32 decoding fails
    #[error("error-atproto-identity-plc-4 Invalid base32 encoding: {details}")]
    InvalidBase32 {
        /// Details about the decoding failure
        details: String,
    },

    /// Occurs when base64url decoding fails
    #[error("error-atproto-identity-plc-5 Invalid base64url encoding: {details}")]
    InvalidBase64Url {
        /// Details about the decoding failure
        details: String,
    },

    /// Occurs when an operation exceeds the maximum allowed size
    #[error("error-atproto-identity-plc-6 Operation exceeds size limit: {size} bytes (max {max})")]
    OperationTooLarge {
        /// Actual size of the operation in bytes
        size: usize,
        /// Maximum allowed size in bytes
        max: usize,
    },

    /// Occurs when rotation keys fail validation
    #[error("error-atproto-identity-plc-7 Invalid rotation keys: {details}")]
    InvalidRotationKeys {
        /// Details about the validation failure
        details: String,
    },

    /// Occurs when verification methods fail validation
    #[error("error-atproto-identity-plc-8 Invalid verification methods: {details}")]
    InvalidVerificationMethods {
        /// Details about the validation failure
        details: String,
    },

    /// Occurs when a service endpoint fails validation
    #[error("error-atproto-identity-plc-9 Invalid service endpoint: {details}")]
    InvalidService {
        /// Details about the validation failure
        details: String,
    },

    /// Occurs when a field exceeds its maximum entry count
    #[error("error-atproto-identity-plc-10 Too many entries in {field}: max {max}, got {actual}")]
    TooManyEntries {
        /// The field that has too many entries
        field: String,
        /// Maximum allowed count
        max: usize,
        /// Actual count
        actual: usize,
    },

    /// Occurs when a duplicate value is found in a field
    #[error("error-atproto-identity-plc-11 Duplicate entry in {field}: {value}")]
    DuplicateEntry {
        /// The field containing the duplicate
        field: String,
        /// The duplicated value
        value: String,
    },

    /// Occurs when DAG-CBOR encoding fails
    #[error("error-atproto-identity-plc-12 DAG-CBOR encoding failed: {details}")]
    DagCborEncodeFailed {
        /// Details about the encoding failure
        details: String,
    },

    /// Occurs when DAG-CBOR decoding fails
    #[error("error-atproto-identity-plc-13 DAG-CBOR decoding failed: {details}")]
    DagCborDecodeFailed {
        /// Details about the decoding failure
        details: String,
    },

    /// Occurs when an operation's signature cannot be verified
    #[error("error-atproto-identity-plc-14 Signature verification failed")]
    SignatureVerificationFailed,

    /// Occurs when a CID is invalid or cannot be computed
    #[error("error-atproto-identity-plc-15 Invalid CID: {details}")]
    InvalidCid {
        /// Details about the CID error
        details: String,
    },

    /// Occurs when an operation has an unrecognized type
    #[error("error-atproto-identity-plc-16 Invalid operation type: {details}")]
    InvalidOperationType {
        /// Details about the invalid operation type
        details: String,
    },

    /// Occurs when a required field is missing from an operation
    #[error("error-atproto-identity-plc-17 Missing required field: {field}")]
    MissingField {
        /// The name of the missing field
        field: String,
    },

    /// Occurs when operation chain validation fails
    #[error("error-atproto-identity-plc-18 Chain validation failed: {details}")]
    ChainValidationFailed {
        /// Details about the validation failure
        details: String,
    },

    /// Occurs when an operation chain is empty
    #[error("error-atproto-identity-plc-19 Empty operation chain")]
    EmptyChain,

    /// Occurs when the first operation in a chain is not a genesis operation
    #[error("error-atproto-identity-plc-20 First operation must be genesis")]
    FirstOperationNotGenesis,

    /// Occurs when an operation references an invalid previous operation
    #[error("error-atproto-identity-plc-21 Invalid prev reference: {details}")]
    InvalidPrev {
        /// Details about the invalid reference
        details: String,
    },

    /// Occurs when fork resolution fails
    #[error("error-atproto-identity-plc-22 Fork resolution error: {details}")]
    ForkResolutionError {
        /// Details about the fork resolution failure
        details: String,
    },

    /// Occurs when an also-known-as URI is invalid
    #[error("error-atproto-identity-plc-23 Invalid also-known-as URI: {details}")]
    InvalidAlsoKnownAs {
        /// Details about the invalid URI
        details: String,
    },

    /// Occurs when a timestamp is invalid
    #[error("error-atproto-identity-plc-24 Invalid timestamp: {details}")]
    InvalidTimestamp {
        /// Details about the invalid timestamp
        details: String,
    },

    /// Occurs when submitting an operation to the PLC directory fails
    #[error("error-atproto-identity-plc-25 Submission failed: {url} status {status}: {body}")]
    SubmissionFailed {
        /// The URL that was requested
        url: String,
        /// The HTTP status code
        status: u16,
        /// The response body
        body: String,
    },

    /// Occurs when fetching the audit log from the PLC directory fails
    #[error("error-atproto-identity-plc-26 Audit log fetch failed: {url} {error}")]
    AuditLogFetchFailed {
        /// The URL that was requested
        url: String,
        /// The underlying HTTP error
        error: reqwest::Error,
    },

    /// Occurs when the audit log response cannot be parsed
    #[error("error-atproto-identity-plc-27 Audit log parse failed: {url} {error}")]
    AuditLogParseFailed {
        /// The URL that was requested
        url: String,
        /// The underlying parse error
        error: reqwest::Error,
    },
}

/// Error types that can occur when working with cryptographic keys
#[derive(Debug, Error)]
pub enum KeyError {
    /// Occurs when multibase decoding of a key fails
    #[error("error-atproto-identity-key-1 Error decoding key: {error:?}")]
    DecodeError {
        /// The underlying multibase decode error
        error: multibase::Error,
    },

    /// Occurs when ECDSA signature parsing fails
    #[error("error-atproto-identity-key-2 Signature parsing failed: {error:?}")]
    SignatureError {
        /// The underlying signature parsing error
        error: ecdsa::signature::Error,
    },

    /// Occurs when P-256 key operations fail
    #[error("error-atproto-identity-key-3 P-256 key operation failed: {error:?}")]
    P256Error {
        /// The underlying P-256 key error
        error: p256::ecdsa::Error,
    },

    /// Occurs when P-384 key operations fail
    #[error("error-atproto-identity-key-4 P-384 key operation failed: {error:?}")]
    P384Error {
        /// The underlying P-384 key error
        error: p384::ecdsa::Error,
    },

    /// Occurs when K-256 key operations fail
    #[error("error-atproto-identity-key-5 K-256 key operation failed: {error:?}")]
    K256Error {
        /// The underlying K-256 key error
        error: k256::ecdsa::Error,
    },

    /// Occurs when ECDSA cryptographic operations fail
    #[error("error-atproto-identity-key-6 ECDSA operation failed: {error:?}")]
    ECDSAError {
        /// The underlying ECDSA error
        error: ecdsa::Error,
    },

    /// Occurs when secret key parsing or operations fail
    #[error("error-atproto-identity-key-7 Secret key operation failed: {error:?}")]
    SecretKeyError {
        /// The underlying secret key error
        error: ecdsa::elliptic_curve::Error,
    },

    /// Occurs when attempting to sign content with a public key instead of a private key
    #[error("error-atproto-identity-key-8 Private key required for signature")]
    PrivateKeyRequiredForSignature,

    /// Occurs when attempting to generate a public key directly
    #[error(
        "error-atproto-identity-key-9 Public key generation not supported: generate private key instead"
    )]
    PublicKeyGenerationNotSupported,

    /// Occurs when the decoded key data is too short to identify the key type
    #[error("error-atproto-identity-key-10 Unidentified key type: key data too short")]
    UnidentifiedKeyType,

    /// Occurs when the multibase key type prefix is not recognized
    #[error("error-atproto-identity-key-11 Invalid multibase key type: {prefix:?}")]
    InvalidMultibaseKeyType {
        /// The unrecognized key type prefix
        prefix: Vec<u8>,
    },

    /// Occurs when JWK format conversion fails for supported key types
    #[error("error-atproto-identity-key-12 JWK format conversion failed: {error}")]
    JWKConversionFailed {
        /// The underlying conversion error
        error: String,
    },

    /// Occurs when Ed25519 key operations fail
    #[error("error-atproto-identity-key-13 Ed25519 key operation failed: {error}")]
    Ed25519Error {
        /// Description of the Ed25519 error
        error: String,
    },
}

/// Error types that can occur when working with WebVH DIDs
#[derive(Debug, Error)]
pub enum WebVHDIDError {
    /// Occurs when the DID is missing the 'did:webvh:' prefix
    #[error("error-atproto-identity-webvh-1 Invalid DID format: missing 'did:webvh:' prefix")]
    InvalidDIDPrefix,

    /// Occurs when the DID is missing a SCID component
    #[error("error-atproto-identity-webvh-2 Invalid DID format: missing SCID component")]
    MissingSCID,

    /// Occurs when the DID is missing a hostname component
    #[error("error-atproto-identity-webvh-3 Invalid DID format: missing hostname component")]
    MissingHostname,

    /// Occurs when the HTTP request to fetch the DID log fails
    #[error("error-atproto-identity-webvh-4 HTTP request failed: {url} {error}")]
    HttpRequestFailed {
        /// The URL that was requested
        url: String,
        /// The underlying HTTP error
        error: reqwest::Error,
    },

    /// Occurs when a log entry cannot be parsed from the JSONL response
    #[error("error-atproto-identity-webvh-5 Failed to parse log entry at line {line}: {details}")]
    LogEntryParseFailed {
        /// The line number (1-indexed) that failed to parse
        line: usize,
        /// Details about the parse failure
        details: String,
    },

    /// Occurs when the DID log file is empty
    #[error("error-atproto-identity-webvh-6 Empty log file")]
    EmptyLog,

    /// Occurs when a version ID is invalid or has incorrect format
    #[error("error-atproto-identity-webvh-7 Invalid version ID at entry {entry}: {details}")]
    InvalidVersionId {
        /// The entry number (1-indexed) with the invalid version ID
        entry: usize,
        /// Details about the validation failure
        details: String,
    },

    /// Occurs when version times are not monotonically increasing
    #[error(
        "error-atproto-identity-webvh-8 Version time not monotonically increasing at entry {entry}"
    )]
    VersionTimeNotMonotonic {
        /// The entry number (1-indexed) with the non-monotonic timestamp
        entry: usize,
    },

    /// Occurs when the SCID does not match the computed value from the genesis entry
    #[error("error-atproto-identity-webvh-9 SCID verification failed on genesis entry")]
    SCIDVerificationFailed,

    /// Occurs when an entry's hash does not match the expected value in the version ID
    #[error("error-atproto-identity-webvh-10 Entry hash verification failed at entry {entry}")]
    EntryHashVerificationFailed {
        /// The entry number (1-indexed) with the hash mismatch
        entry: usize,
    },

    /// Occurs when a Data Integrity proof cannot be verified
    #[error(
        "error-atproto-identity-webvh-11 Proof verification failed at entry {entry}: {details}"
    )]
    ProofVerificationFailed {
        /// The entry number (1-indexed) with the failed proof
        entry: usize,
        /// Details about the verification failure
        details: String,
    },

    /// Occurs when pre-rotation key hashes do not match
    #[error("error-atproto-identity-webvh-12 Pre-rotation key hash mismatch at entry {entry}")]
    PreRotationKeyMismatch {
        /// The entry number (1-indexed) with the key mismatch
        entry: usize,
    },

    /// Occurs when log entry parameters are invalid
    #[error("error-atproto-identity-webvh-13 Invalid parameters at entry {entry}: {details}")]
    InvalidParameters {
        /// The entry number (1-indexed) with the invalid parameters
        entry: usize,
        /// Details about the validation failure
        details: String,
    },

    /// Occurs when witness verification fails
    #[error(
        "error-atproto-identity-webvh-14 Witness verification failed at entry {entry}: {details}"
    )]
    WitnessVerificationFailed {
        /// The entry number (1-indexed) with the failed witness verification
        entry: usize,
        /// Details about the verification failure
        details: String,
    },

    /// Occurs when the DID document cannot be extracted from the log state
    #[error("error-atproto-identity-webvh-15 DID document extraction failed: {details}")]
    DocumentExtractionFailed {
        /// Details about the extraction failure
        details: String,
    },

    /// Occurs when the SCID format is invalid
    #[error("error-atproto-identity-webvh-16 Invalid SCID format: {details}")]
    InvalidSCIDFormat {
        /// Details about the format violation
        details: String,
    },

    /// Occurs when the resolved DID has been deactivated
    #[error("error-atproto-identity-webvh-17 Deactivated DID: {did}")]
    DeactivatedDID {
        /// The deactivated DID
        did: String,
    },

    /// Occurs when a requested version is not found in the log
    #[error("error-atproto-identity-webvh-18 Version not found: {details}")]
    VersionNotFound {
        /// Details about the lookup that failed
        details: String,
    },

    /// Occurs when a version time is in the future
    #[error(
        "error-atproto-identity-webvh-19 Version time is in the future at entry {entry}: {version_time}"
    )]
    VersionTimeInFuture {
        /// The entry number (1-indexed) with the future timestamp
        entry: usize,
        /// The future timestamp value
        version_time: String,
    },

    /// Occurs when the DIDDoc id does not match the DID
    #[error(
        "error-atproto-identity-webvh-20 DIDDoc id mismatch at entry {entry}: expected '{expected}', found '{found}'"
    )]
    DIDDocIdMismatch {
        /// The entry number (1-indexed) with the mismatch
        entry: usize,
        /// The expected DID
        expected: String,
        /// The actual id found in the DIDDoc
        found: String,
    },

    /// Occurs when the hash algorithm in the SCID is not supported
    #[error("error-atproto-identity-webvh-21 Unsupported hash algorithm in SCID: {details}")]
    UnsupportedHashAlgorithm {
        /// Details about the unsupported algorithm
        details: String,
    },

    /// Occurs when an unknown parameter is found in a log entry
    #[error("error-atproto-identity-webvh-22 Unknown parameter at entry {entry}: {parameter}")]
    UnknownParameter {
        /// The entry number (1-indexed) with the unknown parameter
        entry: usize,
        /// The unknown parameter name
        parameter: String,
    },

    /// Occurs when hostname normalization fails
    #[error("error-atproto-identity-webvh-23 Hostname normalization failed: {details}")]
    HostnameNormalizationFailed {
        /// Details about the normalization failure
        details: String,
    },

    /// Occurs when genesis document creation fails
    #[error("error-atproto-identity-webvh-24 Genesis creation failed: {details}")]
    GenesisCreationFailed {
        /// Details about the creation failure
        details: String,
    },

    /// Occurs when update entry creation fails
    #[error("error-atproto-identity-webvh-25 Update creation failed: {details}")]
    UpdateCreationFailed {
        /// Details about the creation failure
        details: String,
    },

    /// Occurs when signing a log entry fails
    #[error("error-atproto-identity-webvh-26 Signing failed: {details}")]
    SigningFailed {
        /// Details about the signing failure
        details: String,
    },

    /// Occurs when the did:webvh target host or path fails validation
    #[error("error-atproto-identity-webvh-27 Rejected did:webvh target: {source}")]
    InvalidHost {
        /// The underlying host-extraction failure
        #[from]
        source: DidHostError,
    },
}

/// Resolution error codes as defined by the did:webvh specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionError {
    /// Error code: "notFound" or "invalidDid".
    pub error: ResolutionErrorCode,
    /// Optional RFC 9457 problem details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem_details: Option<ProblemDetails>,
}

/// Resolution error code per the did:webvh specification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResolutionErrorCode {
    /// The DID was not found.
    #[serde(rename = "notFound")]
    NotFound,
    /// The DID is invalid or failed verification.
    #[serde(rename = "invalidDid")]
    InvalidDid,
}

/// RFC 9457 Problem Details structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemDetails {
    /// Problem type URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// Short human-readable summary.
    pub title: String,
    /// Detailed explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl WebVHDIDError {
    /// Converts this error to a spec-compliant resolution error.
    pub fn to_resolution_error(&self) -> ResolutionError {
        match self {
            WebVHDIDError::HttpRequestFailed { .. } | WebVHDIDError::EmptyLog => ResolutionError {
                error: ResolutionErrorCode::NotFound,
                problem_details: Some(ProblemDetails {
                    r#type: None,
                    title: "DID not found".to_string(),
                    detail: Some(self.to_string()),
                }),
            },
            WebVHDIDError::InvalidDIDPrefix
            | WebVHDIDError::MissingSCID
            | WebVHDIDError::MissingHostname
            | WebVHDIDError::InvalidHost { .. }
            | WebVHDIDError::InvalidSCIDFormat { .. } => ResolutionError {
                error: ResolutionErrorCode::InvalidDid,
                problem_details: Some(ProblemDetails {
                    r#type: None,
                    title: "Invalid DID format".to_string(),
                    detail: Some(self.to_string()),
                }),
            },
            _ => ResolutionError {
                error: ResolutionErrorCode::InvalidDid,
                problem_details: Some(ProblemDetails {
                    r#type: None,
                    title: "DID verification failed".to_string(),
                    detail: Some(self.to_string()),
                }),
            },
        }
    }
}

/// Error types that can occur when working with storage operations
#[derive(Debug, Error)]
pub enum StorageError {
    /// Occurs when cache lock acquisition fails during document retrieval operations
    #[error(
        "error-atproto-identity-storage-1 Cache lock acquisition failed for get operation: {details}"
    )]
    CacheLockFailedGet {
        /// Details about the lock failure
        details: String,
    },

    /// Occurs when cache lock acquisition fails during document storage operations
    #[error(
        "error-atproto-identity-storage-2 Cache lock acquisition failed for store operation: {details}"
    )]
    CacheLockFailedStore {
        /// Details about the lock failure
        details: String,
    },

    /// Occurs when cache lock acquisition fails during document deletion operations
    #[error(
        "error-atproto-identity-storage-3 Cache lock acquisition failed for delete operation: {details}"
    )]
    CacheLockFailedDelete {
        /// Details about the lock failure
        details: String,
    },
}
