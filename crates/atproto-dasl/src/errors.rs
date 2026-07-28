//! Structured error types for DASL operations.
//!
//! All errors follow the project convention of prefixed error codes
//! with descriptive messages: `error-atproto-dasl-{domain}-{number}`

use thiserror::Error;

/// Errors that can occur during DAG-CBOR encoding
#[derive(Debug, Error)]
pub enum EncodeError {
    /// I/O error during writing
    #[error("error-atproto-dasl-encode-1 I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid float value (NaN or Infinity)
    #[error("error-atproto-dasl-encode-2 Invalid float value: {reason}")]
    InvalidFloat {
        /// The reason the float is invalid
        reason: String,
    },

    /// Indefinite length not supported in DAG-CBOR
    #[error("error-atproto-dasl-encode-3 Indefinite length encoding not supported")]
    IndefiniteLengthNotSupported,

    /// Map key was expected but not provided
    #[error("error-atproto-dasl-encode-4 Map key missing before value")]
    MapKeyMissing,

    /// Serialization error from serde
    #[error("error-atproto-dasl-encode-5 Serialization error: {0}")]
    Serialization(String),

    /// Integer overflow during encoding
    #[error("error-atproto-dasl-encode-6 Integer overflow: value too large")]
    IntegerOverflow,

    /// Maximum nesting depth exceeded during encoding
    #[error("error-atproto-dasl-encode-7 Depth limit exceeded: max {max}")]
    DepthLimitExceeded {
        /// The maximum allowed nesting depth.
        max: usize,
    },

    /// Output size exceeded during encoding
    #[error("error-atproto-dasl-encode-8 Output too large: max {max} bytes")]
    OutputTooLarge {
        /// The maximum allowed output size in bytes.
        max: usize,
    },

    /// A value has no representation in the AT Protocol data model.
    #[error("error-atproto-dasl-encode-9 Value not representable: {reason}")]
    InvalidValue {
        /// Which rule the value broke.
        reason: String,
    },
}

impl serde::ser::Error for EncodeError {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        EncodeError::Serialization(msg.to_string())
    }
}

/// Errors that can occur during DAG-CBOR decoding
#[derive(Debug, Error)]
pub enum DecodeError {
    /// I/O error during reading
    #[error("error-atproto-dasl-decode-1 I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Unexpected end of input
    #[error("error-atproto-dasl-decode-2 Unexpected end of input")]
    UnexpectedEof,

    /// Invalid CBOR major type
    #[error("error-atproto-dasl-decode-3 Invalid CBOR structure: {reason}")]
    InvalidCbor {
        /// The reason the CBOR is invalid
        reason: String,
    },

    /// Non-canonical encoding in strict mode
    #[error(
        "error-atproto-dasl-decode-4 Non-canonical encoding: type {major_type}, info {additional_info}, value {value}"
    )]
    NonCanonicalEncoding {
        /// The major type of the non-canonical encoding
        major_type: u8,
        /// The additional info byte
        additional_info: u8,
        /// The decoded value
        value: u64,
    },

    /// Unsupported CBOR tag (only tag 42 allowed)
    #[error("error-atproto-dasl-decode-5 Unsupported CBOR tag: {tag}")]
    UnsupportedTag {
        /// The unsupported tag number
        tag: u64,
    },

    /// Map key is not a string (DAG-CBOR requirement)
    #[error("error-atproto-dasl-decode-6 Map key must be a string")]
    MapKeyNotString,

    /// Invalid CID encoding
    #[error("error-atproto-dasl-decode-7 Invalid CID: {reason}")]
    InvalidCid {
        /// The reason the CID is invalid
        reason: String,
    },

    /// CID tag not followed by byte string
    #[error("error-atproto-dasl-decode-8 CID tag must be followed by byte string")]
    InvalidCidContent,

    /// Invalid float value (NaN or Infinity)
    #[error("error-atproto-dasl-decode-9 Invalid float value: NaN and Infinity not allowed")]
    InvalidFloat,

    /// Invalid simple value (only false, true, null allowed)
    #[error("error-atproto-dasl-decode-10 Unsupported simple value: {value}")]
    UnsupportedSimpleValue {
        /// The unsupported simple value
        value: u8,
    },

    /// Indefinite length not supported
    #[error("error-atproto-dasl-decode-11 Indefinite length encoding not supported")]
    IndefiniteLengthNotSupported,

    /// Type mismatch during deserialization
    #[error("error-atproto-dasl-decode-12 Type mismatch: expected {expected}, found {found}")]
    TypeMismatch {
        /// The expected type
        expected: &'static str,
        /// The found type
        found: String,
    },

    /// Maximum nesting depth exceeded
    #[error("error-atproto-dasl-decode-13 Maximum nesting depth exceeded: {depth} > {max}")]
    MaxDepthExceeded {
        /// The current depth
        depth: usize,
        /// The maximum allowed depth
        max: usize,
    },

    /// Allocation limit exceeded
    #[error("error-atproto-dasl-decode-14 Allocation limit exceeded: {size} > {max}")]
    AllocationExceeded {
        /// The requested allocation size
        size: usize,
        /// The maximum allowed size
        max: usize,
    },

    /// Invalid UTF-8 in text string
    #[error("error-atproto-dasl-decode-15 Invalid UTF-8: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    /// Non-canonical map key ordering in strict mode
    #[error("error-atproto-dasl-decode-16 Map keys not in canonical order")]
    MapKeysNotSorted,

    /// Reserved additional info value (28-30)
    #[error("error-atproto-dasl-decode-17 Reserved additional info value: {value}")]
    ReservedAdditionalInfo {
        /// The reserved value
        value: u8,
    },

    /// Deserialization error from serde
    #[error("error-atproto-dasl-decode-18 Deserialization error: {0}")]
    Deserialization(String),

    /// Trailing data after top-level object
    #[error("error-atproto-dasl-decode-19 Trailing data after top-level object")]
    TrailingData,

    /// Non-canonical float encoding (not 64-bit)
    #[error("error-atproto-dasl-decode-20 Non-canonical float encoding: expected 64-bit double")]
    NonCanonicalFloat,

    /// Duplicate map key detected
    #[error("error-atproto-dasl-decode-21 Duplicate map key")]
    DuplicateMapKey,

    /// Float values not allowed (no_floats config)
    #[error("error-atproto-dasl-decode-22 Float values not allowed")]
    FloatsNotAllowed,

    /// Integer out of i64 range (int64_range_only config)
    #[error("error-atproto-dasl-decode-23 Integer {value} outside i64 range")]
    IntegerOutOfRange {
        /// The value that was out of range
        value: String,
    },

    /// Array exceeds maximum element count
    #[error("error-atproto-dasl-decode-24 Array too large: {count} elements (max {max})")]
    ArrayTooLarge {
        /// Actual array length
        count: usize,
        /// Maximum allowed length
        max: usize,
    },

    /// Map exceeds maximum entry count
    #[error("error-atproto-dasl-decode-25 Map too large: {count} entries (max {max})")]
    MapTooLarge {
        /// Actual map size
        count: usize,
        /// Maximum allowed size
        max: usize,
    },

    /// Declared collection length cannot fit in the bytes that remain.
    #[error(
        "error-atproto-dasl-decode-26 Collection length exceeds input: {count} items need at least {needed} bytes, {remaining} remain"
    )]
    CollectionLengthExceedsInput {
        /// Declared element or entry count from the wire.
        count: usize,
        /// Minimum bytes required to encode that many items.
        needed: u64,
        /// Bytes left in the input.
        remaining: u64,
    },

    /// Declared byte- or text-string length exceeds the bytes that remain.
    #[error(
        "error-atproto-dasl-decode-27 String length exceeds input: {length} bytes declared, {remaining} remain"
    )]
    StringLengthExceedsInput {
        /// Declared string length from the wire.
        length: u64,
        /// Bytes left in the input.
        remaining: u64,
    },

    /// A buffer reservation failed (out of memory or capacity overflow).
    #[error(
        "error-atproto-dasl-decode-28 Allocation failed: {requested} bytes requested: {reason}"
    )]
    AllocationFailed {
        /// Bytes that could not be reserved.
        requested: usize,
        /// Allocator failure description.
        reason: String,
    },
}

impl serde::de::Error for DecodeError {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        DecodeError::Deserialization(msg.to_string())
    }
}

/// Errors during varint encoding/decoding.
#[derive(Debug, Error)]
pub enum VarintError {
    /// Varint exceeds maximum supported size (9 bytes for u64).
    #[error("error-atproto-dasl-varint-1 Varint overflow: exceeded maximum size")]
    Overflow,

    /// Unexpected end of input while reading varint.
    #[error("error-atproto-dasl-varint-2 Unexpected end of input")]
    UnexpectedEof,

    /// Non-minimal varint encoding detected.
    #[error("error-atproto-dasl-varint-3 Non-minimal encoding detected")]
    NonMinimal,
}

/// Errors during CAR file operations.
#[derive(Debug, Error)]
pub enum CarError {
    /// CAR header is missing or malformed.
    #[error("error-atproto-dasl-car-1 Invalid CAR header: {reason}")]
    InvalidHeader {
        /// Description of why the header is invalid.
        reason: String,
    },

    /// CAR version is not supported (only v1 supported).
    #[error("error-atproto-dasl-car-2 Unsupported CAR version: {version}")]
    UnsupportedVersion {
        /// The unsupported version number.
        version: u64,
    },

    /// Block CID does not match computed CID.
    #[error("error-atproto-dasl-car-3 CID mismatch: expected {expected}, got {actual}")]
    CidMismatch {
        /// The expected CID from the block header.
        expected: String,
        /// The actual CID computed from the block data.
        actual: String,
    },

    /// Block data is malformed or truncated.
    #[error("error-atproto-dasl-car-4 Invalid block data: {reason}")]
    InvalidBlock {
        /// Description of why the block is invalid.
        reason: String,
    },

    /// DAG-CBOR encoding error.
    #[error("error-atproto-dasl-car-5 DAG-CBOR encode error: {0}")]
    DagCborEncode(#[from] EncodeError),

    /// DAG-CBOR decoding error.
    #[error("error-atproto-dasl-car-6 DAG-CBOR decode error: {0}")]
    DagCborDecode(DecodeError),

    /// I/O error during CAR operations.
    #[error("error-atproto-dasl-car-7 I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Varint encoding/decoding error.
    #[error("error-atproto-dasl-car-8 Varint error: {0}")]
    Varint(#[from] VarintError),

    /// CID parsing error.
    #[error("error-atproto-dasl-car-9 Invalid CID: {reason}")]
    InvalidCid {
        /// Description of why the CID is invalid.
        reason: String,
    },

    /// Roots array is empty (at least one root required).
    #[error("error-atproto-dasl-car-10 CAR file must have at least one root CID")]
    NoRoots,

    /// CAR file exceeds maximum allowed size.
    #[error("error-atproto-dasl-car-11 CAR file too large: {size} bytes (max {max})")]
    FileTooLarge {
        /// Actual file size in bytes.
        size: u64,
        /// Maximum allowed size in bytes.
        max: u64,
    },

    /// Storage operation failed.
    #[error("error-atproto-dasl-car-12 Storage error: {0}")]
    Storage(#[from] StorageError),

    /// Block frame or block data exceeds the configured block size limit.
    #[error("error-atproto-dasl-car-13 Block too large: {size} bytes (max {max})")]
    BlockTooLarge {
        /// Declared or actual size in bytes.
        size: u64,
        /// Maximum allowed size in bytes.
        max: u64,
    },

    /// Memory allocation for a block failed.
    #[error("error-atproto-dasl-car-14 Allocation failed for {requested} bytes: {reason}")]
    AllocationFailed {
        /// Bytes the allocation attempted to reserve.
        requested: usize,
        /// Allocator failure description.
        reason: String,
    },
}

impl From<DecodeError> for CarError {
    fn from(err: DecodeError) -> Self {
        CarError::DagCborDecode(err)
    }
}

/// Errors during storage operations.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Block not found in storage.
    #[error("error-atproto-dasl-storage-1 Block not found: {cid}")]
    BlockNotFound {
        /// CID of the missing block.
        cid: String,
    },

    /// Storage capacity exceeded.
    #[error("error-atproto-dasl-storage-2 Storage limit exceeded: {limit} bytes")]
    CapacityExceeded {
        /// The storage limit that was exceeded.
        limit: usize,
    },

    /// I/O error during storage operations.
    #[error("error-atproto-dasl-storage-3 Storage I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Block size exceeds maximum allowed.
    #[error("error-atproto-dasl-storage-4 Block too large: {size} bytes (max {max})")]
    BlockTooLarge {
        /// Actual block size in bytes.
        size: usize,
        /// Maximum allowed size in bytes.
        max: usize,
    },

    /// Maximum block count exceeded.
    #[error("error-atproto-dasl-storage-5 Block count exceeded: {count} (max {max})")]
    BlockCountExceeded {
        /// Actual block count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },

    /// Depth limit exceeded.
    #[error("error-atproto-dasl-storage-6 Depth exceeded: {depth} (max {max})")]
    DepthExceeded {
        /// Actual depth encountered.
        depth: usize,
        /// Maximum allowed depth.
        max: usize,
    },
}

/// Errors during DASL CID construction.
#[derive(Debug, Error)]
pub enum DaslCidError {
    /// CID version is not CIDv1.
    #[error("error-atproto-dasl-cid-1 DASL requires CIDv1, got CIDv0")]
    NotCidV1,

    /// Codec is not allowed in DASL.
    #[error(
        "error-atproto-dasl-cid-2 Codec 0x{codec:x} not allowed in DASL (must be raw 0x55 or dag-cbor 0x71)"
    )]
    InvalidCodec {
        /// The codec value that was rejected.
        codec: u64,
    },

    /// Hash algorithm is not allowed in DASL.
    #[error(
        "error-atproto-dasl-cid-3 Hash 0x{hash:x} not allowed in DASL (must be SHA-256 0x12 or BLAKE3 0x1e)"
    )]
    InvalidHash {
        /// The hash algorithm code that was rejected.
        hash: u64,
    },

    /// Digest length is not 32 bytes.
    #[error("error-atproto-dasl-cid-4 Digest length {len} != 32")]
    InvalidDigestLength {
        /// The actual digest length.
        len: usize,
    },

    /// CID parsing failed.
    #[error("error-atproto-dasl-cid-5 Invalid CID: {reason}")]
    InvalidCid {
        /// Description of the parsing failure.
        reason: String,
    },
}

/// Errors during MASL operations.
#[derive(Debug, Error)]
pub enum MaslError {
    /// Document is missing required fields.
    #[error("error-atproto-dasl-masl-1 Missing required field: {field}")]
    MissingField {
        /// The missing field name.
        field: String,
    },

    /// Invalid path format.
    #[error("error-atproto-dasl-masl-2 Invalid path: {reason}")]
    InvalidPath {
        /// Description of why the path is invalid.
        reason: String,
    },

    /// Invalid resource configuration.
    #[error("error-atproto-dasl-masl-3 Invalid resource: {reason}")]
    InvalidResource {
        /// Description of what's wrong with the resource.
        reason: String,
    },

    /// Bundle and single mode conflict.
    #[error("error-atproto-dasl-masl-4 Document mode conflict: {reason}")]
    ModeConflict {
        /// Description of the conflict.
        reason: String,
    },

    /// Invalid CAR format reference.
    #[error("error-atproto-dasl-masl-5 Invalid CAR format: {reason}")]
    InvalidCarFormat {
        /// Description of the issue.
        reason: String,
    },

    /// DAG-CBOR encoding/decoding error.
    #[error("error-atproto-dasl-masl-6 DAG-CBOR error: {0}")]
    DagCbor(String),

    /// Invalid `$type` field value.
    #[error("error-atproto-dasl-masl-7 Invalid type: {reason}")]
    InvalidType {
        /// Description of the invalid type.
        reason: String,
    },

    /// Reference to non-existent resource path.
    #[error(
        "error-atproto-dasl-masl-8 Invalid reference: field '{field}' references non-existent path '{path}'"
    )]
    InvalidReference {
        /// The referenced path that doesn't exist.
        path: String,
        /// The field containing the reference.
        field: String,
    },
}

/// Errors during RASL operations.
#[derive(Debug, Error)]
pub enum RaslError {
    /// Invalid RASL URL scheme.
    #[error("error-atproto-dasl-rasl-1 Invalid scheme: expected 'rasl', got '{scheme}'")]
    InvalidScheme {
        /// The invalid scheme.
        scheme: String,
    },

    /// Missing CID in RASL URL.
    #[error("error-atproto-dasl-rasl-2 Missing CID in RASL URL")]
    MissingCid,

    /// Invalid CID in RASL URL.
    #[error("error-atproto-dasl-rasl-3 Invalid CID: {reason}")]
    InvalidCid {
        /// Description of why the CID is invalid.
        reason: String,
    },

    /// Invalid hint in RASL URL.
    #[error("error-atproto-dasl-rasl-4 Invalid hint: {reason}")]
    InvalidHint {
        /// Description of why the hint is invalid.
        reason: String,
    },

    /// URL parsing failed.
    #[error("error-atproto-dasl-rasl-5 URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    /// Credentials not allowed in RASL URLs.
    #[error("error-atproto-dasl-rasl-6 Credentials not allowed in RASL URLs")]
    CredentialsNotAllowed,

    /// Fragments not allowed in RASL URLs.
    #[error("error-atproto-dasl-rasl-7 Fragments not allowed in RASL URLs")]
    FragmentNotAllowed,

    /// All retrieval hints failed.
    #[error("error-atproto-dasl-rasl-8 All retrieval hints failed")]
    AllHintsFailed,

    /// CID verification failed after streaming.
    #[error("error-atproto-dasl-rasl-9 CID verification failed: {reason}")]
    CidVerification {
        /// Description of the verification failure.
        reason: String,
    },

    /// HTTP request failed.
    #[cfg(feature = "reqwest")]
    #[error("error-atproto-dasl-rasl-10 HTTP request failed for {url}: {reason}")]
    HttpRequest {
        /// The URL that failed.
        url: String,
        /// Description of the failure.
        reason: String,
    },

    /// I/O error during RASL operations.
    #[error("error-atproto-dasl-rasl-11 I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// No hints provided for fetch.
    #[error("error-atproto-dasl-rasl-12 No hints provided for fetch")]
    NoHints,

    /// Directory handler initialization failed.
    #[error("error-atproto-dasl-rasl-13 Directory handler error: {reason}")]
    DirectoryError {
        /// Description of the error.
        reason: String,
    },
}

/// Errors that can occur during Web Tile validation.
#[derive(Debug, Error)]
pub enum TilesError {
    /// The MASL document failed base validation.
    #[error("error-atproto-dasl-tiles-1 MASL validation failed: {reason}")]
    MaslValidation {
        /// Description of the MASL validation failure.
        reason: String,
    },

    /// The document is not in bundle mode.
    #[error("error-atproto-dasl-tiles-2 Tile manifest must be in bundle mode")]
    NotBundleMode,

    /// The tile manifest is missing a name.
    #[error("error-atproto-dasl-tiles-3 Tile manifest must have a name")]
    MissingName,

    /// The tile name exceeds the maximum length.
    #[error("error-atproto-dasl-tiles-4 Tile name too long: {chars} chars (max {max})")]
    NameTooLong {
        /// Actual character count.
        chars: usize,
        /// Maximum allowed characters.
        max: usize,
    },

    /// The tile manifest is missing a root "/" resource.
    #[error("error-atproto-dasl-tiles-5 Tile manifest must have a '/' root resource")]
    MissingRootResource,
}
