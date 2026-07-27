//! Configuration for DAG-CBOR encoding and decoding.
//!
//! Provides options for encode-time constraints (depth and output size limits)
//! and decode-time strict/non-strict mode settings.

/// Time encoding mode for DAG-CBOR serialization.
///
/// Controls how time values (e.g., `chrono::DateTime`) are encoded in DRISL.
/// This configuration is advisory — the actual encoding depends on how the
/// time type implements `serde::Serialize`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum TimeMode {
    /// Encode as RFC 3339 string with nanosecond precision (default).
    #[default]
    Rfc3339Nano,
    /// Encode as Unix timestamp (seconds since epoch) as an integer.
    Unix,
    /// Encode as Unix timestamp in microseconds as an integer.
    UnixMicro,
    /// Encode as Unix timestamp in nanoseconds as an integer.
    UnixNano,
    /// Reject time values during encoding.
    Reject,
}

/// Configuration for DAG-CBOR encoding.
///
/// Controls encode-time constraints such as maximum nesting depth
/// and maximum output size to prevent resource exhaustion.
#[derive(Clone, Debug)]
pub struct EncodeConfig {
    /// Maximum nesting depth for encoding.
    /// Prevents stack overflow on deeply recursive structures.
    /// Default: 256.
    pub max_depth: usize,

    /// Maximum output size in bytes.
    /// Encoding will fail if the output exceeds this limit.
    /// Default: 64MB (67_108_864).
    pub max_output_size: usize,

    /// Time encoding mode.
    /// Controls how time values are serialized in DAG-CBOR.
    /// Default: `TimeMode::Rfc3339Nano`.
    pub time_mode: TimeMode,
}

impl Default for EncodeConfig {
    fn default() -> Self {
        Self {
            max_depth: 256,
            max_output_size: 64 * 1024 * 1024, // 64MB
            time_mode: TimeMode::default(),
        }
    }
}

impl EncodeConfig {
    /// Create a new encoding configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum nesting depth.
    pub fn with_max_depth(mut self, max: usize) -> Self {
        self.max_depth = max;
        self
    }

    /// Set the maximum output size in bytes.
    pub fn with_max_output_size(mut self, max: usize) -> Self {
        self.max_output_size = max;
        self
    }

    /// Set the time encoding mode.
    pub fn with_time_mode(mut self, mode: TimeMode) -> Self {
        self.time_mode = mode;
        self
    }
}

/// Default cap on elements in a single decoded array (2^24).
///
/// Reaching it requires at least 16 MB of input, five orders of magnitude
/// above any AT Protocol collection (MST node entries, `applyWrites` batches,
/// facets, firehose ops).
pub const DEFAULT_MAX_ARRAY_ELEMENTS: usize = 16_777_216;

/// Default cap on entries in a single decoded map (2^24).
///
/// Reaching it requires at least 32 MB of input, since each entry needs a
/// key byte and a value byte.
pub const DEFAULT_MAX_MAP_ENTRIES: usize = 16_777_216;

/// Configuration for DAG-CBOR decoding
#[derive(Debug, Clone)]
pub struct DecodeConfig {
    /// Strict mode enforces all DAG-CBOR requirements.
    /// When false, allows:
    /// - Non-minimal integer encodings
    /// - Non-canonical map key ordering
    /// - Shorter float encodings (16-bit, 32-bit)
    pub strict: bool,

    /// Enforce DASL CID constraints beyond basic CID structure.
    /// When true, validates:
    /// - CIDv1 only (no CIDv0)
    /// - Codec must be raw (0x55) or dag-cbor (0x71)
    /// - Hash must be SHA-256 (0x12) or BLAKE3 (0x1e)
    /// - Digest must be exactly 32 bytes
    pub validate_dasl_cid: bool,

    /// Maximum nesting depth to prevent stack overflow.
    pub max_depth: usize,

    /// Maximum allocation size for strings/bytes.
    pub max_alloc: usize,

    /// Reject all float values during decoding.
    /// When true, any float value (including valid 64-bit doubles) produces an error.
    pub no_floats: bool,

    /// Restrict integers to the i64 range.
    /// When true, unsigned integers > i64::MAX and negative integers < i64::MIN
    /// produce an error.
    pub int64_range_only: bool,

    /// Maximum number of elements in a single array.
    ///
    /// Default: [`DEFAULT_MAX_ARRAY_ELEMENTS`]. Setting 0 disables this count
    /// check only; the remaining-input bound and the bounded pre-allocation
    /// still apply, so 0 is not a denial-of-service vector.
    pub max_array_elements: usize,

    /// Maximum number of entries in a single map.
    ///
    /// Default: [`DEFAULT_MAX_MAP_ENTRIES`]. Setting 0 disables this count
    /// check only; the remaining-input bound and the bounded pre-allocation
    /// still apply, so 0 is not a denial-of-service vector.
    pub max_map_entries: usize,

    /// Decode CID tags as raw bytes without DASL validation.
    /// When true, tag 42 content is emitted as raw bytes, allowing
    /// non-DASL CIDs (e.g., CIDv0) to be decoded as `RawCid`.
    pub use_raw_cid: bool,

    /// Allow CBOR undefined values (simple value 23).
    /// When true, undefined is treated as null during decoding.
    /// When false (default), undefined values produce an error.
    pub allow_undefined: bool,

    /// Reject unknown fields when deserializing into structs.
    /// When true, any map key that does not match a struct field produces
    /// an error. Works in conjunction with serde's `#[serde(deny_unknown_fields)]`.
    pub disallow_unknown_fields: bool,
}

impl Default for DecodeConfig {
    fn default() -> Self {
        Self {
            strict: true,
            validate_dasl_cid: false,
            max_depth: 256,
            max_alloc: 64 * 1024 * 1024, // 64 MB
            no_floats: false,
            int64_range_only: false,
            max_array_elements: DEFAULT_MAX_ARRAY_ELEMENTS,
            max_map_entries: DEFAULT_MAX_MAP_ENTRIES,
            use_raw_cid: false,
            allow_undefined: false,
            disallow_unknown_fields: false,
        }
    }
}

impl DecodeConfig {
    /// Create a strict configuration (default)
    pub fn strict() -> Self {
        Self::default()
    }

    /// Create a non-strict configuration for backward compatibility
    pub fn non_strict() -> Self {
        Self {
            strict: false,
            ..Default::default()
        }
    }

    /// Create a configuration with DASL CID validation enabled
    pub fn dasl() -> Self {
        Self {
            validate_dasl_cid: true,
            ..Default::default()
        }
    }

    /// Enable or disable DASL CID constraint validation
    pub fn with_dasl_cid_validation(mut self, validate: bool) -> Self {
        self.validate_dasl_cid = validate;
        self
    }

    /// Set the maximum nesting depth
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Set the maximum allocation size
    pub fn with_max_alloc(mut self, size: usize) -> Self {
        self.max_alloc = size;
        self
    }

    /// Enable or disable float rejection
    pub fn with_no_floats(mut self, no_floats: bool) -> Self {
        self.no_floats = no_floats;
        self
    }

    /// Enable or disable i64-range-only integer restriction
    pub fn with_int64_range_only(mut self, enabled: bool) -> Self {
        self.int64_range_only = enabled;
        self
    }

    /// Set the maximum number of array elements.
    ///
    /// Passing 0 disables this count check only; the remaining-input bound and
    /// the bounded pre-allocation still apply.
    pub fn with_max_array_elements(mut self, max: usize) -> Self {
        self.max_array_elements = max;
        self
    }

    /// Set the maximum number of map entries.
    ///
    /// Passing 0 disables this count check only; the remaining-input bound and
    /// the bounded pre-allocation still apply.
    pub fn with_max_map_entries(mut self, max: usize) -> Self {
        self.max_map_entries = max;
        self
    }

    /// Disable the array element count check.
    ///
    /// The remaining-input bound and bounded pre-allocation still apply, so
    /// this is not a denial-of-service vector.
    pub fn with_unlimited_array_elements(mut self) -> Self {
        self.max_array_elements = 0;
        self
    }

    /// Disable the map entry count check.
    ///
    /// The remaining-input bound and bounded pre-allocation still apply, so
    /// this is not a denial-of-service vector.
    pub fn with_unlimited_map_entries(mut self) -> Self {
        self.max_map_entries = 0;
        self
    }

    /// Enable or disable raw CID decoding
    pub fn with_use_raw_cid(mut self, enabled: bool) -> Self {
        self.use_raw_cid = enabled;
        self
    }

    /// Enable or disable allowing CBOR undefined values
    pub fn with_allow_undefined(mut self, enabled: bool) -> Self {
        self.allow_undefined = enabled;
        self
    }

    /// Enable or disable rejecting unknown struct fields
    pub fn with_disallow_unknown_fields(mut self, enabled: bool) -> Self {
        self.disallow_unknown_fields = enabled;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_collection_limits_are_non_zero() {
        for config in [
            DecodeConfig::default(),
            DecodeConfig::strict(),
            DecodeConfig::non_strict(),
            DecodeConfig::dasl(),
        ] {
            assert_eq!(config.max_array_elements, DEFAULT_MAX_ARRAY_ELEMENTS);
            assert_eq!(config.max_map_entries, DEFAULT_MAX_MAP_ENTRIES);
        }
    }

    #[test]
    fn unlimited_builders_use_the_zero_sentinel() {
        let config = DecodeConfig::default()
            .with_unlimited_array_elements()
            .with_unlimited_map_entries();
        assert_eq!(config.max_array_elements, 0);
        assert_eq!(config.max_map_entries, 0);
    }
}
