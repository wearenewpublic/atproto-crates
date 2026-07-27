//! Low-level CBOR decoding following RFC 8949.
//!
//! Supports both strict DAG-CBOR validation and relaxed decoding
//! for backward compatibility with non-conforming data.

use crate::drisl::cbor::types::{
    additional_info, additional_info_from_byte, major_type, major_type_from_byte, simple_value,
};
use crate::drisl::config::DecodeConfig;
use crate::errors::DecodeError;
use std::io::Read;

/// Largest single buffer growth step when reading a byte or text string.
///
/// A declared length is never trusted enough to reserve in one shot: the buffer
/// grows in chunks as bytes actually arrive, so a lying header costs at most
/// this much memory before the read fails.
const READ_CHUNK: usize = 64 * 1024;

/// Decoded CBOR data item
#[derive(Debug, Clone, PartialEq)]
pub enum CborItem {
    /// Unsigned integer (major type 0)
    Unsigned(u64),
    /// Negative integer (major type 1), stores the actual negative value.
    /// Uses i128 to support the full CBOR range: -(2^64) to -1.
    Negative(i128),
    /// Byte string (major type 2)
    Bytes(Vec<u8>),
    /// UTF-8 text string (major type 3)
    Text(String),
    /// Array header (major type 4), value is the number of items
    Array(usize),
    /// Map header (major type 5), value is the number of pairs
    Map(usize),
    /// Tag (major type 6), value is the tag number
    Tag(u64),
    /// Boolean false
    False,
    /// Boolean true
    True,
    /// Null value
    Null,
    /// 64-bit floating-point
    Float(f64),
}

impl CborItem {
    /// Get the type name for error messages
    pub fn type_name(&self) -> String {
        match self {
            CborItem::Unsigned(_) => "unsigned integer".to_string(),
            CborItem::Negative(_) => "negative integer".to_string(),
            CborItem::Bytes(_) => "byte string".to_string(),
            CborItem::Text(_) => "text string".to_string(),
            CborItem::Array(_) => "array".to_string(),
            CborItem::Map(_) => "map".to_string(),
            CborItem::Tag(t) => format!("tag {}", t),
            CborItem::False | CborItem::True => "boolean".to_string(),
            CborItem::Null => "null".to_string(),
            CborItem::Float(_) => "float".to_string(),
        }
    }
}

/// CBOR decoder with configurable strictness
pub struct CborDecoder<R: Read> {
    reader: R,
    config: DecodeConfig,
    peeked: Option<u8>,
    /// Bytes consumed from the reader so far.
    consumed: u64,
    /// Total input length, when the input is a slice of known size.
    input_len: Option<u64>,
}

impl<R: Read> CborDecoder<R> {
    /// Create a new decoder with default (strict) configuration
    pub fn new(reader: R) -> Self {
        Self::with_config(reader, DecodeConfig::default())
    }

    /// Create a new decoder with custom configuration
    pub fn with_config(reader: R, config: DecodeConfig) -> Self {
        Self::with_config_and_input_len(reader, config, None)
    }

    /// Create a decoder that knows its total input length.
    ///
    /// Enables rejecting collection headers that declare more items than the
    /// remaining bytes can possibly encode. Pass `None` when the total length
    /// is unknown (an arbitrary stream).
    pub fn with_config_and_input_len(
        reader: R,
        config: DecodeConfig,
        input_len: Option<u64>,
    ) -> Self {
        Self {
            reader,
            config,
            peeked: None,
            consumed: 0,
            input_len,
        }
    }

    /// Create a non-strict decoder for backward compatibility
    pub fn non_strict(reader: R) -> Self {
        Self::with_config(reader, DecodeConfig::non_strict())
    }

    /// Get a reference to the config
    pub fn config(&self) -> &DecodeConfig {
        &self.config
    }

    /// Read a single byte
    fn read_byte(&mut self) -> Result<u8, DecodeError> {
        if let Some(byte) = self.peeked.take() {
            return Ok(byte);
        }

        let mut buf = [0u8; 1];
        match self.reader.read_exact(&mut buf) {
            Ok(()) => {
                self.consumed = self.consumed.saturating_add(1);
                Ok(buf[0])
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                Err(DecodeError::UnexpectedEof)
            }
            Err(e) => Err(DecodeError::Io(e)),
        }
    }

    /// Bytes left in the input, when the total length is known.
    fn remaining_input(&self) -> Option<u64> {
        self.input_len
            .map(|total| total.saturating_sub(self.consumed))
    }

    /// Peek at the next byte without consuming it
    pub fn peek_byte(&mut self) -> Result<u8, DecodeError> {
        if let Some(byte) = self.peeked {
            return Ok(byte);
        }

        let byte = self.read_byte()?;
        self.peeked = Some(byte);
        Ok(byte)
    }

    /// Check if there's more data available
    pub fn has_more_data(&mut self) -> Result<bool, DecodeError> {
        if self.peeked.is_some() {
            return Ok(true);
        }

        let mut buf = [0u8; 1];
        match self.reader.read(&mut buf) {
            Ok(0) => Ok(false),
            Ok(_) => {
                self.consumed = self.consumed.saturating_add(1);
                self.peeked = Some(buf[0]);
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
            Err(e) => Err(DecodeError::Io(e)),
        }
    }

    /// Read exactly `n` bytes.
    ///
    /// The buffer grows incrementally as bytes arrive rather than being
    /// pre-allocated from the wire-declared length, so a header that lies about
    /// its size cannot commit a large allocation.
    ///
    /// # Errors
    ///
    /// Returns `DecodeError::AllocationExceeded` when `n` exceeds
    /// `max_alloc`, `DecodeError::StringLengthExceedsInput` when `n` exceeds
    /// the bytes that remain in a known-length input,
    /// `DecodeError::AllocationFailed` when the allocator refuses a chunk, and
    /// `DecodeError::UnexpectedEof` when the input ends early.
    pub fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>, DecodeError> {
        if n > self.config.max_alloc {
            return Err(DecodeError::AllocationExceeded {
                size: n,
                max: self.config.max_alloc,
            });
        }

        // A string of length n needs exactly n more bytes, so when the total
        // input length is known this bound is exact and never false-rejects.
        if let Some(remaining) = self.remaining_input()
            && n as u64 > remaining
        {
            return Err(DecodeError::StringLengthExceedsInput {
                length: n as u64,
                remaining,
            });
        }

        let mut buf: Vec<u8> = Vec::new();
        let initial = n.min(READ_CHUNK);
        buf.try_reserve_exact(initial)
            .map_err(|e| DecodeError::AllocationFailed {
                requested: initial,
                reason: e.to_string(),
            })?;

        while buf.len() < n {
            let start = buf.len();
            let want = (n - start).min(READ_CHUNK);
            buf.try_reserve(want)
                .map_err(|e| DecodeError::AllocationFailed {
                    requested: start + want,
                    reason: e.to_string(),
                })?;
            buf.resize(start + want, 0);
            match self.reader.read_exact(&mut buf[start..]) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Err(DecodeError::UnexpectedEof);
                }
                Err(e) => return Err(DecodeError::Io(e)),
            }
        }

        self.consumed = self.consumed.saturating_add(n as u64);
        Ok(buf)
    }

    /// Read a u16 in big-endian format
    fn read_u16(&mut self) -> Result<u16, DecodeError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Read a u32 in big-endian format
    fn read_u32(&mut self) -> Result<u32, DecodeError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a u64 in big-endian format
    fn read_u64(&mut self) -> Result<u64, DecodeError> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Validate that encoding is canonical (shortest form)
    fn validate_canonical(&self, major: u8, additional: u8, value: u64) -> Result<(), DecodeError> {
        if !self.config.strict {
            return Ok(());
        }

        // Check that encoding uses shortest form
        let expected_additional = if value < 24 {
            value as u8
        } else if value <= u8::MAX as u64 {
            additional_info::ONE_BYTE
        } else if value <= u16::MAX as u64 {
            additional_info::TWO_BYTES
        } else if value <= u32::MAX as u64 {
            additional_info::FOUR_BYTES
        } else {
            additional_info::EIGHT_BYTES
        };

        if additional != expected_additional {
            return Err(DecodeError::NonCanonicalEncoding {
                major_type: major,
                additional_info: additional,
                value,
            });
        }

        Ok(())
    }

    /// Read the argument following the initial byte
    fn read_argument(&mut self, major: u8, additional: u8) -> Result<u64, DecodeError> {
        let value = match additional {
            0..=23 => additional as u64,
            additional_info::ONE_BYTE => {
                let byte = self.read_byte()?;
                byte as u64
            }
            additional_info::TWO_BYTES => self.read_u16()? as u64,
            additional_info::FOUR_BYTES => self.read_u32()? as u64,
            additional_info::EIGHT_BYTES => self.read_u64()?,
            additional_info::RESERVED_28
            | additional_info::RESERVED_29
            | additional_info::RESERVED_30 => {
                return Err(DecodeError::ReservedAdditionalInfo { value: additional });
            }
            additional_info::INDEFINITE => {
                return Err(DecodeError::IndefiniteLengthNotSupported);
            }
            _ => unreachable!("additional info is 5 bits, max value is 31"),
        };

        self.validate_canonical(major, additional, value)?;
        Ok(value)
    }

    /// Read and decode the next CBOR item
    pub fn decode_item(&mut self) -> Result<CborItem, DecodeError> {
        let initial = self.read_byte()?;
        let major = major_type_from_byte(initial);
        let additional = additional_info_from_byte(initial);

        match major {
            major_type::UNSIGNED => {
                let value = self.read_argument(major, additional)?;
                if self.config.int64_range_only && value > i64::MAX.cast_unsigned() {
                    return Err(DecodeError::IntegerOutOfRange {
                        value: value.to_string(),
                    });
                }
                Ok(CborItem::Unsigned(value))
            }
            major_type::NEGATIVE => {
                let arg = self.read_argument(major, additional)?;
                // CBOR negative is -1-n, so we compute the actual value
                // Be careful about overflow: the most negative i64 is -9223372036854775808
                // CBOR negative: -1 - arg. Use i128 to handle the full range
                // including -(2^64) when arg = u64::MAX.
                let value: i128 = -1 - (arg as i128);
                if self.config.int64_range_only && value < i64::MIN as i128 {
                    return Err(DecodeError::IntegerOutOfRange {
                        value: value.to_string(),
                    });
                }
                Ok(CborItem::Negative(value))
            }
            major_type::BYTES => {
                let len = self.read_argument(major, additional)? as usize;
                if len > self.config.max_alloc {
                    return Err(DecodeError::AllocationExceeded {
                        size: len,
                        max: self.config.max_alloc,
                    });
                }
                // `read_bytes` applies the remaining-input bound and grows its
                // buffer incrementally, so `len` is never pre-allocated.
                let bytes = self.read_bytes(len)?;
                Ok(CborItem::Bytes(bytes))
            }
            major_type::TEXT => {
                let len = self.read_argument(major, additional)? as usize;
                if len > self.config.max_alloc {
                    return Err(DecodeError::AllocationExceeded {
                        size: len,
                        max: self.config.max_alloc,
                    });
                }
                // Same bounded read as the byte-string path above.
                let bytes = self.read_bytes(len)?;
                let text = String::from_utf8(bytes)?;
                Ok(CborItem::Text(text))
            }
            major_type::ARRAY => {
                let len = self.read_argument(major, additional)? as usize;
                if self.config.max_array_elements > 0 && len > self.config.max_array_elements {
                    return Err(DecodeError::ArrayTooLarge {
                        count: len,
                        max: self.config.max_array_elements,
                    });
                }
                // Each element needs at least one byte, so a declared count
                // larger than the bytes that remain cannot be honest.
                if let Some(remaining) = self.remaining_input() {
                    let needed = len as u64;
                    if needed > remaining {
                        return Err(DecodeError::CollectionLengthExceedsInput {
                            count: len,
                            needed,
                            remaining,
                        });
                    }
                }
                Ok(CborItem::Array(len))
            }
            major_type::MAP => {
                let len = self.read_argument(major, additional)? as usize;
                if self.config.max_map_entries > 0 && len > self.config.max_map_entries {
                    return Err(DecodeError::MapTooLarge {
                        count: len,
                        max: self.config.max_map_entries,
                    });
                }
                // Each entry needs at least a key byte and a value byte.
                if let Some(remaining) = self.remaining_input() {
                    let needed = (len as u64).saturating_mul(2);
                    if needed > remaining {
                        return Err(DecodeError::CollectionLengthExceedsInput {
                            count: len,
                            needed,
                            remaining,
                        });
                    }
                }
                Ok(CborItem::Map(len))
            }
            major_type::TAG => {
                let tag = self.read_argument(major, additional)?;
                // In strict mode, only tag 42 is allowed
                if self.config.strict && tag != 42 {
                    return Err(DecodeError::UnsupportedTag { tag });
                }
                Ok(CborItem::Tag(tag))
            }
            major_type::SIMPLE => {
                match additional {
                    simple_value::FALSE => Ok(CborItem::False),
                    simple_value::TRUE => Ok(CborItem::True),
                    simple_value::NULL => Ok(CborItem::Null),
                    simple_value::UNDEFINED => {
                        // Undefined is not allowed in DAG-CBOR
                        Err(DecodeError::UnsupportedSimpleValue {
                            value: simple_value::UNDEFINED,
                        })
                    }
                    simple_value::FLOAT16 => {
                        // 16-bit float - read 2 bytes and convert
                        let bytes = self.read_bytes(2)?;
                        let value = decode_f16(bytes[0], bytes[1]);

                        // In strict mode, floats must be 64-bit
                        if self.config.strict {
                            return Err(DecodeError::NonCanonicalFloat);
                        }

                        if self.config.no_floats {
                            return Err(DecodeError::FloatsNotAllowed);
                        }

                        // Check for NaN/Infinity
                        if value.is_nan() || value.is_infinite() {
                            return Err(DecodeError::InvalidFloat);
                        }

                        Ok(CborItem::Float(value))
                    }
                    simple_value::FLOAT32 => {
                        // 32-bit float - read 4 bytes and convert
                        let bytes = self.read_bytes(4)?;
                        let bits = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                        let value = f32::from_bits(bits) as f64;

                        // In strict mode, floats must be 64-bit
                        if self.config.strict {
                            return Err(DecodeError::NonCanonicalFloat);
                        }

                        if self.config.no_floats {
                            return Err(DecodeError::FloatsNotAllowed);
                        }

                        // Check for NaN/Infinity
                        if value.is_nan() || value.is_infinite() {
                            return Err(DecodeError::InvalidFloat);
                        }

                        Ok(CborItem::Float(value))
                    }
                    simple_value::FLOAT64 => {
                        // 64-bit float
                        let bytes = self.read_bytes(8)?;
                        let bits = u64::from_be_bytes([
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                            bytes[7],
                        ]);
                        let value = f64::from_bits(bits);

                        if self.config.no_floats {
                            return Err(DecodeError::FloatsNotAllowed);
                        }

                        // Check for NaN/Infinity
                        if value.is_nan() || value.is_infinite() {
                            return Err(DecodeError::InvalidFloat);
                        }

                        Ok(CborItem::Float(value))
                    }
                    simple_value::BREAK => {
                        // Break code not allowed in DAG-CBOR
                        Err(DecodeError::IndefiniteLengthNotSupported)
                    }
                    0..=19 => {
                        // Simple values 0-19 are unassigned
                        Err(DecodeError::UnsupportedSimpleValue { value: additional })
                    }
                    additional_info::ONE_BYTE => {
                        // Simple value with 1-byte argument
                        let value = self.read_byte()?;
                        Err(DecodeError::UnsupportedSimpleValue { value })
                    }
                    _ => Err(DecodeError::InvalidCbor {
                        reason: format!("invalid additional info {} for major type 7", additional),
                    }),
                }
            }
            _ => Err(DecodeError::InvalidCbor {
                reason: format!("unknown major type {}", major),
            }),
        }
    }

    /// Decode a complete CBOR value recursively (for testing/debugging)
    #[cfg(test)]
    pub fn decode_value(&mut self) -> Result<CborItem, DecodeError> {
        self.decode_item()
    }
}

/// Decode IEEE 754 half-precision (16-bit) float to f64
fn decode_f16(high: u8, low: u8) -> f64 {
    let half = ((high as u16) << 8) | (low as u16);

    let sign = (half >> 15) & 1;
    let exponent = (half >> 10) & 0x1f;
    let mantissa = half & 0x3ff;

    if exponent == 0 {
        // Subnormal or zero
        if mantissa == 0 {
            0.0
        } else {
            // Subnormal: (-1)^sign * 2^-14 * (mantissa / 1024)
            let m = mantissa as f64 / 1024.0;
            let v = m * 2.0_f64.powi(-14);
            if sign == 1 { -v } else { v }
        }
    } else if exponent == 31 {
        // Infinity or NaN
        if mantissa == 0 {
            if sign == 1 {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            }
        } else {
            f64::NAN
        }
    } else {
        // Normal: (-1)^sign * 2^(exponent-15) * (1 + mantissa/1024)
        let m = 1.0 + (mantissa as f64 / 1024.0);
        let v = m * 2.0_f64.powi(exponent as i32 - 15);
        if sign == 1 { -v } else { v }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn decode_bytes(bytes: &[u8]) -> Result<CborItem, DecodeError> {
        let mut decoder = CborDecoder::new(Cursor::new(bytes));
        decoder.decode_item()
    }

    fn decode_bytes_non_strict(bytes: &[u8]) -> Result<CborItem, DecodeError> {
        let mut decoder = CborDecoder::non_strict(Cursor::new(bytes));
        decoder.decode_item()
    }

    #[test]
    fn test_decode_unsigned() {
        // 0 -> 0x00
        assert_eq!(decode_bytes(&[0x00]).unwrap(), CborItem::Unsigned(0));
        // 1 -> 0x01
        assert_eq!(decode_bytes(&[0x01]).unwrap(), CborItem::Unsigned(1));
        // 23 -> 0x17
        assert_eq!(decode_bytes(&[0x17]).unwrap(), CborItem::Unsigned(23));
        // 24 -> 0x18 0x18
        assert_eq!(decode_bytes(&[0x18, 0x18]).unwrap(), CborItem::Unsigned(24));
        // 255 -> 0x18 0xff
        assert_eq!(
            decode_bytes(&[0x18, 0xff]).unwrap(),
            CborItem::Unsigned(255)
        );
        // 256 -> 0x19 0x01 0x00
        assert_eq!(
            decode_bytes(&[0x19, 0x01, 0x00]).unwrap(),
            CborItem::Unsigned(256)
        );
        // 65535 -> 0x19 0xff 0xff
        assert_eq!(
            decode_bytes(&[0x19, 0xff, 0xff]).unwrap(),
            CborItem::Unsigned(65535)
        );
        // 65536 -> 0x1a 0x00 0x01 0x00 0x00
        assert_eq!(
            decode_bytes(&[0x1a, 0x00, 0x01, 0x00, 0x00]).unwrap(),
            CborItem::Unsigned(65536)
        );
    }

    #[test]
    fn test_decode_negative() {
        // -1 -> 0x20
        assert_eq!(decode_bytes(&[0x20]).unwrap(), CborItem::Negative(-1));
        // -24 -> 0x37
        assert_eq!(decode_bytes(&[0x37]).unwrap(), CborItem::Negative(-24));
        // -25 -> 0x38 0x18
        assert_eq!(
            decode_bytes(&[0x38, 0x18]).unwrap(),
            CborItem::Negative(-25)
        );
        // -256 -> 0x38 0xff
        assert_eq!(
            decode_bytes(&[0x38, 0xff]).unwrap(),
            CborItem::Negative(-256)
        );
        // -257 -> 0x39 0x01 0x00
        assert_eq!(
            decode_bytes(&[0x39, 0x01, 0x00]).unwrap(),
            CborItem::Negative(-257)
        );
    }

    #[test]
    fn test_decode_bytes_string() {
        // Empty bytes -> 0x40
        assert_eq!(decode_bytes(&[0x40]).unwrap(), CborItem::Bytes(vec![]));
        // Single byte -> 0x41 0xaa
        assert_eq!(
            decode_bytes(&[0x41, 0xaa]).unwrap(),
            CborItem::Bytes(vec![0xaa])
        );
        // Multiple bytes
        assert_eq!(
            decode_bytes(&[0x43, 0x01, 0x02, 0x03]).unwrap(),
            CborItem::Bytes(vec![1, 2, 3])
        );
    }

    #[test]
    fn test_decode_text() {
        // Empty string -> 0x60
        assert_eq!(
            decode_bytes(&[0x60]).unwrap(),
            CborItem::Text(String::new())
        );
        // "a" -> 0x61 0x61
        assert_eq!(
            decode_bytes(&[0x61, 0x61]).unwrap(),
            CborItem::Text("a".to_string())
        );
        // "hello"
        assert_eq!(
            decode_bytes(&[0x65, b'h', b'e', b'l', b'l', b'o']).unwrap(),
            CborItem::Text("hello".to_string())
        );
    }

    #[test]
    fn test_decode_array_header() {
        // Empty array -> 0x80
        assert_eq!(decode_bytes(&[0x80]).unwrap(), CborItem::Array(0));
        // Array of 3 -> 0x83
        assert_eq!(decode_bytes(&[0x83]).unwrap(), CborItem::Array(3));
        // Array of 24 -> 0x98 0x18
        assert_eq!(decode_bytes(&[0x98, 0x18]).unwrap(), CborItem::Array(24));
    }

    #[test]
    fn test_decode_map_header() {
        // Empty map -> 0xa0
        assert_eq!(decode_bytes(&[0xa0]).unwrap(), CborItem::Map(0));
        // Map of 1 pair -> 0xa1
        assert_eq!(decode_bytes(&[0xa1]).unwrap(), CborItem::Map(1));
    }

    #[test]
    fn test_decode_bool() {
        // false -> 0xf4
        assert_eq!(decode_bytes(&[0xf4]).unwrap(), CborItem::False);
        // true -> 0xf5
        assert_eq!(decode_bytes(&[0xf5]).unwrap(), CborItem::True);
    }

    #[test]
    fn test_decode_null() {
        // null -> 0xf6
        assert_eq!(decode_bytes(&[0xf6]).unwrap(), CborItem::Null);
    }

    #[test]
    fn test_decode_f64() {
        // 1.0 -> 0xfb 0x3f 0xf0 0x00 0x00 0x00 0x00 0x00 0x00
        if let CborItem::Float(v) =
            decode_bytes(&[0xfb, 0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap()
        {
            assert!((v - 1.0).abs() < f64::EPSILON);
        } else {
            panic!("expected float");
        }
    }

    #[test]
    fn test_decode_tag_42() {
        // Tag 42 -> 0xd8 0x2a
        assert_eq!(decode_bytes(&[0xd8, 0x2a]).unwrap(), CborItem::Tag(42));
    }

    #[test]
    fn test_strict_rejects_non_canonical() {
        // Non-minimal: 0 encoded with 1 extra byte (0x18 0x00)
        assert!(decode_bytes(&[0x18, 0x00]).is_err());
        // Non-minimal: 23 encoded with 2 extra bytes (0x19 0x00 0x17)
        assert!(decode_bytes(&[0x19, 0x00, 0x17]).is_err());
    }

    #[test]
    fn test_non_strict_accepts_non_canonical() {
        // Non-minimal: 0 encoded with 1 extra byte (0x18 0x00)
        assert_eq!(
            decode_bytes_non_strict(&[0x18, 0x00]).unwrap(),
            CborItem::Unsigned(0)
        );
    }

    #[test]
    fn test_strict_rejects_other_tags() {
        // Tag 0 (datetime) -> 0xc0
        assert!(decode_bytes(&[0xc0]).is_err());
        // Tag 1 (epoch) -> 0xc1
        assert!(decode_bytes(&[0xc1]).is_err());
    }

    #[test]
    fn test_strict_rejects_non_64bit_float() {
        // 16-bit float 0.0 -> 0xf9 0x00 0x00
        assert!(decode_bytes(&[0xf9, 0x00, 0x00]).is_err());
        // 32-bit float 0.0 -> 0xfa 0x00 0x00 0x00 0x00
        assert!(decode_bytes(&[0xfa, 0x00, 0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn test_non_strict_accepts_non_64bit_float() {
        // 16-bit float 0.0 -> 0xf9 0x00 0x00
        if let CborItem::Float(v) = decode_bytes_non_strict(&[0xf9, 0x00, 0x00]).unwrap() {
            assert!((v - 0.0).abs() < f64::EPSILON);
        } else {
            panic!("expected float");
        }

        // 32-bit float 0.0 -> 0xfa 0x00 0x00 0x00 0x00
        if let CborItem::Float(v) =
            decode_bytes_non_strict(&[0xfa, 0x00, 0x00, 0x00, 0x00]).unwrap()
        {
            assert!((v - 0.0).abs() < f64::EPSILON);
        } else {
            panic!("expected float");
        }
    }

    #[test]
    fn test_rejects_nan_infinity() {
        // 64-bit NaN
        assert!(decode_bytes(&[0xfb, 0x7f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).is_err());
        // 64-bit Infinity
        assert!(decode_bytes(&[0xfb, 0x7f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).is_err());
        // 64-bit -Infinity
        assert!(decode_bytes(&[0xfb, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn test_rejects_indefinite_length() {
        // Indefinite array -> 0x9f
        assert!(decode_bytes(&[0x9f]).is_err());
        // Indefinite map -> 0xbf
        assert!(decode_bytes(&[0xbf]).is_err());
        // Break code -> 0xff
        assert!(decode_bytes(&[0xff]).is_err());
    }

    #[test]
    fn test_rejects_undefined() {
        // Undefined -> 0xf7
        assert!(decode_bytes(&[0xf7]).is_err());
    }

    fn decode_slice(bytes: &[u8]) -> Result<CborItem, DecodeError> {
        let mut decoder = CborDecoder::with_config_and_input_len(
            Cursor::new(bytes),
            DecodeConfig::default(),
            Some(bytes.len() as u64),
        );
        decoder.decode_item()
    }

    #[test]
    fn test_byte_string_bomb_rejected_before_allocation() {
        // Major type 2, canonical 4-byte length 0x04000000 = 67_108_864, which
        // is exactly DecodeConfig::default().max_alloc. Five bytes of input must
        // not commit a 64 MiB allocation.
        let payload = [0x5a, 0x04, 0x00, 0x00, 0x00];
        match decode_slice(&payload) {
            Err(DecodeError::StringLengthExceedsInput { length, remaining }) => {
                assert_eq!(length, 67_108_864);
                assert_eq!(remaining, 0);
            }
            other => panic!("expected StringLengthExceedsInput, got {:?}", other),
        }
    }

    #[test]
    fn test_text_string_bomb_rejected_before_allocation() {
        // Text-string variant of the same bomb.
        let payload = [0x7a, 0x04, 0x00, 0x00, 0x00];
        match decode_slice(&payload) {
            Err(DecodeError::StringLengthExceedsInput { length, remaining }) => {
                assert_eq!(length, 67_108_864);
                assert_eq!(remaining, 0);
            }
            other => panic!("expected StringLengthExceedsInput, got {:?}", other),
        }
    }

    #[test]
    fn test_string_bomb_over_reader_reads_incrementally() {
        // Without a known input length the bound cannot apply, so the
        // incremental read must surface EOF instead of pre-allocating.
        let payload = [0x5a, 0x04, 0x00, 0x00, 0x00];
        let mut decoder = CborDecoder::new(Cursor::new(&payload[..]));
        assert!(matches!(
            decoder.decode_item(),
            Err(DecodeError::UnexpectedEof)
        ));

        let payload = [0x7a, 0x04, 0x00, 0x00, 0x00];
        let mut decoder = CborDecoder::new(Cursor::new(&payload[..]));
        assert!(matches!(
            decoder.decode_item(),
            Err(DecodeError::UnexpectedEof)
        ));
    }

    #[test]
    fn test_string_bomb_rejected_with_unlimited_max_alloc() {
        // max_alloc is no longer the only defence: a 2^63-byte declaration is
        // rejected by the remaining-input bound even when max_alloc is huge.
        let config = DecodeConfig {
            max_alloc: usize::MAX,
            ..DecodeConfig::default()
        };
        let payload = [0x5b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut decoder = CborDecoder::with_config_and_input_len(
            Cursor::new(&payload[..]),
            config,
            Some(payload.len() as u64),
        );
        assert!(matches!(
            decoder.decode_item(),
            Err(DecodeError::StringLengthExceedsInput { .. })
        ));
    }

    #[test]
    fn test_exact_length_strings_still_decode() {
        // The bound is exact for strings, so a string that exactly fills the
        // remaining input must still be accepted.
        assert_eq!(
            decode_slice(&[0x43, 0x01, 0x02, 0x03]).unwrap(),
            CborItem::Bytes(vec![1, 2, 3])
        );
        assert_eq!(
            decode_slice(&[0x65, b'h', b'e', b'l', b'l', b'o']).unwrap(),
            CborItem::Text("hello".to_string())
        );
    }

    #[test]
    fn test_large_legitimate_string_decodes() {
        // Longer than READ_CHUNK, so the chunked read loop runs several times.
        let data = vec![0x5au8; READ_CHUNK * 3 + 17];
        let mut payload = Vec::new();
        payload.push(0x5a);
        payload.extend_from_slice(&(data.len() as u32).to_be_bytes());
        payload.extend_from_slice(&data);
        assert_eq!(decode_slice(&payload).unwrap(), CborItem::Bytes(data));
    }

    #[test]
    fn test_rejects_reserved_additional_info() {
        // Reserved value 28 -> 0x1c
        assert!(decode_bytes(&[0x1c]).is_err());
        // Reserved value 29 -> 0x1d
        assert!(decode_bytes(&[0x1d]).is_err());
        // Reserved value 30 -> 0x1e
        assert!(decode_bytes(&[0x1e]).is_err());
    }
}
