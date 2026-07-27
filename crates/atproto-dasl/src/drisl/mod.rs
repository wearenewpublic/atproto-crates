//! DRISL (Deterministic Representation for Interoperable Structures and Links).
//!
//! A profile of deterministic CBOR used to ensure that the same data will have
//! the same CID. Features native support for using binary CIDs as compact links
//! between documents.
//!
//! This module provides DAG-CBOR encoding and decoding following the
//! [IPLD DAG-CBOR specification](https://ipld.io/specs/codecs/dag-cbor/spec/).
//!
//! # DAG-CBOR Constraints
//!
//! - **Integers**: Must use shortest possible encoding
//! - **Floats**: Must be 64-bit, no NaN or Infinity
//! - **Maps**: Keys must be strings, sorted in bytewise lexicographic order
//! - **Tags**: Only tag 42 (CIDs) is allowed
//! - **Lengths**: Must be definite (no indefinite-length items)

pub mod cbor;
pub(crate) mod config;
pub mod de;
pub mod raw;
pub mod ser;

pub use config::{
    DEFAULT_MAX_ARRAY_ELEMENTS, DEFAULT_MAX_MAP_ENTRIES, DecodeConfig, EncodeConfig, TimeMode,
};

use crate::errors::{DecodeError, EncodeError};
use std::io::{Cursor, Read, Write};

/// Serialize a value to a DAG-CBOR byte vector.
///
/// Uses canonical encoding with sorted map keys and shortest-form integers.
///
/// # Errors
///
/// Returns `EncodeError` if serialization fails or the value contains
/// invalid data (NaN, Infinity).
///
/// # Example
///
/// ```rust
/// use atproto_dasl::drisl::to_vec;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct Data {
///     value: i32,
/// }
///
/// let data = Data { value: 42 };
/// let bytes = to_vec(&data).unwrap();
/// ```
pub fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, EncodeError> {
    let mut buffer = Vec::new();
    to_writer(&mut buffer, value)?;
    Ok(buffer)
}

/// Serialize a value to a writer in DAG-CBOR format.
///
/// # Errors
///
/// Returns `EncodeError` if serialization fails.
pub fn to_writer<W: Write, T: serde::Serialize>(writer: W, value: &T) -> Result<(), EncodeError> {
    let mut serializer = ser::Serializer::new(writer);
    serde::Serialize::serialize(value, &mut serializer)?;
    Ok(())
}

/// Serialize a value to a DAG-CBOR byte vector with custom configuration.
///
/// # Errors
///
/// Returns `EncodeError` if serialization fails or limits are exceeded.
pub fn to_vec_with_config<T: serde::Serialize>(
    value: &T,
    config: EncodeConfig,
) -> Result<Vec<u8>, EncodeError> {
    let mut buffer = Vec::new();
    to_writer_with_config(&mut buffer, value, config)?;
    Ok(buffer)
}

/// Serialize a value to a writer in DAG-CBOR format with custom configuration.
///
/// # Errors
///
/// Returns `EncodeError` if serialization fails or limits are exceeded.
pub fn to_writer_with_config<W: Write, T: serde::Serialize>(
    writer: W,
    value: &T,
    config: EncodeConfig,
) -> Result<(), EncodeError> {
    let mut serializer = ser::Serializer::with_config(writer, config);
    serde::Serialize::serialize(value, &mut serializer)?;
    Ok(())
}

/// Deserialize a value from a DAG-CBOR byte slice.
///
/// Uses strict mode by default, which rejects non-conforming data.
///
/// # Errors
///
/// Returns `DecodeError` if deserialization fails or data violates
/// DAG-CBOR requirements.
pub fn from_slice<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, DecodeError> {
    from_slice_with_config(bytes, DecodeConfig::default())
}

/// Deserialize a value from a reader in DAG-CBOR format.
///
/// Uses strict mode by default.
///
/// # Errors
///
/// Returns `DecodeError` if deserialization fails.
pub fn from_reader<R: Read, T: serde::de::DeserializeOwned>(reader: R) -> Result<T, DecodeError> {
    from_reader_with_config(reader, DecodeConfig::default())
}

/// Deserialize a value from a DAG-CBOR byte slice with non-strict validation.
///
/// Accepts non-canonical encodings for backward compatibility.
///
/// # Errors
///
/// Returns `DecodeError` if deserialization fails.
pub fn from_slice_non_strict<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, DecodeError> {
    from_slice_with_config(bytes, DecodeConfig::non_strict())
}

/// Deserialize a value from a reader with non-strict validation.
///
/// # Errors
///
/// Returns `DecodeError` if deserialization fails.
pub fn from_reader_non_strict<R: Read, T: serde::de::DeserializeOwned>(
    reader: R,
) -> Result<T, DecodeError> {
    from_reader_with_config(reader, DecodeConfig::non_strict())
}

/// Deserialize a value from a byte slice with custom configuration.
///
/// A slice communicates its total length, which lets the decoder reject
/// collection headers declaring more items than the remaining bytes can hold.
///
/// # Errors
///
/// Returns `DecodeError` if deserialization fails.
pub fn from_slice_with_config<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    config: DecodeConfig,
) -> Result<T, DecodeError> {
    from_reader_with_input_len(Cursor::new(bytes), config, Some(bytes.len() as u64))
}

/// Deserialize a value from a reader with custom configuration.
///
/// The total input length is unknown for an arbitrary reader, so the
/// remaining-input bound on collection lengths does not apply; the element
/// count limits and bounded pre-allocation still do. Prefer
/// [`from_slice_with_config`] when the input is already in memory.
///
/// # Errors
///
/// Returns `DecodeError` if deserialization fails.
pub fn from_reader_with_config<R: Read, T: serde::de::DeserializeOwned>(
    reader: R,
    config: DecodeConfig,
) -> Result<T, DecodeError> {
    from_reader_with_input_len(reader, config, None)
}

/// Shared implementation for the slice and reader entry points.
fn from_reader_with_input_len<R: Read, T: serde::de::DeserializeOwned>(
    reader: R,
    config: DecodeConfig,
    input_len: Option<u64>,
) -> Result<T, DecodeError> {
    let strict = config.strict;
    let mut deserializer = de::Deserializer::with_config_and_input_len(reader, config, input_len);
    let value = serde::Deserialize::deserialize(&mut deserializer)?;
    if strict && deserializer.has_trailing_data()? {
        return Err(DecodeError::TrailingData);
    }
    Ok(value)
}
