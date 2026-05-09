//! Serde Deserializer implementation for DAG-CBOR.
//!
//! Provides deserialization of DAG-CBOR data to Rust types with
//! configurable strict/non-strict mode.

use crate::drisl::cbor::decode::{CborDecoder, CborItem};
use crate::drisl::config::DecodeConfig;
use crate::errors::DecodeError;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::io::Read;

/// DAG-CBOR deserializer.
///
/// Implements the serde `Deserializer` trait to convert DAG-CBOR data
/// to Rust types.
pub struct Deserializer<R: Read> {
    decoder: CborDecoder<R>,
    depth: usize,
    config: DecodeConfig,
}

impl<R: Read> Deserializer<R> {
    /// Create a new deserializer with default (strict) configuration
    pub fn new(reader: R) -> Self {
        Self::with_config(reader, DecodeConfig::default())
    }

    /// Create a new deserializer with custom configuration
    pub fn with_config(reader: R, config: DecodeConfig) -> Self {
        Self {
            decoder: CborDecoder::with_config(reader, config.clone()),
            depth: 0,
            config,
        }
    }

    /// Create a non-strict deserializer for backward compatibility
    pub fn non_strict(reader: R) -> Self {
        Self::with_config(reader, DecodeConfig::non_strict())
    }

    fn check_depth(&mut self) -> Result<(), DecodeError> {
        if self.depth > self.config.max_depth {
            return Err(DecodeError::MaxDepthExceeded {
                depth: self.depth,
                max: self.config.max_depth,
            });
        }
        Ok(())
    }

    fn decode_item(&mut self) -> Result<CborItem, DecodeError> {
        self.decoder.decode_item()
    }

    /// Check if there is trailing data after deserialization
    pub fn has_trailing_data(&mut self) -> Result<bool, DecodeError> {
        self.decoder.has_more_data()
    }
}

impl<'de, R: Read> de::Deserializer<'de> for &mut Deserializer<R> {
    type Error = DecodeError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        let item = self.decode_item()?;

        match item {
            CborItem::Unsigned(n) => {
                if n <= i64::MAX as u64 {
                    visitor.visit_i64(n as i64)
                } else {
                    visitor.visit_u64(n)
                }
            }
            CborItem::Negative(n) => {
                if let Ok(n64) = i64::try_from(n) {
                    visitor.visit_i64(n64)
                } else {
                    visitor.visit_i128(n)
                }
            }
            CborItem::Bytes(bytes) => visitor.visit_byte_buf(bytes),
            CborItem::Text(s) => visitor.visit_string(s),
            CborItem::Array(len) => {
                self.depth += 1;
                self.check_depth()?;
                let result = visitor.visit_seq(SeqAccessor {
                    de: self,
                    remaining: len,
                });
                self.depth -= 1;
                result
            }
            CborItem::Map(len) => {
                self.depth += 1;
                self.check_depth()?;
                let result = visitor.visit_map(MapAccessor {
                    de: self,
                    remaining: len,
                    last_key: None,
                });
                self.depth -= 1;
                result
            }
            CborItem::Tag(42) => {
                // CID: decode the following byte string
                let next = self.decode_item()?;
                match next {
                    CborItem::Bytes(bytes) => {
                        if self.config.strict {
                            let cid = crate::cid::Cid::from_dag_cbor_bytes(&bytes)
                                .map_err(|_| DecodeError::InvalidCidContent)?;
                            if self.config.validate_dasl_cid {
                                crate::cid::validate_dasl_or_bdasl_cid(cid.inner())?;
                            }
                        }
                        visitor.visit_byte_buf(bytes)
                    }
                    _ => Err(DecodeError::InvalidCidContent),
                }
            }
            CborItem::Tag(tag) => {
                // DAG-CBOR only allows tag 42
                Err(DecodeError::UnsupportedTag { tag })
            }
            CborItem::False => visitor.visit_bool(false),
            CborItem::True => visitor.visit_bool(true),
            CborItem::Null => visitor.visit_unit(),
            CborItem::Float(f) => visitor.visit_f64(f),
        }
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        match self.decode_item()? {
            CborItem::False => visitor.visit_bool(false),
            CborItem::True => visitor.visit_bool(true),
            item => Err(DecodeError::TypeMismatch {
                expected: "bool",
                found: item.type_name(),
            }),
        }
    }

    fn deserialize_i8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        self.deserialize_i64(visitor)
    }

    fn deserialize_i16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        self.deserialize_i64(visitor)
    }

    fn deserialize_i32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        self.deserialize_i64(visitor)
    }

    fn deserialize_i64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        match self.decode_item()? {
            CborItem::Unsigned(n) => {
                if n <= i64::MAX as u64 {
                    visitor.visit_i64(n as i64)
                } else {
                    Err(DecodeError::InvalidCbor {
                        reason: format!("unsigned integer {} too large for i64", n),
                    })
                }
            }
            CborItem::Negative(n) => {
                let n64 = i64::try_from(n).map_err(|_| DecodeError::InvalidCbor {
                    reason: format!("negative integer {} too large for i64", n),
                })?;
                visitor.visit_i64(n64)
            }
            item => Err(DecodeError::TypeMismatch {
                expected: "integer",
                found: item.type_name(),
            }),
        }
    }

    fn deserialize_i128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        match self.decode_item()? {
            CborItem::Unsigned(n) => visitor.visit_i128(n as i128),
            CborItem::Negative(n) => visitor.visit_i128(n),
            item => Err(DecodeError::TypeMismatch {
                expected: "integer",
                found: item.type_name(),
            }),
        }
    }

    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        self.deserialize_u64(visitor)
    }

    fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        self.deserialize_u64(visitor)
    }

    fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        self.deserialize_u64(visitor)
    }

    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        match self.decode_item()? {
            CborItem::Unsigned(n) => visitor.visit_u64(n),
            CborItem::Negative(n) => Err(DecodeError::InvalidCbor {
                reason: format!("negative integer {} cannot be converted to unsigned", n),
            }),
            item => Err(DecodeError::TypeMismatch {
                expected: "unsigned integer",
                found: item.type_name(),
            }),
        }
    }

    fn deserialize_u128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        match self.decode_item()? {
            CborItem::Unsigned(n) => visitor.visit_u128(n as u128),
            CborItem::Negative(n) => Err(DecodeError::InvalidCbor {
                reason: format!("negative integer {} cannot be converted to unsigned", n),
            }),
            item => Err(DecodeError::TypeMismatch {
                expected: "unsigned integer",
                found: item.type_name(),
            }),
        }
    }

    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        self.deserialize_f64(visitor)
    }

    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        match self.decode_item()? {
            CborItem::Float(f) => visitor.visit_f64(f),
            item => Err(DecodeError::TypeMismatch {
                expected: "float",
                found: item.type_name(),
            }),
        }
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        match self.decode_item()? {
            CborItem::Text(s) => {
                let mut chars = s.chars();
                match (chars.next(), chars.next()) {
                    (Some(c), None) => visitor.visit_char(c),
                    _ => Err(DecodeError::InvalidCbor {
                        reason: "expected single character string".to_string(),
                    }),
                }
            }
            item => Err(DecodeError::TypeMismatch {
                expected: "char",
                found: item.type_name(),
            }),
        }
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        match self.decode_item()? {
            CborItem::Text(s) => visitor.visit_string(s),
            item => Err(DecodeError::TypeMismatch {
                expected: "string",
                found: item.type_name(),
            }),
        }
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        match self.decode_item()? {
            CborItem::Bytes(bytes) => visitor.visit_byte_buf(bytes),
            // Also accept text strings as bytes (for compatibility)
            CborItem::Text(s) => visitor.visit_byte_buf(s.into_bytes()),
            item => Err(DecodeError::TypeMismatch {
                expected: "bytes",
                found: item.type_name(),
            }),
        }
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        // Peek at the next item to check for null
        match self.decoder.peek_byte()? {
            0xf6 => {
                // It's null, consume it and return None
                let _ = self.decode_item()?;
                visitor.visit_none()
            }
            _ => visitor.visit_some(self),
        }
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        match self.decode_item()? {
            CborItem::Null => visitor.visit_unit(),
            item => Err(DecodeError::TypeMismatch {
                expected: "null",
                found: item.type_name(),
            }),
        }
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, DecodeError> {
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, DecodeError> {
        // Special case for CID deserialization with tag 42
        if name == "__cid_tag_42__" {
            let item = self.decode_item()?;
            match item {
                CborItem::Tag(42) => {
                    // CID: decode the following byte string
                    let next = self.decode_item()?;
                    match next {
                        CborItem::Bytes(bytes) => {
                            if self.config.strict {
                                let cid = crate::cid::Cid::from_dag_cbor_bytes(&bytes)
                                    .map_err(|_| DecodeError::InvalidCidContent)?;
                                if self.config.validate_dasl_cid {
                                    crate::cid::validate_dasl_or_bdasl_cid(cid.inner())?;
                                }
                            }
                            return visitor.visit_bytes(&bytes);
                        }
                        _ => return Err(DecodeError::InvalidCidContent),
                    }
                }
                _ => {
                    return Err(DecodeError::TypeMismatch {
                        expected: "tag 42 for CID",
                        found: item.type_name(),
                    });
                }
            }
        }

        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        match self.decode_item()? {
            CborItem::Array(len) => {
                self.depth += 1;
                self.check_depth()?;
                let result = visitor.visit_seq(SeqAccessor {
                    de: self,
                    remaining: len,
                });
                self.depth -= 1;
                result
            }
            item => Err(DecodeError::TypeMismatch {
                expected: "array",
                found: item.type_name(),
            }),
        }
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, DecodeError> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, DecodeError> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        match self.decode_item()? {
            CborItem::Map(len) => {
                self.depth += 1;
                self.check_depth()?;
                let result = visitor.visit_map(MapAccessor {
                    de: self,
                    remaining: len,
                    last_key: None,
                });
                self.depth -= 1;
                result
            }
            item => Err(DecodeError::TypeMismatch {
                expected: "map",
                found: item.type_name(),
            }),
        }
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, DecodeError> {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, DecodeError> {
        // Peek to determine if this is a unit variant (string) or complex variant (map)
        let byte = self.decoder.peek_byte()?;
        let major = byte >> 5;

        if major == 3 {
            // Text string - unit variant
            let item = self.decode_item()?;
            match item {
                CborItem::Text(variant) => visitor.visit_enum(UnitVariantAccess { variant }),
                _ => unreachable!(),
            }
        } else if major == 5 {
            // Map - complex variant
            let item = self.decode_item()?;
            match item {
                CborItem::Map(len) => {
                    if len != 1 {
                        return Err(DecodeError::InvalidCbor {
                            reason: format!(
                                "enum variant map must have exactly 1 entry, got {}",
                                len
                            ),
                        });
                    }
                    // Read the variant name
                    let variant_item = self.decode_item()?;
                    match variant_item {
                        CborItem::Text(variant) => {
                            visitor.visit_enum(VariantAccess { de: self, variant })
                        }
                        _ => Err(DecodeError::MapKeyNotString),
                    }
                }
                _ => unreachable!(),
            }
        } else {
            Err(DecodeError::TypeMismatch {
                expected: "string or map for enum",
                found: format!("major type {}", major),
            })
        }
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        self.deserialize_str(visitor)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DecodeError> {
        self.deserialize_any(visitor)
    }
}

/// Sequence accessor for arrays
struct SeqAccessor<'a, R: Read> {
    de: &'a mut Deserializer<R>,
    remaining: usize,
}

impl<'de, 'a, R: Read> SeqAccess<'de> for SeqAccessor<'a, R> {
    type Error = DecodeError;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, DecodeError> {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        seed.deserialize(&mut *self.de).map(Some)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.remaining)
    }
}

/// Map accessor for maps
struct MapAccessor<'a, R: Read> {
    de: &'a mut Deserializer<R>,
    remaining: usize,
    /// Previous key for ordering validation: (byte_length, utf8_bytes)
    last_key: Option<(usize, Vec<u8>)>,
}

impl<'de, 'a, R: Read> MapAccess<'de> for MapAccessor<'a, R> {
    type Error = DecodeError;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, DecodeError> {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;

        if self.de.config.strict {
            // Validate key is a string
            let byte = self.de.decoder.peek_byte()?;
            let major = byte >> 5;
            if major != 3 {
                return Err(DecodeError::MapKeyNotString);
            }

            // Decode key directly to validate ordering and duplicates
            let item = self.de.decode_item()?;
            let key_str = match item {
                CborItem::Text(s) => s,
                _ => return Err(DecodeError::MapKeyNotString),
            };

            // Validate ordering: DAG-CBOR canonical order for text strings
            // is (length, bytes) — shorter strings first, then lexicographic.
            let key_bytes = key_str.as_bytes();
            if let Some((prev_len, ref prev_bytes)) = self.last_key {
                let ordering = key_bytes
                    .len()
                    .cmp(&prev_len)
                    .then_with(|| key_bytes.cmp(prev_bytes.as_slice()));
                match ordering {
                    std::cmp::Ordering::Less => return Err(DecodeError::MapKeysNotSorted),
                    std::cmp::Ordering::Equal => return Err(DecodeError::DuplicateMapKey),
                    std::cmp::Ordering::Greater => {}
                }
            }
            self.last_key = Some((key_bytes.len(), key_bytes.to_vec()));

            // Pass the decoded key string to serde via StrDeserializer
            let str_de = de::value::StrDeserializer::<DecodeError>::new(&key_str);
            return seed.deserialize(str_de).map(Some);
        }

        seed.deserialize(&mut *self.de).map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, DecodeError> {
        seed.deserialize(&mut *self.de)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.remaining)
    }
}

/// Unit variant accessor for enums
struct UnitVariantAccess {
    variant: String,
}

impl<'de> de::EnumAccess<'de> for UnitVariantAccess {
    type Error = DecodeError;
    type Variant = UnitVariant;

    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant), DecodeError> {
        let variant = seed.deserialize(de::value::StrDeserializer::<DecodeError>::new(
            &self.variant,
        ))?;
        Ok((variant, UnitVariant))
    }
}

/// Unit variant for enums
struct UnitVariant;

impl<'de> de::VariantAccess<'de> for UnitVariant {
    type Error = DecodeError;

    fn unit_variant(self) -> Result<(), DecodeError> {
        Ok(())
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(
        self,
        _seed: T,
    ) -> Result<T::Value, DecodeError> {
        Err(DecodeError::InvalidCbor {
            reason: "expected unit variant".to_string(),
        })
    }

    fn tuple_variant<V: Visitor<'de>>(
        self,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value, DecodeError> {
        Err(DecodeError::InvalidCbor {
            reason: "expected unit variant".to_string(),
        })
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, DecodeError> {
        Err(DecodeError::InvalidCbor {
            reason: "expected unit variant".to_string(),
        })
    }
}

/// Variant accessor for complex enum variants
struct VariantAccess<'a, R: Read> {
    de: &'a mut Deserializer<R>,
    variant: String,
}

impl<'de, 'a, R: Read> de::EnumAccess<'de> for VariantAccess<'a, R> {
    type Error = DecodeError;
    type Variant = Self;

    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant), DecodeError> {
        let variant = seed.deserialize(de::value::StrDeserializer::<DecodeError>::new(
            &self.variant,
        ))?;
        Ok((variant, self))
    }
}

impl<'de, 'a, R: Read> de::VariantAccess<'de> for VariantAccess<'a, R> {
    type Error = DecodeError;

    fn unit_variant(self) -> Result<(), DecodeError> {
        Err(DecodeError::InvalidCbor {
            reason: "expected complex variant, got unit".to_string(),
        })
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(
        self,
        seed: T,
    ) -> Result<T::Value, DecodeError> {
        seed.deserialize(self.de)
    }

    fn tuple_variant<V: Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, DecodeError> {
        de::Deserializer::deserialize_seq(self.de, visitor)
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, DecodeError> {
        de::Deserializer::deserialize_map(self.de, visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::io::Cursor;

    fn deserialize<'de, T: Deserialize<'de>>(bytes: &[u8]) -> Result<T, DecodeError> {
        let mut de = Deserializer::new(Cursor::new(bytes));
        T::deserialize(&mut de)
    }

    #[test]
    fn test_deserialize_primitives() {
        // Boolean
        assert!(!deserialize::<bool>(&[0xf4]).unwrap());
        assert!(deserialize::<bool>(&[0xf5]).unwrap());

        // Integers
        assert_eq!(deserialize::<u8>(&[0x00]).unwrap(), 0);
        assert_eq!(deserialize::<u8>(&[0x17]).unwrap(), 23);
        assert_eq!(deserialize::<u8>(&[0x18, 0x18]).unwrap(), 24);
        assert_eq!(deserialize::<i8>(&[0x20]).unwrap(), -1);

        // String
        assert_eq!(deserialize::<String>(&[0x60]).unwrap(), "");
        assert_eq!(deserialize::<String>(&[0x61, 0x61]).unwrap(), "a");
    }

    #[test]
    fn test_deserialize_array() {
        let arr: Vec<u8> = deserialize(&[0x83, 0x01, 0x02, 0x03]).unwrap();
        assert_eq!(arr, vec![1, 2, 3]);

        let empty: Vec<u8> = deserialize(&[0x80]).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_deserialize_struct() {
        #[derive(Deserialize, PartialEq, Debug)]
        struct Test {
            a: i32,
            b: i32,
        }

        // Map with sorted keys: "a" then "b"
        let bytes = vec![0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02];
        let t: Test = deserialize(&bytes).unwrap();
        assert_eq!(t, Test { a: 1, b: 2 });
    }

    #[test]
    fn test_deserialize_option() {
        let some: Option<i32> = deserialize(&[0x18, 0x2a]).unwrap();
        assert_eq!(some, Some(42));

        let none: Option<i32> = deserialize(&[0xf6]).unwrap();
        assert_eq!(none, None);
    }

    #[test]
    fn test_deserialize_enum() {
        #[derive(Deserialize, PartialEq, Debug)]
        enum Color {
            Red,
            Green,
            Blue,
        }

        // Unit variant as string
        let red: Color = deserialize(&[0x63, b'R', b'e', b'd']).unwrap();
        assert_eq!(red, Color::Red);
    }
}
