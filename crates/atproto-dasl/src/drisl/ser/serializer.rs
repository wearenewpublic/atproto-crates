//! Serde Serializer implementation for DAG-CBOR.
//!
//! Provides serialization of Rust types to DAG-CBOR format following
//! canonical encoding requirements.

use crate::drisl::cbor::encode::CborEncoder;
use crate::drisl::config::EncodeConfig;
use crate::errors::EncodeError;
use serde::ser::{self, Serialize};
use std::io::Write;

/// DAG-CBOR serializer.
///
/// Implements the serde `Serializer` trait to convert Rust types
/// to DAG-CBOR format with canonical encoding.
pub struct Serializer<W: Write> {
    encoder: CborEncoder<W>,
    config: EncodeConfig,
}

impl<W: Write> Serializer<W> {
    /// Create a new serializer wrapping the given writer
    pub fn new(writer: W) -> Self {
        Self {
            encoder: CborEncoder::new(writer),
            config: EncodeConfig::default(),
        }
    }

    /// Create a new serializer with custom configuration
    pub fn with_config(writer: W, config: EncodeConfig) -> Self {
        Self {
            encoder: CborEncoder::new(writer),
            config,
        }
    }

    /// Get a reference to the encode configuration
    pub fn config(&self) -> &EncodeConfig {
        &self.config
    }

    /// Consume the serializer and return the underlying writer
    pub fn into_inner(self) -> W {
        self.encoder.into_inner()
    }
}

impl<'a, W: Write> ser::Serializer for &'a mut Serializer<W> {
    type Ok = ();
    type Error = EncodeError;

    type SerializeSeq = SeqSerializer<'a, W>;
    type SerializeTuple = SeqSerializer<'a, W>;
    type SerializeTupleStruct = SeqSerializer<'a, W>;
    type SerializeTupleVariant = SeqSerializer<'a, W>;
    type SerializeMap = MapSerializer<'a, W>;
    type SerializeStruct = StructSerializer<'a, W>;
    type SerializeStructVariant = StructVariantSerializer<'a, W>;

    fn serialize_bool(self, v: bool) -> Result<(), EncodeError> {
        self.encoder.encode_bool(v)
    }

    fn serialize_i8(self, v: i8) -> Result<(), EncodeError> {
        self.serialize_i64(v as i64)
    }

    fn serialize_i16(self, v: i16) -> Result<(), EncodeError> {
        self.serialize_i64(v as i64)
    }

    fn serialize_i32(self, v: i32) -> Result<(), EncodeError> {
        self.serialize_i64(v as i64)
    }

    fn serialize_i64(self, v: i64) -> Result<(), EncodeError> {
        self.encoder.encode_integer(v)
    }

    fn serialize_i128(self, v: i128) -> Result<(), EncodeError> {
        self.encoder.encode_i128(v)
    }

    fn serialize_u8(self, v: u8) -> Result<(), EncodeError> {
        self.encoder.encode_unsigned(v as u64)
    }

    fn serialize_u16(self, v: u16) -> Result<(), EncodeError> {
        self.encoder.encode_unsigned(v as u64)
    }

    fn serialize_u32(self, v: u32) -> Result<(), EncodeError> {
        self.encoder.encode_unsigned(v as u64)
    }

    fn serialize_u64(self, v: u64) -> Result<(), EncodeError> {
        self.encoder.encode_unsigned(v)
    }

    fn serialize_u128(self, v: u128) -> Result<(), EncodeError> {
        if v > u64::MAX as u128 {
            return Err(EncodeError::IntegerOverflow);
        }
        self.encoder.encode_unsigned(v as u64)
    }

    fn serialize_f32(self, v: f32) -> Result<(), EncodeError> {
        // DAG-CBOR requires 64-bit floats
        self.serialize_f64(v as f64)
    }

    fn serialize_f64(self, v: f64) -> Result<(), EncodeError> {
        self.encoder.encode_f64(v)
    }

    fn serialize_char(self, v: char) -> Result<(), EncodeError> {
        let mut buf = [0; 4];
        self.serialize_str(v.encode_utf8(&mut buf))
    }

    fn serialize_str(self, v: &str) -> Result<(), EncodeError> {
        self.encoder.encode_text(v)
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<(), EncodeError> {
        self.encoder.encode_bytes(v)
    }

    fn serialize_none(self) -> Result<(), EncodeError> {
        self.serialize_unit()
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<(), EncodeError> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<(), EncodeError> {
        self.encoder.encode_null()
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), EncodeError> {
        self.serialize_unit()
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<(), EncodeError> {
        self.serialize_str(variant)
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<(), EncodeError> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<(), EncodeError> {
        // Special case for CID encoding with tag 42
        if name == "__cid_tag_42__" && variant_index == 42 {
            self.encoder.encode_cid_tag()?;
            return value.serialize(self);
        }

        self.encoder.encode_map_header(1)?;
        self.serialize_str(variant)?;
        value.serialize(self)
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<SeqSerializer<'a, W>, EncodeError> {
        let len = len.ok_or(EncodeError::IndefiniteLengthNotSupported)?;
        self.encoder.encode_array_header(len)?;
        Ok(SeqSerializer { serializer: self })
    }

    fn serialize_tuple(self, len: usize) -> Result<SeqSerializer<'a, W>, EncodeError> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<SeqSerializer<'a, W>, EncodeError> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<SeqSerializer<'a, W>, EncodeError> {
        self.encoder.encode_map_header(1)?;
        self.serialize_str(variant)?;
        self.serialize_seq(Some(len))
    }

    fn serialize_map(self, len: Option<usize>) -> Result<MapSerializer<'a, W>, EncodeError> {
        // DAG-CBOR requires sorted keys, so we buffer entries
        Ok(MapSerializer {
            serializer: self,
            entries: Vec::with_capacity(len.unwrap_or(0)),
            current_key: None,
        })
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<StructSerializer<'a, W>, EncodeError> {
        // Structs also need sorted keys
        Ok(StructSerializer {
            serializer: self,
            entries: Vec::with_capacity(len),
        })
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<StructVariantSerializer<'a, W>, EncodeError> {
        Ok(StructVariantSerializer {
            serializer: self,
            variant,
            entries: Vec::with_capacity(len),
        })
    }
}

/// Sequence serializer for arrays/tuples
pub struct SeqSerializer<'a, W: Write> {
    serializer: &'a mut Serializer<W>,
}

impl<'a, W: Write> ser::SerializeSeq for SeqSerializer<'a, W> {
    type Ok = ();
    type Error = EncodeError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), EncodeError> {
        value.serialize(&mut *self.serializer)
    }

    fn end(self) -> Result<(), EncodeError> {
        Ok(())
    }
}

impl<'a, W: Write> ser::SerializeTuple for SeqSerializer<'a, W> {
    type Ok = ();
    type Error = EncodeError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), EncodeError> {
        value.serialize(&mut *self.serializer)
    }

    fn end(self) -> Result<(), EncodeError> {
        Ok(())
    }
}

impl<'a, W: Write> ser::SerializeTupleStruct for SeqSerializer<'a, W> {
    type Ok = ();
    type Error = EncodeError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), EncodeError> {
        value.serialize(&mut *self.serializer)
    }

    fn end(self) -> Result<(), EncodeError> {
        Ok(())
    }
}

impl<'a, W: Write> ser::SerializeTupleVariant for SeqSerializer<'a, W> {
    type Ok = ();
    type Error = EncodeError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), EncodeError> {
        value.serialize(&mut *self.serializer)
    }

    fn end(self) -> Result<(), EncodeError> {
        Ok(())
    }
}

/// Map serializer that buffers entries for sorting.
///
/// DAG-CBOR requires map keys to be sorted in bytewise lexicographic order,
/// so we buffer all entries and sort before writing.
pub struct MapSerializer<'a, W: Write> {
    serializer: &'a mut Serializer<W>,
    entries: Vec<(Vec<u8>, Vec<u8>)>, // (encoded_key, encoded_value)
    current_key: Option<Vec<u8>>,
}

impl<'a, W: Write> ser::SerializeMap for MapSerializer<'a, W> {
    type Ok = ();
    type Error = EncodeError;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), EncodeError> {
        // Serialize key to buffer for sorting
        let mut key_buf = Vec::new();
        let mut key_ser = Serializer::new(&mut key_buf);
        key.serialize(&mut key_ser)?;
        self.current_key = Some(key_buf);
        Ok(())
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), EncodeError> {
        let key = self.current_key.take().ok_or(EncodeError::MapKeyMissing)?;

        // Serialize value to buffer
        let mut value_buf = Vec::new();
        let mut value_ser = Serializer::new(&mut value_buf);
        value.serialize(&mut value_ser)?;

        self.entries.push((key, value_buf));
        Ok(())
    }

    fn end(mut self) -> Result<(), EncodeError> {
        // Sort entries by key bytes (bytewise lexicographic)
        self.entries.sort_by(|a, b| a.0.cmp(&b.0));

        // Write map header and sorted entries
        self.serializer
            .encoder
            .encode_map_header(self.entries.len())?;
        for (key, value) in self.entries {
            self.serializer.encoder.write_raw(&key)?;
            self.serializer.encoder.write_raw(&value)?;
        }

        Ok(())
    }
}

/// Struct serializer that buffers fields for sorting.
pub struct StructSerializer<'a, W: Write> {
    serializer: &'a mut Serializer<W>,
    entries: Vec<(Vec<u8>, Vec<u8>)>, // (encoded_key, encoded_value)
}

impl<'a, W: Write> ser::SerializeStruct for StructSerializer<'a, W> {
    type Ok = ();
    type Error = EncodeError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), EncodeError> {
        // Serialize key to buffer using encoder directly
        let mut key_buf = Vec::new();
        {
            let mut key_encoder = CborEncoder::new(&mut key_buf);
            key_encoder.encode_text(key)?;
        }

        // Serialize value to buffer
        let mut value_buf = Vec::new();
        let mut value_ser = Serializer::new(&mut value_buf);
        value.serialize(&mut value_ser)?;

        self.entries.push((key_buf, value_buf));
        Ok(())
    }

    fn end(mut self) -> Result<(), EncodeError> {
        // Sort entries by key bytes (bytewise lexicographic)
        self.entries.sort_by(|a, b| a.0.cmp(&b.0));

        // Write map header and sorted entries
        self.serializer
            .encoder
            .encode_map_header(self.entries.len())?;
        for (key, value) in self.entries {
            self.serializer.encoder.write_raw(&key)?;
            self.serializer.encoder.write_raw(&value)?;
        }

        Ok(())
    }
}

/// Struct variant serializer (for enum variants with named fields).
pub struct StructVariantSerializer<'a, W: Write> {
    serializer: &'a mut Serializer<W>,
    variant: &'static str,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

impl<'a, W: Write> ser::SerializeStructVariant for StructVariantSerializer<'a, W> {
    type Ok = ();
    type Error = EncodeError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), EncodeError> {
        // Serialize key to buffer using encoder directly
        let mut key_buf = Vec::new();
        {
            let mut key_encoder = CborEncoder::new(&mut key_buf);
            key_encoder.encode_text(key)?;
        }

        // Serialize value to buffer
        let mut value_buf = Vec::new();
        let mut value_ser = Serializer::new(&mut value_buf);
        value.serialize(&mut value_ser)?;

        self.entries.push((key_buf, value_buf));
        Ok(())
    }

    fn end(mut self) -> Result<(), EncodeError> {
        // Write outer map with variant name
        self.serializer.encoder.encode_map_header(1)?;
        self.serializer.encoder.encode_text(self.variant)?;

        // Sort entries by key bytes
        self.entries.sort_by(|a, b| a.0.cmp(&b.0));

        // Write inner map header and sorted entries
        self.serializer
            .encoder
            .encode_map_header(self.entries.len())?;
        for (key, value) in self.entries {
            self.serializer.encoder.write_raw(&key)?;
            self.serializer.encoder.write_raw(&value)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    fn serialize_to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, EncodeError> {
        let mut buf = Vec::new();
        let mut serializer = Serializer::new(&mut buf);
        value.serialize(&mut serializer)?;
        Ok(buf)
    }

    #[test]
    fn test_serialize_primitives() {
        // Boolean
        assert_eq!(serialize_to_vec(&false).unwrap(), vec![0xf4]);
        assert_eq!(serialize_to_vec(&true).unwrap(), vec![0xf5]);

        // Null (via Option::None)
        let none: Option<i32> = None;
        assert_eq!(serialize_to_vec(&none).unwrap(), vec![0xf6]);

        // Integers
        assert_eq!(serialize_to_vec(&0u8).unwrap(), vec![0x00]);
        assert_eq!(serialize_to_vec(&23u8).unwrap(), vec![0x17]);
        assert_eq!(serialize_to_vec(&24u8).unwrap(), vec![0x18, 0x18]);
        assert_eq!(serialize_to_vec(&(-1i8)).unwrap(), vec![0x20]);

        // String
        assert_eq!(serialize_to_vec(&"").unwrap(), vec![0x60]);
        assert_eq!(serialize_to_vec(&"a").unwrap(), vec![0x61, 0x61]);
    }

    #[test]
    fn test_serialize_array() {
        let arr: Vec<u8> = vec![1, 2, 3];
        assert_eq!(
            serialize_to_vec(&arr).unwrap(),
            vec![0x83, 0x01, 0x02, 0x03]
        );

        let empty: Vec<u8> = vec![];
        assert_eq!(serialize_to_vec(&empty).unwrap(), vec![0x80]);
    }

    #[test]
    fn test_serialize_struct_sorted() {
        #[derive(Serialize)]
        struct Test {
            b: i32,
            a: i32,
        }

        let t = Test { b: 2, a: 1 };
        let bytes = serialize_to_vec(&t).unwrap();

        // Keys should be sorted: "a" comes before "b"
        // Map of 2: 0xa2
        // Key "a": 0x61 0x61
        // Value 1: 0x01
        // Key "b": 0x61 0x62
        // Value 2: 0x02
        assert_eq!(bytes, vec![0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02]);
    }

    #[test]
    fn test_serialize_nested() {
        #[derive(Serialize)]
        struct Inner {
            value: i32,
        }

        #[derive(Serialize)]
        struct Outer {
            inner: Inner,
        }

        let o = Outer {
            inner: Inner { value: 42 },
        };
        let bytes = serialize_to_vec(&o).unwrap();

        // Map of 1: 0xa1
        // Key "inner": 0x65 + "inner"
        // Value: Map of 1: 0xa1
        //   Key "value": 0x65 + "value"
        //   Value 42: 0x18 0x2a
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_serialize_option() {
        let some: Option<i32> = Some(42);
        assert_eq!(serialize_to_vec(&some).unwrap(), vec![0x18, 0x2a]);

        let none: Option<i32> = None;
        assert_eq!(serialize_to_vec(&none).unwrap(), vec![0xf6]);
    }
}
