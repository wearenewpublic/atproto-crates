//! Generic wrapper type for AT Protocol lexicon structures with optional `$type` field handling.
//!
//! This module provides a flexible way to handle the `$type` discriminator field that
//! appears in many AT Protocol lexicon structures. The wrapper can be used when the
//! type field needs to be validated, automatically added during serialization, or
//! when it may not always be present.
//!
//! Both serde implementations are format-agnostic: they adapt the serializer
//! and the map they are handed rather than routing the value through
//! `serde_json::Value`. That is what makes the wrapper usable for DAG-CBOR --
//! a `cid-link` arrives as `visit_byte_buf` and a `bytes` field as
//! `visit_bytes`, and neither has a JSON representation to be collected into,
//! so a record carrying either could not be read at all and a `bytes` field
//! was written as an array of integers, changing the record's CID. It also
//! takes a throwaway JSON document per record off the write path.

use serde::de::value::{MapAccessDeserializer, StringDeserializer};
use serde::de::{DeserializeSeed, IntoDeserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, SerializeStruct};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::marker::PhantomData;

/// A trait for types that have an associated lexicon type identifier.
pub trait LexiconType {
    /// Returns the lexicon type identifier (e.g., "community.lexicon.attestation.signature").
    fn lexicon_type() -> &'static str;

    /// Returns whether the type field is required for this lexicon type.
    /// Default is true, but types can override this for optional type fields.
    fn type_required() -> bool {
        true
    }
}

/// A wrapper type that handles the `$type` field for AT Protocol lexicon structures.
///
/// This wrapper provides flexibility in handling the type field:
/// - Conditionally adds the `$type` field during serialization based on `type_present`
/// - Validates the `$type` during deserialization if present
/// - Preserves the presence/absence of `$type` for round-trip compatibility
/// - Can handle cases where the `$type` field is optional
///
/// # Serialization Behavior
///
/// - When created with `TypedLexicon::new()`, the `$type` field will be included in serialization
/// - When created with `TypedLexicon::new_without_type()`, the `$type` field will be omitted
/// - When deserialized, the presence of `$type` is preserved for round-trip compatibility
///
/// # Example
///
/// ```
/// use atproto_record::typed::{TypedLexicon, LexiconType};
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Debug, PartialEq, Serialize, Deserialize)]
/// struct MyRecord {
///     name: String,
///     value: i32,
/// }
///
/// impl LexiconType for MyRecord {
///     fn lexicon_type() -> &'static str {
///         "com.example.myrecord"
///     }
/// }
///
/// // With type field
/// let record = MyRecord { name: "test".to_string(), value: 42 };
/// let typed = TypedLexicon::new(record);
/// let json = serde_json::to_string(&typed).unwrap();
/// assert!(json.contains("\"$type\":\"com.example.myrecord\""));
///
/// // Without type field
/// let record2 = MyRecord { name: "test2".to_string(), value: 43 };
/// let typed2 = TypedLexicon::new_without_type(record2);
/// let json2 = serde_json::to_string(&typed2).unwrap();
/// assert!(!json2.contains("\"$type\""));
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct TypedLexicon<T: LexiconType + PartialEq> {
    /// The inner value being wrapped
    pub inner: T,
    /// Whether the type field was explicitly present during deserialization
    type_present: bool,
}

impl<T: LexiconType + PartialEq> TypedLexicon<T> {
    /// Creates a new TypedLexicon wrapper that will include the `$type` field when serialized.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            type_present: true,
        }
    }

    /// Creates a new TypedLexicon wrapper that will NOT include the `$type` field when serialized.
    pub fn new_without_type(inner: T) -> Self {
        Self {
            inner,
            type_present: false,
        }
    }

    /// Returns whether the type field was present during deserialization.
    pub fn has_type_field(&self) -> bool {
        self.type_present
    }

    /// Validates that the type field is present if required.
    pub fn validate(&self) -> Result<(), String> {
        if T::type_required() && !self.type_present {
            return Err(format!(
                "Missing required $type field for {}",
                T::lexicon_type()
            ));
        }
        Ok(())
    }

    /// Consumes the wrapper and returns the inner value.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> Serialize for TypedLexicon<T>
where
    T: LexiconType + Serialize + PartialEq,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !self.type_present {
            return self.inner.serialize(serializer);
        }
        self.inner.serialize(TypePrefixed {
            inner: serializer,
            lexicon_type: T::lexicon_type(),
        })
    }
}

/// A value serialized with `$type` written into its map.
///
/// Exists so [`TypePrefixed`] can forward through `serialize_some` and
/// `serialize_newtype_struct`: those hand the inner value to the underlying
/// serializer, and the wrapper has to travel with it or the marker is lost on
/// an `Option<Record>` or a newtype around one.
struct WithType<'a, T: ?Sized> {
    value: &'a T,
    lexicon_type: &'static str,
}

impl<T> Serialize for WithType<'_, T>
where
    T: ?Sized + Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.value.serialize(TypePrefixed {
            inner: serializer,
            lexicon_type: self.lexicon_type,
        })
    }
}

/// A serializer that writes `$type` into whatever map the value opens.
///
/// The alternative -- and what this replaced -- is `serde_json::to_value`, an
/// insert, and a re-emit. That works only for a format `serde_json::Value` can
/// represent, so it materializes every record as a throwaway JSON document on
/// the write path and cannot encode DAG-CBOR at all.
///
/// Everything but a map or a struct is passed straight through. A lexicon
/// record is neither, so nothing is silently dropped; a `T` that serializes as
/// a scalar simply gets no `$type`, which is what the previous implementation
/// did with the same input.
///
/// A struct is opened as a map. Both are maps on the wire in every format this
/// is used with, and it keeps one code path rather than two. DAG-CBOR sorts
/// map keys as it encodes, so writing `$type` first does not disturb canonical
/// ordering.
struct TypePrefixed<S> {
    inner: S,
    lexicon_type: &'static str,
}

/// A map with `$type` already written into it.
struct PrefixedMap<M> {
    inner: M,
}

impl<M: SerializeMap> SerializeMap for PrefixedMap<M> {
    type Ok = M::Ok;
    type Error = M::Error;

    fn serialize_key<K: ?Sized + Serialize>(&mut self, key: &K) -> Result<(), Self::Error> {
        self.inner.serialize_key(key)
    }

    fn serialize_value<V: ?Sized + Serialize>(&mut self, value: &V) -> Result<(), Self::Error> {
        self.inner.serialize_value(value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.inner.end()
    }
}

impl<M: SerializeMap> SerializeStruct for PrefixedMap<M> {
    type Ok = M::Ok;
    type Error = M::Error;

    fn serialize_field<V: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &V,
    ) -> Result<(), Self::Error> {
        self.inner.serialize_entry(key, value)
    }

    fn skip_field(&mut self, _key: &'static str) -> Result<(), Self::Error> {
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.inner.end()
    }
}

impl<S: Serializer> Serializer for TypePrefixed<S> {
    type Ok = S::Ok;
    type Error = S::Error;

    type SerializeSeq = S::SerializeSeq;
    type SerializeTuple = S::SerializeTuple;
    type SerializeTupleStruct = S::SerializeTupleStruct;
    type SerializeTupleVariant = S::SerializeTupleVariant;
    type SerializeMap = PrefixedMap<S::SerializeMap>;
    type SerializeStruct = PrefixedMap<S::SerializeMap>;
    type SerializeStructVariant = S::SerializeStructVariant;

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        let mut inner = self.inner.serialize_map(len.map(|len| len + 1))?;
        inner.serialize_entry("$type", self.lexicon_type)?;
        Ok(PrefixedMap { inner })
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        let mut inner = self.inner.serialize_map(Some(len + 1))?;
        inner.serialize_entry("$type", self.lexicon_type)?;
        Ok(PrefixedMap { inner })
    }

    fn serialize_some<V: ?Sized + Serialize>(self, value: &V) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_some(&WithType {
            value,
            lexicon_type: self.lexicon_type,
        })
    }

    fn serialize_newtype_struct<V: ?Sized + Serialize>(
        self,
        name: &'static str,
        value: &V,
    ) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_newtype_struct(
            name,
            &WithType {
                value,
                lexicon_type: self.lexicon_type,
            },
        )
    }

    fn serialize_bool(self, v: bool) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_bool(v)
    }
    fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_i8(v)
    }
    fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_i16(v)
    }
    fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_i32(v)
    }
    fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_i64(v)
    }
    fn serialize_i128(self, v: i128) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_i128(v)
    }
    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_u8(v)
    }
    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_u16(v)
    }
    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_u32(v)
    }
    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_u64(v)
    }
    fn serialize_u128(self, v: u128) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_u128(v)
    }
    fn serialize_f32(self, v: f32) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_f32(v)
    }
    fn serialize_f64(self, v: f64) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_f64(v)
    }
    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_char(v)
    }
    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_str(v)
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_bytes(v)
    }
    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_none()
    }
    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_unit()
    }
    fn serialize_unit_struct(self, name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_unit_struct(name)
    }
    fn serialize_unit_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_unit_variant(name, index, variant)
    }
    fn serialize_newtype_variant<V: ?Sized + Serialize>(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        value: &V,
    ) -> Result<Self::Ok, Self::Error> {
        self.inner
            .serialize_newtype_variant(name, index, variant, value)
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        self.inner.serialize_seq(len)
    }
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.inner.serialize_tuple(len)
    }
    fn serialize_tuple_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.inner.serialize_tuple_struct(name, len)
    }
    fn serialize_tuple_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        self.inner
            .serialize_tuple_variant(name, index, variant, len)
    }
    fn serialize_struct_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        self.inner
            .serialize_struct_variant(name, index, variant, len)
    }

    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
}

impl<'de, T> Deserialize<'de> for TypedLexicon<T>
where
    T: LexiconType + Deserialize<'de> + PartialEq,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TypedLexiconVisitor<T: LexiconType + PartialEq>(PhantomData<T>);

        impl<'de, T> Visitor<'de> for TypedLexiconVisitor<T>
        where
            T: LexiconType + Deserialize<'de> + PartialEq,
        {
            type Value = TypedLexicon<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a lexicon object")
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut type_present = false;
                let inner = T::deserialize(MapAccessDeserializer::new(TypeFiltering {
                    inner: map,
                    expected: T::lexicon_type(),
                    type_present: &mut type_present,
                }))?;

                Ok(TypedLexicon {
                    inner,
                    type_present,
                })
            }
        }

        deserializer.deserialize_map(TypedLexiconVisitor(PhantomData))
    }
}

/// A map that consumes and validates `$type` before `T` ever sees it.
///
/// The alternative -- and what this replaced -- is collecting every entry into
/// a `serde_json::Value` and deserializing `T` from that. It cannot work off
/// the firehose: DAG-CBOR surfaces a tag-42 CID link as `visit_byte_buf` and a
/// byte string as `visit_bytes`, and neither has a `serde_json::Value` to be
/// collected into, so any record carrying a `cid-link` or a `bytes` field
/// failed at runtime. Most records worth indexing carry one.
///
/// Keys are read as `String` rather than borrowed, which is what the previous
/// implementation did too. Borrowing them would need the key type to be part
/// of this struct's signature, and a key is short.
struct TypeFiltering<'a, A> {
    inner: A,
    expected: &'static str,
    type_present: &'a mut bool,
}

impl<'de, A> MapAccess<'de> for TypeFiltering<'_, A>
where
    A: MapAccess<'de>,
{
    type Error = A::Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: DeserializeSeed<'de>,
    {
        loop {
            let Some(key) = self.inner.next_key::<String>()? else {
                return Ok(None);
            };

            if key != "$type" {
                let key: StringDeserializer<Self::Error> = key.into_deserializer();
                return seed.deserialize(key).map(Some);
            }

            // Read as a string rather than as a format-specific value: a
            // CBOR text string is as acceptable here as a JSON one, and both
            // are the only thing a `$type` may be.
            let found = self.inner.next_value::<String>().map_err(|_| {
                <Self::Error as serde::de::Error>::custom("$type field must be a string")
            })?;

            if found != self.expected {
                return Err(<Self::Error as serde::de::Error>::custom(format!(
                    "Invalid $type field: expected '{}', found '{}'",
                    self.expected, found
                )));
            }

            *self.type_present = true;
        }
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        self.inner.next_value_seed(seed)
    }

    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}

// Allow dereferencing to the inner type
impl<T: LexiconType + PartialEq> std::ops::Deref for TypedLexicon<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: LexiconType + PartialEq> std::ops::DerefMut for TypedLexicon<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
    struct TestRecord {
        name: String,
        value: i32,
    }

    impl LexiconType for TestRecord {
        fn lexicon_type() -> &'static str {
            "test.lexicon.record"
        }
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
    struct OptionalTypeRecord {
        data: String,
    }

    impl LexiconType for OptionalTypeRecord {
        fn lexicon_type() -> &'static str {
            "test.lexicon.optional"
        }

        fn type_required() -> bool {
            false
        }
    }

    #[test]
    fn test_serialization_adds_type() {
        let record = TestRecord {
            name: "test".to_string(),
            value: 42,
        };
        let typed = TypedLexicon::new(record);

        let json = serde_json::to_value(&typed).unwrap();

        assert_eq!(json["$type"], "test.lexicon.record");
        assert_eq!(json["name"], "test");
        assert_eq!(json["value"], 42);
    }

    #[test]
    fn test_deserialization_validates_type() {
        let json = json!({
            "$type": "test.lexicon.record",
            "name": "test",
            "value": 42
        });

        let typed: TypedLexicon<TestRecord> = serde_json::from_value(json).unwrap();

        assert_eq!(typed.inner.name, "test");
        assert_eq!(typed.inner.value, 42);
        assert!(typed.has_type_field());
    }

    #[test]
    fn test_deserialization_without_type() {
        let json = json!({
            "name": "test",
            "value": 42
        });

        let typed: TypedLexicon<TestRecord> = serde_json::from_value(json).unwrap();

        assert_eq!(typed.inner.name, "test");
        assert_eq!(typed.inner.value, 42);
        assert!(!typed.has_type_field());
    }

    #[test]
    fn test_deserialization_wrong_type() {
        let json = json!({
            "$type": "wrong.type",
            "name": "test",
            "value": 42
        });

        let result: Result<TypedLexicon<TestRecord>, _> = serde_json::from_value(json);
        assert!(result.is_err());

        let err = result.unwrap_err().to_string();
        assert!(err.contains("expected 'test.lexicon.record'"));
        assert!(err.contains("found 'wrong.type'"));
    }

    #[test]
    fn test_validation_required_type() {
        let typed = TypedLexicon::new_without_type(TestRecord {
            name: "test".to_string(),
            value: 42,
        });

        let result = typed.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing required $type field"));
    }

    #[test]
    fn test_validation_optional_type() {
        let typed = TypedLexicon::new_without_type(OptionalTypeRecord {
            data: "test".to_string(),
        });

        let result = typed.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_round_trip() {
        let original = TestRecord {
            name: "round trip".to_string(),
            value: 123,
        };
        let typed = TypedLexicon::new(original.clone());

        let json = serde_json::to_string(&typed).unwrap();
        let deserialized: TypedLexicon<TestRecord> = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.inner, original);
        assert!(deserialized.has_type_field());
    }

    #[test]
    fn test_deref() {
        let typed = TypedLexicon::new(TestRecord {
            name: "deref test".to_string(),
            value: 456,
        });

        // Can access fields through deref
        assert_eq!(typed.name, "deref test");
        assert_eq!(typed.value, 456);
    }

    #[test]
    fn test_new_without_type_omits_type_field() {
        let record = TestRecord {
            name: "no type".to_string(),
            value: 99,
        };
        let typed = TypedLexicon::new_without_type(record);

        let json = serde_json::to_value(&typed).unwrap();

        // Should NOT have $type field
        assert!(!json.as_object().unwrap().contains_key("$type"));
        assert_eq!(json["name"], "no type");
        assert_eq!(json["value"], 99);
    }

    #[test]
    fn test_round_trip_preserves_type_absence() {
        // Deserialize without $type
        let json_without_type = json!({
            "name": "test",
            "value": 42
        });

        let typed: TypedLexicon<TestRecord> = serde_json::from_value(json_without_type).unwrap();
        assert!(!typed.has_type_field());

        // Re-serialize should NOT add $type
        let reserialized = serde_json::to_value(&typed).unwrap();
        assert!(!reserialized.as_object().unwrap().contains_key("$type"));
        assert_eq!(reserialized["name"], "test");
        assert_eq!(reserialized["value"], 42);
    }

    #[test]
    fn test_round_trip_preserves_type_presence() {
        // Deserialize with $type
        let json_with_type = json!({
            "$type": "test.lexicon.record",
            "name": "test",
            "value": 42
        });

        let typed: TypedLexicon<TestRecord> = serde_json::from_value(json_with_type).unwrap();
        assert!(typed.has_type_field());

        // Re-serialize should preserve $type
        let reserialized = serde_json::to_value(&typed).unwrap();
        assert_eq!(reserialized["$type"], "test.lexicon.record");
        assert_eq!(reserialized["name"], "test");
        assert_eq!(reserialized["value"], 42);
    }

    /// A record with a `cid-link` field, which is what a lexicon calls a
    /// `Cid` and what the firehose is full of.
    #[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
    struct LinkRecord {
        subject: atproto_dasl::Cid,
        text: String,
    }

    impl LexiconType for LinkRecord {
        fn lexicon_type() -> &'static str {
            "test.lexicon.link"
        }
    }

    /// A record with a `bytes` field.
    #[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
    struct BytesRecord {
        #[serde(with = "serde_bytes")]
        payload: Vec<u8>,
    }

    impl LexiconType for BytesRecord {
        fn lexicon_type() -> &'static str {
            "test.lexicon.bytes"
        }
    }

    fn a_cid() -> atproto_dasl::Cid {
        atproto_dasl::Cid(atproto_dasl::compute_cid_for(&"a block").expect("compute a cid"))
    }

    /// The failure this change exists for.
    ///
    /// DAG-CBOR surfaces a tag-42 CID link through `visit_byte_buf`, which has
    /// no `serde_json::Value` to be collected into -- so the previous
    /// implementation could not deserialize any record carrying one, which is
    /// most records worth indexing. It failed at runtime rather than at
    /// compile time, which is why two parallel type families were being
    /// maintained downstream to avoid it.
    #[test]
    fn a_cid_link_survives_a_dag_cbor_round_trip() {
        let record = LinkRecord {
            subject: a_cid(),
            text: "hello".to_string(),
        };
        let typed = TypedLexicon::new(record.clone());

        let encoded = atproto_dasl::to_vec(&typed).expect("encode");
        let decoded: TypedLexicon<LinkRecord> = atproto_dasl::from_slice(&encoded).expect("decode");

        assert_eq!(decoded.inner, record);
        assert!(decoded.has_type_field());
    }

    /// A `bytes` field stays a byte string on the wire.
    ///
    /// The value round-tripped under the old implementation too, which is
    /// what made this hard to see: `serde_json::Value` has no byte string, so
    /// the field was encoded as a CBOR *array of integers* and decoded back
    /// into a `Vec<u8>` unharmed. The bytes differ, so the record's CID
    /// differs, and a CID is the one thing about a record that has to be
    /// reproducible. Hence the assertion on the encoded form rather than on
    /// the value.
    #[test]
    fn a_bytes_field_stays_a_byte_string_through_dag_cbor() {
        let record = BytesRecord {
            payload: vec![0x00, 0xff, 0x42],
        };
        let typed = TypedLexicon::new(record.clone());

        let encoded = atproto_dasl::to_vec(&typed).expect("encode");
        let decoded: TypedLexicon<BytesRecord> =
            atproto_dasl::from_slice(&encoded).expect("decode");
        assert_eq!(decoded.inner, record);

        let ipld: atproto_dasl::Ipld = atproto_dasl::from_slice(&encoded).expect("as ipld");
        let atproto_dasl::Ipld::Map(map) = ipld else {
            panic!("a record encodes as a map");
        };
        assert!(
            matches!(map.get("payload"), Some(atproto_dasl::Ipld::Bytes(_))),
            "payload encoded as {:?}",
            map.get("payload")
        );
    }

    /// `$type` is written first and the encoding is still canonical.
    ///
    /// `$type` is five bytes, so it sorts *after* a shorter key under
    /// DAG-CBOR's length-first ordering -- writing it first would be wrong if
    /// the encoder emitted keys in the order it received them. It sorts as it
    /// encodes, and a strict decode validates that ordering, so a successful
    /// strict round trip is the assertion.
    #[test]
    fn the_type_marker_does_not_disturb_canonical_key_ordering() {
        let typed = TypedLexicon::new(LinkRecord {
            subject: a_cid(),
            text: "hello".to_string(),
        });

        let encoded = atproto_dasl::to_vec(&typed).expect("encode");

        // `text` is four bytes and `$type` five, so canonical order puts the
        // marker second. Strict decoding refuses anything else.
        atproto_dasl::from_slice::<TypedLexicon<LinkRecord>>(&encoded).expect("canonical");
    }

    /// A wrong `$type` is refused in DAG-CBOR as it is in JSON.
    #[test]
    fn a_wrong_type_marker_is_refused_in_dag_cbor() {
        let encoded = atproto_dasl::to_vec(&TypedLexicon::new(BytesRecord {
            payload: vec![1, 2, 3],
        }))
        .expect("encode");

        let result: Result<TypedLexicon<LinkRecord>, _> = atproto_dasl::from_slice(&encoded);
        let error = result.expect_err("a marker for another type").to_string();
        assert!(error.contains("test.lexicon.link"), "{error}");
    }

    /// An absent marker still round-trips, and still leaves `type_present`
    /// false for a type that does not require one.
    #[test]
    fn an_absent_marker_round_trips_through_dag_cbor() {
        let typed = TypedLexicon::new_without_type(OptionalTypeRecord {
            data: "no marker".to_string(),
        });

        let encoded = atproto_dasl::to_vec(&typed).expect("encode");
        let decoded: TypedLexicon<OptionalTypeRecord> =
            atproto_dasl::from_slice(&encoded).expect("decode");

        assert!(!decoded.has_type_field());
        assert!(decoded.validate().is_ok());
        assert_eq!(decoded.inner.data, "no marker");
    }

    /// This module must not reach for `serde_json` again.
    ///
    /// Both serde impls used to route through `serde_json::Value`, which is
    /// the whole defect: it allocates a throwaway JSON document per record on
    /// the write path and cannot represent DAG-CBOR at all on the read path.
    /// The tests below are the only place the name may still appear.
    #[test]
    fn the_implementation_holds_no_serde_json() {
        let source = include_str!("typed.rs");
        let implementation = source
            .split("#[cfg(test)]")
            .next()
            .expect("the module above its tests");

        for (number, line) in implementation.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            assert!(!code.contains("serde_json"), "line {}: {line}", number + 1);
        }
    }

    #[test]
    fn test_optional_type_record_behavior() {
        // Test with type_required() = false

        // new() should still add $type
        let with_type = TypedLexicon::new(OptionalTypeRecord {
            data: "with".to_string(),
        });
        let json = serde_json::to_value(&with_type).unwrap();
        assert_eq!(json["$type"], "test.lexicon.optional");

        // new_without_type() should omit $type
        let without_type = TypedLexicon::new_without_type(OptionalTypeRecord {
            data: "without".to_string(),
        });
        let json2 = serde_json::to_value(&without_type).unwrap();
        assert!(!json2.as_object().unwrap().contains_key("$type"));

        // Both should validate successfully since type is optional
        assert!(with_type.validate().is_ok());
        assert!(without_type.validate().is_ok());
    }
}
