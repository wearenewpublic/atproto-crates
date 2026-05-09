//! IPLD Data Model value representation.
//!
//! The IPLD Data Model defines a set of types that form the foundation
//! for content-addressed data structures. This module provides the
//! Rust representation of these types.

use crate::cid::Cid;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize, ser::SerializeMap};
use std::collections::BTreeMap;
use std::fmt;

/// IPLD Data Model value.
///
/// Represents any value in the IPLD Data Model, which includes:
/// - Null
/// - Boolean
/// - Integer (signed, up to 64-bit)
/// - Float (64-bit IEEE 754)
/// - String (UTF-8)
/// - Bytes (raw binary)
/// - List (ordered sequence)
/// - Map (string-keyed, ordered)
/// - Link (CID reference to another node)
#[derive(Clone, PartialEq)]
pub enum Ipld {
    /// Null value
    Null,
    /// Boolean value
    Bool(bool),
    /// Integer value (supports full CBOR range via i128)
    Integer(i128),
    /// Floating-point value (64-bit IEEE 754)
    Float(f64),
    /// UTF-8 string
    String(String),
    /// Raw bytes
    Bytes(Vec<u8>),
    /// Ordered list of values
    List(Vec<Ipld>),
    /// String-keyed map (BTreeMap for deterministic ordering)
    Map(BTreeMap<String, Ipld>),
    /// CID link to another IPLD node
    Link(Cid),
}

impl Ipld {
    /// Returns true if this is a null value
    pub fn is_null(&self) -> bool {
        matches!(self, Ipld::Null)
    }

    /// Returns true if this is a boolean value
    pub fn is_bool(&self) -> bool {
        matches!(self, Ipld::Bool(_))
    }

    /// Returns true if this is an integer value
    pub fn is_integer(&self) -> bool {
        matches!(self, Ipld::Integer(_))
    }

    /// Returns true if this is a float value
    pub fn is_float(&self) -> bool {
        matches!(self, Ipld::Float(_))
    }

    /// Returns true if this is a string value
    pub fn is_string(&self) -> bool {
        matches!(self, Ipld::String(_))
    }

    /// Returns true if this is a bytes value
    pub fn is_bytes(&self) -> bool {
        matches!(self, Ipld::Bytes(_))
    }

    /// Returns true if this is a list value
    pub fn is_list(&self) -> bool {
        matches!(self, Ipld::List(_))
    }

    /// Returns true if this is a map value
    pub fn is_map(&self) -> bool {
        matches!(self, Ipld::Map(_))
    }

    /// Returns true if this is a link (CID) value
    pub fn is_link(&self) -> bool {
        matches!(self, Ipld::Link(_))
    }

    /// Attempts to get as boolean
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Ipld::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Attempts to get as integer
    pub fn as_integer(&self) -> Option<i128> {
        match self {
            Ipld::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// Attempts to get as i64
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Ipld::Integer(i) if *i >= i64::MIN as i128 && *i <= i64::MAX as i128 => Some(*i as i64),
            _ => None,
        }
    }

    /// Attempts to get as u64
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Ipld::Integer(i) if *i >= 0 && *i <= u64::MAX as i128 => Some(*i as u64),
            _ => None,
        }
    }

    /// Attempts to get as float
    pub fn as_float(&self) -> Option<f64> {
        match self {
            Ipld::Float(f) => Some(*f),
            _ => None,
        }
    }

    /// Attempts to get as string reference
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Ipld::String(s) => Some(s),
            _ => None,
        }
    }

    /// Attempts to get as bytes reference
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Ipld::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Attempts to get as list reference
    pub fn as_list(&self) -> Option<&Vec<Ipld>> {
        match self {
            Ipld::List(l) => Some(l),
            _ => None,
        }
    }

    /// Attempts to get as mutable list reference
    pub fn as_list_mut(&mut self) -> Option<&mut Vec<Ipld>> {
        match self {
            Ipld::List(l) => Some(l),
            _ => None,
        }
    }

    /// Attempts to get as map reference
    pub fn as_map(&self) -> Option<&BTreeMap<String, Ipld>> {
        match self {
            Ipld::Map(m) => Some(m),
            _ => None,
        }
    }

    /// Attempts to get as mutable map reference
    pub fn as_map_mut(&mut self) -> Option<&mut BTreeMap<String, Ipld>> {
        match self {
            Ipld::Map(m) => Some(m),
            _ => None,
        }
    }

    /// Attempts to get as CID reference
    pub fn as_link(&self) -> Option<&Cid> {
        match self {
            Ipld::Link(c) => Some(c),
            _ => None,
        }
    }

    /// Get the type name for error messages
    pub fn type_name(&self) -> &'static str {
        match self {
            Ipld::Null => "null",
            Ipld::Bool(_) => "bool",
            Ipld::Integer(_) => "integer",
            Ipld::Float(_) => "float",
            Ipld::String(_) => "string",
            Ipld::Bytes(_) => "bytes",
            Ipld::List(_) => "list",
            Ipld::Map(_) => "map",
            Ipld::Link(_) => "link",
        }
    }
}

impl fmt::Debug for Ipld {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ipld::Null => write!(f, "Null"),
            Ipld::Bool(b) => write!(f, "Bool({:?})", b),
            Ipld::Integer(i) => write!(f, "Integer({})", i),
            Ipld::Float(fl) => write!(f, "Float({:?})", fl),
            Ipld::String(s) => write!(f, "String({:?})", s),
            Ipld::Bytes(b) => write!(f, "Bytes({:?})", b),
            Ipld::List(l) => write!(f, "List({:?})", l),
            Ipld::Map(m) => write!(f, "Map({:?})", m),
            Ipld::Link(c) => write!(f, "Link({:?})", c),
        }
    }
}

// Implement From for common types

impl From<bool> for Ipld {
    fn from(b: bool) -> Self {
        Ipld::Bool(b)
    }
}

impl From<i8> for Ipld {
    fn from(i: i8) -> Self {
        Ipld::Integer(i as i128)
    }
}

impl From<i16> for Ipld {
    fn from(i: i16) -> Self {
        Ipld::Integer(i as i128)
    }
}

impl From<i32> for Ipld {
    fn from(i: i32) -> Self {
        Ipld::Integer(i as i128)
    }
}

impl From<i64> for Ipld {
    fn from(i: i64) -> Self {
        Ipld::Integer(i as i128)
    }
}

impl From<i128> for Ipld {
    fn from(i: i128) -> Self {
        Ipld::Integer(i)
    }
}

impl From<u8> for Ipld {
    fn from(u: u8) -> Self {
        Ipld::Integer(u as i128)
    }
}

impl From<u16> for Ipld {
    fn from(u: u16) -> Self {
        Ipld::Integer(u as i128)
    }
}

impl From<u32> for Ipld {
    fn from(u: u32) -> Self {
        Ipld::Integer(u as i128)
    }
}

impl From<u64> for Ipld {
    fn from(u: u64) -> Self {
        Ipld::Integer(u as i128)
    }
}

impl From<f32> for Ipld {
    fn from(f: f32) -> Self {
        Ipld::Float(f as f64)
    }
}

impl From<f64> for Ipld {
    fn from(f: f64) -> Self {
        Ipld::Float(f)
    }
}

impl From<String> for Ipld {
    fn from(s: String) -> Self {
        Ipld::String(s)
    }
}

impl From<&str> for Ipld {
    fn from(s: &str) -> Self {
        Ipld::String(s.to_string())
    }
}

impl From<Vec<u8>> for Ipld {
    fn from(b: Vec<u8>) -> Self {
        Ipld::Bytes(b)
    }
}

impl From<&[u8]> for Ipld {
    fn from(b: &[u8]) -> Self {
        Ipld::Bytes(b.to_vec())
    }
}

impl From<Vec<Ipld>> for Ipld {
    fn from(l: Vec<Ipld>) -> Self {
        Ipld::List(l)
    }
}

impl From<BTreeMap<String, Ipld>> for Ipld {
    fn from(m: BTreeMap<String, Ipld>) -> Self {
        Ipld::Map(m)
    }
}

impl From<Cid> for Ipld {
    fn from(c: Cid) -> Self {
        Ipld::Link(c)
    }
}

impl<T: Into<Ipld>> FromIterator<T> for Ipld {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Ipld::List(iter.into_iter().map(Into::into).collect())
    }
}

// ============================================================================
// Serde Serialize Implementation
// ============================================================================

impl Serialize for Ipld {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Ipld::Null => serializer.serialize_unit(),
            Ipld::Bool(b) => serializer.serialize_bool(*b),
            Ipld::Integer(i) => {
                // Use the most appropriate integer type
                if *i >= 0 && *i <= u64::MAX as i128 {
                    serializer.serialize_u64(*i as u64)
                } else if *i >= i64::MIN as i128 && *i <= i64::MAX as i128 {
                    serializer.serialize_i64(*i as i64)
                } else {
                    serializer.serialize_i128(*i)
                }
            }
            Ipld::Float(f) => serializer.serialize_f64(*f),
            Ipld::String(s) => serializer.serialize_str(s),
            Ipld::Bytes(b) => serializer.serialize_bytes(b),
            Ipld::List(list) => {
                use serde::ser::SerializeSeq;
                let mut seq = serializer.serialize_seq(Some(list.len()))?;
                for item in list {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Ipld::Map(map) => {
                let mut m = serializer.serialize_map(Some(map.len()))?;
                for (k, v) in map {
                    m.serialize_entry(k, v)?;
                }
                m.end()
            }
            Ipld::Link(cid) => cid.serialize(serializer),
        }
    }
}

// ============================================================================
// Serde Deserialize Implementation
// ============================================================================

impl<'de> Deserialize<'de> for Ipld {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_any(IpldVisitor)
    }
}

struct IpldVisitor;

impl<'de> Visitor<'de> for IpldVisitor {
    type Value = Ipld;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("any valid IPLD value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Ipld::Bool(v))
    }

    fn visit_i8<E>(self, v: i8) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Ipld::Integer(v as i128))
    }

    fn visit_i16<E>(self, v: i16) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Ipld::Integer(v as i128))
    }

    fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Ipld::Integer(v as i128))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Ipld::Integer(v as i128))
    }

    fn visit_i128<E>(self, v: i128) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Ipld::Integer(v))
    }

    fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Ipld::Integer(v as i128))
    }

    fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Ipld::Integer(v as i128))
    }

    fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Ipld::Integer(v as i128))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Ipld::Integer(v as i128))
    }

    fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        // i128 can hold all u64 values but not all u128 values
        if v <= i128::MAX as u128 {
            Ok(Ipld::Integer(v as i128))
        } else {
            Err(de::Error::custom(format!(
                "u128 value {} exceeds i128::MAX",
                v
            )))
        }
    }

    fn visit_f32<E>(self, v: f32) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Ipld::Float(v as f64))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Ipld::Float(v))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Ipld::String(v.to_string()))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Ipld::String(v))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        // Check if this looks like a CID (from tag 42 handling in deserializer)
        // CIDs in DAG-CBOR have identity multibase prefix 0x00
        if !v.is_empty() && v[0] == 0x00 && v.len() > 1 {
            // Try to parse as CID
            if let Ok(cid) = Cid::from_dag_cbor_bytes(v) {
                return Ok(Ipld::Link(cid));
            }
        }
        Ok(Ipld::Bytes(v.to_vec()))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        // Check if this looks like a CID (from tag 42 handling in deserializer)
        if !v.is_empty() && v[0] == 0x00 && v.len() > 1 {
            // Try to parse as CID
            if let Ok(cid) = Cid::from_dag_cbor_bytes(&v) {
                return Ok(Ipld::Link(cid));
            }
        }
        Ok(Ipld::Bytes(v))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Ipld::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Ipld::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Ipld::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut list = Vec::new();
        if let Some(size) = seq.size_hint() {
            list.reserve(size);
        }
        while let Some(elem) = seq.next_element()? {
            list.push(elem);
        }
        Ok(Ipld::List(list))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut btree = BTreeMap::new();
        while let Some((key, value)) = map.next_entry()? {
            btree.insert(key, value);
        }
        Ok(Ipld::Map(btree))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_checks() {
        assert!(Ipld::Null.is_null());
        assert!(Ipld::Bool(true).is_bool());
        assert!(Ipld::Integer(42).is_integer());
        assert!(Ipld::Float(2.5).is_float());
        assert!(Ipld::String("test".into()).is_string());
        assert!(Ipld::Bytes(vec![1, 2, 3]).is_bytes());
        assert!(Ipld::List(vec![]).is_list());
        assert!(Ipld::Map(BTreeMap::new()).is_map());
    }

    #[test]
    fn test_accessors() {
        assert_eq!(Ipld::Bool(true).as_bool(), Some(true));
        assert_eq!(Ipld::Integer(42).as_integer(), Some(42));
        assert_eq!(Ipld::Integer(42).as_i64(), Some(42));
        assert_eq!(Ipld::Integer(42).as_u64(), Some(42));
        assert!((Ipld::Float(2.5).as_float().unwrap() - 2.5).abs() < f64::EPSILON);
        assert_eq!(Ipld::String("test".into()).as_str(), Some("test"));
        assert_eq!(
            Ipld::Bytes(vec![1, 2, 3]).as_bytes(),
            Some([1u8, 2, 3].as_slice())
        );
    }

    #[test]
    fn test_from_conversions() {
        assert_eq!(Ipld::from(true), Ipld::Bool(true));
        assert_eq!(Ipld::from(42i32), Ipld::Integer(42));
        assert_eq!(Ipld::from(42u64), Ipld::Integer(42));
        assert_eq!(Ipld::from("test"), Ipld::String("test".into()));
        assert_eq!(Ipld::from(vec![1u8, 2, 3]), Ipld::Bytes(vec![1, 2, 3]));
    }

    #[test]
    fn test_from_iterator() {
        let list: Ipld = vec![1i32, 2, 3].into_iter().collect();
        assert!(list.is_list());
        assert_eq!(list.as_list().unwrap().len(), 3);
    }

    #[test]
    fn test_negative_integers() {
        assert_eq!(Ipld::Integer(-1).as_i64(), Some(-1));
        assert_eq!(Ipld::Integer(-1).as_u64(), None);

        // Large positive that doesn't fit in i64
        let large = Ipld::Integer(i128::from(u64::MAX));
        assert_eq!(large.as_i64(), None);
        assert_eq!(large.as_u64(), Some(u64::MAX));
    }

    // Serde roundtrip tests
    #[test]
    fn test_serde_roundtrip_null() {
        let original = Ipld::Null;
        let bytes = crate::to_vec(&original).unwrap();
        let decoded: Ipld = crate::from_slice(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_serde_roundtrip_bool() {
        for b in [true, false] {
            let original = Ipld::Bool(b);
            let bytes = crate::to_vec(&original).unwrap();
            let decoded: Ipld = crate::from_slice(&bytes).unwrap();
            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn test_serde_roundtrip_integer() {
        for i in [0i128, 1, -1, 42, -42, i64::MAX as i128, i64::MIN as i128] {
            let original = Ipld::Integer(i);
            let bytes = crate::to_vec(&original).unwrap();
            let decoded: Ipld = crate::from_slice(&bytes).unwrap();
            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn test_serde_roundtrip_float() {
        for f in [0.0, 1.5, -1.5, 2.5, f64::MAX, f64::MIN_POSITIVE] {
            let original = Ipld::Float(f);
            let bytes = crate::to_vec(&original).unwrap();
            let decoded: Ipld = crate::from_slice(&bytes).unwrap();
            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn test_serde_roundtrip_string() {
        for s in ["", "hello", "hello world", "emoji: 🎉"] {
            let original = Ipld::String(s.to_string());
            let bytes = crate::to_vec(&original).unwrap();
            let decoded: Ipld = crate::from_slice(&bytes).unwrap();
            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn test_serde_roundtrip_bytes() {
        // Use bytes that don't start with 0x00 to avoid CID detection
        let original = Ipld::Bytes(vec![0x01, 0x02, 0x03, 0x04]);
        let bytes = crate::to_vec(&original).unwrap();
        let decoded: Ipld = crate::from_slice(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_serde_roundtrip_list() {
        let original = Ipld::List(vec![
            Ipld::Integer(1),
            Ipld::String("two".to_string()),
            Ipld::Bool(true),
        ]);
        let bytes = crate::to_vec(&original).unwrap();
        let decoded: Ipld = crate::from_slice(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_serde_roundtrip_map() {
        let mut map = BTreeMap::new();
        map.insert("a".to_string(), Ipld::Integer(1));
        map.insert("b".to_string(), Ipld::String("hello".to_string()));
        map.insert("c".to_string(), Ipld::Bool(false));
        let original = Ipld::Map(map);
        let bytes = crate::to_vec(&original).unwrap();
        let decoded: Ipld = crate::from_slice(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_serde_roundtrip_nested() {
        let mut inner_map = BTreeMap::new();
        inner_map.insert("nested".to_string(), Ipld::Integer(42));

        let original = Ipld::Map({
            let mut m = BTreeMap::new();
            m.insert(
                "list".to_string(),
                Ipld::List(vec![Ipld::Integer(1), Ipld::Integer(2)]),
            );
            m.insert("map".to_string(), Ipld::Map(inner_map));
            m.insert(
                "bytes".to_string(),
                Ipld::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
            );
            m
        });
        let bytes = crate::to_vec(&original).unwrap();
        let decoded: Ipld = crate::from_slice(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_serde_roundtrip_cid_link() {
        use crate::cid::CidCore;
        use multihash::Multihash;

        // Create a test CID
        let hash = Multihash::<64>::wrap(0x12, &[0u8; 32]).unwrap();
        let cid_core = CidCore::new_v1(0x71, hash);
        let cid = Cid::new(cid_core);

        let original = Ipld::Link(cid);
        let bytes = crate::to_vec(&original).unwrap();
        let decoded: Ipld = crate::from_slice(&bytes).unwrap();
        assert_eq!(original, decoded);
    }
}
