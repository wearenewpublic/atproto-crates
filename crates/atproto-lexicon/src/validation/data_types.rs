//! Data model types for ATProtocol lexicon validation

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// A blob reference in ATProtocol data
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Blob {
    /// The $type field indicating this is a blob
    #[serde(rename = "$type")]
    pub type_marker: String,

    /// Reference to the blob (CID link)
    #[serde(rename = "ref")]
    pub ref_link: Option<CIDLink>,

    /// MIME type of the blob
    #[serde(rename = "mimeType")]
    pub mime_type: String,

    /// Size in bytes
    pub size: u64,

    /// Legacy CID field (for legacy blob format)
    pub cid: Option<String>,
}

impl Blob {
    /// Check if this is a legacy blob format
    pub fn is_legacy(&self) -> bool {
        self.type_marker == "blob" && self.cid.is_some() && self.ref_link.is_none()
    }

    /// Check if this is the modern blob format
    pub fn is_modern(&self) -> bool {
        self.type_marker == "blob" && self.ref_link.is_some()
    }

    /// Get the CID string, whether from modern or legacy format
    pub fn get_cid(&self) -> Option<&str> {
        if let Some(ref link) = self.ref_link {
            Some(&link.link)
        } else {
            self.cid.as_deref()
        }
    }
}

/// A CID link in ATProtocol data
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CIDLink {
    /// The linked CID
    #[serde(rename = "$link")]
    pub link: String,
}

impl CIDLink {
    /// Create a new CID link
    pub fn new(cid: impl Into<String>) -> Self {
        Self { link: cid.into() }
    }
}

/// Raw bytes in ATProtocol data (base64 encoded)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bytes {
    /// The $bytes field containing base64-encoded data
    #[serde(rename = "$bytes")]
    pub bytes: String,
}

impl Bytes {
    /// Create new bytes from base64-encoded string
    pub fn new(base64: impl Into<String>) -> Self {
        Self {
            bytes: base64.into(),
        }
    }

    /// Decode the base64 bytes.
    ///
    /// Delegates to `atproto_dasl::atproto_json::decode_bytes` so that a
    /// `$bytes` value means one thing across the workspace. It did not
    /// before: this decoder required padding while the data-model layer emits
    /// unpadded, so a record written through the data model failed lexicon
    /// validation.
    ///
    /// # Errors
    ///
    /// Returns [`atproto_dasl::EncodeError`] when the value is not base64.
    pub fn decode(&self) -> Result<Vec<u8>, atproto_dasl::EncodeError> {
        atproto_dasl::atproto_json::decode_bytes(&self.bytes)
    }

    /// Get the length of decoded bytes
    pub fn decoded_len(&self) -> Option<usize> {
        self.decode().ok().map(|v| v.len())
    }
}

/// A value in the ATProtocol data model
#[derive(Debug, Clone, PartialEq, Default)]
pub enum DataValue {
    /// Null value
    #[default]
    Null,

    /// Boolean value
    Boolean(bool),

    /// Integer value (i64)
    Integer(i64),

    /// Floating point value
    Float(f64),

    /// String value
    String(String),

    /// Bytes value (base64 encoded)
    Bytes(Bytes),

    /// CID link
    Link(CIDLink),

    /// Blob reference
    Blob(Blob),

    /// Array of values
    Array(Vec<DataValue>),

    /// Object with string keys
    Object(IndexMap<String, DataValue>),
}

impl DataValue {
    /// Check if value is null
    pub fn is_null(&self) -> bool {
        matches!(self, DataValue::Null)
    }

    /// Check if value is a boolean
    pub fn is_boolean(&self) -> bool {
        matches!(self, DataValue::Boolean(_))
    }

    /// Check if value is an integer
    pub fn is_integer(&self) -> bool {
        matches!(self, DataValue::Integer(_))
    }

    /// Check if value is a float
    pub fn is_float(&self) -> bool {
        matches!(self, DataValue::Float(_))
    }

    /// Check if value is a number (integer or float)
    pub fn is_number(&self) -> bool {
        matches!(self, DataValue::Integer(_) | DataValue::Float(_))
    }

    /// Check if value is a string
    pub fn is_string(&self) -> bool {
        matches!(self, DataValue::String(_))
    }

    /// Check if value is bytes
    pub fn is_bytes(&self) -> bool {
        matches!(self, DataValue::Bytes(_))
    }

    /// Check if value is a link
    pub fn is_link(&self) -> bool {
        matches!(self, DataValue::Link(_))
    }

    /// Check if value is a blob
    pub fn is_blob(&self) -> bool {
        matches!(self, DataValue::Blob(_))
    }

    /// Check if value is an array
    pub fn is_array(&self) -> bool {
        matches!(self, DataValue::Array(_))
    }

    /// Check if value is an object
    pub fn is_object(&self) -> bool {
        matches!(self, DataValue::Object(_))
    }

    /// Get as boolean
    pub fn as_boolean(&self) -> Option<bool> {
        match self {
            DataValue::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    /// Get as integer
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            DataValue::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// Get as float
    pub fn as_float(&self) -> Option<f64> {
        match self {
            DataValue::Float(f) => Some(*f),
            DataValue::Integer(i) => Some(*i as f64),
            _ => None,
        }
    }

    /// Get as string
    pub fn as_string(&self) -> Option<&str> {
        match self {
            DataValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> Option<&Bytes> {
        match self {
            DataValue::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Get as link
    pub fn as_link(&self) -> Option<&CIDLink> {
        match self {
            DataValue::Link(l) => Some(l),
            _ => None,
        }
    }

    /// Get as blob
    pub fn as_blob(&self) -> Option<&Blob> {
        match self {
            DataValue::Blob(b) => Some(b),
            _ => None,
        }
    }

    /// Get as array
    pub fn as_array(&self) -> Option<&[DataValue]> {
        match self {
            DataValue::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Get as object
    pub fn as_object(&self) -> Option<&IndexMap<String, DataValue>> {
        match self {
            DataValue::Object(o) => Some(o),
            _ => None,
        }
    }

    /// Get mutable reference to array
    pub fn as_array_mut(&mut self) -> Option<&mut Vec<DataValue>> {
        match self {
            DataValue::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Get mutable reference to object
    pub fn as_object_mut(&mut self) -> Option<&mut IndexMap<String, DataValue>> {
        match self {
            DataValue::Object(o) => Some(o),
            _ => None,
        }
    }

    /// Get the type name for this value
    pub fn type_name(&self) -> &'static str {
        match self {
            DataValue::Null => "null",
            DataValue::Boolean(_) => "boolean",
            DataValue::Integer(_) => "integer",
            DataValue::Float(_) => "float",
            DataValue::String(_) => "string",
            DataValue::Bytes(_) => "bytes",
            DataValue::Link(_) => "link",
            DataValue::Blob(_) => "blob",
            DataValue::Array(_) => "array",
            DataValue::Object(_) => "object",
        }
    }

    /// Get the $type field if this is an object with one
    pub fn get_type(&self) -> Option<&str> {
        self.as_object()
            .and_then(|obj| obj.get("$type"))
            .and_then(|v| v.as_string())
    }

    /// Get a field from an object
    pub fn get(&self, key: &str) -> Option<&DataValue> {
        self.as_object().and_then(|obj| obj.get(key))
    }
}

#[cfg(test)]
#[allow(clippy::approx_constant)]
mod tests {
    use super::*;

    #[test]
    fn test_data_value_types() {
        assert!(DataValue::Null.is_null());
        assert!(DataValue::Boolean(true).is_boolean());
        assert!(DataValue::Integer(42).is_integer());
        assert!(DataValue::Float(3.14).is_float());
        assert!(DataValue::String("test".into()).is_string());
        assert!(DataValue::Array(vec![]).is_array());
        assert!(DataValue::Object(IndexMap::new()).is_object());
    }

    #[test]
    fn test_data_value_accessors() {
        assert_eq!(DataValue::Boolean(true).as_boolean(), Some(true));
        assert_eq!(DataValue::Integer(42).as_integer(), Some(42));
        assert_eq!(DataValue::Float(3.14).as_float(), Some(3.14));
        assert_eq!(DataValue::String("test".into()).as_string(), Some("test"));

        // Integer can be accessed as float
        assert_eq!(DataValue::Integer(42).as_float(), Some(42.0));
    }

    #[test]
    fn test_cid_link() {
        let link = CIDLink::new("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi");
        assert_eq!(
            link.link,
            "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
        );
    }

    #[test]
    fn test_bytes() {
        let bytes = Bytes::new("SGVsbG8gV29ybGQ="); // "Hello World" in base64
        let decoded = bytes.decode().unwrap();
        assert_eq!(decoded, b"Hello World");
        assert_eq!(bytes.decoded_len(), Some(11));
    }

    /// `$bytes` is unpadded base64, and the padded form is accepted too.
    ///
    /// The unpadded case is not academic: `atproto-dasl` emits it, and the
    /// data-model interop vectors are 43-character unpadded values. Decoding
    /// with the padded engine alone meant this crate refused records the rest
    /// of the workspace produces.
    #[test]
    fn bytes_decode_unpadded_and_padded_base64() {
        // 3 characters is a valid unpadded encoding of 2 bytes.
        assert_eq!(Bytes::new("123").decoded_len(), Some(2));
        // A 43-character value, the shape the data-model vectors carry.
        let vector = "iE+sPoHobU9tSIqGI+309LLCcWQIRmEXwxcoDt19tas";
        assert_eq!(vector.len(), 43);
        assert_eq!(Bytes::new(vector).decoded_len(), Some(32));
        // The padded spelling of the same bytes still decodes.
        assert_eq!(Bytes::new("aGk=").decoded_len(), Some(2));
        assert_eq!(Bytes::new("aGk").decoded_len(), Some(2));
        assert_eq!(
            Bytes::new("aGk=").decode().unwrap(),
            Bytes::new("aGk").decode().unwrap()
        );
    }

    /// Widening the accepted padding did not make the decoder accept anything.
    #[test]
    fn bytes_reject_values_that_decode_under_neither_alphabet() {
        for value in ["!!!!", "a", "abcde!", "_-_-"] {
            assert!(
                Bytes::new(value).decoded_len().is_none(),
                "should not decode: {value:?}"
            );
        }
    }

    #[test]
    fn test_blob_modern() {
        let blob = Blob {
            type_marker: "blob".to_string(),
            ref_link: Some(CIDLink::new("bafytest")),
            mime_type: "image/png".to_string(),
            size: 1024,
            cid: None,
        };
        assert!(blob.is_modern());
        assert!(!blob.is_legacy());
        assert_eq!(blob.get_cid(), Some("bafytest"));
    }

    #[test]
    fn test_blob_legacy() {
        let blob = Blob {
            type_marker: "blob".to_string(),
            ref_link: None,
            mime_type: "image/png".to_string(),
            size: 1024,
            cid: Some("bafytest".to_string()),
        };
        assert!(!blob.is_modern());
        assert!(blob.is_legacy());
        assert_eq!(blob.get_cid(), Some("bafytest"));
    }

    #[test]
    fn test_data_value_type_names() {
        assert_eq!(DataValue::Null.type_name(), "null");
        assert_eq!(DataValue::Boolean(true).type_name(), "boolean");
        assert_eq!(DataValue::Integer(42).type_name(), "integer");
        assert_eq!(DataValue::Float(3.14).type_name(), "float");
        assert_eq!(DataValue::String("".into()).type_name(), "string");
        assert_eq!(DataValue::Array(vec![]).type_name(), "array");
        assert_eq!(DataValue::Object(IndexMap::new()).type_name(), "object");
    }

    #[test]
    fn test_data_value_get_type() {
        let mut obj = IndexMap::new();
        obj.insert(
            "$type".to_string(),
            DataValue::String("app.bsky.feed.post".into()),
        );
        let value = DataValue::Object(obj);
        assert_eq!(value.get_type(), Some("app.bsky.feed.post"));

        // No $type field
        let empty_obj = DataValue::Object(IndexMap::new());
        assert_eq!(empty_obj.get_type(), None);

        // Not an object
        assert_eq!(DataValue::String("test".into()).get_type(), None);
    }
}
