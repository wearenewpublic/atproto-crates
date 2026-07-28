//! Primitive types used across AT Protocol lexicon definitions.
//!
//! This module contains fundamental data types that are referenced by
//! various AT Protocol lexicon schemas, including blob references,
//! links, and byte arrays.

use crate::bytes::format as bytes_format;
use crate::typed::{LexiconType, TypedLexicon};
use serde::{Deserialize, Serialize};

/// The namespace identifier for blobs
pub const BLOB_NSID: &str = "blob";

/// Blob reference type for AT Protocol.
///
/// Represents a reference to binary data (images, videos, etc.) stored
/// in the AT Protocol network. The blob itself is not included inline,
/// but referenced via a CID (Content Identifier).
///
/// # Example
///
/// ```ignore
/// use atproto_record::lexicon::{Blob, TypedBlob, Link};
///
/// let blob = Blob {
///     ref_: Link {
///         link: "bafkreicid123".to_string(),
///     },
///     mime_type: "image/jpeg".to_string(),
///     size: 123456,
/// };
///
/// // Use TypedBlob for automatic $type field handling
/// let typed_blob = TypedBlob::new(blob);
/// ```
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct Blob {
    /// Link to the blob content via CID
    #[serde(rename = "ref")]
    pub ref_: Link,
    /// MIME type of the blob content (e.g., "image/jpeg", "video/mp4")
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    /// Size of the blob in bytes
    pub size: u64,
}

impl LexiconType for Blob {
    fn lexicon_type() -> &'static str {
        BLOB_NSID
    }
}

/// Type alias for Blob with automatic $type field handling.
///
/// This wrapper ensures that the `$type` field is automatically
/// added during serialization and validated during deserialization.
pub type TypedBlob = TypedLexicon<Blob>;

/// Link reference type for AT Protocol.
///
/// Represents a content-addressed link using a CID (Content Identifier).
/// This is used to reference immutable content in the AT Protocol network.
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct Link {
    /// The CID (Content Identifier) as a string
    #[serde(rename = "$link")]
    pub link: String,
}

/// Byte array type for AT Protocol.
///
/// Represents raw byte data that is serialized/deserialized as base64.
/// Used for signatures, hashes, and other binary data that needs to be
/// transmitted in JSON format.
///
/// # Example
///
/// ```ignore
/// let signature = Bytes {
///     bytes: b"signature data".to_vec(),
/// };
/// // Serializes to: {"$bytes": "c2lnbmF0dXJlIGRhdGE="}
/// ```
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct Bytes {
    /// The raw bytes, serialized as base64 in JSON
    #[serde(rename = "$bytes", with = "bytes_format")]
    pub bytes: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_typed_blob_serialization() {
        // Create a Blob without explicit $type field
        let blob = Blob {
            ref_: Link {
                link: "bafkreitest123".to_string(),
            },
            mime_type: "image/png".to_string(),
            size: 12345,
        };

        // Wrap it in TypedBlob
        let typed_blob = TypedLexicon::new(blob);

        // Serialize and verify $type is added
        let json = serde_json::to_value(&typed_blob).unwrap();
        assert_eq!(json["$type"], "blob");
        assert_eq!(json["ref"]["$link"], "bafkreitest123");
        assert_eq!(json["mimeType"], "image/png");
        assert_eq!(json["size"], 12345);
    }

    #[test]
    fn test_typed_blob_deserialization() {
        let json = json!({
            "$type": "blob",
            "ref": {
                "$link": "bafkreideserialized"
            },
            "mimeType": "video/mp4",
            "size": 54321
        });

        let typed_blob: TypedBlob = serde_json::from_value(json).unwrap();

        assert_eq!(typed_blob.inner.ref_.link, "bafkreideserialized");
        assert_eq!(typed_blob.inner.mime_type, "video/mp4");
        assert_eq!(typed_blob.inner.size, 54321);
        assert!(typed_blob.has_type_field());
        assert!(typed_blob.validate().is_ok());
    }

    #[test]
    fn test_typed_blob_without_type_field() {
        // Test that we can deserialize a blob without $type field
        let json = json!({
            "ref": {
                "$link": "bafkreinotype"
            },
            "mimeType": "text/plain",
            "size": 100
        });

        let typed_blob: TypedBlob = serde_json::from_value(json).unwrap();

        assert_eq!(typed_blob.inner.ref_.link, "bafkreinotype");
        assert_eq!(typed_blob.inner.mime_type, "text/plain");
        assert_eq!(typed_blob.inner.size, 100);
        assert!(!typed_blob.has_type_field());

        // Validation should fail because type is required by default
        assert!(typed_blob.validate().is_err());
    }

    #[test]
    fn test_typed_blob_round_trip() {
        let original = Blob {
            ref_: Link {
                link: "bafkreiroundtrip".to_string(),
            },
            mime_type: "application/octet-stream".to_string(),
            size: 999999,
        };

        let typed = TypedLexicon::new(original.clone());

        let json = serde_json::to_string(&typed).unwrap();
        let deserialized: TypedBlob = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.inner.ref_.link, original.ref_.link);
        assert_eq!(deserialized.inner.mime_type, original.mime_type);
        assert_eq!(deserialized.inner.size, original.size);
        assert!(deserialized.has_type_field());
    }

    #[test]
    fn test_legacy_blob_with_explicit_type() {
        // Test backward compatibility: deserializing old format with type_ field
        let json_old_format = r#"{
            "$type": "blob",
            "ref": {
                "$link": "bafkreilegacy"
            },
            "mimeType": "image/gif",
            "size": 777
        }"#;

        let typed_blob: TypedBlob = serde_json::from_str(json_old_format).unwrap();

        assert_eq!(typed_blob.inner.ref_.link, "bafkreilegacy");
        assert_eq!(typed_blob.inner.mime_type, "image/gif");
        assert_eq!(typed_blob.inner.size, 777);
        assert!(typed_blob.has_type_field());

        // Re-serialize should maintain the $type field
        let json = serde_json::to_value(&typed_blob).unwrap();
        assert_eq!(json["$type"], "blob");
    }

    #[test]
    fn test_blob_in_context() {
        // Test using TypedBlob in a larger structure
        #[derive(Debug, Serialize, Deserialize)]
        struct TestRecord {
            title: String,
            thumbnail: TypedBlob,
        }

        let record = TestRecord {
            title: "Test Image".to_string(),
            thumbnail: TypedLexicon::new(Blob {
                ref_: Link {
                    link: "bafkreicontext".to_string(),
                },
                mime_type: "image/jpeg".to_string(),
                size: 256000,
            }),
        };

        let json = serde_json::to_value(&record).unwrap();

        assert_eq!(json["title"], "Test Image");
        assert_eq!(json["thumbnail"]["$type"], "blob");
        assert_eq!(json["thumbnail"]["ref"]["$link"], "bafkreicontext");
        assert_eq!(json["thumbnail"]["mimeType"], "image/jpeg");
        assert_eq!(json["thumbnail"]["size"], 256000);
    }
}
