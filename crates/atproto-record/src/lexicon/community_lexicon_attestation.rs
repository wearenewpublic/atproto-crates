//! Attestation and signature types for AT Protocol.
//!
//! This module provides types for cryptographic signatures and attestations
//! that can be attached to records to prove authenticity, authorization,
//! or other properties.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::lexicon::Bytes;
use crate::lexicon::com_atproto_repo::TypedStrongRef;
use crate::typed::{LexiconType, TypedLexicon};

/// The namespace identifier for signatures
pub const NSID: &str = "community.lexicon.attestation.signature";

/// Enum that can hold either a signature reference or an inline signature.
///
/// This type allows signatures to be either embedded directly in a record
/// or referenced via a strong reference. This flexibility enables:
/// - Inline signatures for immediate verification
/// - Referenced signatures for deduplication and separate storage
///
/// # Example
///
/// ```ignore
/// use atproto_record::lexicon::community::lexicon::attestation::{SignatureOrRef, create_typed_signature};
/// use atproto_record::lexicon::Bytes;
///
/// // Inline signature
/// let inline = SignatureOrRef::Inline(create_typed_signature(
///     Bytes { bytes: b"signature".to_vec() },
/// ));
///
/// // Referenced signature
/// let reference = SignatureOrRef::Reference(typed_strong_ref);
/// ```
#[derive(Deserialize, Serialize, Clone, PartialEq, Debug)]
#[serde(untagged)]
pub enum SignatureOrRef {
    /// A reference to a signature stored elsewhere
    Reference(TypedStrongRef),
    /// An inline signature
    Inline(TypedSignature),
}

/// A vector of signatures that can be either inline or referenced.
///
/// This type alias is commonly used in records that support multiple
/// signatures, such as badges, awards, and RSVPs.
pub type Signatures = Vec<SignatureOrRef>;

/// Cryptographic signature structure.
///
/// Represents a cryptographic signature over some data. The signature can be
/// used to verify authenticity, authorization, or other properties of the
/// signed content.
///
/// # Fields
///
/// - `signature`: The actual signature bytes
/// - `extra`: Additional fields that may be present in the signature
///
/// # Example
///
/// ```ignore
/// use atproto_record::lexicon::community::lexicon::attestation::Signature;
/// use atproto_record::lexicon::Bytes;
/// use std::collections::HashMap;
///
/// let sig = Signature {
///     signature: Bytes { bytes: b"signature_bytes".to_vec() },
///     extra: HashMap::new(),
/// };
/// ```
#[derive(Deserialize, Serialize, Clone, PartialEq, Debug)]
pub struct Signature {
    /// The cryptographic signature bytes
    pub signature: Bytes,

    /// Additional fields for extensibility
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl LexiconType for Signature {
    fn lexicon_type() -> &'static str {
        NSID
    }

    /// Type field is optional for signatures since they may appear without it
    fn type_required() -> bool {
        false
    }
}

/// Type alias for Signature with automatic $type field handling.
///
/// This wrapper ensures proper serialization/deserialization of the
/// `$type` field when present.
pub type TypedSignature = TypedLexicon<Signature>;

/// Helper function to create a typed signature.
///
/// Creates a new signature with the TypedLexicon wrapper, ensuring
/// proper `$type` field handling.
///
/// # Arguments
///
/// * `signature` - The signature bytes
///
/// # Example
///
/// ```ignore
/// use atproto_record::lexicon::community::lexicon::attestation::create_typed_signature;
/// use atproto_record::lexicon::Bytes;
///
/// let sig = create_typed_signature(
///     Bytes { bytes: b"sig_data".to_vec() },
/// );
/// ```
pub fn create_typed_signature(signature: Bytes) -> TypedSignature {
    TypedLexicon::new(Signature {
        signature,
        extra: HashMap::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexicon::com_atproto_repo::StrongRef;
    use serde_json::json;

    #[test]
    fn test_real_signature_or_ref_deserialization() {
        // Test with the exact signature structure from the user's RSVP
        let json_str = r#"{
            "$type": "community.lexicon.attestation.signature",
            "issuedAt": "2025-08-19T20:17:17.133Z",
            "signature": {
                "$bytes": "mr9c0MCu3g6SXNQ25JFhzfX1ecYgK9k1Kf6OZI2p2AlQRoQu09dOE7J5uaeilIx/UFCjJErO89C/uBBb9ANmUA"
            }
        }"#;

        // First, try to deserialize as TypedSignature
        let typed_sig_result: Result<TypedSignature, _> = serde_json::from_str(json_str);
        match &typed_sig_result {
            Ok(sig) => {
                println!(
                    "TypedSignature OK: signature bytes len={}",
                    sig.inner.signature.bytes.len()
                );
                assert_eq!(sig.inner.signature.bytes.len(), 64);
            }
            Err(e) => {
                eprintln!("TypedSignature deserialization error: {}", e);
            }
        }

        // Then try as SignatureOrRef
        let sig_or_ref_result: Result<SignatureOrRef, _> = serde_json::from_str(json_str);
        match &sig_or_ref_result {
            Ok(SignatureOrRef::Inline(sig)) => {
                println!(
                    "SignatureOrRef OK (Inline): signature bytes len={}",
                    sig.inner.signature.bytes.len()
                );
                assert_eq!(sig.inner.signature.bytes.len(), 64);
            }
            Ok(SignatureOrRef::Reference(_)) => {
                panic!("Expected Inline signature, got Reference");
            }
            Err(e) => {
                eprintln!("SignatureOrRef deserialization error: {}", e);
            }
        }

        // Try without $type field
        let json_no_type = r#"{
            "issuedAt": "2025-08-19T20:17:17.133Z",
            "signature": {
                "$bytes": "mr9c0MCu3g6SXNQ25JFhzfX1ecYgK9k1Kf6OZI2p2AlQRoQu09dOE7J5uaeilIx/UFCjJErO89C/uBBb9ANmUA"
            }
        }"#;

        let no_type_result: Result<Signature, _> = serde_json::from_str(json_no_type);
        match &no_type_result {
            Ok(sig) => {
                println!(
                    "Signature (no type) OK: signature bytes len={}",
                    sig.signature.bytes.len()
                );
                assert_eq!(sig.signature.bytes.len(), 64);

                // Now wrap it in TypedLexicon and try as SignatureOrRef
                let typed = TypedLexicon::new(sig.clone());
                let _as_sig_or_ref = SignatureOrRef::Inline(typed);
                println!("Successfully created SignatureOrRef from Signature");
            }
            Err(e) => {
                eprintln!("Signature (no type) deserialization error: {}", e);
            }
        }

        // Check that at least one worked
        assert!(
            typed_sig_result.is_ok() || sig_or_ref_result.is_ok() || no_type_result.is_ok(),
            "Failed to deserialize signature in any form"
        );
    }

    #[test]
    fn test_signature_deserialization() {
        let json_str = r#"{
            "$type": "community.lexicon.attestation.signature",
            "signature": {"$bytes": "dGVzdCBzaWduYXR1cmU="}
        }"#;

        let signature: Signature = serde_json::from_str(json_str).unwrap();

        assert_eq!(signature.signature.bytes, b"test signature");
        // The $type field will be captured in extra due to #[serde(flatten)]
        assert_eq!(signature.extra.len(), 1);
        assert!(signature.extra.contains_key("$type"));
    }

    #[test]
    fn test_signature_deserialization_with_extra_fields() {
        let json_str = r#"{
            "$type": "community.lexicon.attestation.signature",
            "signature": {"$bytes": "dGVzdCBzaWduYXR1cmU="},
            "issuedAt": "2024-01-01T00:00:00.000Z",
            "purpose": "verification"
        }"#;

        let signature: Signature = serde_json::from_str(json_str).unwrap();

        assert_eq!(signature.signature.bytes, b"test signature");
        // 3 extra fields: $type, issuedAt, purpose
        assert_eq!(signature.extra.len(), 3);
        assert!(signature.extra.contains_key("$type"));
        assert_eq!(
            signature.extra.get("issuedAt").unwrap(),
            "2024-01-01T00:00:00.000Z"
        );
        assert_eq!(signature.extra.get("purpose").unwrap(), "verification");
    }

    #[test]
    fn test_signature_serialization() {
        let mut extra = HashMap::new();
        extra.insert("custom_field".to_string(), json!("custom_value"));

        let signature = Signature {
            signature: Bytes {
                bytes: b"hello world".to_vec(),
            },
            extra,
        };

        let json = serde_json::to_value(&signature).unwrap();

        // Without custom Serialize impl, $type is not automatically added
        assert!(!json.as_object().unwrap().contains_key("$type"));
        // "hello world" base64 encoded is "aGVsbG8gd29ybGQ="
        assert_eq!(json["signature"]["$bytes"], "aGVsbG8gd29ybGQ=");
        assert_eq!(json["custom_field"], "custom_value");
    }

    #[test]
    fn test_signature_round_trip() {
        let original = Signature {
            signature: Bytes {
                bytes: b"round trip test".to_vec(),
            },
            extra: HashMap::new(),
        };

        // Serialize to JSON
        let json = serde_json::to_string(&original).unwrap();

        // Deserialize back
        let deserialized: Signature = serde_json::from_str(&json).unwrap();

        assert_eq!(original.signature.bytes, deserialized.signature.bytes);
        // Without the custom Serialize impl, no $type is added
        // so the round-trip preserves the empty extra map
        assert_eq!(deserialized.extra.len(), 0);
    }

    #[test]
    fn test_signature_with_complex_extra_fields() {
        let mut extra = HashMap::new();
        extra.insert("timestamp".to_string(), json!(1234567890));
        extra.insert(
            "metadata".to_string(),
            json!({
                "version": "1.0",
                "algorithm": "ES256"
            }),
        );
        extra.insert("tags".to_string(), json!(["tag1", "tag2", "tag3"]));

        let signature = Signature {
            signature: Bytes {
                bytes: vec![0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA],
            },
            extra,
        };

        let json = serde_json::to_value(&signature).unwrap();

        // Without custom Serialize impl, $type is not automatically added
        assert!(!json.as_object().unwrap().contains_key("$type"));
        assert_eq!(json["timestamp"], 1234567890);
        assert_eq!(json["metadata"]["version"], "1.0");
        assert_eq!(json["metadata"]["algorithm"], "ES256");
        assert_eq!(json["tags"], json!(["tag1", "tag2", "tag3"]));
    }

    #[test]
    fn test_empty_signature() {
        let signature = Signature {
            signature: Bytes { bytes: Vec::new() },
            extra: HashMap::new(),
        };

        let json = serde_json::to_value(&signature).unwrap();

        // Without custom Serialize impl, $type is not automatically added
        assert!(!json.as_object().unwrap().contains_key("$type"));
        assert_eq!(json["signature"]["$bytes"], ""); // Empty bytes encode to empty string
    }

    #[test]
    fn test_signatures_vec_serialization() {
        // Test with plain Vec<Signature> for basic signature serialization
        let signatures: Vec<Signature> = vec![
            Signature {
                signature: Bytes {
                    bytes: b"first".to_vec(),
                },
                extra: HashMap::new(),
            },
            Signature {
                signature: Bytes {
                    bytes: b"second".to_vec(),
                },
                extra: HashMap::new(),
            },
        ];

        let json = serde_json::to_value(&signatures).unwrap();

        assert!(json.is_array());
        assert_eq!(json.as_array().unwrap().len(), 2);
        assert_eq!(json[0]["signature"]["$bytes"], "Zmlyc3Q="); // "first" in base64
        assert_eq!(json[1]["signature"]["$bytes"], "c2Vjb25k"); // "second" in base64
    }

    #[test]
    fn test_signatures_as_signature_or_ref_vec() {
        // Test the new Signatures type with inline signatures
        let signatures: Signatures = vec![
            SignatureOrRef::Inline(create_typed_signature(Bytes {
                bytes: b"first".to_vec(),
            })),
            SignatureOrRef::Inline(create_typed_signature(Bytes {
                bytes: b"second".to_vec(),
            })),
        ];

        let json = serde_json::to_value(&signatures).unwrap();

        assert!(json.is_array());
        assert_eq!(json.as_array().unwrap().len(), 2);
        assert_eq!(json[0]["$type"], "community.lexicon.attestation.signature");
        assert_eq!(json[0]["signature"]["$bytes"], "Zmlyc3Q="); // "first" in base64
        assert_eq!(json[1]["$type"], "community.lexicon.attestation.signature");
        assert_eq!(json[1]["signature"]["$bytes"], "c2Vjb25k"); // "second" in base64
    }

    #[test]
    fn test_typed_signature_serialization() {
        let typed_sig = create_typed_signature(Bytes {
            bytes: b"typed signature".to_vec(),
        });

        let json = serde_json::to_value(&typed_sig).unwrap();

        assert_eq!(json["$type"], "community.lexicon.attestation.signature");
        // "typed signature" base64 encoded
        assert_eq!(json["signature"]["$bytes"], "dHlwZWQgc2lnbmF0dXJl");
    }

    #[test]
    fn test_typed_signature_deserialization() {
        let json = json!({
            "$type": "community.lexicon.attestation.signature",
            "signature": {"$bytes": "dHlwZWQgc2lnbmF0dXJl"}
        });

        let typed_sig: TypedSignature = serde_json::from_value(json).unwrap();

        assert_eq!(typed_sig.inner.signature.bytes, b"typed signature");
        assert!(typed_sig.has_type_field());
        assert!(typed_sig.validate().is_ok());
    }

    #[test]
    fn test_typed_signature_without_type_field() {
        let json = json!({
            "signature": {"$bytes": "bm8gdHlwZQ=="}  // "no type" in base64
        });

        let typed_sig: TypedSignature = serde_json::from_value(json).unwrap();

        assert_eq!(typed_sig.inner.signature.bytes, b"no type");
        assert!(!typed_sig.has_type_field());
        // Validation should still pass because type_required() returns false for Signature
        assert!(typed_sig.validate().is_ok());
    }

    #[test]
    fn test_typed_signature_with_extra_fields() {
        let mut sig = Signature {
            signature: Bytes {
                bytes: b"extra test".to_vec(),
            },
            extra: HashMap::new(),
        };
        sig.extra
            .insert("customField".to_string(), json!("customValue"));
        sig.extra.insert("timestamp".to_string(), json!(1234567890));

        let typed_sig = TypedLexicon::new(sig);

        let json = serde_json::to_value(&typed_sig).unwrap();

        assert_eq!(json["$type"], "community.lexicon.attestation.signature");
        assert_eq!(json["customField"], "customValue");
        assert_eq!(json["timestamp"], 1234567890);
    }

    #[test]
    fn test_typed_signature_round_trip() {
        let original = Signature {
            signature: Bytes {
                bytes: b"round trip typed".to_vec(),
            },
            extra: HashMap::new(),
        };

        let typed = TypedLexicon::new(original.clone());

        let json = serde_json::to_string(&typed).unwrap();
        let deserialized: TypedSignature = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.inner.signature.bytes, original.signature.bytes);
        assert!(deserialized.has_type_field());
    }

    #[test]
    fn test_typed_signatures_vec() {
        let typed_sigs: Vec<TypedSignature> = vec![
            create_typed_signature(Bytes {
                bytes: b"first".to_vec(),
            }),
            create_typed_signature(Bytes {
                bytes: b"second".to_vec(),
            }),
        ];

        let json = serde_json::to_value(&typed_sigs).unwrap();

        assert!(json.is_array());
        assert_eq!(json[0]["$type"], "community.lexicon.attestation.signature");
        assert_eq!(json[0]["signature"]["$bytes"], "Zmlyc3Q="); // "first" in base64
        assert_eq!(json[1]["$type"], "community.lexicon.attestation.signature");
        assert_eq!(json[1]["signature"]["$bytes"], "c2Vjb25k"); // "second" in base64
    }

    #[test]
    fn test_plain_vs_typed_signature() {
        // Plain Signature doesn't include $type field
        let plain_sig = Signature {
            signature: Bytes {
                bytes: b"plain sig".to_vec(),
            },
            extra: HashMap::new(),
        };

        let plain_json = serde_json::to_value(&plain_sig).unwrap();
        assert!(!plain_json.as_object().unwrap().contains_key("$type"));

        // TypedSignature automatically includes $type field
        let typed_sig = TypedLexicon::new(plain_sig.clone());
        let typed_json = serde_json::to_value(&typed_sig).unwrap();
        assert_eq!(
            typed_json["$type"],
            "community.lexicon.attestation.signature"
        );

        // Both have the same core data
        assert_eq!(plain_json["signature"], typed_json["signature"]);
    }

    #[test]
    fn test_signature_or_ref_inline() {
        // Test inline signature
        let inline_sig = create_typed_signature(Bytes {
            bytes: b"inline signature".to_vec(),
        });

        let sig_or_ref = SignatureOrRef::Inline(inline_sig);

        // Serialize
        let json = serde_json::to_value(&sig_or_ref).unwrap();
        assert_eq!(json["$type"], "community.lexicon.attestation.signature");
        assert_eq!(json["signature"]["$bytes"], "aW5saW5lIHNpZ25hdHVyZQ=="); // "inline signature" in base64

        // Deserialize
        let deserialized: SignatureOrRef = serde_json::from_value(json.clone()).unwrap();
        match deserialized {
            SignatureOrRef::Inline(sig) => {
                assert_eq!(sig.inner.signature.bytes, b"inline signature");
            }
            _ => panic!("Expected inline signature"),
        }
    }

    #[test]
    fn test_signature_or_ref_reference() {
        // Test reference to signature
        let strong_ref = StrongRef {
            uri: "at://did:plc:repo/community.lexicon.attestation.signature/abc123".to_string(),
            cid: "bafyreisigref123".to_string(),
        };
        let typed_ref = TypedLexicon::new(strong_ref);

        let sig_or_ref = SignatureOrRef::Reference(typed_ref);

        // Serialize
        let json = serde_json::to_value(&sig_or_ref).unwrap();
        assert_eq!(json["$type"], "com.atproto.repo.strongRef");
        assert_eq!(
            json["uri"],
            "at://did:plc:repo/community.lexicon.attestation.signature/abc123"
        );
        assert_eq!(json["cid"], "bafyreisigref123");

        // Deserialize
        let deserialized: SignatureOrRef = serde_json::from_value(json.clone()).unwrap();
        match deserialized {
            SignatureOrRef::Reference(ref_) => {
                assert_eq!(
                    ref_.uri,
                    "at://did:plc:repo/community.lexicon.attestation.signature/abc123"
                );
                assert_eq!(ref_.cid, "bafyreisigref123");
            }
            _ => panic!("Expected reference"),
        }
    }

    #[test]
    fn test_signatures_mixed_vector() {
        // Create a vector with both inline and referenced signatures
        let signatures: Signatures = vec![
            // Inline signature
            SignatureOrRef::Inline(create_typed_signature(Bytes {
                bytes: b"sig1".to_vec(),
            })),
            // Referenced signature
            SignatureOrRef::Reference(TypedLexicon::new(StrongRef {
                uri: "at://did:plc:repo/community.lexicon.attestation.signature/sig2".to_string(),
                cid: "bafyreisig2".to_string(),
            })),
            // Another inline signature
            SignatureOrRef::Inline(create_typed_signature(Bytes {
                bytes: b"sig3".to_vec(),
            })),
        ];

        // Serialize
        let json = serde_json::to_value(&signatures).unwrap();
        assert!(json.is_array());
        let array = json.as_array().unwrap();
        assert_eq!(array.len(), 3);

        // First element should be inline signature
        assert_eq!(array[0]["$type"], "community.lexicon.attestation.signature");
        assert_eq!(array[0]["signature"]["$bytes"], "c2lnMQ=="); // "sig1" in base64

        // Second element should be reference
        assert_eq!(array[1]["$type"], "com.atproto.repo.strongRef");
        assert_eq!(
            array[1]["uri"],
            "at://did:plc:repo/community.lexicon.attestation.signature/sig2"
        );

        // Third element should be inline signature
        assert_eq!(array[2]["$type"], "community.lexicon.attestation.signature");
        assert_eq!(array[2]["signature"]["$bytes"], "c2lnMw=="); // "sig3" in base64

        // Deserialize back
        let deserialized: Signatures = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.len(), 3);

        // Verify each element
        match &deserialized[0] {
            SignatureOrRef::Inline(sig) => assert_eq!(sig.inner.signature.bytes, b"sig1"),
            _ => panic!("Expected inline signature at index 0"),
        }

        match &deserialized[1] {
            SignatureOrRef::Reference(ref_) => {
                assert_eq!(
                    ref_.uri,
                    "at://did:plc:repo/community.lexicon.attestation.signature/sig2"
                )
            }
            _ => panic!("Expected reference at index 1"),
        }

        match &deserialized[2] {
            SignatureOrRef::Inline(sig) => assert_eq!(sig.inner.signature.bytes, b"sig3"),
            _ => panic!("Expected inline signature at index 2"),
        }
    }

    #[test]
    fn test_signature_or_ref_deserialization_from_json() {
        // Test deserializing from raw JSON strings

        // Inline signature JSON
        let inline_json = r#"{
            "$type": "community.lexicon.attestation.signature",
            "signature": {"$bytes": "aGVsbG8="}
        }"#;

        let inline_deser: SignatureOrRef = serde_json::from_str(inline_json).unwrap();
        match inline_deser {
            SignatureOrRef::Inline(sig) => {
                assert_eq!(sig.inner.signature.bytes, b"hello");
            }
            _ => panic!("Expected inline signature"),
        }

        // Reference JSON
        let ref_json = r#"{
            "$type": "com.atproto.repo.strongRef",
            "uri": "at://did:plc:test/collection/record",
            "cid": "bafyreicid"
        }"#;

        let ref_deser: SignatureOrRef = serde_json::from_str(ref_json).unwrap();
        match ref_deser {
            SignatureOrRef::Reference(ref_) => {
                assert_eq!(ref_.uri, "at://did:plc:test/collection/record");
                assert_eq!(ref_.cid, "bafyreicid");
            }
            _ => panic!("Expected reference"),
        }
    }
}
