//! CID (Content Identifier) generation for AT Protocol records.
//!
//! This module implements the CID-first attestation workflow, generating
//! deterministic content identifiers using DAG-CBOR serialization and SHA-256 hashing.

use crate::{errors::AttestationError, input::AnyInput};
#[cfg(test)]
use atproto_record::typed::LexiconType;
use cid::Cid;
use serde::Serialize;
use serde_json::{Map, Value};
use std::convert::TryInto;

/// DAG-CBOR codec identifier used in AT Protocol CIDs.
///
/// This codec (0x71) indicates that the data is encoded using DAG-CBOR,
/// a deterministic subset of CBOR designed for content-addressable systems.
pub const DAG_CBOR_CODEC: u64 = 0x71;

/// SHA-256 multihash code used in AT Protocol CIDs.
///
/// This code (0x12) identifies SHA-256 as the hash function used to generate
/// the content identifier. SHA-256 provides 256-bit cryptographic security.
pub const MULTIHASH_SHA256: u64 = 0x12;

/// Create a CID from any serializable data using DAG-CBOR encoding.
///
/// This function generates a content identifier (CID) for arbitrary data by:
/// 1. Serializing the input to DAG-CBOR format
/// 2. Computing a SHA-256 hash of the serialized bytes
/// 3. Creating a CIDv1 with dag-cbor codec (0x71)
///
/// # Arguments
///
/// * `record` - The data to generate a CID for (must implement `Serialize`)
///
/// # Returns
///
/// The generated CID for the data using CIDv1 with dag-cbor codec (0x71) and sha2-256 hash
///
/// # Type Parameters
///
/// * `T` - Any type that implements `Serialize` and is compatible with DAG-CBOR encoding
///
/// # Errors
///
/// Returns an error if:
/// - DAG-CBOR serialization fails
/// - Multihash wrapping fails
///
/// # Example
///
/// ```rust
/// use atproto_attestation::cid::create_dagbor_cid;
/// use serde_json::json;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let data = json!({"text": "Hello, world!"});
/// let cid = create_dagbor_cid(&data)?;
/// assert_eq!(cid.codec(), 0x71); // dag-cbor codec
/// # Ok(())
/// # }
/// ```
pub fn create_dagbor_cid<T: Serialize>(record: &T) -> Result<Cid, AttestationError> {
    Ok(atproto_dasl::compute_cid_for(record)?)
}

/// Create a CID for an attestation with automatic `$sig` metadata preparation.
///
/// This is the high-level function used internally by attestation creation functions.
/// It handles the full workflow of preparing a signing record with `$sig` metadata
/// and generating the CID.
///
/// # Arguments
///
/// * `record_input` - The record to attest (as AnyInput: String, Json, or TypedLexicon)
/// * `metadata_input` - The attestation metadata (must include `$type`)
/// * `repository` - The repository DID to bind the attestation to (prevents replay attacks)
///
/// # Returns
///
/// The generated CID for the prepared attestation record
///
/// # Errors
///
/// Returns an error if:
/// - The record or metadata are not valid JSON objects
/// - The record is missing the required `$type` field
/// - The metadata is missing the required `$type` field
/// - DAG-CBOR serialization fails
pub fn create_attestation_cid<R: Serialize + Clone, M: Serialize + Clone>(
    record_input: AnyInput<R>,
    metadata_input: AnyInput<M>,
    repository: &str,
) -> Result<Cid, AttestationError> {
    let mut record_obj: Map<String, Value> = record_input
        .try_into()
        .map_err(|_| AttestationError::RecordMustBeObject)?;

    if record_obj
        .get("$type")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(AttestationError::RecordMissingType);
    }

    let mut metadata_obj: Map<String, Value> = metadata_input
        .try_into()
        .map_err(|_| AttestationError::MetadataMustBeObject)?;

    if metadata_obj
        .get("$type")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(AttestationError::MetadataMissingSigType);
    }

    record_obj.remove("signatures");

    metadata_obj.remove("cid");
    metadata_obj.remove("signature");
    metadata_obj.insert(
        "repository".to_string(),
        Value::String(repository.to_string()),
    );

    record_obj.insert("$sig".to_string(), Value::Object(metadata_obj.clone()));

    // Directly pass the Map<String, Value> - no need to wrap in Value::Object
    create_dagbor_cid(&record_obj)
}

/// Validates that a CID string is a valid DAG-CBOR CID for AT Protocol attestations.
///
/// This function performs strict validation to ensure the CID meets the exact
/// specifications required for AT Protocol attestations:
///
/// 1. **Valid format**: The string must be a parseable CID
/// 2. **Version**: Must be CIDv1 (not CIDv0)
/// 3. **Codec**: Must use DAG-CBOR codec (0x71)
/// 4. **Hash algorithm**: Must use SHA-256 (multihash code 0x12)
/// 5. **Hash length**: Must have exactly 32 bytes (SHA-256 standard)
///
/// These requirements ensure consistency and security across the AT Protocol
/// ecosystem, particularly for content addressing and attestation verification.
///
/// # Arguments
///
/// * `cid` - A string slice containing the CID to validate
///
/// # Returns
///
/// * `true` if the CID is a valid DAG-CBOR CID with SHA-256 hash
/// * `false` if the CID is invalid or doesn't meet any requirement
///
/// # Examples
///
/// ```rust
/// use atproto_attestation::cid::validate_dagcbor_cid;
///
/// // Valid AT Protocol CID (CIDv1, DAG-CBOR, SHA-256)
/// let valid_cid = "bafyreigw5bqvbz6m3c3zjpqhxwl4njlnbbnw5xvptbx6dzfxjqcde6lt3y";
/// assert!(validate_dagcbor_cid(valid_cid));
///
/// // Invalid: Empty string
/// assert!(!validate_dagcbor_cid(""));
///
/// // Invalid: Not a CID
/// assert!(!validate_dagcbor_cid("not-a-cid"));
///
/// // Invalid: CIDv0 (starts with Qm)
/// let cid_v0 = "QmYwAPJzv5CZsnA625ub3XtLxT3Tz5Lno5Wqv9eKewWKjE";
/// assert!(!validate_dagcbor_cid(cid_v0));
/// ```
pub fn validate_dagcbor_cid(cid: &str) -> bool {
    if cid.is_empty() {
        return false;
    }

    // Parse the CID using the cid crate for proper validation
    let parsed_cid = match Cid::try_from(cid) {
        Ok(value) => value,
        Err(_) => return false,
    };

    // Verify it's CIDv1 (version 1)
    if parsed_cid.version() != cid::Version::V1 {
        return false;
    }

    // Verify it uses DAG-CBOR codec (0x71)
    if parsed_cid.codec() != DAG_CBOR_CODEC {
        return false;
    }

    // Get the multihash and verify it uses SHA-256
    let multihash = parsed_cid.hash();

    // SHA-256 code is 0x12
    if multihash.code() != MULTIHASH_SHA256 {
        return false;
    }

    // Verify the hash digest is 32 bytes (SHA-256 standard)
    if multihash.digest().len() != 32 {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_record::typed::TypedLexicon;
    use serde::Deserialize;

    #[tokio::test]
    async fn test_create_attestation_cid() -> Result<(), AttestationError> {
        use atproto_record::datetime::format as datetime_format;
        use chrono::{DateTime, Utc};

        // Define test record type with createdAt and text fields
        #[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
        struct TestRecord {
            #[serde(rename = "createdAt", with = "datetime_format")]
            created_at: DateTime<Utc>,
            text: String,
        }

        impl LexiconType for TestRecord {
            fn lexicon_type() -> &'static str {
                "com.example.testrecord"
            }
        }

        // Define test metadata type
        #[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
        struct TestMetadata {
            #[serde(rename = "createdAt", with = "datetime_format")]
            created_at: DateTime<Utc>,
            purpose: String,
        }

        impl LexiconType for TestMetadata {
            fn lexicon_type() -> &'static str {
                "com.example.testmetadata"
            }
        }

        // Create test data
        let created_at = DateTime::parse_from_rfc3339("2025-01-15T14:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);

        let record = TestRecord {
            created_at,
            text: "Hello, AT Protocol!".to_string(),
        };

        let metadata_created_at = DateTime::parse_from_rfc3339("2025-01-15T14:05:00.000Z")
            .unwrap()
            .with_timezone(&Utc);

        let metadata = TestMetadata {
            created_at: metadata_created_at,
            purpose: "attestation".to_string(),
        };

        let repository = "did:plc:test123";

        // Create typed lexicons
        let typed_record = TypedLexicon::new(record);
        let typed_metadata = TypedLexicon::new(metadata);

        // Call the function
        let cid = create_attestation_cid(
            AnyInput::Serialize(typed_record),
            AnyInput::Serialize(typed_metadata),
            repository,
        )?;

        // Verify CID properties
        assert_eq!(cid.codec(), 0x71, "CID should use dag-cbor codec");
        assert_eq!(cid.hash().code(), 0x12, "CID should use sha2-256 hash");
        assert_eq!(
            cid.hash().digest().len(),
            32,
            "Hash digest should be 32 bytes"
        );
        assert_eq!(cid.to_bytes().len(), 36, "CID should be 36 bytes total");

        Ok(())
    }

    #[tokio::test]
    async fn test_create_attestation_cid_deterministic() -> Result<(), AttestationError> {
        use atproto_record::datetime::format as datetime_format;
        use chrono::{DateTime, Utc};

        // Define simple test types
        #[derive(Serialize, Deserialize, PartialEq, Clone)]
        struct SimpleRecord {
            #[serde(rename = "createdAt", with = "datetime_format")]
            created_at: DateTime<Utc>,
            text: String,
        }

        impl LexiconType for SimpleRecord {
            fn lexicon_type() -> &'static str {
                "com.example.simple"
            }
        }

        #[derive(Serialize, Deserialize, PartialEq, Clone)]
        struct SimpleMetadata {
            #[serde(rename = "createdAt", with = "datetime_format")]
            created_at: DateTime<Utc>,
        }

        impl LexiconType for SimpleMetadata {
            fn lexicon_type() -> &'static str {
                "com.example.meta"
            }
        }

        let created_at = DateTime::parse_from_rfc3339("2025-01-01T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);

        let record1 = SimpleRecord {
            created_at,
            text: "test".to_string(),
        };
        let record2 = SimpleRecord {
            created_at,
            text: "test".to_string(),
        };

        let metadata1 = SimpleMetadata { created_at };
        let metadata2 = SimpleMetadata { created_at };

        let repository = "did:plc:same";

        // Create CIDs for identical records
        let cid1 = create_attestation_cid(
            AnyInput::Serialize(TypedLexicon::new(record1)),
            AnyInput::Serialize(TypedLexicon::new(metadata1)),
            repository,
        )?;

        let cid2 = create_attestation_cid(
            AnyInput::Serialize(TypedLexicon::new(record2)),
            AnyInput::Serialize(TypedLexicon::new(metadata2)),
            repository,
        )?;

        // Verify determinism: identical inputs produce identical CIDs
        assert_eq!(
            cid1, cid2,
            "Identical records should produce identical CIDs"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_create_attestation_cid_different_repositories() -> Result<(), AttestationError> {
        use atproto_record::datetime::format as datetime_format;
        use chrono::{DateTime, Utc};

        #[derive(Serialize, Deserialize, PartialEq, Clone)]
        struct RepoRecord {
            #[serde(rename = "createdAt", with = "datetime_format")]
            created_at: DateTime<Utc>,
            text: String,
        }

        impl LexiconType for RepoRecord {
            fn lexicon_type() -> &'static str {
                "com.example.repo"
            }
        }

        #[derive(Serialize, Deserialize, PartialEq, Clone)]
        struct RepoMetadata {
            #[serde(rename = "createdAt", with = "datetime_format")]
            created_at: DateTime<Utc>,
        }

        impl LexiconType for RepoMetadata {
            fn lexicon_type() -> &'static str {
                "com.example.repometa"
            }
        }

        let created_at = DateTime::parse_from_rfc3339("2025-01-01T12:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);

        let record = RepoRecord {
            created_at,
            text: "content".to_string(),
        };
        let metadata = RepoMetadata { created_at };

        // Same record and metadata, different repositories
        let cid1 = create_attestation_cid(
            AnyInput::Serialize(TypedLexicon::new(record.clone())),
            AnyInput::Serialize(TypedLexicon::new(metadata.clone())),
            "did:plc:repo1",
        )?;

        let cid2 = create_attestation_cid(
            AnyInput::Serialize(TypedLexicon::new(record)),
            AnyInput::Serialize(TypedLexicon::new(metadata)),
            "did:plc:repo2",
        )?;

        // Different repositories should produce different CIDs (prevents replay attacks)
        assert_ne!(
            cid1, cid2,
            "Different repository DIDs should produce different CIDs"
        );

        Ok(())
    }

    #[test]
    fn test_validate_dagcbor_cid() {
        // Test valid CID (generated from our own create_dagbor_cid function)
        let valid_data = serde_json::json!({"test": "data"});
        let valid_cid = create_dagbor_cid(&valid_data).unwrap();
        let valid_cid_str = valid_cid.to_string();
        assert!(
            validate_dagcbor_cid(&valid_cid_str),
            "Valid CID should pass validation"
        );

        // Test empty string
        assert!(
            !validate_dagcbor_cid(""),
            "Empty string should fail validation"
        );

        // Test invalid CID string
        assert!(
            !validate_dagcbor_cid("not-a-cid"),
            "Invalid string should fail validation"
        );
        assert!(
            !validate_dagcbor_cid("abc123"),
            "Invalid string should fail validation"
        );

        // Test CIDv0 (starts with Qm, uses different format)
        let cid_v0 = "QmYwAPJzv5CZsnA625ub3XtLxT3Tz5Lno5Wqv9eKewWKjE";
        assert!(
            !validate_dagcbor_cid(cid_v0),
            "CIDv0 should fail validation"
        );

        // Test valid CID base32 format but wrong codec (not DAG-CBOR)
        // This is a valid CID but uses raw codec (0x55) instead of DAG-CBOR (0x71)
        let wrong_codec = "bafkreigw5bqvbz6m3c3zjpqhxwl4njlnbbnw5xvptbx6dzfxjqcde6lt3y";
        assert!(
            !validate_dagcbor_cid(wrong_codec),
            "CID with wrong codec should fail"
        );

        // Test that our constants match what we're checking
        assert_eq!(
            DAG_CBOR_CODEC, 0x71,
            "DAG-CBOR codec constant should be 0x71"
        );
        assert_eq!(
            MULTIHASH_SHA256, 0x12,
            "SHA-256 multihash code should be 0x12"
        );
    }

    #[tokio::test]
    async fn phantom_data_test() -> Result<(), AttestationError> {
        let repository = "did:web:example.com";

        #[derive(Serialize, Deserialize, PartialEq, Clone)]
        struct FooRecord {
            text: String,
        }

        impl LexiconType for FooRecord {
            fn lexicon_type() -> &'static str {
                "com.example.foo"
            }
        }

        #[derive(Serialize, Deserialize, PartialEq, Clone)]
        struct BarRecord {
            text: String,
        }

        impl LexiconType for BarRecord {
            fn lexicon_type() -> &'static str {
                "com.example.bar"
            }
        }

        let foo = FooRecord {
            text: "foo".to_string(),
        };
        let typed_foo = TypedLexicon::new(foo);

        let bar = BarRecord {
            text: "bar".to_string(),
        };
        let typed_bar = TypedLexicon::new(bar);

        let cid1 = create_attestation_cid(
            AnyInput::Serialize(typed_foo.clone()),
            AnyInput::Serialize(typed_bar.clone()),
            repository,
        )?;

        let value_bar = serde_json::to_value(typed_bar).expect("bar serde_json::Value conversion");

        let cid2 = create_attestation_cid(
            AnyInput::Serialize(typed_foo),
            AnyInput::Serialize(value_bar),
            repository,
        )?;

        assert_eq!(
            cid1, cid2,
            "Different repository DIDs should produce different CIDs"
        );

        Ok(())
    }
}
