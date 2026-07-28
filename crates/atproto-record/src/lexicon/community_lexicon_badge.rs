//! Badge and award types for AT Protocol.
//!
//! This module provides types for badge definitions and awards in the AT Protocol.
//! Badges can be defined with names, descriptions, and optional images, then awarded
//! to users with cryptographic signatures for verification.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::lexicon::{
    TypedBlob, com::atproto::repo::StrongRef, community::lexicon::attestation::Signatures,
};
use crate::typed::{LexiconType, TypedLexicon};

/// The namespace identifier for badge definitions
pub const DEFINITION_NSID: &str = "community.lexicon.badge.definition";
/// The namespace identifier for badge awards
pub const AWARD_NSID: &str = "community.lexicon.badge.award";

/// Badge definition structure.
///
/// Defines a badge that can be awarded to users. Badges have a name,
/// description, and optional visual representation.
///
/// # Example
///
/// ```ignore
/// use atproto_record::lexicon::community::lexicon::badge::{Definition, TypedDefinition};
/// use std::collections::HashMap;
///
/// let badge = Definition {
///     name: "Early Adopter".to_string(),
///     description: "Joined the platform in the first month".to_string(),
///     image: None,
///     extra: HashMap::new(),
/// };
///
/// let typed_badge = TypedDefinition::new(badge);
/// ```
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Definition {
    /// Name of the badge
    pub name: String,
    /// Description of what the badge represents
    pub description: String,

    /// Optional badge image
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<TypedBlob>,

    /// Extension fields for forward compatibility
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl LexiconType for Definition {
    fn lexicon_type() -> &'static str {
        DEFINITION_NSID
    }
}

/// Type alias for Definition with automatic $type field handling
#[allow(dead_code)]
pub type TypedDefinition = TypedLexicon<Definition>;

/// Badge award structure.
///
/// Represents the awarding of a badge to a specific user (identified by DID).
/// Awards include the badge reference, recipient, issue date, and optional
/// signatures for verification.
///
/// # Example
///
/// ```ignore
/// use atproto_record::lexicon::community::lexicon::badge::{Award, TypedAward};
/// use atproto_record::lexicon::com::atproto::repo::{StrongRef, TypedStrongRef};
/// use chrono::Utc;
/// use std::collections::HashMap;
///
/// let award = Award {
///     badge: StrongRef {
///         uri: "at://did:plc:issuer/community.lexicon.badge.definition/badge123".to_string(),
///         cid: "bafyreicid123".to_string(),
///     },
///     did: "did:plc:recipient".to_string(),
///     issued: Utc::now(),
///     signatures: vec![],
///     extra: HashMap::new(),
/// };
///
/// let typed_award = TypedAward::new(award);
/// ```
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Award {
    /// Reference to the badge definition being awarded
    pub badge: StrongRef,
    /// DID of the recipient
    pub did: String,
    /// When the badge was awarded
    pub issued: DateTime<Utc>,

    /// Optional signatures for verification
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub signatures: Signatures,

    /// Extension fields for forward compatibility
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl LexiconType for Award {
    fn lexicon_type() -> &'static str {
        AWARD_NSID
    }
}

/// Type alias for Award with automatic $type field handling
#[allow(dead_code)]
pub type TypedAward = TypedLexicon<Award>;

#[cfg(test)]
mod tests {
    use crate::lexicon::com_atproto_repo::StrongRef;
    use crate::lexicon::{Blob, Link};

    use super::*;
    use anyhow::Result;

    #[test]
    fn test_deserialize_badge_definition() -> Result<()> {
        let json = r#"{
            "name": "Bug Squasher",
            "$type": "community.lexicon.badge.definition",
            "image": {
                "$type": "blob",
                "ref": {
                    "$link": "bafkreigb3vxlgckp66o2bffnwapagshpt2xdcgdltuzjymapobvgunxmfi"
                },
                "mimeType": "image/png",
                "size": 177111
            },
            "description": "You've helped squash Smoke Signal bugs."
        }"#;

        let typed_def: TypedDefinition = serde_json::from_str(json)?;
        let definition = typed_def.inner;

        assert_eq!(definition.name, "Bug Squasher");
        assert_eq!(
            definition.description,
            "You've helped squash Smoke Signal bugs."
        );

        assert!(definition.image.is_some());
        if let Some(typed_blob) = definition.image {
            // The blob is now wrapped in TypedBlob, so we access via .inner
            let img = typed_blob.inner;
            assert_eq!(img.mime_type, "image/png");
            assert_eq!(img.size, 177111);
            assert_eq!(
                img.ref_.link,
                "bafkreigb3vxlgckp66o2bffnwapagshpt2xdcgdltuzjymapobvgunxmfi"
            );
        }

        Ok(())
    }

    #[test]
    fn test_deserialize_badge_definition_without_image() -> Result<()> {
        let json = r#"{
            "name": "Text Badge",
            "$type": "community.lexicon.badge.definition",
            "description": "A badge without an image."
        }"#;

        let typed_def: TypedDefinition = serde_json::from_str(json)?;
        let definition = typed_def.inner;

        assert_eq!(definition.name, "Text Badge");
        assert_eq!(definition.description, "A badge without an image.");
        assert!(definition.image.is_none());

        Ok(())
    }

    #[test]
    fn test_serialize_badge_definition() -> Result<()> {
        let definition = Definition {
            name: "Test Badge".to_string(),
            description: "A test badge".to_string(),
            image: Some(TypedLexicon::new(Blob {
                ref_: Link {
                    link: "bafkreitest123".to_string(),
                },
                mime_type: "image/png".to_string(),
                size: 12345,
            })),
            extra: HashMap::new(),
        };
        let typed_def = TypedLexicon::new(definition);

        let json = serde_json::to_string_pretty(&typed_def)?;

        // Verify it contains the expected fields
        assert!(json.contains("\"$type\": \"community.lexicon.badge.definition\""));
        assert!(json.contains("\"name\": \"Test Badge\""));
        assert!(json.contains("\"description\": \"A test badge\""));
        assert!(json.contains("\"$link\": \"bafkreitest123\""));
        assert!(json.contains("\"mimeType\": \"image/png\""));
        assert!(json.contains("\"size\": 12345"));

        Ok(())
    }

    #[test]
    fn test_deserialize_badge_award() -> Result<()> {
        let json = r#"{
            "$type": "community.lexicon.badge.award",
            "badge": {
                "cid": "bafyreiansi5jdnsam57ouyzk7zf5vatvzo7narb5o5z3zm7e5lhd4iw5d4",
                "uri": "at://did:plc:tgudj2fjm77pzkuawquqhsxm/community.lexicon.badge.definition/3lqt67gc2i32c"
            },
            "did": "did:plc:cbkjy5n7bk3ax2wplmtjofq2",
            "issued": "2025-06-08T22:10:55.000Z",
            "signatures": []
        }"#;

        let typed_award: TypedAward = serde_json::from_str(json)?;
        let award = typed_award.inner;

        assert_eq!(award.did, "did:plc:cbkjy5n7bk3ax2wplmtjofq2");
        assert_eq!(award.issued.to_rfc3339(), "2025-06-08T22:10:55+00:00");
        assert!(award.signatures.is_empty());

        // badge is a TypedStrongRef, so we access the inner StrongRef
        let badge_ref = &award.badge;
        assert_eq!(
            badge_ref.cid,
            "bafyreiansi5jdnsam57ouyzk7zf5vatvzo7narb5o5z3zm7e5lhd4iw5d4"
        );
        assert_eq!(
            badge_ref.uri,
            "at://did:plc:tgudj2fjm77pzkuawquqhsxm/community.lexicon.badge.definition/3lqt67gc2i32c"
        );

        Ok(())
    }

    #[test]
    fn test_serialize_badge_award() -> Result<()> {
        use chrono::TimeZone;

        let badge = StrongRef {
            uri: "at://did:plc:test/community.lexicon.badge.definition/abc123".to_string(),
            cid: "bafyreicidtest123".to_string(),
        };
        let award = Award {
            badge,
            did: "did:plc:recipient123".to_string(),
            issued: Utc.with_ymd_and_hms(2025, 6, 8, 22, 10, 55).unwrap(),
            signatures: vec![],
            extra: HashMap::new(),
        };
        let typed_award = TypedLexicon::new(award);

        let json = serde_json::to_string_pretty(&typed_award)?;

        // Verify it contains the expected fields
        assert!(json.contains("\"$type\": \"community.lexicon.badge.award\""));
        assert!(json.contains("\"did\": \"did:plc:recipient123\""));
        assert!(json.contains("\"issued\": \"2025-06-08T22:10:55Z\""));
        // Empty signatures array is skipped in serialization due to skip_serializing_if
        assert!(!json.contains("\"signatures\""));

        Ok(())
    }

    #[test]
    fn test_badge_award_with_signatures() -> Result<()> {
        let json = r#"{
            "$type": "community.lexicon.badge.award",
            "badge": {
                "$type": "com.atproto.repo.strongRef",
                "cid": "bafyreicid123",
                "uri": "at://did:plc:issuer/community.lexicon.badge.definition/badge123"
            },
            "did": "did:plc:recipient",
            "issued": "2025-06-08T12:00:00.000Z",
            "signatures": [
                {
                    "$type": "community.lexicon.attestation.signature",
                    "issuer": "did:plc:issuer",
                    "signature": {"$bytes": "dGVzdCBzaWduYXR1cmU="}
                }
            ]
        }"#;

        let typed_award: TypedAward = serde_json::from_str(json)?;
        let award = typed_award.inner;

        assert_eq!(award.did, "did:plc:recipient");
        assert_eq!(award.signatures.len(), 1);

        match award.signatures.first() {
            Some(sig_or_ref) => {
                // The signature should be inline in this test
                match sig_or_ref {
                    crate::lexicon::community_lexicon_attestation::SignatureOrRef::Inline(sig) => {
                        // The bytes should match the decoded base64 value
                        // "dGVzdCBzaWduYXR1cmU=" decodes to "test signature"
                        assert_eq!(sig.inner.signature.bytes, b"test signature".to_vec());
                    }
                    _ => panic!("Expected inline signature"),
                }
            }
            None => panic!("Expected signature data"),
        }

        Ok(())
    }

    #[test]
    fn test_typed_patterns() -> Result<()> {
        // Test that typed patterns automatically handle $type fields

        // StrongRef without explicit $type field
        let badge = StrongRef {
            uri: "at://example".to_string(),
            cid: "bafytest".to_string(),
        };

        // Definition without explicit $type field
        let definition = Definition {
            name: "Test".to_string(),
            description: "Test desc".to_string(),
            image: None,
            extra: HashMap::new(),
        };
        let typed_def = TypedLexicon::new(definition);
        let json = serde_json::to_value(&typed_def)?;
        assert_eq!(json["$type"], "community.lexicon.badge.definition");

        // Award without explicit $type field
        let award = Award {
            badge,
            did: "did:plc:test".to_string(),
            issued: Utc::now(),
            signatures: vec![],
            extra: HashMap::new(),
        };
        let typed_award = TypedLexicon::new(award);
        let json = serde_json::to_value(&typed_award)?;
        assert_eq!(json["$type"], "community.lexicon.badge.award");

        Ok(())
    }
}
