//! RSVP types for calendar events in AT Protocol.
//!
//! This module provides types for representing RSVPs (responses) to calendar
//! events, including status indicators and signature support for verification.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::datetime::format as datetime_format;
use crate::lexicon::com::atproto::repo::StrongRef;
use crate::lexicon::community_lexicon_attestation::Signatures;
use crate::typed::{LexiconType, TypedLexicon};

/// The namespace identifier for RSVPs
pub const NSID: &str = "community.lexicon.calendar.rsvp";

/// RSVP status enumeration.
///
/// Represents the response status for an event invitation.
#[derive(Serialize, Deserialize, PartialEq, Clone, Default)]
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
pub enum RsvpStatus {
    /// Attendee is planning to attend
    #[default]
    #[serde(rename = "community.lexicon.calendar.rsvp#going")]
    Going,

    /// Attendee is interested but not confirmed
    #[serde(rename = "community.lexicon.calendar.rsvp#interested")]
    Interested,

    /// Attendee is not planning to attend
    #[serde(rename = "community.lexicon.calendar.rsvp#notgoing")]
    NotGoing,
}

/// RSVP record structure.
///
/// Represents a user's response to an event invitation, including their
/// attendance status and optional signatures for verification.
///
/// # Example
///
/// ```ignore
/// use atproto_record::lexicon::community::lexicon::calendar::rsvp::{Rsvp, TypedRsvp, RsvpStatus};
/// use atproto_record::lexicon::com::atproto::repo::StrongRef;
/// use chrono::Utc;
/// use std::collections::HashMap;
///
/// let rsvp = Rsvp {
///     subject: StrongRef {
///         uri: "at://did:plc:example/community.lexicon.calendar.event/abc123".to_string(),
///         cid: "bafyreicid123".to_string(),
///     },
///     status: RsvpStatus::Going,
///     created_at: Utc::now(),
///     signatures: vec![],
///     extra: HashMap::new(),
/// };
///
/// // Use TypedRsvp for automatic $type field handling
/// let typed_rsvp = TypedRsvp::new(rsvp);
/// ```
#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
pub struct Rsvp {
    /// Reference to the event being responded to
    pub subject: StrongRef,

    /// The RSVP status (going, interested, not going)
    pub status: RsvpStatus,

    /// When this RSVP was created
    #[serde(rename = "createdAt", with = "datetime_format")]
    pub created_at: DateTime<Utc>,

    /// Optional signatures for verification
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub signatures: Signatures,

    /// Extension fields for forward compatibility
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl LexiconType for Rsvp {
    fn lexicon_type() -> &'static str {
        NSID
    }
}

/// Type alias for Rsvp with automatic $type field handling.
///
/// This wrapper ensures that the `$type` field is automatically
/// added during serialization and validated during deserialization.
pub type TypedRsvp = TypedLexicon<Rsvp>;

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use chrono::TimeZone;

    #[test]
    fn test_typed_rsvp_serialization() -> Result<()> {
        // Create an RSVP without explicit $type field
        let rsvp = Rsvp {
            subject: StrongRef {
                uri: "at://did:plc:example/community.lexicon.calendar.event/event123".to_string(),
                cid: "bafyreievent123".to_string(),
            },
            status: RsvpStatus::Going,
            created_at: Utc.with_ymd_and_hms(2025, 1, 15, 14, 0, 0).unwrap(),
            signatures: vec![],
            extra: HashMap::new(),
        };

        // Wrap it in TypedRsvp
        let typed_rsvp = TypedLexicon::new(rsvp);

        // Serialize and verify $type is added
        let json = serde_json::to_value(&typed_rsvp)?;
        assert_eq!(json["$type"], "community.lexicon.calendar.rsvp");
        assert_eq!(
            json["subject"]["uri"],
            "at://did:plc:example/community.lexicon.calendar.event/event123"
        );
        assert_eq!(json["subject"]["cid"], "bafyreievent123");
        assert_eq!(json["status"], "community.lexicon.calendar.rsvp#going");
        assert_eq!(json["createdAt"], "2025-01-15T14:00:00.000Z");

        Ok(())
    }

    #[test]
    fn test_typed_rsvp_deserialization() -> Result<()> {
        let json_str = r#"{
            "$type": "community.lexicon.calendar.rsvp",
            "subject": {
                "uri": "at://did:plc:test/community.lexicon.calendar.event/abc",
                "cid": "bafyreicid456"
            },
            "status": "community.lexicon.calendar.rsvp#interested",
            "createdAt": "2025-01-10T10:00:00Z",
            "signatures": []
        }"#;

        let typed_rsvp: TypedRsvp = serde_json::from_str(json_str)?;

        assert_eq!(
            typed_rsvp.inner.subject.uri,
            "at://did:plc:test/community.lexicon.calendar.event/abc"
        );
        assert_eq!(typed_rsvp.inner.subject.cid, "bafyreicid456");
        assert_eq!(typed_rsvp.inner.status, RsvpStatus::Interested);
        assert!(typed_rsvp.has_type_field());
        assert!(typed_rsvp.validate().is_ok());

        Ok(())
    }

    #[test]
    fn test_typed_rsvp_without_type_field() -> Result<()> {
        // Test that we can deserialize an RSVP without $type field
        let json_str = r#"{
            "subject": {
                "uri": "at://did:plc:test/community.lexicon.calendar.event/xyz",
                "cid": "bafyreicid789"
            },
            "status": "community.lexicon.calendar.rsvp#notgoing",
            "createdAt": "2025-01-05T15:30:00Z",
            "signatures": []
        }"#;

        let typed_rsvp: TypedRsvp = serde_json::from_str(json_str)?;

        assert_eq!(
            typed_rsvp.inner.subject.uri,
            "at://did:plc:test/community.lexicon.calendar.event/xyz"
        );
        assert_eq!(typed_rsvp.inner.status, RsvpStatus::NotGoing);
        assert!(!typed_rsvp.has_type_field());

        // Validation should fail because type is required by default
        assert!(typed_rsvp.validate().is_err());

        Ok(())
    }

    #[test]
    fn test_rsvp_status_serialization() -> Result<()> {
        // Test all RSVP status values
        let statuses = vec![
            (RsvpStatus::Going, "community.lexicon.calendar.rsvp#going"),
            (
                RsvpStatus::Interested,
                "community.lexicon.calendar.rsvp#interested",
            ),
            (
                RsvpStatus::NotGoing,
                "community.lexicon.calendar.rsvp#notgoing",
            ),
        ];

        for (status, expected) in statuses {
            let json = serde_json::to_value(&status)?;
            assert_eq!(json, expected);

            let deserialized: RsvpStatus = serde_json::from_value(json)?;
            assert_eq!(deserialized, status);
        }

        Ok(())
    }

    #[test]
    fn test_typed_rsvp_round_trip() -> Result<()> {
        let original = Rsvp {
            subject: StrongRef {
                uri: "at://did:plc:roundtrip/community.lexicon.calendar.event/test".to_string(),
                cid: "bafyreiroundtrip".to_string(),
            },
            status: RsvpStatus::Going,
            created_at: Utc.with_ymd_and_hms(2025, 2, 1, 12, 0, 0).unwrap(),
            signatures: vec![],
            extra: HashMap::new(),
        };

        let typed = TypedLexicon::new(original.clone());

        let json = serde_json::to_string(&typed)?;
        let deserialized: TypedRsvp = serde_json::from_str(&json)?;

        assert_eq!(deserialized.inner.subject.uri, original.subject.uri);
        assert_eq!(deserialized.inner.subject.cid, original.subject.cid);
        assert_eq!(deserialized.inner.status, original.status);
        assert_eq!(deserialized.inner.created_at, original.created_at);
        assert!(deserialized.has_type_field());

        Ok(())
    }

    #[test]
    fn test_rsvp_with_extra_fields() -> Result<()> {
        let json_str = r#"{
            "$type": "community.lexicon.calendar.rsvp",
            "subject": {
                "uri": "at://did:plc:test/community.lexicon.calendar.event/extra",
                "cid": "bafyreiextra"
            },
            "status": "community.lexicon.calendar.rsvp#going",
            "createdAt": "2025-01-20T09:00:00Z",
            "signatures": [],
            "customField": "customValue",
            "anotherField": 42
        }"#;

        let typed_rsvp: TypedRsvp = serde_json::from_str(json_str)?;

        assert_eq!(typed_rsvp.inner.extra.len(), 2);
        assert_eq!(
            typed_rsvp.inner.extra.get("customField").unwrap(),
            "customValue"
        );
        assert_eq!(typed_rsvp.inner.extra.get("anotherField").unwrap(), 42);

        Ok(())
    }

    #[test]
    fn test_rsvp_with_signatures() -> Result<()> {
        use crate::lexicon::community_lexicon_attestation::SignatureOrRef;

        let json_str = r#"{
            "$type": "community.lexicon.calendar.rsvp",
            "subject": {
                "uri": "at://did:plc:test/community.lexicon.calendar.event/signed",
                "cid": "bafyreisigned"
            },
            "status": "community.lexicon.calendar.rsvp#going",
            "createdAt": "2025-01-25T16:00:00Z",
            "signatures": [
                {
                    "$type": "community.lexicon.attestation.signature",
                    "issuer": "did:plc:issuer",
                    "signature": {"$bytes": "dGVzdCBzaWduYXR1cmU="}
                }
            ]
        }"#;

        let typed_rsvp: TypedRsvp = serde_json::from_str(json_str)?;

        assert_eq!(typed_rsvp.inner.signatures.len(), 1);
        match &typed_rsvp.inner.signatures[0] {
            SignatureOrRef::Inline(sig) => {
                assert_eq!(sig.inner.signature.bytes, b"test signature");
            }
            _ => panic!("Expected inline signature"),
        }

        Ok(())
    }

    #[test]
    fn test_deserialize_real_rsvp_with_signature() -> Result<()> {
        use crate::lexicon::community_lexicon_attestation::SignatureOrRef;
        use chrono::Timelike;
        use serde_json::Value;

        // Real RSVP JSON with actual signature from the user
        let json_str = r#"{
            "$type": "community.lexicon.calendar.rsvp",
            "createdAt": "2025-08-19T20:17:17.133Z",
            "signatures": [
                {
                    "$type": "community.lexicon.attestation.signature",
                    "issuedAt": "2025-08-19T20:17:17.133Z",
                    "issuer": "did:web:acudo-dev.smokesignal.tools",
                    "signature": {
                        "$bytes": "mr9c0MCu3g6SXNQ25JFhzfX1ecYgK9k1Kf6OZI2p2AlQRoQu09dOE7J5uaeilIx/UFCjJErO89C/uBBb9ANmUA"
                    }
                }
            ],
            "status": "community.lexicon.calendar.rsvp#going",
            "subject": {
                "cid": "bafyreidtr72nriwlscae3gfwhckxiy427b6ni5jmetzkvaafimeuelnlxa",
                "uri": "at://did:web:acudo-dev.smokesignal.tools/community.lexicon.calendar.event/3lwrfkzy36k2s"
            }
        }"#;

        // First parse as generic JSON to verify structure
        let json_value: Value = serde_json::from_str(json_str)?;
        assert_eq!(json_value["$type"], "community.lexicon.calendar.rsvp");
        assert_eq!(
            json_value["status"],
            "community.lexicon.calendar.rsvp#going"
        );

        // Deserialize the JSON
        let typed_rsvp: TypedRsvp = serde_json::from_str(json_str)?;

        // Verify the basic fields
        assert_eq!(typed_rsvp.inner.status, RsvpStatus::Going);
        assert_eq!(
            typed_rsvp.inner.subject.uri,
            "at://did:web:acudo-dev.smokesignal.tools/community.lexicon.calendar.event/3lwrfkzy36k2s"
        );
        assert_eq!(
            typed_rsvp.inner.subject.cid,
            "bafyreidtr72nriwlscae3gfwhckxiy427b6ni5jmetzkvaafimeuelnlxa"
        );

        // Verify the timestamp
        let expected_time = Utc
            .with_ymd_and_hms(2025, 8, 19, 20, 17, 17)
            .unwrap()
            .with_nanosecond(133_000_000)
            .unwrap();
        assert_eq!(typed_rsvp.inner.created_at, expected_time);

        // Verify the signature
        assert_eq!(typed_rsvp.inner.signatures.len(), 1);
        match &typed_rsvp.inner.signatures[0] {
            SignatureOrRef::Inline(sig) => {
                // Verify the issuedAt field if present
                if let Some(issued_at_value) = sig.inner.extra.get("issuedAt") {
                    assert_eq!(issued_at_value, "2025-08-19T20:17:17.133Z");
                }

                // Verify the signature is base64 encoded data
                // The signature should be 64 bytes for P-256 ECDSA (32 bytes for r, 32 bytes for s)
                assert_eq!(sig.inner.signature.bytes.len(), 64);
            }
            _ => panic!("Expected inline signature"),
        }

        // Verify the type field is present
        assert!(typed_rsvp.has_type_field());
        assert!(typed_rsvp.validate().is_ok());

        Ok(())
    }
}
