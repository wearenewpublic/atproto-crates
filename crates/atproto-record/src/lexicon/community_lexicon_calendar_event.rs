//! Calendar event types for AT Protocol.
//!
//! This module provides types for representing calendar events with support
//! for various event properties including status, mode (in-person/virtual/hybrid),
//! locations, media, and links.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::datetime::format as datetime_format;
use crate::datetime::optional_format as optional_datetime_format;
use crate::lexicon::TypedBlob;
use crate::lexicon::app::bsky::richtext::facet::Facet;
use crate::lexicon::community::lexicon::location::LocationOrRef;
use crate::typed::{LexiconType, TypedLexicon};

/// Lexicon namespace identifier for calendar events.
///
/// Used as the `$type` field value for event records in the AT Protocol.
pub const NSID: &str = "community.lexicon.calendar.event";

/// Event status enumeration.
///
/// Represents the current status of a calendar event.
#[derive(Serialize, Deserialize, PartialEq, Clone, Default)]
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
pub enum Status {
    /// Event is scheduled and confirmed
    #[default]
    #[serde(rename = "community.lexicon.calendar.event#scheduled")]
    Scheduled,

    /// Event has been rescheduled to a new time
    #[serde(rename = "community.lexicon.calendar.event#rescheduled")]
    Rescheduled,

    /// Event has been cancelled
    #[serde(rename = "community.lexicon.calendar.event#cancelled")]
    Cancelled,

    /// Event has been postponed (new date TBD)
    #[serde(rename = "community.lexicon.calendar.event#postponed")]
    Postponed,

    /// Event is being planned but not yet confirmed
    #[serde(rename = "community.lexicon.calendar.event#planned")]
    Planned,
}

/// Event mode enumeration.
///
/// Represents how attendees can participate in the event.
#[derive(Serialize, Deserialize, PartialEq, Clone, Default)]
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
pub enum Mode {
    /// In-person attendance only
    #[default]
    #[serde(rename = "community.lexicon.calendar.event#inperson")]
    InPerson,

    /// Virtual/online attendance only
    #[serde(rename = "community.lexicon.calendar.event#virtual")]
    Virtual,

    /// Both in-person and virtual attendance options
    #[serde(rename = "community.lexicon.calendar.event#hybrid")]
    Hybrid,
}

/// Lexicon namespace identifier for named URIs in calendar events.
///
/// Used as the `$type` field value for URI references associated with events.
pub const NAMED_URI_NSID: &str = "community.lexicon.calendar.event#uri";

/// Named URI structure.
///
/// Represents a URI with an optional human-readable name.
/// Used for linking to external resources related to an event.
#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
pub struct NamedUri {
    /// The URI/URL
    pub uri: String,

    /// Optional human-readable name for the link
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
}

impl LexiconType for NamedUri {
    fn lexicon_type() -> &'static str {
        NAMED_URI_NSID
    }
}

/// Type alias for NamedUri with automatic $type field handling.
///
/// Wraps `NamedUri` in `TypedLexicon` to ensure proper serialization
/// and deserialization of the `$type` field.
pub type TypedNamedUri = TypedLexicon<NamedUri>;

/// Lexicon namespace identifier for event links.
///
/// Used as the `$type` field value for event link references.
/// Note: This shares the same NSID as `NAMED_URI_NSID` for compatibility.
pub const EVENT_LINK_NSID: &str = "community.lexicon.calendar.event#uri";

/// Event link structure.
///
/// Similar to NamedUri but kept as a separate type for semantic clarity
/// and type safety when dealing with event-specific links.
#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
pub struct EventLink {
    /// The URI/URL for the event link
    pub uri: String,

    /// Optional human-readable name for the link
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
}

impl LexiconType for EventLink {
    fn lexicon_type() -> &'static str {
        EVENT_LINK_NSID
    }
}

/// Type alias for EventLink with automatic $type field handling.
///
/// Wraps `EventLink` in `TypedLexicon` to ensure proper serialization
/// and deserialization of the `$type` field.
pub type TypedEventLink = TypedLexicon<EventLink>;

/// Collection of typed event links.
///
/// Represents multiple URI references associated with an event,
/// such as registration pages, live streams, or related content.
pub type EventLinks = Vec<TypedEventLink>;

/// Aspect ratio for media content.
///
/// Represents the width-to-height ratio of visual media.
#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
pub struct AspectRatio {
    /// Width component of the ratio
    pub width: u64,
    /// Height component of the ratio
    pub height: u64,
}

/// Lexicon namespace identifier for event media.
///
/// Used as the `$type` field value for media attachments associated with events.
pub const MEDIA_NSID: &str = "community.lexicon.calendar.event#media";

/// Default value for the media role field.
fn default_role() -> String {
    "banner".to_string()
}

/// Media structure for event-related visual content.
///
/// Represents images, videos, or other media associated with an event.
#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
pub struct Media {
    /// The media content as a blob reference
    pub content: TypedBlob,

    /// Alternative text description for accessibility
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub alt: String,

    /// The role/purpose of this media (e.g., "banner", "poster", "thumbnail")
    #[serde(default = "default_role")]
    pub role: String,

    /// Optional aspect ratio information
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub aspect_ratio: Option<AspectRatio>,
}

impl LexiconType for Media {
    fn lexicon_type() -> &'static str {
        MEDIA_NSID
    }
}

/// Type alias for Media with automatic $type field handling.
///
/// Wraps `Media` in `TypedLexicon` to ensure proper serialization
/// and deserialization of the `$type` field.
pub type TypedMedia = TypedLexicon<Media>;

/// Collection of typed media items.
///
/// Represents multiple media attachments for an event, such as banners,
/// posters, thumbnails, or promotional images.
pub type MediaList = Vec<TypedMedia>;

/// Enum that can hold a location, URI reference, or unknown type for calendar events.
///
/// Extends `LocationOrRef` with URI location support specific to calendar events.
#[derive(Deserialize, Serialize, Clone, PartialEq)]
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[serde(untagged)]
pub enum EventLocation {
    /// An inline URI location
    InlineUri(TypedNamedUri),
    /// A known location type (address, geo, h3, fsq, or reference)
    Location(LocationOrRef),
    /// An unknown or unrecognized location type
    Unknown(serde_json::Value),
}

/// A vector of event locations.
pub type EventLocations = Vec<EventLocation>;

/// Calendar event structure.
///
/// Represents a calendar event with comprehensive metadata including
/// timing, location, media, and status information.
///
/// # Example
///
/// ```ignore
/// use atproto_record::lexicon::community::lexicon::calendar::event::{Event, TypedEvent, Status, Mode};
/// use chrono::Utc;
/// use std::collections::HashMap;
///
/// let event = Event {
///     name: "Community Meetup".to_string(),
///     description: "Monthly community gathering".to_string(),
///     created_at: Utc::now(),
///     starts_at: Some(Utc::now()),
///     ends_at: None,
///     mode: Some(Mode::Hybrid),
///     status: Some(Status::Scheduled),
///     locations: vec![],
///     uris: vec![],
///     media: vec![],
///     extra: HashMap::new(),
/// };
///
/// let typed_event = TypedEvent::new(event);
/// ```
#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
pub struct Event {
    /// Name/title of the event
    pub name: String,

    /// Description of the event
    pub description: String,

    /// When the event record was created
    #[serde(rename = "createdAt", with = "datetime_format")]
    pub created_at: DateTime<Utc>,

    /// When the event starts (optional)
    #[serde(
        rename = "startsAt",
        skip_serializing_if = "Option::is_none",
        default,
        with = "optional_datetime_format"
    )]
    pub starts_at: Option<DateTime<Utc>>,

    /// When the event ends (optional)
    #[serde(
        rename = "endsAt",
        skip_serializing_if = "Option::is_none",
        default,
        with = "optional_datetime_format"
    )]
    pub ends_at: Option<DateTime<Utc>>,

    /// Event mode (in-person, virtual, hybrid)
    #[serde(rename = "mode", skip_serializing_if = "Option::is_none", default)]
    pub mode: Option<Mode>,

    /// Event status (scheduled, cancelled, etc.)
    #[serde(rename = "status", skip_serializing_if = "Option::is_none", default)]
    pub status: Option<Status>,

    /// Event locations (can be inline or referenced)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub locations: EventLocations,

    /// Related URIs/links for the event
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub uris: EventLinks,

    /// Media associated with the event
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub media: MediaList,

    /// Rich text facets for semantic annotations in description field.
    ///
    /// Enables mentions, links, and hashtags to be embedded in the event
    /// description text with proper semantic metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facets: Option<Vec<Facet>>,

    /// Extension fields for forward compatibility.
    /// This catch-all allows unknown fields to be preserved and indexed
    /// for potential future use without requiring re-indexing.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl LexiconType for Event {
    fn lexicon_type() -> &'static str {
        NSID
    }
}

/// Type alias for Event with automatic $type field handling.
///
/// This wrapper ensures proper serialization/deserialization of the
/// `$type` field for event records.
pub type TypedEvent = TypedLexicon<Event>;

#[cfg(test)]
mod tests {
    use crate::lexicon::Blob;

    use super::*;
    use anyhow::Result;

    #[test]
    fn test_event_location_uri() {
        let json_str = r#"{
            "$type": "community.lexicon.calendar.event#uri",
            "uri": "https://example.com/location",
            "name": "Example"
        }"#;
        let location: EventLocation = serde_json::from_str(json_str).unwrap();
        assert!(matches!(location, EventLocation::InlineUri(_)));
    }

    #[test]
    fn test_typed_named_uri() -> Result<()> {
        let test_json = r#"{"$type":"community.lexicon.calendar.event#uri","uri":"https://smokesignal.events/","name":"Smoke Signal"}"#;

        // Serialize bare NamedUri
        let named_uri = NamedUri {
            uri: "https://smokesignal.events/".to_string(),
            name: Some("Smoke Signal".to_string()),
        };
        let typed_uri = TypedLexicon::new(named_uri);
        let serialized = serde_json::to_value(&typed_uri)?;
        let expected: serde_json::Value = serde_json::from_str(test_json)?;
        assert_eq!(serialized, expected);

        // Deserialize bare NamedUri
        let deserialized: TypedNamedUri = serde_json::from_str(test_json).unwrap();
        assert_eq!(deserialized.inner.uri, "https://smokesignal.events/");
        assert_eq!(deserialized.inner.name, Some("Smoke Signal".to_string()));

        Ok(())
    }

    #[test]
    fn test_typed_event() -> Result<()> {
        use chrono::TimeZone;

        // Create an Event without explicit $type field
        let event = Event {
            name: "Test Event".to_string(),
            description: "A test event".to_string(),
            created_at: Utc.with_ymd_and_hms(2025, 1, 1, 12, 0, 0).unwrap(),
            starts_at: Some(Utc.with_ymd_and_hms(2025, 1, 15, 14, 0, 0).unwrap()),
            ends_at: Some(Utc.with_ymd_and_hms(2025, 1, 15, 16, 0, 0).unwrap()),
            mode: Some(Mode::Hybrid),
            status: Some(Status::Scheduled),
            locations: vec![],
            uris: vec![],
            media: vec![],
            facets: None,
            extra: HashMap::new(),
        };

        // Wrap it in TypedEvent
        let typed_event = TypedLexicon::new(event.clone());

        // Serialize and verify $type is added
        let json = serde_json::to_value(&typed_event)?;
        assert_eq!(json["$type"], "community.lexicon.calendar.event");
        assert_eq!(json["name"], "Test Event");
        assert_eq!(json["description"], "A test event");

        // Deserialize with $type field
        let json_str = r#"{
            "$type": "community.lexicon.calendar.event",
            "name": "Deserialized Event",
            "description": "Event from JSON",
            "createdAt": "2025-01-01T12:00:00Z",
            "startsAt": "2025-01-15T14:00:00Z",
            "endsAt": "2025-01-15T16:00:00Z",
            "mode": "community.lexicon.calendar.event#hybrid",
            "status": "community.lexicon.calendar.event#scheduled"
        }"#;

        let deserialized: TypedEvent = serde_json::from_str(json_str)?;
        assert_eq!(deserialized.inner.name, "Deserialized Event");
        assert_eq!(deserialized.inner.description, "Event from JSON");
        assert!(deserialized.has_type_field());

        Ok(())
    }

    #[test]
    fn test_typed_event_link() -> Result<()> {
        // Create an EventLink without explicit $type field
        let event_link = EventLink {
            uri: "https://example.com/event".to_string(),
            name: Some("Example Event".to_string()),
        };

        // Wrap it in TypedEventLink
        let typed_link = TypedLexicon::new(event_link);

        // Serialize and verify $type is added
        let json = serde_json::to_value(&typed_link)?;
        assert_eq!(json["$type"], "community.lexicon.calendar.event#uri");
        assert_eq!(json["uri"], "https://example.com/event");
        assert_eq!(json["name"], "Example Event");

        // Deserialize with $type field
        let json_str = r#"{
            "$type": "community.lexicon.calendar.event#uri",
            "uri": "https://test.com",
            "name": "Test Link"
        }"#;

        let deserialized: TypedEventLink = serde_json::from_str(json_str)?;
        assert_eq!(deserialized.inner.uri, "https://test.com");
        assert_eq!(deserialized.inner.name, Some("Test Link".to_string()));
        assert!(deserialized.has_type_field());

        Ok(())
    }

    #[test]
    fn test_typed_media() -> Result<()> {
        // Create a Media without explicit $type field
        let media = Media {
            content: TypedLexicon::new(Blob {
                ref_: crate::lexicon::Link {
                    link: "bafkreiblob123".to_string(),
                },
                mime_type: "image/jpeg".to_string(),
                size: 12345,
            }),
            alt: "Test image".to_string(),
            role: "banner".to_string(),
            aspect_ratio: Some(AspectRatio {
                width: 1920,
                height: 1080,
            }),
        };

        // Wrap it in TypedMedia
        let typed_media = TypedLexicon::new(media);

        // Serialize and verify $type is added
        let json = serde_json::to_value(&typed_media)?;
        assert_eq!(json["$type"], "community.lexicon.calendar.event#media");
        assert_eq!(json["alt"], "Test image");
        assert_eq!(json["role"], "banner");
        assert_eq!(json["content"]["$type"], "blob");
        assert_eq!(json["aspect_ratio"]["width"], 1920);
        assert_eq!(json["aspect_ratio"]["height"], 1080);

        // Deserialize with $type field
        let json_str = r#"{
            "$type": "community.lexicon.calendar.event#media",
            "content": {
                "$type": "blob",
                "ref": {
                    "$link": "bafkreitest456"
                },
                "mimeType": "image/png",
                "size": 54321
            },
            "alt": "Another test",
            "role": "thumbnail"
        }"#;

        let deserialized: TypedMedia = serde_json::from_str(json_str)?;
        assert_eq!(deserialized.inner.alt, "Another test");
        assert_eq!(deserialized.inner.role, "thumbnail");
        assert_eq!(deserialized.inner.content.inner.mime_type, "image/png");
        assert!(deserialized.inner.aspect_ratio.is_none());
        assert!(deserialized.has_type_field());

        Ok(())
    }

    #[test]
    fn test_event_with_typed_fields() -> Result<()> {
        use chrono::TimeZone;

        // Create an Event with typed fields
        let event_link = EventLink {
            uri: "https://event.com".to_string(),
            name: Some("Event Website".to_string()),
        };

        let media = Media {
            content: TypedLexicon::new(Blob {
                ref_: crate::lexicon::Link {
                    link: "bafkreimedia".to_string(),
                },
                mime_type: "image/jpeg".to_string(),
                size: 99999,
            }),
            alt: "Event poster".to_string(),
            role: "poster".to_string(),
            aspect_ratio: None,
        };

        let event = Event {
            name: "Complex Event".to_string(),
            description: "Event with typed fields".to_string(),
            created_at: Utc.with_ymd_and_hms(2025, 1, 1, 12, 0, 0).unwrap(),
            starts_at: None,
            ends_at: None,
            mode: None,
            status: None,
            locations: vec![],
            uris: vec![TypedLexicon::new(event_link)],
            media: vec![TypedLexicon::new(media)],
            facets: None,
            extra: HashMap::new(),
        };

        // Wrap it in TypedEvent
        let typed_event = TypedLexicon::new(event);

        // Serialize and verify nested types have their $type fields
        let json = serde_json::to_value(&typed_event)?;
        assert_eq!(json["$type"], "community.lexicon.calendar.event");
        assert_eq!(json["name"], "Complex Event");

        // Check nested EventLink has $type
        assert_eq!(
            json["uris"][0]["$type"],
            "community.lexicon.calendar.event#uri"
        );
        assert_eq!(json["uris"][0]["uri"], "https://event.com");

        // Check nested Media has $type
        assert_eq!(
            json["media"][0]["$type"],
            "community.lexicon.calendar.event#media"
        );
        assert_eq!(json["media"][0]["alt"], "Event poster");

        Ok(())
    }

    #[test]
    fn test_event_with_address_location() -> Result<()> {
        let json_str = r#"{
            "$type": "community.lexicon.calendar.event",
            "name": "Office Meetup",
            "description": "Team gathering",
            "createdAt": "2025-06-01T10:00:00Z",
            "locations": [
                {
                    "$type": "community.lexicon.location.address",
                    "country": "USA",
                    "region": "California",
                    "locality": "San Francisco",
                    "street": "123 Main St"
                }
            ]
        }"#;

        let event: TypedEvent = serde_json::from_str(json_str)?;
        assert_eq!(event.inner.locations.len(), 1);
        assert!(matches!(
            &event.inner.locations[0],
            EventLocation::Location(LocationOrRef::InlineAddress(_))
        ));

        Ok(())
    }

    #[test]
    fn test_event_with_geo_location() -> Result<()> {
        let json_str = r#"{
            "$type": "community.lexicon.calendar.event",
            "name": "Park Picnic",
            "description": "Outdoor event",
            "createdAt": "2025-06-01T10:00:00Z",
            "locations": [
                {
                    "$type": "community.lexicon.location.geo",
                    "latitude": "37.7749",
                    "longitude": "-122.4194",
                    "name": "Golden Gate Park"
                }
            ]
        }"#;

        let event: TypedEvent = serde_json::from_str(json_str)?;
        assert_eq!(event.inner.locations.len(), 1);
        assert!(matches!(
            &event.inner.locations[0],
            EventLocation::Location(LocationOrRef::InlineGeo(_))
        ));

        Ok(())
    }

    #[test]
    fn test_event_with_uri_location() -> Result<()> {
        let json_str = r#"{
            "$type": "community.lexicon.calendar.event",
            "name": "Virtual Meetup",
            "description": "Online event",
            "createdAt": "2025-06-01T10:00:00Z",
            "locations": [
                {
                    "$type": "community.lexicon.calendar.event#uri",
                    "uri": "https://meet.example.com/room",
                    "name": "Meeting Room"
                }
            ]
        }"#;

        let event: TypedEvent = serde_json::from_str(json_str)?;
        assert_eq!(event.inner.locations.len(), 1);
        assert!(matches!(
            &event.inner.locations[0],
            EventLocation::InlineUri(_)
        ));

        Ok(())
    }

    #[test]
    fn test_event_with_mixed_locations() -> Result<()> {
        let json_str = r#"{
            "$type": "community.lexicon.calendar.event",
            "name": "Hybrid Conference",
            "description": "In-person and online",
            "createdAt": "2025-06-01T10:00:00Z",
            "mode": "community.lexicon.calendar.event#hybrid",
            "locations": [
                {
                    "$type": "community.lexicon.location.address",
                    "country": "USA",
                    "locality": "Austin"
                },
                {
                    "$type": "community.lexicon.calendar.event#uri",
                    "uri": "https://stream.example.com/live"
                },
                {
                    "$type": "community.lexicon.location.geo",
                    "latitude": "30.2672",
                    "longitude": "-97.7431"
                },
                {
                    "$type": "community.lexicon.location.hthree",
                    "value": "8a2a1072b59ffff"
                },
                {
                    "$type": "community.lexicon.location.fsq",
                    "fsq_place_id": "4a27f3d4f964a520a4891fe3"
                },
                {
                    "$type": "some.future.location.type",
                    "data": "opaque"
                }
            ]
        }"#;

        let event: TypedEvent = serde_json::from_str(json_str)?;
        assert_eq!(event.inner.locations.len(), 6);
        assert!(matches!(
            &event.inner.locations[0],
            EventLocation::Location(LocationOrRef::InlineAddress(_))
        ));
        assert!(matches!(
            &event.inner.locations[1],
            EventLocation::InlineUri(_)
        ));
        assert!(matches!(
            &event.inner.locations[2],
            EventLocation::Location(LocationOrRef::InlineGeo(_))
        ));
        assert!(matches!(
            &event.inner.locations[3],
            EventLocation::Location(LocationOrRef::InlineHthree(_))
        ));
        assert!(matches!(
            &event.inner.locations[4],
            EventLocation::Location(LocationOrRef::InlineFsq(_))
        ));
        assert!(matches!(
            &event.inner.locations[5],
            EventLocation::Location(LocationOrRef::Unknown(_))
        ));

        Ok(())
    }
}
