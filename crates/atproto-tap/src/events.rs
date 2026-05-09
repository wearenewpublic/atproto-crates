//! TAP event types for AT Protocol record and identity events.
//!
//! This module defines the event structures received from a TAP service.
//! Events are optimized for memory efficiency using:
//! - `CompactString` for small strings (SSO for ≤24 bytes)
//! - `Box<str>` for immutable strings (no capacity overhead)
//! - `serde_json::Value` for record payloads (allows lazy access)

use compact_str::CompactString;
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt;

/// A TAP event received from the stream.
///
/// TAP delivers two types of events:
/// - `Record`: Repository record changes (create, update, delete)
/// - `Identity`: Identity/handle changes for accounts
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TapEvent {
    /// A repository record event (create, update, or delete).
    Record {
        /// Sequential event identifier.
        id: u64,
        /// The record event data.
        record: RecordEvent,
    },
    /// An identity change event.
    Identity {
        /// Sequential event identifier.
        id: u64,
        /// The identity event data.
        identity: IdentityEvent,
    },
}

impl TapEvent {
    /// Returns the event ID.
    pub fn id(&self) -> u64 {
        match self {
            TapEvent::Record { id, .. } => *id,
            TapEvent::Identity { id, .. } => *id,
        }
    }
}

/// Extract only the event ID from a JSON string without fully parsing it.
///
/// This is a fallback parser used when full `TapEvent` parsing fails (e.g., due to
/// deeply nested records hitting serde_json's recursion limit). It uses `IgnoredAny`
/// to efficiently skip over nested content without building data structures, allowing
/// us to extract the ID for acknowledgment even when full parsing fails.
///
/// # Example
///
/// ```
/// use atproto_tap::extract_event_id;
///
/// let json = r#"{"type":"record","id":12345,"record":{"deeply":"nested"}}"#;
/// assert_eq!(extract_event_id(json), Some(12345));
/// ```
pub fn extract_event_id(json: &str) -> Option<u64> {
    let mut deserializer = serde_json::Deserializer::from_str(json);
    deserializer.disable_recursion_limit();
    EventIdOnly::deserialize(&mut deserializer)
        .ok()
        .map(|e| e.id)
}

/// Internal struct for extracting only the "id" field from a TAP event.
#[derive(Debug)]
struct EventIdOnly {
    id: u64,
}

impl<'de> Deserialize<'de> for EventIdOnly {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(EventIdOnlyVisitor)
    }
}

struct EventIdOnlyVisitor;

impl<'de> Visitor<'de> for EventIdOnlyVisitor {
    type Value = EventIdOnly;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a map with an 'id' field")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut id: Option<u64> = None;

        while let Some(key) = map.next_key::<&str>()? {
            if key == "id" {
                id = Some(map.next_value()?);
                // Found what we need - skip the rest efficiently using IgnoredAny
                // which handles deeply nested structures without recursion issues
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                break;
            } else {
                // Skip this value without fully parsing it
                map.next_value::<IgnoredAny>()?;
            }
        }

        id.map(|id| EventIdOnly { id })
            .ok_or_else(|| de::Error::missing_field("id"))
    }
}

/// A repository record event from TAP.
///
/// Contains information about a record change in a user's repository,
/// including the action taken and the record data (for creates/updates).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordEvent {
    /// True if from live firehose, false if from backfill/resync.
    ///
    /// During initial sync or recovery, TAP delivers historical events
    /// with `live: false`. Once caught up, live events have `live: true`.
    pub live: bool,

    /// Repository revision identifier.
    ///
    /// Typically 13 characters, stored inline via CompactString SSO.
    pub rev: CompactString,

    /// Actor DID (e.g., "did:plc:xyz123").
    pub did: Box<str>,

    /// Collection NSID (e.g., "app.bsky.feed.post").
    pub collection: Box<str>,

    /// Record key within the collection.
    ///
    /// Typically a TID (13 characters), stored inline via CompactString SSO.
    pub rkey: CompactString,

    /// The action performed on the record.
    pub action: RecordAction,

    /// Content identifier (CID) of the record.
    ///
    /// Present for create and update actions, absent for delete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cid: Option<CompactString>,

    /// Record data as JSON value.
    ///
    /// Present for create and update actions, absent for delete.
    /// Use [`parse_record`](Self::parse_record) to deserialize on demand.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record: Option<serde_json::Value>,
}

impl RecordEvent {
    /// Parse the record payload into a typed structure.
    ///
    /// This method deserializes the raw JSON on demand, avoiding
    /// unnecessary allocations when the record data isn't needed.
    ///
    /// # Errors
    ///
    /// Returns an error if the record is absent (delete events) or
    /// if deserialization fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize)]
    /// struct Post {
    ///     text: String,
    ///     #[serde(rename = "createdAt")]
    ///     created_at: String,
    /// }
    ///
    /// let post: Post = record_event.parse_record()?;
    /// println!("Post text: {}", post.text);
    /// ```
    pub fn parse_record<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        match &self.record {
            Some(value) => serde_json::from_value(value.clone()),
            None => Err(serde::de::Error::custom("no record data (delete event)")),
        }
    }

    /// Returns the record as a JSON Value reference, if present.
    pub fn record_value(&self) -> Option<&serde_json::Value> {
        self.record.as_ref()
    }

    /// Returns true if this is a delete event.
    pub fn is_delete(&self) -> bool {
        self.action == RecordAction::Delete
    }

    /// Returns the AT-URI for this record.
    ///
    /// Format: `at://{did}/{collection}/{rkey}`
    pub fn at_uri(&self) -> String {
        format!("at://{}/{}/{}", self.did, self.collection, self.rkey)
    }
}

/// The action performed on a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordAction {
    /// A new record was created.
    Create,
    /// An existing record was updated.
    Update,
    /// A record was deleted.
    Delete,
}

impl std::fmt::Display for RecordAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordAction::Create => write!(f, "create"),
            RecordAction::Update => write!(f, "update"),
            RecordAction::Delete => write!(f, "delete"),
        }
    }
}

/// An identity change event from TAP.
///
/// Contains information about handle or account status changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityEvent {
    /// Actor DID.
    pub did: Box<str>,

    /// Current handle for the account.
    pub handle: Box<str>,

    /// Whether the account is currently active.
    #[serde(default)]
    pub is_active: bool,

    /// Account status.
    #[serde(default)]
    pub status: IdentityStatus,
}

/// Account status in an identity event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityStatus {
    /// Account is active and in good standing.
    #[default]
    Active,
    /// Account has been deactivated by the user.
    Deactivated,
    /// Account has been suspended.
    Suspended,
    /// Account has been deleted.
    Deleted,
    /// Account has been taken down.
    Takendown,
}

impl std::fmt::Display for IdentityStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityStatus::Active => write!(f, "active"),
            IdentityStatus::Deactivated => write!(f, "deactivated"),
            IdentityStatus::Suspended => write!(f, "suspended"),
            IdentityStatus::Deleted => write!(f, "deleted"),
            IdentityStatus::Takendown => write!(f, "takendown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_record_event() {
        let json = r#"{
            "id": 12345,
            "type": "record",
            "record": {
                "live": true,
                "rev": "3lyileto4q52k",
                "did": "did:plc:z72i7hdynmk6r22z27h6tvur",
                "collection": "app.bsky.feed.post",
                "rkey": "3lyiletddxt2c",
                "action": "create",
                "cid": "bafyreigroo6vhxt62ufcndhaxzas6btq4jmniuz4egszbwuqgiyisqwqoy",
                "record": {"$type": "app.bsky.feed.post", "text": "Hello world!", "createdAt": "2025-01-01T00:00:00Z"}
            }
        }"#;

        let event: TapEvent = serde_json::from_str(json).expect("Failed to parse");

        match event {
            TapEvent::Record { id, record } => {
                assert_eq!(id, 12345);
                assert!(record.live);
                assert_eq!(record.rev.as_str(), "3lyileto4q52k");
                assert_eq!(&*record.did, "did:plc:z72i7hdynmk6r22z27h6tvur");
                assert_eq!(&*record.collection, "app.bsky.feed.post");
                assert_eq!(record.rkey.as_str(), "3lyiletddxt2c");
                assert_eq!(record.action, RecordAction::Create);
                assert!(record.cid.is_some());
                assert!(record.record.is_some());

                // Test lazy parsing
                #[derive(Deserialize)]
                struct Post {
                    text: String,
                }
                let post: Post = record.parse_record().expect("Failed to parse record");
                assert_eq!(post.text, "Hello world!");
            }
            _ => panic!("Expected Record event"),
        }
    }

    #[test]
    fn test_parse_delete_event() {
        let json = r#"{
            "id": 12346,
            "type": "record",
            "record": {
                "live": true,
                "rev": "3lyileto4q52k",
                "did": "did:plc:z72i7hdynmk6r22z27h6tvur",
                "collection": "app.bsky.feed.post",
                "rkey": "3lyiletddxt2c",
                "action": "delete"
            }
        }"#;

        let event: TapEvent = serde_json::from_str(json).expect("Failed to parse");

        match event {
            TapEvent::Record { id, record } => {
                assert_eq!(id, 12346);
                assert_eq!(record.action, RecordAction::Delete);
                assert!(record.is_delete());
                assert!(record.cid.is_none());
                assert!(record.record.is_none());
            }
            _ => panic!("Expected Record event"),
        }
    }

    #[test]
    fn test_parse_identity_event() {
        let json = r#"{
            "id": 12347,
            "type": "identity",
            "identity": {
                "did": "did:plc:z72i7hdynmk6r22z27h6tvur",
                "handle": "user.bsky.social",
                "is_active": true,
                "status": "active"
            }
        }"#;

        let event: TapEvent = serde_json::from_str(json).expect("Failed to parse");

        match event {
            TapEvent::Identity { id, identity } => {
                assert_eq!(id, 12347);
                assert_eq!(&*identity.did, "did:plc:z72i7hdynmk6r22z27h6tvur");
                assert_eq!(&*identity.handle, "user.bsky.social");
                assert!(identity.is_active);
                assert_eq!(identity.status, IdentityStatus::Active);
            }
            _ => panic!("Expected Identity event"),
        }
    }

    #[test]
    fn test_record_action_display() {
        assert_eq!(RecordAction::Create.to_string(), "create");
        assert_eq!(RecordAction::Update.to_string(), "update");
        assert_eq!(RecordAction::Delete.to_string(), "delete");
    }

    #[test]
    fn test_identity_status_display() {
        assert_eq!(IdentityStatus::Active.to_string(), "active");
        assert_eq!(IdentityStatus::Deactivated.to_string(), "deactivated");
        assert_eq!(IdentityStatus::Suspended.to_string(), "suspended");
        assert_eq!(IdentityStatus::Deleted.to_string(), "deleted");
        assert_eq!(IdentityStatus::Takendown.to_string(), "takendown");
    }

    #[test]
    fn test_at_uri() {
        let record = RecordEvent {
            live: true,
            rev: "3lyileto4q52k".into(),
            did: "did:plc:xyz".into(),
            collection: "app.bsky.feed.post".into(),
            rkey: "abc123".into(),
            action: RecordAction::Create,
            cid: None,
            record: None,
        };

        assert_eq!(
            record.at_uri(),
            "at://did:plc:xyz/app.bsky.feed.post/abc123"
        );
    }

    #[test]
    fn test_event_id() {
        let record_event = TapEvent::Record {
            id: 100,
            record: RecordEvent {
                live: true,
                rev: "rev".into(),
                did: "did".into(),
                collection: "col".into(),
                rkey: "rkey".into(),
                action: RecordAction::Create,
                cid: None,
                record: None,
            },
        };
        assert_eq!(record_event.id(), 100);

        let identity_event = TapEvent::Identity {
            id: 200,
            identity: IdentityEvent {
                did: "did".into(),
                handle: "handle".into(),
                is_active: true,
                status: IdentityStatus::Active,
            },
        };
        assert_eq!(identity_event.id(), 200);
    }

    #[test]
    fn test_extract_event_id_simple() {
        let json = r#"{"type":"record","id":12345,"record":{"deeply":"nested"}}"#;
        assert_eq!(extract_event_id(json), Some(12345));
    }

    #[test]
    fn test_extract_event_id_at_end() {
        let json = r#"{"type":"record","record":{"deeply":"nested"},"id":99999}"#;
        assert_eq!(extract_event_id(json), Some(99999));
    }

    #[test]
    fn test_extract_event_id_missing() {
        let json = r#"{"type":"record","record":{"deeply":"nested"}}"#;
        assert_eq!(extract_event_id(json), None);
    }

    #[test]
    fn test_extract_event_id_invalid_json() {
        let json = r#"{"type":"record","id":123"#; // Truncated JSON
        assert_eq!(extract_event_id(json), None);
    }

    #[test]
    fn test_extract_event_id_deeply_nested() {
        // Create a deeply nested JSON that would exceed serde_json's default recursion limit
        let mut json = String::from(r#"{"id":42,"record":{"nested":"#);
        for _ in 0..200 {
            json.push('[');
        }
        json.push('1');
        for _ in 0..200 {
            json.push(']');
        }
        json.push_str("}}");

        // extract_event_id should still work because it uses IgnoredAny with disabled recursion limit
        assert_eq!(extract_event_id(&json), Some(42));
    }
}
