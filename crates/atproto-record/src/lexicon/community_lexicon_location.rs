//! Location types for AT Protocol.
//!
//! This module provides various location representation types including
//! addresses, geographic coordinates, Foursquare places, and H3 hexagonal
//! hierarchical spatial indices.

use crate::{
    lexicon::com::atproto::repo::TypedStrongRef,
    typed::{LexiconType, TypedLexicon},
};
use serde::{Deserialize, Serialize};

/// Base namespace identifier for location types
pub const NSID: &str = "community.lexicon.location";
/// Namespace identifier for address locations
pub const ADDRESS_NSID: &str = "community.lexicon.location.address";
/// Namespace identifier for geographic coordinate locations
pub const GEO_NSID: &str = "community.lexicon.location.geo";
/// Namespace identifier for Foursquare locations
pub const FSQ_NSID: &str = "community.lexicon.location.fsq";
/// Namespace identifier for H3 locations
pub const HTHREE_NSID: &str = "community.lexicon.location.hthree";

/// Enum that can hold either a location reference or inline location data.
///
/// This type allows locations to be either embedded directly in a record
/// or referenced via a strong reference. Supports multiple location types
/// including addresses, coordinates, and third-party location identifiers.
///
/// # Example
///
/// ```ignore
/// use atproto_record::lexicon::community::lexicon::location::{LocationOrRef, TypedAddress, Address};
///
/// // Inline address
/// let address = Address {
///     country: "USA".to_string(),
///     postal_code: Some("12345".to_string()),
///     region: Some("CA".to_string()),
///     locality: Some("San Francisco".to_string()),
///     street: None,
///     name: None,
/// };
/// let location = LocationOrRef::InlineAddress(TypedAddress::new(address));
/// ```
#[derive(Deserialize, Serialize, Clone, PartialEq)]
#[cfg_attr(debug_assertions, derive(Debug))]
#[serde(untagged)]
pub enum LocationOrRef {
    /// A reference to a location stored elsewhere
    Reference(TypedStrongRef),
    /// An inline address location
    InlineAddress(TypedAddress),
    /// An inline geographic coordinate location
    InlineGeo(TypedGeo),
    /// An inline H3 location
    InlineHthree(TypedHthree),
    /// An inline Foursquare location
    InlineFsq(TypedFsq),
    /// An unknown or unrecognized location type
    Unknown(serde_json::Value),
}

/// A vector of locations that can be either inline or referenced.
///
/// This type alias is commonly used in records that support multiple
/// locations, such as events that might have both physical and virtual locations.
pub type Locations = Vec<LocationOrRef>;

/// Address location structure.
///
/// Represents a physical address with varying levels of detail.
/// Only the country field is required; all other fields are optional.
///
/// # Example
///
/// ```ignore
/// use atproto_record::lexicon::community::lexicon::location::Address;
///
/// let address = Address {
///     country: "United States".to_string(),
///     postal_code: Some("94102".to_string()),
///     region: Some("California".to_string()),
///     locality: Some("San Francisco".to_string()),
///     street: Some("123 Market St".to_string()),
///     name: Some("Tech Hub Building".to_string()),
/// };
/// ```
#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Address {
    /// Country name (required)
    pub country: String,

    /// Postal/ZIP code
    #[serde(
        rename = "postalCode",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub postal_code: Option<String>,

    /// State, province, or region
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub region: Option<String>,

    /// City or locality
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub locality: Option<String>,

    /// Street address
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub street: Option<String>,

    /// Location name (e.g., building or venue name)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
}

impl LexiconType for Address {
    fn lexicon_type() -> &'static str {
        ADDRESS_NSID
    }
}

/// Type alias for Address with automatic $type field handling
pub type TypedAddress = TypedLexicon<Address>;

/// Geographic coordinates location structure.
///
/// Represents a location using latitude and longitude coordinates.
/// Coordinates are stored as strings to preserve precision.
///
/// # Example
///
/// ```ignore
/// use atproto_record::lexicon::community::lexicon::location::Geo;
///
/// let location = Geo {
///     latitude: "37.7749".to_string(),
///     longitude: "-122.4194".to_string(),
///     name: Some("San Francisco".to_string()),
/// };
/// ```
#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Geo {
    /// Latitude coordinate as a string
    pub latitude: String,

    /// Longitude coordinate as a string
    pub longitude: String,

    /// Optional human-readable name for this location
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
}

impl LexiconType for Geo {
    fn lexicon_type() -> &'static str {
        GEO_NSID
    }
}

/// Type alias for Geo with automatic $type field handling
pub type TypedGeo = TypedLexicon<Geo>;

/// Foursquare location structure.
///
/// Represents a location using Foursquare's place identifier system.
/// This allows integration with Foursquare's venue database.
///
/// # Example
///
/// ```ignore
/// use atproto_record::lexicon::community::lexicon::location::Fsq;
///
/// let location = Fsq {
///     fsq_place_id: "4a27f3d4f964a520a4891fe3".to_string(),
///     name: Some("Empire State Building".to_string()),
/// };
/// ```
#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Fsq {
    /// Foursquare place identifier
    pub fsq_place_id: String,

    /// Optional venue name from Foursquare
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
}

impl LexiconType for Fsq {
    fn lexicon_type() -> &'static str {
        FSQ_NSID
    }
}

/// Type alias for Fsq with automatic $type field handling
pub type TypedFsq = TypedLexicon<Fsq>;

/// H3 location structure.
///
/// Represents a location using Uber's H3 hexagonal hierarchical spatial index.
/// H3 provides a way to represent geographic areas as hexagons at various resolutions.
///
/// # Example
///
/// ```ignore
/// use atproto_record::lexicon::community::lexicon::location::Hthree;
///
/// let location = Hthree {
///     value: "8a2a1072b59ffff".to_string(),
///     name: Some("Downtown Area".to_string()),
/// };
/// ```
#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct Hthree {
    /// H3 hexagon identifier
    pub value: String,

    /// Optional human-readable name for this area
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
}

impl LexiconType for Hthree {
    fn lexicon_type() -> &'static str {
        HTHREE_NSID
    }
}

/// Type alias for Hthree with automatic $type field handling
pub type TypedHthree = TypedLexicon<Hthree>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_typed_address() {
        // Create an Address without explicit $type field
        let address = Address {
            country: "USA".to_string(),
            postal_code: Some("12345".to_string()),
            region: Some("California".to_string()),
            locality: Some("San Francisco".to_string()),
            street: Some("123 Main St".to_string()),
            name: Some("Office Building".to_string()),
        };

        // Wrap it in TypedAddress
        let typed_address = TypedLexicon::new(address.clone());

        // Serialize and verify $type is added
        let json = serde_json::to_value(&typed_address).unwrap();
        assert_eq!(json["$type"], "community.lexicon.location.address");
        assert_eq!(json["country"], "USA");
        assert_eq!(json["postalCode"], "12345");
        assert_eq!(json["region"], "California");

        // Deserialize with $type field
        let json_str = r#"{
            "$type": "community.lexicon.location.address",
            "country": "Canada",
            "postalCode": "K1A 0B1",
            "region": "Ontario",
            "locality": "Ottawa"
        }"#;

        let deserialized: TypedAddress = serde_json::from_str(json_str).unwrap();
        assert_eq!(deserialized.inner.country, "Canada");
        assert_eq!(deserialized.inner.postal_code, Some("K1A 0B1".to_string()));
        assert!(deserialized.has_type_field());
    }

    #[test]
    fn test_typed_geo() {
        // Create a Geo without explicit $type field
        let geo = Geo {
            latitude: "37.7749".to_string(),
            longitude: "-122.4194".to_string(),
            name: Some("San Francisco".to_string()),
        };

        // Wrap it in TypedGeo
        let typed_geo = TypedLexicon::new(geo);

        // Serialize and verify $type is added
        let json = serde_json::to_value(&typed_geo).unwrap();
        assert_eq!(json["$type"], "community.lexicon.location.geo");
        assert_eq!(json["latitude"], "37.7749");
        assert_eq!(json["longitude"], "-122.4194");
        assert_eq!(json["name"], "San Francisco");

        // Deserialize with $type field
        let json_str = r#"{
            "$type": "community.lexicon.location.geo",
            "latitude": "40.7128",
            "longitude": "-74.0060",
            "name": "New York"
        }"#;

        let deserialized: TypedGeo = serde_json::from_str(json_str).unwrap();
        assert_eq!(deserialized.inner.latitude, "40.7128");
        assert_eq!(deserialized.inner.longitude, "-74.0060");
        assert_eq!(deserialized.inner.name, Some("New York".to_string()));
        assert!(deserialized.has_type_field());
    }

    #[test]
    fn test_typed_fsq() {
        // Create an Fsq without explicit $type field
        let fsq = Fsq {
            fsq_place_id: "4a27f3d4f964a520a4891fe3".to_string(),
            name: Some("Empire State Building".to_string()),
        };

        // Wrap it in TypedFsq
        let typed_fsq = TypedLexicon::new(fsq);

        // Serialize and verify $type is added
        let json = serde_json::to_value(&typed_fsq).unwrap();
        assert_eq!(json["$type"], "community.lexicon.location.fsq");
        assert_eq!(json["fsq_place_id"], "4a27f3d4f964a520a4891fe3");
        assert_eq!(json["name"], "Empire State Building");

        // Deserialize without name field
        let json_str = r#"{
            "$type": "community.lexicon.location.fsq",
            "fsq_place_id": "5642aef9498e51025cf4a7a5"
        }"#;

        let deserialized: TypedFsq = serde_json::from_str(json_str).unwrap();
        assert_eq!(deserialized.inner.fsq_place_id, "5642aef9498e51025cf4a7a5");
        assert_eq!(deserialized.inner.name, None);
        assert!(deserialized.has_type_field());
    }

    #[test]
    fn test_typed_hthree() {
        // Create an Hthree without explicit $type field
        let hthree = Hthree {
            value: "8a2a1072b59ffff".to_string(),
            name: Some("Downtown Area".to_string()),
        };

        // Wrap it in TypedHthree
        let typed_hthree = TypedLexicon::new(hthree);

        // Serialize and verify $type is added
        let json = serde_json::to_value(&typed_hthree).unwrap();
        assert_eq!(json["$type"], "community.lexicon.location.hthree");
        assert_eq!(json["value"], "8a2a1072b59ffff");
        assert_eq!(json["name"], "Downtown Area");

        // Deserialize without name field
        let json_str = r#"{
            "$type": "community.lexicon.location.hthree",
            "value": "8928308280fffff"
        }"#;

        let deserialized: TypedHthree = serde_json::from_str(json_str).unwrap();
        assert_eq!(deserialized.inner.value, "8928308280fffff");
        assert_eq!(deserialized.inner.name, None);
        assert!(deserialized.has_type_field());
    }

    #[test]
    fn test_location_or_ref_unknown() {
        let json_str = r#"{
            "$type": "some.unknown.type",
            "foo": "bar"
        }"#;
        let location: LocationOrRef = serde_json::from_str(json_str).unwrap();
        assert!(matches!(location, LocationOrRef::Unknown(_)));
    }

    #[test]
    fn test_optional_fields() {
        // Test Address with minimal fields
        let address = Address {
            country: "USA".to_string(),
            postal_code: None,
            region: None,
            locality: None,
            street: None,
            name: None,
        };

        let typed_address = TypedLexicon::new(address);
        let json = serde_json::to_value(&typed_address).unwrap();

        // Optional fields should not be present when None
        assert_eq!(json["$type"], "community.lexicon.location.address");
        assert_eq!(json["country"], "USA");
        assert!(!json.as_object().unwrap().contains_key("postalCode"));
        assert!(!json.as_object().unwrap().contains_key("region"));
        assert!(!json.as_object().unwrap().contains_key("locality"));
        assert!(!json.as_object().unwrap().contains_key("street"));
        assert!(!json.as_object().unwrap().contains_key("name"));

        // Test Geo with minimal fields
        let geo = Geo {
            latitude: "0.0".to_string(),
            longitude: "0.0".to_string(),
            name: None,
        };

        let typed_geo = TypedLexicon::new(geo);
        let json = serde_json::to_value(&typed_geo).unwrap();

        assert_eq!(json["$type"], "community.lexicon.location.geo");
        assert_eq!(json["latitude"], "0.0");
        assert_eq!(json["longitude"], "0.0");
        assert!(!json.as_object().unwrap().contains_key("name"));
    }
}
