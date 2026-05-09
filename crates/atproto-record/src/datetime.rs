//! DateTime serialization utilities for AT Protocol records.
//!
//! This module provides specialized Serde serialization and deserialization functions
//! for `DateTime<Utc>` values, ensuring consistent RFC 3339 formatting with millisecond
//! precision across all AT Protocol record structures.
//!
//! ## Usage
//!
//! These modules are designed to be used with Serde's `#[serde(with = "...")]` attribute:
//!
//! ```ignore
//! use chrono::{DateTime, Utc};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize)]
//! struct Signature {
//!     #[serde(with = "atproto_record::datetime::format")]
//!     issued_at: DateTime<Utc>,
//!
//!     #[serde(with = "atproto_record::datetime::optional_format")]
//!     expires_at: Option<DateTime<Utc>>,
//! }
//! ```
//!
//! ## Modules
//!
//! - [`format`](crate::datetime::format) - Required datetime field serialization with RFC 3339 millisecond precision
//! - [`optional_format`](crate::datetime::optional_format) - Optional datetime field serialization with proper None handling
//! - [`lenient_optional_format`](crate::datetime::lenient_optional_format) - Lenient optional datetime deserialization that tolerates malformed values

/// Required datetime field serialization with RFC 3339 formatting.
///
/// This module provides serde serialization/deserialization for `DateTime<Utc>` values,
/// ensuring consistent RFC 3339 format with millisecond precision (e.g., "2024-01-01T12:00:00.000Z").
/// Use with `#[serde(with = "atproto_record::datetime::format")]` on required datetime fields.
pub mod format {
    use chrono::{DateTime, SecondsFormat, Utc};
    use serde::{self, Deserialize, Deserializer, Serializer};

    /// Serializes a `DateTime<Utc>` to RFC 3339 string with millisecond precision.
    pub fn serialize<S>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = date.to_rfc3339_opts(SecondsFormat::Millis, true);
        serializer.serialize_str(&s)
    }

    /// Deserializes an RFC 3339 formatted string to `DateTime<Utc>`.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let date_value = String::deserialize(deserializer)?;
        DateTime::parse_from_rfc3339(&date_value)
            .map(|v| v.with_timezone(&Utc))
            .map_err(serde::de::Error::custom)
    }
}

/// Optional datetime field serialization with None value support.
///
/// This module provides serde serialization/deserialization for `Option<DateTime<Utc>>` values,
/// handling both Some values (formatted as RFC 3339 with milliseconds) and None values gracefully.
/// Use with `#[serde(with = "atproto_record::datetime::optional_format")]` on optional datetime fields.
pub mod optional_format {
    use chrono::{DateTime, SecondsFormat, Utc};
    use serde::{self, Deserialize, Deserializer, Serializer};

    /// Serializes an `Option<DateTime<Utc>>` to RFC 3339 string or null.
    pub fn serialize<S>(date: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if date.is_none() {
            return serializer.serialize_none();
        }
        let s = date.unwrap().to_rfc3339_opts(SecondsFormat::Millis, true);
        serializer.serialize_str(&s)
    }

    /// Deserializes an optional RFC 3339 string to `Option<DateTime<Utc>>`.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let maybe_date_value: Option<String> = Option::deserialize(deserializer)?;
        if maybe_date_value.is_none() {
            return Ok(None);
        }
        let date_value = maybe_date_value.unwrap();
        DateTime::parse_from_rfc3339(&date_value)
            .map(|v| v.with_timezone(&Utc))
            .map_err(serde::de::Error::custom)
            .map(Some)
    }
}

/// Lenient optional datetime deserialization that tolerates malformed values.
///
/// This module accepts any JSON value for deserialization. Valid RFC 3339 strings produce
/// `Some(DateTime<Utc>)`, while all other values (objects, nulls, numbers, arrays, booleans,
/// or unparseable strings) produce `None` without error. Serialization matches `optional_format`.
///
/// Use with `#[serde(default, with = "atproto_record::datetime::lenient_optional_format")]`
/// on `Option<DateTime<Utc>>` fields where the data source may contain garbage values.
pub mod lenient_optional_format {
    use chrono::{DateTime, SecondsFormat, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serializes an `Option<DateTime<Utc>>` to RFC 3339 string or null.
    pub fn serialize<S>(date: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match date {
            Some(d) => {
                let s = d.to_rfc3339_opts(SecondsFormat::Millis, true);
                serializer.serialize_str(&s)
            }
            None => serializer.serialize_none(),
        }
    }

    /// Deserializes any JSON value to `Option<DateTime<Utc>>`, returning `None` for non-string or unparseable values.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::String(s) => Ok(DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|v| v.with_timezone(&Utc))),
            _ => Ok(None),
        }
    }
}
