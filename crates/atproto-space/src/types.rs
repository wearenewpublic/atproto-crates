//! Core types for permissioned-data spaces.
//!
//! `SpaceUri`, `SpaceType`, `SpaceKey` are wrapper newtypes around strings
//! that validate at construction time. They are abstracted so the URI scheme
//! (`ats://` per the Spaces Design Spec, provisional) can change without
//! callers needing to update.

use crate::errors::{SpaceError, SpaceResult};
use serde::{Deserialize, Serialize};
use std::fmt;

/// URI scheme for permissioned data spaces (provisional per Spaces Design Spec).
pub const ATS_SCHEME: &str = "ats://";

/// A space type — an NSID describing the space modality (e.g., `app.bsky.group`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SpaceType(String);

impl SpaceType {
    /// Construct a new `SpaceType` validating that `value` is a non-empty NSID-shaped string.
    ///
    /// # Errors
    ///
    /// Returns [`SpaceError::InvalidSpaceType`] if validation fails.
    pub fn new(value: impl Into<String>) -> SpaceResult<Self> {
        let value = value.into();
        if !is_valid_nsid(&value) {
            return Err(SpaceError::InvalidSpaceType { value });
        }
        Ok(Self(value))
    }

    /// Get the underlying string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SpaceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A space key — an arbitrary identifier scoped under (owner, type).
///
/// Cannot contain `/` (would corrupt the URI segment structure) and cannot be empty.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SpaceKey(String);

impl SpaceKey {
    /// Construct a new `SpaceKey`. Validates non-empty and slash-free.
    ///
    /// # Errors
    ///
    /// Returns [`SpaceError::InvalidSpaceKey`] if validation fails.
    pub fn new(value: impl Into<String>) -> SpaceResult<Self> {
        let value = value.into();
        if value.is_empty() || value.contains('/') {
            return Err(SpaceError::InvalidSpaceKey { value });
        }
        Ok(Self(value))
    }

    /// Get the underlying string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SpaceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A space URI: `ats://<owner-did>/<space-type>/<space-key>`.
///
/// The components are validated at construction. The full URI is round-trip
/// stable through `Display` and `parse`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct SpaceUri {
    /// DID of the space owner.
    pub owner_did: String,
    /// Space type (NSID).
    pub space_type: SpaceType,
    /// Space key.
    pub space_key: SpaceKey,
}

impl SpaceUri {
    /// Construct a new `SpaceUri` from validated components.
    pub fn new(owner_did: String, space_type: SpaceType, space_key: SpaceKey) -> Self {
        Self {
            owner_did,
            space_type,
            space_key,
        }
    }

    /// Parse from the canonical wire form `ats://<owner-did>/<type>/<key>`.
    ///
    /// # Errors
    ///
    /// Returns [`SpaceError::InvalidSpaceUri`] (or a more specific component
    /// error) on failure.
    pub fn parse(s: &str) -> SpaceResult<Self> {
        let stripped = s
            .strip_prefix(ATS_SCHEME)
            .ok_or_else(|| SpaceError::InvalidSpaceUri { uri: s.to_string() })?;

        // Split into 3 parts: owner_did, space_type, space_key.
        // owner_did itself may contain `:` but no `/`, so we split on `/`.
        let mut parts = stripped.splitn(3, '/');
        let owner_did = parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SpaceError::InvalidSpaceUri { uri: s.to_string() })?
            .to_string();
        let space_type_str = parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SpaceError::InvalidSpaceUri { uri: s.to_string() })?;
        let space_key_str = parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SpaceError::InvalidSpaceUri { uri: s.to_string() })?;

        if !owner_did.starts_with("did:") {
            return Err(SpaceError::InvalidSpaceUri { uri: s.to_string() });
        }

        Ok(Self {
            owner_did,
            space_type: SpaceType::new(space_type_str)?,
            space_key: SpaceKey::new(space_key_str)?,
        })
    }
}

impl fmt::Display for SpaceUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}/{}/{}",
            ATS_SCHEME, self.owner_did, self.space_type, self.space_key
        )
    }
}

impl From<SpaceUri> for String {
    fn from(uri: SpaceUri) -> Self {
        uri.to_string()
    }
}

impl TryFrom<String> for SpaceUri {
    type Error = SpaceError;

    fn try_from(value: String) -> SpaceResult<Self> {
        Self::parse(&value)
    }
}

impl std::str::FromStr for SpaceUri {
    type Err = SpaceError;

    fn from_str(s: &str) -> SpaceResult<Self> {
        Self::parse(s)
    }
}

/// Minimal NSID validation per AT Protocol — at least three dot-separated segments,
/// each non-empty alphanumeric/hyphen-only.
fn is_valid_nsid(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let segments: Vec<&str> = s.split('.').collect();
    if segments.len() < 3 {
        return false;
    }
    segments.iter().all(|seg| {
        !seg.is_empty()
            && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !seg.starts_with('-')
            && !seg.ends_with('-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn space_type_valid() {
        assert!(SpaceType::new("app.bsky.group").is_ok());
        assert!(SpaceType::new("com.atproto.space").is_ok());
    }

    #[test]
    fn space_type_invalid() {
        assert!(SpaceType::new("").is_err());
        assert!(SpaceType::new("two.parts").is_err());
        assert!(SpaceType::new("with space.bsky.group").is_err());
        assert!(SpaceType::new("trailing.dot.").is_err());
    }

    #[test]
    fn space_key_valid() {
        assert!(SpaceKey::new("default").is_ok());
        assert!(SpaceKey::new("3jui7kd2z2y2e").is_ok());
    }

    #[test]
    fn space_key_invalid() {
        assert!(SpaceKey::new("").is_err());
        assert!(SpaceKey::new("with/slash").is_err());
    }

    #[test]
    fn space_uri_roundtrip() {
        let original = "ats://did:plc:example/app.bsky.group/default";
        let parsed = SpaceUri::parse(original).unwrap();
        assert_eq!(parsed.to_string(), original);
    }

    #[test]
    fn space_uri_parse_failures() {
        assert!(SpaceUri::parse("https://example.com").is_err()); // wrong scheme
        assert!(SpaceUri::parse("ats://").is_err()); // empty
        assert!(SpaceUri::parse("ats://did:plc:x").is_err()); // missing type/key
        assert!(SpaceUri::parse("ats://did:plc:x/app.bsky.group").is_err()); // missing key
        assert!(SpaceUri::parse("ats://not-a-did/app.bsky.group/k").is_err()); // not a DID
    }

    #[test]
    fn space_uri_serde_round_trip() {
        let uri = SpaceUri::parse("ats://did:plc:example/app.bsky.group/default").unwrap();
        let json = serde_json::to_string(&uri).unwrap();
        assert_eq!(json, "\"ats://did:plc:example/app.bsky.group/default\"");
        let parsed: SpaceUri = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, uri);
    }
}
