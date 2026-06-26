//! Core types for permissioned-data spaces.
//!
//! `SpaceUri`, `SpaceType`, `SpaceKey`, `RecordUri` are wrapper newtypes around
//! strings that validate at construction time. They are abstracted so the URI
//! scheme (`ats://` per the 0016 Permissioned Data draft) can change without
//! callers needing to update.

use crate::errors::{SpaceError, SpaceResult};
use serde::{Deserialize, Serialize};
use std::fmt;

/// URI scheme for permissioned data spaces (per the 0016 Permissioned Data draft).
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

/// Maximum `skey` length in UTF-8 bytes (per `com.atproto.simplespace.createSpace`).
pub const SPACE_KEY_MAX_BYTES: usize = 512;

/// A space key — an arbitrary identifier scoped under (authority, type).
///
/// Per the 0016 Permissioned Data draft (line 134), an `skey` has a maximum
/// length of 512 bytes and the same syntax requirements as an `rkey`: the
/// characters are restricted to `[A-Za-z0-9._:~-]`, and the reserved values
/// `.` and `..` are disallowed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SpaceKey(String);

impl SpaceKey {
    /// Construct a new `SpaceKey`. Validates that the value is non-empty, within
    /// the 512-byte length cap, restricted to the record-key character set
    /// `[A-Za-z0-9._:~-]`, and is not a reserved value (`.` or `..`).
    ///
    /// # Errors
    ///
    /// Returns [`SpaceError::InvalidSpaceKey`] if validation fails.
    pub fn new(value: impl Into<String>) -> SpaceResult<Self> {
        let value = value.into();
        if value.len() > SPACE_KEY_MAX_BYTES || !is_valid_record_key(&value) {
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

/// A space URI: `ats://<authority-did>/<space-type>/<space-key>`.
///
/// The components are validated at construction. The full URI is round-trip
/// stable through `Display` and `parse`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct SpaceUri {
    /// Space authority DID.
    pub space_did: String,
    /// Space type (NSID).
    pub space_type: SpaceType,
    /// Space key.
    pub space_key: SpaceKey,
}

impl SpaceUri {
    /// Construct a new `SpaceUri` from validated components.
    pub fn new(space_did: String, space_type: SpaceType, space_key: SpaceKey) -> Self {
        Self {
            space_did,
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

        // Split into 3 parts: space_did, space_type, space_key.
        // space_did itself may contain `:` but no `/`, so we split on `/`.
        let mut parts = stripped.splitn(3, '/');
        let space_did = parts
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

        if !space_did.starts_with("did:") {
            return Err(SpaceError::InvalidSpaceUri { uri: s.to_string() });
        }

        Ok(Self {
            space_did,
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
            ATS_SCHEME, self.space_did, self.space_type, self.space_key
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

/// A permissioned **record** URI of six components:
/// `ats://<spaceDid>/<spaceType>/<skey>/<authorDid>/<collection>/<rkey>`.
///
/// The first three components are the [`SpaceUri`]; the remaining three
/// identify a record authored by `author_did` within that space. All six
/// segments are required to identify a permissioned record (the space does not
/// colocate records — each author's records live in their own permissioned
/// repo, so the author DID is part of the address).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecordUri {
    /// The space the record belongs to (first three URI segments).
    pub space: SpaceUri,
    /// DID of the record's author.
    pub author_did: String,
    /// Record collection (NSID).
    pub collection: String,
    /// Record key.
    pub rkey: String,
}

impl RecordUri {
    /// Construct a record URI from its parts.
    #[must_use]
    pub fn new(space: SpaceUri, author_did: String, collection: String, rkey: String) -> Self {
        Self {
            space,
            author_did,
            collection,
            rkey,
        }
    }

    /// Parse from the canonical six-segment wire form.
    ///
    /// # Errors
    ///
    /// Returns [`SpaceError::InvalidSpaceUri`] if the URI does not have exactly
    /// six non-empty segments or a component fails validation.
    pub fn parse(s: &str) -> SpaceResult<Self> {
        let stripped = s
            .strip_prefix(ATS_SCHEME)
            .ok_or_else(|| SpaceError::InvalidSpaceUri { uri: s.to_string() })?;
        // A record URI has EXACTLY six segments; a 7th `/` (or any extra
        // segment) is rejected rather than absorbed into the rkey.
        let parts: Vec<&str> = stripped.split('/').collect();
        if parts.len() != 6 || parts.iter().any(|p| p.is_empty()) {
            return Err(SpaceError::InvalidSpaceUri { uri: s.to_string() });
        }
        let space = SpaceUri::new(
            {
                if !parts[0].starts_with("did:") {
                    return Err(SpaceError::InvalidSpaceUri { uri: s.to_string() });
                }
                parts[0].to_string()
            },
            SpaceType::new(parts[1])?,
            SpaceKey::new(parts[2])?,
        );
        if !parts[3].starts_with("did:") {
            return Err(SpaceError::InvalidSpaceUri { uri: s.to_string() });
        }
        // The collection segment is typed as an NSID by the spec (Addressing,
        // line 73).
        if !is_valid_nsid(parts[4]) {
            return Err(SpaceError::InvalidSpaceUri { uri: s.to_string() });
        }
        Ok(Self {
            space,
            author_did: parts[3].to_string(),
            collection: parts[4].to_string(),
            rkey: parts[5].to_string(),
        })
    }
}

impl fmt::Display for RecordUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}/{}",
            self.space, self.author_did, self.collection, self.rkey
        )
    }
}

/// Record-key syntax validation per AT Protocol (the `rkey` baseline the 0016
/// draft references for `skey`, line 134): 1-512 characters drawn from
/// `[A-Za-z0-9._:~-]`, and not the reserved values `.` or `..`.
fn is_valid_record_key(s: &str) -> bool {
    if s.is_empty() || s.len() > SPACE_KEY_MAX_BYTES {
        return false;
    }
    if s == "." || s == ".." {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '~' | ':'))
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
    fn space_key_valid_rkey_charset() {
        // Full record-key charset is accepted.
        assert!(SpaceKey::new("key-with-hyphens").is_ok());
        assert!(SpaceKey::new("key_with_underscores").is_ok());
        assert!(SpaceKey::new("key~with~tildes").is_ok());
        assert!(SpaceKey::new("key:with:colons").is_ok());
        assert!(SpaceKey::new("example.com").is_ok());
        assert!(SpaceKey::new("self").is_ok());
    }

    #[test]
    fn space_key_invalid() {
        assert!(SpaceKey::new("").is_err());
        assert!(SpaceKey::new("with/slash").is_err());
        // Reserved record-key values.
        assert!(SpaceKey::new(".").is_err());
        assert!(SpaceKey::new("..").is_err());
        // Out-of-charset values rejected (rkey syntax, spec line 134).
        assert!(SpaceKey::new("has space").is_err());
        assert!(SpaceKey::new("a@b").is_err());
        assert!(SpaceKey::new("emoji\u{1f600}").is_err());
    }

    #[test]
    fn space_key_length_cap() {
        assert!(SpaceKey::new("a".repeat(SPACE_KEY_MAX_BYTES)).is_ok());
        assert!(SpaceKey::new("a".repeat(SPACE_KEY_MAX_BYTES + 1)).is_err());
    }

    #[test]
    fn record_uri_round_trip() {
        let s = "ats://did:plc:auth/app.bsky.group/default/did:plc:alice/app.bsky.feed.post/3jui";
        let parsed = RecordUri::parse(s).unwrap();
        assert_eq!(parsed.author_did, "did:plc:alice");
        assert_eq!(parsed.collection, "app.bsky.feed.post");
        assert_eq!(parsed.rkey, "3jui");
        assert_eq!(parsed.space.space_did, "did:plc:auth");
        assert_eq!(parsed.to_string(), s);
    }

    #[test]
    fn record_uri_parse_failures() {
        // 3-segment (space only) is not a record URI.
        assert!(RecordUri::parse("ats://did:plc:auth/app.bsky.group/default").is_err());
        // author segment must be a DID.
        assert!(
            RecordUri::parse(
                "ats://did:plc:auth/app.bsky.group/default/alice/app.bsky.feed.post/k"
            )
            .is_err()
        );
        // wrong scheme.
        assert!(RecordUri::parse("https://x/y/z/a/b/c").is_err());
        // collection segment must be a valid NSID (spec line 73).
        assert!(
            RecordUri::parse(
                "ats://did:plc:auth/app.bsky.group/default/did:plc:alice/notanNSID/rk"
            )
            .is_err()
        );
        // a 7th segment is rejected rather than absorbed into the rkey.
        assert!(
            RecordUri::parse(
                "ats://did:plc:auth/app.bsky.group/default/did:plc:alice/app.bsky.feed.post/rk/extra"
            )
            .is_err()
        );
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
