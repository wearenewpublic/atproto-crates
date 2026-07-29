//! Core types for permissioned-data spaces.
//!
//! `SpaceUri`, `SpaceType`, `SpaceKey`, `RecordUri` are wrapper newtypes around
//! strings that validate at construction time. Callers build and print URIs
//! through them rather than formatting strings, so the scheme and the `space`
//! marker live in one place — which is exactly what the change from `ats://`
//! to `at://{did}/space/{type}/{skey}` needed and did not have: two hand-rolled
//! `format!` copies in the writer had to be found by grep.

use crate::errors::{SpaceError, SpaceResult};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Canonical URI scheme for permissioned data spaces.
///
/// Space URIs are ordinary `at://` URIs. The 0016 draft and the reference
/// (`packages/syntax/src/space-uri.ts`) both put a fixed `space` marker segment
/// where a public URI would carry a collection NSID; the two are unambiguous
/// because a collection always contains dots and the marker never does.
pub const AT_SCHEME: &str = "at://";

/// The fixed second path segment of every space URI.
pub const SPACE_MARKER: &str = "space";

/// Legacy scheme, accepted on input and rewritten.
///
/// This crate emitted `ats://{did}/{type}/{skey}` before the marker form was
/// adopted. It is still parsed so a caller holding an old URI gets an answer
/// rather than a syntax error — but nothing emits it, and a commit signed
/// against one can never verify, because the space string is length-prefixed
/// into `ctx`.
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

/// A space URI: `at://<authority-did>/space/<space-type>/<space-key>`.
///
/// The components are validated at construction. The full URI is round-trip
/// stable through `Display` and `parse`. Legacy `ats://<did>/<type>/<key>` is
/// accepted on input and normalized to the canonical form.
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

    /// Parse `at://<did>/space/<type>/<key>`, or the legacy
    /// `ats://<did>/<type>/<key>`.
    ///
    /// # Errors
    ///
    /// Returns [`SpaceError::InvalidSpaceUri`] (or a more specific component
    /// error) on failure.
    pub fn parse(s: &str) -> SpaceResult<Self> {
        let bad = || SpaceError::InvalidSpaceUri { uri: s.to_string() };
        let parts = split_space_path(s, 3).ok_or_else(bad)?;
        if !parts[0].starts_with("did:") {
            return Err(bad());
        }
        Ok(Self {
            space_did: parts[0].to_string(),
            space_type: SpaceType::new(parts[1])?,
            space_key: SpaceKey::new(parts[2])?,
        })
    }
}

/// Strip the scheme and marker, returning `expected` non-empty path segments
/// plus any trailing ones.
///
/// Handles both the canonical `at://<did>/space/<...>` and the legacy
/// `ats://<did>/<...>`, so every caller gets the marker handling once rather
/// than repeating it.
fn split_space_path(s: &str, expected: usize) -> Option<Vec<&str>> {
    let parts: Vec<&str> = if let Some(rest) = s.strip_prefix(AT_SCHEME) {
        let all: Vec<&str> = rest.split('/').collect();
        // `did` + marker + the rest.
        if all.len() < 2 || all[1] != SPACE_MARKER {
            return None;
        }
        let mut v = vec![all[0]];
        v.extend_from_slice(&all[2..]);
        v
    } else if let Some(rest) = s.strip_prefix(ATS_SCHEME) {
        rest.split('/').collect()
    } else {
        return None;
    };
    if parts.len() != expected || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    Some(parts)
}

impl fmt::Display for SpaceUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}/{}/{}/{}",
            AT_SCHEME, self.space_did, SPACE_MARKER, self.space_type, self.space_key
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

/// A permissioned **record** URI:
/// `at://<spaceDid>/space/<spaceType>/<skey>/<authorDid>/<collection>/<rkey>`.
///
/// The first four segments are the [`SpaceUri`]; the remaining three identify a
/// record authored by `author_did` within that space. All of them are required
/// (the space does not colocate records — each author's records live in their
/// own permissioned repo, so the author DID is part of the address).
///
/// The legacy six-segment `ats://` form is accepted on input.
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

    /// Parse the canonical wire form, or the legacy `ats://` six-segment one.
    ///
    /// # Errors
    ///
    /// Returns [`SpaceError::InvalidSpaceUri`] if the URI does not have exactly
    /// the required non-empty segments or a component fails validation.
    pub fn parse(s: &str) -> SpaceResult<Self> {
        let bad = || SpaceError::InvalidSpaceUri { uri: s.to_string() };
        // Exactly six segments after the marker is stripped; a seventh is
        // rejected rather than absorbed into the rkey.
        let parts = split_space_path(s, 6).ok_or_else(bad)?;
        let space = SpaceUri::new(
            {
                if !parts[0].starts_with("did:") {
                    return Err(bad());
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
        let s =
            "at://did:plc:auth/space/app.bsky.group/default/did:plc:alice/app.bsky.feed.post/3jui";
        let parsed = RecordUri::parse(s).unwrap();
        assert_eq!(parsed.author_did, "did:plc:alice");
        assert_eq!(parsed.collection, "app.bsky.feed.post");
        assert_eq!(parsed.rkey, "3jui");
        assert_eq!(parsed.space.space_did, "did:plc:auth");
        assert_eq!(parsed.to_string(), s);
    }

    #[test]
    fn a_legacy_record_uri_parses_and_normalizes() {
        let legacy =
            "ats://did:plc:auth/app.bsky.group/default/did:plc:alice/app.bsky.feed.post/3jui";
        let parsed = RecordUri::parse(legacy).unwrap();
        assert_eq!(
            parsed.to_string(),
            "at://did:plc:auth/space/app.bsky.group/default/did:plc:alice/app.bsky.feed.post/3jui",
            "a legacy URI comes back canonical, never as it went in"
        );
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
        let original = "at://did:plc:example/space/app.bsky.group/default";
        let parsed = SpaceUri::parse(original).unwrap();
        assert_eq!(parsed.to_string(), original);
    }

    #[test]
    fn a_legacy_space_uri_parses_and_normalizes() {
        // Accepted so a caller holding an old URI gets an answer rather than a
        // syntax error — but nothing emits it again.
        let parsed = SpaceUri::parse("ats://did:plc:example/app.bsky.group/default").unwrap();
        assert_eq!(
            parsed.to_string(),
            "at://did:plc:example/space/app.bsky.group/default"
        );
    }

    #[test]
    fn the_space_marker_is_required_on_the_canonical_form() {
        // Without the marker check, `at://did/app.bsky.group/default` would
        // parse as a space URI whose type is a collection — the ambiguity the
        // marker exists to prevent.
        assert!(SpaceUri::parse("at://did:plc:x/app.bsky.group/default").is_err());
        assert!(SpaceUri::parse("at://did:plc:x/notspace/app.bsky.group/default").is_err());
        assert!(SpaceUri::parse("at://did:plc:x/space/app.bsky.group").is_err());
        assert!(SpaceUri::parse("at://did:plc:x/space/app.bsky.group/default/extra").is_err());
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
        let uri = SpaceUri::parse("at://did:plc:example/space/app.bsky.group/default").unwrap();
        let json = serde_json::to_string(&uri).unwrap();
        assert_eq!(
            json,
            "\"at://did:plc:example/space/app.bsky.group/default\""
        );
        let parsed: SpaceUri = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, uri);
    }
}
