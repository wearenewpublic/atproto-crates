//! AT-URI syntax validation
//!
//! An AT-URI has the format: `at://<authority>/<collection>/<rkey>`
//! where authority is a DID or handle, collection is an NSID, and rkey is a record key.

use crate::validation::data_errors::DataValidationError;
use crate::validation::syntax::{validate_at_identifier, validate_nsid, validate_record_key};

/// Validate an AT-URI string
pub fn validate_at_uri(value: &str) -> Result<(), DataValidationError> {
    if value.is_empty() {
        return Err(DataValidationError::StringFormatInvalid {
            format: "at-uri".to_string(),
            value: value.to_string(),
            reason: "AT-URI cannot be empty".to_string(),
        });
    }

    // Must start with "at://"
    let rest =
        value
            .strip_prefix("at://")
            .ok_or_else(|| DataValidationError::StringFormatInvalid {
                format: "at-uri".to_string(),
                value: value.to_string(),
                reason: "AT-URI must start with 'at://'".to_string(),
            })?;

    if rest.is_empty() {
        return Err(DataValidationError::StringFormatInvalid {
            format: "at-uri".to_string(),
            value: value.to_string(),
            reason: "AT-URI must have an authority".to_string(),
        });
    }

    // Must not have a fragment
    if value.contains('#') {
        return Err(DataValidationError::StringFormatInvalid {
            format: "at-uri".to_string(),
            value: value.to_string(),
            reason: "AT-URI must not contain a fragment".to_string(),
        });
    }

    // Must not have query parameters
    if value.contains('?') {
        return Err(DataValidationError::StringFormatInvalid {
            format: "at-uri".to_string(),
            value: value.to_string(),
            reason: "AT-URI must not contain query parameters".to_string(),
        });
    }

    // A space is never part of an AT-URI. Checked before the structural rules
    // so trailing whitespace is reported as such rather than as an invalid
    // record key.
    if value.contains(' ') {
        return Err(DataValidationError::StringFormatInvalid {
            format: "at-uri".to_string(),
            value: value.to_string(),
            reason: "AT-URI must not contain spaces".to_string(),
        });
    }

    // An empty path segment is a distinct string denoting the same thing, and
    // that is the problem: `at://alice//c` and `at://alice/c` would both be
    // accepted and would not compare equal. Anything that dedupes or indexes
    // by AT-URI then sees two records where there is one.
    if rest.contains("//") {
        return Err(DataValidationError::StringFormatInvalid {
            format: "at-uri".to_string(),
            value: value.to_string(),
            reason: "AT-URI must not have empty path segments".to_string(),
        });
    }

    // Same reasoning for a trailing slash: `at://alice/c/` and `at://alice/c`
    // denote one record.
    if rest.ends_with('/') {
        return Err(DataValidationError::StringFormatInvalid {
            format: "at-uri".to_string(),
            value: value.to_string(),
            reason: "AT-URI must not have a trailing slash".to_string(),
        });
    }

    // Split into path segments. Four parts means a third path segment, which
    // the grammar does not define — splitting into three would silently fold
    // it into the record key.
    let segments: Vec<&str> = rest.split('/').collect();
    if segments.len() > 3 {
        return Err(DataValidationError::StringFormatInvalid {
            format: "at-uri".to_string(),
            value: value.to_string(),
            reason: "AT-URI must not have more than two path segments".to_string(),
        });
    }

    // Validate authority (first segment)
    let authority = segments[0];
    validate_at_identifier(authority).map_err(|_| DataValidationError::StringFormatInvalid {
        format: "at-uri".to_string(),
        value: value.to_string(),
        reason: format!("invalid authority: {}", authority),
    })?;

    // Every remaining segment is non-empty by the checks above, so each is
    // validated rather than skipped. The previous `!is_empty()` guards meant an
    // empty collection segment silently skipped the record key too.
    if let Some(collection) = segments.get(1) {
        validate_nsid(collection).map_err(|_| DataValidationError::StringFormatInvalid {
            format: "at-uri".to_string(),
            value: value.to_string(),
            reason: format!("invalid collection NSID: {}", collection),
        })?;

        if let Some(rkey) = segments.get(2) {
            validate_record_key(rkey).map_err(|_| DataValidationError::StringFormatInvalid {
                format: "at-uri".to_string(),
                value: value.to_string(),
                reason: format!("invalid record key: {}", rkey),
            })?;
        }
    }

    // Enforce max length of 8 KiB
    if value.len() > 8192 {
        return Err(DataValidationError::StringFormatInvalid {
            format: "at-uri".to_string(),
            value: value.to_string(),
            reason: "AT-URI exceeds maximum length of 8192 bytes".to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_at_uris() {
        let valid = [
            "at://did:plc:asdf123",
            "at://did:plc:asdf123/app.bsky.feed.post",
            "at://did:plc:asdf123/app.bsky.feed.post/3jui7kd54zh2y",
            "at://user.bsky.social",
            "at://user.bsky.social/app.bsky.feed.post",
        ];
        for uri in valid {
            assert!(validate_at_uri(uri).is_ok(), "should be valid: {}", uri);
        }
    }

    #[test]
    fn test_invalid_at_uris() {
        let invalid = [
            "",
            "http://example.com",
            "at://",
            "at://did:plc:asdf123#fragment",
            "at://did:plc:asdf123?query=1",
            "at://invalid",
        ];
        for uri in invalid {
            assert!(validate_at_uri(uri).is_err(), "should be invalid: {}", uri);
        }
    }

    /// A trailing slash and an empty path segment are refused.
    ///
    /// Both were accepted, and both make two distinct strings denote the same
    /// record — so any consumer comparing, deduping or indexing by AT-URI sees
    /// two where there is one. The empty-segment case was the worse of the
    /// two: the old code skipped an empty collection segment *and* the record
    /// key behind it, so `at://alice//com.example.thing` validated without the
    /// collection ever being looked at.
    #[test]
    fn empty_path_segments_and_trailing_slashes_are_refused() {
        for uri in [
            "at://did:plc:asdf123/",
            "at://did:plc:asdf123/com.atproto.feed.post/",
            "at://user.bsky.social/",
            "at://user.bsky.social//",
            "at://user.bsky.social//com.atproto.feed.post",
        ] {
            assert!(validate_at_uri(uri).is_err(), "should be invalid: {uri}");
        }
    }

    /// The grammar defines two path segments; a third is not folded into the
    /// record key.
    #[test]
    fn a_third_path_segment_is_refused() {
        assert!(validate_at_uri("at://did:plc:asdf123/com.atproto.feed.post/rec/extra").is_err());
    }

    /// A space is reported as a space, not as an invalid record key.
    #[test]
    fn a_space_is_named_as_such() {
        let err = validate_at_uri("at://did:plc:asdf123/com.atproto.feed.post/rec ").unwrap_err();
        let DataValidationError::StringFormatInvalid { reason, .. } = &err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(
            reason.contains("space"),
            "the refusal should name the space, got {reason:?}"
        );
    }

    /// The fix must not narrow what is accepted: every shape the grammar
    /// allows still validates.
    #[test]
    fn the_accepted_shapes_are_unchanged() {
        for uri in [
            "at://did:plc:asdf123",
            "at://user.bsky.social",
            "at://did:plc:asdf123/com.atproto.feed.post",
            "at://did:plc:asdf123/com.atproto.feed.post/record",
            "at://did:abc:123/io.nsid.someFunc/record-key",
            "at://did:abc:123/io.nsid.someFunc/self.",
            "at://did:abc:123/io.nsid.someFunc/...",
        ] {
            assert!(validate_at_uri(uri).is_ok(), "should be valid: {uri}");
        }
    }
}
