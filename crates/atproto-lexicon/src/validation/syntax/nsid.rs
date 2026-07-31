//! NSID (Namespaced Identifier) syntax validation
//!
//! Validates NSID strings according to the AT Protocol specification.
//! An NSID identifies a lexicon schema with a reversed domain authority.

use crate::validation::data_errors::DataValidationError;

/// Maximum overall length: 253 for the domain authority, one dot, 63 for the
/// name.
const MAX_LEN: usize = 253 + 1 + 63;

/// Maximum length of a single dot-separated segment.
const MAX_SEGMENT_LEN: usize = 63;

fn invalid(value: &str, reason: &str) -> DataValidationError {
    DataValidationError::StringFormatInvalid {
        format: "nsid".to_string(),
        value: value.to_string(),
        reason: reason.to_string(),
    }
}

/// Validate an NSID string.
///
/// An NSID is a domain authority in reversed notation followed by a name
/// segment. The two halves have **different** rules, which is the whole
/// subtlety:
///
/// - Every segment is 1–63 characters of `[a-zA-Z0-9-]`, and may not start or
///   end with a hyphen. Beyond that the authority segments follow DNS host
///   rules, under which a label may begin with a digit (RFC 1123 §2.1).
///   `org.4chan.lex.getThing` and `cn.8.lex.stuff` are ordinary NSIDs for
///   ordinary domains, and an onion address is digit-leading by construction.
/// - Only the **first** segment may not begin with a digit — it is the TLD.
/// - Only the **last** segment, the name, is restricted to letters and digits
///   with no leading digit; it is an identifier, not a host label, so a hyphen
///   is not allowed there either.
///
/// Expressed as a single regex requiring every segment to start with a letter,
/// this refuses names that exist on the network. Written out per the
/// reference's own structure (`validateNsid`,
/// `packages/syntax/src/nsid.ts:89-122`), each rule says which half it governs.
///
/// # Errors
///
/// [`DataValidationError::StringFormatInvalid`] naming the rule that failed.
pub fn validate_nsid(value: &str) -> Result<(), DataValidationError> {
    if value.is_empty() {
        return Err(invalid(value, "NSID cannot be empty"));
    }

    if value.len() > MAX_LEN {
        return Err(invalid(
            value,
            "NSID exceeds maximum length of 317 characters",
        ));
    }

    // Checked over the whole string before splitting, so that a disallowed
    // character is reported as such rather than as whichever per-segment rule
    // it happens to trip.
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(invalid(
            value,
            "NSID may contain only ASCII letters, digits, dashes and periods",
        ));
    }

    let segments: Vec<&str> = value.split('.').collect();

    if segments.len() < 3 {
        return Err(invalid(value, "NSID must have at least 3 segments"));
    }

    for segment in &segments {
        if segment.is_empty() {
            return Err(invalid(value, "NSID segments must not be empty"));
        }
        if segment.len() > MAX_SEGMENT_LEN {
            return Err(invalid(
                value,
                "NSID segments must not exceed 63 characters",
            ));
        }
        if segment.starts_with('-') || segment.ends_with('-') {
            return Err(invalid(
                value,
                "NSID segments must not start or end with a hyphen",
            ));
        }
    }

    // The first segment is the TLD, which cannot be numeric. Every other
    // authority segment may begin with a digit.
    if segments[0].starts_with(|c: char| c.is_ascii_digit()) {
        return Err(invalid(
            value,
            "the first NSID segment must not start with a digit",
        ));
    }

    // The name is an identifier rather than a host label: letters and digits
    // only, no leading digit, and no hyphen.
    let name = segments[segments.len() - 1];
    if name.starts_with(|c: char| c.is_ascii_digit()) || name.contains('-') {
        return Err(invalid(
            value,
            "the NSID name segment must be letters and digits with no leading digit",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_nsids() {
        let valid = [
            "app.bsky.feed.post",
            "com.atproto.repo.getRecord",
            "com.example.service.method",
            "a.b.c",
        ];
        for nsid in valid {
            assert!(validate_nsid(nsid).is_ok(), "should be valid: {}", nsid);
        }
    }

    #[test]
    fn test_invalid_nsids() {
        let invalid = [
            "",
            "app.bsky",
            "app",
            "app..feed.post",
            "1app.bsky.feed.post",
            ".bsky.feed.post",
        ];
        for nsid in invalid {
            assert!(validate_nsid(nsid).is_err(), "should be invalid: {}", nsid);
        }
    }

    /// An authority segment other than the first may begin with a digit.
    ///
    /// These are real domains — 4chan.org, and an onion address, which is
    /// digit-leading by construction. Requiring every segment to start with a
    /// letter refused NSIDs that exist on the network.
    #[test]
    fn authority_segments_may_start_with_a_digit() {
        for nsid in [
            "a.0.c",
            "one.2.three",
            "cn.8.lex.stuff",
            "org.4chan.lex.getThing",
            "test.12345.record",
            "onion.2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.lex.deleteThing",
        ] {
            assert!(validate_nsid(nsid).is_ok(), "should be valid: {nsid}");
        }
    }

    /// The exemption is for authority segments only, and stops at both ends.
    ///
    /// Without these, "digit-leading segments are fine" would be an easy and
    /// wrong way to make the cases above pass.
    #[test]
    fn the_digit_exemption_does_not_reach_the_first_or_last_segment() {
        // First segment is the TLD.
        assert!(validate_nsid("0two.example.foo").is_err());
        assert!(validate_nsid("1.0.0.127.record").is_err());
        // Last segment is an identifier, not a host label.
        assert!(validate_nsid("com.example.fooBar.2").is_err());
        assert!(
            validate_nsid("a-0.b-1.c-3").is_err(),
            "name may not contain a hyphen"
        );
        assert!(
            validate_nsid("a-0.b-1.c-o").is_err(),
            "name may not contain a hyphen"
        );
        // ...but a hyphen is fine in an authority segment.
        assert!(validate_nsid("a-0.b-1.co").is_ok());
    }

    /// A hyphen may not sit at either end of any segment.
    #[test]
    fn segments_may_not_start_or_end_with_a_hyphen() {
        assert!(validate_nsid("com.example-.foo").is_err());
        assert!(validate_nsid("com.-example.foo").is_err());
    }

    /// Non-ASCII is refused as a character-set violation rather than by
    /// whichever structural rule it happens to trip.
    #[test]
    fn disallowed_characters_are_named_as_such() {
        let err = validate_nsid("com.exa\u{1F4A9}ple.thing").unwrap_err();
        let DataValidationError::StringFormatInvalid { reason, .. } = &err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(
            reason.contains("ASCII"),
            "the refusal should name the character set, got {reason:?}"
        );
    }
}
