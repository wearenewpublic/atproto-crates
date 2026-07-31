//! DID (Decentralized Identifier) syntax validation
//!
//! Validates DID strings according to the W3C DID specification
//! and AT Protocol requirements.

use std::sync::LazyLock;

use regex::Regex;

use crate::validation::data_errors::DataValidationError;

/// Regex for validating DID syntax
///
/// Format: `did:<method>:<method-specific-id>`
/// - method: lowercase letters only — not digits, so `did:m123:val` is invalid
/// - method-specific-id: alphanumeric, dots, hyphens, underscores, colons and
///   percent signs, ending in a character that is neither `:` nor `%`
///
/// The trailing-character class is the whole point of the second bracket
/// group, and is how both reference implementations spell the rule. A DID may
/// not end in `%`, because `%` introduces a percent-escape and a trailing one
/// is an escape with nothing to escape.
static DID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$").expect("DID regex should compile")
});

/// Validate a DID string
///
/// A valid DID must:
/// - Start with "did:"
/// - Have a method name of lowercase letters
/// - Have a method-specific identifier
/// - Not exceed 2048 characters
/// - Not end with ":"
pub fn validate_did(value: &str) -> Result<(), DataValidationError> {
    if value.is_empty() {
        return Err(DataValidationError::StringFormatInvalid {
            format: "did".to_string(),
            value: value.to_string(),
            reason: "DID cannot be empty".to_string(),
        });
    }

    if !value.starts_with("did:") {
        return Err(DataValidationError::StringFormatInvalid {
            format: "did".to_string(),
            value: value.to_string(),
            reason: "DID must start with 'did:'".to_string(),
        });
    }

    if value.len() > 2048 {
        return Err(DataValidationError::StringFormatInvalid {
            format: "did".to_string(),
            value: value.to_string(),
            reason: "DID exceeds maximum length of 2048 characters".to_string(),
        });
    }

    // Checked separately from the regex so the refusal names the reason. The
    // regex enforces the same thing structurally, via its final character
    // class; this is here to say *why*.
    if value.ends_with(':') || value.ends_with('%') {
        return Err(DataValidationError::StringFormatInvalid {
            format: "did".to_string(),
            value: value.to_string(),
            reason: "DID must not end with ':' or '%'".to_string(),
        });
    }

    if !DID_REGEX.is_match(value) {
        return Err(DataValidationError::StringFormatInvalid {
            format: "did".to_string(),
            value: value.to_string(),
            reason: "DID does not match expected syntax".to_string(),
        });
    }

    // Must have at least 3 parts when split by ':'
    let parts: Vec<&str> = value.splitn(3, ':').collect();
    if parts.len() < 3 || parts[2].is_empty() {
        return Err(DataValidationError::StringFormatInvalid {
            format: "did".to_string(),
            value: value.to_string(),
            reason: "DID must have a method-specific identifier".to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_dids() {
        let valid = [
            "did:plc:7iza6de2dwap2sbkpav7c6c6",
            "did:web:example.com",
            "did:method:val",
            "did:method:VAL",
            "did:method:val123",
            "did:method:val:sub:path",
            "did:key:zQ3shZc2QzFh7MC8g...",
        ];
        for did in valid {
            assert!(validate_did(did).is_ok(), "should be valid: {}", did);
        }
    }

    #[test]
    fn test_invalid_dids() {
        let invalid = [
            "",
            "did",
            "did:",
            "did:method:",
            "not:a:did",
            "did:METHOD:val", // method must be lowercase
        ];
        for did in invalid {
            assert!(validate_did(did).is_err(), "should be invalid: {}", did);
        }
    }

    /// A DID may not end in `%`.
    ///
    /// `%` introduces a percent-escape, so a trailing one is an escape with
    /// nothing to escape. Both reference implementations spell this as the
    /// final character class of their DID regex, and the TypeScript one also
    /// says it outright: "DID can not end with ':' or '%'".
    #[test]
    fn a_did_may_not_end_with_a_percent_sign() {
        assert!(validate_did("did:method:val%").is_err());
        assert!(validate_did("did:method:val:").is_err());
        // A percent inside the identifier is still allowed — the rule is about
        // the final character, not about validating each escape.
        assert!(validate_did("did:method:va%20l").is_ok());
    }

    /// The method name is lowercase letters only.
    #[test]
    fn the_method_name_takes_no_digits_or_uppercase() {
        assert!(validate_did("did:m123:val").is_err());
        assert!(validate_did("did:METHOD:val").is_err());
        assert!(validate_did("did:method:val").is_ok());
    }

    /// The identifier may contain colons; only a trailing one is refused.
    #[test]
    fn interior_colons_are_part_of_the_identifier() {
        assert!(validate_did("did:method:val:sub:path").is_ok());
        assert!(validate_did("did:plc:7iza6de2dwap2sbkpav7c6c6").is_ok());
    }
}
