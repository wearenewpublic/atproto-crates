//! TID (Timestamp Identifier) syntax validation
//!
//! Validates AT Protocol TID strings. A TID is a timestamp-based identifier
//! encoded in a specific base32-sortable format.

use crate::validation::data_errors::DataValidationError;

/// Valid characters in a TID (base32-sortable: 234567abcdefghijklmnopqrstuvwxyz)
const TID_CHARS: &str = "234567abcdefghijklmnopqrstuvwxyz";

/// The characters a TID may begin with.
///
/// A TID is a 64-bit integer whose top bit is always zero, and thirteen
/// base32-sortable characters carry 65 bits. The first character therefore
/// contributes only four usable bits, which is the first sixteen of the
/// alphabet — not the first eight, as this module previously documented.
const TID_FIRST_CHARS: &str = "234567abcdefghij";

/// Validate a TID string
///
/// A valid TID must:
/// - Be exactly 13 characters long
/// - Contain only base32-sortable characters (2-7, a-z)
/// - Start with one of [`TID_FIRST_CHARS`], so the encoded value's top bit is
///   zero
pub fn validate_tid(value: &str) -> Result<(), DataValidationError> {
    if value.is_empty() {
        return Err(DataValidationError::StringFormatInvalid {
            format: "tid".to_string(),
            value: value.to_string(),
            reason: "TID cannot be empty".to_string(),
        });
    }

    if value.len() != 13 {
        return Err(DataValidationError::StringFormatInvalid {
            format: "tid".to_string(),
            value: value.to_string(),
            reason: format!("TID must be exactly 13 characters, got {}", value.len()),
        });
    }

    for c in value.chars() {
        if !TID_CHARS.contains(c) {
            return Err(DataValidationError::StringFormatInvalid {
                format: "tid".to_string(),
                value: value.to_string(),
                reason: format!("TID contains invalid character: '{}'", c),
            });
        }
    }

    // Checked last, so a string that is not base32-sortable at all is reported
    // as such rather than as a bad first character.
    let first = value.chars().next().unwrap_or_default();
    if !TID_FIRST_CHARS.contains(first) {
        return Err(DataValidationError::StringFormatInvalid {
            format: "tid".to_string(),
            value: value.to_string(),
            reason: format!("TID must start with one of {TID_FIRST_CHARS}, got '{first}'"),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_tids() {
        let valid = ["3jui7kd54zh2y", "2222222222222", "3333333333333"];
        for tid in valid {
            assert!(validate_tid(tid).is_ok(), "should be valid: {}", tid);
        }
    }

    #[test]
    fn test_invalid_tids() {
        let invalid = [
            "",
            "3jui7kd54zh2",   // too short (12 chars)
            "3jui7kd54zh2yy", // too long (14 chars)
            "0000000000000",  // invalid chars (0, 1 not in base32-sortable)
            "3jui7kd54zH2y",  // uppercase not allowed
        ];
        for tid in invalid {
            assert!(validate_tid(tid).is_err(), "should be invalid: {}", tid);
        }
    }

    /// The first character carries only four usable bits, so it is restricted
    /// to the first sixteen of the alphabet.
    ///
    /// This rule was documented in this module — and as `[2-b]`, which is the
    /// first *eight* — but never implemented, so `zzzzzzzzzzzzz` validated.
    #[test]
    fn the_first_character_must_not_set_the_top_bit() {
        for c in "234567abcdefghij".chars() {
            let tid = format!("{c}222222222222");
            assert!(validate_tid(&tid).is_ok(), "should be valid: {tid}");
        }
        for c in "klmnopqrstuvwxyz".chars() {
            let tid = format!("{c}222222222222");
            assert!(validate_tid(&tid).is_err(), "should be invalid: {tid}");
        }
    }

    /// The boundary is exactly between `j` and `k`, and the restriction
    /// applies only to the first character.
    #[test]
    fn only_the_first_character_is_restricted() {
        assert!(validate_tid("j222222222222").is_ok());
        assert!(validate_tid("k222222222222").is_err());
        // `z` is fine anywhere but the front.
        assert!(validate_tid("2zzzzzzzzzzzz").is_ok());
        assert!(validate_tid("zzzzzzzzzzzzz").is_err());
    }

    /// A non-alphabet character is reported as such, not as a bad first
    /// character.
    #[test]
    fn a_bad_character_is_named_before_the_first_character_rule() {
        let err = validate_tid("0000000000000").unwrap_err();
        let DataValidationError::StringFormatInvalid { reason, .. } = &err else {
            panic!("unexpected error: {err:?}");
        };
        assert!(
            reason.contains("invalid character"),
            "expected a character-set refusal, got {reason:?}"
        );
    }
}
