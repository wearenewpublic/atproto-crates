//! URI syntax validation
//!
//! Validates generic URI strings according to RFC 3986.

use std::sync::LazyLock;

use regex::Regex;

use crate::validation::data_errors::DataValidationError;

/// Regex for validating URI syntax
///
/// A URI must have a scheme followed by ":" and scheme-specific content.
/// Scheme: letter followed by letters, digits, plus, hyphen, or dot
/// (RFC 3986 §3.1).
///
/// The content is `\S+` rather than `.+`: RFC 3986 has no production that
/// admits a raw space, so a space must be percent-encoded. `.+` accepted
/// `https://example.com/path gap`, and — the case that actually bites —
/// trailing whitespace, which survives a careless copy-paste and produces a
/// URI that looks right in every log line it appears in.
///
/// The scheme class is deliberately not the reference's `\w+`
/// (`packages/syntax/src/uri.ts:4`). RFC 3986 allows `+`, `-` and `.` in a
/// scheme and does not allow `_` or a leading digit, so `\w+` is wrong in
/// both directions: it refuses `content-type:text/plan` and
/// `microsoft.windows.camera:thing`, both of which the corpus lists as valid.
static URI_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z][a-zA-Z0-9+.-]*:\S+$").expect("URI regex should compile")
});

/// Validate a URI string
///
/// A valid URI must:
/// - Have a scheme component (e.g., "https:", "at:", "did:")
/// - Have content after the scheme
/// - Not exceed 8192 bytes
pub fn validate_uri(value: &str) -> Result<(), DataValidationError> {
    if value.is_empty() {
        return Err(DataValidationError::StringFormatInvalid {
            format: "uri".to_string(),
            value: value.to_string(),
            reason: "URI cannot be empty".to_string(),
        });
    }

    if value.len() > 8192 {
        return Err(DataValidationError::StringFormatInvalid {
            format: "uri".to_string(),
            value: value.to_string(),
            reason: "URI exceeds maximum length of 8192 bytes".to_string(),
        });
    }

    if !URI_REGEX.is_match(value) {
        return Err(DataValidationError::StringFormatInvalid {
            format: "uri".to_string(),
            value: value.to_string(),
            reason: "URI must have a valid scheme followed by content".to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_uris() {
        let valid = [
            "https://example.com",
            "http://example.com/path?query=1#fragment",
            "at://did:plc:asdf123",
            "did:plc:asdf123",
            "ftp://files.example.com/file.txt",
            "mailto:user@example.com",
            "urn:isbn:0451450523",
        ];
        for uri in valid {
            assert!(validate_uri(uri).is_ok(), "should be valid: {}", uri);
        }
    }

    #[test]
    fn test_invalid_uris() {
        let invalid = [
            "",
            "not a uri",
            "://missing-scheme",
            "123:invalid-scheme",
            ":no-scheme",
        ];
        for uri in invalid {
            assert!(validate_uri(uri).is_err(), "should be invalid: {}", uri);
        }
    }

    /// A URI contains no raw whitespace; RFC 3986 has no production for it.
    ///
    /// Trailing whitespace is the case worth naming: it survives a careless
    /// copy-paste and produces a URI that looks correct everywhere it is
    /// printed.
    #[test]
    fn whitespace_is_refused_anywhere_in_the_uri() {
        for uri in [
            "https://example.com/path gap",
            "https://example.com/trailing-whitespace  ",
            "  https://example.com/path",
            "https://example.com/\tpath",
            "https://example.com/path\n",
        ] {
            assert!(validate_uri(uri).is_err(), "should be invalid: {uri:?}");
        }
    }

    /// The scheme grammar is RFC 3986's, which is wider than `\w` in one
    /// direction and narrower in another.
    ///
    /// `+`, `-` and `.` are legal in a scheme; `_` and a leading digit are
    /// not. Porting the reference's `\w+` would have refused two corpus
    /// vectors while accepting schemes RFC 3986 does not define.
    #[test]
    fn the_scheme_follows_rfc_3986_not_word_characters() {
        assert!(validate_uri("content-type:text/plan").is_ok());
        assert!(validate_uri("microsoft.windows.camera:thing").is_ok());
        assert!(validate_uri("a+b:thing").is_ok());
        assert!(validate_uri("under_score:thing").is_err());
        assert!(validate_uri("123:invalid-scheme").is_err());
    }
}
