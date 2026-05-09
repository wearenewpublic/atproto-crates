//! Input validation for AT Protocol handles and DIDs.
//!
//! Validates AT Protocol identifiers including handles, DIDs, and TLDs
//! following RFC 1035 and AT Protocol specifications.
//! - [`strip_handle_prefixes`] - Removes common handle prefixes (`@`, `at://`)
//!
//! ## DID Validation
//! - [`is_valid_did_method_plc`] - Validates PLC DIDs (`did:plc:...`)
//! - [`is_valid_did_method_web`] - Validates Web DIDs (`did:web:...`)
//! - [`is_valid_did_method_webvh`] - Validates WebVH DIDs (`did:webvh:...`)
//!
//! ## Network Address Validation
//! - [`is_valid_hostname`] - RFC 1035 compliant hostname validation
//! - [`is_ipv4`] - IPv4 address validation
//! - [`is_ipv6`] - IPv6 address validation
//!
//! ## Utility Functions
//! - [`is_valid_base58_btc`] - Base58-btc alphabet character validation
//!
//! # Examples
//!
//! ```
//! use atproto_identity::validation::*;
//!
//! // Handle validation
//! assert_eq!(is_valid_handle("@alice.bsky.social"), Some("alice.bsky.social".to_string()));
//!
//! // DID validation
//! assert!(is_valid_did_method_plc("did:plc:z3f2222fa222f5c33c2f27ez"));
//! assert!(is_valid_did_method_web("did:web:example.com", true));
//! assert!(is_valid_did_method_webvh("did:webvh:abc123:example.com", true));
//!
//! // Network validation
//! assert!(is_valid_hostname("example.com"));
//! assert!(is_ipv4("192.168.1.1"));
//! assert!(is_ipv6("2001:db8::1"));
//! ```

/// Maximum length for a valid hostname as defined in RFC 1035
const MAX_HOSTNAME_LENGTH: usize = 253;

/// Maximum length for a DNS label (component between dots) as defined in RFC 1035
const MAX_LABEL_LENGTH: usize = 63;

/// List of reserved top-level domains that are not valid for AT Protocol handles
const RESERVED_TLDS: [&str; 4] = [".localhost", ".internal", ".arpa", ".local"];

/// Validates if a string is a valid hostname according to RFC 1035.
///
/// A valid hostname must:
/// - Be between 1 and 253 characters in length
/// - Not use reserved top-level domains (.localhost, .internal, .arpa, .local)
/// - Not be an IPv4 or IPv6 address
/// - Contain only valid hostname characters (letters, digits, hyphens, dots)
/// - Have valid DNS labels (no leading/trailing hyphens, max 63 chars per label)
///
/// # Arguments
///
/// * `hostname` - The hostname string to validate
///
/// # Returns
///
/// `true` if the hostname is valid according to RFC 1035, `false` otherwise
///
/// # Examples
///
/// ```
/// use atproto_identity::validation::is_valid_hostname;
///
/// // Valid hostnames
/// assert!(is_valid_hostname("example.com"));
/// assert!(is_valid_hostname("sub.example.com"));
/// assert!(is_valid_hostname("test-host.example.com"));
/// assert!(is_valid_hostname("localhost"));
///
/// // Invalid hostnames
/// assert!(!is_valid_hostname("192.168.1.1")); // IPv4 address
/// assert!(!is_valid_hostname("example.localhost")); // Reserved TLD
/// assert!(!is_valid_hostname("example..com")); // Double dot
/// assert!(!is_valid_hostname("-example.com")); // Leading hyphen
/// ```
pub fn is_valid_hostname(hostname: &str) -> bool {
    // Empty hostnames are invalid
    if hostname.is_empty() || hostname.len() > MAX_HOSTNAME_LENGTH {
        return false;
    }

    // Check if hostname uses any reserved TLDs
    if RESERVED_TLDS.iter().any(|tld| hostname.ends_with(tld)) {
        return false;
    }

    // Reject IPv4 addresses
    if is_ipv4(hostname) {
        return false;
    }

    // Reject IPv6 addresses
    if is_ipv6(hostname) {
        return false;
    }

    // Ensure all characters are valid hostname characters
    if hostname.bytes().any(|byte| !is_valid_hostname_char(byte)) {
        return false;
    }

    // Validate each DNS label in the hostname
    if hostname.split('.').any(|label| !is_valid_dns_label(label)) {
        return false;
    }

    true
}

fn is_valid_hostname_char(byte: u8) -> bool {
    byte.is_ascii_lowercase()
        || byte.is_ascii_uppercase()
        || byte.is_ascii_digit()
        || byte == b'-'
        || byte == b'.'
}

fn is_valid_dns_label(label: &str) -> bool {
    !(label.is_empty()
        || label.len() > MAX_LABEL_LENGTH
        || label.starts_with('-')
        || label.ends_with('-'))
}

/// Checks if a string is a valid IPv4 address.
///
/// Validates that the string consists of exactly four decimal numbers
/// separated by dots, where each number is between 0 and 255.
///
/// # Arguments
///
/// * `s` - The string to validate as an IPv4 address
///
/// # Returns
///
/// `true` if the string is a valid IPv4 address, `false` otherwise
///
/// # Examples
///
/// ```
/// use atproto_identity::validation::is_ipv4;
///
/// // Valid IPv4 addresses
/// assert!(is_ipv4("192.168.1.1"));
/// assert!(is_ipv4("127.0.0.1"));
/// assert!(is_ipv4("255.255.255.255"));
/// assert!(is_ipv4("0.0.0.0"));
///
/// // Invalid IPv4 addresses
/// assert!(!is_ipv4("256.1.1.1")); // Number too large
/// assert!(!is_ipv4("192.168.1")); // Missing octet
/// assert!(!is_ipv4("192.168.1.1.1")); // Too many octets
/// assert!(!is_ipv4("example.com")); // Not numeric
/// ```
pub fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    parts.iter().all(|part| part.parse::<u8>().is_ok())
}

/// Checks if a string is a valid IPv6 address.
///
/// Performs basic IPv6 validation including:
/// - Must contain colons (distinguishing from IPv4)
/// - Supports brackets for URLs (e.g., `[2001:db8::1]`)
/// - Validates compressed notation with `::` (at most one occurrence)
/// - Each segment must be valid hexadecimal (1-4 characters)
/// - At most 8 segments total
///
/// # Arguments
///
/// * `s` - The string to validate as an IPv6 address
///
/// # Returns
///
/// `true` if the string is a valid IPv6 address, `false` otherwise
///
/// # Examples
///
/// ```
/// use atproto_identity::validation::is_ipv6;
///
/// // Valid IPv6 addresses
/// assert!(is_ipv6("2001:db8::1"));
/// assert!(is_ipv6("::1"));
/// assert!(is_ipv6("fe80::1"));
/// assert!(is_ipv6("[2001:db8::1]")); // With brackets
/// assert!(is_ipv6("2001:0db8:0000:0000:0000:ff00:0042:8329"));
///
/// // Invalid IPv6 addresses
/// assert!(!is_ipv6("192.168.1.1")); // IPv4, not IPv6
/// assert!(!is_ipv6("example.com")); // No colons
/// assert!(!is_ipv6("2001:gggg::1")); // Invalid hex characters
/// ```
pub fn is_ipv6(s: &str) -> bool {
    // Basic IPv6 validation - must contain colons and valid hex characters
    if !s.contains(':') {
        return false;
    }

    // Check for IPv6 with brackets
    let s = if s.starts_with('[') && s.ends_with(']') {
        &s[1..s.len() - 1]
    } else {
        s
    };

    // Split by :: for compressed notation
    let parts: Vec<&str> = s.split("::").collect();
    if parts.len() > 2 {
        return false; // More than one :: is invalid
    }

    // Validate each segment
    let segments: Vec<&str> = s.split(':').filter(|s| !s.is_empty()).collect();

    // IPv6 can have at most 8 segments (or fewer with ::)
    if segments.len() > 8 {
        return false;
    }

    // Each segment must be valid hexadecimal and at most 4 characters
    segments
        .iter()
        .all(|segment| segment.len() <= 4 && segment.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Validates and normalizes an AT Protocol handle.
///
/// A valid AT Protocol handle must:
/// - Be a valid hostname (after stripping prefixes)
/// - Contain at least one period (to distinguish from simple hostnames)
/// - Follow all hostname validation rules (RFC 1035)
///
/// The function automatically strips common prefixes (`at://` and `@`) before validation.
///
/// # Arguments
///
/// * `handle` - The handle string to validate and normalize
///
/// # Returns
///
/// `Some(String)` containing the normalized handle if valid, `None` if invalid
///
/// # Examples
///
/// ```
/// use atproto_identity::validation::is_valid_handle;
///
/// // Valid handles
/// assert_eq!(is_valid_handle("alice.bsky.social"), Some("alice.bsky.social".to_string()));
/// assert_eq!(is_valid_handle("@bob.example.com"), Some("bob.example.com".to_string()));
/// assert_eq!(is_valid_handle("at://charlie.test.com"), Some("charlie.test.com".to_string()));
///
/// // Invalid handles
/// assert_eq!(is_valid_handle("localhost"), None); // No period
/// assert_eq!(is_valid_handle("192.168.1.1"), None); // IPv4 address
/// assert_eq!(is_valid_handle("invalid..handle.com"), None); // Double dot
/// ```
pub fn is_valid_handle(handle: &str) -> Option<String> {
    // Strip optional prefixes to get the core handle
    let trimmed = strip_handle_prefixes(handle);

    // A valid handle must be a valid hostname with at least one period
    if is_valid_hostname(trimmed) && trimmed.contains('.') {
        Some(trimmed.to_string())
    } else {
        None
    }
}

/// Strips common AT Protocol handle prefixes from a handle string.
///
/// Removes the `at://` or `@` prefix if present, returning the clean handle.
/// This is useful for normalizing handle input from various sources.
///
/// # Arguments
///
/// * `handle` - The handle string that may contain prefixes
///
/// # Returns
///
/// The handle string with prefixes removed
///
/// # Examples
///
/// ```
/// use atproto_identity::validation::strip_handle_prefixes;
///
/// assert_eq!(strip_handle_prefixes("@alice.bsky.social"), "alice.bsky.social");
/// assert_eq!(strip_handle_prefixes("at://bob.example.com"), "bob.example.com");
/// assert_eq!(strip_handle_prefixes("charlie.test.com"), "charlie.test.com");
/// ```
pub fn strip_handle_prefixes(handle: &str) -> &str {
    if let Some(value) = handle.strip_prefix("at://") {
        value
    } else if let Some(value) = handle.strip_prefix('@') {
        value
    } else {
        handle
    }
}

/// Validates if a string is a properly formatted PLC DID.
///
/// A valid PLC DID must:
/// - Start with the prefix `did:plc:`
/// - Be followed by exactly 24 characters of base32 encoding (lowercase letters a-z and digits 2-7)
///
/// # Arguments
///
/// * `did` - The DID string to validate
///
/// # Returns
///
/// `true` if the DID is a valid PLC DID, `false` otherwise
///
/// # Examples
///
/// ```
/// use atproto_identity::validation::is_valid_did_method_plc;
///
/// // Valid PLC DIDs
/// assert!(is_valid_did_method_plc("did:plc:z3f2222fa222f5c33c2f27ez"));
/// assert!(is_valid_did_method_plc("did:plc:abcdefghijklmnopqrstuvwx"));
///
/// // Invalid PLC DIDs
/// assert!(!is_valid_did_method_plc("did:web:example.com"));
/// assert!(!is_valid_did_method_plc("did:plc:invalid0length"));
/// assert!(!is_valid_did_method_plc("did:plc:UPPERCASE_NOT_ALLOWED"));
/// ```
pub fn is_valid_did_method_plc(did: &str) -> bool {
    let did_value = match did.strip_prefix("did:plc:") {
        Some(value) => value,
        None => return false,
    };

    // Must be exactly 24 characters and all valid base32 (lowercase letters and numbers 2-7)
    did_value.len() == 24
        && did_value
            .chars()
            .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c))
}

/// Validates if a string is a properly formatted Web DID.
///
/// A valid Web DID must start with the prefix `did:web:` followed by content that
/// depends on the strictness mode:
///
/// # Strict Mode (`strict = true`)
/// - Only a valid hostname is allowed after `did:web:`
/// - No additional path segments permitted
///
/// # Non-Strict Mode (`strict = false`)
/// - First segment must be a valid hostname
/// - Additional colon-separated segments are allowed
/// - Each additional segment must be non-empty and alphanumeric
///
/// # Arguments
///
/// * `did` - The DID string to validate
/// * `strict` - Whether to use strict hostname-only validation
///
/// # Returns
///
/// `true` if the DID is a valid Web DID according to the specified mode, `false` otherwise
///
/// # Examples
///
/// ```
/// use atproto_identity::validation::is_valid_did_method_web;
///
/// // Valid in both modes
/// assert!(is_valid_did_method_web("did:web:example.com", true));
/// assert!(is_valid_did_method_web("did:web:example.com", false));
///
/// // Valid only in non-strict mode
/// assert!(!is_valid_did_method_web("did:web:example.com:path", true));
/// assert!(is_valid_did_method_web("did:web:example.com:path", false));
/// assert!(is_valid_did_method_web("did:web:example.com:path:subpath", false));
///
/// // Invalid in both modes
/// assert!(!is_valid_did_method_web("did:web:192.168.1.1", true));
/// assert!(!is_valid_did_method_web("did:web:example.com:", false));
/// ```
pub fn is_valid_did_method_web(did: &str, strict: bool) -> bool {
    let did_value = match did.strip_prefix("did:web:") {
        Some(value) => value,
        None => return false,
    };

    if strict {
        // In strict mode, only a valid hostname is allowed
        is_valid_hostname(did_value)
    } else {
        // In non-strict mode, allow colon-separated segments
        let segments: Vec<&str> = did_value.split(':').collect();

        // Must have at least one segment (the hostname)
        if segments.is_empty() {
            return false;
        }

        // First segment must be a valid hostname
        if !is_valid_hostname(segments[0]) {
            return false;
        }

        // All subsequent segments must be non-empty alphanumeric strings
        segments[1..].iter().all(|segment| {
            !segment.is_empty() && segment.chars().all(|c| c.is_ascii_alphanumeric())
        })
    }
}

/// Validates if a string is a properly formatted WebVH DID.
///
/// A WebVH DID extends the Web DID format by adding a SCIM (Self-Controlled Identity Marker)
/// segment immediately after the `did:webvh:` prefix.
///
/// # Format
///
/// ```text
/// did:webvh:<scim>:<content>
/// ```
///
/// Where:
/// - `<scim>` must contain only base58-btc alphabet characters (`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`)
/// - `<content>` follows the same validation rules as `did:web` content
///
/// # Strict vs Non-Strict Mode
///
/// **Strict Mode (`strict = true`)**:
/// - `<content>` must be a valid hostname only
/// - No additional path segments permitted
///
/// **Non-Strict Mode (`strict = false`)**:
/// - First segment of `<content>` must be a valid hostname
/// - Additional colon-separated segments are allowed
/// - Each additional segment must be non-empty and alphanumeric
///
/// # Arguments
///
/// * `did` - The DID string to validate
/// * `strict` - Whether to use strict hostname-only validation for the content portion
///
/// # Returns
///
/// `true` if the DID is a valid WebVH DID according to the specified mode, `false` otherwise
///
/// # Examples
///
/// ```
/// use atproto_identity::validation::is_valid_did_method_webvh;
///
/// // Valid WebVH DIDs in both modes
/// assert!(is_valid_did_method_webvh("did:webvh:abc123:example.com", true));
/// assert!(is_valid_did_method_webvh("did:webvh:XYZ789:sub.example.com", false));
///
/// // Valid only in non-strict mode (has path segments)
/// assert!(!is_valid_did_method_webvh("did:webvh:abc123:example.com:path", true));
/// assert!(is_valid_did_method_webvh("did:webvh:abc123:example.com:path", false));
/// assert!(is_valid_did_method_webvh("did:webvh:def456:example.com:path:subpath", false));
///
/// // Invalid - SCIM contains excluded base58 characters (0, O, I, l)
/// assert!(!is_valid_did_method_webvh("did:webvh:0abc:example.com", true));
/// assert!(!is_valid_did_method_webvh("did:webvh:Oabc:example.com", false));
/// assert!(!is_valid_did_method_webvh("did:webvh:Iabc:example.com", true));
/// assert!(!is_valid_did_method_webvh("did:webvh:labc:example.com", false));
///
/// // Invalid - wrong format or missing components
/// assert!(!is_valid_did_method_webvh("did:web:abc123:example.com", true)); // Wrong prefix
/// assert!(!is_valid_did_method_webvh("did:webvh:abc123", true)); // Missing content
/// assert!(!is_valid_did_method_webvh("did:webvh::example.com", true)); // Empty SCIM
/// ```
pub fn is_valid_did_method_webvh(did: &str, strict: bool) -> bool {
    let did_value = match did.strip_prefix("did:webvh:") {
        Some(value) => value,
        None => return false,
    };

    // Split by the first colon to separate scim from content
    let parts: Vec<&str> = did_value.splitn(2, ':').collect();

    // Must have exactly 2 parts: scim and content
    if parts.len() != 2 {
        return false;
    }

    let scim = parts[0];
    let content = parts[1];

    // Validate scim - must be non-empty and contain only base58-btc alphabet characters
    if scim.is_empty() || !is_valid_base58_btc(scim) {
        return false;
    }

    // Validate content using the same rules as did:web
    if strict {
        // In strict mode, only a valid hostname is allowed
        is_valid_hostname(content)
    } else {
        // In non-strict mode, allow colon-separated segments
        let segments: Vec<&str> = content.split(':').collect();

        // Must have at least one segment (the hostname)
        if segments.is_empty() {
            return false;
        }

        // First segment must be a valid hostname
        if !is_valid_hostname(segments[0]) {
            return false;
        }

        // All subsequent segments must be non-empty alphanumeric strings
        segments[1..].iter().all(|segment| {
            !segment.is_empty() && segment.chars().all(|c| c.is_ascii_alphanumeric())
        })
    }
}

/// Checks if a string contains only base58-btc alphabet characters.
///
/// The base58-btc alphabet is used in Bitcoin and other cryptocurrency systems.
/// It includes all alphanumeric characters except those that are easily confused:
/// - Excludes: `0` (zero), `O` (capital O), `I` (capital I), `l` (lowercase L)
/// - Includes: `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`
///
/// # Arguments
///
/// * `s` - The string to validate for base58-btc character compliance
///
/// # Returns
///
/// `true` if the string is non-empty and contains only valid base58-btc characters, `false` otherwise
///
/// # Examples
///
/// ```
/// use atproto_identity::validation::is_valid_base58_btc;
///
/// // Valid base58-btc strings
/// assert!(is_valid_base58_btc("123456789"));
/// assert!(is_valid_base58_btc("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz"));
/// assert!(is_valid_base58_btc("abc123XYZ"));
///
/// // Invalid - contains excluded characters
/// assert!(!is_valid_base58_btc("abc0def")); // Contains 0
/// assert!(!is_valid_base58_btc("abcOdef")); // Contains O
/// assert!(!is_valid_base58_btc("abcIdef")); // Contains I
/// assert!(!is_valid_base58_btc("abcldef")); // Contains l
///
/// // Invalid - empty or non-alphanumeric
/// assert!(!is_valid_base58_btc(""));
/// assert!(!is_valid_base58_btc("abc-def"));
/// ```
pub fn is_valid_base58_btc(s: &str) -> bool {
    const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    !s.is_empty() && s.chars().all(|c| BASE58_ALPHABET.contains(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_did_method_plc() {
        // Valid PLC DIDs - exactly 24 base32 characters after "did:plc:"
        assert!(is_valid_did_method_plc("did:plc:abcdefghijklmnopqrstuvwx"));
        assert!(is_valid_did_method_plc("did:plc:z3f2222fa222f5c33c2f27ez"));
        assert!(is_valid_did_method_plc("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")); // 24 'a's
        assert!(is_valid_did_method_plc("did:plc:abcdef2345ghijk6mn7pqrst")); // mix of letters and valid numbers

        // Invalid PLC DIDs - contains uppercase letters (not valid base32)
        assert!(!is_valid_did_method_plc("did:plc:ABCDEFGHIJKLMNOPQRSTUVWX"));
        assert!(!is_valid_did_method_plc("did:plc:Abcdefghijklmnopqrstuvwx"));

        // Invalid PLC DIDs - contains invalid numbers (0, 1, 8, 9)
        assert!(!is_valid_did_method_plc("did:plc:123456789012345678901234"));
        assert!(!is_valid_did_method_plc("did:plc:abcdefghijklmnopqrstuv0x"));
        assert!(!is_valid_did_method_plc("did:plc:abcdefghijklmnopqrstuv1x"));
        assert!(!is_valid_did_method_plc("did:plc:abcdefghijklmnopqrstuv8x"));
        assert!(!is_valid_did_method_plc("did:plc:abcdefghijklmnopqrstuv9x"));

        // Invalid PLC DIDs - wrong prefix
        assert!(!is_valid_did_method_plc("did:web:abcdefghijklmnopqrstuvwx"));
        assert!(!is_valid_did_method_plc("did:key:abcdefghijklmnopqrstuvwx"));
        assert!(!is_valid_did_method_plc("plc:abcdefghijklmnopqrstuvwx"));
        assert!(!is_valid_did_method_plc("abcdefghijklmnopqrstuvwx"));

        // Invalid PLC DIDs - wrong length (not 24 characters)
        assert!(!is_valid_did_method_plc("did:plc:"));
        assert!(!is_valid_did_method_plc("did:plc:abc"));
        assert!(!is_valid_did_method_plc("did:plc:abcdefghijklmnopqrstuv")); // 23 chars
        assert!(!is_valid_did_method_plc(
            "did:plc:abcdefghijklmnopqrstuvwxy"
        )); // 25 chars
        assert!(!is_valid_did_method_plc(
            "did:plc:abcdefghijklmnopqrstuvwxyz"
        )); // 26 chars

        // Edge cases
        assert!(!is_valid_did_method_plc(""));
        assert!(!is_valid_did_method_plc("did:plc"));
        assert!(!is_valid_did_method_plc("did:plc:"));
        assert!(!is_valid_did_method_plc("DID:PLC:abcdefghijklmnopqrstuvwx")); // uppercase prefix
        assert!(!is_valid_did_method_plc("did:PLC:abcdefghijklmnopqrstuvwx")); // uppercase method
        assert!(!is_valid_did_method_plc(
            " did:plc:abcdefghijklmnopqrstuvwx"
        )); // leading space
        assert!(!is_valid_did_method_plc(
            "did:plc:abcdefghijklmnopqrstuvwx "
        )); // trailing space

        // Invalid - special characters (not base32)
        assert!(!is_valid_did_method_plc("did:plc:abc-def_hij.klm~nop!qrst")); // special chars
        assert!(!is_valid_did_method_plc("did:plc:~~~!!!@@@###$$$%%%^^^&")); // special chars
        assert!(!is_valid_did_method_plc("did:plc:                        ")); // spaces
    }

    #[test]
    fn test_is_valid_did_method_web() {
        // Test strict mode (only hostname allowed)
        assert!(is_valid_did_method_web("did:web:example.com", true));
        assert!(is_valid_did_method_web("did:web:sub.example.com", true));
        assert!(is_valid_did_method_web("did:web:example.co.uk", true));
        assert!(is_valid_did_method_web("did:web:localhost", true));

        // Invalid in strict mode - contains colon-separated segments
        assert!(!is_valid_did_method_web("did:web:example.com:path", true));
        assert!(!is_valid_did_method_web(
            "did:web:example.com:path:subpath",
            true
        ));
        assert!(!is_valid_did_method_web("did:web:example.com:123", true));

        // Test non-strict mode (allows colon-separated segments)
        assert!(is_valid_did_method_web("did:web:example.com", false));
        assert!(is_valid_did_method_web("did:web:example.com:path", false));
        assert!(is_valid_did_method_web(
            "did:web:example.com:path:subpath",
            false
        ));
        assert!(is_valid_did_method_web("did:web:example.com:123", false));
        assert!(is_valid_did_method_web("did:web:example.com:abc123", false));
        assert!(is_valid_did_method_web(
            "did:web:example.com:UPPERCASE",
            false
        ));

        // Invalid in non-strict mode - empty segments
        assert!(!is_valid_did_method_web("did:web:example.com:", false));
        assert!(!is_valid_did_method_web("did:web:example.com::", false));
        assert!(!is_valid_did_method_web("did:web:example.com:path:", false));
        assert!(!is_valid_did_method_web("did:web:example.com::path", false));

        // Invalid in non-strict mode - non-alphanumeric in segments
        assert!(!is_valid_did_method_web(
            "did:web:example.com:path/subpath",
            false
        ));
        assert!(!is_valid_did_method_web(
            "did:web:example.com:path-name",
            false
        ));
        assert!(!is_valid_did_method_web(
            "did:web:example.com:path_name",
            false
        ));
        assert!(!is_valid_did_method_web(
            "did:web:example.com:path.name",
            false
        ));
        assert!(!is_valid_did_method_web(
            "did:web:example.com:path@name",
            false
        ));
        assert!(!is_valid_did_method_web(
            "did:web:example.com:path name",
            false
        ));

        // Invalid in both modes - wrong prefix
        assert!(!is_valid_did_method_web("did:plc:example.com", true));
        assert!(!is_valid_did_method_web("did:plc:example.com", false));
        assert!(!is_valid_did_method_web("web:example.com", true));
        assert!(!is_valid_did_method_web("web:example.com", false));
        assert!(!is_valid_did_method_web("example.com", true));
        assert!(!is_valid_did_method_web("example.com", false));

        // Invalid in both modes - invalid hostname
        assert!(!is_valid_did_method_web("did:web:", true));
        assert!(!is_valid_did_method_web("did:web:", false));
        assert!(!is_valid_did_method_web("did:web:example..com", true));
        assert!(!is_valid_did_method_web("did:web:example..com", false));
        assert!(!is_valid_did_method_web("did:web:.example.com", true));
        assert!(!is_valid_did_method_web("did:web:.example.com", false));
        assert!(!is_valid_did_method_web("did:web:example.com.", true));
        assert!(!is_valid_did_method_web("did:web:example.com.", false));
        assert!(!is_valid_did_method_web("did:web:-example.com", true));
        assert!(!is_valid_did_method_web("did:web:-example.com", false));

        // Invalid in both modes - reserved TLDs
        assert!(!is_valid_did_method_web("did:web:example.localhost", true));
        assert!(!is_valid_did_method_web("did:web:example.localhost", false));
        assert!(!is_valid_did_method_web("did:web:example.local", true));
        assert!(!is_valid_did_method_web("did:web:example.local", false));

        // Invalid in both modes - IPv4 addresses
        assert!(!is_valid_did_method_web("did:web:192.168.1.1", true));
        assert!(!is_valid_did_method_web("did:web:192.168.1.1", false));
        assert!(!is_valid_did_method_web("did:web:127.0.0.1", true));
        assert!(!is_valid_did_method_web("did:web:127.0.0.1", false));
        assert!(!is_valid_did_method_web("did:web:10.0.0.1", true));
        assert!(!is_valid_did_method_web("did:web:10.0.0.1", false));

        // Invalid in both modes - IPv6 addresses
        assert!(!is_valid_did_method_web("did:web:2001:db8::1", true));
        assert!(!is_valid_did_method_web("did:web:2001:db8::1", false));
        assert!(!is_valid_did_method_web("did:web:::1", true));
        assert!(!is_valid_did_method_web("did:web:::1", false));
        assert!(!is_valid_did_method_web("did:web:[2001:db8::1]", true));
        assert!(!is_valid_did_method_web("did:web:[2001:db8::1]", false));
    }

    #[test]
    fn test_is_valid_hostname() {
        // Valid hostnames
        assert!(is_valid_hostname("example.com"));
        assert!(is_valid_hostname("sub.example.com"));
        assert!(is_valid_hostname("example.co.uk"));
        assert!(is_valid_hostname("localhost"));
        assert!(is_valid_hostname("test-host.example.com"));
        assert!(is_valid_hostname("123.example.com"));
        assert!(is_valid_hostname("a.b.c.d.example.com"));

        // Invalid - IPv4 addresses
        assert!(!is_valid_hostname("192.168.1.1"));
        assert!(!is_valid_hostname("127.0.0.1"));
        assert!(!is_valid_hostname("10.0.0.1"));
        assert!(!is_valid_hostname("255.255.255.255"));
        assert!(!is_valid_hostname("0.0.0.0"));

        // Invalid - IPv6 addresses
        assert!(!is_valid_hostname("2001:db8::1"));
        assert!(!is_valid_hostname("::1"));
        assert!(!is_valid_hostname("fe80::1"));
        assert!(!is_valid_hostname("[2001:db8::1]"));
        assert!(!is_valid_hostname("[::1]"));
        assert!(!is_valid_hostname(
            "2001:0db8:0000:0000:0000:ff00:0042:8329"
        ));

        // Invalid - empty or too long
        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname(&"a".repeat(254))); // Too long

        // Invalid - reserved TLDs
        assert!(!is_valid_hostname("example.localhost"));
        assert!(!is_valid_hostname("example.local"));
        assert!(!is_valid_hostname("example.internal"));
        assert!(!is_valid_hostname("example.arpa"));

        // Invalid - bad format
        assert!(!is_valid_hostname("example..com"));
        assert!(!is_valid_hostname(".example.com"));
        assert!(!is_valid_hostname("example.com."));
        assert!(!is_valid_hostname("-example.com"));
        assert!(!is_valid_hostname("example-.com"));
        assert!(!is_valid_hostname("exam ple.com"));
        assert!(!is_valid_hostname("exam@ple.com"));
        assert!(!is_valid_hostname("exam_ple.com"));

        // Edge cases that should be valid
        assert!(is_valid_hostname("1.2.3.example.com")); // Numbers are ok in labels
        assert!(is_valid_hostname("xn--example.com")); // Punycode is valid
    }

    #[test]
    fn test_is_valid_did_method_webvh() {
        // Test strict mode - valid cases
        assert!(is_valid_did_method_webvh(
            "did:webvh:abc123:example.com",
            true
        ));
        assert!(is_valid_did_method_webvh(
            "did:webvh:XYZ789:sub.example.com",
            true
        ));
        assert!(is_valid_did_method_webvh(
            "did:webvh:ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz123456789:example.com",
            true
        ));
        assert!(is_valid_did_method_webvh("did:webvh:1:example.com", true)); // single char scim
        assert!(is_valid_did_method_webvh(
            "did:webvh:zzzzzz:localhost",
            true
        ));

        // Test strict mode - invalid cases with path segments
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc123:example.com:path",
            true
        ));
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc123:example.com:path:subpath",
            true
        ));

        // Test non-strict mode - valid cases
        assert!(is_valid_did_method_webvh(
            "did:webvh:abc123:example.com",
            false
        ));
        assert!(is_valid_did_method_webvh(
            "did:webvh:abc123:example.com:path",
            false
        ));
        assert!(is_valid_did_method_webvh(
            "did:webvh:abc123:example.com:path:subpath",
            false
        ));
        assert!(is_valid_did_method_webvh(
            "did:webvh:abc123:example.com:123",
            false
        ));
        assert!(is_valid_did_method_webvh(
            "did:webvh:abc123:example.com:ABC123",
            false
        ));

        // Invalid - wrong prefix
        assert!(!is_valid_did_method_webvh(
            "did:web:abc123:example.com",
            true
        ));
        assert!(!is_valid_did_method_webvh(
            "did:web:abc123:example.com",
            false
        ));
        assert!(!is_valid_did_method_webvh(
            "did:plc:abc123:example.com",
            true
        ));
        assert!(!is_valid_did_method_webvh("webvh:abc123:example.com", true));
        assert!(!is_valid_did_method_webvh("abc123:example.com", true));

        // Invalid - missing scim or content
        assert!(!is_valid_did_method_webvh("did:webvh:", true));
        assert!(!is_valid_did_method_webvh("did:webvh:abc123", true)); // missing content
        assert!(!is_valid_did_method_webvh("did:webvh:abc123:", true)); // empty content
        assert!(!is_valid_did_method_webvh("did:webvh::example.com", true)); // empty scim
        assert!(!is_valid_did_method_webvh("did:webvh:example.com", true)); // no scim separator

        // Invalid - scim contains invalid base58 characters
        assert!(!is_valid_did_method_webvh(
            "did:webvh:0abc:example.com",
            true
        )); // contains 0
        assert!(!is_valid_did_method_webvh(
            "did:webvh:Oabc:example.com",
            true
        )); // contains O
        assert!(!is_valid_did_method_webvh(
            "did:webvh:Iabc:example.com",
            true
        )); // contains I
        assert!(!is_valid_did_method_webvh(
            "did:webvh:labc:example.com",
            true
        )); // contains l
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc-123:example.com",
            true
        )); // contains -
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc_123:example.com",
            true
        )); // contains _
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc.123:example.com",
            true
        )); // contains .
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc@123:example.com",
            true
        )); // contains @
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc 123:example.com",
            true
        )); // contains space
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc!123:example.com",
            true
        )); // contains !
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc#123:example.com",
            true
        )); // contains #
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc$123:example.com",
            true
        )); // contains $

        // Invalid - bad hostname in content
        assert!(!is_valid_did_method_webvh("did:webvh:abc123:", false)); // empty hostname
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc123:..example.com",
            true
        ));
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc123:.example.com",
            true
        ));
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc123:example.com.",
            true
        ));
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc123:-example.com",
            true
        ));
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc123:example.localhost",
            true
        )); // reserved TLD
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc123:192.168.1.1",
            true
        )); // IPv4
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc123:2001:db8::1",
            true
        )); // IPv6

        // Invalid in non-strict mode - empty path segments
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc123:example.com:",
            false
        ));
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc123:example.com::",
            false
        ));
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc123:example.com:path:",
            false
        ));
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc123:example.com::path",
            false
        ));

        // Invalid in non-strict mode - non-alphanumeric in path segments
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc123:example.com:path/subpath",
            false
        ));
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc123:example.com:path-name",
            false
        ));
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc123:example.com:path_name",
            false
        ));
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc123:example.com:path.name",
            false
        ));
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc123:example.com:path@name",
            false
        ));
        assert!(!is_valid_did_method_webvh(
            "did:webvh:abc123:example.com:path name",
            false
        ));

        // Edge cases with base58 characters
        assert!(is_valid_did_method_webvh(
            "did:webvh:111111:example.com",
            true
        )); // all 1s
        assert!(is_valid_did_method_webvh(
            "did:webvh:999999:example.com",
            true
        )); // all 9s
        assert!(is_valid_did_method_webvh(
            "did:webvh:AAAAAA:example.com",
            true
        )); // all As
        assert!(is_valid_did_method_webvh(
            "did:webvh:zzzzzz:example.com",
            true
        )); // all zs
        assert!(is_valid_did_method_webvh(
            "did:webvh:HJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz:example.com",
            true
        )); // no excluded letters
    }

    #[test]
    fn test_is_valid_base58_btc() {
        // Valid base58 strings
        assert!(is_valid_base58_btc("123456789"));
        assert!(is_valid_base58_btc(
            "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz"
        ));
        assert!(is_valid_base58_btc("1"));
        assert!(is_valid_base58_btc("z"));
        assert!(is_valid_base58_btc("ABC123xyz"));

        // Invalid - contains excluded characters
        assert!(!is_valid_base58_btc("0")); // zero
        assert!(!is_valid_base58_btc("O")); // capital O
        assert!(!is_valid_base58_btc("I")); // capital I
        assert!(!is_valid_base58_btc("l")); // lowercase l
        assert!(!is_valid_base58_btc("abc0def"));
        assert!(!is_valid_base58_btc("abcOdef"));
        assert!(!is_valid_base58_btc("abcIdef"));
        assert!(!is_valid_base58_btc("abcldef"));

        // Invalid - contains non-alphanumeric characters
        assert!(!is_valid_base58_btc("abc-def"));
        assert!(!is_valid_base58_btc("abc_def"));
        assert!(!is_valid_base58_btc("abc.def"));
        assert!(!is_valid_base58_btc("abc@def"));
        assert!(!is_valid_base58_btc("abc def"));
        assert!(!is_valid_base58_btc("abc!def"));
        assert!(!is_valid_base58_btc(""));

        // Edge cases
        assert!(is_valid_base58_btc("i")); // lowercase i is allowed
        assert!(is_valid_base58_btc("o")); // lowercase o is allowed
        assert!(is_valid_base58_btc("ioio")); // lowercase i and o are allowed
    }
}
