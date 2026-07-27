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
//! - [`is_ip_literal`] - Detects every numeric address form a resolver accepts
//! - [`is_ipv4`] - IPv4 address validation
//! - [`is_ipv6`] - IPv6 address validation
//!
//! ## Endpoint Validation
//! - [`validate_service_endpoint`] - Strict, SSRF-resistant service endpoint URL policy
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

use crate::errors::EndpointError;

/// Maximum length for a valid hostname as defined in RFC 1035
const MAX_HOSTNAME_LENGTH: usize = 253;

/// Maximum length for a DNS label (component between dots) as defined in RFC 1035
const MAX_LABEL_LENGTH: usize = 63;

/// List of reserved top-level domains that are not valid for AT Protocol handles
const RESERVED_TLDS: [&str; 4] = [".localhost", ".internal", ".arpa", ".local"];

/// Returns `true` when the label is non-empty and composed entirely of ASCII digits.
fn is_all_digits(label: &str) -> bool {
    !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_digit())
}

/// Returns `true` when the label is a `0x`/`0X`-prefixed hexadecimal integer literal.
///
/// A bare `0x` with no digits counts: `inet_aton` and the `url` crate both parse it as
/// zero, so requiring a non-empty body would let `0x7f.0x.0x.0x1` through as a DNS name
/// even though it resolves to `127.0.0.1`.
fn is_hex_literal(label: &str) -> bool {
    let rest = label
        .strip_prefix("0x")
        .or_else(|| label.strip_prefix("0X"));
    matches!(rest, Some(rest) if rest.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

/// Returns `true` when the `url` crate normalizes `hostname` into a network address.
///
/// The rules in [`is_ip_literal`] enumerate the address forms explicitly. This defers to
/// the parser `reqwest` actually uses, so a host that normalizes into an address is
/// caught even when its form is not enumerated above.
///
/// A host the parser rejects outright is not an address, and `reqwest` cannot issue a
/// request for it either, so the verdict is left to the syntactic rules. Treating a parse
/// failure as an address would newly reject malformed-but-harmless punycode such as
/// `xn--example.com`.
fn url_parses_as_address(hostname: &str) -> bool {
    match url::Url::parse(&format!("https://{hostname}/")) {
        Ok(parsed) => !matches!(parsed.host(), Some(url::Host::Domain(_))),
        Err(_) => false,
    }
}

/// Checks whether a host string denotes a numeric network address rather than a DNS name.
///
/// Covers dotted-quad IPv4, IPv6 (bracketed or bare), and the `inet_aton` integer
/// forms that C resolvers, browsers, and most HTTP clients normalize back into an
/// address: 32-bit decimal (`2852039166`), hexadecimal (`0xA9FEA9FE`), octal
/// (`0250.0376.0250.0376`), and the short forms (`1.2.3`, `169.254.43518`).
///
/// # Arguments
///
/// * `host` - The host string to classify
///
/// # Returns
///
/// `true` if the host is a network address literal in any recognized form
///
/// # Examples
///
/// ```
/// use atproto_identity::validation::is_ip_literal;
///
/// assert!(is_ip_literal("169.254.169.254"));
/// assert!(is_ip_literal("2852039166")); // decimal form of 169.254.169.254
/// assert!(is_ip_literal("0xA9FEA9FE")); // hexadecimal form
/// assert!(is_ip_literal("[::1]"));
///
/// assert!(!is_ip_literal("example.com"));
/// assert!(!is_ip_literal("123.example.com"));
/// ```
pub fn is_ip_literal(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }

    if is_ipv4(host) || is_ipv6(host) {
        return true;
    }

    // Every label being an integer literal (decimal, octal, or hexadecimal)
    // means a resolver will treat the whole string as an address.
    host.split('.')
        .all(|label| is_all_digits(label) || is_hex_literal(label))
}

/// Validates if a string is a valid hostname according to RFC 1035.
///
/// Validation is case-insensitive: the name is ASCII-lowercased before any rule runs,
/// because DNS and HTTP host matching are case-insensitive and an uppercased suffix
/// would otherwise slip past the reserved-TLD and address-literal rules.
///
/// A valid hostname must:
/// - Be between 1 and 253 characters in length
/// - Not use reserved top-level domains (.localhost, .internal, .arpa, .local),
///   in any letter case
/// - Not be a network address literal in any form accepted by resolvers — dotted-quad
///   IPv4, IPv6, or the `inet_aton` decimal/octal/hexadecimal integer forms (see
///   [`is_ip_literal`])
/// - Not have an entirely numeric rightmost label (RFC 1123 section 2.1)
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
/// assert!(is_valid_hostname("123.example.com"));
///
/// // Invalid hostnames
/// assert!(!is_valid_hostname("192.168.1.1")); // IPv4 address
/// assert!(!is_valid_hostname("2852039166")); // Integer form of 169.254.169.254
/// assert!(!is_valid_hostname("0xA9FEA9FE")); // Hexadecimal form of 169.254.169.254
/// assert!(!is_valid_hostname("example.localhost")); // Reserved TLD
/// assert!(!is_valid_hostname("example.LOCALHOST")); // Reserved TLD, uppercased
/// assert!(!is_valid_hostname("metadata.google.INTERNAL")); // Reserved TLD, uppercased
/// assert!(!is_valid_hostname("example..com")); // Double dot
/// assert!(!is_valid_hostname("-example.com")); // Leading hyphen
/// ```
pub fn is_valid_hostname(hostname: &str) -> bool {
    // Empty hostnames are invalid
    if hostname.is_empty() || hostname.len() > MAX_HOSTNAME_LENGTH {
        return false;
    }

    // DNS lookups and HTTP host matching are case-insensitive, so every rule below has
    // to run against a case-normalized name. Comparing the raw input would let
    // `metadata.google.INTERNAL` through while blocking `metadata.google.internal`,
    // even though both reach the identical target.
    let normalized = hostname.to_ascii_lowercase();
    let hostname = normalized.as_str();

    // Check if hostname uses any reserved TLDs
    if RESERVED_TLDS.iter().any(|tld| hostname.ends_with(tld)) {
        return false;
    }

    // Reject IPv4, IPv6, and the inet_aton integer/octal/hexadecimal address forms
    if is_ip_literal(hostname) {
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

    // RFC 1123 section 2.1: the rightmost label must not be entirely numeric,
    // otherwise the name is ambiguous with an address literal.
    if hostname.rsplit('.').next().is_some_and(is_all_digits) {
        return false;
    }

    // Authoritative backstop. Everything above is a hand-rolled model of what a resolver
    // does; this asks the parser that `reqwest` will actually use. Without it, any
    // address form the model fails to anticipate becomes an SSRF vector, because a
    // hostname that passes here is interpolated straight into a request URL by
    // `resolve_handle_http`.
    if url_parses_as_address(hostname) {
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
/// The returned handle is ASCII-lowercased. AT Protocol handles are case-insensitive
/// and canonically lowercase, and normalizing here means callers that interpolate the
/// result into a DNS query name or an HTTPS URL cannot be handed a case variant that
/// slipped past a case-sensitive rule.
///
/// # Arguments
///
/// * `handle` - The handle string to validate and normalize
///
/// # Returns
///
/// `Some(String)` containing the lowercased handle if valid, `None` if invalid
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
/// // Normalized to lowercase
/// assert_eq!(is_valid_handle("Alice.BSKY.social"), Some("alice.bsky.social".to_string()));
///
/// // Invalid handles
/// assert_eq!(is_valid_handle("localhost"), None); // No period
/// assert_eq!(is_valid_handle("192.168.1.1"), None); // IPv4 address
/// assert_eq!(is_valid_handle("invalid..handle.com"), None); // Double dot
/// assert_eq!(is_valid_handle("metadata.google.INTERNAL"), None); // Reserved TLD, uppercased
/// ```
pub fn is_valid_handle(handle: &str) -> Option<String> {
    // Strip optional prefixes to get the core handle
    let trimmed = strip_handle_prefixes(handle);

    // A valid handle must be a valid hostname with at least one period
    if is_valid_hostname(trimmed) && trimmed.contains('.') {
        Some(trimmed.to_ascii_lowercase())
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

/// Validates an AT Protocol service endpoint URL against a strict, SSRF-resistant
/// syntactic policy.
///
/// Service endpoints come out of DID documents, which are published by the DID
/// subject. They are attacker-controlled input whenever the subject is not you.
/// This function is the syntactic gate to apply before handing such a URL to an
/// HTTP client.
///
/// Accepts only:
/// - the `https` scheme,
/// - a host that parses as a DNS domain and is never an IPv4/IPv6/integer address
///   literal (see [`is_ip_literal`]),
/// - a hostname that passes [`is_valid_hostname`], which also excludes the reserved
///   `.localhost`, `.internal`, `.arpa` and `.local` suffixes,
/// - no embedded userinfo (`https://user:pw@host`),
/// - no explicit port other than 443,
/// - no query string and no fragment.
///
/// A path is permitted.
///
/// # Security
///
/// No DNS resolution is performed, so this does **not** defend against DNS
/// rebinding, nor against a public name whose A record points at a private
/// address. It is a syntactic layer of defense, not a complete SSRF control.
///
/// # Arguments
///
/// * `endpoint` - The service endpoint URL to validate
///
/// # Returns
///
/// `Ok(())` when the endpoint satisfies the policy, otherwise the [`EndpointError`]
/// describing the first rule violated.
///
/// # Examples
///
/// ```
/// use atproto_identity::validation::validate_service_endpoint;
///
/// assert!(validate_service_endpoint("https://pds.example.com").is_ok());
/// assert!(validate_service_endpoint("https://pds.example.com:443/xrpc").is_ok());
///
/// assert!(validate_service_endpoint("http://169.254.169.254").is_err());
/// assert!(validate_service_endpoint("https://2852039166").is_err());
/// assert!(validate_service_endpoint("https://user:pw@evil.example.com").is_err());
/// ```
pub fn validate_service_endpoint(endpoint: &str) -> Result<(), EndpointError> {
    let parsed = url::Url::parse(endpoint).map_err(|error| EndpointError::NotAbsoluteUrl {
        endpoint: endpoint.to_string(),
        details: error.to_string(),
    })?;

    if parsed.scheme() != "https" {
        return Err(EndpointError::InvalidScheme {
            scheme: parsed.scheme().to_string(),
        });
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(EndpointError::EmbeddedCredentials {
            endpoint: endpoint.to_string(),
        });
    }

    let host = parsed.host().ok_or_else(|| EndpointError::MissingHost {
        endpoint: endpoint.to_string(),
    })?;

    let domain = match host {
        url::Host::Domain(domain) => domain.to_string(),
        other => {
            return Err(EndpointError::IpLiteralHost {
                host: other.to_string(),
            });
        }
    };

    if is_ip_literal(&domain) {
        return Err(EndpointError::IpLiteralHost { host: domain });
    }

    if !is_valid_hostname(&domain) {
        return Err(EndpointError::InvalidHostname { host: domain });
    }

    if let Some(port) = parsed.port()
        && port != 443
    {
        return Err(EndpointError::NonDefaultPort { port });
    }

    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(EndpointError::QueryOrFragment {
            endpoint: endpoint.to_string(),
        });
    }

    Ok(())
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
    fn test_is_valid_hostname_rejects_integer_address_forms() {
        // 2852039166 == 0xA9FEA9FE == 169.254.169.254, the cloud metadata endpoint.
        for host in [
            "2852039166",
            "0xA9FEA9FE",
            "0xa9fea9fe",
            "0250.0376.0250.0376",
            "1.2.3",
            "169.254.43518",
            "0x7f.1",
            "017700000001",
            "0xa9.0xfe.0xa9.0xfe",
            "example.123",
            "169.254.169.254",
            // Case variants: DNS and HTTP host matching are case-insensitive, so an
            // uppercased reserved suffix reaches the exact same target.
            "metadata.google.INTERNAL",
            "metadata.google.Internal",
            "x.LOCALHOST",
            "y.LOCAL",
            "z.ARPA",
            "EXAMPLE.LocalHost",
            "0XA9FEA9FE",
        ] {
            assert!(
                !is_valid_hostname(host),
                "{host} must not be a valid hostname"
            );
        }
    }

    #[test]
    fn test_is_valid_hostname_rejects_empty_hex_address_labels() {
        // A bare `0x` label parses as zero, so these are address literals even though
        // every label is not obviously numeric. `is_hex_literal` used to require a
        // non-empty body, which let all of these through as DNS names while `url` and
        // `reqwest` resolved them to loopback and RFC 1918 targets.
        for (host, resolves_to) in [
            ("0x7f.0x.0x.0x1", "127.0.0.1"),
            ("0xa.0x.0x.0x1", "10.0.0.1"),
            ("0xc0.0xa8.0x.0x1", "192.168.0.1"),
            ("0x.0x.0x.0x", "0.0.0.0"),
            ("0X7F.0X.0X.0X1", "127.0.0.1"),
        ] {
            assert!(
                is_ip_literal(host),
                "{host} is an address literal for {resolves_to}"
            );
            assert!(
                !is_valid_hostname(host),
                "{host} must not be a valid hostname; it reaches {resolves_to}"
            );
            assert!(
                is_valid_handle(host).is_none(),
                "{host} must not be a valid handle; it reaches {resolves_to}"
            );
        }
    }

    #[test]
    fn test_is_valid_hostname_defers_to_the_url_parser() {
        // The backstop must agree with the parser reqwest uses: anything that parses as
        // an address rather than a domain is rejected, and ordinary names still pass.
        for host in [
            "example.com",
            "sub.example.com",
            "localhost",
            "3lab.example.com",
        ] {
            assert!(!url_parses_as_address(host), "{host} is a DNS name");
            assert!(is_valid_hostname(host), "{host} must remain valid");
        }
        for host in ["0x7f.0x.0x.0x1", "127.0.0.1", "2852039166"] {
            assert!(url_parses_as_address(host), "{host} parses as an address");
        }
        // A host the parser cannot handle is not an address, so the syntactic rules
        // decide and malformed punycode keeps its previous verdict.
        assert!(!url_parses_as_address("xn--example.com"));
        assert!(is_valid_hostname("xn--example.com"));
    }

    #[test]
    fn test_is_valid_hostname_reserved_tlds_are_case_insensitive() {
        for host in [
            "metadata.google.INTERNAL",
            "metadata.google.Internal",
            "metadata.google.internal",
            "victim.LOCALHOST",
            "printer.LOCAL",
            "target.ARPA",
        ] {
            assert!(
                !is_valid_hostname(host),
                "{host} must be rejected regardless of letter case"
            );
        }
    }

    #[test]
    fn test_is_valid_handle_rejects_uppercased_reserved_tlds() {
        // Confirmed bypass payloads: the lowercase forms were blocked but the
        // uppercased spellings reached _atproto.metadata.google.INTERNAL and
        // https://metadata.google.INTERNAL/.well-known/atproto-did.
        for handle in [
            "metadata.google.INTERNAL",
            "metadata.google.Internal",
            "victim.LOCALHOST",
            "printer.LOCAL",
            "target.ARPA",
            "x.LOCALHOST",
            "y.LOCAL",
            "z.ARPA",
        ] {
            assert_eq!(is_valid_handle(handle), None, "{handle} must be rejected");
        }
    }

    #[test]
    fn test_is_valid_handle_normalizes_case() {
        assert_eq!(
            is_valid_handle("Alice.BSKY.Social"),
            Some("alice.bsky.social".to_string())
        );
        assert_eq!(
            is_valid_handle("@BOB.EXAMPLE.COM"),
            Some("bob.example.com".to_string())
        );
        assert_eq!(
            is_valid_handle("at://Charlie.Test.Com"),
            Some("charlie.test.com".to_string())
        );
    }

    #[test]
    fn test_is_valid_did_method_web_reserved_tlds_case_insensitive() {
        for did in [
            "did:web:metadata.google.INTERNAL",
            "did:web:svc.LOCALHOST",
            "did:web:printer.LOCAL",
            "did:web:target.ARPA",
        ] {
            assert!(
                !is_valid_did_method_web(did, true),
                "{did} must be rejected"
            );
            assert!(
                !is_valid_did_method_web(did, false),
                "{did} must be rejected"
            );
        }
    }

    #[test]
    fn test_is_valid_hostname_still_accepts_dns_names() {
        for host in [
            "example.com",
            "sub.example.com",
            "localhost",
            "123.example.com",
            "1.2.3.example.com",
            "a.b.c.d.example.com",
            "xn--example.com",
            "test-host.example.com",
            "pds.cauda.cloud",
            // Case variants of ordinary names stay valid.
            "EXAMPLE.COM",
            "Pds.Example.Com",
        ] {
            assert!(
                is_valid_hostname(host),
                "{host} must remain a valid hostname"
            );
        }
    }

    #[test]
    fn test_is_ip_literal() {
        for host in [
            "169.254.169.254",
            "127.0.0.1",
            "0.0.0.0",
            "2001:db8::1",
            "::1",
            "[2001:db8::1]",
            "[::1]",
            "2852039166",
            "0xA9FEA9FE",
            "0250.0376.0250.0376",
            "1.2.3",
            "169.254.43518",
            "0x7f.1",
            "017700000001",
        ] {
            assert!(is_ip_literal(host), "{host} must be an address literal");
        }

        for host in [
            "example.com",
            "localhost",
            "123.example.com",
            "xn--example.com",
            "",
            "0xdead.com",
        ] {
            assert!(
                !is_ip_literal(host),
                "{host} must not be an address literal"
            );
        }
    }

    #[test]
    fn test_is_valid_handle_rejects_address_form_handles() {
        // Confirmed handle-resolution SSRF payloads.
        assert_eq!(is_valid_handle("169.254.43518"), None);
        assert_eq!(is_valid_handle("1.2.3"), None);
        assert_eq!(is_valid_handle("169.254.169.254"), None);
        assert_eq!(is_valid_handle("0250.0376.0250.0376"), None);

        assert_eq!(
            is_valid_handle("alice.bsky.social"),
            Some("alice.bsky.social".to_string())
        );
        assert_eq!(
            is_valid_handle("@bob.example.com"),
            Some("bob.example.com".to_string())
        );
    }

    #[test]
    fn test_validate_service_endpoint_rejects_ssrf_payloads() {
        for endpoint in [
            "http://169.254.169.254",
            "https://169.254.169.254",
            "https://2852039166",
            "https://0xA9FEA9FE",
            "https://169.254.43518",
            "https://0x7f.1",
            "https://017700000001",
            "https://[::1]",
            "https://user:pw@evil.example.com",
            "https://pds.example.com:6379",
            "https://pds.example.com/?x=1",
            "https://pds.example.com#frag",
            "https://metadata.google.internal",
            "https://exam_ple.com",
            "file:///etc/passwd",
            "not-a-url",
            "/relative/path",
        ] {
            assert!(
                validate_service_endpoint(endpoint).is_err(),
                "{endpoint} must be rejected"
            );
        }

        for endpoint in [
            "https://pds.example.com",
            "https://pds.example.com:443/xrpc",
            "https://pds.cauda.cloud",
            "https://pds.example.com/some/path",
        ] {
            assert!(
                validate_service_endpoint(endpoint).is_ok(),
                "{endpoint} must be accepted: {:?}",
                validate_service_endpoint(endpoint).unwrap_err()
            );
        }
    }

    #[test]
    fn test_validate_service_endpoint_error_message_format() {
        let error = validate_service_endpoint("https://2852039166").unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("error-atproto-identity-endpoint-4 "),
            "unexpected message: {error}"
        );

        let error = validate_service_endpoint("http://pds.example.com").unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("error-atproto-identity-endpoint-2 "),
            "unexpected message: {error}"
        );
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
