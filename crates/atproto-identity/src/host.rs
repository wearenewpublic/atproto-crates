//! Method-aware host extraction for `did:web` and `did:webvh`.
//!
//! Both methods encode an HTTPS target inside the DID identifier, but they place
//! the host in different positions: `did:web` puts it first, `did:webvh` puts a
//! self-certifying identifier (SCID) first and the host second. Re-deriving this
//! by hand is how `did:webvh:SCID:host` gets misread as host = SCID, which turns a
//! DID under an attacker's control into a request against an arbitrary target.
//!
//! [`did_host`] is the single supported way to derive a host from these methods.
//! It validates the result: the host is IDNA-normalized, must be a syntactic public
//! DNS name, must never be a network address literal in any resolver-accepted form,
//! and every colon-separated path segment must be free of traversal and URL
//! metacharacters.
//!
//! # Security
//!
//! Validation here is purely syntactic. No DNS resolution is performed, so this does
//! not defend against DNS rebinding, nor against a public name whose address record
//! points into a private range.

use crate::errors::DidHostError;
use crate::validation::{is_ip_literal, is_valid_hostname};

/// DID methods whose identifier encodes a network host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidHostMethod {
    /// `did:web` — the host is the first colon-separated segment.
    Web,
    /// `did:webvh` — the host is the second colon-separated segment, after the SCID.
    WebVH,
}

/// The validated network target extracted from a `did:web` or `did:webvh` DID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidHost {
    /// The method the host was extracted from.
    pub method: DidHostMethod,
    /// The self-certifying identifier; `Some` only for `did:webvh`.
    pub scid: Option<String>,
    /// IDNA-normalized, lowercased ASCII hostname. Never an address literal.
    pub host: String,
    /// Port decoded from a `%3A`-escaped authority, when present.
    pub port: Option<u16>,
    /// Remaining colon-separated segments, to be used as URL path segments.
    pub path_segments: Vec<String>,
}

impl DidHost {
    /// Renders `host` or `host:port` for use as a URL authority.
    pub fn authority(&self) -> String {
        match self.port {
            Some(port) => format!("{}:{}", self.host, port),
            None => self.host.clone(),
        }
    }

    /// Builds the HTTPS document URL for `file`.
    ///
    /// With no path segments this is `https://{authority}/.well-known/{file}`,
    /// otherwise `https://{authority}/{segments…}/{file}`.
    pub fn document_url(&self, file: &str) -> String {
        if self.path_segments.is_empty() {
            format!("https://{}/.well-known/{}", self.authority(), file)
        } else {
            format!(
                "https://{}/{}/{}",
                self.authority(),
                self.path_segments.join("/"),
                file
            )
        }
    }
}

/// Extracts and validates the HTTPS target encoded in a `did:web` or `did:webvh` DID.
///
/// `did:web` places the host in the first segment after the method prefix;
/// `did:webvh` places a SCID first and the host second. Use this rather than
/// splitting the DID yourself — reusing `did:web` parsing on a `did:webvh` string
/// yields the SCID as the host.
///
/// The authority may carry a `%3A`-escaped port, which is decoded and range-checked.
/// Any other percent-escape is rejected so that path or authority smuggling cannot
/// survive into the constructed URL.
///
/// # Arguments
///
/// * `did` - The `did:web` or `did:webvh` DID to inspect
///
/// # Returns
///
/// The validated [`DidHost`], or the [`DidHostError`] describing the first rule violated.
///
/// # Security
///
/// The returned host is guaranteed to be a syntactic public DNS name and never an
/// address literal — including the `inet_aton` decimal, octal, and hexadecimal
/// forms that resolvers normalize back into an address. DNS-level protection
/// (rebinding, a public name resolving into a private range) is explicitly not
/// provided.
///
/// # Examples
///
/// ```
/// use atproto_identity::host::{did_host, DidHostMethod};
///
/// let target = did_host("did:web:example.com:path").unwrap();
/// assert_eq!(target.method, DidHostMethod::Web);
/// assert_eq!(target.host, "example.com");
/// assert_eq!(target.path_segments, vec!["path".to_string()]);
///
/// let target = did_host("did:webvh:z6MkScid:example.com").unwrap();
/// assert_eq!(target.scid.as_deref(), Some("z6MkScid"));
/// assert_eq!(target.host, "example.com");
///
/// // Address literals never produce a URL.
/// assert!(did_host("did:web:2852039166").is_err());
/// ```
pub fn did_host(did: &str) -> Result<DidHost, DidHostError> {
    let (method, remainder) = if let Some(rest) = did.strip_prefix("did:webvh:") {
        (DidHostMethod::WebVH, rest)
    } else if let Some(rest) = did.strip_prefix("did:web:") {
        (DidHostMethod::Web, rest)
    } else {
        return Err(DidHostError::UnsupportedMethod {
            did: did.to_string(),
        });
    };

    let parts: Vec<&str> = remainder.split(':').collect();

    let (scid, host_token, path) = match method {
        DidHostMethod::Web => (None, parts[0], &parts[1..]),
        DidHostMethod::WebVH => {
            if parts.len() < 2 || parts[0].is_empty() {
                return Err(DidHostError::MissingScid {
                    did: did.to_string(),
                });
            }
            (Some(parts[0].to_string()), parts[1], &parts[2..])
        }
    };

    if host_token.is_empty() {
        return Err(DidHostError::MissingHostname {
            did: did.to_string(),
        });
    }

    let (host, port) = parse_authority(host_token)?;
    let path_segments = validate_path_segments(path)?;

    Ok(DidHost {
        method,
        scid,
        host,
        port,
        path_segments,
    })
}

/// Decodes and validates the authority token of a DID into a host and optional port.
fn parse_authority(token: &str) -> Result<(String, Option<u16>), DidHostError> {
    // Only the port separator may be percent-encoded. Anything else is an attempt to
    // smuggle path, query, fragment, or userinfo characters into the authority.
    let decoded = token.replace("%3A", ":").replace("%3a", ":");
    if decoded.contains('%') {
        return Err(DidHostError::InvalidHostname {
            host: token.to_string(),
        });
    }

    let mut authority = decoded.split(':');
    let host_part = authority.next().unwrap_or_default();
    let port_part = authority.next();
    if authority.next().is_some() {
        return Err(DidHostError::InvalidHostname { host: decoded });
    }

    let port = match port_part {
        Some(raw) => Some(parse_port(raw)?),
        None => None,
    };

    if host_part.is_empty() {
        return Err(DidHostError::InvalidHostname { host: decoded });
    }

    let ascii = idna::domain_to_ascii(host_part)
        .map_err(|_| DidHostError::IdnaFailed {
            host: host_part.to_string(),
        })?
        .to_ascii_lowercase();

    if is_ip_literal(&ascii) {
        return Err(DidHostError::IpLiteralHost { host: ascii });
    }

    if !is_valid_hostname(&ascii) {
        return Err(DidHostError::InvalidHostname { host: ascii });
    }

    // Second gate: WHATWG URL parsing normalizes every remaining address form
    // (integer, hex, octal, short) back into a Host::Ipv4 or Host::Ipv6.
    let probe = format!("https://{}/", ascii);
    match url::Url::parse(&probe).ok().and_then(|url| {
        url.host().map(|host| match host {
            url::Host::Domain(domain) => Some(domain.to_string()),
            _ => None,
        })
    }) {
        Some(Some(domain)) if domain == ascii => {}
        Some(None) => return Err(DidHostError::IpLiteralHost { host: ascii }),
        _ => return Err(DidHostError::InvalidHostname { host: ascii }),
    }

    Ok((ascii, port))
}

/// Validates the port text of a percent-decoded authority.
fn parse_port(raw: &str) -> Result<u16, DidHostError> {
    let invalid = || DidHostError::InvalidPort {
        port: raw.to_string(),
    };

    if raw.is_empty() || raw.len() > 5 || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    if raw.len() > 1 && raw.starts_with('0') {
        return Err(invalid());
    }

    let port: u16 = raw.parse().map_err(|_| invalid())?;
    if port == 0 {
        return Err(invalid());
    }

    Ok(port)
}

/// Validates the colon-separated path segments of a DID.
fn validate_path_segments(segments: &[&str]) -> Result<Vec<String>, DidHostError> {
    segments
        .iter()
        .map(|segment| {
            let safe = !segment.is_empty()
                && *segment != "."
                && *segment != ".."
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));

            if safe {
                Ok((*segment).to_string())
            } else {
                Err(DidHostError::InvalidPathSegment {
                    segment: (*segment).to_string(),
                })
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_host_web_extracts_first_segment() {
        let target = did_host("did:web:example.com:path:sub").unwrap();
        assert_eq!(target.method, DidHostMethod::Web);
        assert_eq!(target.scid, None);
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, None);
        assert_eq!(target.path_segments, vec!["path", "sub"]);
        assert_eq!(
            target.document_url("did.json"),
            "https://example.com/path/sub/did.json"
        );
    }

    #[test]
    fn test_did_host_webvh_skips_scid() {
        // The exact SCID-vs-host footgun: the host is the SECOND segment.
        let target = did_host("did:webvh:z6MkFakeScid:example.com:dids:issuer").unwrap();
        assert_eq!(target.method, DidHostMethod::WebVH);
        assert_eq!(target.scid.as_deref(), Some("z6MkFakeScid"));
        assert_eq!(target.host, "example.com");
        assert_eq!(target.path_segments, vec!["dids", "issuer"]);
    }

    #[test]
    fn test_did_host_rejects_address_literals() {
        for did in [
            "did:web:2852039166",
            "did:web:169.254.169.254",
            "did:web:0xA9FEA9FE",
            "did:web:0250.0376.0250.0376",
            "did:web:169.254.43518",
            "did:web:017700000001",
            "did:webvh:z6MkFakeScid:2852039166",
            "did:webvh:z6MkFakeScid:169.254.43518",
            "did:webvh:z6MkFakeScid:0xA9FEA9FE",
        ] {
            let result = did_host(did);
            assert!(
                matches!(result, Err(DidHostError::IpLiteralHost { .. })),
                "expected IpLiteralHost for {did}, got {result:?}"
            );
        }
    }

    #[test]
    fn test_did_host_rejects_ipv6_literals() {
        // Bare IPv6 in a DID splits on colons, so it never reaches the host check
        // intact; assert only that no URL is produced.
        for did in ["did:web:[::1]", "did:web:[2001:db8::1]", "did:web:::1"] {
            assert!(did_host(did).is_err(), "expected error for {did}");
        }
    }

    #[test]
    fn test_did_host_decodes_percent_encoded_port() {
        let target = did_host("did:web:example.com%3A3000").unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, Some(3000));
        assert_eq!(target.authority(), "example.com:3000");

        let target = did_host("did:webvh:abc123:example.com%3a8080").unwrap();
        assert_eq!(target.port, Some(8080));

        for did in [
            "did:web:example.com%3A0",
            "did:web:example.com%3A99999",
            "did:web:example.com%3Aabc",
            "did:web:example.com%3A00443",
            "did:web:example.com%3A",
        ] {
            assert!(
                matches!(did_host(did), Err(DidHostError::InvalidPort { .. })),
                "expected InvalidPort for {did}"
            );
        }
    }

    #[test]
    fn test_did_host_rejects_smuggled_authority() {
        for did in [
            "did:web:user@evil.example.com",
            "did:web:example.com%2f..%2fx",
            "did:web:example.com?x=1",
            "did:web:example.com#frag",
            "did:web:example.com%3A80%3A443",
            "did:web:example.com%00",
        ] {
            assert!(did_host(did).is_err(), "expected error for {did}");
        }
    }

    #[test]
    fn test_did_host_rejects_traversal_path_segments() {
        for did in [
            "did:web:example.com:..:..:etc",
            "did:web:example.com:.",
            "did:web:example.com:a/b",
            "did:web:example.com:a?b",
        ] {
            assert!(
                matches!(did_host(did), Err(DidHostError::InvalidPathSegment { .. })),
                "expected InvalidPathSegment for {did}"
            );
        }
    }

    #[test]
    fn test_did_host_missing_components() {
        assert!(matches!(
            did_host("did:web:"),
            Err(DidHostError::MissingHostname { .. })
        ));
        assert!(matches!(
            did_host("did:webvh:"),
            Err(DidHostError::MissingScid { .. })
        ));
        assert!(matches!(
            did_host("did:webvh:abc123"),
            Err(DidHostError::MissingScid { .. })
        ));
        assert!(matches!(
            did_host("did:webvh:abc123:"),
            Err(DidHostError::MissingHostname { .. })
        ));
        assert!(matches!(
            did_host("did:plc:abcdefghijklmnopqrstuvwx"),
            Err(DidHostError::UnsupportedMethod { .. })
        ));
    }

    #[test]
    fn test_did_host_reserved_tlds_rejected() {
        for did in [
            "did:web:metadata.google.internal",
            "did:web:svc.localhost",
            "did:web:printer.local",
        ] {
            assert!(
                matches!(did_host(did), Err(DidHostError::InvalidHostname { .. })),
                "expected InvalidHostname for {did}"
            );
        }

        // Bare "localhost" stays valid: single non-numeric label, no reserved suffix.
        assert_eq!(did_host("did:web:localhost").unwrap().host, "localhost");
    }

    #[test]
    fn test_did_host_reserved_tlds_rejected_in_any_case() {
        // The uppercased spellings reach the identical target, so they must be
        // rejected identically.
        for did in [
            "did:web:metadata.google.INTERNAL",
            "did:web:metadata.google.Internal",
            "did:web:svc.LOCALHOST",
            "did:web:printer.LOCAL",
            "did:web:target.ARPA",
            "did:webvh:z6MkFakeScid:metadata.google.INTERNAL",
            "did:webvh:z6MkFakeScid:x.LOCALHOST",
        ] {
            assert!(
                matches!(did_host(did), Err(DidHostError::InvalidHostname { .. })),
                "expected InvalidHostname for {did}"
            );
        }
    }

    #[test]
    fn test_did_host_lowercases_and_idna_normalizes() {
        assert_eq!(did_host("did:web:EXAMPLE.COM").unwrap().host, "example.com");
        assert_eq!(
            did_host("did:web:bücher.example").unwrap().host,
            "xn--bcher-kva.example"
        );
    }

    #[test]
    fn test_did_host_error_message_format() {
        let error = did_host("did:web:2852039166").unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("error-atproto-identity-host-4 "),
            "unexpected message: {error}"
        );
    }
}
