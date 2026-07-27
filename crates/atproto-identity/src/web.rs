//! Web DID client for did:web resolution.
//!
//! Resolves did:web identifiers by converting them to HTTPS URLs and fetching
//! DID documents from well-known locations on web servers.
//! - **`query_hostname()`**: Direct document retrieval from hostname well-known endpoints
//!
//! ## URL Conversion
//!
//! Transforms DIDs like `did:web:example.com:path:subpath` into HTTPS URLs following
//! the did:web specification for well-known document locations.

use tracing::instrument;

use super::errors::{DidHostError, WebDIDError};
use super::model::Document;
use crate::host::did_host;
use crate::validation::{is_ip_literal, is_valid_hostname};

/// Converts a did:web DID to its corresponding HTTPS URL.
///
/// Transforms DID format to the expected well-known document location:
/// - `did:web:example.com` → `https://example.com/.well-known/did.json`
/// - `did:web:example.com:path:sub` → `https://example.com/path/sub/did.json`
/// - `did:web:example.com%3A3000` → `https://example.com:3000/.well-known/did.json`
///
/// # Security
///
/// The host of the returned URL is validated by [`crate::host::did_host`]: it is a
/// syntactic public DNS name and never a network address literal, so an
/// attacker-supplied DID cannot direct a fetch at `169.254.169.254` or any of its
/// decimal, octal, or hexadecimal spellings. DNS-level protection (rebinding, a
/// public name resolving into a private range) is explicitly not provided.
pub fn did_web_to_url(did: &str) -> Result<String, WebDIDError> {
    if !did.starts_with("did:web:") {
        return Err(WebDIDError::InvalidDIDPrefix);
    }

    let target = did_host(did).map_err(|source| match source {
        DidHostError::MissingHostname { .. } => WebDIDError::MissingHostname,
        other => WebDIDError::InvalidHost { source: other },
    })?;

    Ok(target.document_url("did.json"))
}

/// Queries a did:web DID document from its hosting location.
/// Resolves the DID to HTTPS URL and fetches the JSON document.
#[instrument(skip(http_client), err)]
pub async fn query(http_client: &reqwest::Client, did: &str) -> Result<Document, WebDIDError> {
    let url = did_web_to_url(did)?;

    http_client
        .get(&url)
        .send()
        .await
        .map_err(|error| WebDIDError::HttpRequestFailed {
            url: url.clone(),
            error,
        })?
        .json::<Document>()
        .await
        .map_err(|error| WebDIDError::DocumentParseFailed { url, error })
}

/// Queries a DID document directly from a hostname's well-known location.
///
/// Fetches from `https://{hostname}/.well-known/did.json`.
///
/// # Security
///
/// `hostname` is validated with [`crate::validation::is_valid_hostname`] before the
/// URL is built, so address literals and hosts carrying URL metacharacters are
/// rejected instead of being interpolated into a request target. The host is
/// ASCII-lowercased first, because DNS and HTTP host matching are case-insensitive and
/// an uppercased spelling such as `metadata.google.INTERNAL` must not reach a target
/// the lowercase form is blocked from.
#[instrument(skip(http_client), err)]
pub async fn query_hostname(
    http_client: &reqwest::Client,
    hostname: &str,
) -> Result<Document, WebDIDError> {
    let hostname = hostname.to_ascii_lowercase();
    let hostname = hostname.as_str();

    if is_ip_literal(hostname) {
        return Err(WebDIDError::InvalidHost {
            source: DidHostError::IpLiteralHost {
                host: hostname.to_string(),
            },
        });
    }
    if !is_valid_hostname(hostname) {
        return Err(WebDIDError::InvalidHost {
            source: DidHostError::InvalidHostname {
                host: hostname.to_string(),
            },
        });
    }

    let url = format!("https://{}/.well-known/did.json", hostname);

    http_client
        .get(&url)
        .send()
        .await
        .map_err(|error| WebDIDError::HttpRequestFailed {
            url: url.clone(),
            error,
        })?
        .json::<Document>()
        .await
        .map_err(|error| WebDIDError::DocumentParseFailed { url, error })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_web_to_url_simple_hostname() {
        let result = did_web_to_url("did:web:example.com");
        assert_eq!(result.unwrap(), "https://example.com/.well-known/did.json");
    }

    #[test]
    fn test_did_web_to_url_with_path() {
        let result = did_web_to_url("did:web:example.com:path");
        assert_eq!(result.unwrap(), "https://example.com/path/did.json");
    }

    #[test]
    fn test_did_web_to_url_with_nested_path() {
        let result = did_web_to_url("did:web:example.com:path:subpath");
        assert_eq!(result.unwrap(), "https://example.com/path/subpath/did.json");
    }

    #[test]
    fn test_did_web_to_url_invalid_prefix() {
        let result = did_web_to_url("did:plc:example.com");
        assert!(matches!(result, Err(WebDIDError::InvalidDIDPrefix)));
    }

    #[test]
    fn test_did_web_to_url_missing_hostname() {
        let result = did_web_to_url("did:web:");
        assert!(matches!(result, Err(WebDIDError::MissingHostname)));
    }

    #[test]
    fn test_did_web_to_url_no_prefix() {
        let result = did_web_to_url("example.com");
        assert!(matches!(result, Err(WebDIDError::InvalidDIDPrefix)));
    }

    #[test]
    fn test_did_web_to_url_rejects_metadata_endpoint() {
        // 2852039166 == 0xA9FEA9FE == 169.254.169.254, the cloud metadata endpoint.
        for did in [
            "did:web:2852039166",
            "did:web:169.254.169.254",
            "did:web:0xA9FEA9FE",
            "did:web:169.254.43518",
            "did:web:0250.0376.0250.0376",
            "did:web:017700000001",
            "did:web:0x7f.1",
        ] {
            let result = did_web_to_url(did);
            assert!(
                matches!(result, Err(WebDIDError::InvalidHost { .. })),
                "expected InvalidHost for {did}, got {result:?}"
            );
            let message = result.unwrap_err().to_string();
            assert!(
                message.starts_with("error-atproto-identity-web-5 "),
                "unexpected message: {message}"
            );
        }
    }

    #[test]
    fn test_did_web_to_url_scid_shaped_input_never_targets_the_address() {
        // A literal `did:web:` string always takes the FIRST segment as the host —
        // that is the did:web specification, so "z6MkFakeScid" as host is correct
        // here and the address literal stays an inert path segment. What must never
        // happen is the address becoming the request target.
        let url = did_web_to_url("did:web:z6MkFakeScid:2852039166").unwrap();
        assert_eq!(url, "https://z6mkfakescid/2852039166/did.json");
        assert!(!url.starts_with("https://2852039166"));

        // The SCID-vs-host footgun the report describes is a did:webvh string being
        // parsed with did:web rules. crate::host::did_host is method-aware, so the
        // did:webvh form resolves the host from the second segment and rejects it.
        assert!(crate::host::did_host("did:webvh:z6MkFakeScid:2852039166").is_err());
    }

    #[test]
    fn test_did_web_to_url_preserves_existing_errors() {
        assert!(matches!(
            did_web_to_url("did:plc:example.com"),
            Err(WebDIDError::InvalidDIDPrefix)
        ));
        assert!(matches!(
            did_web_to_url("example.com"),
            Err(WebDIDError::InvalidDIDPrefix)
        ));
        assert!(matches!(
            did_web_to_url("did:web:"),
            Err(WebDIDError::MissingHostname)
        ));
        assert!(matches!(
            did_web_to_url("did:webvh:abc123:example.com"),
            Err(WebDIDError::InvalidDIDPrefix)
        ));
    }

    #[test]
    fn test_did_web_to_url_decodes_percent_encoded_port() {
        assert_eq!(
            did_web_to_url("did:web:example.com%3A3000").unwrap(),
            "https://example.com:3000/.well-known/did.json"
        );
    }

    #[test]
    fn test_did_web_to_url_rejects_path_traversal() {
        assert!(did_web_to_url("did:web:example.com:..:..:etc").is_err());
        assert!(did_web_to_url("did:web:example.com?x=1").is_err());
    }

    #[tokio::test]
    async fn test_query_hostname_rejects_address_literals() {
        let client = reqwest::Client::new();
        for hostname in [
            "169.254.169.254",
            "2852039166",
            "0xA9FEA9FE",
            "exam_ple.com",
        ] {
            let result = query_hostname(&client, hostname).await;
            assert!(
                matches!(result, Err(WebDIDError::InvalidHost { .. })),
                "expected InvalidHost for {hostname}"
            );
        }
    }

    #[tokio::test]
    async fn test_query_hostname_rejects_uppercased_reserved_tlds() {
        // Confirmed bypass: the lowercase forms were rejected while the uppercased
        // spellings built https://metadata.google.INTERNAL/.well-known/did.json,
        // which reaches the identical host.
        let client = reqwest::Client::new();
        for hostname in [
            "metadata.google.internal",
            "metadata.google.INTERNAL",
            "metadata.google.Internal",
            "x.LOCALHOST",
            "y.LOCAL",
            "z.ARPA",
        ] {
            let result = query_hostname(&client, hostname).await;
            assert!(
                matches!(result, Err(WebDIDError::InvalidHost { .. })),
                "expected InvalidHost for {hostname}, got {result:?}"
            );
        }
    }

    #[test]
    fn test_did_web_to_url_rejects_uppercased_reserved_tlds() {
        for did in [
            "did:web:metadata.google.INTERNAL",
            "did:web:svc.LOCALHOST",
            "did:web:printer.LOCAL",
            "did:web:target.ARPA",
        ] {
            let result = did_web_to_url(did);
            assert!(
                matches!(result, Err(WebDIDError::InvalidHost { .. })),
                "expected InvalidHost for {did}, got {result:?}"
            );
        }
    }
}
