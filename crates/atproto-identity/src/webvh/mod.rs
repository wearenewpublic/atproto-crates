//! Web Verifiable History DID client for did:webvh resolution.
//!
//! Implements the [did:webvh v1.0](https://identity.foundation/didwebvh/v1.0/)
//! DID method, which extends did:web with a verifiable, append-only log of DID
//! document changes. Resolution fetches a `did.jsonl` (JSON Lines) file and
//! sequentially validates every entry — verifying hashes, signatures, SCID
//! integrity, pre-rotation keys, and timestamp ordering.
//!
//! ## URL Conversion
//!
//! Transforms DIDs like `did:webvh:{SCID}:example.com:path` into HTTPS URLs
//! pointing to `did.jsonl` files at well-known locations.
//!
//! ## Resolution Flow
//!
//! 1. Parse DID, extract SCID and domain/path
//! 2. Convert to HTTPS URL, fetch `did.jsonl`
//! 3. Process each log entry sequentially with full verification
//! 4. Return the latest DID document

pub mod create;
pub mod jcs;
pub mod log;
pub mod model;
pub mod proof;
pub mod scid;

use tracing::instrument;

use crate::errors::{DidHostError, WebVHDIDError};
use crate::host::did_host;
use crate::model::Document;

pub use model::{
    DataIntegrityProof, LogEntry, MergedParameters, QueryParams, ResolutionMetadata, ResolvedLog,
    WitnessConfig, WitnessEntry, WitnessProofEntry,
};
pub use scid::HashAlgorithm;

pub use crate::errors::{ProblemDetails, ResolutionError, ResolutionErrorCode};

/// Converts a did:webvh DID to its corresponding HTTPS URL for the log file.
///
/// Transforms the DID format to the expected `did.jsonl` location:
/// - `did:webvh:{SCID}:example.com` → `https://example.com/.well-known/did.jsonl`
/// - `did:webvh:{SCID}:example.com:path:sub` → `https://example.com/path/sub/did.jsonl`
/// - `did:webvh:{SCID}:example.com%3A3000` → `https://example.com:3000/.well-known/did.jsonl`
///
/// International domain names are converted to ASCII-compatible encoding
/// (Punycode) per RFC 9233.
///
/// # Security
///
/// The host is the **second** segment, after the SCID, and is validated by
/// [`crate::host::did_host`]: it is a syntactic public DNS name and never a network
/// address literal, so an attacker-published DID cannot direct a fetch at
/// `169.254.169.254` or any of its decimal, octal, or hexadecimal spellings.
/// DNS-level protection (rebinding, a public name resolving into a private range)
/// is explicitly not provided.
pub fn did_webvh_to_url(did: &str) -> Result<String, WebVHDIDError> {
    if !did.starts_with("did:webvh:") {
        return Err(WebVHDIDError::InvalidDIDPrefix);
    }

    let target = did_host(did).map_err(|source| match source {
        DidHostError::MissingScid { .. } => WebVHDIDError::MissingSCID,
        DidHostError::MissingHostname { .. } => WebVHDIDError::MissingHostname,
        DidHostError::IdnaFailed { host } => WebVHDIDError::HostnameNormalizationFailed {
            details: format!("IDNA processing failed for hostname: {}", host),
        },
        other => WebVHDIDError::InvalidHost { source: other },
    })?;

    Ok(target.document_url("did.jsonl"))
}

/// Converts a did:webvh DID to its corresponding witness proof file URL.
///
/// Same URL derivation as `did_webvh_to_url` but returns the path to
/// `did-witnesses.json` instead of `did.jsonl`.
pub fn did_webvh_to_witness_url(did: &str) -> Result<String, WebVHDIDError> {
    let log_url = did_webvh_to_url(did)?;
    Ok(log_url.replace("did.jsonl", "did-witnesses.json"))
}

/// Extracts the SCID from a did:webvh DID string.
///
/// Returns the SCID component (the first segment after `did:webvh:`).
pub fn extract_scid(did: &str) -> Result<String, WebVHDIDError> {
    let remainder = did
        .strip_prefix("did:webvh:")
        .ok_or(WebVHDIDError::InvalidDIDPrefix)?;

    let scid = remainder
        .split(':')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or(WebVHDIDError::MissingSCID)?;

    Ok(scid.to_string())
}

/// Queries a did:webvh DID document from its hosting location.
///
/// Fetches the `did.jsonl` log file, processes all entries sequentially
/// with full verification, and returns the resolved DID document.
///
/// If the log parameters include a witness configuration, the
/// `did-witnesses.json` file is also fetched and witness proofs are
/// verified against the configured threshold.
#[instrument(skip(http_client), err)]
pub async fn query(http_client: &reqwest::Client, did: &str) -> Result<Document, WebVHDIDError> {
    let scid = extract_scid(did)?;
    let url = did_webvh_to_url(did)?;

    let body = http_client
        .get(&url)
        .send()
        .await
        .map_err(|error| WebVHDIDError::HttpRequestFailed {
            url: url.clone(),
            error,
        })?
        .text()
        .await
        .map_err(|error| WebVHDIDError::HttpRequestFailed { url, error })?;

    // First pass: process log without witness verification to determine if witnesses are configured
    let preliminary = log::process_log(did, &scid, &body)?;

    if preliminary.parameters.witness.is_some() {
        // Witnesses are configured — fetch witness proofs and re-process with full verification
        let witness_url = did_webvh_to_witness_url(did)?;
        let witness_body = http_client
            .get(&witness_url)
            .send()
            .await
            .map_err(|error| WebVHDIDError::HttpRequestFailed {
                url: witness_url.clone(),
                error,
            })?
            .text()
            .await
            .map_err(|error| WebVHDIDError::HttpRequestFailed {
                url: witness_url.clone(),
                error,
            })?;

        let witness_proofs: Vec<model::WitnessProofEntry> = serde_json::from_str(&witness_body)
            .map_err(|e| WebVHDIDError::WitnessVerificationFailed {
                entry: 0,
                details: format!("failed to parse witness proofs: {}", e),
            })?;

        let resolved = log::process_log_with_witnesses(did, &scid, &body, Some(&witness_proofs))?;
        Ok(resolved.document)
    } else {
        Ok(preliminary.document)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_webvh_to_url_simple_hostname() {
        let result = did_webvh_to_url("did:webvh:abc123:example.com");
        assert_eq!(result.unwrap(), "https://example.com/.well-known/did.jsonl");
    }

    #[test]
    fn test_did_webvh_to_url_with_path() {
        let result = did_webvh_to_url("did:webvh:abc123:example.com:path");
        assert_eq!(result.unwrap(), "https://example.com/path/did.jsonl");
    }

    #[test]
    fn test_did_webvh_to_url_with_nested_path() {
        let result = did_webvh_to_url("did:webvh:abc123:example.com:path:subpath");
        assert_eq!(
            result.unwrap(),
            "https://example.com/path/subpath/did.jsonl"
        );
    }

    #[test]
    fn test_did_webvh_to_url_with_port() {
        let result = did_webvh_to_url("did:webvh:abc123:example.com%3A3000");
        assert_eq!(
            result.unwrap(),
            "https://example.com:3000/.well-known/did.jsonl"
        );
    }

    #[test]
    fn test_did_webvh_to_url_with_port_and_path() {
        let result = did_webvh_to_url("did:webvh:abc123:example.com%3A3000:dids:issuer");
        assert_eq!(
            result.unwrap(),
            "https://example.com:3000/dids/issuer/did.jsonl"
        );
    }

    #[test]
    fn test_did_webvh_to_url_with_subdomain() {
        let result = did_webvh_to_url("did:webvh:abc123:issuer.example.com");
        assert_eq!(
            result.unwrap(),
            "https://issuer.example.com/.well-known/did.jsonl"
        );
    }

    #[test]
    fn test_did_webvh_to_url_invalid_prefix() {
        let result = did_webvh_to_url("did:web:abc123:example.com");
        assert!(matches!(result, Err(WebVHDIDError::InvalidDIDPrefix)));
    }

    #[test]
    fn test_did_webvh_to_url_missing_scid() {
        let result = did_webvh_to_url("did:webvh:");
        assert!(matches!(result, Err(WebVHDIDError::MissingSCID)));
    }

    #[test]
    fn test_did_webvh_to_url_missing_hostname() {
        let result = did_webvh_to_url("did:webvh:abc123:");
        assert!(matches!(result, Err(WebVHDIDError::MissingHostname)));
    }

    #[test]
    fn test_did_webvh_to_url_only_scid() {
        // Only SCID, no hostname
        let result = did_webvh_to_url("did:webvh:abc123");
        assert!(matches!(result, Err(WebVHDIDError::MissingSCID)));
    }

    #[test]
    fn test_did_webvh_to_url_no_prefix() {
        let result = did_webvh_to_url("example.com");
        assert!(matches!(result, Err(WebVHDIDError::InvalidDIDPrefix)));
    }

    #[test]
    fn test_did_webvh_to_witness_url() {
        let result = did_webvh_to_witness_url("did:webvh:abc123:example.com");
        assert_eq!(
            result.unwrap(),
            "https://example.com/.well-known/did-witnesses.json"
        );
    }

    #[test]
    fn test_did_webvh_to_witness_url_with_path() {
        let result = did_webvh_to_witness_url("did:webvh:abc123:example.com:dids:issuer");
        assert_eq!(
            result.unwrap(),
            "https://example.com/dids/issuer/did-witnesses.json"
        );
    }

    #[test]
    fn test_extract_scid() {
        let scid = extract_scid("did:webvh:QmTest123:example.com").unwrap();
        assert_eq!(scid, "QmTest123");
    }

    #[test]
    fn test_extract_scid_with_path() {
        let scid = extract_scid("did:webvh:QmTest123:example.com:path:sub").unwrap();
        assert_eq!(scid, "QmTest123");
    }

    #[test]
    fn test_extract_scid_invalid_prefix() {
        let result = extract_scid("did:web:example.com");
        assert!(matches!(result, Err(WebVHDIDError::InvalidDIDPrefix)));
    }

    #[test]
    fn test_extract_scid_empty() {
        let result = extract_scid("did:webvh:");
        assert!(matches!(result, Err(WebVHDIDError::MissingSCID)));
    }

    #[test]
    fn test_did_webvh_to_url_rejects_address_literal_host() {
        // Previously returned Ok("https://2852039166/.well-known/did.jsonl").
        for did in [
            "did:webvh:z6MkFakeScid:2852039166",
            "did:webvh:z6MkFakeScid:169.254.169.254",
            "did:webvh:z6MkFakeScid:0xA9FEA9FE",
            "did:webvh:z6MkFakeScid:169.254.43518",
        ] {
            let result = did_webvh_to_url(did);
            assert!(
                matches!(result, Err(WebVHDIDError::InvalidHost { .. })),
                "expected InvalidHost for {did}, got {result:?}"
            );
            let message = result.unwrap_err().to_string();
            assert!(
                message.starts_with("error-atproto-identity-webvh-27 "),
                "unexpected message: {message}"
            );
        }
    }

    #[test]
    fn test_did_webvh_to_witness_url_inherits_validation() {
        let result = did_webvh_to_witness_url("did:webvh:z6MkFakeScid:2852039166");
        assert!(matches!(result, Err(WebVHDIDError::InvalidHost { .. })));
    }

    #[test]
    fn test_did_webvh_to_url_resolution_error_is_invalid_did() {
        let error = did_webvh_to_url("did:webvh:z6MkFakeScid:2852039166").unwrap_err();
        let resolution = error.to_resolution_error();
        assert_eq!(resolution.error, ResolutionErrorCode::InvalidDid);
        assert_eq!(
            resolution.problem_details.unwrap().title,
            "Invalid DID format"
        );
    }

    #[test]
    fn test_did_webvh_to_url_rejects_path_traversal() {
        assert!(did_webvh_to_url("did:webvh:abc123:example.com:..:..:etc").is_err());
        assert!(did_webvh_to_url("did:webvh:abc123:example.com%2f..%2fx").is_err());
    }

    #[test]
    fn test_did_webvh_to_url_lowercase_port_encoding() {
        let result = did_webvh_to_url("did:webvh:abc123:example.com%3a8080");
        assert_eq!(
            result.unwrap(),
            "https://example.com:8080/.well-known/did.jsonl"
        );
    }
}
