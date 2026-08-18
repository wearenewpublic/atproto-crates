//! Command-line tool for verifying cryptographic signatures on AT Protocol records.
//!
//! This tool validates attestation signatures on AT Protocol records by reconstructing
//! the signed content and verifying ECDSA signatures against public keys embedded in the
//! attestation metadata.
//!
//! ## Usage Patterns
//!
//! ### Verify all signatures in a record
//! ```bash
//! atproto-attestation-verify <record> <repository_did>
//! ```
//!
//! ### Verify a specific attestation against a record
//! ```bash
//! atproto-attestation-verify <record> <repository_did> <attestation>
//! ```
//!
//! ## Parameter Formats
//!
//! Both `record` and `attestation` parameters accept:
//! - **JSON string**: Direct JSON payload (e.g., `'{"$type":"...","text":"..."}'`)
//! - **File path**: Path to a JSON file (e.g., `./record.json`)
//! - **AT-URI**: AT Protocol URI to fetch the record (e.g., `at://did:plc:abc/app.bsky.feed.post/123`)
//!
//! ## Examples
//!
//! ```bash
//! # Verify all signatures in a record from file
//! atproto-attestation-verify ./signed_post.json did:plc:repo123
//!
//! # Verify all signatures in a record from AT-URI
//! atproto-attestation-verify at://did:plc:abc123/app.bsky.feed.post/3k2k4j5h6g did:plc:abc123
//!
//! # Verify specific attestation against a record (both from files)
//! atproto-attestation-verify ./record.json did:plc:repo123 ./attestation.json
//!
//! # Verify specific attestation (from AT-URI) against record (from file)
//! atproto-attestation-verify ./record.json did:plc:repo123 at://did:plc:xyz/com.example.attestation/abc123
//!
//! # Read record from stdin, verify all signatures
//! cat signed.json | atproto-attestation-verify - did:plc:repo123
//!
//! # Verify inline JSON
//! atproto-attestation-verify '{"$type":"app.bsky.feed.post","text":"Hello","signatures":[...]}' did:plc:repo123
//! ```

use anyhow::{Context, Result, anyhow};
use atproto_attestation::AnyInput;
use atproto_identity::key::{KeyData, KeyResolver, identify_key};
use atproto_identity::model::VerificationMethod;
use atproto_identity::resolve::SharedIdentityResolver;
use atproto_identity::resolve::{HickoryDnsResolver, InnerIdentityResolver};
use atproto_identity::traits::IdentityResolver;
use clap::Parser;
use serde_json::Value;
use std::sync::Arc;
use std::{
    fs,
    io::{self, Read},
    path::Path,
};

/// Command-line tool for verifying cryptographic signatures on AT Protocol records.
///
/// Validates attestation signatures by reconstructing signed content and checking
/// ECDSA signatures against embedded public keys. Supports verifying all signatures
/// in a record or validating a specific attestation record.
///
/// The repository DID parameter is now REQUIRED to prevent replay attacks where
/// attestations might be copied to different repositories.
#[derive(Parser)]
#[command(
    name = "atproto-attestation-verify",
    version,
    about = "Verify cryptographic signatures of AT Protocol records",
    long_about = "
A command-line tool for verifying cryptographic signatures of AT Protocol records.

USAGE:
  atproto-attestation-verify <record> <repository_did>                      Verify all signatures

PARAMETER FORMATS:
  Each parameter accepts JSON strings, file paths, or AT-URIs:
  - JSON string:  '{\"$type\":\"...\",\"text\":\"...\"}'
  - File path:    ./record.json
  - AT-URI:       at://did:plc:abc/app.bsky.feed.post/123
  - Stdin:        - (for record parameter only)

EXAMPLES:
  # Verify all signatures in a record:
  atproto-attestation-verify ./signed_post.json did:plc:repo123
  atproto-attestation-verify at://did:plc:abc/app.bsky.feed.post/123 did:plc:abc

  # Verify specific attestation:
  atproto-attestation-verify ./record.json did:plc:repo123 ./attestation.json
  atproto-attestation-verify ./record.json did:plc:repo123 at://did:plc:xyz/com.example.attestation/abc

  # Read from stdin:
  cat signed.json | atproto-attestation-verify - did:plc:repo123

OUTPUT:
  Single record mode:   Reports each signature with ✓ (valid), ✗ (invalid), or ? (unverified)
  Attestation mode:     Outputs 'OK' on success, error message on failure

VERIFICATION:
  - Inline signatures are verified by reconstructing $sig and validating against embedded keys
  - Remote attestations (strongRef) are reported as unverified (require fetching proof record)
  - Keys are resolved from did:key identifiers or require a key resolver for DID document keys
"
)]
struct Args {
    /// Record to verify - JSON string, file path, AT-URI, or '-' for stdin
    record: String,

    /// Repository DID that houses the record (required for replay attack prevention)
    repository_did: String,

    /// Optional attestation record to verify against the record - JSON string, file path, or AT-URI
    attestation: Option<String>,
}

/// A key resolver that supports `did:key:` identifiers directly.
///
/// This resolver handles key references that are encoded as `did:key:` strings,
/// parsing them to extract the cryptographic key data. For other DID methods,
/// it returns an error since those would require fetching DID documents.
struct DidKeyResolver {
    identity_resolver: Arc<dyn IdentityResolver>,
}

#[async_trait::async_trait]
impl KeyResolver for DidKeyResolver {
    async fn resolve(&self, key: &str) -> Result<KeyData> {
        if let Some(did_key) = key.split('#').next()
            && let Ok(key_data) = identify_key(did_key)
        {
            return Ok(key_data);
        } else if let Ok(key_data) = identify_key(key) {
            return Ok(key_data);
        }

        let (did, fragment) = key
            .split_once('#')
            .context("Key reference must contain a DID fragment (e.g., did:example#key)")?;

        if did.is_empty() || fragment.is_empty() {
            return Err(anyhow!(
                "Key reference must include both DID and fragment (received `{key}`)"
            ));
        }

        let document = self.identity_resolver.resolve(did).await?;
        let fragment_with_hash = format!("#{fragment}");

        let public_key_multibase = document
            .verification_method
            .iter()
            .find_map(|method| match method {
                VerificationMethod::Multikey {
                    id,
                    public_key_multibase,
                    ..
                } if id == key || *id == fragment_with_hash => Some(public_key_multibase.clone()),
                _ => None,
            })
            .context(format!(
                "Verification method `{key}` not found in DID document `{did}`"
            ))?;

        let full_key = if public_key_multibase.starts_with("did:key:") {
            public_key_multibase
        } else {
            format!("did:key:{}", public_key_multibase)
        };

        identify_key(&full_key).context("Failed to parse key data from verification method")
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Load the record
    let record = load_input(&args.record, true)
        .await
        .context("Failed to load record")?;

    if !record.is_object() {
        return Err(anyhow!("Record must be a JSON object"));
    }

    // Validate repository DID
    if !args.repository_did.starts_with("did:") {
        return Err(anyhow!(
            "Repository DID must start with 'did:' prefix, got: {}",
            args.repository_did
        ));
    }

    // Determine verification mode
    verify_all_mode(&record, &args.repository_did).await
}

/// Mode 1: Verify all signatures contained in the record.
///
/// Reports each signature with status indicators:
/// - ✓ Valid signature
/// - ✗ Invalid signature
/// - ? Unverified (e.g., remote attestations requiring proof record fetch)
async fn verify_all_mode(record: &Value, repository_did: &str) -> Result<()> {
    // Create an identity resolver for fetching remote attestations

    let http_client = reqwest::Client::new();
    let dns_resolver = HickoryDnsResolver::create_resolver(&[]);

    let identity_resolver = Arc::new(SharedIdentityResolver(Arc::new(InnerIdentityResolver {
        http_client: http_client.clone(),
        dns_resolver: Arc::new(dns_resolver),
        plc_hostname: "plc.directory".to_string(),
    })));

    // Create record resolver that can fetch remote attestation proof records
    let record_resolver = RemoteAttestationResolver {
        http_client,
        identity_resolver: identity_resolver.clone(),
    };

    let key_resolver = DidKeyResolver { identity_resolver };

    atproto_attestation::verify_record(
        AnyInput::Serialize(record.clone()),
        repository_did,
        key_resolver,
        record_resolver,
    )
    .await
    .context("Failed to verify signatures")
}

/// Load input from various sources: JSON string, file path, AT-URI, or stdin.
///
/// The `allow_stdin` parameter controls whether "-" is interpreted as stdin.
async fn load_input(input: &str, allow_stdin: bool) -> Result<Value> {
    // Handle stdin
    if input == "-" {
        if !allow_stdin {
            return Err(anyhow!(
                "Stdin ('-') is only supported for the record parameter"
            ));
        }

        let mut buffer = String::new();
        io::stdin()
            .read_to_string(&mut buffer)
            .context("Failed to read from stdin")?;

        return serde_json::from_str(&buffer).context("Failed to parse JSON from stdin");
    }

    // Check if it's an AT-URI
    if input.starts_with("at://") {
        return load_from_aturi(input)
            .await
            .with_context(|| format!("Failed to fetch record from AT-URI: {}", input));
    }

    // Try as file path
    let path = Path::new(input);
    if path.exists() && path.is_file() {
        let content =
            fs::read_to_string(path).with_context(|| format!("Failed to read file: {}", input))?;

        return serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse JSON from file: {}", input));
    }

    // Try as direct JSON string
    serde_json::from_str(input).with_context(|| {
        format!(
            "Input is not valid JSON, an existing file, or an AT-URI: {}",
            input
        )
    })
}

/// Load a record from an AT-URI by fetching it from a PDS.
///
/// This requires resolving the DID to find the PDS endpoint, then fetching the record.
async fn load_from_aturi(aturi: &str) -> Result<Value> {
    use atproto_identity::resolve::{HickoryDnsResolver, InnerIdentityResolver};
    use atproto_record::aturi::ATURI;
    use std::str::FromStr;
    use std::sync::Arc;

    // Parse the AT-URI
    let parsed = ATURI::from_str(aturi).map_err(|e| anyhow!("Invalid AT-URI: {}", e))?;

    // Create resolver components
    let http_client = reqwest::Client::new();
    let dns_resolver = HickoryDnsResolver::create_resolver(&[]);

    // Create identity resolver
    let identity_resolver = InnerIdentityResolver {
        http_client: http_client.clone(),
        dns_resolver: Arc::new(dns_resolver),
        plc_hostname: "plc.directory".to_string(),
    };

    // Resolve the DID to get the PDS endpoint
    let document = identity_resolver
        .resolve(&parsed.authority)
        .await
        .with_context(|| format!("Failed to resolve DID: {}", parsed.authority))?;

    // Find the PDS endpoint
    let pds_endpoint = document
        .service
        .iter()
        .find(|s| s.r#type == "AtprotoPersonalDataServer")
        .map(|s| s.service_endpoint.as_str())
        .ok_or_else(|| anyhow!("No PDS endpoint found for DID: {}", parsed.authority))?;

    // Fetch the record using the XRPC client
    let response = atproto_client::com::atproto::repo::get_record(
        &http_client,
        &atproto_client::client::Auth::None,
        pds_endpoint,
        &parsed.authority,
        &parsed.collection,
        &parsed.record_key,
        None,
    )
    .await
    .with_context(|| format!("Failed to fetch record from PDS: {}", pds_endpoint))?;

    match response {
        atproto_client::com::atproto::repo::GetRecordResponse::Record { value, .. } => Ok(value),
        atproto_client::com::atproto::repo::GetRecordResponse::Error(error) => {
            Err(anyhow!("Failed to fetch record: {}", error.error_message()))
        }
    }
}

/// Record resolver for remote attestations that resolves DIDs to find PDS endpoints.
struct RemoteAttestationResolver {
    http_client: reqwest::Client,
    identity_resolver: Arc<dyn IdentityResolver>,
}

#[async_trait::async_trait]
impl atproto_client::record_resolver::RecordResolver for RemoteAttestationResolver {
    async fn resolve<T>(&self, aturi: &str) -> anyhow::Result<T>
    where
        T: serde::de::DeserializeOwned + Send,
    {
        use atproto_record::aturi::ATURI;
        use std::str::FromStr;

        // Parse the AT-URI
        let parsed = ATURI::from_str(aturi).map_err(|e| anyhow!("Invalid AT-URI: {}", e))?;

        // Resolve the DID to get the PDS endpoint
        let document = self
            .identity_resolver
            .resolve(&parsed.authority)
            .await
            .with_context(|| format!("Failed to resolve DID: {}", parsed.authority))?;

        // Find the PDS endpoint
        let pds_endpoint = document
            .service
            .iter()
            .find(|s| s.r#type == "AtprotoPersonalDataServer")
            .map(|s| s.service_endpoint.as_str())
            .ok_or_else(|| anyhow!("No PDS endpoint found for DID: {}", parsed.authority))?;

        // Fetch the record using the XRPC client
        let response = atproto_client::com::atproto::repo::get_record(
            &self.http_client,
            &atproto_client::client::Auth::None,
            pds_endpoint,
            &parsed.authority,
            &parsed.collection,
            &parsed.record_key,
            None,
        )
        .await
        .with_context(|| format!("Failed to fetch record from PDS: {}", pds_endpoint))?;

        match response {
            atproto_client::com::atproto::repo::GetRecordResponse::Record { value, .. } => {
                serde_json::from_value(value)
                    .map_err(|e| anyhow!("Failed to deserialize record: {}", e))
            }
            atproto_client::com::atproto::repo::GetRecordResponse::Error(error) => {
                Err(anyhow!("Failed to fetch record: {}", error.error_message()))
            }
        }
    }

    /// Resolve a record at the CID a `strongRef` pins.
    ///
    /// A remote attestation *is* a strongRef, so this is the shape that
    /// belongs here -- the proof record is named by `(uri, cid)` and fetching
    /// whatever is at the address now would let a repository substitute a
    /// different proof for the one the signature covers.
    ///
    /// Verified by recomputing the CID over what came back rather than by
    /// reading the envelope's `cid`, which is the server's claim about the
    /// bytes it sent.
    async fn resolve_pinned<T>(&self, aturi: &str, cid: &str) -> anyhow::Result<T>
    where
        T: serde::de::DeserializeOwned + Send,
    {
        let value: serde_json::Value = self.resolve(aturi).await?;

        let computed = atproto_client::record_resolver::record_cid(&value)?;
        if computed != cid {
            return Err(anyhow!(
                "Pinned record does not match its CID: {aturi} pins {cid}, \
                 the record fetched hashes to {computed}"
            ));
        }

        serde_json::from_value(value).map_err(|e| anyhow!("Failed to deserialize record: {}", e))
    }
}
