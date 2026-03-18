//! AT Protocol identity resolution for handles and DIDs.
//!
//! Resolves AT Protocol identities via DNS TXT records and HTTPS well-known endpoints,
//! with automatic input detection for handles, did:plc, and did:web identifiers.
//! - **Validation**: Ensures DNS and HTTP resolution methods agree on the resolved DID
//! - **Custom DNS**: Supports custom DNS nameservers for resolution
//!
//! ## Resolution Flow
//!
//! 1. Parse input to determine identifier type (handle vs DID)
//! 2. For handles: perform parallel DNS and HTTP resolution
//! 3. Validate that both methods return the same DID
//! 4. For DIDs: return the identifier directly

use anyhow::Result;
#[cfg(feature = "hickory-dns")]
use hickory_resolver::{
    Resolver, TokioResolver,
    config::{NameServerConfigGroup, ResolverConfig},
    name_server::TokioConnectionProvider,
};
use reqwest::Client;
use std::collections::HashSet;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use tracing::{Instrument, instrument};

use crate::errors::ResolveError;
use crate::model::Document;
use crate::plc::query as plc_query;
use crate::validation::{is_valid_did_method_plc, is_valid_did_method_webvh, is_valid_handle};
use crate::web::query as web_query;
use crate::webvh::query as webvh_query;

pub use crate::traits::{DnsResolver, IdentityResolver};

/// Hickory DNS implementation of the DnsResolver trait.
/// Wraps hickory_resolver::TokioResolver for TXT record resolution.
#[cfg(feature = "hickory-dns")]
#[derive(Clone)]
pub struct HickoryDnsResolver {
    resolver: TokioResolver,
}

#[cfg(feature = "hickory-dns")]
impl HickoryDnsResolver {
    /// Creates a new HickoryDnsResolver with the given TokioResolver.
    pub fn new(resolver: TokioResolver) -> Self {
        Self { resolver }
    }

    /// Creates a DNS resolver with custom or system nameservers.
    /// Uses custom nameservers if provided, otherwise system defaults.
    pub fn create_resolver(nameservers: &[std::net::IpAddr]) -> Self {
        // Initialize the DNS resolver with custom nameservers if configured
        let tokio_resolver = if !nameservers.is_empty() {
            tracing::debug!("Using custom DNS nameservers: {:?}", nameservers);
            let nameserver_group = NameServerConfigGroup::from_ips_clear(nameservers, 53, true);
            let resolver_config = ResolverConfig::from_parts(None, vec![], nameserver_group);
            Resolver::builder_with_config(resolver_config, TokioConnectionProvider::default())
                .build()
        } else {
            tracing::debug!("Using system default DNS nameservers");
            Resolver::builder_tokio().unwrap().build()
        };
        Self::new(tokio_resolver)
    }
}

#[cfg(feature = "hickory-dns")]
#[async_trait::async_trait]
impl DnsResolver for HickoryDnsResolver {
    async fn resolve_txt(&self, domain: &str) -> Result<Vec<String>, ResolveError> {
        let lookup = self
            .resolver
            .txt_lookup(domain)
            .instrument(tracing::info_span!("txt_lookup"))
            .await
            .map_err(|error| ResolveError::DNSResolutionFailed { error })?;

        Ok(lookup.iter().map(|record| record.to_string()).collect())
    }
}

/// Type of input identifier for resolution.
/// Distinguishes between handles and different DID methods.
pub enum InputType {
    /// AT Protocol handle (e.g., "alice.bsky.social").
    Handle(String),
    /// PLC DID identifier (e.g., "did:plc:abc123").
    Plc(String),
    /// Web DID identifier (e.g., "did:web:example.com").
    Web(String),
    /// Web Verifiable History DID identifier (e.g., "did:webvh:SCID:example.com").
    WebVH(String),
}

/// Resolves a handle to DID using DNS TXT records.
/// Looks up _atproto.{handle} TXT record for DID value.
#[instrument(skip(dns_resolver), err)]
pub async fn resolve_handle_dns<R: DnsResolver + ?Sized>(
    dns_resolver: &R,
    lookup_dns: &str,
) -> Result<String, ResolveError> {
    let txt_records = dns_resolver
        .resolve_txt(&format!("_atproto.{}", lookup_dns))
        .await?;

    let dids = txt_records
        .iter()
        .filter_map(|record| record.strip_prefix("did=").map(|did| did.to_string()))
        .collect::<HashSet<String>>();

    if dids.len() > 1 {
        return Err(ResolveError::MultipleDIDsFound);
    }

    dids.iter().next().cloned().ok_or(ResolveError::NoDIDsFound)
}

/// Resolves a handle to DID using HTTPS well-known endpoint.
/// Fetches DID from https://{handle}/.well-known/atproto-did
#[instrument(skip(http_client), err)]
pub async fn resolve_handle_http(
    http_client: &reqwest::Client,
    handle: &str,
) -> Result<String, ResolveError> {
    let lookup_url = format!("https://{}/.well-known/atproto-did", handle);

    http_client
        .get(lookup_url.clone())
        .timeout(Duration::from_secs(10))
        .send()
        .instrument(tracing::info_span!("http_client_get"))
        .await
        .map_err(|error| ResolveError::HTTPResolutionFailed { error })?
        .text()
        .instrument(tracing::info_span!("response_text"))
        .await
        .map_err(|error| ResolveError::HTTPResolutionFailed { error })
        .and_then(|body| {
            if body.starts_with("did:") {
                Ok(body.trim().to_string())
            } else {
                Err(ResolveError::InvalidHTTPResolutionResponse)
            }
        })
}

/// Parses input string into appropriate identifier type.
/// Handles prefixes like "at://", "@", and DID formats.
pub fn parse_input(input: &str) -> Result<InputType, ResolveError> {
    let trimmed = {
        if let Some(value) = input.trim().strip_prefix("at://") {
            value.trim()
        } else if let Some(value) = input.trim().strip_prefix('@') {
            value.trim()
        } else {
            input.trim()
        }
    };
    if trimmed.is_empty() {
        return Err(ResolveError::InvalidInput);
    }
    if trimmed.starts_with("did:webvh:") && is_valid_did_method_webvh(trimmed, false) {
        Ok(InputType::WebVH(trimmed.to_string()))
    } else if trimmed.starts_with("did:web:") {
        Ok(InputType::Web(trimmed.to_string()))
    } else if trimmed.starts_with("did:plc:") && is_valid_did_method_plc(trimmed) {
        Ok(InputType::Plc(trimmed.to_string()))
    } else {
        is_valid_handle(trimmed)
            .map(InputType::Handle)
            .ok_or(ResolveError::InvalidInput)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{
        IdentityDocumentKeyResolver, KeyResolver, KeyType, generate_key, identify_key, to_public,
    };
    use crate::model::{DocumentBuilder, VerificationMethod};
    use std::collections::HashMap;

    struct StubIdentityResolver {
        expected: String,
        document: Document,
    }

    #[async_trait::async_trait]
    impl IdentityResolver for StubIdentityResolver {
        async fn resolve(&self, subject: &str) -> Result<Document> {
            if !self.expected.is_empty() {
                assert_eq!(self.expected, subject);
            }
            Ok(self.document.clone())
        }
    }

    #[test]
    fn test_parse_input_webvh() {
        let result = parse_input("did:webvh:z6MkTest123:example.com");
        assert!(result.is_ok());
        assert!(
            matches!(result.unwrap(), InputType::WebVH(did) if did == "did:webvh:z6MkTest123:example.com")
        );
    }

    #[test]
    fn test_parse_input_webvh_with_path() {
        let result = parse_input("did:webvh:z6MkTest123:example.com:path:sub");
        assert!(result.is_ok());
        assert!(
            matches!(result.unwrap(), InputType::WebVH(did) if did == "did:webvh:z6MkTest123:example.com:path:sub")
        );
    }

    #[test]
    fn test_parse_input_webvh_simple_hostname() {
        let result = parse_input("did:webvh:z6MkTest123:example.com");
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), InputType::WebVH(_)));
    }

    #[test]
    fn test_parse_input_webvh_with_at_prefix() {
        let result = parse_input("at://did:webvh:z6MkTest123:example.com");
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), InputType::WebVH(_)));
    }

    #[test]
    fn test_parse_input_web_not_webvh() {
        // did:web should not be parsed as did:webvh
        let result = parse_input("did:web:example.com");
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), InputType::Web(_)));
    }

    #[test]
    fn test_parse_input_plc_not_webvh() {
        let result = parse_input("did:plc:ewvi7nxzyoun6zhxrhs64oiz");
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), InputType::Plc(_)));
    }

    #[tokio::test]
    async fn resolves_direct_did_key() -> Result<()> {
        let private_key = generate_key(KeyType::K256Private)?;
        let public_key = to_public(&private_key)?;
        let key_reference = format!("{}", &public_key);

        let resolver = IdentityDocumentKeyResolver::new(Arc::new(StubIdentityResolver {
            expected: String::new(),
            document: Document::builder()
                .id("did:plc:placeholder")
                .build()
                .unwrap(),
        }));

        let key_data = resolver.resolve(&key_reference).await?;
        assert_eq!(key_data.bytes(), public_key.bytes());
        Ok(())
    }

    #[tokio::test]
    async fn resolves_literal_did_key_reference() -> Result<()> {
        let resolver = IdentityDocumentKeyResolver::new(Arc::new(StubIdentityResolver {
            expected: String::new(),
            document: Document::builder()
                .id("did:example:unused".to_string())
                .build()
                .unwrap(),
        }));

        let sample = "did:key:zDnaezRmyM3NKx9NCphGiDFNBEMyR2sTZhhMGTseXCU2iXn53";
        let expected = identify_key(sample)?;
        let resolved = resolver.resolve(sample).await?;
        assert_eq!(resolved.bytes(), expected.bytes());
        Ok(())
    }

    #[tokio::test]
    async fn resolves_via_identity_document() -> Result<()> {
        let private_key = generate_key(KeyType::P256Private)?;
        let public_key = to_public(&private_key)?;
        let public_key_multibase = format!("{}", &public_key)
            .strip_prefix("did:key:")
            .unwrap()
            .to_string();

        let did = "did:web:example.com";
        let method_id = format!("{did}#atproto");

        let document = DocumentBuilder::new()
            .id(did.to_string())
            .add_verification_method(VerificationMethod::Multikey {
                id: method_id.clone(),
                controller: did.to_string(),
                public_key_multibase,
                extra: HashMap::new(),
            })
            .build()
            .unwrap();

        let resolver = IdentityDocumentKeyResolver::new(Arc::new(StubIdentityResolver {
            expected: did.to_string(),
            document,
        }));

        let key_data = resolver.resolve(&method_id).await?;
        assert_eq!(key_data.bytes(), public_key.bytes());
        Ok(())
    }
}

/// Resolves a handle to DID using both DNS and HTTP methods.
/// Returns DID if both methods agree, or error if conflicting.
#[instrument(skip(http_client, dns_resolver), err)]
pub async fn resolve_handle<R: DnsResolver + ?Sized>(
    http_client: &reqwest::Client,
    dns_resolver: &R,
    handle: &str,
) -> Result<String, ResolveError> {
    let trimmed = {
        if let Some(value) = handle.trim().strip_prefix("at://") {
            value
        } else if let Some(value) = handle.trim().strip_prefix('@') {
            value
        } else {
            handle.trim()
        }
    };

    let (dns_lookup, http_lookup) = tokio::join!(
        resolve_handle_dns(dns_resolver, trimmed),
        resolve_handle_http(http_client, trimmed),
    );

    let results = vec![dns_lookup, http_lookup]
        .into_iter()
        .filter_map(|result| result.ok())
        .collect::<Vec<String>>();
    if results.is_empty() {
        return Err(ResolveError::NoDIDsFound);
    }

    let first = results[0].clone();
    if results.iter().all(|result| result == &first) {
        return Ok(first);
    }
    Err(ResolveError::ConflictingDIDsFound)
}

/// Resolves any subject (handle or DID) to a canonical DID.
/// Handles all supported identifier formats automatically.
#[instrument(skip(http_client, dns_resolver), err)]
pub async fn resolve_subject<R: DnsResolver + ?Sized>(
    http_client: &reqwest::Client,
    dns_resolver: &R,
    subject: &str,
) -> Result<String, ResolveError> {
    match parse_input(subject)? {
        InputType::Handle(handle) => resolve_handle(http_client, dns_resolver, &handle).await,
        InputType::Plc(did) | InputType::Web(did) | InputType::WebVH(did) => Ok(did),
    }
}

/// Core identity resolution components for AT Protocol subjects.
///
/// Contains the networking and configuration components needed to resolve
/// handles and DIDs to their corresponding DID documents.
pub struct InnerIdentityResolver {
    /// DNS resolver for handle-to-DID resolution via TXT records.
    pub dns_resolver: Arc<dyn DnsResolver>,
    /// HTTP client for DID document retrieval and well-known endpoint queries.
    pub http_client: Client,
    /// Hostname of the PLC directory server for `did:plc` resolution.
    pub plc_hostname: String,
}

/// Shared identity resolver for AT Protocol subjects.
///
/// Wraps `InnerIdentityResolver` in an Arc for shared access across threads,
/// enabling resolution of AT Protocol handles and DIDs to DID documents.
#[derive(Clone)]
pub struct SharedIdentityResolver(pub Arc<InnerIdentityResolver>);

impl Deref for SharedIdentityResolver {
    type Target = InnerIdentityResolver;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait::async_trait]
impl IdentityResolver for SharedIdentityResolver {
    async fn resolve(&self, subject: &str) -> Result<Document> {
        self.0.resolve(subject).await
    }
}

#[async_trait::async_trait]
impl IdentityResolver for InnerIdentityResolver {
    async fn resolve(&self, subject: &str) -> Result<Document> {
        let resolved_did = resolve_subject(&self.http_client, &*self.dns_resolver, subject).await?;

        match parse_input(&resolved_did) {
            Ok(InputType::Plc(did)) => plc_query(&self.http_client, &self.plc_hostname, &did)
                .await
                .map_err(Into::into),
            Ok(InputType::Web(did)) => web_query(&self.http_client, &did).await.map_err(Into::into),
            Ok(InputType::WebVH(did)) => webvh_query(&self.http_client, &did)
                .await
                .map_err(Into::into),
            Ok(InputType::Handle(_)) => Err(ResolveError::SubjectResolvedToHandle.into()),
            Err(err) => Err(err.into()),
        }
    }
}

impl InnerIdentityResolver {
    /// Resolves an AT Protocol subject to its DID document.
    ///
    /// Takes a handle or DID, resolves it to a canonical DID, then retrieves
    /// the corresponding DID document from the appropriate source (PLC directory or web).
    pub async fn resolve(&self, subject: &str) -> Result<Document> {
        <Self as IdentityResolver>::resolve(self, subject).await
    }
}
