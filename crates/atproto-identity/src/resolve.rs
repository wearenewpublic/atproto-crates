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

#[cfg(feature = "resolve")]
use anyhow::Result;
#[cfg(feature = "hickory-dns")]
use hickory_resolver::{
    Resolver, TokioResolver,
    config::{NameServerConfig, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
    proto::rr::RData,
};
#[cfg(feature = "resolve")]
use reqwest::Client;
#[cfg(feature = "resolve")]
use std::collections::HashSet;
#[cfg(feature = "resolve")]
use std::ops::Deref;
#[cfg(feature = "resolve")]
use std::sync::Arc;
#[cfg(feature = "resolve")]
use std::time::Duration;
#[cfg(feature = "resolve")]
use tracing::{Instrument, instrument};

use crate::errors::ResolveError;
use crate::host::did_host;
#[cfg(feature = "resolve")]
use crate::model::Document;
#[cfg(feature = "resolve")]
use crate::plc::query as plc_query;
use crate::validation::{is_valid_did_method_plc, is_valid_did_method_webvh, is_valid_handle};
#[cfg(feature = "resolve")]
use crate::web::query as web_query;
#[cfg(feature = "resolve")]
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
            // 0.26 replaced `NameServerConfigGroup::from_ips_clear(ips, 53, true)`
            // with one config per address. `udp_and_tcp` is the same thing the
            // old call meant: unencrypted UDP and TCP on the default port 53,
            // with negative responses trusted.
            let name_servers: Vec<NameServerConfig> = nameservers
                .iter()
                .copied()
                .map(NameServerConfig::udp_and_tcp)
                .collect();
            let resolver_config = ResolverConfig::from_parts(None, vec![], name_servers);
            // `build()` became fallible in 0.26. This constructor is infallible
            // by signature and the system-nameserver arm below already panicked
            // on a failed builder, so both arms keep that contract rather than
            // changing a public signature under a dependency bump.
            Resolver::builder_with_config(resolver_config, TokioRuntimeProvider::default())
                .build()
                .expect("DNS resolver could not be built from the configured nameservers")
        } else {
            tracing::debug!("Using system default DNS nameservers");
            Resolver::builder_tokio()
                .expect("system DNS configuration could not be read")
                .build()
                .expect("DNS resolver could not be built from the system configuration")
        };
        Self::new(tokio_resolver)
    }
}

/// The TXT payloads of a lookup's answers, dropping anything that is not TXT.
///
/// Split out so it can be tested without a resolver, because getting it wrong
/// is silent. 0.26 returns a generic `Lookup` rather than a `TxtLookup`, so the
/// answers are `Record`s and not TXT rdata — and `Record`'s `Display` renders
/// the whole record: name, TTL, class, type, quoted rdata. Mapping
/// `to_string()` over the answers still yields a `Vec<String>` and still
/// compiles, and every handle stops resolving, because the caller looks for a
/// value beginning `did=` and
/// `_atproto.alice.example. 300 IN TXT "did=…"` does not begin with it.
#[cfg(feature = "hickory-dns")]
fn txt_values(lookup: &hickory_resolver::lookup::Lookup) -> Vec<String> {
    lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::TXT(txt) => Some(txt.to_string()),
            _ => None,
        })
        .collect()
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

        Ok(txt_values(&lookup))
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

/// Validates and normalizes handle input at the point where it becomes a network target.
///
/// Trims surrounding whitespace, strips the `at://` and `@` prefixes, and requires the
/// remainder to pass [`is_valid_handle`], which rejects every network address literal
/// form — dotted-quad, IPv6, and the `inet_aton` decimal, octal, hexadecimal, and short
/// forms — along with any string carrying URL metacharacters such as `:`, `/`, or `%`.
#[cfg(feature = "resolve")]
fn validated_handle(handle: &str) -> Result<String, ResolveError> {
    is_valid_handle(handle.trim()).ok_or(ResolveError::InvalidInput)
}

/// Resolves a handle to DID using DNS TXT records.
/// Looks up _atproto.{handle} TXT record for DID value.
///
/// # Security
///
/// `lookup_dns` is validated with [`crate::validation::is_valid_handle`] before it is
/// interpolated into the `_atproto.{handle}` query name. Address-shaped or
/// metacharacter-bearing input is rejected with [`ResolveError::InvalidInput`] and no
/// query is issued.
#[cfg(feature = "resolve")]
#[instrument(skip(dns_resolver), err)]
pub async fn resolve_handle_dns<R: DnsResolver + ?Sized>(
    dns_resolver: &R,
    lookup_dns: &str,
) -> Result<String, ResolveError> {
    let lookup_dns = validated_handle(lookup_dns)?;

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
///
/// # Security
///
/// This function is the validating sink for well-known handle resolution: `handle` is
/// checked with [`crate::validation::is_valid_handle`] *before* it is interpolated into
/// the lookup URL, so callers cannot reach an arbitrary network target by handing over
/// unvalidated input. Address literals in every resolver-accepted form — `127.0.0.1`,
/// the decimal `2130706433`, the hexadecimal `0x7f000001`, the octal `0177.0.0.1`, and
/// the short `127.1` — are rejected with [`ResolveError::InvalidInput`] and no request
/// is made. Input carrying `:`, `/`, `%`, or userinfo is rejected for the same reason.
///
/// Validation is purely syntactic. It does not defend against DNS rebinding, nor
/// against a public hostname whose address record points into a private range.
#[cfg(feature = "resolve")]
#[instrument(skip(http_client), err)]
pub async fn resolve_handle_http(
    http_client: &reqwest::Client,
    handle: &str,
) -> Result<String, ResolveError> {
    let handle = validated_handle(handle)?;

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
///
/// Handles prefixes like "at://", "@", and DID formats.
///
/// # Security
///
/// Every accepted variant is validated before it is returned. `did:web` input must
/// encode a safe HTTPS target per [`crate::host::did_host`], and handle input must
/// pass [`crate::validation::is_valid_handle`], so an address-literal identifier
/// never reaches an HTTP client through this entry point.
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
    } else if trimmed.starts_with("did:web:") && did_host(trimmed).is_ok() {
        Ok(InputType::Web(trimmed.to_string()))
    } else if trimmed.starts_with("did:plc:") && is_valid_did_method_plc(trimmed) {
        Ok(InputType::Plc(trimmed.to_string()))
    } else {
        is_valid_handle(trimmed)
            .map(InputType::Handle)
            .ok_or(ResolveError::InvalidInput)
    }
}

// The tests here stand up resolvers and HTTP clients, so they need the
// network half of the crate.
#[cfg(all(test, feature = "resolve"))]
mod tests {

    /// A TXT answer yields its payload, not the whole record.
    ///
    /// This is the hickory 0.26 migration's one silent hazard. 0.25 returned a
    /// `TxtLookup` whose `iter()` gave TXT rdata; 0.26 returns a generic
    /// `Lookup` whose answers are `Record`s. Mapping `to_string()` over them
    /// compiles, type-checks, and returns a `Vec<String>` of the right length
    /// — and every handle stops resolving, because the caller matches a `did=`
    /// prefix that `_atproto.alice.example. 300 IN TXT "did=…"` does not have.
    #[cfg(feature = "hickory-dns")]
    #[test]
    fn a_txt_answer_yields_its_payload_not_the_whole_record() {
        use hickory_resolver::lookup::Lookup;
        use hickory_resolver::proto::op::Query;
        use hickory_resolver::proto::rr::rdata::TXT;
        use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
        use std::str::FromStr;

        let name = Name::from_str("_atproto.alice.example.").unwrap();
        let query = Query::query(name.clone(), RecordType::TXT);
        let did = "did=did:plc:iu5fzdrrfrc6kk7vmmatvin2";
        let answers = vec![
            Record::from_rdata(
                name.clone(),
                300,
                RData::TXT(TXT::new(vec![did.to_string()])),
            ),
            // A non-TXT answer in the same response is dropped rather than
            // stringified into the result.
            Record::from_rdata(
                name,
                300,
                RData::A(hickory_resolver::proto::rr::rdata::A::new(127, 0, 0, 1)),
            ),
        ];

        let values = txt_values(&Lookup::new_with_max_ttl(query, answers));
        assert_eq!(values, vec![did.to_string()]);
        assert!(
            values[0].starts_with("did="),
            "the caller matches this prefix; got {:?}",
            values[0]
        );
    }
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
    fn test_parse_input_rejects_address_form_did_web() {
        for input in [
            "did:web:169.254.169.254",
            "did:web:2852039166",
            "did:web:0xA9FEA9FE",
            "did:web:169.254.43518",
            "did:webvh:z6MkFakeScid:2852039166",
            "did:web:metadata.google.internal",
            "did:web:example.com:..:..:etc",
        ] {
            assert!(
                matches!(parse_input(input), Err(ResolveError::InvalidInput)),
                "expected InvalidInput for {input}"
            );
        }

        // Legitimate did:web input still parses.
        assert!(matches!(
            parse_input("did:web:example.com"),
            Ok(InputType::Web(_))
        ));
        assert!(matches!(
            parse_input("did:web:example.com:path:sub"),
            Ok(InputType::Web(_))
        ));
        assert!(matches!(
            parse_input("did:web:localhost"),
            Ok(InputType::Web(_))
        ));
    }

    #[test]
    fn test_parse_input_rejects_address_form_handle() {
        for input in ["169.254.43518", "1.2.3", "2852039166", "0xA9FEA9FE"] {
            assert!(
                matches!(parse_input(input), Err(ResolveError::InvalidInput)),
                "expected InvalidInput for {input}"
            );
        }

        assert!(matches!(
            parse_input("alice.bsky.social"),
            Ok(InputType::Handle(_))
        ));
    }

    #[tokio::test]
    async fn test_resolve_handle_rejects_address_form_handle() {
        struct PanickingDnsResolver;

        #[async_trait::async_trait]
        impl DnsResolver for PanickingDnsResolver {
            async fn resolve_txt(&self, _domain: &str) -> Result<Vec<String>, ResolveError> {
                panic!("DNS resolution must not be attempted for invalid handles");
            }
        }

        let client = reqwest::Client::new();
        for handle in ["169.254.43518", "1.2.3", "localhost", "2852039166"] {
            let result = resolve_handle(&client, &PanickingDnsResolver, handle).await;
            assert!(
                matches!(result, Err(ResolveError::InvalidInput)),
                "expected InvalidInput for {handle}"
            );
        }
    }

    /// Confirmed SSRF payloads against the `resolve_handle_http` sink itself.
    ///
    /// Every one of these previously produced a real outbound connection to
    /// 127.0.0.1:8099 because validation lived in `resolve_handle` rather than in the
    /// function that builds the URL.
    const LOOPBACK_HANDLE_PAYLOADS: [&str; 10] = [
        "2130706433:8099",
        "0x7f000001:8099",
        "0177.0.0.1:8099",
        "127.1:8099",
        "127.0.0.1:8099",
        "2130706433",
        "0x7f000001",
        "0177.0.0.1",
        "127.1",
        "127.0.0.1",
    ];

    #[tokio::test]
    async fn test_resolve_handle_http_rejects_address_literal_payloads() {
        let client = reqwest::Client::new();

        for handle in LOOPBACK_HANDLE_PAYLOADS {
            let result = resolve_handle_http(&client, handle).await;
            assert!(
                matches!(result, Err(ResolveError::InvalidInput)),
                "expected InvalidInput for {handle}, got {result:?}"
            );
        }

        // Metadata-endpoint forms confirmed in the original report.
        for handle in [
            "169.254.169.254",
            "2852039166",
            "0xA9FEA9FE",
            "0250.0376.0250.0376",
            "169.254.43518",
            "017700000001",
            "[::1]",
            "metadata.google.internal",
            "user@evil.example.com",
            "example.com/../../x",
            "example.com%2f..%2fx",
            "example.com?x=1",
        ] {
            assert!(
                matches!(
                    resolve_handle_http(&client, handle).await,
                    Err(ResolveError::InvalidInput)
                ),
                "expected InvalidInput for {handle}"
            );
        }
    }

    #[tokio::test]
    async fn test_resolve_handle_dns_rejects_address_literal_payloads() {
        struct PanickingDnsResolver;

        #[async_trait::async_trait]
        impl DnsResolver for PanickingDnsResolver {
            async fn resolve_txt(&self, domain: &str) -> Result<Vec<String>, ResolveError> {
                panic!("DNS resolution must not be attempted: {domain}");
            }
        }

        for handle in LOOPBACK_HANDLE_PAYLOADS {
            let result = resolve_handle_dns(&PanickingDnsResolver, handle).await;
            assert!(
                matches!(result, Err(ResolveError::InvalidInput)),
                "expected InvalidInput for {handle}, got {result:?}"
            );
        }
    }

    /// Reserved-TLD payloads whose lowercase spelling was already blocked, but whose
    /// uppercased spelling reached the identical target because the reserved-TLD
    /// comparison was case-sensitive. DNS and HTTP host matching are case-insensitive.
    const UPPERCASE_RESERVED_TLD_PAYLOADS: [&str; 6] = [
        "metadata.google.INTERNAL",
        "metadata.google.Internal",
        "victim.LOCALHOST",
        "printer.LOCAL",
        "target.ARPA",
        "x.LOCALHOST",
    ];

    #[tokio::test]
    async fn test_resolve_handle_dns_rejects_uppercased_reserved_tlds() {
        struct PanickingDnsResolver;

        #[async_trait::async_trait]
        impl DnsResolver for PanickingDnsResolver {
            async fn resolve_txt(&self, domain: &str) -> Result<Vec<String>, ResolveError> {
                panic!("DNS resolution must not be attempted: {domain}");
            }
        }

        for handle in UPPERCASE_RESERVED_TLD_PAYLOADS {
            let result = resolve_handle_dns(&PanickingDnsResolver, handle).await;
            assert!(
                matches!(result, Err(ResolveError::InvalidInput)),
                "expected InvalidInput for {handle}, got {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_resolve_handle_http_rejects_uppercased_reserved_tlds() {
        let client = reqwest::Client::new();

        for handle in UPPERCASE_RESERVED_TLD_PAYLOADS {
            let result = resolve_handle_http(&client, handle).await;
            assert!(
                matches!(result, Err(ResolveError::InvalidInput)),
                "expected InvalidInput for {handle}, got {result:?}"
            );
        }
    }

    #[test]
    fn test_parse_input_rejects_uppercased_reserved_tlds() {
        for input in UPPERCASE_RESERVED_TLD_PAYLOADS {
            assert!(
                matches!(parse_input(input), Err(ResolveError::InvalidInput)),
                "expected InvalidInput for {input}"
            );
        }
    }

    #[tokio::test]
    async fn test_resolve_handle_dns_lowercases_the_query_name() {
        struct AssertingDnsResolver;

        #[async_trait::async_trait]
        impl DnsResolver for AssertingDnsResolver {
            async fn resolve_txt(&self, domain: &str) -> Result<Vec<String>, ResolveError> {
                assert_eq!(domain, "_atproto.alice.bsky.social");
                Ok(vec!["did=did:plc:z3f2222fa222f5c33c2f27ez".to_string()])
            }
        }

        let did = resolve_handle_dns(&AssertingDnsResolver, "Alice.BSKY.Social")
            .await
            .unwrap();
        assert_eq!(did, "did:plc:z3f2222fa222f5c33c2f27ez");
    }

    #[tokio::test]
    async fn test_resolve_handle_dns_accepts_valid_handle() {
        struct StubDnsResolver;

        #[async_trait::async_trait]
        impl DnsResolver for StubDnsResolver {
            async fn resolve_txt(&self, domain: &str) -> Result<Vec<String>, ResolveError> {
                assert_eq!(domain, "_atproto.alice.bsky.social");
                Ok(vec!["did=did:plc:z3f2222fa222f5c33c2f27ez".to_string()])
            }
        }

        // Prefixes and surrounding whitespace are normalized, not rejected.
        for handle in [
            "alice.bsky.social",
            "@alice.bsky.social",
            "at://alice.bsky.social",
            "  alice.bsky.social  ",
        ] {
            let did = resolve_handle_dns(&StubDnsResolver, handle).await.unwrap();
            assert_eq!(did, "did:plc:z3f2222fa222f5c33c2f27ez");
        }
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
        let key_reference = format!("{}", public_key);

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
        let public_key_multibase = format!("{}", public_key)
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
///
/// Returns DID if both methods agree, or error if conflicting.
///
/// # Security
///
/// The handle is validated with [`crate::validation::is_valid_handle`] before it is
/// interpolated into the `https://{handle}/.well-known/atproto-did` lookup URL.
/// Address-shaped input such as `169.254.43518` is rejected with
/// [`ResolveError::InvalidInput`] rather than fetched. The same check is enforced
/// independently by [`resolve_handle_http`] and [`resolve_handle_dns`], so it cannot be
/// bypassed by calling either of those directly.
#[cfg(feature = "resolve")]
#[instrument(skip(http_client, dns_resolver), err)]
pub async fn resolve_handle<R: DnsResolver + ?Sized>(
    http_client: &reqwest::Client,
    dns_resolver: &R,
    handle: &str,
) -> Result<String, ResolveError> {
    let trimmed = validated_handle(handle)?;
    let trimmed = trimmed.as_str();

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
#[cfg(feature = "resolve")]
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
#[cfg(feature = "resolve")]
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
#[cfg(feature = "resolve")]
#[derive(Clone)]
pub struct SharedIdentityResolver(pub Arc<InnerIdentityResolver>);

#[cfg(feature = "resolve")]
impl Deref for SharedIdentityResolver {
    type Target = InnerIdentityResolver;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait::async_trait]
#[cfg(feature = "resolve")]
impl IdentityResolver for SharedIdentityResolver {
    async fn resolve(&self, subject: &str) -> Result<Document> {
        self.0.resolve(subject).await
    }
}

#[async_trait::async_trait]
#[cfg(feature = "resolve")]
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

#[cfg(feature = "resolve")]
impl InnerIdentityResolver {
    /// Resolves an AT Protocol subject to its DID document.
    ///
    /// Takes a handle or DID, resolves it to a canonical DID, then retrieves
    /// the corresponding DID document from the appropriate source (PLC directory or web).
    pub async fn resolve(&self, subject: &str) -> Result<Document> {
        <Self as IdentityResolver>::resolve(self, subject).await
    }
}
