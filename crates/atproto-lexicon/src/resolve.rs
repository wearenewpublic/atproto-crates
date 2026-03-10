//! Lexicon resolution functionality for AT Protocol.
//!
//! This module handles the resolution of lexicon identifiers to their corresponding
//! schema definitions according to the AT Protocol specification.
//!
//! The resolution process:
//! 1. Convert NSID to DNS name with "_lexicon" prefix
//! 2. Perform DNS TXT lookup to get DID
//! 3. Resolve DID to get DID document
//! 4. Extract PDS endpoint from DID document
//! 5. Make XRPC call to com.atproto.repo.getRecord to fetch lexicon

use anyhow::Result;
use atproto_client::{
    client::Auth,
    com::atproto::repo::{GetRecordResponse, get_record},
};
use atproto_identity::resolve::{DnsResolver, resolve_subject};
use serde_json::Value;
use tracing::instrument;

use crate::{errors::LexiconResolveError, validation};

/// Trait for lexicon resolution implementations.
#[async_trait::async_trait]
pub trait LexiconResolver: Send + Sync {
    /// Resolve a lexicon NSID to its schema definition.
    async fn resolve(&self, nsid: &str) -> Result<Value>;
}

/// Default lexicon resolver implementation using DNS and XRPC.
#[derive(Clone)]
pub struct DefaultLexiconResolver<R> {
    http_client: reqwest::Client,
    dns_resolver: R,
}

impl<R> DefaultLexiconResolver<R> {
    /// Create a new lexicon resolver.
    pub fn new(http_client: reqwest::Client, dns_resolver: R) -> Self {
        Self {
            http_client,
            dns_resolver,
        }
    }
}

#[async_trait::async_trait]
impl<R> LexiconResolver for DefaultLexiconResolver<R>
where
    R: DnsResolver + Send + Sync,
{
    #[instrument(skip(self), err)]
    async fn resolve(&self, nsid: &str) -> Result<Value> {
        // Step 1: Convert NSID to DNS name
        let dns_name = validation::nsid_to_dns_name(nsid)?;

        // Step 2: Perform DNS lookup to get DID
        let did = resolve_lexicon_dns(&self.dns_resolver, &dns_name).await?;

        // Step 3: Resolve DID to get DID document
        let resolved_did = resolve_subject(&self.http_client, &self.dns_resolver, &did).await?;

        // Step 4: Get PDS endpoint from DID document
        let pds_endpoint = get_pds_from_did(&self.http_client, &resolved_did).await?;

        // Step 5: Fetch lexicon from PDS
        let lexicon =
            fetch_lexicon_from_pds(&self.http_client, &pds_endpoint, &resolved_did, nsid).await?;

        Ok(lexicon)
    }
}

/// Resolve lexicon DID from DNS TXT records.
#[instrument(skip(dns_resolver), err)]
pub async fn resolve_lexicon_dns<R: DnsResolver + ?Sized>(
    dns_resolver: &R,
    lookup_dns: &str,
) -> Result<String, LexiconResolveError> {
    let txt_records = dns_resolver.resolve_txt(lookup_dns).await?;

    // Look for did= prefix in TXT records
    let dids: Vec<String> = txt_records
        .iter()
        .filter_map(|record| {
            record
                .strip_prefix("did=")
                .or_else(|| record.strip_prefix("did:"))
                .map(|did| {
                    // Ensure proper DID format
                    if did.starts_with("plc:") || did.starts_with("web:") {
                        format!("did:{}", did)
                    } else if did.starts_with("did:") {
                        did.to_string()
                    } else {
                        format!("did:{}", did)
                    }
                })
        })
        .collect();

    if dids.is_empty() {
        return Err(LexiconResolveError::NoDIDsFound);
    }

    if dids.len() > 1 {
        return Err(LexiconResolveError::MultipleDIDsFound);
    }

    Ok(dids[0].clone())
}

/// Get PDS endpoint from DID document.
#[instrument(skip(http_client), err)]
pub async fn get_pds_from_did(http_client: &reqwest::Client, did: &str) -> Result<String> {
    use atproto_identity::{
        model::Document,
        plc,
        resolve::{InputType, parse_input},
        web,
    };

    // Get DID document based on DID method
    let did_document: Document = match parse_input(did)? {
        InputType::Plc(did) => plc::query(http_client, "plc.directory", &did).await?,
        InputType::Web(did) => web::query(http_client, &did).await?,
        _ => {
            return Err(LexiconResolveError::InvalidDIDFormat {
                did: did.to_string(),
            }
            .into());
        }
    };

    // Extract PDS endpoint from service array
    for service in &did_document.service {
        if service.r#type == "AtprotoPersonalDataServer" {
            return Ok(service.service_endpoint.clone());
        }
    }

    Err(LexiconResolveError::NoPDSEndpoint.into())
}

/// Fetch lexicon schema from PDS using XRPC.
#[instrument(skip(http_client), err)]
pub async fn fetch_lexicon_from_pds(
    http_client: &reqwest::Client,
    pds_endpoint: &str,
    did: &str,
    nsid: &str,
) -> Result<Value> {
    // Construct the record key for the lexicon
    // Lexicons are stored under the com.atproto.repo.lexicon collection
    let collection = "com.atproto.lexicon.schema";

    // Make XRPC call to get the lexicon record without authentication
    let auth = Auth::None;
    let response = get_record(
        http_client,
        &auth,
        pds_endpoint,
        did,
        collection,
        nsid,
        None,
    )
    .await
    .map_err(|e| LexiconResolveError::PDSFetchFailed {
        details: e.to_string(),
    })?;

    // Extract the value from the response
    match response {
        GetRecordResponse::Record { value, .. } => Ok(value),
        GetRecordResponse::Error(err) => {
            let msg = err
                .message
                .or(err.error_description)
                .or(err.error)
                .unwrap_or_else(|| "Unknown error".to_string());
            Err(LexiconResolveError::PDSErrorResponse {
                nsid: nsid.to_string(),
                message: msg,
            }
            .into())
        }
    }
}

/// Fetch a lexicon schema record by NSID.
///
/// If `repo` is provided, the lexicon is fetched from that repository's PDS.
/// If `repo` is `None`, the authority is resolved from the NSID via DNS TXT
/// lookup on the `_lexicon` prefixed domain.
///
/// # Parameters
/// - `http_client`: HTTP client for making requests
/// - `dns_resolver`: DNS resolver for TXT lookups and handle resolution
/// - `nsid`: The NSID of the lexicon to fetch (e.g., "app.bsky.feed.post")
/// - `repo`: Optional repository DID or handle to fetch the lexicon from
#[instrument(skip(http_client, dns_resolver), err)]
pub async fn get_lexicon<R: DnsResolver + ?Sized>(
    http_client: &reqwest::Client,
    dns_resolver: &R,
    nsid: &str,
    repo: Option<&str>,
) -> Result<Value> {
    if !validation::is_valid_nsid(nsid) {
        return Err(LexiconResolveError::InvalidNsid {
            nsid: nsid.to_string(),
        }
        .into());
    }

    let resolved_did = match repo {
        Some(subject) => resolve_subject(http_client, dns_resolver, subject).await?,
        None => {
            let dns_name = validation::nsid_to_dns_name(nsid)?;
            let did = resolve_lexicon_dns(dns_resolver, &dns_name).await?;
            resolve_subject(http_client, dns_resolver, &did).await?
        }
    };

    let pds_endpoint = get_pds_from_did(http_client, &resolved_did).await?;
    fetch_lexicon_from_pds(http_client, &pds_endpoint, &resolved_did, nsid).await
}
