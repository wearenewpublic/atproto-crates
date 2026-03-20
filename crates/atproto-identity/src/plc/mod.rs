//! PLC directory client and did:plc operations.
//!
//! Core functionality for did:plc resolution from PLC directory servers, plus
//! full did:plc specification support including operation creation, signing,
//! chain validation, and DID creation.
//!
//! ## Modules
//!
//! - [`did`] - Strongly-typed PLC DID identifiers with parsing and validation
//! - [`encoding`] - Base32, base64url, and SHA-256 encoding utilities
//! - [`state`] - PLC state management and DID document conversion
//! - [`operations`] - PLC operation types (genesis, update, tombstone) with signing
//! - [`builder`] - Fluent API for creating new did:plc identities
//! - [`chain`] - Operation chain validation with fork resolution

use serde::Deserialize;
use tracing::{Instrument, instrument};

use super::errors::PLCDIDError;
use super::model::Document;

pub mod builder;
pub mod chain;
pub mod did;
pub mod encoding;
pub mod operations;
pub mod state;

pub use builder::{BuilderKeys, DidBuilder};
pub use chain::OperationChainValidator;
pub use did::Did;
pub use operations::{Operation, UnsignedOperation};
pub use state::{PlcState, ServiceEndpoint};

/// An entry in the PLC directory audit log.
#[derive(Debug, Deserialize)]
pub struct AuditLogEntry {
    /// The DID this operation is for.
    pub did: String,

    /// The operation itself.
    pub operation: Operation,

    /// CID of this operation.
    pub cid: String,

    /// Timestamp when this operation was created.
    #[serde(rename = "createdAt")]
    pub created_at: String,

    /// Nullified flag (if this operation was invalidated).
    #[serde(default)]
    pub nullified: bool,
}

/// Queries a PLC directory for a DID document.
/// Fetches the complete DID document from the specified PLC hostname.
#[instrument(skip(http_client), err)]
pub async fn query(
    http_client: &reqwest::Client,
    plc_hostname: &str,
    did: &str,
) -> Result<Document, PLCDIDError> {
    let url = format!("https://{}/{}", plc_hostname, did);

    http_client
        .get(&url)
        .send()
        .instrument(tracing::info_span!("http_client_get"))
        .await
        .map_err(|error| PLCDIDError::HttpRequestFailed {
            url: url.clone(),
            error,
        })?
        .json::<Document>()
        .await
        .map_err(|error| PLCDIDError::DocumentParseFailed { url, error })
}

/// Fetches the complete audit log for a DID from the PLC directory.
#[instrument(skip(http_client), err)]
pub async fn fetch_audit_log(
    http_client: &reqwest::Client,
    plc_hostname: &str,
    did: &str,
) -> Result<Vec<AuditLogEntry>, PLCDIDError> {
    let url = format!("https://{}/{}/log/audit", plc_hostname, did);

    let response = http_client
        .get(&url)
        .send()
        .instrument(tracing::info_span!("http_client_get_audit_log"))
        .await
        .map_err(|error| PLCDIDError::AuditLogFetchFailed {
            url: url.clone(),
            error,
        })?;

    response
        .json::<Vec<AuditLogEntry>>()
        .await
        .map_err(|error| PLCDIDError::AuditLogParseFailed { url, error })
}

/// Submits a signed PLC operation to the PLC directory.
#[instrument(skip(http_client, operation), err)]
pub async fn submit(
    http_client: &reqwest::Client,
    plc_hostname: &str,
    did: &str,
    operation: &Operation,
) -> Result<(), PLCDIDError> {
    let url = format!("https://{}/{}", plc_hostname, did);

    let response = http_client
        .post(&url)
        .json(operation)
        .send()
        .instrument(tracing::info_span!("http_client_post_operation"))
        .await
        .map_err(|error| PLCDIDError::HttpRequestFailed {
            url: url.clone(),
            error,
        })?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        return Err(PLCDIDError::SubmissionFailed { url, status, body });
    }

    Ok(())
}
