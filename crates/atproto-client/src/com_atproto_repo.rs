//! AT Protocol repository operations.
//!
//! Client functions for com.atproto.repo XRPC methods including
//! record CRUD operations with DPoP authentication support.
//! - **`create_record()`**: Create a new record in a repository
//! - **`put_record()`**: Update or create a record with a specific key
//! - **`delete_record()`**: Delete a record from a repository
//!
//! ## Request/Response Types
//!
//! - **`CreateRecordRequest`**: Parameters for creating new records
//! - **`PutRecordRequest`**: Parameters for updating/creating records with specific keys
//! - **`DeleteRecordRequest`**: Parameters for deleting records
//! - **`GetRecordResponse`**: Response containing record data or error
//! - **`ListRecordsResponse`**: Paginated list of records with cursor support
//! - **`CreateRecordResponse`**: Response with created record URI and CID
//! - **`PutRecordResponse`**: Response with updated record URI and CID
//! - **`DeleteRecordResponse`**: Response with commit information or error
//!
//! ## Authentication
//!
//! All operations require DPoP authentication using the `DPoPAuth` struct containing
//! OAuth access tokens and private keys for proof generation.

use std::collections::HashMap;
use std::iter;

use anyhow::Result;
use atproto_identity::url::build_url;
use bytes::Bytes;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    client::{
        Auth, get_apppassword_json, get_bytes, get_dpop_json, get_json, post_apppassword_json,
        post_dpop_json, post_json,
    },
    errors::SimpleError,
};

/// Response from getting a record from an AT Protocol repository.
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Deserialize, Clone)]
#[serde(untagged)]
pub enum GetRecordResponse {
    /// Successfully retrieved record
    Record {
        /// AT-URI identifying the record
        uri: String,
        /// Content identifier (CID) of the record
        cid: String,
        /// The record content as JSON
        value: serde_json::Value,

        /// Additional fields not part of the standard response
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
    /// Error response from the server
    Error(SimpleError),
}

/// Retrieves a blob from an AT Protocol repository by DID and CID.
///
/// # Arguments
///
/// * `http_client` - HTTP client for making requests
/// * `base_url` - Base URL of the AT Protocol server
/// * `did` - Repository identifier (DID) containing the blob
/// * `cid` - Content identifier (CID) of the blob to retrieve
///
/// # Returns
///
/// The blob data as bytes
pub async fn get_blob(
    http_client: &reqwest::Client,
    base_url: &str,
    did: &str,
    cid: &str,
) -> Result<Bytes> {
    let url = build_url(
        base_url,
        "/xrpc/com.atproto.sync.getBlob",
        [("did", did), ("cid", cid)],
    )?
    .to_string();

    get_bytes(http_client, &url).await
}

/// Retrieves a record from an AT Protocol repository.
///
/// # Arguments
///
/// * `http_client` - HTTP client for making requests
/// * `auth` - Authentication method (None, DPoP, or AppPassword)
/// * `base_url` - Base URL of the AT Protocol server
/// * `repo` - Repository identifier (DID)
/// * `collection` - Collection NSID
/// * `rkey` - Record key
/// * `cid` - Optional specific version CID to retrieve
///
/// # Returns
///
/// The record data or an error response
pub async fn get_record(
    http_client: &reqwest::Client,
    auth: &Auth,
    base_url: &str,
    repo: &str,
    collection: &str,
    rkey: &str,
    cid: Option<&str>,
) -> Result<GetRecordResponse> {
    let mut params = vec![("repo", repo), ("collection", collection), ("rkey", rkey)];
    if let Some(cid) = cid {
        params.push(("cid", cid));
    }

    let url = build_url(base_url, "/xrpc/com.atproto.repo.getRecord", params)?.to_string();

    match auth {
        Auth::None => get_json(http_client, &url)
            .await
            .and_then(|value| serde_json::from_value(value).map_err(|err| err.into())),
        Auth::DPoP(dpop_auth) => get_dpop_json(http_client, dpop_auth, &url)
            .await
            .and_then(|value| serde_json::from_value(value).map_err(|err| err.into())),
        Auth::AppPassword(app_auth) => get_apppassword_json(http_client, app_auth, &url)
            .await
            .and_then(|value| serde_json::from_value(value).map_err(|err| err.into())),
    }
}

/// A single record in a list records response.
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Deserialize, Clone)]
pub struct ListRecord<T> {
    /// AT-URI of the record
    pub uri: String,
    /// Content identifier (CID) of the record
    pub cid: String,
    /// The record content
    pub value: T,
}

/// Response from listing records in an AT Protocol repository.
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Deserialize, Clone)]
pub struct ListRecordsResponse<T> {
    /// Pagination cursor for retrieving more records
    pub cursor: Option<String>,
    /// List of records in the collection
    pub records: Vec<ListRecord<T>>,
}

/// Parameters for listing records from a repository collection.
#[derive(Default)]
pub struct ListRecordsParams {
    /// Maximum number of records to return
    pub limit: Option<u32>,
    /// Pagination cursor from previous request
    pub cursor: Option<String>,
    /// Whether to return records in reverse chronological order
    pub reverse: Option<bool>,
}

impl ListRecordsParams {
    /// Creates new list records parameters with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum number of records to return.
    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Sets the pagination cursor.
    pub fn cursor(mut self, cursor: String) -> Self {
        self.cursor = Some(cursor);
        self
    }

    /// Sets reverse chronological ordering.
    pub fn reverse(mut self, reverse: bool) -> Self {
        self.reverse = Some(reverse);
        self
    }
}

/// Lists records from an AT Protocol repository collection.
///
/// # Arguments
///
/// * `http_client` - HTTP client for making requests
/// * `auth` - Authentication method (None, DPoP, or AppPassword)
/// * `base_url` - Base URL of the AT Protocol server
/// * `repo` - Repository identifier (DID)
/// * `collection` - Collection NSID to list from
/// * `params` - Optional parameters for listing (limit, cursor, reverse)
///
/// # Returns
///
/// A paginated list of records from the collection
pub async fn list_records<T: DeserializeOwned>(
    http_client: &reqwest::Client,
    auth: &Auth,
    base_url: &str,
    repo: String,
    collection: String,
    params: ListRecordsParams,
) -> Result<ListRecordsResponse<T>> {
    let mut url = build_url(
        base_url,
        "/xrpc/com.atproto.repo.listRecords",
        iter::empty::<(&str, &str)>(),
    )?;
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("repo", &repo);
        pairs.append_pair("collection", &collection);

        if let Some(limit) = params.limit {
            pairs.append_pair("limit", &limit.to_string());
        }

        if let Some(cursor) = params.cursor {
            pairs.append_pair("cursor", &cursor);
        }

        if let Some(reverse) = params.reverse {
            pairs.append_pair("reverse", &reverse.to_string());
        }
    }

    let url = url.to_string();

    match auth {
        Auth::None => get_json(http_client, &url)
            .await
            .and_then(|value| serde_json::from_value(value).map_err(|err| err.into())),
        Auth::DPoP(dpop_auth) => get_dpop_json(http_client, dpop_auth, &url)
            .await
            .and_then(|value| serde_json::from_value(value).map_err(|err| err.into())),
        Auth::AppPassword(app_auth) => get_apppassword_json(http_client, app_auth, &url)
            .await
            .and_then(|value| serde_json::from_value(value).map_err(|err| err.into())),
    }
}

/// Request to create a new record in an AT Protocol repository.
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "T: Serialize + DeserializeOwned")]
pub struct CreateRecordRequest<T: DeserializeOwned> {
    /// Repository identifier (DID)
    pub repo: String,
    /// Collection NSID (e.g., "app.bsky.feed.post")
    pub collection: String,

    /// Optional record key; if None, server will generate one
    #[serde(skip_serializing_if = "Option::is_none", default, rename = "rkey")]
    pub record_key: Option<String>,

    /// Whether to validate the record against its schema
    pub validate: bool,

    /// The record content to create
    pub record: T,

    /// Optional commit CID to swap (for atomic updates)
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        rename = "swapCommit"
    )]
    pub swap_commit: Option<String>,
}

/// Response from creating a record in an AT Protocol repository.
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Deserialize, Clone)]
#[serde(untagged)]
pub enum CreateRecordResponse {
    /// Successfully created record reference
    StrongRef {
        /// AT-URI of the created record
        uri: String,
        /// Content identifier (CID) of the created record
        cid: String,

        /// Additional fields not part of the standard response
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
    /// Error response from the server
    Error(SimpleError),
}

/// Creates a new record in an AT Protocol repository.
///
/// # Arguments
///
/// * `http_client` - HTTP client for making requests
/// * `auth` - Authentication method (None, DPoP, or AppPassword)
/// * `base_url` - Base URL of the AT Protocol server
/// * `record` - Record creation request with content and metadata
///
/// # Returns
///
/// The created record reference or an error response
pub async fn create_record<T: DeserializeOwned + Serialize>(
    http_client: &reqwest::Client,
    auth: &Auth,
    base_url: &str,
    record: CreateRecordRequest<T>,
) -> Result<CreateRecordResponse> {
    let url = build_url(
        base_url,
        "/xrpc/com.atproto.repo.createRecord",
        iter::empty::<(&str, &str)>(),
    )?
    .to_string();

    let value = serde_json::to_value(record)?;

    match auth {
        Auth::None => post_json(http_client, &url, value)
            .await
            .and_then(|value| serde_json::from_value(value).map_err(|err| err.into())),
        Auth::DPoP(dpop_auth) => post_dpop_json(http_client, dpop_auth, &url, value)
            .await
            .and_then(|value| serde_json::from_value(value).map_err(|err| err.into())),
        Auth::AppPassword(app_auth) => post_apppassword_json(http_client, app_auth, &url, value)
            .await
            .and_then(|value| serde_json::from_value(value).map_err(|err| err.into())),
    }
}

/// Request to update an existing record in an AT Protocol repository.
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "T: Serialize + DeserializeOwned")]
pub struct PutRecordRequest<T: DeserializeOwned> {
    /// Repository identifier (DID)
    pub repo: String,
    /// Collection NSID (e.g., "app.bsky.feed.post")
    pub collection: String,

    /// Record key to update
    #[serde(rename = "rkey")]
    pub record_key: String,

    /// Whether to validate the record against its schema
    pub validate: bool,

    /// The new record content
    pub record: T,

    /// Optional commit CID to swap (for atomic updates)
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        rename = "swapCommit"
    )]
    pub swap_commit: Option<String>,

    /// Optional record CID to swap (for conditional updates)
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        rename = "swapRecord"
    )]
    pub swap_record: Option<String>,
}

/// Response from updating a record in an AT Protocol repository.
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum PutRecordResponse {
    /// Successfully updated record reference
    StrongRef {
        /// AT-URI of the updated record
        uri: String,
        /// Content identifier (CID) of the updated record
        cid: String,

        /// Additional fields not part of the standard response
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
    /// Error response from the server
    Error(SimpleError),
}

/// Updates an existing record in an AT Protocol repository.
///
/// # Arguments
///
/// * `http_client` - HTTP client for making requests
/// * `auth` - Authentication method (None, DPoP, or AppPassword)
/// * `base_url` - Base URL of the AT Protocol server
/// * `record` - Record update request with new content and metadata
///
/// # Returns
///
/// The updated record reference or an error response
pub async fn put_record<T: DeserializeOwned + Serialize>(
    http_client: &reqwest::Client,
    auth: &Auth,
    base_url: &str,
    record: PutRecordRequest<T>,
) -> Result<PutRecordResponse> {
    let url = build_url(
        base_url,
        "/xrpc/com.atproto.repo.putRecord",
        iter::empty::<(&str, &str)>(),
    )?
    .to_string();

    let value = serde_json::to_value(record)?;

    match auth {
        Auth::None => post_json(http_client, &url, value)
            .await
            .and_then(|value| serde_json::from_value(value).map_err(|err| err.into())),
        Auth::DPoP(dpop_auth) => post_dpop_json(http_client, dpop_auth, &url, value)
            .await
            .and_then(|value| serde_json::from_value(value).map_err(|err| err.into())),
        Auth::AppPassword(app_auth) => post_apppassword_json(http_client, app_auth, &url, value)
            .await
            .and_then(|value| serde_json::from_value(value).map_err(|err| err.into())),
    }
}

/// Request to delete a record from an AT Protocol repository.
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Serialize, Deserialize, Clone)]
pub struct DeleteRecordRequest {
    /// Repository identifier (DID)
    pub repo: String,
    /// Collection NSID (e.g., "app.bsky.feed.post")
    pub collection: String,

    /// Record key to delete
    #[serde(rename = "rkey")]
    pub record_key: String,

    /// Optional commit CID to swap (for atomic updates)
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        rename = "swapCommit"
    )]
    pub swap_commit: Option<String>,

    /// Optional record CID to swap (for atomic updates)
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        rename = "swapRecord"
    )]
    pub swap_record: Option<String>,
}

/// Response from deleting a record in an AT Protocol repository.
#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Deserialize, Clone)]
#[serde(untagged)]
pub enum DeleteRecordResponse {
    /// Successfully deleted record with commit information
    Commit {
        /// Commit information as a map of fields
        #[serde(flatten)]
        commit: HashMap<String, serde_json::Value>,
    },

    /// Error response from the server
    Error(SimpleError),
}

/// Deletes a record from an AT Protocol repository.
///
/// # Arguments
///
/// * `http_client` - HTTP client for making requests
/// * `auth` - Authentication method (None, DPoP, or AppPassword)
/// * `base_url` - Base URL of the AT Protocol server
/// * `record` - Record deletion request with repository, collection, and key
///
/// # Returns
///
/// The deletion response with commit information or an error
pub async fn delete_record(
    http_client: &reqwest::Client,
    auth: &Auth,
    base_url: &str,
    record: DeleteRecordRequest,
) -> Result<DeleteRecordResponse> {
    let url = build_url(
        base_url,
        "/xrpc/com.atproto.repo.deleteRecord",
        iter::empty::<(&str, &str)>(),
    )?
    .to_string();

    let value = serde_json::to_value(record)?;

    match auth {
        Auth::None => post_json(http_client, &url, value)
            .await
            .and_then(|value| serde_json::from_value(value).map_err(|err| err.into())),
        Auth::DPoP(dpop_auth) => post_dpop_json(http_client, dpop_auth, &url, value)
            .await
            .and_then(|value| serde_json::from_value(value).map_err(|err| err.into())),
        Auth::AppPassword(app_auth) => post_apppassword_json(http_client, app_auth, &url, value)
            .await
            .and_then(|value| serde_json::from_value(value).map_err(|err| err.into())),
    }
}
