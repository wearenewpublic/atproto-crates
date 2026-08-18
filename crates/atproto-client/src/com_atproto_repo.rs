//! AT Protocol repository operations.
//!
//! Client functions for com.atproto.repo XRPC methods including
//! record CRUD operations with DPoP authentication support.
//! - **`create_record()`**: Create a new record in a repository
//! - **`put_record()`**: Update or create a record with a specific key
//! - **`delete_record()`**: Delete a record from a repository
//! - **`apply_writes()`**: Apply a batch of writes in one commit
//! - **`upload_blob()`**: Upload a blob and get the reference to embed
//! - **`describe_repo()`**: A repository's handle, DID document and collections
//!
//! ## Two generations of function here
//!
//! The record CRUD functions above return `#[serde(untagged)]` response enums
//! with an `Error(SimpleError)` variant, because the transport they are built
//! on returns the body regardless of status. That is enough to read an XRPC
//! error *code* and not enough to tell a `404` from a `503`.
//!
//! The functions added since -- `apply_writes`, `upload_blob`,
//! `describe_repo`, and everything in [`crate::com::atproto::sync`] -- are
//! built on [`crate::client::xrpc_call`] and report a refusal as
//! [`crate::errors::XrpcError`], classified from the status and the error code
//! together. Moving the older ones across is a behaviour change for their
//! callers and is not done here.
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
use atproto_record::lexicon::TypedBlob;
use bytes::Bytes;
use reqwest::Method;
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    client::{
        Auth, DpopBody, decode_xrpc, get_apppassword_json, get_bytes, get_dpop_json, get_json,
        post_apppassword_json, post_dpop_json, post_json, xrpc_call,
    },
    errors::SimpleError,
};

/// Response from getting a record from an AT Protocol repository.
#[derive(Debug, Deserialize, Clone)]
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
#[derive(Debug, Deserialize, Clone)]
pub struct ListRecord<T> {
    /// AT-URI of the record
    pub uri: String,
    /// Content identifier (CID) of the record
    pub cid: String,
    /// The record content
    pub value: T,
}

/// Response from listing records in an AT Protocol repository.
#[derive(Debug, Deserialize, Clone)]
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
#[derive(Debug, Serialize, Deserialize, Clone)]
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
#[derive(Debug, Deserialize, Clone)]
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
#[derive(Debug, Serialize, Deserialize, Clone)]
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
#[derive(Debug, Serialize, Deserialize, Clone)]
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
#[derive(Debug, Serialize, Deserialize, Clone)]
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
#[derive(Debug, Deserialize, Clone)]
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

// ---------------------------------------------------------------------------
//  Batched writes, blobs, and repository description.
// ---------------------------------------------------------------------------

/// The protocol maximum for one `applyWrites` batch.
///
/// The sync specification: "at most 200 record operations can be included in a
/// commit". `atproto-pds` enforces it and refuses the **whole** commit past
/// it, not the excess, so a caller that batches near this number should assert
/// against it in its own tests rather than discover it as a lost batch.
pub const MAX_WRITES_PER_COMMIT: usize = 200;

/// One operation in an `applyWrites` batch.
///
/// The `$type` discriminators are the lexicon's, and a batch whose
/// discriminators are wrong by a word is one every PDS refuses with
/// `InvalidRequest` -- invisible in Rust, which is why they are pinned by a
/// serialization test rather than only by reading.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "$type")]
pub enum WriteOp {
    /// Create a record. The server generates an `rkey` when none is given.
    #[serde(rename = "com.atproto.repo.applyWrites#create")]
    Create {
        /// Collection NSID.
        collection: String,
        /// Record key. Omitted from the wire when `None`, never sent as
        /// `null`: the lexicon declares it optional rather than nullable.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        rkey: Option<String>,
        /// Record value.
        value: serde_json::Value,
    },
    /// Replace a record.
    #[serde(rename = "com.atproto.repo.applyWrites#update")]
    Update {
        /// Collection NSID.
        collection: String,
        /// Record key.
        rkey: String,
        /// Record value.
        value: serde_json::Value,
    },
    /// Remove a record.
    #[serde(rename = "com.atproto.repo.applyWrites#delete")]
    Delete {
        /// Collection NSID.
        collection: String,
        /// Record key.
        rkey: String,
    },
}

/// Input for `com.atproto.repo.applyWrites`.
#[derive(Debug, Clone, Serialize)]
pub struct ApplyWritesRequest {
    /// Repository identifier (DID or handle).
    pub repo: String,
    /// Whether to validate the records against their lexicons.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validate: Option<bool>,
    /// The batch, in the order the server should apply it.
    pub writes: Vec<WriteOp>,
    /// Commit CID to swap against, for an atomic batch.
    #[serde(rename = "swapCommit", skip_serializing_if = "Option::is_none")]
    pub swap_commit: Option<String>,
}

/// Commit metadata returned alongside a write.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct CommitMeta {
    /// CID of the new commit.
    pub cid: String,
    /// Revision (TID) of the new commit.
    pub rev: String,
}

/// One entry of the `applyWrites` results union.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "$type")]
pub enum WriteResult {
    /// A record was created.
    #[serde(rename = "com.atproto.repo.applyWrites#createResult")]
    Create {
        /// AT-URI of the new record.
        uri: String,
        /// CID of the record value.
        cid: String,
        /// What validation the server performed, when it said.
        #[serde(rename = "validationStatus", default)]
        validation_status: Option<String>,
    },
    /// A record was replaced.
    #[serde(rename = "com.atproto.repo.applyWrites#updateResult")]
    Update {
        /// AT-URI of the record.
        uri: String,
        /// CID of the new record value.
        cid: String,
        /// What validation the server performed, when it said.
        #[serde(rename = "validationStatus", default)]
        validation_status: Option<String>,
    },
    /// A record was removed. Carries nothing else, per the lexicon.
    #[serde(rename = "com.atproto.repo.applyWrites#deleteResult")]
    Delete,
    /// A `$type` this client does not know.
    ///
    /// The union is closed, so this means the server is speaking a lexicon
    /// revision this build predates. Refusing to decode the whole response
    /// over it would turn a successful write into an error the caller retries,
    /// creating a duplicate.
    #[serde(other)]
    Unknown,
}

/// Response from `com.atproto.repo.applyWrites`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ApplyWritesResponse {
    /// New commit metadata.
    #[serde(default)]
    pub commit: Option<CommitMeta>,

    /// One result per write, in request order.
    ///
    /// **Optional, and this is not a modelling nicety.** Some PDS builds
    /// answer with a bare commit and no per-op results. Treating that as an
    /// error would turn a *successful* write into one the caller retries,
    /// creating a duplicate -- so a caller that needs the new CIDs has to
    /// handle their absence, and the usual handling is to store nothing and
    /// send the next edit without a `swapRecord`. That is a real loss of
    /// compare-and-swap safety on those deployments. It is worth logging at
    /// `warn`; it is not worth failing over.
    #[serde(default)]
    pub results: Option<Vec<WriteResult>>,
}

/// Applies a batch of writes to a repository in one commit.
///
/// # Errors
///
/// Returns [`crate::errors::XrpcError`] when the server refuses the batch --
/// `InvalidSwap` when the commit moved underneath it, which is the one every
/// correct writer handles by re-reading rather than by reporting a failure.
/// The batch is **not** checked against [`MAX_WRITES_PER_COMMIT`] here: the
/// server's limit is the one that matters and a client-side copy of it would
/// be a second place for it to be wrong.
pub async fn apply_writes(
    http_client: &reqwest::Client,
    auth: &Auth,
    base_url: &str,
    request: &ApplyWritesRequest,
) -> Result<ApplyWritesResponse> {
    let url = build_url(
        base_url,
        "/xrpc/com.atproto.repo.applyWrites",
        iter::empty::<(&str, &str)>(),
    )?
    .to_string();

    let body = serde_json::to_value(request)?;
    let response = xrpc_call(
        http_client,
        auth,
        Method::POST,
        &url,
        Some(DpopBody::Json(&body)),
        &HeaderMap::new(),
    )
    .await?;

    decode_xrpc(response)
}

/// Response from `com.atproto.repo.uploadBlob`.
#[derive(Debug, Clone, Deserialize)]
pub struct UploadBlobResponse {
    /// The blob reference to embed in a record.
    pub blob: TypedBlob,
}

/// Uploads a blob and returns the reference to embed in a record.
///
/// `content_type` is what the server records on the blob and what every later
/// fetch of it will be served as, so it must be the type determined from the
/// bytes -- never the one a browser declared, which a caller does not control.
///
/// # Errors
///
/// Returns [`crate::errors::XrpcError`] when the server refuses the upload,
/// which for this method is usually a size or a MIME-type refusal.
pub async fn upload_blob(
    http_client: &reqwest::Client,
    auth: &Auth,
    base_url: &str,
    content_type: &str,
    data: Vec<u8>,
) -> Result<UploadBlobResponse> {
    let url = build_url(
        base_url,
        "/xrpc/com.atproto.repo.uploadBlob",
        iter::empty::<(&str, &str)>(),
    )?
    .to_string();

    let response = xrpc_call(
        http_client,
        auth,
        Method::POST,
        &url,
        Some(DpopBody::Bytes { content_type, data }),
        &HeaderMap::new(),
    )
    .await?;

    decode_xrpc(response)
}

/// Response from `com.atproto.repo.describeRepo`.
#[derive(Debug, Clone, Deserialize)]
pub struct DescribeRepoResponse {
    /// The repository's handle.
    pub handle: String,
    /// The repository's DID.
    pub did: String,
    /// The DID document, as served.
    #[serde(rename = "didDoc", default)]
    pub did_doc: Option<serde_json::Value>,
    /// Every collection holding at least one record.
    #[serde(default)]
    pub collections: Vec<String>,
    /// Whether the handle resolves back to this DID in both directions.
    #[serde(rename = "handleIsCorrect", default)]
    pub handle_is_correct: bool,

    /// Fields a later lexicon revision added.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Describes a repository: its handle, DID document, and collections.
///
/// # Errors
///
/// Returns [`crate::errors::XrpcError`] when the server refuses, which for
/// this method distinguishes a repository that does not exist from a host that
/// could not answer.
pub async fn describe_repo(
    http_client: &reqwest::Client,
    auth: &Auth,
    base_url: &str,
    repo: &str,
) -> Result<DescribeRepoResponse> {
    let url = build_url(
        base_url,
        "/xrpc/com.atproto.repo.describeRepo",
        [("repo", repo)],
    )?
    .to_string();

    let response = xrpc_call(
        http_client,
        auth,
        Method::GET,
        &url,
        None,
        &HeaderMap::new(),
    )
    .await?;

    decode_xrpc(response)
}
