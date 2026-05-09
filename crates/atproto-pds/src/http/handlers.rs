//! XRPC HTTP handler functions.
//!
//! Read-only + sync surface:
//! - `GET /xrpc/com.atproto.repo.getRecord`
//! - `GET /xrpc/com.atproto.repo.listRecords`
//! - `GET /xrpc/com.atproto.repo.describeRepo`
//! - `GET /xrpc/com.atproto.sync.getLatestCommit`
//! - `GET /xrpc/com.atproto.sync.getRepoStatus`
//! - `GET /xrpc/_health`
//! - `GET /_alive`, `GET /_ready`

use crate::BUILD_REV;
use crate::http::errors::XrpcError;
use crate::http::state::HttpState;
use crate::repo::{DescribeRepoResponse, ListRecordsResponse, RecordResponse, RepoStatusResponse};
use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};

/// Liveness probe — process up.
pub async fn alive() -> StatusCode {
    StatusCode::OK
}

/// Readiness probe — accounts DB reachable.
pub async fn ready(State(state): State<HttpState>) -> Result<StatusCode, XrpcError> {
    use sqlx::Connection;
    let mut conn = state
        .reader
        .accounts()
        .pool()
        .acquire()
        .await
        .map_err(|e| XrpcError::new(StatusCode::SERVICE_UNAVAILABLE, "NotReady", e.to_string()))?;
    conn.ping()
        .await
        .map_err(|e| XrpcError::new(StatusCode::SERVICE_UNAVAILABLE, "NotReady", e.to_string()))?;
    Ok(StatusCode::OK)
}

/// AT Protocol spec-compliant health endpoint.
///
/// Beyond the spec-required `version`, also exposes the SetHash impl name so
/// federation peers can confirm interop without trial-and-error commits.
pub async fn xrpc_health() -> Json<Value> {
    Json(json!({
        "version": format!("{}+{}", env!("CARGO_PKG_VERSION"), BUILD_REV),
        "status": "ok",
        "setHash": crate::realm::SET_HASH_NAME,
    }))
}

/// Query parameters for `com.atproto.repo.getRecord`.
#[derive(Debug, Deserialize)]
pub struct GetRecordParams {
    /// DID or handle of the repo.
    pub repo: String,
    /// NSID collection.
    pub collection: String,
    /// Record key.
    pub rkey: String,
    /// Optional CID to require an exact match.
    pub cid: Option<String>,
}

/// Handler for `com.atproto.repo.getRecord`.
pub async fn get_record(
    State(state): State<HttpState>,
    Query(params): Query<GetRecordParams>,
) -> Result<Json<RecordResponse>, XrpcError> {
    let response = state
        .reader
        .get_record(
            &params.repo,
            &params.collection,
            &params.rkey,
            params.cid.as_deref(),
        )
        .await?;
    Ok(Json(response))
}

/// Query parameters for `com.atproto.repo.listRecords`.
#[derive(Debug, Deserialize)]
pub struct ListRecordsParams {
    /// DID or handle of the repo.
    pub repo: String,
    /// NSID collection.
    pub collection: String,
    /// Page size (1..=100). Default 50.
    #[serde(default = "default_limit")]
    pub limit: u32,
    /// Page cursor (last `rkey` from prior page).
    pub cursor: Option<String>,
    /// Reverse-sort the page.
    #[serde(default)]
    pub reverse: bool,
}

fn default_limit() -> u32 {
    50
}

/// Handler for `com.atproto.repo.listRecords`.
pub async fn list_records(
    State(state): State<HttpState>,
    Query(params): Query<ListRecordsParams>,
) -> Result<Json<ListRecordsResponse>, XrpcError> {
    let response = state
        .reader
        .list_records(
            &params.repo,
            &params.collection,
            params.limit,
            params.cursor.as_deref(),
            params.reverse,
        )
        .await?;
    Ok(Json(response))
}

/// Query parameters for `com.atproto.repo.describeRepo`.
#[derive(Debug, Deserialize)]
pub struct DescribeRepoParams {
    /// DID or handle of the repo.
    pub repo: String,
}

/// Handler for `com.atproto.repo.describeRepo`.
pub async fn describe_repo(
    State(state): State<HttpState>,
    Query(params): Query<DescribeRepoParams>,
) -> Result<Json<DescribeRepoResponse>, XrpcError> {
    let response = state.reader.describe_repo(&params.repo).await?;
    Ok(Json(response))
}

/// Query parameters carrying just a `did`.
#[derive(Debug, Deserialize)]
pub struct DidParam {
    /// DID or handle.
    pub did: String,
}

/// Handler for `com.atproto.sync.getLatestCommit`.
pub async fn get_latest_commit(
    State(state): State<HttpState>,
    Query(params): Query<DidParam>,
) -> Result<Json<Value>, XrpcError> {
    let result = state.reader.get_latest_commit(&params.did).await?;
    match result {
        Some(commit) => Ok(Json(json!({"cid": commit.cid, "rev": commit.rev}))),
        None => Err(XrpcError::new(
            StatusCode::NOT_FOUND,
            "RepoNotFound",
            "no commits in repo",
        )),
    }
}

/// Handler for `com.atproto.sync.getRepoStatus`.
pub async fn get_repo_status(
    State(state): State<HttpState>,
    Query(params): Query<DidParam>,
) -> Result<Json<RepoStatusResponse>, XrpcError> {
    let response = state.reader.get_repo_status(&params.did).await?;
    Ok(Json(response))
}

/// Query parameters for `com.atproto.sync.getRepo`.
#[derive(Debug, Deserialize)]
pub struct GetRepoParams {
    /// DID or handle of the repo.
    pub did: String,
    /// Optional `since=<rev>` cursor. Per Sync 1.1,
    /// when supplied, the response is a CARv1 diff slice — only blocks
    /// reachable from `head` that are NOT reachable from the `since` rev.
    /// Subscribers holding the snapshot at `since` apply the diff to advance
    /// their MST without re-downloading the whole repo.
    pub since: Option<String>,
}

/// Handler for `com.atproto.sync.getRepo` — returns the repo as a CAR v1 stream.
pub async fn get_repo(
    State(state): State<HttpState>,
    Query(params): Query<GetRepoParams>,
) -> Result<axum::response::Response, XrpcError> {
    use crate::actor_store::sql::SqlActorStore;
    use crate::repo::car_export::{
        export_repo_car, export_repo_car_since, export_repo_car_since_via_backend,
        export_repo_car_via_backend,
    };
    use axum::http::header;
    use axum::response::IntoResponse;

    let directory = state.reader.accounts();
    let did = if params.did.starts_with("did:") {
        params.did.clone()
    } else {
        directory
            .lookup_handle(&params.did)
            .await?
            .ok_or_else(|| {
                XrpcError::new(
                    StatusCode::BAD_REQUEST,
                    "RepoNotFound",
                    format!("handle {} not found", params.did),
                )
            })?
            .did
    };
    let car_bytes = if let Some(backend) = state.public_realm_backend.as_ref() {
        match params.since.as_deref() {
            Some(since) => export_repo_car_since_via_backend(backend, &did, since).await?,
            None => export_repo_car_via_backend(backend, &did).await?,
        }
    } else {
        let data_dir = state.reader.data_dir().clone();
        let store = SqlActorStore::open(&data_dir, &did).await?;
        match params.since.as_deref() {
            Some(since) => export_repo_car_since(&store, since).await?,
            None => export_repo_car(&store).await?,
        }
    };
    let mut response = (StatusCode::OK, car_bytes).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/vnd.ipld.car".parse().unwrap(),
    );
    Ok(response)
}

/// Query parameters for `com.atproto.sync.getBlocks`.
#[derive(Debug, Deserialize)]
pub struct GetBlocksParams {
    /// DID or handle of the repo.
    pub did: String,
    /// Comma-separated CIDs (axum doesn't auto-deserialize repeated params).
    pub cids: String,
}

/// Handler for `com.atproto.sync.getBlocks`.
pub async fn get_blocks(
    State(state): State<HttpState>,
    Query(params): Query<GetBlocksParams>,
) -> Result<axum::response::Response, XrpcError> {
    use crate::actor_store::sql::SqlActorStore;
    use crate::repo::car_export::{export_blocks_car, export_blocks_car_via_backend};
    use axum::http::header;
    use axum::response::IntoResponse;

    let cids: Vec<String> = params
        .cids
        .split(',')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    if cids.is_empty() {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "cids must be a comma-separated list of CIDs",
        ));
    }
    let directory = state.reader.accounts();
    let did = if params.did.starts_with("did:") {
        params.did.clone()
    } else {
        directory
            .lookup_handle(&params.did)
            .await?
            .ok_or_else(|| {
                XrpcError::new(
                    StatusCode::BAD_REQUEST,
                    "RepoNotFound",
                    format!("handle {} not found", params.did),
                )
            })?
            .did
    };
    let car_bytes = if let Some(backend) = state.public_realm_backend.as_ref() {
        export_blocks_car_via_backend(backend, &did, &cids).await?
    } else {
        let data_dir = state.reader.data_dir().clone();
        let store = SqlActorStore::open(&data_dir, &did).await?;
        export_blocks_car(&store, &cids).await?
    };
    let mut response = (StatusCode::OK, car_bytes).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/vnd.ipld.car".parse().unwrap(),
    );
    Ok(response)
}

// ---------------------------------------------------------------------------
//  §11b — requestCrawl.
// ---------------------------------------------------------------------------

/// Inputs for `com.atproto.sync.requestCrawl`.
#[derive(Debug, serde::Deserialize)]
pub struct RequestCrawlInput {
    /// Hostname this PDS exposes (the crawler will subscribe to its
    /// firehose). Operators typically set this via the request body so a
    /// single PDS can announce itself to multiple crawlers in one call.
    /// Defaults to the configured `service_did` host when omitted.
    pub hostname: Option<String>,
}

/// Handler for `POST /xrpc/com.atproto.sync.requestCrawl`. For each entry in `PDS_CRAWLERS`, POSTs a minimal request-crawl
/// payload announcing this PDS's hostname so the crawler starts
/// consuming the firehose. Per-crawler failures log + continue; the
/// handler always returns 200 so a partial outage doesn't fail the
/// caller's outbound crawl.
pub async fn request_crawl(
    State(state): State<HttpState>,
    body: Option<Json<RequestCrawlInput>>,
) -> Result<StatusCode, XrpcError> {
    let hostname = body
        .as_ref()
        .and_then(|b| b.hostname.clone())
        .unwrap_or_else(|| {
            state
                .service_did
                .strip_prefix("did:web:")
                .unwrap_or(&state.service_did)
                .to_string()
        });
    if state.crawlers.is_empty() {
        tracing::info!(hostname = %hostname, "requestCrawl: no PDS_CRAWLERS configured; no-op");
        return Ok(StatusCode::OK);
    }
    let http = reqwest::Client::builder()
        .user_agent(crate::user_agent())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();
    for base in &state.crawlers {
        let endpoint = format!(
            "{}/xrpc/com.atproto.sync.requestCrawl",
            base.trim_end_matches('/')
        );
        let body = serde_json::json!({ "hostname": hostname });
        let result = http
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .body(serde_json::to_vec(&body).unwrap_or_default())
            .send()
            .await;
        match result {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(crawler = %endpoint, hostname = %hostname, "requestCrawl: announced");
            }
            Ok(resp) => {
                tracing::warn!(crawler = %endpoint, status = %resp.status(), "requestCrawl: non-2xx");
            }
            Err(e) => {
                tracing::warn!(crawler = %endpoint, error = ?e, "requestCrawl: forward failed");
            }
        }
    }
    Ok(StatusCode::OK)
}
