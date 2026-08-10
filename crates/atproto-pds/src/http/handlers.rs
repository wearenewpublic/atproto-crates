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
use crate::errors::PdsError;
use crate::http::errors::XrpcError;
use crate::http::extract::{XrpcJson as Json, XrpcQuery as Query};
use crate::http::state::HttpState;
use crate::repo::{DescribeRepoResponse, ListRecordsResponse, RecordResponse, RepoStatusResponse};
use axum::extract::State;
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};

/// `GET /` — a plain-text description of this server.
///
/// A browser pointed at the host used to get an empty 404, which says nothing
/// about what is running, whether it is healthy, or where to go next. The
/// reference serves a short description for the same reason, and this is the
/// first thing anyone sees when they type the hostname in.
///
/// Plain text, not HTML: it is read by people diagnosing a deployment as often
/// as by browsers, and `curl` should show the same thing the browser does. The
/// account portal is linked because it is the one page here a person can
/// actually use.
pub async fn root(State(state): State<HttpState>) -> impl axum::response::IntoResponse {
    let host = state
        .service_did
        .strip_prefix("did:web:")
        .unwrap_or(&state.service_did)
        // A did:web may percent-encode a port as `%3A`.
        .replace("%3A", ":");
    let version = format!("{}+{}", env!("CARGO_PKG_VERSION"), BUILD_REV);
    let body = format!(
        "This is an AT Protocol Personal Data Server (an atproto PDS).\n\
         \n\
         Host:     {host}\n\
         DID:      {did}\n\
         Software: atproto-pds {version}\n\
         \n\
         Most API routes are under /xrpc/\n\
         Account portal:  /account\n\
         Health:          /xrpc/_health\n\
         \n\
         Protocol: https://atproto.com\n",
        host = host,
        did = state.service_did,
        version = version,
    );
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        body,
    )
}

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
        .await
        .map_err(|err| match err {
            // The only `NotFound` this call can still raise is an unhosted
            // repository, and `getRecord` declares no name for that: its one
            // declared error is `RecordNotFound`, which would claim this server
            // holds the repo and not the record. The reference implementation
            // answers a repo it cannot locate with a bare `InvalidRequestError`,
            // so report the generic `InvalidRequest` every XRPC client already
            // understands rather than a name no lexicon mentions. Mapped here,
            // at the one endpoint that needs it, rather than in the shared
            // `PdsError` conversion that a dozen other methods depend on.
            PdsError::NotFound { what } => {
                XrpcError::new(StatusCode::BAD_REQUEST, "InvalidRequest", what)
            }
            other => XrpcError::from(other),
        })?;
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
    let mut response = state.reader.describe_repo(&params.repo).await?;
    response.did_doc = Some(local_did_document(&state, &response.did, &response.handle).await?);
    Ok(Json(response))
}

/// Build the DID document for an account this server hosts.
///
/// Synthesised from local state rather than resolved from PLC. The lexicon
/// marks `didDoc` required, so resolving would make `describeRepo` fail
/// outright whenever the directory is unreachable — for a field whose useful
/// contents (the handle, the signing key, the PDS endpoint) this server is
/// itself the authority for.
///
/// The tradeoff: an account whose PLC document already points at another PDS
/// mid-migration is described here as still living on this one. `describeRepo`
/// is only meaningful for accounts this server holds, so that window is the
/// migration itself.
async fn local_did_document(
    state: &HttpState,
    did: &str,
    handle: &str,
) -> Result<serde_json::Value, XrpcError> {
    use atproto_identity::key::to_public;
    use atproto_identity::model::DocumentBuilder;

    let mut builder = DocumentBuilder::new()
        .add_context("https://www.w3.org/ns/did/v1")
        .add_context("https://w3id.org/security/multikey/v1")
        .id(did.to_string())
        .add_also_known_as(format!("at://{handle}"));

    if let Some(origin) = state
        .service_did
        .strip_prefix("did:web:")
        .map(|host| format!("https://{}", host.replace("%3A", ":")))
    {
        builder = builder.add_pds_service(origin);
    }

    // The signing key is what a consumer needs in order to verify this
    // account's commits, so a document without it is not much use.
    if let Some(manager) = state.account_manager.as_deref() {
        match crate::http::space_auth::local_signing_key(manager, did).await {
            Ok(private) => match to_public(&private) {
                Ok(public) => {
                    builder = builder.add_multikey(
                        format!("{did}#atproto"),
                        did.to_string(),
                        public.to_string(),
                    );
                }
                Err(err) => {
                    tracing::warn!(did, error = %err, "describeRepo: could not derive public signing key");
                }
            },
            Err(err) => {
                tracing::warn!(did, error = ?err, "describeRepo: could not load signing key");
            }
        }
    }

    let document = builder.build().map_err(|reason| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("build DID document: {reason}"),
        )
    })?;
    serde_json::to_value(document).map_err(|err| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("encode DID document: {err}"),
        )
    })
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
    // Gated here rather than inside the reader: `listRepos` shares that method
    // and must list taken-down repositories rather than refuse them.
    state.reader.require_available(&params.did).await?;
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

    // Availability first, and before any store is opened: a takedown that
    // still serves the whole repository CAR has not taken anything down.
    let did = state.reader.require_available(&params.did).await?.did;
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
    // Same gate as `getRepo`, for the same reason: raw blocks are the
    // repository's contents by another name.
    let did = state.reader.require_available(&params.did).await?.did;
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

/// Query for `com.atproto.sync.getRecord`.
#[derive(Debug, serde::Deserialize)]
pub struct SyncGetRecordParams {
    /// Repository DID.
    pub did: String,
    /// NSID collection.
    pub collection: String,
    /// Record key.
    pub rkey: String,
}

/// Handler for `GET /xrpc/com.atproto.sync.getRecord`.
///
/// A proof, not a lookup. The CAR carries the signed commit, the MST nodes
/// along the path to the key, and the record block when there is one, so a
/// caller can check the record belongs to this repository without trusting
/// this server. `com.atproto.repo.getRecord` hands over the value and asks to
/// be believed.
///
/// That distinction is why this being absent broke more than sync. It is the
/// only fetch `@atproto/lex-resolver` makes when an authorization server
/// resolves an OAuth permission set, so a lexicon published to a repository
/// here could not be resolved by any server running the reference stack --
/// surfacing to the user as `invalid_scope`, naming no method and no host.
///
/// Unauthenticated, per the lexicon: the caller is an authorization server
/// that has never seen this one.
pub async fn sync_get_record(
    State(state): State<HttpState>,
    Query(params): Query<SyncGetRecordParams>,
) -> Result<axum::response::Response, XrpcError> {
    use crate::actor_store::sql::SqlActorStore;
    use crate::repo::car_export::{export_record_proof_car, export_record_proof_car_via_backend};
    use axum::http::header;
    use axum::response::IntoResponse;

    // Same gate as `getRepo` and `getBlocks`, which is where the lexicon's
    // takendown / suspended / deactivated errors come from.
    let did = state.reader.require_available(&params.did).await?.did;

    let car_bytes = if let Some(backend) = state.public_realm_backend.as_ref() {
        export_record_proof_car_via_backend(backend, &did, &params.collection, &params.rkey).await?
    } else {
        let data_dir = state.reader.data_dir().clone();
        let store = SqlActorStore::open(&data_dir, &did).await?;
        export_record_proof_car(&store, &params.collection, &params.rkey).await?
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
    crate::crawl::announce(&state.crawlers, &hostname).await;
    Ok(StatusCode::OK)
}
