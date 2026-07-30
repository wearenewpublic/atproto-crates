//! HTTP handlers for `com.atproto.sync.getBlob` + `listBlobs`.
//!
//! `getBlob` is **public** per the lexicon — anyone can fetch a blob by CID
//! when they know which DID hosts it. (Privacy is handled at the record
//! layer; if a record references a blob, the blob is reachable.)
//! `listBlobs` is also public.
//!
//! Because it is public and serves attacker-supplied bytes under an
//! attacker-declared MIME type, `getBlob` responds with `nosniff`,
//! `content-disposition: attachment` and a `default-src 'none'; sandbox` CSP.
//! Without them an uploaded `text/html` blob renders as a document on the
//! origin that also serves the OAuth consent screen and its session cookies.

use crate::actor_store::sql::SqlActorStore;
use crate::http::errors::XrpcError;
use crate::http::extract::XrpcQuery as Query;
use crate::http::state::HttpState;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use serde::{Deserialize, Serialize};

/// Query params for `com.atproto.sync.getBlob`.
#[derive(Debug, Deserialize)]
pub struct GetBlobQuery {
    /// DID of the repo hosting the blob.
    pub did: String,
    /// CID of the blob.
    pub cid: String,
}

/// `GET /xrpc/com.atproto.sync.getBlob`.
///
/// Responds with the blob bytes under the stored MIME type, plus the three
/// headers that keep a blob from rendering as a document on this origin.
///
/// When a `PublicRealmBackend` is wired into `HttpState` (per
/// ), the blob lookup dispatches through the
/// `BlobStorage` trait so fjall-mode deployments serve blobs from the
/// fjall keyspace. Without the backend, the legacy SQLite-direct path
/// runs.
pub async fn get_blob(
    State(state): State<HttpState>,
    Query(q): Query<GetBlobQuery>,
) -> Result<Response, XrpcError> {
    // Availability before storage. `SqlActorStore::open` creates the directory
    // and runs migrations, so gating after it would let an unauthenticated
    // caller materialise a SQLite file for every DID it cared to invent.
    let did = state.reader.require_available(&q.did).await?.did;

    // Blob-level takedown. Checked before the bytes are fetched and reported as
    // `BlobNotFound` rather than a distinct error: an operator removing an
    // illegal image should not leave behind a response that confirms it is
    // still stored here.
    //
    // The takedown row lives in the per-actor SQLite on both storage profiles,
    // so this gate holds whether the bytes came from SQLite or from fjall.
    {
        let manager = state.account_manager.as_deref().ok_or_else(|| {
            XrpcError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "AccountManagementUnavailable",
                "account manager not configured",
            )
        })?;
        let store = SqlActorStore::open(manager.data_dir(), &did)
            .await
            .map_err(XrpcError::from)?;
        if crate::takedown::get_blob(&store, &q.cid)
            .await
            .map_err(XrpcError::from)?
            .is_some()
        {
            return Err(XrpcError::new(
                StatusCode::NOT_FOUND,
                "BlobNotFound",
                format!("no blob {} for {}", q.cid, q.did),
            ));
        }
    }

    // Public means publicly referenced. `repo_blob` holds public and
    // permissioned bytes together — permissioned blobs arrive through the
    // ordinary `uploadBlob`, since there is no space-specific upload endpoint —
    // so serving by CID alone let anyone holding a CID read permissioned
    // content with no credential at all. CIDs are high-entropy but not secret:
    // they appear in space oplog entries, in `listRepoOps`, in any indexing
    // AppView, in logs, and to every member including one since removed.
    //
    // Reported as `BlobNotFound`, like a takedown: a caller with no business
    // knowing whether these bytes exist should not learn it from the error.
    {
        let manager = state.account_manager.as_deref().ok_or_else(|| {
            XrpcError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "AccountManagementUnavailable",
                "account manager not configured",
            )
        })?;
        let store = SqlActorStore::open(manager.data_dir(), &did)
            .await
            .map_err(XrpcError::from)?;
        if !crate::blob::is_publicly_referenced(&store, &q.cid)
            .await
            .map_err(XrpcError::from)?
        {
            return Err(XrpcError::new(
                StatusCode::NOT_FOUND,
                "BlobNotFound",
                format!("no blob {} for {}", q.cid, q.did),
            ));
        }
    }

    let pair = if let Some(backend) = state.public_realm_backend.as_ref() {
        backend
            .blob
            .get(&did, &q.cid)
            .await
            .map_err(XrpcError::from)?
    } else {
        let manager = state.account_manager.as_deref().ok_or_else(|| {
            XrpcError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "AccountManagementUnavailable",
                "account manager not configured",
            )
        })?;
        let store = SqlActorStore::open(manager.data_dir(), &did)
            .await
            .map_err(XrpcError::from)?;
        crate::blob::get_blob(&store, &q.cid)
            .await
            .map_err(XrpcError::from)?
    };
    let (data, mime) = pair.ok_or_else(|| {
        XrpcError::new(
            StatusCode::NOT_FOUND,
            "BlobNotFound",
            format!("no blob {} for {}", q.cid, q.did),
        )
    })?;
    let mut resp = Response::new(Body::from(data));
    // The MIME comes from the uploader's `content-type` header and is not
    // validated (F-BLOB-08), so a caller can declare `text/html`. This origin
    // also serves the OAuth consent screen and its session cookies, which makes
    // a blob that renders stored XSS against the authorization server. Three
    // headers close that: `nosniff` stops a browser second-guessing a benign
    // declared type, `attachment` makes the response a download rather than a
    // document, and the CSP neuters anything that is rendered regardless.
    //
    // `space.getBlob` has set these since it shipped; this is the same set.
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&mime)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    // The filename is the CID, which reached here only by matching a stored
    // blob, so it is server-generated base32 rather than caller text. Built
    // through `HeaderValue::from_str` anyway, so a value that could not be a
    // well-formed header degrades to a bare `attachment` instead of being
    // interpolated.
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{}\"", q.cid))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
    Ok(resp)
}

/// Query params for `com.atproto.sync.listBlobs`.
#[derive(Debug, Deserialize)]
pub struct ListBlobsQuery {
    /// DID of the repo to list.
    pub did: String,
    /// Cursor (last CID from the prior page).
    pub cursor: Option<String>,
    /// Page size (default 500, max 1000).
    pub limit: Option<u32>,
}

/// Output of `listBlobs`.
#[derive(Debug, Serialize)]
pub struct ListBlobsResponse {
    /// Page of CIDs.
    pub cids: Vec<String>,
    /// Cursor for the next page (None when exhausted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// `GET /xrpc/com.atproto.sync.listBlobs`.
pub async fn list_blobs(
    State(state): State<HttpState>,
    Query(q): Query<ListBlobsQuery>,
) -> Result<axum::Json<ListBlobsResponse>, XrpcError> {
    // Same gate and the same ordering as `getBlob`.
    let did = state.reader.require_available(&q.did).await?.did;
    // The cursor must advance over CIDs *scanned*, not CIDs *kept*. A page in
    // which every blob turned out to be permissioned would otherwise yield an
    // empty `cids` and no cursor, which a client reads as "end of list" while
    // there is more behind it — or, if it restarts from the beginning, as a
    // loop.
    let last_scanned: Option<String>;
    let cids = if let Some(backend) = state.public_realm_backend.as_ref() {
        // The trait cannot express the join — on the fjall profile the bytes are
        // not in a database that knows about records — so the page is filtered
        // after the fact. A page may therefore come back shorter than `limit`;
        // the cursor still advances over the underlying CIDs, so pagination
        // terminates. The SQLite path below joins in SQL and keeps full pages.
        let manager = state.account_manager.as_deref().ok_or_else(|| {
            XrpcError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "AccountManagementUnavailable",
                "account manager not configured",
            )
        })?;
        let store = SqlActorStore::open(manager.data_dir(), &did)
            .await
            .map_err(XrpcError::from)?;
        let all = backend
            .blob
            .list_all_cids(&did, q.cursor.as_deref(), q.limit.unwrap_or(500))
            .await
            .map_err(XrpcError::from)?;
        last_scanned = all.last().cloned();
        let mut kept = Vec::with_capacity(all.len());
        for cid in all {
            if crate::blob::is_publicly_referenced(&store, &cid)
                .await
                .map_err(XrpcError::from)?
            {
                kept.push(cid);
            }
        }
        kept
    } else {
        let manager = state.account_manager.as_deref().ok_or_else(|| {
            XrpcError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "AccountManagementUnavailable",
                "account manager not configured",
            )
        })?;
        let store = SqlActorStore::open(manager.data_dir(), &did)
            .await
            .map_err(XrpcError::from)?;
        // This path joins in SQL, so every row returned is kept and the last
        // row is both the last scanned and the last kept.
        let page = crate::blob::list_all(&store, q.cursor.as_deref(), q.limit.unwrap_or(500))
            .await
            .map_err(XrpcError::from)?;
        last_scanned = page.last().cloned();
        page
    };
    let cursor = last_scanned;
    Ok(axum::Json(ListBlobsResponse { cids, cursor }))
}
