//! AT Protocol repository synchronization operations.
//!
//! Client functions for `com.atproto.sync` XRPC methods: the repository
//! export and proof surface a relay or an app view reads, as distinct from
//! `com.atproto.repo`, which hands over values and asks to be believed.
//!
//! The distinction matters for one method in particular.
//! `com.atproto.repo.getRecord` returns a record's JSON; [`get_record`] here
//! returns a CAR carrying the signed commit, the MST nodes along the path to
//! the key, and the record block. The second can be checked against the
//! repository's signing key without trusting the server that served it, and
//! the first cannot.
//!
//! CAR-returning methods return raw bytes. Parsing them is
//! `atproto-repo`'s job, and taking a dependency on it here to do that would
//! put an MST implementation in the graph of every crate that only wanted to
//! make an HTTP request.

use std::iter;

use anyhow::Result;
use atproto_identity::url::build_url;
use bytes::Bytes;
use reqwest::Method;
use reqwest::header::HeaderMap;
use serde::Deserialize;

use crate::client::{Auth, decode_xrpc, xrpc_call};
use crate::errors::XrpcError;

/// Fetch bytes rather than JSON, with the status still deciding.
///
/// The CAR methods answer `application/vnd.ipld.car` on success and an XRPC
/// JSON error otherwise, so the status has to be read before the body can be
/// interpreted as either.
async fn get_bytes_checked(http_client: &reqwest::Client, auth: &Auth, url: &str) -> Result<Bytes> {
    let response = xrpc_call(http_client, auth, Method::GET, url, None, &HeaderMap::new()).await?;

    // The status first. A CAR does not parse as JSON, so a transport that
    // reported "the body was not JSON" would report every successful export as
    // a failure and every failure as the same thing.
    if let Some(error) = XrpcError::from_response(&response) {
        return Err(error.into());
    }

    Ok(response.bytes)
}

/// Response from `com.atproto.sync.getLatestCommit`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct LatestCommit {
    /// CID of the repository's most recent commit.
    pub cid: String,
    /// Revision (TID) of that commit.
    pub rev: String,
}

/// The head of a repository: the commit CID and revision it is currently at.
///
/// # Errors
///
/// Returns [`XrpcError`] when the server refuses -- `RepoNotFound` for a
/// repository with no commits, which is a different thing from a host that
/// could not answer.
pub async fn get_latest_commit(
    http_client: &reqwest::Client,
    auth: &Auth,
    base_url: &str,
    did: &str,
) -> Result<LatestCommit> {
    let url = build_url(
        base_url,
        "/xrpc/com.atproto.sync.getLatestCommit",
        [("did", did)],
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

/// Response from `com.atproto.sync.getRepoStatus`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RepoStatus {
    /// The repository's DID.
    pub did: String,
    /// Whether the repository is being served at all.
    pub active: bool,
    /// Why it is not, when it is not: `takendown`, `suspended`, `deactivated`.
    #[serde(default)]
    pub status: Option<String>,
    /// The revision it is at, when it is active.
    #[serde(default)]
    pub rev: Option<String>,
}

/// Whether a repository is being served, and why not when it is not.
///
/// # Errors
///
/// Returns [`XrpcError`] when the server refuses.
pub async fn get_repo_status(
    http_client: &reqwest::Client,
    auth: &Auth,
    base_url: &str,
    did: &str,
) -> Result<RepoStatus> {
    let url = build_url(
        base_url,
        "/xrpc/com.atproto.sync.getRepoStatus",
        [("did", did)],
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

/// A whole repository as a CAR, or the part of it since `since`.
///
/// `since` is a revision (TID), and passing one asks for a diff rather than a
/// full export: the blocks a consumer at that revision does not already have.
/// A relay that stores nothing passes `None` and pays for the whole repo.
///
/// # Errors
///
/// Returns [`XrpcError`] when the server refuses.
pub async fn get_repo(
    http_client: &reqwest::Client,
    auth: &Auth,
    base_url: &str,
    did: &str,
    since: Option<&str>,
) -> Result<Bytes> {
    let mut params = vec![("did", did)];
    if let Some(since) = since {
        params.push(("since", since));
    }
    let url = build_url(base_url, "/xrpc/com.atproto.sync.getRepo", params)?.to_string();

    get_bytes_checked(http_client, auth, &url).await
}

/// Named blocks from a repository, as a CAR.
///
/// # Errors
///
/// Returns [`XrpcError`] when the server refuses. Passing no CIDs is refused
/// by the server as `InvalidRequest` rather than answered with an empty CAR.
pub async fn get_blocks(
    http_client: &reqwest::Client,
    auth: &Auth,
    base_url: &str,
    did: &str,
    cids: &[&str],
) -> Result<Bytes> {
    // Comma-separated, not repeated: the lexicon types this as an array and
    // the reference servers read it either way, but a repeated parameter is
    // what `axum::extract::Query` cannot deserialize, so the joined form is
    // the one every server accepts.
    let joined = cids.join(",");
    let url = build_url(
        base_url,
        "/xrpc/com.atproto.sync.getBlocks",
        [("did", did), ("cids", joined.as_str())],
    )?
    .to_string();

    get_bytes_checked(http_client, auth, &url).await
}

/// One record with the proof that it belongs to the repository, as a CAR.
///
/// Not a lookup. The CAR carries the signed commit, the MST nodes along the
/// path to the key, and the record block when there is one, so a caller can
/// check the record against the repository's signing key without trusting the
/// server that served it. Use `com.atproto.repo.getRecord` when the value is
/// all that is wanted and the server is already trusted.
///
/// Unauthenticated in the lexicon: the usual caller is an authorization server
/// that has never spoken to this one.
///
/// # Errors
///
/// Returns [`XrpcError`] when the server refuses -- `RecordNotFound` for a key
/// the repository does not hold.
pub async fn get_record(
    http_client: &reqwest::Client,
    auth: &Auth,
    base_url: &str,
    did: &str,
    collection: &str,
    rkey: &str,
) -> Result<Bytes> {
    let url = build_url(
        base_url,
        "/xrpc/com.atproto.sync.getRecord",
        [("did", did), ("collection", collection), ("rkey", rkey)],
    )?
    .to_string();

    get_bytes_checked(http_client, auth, &url).await
}

/// One entry of `com.atproto.sync.listRepos`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RepoEntry {
    /// Account DID.
    pub did: String,
    /// Current commit CID.
    pub head: String,
    /// Current revision (TID).
    pub rev: String,
    /// Whether the repository is being served.
    #[serde(default)]
    pub active: Option<bool>,
    /// Why it is not, when it is not.
    #[serde(default)]
    pub status: Option<String>,
}

/// A page of `com.atproto.sync.listRepos`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ListReposResponse {
    /// Cursor for the next page; absent on the last one.
    #[serde(default)]
    pub cursor: Option<String>,
    /// This page of repositories.
    pub repos: Vec<RepoEntry>,
}

/// Every repository a host serves, a page at a time.
///
/// # Errors
///
/// Returns [`XrpcError`] when the server refuses.
pub async fn list_repos(
    http_client: &reqwest::Client,
    auth: &Auth,
    base_url: &str,
    limit: Option<u32>,
    cursor: Option<&str>,
) -> Result<ListReposResponse> {
    let mut url = build_url(
        base_url,
        "/xrpc/com.atproto.sync.listRepos",
        iter::empty::<(&str, &str)>(),
    )?;
    {
        let mut pairs = url.query_pairs_mut();
        if let Some(limit) = limit {
            pairs.append_pair("limit", &limit.to_string());
        }
        if let Some(cursor) = cursor {
            pairs.append_pair("cursor", cursor);
        }
    }
    let url = url.to_string();

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

/// The WebSocket URL for `com.atproto.sync.subscribeRepos`.
///
/// `cursor` is the last sequence number the consumer durably processed, not
/// the next one it wants: the server resumes *after* it. Passing `None` starts
/// at the live edge and skips the backlog, which is what a consumer that has
/// never run wants and what a consumer that has lost its cursor must not do.
///
/// The scheme is derived from `base_url`: `https` becomes `wss` and anything
/// else becomes `ws`, so a local `http://127.0.0.1:2583` develops against a
/// plaintext socket without a second argument saying so.
///
/// # Errors
///
/// Returns an error if `base_url` is not a URL.
pub fn subscribe_repos_url(base_url: &str, cursor: Option<i64>) -> Result<String> {
    let mut url = build_url(
        base_url,
        "/xrpc/com.atproto.sync.subscribeRepos",
        iter::empty::<(&str, &str)>(),
    )?;

    let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
    url.set_scheme(scheme)
        .map_err(|()| anyhow::anyhow!("cannot use scheme {scheme} for {base_url}"))?;

    if let Some(cursor) = cursor {
        url.query_pairs_mut()
            .append_pair("cursor", &cursor.to_string());
    }

    Ok(url.to_string())
}
