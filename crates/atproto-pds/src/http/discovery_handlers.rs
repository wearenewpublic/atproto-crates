//! Discovery endpoints — how the rest of the network finds out about this
//! server, its accounts, and its own identity.
//!
//! Four routes that are unusually load-bearing for how small they are:
//!
//! - `com.atproto.server.describeServer` — the first call a client makes.
//!   Account migration reads the *new* PDS's `did` from here to learn the
//!   `aud` the old PDS must mint its service-auth token for, so migration
//!   fails at step two without it.
//! - `com.atproto.sync.listRepos` — how a relay discovers which accounts this
//!   server hosts. Without it a relay can subscribe to the firehose but never
//!   learn what to backfill.
//! - `/.well-known/atproto-did` — how a handle hosted on this server's own
//!   domain resolves to a DID. Absent it, the PDS cannot host handles on its
//!   own domain without an external web server synthesising the response.
//! - `/.well-known/did.json` — this server's own `did:web` document, needed by
//!   spaces and service-auth peers that must resolve it.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::account::AccountState;
use crate::http::errors::XrpcError;
use crate::http::state::HttpState;

/// The `https://` origin this server answers on, derived from its service DID.
///
/// Only `did:web` encodes a host; for any other method there is nothing to
/// derive and the caller has to fall back.
fn service_origin(service_did: &str) -> Option<String> {
    service_did
        .strip_prefix("did:web:")
        .map(|host| format!("https://{}", host.replace("%3A", ":")))
}

// ---------------------------------------------------------------------------
//  com.atproto.server.describeServer
// ---------------------------------------------------------------------------

/// Output of `com.atproto.server.describeServer`.
#[derive(Debug, Serialize)]
pub struct DescribeServerResponse {
    /// This server's DID. Clients migrating an account read it to learn the
    /// `aud` for the service-auth token the old PDS must mint.
    pub did: String,
    /// Handle suffixes this server will issue accounts under. Empty when the
    /// operator has pinned none, which means any handle is accepted.
    #[serde(rename = "availableUserDomains")]
    pub available_user_domains: Vec<String>,
    /// Whether `createAccount` requires an invite code.
    #[serde(rename = "inviteCodeRequired")]
    pub invite_code_required: bool,
    /// Whether `createAccount` requires phone verification. Always false —
    /// this server has no phone-verification path.
    #[serde(rename = "phoneVerificationRequired")]
    pub phone_verification_required: bool,
}

/// Handler for `com.atproto.server.describeServer`. Unauthenticated.
pub async fn describe_server(
    State(state): State<HttpState>,
) -> Result<Json<DescribeServerResponse>, XrpcError> {
    Ok(Json(DescribeServerResponse {
        did: state.service_did.clone(),
        available_user_domains: state.service_handle_domains.clone(),
        invite_code_required: state.invite_required,
        phone_verification_required: false,
    }))
}

// ---------------------------------------------------------------------------
//  com.atproto.sync.listRepos
// ---------------------------------------------------------------------------

/// Query parameters for `com.atproto.sync.listRepos`.
#[derive(Debug, Deserialize)]
pub struct ListReposParams {
    /// Page size, clamped to [1, 1000]. Defaults to 500.
    pub limit: Option<u32>,
    /// Opaque cursor — the last DID of the previous page.
    pub cursor: Option<String>,
}

/// One entry of `com.atproto.sync.listRepos#repo`.
#[derive(Debug, Serialize)]
pub struct ListReposRepo {
    /// Account DID.
    pub did: String,
    /// Current repo commit CID.
    pub head: String,
    /// Revision of that commit.
    pub rev: String,
    /// Whether the repository is currently served.
    pub active: bool,
    /// Why it is not, when `active` is false. Omitted when active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Output of `com.atproto.sync.listRepos`.
#[derive(Debug, Serialize)]
pub struct ListReposResponse {
    /// Cursor for the next page, absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// This page of repositories.
    pub repos: Vec<ListReposRepo>,
}

/// Map an account's lifecycle state onto the `active`/`status` pair.
///
/// `status` is only meaningful when `active` is false, and the lexicon's
/// `knownValues` are exactly the non-active states.
fn active_and_status(state: AccountState) -> (bool, Option<String>) {
    match state {
        AccountState::Active => (true, None),
        other => (false, Some(other.as_str().to_string())),
    }
}

/// Handler for `com.atproto.sync.listRepos`. Unauthenticated.
///
/// Accounts with no commits yet are omitted rather than reported with an empty
/// head: `head` and `rev` are required fields, and inventing values for them
/// would have a relay try to fetch a commit that does not exist.
pub async fn list_repos(
    State(state): State<HttpState>,
    Query(params): Query<ListReposParams>,
) -> Result<Json<ListReposResponse>, XrpcError> {
    let limit = params.limit.unwrap_or(500).clamp(1, 1000);
    let accounts = state
        .reader
        .accounts()
        .list_accounts(params.cursor.as_deref(), limit)
        .await
        .map_err(XrpcError::from)?;

    let next_cursor = (accounts.len() as u32 == limit)
        .then(|| accounts.last().map(|row| row.did.clone()))
        .flatten();

    let mut repos = Vec::with_capacity(accounts.len());
    for account in accounts {
        let Some(commit) = state.reader.get_latest_commit(&account.did).await? else {
            continue;
        };
        let (active, status) = active_and_status(account.state);
        repos.push(ListReposRepo {
            did: account.did,
            head: commit.cid,
            rev: commit.rev,
            active,
            status,
        });
    }

    Ok(Json(ListReposResponse {
        cursor: next_cursor,
        repos,
    }))
}

// ---------------------------------------------------------------------------
//  /.well-known/atproto-did
// ---------------------------------------------------------------------------

/// Handler for `GET /.well-known/atproto-did`.
///
/// Resolves the requested `Host` as a handle held on this server and answers
/// with that account's DID as `text/plain`. This is how a handle that *is* a
/// domain this server answers on gets resolved, without the operator standing
/// up a separate web server to synthesise the file.
pub async fn well_known_atproto_did(
    State(state): State<HttpState>,
    parts: Parts,
) -> Result<Response, XrpcError> {
    let host = parts
        .headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(':')
                .next()
                .unwrap_or(value)
                .to_ascii_lowercase()
        })
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "request has no Host header to resolve",
            )
        })?;

    let account = state
        .reader
        .accounts()
        .lookup_handle(&host)
        .await
        .map_err(XrpcError::from)?;

    match account {
        Some(account) if account.state.allows_public_read() => Ok((
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8",
            )],
            account.did,
        )
            .into_response()),
        // A handle this server does not hold, or holds for an account that is
        // no longer served, is a 404 rather than a 200 with an empty body: a
        // resolver must be able to tell "not here" from "here, but blank".
        _ => Err(XrpcError::new(
            StatusCode::NOT_FOUND,
            "NotFound",
            format!("no account with handle {host} on this server"),
        )),
    }
}

// ---------------------------------------------------------------------------
//  /.well-known/did.json
// ---------------------------------------------------------------------------

/// Handler for `GET /.well-known/did.json`.
///
/// Serves this server's own `did:web` document, synthesised from its service
/// DID rather than read from a file on disk. A static file is a second source
/// of truth that can drift from the DID the server actually runs as.
///
/// Returns 404 when the service DID is not a `did:web`, since no other method
/// resolves through this path.
pub async fn well_known_did_json(State(state): State<HttpState>) -> Result<Json<Value>, XrpcError> {
    let origin = service_origin(&state.service_did).ok_or_else(|| {
        XrpcError::new(
            StatusCode::NOT_FOUND,
            "NotFound",
            format!(
                "service DID {} is not a did:web, so it does not resolve through this path",
                state.service_did
            ),
        )
    })?;

    Ok(Json(json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": state.service_did,
        "service": [
            {
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": origin,
            },
            {
                "id": "#atproto_space_host",
                "type": "AtprotoSpaceHost",
                "serviceEndpoint": origin,
            },
        ],
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_origin_derives_the_https_origin() {
        assert_eq!(
            service_origin("did:web:pds.example.com").as_deref(),
            Some("https://pds.example.com")
        );
    }

    /// `did:web` percent-encodes a port as `%3A`.
    #[test]
    fn service_origin_decodes_an_encoded_port() {
        assert_eq!(
            service_origin("did:web:localhost%3A8080").as_deref(),
            Some("https://localhost:8080")
        );
    }

    #[test]
    fn service_origin_is_none_for_other_methods() {
        assert_eq!(service_origin("did:plc:ewvi7nxzyoun6zhxrhs64oiz"), None);
    }

    #[test]
    fn active_accounts_report_no_status() {
        assert_eq!(active_and_status(AccountState::Active), (true, None));
    }

    #[test]
    fn inactive_accounts_report_their_state_as_status() {
        for state in [
            AccountState::Takendown,
            AccountState::Suspended,
            AccountState::Deactivated,
            AccountState::Deleted,
        ] {
            let (active, status) = active_and_status(state);
            assert!(!active, "{state:?} should not be active");
            assert_eq!(status.as_deref(), Some(state.as_str()));
        }
    }
}
