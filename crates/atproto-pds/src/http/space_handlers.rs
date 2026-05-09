//! XRPC HTTP handlers for `com.atproto.space.*`.
//!
//! Surface ():
//!
//! Management (owner-only, OAuth):
//! - `POST /xrpc/com.atproto.space.createSpace`
//! - `GET  /xrpc/com.atproto.space.getSpace`
//! - `GET  /xrpc/com.atproto.space.listSpaces`
//! - `POST /xrpc/com.atproto.space.addMember`
//! - `POST /xrpc/com.atproto.space.removeMember`
//! - `GET  /xrpc/com.atproto.space.getMembers`
//!
//! Records (member-OAuth or remote SpaceCredential):
//! - `POST /xrpc/com.atproto.space.applyWrites`
//! - `GET  /xrpc/com.atproto.space.getRecord`
//! - `GET  /xrpc/com.atproto.space.listRecords`
//!
//! Sync (read-only state + oplog):
//! - `GET  /xrpc/com.atproto.space.getRepoState`
//! - `GET  /xrpc/com.atproto.space.getRepoOplog`
//! - `GET  /xrpc/com.atproto.space.getMemberState`
//! - `GET  /xrpc/com.atproto.space.getMemberOplog`
//!
//! Credentials (member + owner two-step flow):
//! - `POST /xrpc/com.atproto.space.getMemberGrant`  (member-OAuth)
//! - `POST /xrpc/com.atproto.space.getSpaceCredential`  (no auth — grant *is* the auth)

use crate::account::AccountManager;
use crate::actor_store::sql::SqlActorStore;
use crate::errors::PdsError;
use crate::http::auth::{bearer_token, request_htm_htu, require_authn_sub};
use crate::http::errors::XrpcError;
use crate::http::space_auth::{
    SpaceTokenKind, classify, local_signing_key, verify_local_member_grant,
};
use crate::http::state::HttpState;
use crate::space::notify::upsert_recipient;
use crate::space::reader::SpaceReadAuth;
use crate::space::writer::{SpaceCommitResult, SpaceWriteAction, SpaceWriteOp};
use crate::space::{SpaceReader, SpaceService, SpaceSync, SpaceWriter};
use atproto_space::credential::{
    MEMBER_GRANT_TTL_SECS, create_member_grant, create_space_credential,
};
use atproto_space::types::SpaceUri;
use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ---------------------------------------------------------------------------
//  Service availability gates.
// ---------------------------------------------------------------------------

fn space_service(state: &HttpState) -> Result<&Arc<SpaceService>, XrpcError> {
    state.space_service.as_ref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "SpacesUnavailable",
            "Spaces are not enabled on this PDS",
        )
    })
}

fn space_writer(state: &HttpState) -> Result<&Arc<SpaceWriter>, XrpcError> {
    state.space_writer.as_ref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "SpacesUnavailable",
            "Spaces writes are not enabled on this PDS",
        )
    })
}

fn space_reader(state: &HttpState) -> Result<&Arc<SpaceReader>, XrpcError> {
    state.space_reader.as_ref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "SpacesUnavailable",
            "Spaces reads are not enabled on this PDS",
        )
    })
}

fn space_sync(state: &HttpState) -> Result<&Arc<SpaceSync>, XrpcError> {
    state.space_sync.as_ref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "SpacesUnavailable",
            "Spaces sync is not enabled on this PDS",
        )
    })
}

fn account_manager(state: &HttpState) -> Result<&Arc<AccountManager>, XrpcError> {
    state.account_manager.as_ref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account management is not configured on this PDS",
        )
    })
}

// ---------------------------------------------------------------------------
//  Auth helpers (HTTP layer).
//
//  Bearer token extraction lives in `crate::http::auth::bearer_token` and the
//  full OAuth-or-session-and-DPoP check lives in `require_authn`. The thin
//  wrapper here forwards to the unified helper so handlers can keep their
//  `parts: Parts` signatures unchanged.
// ---------------------------------------------------------------------------

/// Async wrapper around `auth::require_authn_sub` — derives htm/htu from the
/// live request and runs the full session-or-OAuth + DPoP check. Returns
/// just the subject DID since Spaces management endpoints don't care about
/// the rest of the OAuth claims.
async fn require_session_subject(parts: &Parts, state: &HttpState) -> Result<String, XrpcError> {
    let (htm, htu) = request_htm_htu(parts);
    require_authn_sub(parts, state, &htm, &htu).await
}

// ---------------------------------------------------------------------------
//  Management endpoints.
// ---------------------------------------------------------------------------

/// Inputs for `createSpace`.
#[derive(Debug, Deserialize)]
pub struct CreateSpaceInput {
    /// NSID space type (e.g., `app.bsky.group`).
    #[serde(rename = "spaceType")]
    pub space_type: String,
    /// Caller-chosen key.
    #[serde(rename = "spaceKey")]
    pub space_key: String,
}

/// Output of `createSpace` / `getSpace`.
pub use crate::space::SpaceInfo;

/// `POST /xrpc/com.atproto.space.createSpace`.
pub async fn create_space(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<CreateSpaceInput>,
) -> Result<Json<SpaceInfo>, XrpcError> {
    let owner_did = require_session_subject(&parts, &state).await?;
    let svc = space_service(&state)?;
    let info = svc
        .create_space(&owner_did, &input.space_type, &input.space_key)
        .await
        .map_err(XrpcError::from)?;
    Ok(Json(info))
}

/// Query params for `getSpace`.
#[derive(Debug, Deserialize)]
pub struct GetSpaceQuery {
    /// Full `ats://...` URI of the space.
    pub space: String,
}

/// `GET /xrpc/com.atproto.space.getSpace`.
pub async fn get_space(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<GetSpaceQuery>,
) -> Result<Json<SpaceInfo>, XrpcError> {
    let viewer = require_session_subject(&parts, &state).await?;
    let uri = parse_space_uri(&q.space)?;
    let svc = space_service(&state)?;
    svc.get_space(&viewer, &uri)
        .await
        .map_err(XrpcError::from)?
        .map(Json)
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::NOT_FOUND,
                "SpaceNotFound",
                format!("no such space {uri}"),
            )
        })
}

/// Query params for `listSpaces`.
#[derive(Debug, Deserialize)]
pub struct ListSpacesQuery {
    /// `"owned"` | `"member"` | `"all"`.
    #[serde(default = "default_filter")]
    pub filter: String,
    /// Cursor (last `uri` from prior page).
    pub cursor: Option<String>,
    /// Page size.
    pub limit: Option<u32>,
}

fn default_filter() -> String {
    "all".to_string()
}

/// Output of `listSpaces`.
#[derive(Debug, Serialize)]
pub struct ListSpacesResponse {
    /// Page of spaces.
    pub spaces: Vec<SpaceInfo>,
}

/// `GET /xrpc/com.atproto.space.listSpaces`.
pub async fn list_spaces(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<ListSpacesQuery>,
) -> Result<Json<ListSpacesResponse>, XrpcError> {
    let viewer = require_session_subject(&parts, &state).await?;
    let svc = space_service(&state)?;
    let spaces = svc
        .list_spaces(
            &viewer,
            &q.filter,
            q.cursor.as_deref(),
            q.limit.unwrap_or(50),
        )
        .await
        .map_err(XrpcError::from)?;
    Ok(Json(ListSpacesResponse { spaces }))
}

/// Inputs for `addMember` / `removeMember`.
#[derive(Debug, Deserialize)]
pub struct MemberInput {
    /// Space URI.
    pub space: String,
    /// DID of the member to add or remove.
    pub did: String,
}

/// `POST /xrpc/com.atproto.space.addMember`.
pub async fn add_member(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<MemberInput>,
) -> Result<StatusCode, XrpcError> {
    let owner = require_session_subject(&parts, &state).await?;
    let uri = parse_space_uri(&input.space)?;
    space_service(&state)?
        .add_member(&owner, &uri, &input.did)
        .await
        .map_err(XrpcError::from)?;
    if state.notify_membership_email {
        notify_membership_change(&state, &input.did, &uri, "added").await;
    }
    Ok(StatusCode::OK)
}

/// `POST /xrpc/com.atproto.space.removeMember`.
pub async fn remove_member(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<MemberInput>,
) -> Result<StatusCode, XrpcError> {
    let owner = require_session_subject(&parts, &state).await?;
    let uri = parse_space_uri(&input.space)?;
    space_service(&state)?
        .remove_member(&owner, &uri, &input.did)
        .await
        .map_err(XrpcError::from)?;
    if state.notify_membership_email {
        notify_membership_change(&state, &input.did, &uri, "removed").await;
    }
    Ok(StatusCode::OK)
}

/// Best-effort: send a notification email to the affected member when
/// `PDS_NOTIFY_MEMBERSHIP_EMAIL` is enabled. Logs
/// continues on any failure (no email address, send error).
async fn notify_membership_change(state: &HttpState, member_did: &str, uri: &SpaceUri, verb: &str) {
    // Lookup member's email — only send when the affected member is on
    // this PDS and has a confirmed email. Cross-PDS members are skipped
    // (we'd need a service-auth proxy to reach their PDS, out of scope).
    let directory = state.reader.accounts();
    let row = match directory.lookup_did(member_did).await {
        Ok(Some(r)) => r,
        _ => {
            tracing::debug!(member_did, "membership-email: member not local; skipping");
            return;
        }
    };
    let Some(email) = row.email else {
        tracing::debug!(
            member_did,
            "membership-email: no email on account; skipping"
        );
        return;
    };
    let subject = match verb {
        "added" => "You've been added to a Spaces group",
        "removed" => "You've been removed from a Spaces group",
        _ => "Spaces membership change",
    };
    let body = format!(
        "Your account ({member_did}) has been {verb} {} the Spaces group {uri}.\n\n\
         If you didn't expect this, contact the space owner via your client.",
        if verb == "added" { "to" } else { "from" }
    );
    if let Err(e) = state.email.send(&email, subject, &body).await {
        tracing::warn!(error = ?e, member_did, "membership-email send failed");
    }
}

/// Query params for `getMembers`.
#[derive(Debug, Deserialize)]
pub struct GetMembersQuery {
    /// Space URI.
    pub space: String,
    /// Cursor.
    pub cursor: Option<String>,
    /// Page size.
    pub limit: Option<u32>,
}

/// Output of `getMembers`.
#[derive(Debug, Serialize)]
pub struct GetMembersResponse {
    /// Member DIDs on this page.
    pub members: Vec<MemberRowDto>,
    /// Cursor for the next page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Wire-shape of a member row.
#[derive(Debug, Serialize)]
pub struct MemberRowDto {
    /// Member DID.
    pub did: String,
    /// Rev (TID) at which this member was added.
    #[serde(rename = "memberRev")]
    pub member_rev: String,
    /// ISO-8601 add timestamp.
    #[serde(rename = "addedAt")]
    pub added_at: String,
}

/// `GET /xrpc/com.atproto.space.getMembers`.
pub async fn get_members(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<GetMembersQuery>,
) -> Result<Json<GetMembersResponse>, XrpcError> {
    let owner = require_session_subject(&parts, &state).await?;
    let uri = parse_space_uri(&q.space)?;
    let page = space_service(&state)?
        .list_members(&owner, &uri, q.cursor.as_deref(), q.limit.unwrap_or(50))
        .await
        .map_err(XrpcError::from)?;
    Ok(Json(GetMembersResponse {
        members: page
            .members
            .into_iter()
            .map(|m| MemberRowDto {
                did: m.did,
                member_rev: m.member_rev,
                added_at: m.added_at,
            })
            .collect(),
        cursor: page.cursor,
    }))
}

// ---------------------------------------------------------------------------
//  Records: applyWrites / getRecord / listRecords.
// ---------------------------------------------------------------------------

/// One write inside `applyWrites`.
#[derive(Debug, Deserialize)]
pub struct ApplyWritesOp {
    /// `"create"` | `"update"` | `"delete"`.
    pub action: String,
    /// NSID collection.
    pub collection: String,
    /// Record key (empty allowed for create — auto-TID).
    #[serde(default)]
    pub rkey: String,
    /// Record value (omitted for delete).
    pub value: Option<serde_json::Value>,
}

/// Inputs for `applyWrites`.
#[derive(Debug, Deserialize)]
pub struct ApplyWritesInput {
    /// Space URI.
    pub space: String,
    /// Write batch.
    pub writes: Vec<ApplyWritesOp>,
}

/// Output of `applyWrites` / `createRecord` / `putRecord` / `deleteRecord`.
pub use crate::space::writer::SpaceCommitResult as ApplyWritesResponse;

/// `POST /xrpc/com.atproto.space.applyWrites`.
pub async fn apply_writes(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<ApplyWritesInput>,
) -> Result<Json<SpaceCommitResult>, XrpcError> {
    let member_did = require_session_subject(&parts, &state).await?;
    let uri = parse_space_uri(&input.space)?;
    let writer = space_writer(&state)?;

    if input.writes.is_empty() {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "applyWrites requires at least one op",
        ));
    }

    let mut ops = Vec::with_capacity(input.writes.len());
    for w in input.writes {
        let action = match w.action.as_str() {
            "create" => SpaceWriteAction::Create,
            "update" => SpaceWriteAction::Update,
            "delete" => SpaceWriteAction::Delete,
            other => {
                return Err(XrpcError::new(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    format!("invalid action {other:?}"),
                ));
            }
        };
        ops.push(SpaceWriteOp {
            action,
            collection: w.collection,
            rkey: w.rkey,
            value: w.value,
        });
    }

    writer
        .apply_writes(&member_did, &uri, ops)
        .await
        .map(Json)
        .map_err(XrpcError::from)
}

/// Query params for `getRecord`.
#[derive(Debug, Deserialize)]
pub struct GetSpaceRecordQuery {
    /// Space URI.
    pub space: String,
    /// NSID collection.
    pub collection: String,
    /// Record key.
    pub rkey: String,
}

/// Output of `getRecord`.
#[derive(Debug, Serialize)]
pub struct GetSpaceRecordResponse {
    /// AT-URI of the record (`ats://owner/type/key/collection/rkey`).
    pub uri: String,
    /// CID of the record value (DAG-CBOR).
    pub cid: String,
    /// Decoded record value (DAG-CBOR → JSON best-effort via `serde_json`).
    pub value: serde_json::Value,
}

/// `GET /xrpc/com.atproto.space.getRecord`.
pub async fn get_record(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<GetSpaceRecordQuery>,
) -> Result<Json<GetSpaceRecordResponse>, XrpcError> {
    let uri = parse_space_uri(&q.space)?;
    let auth = resolve_record_auth(&parts, &state).await?;
    let row = space_reader(&state)?
        .get_record(&uri, auth, &q.collection, &q.rkey)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::NOT_FOUND,
                "RecordNotFound",
                format!("no record at {}/{}/{}", uri, q.collection, q.rkey),
            )
        })?;
    let value: serde_json::Value = atproto_dasl::from_slice(&row.value).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("decode record value: {e}"),
        )
    })?;
    Ok(Json(GetSpaceRecordResponse {
        uri: format!("{}/{}/{}", uri, q.collection, q.rkey),
        cid: row.cid,
        value,
    }))
}

/// Query params for `listRecords`.
#[derive(Debug, Deserialize)]
pub struct ListSpaceRecordsQuery {
    /// Space URI.
    pub space: String,
    /// NSID collection.
    pub collection: String,
    /// Cursor (last `rkey`).
    pub cursor: Option<String>,
    /// Page size.
    pub limit: Option<u32>,
}

/// One record in `listRecords`.
#[derive(Debug, Serialize)]
pub struct SpaceRecordItem {
    /// AT-URI.
    pub uri: String,
    /// CID.
    pub cid: String,
    /// Decoded value.
    pub value: serde_json::Value,
}

/// Output of `listRecords`.
#[derive(Debug, Serialize)]
pub struct ListSpaceRecordsResponse {
    /// Page of records.
    pub records: Vec<SpaceRecordItem>,
    /// Cursor for the next page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// `GET /xrpc/com.atproto.space.listRecords`.
pub async fn list_records(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<ListSpaceRecordsQuery>,
) -> Result<Json<ListSpaceRecordsResponse>, XrpcError> {
    let uri = parse_space_uri(&q.space)?;
    let auth = resolve_record_auth(&parts, &state).await?;
    let page = space_reader(&state)?
        .list_records(
            &uri,
            auth,
            &q.collection,
            q.cursor.as_deref(),
            q.limit.unwrap_or(50),
        )
        .await
        .map_err(XrpcError::from)?;
    let mut records = Vec::with_capacity(page.records.len());
    for r in page.records {
        let value: serde_json::Value = atproto_dasl::from_slice(&r.value).map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("decode record value: {e}"),
            )
        })?;
        records.push(SpaceRecordItem {
            uri: format!("{}/{}/{}", uri, r.collection, r.rkey),
            cid: r.cid,
            value,
        });
    }
    Ok(Json(ListSpaceRecordsResponse {
        records,
        cursor: page.cursor,
    }))
}

/// Decide which auth flavor a record-read uses based on the bearer token's
/// `typ` header. Owns the borrow of `parts` so callers don't need separate
/// branches.
async fn resolve_record_auth<'a>(
    parts: &'a Parts,
    state: &HttpState,
) -> Result<SpaceReadAuth<'a>, XrpcError> {
    let raw = bearer_token(parts)?;
    match classify(raw) {
        Some(SpaceTokenKind::SpaceCredential) => Ok(SpaceReadAuth::SpaceCredential {
            token: raw,
            // Issuer-binding simplification: bind to the issuer's
            // `client_id` claim rather than enforcing an HTTP-layer
            // expected client. The SpaceReader will re-verify the JWT
            // including its `client_id` claim; we pass the same value
            // here so that check is a no-op. The follow-up tracked in
            // pulls the expected `client_id` from a
            // DPoP/cnf binding on the peer access token wrapping this
            // credential.
            expected_client_id: extract_credential_client_id(raw)
                .map(|s| Box::leak(s.into_boxed_str()) as &str)
                .unwrap_or(""),
        }),
        Some(SpaceTokenKind::MemberGrant) => Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "MemberGrant cannot be used to read records; exchange it at getSpaceCredential first",
        )),
        _ => {
            // Treat as a session-style or OAuth access token. The unified
            // helper transparently accepts both shapes and enforces DPoP
            // when an OAuth token carries a `cnf.jkt` thumbprint.
            let (htm, htu) = request_htm_htu(parts);
            let sub = require_authn_sub(parts, state, &htm, &htu).await?;
            let did_static: &'a str = Box::leak(sub.into_boxed_str());
            Ok(SpaceReadAuth::OwnPds {
                account_did: did_static,
            })
        }
    }
}

/// Best-effort extraction of `clientId` from a SpaceCredential JWT *without*
/// signature verification — used solely to forward the value into
/// `SpaceReadAuth::SpaceCredential::expected_client_id` so the reader's
/// re-verification accepts the same bound `client_id`.
fn extract_credential_client_id(token: &str) -> Option<String> {
    let payload_b64 = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64.as_bytes())
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    Some(value.get("clientId")?.as_str()?.to_string())
}

// ---------------------------------------------------------------------------
//  Sync endpoints.
// ---------------------------------------------------------------------------

/// Query params for `getRepoState`.
#[derive(Debug, Deserialize)]
pub struct RepoStateQuery {
    /// Space URI.
    pub space: String,
    /// Member DID whose record-state to fetch.
    pub member: String,
}

/// Output of `getRepoState` / `getMemberState`.
#[derive(Debug, Serialize)]
pub struct StateResponse {
    /// Hex-encoded SetHash digest. `null` if empty.
    #[serde(rename = "setHash")]
    pub set_hash: Option<String>,
    /// Latest rev (TID). `null` if empty.
    pub rev: Option<String>,
}

/// `GET /xrpc/com.atproto.space.getRepoState`.
pub async fn get_repo_state(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<RepoStateQuery>,
) -> Result<Json<StateResponse>, XrpcError> {
    require_any_authn(&parts, &state).await?;
    let uri = parse_space_uri(&q.space)?;
    let st = space_sync(&state)?
        .get_repo_state(&uri, &q.member)
        .await
        .map_err(XrpcError::from)?;
    Ok(Json(StateResponse {
        set_hash: st.set_hash.as_deref().map(hex::encode),
        rev: st.rev,
    }))
}

/// Query params for `getRepoOplog`.
#[derive(Debug, Deserialize)]
pub struct RepoOplogQuery {
    /// Space URI.
    pub space: String,
    /// Member DID.
    pub member: String,
    /// Rev to start *after* (exclusive).
    pub since: Option<String>,
    /// Page size.
    pub limit: Option<u32>,
}

/// One oplog entry in the wire form.
#[derive(Debug, Serialize)]
pub struct OplogEntryDto {
    /// Rev (TID).
    pub rev: String,
    /// Index within the batch.
    pub idx: u32,
    /// Action.
    pub action: String,
    /// NSID collection (records only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection: Option<String>,
    /// Record key (records only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rkey: Option<String>,
    /// New CID (records only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    /// Prior CID (records only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    /// DID (members only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
}

/// Output of `getRepoOplog` / `getMemberOplog`.
#[derive(Debug, Serialize)]
pub struct OplogResponse {
    /// Oplog ops on this page (rev,idx ascending).
    pub ops: Vec<OplogEntryDto>,
    /// Current state at read time.
    pub state: StateResponse,
}

/// `GET /xrpc/com.atproto.space.getRepoOplog`.
pub async fn get_repo_oplog(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<RepoOplogQuery>,
) -> Result<Json<OplogResponse>, XrpcError> {
    require_any_authn(&parts, &state).await?;
    let uri = parse_space_uri(&q.space)?;
    let page = space_sync(&state)?
        .get_repo_oplog(&uri, &q.member, q.since.as_deref(), q.limit.unwrap_or(100))
        .await
        .map_err(XrpcError::from)?;
    Ok(Json(oplog_to_dto(page)))
}

/// Query params for `getMemberState`.
#[derive(Debug, Deserialize)]
pub struct MemberStateQuery {
    /// Space URI.
    pub space: String,
}

/// `GET /xrpc/com.atproto.space.getMemberState`.
pub async fn get_member_state(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<MemberStateQuery>,
) -> Result<Json<StateResponse>, XrpcError> {
    require_any_authn(&parts, &state).await?;
    let uri = parse_space_uri(&q.space)?;
    let st = space_sync(&state)?
        .get_member_state(&uri)
        .await
        .map_err(XrpcError::from)?;
    Ok(Json(StateResponse {
        set_hash: st.set_hash.as_deref().map(hex::encode),
        rev: st.rev,
    }))
}

/// Query params for `getMemberOplog`.
#[derive(Debug, Deserialize)]
pub struct MemberOplogQuery {
    /// Space URI.
    pub space: String,
    /// Rev to start after.
    pub since: Option<String>,
    /// Page size.
    pub limit: Option<u32>,
}

/// `GET /xrpc/com.atproto.space.getMemberOplog`.
pub async fn get_member_oplog(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<MemberOplogQuery>,
) -> Result<Json<OplogResponse>, XrpcError> {
    require_any_authn(&parts, &state).await?;
    let uri = parse_space_uri(&q.space)?;
    let page = space_sync(&state)?
        .get_member_oplog(&uri, q.since.as_deref(), q.limit.unwrap_or(100))
        .await
        .map_err(XrpcError::from)?;
    Ok(Json(oplog_to_dto(page)))
}

fn oplog_to_dto(page: atproto_space::storage::OplogPage) -> OplogResponse {
    OplogResponse {
        ops: page
            .ops
            .into_iter()
            .map(|o| OplogEntryDto {
                rev: o.rev,
                idx: o.idx,
                action: o.action,
                collection: o.collection,
                rkey: o.rkey,
                cid: o.cid,
                prev: o.prev,
                did: o.did,
            })
            .collect(),
        state: StateResponse {
            set_hash: page.state.set_hash.as_deref().map(hex::encode),
            rev: page.state.rev,
        },
    }
}

// ---------------------------------------------------------------------------
//  Credential mint endpoints.
// ---------------------------------------------------------------------------

/// Inputs for `getMemberGrant`.
#[derive(Debug, Deserialize)]
pub struct GetMemberGrantInput {
    /// Space URI.
    pub space: String,
    /// OAuth `client_id` of the requesting app.
    #[serde(rename = "clientId")]
    pub client_id: String,
}

/// Output of `getMemberGrant` and `getSpaceCredential`.
#[derive(Debug, Serialize)]
pub struct TokenWrapper {
    /// The compact-form JWT.
    pub token: String,
    /// Expiry in seconds since epoch.
    #[serde(rename = "expiresAt")]
    pub expires_at: u64,
}

/// `POST /xrpc/com.atproto.space.getMemberGrant` — member-OAuth gated.
/// Mints a [`MemberGrant`](atproto_space::credential::MemberGrant) signed by
/// the member's atproto signing key, scoped to the given `clientId`.
pub async fn get_member_grant(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<GetMemberGrantInput>,
) -> Result<Json<TokenWrapper>, XrpcError> {
    let member_did = require_session_subject(&parts, &state).await?;
    let uri = parse_space_uri(&input.space)?;
    let manager = account_manager(&state)?;
    let signing_key = local_signing_key(manager, &member_did).await?;
    let token = create_member_grant(
        &member_did,
        &uri.owner_did,
        &uri,
        &input.client_id,
        &signing_key,
        MEMBER_GRANT_TTL_SECS,
    )
    .map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("mint MemberGrant: {e}"),
        )
    })?;
    Ok(Json(TokenWrapper {
        token,
        expires_at: now_secs() + MEMBER_GRANT_TTL_SECS,
    }))
}

/// Inputs for `getSpaceCredential` — the grant *is* the auth.
#[derive(Debug, Deserialize)]
pub struct GetSpaceCredentialInput {
    /// MemberGrant compact-form JWT.
    pub grant: String,
}

/// `POST /xrpc/com.atproto.space.getSpaceCredential` — grant-gated.
/// Verifies the [`MemberGrant`](atproto_space::credential::MemberGrant)
/// against the member's signing key, then mints a
/// [`SpaceCredential`](atproto_space::credential::SpaceCredential) signed by
/// the owner's signing key.
pub async fn get_space_credential(
    State(state): State<HttpState>,
    Json(input): Json<GetSpaceCredentialInput>,
) -> Result<Json<TokenWrapper>, XrpcError> {
    let manager = account_manager(&state)?;

    // First, peek the grant payload to learn space + clientId so we can
    // verify against the right key.
    let payload_b64 = input.grant.split('.').nth(1).ok_or_else(|| {
        XrpcError::new(StatusCode::BAD_REQUEST, "InvalidToken", "grant: malformed")
    })?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64.as_bytes())
        .map_err(|_| {
            XrpcError::new(
                StatusCode::BAD_REQUEST,
                "InvalidToken",
                "grant: payload not base64url",
            )
        })?;
    let unverified: atproto_space::credential::MemberGrant = serde_json::from_slice(&bytes)
        .map_err(|_| {
            XrpcError::new(
                StatusCode::BAD_REQUEST,
                "InvalidToken",
                "grant: payload not JSON",
            )
        })?;

    let space = parse_space_uri(&unverified.space)?;
    // §3.3: try the local path first (fast); on `AccountNotFound` (the
    // member is not on this PDS), fall through to the remote path that
    // resolves the member's DID document via atproto-identity.
    let payload = match verify_local_member_grant(
        manager,
        &state.jti_guard,
        &input.grant,
        &space.owner_did,
        &space,
        &unverified.client_id,
    )
    .await
    {
        Ok(p) => p,
        Err(e) if e.status == StatusCode::NOT_FOUND && e.name == "AccountNotFound" => {
            tracing::debug!(
                member = %unverified.iss,
                "member not local; attempting cross-PDS DID-document resolution"
            );
            let plc_dir = state.plc_service.as_ref().map(|p| p.directory_hostname());
            let http = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .user_agent(crate::user_agent())
                .build()
                .unwrap_or_default();
            crate::http::space_auth::verify_remote_member_grant(
                &http,
                &state.jti_guard,
                &input.grant,
                &space.owner_did,
                &space,
                &unverified.client_id,
                plc_dir,
            )
            .await?
        }
        Err(e) => return Err(e),
    };

    let owner_signing = local_signing_key(manager, &space.owner_did).await?;
    let credential_ttl = state.space_credential_ttl_secs;
    let token = create_space_credential(
        &space.owner_did,
        &space,
        &payload.client_id,
        &owner_signing,
        credential_ttl,
    )
    .map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("mint SpaceCredential: {e}"),
        )
    })?;

    // Register the consumer in `space_credential_recipient` so the notifier
    // can fan out future commits to this client. Idempotent on
    // `(space, service_did)` — re-issuing to the same client just bumps
    // `last_issued_at`.
    //
    // §3.2: discover the consumer's actual `(service_did, service_endpoint)`
    // by resolving `<host_of_client_id>/.well-known/atproto-did` and the
    // resulting DID document's `AtprotoPersonalDataServer` service. Falls
    // back to a documented stub `(grant.iss, client_id-origin)` when any
    // step fails — that's the same behavior the §3.2 audit identified, but
    // now flagged as `fully_resolved=false` so operators can audit.
    let plc_dir = state.plc_service.as_ref().map(|p| p.directory_hostname());
    let recipient_http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(crate::user_agent())
        .build()
        .unwrap_or_default();
    let resolved = match crate::space::recipient::resolve_recipient(
        &recipient_http,
        &payload.iss,
        &payload.client_id,
        plc_dir,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                error = ?e,
                client_id = %payload.client_id,
                "recipient resolution failed; falling back to stub"
            );
            crate::space::recipient::stub_recipient(&payload.iss, &payload.client_id)
        }
    };
    if !resolved.fully_resolved {
        tracing::warn!(
            client_id = %payload.client_id,
            stub_did = %resolved.service_did,
            stub_endpoint = %resolved.service_endpoint,
            "recipient resolved via stub; consumer DID document was unreachable or missing a PDS service entry"
        );
    }

    match SqlActorStore::open(manager.data_dir(), &space.owner_did).await {
        Ok(owner_store) => {
            if let Err(e) = upsert_recipient(
                owner_store.pool(),
                &space,
                &resolved.service_did,
                &resolved.service_endpoint,
            )
            .await
            {
                tracing::warn!(
                    error = ?e,
                    space = %space,
                    client_id = %payload.client_id,
                    "register space_credential_recipient failed; this consumer will not receive notifyWrite/notifyMembership"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                error = ?e,
                space = %space,
                "failed to open owner per-actor store while registering recipient"
            );
        }
    }

    Ok(Json(TokenWrapper {
        token,
        expires_at: now_secs() + credential_ttl,
    }))
}

// ---------------------------------------------------------------------------
//  Helpers.
// ---------------------------------------------------------------------------

fn parse_space_uri(s: &str) -> Result<SpaceUri, XrpcError> {
    SpaceUri::parse(s).map_err(|e| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            format!("invalid space URI: {e}"),
        )
    })
}

/// Sync endpoints accept either a session/OAuth access token or a
/// SpaceCredential. / G35 the PDS does not enforce
/// membership at sync time — we just require *some* valid token shape.
/// OAuth tokens with a DPoP `cnf.jkt` binding still trigger the proof
/// check via the unified helper.
async fn require_any_authn(parts: &Parts, state: &HttpState) -> Result<(), XrpcError> {
    let raw = bearer_token(parts)?;
    if let Some(SpaceTokenKind::SpaceCredential) = classify(raw) {
        // We don't have the space URI here for full verification, but the
        // structural typ check is enough — the reader handlers re-verify
        // signatures against owner keys on every record read. Sync endpoints
        // are intentionally permissive; consumers do inductive verification.
        return Ok(());
    }
    let (htm, htu) = request_htm_htu(parts);
    require_authn_sub(parts, state, &htm, &htu)
        .await
        .map(|_| ())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
//  Inbound notify endpoints (§3.1).
// ---------------------------------------------------------------------------

/// `POST /xrpc/com.atproto.space.notifyWrite` — receive a notify-write
/// payload from a remote owner PDS.
///
/// Authentication is structural: the embedded signed `Commit` must
/// verify against the owner's atproto signing key (resolved from the
/// owner's DID document). No bearer token is required — the signature
/// IS the auth, and the `(space, rev)` dedup keeps replays harmless.
///
/// The `?recipient=<did>` query parameter selects which local account's
/// per-actor store records the receipt. Typically this is the local
/// account holding the `SpaceCredential` for the named space.
pub async fn notify_write(
    State(state): State<HttpState>,
    Query(q): Query<NotifyRecipientQuery>,
    body: axum::body::Bytes,
) -> Result<StatusCode, XrpcError> {
    let manager = account_manager(&state)?;
    let plc_dir = state.plc_service.as_ref().map(|p| p.directory_hostname());
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(crate::user_agent())
        .build()
        .unwrap_or_default();
    crate::space::inbound::receive_write(
        &http,
        plc_dir,
        manager.data_dir(),
        &q.recipient,
        body.as_ref(),
    )
    .await
    .map_err(XrpcError::from)?;
    Ok(StatusCode::OK)
}

/// `POST /xrpc/com.atproto.space.notifyMembership` — receive a
/// notify-membership payload from a remote owner PDS.
pub async fn notify_membership(
    State(state): State<HttpState>,
    Query(q): Query<NotifyRecipientQuery>,
    body: axum::body::Bytes,
) -> Result<StatusCode, XrpcError> {
    let manager = account_manager(&state)?;
    let plc_dir = state.plc_service.as_ref().map(|p| p.directory_hostname());
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(crate::user_agent())
        .build()
        .unwrap_or_default();
    crate::space::inbound::receive_membership(
        &http,
        plc_dir,
        manager.data_dir(),
        &q.recipient,
        body.as_ref(),
    )
    .await
    .map_err(XrpcError::from)?;
    Ok(StatusCode::OK)
}

/// Query params for the inbound notify-* endpoints.
#[derive(Debug, Deserialize)]
pub struct NotifyRecipientQuery {
    /// DID of the local account this PDS hosts that should record the
    /// receipt. The notifying peer learned this DID from the
    /// `getSpaceCredential` flow.
    pub recipient: String,
}

// ---------------------------------------------------------------------------
//  Export / import endpoints (§3.4).
// ---------------------------------------------------------------------------

/// Query params for `exportSpaces`.
#[derive(Debug, Deserialize)]
pub struct ExportSpacesQuery {
    /// Space URI (`ats://owner/type/key`).
    pub space: String,
    /// DID whose record-set should be exported. When omitted the export
    /// emits a member-list-only manifest (owner-side migration shape).
    pub member: Option<String>,
}

/// `GET /xrpc/com.atproto.space.exportSpaces` — stream a CARv1 of the
/// requested `(member, space)` records + member list.
///
/// Auth model: the caller must be the space owner or the named member.
/// This bounds the export to actors who are authorized to read that
/// data via the existing `getRecord` / `getMembers` paths.
pub async fn export_spaces(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<ExportSpacesQuery>,
) -> Result<axum::response::Response, XrpcError> {
    use axum::http::header;
    use axum::response::IntoResponse;

    let caller = require_session_subject(&parts, &state).await?;
    let uri = parse_space_uri(&q.space)?;
    let manager = account_manager(&state)?;
    let _ = space_service(&state)?; // gate on Spaces being enabled

    // Authorize: caller must be owner OR the named member.
    let caller_is_owner = caller == uri.owner_did;
    let caller_is_named_member = q.member.as_deref() == Some(caller.as_str());
    if !caller_is_owner && !caller_is_named_member {
        return Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "exportSpaces requires owner or named-member auth",
        ));
    }

    // Buffer the CAR in memory. CARv1 export size for a space scales
    // with record count — the simple buffered shape ships today; a
    // future streaming bridge would use `axum::body::Body::from_stream`.
    let mut car_bytes: Vec<u8> = Vec::new();
    crate::space::export::export_to_writer(
        manager.data_dir(),
        &uri,
        q.member.as_deref(),
        &mut car_bytes,
    )
    .await
    .map_err(XrpcError::from)?;

    let mut response = (StatusCode::OK, car_bytes).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/vnd.ipld.car".parse().unwrap(),
    );
    Ok(response)
}

/// Query params for `importSpaces`.
#[derive(Debug, Deserialize)]
pub struct ImportSpacesQuery {
    /// Optional override for the manifest-declared space URI.
    pub space: Option<String>,
    /// Optional override for the manifest-declared member DID.
    pub member: Option<String>,
}

/// Output of `importSpaces`.
#[derive(Debug, Serialize)]
pub struct ImportSpacesResponse {
    /// Space URI restored.
    pub space: String,
    /// Imported member DID, when the export carried records for one.
    #[serde(rename = "memberDid", skip_serializing_if = "Option::is_none")]
    pub member_did: Option<String>,
    /// Number of records inserted.
    #[serde(rename = "recordsInserted")]
    pub records_inserted: usize,
    /// Number of members inserted.
    #[serde(rename = "membersInserted")]
    pub members_inserted: usize,
}

/// `POST /xrpc/com.atproto.space.importSpaces` — restore a previously
/// exported CARv1 onto this PDS.
///
/// Auth model: the caller must be the destination space owner OR the
/// destination member DID. Override query params let callers retarget
/// the import (useful after handle/DID migration); the override DID
/// must match the auth subject.
pub async fn import_spaces(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<ImportSpacesQuery>,
    body: axum::body::Bytes,
) -> Result<Json<ImportSpacesResponse>, XrpcError> {
    let caller = require_session_subject(&parts, &state).await?;
    let manager = account_manager(&state)?;
    let _ = space_service(&state)?; // gate on Spaces being enabled

    // Resolve target overrides up-front so we can authorize.
    let target_space = match q.space.as_deref() {
        Some(s) => Some(parse_space_uri(s)?),
        None => None,
    };
    let target_member = q.member.as_deref();

    // Authorize: when targeting a specific member DID, caller must equal
    // that member. When targeting only a space, caller must be its
    // owner. When neither override is provided, defer the auth check
    // until we've decoded the manifest below (we pull the manifest's
    // claimed (space, member) and re-check).
    if let Some(m) = target_member
        && m != caller
    {
        return Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "importSpaces member override must match the authenticated subject",
        ));
    }
    if let Some(ref s) = target_space
        && target_member.is_none()
        && s.owner_did != caller
    {
        return Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "importSpaces requires owner auth when no member override is set",
        ));
    }

    let outcome = crate::space::export::import_from_reader(
        manager.data_dir(),
        std::io::Cursor::new(body.to_vec()),
        target_space.as_ref(),
        target_member,
    )
    .await
    .map_err(XrpcError::from)?;

    // Post-decode authorization: if no overrides were supplied, the
    // manifest's claimed (space, member) must square with the caller.
    if target_space.is_none() && target_member.is_none() {
        let restored_space = SpaceUri::parse(&outcome.space).map_err(PdsError::Space)?;
        let manifest_member = outcome.member_did.as_deref();
        let caller_is_owner = caller == restored_space.owner_did;
        let caller_is_named_member = manifest_member == Some(caller.as_str());
        if !caller_is_owner && !caller_is_named_member {
            return Err(XrpcError::new(
                StatusCode::FORBIDDEN,
                "Forbidden",
                "importSpaces caller is neither owner nor the manifest's member",
            ));
        }
    }

    Ok(Json(ImportSpacesResponse {
        space: outcome.space,
        member_did: outcome.member_did,
        records_inserted: outcome.records_inserted,
        members_inserted: outcome.members_inserted,
    }))
}
