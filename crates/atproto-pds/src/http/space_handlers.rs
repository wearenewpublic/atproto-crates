//! XRPC HTTP handlers for `com.atproto.space.*` and `com.atproto.simplespace.*`.
//!
//! Surface:
//!
//! Simplespace management (owner-only, OAuth):
//! - `POST /xrpc/com.atproto.simplespace.createSpace`
//! - `POST /xrpc/com.atproto.simplespace.addMember`
//! - `POST /xrpc/com.atproto.simplespace.removeMember`
//! - `GET  /xrpc/com.atproto.simplespace.listMembers`
//!
//! Space reads (OAuth):
//! - `GET  /xrpc/com.atproto.space.getSpace`
//! - `GET  /xrpc/com.atproto.space.listSpaces`
//!
//! Records (member-OAuth or remote SpaceCredential):
//! - `POST /xrpc/com.atproto.space.applyWrites`
//! - `POST /xrpc/com.atproto.space.createRecord`
//! - `POST /xrpc/com.atproto.space.putRecord`
//! - `POST /xrpc/com.atproto.space.deleteRecord`
//! - `GET  /xrpc/com.atproto.space.getRecord`
//! - `GET  /xrpc/com.atproto.space.listRecords`
//!
//! Sync (read-only state + oplog):
//! - `GET  /xrpc/com.atproto.space.getRepoState`
//! - `GET  /xrpc/com.atproto.space.listRepoOps`
//!
//! Credentials (member + owner two-step flow):
//! - `GET  /xrpc/com.atproto.space.getDelegationToken`  (member-OAuth)
//! - `POST /xrpc/com.atproto.space.getSpaceCredential`  (no auth — grant *is* the auth)

use crate::account::AccountManager;
use crate::actor_store::sql::SqlActorStore;
use crate::http::auth::{bearer_token, request_htm_htu, require_authn, require_authn_sub};
use crate::http::errors::XrpcError;
use crate::http::space_auth::{
    SpaceTokenKind, classify, local_signing_key, peek_delegation_token,
    verify_local_delegation_token,
};
use crate::http::state::HttpState;
use crate::space::notify::upsert_recipient;
use crate::space::reader::SpaceReadAuth;
use crate::space::writer::{SpaceCommitResult, SpaceWriteAction, SpaceWriteOp};
use crate::space::{SpaceReader, SpaceService, SpaceSync, SpaceWriter};
use atproto_space::credential::{
    DELEGATION_TOKEN_TTL_SECS, create_delegation_token, create_space_credential,
};
use atproto_space::storage::OplogCursor;
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

/// Like [`require_session_subject`] but returns the full
/// [`AuthSubject`](crate::http::auth::AuthSubject), so the caller can both
/// read the subject DID and run an [`assert_space_scope`] check on OAuth
/// tokens.
async fn require_session_auth(
    parts: &Parts,
    state: &HttpState,
) -> Result<crate::http::auth::AuthSubject, XrpcError> {
    let (htm, htu) = request_htm_htu(parts);
    require_authn(parts, state, &htm, &htu).await
}

// ---------------------------------------------------------------------------
//  Management endpoints.
// ---------------------------------------------------------------------------

/// Inputs for `com.atproto.simplespace.createSpace`.
///
/// Matches the authoritative lexicon: `{did, type, skey?, config?}`. `did`
/// is the DID of the space authority — it defaults to the authenticated
/// caller and, if supplied, must equal the caller. `skey` auto-generates a
/// TID when absent. `config` carries the initial `#spaceConfig`.
#[derive(Debug, Deserialize)]
pub struct CreateSpaceInput {
    /// DID of the space (the authority). Defaults to the caller.
    pub did: Option<String>,
    /// NSID space type (e.g., `app.bsky.group`).
    #[serde(rename = "type")]
    pub space_type: String,
    /// Space key. Auto-generated as a TID when omitted.
    pub skey: Option<String>,
    /// Initial space configuration (`com.atproto.simplespace.defs#spaceConfig`).
    pub config: Option<serde_json::Value>,
}

/// Output of `createSpace`: `{uri}`.
#[derive(Debug, Serialize)]
pub struct CreateSpaceResponse {
    /// URI of the created space.
    pub uri: String,
}

/// `getSpace` output (`{uri, config}`).
pub use crate::space::GetSpaceOutput;
/// Internal view of a space (re-exported for `listSpaces`).
pub use crate::space::SpaceInfo;

/// `POST /xrpc/com.atproto.simplespace.createSpace`.
pub async fn create_space(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<CreateSpaceInput>,
) -> Result<Json<CreateSpaceResponse>, XrpcError> {
    let subject = require_session_auth(&parts, &state).await?;
    let caller = subject.sub().to_string();
    // The space authority defaults to the caller; an explicit `did` must
    // match (callers may only create spaces under their own authority).
    let authority_did = match input.did {
        Some(ref d) if d != &caller => {
            return Err(XrpcError::new(
                StatusCode::FORBIDDEN,
                "NotSpaceOwner",
                "space did must equal the authenticated caller",
            ));
        }
        Some(d) => d,
        None => caller,
    };
    let skey = input
        .skey
        .unwrap_or_else(|| atproto_record::tid::Tid::new().to_string());
    // OAuth `space:` scope gate (manage). Build the target URI from the
    // resolved authority/type/skey; no-op for app-password sessions.
    let scope_uri = parse_space_uri(&format!(
        "{}{}/{}/{}",
        atproto_space::types::ATS_SCHEME,
        authority_did,
        input.space_type,
        skey
    ))?;
    assert_space_manage(
        &subject,
        &scope_uri,
        atproto_oauth::scopes::SpaceManageVerb::Create,
    )?;
    let config = match input.config {
        Some(ref v) => crate::space::SpaceConfig::from_create_input(v).map_err(XrpcError::from)?,
        None => crate::space::SpaceConfig::default(),
    };
    let svc = space_service(&state)?;
    let info = svc
        .create_space(&authority_did, &input.space_type, &skey, config)
        .await
        .map_err(XrpcError::from)?;
    Ok(Json(CreateSpaceResponse { uri: info.uri }))
}

/// Inputs for `com.atproto.simplespace.updateSpace`.
#[derive(Debug, Deserialize)]
pub struct UpdateSpaceInput {
    /// Space URI to update.
    pub space: String,
    /// New mint policy, if provided.
    #[serde(rename = "mintPolicy")]
    pub mint_policy: Option<String>,
    /// New managing-app identifier. Empty string clears to NULL.
    #[serde(rename = "managingApp")]
    pub managing_app: Option<String>,
    /// New app-access union, if provided (replaces wholesale).
    #[serde(rename = "appAccess")]
    pub app_access: Option<serde_json::Value>,
}

/// `POST /xrpc/com.atproto.simplespace.updateSpace`.
pub async fn update_space(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<UpdateSpaceInput>,
) -> Result<StatusCode, XrpcError> {
    let subject = require_session_auth(&parts, &state).await?;
    let owner = subject.sub().to_string();
    let uri = parse_space_uri(&input.space)?;
    assert_space_manage(
        &subject,
        &uri,
        atproto_oauth::scopes::SpaceManageVerb::Update,
    )?;
    // Reassemble the config-field object the patch parser expects.
    let mut obj = serde_json::Map::new();
    if let Some(p) = input.mint_policy {
        obj.insert("mintPolicy".to_string(), serde_json::Value::String(p));
    }
    if let Some(a) = input.managing_app {
        obj.insert("managingApp".to_string(), serde_json::Value::String(a));
    }
    if let Some(v) = input.app_access {
        obj.insert("appAccess".to_string(), v);
    }
    let patch = crate::space::SpaceConfigPatch::from_update_input(&serde_json::Value::Object(obj))
        .map_err(XrpcError::from)?;
    space_service(&state)?
        .update_space(&owner, &uri, patch)
        .await
        .map_err(XrpcError::from)?;
    Ok(StatusCode::OK)
}

/// Inputs for `com.atproto.simplespace.deleteSpace`.
#[derive(Debug, Deserialize)]
pub struct DeleteSpaceInput {
    /// Space URI to tombstone.
    pub space: String,
}

/// `POST /xrpc/com.atproto.simplespace.deleteSpace`.
pub async fn delete_space(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<DeleteSpaceInput>,
) -> Result<StatusCode, XrpcError> {
    let subject = require_session_auth(&parts, &state).await?;
    let owner = subject.sub().to_string();
    let uri = parse_space_uri(&input.space)?;
    assert_space_manage(
        &subject,
        &uri,
        atproto_oauth::scopes::SpaceManageVerb::Delete,
    )?;
    space_service(&state)?
        .delete_space(&owner, &uri)
        .await
        .map_err(XrpcError::from)?;

    // Best-effort: notify registered recipients + members that the space was
    // deleted (com.atproto.space.notifySpaceDeleted). Failures are swallowed —
    // the tombstone is already durable.
    fire_notify_space_deleted(&state, &uri, &owner).await;

    Ok(StatusCode::OK)
}

/// Best-effort fan-out of `notifySpaceDeleted` to every registered recipient
/// and member of `uri` after the authority deletes the space. Resolves each
/// target's PDS endpoint, mints a service-auth token (iss = authority, aud =
/// target), and POSTs. All errors are logged and swallowed.
async fn fire_notify_space_deleted(state: &HttpState, uri: &SpaceUri, authority_did: &str) {
    let Ok(manager) = account_manager(state) else {
        return;
    };
    let plc_dir = state.plc_service.as_ref().map(|p| p.directory_hostname());
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(crate::user_agent())
        .build()
        .unwrap_or_default();

    // Owner signing key to mint the outbound service-auth tokens.
    let signing_key = match crate::http::space_auth::local_signing_key(manager, authority_did).await
    {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(error = ?e, space = %uri, "notifySpaceDeleted: owner signing key unavailable; skipping fan-out");
            return;
        }
    };

    // Open the owner's per-actor store to read recipients + members.
    let owner_store = match SqlActorStore::open(manager.data_dir(), authority_did).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = ?e, space = %uri, "notifySpaceDeleted: owner store unavailable; skipping fan-out");
            return;
        }
    };

    // Collect distinct target DIDs: recipient services + members.
    let mut targets: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    if let Ok(rows) = sqlx::query_as::<_, (String,)>(
        "SELECT DISTINCT service_did FROM space_credential_recipient WHERE space = ?",
    )
    .bind(uri.to_string())
    .fetch_all(owner_store.pool())
    .await
    {
        for (did,) in rows {
            targets.insert(did);
        }
    }
    if let Ok(rows) = sqlx::query_as::<_, (String,)>("SELECT did FROM space_member WHERE space = ?")
        .bind(uri.to_string())
        .fetch_all(owner_store.pool())
        .await
    {
        for (did,) in rows {
            targets.insert(did);
        }
    }
    targets.remove(authority_did);

    for target in targets {
        if !target.starts_with("did:") {
            continue;
        }
        let endpoint = match crate::space::recipient::resolve_service_endpoint(
            &http,
            &format!("{target}#atproto_pds"),
            plc_dir,
        )
        .await
        {
            Ok(Some(ep)) => ep,
            _ => continue,
        };
        let token = match crate::space::service_auth::mint_service_auth(
            &signing_key,
            authority_did,
            &target,
            "com.atproto.space.notifySpaceDeleted",
            crate::space::service_auth::NOTIFY_SERVICE_AUTH_TTL_SECS,
        ) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let url = format!(
            "{}/xrpc/com.atproto.space.notifySpaceDeleted",
            endpoint.trim_end_matches('/')
        );
        let body = serde_json::json!({ "space": uri.to_string() });
        let _ = http.post(&url).bearer_auth(&token).json(&body).send().await;
    }
}

/// Query params for `getSpace`.
#[derive(Debug, Deserialize)]
pub struct GetSpaceQuery {
    /// Full space URI.
    pub space: String,
}

/// `GET /xrpc/com.atproto.space.getSpace`.
///
/// A **host** query authorized by a **space credential** (spec XRPC table line
/// 481). A space credential confers whole-space read access, so this accepts
/// either a space credential or a covering OAuth `read` scope, mirroring the
/// other host/repo read methods. The `read` scope is whole-space and so is not
/// collection-constrained.
pub async fn get_space(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<GetSpaceQuery>,
) -> Result<Json<GetSpaceOutput>, XrpcError> {
    let uri = parse_space_uri(&q.space)?;
    let subject = require_any_authn(&parts, &state, &uri).await?;
    assert_space_read_opt(&state, &subject, &uri).await?;
    // The space authority hosts the space config; describe from the authority's
    // store regardless of which member's credential authorized the read.
    let viewer = match &subject {
        Some(s) => s.sub().to_string(),
        None => uri.space_did.clone(),
    };
    let svc = space_service(&state)?;
    let out = svc
        .get_space(&viewer, &uri)
        .await
        .map_err(XrpcError::from)?;
    Ok(Json(out))
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

/// `POST /xrpc/com.atproto.simplespace.addMember`.
pub async fn add_member(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<MemberInput>,
) -> Result<StatusCode, XrpcError> {
    let subject = require_session_auth(&parts, &state).await?;
    let owner = subject.sub().to_string();
    let uri = parse_space_uri(&input.space)?;
    assert_space_manage(
        &subject,
        &uri,
        atproto_oauth::scopes::SpaceManageVerb::Update,
    )?;
    space_service(&state)?
        .add_member(&owner, &uri, &input.did)
        .await
        .map_err(XrpcError::from)?;
    Ok(StatusCode::OK)
}

/// `POST /xrpc/com.atproto.simplespace.removeMember`.
pub async fn remove_member(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<MemberInput>,
) -> Result<StatusCode, XrpcError> {
    let subject = require_session_auth(&parts, &state).await?;
    let owner = subject.sub().to_string();
    let uri = parse_space_uri(&input.space)?;
    assert_space_manage(
        &subject,
        &uri,
        atproto_oauth::scopes::SpaceManageVerb::Update,
    )?;
    space_service(&state)?
        .remove_member(&owner, &uri, &input.did)
        .await
        .map_err(XrpcError::from)?;
    Ok(StatusCode::OK)
}

/// Query params for `listMembers`.
#[derive(Debug, Deserialize)]
pub struct GetMembersQuery {
    /// Space URI.
    pub space: String,
    /// Cursor.
    pub cursor: Option<String>,
    /// Page size.
    pub limit: Option<u32>,
}

/// Output of `listMembers`.
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

/// `GET /xrpc/com.atproto.simplespace.listMembers`.
pub async fn get_members(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<GetMembersQuery>,
) -> Result<Json<GetMembersResponse>, XrpcError> {
    let subject = require_session_auth(&parts, &state).await?;
    let owner = subject.sub().to_string();
    let uri = parse_space_uri(&q.space)?;
    assert_space_scope(
        &state,
        &subject,
        &uri,
        atproto_oauth::scopes::SpaceAction::Read,
        None,
    )
    .await?;
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
    let auth = require_session_auth(&parts, &state).await?;
    let member_did = auth.sub().to_string();
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
        let (action, scope_action) = match w.action.as_str() {
            "create" => (
                SpaceWriteAction::Create,
                atproto_oauth::scopes::SpaceAction::Create,
            ),
            "update" => (
                SpaceWriteAction::Update,
                atproto_oauth::scopes::SpaceAction::Update,
            ),
            "delete" => (
                SpaceWriteAction::Delete,
                atproto_oauth::scopes::SpaceAction::Delete,
            ),
            other => {
                return Err(XrpcError::new(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    format!("invalid action {other:?}"),
                ));
            }
        };
        // OAuth `space:` scope gate — each op's action must be covered for
        // its collection (no-op for app-password sessions).
        assert_space_scope(&state, &auth, &uri, scope_action, Some(&w.collection)).await?;
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

// ---------------------------------------------------------------------------
//  Single-op record writes: createRecord / putRecord / deleteRecord.
//
//  Each is a thin wrapper over the SpaceWriter single-op path. The `repo`
//  field names the DID being written to and MUST equal the authenticated
//  subject — members write only to their own per-actor store.
// ---------------------------------------------------------------------------

/// Output of `createRecord` / `putRecord`.
#[derive(Debug, Serialize)]
pub struct WriteRecordResponse {
    /// Six-segment space-URI of the written record.
    pub uri: String,
    /// CID of the record value (DAG-CBOR).
    pub cid: String,
    /// Validation status when known.
    #[serde(rename = "validationStatus", skip_serializing_if = "Option::is_none")]
    pub validation_status: Option<String>,
}

/// Inputs for `createRecord`.
#[derive(Debug, Deserialize)]
pub struct CreateRecordInput {
    /// Space URI.
    pub space: String,
    /// DID of the repo to write to (the authenticated member).
    pub repo: String,
    /// NSID collection.
    pub collection: String,
    /// Record key (optional — auto-TID when omitted).
    pub rkey: Option<String>,
    /// Lexicon validation toggle (reserved; not yet enforced).
    #[allow(dead_code)]
    pub validate: Option<bool>,
    /// Record value (must contain a `$type` field).
    pub record: serde_json::Value,
}

/// `POST /xrpc/com.atproto.space.createRecord`.
pub async fn create_record_write(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<CreateRecordInput>,
) -> Result<Json<WriteRecordResponse>, XrpcError> {
    let auth = require_session_auth(&parts, &state).await?;
    let subject = auth.sub().to_string();
    require_repo_matches_subject(&input.repo, &subject)?;
    let uri = parse_space_uri(&input.space)?;
    assert_space_scope(
        &state,
        &auth,
        &uri,
        atproto_oauth::scopes::SpaceAction::Create,
        Some(&input.collection),
    )
    .await?;
    let writer = space_writer(&state)?;
    let result = writer
        .create_record(
            &subject,
            &uri,
            input.collection,
            input.rkey.unwrap_or_default(),
            input.record,
        )
        .await
        .map_err(XrpcError::from)?;
    Ok(Json(single_write_response(result)?))
}

/// Inputs for `putRecord`.
#[derive(Debug, Deserialize)]
pub struct PutRecordInput {
    /// Space URI.
    pub space: String,
    /// DID of the repo to write to (the authenticated member).
    pub repo: String,
    /// NSID collection.
    pub collection: String,
    /// Record key.
    pub rkey: String,
    /// Lexicon validation toggle (reserved; not yet enforced).
    #[allow(dead_code)]
    pub validate: Option<bool>,
    /// Record value.
    pub record: serde_json::Value,
}

/// `POST /xrpc/com.atproto.space.putRecord`.
pub async fn put_record_write(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<PutRecordInput>,
) -> Result<Json<WriteRecordResponse>, XrpcError> {
    let auth = require_session_auth(&parts, &state).await?;
    let subject = auth.sub().to_string();
    require_repo_matches_subject(&input.repo, &subject)?;
    let uri = parse_space_uri(&input.space)?;
    // putRecord may either create or update the record, so it requires both
    // the `create` and `update` actions per the 0016 OAuth-scope rules (spec
    // lines 405-411), asserting both before the upsert.
    assert_space_scope(
        &state,
        &auth,
        &uri,
        atproto_oauth::scopes::SpaceAction::Create,
        Some(&input.collection),
    )
    .await?;
    assert_space_scope(
        &state,
        &auth,
        &uri,
        atproto_oauth::scopes::SpaceAction::Update,
        Some(&input.collection),
    )
    .await?;
    let writer = space_writer(&state)?;
    let result = writer
        .put_record(&subject, &uri, input.collection, input.rkey, input.record)
        .await
        .map_err(XrpcError::from)?;
    Ok(Json(single_write_response(result)?))
}

/// Inputs for `deleteRecord`.
#[derive(Debug, Deserialize)]
pub struct DeleteRecordInput {
    /// Space URI.
    pub space: String,
    /// DID of the repo to delete from (the authenticated member).
    pub repo: String,
    /// NSID collection.
    pub collection: String,
    /// Record key.
    pub rkey: String,
}

/// `POST /xrpc/com.atproto.space.deleteRecord`.
pub async fn delete_record_write(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<DeleteRecordInput>,
) -> Result<Json<serde_json::Value>, XrpcError> {
    let auth = require_session_auth(&parts, &state).await?;
    let subject = auth.sub().to_string();
    require_repo_matches_subject(&input.repo, &subject)?;
    let uri = parse_space_uri(&input.space)?;
    assert_space_scope(
        &state,
        &auth,
        &uri,
        atproto_oauth::scopes::SpaceAction::Delete,
        Some(&input.collection),
    )
    .await?;
    let writer = space_writer(&state)?;
    writer
        .delete_record(&subject, &uri, input.collection, input.rkey)
        .await
        .map_err(XrpcError::from)?;
    Ok(Json(serde_json::json!({})))
}

/// Enforce that the `repo` field of a record-write request names the
/// authenticated subject. Members may only write to their own per-actor
/// store.
fn require_repo_matches_subject(repo: &str, subject: &str) -> Result<(), XrpcError> {
    if repo == subject {
        Ok(())
    } else {
        Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "InvalidRequest",
            "repo must equal the authenticated subject",
        ))
    }
}

/// Project a single-op [`SpaceCommitResult`] into a `createRecord` /
/// `putRecord` output `{uri, cid}`.
fn single_write_response(result: SpaceCommitResult) -> Result<WriteRecordResponse, XrpcError> {
    let uri = result.uris.into_iter().next().ok_or_else(|| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "write produced no record URI",
        )
    })?;
    let cid = result.cids.into_iter().next().flatten().ok_or_else(|| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "write produced no record CID",
        )
    })?;
    Ok(WriteRecordResponse {
        uri,
        cid,
        validation_status: None,
    })
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
    /// DID of the member whose repo to read from. If omitted, defaults to
    /// the authenticated subject (OAuth auth). Required when using
    /// space-credential auth.
    pub repo: Option<String>,
}

/// Output of `getRecord`.
#[derive(Debug, Serialize)]
pub struct GetSpaceRecordResponse {
    /// AT-URI of the record (`at://owner/space/type/key/author/collection/rkey`).
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
    let resolved = resolve_record_auth(&parts, &state, &uri, q.repo.as_deref()).await?;
    if let Some(subject) = &resolved.subject {
        assert_space_record_read(
            &state,
            subject,
            &uri,
            &resolved.target_repo,
            Some(&q.collection),
        )
        .await?;
    }
    let row = space_reader(&state)?
        .get_record(
            &uri,
            resolved.auth,
            &resolved.target_repo,
            &q.collection,
            &q.rkey,
        )
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
    /// NSID collection. When omitted, records are listed across every
    /// collection in the space (one page per collection, no cross-collection
    /// cursor).
    pub collection: Option<String>,
    /// Cursor (last `rkey`). Ignored when `collection` is omitted.
    pub cursor: Option<String>,
    /// Page size.
    pub limit: Option<u32>,
    /// DID of the member whose repo to read from. If omitted, defaults to
    /// the authenticated subject (OAuth auth). Required when using
    /// space-credential auth.
    pub repo: Option<String>,
}

/// One record in `listRecords` — keys-only per
/// `com.atproto.space.listRecords#record` (`{collection, rkey, cid}`). Fetch
/// the value separately via `getRecord`.
#[derive(Debug, Serialize)]
pub struct SpaceRecordItem {
    /// NSID collection.
    pub collection: String,
    /// Record key.
    pub rkey: String,
    /// CID of the record value.
    pub cid: String,
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
    let resolved = resolve_record_auth(&parts, &state, &uri, q.repo.as_deref()).await?;
    if let Some(subject) = &resolved.subject {
        // listRecords may span every collection in the repo (collection
        // omitted). A `read_self` grant is collection-constrained, so a
        // cross-collection list of the own repo requires a whole-space `read`
        // grant; pass `None` to force the `read` path in that case.
        assert_space_record_read(
            &state,
            subject,
            &uri,
            &resolved.target_repo,
            q.collection.as_deref(),
        )
        .await?;
    }
    let page = space_reader(&state)?
        .list_records(
            &uri,
            resolved.auth,
            &resolved.target_repo,
            q.collection.as_deref(),
            q.cursor.as_deref(),
            q.limit.unwrap_or(50),
        )
        .await
        .map_err(XrpcError::from)?;
    let records: Vec<SpaceRecordItem> = page
        .records
        .into_iter()
        .map(|r| SpaceRecordItem {
            collection: r.collection,
            rkey: r.rkey,
            cid: r.cid,
        })
        .collect();
    Ok(Json(ListSpaceRecordsResponse {
        records,
        cursor: page.cursor,
    }))
}

/// Resolved auth + read-target DID for a Spaces record read.
struct ResolvedRecordAuth<'a> {
    auth: SpaceReadAuth<'a>,
    target_repo: String,
    /// The bearer subject when the request authenticated via a session/OAuth
    /// access token. `None` for SpaceCredential auth, which pre-authorizes
    /// whole-space read at the auth layer and skips the `space:` scope gate.
    subject: Option<crate::http::auth::AuthSubject>,
}

/// Require that a permissioned read is between members of the space.
///
/// This is the check the permissioned-data feature exists to provide, and it
/// was absent: `resolve_record_auth` adopted the caller-supplied `repo`
/// verbatim, so any authenticated local account could read any other local
/// account's permissioned records by naming them.
///
/// Two questions, both necessary:
///
/// - **Is the caller a member?** Otherwise a stranger with an ordinary session
///   reads a space they were never added to. Skipped for a SpaceCredential:
///   that credential is signed by the authority and pre-authorises whole-space
///   read, which [`SpaceReader::verify_auth`] checks.
/// - **Is the target a member?** A space is not a lens onto arbitrary accounts.
///   This applies to a SpaceCredential too — an authority authorises reads
///   *within* its space, not reads of repos outside it.
///
/// Deliberately **not** behind the `is_oauth` gate that
/// [`assert_space_scope`] opens with. Scope asks what a token was granted;
/// membership asks who the account is. App-password sessions carry no scopes
/// by construction and are full-authority (see PR #30), so gating membership on
/// scope enforcement is what let the app-password path through.
///
/// Refusals report `SpaceNotFound` rather than a distinct error: whether a
/// given space contains a given account's records is itself the confidential
/// fact, and a caller who is not a member should not be able to probe it.
async fn assert_space_membership(
    state: &HttpState,
    uri: &SpaceUri,
    caller: Option<&str>,
    target: &str,
) -> Result<(), XrpcError> {
    let service = space_service(state)?;
    let deny = || {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "SpaceNotFound",
            format!("no such space {uri}"),
        )
    };
    if let Some(caller) = caller
        && !service
            .is_member(uri, caller)
            .await
            .map_err(XrpcError::from)?
    {
        tracing::debug!(space = %uri, caller = %caller, "space read refused: caller is not a member");
        return Err(deny());
    }
    // When the caller reads its own repo, the caller check above already
    // established membership.
    if caller != Some(target)
        && !service
            .is_member(uri, target)
            .await
            .map_err(XrpcError::from)?
    {
        tracing::debug!(space = %uri, target = %target, "space read refused: target is not a member");
        return Err(deny());
    }
    Ok(())
}

/// Decide which auth flavor a record-read uses based on the bearer token's
/// `typ` header, validate the `repo` parameter against the auth mode, and
/// return the resolved target DID.
///
/// - **OAuth / session bearer** — `repo` may be omitted (defaults to the
///   authenticated subject) or supplied to read another member's per-actor
///   store on this PDS.
/// - **SpaceCredential** — `repo` is **required**; returns 400
///   `InvalidRequest` when missing because a SpaceCredential is not bound
///   to any one member's repo.
/// - **Delegation token** — rejected; delegation tokens must be exchanged at
///   `getSpaceCredential` before being used to read records.
async fn resolve_record_auth<'a>(
    parts: &'a Parts,
    state: &HttpState,
    space: &SpaceUri,
    repo: Option<&str>,
) -> Result<ResolvedRecordAuth<'a>, XrpcError> {
    let raw = bearer_token(parts)?;
    match classify(raw) {
        Some(SpaceTokenKind::SpaceCredential) => {
            let repo = repo.ok_or_else(|| {
                XrpcError::new(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "repo is required for space credential auth",
                )
            })?;
            // The credential itself is verified downstream; what is checked
            // here is that the repo it names belongs to this space.
            assert_space_membership(state, space, None, repo).await?;
            Ok(ResolvedRecordAuth {
                auth: SpaceReadAuth::SpaceCredential { token: raw },
                target_repo: repo.to_string(),
                subject: None,
            })
        }
        Some(SpaceTokenKind::DelegationToken) => Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "delegation token cannot be used to read records; exchange it at getSpaceCredential first",
        )),
        _ => {
            // Treat as a session-style or OAuth access token. The unified
            // helper transparently accepts both shapes and enforces DPoP
            // when an OAuth token carries a `cnf.jkt` thumbprint.
            let (htm, htu) = request_htm_htu(parts);
            let subject = require_authn(parts, state, &htm, &htu).await?;
            let sub = subject.sub().to_string();
            let target_repo = repo.map(|r| r.to_string()).unwrap_or_else(|| sub.clone());
            assert_space_membership(state, space, Some(&sub), &target_repo).await?;
            Ok(ResolvedRecordAuth {
                auth: SpaceReadAuth::OwnPds { account_did: sub },
                target_repo,
                subject: Some(subject),
            })
        }
    }
}

// ---------------------------------------------------------------------------
//  Sync endpoints.
// ---------------------------------------------------------------------------

/// Query params for `getRepoState`.
#[derive(Debug, Deserialize)]
pub struct RepoStateQuery {
    /// Space URI.
    pub space: String,
    /// DID of the account whose repo state to retrieve.
    pub repo: String,
}

/// JSON wire form of a signed commit (`com.atproto.space.defs#signedCommit`).
///
/// The four byte fields are emitted in atproto's lex-data `bytes` form
/// (`{"$bytes": "<base64>"}`, standard alphabet, unpadded) rather than the
/// JSON array that [`atproto_space::Commit`]'s `serde_bytes` derive would
/// produce, so the wire shape matches the lexicon and the 0016 spec
/// `#signedCommit` field table (lines 307-316).
#[derive(Debug, Serialize)]
pub struct SignedCommitDto {
    /// Commit format version. Listed first in the lexicon's `required` set.
    pub ver: u32,
    /// `sha256` of the LtHash state (32 bytes), as `{"$bytes": ...}`.
    pub hash: BytesValue,
    /// `HMAC-SHA256` over `hash`, as `{"$bytes": ...}`.
    pub mac: BytesValue,
    /// Per-commit fresh IKM (32 bytes), as `{"$bytes": ...}`.
    pub ikm: BytesValue,
    /// `sign(ctx)` over the commit context, as `{"$bytes": ...}`.
    pub sig: BytesValue,
    /// Commit revision (TID).
    pub rev: String,
}

/// atproto lex-data `bytes` value — serializes as `{"$bytes": "<base64>"}`
/// (standard alphabet, unpadded).
#[derive(Debug)]
pub struct BytesValue(Vec<u8>);

impl Serialize for BytesValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&self.0);
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("$bytes", &b64)?;
        map.end()
    }
}

impl SignedCommitDto {
    /// Convert an [`atproto_space::Commit`] into its `$bytes`-encoded wire DTO.
    fn from_commit(c: atproto_space::Commit) -> Self {
        Self {
            ver: c.ver,
            hash: BytesValue(c.hash),
            mac: BytesValue(c.mac),
            ikm: BytesValue(c.ikm),
            sig: BytesValue(c.sig),
            rev: c.rev,
        }
    }
}

/// Output of `getRepoState`.
///
/// `commit` is absent when the repo has never been written to, per
/// `com.atproto.space.getRepoState`.
#[derive(Debug, Serialize)]
pub struct StateResponse {
    /// The current signed commit, or absent when empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<SignedCommitDto>,
}

/// Build a signed commit from a persisted SetHash state + rev.
///
/// Rehydrates the [`PdsSetHash`](crate::realm::PdsSetHash) lattice from the
/// 2048-byte state persisted in [`RepoState`](atproto_space::RepoState),
/// derives the 32-byte commitment, and signs a [`SpaceContext`] (space URI,
/// author DID, rev) with `signing_key`, per the 0016 Permissioned Data draft
/// (§ Commit signature). Returns `None` when the state is empty (no commits
/// yet).
///
/// `author` is the DID of the repo the state belongs to. It is bound into the
/// `ctx`, which is what domain-separates the signature within a space — a
/// signature without it covers any author's commit at the same rev.
fn signed_commit_from_state(
    space: &SpaceUri,
    author: &str,
    state: &atproto_space::RepoState,
    signing_key: &atproto_identity::key::KeyData,
) -> Result<Option<SignedCommitDto>, XrpcError> {
    use atproto_space::set_hash::SetHash;
    let (Some(state_bytes), Some(rev)) = (state.set_hash.as_deref(), state.rev.as_deref()) else {
        return Ok(None);
    };
    let set_hash = crate::realm::PdsSetHash::from_state_bytes(state_bytes).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("rehydrate set hash: {e}"),
        )
    })?;
    let ctx = atproto_space::SpaceContext {
        space: space.to_string(),
        author: author.to_string(),
        rev: rev.to_string(),
    };
    let commit = atproto_space::create_commit(&set_hash, &ctx, signing_key).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("sign commit: {e}"),
        )
    })?;
    Ok(Some(SignedCommitDto::from_commit(commit)))
}

/// `GET /xrpc/com.atproto.space.getRepoState`.
///
/// Returns the repo account's current signed commit (`records` scope, signed
/// by the repo account's atproto signing key). `commit` is absent when the
/// repo is empty.
pub async fn get_repo_state(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<RepoStateQuery>,
) -> Result<Json<StateResponse>, XrpcError> {
    let uri = parse_space_uri(&q.space)?;
    let subject = require_any_authn(&parts, &state, &uri).await?;
    assert_space_read_opt(&state, &subject, &uri).await?;
    let st = space_sync(&state)?
        .get_repo_state(&uri, &q.repo)
        .await
        .map_err(XrpcError::from)?;
    let manager = account_manager(&state)?;
    let signing_key = local_signing_key(manager, &q.repo).await?;
    let commit = signed_commit_from_state(&uri, &q.repo, &st, &signing_key)?;
    Ok(Json(StateResponse { commit }))
}

/// Query params for `listRepoOps`.
#[derive(Debug, Deserialize)]
pub struct RepoOplogQuery {
    /// Space URI.
    pub space: String,
    /// DID of the account whose oplog to retrieve.
    pub repo: String,
    /// Opaque `(rev, idx)` cursor (`"<rev>__<idx>"`) to start *after*
    /// (exclusive). Carries the last op delivered on the prior page so that an
    /// atomic batch larger than `limit` is not skipped across paging.
    pub since: Option<String>,
    /// Page size.
    pub limit: Option<u32>,
}

/// One records-oplog entry, wire shape per `com.atproto.space.listRepoOps#opEntry`.
///
/// Exactly `{ rev, collection, rkey, cid, prev }`. `cid` is `null` for deletes;
/// `prev` is `null` for creates (both keys are always present, per the
/// lexicon's `nullable` set).
#[derive(Debug, Serialize)]
pub struct RecordOpEntry {
    /// Rev (TID). Ops sharing a rev belong to the same batch.
    pub rev: String,
    /// NSID collection.
    pub collection: String,
    /// Record key.
    pub rkey: String,
    /// New record CID; `null` for deletes.
    pub cid: Option<String>,
    /// Prior record CID; `null` for creates.
    pub prev: Option<String>,
}

/// Output of `listRepoOps`.
///
/// `commit` is included only when the page reaches the head of the oplog
/// (`ops.len() < limit`), so a caught-up consumer can verify the resulting
/// state; it is omitted on backfill responses.
#[derive(Debug, Serialize)]
pub struct RepoOpsResponse {
    /// Oplog ops on this page (rev,idx ascending).
    pub ops: Vec<RecordOpEntry>,
    /// The repo's current signed commit, when caught up. Absent on backfill
    /// or when the repo is empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<SignedCommitDto>,
    /// Opaque `(rev, idx)` cursor for the next page (the last op on this page),
    /// when more may remain. Encoded as `"<rev>__<idx>"` so a batch larger than
    /// `limit` resumes within the batch rather than skipping its tail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// `GET /xrpc/com.atproto.space.listRepoOps`.
///
/// Incremental sync for a per-account repo within a space. On a caught-up
/// page (fewer ops than `limit`), attaches the repo's current signed commit
/// (`records` scope, signed by the repo account's key).
pub async fn list_repo_ops(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<RepoOplogQuery>,
) -> Result<Json<RepoOpsResponse>, XrpcError> {
    let uri = parse_space_uri(&q.space)?;
    let subject = require_any_authn(&parts, &state, &uri).await?;
    assert_space_read_opt(&state, &subject, &uri).await?;
    let limit = q.limit.unwrap_or(100);
    let since = match q.since.as_deref() {
        Some(token) => Some(OplogCursor::from_token(token).map_err(|_| {
            XrpcError::new(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "since cursor is malformed",
            )
        })?),
        None => None,
    };
    let page = space_sync(&state)?
        .list_repo_ops(&uri, &q.repo, since.as_ref(), limit)
        .await
        .map_err(XrpcError::from)?;

    let caught_up = (page.ops.len() as u32) < limit;
    // Next-page cursor is the `(rev, idx)` of the last op on this page, so a
    // batch larger than `limit` resumes within the batch on the next call.
    let cursor = if caught_up {
        None
    } else {
        page.ops
            .last()
            .map(|o| OplogCursor::new(o.rev.clone(), o.idx).to_token())
    };
    let ops: Vec<RecordOpEntry> = page
        .ops
        .into_iter()
        .map(|o| RecordOpEntry {
            rev: o.rev,
            collection: o.collection.unwrap_or_default(),
            rkey: o.rkey.unwrap_or_default(),
            cid: o.cid,
            prev: o.prev,
        })
        .collect();

    let commit = if caught_up {
        let manager = account_manager(&state)?;
        let signing_key = local_signing_key(manager, &q.repo).await?;
        signed_commit_from_state(&uri, &q.repo, &page.state, &signing_key)?
    } else {
        None
    };

    Ok(Json(RepoOpsResponse {
        ops,
        commit,
        cursor,
    }))
}

// ---------------------------------------------------------------------------
//  Credential mint endpoints.
// ---------------------------------------------------------------------------

/// Query params for `getDelegationToken`.
#[derive(Debug, Deserialize)]
pub struct GetDelegationTokenQuery {
    /// Space URI.
    pub space: String,
}

/// Output of `getDelegationToken` — `{ token }` only, per the
/// `com.atproto.space.getDelegationToken` lexicon.
#[derive(Debug, Serialize)]
pub struct DelegationTokenResponse {
    /// The compact-form delegation JWT.
    pub token: String,
}

/// Output of `getSpaceCredential` — `{ credential }`, the bare JWT, per the
/// `com.atproto.space.getSpaceCredential` lexicon (spec lines 246).
#[derive(Debug, Serialize)]
pub struct SpaceCredentialResponse {
    /// The compact-form space-credential JWT.
    pub credential: String,
}

/// `GET /xrpc/com.atproto.space.getDelegationToken` — member-OAuth gated.
/// Mints a [`DelegationToken`](atproto_space::credential::DelegationToken)
/// signed by the member's atproto signing key (header `kid="#atproto"`).
///
/// The delegation token asserts only the user-to-app delegation; it carries no
/// app identity. It is `aud`-addressed to the space host
/// (`<spaceDid>#atproto_space_host`) and `sub`-bound to the space URI. The
/// output body is exactly `{ "token": <jwt> }` — the token is later exchanged
/// with the space authority at `getSpaceCredential`.
pub async fn get_delegation_token(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<GetDelegationTokenQuery>,
) -> Result<Json<DelegationTokenResponse>, XrpcError> {
    let (htm, htu) = request_htm_htu(&parts);
    let subject = require_authn(&parts, &state, &htm, &htu).await?;
    let member_did = subject.sub().to_string();
    // The delegation token proves an app is acting on the user's behalf, so
    // the request must come from an OAuth session (which carries a client
    // identity). The token itself records nothing about the app — app
    // identity is the client attestation's job — but we still reject
    // app-password sessions here, matching the OAuth-gated flow.
    if subject.client_id().is_none() {
        return Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "InvalidRequest",
            "getDelegationToken requires OAuth auth with a client_id",
        ));
    }
    let uri = parse_space_uri(&q.space)?;
    // OAuth `space:` read-scope gate before minting. No-op for app-password
    // sessions, which are rejected above for lacking a client_id anyway.
    assert_space_scope(
        &state,
        &subject,
        &uri,
        atproto_oauth::scopes::SpaceAction::Read,
        None,
    )
    .await?;
    let manager = account_manager(&state)?;
    let signing_key = local_signing_key(manager, &member_did).await?;
    let token = create_delegation_token(&member_did, &uri, &signing_key, DELEGATION_TOKEN_TTL_SECS)
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("mint delegation token: {e}"),
            )
        })?;
    Ok(Json(DelegationTokenResponse { token }))
}

/// Inputs for `getSpaceCredential`. The delegation token is presented in the
/// `Authorization: Bearer` header (not the body); the body carries the target
/// space and an optional client attestation.
#[derive(Debug, Deserialize)]
pub struct GetSpaceCredentialInput {
    /// The space being requested, an `at://…/space/…` URI.
    pub space: String,
    /// Optional client attestation (compact JWT) establishing the app's
    /// identity. Required only when the space gates on app identity
    /// (`appAccess` is `#allowList`). Matches the lexicon
    /// `clientAttestation` field.
    #[serde(rename = "clientAttestation", default)]
    pub client_attestation: Option<String>,
}

/// `POST /xrpc/com.atproto.space.getSpaceCredential` — delegation-token gated.
/// Reads the [`DelegationToken`](atproto_space::credential::DelegationToken)
/// from the `Authorization: Bearer` header, verifies it against the member's
/// `#atproto` signing key, enforces single-use via its `jti`, then mints a
/// [`SpaceCredential`](atproto_space::credential::SpaceCredential) signed by
/// the authority's `#atproto_space` signing key.
pub async fn get_space_credential(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<GetSpaceCredentialInput>,
) -> Result<Json<SpaceCredentialResponse>, XrpcError> {
    let manager = account_manager(&state)?;

    // The delegation token is the bearer credential.
    let grant_jwt = bearer_token(&parts)?;

    let space = parse_space_uri(&input.space)?;

    // Peek the delegation token to learn its issuer (the member) so we know
    // which key to resolve, and confirm it targets this space.
    let unverified = peek_delegation_token(grant_jwt)?;

    // Try the local path first (fast); on `AccountNotFound` (the
    // member is not on this PDS), fall through to the remote path that
    // resolves the member's DID document via atproto-identity.
    let payload =
        match verify_local_delegation_token(manager, grant_jwt, &space.space_did, &space).await {
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
                crate::http::space_auth::verify_remote_delegation_token(
                    &http,
                    grant_jwt,
                    &space.space_did,
                    &space,
                    plc_dir,
                )
                .await?
            }
            Err(e) => return Err(e),
        };

    // Enforce single-use of the delegation token via its `jti` (spec line
    // 149). Consume it before minting so a replayed token is refused.
    let dt_ttl = std::time::Duration::from_secs(payload.exp.saturating_sub(now_secs()));
    state
        .jti_guard
        .check_and_insert(&payload.jti, dt_ttl)
        .await
        .map_err(|_| {
            XrpcError::new(
                StatusCode::FORBIDDEN,
                "InvalidToken",
                "delegation token already used (single-use replay)",
            )
        })?;

    let owner_signing = local_signing_key(manager, &space.space_did).await?;

    // ── Mint-time authorization (defs.json: a credential is minted only when
    //    the user is authorized by `mintPolicy` AND their app by `appAccess`).
    //
    // The requesting member is the delegation token's issuer. App identity is
    // established solely by the optional client attestation: when one is
    // presented we verify it (which yields the attested client_id) and use
    // that for the APP axis and the credential's `client_id`. When none is
    // presented the credential's `client_id` is omitted (spec lines 221, 228).
    let mint_http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(crate::user_agent())
        .build()
        .unwrap_or_default();

    let attested_client_id: Option<String> = match input.client_attestation.as_deref() {
        Some(att) => Some(
            crate::space::mint_authz::verify_client_attestation(
                &mint_http,
                &state.jti_guard,
                att,
                &space,
            )
            .await
            .map_err(mint_denial_to_xrpc)?,
        ),
        None => None,
    };

    let svc = space_service(&state)?;
    let inputs = svc
        .load_mint_authz_inputs(&space, &payload.iss)
        .await
        .map_err(XrpcError::from)?;
    if !inputs.found {
        return Err(XrpcError::new(
            StatusCode::NOT_FOUND,
            "SpaceNotFound",
            format!("space not found: {space}"),
        ));
    }
    if inputs.deleted {
        return Err(XrpcError::new(
            StatusCode::NOT_FOUND,
            "SpaceDeleted",
            format!("space deleted: {space}"),
        ));
    }

    // USER axis (mintPolicy).
    match crate::space::mint_authz::user_axis_local(inputs.config.mint_policy, inputs.is_member)
        .map_err(mint_denial_to_xrpc)?
    {
        Some(()) => {}
        None => {
            // managing-app: ask the managingApp via checkUserAccess.
            let managing_app = inputs.config.managing_app.as_deref().ok_or_else(|| {
                XrpcError::new(
                    StatusCode::FORBIDDEN,
                    "NotAuthorized",
                    "mintPolicy is managing-app but no managingApp is configured",
                )
            })?;
            let plc_dir = state.plc_service.as_ref().map(|p| p.directory_hostname());
            let endpoint = crate::space::recipient::resolve_service_endpoint(
                &mint_http,
                managing_app,
                plc_dir,
            )
            .await
            .map_err(XrpcError::from)?
            .ok_or_else(|| {
                XrpcError::new(
                    StatusCode::FORBIDDEN,
                    "NotAuthorized",
                    format!("could not resolve managingApp service endpoint: {managing_app}"),
                )
            })?;
            crate::space::mint_authz::check_user_access(
                &mint_http,
                &endpoint,
                managing_app,
                &owner_signing,
                &space.space_did,
                &space,
                &payload.iss,
                attested_client_id.as_deref(),
            )
            .await
            .map_err(mint_denial_to_xrpc)?;
        }
    }

    // APP axis (appAccess).
    crate::space::mint_authz::app_axis(&inputs.config.app_access, attested_client_id.as_deref())
        .map_err(mint_denial_to_xrpc)?;

    // The credential's `client_id` is the attested application identity, or
    // omitted entirely when the request carried no attestation.
    let credential_ttl = state.space_credential_ttl_secs;
    let token = create_space_credential(
        &space.space_did,
        &space,
        attested_client_id.as_deref(),
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
    // Recipient discovery is keyed off the *attested* client_id (the
    // consumer's client-metadata URL): we resolve
    // `<host_of_client_id>/.well-known/atproto-did` and the resulting DID
    // document's `AtprotoPersonalDataServer` service, falling back to a
    // documented stub when any step fails. When the request carried no
    // attestation there is no consumer URL to resolve, so we register the
    // member's own DID as the recipient via the stub.
    let plc_dir = state.plc_service.as_ref().map(|p| p.directory_hostname());
    let recipient_http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(crate::user_agent())
        .build()
        .unwrap_or_default();
    let resolved = match attested_client_id.as_deref() {
        Some(client_id) => match crate::space::recipient::resolve_recipient(
            &recipient_http,
            &payload.iss,
            client_id,
            plc_dir,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    client_id = %client_id,
                    "recipient resolution failed; falling back to stub"
                );
                crate::space::recipient::stub_recipient(&payload.iss, client_id)
            }
        },
        None => crate::space::recipient::stub_recipient(&payload.iss, &payload.iss),
    };
    if !resolved.fully_resolved {
        tracing::warn!(
            member = %payload.iss,
            stub_did = %resolved.service_did,
            stub_endpoint = %resolved.service_endpoint,
            "recipient resolved via stub; consumer DID document was unreachable or missing a PDS service entry"
        );
    }

    match SqlActorStore::open(manager.data_dir(), &space.space_did).await {
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
                    member = %payload.iss,
                    "register space_credential_recipient failed; this consumer will not receive notifyWrite"
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

    Ok(Json(SpaceCredentialResponse { credential: token }))
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

/// Host/sync read endpoints accept either a session/OAuth access token or a
/// `SpaceCredential` bound to `space`. The PDS does not enforce membership at
/// sync time, but a presented credential MUST verify: when the bearer's `typ`
/// classifies as a `SpaceCredential`, its signature is checked against the
/// space authority's `#atproto_space` key and its `iss`/`sub`/`exp` are bound
/// to `space`. A forged, unsigned, expired, or wrong-space credential is
/// rejected with 401 rather than admitted on its `typ` string alone.
/// OAuth tokens with a DPoP `cnf.jkt` binding still trigger the proof check via
/// the unified helper.
///
/// Returns the bearer [`AuthSubject`](crate::http::auth::AuthSubject) for a
/// session/OAuth access token, or `None` for a verified `SpaceCredential`
/// (which pre-authorizes whole-space read at the auth layer). Callers gate the
/// `space:` scope only on the returned subject.
async fn require_any_authn(
    parts: &Parts,
    state: &HttpState,
    space: &SpaceUri,
) -> Result<Option<crate::http::auth::AuthSubject>, XrpcError> {
    let raw = bearer_token(parts)?;
    if let Some(SpaceTokenKind::SpaceCredential) = classify(raw) {
        space_reader(state)?
            .verify_space_credential_for(space, raw)
            .await
            .map_err(|e| {
                XrpcError::new(
                    StatusCode::UNAUTHORIZED,
                    "Unauthorized",
                    format!("invalid space credential: {e}"),
                )
            })?;
        return Ok(None);
    }
    let (htm, htu) = request_htm_htu(parts);
    require_authn(parts, state, &htm, &htu).await.map(Some)
}

/// Host/sync read auth restricted to a verified `SpaceCredential` (spec XRPC
/// table: `getSpace` and `listRepos` are "space credential" only). Rejects an
/// OAuth/session bearer with 401 — only a credential minted by the space
/// authority is acceptable — and verifies the credential against `space`.
async fn require_space_credential(
    parts: &Parts,
    state: &HttpState,
    space: &SpaceUri,
) -> Result<(), XrpcError> {
    let raw = bearer_token(parts)?;
    if classify(raw) != Some(SpaceTokenKind::SpaceCredential) {
        return Err(XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "Unauthorized",
            "this method requires a space credential",
        ));
    }
    space_reader(state)?
        .verify_space_credential_for(space, raw)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::UNAUTHORIZED,
                "Unauthorized",
                format!("invalid space credential: {e}"),
            )
        })
}

// ---------------------------------------------------------------------------
//  OAuth `space:` scope enforcement.
//
//  Enforces the 0016 `space:` OAuth scope rules (spec lines 369-419): only
//  OAuth credentials carry granular `space:` permissions. App-password
//  sessions (`access`) and SpaceCredential auth pre-authorize at the auth
//  layer and skip the scope check entirely. A missing scope maps to 403.
// ---------------------------------------------------------------------------

/// Assert that the OAuth scope set granted to `subject` permits `action` on
/// the space `uri`. Collection-scoped (`create`/`update`/`delete`) targets
/// must pass `collection`; `read`/`manage` leave it `None`.
///
/// No-op for non-OAuth subjects (app-password sessions): they carry no
/// `space:` grants and are authorized at the session layer, matching the
/// reference `auth.credentials.type !== 'oauth'` early-return. A scope
/// shortfall on an OAuth subject becomes a 403 `InvalidToken` carrying the
/// minimal scope that would have satisfied the request.
/// Gate the `read` action for a sync/read endpoint whose auth was resolved
/// via [`require_any_authn`]: `Some(subject)` runs the OAuth scope check,
/// `None` (SpaceCredential auth) skips it.
async fn assert_space_read_opt(
    state: &HttpState,
    subject: &Option<crate::http::auth::AuthSubject>,
    uri: &SpaceUri,
) -> Result<(), XrpcError> {
    match subject {
        Some(s) => {
            assert_space_scope(
                state,
                s,
                uri,
                atproto_oauth::scopes::SpaceAction::Read,
                None,
            )
            .await
        }
        None => Ok(()),
    }
}

async fn assert_space_scope(
    state: &HttpState,
    subject: &crate::http::auth::AuthSubject,
    uri: &SpaceUri,
    action: atproto_oauth::scopes::SpaceAction,
    collection: Option<&str>,
) -> Result<(), XrpcError> {
    if !subject.is_oauth() {
        return Ok(());
    }
    let target = match collection {
        Some(c) => atproto_oauth::scopes::SpaceTarget::with_collection(
            uri.space_type.as_str(),
            &uri.space_did,
            uri.space_key.as_str(),
            action,
            c,
        ),
        None => atproto_oauth::scopes::SpaceTarget::new(
            uri.space_type.as_str(),
            &uri.space_did,
            uri.space_key.as_str(),
            action,
        ),
    };
    // Resolve the space type declaration's collections so a bare grant's
    // omitted-`collection` default matches the declared collections (spec line
    // 413). Whole-space `read` ignores collection, so the lookup is skipped.
    let declared = match action {
        atproto_oauth::scopes::SpaceAction::Read => Vec::new(),
        _ => declared_collections(state, uri.space_type.as_str()).await,
    };
    subject
        .scopes()
        .assert_space_with(&target, &declared)
        .map_err(|e| {
            tracing::debug!(
                space = %uri,
                action = action.as_str(),
                needed = %e.scope,
                "space scope assertion failed"
            );
            XrpcError::new(
                StatusCode::FORBIDDEN,
                "InvalidToken",
                format!(
                    "insufficient OAuth scope for this space operation; need `{}`",
                    e.scope
                ),
            )
        })
}

/// Assert that the OAuth scope set granted to `subject` permits the
/// space-management `verb` on the space `uri` (spec lines 415-419). The verb
/// maps onto the management surface at the call site (e.g. `update` authorizes
/// `updateSpace`/`addMember`/`removeMember`). No-op for non-OAuth subjects.
fn assert_space_manage(
    subject: &crate::http::auth::AuthSubject,
    uri: &SpaceUri,
    verb: atproto_oauth::scopes::SpaceManageVerb,
) -> Result<(), XrpcError> {
    if !subject.is_oauth() {
        return Ok(());
    }
    let target = atproto_oauth::scopes::SpaceManageTarget::new(
        uri.space_type.as_str(),
        &uri.space_did,
        uri.space_key.as_str(),
        verb,
    );
    subject.scopes().assert_space_manage(&target).map_err(|e| {
        tracing::debug!(
            space = %uri,
            verb = verb.as_str(),
            needed = %e.scope,
            "space manage scope assertion failed"
        );
        XrpcError::new(
            StatusCode::FORBIDDEN,
            "InvalidToken",
            format!(
                "insufficient OAuth scope for this space-management operation; need `{}`",
                e.scope
            ),
        )
    })
}

/// Assert that the OAuth scope set granted to `subject` permits reading the
/// record(s) at `uri` from `target_repo` (spec lines 392-413).
///
/// - Reading the holder's **own** repo (`target_repo == subject.sub()`) is
///   satisfied by either a whole-space `read` grant or a collection-covering
///   `read_self` grant. A `read_self` grant is collection-constrained, so a
///   cross-collection listing (`collection == None`) of the own repo falls
///   back to requiring whole-space `read`.
/// - Reading **another** member's repo requires whole-space `read`
///   (collection-independent).
///
/// No-op for non-OAuth subjects (app-password sessions).
async fn assert_space_record_read(
    state: &HttpState,
    subject: &crate::http::auth::AuthSubject,
    uri: &SpaceUri,
    target_repo: &str,
    collection: Option<&str>,
) -> Result<(), XrpcError> {
    let own_repo = subject.sub() == target_repo;
    match (own_repo, collection) {
        // Own repo, single collection: read_self (also satisfied by read).
        (true, Some(c)) => {
            assert_space_scope(
                state,
                subject,
                uri,
                atproto_oauth::scopes::SpaceAction::ReadSelf,
                Some(c),
            )
            .await
        }
        // Own repo across all collections, or any other member's repo: the
        // collection-independent whole-space `read` grant is required.
        _ => {
            assert_space_scope(
                state,
                subject,
                uri,
                atproto_oauth::scopes::SpaceAction::Read,
                None,
            )
            .await
        }
    }
}

/// Resolve the `collections` declared by the space type's declaration for the
/// `space_type` NSID, used to expand a bare `space:` grant's
/// omitted-`collection` default (spec line 413).
///
/// Resolution is delegated to the configured
/// [`SpaceDeclarationResolver`](crate::space::SpaceDeclarationResolver). It is
/// **fail-closed**: when no resolver is configured, the spaceType is the `*`
/// wildcard (no declaration to draw from), or resolution fails, this returns an
/// empty list — a bare grant then confers no write targets. Explicit
/// `collection=` grants are unaffected (they never consult the default).
async fn declared_collections(state: &HttpState, space_type: &str) -> Vec<String> {
    // `spaceType=*` has no declaration (spec line 413); skip resolution.
    if space_type == "*" {
        return Vec::new();
    }
    let Some(resolver) = state.space_declaration_resolver.as_ref() else {
        return Vec::new();
    };
    match resolver.resolve(space_type).await {
        Some(decl) => decl.collections,
        None => {
            tracing::warn!(
                space_type,
                "space-type declaration resolution failed; bare `space:` grant defaults to no write collections (fail-closed)"
            );
            Vec::new()
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Map a mint-authorization denial to its documented `getSpaceCredential`
/// XRPC error. User/app/not-authorized refusals are `403`; an invalid client
/// attestation is `400`.
fn mint_denial_to_xrpc(denial: crate::space::mint_authz::MintDenial) -> XrpcError {
    use crate::space::mint_authz::MintDenial;
    let status = match denial {
        MintDenial::InvalidClientAttestation { .. } => StatusCode::BAD_REQUEST,
        _ => StatusCode::FORBIDDEN,
    };
    tracing::debug!(
        error_name = denial.error_name(),
        reason = denial.reason(),
        "getSpaceCredential mint authorization denied"
    );
    XrpcError::new(status, denial.error_name(), denial.reason().to_string())
}

// ---------------------------------------------------------------------------
//  Inbound notify endpoints.
// ---------------------------------------------------------------------------

/// `POST /xrpc/com.atproto.space.notifyWrite` — receive a contentless
/// notify-write `{ space, repo, rev }` announcing that `repo` advanced to
/// `rev` within `space`.
///
/// Authentication is **service auth**: a bearer JWT signed by the writer's
/// `#atproto` key, with `iss == repo` and `aud == <space owner DID>`,
/// scoped to `lxm == com.atproto.space.notifyWrite`.
///
/// Behavior implements the spec's two-hop fan-out (lines 343-351): members
/// notify the authority, which forwards to the endpoints registered for the
/// space. When this PDS hosts the space owner and the writer is a member, the
/// notification is forwarded to every registered recipient (registerNotify
/// subscribers + credential consumers). A lightweight receipt is recorded for
/// dedup + audit. For a non-owner host (e.g. a syncing service that also holds
/// a replica) the handler simply records the receipt — there is no fan-out
/// state.
pub async fn notify_write(
    State(state): State<HttpState>,
    parts: Parts,
    body: axum::body::Bytes,
) -> Result<StatusCode, XrpcError> {
    let manager = account_manager(&state)?;
    let plc_dir = state.plc_service.as_ref().map(|p| p.directory_hostname());
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(crate::user_agent())
        .build()
        .unwrap_or_default();

    // Decode first so we know the space/owner the service-auth `aud` must bind.
    let payload: crate::space::notify::NotifyWritePayload = serde_json::from_slice(body.as_ref())
        .map_err(|e| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            format!("decode notifyWrite payload: {e}"),
        )
    })?;
    let space = parse_space_uri(&payload.space)?;

    // Service-auth: signature over the writer's key, aud = owner DID,
    // lxm scoped to notifyWrite.
    let token = bearer_token(&parts)?;
    let claims = crate::space::service_auth::verify_service_auth(
        &http,
        token,
        plc_dir,
        &space.space_did,
        crate::space::notify::NOTIFY_WRITE_NSID,
        state
            .account_manager
            .as_deref()
            .map(AccountManager::account_pool_ref),
    )
    .await
    .map_err(XrpcError::from)?;
    // The JWT issuer must match the claimed writer so a PDS can't deliver a
    // notification on someone else's behalf (reference `notifyWrite.ts`).
    if claims.iss != payload.repo {
        return Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "notifyWrite iss does not match claimed writer",
        ));
    }

    // Owner-side fan-out (HOP 2): only the owner's PDS holds the member list +
    // recipient subscriptions. For a non-owner host this is a best-effort
    // no-op (the receipt below is still recorded).
    let owner_is_local = manager
        .lookup_handle(&space.space_did)
        .await
        .map_err(XrpcError::from)?
        .is_some();
    if owner_is_local {
        let is_member = space_service(&state)?
            .is_member(&space, &payload.repo)
            .await
            .map_err(XrpcError::from)?;
        if !is_member {
            return Err(XrpcError::new(
                StatusCode::FORBIDDEN,
                "Forbidden",
                "notifyWrite writer is not a member of the space",
            ));
        }
        // Owner signing key to mint per-recipient service-auth tokens for the
        // outbound fan-out. If it's unavailable we log and skip fan-out (the
        // receipt below is still recorded).
        match local_signing_key(manager, &space.space_did).await {
            Ok(owner_key) => {
                if let Err(e) = crate::space::notify::enqueue_writes(
                    manager.pool(),
                    manager.data_dir(),
                    &space,
                    &payload,
                    &owner_key,
                )
                .await
                {
                    tracing::warn!(
                        error = ?e,
                        space = %space,
                        repo = %payload.repo,
                        "notifyWrite fan-out enqueue failed; recipients may miss this revision"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    space = %space,
                    "notifyWrite fan-out skipped: owner signing key unavailable"
                );
            }
        }
    }

    // Record a lightweight receipt (dedup + audit) pinned to the owner DID.
    crate::space::inbound::receive_write(
        &http,
        plc_dir,
        manager.data_dir(),
        &space.space_did,
        body.as_ref(),
    )
    .await
    .map_err(XrpcError::from)?;
    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
//  getBlob — permissioned blob fetch (com.atproto.space.getBlob).
// ---------------------------------------------------------------------------

/// Query params for `com.atproto.space.getBlob`.
#[derive(Debug, Deserialize)]
pub struct GetSpaceBlobQuery {
    /// Space URI.
    pub space: String,
    /// DID of the account whose repo holds the blob.
    pub repo: String,
    /// CID of the blob to fetch.
    pub cid: String,
}

/// `GET /xrpc/com.atproto.space.getBlob`.
///
/// Serves the full blob as originally uploaded from `repo`'s regular
/// blobstore, gated by the same auth as `getRecord` / `listRecords`
/// (space-credential-space-match OR OAuth/session). Distinct from the public
/// `com.atproto.sync.getBlob`, which has no permissioned gate. Response carries
/// the standard atproto blob security headers (`x-content-type-options:
/// nosniff`, `content-disposition: attachment`, restrictive
/// `content-security-policy`).
pub async fn get_blob(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<GetSpaceBlobQuery>,
) -> Result<axum::response::Response, XrpcError> {
    use axum::body::Body;
    use axum::http::HeaderValue;
    use axum::http::header;

    let space = parse_space_uri(&q.space)?;
    // `repo` is required by the lexicon; ignore the auth-resolver default by
    // always passing the explicit repo param.
    let resolved = resolve_record_auth(&parts, &state, &space, Some(q.repo.as_str())).await?;
    if let Some(subject) = &resolved.subject {
        assert_space_scope(
            &state,
            subject,
            &space,
            atproto_oauth::scopes::SpaceAction::Read,
            None,
        )
        .await?;
    }
    space_reader(&state)?
        .verify_read_auth(&space, &resolved.auth)
        .await
        .map_err(XrpcError::from)?;

    let manager = account_manager(&state)?;

    // The `space` parameter has to reach the lookup. It previously gated the
    // request and was then discarded: the blob was fetched by `(repo, cid)`
    // alone, so a member of one space could read a blob referenced only from
    // another space in the same account's store.
    //
    // Asked as a predicate against the per-actor SQLite rather than joined into
    // the fetch, because on the fjall profile the bytes are not in a database
    // that knows about records. Same reasoning as the blob-takedown gate.
    let store = SqlActorStore::open(manager.data_dir(), &q.repo)
        .await
        .map_err(XrpcError::from)?;
    if !crate::space::blob_ref::is_referenced_in_space(&store, &space.to_string(), &q.cid)
        .await
        .map_err(XrpcError::from)?
    {
        return Err(XrpcError::new(
            StatusCode::NOT_FOUND,
            "BlobNotFound",
            format!("no blob {} for {}", q.cid, q.repo),
        ));
    }

    let pair = if let Some(backend) = state.public_realm_backend.as_ref() {
        backend
            .blob
            .get(&q.repo, &q.cid)
            .await
            .map_err(XrpcError::from)?
    } else {
        crate::blob::get_blob(&store, &q.cid)
            .await
            .map_err(XrpcError::from)?
    };
    let (data, mime) = pair.ok_or_else(|| {
        XrpcError::new(
            StatusCode::NOT_FOUND,
            "BlobNotFound",
            format!("no blob {} for {}", q.cid, q.repo),
        )
    })?;

    let mut resp = axum::response::Response::new(Body::from(data));
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&mime)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
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

// ---------------------------------------------------------------------------
//  listRepos — the writer set (com.atproto.space.listRepos).
// ---------------------------------------------------------------------------

/// Query params for `com.atproto.space.listRepos`.
#[derive(Debug, Deserialize)]
pub struct ListReposQuery {
    /// Space URI.
    pub space: String,
    /// Maximum number of repos to return (1..1000, default 100).
    pub limit: Option<u32>,
    /// Cursor (last `did` from the prior page).
    pub cursor: Option<String>,
}

/// One repo in `listRepos` — `{ did, rev }` per `com.atproto.space.listRepos#repo`.
///
/// Per the 0016 Permissioned Data draft (line 357), the writer set conveys each
/// repo together with its current `rev` so a syncer can resume per repo without
/// a separate probe.
#[derive(Debug, Serialize)]
pub struct RepoRef {
    /// DID of a repo that holds data in the space.
    pub did: String,
    /// The repo's current `rev` (the latest observed in this space's
    /// write-receipt log for that issuer).
    pub rev: String,
}

/// Output of `listRepos`.
#[derive(Debug, Serialize)]
pub struct ListReposResponse {
    /// Cursor for the next page, when more may remain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Page of writer repos.
    pub repos: Vec<RepoRef>,
}

/// `GET /xrpc/com.atproto.space.listRepos`.
///
/// The writer set: distinct issuer DIDs observed in the owner's inbound
/// write-receipt log (`space_received_op`), each paired with its current `rev`
/// (`MAX(rev)` over that issuer's receipts), ordered by DID, paginated by
/// `did > cursor`. Output is `{ did, rev }` per writer (spec line 357).
/// `SpaceNotFound` when the space row is absent.
///
/// Auth is **space credential only** (spec XRPC table: `listRepos` is "space
/// credential"). An OAuth/session bearer is rejected with 401; the presented
/// credential is verified against the space authority's `#atproto_space` key.
pub async fn list_repos(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<ListReposQuery>,
) -> Result<Json<ListReposResponse>, XrpcError> {
    let space = parse_space_uri(&q.space)?;
    // listRepos is space-credential-only (spec XRPC table line 483 + 394): an
    // OAuth/session token is rejected; only a verified credential is accepted.
    require_space_credential(&parts, &state, &space).await?;
    let manager = account_manager(&state)?;
    let _ = space_service(&state)?; // gate on Spaces being enabled
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);

    let store = SqlActorStore::open(manager.data_dir(), &space.space_did)
        .await
        .map_err(XrpcError::from)?;

    // SpaceNotFound when the owner's space row is absent.
    let space_exists: Option<i64> = sqlx::query_scalar("SELECT 1 FROM space WHERE uri = ? LIMIT 1")
        .bind(space.to_string())
        .fetch_optional(store.pool())
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("listRepos space lookup: {e}"),
            )
        })?;
    if space_exists.is_none() {
        return Err(XrpcError::new(
            StatusCode::NOT_FOUND,
            "SpaceNotFound",
            format!("space not found: {space}"),
        ));
    }

    let cursor = q.cursor.clone().unwrap_or_default();
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT issuer_did, MAX(rev) FROM space_received_op
         WHERE space = ? AND issuer_did > ?
         GROUP BY issuer_did
         ORDER BY issuer_did ASC
         LIMIT ?",
    )
    .bind(space.to_string())
    .bind(&cursor)
    .bind(limit as i64)
    .fetch_all(store.pool())
    .await
    .map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("listRepos query: {e}"),
        )
    })?;

    let repos: Vec<RepoRef> = rows
        .into_iter()
        .map(|(did, rev)| RepoRef { did, rev })
        .collect();
    let next_cursor = if repos.len() as u32 == limit {
        repos.last().map(|r| r.did.clone())
    } else {
        None
    };
    Ok(Json(ListReposResponse {
        cursor: next_cursor,
        repos,
    }))
}

// ---------------------------------------------------------------------------
//  registerNotify — subscribe an endpoint to write notifications.
// ---------------------------------------------------------------------------

/// Inputs for `com.atproto.space.registerNotify`.
#[derive(Debug, Deserialize)]
pub struct RegisterNotifyInput {
    /// Space URI.
    pub space: String,
    /// DID of a specific repo to subscribe to (repo host). Omit for whole-space.
    #[serde(default)]
    pub repo: Option<String>,
    /// Endpoint to which `notifyWrite` events should be delivered.
    pub endpoint: String,
}

/// Output of `registerNotify`.
#[derive(Debug, Serialize)]
pub struct RegisterNotifyResponse {
    /// When the registration expires (RFC 3339).
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
}

/// Registration window for `registerNotify` (24h).
const REGISTER_NOTIFY_TTL_SECS: i64 = 24 * 60 * 60;

/// `POST /xrpc/com.atproto.space.registerNotify`.
///
/// Authenticated with a **space credential** (`typ = space_credential`): the
/// presented JWT is verified against the space owner's `#atproto` signing key
/// and must bind to `space`. Persists a subscription keyed
/// `(space, repo-or-null, service)` with a 24h expiry and returns `expiresAt`.
pub async fn register_notify(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<RegisterNotifyInput>,
) -> Result<Json<RegisterNotifyResponse>, XrpcError> {
    let space = parse_space_uri(&input.space)?;
    let manager = account_manager(&state)?;
    let _ = space_service(&state)?; // gate on Spaces being enabled

    // Require a space-credential bearer.
    let token = bearer_token(&parts)?;
    if classify(token) != Some(SpaceTokenKind::SpaceCredential) {
        return Err(XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "registerNotify requires a space credential",
        ));
    }

    // SpaceNotFound when the owner's space row is absent.
    let owner_store = SqlActorStore::open(manager.data_dir(), &space.space_did)
        .await
        .map_err(XrpcError::from)?;
    let space_exists: Option<i64> = sqlx::query_scalar("SELECT 1 FROM space WHERE uri = ? LIMIT 1")
        .bind(space.to_string())
        .fetch_optional(owner_store.pool())
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("registerNotify space lookup: {e}"),
            )
        })?;
    if space_exists.is_none() {
        return Err(XrpcError::new(
            StatusCode::NOT_FOUND,
            "SpaceNotFound",
            format!("space not found: {space}"),
        ));
    }

    // Verify the space credential: signature over the authority's
    // #atproto_space key, bound to this space, not expired. The authority is
    // local to this host PDS, and per 0016 line 92 #atproto_space coincides
    // with the account's #atproto signing key (resolved via local_public_key).
    let owner_pub = crate::http::space_auth::local_public_key(manager, &space.space_did).await?;
    let credential = atproto_space::credential::verify_space_credential(
        token,
        &space.space_did,
        &space,
        &owner_pub,
    )
    .map_err(|e| {
        XrpcError::new(
            StatusCode::FORBIDDEN,
            "InvalidToken",
            format!("SpaceCredential verification: {e}"),
        )
    })?;

    // The credential's advisory `client_id` (the attested application)
    // identifies the subscribing service. When the credential carried no
    // attestation we key the subscription on the credential issuer (the space
    // authority) instead, so registration still succeeds.
    let service_did = credential
        .client_id
        .clone()
        .unwrap_or_else(|| credential.iss.clone());
    let expires_at =
        (chrono::Utc::now() + chrono::Duration::seconds(REGISTER_NOTIFY_TTL_SECS)).to_rfc3339();
    crate::space::notify::upsert_subscription(
        owner_store.pool(),
        &space,
        input.repo.as_deref(),
        &service_did,
        &input.endpoint,
        Some(&expires_at),
    )
    .await
    .map_err(XrpcError::from)?;

    Ok(Json(RegisterNotifyResponse { expires_at }))
}

// ---------------------------------------------------------------------------
//  notifySpaceDeleted — space-deletion lifecycle notification.
// ---------------------------------------------------------------------------

/// Inputs for `com.atproto.space.notifySpaceDeleted`.
#[derive(Debug, Deserialize)]
pub struct NotifySpaceDeletedInput {
    /// Space URI of the deleted space.
    pub space: String,
}

/// `POST /xrpc/com.atproto.space.notifySpaceDeleted`.
///
/// Service-auth: the JWT `iss` must equal the space's `spaceDid` (the
/// authority) and `aud` the recipient (a repo host or syncing service hosted
/// here). Marks the recipient-side space row as deleted (`deleted_at`).
/// Best-effort: a no-op when the recipient is not local or the space row is
/// unknown.
///
/// This PDS acts as a **repo host** here, so it implements the repo-host
/// behavior of the 0016 draft (line 365): flag the member's repo as belonging
/// to a deleted space rather than erase it (the data is the user's own). The
/// **syncer** behavior of line 367 — "delete every copy of the space's data it
/// holds, both the repos it pulled and any derived state" — is a syncer-role
/// responsibility and does not apply to the PDS-as-repo-host; this handler
/// therefore tombstones rather than purges.
pub async fn notify_space_deleted(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<NotifySpaceDeletedInput>,
) -> Result<StatusCode, XrpcError> {
    let space = parse_space_uri(&input.space)?;
    let manager = account_manager(&state)?;
    let plc_dir = state.plc_service.as_ref().map(|p| p.directory_hostname());
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(crate::user_agent())
        .build()
        .unwrap_or_default();

    // Service-auth verification. `iss` must be the space authority; `aud` is
    // the recipient hosted here. We don't know the recipient ahead of time, so
    // we peek the unverified `aud`, then verify with that expected audience.
    let token = bearer_token(&parts)?;
    let recipient_did = peek_jwt_aud(token).ok_or_else(|| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "notifySpaceDeleted: missing aud claim",
        )
    })?;
    let claims = crate::space::service_auth::verify_service_auth(
        &http,
        token,
        plc_dir,
        &recipient_did,
        "com.atproto.space.notifySpaceDeleted",
        state
            .account_manager
            .as_deref()
            .map(AccountManager::account_pool_ref),
    )
    .await
    .map_err(XrpcError::from)?;
    if claims.iss != space.space_did {
        return Err(XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "UntrustedIss",
            "notifySpaceDeleted JWT issuer must be the space DID",
        ));
    }

    // aud must be a DID/handle; best-effort no-op otherwise.
    if !recipient_did.starts_with("did:") {
        return Ok(StatusCode::OK);
    }
    // Recipient must be hosted here; otherwise best-effort no-op.
    if manager
        .lookup_handle(&recipient_did)
        .await
        .map_err(XrpcError::from)?
        .is_none()
    {
        return Ok(StatusCode::OK);
    }

    // Mark the recipient-side space row deleted; no-op if unknown.
    let store = SqlActorStore::open(manager.data_dir(), &recipient_did)
        .await
        .map_err(XrpcError::from)?;
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query("UPDATE space SET deleted_at = ? WHERE uri = ? AND deleted_at IS NULL")
        .bind(&now)
        .bind(space.to_string())
        .execute(store.pool())
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("notifySpaceDeleted mark deleted: {e}"),
            )
        })?;
    Ok(StatusCode::OK)
}

/// Best-effort extraction of the `aud` claim from a JWT *without* signature
/// verification — used only to learn the expected audience before the full
/// service-auth verification.
fn peek_jwt_aud(token: &str) -> Option<String> {
    let payload_b64 = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64.as_bytes())
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    Some(value.get("aud")?.as_str()?.to_string())
}

#[cfg(test)]
mod scope_gate_tests {
    use super::*;
    use crate::account::session::SessionClaims;
    use crate::http::auth::AuthSubject;
    use crate::oauth::token::OAuthClaims;
    use crate::space::declaration::{SpaceDeclaration, StubSpaceDeclarationResolver};
    use atproto_oauth::scopes::{SpaceAction, SpaceManageVerb};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn space_uri() -> SpaceUri {
        parse_space_uri("at://did:plc:owner/space/app.bsky.group/default").unwrap()
    }

    /// Minimal `HttpState` with no declaration resolver configured (the
    /// fail-closed default: bare grants confer no write targets).
    async fn test_state() -> HttpState {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let accounts = crate::account::AccountDirectory::open_memory()
            .await
            .unwrap();
        let reader = Arc::new(crate::repo::RepoReader::new(accounts, dir));
        HttpState::new(reader)
    }

    /// `HttpState` whose declaration resolver maps `app.bsky.group` to a
    /// declaration listing `app.bsky.feed.post` as its sole collection.
    async fn test_state_with_declaration() -> HttpState {
        let mut map = HashMap::new();
        map.insert(
            "app.bsky.group".to_string(),
            SpaceDeclaration {
                name: "Group".to_string(),
                key: "tid".to_string(),
                collections: vec!["app.bsky.feed.post".to_string()],
            },
        );
        let resolver = Arc::new(StubSpaceDeclarationResolver::new(map));
        test_state().await.with_space_declaration_resolver(resolver)
    }

    fn oauth_subject(scope: &str) -> AuthSubject {
        AuthSubject::OAuth(OAuthClaims {
            sub: "did:plc:member".to_string(),
            iss: "did:web:pds".to_string(),
            aud: "did:web:pds".to_string(),
            client_id: "https://app.example/cm".to_string(),
            scope: scope.to_string(),
            cnf: None,
            iat: 0,
            exp: u64::MAX,
            jti: "jti".to_string(),
        })
    }

    fn session_subject() -> AuthSubject {
        AuthSubject::AppPassword(SessionClaims {
            sub: "did:plc:member".to_string(),
            iss: "did:web:pds".to_string(),
            apw: "apw".to_string(),
            privileged: true,
            iat: 0,
            exp: u64::MAX,
            jti: "jti".to_string(),
        })
    }

    #[tokio::test]
    async fn oauth_read_scope_matching_space_allows_read() {
        let state = test_state().await;
        let subject =
            oauth_subject("space:app.bsky.group?did=did:plc:owner&skey=default&action=read");
        assert!(
            assert_space_scope(&state, &subject, &space_uri(), SpaceAction::Read, None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn oauth_without_space_scope_denied_403() {
        let state = test_state().await;
        let subject = oauth_subject("atproto");
        let err = assert_space_scope(&state, &subject, &space_uri(), SpaceAction::Read, None)
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(err.name, "InvalidToken");
    }

    #[tokio::test]
    async fn oauth_manage_scope_does_not_imply_read() {
        // A grant with only `manage` and no record `action` confers no record
        // read (manage and action are orthogonal axes per the 0016 spec).
        let state = test_state().await;
        let subject = oauth_subject(
            "space:app.bsky.group?did=did:plc:owner&skey=default&action=create&manage=update",
        );
        let err = assert_space_scope(&state, &subject, &space_uri(), SpaceAction::Read, None)
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn oauth_manage_verb_gated_per_verb() {
        // `manage=update` authorizes the update verb but not create/delete.
        let subject =
            oauth_subject("space:app.bsky.group?did=did:plc:owner&skey=default&manage=update");
        assert!(assert_space_manage(&subject, &space_uri(), SpaceManageVerb::Update).is_ok());
        let err = assert_space_manage(&subject, &space_uri(), SpaceManageVerb::Create).unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(err.name, "InvalidToken");
    }

    #[test]
    fn oauth_bare_grant_confers_no_manage() {
        // A bare record-access grant must not authorize any management op.
        let subject = oauth_subject("space:app.bsky.group?did=did:plc:owner&skey=default");
        for verb in SpaceManageVerb::ALL {
            let err = assert_space_manage(&subject, &space_uri(), verb).unwrap_err();
            assert_eq!(err.status, StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn oauth_read_self_own_repo_collection_constrained() {
        // read_self on the holder's own repo is collection-constrained.
        let state = test_state().await;
        let subject = oauth_subject(
            "space:app.bsky.group?did=did:plc:owner&skey=default&action=read_self&collection=app.bsky.feed.post",
        );
        // sub() == "did:plc:member"; reading own repo + covered collection.
        assert!(
            assert_space_record_read(
                &state,
                &subject,
                &space_uri(),
                "did:plc:member",
                Some("app.bsky.feed.post"),
            )
            .await
            .is_ok()
        );
        // Uncovered collection denied.
        let err = assert_space_record_read(
            &state,
            &subject,
            &space_uri(),
            "did:plc:member",
            Some("app.bsky.feed.like"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        // Reading ANOTHER member's repo requires whole-space read → denied.
        let err = assert_space_record_read(
            &state,
            &subject,
            &space_uri(),
            "did:plc:other",
            Some("app.bsky.feed.post"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn oauth_read_grant_reads_any_repo() {
        // A whole-space `read` grant reads any member's repo, any collection.
        let state = test_state().await;
        let subject =
            oauth_subject("space:app.bsky.group?did=did:plc:owner&skey=default&action=read");
        assert!(
            assert_space_record_read(
                &state,
                &subject,
                &space_uri(),
                "did:plc:other",
                Some("any.collection"),
            )
            .await
            .is_ok()
        );
        // And cross-collection (collection=None) own-repo listing.
        assert!(
            assert_space_record_read(&state, &subject, &space_uri(), "did:plc:member", None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn oauth_wildcard_type_and_did_allows_any_space() {
        let state = test_state().await;
        let subject = oauth_subject("space:*?action=read");
        assert!(
            assert_space_scope(&state, &subject, &space_uri(), SpaceAction::Read, None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn oauth_tuple_mismatch_denied() {
        // Scope is for a different owner DID — tuple gate fails.
        let state = test_state().await;
        let subject =
            oauth_subject("space:app.bsky.group?did=did:plc:other&skey=default&action=read");
        let err = assert_space_scope(&state, &subject, &space_uri(), SpaceAction::Read, None)
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn oauth_create_requires_covered_collection() {
        // `create` action but collection list does not cover the target.
        let state = test_state().await;
        let subject = oauth_subject(
            "space:app.bsky.group?did=did:plc:owner&skey=default&collection=app.bsky.feed.post&action=create",
        );
        // Covered collection → allowed.
        assert!(
            assert_space_scope(
                &state,
                &subject,
                &space_uri(),
                SpaceAction::Create,
                Some("app.bsky.feed.post"),
            )
            .await
            .is_ok()
        );
        // Uncovered collection → denied.
        let err = assert_space_scope(
            &state,
            &subject,
            &space_uri(),
            SpaceAction::Create,
            Some("app.bsky.feed.like"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn read_scope_does_not_grant_write() {
        let state = test_state().await;
        let subject =
            oauth_subject("space:app.bsky.group?did=did:plc:owner&skey=default&action=read");
        let err = assert_space_scope(
            &state,
            &subject,
            &space_uri(),
            SpaceAction::Create,
            Some("app.bsky.feed.post"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn app_password_session_skips_scope_gate() {
        // Non-OAuth subjects are authorized at the session layer and skip the
        // `space:` scope check entirely. `assert_space_manage` is sync; the
        // record-scope gate is covered by the async tests above.
        let subject = session_subject();
        assert!(assert_space_manage(&subject, &space_uri(), SpaceManageVerb::Update).is_ok());
    }

    #[tokio::test]
    async fn app_password_session_skips_record_scope_gate() {
        // Non-OAuth subjects skip the `space:` record-scope check entirely
        // (only OAuth grants carry `space:` scopes per the 0016 spec, lines
        // 369-419).
        let state = test_state().await;
        let subject = session_subject();
        assert!(
            assert_space_scope(&state, &subject, &space_uri(), SpaceAction::Read, None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn read_opt_none_skips_gate() {
        // SpaceCredential auth (None subject) always passes the read gate.
        let state = test_state().await;
        assert!(
            assert_space_read_opt(&state, &None, &space_uri())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn bare_grant_defaults_to_declared_collections() {
        // A bare `space:app.bsky.group` grant (omits `collection` and `action`)
        // must default its write targets to the declaration's `collections`
        // (spec line 413). With a resolver mapping the type to a declaration
        // listing `app.bsky.feed.post`, a create on that collection is allowed.
        let state = test_state_with_declaration().await;
        let subject = oauth_subject("space:app.bsky.group?did=did:plc:owner&skey=default");
        assert!(
            assert_space_scope(
                &state,
                &subject,
                &space_uri(),
                SpaceAction::Create,
                Some("app.bsky.feed.post"),
            )
            .await
            .is_ok()
        );
        // A collection NOT in the declaration is not conferred by the default.
        let err = assert_space_scope(
            &state,
            &subject,
            &space_uri(),
            SpaceAction::Create,
            Some("app.bsky.feed.like"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn bare_grant_without_resolver_confers_no_write_targets() {
        // Fail-closed: with no declaration resolver configured, a bare grant's
        // omitted-`collection` default resolves to empty, so no write target is
        // conferred (the pre-F4 behavior, now explicit and documented).
        let state = test_state().await;
        let subject = oauth_subject("space:app.bsky.group?did=did:plc:owner&skey=default");
        let err = assert_space_scope(
            &state,
            &subject,
            &space_uri(),
            SpaceAction::Create,
            Some("app.bsky.feed.post"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
    }
}
