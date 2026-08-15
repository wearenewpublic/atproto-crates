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
use crate::http::auth::{
    AuthScheme, authorization_token, bearer_token, request_htm_htu, require_authn,
    require_authn_sub, require_scheme,
};
use crate::http::errors::XrpcError;
use crate::http::extract::{XrpcJson as Json, XrpcQuery as Query};
use crate::http::space_auth::{
    SpaceTokenKind, classify, local_signing_key, peek_delegation_token,
    verify_local_delegation_token,
};
use crate::http::state::HttpState;
use crate::space::notify::upsert_recipient;
use crate::space::reader::SpaceReadAuth;
use crate::space::writer::{SpaceCommitResult, SpaceWriteAction, SpaceWriteOp};
use crate::space::{Membership, SpaceReader, SpaceService, SpaceSync, SpaceWriter};
use atproto_space::credential::{
    DELEGATION_TOKEN_TTL_SECS, TYP_SPACE_CREDENTIAL, create_delegation_token,
    create_space_credential,
};
use atproto_space::storage::OplogCursor;
use atproto_space::types::SpaceUri;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::request::Parts;
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
    let (htm, htu) = request_htm_htu(parts, state.trusted_proxy_hops);
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
    let (htm, htu) = request_htm_htu(parts, state.trusted_proxy_hops);
    require_authn(parts, state, &htm, &htu).await
}

/// Refuse to serve a permissioned repo whose account this server may no longer
/// serve.
///
/// 0016's "Account lifecycle" section is explicit that the events already in
/// the protocol carry over unchanged: a deleted account's permissioned data is
/// deleted, and a deactivated account's is not served. So this is the same
/// account-state gate the public sync and blob endpoints pass through, applied
/// to the repo a space read names.
///
/// `caller` is the DID authenticated by an OAuth or session token, and `None`
/// for a space credential. That distinction is the whole point of taking the
/// caller at all: deactivation withdraws a repository from everyone except its
/// owner, and a space credential is the one auth mode here that proves nothing
/// about who is asking beyond the space authority's say-so. Reading it as
/// anonymous is correct — its holder is a syncer, which is exactly the
/// audience deactivation withdraws from.
///
/// # Why `require_readable_if_present` and not `require_available_for`
///
/// A repo this server does not host is not this gate's business to answer for.
/// Cross-host membership is ordinary here — `assert_space_membership` defers to
/// the authority precisely because the member list may name accounts that live
/// elsewhere — so resolving the identifier and refusing what is missing would
/// turn "not hosted here" into a refusal, ahead of the scope check that should
/// have answered first. Doing it that way also makes this endpoint a directory:
/// an under-scoped caller could tell a DID this server hosts from one it does
/// not by which error came back.
///
/// Membership is checked separately and does not overlap: it asks whether the
/// repo belongs to this space, and this asks whether the account behind it is
/// still one this server answers for.
///
/// # Errors
///
/// [`PdsError::RepoUnavailable`](crate::errors::PdsError::RepoUnavailable),
/// rendered as `RepoDeactivated` / `RepoTakendown` / `RepoSuspended`, matching
/// what a caller already branches on for the public realm.
async fn require_repo_hosted(
    state: &HttpState,
    repo: &str,
    caller: Option<&str>,
) -> Result<(), XrpcError> {
    state
        .reader
        .require_readable_if_present(repo, caller)
        .await
        .map_err(XrpcError::from)
}

/// Authenticate a space write, and refuse an account whose state disallows
/// writing.
///
/// The mirror of [`require_repo_hosted`], and needed for the same reason the
/// public realm needed `require_writable_session`: a valid token is not an
/// account permitted to write, and a moderated account kept writing until its
/// refresh token expired — up to 90 days after the action.
///
/// `allows_writes` is `Active` alone, so a deactivated account is refused here
/// where it is permitted to *read* its own repo above. That asymmetry is
/// deliberate and matches the public realm: deactivation is a withdrawal, and
/// letting it keep writing would mean records accruing in a repo nothing is
/// allowed to sync. The public realm's one carve-out, `require_migration_session`,
/// has no counterpart here because there is no inbound-migration path that
/// writes permissioned records — when one lands it will need the same
/// exception, and will have to say so.
///
/// # Errors
///
/// Whatever [`require_authn`] returns, or 403 `AccountDeactivated` /
/// `AccountTakendown` when the account may not write.
async fn require_writable_session_auth(
    parts: &Parts,
    state: &HttpState,
) -> Result<crate::http::auth::AuthSubject, XrpcError> {
    let subject = require_session_auth(parts, state).await?;
    let account = state
        .reader
        .accounts()
        .lookup_did(subject.sub())
        .await
        .map_err(XrpcError::from)?;
    if let Some(account) = account
        && !account.state.allows_writes()
    {
        return Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            match account.state {
                crate::account::AccountState::Deactivated => "AccountDeactivated",
                crate::account::AccountState::Takendown => "AccountTakendown",
                crate::account::AccountState::Suspended => "AccountSuspended",
                _ => "AccountInactive",
            },
            format!(
                "this account is {} and may not write permissioned records",
                account.state.as_str()
            ),
        ));
    }
    Ok(subject)
}

// ---------------------------------------------------------------------------
//  Management endpoints.
// ---------------------------------------------------------------------------

/// Inputs for `com.atproto.simplespace.createSpace`.
///
/// The lexicon shape is `{type, skey?, policy, appAccess}`, with `policy` and
/// `appAccess` as top-level open unions. `skey` auto-generates a TID when
/// absent.
///
/// Two fields are kept beyond that shape. `did` is the DID of the space
/// authority: it defaults to the authenticated caller and, if supplied, must
/// equal the caller. `config` is the nested `#spaceConfig` object this server
/// required before the unions were lifted to the top level; a caller sending
/// both gets the top-level fields, which are the lexicon's.
///
/// `policy` and `appAccess` are optional here where the lexicon marks them
/// required, so that a client written against the older shape keeps creating
/// spaces. Omitting them applies the documented defaults (`member-list` /
/// `#open`) — which is what the spec prose says an unconfigured space has.
/// Nothing is silently discarded either way: what a caller sends is what the
/// space gets.
#[derive(Debug, Deserialize)]
pub struct CreateSpaceInput {
    /// DID of the space (the authority). Defaults to the caller.
    pub did: Option<String>,
    /// NSID space type (e.g., `app.bsky.group`).
    #[serde(rename = "type")]
    pub space_type: String,
    /// Space key. Auto-generated as a TID when omitted.
    pub skey: Option<String>,
    /// User-authorization policy, as the lexicon's open union.
    pub policy: Option<serde_json::Value>,
    /// App-authorization policy, as the lexicon's open union.
    #[serde(rename = "appAccess")]
    pub app_access: Option<serde_json::Value>,
    /// Initial space configuration (`com.atproto.simplespace.defs#spaceConfig`),
    /// the pre-union nesting. Superseded by the two fields above.
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
    let subject = require_writable_session_auth(&parts, &state).await?;
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
    // The lexicon's top-level `policy`/`appAccess` win over the nested
    // `config` this server used to require; either shape reaches the same
    // parser, which is also what rejects a union variant we do not implement.
    let config_value = match (&input.policy, &input.app_access) {
        (None, None) => input.config.clone(),
        _ => {
            let mut obj = match input.config.clone() {
                Some(serde_json::Value::Object(m)) => m,
                _ => serde_json::Map::new(),
            };
            if let Some(p) = input.policy.clone() {
                obj.insert("policy".to_string(), p);
            }
            if let Some(a) = input.app_access.clone() {
                obj.insert("appAccess".to_string(), a);
            }
            Some(serde_json::Value::Object(obj))
        }
    };
    let config = match config_value {
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
///
/// The lexicon shape is `{space, policy?, appAccess?}`, both config fields
/// being open unions that replace the current value wholesale. Omitted fields
/// are left unchanged.
#[derive(Debug, Deserialize)]
pub struct UpdateSpaceInput {
    /// Space URI to update.
    pub space: String,
    /// New user-authorization policy, if provided.
    ///
    /// Untyped because it carries either shape: the lexicon's `$type`-tagged
    /// union, or the bare `knownValues` string this server used to require.
    /// Typing it as `String` is what made a conformant client's union fail
    /// deserialization with a generic 400 that named nothing.
    pub policy: Option<serde_json::Value>,
    /// Deprecated spelling of [`UpdateSpaceInput::policy`].
    #[serde(rename = "mintPolicy")]
    pub mint_policy: Option<serde_json::Value>,
    /// New managing-app identifier. Empty string clears to NULL.
    ///
    /// Superseded by `#managingAppPolicy`, which carries its own; kept for the
    /// legacy string `policy`, which cannot express one.
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
    let subject = require_writable_session_auth(&parts, &state).await?;
    let owner = subject.sub().to_string();
    let uri = parse_space_uri(&input.space)?;
    assert_space_manage(
        &subject,
        &uri,
        atproto_oauth::scopes::SpaceManageVerb::Update,
    )?;
    // Reassemble the config-field object the patch parser expects.
    let mut obj = serde_json::Map::new();
    if let Some(p) = input.policy.or(input.mint_policy) {
        obj.insert("policy".to_string(), p);
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
    let subject = require_writable_session_auth(&parts, &state).await?;
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

/// Best-effort fan-out of `notifySpaceDeleted` to the services registered for
/// `uri`, after the authority deletes the space.
///
/// **Only** the registered services. This used to notify every member of the
/// space as well, which the amended 0016 repeals: a member's records are the
/// member's own data, and deleting the space does not entitle the authority to
/// reach into the repos that hold them. Those records simply become
/// unreadable to everyone but the member's own account.
///
/// Worse than being wrong about the members, the old target selection was
/// close to inverted. It re-resolved every target through `#atproto_pds`
/// rather than using the endpoint the service registered, and a syncer service
/// typically publishes no `#atproto_pds` at all — so the recipients the spec
/// requires were the ones silently dropped, while the recipients it forbids
/// resolved reliably.
///
/// Delivery now goes through the notifier queue, which is what "over the same
/// best-effort path as write notifications" asks for: a failed POST is retried
/// rather than lost, expired registrations are filtered, and each endpoint is
/// re-validated before anything is signed for it.
async fn fire_notify_space_deleted(state: &HttpState, uri: &SpaceUri, authority_did: &str) {
    let Ok(manager) = account_manager(state) else {
        return;
    };
    let signing_key = match crate::http::space_auth::local_signing_key(manager, authority_did).await
    {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(error = ?e, space = %uri, "notifySpaceDeleted: owner signing key unavailable; skipping fan-out");
            return;
        }
    };
    match crate::space::notify::enqueue_space_deleted(
        manager.pool(),
        manager.data_dir(),
        uri,
        &signing_key,
    )
    .await
    {
        Ok(count) => {
            tracing::debug!(space = %uri, recipients = count, "notifySpaceDeleted enqueued");
        }
        Err(e) => {
            tracing::warn!(error = ?e, space = %uri, "notifySpaceDeleted fan-out could not be enqueued");
        }
    }
}

/// Query params for `getSpace`.
#[derive(Debug, Deserialize)]
pub struct GetSpaceQuery {
    /// Full space URI.
    pub space: String,
}

/// `GET /xrpc/com.atproto.simplespace.getSpace` — describe a space and its
/// configuration.
///
/// Accepts a space credential or an OAuth session covering the space. The
/// space authority hosts the config, so this reads the authority's store and
/// takes no viewer: authorization decides *who may ask*, and the answer does
/// not depend on who asked.
pub async fn get_space(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<GetSpaceQuery>,
) -> Result<Json<GetSpaceOutput>, XrpcError> {
    let mut out = describe_space(&state, &parts, &q).await?;
    // The lexicon's output is `{uri, policy, appAccess}`; the wrapper is the
    // alias's business, not this endpoint's.
    out.config = None;
    Ok(Json(out))
}

/// `GET /xrpc/com.atproto.space.getSpace` — deprecated alias.
///
/// PR #100 moved `getSpace` into `com.atproto.simplespace`, where it belongs:
/// describing a space's `policy` and `appAccess` is a question about the
/// management implementation, not about the permissioned-data protocol every
/// space host implements.
///
/// The alias answers with a superset — the lexicon's top-level `policy` and
/// `appAccess` *plus* the `config` wrapper this server used to nest them in —
/// so a caller written against either shape keeps working and can migrate in
/// place rather than in lockstep with the rename.
pub async fn get_space_deprecated_alias(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<GetSpaceQuery>,
) -> Result<Json<GetSpaceOutput>, XrpcError> {
    tracing::debug!(
        space = %q.space,
        "com.atproto.space.getSpace is deprecated; use com.atproto.simplespace.getSpace"
    );
    Ok(Json(describe_space(&state, &parts, &q).await?))
}

/// Shared body of the two `getSpace` routes.
async fn describe_space(
    state: &HttpState,
    parts: &Parts,
    q: &GetSpaceQuery,
) -> Result<GetSpaceOutput, XrpcError> {
    let uri = parse_space_uri(&q.space)?;
    let subject = require_any_authn(parts, state, &uri).await?;
    assert_space_read_opt(state, &subject, &uri).await?;
    let svc = space_service(state)?;
    svc.get_space(&uri).await.map_err(XrpcError::from)
}

/// Query params for `listSpaces`.
#[derive(Debug, Deserialize)]
pub struct ListSpacesQuery {
    /// Filter to spaces of this type (NSID). The lexicon names this `type`.
    #[serde(rename = "type")]
    pub space_type: Option<String>,
    /// Filter to spaces under this authority DID.
    pub did: Option<String>,
    /// Cursor (last `uri` from prior page).
    pub cursor: Option<String>,
    /// Page size, 1..=100, default 50.
    pub limit: Option<u32>,
}

/// Output of `listSpaces`.
#[derive(Debug, Serialize)]
pub struct ListSpacesResponse {
    /// Page of spaces.
    pub spaces: Vec<SpaceInfo>,
    /// Cursor for the next page, absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// `GET /xrpc/com.atproto.space.listSpaces`.
pub async fn list_spaces(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<ListSpacesQuery>,
) -> Result<Json<ListSpacesResponse>, XrpcError> {
    let viewer = require_session_subject(&parts, &state).await?;
    let svc = space_service(&state)?;
    let page = svc
        .list_spaces(
            &viewer,
            q.space_type.as_deref(),
            q.did.as_deref(),
            q.cursor.as_deref(),
            page_limit(q.limit, 50, 100),
        )
        .await
        .map_err(XrpcError::from)?;
    Ok(Json(ListSpacesResponse {
        spaces: page.spaces,
        cursor: page.cursor,
    }))
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
    let subject = require_writable_session_auth(&parts, &state).await?;
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
    let subject = require_writable_session_auth(&parts, &state).await?;
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
    let caller = subject.sub().to_string();
    let uri = parse_space_uri(&q.space)?;
    // A read grant over the space, not a management one: enumerating who is in
    // a space you are in is reading, and `read` implies `read_self`.
    assert_space_scope(
        &state,
        &subject,
        &uri,
        atproto_oauth::scopes::SpaceAction::ReadSelf,
        None,
    )
    .await?;
    // Holding a covering scope is the user's consent to the app, not evidence
    // that the user is in the space. Membership is the other half, and is what
    // stops any local account that happened to be granted a `space:` scope
    // from enumerating a space it was never admitted to.
    assert_space_membership(&state, &uri, Some(&caller), &caller).await?;
    let page = space_service(&state)?
        .list_members(&uri, q.cursor.as_deref(), page_limit(q.limit, 100, 1000))
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
    /// DID of the repo to write to (the authenticated member).
    pub repo: String,
    /// Lexicon validation toggle (reserved; not yet enforced, matching
    /// `createRecord` and `putRecord`).
    #[allow(dead_code)]
    pub validate: Option<bool>,
    /// Write batch.
    pub writes: Vec<ApplyWritesOp>,
}

/// One entry in the `applyWrites` results array.
///
/// The lexicon declares a closed union of `#createResult` / `#updateResult` /
/// `#deleteResult`, so each entry carries its `$type` and the variant decides
/// which fields are present — a delete result is an empty object.
#[derive(Debug, Serialize)]
#[serde(tag = "$type")]
pub enum ApplyWritesResult {
    /// `com.atproto.space.applyWrites#createResult`.
    #[serde(rename = "com.atproto.space.applyWrites#createResult")]
    Create {
        /// URI of the created record.
        uri: String,
        /// CID of the record value.
        cid: String,
        /// Validation status when known.
        #[serde(rename = "validationStatus", skip_serializing_if = "Option::is_none")]
        validation_status: Option<String>,
    },
    /// `com.atproto.space.applyWrites#updateResult`.
    #[serde(rename = "com.atproto.space.applyWrites#updateResult")]
    Update {
        /// URI of the written record.
        uri: String,
        /// CID of the record value.
        cid: String,
        /// Validation status when known.
        #[serde(rename = "validationStatus", skip_serializing_if = "Option::is_none")]
        validation_status: Option<String>,
    },
    /// `com.atproto.space.applyWrites#deleteResult` — an empty object.
    #[serde(rename = "com.atproto.space.applyWrites#deleteResult")]
    Delete {},
}

/// Output of `applyWrites`.
///
/// The lexicon declares `{results}` and nothing else. The commit `rev` and
/// `setHash` this server used to return here are not part of the shape; a
/// caller that needs them reads `getLatestCommit`.
#[derive(Debug, Serialize)]
pub struct ApplyWritesResponse {
    /// One result per write, in request order.
    pub results: Vec<ApplyWritesResult>,
}

/// Project a [`SpaceCommitResult`] into the lexicon's results array.
///
/// `actions` is the batch in request order; the writer returns `uris` and
/// `cids` parallel to it, so the variant of each result is decided by the
/// action that produced it rather than by whether a CID came back.
fn apply_writes_results(
    actions: &[SpaceWriteAction],
    result: SpaceCommitResult,
) -> Result<Vec<ApplyWritesResult>, XrpcError> {
    if result.uris.len() != actions.len() || result.cids.len() != actions.len() {
        return Err(XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "commit returned a different number of results than writes",
        ));
    }
    let mut out = Vec::with_capacity(actions.len());
    for ((action, uri), cid) in actions.iter().zip(result.uris).zip(result.cids) {
        match action {
            SpaceWriteAction::Delete => out.push(ApplyWritesResult::Delete {}),
            SpaceWriteAction::Create | SpaceWriteAction::Update => {
                let cid = cid.ok_or_else(|| {
                    XrpcError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        "write produced no record CID",
                    )
                })?;
                if matches!(action, SpaceWriteAction::Create) {
                    out.push(ApplyWritesResult::Create {
                        uri,
                        cid,
                        validation_status: None,
                    });
                } else {
                    out.push(ApplyWritesResult::Update {
                        uri,
                        cid,
                        validation_status: None,
                    });
                }
            }
        }
    }
    Ok(out)
}

/// `POST /xrpc/com.atproto.space.applyWrites`.
pub async fn apply_writes(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<ApplyWritesInput>,
) -> Result<Json<ApplyWritesResponse>, XrpcError> {
    let auth = require_writable_session_auth(&parts, &state).await?;
    let member_did = auth.sub().to_string();
    require_repo_matches_subject(&input.repo, &member_did)?;
    let uri = parse_space_uri(&input.space)?;
    require_space_member(&state, &uri, &member_did).await?;
    let writer = space_writer(&state)?;

    if input.writes.is_empty() {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "applyWrites requires at least one op",
        ));
    }

    let mut ops = Vec::with_capacity(input.writes.len());
    let mut actions = Vec::with_capacity(input.writes.len());
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
        actions.push(action.clone());
        ops.push(SpaceWriteOp {
            action,
            collection: w.collection,
            rkey: w.rkey,
            value: w.value,
        });
    }

    let result = writer
        .apply_writes(&member_did, &uri, ops)
        .await
        .map_err(XrpcError::from)?;
    Ok(Json(ApplyWritesResponse {
        results: apply_writes_results(&actions, result)?,
    }))
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
    let auth = require_writable_session_auth(&parts, &state).await?;
    let subject = auth.sub().to_string();
    require_repo_matches_subject(&input.repo, &subject)?;
    let uri = parse_space_uri(&input.space)?;
    require_space_member(&state, &uri, &subject).await?;
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
    let auth = require_writable_session_auth(&parts, &state).await?;
    let subject = auth.sub().to_string();
    require_repo_matches_subject(&input.repo, &subject)?;
    let uri = parse_space_uri(&input.space)?;
    require_space_member(&state, &uri, &subject).await?;
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
    let auth = require_writable_session_auth(&parts, &state).await?;
    let subject = auth.sub().to_string();
    require_repo_matches_subject(&input.repo, &subject)?;
    let uri = parse_space_uri(&input.space)?;
    require_space_member(&state, &uri, &subject).await?;
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
    /// DID of the member whose repo to read from.
    ///
    /// Required by the lexicon. It used to be optional, defaulting to the
    /// authenticated subject — but a record URI names its author, so a caller
    /// that omitted it got back a URI missing the segment that identifies whose
    /// record it is.
    pub repo: String,
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
    let resolved = resolve_record_auth(&parts, &state, &uri, Some(q.repo.as_str())).await?;
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
        // Built through `RecordUri` rather than a format string. The old
        // version omitted the author segment, so the URI this endpoint returned
        // did not parse with this crate's own `RecordUri::parse` — a client
        // that fed it back got a syntax error.
        uri: atproto_space::RecordUri::new(
            uri.clone(),
            resolved.target_repo.clone(),
            q.collection.clone(),
            q.rkey.clone(),
        )
        .to_string(),
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
    /// Page size. Clamped to the lexicon's 1–100.
    pub limit: Option<u32>,
    /// DID of the member whose repo to read from. If omitted, defaults to
    /// the authenticated subject (OAuth auth). Required when using
    /// space-credential auth.
    pub repo: Option<String>,
    /// Reverse the record order.
    #[serde(default)]
    pub reverse: bool,
    /// Return `{collection, rkey, cid}` only, omitting inlined values.
    ///
    /// Defaults to `false`: the lexicon inlines values by default, and a
    /// keys-only listing made sync quadratic — one `getRecord` round trip per
    /// record, with no bulk path.
    #[serde(rename = "excludeValues", default)]
    pub exclude_values: bool,
}

/// One record in `listRecords`, per `com.atproto.space.listRecords#record`.
///
/// `value` is inlined **by default**; `excludeValues` reduces the entry to
/// `{collection, rkey, cid}`. It previously always omitted the value, which
/// made sync quadratic: a syncer had to issue one `getRecord` per record with
/// no bulk path, so initial backfill was unusable.
#[derive(Debug, Serialize)]
pub struct SpaceRecordItem {
    /// NSID collection.
    pub collection: String,
    /// Record key.
    pub rkey: String,
    /// CID of the record value.
    pub cid: String,
    /// The record's value, inlined by default. Omitted when `excludeValues`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
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
            crate::space::reader::RecordListing {
                collection: q.collection.as_deref(),
                cursor: q.cursor.as_deref(),
                limit: page_limit(q.limit, 50, 100),
                reverse: q.reverse,
            },
        )
        .await
        .map_err(XrpcError::from)?;
    let mut records = Vec::with_capacity(page.records.len());
    for r in page.records {
        let value = if q.exclude_values {
            None
        } else {
            Some(decode_record_value(&r.value)?)
        };
        records.push(SpaceRecordItem {
            collection: r.collection,
            rkey: r.rkey,
            cid: r.cid,
            value,
        });
    }
    Ok(Json(ListSpaceRecordsResponse {
        records,
        cursor: page.cursor,
    }))
}

/// Decode a stored DAG-CBOR record value into its JSON representation.
///
/// The same path the public reader uses, so a link stored as CBOR tag 42 comes
/// back as `{"$link": …}` rather than as a raw map.
fn decode_record_value(bytes: &[u8]) -> Result<serde_json::Value, XrpcError> {
    atproto_dasl::atproto_json::from_slice(bytes).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("decode permissioned record value: {e}"),
        )
    })
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
///
/// # When the member list is not on this server
///
/// The list belongs to the space authority, so for a space hosted elsewhere
/// there is nothing here to check against, and reading that absence as "not a
/// member" refused every read in every cross-PDS space — including a member
/// reading their own repo, and including a SpaceCredential minted by the very
/// authority that holds the list. But it cannot simply be waved through
/// either: the *target* check is what stops one account being handed another
/// account's permissioned records, and "I could not verify it" is not a reason
/// to answer with someone else's data.
///
/// So the two questions part company on
/// [`Membership::AuthorityElsewhere`]:
///
/// - **The caller**, and a target that *is* the caller, defer to the authority
///   that owns the list — the caller is authenticated as themselves and is
///   reading their own records either way.
/// - **A target that is not the caller** needs positive local evidence, and an
///   unverifiable claim is refused. A session-authenticated account does not
///   get another account's records out of a space this server cannot vouch for.
/// - **A SpaceCredential** (`caller: None`) defers, because the credential is
///   the authority's own signed statement about its space and
///   [`SpaceReader::verify_auth`] has checked that signature. That is the
///   cross-host read path, and the authority is exactly who should answer.
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
        && service
            .membership(uri, caller)
            .await
            .map_err(XrpcError::from)?
            == Membership::NotMember
    {
        tracing::debug!(space = %uri, caller = %caller, "space read refused: caller is not a member");
        return Err(deny());
    }
    // When the caller reads its own repo, the caller check above already
    // established membership.
    if caller != Some(target) {
        let target_membership = service
            .membership(uri, target)
            .await
            .map_err(XrpcError::from)?;
        let vouched = match caller {
            // Session or OAuth: only a local member list can put another
            // account's records in front of this caller.
            Some(_) => target_membership == Membership::Member,
            // SpaceCredential: the authority signed for this space, so its
            // absence from this server is not evidence against the target.
            None => target_membership != Membership::NotMember,
        };
        if !vouched {
            tracing::debug!(
                space = %uri,
                target = %target,
                membership = ?target_membership,
                "space read refused: target is not a member this server can vouch for"
            );
            return Err(deny());
        }
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
    // Both token kinds that reach here are DPoP-bound -- a `cnf`-bound OAuth
    // token and a space credential -- so the scheme is read rather than
    // assumed, and each branch requires the one its binding implies.
    let (scheme, raw) = authorization_token(parts)?;
    match classify(raw) {
        Some(SpaceTokenKind::SpaceCredential) => {
            require_scheme(
                scheme,
                AuthScheme::Dpop,
                "a space credential is bound to a key",
            )?;
            let repo = repo.ok_or_else(|| {
                XrpcError::new(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "repo is required for space credential auth",
                )
            })?;
            // Proof of possession before anything else this credential could
            // buy: the signature is checked downstream by the reader, and
            // neither check stands in for the other.
            crate::http::space_auth::require_credential_dpop_proof(parts, state, raw).await?;
            // What is checked here is that the repo it names belongs to this
            // space.
            assert_space_membership(state, space, None, repo).await?;
            // A credential says the authority admitted this reader to the
            // space. It says nothing about whether this server may still serve
            // the repo, which is the account holder's and this host's business.
            require_repo_hosted(state, repo, None).await?;
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
        other => {
            // A token signed with somebody's key is not one of the two HMAC
            // shapes below, and saying so here is the difference between a
            // usable refusal and a misleading one. Falling through, the HMAC
            // verifier reported the first thing it noticed -- "bearer token
            // rejected: unsupported alg ES256K" -- which reads as this server
            // lacking ES256K support. It does not: the algorithm is fine and
            // the token is simply not one of the kinds this endpoint takes,
            // which is what a caller needs to be told.
            if let Some(alg) = crate::http::space_auth::token_alg(raw)
                && crate::http::space_auth::is_asymmetric_jws(&alg)
            {
                let typ = match &other {
                    Some(SpaceTokenKind::Other(typ)) => typ.clone(),
                    _ => "none".to_string(),
                };
                tracing::debug!(
                    alg = %alg,
                    typ = %typ,
                    "space read refused: token is signed with a key but is not a space token"
                );
                return Err(XrpcError::new(
                    StatusCode::UNAUTHORIZED,
                    "AuthenticationRequired",
                    format!(
                        "this endpoint accepts a session token, an OAuth access token, or a \
                         SpaceCredential (typ={TYP_SPACE_CREDENTIAL}); the presented token is \
                         signed with {alg} and declares typ={typ}"
                    ),
                ));
            }
            // Treat as a session-style or OAuth access token. The unified
            // helper transparently accepts both shapes and enforces DPoP
            // when an OAuth token carries a `cnf.jkt` thumbprint.
            let (htm, htu) = request_htm_htu(parts, state.trusted_proxy_hops);
            let subject = require_authn(parts, state, &htm, &htu).await?;
            let sub = subject.sub().to_string();
            let target_repo = repo.map(|r| r.to_string()).unwrap_or_else(|| sub.clone());
            assert_space_membership(state, space, Some(&sub), &target_repo).await?;
            require_repo_hosted(state, &target_repo, Some(&sub)).await?;
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

/// atproto lex-data `bytes` value, `{"$bytes": "<base64>"}`.
///
/// Defined in [`crate::space::lex_bytes`] so the writer can build one without
/// reaching into the HTTP layer — `notifyWrite` carries a `$bytes` field and is
/// sent by domain code.
pub use crate::space::lex_bytes::BytesValue;

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
    Ok(sign_current_commit(space, author, state, signing_key)?.map(SignedCommitDto::from_commit))
}

/// Sign the repo's current state, returning the commit itself.
///
/// Shared by the JSON path (which wraps it in a [`SignedCommitDto`]) and
/// `getRepo` (which needs the DAG-CBOR block for the CAR's first root). The two
/// must be the same commit: a CAR whose root disagreed with what
/// `getLatestCommit` reports would send a syncer chasing a mismatch.
fn sign_current_commit(
    space: &SpaceUri,
    author: &str,
    state: &atproto_space::RepoState,
    signing_key: &atproto_identity::key::KeyData,
) -> Result<Option<atproto_space::Commit>, XrpcError> {
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
    Ok(Some(commit))
}

/// The signed commit as the DAG-CBOR block that becomes the CAR's first root.
fn signed_commit_block(
    space: &SpaceUri,
    author: &str,
    state: &atproto_space::RepoState,
    signing_key: &atproto_identity::key::KeyData,
) -> Result<Option<Vec<u8>>, XrpcError> {
    let Some(commit) = sign_current_commit(space, author, state, signing_key)? else {
        return Ok(None);
    };
    let block = atproto_dasl::to_vec(&commit).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("encode signed commit: {e}"),
        )
    })?;
    Ok(Some(block))
}

/// `GET /xrpc/com.atproto.space.getRepoState`.
///
/// Returns the repo account's current signed commit (`records` scope, signed
/// by the repo account's atproto signing key). `commit` is absent when the
/// repo is empty.
///
/// Auth goes through [`resolve_record_auth`], the same as every other record
/// read. It authenticated before, which is not the same thing: the caller was
/// established and then never checked against the space, so any account on
/// this server could name any space and any member and be answered. That it
/// signs a fresh commit with the repo account's own key made it the worse of
/// the two endpoints to leave open.
pub async fn get_repo_state(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<RepoStateQuery>,
) -> Result<Json<StateResponse>, XrpcError> {
    let uri = parse_space_uri(&q.space)?;
    let resolved = resolve_record_auth(&parts, &state, &uri, Some(q.repo.as_str())).await?;
    if let Some(subject) = &resolved.subject {
        // An own-repo read is a `read_self` read; only reaching
        // another member's repo needs whole-space `read`.
        assert_space_record_read(&state, subject, &uri, &q.repo, None).await?;
    }
    // 401 rather than the `AuthDenied` default of 403: a credential that does
    // not verify is a failure to authenticate, not a permission shortfall, and
    // this is the status these two endpoints have always answered a forged one
    // with. Routing them through `resolve_record_auth` should change who is
    // refused, not what a refusal looks like.
    space_reader(&state)?
        .verify_read_auth(&uri, &resolved.auth)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::UNAUTHORIZED,
                "Unauthorized",
                format!("invalid space credential: {e}"),
            )
        })?;
    let st = space_sync(&state)?
        .get_repo_state(
            &uri,
            &q.repo,
            resolved.subject.as_ref().is_some_and(|s| s.sub() == q.repo),
        )
        .await
        .map_err(XrpcError::from)?;
    let manager = account_manager(&state)?;
    let signing_key = local_signing_key(manager, &q.repo).await?;
    let commit = signed_commit_from_state(&uri, &q.repo, &st, &signing_key)?;
    Ok(Json(StateResponse { commit }))
}

/// `GET /xrpc/com.atproto.space.getRepo`.
///
/// The whole repo as a CAR, for full-state recovery — the only path available to
/// a syncer that has fallen past its oplog retention. `listRepoOps` replays
/// changes and cannot rebuild a repo whose earliest ops were pruned;
/// `listRecords` carries no commit and no CID-addressed blocks.
///
/// Layout is [`crate::space::export_car`]'s: two roots (commit, then a DRISL
/// index), the commit block, the index block, then record blocks in
/// `{collection}/{rkey}` order. Blobs are excluded by the lexicon and fetched
/// separately through `space.getBlob`.
///
/// Auth goes through the same [`resolve_record_auth`] as every other record
/// read, so the membership check and the space gate apply unchanged.
pub async fn get_repo(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<RepoStateQuery>,
) -> Result<axum::response::Response, XrpcError> {
    use axum::body::Body;
    use axum::http::HeaderValue;
    use axum::http::header;

    let uri = parse_space_uri(&q.space)?;
    let resolved = resolve_record_auth(&parts, &state, &uri, Some(q.repo.as_str())).await?;
    if let Some(subject) = &resolved.subject {
        // An own-repo read is a `read_self` read; only reaching
        // another member's repo needs whole-space `read`.
        assert_space_record_read(&state, subject, &uri, &q.repo, None).await?;
    }
    space_reader(&state)?
        .verify_read_auth(&uri, &resolved.auth)
        .await
        .map_err(XrpcError::from)?;

    let st = space_sync(&state)?
        .get_repo_state(
            &uri,
            &q.repo,
            resolved.subject.as_ref().is_some_and(|s| s.sub() == q.repo),
        )
        .await
        .map_err(XrpcError::from)?;
    let manager = account_manager(&state)?;
    let signing_key = local_signing_key(manager, &q.repo).await?;

    // A repo with no commits has no state to export. `RepoNotFound` is declared
    // on this method and on no other in the family, which is what it is for.
    let Some(commit_block) = signed_commit_block(&uri, &q.repo, &st, &signing_key)? else {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "RepoNotFound",
            format!("{} has no permissioned repo in {uri}", q.repo),
        ));
    };

    // Drain every collection a page at a time. `list_records` clamps to the
    // lexicon's 100, and an export that issued one unbounded query would be
    // reaching around the contract every other reader honours.
    let reader = space_reader(&state)?;
    // Pages fold into the sorted set as they arrive rather than piling up in a
    // second `Vec` first. This does not change what an export costs -- the
    // format declares an index root and requires the record blocks to follow
    // in the same canonical order as their index entries, so
    // every record has to be in hand before the header can be written -- but
    // it stops the same records being held twice on the way there.
    let mut records = crate::space::export_car::SortedRecords::default();
    let collections = reader
        .list_collections(&uri, &resolved.auth, &q.repo)
        .await
        .map_err(XrpcError::from)?;
    for collection in collections {
        let mut cursor: Option<String> = None;
        loop {
            let page = reader
                .list_records(
                    &uri,
                    resolved.auth.clone(),
                    &resolved.target_repo,
                    crate::space::reader::RecordListing {
                        collection: Some(&collection),
                        cursor: cursor.as_deref(),
                        limit: crate::space::export_car::EXPORT_PAGE,
                        reverse: false,
                    },
                )
                .await
                .map_err(XrpcError::from)?;
            let drained = page.records.len();
            records.extend(page.records).map_err(XrpcError::from)?;
            // A page shorter than the limit is the last one. Relying on the
            // cursor going `None` would spin forever if a page were entirely
            // filtered by a takedown.
            if drained < crate::space::export_car::EXPORT_PAGE as usize {
                break;
            }
            match page.cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
    }

    let car = crate::space::export_car::build_repo_car_sorted(&commit_block, records)
        .await
        .map_err(XrpcError::from)?;

    let mut resp = axum::response::Response::new(Body::from(car));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.ipld.car"),
    );
    Ok(resp)
}

/// Query params for `listRepoOps`.
#[derive(Debug, Deserialize)]
pub struct RepoOplogQuery {
    /// Space URI.
    pub space: String,
    /// DID of the account whose oplog to retrieve.
    pub repo: String,
    /// Resume point, exclusive. Either the composite `"<rev>__<idx>"` cursor
    /// this endpoint emits — which names the last op delivered, so an atomic
    /// batch larger than `limit` is not skipped across paging — or a bare rev,
    /// which the lexicon's wording implies and which resolves to `(rev, 0)`.
    pub since: Option<String>,
    /// Page size.
    pub limit: Option<u32>,
    /// Return operation metadata only, omitting inlined values.
    #[serde(rename = "excludeValues", default)]
    pub exclude_values: bool,
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
    /// The record's current value, inlined for creates and updates.
    ///
    /// Omitted when `excludeValues` is set, for deletes, and when this op has
    /// been superseded by a later write to the same `(collection, rkey)` — the
    /// storage layer decides the last case by matching the op's own CID against
    /// the current record's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
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
///
/// Auth goes through [`resolve_record_auth`], the same as every other record
/// read. This endpoint inlines record values, so the page it returns is the
/// space's contents rather than a summary of them — it was reachable by any
/// authenticated account naming any space and any member.
pub async fn list_repo_ops(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<RepoOplogQuery>,
) -> Result<Json<RepoOpsResponse>, XrpcError> {
    let uri = parse_space_uri(&q.space)?;
    let resolved = resolve_record_auth(&parts, &state, &uri, Some(q.repo.as_str())).await?;
    if let Some(subject) = &resolved.subject {
        // An own-repo read is a `read_self` read; only reaching
        // another member's repo needs whole-space `read`.
        assert_space_record_read(&state, subject, &uri, &q.repo, None).await?;
    }
    // See `get_repo_state`: an unverifiable credential stays a 401.
    space_reader(&state)?
        .verify_read_auth(&uri, &resolved.auth)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::UNAUTHORIZED,
                "Unauthorized",
                format!("invalid space credential: {e}"),
            )
        })?;
    let limit = page_limit(q.limit, 100, 1000);
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
    let mut ops = Vec::with_capacity(page.ops.len());
    for o in page.ops {
        // `o.value` is already `None` for deletes and for superseded ops — the
        // storage layer matched on the op's own CID. `excludeValues` drops the
        // rest.
        let value = match (&o.value, q.exclude_values) {
            (Some(bytes), false) => Some(decode_record_value(bytes)?),
            _ => None,
        };
        ops.push(RecordOpEntry {
            rev: o.rev,
            collection: o.collection.unwrap_or_default(),
            rkey: o.rkey.unwrap_or_default(),
            cid: o.cid,
            prev: o.prev,
            value,
        });
    }

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
/// `com.atproto.space.getSpaceCredential` lexicon (the spec's "Space credential" section).
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
    let (htm, htu) = request_htm_htu(&parts, state.trusted_proxy_hops);
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
/// `Authorization: Bearer` header (not the body); the key to bind the
/// credential to arrives as a DPoP proof in the `DPoP` header. The body
/// carries only the target space and an optional client attestation.
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
/// Verifies the DPoP proof in the `DPoP` header (RFC 9449; no `ath`, as the
/// delegation token is an authorization grant rather than an access token),
/// reads the [`DelegationToken`](atproto_space::credential::DelegationToken)
/// from the `Authorization: Bearer` header, verifies it against the member's
/// `#atproto` signing key, enforces single-use via its `jti`, then mints a
/// [`SpaceCredential`](atproto_space::credential::SpaceCredential) signed by
/// the authority's `#atproto_space` signing key and bound to the proof key's
/// RFC 7638 thumbprint in `cnf.jkt`.
///
/// The thumbprint is computed from the verified proof's own `jwk`, never
/// taken from the request body: a body field would be an assertion anyone
/// holding a delegation token could make about a key someone else controls,
/// where a proof demonstrates possession. The delegation token itself stays a
/// bearer token — the proof binds the *minted credential*, and says nothing
/// about how this request is authenticated.
pub async fn get_space_credential(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<GetSpaceCredentialInput>,
) -> Result<Json<SpaceCredentialResponse>, XrpcError> {
    let manager = account_manager(&state)?;

    // The delegation token is the bearer credential.
    let grant_jwt = bearer_token(&parts)?;

    let space = parse_space_uri(&input.space)?;

    // The key the credential binds to is established by the DPoP proof on
    // this request; the verified proof's thumbprint becomes the credential's
    // `cnf.jkt`. Checked before the delegation token below, so a caller with
    // a bad proof does not burn its single-use grant finding out.
    let (htm, htu) = crate::http::auth::request_htm_htu(&parts, state.trusted_proxy_hops);
    let dpop_jkt = crate::oauth::dpop::verify_issuance_dpop_proof(
        &parts.headers,
        &htm,
        &htu,
        &state.jti_guard,
    )
    .await?;

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

    // Enforce single-use of the delegation token via its `jti` (the spec's "Delegation token" section
    //). Consume it before minting so a replayed token is refused.
    let dt_ttl = std::time::Duration::from_secs(payload.exp.saturating_sub(now_secs()));
    state
        .jti_guard
        .check_and_insert(&payload.jti, dt_ttl)
        .await
        .map_err(|_| {
            XrpcError::new(
                StatusCode::FORBIDDEN,
                "InvalidDelegationToken",
                "delegation token already used (single-use replay)",
            )
        })?;

    let owner_signing = local_signing_key(manager, &space.space_did).await?;

    // ── Mint-time authorization (defs.json: a credential is minted only when
    //    the user is authorized by `policy` AND their app by `appAccess`).
    //
    // The requesting member is the delegation token's issuer. App identity is
    // established solely by the optional client attestation: when one is
    // presented we verify it (which yields the attested client_id) and use
    // that for the APP axis and the credential's `client_id`. When none is
    // presented the credential's `client_id` is omitted (the spec's "Space credential" section).
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
            StatusCode::BAD_REQUEST,
            "SpaceNotFound",
            format!("space not found: {space}"),
        ));
    }
    if inputs.deleted {
        // 400, like its siblings on this method. A deleted space is a fact
        // about the space the caller named, not a missing route, and a client
        // that switches on HTTP status before reading the error name should
        // not have to treat this one differently from `SpaceNotFound` -- which
        // this server deliberately normalised to 400 for the same reason.
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "SpaceDeleted",
            format!("space deleted: {space}"),
        ));
    }

    // USER axis (`policy`).
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
                    "policy is managing-app but no managingApp is configured",
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
    // omitted entirely when the request carried no attestation. `cnf.jkt` is
    // the thumbprint of the key the proof above demonstrated possession of.
    let credential_ttl = state.space_credential_ttl_secs;
    let token = create_space_credential(
        &space.space_did,
        &space,
        &dpop_jkt,
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
        Some(client_id) => {
            let resolved = match crate::space::recipient::resolve_recipient(
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
            };
            if !resolved.fully_resolved {
                tracing::warn!(
                    member = %payload.iss,
                    client_id = %client_id,
                    stub_did = %resolved.service_did,
                    stub_endpoint = ?resolved.service_endpoint,
                    "recipient resolved via stub; the consumer's DID document was unreachable or had no PDS service entry"
                );
            }
            Some(resolved)
        }
        // No attestation means no consumer URL, and the member's own DID is not
        // somewhere a notification can be sent. This used to register it as the
        // endpoint anyway: the row looked like a subscription, delivery refused
        // the endpoint on every write to the space, and the warning above
        // blamed a DID-document lookup that had never been attempted.
        //
        // Registering nothing costs the operator a record that this member took
        // a credential, and buys back a fan-out log that only mentions
        // subscribers that can actually be reached.
        None => {
            tracing::debug!(
                member = %payload.iss,
                space = %space,
                "credential issued without a client attestation; no notify recipient to register"
            );
            None
        }
    };

    if let Some(resolved) = resolved {
        match resolved.service_endpoint.as_deref() {
            Some(endpoint) => match SqlActorStore::open(manager.data_dir(), &space.space_did).await
            {
                Ok(owner_store) => {
                    if let Err(e) = upsert_recipient(
                        owner_store.pool(),
                        &space,
                        &resolved.service_did,
                        endpoint,
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
            },
            None => {
                tracing::warn!(
                    space = %space,
                    member = %payload.iss,
                    service_did = %resolved.service_did,
                    "no endpoint could be derived for this consumer; not registering it, so it will not receive notifyWrite"
                );
            }
        }
    }

    Ok(Json(SpaceCredentialResponse { credential: token }))
}

// ---------------------------------------------------------------------------
//  Helpers.
// ---------------------------------------------------------------------------

/// Resolve a paginated endpoint's `limit` parameter.
///
/// Every listing lexicon declares a `default` and a `maximum`, and they are not
/// the same across endpoints — `listRecords` and `listSpaces` cap at 100,
/// `listRepoOps` and `listMembers` at 1000. An unclamped `limit` lets one
/// request demand an entire collection in a single page.
fn page_limit(requested: Option<u32>, default: u32, max: u32) -> u32 {
    requested.unwrap_or(default).clamp(1, max)
}

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
    // Both token kinds that reach here are DPoP-bound; see
    // `resolve_record_auth`.
    let (scheme, raw) = authorization_token(parts)?;
    if let Some(SpaceTokenKind::SpaceCredential) = classify(raw) {
        require_scheme(
            scheme,
            AuthScheme::Dpop,
            "a space credential is bound to a key",
        )?;
        crate::http::space_auth::require_credential_dpop_proof(parts, state, raw).await?;
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
    let (htm, htu) = request_htm_htu(parts, state.trusted_proxy_hops);
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
    // `bearer_token` refuses the DPoP scheme outright, so this could not read
    // a conformant presentation at all.
    let (scheme, raw) = authorization_token(parts)?;
    if classify(raw) != Some(SpaceTokenKind::SpaceCredential) {
        return Err(XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "Unauthorized",
            "this method requires a space credential",
        ));
    }
    require_scheme(
        scheme,
        AuthScheme::Dpop,
        "a space credential is bound to a key",
    )?;
    crate::http::space_auth::require_credential_dpop_proof(parts, state, raw).await?;
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
    Ok(())
}

// ---------------------------------------------------------------------------
//  OAuth `space:` scope enforcement.
//
//  Enforces the 0016 `space:` OAuth scope rules (the spec's "OAuth scopes" section): only
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
/// Gate a read endpoint whose auth was resolved via [`require_any_authn`]:
/// `Some(subject)` runs the OAuth scope check, `None` (SpaceCredential auth)
/// skips it, the credential being whole-space read access already.
async fn assert_space_read_opt(
    state: &HttpState,
    subject: &Option<crate::http::auth::AuthSubject>,
    uri: &SpaceUri,
) -> Result<(), XrpcError> {
    match subject {
        Some(s) => {
            // `read_self` suffices, and `read` implies it. Describing a space
            // one holds a repo in is not access to the other repos in it, so
            // requiring the whole-space grant asked for more than the answer
            // discloses.
            assert_space_scope(
                state,
                s,
                uri,
                atproto_oauth::scopes::SpaceAction::ReadSelf,
                None,
            )
            .await
        }
        None => Ok(()),
    }
}

/// Refuse a space write from an account that is not a member.
///
/// [`assert_space_scope`] is the authorisation on these endpoints and it opens
/// with `if !subject.is_oauth() { return Ok(()) }`. An app-password session is
/// not OAuth -- it carries no scopes and is full-authority over its own
/// account -- so the assertion has nothing to assert and succeeds. Below it the
/// writer checks only that the space is not tombstoned, and `SpaceRepo` storage
/// creates the space row on demand, by design, so cross-PDS members can receive
/// records for a space they have no local row for.
///
/// Nothing in that chain asked whether the caller belongs to the space.
/// `require_repo_matches_subject` keeps a stranger writing into their own
/// repository rather than someone else's, which bounds the damage without
/// preventing it: the records are real, are filed under a space they have no
/// claim to, and sync offers them to that space's members.
///
/// Full authority over an account is not authority over every space that
/// account can name, so this is checked for every caller rather than only the
/// ones carrying scopes.
async fn require_space_member(
    state: &HttpState,
    uri: &SpaceUri,
    did: &str,
) -> Result<(), XrpcError> {
    // Only when this server can answer the question. Membership lives in the
    // *authority's* per-actor store, and for a cross-PDS space that store is
    // not here, so reading its absence as a negative would report every
    // legitimate remote member as a stranger and break cross-host spaces
    // outright.
    //
    // Same shape as `ensure_space_live`: local authority, enforce; remote
    // authority, defer to the side that owns the member list. A space
    // credential minted by that authority is what carries the claim there.
    if space_service(state)?
        .membership(uri, did)
        .await
        .map_err(XrpcError::from)?
        != Membership::NotMember
    {
        return Ok(());
    }
    tracing::warn!(
        did = %did,
        space = %uri,
        "refused a space write from a non-member"
    );
    Err(XrpcError::new(
        StatusCode::FORBIDDEN,
        "Forbidden",
        "you are not a member of that space",
    ))
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
    // omitted-`collection` default matches the declared collections (the spec's "Matching" section). Whole-space `read` ignores collection, so the lookup is skipped.
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
/// space-management `verb` on the space `uri` (the spec's "Matching" section). The verb
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
/// record(s) at `uri` from `target_repo`.
///
/// - Reading the holder's **own** repo (`target_repo == subject.sub()`) is
///   satisfied by a `read_self` grant, or by `read`, which implies it. Neither
///   is constrained by collection: read access is all-or-nothing at the space
///   boundary, and `read_self` narrows which *repo* is reachable rather than
///   which collections within it.
/// - Reading **another** member's repo requires whole-space `read`.
///
/// The collection is therefore not consulted at all, and is taken only so the
/// call sites read the same as the write ones.
///
/// No-op for non-OAuth subjects (app-password sessions).
async fn assert_space_record_read(
    state: &HttpState,
    subject: &crate::http::auth::AuthSubject,
    uri: &SpaceUri,
    target_repo: &str,
    _collection: Option<&str>,
) -> Result<(), XrpcError> {
    let action = if subject.sub() == target_repo {
        atproto_oauth::scopes::SpaceAction::ReadSelf
    } else {
        atproto_oauth::scopes::SpaceAction::Read
    };
    assert_space_scope(state, subject, uri, action, None).await
}

/// Resolve the `collections` declared by the space type's declaration for the
/// `space_type` NSID, used to expand a bare `space:` grant's
/// omitted-`collection` default (the spec's "Matching" section).
///
/// Resolution is delegated to the configured
/// [`SpaceDeclarationResolver`](crate::space::SpaceDeclarationResolver). It is
/// **fail-closed**: when no resolver is configured, the spaceType is the `*`
/// wildcard (no declaration to draw from), or resolution fails, this returns an
/// empty list — a bare grant then confers no write targets. Explicit
/// `collection=` grants are unaffected (they never consult the default).
async fn declared_collections(state: &HttpState, space_type: &str) -> Vec<String> {
    // `spaceType=*` has no declaration (the spec's "Matching" section); skip resolution.
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

    // `notifyWrite` arrives on two legs, and this accepted only the first.
    //
    //   1. repo host -> space host. `iss` is the writing account, `aud` the
    //      space authority. The receiver fans the notification out.
    //   2. space host -> a registered subscriber. `iss` is the authority,
    //      `aud` the identifier that subscriber registered. The receiver
    //      records it and pulls.
    //
    // Demanding `iss == payload.repo` and `aud == space.space_did` is leg 1's
    // shape, so a server acting as a subscriber refused every forwarded
    // notification this same codebase sends -- and the non-owner branch below,
    // which exists to record exactly those, was unreachable.
    //
    // The audience is checked after verification rather than supplied to it,
    // because which audience is correct depends on which leg this is.
    let token = bearer_token(&parts)?;
    let claims = crate::space::service_auth::verify_service_auth_unaudienced(
        &http,
        token,
        plc_dir,
        crate::space::notify::NOTIFY_WRITE_NSID,
        state
            .account_manager
            .as_deref()
            .map(AccountManager::account_pool_ref),
    )
    .await
    .map_err(XrpcError::from)?;

    let forwarded = claims.iss == space.space_did && claims.iss != payload.repo;
    if forwarded {
        // Leg 2. The authority vouches for the notification; the writer's own
        // signature was checked by the authority on leg 1. `aud` must name a
        // service this server answers for, or the token was minted for
        // somebody else and merely delivered here.
        let audience_did = claims.aud.split('#').next().unwrap_or(claims.aud.as_str());
        if manager
            .lookup_handle(audience_did)
            .await
            .map_err(XrpcError::from)?
            .is_none()
        {
            return Err(XrpcError::new(
                StatusCode::FORBIDDEN,
                "Forbidden",
                "notifyWrite aud does not name a service hosted here",
            ));
        }
    } else {
        // Leg 1. The issuer must be the account that wrote, so a PDS cannot
        // deliver a notification on someone else's behalf (reference
        // `notifyWrite.ts`), and the audience must be the space authority.
        if claims.aud != space.space_did {
            return Err(XrpcError::new(
                StatusCode::FORBIDDEN,
                "Forbidden",
                "notifyWrite aud must be the space authority",
            ));
        }
        if claims.iss != payload.repo {
            return Err(XrpcError::new(
                StatusCode::FORBIDDEN,
                "Forbidden",
                "notifyWrite iss does not match claimed writer",
            ));
        }
    }

    // Owner-side fan-out (HOP 2): only the owner's PDS holds the member list +
    // recipient subscriptions. For a non-owner host this is a best-effort
    // no-op (the receipt below is still recorded).
    let owner_is_local = !forwarded
        && manager
            .lookup_handle(&space.space_did)
            .await
            .map_err(XrpcError::from)?
            .is_some();
    if owner_is_local {
        // `owner_is_local` came from the account directory, so this branch has
        // already established that the member list is ours to hold. Not finding
        // one is a space that does not exist here, which is a refusal like any
        // other non-member: unlike the read and write guards, there is no remote
        // authority to defer to.
        let is_member = space_service(&state)?
            .membership(&space, &payload.repo)
            .await
            .map_err(XrpcError::from)?
            == Membership::Member;
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
//  listBlobs — enumerate the blobs a repo references within a space.
// ---------------------------------------------------------------------------

/// Query params for `com.atproto.space.listBlobs`.
#[derive(Debug, Deserialize)]
pub struct ListSpaceBlobsQuery {
    /// Space URI.
    pub space: String,
    /// DID of the account whose blobs to list.
    pub repo: String,
    /// List only blobs named by records written after this repo revision.
    #[serde(default)]
    pub since: Option<String>,
    /// Page size, clamped to the lexicon's 1..=1000 (default 500).
    #[serde(default)]
    pub limit: Option<u32>,
    /// Last CID of the previous page.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Output of `listBlobs`: `{cursor?, cids[]}`.
#[derive(Debug, Serialize)]
pub struct ListSpaceBlobsResponse {
    /// Cursor for the next page, absent on the last one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// The blob CIDs.
    pub cids: Vec<String>,
}

/// `GET /xrpc/com.atproto.space.listBlobs`.
///
/// The enumeration primitive the spec's sync and migration stories both rest
/// on. A repo's CAR carries no blobs — `getRepo` says so explicitly — so a
/// syncer that has pulled a repo still has to discover which blobs those
/// records name, and an account migrating its permissioned repos has to carry
/// them. Neither can be done by reading records alone without re-walking every
/// record's value.
///
/// Blobs behind permissioned records are never enumerated by the public
/// `com.atproto.sync.listBlobs`, which is unauthenticated; this is the
/// authenticated counterpart, scoped to one space.
pub async fn list_blobs(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<ListSpaceBlobsQuery>,
) -> Result<Json<ListSpaceBlobsResponse>, XrpcError> {
    let space = parse_space_uri(&q.space)?;
    // `repo` is required by the lexicon, as it is for `getBlob`: a space
    // credential is not bound to any one member's repo, so there is no
    // sensible default.
    let resolved = resolve_record_auth(&parts, &state, &space, Some(q.repo.as_str())).await?;
    if let Some(subject) = &resolved.subject {
        // An own-repo read is a `read_self` read; only reaching
        // another member's repo needs whole-space `read`.
        assert_space_record_read(&state, subject, &space, &q.repo, None).await?;
    }
    space_reader(&state)?
        .verify_read_auth(&space, &resolved.auth)
        .await
        .map_err(XrpcError::from)?;

    let manager = account_manager(&state)?;
    let store = SqlActorStore::open(manager.data_dir(), &q.repo)
        .await
        .map_err(XrpcError::from)?;

    let limit = page_limit(q.limit, 500, 1000);
    let cids = crate::space::blob_ref::list_refs(
        &store,
        &space.to_string(),
        q.since.as_deref(),
        q.cursor.as_deref(),
        limit,
    )
    .await
    .map_err(XrpcError::from)?;

    // A full page means there may be more; a short one is the end. The cursor
    // is the last CID, which is what the listing pages on.
    let cursor = (cids.len() as u32 == limit)
        .then(|| cids.last().cloned())
        .flatten();
    Ok(Json(ListSpaceBlobsResponse { cursor, cids }))
}

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
        // An own-repo read is a `read_self` read; only reaching
        // another member's repo needs whole-space `read`.
        assert_space_record_read(&state, subject, &space, &q.repo, None).await?;
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
    /// The repo's commit hash at that rev, as last reported by its host.
    ///
    /// Absent when the reporting peer sent none. This is what lets a syncer see
    /// which repos actually changed without fetching each one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<BytesValue>,
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

/// The writer-set query, hoisted so the plan test cannot drift from it.
///
/// Answered entirely from `idx_space_received_op_issuer`; see the migration
/// that adds it for the measurements.
const LIST_REPOS_SQL: &str = "SELECT o.issuer_did, o.rev, o.set_hash
         FROM space_received_op o
         WHERE o.space = ? AND o.issuer_did > ?
           AND o.rev = (
             SELECT MAX(i.rev) FROM space_received_op i
             WHERE i.space = o.space AND i.issuer_did = o.issuer_did
           )
         GROUP BY o.issuer_did
         ORDER BY o.issuer_did ASC
         LIMIT ?";

/// `GET /xrpc/com.atproto.space.listRepos`.
///
/// The writer set: distinct issuer DIDs observed in the owner's inbound
/// write-receipt log (`space_received_op`), each paired with its current `rev`
/// (`MAX(rev)` over that issuer's receipts), ordered by DID, paginated by
/// `did > cursor`. Output is `{ did, rev }` per writer (the spec's "The sync boundary (writer set)" section).
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
    let limit = page_limit(q.limit, 100, 1000);

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
            StatusCode::BAD_REQUEST,
            "SpaceNotFound",
            format!("space not found: {space}"),
        ));
    }

    let cursor = q.cursor.clone().unwrap_or_default();
    // The hash has to come from the row that produced the max rev. SQLite would
    // in fact give that with a bare `set_hash` alongside `MAX(rev)`, but that is
    // a SQLite-specific guarantee — anywhere else it would silently pair a rev
    // with some other row's hash, which is a wrong answer rather than a missing
    // one. The correlated subquery says what is meant.
    //
    // It is also the faster shape, which is worth writing down because the
    // obvious rewrite is slower. `idx_space_received_op_issuer` turns both
    // halves into covering seeks and lets `LIMIT` stop the scan after one
    // page's worth of issuers. A `ROW_NUMBER() OVER (PARTITION BY issuer_did)`
    // formulation returns identical rows but has to materialise every issuer
    // in the space before it can order and cut, so its cost tracks the space
    // rather than the page: measured over 200k receipts, 0.008s here against
    // 0.104s for the window function.
    let rows: Vec<(String, String, Option<Vec<u8>>)> = sqlx::query_as(LIST_REPOS_SQL)
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
        .map(|(did, rev, set_hash)| RepoRef {
            did,
            rev,
            // An empty blob means the reporting peer sent no hash. Reporting
            // `{"$bytes": ""}` would claim a hash that is not one.
            hash: set_hash.filter(|h| !h.is_empty()).map(BytesValue),
        })
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
    /// Service identifier of the subscriber: a DID with an optional service
    /// fragment naming the entry in its DID document to deliver to, e.g.
    /// `did:web:syncer.example#atproto_space_syncer`.
    ///
    /// The subscriber is named rather than located because `notifyWrite` is
    /// delivered with service auth *addressed to* this identifier: a bare URL
    /// cannot be an audience, so a caller supplying one leaves the delivery
    /// unverifiable by whoever receives it. The endpoint is resolved from the
    /// DID document instead.
    #[serde(default)]
    pub service: Option<String>,
    /// Endpoint to which `notifyWrite` events should be delivered.
    ///
    /// The pre-lexicon shape, kept so a deployed subscriber keeps receiving
    /// notifications. Superseded by `service`, which supplies both the
    /// audience and the endpoint; when both are sent, `service` decides.
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// Output of `registerNotify`.
#[derive(Debug, Serialize)]
pub struct RegisterNotifyResponse {
    /// When the registration expires (RFC 3339).
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
}

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

    // Require a space credential, presented under the scheme its binding
    // implies. `bearer_token` used to read this, which refuses the DPoP scheme
    // outright -- a conformant presentation could not reach the handler.
    let (scheme, token) = authorization_token(&parts)?;
    if classify(token) != Some(SpaceTokenKind::SpaceCredential) {
        return Err(XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "registerNotify requires a space credential",
        ));
    }
    require_scheme(
        scheme,
        AuthScheme::Dpop,
        "a space credential is bound to a key",
    )?;
    crate::http::space_auth::require_credential_dpop_proof(&parts, &state, token).await?;

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
            StatusCode::BAD_REQUEST,
            "SpaceNotFound",
            format!("space not found: {space}"),
        ));
    }

    // Verify the space credential: signature over the authority's key, bound
    // to this space, not expired.
    //
    // Resolved the same way every other credentialed endpoint resolves it --
    // the local account first, then the authority's DID document, preferring
    // `#atproto_space` over `#atproto`. Reading only the local account's
    // `#atproto` key, as this did, assumed both that the authority is hosted
    // here and that it publishes no separate space key; an authority that does
    // either had its own valid credentials refused.
    let credential = space_reader(&state)?
        .verify_space_credential_for(&space, token)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::FORBIDDEN,
                "InvalidToken",
                format!("SpaceCredential verification: {e}"),
            )
        })?;

    // Who is subscribing, and where deliveries go.
    //
    // With a `service` identifier both come from the DID document: the
    // identifier is the audience `notifyWrite` will be addressed to, and its
    // service entry is the endpoint. That is the whole reason the lexicon
    // names a service rather than a URL — an audience has to be something the
    // receiver can verify was meant for it, and a URL is not.
    //
    // Without one, the pre-lexicon behaviour: the endpoint is taken from the
    // request and the identity inferred from the credential's attested
    // `client_id`, falling back to its issuer. That identity is frequently an
    // OAuth client-metadata URL, which no service-auth verifier will accept as
    // an audience, so notifications addressed to it are unverifiable by the
    // recipient. Supplying `service` is how a subscriber fixes that.
    let (service_did, endpoint) = match input.service.as_deref() {
        Some(service) => {
            let plc_dir = state.plc_service.as_ref().map(|p| p.directory_hostname());
            let http = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .user_agent(crate::user_agent())
                .build()
                .unwrap_or_default();
            // Unreachable, absent, or present without a matching service
            // entry are one answer to the caller: this identifier cannot be
            // delivered to. The lexicon names exactly one error for it, and a
            // 500 would implicate the server in what is usually a typo'd DID.
            // The underlying cause is logged rather than returned.
            let not_resolvable = || {
                XrpcError::new(
                    StatusCode::BAD_REQUEST,
                    "ServiceNotResolvable",
                    format!(
                        "could not resolve {service} to a DID document with a matching service endpoint"
                    ),
                )
            };
            let resolved =
                match crate::space::recipient::resolve_service_endpoint(&http, service, plc_dir)
                    .await
                {
                    Ok(Some(endpoint)) => endpoint,
                    Ok(None) => return Err(not_resolvable()),
                    Err(error) => {
                        tracing::debug!(
                            error = ?error,
                            service = %service,
                            "registerNotify: service identifier did not resolve"
                        );
                        return Err(not_resolvable());
                    }
                };
            (service.to_string(), resolved)
        }
        None => {
            let endpoint = input.endpoint.clone().ok_or_else(|| {
                XrpcError::new(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "registerNotify requires a service identifier",
                )
            })?;
            let did = credential
                .client_id
                .clone()
                .unwrap_or_else(|| credential.iss.clone());
            (did, endpoint)
        }
    };
    // The endpoint is a URL this server will later POST to, carrying a JWT
    // signed with the space authority's key. Storing it unchecked made
    // `registerNotify` a request generator pointed wherever the caller liked:
    // an SSRF sink reaching whatever the PDS can reach, and a delivery
    // mechanism for an authority-signed token to a host of the caller's
    // choosing. A resolved endpoint gets the same check as a supplied one --
    // a DID document is not this server's to trust either.
    atproto_identity::validation::validate_service_endpoint(&endpoint).map_err(|err| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            format!("endpoint is not a permitted service endpoint: {err}"),
        )
    })?;

    // Host policy, not a protocol constant: 0016 requires an expiry to be
    // reported and lets it outlast the space credential that created the
    // registration, but names no duration.
    let ttl = i64::try_from(state.space_register_notify_ttl_secs)
        .unwrap_or(crate::space::notify::DEFAULT_REGISTER_NOTIFY_TTL_SECS as i64);
    let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(ttl)).to_rfc3339();
    crate::space::notify::upsert_subscription(
        owner_store.pool(),
        &space,
        input.repo.as_deref(),
        &service_did,
        &endpoint,
        Some(&expires_at),
    )
    .await
    .map_err(XrpcError::from)?;

    Ok(Json(RegisterNotifyResponse { expires_at }))
}

// ---------------------------------------------------------------------------
//  unregisterNotify — withdraw a write-notification registration.
// ---------------------------------------------------------------------------

/// Inputs for `com.atproto.space.unregisterNotify`.
#[derive(Debug, Deserialize)]
pub struct UnregisterNotifyInput {
    /// Space URI.
    pub space: String,
    /// The per-repo registration to withdraw. Omit for a whole-space one.
    ///
    /// Mirrors `registerNotify`, which accepts the same parameter: a
    /// registration made for one repo has to be withdrawable, and a request
    /// naming no repo would otherwise silently target the whole-space row
    /// instead. The draft lexicon omits `repo` on both methods while the
    /// amended README keeps per-repo registrations — an inconsistency raised
    /// upstream; this server follows the README, on both sides.
    #[serde(default)]
    pub repo: Option<String>,
    /// Service identifier of the subscriber to remove, as passed to
    /// `registerNotify`.
    ///
    /// Optional here, where the lexicon requires it. Registrations are
    /// currently keyed on an identity derived from the presenting credential
    /// rather than on a caller-supplied name, so a service does not
    /// necessarily know the string its own registration was stored under.
    /// Omitting it withdraws the caller's own registration, derived exactly as
    /// `registerNotify` derived it. Naming one explicitly does what the
    /// lexicon says.
    #[serde(default)]
    pub service: Option<String>,
}

/// `POST /xrpc/com.atproto.space.unregisterNotify`.
///
/// Authenticated with a space credential, like `registerNotify`. Idempotent:
/// succeeds whether or not a matching registration existed, because a caller
/// retrying after a timeout, or withdrawing one that already lapsed, is asking
/// for the same end state as one that removed a live row.
pub async fn unregister_notify(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<UnregisterNotifyInput>,
) -> Result<StatusCode, XrpcError> {
    let space = parse_space_uri(&input.space)?;
    let manager = account_manager(&state)?;
    let _ = space_service(&state)?; // gate on Spaces being enabled

    let (scheme, token) = authorization_token(&parts)?;
    if classify(token) != Some(SpaceTokenKind::SpaceCredential) {
        return Err(XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "unregisterNotify requires a space credential",
        ));
    }
    require_scheme(
        scheme,
        AuthScheme::Dpop,
        "a space credential is bound to a key",
    )?;
    crate::http::space_auth::require_credential_dpop_proof(&parts, &state, token).await?;

    // Verify the credential before looking the space up. The credential's
    // `sub` binds it to one space, so checking it first means a credential for
    // a space that exists cannot be used to ask whether some *other* space
    // does: the existence answer is only given to a caller already authorized
    // for the space it is asking about.
    let credential = space_reader(&state)?
        .verify_space_credential_for(&space, token)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::FORBIDDEN,
                "InvalidToken",
                format!("SpaceCredential verification: {e}"),
            )
        })?;

    // SpaceNotFound when the authority's space row is absent: a withdrawal
    // against a space this host does not answer for is a different failure
    // from a withdrawal that found no registration.
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
                format!("unregisterNotify space lookup: {e}"),
            )
        })?;
    if space_exists.is_none() {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "SpaceNotFound",
            format!("space not found: {space}"),
        ));
    }

    // Same derivation `registerNotify` uses, so an omitted `service` names the
    // row this caller's own registration created.
    let service_did = input.service.clone().unwrap_or_else(|| {
        credential
            .client_id
            .clone()
            .unwrap_or_else(|| credential.iss.clone())
    });

    let removed = crate::space::notify::delete_subscription(
        owner_store.pool(),
        &space,
        input.repo.as_deref(),
        &service_did,
    )
    .await
    .map_err(XrpcError::from)?;
    tracing::debug!(
        space = %space,
        service = %service_did,
        removed,
        "unregisterNotify"
    );

    Ok(StatusCode::OK)
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
/// authority) and `aud` a service hosted here.
///
/// The notification is **acknowledged and no local state is changed**. That is
/// not a stub — it is the behaviour the amended 0016 asks of a repo host, and
/// the reversal of what this used to do.
///
/// This handler tombstoned the recipient's own space row, which is the
/// repealed repo-host behaviour: flagging a member's repo as belonging to a
/// deleted space. A member's records are the member's own data, and an
/// authority deleting a space it anchors does not thereby get to reach into
/// the repos other people hold. Under the amended spec a member's repo host is
/// not notified at all; the records stay, and simply become unreadable to
/// everyone but the member's own account, because the credentials that reached
/// them stop being issued.
///
/// The **syncer** duty — "delete every copy of the space's data it holds, both
/// the repos it pulled and any derived state" — is real, and still has no home
/// here: this codebase implements the authority, repo-host and notification
/// roles, and pulls no remote space's repos, so there are no copies to drop.
/// A syncer added later handles this notification, and a `SpaceDeleted` at
/// credential renewal, by purging what it pulled.
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

    // Verify the token, then decide whether its audience is one this server
    // will act on. The order is the point.
    //
    // This used to read `aud` out of the unverified payload and pass that same
    // string back as the expected audience, so the comparison inside the
    // verifier was between a claim and itself: it could not fail, and the line
    // that looked like audience binding was not doing any. What remained was
    // `iss` and "the named DID has an account here", which is thinner than it
    // reads and, in the window where a DID is served by two hosts at once --
    // the middle of a migration -- lets a token minted for one of them be
    // replayed at the other.
    //
    // Now the claims are verified first and the audience is checked against
    // something this server knows independently: an account it hosts.
    let token = bearer_token(&parts)?;
    let claims = crate::space::service_auth::verify_service_auth_unaudienced(
        &http,
        token,
        plc_dir,
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

    let recipient_did = claims.aud.clone();
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

    // Nothing local is mutated. The recipient is a member's repo host, and its
    // member's records are not the authority's to retire; a syncer role, which
    // this codebase does not implement, is what would drop pulled copies here.
    tracing::info!(
        space = %space,
        recipient = %recipient_did,
        "notifySpaceDeleted acknowledged; member repos are left intact"
    );
    Ok(StatusCode::OK)
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
                name_lang: std::collections::BTreeMap::new(),
                key: "tid".to_string(),
                collections: vec!["app.bsky.feed.post".to_string()],
            },
        );
        let resolver = Arc::new(StubSpaceDeclarationResolver::new(map));
        test_state().await.with_space_declaration_resolver(resolver)
    }

    fn oauth_subject(scope: &str) -> AuthSubject {
        AuthSubject::OAuth(OAuthClaims {
            fam: None,
            sub: "did:plc:member".to_string(),
            iss: "did:web:pds".to_string(),
            aud: "did:web:pds".to_string(),
            client_id: "https://app.example/cm".to_string(),
            scope: scope.to_string(),
            cnf: None,
            iat: 0,
            exp: u64::MAX,
            jti: "jti".to_string(),
            ses: 0,
            act: None,
        })
    }

    fn session_subject() -> AuthSubject {
        AuthSubject::AppPassword(SessionClaims {
            sub: "did:plc:member".to_string(),
            iss: "did:web:pds".to_string(),
            apw: "apw".to_string(),
            privileged: true,
            full: true,
            iat: 0,
            exp: u64::MAX,
            jti: "jti".to_string(),
            ses: 0,
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

    /// `read_self` reads the holder's own repo in full, and nobody else's.
    ///
    /// The boundary it draws is the repo, not the collection: read access is
    /// all-or-nothing at the space boundary, so a grant naming one collection
    /// still reads the rest of the holder's own repo. What it does not reach
    /// is another member's — that is what whole-space `read` is for.
    #[tokio::test]
    async fn oauth_read_self_reads_the_whole_of_the_holders_own_repo() {
        let state = test_state().await;
        let subject = oauth_subject(
            "space:app.bsky.group?did=did:plc:owner&skey=default&action=read_self&collection=app.bsky.feed.post",
        );
        // sub() == "did:plc:member". Every collection of the own repo, named
        // or not, and the cross-collection listing that names none.
        for collection in [Some("app.bsky.feed.post"), Some("app.bsky.feed.like"), None] {
            assert!(
                assert_space_record_read(
                    &state,
                    &subject,
                    &space_uri(),
                    "did:plc:member",
                    collection,
                )
                .await
                .is_ok(),
                "own repo, collection {collection:?}"
            );
        }
        // Another member's repo still requires whole-space read.
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
        // `authority=*` is what makes this reach a space owned by someone
        // else; a bare `space:*` would cover only the subject's own spaces.
        let subject = oauth_subject("space:*?authority=*&action=read");
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
        // (the spec's "Matching" section). With a resolver mapping the type to a declaration
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

#[cfg(test)]
mod wire_shape_tests {
    use super::*;

    #[test]
    fn a_limit_above_the_lexicon_maximum_is_clamped_not_honoured() {
        // Each listing lexicon carries its own ceiling; an unclamped `limit`
        // lets one request pull a whole collection in a single page.
        assert_eq!(page_limit(Some(5_000), 50, 100), 100);
        assert_eq!(page_limit(Some(5_000), 100, 1000), 1000);
    }

    #[test]
    fn a_zero_or_absent_limit_falls_back_rather_than_returning_nothing() {
        assert_eq!(page_limit(Some(0), 50, 100), 1);
        assert_eq!(page_limit(None, 50, 100), 50);
        assert_eq!(page_limit(None, 100, 1000), 100);
        assert_eq!(page_limit(Some(25), 50, 100), 25);
    }

    #[test]
    fn a_delete_result_serialises_as_a_bare_typed_object() {
        // `#deleteResult` declares no properties. A delete that reported a
        // null `uri`/`cid` would not validate against the closed union.
        let v = serde_json::to_value(ApplyWritesResult::Delete {}).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"$type": "com.atproto.space.applyWrites#deleteResult"})
        );
    }

    #[test]
    fn create_and_update_results_carry_distinct_types() {
        let create = serde_json::to_value(ApplyWritesResult::Create {
            uri: "at://did:plc:owner/space/app.t/s/did:plc:alice/app.c/r".to_string(),
            cid: "bafyreigh2akiscaildc".to_string(),
            validation_status: None,
        })
        .unwrap();
        let update = serde_json::to_value(ApplyWritesResult::Update {
            uri: "at://did:plc:owner/space/app.t/s/did:plc:alice/app.c/r".to_string(),
            cid: "bafyreigh2akiscaildc".to_string(),
            validation_status: None,
        })
        .unwrap();
        assert_eq!(
            create["$type"],
            "com.atproto.space.applyWrites#createResult"
        );
        assert_eq!(
            update["$type"],
            "com.atproto.space.applyWrites#updateResult"
        );
        // `validationStatus` is optional and omitted rather than null.
        assert!(create.get("validationStatus").is_none());
    }

    #[test]
    fn results_follow_the_actions_not_the_presence_of_a_cid() {
        let actions = vec![
            SpaceWriteAction::Create,
            SpaceWriteAction::Delete,
            SpaceWriteAction::Update,
        ];
        let commit = SpaceCommitResult {
            rev: "3lb".to_string(),
            set_hash: "00".to_string(),
            uris: vec![
                "at://a".to_string(),
                "at://b".to_string(),
                "at://c".to_string(),
            ],
            cids: vec![Some("cid1".to_string()), None, Some("cid3".to_string())],
        };
        let results = apply_writes_results(&actions, commit).unwrap();
        let types: Vec<String> = results
            .iter()
            .map(|r| {
                serde_json::to_value(r).unwrap()["$type"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(
            types,
            vec![
                "com.atproto.space.applyWrites#createResult",
                "com.atproto.space.applyWrites#deleteResult",
                "com.atproto.space.applyWrites#updateResult",
            ]
        );
    }

    #[test]
    fn a_short_results_array_is_an_internal_error_not_a_silent_truncation() {
        let actions = vec![SpaceWriteAction::Create, SpaceWriteAction::Create];
        let commit = SpaceCommitResult {
            rev: "3lb".to_string(),
            set_hash: "00".to_string(),
            uris: vec!["at://a".to_string()],
            cids: vec![Some("cid1".to_string())],
        };
        let err = apply_writes_results(&actions, commit).unwrap_err();
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    }
}

#[cfg(test)]
mod list_repos_plan_tests {
    use super::*;
    use crate::actor_store::sql::SqlActorStore;

    /// `listRepos` must answer a page from the index, not by scanning a space.
    ///
    /// The query filters `space = ? AND issuer_did > ?` and correlates
    /// `MAX(rev)` per issuer. With only `PRIMARY KEY (space, rev, nsid)` and an
    /// index on `(space, received_at)`, neither half can seek on `issuer_did`:
    /// the outer read every row in the space, the subquery read them all again
    /// for each of those, and `GROUP BY` filled a temp b-tree before `LIMIT`
    /// could take its hundred. One page over 2,000 issuers took 3.63s.
    ///
    /// Asserted on the plan rather than a stopwatch, because a timing
    /// threshold on a shared machine either flakes or is set so loose it stops
    /// catching the regression. The plan is what changed, and the plan is what
    /// a dropped or reordered index would change back.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_writer_set_query_seeks_the_issuer_index() {
        let tmp = tempfile::tempdir().unwrap();
        let store = SqlActorStore::open(tmp.path(), "did:plc:planowner")
            .await
            .unwrap();

        let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "EXPLAIN QUERY PLAN {LIST_REPOS_SQL}"
        )))
        .bind("at://did:plc:planowner/space/main")
        .bind("")
        .bind(100i64)
        .fetch_all(store.pool())
        .await
        .expect("explain");
        let plan: Vec<String> = plan.into_iter().map(|(_, _, _, detail)| detail).collect();
        let rendered = plan.join("\n");

        assert!(
            plan.iter()
                .filter(|step| step.contains("idx_space_received_op_issuer"))
                .count()
                >= 2,
            "both the scan and the correlated subquery should seek the issuer \
             index; plan was:\n{rendered}"
        );
        assert!(
            !rendered.contains("TEMP B-TREE"),
            "a temp b-tree has to be filled before LIMIT can cut, so page cost \
             would track the space rather than the page; plan was:\n{rendered}"
        );
        assert!(
            !rendered.contains("SCAN space_received_op"),
            "the writer set must not be answered by scanning the table; plan \
             was:\n{rendered}"
        );
    }
}
