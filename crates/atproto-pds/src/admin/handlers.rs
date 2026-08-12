//! XRPC HTTP handlers for `com.atproto.admin.*`.
//!
//! Surface (basic-auth gated, ):
//!
//! - `getAccountInfo` — return AccountRow detail.
//! - `getAccountInfos` — batch lookup by DID (§4.1).
//! - `searchAccounts` — handle/email substring search.
//! - `getSubjectStatus` — current takedown state.
//! - `updateSubjectStatus` — apply/lift takedown on an account or record.
//! - `deleteAccount` — admin-initiated account deletion.
//! - `getInviteCodes` — list invite codes globally / by issuer.
//! - `sendEmail` — admin-issued message to a user (§4.2).
//! - `updateAccountEmail` / `updateAccountHandle` / `updateAccountPassword` —
//!   admin overrides of the user-side confirmation flows (§4.3).
//! - `takedownSpaceRecord` — Spaces record-level takedown (§4.4).
//! - `revokeServiceAuth` — JTI-blacklist a service-auth token (§4.5).
//! - `disableAccountInvites` / `enableAccountInvites` — per-account toggle
//!   on invite-code issuance (§4.6).
//! - `disableInviteCodes` — bulk-disable a list of codes (§4.6).

use crate::account::{AccountState, hash_password};
use crate::admin::subject::{StatusAttr, SubjectRef};
use crate::http::errors::XrpcError;
use crate::http::extract::{XrpcJson as Json, XrpcQuery as Query};
use crate::http::state::HttpState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64STD};
use serde::{Deserialize, Serialize};

/// Verify the admin Basic-auth header.
///
/// Rate-limited and constant-time. One shared secret guards every admin verb,
/// so a `!=` gave a timing oracle against it and an unbounded endpoint gave an
/// online guessing oracle — the second being the larger of the two.
///
/// # No password means no admin surface
///
/// There used to be a `DEFAULT_ADMIN_PASSWORD` constant here, published in this
/// repository, that an unset `admin_password` fell back to. The `pds` binary
/// closes that through `validate_production_safety`, so a server started the
/// documented way was never exposed — but this is a library, and anything
/// building an `HttpState` without `with_admin_password` served
/// `updateAccountPassword`, `deleteAccount` and `updateAccountEmail` behind a
/// string anyone could read here.
///
/// An absent password now refuses every admin request rather than standing in
/// for one. A credential that has to be configured before it works cannot be
/// left at its default by accident, which is the only property that survives
/// somebody not reading the documentation.
///
/// An empty password counts as absent, for the same reason.
///
/// # Errors
///
/// `AdminAuthenticationRequired` when the header is absent or malformed,
/// `AdminAuthenticationFailed` when the password does not match or none is
/// configured, and `RateLimited` when the attempt budget for the caller's
/// address is exhausted.
pub(crate) async fn require_admin(parts: &Parts, state: &HttpState) -> Result<(), XrpcError> {
    let header = parts.headers.get(AUTHORIZATION).ok_or_else(|| {
        XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "AdminAuthenticationRequired",
            "no Authorization header",
        )
    })?;
    let raw = header.to_str().map_err(|_| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Authorization header is not valid UTF-8",
        )
    })?;
    let encoded = raw.strip_prefix("Basic ").ok_or_else(|| {
        XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "AdminAuthenticationRequired",
            "expected Basic scheme",
        )
    })?;
    let decoded = B64STD.decode(encoded).map_err(|_| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Authorization header is not valid base64",
        )
    })?;
    let s = String::from_utf8(decoded).map_err(|_| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Authorization header is not valid UTF-8",
        )
    })?;
    let (_, password) = s.split_once(':').ok_or_else(|| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "expected user:pass format",
        )
    })?;
    // Bounded before comparing: an attacker who can guess without limit does
    // not need a timing side-channel.
    //
    // Keyed per address. It was one constant key for the whole server, which
    // bounds the guessing but hands anyone a lockout: 3000 bad requests from
    // anywhere exhaust the operator's budget too, and the moment an operator
    // most needs the admin surface is during the incident that is generating
    // them. A caller with no resolvable address -- an in-process call or a test
    // harness -- falls back to the shared key, so the bound never disappears.
    let ip = crate::http::rate_limit::client_ip_from_parts(parts, state.trusted_proxy_hops);
    let limiter_key = ip.map_or_else(|| "admin-auth".to_string(), |ip| format!("admin-auth:{ip}"));
    state
        .rate_limiter
        .try_acquire(&limiter_key)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "RateLimited",
                format!("admin authentication rate-limit hit: {e}"),
            )
        })?;

    // Fail closed. See the note above.
    let Some(expected) = state.admin_password.as_deref().filter(|p| !p.is_empty()) else {
        // ERROR rather than WARN: every admin request will fail until someone
        // configures one, and the caller is told only that authentication
        // failed, so this log line is the sole place the actual cause appears.
        tracing::error!(
            "refused an admin request because no admin password is configured; set one with \
             HttpState::with_admin_password (PDS_ADMIN_PASSWORD for the pds binary)"
        );
        return Err(XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "AdminAuthenticationFailed",
            "invalid admin password",
        ));
    };

    if !crate::security::secret_eq(password, expected) {
        // There was no log line at all on a failed admin attempt, so a campaign
        // against the one secret that guards every admin verb left no trace.
        // The address and nothing else: the submitted password is the secret
        // being guessed, and a log is not where it should end up.
        tracing::warn!(
            client_ip = ?ip,
            "admin authentication failed"
        );
        return Err(XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "AdminAuthenticationFailed",
            "invalid admin password",
        ));
    }
    Ok(())
}

/// Resolve an `at-identifier` — a handle or a DID — to the account's DID.
///
/// Several admin inputs are typed `at-identifier` rather than `did`, so
/// accepting only a DID makes a conformant request fail.
async fn resolve_at_identifier(state: &HttpState, identifier: &str) -> Result<String, XrpcError> {
    let directory = state.reader.accounts();
    let row = if identifier.starts_with("did:") {
        directory.lookup_did(identifier).await
    } else {
        directory.lookup_handle(identifier).await
    }
    .map_err(XrpcError::from)?;

    row.map(|r| r.did).ok_or_else(|| {
        XrpcError::new(
            StatusCode::NOT_FOUND,
            "AccountNotFound",
            format!("account {identifier} not found"),
        )
    })
}

/// Query params for `getAccountInfo`.
#[derive(Debug, Deserialize)]
pub struct AccountInfoParams {
    /// DID or handle.
    pub did: String,
}

/// `com.atproto.admin.defs#accountView`.
///
/// The lexicon requires `did`, `handle` and `indexedAt`; it declares no
/// `createdAt`. This shape previously emitted `createdAt` and omitted
/// `indexedAt`, so a client validating against the schema rejected every
/// account this server described.
///
/// `indexedAt` carries the account's creation time — when this server came to
/// know of the account, which for a locally-created account is the same moment.
///
/// The optional `invites`, `invitedBy`, `invitesDisabled`, `deactivatedAt` and
/// `threatSignatures` are not populated; they are optional, and filling them is
/// a question about data this server does not track rather than about shape.
#[derive(Debug, Serialize)]
pub struct AccountView {
    /// DID.
    pub did: String,
    /// Handle.
    pub handle: String,
    /// Email if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Email confirmation timestamp.
    #[serde(rename = "emailConfirmedAt", skip_serializing_if = "Option::is_none")]
    pub email_confirmed_at: Option<String>,
    /// When this server indexed the account.
    #[serde(rename = "indexedAt")]
    pub indexed_at: String,
}

/// Handler for `com.atproto.admin.getAccountInfo`.
pub async fn get_account_info(
    State(state): State<HttpState>,
    parts: Parts,
    Query(params): Query<AccountInfoParams>,
) -> Result<Json<AccountView>, XrpcError> {
    require_admin(&parts, &state).await?;
    let directory = state.reader.accounts();
    let row = if params.did.starts_with("did:") {
        directory.lookup_did(&params.did).await
    } else {
        directory.lookup_handle(&params.did).await
    }
    .map_err(XrpcError::from)?
    .ok_or_else(|| {
        XrpcError::new(
            StatusCode::NOT_FOUND,
            "AccountNotFound",
            format!("account {} not found", params.did),
        )
    })?;
    Ok(Json(AccountView {
        did: row.did,
        handle: row.handle,
        email: row.email,
        email_confirmed_at: row.email_confirmed_at,
        indexed_at: row.created_at,
    }))
}

/// Inputs for `updateSubjectStatus`.
#[derive(Debug, Deserialize)]
pub struct UpdateSubjectStatusInput {
    /// Account, record or blob being acted on.
    pub subject: SubjectRef,
    /// Takedown status to apply or lift.
    #[serde(default)]
    pub takedown: Option<StatusAttr>,
    /// Deactivation status to apply or lift. Accounts only.
    #[serde(default)]
    pub deactivated: Option<StatusAttr>,
}

/// Output of `updateSubjectStatus`.
#[derive(Debug, Serialize)]
pub struct UpdateSubjectStatusResponse {
    /// The subject as supplied, echoed back.
    pub subject: SubjectRef,
    /// The takedown status now in force, when one was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub takedown: Option<StatusAttr>,
}

/// Handler for `com.atproto.admin.updateSubjectStatus`.
///
/// Three subject kinds, per the lexicon's union. Account takedown maps onto
/// `AccountState::Takendown`, which the public read and write gates already
/// enforce everywhere. Record and blob takedown are recorded in the per-actor
/// store and enforced by the readers.
///
/// `deactivated` applies only to an account: a record has no deactivated state
/// and neither does a blob. A request naming one on either is refused rather
/// than silently ignored, because a moderator who believes they deactivated
/// something has no way to discover otherwise.
pub async fn update_subject_status(
    State(state): State<HttpState>,
    parts: Parts,
    // `subject` is an open union, so a moderation service naming a type this
    // build has not been taught is the likeliest rejection on this endpoint.
    Json(input): Json<UpdateSubjectStatusInput>,
) -> Result<Json<UpdateSubjectStatusResponse>, XrpcError> {
    require_admin(&parts, &state).await?;
    let manager = state.account_manager.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account manager not configured",
        )
    })?;

    // The reference refuses this pair outright, and it is worth refusing: the
    // two halves would fight, and whichever ran last would win silently.
    if let (Some(t), Some(d)) = (input.takedown.as_ref(), input.deactivated.as_ref())
        && t.applied
        && !d.applied
    {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "cannot activate and take down an account at the same time",
        ));
    }

    let did = input.subject.did().map_err(XrpcError::from)?;

    if let Some(takedown) = input.takedown.as_ref() {
        match &input.subject {
            SubjectRef::Repo { did } => {
                let target = if takedown.applied {
                    AccountState::Takendown
                } else {
                    AccountState::Active
                };
                manager
                    .set_state(did, target)
                    .await
                    .map_err(XrpcError::from)?;
            }
            SubjectRef::Record { uri, .. } => {
                // Parsed for its shape even though only the DID is needed
                // here: a malformed URI must fail before anything is written.
                let _ = crate::admin::subject::parse_record_uri(uri).map_err(XrpcError::from)?;
                let store = open_actor(&state, &did).await?;
                crate::takedown::set_record(
                    &store,
                    uri,
                    takedown.applied,
                    takedown.reference.as_deref(),
                )
                .await
                .map_err(XrpcError::from)?;
            }
            SubjectRef::Blob { cid, .. } => {
                let store = open_actor(&state, &did).await?;
                crate::takedown::set_blob(
                    &store,
                    cid,
                    takedown.applied,
                    takedown.reference.as_deref(),
                )
                .await
                .map_err(XrpcError::from)?;
            }
        }
    }

    if let Some(deactivated) = input.deactivated.as_ref() {
        match &input.subject {
            SubjectRef::Repo { did } => {
                let target = if deactivated.applied {
                    AccountState::Deactivated
                } else {
                    AccountState::Active
                };
                manager
                    .set_state(did, target)
                    .await
                    .map_err(XrpcError::from)?;
            }
            _ => {
                return Err(XrpcError::new(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "deactivated applies only to an account subject",
                ));
            }
        }
    }

    Ok(Json(UpdateSubjectStatusResponse {
        subject: input.subject,
        takedown: input.takedown,
    }))
}

/// Query params for `getSubjectStatus`.
///
/// All three are optional in the lexicon and the caller supplies exactly one
/// subject: `blob` (with `did`), or `uri`, or `did` alone.
#[derive(Debug, Deserialize)]
pub struct GetSubjectStatusParams {
    /// DID of an account, or the account holding a blob.
    pub did: Option<String>,
    /// AT-URI of a record.
    pub uri: Option<String>,
    /// CID of a blob. Requires `did`.
    pub blob: Option<String>,
}

/// Output of `getSubjectStatus`.
#[derive(Debug, Serialize)]
pub struct GetSubjectStatusResponse {
    /// The subject that was found.
    pub subject: SubjectRef,
    /// Takedown status, when one is in force.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub takedown: Option<StatusAttr>,
    /// Deactivation status. Accounts only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<StatusAttr>,
}

/// Handler for `com.atproto.admin.getSubjectStatus`.
///
/// Checked most-specific-first — blob, then record, then account — because a
/// blob query carries a `did` too, and reading them in the other order would
/// answer about the account every time.
pub async fn get_subject_status(
    State(state): State<HttpState>,
    parts: Parts,
    Query(params): Query<GetSubjectStatusParams>,
) -> Result<Json<GetSubjectStatusResponse>, XrpcError> {
    require_admin(&parts, &state).await?;

    if let Some(blob_cid) = params.blob.as_deref() {
        let did = params.did.as_deref().ok_or_else(|| {
            XrpcError::new(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "must provide a did to request blob state",
            )
        })?;
        let store = open_actor(&state, did).await?;
        let takedown = crate::takedown::get_blob(&store, blob_cid)
            .await
            .map_err(XrpcError::from)?;
        return Ok(Json(GetSubjectStatusResponse {
            subject: SubjectRef::Blob {
                did: did.to_string(),
                cid: blob_cid.to_string(),
                record_uri: None,
            },
            takedown: takedown.map(|t| StatusAttr {
                applied: true,
                reference: t.reference,
            }),
            deactivated: None,
        }));
    }

    if let Some(uri) = params.uri.as_deref() {
        let (did, _, _) = crate::admin::subject::parse_record_uri(uri).map_err(XrpcError::from)?;
        let store = open_actor(&state, &did).await?;
        let takedown = crate::takedown::get_record(&store, uri)
            .await
            .map_err(XrpcError::from)?;
        // The record's current CID, so the echoed `strongRef` is a real one.
        let cid = current_record_cid(&state, &did, uri).await?;
        return Ok(Json(GetSubjectStatusResponse {
            subject: SubjectRef::Record {
                uri: uri.to_string(),
                cid,
            },
            takedown: takedown.map(|t| StatusAttr {
                applied: true,
                reference: t.reference,
            }),
            deactivated: None,
        }));
    }

    let did = params.did.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "no provided subject",
        )
    })?;
    let directory = state.reader.accounts();
    let row = directory
        .lookup_did(did)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::NOT_FOUND,
                "AccountNotFound",
                format!("account {did} not found"),
            )
        })?;
    Ok(Json(GetSubjectStatusResponse {
        subject: SubjectRef::Repo {
            did: did.to_string(),
        },
        takedown: Some(StatusAttr {
            applied: row.state == AccountState::Takendown,
            reference: None,
        }),
        deactivated: Some(StatusAttr {
            applied: row.state == AccountState::Deactivated,
            reference: None,
        }),
    }))
}

/// Open the per-actor store for `did`, after confirming the account exists.
///
/// Opening blind would create a store for a DID this server does not host,
/// which is how a typo in a moderation queue becomes a stray database.
async fn open_actor(
    state: &HttpState,
    did: &str,
) -> Result<crate::actor_store::sql::SqlActorStore, XrpcError> {
    state
        .reader
        .accounts()
        .lookup_did(did)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::NOT_FOUND,
                "AccountNotFound",
                format!("account {did} not found"),
            )
        })?;
    crate::actor_store::sql::SqlActorStore::open(state.reader.data_dir(), did)
        .await
        .map_err(XrpcError::from)
}

/// The CID a record currently sits at, so `getSubjectStatus` can echo a
/// `strongRef` that resolves. Empty when the record is gone — a takedown row
/// can outlive the record it names.
async fn current_record_cid(state: &HttpState, did: &str, uri: &str) -> Result<String, XrpcError> {
    let store = open_actor(state, did).await?;
    let row: Option<(String,)> = sqlx::query_as("SELECT cid FROM repo_record WHERE uri = ?")
        .bind(uri)
        .fetch_optional(store.pool())
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("record cid lookup: {e}"),
            )
        })?;
    Ok(row.map(|(c,)| c).unwrap_or_default())
}

/// Inputs for `deleteAccount`.
#[derive(Debug, Deserialize)]
pub struct DeleteAccountInput {
    /// DID to delete.
    pub did: String,
}

/// Handler for `com.atproto.admin.deleteAccount`.
pub async fn delete_account(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<DeleteAccountInput>,
) -> Result<StatusCode, XrpcError> {
    require_admin(&parts, &state).await?;
    let manager = state.account_manager.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account manager not configured",
        )
    })?;
    manager
        .set_state(&input.did, AccountState::Deleted)
        .await
        .map_err(XrpcError::from)?;
    Ok(StatusCode::OK)
}

/// Query params for `searchAccounts`.
#[derive(Debug, Deserialize)]
pub struct SearchAccountsQuery {
    /// Search term. Named `email` because that is the only search parameter
    /// `com.atproto.admin.searchAccounts` declares — this endpoint previously
    /// required an undeclared `q` and ignored `email`, so a canonical caller
    /// got a 400 and an operator's `email=` was silently dropped.
    ///
    /// The underlying match still covers handle as well as email, so searching
    /// by handle still works; it is spelled `email=` because the lexicon has no
    /// other spelling for it.
    pub email: Option<String>,
    /// Cursor (last DID).
    pub cursor: Option<String>,
    /// Page size. The lexicon declares default 50, min 1, max 100.
    pub limit: Option<u32>,
}

/// Output of `searchAccounts`.
#[derive(Debug, Serialize)]
pub struct SearchAccountsResponse {
    /// Page of accounts.
    pub accounts: Vec<AccountView>,
    /// Cursor for the next page (None when exhausted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Handler for `com.atproto.admin.searchAccounts`. Basic-auth gated.
pub async fn search_accounts(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<SearchAccountsQuery>,
) -> Result<Json<SearchAccountsResponse>, XrpcError> {
    require_admin(&parts, &state).await?;
    let limit = q.limit.unwrap_or(50).clamp(1, 100);
    let directory = state.reader.accounts();
    let term = q.email.unwrap_or_default();
    let rows = directory
        .search_accounts(&term, q.cursor.as_deref(), limit)
        .await
        .map_err(XrpcError::from)?;
    let cursor = rows.last().map(|r| r.did.clone());
    Ok(Json(SearchAccountsResponse {
        accounts: rows
            .into_iter()
            .map(|r| AccountView {
                did: r.did,
                handle: r.handle,
                email: r.email,
                email_confirmed_at: r.email_confirmed_at,
                indexed_at: r.created_at,
            })
            .collect(),
        cursor,
    }))
}

/// Query params for `getInviteCodes`.
#[derive(Debug, Deserialize)]
pub struct GetInviteCodesQuery {
    /// Restrict to invite codes issued by this DID.
    #[serde(rename = "createdBy")]
    pub created_by: Option<String>,
}

/// One invite-code row in the response.
#[derive(Debug, Serialize)]
pub struct InviteCodeItem {
    /// The code string.
    pub code: String,
    /// Issuer DID (None for admin-issued).
    #[serde(rename = "createdBy", skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    /// Remaining uses.
    #[serde(rename = "availableUses")]
    pub available_uses: u32,
    /// Consuming DID (None when not yet redeemed).
    #[serde(rename = "usedBy", skip_serializing_if = "Option::is_none")]
    pub used_by: Option<String>,
    /// Creation timestamp.
    #[serde(rename = "createdAt")]
    pub created_at: String,
    /// `true` if admin-disabled.
    pub disabled: bool,
}

/// Output of `getInviteCodes`.
#[derive(Debug, Serialize)]
pub struct GetInviteCodesResponse {
    /// Invite codes matching the filter.
    pub codes: Vec<InviteCodeItem>,
}

/// Handler for `com.atproto.admin.getInviteCodes`. Basic-auth gated.
///
/// Without `createdBy`, returns ALL invite codes in the system. With
/// `createdBy`, restricts to codes created by that DID.
pub async fn get_invite_codes(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<GetInviteCodesQuery>,
) -> Result<Json<GetInviteCodesResponse>, XrpcError> {
    require_admin(&parts, &state).await?;
    let manager = state.account_manager.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account manager not configured",
        )
    })?;
    // §5.4 — invite list dispatches through `AccountPool`.
    let rows = crate::account::invite::list_all(&manager.account_pool(), q.created_by.as_deref())
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("getInviteCodes: {e}"),
            )
        })?;
    Ok(Json(GetInviteCodesResponse {
        codes: rows
            .into_iter()
            .map(|r| InviteCodeItem {
                code: r.code,
                created_by: r.created_by_did,
                available_uses: r.available_uses,
                used_by: r.used_by,
                created_at: r.created_at,
                disabled: r.disabled,
            })
            .collect(),
    }))
}

// ---------------------------------------------------------------------------
//  §4.1 — getAccountInfos (batch lookup).
// ---------------------------------------------------------------------------

/// Query params for `getAccountInfos`.
#[derive(Debug, Deserialize)]
pub struct GetAccountInfosQuery {
    /// Comma-separated list of DIDs (axum doesn't auto-deserialize repeated
    /// params).
    pub dids: String,
}

/// Output of `getAccountInfos`.
#[derive(Debug, Serialize)]
pub struct GetAccountInfosResponse {
    /// One entry per requested DID (in input order). DIDs that don't exist
    /// are omitted from the response — callers diff their inputs against
    /// the returned DIDs to discover misses.
    pub infos: Vec<AccountView>,
}

/// Handler for `com.atproto.admin.getAccountInfos`.
///
/// §4.1 — thin wrapper over `getAccountInfo` for bulk operator workflows
/// (status dashboards, audit jobs). Each lookup runs in parallel via
/// `futures::future::try_join_all`. DIDs that resolve to no account are
/// silently dropped from the response so callers can identify misses by
/// diffing requested-DIDs against returned-DIDs.
pub async fn get_account_infos(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<GetAccountInfosQuery>,
) -> Result<Json<GetAccountInfosResponse>, XrpcError> {
    require_admin(&parts, &state).await?;
    let dids: Vec<&str> = q
        .dids
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if dids.is_empty() {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "dids must be a non-empty comma-separated list",
        ));
    }
    if dids.len() > 100 {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "no more than 100 DIDs per call",
        ));
    }
    let directory = state.reader.accounts();
    let mut infos: Vec<AccountView> = Vec::with_capacity(dids.len());
    // Sequential lookups: AccountDirectory is single-instance and SQLite
    // pool is small; 100-DID batches at typical SQLite read latency are
    // sub-100ms and admin endpoints aren't latency-critical.
    for did in dids {
        if let Some(row) = directory.lookup_did(did).await.map_err(XrpcError::from)? {
            infos.push(AccountView {
                did: row.did,
                handle: row.handle,
                email: row.email,
                email_confirmed_at: row.email_confirmed_at,
                indexed_at: row.created_at,
            });
        }
    }
    Ok(Json(GetAccountInfosResponse { infos }))
}

// ---------------------------------------------------------------------------
//  §4.2 — admin sendEmail.
// ---------------------------------------------------------------------------

/// Inputs for `admin.sendEmail`.
#[derive(Debug, Deserialize)]
pub struct SendEmailInput {
    /// DID of the recipient account. The address is looked up from
    /// `account.email`.
    #[serde(rename = "recipientDid")]
    pub recipient_did: String,
    /// DID of the operator or service sending the message. Required by the
    /// lexicon so a recipient — and any later reviewer — can tell who sent it.
    #[serde(rename = "senderDid")]
    pub sender_did: String,
    /// Email subject line. Optional per the lexicon; defaults to a neutral
    /// subject rather than being rejected.
    #[serde(default)]
    pub subject: Option<String>,
    /// Plain-text body.
    pub content: String,
    /// Context for moderators and reviewers. Never included in the email
    /// itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Output of `admin.sendEmail`.
#[derive(Debug, Serialize)]
pub struct SendEmailResponse {
    /// `true` when the email service accepted the message. With the SMTP
    /// feature off, the disabled-stub backend logs the body at INFO and
    /// returns `true` here so test harnesses can observe success.
    pub sent: bool,
}

/// Handler for `com.atproto.admin.sendEmail`.
///
/// §4.2 — dispatches through `EmailService` shipped in the email subsystem.
/// When the SMTP feature is off (or `PDS_EMAIL_SMTP_URL`/`FROM_ADDRESS`
/// unset), the disabled-stub backend logs the message body and returns Ok.
pub async fn send_email(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<SendEmailInput>,
) -> Result<Json<SendEmailResponse>, XrpcError> {
    require_admin(&parts, &state).await?;
    let directory = state.reader.accounts();
    let row = directory
        .lookup_did(&input.recipient_did)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::NOT_FOUND,
                "AccountNotFound",
                format!("account {} not found", input.recipient_did),
            )
        })?;
    let to = row.email.ok_or_else(|| {
        XrpcError::new(
            StatusCode::PRECONDITION_FAILED,
            "NoEmailOnAccount",
            format!("account {} has no email address", input.recipient_did),
        )
    })?;
    // `subject` is optional per the lexicon. A message with no subject line is
    // still a message, so supply a neutral one rather than refusing.
    let subject = input.subject.as_deref().unwrap_or("Message from your PDS");
    state
        .email
        .send(&to, subject, &input.content)
        .await
        .map_err(XrpcError::from)?;
    tracing::info!(
        recipient = %input.recipient_did,
        sender = %input.sender_did,
        subject,
        "admin sendEmail dispatched"
    );
    Ok(Json(SendEmailResponse { sent: true }))
}

// ---------------------------------------------------------------------------
//  §4.3 — admin overrides of user-confirmation flows.
// ---------------------------------------------------------------------------

/// Inputs for `admin.updateAccountEmail`.
#[derive(Debug, Deserialize)]
pub struct UpdateAccountEmailInput {
    /// Handle or DID of the account. The lexicon types this `at-identifier`,
    /// so a handle is as valid as a DID; this previously read `did` and
    /// accepted only a DID, which made a canonical request fail to
    /// deserialize.
    pub account: String,
    /// New email address.
    pub email: String,
}

/// Handler for `com.atproto.admin.updateAccountEmail`.
///
/// §4.3 — bypasses the user-side `requestEmailUpdate` / `confirmEmailUpdate`
/// token-redemption flow. Sets `account.email` directly. `email_confirmed_at`
/// is intentionally NOT touched here — operators set confirmation
/// independently via a future endpoint or via direct DB access. (Marking
/// confirmation on an admin-set email would let operators bypass
/// verification UX — keep the surface focused.)
pub async fn update_account_email(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<UpdateAccountEmailInput>,
) -> Result<StatusCode, XrpcError> {
    require_admin(&parts, &state).await?;
    let manager = state.account_manager.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account manager not configured",
        )
    })?;
    // `account` is an at-identifier, so resolve a handle to its DID before
    // writing. This also preserves the 404 path: `set_email` dispatches to the
    // backend without telling us whether a row existed.
    let did = resolve_at_identifier(&state, &input.account).await?;
    manager
        .set_email(&did, Some(&input.email))
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("update email: {e}"),
            )
        })?;
    tracing::info!(did = %did, new_email = %input.email, "admin override: account email updated");
    Ok(StatusCode::OK)
}

/// Inputs for `admin.updateAccountHandle`.
#[derive(Debug, Deserialize)]
pub struct UpdateAccountHandleInput {
    /// DID whose handle to update.
    pub did: String,
    /// New handle.
    pub handle: String,
}

/// Handler for `com.atproto.admin.updateAccountHandle`.
///
/// §4.3 — runs the same PLC-update flow as `com.atproto.identity.updateHandle`
/// (signs an `Operation::new_update` against the PDS-managed rotation key
/// and submits to PLC) but skips the user-OAuth check. Reuses the shared
/// `crate::http::identity_handlers::do_update_handle_as_admin` helper so both
/// paths stay in lockstep, including handle validation and the `#identity`
/// event.
///
/// The admin variant permits reserved names: an operator assigning
/// `support.<their-domain>` to their own support account is doing exactly
/// what the reserved list exists to stop a stranger doing. Every other
/// check — syntax, TLD, service-domain shape, ownership proof for an
/// external domain, uniqueness — applies unchanged.
pub async fn update_account_handle(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<UpdateAccountHandleInput>,
) -> Result<StatusCode, XrpcError> {
    require_admin(&parts, &state).await?;
    crate::http::identity_handlers::do_update_handle_as_admin(&state, &input.did, &input.handle)
        .await?;
    Ok(StatusCode::OK)
}

/// Inputs for `admin.updateAccountPassword`.
#[derive(Debug, Deserialize)]
pub struct UpdateAccountPasswordInput {
    /// DID whose password to reset.
    pub did: String,
    /// New password (plaintext; hashed server-side via argon2id).
    pub password: String,
}

/// Handler for `com.atproto.admin.updateAccountPassword`.
///
/// §4.3 — bypasses any user-side reset flow. Hashes the new password with
/// argon2id (same code path as account creation) and writes it to BOTH:
///
/// - `account.password_hash` (used by the OAuth `/authorize` flow), and
/// - the `__primary__` app-password row's `password_hash` (used by
///   `com.atproto.server.createSession`).
///
/// `createAccount` keeps these in lockstep at account creation; admin
/// password resets must do the same so users can log in via either path.
/// Other named app-passwords are intentionally left alone — admins revoke
/// them separately via `revokeAppPassword` if needed.
pub async fn update_account_password(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<UpdateAccountPasswordInput>,
) -> Result<StatusCode, XrpcError> {
    require_admin(&parts, &state).await?;
    let manager = state.account_manager.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account manager not configured",
        )
    })?;
    if input.password.len() < 8 {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "password must be at least 8 characters",
        ));
    }
    let hash = hash_password(&input.password).map_err(XrpcError::from)?;
    // §5.4 — both `account.password_hash` and the
    // `__primary__` `app_password.password_hash` route through their
    // respective dispatching helpers. The DID-existence check
    // preserves the historical 404 path.
    if manager.lookup_handle(&input.did).await?.is_none() {
        return Err(XrpcError::new(
            StatusCode::NOT_FOUND,
            "AccountNotFound",
            format!("account {} not found", input.did),
        ));
    }
    manager
        .set_password_hash(&input.did, &hash)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("update password_hash: {e}"),
            )
        })?;
    crate::account::app_password::update_primary_hash(&manager.account_pool(), &input.did, &hash)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("update __primary__ app_password: {e}"),
            )
        })?;
    tracing::info!(did = %input.did, "admin override: account password reset");
    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
//  §4.4 — Spaces record-level takedown.
// ---------------------------------------------------------------------------

/// Inputs for `admin.takedownSpaceRecord`.
#[derive(Debug, Deserialize)]
pub struct TakedownSpaceRecordInput {
    /// Space URI (`at://owner/space/type/key`).
    pub space: String,
    /// NSID collection.
    pub collection: String,
    /// Record key.
    pub rkey: String,
    /// `true` to apply the takedown, `false` to lift it.
    #[serde(rename = "takedown", default = "default_true")]
    pub takedown: bool,
}

fn default_true() -> bool {
    true
}

/// Handler for `com.atproto.admin.takedownSpaceRecord`.
///
/// §4.4 — INSERT-OR-IGNOREs (or DELETEs) a row in `space_record_takedown`
/// in the *owner's* per-actor SQLite. `SpaceReader::get_record` and
/// `SpaceReader::list_records` consult that table on every read, so the
/// takedown takes effect immediately without modifying the underlying
/// `space_record` row (the source of truth — an admin-initiated takedown
/// is reversible without losing data).
pub async fn takedown_space_record(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<TakedownSpaceRecordInput>,
) -> Result<StatusCode, XrpcError> {
    require_admin(&parts, &state).await?;
    let manager = state.account_manager.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account manager not configured",
        )
    })?;
    let space = atproto_space::types::SpaceUri::parse(&input.space).map_err(|e| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            format!("invalid space URI: {e}"),
        )
    })?;
    let store = crate::actor_store::sql::SqlActorStore::open(manager.data_dir(), &space.space_did)
        .await
        .map_err(XrpcError::from)?;
    if input.takedown {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT OR IGNORE INTO space_record_takedown
                (space, collection, rkey, taken_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(input.space.clone())
        .bind(&input.collection)
        .bind(&input.rkey)
        .bind(&now)
        .execute(store.pool())
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("insert space_record_takedown: {e}"),
            )
        })?;
        tracing::info!(
            space = %input.space,
            collection = %input.collection,
            rkey = %input.rkey,
            "admin space-record takedown applied"
        );
    } else {
        sqlx::query(
            "DELETE FROM space_record_takedown
             WHERE space = ? AND collection = ? AND rkey = ?",
        )
        .bind(input.space.clone())
        .bind(&input.collection)
        .bind(&input.rkey)
        .execute(store.pool())
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("lift space_record_takedown: {e}"),
            )
        })?;
        tracing::info!(
            space = %input.space,
            collection = %input.collection,
            rkey = %input.rkey,
            "admin space-record takedown lifted"
        );
    }
    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
//  §4.5 — service-auth JTI revocation.
// ---------------------------------------------------------------------------

/// Inputs for `admin.revokeServiceAuth`.
#[derive(Debug, Deserialize)]
pub struct RevokeServiceAuthInput {
    /// JWT ID claim of the service-auth token to revoke.
    pub jti: String,
    /// ISO-8601 expiry of the token. Used so the blacklist row can be
    /// GC'd after the token would have expired anyway.
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
}

/// Handler for `com.atproto.admin.revokeServiceAuth`.
///
/// Appends a row to `service_auth_blacklist`. Inbound service-auth
/// verifiers check `service_auth_blacklist::contains` before honoring a
/// token. The existing GC helper `service_auth_blacklist::gc` drops
/// blacklist rows past `expiresAt` so the table stays bounded.
pub async fn revoke_service_auth(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<RevokeServiceAuthInput>,
) -> Result<StatusCode, XrpcError> {
    require_admin(&parts, &state).await?;
    let manager = state.account_manager.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account manager not configured",
        )
    })?;
    crate::service_auth_blacklist::add(&manager.account_pool(), &input.jti, &input.expires_at)
        .await
        .map_err(XrpcError::from)?;
    tracing::info!(jti = %input.jti, "admin: service-auth jti revoked");
    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
//  §4.6 — invite toggles.
// ---------------------------------------------------------------------------

/// Inputs for `com.atproto.admin.{disable,enable}AccountInvites`.
#[derive(Debug, Deserialize)]
pub struct InviteToggleInput {
    /// DID whose invite-issuance flag to flip. Named `account` per the
    /// lexicon; this previously read `did`.
    pub account: String,
    /// Optional reason, recorded in the log. Declared by
    /// `disableAccountInvites` and accepted on both for symmetry.
    #[serde(default)]
    pub note: Option<String>,
}

/// Handler for `com.atproto.admin.disableAccountInvites`. Admin Basic-auth
/// gated. Sets `account.can_issue_invites = 0` for the named DID; the
/// `createInviteCode` handler refuses with `403 InviteIssuanceDisabled`
/// after this.
pub async fn disable_account_invites(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<InviteToggleInput>,
) -> Result<StatusCode, XrpcError> {
    require_admin(&parts, &state).await?;
    set_invite_flag(&state, &input.account, 0).await
}

/// Handler for `com.atproto.admin.enableAccountInvites`. Admin Basic-auth
/// gated. Sets `account.can_issue_invites = 1` for the named DID,
/// reversing a prior `disableAccountInvites`.
pub async fn enable_account_invites(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<InviteToggleInput>,
) -> Result<StatusCode, XrpcError> {
    require_admin(&parts, &state).await?;
    set_invite_flag(&state, &input.account, 1).await
}

async fn set_invite_flag(state: &HttpState, did: &str, flag: i64) -> Result<StatusCode, XrpcError> {
    let manager = state.account_manager.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account manager not configured",
        )
    })?;
    // §5.4 — `set_can_issue_invites` dispatches per backend
    // and surfaces a `false` rows_affected back to the caller so we
    // can preserve the historical 404 path on unknown DIDs.
    let updated = manager
        .set_can_issue_invites(did, flag != 0)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("update can_issue_invites: {e}"),
            )
        })?;
    if !updated {
        return Err(XrpcError::new(
            StatusCode::NOT_FOUND,
            "AccountNotFound",
            format!("account {did} not found"),
        ));
    }
    tracing::info!(did = %did, flag = %flag, "admin: account invite flag updated");
    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
//  §7.2 — admin force repo sync.
// ---------------------------------------------------------------------------

/// Inputs for `admin.forceRepoSync`.
#[derive(Debug, Deserialize)]
pub struct ForceRepoSyncInput {
    /// DID whose `#sync` event to emit.
    pub did: String,
}

/// Output of `admin.forceRepoSync`.
#[derive(Debug, Serialize)]
pub struct ForceRepoSyncResponse {
    /// DID synced.
    pub did: String,
    /// Outbox seq assigned to the emitted `#sync` event.
    pub seq: i64,
    /// Head CID embedded in the `#sync` payload.
    #[serde(rename = "headCid")]
    pub head_cid: String,
    /// Head rev embedded in the `#sync` payload.
    #[serde(rename = "headRev")]
    pub head_rev: String,
}

/// Handler for `com.atproto.admin.forceRepoSync`.
///
/// §7.2 — operator-initiated drift fix. Looks up the named account's
/// current head commit + rev and emits a `#sync` event into the per-actor
/// outbox. Tailing subscribers see it on the next `subscribeRepos` poll +
/// reset their cached head to match. Idempotent: repeated calls just
/// emit additional `#sync` rows; subscribers tolerate duplicates.
///
/// Returns `404 RepoNotFound` if the account has no commits yet.
pub async fn force_repo_sync(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<ForceRepoSyncInput>,
) -> Result<Json<ForceRepoSyncResponse>, XrpcError> {
    require_admin(&parts, &state).await?;
    let manager = state.account_manager.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account manager not configured",
        )
    })?;
    let store = crate::actor_store::sql::SqlActorStore::open(manager.data_dir(), &input.did)
        .await
        .map_err(XrpcError::from)?;
    let head: Option<(String, String)> =
        sqlx::query_as("SELECT cid, rev FROM commit_obj ORDER BY rev DESC LIMIT 1")
            .fetch_optional(store.pool())
            .await
            .map_err(|e| {
                XrpcError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    format!("forceRepoSync head lookup: {e}"),
                )
            })?;
    let (head_cid, head_rev) = head.ok_or_else(|| {
        XrpcError::new(
            StatusCode::NOT_FOUND,
            "RepoNotFound",
            format!("account {} has no commits", input.did),
        )
    })?;
    // `#sync` carries the commit block, so read it back out of the repo.
    let commit_cid: cid::Cid = head_cid.parse().map_err(|e: cid::Error| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("forceRepoSync parse head CID: {e}"),
        )
    })?;
    let commit_block: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT data FROM repo_block WHERE cid = ?")
            .bind(&head_cid)
            .fetch_optional(store.pool())
            .await
            .map_err(|e| {
                XrpcError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    format!("forceRepoSync head block lookup: {e}"),
                )
            })?;
    let commit_block = commit_block
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::NOT_FOUND,
                "RepoNotFound",
                format!("head commit block {head_cid} is missing from the repo"),
            )
        })?
        .0;
    let event = crate::sequencer::sync_event::SyncEvent {
        did: &input.did,
        rev: &head_rev,
        commit_cid: &commit_cid,
        commit_block: &commit_block,
    };
    let seq = crate::sequencer::publish_sync(&manager.sequencer(), &event)
        .await
        .map_err(XrpcError::from)?;
    tracing::info!(did = %input.did, seq, head_cid = %head_cid, "admin: forceRepoSync emitted");
    Ok(Json(ForceRepoSyncResponse {
        did: input.did,
        seq,
        head_cid,
        head_rev,
    }))
}

/// Inputs for `disableInviteCodes`.
#[derive(Debug, Deserialize)]
pub struct DisableInviteCodesInput {
    /// List of code strings to disable. Idempotent — already-disabled
    /// codes are left alone. Unknown codes are silently skipped (the
    /// caller's own list-state may be stale).
    pub codes: Vec<String>,
}

/// Handler for `com.atproto.admin.disableInviteCodes`. Admin Basic-auth
/// gated. Bulk-disables the supplied list via `invite::disable` per code.
pub async fn disable_invite_codes(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<DisableInviteCodesInput>,
) -> Result<StatusCode, XrpcError> {
    require_admin(&parts, &state).await?;
    let manager = state.account_manager.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account manager not configured",
        )
    })?;
    if input.codes.is_empty() {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "codes must be a non-empty list",
        ));
    }
    if input.codes.len() > 1000 {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "no more than 1000 codes per call",
        ));
    }
    for code in &input.codes {
        crate::account::invite::disable(&manager.account_pool(), code)
            .await
            .map_err(XrpcError::from)?;
    }
    tracing::info!(count = input.codes.len(), "admin: invite codes disabled");
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SlidingWindowLimiter;
    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;
    use std::time::Duration;

    async fn test_state() -> HttpState {
        let tmp = tempfile::tempdir().expect("tempdir");
        let accounts = crate::account::AccountDirectory::open_memory()
            .await
            .expect("accounts");
        let reader = std::sync::Arc::new(crate::repo::RepoReader::new(
            accounts,
            tmp.path().to_path_buf(),
        ));
        // The tempdir is dropped here; nothing in these tests touches the data
        // directory, only the admin gate.
        HttpState::new(reader)
    }

    /// `Parts` carrying a Basic credential, optionally from a named address.
    fn parts_with(password: &str, peer: Option<&str>) -> Parts {
        let encoded = B64STD.encode(format!("admin:{password}"));
        let mut builder = axum::http::Request::builder()
            .uri("/xrpc/com.atproto.admin.getAccountInfo")
            .header(AUTHORIZATION, format!("Basic {encoded}"));
        if let Some(peer) = peer {
            let addr: SocketAddr = peer.parse().expect("socket addr");
            builder = builder.extension(ConnectInfo(addr));
        }
        builder.body(()).expect("request").into_parts().0
    }

    /// The published constant this used to fall back to. Named here so the test
    /// fails loudly if anything reintroduces it.
    const FORMER_DEFAULT: &str = "admin-default-CHANGE-ME";

    /// The defect: an `HttpState` built without `with_admin_password` served
    /// every admin verb behind a string published in this repository.
    #[tokio::test(flavor = "multi_thread")]
    async fn no_configured_password_refuses_the_former_default() {
        let state = test_state().await;
        assert!(state.admin_password.is_none(), "the case under test");

        let err = require_admin(&parts_with(FORMER_DEFAULT, None), &state)
            .await
            .expect_err("an unconfigured admin surface must refuse");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }

    /// And refuses everything else too, rather than only that one string.
    #[tokio::test(flavor = "multi_thread")]
    async fn no_configured_password_refuses_any_password() {
        let state = test_state().await;
        for attempt in ["", "hunter2", FORMER_DEFAULT] {
            assert!(
                require_admin(&parts_with(attempt, None), &state)
                    .await
                    .is_err(),
                "unconfigured admin surface accepted {attempt:?}"
            );
        }
    }

    /// An empty configured password is not a password.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_empty_configured_password_is_treated_as_absent() {
        let mut state = test_state().await;
        state.admin_password = Some(String::new());

        assert!(
            require_admin(&parts_with("", None), &state).await.is_err(),
            "an empty password must not authenticate against itself"
        );
    }

    /// The ordinary path still works.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_configured_password_authenticates() {
        let mut state = test_state().await;
        state.admin_password = Some("correct horse".to_string());

        require_admin(&parts_with("correct horse", None), &state)
            .await
            .expect("the configured password authenticates");
        assert!(
            require_admin(&parts_with("wrong horse", None), &state)
                .await
                .is_err()
        );
    }

    /// The budget was one constant key for the whole server, so anyone could
    /// exhaust it and lock the operator out during the incident that was
    /// generating the attempts.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_attempt_budget_is_per_address() {
        let mut state = test_state().await;
        state.admin_password = Some("correct horse".to_string());
        state.rate_limiter = SlidingWindowLimiter::new(2, Duration::from_secs(60), 1_000);

        // Burn the attacker's whole budget.
        for _ in 0..2 {
            assert!(
                require_admin(&parts_with("guess", Some("203.0.113.9:5000")), &state)
                    .await
                    .is_err(),
                "a wrong password is refused"
            );
        }
        let exhausted = require_admin(&parts_with("guess", Some("203.0.113.9:5001")), &state)
            .await
            .expect_err("the attacker's third attempt is over budget");
        assert_eq!(exhausted.status, StatusCode::TOO_MANY_REQUESTS);

        // The operator, on a different address, is unaffected.
        require_admin(
            &parts_with("correct horse", Some("198.51.100.4:6000")),
            &state,
        )
        .await
        .expect("the operator keeps their own budget");
    }
}
