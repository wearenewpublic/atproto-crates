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
use crate::http::errors::XrpcError;
use crate::http::state::HttpState;
use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64STD};
use serde::{Deserialize, Serialize};

/// Default admin password for unconfigured deployments. **Never** ship a
/// PDS without overriding `PDS_ADMIN_PASSWORD`.
pub const DEFAULT_ADMIN_PASSWORD: &str = "admin-default-CHANGE-ME";

/// Verify the admin Basic-auth header.
///
/// Rate-limited and constant-time. One shared secret guards every admin verb,
/// so a `!=` gave a timing oracle against it and an unbounded endpoint gave an
/// online guessing oracle — the second being the larger of the two.
async fn require_admin(parts: &Parts, state: &HttpState) -> Result<(), XrpcError> {
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
    state
        .rate_limiter
        .try_acquire("admin-auth")
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "RateLimited",
                format!("admin authentication rate-limit hit: {e}"),
            )
        })?;

    if !crate::security::secret_eq(password, admin_password(state)) {
        return Err(XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "AdminAuthenticationFailed",
            "invalid admin password",
        ));
    }
    Ok(())
}

fn admin_password(state: &HttpState) -> &str {
    state
        .admin_password
        .as_deref()
        .unwrap_or(DEFAULT_ADMIN_PASSWORD)
}

/// Query params for `getAccountInfo`.
#[derive(Debug, Deserialize)]
pub struct AccountInfoParams {
    /// DID or handle.
    pub did: String,
}

/// Output of `getAccountInfo`.
#[derive(Debug, Serialize)]
pub struct AccountInfoResponse {
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
    /// Lifecycle state.
    pub state: String,
    /// Creation timestamp.
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

/// Handler for `com.atproto.admin.getAccountInfo`.
pub async fn get_account_info(
    State(state): State<HttpState>,
    parts: Parts,
    Query(params): Query<AccountInfoParams>,
) -> Result<Json<AccountInfoResponse>, XrpcError> {
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
    Ok(Json(AccountInfoResponse {
        did: row.did,
        handle: row.handle,
        email: row.email,
        email_confirmed_at: row.email_confirmed_at,
        state: row.state.to_string(),
        created_at: row.created_at,
    }))
}

/// Inputs for `updateSubjectStatus`.
#[derive(Debug, Deserialize)]
pub struct UpdateSubjectStatusInput {
    /// DID of the affected account.
    pub did: String,
    /// New state (`active`, `deactivated`, `takendown`, `suspended`, `deleted`).
    pub state: String,
}

/// Output of `updateSubjectStatus`.
#[derive(Debug, Serialize)]
pub struct UpdateSubjectStatusResponse {
    /// DID.
    pub did: String,
    /// New state.
    pub state: String,
}

/// Handler for `com.atproto.admin.updateSubjectStatus`.
pub async fn update_subject_status(
    State(state): State<HttpState>,
    parts: Parts,
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
    let new_state = AccountState::parse(&input.state).ok_or_else(|| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidAccountState",
            format!("unknown state {}", input.state),
        )
    })?;
    manager
        .set_state(&input.did, new_state)
        .await
        .map_err(XrpcError::from)?;
    Ok(Json(UpdateSubjectStatusResponse {
        did: input.did,
        state: new_state.to_string(),
    }))
}

/// Query params for `getSubjectStatus`.
#[derive(Debug, Deserialize)]
pub struct GetSubjectStatusParams {
    /// DID of the subject.
    pub did: String,
}

/// Output of `getSubjectStatus`.
#[derive(Debug, Serialize)]
pub struct GetSubjectStatusResponse {
    /// DID.
    pub did: String,
    /// State.
    pub state: String,
}

/// Handler for `com.atproto.admin.getSubjectStatus`.
pub async fn get_subject_status(
    State(state): State<HttpState>,
    parts: Parts,
    Query(params): Query<GetSubjectStatusParams>,
) -> Result<Json<GetSubjectStatusResponse>, XrpcError> {
    require_admin(&parts, &state).await?;
    let directory = state.reader.accounts();
    let row = directory
        .lookup_did(&params.did)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::NOT_FOUND,
                "AccountNotFound",
                format!("account {} not found", params.did),
            )
        })?;
    Ok(Json(GetSubjectStatusResponse {
        did: params.did,
        state: row.state.to_string(),
    }))
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
    /// Substring to match against handle/email (case-insensitive).
    #[serde(rename = "q")]
    pub query: String,
    /// Cursor (last DID).
    pub cursor: Option<String>,
    /// Page size (default 25, max 100).
    pub limit: Option<u32>,
}

/// One account in the search results.
#[derive(Debug, Serialize)]
pub struct SearchAccountItem {
    /// DID.
    pub did: String,
    /// Handle.
    pub handle: String,
    /// State.
    pub state: String,
    /// Creation timestamp.
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

/// Output of `searchAccounts`.
#[derive(Debug, Serialize)]
pub struct SearchAccountsResponse {
    /// Page of accounts.
    pub accounts: Vec<SearchAccountItem>,
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
    let limit = q.limit.unwrap_or(25).clamp(1, 100);
    let directory = state.reader.accounts();
    let rows = directory
        .search_accounts(&q.query, q.cursor.as_deref(), limit)
        .await
        .map_err(XrpcError::from)?;
    let cursor = rows.last().map(|r| r.did.clone());
    Ok(Json(SearchAccountsResponse {
        accounts: rows
            .into_iter()
            .map(|r| SearchAccountItem {
                did: r.did,
                handle: r.handle,
                state: r.state.to_string(),
                created_at: r.created_at,
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
    pub infos: Vec<AccountInfoResponse>,
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
    let mut infos: Vec<AccountInfoResponse> = Vec::with_capacity(dids.len());
    // Sequential lookups: AccountDirectory is single-instance and SQLite
    // pool is small; 100-DID batches at typical SQLite read latency are
    // sub-100ms and admin endpoints aren't latency-critical.
    for did in dids {
        if let Some(row) = directory.lookup_did(did).await.map_err(XrpcError::from)? {
            infos.push(AccountInfoResponse {
                did: row.did,
                handle: row.handle,
                email: row.email,
                email_confirmed_at: row.email_confirmed_at,
                state: row.state.to_string(),
                created_at: row.created_at,
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
    /// Email subject line.
    pub subject: String,
    /// Plain-text body.
    pub content: String,
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
    state
        .email
        .send(&to, &input.subject, &input.content)
        .await
        .map_err(XrpcError::from)?;
    tracing::info!(did = %input.recipient_did, subject = %input.subject, "admin sendEmail dispatched");
    Ok(Json(SendEmailResponse { sent: true }))
}

// ---------------------------------------------------------------------------
//  §4.3 — admin overrides of user-confirmation flows.
// ---------------------------------------------------------------------------

/// Inputs for `admin.updateAccountEmail`.
#[derive(Debug, Deserialize)]
pub struct UpdateAccountEmailInput {
    /// DID whose email to set.
    pub did: String,
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
    // §5.4 — `manager.set_email` already dispatches
    // backend; preserve the AccountNotFound behavior by checking that
    // the row exists before the write so the 404 path is preserved.
    if manager.lookup_handle(&input.did).await?.is_none() {
        return Err(XrpcError::new(
            StatusCode::NOT_FOUND,
            "AccountNotFound",
            format!("account {} not found", input.did),
        ));
    }
    manager
        .set_email(&input.did, Some(&input.email))
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("update email: {e}"),
            )
        })?;
    tracing::info!(did = %input.did, new_email = %input.email, "admin override: account email updated");
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
/// `crate::http::identity_handlers::do_update_handle` helper so both paths
/// stay in lockstep.
pub async fn update_account_handle(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<UpdateAccountHandleInput>,
) -> Result<StatusCode, XrpcError> {
    require_admin(&parts, &state).await?;
    crate::http::identity_handlers::do_update_handle(&state, &input.did, &input.handle).await?;
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
    /// Space URI (`ats://owner/type/key`).
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

/// Inputs for `disableAccountInvites` / `enableAccountInvites`.
#[derive(Debug, Deserialize)]
pub struct InviteToggleInput {
    /// DID whose invite-issuance flag to flip.
    pub did: String,
}

/// Handler for `com.atproto.server.disableAccountInvites`. Admin Basic-auth
/// gated. Sets `account.can_issue_invites = 0` for the named DID; the
/// `createInviteCode` handler refuses with `403 InviteIssuanceDisabled`
/// after this.
pub async fn disable_account_invites(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<InviteToggleInput>,
) -> Result<StatusCode, XrpcError> {
    require_admin(&parts, &state).await?;
    set_invite_flag(&state, &input.did, 0).await
}

/// Handler for `com.atproto.server.enableAccountInvites`. Admin Basic-auth
/// gated. Sets `account.can_issue_invites = 1` for the named DID,
/// reversing a prior `disableAccountInvites`.
pub async fn enable_account_invites(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<InviteToggleInput>,
) -> Result<StatusCode, XrpcError> {
    require_admin(&parts, &state).await?;
    set_invite_flag(&state, &input.did, 1).await
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
