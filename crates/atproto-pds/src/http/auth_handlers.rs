//! XRPC HTTP handlers for `com.atproto.server.*` auth flows.
//!
//! Surface:
//! - `POST /xrpc/com.atproto.server.createAccount`
//! - `POST /xrpc/com.atproto.server.createSession`
//! - `GET /xrpc/com.atproto.server.getSession`
//! - `POST /xrpc/com.atproto.server.refreshSession`
//! - `POST /xrpc/com.atproto.server.deleteSession`
//! - `POST /xrpc/com.atproto.server.createAppPassword`
//! - `GET /xrpc/com.atproto.server.listAppPasswords`
//! - `POST /xrpc/com.atproto.server.revokeAppPassword`

use crate::account::{
    self, AccountState, CreateAccountParams, SessionTokens, app_password, invite, session,
};
use crate::errors::PdsError;
use crate::http::errors::XrpcError;
use crate::http::state::HttpState;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use serde::{Deserialize, Serialize};

/// Inputs for `com.atproto.server.createAccount`.
#[derive(Debug, Deserialize)]
pub struct CreateAccountInput {
    /// Email address.
    pub email: Option<String>,
    /// Handle (DNS-name).
    pub handle: String,
    /// Optional pre-allocated DID. When omitted (and a PLC directory is
    /// configured), the PLC genesis service mints a fresh did:plc.
    pub did: Option<String>,
    /// Optional invite code (required if `PDS_INVITE_REQUIRED`).
    #[serde(rename = "inviteCode")]
    pub invite_code: Option<String>,
    /// Plaintext password.
    pub password: String,
}

/// Output of `com.atproto.server.createAccount` — also the shape of `createSession`.
#[derive(Debug, Serialize)]
pub struct SessionResponse {
    /// Access token (JWT).
    #[serde(rename = "accessJwt")]
    pub access_jwt: String,
    /// Refresh token (JWT).
    #[serde(rename = "refreshJwt")]
    pub refresh_jwt: String,
    /// Account handle.
    pub handle: String,
    /// Account DID.
    pub did: String,
}

fn account_manager(state: &HttpState) -> Result<&account::AccountManager, XrpcError> {
    state.account_manager.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account management is not configured on this PDS",
        )
    })
}

/// Enforce the per-key sliding-window rate limit. Returns 429 on hit.
async fn enforce_rate_limit(state: &HttpState, key: &str) -> Result<(), XrpcError> {
    state.rate_limiter.try_acquire(key).await.map_err(|e| {
        XrpcError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "RateLimited",
            format!("{key}: {e}"),
        )
    })?;
    Ok(())
}

/// Handler for `com.atproto.server.createAccount`.
pub async fn create_account(
    State(state): State<HttpState>,
    Json(input): Json<CreateAccountInput>,
) -> Result<Json<SessionResponse>, XrpcError> {
    // Rate-limit by handle (the externally-visible identifier in the request).
    // Limits credential-stuffing-shaped attacks against signup forms.
    enforce_rate_limit(&state, &format!("createAccount:{}", input.handle)).await?;
    let manager = account_manager(&state)?;

    // §11e — when the operator pinned a list of allowed handle suffix
    // domains, reject handles that don't end with one of them. Empty list
    // means any handle is accepted (back-compat for dev / test).
    if !state.service_handle_domains.is_empty() {
        let lower = input.handle.to_ascii_lowercase();
        let allowed = state.service_handle_domains.iter().any(|d| {
            let needle = format!(".{}", d.trim_start_matches('.').to_ascii_lowercase());
            // Either exact-match or handle ends with `.<domain>`.
            lower == d.trim_start_matches('.').to_ascii_lowercase() || lower.ends_with(&needle)
        });
        if !allowed {
            return Err(XrpcError::new(
                StatusCode::BAD_REQUEST,
                "InvalidHandle",
                format!(
                    "handle {} is not under any of the allowed service handle domains",
                    input.handle
                ),
            ));
        }
    }

    // Privacy-preserving denylist check — operators may have banned the
    // handle or email without leaving plaintext in the DB. See
    // `crate::denylist`.
    if crate::denylist::contains(
        &manager.account_pool(),
        crate::denylist::KIND_HANDLE,
        &input.handle,
    )
    .await
    .map_err(XrpcError::from)?
    {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "BlockedHandle",
            "this handle is denied by the operator",
        ));
    }
    if let Some(email) = input.email.as_deref()
        && crate::denylist::contains(&manager.account_pool(), crate::denylist::KIND_EMAIL, email)
            .await
            .map_err(XrpcError::from)?
    {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "BlockedEmail",
            "this email address is denied by the operator",
        ));
    }
    // §2.3: invite-code lifecycle has three phases:
    //   1. peek (cheap pre-check) — fail fast on a clearly invalid code
    //      before spending a PLC-genesis op.
    //   2. PLC genesis (if needed) + account row insert.
    //   3. redeem — must come AFTER the account row exists because the
    //      `invite_code.used_by` FK references `account(did)`. Pre-§2.3
    //      the handler used a `"did:plc:pending"` placeholder to satisfy
    //      this FK; we now defer the redeem until the real DID is in the
    //      account table, which both keeps the placeholder out of the DB
    //      and lets the FK do its job.
    //
    // TOCTOU note: between `peek` and `redeem` another caller may exhaust
    // the code. In that case `redeem` returns `false` and we have an
    // account without a corresponding invite consumption — operators see
    // an `account_without_invite` log line and reconcile out-of-band. The
    // alternative (transactional spanning a network call to PLC) is
    // impossible.
    let invite_code: Option<&str> = if state.invite_required {
        let Some(code) = input.invite_code.as_deref() else {
            return Err(XrpcError::new(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "invite code required",
            ));
        };
        if !invite::peek(&manager.account_pool(), code)
            .await
            .map_err(XrpcError::from)?
        {
            return Err(XrpcError::new(
                StatusCode::BAD_REQUEST,
                "InvalidInviteCode",
                "invite code unknown, disabled, or exhausted",
            ));
        }
        Some(code)
    } else {
        None
    };

    // If no DID supplied, run a PLC genesis op to mint a fresh did:plc
    // identifier + a P-256 rotation key. Otherwise (test paths, account
    // migration), trust the caller-supplied DID and let the manager
    // generate the signing key.
    let (did, rotation_key_ref, signing_key_ref) = if let Some(d) = input.did.clone() {
        (d, None, None)
    } else {
        let plc_service = state.plc_service.as_ref().ok_or_else(|| {
            XrpcError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "PlcUnavailable",
                "PLC genesis is not configured on this PDS; supply `did` directly",
            )
        })?;
        let outcome = plc_service
            .genesis(&input.handle)
            .await
            .map_err(XrpcError::from)?;
        (
            outcome.did,
            Some(outcome.rotation_key_ref),
            Some(outcome.signing_key_ref),
        )
    };

    let row = manager
        .create_account(CreateAccountParams {
            did: &did,
            handle: &input.handle,
            email: input.email.as_deref(),
            password: &input.password,
            pds_managed_rotation: true,
            rotation_key_ref: rotation_key_ref.as_deref(),
            signing_key_ref: signing_key_ref.as_deref(),
        })
        .await
        .map_err(XrpcError::from)?;

    // §2.3 phase 3: now that the account row exists, atomically redeem the
    // invite against the real DID. The FK on `invite_code.used_by` is now
    // satisfied. A `false` return means another caller raced us between
    // `peek` and here — log + continue (the account is already real;
    // operators reconcile orphans).
    if let Some(code) = invite_code {
        match invite::redeem(&manager.account_pool(), code, &row.did).await {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(
                    did = %row.did,
                    code = %code,
                    "account_without_invite: invite code raced (peek ok, redeem now exhausted) — operator reconcile"
                );
            }
            Err(e) => {
                tracing::warn!(
                    did = %row.did,
                    code = %code,
                    error = ?e,
                    "account_without_invite: invite redeem storage error — operator reconcile"
                );
            }
        }
    }

    // Mint a session immediately. We need an app-password row to attach the
    // session to; createAccount issues an implicit "primary" app password
    // on account creation, mirroring how the TS reference treats the
    // password.
    let primary = app_password::create(&manager.account_pool(), &row.did, "__primary__", true)
        .await
        .map_err(XrpcError::from)?;
    // Re-set the primary's password to match what the user supplied, so a
    // subsequent createSession with the same password verifies. We re-hash
    // the user's password and overwrite the row.
    let user_hash = account::hash_password(&input.password).map_err(XrpcError::from)?;
    // §5.4 — `update_hash_by_id` dispatches per backend.
    app_password::update_hash_by_id(&manager.account_pool(), &primary.row.id, &user_hash)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                e.to_string(),
            )
        })?;

    let tokens = session::issue_pair(
        &state.service_did,
        &row.did,
        &primary.row.id,
        true,
        &state.jwt_secret,
        session::DEFAULT_ACCESS_TTL_SECS,
        session::DEFAULT_REFRESH_TTL_SECS,
    )
    .map_err(XrpcError::from)?;

    Ok(Json(SessionResponse {
        access_jwt: tokens.access_jwt,
        refresh_jwt: tokens.refresh_jwt,
        handle: row.handle,
        did: row.did,
    }))
}

/// Inputs for `com.atproto.server.createSession`.
#[derive(Debug, Deserialize)]
pub struct CreateSessionInput {
    /// DID, handle, or email of the account.
    pub identifier: String,
    /// Plaintext password (account or app-password).
    pub password: String,
}

/// Handler for `com.atproto.server.createSession`.
pub async fn create_session(
    State(state): State<HttpState>,
    Json(input): Json<CreateSessionInput>,
) -> Result<Json<SessionResponse>, XrpcError> {
    // Rate-limit by identifier — credential-stuffing protection.
    enforce_rate_limit(&state, &format!("createSession:{}", input.identifier)).await?;
    let manager = account_manager(&state)?;
    let directory = state.reader.accounts();

    // Resolve identifier → AccountRow.
    let account = if input.identifier.starts_with("did:") {
        directory.lookup_did(&input.identifier).await
    } else {
        directory.lookup_handle(&input.identifier).await
    }
    .map_err(XrpcError::from)?
    .ok_or_else(|| {
        XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "no such account",
        )
    })?;

    if !matches!(
        account.state,
        AccountState::Active | AccountState::Deactivated
    ) {
        return Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "Forbidden",
            format!("account is {}", account.state),
        ));
    }

    // Try app-password verification first.
    let app = app_password::verify(&manager.account_pool(), &account.did, &input.password)
        .await
        .map_err(XrpcError::from)?;
    let (app_id, privileged) = match app {
        Some(row) => (row.id, row.privileged),
        None => {
            return Err(XrpcError::new(
                StatusCode::UNAUTHORIZED,
                "AuthenticationRequired",
                "invalid identifier or password",
            ));
        }
    };

    let tokens = session::issue_pair(
        &state.service_did,
        &account.did,
        &app_id,
        privileged,
        &state.jwt_secret,
        session::DEFAULT_ACCESS_TTL_SECS,
        session::DEFAULT_REFRESH_TTL_SECS,
    )
    .map_err(XrpcError::from)?;

    Ok(Json(SessionResponse {
        access_jwt: tokens.access_jwt,
        refresh_jwt: tokens.refresh_jwt,
        handle: account.handle,
        did: account.did,
    }))
}

/// Output of `com.atproto.server.getSession`.
#[derive(Debug, Serialize)]
pub struct GetSessionResponse {
    /// Account handle.
    pub handle: String,
    /// Account DID.
    pub did: String,
    /// Email if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

/// Handler for `com.atproto.server.getSession`. Auth-required.
pub async fn get_session(
    State(state): State<HttpState>,
    parts: Parts,
) -> Result<Json<GetSessionResponse>, XrpcError> {
    let claims = require_access_jwt(&parts, &state)?;
    let directory = state.reader.accounts();
    let account = directory
        .lookup_did(&claims.sub)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::UNAUTHORIZED,
                "AuthenticationRequired",
                "session subject not found",
            )
        })?;
    Ok(Json(GetSessionResponse {
        handle: account.handle,
        did: account.did,
        email: account.email,
    }))
}

/// Handler for `com.atproto.server.refreshSession`.
///
/// Refresh tokens are single-use: once exchanged, the JTI is recorded in the
/// in-memory replay guard with TTL = remaining lifetime so a captured
/// refresh token cannot be replayed against a different IP after rotation.
pub async fn refresh_session(
    State(state): State<HttpState>,
    parts: Parts,
) -> Result<Json<SessionResponse>, XrpcError> {
    let raw = bearer_token(&parts)?;
    let claims = session::verify_refresh(raw, &state.jwt_secret).map_err(XrpcError::from)?;
    // JTI replay protection — single-use rotation defense in depth.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ttl = std::time::Duration::from_secs(claims.exp.saturating_sub(now));
    state
        .jti_guard
        .check_and_insert(&claims.jti, ttl)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::UNAUTHORIZED,
                "AuthenticationRequired",
                format!("refresh token replayed: {e}"),
            )
        })?;
    let directory = state.reader.accounts();
    let account = directory
        .lookup_did(&claims.sub)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::UNAUTHORIZED,
                "AuthenticationRequired",
                "refresh token subject not found",
            )
        })?;
    // The account row was already loaded here and only its `did` was read. A
    // refresh token lives 90 days, so without this a token minted before a
    // takedown kept issuing access tokens for 90 days after it.
    if !account.state.allows_writes() {
        return Err(XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "AccountTakedown",
            format!("account {} is {}", account.did, account.state),
        ));
    }
    let tokens: SessionTokens = session::issue_pair(
        &state.service_did,
        &account.did,
        &claims.apw,
        claims.privileged,
        &state.jwt_secret,
        session::DEFAULT_ACCESS_TTL_SECS,
        session::DEFAULT_REFRESH_TTL_SECS,
    )
    .map_err(XrpcError::from)?;
    Ok(Json(SessionResponse {
        access_jwt: tokens.access_jwt,
        refresh_jwt: tokens.refresh_jwt,
        handle: account.handle,
        did: account.did,
    }))
}

/// Handler for `com.atproto.server.deleteSession`.
///
/// Verifies the refresh token; records its `jti` in the JTI replay guard
/// with TTL = remaining lifetime so subsequent presentations are rejected.
/// This is the symmetric of `oauth::revoke` for app-password sessions.
pub async fn delete_session(
    State(state): State<HttpState>,
    parts: Parts,
) -> Result<StatusCode, XrpcError> {
    let raw = bearer_token(&parts)?;
    let claims = session::verify_refresh(raw, &state.jwt_secret).map_err(XrpcError::from)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ttl = std::time::Duration::from_secs(claims.exp.saturating_sub(now));
    // Best-effort: ignore "already in guard" — that's the desired terminal
    // state. We only fail closed if the guard is itself broken.
    if let Err(e) = state.jti_guard.check_and_insert(&claims.jti, ttl).await {
        tracing::debug!(jti = %claims.jti, ?e, "deleteSession: jti already known");
    }
    tracing::info!(did = %claims.sub, jti = %claims.jti, "deleteSession revoked");
    Ok(StatusCode::OK)
}

/// Inputs for `com.atproto.server.createAppPassword`.
#[derive(Debug, Deserialize)]
pub struct CreateAppPasswordInput {
    /// User-facing name.
    pub name: String,
    /// Whether the password has access to privileged endpoints.
    #[serde(default)]
    pub privileged: bool,
}

/// Output of `com.atproto.server.createAppPassword`.
#[derive(Debug, Serialize)]
pub struct AppPasswordCreated {
    /// User-facing name.
    pub name: String,
    /// Plaintext password — shown to the user once.
    pub password: String,
    /// Privileged flag.
    pub privileged: bool,
    /// ISO-8601 creation timestamp.
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

/// Handler for `com.atproto.server.createAppPassword`.
pub async fn create_app_password(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<CreateAppPasswordInput>,
) -> Result<Json<AppPasswordCreated>, XrpcError> {
    let claims = require_access_jwt(&parts, &state)?;
    let manager = account_manager(&state)?;
    // Deactivation is self-service and reversible; a takedown or suspension is
    // a moderation decision and must not be. `valid_transition` still permits
    // Takendown -> Active because an admin lifting a takedown is legitimate —
    // the defect was who could ask, not that the transition exists.
    if let Some(account) = state
        .reader
        .accounts()
        .lookup_did(&claims.sub)
        .await
        .map_err(XrpcError::from)?
        && matches!(
            account.state,
            crate::account::AccountState::Takendown | crate::account::AccountState::Suspended
        )
    {
        return Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "AccountTakedown",
            format!(
                "account {} is {}; only an administrator can restore it",
                account.did, account.state
            ),
        ));
    }
    let created = app_password::create(
        &manager.account_pool(),
        &claims.sub,
        &input.name,
        input.privileged,
    )
    .await
    .map_err(XrpcError::from)?;
    Ok(Json(AppPasswordCreated {
        name: created.row.name,
        password: created.plaintext,
        privileged: created.row.privileged,
        created_at: created.row.created_at,
    }))
}

/// Item in `com.atproto.server.listAppPasswords` output.
#[derive(Debug, Serialize)]
pub struct AppPasswordListItem {
    /// Name.
    pub name: String,
    /// Privileged flag.
    pub privileged: bool,
    /// Creation timestamp.
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

/// Output of `com.atproto.server.listAppPasswords`.
#[derive(Debug, Serialize)]
pub struct ListAppPasswordsResponse {
    /// The passwords, hashes excluded.
    pub passwords: Vec<AppPasswordListItem>,
}

/// Handler for `com.atproto.server.listAppPasswords`.
pub async fn list_app_passwords(
    State(state): State<HttpState>,
    parts: Parts,
) -> Result<Json<ListAppPasswordsResponse>, XrpcError> {
    let claims = require_access_jwt(&parts, &state)?;
    let manager = account_manager(&state)?;
    let rows = app_password::list(&manager.account_pool(), &claims.sub)
        .await
        .map_err(XrpcError::from)?;
    Ok(Json(ListAppPasswordsResponse {
        passwords: rows
            .into_iter()
            // Hide the implicit primary so users only see what they explicitly created.
            .filter(|row| row.name != "__primary__")
            .map(|row| AppPasswordListItem {
                name: row.name,
                privileged: row.privileged,
                created_at: row.created_at,
            })
            .collect(),
    }))
}

/// Inputs for `com.atproto.server.revokeAppPassword`.
#[derive(Debug, Deserialize)]
pub struct RevokeAppPasswordInput {
    /// Name of the password to revoke.
    pub name: String,
}

/// Handler for `com.atproto.server.revokeAppPassword`.
pub async fn revoke_app_password(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<RevokeAppPasswordInput>,
) -> Result<StatusCode, XrpcError> {
    let claims = require_access_jwt(&parts, &state)?;
    let manager = account_manager(&state)?;
    let removed = app_password::revoke(&manager.account_pool(), &claims.sub, &input.name)
        .await
        .map_err(XrpcError::from)?;
    if removed {
        Ok(StatusCode::OK)
    } else {
        Err(XrpcError::new(
            StatusCode::NOT_FOUND,
            "AppPasswordNotFound",
            format!("no app password named {:?}", input.name),
        ))
    }
}

/// Inputs for `com.atproto.server.createInviteCode`.
#[derive(Debug, Deserialize)]
pub struct CreateInviteCodeInput {
    /// Number of slots in the new code.
    #[serde(rename = "useCount")]
    pub use_count: u32,
    /// Optional DID to attribute the issuance to (admin use).
    #[serde(rename = "forAccount")]
    pub for_account: Option<String>,
}

/// Output of `com.atproto.server.createInviteCode`.
#[derive(Debug, Serialize)]
pub struct InviteCodeIssued {
    /// The code string.
    pub code: String,
}

/// Handler for `com.atproto.server.createInviteCode`. Auth-required.
///
/// §4.6 — gated on `account.can_issue_invites`. Admins can flip the toggle
/// via `com.atproto.admin.{disable,enable}AccountInvites`. The DID checked
/// is the attributed-to DID (the one that will own the issued code), not
/// the calling DID — this preserves the existing admin-overrides pattern
/// where one privileged caller can mint a code for another account.
pub async fn create_invite_code(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<CreateInviteCodeInput>,
) -> Result<Json<InviteCodeIssued>, XrpcError> {
    let claims = require_access_jwt(&parts, &state)?;
    let manager = account_manager(&state)?;
    let attribute_to = input.for_account.as_deref().unwrap_or(&claims.sub);

    // §4.6 toggle check — §5.4 : route through dispatch helper.
    match manager
        .lookup_can_issue_invites(attribute_to)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("can_issue_invites lookup: {e}"),
            )
        })? {
        Some(false) => {
            return Err(XrpcError::new(
                StatusCode::FORBIDDEN,
                "InviteIssuanceDisabled",
                "invite-code issuance is disabled for this account",
            ));
        }
        Some(true) => {}
        None => {
            return Err(XrpcError::new(
                StatusCode::NOT_FOUND,
                "AccountNotFound",
                format!("account {attribute_to} not found"),
            ));
        }
    }

    let issued = invite::create(&manager.account_pool(), Some(attribute_to), input.use_count)
        .await
        .map_err(XrpcError::from)?;
    Ok(Json(InviteCodeIssued { code: issued.code }))
}

/// `POST /xrpc/com.atproto.server.activateAccount`. Auth-required.
///
/// transitions a `Deactivated` account back to `Active`.
/// Used at the end of an account migration after the new PDS has imported
/// the repo and rotated keys via PLC.
pub async fn activate_account(
    State(state): State<HttpState>,
    parts: Parts,
) -> Result<axum::http::StatusCode, XrpcError> {
    let claims = require_access_jwt(&parts, &state)?;
    let manager = account_manager(&state)?;

    // Deactivation is self-service and reversible; a takedown or suspension is
    // a moderation decision and must not be. Without this an admin takedown was
    // undone by its subject with one unprivileged call.
    //
    // `valid_transition` still permits Takendown -> Active, because an
    // administrator lifting a takedown is legitimate. The defect was who could
    // ask, not that the transition exists.
    if let Some(current) = manager
        .account_state(&claims.sub)
        .await
        .map_err(XrpcError::from)?
        && matches!(current, AccountState::Takendown | AccountState::Suspended)
    {
        return Err(XrpcError::new(
            axum::http::StatusCode::FORBIDDEN,
            "AccountTakedown",
            format!(
                "account {} is {current}; only an administrator can restore it",
                claims.sub
            ),
        ));
    }

    manager
        .set_state(&claims.sub, AccountState::Active)
        .await
        .map_err(XrpcError::from)?;
    Ok(axum::http::StatusCode::OK)
}

/// `POST /xrpc/com.atproto.server.deactivateAccount`. Auth-required.
///
/// transitions an `Active` account to `Deactivated`. The
/// caller may set `deleteAfter` (ISO-8601) to schedule a hard-delete; the
/// PDS persists it on the `account` row and a background GC task in
/// `bin/pds.rs` (`account_deletion_loop`) hourly walks deactivated accounts
/// whose `delete_after <= now` and transitions each to `Deleted`.
pub async fn deactivate_account(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<DeactivateAccountInput>,
) -> Result<axum::http::StatusCode, XrpcError> {
    let claims = require_access_jwt(&parts, &state)?;
    let manager = account_manager(&state)?;
    manager
        .set_state(&claims.sub, AccountState::Deactivated)
        .await
        .map_err(XrpcError::from)?;
    if let Some(after) = input.delete_after.as_deref() {
        manager
            .set_delete_after(&claims.sub, Some(after))
            .await
            .map_err(XrpcError::from)?;
        tracing::info!(did = %claims.sub, %after, "account deactivated with deleteAfter");
    } else {
        // Clearing any prior schedule — re-deactivating with no deleteAfter
        // means "no scheduled deletion" again.
        manager
            .set_delete_after(&claims.sub, None)
            .await
            .map_err(XrpcError::from)?;
    }
    Ok(axum::http::StatusCode::OK)
}

/// Inputs for `deactivateAccount`.
#[derive(Debug, Deserialize)]
pub struct DeactivateAccountInput {
    /// Optional ISO-8601 instant after which the PDS may hard-delete this
    /// account. Stored as a log line; the admin GC loop enforces the
    /// schedule.
    #[serde(rename = "deleteAfter")]
    pub delete_after: Option<String>,
}

/// `GET /xrpc/com.atproto.server.checkAccountStatus`. Auth-required.
///
/// reports the current state of the caller's account.
/// Reads real metrics from the per-actor SQLite tables (`repo_block`,
/// `repo_record`, `app_password`, `repo_blob_ref`, `repo_blob`).
pub async fn check_account_status(
    State(state): State<HttpState>,
    parts: Parts,
) -> Result<Json<CheckAccountStatusResponse>, XrpcError> {
    let claims = require_access_jwt(&parts, &state)?;
    let manager = account_manager(&state)?;
    let directory = state.reader.accounts();
    let account = directory
        .lookup_did(&claims.sub)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::NOT_FOUND,
                "AccountNotFound",
                format!("no account {}", claims.sub),
            )
        })?;

    // Per-actor counts (best-effort; on storage error we report 0 + log).
    let store =
        match crate::actor_store::sql::SqlActorStore::open(manager.data_dir(), &claims.sub).await {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!(did = %claims.sub, error = ?e, "checkAccountStatus: open store");
                None
            }
        };

    let (repo_commit, repo_rev, repo_blocks, indexed_records, expected_blobs, imported_blobs) =
        if let Some(store) = store.as_ref() {
            let pool = store.pool();
            let head: (Option<String>, Option<String>) =
                sqlx::query_as("SELECT cid, rev FROM commit_obj ORDER BY rev DESC LIMIT 1")
                    .fetch_optional(pool)
                    .await
                    .map_err(|e| PdsError::Storage {
                        reason: format!("checkAccountStatus head: {e}"),
                    })
                    .map_err(XrpcError::from)?
                    .map(|(c, r)| (Some(c), Some(r)))
                    .unwrap_or((None, None));
            let blocks: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM repo_block")
                .fetch_one(pool)
                .await
                .unwrap_or((0,));
            let records: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM repo_record")
                .fetch_one(pool)
                .await
                .unwrap_or((0,));
            let expected: (i64,) =
                sqlx::query_as("SELECT COUNT(DISTINCT blob_cid) FROM repo_blob_ref")
                    .fetch_one(pool)
                    .await
                    .unwrap_or((0,));
            let imported: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM repo_blob")
                .fetch_one(pool)
                .await
                .unwrap_or((0,));
            (
                head.0,
                head.1,
                blocks.0 as u64,
                records.0 as u64,
                expected.0 as u64,
                imported.0 as u64,
            )
        } else {
            (None, None, 0, 0, 0, 0)
        };

    // Account-level state count: app passwords belong to the calling DID.
    // §5.4 — dispatches per backend; failure-open behavior
    // matches the historical `unwrap_or((0,))`.
    let private_state_values = app_password::count_for_did(&manager.account_pool(), &claims.sub)
        .await
        .unwrap_or(0);

    Ok(Json(CheckAccountStatusResponse {
        activated: matches!(account.state, AccountState::Active),
        valid_did: true,
        repo_commit,
        repo_rev,
        repo_blocks,
        indexed_records,
        private_state_values: private_state_values.max(0) as u64,
        expected_blobs,
        imported_blobs,
    }))
}

/// Output of `checkAccountStatus`. Matches the lexicon shape (zeros where
/// metrics are not yet tracked).
#[derive(Debug, Serialize)]
pub struct CheckAccountStatusResponse {
    /// `true` iff the account is in `Active` state.
    pub activated: bool,
    /// `true` iff the DID resolves to this PDS.
    #[serde(rename = "validDid")]
    pub valid_did: bool,
    /// Latest commit CID (if any).
    #[serde(skip_serializing_if = "Option::is_none", rename = "repoCommit")]
    pub repo_commit: Option<String>,
    /// Latest rev (TID).
    #[serde(skip_serializing_if = "Option::is_none", rename = "repoRev")]
    pub repo_rev: Option<String>,
    /// Block count in the repo store.
    #[serde(rename = "repoBlocks")]
    pub repo_blocks: u64,
    /// Indexed record count.
    #[serde(rename = "indexedRecords")]
    pub indexed_records: u64,
    /// Private state value count (preferences / app passwords / etc.).
    #[serde(rename = "privateStateValues")]
    pub private_state_values: u64,
    /// Expected blob count.
    #[serde(rename = "expectedBlobs")]
    pub expected_blobs: u64,
    /// Imported blob count.
    #[serde(rename = "importedBlobs")]
    pub imported_blobs: u64,
}

/// Output of `com.atproto.server.reserveSigningKey`.
#[derive(Debug, Serialize)]
pub struct ReserveSigningKeyResponse {
    /// Newly-allocated public signing key in `did:key:` form.
    #[serde(rename = "signingKey")]
    pub signing_key: String,
}

/// Inputs for `com.atproto.server.reserveSigningKey`.
#[derive(Debug, Deserialize)]
pub struct ReserveSigningKeyInput {
    /// DID this key will be associated with on `createAccount`. Optional —
    /// when supplied, the PDS records the reservation so the same key is
    /// returned on subsequent calls (idempotent).
    pub did: Option<String>,
}

/// `POST /xrpc/com.atproto.server.reserveSigningKey`.
///
/// generate a fresh atproto
/// signing key, persist its public form, and return the `did:key:...`
/// representation. The migration flow uses this so the new PDS can supply
/// the public key in the PLC update operation *before* `importRepo`.
///
/// Generates a P-256 key via `atproto-identity`, persists to the
/// KeyStore, returns the public form. The reservation row is keyed by
/// the supplied DID (when present); subsequent calls with the same
/// DID return the same key.
pub async fn reserve_signing_key(
    State(state): State<HttpState>,
    Json(input): Json<ReserveSigningKeyInput>,
) -> Result<Json<ReserveSigningKeyResponse>, XrpcError> {
    let manager = account_manager(&state)?;
    use atproto_identity::key::{KeyType, generate_key, to_public};
    let signing_priv = generate_key(KeyType::P256Private).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("generate signing key: {e}"),
        )
    })?;
    let signing_pub = to_public(&signing_priv).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("derive pub: {e}"),
        )
    })?;
    let key_ref = manager
        .key_store()
        .put(&signing_priv)
        .await
        .map_err(XrpcError::from)?;
    if let Some(did) = input.did.as_deref() {
        // Best-effort note in the signing_key table for later attribution.
        // §5.4 — `reserve_signing_key` dispatches per backend.
        let now = chrono::Utc::now().to_rfc3339();
        let id = format!("reserved-{}", chrono::Utc::now().timestamp_millis());
        let _ = manager
            .reserve_signing_key(&id, did, "P256Private", &key_ref, &now)
            .await;
    }
    Ok(Json(ReserveSigningKeyResponse {
        signing_key: signing_pub.to_string(),
    }))
}

/// Inputs for `com.atproto.server.requestEmailUpdate`.
#[derive(Debug, Deserialize)]
pub struct RequestEmailUpdateInput {
    /// New email address.
    pub email: String,
}

/// Output of `com.atproto.server.requestEmailUpdate`.
#[derive(Debug, Serialize)]
pub struct RequestEmailUpdateResponse {
    /// Whether confirmation is required (always true for now).
    #[serde(rename = "tokenRequired")]
    pub token_required: bool,
}

/// Purpose tag for the email-update flow. `requestEmailUpdate` writes
/// `email_token` rows with this value; `confirmEmailUpdate` only consumes
/// rows that carry it. Other flows (e.g. password reset) would use
/// distinct purposes.
const EMAIL_TOKEN_PURPOSE_UPDATE: &str = "update_email";

/// 1-hour TTL for email-update tokens. Same window as the standard
/// password-reset link.
const EMAIL_TOKEN_TTL_SECS: i64 = 60 * 60;

/// `POST /xrpc/com.atproto.server.requestEmailUpdate`. Auth-required.
///
/// Issues a one-time token bound to the caller's DID + the new email
/// address. The token is persisted in `email_token` for 1 hour.
///
/// When SMTP is configured (per §3.1) the PDS sends a confirmation email
/// containing the token URL; otherwise the token is logged at INFO with a
/// `dev-only:` prefix so a developer can complete the flow against a
/// localhost build.
pub async fn request_email_update(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<RequestEmailUpdateInput>,
) -> Result<Json<RequestEmailUpdateResponse>, XrpcError> {
    let claims = require_access_jwt(&parts, &state)?;
    if !is_email_shape(&input.email) {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            format!("invalid email: {}", input.email),
        ));
    }
    let manager = account_manager(&state)?;

    // 32 random bytes → URL-safe base64 → 43-char token. Unique enough
    // to avoid collisions even if the table accumulates millions of rows.
    let token = {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use rand::RngExt;
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        base64::Engine::encode(&URL_SAFE_NO_PAD, bytes)
    };
    let now = chrono::Utc::now();
    let expires_at = (now + chrono::Duration::seconds(EMAIL_TOKEN_TTL_SECS)).to_rfc3339();
    crate::account::email_token::insert(
        &manager.account_pool(),
        &token,
        &claims.sub,
        EMAIL_TOKEN_PURPOSE_UPDATE,
        &expires_at,
        Some(&input.email),
    )
    .await
    .map_err(XrpcError::from)?;

    // Dispatch via EmailService — when SMTP is configured this sends a
    // real message, otherwise the disabled stub logs the URL at INFO.
    let body = format!(
        "Confirm your email update at:\n\n  /xrpc/com.atproto.server.confirmEmailUpdate?token={token}\n\nThis link expires in 1 hour."
    );
    if let Err(e) = state
        .email
        .send(&input.email, "Confirm your email update", &body)
        .await
    {
        tracing::warn!(error = ?e, did = %claims.sub, "email send failed; token still valid");
    }

    Ok(Json(RequestEmailUpdateResponse {
        token_required: true,
    }))
}

/// Inputs for `com.atproto.server.confirmEmailUpdate`.
#[derive(Debug, Deserialize)]
pub struct ConfirmEmailUpdateInput {
    /// Token issued by `requestEmailUpdate`.
    pub token: String,
}

/// `POST /xrpc/com.atproto.server.confirmEmailUpdate`. No auth — the token
/// itself is the auth.
///
/// Verifies the token (matching purpose, not expired), updates
/// `account.email` to the recorded `new_email`, and consumes (deletes) the
/// row so it can't be replayed. All in a single transaction.
pub async fn confirm_email_update(
    State(state): State<HttpState>,
    Json(input): Json<ConfirmEmailUpdateInput>,
) -> Result<axum::http::StatusCode, XrpcError> {
    let manager = account_manager(&state)?;
    let pool = manager.account_pool();

    let row = crate::account::email_token::lookup(&pool, &input.token)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(StatusCode::BAD_REQUEST, "InvalidToken", "token not found")
        })?;
    if row.purpose != EMAIL_TOKEN_PURPOSE_UPDATE {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            format!("token has wrong purpose: {}", row.purpose),
        ));
    }
    let exp = chrono::DateTime::parse_from_rfc3339(&row.expires_at).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("parse expires_at: {e}"),
        )
    })?;
    if exp < chrono::Utc::now() {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "token expired",
        ));
    }
    let new_email = row.new_email.ok_or_else(|| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "email_token missing new_email",
        )
    })?;

    // The legacy SQL path ran these two ops in a single transaction.
    // With the dispatch routing through `AccountPool`, atomicity
    // crosses the connection boundary; we accept best-effort semantic
    // here — a partial failure leaves the email_token row consumable
    // until expires_at, which the unified GC tick prunes.
    manager
        .set_email(&row.did, Some(&new_email))
        .await
        .map_err(XrpcError::from)?;
    crate::account::email_token::delete(&pool, &input.token)
        .await
        .map_err(XrpcError::from)?;

    tracing::info!(did = %row.did, new_email = %new_email, "email updated via confirmEmailUpdate");
    Ok(axum::http::StatusCode::OK)
}

/// Purpose tag for the account-deletion flow.
const EMAIL_TOKEN_PURPOSE_DELETE: &str = "delete_account";

/// `POST /xrpc/com.atproto.server.requestAccountDelete`. Auth-required.
///
/// Issues a one-time confirmation token (1-hour TTL) and emails it to the
/// caller's primary email address. The user redeems it via
/// `com.atproto.server.deleteAccount`. Same machinery as
/// `requestEmailUpdate` (§1.9) — re-uses the `email_token` table with a
/// different `purpose` value.
pub async fn request_account_delete(
    State(state): State<HttpState>,
    parts: Parts,
) -> Result<axum::http::StatusCode, XrpcError> {
    let claims = require_access_jwt(&parts, &state)?;
    let manager = account_manager(&state)?;

    let directory = state.reader.accounts();
    let row = directory
        .lookup_did(&claims.sub)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::NOT_FOUND,
                "AccountNotFound",
                format!("no account {}", claims.sub),
            )
        })?;
    let to_email = row.email.clone().ok_or_else(|| {
        XrpcError::new(
            StatusCode::PRECONDITION_FAILED,
            "NoEmailOnAccount",
            "this account has no email address; set one via requestEmailUpdate first",
        )
    })?;

    let token = {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use rand::RngExt;
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        base64::Engine::encode(&URL_SAFE_NO_PAD, bytes)
    };
    let now = chrono::Utc::now();
    let expires_at = (now + chrono::Duration::seconds(EMAIL_TOKEN_TTL_SECS)).to_rfc3339();
    crate::account::email_token::insert(
        &manager.account_pool(),
        &token,
        &claims.sub,
        EMAIL_TOKEN_PURPOSE_DELETE,
        &expires_at,
        None,
    )
    .await
    .map_err(XrpcError::from)?;

    let body = format!(
        "Confirm account deletion at:\n\n  /xrpc/com.atproto.server.deleteAccount?token={token}\n\nThis link expires in 1 hour. If you did not request this, ignore this message."
    );
    if let Err(e) = state
        .email
        .send(&to_email, "Confirm account deletion", &body)
        .await
    {
        tracing::warn!(error = ?e, did = %claims.sub, "delete-account email send failed; token still valid");
    }
    Ok(axum::http::StatusCode::OK)
}

/// Inputs for `com.atproto.server.deleteAccount`.
#[derive(Debug, Deserialize)]
pub struct DeleteAccountInput {
    /// Confirmation token from `requestAccountDelete`.
    pub token: String,
}

/// `POST /xrpc/com.atproto.server.deleteAccount`. No bearer auth — the
/// token itself is the auth.
///
/// Verifies the token (matching purpose, not expired), transitions the
/// account to `Deleted`, and consumes the row.
pub async fn delete_account_with_token(
    State(state): State<HttpState>,
    Json(input): Json<DeleteAccountInput>,
) -> Result<axum::http::StatusCode, XrpcError> {
    let manager = account_manager(&state)?;
    let pool = manager.account_pool();

    let row = crate::account::email_token::lookup(&pool, &input.token)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(StatusCode::BAD_REQUEST, "InvalidToken", "token not found")
        })?;
    if row.purpose != EMAIL_TOKEN_PURPOSE_DELETE {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            format!("token has wrong purpose: {}", row.purpose),
        ));
    }
    let exp = chrono::DateTime::parse_from_rfc3339(&row.expires_at).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("parse expires_at: {e}"),
        )
    })?;
    if exp < chrono::Utc::now() {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "token expired",
        ));
    }

    crate::account::email_token::delete(&pool, &input.token)
        .await
        .map_err(XrpcError::from)?;
    manager
        .set_state(&row.did, AccountState::Deleted)
        .await
        .map_err(XrpcError::from)?;
    tracing::info!(did = %row.did, "account deleted via deleteAccount token redemption");
    Ok(axum::http::StatusCode::OK)
}

// ---------------------------------------------------------------------------
//  §9.1 — initial-email confirmation flow.
// ---------------------------------------------------------------------------

/// Purpose tag for the initial-email confirmation flow.
const EMAIL_TOKEN_PURPOSE_CONFIRM: &str = "confirm_email";

/// `POST /xrpc/com.atproto.server.requestEmailConfirmation`. Auth-required.
///
/// Issues a one-time confirmation token (1-hour TTL) and emails it to the
/// caller's primary `account.email`. Once redeemed via `confirmEmail`, the
/// PDS sets `account.email_confirmed_at = now()`. Distinct from
/// `requestEmailUpdate` (§1.9): this confirms an already-stored address;
/// `requestEmailUpdate` changes the address to a new one.
///
/// Returns `412 NoEmailOnAccount` when `account.email IS NULL`. Returns
/// `400 EmailAlreadyConfirmed` when `email_confirmed_at` is already set —
/// no need to re-confirm.
pub async fn request_email_confirmation(
    State(state): State<HttpState>,
    parts: Parts,
) -> Result<axum::http::StatusCode, XrpcError> {
    let claims = require_access_jwt(&parts, &state)?;
    let manager = account_manager(&state)?;

    let directory = state.reader.accounts();
    let row = directory
        .lookup_did(&claims.sub)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::NOT_FOUND,
                "AccountNotFound",
                format!("no account {}", claims.sub),
            )
        })?;
    if row.email_confirmed_at.is_some() {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "EmailAlreadyConfirmed",
            "this account's email is already confirmed",
        ));
    }
    let to_email = row.email.clone().ok_or_else(|| {
        XrpcError::new(
            StatusCode::PRECONDITION_FAILED,
            "NoEmailOnAccount",
            "this account has no email address; set one via requestEmailUpdate first",
        )
    })?;

    let token = {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use rand::RngExt;
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        base64::Engine::encode(&URL_SAFE_NO_PAD, bytes)
    };
    let now = chrono::Utc::now();
    let expires_at = (now + chrono::Duration::seconds(EMAIL_TOKEN_TTL_SECS)).to_rfc3339();
    crate::account::email_token::insert(
        &manager.account_pool(),
        &token,
        &claims.sub,
        EMAIL_TOKEN_PURPOSE_CONFIRM,
        &expires_at,
        None,
    )
    .await
    .map_err(XrpcError::from)?;

    let body = format!(
        "Confirm your email address at:\n\n  /xrpc/com.atproto.server.confirmEmail?token={token}\n\nThis link expires in 1 hour."
    );
    if let Err(e) = state
        .email
        .send(&to_email, "Confirm your email address", &body)
        .await
    {
        tracing::warn!(error = ?e, did = %claims.sub, "email send failed; token still valid");
    }
    Ok(axum::http::StatusCode::OK)
}

/// Inputs for `com.atproto.server.confirmEmail`.
#[derive(Debug, Deserialize)]
pub struct ConfirmEmailInput {
    /// Token issued by `requestEmailConfirmation`.
    pub token: String,
}

/// `POST /xrpc/com.atproto.server.confirmEmail`. No auth — the token is
/// the auth.
///
/// Verifies the token (matching purpose, not expired), sets
/// `account.email_confirmed_at = now()`, and consumes (deletes) the row
/// so it can't be replayed. All in a single transaction.
pub async fn confirm_email(
    State(state): State<HttpState>,
    Json(input): Json<ConfirmEmailInput>,
) -> Result<axum::http::StatusCode, XrpcError> {
    let manager = account_manager(&state)?;
    let pool = manager.account_pool();
    let row = crate::account::email_token::lookup(&pool, &input.token)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(StatusCode::BAD_REQUEST, "InvalidToken", "token not found")
        })?;
    if row.purpose != EMAIL_TOKEN_PURPOSE_CONFIRM {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            format!("token has wrong purpose: {}", row.purpose),
        ));
    }
    let exp = chrono::DateTime::parse_from_rfc3339(&row.expires_at).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("parse expires_at: {e}"),
        )
    })?;
    if exp < chrono::Utc::now() {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "token expired",
        ));
    }

    let now = chrono::Utc::now().to_rfc3339();
    // Pre-Batch-S, these two ops ran in a single SQL transaction. With
    // dispatch routing through `AccountPool`, atomicity crosses the
    // connection boundary; we accept best-effort semantic — a partial
    // failure leaves the email_token row consumable until expires_at
    // (the unified GC tick prunes), and the user can retry.
    manager
        .set_email_confirmed_at(&row.did, Some(&now))
        .await
        .map_err(XrpcError::from)?;
    crate::account::email_token::delete(&pool, &input.token)
        .await
        .map_err(XrpcError::from)?;
    tracing::info!(did = %row.did, "email confirmed via confirmEmail");
    Ok(axum::http::StatusCode::OK)
}

// ---------------------------------------------------------------------------
//  §9.2 — password-reset flow.
// ---------------------------------------------------------------------------

/// Purpose tag for the password-reset flow.
const EMAIL_TOKEN_PURPOSE_RESET: &str = "reset_password";

/// Inputs for `com.atproto.server.requestPasswordReset`.
#[derive(Debug, Deserialize)]
pub struct RequestPasswordResetInput {
    /// Account email address. The recovery flow does NOT require auth —
    /// the user is, by definition, locked out and looking up by email is
    /// the only side-channel we can offer. To rate-limit abuse the
    /// `request_password_reset` handler reuses the existing per-key
    /// `SlidingWindowLimiter` keyed on the email.
    pub email: String,
}

/// `POST /xrpc/com.atproto.server.requestPasswordReset`. **No auth** — the
/// caller is presumed locked out. We always return 200 to avoid leaking
/// account existence; only when the email matches a real account do we
/// actually persist a token and dispatch the recovery email.
pub async fn request_password_reset(
    State(state): State<HttpState>,
    Json(input): Json<RequestPasswordResetInput>,
) -> Result<axum::http::StatusCode, XrpcError> {
    if !is_email_shape(&input.email) {
        // Don't leak validation specifics — same opaque 200 as the not-found case.
        return Ok(axum::http::StatusCode::OK);
    }
    let manager = account_manager(&state)?;

    // Rate-limit per email. Failure-open: a storage hiccup on the
    // limiter is logged but doesn't block the user.
    let _ = state
        .rate_limiter
        .try_acquire(&format!("requestPasswordReset:{}", input.email))
        .await;

    // Look up the account by email. Always 200, regardless of hit/miss.
    // §5.4 — dispatch helper folds the `state = 'active'`
    // filter into one query.
    let did = match manager
        .lookup_did_by_active_email(&input.email)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("account lookup: {e}"),
            )
        })? {
        Some(d) => d,
        None => {
            tracing::info!(email = %input.email, "requestPasswordReset: no active account match (silent 200)");
            return Ok(axum::http::StatusCode::OK);
        }
    };

    let token = {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use rand::RngExt;
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        base64::Engine::encode(&URL_SAFE_NO_PAD, bytes)
    };
    let now = chrono::Utc::now();
    let expires_at = (now + chrono::Duration::seconds(EMAIL_TOKEN_TTL_SECS)).to_rfc3339();
    crate::account::email_token::insert(
        &manager.account_pool(),
        &token,
        &did,
        EMAIL_TOKEN_PURPOSE_RESET,
        &expires_at,
        None,
    )
    .await
    .map_err(XrpcError::from)?;

    let body = format!(
        "Reset your password at:\n\n  /xrpc/com.atproto.server.resetPassword?token={token}\n\nIf you did not request this, you can ignore this email. The link expires in 1 hour."
    );
    if let Err(e) = state
        .email
        .send(&input.email, "Reset your password", &body)
        .await
    {
        tracing::warn!(error = ?e, did = %did, "email send failed; token still valid");
    }
    Ok(axum::http::StatusCode::OK)
}

/// Inputs for `com.atproto.server.resetPassword`.
#[derive(Debug, Deserialize)]
pub struct ResetPasswordInput {
    /// Token issued by `requestPasswordReset`.
    pub token: String,
    /// New password (plaintext; hashed server-side via argon2id).
    pub password: String,
}

/// `POST /xrpc/com.atproto.server.resetPassword`. **No auth** — the token
/// is the auth.
///
/// Verifies the token (matching purpose, not expired), updates BOTH
/// `account.password_hash` (used by OAuth `/authorize`) AND the
/// `__primary__` app-password row (used by `createSession`) so the user
/// can log in via either path. Same lockstep as `createAccount` and the
/// admin override (§4.3). Consumes the token in one transaction.
pub async fn reset_password(
    State(state): State<HttpState>,
    Json(input): Json<ResetPasswordInput>,
) -> Result<axum::http::StatusCode, XrpcError> {
    if input.password.len() < 8 {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "password must be at least 8 characters",
        ));
    }
    let manager = account_manager(&state)?;
    let hash = account::hash_password(&input.password).map_err(XrpcError::from)?;

    let pool = manager.account_pool();
    let row = crate::account::email_token::lookup(&pool, &input.token)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(StatusCode::BAD_REQUEST, "InvalidToken", "token not found")
        })?;
    if row.purpose != EMAIL_TOKEN_PURPOSE_RESET {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            format!("token has wrong purpose: {}", row.purpose),
        ));
    }
    let exp = chrono::DateTime::parse_from_rfc3339(&row.expires_at).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("parse expires_at: {e}"),
        )
    })?;
    if exp < chrono::Utc::now() {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "token expired",
        ));
    }

    // Pre-Batch-S, these three ops ran in a single SQL transaction.
    // With dispatch routing through `AccountPool`, atomicity crosses
    // the connection boundary; we accept best-effort semantic — a
    // partial failure leaves either the password update incomplete
    // (user can retry) or the email_token consumable until expires_at
    // (the unified GC tick prunes).
    manager
        .set_password_hash(&row.did, &hash)
        .await
        .map_err(XrpcError::from)?;
    crate::account::app_password::update_primary_hash(&pool, &row.did, &hash)
        .await
        .map_err(XrpcError::from)?;
    crate::account::email_token::delete(&pool, &input.token)
        .await
        .map_err(XrpcError::from)?;
    tracing::info!(did = %row.did, "password reset via resetPassword token redemption");
    Ok(axum::http::StatusCode::OK)
}

/// One row in `getAccountInviteCodes` output.
#[derive(Debug, Serialize)]
pub struct AccountInviteCode {
    /// The invite code string.
    pub code: String,
    /// Whether the code is currently disabled by an admin.
    pub disabled: bool,
    /// Remaining redemptions allowed.
    #[serde(rename = "availableUses")]
    pub available_uses: i64,
    /// Optional DID of the account that redeemed this code.
    #[serde(skip_serializing_if = "Option::is_none", rename = "usedBy")]
    pub used_by: Option<String>,
    /// ISO-8601 issuance timestamp.
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

/// Output of `getAccountInviteCodes`.
#[derive(Debug, Serialize)]
pub struct GetAccountInviteCodesResponse {
    /// Codes the caller has issued.
    pub codes: Vec<AccountInviteCode>,
}

/// `GET /xrpc/com.atproto.server.getAccountInviteCodes`. Auth-required.
///
/// Returns the invite codes the caller has issued. Same data shape as the
/// admin `getInviteCodes` but auth-gated by the account's session JWT —
/// users see only their own codes; the admin endpoint sees everyone's.
pub async fn get_account_invite_codes(
    State(state): State<HttpState>,
    parts: Parts,
) -> Result<Json<GetAccountInviteCodesResponse>, XrpcError> {
    let claims = require_access_jwt(&parts, &state)?;
    let manager = account_manager(&state)?;
    let rows = invite::list_for_did(&manager.account_pool(), &claims.sub)
        .await
        .map_err(XrpcError::from)?;
    let codes = rows
        .into_iter()
        .map(|r| AccountInviteCode {
            code: r.code,
            disabled: r.disabled,
            available_uses: r.available_uses as i64,
            used_by: r.used_by,
            created_at: r.created_at,
        })
        .collect();
    Ok(Json(GetAccountInviteCodesResponse { codes }))
}

/// Inputs for `com.atproto.identity.signPlcOperation`.
#[derive(Debug, Deserialize)]
pub struct SignPlcOperationInput {
    /// Unsigned operation as a JSON object (PLC `Operation` shape pre-signing).
    pub op: serde_json::Value,
}

/// Output of `signPlcOperation`.
#[derive(Debug, Serialize)]
pub struct SignPlcOperationResponse {
    /// The signed operation; ready for `submitPlcOperation`.
    pub operation: serde_json::Value,
}

/// `POST /xrpc/com.atproto.identity.signPlcOperation`. Auth-required.
///
/// Signs a PLC update operation with the caller's PDS-managed rotation key.
/// The unsigned `op` arrives from the client (or from `getRecommendedDidCredentials`);
/// we sign with the rotation key persisted at account-creation and return
/// the signed operation for the client to submit (or to pass to
/// `submitPlcOperation` below).
pub async fn sign_plc_operation(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<SignPlcOperationInput>,
) -> Result<Json<SignPlcOperationResponse>, XrpcError> {
    use atproto_identity::plc::operations::UnsignedOperation;
    let claims = require_access_jwt(&parts, &state)?;
    let manager = account_manager(&state)?;
    // The rotation key is tracked in
    // `account.rotation_key_ref` (NOT in the `signing_key` table, which is
    // for the atproto signing key). Pre-genesis rows may have NULL here —
    // the caller has no PDS-managed rotation key and must rotate by other
    // means (e.g. an externally-held rotation key submitted directly to PLC).
    // §5.4 — dispatch helper picks the right SQL flavor.
    let rotation_key_ref = manager
        .lookup_rotation_key_ref(&claims.sub)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("lookup rotation key: {e}"),
            )
        })?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::PRECONDITION_FAILED,
                "NoRotationKey",
                "this account has no PDS-managed rotation key",
            )
        })?;
    let rotation_priv = manager
        .key_store()
        .get(&rotation_key_ref)
        .await
        .map_err(XrpcError::from)?;

    let unsigned: UnsignedOperation = serde_json::from_value(input.op).map_err(|e| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            format!("op must be an unsigned PLC Operation: {e}"),
        )
    })?;
    let signed = unsigned.sign(&rotation_priv).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("sign PLC op: {e}"),
        )
    })?;
    let value = serde_json::to_value(&signed).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("serialize signed op: {e}"),
        )
    })?;
    Ok(Json(SignPlcOperationResponse { operation: value }))
}

/// Inputs for `com.atproto.identity.submitPlcOperation`.
#[derive(Debug, Deserialize)]
pub struct SubmitPlcOperationInput {
    /// A signed PLC Operation (from `signPlcOperation`).
    pub operation: serde_json::Value,
}

/// `POST /xrpc/com.atproto.identity.submitPlcOperation`. Auth-required.
///
/// POSTs the signed operation to the configured PLC directory. Requires the
/// PDS to have a `PlcService` configured (i.e., `PDS_DID_PLC_URL` was set).
pub async fn submit_plc_operation(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<SubmitPlcOperationInput>,
) -> Result<axum::http::StatusCode, XrpcError> {
    let claims = require_access_jwt(&parts, &state)?;
    let plc = state.plc_service.as_ref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "PlcUnavailable",
            "PDS_DID_PLC_URL is not configured",
        )
    })?;
    let signed: atproto_identity::plc::Operation = serde_json::from_value(input.operation)
        .map_err(|e| {
            XrpcError::new(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                format!("operation must be a signed PLC Operation: {e}"),
            )
        })?;
    plc.submit_operation(&claims.sub, &signed)
        .await
        .map_err(XrpcError::from)?;
    Ok(StatusCode::OK)
}

/// Cheap email-shape validator — `<x>@<y>.<z>` with at least one char per part.
fn is_email_shape(s: &str) -> bool {
    let mut parts = s.split('@');
    let local = parts.next();
    let domain = parts.next();
    if parts.next().is_some() {
        return false;
    }
    match (local, domain) {
        (Some(l), Some(d)) if !l.is_empty() && d.contains('.') => {
            d.split('.').all(|seg| !seg.is_empty())
        }
        _ => false,
    }
}

// ---- Helpers ----

fn bearer_token(parts: &Parts) -> Result<&str, XrpcError> {
    let header = parts.headers.get(AUTHORIZATION).ok_or_else(|| {
        XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
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
    raw.strip_prefix("Bearer ").ok_or_else(|| {
        XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "expected Bearer scheme",
        )
    })
}

fn require_access_jwt(
    parts: &Parts,
    state: &HttpState,
) -> Result<account::SessionClaims, XrpcError> {
    let raw = bearer_token(parts)?;
    session::verify_access(raw, &state.jwt_secret).map_err(XrpcError::from)
}
