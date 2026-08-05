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
use crate::http::auth::{authorization_token, request_htm_htu, require_authn};
use crate::http::errors::XrpcError;
use crate::http::extract::XrpcJson as Json;
use crate::http::state::HttpState;
use crate::oauth::token::{TYP_ACCESS as OAUTH_TYP_ACCESS, verify_oauth_jwt};
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The lexicon method an inbound migration's service-auth token must name.
const CREATE_ACCOUNT_LXM: &str = "com.atproto.server.createAccount";

/// Verify that the caller controls the DID they are claiming.
///
/// The proof is a service-auth token issued by the DID's current host, bound to
/// this PDS (`aud`) and to this method (`lxm`), and signed by the `#atproto`
/// key published in the DID's own document. That document is fetched live, so
/// the check is against what the identity says about itself right now — which
/// is the only thing that distinguishes a migration from a squat.
///
/// There is deliberately no way to switch this off. An escape hatch here would
/// be set on exactly the deployments that most need the check, and a DID that
/// cannot be resolved is a DID whose control cannot be demonstrated.
async fn verify_inbound_did_claim(
    state: &HttpState,
    parts: &Parts,
    claimed_did: &str,
) -> Result<(), XrpcError> {
    let token = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::UNAUTHORIZED,
                "AuthRequired",
                format!(
                    "creating an account for an existing DID requires a service-auth token from \
                     {claimed_did}'s current host, bound to this server with lxm \
                     {CREATE_ACCOUNT_LXM}"
                ),
            )
        })?;

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(crate::user_agent())
        .build()
        .unwrap_or_default();
    let plc_dir = state.plc_service.as_ref().map(|p| p.directory_hostname());

    let claims = crate::space::service_auth::verify_service_auth(
        &http,
        token,
        plc_dir,
        &state.service_did,
        CREATE_ACCOUNT_LXM,
        state
            .account_manager
            .as_deref()
            .map(crate::account::AccountManager::account_pool_ref),
    )
    .await
    .map_err(XrpcError::from)?;

    // The token proves control of whatever `iss` names. It has to name the DID
    // being claimed, or a valid token for one identity would create accounts
    // for any other.
    if claims.iss != claimed_did {
        tracing::warn!(
            claimed = %claimed_did,
            issuer = %claims.iss,
            "createAccount rejected: service-auth issuer is not the DID being claimed"
        );
        return Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "AuthDenied",
            format!(
                "service-auth token was issued by {}, not by {claimed_did}",
                claims.iss
            ),
        ));
    }
    Ok(())
}

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
    parts: Parts,
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
    // A caller-supplied DID must be proven, not taken on trust.
    //
    // Adopting one verbatim let anyone squat an arbitrary DID: obtain a session
    // bound to the victim's identity, have this PDS serve `describeRepo`,
    // `getRepo` and firehose events for it, and permanently deny the victim an
    // inbound migration here. Forged commits fail relay signature verification,
    // so the damage is bounded — the lockout is not.
    //
    // Proof is an inbound service-auth token issued by the DID's *current*
    // host: `iss` is the DID being claimed, `aud` is this PDS, and `lxm` is
    // this method. The signature is checked against the `#atproto` key in the
    // DID's own document, so only whoever controls that identity today can
    // move it here. This is the other face of F-SVC-14 — no canonical endpoint
    // accepted an inbound service-auth token at all.
    let (did, rotation_key_ref, signing_key_ref, verified_migration) =
        if let Some(d) = input.did.clone() {
            verify_inbound_did_claim(&state, &parts, &d).await?;
            (d, None, None, true)
        } else {
            // Uniqueness is checked here as well as inside `create_account`,
            // because genesis is not free and not reversible: it publishes an
            // operation to the PLC directory's append-only log, and a DID
            // abandoned a moment later when the INSERT hits a taken handle or
            // email stays in that log forever. Checking after minting means one
            // orphaned identity per duplicate signup attempt.
            //
            // The conflict is reported ahead of `PlcUnavailable` because it
            // does not depend on how this server is configured: the request
            // cannot succeed either way, and a 400 tells the caller something
            // they can act on where a 503 invites a pointless retry.
            //
            // The DID is passed as `None` — there is nothing to check until
            // genesis mints one. `create_account` covers that column.
            manager
                .ensure_available(None, &input.handle, input.email.as_deref())
                .await
                .map_err(XrpcError::from)?;
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
                false,
            )
        };

    let row = manager
        .create_account(CreateAccountParams {
            // A verified inbound migration lands deactivated: until the DID
            // document points here, the repository must not be publicly
            // readable or emitting firehose events. Locally-issued DIDs are
            // an ordinary signup and land active.
            state: if verified_migration {
                AccountState::Deactivated
            } else {
                AccountState::Active
            },
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

    // Give the account an empty repository, so it *has* one rather than
    // merely being entitled to one. Without this, `getLatestCommit` answers
    // `RepoNotFound` for a valid account, `getRepo` has nothing to export,
    // and the account announcement can carry neither `#commit` nor `#sync`
    // because there is no commit to name — a relay learns the account exists
    // and cannot learn where its repository starts.
    //
    // Here rather than in `AccountManager`, which is where the `#identity`
    // and `#account` events are emitted from: a repository is a different
    // subsystem, and `RepoWriter` already holds an `Arc<AccountManager>`, so
    // reaching the other way would invert the dependency. The reference makes
    // the same split — `actorTxn.repo.createRepo([])` lives in
    // `createAccount.ts`, not in its account store.
    //
    // Only for accounts that land active. A verified inbound migration lands
    // deactivated and receives its repository from the CAR import; creating
    // an empty genesis commit first would give the import a prior commit to
    // conflict with.
    if !verified_migration
        && let Some(writer) = state.writer.as_ref()
        && let Err(error) = writer.create_genesis_commit(&row.did).await
    {
        // Best-effort, matching the account announcement: the account row is
        // durable and usable, and the first write will create a commit
        // anyway. Logged at ERROR because until then the repository reads as
        // absent rather than empty.
        tracing::error!(did = %row.did, ?error, "createAccount: genesis commit failed");
    }

    // Mint a session immediately. We need an app-password row to attach the
    // session to; createAccount issues an implicit "primary" app password
    // on account creation, mirroring how the TS reference treats the
    // password.
    let primary_id = manager
        .set_primary_password(&row.did, &input.password)
        .await
        .map_err(XrpcError::from)?;

    let tokens = session::issue_pair(
        &state.service_did,
        &row.did,
        &primary_id,
        // The signup session is the account password by definition.
        session::SessionAuthority::Full,
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
    let (app_id, authority) = match app {
        Some(row) => {
            let authority = session::SessionAuthority::from_row(&row.name, row.privileged);
            (row.id, authority)
        }
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
        authority,
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
    // Always allowed for OAuth. The reference says as much in so many words
    // (`authorize: () => { /* Always allowed */ }`); "email" access is
    // decided in the handler, not here. This is the first call most
    // clients make after authorizing, and refusing it made every OAuth
    // token look broken at the first hop.
    let did = require_session_or_oauth(&parts, &state, &OAuthScope::Any).await?;
    let directory = state.reader.accounts();
    let account = directory
        .lookup_did(&did)
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

    // A client with two requests in flight can meet a 401 on both and refresh
    // with the same stored token twice. One wins the replay check below; the
    // other would get `AuthenticationRequired`, and the official client treats
    // a refresh that yields no session as the session being gone and logs the
    // account holder out. So a refresh is idempotent for a few seconds: the
    // same token returns the same successor rather than an error.
    //
    // Outside that window the replay check still refuses it, which is what
    // keeps rotation meaningful.
    if let Some(existing) = state.refresh_grace.get(&claims.jti) {
        tracing::debug!(
            did = %claims.sub,
            "refresh replayed inside the grace window; returning the same successor"
        );
        let account_handle = state
            .reader
            .accounts()
            .lookup_did(&claims.sub)
            .await
            .map_err(XrpcError::from)?
            .map(|a| a.handle)
            .unwrap_or_default();
        return Ok(Json(SessionResponse {
            access_jwt: existing.access_jwt,
            refresh_jwt: existing.refresh_jwt,
            handle: account_handle,
            did: claims.sub,
        }));
    }

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
        // Carried, not recomputed: refreshing a session must not change what
        // it is allowed to do.
        if claims.full {
            session::SessionAuthority::Full
        } else if claims.privileged {
            session::SessionAuthority::PrivilegedAppPassword
        } else {
            session::SessionAuthority::AppPassword
        },
        &state.jwt_secret,
        session::DEFAULT_ACCESS_TTL_SECS,
        session::DEFAULT_REFRESH_TTL_SECS,
    )
    .map_err(XrpcError::from)?;

    // Remember what this token bought, so a racing second request gets the
    // same answer instead of a 401.
    state.refresh_grace.insert(&claims.jti, &tokens);

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
    require_full_session(&claims, "com.atproto.server.createAppPassword")?;
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

/// Outcome of asking whether an account's DID document names this server.
///
/// Four states rather than a `Result<bool, _>` because "no PLC directory is
/// configured" and "the PLC directory did not answer" are different situations
/// that deserve different responses, and collapsing them into one error was
/// what made this awkward to get right.
#[derive(Debug)]
enum DidDocCheck {
    /// The document resolved and names this server.
    NamesThisPds,
    /// The document resolved and names somewhere else.
    NamesElsewhere,
    /// No PLC directory is configured, so this deployment has no `did:plc`
    /// identity for the server to be wrong about — and no migration path
    /// either, since every phase of one goes through PLC.
    NotApplicable,
    /// A directory is configured but the document could not be resolved.
    /// Transient, and distinct from the above: the answer is unknown rather
    /// than known-not-to-matter.
    Unresolvable(String),
}

/// Does the account's DID document name this server as its PDS?
///
/// Resolves the DID through the configured PLC directory and compares the
/// `AtprotoPersonalDataServer` service endpoints against this server's public
/// URL.
async fn check_did_document(state: &HttpState, did: &str) -> DidDocCheck {
    let Some(plc) = state.plc_service.as_ref() else {
        return DidDocCheck::NotApplicable;
    };

    let http = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(crate::user_agent())
        .build()
    {
        Ok(c) => c,
        Err(e) => return DidDocCheck::Unresolvable(format!("build http client: {e}")),
    };

    let document = match atproto_identity::plc::query(&http, plc.directory_hostname(), did).await {
        Ok(d) => d,
        Err(e) => return DidDocCheck::Unresolvable(format!("resolve {did}: {e}")),
    };

    // Trailing slashes are not a difference: an endpoint is a URL, and
    // `https://pds.example` and `https://pds.example/` name the same server.
    let ours = plc.service_endpoint().trim_end_matches('/');
    if document
        .pds_endpoints()
        .iter()
        .any(|e| e.trim_end_matches('/') == ours)
    {
        DidDocCheck::NamesThisPds
    } else {
        DidDocCheck::NamesElsewhere
    }
}

/// `POST /xrpc/com.atproto.server.activateAccount`. Auth-required.
///
/// Transitions a `Deactivated` account back to `Active`, once the account's
/// DID document names this server as its PDS. Used at the end of an account
/// migration, after the new PDS has imported the repo and the PLC operation
/// repointing the identity has been submitted.
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

    // The DID has to point here before this server starts serving the repo
    // and emitting firehose events for it.
    //
    // This is the last step of an inbound migration, and without the check an
    // account activates while its DID document still names the *source* PDS.
    // Two servers then both consider themselves authoritative for one
    // identity: both answer describeRepo and getRepo, both sequence commits,
    // and consumers resolve the DID to the old host while the new host insists
    // otherwise. Nothing reconciles that afterwards — the split is silent and
    // the account looks activated.
    //
    // The reference gates activation the same way, through
    // `assertValidDidDocumentForService` (packages/pds/src/account-manager/
    // account-manager.ts, `activateAccount`).
    //
    // An unresolvable DID refuses rather than passes: activation is the point
    // where this server takes responsibility for an identity, and it should
    // not do that on an assumption. The account stays deactivated and the
    // caller can retry once the PLC operation has propagated.
    match check_did_document(&state, &claims.sub).await {
        // Nothing to contradict. Deactivation stays self-service on a
        // deployment that has no PLC directory, which also has no migration
        // flow for this check to protect.
        DidDocCheck::NamesThisPds | DidDocCheck::NotApplicable => {}
        DidDocCheck::NamesElsewhere => {
            return Err(XrpcError::new(
                axum::http::StatusCode::BAD_REQUEST,
                "InvalidDidDoc",
                format!(
                    "the DID document for {} does not name this server as its PDS; \
                     submit the PLC operation before activating",
                    claims.sub
                ),
            ));
        }
        DidDocCheck::Unresolvable(reason) => {
            tracing::warn!(did = %claims.sub, reason, "activateAccount: DID document unresolvable");
            return Err(XrpcError::new(
                axum::http::StatusCode::BAD_REQUEST,
                "InvalidDidDoc",
                format!(
                    "could not verify the DID document for {}: {reason}",
                    claims.sub
                ),
            ));
        }
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
    // Always allowed for OAuth, matching the reference. It reports the
    // account's own state to the account's own client.
    let did = require_session_or_oauth(&parts, &state, &OAuthScope::Any).await?;
    let manager = account_manager(&state)?;
    let directory = state.reader.accounts();
    let account = directory
        .lookup_did(&did)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::NOT_FOUND,
                "AccountNotFound",
                format!("no account {}", did),
            )
        })?;

    // Per-actor counts (best-effort; on storage error we report 0 + log).
    let store = match crate::actor_store::sql::SqlActorStore::open(manager.data_dir(), &did).await {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(did = %did, error = ?e, "checkAccountStatus: open store");
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
    let private_state_values = app_password::count_for_did(&manager.account_pool(), &did)
        .await
        .unwrap_or(0);

    // Actually resolved, not assumed. This reported a hardcoded `true`, which
    // made the field useless exactly when it matters: during a migration it is
    // what tells the operator whether the identity has finished moving, and it
    // answered "yes" before the PLC operation had even been submitted.
    //
    // Unlike `activateAccount`, a resolution failure is reported rather than
    // raised — this endpoint is a status report, and the other counts above
    // already degrade to a best-effort value rather than failing the call.
    let valid_did = match check_did_document(&state, &did).await {
        DidDocCheck::NamesThisPds => true,
        // No directory to disagree with, so nothing contradicts the claim.
        DidDocCheck::NotApplicable => true,
        DidDocCheck::NamesElsewhere => false,
        DidDocCheck::Unresolvable(reason) => {
            tracing::warn!(did = %did, reason, "checkAccountStatus: DID document unresolvable");
            false
        }
    };

    Ok(Json(CheckAccountStatusResponse {
        activated: matches!(account.state, AccountState::Active),
        valid_did,
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
    parts: Parts,
    Json(input): Json<ReserveSigningKeyInput>,
) -> Result<Json<ReserveSigningKeyResponse>, XrpcError> {
    // Unauthenticated, this generated a fresh keypair on every call and stored
    // a row for whatever `did` the caller named — unbounded key generation and
    // reservation squatting for anyone who could reach the endpoint, and the
    // precursor primitive for claiming a DID outright.
    let claims = require_access_jwt(&parts, &state)?;
    let manager = account_manager(&state)?;

    // A caller may only reserve against its own DID. `did` is optional in the
    // lexicon; when present it must be the session subject.
    if let Some(requested) = input.did.as_deref()
        && requested != claims.sub
    {
        return Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "AuthDenied",
            format!("cannot reserve a signing key for {requested}"),
        ));
    }
    let subject = input.did.clone().unwrap_or_else(|| claims.sub.clone());

    // Idempotent: a repeat call returns the key already reserved. The row id
    // used to be a millisecond timestamp, so every call wrote a fresh row and
    // handed back a different key while the reservation kept the first one.
    if let Some(existing_ref) = manager
        .lookup_reserved_signing_key(&subject)
        .await
        .map_err(XrpcError::from)?
    {
        let key = manager
            .key_store()
            .get(&existing_ref)
            .await
            .map_err(XrpcError::from)?;
        let public = atproto_identity::key::to_public(&key).map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("derive pub: {e}"),
            )
        })?;
        return Ok(Json(ReserveSigningKeyResponse {
            signing_key: public.to_string(),
        }));
    }
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
    // Idempotent per DID. The row id was a millisecond timestamp, so every call
    // wrote a fresh row and the dedupe guard the docs describe never fired.
    let now = chrono::Utc::now().to_rfc3339();
    let id = format!("reserved-{subject}");
    let _ = manager
        .reserve_signing_key(&id, &subject, "P256Private", &key_ref, &now)
        .await;
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
    require_full_session(&claims, "com.atproto.server.requestEmailUpdate")?;
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
    require_full_session(&claims, "com.atproto.server.requestAccountDelete")?;
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
///
/// All three fields are required by the lexicon
/// (`lexicons/com/atproto/server/deleteAccount.json`,
/// `required: ["did", "password", "token"]`). This accepted the token alone,
/// which made the emailed token a single factor for destroying an account.
#[derive(Debug, Deserialize)]
pub struct DeleteAccountInput {
    /// The account being deleted. Checked against the token's own DID.
    pub did: String,
    /// The account password — not an app password.
    pub password: String,
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

    // The token names the account; the caller must name the same one. A
    // mismatch means the request and the token disagree about what is being
    // deleted, and guessing which to believe is not this endpoint's job.
    if row.did != input.did {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "the token was not issued for the DID in this request",
        ));
    }

    // Second factor. Deletion is irreversible, and without this the emailed
    // token was sufficient on its own: anyone who read the message — a
    // forwarded mail, a shared inbox, a mail client on an unlocked phone —
    // could destroy the account. The lexicon has required `password`
    // alongside `token` all along, and the reference enforces it.
    //
    // `__primary__` is the account password specifically. An app password
    // must not satisfy this: app passwords are handed to third-party tools,
    // and one of them being able to complete an account deletion is the
    // outcome this check exists to prevent.
    let verified = crate::account::app_password::verify(&pool, &row.did, &input.password)
        .await
        .map_err(XrpcError::from)?;
    if verified.is_none_or(|p| p.name != "__primary__") {
        tracing::warn!(did = %row.did, "deleteAccount: password verification failed");
        return Err(XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "the account password is required to delete an account",
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
    // Sending mail to the address is managing it, not reading it, so
    // `transition:email` (read-only) is not enough.
    let did = require_session_or_oauth(&parts, &state, &OAuthScope::AccountEmailManage).await?;
    let manager = account_manager(&state)?;

    let directory = state.reader.accounts();
    let row = directory
        .lookup_did(&did)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::NOT_FOUND,
                "AccountNotFound",
                format!("no account {}", did),
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
        &did,
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
        tracing::warn!(error = ?e, did = %did, "email send failed; token still valid");
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

    // Rate-limit per email, fail-closed. This used to discard the result — a
    // caller could ask for reset mails as fast as it could send requests, and
    // the limit that existed to stop that was decorative. Reset mail is sent
    // to an address the requester does not have to control, so an unbounded
    // endpoint is a mail cannon pointed at a third party.
    //
    // The 429 is the same one the middleware returns, so a client that already
    // handles rate limiting handles this.
    enforce_rate_limit(&state, &format!("requestPasswordReset:{}", input.email)).await?;

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
///
/// Matches the lexicon: every field is optional and describes a *change*.
/// Anything omitted is carried over from the DID's current operation, which
/// this server fetches — the caller does not supply the whole operation, and
/// cannot, because it does not know `prev`.
#[derive(Debug, Default, Deserialize)]
pub struct SignPlcOperationInput {
    /// Code from `com.atproto.identity.requestPlcOperationSignature`.
    pub token: Option<String>,
    /// Replacement service map.
    pub services: Option<HashMap<String, atproto_identity::plc::ServiceEndpoint>>,
    /// Replacement `alsoKnownAs` list.
    #[serde(rename = "alsoKnownAs")]
    pub also_known_as: Option<Vec<String>>,
    /// Replacement rotation keys.
    #[serde(rename = "rotationKeys")]
    pub rotation_keys: Option<Vec<String>>,
    /// Replacement verification methods.
    #[serde(rename = "verificationMethods")]
    pub verification_methods: Option<HashMap<String, String>>,
}

/// Apply the caller's deltas to the DID's current operation.
///
/// Field-wise replacement, not a merge within a field: supplying
/// `rotationKeys` replaces the list rather than appending to it. That is
/// what the reference does, and the alternative — union — would make it
/// impossible to *remove* a rotation key, which is the main reason to
/// rotate at all.
///
/// # Errors
///
/// [`PdsError::InvalidPlcOperation`] when the DID's last operation is a
/// tombstone or a legacy create, neither of which can be updated.
pub fn apply_plc_deltas(
    last: atproto_identity::plc::Operation,
    last_cid: String,
    input: &SignPlcOperationInput,
) -> Result<atproto_identity::plc::operations::UnsignedOperation, PdsError> {
    use atproto_identity::plc::Operation;
    match last {
        Operation::PlcOperation {
            rotation_keys,
            verification_methods,
            also_known_as,
            services,
            ..
        } => Ok(Operation::new_update(
            input.rotation_keys.clone().unwrap_or(rotation_keys),
            input
                .verification_methods
                .clone()
                .unwrap_or(verification_methods),
            input.also_known_as.clone().unwrap_or(also_known_as),
            input.services.clone().unwrap_or(services),
            last_cid,
        )),
        Operation::PlcTombstone { .. } => Err(PdsError::InvalidPlcOperation {
            reason: "this DID is tombstoned".to_string(),
        }),
        Operation::LegacyCreate { .. } => Err(PdsError::InvalidPlcOperation {
            reason: "this DID's last operation is a legacy create and cannot be updated"
                .to_string(),
        }),
    }
}

/// Output of `signPlcOperation`.
#[derive(Debug, Serialize)]
pub struct SignPlcOperationResponse {
    /// The signed operation; ready for `submitPlcOperation`.
    pub operation: serde_json::Value,
}

/// `POST /xrpc/com.atproto.identity.signPlcOperation`. Auth-required, and
/// additionally gated on a code from `requestPlcOperationSignature`.
///
/// Signs a PLC update operation with the caller's PDS-managed rotation key.
/// The caller describes what it wants changed; this server fetches the DID's
/// current operation, applies those changes, signs, and returns the signed
/// operation for the client to submit (or to pass to `submitPlcOperation`
/// below).
///
/// The token is not optional in practice even though the lexicon marks it so.
/// This endpoint will sign a rotation of the account's keys — the operation
/// that can hand the identity to someone else permanently — so an access
/// token alone must not be enough. That is what the emailed code is for.
pub async fn sign_plc_operation(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<SignPlcOperationInput>,
) -> Result<Json<SignPlcOperationResponse>, XrpcError> {
    // `identity:*`, not `identity:handle`: a PLC operation can rewrite
    // rotation keys and verification methods, not just the handle.
    let did = require_session_or_oauth(&parts, &state, &OAuthScope::IdentityAll).await?;
    let manager = account_manager(&state)?;

    let token = input.token.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "a confirmation code from requestPlcOperationSignature is required to sign PLC operations",
        )
    })?;
    crate::account::email_token::consume(
        &manager.account_pool(),
        token,
        crate::account::email_token::PURPOSE_PLC_OPERATION,
        &did,
    )
    .await
    .map_err(XrpcError::from)?;
    // The rotation key is tracked in
    // `account.rotation_key_ref` (NOT in the `signing_key` table, which is
    // for the atproto signing key). Pre-genesis rows may have NULL here —
    // the caller has no PDS-managed rotation key and must rotate by other
    // means (e.g. an externally-held rotation key submitted directly to PLC).
    // §5.4 — dispatch helper picks the right SQL flavor.
    let rotation_key_ref = manager
        .lookup_rotation_key_ref(&did)
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

    // The caller supplies deltas, so the current operation is what they are
    // deltas against — and it also carries `prev`, which the caller has no
    // way to know.
    let plc = state.plc_service.as_ref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "PlcUnavailable",
            "PDS_DID_PLC_URL is not configured",
        )
    })?;
    let http = reqwest::Client::builder()
        .user_agent(crate::user_agent())
        .build()
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("build http client: {e}"),
            )
        })?;
    let log = atproto_identity::plc::fetch_audit_log(&http, plc.directory_hostname(), &did)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::BAD_GATEWAY,
                "PlcUnavailable",
                format!("fetch audit log: {e}"),
            )
        })?;
    let last = log.into_iter().rfind(|e| !e.nullified).ok_or_else(|| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "PLC audit log empty for this DID",
        )
    })?;
    let unsigned = apply_plc_deltas(last.operation, last.cid, &input).map_err(XrpcError::from)?;

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

/// Constraints an operation must satisfy before this server will submit it.
///
/// Named so the checks can be unit-tested without a PLC directory or an
/// account store.
pub struct PlcSubmitConstraints<'a> {
    /// Rotation key this server holds for the account, in `did:key` form.
    pub rotation_key: &'a str,
    /// This server's public endpoint, as it should appear in
    /// `services.atproto_pds.endpoint`.
    pub service_endpoint: &'a str,
    /// The account's atproto signing key, in `did:key` form.
    pub signing_key: &'a str,
    /// The account's current handle.
    pub handle: &'a str,
}

/// Reject an operation that would leave the account unreachable here.
///
/// The lexicon's own description is the specification for this function:
/// *"Validates a PLC operation to ensure that it doesn't violate a
/// service's constraints or get the identity into a bad state, then submits
/// it to the PLC registry."* Routing the operation through the PDS buys the
/// user nothing if the PDS forwards it unread.
///
/// PLC is append-only. A submitted operation that drops this server's
/// rotation key cannot be undone by this server, so every one of these is
/// checked *before* submission, not after.
///
/// # Errors
///
/// [`PdsError::InvalidPlcOperation`] naming the constraint that failed.
pub fn check_plc_submit(
    op: &atproto_identity::plc::Operation,
    c: &PlcSubmitConstraints<'_>,
) -> Result<(), PdsError> {
    use atproto_identity::plc::Operation;
    let deny = |reason: String| Err(PdsError::InvalidPlcOperation { reason });

    let Operation::PlcOperation {
        rotation_keys,
        verification_methods,
        also_known_as,
        services,
        ..
    } = op
    else {
        // A tombstone is a deliberate act of self-destruction and a legacy
        // create cannot be an update; neither is something to forward on an
        // account's behalf from a migration flow.
        return deny("only a plc_operation may be submitted through this server".to_string());
    };

    if !rotation_keys.iter().any(|k| k == c.rotation_key) {
        return deny(
            "the operation does not list this server's rotation key; submitting it would leave this server unable to manage the identity".to_string(),
        );
    }
    match services.get("atproto_pds") {
        None => return deny("the operation has no atproto_pds service".to_string()),
        Some(svc) if svc.service_type != "AtprotoPersonalDataServer" => {
            return deny(format!(
                "atproto_pds service type is {}, expected AtprotoPersonalDataServer",
                svc.service_type
            ));
        }
        Some(svc) if svc.endpoint != c.service_endpoint => {
            return deny(format!(
                "atproto_pds endpoint is {}, expected {}",
                svc.endpoint, c.service_endpoint
            ));
        }
        Some(_) => {}
    }
    match verification_methods.get("atproto") {
        None => return deny("the operation has no atproto verification method".to_string()),
        Some(vm) if vm != c.signing_key => {
            return deny(format!(
                "atproto verification method is {vm}, expected this account's signing key {}",
                c.signing_key
            ));
        }
        Some(_) => {}
    }
    let expected_aka = format!("at://{}", c.handle);
    if also_known_as.first().map(String::as_str) != Some(expected_aka.as_str()) {
        return deny(format!(
            "alsoKnownAs[0] is {:?}, expected {expected_aka}",
            also_known_as.first()
        ));
    }
    Ok(())
}

/// `POST /xrpc/com.atproto.identity.submitPlcOperation`. Auth-required.
///
/// Validates the operation against this server's constraints (see
/// [`check_plc_submit`]), POSTs it to the configured PLC directory, and
/// emits `#identity` so consumers re-resolve. Requires the PDS to have a
/// `PlcService` configured (i.e., `PDS_DID_PLC_URL` was set).
pub async fn submit_plc_operation(
    State(state): State<HttpState>,
    parts: Parts,
    Json(input): Json<SubmitPlcOperationInput>,
) -> Result<axum::http::StatusCode, XrpcError> {
    // Same authority as signing — submitting is what makes it take effect.
    let did = require_session_or_oauth(&parts, &state, &OAuthScope::IdentityAll).await?;
    let manager = account_manager(&state)?;
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

    let account = state
        .reader
        .accounts()
        .lookup_did(&did)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(StatusCode::NOT_FOUND, "AccountNotFound", "no such account")
        })?;
    let rotation_key_ref = manager
        .lookup_rotation_key_ref(&did)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::PRECONDITION_FAILED,
                "NoRotationKey",
                "this account has no PDS-managed rotation key",
            )
        })?;
    let rotation_did = atproto_identity::key::to_public(
        &manager
            .key_store()
            .get(&rotation_key_ref)
            .await
            .map_err(XrpcError::from)?,
    )
    .map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("derive rotation public key: {e}"),
        )
    })?
    .to_string();
    let signing_did = atproto_identity::key::to_public(
        &manager
            .key_store()
            .get(&account.signing_key_ref)
            .await
            .map_err(XrpcError::from)?,
    )
    .map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("derive signing public key: {e}"),
        )
    })?
    .to_string();

    check_plc_submit(
        &signed,
        &PlcSubmitConstraints {
            rotation_key: &rotation_did,
            service_endpoint: plc.service_endpoint(),
            signing_key: &signing_did,
            handle: &account.handle,
        },
    )
    .map_err(XrpcError::from)?;

    plc.submit_operation(&did, &signed)
        .await
        .map_err(XrpcError::from)?;

    // The DID document just changed. Best-effort, as with the handle path:
    // the operation is already in PLC's append-only log, so failing here
    // would report a completed change as an error.
    if let Err(e) = crate::http::identity_handlers::emit_identity_event(
        &manager.sequencer(),
        &did,
        Some(&account.handle),
    )
    .await
    {
        tracing::error!(did = %did, error = ?e, "failed to sequence #identity after submitPlcOperation");
    }
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

/// Authenticate an endpoint that app-password sessions alone may reach.
///
/// Some account-lifecycle operations are deliberately outside what any OAuth
/// client can do, however broadly scoped — minting app passwords, deleting
/// the account, changing the email address. The reference refuses those with
/// `ForbiddenError('OAuth credentials are not supported for this endpoint')`
/// rather than by scope, and so does this.
///
/// The distinction is worth making in the error: a well-formed OAuth token is
/// not a malformed session token, and reporting it as one sent client authors
/// looking for a bug in their JWT.
/// Refuse an operation that an app-password or OAuth session must not reach.
///
/// App passwords and OAuth grants are given to third parties. These four
/// operations can take over or destroy the identity -- mint further app
/// passwords, begin a PLC signature (identity takeover), begin an account
/// deletion, begin an email change -- so they are reserved to a session the
/// account holder authenticated for directly.
///
/// `400 InvalidToken` matches what the reference answers for the same
/// requests, so a client can tell "wrong kind of credential" from "no
/// credential" without special-casing this implementation.
fn require_full_session(claims: &account::SessionClaims, operation: &str) -> Result<(), XrpcError> {
    if claims.full {
        return Ok(());
    }
    tracing::warn!(
        did = %claims.sub,
        operation,
        "refused a privileged operation from an app-password session"
    );
    Err(XrpcError::new(
        StatusCode::BAD_REQUEST,
        "InvalidToken",
        format!("{operation} requires the account password, not an app password"),
    ))
}

fn require_access_jwt(
    parts: &Parts,
    state: &HttpState,
) -> Result<account::SessionClaims, XrpcError> {
    let (_, raw) = authorization_token(parts)?;

    if let Ok(claims) = session::verify_access(raw, &state.jwt_secret) {
        return Ok(claims);
    }

    // Name the actual situation when the caller presented a perfectly valid
    // OAuth token at an endpoint that does not take one.
    if verify_oauth_jwt(raw, OAUTH_TYP_ACCESS, &state.jwt_secret).is_ok() {
        return Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "OAuth credentials are not supported for this endpoint",
        ));
    }

    session::verify_access(raw, &state.jwt_secret).map_err(XrpcError::from)
}

/// What an OAuth token must carry to reach an endpoint that accepts one.
///
/// App-password sessions carry no scopes and are full-authority, so the
/// policy applies to OAuth tokens only. Spelled out per endpoint rather than
/// inferred, because "which scope does this need" is the question that has to
/// be answered deliberately for each one.
enum OAuthScope {
    /// Any valid OAuth token. The endpoint exposes nothing a client holding
    /// a token should not already be able to see.
    Any,
    /// `account:email?action=manage`.
    AccountEmailManage,
    /// `identity:*`.
    IdentityAll,
}

/// Authenticate an endpoint that accepts an app-password session **or** an
/// OAuth token satisfying `policy`, returning the subject DID.
async fn require_session_or_oauth(
    parts: &Parts,
    state: &HttpState,
    policy: &OAuthScope,
) -> Result<String, XrpcError> {
    let (htm, htu) = request_htm_htu(parts);
    let subject = require_authn(parts, state, &htm, &htu).await?;

    if subject.is_oauth() {
        let scopes = subject.scopes();
        let result = match policy {
            OAuthScope::Any => Ok(()),
            OAuthScope::AccountEmailManage => scopes.assert_account_email_manage(),
            OAuthScope::IdentityAll => scopes.assert_identity_all(),
        };
        result.map_err(|missing| {
            XrpcError::new(
                StatusCode::FORBIDDEN,
                "InsufficientScope",
                format!("this token does not grant {}", missing.scope),
            )
        })?;
    }

    Ok(subject.sub().to_string())
}

#[cfg(test)]
mod plc_tests {
    use super::*;
    use atproto_identity::plc::{Operation, ServiceEndpoint};

    const ROTATION: &str = "did:key:zRotationKeyOfThisServer";
    const SIGNING: &str = "did:key:zSigningKeyOfThisAccount";
    const ENDPOINT: &str = "https://pds.example.test";
    const HANDLE: &str = "alice.example.test";

    fn constraints() -> PlcSubmitConstraints<'static> {
        PlcSubmitConstraints {
            rotation_key: ROTATION,
            service_endpoint: ENDPOINT,
            signing_key: SIGNING,
            handle: HANDLE,
        }
    }

    fn services(endpoint: &str, service_type: &str) -> HashMap<String, ServiceEndpoint> {
        HashMap::from([(
            "atproto_pds".to_string(),
            ServiceEndpoint {
                service_type: service_type.to_string(),
                endpoint: endpoint.to_string(),
            },
        )])
    }

    /// A well-formed operation that satisfies every constraint.
    fn good_op() -> Operation {
        op(
            vec![ROTATION.to_string()],
            HashMap::from([("atproto".to_string(), SIGNING.to_string())]),
            vec![format!("at://{HANDLE}")],
            services(ENDPOINT, "AtprotoPersonalDataServer"),
        )
    }

    /// Build an operation from its four constrained fields.
    fn op(
        rotation_keys: Vec<String>,
        verification_methods: HashMap<String, String>,
        also_known_as: Vec<String>,
        services: HashMap<String, ServiceEndpoint>,
    ) -> Operation {
        Operation::PlcOperation {
            rotation_keys,
            verification_methods,
            also_known_as,
            services,
            prev: Some("bafyprev".to_string()),
            sig: "sig".to_string(),
        }
    }

    fn atproto_vm(key: &str) -> HashMap<String, String> {
        HashMap::from([("atproto".to_string(), key.to_string())])
    }

    fn aka(handle: &str) -> Vec<String> {
        vec![format!("at://{handle}")]
    }

    fn pds_services() -> HashMap<String, ServiceEndpoint> {
        services(ENDPOINT, "AtprotoPersonalDataServer")
    }

    #[test]
    fn a_conformant_operation_is_accepted() {
        // Without this the other five tests would pass against a function
        // that refused everything.
        assert!(check_plc_submit(&good_op(), &constraints()).is_ok());
    }

    #[test]
    fn an_operation_dropping_this_servers_rotation_key_is_refused() {
        // The one that cannot be undone: PLC is append-only, so once this
        // lands the server can no longer manage the identity at all.
        let bad = op(
            vec!["did:key:zSomeoneElse".to_string()],
            atproto_vm(SIGNING),
            aka(HANDLE),
            pds_services(),
        );
        assert!(matches!(
            check_plc_submit(&bad, &constraints()),
            Err(PdsError::InvalidPlcOperation { .. })
        ));
    }

    #[test]
    fn an_operation_pointing_elsewhere_is_refused() {
        // Endpoint belongs to another server — the account would become
        // unreachable here the moment this lands.
        let wrong_endpoint = op(
            vec![ROTATION.to_string()],
            atproto_vm(SIGNING),
            aka(HANDLE),
            services(
                "https://someone-else.example.test",
                "AtprotoPersonalDataServer",
            ),
        );
        assert!(check_plc_submit(&wrong_endpoint, &constraints()).is_err());

        // Right endpoint, wrong service type.
        let wrong_type = op(
            vec![ROTATION.to_string()],
            atproto_vm(SIGNING),
            aka(HANDLE),
            services(ENDPOINT, "SomethingElse"),
        );
        assert!(check_plc_submit(&wrong_type, &constraints()).is_err());

        // No atproto_pds service at all.
        let no_service = op(
            vec![ROTATION.to_string()],
            atproto_vm(SIGNING),
            aka(HANDLE),
            HashMap::new(),
        );
        assert!(check_plc_submit(&no_service, &constraints()).is_err());
    }

    #[test]
    fn an_operation_with_the_wrong_signing_key_is_refused() {
        // Commits signed by this server would stop verifying against the
        // document the moment this lands.
        let bad = op(
            vec![ROTATION.to_string()],
            atproto_vm("did:key:zNotThisAccount"),
            aka(HANDLE),
            pds_services(),
        );
        assert!(check_plc_submit(&bad, &constraints()).is_err());

        let missing = op(
            vec![ROTATION.to_string()],
            HashMap::new(),
            aka(HANDLE),
            pds_services(),
        );
        assert!(check_plc_submit(&missing, &constraints()).is_err());
    }

    #[test]
    fn an_operation_with_a_mismatched_handle_is_refused() {
        let bad = op(
            vec![ROTATION.to_string()],
            atproto_vm(SIGNING),
            aka("someone.else.test"),
            pds_services(),
        );
        assert!(check_plc_submit(&bad, &constraints()).is_err());
    }

    #[test]
    fn a_tombstone_is_not_submittable_through_this_server() {
        let op = Operation::PlcTombstone {
            prev: "bafyprev".to_string(),
            sig: "sig".to_string(),
        };
        assert!(check_plc_submit(&op, &constraints()).is_err());
    }

    // -----------------------------------------------------------------
    //  apply_plc_deltas
    // -----------------------------------------------------------------

    fn last_op() -> Operation {
        good_op()
    }

    #[test]
    fn omitted_fields_are_carried_over_verbatim() {
        use atproto_identity::plc::operations::UnsignedOperation;
        let unsigned = apply_plc_deltas(
            last_op(),
            "bafylast".to_string(),
            &SignPlcOperationInput::default(),
        )
        .unwrap();
        let UnsignedOperation::PlcOperation {
            rotation_keys,
            verification_methods,
            also_known_as,
            services,
            prev,
        } = unsigned
        else {
            unreachable!()
        };
        assert_eq!(rotation_keys, vec![ROTATION.to_string()]);
        assert_eq!(verification_methods["atproto"], SIGNING);
        assert_eq!(also_known_as, vec![format!("at://{HANDLE}")]);
        assert_eq!(services["atproto_pds"].endpoint, ENDPOINT);
        // `prev` comes from the fetched operation's CID, never from input —
        // the caller has no way to know it.
        assert_eq!(prev, Some("bafylast".to_string()));
    }

    #[test]
    fn a_supplied_field_replaces_rather_than_merges() {
        use atproto_identity::plc::operations::UnsignedOperation;
        // Replacement is what makes key removal possible. A union would let
        // a compromised key stay in the list forever.
        let input = SignPlcOperationInput {
            rotation_keys: Some(vec!["did:key:zBrandNew".to_string()]),
            ..Default::default()
        };
        let unsigned = apply_plc_deltas(last_op(), "bafylast".to_string(), &input).unwrap();
        let UnsignedOperation::PlcOperation {
            rotation_keys,
            also_known_as,
            ..
        } = unsigned
        else {
            unreachable!()
        };
        assert_eq!(rotation_keys, vec!["did:key:zBrandNew".to_string()]);
        // Untouched fields still carried over.
        assert_eq!(also_known_as, vec![format!("at://{HANDLE}")]);
    }

    #[test]
    fn a_tombstoned_did_cannot_be_updated() {
        let tombstone = Operation::PlcTombstone {
            prev: "bafyprev".to_string(),
            sig: "sig".to_string(),
        };
        assert!(matches!(
            apply_plc_deltas(
                tombstone,
                "bafylast".to_string(),
                &SignPlcOperationInput::default()
            ),
            Err(PdsError::InvalidPlcOperation { .. })
        ));
    }
}
