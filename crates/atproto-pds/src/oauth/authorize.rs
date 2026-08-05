//! Authorization endpoint — exchanges a PAR `request_uri` for an
//! authorization code, after authenticating the user.
//!
//! Ships a **JSON-API consent flow** where the resource owner
//! presents identifier+password (an app-password session works too) and the
//! server issues a code. The hand-rolled HTML consent page in `consent.rs`
//! ships friendly per-scope descriptions; the Askama-rendered template form is documented in
//! D-7.

use crate::account::{AccountState, app_password};
use crate::http::errors::XrpcError;
use crate::http::state::HttpState;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use rand::RngExt;
use serde::{Deserialize, Serialize};

/// Inputs for `POST /oauth/authorize`.
#[derive(Debug, Deserialize)]
pub struct AuthorizeInput {
    /// PAR-issued `request_uri`.
    pub request_uri: String,
    /// User identifier (handle, DID, or email).
    pub identifier: String,
    /// Password (account or app-password).
    pub password: String,
    /// Whether the user approved the requested scopes.
    pub approve: bool,
}

/// Output of `POST /oauth/authorize`.
#[derive(Debug, Serialize)]
pub struct AuthorizeResponse {
    /// Authorization code to present at `/oauth/token`.
    pub code: String,
    /// Echoed `state` from the original PAR request.
    pub state: String,
    /// Issuer identifier (per RFC 9207 — the `iss` query parameter that
    /// must accompany the redirect).
    pub iss: String,
    /// `redirect_uri` the client should use.
    pub redirect_uri: String,
}

/// Handler for `POST /oauth/authorize`.
pub async fn authorize_handler(
    State(state): State<HttpState>,
    Json(input): Json<AuthorizeInput>,
) -> Result<Json<AuthorizeResponse>, XrpcError> {
    let manager = state.account_manager.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "OAuthUnavailable",
            "OAuth requires the account-manager subsystem",
        )
    })?;

    if !input.approve {
        return Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "access_denied",
            "user declined the authorization request",
        ));
    }

    let request = state
        .oauth
        .take_par(&input.request_uri)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request_uri unknown or expired",
            )
        })?;

    // Resolve identifier → DID via the accounts directory.
    let directory = state.reader.accounts();
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
            "access_denied",
            format!("account is {}", account.state),
        ));
    }

    let auth_ok = if app_password::verify(&manager.account_pool(), &account.did, &input.password)
        .await
        .map_err(XrpcError::from)?
        .is_some()
    {
        true
    } else {
        manager
            .verify_password(&account.did, &input.password)
            .await
            .map_err(XrpcError::from)?
    };
    if !auth_ok {
        return Err(XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "invalid identifier or password",
        ));
    }

    // Same gate as `createSession`. Without it here, a client could route
    // around the policy requirement by asking for an OAuth grant instead of a
    // session -- the two are different doors into the same house.
    if crate::account::policy::acceptance_required(
        &state.reader,
        &account.did,
        state.policy.as_ref(),
    )
    .await
    {
        tracing::info!(did = %account.did, "authorization refused: policy not accepted");
        return Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "access_denied",
            "this account must accept the current policy before authorizing an \
             application; open /account on this server to do so",
        ));
    }

    let code = random_code();
    let response = AuthorizeResponse {
        code: code.clone(),
        state: request.state.clone(),
        iss: format!("https://{}", state.service_did.replace("did:web:", "")),
        redirect_uri: request.redirect_uri.clone(),
    };
    state
        .oauth
        .issue_code(code, account.did, request)
        .await
        .map_err(XrpcError::from)?;
    Ok(Json(response))
}

fn random_code() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}
