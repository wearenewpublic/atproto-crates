//! Authorization endpoint — exchanges a PAR `request_uri` for an
//! authorization code, after authenticating the user.
//!
//! Ships a **JSON-API consent flow** where the resource owner
//! presents identifier+password (an app-password session works too) and the
//! server issues a code. The hand-rolled HTML consent page in `consent.rs`
//! ships friendly per-scope descriptions; the Askama-rendered template form is documented in
//! D-7.

use crate::account::AccountState;
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

    // Read without consuming.
    //
    // This used to `take_par` here, at the top, before the password had been
    // looked at. So a single mistyped password destroyed the pushed request
    // and the retry answered `request_uri unknown or expired` -- the flow was
    // dead and the only way forward was to start again from the client. One
    // typo, and the person is bounced out of an authorization they were in the
    // middle of. It is consumed below, once the outcome is settled.
    let request = state
        .oauth
        .peek_par(&input.request_uri)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request_uri unknown or expired",
            )
        })?;

    // A refusal is a settled outcome, so the request is spent. Previously this
    // returned before the row was even read, which left a declined
    // `request_uri` replayable -- the holder said no and the client could
    // present it again.
    if !input.approve {
        state
            .oauth
            .take_par(&input.request_uri)
            .await
            .map_err(XrpcError::from)?;
        return Err(XrpcError::new(
            StatusCode::FORBIDDEN,
            "access_denied",
            "user declined the authorization request",
        ));
    }

    // Resolve identifier → DID via the accounts directory.
    let directory = state.reader.accounts();
    let account = if input.identifier.starts_with("did:") {
        directory.lookup_did(&input.identifier).await
    } else {
        directory.lookup_handle(&input.identifier).await
    };

    // One refusal for every way a login can fail, and the same work spent
    // reaching it.
    //
    // "no such account" and "invalid identifier or password" were distinct
    // messages, which answers "does this handle exist here" to anyone who asks
    // -- and the account-state check sat ahead of the password check, so an
    // unauthenticated caller could also learn that an account was suspended or
    // taken down. Enumeration is the first step of a credential-stuffing run
    // and there is no reason to assist it.
    let refused = || {
        XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "invalid identifier or password",
        )
    };

    let Some(account) = account.map_err(XrpcError::from)? else {
        crate::account::verify_password_against_decoy(&input.password);
        return Err(refused());
    };

    // The account password, and not an app password.
    //
    // An app password is a credential handed to a third-party tool, which is
    // why `SessionClaims::full` exists and why `createAppPassword`,
    // `signPlcOperation` and `requestAccountDelete` are all reserved to a
    // session the holder authenticated for directly: "the operations that can
    // take over or destroy an identity" are not delegable.
    //
    // Approving an OAuth client mints a third-party credential of whatever
    // scope was asked for -- `transition:generic` among them. That is the same
    // act as minting an app password, reached through a different door, and it
    // accepted an app password to do it. A leaked app password could therefore
    // be exchanged for an OAuth grant, which is the boundary going around
    // itself rather than being broken.
    let auth_ok = manager
        .verify_password(&account.did, &input.password)
        .await
        .map_err(XrpcError::from)?;
    if !auth_ok {
        // An app password presented here is refused as a credential, not
        // named as one: saying "that was an app password" would confirm the
        // account exists and that the string is a live credential for it.
        return Err(refused());
    }

    // Only now, with the credential proved, is the holder entitled to know
    // anything about the account's state.
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

    // Everything has passed, so spend the request. Taking it here rather than
    // earlier also settles the race: two requests arriving together, only one
    // gets `Some`, and only that one issues a code.
    if state
        .oauth
        .take_par(&input.request_uri)
        .await
        .map_err(XrpcError::from)?
        .is_none()
    {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request_uri unknown or expired",
        ));
    }

    // Pin the expansion here, at the moment the holder approves.
    //
    // A permission set lives in the *client's* repository. It used to be
    // resolved twice: once by the consent page to describe it, and again at
    // redemption to decide what the token actually carries. Between those two
    // reads the client could edit its own record, so the grant a token came
    // away with was not required to be the grant the account holder was shown
    // -- and the second read is the one that counted.
    //
    // `permission_set` states the rule this restores: "A grant is what was
    // shown at consent, and it has to stop moving after that." Expanding once,
    // now, is what makes that true. There is no later reader of the
    // unexpanded form: after a code exists the only thing that consults its
    // scope is token issuance, and what that needs is the granted scope.
    let mut request = request;
    request.scope =
        crate::oauth::permission_set::expand(state.lexicon_resolver.as_ref(), &request.scope).await;

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
