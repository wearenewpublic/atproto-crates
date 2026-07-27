//! OAuth login init: resolve the user's PDS authorization server, generate
//! PKCE + state + a per-session DPoP key, persist request state, run PAR, and
//! redirect to the authorization endpoint.

use atproto_identity::key::{KeyType, generate_key};
use atproto_oauth::pkce;
use atproto_oauth::resources::{AuthorizationServer, pds_resources};
use atproto_oauth::workflow::{OAuthClient, OAuthRequestState, oauth_init};
use axum::Form;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{Duration, Utc};
use rand::distr::{Alphanumeric, SampleString};
use serde::Deserialize;

use crate::error::WebError;
use crate::oauth::callback::PersistedOAuthRequest;
use crate::state::WebContext;

/// Form body for `POST /login`.
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    /// A handle, DID, or PDS URL to authenticate against.
    pub handle: String,
}

/// `POST /login` — begin the OAuth authorization-code + PKCE + PAR flow.
pub async fn login(
    State(ctx): State<WebContext>,
    Form(form): Form<LoginForm>,
) -> Result<Response, WebError> {
    if !ctx.config.oauth_enabled() {
        return Err(WebError::BadRequest("OAuth is not configured".to_string()));
    }

    let login_hint = form.handle.trim();
    if login_hint.is_empty() {
        return Err(WebError::BadRequest("handle is required".to_string()));
    }

    // Resolve the login hint to the user's authorization server.
    let (authorization_server, par_login_hint) = resolve_login_hint(&ctx, login_hint).await?;

    // The active signing key (private_key_jwt).
    let signing_key =
        ctx.config.oauth_signing_key().cloned().ok_or_else(|| {
            WebError::Internal(anyhow::anyhow!("no OAuth signing key configured"))
        })?;

    // Per-session DPoP key.
    let dpop_key = generate_key(KeyType::P256Private)
        .map_err(|e| WebError::Internal(anyhow::anyhow!("failed to generate DPoP key: {e}")))?;

    // PKCE + CSRF state + nonce.
    let (pkce_verifier, code_challenge) = pkce::generate();
    let state = Alphanumeric.sample_string(&mut rand::rng(), 32);
    let nonce = Alphanumeric.sample_string(&mut rand::rng(), 32);

    let oauth_client = OAuthClient {
        redirect_uri: ctx.config.oauth_redirect_uri(),
        client_id: ctx.config.oauth_client_id(),
        private_signing_key_data: signing_key,
    };

    let oauth_request_state = OAuthRequestState {
        state: state.clone(),
        nonce: nonce.clone(),
        code_challenge,
        scope: oauth_scope(),
    };

    // Pushed Authorization Request (PAR).
    let par_response = oauth_init(
        &ctx.http_client,
        &oauth_client,
        &dpop_key,
        par_login_hint.as_deref(),
        &authorization_server,
        &oauth_request_state,
    )
    .await
    .map_err(|e| WebError::Internal(anyhow::anyhow!("PAR request failed: {e}")))?;

    // Persist the request so the callback can complete it.
    let now = Utc::now();
    let persisted = PersistedOAuthRequest {
        state: state.clone(),
        issuer: authorization_server.issuer.clone(),
        nonce,
        pkce_verifier,
        dpop_private_key: dpop_key.to_string(),
        login_hint: login_hint.to_string(),
        subject: par_login_hint.clone(),
        created_at: now,
        expires_at: now + Duration::minutes(10),
    };
    persist_oauth_request(&ctx, &persisted).await?;

    // Redirect to the authorization endpoint with the PAR `request_uri`.
    let authorize_url = format!(
        "{}?client_id={}&request_uri={}",
        authorization_server.authorization_endpoint,
        urlencoding::encode(&oauth_client.client_id),
        urlencoding::encode(&par_response.request_uri),
    );

    Ok(Redirect::to(&authorize_url).into_response())
}

/// The full OAuth scope string requested by this client.
fn oauth_scope() -> String {
    "atproto transition:generic".to_string()
}

/// Resolve a login hint (handle/DID/URL) into an authorization server.
///
/// Returns the authorization server metadata and an optional login hint to pass
/// to PAR. The hint may be a handle, a DID, or a PDS URL; handles/DIDs are
/// resolved via the identity resolver to a DID document whose
/// `AtprotoPersonalDataServer` endpoint hosts the OAuth resources.
pub async fn resolve_login_hint(
    ctx: &WebContext,
    login_hint: &str,
) -> Result<(AuthorizationServer, Option<String>), WebError> {
    // Accept `at://`/`@` decorated handles.
    let subject = login_hint
        .trim()
        .trim_start_matches("at://")
        .trim_start_matches('@');

    // A bare PDS URL can be used directly; otherwise resolve the identity.
    let (pds_endpoint, par_hint) = if subject.starts_with("https://") {
        (subject.to_string(), None)
    } else {
        let document = ctx
            .identity_resolver
            .resolve(subject)
            .await
            .map_err(|e| WebError::BadRequest(format!("could not resolve '{subject}': {e}")))?;
        let pds = document
            .pds_endpoints()
            .first()
            .map(|s| s.to_string())
            .ok_or_else(|| WebError::BadRequest(format!("no PDS endpoint for '{subject}'")))?;
        (pds, Some(document.id.clone()))
    };

    let (_protected_resource, authorization_server) =
        pds_resources(&ctx.http_client, &pds_endpoint)
            .await
            .map_err(|e| WebError::BadRequest(format!("OAuth resource discovery failed: {e}")))?;

    Ok((authorization_server, par_hint))
}

/// Persist an OAuth request row keyed by `state` (single-use, TTL-bounded).
async fn persist_oauth_request(
    ctx: &WebContext,
    request: &PersistedOAuthRequest,
) -> Result<(), WebError> {
    let data = serde_json::to_string(request)?;
    let expires_at = request.expires_at.to_rfc3339();
    sqlx::query("INSERT OR REPLACE INTO oauth_request (state, data, expires_at) VALUES (?, ?, ?)")
        .bind(&request.state)
        .bind(&data)
        .bind(&expires_at)
        .execute(&ctx.pool)
        .await?;
    Ok(())
}
