//! Delegated sign-in: authenticating somebody else so they can act as an
//! account here.
//!
//! # The inversion
//!
//! Everywhere else in this crate, OAuth runs one way: an application asks, and
//! this server decides. For the length of one delegated sign-in it runs the
//! other way too. This server becomes an OAuth *client* — pushing an
//! authorization request at a stranger's authorization server, proving itself
//! with a signed client assertion, and redeeming a code for a token it does
//! not want.
//!
//! It does not want the token because it is not after access. A delegate's
//! repository is none of this server's business; the only thing the exchange
//! establishes is *who they are*, which is why the scope requested is bare
//! `atproto` and why the access token is dropped the moment its `sub` has been
//! read. What survives the round trip is one DID.
//!
//! # The shape of a flow
//!
//! 1. A client pushes an authorization request and sends the person to
//!    `/oauth/authorize`. The consent page offers "sign in as a delegate" when
//!    the client named who is signing in ([`crate::oauth::consent`]).
//! 2. [`start_page`] shows what the client is asking for and takes one thing:
//!    the delegate's own handle.
//! 3. [`begin`] resolves that handle, discovers the delegate's authorization
//!    server, pushes a request at it, moves the original authorization request
//!    out of `oauth_par` and into [`crate::oauth::delegation_login`], and
//!    redirects.
//! 4. The delegate signs in on their own server, as themselves.
//! 5. [`callback`] redeems the code, learns the delegate's DID, checks it
//!    against the account's delegation list, and issues the authorization code
//!    the *client* has been waiting for — for the core account, marked with who
//!    obtained it.
//!
//! # What is checked, and when
//!
//! The delegation list is consulted in [`callback`] and nowhere earlier. The
//! handle-entry page is reachable by anyone holding a `request_uri`, so
//! refusing an unlisted handle there would answer "is X a delegate of Y" for
//! whoever asks. The cost is a wasted round trip for someone who was never
//! delegated; the alternative is an oracle.
//!
//! For the same reason every failure after the redirect — not a delegate, flow
//! expired, account suspended, token exchange refused — comes back as one
//! `access_denied` to the client. The log says which; the caller does not. And
//! for the same reason again, [`begin`] resolves the delegate's handle *and*
//! looks up the account being acted for before deciding anything, so which of
//! the two was missing cannot be read off the answer.
//!
//! # This server as a client of strangers
//!
//! Two of the URLs in a delegated sign-in are chosen by whoever controls the
//! identity being authenticated: the PDS endpoint in their DID document, and
//! the authorization server that endpoint points at. Fetching an
//! attacker-nominated URL is server-side request forgery, and it is guarded in
//! two places that are both necessary. [`resolve_identity`] takes the endpoint
//! through `pds_endpoints_validated`, which refuses anything that is not HTTPS
//! on a public name at the default port; [`peer_client`] refuses to follow
//! redirects, without which that validation lasts exactly one hop.
//!
//! # One browser, one flow
//!
//! [`begin`] sets a cookie and stores its hash beside the parked sign-in;
//! [`callback`] requires it back. Everything else the callback carries has
//! passed through the delegate's own server and is therefore known to it, so
//! the cookie is the only part of the flow an onlooker cannot reproduce. See
//! the check in [`callback`] for the attack this closes.

use crate::account::AccountState;
use crate::account::delegation;
use crate::errors::PdsError;
use crate::http::errors::XrpcError;
use crate::http::state::{DelegationConfig, HttpState};
use crate::oauth::consent::{html_escape, prefill_identifier, render_scope_list, urlencode};
use crate::oauth::delegation_login::{ParkedLogin, binding_id, park, take};
use atproto_identity::key::{KeyType, generate_key, identify_key};
use atproto_oauth::resources::{AuthorizationServer, oauth_authorization_server, pds_resources};
use atproto_oauth::workflow::{
    OAuthClient, OAuthRequest as WorkflowRequest, OAuthRequestState, oauth_complete, oauth_init,
};
use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{Html, IntoResponse, Response};
use rand::RngExt;
use serde::{Deserialize, Serialize};

/// Scope this server asks a delegate's authorization server for.
///
/// The AT Protocol base scope and nothing else. A delegated sign-in proves an
/// identity; it is not a reason for this server to hold a grant on somebody
/// else's repository, and asking for one would put a permission on the
/// delegate's consent screen that nothing here would ever use.
const DELEGATE_SCOPE: &str = "atproto";

/// How long this server waits on a delegate's server, per request.
///
/// Every call under this module is a fetch of somebody else's metadata or
/// token endpoint, made while a person watches a blank page. Ten seconds is
/// long enough for a slow but working server and short enough that a dead one
/// produces an answer rather than a hang.
const PEER_TIMEOUT_SECS: u64 = 10;

/// Name of the cookie binding a delegated sign-in to one browser.
const BINDING_COOKIE: &str = "atproto_pds_delegation";

/// A `Set-Cookie` binding the flow about to start to this browser.
///
/// `SameSite=Lax`, and the choice is load-bearing rather than a default. The
/// cookie has to survive exactly one journey: a top-level GET navigation back
/// from the delegate's authorization server, which is a different site.
/// `Strict` would withhold it on precisely that request and refuse every
/// legitimate sign-in; `None` would send it on subresource requests from
/// anywhere, which is more reach than this needs.
///
/// `Path` is the delegation subtree, so it does not accompany requests that
/// have no use for it. `Secure` unconditionally: delegation is refused outright
/// on a non-HTTPS origin ([`crate::http::state::DelegationStatus::resolve`]),
/// so there is no development case to accommodate.
///
/// `Max-Age` matches [`crate::oauth::delegation_login::LOGIN_TTL_SECS`]; a
/// cookie outliving the row it refers to is only a thing to clean up later.
fn set_binding_cookie(response: Response, value: &str) -> Response {
    let cookie = format!(
        "{BINDING_COOKIE}={value}; Path=/oauth/delegation; Max-Age={}; \
         HttpOnly; Secure; SameSite=Lax",
        crate::oauth::delegation_login::LOGIN_TTL_SECS
    );
    with_cookie(response, &cookie)
}

/// Expire the binding cookie, whichever way the flow ended.
///
/// The row is gone by this point and the cookie refers to nothing. Leaving it
/// would mean a stale credential riding along with every later request to this
/// subtree for ten minutes, which is ten minutes of nothing useful.
fn clear_binding(response: Response) -> Response {
    with_cookie(
        response,
        &format!(
            "{BINDING_COOKIE}=; Path=/oauth/delegation; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
        ),
    )
}

/// Append a `Set-Cookie` header, dropping it if it cannot be encoded.
///
/// Every value passed here is built from a hex string and constants, so the
/// encode cannot fail; it is written as a `match` rather than an `unwrap` so a
/// future caller with an unexpected value gets a logged omission instead of a
/// panic in the middle of an authorization.
fn with_cookie(mut response: Response, cookie: &str) -> Response {
    match axum::http::HeaderValue::from_str(cookie) {
        Ok(value) => {
            response
                .headers_mut()
                .append(axum::http::header::SET_COOKIE, value);
        }
        Err(e) => {
            tracing::error!(error = ?e, "could not encode the delegation binding cookie");
        }
    }
    response
}

/// Read the binding cookie out of a request.
fn binding_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find(|(name, _)| *name == BINDING_COOKIE)
        .map(|(_, value)| value.to_string())
}

// ---------------------------------------------------------------------------
//  Client metadata
// ---------------------------------------------------------------------------

/// This server's OAuth client metadata document, as a peer reads it.
///
/// The AT Protocol client-id metadata document
/// (<https://atproto.com/specs/oauth#clients>). `client_id` is the URL this is
/// served from and must equal it exactly, which is why it is built from the
/// same [`DelegationConfig`] the flow uses rather than restated here.
#[derive(Debug, Serialize)]
pub struct DelegationClientMetadata {
    /// The URL this document is served from.
    pub client_id: String,
    /// `web`: this server redirects a browser, it is not a native app.
    pub application_type: &'static str,
    /// Shown on the delegate's own consent screen.
    pub client_name: String,
    /// Where a curious delegate can find out what is asking.
    pub client_uri: String,
    /// The single callback this server accepts.
    pub redirect_uris: Vec<String>,
    /// Only the authorization-code grant. This server never refreshes a
    /// delegate's token — it discards the first one it is given.
    pub grant_types: Vec<&'static str>,
    /// Only `code`.
    pub response_types: Vec<&'static str>,
    /// [`DELEGATE_SCOPE`].
    pub scope: &'static str,
    /// Confidential: this server holds a key and signs an assertion with it.
    pub token_endpoint_auth_method: &'static str,
    /// `ES256`, which is why delegation requires a P-256 service key.
    pub token_endpoint_auth_signing_alg: &'static str,
    /// Required of every AT Protocol client.
    pub dpop_bound_access_tokens: bool,
    /// `/oauth/delegation/jwks.json`, and deliberately *not* `/oauth/jwks`.
    ///
    /// Both publish the same key. They disagree about what to call it: the
    /// provider set names keys by RFC 7638 thumbprint, and the client
    /// assertion this server signs names its key by `did:key`, because that is
    /// what `atproto_oauth`'s header builder puts in `kid`. Pointing a peer at
    /// the provider set made it look for a `kid` that set does not contain,
    /// and every pushed request came back `invalid_client`.
    pub jwks_uri: String,
}

/// `GET /oauth/delegation/jwks.json`.
///
/// The public half of the key this server signs client assertions with, named
/// the way those assertions name it.
///
/// This exists because the same key wears two hats. As an authorization
/// *server* the PDS publishes `/oauth/jwks`, where `kid` is a JWK thumbprint;
/// as an OAuth *client* against a delegate's server it signs an assertion
/// whose `kid` is the key's `did:key` form. A peer resolves the assertion's
/// `kid` against whatever `jwks_uri` names, so the two have to agree, and the
/// convention that has to win here is the client one -- it is the assertion
/// that is being verified. Changing `/oauth/jwks` instead would break anyone
/// pinning the thumbprint, and changing the shared header builder would change
/// behaviour for every other consumer of `atproto-oauth`.
///
/// Only the current signer is published. Historical rotations belong in the
/// provider set, where they let a consumer verify a token issued before a
/// rotation; here they would only widen what a peer accepts, since an
/// assertion is signed fresh with the current key every time.
pub async fn jwks(State(state): State<HttpState>) -> Result<Json<serde_json::Value>, XrpcError> {
    // Behind the same gate as the metadata document: a client that this server
    // will not act as should not publish keys for it.
    let _ = require_delegation(&state)?;

    let Some(signing_key) = state.pds_signing_key.as_deref() else {
        return Err(PdsError::DelegationUnavailable {
            reason: "this server has no signing key".to_string(),
        }
        .into());
    };

    let public = atproto_identity::key::to_public(signing_key).map_err(|error| {
        tracing::error!(error = ?error, "delegation JWKS: could not derive the public key");
        PdsError::DelegationUnavailable {
            reason: "this server's signing key could not be published".to_string(),
        }
    })?;
    let jwk = atproto_oauth::jwk::generate(&public).map_err(|error| {
        tracing::error!(error = ?error, "delegation JWKS: could not build the JWK");
        PdsError::DelegationUnavailable {
            reason: "this server's signing key could not be published".to_string(),
        }
    })?;

    Ok(Json(serde_json::json!({ "keys": [jwk] })))
}

/// `GET /oauth/delegation/client-metadata.json`.
///
/// Served whether or not delegation is enabled — but with contents that say
/// so. A 404 here would be read by a peer as "this client does not exist",
/// which is indistinguishable from a misconfiguration; a document naming a
/// `client_id` this server will not act as is at least honest. When delegation
/// is off there is no configuration to build one from, so this answers 404
/// after all, and the log line is what an operator debugging it needs.
pub async fn client_metadata(
    State(state): State<HttpState>,
) -> Result<Json<DelegationClientMetadata>, XrpcError> {
    let config = require_delegation(&state)?;
    Ok(Json(DelegationClientMetadata {
        client_id: config.client_id.clone(),
        application_type: "web",
        client_name: config.client_name.clone(),
        client_uri: config.client_uri.clone(),
        redirect_uris: vec![config.redirect_uri.clone()],
        grant_types: vec!["authorization_code"],
        response_types: vec!["code"],
        scope: DELEGATE_SCOPE,
        token_endpoint_auth_method: "private_key_jwt",
        token_endpoint_auth_signing_alg: "ES256",
        dpop_bound_access_tokens: true,
        jwks_uri: config.jwks_uri.clone(),
    }))
}

/// The delegation configuration, or the refusal that names what is missing.
fn require_delegation(state: &HttpState) -> Result<&DelegationConfig, XrpcError> {
    match state.delegation.config() {
        Some(config) => Ok(config),
        None => {
            let reason = match &state.delegation {
                crate::http::state::DelegationStatus::Unavailable(why) => why.explain(),
                crate::http::state::DelegationStatus::Available(_) => unreachable!(),
            };
            tracing::info!(reason, "a delegation request arrived but delegation is off");
            Err(PdsError::DelegationUnavailable {
                reason: reason.to_string(),
            }
            .into())
        }
    }
}

// ---------------------------------------------------------------------------
//  Step 2 — the handle-entry page
// ---------------------------------------------------------------------------

/// Query for the delegate handle-entry page.
#[derive(Debug, Deserialize)]
pub struct StartQuery {
    /// The pending authorization this sign-in would complete.
    pub request_uri: String,
}

/// `GET /oauth/delegation/start` — asks the delegate for their own handle.
///
/// Guarded exactly as the consent page is: a real browser navigation, and a
/// `request_uri` that names a live authorization request. It does **not**
/// consume that request — nothing is spent until [`begin`] has everything it
/// needs.
pub async fn start_page(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<StartQuery>,
) -> Result<Response, XrpcError> {
    crate::oauth::consent::require_browser_navigation(&parts)?;
    let _ = require_delegation(&state)?;

    let request = state
        .oauth
        .peek_par(&q.request_uri)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request_uri unknown or expired",
            )
        })?;

    // Without a hint there is no account to act for. The consent page only
    // offers the link when one is present, so arriving here without one means
    // the URL was typed or the request has a different shape than the page
    // that linked it.
    let Some(core_hint) = prefill_identifier(request.login_hint.as_deref()) else {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "this authorization request does not name an account to act for, \
             so it cannot be completed by a delegate",
        ));
    };

    let scopes_list = render_scope_list(&state, &request.scope).await;
    Ok(start_response(render_start(
        &q.request_uri,
        &request.client_id,
        &core_hint,
        &scopes_list,
        None,
    )))
}

/// Serve the handle-entry page, however it was reached.
///
/// One constructor because there are two ways to arrive at this page -- a fresh
/// [`start_page`], and [`begin`] re-rendering it with a refusal -- and both
/// carry the same content: an account, a client, and a pending grant. The
/// second was reachable without these headers, so a copy of somebody's
/// in-progress sign-in could be served from a shared cache or replayed out of
/// history to whoever came next.
///
/// `Pragma` alongside `Cache-Control` for HTTP/1.0 intermediaries, matching
/// what the consent page sends.
fn start_response(html: String) -> Response {
    let mut response = Html(html).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        axum::http::header::PRAGMA,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    // Set here rather than left to the middleware, which only fills in a
    // policy a handler did not choose. This page's form ends up at the
    // delegate's authorization server, and the default `form-action 'self'`
    // stops the browser following the redirect that takes it there. See
    // `DELEGATION_START_CSP`.
    response.headers_mut().insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(crate::http::security_headers::DELEGATION_START_CSP),
    );
    response
}

/// The handle-entry page.
///
/// Deliberately in the consent page's clothes and not the portal's: it is the
/// same errand, mid-flight, and a person who has just been shown a list of
/// scopes on one design should not appear to have been handed to a different
/// site to finish.
fn render_start(
    request_uri: &str,
    client_id: &str,
    core_hint: &str,
    scopes_list: &str,
    error: Option<&str>,
) -> String {
    let banner = error
        .map(|message| format!(r#"<div class="err">{}</div>"#, html_escape(message)))
        .unwrap_or_default();

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>atproto-pds — sign in as a delegate</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
      max-width: 520px; margin: 4em auto; padding: 0 1em;
      color: #1a1a1a; background: #fafafa;
    }}
    h1 {{ font-size: 1.3em; font-weight: 600; }}
    fieldset {{ border: 1px solid #ddd; border-radius: 6px; padding: 1em 1.2em; }}
    legend {{ padding: 0 0.5em; font-weight: 600; font-size: 0.9em; color: #555; }}
    label {{ display: block; margin: 0.7em 0 0.2em; font-size: 0.9em; }}
    input[type=text] {{
      width: 100%; padding: 0.5em; border: 1px solid #ccc; border-radius: 4px;
      font-size: 1em; box-sizing: border-box;
    }}
    .scopes {{ background: #f0f0f0; padding: 0.6em 0.8em; border-radius: 4px;
              font-size: 0.9em; margin: 1em 0; }}
    .scopes ul {{ margin: 0.3em 0 0 1.2em; padding: 0; }}
    .scopes li {{ margin-bottom: 0.4em; }}
    .scope-desc {{ color: #555; font-size: 0.85em; margin-left: 0.2em; }}
    .err {{ background: #fff4f4; border: 1px solid #e0b4b4; color: #7a1f1f;
           border-radius: 6px; padding: 0.8em 1em; margin: 1em 0; font-size: 0.9em; }}
    button {{
      padding: 0.6em 1.2em; border: 0; border-radius: 4px; background: #2563eb;
      color: white; font-size: 1em; cursor: pointer; margin-top: 1em;
    }}
    code {{ font-family: ui-monospace, "SFMono-Regular", Menlo, monospace; font-size: 0.9em; }}
    .meta {{ font-size: 0.8em; color: #777; margin-top: 1.5em; }}
    .back {{ font-size: 0.9em; margin-top: 1.2em; }}
  </style>
</head>
<body>
  <h1>Sign in as a delegate</h1>
  <p>You are about to authorize <code>{client_id_safe}</code> to act on the
  account <b>{core_safe}</b>, by proving your own identity rather than that
  account's password.</p>

  {banner}

  <div class="scopes">
    <code>{client_id_safe}</code> is asking for:
    <ul>{scopes_list}</ul>
  </div>

  <form method="POST" action="/oauth/delegation/begin">
    <fieldset>
      <legend>Your identity</legend>
      <label for="handle">Your handle</label>
      <input id="handle" name="handle" type="text" autocomplete="username"
             placeholder="you.example.com" required autofocus>
      <input type="hidden" name="request_uri" value="{request_uri_safe}">
    </fieldset>
    <button type="submit">Continue to your server</button>
  </form>

  <p class="back"><a href="/oauth/authorize?request_uri={request_uri_query}">Sign in as
  <b>{core_safe}</b> instead</a></p>

  <p class="meta">
    You will be sent to your own server to sign in. This server asks it for
    nothing except confirmation of who you are; it receives no access to your
    own repository. It will only proceed if <b>{core_safe}</b> has named you as
    a delegate.
  </p>
</body>
</html>
"#,
        client_id_safe = html_escape(client_id),
        core_safe = html_escape(core_hint),
        request_uri_safe = html_escape(request_uri),
        request_uri_query = urlencode(request_uri),
    )
}

// ---------------------------------------------------------------------------
//  Step 3 — begin the delegate's own OAuth
// ---------------------------------------------------------------------------

/// Form body for [`begin`].
#[derive(Debug, Deserialize)]
pub struct BeginForm {
    /// The pending authorization this sign-in completes.
    pub request_uri: String,
    /// The delegate's own handle.
    pub handle: String,
}

/// `POST /oauth/delegation/begin` — send the delegate to their own server.
///
/// # Ordering
///
/// The pending authorization request is consumed *last*, immediately before
/// the redirect and after every resolution has succeeded. Two things depend on
/// that. It has a sixty-second TTL and the round trip takes minutes, so it
/// cannot be left where it is; and consuming it earlier would destroy the
/// authorization on any failure here, leaving the person with a dead flow and
/// nothing to retry — the same trap `authorize_handler` documents at length.
///
/// Consuming it also settles the race: `take_par` succeeds once, so two
/// submissions of this form start one delegated sign-in.
pub async fn begin(
    State(state): State<HttpState>,
    parts: Parts,
    axum::Form(form): axum::Form<BeginForm>,
) -> Result<Response, XrpcError> {
    let config = require_delegation(&state)?.clone();
    crate::http::portal::require_same_origin(&parts.headers)?;

    let request = state
        .oauth
        .peek_par(&form.request_uri)
        .await
        .map_err(XrpcError::from)?
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request_uri unknown or expired",
            )
        })?;

    // One page to send every refusal back to, with the same fields still on
    // screen. A failure here is nearly always a typo in a handle, and bouncing
    // to a bare error page would mean starting again from the application.
    let refuse = |message: &str, scopes_list: &str| {
        start_response(render_start(
            &form.request_uri,
            &request.client_id,
            prefill_identifier(request.login_hint.as_deref())
                .as_deref()
                .unwrap_or("this account"),
            scopes_list,
            Some(message),
        ))
    };

    let Some(core_hint) = prefill_identifier(request.login_hint.as_deref()) else {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "this authorization request does not name an account to act for",
        ));
    };

    let typed = form.handle.trim();
    if typed.is_empty() {
        let scopes_list = render_scope_list(&state, &request.scope).await;
        return Ok(refuse("Enter your handle to continue.", &scopes_list));
    }

    // One refusal for every way this can fail before the redirect, and the same
    // work spent reaching it.
    //
    // The account being acted for comes from a `login_hint` the *client* chose,
    // so whether it names an account here is not the caller's to learn. When
    // that check ran first and had a message of its own, an unauthenticated
    // caller could ask "does this handle exist on this server" by pushing an
    // authorization request per guess and reading which of two strings came
    // back. `authorize_handler` spends a decoy password verification avoiding
    // exactly this; the cost here is a handle resolution that was going to
    // happen anyway, now performed before the answer can depend on it.
    let cannot_start = "This sign-in could not be started. Check the handle you \
                        typed, or go back and sign in with the account's own password.";

    // Resolve the delegate first. This says nothing about whether they are a
    // delegate -- only whether the name they typed is a real identity.
    let delegate = match resolve_identity(&state, typed).await {
        Ok(found) => Some(found),
        Err(error) => {
            tracing::debug!(error = ?error, "a delegate handle did not resolve");
            None
        }
    };
    let core = lookup_local_account(&state, &core_hint).await?;

    let (Some(delegate), Some(core)) = (delegate, core) else {
        tracing::debug!("a delegated sign-in could not be started");
        let scopes_list = render_scope_list(&state, &request.scope).await;
        return Ok(refuse(cannot_start, &scopes_list));
    };

    // A self-delegation can never be on the list -- `add_delegate` refuses to
    // write one -- and saying so plainly is better than a round trip that ends
    // in a generic refusal. It reveals nothing: the account being acted for is
    // already named on this page.
    if delegate.did == core.did {
        let scopes_list = render_scope_list(&state, &request.scope).await;
        return Ok(refuse(
            "That is the account you are signing in to. Go back and use its own password.",
            &scopes_list,
        ));
    }

    let signing_key = state.pds_signing_key.clone().ok_or_else(|| {
        // Unreachable: `DelegationStatus::resolve` refuses to produce a
        // configuration without one. Stated rather than unwrapped so a future
        // change to that resolution cannot turn into a panic here.
        PdsError::DelegationUnavailable {
            reason: "this server has no signing key".to_string(),
        }
    })?;

    let http_client = peer_client()?;
    let (_, auth_server) = pds_resources(&http_client, &delegate.pds_url)
        .await
        .map_err(|e| {
            // The DID, not the handle. `typed` is a form field on an
            // unauthenticated endpoint, and `%` renders it verbatim -- the fmt
            // layer does not escape newlines in a field value, so a handle
            // containing one forges log lines. It also writes an arbitrary
            // caller's chosen string into this server's log, which is the
            // defect `tests/log_hygiene.rs` exists for.
            //
            // The DID and the endpoint are safe to name: both come back from
            // resolution, so they are shapes this server established rather
            // than text the caller supplied.
            tracing::info!(
                delegate_did = %delegate.did,
                pds = %delegate.pds_url,
                error = ?e,
                "a delegate's server did not advertise usable OAuth metadata"
            );
            PdsError::DelegationUnresolvable {
                handle: typed.to_string(),
            }
        })?;

    let (pkce_verifier, code_challenge) = atproto_oauth::pkce::generate();
    let oauth_state = random_hex();
    let nonce = random_hex();
    let dpop_key = generate_key(KeyType::P256Private).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("generate DPoP key: {e}"),
        )
    })?;

    let oauth_client = OAuthClient {
        redirect_uri: config.redirect_uri.clone(),
        client_id: config.client_id.clone(),
        private_signing_key_data: (*signing_key).clone(),
    };
    let request_state = OAuthRequestState {
        state: oauth_state.clone(),
        nonce: nonce.clone(),
        code_challenge,
        scope: DELEGATE_SCOPE.to_string(),
    };

    let par = oauth_init(
        &http_client,
        &oauth_client,
        &dpop_key,
        Some(&delegate.handle),
        &auth_server,
        &request_state,
    )
    .await
    .map_err(|e| {
        tracing::warn!(
            delegate_did = %delegate.did,
            issuer = %auth_server.issuer,
            error = ?e,
            "a delegate's authorization server refused this server's pushed request"
        );
        PdsError::DelegationUnresolvable {
            handle: typed.to_string(),
        }
    })?;

    // Everything has succeeded, so the authorization request moves out of
    // `oauth_par` and into the parked sign-in. From here the only thing that
    // can complete it is the callback.
    //
    // # Park first, spend second
    //
    // These two steps live in different stores -- `oauth_par` behind
    // `OAuthState`, which may be in memory, and `delegation_login` in the
    // accounts pool -- so there is no transaction that covers both, and one of
    // the two orders has to lose. Written the other way round the loss was the
    // expensive one: the request was consumed, `park` was the next fallible
    // thing, and a write failure left a person holding a dead authorization, a
    // 500, and nothing to retry.
    //
    // This way a `park` failure leaves `oauth_par` untouched and the flow
    // retryable, and a lost race on `take_par` leaves a parked row that is
    // cleaned up below. The parked row is not a way in on its own: its `state`
    // never reached the caller, and the binding cookie is only set on the
    // redirect that this path does not reach.
    let pool = state.reader.accounts().account_pool();

    // What ties the rest of this flow to the browser in front of us. Only its
    // hash is stored; the value goes out as a cookie and comes back on the
    // callback, and nothing else can produce it.
    let binding = random_hex();
    park(
        &pool,
        &oauth_state,
        &ParkedLogin {
            core_did: core.did.clone(),
            delegate_did: delegate.did.clone(),
            issuer: auth_server.issuer.clone(),
            token_endpoint: auth_server.token_endpoint.clone(),
            request,
            nonce,
            pkce_verifier,
            dpop_private_key: dpop_key.to_string(),
            browser_binding: crate::oauth::delegation_login::binding_id(&binding),
        },
    )
    .await
    .map_err(XrpcError::from)?;

    // `take_par` succeeds exactly once, so this is still what settles two
    // submissions of the same form racing each other: the loser withdraws the
    // row it just parked rather than leaving a private DPoP key to sit out its
    // ten minutes.
    if state
        .oauth
        .take_par(&form.request_uri)
        .await
        .map_err(XrpcError::from)?
        .is_none()
    {
        if let Err(error) = take(&pool, &oauth_state).await {
            tracing::warn!(error = ?error, "could not withdraw a parked sign-in that lost its race");
        }
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request_uri unknown or expired",
        ));
    }

    tracing::info!(
        core_did = %core.did,
        delegate_did = %delegate.did,
        issuer = %auth_server.issuer,
        "a delegated sign-in has begun"
    );

    let mut authorization_url =
        url::Url::parse(&auth_server.authorization_endpoint).map_err(|e| {
            XrpcError::new(
                StatusCode::BAD_GATEWAY,
                "InvalidRequest",
                format!("a delegate's authorization endpoint is not a URL: {e}"),
            )
        })?;
    authorization_url
        .query_pairs_mut()
        .append_pair("client_id", &config.client_id)
        .append_pair("request_uri", &par.request_uri);
    Ok(set_binding_cookie(
        see_other(authorization_url.as_str()),
        &binding,
    ))
}

// ---------------------------------------------------------------------------
//  Step 5 — the delegate comes back
// ---------------------------------------------------------------------------

/// Query for the callback, covering both outcomes an authorization server may
/// redirect with.
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    /// The `state` this server sent, and the only key to the parked flow.
    pub state: String,
    /// Authorization code, on success.
    #[serde(default)]
    pub code: Option<String>,
    /// Issuer identifier (RFC 9207), on success.
    #[serde(default)]
    pub iss: Option<String>,
    /// OAuth error code, when the delegate declined or their server refused.
    #[serde(default)]
    pub error: Option<String>,
}

/// `GET /oauth/delegation/callback` — finish, and hand the client its code.
///
/// Every refusal past this point goes back to the *client's* redirect URI as
/// `access_denied`, not to an error page here. The person is mid-flow in an
/// application, and the application is the only thing that can offer them
/// another way in; leaving them on this server with a message would strand
/// them.
pub async fn callback(
    State(state): State<HttpState>,
    headers: axum::http::HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Result<Response, XrpcError> {
    let config = require_delegation(&state)?.clone();
    let pool = state.reader.accounts().account_pool();

    // Single-use: the row is gone whether or not what follows succeeds, so a
    // replayed callback finds nothing.
    let Some(parked) = take(&pool, &q.state).await.map_err(XrpcError::from)? else {
        return Err(PdsError::DelegationFlowLost {
            reason: "no parked sign-in for this state".to_string(),
        }
        .into());
    };

    let origin = state.origin();
    let deny = |reason: &str| -> Response {
        tracing::warn!(
            core_did = %parked.core_did,
            delegate_did = %parked.delegate_did,
            reason,
            "a delegated sign-in was refused"
        );
        // One `access_denied` for every way this can fail -- not a delegate,
        // flow expired, account suspended, exchange refused. The log says
        // which; the client is told only that it did not happen.
        let refused = redirect_with(
            &parked.request.redirect_uri,
            &[
                ("error", "access_denied"),
                (
                    "error_description",
                    "this account could not be authorized by that identity",
                ),
                ("state", &parked.request.state),
                ("iss", &origin),
            ],
        );
        match refused {
            Some(location) => clear_binding(see_other(&location)),
            None => XrpcError::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "this delegated sign-in cannot be completed",
            )
            .into_response(),
        }
    };

    // Before anything else: is this the browser that started the sign-in?
    //
    // Everything the callback carries -- `state`, `code`, `iss` -- travels
    // through the delegate's authorization server, so it is in that server's
    // logs and in a URL it chose to redirect to. Without this check, whoever
    // holds those values completes the flow, and the flow ends in an
    // authorization code for an account the holder does not own.
    //
    // The attack it closes is a phishing one, and it does not need anything
    // subtle: begin a delegated sign-in for the account you want, name a real
    // delegate of it, and mail that delegate the authorization URL. They sign
    // in on their *own* server, where the consent screen says only that this
    // PDS wants scope `atproto` -- it cannot name the account being acted for,
    // or the application that will receive the grant, because it does not know
    // either. The page that *does* name both is the handle-entry form, and
    // this cookie is what makes reaching it non-optional.
    let presented = binding_cookie(&headers).map(|value| binding_id(&value));
    if presented.as_deref() != Some(parked.browser_binding.as_str()) {
        return Ok(deny(
            "the callback did not come from the browser that began this sign-in",
        ));
    }

    // The delegate said no on their own server, or it refused them.
    //
    // The code the peer sent is recorded as its own field rather than
    // interpolated into the reason. `deny` renders the reason with `%`, and a
    // remote server choosing the text that lands in this server's log --
    // newlines included -- is the same log-forgery primitive an unauthenticated
    // form field would be.
    if let Some(error) = q.error.as_deref() {
        tracing::info!(peer_error = ?error, "a delegate's server refused the sign-in");
        return Ok(deny("the delegate's server returned an error"));
    }
    let Some(code) = q.code.as_deref() else {
        return Ok(deny("callback carried neither a code nor an error"));
    };

    // RFC 9207: the issuer that answers must be the one the flow was begun
    // with. Without this a mix-up attack can substitute a different server's
    // response for the one expected.
    if q.iss.as_deref() != Some(parked.issuer.as_str()) {
        return Ok(deny(
            "callback issuer does not match the one the flow began with",
        ));
    }

    let http_client = peer_client()?;
    let Ok(auth_server) = fetch_auth_server(&http_client, &parked).await else {
        return Ok(deny(
            "could not re-read the delegate's authorization server metadata",
        ));
    };

    let Ok(dpop_key) = identify_key(&parked.dpop_private_key) else {
        return Ok(deny("the parked DPoP key could not be read back"));
    };
    let Some(signing_key) = state.pds_signing_key.clone() else {
        return Ok(deny("this server has no signing key"));
    };

    let oauth_client = OAuthClient {
        redirect_uri: config.redirect_uri.clone(),
        client_id: config.client_id.clone(),
        private_signing_key_data: (*signing_key).clone(),
    };
    let workflow_request = WorkflowRequest {
        oauth_state: q.state.clone(),
        subject: parked.delegate_did.clone(),
        issuer: parked.issuer.clone(),
        authorization_server: auth_server.pushed_authorization_request_endpoint.clone(),
        nonce: parked.nonce.clone(),
        pkce_verifier: parked.pkce_verifier.clone(),
        // The public half of the key the client assertion is signed with.
        //
        // `oauth_complete` does not read this field today -- it takes the
        // private key off `oauth_client` -- so an empty string was inert. It
        // was also a field whose contract says "the public key used for
        // signing" holding nothing, which is the sort of thing that stays
        // correct only until somebody adds a reader.
        signing_public_key: atproto_identity::key::to_public(&signing_key)
            .map(|public| public.to_string())
            .unwrap_or_default(),
        dpop_private_key: parked.dpop_private_key.clone(),
        created_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now(),
    };

    // `oauth_complete` binds the response's `sub` to the subject the flow
    // began for, so a server answering with somebody else's DID fails here
    // rather than producing a delegate this server never resolved.
    //
    // The token it returns is dropped. It is a bare `atproto` grant bound to a
    // DPoP key that goes out of scope with this function, so nothing else can
    // use it either.
    if let Err(error) = oauth_complete(
        &http_client,
        &oauth_client,
        &dpop_key,
        code,
        &parked.delegate_did,
        &workflow_request,
        &auth_server,
    )
    .await
    {
        tracing::info!(error = ?error, "a delegate's token exchange failed");
        return Ok(deny("the token exchange with the delegate's server failed"));
    }

    // Identity proved. Now, and only now, the question this flow exists to
    // ask.
    if !delegation::is_delegate(&pool, &parked.core_did, &parked.delegate_did)
        .await
        .map_err(XrpcError::from)?
    {
        return Ok(deny("that identity is not a delegate of this account"));
    }

    // The same gates the account's own password would have to pass. A delegate
    // is not a way around a suspension or an unaccepted policy -- they act as
    // the account, and the account cannot do these things either.
    let Some(account) = state
        .reader
        .accounts()
        .lookup_did(&parked.core_did)
        .await
        .map_err(XrpcError::from)?
    else {
        return Ok(deny("the account no longer exists"));
    };
    if !matches!(
        account.state,
        AccountState::Active | AccountState::Deactivated
    ) {
        return Ok(deny("the account is not in a state that can authorize"));
    }
    if crate::account::policy::acceptance_required(
        &state.reader,
        &account.did,
        state.policy.as_ref(),
    )
    .await
    {
        return Ok(deny("the account owes a policy acceptance"));
    }

    // Pinned here for the same reason `authorize_handler` pins it: a
    // permission set lives in the client's own repository, and expanding once,
    // at the moment authorization is settled, is what stops the grant moving
    // between what was shown and what a token carries.
    let mut request = parked.request;
    request.scope =
        crate::oauth::permission_set::expand(state.lexicon_resolver.as_ref(), &request.scope).await;

    let issued = random_hex();
    // Built before the code is stored: if the client's registered redirect is
    // somehow unusable there is nothing to hand the code to, and issuing one
    // anyway would leave a live authorization nobody can redeem.
    let Some(redirect) = redirect_with(
        &request.redirect_uri,
        &[
            ("code", &issued),
            ("state", &request.state),
            ("iss", &origin),
        ],
    ) else {
        return Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "this client's redirect_uri cannot be built on",
        ));
    };

    state
        .oauth
        .issue_code(
            issued,
            account.did.clone(),
            request,
            Some(parked.delegate_did.clone()),
        )
        .await
        .map_err(XrpcError::from)?;

    tracing::info!(
        core_did = %account.did,
        delegate_did = %parked.delegate_did,
        "a delegate authorized an application on an account's behalf"
    );
    Ok(clear_binding(see_other(&redirect)))
}

// ---------------------------------------------------------------------------
//  Identity
// ---------------------------------------------------------------------------

/// An AT Protocol identity, resolved and verified both ways.
#[derive(Debug, Clone)]
pub struct ResolvedIdentity {
    /// The DID, which is the only thing authority is ever decided on.
    pub did: String,
    /// The handle, verified to resolve to that DID and claimed back by it.
    pub handle: String,
    /// The identity's PDS, where its OAuth metadata is discovered.
    pub pds_url: String,
}

/// Resolve a handle or DID, and require it to agree with itself.
///
/// Bidirectional by design. A handle resolves to a DID, and the DID document
/// must claim that same handle back in `alsoKnownAs`; a DID resolves to a
/// document, and its first claimed handle must resolve back to it. Either
/// direction alone can be arranged by whoever controls one side, and this is
/// used both to decide who an account is delegating to and to decide whose
/// authorization server to trust with the question.
///
/// # Errors
///
/// [`PdsError::DelegationUnresolvable`] for every failure: no DNS resolver, no
/// answer, a document with no handle, a mismatch, or no PDS endpoint. They are
/// one error because the remedy is the same and because distinguishing them
/// tells a caller about an identity they may not know.
pub(crate) async fn resolve_identity(
    state: &HttpState,
    input: &str,
) -> Result<ResolvedIdentity, PdsError> {
    let typed = input
        .trim()
        .trim_start_matches("at://")
        .trim_start_matches('@');
    let unresolvable = || PdsError::DelegationUnresolvable {
        handle: typed.to_string(),
    };

    let dns_resolver = state.dns_resolver.clone().ok_or_else(unresolvable)?;
    let plc_hostname = state
        .plc_service
        .as_ref()
        .map(|p| p.directory_hostname().to_string())
        .ok_or_else(unresolvable)?;
    let http_client = peer_client().map_err(|_| unresolvable())?;
    let resolver = atproto_identity::resolve::InnerIdentityResolver {
        dns_resolver: dns_resolver.clone(),
        http_client: http_client.clone(),
        plc_hostname,
    };

    // Whichever way round the caller gave it, the pair has to agree. The DID
    // document is the authority on which handle an identity claims; DNS (or
    // `.well-known`) is the authority on which identity a handle points at.
    let did = if typed.starts_with("did:") {
        typed.to_string()
    } else {
        atproto_identity::resolve::resolve_handle(&http_client, dns_resolver.as_ref(), typed)
            .await
            .map_err(|_| unresolvable())?
    };

    let document = resolver.resolve(&did).await.map_err(|_| unresolvable())?;
    let claimed = document
        .also_known_as
        .iter()
        .find_map(|aka| aka.strip_prefix("at://"))
        .ok_or_else(unresolvable)?
        .to_string();

    // Coming from a DID, this is the leg that has not been checked yet;
    // coming from a handle, it is the confirmation that the document claims
    // the name back.
    let round_trip =
        atproto_identity::resolve::resolve_handle(&http_client, dns_resolver.as_ref(), &claimed)
            .await
            .map_err(|_| unresolvable())?;
    if round_trip != did {
        tracing::info!(
            did,
            claimed,
            round_trip,
            "an identity's handle does not resolve back to it"
        );
        return Err(unresolvable());
    }
    if !typed.starts_with("did:") && !claimed.eq_ignore_ascii_case(typed) {
        tracing::info!(
            typed,
            claimed,
            "an identity does not claim the handle it was reached by"
        );
        return Err(unresolvable());
    }

    // `pds_endpoints_validated`, never `pds_endpoints`.
    //
    // This string is the `serviceEndpoint` out of a DID document, which is
    // written by whoever controls the identity being resolved -- a stranger, by
    // construction, since the whole point is authenticating someone this server
    // has never met. The caller then fetches it. That is a server-side
    // request-forgery sink, and the raw accessor hands over
    // `http://169.254.169.254/`, `http://localhost:5432` or an internal admin
    // panel as readily as a real PDS.
    //
    // The validated form applies the workspace URL policy -- HTTPS only, no
    // address literal in any form a resolver accepts, no embedded credentials,
    // no port other than 443, no reserved suffix -- and drops what fails.
    // `http::proxy_target` guards the same sink the same way.
    //
    // The guard is syntactic: it does not resolve DNS, so a public name with an
    // A record inside a private range still passes. `peer_client` refusing to
    // follow redirects is the other half of this; neither is sufficient alone.
    let pds_url = document
        .pds_endpoints_validated()
        .first()
        .ok_or_else(unresolvable)?
        .to_string();

    Ok(ResolvedIdentity {
        did,
        handle: claimed,
        pds_url,
    })
}

/// Find the local account a `login_hint` names, by DID or handle.
async fn lookup_local_account(
    state: &HttpState,
    hint: &str,
) -> Result<Option<crate::account::AccountRow>, XrpcError> {
    let directory = state.reader.accounts();
    if hint.starts_with("did:") {
        directory.lookup_did(hint).await.map_err(XrpcError::from)
    } else {
        directory
            .lookup_handle(&hint.to_ascii_lowercase())
            .await
            .map_err(XrpcError::from)
    }
}

// ---------------------------------------------------------------------------
//  Small shared pieces
// ---------------------------------------------------------------------------

/// Re-read the delegate's authorization server metadata at callback time.
///
/// The token exchange needs the token endpoint and the issuer, and the parked
/// row holds both — but `oauth_complete` takes the whole metadata document,
/// and a stale copy of somebody else's configuration is not something to carry
/// across a multi-minute gap. Fetching from the stored issuer also re-runs the
/// library's validation, including that the document's `issuer` equals the URL
/// it came from.
async fn fetch_auth_server(
    http_client: &reqwest::Client,
    parked: &ParkedLogin,
) -> Result<AuthorizationServer, ()> {
    match oauth_authorization_server(http_client, &parked.issuer).await {
        Ok(found) if found.token_endpoint == parked.token_endpoint => Ok(found),
        Ok(found) => {
            tracing::warn!(
                issuer = %parked.issuer,
                was = %parked.token_endpoint,
                now = %found.token_endpoint,
                "a delegate's token endpoint moved mid-flow"
            );
            Err(())
        }
        Err(error) => {
            tracing::info!(issuer = %parked.issuer, error = ?error, "could not re-read a delegate's authorization server");
            Err(())
        }
    }
}

/// An HTTP client for talking to somebody else's server.
///
/// Built once and shared. Every URL it fetches is named by a stranger, so its
/// configuration is a security boundary rather than a convenience, and one
/// instance is what stops the next call site deciding differently.
///
/// # Redirects are refused outright
///
/// `reqwest` follows up to ten by default, and that alone defeats the endpoint
/// validation in [`resolve_identity`]: a hostile server passes the syntactic
/// policy with `https://evil.example`, then answers `302 Location:
/// http://169.254.169.254/`, and the client walks into the private range the
/// policy exists to keep it out of. A redirect from an OAuth metadata document
/// is not something a correct peer needs, so refusing every one costs nothing
/// and closes the bypass.
///
/// Pooling is the secondary reason. A client built per call keeps no
/// connections and leaks a pool each time, which on the fan-out
/// [`begin`] performs is a file-descriptor problem before it is a latency one.
fn peer_client() -> Result<reqwest::Client, XrpcError> {
    static CLIENT: std::sync::OnceLock<Result<reqwest::Client, String>> =
        std::sync::OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .user_agent(crate::user_agent())
                .timeout(std::time::Duration::from_secs(PEER_TIMEOUT_SECS))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|e| e.to_string())
        })
        .clone()
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("build http client: {e}"),
            )
        })
}

/// 32 bytes of randomness, hex-encoded. Used for the OAuth `state`, the nonce,
/// and the authorization code this server issues at the end.
fn random_hex() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

/// Append query parameters to a redirect URI that may already carry some.
///
/// Not `format!("{base}?{params}")`. A registered `redirect_uri` is permitted
/// to have a query of its own -- `assert_redirect_uri_permitted` checks the
/// scheme and the authority and says nothing about the query -- so a client
/// registering `https://app.example/cb?tenant=acme` was handed
/// `...?tenant=acme?code=abc`, where the code parses as part of `tenant`'s
/// value. The flow appeared to succeed, the browser landed on the client, and
/// the client received no code: a failure with no visible cause at either end.
///
/// Returns `None` only if the base does not parse, which
/// [`crate::oauth::client_metadata::assert_redirect_uri_registered`] has
/// already established at PAR time. Callers answer a plain refusal rather than
/// unwrapping, so a future change there cannot become a panic here.
fn redirect_with(base: &str, params: &[(&str, &str)]) -> Option<String> {
    let mut url = url::Url::parse(base).ok()?;
    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in params {
            pairs.append_pair(key, value);
        }
    }
    Some(url.to_string())
}

/// A 303 to `location`.
///
/// `See Other` rather than `Found`: the browser arrives at `begin` on a POST,
/// and the next thing must be a GET.
fn see_other(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(axum::http::header::LOCATION, location)],
    )
        .into_response()
}
