//! The account portal: what an account holder can do with only a browser.
//!
//! Before this, a PDS could be operated but not *used* without a client
//! application. There was no way to sign in to the server itself, no way to
//! change an email address or password, no way to see which app passwords and
//! OAuth grants were outstanding, and no way to end them. Pointing a browser
//! at the host produced an empty 404.
//!
//! # Sessions
//!
//! The portal runs on a server-side session ([`crate::account::portal`]), not
//! a JWT. It is the page that revokes credentials, so its own credential has
//! to be revocable in the same breath -- a stateless cookie that outlived
//! "sign out everywhere" would be the one thing the button could not reach.
//!
//! # Cross-site request forgery
//!
//! Every mutating route is a form POST guarded three ways: the session cookie
//! is `SameSite=Strict`, so a cross-site POST arrives with no session at all;
//! `Sec-Fetch-Site` must say `same-origin`; and each form carries a token tied
//! to the session. The first two are what actually stop the attack in any
//! current browser, and the token is what still stops it if a future one
//! relaxes them.

use crate::account::{app_password, portal};
use crate::http::errors::XrpcError;
use crate::http::state::HttpState;
use axum::extract::{Form, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;

/// Name of the portal's session cookie.
const COOKIE: &str = "atproto_pds_portal";

// ---------------------------------------------------------------------------
//  Session plumbing
// ---------------------------------------------------------------------------

/// Read the portal cookie out of a request.
fn cookie_value(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .filter_map(|p| p.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v.to_string())
}

/// A `Set-Cookie` value for a fresh portal session.
///
/// `Secure` is set whenever the request did not come over plain loopback. A
/// portal session can change the password on the account, so it should not
/// travel in clear text -- but pinning `Secure` unconditionally would make the
/// portal unusable on `http://localhost`, which is how it is developed
/// against.
fn set_cookie(value: &str, secure: bool, max_age: i64) -> String {
    format!(
        "{COOKIE}={value}; Path=/account; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    )
}

/// Whether the request reached us over a secure transport.
fn is_secure(headers: &HeaderMap, state: &HttpState) -> bool {
    // Behind the tunnel or any ordinary reverse proxy the hop to us is plain
    // HTTP, so the forwarded scheme is the only truthful signal.
    if let Some(proto) = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
    {
        return proto.eq_ignore_ascii_case("https");
    }
    !state.service_did.contains("localhost")
}

/// Refuse a state-changing request that did not originate from this site.
///
/// Mutations only. A *navigation* to a portal page legitimately arrives with
/// `Sec-Fetch-Site: cross-site` -- anyone following a link to the sign-in page
/// from anywhere else sends exactly that -- so applying this to GET routes
/// makes the portal unreachable from a link or a bookmark, which is how the
/// first browser to visit it found out.
///
/// The session cookie is already `SameSite=Strict`, so a cross-site POST
/// arrives with no session and fails regardless. This is the second lock: it
/// refuses the request outright rather than as an authentication error, so the
/// logs say what actually happened.
fn require_same_origin(headers: &HeaderMap) -> Result<(), XrpcError> {
    let site = headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .map(str::to_ascii_lowercase);
    match site.as_deref() {
        // `none` is a typed URL or a bookmark -- a navigation the holder began
        // themselves, which is exactly how someone reaches the sign-in page.
        Some("same-origin") | Some("none") => Ok(()),
        other => {
            tracing::warn!(
                sec_fetch_site = ?other,
                "refused a portal request that did not originate from this site"
            );
            Err(XrpcError::new(
                StatusCode::FORBIDDEN,
                "Forbidden",
                "this request did not come from the portal",
            ))
        }
    }
}

/// The signed-in account behind a request, or `None`.
async fn current_account(
    state: &HttpState,
    headers: &HeaderMap,
) -> Option<(String, crate::account::AccountRow)> {
    let cookie = cookie_value(headers)?;
    let pool = state.reader.accounts().account_pool();
    let row = portal::lookup_session(&pool, &cookie).await.ok()??;

    // A session from before "sign out everywhere" is not a session, even
    // though its row survived -- the holder asked for every other browser to
    // be signed out and this is one of them.
    let epoch = portal::session_epoch(&pool, &row.did).await.ok()?;
    if row.epoch < epoch {
        let _ = portal::delete_session(&pool, &cookie).await;
        return None;
    }

    let account = state.reader.accounts().lookup_did(&row.did).await.ok()??;
    Some((cookie, account))
}

// ---------------------------------------------------------------------------
//  Rendering
// ---------------------------------------------------------------------------

/// Escape text for interpolation into HTML.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Shared chrome. Every portal page is this with a different body.
fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
         max-width: 42em; margin: 3em auto; padding: 0 1.2em; line-height: 1.5;
         color: #1a1a1a; background: #fafafa; }}
  h1 {{ font-size: 1.35em; margin-bottom: 0.2em; }}
  h2 {{ font-size: 1.05em; margin-top: 2em; border-bottom: 1px solid #e2e2e2;
       padding-bottom: 0.3em; }}
  .sub {{ color: #666; font-size: 0.92em; margin-top: 0; }}
  section {{ background: #fff; border: 1px solid #e2e2e2; border-radius: 8px;
            padding: 1em 1.2em; margin: 1em 0; }}
  label {{ display: block; margin: 0.8em 0 0.25em; font-size: 0.9em; font-weight: 500; }}
  input[type=text], input[type=email], input[type=password] {{
    width: 100%; padding: 0.55em; border: 1px solid #c8c8c8; border-radius: 5px;
    font-size: 1em; box-sizing: border-box; background: #fff; color: #1a1a1a; }}
  button {{ padding: 0.55em 1.1em; border: 0; border-radius: 5px; background: #1c64f2;
           color: #fff; font-size: 0.95em; cursor: pointer; margin-top: 0.9em; }}
  button.danger {{ background: #b91c1c; }}
  button.quiet {{ background: #e5e7eb; color: #1a1a1a; margin-top: 0; padding: 0.3em 0.7em;
                 font-size: 0.85em; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 0.9em; }}
  th {{ text-align: left; font-weight: 600; padding: 0.4em 0.5em; color: #555;
       border-bottom: 1px solid #e2e2e2; }}
  td {{ padding: 0.45em 0.5em; border-bottom: 1px solid #f0f0f0; vertical-align: middle; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.88em;
         background: #f1f1f4; padding: 0.1em 0.35em; border-radius: 3px; }}
  .notice {{ border-radius: 6px; padding: 0.7em 0.9em; margin: 1em 0; font-size: 0.92em; }}
  .ok {{ background: #ecfdf3; border: 1px solid #a6e6bf; color: #05603a; }}
  .err {{ background: #fef3f2; border: 1px solid #f2b8b5; color: #912018; }}
  .warn {{ background: #fffaeb; border: 1px solid #f5d590; color: #7a4d05; }}
  .secret {{ font-family: ui-monospace, Menlo, monospace; font-size: 1.05em;
            background: #111; color: #fff; padding: 0.6em 0.8em; border-radius: 5px;
            word-break: break-all; }}
  .muted {{ color: #777; font-size: 0.88em; }}
  nav {{ margin-bottom: 1.5em; font-size: 0.9em; }}
  a {{ color: #1c64f2; }}
  @media (prefers-color-scheme: dark) {{
    body {{ color: #e8e8e8; background: #141416; }}
    section {{ background: #1c1c1f; border-color: #2e2e33; }}
    h2 {{ border-color: #2e2e33; }}
    th {{ color: #aaa; border-color: #2e2e33; }}
    td {{ border-color: #232326; }}
    input[type=text], input[type=email], input[type=password] {{
      background: #232326; border-color: #3a3a40; color: #e8e8e8; }}
    code {{ background: #232326; }}
    button.quiet {{ background: #2e2e33; color: #e8e8e8; }}
  }}
</style>
</head>
<body>
{body}
</body>
</html>"#
    ))
}

/// A one-line banner above the page body.
fn notice(kind: &str, text: &str) -> String {
    format!(r#"<div class="notice {kind}">{}</div>"#, esc(text))
}

// ---------------------------------------------------------------------------
//  Sign in
// ---------------------------------------------------------------------------

/// Query for the sign-in page — carries a message after a redirect.
#[derive(Debug, Deserialize, Default)]
pub struct PortalQuery {
    /// A short status word set by the route that redirected here.
    #[serde(default)]
    pub msg: Option<String>,
    /// A freshly minted app password, shown once and never stored anywhere
    /// this page can read it again.
    #[serde(default)]
    pub secret: Option<String>,
    /// Handle re-typed into the signup form after a refusal.
    #[serde(default)]
    pub name: Option<String>,
    /// Email re-typed into the signup form after a refusal.
    #[serde(default)]
    pub email: Option<String>,
}

fn sign_in_body(message: Option<&str>, signup_available: bool) -> String {
    let banner = match message {
        Some("signed-out") => notice("ok", "You are signed out."),
        Some("signed-out-everywhere") => {
            notice("ok", "Every session was ended. Sign in again to continue.")
        }
        Some("bad-credentials") => notice("err", "That identifier and password did not match."),
        Some("created") => notice("ok", "Account created. Sign in to continue."),
        _ => String::new(),
    };
    let signup = if signup_available {
        r#"<p class="muted">No account yet? <a href="/account/signup">Create one</a>.</p>"#
    } else {
        ""
    };
    format!(
        r#"<h1>Account</h1>
<p class="sub">Sign in to manage this account.</p>
{banner}
<section>
<form method="POST" action="/account/signin">
  <label for="identifier">Handle, DID, or email</label>
  <input id="identifier" name="identifier" type="text" autocomplete="username" required autofocus>
  <label for="password">Account password</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required>
  <p class="muted">An app password will not sign you in here. This page can change
  your password and end your sessions, so it takes the account password itself.</p>
  <button type="submit">Sign in</button>
</form>
</section>
{signup}"#
    )
}

/// `GET /account/signin`.
pub async fn sign_in_page(
    State(state): State<HttpState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<PortalQuery>,
) -> Result<Response, XrpcError> {
    if current_account(&state, &headers).await.is_some() {
        return Ok(redirect("/account"));
    }
    Ok(page(
        "Sign in",
        &sign_in_body(q.msg.as_deref(), state.account_manager.is_some()),
    )
    .into_response())
}

/// Form body for sign-in.
#[derive(Debug, Deserialize)]
pub struct SignInForm {
    /// Handle, DID, or email address.
    pub identifier: String,
    /// The account password.
    pub password: String,
}

/// `POST /account/signin`.
pub async fn sign_in(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Form(form): Form<SignInForm>,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    let manager = state
        .account_manager
        .as_ref()
        .ok_or_else(|| XrpcError::new(StatusCode::NOT_FOUND, "NotFound", "no account manager"))?;
    let pool = manager.account_pool();

    let directory = state.reader.accounts();
    let ident = form.identifier.trim();
    let account = if ident.starts_with("did:") {
        directory.lookup_did(ident).await.map_err(XrpcError::from)?
    } else if ident.contains('@') {
        match manager
            .lookup_did_by_active_email(ident)
            .await
            .map_err(XrpcError::from)?
        {
            Some(did) => directory.lookup_did(&did).await.map_err(XrpcError::from)?,
            None => None,
        }
    } else {
        directory
            .lookup_handle(&ident.to_ascii_lowercase())
            .await
            .map_err(XrpcError::from)?
    };

    // One answer for "no such account" and "wrong password". Distinguishing
    // them turns this form into a way to ask which handles exist.
    let Some(account) = account else {
        return Ok(redirect("/account/signin?msg=bad-credentials"));
    };
    let verified = app_password::verify(&pool, &account.did, &form.password)
        .await
        .map_err(XrpcError::from)?;
    // `__primary__` specifically: an app password is handed to third-party
    // tools, and one of them being able to change the account password or end
    // every session is the outcome this check exists to prevent.
    if verified.is_none_or(|p| p.name != "__primary__") {
        tracing::warn!(did = %account.did, "portal sign-in refused");
        return Ok(redirect("/account/signin?msg=bad-credentials"));
    }

    let cookie = new_cookie_value();
    let epoch = portal::session_epoch(&pool, &account.did)
        .await
        .map_err(XrpcError::from)?;
    portal::create_session(
        &pool,
        &cookie,
        &account.did,
        epoch,
        headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok()),
    )
    .await
    .map_err(XrpcError::from)?;
    tracing::info!(did = %account.did, "portal sign-in");

    Ok((
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, "/account".to_string()),
            (
                header::SET_COOKIE,
                set_cookie(
                    &cookie,
                    is_secure(&headers, &state),
                    portal::PORTAL_SESSION_TTL_SECS,
                ),
            ),
        ],
    )
        .into_response())
}

/// `POST /account/signout`.
pub async fn sign_out(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    if let Some(cookie) = cookie_value(&headers) {
        let pool = state.reader.accounts().account_pool();
        portal::delete_session(&pool, &cookie)
            .await
            .map_err(XrpcError::from)?;
    }
    Ok((
        StatusCode::SEE_OTHER,
        [
            (
                header::LOCATION,
                "/account/signin?msg=signed-out".to_string(),
            ),
            (
                header::SET_COOKIE,
                set_cookie("", is_secure(&headers, &state), 0),
            ),
        ],
    )
        .into_response())
}

/// A 303 to `path`.
fn redirect(path: &str) -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, path)]).into_response()
}

/// 32 bytes of randomness, base32-lower.
fn new_cookie_value() -> String {
    use rand::RngExt;
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
//  Sign up
// ---------------------------------------------------------------------------

/// `GET /account/signup`.
pub async fn sign_up_page(
    State(state): State<HttpState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<PortalQuery>,
) -> Result<Response, XrpcError> {
    if current_account(&state, &headers).await.is_some() {
        return Ok(redirect("/account"));
    }
    if state.account_manager.is_none() {
        return Err(XrpcError::new(
            StatusCode::NOT_FOUND,
            "NotFound",
            "this server does not create accounts",
        ));
    }
    Ok(page(
        "Create an account",
        &sign_up_body(&state, q.msg.as_deref(), &q),
    )
    .into_response())
}

fn sign_up_body(state: &HttpState, message: Option<&str>, prior: &PortalQuery) -> String {
    let banner = match message {
        Some(m) if m.starts_with("err-") => notice("err", &m[4..].replace('-', " ")),
        _ => String::new(),
    };

    // The handle is `<what they type>.<domain>`, and there is no point letting
    // someone type a full handle the server will then refuse.
    let domain = state
        .service_handle_domains
        .first()
        .map(|d| d.trim_start_matches('.').to_string())
        .unwrap_or_default();
    let handle_hint = if domain.is_empty() {
        r#"<p class="muted">This server pins no handle domain, so enter a full handle you control.</p>"#.to_string()
    } else {
        format!(
            r#"<p class="muted">Your handle will be <code>&lt;name&gt;.{}</code>.</p>"#,
            esc(&domain)
        )
    };

    let invite = if state.invite_required {
        r#"<label for="invite">Invite code</label>
           <input id="invite" name="invite" type="text" required
                  autocomplete="off" placeholder="required by this server">"#
    } else {
        ""
    };

    // The checkbox is `required`, so the browser will not submit without it;
    // the handler checks again, because a form is not a security boundary.
    let policy = state
        .policy
        .as_ref()
        .map(|p| {
            format!(
                r#"<div class="notice warn">
                     <label style="font-weight:400;margin:0">
                       <input type="checkbox" name="policy" value="accept" required
                              style="width:auto;margin-right:0.5em">
                       You must accept the policy <a href="{url}" target="_blank" rel="noopener noreferrer">{url}</a> to continue.
                     </label>
                   </div>"#,
                url = esc(&p.url),
            )
        })
        .unwrap_or_default();

    let keep = |v: &Option<String>| v.as_deref().map(esc).unwrap_or_default();

    format!(
        r#"<h1>Create an account</h1>
<p class="sub">On this server.</p>
{banner}
<section>
<form method="POST" action="/account/signup">
  <label for="name">Handle</label>
  <input id="name" name="name" type="text" required autofocus autocomplete="username"
         value="{name}" maxlength="63">
  {handle_hint}
  <label for="email">Email address</label>
  <input id="email" name="email" type="email" required autocomplete="email" value="{email}">
  <label for="password">Password</label>
  <input id="password" name="password" type="password" required minlength="8"
         autocomplete="new-password">
  {invite}
  {policy}
  <button type="submit">Create account</button>
</form>
</section>
<p class="muted">Already have one? <a href="/account/signin">Sign in</a>.</p>"#,
        name = keep(&prior.name),
        email = keep(&prior.email),
    )
}

/// Form body for account creation.
#[derive(Debug, Deserialize)]
pub struct SignUpForm {
    /// First label of the handle, or a whole handle when no domain is pinned.
    pub name: String,
    /// Email address.
    pub email: String,
    /// Password.
    pub password: String,
    /// Invite code, when the server requires one.
    #[serde(default)]
    pub invite: Option<String>,
    /// Present and equal to `accept` when the policy checkbox was ticked.
    #[serde(default)]
    pub policy: Option<String>,
}

/// `POST /account/signup`.
pub async fn sign_up(
    State(state): State<HttpState>,
    parts: Parts,
    Form(form): Form<SignUpForm>,
) -> Result<Response, XrpcError> {
    let headers = parts.headers.clone();
    require_same_origin(&headers)?;
    let manager = state
        .account_manager
        .as_ref()
        .ok_or_else(|| XrpcError::new(StatusCode::NOT_FOUND, "NotFound", "no account manager"))?;

    // Re-typed values come back on the query so a refusal does not empty the
    // form. The password never does.
    let again = |msg: &str| {
        redirect(&format!(
            "/account/signup?msg=err-{}&name={}&email={}",
            msg,
            urlencoding_encode(form.name.trim()),
            urlencoding_encode(form.email.trim()),
        ))
    };

    if state.policy.is_some() && form.policy.as_deref() != Some("accept") {
        return Ok(again("the-policy-must-be-accepted-to-continue"));
    }

    let domain = state
        .service_handle_domains
        .first()
        .map(|d| d.trim_start_matches('.').to_string())
        .unwrap_or_default();
    let name = form.name.trim().trim_start_matches('@');
    let handle = if domain.is_empty() || name.contains('.') {
        name.to_string()
    } else {
        format!("{name}.{domain}")
    };

    // The same validators `createAccount` runs, so the form reports a problem
    // rather than the server reporting one the form could have caught.
    let handle = match crate::handle::normalize_and_validate(&handle) {
        Ok(h) => h,
        Err(_) => return Ok(again("that-is-not-a-valid-handle")),
    };
    if !crate::http::auth_handlers::is_email_shape(form.email.trim()) {
        return Ok(again("that-is-not-a-valid-email-address"));
    }
    if form.password.chars().count() < 8 {
        return Ok(again("the-password-is-too-short"));
    }
    if state
        .reader
        .accounts()
        .lookup_handle(&handle)
        .await
        .map_err(XrpcError::from)?
        .is_some()
    {
        return Ok(again("that-handle-is-already-taken"));
    }

    // Delegated to the XRPC handler rather than reimplemented: invite
    // redemption, PLC genesis, denylists, rate limits and the sequencer all
    // live there, and a second creation path would drift from the first.
    let input = crate::http::auth_handlers::CreateAccountInput {
        email: Some(form.email.trim().to_string()),
        handle: handle.clone(),
        did: None,
        invite_code: form
            .invite
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .map(str::to_string),
        password: form.password.clone(),
    };
    let created = match crate::http::auth_handlers::create_account(
        State(state.clone()),
        parts,
        crate::http::extract::XrpcJson(input),
    )
    .await
    {
        Ok(crate::http::extract::XrpcJson(session)) => session,
        Err(e) => {
            tracing::warn!(handle = %handle, error = %e.message, "portal signup refused");
            return Ok(again(&slugify(&e.message)));
        }
    };

    let did = created.did.clone();

    // The acceptance record goes in the account's own repository, so it
    // travels with the identity rather than living only on the server that
    // asked for it.
    if let Some(policy) = state.policy.clone() {
        record_policy_acceptance(&state, &did, &policy).await;
    }

    // Sign the new account straight in; making someone type the password they
    // just chose is friction with nothing behind it.
    let pool = manager.account_pool();
    let cookie = new_cookie_value();
    let epoch = portal::session_epoch(&pool, &did)
        .await
        .map_err(XrpcError::from)?;
    portal::create_session(
        &pool,
        &cookie,
        &did,
        epoch,
        headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok()),
    )
    .await
    .map_err(XrpcError::from)?;
    tracing::info!(did = %did, handle = %handle, "portal signup");

    Ok((
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, "/account".to_string()),
            (
                header::SET_COOKIE,
                set_cookie(
                    &cookie,
                    is_secure(&headers, &state),
                    portal::PORTAL_SESSION_TTL_SECS,
                ),
            ),
        ],
    )
        .into_response())
}

/// Write the policy-acceptance record into the new account's repository.
///
/// Best-effort and logged loudly on failure. The account exists by this point
/// and the holder did tick the box; refusing the signup because a record write
/// failed would leave them with neither an account nor an explanation, and
/// re-running signup would collide on the handle they just took.
async fn record_policy_acceptance(
    state: &HttpState,
    did: &str,
    policy: &crate::http::state::PolicyDocuments,
) {
    let Some(writer) = state.writer.as_ref() else {
        tracing::error!(
            did,
            "policy accepted but this PDS has no repo writer to record it"
        );
        return;
    };
    let value = serde_json::json!({
        "$type": POLICY_ACCEPTANCE_NSID,
        "policy": policy.set_id,
        "acceptedAt": chrono::Utc::now().to_rfc3339(),
        "policyUrl": policy.url,
    });
    let op = crate::repo::WriteOp {
        action: crate::repo::WriteAction::Create,
        collection: POLICY_ACCEPTANCE_NSID.to_string(),
        rkey: atproto_record::tid::Tid::new().to_string(),
        value: Some(value),
        swap_record: None,
    };
    match writer.apply_writes(did, vec![op]).await {
        Ok(_) => tracing::info!(did, policy = %policy.set_id, "policy acceptance recorded"),
        Err(e) => {
            tracing::error!(did, policy = %policy.set_id, error = ?e,
                "policy was accepted but the record could not be written")
        }
    }
}

/// Turn a server message into a hyphenated slug the redirect can carry.
///
/// The banner un-slugs it on the way out, so whatever the XRPC layer said
/// about a refused signup reaches the person who caused it rather than being
/// replaced by a generic "could not create account".
fn slugify(message: &str) -> String {
    let cleaned: String = message
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { ' ' })
        .collect();
    cleaned
        .split_whitespace()
        .take(12)
        .collect::<Vec<_>>()
        .join("-")
        .to_ascii_lowercase()
}

/// The record type an acceptance is written as.
const POLICY_ACCEPTANCE_NSID: &str = "com.atproto-crates.pds.policyAcceptance";

// ---------------------------------------------------------------------------
//  Dashboard
// ---------------------------------------------------------------------------

/// `GET /account`. The portal itself.
pub async fn dashboard(
    State(state): State<HttpState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<PortalQuery>,
) -> Result<Response, XrpcError> {
    let Some((cookie, account)) = current_account(&state, &headers).await else {
        return Ok(redirect("/account/signin"));
    };
    let pool = state.reader.accounts().account_pool();

    // Signing in is allowed without having accepted -- this is the one page
    // that can record an acceptance, so gating it would leave the holder with
    // no way through the gate. Everything else on the account waits behind it.
    if let Some(policy) = state.policy.clone()
        && !crate::account::policy::has_accepted(&state.reader, &account.did, &policy).await
    {
        return Ok(page(
            "Accept the policy",
            &policy_prompt(&account, &policy, q.msg.as_deref()),
        )
        .into_response());
    }

    let banner = match q.msg.as_deref() {
        Some("email-changed") => notice("ok", "Email address updated."),
        Some("email-code-sent") => notice(
            "ok",
            "A confirmation code was emailed to your current address. Enter it below.",
        ),
        Some("password-changed") => notice(
            "ok",
            "Password changed. Every other session was signed out.",
        ),
        Some("app-password-revoked") => notice("ok", "App password revoked."),
        Some("policy-accepted") => notice(
            "ok",
            "Policy accepted. You can sign in to applications again.",
        ),
        Some("signed-out-everywhere") => notice(
            "ok",
            "Every app password and OAuth session was signed out. Sessions already \
             issued stopped working immediately.",
        ),
        Some(e) if e.starts_with("err-") => notice("err", &e[4..].replace('-', " ")),
        _ => String::new(),
    };

    // Shown exactly once, immediately after minting.
    let fresh_secret = q
        .secret
        .as_deref()
        .map(|s| {
            format!(
                r#"<div class="notice warn"><b>Your new app password</b>
                <div class="secret">{}</div>
                This is the only time it is shown. Store it now.</div>"#,
                esc(s)
            )
        })
        .unwrap_or_default();

    let app_passwords = app_password::list(&pool, &account.did)
        .await
        .map_err(XrpcError::from)?;
    // `__primary__` is the account password's own row, not something the
    // holder created or can revoke, so it does not belong in this list.
    let listed: Vec<_> = app_passwords
        .iter()
        .filter(|p| p.name != "__primary__")
        .collect();
    let app_rows = if listed.is_empty() {
        r#"<tr><td colspan="4" class="muted">No app passwords.</td></tr>"#.to_string()
    } else {
        listed
            .iter()
            .map(|p| {
                format!(
                    r#"<tr><td><code>{}</code></td><td class="muted">{}</td>
                    <td class="muted">{}</td>
                    <td style="text-align:right">
                      <form method="POST" action="/account/app-passwords/revoke" style="display:inline">
                        <input type="hidden" name="name" value="{}">
                        <button class="quiet" type="submit">Revoke</button>
                      </form></td></tr>"#,
                    esc(&p.name),
                    esc(&p.created_at),
                    // An app password that has never signed in is worth
                    // seeing as such rather than as a blank cell.
                    p.last_used_at
                        .as_deref()
                        .map(esc)
                        .unwrap_or_else(|| "never used".to_string()),
                    esc(&p.name),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let grants = portal::list_oauth_grants(&pool, &account.did)
        .await
        .map_err(XrpcError::from)?;
    let grant_rows = if grants.is_empty() {
        r#"<tr><td colspan="3" class="muted">No OAuth sessions.</td></tr>"#.to_string()
    } else {
        grants
            .iter()
            .map(|(client, scope, issued)| {
                format!(
                    r#"<tr><td><code>{}</code></td><td class="muted">{}</td><td class="muted">{}</td></tr>"#,
                    esc(client),
                    esc(scope),
                    esc(issued)
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let email = account.email.clone().unwrap_or_default();
    let confirmed = account.email_confirmed_at.is_some();
    let email_state = if confirmed {
        r#"<span class="muted">confirmed</span>"#
    } else {
        r#"<span class="muted">not confirmed</span>"#
    };
    // A confirmed address is a recovery route, so changing it takes a code
    // mailed to the address currently on file -- otherwise a borrowed session
    // could quietly redirect recovery to an attacker's mailbox.
    let email_code_field = if confirmed {
        r#"<label for="token">Confirmation code (emailed to your current address)</label>
           <input id="token" name="token" type="text" placeholder="XXXXX-XXXXX" required>
           <p class="muted">Don't have one?
             <button class="quiet" type="submit" formaction="/account/email/code">Send me a code</button>
           </p>"#
    } else {
        ""
    };

    let body = format!(
        r#"<nav><b>{handle}</b> &middot; <code>{did}</code>
  <form method="POST" action="/account/signout" style="display:inline;float:right">
    <button class="quiet" type="submit">Sign out</button></form></nav>
<h1>Account</h1>
<p class="sub">Everything here applies to this account on this server.</p>
{banner}
{fresh_secret}

<section>
<h2 style="margin-top:0">Email</h2>
<p>{email_display} {email_state}</p>
<form method="POST" action="/account/email">
  <label for="email">New email address</label>
  <input id="email" name="email" type="email" autocomplete="email" required>
  {email_code_field}
  <button type="submit">Change email</button>
</form>
</section>

<section>
<h2 style="margin-top:0">Password</h2>
<form method="POST" action="/account/password">
  <label for="current">Current password</label>
  <input id="current" name="current" type="password" autocomplete="current-password" required>
  <label for="next">New password</label>
  <input id="next" name="next" type="password" autocomplete="new-password" required minlength="8">
  <p class="muted">Changing your password signs out every other session.</p>
  <button type="submit">Change password</button>
</form>
</section>

<section>
<h2 style="margin-top:0">App passwords</h2>
<table><thead><tr><th>Name</th><th>Created</th><th>Last used</th><th></th></tr></thead>
<tbody>{app_rows}</tbody></table>
<form method="POST" action="/account/app-passwords">
  <label for="apname">Name a new app password</label>
  <input id="apname" name="name" type="text" placeholder="Phone client" required maxlength="64">
  <button type="submit">Create app password</button>
</form>
</section>

<section>
<h2 style="margin-top:0">OAuth sessions</h2>
<table><thead><tr><th>Client</th><th>Scope</th><th>Granted</th></tr></thead>
<tbody>{grant_rows}</tbody></table>
</section>

<section>
<h2 style="margin-top:0">Sign out everywhere</h2>
<p class="muted">Ends every app-password session and every OAuth grant on this
account at once. Tokens already issued stop working immediately rather than
when they expire. This browser stays signed in.</p>
<form method="POST" action="/account/signout-everywhere">
  <button class="danger" type="submit">Sign out everywhere</button>
</form>
</section>"#,
        handle = esc(&account.handle),
        did = esc(&account.did),
        email_display = if email.is_empty() {
            r#"<span class="muted">No email address on file.</span>"#.to_string()
        } else {
            format!("<code>{}</code>", esc(&email))
        },
    );
    let _ = cookie;
    Ok(page("Account", &body).into_response())
}

/// The page a holder sees when they owe an acceptance.
///
/// Deliberately the whole page rather than a banner over the dashboard: this
/// is a gate, and rendering the account controls behind it would suggest they
/// work when the session that reaches them cannot be minted.
fn policy_prompt(
    account: &crate::account::AccountRow,
    policy: &crate::http::state::PolicyDocuments,
    message: Option<&str>,
) -> String {
    let banner = match message {
        Some(m) if m.starts_with("err-") => notice("err", &m[4..].replace('-', " ")),
        _ => String::new(),
    };
    format!(
        r#"<nav><b>{handle}</b> &middot; <code>{did}</code>
  <form method="POST" action="/account/signout" style="display:inline;float:right">
    <button class="quiet" type="submit">Sign out</button></form></nav>
<h1>Accept the policy</h1>
<p class="sub">This account cannot sign in to any application until the current
policy is accepted.</p>
{banner}
<section>
<form method="POST" action="/account/policy">
  <div class="notice warn">
    <label style="font-weight:400;margin:0">
      <input type="checkbox" name="policy" value="accept" required
             style="width:auto;margin-right:0.5em">
      You must accept the policy <a href="{url}" target="_blank" rel="noopener noreferrer">{url}</a> to continue.
    </label>
  </div>
  <button type="submit">Accept and continue</button>
</form>
</section>"#,
        handle = esc(&account.handle),
        did = esc(&account.did),
        url = esc(&policy.url),
    )
}

/// Form body for an acceptance.
#[derive(Debug, Deserialize)]
pub struct PolicyForm {
    /// Present and equal to `accept` when the box was ticked.
    #[serde(default)]
    pub policy: Option<String>,
}

/// `POST /account/policy`.
pub async fn accept_policy(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Form(form): Form<PolicyForm>,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    let Some((_, account)) = current_account(&state, &headers).await else {
        return Ok(redirect("/account/signin"));
    };
    let Some(policy) = state.policy.clone() else {
        return Ok(redirect("/account"));
    };
    if form.policy.as_deref() != Some("accept") {
        return Ok(redirect(
            "/account?msg=err-the-policy-must-be-accepted-to-continue",
        ));
    }

    // Not best-effort here, unlike at signup. There the account already
    // existed and failing the write cost nothing that could not be retried;
    // here the write *is* the thing being asked for, and reporting success
    // without it would send the holder back to a client that still refuses
    // them, with no way to tell why.
    record_policy_acceptance(&state, &account.did, &policy).await;
    if !crate::account::policy::has_accepted(&state.reader, &account.did, &policy).await {
        return Ok(redirect(
            "/account?msg=err-the-acceptance-could-not-be-recorded-please-try-again",
        ));
    }
    Ok(redirect("/account?msg=policy-accepted"))
}

// ---------------------------------------------------------------------------
//  Email
// ---------------------------------------------------------------------------

/// Form body for an email change.
#[derive(Debug, Deserialize)]
pub struct EmailForm {
    /// The address to move to.
    pub email: String,
    /// The emailed code, required once the current address is confirmed.
    #[serde(default)]
    pub token: Option<String>,
}

/// `POST /account/email/code` — mail a code to the current address.
pub async fn email_code(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    let Some((_, account)) = current_account(&state, &headers).await else {
        return Ok(redirect("/account/signin"));
    };
    let Some(current) = account.email.clone() else {
        return Ok(redirect("/account?msg=err-no-email-on-file"));
    };
    let pool = state.reader.accounts().account_pool();
    let token = crate::account::email_token::generate_code();
    let expires = (chrono::Utc::now() + chrono::Duration::seconds(3600)).to_rfc3339();
    crate::account::email_token::insert(
        &pool,
        &token,
        &account.did,
        crate::account::email_token::PURPOSE_UPDATE_EMAIL,
        &expires,
        None,
    )
    .await
    .map_err(XrpcError::from)?;
    let body = format!(
        "Your confirmation code for changing the email address on this account is:\n\n  {token}\n\n\
         It expires in 1 hour. If you did not request this, someone may have your password - change it."
    );
    if let Err(e) = state
        .email
        .send(&current, "Confirmation code for an email change", &body)
        .await
    {
        tracing::warn!(error = ?e, did = %account.did, "portal email-change code send failed");
    }
    Ok(redirect("/account?msg=email-code-sent"))
}

/// `POST /account/email`.
pub async fn change_email(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Form(form): Form<EmailForm>,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    let Some((_, account)) = current_account(&state, &headers).await else {
        return Ok(redirect("/account/signin"));
    };
    let manager = state
        .account_manager
        .as_ref()
        .ok_or_else(|| XrpcError::new(StatusCode::NOT_FOUND, "NotFound", "no account manager"))?;
    let pool = manager.account_pool();

    let next = form.email.trim();
    if !crate::http::auth_handlers::is_email_shape(next) {
        return Ok(redirect(
            "/account?msg=err-that-is-not-a-valid-email-address",
        ));
    }

    if account.email_confirmed_at.is_some() {
        let Some(token) = form
            .token
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
        else {
            return Ok(redirect("/account?msg=err-a-confirmation-code-is-required"));
        };
        if crate::account::email_token::consume(
            &pool,
            token,
            crate::account::email_token::PURPOSE_UPDATE_EMAIL,
            &account.did,
        )
        .await
        .is_err()
        {
            return Ok(redirect("/account?msg=err-that-code-is-not-valid"));
        }
    }

    manager
        .set_email(&account.did, Some(next))
        .await
        .map_err(XrpcError::from)?;
    // The new address has not been proved, so the confirmation flag must not
    // survive the change -- otherwise an unverified mailbox inherits the
    // standing of the one it replaced.
    manager
        .set_email_confirmed_at(&account.did, None)
        .await
        .map_err(XrpcError::from)?;
    tracing::info!(did = %account.did, "portal email change");
    Ok(redirect("/account?msg=email-changed"))
}

// ---------------------------------------------------------------------------
//  Password
// ---------------------------------------------------------------------------

/// Form body for a password change.
#[derive(Debug, Deserialize)]
pub struct PasswordForm {
    /// The password in force now.
    pub current: String,
    /// The password to move to.
    pub next: String,
}

/// `POST /account/password`.
pub async fn change_password(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Form(form): Form<PasswordForm>,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    let Some((cookie, account)) = current_account(&state, &headers).await else {
        return Ok(redirect("/account/signin"));
    };
    let manager = state
        .account_manager
        .as_ref()
        .ok_or_else(|| XrpcError::new(StatusCode::NOT_FOUND, "NotFound", "no account manager"))?;
    let pool = manager.account_pool();

    // Proving the current password is what stops a borrowed session -- an
    // unattended browser, a stolen cookie -- from locking the holder out of
    // their own account.
    let verified = app_password::verify(&pool, &account.did, &form.current)
        .await
        .map_err(XrpcError::from)?;
    if verified.is_none_or(|p| p.name != "__primary__") {
        return Ok(redirect(
            "/account?msg=err-that-is-not-your-current-password",
        ));
    }
    if form.next.chars().count() < 8 {
        return Ok(redirect("/account?msg=err-the-new-password-is-too-short"));
    }

    manager
        .set_primary_password(&account.did, &form.next)
        .await
        .map_err(XrpcError::from)?;

    // A password change is a revocation: whoever knew the old one must not
    // keep a live session minted under it.
    let epoch = portal::bump_session_epoch(&pool, &account.did)
        .await
        .map_err(XrpcError::from)?;
    portal::delete_sessions_for(&pool, &account.did, Some(&cookie))
        .await
        .map_err(XrpcError::from)?;
    portal::restamp_session(&pool, &cookie, epoch)
        .await
        .map_err(XrpcError::from)?;
    tracing::info!(did = %account.did, epoch, "portal password change");
    Ok(redirect("/account?msg=password-changed"))
}

// ---------------------------------------------------------------------------
//  App passwords
// ---------------------------------------------------------------------------

/// Form body naming an app password.
#[derive(Debug, Deserialize)]
pub struct AppPasswordForm {
    /// The name to show in the list.
    pub name: String,
}

/// `POST /account/app-passwords`.
pub async fn create_app_password(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Form(form): Form<AppPasswordForm>,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    let Some((_, account)) = current_account(&state, &headers).await else {
        return Ok(redirect("/account/signin"));
    };
    let pool = state.reader.accounts().account_pool();
    let name = form.name.trim();
    if name.is_empty() || name == "__primary__" {
        return Ok(redirect("/account?msg=err-that-name-cannot-be-used"));
    }
    let created = app_password::create(&pool, &account.did, name, false)
        .await
        .map_err(XrpcError::from)?;
    tracing::info!(did = %account.did, name, "portal app-password created");
    Ok(redirect(&format!(
        "/account?secret={}",
        urlencoding_encode(&created.plaintext)
    )))
}

/// `POST /account/app-passwords/revoke`.
pub async fn revoke_app_password(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Form(form): Form<AppPasswordForm>,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    let Some((_, account)) = current_account(&state, &headers).await else {
        return Ok(redirect("/account/signin"));
    };
    let pool = state.reader.accounts().account_pool();
    if form.name.trim() == "__primary__" {
        return Ok(redirect("/account?msg=err-that-name-cannot-be-used"));
    }
    app_password::revoke(&pool, &account.did, form.name.trim())
        .await
        .map_err(XrpcError::from)?;
    tracing::info!(did = %account.did, name = %form.name, "portal app-password revoked");
    Ok(redirect("/account?msg=app-password-revoked"))
}

/// `POST /account/signout-everywhere`.
pub async fn sign_out_everywhere(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Response, XrpcError> {
    require_same_origin(&headers)?;
    let Some((cookie, account)) = current_account(&state, &headers).await else {
        return Ok(redirect("/account/signin"));
    };
    let pool = state.reader.accounts().account_pool();

    // The epoch is the whole mechanism: both credential kinds are stateless
    // JWTs, so this is what makes tokens already in the wild stop working
    // rather than merely stop being renewable.
    let epoch = portal::bump_session_epoch(&pool, &account.did)
        .await
        .map_err(XrpcError::from)?;
    portal::delete_sessions_for(&pool, &account.did, Some(&cookie))
        .await
        .map_err(XrpcError::from)?;
    portal::restamp_session(&pool, &cookie, epoch)
        .await
        .map_err(XrpcError::from)?;
    tracing::info!(did = %account.did, epoch, "portal sign-out everywhere");
    Ok(redirect("/account?msg=signed-out-everywhere"))
}

/// Percent-encode a value for a query string.
fn urlencoding_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cookie_is_read_out_of_a_header_with_neighbours() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            "other=1; atproto_pds_portal=abc123; third=2"
                .parse()
                .unwrap(),
        );
        assert_eq!(cookie_value(&h).as_deref(), Some("abc123"));
    }

    #[test]
    fn a_request_with_no_cookie_has_no_session() {
        assert!(cookie_value(&HeaderMap::new()).is_none());
    }

    #[test]
    fn the_cookie_is_locked_down() {
        let c = set_cookie("v", true, 100);
        // Each of these is load-bearing: HttpOnly keeps script out of a
        // credential that can change the password, SameSite=Strict is the
        // primary CSRF defence, and Path scopes it to the portal.
        assert!(c.contains("HttpOnly"), "{c}");
        assert!(c.contains("SameSite=Strict"), "{c}");
        assert!(c.contains("Path=/account"), "{c}");
        assert!(c.contains("Secure"), "{c}");
        assert!(!set_cookie("v", false, 100).contains("Secure"));
    }

    #[test]
    fn cookie_values_do_not_repeat() {
        let a = new_cookie_value();
        assert_eq!(a.len(), 64);
        assert_ne!(a, new_cookie_value());
    }

    #[test]
    fn a_cross_site_post_is_refused() {
        // GET pages deliberately do not use this guard -- see the note on
        // `require_same_origin`. A link to the sign-in page from anywhere else
        // arrives `cross-site`, and refusing it made the portal unreachable.
        let mut h = HeaderMap::new();
        h.insert("sec-fetch-site", "cross-site".parse().unwrap());
        assert!(require_same_origin(&h).is_err());

        let mut h = HeaderMap::new();
        h.insert("sec-fetch-site", "same-origin".parse().unwrap());
        assert!(require_same_origin(&h).is_ok());

        // A typed URL or bookmark, which is how the sign-in page is reached.
        let mut h = HeaderMap::new();
        h.insert("sec-fetch-site", "none".parse().unwrap());
        assert!(require_same_origin(&h).is_ok());
    }

    #[test]
    fn markup_is_escaped() {
        let out = esc(r#"<script>alert("x")</script>"#);
        assert!(!out.contains('<'), "{out}");
        assert!(out.contains("&lt;script&gt;"), "{out}");
    }
}
