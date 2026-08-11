//! OAuth consent UI — `GET /oauth/authorize` HTML page.
//!
//! after a client
//! redirects the user to `/oauth/authorize?request_uri=...`, the PDS shows
//! a consent form listing the requested scopes and the client's identity.
//! On submit, the form POSTs to the existing `/oauth/authorize` JSON
//! endpoint with `approve=true|false`.
//!
//! Hand-rolled HTML (no Askama dep) — same approach as the admin dashboard.
//! The page ships **friendly scope descriptions** so users see readable text
//! instead of opaque scope strings. Space scopes follow the 0016 spec grammar
//! (`space:<spaceType>[?did&skey&collection&action&manage]`): the space type
//! renders its declaration `name` resolved from its `com.atproto.lexicon.schema`
//! record (NSID fallback; spec line 434), the owner DID renders its
//! bidirectionally-verified handle (DID fallback), and a prominent warning is
//! shown when an app requests access to every space on the network
//! (`type=* && did=*`). The `describe_scope` helper is the single source of
//! truth — a future Askama refactor (deferred polish) drops it into a
//! template directly.

use crate::http::errors::XrpcError;
use crate::http::state::HttpState;
use atproto_oauth::scopes::{Scope, SpaceCollection, SpaceDid, SpacePermission, SpaceType};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;
use std::collections::BTreeMap;

/// Query params accepted by the consent page.
#[derive(Debug, Deserialize)]
pub struct ConsentQuery {
    /// PAR-issued `request_uri` (the consent target).
    pub request_uri: String,
}

/// Reject an authorize request that does not look like a browser navigation.
///
/// The consent screen is where an account holder grants an application access
/// to their repository. Rendering it for a request that a page made *about*
/// the user rather than a navigation *by* the user is the setup for
/// clickjacking and cross-site request forgery: a hostile page can embed or
/// fetch the endpoint and drive the grant without the user ever seeing it.
///
/// `Sec-Fetch-*` are the browser's own account of how a request was initiated,
/// and a page cannot forge them — they are forbidden header names, so script
/// cannot set them. That makes them the one signal here worth trusting.
///
/// The accepted values mirror the reference
/// (`packages/oauth/oauth-provider/src/router/create-authorization-page-middleware.ts`):
///
/// - `sec-fetch-mode: navigate` — the user went here, rather than a page
///   fetching it in the background
/// - `sec-fetch-dest: document` — it is being rendered as a page, not loaded
///   as a script, image or frame subresource
/// - `sec-fetch-site` — any of `same-origin`, `same-site`, `cross-site` or
///   `none`. Deliberately permissive: a client on another origin redirecting
///   the user here is the *ordinary* case, so this header cannot be used to
///   distinguish an attack. The other two carry the weight.
///
/// A request with no `Sec-Fetch-*` headers at all is refused. Every browser
/// that can run an OAuth client sends them, so their absence means the caller
/// is not a browser — and a non-browser has no business rendering a consent
/// screen.
fn require_browser_navigation(parts: &Parts) -> Result<(), XrpcError> {
    let header = |name: &str| {
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .map(str::to_ascii_lowercase)
    };

    let refuse = |detail: String| {
        tracing::warn!(
            detail,
            "refused an authorize request that is not a browser navigation"
        );
        Err(XrpcError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            detail,
        ))
    };

    match header("sec-fetch-mode").as_deref() {
        Some("navigate") => {}
        Some(other) => {
            return refuse(format!(
                "Forbidden sec-fetch-mode header \"{other}\" (expected navigate)"
            ));
        }
        None => return refuse("Missing sec-fetch-mode header".to_string()),
    }

    match header("sec-fetch-dest").as_deref() {
        Some("document") => {}
        Some(other) => {
            return refuse(format!(
                "Forbidden sec-fetch-dest header \"{other}\" (expected document)"
            ));
        }
        None => return refuse("Missing sec-fetch-dest header".to_string()),
    }

    match header("sec-fetch-site").as_deref() {
        Some("same-origin" | "same-site" | "cross-site" | "none") => {}
        Some(other) => {
            return refuse(format!("Forbidden sec-fetch-site header \"{other}\""));
        }
        None => return refuse("Missing sec-fetch-site header".to_string()),
    }

    Ok(())
}

/// `GET /oauth/authorize` — renders the consent form.
///
/// The form action is `POST /oauth/authorize` (the existing JSON endpoint),
/// so the page works as a thin frontend. We do **not** consume the PAR row
/// here — only `peek` it; the JSON POST is what actually exchanges the
/// `request_uri` for an authorization code.
pub async fn consent_page(
    State(state): State<HttpState>,
    parts: Parts,
    Query(q): Query<ConsentQuery>,
) -> Result<Response, XrpcError> {
    require_browser_navigation(&parts)?;

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

    // Best-effort: resolve the space-owner DIDs named in any `space:` scope to
    // their bidirectionally-verified handles, so the consent screen can render
    // a human-readable owner instead of an opaque DID. Failures fall back to
    // the raw DID.
    let handles = resolve_space_owner_handles(&state, &request.scope).await;

    // Best-effort: resolve the space-type NSIDs named in any `space:` scope to
    // their declaration `name` (spec line 434). Failures fall back to the NSID.
    let type_names = resolve_space_type_names(&state, &request.scope).await;
    let permission_sets = resolve_permission_sets(&state, &request.scope).await;

    let html = render_consent(
        &q.request_uri,
        &request.client_id,
        &request.scope,
        request.login_hint.as_deref(),
        &handles,
        &type_names,
        &permission_sets,
    );
    // Never cached. The page is per-user and per-request: it names the client
    // asking, the scopes it wants, and the account being asked. A copy served
    // to someone else -- from a shared proxy, or replayed from history after
    // sign-out -- shows one account's pending grant to whoever comes next.
    //
    // `Pragma` alongside `Cache-Control` for HTTP/1.0 intermediaries, which is
    // what the reference sends.
    let mut response = Html(html).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        axum::http::header::PRAGMA,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    Ok(response)
}

/// Collect the distinct, concrete owner DIDs referenced by `space:` scopes in
/// `scope`, resolve each to a bidirectionally-verified handle, and return the
/// DID→handle map. DIDs that fail verification are simply omitted (callers
/// fall back to the raw DID).
async fn resolve_space_owner_handles(state: &HttpState, scope: &str) -> BTreeMap<String, String> {
    let mut dids: Vec<String> = Vec::new();
    for token in scope.split_whitespace() {
        if let Ok(Scope::Space(perm)) = Scope::parse(token)
            && let SpaceDid::Did(did) = &perm.did
            && !dids.contains(did)
        {
            dids.push(did.clone());
        }
    }

    let mut out = BTreeMap::new();
    for did in dids {
        if let Some(handle) = verify_bidirectional_handle(state, &did).await {
            out.insert(did, handle);
        }
    }
    out
}

/// Collect the distinct, concrete space-type NSIDs referenced by `space:`
/// scopes in `scope`, resolve each to its declaration `name` (spec line 434),
/// and return the NSID→name map. NSIDs that fail to resolve are omitted
/// (callers fall back to the raw NSID).
/// Resolve every `include:` in `scope` to what its permission set says it is.
///
/// A permission set exists so a consent screen can say "Read and write your
/// outlines" instead of reciting seven collections, and this page was showing
/// the NSID — the one string in the document that means nothing to the person
/// being asked. The set's own `title` and `detail` are written for exactly this
/// moment.
///
/// Sets that do not resolve are omitted, and the caller falls back to naming
/// the NSID. Showing the raw scope is poor; inventing a description for a
/// record this server could not read would be worse.
async fn resolve_permission_sets(state: &HttpState, scope: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(resolver) = state.lexicon_resolver.as_ref() else {
        return out;
    };
    for token in scope.split_whitespace() {
        let Ok(Scope::Include(inc)) = Scope::parse(token) else {
            continue;
        };
        if out.contains_key(&inc.nsid) {
            continue;
        }
        let Some(doc) = resolver.resolve(&inc.nsid).await else {
            continue;
        };
        let main = &doc["defs"]["main"];
        if main["type"].as_str() != Some("permission-set") {
            continue;
        }
        let title = main["title"].as_str().unwrap_or(&inc.nsid);
        let detail = main["detail"].as_str().unwrap_or_default();
        let mut described = if detail.is_empty() {
            title.to_string()
        } else {
            format!("{title} — {detail}")
        };
        // The permissions themselves, not only the summary. The description is
        // the client's own words; this is what it actually gets, and the two
        // are not obliged to agree.
        let grants = summarise_permissions(main);
        if !grants.is_empty() {
            described.push_str(" Grants: ");
            described.push_str(&grants.join("; "));
            described.push('.');
        }
        out.insert(inc.nsid.clone(), described);
    }
    out
}

/// One readable line per permission a set declares.
fn summarise_permissions(main: &serde_json::Value) -> Vec<String> {
    let Some(permissions) = main["permissions"].as_array() else {
        return Vec::new();
    };
    permissions
        .iter()
        .filter_map(|perm| {
            let list = |k: &str| -> Vec<String> {
                match &perm[k] {
                    serde_json::Value::String(v) => vec![v.clone()],
                    serde_json::Value::Array(a) => a
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect(),
                    _ => Vec::new(),
                }
            };
            match perm["resource"].as_str()? {
                "repo" => {
                    let mut actions = list("action");
                    if actions.is_empty() {
                        actions = vec!["create".into(), "update".into(), "delete".into()];
                    }
                    let collections = list("collection");
                    if collections.is_empty() {
                        return None;
                    }
                    Some(format!(
                        "{} on {}",
                        actions.join(", "),
                        collections.join(", ")
                    ))
                }
                "blob" => {
                    let accept = list("accept");
                    Some(if accept.is_empty() {
                        "upload files of any type".to_string()
                    } else {
                        format!("upload {}", accept.join(", "))
                    })
                }
                // Named rather than described: this server does not grant it,
                // so claiming it does on the consent screen would be a lie in
                // the one place that must not contain one.
                other => Some(format!("{other} (not granted by this server)")),
            }
        })
        .collect()
}

async fn resolve_space_type_names(state: &HttpState, scope: &str) -> BTreeMap<String, String> {
    let mut nsids: Vec<String> = Vec::new();
    for token in scope.split_whitespace() {
        if let Ok(Scope::Space(perm)) = Scope::parse(token)
            && let SpaceType::Nsid(nsid) = &perm.space_type
            && !nsids.contains(nsid)
        {
            nsids.push(nsid.clone());
        }
    }

    let mut out = BTreeMap::new();
    for nsid in nsids {
        if let Some(name) = resolve_space_declaration_name(state, &nsid).await {
            out.insert(nsid, name);
        }
    }
    out
}

/// Resolve a space-type NSID to its declaration `name` for the consent screen
/// (spec lines 126, 434), via the shared
/// [`SpaceDeclarationResolver`](crate::space::SpaceDeclarationResolver)
/// configured on [`HttpState`].
///
/// This delegates to the same NSID → `com.atproto.lexicon.schema` resolution
/// path (with shared TTL caching) used by the OAuth `space:` scope gate, so the
/// consent UI and the gate never diverge. Returns `None` when no resolver is
/// configured, resolution fails, or the declaration has an empty `name`
/// (callers fall back to the raw NSID).
async fn resolve_space_declaration_name(state: &HttpState, nsid: &str) -> Option<String> {
    let declaration = state
        .space_declaration_resolver
        .as_ref()?
        .resolve(nsid)
        .await?;
    (!declaration.name.is_empty()).then_some(declaration.name)
}

/// Resolve `did` to its handle and verify the binding bidirectionally:
/// resolve the DID document, take its first `at://` `alsoKnownAs`, re-resolve
/// that handle, and require the result to equal `did`. Returns the handle on
/// success, `None` on any failure (network, missing handle, mismatch, or no
/// DNS resolver configured).
async fn verify_bidirectional_handle(state: &HttpState, did: &str) -> Option<String> {
    let dns_resolver = state.dns_resolver.clone()?;
    let plc_hostname = state
        .plc_service
        .as_ref()
        .map(|p| p.directory_hostname().to_string())?;
    let http_client = reqwest::Client::builder()
        .user_agent(crate::user_agent())
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;

    let resolver = atproto_identity::resolve::InnerIdentityResolver {
        dns_resolver,
        http_client: http_client.clone(),
        plc_hostname,
    };

    // DID document → first at:// handle.
    let document = resolver.resolve(did).await.ok()?;
    let handle = document
        .also_known_as
        .iter()
        .find_map(|aka| aka.strip_prefix("at://"))?
        .to_string();

    // Re-resolve the handle and require it to round-trip back to `did`.
    let resolved =
        atproto_identity::resolve::resolve_handle(&http_client, dns_resolver_ref(state)?, &handle)
            .await
            .ok()?;
    if resolved == did {
        Some(handle)
    } else {
        tracing::debug!(
            did,
            handle,
            resolved,
            "consent: bidirectional handle verification mismatch; rendering DID"
        );
        None
    }
}

/// Borrow the configured DNS resolver, if any.
fn dns_resolver_ref(state: &HttpState) -> Option<&dyn atproto_identity::traits::DnsResolver> {
    state.dns_resolver.as_deref()
}

/// The identifier to prefill the sign-in field with, from a client's
/// `login_hint`, or `None` to leave it empty.
///
/// A client that already knows who is signing in says so at PAR time, and the
/// holder should not have to type it again — they arrive at this page from an
/// application that just asked them for exactly this.
///
/// # Why the hint is validated rather than echoed
///
/// `login_hint` is chosen by the client and lands in an HTML attribute on the
/// one page whose whole job is collecting a password. Escaping stops it being
/// markup; validating stops it being *text*. An unvalidated hint renders
/// attacker-chosen prose inside the sign-in box — "type your password here to
/// continue" is a legal string — on a page carrying this server's name and
/// styling. A handle or a DID cannot say anything.
///
/// # Why an email is not prefilled
///
/// The field accepts one, and `login_hint` is a handle or DID by the AT
/// Protocol OAuth spec. Filling in an address a third-party client supplied
/// would also put an email this server never disclosed onto the screen, which
/// is a claim about the account rather than a convenience.
///
/// Handles come back normalized (lowercased, `at://` and `@` stripped) because
/// that is what [`is_valid_handle`] returns and what the account lookup will do
/// anyway; a DID is returned as given, since case is not ours to change.
fn prefill_identifier(hint: Option<&str>) -> Option<String> {
    use atproto_identity::validation::{
        is_valid_did_method_plc, is_valid_did_method_web, is_valid_did_method_webvh,
        is_valid_handle,
    };

    let hint = hint?.trim();
    if hint.is_empty() {
        return None;
    }

    if hint.starts_with("did:") {
        // Non-strict for `did:web`/`did:webvh`: this decides whether to fill a
        // text box, not whether to trust an identity. A path-bearing did:web is
        // a real DID and refusing to type it back helps nobody.
        let known_method = is_valid_did_method_plc(hint)
            || is_valid_did_method_web(hint, false)
            || is_valid_did_method_webvh(hint, false);
        return known_method.then(|| hint.to_string());
    }

    is_valid_handle(hint)
}

fn render_consent(
    request_uri: &str,
    client_id: &str,
    scope: &str,
    login_hint: Option<&str>,
    handles: &BTreeMap<String, String>,
    type_names: &BTreeMap<String, String>,
    permission_sets: &BTreeMap<String, String>,
) -> String {
    let scopes_list: String = scope
        .split_whitespace()
        .map(|s| {
            let raw = html_escape(s);
            let description = describe_scope(s, handles, type_names, permission_sets);
            format!(
                "<li><code>{raw}</code><div class=\"scope-desc\">{}</div></li>",
                html_escape(&description),
            )
        })
        .collect();

    // Loud warning when any space scope grants access to *every* space on the
    // network (`type=* && did=*`) — the prominent-warning requirement of spec
    // lines 437-438.
    let universal_warning = if has_universal_space_scope(scope) {
        r#"<div class="space-warning"><strong>Warning:</strong> this application is requesting access to <b>every space on the network</b>. This is an extremely broad permission. Only grant it to applications you deeply trust.</div>"#
    } else {
        ""
    };

    // Prefilled from `login_hint` when the client named a handle or DID.
    // Focus follows the value: with the identifier already filled, the first
    // thing left to do is type the password, and landing the cursor on a field
    // that is already correct makes the holder check it rather than use it.
    let prefill = prefill_identifier(login_hint);
    let identifier_value = prefill
        .as_deref()
        .map(|v| format!(r#" value="{}""#, html_escape(v)))
        .unwrap_or_default();
    let (identifier_autofocus, password_autofocus) = if prefill.is_some() {
        ("", " autofocus")
    } else {
        (" autofocus", "")
    };

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>atproto-pds — authorize {client_id}</title>
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
    input[type=text], input[type=password] {{
      width: 100%; padding: 0.5em; border: 1px solid #ccc; border-radius: 4px;
      font-size: 1em; box-sizing: border-box;
    }}
    .scopes {{ background: #f0f0f0; padding: 0.6em 0.8em; border-radius: 4px;
              font-size: 0.9em; margin: 1em 0; }}
    .scopes ul {{ margin: 0.3em 0 0 1.2em; padding: 0; }}
    .scopes li {{ margin-bottom: 0.4em; }}
    .scope-desc {{ color: #555; font-size: 0.85em; margin-left: 0.2em; }}
    .space-warning {{
      background: #fff4f4; border: 1px solid #e0b4b4; color: #7a1f1f;
      border-radius: 6px; padding: 0.8em 1em; margin: 1em 0; font-size: 0.9em;
    }}
    button {{
      padding: 0.6em 1.2em; border: 0; border-radius: 4px;
      font-size: 1em; cursor: pointer; margin-right: 0.5em;
    }}
    .approve {{ background: #2563eb; color: white; }}
    .deny    {{ background: #e5e5e5; color: #333; }}
    code {{ font-family: ui-monospace, "SFMono-Regular", Menlo, monospace; font-size: 0.9em; }}
    .meta {{ font-size: 0.8em; color: #777; margin-top: 1.5em; }}
  </style>
</head>
<body>
  <h1>Authorize {client_id_safe}</h1>
  <p>Sign in to grant access to your account.</p>

  {universal_warning}

  <div class="scopes">
    Requested scopes:
    <ul>{scopes_list}</ul>
  </div>

  <form method="POST" action="/oauth/authorize" enctype="application/json"
        onsubmit="return submitJson(event, this)">
    <fieldset>
      <legend>Sign in</legend>
      <label for="identifier">Handle, DID, or email</label>
      <input id="identifier" name="identifier" type="text" autocomplete="username" required{identifier_value}{identifier_autofocus}>

      <label for="password">Account password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required{password_autofocus}>

      <input type="hidden" name="request_uri" value="{request_uri_safe}">
    </fieldset>

    <p style="margin-top: 1em;">
      <button class="approve" type="submit" name="approve" value="true">Approve</button>
      <button class="deny" type="submit" name="approve" value="false">Deny</button>
    </p>
  </form>

  <p class="meta">
    Powered by <code>atproto-pds</code>. Scopes shown above are what
    <code>{client_id_safe}</code> requested. Approving gives only those.
  </p>

  <script>
    // Lift the form-encoded POST into a JSON POST that the JSON authorize
    // endpoint understands. No JS framework — three lines.
    function submitJson(ev, form) {{
      ev.preventDefault();
      var data = {{
        request_uri: form.request_uri.value,
        identifier:  form.identifier.value,
        password:    form.password.value,
        approve:     ev.submitter && ev.submitter.value === 'true'
      }};
      fetch(form.action, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(data)
      }}).then(function(r) {{
        return r.json().then(function(j) {{ return [r, j]; }});
      }}).then(function(pair) {{
        var resp = pair[0], body = pair[1];
        if (!resp.ok) {{
          document.body.insertAdjacentHTML('beforeend',
            '<p style="color:#b00">Error: ' + (body.message || resp.statusText) + '</p>');
          return;
        }}
        // On success, redirect with code + state + iss per RFC 9207.
        var url = body.redirect_uri + '?code=' + encodeURIComponent(body.code)
          + '&state=' + encodeURIComponent(body.state)
          + '&iss=' + encodeURIComponent(body.iss);
        window.location = url;
      }});
      return false;
    }}
  </script>
</body>
</html>
"#,
        client_id = html_escape(client_id),
        client_id_safe = html_escape(client_id),
        request_uri_safe = html_escape(request_uri),
        scopes_list = scopes_list,
        universal_warning = universal_warning,
    )
}

/// `true` when any `space:` scope in `scope` grants access to every space on
/// the network — i.e. its `type` is `*` **and** its `authority` is `*`.
///
/// Both halves are load-bearing, and the authority half more than it looks. A
/// bare `space:*` is *not* universal: `authority` defaults to `self`, so it
/// covers every space type under the signing-in user's own DID and nothing
/// else. Warning on that would train users to dismiss the warning.
fn has_universal_space_scope(scope: &str) -> bool {
    scope.split_whitespace().any(|token| {
        matches!(
            Scope::parse(token),
            Ok(Scope::Space(perm))
                if perm.space_type == SpaceType::All && perm.did == SpaceDid::All
        )
    })
}

/// Convert a raw OAuth scope token into a human-readable description for the
/// consent page. Recognizes:
///
/// - `atproto` → "core atproto session — sign in to your account"
/// - `transition:generic` → "all atproto records (legacy transition scope)"
/// - `transition:chat.bsky` → "Bluesky chat records (legacy transition scope)"
/// - `space:<type>[?did&skey&collection&action]` → a description built from the
///   real space-scope grammar via [`describe_space_scope`].
///
/// Unknown scopes fall back to a generic "request access to scope <s>"
/// string so the user still sees something readable.
///
/// `handles` maps space-owner DIDs to their bidirectionally-verified handles;
/// space scopes render the handle when present, the DID otherwise.
/// `type_names` maps space-type NSIDs to their resolved declaration names
/// (spec line 434); absent entries fall back to the raw NSID.
pub fn describe_scope(
    scope: &str,
    handles: &BTreeMap<String, String>,
    type_names: &BTreeMap<String, String>,
    permission_sets: &BTreeMap<String, String>,
) -> String {
    // A permission set describes itself, in words written for this screen.
    if let Ok(Scope::Include(inc)) = Scope::parse(scope) {
        return match permission_sets.get(&inc.nsid) {
            Some(described) => described.clone(),
            // Unresolved: name it plainly rather than dress it up.
            None => format!(
                "a permission set this server could not read ({}) — nothing is granted for it",
                inc.nsid
            ),
        };
    }
    if scope == "atproto" {
        return "core atproto session — sign in to your account".to_string();
    }
    if let Some(rest) = scope.strip_prefix("transition:") {
        return match rest {
            "generic" => "all atproto records (legacy transition scope)".to_string(),
            "chat.bsky" => "Bluesky chat records (legacy transition scope)".to_string(),
            other => format!("legacy transition scope `{other}`"),
        };
    }
    if scope == "space" || scope.starts_with("space:") || scope.starts_with("space?") {
        return match Scope::parse(scope) {
            Ok(Scope::Space(perm)) => describe_space_scope(&perm, handles, type_names),
            // A `space:` prefix that fails to parse is a malformed scope; show
            // it verbatim rather than a misleading description.
            _ => format!("malformed Spaces scope `{scope}`"),
        };
    }
    format!("request access to scope `{scope}`")
}

/// Build a human-readable description of a parsed `space:` permission, using
/// the real grammar (`type`, `did`, `skey`, `collection`, `action`).
///
/// - The space *type* renders its declaration name when resolvable, falling
///   back to the raw NSID (or "any space type" for the `*` wildcard).
/// - The *owner* renders its verified handle (from `handles`) when available,
///   the raw DID otherwise, or "any owner" for `*`.
/// - The *actions* render as a friendly verb list (read / create / update /
///   delete / manage).
pub fn describe_space_scope(
    perm: &SpacePermission,
    handles: &BTreeMap<String, String>,
    type_names: &BTreeMap<String, String>,
) -> String {
    let type_label = match &perm.space_type {
        SpaceType::All => "any space type".to_string(),
        SpaceType::Nsid(nsid) => space_type_declaration_name(nsid, type_names),
    };

    let owner_label = match &perm.did {
        // The default, and the narrow case: only the signing-in user's own
        // spaces. Worth saying plainly, because "any owner" and "your own" are
        // very different grants and this line is what the user reads before
        // deciding.
        SpaceDid::SelfDid => "your own".to_string(),
        SpaceDid::All => "any owner".to_string(),
        SpaceDid::Did(did) => handles
            .get(did)
            .map(|h| format!("@{h}"))
            .unwrap_or_else(|| did.clone()),
    };

    // Record action verbs in canonical order (BTreeSet iteration is sorted by
    // the SpaceAction Ord: read_self, read, create, update, delete).
    let actions: Vec<&str> = perm.action.iter().map(|a| a.as_str()).collect();
    let actions_label = if actions.is_empty() {
        "no".to_string()
    } else {
        actions.join(", ")
    };

    // Collections constrain the write actions; neither read action consults
    // them. `Default` defers to the declaration's collections (not enumerable
    // here); an explicit empty list means no write targets.
    let collections_label = match &perm.collection {
        atproto_oauth::scopes::SpaceCollections::Default => {
            Some("the space type's declared collections".to_string())
        }
        atproto_oauth::scopes::SpaceCollections::Explicit(set) if set.is_empty() => None,
        atproto_oauth::scopes::SpaceCollections::Explicit(set) => {
            let names: Vec<String> = set
                .iter()
                .map(|c| match c {
                    SpaceCollection::All => "any collection".to_string(),
                    SpaceCollection::Nsid(nsid) => nsid.clone(),
                })
                .collect();
            Some(names.join(", "))
        }
    };

    let mut out = format!("{actions_label} access to {type_label} spaces owned by {owner_label}");
    match &perm.skey {
        atproto_oauth::scopes::SpaceSkey::Key(skey) => {
            out.push_str(&format!(" (space key `{skey}`)"));
        }
        atproto_oauth::scopes::SpaceSkey::All => {}
    }
    if let Some(cols) = collections_label {
        out.push_str(&format!(", collections: {cols}"));
    }
    // Space-management verbs are a separate axis; surface them prominently.
    if !perm.manage.is_empty() {
        let verbs: Vec<&str> = perm.manage.iter().map(|m| m.as_str()).collect();
        out.push_str(&format!("; manage the spaces ({})", verbs.join(", ")));
    }
    out
}

/// Render a space-type NSID's declaration `name` (spec line 434), falling back
/// to the raw NSID when the declaration could not be resolved.
///
/// `type_names` is the NSID→declaration-name map produced by
/// [`resolve_space_type_names`]; absent entries fall back to the NSID.
fn space_type_declaration_name(nsid: &str, type_names: &BTreeMap<String, String>) -> String {
    type_names
        .get(nsid)
        .cloned()
        .unwrap_or_else(|| nsid.to_string())
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_handles() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    fn no_names() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    #[test]
    fn render_includes_client_id_and_scopes() {
        let html = render_consent(
            "urn:ietf:params:oauth:request_uri:abcd",
            "https://app.example/client-metadata.json",
            "atproto transition:generic",
            None,
            &no_handles(),
            &no_names(),
            &no_names(),
        );
        assert!(html.contains("https://app.example/client-metadata.json"));
        assert!(html.contains("atproto"));
        assert!(html.contains("transition:generic"));
        assert!(html.contains("urn:ietf:params:oauth:request_uri:abcd"));
        assert!(html.contains("Approve"));
        assert!(html.contains("Deny"));
    }

    #[test]
    fn render_escapes_client_id_html() {
        let html = render_consent(
            "uri",
            "https://evil/<script>",
            "atproto",
            None,
            &no_handles(),
            &no_names(),
            &no_names(),
        );
        // The injected `<script>` substring must show up escaped in the
        // attacker-controlled positions (page title + body header). The page
        // legitimately contains its own `<script>` block for the form submit
        // helper, so we assert *count* not *absence*: there should be exactly
        // one occurrence of `<script>` (the legit one) and one of `&lt;script&gt;`
        // (the escaped attacker payload).
        assert!(html.contains("&lt;script&gt;"));
        let unescaped_count = html.matches("<script>").count();
        assert_eq!(unescaped_count, 1, "only the legit form-submit script tag");
    }

    #[test]
    fn render_handles_empty_scope() {
        let html = render_consent(
            "uri",
            "client",
            "",
            None,
            &no_handles(),
            &no_names(),
            &no_names(),
        );
        assert!(html.contains("Requested scopes"));
    }

    /// A permission set describes itself in the words written for this screen.
    #[test]
    fn describe_scope_renders_a_permission_set() {
        let mut sets = BTreeMap::new();
        sets.insert(
            "app.bulleted.appAccess".to_string(),
            "Bulleted — Read and write your outlines, bullets, and notes. \
             Grants: create, update, delete on app.bulleted.outline."
                .to_string(),
        );

        let d = describe_scope(
            "include:app.bulleted.appAccess",
            &no_handles(),
            &no_names(),
            &sets,
        );

        assert!(d.contains("Bulleted"), "the set's title is missing: {d}");
        assert!(d.contains("Read and write your outlines"), "{d}");
        assert!(
            d.contains("app.bulleted.outline"),
            "what is actually granted must be shown, not only the summary: {d}"
        );
        assert!(
            !d.starts_with("include:"),
            "the raw scope is what this replaced: {d}"
        );
    }

    /// An unresolved set says so rather than inventing a description.
    #[test]
    fn describe_scope_admits_an_unresolved_permission_set() {
        let d = describe_scope(
            "include:app.example.unknown",
            &no_handles(),
            &no_names(),
            &no_names(),
        );

        assert!(d.contains("could not read"), "{d}");
        assert!(d.contains("app.example.unknown"), "{d}");
        assert!(
            d.contains("nothing is granted"),
            "an unreadable set grants nothing and the page must say so: {d}"
        );
    }

    /// The permission lines name collections and actions, not counts.
    #[test]
    fn permissions_are_summarised_in_full() {
        let main = serde_json::json!({
            "type": "permission-set",
            "permissions": [
                {"resource": "repo", "action": ["create", "update"],
                 "collection": ["app.x.one", "app.x.two"]},
                {"resource": "blob", "accept": ["image/png"]},
                {"resource": "something-new"},
            ],
        });

        let lines = summarise_permissions(&main);

        assert!(
            lines.iter().any(|l| l.contains("app.x.one, app.x.two")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("create, update")),
            "{lines:?}"
        );
        assert!(lines.iter().any(|l| l.contains("image/png")), "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|l| l.contains("not granted by this server")),
            "a resource this server ignores must not read as granted: {lines:?}"
        );
    }

    /// An omitted action list is every action, and the page must say all three.
    #[test]
    fn an_omitted_action_list_is_shown_as_all_three() {
        let main = serde_json::json!({
            "type": "permission-set",
            "permissions": [{"resource": "repo", "collection": ["app.x.one"]}],
        });

        let lines = summarise_permissions(&main);

        assert!(lines[0].contains("create, update, delete"), "{lines:?}");
    }

    #[test]
    fn describe_scope_atproto_core() {
        let d = describe_scope("atproto", &no_handles(), &no_names(), &no_names());
        assert!(d.contains("core atproto session"));
    }

    #[test]
    fn describe_scope_transition_generic() {
        let d = describe_scope(
            "transition:generic",
            &no_handles(),
            &no_names(),
            &no_names(),
        );
        assert!(d.contains("all atproto records"));
    }

    #[test]
    fn describe_scope_space_read_only() {
        // `action=read` on a concrete type; no authority/skey → "your own",
        // because `authority` defaults to `self`.
        let d = describe_scope(
            "space:app.bsky.group?action=read",
            &no_handles(),
            &no_names(),
            &no_names(),
        );
        assert!(d.contains("read access to"), "got: {d}");
        assert!(d.contains("app.bsky.group"), "got: {d}");
        assert!(d.contains("your own"), "got: {d}");
    }

    #[test]
    fn describe_scope_space_default_actions() {
        // Bare `space:<type>` defaults to {read, create, update, delete} — no
        // manage (manage is a separate, none-by-default parameter).
        let d = describe_scope(
            "space:app.bsky.group",
            &no_handles(),
            &no_names(),
            &no_names(),
        );
        assert!(d.contains("read"), "got: {d}");
        assert!(d.contains("create"), "got: {d}");
        assert!(
            !d.contains("manage"),
            "default grant confers no manage, got: {d}"
        );
        assert!(d.contains("app.bsky.group"), "got: {d}");
    }

    #[test]
    fn describe_scope_space_manage_surfaced() {
        let d = describe_scope(
            "space:app.bsky.group?manage=update&manage=delete",
            &no_handles(),
            &no_names(),
            &no_names(),
        );
        assert!(d.contains("manage the spaces"), "got: {d}");
        assert!(d.contains("update"), "got: {d}");
        assert!(d.contains("delete"), "got: {d}");
    }

    #[test]
    fn describe_scope_space_read_self() {
        let d = describe_scope(
            "space:app.bsky.group?action=read_self&collection=app.bsky.feed.post",
            &no_handles(),
            &no_names(),
            &no_names(),
        );
        assert!(d.contains("read_self"), "got: {d}");
        assert!(d.contains("app.bsky.feed.post"), "got: {d}");
    }

    #[test]
    fn describe_scope_space_renders_declaration_name() {
        // A resolved declaration name replaces the raw NSID (spec line 434).
        let mut names = BTreeMap::new();
        names.insert("app.bsky.group".to_string(), "Bluesky Group".to_string());
        let d = describe_scope(
            "space:app.bsky.group?action=read",
            &no_handles(),
            &names,
            &no_names(),
        );
        assert!(d.contains("Bluesky Group"), "got: {d}");
        assert!(
            !d.contains("app.bsky.group"),
            "should prefer name, got: {d}"
        );
    }

    #[test]
    fn describe_scope_space_renders_handle_when_known() {
        let mut handles = BTreeMap::new();
        handles.insert("did:plc:abc".to_string(), "alice.example".to_string());
        let d = describe_scope(
            "space:app.bsky.group?did=did:plc:abc&action=read",
            &handles,
            &no_names(),
            &no_names(),
        );
        assert!(d.contains("@alice.example"), "got: {d}");
        assert!(!d.contains("did:plc:abc"), "should prefer handle, got: {d}");
    }

    #[test]
    fn describe_scope_space_falls_back_to_did() {
        let d = describe_scope(
            "space:app.bsky.group?did=did:plc:xyz&action=read",
            &no_handles(),
            &no_names(),
            &no_names(),
        );
        assert!(d.contains("did:plc:xyz"), "got: {d}");
    }

    #[test]
    fn describe_scope_space_skey_and_collection() {
        let d = describe_scope(
            "space:app.bsky.group?skey=team&collection=app.bsky.feed.post&action=create",
            &no_handles(),
            &no_names(),
            &no_names(),
        );
        assert!(d.contains("team"), "got: {d}");
        assert!(d.contains("app.bsky.feed.post"), "got: {d}");
        assert!(d.contains("create"), "got: {d}");
    }

    #[test]
    fn describe_scope_space_malformed() {
        // A `space:` prefix with no positional type is invalid.
        let d = describe_scope("space:", &no_handles(), &no_names(), &no_names());
        assert!(d.contains("malformed"), "got: {d}");
    }

    #[test]
    fn describe_scope_unknown_falls_back() {
        let d = describe_scope(
            "custom:something:weird",
            &no_handles(),
            &no_names(),
            &no_names(),
        );
        assert!(d.contains("custom:something:weird"));
    }

    #[test]
    fn universal_warning_triggers_on_type_and_did_wildcard() {
        // Universal needs both wildcards: any type *and* any authority.
        assert!(has_universal_space_scope("space:*?authority=*"));
        let html = render_consent(
            "uri",
            "client",
            "space:*?authority=*",
            None,
            &no_handles(),
            &no_names(),
            &no_names(),
        );
        assert!(html.contains("every space on the network"));
        assert!(html.contains("space-warning"));

        // A bare `space:*` is every space *type* under the user's own DID, and
        // must not raise the network-wide warning — a warning shown on a
        // narrow grant is a warning users learn to dismiss.
        assert!(!has_universal_space_scope("space:*"));
        let own = render_consent(
            "uri",
            "client",
            "space:*",
            None,
            &no_handles(),
            &no_names(),
            &no_names(),
        );
        assert!(!own.contains("every space on the network"));
    }

    #[test]
    fn universal_warning_absent_when_did_anchored() {
        // A concrete did anchors the scope → not universal.
        assert!(!has_universal_space_scope("space:*?did=did:plc:abc"));
        let html = render_consent(
            "uri",
            "client",
            "space:*?did=did:plc:abc",
            None,
            &no_handles(),
            &no_names(),
            &no_names(),
        );
        assert!(!html.contains("every space on the network"));
    }

    #[test]
    fn universal_warning_absent_for_concrete_type() {
        assert!(!has_universal_space_scope("space:app.bsky.group"));
    }

    #[test]
    fn render_includes_friendly_descriptions() {
        let html = render_consent(
            "uri",
            "https://app.example/cm",
            "atproto space:app.bsky.group?action=read",
            None,
            &no_handles(),
            &no_names(),
            &no_names(),
        );
        assert!(html.contains("core atproto session"));
        assert!(html.contains("read access to"));
    }

    // --- login_hint prefill --------------------------------------------------

    /// A handle hint fills the field, normalized.
    #[test]
    fn a_handle_hint_prefills_the_identifier() {
        let html = render_consent(
            "uri",
            "client",
            "atproto",
            Some("Alice.Example.com"),
            &no_handles(),
            &no_names(),
            &no_names(),
        );
        assert!(
            html.contains(r#"value="alice.example.com""#),
            "the handle was not prefilled: {html}"
        );
    }

    /// `at://` and `@` forms are what clients actually send.
    #[test]
    fn decorated_handle_hints_are_stripped() {
        for hint in ["at://alice.example.com", "@alice.example.com"] {
            assert_eq!(
                prefill_identifier(Some(hint)).as_deref(),
                Some("alice.example.com"),
                "{hint}"
            );
        }
    }

    /// A DID hint fills the field as given -- case is not ours to change.
    #[test]
    fn did_hints_prefill_across_methods() {
        for hint in [
            "did:plc:f6ousnmkackzyuei5iiosom6",
            "did:web:example.com",
            "did:web:example.com:path",
        ] {
            assert_eq!(
                prefill_identifier(Some(hint)).as_deref(),
                Some(hint),
                "{hint}"
            );
        }
    }

    /// Anything that is not a handle or a DID leaves the field empty.
    ///
    /// The email case is deliberate: the field accepts one, but `login_hint` is
    /// a handle or DID per the spec, and echoing an address a third-party client
    /// supplied is a claim about the account rather than a convenience.
    #[test]
    fn a_hint_that_is_neither_handle_nor_did_is_ignored() {
        for hint in [
            "alice@example.com",    // email
            "not a handle",         // spaces
            "localhost",            // no dot
            "did:unknown:whatever", // unsupported method
            "did:plc:",             // malformed
            "",                     // empty
            "   ",                  // whitespace only
        ] {
            assert_eq!(
                prefill_identifier(Some(hint)),
                None,
                "{hint:?} should not prefill"
            );
        }
        assert_eq!(prefill_identifier(None), None);
    }

    /// A hostile hint cannot break out of the attribute, and cannot speak.
    ///
    /// Two defences, and the test asserts both: validation refuses the value
    /// outright, so the markup never carries it. A hint that *is* a valid handle
    /// still goes through `html_escape` on the way into the attribute.
    #[test]
    fn a_hostile_hint_never_reaches_the_page() {
        let hostile = [
            r#"" autofocus onfocus="alert(1)"#,
            "<script>alert(1)</script>",
            "type your password here to continue",
        ];
        for hint in hostile {
            assert_eq!(
                prefill_identifier(Some(hint)),
                None,
                "{hint:?} was accepted"
            );
            let html = render_consent(
                "uri",
                "client",
                "atproto",
                Some(hint),
                &no_handles(),
                &no_names(),
                &no_names(),
            );
            assert!(!html.contains("onfocus"), "{hint:?} injected an attribute");
            assert!(
                !html.contains("<script>alert"),
                "{hint:?} injected a script"
            );
            assert!(
                !html.contains("type your password here"),
                "{hint:?} put attacker prose on the page"
            );
        }
    }

    /// With no hint the identifier keeps focus; with one, focus moves on.
    #[test]
    fn focus_follows_the_prefill() {
        let without = render_consent(
            "uri",
            "client",
            "atproto",
            None,
            &no_handles(),
            &no_names(),
            &no_names(),
        );
        assert!(
            without.contains(r#"id="identifier""#) && without.contains("autofocus"),
            "the identifier should be focused when empty"
        );
        assert_eq!(without.matches("autofocus").count(), 1);

        let with = render_consent(
            "uri",
            "client",
            "atproto",
            Some("alice.example.com"),
            &no_handles(),
            &no_names(),
            &no_names(),
        );
        assert_eq!(
            with.matches("autofocus").count(),
            1,
            "exactly one field focused"
        );
        let password_line = with
            .lines()
            .find(|l| l.contains(r#"id="password""#))
            .expect("password field");
        assert!(
            password_line.contains("autofocus"),
            "focus should move to the password once the identifier is filled"
        );
    }
}
