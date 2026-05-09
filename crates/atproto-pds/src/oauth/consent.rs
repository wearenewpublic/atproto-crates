//! OAuth consent UI — `GET /oauth/authorize` HTML page.
//!
//! after a client
//! redirects the user to `/oauth/authorize?request_uri=...`, the PDS shows
//! a consent form listing the requested scopes and the client's identity.
//! On submit, the form POSTs to the existing `/oauth/authorize` JSON
//! endpoint with `approve=true|false`.
//!
//! Hand-rolled HTML (no Askama dep) — same approach as the admin dashboard.
//! the page now ships **friendly scope
//! descriptions** so users see "Allow `app.example` to read your
//! `app.bsky.group/default` records" instead of opaque scope strings like
//! `space:read:app.bsky.group/default`. The `describe_scope` helper is
//! the single source of truth — a future Askama refactor (deferred polish)
//! drops it into a template directly.

use crate::http::errors::XrpcError;
use crate::http::state::HttpState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;

/// Query params accepted by the consent page.
#[derive(Debug, Deserialize)]
pub struct ConsentQuery {
    /// PAR-issued `request_uri` (the consent target).
    pub request_uri: String,
}

/// `GET /oauth/authorize` — renders the consent form.
///
/// The form action is `POST /oauth/authorize` (the existing JSON endpoint),
/// so the page works as a thin frontend. We do **not** consume the PAR row
/// here — only `peek` it; the JSON POST is what actually exchanges the
/// `request_uri` for an authorization code.
pub async fn consent_page(
    State(state): State<HttpState>,
    Query(q): Query<ConsentQuery>,
) -> Result<Response, XrpcError> {
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

    let html = render_consent(&q.request_uri, &request.client_id, &request.scope);
    Ok(Html(html).into_response())
}

fn render_consent(request_uri: &str, client_id: &str, scope: &str) -> String {
    let scopes_list: String = scope
        .split_whitespace()
        .map(|s| {
            let raw = html_escape(s);
            let description = describe_scope(s);
            format!(
                "<li><code>{raw}</code><div class=\"scope-desc\">{}</div></li>",
                html_escape(&description),
            )
        })
        .collect();

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

  <div class="scopes">
    Requested scopes:
    <ul>{scopes_list}</ul>
  </div>

  <form method="POST" action="/oauth/authorize" enctype="application/json"
        onsubmit="return submitJson(event, this)">
    <fieldset>
      <legend>Sign in</legend>
      <label for="identifier">Handle, DID, or email</label>
      <input id="identifier" name="identifier" type="text" autocomplete="username" required>

      <label for="password">Password (account or app password)</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>

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
    )
}

/// Convert a raw OAuth scope token into a human-readable description for the
/// consent page. Recognizes:
///
/// - `atproto` → "core atproto session — sign in to your account"
/// - `transition:generic` → "all atproto records (legacy transition scope)"
/// - `transition:chat.bsky` → "Bluesky chat records (legacy transition scope)"
/// - `space:read:<type>/<key>` → "read your Spaces records under <type>/<key>"
/// - `space:write:<type>/<key>` → "create and update your Spaces records under <type>/<key>"
/// - `space:admin:<type>/<key>` → "manage members of your Spaces under <type>/<key>"
///
/// Unknown scopes fall back to a generic "request access to scope <s>"
/// string so the user still sees something readable.
pub fn describe_scope(scope: &str) -> String {
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
    if let Some(rest) = scope.strip_prefix("space:") {
        // Format: space:<verb>:<type>/<key>  e.g. space:read:app.bsky.group/default
        let mut parts = rest.splitn(2, ':');
        let verb = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("");
        let target_friendly = if target.is_empty() {
            "all your Spaces"
        } else {
            target
        };
        return match verb {
            "read" => format!("read your Spaces records under `{target_friendly}`"),
            "write" => format!("create and update your Spaces records under `{target_friendly}`"),
            "admin" => format!("manage members of your Spaces under `{target_friendly}`"),
            other => format!("`{other}` Spaces access under `{target_friendly}`"),
        };
    }
    format!("request access to scope `{scope}`")
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

    #[test]
    fn render_includes_client_id_and_scopes() {
        let html = render_consent(
            "urn:ietf:params:oauth:request_uri:abcd",
            "https://app.example/client-metadata.json",
            "atproto transition:generic",
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
        let html = render_consent("uri", "https://evil/<script>", "atproto");
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
        let html = render_consent("uri", "client", "");
        assert!(html.contains("Requested scopes"));
    }

    #[test]
    fn describe_scope_atproto_core() {
        let d = describe_scope("atproto");
        assert!(d.contains("core atproto session"));
    }

    #[test]
    fn describe_scope_transition_generic() {
        let d = describe_scope("transition:generic");
        assert!(d.contains("all atproto records"));
    }

    #[test]
    fn describe_scope_space_read() {
        let d = describe_scope("space:read:app.bsky.group/default");
        assert!(d.contains("read your Spaces records"));
        assert!(d.contains("app.bsky.group/default"));
    }

    #[test]
    fn describe_scope_space_write() {
        let d = describe_scope("space:write:app.bsky.group/default");
        assert!(d.contains("create and update"));
    }

    #[test]
    fn describe_scope_unknown_falls_back() {
        let d = describe_scope("custom:something:weird");
        assert!(d.contains("custom:something:weird"));
    }

    #[test]
    fn render_includes_friendly_descriptions() {
        let html = render_consent(
            "uri",
            "https://app.example/cm",
            "atproto space:read:app.bsky.group/default",
        );
        assert!(html.contains("core atproto session"));
        assert!(html.contains("read your Spaces records"));
    }
}
