#![allow(clippy::type_complexity)] // SQL row tuples; named aliases would just shift the noise.
//! Minimal admin HTML dashboard.
//!
//!  the admin surface
//! ships with a small operational dashboard so operators can spot-check
//! account counts, account state breakdown, and recent invite issuance
//! without needing to script `getInviteCodes` / `searchAccounts` themselves.
//!
//! This is intentionally a single-page server-rendered HTML view (no JS, no
//! framework) — the same Basic-auth gate as the JSON admin API protects it.
//! Bigger UIs (record-level moderation, takedown bulk-ops) are an
//! operational-tooling concern, kept outside the PDS binary.

use crate::admin::handlers::DEFAULT_ADMIN_PASSWORD;
use crate::http::errors::XrpcError;
use crate::http::state::HttpState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::response::{Html, IntoResponse, Response};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64STD};

fn require_admin(parts: &Parts, state: &HttpState) -> Result<(), XrpcError> {
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
            "Authorization header is not base64",
        )
    })?;
    let s = String::from_utf8(decoded).map_err(|_| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Authorization header is not UTF-8",
        )
    })?;
    let (_, password) = s.split_once(':').ok_or_else(|| {
        XrpcError::new(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "expected user:pass",
        )
    })?;
    let expected = state
        .admin_password
        .as_deref()
        .unwrap_or(DEFAULT_ADMIN_PASSWORD);
    if password != expected {
        return Err(XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "AdminAuthenticationFailed",
            "invalid admin password",
        ));
    }
    Ok(())
}

/// Render the admin status dashboard.
///
/// Reports:
/// - account counts by state
/// - 10 most recent invite codes
/// - PDS service DID + build rev
pub async fn dashboard(
    State(state): State<HttpState>,
    parts: Parts,
) -> Result<Response, XrpcError> {
    require_admin(&parts, &state)?;
    let manager = state.account_manager.as_deref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account manager not configured",
        )
    })?;

    // §5.4 — both reads route through `AccountPool` dispatch.
    // The dashboard uses the typed helpers so SQLite-vs-Postgres SQL
    // dialect selection stays in one place per table.
    let by_state = manager.counts_by_state().await.map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("count by state: {e}"),
        )
    })?;
    let total_accounts: i64 = by_state.iter().map(|(_, n)| *n).sum();

    let recent_invites_rows = crate::account::invite::list_recent(&manager.account_pool(), 10)
        .await
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("list invites: {e}"),
            )
        })?;
    // The renderer wants (code, created_by, available_uses, used_by,
    // created_at) tuples — keep the existing render_dashboard signature
    // by projecting the typed `InviteCodeRow` into that shape here.
    let recent_invites: Vec<(String, Option<String>, i64, Option<String>, String)> =
        recent_invites_rows
            .into_iter()
            .map(|r| {
                (
                    r.code,
                    r.created_by_did,
                    r.available_uses as i64,
                    r.used_by,
                    r.created_at,
                )
            })
            .collect();

    let html = render_dashboard(
        &state.service_did,
        crate::BUILD_REV,
        total_accounts,
        &by_state,
        &recent_invites,
    );
    Ok(Html(html).into_response())
}

fn render_dashboard(
    service_did: &str,
    build_rev: &str,
    total_accounts: i64,
    by_state: &[(String, i64)],
    recent_invites: &[(String, Option<String>, i64, Option<String>, String)],
) -> String {
    let by_state_rows: String = by_state
        .iter()
        .map(|(s, n)| {
            format!(
                "<tr><td>{}</td><td class=\"r\">{}</td></tr>",
                html_escape(s),
                n
            )
        })
        .collect();
    let invite_rows: String = if recent_invites.is_empty() {
        "<tr><td colspan=\"5\" class=\"muted\">no invite codes issued yet</td></tr>".to_string()
    } else {
        recent_invites
            .iter()
            .map(|(code, created_by, available_uses, used_by, created_at)| {
                format!(
                    "<tr><td><code>{}</code></td><td>{}</td><td class=\"r\">{}</td><td>{}</td><td>{}</td></tr>",
                    html_escape(code),
                    html_escape(created_by.as_deref().unwrap_or("(admin)")),
                    available_uses,
                    html_escape(used_by.as_deref().unwrap_or("—")),
                    html_escape(created_at),
                )
            })
            .collect()
    };

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>atproto-pds — admin dashboard</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
      max-width: 880px; margin: 2em auto; padding: 0 1em;
      color: #1a1a1a; background: #fafafa;
    }}
    h1, h2 {{ font-weight: 600; }}
    h1 {{ font-size: 1.4em; border-bottom: 2px solid #333; padding-bottom: 0.3em; }}
    h2 {{ font-size: 1.1em; margin-top: 2em; color: #333; }}
    table {{ width: 100%; border-collapse: collapse; margin: 0.5em 0; }}
    th, td {{ padding: 0.4em 0.6em; border-bottom: 1px solid #ddd; text-align: left; }}
    th {{ background: #eaeaea; font-weight: 600; }}
    td.r {{ text-align: right; font-variant-numeric: tabular-nums; }}
    code {{ font-family: ui-monospace, "SFMono-Regular", Menlo, monospace; font-size: 0.9em; }}
    .muted {{ color: #666; font-style: italic; }}
    .meta {{ color: #555; font-size: 0.85em; margin-top: 2em; padding-top: 1em; border-top: 1px solid #ddd; }}
    .meta dt {{ font-weight: 600; display: inline; }}
    .meta dd {{ display: inline; margin: 0 1.5em 0 0.3em; }}
  </style>
</head>
<body>
  <h1>atproto-pds — admin dashboard</h1>

  <h2>Accounts ({total})</h2>
  <table>
    <thead><tr><th>state</th><th class="r">count</th></tr></thead>
    <tbody>
      {by_state_rows}
    </tbody>
  </table>

  <h2>Recent invite codes (last 10)</h2>
  <table>
    <thead><tr><th>code</th><th>created by</th><th class="r">uses left</th><th>used by</th><th>created at</th></tr></thead>
    <tbody>
      {invite_rows}
    </tbody>
  </table>

  <dl class="meta">
    <dt>Service DID:</dt><dd><code>{service_did}</code></dd>
    <dt>Build rev:</dt><dd><code>{build_rev}</code></dd>
  </dl>
</body>
</html>
"#,
        total = total_accounts,
        service_did = html_escape(service_did),
        build_rev = html_escape(build_rev),
    )
}

/// Minimal HTML-attribute-and-text escape — we only need to neutralize
/// `<`, `>`, `&`, `"`, `'` for the values we actually inject. Avoids pulling
/// in a templating library for what amounts to a single page.
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
    fn html_escape_neutralizes_specials() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(html_escape("'apos'"), "&#39;apos&#39;");
    }

    #[test]
    fn render_dashboard_includes_required_sections() {
        let html = render_dashboard(
            "did:web:test.example",
            "abc123",
            42,
            &[("active".to_string(), 40), ("deactivated".to_string(), 2)],
            &[(
                "code-xyz".to_string(),
                Some("did:plc:alice".to_string()),
                3,
                None,
                "2026-05-02T10:00:00Z".to_string(),
            )],
        );
        assert!(html.contains("admin dashboard"));
        assert!(html.contains("did:web:test.example"));
        assert!(html.contains("abc123"));
        assert!(html.contains("Accounts (42)"));
        assert!(html.contains("active"));
        assert!(html.contains("deactivated"));
        assert!(html.contains("code-xyz"));
    }

    #[test]
    fn render_dashboard_handles_empty_invite_list() {
        let html = render_dashboard("did:web:test", "rev", 0, &[], &[]);
        assert!(html.contains("no invite codes issued yet"));
    }

    #[test]
    fn render_dashboard_escapes_user_content() {
        let html = render_dashboard(
            "did:web:<bad>",
            "rev",
            0,
            &[("\"injected\"".to_string(), 1)],
            &[],
        );
        assert!(html.contains("did:web:&lt;bad&gt;"));
        assert!(html.contains("&quot;injected&quot;"));
        assert!(!html.contains("did:web:<bad>"));
    }
}
