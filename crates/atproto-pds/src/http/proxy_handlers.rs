//! `Atproto-Proxy` request forwarding.
//!
//! When the PDS receives an `app.bsky.*` (or any non-local) XRPC call,
//! per-spec the request can be **proxied** to an upstream service —
//! typically an AppView or labeler. The decision tree:
//!
//! 1. If the inbound request carries an `Atproto-Proxy: <did>#<service-id>`
//!    header, that explicit pin wins. Resolve the DID document, look up
//!    the named service entry, and forward.
//! 2. Otherwise, when the NSID starts with `app.bsky.`, fall back to the
//!    operator-configured `(PDS_BSKY_APP_VIEW_DID, PDS_BSKY_APP_VIEW_URL)`
//!    pair. This is the *default pin* — clients get sensible behavior
//!    out of the box without having to set the proxy header on every
//!    call.
//! 3. If neither path applies, the route is handled locally (or 404s if
//!    no local handler exists).
//!
//! All forwarded calls carry a fresh service-auth bearer signed by the
//! caller's atproto signing key (`aud=<target_did>`,
//! `lxm=<request NSID>`, 60s TTL) so the upstream service can identify
//! the calling user.
//!
//! Today's implementation handles the **default pin** for the
//! configured `app.bsky.*` AppView via a single catch-all route
//! (`/xrpc/app.bsky.*`). Per-request `Atproto-Proxy: did#service` headers
//! also override the AppView default. Per-request DID-document resolution
//! for arbitrary services is — today the proxy uses
//! the operator-configured URL when the requested DID matches
//! `bsky_app_view_did`, and otherwise returns `502 ProxyDidUnknown`.

use crate::http::auth::{bearer_token, request_htm_htu};
use crate::http::errors::XrpcError;
use crate::http::proxy_target::ProxyTarget;
use crate::http::space_auth::local_signing_key;
use crate::http::state::HttpState;
use atproto_identity::key::{jws_alg, sign as identity_sign};
use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::IntoResponse;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use rand::RngExt;
use serde::Serialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Resolve the proxy target for an inbound request.
///
/// Precedence per the §11a contract: the explicit `Atproto-Proxy` header
/// wins; otherwise fall back to the configured AppView when the NSID
/// starts with `app.bsky.`; otherwise no target.
///
/// Returns `Ok(None)` when there is no proxy target (the request should
/// be served locally). `Err` is reserved for malformed proxy headers.
async fn resolve_target(
    headers: &HeaderMap,
    state: &HttpState,
    nsid: &str,
) -> Result<Option<ProxyTarget>, XrpcError> {
    if let Some(raw) = headers.get("atproto-proxy") {
        let raw = raw.to_str().map_err(|_| {
            XrpcError::new(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "Atproto-Proxy header is not valid UTF-8",
            )
        })?;
        let mut parts = raw.splitn(2, '#');
        let did = parts.next().unwrap_or("").trim();
        let service_id = parts.next().unwrap_or("").trim();
        if did.is_empty() || service_id.is_empty() {
            return Err(XrpcError::new(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "Atproto-Proxy must be `<did>#<service-id>`",
            ));
        }
        // The operator's own AppView is a fast path — it needs no network and
        // is by far the most requested target.
        if let Some(app_view_did) = state.bsky_app_view_did.as_deref()
            && did == app_view_did
            && let Some(url) = state.bsky_app_view_url.as_deref()
        {
            return Ok(Some(ProxyTarget {
                did: did.to_string(),
                url: url.to_string(),
            }));
        }
        // Anything else is resolved from its DID document. This is what makes
        // labelers, feed generators, chat and third-party AppViews reachable
        // at all, rather than only the one endpoint the operator pinned.
        if let Some(resolver) = state.proxy_resolver.as_ref()
            && let Some(target) = resolver.resolve(did, service_id).await
        {
            return Ok(Some(target));
        }
        return Err(XrpcError::new(
            StatusCode::BAD_GATEWAY,
            "ProxyDidUnknown",
            format!("could not resolve Atproto-Proxy target {did}#{service_id}"),
        ));
    }
    // Default pin: the configured AppView, when one is set. Only namespaces
    // this PDS does not serve locally reach here at all.
    if PROXIED_NAMESPACES.iter().any(|ns| nsid.starts_with(ns))
        && let (Some(did), Some(url)) = (
            state.bsky_app_view_did.as_deref(),
            state.bsky_app_view_url.as_deref(),
        )
    {
        return Ok(Some(ProxyTarget {
            did: did.to_string(),
            url: url.to_string(),
        }));
    }
    Ok(None)
}

/// Namespaces this PDS forwards rather than serves.
///
/// `com.atproto.label.*` is listed rather than `com.atproto.*` because almost
/// every other `com.atproto` method is served locally; a broader prefix would
/// shadow them.
pub const PROXIED_NAMESPACES: &[&str] = &[
    "app.bsky.",
    "chat.bsky.",
    "tools.ozone.",
    "com.atproto.label.",
];

/// Catch-all proxy handler. Forwards to the configured AppView, or to the
/// service named by a per-request `Atproto-Proxy` header.
///
/// The NSID and query string are read from [`OriginalUri`] rather than from the
/// route capture. A catch-all after a literal prefix captures only the
/// remainder — `/xrpc/app.bsky.{*nsid}` yields `feed.getTimeline`, not
/// `app.bsky.feed.getTimeline` — so re-prefixing by hand would tie this handler
/// to the exact route literals it happens to be mounted at.
pub async fn proxy_app_bsky(
    State(state): State<HttpState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<axum::response::Response, XrpcError> {
    let nsid = uri
        .path()
        .strip_prefix("/xrpc/")
        .ok_or_else(|| {
            XrpcError::new(
                StatusCode::NOT_FOUND,
                "NotFound",
                "proxy route reached without an /xrpc/ path",
            )
        })?
        .to_string();
    proxy_call(&state, &nsid, uri.query(), method, headers, body).await
}

/// Core proxy logic. Resolves the target, mints a service-auth bearer
/// signed by the caller's signing key, and forwards the request.
async fn proxy_call(
    state: &HttpState,
    nsid: &str,
    query: Option<&str>,
    method: Method,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<axum::response::Response, XrpcError> {
    let target = match resolve_target(&headers, state, nsid).await? {
        Some(t) => t,
        None => {
            // No proxy configured — return a structured 502 so the
            // caller knows this PDS doesn't serve `app.bsky.*` locally
            // and no upstream is wired.
            return Err(XrpcError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ProxyUnavailable",
                format!("no AppView configured to handle {nsid}"),
            ));
        }
    };

    // Mint a service-auth JWT for the caller — same shape as
    // `getServiceAuth`. Auth-required so we can tie the token to the
    // logged-in subject.
    let manager = state.account_manager.as_ref().ok_or_else(|| {
        XrpcError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AccountManagementUnavailable",
            "account management is not configured on this PDS",
        )
    })?;
    let parts = build_parts_for_authn(&headers, &method)?;
    let (htm, htu) = request_htm_htu(&parts);
    let subject = crate::http::auth::require_authn(&parts, state, &htm, &htu).await?;

    // `rpc:` scopes bound which method may be called at which audience. Without
    // this a token could proxy arbitrary calls to arbitrary services on the
    // holder's behalf — the PDS signs each one with the caller's own key, so
    // the upstream sees a request the account genuinely authorised.
    //
    // App-password sessions carry no scopes and are full-authority, matching
    // how the repo, blob and space assertions treat them.
    if subject.is_oauth() {
        subject
            .scopes()
            .assert_rpc(nsid, &target.did)
            .map_err(|missing| {
                XrpcError::new(
                    StatusCode::FORBIDDEN,
                    "InsufficientScope",
                    format!("this token does not grant {}", missing.scope),
                )
            })?;
    }
    let caller = subject.sub().to_string();
    let signing_key = local_signing_key(manager, &caller).await?;
    let token = mint_proxy_service_auth(&caller, &target.did, nsid, &signing_key)?;

    // Forward, carrying the query string. Dropping it turns every
    // parameterised call — every cursor, every limit — into its unfiltered
    // form, which is worse than failing.
    let endpoint = match query {
        Some(query) if !query.is_empty() => format!(
            "{base}/xrpc/{nsid}?{query}",
            base = target.url.trim_end_matches('/')
        ),
        _ => format!(
            "{base}/xrpc/{nsid}",
            base = target.url.trim_end_matches('/')
        ),
    };
    let http = reqwest::Client::builder()
        .user_agent(crate::user_agent())
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("build http client: {e}"),
            )
        })?;
    // Forward the request body + content-type; leave query string parsing
    // to axum's catch-all (axum 0.8 reconstructs the URI on Request via
    // extractor; we use the inbound `headers` map to carry the original
    // accept/content-type).
    let mut req_builder = http
        .request(
            reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET),
            &endpoint,
        )
        .bearer_auth(&token);
    if let Some(ct) = headers.get(axum::http::header::CONTENT_TYPE)
        && let Ok(s) = ct.to_str()
    {
        req_builder = req_builder.header(reqwest::header::CONTENT_TYPE, s);
    }
    let resp = req_builder.body(body.to_vec()).send().await.map_err(|e| {
        tracing::warn!(error = ?e, endpoint = %endpoint, "AppView proxy: forward failed");
        XrpcError::new(
            StatusCode::BAD_GATEWAY,
            "ProxyForwardFailed",
            format!("forward to AppView failed: {e}"),
        )
    })?;
    let status = resp.status();
    let upstream_ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .map(str::to_string);
    let body_bytes = resp.bytes().await.map_err(|e| {
        XrpcError::new(
            StatusCode::BAD_GATEWAY,
            "ProxyForwardFailed",
            format!("read upstream body: {e}"),
        )
    })?;
    tracing::info!(
        nsid = %nsid,
        upstream = %endpoint,
        upstream_status = status.as_u16(),
        "AppView proxy: forwarded"
    );
    let mut response = (
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
        Body::from(body_bytes),
    )
        .into_response();
    if let Some(ct) = upstream_ct
        && let Ok(v) = HeaderValue::from_str(&ct)
    {
        response
            .headers_mut()
            .insert(axum::http::header::CONTENT_TYPE, v);
    }
    Ok(response)
}

/// Build a `Parts` shim from the inbound headers + method for the auth
/// extractor. The DPoP layer derives `htm`/`htu` from this.
fn build_parts_for_authn(
    headers: &HeaderMap,
    method: &Method,
) -> Result<axum::http::request::Parts, XrpcError> {
    let mut req = axum::http::Request::builder()
        .method(method.clone())
        .uri("/")
        .body(())
        .map_err(|e| {
            XrpcError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("build req: {e}"),
            )
        })?;
    *req.headers_mut() = headers.clone();
    Ok(req.into_parts().0)
}

#[derive(Serialize)]
struct ProxyServiceAuthHeader {
    alg: String,
    typ: &'static str,
}

#[derive(Serialize)]
struct ProxyServiceAuthClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    lxm: &'a str,
    iat: u64,
    exp: u64,
    jti: String,
}

/// Best-effort `bearer_token` lookup so the JTI can include a per-call
/// nonce — defensive only, not required for the JWT proper.
#[allow(dead_code)]
fn _ensure_bearer_helper_imported(parts: &axum::http::request::Parts) -> Option<&str> {
    bearer_token(parts).ok()
}

/// Mint a 60-second service-auth token bound to the proxy
/// audience + lexicon method.
fn mint_proxy_service_auth(
    caller_did: &str,
    aud_did: &str,
    nsid: &str,
    signing_key: &atproto_identity::key::KeyData,
) -> Result<String, XrpcError> {
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let exp = iat + 60;
    let jti = {
        let mut bytes = [0u8; 16];
        rand::rng().fill(&mut bytes);
        B64URL.encode(bytes)
    };
    let header = ProxyServiceAuthHeader {
        alg: jws_alg(signing_key).to_string(),
        typ: crate::http::service_auth_handlers::TYP_SERVICE_AUTH,
    };
    let payload = ProxyServiceAuthClaims {
        iss: caller_did,
        aud: aud_did,
        lxm: nsid,
        iat,
        exp,
        jti,
    };
    let header_bytes = serde_json::to_vec(&header).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            e.to_string(),
        )
    })?;
    let payload_bytes = serde_json::to_vec(&payload).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            e.to_string(),
        )
    })?;
    let signing_input = format!(
        "{}.{}",
        B64URL.encode(&header_bytes),
        B64URL.encode(&payload_bytes)
    );
    let sig = identity_sign(signing_key, signing_input.as_bytes()).map_err(|e| {
        XrpcError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            format!("sign: {e}"),
        )
    })?;
    Ok(format!("{}.{}", signing_input, B64URL.encode(&sig)))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn empty_state() -> HttpState {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let accounts = crate::account::AccountDirectory::open_memory()
            .await
            .unwrap();
        let reader = std::sync::Arc::new(crate::repo::RepoReader::new(accounts, dir));
        HttpState::new(reader)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_target_default_pin_app_bsky() {
        let mut state = empty_state().await;
        state.bsky_app_view_did = Some("did:web:appview".to_string());
        state.bsky_app_view_url = Some("https://app.example".to_string());
        let headers = HeaderMap::new();
        let target = resolve_target(&headers, &state, "app.bsky.feed.getTimeline")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(target.did, "did:web:appview");
        assert_eq!(target.url, "https://app.example");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_target_explicit_header_overrides() {
        let mut state = empty_state().await;
        state.bsky_app_view_did = Some("did:web:appview".to_string());
        state.bsky_app_view_url = Some("https://app.example".to_string());
        let mut headers = HeaderMap::new();
        headers.insert(
            "atproto-proxy",
            HeaderValue::from_static("did:web:appview#bsky_appview"),
        );
        let target = resolve_target(&headers, &state, "app.bsky.feed.getTimeline")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(target.did, "did:web:appview");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_target_unknown_proxy_did_is_502() {
        let mut state = empty_state().await;
        state.bsky_app_view_did = Some("did:web:appview".to_string());
        state.bsky_app_view_url = Some("https://app.example".to_string());
        let mut headers = HeaderMap::new();
        headers.insert(
            "atproto-proxy",
            HeaderValue::from_static("did:web:other#svc"),
        );
        let err = resolve_target(&headers, &state, "app.bsky.actor.getProfile")
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_GATEWAY);
        assert_eq!(err.name, "ProxyDidUnknown");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_target_no_appview_no_proxy_returns_none() {
        let state = empty_state().await;
        let target = resolve_target(&HeaderMap::new(), &state, "app.bsky.feed.getTimeline")
            .await
            .unwrap();
        assert!(target.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_target_skips_non_bsky_nsids() {
        let mut state = empty_state().await;
        state.bsky_app_view_did = Some("did:web:appview".to_string());
        state.bsky_app_view_url = Some("https://app.example".to_string());
        // com.atproto.* is locally served — no proxy target by default.
        let target = resolve_target(&HeaderMap::new(), &state, "com.atproto.repo.getRecord")
            .await
            .unwrap();
        assert!(target.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_target_malformed_header_400() {
        let state = empty_state().await;
        let mut headers = HeaderMap::new();
        // Missing `#service-id` half.
        headers.insert("atproto-proxy", HeaderValue::from_static("did:web:appview"));
        let err = resolve_target(&headers, &state, "app.bsky.actor.getProfile")
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }
}
