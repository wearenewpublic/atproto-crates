//! Integration tests for delegated sign-in.
//!
//! # What can and cannot be tested in process
//!
//! The middle of the flow leaves this server: the delegate authenticates
//! against their own PDS, over HTTPS, against a real authorization server. No
//! in-process router can stand in for that, so nothing here drives the round
//! trip end to end — that is a manual check against a second deployment, and
//! `oauth::delegation` says so in its own docs.
//!
//! What *is* testable is everything on either side of it, and that is what
//! these cover: the client-metadata document a peer fetches, the guards on the
//! two pages a browser sees, and the marker that survives the exchange —
//! including through a refresh rotation, which is where a carried claim is
//! most likely to be quietly dropped.

use atproto_identity::key::{KeyType, generate_key};
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::oauth::state::{OAuthRequest, OAuthState};
use atproto_pds::repo::{RepoReader, RepoWriter};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

const DID: &str = "did:plc:oauthdelegationfixture001";
const HANDLE: &str = "holder.pds.test";

struct Harness {
    app: axum::Router,
    state: HttpState,
    _tmp: TempDir,
}

async fn build(enabled: bool) -> Harness {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
        .await
        .unwrap();
    let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let manager = Arc::new(AccountManager::new(
        accounts.pool().clone(),
        dir.clone(),
        key_store,
        KeyType::K256Private,
    ));
    manager
        .create_account(CreateAccountParams::new(DID, HANDLE, "pw"))
        .await
        .expect("fixture account");
    let writer = Arc::new(RepoWriter::new(manager.clone(), dir.clone()));
    let reader = Arc::new(RepoReader::new(accounts, dir.clone()));
    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:pds.test".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer)
    .with_pds_signing_key(Arc::new(generate_key(KeyType::P256Private).unwrap()))
    .with_delegation_enabled(enabled);
    Harness {
        app: build_router(state.clone()),
        state,
        _tmp: tmp,
    }
}

/// Stage an authorization request the way `/oauth/par` would.
async fn stage_par(state: &HttpState, request_uri: &str, login_hint: Option<&str>) {
    state
        .oauth
        .store_par(
            request_uri.to_string(),
            OAuthRequest {
                client_id: "https://app.example/client-metadata.json".to_string(),
                redirect_uri: "https://app.example/callback".to_string(),
                scope: "atproto transition:generic".to_string(),
                state: "client-state".to_string(),
                code_challenge: "challenge".to_string(),
                code_challenge_method: "S256".to_string(),
                dpop_jkt: Some("thumb".to_string()),
                login_hint: login_hint.map(str::to_string),
                created_at: chrono::Utc::now(),
            },
        )
        .await
        .unwrap();
}

/// A browser navigation, which is what both pages require.
fn navigation(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-dest", "document")
        .header("sec-fetch-site", "cross-site")
        .body(Body::empty())
        .unwrap()
}

async fn body_of(resp: axum::response::Response) -> String {
    String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

/// GET a JSON document, or `None` if the status was not 200.
async fn get_json(app: &axum::Router, uri: &str) -> Option<Value> {
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    if resp.status() != StatusCode::OK {
        return None;
    }
    serde_json::from_str(&body_of(resp).await).ok()
}

// ---------------------------------------------------------------------------
//  Client metadata
// ---------------------------------------------------------------------------

/// The document a delegate's server fetches, and the two facts it turns on:
/// `client_id` must equal the URL it was served from, and `jwks_uri` must point
/// at a JWKS that actually publishes a key.
#[tokio::test(flavor = "multi_thread")]
async fn the_client_metadata_document_is_self_consistent() {
    let h = build(true).await;

    let resp = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth/delegation/client-metadata.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let doc: Value = serde_json::from_str(&body_of(resp).await).unwrap();

    assert_eq!(
        doc["client_id"], "https://pds.test/oauth/delegation/client-metadata.json",
        "client_id must be the URL this document is served from"
    );
    assert_eq!(
        doc["redirect_uris"][0], "https://pds.test/oauth/delegation/callback",
        "the registered callback must be the route that exists"
    );
    assert_eq!(
        doc["jwks_uri"], "https://pds.test/oauth/delegation/jwks.json",
        "the client-role set, not the provider set -- they name keys differently"
    );
    assert_eq!(doc["token_endpoint_auth_method"], "private_key_jwt");
    assert_eq!(doc["token_endpoint_auth_signing_alg"], "ES256");
    assert_eq!(doc["dpop_bound_access_tokens"], true);
    // Identity only. Asking for more would put a permission on the delegate's
    // consent screen that nothing here would ever use.
    assert_eq!(doc["scope"], "atproto");
    assert_eq!(
        doc["grant_types"],
        serde_json::json!(["authorization_code"])
    );

    // That the advertised document publishes *a* key. That it publishes the
    // key the assertion actually names is
    // `the_assertion_kid_resolves_against_the_published_client_jwks`, which is
    // the part this test used to leave unchecked.
    let jwks = get_json(&h.app, "/oauth/delegation/jwks.json")
        .await
        .expect("the advertised jwks_uri is fetchable");
    assert!(
        jwks["keys"].as_array().is_some_and(|k| !k.is_empty()),
        "the advertised jwks_uri publishes no keys: {jwks}"
    );
}

/// With delegation off there is no client identity to publish, and saying so is
/// better than publishing a `client_id` this server will not act as.
#[tokio::test(flavor = "multi_thread")]
async fn the_metadata_document_is_absent_when_delegation_is_off() {
    let h = build(false).await;
    let resp = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth/delegation/client-metadata.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// A K-256 service key cannot sign an ES256 assertion, so delegation reports
/// itself unavailable rather than advertising a client no peer will accept.
#[tokio::test(flavor = "multi_thread")]
async fn a_non_p256_signing_key_disables_delegation() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
        .await
        .unwrap();
    let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let manager = Arc::new(AccountManager::new(
        accounts.pool().clone(),
        dir.clone(),
        key_store,
        KeyType::K256Private,
    ));
    let reader = Arc::new(RepoReader::new(accounts, dir.clone()));
    let state = HttpState::with_account_manager(
        reader,
        manager,
        "did:web:pds.test".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_pds_signing_key(Arc::new(generate_key(KeyType::K256Private).unwrap()))
    .with_delegation_enabled(true);

    assert!(!state.delegation.is_available());
}

/// A server that is not on HTTPS cannot have its `client_id` fetched, so the
/// preconditions refuse it before anything advertises otherwise.
#[tokio::test(flavor = "multi_thread")]
async fn an_insecure_origin_disables_delegation() {
    use atproto_pds::http::state::{DelegationStatus, DelegationUnavailable};
    let key = generate_key(KeyType::P256Private).unwrap();
    assert!(matches!(
        DelegationStatus::resolve(true, "http://localhost:3000", Some(&key)),
        DelegationStatus::Unavailable(DelegationUnavailable::InsecureOrigin)
    ));
    assert!(DelegationStatus::resolve(true, "https://pds.test", Some(&key)).is_available());
}

// ---------------------------------------------------------------------------
//  The consent-page link
// ---------------------------------------------------------------------------

/// The link appears only when this server can complete the flow *and* the
/// client said who is signing in. Both halves are load-bearing: without a hint
/// there is no account to act for.
#[tokio::test(flavor = "multi_thread")]
async fn the_delegate_link_needs_both_delegation_and_a_login_hint() {
    let with_hint = "urn:ietf:params:oauth:request_uri:hinted";
    let no_hint = "urn:ietf:params:oauth:request_uri:bare";

    let on = build(true).await;
    stage_par(&on.state, with_hint, Some(HANDLE)).await;
    stage_par(&on.state, no_hint, None).await;

    let page = body_of(
        on.app
            .clone()
            .oneshot(navigation(&format!(
                "/oauth/authorize?request_uri={with_hint}"
            )))
            .await
            .unwrap(),
    )
    .await;
    assert!(
        page.contains("Sign in as a delegate"),
        "the link is missing where it should be offered: {page}"
    );

    let page = body_of(
        on.app
            .clone()
            .oneshot(navigation(&format!(
                "/oauth/authorize?request_uri={no_hint}"
            )))
            .await
            .unwrap(),
    )
    .await;
    assert!(
        !page.contains("Sign in as a delegate"),
        "the link was offered for a request that names no account"
    );

    let off = build(false).await;
    stage_par(&off.state, with_hint, Some(HANDLE)).await;
    let page = body_of(
        off.app
            .clone()
            .oneshot(navigation(&format!(
                "/oauth/authorize?request_uri={with_hint}"
            )))
            .await
            .unwrap(),
    )
    .await;
    assert!(
        !page.contains("Sign in as a delegate"),
        "a server that cannot delegate offered the link anyway"
    );
}

// ---------------------------------------------------------------------------
//  The handle-entry page
// ---------------------------------------------------------------------------

/// The page names the client, the account being acted for, and the scopes —
/// the same three facts the consent page shows, because it is the same errand.
#[tokio::test(flavor = "multi_thread")]
async fn the_start_page_restates_what_is_being_authorized() {
    let h = build(true).await;
    let uri = "urn:ietf:params:oauth:request_uri:start";
    stage_par(&h.state, uri, Some(HANDLE)).await;

    let resp = h
        .app
        .clone()
        .oneshot(navigation(&format!(
            "/oauth/delegation/start?request_uri={uri}"
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Never cached: it names an account and a pending grant.
    assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
    let page = body_of(resp).await;

    assert!(
        page.contains("https://app.example/client-metadata.json"),
        "{page}"
    );
    assert!(page.contains(HANDLE), "{page}");
    assert!(page.contains("transition:generic"), "{page}");
    assert!(page.contains(r#"name="handle""#), "{page}");
    // One field, and no password box: the whole point is that the account's
    // password is not what is being asked for.
    assert!(!page.contains("type=\"password\""), "{page}");
}

/// The page is not reachable except as a browser navigation, for the same
/// reason the consent page is not.
#[tokio::test(flavor = "multi_thread")]
async fn the_start_page_refuses_a_non_navigation() {
    let h = build(true).await;
    let uri = "urn:ietf:params:oauth:request_uri:fetched";
    stage_par(&h.state, uri, Some(HANDLE)).await;

    let resp = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/oauth/delegation/start?request_uri={uri}"))
                .header("sec-fetch-mode", "cors")
                .header("sec-fetch-dest", "empty")
                .header("sec-fetch-site", "cross-site")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// An authorization request that names nobody cannot be completed by a
/// delegate, and the page says which of the two things is missing.
#[tokio::test(flavor = "multi_thread")]
async fn the_start_page_refuses_a_request_with_no_login_hint() {
    let h = build(true).await;
    let uri = "urn:ietf:params:oauth:request_uri:hintless";
    stage_par(&h.state, uri, None).await;

    let resp = h
        .app
        .clone()
        .oneshot(navigation(&format!(
            "/oauth/delegation/start?request_uri={uri}"
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body_of(resp).await.contains("does not name an account"));
}

/// An unknown `request_uri` is refused, and the page does not exist at all when
/// delegation is off.
#[tokio::test(flavor = "multi_thread")]
async fn the_start_page_refuses_an_unknown_or_unavailable_request() {
    let h = build(true).await;
    let resp = h
        .app
        .clone()
        .oneshot(navigation(
            "/oauth/delegation/start?request_uri=urn:never:issued",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let off = build(false).await;
    let uri = "urn:ietf:params:oauth:request_uri:offserver";
    stage_par(&off.state, uri, Some(HANDLE)).await;
    let resp = off
        .app
        .clone()
        .oneshot(navigation(&format!(
            "/oauth/delegation/start?request_uri={uri}"
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// The form POST is a portal-style mutation and refuses a cross-site origin.
#[tokio::test(flavor = "multi_thread")]
async fn beginning_refuses_a_cross_site_post() {
    let h = build(true).await;
    let uri = "urn:ietf:params:oauth:request_uri:crosssite";
    stage_par(&h.state, uri, Some(HANDLE)).await;

    let resp = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth/delegation/begin")
                .method("POST")
                .header("sec-fetch-site", "cross-site")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "request_uri={uri}&handle=friend.example.com"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // And the authorization request is untouched, so the person can go back
    // and sign in the ordinary way.
    assert!(h.state.oauth.peek_par(uri).await.unwrap().is_some());
}

/// Submit the handle form and return the whole response.
async fn begin_raw(h: &Harness, request_uri: &str, handle: &str) -> axum::response::Response {
    h.app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth/delegation/begin")
                .method("POST")
                .header("sec-fetch-site", "same-origin")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "request_uri={request_uri}&handle={handle}"
                )))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Submit the handle form and return the rendered page.
async fn begin(h: &Harness, request_uri: &str, handle: &str) -> (StatusCode, String) {
    let resp = begin_raw(h, request_uri, handle).await;
    let status = resp.status();
    (status, body_of(resp).await)
}

/// The handle-entry page names an account, a client and a pending grant, so it
/// must not be cached — and that has to hold for the refusal rendering too,
/// which is the one a person actually sees more than once.
#[tokio::test(flavor = "multi_thread")]
async fn every_rendering_of_the_handle_page_refuses_to_be_cached() {
    let h = build(true).await;

    let fresh = "urn:ietf:params:oauth:request_uri:fresh";
    stage_par(&h.state, fresh, Some(HANDLE)).await;
    let first = h
        .app
        .clone()
        .oneshot(navigation(&format!(
            "/oauth/delegation/start?request_uri={fresh}"
        )))
        .await
        .unwrap();

    let refused = "urn:ietf:params:oauth:request_uri:refused";
    stage_par(&h.state, refused, Some(HANDLE)).await;
    let second = begin_raw(&h, refused, "nobody.example.com").await;

    for (name, resp) in [("start", first), ("refusal", second)] {
        assert_eq!(resp.status(), StatusCode::OK, "{name}");
        assert_eq!(
            resp.headers()
                .get("cache-control")
                .map(|v| v.to_str().unwrap()),
            Some("no-store"),
            "the {name} rendering may be cached"
        );
        assert_eq!(
            resp.headers().get("pragma").map(|v| v.to_str().unwrap()),
            Some("no-cache"),
            "the {name} rendering may be cached by an HTTP/1.0 intermediary"
        );
    }
}

/// A handle that does not resolve comes back to the same page with the
/// authorization request still alive — a typo must not end the flow.
#[tokio::test(flavor = "multi_thread")]
async fn an_unresolvable_delegate_handle_leaves_the_flow_intact() {
    let h = build(true).await;
    let uri = "urn:ietf:params:oauth:request_uri:typo";
    stage_par(&h.state, uri, Some(HANDLE)).await;

    let (status, body) = begin(&h, uri, "nobody.example.com").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("could not be started"),
        "the refusal did not offer a way forward: {body}"
    );
    assert!(
        h.state.oauth.peek_par(uri).await.unwrap().is_some(),
        "a mistyped handle destroyed the pending authorization"
    );
}

/// `begin` must not become an oracle for "does this server host that account".
///
/// The `login_hint` is chosen by the client, so whether it names an account
/// here is not the caller's to learn. A caller can push one authorization
/// request per guess and submit a deliberately bad handle; if the two failures
/// read differently, that loop enumerates the server's accounts.
///
/// Both branches must therefore be byte-identical, which means the account
/// lookup cannot short-circuit ahead of the handle resolution.
#[tokio::test(flavor = "multi_thread")]
async fn the_two_ways_to_fail_before_the_redirect_are_indistinguishable() {
    let h = build(true).await;

    // A real local account, and a handle that will not resolve.
    let real = "urn:ietf:params:oauth:request_uri:realaccount";
    stage_par(&h.state, real, Some(HANDLE)).await;
    let (real_status, real_body) = begin(&h, real, "nobody.example.com").await;

    // No such account here, and the same unresolvable handle.
    let absent = "urn:ietf:params:oauth:request_uri:noaccount";
    stage_par(&h.state, absent, Some("stranger.pds.test")).await;
    let (absent_status, absent_body) = begin(&h, absent, "nobody.example.com").await;

    assert_eq!(real_status, absent_status);
    // The pages differ only where they echo the request they belong to; the
    // refusal itself must not.
    let banner = |body: &str| {
        body.split("<div class=\"err\">")
            .nth(1)
            .and_then(|rest| rest.split("</div>").next())
            .map(str::to_string)
            .expect("a refusal banner")
    };
    assert_eq!(
        banner(&real_body),
        banner(&absent_body),
        "the refusal says which of the two things was missing"
    );
}

/// A callback whose `state` names no parked sign-in is refused, and says
/// nothing about whether that value was ever real.
#[tokio::test(flavor = "multi_thread")]
async fn a_callback_for_an_unknown_flow_is_refused() {
    let h = build(true).await;
    let resp = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth/delegation/callback?state=never-issued&code=x&iss=https://elsewhere")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_of(resp).await;
    assert!(body.contains("no longer valid"), "{body}");
}

// ---------------------------------------------------------------------------
//  Browser binding
// ---------------------------------------------------------------------------

/// Park a sign-in directly, as a successful `begin` would have, so the callback
/// can be driven without a live peer to authenticate against.
///
/// `redirect_uri` carries a query of its own, which is legal — the redirect
/// policy in `client_metadata` checks the scheme and the authority and says
/// nothing about the query — and is what the parameter-appending assertions
/// below turn on.
async fn park_a_flow(h: &Harness, state: &str, cookie_value: &str) {
    use atproto_pds::oauth::delegation_login::{ParkedLogin, binding_id, park};
    park(
        &h.state.reader.accounts().account_pool(),
        state,
        &ParkedLogin {
            core_did: DID.to_string(),
            delegate_did: "did:plc:thedelegate00000000000001".to_string(),
            issuer: "https://delegate.example".to_string(),
            token_endpoint: "https://delegate.example/oauth/token".to_string(),
            request: OAuthRequest {
                client_id: "https://app.example/client-metadata.json".to_string(),
                redirect_uri: "https://app.example/callback?tenant=acme".to_string(),
                scope: "atproto".to_string(),
                state: "client-state".to_string(),
                code_challenge: "challenge".to_string(),
                code_challenge_method: "S256".to_string(),
                dpop_jkt: Some("thumb".to_string()),
                login_hint: Some(HANDLE.to_string()),
                created_at: chrono::Utc::now(),
            },
            nonce: "nonce".to_string(),
            pkce_verifier: "verifier".to_string(),
            dpop_private_key: "did:key:zNotARealKey".to_string(),
            browser_binding: binding_id(cookie_value),
        },
    )
    .await
    .unwrap();
}

async fn hit_callback(h: &Harness, query: &str, cookie: Option<&str>) -> axum::response::Response {
    let mut builder = Request::builder().uri(format!("/oauth/delegation/callback?{query}"));
    if let Some(value) = cookie {
        builder = builder.header("cookie", format!("atproto_pds_delegation={value}"));
    }
    h.app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

fn location_of(resp: &axum::response::Response) -> String {
    resp.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// A callback that does not carry the cookie `begin` set is refused, even
/// though its `state`, `code` and `iss` are all correct.
///
/// This is the phishing case. Everything the callback carries has travelled
/// through the delegate's own authorization server, so that server — and
/// anyone who obtained the URL from it — can reproduce all of it. The cookie is
/// the one part they cannot, which is what forces a delegate through the page
/// that names the client and the account before they can authorize either.
#[tokio::test(flavor = "multi_thread")]
async fn a_callback_without_the_binding_cookie_is_refused() {
    let h = build(true).await;
    park_a_flow(&h, "the-state", "the-cookie").await;

    let resp = hit_callback(
        &h,
        "state=the-state&code=abc&iss=https%3A%2F%2Fdelegate.example",
        None,
    )
    .await;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = location_of(&resp);
    assert!(
        location.contains("error=access_denied"),
        "a callback with no binding was not refused: {location}"
    );
}

/// The same, with somebody else's cookie value.
#[tokio::test(flavor = "multi_thread")]
async fn a_callback_with_the_wrong_binding_cookie_is_refused() {
    let h = build(true).await;
    park_a_flow(&h, "the-state", "the-cookie").await;

    let resp = hit_callback(
        &h,
        "state=the-state&code=abc&iss=https%3A%2F%2Fdelegate.example",
        Some("some-other-value"),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(location_of(&resp).contains("error=access_denied"));
}

/// The cookie is spent along with the flow: the refusal expires it, so it
/// cannot ride along with later requests to this subtree.
#[tokio::test(flavor = "multi_thread")]
async fn a_finished_flow_expires_its_binding_cookie() {
    let h = build(true).await;
    park_a_flow(&h, "the-state", "the-cookie").await;

    let resp = hit_callback(
        &h,
        "state=the-state&error=access_denied",
        Some("the-cookie"),
    )
    .await;

    let set_cookie = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("atproto_pds_delegation="))
        .unwrap_or_default()
        .to_string();
    assert!(
        set_cookie.contains("Max-Age=0"),
        "the binding cookie outlived its flow: {set_cookie:?}"
    );
    assert!(set_cookie.contains("HttpOnly"), "{set_cookie:?}");
    assert!(set_cookie.contains("Secure"), "{set_cookie:?}");
    // Lax and not Strict: the callback is a cross-site top-level navigation
    // back from the delegate's server, and Strict would withhold the cookie on
    // exactly that request.
    assert!(set_cookie.contains("SameSite=Lax"), "{set_cookie:?}");
}

/// A registered `redirect_uri` may carry a query of its own, and the
/// parameters this server appends must be appended rather than concatenated.
///
/// Written as `format!("{redirect_uri}?code=…")` the result is
/// `...?tenant=acme?code=abc`, where the code parses as part of `tenant`'s
/// value — the client lands on its own callback holding no code, with nothing
/// at either end to explain why.
#[tokio::test(flavor = "multi_thread")]
async fn redirect_parameters_are_appended_to_an_existing_query() {
    let h = build(true).await;
    park_a_flow(&h, "the-state", "the-cookie").await;

    let resp = hit_callback(
        &h,
        "state=the-state&error=access_denied",
        Some("the-cookie"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let location = location_of(&resp);
    let url = url::Url::parse(&location).expect("a parseable redirect");
    let pairs: std::collections::HashMap<_, _> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    assert_eq!(
        pairs.get("tenant").map(String::as_str),
        Some("acme"),
        "the client's own query parameter was mangled: {location}"
    );
    assert_eq!(
        pairs.get("error").map(String::as_str),
        Some("access_denied"),
        "the error did not arrive as its own parameter: {location}"
    );
    assert_eq!(pairs.get("state").map(String::as_str), Some("client-state"));
    assert_eq!(
        pairs.get("iss").map(String::as_str),
        Some("https://pds.test")
    );
}

// ---------------------------------------------------------------------------
//  The marker
// ---------------------------------------------------------------------------

/// A delegated grant is marked from its first token, and an ordinary one is
/// not marked at all — the claim is absent from the wire form rather than
/// present and null.
#[tokio::test(flavor = "multi_thread")]
async fn the_acting_delegate_survives_a_code_exchange_and_a_rotation() {
    use atproto_pds::oauth::state::RefreshHandle;

    let h = build(true).await;
    let oauth = OAuthState::memory();
    let delegate = "did:plc:thedelegate00000000000001";

    // The code an ordinary authorization issues, and the one a delegated
    // sign-in issues.
    let request = OAuthRequest {
        client_id: "https://app.example/client-metadata.json".to_string(),
        redirect_uri: "https://app.example/callback".to_string(),
        scope: "atproto".to_string(),
        state: "client-state".to_string(),
        code_challenge: "challenge".to_string(),
        code_challenge_method: "S256".to_string(),
        dpop_jkt: Some("thumb".to_string()),
        login_hint: None,
        created_at: chrono::Utc::now(),
    };
    oauth
        .issue_code("plain".to_string(), DID.to_string(), request.clone(), None)
        .await
        .unwrap();
    oauth
        .issue_code(
            "delegated".to_string(),
            DID.to_string(),
            request,
            Some(delegate.to_string()),
        )
        .await
        .unwrap();

    assert_eq!(
        oauth.take_code("plain").await.unwrap().unwrap().acting_did,
        None
    );
    assert_eq!(
        oauth
            .take_code("delegated")
            .await
            .unwrap()
            .unwrap()
            .acting_did
            .as_deref(),
        Some(delegate)
    );

    // And a rotation carries it, which is where a claim that is set once and
    // read from the wrong place goes missing.
    oauth
        .register_refresh(
            "first".to_string(),
            RefreshHandle {
                did: DID.to_string(),
                client_id: "https://app.example/client-metadata.json".to_string(),
                dpop_jkt: "thumb".to_string(),
                scope: "atproto".to_string(),
                issued_at: chrono::Utc::now(),
                family_id: "family".to_string(),
                client_kid: None,
                grant_started_at: None,
                expires_at: None,
                acting_did: Some(delegate.to_string()),
            },
        )
        .await
        .unwrap();
    let rotated = oauth
        .rotate_refresh("first", "second".to_string())
        .await
        .unwrap()
        .expect("rotation");
    assert_eq!(
        rotated.acting_did.as_deref(),
        Some(delegate),
        "rotation dropped the acting delegate"
    );
    assert_eq!(
        oauth
            .peek_refresh("second")
            .await
            .unwrap()
            .unwrap()
            .acting_did
            .as_deref(),
        Some(delegate),
        "the successor token did not keep the acting delegate"
    );

    // The same, through the SQL backend the server actually runs.
    let sql = h.state.oauth.clone();
    sql.register_refresh(
        "sql-first".to_string(),
        RefreshHandle {
            did: DID.to_string(),
            client_id: "https://app.example/client-metadata.json".to_string(),
            dpop_jkt: "thumb".to_string(),
            scope: "atproto".to_string(),
            issued_at: chrono::Utc::now(),
            family_id: "family".to_string(),
            client_kid: None,
            grant_started_at: None,
            expires_at: None,
            acting_did: Some(delegate.to_string()),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        sql.rotate_refresh("sql-first", "sql-second".to_string())
            .await
            .unwrap()
            .unwrap()
            .acting_did
            .as_deref(),
        Some(delegate)
    );
}

/// The `kid` a peer is told to look for is the `kid` it will actually find.
///
/// This is the check that was missing when delegation first shipped. The
/// client metadata pointed `jwks_uri` at `/oauth/jwks`, which names keys by
/// RFC 7638 thumbprint, while the client assertion names its key by `did:key`
/// -- so every pushed authorization request came back `invalid_client` from a
/// real peer, and nothing here noticed, because nothing compared the two.
#[tokio::test]
async fn the_assertion_kid_resolves_against_the_published_client_jwks() {
    let h = build(true).await;

    // What a peer is told to fetch.
    let metadata: serde_json::Value = get_json(&h.app, "/oauth/delegation/client-metadata.json")
        .await
        .expect("client metadata");
    let jwks_uri = metadata["jwks_uri"].as_str().expect("a jwks_uri");
    assert!(
        jwks_uri.ends_with("/oauth/delegation/jwks.json"),
        "the client set is what a peer must be sent to, not the provider set: {jwks_uri}"
    );

    // What it finds there.
    let published: serde_json::Value = get_json(&h.app, "/oauth/delegation/jwks.json")
        .await
        .expect("delegation jwks");
    let kids: Vec<&str> = published["keys"]
        .as_array()
        .expect("a keys array")
        .iter()
        .filter_map(|k| k["kid"].as_str())
        .collect();
    assert!(!kids.is_empty(), "the client set publishes no key");

    // What this server actually puts in the assertion it signs -- built the
    // same way `oauth_init` builds it, from the same key.
    let signing_key = h.state.pds_signing_key.clone().expect("a signing key");
    let header: atproto_oauth::jwt::Header = (*signing_key)
        .clone()
        .try_into()
        .expect("an assertion header");
    let assertion_kid = header.key_id.expect("the assertion names its key");

    assert!(
        kids.contains(&assertion_kid.as_str()),
        "a peer resolving the assertion's kid finds nothing.\n  \
         assertion kid: {assertion_kid}\n  published kids: {kids:?}"
    );
    assert_eq!(
        header.algorithm.as_deref(),
        Some("ES256"),
        "the metadata promises ES256"
    );
}

/// The two key sets are genuinely different, so the test above is not vacuous.
///
/// If `/oauth/jwks` ever started naming keys the way an assertion does, the
/// original bug would be gone and so would the reason for a second document --
/// this says so out loud rather than leaving a route nobody can justify.
#[tokio::test]
async fn the_provider_set_names_the_same_key_differently() {
    let h = build(true).await;

    let provider: serde_json::Value = get_json(&h.app, "/oauth/jwks")
        .await
        .expect("provider jwks");
    let client: serde_json::Value = get_json(&h.app, "/oauth/delegation/jwks.json")
        .await
        .expect("client jwks");

    let kid_of = |v: &serde_json::Value| -> String {
        v["keys"][0]["kid"].as_str().unwrap_or_default().to_string()
    };
    let provider_kid = kid_of(&provider);
    let client_kid = kid_of(&client);

    assert!(!provider_kid.is_empty() && !client_kid.is_empty());
    assert_ne!(
        provider_kid, client_kid,
        "the two sets agree; the second document has no reason to exist"
    );
    assert!(
        client_kid.starts_with("did:key:"),
        "a client assertion names its key by did:key, got {client_kid}"
    );
}

/// The client key set is behind the same gate as the metadata document.
#[tokio::test]
async fn the_client_jwks_is_absent_when_delegation_is_off() {
    let h = build(false).await;
    let response = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth/delegation/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        response.status(),
        StatusCode::OK,
        "a client this server will not act as should not publish keys for it"
    );
}
