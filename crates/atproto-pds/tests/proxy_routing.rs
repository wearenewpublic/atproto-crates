//! What the AppView proxy sends upstream, asserted through the real router.
//!
//! The defect these cover was concealed by unit tests that called
//! `resolve_target` with a hand-written NSID instead of routing a request. A
//! catch-all mounted after a literal prefix captures only the remainder, so
//! `/xrpc/app.bsky.feed.getTimeline` arrived as `feed.getTimeline` — which no
//! `starts_with("app.bsky.")` check matches, and which forwards to the wrong
//! path. Nothing below hand-writes an NSID.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tower::ServiceExt;

/// A stand-in AppView that records what it was asked for.
struct Upstream {
    base: String,
    seen: Arc<std::sync::Mutex<Vec<String>>>,
}

/// Start a server that records `path?query` for every request and returns `{}`.
async fn start_upstream() -> Upstream {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorder = seen.clone();
    let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
        let recorder = recorder.clone();
        async move {
            let mut full = uri.path().to_string();
            if let Some(query) = uri.query() {
                full.push('?');
                full.push_str(query);
            }
            recorder.lock().unwrap().push(full);
            axum::Json(json!({}))
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Upstream {
        base: format!("http://{addr}"),
        seen,
    }
}

async fn build_app(app_view: Option<&Upstream>) -> (axum::Router, Arc<AccountManager>, TempDir) {
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
    let writer = Arc::new(RepoWriter::new(manager.clone(), dir.clone()));
    let reader = Arc::new(RepoReader::new(accounts, dir.clone()));
    let mut state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer);
    if let Some(upstream) = app_view {
        state =
            state.with_bsky_app_view("did:web:appview.example".to_string(), upstream.base.clone());
    }
    (build_router(state), manager, tmp)
}

async fn create_account(
    app: &axum::Router,
    manager: &AccountManager,
    did: &str,
    handle: &str,
) -> String {
    // Created through the internal API rather than the XRPC endpoint. That
    // endpoint now requires a service-auth token proving control of the DID,
    // signed by a key published in the DID's own document, which a test DID
    // cannot have. Fixture setup is not the thing under test; where
    // `createAccount` itself is the subject, the test calls the endpoint.
    manager
        .create_account(CreateAccountParams::new(did, handle, "pw"))
        .await
        .expect("fixture account should be created");
    manager
        .set_primary_password(did, "pw")
        .await
        .expect("fixture account needs a session password");
    session_token(app, handle).await
}

async fn get(app: axum::Router, path: &str, token: &str) -> StatusCode {
    let req = Request::builder()
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    app.oneshot(req).await.unwrap().status()
}

/// The upstream must receive the full NSID and the original query string.
#[tokio::test(flavor = "multi_thread")]
async fn proxying_forwards_the_full_nsid_and_query() {
    let upstream = start_upstream().await;
    let (app, manager, _tmp) = build_app(Some(&upstream)).await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.test").await;

    let status = get(
        app,
        "/xrpc/app.bsky.feed.getTimeline?limit=5&cursor=abc",
        &token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let seen = upstream.seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec!["/xrpc/app.bsky.feed.getTimeline?limit=5&cursor=abc".to_string()],
        "the upstream must see the whole method name and every parameter"
    );
}

/// A call with no query must not gain a stray `?`.
#[tokio::test(flavor = "multi_thread")]
async fn proxying_without_a_query_sends_a_bare_path() {
    let upstream = start_upstream().await;
    let (app, manager, _tmp) = build_app(Some(&upstream)).await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.test").await;

    assert_eq!(
        get(app, "/xrpc/app.bsky.actor.getProfile", &token).await,
        StatusCode::OK
    );
    assert_eq!(
        upstream.seen.lock().unwrap().clone(),
        vec!["/xrpc/app.bsky.actor.getProfile".to_string()]
    );
}

/// The namespaces a PDS forwards rather than serves are all routed.
#[tokio::test(flavor = "multi_thread")]
async fn every_proxied_namespace_is_routed() {
    let upstream = start_upstream().await;
    let (app, manager, _tmp) = build_app(Some(&upstream)).await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.test").await;

    for path in [
        "/xrpc/app.bsky.feed.getTimeline",
        "/xrpc/chat.bsky.convo.listConvos",
        "/xrpc/tools.ozone.moderation.getRepo",
        "/xrpc/com.atproto.label.queryLabels",
    ] {
        assert_eq!(
            get(app.clone(), path, &token).await,
            StatusCode::OK,
            "{path} should be proxied"
        );
    }

    let seen = upstream.seen.lock().unwrap().clone();
    assert_eq!(
        seen.len(),
        4,
        "all four namespaces reached the upstream: {seen:?}"
    );
    assert!(
        seen.iter()
            .any(|p| p.contains("chat.bsky.convo.listConvos"))
    );
    assert!(
        seen.iter()
            .any(|p| p.contains("tools.ozone.moderation.getRepo"))
    );
    assert!(
        seen.iter()
            .any(|p| p.contains("com.atproto.label.queryLabels"))
    );
}

/// `com.atproto.label.` is proxied; the rest of `com.atproto.` is not.
#[tokio::test(flavor = "multi_thread")]
async fn locally_served_com_atproto_methods_are_not_shadowed() {
    let upstream = start_upstream().await;
    let (app, manager, _tmp) = build_app(Some(&upstream)).await;
    create_account(&app, &manager, "did:plc:alice", "alice.test").await;

    // Served locally, and must stay that way.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.repo.describeRepo?repo=did:plc:alice")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        upstream.seen.lock().unwrap().is_empty(),
        "a locally-served method must not reach the AppView"
    );
}

/// With no AppView configured and no proxy header, the call is refused rather
/// than silently served.
#[tokio::test(flavor = "multi_thread")]
async fn an_unconfigured_proxy_is_refused() {
    let (app, manager, _tmp) = build_app(None).await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.test").await;
    assert_eq!(
        get(app, "/xrpc/app.bsky.feed.getTimeline", &token).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

/// Log in as a fixture account and return its access token.
async fn session_token(app: &axum::Router, handle: &str) -> String {
    let req = Request::builder()
        .uri("/xrpc/com.atproto.server.createSession")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({ "identifier": handle, "password": "pw" })).unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    body["accessJwt"]
        .as_str()
        .expect("createSession should return an access token")
        .to_string()
}
