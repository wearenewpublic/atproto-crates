//! Phase 8 polish integration tests:
//! - OAuth /token rate limiter rejects burst
//! - reserveSigningKey returns a `did:key:` string
//! - requestEmailUpdate validates email shape
//! - GET /oauth/authorize renders HTML consent
//! - subscribeRepos broadcast wakeup propagates writes immediately

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use atproto_pds::security::SlidingWindowLimiter;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tower::ServiceExt;

async fn build_app() -> (axum::Router, Arc<AccountManager>, TempDir) {
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
    // Use a tight rate-limit so the test doesn't have to spam to trigger.
    let limiter = SlidingWindowLimiter::new(2, Duration::from_secs(60), 100);
    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer)
    .with_rate_limiter(limiter);
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

async fn post_json(
    app: axum::Router,
    path: &str,
    body: Value,
    bearer: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .uri(path)
        .method("POST")
        .header("content-type", "application/json");
    if let Some(t) = bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let request = req
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

#[tokio::test(flavor = "multi_thread")]
async fn oauth_token_rate_limit_kicks_in() {
    let (app, _manager, _tmp) = build_app().await;
    // The endpoint will reject before reaching authorization-code processing
    // because we deliberately send invalid grants — but the rate-limit hook
    // runs *first*, so after limit+1 requests the response is 429.
    for _ in 0..2 {
        let (_, _) = post_json(
            app.clone(),
            "/oauth/token",
            json!({
                "grant_type": "authorization_code",
                "client_id": "https://app.example/client-metadata.json",
                "code": "nope"
            }),
            None,
        )
        .await;
    }
    let (status, _) = post_json(
        app.clone(),
        "/oauth/token",
        json!({
            "grant_type": "authorization_code",
            "client_id": "https://app.example/client-metadata.json",
            "code": "still-nope"
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test(flavor = "multi_thread")]
async fn reserve_signing_key_returns_did_key() {
    let (app, manager, _tmp) = build_app().await;
    // Now session-gated: unauthenticated, this generated a fresh keypair per
    // call and wrote a reservation row for any DID the caller named.
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let (status, body) = post_json(
        app,
        "/xrpc/com.atproto.server.reserveSigningKey",
        json!({}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let key = body["signingKey"].as_str().unwrap();
    assert!(
        key.starts_with("did:key:"),
        "expected did:key prefix, got {key}"
    );
}

/// The address is validated where it is now supplied.
///
/// `requestEmailUpdate` takes no input, so this moved to `updateEmail` — the
/// method that actually receives an address.
#[tokio::test(flavor = "multi_thread")]
async fn update_email_validates_email_shape() {
    let (app, manager, _tmp) = build_app().await;
    let bearer = create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    manager
        .set_email("did:plc:alice", Some("old@example.com"))
        .await
        .unwrap();

    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.updateEmail",
        json!({"email": "not-an-email"}),
        Some(&bearer),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = post_json(
        app,
        "/xrpc/com.atproto.server.updateEmail",
        json!({"email": "alice@example.com"}),
        Some(&bearer),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
}

/// `requestEmailUpdate` reports whether a token will be needed, and takes no
/// input to do it.
#[tokio::test(flavor = "multi_thread")]
async fn request_email_update_reports_whether_a_token_is_needed() {
    let (app, manager, _tmp) = build_app().await;
    let bearer = create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    manager
        .set_email("did:plc:alice", Some("old@example.com"))
        .await
        .unwrap();

    let (status, body) = post_json(
        app,
        "/xrpc/com.atproto.server.requestEmailUpdate",
        json!({}),
        Some(&bearer),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["tokenRequired"], false,
        "an unconfirmed address needs no token: {body}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn request_email_update_requires_auth() {
    let (app, _manager, _tmp) = build_app().await;
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.server.requestEmailUpdate",
        json!({"email": "alice@example.com"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Headers a browser sends on a top-level navigation, which is what arriving
/// at the consent screen is.
fn navigation(req: axum::http::request::Builder) -> axum::http::request::Builder {
    req.header("sec-fetch-mode", "navigate")
        .header("sec-fetch-dest", "document")
        .header("sec-fetch-site", "cross-site")
}

#[tokio::test(flavor = "multi_thread")]
async fn oauth_consent_page_responds_404_for_unknown_request_uri() {
    let (app, _manager, _tmp) = build_app().await;
    let req = navigation(Request::builder().uri("/oauth/authorize?request_uri=urn:nope"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Either 400 (invalid_request) is expected for unknown URI.
    assert!(resp.status().is_client_error(), "got {:?}", resp.status());
}

/// The consent screen is only rendered for a real browser navigation.
///
/// It is where an account holder grants an application access to their
/// repository, so a page that can drive it without the user seeing it has a
/// clickjacking and CSRF vector. `Sec-Fetch-*` are forbidden header names —
/// script cannot set them — which is what makes them worth trusting.
///
/// A request carrying none of them is refused too: every browser that can run
/// an OAuth client sends them, so their absence means the caller is not one.
#[tokio::test(flavor = "multi_thread")]
async fn oauth_consent_page_refuses_anything_that_is_not_a_navigation() {
    let (app, _manager, _tmp) = build_app().await;

    for (label, headers) in [
        ("no Sec-Fetch-* at all", vec![]),
        (
            "fetched by script rather than navigated to",
            vec![
                ("sec-fetch-mode", "cors"),
                ("sec-fetch-dest", "empty"),
                ("sec-fetch-site", "cross-site"),
            ],
        ),
        (
            "loaded as a subresource rather than a document",
            vec![
                ("sec-fetch-mode", "navigate"),
                ("sec-fetch-dest", "iframe"),
                ("sec-fetch-site", "cross-site"),
            ],
        ),
    ] {
        let mut req = Request::builder().uri("/oauth/authorize?request_uri=urn:nope");
        for (k, v) in &headers {
            req = req.header(*k, *v);
        }
        let resp = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "consent screen rendered for a request that was {label}",
        );
    }
}

/// The mirror: a genuine navigation is not refused by the guard.
///
/// It still fails on the unknown `request_uri`, which is the point — the
/// request gets past the Fetch Metadata check and is rejected for its
/// contents, not for how it arrived.
#[tokio::test(flavor = "multi_thread")]
async fn oauth_consent_page_admits_a_browser_navigation() {
    let (app, _manager, _tmp) = build_app().await;
    let req = navigation(Request::builder().uri("/oauth/authorize?request_uri=urn:nope"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(
        !text.contains("sec-fetch"),
        "a real navigation was refused by the Fetch Metadata guard: {text}",
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

#[tokio::test(flavor = "multi_thread")]
async fn reserve_signing_key_requires_a_session() {
    let (app, _manager, _tmp) = build_app().await;
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.server.reserveSigningKey",
        json!({ "did": "did:plc:victim" }),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an anonymous caller could force unbounded key generation and squat reservations"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reserve_signing_key_is_idempotent_per_did() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let mut keys = Vec::new();
    for _ in 0..3 {
        let (status, body) = post_json(
            app.clone(),
            "/xrpc/com.atproto.server.reserveSigningKey",
            json!({}),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        keys.push(body["signingKey"].as_str().unwrap().to_string());
    }
    assert_eq!(
        keys[0], keys[1],
        "a repeat reservation must return the key already reserved, not a new one"
    );
    assert_eq!(keys[1], keys[2]);

    assert!(
        manager
            .lookup_reserved_signing_key("did:plc:alice")
            .await
            .expect("lookup should succeed")
            .is_some(),
        "a reservation should exist"
    );
}
