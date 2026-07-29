//! acceptance tests — `com.atproto.identity.*`.
//!
//! Coverage:
//! - `resolveHandle` for a local account.
//! - `resolveHandle` for an unknown handle → 404.
//! - `requestPlcOperationSignature` returns a service-auth JWT scoped to
//!   the PLC-signing lexicon.
//!
//! `updateHandle` requires a live PLC directory at the configured
//! hostname; we don't exercise the full network round-trip here, but the
//! handler is wired and the route is reachable (a separate end-to-end
//! integration would need a mock PLC server).

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
    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer);
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

async fn get_json(app: axum::Router, path: &str, bearer: Option<&str>) -> (StatusCode, Value) {
    let mut req = Request::builder().uri(path);
    if let Some(t) = bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let request = req.body(Body::empty()).unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
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
async fn resolve_handle_returns_local_did() {
    let (app, manager, _tmp) = build_app().await;
    let _ = create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let (status, body) = get_json(
        app,
        "/xrpc/com.atproto.identity.resolveHandle?handle=alice.example",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["did"], "did:plc:alice");
}

#[tokio::test(flavor = "multi_thread")]
async fn resolve_handle_unknown_returns_404() {
    let (app, _manager, _tmp) = build_app().await;

    let (status, _) = get_json(
        app,
        "/xrpc/com.atproto.identity.resolveHandle?handle=nonexistent.invalid",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn request_plc_operation_signature_returns_token() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let (status, body) = post_json(
        app,
        "/xrpc/com.atproto.identity.requestPlcOperationSignature",
        json!({}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let jwt = body["token"].as_str().unwrap();
    // Three dot-separated segments.
    assert_eq!(jwt.split('.').count(), 3);

    // Decode the payload to confirm `lxm` is locked to the PLC method.
    use base64::Engine as _;
    let payload_b64 = jwt.split('.').nth(1).unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .unwrap();
    let payload: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(payload["iss"], "did:plc:alice");
    assert_eq!(payload["lxm"], "com.atproto.identity.signPlcOperation");
    assert!(payload["jti"].is_string());
}

#[tokio::test(flavor = "multi_thread")]
async fn request_plc_operation_signature_requires_auth() {
    let (app, _manager, _tmp) = build_app().await;
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.identity.requestPlcOperationSignature",
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
//  §8.2 — getRecommendedDidCredentials.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn get_recommended_did_credentials_returns_local_state() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let (status, body) = get_json(
        app,
        "/xrpc/com.atproto.identity.getRecommendedDidCredentials",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    // The test harness creates accounts without PDS-managed rotation
    // (rotation_key_ref is null), so rotationKeys is empty.
    assert!(body["rotationKeys"].as_array().unwrap().is_empty());
    // Verification methods carry an `atproto` did:key for the signing key.
    let vm = body["verificationMethods"].as_object().unwrap();
    let atproto = vm.get("atproto").unwrap().as_str().unwrap();
    assert!(atproto.starts_with("did:key:"));
    // alsoKnownAs echoes the registered handle as `at://...`.
    assert_eq!(body["alsoKnownAs"][0], "at://alice.example");
    // services.atproto_pds carries the PDS endpoint.
    let svc = body["services"]["atproto_pds"].as_object().unwrap();
    assert_eq!(svc["type"], "AtprotoPersonalDataServer");
    assert!(svc["endpoint"].as_str().unwrap().ends_with("test.example"));
}

#[tokio::test(flavor = "multi_thread")]
async fn get_recommended_did_credentials_requires_auth() {
    let (app, _manager, _tmp) = build_app().await;
    let (status, _) = get_json(
        app,
        "/xrpc/com.atproto.identity.getRecommendedDidCredentials",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
//  §8.3 — refreshIdentity.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn refresh_identity_emits_event_for_did_web() {
    // did:web doesn't trigger a PLC fetch; the handler still emits an
    // `#identity` event into the per-actor outbox so consumers re-resolve.
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:web:alice.example", "alice.example").await;

    let (status, body) = post_json(
        app,
        "/xrpc/com.atproto.identity.refreshIdentity",
        json!({"did": "did:web:alice.example"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["did"], "did:web:alice.example");
    assert_eq!(body["handleUpdated"], false);
    assert_eq!(body["identityEventEmitted"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_identity_requires_auth() {
    let (app, _manager, _tmp) = build_app().await;
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.identity.refreshIdentity",
        json!({"did": "did:plc:alice"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
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
