//! Phase 5 HTTP integration tests — `com.atproto.server.getServiceAuth`.
//!
//! Mints a short-lived service-auth JWT signed by the calling account's
//! atproto signing key. The receiving service verifies via the issuer's DID
//! document; here we just check structural shape and verify the signature
//! against the same account's key in the test fixture.

use atproto_identity::key::{KeyData, validate as identity_validate};
use atproto_identity::key::{KeyType, to_public};
use atproto_pds::account::{AccountDirectory, AccountManager};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use atproto_pds::space::{SpaceReader, SpaceService, SpaceSync, SpaceWriter};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{Engine as _, engine::general_purpose};
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
    let svc = Arc::new(SpaceService::new(dir.clone()));
    let sw = Arc::new(SpaceWriter::new(manager.clone(), dir.clone()));
    let sr = Arc::new(SpaceReader::new(manager.clone(), dir.clone()));
    let ss = Arc::new(SpaceSync::new(dir.clone()));
    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer)
    .with_spaces(svc, sw, sr, ss);
    (build_router(state), manager, tmp)
}

async fn create_account_and_token(app: &axum::Router, did: &str, handle: &str) -> String {
    let req = Request::builder()
        .uri("/xrpc/com.atproto.server.createAccount")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "did": did,
                "handle": handle,
                "password": "pw"
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    body["accessJwt"].as_str().unwrap().to_string()
}

async fn account_signing_pubkey(manager: &AccountManager, did: &str) -> KeyData {
    let key_ref: (String,) = sqlx::query_as("SELECT signing_key_ref FROM account WHERE did = ?")
        .bind(did)
        .fetch_one(manager.pool())
        .await
        .unwrap();
    let private = manager.key_store().get(&key_ref.0).await.unwrap();
    to_public(&private).unwrap()
}

async fn get_token(app: axum::Router, path: &str, bearer: Option<&str>) -> (StatusCode, Value) {
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

#[tokio::test(flavor = "multi_thread")]
async fn service_auth_round_trip_signature_verifies() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, "did:plc:alice", "alice.example").await;

    let (status, body) = get_token(
        app,
        "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:appview.example&exp=120&lxm=app.bsky.feed.getPosts",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let jwt = body["token"].as_str().unwrap().to_string();

    // Verify the signature against Alice's public key.
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have header.payload.sig");
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = general_purpose::URL_SAFE_NO_PAD
        .decode(parts[2].as_bytes())
        .unwrap();
    let alice_pub = account_signing_pubkey(&manager, "did:plc:alice").await;
    identity_validate(&alice_pub, &sig, signing_input.as_bytes())
        .expect("signature should verify against Alice's atproto key");

    // Inspect payload claims.
    let payload_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1].as_bytes())
        .unwrap();
    let payload: Value = serde_json::from_slice(&payload_bytes).unwrap();
    assert_eq!(payload["iss"], "did:plc:alice");
    assert_eq!(payload["aud"], "did:web:appview.example");
    assert_eq!(payload["lxm"], "app.bsky.feed.getPosts");
    assert!(payload["jti"].as_str().unwrap().len() >= 10);
    let iat = payload["iat"].as_u64().unwrap();
    let exp = payload["exp"].as_u64().unwrap();
    assert_eq!(exp - iat, 120);
}

#[tokio::test(flavor = "multi_thread")]
async fn service_auth_requires_session() {
    let (app, _, _tmp) = build_app().await;
    let (status, _) = get_token(
        app,
        "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:x.example",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn service_auth_rejects_non_did_aud() {
    let (app, _, _tmp) = build_app().await;
    let token = create_account_and_token(&app, "did:plc:alice", "alice.example").await;
    let (status, _) = get_token(
        app,
        "/xrpc/com.atproto.server.getServiceAuth?aud=https://example.com",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn service_auth_clamps_max_ttl() {
    let (app, _, _tmp) = build_app().await;
    let token = create_account_and_token(&app, "did:plc:alice", "alice.example").await;
    let (status, body) = get_token(
        app,
        "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:x.example&exp=99999",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let jwt = body["token"].as_str().unwrap();
    let parts: Vec<&str> = jwt.split('.').collect();
    let payload: Value = serde_json::from_slice(
        &general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1].as_bytes())
            .unwrap(),
    )
    .unwrap();
    let iat = payload["iat"].as_u64().unwrap();
    let exp = payload["exp"].as_u64().unwrap();
    assert_eq!(exp - iat, 600, "ttl should clamp to 600s");
}

#[tokio::test(flavor = "multi_thread")]
async fn service_auth_omits_lxm_when_not_provided() {
    let (app, _, _tmp) = build_app().await;
    let token = create_account_and_token(&app, "did:plc:alice", "alice.example").await;
    let (status, body) = get_token(
        app,
        "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:x.example",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let jwt = body["token"].as_str().unwrap();
    let parts: Vec<&str> = jwt.split('.').collect();
    let payload: Value = serde_json::from_slice(
        &general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1].as_bytes())
            .unwrap(),
    )
    .unwrap();
    assert!(payload.get("lxm").is_none() || payload["lxm"].is_null());
}
