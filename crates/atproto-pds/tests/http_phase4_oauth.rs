//! Phase 4 OAuth integration tests — PAR → authorize → token end-to-end.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

async fn build_app() -> (axum::Router, TempDir) {
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
    let reader = Arc::new(RepoReader::new(accounts, dir));
    let state = HttpState::with_account_manager(
        reader,
        manager,
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer);
    let app = build_router(state);
    (app, tmp)
}

async fn create_account(app: &axum::Router, did: &str, handle: &str) {
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
    assert!(resp.status().is_success(), "createAccount failed");
}

async fn post_json(app: axum::Router, path: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .uri(path)
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

async fn get_json(app: axum::Router, path: &str) -> (StatusCode, Value) {
    let req = Request::builder().uri(path).body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

fn pkce_pair() -> (String, String) {
    let verifier = "x".repeat(43);
    let challenge = B64URL.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

#[tokio::test(flavor = "multi_thread")]
async fn metadata_documents_published() {
    let (app, _tmp) = build_app().await;
    let (status, body) = get_json(app.clone(), "/.well-known/oauth-authorization-server").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["issuer"], "https://test.example");
    assert_eq!(body["require_pushed_authorization_requests"], true);
    assert!(
        body["scopes_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str() == Some("atproto"))
    );

    let (status, body) = get_json(app, "/.well-known/oauth-protected-resource").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["resource"], "https://test.example");
}

#[tokio::test(flavor = "multi_thread")]
async fn jwks_returns_keys_array() {
    let (app, _tmp) = build_app().await;
    let (status, body) = get_json(app, "/oauth/jwks").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["keys"].as_array().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn par_then_authorize_then_token_flow() {
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;
    let (verifier, challenge) = pkce_pair();

    // 1. PAR.
    let (status, body) = post_json(
        app.clone(),
        "/oauth/par",
        json!({
            "client_id": "https://app.example/cm.json",
            "response_type": "code",
            "redirect_uri": "https://app.example/cb",
            "scope": "atproto transition:generic",
            "state": "abc",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PAR body: {body}");
    let request_uri = body["request_uri"].as_str().unwrap().to_string();
    assert!(request_uri.starts_with("urn:ietf:params:oauth:request_uri:"));

    // 2. authorize.
    let (status, body) = post_json(
        app.clone(),
        "/oauth/authorize",
        json!({
            "request_uri": request_uri,
            "identifier": "alice.example",
            "password": "pw",
            "approve": true,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "authorize body: {body}");
    let code = body["code"].as_str().unwrap().to_string();
    assert_eq!(body["state"], "abc");

    // 3. token exchange.
    let (status, body) = post_json(
        app,
        "/oauth/token",
        json!({
            "grant_type": "authorization_code",
            "client_id": "https://app.example/cm.json",
            "code": code,
            "redirect_uri": "https://app.example/cb",
            "code_verifier": verifier,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "token body: {body}");
    assert!(body["access_token"].as_str().unwrap().len() > 50);
    assert!(body["refresh_token"].as_str().unwrap().len() > 50);
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["sub"], "did:plc:alice");
}

#[tokio::test(flavor = "multi_thread")]
async fn par_rejects_non_s256_pkce() {
    let (app, _tmp) = build_app().await;
    let (status, body) = post_json(
        app,
        "/oauth/par",
        json!({
            "client_id": "https://app.example/cm.json",
            "response_type": "code",
            "redirect_uri": "https://app.example/cb",
            "scope": "atproto",
            "state": "x",
            "code_challenge": "abc",
            "code_challenge_method": "plain",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test(flavor = "multi_thread")]
async fn par_rejects_missing_atproto_scope() {
    let (app, _tmp) = build_app().await;
    let (status, body) = post_json(
        app,
        "/oauth/par",
        json!({
            "client_id": "https://app.example/cm.json",
            "response_type": "code",
            "redirect_uri": "https://app.example/cb",
            "scope": "transition:generic",
            "state": "x",
            "code_challenge": "ZGVhZGJlZWY",
            "code_challenge_method": "S256",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_scope");
}

#[tokio::test(flavor = "multi_thread")]
async fn token_rejects_pkce_mismatch() {
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;
    let (_verifier, challenge) = pkce_pair();

    let (_, par_body) = post_json(
        app.clone(),
        "/oauth/par",
        json!({
            "client_id": "https://c", "response_type": "code",
            "redirect_uri": "https://c/cb",
            "scope": "atproto", "state": "s",
            "code_challenge": challenge, "code_challenge_method": "S256",
        }),
    )
    .await;
    let request_uri = par_body["request_uri"].as_str().unwrap().to_string();

    let (_, authz) = post_json(
        app.clone(),
        "/oauth/authorize",
        json!({
            "request_uri": request_uri, "identifier": "alice.example",
            "password": "pw", "approve": true,
        }),
    )
    .await;
    let code = authz["code"].as_str().unwrap().to_string();

    // Wrong verifier.
    let (status, body) = post_json(
        app,
        "/oauth/token",
        json!({
            "grant_type": "authorization_code", "client_id": "https://c",
            "code": code, "redirect_uri": "https://c/cb",
            "code_verifier": "wrong-verifier",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_token_rotates() {
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;
    let (verifier, challenge) = pkce_pair();

    let (_, par_body) = post_json(
        app.clone(),
        "/oauth/par",
        json!({
            "client_id": "https://c", "response_type": "code",
            "redirect_uri": "https://c/cb",
            "scope": "atproto", "state": "s",
            "code_challenge": challenge, "code_challenge_method": "S256",
        }),
    )
    .await;
    let request_uri = par_body["request_uri"].as_str().unwrap().to_string();
    let (_, authz) = post_json(
        app.clone(),
        "/oauth/authorize",
        json!({
            "request_uri": request_uri, "identifier": "alice.example",
            "password": "pw", "approve": true,
        }),
    )
    .await;
    let code = authz["code"].as_str().unwrap().to_string();
    let (_, tokens) = post_json(
        app.clone(),
        "/oauth/token",
        json!({
            "grant_type": "authorization_code", "client_id": "https://c",
            "code": code, "redirect_uri": "https://c/cb",
            "code_verifier": verifier,
        }),
    )
    .await;
    let refresh = tokens["refresh_token"].as_str().unwrap().to_string();
    let original_access = tokens["access_token"].as_str().unwrap().to_string();

    // Refresh.
    let (status, refreshed) = post_json(
        app.clone(),
        "/oauth/token",
        json!({
            "grant_type": "refresh_token", "client_id": "https://c",
            "refresh_token": refresh,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {refreshed}");
    let new_access = refreshed["access_token"].as_str().unwrap();
    let new_refresh = refreshed["refresh_token"].as_str().unwrap();
    assert_ne!(new_access, original_access);
    assert_ne!(new_refresh, refresh);

    // Single-use: re-presenting the old refresh fails.
    let (status, body) = post_json(
        app,
        "/oauth/token",
        json!({
            "grant_type": "refresh_token", "client_id": "https://c",
            "refresh_token": refresh,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test(flavor = "multi_thread")]
async fn authorize_decline_is_access_denied() {
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;
    let (_verifier, challenge) = pkce_pair();

    let (_, par_body) = post_json(
        app.clone(),
        "/oauth/par",
        json!({
            "client_id": "https://c", "response_type": "code",
            "redirect_uri": "https://c/cb",
            "scope": "atproto", "state": "s",
            "code_challenge": challenge, "code_challenge_method": "S256",
        }),
    )
    .await;
    let request_uri = par_body["request_uri"].as_str().unwrap().to_string();
    let (status, body) = post_json(
        app,
        "/oauth/authorize",
        json!({
            "request_uri": request_uri, "identifier": "alice.example",
            "password": "pw", "approve": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "access_denied");
}

#[tokio::test(flavor = "multi_thread")]
async fn token_unsupported_grant_type_rejected() {
    let (app, _tmp) = build_app().await;
    let (status, body) = post_json(
        app,
        "/oauth/token",
        json!({"grant_type": "password", "client_id": "x"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "unsupported_grant_type");
}

/// acceptance — OAuth in-flight state survives a PDS
/// restart. We simulate the restart by tearing down the axum router and
/// reopening the `accounts.sqlite` against a fresh `OAuthState::sql(...)`.
/// The auth code minted before the "restart" must still exchange for an
/// access token after.
#[tokio::test(flavor = "multi_thread")]
async fn oauth_state_persists_across_restart() {
    use atproto_pds::oauth::state::OAuthState;

    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let db_path = dir.join("accounts.sqlite");
    let (verifier, challenge) = pkce_pair();

    // ---- Phase A: boot, run PAR + authorize, get a code, drop the app. ----
    let code = {
        let accounts = AccountDirectory::open(&db_path).await.unwrap();
        let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
        let manager = Arc::new(AccountManager::new(
            accounts.pool().clone(),
            dir.clone(),
            key_store,
            KeyType::K256Private,
        ));
        let writer = Arc::new(RepoWriter::new(manager.clone(), dir.clone()));
        let reader = Arc::new(RepoReader::new(accounts, dir.clone()));
        let oauth = OAuthState::sql(manager.pool().clone());
        let state = HttpState::with_account_manager(
            reader,
            manager.clone(),
            "did:web:test.example".to_string(),
            b"test-secret-do-not-use-in-prod-32!".to_vec(),
            false,
        )
        .with_writer(writer)
        .with_oauth_state(oauth);
        let app = build_router(state);

        create_account(&app, "did:plc:alice", "alice.example").await;

        let (s, body) = post_json(
            app.clone(),
            "/oauth/par",
            json!({
                "client_id": "https://app.example/cm.json",
                "response_type": "code",
                "redirect_uri": "https://app.example/cb",
                "scope": "atproto transition:generic",
                "state": "abc",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "PAR: {body}");
        let request_uri = body["request_uri"].as_str().unwrap().to_string();

        let (s, body) = post_json(
            app.clone(),
            "/oauth/authorize",
            json!({
                "request_uri": request_uri,
                "identifier": "alice.example",
                "password": "pw",
                "approve": true,
            }),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "authorize: {body}");
        body["code"].as_str().unwrap().to_string()
        // `app`, `state`, `manager`, `accounts` all drop here — simulates
        // the PDS process exiting.
    };

    // ---- Phase B: re-boot pointing at the same DB; redeem the code. ----
    let accounts = AccountDirectory::open(&db_path).await.unwrap();
    let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let manager = Arc::new(AccountManager::new(
        accounts.pool().clone(),
        dir.clone(),
        key_store,
        KeyType::K256Private,
    ));
    let writer = Arc::new(RepoWriter::new(manager.clone(), dir.clone()));
    let reader = Arc::new(RepoReader::new(accounts, dir.clone()));
    let oauth = OAuthState::sql(manager.pool().clone());
    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer)
    .with_oauth_state(oauth);
    let app = build_router(state);

    let (status, body) = post_json(
        app,
        "/oauth/token",
        json!({
            "grant_type": "authorization_code",
            "client_id": "https://app.example/cm.json",
            "code": code,
            "redirect_uri": "https://app.example/cb",
            "code_verifier": verifier,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "token exchange after restart: {body}"
    );
    assert!(body["access_token"].as_str().unwrap().len() > 50);
}
