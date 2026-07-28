//! Phase 4 OAuth integration tests — PAR → authorize → token end-to-end.

use atproto_identity::key::{KeyData, KeyType, generate_key};
use atproto_oauth::dpop::auth_dpop;
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

/// A loopback `client_id`, whose metadata is derived from the identifier
/// itself rather than fetched. Tests need a client the server will accept
/// without reaching the network; the loopback shape is the specified way to
/// have one, not a test-only shortcut.
const CLIENT_ID: &str = "http://localhost";

/// One of the two redirects a loopback client gets by default.
const REDIRECT_URI: &str = "http://127.0.0.1/";

/// The `htu` a token-endpoint DPoP proof must be bound to, given the
/// `did:web:test.example` service DID these tests build.
const TOKEN_ENDPOINT: &str = "https://test.example/oauth/token";

fn dpop_key() -> KeyData {
    generate_key(KeyType::P256Private).expect("generate DPoP key")
}

/// POST a form-encoded body, optionally attaching a DPoP proof.
async fn post_form(
    app: axum::Router,
    path: &str,
    fields: &[(&str, &str)],
    dpop_proof: Option<&str>,
) -> (StatusCode, Value) {
    let body = fields
        .iter()
        .fold(
            url::form_urlencoded::Serializer::new(String::new()),
            |mut acc, (k, v)| {
                acc.append_pair(k, v);
                acc
            },
        )
        .finish();
    let mut builder = Request::builder()
        .uri(path)
        .method("POST")
        .header("content-type", "application/x-www-form-urlencoded");
    if let Some(proof) = dpop_proof {
        builder = builder.header("DPoP", proof);
    }
    let resp = app
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

/// Run PAR + authorize and return the issued authorization code.
async fn authorize_for_code(app: &axum::Router, challenge: &str) -> String {
    authorize_for_code_with_jkt(app, challenge, None).await
}

/// Run PAR + authorize, optionally pinning a DPoP thumbprint at PAR time.
async fn authorize_for_code_with_jkt(
    app: &axum::Router,
    challenge: &str,
    dpop_jkt: Option<&str>,
) -> String {
    let mut par = json!({
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "atproto transition:generic",
        "state": "abc",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    });
    if let Some(jkt) = dpop_jkt {
        par["dpop_jkt"] = json!(jkt);
    }
    let (status, body) = post_json(app.clone(), "/oauth/par", par).await;
    assert_eq!(status, StatusCode::OK, "PAR setup failed: {body}");
    let request_uri = body["request_uri"].as_str().unwrap().to_string();

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
    assert_eq!(status, StatusCode::OK, "authorize setup failed: {body}");
    body["code"].as_str().unwrap().to_string()
}

/// POST to the token endpoint carrying a DPoP proof signed by `key`.
async fn post_token(app: axum::Router, body: Value, key: &KeyData) -> (StatusCode, Value) {
    let (proof, _, _) = auth_dpop(key, "POST", TOKEN_ENDPOINT).expect("mint DPoP proof");
    let request = Request::builder()
        .uri("/oauth/token")
        .method("POST")
        .header("content-type", "application/json")
        .header("DPoP", proof)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
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
    let key = dpop_key();
    create_account(&app, "did:plc:alice", "alice.example").await;
    let (verifier, challenge) = pkce_pair();

    // 1. PAR.
    let (status, body) = post_json(
        app.clone(),
        "/oauth/par",
        json!({
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
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
    let (status, body) = post_token(
        app,
        json!({
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        }),
        &key,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "token body: {body}");
    assert!(body["access_token"].as_str().unwrap().len() > 50);
    assert!(body["refresh_token"].as_str().unwrap().len() > 50);
    // Every issued token is DPoP-bound, because every grant now has to present
    // a proof. That matches the `require_dpop_bound_access_tokens: true` the
    // server advertises in its authorization-server metadata.
    assert_eq!(body["token_type"], "DPoP");
    assert_eq!(body["sub"], "did:plc:alice");
}

#[tokio::test(flavor = "multi_thread")]
async fn par_rejects_non_s256_pkce() {
    let (app, _tmp) = build_app().await;
    let (status, body) = post_json(
        app,
        "/oauth/par",
        json!({
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
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
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
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
    let key = dpop_key();
    create_account(&app, "did:plc:alice", "alice.example").await;
    let (_verifier, challenge) = pkce_pair();

    let (_, par_body) = post_json(
        app.clone(),
        "/oauth/par",
        json!({
            "client_id": CLIENT_ID, "response_type": "code",
            "redirect_uri": REDIRECT_URI,
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
    let (status, body) = post_token(
        app,
        json!({
            "grant_type": "authorization_code", "client_id": CLIENT_ID,
            "code": code, "redirect_uri": REDIRECT_URI,
            "code_verifier": "wrong-verifier",
        }),
        &key,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_token_rotates() {
    let (app, _tmp) = build_app().await;
    let key = dpop_key();
    create_account(&app, "did:plc:alice", "alice.example").await;
    let (verifier, challenge) = pkce_pair();

    let (_, par_body) = post_json(
        app.clone(),
        "/oauth/par",
        json!({
            "client_id": CLIENT_ID, "response_type": "code",
            "redirect_uri": REDIRECT_URI,
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
    let (_, tokens) = post_token(
        app.clone(),
        json!({
            "grant_type": "authorization_code", "client_id": CLIENT_ID,
            "code": code, "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        }),
        &key,
    )
    .await;
    let refresh = tokens["refresh_token"].as_str().unwrap().to_string();
    let original_access = tokens["access_token"].as_str().unwrap().to_string();

    // Refresh.
    let (status, refreshed) = post_token(
        app.clone(),
        json!({
            "grant_type": "refresh_token", "client_id": CLIENT_ID,
            "refresh_token": refresh,
        }),
        &key,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {refreshed}");
    let new_access = refreshed["access_token"].as_str().unwrap();
    let new_refresh = refreshed["refresh_token"].as_str().unwrap();
    assert_ne!(new_access, original_access);
    assert_ne!(new_refresh, refresh);

    // Single-use: re-presenting the old refresh fails.
    let (status, body) = post_token(
        app,
        json!({
            "grant_type": "refresh_token", "client_id": CLIENT_ID,
            "refresh_token": refresh,
        }),
        &key,
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
            "client_id": CLIENT_ID, "response_type": "code",
            "redirect_uri": REDIRECT_URI,
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
    let key = dpop_key();
    let (status, body) = post_token(
        app,
        json!({"grant_type": "password", "client_id": "x"}),
        &key,
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
    let key = dpop_key();

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
                "client_id": CLIENT_ID,
                "response_type": "code",
                "redirect_uri": REDIRECT_URI,
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

    let (status, body) = post_token(
        app,
        json!({
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        }),
        &key,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "token exchange after restart: {body}"
    );
    assert!(body["access_token"].as_str().unwrap().len() > 50);
}

// ---------------------------------------------------------------------------
// Security regressions: the authorization-code exfiltration chain.
//
// Three defects composed into full account takeover against any user who could
// be phished onto a consent URL, and the compromise was invisible because the
// `client_id` on the consent screen was genuine:
//
//   1. PAR accepted any `redirect_uri`, so the code for a trusted client could
//      be delivered to an attacker (F-OAUTH-03).
//   2. The token endpoint required no proof of possession, so a stolen code was
//      redeemable by whoever held it (F-OAUTH-02).
//   3. The caller chose its own `cnf.jkt`, so the resulting token was
//      DPoP-bound to the attacker's key (F-OAUTH-02).
//
// Each test below closes one link. The wall that made the chain unexploitable
// until now — JSON-only request bodies (F-OAUTH-01) — comes down in the same
// change, which is why all of this ships together.
// ---------------------------------------------------------------------------

/// PAR must refuse a redirect the client never registered.
///
/// This is the first link. The `client_id` here is genuine and the user would
/// see it on the consent screen; only the destination is the attacker's.
#[tokio::test(flavor = "multi_thread")]
async fn par_rejects_redirect_uri_not_registered_by_the_client() {
    let (app, _tmp) = build_app().await;
    let (_, challenge) = pkce_pair();

    let (status, body) = post_json(
        app,
        "/oauth/par",
        json!({
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": "https://attacker.test/steal",
            "scope": "atproto transition:generic",
            "state": "abc",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unregistered redirect_uri must be refused: {body}"
    );
    assert_eq!(body["error"], "invalid_request");
}

/// The token endpoint must refuse a request carrying no DPoP proof.
///
/// This is the second link: without it, a code obtained by any means is
/// redeemable by whoever holds it.
#[tokio::test(flavor = "multi_thread")]
async fn token_rejects_request_without_a_dpop_proof() {
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;
    let key = dpop_key();
    let (verifier, challenge) = pkce_pair();
    let code = authorize_for_code(&app, &challenge).await;

    // Deliberately uses `post_json`, which attaches no DPoP header.
    let (status, body) = post_json(
        app,
        "/oauth/token",
        json!({
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        }),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a token request without a DPoP proof must be refused: {body}"
    );
    assert_eq!(body["error"], "invalid_dpop_proof");
    let _ = key;
}

/// A code pinned to one DPoP key must not be redeemable with another.
///
/// This is the third link, and the one that made DPoP decorative: the caller
/// used to name its own thumbprint, so an attacker redeeming a stolen code
/// received a token bound to the attacker's key.
#[tokio::test(flavor = "multi_thread")]
async fn token_rejects_a_dpop_key_other_than_the_one_pinned_at_authorization() {
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;
    let victim_key = dpop_key();
    let attacker_key = dpop_key();
    let (verifier, challenge) = pkce_pair();

    let victim_jkt = atproto_oauth::dpop::extract_jwk_thumbprint(
        &auth_dpop(&victim_key, "POST", TOKEN_ENDPOINT).unwrap().0,
    )
    .unwrap();
    let code = authorize_for_code_with_jkt(&app, &challenge, Some(&victim_jkt)).await;

    let (status, body) = post_token(
        app,
        json!({
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        }),
        &attacker_key,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "redeeming with a different DPoP key must be refused: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");
}

/// A refresh token must not be usable by a key other than the one it is bound to.
#[tokio::test(flavor = "multi_thread")]
async fn refresh_rejects_a_dpop_key_other_than_the_bound_one() {
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;
    let key = dpop_key();
    let attacker_key = dpop_key();
    let (verifier, challenge) = pkce_pair();
    let code = authorize_for_code(&app, &challenge).await;

    let (status, tokens) = post_token(
        app.clone(),
        json!({
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        }),
        &key,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "setup exchange failed: {tokens}");
    let refresh = tokens["refresh_token"].as_str().unwrap().to_string();

    let (status, body) = post_token(
        app,
        json!({
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": refresh,
        }),
        &attacker_key,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a leaked refresh token must not be bearer-usable: {body}"
    );
    assert_eq!(body["error"], "invalid_grant");
}

/// Form encoding is what every standard client sends, and it must work.
#[tokio::test(flavor = "multi_thread")]
async fn par_and_token_accept_form_encoding() {
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;
    let key = dpop_key();
    let (verifier, challenge) = pkce_pair();

    let (status, body) = post_form(
        app.clone(),
        "/oauth/par",
        &[
            ("client_id", CLIENT_ID),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "atproto transition:generic"),
            ("state", "abc"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "form-encoded PAR must work: {body}");
    let request_uri = body["request_uri"].as_str().unwrap().to_string();

    let (_, authz) = post_json(
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
    let code = authz["code"].as_str().unwrap().to_string();

    let (proof, _, _) = auth_dpop(&key, "POST", TOKEN_ENDPOINT).unwrap();
    let (status, body) = post_form(
        app,
        "/oauth/token",
        &[
            ("grant_type", "authorization_code"),
            ("client_id", CLIENT_ID),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", &verifier),
        ],
        Some(&proof),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "form-encoded token exchange must work: {body}"
    );
    assert_eq!(body["token_type"], "DPoP");
}

/// A session survives repeated refreshes, and every token stays bound to the
/// same key.
///
/// F-OAUTH-04 described a session that broke permanently after the first
/// refresh: an absent `dpop_jkt` was stored as an empty string, came back as
/// `cnf.jkt = ""`, and thereafter no proof could ever match it — an
/// `InvalidDpopProof` with no way out. Requiring a DPoP proof at the token
/// endpoint (F-OAUTH-02) closed that by removing the absent case, and the
/// binding type now makes it unrepresentable.
///
/// This is a regression guard, not a reproduction: it passes before the type
/// change as well. What it pins is the property the type change relies on —
/// that a thumbprint is always present and always the real one.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_survives_repeated_refreshes_bound_to_one_key() {
    let (app, _tmp) = build_app().await;
    let key = dpop_key();
    create_account(&app, "did:plc:alice", "alice.example").await;
    let (verifier, challenge) = pkce_pair();

    let code = authorize_for_code(&app, &challenge).await;
    let (status, tokens) = post_token(
        app.clone(),
        json!({
            "grant_type": "authorization_code", "client_id": CLIENT_ID,
            "code": code, "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        }),
        &key,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {tokens}");
    assert_eq!(
        tokens["token_type"], "DPoP",
        "every token this server issues is DPoP-bound"
    );

    // Refresh three times. The finding's failure appeared on the second
    // exchange — the first refresh minted the poisoned binding, the next use
    // of it failed — so one round trip would not have caught it.
    let mut refresh = tokens["refresh_token"].as_str().unwrap().to_string();
    for round in 0..3 {
        let (status, body) = post_token(
            app.clone(),
            json!({
                "grant_type": "refresh_token", "client_id": CLIENT_ID,
                "refresh_token": refresh,
            }),
            &key,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "refresh {round} should succeed, body: {body}"
        );
        assert_eq!(body["token_type"], "DPoP", "refresh {round}");
        refresh = body["refresh_token"].as_str().unwrap().to_string();
    }
}
