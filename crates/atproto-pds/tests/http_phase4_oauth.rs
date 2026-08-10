//! Phase 4 OAuth integration tests — PAR → authorize → token end-to-end.

use atproto_identity::key::{KeyData, KeyType, generate_key};
use atproto_oauth::dpop::{auth_dpop, extract_jwk_thumbprint, request_dpop};
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams};
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
    let reader = Arc::new(RepoReader::new(accounts, dir));
    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer);
    let app = build_router(state);
    (app, manager, tmp)
}

/// Reopen the same data directory as a fresh app, for asserting what survives
/// a restart.
async fn rebuild_app_over(dir: &std::path::Path) -> axum::Router {
    let dir = dir.to_path_buf();
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
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer);
    build_router(state)
}

/// The same app, but with a policy set the account has not accepted.
async fn build_app_with_policy() -> (axum::Router, Arc<AccountManager>, TempDir) {
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
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer)
    .with_policy_documents(Some(atproto_pds::http::state::PolicyDocuments {
        set_id: "2026-08-05-testpolicyset".to_string(),
        url: "https://example.invalid/policies/2026-08-05".to_string(),
    }));
    let app = build_router(state);
    (app, manager, tmp)
}

async fn create_account(_app: &axum::Router, manager: &AccountManager, did: &str, handle: &str) {
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

/// The `htu` a PAR-time DPoP proof must be bound to.
const PAR_ENDPOINT: &str = "https://test.example/oauth/par";

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

/// Run the full PAR → authorize → token exchange and return an access token
/// carrying exactly `scope`.
async fn token_with_scope(app: &axum::Router, key: &KeyData, scope: &str) -> String {
    let (verifier, challenge) = pkce_pair();
    let (_, par_body) = post_json(
        app.clone(),
        "/oauth/par",
        json!({
            "client_id": CLIENT_ID, "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "scope": scope, "state": "s",
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
    let (status, tokens) = post_token(
        app.clone(),
        json!({
            "grant_type": "authorization_code", "client_id": CLIENT_ID,
            "code": code, "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        }),
        key,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "token exchange: {tokens}");
    tokens["access_token"].as_str().unwrap().to_string()
}

/// Attempt a record write with `token`, returning the status.
/// The token these tests mint is `cnf.jkt`-bound, so it is presented under the
/// `DPoP` scheme (RFC 9449 §7.1) rather than `Bearer`. The scheme is
/// incidental to what the scope tests assert, but sending the wrong one now
/// fails authentication before scope is ever reached.
async fn write_with_token(
    app: &axum::Router,
    key: &KeyData,
    token: &str,
    collection: &str,
) -> StatusCode {
    let uri = "/xrpc/com.atproto.repo.createRecord";
    let (dpop, _, _) = request_dpop(key, "POST", &format!("http://test.example{uri}"), token)
        .expect("mint DPoP proof");
    let request = Request::builder()
        .uri(uri)
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("DPoP {token}"))
        .header("host", "test.example")
        .header("DPoP", dpop)
        .body(Body::from(
            serde_json::to_vec(&json!({
                "repo": "did:plc:alice",
                "collection": collection,
                "record": { "$type": collection, "text": "hi" }
            }))
            .unwrap(),
        ))
        .unwrap();
    app.clone().oneshot(request).await.unwrap().status()
}

/// A `dpop_jkt` that contradicts the DPoP proof on the same PAR request must be
/// refused.
///
/// RFC 9449 §10.1 lets a pushed request bind the key by either mechanism, and
/// either alone is fine — the proof is optional on PAR. What must not happen is
/// the parameter winning over a signed proof: `dpop_jkt` is an assertion by
/// whoever sent the request, so honouring it would let a caller bind the
/// eventual token to a key it does not hold.
#[tokio::test]
async fn par_refuses_a_dpop_jkt_that_contradicts_the_proof() {
    let (app, _manager, _tmp) = build_app().await;

    let holder = dpop_key();
    let other = dpop_key();
    let (proof, _, _) = auth_dpop(&holder, "POST", PAR_ENDPOINT).expect("mint DPoP proof");
    let (other_proof, _, _) = auth_dpop(&other, "POST", PAR_ENDPOINT).expect("mint other proof");
    let holder_jkt = extract_jwk_thumbprint(&proof).expect("thumbprint");
    let other_jkt = extract_jwk_thumbprint(&other_proof).expect("thumbprint");
    assert_ne!(holder_jkt, other_jkt, "the two keys must differ");

    let par = json!({
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "atproto transition:generic",
        "state": "abc",
        "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "code_challenge_method": "S256",
        // Names a key the sender does not hold.
        "dpop_jkt": other_jkt,
    });

    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/oauth/par")
        .header("content-type", "application/json")
        .header("DPoP", proof)
        .body(axum::body::Body::from(serde_json::to_vec(&par).unwrap()))
        .unwrap();
    let res = tower::ServiceExt::oneshot(app.clone(), req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));

    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_dpop_proof", "body: {body}");
}

/// The same request with a matching `dpop_jkt` is accepted, so the check above
/// is rejecting the contradiction rather than the presence of both.
#[tokio::test]
async fn par_accepts_a_dpop_jkt_matching_the_proof() {
    let (app, _manager, _tmp) = build_app().await;

    let holder = dpop_key();
    let (proof, _, _) = auth_dpop(&holder, "POST", PAR_ENDPOINT).expect("mint DPoP proof");
    let holder_jkt = extract_jwk_thumbprint(&proof).expect("thumbprint");

    let par = json!({
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "atproto transition:generic",
        "state": "abc",
        "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "code_challenge_method": "S256",
        "dpop_jkt": holder_jkt,
    });

    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/oauth/par")
        .header("content-type", "application/json")
        .header("DPoP", proof)
        .body(axum::body::Body::from(serde_json::to_vec(&par).unwrap()))
        .unwrap();
    let res = tower::ServiceExt::oneshot(app.clone(), req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));

    // RFC 9126 §2.2: a pushed authorization request responds 201 Created.
    assert_eq!(status, StatusCode::CREATED, "body: {body}");
    assert!(body["request_uri"].is_string(), "body: {body}");
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
    assert_eq!(status, StatusCode::CREATED, "PAR setup failed: {body}");
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
    let (app, _manager, _tmp) = build_app().await;
    let (status, body) = get_json(app.clone(), "/.well-known/oauth-authorization-server").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["issuer"], "https://test.example");
    assert_eq!(body["require_pushed_authorization_requests"], true);
    // AT Protocol identifies a client by the URL of its metadata document, and
    // `@atproto/oauth-client` refuses any server that does not say so:
    // `Authorization server "..." does not support client_id_metadata_document`
    // is thrown before a single request is made. Without this field no client
    // built on the official library can authenticate here at all.
    assert_eq!(body["client_id_metadata_document_supported"], true);
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
    let (app, _manager, _tmp) = build_app().await;
    let (status, body) = get_json(app, "/oauth/jwks").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["keys"].as_array().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn par_then_authorize_then_token_flow() {
    let (app, manager, _tmp) = build_app().await;
    let key = dpop_key();
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
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
    assert_eq!(status, StatusCode::CREATED, "PAR body: {body}");
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
    let (app, _manager, _tmp) = build_app().await;
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
    let (app, _manager, _tmp) = build_app().await;
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
    let (app, manager, _tmp) = build_app().await;
    let key = dpop_key();
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
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
    let (app, manager, _tmp) = build_app().await;
    let key = dpop_key();
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
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
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
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
    let (app, _manager, _tmp) = build_app().await;
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

        create_account(&app, &manager, "did:plc:alice", "alice.example").await;

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
        assert_eq!(s, StatusCode::CREATED, "PAR: {body}");
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
    let (app, _manager, _tmp) = build_app().await;
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
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
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
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
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
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
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
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
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
    assert_eq!(
        status,
        StatusCode::CREATED,
        "form-encoded PAR must work: {body}"
    );
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
    let (app, manager, _tmp) = build_app().await;
    let key = dpop_key();
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
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

// ---------------------------------------------------------------------------
//  Granular scope enforcement (F-OAUTH-12).
//
//  The authorization server parsed and stored what it granted; the resource
//  server never consulted it. Every OAuth token behaved as a wildcard.
// ---------------------------------------------------------------------------

/// `atproto` alone must not authorise a repo write.
///
/// It is the scope that says "other AT Protocol scopes will be used" — on its
/// own it grants nothing, and it used to grant everything.
#[tokio::test(flavor = "multi_thread")]
async fn atproto_alone_cannot_write_a_record() {
    let (app, manager, _tmp) = build_app().await;
    let key = dpop_key();
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let token = token_with_scope(&app, &key, "atproto").await;
    let status = write_with_token(&app, &key, &token, "app.bsky.feed.post").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a token granted only `atproto` wrote a record"
    );
}

/// A grant for one collection does not confer another.
#[tokio::test(flavor = "multi_thread")]
async fn a_repo_grant_is_bounded_by_collection() {
    let (app, manager, _tmp) = build_app().await;
    let key = dpop_key();
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let token = token_with_scope(&app, &key, "atproto repo:app.bsky.feed.post?action=create").await;

    assert_eq!(
        write_with_token(&app, &key, &token, "app.bsky.feed.post").await,
        StatusCode::OK,
        "the granted collection should be writable"
    );
    assert_eq!(
        write_with_token(&app, &key, &token, "app.bsky.graph.follow").await,
        StatusCode::FORBIDDEN,
        "a grant for one collection conferred another"
    );
}

/// The legacy migration scope keeps working.
///
/// `transition:generic` is what most AT Protocol OAuth clients request today.
/// Enforcing the granular axes without honouring it would refuse all of them.
#[tokio::test(flavor = "multi_thread")]
async fn transition_generic_still_writes() {
    let (app, manager, _tmp) = build_app().await;
    let key = dpop_key();
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let token = token_with_scope(&app, &key, "atproto transition:generic").await;
    assert_eq!(
        write_with_token(&app, &key, &token, "app.bsky.feed.post").await,
        StatusCode::OK,
        "the legacy full-access scope must keep working"
    );
}

/// The refusal names the scope that would have worked.
#[tokio::test(flavor = "multi_thread")]
async fn a_scope_refusal_says_what_was_needed() {
    let (app, manager, _tmp) = build_app().await;
    let key = dpop_key();
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let token = token_with_scope(&app, &key, "atproto").await;

    let uri = "/xrpc/com.atproto.repo.createRecord";
    let (dpop, _, _) = request_dpop(&key, "POST", &format!("http://test.example{uri}"), &token)
        .expect("mint DPoP proof");
    let request = Request::builder()
        .uri(uri)
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("DPoP {token}"))
        .header("host", "test.example")
        .header("DPoP", dpop)
        .body(Body::from(
            serde_json::to_vec(&json!({
                "repo": "did:plc:alice",
                "collection": "app.bsky.feed.post",
                "record": { "$type": "app.bsky.feed.post", "text": "hi" }
            }))
            .unwrap(),
        ))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();

    assert_eq!(body["error"], "InsufficientScope");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("repo:app.bsky.feed.post?action=create"),
        "the refusal should name the scope that would have worked: {body}"
    );
}

/// An app-password session is unaffected — it carries no scopes and is
/// full-authority, which is how the space assertions already treat it.
#[tokio::test(flavor = "multi_thread")]
async fn an_app_password_session_is_not_scope_checked() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let (_, session) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.createSession",
        json!({ "identifier": "alice.example", "password": "pw" }),
    )
    .await;
    let token = session["accessJwt"]
        .as_str()
        .expect("accessJwt")
        .to_string();

    let request = Request::builder()
        .uri("/xrpc/com.atproto.repo.createRecord")
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&json!({
                "repo": "did:plc:alice",
                "collection": "app.bsky.feed.post",
                "record": { "$type": "app.bsky.feed.post", "text": "hi" }
            }))
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::OK
    );
}

// ---------------------------------------------------------------------------
//  F-OAUTH-17 — endpoints that accept an OAuth token, and those that do not.
//
//  Before this, every endpoint in `auth_handlers` verified an app-password
//  session and nothing else, so a valid OAuth token was answered
//  `expected typ at-pp-access, got at-oauth-access`. That is right for the
//  endpoints the reference puts out of OAuth's reach and wrong for the five it
//  does not — including `getSession`, which is the first call most clients make
//  after authorizing.
// ---------------------------------------------------------------------------

/// GET an endpoint with a DPoP-bound OAuth token.
async fn get_with_token(
    app: &axum::Router,
    key: &KeyData,
    token: &str,
    path: &str,
) -> (StatusCode, Value) {
    let (dpop, _, _) = request_dpop(key, "GET", &format!("http://test.example{path}"), token)
        .expect("mint DPoP proof");
    let request = Request::builder()
        .uri(path)
        .method("GET")
        .header("authorization", format!("DPoP {token}"))
        .header("host", "test.example")
        .header("DPoP", dpop)
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
            .unwrap_or(Value::Null);
    (status, body)
}

/// POST an endpoint with a DPoP-bound OAuth token.
async fn post_with_token(
    app: &axum::Router,
    key: &KeyData,
    token: &str,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let (dpop, _, _) = request_dpop(key, "POST", &format!("http://test.example{path}"), token)
        .expect("mint DPoP proof");
    let request = Request::builder()
        .uri(path)
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("DPoP {token}"))
        .header("host", "test.example")
        .header("DPoP", dpop)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
            .unwrap_or(Value::Null);
    (status, body)
}

/// `getSession` takes any OAuth token. It is the first call most clients make,
/// and refusing it made every token look broken at the first hop.
#[tokio::test(flavor = "multi_thread")]
async fn get_session_accepts_an_oauth_token() {
    let (app, manager, _tmp) = build_app().await;
    let key = dpop_key();
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    // Deliberately the narrowest scope there is: `atproto` alone grants no
    // repo, blob or rpc access, and getSession must still work — the policy is
    // "any token", not "a broadly scoped one".
    let token = token_with_scope(&app, &key, "atproto").await;
    let (status, body) =
        get_with_token(&app, &key, &token, "/xrpc/com.atproto.server.getSession").await;

    assert_eq!(
        status,
        StatusCode::OK,
        "getSession refused an OAuth token: {body}"
    );
    assert_eq!(body["did"], "did:plc:alice");
}

/// `checkAccountStatus` likewise.
#[tokio::test(flavor = "multi_thread")]
async fn check_account_status_accepts_an_oauth_token() {
    let (app, manager, _tmp) = build_app().await;
    let key = dpop_key();
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let token = token_with_scope(&app, &key, "atproto").await;
    let (status, body) = get_with_token(
        &app,
        &key,
        &token,
        "/xrpc/com.atproto.server.checkAccountStatus",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "checkAccountStatus refused an OAuth token: {body}"
    );
}

/// `signPlcOperation` needs `identity:*`, not merely a token.
///
/// The two halves matter together: a bare token is refused and a token holding
/// the scope gets past authentication. Without the second, the test would pass
/// against a handler that refused everything.
#[tokio::test(flavor = "multi_thread")]
async fn sign_plc_operation_requires_identity_all() {
    let (app, manager, _tmp) = build_app().await;
    let key = dpop_key();
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let path = "/xrpc/com.atproto.identity.signPlcOperation";

    let bare = token_with_scope(&app, &key, "atproto").await;
    let (status, body) = post_with_token(&app, &key, &bare, path, json!({})).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a bare token reached signPlcOperation: {body}"
    );
    assert_eq!(body["error"], "InsufficientScope");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("identity:*"),
        "the refusal should name the scope that would work, got {body}"
    );

    // `identity:handle` is not enough either — a PLC operation can rewrite
    // rotation keys, not just the handle.
    let handle_only = token_with_scope(&app, &key, "atproto identity:handle").await;
    let (status, body) = post_with_token(&app, &key, &handle_only, path, json!({})).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "identity:handle should not authorise a PLC operation: {body}"
    );

    // With `identity:*` the scope check passes; the request then fails on its
    // own merits (no signing key reserved), which is a different error.
    let full = token_with_scope(&app, &key, "atproto identity:*").await;
    let (status, body) = post_with_token(&app, &key, &full, path, json!({})).await;
    assert_ne!(
        body["error"], "InsufficientScope",
        "identity:* should satisfy the scope check, got {status} {body}"
    );
}

/// `requestEmailConfirmation` needs `account:email?action=manage`.
#[tokio::test(flavor = "multi_thread")]
async fn request_email_confirmation_requires_email_manage() {
    let (app, manager, _tmp) = build_app().await;
    let key = dpop_key();
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let path = "/xrpc/com.atproto.server.requestEmailConfirmation";

    let bare = token_with_scope(&app, &key, "atproto").await;
    let (status, body) = post_with_token(&app, &key, &bare, path, json!({})).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a bare token reached it: {body}"
    );
    assert_eq!(body["error"], "InsufficientScope");

    let granted = token_with_scope(&app, &key, "atproto account:email?action=manage").await;
    let (status, body) = post_with_token(&app, &key, &granted, path, json!({})).await;
    assert_ne!(
        body["error"], "InsufficientScope",
        "account:email?action=manage should satisfy it, got {status} {body}"
    );
}

/// The endpoints the reference puts out of OAuth's reach stay refused — and
/// say so, rather than reporting a JWT `typ` mismatch that sends client
/// authors looking for a bug in their token.
#[tokio::test(flavor = "multi_thread")]
async fn account_lifecycle_endpoints_refuse_oauth_and_say_why() {
    let (app, manager, _tmp) = build_app().await;
    let key = dpop_key();
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    // The broadest scope obtainable, to show the refusal is categorical rather
    // than a scope shortfall that a wider grant could fix.
    let token = token_with_scope(&app, &key, "atproto transition:generic identity:*").await;

    // Each body is valid for its endpoint. Axum runs body extraction before
    // the handler runs, so a malformed body would be answered 400 without the
    // auth check ever being reached — and the test would prove nothing.
    for (path, body) in [
        (
            "/xrpc/com.atproto.server.createAppPassword",
            json!({"name": "x"}),
        ),
        ("/xrpc/com.atproto.server.requestAccountDelete", json!({})),
        (
            "/xrpc/com.atproto.server.requestEmailUpdate",
            json!({"email": "new@example.invalid"}),
        ),
        ("/xrpc/com.atproto.server.deactivateAccount", json!({})),
    ] {
        let (status, body) = post_with_token(&app, &key, &token, path, body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{path} should refuse OAuth: {body}"
        );
        assert_eq!(
            body["message"], "OAuth credentials are not supported for this endpoint",
            "{path} should say OAuth is not accepted, not leak the JWT typ"
        );
    }
}

/// An account that owes a policy acceptance cannot complete an OAuth
/// authorization.
///
/// `createSession` is gated the same way, and gating only that one would leave
/// the requirement trivially avoidable: a client that wanted a credential
/// would ask for an OAuth grant instead. The two are different doors into the
/// same house.
#[tokio::test(flavor = "multi_thread")]
async fn authorize_is_refused_until_the_policy_is_accepted() {
    let (app, manager, _tmp) = build_app_with_policy().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let (_, challenge) = pkce_pair();
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
    let request_uri = par_body["request_uri"].as_str().expect("request_uri");

    let (status, body) = post_json(
        app,
        "/oauth/authorize",
        json!({
            "request_uri": request_uri, "identifier": "alice.example",
            "password": "pw", "approve": true,
        }),
    )
    .await;
    // Refused *after* the password was accepted, so this is not a credential
    // failure being mistaken for a policy one.
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    assert_eq!(body["error"], "access_denied", "body: {body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("accept the current policy"),
        "body: {body}"
    );
    assert!(
        body["code"].is_null(),
        "an authorization code was issued anyway"
    );
}

/// A session minted before the policy existed cannot mint fresh credentials.
///
/// The session gate alone does not cover this: the token predates the policy,
/// so it is still valid, and without a check on `createAppPassword` it could
/// hand out a credential the gate was meant to withhold -- outliving the
/// requirement rather than being subject to it.
#[tokio::test(flavor = "multi_thread")]
async fn an_existing_session_cannot_mint_an_app_password_while_a_policy_is_owed() {
    // Signed in first, on a server with no policy, exactly as an account that
    // predates the policy would have been.
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let (status, session) = post_json(
        app,
        "/xrpc/com.atproto.server.createSession",
        json!({ "identifier": "alice.example", "password": "pw" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {session}");
    let token = session["accessJwt"]
        .as_str()
        .expect("accessJwt")
        .to_string();

    // The operator then introduces a policy. Same accounts, same tokens.
    let (gated, _gated_manager, _tmp2) = build_app_with_policy().await;
    create_account(&gated, &_gated_manager, "did:plc:alice", "alice.example").await;
    let (status, fresh) = post_json(
        gated.clone(),
        "/xrpc/com.atproto.server.createSession",
        json!({ "identifier": "alice.example", "password": "pw" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the session gate should already refuse: {fresh}"
    );

    // And a token that predates it cannot be spent on a new credential.
    let req = axum::http::Request::builder()
        .uri("/xrpc/com.atproto.server.createAppPassword")
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(axum::body::Body::from(
            serde_json::to_vec(&json!({ "name": "sneaky" })).unwrap(),
        ))
        .unwrap();
    let resp = gated.oneshot(req).await.unwrap();
    let status = resp.status();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap_or(serde_json::Value::Null);
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "PolicyAcceptanceRequired", "body: {body}");
    assert!(
        body["password"].is_null(),
        "an app password was issued anyway"
    );
}

/// The authorization-server document declares what it accepts for signed
/// client JWTs.
///
/// `private_key_jwt` is offered, and RFC 8414 requires the algorithm list
/// alongside it; AT Protocol requires ES256 among them. Without it a client
/// cannot know what to sign with, and a validating one refuses the server
/// before issuing a single request -- which is exactly what happened: an
/// OAuth login failed at metadata fetch with "Token endpoint auth signing
/// algorithm values must include 'ES256'".
#[tokio::test(flavor = "multi_thread")]
async fn the_metadata_declares_its_signing_algorithms() {
    let (app, _mgr, _tmp) = build_app().await;

    let (status, body) = get_json(app.clone(), "/.well-known/oauth-authorization-server").await;
    assert_eq!(status, StatusCode::OK);

    let algs = body["token_endpoint_auth_signing_alg_values_supported"]
        .as_array()
        .expect("private_key_jwt is offered, so this list is required");
    assert!(
        algs.iter().any(|a| a == "ES256"),
        "AT Protocol requires ES256 here; clients refuse the server without it: {algs:?}"
    );

    // The request-object list must match what verify_request_object enforces,
    // or a client signs with something this server will reject.
    let request_algs = body["request_object_signing_alg_values_supported"]
        .as_array()
        .expect("request objects are accepted, so this list belongs here");
    assert!(
        request_algs.iter().any(|a| a == "ES256"),
        "{request_algs:?}"
    );
}

/// Our metadata satisfies every check the atproto OAuth client makes.
///
/// Three separate logins failed here in sequence, each on a different missing
/// field, because the document was compared against the spec by eye and the
/// checks live in `atproto_oauth::resources::oauth_authorization_server`.
/// Deserialising into that crate's own `AuthorizationServer` and asserting its
/// twelve conditions turns the next omission into a test failure rather than
/// another round trip through a browser.
///
/// The type matters as much as the assertions: a field renamed here stops
/// deserialising there, which is the same failure a client would see.
#[tokio::test(flavor = "multi_thread")]
async fn the_metadata_satisfies_the_atproto_oauth_client() {
    use atproto_oauth::resources::AuthorizationServer;

    let (app, _mgr, _tmp) = build_app().await;
    let (status, body) = get_json(app.clone(), "/.well-known/oauth-authorization-server").await;
    assert_eq!(status, StatusCode::OK);

    let meta: AuthorizationServer =
        serde_json::from_value(body.clone()).expect("must deserialise as the client's own type");

    // auth-server-1..5
    assert!(!meta.issuer.is_empty(), "{body}");
    assert!(
        meta.response_types_supported.iter().any(|v| v == "code"),
        "{body}"
    );
    assert!(
        meta.grant_types_supported
            .iter()
            .any(|v| v == "authorization_code"),
        "{body}"
    );
    assert!(
        meta.grant_types_supported
            .iter()
            .any(|v| v == "refresh_token"),
        "{body}"
    );
    assert!(
        meta.code_challenge_methods_supported
            .iter()
            .any(|v| v == "S256"),
        "{body}"
    );
    // auth-server-6..8
    assert!(
        meta.token_endpoint_auth_methods_supported
            .iter()
            .any(|v| v == "none"),
        "{body}"
    );
    assert!(
        meta.token_endpoint_auth_methods_supported
            .iter()
            .any(|v| v == "private_key_jwt"),
        "{body}"
    );
    assert!(
        meta.token_endpoint_auth_signing_alg_values_supported
            .iter()
            .any(|v| v == "ES256"),
        "{body}"
    );
    // auth-server-9..11
    assert!(
        meta.scopes_supported.iter().any(|v| v == "atproto"),
        "{body}"
    );
    assert!(
        meta.scopes_supported
            .iter()
            .any(|v| v == "transition:generic"),
        "{body}"
    );
    assert!(
        meta.dpop_signing_alg_values_supported
            .iter()
            .any(|v| v == "ES256"),
        "{body}"
    );
    // auth-server-12 — the three that must all be true together.
    assert!(
        meta.authorization_response_iss_parameter_supported
            && meta.require_pushed_authorization_requests
            && meta.client_id_metadata_document_supported,
        "the client refuses a server missing any of these: {body}"
    );
}

/// Revoking an access token must stop it authenticating.
///
/// The endpoint reported success and did nothing: it put the token's `jti`
/// into the JTI replay guard, which is only ever consulted for the *DPoP
/// proof's* jti -- a different claim from a different JWT -- so the revoked
/// token kept working for its whole remaining lifetime.
///
/// The unit test that was supposed to cover this asserted against a local
/// reimplementation of the revoke logic and then queried the guard directly.
/// It never called the handler and never asked whether authentication
/// consulted anything, so it passed throughout. This one goes through the
/// HTTP endpoint and then tries to use the token.
#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_access_token_stops_authenticating() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let key = generate_key(KeyType::P256Private).unwrap();
    let token = token_with_scope(&app, &key, "atproto transition:generic").await;

    // It works before revocation, or the test proves nothing afterwards.
    assert_eq!(
        write_with_token(&app, &key, &token, "app.bsky.feed.post").await,
        StatusCode::OK,
        "the token should authenticate before it is revoked"
    );

    let (status, _) = post_form(
        app.clone(),
        "/oauth/revoke",
        &[
            ("token", token.as_str()),
            ("token_type_hint", "access_token"),
        ],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "RFC 7009 always answers 200");

    assert_eq!(
        write_with_token(&app, &key, &token, "app.bsky.feed.post").await,
        StatusCode::UNAUTHORIZED,
        "the revoked token still authenticated"
    );
}

/// Revocation must outlive the process. It is durable state, not a cache: the
/// replay guard it used to be written to is memory-backed by default, so a
/// restart would have restored every revoked token even once the guard was
/// being read.
#[tokio::test(flavor = "multi_thread")]
async fn a_revocation_survives_a_restart() {
    let (app, manager, tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let key = generate_key(KeyType::P256Private).unwrap();
    let token = token_with_scope(&app, &key, "atproto transition:generic").await;

    let (status, _) = post_form(
        app.clone(),
        "/oauth/revoke",
        &[
            ("token", token.as_str()),
            ("token_type_hint", "access_token"),
        ],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Same data directory, fresh process state.
    let restarted = rebuild_app_over(tmp.path()).await;
    assert_eq!(
        write_with_token(&restarted, &key, &token, "app.bsky.feed.post").await,
        StatusCode::UNAUTHORIZED,
        "the revocation did not survive a restart"
    );
}

/// Obtain a refresh token for `alice`, bound to `key`.
async fn refresh_token_for(app: &axum::Router, key: &KeyData) -> String {
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
    let (status, tokens) = post_token(
        app.clone(),
        json!({
            "grant_type": "authorization_code", "client_id": CLIENT_ID,
            "code": code, "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        }),
        key,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "token exchange: {tokens}");
    tokens["refresh_token"].as_str().unwrap().to_string()
}

/// A refresh token presented without its DPoP key must not consume it.
///
/// Rotation ran before the binding check, and rotation succeeds for anyone
/// holding the token bytes. So a thief with no key could burn the legitimate
/// client's token -- the thief got an error, the rightful holder got logged
/// out, and it could be repeated on every new token the client obtained.
#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_presented_without_its_key_does_not_consume_it() {
    let (app, manager, _tmp) = build_app().await;
    let key = dpop_key();
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let refresh = refresh_token_for(&app, &key).await;

    // The thief has the token bytes but a different key.
    let thief_key = generate_key(KeyType::P256Private).unwrap();
    let (status, body) = post_token(
        app.clone(),
        json!({
            "grant_type": "refresh_token", "client_id": CLIENT_ID,
            "refresh_token": refresh,
        }),
        &thief_key,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "the thief must be refused");
    assert_eq!(body["error"], "invalid_grant", "{body}");

    // The rightful holder is unaffected.
    let (status, body) = post_token(
        app,
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
        "a failed theft consumed the legitimate refresh token: {body}"
    );
}

/// Presenting an already-rotated refresh token ends the whole grant.
///
/// OAuth 2.1 §4.14.2: the explanations for a second presentation are a leaked
/// token being used or a client racing itself, and ending the grant is the
/// right answer to both. Previously the replay got a generic `invalid_grant`
/// while whoever held the successor -- possibly the attacker -- went on
/// refreshing indefinitely.
#[tokio::test(flavor = "multi_thread")]
async fn replaying_a_consumed_refresh_token_revokes_the_whole_grant() {
    let (app, manager, _tmp) = build_app().await;
    let key = dpop_key();
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let first = refresh_token_for(&app, &key).await;

    let (status, refreshed) = post_token(
        app.clone(),
        json!({
            "grant_type": "refresh_token", "client_id": CLIENT_ID,
            "refresh_token": first,
        }),
        &key,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{refreshed}");
    let second = refreshed["refresh_token"].as_str().unwrap().to_string();

    // Replay the consumed one.
    let (status, body) = post_token(
        app.clone(),
        json!({
            "grant_type": "refresh_token", "client_id": CLIENT_ID,
            "refresh_token": first,
        }),
        &key,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // The successor must now be dead too. Without family revocation it would
    // still work, which is the whole point: detecting the replay is worthless
    // if the token the attacker holds keeps refreshing.
    let (status, body) = post_token(
        app,
        json!({
            "grant_type": "refresh_token", "client_id": CLIENT_ID,
            "refresh_token": second,
        }),
        &key,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the successor survived a detected replay: {body}"
    );
    assert_eq!(body["error"], "invalid_grant", "{body}");
}

/// A login must not say which half was wrong.
///
/// "no such account" and "invalid identifier or password" were distinct
/// replies, so anyone could ask this server whether a handle exists on it --
/// the first step of a credential-stuffing run, answered for free and at the
/// ordinary rate-limit tier.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_account_and_a_wrong_password_are_indistinguishable() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    // A real PAR request each time, so both attempts fail on the credential
    // rather than on the request_uri.
    let attempt = |app: axum::Router, identifier: &'static str, password: &'static str| async move {
        let (_, challenge) = pkce_pair();
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
        post_json(
            app,
            "/oauth/authorize",
            json!({
                "request_uri": request_uri, "identifier": identifier,
                "password": password, "approve": true,
            }),
        )
        .await
    };

    let (absent_status, absent_body) = attempt(app.clone(), "nobody.example", "whatever").await;
    let (wrong_status, wrong_body) = attempt(app.clone(), "alice.example", "wrong").await;

    assert_eq!(
        absent_status, wrong_status,
        "status distinguishes a missing account from a bad password"
    );
    assert_eq!(
        absent_body["error"], wrong_body["error"],
        "error code distinguishes a missing account from a bad password"
    );
    assert_eq!(
        absent_body["message"], wrong_body["message"],
        "message distinguishes a missing account from a bad password: \
         {absent_body} vs {wrong_body}"
    );
}

/// The same app, but requiring DPoP nonces the way a conformant server does.
async fn build_app_requiring_nonces() -> (axum::Router, Arc<AccountManager>, TempDir) {
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
    let issuer = atproto_pds::oauth::nonce::NonceIssuer::new(Arc::new(
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
    ));
    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer)
    .with_dpop_nonce(issuer.clone());
    let app = atproto_pds::http::with_dpop_nonce(build_router(state), issuer);
    (app, manager, tmp)
}

/// A proof without a nonce must be answered with the nonce to use, not merely
/// refused. A client that has never spoken to this server cannot know one, so
/// its first request failing is the protocol working -- but only if the reply
/// carries what the retry needs.
#[tokio::test(flavor = "multi_thread")]
async fn a_proof_without_a_nonce_is_challenged_with_one() {
    let (app, manager, _tmp) = build_app_requiring_nonces().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let key = dpop_key();

    let (dpop, _, _) = auth_dpop(&key, "POST", PAR_ENDPOINT).unwrap();
    let (_, challenge) = pkce_pair();
    let request = Request::builder()
        .uri("/oauth/par")
        .method("POST")
        .header("content-type", "application/json")
        .header("host", "test.example")
        .header("DPoP", dpop)
        .body(Body::from(
            serde_json::to_vec(&json!({
                "client_id": CLIENT_ID, "response_type": "code",
                "redirect_uri": REDIRECT_URI,
                "scope": "atproto", "state": "s",
                "code_challenge": challenge, "code_challenge_method": "S256",
            }))
            .unwrap(),
        ))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let nonce = response
        .headers()
        .get("dpop-nonce")
        .expect("the challenge must carry the nonce to retry with")
        .to_str()
        .unwrap()
        .to_string();
    assert!(!nonce.is_empty());
    let www = response
        .headers()
        .get(axum::http::header::WWW_AUTHENTICATE)
        .expect("a client should not have to parse prose to know what happened")
        .to_str()
        .unwrap()
        .to_string();
    assert!(www.contains("use_dpop_nonce"), "{www}");
}

/// And retrying with the challenged nonce works, which is the half that makes
/// the challenge a protocol rather than an outage.
///
/// This is the client's actual sequence: send, be challenged, read the nonce
/// off the refusal, resend. The nonce comes from the challenge deliberately --
/// an authorization-server nonce is what `/oauth/par` wants, and a client that
/// picked one up from some earlier XRPC response would hold a resource-server
/// one, which is a different value by design.
#[tokio::test(flavor = "multi_thread")]
async fn retrying_with_the_challenged_nonce_succeeds() {
    let (app, manager, _tmp) = build_app_requiring_nonces().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let key = dpop_key();

    let par_request = |dpop: String| {
        let (_, challenge) = pkce_pair();
        Request::builder()
            .uri("/oauth/par")
            .method("POST")
            .header("content-type", "application/json")
            .header("host", "test.example")
            .header("DPoP", dpop)
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "client_id": CLIENT_ID, "response_type": "code",
                    "redirect_uri": REDIRECT_URI,
                    "scope": "atproto", "state": "s",
                    "code_challenge": challenge, "code_challenge_method": "S256",
                }))
                .unwrap(),
            ))
            .unwrap()
    };

    let (first, _, _) = auth_dpop(&key, "POST", PAR_ENDPOINT).unwrap();
    let challenged = app.clone().oneshot(par_request(first)).await.unwrap();
    assert_eq!(challenged.status(), StatusCode::UNAUTHORIZED);
    let nonce = challenged
        .headers()
        .get("dpop-nonce")
        .expect("the challenge must name the nonce to retry with")
        .to_str()
        .unwrap()
        .to_string();

    let (retry, _, _) =
        atproto_oauth::dpop::dpop_with_nonce(&key, "POST", PAR_ENDPOINT, None, &nonce).unwrap();
    let response = app.oneshot(par_request(retry)).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "a proof carrying the challenged nonce must be accepted"
    );
}

/// Every response carries the current nonce, so a client that keeps the latest
/// value it saw is challenged once per session rather than once per request.
#[tokio::test(flavor = "multi_thread")]
async fn every_response_carries_the_current_nonce() {
    let (app, _manager, _tmp) = build_app_requiring_nonces().await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/xrpc/_health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        response.headers().contains_key("dpop-nonce"),
        "an ordinary response should hand the client a current nonce"
    );
}

/// A nonce minted for the authorization server is not valid at the resource
/// server. RFC 9449 §8.1 keeps the two separate and this process is both.
#[tokio::test(flavor = "multi_thread")]
async fn an_authorization_nonce_is_not_accepted_at_the_resource_server() {
    use atproto_pds::oauth::nonce::{NonceIssuer, NonceSpace};
    let issuer = NonceIssuer::new(Arc::new(b"test-secret-do-not-use-in-prod-32!".to_vec()));
    assert!(
        !issuer
            .accepted(NonceSpace::Resource)
            .contains(&issuer.current(NonceSpace::Authorization)),
        "the two nonce spaces must not overlap"
    );
}

/// `getServiceAuth` mints a credential signed with the account's own key,
/// naming an audience and method of the caller's choosing -- the same thing
/// the proxy mints, handed over to be spent directly. The proxy checks the
/// token's `rpc:` scopes; this did not, so the minimum `atproto` scope bought
/// account-signed authority for any service and method the denylists did not
/// happen to name.
#[tokio::test(flavor = "multi_thread")]
async fn service_auth_refuses_a_token_without_the_matching_rpc_scope() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let key = dpop_key();
    let token = token_with_scope(&app, &key, "atproto").await;

    let (status, body) = get_with_token(
        &app,
        &key,
        &token,
        "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:elsewhere.example&lxm=app.bsky.feed.getPosts",
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "InsufficientScope", "{body}");
}

/// And a token that does grant it still works, so the gate is a scope check
/// rather than a refusal to mint.
#[tokio::test(flavor = "multi_thread")]
async fn service_auth_allows_a_token_that_grants_the_rpc_scope() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let key = dpop_key();
    let token = token_with_scope(
        &app,
        &key,
        "atproto rpc:app.bsky.feed.getPosts?aud=did:web:appview.example",
    )
    .await;

    let (status, body) = get_with_token(
        &app,
        &key,
        &token,
        "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:appview.example&lxm=app.bsky.feed.getPosts",
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["token"].as_str().is_some(), "{body}");
}

/// A token naming no `lxm` is bounded by nothing, and no `rpc:` scope
/// authorises everything. An OAuth caller has to say what it wants.
#[tokio::test(flavor = "multi_thread")]
async fn service_auth_refuses_an_oauth_token_that_names_no_lxm() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let key = dpop_key();
    let token = token_with_scope(&app, &key, "atproto").await;

    let (status, body) = get_with_token(
        &app,
        &key,
        &token,
        "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:elsewhere.example",
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "InsufficientScope", "{body}");
}

/// POST `path` with a DPoP-bound OAuth token and a raw body.
async fn post_raw_with_token(
    app: &axum::Router,
    key: &KeyData,
    token: &str,
    path: &str,
    content_type: &str,
    body: Vec<u8>,
) -> (StatusCode, Value) {
    let url = format!("http://test.example{path}");
    let (dpop, _, _) = request_dpop(key, "POST", &url, token).expect("mint DPoP proof");
    let request = Request::builder()
        .uri(path)
        .method("POST")
        .header("content-type", content_type)
        .header("authorization", format!("DPoP {token}"))
        .header("host", "test.example")
        .header("DPoP", dpop)
        .body(Body::from(body))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// `importRepo` replaces every record in every collection at once. That is
/// account migration, and the specification says `transition:generic` grants
/// writing any record type while excluding "account management actions:
/// ... migrate account". `privileged()` read the legacy scope as privileged,
/// so this endpoint admitted exactly what the specification excludes.
#[tokio::test(flavor = "multi_thread")]
async fn import_repo_refuses_the_legacy_generic_scope() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let key = dpop_key();
    let token = token_with_scope(&app, &key, "atproto transition:generic").await;

    let (status, body) = post_raw_with_token(
        &app,
        &key,
        &token,
        "/xrpc/com.atproto.repo.importRepo",
        "application/vnd.ipld.car",
        b"not-a-car".to_vec(),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "InsufficientScope", "{body}");
}

/// And the granular grant gets past the scope gate -- it fails later, on the
/// body not being a CAR, which is the point: the refusal is about scope and
/// stops being about scope once the scope is held.
#[tokio::test(flavor = "multi_thread")]
async fn import_repo_admits_the_granular_account_repo_scope() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let key = dpop_key();
    let token = token_with_scope(
        &app,
        &key,
        "atproto transition:generic account:repo?action=manage",
    )
    .await;

    let (status, body) = post_raw_with_token(
        &app,
        &key,
        &token,
        "/xrpc/com.atproto.repo.importRepo",
        "application/vnd.ipld.car",
        b"not-a-car".to_vec(),
    )
    .await;

    assert_ne!(
        body["error"], "InsufficientScope",
        "the granular grant should pass the scope gate: {body}"
    );
    assert_ne!(status, StatusCode::FORBIDDEN, "{body}");
}

/// `refreshIdentity` rewrites the handle and emits `#identity`, which is what
/// `identity:handle` gates. The handler took only the DID from
/// authentication, so the scopes were never in reach to be checked.
#[tokio::test(flavor = "multi_thread")]
async fn refresh_identity_refuses_a_token_without_the_identity_scope() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let key = dpop_key();
    let token = token_with_scope(&app, &key, "atproto transition:generic").await;

    let (status, body) = post_raw_with_token(
        &app,
        &key,
        &token,
        "/xrpc/com.atproto.identity.refreshIdentity",
        "application/json",
        serde_json::to_vec(&json!({"did": "did:plc:alice"})).unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "InsufficientScope", "{body}");
}

/// Preferences are account data and any token at all could rewrite them.
#[tokio::test(flavor = "multi_thread")]
async fn put_preferences_refuses_a_bare_atproto_token() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let key = dpop_key();
    let token = token_with_scope(&app, &key, "atproto").await;

    let (status, body) = post_raw_with_token(
        &app,
        &key,
        &token,
        "/xrpc/app.bsky.actor.putPreferences",
        "application/json",
        serde_json::to_vec(&json!({"preferences": []})).unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "InsufficientScope", "{body}");
}

/// The specification names personal preferences among what
/// `transition:generic` grants, so that token must keep working.
#[tokio::test(flavor = "multi_thread")]
async fn put_preferences_admits_the_legacy_generic_scope() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let key = dpop_key();
    let token = token_with_scope(&app, &key, "atproto transition:generic").await;

    let (status, body) = post_raw_with_token(
        &app,
        &key,
        &token,
        "/xrpc/app.bsky.actor.putPreferences",
        "application/json",
        serde_json::to_vec(&json!({"preferences": []})).unwrap(),
    )
    .await;

    assert_ne!(status, StatusCode::FORBIDDEN, "{body}");
}

/// Create a fixture account that actually has an email, so a test asserting
/// the address is withheld is not merely observing that there is none.
async fn create_account_with_email(manager: &AccountManager, did: &str, handle: &str) {
    manager
        .create_account(
            CreateAccountParams::new(did, handle, "pw").with_email(Some("alice@example.com")),
        )
        .await
        .expect("fixture account should be created");
    manager
        .set_primary_password(did, "pw")
        .await
        .expect("fixture account needs a session password");
}

/// `getSession` returned the account's email address to every OAuth token,
/// whatever it had been granted. `transition:email` exists for exactly this
/// disclosure -- its whole described effect is that the address and its
/// confirmation status appear in this response -- which is only a grant if
/// withholding is the default.
#[tokio::test(flavor = "multi_thread")]
async fn get_session_withholds_the_email_from_a_token_without_the_scope() {
    let (app, manager, _tmp) = build_app().await;
    create_account_with_email(&manager, "did:plc:alice", "alice.example").await;
    let key = dpop_key();
    let token = token_with_scope(&app, &key, "atproto transition:generic").await;

    let (status, body) =
        get_with_token(&app, &key, &token, "/xrpc/com.atproto.server.getSession").await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.get("email").is_none(),
        "the address was disclosed to a token that was not granted it: {body}"
    );
    assert!(
        body.get("emailConfirmed").is_none(),
        "confirmation status is part of the same disclosure: {body}"
    );
    // The rest of the response is unaffected -- this is a redaction, not a
    // refusal.
    assert_eq!(body["did"], "did:plc:alice", "{body}");
    assert_eq!(body["handle"], "alice.example", "{body}");
}

/// And `transition:email` still receives it, or the scope would grant nothing.
#[tokio::test(flavor = "multi_thread")]
async fn get_session_discloses_the_email_to_the_transition_email_scope() {
    let (app, manager, _tmp) = build_app().await;
    create_account_with_email(&manager, "did:plc:alice", "alice.example").await;
    let key = dpop_key();
    let token = token_with_scope(&app, &key, "atproto transition:generic transition:email").await;

    let (status, body) =
        get_with_token(&app, &key, &token, "/xrpc/com.atproto.server.getSession").await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["email"], "alice@example.com", "{body}");
    assert!(body.get("emailConfirmed").is_some(), "{body}");
}

/// The granular spelling works too.
#[tokio::test(flavor = "multi_thread")]
async fn get_session_discloses_the_email_to_the_granular_read_scope() {
    let (app, manager, _tmp) = build_app().await;
    create_account_with_email(&manager, "did:plc:alice", "alice.example").await;
    let key = dpop_key();
    let token = token_with_scope(&app, &key, "atproto account:email?action=read").await;

    let (status, body) =
        get_with_token(&app, &key, &token, "/xrpc/com.atproto.server.getSession").await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["email"], "alice@example.com", "{body}");
}
