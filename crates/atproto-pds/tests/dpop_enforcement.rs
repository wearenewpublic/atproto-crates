//! acceptance — DPoP-bound OAuth tokens require a fresh
//! DPoP proof on every request, with replay protection.
//!
//! Strategy:
//! 1. Mint an OAuth access token (HS256, `typ=at-oauth-access`) with
//!    `cnf.jkt` set to a thumbprint we control.
//! 2. Hit a write endpoint (`com.atproto.repo.createRecord`) with three
//!    scenarios:
//!    - **No DPoP header**: expect 401 `InvalidDpopProof`.
//!    - **Fresh DPoP proof**: expect 200.
//!    - **Replay of the same proof**: expect 401 `InvalidDpopProof: replay`.

use atproto_identity::key::{KeyType, generate_key};
use atproto_oauth::dpop::{extract_jwk_thumbprint, request_dpop};
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sha2::Sha256;
use sha2::digest::KeyInit;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

type HmacSha256 = Hmac<Sha256>;

const JWT_SECRET: &[u8] = b"test-secret-do-not-use-in-prod-32!";

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
        JWT_SECRET.to_vec(),
        false,
    )
    .with_writer(writer);
    (build_router(state), manager, tmp)
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

/// Mint an OAuth access JWT with `typ=at-oauth-access` and the supplied
/// `cnf.jkt`. HS256 over the same shared secret the PDS uses.
fn mint_oauth_access(sub: &str, jkt: &str) -> String {
    let header = json!({"alg": "HS256", "typ": "at-oauth-access"});
    let now = chrono::Utc::now().timestamp() as u64;
    let payload = json!({
        "sub": sub,
        "iss": "did:web:test.example",
        "aud": "did:web:test.example",
        "client_id": "https://app.example/client-metadata.json",
        "scope": "atproto transition:generic",
        "cnf": {"jkt": jkt},
        "iat": now,
        "exp": now + 3600,
        "jti": "test-oauth-jti",
    });
    let h = B64URL.encode(serde_json::to_vec(&header).unwrap());
    let p = B64URL.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{h}.{p}");
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(JWT_SECRET).unwrap();
    mac.update(signing_input.as_bytes());
    format!(
        "{}.{}",
        signing_input,
        B64URL.encode(mac.finalize().into_bytes())
    )
}

async fn write_with(app: &axum::Router, bearer: &str, dpop: Option<&str>) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .uri("/xrpc/com.atproto.repo.createRecord")
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {bearer}"))
        .header("host", "test.example");
    if let Some(d) = dpop {
        req = req.header("DPoP", d);
    }
    let request = req
        .body(Body::from(
            serde_json::to_vec(&json!({
                "repo": "did:plc:alice",
                "collection": "app.bsky.feed.post",
                "record": {"text": "hi"}
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

#[tokio::test(flavor = "multi_thread")]
async fn dpop_bound_token_rejected_without_proof() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    // Generate a key just to derive a stable thumbprint — we don't use it
    // for signing in this scenario since we never include a proof.
    let key = generate_key(KeyType::P256Private).unwrap();
    let (proof, _, _) = request_dpop(
        &key,
        "POST",
        "http://test.example/xrpc/com.atproto.repo.createRecord",
        "unused",
    )
    .unwrap();
    let jkt = extract_jwk_thumbprint(&proof).unwrap();

    let token = mint_oauth_access("did:plc:alice", &jkt);
    let (status, body) = write_with(&app, &token, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["error"], "InvalidDpopProof");
}

#[tokio::test(flavor = "multi_thread")]
async fn dpop_bound_token_accepted_with_fresh_proof() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let key = generate_key(KeyType::P256Private).unwrap();
    let token = {
        // Mint a throwaway proof just to extract the JWK thumbprint we'll
        // bind into the access token.
        let (p, _, _) = request_dpop(
            &key,
            "POST",
            "http://test.example/xrpc/com.atproto.repo.createRecord",
            "unused",
        )
        .unwrap();
        let jkt = extract_jwk_thumbprint(&p).unwrap();
        mint_oauth_access("did:plc:alice", &jkt)
    };

    // Now mint a real proof bound to this access token.
    let (proof, _, _) = request_dpop(
        &key,
        "POST",
        "http://test.example/xrpc/com.atproto.repo.createRecord",
        &token,
    )
    .unwrap();

    let (status, body) = write_with(&app, &token, Some(&proof)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn dpop_replay_rejected() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let key = generate_key(KeyType::P256Private).unwrap();
    let token = {
        let (p, _, _) = request_dpop(
            &key,
            "POST",
            "http://test.example/xrpc/com.atproto.repo.createRecord",
            "unused",
        )
        .unwrap();
        let jkt = extract_jwk_thumbprint(&p).unwrap();
        mint_oauth_access("did:plc:alice", &jkt)
    };

    let (proof, _, _) = request_dpop(
        &key,
        "POST",
        "http://test.example/xrpc/com.atproto.repo.createRecord",
        &token,
    )
    .unwrap();

    // First use of the proof: succeeds (or fails for non-DPoP reasons —
    // we accept either, the test is about the SECOND call).
    let (status, _) = write_with(&app, &token, Some(&proof)).await;
    assert!(
        status.is_success() || status.is_client_error(),
        "first call should not 5xx; got {status}"
    );

    // Replay: the JTI is now in the guard, so the proof is rejected.
    let (status, body) = write_with(&app, &token, Some(&proof)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["error"], "InvalidDpopProof");
    let msg = body["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("replay"),
        "expected replay message, got: {msg}"
    );
}
