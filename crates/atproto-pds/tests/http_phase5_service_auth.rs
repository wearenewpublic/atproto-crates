//! Phase 5 HTTP integration tests — `com.atproto.server.getServiceAuth`.
//!
//! Mints a short-lived service-auth JWT signed by the calling account's
//! atproto signing key. The receiving service verifies via the issuer's DID
//! document; here we just check structural shape and verify the signature
//! against the same account's key in the test fixture.

use atproto_identity::key::{KeyData, validate as identity_validate};
use atproto_identity::key::{KeyType, to_public};
use atproto_pds::account::session::SessionAuthority;
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams};
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

async fn create_account_and_token(
    app: &axum::Router,
    manager: &AccountManager,
    did: &str,
    handle: &str,
) -> String {
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

async fn account_signing_pubkey(manager: &AccountManager, did: &str) -> KeyData {
    let key_ref: (String,) = sqlx::query_as("SELECT signing_key_ref FROM account WHERE did = ?")
        .bind(did)
        .fetch_one(manager.pool())
        .await
        .unwrap();
    let private = manager.key_store().get(&key_ref.0).await.unwrap();
    to_public(&private).unwrap()
}

/// Epoch seconds, `secs` from now. `exp` is an absolute instant, not a
/// lifetime, so every test that names one has to compute it.
fn epoch_in(secs: i64) -> u64 {
    (chrono::Utc::now().timestamp() + secs).max(0) as u64
}

/// Decode a compact JWT's header and payload without verifying the signature.
fn jwt_parts(jwt: &str) -> (Value, Value) {
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have header.payload.sig");
    let decode = |p: &str| -> Value {
        serde_json::from_slice(
            &general_purpose::URL_SAFE_NO_PAD
                .decode(p.as_bytes())
                .unwrap(),
        )
        .unwrap()
    };
    (decode(parts[0]), decode(parts[1]))
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
    let token = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;

    let (status, body) = get_token(
        app,
        &format!("/xrpc/com.atproto.server.getServiceAuth?aud=did:web:appview.example&exp={}&lxm=app.bsky.feed.getPosts", epoch_in(120)),
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
    assert!(
        (118..=122).contains(&(exp - iat)),
        "requested expiry should be honoured as an absolute instant, got {}s",
        exp - iat
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn service_auth_requires_session() {
    let (app, _manager, _tmp) = build_app().await;
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
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;
    let (status, _) = get_token(
        app,
        "/xrpc/com.atproto.server.getServiceAuth?aud=https://example.com",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn service_auth_rejects_expiry_beyond_one_hour() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;
    let (status, body) = get_token(
        app,
        &format!(
            "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:x.example&lxm=app.bsky.feed.getPosts&exp={}",
            epoch_in(7200)
        ),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "BadExpiration");
}

#[tokio::test(flavor = "multi_thread")]
async fn service_auth_omits_lxm_when_not_provided() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;
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

// ---------------------------------------------------------------------------
// Service-auth is a credential handed to another service to act for this
// account. What it authorises, for how long, and whether it is honoured at all
// are the whole security surface — and until these gates existed the `typ`
// header was the only thing keeping the tokens from working at real peers.
// ---------------------------------------------------------------------------

/// The JWS header must be typed `JWT`.
///
/// `@atproto/xrpc-server` throws `BadJwtType` for anything else, so a token
/// typed `at+jwt` is refused by the Bluesky AppView, by Ozone and by every
/// service built on that library before the signature is even checked.
#[tokio::test(flavor = "multi_thread")]
async fn service_auth_header_is_typed_jwt() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;
    let (status, body) = get_token(
        app,
        "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:x.example&lxm=app.bsky.feed.getPosts",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let (header, _) = jwt_parts(body["token"].as_str().unwrap());
    assert_eq!(header["typ"], "JWT", "header: {header}");
}

/// Omitting `exp` yields the one-minute default.
#[tokio::test(flavor = "multi_thread")]
async fn service_auth_defaults_to_sixty_seconds() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;
    let (status, body) = get_token(
        app,
        "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:x.example&lxm=app.bsky.feed.getPosts",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, payload) = jwt_parts(body["token"].as_str().unwrap());
    assert_eq!(
        payload["exp"].as_u64().unwrap() - payload["iat"].as_u64().unwrap(),
        60
    );
}

/// An `exp` already in the past is refused rather than silently honoured.
#[tokio::test(flavor = "multi_thread")]
async fn service_auth_rejects_expiry_in_the_past() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;
    let (status, body) = get_token(
        app,
        &format!(
            "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:x.example&lxm=app.bsky.feed.getPosts&exp={}",
            epoch_in(-60)
        ),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "BadExpiration");
}

/// A token with no `lxm` satisfies every method the receiver scopes by one, so
/// it is a general-purpose credential and is capped at a minute.
#[tokio::test(flavor = "multi_thread")]
async fn service_auth_caps_method_less_tokens_at_one_minute() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;
    let (status, body) = get_token(
        app,
        &format!(
            "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:x.example&exp={}",
            epoch_in(600)
        ),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "BadExpiration");
}

/// Account-management methods must never be reachable through service auth.
#[tokio::test(flavor = "multi_thread")]
async fn service_auth_refuses_protected_methods() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;
    for lxm in [
        "com.atproto.identity.updateHandle",
        "com.atproto.server.createAppPassword",
        "com.atproto.server.getSession",
        "com.atproto.identity.signPlcOperation",
    ] {
        let (status, body) = get_token(
            app.clone(),
            &format!("/xrpc/com.atproto.server.getServiceAuth?aud=did:web:x.example&lxm={lxm}"),
            Some(&token),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{lxm} must be refused: {body}"
        );
    }
}

/// A taken-down account keeps only its ability to migrate away.
#[tokio::test(flavor = "multi_thread")]
async fn service_auth_restricts_takendown_accounts_to_migration() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;
    manager
        .set_state(
            "did:plc:alice",
            atproto_pds::account::AccountState::Takendown,
        )
        .await
        .expect("takedown should apply");

    let (status, body) = get_token(
        app.clone(),
        "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:x.example&lxm=app.bsky.feed.getPosts",
        Some(&token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a taken-down account should not mint general service auth: {body}"
    );

    // Migration remains possible, so a takedown cannot strand an account.
    let (status, body) = get_token(
        app,
        "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:x.example&lxm=com.atproto.server.createAccount",
        Some(&token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "migration credential must remain available: {body}"
    );
}

/// `createAccount` is the migration credential: a token bearing it lets the
/// holder create an account elsewhere in the issuer's name. A non-privileged
/// session — an app password without the privileged flag — must not mint one.
#[tokio::test(flavor = "multi_thread")]
async fn service_auth_refuses_privileged_methods_to_unprivileged_sessions() {
    let (app, manager, _tmp) = build_app().await;
    create_account_and_token(&app, &manager, "did:plc:alice", "alice.example").await;

    let unprivileged = atproto_pds::account::session::issue_pair(
        "did:web:test.example",
        "did:plc:alice",
        "app-password-1",
        SessionAuthority::AppPassword,
        b"test-secret-do-not-use-in-prod-32!",
        600,
        3600,
    )
    .expect("issue an unprivileged session")
    .access_jwt;

    let (status, body) = get_token(
        app.clone(),
        "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:x.example&lxm=com.atproto.server.createAccount",
        Some(&unprivileged),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unprivileged session must not mint the migration credential: {body}"
    );

    // The same session may still mint an ordinary read-scoped token.
    let (status, body) = get_token(
        app,
        "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:x.example&lxm=app.bsky.feed.getPosts",
        Some(&unprivileged),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "ordinary methods stay available: {body}"
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
