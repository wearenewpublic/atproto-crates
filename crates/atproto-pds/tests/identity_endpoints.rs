//! acceptance tests — `com.atproto.identity.*`.
//!
//! Coverage:
//! - `resolveHandle` for a local account.
//! - `resolveHandle` for an unknown handle → 404.
//! - `requestPlcOperationSignature` mails a one-time code and returns
//!   nothing, per its lexicon.
//! - `updateHandle` validation: syntax, disallowed TLDs, uniqueness,
//!   service-domain shape and the ownership proof for external domains.
//! - `signPlcOperation`'s emailed-code gate.
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

// ---------------------------------------------------------------------------
//  F-IDENT-02 — updateHandle validates before it touches PLC.
//
//  The harness has no PLC directory, so an unvalidated handle reaches the
//  `plc_service` lookup and returns 503. Every test below asserts a 400
//  instead: the handle was refused on its own terms, before any network
//  call and before any PLC operation could be signed.
// ---------------------------------------------------------------------------

/// Build an app whose operator has pinned `example.test` as a service domain.
async fn build_app_with_service_domain() -> (axum::Router, Arc<AccountManager>, TempDir) {
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
    .with_writer(writer)
    .with_service_handle_domains(vec!["example.test".to_string()]);
    (build_router(state), manager, tmp)
}

async fn update_handle(app: &axum::Router, token: &str, handle: &str) -> (StatusCode, Value) {
    post_json(
        app.clone(),
        "/xrpc/com.atproto.identity.updateHandle",
        json!({ "handle": handle }),
        Some(token),
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn update_handle_refuses_a_syntactically_invalid_handle() {
    let (app, manager, _tmp) = build_app_with_service_domain().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example.test").await;

    for bad in [
        "not a handle",
        "localhost",
        "192.168.1.1",
        "double..dot.test",
        "-leading.example.test",
    ] {
        let (status, body) = update_handle(&app, &token, bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad} — body: {body}");
        assert_eq!(body["error"], "InvalidHandle", "{bad}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn update_handle_refuses_a_disallowed_tld() {
    let (app, manager, _tmp) = build_app_with_service_domain().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example.test").await;

    // `.example` reads as an ordinary handle and is on the upstream
    // disallowed list. Getting this wrong is how a PDS ends up hosting
    // handles that can never resolve for anyone else.
    for bad in ["bob.example", "bob.invalid", "bob.onion", "bob.local"] {
        let (status, body) = update_handle(&app, &token, bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad} — body: {body}");
        assert_eq!(body["error"], "InvalidHandle", "{bad}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn update_handle_refuses_a_handle_another_account_holds() {
    let (app, manager, _tmp) = build_app_with_service_domain().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example.test").await;
    let _ = create_account(&app, &manager, "did:plc:bob", "bob.example.test").await;

    let (status, body) = update_handle(&app, &token, "bob.example.test").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "HandleNotAvailable");
}

#[tokio::test(flavor = "multi_thread")]
async fn update_handle_refuses_a_reserved_name_and_a_bad_shape() {
    let (app, manager, _tmp) = build_app_with_service_domain().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example.test").await;

    // Reserved: handing out `admin.example.test` lets the holder impersonate
    // the operator.
    let (status, body) = update_handle(&app, &token, "admin.example.test").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "HandleNotAvailable");

    // Too short, too long, and nested — all shape constraints on a handle
    // issued under a domain this server operates.
    for bad in [
        "ab.example.test",
        "abcdefghijklmnopqrs.example.test",
        "a.b.example.test",
    ] {
        let (status, body) = update_handle(&app, &token, bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad} — body: {body}");
        assert_eq!(body["error"], "InvalidHandle", "{bad}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn update_handle_refuses_an_unproven_external_domain() {
    let (app, manager, _tmp) = build_app_with_service_domain().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example.test").await;

    // Outside the service domain, so the caller must prove they control it.
    // `.test` is reserved by RFC 6761 and never resolves; whether the lookup
    // NXDOMAINs or the sandbox has no network at all, the answer is the
    // same — no proof, no handle.
    let (status, body) = update_handle(&app, &token, "definitely-not-mine.someone-else.test").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "UnsupportedDomain");
}

#[tokio::test(flavor = "multi_thread")]
async fn update_handle_still_requires_auth() {
    let (app, manager, _tmp) = build_app_with_service_domain().await;
    let _ = create_account(&app, &manager, "did:plc:alice", "alice.example.test").await;

    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.identity.updateHandle",
        json!({ "handle": "newname.example.test" }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
//  F-IDENT-11 + F-IDENT-03 — the emailed code, and the gate that consumes it.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn request_plc_operation_signature_does_not_hand_back_the_second_factor() {
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
    // The lexicon declares no output. Returning the code in the response
    // handed the second factor to whoever already held the first.
    assert!(
        body.get("token").is_none(),
        "the code must not come back in the response: {body}"
    );

    // It was issued, though — as a row bound to this account and this flow.
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT did, purpose FROM email_token WHERE purpose = 'plc_operation'")
            .fetch_optional(manager.account_pool().as_sqlite())
            .await
            .unwrap();
    let (did, purpose) = row.expect("a plc_operation token should have been issued");
    assert_eq!(did, "did:plc:alice");
    assert_eq!(purpose, "plc_operation");
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_plc_operation_refuses_without_a_code() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    // An access token alone must not be enough to have this server sign a
    // key rotation with the account's rotation key.
    let (status, body) = post_json(
        app,
        "/xrpc/com.atproto.identity.signPlcOperation",
        json!({ "alsoKnownAs": ["at://newname.example.test"] }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_plc_operation_refuses_a_code_belonging_to_another_account() {
    let (app, manager, _tmp) = build_app().await;
    let alice = create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let bob = create_account(&app, &manager, "did:plc:bob", "bob.example").await;

    // Bob requests a code...
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.identity.requestPlcOperationSignature",
        json!({}),
        Some(&bob),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let bobs_code: (String,) =
        sqlx::query_as("SELECT token FROM email_token WHERE did = 'did:plc:bob'")
            .fetch_one(manager.account_pool().as_sqlite())
            .await
            .unwrap();

    // ...and Alice tries to spend it.
    let (status, body) = post_json(
        app,
        "/xrpc/com.atproto.identity.signPlcOperation",
        json!({ "token": bobs_code.0, "alsoKnownAs": ["at://taken.example.test"] }),
        Some(&alice),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "body: {body}");
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_plc_operation_refuses_a_code_from_a_different_flow() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    // A password-reset code is not a PLC-signing code. Without the purpose
    // check, any token the account holds would open this door.
    sqlx::query("INSERT INTO email_token (token, did, purpose, expires_at) VALUES (?, ?, ?, ?)")
        .bind("wrong-flow")
        .bind("did:plc:alice")
        .bind("reset_password")
        .bind((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339())
        .execute(manager.account_pool().as_sqlite())
        .await
        .unwrap();

    let (status, body) = post_json(
        app,
        "/xrpc/com.atproto.identity.signPlcOperation",
        json!({ "token": "wrong-flow", "alsoKnownAs": ["at://taken.example.test"] }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_plc_operation_refuses_an_expired_code() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    sqlx::query("INSERT INTO email_token (token, did, purpose, expires_at) VALUES (?, ?, ?, ?)")
        .bind("stale")
        .bind("did:plc:alice")
        .bind("plc_operation")
        .bind((chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339())
        .execute(manager.account_pool().as_sqlite())
        .await
        .unwrap();

    let (status, body) = post_json(
        app,
        "/xrpc/com.atproto.identity.signPlcOperation",
        json!({ "token": "stale", "alsoKnownAs": ["at://taken.example.test"] }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
}

// ---------------------------------------------------------------------------
//  F-IDENT-05 — submitPlcOperation validates before it forwards.
//
//  PLC is append-only. An operation that drops this server's rotation key,
//  or points the account at another host, cannot be undone by this server
//  afterwards — so every check runs before submission, and each of these
//  tests reaches its assertion without a single network call.
// ---------------------------------------------------------------------------

/// Build an app with a PLC service configured and an account that has a
/// PDS-managed rotation key.
///
/// The directory hostname is deliberately unroutable: every assertion below
/// must be reached before anything is submitted, so a test that starts
/// making network calls has stopped testing what it claims to.
async fn build_app_with_plc() -> (
    axum::Router,
    Arc<AccountManager>,
    String,
    String,
    String,
    TempDir,
) {
    use atproto_identity::key::{generate_key, to_public};
    use atproto_pds::plc::{PlcConfig, PlcService};

    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().to_path_buf();
    let accounts = AccountDirectory::open(&dir.join("accounts.sqlite"))
        .await
        .unwrap();
    let key_store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());

    let rotation_priv = generate_key(KeyType::P256Private).unwrap();
    let rotation_did = to_public(&rotation_priv).unwrap().to_string();
    let rotation_ref = key_store.put(&rotation_priv).await.unwrap();

    let manager = Arc::new(AccountManager::new(
        accounts.pool().clone(),
        dir.clone(),
        key_store.clone(),
        KeyType::K256Private,
    ));
    manager
        .create_account(
            CreateAccountParams::new("did:plc:alice", "alice.example.test", "pw")
                .with_keys(Some(&rotation_ref), None)
                .with_pds_managed_rotation(true),
        )
        .await
        .unwrap();
    manager
        .set_primary_password("did:plc:alice", "pw")
        .await
        .unwrap();

    let (_, signing_ref, _) = manager
        .lookup_did_credentials("did:plc:alice")
        .await
        .unwrap()
        .unwrap();
    let signing_did = to_public(&key_store.get(&signing_ref).await.unwrap())
        .unwrap()
        .to_string();

    let writer = Arc::new(RepoWriter::new(manager.clone(), dir.clone()));
    let reader = Arc::new(RepoReader::new(accounts, dir.clone()));
    let plc = Arc::new(PlcService::new(
        PlcConfig::new(
            "plc.unroutable.test".to_string(),
            "did:web:pds.example.test".to_string(),
            "https://pds.example.test".to_string(),
        ),
        key_store,
    ));
    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:pds.example.test".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer)
    .with_plc_service(plc);

    let app = build_router(state);
    let token = session_token(&app, "alice.example.test").await;
    (app, manager, token, rotation_did, signing_did, tmp)
}

fn plc_op(rotation_keys: Value, signing: &str, aka: &str, endpoint: &str) -> Value {
    json!({
        "type": "plc_operation",
        "rotationKeys": rotation_keys,
        "verificationMethods": { "atproto": signing },
        "alsoKnownAs": [aka],
        "services": {
            "atproto_pds": {
                "type": "AtprotoPersonalDataServer",
                "endpoint": endpoint,
            }
        },
        "prev": "bafyreiprev",
        "sig": "not-checked-here",
    })
}

async fn submit_op(app: &axum::Router, token: &str, op: Value) -> (StatusCode, Value) {
    post_json(
        app.clone(),
        "/xrpc/com.atproto.identity.submitPlcOperation",
        json!({ "operation": op }),
        Some(token),
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn submit_plc_operation_refuses_an_operation_dropping_the_servers_rotation_key() {
    let (app, _m, token, _rotation, _signing, _tmp) = build_app_with_plc().await;
    let op = plc_op(
        json!(["did:key:zSomeoneElsesRotationKey"]),
        "did:key:zAnything",
        "at://alice.example.test",
        "https://pds.example.test",
    );
    let (status, body) = submit_op(&app, &token, op).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test(flavor = "multi_thread")]
async fn submit_plc_operation_refuses_an_operation_pointing_at_another_host() {
    let (app, _m, token, rotation, _signing, _tmp) = build_app_with_plc().await;
    let op = plc_op(
        json!([rotation]),
        "did:key:zAnything",
        "at://alice.example.test",
        "https://someone-else.example.test",
    );
    let (status, body) = submit_op(&app, &token, op).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test(flavor = "multi_thread")]
async fn submit_plc_operation_refuses_a_mismatched_signing_key_or_handle() {
    let (app, _m, token, rotation, _signing, _tmp) = build_app_with_plc().await;

    // Wrong signing key: every commit this server has already signed would
    // stop verifying against the document.
    let op = plc_op(
        json!([rotation]),
        "did:key:zNotThisAccountsSigningKey",
        "at://alice.example.test",
        "https://pds.example.test",
    );
    let (status, body) = submit_op(&app, &token, op).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "InvalidRequest");

    // Wrong handle: the document would claim a handle this server does not
    // serve, so bidirectional resolution breaks.
    let op = plc_op(
        json!([rotation]),
        "did:key:zNotThisAccountsSigningKey",
        "at://someone.else.test",
        "https://pds.example.test",
    );
    let (status, body) = submit_op(&app, &token, op).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test(flavor = "multi_thread")]
async fn submit_plc_operation_refuses_a_tombstone() {
    let (app, _m, token, _rotation, _signing, _tmp) = build_app_with_plc().await;
    let op = json!({
        "type": "plc_tombstone",
        "prev": "bafyreiprev",
        "sig": "not-checked-here",
    });
    let (status, body) = submit_op(&app, &token, op).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "InvalidRequest");
}

#[tokio::test(flavor = "multi_thread")]
async fn submit_plc_operation_lets_a_conformant_operation_through_to_plc() {
    // Not redundant with the four refusal tests: a check that rejected
    // everything would pass all of them. This one satisfies every
    // constraint and asserts the request got *past* validation — it then
    // fails at the unroutable directory, which is the proof it was
    // forwarded rather than refused.
    let (app, _m, token, rotation, signing, _tmp) = build_app_with_plc().await;
    let op = plc_op(
        json!([rotation]),
        &signing,
        "at://alice.example.test",
        "https://pds.example.test",
    );
    let (status, body) = submit_op(&app, &token, op).await;
    assert_ne!(
        status,
        StatusCode::BAD_REQUEST,
        "a conformant operation must not be refused: {body}"
    );
    assert!(
        status.is_server_error(),
        "expected the unroutable directory to fail the submission, got {status}: {body}"
    );
}

/// A handle that has stopped resolving is served as `handle.invalid`.
///
/// The account keeps its handle -- the record is untouched -- but callers are
/// told a name they can act on rather than one the rest of the network will
/// refuse to honour. Before this, a handle whose DNS record expired was served
/// as live indefinitely, and `describeRepo` asserted `handleIsCorrect: true`
/// on the strength of a proof taken when the handle was first set.
#[tokio::test(flavor = "multi_thread")]
async fn an_invalidated_handle_is_served_as_handle_invalid() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    atproto_pds::account::handle_validation::record(
        &manager.account_pool(),
        "did:plc:alice",
        false,
    )
    .await
    .expect("record the failed check");

    let (status, body) = get_json(
        app.clone(),
        "/xrpc/com.atproto.server.getSession",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["handle"], "handle.invalid", "{body}");
    assert_eq!(
        body["did"], "did:plc:alice",
        "the DID is unaffected: {body}"
    );

    let (status, body) = get_json(
        app,
        "/xrpc/com.atproto.repo.describeRepo?repo=did:plc:alice",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["handle"], "handle.invalid", "{body}");
    assert_eq!(
        body["handleIsCorrect"], false,
        "the lexicon has a field for exactly this: {body}"
    );
    // The DID document is a statement of what this DID claims to be known as,
    // and a lapsed DNS record does not retract the claim. Putting
    // `handle.invalid` here would publish a DID document asserting an identity
    // that cannot exist.
    assert_eq!(
        body["didDoc"]["alsoKnownAs"][0], "at://alice.example",
        "the document keeps the account's own handle: {body}"
    );
}

/// An account nobody has checked keeps its handle.
///
/// This is the failure mode that would matter most: every account starts
/// unchecked, so treating "no record" as "invalid" would serve
/// `handle.invalid` for the whole server the moment this shipped.
#[tokio::test(flavor = "multi_thread")]
async fn an_unchecked_handle_is_served_as_itself() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let (status, body) = get_json(
        app.clone(),
        "/xrpc/com.atproto.server.getSession",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["handle"], "alice.example", "{body}");

    let (status, body) = get_json(
        app,
        "/xrpc/com.atproto.repo.describeRepo?repo=did:plc:alice",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["handle"], "alice.example", "{body}");
    assert_eq!(body["handleIsCorrect"], true, "{body}");
}

/// A handle that resolves again is served again.
///
/// The recovery path is the one an account holder actually walks: the DNS
/// record comes back, the next check passes, and nothing on this server should
/// need an operator to undo.
#[tokio::test(flavor = "multi_thread")]
async fn a_recovered_handle_is_served_again() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    atproto_pds::account::handle_validation::record(
        &manager.account_pool(),
        "did:plc:alice",
        false,
    )
    .await
    .expect("record the failed check");
    atproto_pds::account::handle_validation::record(&manager.account_pool(), "did:plc:alice", true)
        .await
        .expect("record the passing check");

    let (status, body) = get_json(app, "/xrpc/com.atproto.server.getSession", Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["handle"], "alice.example", "{body}");
}

/// `refreshIdentity` is what notices.
///
/// It read the DID document's `alsoKnownAs` and stopped there, which proves
/// nothing on its own -- a handle whose DNS record expired still appears
/// there, unchanged, forever. The half that can go wrong is the domain
/// resolving back to the DID, and nothing checked it after the handle was
/// first set.
///
/// `alice.example` is a reserved domain with no `.well-known` and no DNS
/// record, so the check fails the way a real broken handle does.
#[tokio::test(flavor = "multi_thread")]
async fn refresh_identity_marks_a_handle_that_no_longer_resolves() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:web:alice.example", "alice.example").await;

    let (status, body) = get_json(
        app.clone(),
        "/xrpc/com.atproto.repo.describeRepo?repo=did:web:alice.example",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["handleIsCorrect"], true, "unchecked, so far: {body}");

    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.identity.refreshIdentity",
        json!({"did": "did:web:alice.example"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let (status, body) = get_json(
        app,
        "/xrpc/com.atproto.repo.describeRepo?repo=did:web:alice.example",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["handleIsCorrect"], false,
        "the refresh checked the handle and it did not resolve: {body}"
    );
    assert_eq!(body["handle"], "handle.invalid", "{body}");
}

/// A handle this server issues is not checked against the open internet.
///
/// A service handle resolves because this server answers for it, so checking
/// one asks this process whether it is running -- and the answer arrives over
/// a network round-trip that can fail for reasons that have nothing to do with
/// the handle. Getting this wrong is not a small error: every account on a
/// server that issues its own handles would go `handle.invalid` together, on
/// one bad DNS moment.
#[tokio::test(flavor = "multi_thread")]
async fn a_service_handle_is_not_checked() {
    let (app, manager, _tmp) = build_app_with_service_domain().await;
    let token = create_account(
        &app,
        &manager,
        "did:web:alice.example.test",
        "alice.example.test",
    )
    .await;

    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.identity.refreshIdentity",
        json!({"did": "did:web:alice.example.test"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let (status, body) = get_json(
        app,
        "/xrpc/com.atproto.repo.describeRepo?repo=did:web:alice.example.test",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["handle"], "alice.example.test", "{body}");
    assert_eq!(
        body["handleIsCorrect"], true,
        "a handle this server issues must not be invalidated by a lookup: {body}"
    );
}
