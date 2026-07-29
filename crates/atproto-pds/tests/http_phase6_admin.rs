//! Phase 6 admin-endpoint integration tests.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64STD;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

const ADMIN_PASSWORD: &str = "admin-test-secret";

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
    .with_writer(writer)
    .with_admin_password(ADMIN_PASSWORD.to_string());
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

fn admin_basic() -> String {
    format!("Basic {}", B64STD.encode(format!("admin:{ADMIN_PASSWORD}")))
}

async fn get_admin(app: axum::Router, path: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .uri(path)
        .header("authorization", admin_basic())
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

async fn post_admin(app: axum::Router, path: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .uri(path)
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", admin_basic())
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_get_account_info_round_trip() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let (status, body) = get_admin(
        app,
        "/xrpc/com.atproto.admin.getAccountInfo?did=did:plc:alice",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["did"], "did:plc:alice");
    assert!(body["indexedAt"].is_string(), "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_endpoints_require_basic_auth() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    // No auth header.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.admin.getAccountInfo?did=did:plc:alice")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Wrong password.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.admin.getAccountInfo?did=did:plc:alice")
                .header(
                    "authorization",
                    format!("Basic {}", B64STD.encode("admin:wrong")),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_takedown_then_lift() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    // Takedown.
    let (status, body) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateSubjectStatus",
        json!({
            "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:alice"},
            "takedown": {"applied": true},
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let (_, body) = get_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.getSubjectStatus?did=did:plc:alice",
    )
    .await;
    assert_eq!(body["takedown"]["applied"], true);
    assert_eq!(body["subject"]["$type"], "com.atproto.admin.defs#repoRef");

    // Lift.
    let (status, _) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateSubjectStatus",
        json!({
            "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:alice"},
            "takedown": {"applied": false},
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = get_admin(
        app,
        "/xrpc/com.atproto.admin.getSubjectStatus?did=did:plc:alice",
    )
    .await;
    assert_eq!(body["takedown"]["applied"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_takedown_blocks_public_reads() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateSubjectStatus",
        json!({
            "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:alice"},
            "takedown": {"applied": true},
        }),
    )
    .await;

    // describeRepo doesn't enforce takedown but getRecord does.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.repo.getRecord?repo=did:plc:alice&collection=x.y.z&rkey=k")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // A takedown now reports as the lexicon's named error rather than a generic
    // 403, and does so identically on all nine public read paths.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_delete_account_terminal() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let (status, _) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.deleteAccount",
        json!({"did": "did:plc:alice"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Subsequent state changes from Deleted fail per the lifecycle rules.
    let (status, _) = post_admin(
        app,
        "/xrpc/com.atproto.admin.updateSubjectStatus",
        json!({
            "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:alice"},
            "takedown": {"applied": false},
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_search_accounts_substring() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    create_account(&app, &manager, "did:plc:bob", "bob.example").await;
    create_account(&app, &manager, "did:plc:carol", "carol.example").await;

    let (status, body) = get_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.searchAccounts?email=ali",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let accounts = body["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0]["did"], "did:plc:alice");

    // Empty match.
    let (_, body) = get_admin(app, "/xrpc/com.atproto.admin.searchAccounts?email=zzzz").await;
    assert_eq!(body["accounts"].as_array().unwrap().len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_get_invite_codes_listing() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    // Issue an invite via the user-facing endpoint (alice as issuer).
    let session_req = Request::builder()
        .uri("/xrpc/com.atproto.server.createSession")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"identifier": "alice.example", "password": "pw"})).unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(session_req).await.unwrap();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let token = body["accessJwt"].as_str().unwrap().to_string();

    let invite_req = Request::builder()
        .uri("/xrpc/com.atproto.server.createInviteCode")
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&json!({"useCount": 5})).unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(invite_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (status, body) = get_admin(app, "/xrpc/com.atproto.admin.getInviteCodes").await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let codes = body["codes"].as_array().unwrap();
    assert!(!codes.is_empty());
    assert!(codes[0]["code"].as_str().is_some());
    assert_eq!(codes[0]["availableUses"], 5);
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_search_accounts_requires_basic_auth() {
    let (app, _manager, _tmp) = build_app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.admin.searchAccounts?email=any")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
//  §4.1 — getAccountInfos (batch lookup).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn admin_get_account_infos_batch() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    create_account(&app, &manager, "did:plc:bob", "bob.example").await;

    let (status, body) = get_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.getAccountInfos?dids=did:plc:alice,did:plc:bob,did:plc:nope",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let infos = body["infos"].as_array().unwrap();
    // The unknown DID is silently dropped per spec; alice + bob remain.
    assert_eq!(infos.len(), 2);
    let dids: Vec<&str> = infos.iter().map(|x| x["did"].as_str().unwrap()).collect();
    assert!(dids.contains(&"did:plc:alice"));
    assert!(dids.contains(&"did:plc:bob"));
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_get_account_infos_rejects_empty_list() {
    let (app, _manager, _tmp) = build_app().await;
    let (status, _) = get_admin(app, "/xrpc/com.atproto.admin.getAccountInfos?dids=").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
//  §4.2 — sendEmail.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn admin_send_email_to_account_with_email() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    // The default createAccount in this test harness doesn't set an email
    // address, so seed one directly via updateAccountEmail (§4.3).
    let (status, _) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateAccountEmail",
        json!({"account": "did:plc:alice", "email": "alice@example.com"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = post_admin(
        app,
        "/xrpc/com.atproto.admin.sendEmail",
        json!({
            "recipientDid": "did:plc:alice",
            "senderDid": "did:web:test.example",
            "subject": "test",
            "content": "hello",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    // Disabled-stub email backend always returns sent=true.
    assert_eq!(body["sent"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_send_email_rejects_account_without_email() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let (status, _) = post_admin(
        app,
        "/xrpc/com.atproto.admin.sendEmail",
        json!({
            "recipientDid": "did:plc:alice",
            "senderDid": "did:web:test.example",
            "subject": "test",
            "content": "hello",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
}

// ---------------------------------------------------------------------------
//  §4.3 — admin override of confirmation flows.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn admin_update_account_email_round_trip() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let (status, _) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateAccountEmail",
        json!({"account": "did:plc:alice", "email": "alice@new.example"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, body) = get_admin(
        app,
        "/xrpc/com.atproto.admin.getAccountInfo?did=did:plc:alice",
    )
    .await;
    assert_eq!(body["email"], "alice@new.example");
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_update_account_password_lets_user_log_in() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let (status, _) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateAccountPassword",
        json!({"did": "did:plc:alice", "password": "newsecret123"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Old password no longer works.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.server.createSession")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"identifier": "alice.example", "password": "pw"}))
                        .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // New password works.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.server.createSession")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(
                        &json!({"identifier": "alice.example", "password": "newsecret123"}),
                    )
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_update_account_password_rejects_short_password() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let (status, _) = post_admin(
        app,
        "/xrpc/com.atproto.admin.updateAccountPassword",
        json!({"did": "did:plc:alice", "password": "short"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
//  §4.5 — service-auth revocation.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn admin_revoke_service_auth_appends_blacklist_row() {
    let (app, _manager, _tmp) = build_app().await;
    let (status, _) = post_admin(
        app,
        "/xrpc/com.atproto.admin.revokeServiceAuth",
        json!({
            "jti": "abc-123",
            "expiresAt": "2099-01-01T00:00:00Z",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
//  §4.6 — invite toggles.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn admin_disable_account_invites_blocks_create() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let (status, _) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.disableAccountInvites",
        json!({"account": "did:plc:alice"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Login to get an access token.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.server.createSession")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"identifier": "alice.example", "password": "pw"}))
                        .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let token = body["accessJwt"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.server.createInviteCode")
                .method("POST")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(
                    serde_json::to_vec(&json!({"useCount": 1})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Re-enable.
    let (status, _) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.enableAccountInvites",
        json!({"account": "did:plc:alice"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.server.createInviteCode")
                .method("POST")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(
                    serde_json::to_vec(&json!({"useCount": 1})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
//  §7.2 — admin forceRepoSync.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn admin_force_repo_sync_returns_404_when_no_commits() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let (status, _) = post_admin(
        app,
        "/xrpc/com.atproto.admin.forceRepoSync",
        json!({"did": "did:plc:alice"}),
    )
    .await;
    // Fresh account has no commits yet; the handler returns 404.
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_force_repo_sync_requires_admin_basic_auth() {
    let (app, _manager, _tmp) = build_app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.admin.forceRepoSync")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"did": "did:plc:alice"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_disable_invite_codes_marks_disabled() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.server.createSession")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"identifier": "alice.example", "password": "pw"}))
                        .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let token = body["accessJwt"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.server.createInviteCode")
                .method("POST")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(
                    serde_json::to_vec(&json!({"useCount": 1})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let code = body["code"].as_str().unwrap().to_string();

    let (status, _) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.disableInviteCodes",
        json!({"codes": [code.clone()]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Verify the code is now disabled in the listing.
    let (_, body) = get_admin(app, "/xrpc/com.atproto.admin.getInviteCodes").await;
    let codes = body["codes"].as_array().unwrap();
    let found = codes
        .iter()
        .find(|x| x["code"] == code)
        .expect("code present");
    assert_eq!(found["disabled"], true);
}

/// The rewritten comparison still accepts the right password and rejects the
/// wrong one.
///
/// A constant-time rewrite is exactly the kind of change that can silently
/// break correctness — an always-false comparison leaks nothing and locks
/// everyone out, and an always-true one leaks nothing either. Neither shows up
/// in a timing measurement, so the property worth testing is the boring one.
#[tokio::test(flavor = "multi_thread")]
async fn admin_auth_still_distinguishes_right_from_wrong() {
    let (app, _manager, _tmp) = build_app().await;

    for (label, password, expect_ok) in [
        ("exact", ADMIN_PASSWORD.to_string(), true),
        ("wrong", "definitely-not-it".to_string(), false),
        // A prefix and an extension: a length-sensitive comparison would treat
        // these differently from an unrelated string.
        ("prefix", ADMIN_PASSWORD[..4].to_string(), false),
        ("extended", format!("{ADMIN_PASSWORD}x"), false),
        ("empty", String::new(), false),
    ] {
        let request = Request::builder()
            .uri("/xrpc/com.atproto.admin.getAccountInfo?did=did:plc:nobody")
            .header(
                "authorization",
                format!("Basic {}", B64STD.encode(format!("admin:{password}"))),
            )
            .body(Body::empty())
            .unwrap();
        let status = app.clone().oneshot(request).await.unwrap().status();
        if expect_ok {
            assert_ne!(
                status,
                StatusCode::UNAUTHORIZED,
                "the correct password was rejected ({label})"
            );
        } else {
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "a wrong password was accepted ({label})"
            );
        }
    }
}

// ---------------------------------------------------------------------------
//  Lexicon conformance for the admin surface.
//
//  Each assertion below is taken from the published lexicon, not from what this
//  crate happened to emit. A canonical client validates against these schemas,
//  so a missing required field or a renamed input is a hard failure for it even
//  though the endpoint "works" when called by a client shaped like this server.
// ---------------------------------------------------------------------------

/// `com.atproto.admin.defs#accountView` requires `did`, `handle`, `indexedAt`.
#[tokio::test(flavor = "multi_thread")]
async fn account_view_carries_the_fields_the_lexicon_requires() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let (status, body) = get_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.getAccountInfo?did=did:plc:alice",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for field in ["did", "handle", "indexedAt"] {
        assert!(
            body.get(field).is_some(),
            "accountView requires {field}: {body}"
        );
    }

    // The same shape through the batch and search endpoints — they return
    // `accountView` refs, so a struct that satisfies one must satisfy all.
    let (_, batch) = get_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.getAccountInfos?dids=did:plc:alice",
    )
    .await;
    assert!(
        batch["infos"][0]["indexedAt"].is_string(),
        "getAccountInfos returns accountView refs: {batch}"
    );

    let (_, found) = get_admin(app, "/xrpc/com.atproto.admin.searchAccounts?email=ali").await;
    assert!(
        found["accounts"][0]["indexedAt"].is_string(),
        "searchAccounts returns accountView refs: {found}"
    );
}

/// `searchAccounts` declares `email`, `limit`, `cursor` — and no `q`.
#[tokio::test(flavor = "multi_thread")]
async fn search_accounts_takes_the_declared_parameter() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let (status, body) = get_admin(app, "/xrpc/com.atproto.admin.searchAccounts?email=ali").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["accounts"].as_array().map(Vec::len),
        Some(1),
        "the declared `email` parameter should drive the search: {body}"
    );
}

/// `updateAccountEmail` names the subject `account`, an at-identifier.
#[tokio::test(flavor = "multi_thread")]
async fn update_account_email_takes_an_at_identifier_named_account() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let (status, body) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateAccountEmail",
        json!({ "account": "did:plc:alice", "email": "new@example.com" }),
    )
    .await;
    assert!(status.is_success(), "`account` should be accepted: {body}");

    // `at-identifier` means a handle is equally valid.
    let (status, body) = post_admin(
        app,
        "/xrpc/com.atproto.admin.updateAccountEmail",
        json!({ "account": "alice.example", "email": "byhandle@example.com" }),
    )
    .await;
    assert!(
        status.is_success(),
        "an at-identifier may be a handle: {body}"
    );
}

/// `sendEmail` requires `senderDid` and leaves `subject` optional.
#[tokio::test(flavor = "multi_thread")]
async fn send_email_takes_sender_did_and_an_optional_subject() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateAccountEmail",
        json!({ "account": "did:plc:alice", "email": "alice@example.com" }),
    )
    .await;

    let (status, body) = post_admin(
        app,
        "/xrpc/com.atproto.admin.sendEmail",
        json!({
            "recipientDid": "did:plc:alice",
            "senderDid": "did:web:test.example",
            "content": "hello",
        }),
    )
    .await;
    assert!(
        status.is_success(),
        "senderDid required, subject optional: {body}"
    );
    assert_eq!(body["sent"], true);
}

/// The invite toggles live under `com.atproto.admin.*` and name the subject
/// `account`.
#[tokio::test(flavor = "multi_thread")]
async fn invite_toggles_are_admin_namespaced() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let (status, body) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.disableAccountInvites",
        json!({ "account": "did:plc:alice", "note": "spam" }),
    )
    .await;
    assert!(status.is_success(), "{body}");

    let (status, body) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.enableAccountInvites",
        json!({ "account": "did:plc:alice" }),
    )
    .await;
    assert!(status.is_success(), "{body}");

    // The old server-namespaced paths are gone.
    let (status, _) = post_admin(
        app,
        "/xrpc/com.atproto.server.disableAccountInvites",
        json!({ "did": "did:plc:alice" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
//  F-MOD-03 + F-BLOB-15 — the canonical subject union, and the two subject
//  kinds it makes addressable.
//
//  Until now `updateSubjectStatus` took `{did, state}`, a shape that appears
//  nowhere in the lexicon. Ozone and `pdsadmin` send `{subject, takedown}`, so
//  every canonical moderation call failed to deserialize — and record and blob
//  subjects had no storage behind them at all.
// ---------------------------------------------------------------------------

fn repo_ref(did: &str) -> Value {
    json!({"$type": "com.atproto.admin.defs#repoRef", "did": did})
}

fn strong_ref(uri: &str, cid: &str) -> Value {
    json!({"$type": "com.atproto.repo.strongRef", "uri": uri, "cid": cid})
}

fn blob_ref(did: &str, cid: &str) -> Value {
    json!({"$type": "com.atproto.admin.defs#repoBlobRef", "did": did, "cid": cid})
}

/// Log in as the account and create a record through the XRPC surface, so the
/// takedown tests act on a record that really exists.
async fn seed_record(app: &axum::Router, handle: &str, rkey: &str, text: &str) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.server.createSession")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"identifier": handle, "password": "pw"})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let token = body["accessJwt"].as_str().unwrap().to_string();
    let did = body["did"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.repo.createRecord")
                .method("POST")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "repo": did,
                        "collection": "app.bsky.feed.post",
                        "rkey": rkey,
                        "record": {"$type": "app.bsky.feed.post", "text": text},
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(status, StatusCode::OK, "seed record: {body}");
    body["cid"].as_str().unwrap().to_string()
}

async fn get_record(app: &axum::Router, did: &str, rkey: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/xrpc/com.atproto.repo.getRecord?repo={did}&collection=app.bsky.feed.post&rkey={rkey}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

async fn list_rkeys(app: &axum::Router, did: &str) -> Vec<String> {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/xrpc/com.atproto.repo.listRecords?repo={did}&collection=app.bsky.feed.post"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    body["records"]
        .as_array()
        .expect("records array")
        .iter()
        .map(|r| {
            r["uri"]
                .as_str()
                .unwrap()
                .rsplit('/')
                .next()
                .unwrap()
                .to_string()
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn update_subject_status_speaks_the_canonical_union() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    // The exact body Ozone sends. Under the old `{did, state}` shape this was
    // a deserialization failure, not a partial success.
    let (status, body) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateSubjectStatus",
        json!({
            "subject": repo_ref("did:plc:alice"),
            "takedown": {"applied": true, "ref": "ozone-action-1"},
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["subject"]["$type"], "com.atproto.admin.defs#repoRef");
    assert_eq!(body["subject"]["did"], "did:plc:alice");
    assert_eq!(body["takedown"]["applied"], true);
    assert_eq!(body["takedown"]["ref"], "ozone-action-1");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_record_can_be_taken_down_without_touching_the_account() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let cid = seed_record(&app, "alice.example", "bad", "illegal").await;
    seed_record(&app, "alice.example", "good", "fine").await;

    let uri = "at://did:plc:alice/app.bsky.feed.post/bad";
    assert_eq!(
        get_record(&app, "did:plc:alice", "bad").await,
        StatusCode::OK
    );

    let (status, body) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateSubjectStatus",
        json!({
            "subject": strong_ref(uri, &cid),
            "takedown": {"applied": true, "ref": "mod-9"},
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    // The point of the whole finding: one record gone, the account and its
    // other records untouched.
    assert_eq!(
        get_record(&app, "did:plc:alice", "bad").await,
        StatusCode::BAD_REQUEST,
        "a taken-down record must not be readable"
    );
    assert_eq!(
        get_record(&app, "did:plc:alice", "good").await,
        StatusCode::OK,
        "its neighbours must be unaffected"
    );
    let rkeys = list_rkeys(&app, "did:plc:alice").await;
    assert_eq!(
        rkeys,
        vec!["good".to_string()],
        "listRecords must filter it"
    );

    // And it lifts.
    let (status, _) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateSubjectStatus",
        json!({"subject": strong_ref(uri, &cid), "takedown": {"applied": false}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        get_record(&app, "did:plc:alice", "bad").await,
        StatusCode::OK
    );
    assert_eq!(list_rkeys(&app, "did:plc:alice").await.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_record_takedown_is_reported_by_get_subject_status() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let cid = seed_record(&app, "alice.example", "bad", "illegal").await;
    let uri = "at://did:plc:alice/app.bsky.feed.post/bad";

    post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateSubjectStatus",
        json!({"subject": strong_ref(uri, &cid), "takedown": {"applied": true, "ref": "mod-9"}}),
    )
    .await;

    let (status, body) = get_admin(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.admin.getSubjectStatus?uri={}",
            urlencode(uri)
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["subject"]["$type"], "com.atproto.repo.strongRef");
    assert_eq!(body["subject"]["uri"], uri);
    // The echoed strongRef carries the record's real CID, not one the caller
    // supplied — a moderator reading status should learn what is there now.
    assert_eq!(body["subject"]["cid"], cid);
    assert_eq!(body["takedown"]["applied"], true);
    assert_eq!(body["takedown"]["ref"], "mod-9");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_blob_can_be_taken_down_without_touching_the_account() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    // Upload a blob as the account.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.server.createSession")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"identifier": "alice.example", "password": "pw"}))
                        .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let token = body["accessJwt"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.repo.uploadBlob")
                .method("POST")
                .header("content-type", "image/png")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(b"not really a png".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let cid = body["blob"]["ref"]["$link"].as_str().unwrap().to_string();

    let fetch = |app: axum::Router, cid: String| async move {
        app.oneshot(
            Request::builder()
                .uri(format!(
                    "/xrpc/com.atproto.sync.getBlob?did=did:plc:alice&cid={cid}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    };
    assert_eq!(fetch(app.clone(), cid.clone()).await, StatusCode::OK);

    let (status, body) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateSubjectStatus",
        json!({
            "subject": blob_ref("did:plc:alice", &cid),
            "takedown": {"applied": true, "ref": "mod-11"},
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    // Withheld, and reported as absent rather than forbidden: a probe should
    // not confirm the bytes are still stored here.
    assert_eq!(
        fetch(app.clone(), cid.clone()).await,
        StatusCode::NOT_FOUND,
        "a taken-down blob must not be served"
    );

    let (_, body) = get_admin(
        app.clone(),
        &format!("/xrpc/com.atproto.admin.getSubjectStatus?did=did:plc:alice&blob={cid}"),
    )
    .await;
    assert_eq!(
        body["subject"]["$type"],
        "com.atproto.admin.defs#repoBlobRef"
    );
    assert_eq!(body["takedown"]["applied"], true);
    assert_eq!(body["takedown"]["ref"], "mod-11");

    // Lift restores it.
    post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateSubjectStatus",
        json!({"subject": blob_ref("did:plc:alice", &cid), "takedown": {"applied": false}}),
    )
    .await;
    assert_eq!(fetch(app, cid).await, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn deactivated_round_trips_on_an_account_and_is_refused_elsewhere() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let cid = seed_record(&app, "alice.example", "one", "hi").await;

    let (status, _) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateSubjectStatus",
        json!({"subject": repo_ref("did:plc:alice"), "deactivated": {"applied": true}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = get_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.getSubjectStatus?did=did:plc:alice",
    )
    .await;
    assert_eq!(body["deactivated"]["applied"], true);

    // A record has no deactivated state. Refused rather than ignored, so a
    // moderator who thinks they deactivated something finds out.
    let (status, _) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateSubjectStatus",
        json!({
            "subject": strong_ref("at://did:plc:alice/app.bsky.feed.post/one", &cid),
            "deactivated": {"applied": true},
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn contradictory_takedown_and_activation_is_refused() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    // Whichever half ran last would win silently, so neither runs.
    let (status, _) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateSubjectStatus",
        json!({
            "subject": repo_ref("did:plc:alice"),
            "takedown": {"applied": true},
            "deactivated": {"applied": false},
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (_, body) = get_admin(
        app,
        "/xrpc/com.atproto.admin.getSubjectStatus?did=did:plc:alice",
    )
    .await;
    assert_eq!(
        body["takedown"]["applied"], false,
        "the refused request must not have applied half of itself"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn get_subject_status_needs_a_subject_and_a_blob_needs_a_did() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let (status, _) = get_admin(app.clone(), "/xrpc/com.atproto.admin.getSubjectStatus").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = get_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.getSubjectStatus?blob=bafkreiabc",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A malformed record URI is a client error, named as such.
    let (status, _) = get_admin(
        app,
        "/xrpc/com.atproto.admin.getSubjectStatus?uri=not-a-uri",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_subject_type_is_refused() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let (status, _) = post_admin(
        app,
        "/xrpc/com.atproto.admin.updateSubjectStatus",
        json!({
            "subject": {"$type": "com.example.notASubject", "did": "did:plc:alice"},
            "takedown": {"applied": true},
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Percent-encode the characters an AT-URI carries that a query string cannot.
fn urlencode(s: &str) -> String {
    s.replace(':', "%3A").replace('/', "%2F")
}
