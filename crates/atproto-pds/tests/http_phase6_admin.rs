//! Phase 6 admin-endpoint integration tests.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager};
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
    .with_writer(writer)
    .with_admin_password(ADMIN_PASSWORD.to_string());
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
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;

    let (status, body) = get_admin(
        app,
        "/xrpc/com.atproto.admin.getAccountInfo?did=did:plc:alice",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["did"], "did:plc:alice");
    assert_eq!(body["state"], "active");
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_endpoints_require_basic_auth() {
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;
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
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;

    // Takedown.
    let (status, body) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateSubjectStatus",
        json!({"did": "did:plc:alice", "state": "takendown"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let (_, body) = get_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.getSubjectStatus?did=did:plc:alice",
    )
    .await;
    assert_eq!(body["state"], "takendown");

    // Lift.
    let (status, _) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateSubjectStatus",
        json!({"did": "did:plc:alice", "state": "active"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = get_admin(
        app,
        "/xrpc/com.atproto.admin.getSubjectStatus?did=did:plc:alice",
    )
    .await;
    assert_eq!(body["state"], "active");
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_takedown_blocks_public_reads() {
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;
    post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateSubjectStatus",
        json!({"did": "did:plc:alice", "state": "takendown"}),
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
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_delete_account_terminal() {
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;
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
        json!({"did": "did:plc:alice", "state": "active"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_search_accounts_substring() {
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;
    create_account(&app, "did:plc:bob", "bob.example").await;
    create_account(&app, "did:plc:carol", "carol.example").await;

    let (status, body) =
        get_admin(app.clone(), "/xrpc/com.atproto.admin.searchAccounts?q=ali").await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let accounts = body["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0]["did"], "did:plc:alice");

    // Empty match.
    let (_, body) = get_admin(app, "/xrpc/com.atproto.admin.searchAccounts?q=zzzz").await;
    assert_eq!(body["accounts"].as_array().unwrap().len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_get_invite_codes_listing() {
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;

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
    let (app, _tmp) = build_app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/xrpc/com.atproto.admin.searchAccounts?q=any")
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
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;
    create_account(&app, "did:plc:bob", "bob.example").await;

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
    let (app, _tmp) = build_app().await;
    let (status, _) = get_admin(app, "/xrpc/com.atproto.admin.getAccountInfos?dids=").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
//  §4.2 — sendEmail.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn admin_send_email_to_account_with_email() {
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;
    // The default createAccount in this test harness doesn't set an email
    // address, so seed one directly via updateAccountEmail (§4.3).
    let (status, _) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateAccountEmail",
        json!({"did": "did:plc:alice", "email": "alice@example.com"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = post_admin(
        app,
        "/xrpc/com.atproto.admin.sendEmail",
        json!({
            "recipientDid": "did:plc:alice",
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
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;
    let (status, _) = post_admin(
        app,
        "/xrpc/com.atproto.admin.sendEmail",
        json!({
            "recipientDid": "did:plc:alice",
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
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;

    let (status, _) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.admin.updateAccountEmail",
        json!({"did": "did:plc:alice", "email": "alice@new.example"}),
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
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;

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
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;
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
    let (app, _tmp) = build_app().await;
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
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;

    let (status, _) = post_admin(
        app.clone(),
        "/xrpc/com.atproto.server.disableAccountInvites",
        json!({"did": "did:plc:alice"}),
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
        "/xrpc/com.atproto.server.enableAccountInvites",
        json!({"did": "did:plc:alice"}),
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
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;
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
    let (app, _tmp) = build_app().await;
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
    let (app, _tmp) = build_app().await;
    create_account(&app, "did:plc:alice", "alice.example").await;
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
