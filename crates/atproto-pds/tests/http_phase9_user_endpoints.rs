//! acceptance — user-facing endpoints.
//!
//! Coverage:
//! - `requestEmailConfirmation` + `confirmEmail` (§9.1).
//! - `requestPasswordReset` + `resetPassword` (§9.2).
//! - `com.atproto.moderation.createReport` (§9.3) — forwarded to the
//!   moderation service when configured, 503 otherwise.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::RepoReader;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

async fn build_app() -> (axum::Router, TempDir, Arc<AccountManager>) {
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
    let reader = Arc::new(RepoReader::new(accounts, dir));
    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    );
    (build_router(state), tmp, manager)
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

async fn create_account(app: &axum::Router, did: &str, handle: &str) -> String {
    let req = Request::builder()
        .uri("/xrpc/com.atproto.server.createAccount")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "did": did,
                "handle": handle,
                "password": "originalpw",
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    body["accessJwt"].as_str().unwrap().to_string()
}

/// Helper — read the most-recent email_token row for a DID + purpose, if any.
async fn fetch_email_token(manager: &AccountManager, did: &str, purpose: &str) -> Option<String> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT token FROM email_token
         WHERE did = ? AND purpose = ?
         ORDER BY expires_at DESC LIMIT 1",
    )
    .bind(did)
    .bind(purpose)
    .fetch_optional(manager.pool())
    .await
    .unwrap();
    row.map(|(t,)| t)
}

// ---------------------------------------------------------------------------
//  §9.1 — initial-email confirmation flow.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn request_email_confirmation_412_when_no_email() {
    let (app, _tmp, _manager) = build_app().await;
    let token = create_account(&app, "did:plc:alice", "alice.example").await;
    // No email set on the account → precondition failed.
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.server.requestEmailConfirmation",
        json!({}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
}

#[tokio::test(flavor = "multi_thread")]
async fn confirm_email_round_trip_sets_email_confirmed_at() {
    let (app, _tmp, manager) = build_app().await;
    let token = create_account(&app, "did:plc:alice", "alice.example").await;

    // Seed account.email so requestEmailConfirmation passes the precondition.
    sqlx::query("UPDATE account SET email = ? WHERE did = ?")
        .bind("alice@example.com")
        .bind("did:plc:alice")
        .execute(manager.pool())
        .await
        .unwrap();

    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.requestEmailConfirmation",
        json!({}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let confirm_token = fetch_email_token(&manager, "did:plc:alice", "confirm_email")
        .await
        .expect("email_token row exists");

    // Redeem.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.confirmEmail",
        json!({"token": confirm_token.clone()}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Account row reflects the confirmation timestamp.
    let row: (Option<String>,) =
        sqlx::query_as("SELECT email_confirmed_at FROM account WHERE did = ?")
            .bind("did:plc:alice")
            .fetch_one(manager.pool())
            .await
            .unwrap();
    assert!(row.0.is_some(), "email_confirmed_at must be set");

    // Token consumed — second redemption fails.
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.server.confirmEmail",
        json!({"token": confirm_token}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn request_email_confirmation_400_when_already_confirmed() {
    let (app, _tmp, manager) = build_app().await;
    let token = create_account(&app, "did:plc:alice", "alice.example").await;
    sqlx::query("UPDATE account SET email = ?, email_confirmed_at = ? WHERE did = ?")
        .bind("alice@example.com")
        .bind(chrono::Utc::now().to_rfc3339())
        .bind("did:plc:alice")
        .execute(manager.pool())
        .await
        .unwrap();
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.server.requestEmailConfirmation",
        json!({}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
//  §9.2 — password-reset flow.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn request_password_reset_returns_200_for_unknown_email() {
    let (app, _tmp, _manager) = build_app().await;
    // No account at all — should still be 200 to avoid leaking existence.
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.server.requestPasswordReset",
        json!({"email": "ghost@example.com"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_password_round_trip_lets_user_log_in_with_new_password() {
    let (app, _tmp, manager) = build_app().await;
    let _ = create_account(&app, "did:plc:alice", "alice.example").await;
    sqlx::query("UPDATE account SET email = ? WHERE did = ?")
        .bind("alice@example.com")
        .bind("did:plc:alice")
        .execute(manager.pool())
        .await
        .unwrap();

    // Issue.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.requestPasswordReset",
        json!({"email": "alice@example.com"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let reset_token = fetch_email_token(&manager, "did:plc:alice", "reset_password")
        .await
        .expect("email_token row exists");

    // Redeem.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.resetPassword",
        json!({"token": reset_token, "password": "newsecret123"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Old password fails.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.createSession",
        json!({"identifier": "alice.example", "password": "originalpw"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // New password works.
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.server.createSession",
        json!({"identifier": "alice.example", "password": "newsecret123"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_password_rejects_short_password() {
    let (app, _tmp, _manager) = build_app().await;
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.server.resetPassword",
        json!({"token": "irrelevant", "password": "short"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
//  §9.3 — moderation report forwarding.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn create_report_503_when_unconfigured() {
    let (app, _tmp, _manager) = build_app().await;
    let token = create_account(&app, "did:plc:alice", "alice.example").await;
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.moderation.createReport",
        json!({
            "reasonType": "com.atproto.moderation.defs#reasonOther",
            "subject": {"$type": "com.atproto.repo.strongRef", "uri": "at://did:plc:bob/x.y/k", "cid": "bafy"},
        }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_report_requires_auth() {
    let (app, _tmp, _manager) = build_app().await;
    let (status, _) = post_json(
        app,
        "/xrpc/com.atproto.moderation.createReport",
        json!({"reasonType": "x"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
