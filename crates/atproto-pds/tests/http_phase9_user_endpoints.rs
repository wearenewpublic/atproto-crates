//! acceptance — user-facing endpoints.
//!
//! Coverage:
//! - `requestEmailConfirmation` + `confirmEmail` (§9.1).
//! - `requestPasswordReset` + `resetPassword` (§9.2).
//! - `com.atproto.moderation.createReport` (§9.3) — forwarded to the
//!   moderation service when configured, 503 otherwise.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams};
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

/// GET a JSON endpoint, optionally bearing a token.
async fn get_json(app: axum::Router, path: &str, bearer: Option<&str>) -> (StatusCode, Value) {
    let mut req = Request::builder().uri(path).method("GET");
    if let Some(token) = bearer {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let resp = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
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
    let (app, _tmp, manager) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;
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

/// `getSession` reports the fields its lexicon defines, not just the handle.
///
/// `emailConfirmed` is the flag a client reads to decide whether to prompt the
/// account holder to verify their address. While it was omitted the prompt
/// could not be dismissed: no number of successful `confirmEmail` calls made
/// the response say so. `active` and `status` are the same story for a
/// deactivated or suspended account, which otherwise looked ordinary.
#[tokio::test(flavor = "multi_thread")]
async fn get_session_reports_email_confirmation_and_activity() {
    let (app, _tmp, manager) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    sqlx::query("UPDATE account SET email = ? WHERE did = ?")
        .bind("alice@example.com")
        .bind("did:plc:alice")
        .execute(manager.pool())
        .await
        .unwrap();

    let (status, body) = get_json(
        app.clone(),
        "/xrpc/com.atproto.server.getSession",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["emailConfirmed"], false, "body: {body}");
    assert_eq!(body["active"], true, "body: {body}");
    assert!(body["status"].is_null(), "an active account named a status");

    // Confirm, then look again.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.requestEmailConfirmation",
        json!({}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let code = fetch_email_token(&manager, "did:plc:alice", "confirm_email")
        .await
        .expect("email_token row exists");
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.confirmEmail",
        json!({"email": "alice@example.com", "token": code}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = get_json(
        app.clone(),
        "/xrpc/com.atproto.server.getSession",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["emailConfirmed"], true, "body: {body}");

    // A deactivated account says so rather than reading as ordinary.
    sqlx::query("UPDATE account SET state = 'deactivated' WHERE did = ?")
        .bind("did:plc:alice")
        .execute(manager.pool())
        .await
        .unwrap();
    let (status, body) = get_json(
        app.clone(),
        "/xrpc/com.atproto.server.getSession",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["active"], false, "body: {body}");
    assert_eq!(body["status"], "deactivated", "body: {body}");
}

/// `confirmEmail` reports refusals under the names its lexicon declares.
///
/// `ExpiredToken`, `InvalidToken` and `InvalidEmail` are three separate
/// declared errors and clients switch on them: expired means "request another
/// code", invalid means "that code is not yours", and a mismatched address
/// means the code is fine but names a different mailbox. All three previously
/// arrived as an undifferentiated `403`, which the lexicon does not declare at
/// all, so no client could tell them apart.
#[tokio::test(flavor = "multi_thread")]
async fn confirm_email_reports_declared_error_names() {
    let (app, _tmp, manager) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    sqlx::query("UPDATE account SET email = ? WHERE did = ?")
        .bind("alice@example.com")
        .bind("did:plc:alice")
        .execute(manager.pool())
        .await
        .unwrap();

    // A code that was never issued.
    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.confirmEmail",
        json!({"email": "alice@example.com", "token": "NOPE-NOPE"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidToken", "body: {body}");

    // A real code whose window has closed.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.requestEmailConfirmation",
        json!({}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let code = fetch_email_token(&manager, "did:plc:alice", "confirm_email")
        .await
        .expect("email_token row exists");
    sqlx::query("UPDATE email_token SET expires_at = ? WHERE token = ?")
        .bind((chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339())
        .bind(&code)
        .execute(manager.pool())
        .await
        .unwrap();
    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.confirmEmail",
        json!({"email": "alice@example.com", "token": code}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "ExpiredToken", "body: {body}");

    // A valid code, but the caller names an address that is not the one on
    // the account. Confirming would record the wrong mailbox as verified.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.requestEmailConfirmation",
        json!({}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let code = fetch_email_token(&manager, "did:plc:alice", "confirm_email")
        .await
        .expect("email_token row exists");
    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.confirmEmail",
        json!({"email": "someone.else@example.com", "token": code}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidEmail", "body: {body}");

    // None of the three confirmed anything.
    let row: (Option<String>,) =
        sqlx::query_as("SELECT email_confirmed_at FROM account WHERE did = ?")
            .bind("did:plc:alice")
            .fetch_one(manager.pool())
            .await
            .unwrap();
    assert!(
        row.0.is_none(),
        "a refused confirmEmail confirmed the email"
    );
}

/// `resetPassword` declares `ExpiredToken` and `InvalidToken` too. It is
/// reached without a session -- the code is the whole credential -- so the row
/// supplies the account rather than a bearer token.
#[tokio::test(flavor = "multi_thread")]
async fn reset_password_reports_declared_error_names() {
    let (app, _tmp, manager) = build_app().await;
    let _token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    sqlx::query("UPDATE account SET email = ? WHERE did = ?")
        .bind("alice@example.com")
        .bind("did:plc:alice")
        .execute(manager.pool())
        .await
        .unwrap();

    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.resetPassword",
        json!({"token": "NOT-A-CODE", "password": "new-password"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidToken", "body: {body}");

    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.requestPasswordReset",
        json!({"email": "alice@example.com"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let code = fetch_email_token(&manager, "did:plc:alice", "reset_password")
        .await
        .expect("email_token row exists");
    sqlx::query("UPDATE email_token SET expires_at = ? WHERE token = ?")
        .bind((chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339())
        .bind(&code)
        .execute(manager.pool())
        .await
        .unwrap();
    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.resetPassword",
        json!({"token": code, "password": "new-password"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "ExpiredToken", "body: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn confirm_email_round_trip_sets_email_confirmed_at() {
    let (app, _tmp, manager) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;

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

    // Redeem. The lexicon requires `email` alongside `token` and the call is
    // auth-required: the token confirms an address the session already owns.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.confirmEmail",
        json!({"email": "alice@example.com", "token": confirm_token.clone()}),
        Some(&token),
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
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;
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
    let _ = create_account(&app, &manager, "did:plc:alice", "alice.example").await;
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
    let (app, _tmp, manager) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;
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
//  Preferences (F-MIG-02).
//
//  These fell through the `app.bsky.*` catch-all to an AppView that implements
//  neither, so every call failed and private state could not migrate in either
//  direction. The lexicon names the purpose: synchronisation between devices,
//  and import/export during account migration.
// ---------------------------------------------------------------------------

/// A fresh account has an empty preferences array, not an error.
///
/// `preferences` is required by the lexicon, so the field is present and empty
/// rather than absent — a client reading `.preferences.length` must not have to
/// special-case a first run.
#[tokio::test(flavor = "multi_thread")]
async fn get_preferences_starts_empty() {
    let (app, _tmp, manager) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let (status, body) = get_json(app, "/xrpc/app.bsky.actor.getPreferences", Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["preferences"], json!([]));
}

/// Preferences round-trip verbatim, including types this build does not know.
///
/// `#preferences` is an array of open-union objects. A PDS that parsed them
/// would silently drop every preference type it had not been taught, which for
/// private state is data loss the user only discovers later.
#[tokio::test(flavor = "multi_thread")]
async fn preferences_round_trip_including_unknown_types() {
    let (app, _tmp, manager) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let prefs = json!([
        { "$type": "app.bsky.actor.defs#adultContentPref", "enabled": false },
        { "$type": "app.bsky.actor.defs#mutedWordsPref",
          "items": [{ "value": "spoilers", "targets": ["content"] }] },
        // A type this build has never heard of, with nested structure.
        { "$type": "com.example.someFuturePref",
          "nested": { "deep": [1, 2, 3] }, "flag": true },
    ]);

    let (status, body) = post_json(
        app.clone(),
        "/xrpc/app.bsky.actor.putPreferences",
        json!({ "preferences": prefs }),
        Some(&token),
    )
    .await;
    assert!(status.is_success(), "putPreferences: {body}");

    let (status, body) = get_json(app, "/xrpc/app.bsky.actor.getPreferences", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["preferences"], prefs,
        "preferences did not round-trip intact"
    );
}

/// A second put replaces rather than appends.
#[tokio::test(flavor = "multi_thread")]
async fn put_preferences_replaces_the_stored_set() {
    let (app, _tmp, manager) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    for prefs in [
        json!([{ "$type": "app.bsky.actor.defs#adultContentPref", "enabled": true }]),
        json!([{ "$type": "app.bsky.actor.defs#adultContentPref", "enabled": false }]),
    ] {
        post_json(
            app.clone(),
            "/xrpc/app.bsky.actor.putPreferences",
            json!({ "preferences": prefs }),
            Some(&token),
        )
        .await;
    }

    let (_, body) = get_json(app, "/xrpc/app.bsky.actor.getPreferences", Some(&token)).await;
    let stored = body["preferences"].as_array().expect("an array");
    assert_eq!(
        stored.len(),
        1,
        "a second put appended instead of replacing"
    );
    assert_eq!(stored[0]["enabled"], false);
}

/// Preferences are private state — both directions require auth.
#[tokio::test(flavor = "multi_thread")]
async fn preferences_require_auth() {
    let (app, _tmp, _manager) = build_app().await;

    let (status, _) = get_json(app.clone(), "/xrpc/app.bsky.actor.getPreferences", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = post_json(
        app,
        "/xrpc/app.bsky.actor.putPreferences",
        json!({ "preferences": [] }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// One account's preferences are not another's.
#[tokio::test(flavor = "multi_thread")]
async fn preferences_are_per_account() {
    let (app, _tmp, manager) = build_app().await;
    let alice = create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let bob = create_account(&app, &manager, "did:plc:bob", "bob.example").await;

    post_json(
        app.clone(),
        "/xrpc/app.bsky.actor.putPreferences",
        json!({ "preferences": [{ "$type": "app.bsky.actor.defs#adultContentPref", "enabled": true }] }),
        Some(&alice),
    )
    .await;

    let (_, body) = get_json(app, "/xrpc/app.bsky.actor.getPreferences", Some(&bob)).await;
    assert_eq!(
        body["preferences"],
        json!([]),
        "one account read another's private preferences"
    );
}
