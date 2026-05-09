//! End-to-end account-migration smoke test.
//!
//! Walks the full migration sequence per the design's §4.5 flow:
//!
//! 1. **Old PDS** issues a service-auth JWT scoped to `lxm=createAccount`.
//! 2. **New PDS** receives `createAccount(did=..., plcOp=...)` and creates a
//!    deactivated account (Phase 5 short-circuit: caller-supplied DID).
//! 3. **New PDS** receives a CAR import via `importRepo`.
//! 4. **New PDS** lists missing blobs (returns empty in Phase 5 — blob storage is
//!    deferred but the contract holds).
//! 5. **New PDS** activates the account.
//! 6. The session JWT issued at createAccount continues to work post-activation
//!    for read endpoints.
//!
//! This test is intentionally narrow on the cryptographic verification side
//! (we don't validate PLC-rotation signatures end-to-end, since that requires
//! a live PLC directory). The focus is on HTTP-flow continuity.

use atproto_dasl::car::{CarBlock, CarWriter};
use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use atproto_repo::repo::UnsignedCommit;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
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
    let reader = Arc::new(RepoReader::new(accounts, dir.clone()));
    let state = HttpState::with_account_manager(
        reader,
        manager,
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer);
    (build_router(state), tmp)
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

/// Build a minimal valid one-commit CAR for `did`.
async fn minimal_car_for(did: &str) -> Vec<u8> {
    let empty_mst_bytes = atproto_dasl::to_vec(&serde_json::json!({"e": [], "l": null})).unwrap();
    let mst_cid_raw = atproto_dasl::cid::compute_cid(&empty_mst_bytes);
    let mst_cid = atproto_dasl::Cid(mst_cid_raw);

    let signed = UnsignedCommit::new(did.to_string(), mst_cid, "3jui7kd2z2y2e".to_string(), None)
        .sign(vec![0u8; 64]);
    let commit_bytes = signed.to_bytes().unwrap();
    let commit_cid_raw = signed.cid().unwrap();
    let commit_cid = atproto_dasl::Cid(commit_cid_raw);

    let mut buf: Vec<u8> = Vec::new();
    let mut writer = CarWriter::new(&mut buf, vec![commit_cid]).await.unwrap();
    writer
        .write_block(&CarBlock {
            cid: commit_cid_raw,
            data: commit_bytes,
        })
        .await
        .unwrap();
    writer
        .write_block(&CarBlock {
            cid: mst_cid_raw,
            data: empty_mst_bytes,
        })
        .await
        .unwrap();
    writer.finish().await.unwrap();
    buf
}

#[tokio::test(flavor = "multi_thread")]
async fn full_migration_sequence() {
    let (app, _tmp) = build_app().await;

    // Step 1+2: create account with a caller-supplied DID (Phase 5 stub
    // for the migrating-account path, which the design says comes in
    // `deactivated` state pending repo import).
    let did = "did:plc:migrate";
    let handle = "migrate.example";
    let (status, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.createAccount",
        json!({"did": did, "handle": handle, "password": "pw"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "createAccount: body {body}");
    let access_jwt = body["accessJwt"].as_str().unwrap().to_string();

    // For the migration sequence, the account should typically start in
    // `deactivated` state. The Phase 5 createAccount path always activates
    // — so we explicitly deactivate to mirror the design.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.deactivateAccount",
        json!({}),
        Some(&access_jwt),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "deactivate during migration");

    // Step 3: importRepo with a valid CAR.
    let car = minimal_car_for(did).await;
    let req = Request::builder()
        .uri("/xrpc/com.atproto.repo.importRepo")
        .method("POST")
        .header("authorization", format!("Bearer {access_jwt}"))
        .header("content-type", "application/vnd.ipld.car")
        .body(Body::from(car))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "importRepo body: {:?}",
        resp.into_body().collect().await.unwrap().to_bytes()
    );

    // Step 4: listMissingBlobs returns [] (Phase 5 scaffold; blob storage
    // not yet implemented).
    let (status, body) = get_json(
        app.clone(),
        "/xrpc/com.atproto.repo.listMissingBlobs",
        Some(&access_jwt),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "listMissingBlobs: {body}");
    assert_eq!(body["blobs"].as_array().unwrap().len(), 0);

    // Step 5: activateAccount.
    let (status, _) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.activateAccount",
        json!({}),
        Some(&access_jwt),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "activate post-import");

    // Step 6: account is `active` again — the same JWT continues to work
    // for authenticated reads.
    let (status, body) = get_json(
        app.clone(),
        "/xrpc/com.atproto.server.checkAccountStatus",
        Some(&access_jwt),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "checkAccountStatus: {body}");
    assert_eq!(body["activated"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_with_invalid_car_fails_cleanly() {
    let (app, _tmp) = build_app().await;
    let did = "did:plc:migrate";
    let (_, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.createAccount",
        json!({"did": did, "handle": "migrate.example", "password": "pw"}),
        None,
    )
    .await;
    let access_jwt = body["accessJwt"].as_str().unwrap().to_string();

    let req = Request::builder()
        .uri("/xrpc/com.atproto.repo.importRepo")
        .method("POST")
        .header("authorization", format!("Bearer {access_jwt}"))
        .header("content-type", "application/vnd.ipld.car")
        .body(Body::from(b"definitely-not-a-CAR".to_vec()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_client_error() || resp.status().is_server_error(),
        "garbage CAR rejected, got {:?}",
        resp.status()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_importrepo_requires_privileged_session() {
    let (app, _tmp) = build_app().await;
    // createAccount path issues a privileged primary password. Then we
    // create a non-privileged app password and try importRepo with that
    // session — expect 403.
    let (_, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.createAccount",
        json!({"did": "did:plc:alice", "handle": "alice.example", "password": "pw"}),
        None,
    )
    .await;
    let primary_jwt = body["accessJwt"].as_str().unwrap().to_string();

    let (_, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.createAppPassword",
        json!({"name": "non-priv", "privileged": false}),
        Some(&primary_jwt),
    )
    .await;
    let app_password = body["password"].as_str().unwrap().to_string();
    let (_, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.createSession",
        json!({"identifier": "alice.example", "password": app_password}),
        None,
    )
    .await;
    let unprivileged_jwt = body["accessJwt"].as_str().unwrap().to_string();

    let car = minimal_car_for("did:plc:alice").await;
    let req = Request::builder()
        .uri("/xrpc/com.atproto.repo.importRepo")
        .method("POST")
        .header("authorization", format!("Bearer {unprivileged_jwt}"))
        .header("content-type", "application/vnd.ipld.car")
        .body(Body::from(car))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
