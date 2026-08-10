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
use atproto_pds::account::{AccountDirectory, AccountManager, AccountState, CreateAccountParams};
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

/// A CAR carrying one real record in a real MST.
///
/// `minimal_car_for` builds an empty tree, which cannot show whether the import
/// indexes anything. This builds the tree properly — record block, MST nodes,
/// commit — so the assertions afterwards are about the import and not about the
/// fixture.
///
/// `omit_blob_block` leaves the referenced blob out of the CAR, which is the
/// normal case for a migration: blobs transfer separately, and
/// `listMissingBlobs` is how the client learns which ones it still owes.
async fn car_with_record(
    did: &str,
    collection: &str,
    rkey: &str,
    record: serde_json::Value,
) -> Vec<u8> {
    use atproto_dasl::storage::{BlockStorage, MemoryStorage};
    use atproto_repo::RepoConfig;
    use atproto_repo::mst::Mst;

    let record_bytes = atproto_dasl::atproto_json::to_vec(&record).unwrap();
    let record_cid = atproto_dasl::cid::compute_cid(&record_bytes);

    let mut storage = MemoryStorage::new();
    storage
        .put(&record_cid, record_bytes.clone())
        .await
        .unwrap();
    let mut mst = Mst::new(storage, RepoConfig::default());
    mst.insert(
        &format!("{collection}/{rkey}"),
        atproto_dasl::Cid(record_cid),
    )
    .await
    .unwrap();
    let root = mst.root().cloned().expect("a populated tree has a root");

    let signed = UnsignedCommit::new(
        did.to_string(),
        atproto_dasl::Cid(root),
        "3jui7kd2z2y2e".to_string(),
        None,
    )
    .sign(vec![0u8; 64]);
    let commit_bytes = signed.to_bytes().unwrap();
    let commit_cid = signed.cid().unwrap();

    let storage = mst.into_storage();
    let mut buf: Vec<u8> = Vec::new();
    let mut writer = CarWriter::new(&mut buf, vec![atproto_dasl::Cid(commit_cid)])
        .await
        .unwrap();
    writer
        .write_block(&CarBlock {
            cid: commit_cid,
            data: commit_bytes,
        })
        .await
        .unwrap();
    let cids: Vec<_> = storage.cids().collect();
    for cid in cids {
        let data = storage.get(&cid).await.unwrap().unwrap();
        writer.write_block(&CarBlock { cid, data }).await.unwrap();
    }
    writer.finish().await.unwrap();
    buf
}

#[tokio::test(flavor = "multi_thread")]
async fn full_migration_sequence() {
    let (app, manager, _tmp) = build_app().await;

    // Step 1+2: create account with a caller-supplied DID (Phase 5 stub
    // for the migrating-account path, which the design says comes in
    // `deactivated` state pending repo import).
    let did = "did:plc:migrate";
    let handle = "migrate.example";
    // Created through the internal API: the endpoint now requires a
    // service-auth token from the DID's current host, signed by a key in that
    // DID's document, which a test DID cannot produce. The endpoint's own
    // behaviour is asserted in `migration_create_account_requires_service_auth`
    // below.
    //
    // Deactivated at creation, which is what the endpoint now does for a
    // verified inbound migration — the test used to create the account active
    // and then deactivate it explicitly to mirror a design the code did not
    // implement.
    manager
        .create_account(
            CreateAccountParams::new(did, handle, "pw").with_state(AccountState::Deactivated),
        )
        .await
        .expect("migrating account");
    manager
        .set_primary_password(did, "pw")
        .await
        .expect("session password");
    let (_, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.createSession",
        json!({"identifier": handle, "password": "pw"}),
        None,
    )
    .await;
    let access_jwt = body["accessJwt"].as_str().unwrap().to_string();

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

    // Step 7: what a relay has to work from.
    //
    // Only `importRepo` emitted anything carrying a `rev`, and it did so while
    // the account was still deactivated -- when a relay may reasonably ignore
    // it and `getRepo` refuses to serve. Activation's own event is `#account
    // active=true`, which says the account is live and not where its head is,
    // so a relay learned to start indexing and had nothing to index from.
    let sequencer = manager.sequencer();
    let rows = sequencer
        .read_after(None, Some(did), 100)
        .await
        .expect("read the stream log");
    let last_sync = rows
        .iter()
        .rev()
        .find(|row| row.event_type == "sync")
        .expect("the migration should leave a #sync on the log");
    let last_account = rows
        .iter()
        .rev()
        .find(|row| row.event_type == "account")
        .expect("activation emits an #account event");
    assert!(
        last_sync.seq > last_account.seq,
        "the #sync naming the repo head must not be older than the event saying \
         the account is live: sync at {}, account at {}",
        last_sync.seq,
        last_account.seq
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_with_invalid_car_fails_cleanly() {
    let (app, manager, _tmp) = build_app().await;
    let did = "did:plc:migrate";
    manager
        .create_account(CreateAccountParams::new(did, "migrate.example", "pw"))
        .await
        .expect("fixture account");
    manager
        .set_primary_password(did, "pw")
        .await
        .expect("session password");
    let (_, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.createSession",
        json!({"identifier": "migrate.example", "password": "pw"}),
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
    let (app, manager, _tmp) = build_app().await;
    // createAccount path issues a privileged primary password. Then we
    // create a non-privileged app password and try importRepo with that
    // session — expect 403.
    manager
        .create_account(CreateAccountParams::new(
            "did:plc:alice",
            "alice.example",
            "pw",
        ))
        .await
        .expect("fixture account");
    manager
        .set_primary_password("did:plc:alice", "pw")
        .await
        .expect("session password");
    let (_, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.createSession",
        json!({"identifier": "alice.example", "password": "pw"}),
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

/// The endpoint that begins a migration demands proof of the DID.
///
/// This is the other half of the flow the tests above exercise with fixtures:
/// an inbound migration is authorised by a service-auth token from the DID's
/// current host, and without one `createAccount` must refuse rather than adopt
/// the identity on the caller's word.
#[tokio::test(flavor = "multi_thread")]
async fn migration_create_account_requires_service_auth() {
    let (app, _manager, _tmp) = build_app().await;
    let (status, body) = post_json(
        app,
        "/xrpc/com.atproto.server.createAccount",
        json!({"did": "did:plc:elsewhere", "handle": "elsewhere.test", "password": "pw"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(body["error"], "AuthRequired");
}

// ---------------------------------------------------------------------------
//  Record indexing on import (F-MIG-01).
//
//  Every record read resolves through `repo_record`, and the import wrote
//  blocks and commits and stopped. So `importRepo` reported success and the
//  account then presented as empty — silent data loss at the last step of a
//  migration.
// ---------------------------------------------------------------------------

/// Import a CAR as `did`, returning the response status.
async fn import_car(app: &axum::Router, token: &str, car: Vec<u8>) -> StatusCode {
    let req = Request::builder()
        .uri("/xrpc/com.atproto.repo.importRepo")
        .method("POST")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/vnd.ipld.car")
        .body(Body::from(car))
        .unwrap();
    app.clone().oneshot(req).await.unwrap().status()
}

/// Set up a deactivated migrating account and return its access token.
async fn migrating_account(app: &axum::Router, manager: &AccountManager, did: &str) -> String {
    manager
        .create_account(
            CreateAccountParams::new(did, "imported.example", "pw")
                .with_state(AccountState::Deactivated),
        )
        .await
        .expect("migrating account");
    manager
        .set_primary_password(did, "pw")
        .await
        .expect("session password");
    let (_, body) = post_json(
        app.clone(),
        "/xrpc/com.atproto.server.createSession",
        json!({"identifier": "imported.example", "password": "pw"}),
        None,
    )
    .await;
    body["accessJwt"].as_str().unwrap().to_string()
}

/// An imported repository is readable through every record API.
#[tokio::test(flavor = "multi_thread")]
async fn an_imported_repo_is_visible_to_the_record_apis() {
    let (app, manager, _tmp) = build_app().await;
    let did = "did:plc:imported";
    let token = migrating_account(&app, &manager, did).await;

    let car = car_with_record(
        did,
        "app.bsky.feed.post",
        "abc123",
        json!({ "$type": "app.bsky.feed.post", "text": "imported" }),
    )
    .await;
    assert_eq!(import_car(&app, &token, car).await, StatusCode::OK);

    // The account is deactivated mid-migration, so read as the owner.
    let (status, body) = get_json(
        app.clone(),
        &format!(
            "/xrpc/com.atproto.repo.getRecord?repo={did}&collection=app.bsky.feed.post&rkey=abc123"
        ),
        Some(&token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an imported record was not found: {body}"
    );
    assert_eq!(body["value"]["text"], "imported");

    let (status, body) = get_json(
        app.clone(),
        &format!("/xrpc/com.atproto.repo.listRecords?repo={did}&collection=app.bsky.feed.post"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["records"].as_array().map(Vec::len),
        Some(1),
        "listRecords returned an empty page for an imported repo: {body}"
    );

    let (status, body) = get_json(
        app,
        &format!("/xrpc/com.atproto.repo.describeRepo?repo={did}"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["collections"]
            .as_array()
            .is_some_and(|c| c.iter().any(|v| v == "app.bsky.feed.post")),
        "describeRepo listed no collections for an imported repo: {body}"
    );
}

/// A blob an imported record references, and the CAR did not carry, is
/// reported as still owed.
///
/// This is the question a migrating client asks next, and the answer used to be
/// "nothing" regardless.
#[tokio::test(flavor = "multi_thread")]
async fn an_imported_record_reports_the_blobs_it_still_needs() {
    let (app, manager, _tmp) = build_app().await;
    let did = "did:plc:importedblob";
    let token = migrating_account(&app, &manager, did).await;

    let blob_cid =
        atproto_dasl::cid::compute_raw_cid(b"a photo that travels separately").to_string();
    let car = car_with_record(
        did,
        "app.bsky.feed.post",
        "withmedia",
        json!({
            "$type": "app.bsky.feed.post",
            "text": "look",
            "embed": {
                "images": [{
                    "alt": "a",
                    "image": {
                        "$type": "blob",
                        "ref": { "$link": blob_cid },
                        "mimeType": "image/jpeg",
                        "size": 4321,
                    }
                }]
            }
        }),
    )
    .await;
    assert_eq!(import_car(&app, &token, car).await, StatusCode::OK);

    let (status, body) = get_json(
        app,
        &format!("/xrpc/com.atproto.repo.listMissingBlobs?did={did}"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let reported: Vec<&str> = body["blobs"]
        .as_array()
        .map(|items| items.iter().filter_map(|b| b["cid"].as_str()).collect())
        .unwrap_or_default();
    assert_eq!(
        reported,
        vec![blob_cid.as_str()],
        "the client was told it owed nothing: {body}"
    );
}

/// Importing the same CAR twice leaves one of each record.
#[tokio::test(flavor = "multi_thread")]
async fn importing_twice_is_idempotent() {
    let (app, manager, _tmp) = build_app().await;
    let did = "did:plc:importedtwice";
    let token = migrating_account(&app, &manager, did).await;

    for _ in 0..2 {
        let car = car_with_record(
            did,
            "app.bsky.feed.post",
            "abc123",
            json!({ "$type": "app.bsky.feed.post", "text": "imported" }),
        )
        .await;
        assert_eq!(import_car(&app, &token, car).await, StatusCode::OK);
    }

    let (_, body) = get_json(
        app,
        &format!("/xrpc/com.atproto.repo.listRecords?repo={did}&collection=app.bsky.feed.post"),
        Some(&token),
    )
    .await;
    assert_eq!(body["records"].as_array().map(Vec::len), Some(1));
}
