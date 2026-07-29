//! HTTP integration tests for `com.atproto.repo.uploadBlob` +
//! `listMissingBlobs`. Together with `migration_e2e` these cover the audit
//! follow-up that previously had `listMissingBlobs` returning an unconditional
//! empty list.

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

#[tokio::test(flavor = "multi_thread")]
async fn upload_blob_round_trip() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;

    let req = Request::builder()
        .uri("/xrpc/com.atproto.repo.uploadBlob")
        .method("POST")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "image/png")
        .body(Body::from(b"\x89PNG\r\n\x1a\nfake-png-bytes".to_vec()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    // The typed lexicon envelope: `$type`, a nested `ref` cid-link, `mimeType`
    // and `size`. This is what a client embeds verbatim into a record value,
    // so the shape returned here is the shape the reference validator sees.
    let blob = &body["blob"];
    assert_eq!(blob["$type"], "blob", "blob envelope: {blob}");
    let link = blob["ref"]["$link"].as_str().unwrap_or_else(|| {
        panic!("blob ref must nest the CID under `ref.$link`, got {blob}");
    });
    assert!(link.starts_with("bafkrei") || link.starts_with("bafy"));
    assert_eq!(blob["mimeType"], "image/png");
    assert!(blob["size"].as_u64().unwrap() > 0);
    assert!(
        blob.get("$link").is_none(),
        "`$link` must not appear at the top level of the envelope: {blob}"
    );
    assert_eq!(blob.as_object().unwrap().len(), 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_blob_requires_auth() {
    let (app, _manager, _tmp) = build_app().await;
    let req = Request::builder()
        .uri("/xrpc/com.atproto.repo.uploadBlob")
        .method("POST")
        .header("content-type", "image/png")
        .body(Body::from(b"some-bytes".to_vec()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn list_missing_blobs_starts_empty() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.example").await;
    let req = Request::builder()
        .uri("/xrpc/com.atproto.repo.listMissingBlobs")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["blobs"].as_array().unwrap().len(), 0);
}

/// An uploaded blob must never render as a document on this origin.
///
/// The MIME type comes from the client's `content-type` header and is not
/// validated, so a caller can declare `text/html`. This origin also serves the
/// OAuth consent screen and session cookies, so a blob that renders is stored
/// XSS against the authorization server — a victim who opens the blob URL runs
/// the uploader's script with this origin's cookies in scope.
///
/// Three headers together prevent it: `nosniff` stops a browser second-guessing
/// a benign declared type, `content-disposition: attachment` makes the response
/// a download rather than a document, and the CSP neuters it if it is rendered
/// anyway.
#[tokio::test(flavor = "multi_thread")]
async fn get_blob_refuses_to_render_as_a_document() {
    let (app, manager, _tmp) = build_app().await;
    let did = "did:plc:blobxss";
    let token = create_account(&app, &manager, did, "xss.test.example").await;

    // Upload something a browser would happily execute, declared as such.
    let payload = b"<script>alert(document.domain)</script>".to_vec();
    let request = Request::builder()
        .uri("/xrpc/com.atproto.repo.uploadBlob")
        .method("POST")
        .header("content-type", "text/html")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(payload))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let cid = body["blob"]["ref"]["$link"]
        .as_str()
        .or_else(|| body["blob"]["$link"].as_str())
        .expect("uploadBlob should return the blob ref")
        .to_string();

    let request = Request::builder()
        .uri(format!(
            "/xrpc/com.atproto.sync.getBlob?did={did}&cid={cid}"
        ))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();

    assert_eq!(
        headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff"),
        "without nosniff a browser may execute a blob whose declared type is benign"
    );
    let disposition = headers
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        disposition.starts_with("attachment"),
        "a blob must download, not render; content-disposition was {disposition:?}"
    );
    let csp = headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        csp.contains("default-src 'none'") && csp.contains("sandbox"),
        "the CSP must neuter a blob that is rendered anyway; was {csp:?}"
    );
}

/// A blob under the advertised ceiling must upload.
///
/// `MAX_BLOB_BYTES` is 16 MiB and `uploadBlob` checks it, but the handler
/// extracts `axum::body::Bytes` and axum applies its own 2 MiB default to every
/// route unless a `DefaultBodyLimit` layer says otherwise. So the documented
/// ceiling was dead code: the real limit was eight times smaller, and a typical
/// phone photo failed.
#[tokio::test(flavor = "multi_thread")]
async fn a_blob_under_the_ceiling_uploads() {
    let (app, manager, _tmp) = build_app().await;
    let did = "did:plc:bigblob";
    let token = create_account(&app, &manager, did, "big.test.example").await;

    // 3 MiB — comfortably over axum's 2 MiB default, comfortably under 16 MiB.
    let payload = vec![0x42u8; 3 * 1024 * 1024];
    let request = Request::builder()
        .uri("/xrpc/com.atproto.repo.uploadBlob")
        .method("POST")
        .header("content-type", "image/jpeg")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(payload))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        StatusCode::OK,
        "a 3 MiB upload is well under the 16 MiB ceiling this server advertises; body: {}",
        String::from_utf8_lossy(&body)
    );
}

/// Over the ceiling, the refusal is an XRPC error and not a bare 413.
///
/// A client cannot act on `length limit exceeded` in text/plain — it is not the
/// error shape every other failure on this surface uses, so a client's error
/// handling does not see it.
#[tokio::test(flavor = "multi_thread")]
async fn a_blob_over_the_ceiling_is_refused_as_xrpc() {
    let (app, manager, _tmp) = build_app().await;
    let did = "did:plc:hugeblob";
    let token = create_account(&app, &manager, did, "huge.test.example").await;

    let payload = vec![0x42u8; 17 * 1024 * 1024];
    let request = Request::builder()
        .uri("/xrpc/com.atproto.repo.uploadBlob")
        .method("POST")
        .header("content-type", "image/jpeg")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(payload))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    assert!(
        parsed.get("error").is_some(),
        "the refusal should be an XRPC error body, got {:?}",
        String::from_utf8_lossy(&body)
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

// ---------------------------------------------------------------------------
//  Record→blob reference tracking (F-BLOB-02).
//
//  Every piece of this existed and nothing called it, so `listMissingBlobs`
//  answered `{"blobs": []}` forever. A migrating client concluded there was
//  nothing to transfer and activated an account with none of its media, while
//  every step reported success.
// ---------------------------------------------------------------------------

/// Write a record and return its AT-URI.
async fn write_record_with(
    app: &axum::Router,
    did: &str,
    token: &str,
    rkey: &str,
    record: Value,
) -> StatusCode {
    let request = Request::builder()
        .uri("/xrpc/com.atproto.repo.putRecord")
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&json!({
                "repo": did,
                "collection": "app.bsky.feed.post",
                "rkey": rkey,
                "record": record,
            }))
            .unwrap(),
        ))
        .unwrap();
    app.clone().oneshot(request).await.unwrap().status()
}

async fn missing_blobs(app: &axum::Router, did: &str, token: &str) -> Vec<String> {
    let request = Request::builder()
        .uri(format!("/xrpc/com.atproto.repo.listMissingBlobs?did={did}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
            .unwrap_or(Value::Null);
    body["blobs"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|b| b["cid"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn blob_envelope(cid: &str) -> Value {
    json!({
        "$type": "blob",
        "ref": { "$link": cid },
        "mimeType": "image/jpeg",
        "size": 1234,
    })
}

/// A record referencing a blob that was never uploaded is reported missing.
///
/// This is the whole point of `listMissingBlobs`: it is how a migrating client
/// learns what it still has to transfer.
#[tokio::test(flavor = "multi_thread")]
async fn a_referenced_but_absent_blob_is_reported_missing() {
    let (app, manager, _tmp) = build_app().await;
    let did = "did:plc:refs";
    let token = create_account(&app, &manager, did, "refs.test.example").await;

    // A real CID for bytes that were never uploaded. A made-up string will not
    // do: the record encoder reads `$link` into the data model, so an
    // unparseable CID fails the write rather than reaching the ref index.
    let cid = atproto_dasl::cid::compute_raw_cid(b"never uploaded").to_string();
    let cid = cid.as_str();
    assert_eq!(
        write_record_with(
            &app,
            did,
            &token,
            "post1",
            json!({
                "$type": "app.bsky.feed.post",
                "text": "with media",
                "embed": { "images": [{ "alt": "a", "image": blob_envelope(cid) }] },
            }),
        )
        .await,
        StatusCode::OK
    );

    assert_eq!(
        missing_blobs(&app, did, &token).await,
        vec![cid.to_string()],
        "a record referenced a blob that was never uploaded and nothing noticed"
    );
}

/// An uploaded blob is not missing.
#[tokio::test(flavor = "multi_thread")]
async fn an_uploaded_blob_is_not_reported_missing() {
    let (app, manager, _tmp) = build_app().await;
    let did = "did:plc:refs2";
    let token = create_account(&app, &manager, did, "refs2.test.example").await;

    // Upload first, then reference what was uploaded.
    let request = Request::builder()
        .uri("/xrpc/com.atproto.repo.uploadBlob")
        .method("POST")
        .header("content-type", "image/jpeg")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(b"pretend jpeg".to_vec()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let cid = body["blob"]["ref"]["$link"]
        .as_str()
        .or_else(|| body["blob"]["$link"].as_str())
        .expect("uploadBlob returns a ref")
        .to_string();

    write_record_with(
        &app,
        did,
        &token,
        "post1",
        json!({
            "$type": "app.bsky.feed.post",
            "text": "with media",
            "embed": { "images": [{ "alt": "a", "image": blob_envelope(&cid) }] },
        }),
    )
    .await;

    assert!(
        missing_blobs(&app, did, &token).await.is_empty(),
        "an uploaded blob should not be reported missing"
    );
}

/// Rewriting a record without the blob drops the reference.
///
/// Adding refs without ever dropping them would make the counts only grow —
/// a different wrong answer, and blob GC reads those counts to decide what is
/// orphaned.
#[tokio::test(flavor = "multi_thread")]
async fn dropping_a_blob_from_a_record_drops_the_reference() {
    let (app, manager, _tmp) = build_app().await;
    let did = "did:plc:refs3";
    let token = create_account(&app, &manager, did, "refs3.test.example").await;
    let cid = atproto_dasl::cid::compute_raw_cid(b"dropped blob").to_string();
    let cid = cid.as_str();

    write_record_with(
        &app,
        did,
        &token,
        "post1",
        json!({
            "$type": "app.bsky.feed.post",
            "text": "with media",
            "embed": { "images": [{ "alt": "a", "image": blob_envelope(cid) }] },
        }),
    )
    .await;
    assert_eq!(missing_blobs(&app, did, &token).await.len(), 1);

    // Same record, no blob.
    write_record_with(
        &app,
        did,
        &token,
        "post1",
        json!({ "$type": "app.bsky.feed.post", "text": "media removed" }),
    )
    .await;

    assert!(
        missing_blobs(&app, did, &token).await.is_empty(),
        "the reference survived a rewrite that removed the blob"
    );
}

/// Deleting the record drops its references.
#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_record_drops_its_references() {
    let (app, manager, _tmp) = build_app().await;
    let did = "did:plc:refs4";
    let token = create_account(&app, &manager, did, "refs4.test.example").await;
    let cid = atproto_dasl::cid::compute_raw_cid(b"deleted blob").to_string();
    let cid = cid.as_str();

    write_record_with(
        &app,
        did,
        &token,
        "post1",
        json!({
            "$type": "app.bsky.feed.post",
            "text": "with media",
            "embed": { "images": [{ "alt": "a", "image": blob_envelope(cid) }] },
        }),
    )
    .await;
    assert_eq!(missing_blobs(&app, did, &token).await.len(), 1);

    let request = Request::builder()
        .uri("/xrpc/com.atproto.repo.deleteRecord")
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&json!({
                "repo": did,
                "collection": "app.bsky.feed.post",
                "rkey": "post1",
            }))
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::OK
    );

    assert!(
        missing_blobs(&app, did, &token).await.is_empty(),
        "a deleted record left its blob references behind"
    );
}
