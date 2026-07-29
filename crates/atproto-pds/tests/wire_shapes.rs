//! Wire-shape conformance for four response objects that diverged from the
//! lexicons in ways a validating client rejects.
//!
//! Each is asserted on the serialized JSON rather than on a Rust value,
//! because in every case the defect is the *presence or absence of a key* —
//! something a round trip through the same types cannot see.

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

async fn post(app: axum::Router, path: &str, body: Value, token: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .uri(path)
        .method("POST")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn get(app: axum::Router, path: &str) -> (StatusCode, Value) {
    let resp = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The lexicon types `cursor` as a plain string, so the exhausted page must
/// omit the key rather than send `null` — otherwise the last iteration of
/// every pagination loop throws.
#[tokio::test(flavor = "multi_thread")]
async fn list_records_omits_cursor_when_exhausted() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.test").await;
    let (status, _) = post(
        app.clone(),
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "repo": "did:plc:alice",
            "collection": "app.bsky.feed.post",
            "record": {"$type": "app.bsky.feed.post", "text": "one"}
        }),
        &token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = get(
        app,
        "/xrpc/com.atproto.repo.listRecords?repo=did:plc:alice&collection=app.bsky.feed.post",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["records"].as_array().unwrap().len(), 1);
    assert!(
        body.get("cursor").is_none(),
        "an exhausted listing must omit `cursor`, not send null: {body}"
    );
}

/// `describeRepo` must carry `didDoc` — the lexicon marks it required, so its
/// absence throws in a validating client and breaks the migration handshake.
#[tokio::test(flavor = "multi_thread")]
async fn describe_repo_includes_the_did_document() {
    let (app, manager, _tmp) = build_app().await;
    create_account(&app, &manager, "did:plc:alice", "alice.test").await;

    let (status, body) = get(
        app,
        "/xrpc/com.atproto.repo.describeRepo?repo=did:plc:alice",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let did_doc = body
        .get("didDoc")
        .unwrap_or_else(|| panic!("describeRepo must carry didDoc: {body}"));
    assert_eq!(did_doc["id"], "did:plc:alice");
    assert_eq!(did_doc["alsoKnownAs"], json!(["at://alice.test"]));

    // A consumer reads the service endpoint to know where to fetch the repo,
    // and the signing key to verify its commits.
    let services = did_doc["service"].as_array().expect("service array");
    let pds = services
        .iter()
        .find(|s| s["id"] == "#atproto_pds")
        .expect("an #atproto_pds entry");
    assert_eq!(pds["serviceEndpoint"], "https://test.example");

    let methods = did_doc["verificationMethod"]
        .as_array()
        .expect("verificationMethod array");
    let atproto = methods
        .iter()
        .find(|m| m["id"] == "did:plc:alice#atproto")
        .expect("an #atproto verification method");
    assert_eq!(atproto["type"], "Multikey");
    assert!(
        atproto["publicKeyMultibase"]
            .as_str()
            .unwrap()
            .starts_with('z'),
        "multibase key should be z-prefixed: {atproto}"
    );
}

/// `applyWrites` results are a closed union, so every entry needs a `$type`.
///
/// A delete result additionally carries *nothing else*: `#deleteResult` is an
/// empty object, and neither create nor update results carry `commit` — that
/// appears once at the top level.
#[tokio::test(flavor = "multi_thread")]
async fn apply_writes_results_are_discriminated_union_members() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.test").await;

    let (status, body) = post(
        app.clone(),
        "/xrpc/com.atproto.repo.applyWrites",
        json!({
            "repo": "did:plc:alice",
            "writes": [{
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": "aaaaaaaaaaaaa",
                "value": {"$type": "app.bsky.feed.post", "text": "one"}
            }]
        }),
        &token,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let results = body["results"].as_array().expect("results array");
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0]["$type"], "com.atproto.repo.applyWrites#createResult",
        "results: {results:?}"
    );
    assert!(
        results[0]["uri"]
            .as_str()
            .unwrap()
            .contains("did:plc:alice")
    );
    assert!(results[0]["cid"].as_str().is_some());
    assert!(
        results[0].get("commit").is_none(),
        "commit belongs at the top level, not on each result: {results:?}"
    );
    assert!(body["commit"]["cid"].as_str().is_some());

    // Now delete it, and confirm the delete result is the empty variant.
    let (status, body) = post(
        app,
        "/xrpc/com.atproto.repo.applyWrites",
        json!({
            "repo": "did:plc:alice",
            "writes": [{
                "$type": "com.atproto.repo.applyWrites#delete",
                "collection": "app.bsky.feed.post",
                "rkey": "aaaaaaaaaaaaa"
            }]
        }),
        &token,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let results = body["results"].as_array().unwrap();
    assert_eq!(
        results[0]["$type"], "com.atproto.repo.applyWrites#deleteResult",
        "results: {results:?}"
    );
    assert_eq!(
        results[0].as_object().unwrap().len(),
        1,
        "#deleteResult is an empty object apart from its $type: {results:?}"
    );
}

/// `#repoOp.cid` is required-and-nullable; `prev` is optional.
///
/// The distinction matters and is easy to collapse into "both are optional".
/// A delete must emit `"cid": null` — dropping the key gives subscribers an
/// object that does not decode against the lexicon — while a create must omit
/// `prev` entirely, because the lexicon says "for creations, field should not
/// be defined".
#[test]
fn repo_op_emits_null_cid_but_omits_absent_prev() {
    use atproto_dasl::Cid;
    use atproto_repo::mst::{RepoOp, RepoOpAction};

    let cid: Cid = Cid(
        "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454"
            .parse()
            .unwrap(),
    );

    let create = RepoOp {
        action: RepoOpAction::Create,
        path: "app.bsky.feed.post/aaaa".to_string(),
        cid: Some(cid.clone()),
        prev: None,
    };
    let json = serde_json::to_value(&create).unwrap();
    assert!(
        json.get("prev").is_none(),
        "a create must not define `prev`: {json}"
    );
    assert!(json.get("cid").is_some());

    let delete = RepoOp {
        action: RepoOpAction::Delete,
        path: "app.bsky.feed.post/aaaa".to_string(),
        cid: None,
        prev: Some(cid),
    };
    let json = serde_json::to_value(&delete).unwrap();
    assert!(
        json.get("cid").is_some_and(Value::is_null),
        "a delete must carry `cid` as an explicit null: {json}"
    );
    assert!(
        json.get("prev").is_some(),
        "a delete carries `prev`: {json}"
    );
}

/// A record carrying a blob ref must survive write and read unchanged, and get
/// the CID the data model dictates.
///
/// The JSON representation spells a link as `{"$link": …}`; the data model has
/// a link type, and DAG-CBOR encodes it as tag 42. Storing the JSON object
/// verbatim produces a different CID from every other implementation and a body
/// that fails `blob`-typed validation downstream.
#[tokio::test(flavor = "multi_thread")]
async fn a_record_with_a_blob_ref_round_trips_and_hashes_correctly() {
    let (app, manager, _tmp) = build_app().await;
    let token = create_account(&app, &manager, "did:plc:alice", "alice.test").await;

    let record = json!({
        "$type": "app.bsky.feed.post",
        "text": "with an image",
        "embed": {
            "$type": "blob",
            "ref": { "$link": "bafkreiccldh766hwcnuxnf2wh6jgzepf2nlu2lvcllt63eww5p6chi4ity" },
            "mimeType": "image/jpeg",
            "size": 10000
        }
    });

    let (status, created) = post(
        app.clone(),
        "/xrpc/com.atproto.repo.createRecord",
        json!({
            "repo": "did:plc:alice",
            "collection": "app.bsky.feed.post",
            "rkey": "aaaaaaaaaaaaa",
            "record": record,
        }),
        &token,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {created}");

    // Pinned rather than recomputed, so this cannot pass by agreeing with
    // whatever the writer happens to do. The encoder that produces it is
    // separately checked against upstream-supplied CIDs by the data-model
    // fixtures in `atproto-dasl`.
    assert_eq!(
        created["cid"].as_str().unwrap(),
        "bafyreidbmrjqco5tedmdigvwvdaonch4o4esflpgztmz7dqhl36z26hshq",
        "the record's CID must be the data model's encoding of it, \
         with `ref` stored as a link rather than a map with a `$link` key"
    );

    // And reading it back must give the same JSON that went in — the link
    // stored as tag 42 renders as `$link` again.
    let (status, fetched) = get(
        app,
        "/xrpc/com.atproto.repo.getRecord?repo=did:plc:alice\
         &collection=app.bsky.feed.post&rkey=aaaaaaaaaaaaa",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {fetched}");
    assert_eq!(fetched["value"], record, "record did not round-trip");
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
