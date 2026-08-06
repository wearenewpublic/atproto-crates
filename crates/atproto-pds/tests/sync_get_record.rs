//! `com.atproto.sync.getRecord` — the proof form of a record fetch.
//!
//! This method was absent, and its absence was invisible from here. Every
//! manual check of "is the record published and fetchable" used
//! `com.atproto.repo.getRecord`, which answered 200 the whole time; the thing
//! that needed the sync method was an authorization server on another host
//! resolving an OAuth permission set, and it reported the failure as
//! `invalid_scope` naming no method.
//!
//! So these assert what a caller on the other end actually needs: a CAR rooted
//! at the current commit, carrying the blocks that prove the record is in it.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter, WriteAction, WriteOp};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

const DID: &str = "did:plc:syncgetrecordfixture000000";
const HANDLE: &str = "proof.test.example";
const COLLECTION: &str = "com.atproto.lexicon.schema";
const RKEY: &str = "app.bulleted.authFull";

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
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer.clone())
    .with_service_handle_domains(vec!["test.example".to_string()]);

    manager
        .create_account(CreateAccountParams::new(DID, HANDLE, "pw"))
        .await
        .expect("fixture account");
    writer.create_genesis_commit(DID).await.expect("genesis");
    writer
        .apply_writes(
            DID,
            vec![WriteOp {
                action: WriteAction::Create,
                collection: COLLECTION.to_string(),
                rkey: RKEY.to_string(),
                value: Some(serde_json::json!({
                    "lexicon": 1,
                    "id": RKEY,
                    "defs": {"main": {"type": "permission-set", "title": "Bulleted"}},
                })),
                swap_record: None,
            }],
        )
        .await
        .expect("fixture record");

    (build_router(state), tmp)
}

/// GET the method with no auth at all. Returns (status, content-type, body).
async fn get(app: &axum::Router, path: &str) -> (StatusCode, String, Vec<u8>) {
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let ctype = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, ctype, body)
}

fn url(collection: &str, rkey: &str) -> String {
    format!("/xrpc/com.atproto.sync.getRecord?did={DID}&collection={collection}&rkey={rkey}")
}

/// A record that exists returns a CAR, unauthenticated.
///
/// No session, no bearer: the caller is an authorization server that has never
/// seen this one, which is the whole point of the method being open.
#[tokio::test(flavor = "multi_thread")]
async fn an_existing_record_returns_a_car_without_auth() {
    let (app, _tmp) = build_app().await;

    let (status, ctype, body) = get(&app, &url(COLLECTION, RKEY)).await;

    assert_eq!(status, StatusCode::OK, "the method must answer anonymously");
    assert_eq!(ctype, "application/vnd.ipld.car");
    assert!(!body.is_empty(), "an empty CAR proves nothing");
}

/// The CAR is rooted at the current commit and carries the record.
///
/// A caller checks the record belongs to this repository by walking from the
/// signed commit down; a CAR rooted anywhere else, or missing the record
/// block, cannot be verified no matter how well-formed it is.
#[tokio::test(flavor = "multi_thread")]
async fn the_car_is_rooted_at_the_commit_and_contains_the_record() {
    let (app, _tmp) = build_app().await;

    // What the repository says its head is.
    let (_, _, head) = get(
        &app,
        &format!("/xrpc/com.atproto.sync.getLatestCommit?did={DID}"),
    )
    .await;
    let head: serde_json::Value = serde_json::from_slice(&head).expect("latest commit json");
    let commit_cid = head["cid"].as_str().expect("a head cid").to_string();

    let (_, _, car) = get(&app, &url(COLLECTION, RKEY)).await;

    // Read it as a CAR rather than scanning bytes: the header stores CIDs in
    // binary, so their base32 spelling never appears in the file.
    let mut reader = atproto_dasl::car::CarReader::new(std::io::Cursor::new(car))
        .await
        .expect("the response must be a readable CAR");

    let roots: Vec<String> = reader.roots().iter().map(ToString::to_string).collect();
    assert_eq!(
        roots,
        vec![commit_cid.clone()],
        "the CAR must be rooted at the current commit"
    );

    let mut cids = Vec::new();
    let mut carries_the_record = false;
    while let Some(block) = reader.next_block().await.expect("read block") {
        cids.push(block.cid.to_string());
        if block.data.windows(RKEY.len()).any(|w| w == RKEY.as_bytes()) {
            carries_the_record = true;
        }
    }

    assert!(
        cids.contains(&commit_cid),
        "the commit block itself must travel with the proof: {cids:?}"
    );
    assert!(
        cids.len() >= 2,
        "a proof is the commit plus the path to the key, not the commit alone: {cids:?}"
    );
    assert!(
        carries_the_record,
        "the record block is not in the CAR: {cids:?}"
    );
}

/// An absent record is a success, not an error.
///
/// The CAR proves the key is not there. Returning `RecordNotFound` for a
/// repository this server holds would refuse to answer a question it can
/// answer — that name is for repositories whose absence cannot be proved.
#[tokio::test(flavor = "multi_thread")]
async fn an_absent_record_is_proved_rather_than_refused() {
    let (app, _tmp) = build_app().await;

    let (status, ctype, body) = get(&app, &url(COLLECTION, "no.such.record")).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "absence has a proof and this method returns it"
    );
    assert_eq!(ctype, "application/vnd.ipld.car");
    assert!(!body.is_empty(), "the commit alone is still a proof");
}

/// An unknown repository is `RepoNotFound`.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_did_is_refused() {
    let (app, _tmp) = build_app().await;

    let (status, _, body) = get(
        &app,
        &format!(
            "/xrpc/com.atproto.sync.getRecord?did=did:plc:nosuchrepo000000000000000&collection={COLLECTION}&rkey={RKEY}"
        ),
    )
    .await;

    assert_ne!(status, StatusCode::OK, "an unknown repo has no proof");
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("RepoNotFound") || text.contains("NotFound"),
        "expected RepoNotFound, got: {text}"
    );
}
