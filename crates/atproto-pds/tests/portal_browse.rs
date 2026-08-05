//! Integration tests for the portal's repository browser.
//!
//! The browser is the one part of the portal that both reads *and rewrites*
//! repository contents from a browser session, so what matters is that the
//! round trip is real: a record written through the repo writer shows up in
//! the listing, its JSON renders, an edit through the form changes what the
//! reader returns, and a delete removes it.
//!
//! Asserting through the rendered pages rather than the storage layer is
//! deliberate. A browser that shows a record which is not there, or hides one
//! that is, is broken in exactly the way a storage-level test cannot see.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams, portal};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter, WriteAction, WriteOp};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

const DID: &str = "did:plc:portalbrowsefixture000000";
const HANDLE: &str = "browser.pds.test";
const COLLECTION: &str = "app.bsky.feed.post";
const RKEY: &str = "3kaaaaaaaaaa2";

async fn build_app() -> (axum::Router, Arc<AccountManager>, Arc<RepoWriter>, TempDir) {
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
        "did:web:pds.test".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer.clone())
    .with_service_handle_domains(vec!["pds.test".to_string()]);
    (build_router(state), manager, writer, tmp)
}

/// An account with a portal session and one record in its public repo.
async fn signed_in_with_a_record(manager: &AccountManager, writer: &RepoWriter) -> String {
    manager
        .create_account(CreateAccountParams::new(DID, HANDLE, "pw"))
        .await
        .expect("fixture account");
    writer
        .create_genesis_commit(DID)
        .await
        .expect("fixture genesis");
    writer
        .apply_writes(
            DID,
            vec![WriteOp {
                action: WriteAction::Create,
                collection: COLLECTION.to_string(),
                rkey: RKEY.to_string(),
                value: Some(serde_json::json!({
                    "$type": COLLECTION,
                    "text": "the original text",
                    "createdAt": "2026-08-05T00:00:00Z",
                })),
                swap_record: None,
            }],
        )
        .await
        .expect("fixture record");

    let cookie = format!("cookie-for-{DID}");
    portal::create_session(&manager.account_pool(), &cookie, DID, 0, None)
        .await
        .expect("fixture session");
    cookie
}

async fn get(app: &axum::Router, cookie: &str, path: &str) -> (StatusCode, String, Option<String>) {
    let req = Request::builder()
        .uri(path)
        .header("sec-fetch-site", "same-origin")
        .header("cookie", format!("atproto_pds_portal={cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body =
        String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).to_string();
    (status, body, location)
}

async fn post(app: &axum::Router, cookie: &str, path: &str, body: &str) -> Option<String> {
    let req = Request::builder()
        .uri(path)
        .method("POST")
        .header("sec-fetch-site", "same-origin")
        .header("cookie", format!("atproto_pds_portal={cookie}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    resp.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// The index offers both realms.
#[tokio::test(flavor = "multi_thread")]
async fn the_index_links_the_public_repository() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;

    let (status, body, _) = get(&app, &cookie, "/browse/").await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("/browse/public/"),
        "no link to public records"
    );
    assert!(body.contains("Spaces"), "spaces are not offered");
}

/// A collection holding records is listed, and links to it.
#[tokio::test(flavor = "multi_thread")]
async fn collections_are_listed() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;

    let (status, body, _) = get(&app, &cookie, "/browse/public/").await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(COLLECTION),
        "the collection holding a record was not listed"
    );
    assert!(
        body.contains(&format!("/browse/public/{COLLECTION}")),
        "the collection does not link to its records"
    );
}

/// Records in a collection are listed by rkey.
#[tokio::test(flavor = "multi_thread")]
async fn records_are_listed() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;

    let (status, body, _) = get(&app, &cookie, &format!("/browse/public/{COLLECTION}")).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(RKEY), "the record was not listed");
}

/// One record renders its JSON, in a form that can be edited.
#[tokio::test(flavor = "multi_thread")]
async fn a_record_shows_its_json() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;

    let (status, body, _) = get(
        &app,
        &cookie,
        &format!("/browse/public/{COLLECTION}/{RKEY}"),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("the original text"),
        "the record's contents are not shown"
    );
    assert!(body.contains("<textarea"), "the record is not editable");
}

/// An edit through the form changes what the reader returns.
///
/// The whole point of the feature: not that the form accepts input, but that
/// the repository afterwards holds what was typed.
#[tokio::test(flavor = "multi_thread")]
async fn editing_a_record_rewrites_it() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;

    let edited = serde_json::json!({
        "$type": COLLECTION,
        "text": "the replacement text",
        "createdAt": "2026-08-05T00:00:00Z",
    })
    .to_string();
    let location = post(
        &app,
        &cookie,
        &format!("/browse/public/{COLLECTION}/{RKEY}"),
        &format!("value={}", urlencode(&edited)),
    )
    .await;

    assert_eq!(
        location.as_deref(),
        Some(format!("/browse/public/{COLLECTION}/{RKEY}?msg=saved").as_str()),
        "the edit was not accepted"
    );

    let (_, body, _) = get(
        &app,
        &cookie,
        &format!("/browse/public/{COLLECTION}/{RKEY}"),
    )
    .await;
    assert!(
        body.contains("the replacement text"),
        "the edit did not reach the repository"
    );
    assert!(
        !body.contains("the original text"),
        "the old value survived the edit"
    );
}

/// Malformed JSON is refused, and the record is left alone.
#[tokio::test(flavor = "multi_thread")]
async fn a_broken_edit_is_refused_without_touching_the_record() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;

    let location = post(
        &app,
        &cookie,
        &format!("/browse/public/{COLLECTION}/{RKEY}"),
        "value=not+json+at+all",
    )
    .await;

    assert_eq!(
        location.as_deref(),
        Some(format!("/browse/public/{COLLECTION}/{RKEY}?msg=err-that-is-not-valid-json").as_str())
    );

    let (_, body, _) = get(
        &app,
        &cookie,
        &format!("/browse/public/{COLLECTION}/{RKEY}"),
    )
    .await;
    assert!(
        body.contains("the original text"),
        "a refused edit still changed the record"
    );
}

/// The delete button — a POST carrying `_method=delete` — removes the record.
#[tokio::test(flavor = "multi_thread")]
async fn deleting_from_the_form_removes_the_record() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;

    let location = post(
        &app,
        &cookie,
        &format!("/browse/public/{COLLECTION}/{RKEY}"),
        "_method=delete",
    )
    .await;

    assert_eq!(
        location.as_deref(),
        Some(format!("/browse/public/{COLLECTION}?msg=deleted").as_str())
    );

    let (_, body, _) = get(&app, &cookie, &format!("/browse/public/{COLLECTION}")).await;
    assert!(
        !body.contains(RKEY),
        "the record is still listed after being deleted"
    );
}

/// The `DELETE` method works too, for anything not driving a browser form.
#[tokio::test(flavor = "multi_thread")]
async fn the_delete_method_removes_the_record() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;

    let req = Request::builder()
        .uri(format!("/browse/public/{COLLECTION}/{RKEY}"))
        .method("DELETE")
        .header("sec-fetch-site", "same-origin")
        .header("cookie", format!("atproto_pds_portal={cookie}"))
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(req).await.unwrap();

    let (_, body, _) = get(&app, &cookie, &format!("/browse/public/{COLLECTION}")).await;
    assert!(!body.contains(RKEY), "DELETE did not remove the record");
}

/// A CID in the collection position is served as a blob, not looked up as a
/// collection. This is the one ambiguity in the URL scheme.
#[tokio::test(flavor = "multi_thread")]
async fn a_cid_in_the_collection_position_is_treated_as_a_blob() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;
    let cid = "bafkreigcsk44torjvfr6rvmixv23vsmp2ey4c6z2yftuqecmqgvsyk4uye";

    let (_, _, location) = get(&app, &cookie, &format!("/browse/public/{cid}")).await;

    let location = location.expect("a CID should route to the blob endpoint");
    assert!(
        location.contains("com.atproto.sync.getBlob"),
        "a CID was not served as a blob: {location}"
    );
    assert!(location.contains(cid), "the blob CID was lost: {location}");
}

/// Signed out, the browser sends you to sign in rather than serving anything.
#[tokio::test(flavor = "multi_thread")]
async fn the_browser_requires_a_session() {
    let (app, manager, writer, _tmp) = build_app().await;
    let _ = signed_in_with_a_record(&manager, &writer).await;

    for path in [
        "/browse/",
        "/browse/public/",
        &format!("/browse/public/{COLLECTION}"),
        &format!("/browse/public/{COLLECTION}/{RKEY}"),
    ] {
        let (_, _, location) = get(&app, "not-a-real-session", path).await;
        assert_eq!(
            location.as_deref(),
            Some("/account/signin"),
            "{path} served something to a request with no session"
        );
    }
}

/// Percent-encode a form value.
fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
