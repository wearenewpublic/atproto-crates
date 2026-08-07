//! Integration tests for browsing permissioned spaces from the portal.
//!
//! The public half of the browser shipped with tests; this half did not,
//! because the harness had no way to make a space exist. That gap is the
//! reason these exist: the space handlers were structurally parallel to the
//! public ones and compiled against the real APIs, which is not the same as
//! having been run.
//!
//! The fixture seeds a space through the same service the XRPC layer uses,
//! writes a record into it through the same writer, and then drives the
//! browser. Nothing here reaches into storage directly, so a space that the
//! browser cannot show is a failure rather than an assertion that adapts.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams, portal};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use atproto_pds::space::config::SpaceConfig;
use atproto_pds::space::{SpaceReader, SpaceService, SpaceSync, SpaceWriter};
use atproto_space::types::SpaceUri;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

const DID: &str = "did:plc:spacebrowsefixture00000000";
const HANDLE: &str = "member.pds.test";
const SPACE_TYPE: &str = "app.bsky.group";
const SPACE_KEY: &str = "default";
const COLLECTION: &str = "app.bsky.feed.post";
const RKEY: &str = "3kaaaaaaaaaa2";

struct Fixture {
    app: axum::Router,
    svc: Arc<SpaceService>,
    cookie: String,
    space: SpaceUri,
    _tmp: TempDir,
}

/// An account holding one record in one space, with a portal session.
async fn fixture() -> Fixture {
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

    let svc = Arc::new(SpaceService::with_accounts(dir.clone(), manager.clone()));
    let space_writer = Arc::new(SpaceWriter::new(manager.clone(), dir.clone()));
    let space_reader = Arc::new(SpaceReader::new(manager.clone(), dir.clone()));
    let space_sync = Arc::new(SpaceSync::new(dir.clone()));

    let state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:pds.test".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer.clone())
    .with_spaces(svc.clone(), space_writer.clone(), space_reader, space_sync)
    .with_service_handle_domains(vec!["pds.test".to_string()]);
    let app = build_router(state);

    manager
        .create_account(CreateAccountParams::new(DID, HANDLE, "pw"))
        .await
        .expect("fixture account");
    writer
        .create_genesis_commit(DID)
        .await
        .expect("fixture genesis");

    let info = svc
        .create_space(DID, SPACE_TYPE, SPACE_KEY, SpaceConfig::default())
        .await
        .expect("fixture space");
    let space = SpaceUri::parse(&info.uri.to_string()).expect("fixture space uri");

    space_writer
        .put_record(
            DID,
            &space,
            COLLECTION.to_string(),
            RKEY.to_string(),
            serde_json::json!({
                "$type": COLLECTION,
                "text": "the original space text",
                "createdAt": "2026-08-05T00:00:00Z",
            }),
        )
        .await
        .expect("fixture space record");

    let cookie = format!("cookie-for-{DID}");
    portal::create_session(&manager.account_pool(), &cookie, DID, 0, None)
        .await
        .expect("fixture session");

    Fixture {
        app,
        svc: svc.clone(),
        cookie,
        space,
        _tmp: tmp,
    }
}

impl Fixture {
    /// Browser URL prefix for this space.
    fn base(&self) -> String {
        format!(
            "/account/repository/space/{}/{}/{}",
            urlenc(&self.space.space_did),
            urlenc(self.space.space_type.as_str()),
            urlenc(self.space.space_key.as_str())
        )
    }

    async fn get(&self, path: &str) -> (StatusCode, String, Option<String>) {
        let req = Request::builder()
            .uri(path)
            .header("sec-fetch-site", "same-origin")
            .header("cookie", format!("atproto_pds_portal={}", self.cookie))
            .body(Body::empty())
            .unwrap();
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes())
            .to_string();
        (status, body, location)
    }

    async fn post(&self, path: &str, body: &str) -> Option<String> {
        let req = Request::builder()
            .uri(path)
            .method("POST")
            .header("sec-fetch-site", "same-origin")
            .header("cookie", format!("atproto_pds_portal={}", self.cookie))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = self.app.clone().oneshot(req).await.unwrap();
        resp.headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    }
}

/// The index lists a space this account holds records in, and links to it.
#[tokio::test(flavor = "multi_thread")]
async fn the_index_lists_a_space_with_records() {
    let f = fixture().await;

    let (status, body, _) = f.get("/account/repository").await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(&urlenc(self_space_type())),
        "the space was not listed on the index"
    );
    assert!(
        body.contains(&f.base()),
        "the listed space does not link anywhere usable"
    );
}

fn self_space_type() -> &'static str {
    SPACE_TYPE
}

/// A space with no records is still listed.
///
/// The index used to read the distinct values in `space_record`, so a space
/// that had just been created — before anything was written to it — did not
/// appear at all. The holder had made it moments earlier and the page said
/// they had none.
#[tokio::test(flavor = "multi_thread")]
async fn a_space_with_no_records_is_listed() {
    let f = fixture().await;

    // A second space, deliberately left empty.
    let empty = f
        .svc
        .create_space(DID, SPACE_TYPE, "emptyone", SpaceConfig::default())
        .await
        .expect("second space");

    let (status, body, _) = f.get("/account/repository").await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("emptyone"),
        "a space with no records was omitted from the index"
    );
    // And the one that does have records is still there.
    assert!(
        body.contains(SPACE_KEY),
        "the populated space vanished: {}",
        empty.uri
    );
}

/// Collections holding space records are listed.
#[tokio::test(flavor = "multi_thread")]
async fn space_collections_are_listed() {
    let f = fixture().await;

    let (status, body, _) = f.get(&f.base()).await;

    assert_eq!(status, StatusCode::OK, "space collections did not render");
    assert!(
        body.contains(COLLECTION),
        "the collection holding a space record was not listed"
    );
}

/// Records in a space collection are listed by rkey.
#[tokio::test(flavor = "multi_thread")]
async fn space_records_are_listed() {
    let f = fixture().await;

    let (status, body, _) = f.get(&format!("{}/{COLLECTION}", f.base())).await;

    assert_eq!(status, StatusCode::OK, "space records did not render");
    assert!(body.contains(RKEY), "the space record was not listed");
}

/// A space record renders its JSON.
///
/// Space records are stored as DAG-CBOR rather than JSON, so this also pins
/// the decode: a browser that showed the raw bytes would still return 200.
#[tokio::test(flavor = "multi_thread")]
async fn a_space_record_shows_its_decoded_json() {
    let f = fixture().await;

    let (status, body, _) = f.get(&format!("{}/{COLLECTION}/{RKEY}", f.base())).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("the original space text"),
        "the space record's contents are not shown"
    );
    assert!(
        body.contains("<textarea"),
        "the space record is not editable"
    );
}

/// An edit through the form rewrites the space record.
#[tokio::test(flavor = "multi_thread")]
async fn editing_a_space_record_rewrites_it() {
    let f = fixture().await;
    let path = format!("{}/{COLLECTION}/{RKEY}", f.base());

    let edited = serde_json::json!({
        "$type": COLLECTION,
        "text": "the replacement space text",
        "createdAt": "2026-08-05T00:00:00Z",
    })
    .to_string();
    let location = f
        .post(&path, &format!("value={}", urlencode_form(&edited)))
        .await;

    assert_eq!(
        location.as_deref(),
        Some(format!("{path}?msg=saved").as_str()),
        "the space edit was not accepted"
    );

    let (_, body, _) = f.get(&path).await;
    assert!(
        body.contains("the replacement space text"),
        "the edit did not reach the space"
    );
    assert!(
        !body.contains("the original space text"),
        "the old space value survived the edit"
    );
}

/// Malformed JSON is refused, and the space record is left alone.
#[tokio::test(flavor = "multi_thread")]
async fn a_broken_space_edit_leaves_the_record_alone() {
    let f = fixture().await;
    let path = format!("{}/{COLLECTION}/{RKEY}", f.base());

    let location = f.post(&path, "value=not+json").await;

    assert_eq!(
        location.as_deref(),
        Some(format!("{path}?msg=err-that-is-not-valid-json").as_str())
    );
    let (_, body, _) = f.get(&path).await;
    assert!(
        body.contains("the original space text"),
        "a refused edit still changed the space record"
    );
}

/// The delete button removes a space record.
#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_space_record_removes_it() {
    let f = fixture().await;
    let path = format!("{}/{COLLECTION}/{RKEY}", f.base());

    let location = f.post(&path, "_method=delete").await;

    assert_eq!(
        location.as_deref(),
        Some(format!("{}/{COLLECTION}?msg=deleted", f.base()).as_str())
    );

    let (_, body, _) = f.get(&format!("{}/{COLLECTION}", f.base())).await;
    assert!(
        !body.contains(RKEY),
        "the space record is still listed after being deleted"
    );
}

/// `DELETE` works on space records too.
#[tokio::test(flavor = "multi_thread")]
async fn the_delete_method_removes_a_space_record() {
    let f = fixture().await;
    let path = format!("{}/{COLLECTION}/{RKEY}", f.base());

    let req = Request::builder()
        .uri(&path)
        .method("DELETE")
        .header("sec-fetch-site", "same-origin")
        .header("cookie", format!("atproto_pds_portal={}", f.cookie))
        .body(Body::empty())
        .unwrap();
    f.app.clone().oneshot(req).await.unwrap();

    let (_, body, _) = f.get(&format!("{}/{COLLECTION}", f.base())).await;
    assert!(
        !body.contains(RKEY),
        "DELETE did not remove the space record"
    );
}

/// A CID in the collection position is a blob here too.
#[tokio::test(flavor = "multi_thread")]
async fn a_cid_in_a_space_path_is_treated_as_a_blob() {
    let f = fixture().await;
    let cid = "bafkreigcsk44torjvfr6rvmixv23vsmp2ey4c6z2yftuqecmqgvsyk4uye";

    let (_, _, location) = f.get(&format!("{}/{cid}", f.base())).await;

    let location = location.expect("a CID should route to the blob endpoint");
    assert!(
        location.contains("com.atproto.sync.getBlob"),
        "a CID in a space path was not served as a blob: {location}"
    );
}

/// A malformed space in the URL is refused rather than served as empty.
#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_space_uri_is_refused() {
    let f = fixture().await;

    let (status, _, _) = f
        .get("/account/repository/space/not-a-did/app.bsky.group/default")
        .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a space URI with no DID rendered as though it were a real space"
    );
}

/// Space browsing requires a session, like the rest of the portal.
#[tokio::test(flavor = "multi_thread")]
async fn space_browsing_requires_a_session() {
    let f = fixture().await;
    let base = f.base();

    for path in [
        base.clone(),
        format!("{base}/{COLLECTION}"),
        format!("{base}/{COLLECTION}/{RKEY}"),
    ] {
        let req = Request::builder()
            .uri(&path)
            .header("sec-fetch-site", "same-origin")
            .header("cookie", "atproto_pds_portal=not-a-real-session")
            .body(Body::empty())
            .unwrap();
        let resp = f.app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.headers().get("location").and_then(|v| v.to_str().ok()),
            Some("/account/signin"),
            "{path} served something to a request with no session"
        );
    }
}

/// A space this account does not belong to is refused, not browsed.
///
/// The URL is guessable and nothing above the browser stops it: the XRPC path
/// authorises space writes with OAuth scopes, which a portal session does not
/// carry, and the writer checks only that the space is not deleted.
#[tokio::test(flavor = "multi_thread")]
async fn a_space_the_account_does_not_belong_to_is_refused() {
    let f = fixture().await;
    let stranger = format!(
        "/account/repository/space/{}/{SPACE_TYPE}/{SPACE_KEY}",
        urlenc("did:plc:someoneelsesspace0000000000")
    );

    for path in [
        stranger.clone(),
        format!("{stranger}/{COLLECTION}"),
        format!("{stranger}/{COLLECTION}/{RKEY}"),
    ] {
        let (status, _, _) = f.get(&path).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{path} was browsable by a non-member"
        );
    }
}

/// A non-member cannot write into someone else's space by guessing the URL.
///
/// The record would land in the caller's own store and sync nowhere, but it
/// would be a real record in a space they have no claim to.
#[tokio::test(flavor = "multi_thread")]
async fn a_non_member_cannot_write_to_a_space() {
    let f = fixture().await;
    let path = format!(
        "/account/repository/space/{}/{SPACE_TYPE}/{SPACE_KEY}/{COLLECTION}/{RKEY}",
        urlenc("did:plc:someoneelsesspace0000000000")
    );

    let req = Request::builder()
        .uri(&path)
        .method("POST")
        .header("sec-fetch-site", "same-origin")
        .header("cookie", format!("atproto_pds_portal={}", f.cookie))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "value={}",
            urlencode_form(r#"{"$type":"app.bsky.feed.post","text":"intruder"}"#)
        )))
        .unwrap();
    let resp = f.app.clone().oneshot(req).await.unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a non-member wrote a record into another account's space"
    );
}

/// The same guard covers deletes.
#[tokio::test(flavor = "multi_thread")]
async fn a_non_member_cannot_delete_from_a_space() {
    let f = fixture().await;
    let path = format!(
        "/account/repository/space/{}/{SPACE_TYPE}/{SPACE_KEY}/{COLLECTION}/{RKEY}",
        urlenc("did:plc:someoneelsesspace0000000000")
    );

    let req = Request::builder()
        .uri(&path)
        .method("DELETE")
        .header("sec-fetch-site", "same-origin")
        .header("cookie", format!("atproto_pds_portal={}", f.cookie))
        .body(Body::empty())
        .unwrap();
    let resp = f.app.clone().oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// Percent-encode a path segment, matching the browser's own encoding.
fn urlenc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Percent-encode a form value.
fn urlencode_form(s: &str) -> String {
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
