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
use atproto_pds::actor_store::sql::SqlActorStore;
use atproto_pds::blob;
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

    let (status, body, _) = get(&app, &cookie, "/account/repository").await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("/account/repository/public/"),
        "no link to public records"
    );
    assert!(body.contains("Spaces"), "spaces are not offered");
}

/// A collection holding records is listed, and links to it.
#[tokio::test(flavor = "multi_thread")]
async fn collections_are_listed() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;

    let (status, body, _) = get(&app, &cookie, "/account/repository/public/").await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(COLLECTION),
        "the collection holding a record was not listed"
    );
    assert!(
        body.contains(&format!("/account/repository/public/{COLLECTION}")),
        "the collection does not link to its records"
    );
}

/// Records in a collection are listed by rkey.
#[tokio::test(flavor = "multi_thread")]
async fn records_are_listed() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;

    let (status, body, _) = get(
        &app,
        &cookie,
        &format!("/account/repository/public/{COLLECTION}"),
    )
    .await;

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
        &format!("/account/repository/public/{COLLECTION}/{RKEY}"),
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
        &format!("/account/repository/public/{COLLECTION}/{RKEY}"),
        &format!("value={}", urlencode(&edited)),
    )
    .await;

    assert_eq!(
        location.as_deref(),
        Some(format!("/account/repository/public/{COLLECTION}/{RKEY}?msg=saved").as_str()),
        "the edit was not accepted"
    );

    let (_, body, _) = get(
        &app,
        &cookie,
        &format!("/account/repository/public/{COLLECTION}/{RKEY}"),
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
        &format!("/account/repository/public/{COLLECTION}/{RKEY}"),
        "value=not+json+at+all",
    )
    .await;

    assert_eq!(
        location.as_deref(),
        Some(
            format!(
                "/account/repository/public/{COLLECTION}/{RKEY}?msg=err-that-is-not-valid-json"
            )
            .as_str()
        )
    );

    let (_, body, _) = get(
        &app,
        &cookie,
        &format!("/account/repository/public/{COLLECTION}/{RKEY}"),
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
        &format!("/account/repository/public/{COLLECTION}/{RKEY}"),
        "_method=delete",
    )
    .await;

    assert_eq!(
        location.as_deref(),
        Some(format!("/account/repository/public/{COLLECTION}?msg=deleted").as_str())
    );

    let (_, body, _) = get(
        &app,
        &cookie,
        &format!("/account/repository/public/{COLLECTION}"),
    )
    .await;
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
        .uri(format!("/account/repository/public/{COLLECTION}/{RKEY}"))
        .method("DELETE")
        .header("sec-fetch-site", "same-origin")
        .header("cookie", format!("atproto_pds_portal={cookie}"))
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(req).await.unwrap();

    let (_, body, _) = get(
        &app,
        &cookie,
        &format!("/account/repository/public/{COLLECTION}"),
    )
    .await;
    assert!(!body.contains(RKEY), "DELETE did not remove the record");
}

/// A CID in the collection position is served as a blob, not looked up as a
/// collection. This is the one ambiguity in the URL scheme.
#[tokio::test(flavor = "multi_thread")]
async fn a_cid_in_the_collection_position_is_treated_as_a_blob() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;
    let cid = "bafkreigcsk44torjvfr6rvmixv23vsmp2ey4c6z2yftuqecmqgvsyk4uye";

    let (_, _, location) = get(&app, &cookie, &format!("/account/repository/public/{cid}")).await;

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
        "/account/repository",
        "/account/repository/public/",
        &format!("/account/repository/public/{COLLECTION}"),
        &format!("/account/repository/public/{COLLECTION}/{RKEY}"),
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

/// Every portal link the browser renders must resolve.
///
/// Three breadcrumbs pointed at a collection listing with a trailing slash --
/// `/account/repository/public/app.bsky.feed.post/` -- and axum treats that as
/// a different path from the route, so following one 404ed. The pages that
/// *contained* the links all rendered fine, which is why the existing tests
/// passed: they assert what a page says, never that what it points at exists.
///
/// So this follows them. Anything reachable from the browser has to answer --
/// which now includes the section nav, so a section named on every page but
/// mounted at a path nobody routed fails here rather than in a browser.
#[tokio::test(flavor = "multi_thread")]
async fn every_link_the_browser_renders_resolves() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;

    let pages = [
        "/account".to_string(),
        "/account/sessions".to_string(),
        "/account/delegation".to_string(),
        "/account/repository".to_string(),
        "/account/repository/public/".to_string(),
        format!("/account/repository/public/{COLLECTION}"),
        format!("/account/repository/public/{COLLECTION}/{RKEY}"),
    ];

    let mut checked = 0;
    for page in &pages {
        let (status, body, _) = get(&app, &cookie, page).await;
        assert_eq!(status, StatusCode::OK, "{page} did not render");

        for href in hrefs(&body) {
            // `/xrpc/...` blob links are followed by their own tests; this one
            // is about the portal's own pages.
            if !href.starts_with("/account") {
                continue;
            }
            let (status, _, location) = get(&app, &cookie, &href).await;
            assert_ne!(
                status,
                StatusCode::NOT_FOUND,
                "{page} links to {href}, which does not resolve"
            );
            // A link that bounces to sign-in is a link the session cannot
            // follow, which is the same dead end from the holder's side.
            assert_ne!(
                location.as_deref(),
                Some("/account/signin"),
                "{page} links to {href}, which rejects the session that rendered it"
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 20,
        "only {checked} links were followed; the crawl is not covering the pages"
    );
}

/// Every section names every other one, on every page.
///
/// The property that makes this a navigated set rather than four pages that
/// happen to exist: no section is reachable only by knowing its URL. Asserting
/// on the rendered pages rather than on `Section::ALL`, because a section can
/// be in that table and still be missing from a page that builds its own
/// header.
#[tokio::test(flavor = "multi_thread")]
async fn every_section_carries_the_nav() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;

    let sections = [
        "/account",
        "/account/sessions",
        "/account/repository",
        "/account/delegation",
    ];

    for page in sections {
        let (status, body, _) = get(&app, &cookie, page).await;
        assert_eq!(status, StatusCode::OK, "{page} did not render");
        for label in ["Settings", "Access", "Repository", "Delegation"] {
            assert!(body.contains(label), "{page} does not name {label}");
        }
        for other in sections {
            if other == page {
                continue;
            }
            assert!(
                body.contains(&format!(r#"href="{other}""#)),
                "{page} does not link {other}"
            );
        }
    }
}

/// A server that has not enabled delegation says so, in as many words.
///
/// This harness leaves `PDS_DELEGATION_ENABLED` off, which is the default, so
/// what it sees is what most operators see. A section about letting other
/// identities act as you is the last place to leave a reader unsure whether it
/// is switched on, and an empty table under a plausible heading reads as a
/// feature with no entries.
///
/// The section's behaviour when it *is* enabled belongs to
/// `tests/portal_delegation.rs`, which builds a server that meets every
/// precondition.
#[tokio::test(flavor = "multi_thread")]
async fn delegation_says_when_it_is_not_available() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;

    let (status, body, _) = get(&app, &cookie, "/account/delegation").await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Not available on this server"),
        "the page does not say delegation is off"
    );
    assert!(
        body.contains("has not enabled account delegation"),
        "the page does not name the obstacle"
    );
    assert!(
        body.contains("sign in as themselves and act as this account"),
        "the page does not say what delegation would be"
    );
    assert!(
        !body.contains("Add delegate"),
        "a server that cannot delegate offered the control anyway"
    );
}

/// App passwords, OAuth sessions and revocation live on Access, not Settings.
#[tokio::test(flavor = "multi_thread")]
async fn access_holds_the_credentials_and_settings_does_not() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;
    // The revoke control only exists next to a row, so there has to be one.
    post(&app, &cookie, "/account/app-passwords", "name=phone").await;

    let (_, access, _) = get(&app, &cookie, "/account/sessions").await;
    for control in [
        r#"action="/account/app-passwords""#,
        r#"action="/account/app-passwords/revoke""#,
        r#"action="/account/signout-everywhere""#,
        "OAuth sessions",
    ] {
        assert!(access.contains(control), "Access is missing {control}");
    }

    let (_, settings, _) = get(&app, &cookie, "/account").await;
    for control in [
        r#"action="/account/app-passwords""#,
        r#"action="/account/signout-everywhere""#,
    ] {
        assert!(
            !settings.contains(control),
            "Settings still carries {control}"
        );
    }
    // And what Settings does keep.
    for control in [
        r#"action="/account/email""#,
        r#"action="/account/handle""#,
        r#"action="/account/password""#,
    ] {
        assert!(settings.contains(control), "Settings is missing {control}");
    }
}

/// A freshly minted app password is shown once, on the page that minted it.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_app_password_lands_on_access() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;

    let location = post(&app, &cookie, "/account/app-passwords", "name=phone").await;
    assert_eq!(
        location.as_deref(),
        Some("/account/sessions?msg=app-password-created"),
        "creating an app password did not land on Access"
    );

    let (_, body, _) = get(&app, &cookie, "/account/sessions").await;
    assert!(
        body.contains("Your new app password"),
        "the secret was not shown"
    );
    assert!(body.contains("phone"), "the app password was not listed");

    // Exactly once: a reload must not repeat a live credential.
    let (_, again, _) = get(&app, &cookie, "/account/sessions").await;
    assert!(
        !again.contains("Your new app password"),
        "the secret survived being shown"
    );
    assert!(
        again.contains("phone"),
        "the app password stopped being listed"
    );
}

/// The Repository index lists the blobs a public record references.
///
/// Through the same enumeration `com.atproto.sync.listBlobs` serves, so what
/// the holder is shown here is what the network can fetch. Asserting both
/// directions: an uploaded-but-unreferenced blob is not public and must not be
/// listed, which is the property a naive "every CID in `repo_blob`" listing
/// would break.
#[tokio::test(flavor = "multi_thread")]
async fn the_index_lists_publicly_referenced_blobs_only() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;

    let store = SqlActorStore::open(manager.data_dir(), DID)
        .await
        .expect("actor store");
    let referenced = blob::put_blob(&store, b"referenced bytes", "image/png", 1024)
        .await
        .expect("referenced blob");
    let orphan = blob::put_blob(&store, b"nothing points here", "image/png", 1024)
        .await
        .expect("orphan blob");

    // A record carrying the blob envelope is what makes the first one public;
    // the writer records the reference as part of the write.
    writer
        .apply_writes(
            DID,
            vec![WriteOp {
                action: WriteAction::Create,
                collection: COLLECTION.to_string(),
                rkey: "3kaaaaaaaaaa3".to_string(),
                value: Some(serde_json::json!({
                    "$type": COLLECTION,
                    "text": "with an image",
                    "createdAt": "2026-08-05T00:00:00Z",
                    "image": serde_json::to_value(&referenced).unwrap(),
                })),
                swap_record: None,
            }],
        )
        .await
        .expect("record referencing the blob");

    let (status, body, _) = get(&app, &cookie, "/account/repository").await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(&referenced.inner.ref_.link),
        "a publicly referenced blob was not listed"
    );
    assert!(
        !body.contains(&orphan.inner.ref_.link),
        "an unreferenced blob was listed as public"
    );
    assert!(
        body.contains("com.atproto.sync.getBlob"),
        "the listed blob does not link to its bytes"
    );
}

/// `/browse/*` is gone rather than redirected. Single user, and the URLs were
/// never load-bearing -- a redirect would be a second name for every page.
#[tokio::test(flavor = "multi_thread")]
async fn the_old_browse_paths_are_gone() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;

    for path in [
        "/browse/",
        "/browse/public/",
        &format!("/browse/public/{COLLECTION}"),
        &format!("/browse/public/{COLLECTION}/{RKEY}"),
    ] {
        let (status, _, _) = get(&app, &cookie, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path} still answers");
    }
}

/// Pull the `href` values out of rendered HTML.
fn hrefs(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(i) = rest.find("href=\"") {
        rest = &rest[i + 6..];
        if let Some(end) = rest.find('"') {
            out.push(rest[..end].replace("&amp;", "&"));
            rest = &rest[end..];
        }
    }
    out
}

/// One application can be cut off without ending every other application's
/// access.
///
/// Until this existed, the Access page listed OAuth grants and offered exactly
/// one control over them: sign out everywhere. An account holder who wanted a
/// single application gone had to end all of them and sign back in everywhere
/// else.
#[tokio::test(flavor = "multi_thread")]
async fn one_oauth_grant_can_be_revoked_without_touching_the_others() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;
    let pool = manager.account_pool();

    for client in [
        "https://one.example/client-metadata.json",
        "https://two.example/client-metadata.json",
    ] {
        sqlx::query(
            "INSERT INTO oauth_refresh (jti, did, client_id, dpop_jkt, scope, issued_at)
             VALUES (?, ?, ?, 'thumb', 'atproto', '2026-08-13T00:00:00Z')",
        )
        .bind(format!("jti-{client}"))
        .bind(DID)
        .bind(client)
        .execute(pool.as_sqlite())
        .await
        .expect("seed grant");
    }

    let (_, listed, _) = get(&app, &cookie, "/account/sessions").await;
    assert!(
        listed.contains("https://one.example/client-metadata.json"),
        "the grant should be listed before it is revoked: {listed}"
    );

    let location = post(
        &app,
        &cookie,
        "/account/sessions/revoke",
        "client_id=https%3A%2F%2Fone.example%2Fclient-metadata.json",
    )
    .await;
    assert_eq!(
        location.as_deref(),
        Some("/account/sessions?msg=grant-revoked")
    );

    let (_, after, _) = get(&app, &cookie, "/account/sessions").await;
    assert!(
        !after.contains("https://one.example/client-metadata.json"),
        "the revoked grant should be gone: {after}"
    );
    assert!(
        after.contains("https://two.example/client-metadata.json"),
        "the other application should be untouched: {after}"
    );
    // The copy has to be honest about the 15-minute tail, since the access
    // token already issued is a stateless JWT with no row to delete.
    assert!(
        after.contains("15 minutes"),
        "the page should say when access actually ends: {after}"
    );
}

/// Revoking something that is not there is the account holder's mistake to
/// read, not a 500 — a double-clicked button lands here.
#[tokio::test(flavor = "multi_thread")]
async fn revoking_a_grant_that_is_not_there_says_so() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;
    let location = post(
        &app,
        &cookie,
        "/account/sessions/revoke",
        "client_id=https%3A%2F%2Fnobody.example%2Fc.json",
    )
    .await;
    assert_eq!(
        location.as_deref(),
        Some("/account/sessions?msg=err-nothing-to-revoke")
    );
}

/// Collections are grouped by the domain that publishes them, and each row
/// shows only the part that differs.
///
/// A repository with a few dozen collections is a wall of reverse-DNS in which
/// `app.bsky.feed.post` and `app.bsky.graph.follow` look no more related than
/// `app.bsky.feed.post` and `blue.badge.collection`. The publisher is the thing
/// a person scans for.
#[tokio::test(flavor = "multi_thread")]
async fn collections_are_grouped_by_publishing_domain() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;

    for collection in [
        "app.bsky.feed.post",
        "app.bsky.graph.follow",
        "blue.badge.collection",
    ] {
        writer
            .apply_writes(
                DID,
                vec![WriteOp {
                    action: WriteAction::Create,
                    collection: collection.to_string(),
                    rkey: "3kaaaaaaaaaa9".to_string(),
                    value: Some(serde_json::json!({"$type": collection, "text": "x"})),
                    swap_record: None,
                }],
            )
            .await
            .expect("seed record");
    }

    let (status, body, _) = get(&app, &cookie, "/account/repository/public/").await;
    assert_eq!(status, StatusCode::OK);

    // One badge per publisher, not one per collection: the two app.bsky
    // collections share a group, so there are two badges for three rows.
    let badges = body.matches(r#"<span class="badge"><img"#).count();
    assert_eq!(badges, 2, "expected one badge per domain group: {body}");
    // Rows inside a group are indented under it rather than repeating it.
    assert!(
        body.contains(r#"<span class="badge-gap">"#),
        "the second row of a group should be indented: {body}"
    );
    // The shared authority is dimmed and the distinguishing tail is not.
    assert!(
        body.contains(r#"<span class="dim">app.bsky.feed.</span>post"#),
        "the row should dim everything but the last segment: {body}"
    );
    // Grouping is presentation only — every collection is still linked.
    for collection in [
        "app.bsky.feed.post",
        "app.bsky.graph.follow",
        "blue.badge.collection",
    ] {
        assert!(
            body.contains(&format!("/account/repository/public/{collection}")),
            "{collection} should still be reachable: {body}"
        );
    }
}

/// The icon route serves an image for any NSID, and never a broken one.
///
/// An authority with no reachable favicon still gets a drawn stand-in, so the
/// listing's icon column is total and the page shows no broken images. The
/// fetch itself is not exercised here — there is no network in this test — which
/// is the point: the fallback is what runs when a fetch cannot happen.
#[tokio::test(flavor = "multi_thread")]
async fn the_icon_route_always_returns_an_image() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;

    let req = Request::builder()
        .uri("/account/repository/icon/app.bsky.feed.post")
        .header("sec-fetch-site", "same-origin")
        .header("cookie", format!("atproto_pds_portal={cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        content_type.starts_with("image/"),
        "an icon route must serve an image, got {content_type}"
    );
    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(!body.is_empty(), "the icon should have bytes");
}

/// Icons are for the account, not the network: they say which authorities
/// appear in someone's repository.
#[tokio::test(flavor = "multi_thread")]
async fn the_icon_route_requires_a_session() {
    let (app, _manager, _writer, _tmp) = build_app().await;
    let req = Request::builder()
        .uri("/account/repository/icon/app.bsky.feed.post")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// The listing points at this server for its icons, never at the authority.
#[tokio::test(flavor = "multi_thread")]
async fn the_listing_never_hot_links_an_authority() {
    let (app, manager, writer, _tmp) = build_app().await;
    let cookie = signed_in_with_a_record(&manager, &writer).await;
    let (_, body, _) = get(&app, &cookie, "/account/repository/public/").await;
    assert!(
        body.contains(r#"src="/account/repository/icon/"#),
        "the icon should be proxied: {body}"
    );
    assert!(
        !body.contains(r#"src="https://"#),
        "no image on a signed-in page may be fetched from another origin: {body}"
    );
}
