//! Integration tests for the portal's Delegation section.
//!
//! Two servers are built here, and the difference between them is the whole
//! point. One has delegation resolved as available; the other does not,
//! because the harness's `did:web:pds.test` origin and default key are exactly
//! the configuration an operator can trip over.
//!
//! What is worth pinning is not the storage — `account::delegation` has its own
//! tests — but the things the portal owns: that a server which cannot do this
//! says so instead of rendering an empty table, that every mutating route
//! refuses a request that did not come from the portal, and that removing a
//! delegate takes their sessions with it.

use atproto_identity::key::{KeyType, generate_key};
use atproto_pds::account::{
    AccountDirectory, AccountManager, CreateAccountParams, delegation, portal,
};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::oauth::state::RefreshHandle;
use atproto_pds::repo::{RepoReader, RepoWriter};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

const DID: &str = "did:plc:portaldelegationfixture0001";
const HANDLE: &str = "holder.pds.test";
const DELEGATE: &str = "did:plc:portaldelegationdelegate01";

/// A server with delegation resolved from `enabled` plus a P-256 signing key.
///
/// The service DID is `did:web:pds.test`, which yields an `https://` origin —
/// so with the flag on and a P-256 key, every precondition passes.
async fn build_app(enabled: bool) -> (axum::Router, Arc<AccountManager>, TempDir) {
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
    .with_writer(writer)
    .with_pds_signing_key(Arc::new(generate_key(KeyType::P256Private).unwrap()))
    .with_delegation_enabled(enabled);
    (build_router(state), manager, tmp)
}

async fn signed_in(manager: &AccountManager) -> String {
    manager
        .create_account(CreateAccountParams::new(DID, HANDLE, "pw"))
        .await
        .expect("fixture account");
    let cookie = "cookie-for-delegation-fixture".to_string();
    portal::create_session(&manager.account_pool(), &cookie, DID, 0, None)
        .await
        .expect("fixture session");
    cookie
}

async fn delegation_page(app: &axum::Router, cookie: &str) -> String {
    let req = Request::builder()
        .uri("/account/delegation")
        .header("sec-fetch-site", "same-origin")
        .header("cookie", format!("atproto_pds_portal={cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    body_of(resp).await
}

async fn body_of(resp: axum::response::Response) -> String {
    String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

/// POST a form to the portal and return the `Location` it redirected to.
async fn post_form(
    app: &axum::Router,
    cookie: &str,
    path: &str,
    body: &str,
    same_origin: bool,
) -> (StatusCode, Option<String>) {
    let mut builder = Request::builder()
        .uri(path)
        .method("POST")
        .header("cookie", format!("atproto_pds_portal={cookie}"))
        .header("content-type", "application/x-www-form-urlencoded");
    if same_origin {
        builder = builder.header("sec-fetch-site", "same-origin");
    } else {
        builder = builder.header("sec-fetch-site", "cross-site");
    }
    let resp = app
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (resp.status(), location)
}

/// A server that cannot do this says so, rather than rendering an empty table
/// that reads as "nobody is delegated".
#[tokio::test(flavor = "multi_thread")]
async fn an_unconfigured_server_names_the_obstacle() {
    let (app, manager, _tmp) = build_app(false).await;
    let cookie = signed_in(&manager).await;

    let page = delegation_page(&app, &cookie).await;
    assert!(
        page.contains("Not available on this server"),
        "the page did not say delegation is off: {page}"
    );
    assert!(
        page.contains("has not enabled account delegation"),
        "the page did not name the obstacle: {page}"
    );
    assert!(
        !page.contains("Add delegate"),
        "a server that cannot delegate offered the control anyway"
    );
}

/// With every precondition met, the section renders its controls and an empty
/// state that says plainly that nothing can act as this account.
#[tokio::test(flavor = "multi_thread")]
async fn a_configured_server_offers_the_controls() {
    let (app, manager, _tmp) = build_app(true).await;
    let cookie = signed_in(&manager).await;

    let page = delegation_page(&app, &cookie).await;
    assert!(page.contains("Add delegate"), "{page}");
    assert!(
        page.contains("No identity can act as this account"),
        "the empty state did not say what it means: {page}"
    );
    assert!(!page.contains("Not available on this server"), "{page}");
}

/// A delegate on the list is rendered by handle and DID, with how many live
/// sessions they hold.
#[tokio::test(flavor = "multi_thread")]
async fn a_delegate_is_listed_with_its_live_session_count() {
    let (app, manager, _tmp) = build_app(true).await;
    let cookie = signed_in(&manager).await;
    let pool = manager.account_pool();
    delegation::add(&pool, DID, DELEGATE, "friend.example.com")
        .await
        .unwrap();

    let page = delegation_page(&app, &cookie).await;
    assert!(page.contains("friend.example.com"), "{page}");
    assert!(page.contains(DELEGATE), "{page}");
    // No grants yet.
    assert!(page.contains("<td class=\"muted\">0</td>"), "{page}");
}

/// Adding refuses a handle that does not resolve. The harness has no DNS
/// resolver at all, which is the strongest form of "did not resolve".
#[tokio::test(flavor = "multi_thread")]
async fn an_unresolvable_handle_is_refused() {
    let (app, manager, _tmp) = build_app(true).await;
    let cookie = signed_in(&manager).await;

    let (_, location) = post_form(
        &app,
        &cookie,
        "/account/delegation",
        "handle=nobody.example.com",
        true,
    )
    .await;
    assert_eq!(
        location.as_deref(),
        Some("/account/delegation?msg=err-that-handle-could-not-be-verified")
    );
    assert!(
        delegation::list(&manager.account_pool(), DID)
            .await
            .unwrap()
            .is_empty()
    );
}

/// An empty handle is its own message, not a resolution failure.
#[tokio::test(flavor = "multi_thread")]
async fn an_empty_handle_says_so() {
    let (app, manager, _tmp) = build_app(true).await;
    let cookie = signed_in(&manager).await;

    let (_, location) = post_form(&app, &cookie, "/account/delegation", "handle=", true).await;
    assert_eq!(
        location.as_deref(),
        Some("/account/delegation?msg=err-enter-a-handle")
    );
}

/// A server with delegation off refuses the write too, not only the render. A
/// control that is not on the page is still a URL somebody can POST to.
#[tokio::test(flavor = "multi_thread")]
async fn adding_is_refused_when_delegation_is_off() {
    let (app, manager, _tmp) = build_app(false).await;
    let cookie = signed_in(&manager).await;

    let (_, location) = post_form(
        &app,
        &cookie,
        "/account/delegation",
        "handle=friend.example.com",
        true,
    )
    .await;
    assert_eq!(
        location.as_deref(),
        Some("/account/delegation?msg=err-delegation-is-not-available-on-this-server")
    );
}

/// Removing a delegate that is not on the list reports that, rather than
/// claiming a removal.
#[tokio::test(flavor = "multi_thread")]
async fn removing_a_stranger_reports_nothing_to_remove() {
    let (app, manager, _tmp) = build_app(true).await;
    let cookie = signed_in(&manager).await;

    let (_, location) = post_form(
        &app,
        &cookie,
        "/account/delegation/remove",
        &format!("did={DELEGATE}"),
        true,
    )
    .await;
    assert_eq!(
        location.as_deref(),
        Some("/account/delegation?msg=err-that-identity-was-not-a-delegate")
    );
}

/// Removing a delegate revokes the grants they obtained, and says so.
#[tokio::test(flavor = "multi_thread")]
async fn removing_a_delegate_revokes_the_sessions_they_obtained() {
    let (app, manager, _tmp) = build_app(true).await;
    let cookie = signed_in(&manager).await;
    let pool = manager.account_pool();
    delegation::add(&pool, DID, DELEGATE, "friend.example.com")
        .await
        .unwrap();

    // Two grants on this account: one the delegate obtained, one the holder
    // did. Only the first should go.
    let oauth = atproto_pds::oauth::state::OAuthState::sql(manager.pool().clone());
    oauth
        .register_refresh("by-delegate".to_string(), handle_for(Some(DELEGATE)))
        .await
        .unwrap();
    oauth
        .register_refresh("by-holder".to_string(), handle_for(None))
        .await
        .unwrap();

    let (_, location) = post_form(
        &app,
        &cookie,
        "/account/delegation/remove",
        &format!("did={DELEGATE}"),
        true,
    )
    .await;
    assert_eq!(
        location.as_deref(),
        Some("/account/delegation?msg=delegate-removed-with-grants")
    );

    let remaining = portal::list_oauth_grants(&pool, DID).await.unwrap();
    assert_eq!(remaining.len(), 1, "the wrong number of grants survived");
    assert_eq!(
        remaining[0].acting_did, None,
        "the holder's own grant was the one revoked"
    );
    assert!(!delegation::is_delegate(&pool, DID, DELEGATE).await.unwrap());
}

fn handle_for(acting_did: Option<&str>) -> RefreshHandle {
    RefreshHandle {
        did: DID.to_string(),
        client_id: "https://app.example/client-metadata.json".to_string(),
        dpop_jkt: "thumb".to_string(),
        scope: "atproto".to_string(),
        issued_at: chrono::Utc::now(),
        family_id: "family".to_string(),
        client_kid: None,
        grant_started_at: None,
        expires_at: None,
        acting_did: acting_did.map(str::to_string),
    }
}

/// Both mutating routes refuse a POST that did not originate here, before they
/// look at anything else.
#[tokio::test(flavor = "multi_thread")]
async fn a_cross_site_post_is_refused() {
    let (app, manager, _tmp) = build_app(true).await;
    let cookie = signed_in(&manager).await;

    for (path, body) in [
        ("/account/delegation", "handle=friend.example.com"),
        ("/account/delegation/remove", "did=did:plc:whoever"),
    ] {
        let (status, _) = post_form(&app, &cookie, path, body, false).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{path} accepted a cross-site POST"
        );
    }
}

/// Without a session there is nothing to render and nothing to change.
#[tokio::test(flavor = "multi_thread")]
async fn an_unauthenticated_request_reaches_the_sign_in_page() {
    let (app, _manager, _tmp) = build_app(true).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/account/delegation")
                .header("sec-fetch-site", "same-origin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(resp.headers().get("location").unwrap(), "/account/signin");

    let (_, location) = post_form(
        &app,
        "not-a-session",
        "/account/delegation",
        "handle=friend.example.com",
        true,
    )
    .await;
    assert_eq!(location.as_deref(), Some("/account/signin"));
}

/// The Access page names the delegate behind a grant, and leaves the holder's
/// own rows unattributed.
#[tokio::test(flavor = "multi_thread")]
async fn the_access_page_says_who_obtained_each_grant() {
    let (app, manager, _tmp) = build_app(true).await;
    let cookie = signed_in(&manager).await;
    let pool = manager.account_pool();
    delegation::add(&pool, DID, DELEGATE, "friend.example.com")
        .await
        .unwrap();

    let oauth = atproto_pds::oauth::state::OAuthState::sql(manager.pool().clone());
    oauth
        .register_refresh("by-delegate".to_string(), handle_for(Some(DELEGATE)))
        .await
        .unwrap();
    oauth
        .register_refresh("by-holder".to_string(), handle_for(None))
        .await
        .unwrap();

    let req = Request::builder()
        .uri("/account/sessions")
        .header("sec-fetch-site", "same-origin")
        .header("cookie", format!("atproto_pds_portal={cookie}"))
        .body(Body::empty())
        .unwrap();
    let page = body_of(app.clone().oneshot(req).await.unwrap()).await;

    assert!(page.contains("Acting as"), "the column is missing: {page}");
    assert!(
        page.contains("friend.example.com"),
        "the delegate was not named: {page}"
    );
    assert!(
        page.contains("&mdash;"),
        "the holder's own grant should be unattributed: {page}"
    );
}
