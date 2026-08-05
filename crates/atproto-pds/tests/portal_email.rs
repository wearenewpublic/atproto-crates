//! Integration tests for the portal's email-change flow.
//!
//! The portal had no test coverage at all, and this is the page that owns the
//! account's recovery route: the address here is where password reset and
//! account recovery are sent, so what may change it, and what counts as having
//! proved it, decide who can take the account.
//!
//! The flow these pin is one-step. A change carries only the destination, takes
//! effect immediately, lands unconfirmed, and mails the code that proves it to
//! the new address. What replaced it required a code mailed to the *current*
//! address, which put the field on screen before any code existed and sent the
//! one you asked for to the mailbox you were leaving.

use atproto_identity::key::KeyType;
use atproto_pds::account::{
    AccountDirectory, AccountManager, CreateAccountParams, email_token, portal,
};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

const DID: &str = "did:plc:portalemailfixture000000";
const HANDLE: &str = "holder.test.example";
const OLD_EMAIL: &str = "old@example.test";
const NEW_EMAIL: &str = "new@example.test";

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
    .with_writer(writer)
    .with_service_handle_domains(vec!["test.example".to_string()]);
    (build_router(state), manager, tmp)
}

/// An account holding `email`, confirmed, plus a portal cookie for it.
async fn signed_in(
    manager: &AccountManager,
    did: &str,
    handle: &str,
    email: &str,
    confirmed: bool,
) -> String {
    manager
        .create_account(CreateAccountParams::new(did, handle, "pw").with_email(Some(email)))
        .await
        .expect("fixture account should be created");
    if confirmed {
        manager
            .set_email_confirmed_at(did, Some(&chrono::Utc::now().to_rfc3339()))
            .await
            .expect("fixture address should confirm");
    }
    let cookie = format!("cookie-for-{did}");
    portal::create_session(&manager.account_pool(), &cookie, did, 0, None)
        .await
        .expect("fixture session should be created");
    cookie
}

/// POST a form to the portal as a signed-in holder. Returns (status, Location).
async fn post(
    app: &axum::Router,
    cookie: &str,
    path: &str,
    body: &str,
) -> (StatusCode, Option<String>) {
    let req = Request::builder()
        .uri(path)
        .method("POST")
        .header("sec-fetch-site", "same-origin")
        .header("cookie", format!("atproto_pds_portal={cookie}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (status, location)
}

/// The rendered account page, which reports the address and whether it is
/// confirmed. Asserting through this rather than the database keeps these
/// tests on what the account holder can actually see.
async fn account_page(app: &axum::Router, cookie: &str) -> String {
    let req = Request::builder()
        .uri("/account")
        .header("sec-fetch-site", "same-origin")
        .header("cookie", format!("atproto_pds_portal={cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
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

/// The change carries only the destination.
///
/// The form used to demand a code mailed to the address being left behind. A
/// holder who had lost access to that mailbox — the ordinary reason to change
/// an address — could not get past it.
#[tokio::test(flavor = "multi_thread")]
async fn changing_email_asks_for_no_code_from_the_old_address() {
    let (app, manager, _tmp) = build_app().await;
    let cookie = signed_in(&manager, DID, HANDLE, OLD_EMAIL, true).await;

    let (status, location) = post(
        &app,
        &cookie,
        "/account/email",
        &format!("email={}", NEW_EMAIL.replace('@', "%40")),
    )
    .await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location.as_deref(), Some("/account?msg=email-changed"));

    let page = account_page(&app, &cookie).await;
    assert!(
        page.contains(NEW_EMAIL),
        "the account page does not show the new address"
    );
    assert!(
        !page.contains(OLD_EMAIL),
        "the account page still shows the old address"
    );
}

/// The new address arrives unproved.
///
/// Inheriting the outgoing address's confirmed standing would hand an
/// unverified mailbox a working recovery route.
#[tokio::test(flavor = "multi_thread")]
async fn the_new_address_lands_unconfirmed() {
    let (app, manager, _tmp) = build_app().await;
    let cookie = signed_in(&manager, DID, HANDLE, OLD_EMAIL, true).await;

    post(
        &app,
        &cookie,
        "/account/email",
        &format!("email={}", NEW_EMAIL.replace('@', "%40")),
    )
    .await;

    let page = account_page(&app, &cookie).await;
    assert!(
        page.contains("not confirmed"),
        "a freshly changed address is reported as confirmed"
    );
}

/// Codes issued against the old address die with it.
///
/// A confirmation code proves control of the mailbox it was mailed to. Once the
/// account moves elsewhere, redeeming one would mark the *new* address
/// confirmed on the strength of access to an address it has nothing to do with.
#[tokio::test(flavor = "multi_thread")]
async fn a_code_for_the_old_address_stops_working() {
    let (app, manager, _tmp) = build_app().await;
    let cookie = signed_in(&manager, DID, HANDLE, OLD_EMAIL, false).await;

    // Outstanding against the address the account is about to leave.
    let stale = email_token::generate_code();
    let expires = (chrono::Utc::now() + chrono::Duration::seconds(3600)).to_rfc3339();
    email_token::insert(
        &manager.account_pool(),
        &stale,
        DID,
        email_token::PURPOSE_CONFIRM_EMAIL,
        &expires,
        None,
    )
    .await
    .expect("fixture token should insert");

    post(
        &app,
        &cookie,
        "/account/email",
        &format!("email={}", NEW_EMAIL.replace('@', "%40")),
    )
    .await;

    let (_, location) = post(
        &app,
        &cookie,
        "/account/email/verify",
        &format!("token={stale}"),
    )
    .await;
    assert_eq!(
        location.as_deref(),
        Some("/account?msg=err-that-code-is-not-valid-or-has-expired"),
        "a code mailed to the previous address still confirmed the new one"
    );

    let page = account_page(&app, &cookie).await;
    assert!(
        page.contains("not confirmed"),
        "the address was confirmed by a code issued against a different one"
    );
}

/// One account per address.
///
/// `account.email` is UNIQUE, and the collision has to read as a collision. It
/// surfaced as an opaque storage fault, which told the holder their server was
/// broken when the address was simply taken.
#[tokio::test(flavor = "multi_thread")]
async fn an_address_another_account_holds_is_refused() {
    let (app, manager, _tmp) = build_app().await;
    let cookie = signed_in(&manager, DID, HANDLE, OLD_EMAIL, true).await;
    signed_in(
        &manager,
        "did:plc:portalemailother00000000000",
        "other.test.example",
        NEW_EMAIL,
        true,
    )
    .await;

    let (status, location) = post(
        &app,
        &cookie,
        "/account/email",
        &format!("email={}", NEW_EMAIL.replace('@', "%40")),
    )
    .await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location.as_deref(),
        Some("/account?msg=err-that-address-is-already-in-use-on-this-server"),
        "a taken address was not reported as taken"
    );

    // The refusal must not have cost the holder anything.
    let page = account_page(&app, &cookie).await;
    assert!(
        page.contains(OLD_EMAIL),
        "a refused change moved the address anyway"
    );
    assert!(
        !page.contains("not confirmed"),
        "a refused change cleared the confirmation on the address that stayed"
    );
}

/// Re-submitting the address already on file changes nothing.
///
/// Falling through would clear the confirmation flag on an address that is not
/// moving, spending a proved recovery route for nothing.
#[tokio::test(flavor = "multi_thread")]
async fn resubmitting_the_current_address_keeps_its_confirmation() {
    let (app, manager, _tmp) = build_app().await;
    let cookie = signed_in(&manager, DID, HANDLE, OLD_EMAIL, true).await;

    let (_, location) = post(
        &app,
        &cookie,
        "/account/email",
        &format!("email={}", OLD_EMAIL.replace('@', "%40")),
    )
    .await;
    assert_eq!(
        location.as_deref(),
        Some("/account?msg=err-that-is-already-the-address-on-file")
    );

    let page = account_page(&app, &cookie).await;
    assert!(
        !page.contains("not confirmed"),
        "re-submitting the current address dropped its confirmation"
    );
}
