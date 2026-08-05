//! Integration tests for changing a handle from the portal.
//!
//! The portal delegates to the same `do_update_handle` that
//! `com.atproto.identity.updateHandle` runs, so what is worth pinning here is
//! not the PLC mechanics — those are the XRPC handler's — but the two things
//! the portal owns: that a refusal is reported in terms an account holder can
//! act on, and that a request which should never reach PLC does not.
//!
//! As in `identity_endpoints`, the harness has no PLC directory. A handle that
//! passes validation therefore fails at the PLC call, which is exactly what
//! makes the difference observable: a validation refusal and a PLC failure
//! carry different messages, so a test can tell how far a request travelled.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams, portal};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

const DID: &str = "did:plc:portalhandlefixture00000000";
const HANDLE: &str = "holder.pds.test";
const SERVICE_DOMAIN: &str = "pds.test";

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
        "did:web:pds.test".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer)
    .with_service_handle_domains(vec![SERVICE_DOMAIN.to_string()]);
    (build_router(state), manager, tmp)
}

async fn signed_in(manager: &AccountManager, did: &str, handle: &str) -> String {
    manager
        .create_account(CreateAccountParams::new(did, handle, "pw"))
        .await
        .expect("fixture account should be created");
    let cookie = format!("cookie-for-{did}");
    portal::create_session(&manager.account_pool(), &cookie, did, 0, None)
        .await
        .expect("fixture session should be created");
    cookie
}

/// Submit the handle form. Returns the `Location` the portal redirected to.
async fn change_handle(app: &axum::Router, cookie: &str, handle: &str) -> Option<String> {
    let req = Request::builder()
        .uri("/account/handle")
        .method("POST")
        .header("sec-fetch-site", "same-origin")
        .header("cookie", format!("atproto_pds_portal={cookie}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(format!("handle={}", urlencoding_lite(handle))))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    resp.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Enough percent-encoding for the values these tests submit.
fn urlencoding_lite(s: &str) -> String {
    s.replace('%', "%25")
        .replace(' ', "%20")
        .replace('&', "%26")
        .replace('!', "%21")
}

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

/// A malformed handle is refused on its own terms.
#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_handle_is_refused() {
    let (app, manager, _tmp) = build_app().await;
    let cookie = signed_in(&manager, DID, HANDLE).await;

    let location = change_handle(&app, &cookie, "not a handle!").await;

    assert_eq!(
        location.as_deref(),
        Some("/account?msg=err-that-is-not-a-valid-handle")
    );
}

/// A handle another account already holds is reported as taken.
///
/// The check is local and happens before the ownership proof, so no network
/// call is spent on a handle that could not be claimed either way.
#[tokio::test(flavor = "multi_thread")]
async fn a_handle_another_account_holds_is_refused() {
    let (app, manager, _tmp) = build_app().await;
    let cookie = signed_in(&manager, DID, HANDLE).await;
    signed_in(
        &manager,
        "did:plc:portalhandleother0000000000",
        "taken.pds.test",
    )
    .await;

    let location = change_handle(&app, &cookie, "taken.pds.test").await;

    assert_eq!(
        location.as_deref(),
        Some("/account?msg=err-that-handle-is-already-taken")
    );
}

/// Re-submitting the handle already in force does nothing, and costs nothing.
///
/// Handles are case-insensitive, so this is the same handle. Falling through
/// would sign a PLC operation and append an entry to the account's permanent
/// audit log to change it to what it already is.
#[tokio::test(flavor = "multi_thread")]
async fn resubmitting_the_current_handle_is_a_no_op() {
    let (app, manager, _tmp) = build_app().await;
    let cookie = signed_in(&manager, DID, HANDLE).await;

    let location = change_handle(&app, &cookie, "HOLDER.PDS.TEST").await;

    assert_eq!(
        location.as_deref(),
        Some("/account?msg=err-that-is-already-your-handle"),
        "a differently-cased copy of the current handle was treated as a change"
    );
}

/// A domain this server does not issue must prove itself first.
///
/// `.test` never resolves publicly, so the proof fails whether or not the
/// machine running this has a network.
#[tokio::test(flavor = "multi_thread")]
async fn an_unproven_external_domain_is_refused() {
    let (app, manager, _tmp) = build_app().await;
    let cookie = signed_in(&manager, DID, HANDLE).await;

    let location = change_handle(&app, &cookie, "someone.elsewhere.test").await;

    assert_eq!(
        location.as_deref(),
        Some(
            "/account?msg=err-that-domain-does-not-point-at-your-did-yet-see-using-a-domain-you-own-below"
        ),
        "an unproven external domain was not reported as unproven"
    );
}

/// A valid handle on this server's own domain gets past validation.
///
/// It then fails at PLC, which this harness does not run — and that is the
/// assertion. A validation refusal and a PLC failure carry different messages,
/// so the generic one is proof the request travelled the whole way rather than
/// being turned back at the door.
#[tokio::test(flavor = "multi_thread")]
async fn a_valid_service_handle_reaches_plc() {
    let (app, manager, _tmp) = build_app().await;
    let cookie = signed_in(&manager, DID, HANDLE).await;

    let location = change_handle(&app, &cookie, "renamed.pds.test").await;

    assert_eq!(
        location.as_deref(),
        Some("/account?msg=err-the-handle-could-not-be-changed-check-the-server-logs"),
        "a valid service-domain handle was refused before reaching PLC"
    );
}

/// The page carries what someone needs to point their own domain here.
///
/// The DID is not something an account holder can be expected to have to hand,
/// and the proof has to be in place *before* submitting — so instructions that
/// appeared only after a refusal would arrive a step too late.
#[tokio::test(flavor = "multi_thread")]
async fn the_page_shows_how_to_claim_your_own_domain() {
    let (app, manager, _tmp) = build_app().await;
    let cookie = signed_in(&manager, DID, HANDLE).await;

    let page = account_page(&app, &cookie).await;

    assert!(
        page.contains("_atproto."),
        "the page does not name the DNS record to create"
    );
    assert!(
        page.contains(".well-known/atproto-did"),
        "the page does not offer the HTTPS route"
    );
    assert!(
        page.contains(DID),
        "the page does not show the DID the record has to contain"
    );
    assert!(
        page.contains(SERVICE_DOMAIN),
        "the page does not say which domain this server issues handles under"
    );
}
