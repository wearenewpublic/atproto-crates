//! Per-IP rate limiting across the request surface.
//!
//! Before this, the limiter reached six call sites out of 104 routes and every
//! bucket key was derived from caller-supplied input — so a password sprayer
//! varied `identifier` for a fresh bucket per attempt, and everything else
//! (all repo writes, all of sync, `subscribeRepos`, the whole spaces
//! namespace) had no limit at all.
//!
//! These tests drive the router through `tower`'s `Service` rather than a
//! socket, so the peer address is injected as `ConnectInfo` the same way
//! `into_make_service_with_connect_info` does at runtime.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager, CreateAccountParams};
use atproto_pds::http::{HttpState, RateLimitPolicy, build_router, with_rate_limit};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use atproto_pds::security::SlidingWindowLimiter;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tower::ServiceExt;

/// Build a router with an explicit rate-limit policy.
async fn build_app(
    global: usize,
    auth: usize,
    hops: usize,
    bypass: &[&str],
) -> (axum::Router, Arc<AccountManager>, TempDir) {
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

    let window = Duration::from_secs(60);
    let policy = RateLimitPolicy::new(
        SlidingWindowLimiter::new(global, window, 1000),
        SlidingWindowLimiter::new(auth, window, 1000),
        hops,
        bypass
            .iter()
            .map(|s| s.parse::<IpAddr>().unwrap())
            .collect::<HashSet<_>>(),
    );
    let app = with_rate_limit(build_router(state), policy);
    (app, manager, tmp)
}

async fn create_account(manager: &AccountManager, did: &str, handle: &str) {
    manager
        .create_account(CreateAccountParams::new(did, handle, "pw"))
        .await
        .unwrap();
    manager.set_primary_password(did, "pw").await.unwrap();
}

/// One request from `peer`, optionally carrying an `X-Forwarded-For`.
async fn hit(app: &axum::Router, path: &str, peer: &str, xff: Option<&str>) -> StatusCode {
    let mut builder = Request::builder().uri(path);
    if let Some(v) = xff {
        builder = builder.header("x-forwarded-for", v);
    }
    let mut req = builder.body(Body::empty()).unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
    app.clone().oneshot(req).await.unwrap().status()
}

/// A path that is not `/xrpc/...`-authenticated and was previously unlimited.
const PUBLIC_PATH: &str =
    "/xrpc/com.atproto.repo.getRecord?repo=did:plc:alice&collection=x.y.z&rkey=k";

#[tokio::test(flavor = "multi_thread")]
async fn an_ordinary_read_path_is_limited_per_address() {
    // `getRecord` is one of the ~100 routes that had no limit of any kind.
    let (app, manager, _tmp) = build_app(3, 100, 0, &[]).await;
    create_account(&manager, "did:plc:alice", "alice.example").await;

    for i in 0..3 {
        let status = hit(&app, PUBLIC_PATH, "9.9.9.9:1000", None).await;
        assert_ne!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "request {i} should be within budget"
        );
    }
    assert_eq!(
        hit(&app, PUBLIC_PATH, "9.9.9.9:1000", None).await,
        StatusCode::TOO_MANY_REQUESTS,
        "the fourth request from the same address must be refused"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_addresses_get_independent_budgets() {
    // Otherwise the limit is a global outage switch rather than a per-caller
    // bound: one noisy client would lock out everyone.
    let (app, manager, _tmp) = build_app(2, 100, 0, &[]).await;
    create_account(&manager, "did:plc:alice", "alice.example").await;

    for _ in 0..2 {
        hit(&app, PUBLIC_PATH, "1.1.1.1:1000", None).await;
    }
    assert_eq!(
        hit(&app, PUBLIC_PATH, "1.1.1.1:1000", None).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_ne!(
        hit(&app, PUBLIC_PATH, "2.2.2.2:1000", None).await,
        StatusCode::TOO_MANY_REQUESTS,
        "a different address must have its own budget"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_spoofed_forwarded_header_cannot_buy_a_fresh_bucket() {
    // The whole reason `X-Forwarded-For` is off by default. If a caller could
    // set its own key, the limiter would bound nobody while appearing to work.
    let (app, manager, _tmp) = build_app(2, 100, 0, &[]).await;
    create_account(&manager, "did:plc:alice", "alice.example").await;

    for i in 0..2 {
        hit(
            &app,
            PUBLIC_PATH,
            "9.9.9.9:1000",
            Some(&format!("5.5.5.{i}")),
        )
        .await;
    }
    assert_eq!(
        hit(&app, PUBLIC_PATH, "9.9.9.9:1000", Some("5.5.5.99")).await,
        StatusCode::TOO_MANY_REQUESTS,
        "varying X-Forwarded-For must not reset the bucket when hops = 0"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn with_a_trusted_proxy_the_header_is_the_key() {
    // Behind a proxy every request shares one peer address, so without this the
    // whole deployment would share a single bucket.
    let (app, manager, _tmp) = build_app(2, 100, 1, &[]).await;
    create_account(&manager, "did:plc:alice", "alice.example").await;

    for _ in 0..2 {
        hit(&app, PUBLIC_PATH, "10.0.0.1:1000", Some("7.7.7.7")).await;
    }
    assert_eq!(
        hit(&app, PUBLIC_PATH, "10.0.0.1:1000", Some("7.7.7.7")).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_ne!(
        hit(&app, PUBLIC_PATH, "10.0.0.1:1000", Some("8.8.8.8")).await,
        StatusCode::TOO_MANY_REQUESTS,
        "a different client behind the same proxy must have its own budget"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bypassed_address_is_never_limited() {
    // A relay or an AppView pulling from this server must not be throttled by
    // a policy aimed at attackers.
    let (app, manager, _tmp) = build_app(1, 1, 0, &["3.3.3.3"]).await;
    create_account(&manager, "did:plc:alice", "alice.example").await;

    for i in 0..10 {
        assert_ne!(
            hit(&app, PUBLIC_PATH, "3.3.3.3:1000", None).await,
            StatusCode::TOO_MANY_REQUESTS,
            "bypassed address, request {i}"
        );
    }
    // And the bypass is per-address, not a global off switch.
    hit(&app, PUBLIC_PATH, "4.4.4.4:1000", None).await;
    assert_eq!(
        hit(&app, PUBLIC_PATH, "4.4.4.4:1000", None).await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_auth_tier_trips_before_the_global_one() {
    // A hundred `getRecord` calls a minute is a busy client; a hundred
    // `createSession` calls a minute is someone guessing.
    let (app, manager, _tmp) = build_app(100, 2, 0, &[]).await;
    create_account(&manager, "did:plc:alice", "alice.example").await;

    let login = |app: axum::Router| async move {
        let mut req = Request::builder()
            .uri("/xrpc/com.atproto.server.createSession")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "identifier": "alice.example",
                    "password": "wrong",
                }))
                .unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo("6.6.6.6:1000".parse::<SocketAddr>().unwrap()));
        app.oneshot(req).await.unwrap().status()
    };

    for _ in 0..2 {
        login(app.clone()).await;
    }
    assert_eq!(
        login(app.clone()).await,
        StatusCode::TOO_MANY_REQUESTS,
        "the auth tier must bound login attempts"
    );
    // The global tier still has budget, so ordinary reads keep working while
    // the sprayer is locked out.
    assert_ne!(
        hit(&app, PUBLIC_PATH, "6.6.6.6:1000", None).await,
        StatusCode::TOO_MANY_REQUESTS,
        "the auth tier must not consume the global budget"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_sprayer_cannot_escape_by_varying_the_identifier() {
    // This is the finding stated as a test. The per-identifier limit that
    // existed keyed on `identifier`, so a different guess meant a different
    // bucket and the limiter bounded nothing.
    let (app, manager, _tmp) = build_app(100, 3, 0, &[]).await;
    create_account(&manager, "did:plc:alice", "alice.example").await;

    let attempt = |app: axum::Router, who: String| async move {
        let mut req = Request::builder()
            .uri("/xrpc/com.atproto.server.createSession")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "identifier": who,
                    "password": "guess",
                }))
                .unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo("6.6.6.6:1000".parse::<SocketAddr>().unwrap()));
        app.oneshot(req).await.unwrap().status()
    };

    for i in 0..3 {
        attempt(app.clone(), format!("victim{i}.example")).await;
    }
    assert_eq!(
        attempt(app.clone(), "victim99.example".to_string()).await,
        StatusCode::TOO_MANY_REQUESTS,
        "a fresh identifier must not buy a fresh budget"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn request_password_reset_is_now_fail_closed() {
    // It discarded the limiter's answer, so an attacker could send reset mail
    // to a third party as fast as it could make requests.
    let (app, manager, _tmp) = build_app(100, 2, 0, &[]).await;
    create_account(&manager, "did:plc:alice", "alice.example").await;

    let ask = |app: axum::Router| async move {
        let mut req = Request::builder()
            .uri("/xrpc/com.atproto.server.requestPasswordReset")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({"email": "alice@example.test"})).unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo("7.7.7.7:1000".parse::<SocketAddr>().unwrap()));
        app.oneshot(req).await.unwrap().status()
    };

    for _ in 0..2 {
        ask(app.clone()).await;
    }
    assert_eq!(
        ask(app.clone()).await,
        StatusCode::TOO_MANY_REQUESTS,
        "reset requests must be bounded, not merely counted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unrouted_path_still_costs_budget() {
    // The middleware layers outside the router, so a scan of a hundred
    // nonexistent endpoints costs the scanner rather than costing nothing.
    let (app, _m, _tmp) = build_app(2, 100, 0, &[]).await;
    for _ in 0..2 {
        hit(&app, "/xrpc/com.example.doesNotExist", "8.8.8.8:1000", None).await;
    }
    assert_eq!(
        hit(&app, "/xrpc/com.example.alsoMissing", "8.8.8.8:1000", None).await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_with_no_peer_address_is_not_refused() {
    // In-process callers and test harnesses have no socket. Refusing those
    // would break the caller rather than an attacker.
    let (app, manager, _tmp) = build_app(1, 1, 0, &[]).await;
    create_account(&manager, "did:plc:alice", "alice.example").await;

    for _ in 0..5 {
        let req = Request::builder()
            .uri(PUBLIC_PATH)
            .body(Body::empty())
            .unwrap();
        let status = app.clone().oneshot(req).await.unwrap().status();
        assert_ne!(status, StatusCode::TOO_MANY_REQUESTS);
    }
}

/// `/oauth/authorize` is the OAuth endpoint that takes a password, and it was
/// the one not on the auth tier. `/oauth/token` and `/oauth/par` were listed,
/// so the two steps that *consume* a credential were budgeted while the step
/// that guesses at one ran at the ordinary tier.
#[tokio::test(flavor = "multi_thread")]
async fn the_oauth_authorize_form_is_on_the_auth_tier() {
    let (app, manager, _tmp) = build_app(100, 2, 0, &[]).await;
    create_account(&manager, "did:plc:alice", "alice.example").await;

    let guess = |app: axum::Router| async move {
        let mut req = Request::builder()
            .uri("/oauth/authorize")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "request_uri": "urn:ietf:params:oauth:request_uri:nonexistent",
                    "identifier": "alice.example",
                    "password": "wrong",
                    "approve": true,
                }))
                .unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo("7.7.7.7:1000".parse::<SocketAddr>().unwrap()));
        app.oneshot(req).await.unwrap().status()
    };

    for _ in 0..2 {
        guess(app.clone()).await;
    }
    assert_eq!(
        guess(app.clone()).await,
        StatusCode::TOO_MANY_REQUESTS,
        "the authorize form must be bounded like every other password entry point"
    );
}
