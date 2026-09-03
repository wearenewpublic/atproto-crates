//! `town.roundabout.server.createSessionFromToken` — a session from a
//! gateway-signed RS256 token, matched to an account by email.
//!
//! The JWKS is served by a throwaway axum server on a loopback port; the
//! router under test is pointed at it through `HttpState::with_auth_gateway`.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager, AccountState, CreateAccountParams};
use atproto_pds::http::auth_gateway::{AuthGateway, AuthGatewayConfig};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::RepoReader;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

const PRIVATE_PEM: &str = include_str!("fixtures/auth_gateway/private.pem");
const JWKS_JSON: &str = include_str!("fixtures/auth_gateway/jwks.json");
const AUDIENCE: &str = "https://pds.example";
const NSID: &str = "/xrpc/town.roundabout.server.createSessionFromToken";

/// Serve `body` at `/.well-known/jwks.json` on a random loopback port and
/// return the origin. Counts requests so the re-fetch behaviour is observable.
async fn jwks_server(
    body: Arc<std::sync::Mutex<String>>,
    hits: Arc<std::sync::atomic::AtomicUsize>,
) -> String {
    use axum::{Router, routing::get};
    let app = Router::new().route(
        "/.well-known/jwks.json",
        get(move || {
            let body = body.clone();
            let hits = hits.clone();
            async move {
                hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let text = body.lock().unwrap().clone();
                ([("content-type", "application/json")], text)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

struct Harness {
    app: axum::Router,
    manager: Arc<AccountManager>,
    jwks_hits: Arc<std::sync::atomic::AtomicUsize>,
    jwks_body: Arc<std::sync::Mutex<String>>,
    _tmp: TempDir,
}

async fn build(configured: bool) -> Harness {
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
    let reader = Arc::new(RepoReader::new(accounts, dir));
    let mut state = HttpState::with_account_manager(
        reader,
        manager.clone(),
        "did:web:test.example".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    );
    let jwks_body = Arc::new(std::sync::Mutex::new(JWKS_JSON.to_string()));
    let jwks_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    if configured {
        let origin = jwks_server(jwks_body.clone(), jwks_hits.clone()).await;
        state = state.with_auth_gateway(AuthGateway::new(
            AuthGatewayConfig::new(&origin, AUDIENCE).unwrap(),
        ));
    }
    Harness {
        app: build_router(state),
        manager,
        jwks_hits,
        jwks_body,
        _tmp: tmp,
    }
}

async fn seed(manager: &AccountManager, did: &str, handle: &str, email: &str) {
    manager
        .create_account(CreateAccountParams::new(did, handle, "pw").with_email(Some(email)))
        .await
        .expect("fixture account");
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn gateway_token(email: &str, kid: &str, overrides: Value) -> String {
    let mut claims = json!({
        "iss": "auth-gateway",
        "aud": AUDIENCE,
        "sub": email,
        "email": email,
        "provider": "email",
        "emailId": "ml_1",
        "environment": "roundabout-grove.fly.dev",
        "iat": now(),
        "exp": now() + 300,
    });
    if let Value::Object(map) = overrides {
        for (k, v) in map {
            claims[k] = v;
        }
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(PRIVATE_PEM.as_bytes()).unwrap(),
    )
    .unwrap()
}

async fn post_json(app: axum::Router, path: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .uri(path)
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn post_bearer(app: axum::Router, path: &str, bearer: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .uri(path)
        .method("POST")
        .header("authorization", format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn get_json(app: axum::Router, path: &str, bearer: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .uri(path)
        .header("authorization", format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The whole contract on one request: a gateway token for a known email
/// returns a session whose keys the xoxo client reads (`accessJwt`,
/// `refreshJwt`, `did`, `handle`, camel-cased `emailConfirmed`), the access
/// token works against `getSession`, and the exchange confirms the email —
/// the gateway proved the mailbox, exactly as the TS PDS reasons.
#[tokio::test(flavor = "multi_thread")]
async fn exchanges_a_gateway_token_for_a_session() {
    let h = build(true).await;
    seed(
        &h.manager,
        "did:web:admin.example",
        "admin.example",
        "Admin@Example.com",
    )
    .await;

    let (status, body) = post_json(
        h.app.clone(),
        NSID,
        json!({ "authToken": gateway_token("admin@example.com", "test-key-1", json!({})) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["did"], "did:web:admin.example");
    assert_eq!(body["handle"], "admin.example");
    assert_eq!(body["email"], "Admin@Example.com");
    assert_eq!(body["emailConfirmed"], true);
    assert_eq!(body["active"], true);
    assert!(
        body.get("email_confirmed").is_none(),
        "must be camelCase on the wire"
    );
    assert!(
        body.get("status").is_none(),
        "status is absent for an active account"
    );
    assert!(body["didDoc"].is_object());
    assert!(body["accessJwt"].is_string() && body["refreshJwt"].is_string());

    let (status, session) = get_json(
        h.app.clone(),
        "/xrpc/com.atproto.server.getSession",
        body["accessJwt"].as_str().unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(session["did"], "did:web:admin.example");
    assert_eq!(session["emailConfirmed"], true);
}

/// No account creation, ever — the spec keeps org admins manually
/// provisioned.
#[tokio::test(flavor = "multi_thread")]
async fn unknown_email_is_account_not_found() {
    let h = build(true).await;
    let (status, body) = post_json(
        h.app.clone(),
        NSID,
        json!({ "authToken": gateway_token("stranger@example.com", "test-key-1", json!({})) }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "AccountNotFound");
}

/// Taken-down and deactivated accounts are refused with the lexicon's names
/// (`AccountTakenDown`, `AccountDeactivated`), not `createSession`'s
/// generic `Forbidden`.
#[tokio::test(flavor = "multi_thread")]
async fn state_is_reported_with_the_lexicon_error_names() {
    let h = build(true).await;
    seed(
        &h.manager,
        "did:web:td.example",
        "td.example",
        "td@example.com",
    )
    .await;
    seed(
        &h.manager,
        "did:web:de.example",
        "de.example",
        "de@example.com",
    )
    .await;
    h.manager
        .set_state("did:web:td.example", AccountState::Takendown)
        .await
        .unwrap();
    h.manager
        .set_state("did:web:de.example", AccountState::Deactivated)
        .await
        .unwrap();

    let (status, body) = post_json(
        h.app.clone(),
        NSID,
        json!({ "authToken": gateway_token("td@example.com", "test-key-1", json!({})) }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "AccountTakenDown");

    let (status, body) = post_json(
        h.app.clone(),
        NSID,
        json!({ "authToken": gateway_token("de@example.com", "test-key-1", json!({})) }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "AccountDeactivated");
}

/// Every verification failure is `InvalidToken`: wrong audience, expired,
/// missing gateway claims, garbage. The message never echoes the email.
///
/// The expired case is dated well past `exp` rather than a few seconds past
/// it: the verifier keeps `jsonwebtoken`'s default sixty seconds of
/// clock-skew leeway, so a token that died ten seconds ago is still a live
/// token as far as this server is concerned.
#[tokio::test(flavor = "multi_thread")]
async fn verification_failures_are_invalid_token() {
    let h = build(true).await;
    seed(
        &h.manager,
        "did:web:admin.example",
        "admin.example",
        "admin@example.com",
    )
    .await;
    let cases = [
        (
            "wrong audience",
            gateway_token(
                "admin@example.com",
                "test-key-1",
                json!({ "aud": "https://pds.other" }),
            ),
        ),
        (
            "expired",
            gateway_token(
                "admin@example.com",
                "test-key-1",
                json!({ "exp": now() - 600, "iat": now() - 900 }),
            ),
        ),
        (
            "no provider claim",
            gateway_token(
                "admin@example.com",
                "test-key-1",
                json!({ "provider": Value::Null }),
            ),
        ),
        ("not a jwt", "garbage".to_string()),
    ];
    for (label, token) in cases {
        let (status, body) = post_json(h.app.clone(), NSID, json!({ "authToken": token })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: {body}");
        assert_eq!(body["error"], "InvalidToken", "{label}");
        assert!(
            !body["message"]
                .as_str()
                .unwrap()
                .contains("admin@example.com"),
            "{label}: the refusal must not echo the address"
        );
    }
    let (status, body) = post_json(h.app.clone(), NSID, json!({ "authToken": "" })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidToken");
}

/// With no gateway configured the endpoint is routed but dark, answering
/// `InvalidToken` — the TS PDS's "External authentication not configured".
#[tokio::test(flavor = "multi_thread")]
async fn unconfigured_gateway_is_invalid_token() {
    let h = build(false).await;
    let (status, body) = post_json(
        h.app.clone(),
        NSID,
        json!({ "authToken": gateway_token("admin@example.com", "test-key-1", json!({})) }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidToken");
    assert_eq!(h.jwks_hits.load(std::sync::atomic::Ordering::SeqCst), 0);
}

/// Key rotation without coordination: a token signed by a kid the cached
/// set lacks forces one re-fetch; once the gateway publishes the new key the
/// next token succeeds.
#[tokio::test(flavor = "multi_thread")]
async fn unknown_kid_forces_one_refetch() {
    let h = build(true).await;
    seed(
        &h.manager,
        "did:web:admin.example",
        "admin.example",
        "admin@example.com",
    )
    .await;

    // Warm the cache with a good token.
    let (status, _) = post_json(
        h.app.clone(),
        NSID,
        json!({ "authToken": gateway_token("admin@example.com", "test-key-1", json!({})) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.jwks_hits.load(std::sync::atomic::Ordering::SeqCst), 1);

    // The gateway "rotates": same key material, published under a new kid.
    let mut set: Value = serde_json::from_str(JWKS_JSON).unwrap();
    set["keys"][0]["kid"] = "test-key-2".into();
    *h.jwks_body.lock().unwrap() = set.to_string();

    let (status, body) = post_json(
        h.app.clone(),
        NSID,
        json!({ "authToken": gateway_token("admin@example.com", "test-key-2", json!({})) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(h.jwks_hits.load(std::sync::atomic::Ordering::SeqCst), 2);
}

/// A gateway session must survive its first refresh, an hour after sign-in.
///
/// `issue_pair` stamps a synthetic `apw` of `__auth_gateway__` into both
/// tokens, and no `app_password` row backs it. That is only safe because
/// nothing joins `apw` against that table today — `require_authn` reads the
/// claim without looking it up, and so does `refreshSession`. This pins that:
/// a future lookup keyed on `apw` (revocation, per-app-password scoping,
/// listing) written on the reasonable assumption that the row exists would not
/// fail at deploy or at sign-in, but silently lock every org admin out at
/// their first refresh.
#[tokio::test(flavor = "multi_thread")]
async fn a_gateway_session_refreshes_despite_its_synthetic_app_password_id() {
    let h = build(true).await;
    seed(
        &h.manager,
        "did:web:admin.example",
        "admin.example",
        "admin@example.com",
    )
    .await;

    let (status, minted) = post_json(
        h.app.clone(),
        NSID,
        json!({ "authToken": gateway_token("admin@example.com", "test-key-1", json!({})) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{minted}");

    let (status, refreshed) = post_bearer(
        h.app.clone(),
        "/xrpc/com.atproto.server.refreshSession",
        minted["refreshJwt"].as_str().unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{refreshed}");
    assert_eq!(refreshed["did"], "did:web:admin.example");
    assert!(refreshed["accessJwt"].is_string() && refreshed["refreshJwt"].is_string());

    let (status, session) = get_json(
        h.app.clone(),
        "/xrpc/com.atproto.server.getSession",
        refreshed["accessJwt"].as_str().unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert_eq!(session["did"], "did:web:admin.example");
}
