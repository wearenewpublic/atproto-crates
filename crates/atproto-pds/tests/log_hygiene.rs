//! What this server writes about people who are not its users.
//!
//! `requestPasswordReset` answers 200 to everything, on purpose: telling a
//! caller whether an address is registered is the enumeration answer the
//! endpoint exists to withhold. It was then writing that same answer into the
//! log — the addresses reaching the miss branch are exactly the ones that are
//! *not* registered — from an unauthenticated endpoint, which also made the log
//! writable by anyone with a curl command.
//!
//! The capture layer here records structured fields as well as the message,
//! because the address was never in the message; it was a field, which is
//! precisely the sort of thing a message-only assertion would have missed.
//!
//! `town.roundabout.server.createSessionFromToken` has the same shape: it is
//! unauthenticated, and its `AccountNotFound` branch is reached with exactly
//! the addresses that have no account here. Its handler carries a comment
//! promising the address stays out of the log; the second test is what makes
//! that promise true.

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager};
use atproto_pds::http::auth_gateway::{AuthGateway, AuthGatewayConfig};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use axum::body::Body;
use axum::http::Request;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tower::ServiceExt;
use tracing_subscriber::layer::SubscriberExt;

const GATEWAY_PRIVATE_PEM: &str = include_str!("fixtures/auth_gateway/private.pem");
const GATEWAY_JWKS_JSON: &str = include_str!("fixtures/auth_gateway/jwks.json");
const GATEWAY_AUDIENCE: &str = "https://pds.example";

/// Captures every event's message *and* its fields, rendered the way a log sink
/// would see them.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Captured {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct All(String);
        impl tracing::field::Visit for All {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!(" {}={:?}", field.name(), value));
            }
        }
        let mut all = All(String::new());
        event.record(&mut all);
        self.0.lock().unwrap().push(all.0);
    }
}

impl Captured {
    fn contains(&self, needle: &str) -> bool {
        self.0
            .lock()
            .unwrap()
            .iter()
            .any(|line| line.contains(needle))
    }
}

async fn build_app() -> (axum::Router, TempDir) {
    build_app_with_gateway(None).await
}

/// Serve the fixture key set at `/.well-known/jwks.json` on a loopback port
/// and return its origin, so the gateway verifier has real keys to fetch.
async fn jwks_server() -> String {
    use axum::{Router, routing::get};
    let app = Router::new().route(
        "/.well-known/jwks.json",
        get(|| async { ([("content-type", "application/json")], GATEWAY_JWKS_JSON) }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

/// A token shaped like `services/auth-gateway`'s `sign()`, signed by the
/// fixture key the JWKS server publishes.
fn gateway_token(email: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = serde_json::json!({
        "iss": "auth-gateway",
        "aud": GATEWAY_AUDIENCE,
        "sub": email,
        "email": email,
        "provider": "email",
        "emailId": "ml_1",
        "environment": "roundabout-grove.fly.dev",
        "iat": now,
        "exp": now + 300,
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".to_string());
    jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(GATEWAY_PRIVATE_PEM.as_bytes()).unwrap(),
    )
    .unwrap()
}

async fn build_app_with_gateway(gateway_origin: Option<&str>) -> (axum::Router, TempDir) {
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
    let mut state = HttpState::with_account_manager(
        reader,
        manager,
        "did:web:pds.test".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer);
    if let Some(origin) = gateway_origin {
        state = state.with_auth_gateway(AuthGateway::new(
            AuthGatewayConfig::new(origin, GATEWAY_AUDIENCE).unwrap(),
        ));
    }
    (build_router(state), tmp)
}

/// A reset request for an address this server has never heard of must leave no
/// record of the address.
#[tokio::test(flavor = "multi_thread")]
async fn a_password_reset_probe_does_not_log_the_address() {
    const PROBE: &str = "somebody-elses-address@example.invalid";

    let (app, _tmp) = build_app().await;
    let captured = Captured::default();
    let subscriber = tracing_subscriber::registry().with(captured.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/com.atproto.server.requestPasswordReset")
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"email":"{PROBE}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        200,
        "the silent 200 is the behaviour being protected"
    );
    assert!(
        captured.contains("no active account match"),
        "the line still has to exist -- it is what makes probing visible in \
         aggregate; only the address is gone"
    );
    assert!(
        !captured.contains(PROBE),
        "the probed address reached the log: {:?}",
        captured.0.lock().unwrap()
    );
    assert!(
        !captured.contains("example.invalid"),
        "not even the domain: {:?}",
        captured.0.lock().unwrap()
    );
}

/// A gateway token for an address with no account here must leave no record of
/// the address either.
///
/// `createSessionFromToken` is unauthenticated, so anyone holding a gateway
/// token — or, for the shape of the log line, anyone at all, since the miss
/// branch is reached before any account exists — can decide which addresses
/// this server writes down; and the addresses that reach `AccountNotFound`
/// are precisely the ones with no account, the same enumeration answer the
/// reset endpoint withholds. The handler's comment claims this is guarded;
/// this is the guard.
#[tokio::test]
async fn a_gateway_token_for_an_unknown_email_does_not_log_the_address() {
    const PROBE: &str = "nobody-with-an-account@example.invalid";

    let origin = jwks_server().await;
    let (app, _tmp) = build_app_with_gateway(Some(&origin)).await;
    let captured = Captured::default();
    let subscriber = tracing_subscriber::registry().with(captured.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/xrpc/town.roundabout.server.createSessionFromToken")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "authToken": gateway_token(PROBE) }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let bytes = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status, 400, "body: {body}");
    assert_eq!(
        body["error"], "AccountNotFound",
        "the miss branch is the one under test: {body}"
    );

    assert!(
        captured.contains("auth-gateway token for an unknown email"),
        "the line still has to exist -- it is what makes probing visible in \
         aggregate; only the address is gone: {:?}",
        captured.0.lock().unwrap()
    );
    assert!(
        !captured.contains(PROBE),
        "the probed address reached the log: {:?}",
        captured.0.lock().unwrap()
    );
    assert!(
        !captured.contains("example.invalid"),
        "not even the domain: {:?}",
        captured.0.lock().unwrap()
    );
}
