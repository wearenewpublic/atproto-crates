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

use atproto_identity::key::KeyType;
use atproto_pds::account::{AccountDirectory, AccountManager};
use atproto_pds::http::{HttpState, build_router};
use atproto_pds::keys::{KeyStore, MemoryKeyStore};
use atproto_pds::repo::{RepoReader, RepoWriter};
use axum::body::Body;
use axum::http::Request;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tower::ServiceExt;
use tracing_subscriber::layer::SubscriberExt;

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
        manager,
        "did:web:pds.test".to_string(),
        b"test-secret-do-not-use-in-prod-32!".to_vec(),
        false,
    )
    .with_writer(writer);
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
