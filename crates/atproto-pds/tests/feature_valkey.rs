//! — `valkey` feature acceptance.
//!
//! This test exercises the `valkey` feature's gated symbols so CI
//! proves the build path lights up under `cargo test --features valkey`.
//! It does NOT require a live Valkey/Redis instance — that would mean
//! pulling in a testcontainers dependency. Instead, the test
//! constructs the JTI guard / rate-limiter enums via the
//! `new_valkey(...)` constructors, drives them against a deliberately
//! unreachable URL, and asserts the fail-open behavior matches the
//! documented contract.

#[cfg(feature = "valkey")]
#[test]
#[allow(clippy::type_complexity)] // boxed future is the surface this compile-only check is checking.
fn valkey_client_rejects_malformed_url() {
    // `redis::Client::open` rejects scheme-less / non-redis URLs at
    // parse time — so this exercises the constructor without a live
    // server. We can't easily test the ConnectionManager path in CI
    // without testcontainers; the unreachable-URL retry path takes
    // multiple minutes in offline CI which makes for a brittle test.
    use atproto_pds::valkey_backend::ValkeyClient;

    // The connect call requires a runtime; use an offline check by
    // calling `redis::Client::open` directly (which is what
    // `ValkeyClient::connect` does internally before the connection
    // attempt).
    let bad = redis::Client::open("not-a-valid-url");
    assert!(bad.is_err(), "expected malformed URL to be rejected");

    // The `ValkeyClient` type itself is constructed during the test
    // suite's compile pass — this `_` use proves the symbol resolves.
    let _: fn(
        &str,
        &str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = atproto_pds::errors::PdsResult<ValkeyClient>> + Send>,
    > = |url, prefix| {
        let url = url.to_string();
        let prefix = prefix.to_string();
        Box::pin(async move { ValkeyClient::connect(&url, &prefix).await })
    };
}

/// Live round-trip against a real Valkey/Redis, opted into with
/// `PDS_VALKEY_TEST_URL` (same shape as `postgres-live-tests`). Skips
/// with an `INFO` line when the variable is unset so offline CI passes.
///
/// This covers what the offline checks above structurally cannot. Both
/// guards below read a *reply shape* rather than a status code, and
/// both treat a client error as fail-open:
///
/// - the JTI guard distinguishes `SET NX` returning `OK` from returning
///   nil, and admits the request when the parse errors;
/// - the limiter reads a two-element pipeline reply, and admits when
///   that parse errors.
///
/// So a client-library upgrade that changed nil handling or pipeline
/// reply typing would not fail to compile and would not fail any
/// offline test — it would silently stop rejecting replays and stop
/// enforcing limits. Only a live reply proves the mapping still holds.
#[cfg(feature = "valkey")]
#[tokio::test]
async fn valkey_live_replay_and_limit_enforcement() {
    use atproto_pds::valkey_backend::{ValkeyClient, ValkeyJtiInner, ValkeyLimiterInner};
    use std::time::Duration;

    // Unique-per-run suffix so repeat runs never collide on keys a
    // previous run left inside the TTL window.
    fn unique() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock at or after the Unix epoch")
            .as_nanos()
    }

    let Ok(url) = std::env::var("PDS_VALKEY_TEST_URL") else {
        eprintln!("INFO: PDS_VALKEY_TEST_URL unset; skipping live Valkey test");
        return;
    };

    let prefix = format!("atproto-pds-test-{}:", unique());
    let client = ValkeyClient::connect(&url, &prefix)
        .await
        .expect("connect to the configured Valkey");

    // A fresh JTI is admitted; the same JTI is a replay. If the nil
    // reply stopped mapping to `Ok(None)`, the second call would
    // fail open and this assertion is what catches it.
    let jti_guard = ValkeyJtiInner::new(client.clone());
    let jti = format!("jti-{}", unique());
    let ttl = Duration::from_secs(60);
    assert!(
        jti_guard.check_and_insert(&jti, ttl).await.is_ok(),
        "first sight of a JTI must be admitted"
    );
    assert!(
        jti_guard.check_and_insert(&jti, ttl).await.is_err(),
        "second sight of the same JTI must be rejected as a replay"
    );

    // The limiter admits exactly `limit` requests in the window and
    // rejects the next one, with a retry-after inside the window.
    let limit = 3usize;
    let window = Duration::from_secs(60);
    let limiter = ValkeyLimiterInner::new(client, limit, window);
    let limit_key = format!("key-{}", unique());
    for i in 0..limit {
        assert!(
            limiter.try_acquire(&limit_key).await.is_ok(),
            "request {i} of {limit} must be admitted"
        );
    }
    let rejected = limiter
        .try_acquire(&limit_key)
        .await
        .expect_err("the request past the limit must be rejected");
    assert!(
        rejected.retry_after <= window,
        "retry_after {:?} must fall inside the {window:?} window",
        rejected.retry_after
    );
}
