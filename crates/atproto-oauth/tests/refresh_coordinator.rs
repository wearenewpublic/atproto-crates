//! One refresh per subject at a time.
//!
//! Under OAuth 2.1 §4.14.2 a replayed refresh token revokes the whole grant,
//! and the specification does not distinguish a leaked token from a client
//! racing itself. Everything here is about making the second impossible.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use atproto_oauth::errors::OAuthClientError;
use atproto_oauth::refresh::{RefreshCoordinator, RefreshOutcome};
use atproto_oauth::workflow::TokenResponse;

fn tokens() -> TokenResponse {
    TokenResponse {
        access_token: "an-access-token".to_string(),
        token_type: "DPoP".to_string(),
        refresh_token: Some("a-refresh-token".to_string()),
        scope: "atproto".to_string(),
        expires_in: 3600,
        sub: Some("did:plc:holder".to_string()),
        extra: Default::default(),
    }
}

/// Ten concurrent callers, one network call.
///
/// This is the whole point: the second call would spend a refresh token the
/// first already spent, and the authorization server treats that as a replay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_refreshes_issue_one_call() {
    let coordinator = Arc::new(RefreshCoordinator::new());
    let calls = Arc::new(AtomicUsize::new(0));

    let mut tasks = Vec::new();
    for _ in 0..10 {
        let coordinator = coordinator.clone();
        let calls = calls.clone();
        tasks.push(tokio::spawn(async move {
            coordinator
                .refresh("did:plc:holder", async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    // Long enough that the others are certainly waiting on the
                    // lock rather than arriving after it was released.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    Ok(tokens())
                })
                .await
        }));
    }

    let mut refreshed = 0;
    let mut already_fresh = 0;
    for task in tasks {
        match task.await.expect("join").expect("refresh") {
            RefreshOutcome::Refreshed(_) => refreshed += 1,
            RefreshOutcome::AlreadyFresh => already_fresh += 1,
            RefreshOutcome::Backoff { .. } => panic!("nothing failed"),
        }
    }

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(refreshed, 1);
    assert_eq!(already_fresh, 9);
}

/// A caller arriving after a success is told the work is done.
#[tokio::test]
async fn a_caller_arriving_after_a_success_is_told_it_is_already_fresh() {
    let coordinator = RefreshCoordinator::new();
    let calls = AtomicUsize::new(0);

    let attempt = || async {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(tokens())
    };

    assert!(matches!(
        coordinator
            .refresh("did:plc:holder", attempt())
            .await
            .expect("refresh"),
        RefreshOutcome::Refreshed(_)
    ));
    assert!(matches!(
        coordinator
            .refresh("did:plc:holder", attempt())
            .await
            .expect("refresh"),
        RefreshOutcome::AlreadyFresh
    ));

    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// And once the memo lapses, the next caller does refresh.
#[tokio::test]
async fn a_caller_arriving_after_the_memo_lapses_does_refresh() {
    let coordinator = RefreshCoordinator::new().memo_ttl(Duration::from_millis(20));
    let calls = AtomicUsize::new(0);

    let attempt = || async {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(tokens())
    };

    coordinator
        .refresh("did:plc:holder", attempt())
        .await
        .expect("refresh");
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert!(matches!(
        coordinator
            .refresh("did:plc:holder", attempt())
            .await
            .expect("refresh"),
        RefreshOutcome::Refreshed(_)
    ));

    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

/// A failure sets a backoff, and the next caller is told so without the
/// future being polled.
#[tokio::test]
async fn a_failure_backs_off_without_calling_again() {
    let coordinator = RefreshCoordinator::new().backoff(vec![Duration::from_secs(30)]);
    let calls = AtomicUsize::new(0);

    let attempt = || async {
        calls.fetch_add(1, Ordering::SeqCst);
        Err(OAuthClientError::InvalidOAuthProtectedResource)
    };

    coordinator
        .refresh("did:plc:holder", attempt())
        .await
        .expect_err("the attempt failed");

    let outcome = coordinator
        .refresh("did:plc:holder", attempt())
        .await
        .expect("backoff is an outcome, not an error");
    assert!(
        matches!(outcome, RefreshOutcome::Backoff { .. }),
        "{outcome:?}"
    );

    // The second future was never polled: an authorization server that is
    // refusing should not be asked again by every request that arrives.
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// A backoff that has lapsed lets the next caller through, and a success
/// clears it.
#[tokio::test]
async fn a_lapsed_backoff_lets_the_next_caller_through() {
    let coordinator = RefreshCoordinator::new().backoff(vec![Duration::from_millis(20)]);

    coordinator
        .refresh("did:plc:holder", async {
            Err(OAuthClientError::InvalidOAuthProtectedResource)
        })
        .await
        .expect_err("failed");

    tokio::time::sleep(Duration::from_millis(40)).await;

    assert!(matches!(
        coordinator
            .refresh("did:plc:holder", async { Ok(tokens()) })
            .await
            .expect("refresh"),
        RefreshOutcome::Refreshed(_)
    ));
}

/// Subjects do not block each other.
#[tokio::test]
async fn one_subjects_refresh_does_not_block_another() {
    let coordinator = RefreshCoordinator::new();
    let calls = AtomicUsize::new(0);

    for subject in ["did:plc:one", "did:plc:two"] {
        assert!(matches!(
            coordinator
                .refresh(subject, async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(tokens())
                })
                .await
                .expect("refresh"),
            RefreshOutcome::Refreshed(_)
        ));
    }

    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

/// The slot map does not grow without bound.
///
/// One entry per DID that has ever signed in is a slow leak nobody attributes
/// to the refresh path, so entries whose memo and backoff have both lapsed are
/// evicted.
#[tokio::test]
async fn the_slot_map_stays_bounded() {
    let coordinator = RefreshCoordinator::new().memo_ttl(Duration::from_millis(5));

    for index in 0..200 {
        coordinator
            .refresh(&format!("did:plc:holder{index}"), async { Ok(tokens()) })
            .await
            .expect("refresh");
    }

    // Everything above has lapsed by now; one more call sweeps them.
    tokio::time::sleep(Duration::from_millis(20)).await;
    coordinator
        .refresh("did:plc:last", async { Ok(tokens()) })
        .await
        .expect("refresh");

    assert!(
        coordinator.tracked() <= 2,
        "expected the map to have been swept, {} entries remain",
        coordinator.tracked()
    );
}
