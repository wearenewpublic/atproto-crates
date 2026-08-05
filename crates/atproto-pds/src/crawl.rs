//! Announcing this PDS to relays and other crawlers.
//!
//! A PDS is invisible to the network until a relay is told to crawl it. Nothing
//! discovers one on its own: not the AppView, not a client, not the relay. The
//! server can be reachable, serving `listRepos`, holding valid repos and
//! upgrading firehose connections correctly, and still have no reader, because
//! nobody has been told it exists.
//!
//! The failure this causes is quiet and points at the wrong layer. Writes
//! succeed, `putRecord` returns a real commit, third-party tools read the
//! records straight out of the repo, and the AppView still shows nothing —
//! because the AppView knows the *identity* from PLC, which resolves
//! independently, while the repo behind it was never ingested. It reads as a
//! broken write path or a broken firehose. It is neither.
//!
//! So [`announce_with_retry`] runs at startup for every entry in
//! `PDS_CRAWLERS`. An operator who configured a relay has said what they want;
//! requiring them to also know that a manual `requestCrawl` is the thing that
//! sets it in motion is a step that exists only to be missed.
//!
//! # Why it retries
//!
//! A relay does not take `requestCrawl` on trust — it tries to reach the host
//! it was handed and refuses the announcement if it cannot. That makes process
//! start the *worst* moment to announce and the one this code naturally picks:
//! the listener is up locally while the deployment is not yet reachable from
//! outside, because the platform has not finished health-checking the new
//! container or moving traffic off the old one. Announcing once at `t=0` fails
//! for a server that is completely healthy thirty seconds later.
//!
//! That is not hypothetical. The first deployment carrying this module
//! announced during a container swap and was refused with a bare `400`, which
//! left the PDS uncrawled and looked exactly like a misconfiguration.

use std::time::Duration;

/// How long to wait on a crawler before giving up on one attempt.
const ANNOUNCE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait before each attempt.
///
/// The first is immediate, for the ordinary case where the host is already
/// reachable — a restart of a server the relay already knows. The rest span
/// roughly twenty minutes, which covers a slow rollout, a health check that
/// takes its time, and a relay that is briefly down, without hammering anyone.
const RETRY_DELAYS: [Duration; 5] = [
    Duration::from_secs(0),
    Duration::from_secs(15),
    Duration::from_secs(60),
    Duration::from_secs(180),
    Duration::from_secs(900),
];

/// How much of a crawler's error body to keep in the log.
const MAX_LOGGED_BODY: usize = 300;

/// What a crawler said when asked to crawl.
#[derive(Debug)]
enum Outcome {
    /// The crawler accepted the announcement.
    Accepted,
    /// The crawler answered, and said no. Carries its own explanation.
    Refused(String),
    /// The crawler could not be reached at all.
    Unreachable(String),
}

/// Ask one crawler to crawl `hostname`.
async fn announce_one(http: &reqwest::Client, base: &str, hostname: &str) -> Outcome {
    let endpoint = format!(
        "{}/xrpc/com.atproto.sync.requestCrawl",
        base.trim_end_matches('/')
    );
    let body = serde_json::json!({ "hostname": hostname });
    match http
        .post(&endpoint)
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(&body).unwrap_or_default())
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => Outcome::Accepted,
        Ok(resp) => {
            let status = resp.status();
            // The status on its own does not say what to do about it. A relay
            // that refuses because it cannot reach this host needs the operator
            // to check DNS or wait for a rollout; one that refuses the hostname
            // needs the config changed. Both are a bare 400 without the body.
            let detail = resp.text().await.unwrap_or_default();
            let detail = detail.trim();
            let detail = if detail.is_empty() {
                "no response body".to_string()
            } else {
                detail.chars().take(MAX_LOGGED_BODY).collect()
            };
            Outcome::Refused(format!("{status}: {detail}"))
        }
        Err(e) => Outcome::Unreachable(format!("{e}")),
    }
}

/// Announce to every crawler once, without retrying.
///
/// This is the path behind `com.atproto.sync.requestCrawl`: a caller asked for
/// an announcement now and is waiting on the answer, so a retry schedule
/// measured in minutes would hold the request open rather than help.
pub async fn announce(crawlers: &[String], hostname: &str) {
    if crawlers.is_empty() {
        tracing::debug!(
            hostname = %hostname,
            "no crawlers configured; this server will not be crawled until one is"
        );
        return;
    }
    let http = client();
    for base in crawlers {
        report(
            &announce_one(&http, base, hostname).await,
            base,
            hostname,
            1,
        );
    }
}

/// Announce at startup, retrying each crawler until it accepts.
///
/// Crawlers are announced to concurrently so a slow one does not delay the
/// rest. Never fails: a crawler that will not accept is logged and abandoned,
/// because a PDS that refused to run because a relay was down would be trading
/// a working server for an unreachable one.
pub async fn announce_with_retry(crawlers: &[String], hostname: &str) {
    if crawlers.is_empty() {
        tracing::debug!(
            hostname = %hostname,
            "no crawlers configured; this server will not be crawled until one is"
        );
        return;
    }

    let http = client();
    let mut tasks = Vec::with_capacity(crawlers.len());
    for base in crawlers {
        let http = http.clone();
        let base = base.clone();
        let hostname = hostname.to_string();
        tasks.push(tokio::spawn(async move {
            if announce_retrying(&http, &base, &hostname, &RETRY_DELAYS).await {
                return;
            }
            // Out of attempts. This is the one case an operator has to act on,
            // so it says what to do rather than only what happened.
            tracing::error!(
                crawler = %base,
                hostname = %hostname,
                attempts = RETRY_DELAYS.len(),
                "requestCrawl: gave up; this server will not be crawled. Check that \
                 the host is reachable from the public internet, then announce by \
                 hand: curl -X POST {}/xrpc/com.atproto.sync.requestCrawl \
                 -H 'Content-Type: application/json' -d '{{\"hostname\":\"{}\"}}'",
                base.trim_end_matches('/'),
                hostname
            );
        }));
    }
    for task in tasks {
        let _ = task.await;
    }
}

/// Announce to one crawler, retrying on `delays` until it accepts.
///
/// Returns whether it was accepted. Split out from [`announce_with_retry`] so a
/// test can drive the schedule without waiting out the real one -- a retry that
/// is only exercised in production is a retry nobody has seen work.
async fn announce_retrying(
    http: &reqwest::Client,
    base: &str,
    hostname: &str,
    delays: &[Duration],
) -> bool {
    for (attempt, delay) in delays.iter().enumerate() {
        if !delay.is_zero() {
            tokio::time::sleep(*delay).await;
        }
        let outcome = announce_one(http, base, hostname).await;
        let accepted = matches!(outcome, Outcome::Accepted);
        report(&outcome, base, hostname, attempt + 1);
        if accepted {
            return true;
        }
    }
    false
}

/// Log one attempt's outcome.
fn report(outcome: &Outcome, base: &str, hostname: &str, attempt: usize) {
    match outcome {
        Outcome::Accepted => {
            tracing::info!(
                crawler = %base,
                hostname = %hostname,
                attempt,
                "requestCrawl: announced"
            );
        }
        Outcome::Refused(detail) => {
            tracing::warn!(
                crawler = %base,
                hostname = %hostname,
                attempt,
                detail = %detail,
                "requestCrawl: crawler refused the announcement"
            );
        }
        Outcome::Unreachable(detail) => {
            tracing::warn!(
                crawler = %base,
                hostname = %hostname,
                attempt,
                detail = %detail,
                "requestCrawl: could not reach crawler"
            );
        }
    }
}

/// The HTTP client used for announcements.
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(crate::user_agent())
        .timeout(ANNOUNCE_TIMEOUT)
        .build()
        .unwrap_or_default()
}

/// This server's public hostname, for announcing.
///
/// Prefers the explicitly configured hostname and falls back to the host inside
/// a `did:web:` service DID, which is where it is already derived from
/// elsewhere.
#[must_use]
pub fn public_hostname(hostname: Option<&str>, service_did: &str) -> String {
    if let Some(h) = hostname.map(str::trim).filter(|h| !h.is_empty()) {
        return h.to_string();
    }
    service_did
        .strip_prefix("did:web:")
        .unwrap_or(service_did)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn hostname_prefers_the_configured_value() {
        assert_eq!(
            public_hostname(Some("pds.example"), "did:web:other.example"),
            "pds.example"
        );
    }

    #[test]
    fn hostname_falls_back_to_the_did_web_host() {
        assert_eq!(
            public_hostname(None, "did:web:pds.example"),
            "pds.example",
            "a did:web service DID carries the host and must be usable as one"
        );
    }

    /// An empty string is what an unset environment variable deserialises to,
    /// and announcing `hostname: ""` asks the relay to crawl nothing.
    #[test]
    fn hostname_ignores_a_blank_configured_value() {
        assert_eq!(
            public_hostname(Some("  "), "did:web:pds.example"),
            "pds.example"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn no_crawlers_is_not_an_error() {
        announce(&[], "pds.example").await;
        announce_with_retry(&[], "pds.example").await;
    }

    /// The first delay must be zero, or every restart of an already-reachable
    /// server waits before announcing for no reason.
    #[test]
    fn the_first_attempt_is_immediate() {
        assert!(RETRY_DELAYS[0].is_zero());
    }

    /// A crawler that refuses the first `fail_times` attempts, then accepts.
    /// Returns its base URL and the number of requests it received.
    async fn flaky_crawler(fail_times: usize) -> (String, Arc<AtomicUsize>) {
        use axum::routing::post;
        let hits = Arc::new(AtomicUsize::new(0));
        let seen = hits.clone();
        let app = axum::Router::new().route(
            "/xrpc/com.atproto.sync.requestCrawl",
            post(move || {
                let seen = seen.clone();
                async move {
                    let n = seen.fetch_add(1, Ordering::SeqCst);
                    if n < fail_times {
                        // What a relay says when it cannot reach the host it
                        // was handed -- the case this retry exists for.
                        (
                            axum::http::StatusCode::BAD_REQUEST,
                            "could not resolve host",
                        )
                    } else {
                        (axum::http::StatusCode::OK, "")
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), hits)
    }

    /// The whole point: a refusal at startup is not the end of it.
    ///
    /// A relay refuses while the deployment is still coming up, and the server
    /// is reachable moments later. One attempt leaves the PDS uncrawled
    /// forever; this is what makes the second attempt happen.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_refusal_is_retried_until_it_is_accepted() {
        let (base, hits) = flaky_crawler(2).await;

        let accepted =
            announce_retrying(&client(), &base, "pds.example", &[Duration::ZERO; 5]).await;

        assert!(
            accepted,
            "the crawler accepted, but the retry gave up first"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            3,
            "expected two refusals then an acceptance"
        );
    }

    /// Retrying stops as soon as it works.
    #[tokio::test(flavor = "multi_thread")]
    async fn acceptance_ends_the_retries() {
        let (base, hits) = flaky_crawler(0).await;

        announce_retrying(&client(), &base, "pds.example", &[Duration::ZERO; 5]).await;

        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "kept announcing to a crawler that had already accepted"
        );
    }

    /// A crawler that never accepts is abandoned rather than retried forever.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_crawler_that_never_accepts_is_given_up_on() {
        let (base, hits) = flaky_crawler(usize::MAX).await;

        let accepted =
            announce_retrying(&client(), &base, "pds.example", &[Duration::ZERO; 3]).await;

        assert!(!accepted);
        assert_eq!(
            hits.load(Ordering::SeqCst),
            3,
            "the schedule was not honoured"
        );
    }
}
