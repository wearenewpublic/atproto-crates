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
//! So [`announce`] runs at startup, once the listener is up, for every entry in
//! `PDS_CRAWLERS`. An operator who configured a relay has said what they want;
//! requiring them to also know that a manual `requestCrawl` is the thing that
//! sets it in motion is a step that exists only to be missed.

use std::time::Duration;

/// How long to wait on a crawler before giving up on it.
const ANNOUNCE_TIMEOUT: Duration = Duration::from_secs(10);

/// POST `com.atproto.sync.requestCrawl` to every configured crawler.
///
/// `hostname` is what the crawler will subscribe to — this server's public
/// name, not a URL.
///
/// Never fails. A crawler that is unreachable, slow, or returning errors is
/// that crawler's problem: the others are still worth telling, and a PDS that
/// refused to start because a relay was down would be trading a working server
/// for an unreachable one. Every outcome is logged, because a silent announce
/// is indistinguishable from one that never happened — which is the exact
/// ambiguity this module exists to remove.
pub async fn announce(crawlers: &[String], hostname: &str) {
    if crawlers.is_empty() {
        tracing::debug!(
            hostname = %hostname,
            "no crawlers configured; this server will not be crawled until one is"
        );
        return;
    }

    let http = reqwest::Client::builder()
        .user_agent(crate::user_agent())
        .timeout(ANNOUNCE_TIMEOUT)
        .build()
        .unwrap_or_default();

    for base in crawlers {
        let endpoint = format!(
            "{}/xrpc/com.atproto.sync.requestCrawl",
            base.trim_end_matches('/')
        );
        let body = serde_json::json!({ "hostname": hostname });
        let result = http
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .body(serde_json::to_vec(&body).unwrap_or_default())
            .send()
            .await;
        match result {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(crawler = %endpoint, hostname = %hostname, "requestCrawl: announced");
            }
            Ok(resp) => {
                // Worth a warning rather than an info: the operator asked to be
                // crawled and is not going to be, and nothing else will say so.
                tracing::warn!(
                    crawler = %endpoint,
                    status = %resp.status(),
                    hostname = %hostname,
                    "requestCrawl: crawler refused the announcement"
                );
            }
            Err(e) => {
                tracing::warn!(
                    crawler = %endpoint,
                    error = ?e,
                    hostname = %hostname,
                    "requestCrawl: could not reach crawler"
                );
            }
        }
    }
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
    }

    /// An unreachable crawler must not take the caller down with it — this runs
    /// at startup, before the server is serving.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unreachable_crawler_is_survivable() {
        announce(&["http://127.0.0.1:1/".to_string()], "pds.example").await;
    }
}
