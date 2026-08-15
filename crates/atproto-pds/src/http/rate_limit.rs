//! Per-IP rate limiting across the whole request surface.
//!
//! The `SlidingWindowLimiter` in [`crate::security`] has always existed and has
//! always worked. What was missing was a caller it could bound: every bucket
//! key was derived from caller-supplied input — `createSession:{identifier}`,
//! `createAccount:{handle}`, `requestPasswordReset:{email}` — so a password
//! sprayer varied `identifier` and got a fresh bucket per attempt. The limiter
//! did not bound the attack it most resembles a defence against, and roughly
//! 100 of 104 routes had no limit at all.
//!
//! This module adds the missing half: a middleware over every route, keyed on
//! something the caller cannot choose.
//!
//! # Where the address comes from
//!
//! By default, the TCP peer address. `X-Forwarded-For` is **not** trusted
//! unless the operator says how many proxies sit in front of the PDS, because
//! a header any client can set is not an identity — trusting it blindly would
//! hand every caller a private bucket, which is worse than no limit at all
//! because it reads as a defence.
//!
//! With `PDS_TRUSTED_PROXY_HOPS=N`, the address is the *N*th entry from the
//! right of `X-Forwarded-For`. Counting from the right is what makes this
//! sound: each trusted proxy appends the address it saw, so the rightmost N
//! entries were written by infrastructure the operator controls and everything
//! left of them is caller-supplied text.
//!
//! # Two tiers
//!
//! Authentication and account-creation endpoints get a tighter budget than
//! ordinary reads. A hundred `getRecord` calls a minute is a busy client; a
//! hundred `createSession` calls a minute is someone guessing.
//!
//! The per-identifier limits at the existing call sites are kept. They bound a
//! single account being attacked from many addresses, which a per-IP limit
//! cannot see. The finding was that they were the *only* limit, not that they
//! were the wrong one.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Request};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::http::errors::XrpcError;
use crate::security::SlidingWindowLimiter;

/// Route prefixes that get the tighter budget.
///
/// Everything here either mints a credential or consumes one, so a caller
/// making many attempts in a minute is doing something other than using the
/// service.
const AUTH_PATHS: [&str; 10] = [
    "/xrpc/com.atproto.server.createSession",
    "/xrpc/com.atproto.server.createAccount",
    "/xrpc/com.atproto.server.refreshSession",
    "/xrpc/com.atproto.server.requestPasswordReset",
    "/xrpc/com.atproto.server.resetPassword",
    "/oauth/token",
    "/oauth/par",
    // The OAuth endpoint that actually takes a password. `/oauth/token` and
    // `/oauth/par` were listed and this was not, so the two steps that consume
    // a credential were budgeted while the one that guesses at it ran at the
    // ordinary tier -- thousands of attempts per IP per window against a form
    // taking an identifier and a password.
    "/oauth/authorize",
    // Delegated sign-in. `begin` mints nothing by itself but is the most
    // expensive route this server has: one call fans out to DNS, a handle
    // resolution, a DID document, a second handle resolution, two metadata
    // documents and a pushed authorization request -- roughly six outbound
    // requests to hosts the caller names, each with its own timeout. At the
    // ordinary tier that is an amplifier pointed at third parties and a
    // connection-exhaustion lever pointed at this server.
    //
    // `callback` is the step that actually issues an authorization code, which
    // puts it in the same class as `/oauth/authorize` regardless of cost.
    "/oauth/delegation/begin",
    "/oauth/delegation/callback",
];

/// Operator-tunable rate-limit policy.
#[derive(Clone)]
pub struct RateLimitPolicy {
    /// Limiter for ordinary requests.
    global: SlidingWindowLimiter,
    /// Limiter for [`AUTH_PATHS`].
    auth: SlidingWindowLimiter,
    /// How many trusted proxies sit in front of this server.
    trusted_proxy_hops: usize,
    /// Addresses exempt from both limiters — a relay, an AppView, a backfill
    /// job. Without this an operator has to choose between limiting attackers
    /// and letting their own infrastructure work.
    bypass: Arc<HashSet<IpAddr>>,
    /// Per-address ceiling on concurrent `getRepo` exports. `getRepo` is exempt
    /// from the rate buckets (it is the sync path), but each call buffers a
    /// whole repo CAR in memory, so without this one address could hold open
    /// enough of them to exhaust the process and starve the global concurrency
    /// budget every other route shares. Keyed by address, shared across the
    /// policy's clones through the `Arc`.
    get_repo_inflight: Arc<dashmap::DashMap<IpAddr, Arc<tokio::sync::Semaphore>>>,
}

impl RateLimitPolicy {
    /// Build a policy from operator configuration.
    ///
    /// `global` and `auth` are pre-constructed so the caller chooses the
    /// backend — memory, SQL or Valkey — the same way the existing limiter
    /// does.
    #[must_use]
    pub fn new(
        global: SlidingWindowLimiter,
        auth: SlidingWindowLimiter,
        trusted_proxy_hops: usize,
        bypass: HashSet<IpAddr>,
    ) -> Self {
        Self {
            global,
            auth,
            trusted_proxy_hops,
            bypass: Arc::new(bypass),
            get_repo_inflight: Arc::new(dashmap::DashMap::new()),
        }
    }

    /// A permissive policy for tests and for `HttpState::minimal`.
    #[must_use]
    pub fn permissive() -> Self {
        Self::new(
            SlidingWindowLimiter::new(usize::MAX, Duration::from_secs(60), 1),
            SlidingWindowLimiter::new(usize::MAX, Duration::from_secs(60), 1),
            0,
            HashSet::new(),
        )
    }
}

/// Resolve the client address for a request.
///
/// Returns `None` when no address can be established, which the middleware
/// treats as "do not limit" rather than "reject": a request that reached a
/// handler without a peer address came from a test harness or an in-process
/// call, and refusing those would break the caller rather than an attacker.
#[must_use]
pub fn client_ip(request: &Request, trusted_proxy_hops: usize) -> Option<IpAddr> {
    client_ip_parts(request.headers(), request.extensions(), trusted_proxy_hops)
}

/// [`client_ip`] for a handler that has already destructured the request.
#[must_use]
pub fn client_ip_from_parts(
    parts: &axum::http::request::Parts,
    trusted_proxy_hops: usize,
) -> Option<IpAddr> {
    client_ip_parts(&parts.headers, &parts.extensions, trusted_proxy_hops)
}

fn client_ip_parts(
    headers: &axum::http::HeaderMap,
    extensions: &axum::http::Extensions,
    trusted_proxy_hops: usize,
) -> Option<IpAddr> {
    if trusted_proxy_hops > 0
        && let Some(header) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
    {
        // Each trusted proxy appended the address it saw, so the rightmost
        // `hops` entries are ours. The one we want is the address the
        // outermost trusted proxy observed: `hops` from the right.
        let entries: Vec<&str> = header.split(',').map(str::trim).collect();
        if entries.len() >= trusted_proxy_hops
            && let Some(candidate) = entries.get(entries.len() - trusted_proxy_hops)
            && let Ok(ip) = candidate.parse::<IpAddr>()
        {
            return Some(ip);
        }
        // A header that is too short or unparseable means the chain is not
        // what the operator described. Fall through to the peer address —
        // the one thing that cannot be forged — rather than trusting it.
    }
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

/// The repository export path, exempt from the shared bucket. See the
/// middleware for why.
const SYNC_GET_REPO_PATH: &str = "/xrpc/com.atproto.sync.getRepo";

/// Maximum concurrent `getRepo` exports one address may have in flight. A
/// caller over the ceiling gets a 429 to retry, not an outage; the number is
/// small because each export holds a whole repo CAR in memory at once.
const MAX_GET_REPO_INFLIGHT_PER_IP: usize = 4;

/// Whether a path belongs to the tighter auth tier.
#[must_use]
pub fn is_auth_path(path: &str) -> bool {
    AUTH_PATHS.contains(&path)
}

/// Middleware applying the policy to every request.
///
/// Runs before routing, so a path that matches no route is limited too — an
/// unauthenticated scan of a hundred nonexistent endpoints should cost the
/// scanner its budget.
pub async fn rate_limit_middleware(
    axum::extract::Extension(policy): axum::extract::Extension<RateLimitPolicy>,
    request: Request,
    next: Next,
) -> Response {
    let Some(ip) = client_ip(&request, policy.trusted_proxy_hops) else {
        return next.run(request).await;
    };
    if policy.bypass.contains(&ip) {
        return next.run(request).await;
    }

    let path = request.uri().path();

    // `getRepo` is the repository sync path: a full CAR export, called during
    // account migration and by any consumer backfilling this server. It is
    // high-volume by design and unrelated to the abuse the shared bucket
    // exists to bound, so charging it there means one migration can exhaust an
    // address's budget for everything else. The reference excludes it from its
    // global-ip bucket for the same reason (packages/pds/src/rate-limits.ts).
    if path == SYNC_GET_REPO_PATH {
        // Still outside the shared rate buckets, but bounded per address:
        // acquire a `getRepo` slot for this IP and hold it for the export. Over
        // the per-address ceiling is a 429 the caller retries, far better than an
        // unbounded pile of in-memory CAR builds from one source. The permit
        // releases when the request future completes.
        let semaphore = policy
            .get_repo_inflight
            .entry(ip)
            .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(MAX_GET_REPO_INFLIGHT_PER_IP)))
            .clone();
        let Ok(_permit) = semaphore.try_acquire_owned() else {
            tracing::debug!(ip = %ip, "getRepo per-address concurrency limit exceeded");
            return XrpcError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "RateLimited",
                "too many concurrent repository exports from this address; retry shortly",
            )
            .into_response();
        };
        return next.run(request).await;
    }

    let (limiter, key) = if is_auth_path(path) {
        (&policy.auth, format!("ip-auth:{ip}"))
    } else {
        (&policy.global, format!("ip:{ip}"))
    };

    if let Err(e) = limiter.try_acquire(&key).await {
        tracing::debug!(ip = %ip, path = %path, "rate limit exceeded");
        // `RateLimited` is the name this server has always used for a
        // rate-limit refusal. Aligning it with the lexicon's
        // `RateLimitExceeded`, and adding the `RateLimit-*` headers, is
        // F-OPS-17 and is deliberately not done here.
        return XrpcError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "RateLimited",
            format!("too many requests from this address; {e}"),
        )
        .into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    /// The repository export is exempt from the shared bucket.
    ///
    /// It is the sync path -- a full CAR -- used by account migration and by
    /// any consumer backfilling this server. Charging it to the same bucket as
    /// ordinary reads means one migration can exhaust an address's budget for
    /// everything else.
    #[test]
    fn get_repo_is_outside_the_shared_bucket() {
        assert_eq!(SYNC_GET_REPO_PATH, "/xrpc/com.atproto.sync.getRepo");
        // And it is not in the auth tier either -- it is exempt, not merely
        // moved to the tighter one.
        assert!(!is_auth_path(SYNC_GET_REPO_PATH));
    }

    fn request_with(xff: Option<&str>, peer: Option<&str>) -> Request {
        let mut builder = axum::http::Request::builder().uri("/xrpc/whatever");
        if let Some(v) = xff {
            builder = builder.header("x-forwarded-for", v);
        }
        let mut req = builder.body(Body::empty()).unwrap();
        if let Some(p) = peer {
            req.extensions_mut()
                .insert(ConnectInfo(p.parse::<SocketAddr>().unwrap()));
        }
        req
    }

    #[test]
    fn without_configured_hops_the_header_is_ignored() {
        // The whole point: a caller that sets its own `X-Forwarded-For` must
        // not get to choose its bucket.
        let req = request_with(Some("1.2.3.4"), Some("9.9.9.9:1234"));
        assert_eq!(
            client_ip(&req, 0),
            Some("9.9.9.9".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn hops_counts_from_the_right() {
        // Chain: client 1.1.1.1 → proxy A → proxy B → us. Proxy B appended
        // proxy A's address; proxy A appended the client's. With one trusted
        // proxy we believe what it saw, which is the last entry.
        let req = request_with(Some("1.1.1.1, 2.2.2.2, 3.3.3.3"), Some("9.9.9.9:1234"));
        assert_eq!(
            client_ip(&req, 1),
            Some("3.3.3.3".parse::<IpAddr>().unwrap()),
            "one hop must take the rightmost entry"
        );
        assert_eq!(
            client_ip(&req, 2),
            Some("2.2.2.2".parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            client_ip(&req, 3),
            Some("1.1.1.1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn a_forged_prefix_cannot_reach_past_the_trusted_hops() {
        // The client wrote the first two entries itself. With one trusted
        // proxy we still land on what that proxy observed.
        let req = request_with(Some("evil, 127.0.0.1, 5.5.5.5"), Some("9.9.9.9:1234"));
        assert_eq!(
            client_ip(&req, 1),
            Some("5.5.5.5".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn a_chain_shorter_than_configured_falls_back_to_the_peer() {
        // The operator said two proxies; the header shows one. Something is
        // not as described, so trust only what cannot be forged.
        let req = request_with(Some("1.1.1.1"), Some("9.9.9.9:1234"));
        assert_eq!(
            client_ip(&req, 2),
            Some("9.9.9.9".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn an_unparseable_entry_falls_back_to_the_peer() {
        let req = request_with(Some("not-an-address"), Some("9.9.9.9:1234"));
        assert_eq!(
            client_ip(&req, 1),
            Some("9.9.9.9".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn no_peer_and_no_header_yields_nothing() {
        let req = request_with(None, None);
        assert_eq!(client_ip(&req, 0), None);
        assert_eq!(client_ip(&req, 1), None);
    }

    #[test]
    fn the_auth_tier_covers_credential_endpoints_only() {
        assert!(is_auth_path("/xrpc/com.atproto.server.createSession"));
        assert!(is_auth_path("/oauth/token"));
        assert!(!is_auth_path("/xrpc/com.atproto.repo.getRecord"));
        // Prefix matching would put `createSessionSomething` in the auth tier;
        // exact matching is what keeps the tiers meaning what they say.
        assert!(!is_auth_path("/xrpc/com.atproto.server.createSessionX"));
    }

    /// Delegated sign-in belongs in the tight tier on both counts: `begin` is
    /// the most expensive route this server has, fanning out to half a dozen
    /// hosts the caller names, and `callback` issues an authorization code.
    ///
    /// The listing is hand-maintained, so this is the assertion that fails if
    /// somebody adds a delegation route and forgets it.
    #[test]
    fn delegated_sign_in_is_budgeted_as_an_auth_path() {
        assert!(is_auth_path("/oauth/delegation/begin"));
        assert!(is_auth_path("/oauth/delegation/callback"));
        // The two that only render or publish stay at the ordinary tier: one
        // is a static document a peer fetches, the other a page a browser is
        // redirected to, and budgeting them alongside credential issuance
        // would refuse ordinary use.
        assert!(!is_auth_path("/oauth/delegation/start"));
        assert!(!is_auth_path("/oauth/delegation/client-metadata.json"));
    }
}
