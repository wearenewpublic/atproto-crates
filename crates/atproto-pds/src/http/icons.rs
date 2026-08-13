//! Small icons for the NSID authorities a repository holds records from.
//!
//! The repository browser groups collections by the domain that publishes them,
//! and a favicon is what makes those groups scannable. This module fetches one,
//! caches it, and serves it from this origin.
//!
//! # Why proxy rather than hot-link
//!
//! The obvious implementation is `<img src="https://bsky.app/favicon.ico">`, and
//! it is the wrong one for a signed-in page. It would need the portal's
//! `Content-Security-Policy` opened to other origins, and then every NSID
//! authority in the account's repository learns each time the holder opens it —
//! from their IP, with their cookies for that host attached. Serving the bytes
//! from here keeps `img-src 'self'` and keeps the browser's conversation with
//! this server alone.
//!
//! # What is fetched, and what is refused
//!
//! The domain comes from an NSID in the account's own repository, so it is
//! caller-influenced: an account can write a record in any collection it likes
//! and make this server fetch the matching host. The same endpoint policy the
//! rest of the server applies to caller-supplied hosts applies here, which is
//! what keeps this from being an SSRF lever pointed at the network the PDS sits
//! in. Beyond that: HTTPS only, one redirect-free GET, a short timeout, a size
//! cap, and a content type from a fixed list.
//!
//! **SVG is refused even though browsers would render it.** An SVG is a
//! document that can carry script and external references; the safety of
//! rendering one in an `<img>` rests on browser behaviour rather than on
//! anything this server checks. Bitmaps cannot carry either, and every real
//! favicon is available as one.
//!
//! # When there is no favicon
//!
//! There always is one here: a monogram this server draws, in a hue derived
//! from the domain. That makes the icon column total — the page never shows a
//! broken image — and means the negative case costs one cache entry rather
//! than a fetch per page view.

use crate::http::errors::XrpcError;
use crate::http::portal::{esc, section_account};
use crate::http::state::HttpState;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use std::time::Duration;

/// How long a fetched icon is kept before it is looked up again.
pub const ICON_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// How many authorities' icons are held at once.
pub const ICON_CAPACITY: usize = 512;

/// Ceiling on a favicon's size. A favicon is a few kilobytes; anything past
/// this is not one, and is not worth holding in memory to find out.
const MAX_ICON_BYTES: usize = 64 * 1024;

/// How long the fetch may take before the drawn fallback is used instead.
const FETCH_TIMEOUT: Duration = Duration::from_secs(4);

/// Content types served back. Bitmaps only — see the module note on SVG.
const ALLOWED_TYPES: [&str; 4] = [
    "image/png",
    "image/x-icon",
    "image/vnd.microsoft.icon",
    "image/webp",
];

/// A cached icon: the bytes and the type to serve them as.
#[derive(Debug, Clone)]
pub struct Icon {
    /// Response body.
    pub bytes: Vec<u8>,
    /// `Content-Type` to serve.
    pub content_type: String,
}

/// `GET /account/repository/icon/{nsid}` — the icon for that NSID's authority.
///
/// Signed-in only. The icon says which authorities appear in an account's
/// repository, which is the account's business rather than the network's.
pub async fn icon(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(nsid): Path<String>,
) -> Result<Response, XrpcError> {
    if section_account(&state, &headers).await.is_err() {
        // No redirect: this is an image, and a browser asking for one wants a
        // status rather than a sign-in page rendered into an `<img>`.
        return Err(XrpcError::new(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "sign in to load repository icons",
        ));
    }

    let domain = crate::http::repository::nsid_domain(&nsid);
    let icon = resolve(&state, &domain).await;

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, icon.content_type.as_str()),
            // A day in the browser as well as in the cache here: an authority's
            // favicon is not news, and the request costs a round trip per group
            // per page without it.
            (header::CACHE_CONTROL, "private, max-age=86400"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        icon.bytes,
    )
        .into_response())
}

/// The icon for `domain`, from cache when possible.
async fn resolve(state: &HttpState, domain: &str) -> Icon {
    if let Some(cached) = state.icon_cache.get(domain) {
        return cached;
    }
    let icon = match fetch(domain).await {
        Some(fetched) => fetched,
        // A miss is cached like a hit. Without that, a domain with no favicon
        // is re-fetched every time the page is opened, which is the common case
        // rather than the rare one.
        None => monogram(domain),
    };
    state.icon_cache.put(domain, icon.clone());
    icon
}

/// Fetch `https://<domain>/favicon.ico`, or `None` for anything that is not a
/// small bitmap this server is willing to serve.
async fn fetch(domain: &str) -> Option<Icon> {
    // The host is derived from a record in the account's repository, so it is
    // chosen by whoever wrote that record. This is the same guard the recipient
    // resolver applies before dereferencing an attested `client_id`.
    if let Err(error) =
        atproto_identity::validation::validate_service_endpoint(&format!("https://{domain}"))
    {
        tracing::debug!(domain, error = ?error, "icon fetch refused: not a permitted host");
        return None;
    }

    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .user_agent(crate::user_agent())
        // A redirect is a second host to validate, and a favicon does not need
        // one. Following without re-checking is how a validated host becomes an
        // unvalidated fetch.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?;

    let response = client
        .get(format!("https://{domain}/favicon.ico"))
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }

    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(|v| v.trim().to_ascii_lowercase())?;
    if !ALLOWED_TYPES.contains(&content_type.as_str()) {
        tracing::debug!(
            domain,
            content_type,
            "icon fetch refused: not a served type"
        );
        return None;
    }

    // Declared length first, so an oversized body is refused before it is read.
    if response
        .content_length()
        .is_some_and(|n| n > MAX_ICON_BYTES as u64)
    {
        return None;
    }
    let bytes = response.bytes().await.ok()?;
    if bytes.is_empty() || bytes.len() > MAX_ICON_BYTES {
        return None;
    }

    Some(Icon {
        bytes: bytes.to_vec(),
        content_type,
    })
}

/// The drawn stand-in: the domain's initial on a hue derived from it.
///
/// An SVG this server generates, which is not the same risk as one it fetched:
/// the only text in it is a single escaped character.
fn monogram(domain: &str) -> Icon {
    let hash = domain.bytes().fold(0u32, |acc, b| {
        acc.wrapping_mul(31).wrapping_add(u32::from(b))
    });
    let hue = hash % 360;
    let initial = domain
        .chars()
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "?".to_string());
    let svg = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16">
<rect width="16" height="16" rx="4" fill="hsl({hue} 45% 88%)"/>
<text x="8" y="11.5" text-anchor="middle" font-family="sans-serif" font-size="10"
 font-weight="600" fill="hsl({hue} 55% 28%)">{}</text></svg>"##,
        esc(&initial)
    );
    Icon {
        bytes: svg.into_bytes(),
        content_type: "image/svg+xml".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_monogram_is_stable_and_distinct() {
        let a = monogram("bsky.app");
        assert_eq!(a.bytes, monogram("bsky.app").bytes);
        assert_ne!(a.bytes, monogram("badge.blue").bytes);
        assert_eq!(a.content_type, "image/svg+xml");
        assert!(String::from_utf8_lossy(&a.bytes).contains(">B<"));
    }

    /// The drawn icon carries one character of the domain and nothing else a
    /// domain could smuggle in.
    #[test]
    fn a_monogram_escapes_what_it_draws() {
        let icon = monogram("<script>.evil");
        let svg = String::from_utf8_lossy(&icon.bytes);
        assert!(!svg.contains("<script>"), "{svg}");
    }

    /// Hosts the endpoint policy refuses are never dereferenced, so the icon
    /// column cannot be turned into a probe of the network this server sits in.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_impermissible_host_is_not_fetched() {
        for hostile in ["169.254.169.254", "localhost", "10.0.0.5", "box.localhost"] {
            assert!(
                fetch(hostile).await.is_none(),
                "{hostile} should not be fetched"
            );
        }
    }
}
