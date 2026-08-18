//! URL construction utilities leveraging the `url` crate.
//!
//! Provides helpers for building URLs and appending query parameters
//! without manual string concatenation.

use url::{ParseError, Url};

/// Builds a URL from the provided components.
/// Returns `Result<Url, ParseError>` to surface parsing errors.
pub fn build_url<K, V, I>(host: &str, path: &str, params: I) -> Result<Url, ParseError>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let mut base = if host.starts_with("http://") || host.starts_with("https://") {
        Url::parse(host)?
    } else {
        Url::parse(&format!("https://{}", host))?
    };

    if !base.path().ends_with('/') {
        let mut new_path = base.path().to_string();
        if !new_path.ends_with('/') {
            new_path.push('/');
        }
        if new_path.is_empty() {
            new_path.push('/');
        }
        base.set_path(&new_path);
    }

    let mut url = base.join(path.trim_start_matches('/'))?;
    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in params {
            pairs.append_pair(key.as_ref(), value.as_ref());
        }
    }
    // `query_pairs_mut` sets the query to the empty string whether or not
    // anything was appended, so a call with no parameters came out with a
    // trailing `?`. Legal, and every HTTP server accepts it -- but it appeared
    // in every parameterless URL this workspace builds, including the
    // WebSocket URL for `subscribeRepos`, where the set of servers that accept
    // it is smaller.
    if url.query() == Some("") {
        url.set_query(None);
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No parameters means no query, rather than a bare `?`.
    #[test]
    fn a_parameterless_url_has_no_query() {
        let url = build_url(
            "example.com",
            "/xrpc/com.atproto.repo.applyWrites",
            std::iter::empty::<(&str, &str)>(),
        )
        .expect("url build failed");

        assert_eq!(
            url.as_str(),
            "https://example.com/xrpc/com.atproto.repo.applyWrites"
        );
    }

    #[test]
    fn builds_url_with_params() {
        let url = build_url(
            "example.com/api",
            "resource",
            [("id", "123"), ("status", "active")],
        )
        .expect("url build failed");

        assert_eq!(
            url.as_str(),
            "https://example.com/api/resource?id=123&status=active"
        );
    }
}
