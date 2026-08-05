//! Client identification and `redirect_uri` validation.
//!
//! In AT Protocol OAuth a `client_id` is not an opaque registration handle: it
//! is the URL of the client's own metadata document, which declares — among
//! other things — the exact set of `redirect_uris` the authorization server may
//! send an authorization code to. Resolving that document and checking the
//! requested redirect against it is the only thing standing between a
//! legitimate, user-trusted `client_id` and an attacker-chosen destination for
//! the code issued under it.
//!
//! Two client shapes exist, and the distinction is part of the specification
//! rather than a convenience:
//!
//! - **Discoverable clients** publish an HTTPS metadata document at their
//!   `client_id`. The document is fetched and its `redirect_uris` are
//!   authoritative.
//! - **Loopback clients** — native and development clients — use a `client_id`
//!   of the form `http://localhost[/][?scope=…&redirect_uri=…]`. Nothing is
//!   fetched: the `client_id` *is* the metadata, and its query string carries
//!   the permitted redirects. Absent an explicit `redirect_uri` parameter, the
//!   permitted set is `http://127.0.0.1/` and `http://[::1]/`.
//!
//! # Security
//!
//! The discoverable fetch takes an unauthenticated caller's URL and asks the
//! server to retrieve it, which is an SSRF sink. Every such URL — the
//! `client_id` itself and any `jwks_uri` reached through it — passes
//! [`atproto_identity::validation::validate_service_endpoint`] first, which
//! rejects non-HTTPS schemes, address literals in every resolver-accepted form,
//! embedded userinfo, non-443 ports and reserved suffixes. That guard is
//! syntactic: it does not resolve DNS, so it does not defend against rebinding
//! or a public name pointing into a private range.

use std::time::Duration;

use atproto_identity::validation::validate_service_endpoint;
use serde::Deserialize;

/// Redirect URIs permitted for a loopback client that names none explicitly.
///
/// `localhost` is deliberately absent: it may resolve to an address other than
/// the loopback interface, so the specification directs clients to bind an
/// explicit loopback address instead.
pub const DEFAULT_LOOPBACK_REDIRECT_URIS: &[&str] = &["http://127.0.0.1/", "http://[::1]/"];

/// Origin prefix identifying a loopback `client_id`.
const LOOPBACK_CLIENT_ID_ORIGIN: &str = "http://localhost";

/// How long to wait for a client metadata or JWKS fetch.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// The parts of a client metadata document this server acts on.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ClientMetadata {
    /// The document's self-declared identifier. Must equal the URL it was
    /// fetched from; a mismatch means the document does not belong to the
    /// client being claimed.
    #[serde(default)]
    pub client_id: Option<String>,
    /// Every redirect destination this client may receive a code at.
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    /// Inline JWKS, if published directly in the document.
    #[serde(default)]
    pub jwks: Option<serde_json::Value>,
    /// URL of the client's JWKS, if published by reference.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// The grant types this client declares it will use.
    ///
    /// Read because `response_type=code` is a request to use the
    /// authorization-code grant, and a client that did not declare it is
    /// asking for something it never registered for.
    #[serde(default)]
    pub grant_types: Vec<String>,
    /// The scopes this client declares, space-separated.
    ///
    /// The bound on what it may request. Absent means it declared none, and a
    /// request for any scope is then unregistered.
    #[serde(default)]
    pub scope: Option<String>,
    /// How the client authenticates at the token endpoint.
    ///
    /// `none` is a public client. Anything else is a confidential one, which
    /// has to publish keys to authenticate with.
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
}

/// Why a client could not be resolved or a redirect could not be accepted.
#[derive(Debug, thiserror::Error)]
pub enum ClientMetadataError {
    /// The `client_id` is not a URL this server will dereference.
    #[error("error-atproto-pds-oauth-1 Client ID rejected: {client_id} {details}")]
    UnsafeClientId {
        /// The rejected `client_id`.
        client_id: String,
        /// Why the URL policy rejected it.
        details: String,
    },

    /// The loopback `client_id` is malformed.
    #[error("error-atproto-pds-oauth-2 Invalid loopback client ID: {client_id} {details}")]
    InvalidLoopbackClientId {
        /// The rejected `client_id`.
        client_id: String,
        /// Which rule it broke.
        details: String,
    },

    /// The metadata document could not be retrieved or parsed.
    #[error("error-atproto-pds-oauth-3 Client metadata unavailable: {client_id} {details}")]
    Unavailable {
        /// The `client_id` that was fetched.
        client_id: String,
        /// The transport or parse failure.
        details: String,
    },

    /// The document's `client_id` disagrees with the URL it was fetched from.
    #[error(
        "error-atproto-pds-oauth-4 Client metadata client_id mismatch: {client_id} document declares {declared}"
    )]
    ClientIdMismatch {
        /// The `client_id` requested.
        client_id: String,
        /// The `client_id` the document declared.
        declared: String,
    },

    /// The requested redirect is not one the client published.
    #[error(
        "error-atproto-pds-oauth-5 redirect_uri not registered for client: {client_id} {redirect_uri}"
    )]
    RedirectUriNotRegistered {
        /// The client whose metadata was consulted.
        client_id: String,
        /// The redirect the caller asked for.
        redirect_uri: String,
    },
}

/// True when `client_id` names a loopback client rather than a discoverable one.
#[must_use]
pub fn is_loopback_client_id(client_id: &str) -> bool {
    client_id.starts_with(LOOPBACK_CLIENT_ID_ORIGIN)
}

/// Derive a loopback client's metadata from its `client_id`.
///
/// Nothing is fetched. The query string may carry `scope` and any number of
/// `redirect_uri` parameters; no other parameter is accepted, and no path or
/// fragment component is permitted.
///
/// # Errors
///
/// Returns [`ClientMetadataError::InvalidLoopbackClientId`] when the identifier
/// carries a fragment, a path beyond a single `/`, or an unrecognised query
/// parameter.
pub fn loopback_client_metadata(client_id: &str) -> Result<ClientMetadata, ClientMetadataError> {
    let invalid = |details: &str| ClientMetadataError::InvalidLoopbackClientId {
        client_id: client_id.to_string(),
        details: details.to_string(),
    };

    let rest = &client_id[LOOPBACK_CLIENT_ID_ORIGIN.len()..];
    if rest.contains('#') {
        return Err(invalid("must not contain a fragment"));
    }
    let query = match rest.strip_prefix('/').unwrap_or(rest) {
        "" => "",
        other => other
            .strip_prefix('?')
            .ok_or_else(|| invalid("must not contain a path component"))?,
    };

    let mut redirect_uris = Vec::new();
    if !query.is_empty() {
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "redirect_uri" => redirect_uris.push(value.into_owned()),
                "scope" => {}
                other => return Err(invalid(&format!("unexpected query parameter {other:?}"))),
            }
        }
    }
    if redirect_uris.is_empty() {
        redirect_uris = DEFAULT_LOOPBACK_REDIRECT_URIS
            .iter()
            .map(|uri| (*uri).to_string())
            .collect();
    }

    Ok(ClientMetadata {
        client_id: Some(client_id.to_string()),
        redirect_uris,
        jwks: None,
        jwks_uri: None,
        // The loopback development client declares nothing, and an empty
        // declaration is read as "unconstrained" by the checks in `par` --
        // which is right here: there is no document to contradict.
        grant_types: Vec::new(),
        scope: None,
        token_endpoint_auth_method: None,
    })
}

/// Resolve a client's metadata, fetching it when the client is discoverable.
///
/// # Errors
///
/// Returns [`ClientMetadataError`] when the `client_id` fails the URL policy,
/// the document cannot be retrieved or parsed, or the document's own
/// `client_id` disagrees with the URL it came from.
pub async fn resolve_client_metadata(
    client_id: &str,
    user_agent: &str,
) -> Result<ClientMetadata, ClientMetadataError> {
    if is_loopback_client_id(client_id) {
        return loopback_client_metadata(client_id);
    }

    validate_service_endpoint(client_id).map_err(|err| ClientMetadataError::UnsafeClientId {
        client_id: client_id.to_string(),
        details: err.to_string(),
    })?;

    let http = reqwest::Client::builder()
        .user_agent(user_agent)
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|err| ClientMetadataError::Unavailable {
            client_id: client_id.to_string(),
            details: format!("build http client: {err}"),
        })?;

    let metadata: ClientMetadata = http
        .get(client_id)
        .send()
        .await
        .map_err(|err| ClientMetadataError::Unavailable {
            client_id: client_id.to_string(),
            details: format!("fetch: {err}"),
        })?
        .error_for_status()
        .map_err(|err| ClientMetadataError::Unavailable {
            client_id: client_id.to_string(),
            details: format!("status: {err}"),
        })?
        .json()
        .await
        .map_err(|err| ClientMetadataError::Unavailable {
            client_id: client_id.to_string(),
            details: format!("parse json: {err}"),
        })?;

    if let Some(declared) = metadata.client_id.as_deref()
        && declared != client_id
    {
        return Err(ClientMetadataError::ClientIdMismatch {
            client_id: client_id.to_string(),
            declared: declared.to_string(),
        });
    }

    Ok(metadata)
}

/// Fetch a client's JWKS, whether published inline or by reference.
///
/// # Errors
///
/// Returns [`ClientMetadataError`] when the document publishes neither form, or
/// when a `jwks_uri` fails the URL policy or cannot be retrieved.
pub async fn resolve_client_jwks(
    client_id: &str,
    metadata: &ClientMetadata,
    user_agent: &str,
) -> Result<serde_json::Value, ClientMetadataError> {
    if let Some(jwks) = metadata.jwks.clone() {
        return Ok(jwks);
    }
    let uri = metadata
        .jwks_uri
        .as_deref()
        .ok_or_else(|| ClientMetadataError::Unavailable {
            client_id: client_id.to_string(),
            details: "client metadata has neither `jwks` nor `jwks_uri`".to_string(),
        })?;

    validate_service_endpoint(uri).map_err(|err| ClientMetadataError::UnsafeClientId {
        client_id: uri.to_string(),
        details: err.to_string(),
    })?;

    let http = reqwest::Client::builder()
        .user_agent(user_agent)
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|err| ClientMetadataError::Unavailable {
            client_id: uri.to_string(),
            details: format!("build http client: {err}"),
        })?;

    http.get(uri)
        .send()
        .await
        .map_err(|err| ClientMetadataError::Unavailable {
            client_id: uri.to_string(),
            details: format!("fetch jwks_uri: {err}"),
        })?
        .json()
        .await
        .map_err(|err| ClientMetadataError::Unavailable {
            client_id: uri.to_string(),
            details: format!("parse jwks_uri json: {err}"),
        })
}

/// Check a requested redirect against the client's registered set.
///
/// Comparison is exact string equality, as RFC 6749 §3.1.2.3 requires: prefix
/// or host-only matching is what turns a registered `https://app.example/cb`
/// into an accepted `https://app.example.attacker.test/cb`.
///
/// # Errors
///
/// Returns [`ClientMetadataError::RedirectUriNotRegistered`] when the client
/// published no redirects at all, or none equal to the one requested.
pub fn assert_redirect_uri_registered(
    client_id: &str,
    metadata: &ClientMetadata,
    redirect_uri: &str,
) -> Result<(), ClientMetadataError> {
    if metadata
        .redirect_uris
        .iter()
        .any(|registered| registered == redirect_uri)
    {
        return Ok(());
    }
    Err(ClientMetadataError::RedirectUriNotRegistered {
        client_id: client_id.to_string(),
        redirect_uri: redirect_uri.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata_with(uris: &[&str]) -> ClientMetadata {
        ClientMetadata {
            grant_types: Vec::new(),
            scope: None,
            token_endpoint_auth_method: None,
            client_id: Some("https://app.example/client-metadata.json".to_string()),
            redirect_uris: uris.iter().map(|u| (*u).to_string()).collect(),
            jwks: None,
            jwks_uri: None,
        }
    }

    #[test]
    fn accepts_an_exactly_registered_redirect() {
        let metadata = metadata_with(&["https://app.example/cb"]);
        assert!(
            assert_redirect_uri_registered(
                "https://app.example/client-metadata.json",
                &metadata,
                "https://app.example/cb",
            )
            .is_ok()
        );
    }

    /// The exfiltration step: a genuine `client_id` with someone else's redirect.
    #[test]
    fn rejects_an_unregistered_redirect() {
        let metadata = metadata_with(&["https://app.example/cb"]);
        let err = assert_redirect_uri_registered(
            "https://app.example/client-metadata.json",
            &metadata,
            "https://attacker.test/steal",
        )
        .expect_err("unregistered redirect must be rejected");
        assert!(matches!(
            err,
            ClientMetadataError::RedirectUriNotRegistered { .. }
        ));
    }

    /// Matching must be exact, not prefix-based.
    #[test]
    fn rejects_a_suffix_extended_host() {
        let metadata = metadata_with(&["https://app.example/cb"]);
        for candidate in [
            "https://app.example.attacker.test/cb",
            "https://app.example/cb/../../evil",
            "https://app.example/cb?next=https://attacker.test",
            "https://app.example/cbx",
        ] {
            assert!(
                assert_redirect_uri_registered(
                    "https://app.example/client-metadata.json",
                    &metadata,
                    candidate,
                )
                .is_err(),
                "{candidate} must not match a registered https://app.example/cb"
            );
        }
    }

    #[test]
    fn rejects_when_no_redirects_are_registered() {
        let metadata = metadata_with(&[]);
        assert!(
            assert_redirect_uri_registered(
                "https://app.example/client-metadata.json",
                &metadata,
                "https://app.example/cb",
            )
            .is_err()
        );
    }

    #[test]
    fn loopback_without_query_uses_the_default_redirects() {
        let metadata = loopback_client_metadata("http://localhost").unwrap();
        assert_eq!(metadata.redirect_uris, DEFAULT_LOOPBACK_REDIRECT_URIS);
        let with_slash = loopback_client_metadata("http://localhost/").unwrap();
        assert_eq!(with_slash.redirect_uris, DEFAULT_LOOPBACK_REDIRECT_URIS);
    }

    #[test]
    fn loopback_query_declares_its_redirects() {
        let metadata = loopback_client_metadata(
            "http://localhost?scope=atproto&redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Fcb",
        )
        .unwrap();
        assert_eq!(metadata.redirect_uris, vec!["http://127.0.0.1:8080/cb"]);
        assert!(
            assert_redirect_uri_registered(
                "http://localhost",
                &metadata,
                "http://127.0.0.1:8080/cb"
            )
            .is_ok()
        );
        assert!(
            assert_redirect_uri_registered("http://localhost", &metadata, "http://127.0.0.1/")
                .is_err(),
            "declaring a redirect replaces the defaults rather than adding to them"
        );
    }

    #[test]
    fn loopback_rejects_paths_fragments_and_unknown_parameters() {
        for bad in [
            "http://localhost/callback",
            "http://localhost#frag",
            "http://localhost?client_secret=hunter2",
        ] {
            assert!(
                loopback_client_metadata(bad).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn discoverable_client_id_must_survive_the_url_policy() {
        for hostile in [
            "http://169.254.169.254/client-metadata.json",
            "https://169.254.169.254/client-metadata.json",
            "https://2852039166/client-metadata.json",
            "https://user:pw@app.example/client-metadata.json",
            "https://metadata.google.internal/client-metadata.json",
        ] {
            let err = resolve_client_metadata(hostile, "test")
                .await
                .expect_err("{hostile} must be rejected before any request is made");
            assert!(
                matches!(err, ClientMetadataError::UnsafeClientId { .. }),
                "{hostile} produced {err:?}"
            );
        }
    }
}
