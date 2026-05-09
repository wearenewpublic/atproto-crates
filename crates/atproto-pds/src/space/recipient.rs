//! Consumer recipient discovery for `getSpaceCredential`.
//!
//! when a consumer service swaps a `MemberGrant`
//! for a `SpaceCredential`, the owner's PDS must record the consumer's
//! `(service_did, service_endpoint)` so the notifier knows where to fan
//! out future commits.
//!
//! The OAuth `client_id` is an HTTPS URL pointing at the consumer's
//! client metadata (an OAuth-2.1 + atproto convention). Derivation flow:
//!
//! 1. Extract the host (origin) from the `client_id` URL.
//! 2. Treat the host as a candidate atproto handle — fetch
//!    `https://<host>/.well-known/atproto-did` to learn the consumer's
//!    canonical DID.
//! 3. Resolve the DID document via `atproto_identity::plc::query` (for
//!    `did:plc`) or `atproto_identity::web::query` (for `did:web`).
//! 4. Pull the `AtprotoPersonalDataServer` service endpoint out of the
//!    DID document.
//! 5. Return `(did, endpoint)`.
//!
//! Any step failing falls back to a documented stub: `service_did =
//! grant.iss`, `service_endpoint = origin(client_id)`. The stub is
//! marked in the recipient row so operators can audit which entries are
//! provisional.

use crate::errors::{PdsError, PdsResult};
use atproto_identity::resolve::resolve_handle_http;

/// Resolved consumer identity, derivable from a MemberGrant + its
/// bearing `client_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRecipient {
    /// Consumer service DID (e.g. `did:web:appview.example`).
    pub service_did: String,
    /// HTTPS endpoint base (e.g. `https://appview.example`).
    pub service_endpoint: String,
    /// `true` when the resolution went through the full
    /// well-known-DID + DID-document path. `false` when it fell back to
    /// the `(grant.iss, client_id-origin)` stub.
    pub fully_resolved: bool,
}

/// Resolve the consumer's identity for the given grant + client_id.
///
/// Returns `Ok(ResolvedRecipient)` on every input; failures during
/// resolution fall back to the stub flagged with `fully_resolved=false`.
/// Network errors are logged at WARN.
pub async fn resolve_recipient(
    http: &reqwest::Client,
    grant_iss: &str,
    client_id: &str,
    plc_directory_hostname: Option<&str>,
) -> PdsResult<ResolvedRecipient> {
    let stub = stub_recipient(grant_iss, client_id);
    let Some(host) = client_id_origin_host(client_id) else {
        return Ok(stub);
    };

    // Step 2: candidate-handle resolution via .well-known/atproto-did.
    let did = match resolve_handle_http(http, &host).await {
        Ok(d) => d,
        Err(e) => {
            tracing::debug!(
                client_id = %client_id,
                host = %host,
                error = ?e,
                "consumer well-known DID resolve failed; falling back to stub"
            );
            return Ok(stub);
        }
    };

    // Step 3-4: fetch the DID document and extract atproto_pds endpoint.
    let endpoint = match fetch_atproto_pds_endpoint(http, &did, plc_directory_hostname).await {
        Ok(Some(ep)) => ep,
        Ok(None) => {
            tracing::debug!(
                client_id = %client_id,
                did = %did,
                "consumer DID document has no AtprotoPersonalDataServer service; falling back to stub"
            );
            return Ok(stub);
        }
        Err(e) => {
            tracing::debug!(
                client_id = %client_id,
                did = %did,
                error = ?e,
                "consumer DID document fetch failed; falling back to stub"
            );
            return Ok(stub);
        }
    };

    Ok(ResolvedRecipient {
        service_did: did,
        service_endpoint: endpoint,
        fully_resolved: true,
    })
}

async fn fetch_atproto_pds_endpoint(
    http: &reqwest::Client,
    did: &str,
    plc_directory_hostname: Option<&str>,
) -> PdsResult<Option<String>> {
    use atproto_identity::plc::query as plc_query;
    use atproto_identity::web::query as web_query;
    let document = if let Some(stripped) = did.strip_prefix("did:plc:") {
        let host = plc_directory_hostname.unwrap_or("plc.directory");
        let _ = stripped;
        plc_query(http, host, did)
            .await
            .map_err(|e| PdsError::Storage {
                reason: format!("plc query: {e}"),
            })?
    } else if did.starts_with("did:web:") {
        web_query(http, did).await.map_err(|e| PdsError::Storage {
            reason: format!("web query: {e}"),
        })?
    } else {
        // did:webvh and other methods aren't yet covered by the
        // recipient resolver — see. Surface a soft
        // failure so the stub kicks in.
        return Ok(None);
    };
    Ok(document.pds_endpoints().first().map(|s| s.to_string()))
}

/// Build the fallback recipient — used both as the result on failure
/// paths and as the documented behavior for unparseable client_id URLs.
#[must_use]
pub fn stub_recipient(grant_iss: &str, client_id: &str) -> ResolvedRecipient {
    let endpoint = client_id_origin(client_id).unwrap_or_else(|| client_id.to_string());
    ResolvedRecipient {
        service_did: grant_iss.to_string(),
        service_endpoint: endpoint,
        fully_resolved: false,
    }
}

/// Extract the scheme + host (+ optional port) of a URL. Returns `None`
/// if the input isn't `scheme://host[/...]`.
#[must_use]
pub fn client_id_origin(client_id: &str) -> Option<String> {
    let (scheme, rest) = client_id.split_once("://")?;
    if scheme.is_empty() || rest.is_empty() {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{authority}"))
}

/// Extract just the host portion of a `scheme://host[:port]/...` URL —
/// used for the well-known DID lookup which expects a bare host.
#[must_use]
pub fn client_id_origin_host(client_id: &str) -> Option<String> {
    let (_, rest) = client_id.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() {
        return None;
    }
    // Strip port if present — `resolve_handle_http` expects a hostname
    // without port for the well-known fetch. (HTTPS port is always 443.)
    let host = authority.split(':').next().unwrap_or(authority);
    Some(host.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_id_origin_parses() {
        assert_eq!(
            client_id_origin("https://app.example/cm.json").as_deref(),
            Some("https://app.example")
        );
        assert_eq!(
            client_id_origin("https://app.example:8443/cm.json").as_deref(),
            Some("https://app.example:8443")
        );
        assert_eq!(client_id_origin("notaurl").as_deref(), None);
        assert_eq!(client_id_origin("://noscheme").as_deref(), None);
    }

    #[test]
    fn client_id_origin_host_strips_port_and_scheme() {
        assert_eq!(
            client_id_origin_host("https://app.example/cm.json").as_deref(),
            Some("app.example")
        );
        assert_eq!(
            client_id_origin_host("https://app.example:8443/cm.json").as_deref(),
            Some("app.example")
        );
    }

    #[test]
    fn stub_recipient_uses_iss_and_origin() {
        let stub = stub_recipient("did:plc:alice", "https://app.example/cm.json");
        assert_eq!(stub.service_did, "did:plc:alice");
        assert_eq!(stub.service_endpoint, "https://app.example");
        assert!(!stub.fully_resolved);
    }

    /// Resolve against a hostname that has no `.well-known/atproto-did`
    /// served — the resolution falls through to the stub.
    #[tokio::test(flavor = "multi_thread")]
    async fn unreachable_well_known_falls_back_to_stub() {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(50))
            .build()
            .unwrap();
        // 192.0.2.0/24 is RFC 5737 documentation space; reliably unreachable.
        let r = resolve_recipient(&client, "did:plc:alice", "https://192.0.2.1/cm.json", None)
            .await
            .unwrap();
        assert!(!r.fully_resolved);
        assert_eq!(r.service_did, "did:plc:alice");
    }
}
