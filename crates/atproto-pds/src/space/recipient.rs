//! Consumer recipient discovery for `getSpaceCredential`.
//!
//! When a consumer service swaps a delegation token
//! for a `SpaceCredential`, the authority's PDS must record the consumer's
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
use atproto_identity::validation::validate_service_endpoint;

/// Resolved consumer identity, derivable from a delegation token's issuer +
/// the attested `client_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRecipient {
    /// Consumer service DID (e.g. `did:web:appview.example`).
    pub service_did: String,
    /// HTTPS endpoint base (e.g. `https://appview.example`), or `None` when
    /// resolution produced no endpoint to deliver to. Never a DID or any other
    /// non-URL: a value here is something the notifier can POST to.
    pub service_endpoint: Option<String>,
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

    // `client_id` reaches here from a client attestation, so the host below is
    // attacker-chosen and this function is about to fetch it — twice, counting
    // the DID document. The same endpoint policy the attestation verifier
    // applies to `client_id` applies here, because a host that policy refuses
    // is exactly the one worth refusing to dereference.
    //
    // Resolution failures fall back to the stub by design, so a refusal is
    // logged: otherwise a guarded host and an unreachable one look identical
    // from the outside, including to whoever is debugging it.
    if let Err(err) = validate_service_endpoint(&format!("https://{host}")) {
        tracing::warn!(
            client_id = %client_id,
            host = %host,
            error = ?err,
            "recipient resolution refused: client_id host is not a permitted endpoint"
        );
        return Ok(stub);
    }

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
        service_endpoint: Some(endpoint),
        fully_resolved: true,
    })
}

async fn fetch_atproto_pds_endpoint(
    http: &reqwest::Client,
    did: &str,
    plc_directory_hostname: Option<&str>,
) -> PdsResult<Option<String>> {
    let Some(document) = fetch_did_document(http, did, plc_directory_hostname).await? else {
        return Ok(None);
    };
    Ok(document.pds_endpoints().first().map(|s| s.to_string()))
}

/// Fetch a DID document for `did:plc:`/`did:web:`, returning `None` for
/// unsupported methods (e.g. `did:webvh`).
async fn fetch_did_document(
    http: &reqwest::Client,
    did: &str,
    plc_directory_hostname: Option<&str>,
) -> PdsResult<Option<atproto_identity::model::Document>> {
    use atproto_identity::plc::query as plc_query;
    use atproto_identity::web::query as web_query;
    let document = if did.starts_with("did:plc:") {
        let host = plc_directory_hostname.unwrap_or("plc.directory");
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
        // did:webvh and other methods aren't yet covered.
        return Ok(None);
    };
    Ok(Some(document))
}

/// Resolve a service identifier of the form `<did>#<fragment>` (e.g.
/// `did:web:example.com#forum`) to the service's base endpoint URL by fetching
/// the DID document and matching the service entry by fragment.
///
/// Returns `Ok(None)` when the DID method is unsupported, the document has no
/// matching service entry, or the identifier is malformed.
///
/// # Errors
/// Returns [`PdsError::Storage`] on a DID-document fetch failure.
pub async fn resolve_service_endpoint(
    http: &reqwest::Client,
    service_id: &str,
    plc_directory_hostname: Option<&str>,
) -> PdsResult<Option<String>> {
    let (did, fragment) = match service_id.split_once('#') {
        Some((did, frag)) => (did, Some(frag)),
        None => (service_id, None),
    };
    let Some(document) = fetch_did_document(http, did, plc_directory_hostname).await? else {
        return Ok(None);
    };
    // Match the service whose `id` ends with the requested fragment
    // (DID documents render service ids as `<did>#frag` or `#frag`).
    let endpoint = document.service.iter().find_map(|svc| match fragment {
        Some(frag) => {
            let svc_frag = svc.id.rsplit('#').next().unwrap_or(svc.id.as_str());
            (svc_frag == frag).then(|| svc.service_endpoint.clone())
        }
        None => Some(svc.service_endpoint.clone()),
    });
    Ok(endpoint)
}

/// Build the fallback recipient — used both as the result on failure
/// paths and as the documented behavior for unparseable client_id URLs.
///
/// `service_endpoint` is `None` when `client_id` carries no origin to fall back
/// to. It used to be the `client_id` string verbatim, which meant a `client_id`
/// that was not a URL at all — the member's own DID, on the no-attestation path
/// — was stored as the endpoint. Nothing rejected it at registration, and the
/// notifier then refused that endpoint on every single write to the space:
/// `endpoint=did:plc:… Endpoint scheme must be https`. The subscriber was
/// registered and could never be delivered to.
///
/// A stub with no endpoint is the honest result. Whether that is worth a refusal
/// or a skip belongs to the caller, which knows what it was asked to register.
#[must_use]
pub fn stub_recipient(grant_iss: &str, client_id: &str) -> ResolvedRecipient {
    ResolvedRecipient {
        service_did: grant_iss.to_string(),
        service_endpoint: client_id_origin(client_id),
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
        assert_eq!(
            stub.service_endpoint.as_deref(),
            Some("https://app.example")
        );
        assert!(!stub.fully_resolved);
    }

    /// A `client_id` that is not a URL yields no endpoint rather than itself.
    ///
    /// The no-attestation path passed the member's DID here, and the DID came
    /// back as the endpoint. It was stored, and the notifier then refused it on
    /// every write to the space — a subscriber registered and unreachable.
    #[test]
    fn a_client_id_that_is_not_a_url_yields_no_endpoint() {
        for not_a_url in ["did:plc:alice", "", "notaurl", "://noscheme"] {
            let stub = stub_recipient("did:plc:alice", not_a_url);
            assert_eq!(
                stub.service_endpoint, None,
                "{not_a_url} was turned into an endpoint"
            );
        }
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

    /// A `client_id` host the endpoint policy refuses is never dereferenced.
    ///
    /// This function falls back to a stub on any resolution failure, so an
    /// unreachable host and a refused one produce the same return value. The
    /// assertion is therefore on the emitted event, which is the only thing
    /// that distinguishes "we declined to ask" from "we asked and it failed".
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unsafe_client_id_host_is_not_dereferenced() {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::Layer;
        use tracing_subscriber::layer::{Context, SubscriberExt};

        #[derive(Clone, Default)]
        struct Collector(Arc<Mutex<Vec<String>>>);

        impl<S: tracing::Subscriber> Layer<S> for Collector {
            fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
                self.0
                    .lock()
                    .unwrap()
                    .push(format!("{:?}", event.metadata().name()));
                struct Msg(Arc<Mutex<Vec<String>>>);
                impl tracing::field::Visit for Msg {
                    fn record_debug(
                        &mut self,
                        field: &tracing::field::Field,
                        value: &dyn std::fmt::Debug,
                    ) {
                        if field.name() == "message" {
                            self.0.lock().unwrap().push(format!("{value:?}"));
                        }
                    }
                }
                event.record(&mut Msg(self.0.clone()));
            }
        }

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(1))
            .build()
            .unwrap();

        for hostile in [
            "https://169.254.169.254/cm.json",
            "https://2852039166/cm.json",
            "https://admin.internal/cm.json",
            "https://box.localhost/cm.json",
        ] {
            let collector = Collector::default();
            let subscriber = tracing_subscriber::registry().with(collector.clone());
            let guard = tracing::subscriber::set_default(subscriber);
            let resolved = resolve_recipient(&http, "did:plc:alice", hostile, None)
                .await
                .expect("resolution always yields a recipient");
            drop(guard);

            assert!(
                !resolved.fully_resolved,
                "{hostile} should not resolve to a real recipient"
            );
            let events = collector.0.lock().unwrap().join(" ");
            assert!(
                events.contains("not a permitted endpoint"),
                "{hostile} was not refused by the endpoint policy — it was \
                 dereferenced and failed on the network instead: {events}"
            );
        }
    }
}
