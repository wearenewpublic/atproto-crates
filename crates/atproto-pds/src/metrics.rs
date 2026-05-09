//! Prometheus exporter.
//!
//! When the `metrics` feature is enabled and `PDS_METRICS_BIND` is set,
//! the binary mounts a `GET /metrics` route on the main HTTP listener
//! and an axum middleware records per-route request counters + status
//! code histograms. The output format is the standard
//! `text/plain; version=0.0.4; charset=utf-8` Prometheus text format
//! (per OpenMetrics §3.2 — what `prometheus-client::encoding::text`
//! emits).
//!
//! The exporter does NOT bind a separate listener. Operators front
//! the PDS with a reverse proxy and ACL `/metrics` to the metrics
//! scrape network there. The `--metrics-bind` flag exists for
//! parity with the original §5.1 spec; today it gates whether the
//! handler is mounted, not which interface it listens on.
//!
//! The middleware is intentionally low-cardinality: labels are
//! `(method, route_template)` only — never raw paths — so cardinality
//! stays bounded as the route table grows. Status codes go on a
//! separate counter to avoid blowing up the matrix.

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::encoding::text::encode as encode_text;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use std::sync::Arc;

/// Per-route request counter labels — `(method, route)` only. Status
/// codes live on a sibling counter so the cardinality of a single
/// metric line stays constant in the route count.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RequestLabels {
    /// HTTP method (`GET`, `POST`, etc.).
    pub method: String,
    /// Axum route-template path (e.g. `/xrpc/com.atproto.repo.getRecord`).
    /// Never the raw path — that would explode cardinality.
    pub route: String,
}

/// Per-status response counter labels — same `(method, route)` join
/// keys plus the response status code.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ResponseLabels {
    /// HTTP method.
    pub method: String,
    /// Route template.
    pub route: String,
    /// Numeric HTTP status code.
    pub status: u16,
}

/// Metrics handle — clone-able pointer to the shared registry +
/// counter families.
#[derive(Clone)]
pub struct Metrics {
    inner: Arc<MetricsInner>,
}

struct MetricsInner {
    registry: Registry,
    requests: Family<RequestLabels, Counter>,
    responses: Family<ResponseLabels, Counter>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    /// Build a fresh registry with the default counter families
    /// registered.
    #[must_use]
    pub fn new() -> Self {
        let mut registry = Registry::default();
        let requests = Family::<RequestLabels, Counter>::default();
        let responses = Family::<ResponseLabels, Counter>::default();
        registry.register(
            "atproto_pds_http_requests",
            "Total HTTP requests received, labeled by method + route template.",
            requests.clone(),
        );
        registry.register(
            "atproto_pds_http_responses",
            "Total HTTP responses emitted, labeled by method + route + status code.",
            responses.clone(),
        );
        Self {
            inner: Arc::new(MetricsInner {
                registry,
                requests,
                responses,
            }),
        }
    }

    /// Record a single request begin (called from middleware before
    /// the handler runs).
    pub fn record_request(&self, method: &str, route: &str) {
        self.inner
            .requests
            .get_or_create(&RequestLabels {
                method: method.to_string(),
                route: route.to_string(),
            })
            .inc();
    }

    /// Record a single response (called from middleware after the
    /// handler returns).
    pub fn record_response(&self, method: &str, route: &str, status: u16) {
        self.inner
            .responses
            .get_or_create(&ResponseLabels {
                method: method.to_string(),
                route: route.to_string(),
                status,
            })
            .inc();
    }

    /// Encode the current registry to Prometheus text format.
    /// Returns `(content_type, body)` for the response.
    #[must_use]
    pub fn export(&self) -> (&'static str, String) {
        let mut buf = String::new();
        // The encoder errors are infallible for `String` writers — `expect`
        // is safe.
        encode_text(&mut buf, &self.inner.registry).expect("encode prometheus text format");
        (
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
            buf,
        )
    }
}

/// Axum handler — `GET /metrics`. Returns the Prometheus text output
/// from the shared `Metrics` registry. Stateless aside from the
/// `Metrics` extractor.
#[cfg(feature = "http")]
pub async fn metrics_handler(
    axum::extract::Extension(metrics): axum::extract::Extension<Metrics>,
) -> axum::response::Response {
    use axum::http::header;
    use axum::response::IntoResponse;
    let (ct, body) = metrics.export();
    ([(header::CONTENT_TYPE, ct)], body).into_response()
}

/// Axum middleware — increments request + response counters around
/// the handler. The route template is the matched router pattern when
/// available (`MatchedPath`), otherwise the raw URI path is used as
/// a fall-back.
#[cfg(feature = "http")]
pub async fn metrics_middleware(
    axum::extract::Extension(metrics): axum::extract::Extension<Metrics>,
    matched: Option<axum::extract::MatchedPath>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = request.method().clone();
    let route = matched
        .as_ref()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());
    metrics.record_request(method.as_str(), &route);
    let response = next.run(request).await;
    metrics.record_response(method.as_str(), &route, response.status().as_u16());
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_metrics_export_lists_counter_families() {
        let metrics = Metrics::new();
        let (ct, body) = metrics.export();
        assert!(ct.starts_with("application/openmetrics-text"));
        assert!(body.contains("atproto_pds_http_requests"));
        assert!(body.contains("atproto_pds_http_responses"));
    }

    #[test]
    fn record_request_then_export_includes_increment() {
        let metrics = Metrics::new();
        metrics.record_request("GET", "/xrpc/_health");
        metrics.record_request("GET", "/xrpc/_health");
        metrics.record_response("GET", "/xrpc/_health", 200);
        let (_ct, body) = metrics.export();
        // The counter line should show the 2-request, 1-response totals.
        assert!(
            body.contains(
                r#"atproto_pds_http_requests_total{method="GET",route="/xrpc/_health"} 2"#
            ),
            "missing request counter, got: {body}"
        );
        assert!(
            body.contains(
                r#"atproto_pds_http_responses_total{method="GET",route="/xrpc/_health",status="200"} 1"#
            ),
            "missing response counter, got: {body}"
        );
    }

    #[test]
    fn distinct_routes_get_distinct_lines() {
        let metrics = Metrics::new();
        metrics.record_request("GET", "/xrpc/a");
        metrics.record_request("POST", "/xrpc/b");
        let (_ct, body) = metrics.export();
        assert!(body.contains(r#"method="GET",route="/xrpc/a""#));
        assert!(body.contains(r#"method="POST",route="/xrpc/b""#));
    }
}
