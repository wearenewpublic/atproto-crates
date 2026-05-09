//! — `metrics` feature acceptance.
//!
//! When the `metrics` feature is compiled in, the Prometheus exporter
//! emits counter families and the axum middleware records per-route
//! request + response counters. This test exercises the gated
//! symbols so CI proves the build path lights up under
//! `cargo test --features metrics`.

#[cfg(feature = "metrics")]
#[test]
fn metrics_export_round_trip_increments_counters() {
    use atproto_pds::metrics::Metrics;

    let metrics = Metrics::new();
    metrics.record_request("GET", "/xrpc/_health");
    metrics.record_response("GET", "/xrpc/_health", 200);

    let (ct, body) = metrics.export();
    assert!(
        ct.starts_with("application/openmetrics-text"),
        "wrong content-type: {ct}"
    );
    assert!(
        body.contains("atproto_pds_http_requests_total"),
        "missing requests counter family in: {body}"
    );
    assert!(
        body.contains("atproto_pds_http_responses_total"),
        "missing responses counter family in: {body}"
    );
    assert!(
        body.contains(r#"method="GET""#),
        "missing method label in: {body}"
    );
    assert!(
        body.contains(r#"route="/xrpc/_health""#),
        "missing route label in: {body}"
    );
    assert!(
        body.contains(r#"status="200""#),
        "missing status label in: {body}"
    );
}
