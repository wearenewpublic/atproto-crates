//! — `otel` feature acceptance.
//!
//! When the `otel` feature is compiled in, `init_otlp_layer` returns a
//! `Some(layer)` for a well-formed endpoint string. Off-feature, it
//! returns `None`. This test exercises the gated symbol so CI proves
//! the build path lights up under `cargo test --features otel`.

#[cfg(feature = "otel")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn otel_layer_constructs_for_well_formed_endpoint() {
    // `with_batch_exporter(_, runtime::Tokio)` requires a live Tokio
    // reactor; running under `#[tokio::test]` provides one.
    let layer = atproto_pds::telemetry::init_otlp_layer::<tracing_subscriber::Registry>(
        "http://127.0.0.1:4318",
        "atproto-pds-test",
    );
    // The OTLP HTTP exporter init can succeed even with no live
    // collector — actual traffic is best-effort + batched. We only
    // assert the layer constructed, which proves the deps are wired.
    assert!(
        layer.is_some(),
        "expected otel layer to construct for a well-formed endpoint"
    );
}

#[cfg(not(feature = "otel"))]
#[test]
fn otel_layer_is_none_when_feature_off() {
    let layer = atproto_pds::telemetry::init_otlp_layer::<tracing_subscriber::Registry>(
        "http://127.0.0.1:4318",
        "atproto-pds-test",
    );
    assert!(
        layer.is_none(),
        "expected otel layer to be absent when feature is off"
    );
}
