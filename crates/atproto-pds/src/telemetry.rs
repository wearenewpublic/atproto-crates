//! OpenTelemetry OTLP exporter wiring.
//!
//! When the `otel` feature is enabled and `PDS_OTEL_ENDPOINT` is set,
//! the binary attaches a `tracing-opentelemetry` layer to the global
//! subscriber so all spans + events flow to the configured collector.
//!
//! Off-feature builds compile a no-op stub so call sites in
//! `bin/pds.rs` don't need feature gates of their own — the boot
//! sequence stays readable, and disabling the feature simply yields a
//! tracing pipeline with no OTLP layer.

#[cfg(feature = "otel")]
mod inner {
    use opentelemetry::{global, trace::TracerProvider as _};
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::propagation::TraceContextPropagator;
    use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler, SdkTracerProvider};
    use std::sync::OnceLock;
    use tracing_subscriber::Layer;
    use tracing_subscriber::registry::LookupSpan;

    /// Handle kept so [`shutdown`] can flush the batch processor.
    ///
    /// The SDK dropped `global::shutdown_tracer_provider` because
    /// shutting down through the global slot could not guarantee the
    /// exporter had actually drained. Flushing is now the provider's own
    /// method, so the caller has to retain one.
    static PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

    /// Build a `tracing-opentelemetry` layer wired to an OTLP HTTP/protobuf
    /// exporter at `endpoint`.
    ///
    /// `service_name` is reported as the `service.name` resource attribute
    /// — operators see it in collectors / Jaeger / Tempo as the source.
    ///
    /// Returns `None` when the SDK fails to initialize (collector
    /// unreachable, malformed endpoint, etc.) so callers can degrade
    /// gracefully without aborting the boot.
    pub fn init_otlp_layer<S>(endpoint: &str, service_name: &str) -> Option<impl Layer<S>>
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    {
        // Cross-process trace correlation via the W3C TraceContext header.
        global::set_text_map_propagator(TraceContextPropagator::new());

        let exporter = match opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(endpoint)
            .build()
        {
            Ok(e) => e,
            Err(err) => {
                tracing::warn!(
                    error = ?err,
                    endpoint,
                    "otel: span exporter init failed; OTLP disabled"
                );
                return None;
            }
        };
        // `builder_empty` rather than `builder`: the latter runs the env
        // detectors and stamps SDK metadata, which would change the
        // attributes operators already filter on.
        let resource = Resource::builder_empty()
            .with_service_name(service_name.to_string())
            .build();
        let provider = SdkTracerProvider::builder()
            .with_resource(resource)
            .with_sampler(Sampler::AlwaysOn)
            .with_id_generator(RandomIdGenerator::default())
            .with_batch_exporter(exporter)
            .build();
        let tracer = provider.tracer("atproto-pds");
        let _ = PROVIDER.set(provider.clone());
        global::set_tracer_provider(provider);
        Some(tracing_opentelemetry::layer().with_tracer(tracer))
    }

    /// Best-effort shutdown — flushes pending spans before process exit.
    /// Called from `bin/pds.rs::shutdown_signal` when the OTLP layer is
    /// active.
    pub fn shutdown() {
        if let Some(provider) = PROVIDER.get()
            && let Err(err) = provider.shutdown()
        {
            tracing::warn!(error = ?err, "otel: span flush on shutdown failed");
        }
    }
}

#[cfg(not(feature = "otel"))]
mod inner {
    /// Off-feature stub — returns `None` so boot code can call this
    /// uniformly.
    pub fn init_otlp_layer<S>(_endpoint: &str, _service_name: &str) -> Option<DummyLayer<S>>
    where
        S: tracing::Subscriber,
    {
        None
    }

    /// Off-feature shutdown — does nothing.
    pub fn shutdown() {}

    /// Phantom layer type so the off-feature path has a concrete return
    /// type that satisfies `Option<impl Layer>` consumers.
    pub struct DummyLayer<S>(std::marker::PhantomData<fn(S)>);

    impl<S> tracing_subscriber::Layer<S> for DummyLayer<S> where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>
    {
    }
}

pub use inner::*;

#[cfg(test)]
mod tests {
    /// Off-feature compile sanity check — under default features the
    /// stub `init_otlp_layer` always returns `None`. The on-feature
    /// path needs a Tokio reactor (its batch exporter spawns one) and
    /// is exercised by `tests/feature_otel.rs` instead.
    #[cfg(not(feature = "otel"))]
    #[test]
    fn init_otlp_layer_returns_none_when_feature_off() {
        let result = super::init_otlp_layer::<tracing_subscriber::Registry>(
            "http://127.0.0.1:4318",
            "atproto-pds",
        );
        assert!(result.is_none());
    }
}
