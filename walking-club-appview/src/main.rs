//! Walking Club AppView entrypoint.
//!
//! Loads configuration, initializes tracing, opens the SQLite pool (WAL) and
//! runs migrations, builds the minijinja engine + identity resolver, constructs
//! the `WebContext`, spawns the firehose indexer and notify keepalive worker,
//! and serves the axum router with graceful shutdown.

use std::sync::Arc;

use atproto_identity::resolve::{
    HickoryDnsResolver, InnerIdentityResolver, SharedIdentityResolver,
};
use prometheus_client::registry::Registry;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing_subscriber::EnvFilter;

use walking_club_appview::config::Config;
use walking_club_appview::db;
use walking_club_appview::firehose_processor;
use walking_club_appview::ratelimit::RateLimiter;
use walking_club_appview::server::build_router;
use walking_club_appview::space::notify::{self, NotifyJob};
use walking_club_appview::state::{Metrics, WebContext};
use walking_club_appview::templates;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,walking_club_appview=info")),
        )
        .init();

    let config = Config::from_env()?;
    tracing::info!(external_base = %config.http_external_base, "starting walking-club-appview");

    // Database pool + migrations.
    let pool = db::connect(&config.database_url, config.database_max_connections).await?;

    // HTTP client.
    let http_client = reqwest::Client::builder()
        .user_agent("walking-club-appview")
        .build()?;

    // Identity resolver (Hickory DNS + PLC).
    let dns_resolver = Arc::new(HickoryDnsResolver::create_resolver(&config.dns_nameservers));
    let identity_resolver = Arc::new(SharedIdentityResolver(Arc::new(InnerIdentityResolver {
        dns_resolver: dns_resolver.clone(),
        http_client: http_client.clone(),
        plc_hostname: config.plc_hostname.clone(),
    })));

    // Rate limiter.
    let rate_limiter = Arc::new(RateLimiter::with_count(config.rate_limit_count));

    // Metrics.
    let mut registry = Registry::default();
    let metrics = Metrics::register(&mut registry);
    let metrics_registry = Arc::new(registry);

    // Template engine (feature-gated reload vs embed).
    #[cfg(all(feature = "reload", not(feature = "embed")))]
    let engine = templates::reload_env::build_env(&config.http_external_base);
    #[cfg(feature = "embed")]
    let engine = templates::embed_env::build_env(config.http_external_base.clone());

    // Notify channel: inbound notifyWrite -> reader worker.
    let (notify_tx, notify_rx) = mpsc::channel::<NotifyJob>(256);

    let web_context = WebContext::new(
        engine,
        pool.clone(),
        config.clone(),
        http_client.clone(),
        identity_resolver.clone(),
        dns_resolver.clone(),
        rate_limiter.clone(),
        metrics_registry.clone(),
        metrics.clone(),
        notify_tx,
    );

    // Background tasks.
    let tracker = TaskTracker::new();
    let cancel = CancellationToken::new();

    // Notify keepalive + reader worker.
    {
        let ctx = web_context.clone();
        let cancel = cancel.clone();
        tracker.spawn(async move {
            notify::run_notify_worker(ctx, notify_rx, cancel).await;
        });
    }

    // Firehose consumers (one per source).
    if config.public_index_enabled {
        for (name, url) in config.firehose_sources.clone() {
            let ctx = web_context.clone();
            let cancel = cancel.clone();
            tracker.spawn(async move {
                firehose_processor::run_source(ctx, name, url, cancel).await;
            });
        }
    }

    // Serve.
    let addr = format!("{}:{}", config.http_bind, config.http_port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "listening");
    let router = build_router(web_context);

    let shutdown_cancel = cancel.clone();
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            tracing::info!("shutdown signal received");
            shutdown_cancel.cancel();
        })
        .await?;

    cancel.cancel();
    tracker.close();
    tracker.wait().await;
    Ok(())
}

/// Wait for SIGINT or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
