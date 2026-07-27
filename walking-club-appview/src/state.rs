//! Application state (`WebContext`) shared across all axum handlers.
//!
//! Wraps an `Arc<InnerWebContext>` carrying the template engine, SQLite pool,
//! config, HTTP client, identity resolver, rate limiter, metrics, and the
//! notify-job channel for the inbound-notify -> reader worker. Provides
//! `render_template` helpers that hide the reload/embed `#[cfg]` split.

use std::ops::Deref;
use std::sync::Arc;

use atproto_identity::resolve::{HickoryDnsResolver, SharedIdentityResolver};
use atproto_identity::traits::IdentityResolver;
use axum::extract::FromRef;
use prometheus_client::registry::Registry;
use serde::Serialize;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::db::DbPool;
use crate::error::WebError;
use crate::ratelimit::RateLimiter;
use crate::space::notify::NotifyJob;

#[cfg(all(feature = "reload", not(feature = "embed")))]
use minijinja_autoreload::AutoReloader;

/// The template engine type, dependent on feature flags.
#[cfg(all(feature = "reload", not(feature = "embed")))]
pub type AppEngine = AutoReloader;

#[cfg(feature = "embed")]
use minijinja::Environment;

/// The template engine type, dependent on feature flags.
#[cfg(feature = "embed")]
pub type AppEngine = Environment<'static>;

/// Lightweight Prometheus metrics holder.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Total HTTP requests served.
    pub requests_total: prometheus_client::metrics::counter::Counter,
    /// Total firehose frames processed.
    pub firehose_frames_total: prometheus_client::metrics::counter::Counter,
    /// Total inbound notifyWrite requests.
    pub notify_total: prometheus_client::metrics::counter::Counter,
}

impl Metrics {
    /// Register metrics on the given registry and return the holder.
    pub fn register(registry: &mut Registry) -> Arc<Self> {
        let metrics = Self::default();
        registry.register(
            "http_requests",
            "Total HTTP requests served",
            metrics.requests_total.clone(),
        );
        registry.register(
            "firehose_frames",
            "Total firehose frames processed",
            metrics.firehose_frames_total.clone(),
        );
        registry.register(
            "notify_requests",
            "Total inbound notifyWrite requests",
            metrics.notify_total.clone(),
        );
        Arc::new(metrics)
    }
}

/// Inner shared web context (held behind an `Arc`).
pub struct InnerWebContext {
    /// Template engine.
    pub engine: AppEngine,
    /// SQLite connection pool.
    pub pool: DbPool,
    /// Loaded configuration.
    pub config: Config,
    /// Shared HTTP client.
    pub http_client: reqwest::Client,
    /// Identity resolver (handle/DID -> Document).
    pub identity_resolver: Arc<SharedIdentityResolver>,
    /// DNS resolver.
    pub dns_resolver: Arc<HickoryDnsResolver>,
    /// In-memory rate limiter.
    pub rate_limiter: Arc<RateLimiter>,
    /// Prometheus registry.
    pub metrics_registry: Arc<Registry>,
    /// Metrics holder.
    pub metrics: Arc<Metrics>,
    /// Channel to enqueue notify-triggered reader jobs.
    pub notify_tx: mpsc::Sender<NotifyJob>,
}

/// Cloneable web context handed to axum as state.
#[derive(Clone)]
pub struct WebContext(pub Arc<InnerWebContext>);

impl Deref for WebContext {
    type Target = InnerWebContext;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl WebContext {
    /// Construct a new web context.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        engine: AppEngine,
        pool: DbPool,
        config: Config,
        http_client: reqwest::Client,
        identity_resolver: Arc<SharedIdentityResolver>,
        dns_resolver: Arc<HickoryDnsResolver>,
        rate_limiter: Arc<RateLimiter>,
        metrics_registry: Arc<Registry>,
        metrics: Arc<Metrics>,
        notify_tx: mpsc::Sender<NotifyJob>,
    ) -> Self {
        Self(Arc::new(InnerWebContext {
            engine,
            pool,
            config,
            http_client,
            identity_resolver,
            dns_resolver,
            rate_limiter,
            metrics_registry,
            metrics,
            notify_tx,
        }))
    }

    /// Render a template, returning a `WebError` on failure.
    pub fn render_template<S: Serialize>(
        &self,
        template_name: &str,
        context: &S,
    ) -> Result<String, WebError> {
        #[cfg(all(feature = "reload", not(feature = "embed")))]
        {
            let env = self
                .engine
                .acquire_env()
                .map_err(|e| WebError::Internal(anyhow::Error::msg(e.to_string())))?;
            let template = env
                .get_template(template_name)
                .map_err(|e| WebError::Internal(anyhow::Error::msg(e.to_string())))?;
            template
                .render(context)
                .map_err(|e| WebError::Internal(anyhow::Error::msg(e.to_string())))
        }

        #[cfg(feature = "embed")]
        {
            let template = self
                .engine
                .get_template(template_name)
                .map_err(|e| WebError::Internal(anyhow::Error::msg(e.to_string())))?;
            template
                .render(context)
                .map_err(|e| WebError::Internal(anyhow::Error::msg(e.to_string())))
        }
    }

    /// Render a template, returning `None` on failure (for fallback pages).
    pub fn try_render_template<S: Serialize>(
        &self,
        template_name: &str,
        context: &S,
    ) -> Option<String> {
        #[cfg(all(feature = "reload", not(feature = "embed")))]
        {
            self.engine.acquire_env().ok().and_then(|env| {
                let template = env.get_template(template_name).ok()?;
                template.render(context).ok()
            })
        }

        #[cfg(feature = "embed")]
        {
            self.engine
                .get_template(template_name)
                .ok()
                .and_then(|template| template.render(context).ok())
        }
    }
}

impl FromRef<WebContext> for DbPool {
    fn from_ref(context: &WebContext) -> Self {
        context.pool.clone()
    }
}

impl FromRef<WebContext> for Config {
    fn from_ref(context: &WebContext) -> Self {
        context.config.clone()
    }
}

impl FromRef<WebContext> for Arc<SharedIdentityResolver> {
    fn from_ref(context: &WebContext) -> Self {
        context.identity_resolver.clone()
    }
}

impl FromRef<WebContext> for Arc<dyn IdentityResolver> {
    fn from_ref(context: &WebContext) -> Self {
        context.identity_resolver.clone()
    }
}

impl FromRef<WebContext> for Arc<HickoryDnsResolver> {
    fn from_ref(context: &WebContext) -> Self {
        context.dns_resolver.clone()
    }
}

impl FromRef<WebContext> for Arc<RateLimiter> {
    fn from_ref(context: &WebContext) -> Self {
        context.rate_limiter.clone()
    }
}
