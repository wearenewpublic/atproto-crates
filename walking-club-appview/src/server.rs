//! Axum router construction.
//!
//! Wires every route from the cluster plan (§3.3): landing, OAuth metadata +
//! flow, did:web well-knowns, feed, compose, inbound notify, admin, health +
//! metrics, and the static asset directory. Outer layers add tracing, CORS, and
//! a request timeout.

use std::time::Duration;

use axum::Router;
use axum::routing::{get, post};
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::handlers;
use crate::oauth;
use crate::state::WebContext;

/// Build the full application router.
pub fn build_router(ctx: WebContext) -> Router {
    let serve_dir = ServeDir::new(ctx.config.http_static_path.clone());

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .max_age(Duration::from_secs(86400));

    Router::new()
        // ── Public pages ──
        .route("/", get(handlers::index::index))
        // ── OAuth metadata ──
        .route(
            "/client-metadata.json",
            get(oauth::metadata::client_metadata),
        )
        .route("/jwks.json", get(oauth::metadata::jwks))
        // ── did:web well-knowns ──
        .route("/.well-known/did.json", get(handlers::did::did_json))
        .route(
            "/.well-known/atproto-did",
            get(handlers::atproto_did::atproto_did),
        )
        // ── OAuth flow ──
        .route("/login", post(oauth::login::login))
        .route("/callback", get(oauth::callback::callback))
        .route("/auth/refresh", post(oauth::refresh::refresh))
        .route("/auth/logout", post(oauth::logout::logout))
        // ── Feed + compose ──
        .route("/feed", get(handlers::feed::feed))
        .route("/feed/fragment", get(handlers::feed::feed_fragment))
        .route("/compose", get(handlers::compose::compose))
        .route("/api/compose/event", post(handlers::compose::create_event))
        .route("/api/compose/post", post(handlers::compose::create_post))
        // ── Inbound space notify ──
        .route(
            "/xrpc/com.atproto.space.notifyWrite",
            post(handlers::notify::notify_write),
        )
        // ── Admin ──
        .route("/admin", get(handlers::admin::admin_index))
        // ── Health + metrics ──
        .route("/_alive", get(handlers::health::alive))
        .route("/_ready", get(handlers::health::ready))
        .route("/metrics", get(handlers::health::metrics))
        // ── Static assets ──
        .nest_service("/static", serve_dir)
        // ── Outer layers ──
        .layer(TimeoutLayer::with_status_code(
            http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(ctx)
}
