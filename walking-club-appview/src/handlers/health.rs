//! Health + metrics handlers.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use prometheus_client::encoding::text::encode;

use crate::state::WebContext;

/// `GET /_alive` — liveness probe.
pub async fn alive() -> Response {
    (StatusCode::OK, "ok").into_response()
}

/// `GET /_ready` — readiness probe (DB reachable).
pub async fn ready(State(ctx): State<WebContext>) -> Response {
    match sqlx::query("SELECT 1").execute(&ctx.pool).await {
        Ok(_) => (StatusCode::OK, "ready").into_response(),
        Err(e) => {
            tracing::warn!(error = ?e, "readiness check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "not ready").into_response()
        }
    }
}

/// `GET /metrics` — Prometheus exposition.
pub async fn metrics(State(ctx): State<WebContext>) -> Response {
    let mut buf = String::new();
    match encode(&mut buf, &ctx.metrics_registry) {
        Ok(_) => (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "application/openmetrics-text; version=1.0.0; charset=utf-8",
            )],
            buf,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = ?e, "metrics encode failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "encode error").into_response()
        }
    }
}
