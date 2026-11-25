//! Top-level Axum HTTP server router assembly.
//!
//! Owned by the `gmail-api` worker.

use axum::{Json, Router, routing::get};
use serde_json::json;

use crate::{AppState, ai, gmail, mcp, resend};

/// Healthcheck endpoint (`GET /healthz`), always unauthenticated.
async fn healthz() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "service": "nogml",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Assemble the complete HTTP router mounting:
/// - `GET /healthz` (unauthenticated)
/// - `POST /webhooks/resend` (Svix-verified, unauthenticated bearer)
/// - `/gmail/v1/...`, `/upload/gmail/v1/...`, `/batch/gmail/v1` (bearer-protected)
/// - `/v1/...` AI-first REST + SSE (bearer-protected)
/// - `/mcp` Streamable HTTP MCP (bearer-protected)
pub fn build_router(state: AppState) -> Router {
    let protected = Router::new()
        .merge(gmail::gmail_router())
        .merge(ai::ai_router())
        .merge(mcp::mcp_router());

    Router::new()
        .route("/healthz", get(healthz))
        .merge(resend::resend_router())
        .merge(protected)
        .with_state(state)
}
