//! Top-level Axum HTTP server router assembly.
//!
//! Owned by the `gmail-api` worker.

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderValue, Method, StatusCode},
    middleware,
    response::IntoResponse,
    routing::get,
};
use serde_json::json;
use tower_http::{
    cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer},
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};

use crate::{AppState, ai, auth, gmail, mcp, resend};

/// Liveness endpoint (`GET /healthz`), always unauthenticated.
async fn healthz() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "service": "nogml",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Readiness endpoint (`GET /readyz`), always unauthenticated.
/// Verifies that the configured `MailStore` backend responds.
async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    match state.store.current_history_id().await {
        Ok(history_id) => (
            StatusCode::OK,
            Json(json!({
                "status": "ready",
                "service": "nogml",
                "version": env!("CARGO_PKG_VERSION"),
                "history_id": history_id.to_string(),
            })),
        ),
        Err(err) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "not_ready",
                "service": "nogml",
                "error": err.to_string(),
            })),
        ),
    }
}

/// Build the CORS layer from `Config::cors_allow_origins`.
/// Empty list (or containing `"*"`) allows any origin; otherwise restricts to the configured origins.
fn build_cors_layer(origins: &[String]) -> CorsLayer {
    let allow_origin = if origins.is_empty() || origins.iter().any(|o| o.trim() == "*") {
        AllowOrigin::any()
    } else {
        let parsed: Vec<HeaderValue> = origins
            .iter()
            .filter_map(|o| {
                let trimmed = o.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    HeaderValue::from_str(trimmed).ok()
                }
            })
            .collect();
        if parsed.is_empty() {
            AllowOrigin::any()
        } else {
            AllowOrigin::list(parsed)
        }
    };

    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods(AllowMethods::list([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
            Method::HEAD,
        ]))
        .allow_headers(AllowHeaders::any())
}

/// Assemble the complete HTTP router mounting:
/// - `GET /healthz` (unauthenticated)
/// - `GET /readyz` (unauthenticated)
/// - `POST /webhooks/resend` (Svix-verified, exempt from bearer auth)
/// - `/gmail/v1/...`, `/upload/gmail/v1/...`, `/batch/gmail/v1` (bearer-protected)
/// - `/v1/...` AI-first REST + SSE (bearer-protected)
/// - `/mcp` Streamable HTTP MCP (bearer-protected)
///
/// Layers applied (outermost to innermost):
/// - HTTP tracing (`TraceLayer`)
/// - CORS (`CorsLayer` configured from `config.cors_allow_origins`)
/// - Request body limit (`RequestBodyLimitLayer` + `DefaultBodyLimit` from `config.max_body_bytes`)
/// - Bearer authentication (`auth::require_auth` on protected routes)
pub fn build_router(state: AppState) -> Router {
    let max_body_bytes = state.config.max_body_bytes;
    let cors_layer = build_cors_layer(&state.config.cors_allow_origins);

    let protected = Router::new()
        .merge(gmail::gmail_router())
        .merge(ai::ai_router())
        .merge(mcp::mcp_router())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .merge(resend::resend_router())
        .merge(protected)
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
        .layer(cors_layer)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
