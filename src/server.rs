//! Top-level Axum HTTP server router assembly.
//!
//! Owned by the `gmail-api` worker.

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::json;
use tower_http::{
    cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer},
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};

use crate::{
    AppState, ai, auth, gmail, mcp, metrics::PROMETHEUS_CONTENT_TYPE, oauth2, resend, transport,
};

/// Synthetic non-mutating blob key probed by `GET /readyz` when an external `BlobStore` is active.
const READYZ_BLOB_PROBE_KEY: &str = "__nogml_readyz_probe__";

/// Liveness endpoint (`GET /healthz`), always unauthenticated.
async fn healthz() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "service": "nogml",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Readiness endpoint (`GET /readyz`), always unauthenticated.
/// Verifies `MailStore` reachability and (when external) `BlobStore` reachability without
/// leaking raw internal error strings to unauthenticated callers.
async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    let (store_ok, history_id) = match state.store.current_history_id().await {
        Ok(history_id) => (true, Some(history_id)),
        Err(err) => {
            tracing::warn!(
                %err,
                backend = state.store.backend_name(),
                "Readiness check failed: MailStore probe error"
            );
            (false, None)
        }
    };

    let blobs_ok = if state.blobs.backend_name() != "inline" {
        match state.blobs.get(READYZ_BLOB_PROBE_KEY).await {
            Ok(_) => true,
            Err(err) => {
                tracing::warn!(
                    %err,
                    backend = state.blobs.backend_name(),
                    "Readiness check failed: BlobStore probe error"
                );
                false
            }
        }
    } else {
        true
    };

    let store_status = if store_ok { "ok" } else { "error" };
    let blobs_status = if blobs_ok { "ok" } else { "error" };

    if store_ok && blobs_ok {
        (
            StatusCode::OK,
            Json(json!({
                "status": "ready",
                "service": "nogml",
                "version": env!("CARGO_PKG_VERSION"),
                "store": store_status,
                "blobs": blobs_status,
                "history_id": history_id.unwrap_or_default().to_string(),
            })),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "not_ready",
                "service": "nogml",
                "store": store_status,
                "blobs": blobs_status,
            })),
        )
    }
}

/// Prometheus text exposition endpoint (`GET /metrics`), protected by `auth::require_auth`.
async fn metrics_endpoint(State(state): State<AppState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
        state.metrics.render_prometheus(),
    )
}

/// Middleware incrementing `nogml_http_requests_total` for every handled HTTP request.
async fn count_http_requests(State(state): State<AppState>, req: Request, next: Next) -> Response {
    state.metrics.inc_http_requests();
    next.run(req).await
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
/// - `POST /webhooks/ses` (SNS/SES inbound webhook, optional shared secret, exempt from bearer auth)
/// - `GET /.well-known/oauth-authorization-server`, `POST /oauth2/token` (optional local OAuth2, exempt from bearer auth)
/// - `GET /oauth2/authorize` (optional local OAuth2 authorization endpoint, bearer-protected)
/// - `GET /metrics` (Prometheus text exposition format, bearer-protected)
/// - `/gmail/v1/...`, `/upload/gmail/v1/...`, `/batch/gmail/v1`, `/oauth2/v2/userinfo`, `/oauth2/v3/userinfo`, `/v1/people/me` (bearer-protected)
/// - `/v1/...` AI-first REST + SSE (bearer-protected)
/// - `/mcp` Streamable HTTP MCP (bearer-protected)
///
/// Layers applied (outermost to innermost):
/// - HTTP tracing (`TraceLayer`)
/// - HTTP request metrics (`count_http_requests`)
/// - CORS (`CorsLayer` configured from `config.cors_allow_origins`)
/// - Request body limit (`RequestBodyLimitLayer` + `DefaultBodyLimit` from `config.max_body_bytes`)
/// - Bearer authentication (`auth::require_auth` on protected routes)
pub fn build_router(state: AppState) -> Router {
    let max_body_bytes = state.config.max_body_bytes;
    let cors_layer = build_cors_layer(&state.config.cors_allow_origins);

    let protected = Router::new()
        .route("/metrics", get(metrics_endpoint))
        .merge(oauth2::oauth2_router())
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
        .merge(transport::ses::ses_router())
        .merge(protected)
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
        .layer(cors_layer)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            count_http_requests,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
