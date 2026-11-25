//! Partial response `?fields=` middleware and `alt=json` tolerance for Gmail REST API v1.

use axum::{
    body::{Body, to_bytes},
    extract::Request,
    http::{HeaderValue, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::Value;

use crate::{error::AppError, gmail::query::QueryParams, mime};

/// Maximum JSON response size buffered when applying `?fields=` projection (64 MiB).
const MAX_FIELDS_BUFFER_BYTES: usize = 64 * 1024 * 1024;

/// Axum middleware that:
/// 1. Validates/tolerates `?alt=json` (rejects unsupported `alt` values).
/// 2. Applies Google/Gmail `?fields=` partial response masking to successful JSON responses
///    via [`crate::mime::apply_fields_mask`].
pub async fn fields_and_alt_middleware(req: Request, next: Next) -> Response {
    let query = QueryParams::from_raw(req.uri().query());

    if let Some(alt) = query.get("alt")
        && !alt.eq_ignore_ascii_case("json")
        && !alt.eq_ignore_ascii_case("media")
    {
        return AppError::BadRequest(format!(
            "Unsupported alt parameter '{alt}'; only 'json' is supported"
        ))
        .into_response();
    }

    let fields = query
        .get("fields")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    let res = next.run(req).await;

    let Some(mask) = fields else {
        return res;
    };

    if !res.status().is_success() {
        return res;
    }

    let is_json = res
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.to_ascii_lowercase().starts_with("application/json"));

    if !is_json {
        return res;
    }

    let (mut parts, body) = res.into_parts();
    let bytes = match to_bytes(body, MAX_FIELDS_BUFFER_BYTES).await {
        Ok(b) => b,
        Err(err) => {
            return AppError::Internal(format!("Failed to buffer response for ?fields=: {err}"))
                .into_response();
        }
    };

    if bytes.is_empty() {
        return Response::from_parts(parts, Body::from(bytes));
    }

    let parsed: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return Response::from_parts(parts, Body::from(bytes)),
    };

    let projected = match mime::apply_fields_mask(parsed, &mask) {
        Ok(v) => v,
        Err(err) => return err.into_response(),
    };

    let encoded = match serde_json::to_vec(&projected) {
        Ok(v) => v,
        Err(err) => {
            return AppError::Internal(format!("Failed to serialize projected JSON: {err}"))
                .into_response();
        }
    };

    parts.headers.remove(header::CONTENT_LENGTH);
    if let Ok(len_val) = HeaderValue::from_str(&encoded.len().to_string()) {
        parts.headers.insert(header::CONTENT_LENGTH, len_val);
    }

    Response::from_parts(parts, Body::from(encoded))
}
