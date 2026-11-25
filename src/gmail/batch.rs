//! Gmail HTTP Batching (`POST /batch/gmail/v1`) implementing Google's `multipart/mixed`
//! `application/http` batch protocol for Superhuman and Google API client compatibility.

use axum::{
    Extension,
    body::{Body, Bytes, to_bytes},
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
};
use tower::ServiceExt;
use uuid::Uuid;

use crate::{
    AppState,
    auth::{self, Principal},
    error::{AppError, AppResult},
    gmail::{
        gmail_api_routes,
        upload::{parse_multipart_parts, split_headers_and_body},
    },
};

/// Google Gmail REST API batch ceiling: at most 100 sub-requests per batch.
const MAX_BATCH_PARTS: usize = 100;

/// Max buffered size of a single sub-response body (32 MiB).
const MAX_SUB_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

/// `POST /batch/gmail/v1`
pub async fn batch_handler(
    State(state): State<AppState>,
    outer_principal: Option<Extension<Principal>>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            AppError::BadRequest("Missing Content-Type header for batch request".into())
        })?;

    let parts = parse_multipart_parts(content_type, &body)?;
    if parts.is_empty() {
        return Err(AppError::BadRequest(
            "Batch request contains no sub-requests".to_string(),
        ));
    }
    if parts.len() > MAX_BATCH_PARTS {
        return Err(AppError::BadRequest(format!(
            "Batch request exceeds maximum of {MAX_BATCH_PARTS} sub-requests (got {})",
            parts.len()
        )));
    }

    let outer_auth = headers.get(header::AUTHORIZATION).cloned();
    let outer_api_key = headers.get("x-api-key").cloned();
    let outer_principal = outer_principal.map(|Extension(p)| p);

    let sub_router = gmail_api_routes()
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ))
        .with_state(state);
    let response_boundary = format!("batch_{}", Uuid::new_v4().simple());
    let mut out = Vec::with_capacity(body.len() + 1024);

    for part in parts {
        let part_content_id = part.header("content-id").map(strip_angle_brackets);

        let sub_response =
            match build_embedded_request(&part.body, outer_auth.as_ref(), outer_api_key.as_ref()) {
                Ok(mut req) => {
                    if let Some(ref p) = outer_principal {
                        req.extensions_mut().insert(p.clone());
                    }
                    match sub_router.clone().oneshot(req).await {
                        Ok(resp) => resp,
                        Err(infallible) => match infallible {},
                    }
                }
                Err(err) => err.into_response(),
            };

        write_batch_part(
            &mut out,
            &response_boundary,
            part_content_id.as_deref(),
            sub_response,
        )
        .await?;
    }

    out.extend_from_slice(format!("--{response_boundary}--\r\n").as_bytes());

    let ct_value = HeaderValue::from_str(&format!("multipart/mixed; boundary={response_boundary}"))
        .map_err(|e| AppError::Internal(format!("Invalid batch boundary header: {e}")))?;

    let mut resp = Response::new(Body::from(out));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(header::CONTENT_TYPE, ct_value);
    Ok(resp)
}

fn strip_angle_brackets(raw: &str) -> String {
    raw.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim()
        .to_string()
}

fn build_embedded_request(
    raw: &[u8],
    outer_auth: Option<&HeaderValue>,
    outer_api_key: Option<&HeaderValue>,
) -> AppResult<Request<Body>> {
    // Trim leading blank lines before the HTTP request line.
    let mut slice = raw;
    while slice.starts_with(b"\r\n") {
        slice = &slice[2..];
    }
    while slice.starts_with(b"\n") {
        slice = &slice[1..];
    }

    if slice.is_empty() {
        return Err(AppError::BadRequest(
            "Empty HTTP sub-request inside batch part".to_string(),
        ));
    }

    let (first_line_bytes, rest) = if let Some(idx) = slice.iter().position(|&b| b == b'\n') {
        let line = slice[..idx].strip_suffix(b"\r").unwrap_or(&slice[..idx]);
        (line, &slice[idx + 1..])
    } else {
        (slice, &[][..])
    };

    let first_line = std::str::from_utf8(first_line_bytes)
        .map_err(|_| AppError::BadRequest("Non-UTF-8 HTTP request line in batch part".into()))?
        .trim();

    let mut tokens = first_line.split_whitespace();
    let method_str = tokens
        .next()
        .ok_or_else(|| AppError::BadRequest("Missing HTTP method in batch part".into()))?;
    let target_raw = tokens
        .next()
        .ok_or_else(|| AppError::BadRequest("Missing request URI in batch part".into()))?;

    let method = Method::from_bytes(method_str.as_bytes()).map_err(|_| {
        AppError::BadRequest(format!("Invalid HTTP method '{method_str}' in batch part"))
    })?;

    let normalized_uri = normalize_batch_target(target_raw)?;

    let (inner_headers, inner_body) = if rest.is_empty() {
        (Vec::new(), &[][..])
    } else if rest.starts_with(b"\r\n") {
        (Vec::new(), &rest[2..])
    } else if rest.starts_with(b"\n") {
        (Vec::new(), &rest[1..])
    } else if has_header_separator(rest) {
        split_headers_and_body(rest)
    } else {
        // Headers only with no trailing blank line / body
        let mut hdrs = Vec::new();
        for line in String::from_utf8_lossy(rest).lines() {
            let line = line.trim_end_matches('\r');
            if let Some((k, v)) = line.split_once(':') {
                hdrs.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        (hdrs, &[][..])
    };

    let mut builder = Request::builder().method(method).uri(&normalized_uri);
    let mut has_auth = false;
    let mut has_api_key = false;

    for (name, value) in inner_headers {
        if name.eq_ignore_ascii_case("authorization") {
            has_auth = true;
        }
        if name.eq_ignore_ascii_case("x-api-key") {
            has_api_key = true;
        }
        // Skip hop-by-hop Content-Length so hyper/axum derives it accurately from Body.
        if name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            builder = builder.header(hn, hv);
        }
    }

    if !has_auth && let Some(auth) = outer_auth {
        builder = builder.header(header::AUTHORIZATION, auth.clone());
    }
    if !has_api_key && let Some(api_key) = outer_api_key {
        builder = builder.header("x-api-key", api_key.clone());
    }

    builder
        .body(Body::from(inner_body.to_vec()))
        .map_err(|e| AppError::BadRequest(format!("Invalid sub-request in batch part: {e}")))
}

fn has_header_separator(bytes: &[u8]) -> bool {
    bytes.windows(4).any(|w| w == b"\r\n\r\n") || bytes.windows(2).any(|w| w == b"\n\n")
}

fn normalize_batch_target(raw: &str) -> AppResult<String> {
    let target = if raw.starts_with("http://") || raw.starts_with("https://") {
        let parsed = url::Url::parse(raw)
            .map_err(|_| AppError::BadRequest(format!("Invalid URL '{raw}' in batch part")))?;
        match parsed.query() {
            Some(q) => format!("{}?{q}", parsed.path()),
            None => parsed.path().to_string(),
        }
    } else if raw.starts_with('/') {
        raw.to_string()
    } else {
        format!("/{raw}")
    };

    let path_only = target.split('?').next().unwrap_or(&target);
    if path_only.starts_with("/batch/") || path_only == "/batch" {
        return Err(AppError::BadRequest(
            "Nested /batch/ requests are not allowed".to_string(),
        ));
    }

    if !path_only.starts_with("/gmail/v1/") && !path_only.starts_with("/upload/gmail/v1/") {
        return Err(AppError::BadRequest(format!(
            "Batch sub-request path '{path_only}' must target /gmail/v1/ or /upload/gmail/v1/"
        )));
    }

    Ok(target)
}

async fn write_batch_part(
    out: &mut Vec<u8>,
    boundary: &str,
    content_id: Option<&str>,
    response: Response,
) -> AppResult<()> {
    let status = response.status();
    let headers = response.headers().clone();
    let body_bytes = to_bytes(response.into_body(), MAX_SUB_RESPONSE_BYTES)
        .await
        .map_err(|e| AppError::Internal(format!("Failed reading batch sub-response: {e}")))?;

    out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    out.extend_from_slice(b"Content-Type: application/http\r\n");
    if let Some(cid) = content_id
        && !cid.is_empty()
    {
        out.extend_from_slice(format!("Content-ID: response-{cid}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");

    let reason = status.canonical_reason().unwrap_or("OK");
    out.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status.as_u16(), reason).as_bytes());

    let mut wrote_content_type = false;
    for (name, val) in &headers {
        if name == header::TRANSFER_ENCODING || name == header::CONTENT_LENGTH {
            continue;
        }
        if name == header::CONTENT_TYPE {
            wrote_content_type = true;
        }
        if let Ok(val_str) = val.to_str() {
            out.extend_from_slice(format!("{name}: {val_str}\r\n").as_bytes());
        }
    }
    if !wrote_content_type && !body_bytes.is_empty() {
        out.extend_from_slice(b"content-type: application/json; charset=UTF-8\r\n");
    }
    out.extend_from_slice(format!("content-length: {}\r\n", body_bytes.len()).as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&body_bytes);
    out.extend_from_slice(b"\r\n");

    Ok(())
}
