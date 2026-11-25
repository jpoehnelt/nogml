//! Bearer token authentication middleware and input hardening validators.
//!
//! Owned by the `gmail-api` worker.

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};

use crate::{AppState, error::AppResult};

/// Axum middleware enforcing `Authorization: Bearer <token>` using constant-time comparison
/// when `Config::auth_tokens` is non-empty. Allows unauthenticated access in dev mode (empty tokens).
pub async fn require_auth(
    State(_state): State<AppState>,
    _req: Request,
    _next: Next,
) -> AppResult<Response> {
    todo!("gmail-api worker: bearer token auth middleware")
}

/// Reject control chars (`0x00..=0x1f`, `0x7f`), `..`, `/`, `\`, `%2e`, `%2f`, `?`, `#`
/// in resource IDs (`message_id`, `thread_id`, `draft_id`, `label_id`).
pub fn validate_resource_id(_id: &str) -> AppResult<()> {
    todo!("gmail-api worker: validate resource ID against traversal and control chars")
}

/// Reject CR/LF header injection in email headers (`subject`, `to`, `cc`, `bcc`, `from`).
pub fn validate_email_header(_name: &str, _value: &str) -> AppResult<()> {
    todo!("gmail-api worker: validate email header value")
}
