//! AI-first REST API (`/v1/...`), SSE event stream (`/v1/events`),
//! agent safety guardrails (`draft_only`, `allowed_recipients`, `dry_run`),
//! and Agent-DX CLI helpers.
//!
//! Owned by the `ai-mcp` worker.

use axum::Router;
use serde_json::Value;

use crate::{
    AppState,
    config::Config,
    error::AppResult,
    models::{
        AiCreateDraftRequest, AiModifyLabelsRequest, AiSendDraftRequest, AiSendEmailRequest,
        AiTriageRequest, CompactMessage, DryRunResponse,
    },
    storage::StoredMessage,
};

/// Build the AI-first `/v1` router:
/// - `GET /v1/capabilities`
/// - `GET /v1/threads`, `GET /v1/threads/{id}`, `POST /v1/threads/{id}/triage`
/// - `GET /v1/messages`, `GET /v1/messages/{id}`, `GET /v1/messages/{id}/attachments/{attachment_id}`
/// - `POST /v1/messages/send`, `POST /v1/messages/modify`
/// - `GET /v1/drafts`, `POST /v1/drafts`, `POST /v1/drafts/{id}/send`, `DELETE /v1/drafts/{id}`
/// - `GET /v1/labels`
/// - `GET /v1/search`
/// - `GET /v1/events` (SSE)
/// - `POST /v1/sync/gmail`, `GET /v1/sync/status`
pub fn ai_router() -> Router<AppState> {
    Router::new()
}

/// Evaluate safety guardrails (`draft_only`, `allowed_recipients`, `max_send_recipients`)
/// and return a full dry-run preview without mutating storage or calling Resend.
pub async fn evaluate_send_dry_run(
    _state: &AppState,
    _req: &AiSendEmailRequest,
) -> AppResult<DryRunResponse> {
    todo!("ai-mcp worker: evaluate send safety policy and build DryRunResponse")
}

/// Enforce recipient allowlist & max-recipient policy against `to`/`cc`/`bcc`.
pub fn check_recipients_policy(
    _config: &Config,
    _to: &[String],
    _cc: &[String],
    _bcc: &[String],
) -> AppResult<()> {
    todo!("ai-mcp worker: check allowed_recipients and max_send_recipients")
}

/// Execute an AI-first send (shared across `/v1/messages/send`, MCP `send_email`, and CLI `nogml mail send`).
pub async fn execute_send_email(_state: &AppState, _req: AiSendEmailRequest) -> AppResult<Value> {
    todo!("ai-mcp worker: send email with safety guardrails, threading, and Resend delivery")
}

/// Execute an AI-first draft creation (shared across `/v1/drafts`, MCP `create_draft`, and CLI).
pub async fn execute_create_draft(
    _state: &AppState,
    _req: AiCreateDraftRequest,
) -> AppResult<Value> {
    todo!("ai-mcp worker: create draft")
}

/// Execute sending an existing draft (shared across `/v1/drafts/{id}/send` and MCP `send_draft`).
pub async fn execute_send_draft(
    _state: &AppState,
    _draft_id: &str,
    _req: AiSendDraftRequest,
) -> AppResult<Value> {
    todo!("ai-mcp worker: send draft")
}

/// Execute thread triage (shared across `/v1/threads/{id}/triage`, MCP `triage_thread`, and CLI).
pub async fn execute_triage_thread(
    _state: &AppState,
    _thread_id: &str,
    _req: AiTriageRequest,
) -> AppResult<Value> {
    todo!("ai-mcp worker: triage thread")
}

/// Execute label modification (shared across `/v1/messages/modify` and MCP `modify_labels`).
pub async fn execute_modify_labels(
    _state: &AppState,
    _req: AiModifyLabelsRequest,
) -> AppResult<Value> {
    todo!("ai-mcp worker: modify labels")
}

/// Project a [`StoredMessage`] into a token-efficient [`CompactMessage`].
pub fn to_compact_message(
    _msg: &StoredMessage,
    _config: &Config,
    _include_body: bool,
    _max_body_chars: usize,
    _strip_quotes: bool,
    _include_html: bool,
) -> CompactMessage {
    todo!("ai-mcp worker: build CompactMessage")
}

/// Return runtime JSON schema descriptions for `nogml schema [--command <name>]`.
pub fn runtime_schema(_command: Option<&str>) -> Value {
    todo!("ai-mcp worker: build runtime CLI & /v1 JSON schema manifest")
}
