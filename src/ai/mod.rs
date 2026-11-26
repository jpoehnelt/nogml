//! AI-first REST API (`/v1/...`), SSE event stream (`/v1/events`),
//! agent safety guardrails (`draft_only`, `allowed_recipients`, `dry_run`),
//! and Agent-DX CLI helpers.
//!
//! Owned by the `ai-mcp` worker.

pub mod briefing;
pub mod reply_context;
pub mod rules;
pub mod safety;
pub mod scheduler;
pub mod schema;
#[cfg(test)]
pub(crate) mod tests;
pub mod unsubscribe;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{Path, Query},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{delete, get, patch, post},
};
use chrono::{DateTime, Utc};
use futures_util::stream::{self, Stream};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::warn;
use uuid::Uuid;

use crate::{
    AppState, MailboxState,
    auth::Principal,
    config::{Config, SyncMode},
    error::{AiError, AppError, AppResult},
    events::{EventEnvelope, EventSource, MailEvent},
    mime::{
        ComposeEmailInput, DEFAULT_ATTACHMENT_MAX_BYTES, apply_fields_mask, build_rfc2822,
        extract_attachment_text, extract_html_links, generate_snippet,
        oversize_attachment_extraction, parse_unsubscribe_from_raw, select_body_or_html_markdown,
        strip_quoted_text, strip_tracking_pixels,
    },
    models::{
        AiBatchTriageRequest, AiCreateDraftRequest, AiModifyLabelsRequest, AiSendDraftRequest,
        AiSendEmailRequest, AiTriageRequest, AiUnsubscribeRequest, AttachmentTextExtraction,
        BatchTriageApplyResponse, BatchTriageDryRunResponse, BatchTriagePreviewItem,
        BatchTriageThreadError, BatchTriageThreadResult, CompactMessage, ContactSummary,
        EmailAddress, LABEL_DRAFT, LABEL_INBOX, LABEL_SENT, LABEL_STARRED, LABEL_TRASH,
        LABEL_UNREAD, PatchThreadAnnotationRequest, SnoozeThreadRequest, SyncTriggerRequest,
        ThreadAnnotation, ThreadDetail, ThreadSummary, UnsubscribeInfo,
        UpsertThreadAnnotationRequest, WaitingOn, truncate_to_millis,
    },
    storage::{
        AiSearchQuery, AiThreadQuery, ApprovalStatus, AuditLogQuery, ContactPatch, ContactQuery,
        ContactRecord, InboxRulePatch, MessageListQuery, NewAttachmentInput, NewInboxRule,
        NewMessageInput, NewPendingApprovalInput, NewScheduledSend, PendingApproval, StoredLabel,
        StoredMessage, StoredThreadDetail, TriagePatch, parse_simple_email_address,
        validate_and_normalize_contact_email,
    },
    sync::{self, SyncRunOptions},
    transport::{OutboundAttachment, OutboundMessage},
};

pub use briefing::{
    ApprovalBriefingItem, BriefingCounts, BriefingParams, BriefingResponse, FollowUpCandidate,
    build_briefing, execute_briefing, parse_briefing_since,
};
pub use reply_context::{
    ReplyContextOptions, ReplyContextResponse, clean_subject, execute_get_reply_context,
};
pub use safety::{
    ConfigOutboundPolicy, DlpOutboundPolicy, FirstContactPolicy, OutboundCheck, OutboundDecision,
    OutboundPolicy, OutboundPolicyChain, PolicyCheck, check_recipients_policy,
    clamp_max_body_chars, evaluate_send_dry_run, open_outbound_policy, sanitize_untrusted_text,
    scan_dlp_findings, scan_dlp_text, untrusted_meta, validate_email_header, validate_resource_id,
};
pub use scheduler::{
    DEFAULT_SCHEDULER_INTERVAL_SECS, SchedulerTickReport, execute_cancel_scheduled_send,
    execute_cancel_scheduled_send_with_context, execute_list_scheduled_sends,
    execute_snooze_thread, execute_snooze_thread_with_context, execute_unsnooze_thread,
    execute_unsnooze_thread_with_context, parse_scheduled_send_status_filter,
    process_due_scheduler_items, run_background_scheduler,
};
pub use schema::runtime_schema;
pub use unsubscribe::{
    ParsedMailto, ValidatedUnsubscribeUrl, execute_unsubscribe, execute_unsubscribe_with_source,
    is_globally_routable_ip, parse_mailto_uri, validate_unsubscribe_https_url,
    validate_unsubscribe_https_url_static,
};

const DEFAULT_LIST_LIMIT: usize = 20;
pub(crate) const MAX_LIST_LIMIT: usize = 100;
const DEFAULT_CONTACTS_LIMIT: usize = 50;
const MAX_CONTACTS_LIMIT: usize = 200;
const DEFAULT_AUDIT_LIMIT: usize = 50;
const MAX_AUDIT_LIMIT: usize = 500;
/// Default safety cap on unique target threads per `batch_triage` call.
pub const DEFAULT_BATCH_TRIAGE_MAX_THREADS: usize = 100;
/// Hard ceiling on unique target threads per `batch_triage` call.
pub const HARD_MAX_BATCH_TRIAGE_THREADS: usize = 500;
const DEFAULT_LIST_BODY_CHARS: usize = 1000;
const SSE_REPLAY_LIMIT: usize = 1024;
/// Default TTL (24 hours) for persisted send/draft idempotency keys.
pub const DEFAULT_IDEMPOTENCY_TTL_SECS: i64 = 86_400;
const MAX_IDEMPOTENCY_KEY_LEN: usize = 256;
const IDEMPOTENCY_SCOPE_SEND: &str = "send_email";
const IDEMPOTENCY_SCOPE_DRAFT: &str = "create_draft";

pub(crate) fn channel_for_source(source: EventSource) -> &'static str {
    match source {
        EventSource::Mcp => "/mcp",
        EventSource::Api => "/v1",
        EventSource::Imap => "imap",
        EventSource::GmailSync => "sync",
        EventSource::ResendInbound | EventSource::ResendWebhook => "resend",
        EventSource::SesInbound => "ses",
        EventSource::System => "system",
    }
}

fn idempotency_key_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn normalize_idempotency_key(raw: Option<&str>) -> AppResult<Option<String>> {
    let Some(trimmed) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    if trimmed.len() > MAX_IDEMPOTENCY_KEY_LEN {
        return Err(AppError::validation(
            format!("idempotency_key exceeds maximum length of {MAX_IDEMPOTENCY_KEY_LEN} bytes"),
            Some("Provide a shorter idempotency key (<= 256 bytes).".to_string()),
        ));
    }
    if trimmed.bytes().any(|b| b <= 0x1f || b == 0x7f) || trimmed.chars().any(char::is_control) {
        return Err(AppError::validation(
            "idempotency_key contains disallowed control characters",
            None,
        ));
    }
    Ok(Some(trimmed.to_string()))
}

fn extract_cached_target_ids(val: &Value) -> Vec<String> {
    let mut ids = Vec::new();
    for field in [
        "approval_id",
        "scheduled_id",
        "draft_id",
        "message_id",
        "thread_id",
    ] {
        if let Some(s) = val.get(field).and_then(Value::as_str)
            && !s.is_empty()
            && !ids.iter().any(|existing| existing == s)
        {
            ids.push(s.to_string());
        }
    }
    ids
}

/// Parse an audit `since` filter accepting either epoch milliseconds (`i64`) or RFC 3339 timestamp.
pub fn parse_since_ms(raw: Option<&str>) -> AppResult<Option<i64>> {
    let Some(trimmed) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    if let Ok(ms) = trimmed.parse::<i64>() {
        return Ok(Some(ms));
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Ok(Some(dt.timestamp_millis()));
    }
    Err(AppError::validation(
        format!("Invalid 'since' timestamp '{trimmed}'"),
        Some("Provide Unix epoch milliseconds (e.g. 1700000000000) or an RFC 3339 timestamp (e.g. 2026-01-01T00:00:00Z).".to_string()),
    ))
}

/// Build the AI-first `/v1` router (alias for [`ai_router`]).
pub fn router() -> Router<AppState> {
    ai_router()
}

/// Build the AI-first `/v1` router:
/// - `GET /v1/capabilities`
/// - `GET /v1/briefing`
/// - `GET /v1/threads`, `POST /v1/threads/batch_triage`, `GET /v1/threads/{id}`, `POST /v1/threads/{id}/triage`
/// - `GET /v1/threads/{id}/reply-context`
/// - `GET /v1/messages`, `GET /v1/messages/{id}`, `GET /v1/messages/{id}/attachments/{attachment_id}`
/// - `POST /v1/messages/send`, `POST /v1/messages/modify`
/// - `GET /v1/drafts`, `POST /v1/drafts`, `POST /v1/drafts/{id}/send`, `DELETE /v1/drafts/{id}`
/// - `GET /v1/approvals`, `GET /v1/approvals/{id}`, `POST /v1/approvals/{id}/approve`, `POST /v1/approvals/{id}/reject`
/// - `GET /v1/labels`
/// - `GET /v1/search`
/// - `GET /v1/events` (SSE)
/// - `POST /v1/sync/gmail`, `GET /v1/sync/status`
pub fn ai_router() -> Router<AppState> {
    Router::new()
        .route("/v1/capabilities", get(get_capabilities))
        .route("/v1/briefing", get(briefing_handler))
        .route("/v1/threads", get(list_threads))
        .route("/v1/threads/batch_triage", post(batch_triage_handler))
        .route("/v1/threads/{id}", get(get_thread))
        .route("/v1/threads/{id}/triage", post(triage_thread_handler))
        .route(
            "/v1/threads/{id}/reply-context",
            get(get_reply_context_handler),
        )
        .route(
            "/v1/threads/{id}/snooze",
            post(snooze_thread_handler).delete(unsnooze_thread_handler),
        )
        .route(
            "/v1/threads/{id}/annotations",
            get(get_thread_annotations_handler)
                .put(put_thread_annotations_handler)
                .patch(patch_thread_annotations_handler)
                .delete(delete_thread_annotations_handler),
        )
        .route("/v1/scheduled", get(list_scheduled_sends_handler))
        .route("/v1/scheduled/{id}", delete(cancel_scheduled_send_handler))
        .route("/v1/messages", get(list_messages))
        .route("/v1/messages/send", post(send_message_handler))
        .route("/v1/messages/modify", post(modify_messages_handler))
        .route("/v1/messages/{id}", get(get_message))
        .route(
            "/v1/messages/{id}/unsubscribe",
            post(unsubscribe_message_handler),
        )
        .route(
            "/v1/messages/{id}/attachments/{attachment_id}",
            get(get_attachment_handler),
        )
        .route(
            "/v1/messages/{id}/attachments/{attachment_id}/text",
            get(get_attachment_text_handler),
        )
        .route("/v1/drafts", get(list_drafts).post(create_draft_handler))
        .route("/v1/drafts/{id}", delete(delete_draft_handler))
        .route("/v1/drafts/{id}/send", post(send_draft_handler))
        .route("/v1/approvals", get(list_approvals_handler))
        .route("/v1/approvals/{id}", get(get_approval_handler))
        .route("/v1/approvals/{id}/approve", post(approve_approval_handler))
        .route("/v1/approvals/{id}/reject", post(reject_approval_handler))
        .route("/v1/contacts", get(list_contacts_handler))
        .route(
            "/v1/contacts/{email}",
            get(get_contact_handler).patch(patch_contact_handler),
        )
        .route(
            "/v1/rules",
            get(list_rules_handler).post(create_rule_handler),
        )
        .route(
            "/v1/rules/{id}",
            patch(patch_rule_handler).delete(delete_rule_handler),
        )
        .route("/v1/rules/{id}/test", post(test_rule_handler))
        .route("/v1/audit", get(list_audit_handler))
        .route("/v1/labels", get(list_labels))
        .route("/v1/search", get(search_messages))
        .route("/v1/events", get(events_sse_handler))
        .route("/v1/sync/gmail", post(sync_gmail_handler))
        .route("/v1/sync/status", get(sync_status_handler))
}

// ============================================================================
// Shared Operations (used by REST `/v1`, MCP tools/resources, and CLI)
// ============================================================================

/// Optional JSON request body for `POST /v1/approvals/{id}/approve` and `/reject`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ApprovalDecisionRequest {
    #[serde(default)]
    pub decided_by: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

/// Execute an AI-first send (shared across `/v1/messages/send`, MCP `send_email`, and CLI `nogml mail send`).
pub async fn execute_send_email(state: &AppState, req: AiSendEmailRequest) -> AppResult<Value> {
    execute_send_email_with_context(state, req, None, EventSource::Api).await
}

/// Internal variant allowing callers (REST vs MCP) to tag the published [`EventSource`].
pub async fn execute_send_email_with_source(
    state: &AppState,
    req: AiSendEmailRequest,
    source: EventSource,
) -> AppResult<Value> {
    execute_send_email_with_context(state, req, None, source).await
}

/// Variant accepting the authenticated [`Principal`] for approval requester attribution
/// and per-agent [`crate::auth::AgentPolicyOverride`] enforcement.
pub async fn execute_send_email_with_context(
    state: &AppState,
    req: AiSendEmailRequest,
    principal: Option<Principal>,
    source: EventSource,
) -> AppResult<Value> {
    let channel = channel_for_source(source);
    let agent_policy = principal.as_ref().and_then(|p| p.agent_policy.clone());
    if req.dry_run {
        let preview =
            safety::evaluate_send_dry_run_with_policy(state, &req, agent_policy.as_ref()).await?;
        state
            .record_audit(
                principal.as_ref(),
                channel,
                "send",
                Vec::new(),
                "dry_run",
                Some(format!("would_succeed={}", preview.would_succeed)),
            )
            .await;
        return Ok(serde_json::to_value(preview)?);
    }

    let idempotency_key = normalize_idempotency_key(req.idempotency_key.as_deref())?;
    let _idem_guard = match idempotency_key.as_deref() {
        Some(key) => {
            let lock = state.idempotency_key_lock(IDEMPOTENCY_SCOPE_SEND, key);
            Some(lock.lock_owned().await)
        }
        None => None,
    };

    if let Some(ref key) = idempotency_key {
        let now_ms = Utc::now().timestamp_millis();
        if let Some(rec) = state
            .store
            .get_idempotency_key(IDEMPOTENCY_SCOPE_SEND, key, now_ms)
            .await?
        {
            let cached: Value = serde_json::from_str(&rec.response_json)?;
            state
                .record_audit(
                    principal.as_ref(),
                    channel,
                    "send",
                    extract_cached_target_ids(&cached),
                    "idempotent_replay",
                    Some(format!("idempotency_key={key}")),
                )
                .await;
            return Ok(cached);
        }
    }

    if let Some(subj) = req.subject.as_deref() {
        validate_email_header("subject", subj)?;
    }

    let resolved = safety::resolve_reply_threading(
        state,
        &req.to,
        &req.cc,
        &req.bcc,
        req.subject.as_deref(),
        req.text.as_deref(),
        req.html.as_deref(),
        req.reply_to_message_id.as_deref(),
    )
    .await?;

    validate_email_header("subject", &resolved.subject)?;

    if resolved.to.is_empty() {
        return Err(AppError::validation(
            "At least one 'to' recipient is required",
            Some(
                "Provide at least one email address in 'to', or supply 'reply_to_message_id'."
                    .to_string(),
            ),
        ));
    }

    validate_recipients_syntax(&resolved.to, &resolved.cc, &resolved.bcc)?;

    let policy_check = OutboundCheck {
        from: resolved.from.clone(),
        to: resolved.to.clone(),
        cc: resolved.cc.clone(),
        bcc: resolved.bcc.clone(),
        subject: resolved.subject.clone(),
        text: resolved.text.clone(),
        html: resolved.html.clone(),
        attachment_filenames: Vec::new(),
        thread_id: resolved.thread_id.clone(),
        mailbox_id: Some(state.mailbox_id().to_string()),
        is_draft_send: false,
        agent_policy,
    };
    let decision = state.evaluate_outbound_policy(&policy_check).await?;

    let rfc_message_id = format!("<{}@{}>", Uuid::new_v4(), state.config.default_domain);
    let raw_rfc2822 = build_outbound_rfc2822(&resolved, &rfc_message_id)?;
    let text_body = resolved.text.clone().unwrap_or_default();
    let snippet = generate_snippet(&text_body, resolved.html.as_deref());
    let now_ms = Utc::now().timestamp_millis();

    match decision {
        OutboundDecision::Deny { code, reason, hint } => {
            state
                .record_audit(
                    principal.as_ref(),
                    channel,
                    "send",
                    Vec::new(),
                    "denied",
                    Some(format!("{code}: {reason}")),
                )
                .await;
            return Err(policy_deny_to_error(code, reason, hint));
        }
        OutboundDecision::DowngradeToDraft { .. } => {
            let draft_input = NewMessageInput {
                id: None,
                thread_id: resolved.thread_id.clone(),
                label_ids: vec![LABEL_DRAFT.to_string()],
                raw_rfc2822,
                snippet,
                internal_date_ms: now_ms,
                subject: resolved.subject.clone(),
                from_addr: resolved.from.clone(),
                to_addrs: resolved.to.clone(),
                cc_addrs: resolved.cc.clone(),
                bcc_addrs: resolved.bcc.clone(),
                text_body,
                html_body: resolved.html.clone(),
                rfc822_message_id: Some(rfc_message_id),
                in_reply_to: resolved.in_reply_to.clone(),
                references_header: resolved.references.clone(),
                resend_id: None,
                upstream_gmail_id: None,
                upstream_thread_id: None,
                source: "local".to_string(),
                is_answered: false,
                is_deleted: false,
                attachments: Vec::new(),
            };
            let draft = state.store.create_draft(draft_input).await?;
            state.post_store_message(&draft.message).await?;
            state.events.publish(
                source,
                MailEvent::DraftCreated {
                    draft_id: draft.id.clone(),
                    message_id: draft.message.id.clone(),
                    thread_id: draft.message.thread_id.clone(),
                },
            );
            let resp = json!({
                "status": "draft_created",
                "downgraded_from_send": true,
                "draft_id": draft.id,
                "message_id": draft.message.id,
                "thread_id": draft.message.thread_id,
                "to": draft.message.to_addrs,
                "subject": draft.message.subject,
            });
            if let Some(ref key) = idempotency_key {
                let encoded = serde_json::to_string(&resp)?;
                state
                    .store
                    .put_idempotency_key(
                        IDEMPOTENCY_SCOPE_SEND,
                        key,
                        &encoded,
                        DEFAULT_IDEMPOTENCY_TTL_SECS,
                    )
                    .await?;
            }
            state
                .record_audit(
                    principal.as_ref(),
                    channel,
                    "send",
                    vec![draft.id.clone(), draft.message.id.clone()],
                    "downgraded_to_draft",
                    None,
                )
                .await;
            return Ok(resp);
        }
        OutboundDecision::HoldForApproval { reason } => {
            let mut outbound_msg = build_outbound_message(&resolved, &rfc_message_id, &raw_rfc2822);
            outbound_msg.idempotency_key = idempotency_key.clone();
            let draft_input = NewMessageInput {
                id: None,
                thread_id: resolved.thread_id.clone(),
                label_ids: vec![LABEL_DRAFT.to_string()],
                raw_rfc2822,
                snippet: snippet.clone(),
                internal_date_ms: now_ms,
                subject: resolved.subject.clone(),
                from_addr: resolved.from.clone(),
                to_addrs: resolved.to.clone(),
                cc_addrs: resolved.cc.clone(),
                bcc_addrs: resolved.bcc.clone(),
                text_body,
                html_body: resolved.html.clone(),
                rfc822_message_id: Some(rfc_message_id),
                in_reply_to: resolved.in_reply_to.clone(),
                references_header: resolved.references.clone(),
                resend_id: None,
                upstream_gmail_id: None,
                upstream_thread_id: None,
                source: "local".to_string(),
                is_answered: false,
                is_deleted: false,
                attachments: Vec::new(),
            };
            let draft = state.store.create_draft(draft_input).await?;
            state.post_store_message(&draft.message).await?;
            state.events.publish(
                source,
                MailEvent::DraftCreated {
                    draft_id: draft.id.clone(),
                    message_id: draft.message.id.clone(),
                    thread_id: draft.message.thread_id.clone(),
                },
            );

            let preview_snippet = safe_hold_preview_snippet(&state.config, &snippet);
            let approval = enqueue_pending_approval(
                state,
                reason,
                principal.clone(),
                outbound_msg,
                req.reply_to_message_id.clone(),
                Some(draft.message.thread_id.clone()),
                Some(draft.id.clone()),
                now_ms,
                preview_snippet,
                source,
            )
            .await?;

            let resp = build_hold_response(
                &approval,
                Some(&draft.id),
                Some(&draft.message.id),
                Some(&draft.message.thread_id),
                preview_snippet,
            );
            if let Some(ref key) = idempotency_key {
                let encoded = serde_json::to_string(&resp)?;
                state
                    .store
                    .put_idempotency_key(
                        IDEMPOTENCY_SCOPE_SEND,
                        key,
                        &encoded,
                        DEFAULT_IDEMPOTENCY_TTL_SECS,
                    )
                    .await?;
            }
            state
                .record_audit(
                    principal.as_ref(),
                    channel,
                    "send",
                    vec![approval.id.clone(), draft.id.clone()],
                    "pending_approval",
                    Some(approval.reason.clone()),
                )
                .await;
            return Ok(resp);
        }
        OutboundDecision::Allow => {}
    }

    if let Some(send_at) = req.send_at {
        let send_at = truncate_to_millis(send_at);
        let send_at_ms = send_at.timestamp_millis();
        if send_at_ms > now_ms {
            let mut outbound_msg = build_outbound_message(&resolved, &rfc_message_id, &raw_rfc2822);
            outbound_msg.idempotency_key = idempotency_key.clone();
            let scheduled = state
                .store
                .create_scheduled_send(&NewScheduledSend {
                    id: None,
                    send_at_ms,
                    outbound_message: outbound_msg,
                    reply_to_message_id: req.reply_to_message_id.clone(),
                    thread_id: resolved.thread_id.clone(),
                    created_at_ms: now_ms,
                })
                .await?;
            let scheduled_at =
                DateTime::from_timestamp_millis(scheduled.send_at_ms).unwrap_or(send_at);
            let resp = json!({
                "status": "scheduled",
                "scheduled_id": scheduled.id,
                "send_at": scheduled_at,
                "send_at_ms": scheduled.send_at_ms,
                "thread_id": scheduled.thread_id,
                "preview": {
                    "from": scheduled.outbound_message.from,
                    "to": scheduled.outbound_message.to,
                    "cc": scheduled.outbound_message.cc,
                    "bcc": scheduled.outbound_message.bcc,
                    "subject": scheduled.outbound_message.subject,
                    "snippet": snippet,
                    "estimated_bytes": scheduled.outbound_message.raw_rfc2822.len(),
                },
            });
            if let Some(ref key) = idempotency_key {
                let encoded = serde_json::to_string(&resp)?;
                state
                    .store
                    .put_idempotency_key(
                        IDEMPOTENCY_SCOPE_SEND,
                        key,
                        &encoded,
                        DEFAULT_IDEMPOTENCY_TTL_SECS,
                    )
                    .await?;
            }
            state
                .record_audit(
                    principal.as_ref(),
                    channel,
                    "schedule_send",
                    vec![scheduled.id.clone()],
                    "scheduled",
                    Some(format!(
                        "send_at={} to={}",
                        scheduled_at.to_rfc3339(),
                        scheduled.outbound_message.to.join(",")
                    )),
                )
                .await;
            return Ok(resp);
        }
    }

    let mut outbound_msg = build_outbound_message(&resolved, &rfc_message_id, &raw_rfc2822);
    outbound_msg.idempotency_key = idempotency_key.clone();
    let send_outcome = state
        .transport
        .send(&outbound_msg, idempotency_key.as_deref())
        .await?;

    let stored = state
        .store
        .insert_message(NewMessageInput {
            id: None,
            thread_id: resolved.thread_id.clone(),
            label_ids: vec![LABEL_SENT.to_string()],
            raw_rfc2822,
            snippet,
            internal_date_ms: now_ms,
            subject: resolved.subject.clone(),
            from_addr: resolved.from.clone(),
            to_addrs: resolved.to.clone(),
            cc_addrs: resolved.cc.clone(),
            bcc_addrs: resolved.bcc.clone(),
            text_body,
            html_body: resolved.html.clone(),
            rfc822_message_id: Some(rfc_message_id),
            in_reply_to: resolved.in_reply_to.clone(),
            references_header: resolved.references.clone(),
            resend_id: Some(send_outcome.provider_message_id.clone()),
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "local".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: Vec::new(),
        })
        .await?;

    state.post_store_message(&stored).await?;
    state.metrics.inc_messages_sent();

    state.events.publish(
        source,
        MailEvent::MessageSent {
            message_id: stored.id.clone(),
            thread_id: stored.thread_id.clone(),
            to: stored.to_addrs.clone(),
            subject: stored.subject.clone(),
            resend_id: Some(send_outcome.provider_message_id.clone()),
            labels: stored.label_ids.clone(),
        },
    );

    let resp = json!({
        "status": "sent",
        "provider": send_outcome.provider,
        "message_id": stored.id,
        "thread_id": stored.thread_id,
        "resend_id": send_outcome.provider_message_id,
        "from": stored.from_addr,
        "to": stored.to_addrs,
        "cc": stored.cc_addrs,
        "bcc": stored.bcc_addrs,
        "subject": stored.subject,
        "in_reply_to": stored.in_reply_to,
        "references": stored.references_header,
        "rfc_message_id": stored.rfc822_message_id,
    });

    if let Some(ref key) = idempotency_key {
        let encoded = serde_json::to_string(&resp)?;
        state
            .store
            .put_idempotency_key(
                IDEMPOTENCY_SCOPE_SEND,
                key,
                &encoded,
                DEFAULT_IDEMPOTENCY_TTL_SECS,
            )
            .await?;
    }

    state
        .record_audit(
            principal.as_ref(),
            channel,
            "send",
            vec![stored.id.clone(), stored.thread_id.clone()],
            "ok",
            Some(format!("to={}", stored.to_addrs.join(","))),
        )
        .await;

    Ok(resp)
}

/// Execute an AI-first draft creation (shared across `/v1/drafts`, MCP `create_draft`, and CLI).
pub async fn execute_create_draft(state: &AppState, req: AiCreateDraftRequest) -> AppResult<Value> {
    execute_create_draft_with_context(state, req, None, EventSource::Api).await
}

/// Internal variant allowing callers to tag the published [`EventSource`].
pub async fn execute_create_draft_with_source(
    state: &AppState,
    req: AiCreateDraftRequest,
    source: EventSource,
) -> AppResult<Value> {
    execute_create_draft_with_context(state, req, None, source).await
}

/// Variant accepting the authenticated [`Principal`] for audit attribution and idempotency handling.
pub async fn execute_create_draft_with_context(
    state: &AppState,
    req: AiCreateDraftRequest,
    principal: Option<Principal>,
    source: EventSource,
) -> AppResult<Value> {
    let channel = channel_for_source(source);
    let idempotency_key = normalize_idempotency_key(req.idempotency_key.as_deref())?;
    let _idem_guard = match idempotency_key.as_deref() {
        Some(key) => {
            let lock = state.idempotency_key_lock(IDEMPOTENCY_SCOPE_DRAFT, key);
            Some(lock.lock_owned().await)
        }
        None => None,
    };

    if let Some(ref key) = idempotency_key {
        let now_ms = Utc::now().timestamp_millis();
        if let Some(rec) = state
            .store
            .get_idempotency_key(IDEMPOTENCY_SCOPE_DRAFT, key, now_ms)
            .await?
        {
            let cached: Value = serde_json::from_str(&rec.response_json)?;
            state
                .record_audit(
                    principal.as_ref(),
                    channel,
                    "draft",
                    extract_cached_target_ids(&cached),
                    "idempotent_replay",
                    Some(format!("idempotency_key={key}")),
                )
                .await;
            return Ok(cached);
        }
    }

    if let Some(subj) = req.subject.as_deref() {
        validate_email_header("subject", subj)?;
    }
    for (field, list) in [("to", &req.to), ("cc", &req.cc), ("bcc", &req.bcc)] {
        for addr in list {
            validate_email_header(field, addr)?;
        }
    }

    let resolved = safety::resolve_reply_threading(
        state,
        &req.to,
        &req.cc,
        &req.bcc,
        req.subject.as_deref(),
        req.text.as_deref(),
        req.html.as_deref(),
        req.reply_to_message_id.as_deref(),
    )
    .await?;

    validate_email_header("subject", &resolved.subject)?;

    let rfc_message_id = format!("<{}@{}>", Uuid::new_v4(), state.config.default_domain);
    let raw_rfc2822 = build_outbound_rfc2822(&resolved, &rfc_message_id)?;
    let text_body = resolved.text.clone().unwrap_or_default();
    let snippet = generate_snippet(&text_body, resolved.html.as_deref());
    let now_ms = Utc::now().timestamp_millis();

    let draft = state
        .store
        .create_draft(NewMessageInput {
            id: None,
            thread_id: resolved.thread_id.clone(),
            label_ids: vec![LABEL_DRAFT.to_string()],
            raw_rfc2822,
            snippet,
            internal_date_ms: now_ms,
            subject: resolved.subject.clone(),
            from_addr: resolved.from.clone(),
            to_addrs: resolved.to.clone(),
            cc_addrs: resolved.cc.clone(),
            bcc_addrs: resolved.bcc.clone(),
            text_body,
            html_body: resolved.html.clone(),
            rfc822_message_id: Some(rfc_message_id),
            in_reply_to: resolved.in_reply_to.clone(),
            references_header: resolved.references.clone(),
            resend_id: None,
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "local".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: Vec::new(),
        })
        .await?;

    state.post_store_message(&draft.message).await?;

    state.events.publish(
        source,
        MailEvent::DraftCreated {
            draft_id: draft.id.clone(),
            message_id: draft.message.id.clone(),
            thread_id: draft.message.thread_id.clone(),
        },
    );

    let resp = json!({
        "status": "draft_created",
        "draft_id": draft.id,
        "message_id": draft.message.id,
        "thread_id": draft.message.thread_id,
        "to": draft.message.to_addrs,
        "cc": draft.message.cc_addrs,
        "bcc": draft.message.bcc_addrs,
        "subject": draft.message.subject,
        "in_reply_to": draft.message.in_reply_to,
        "references": draft.message.references_header,
    });

    if let Some(ref key) = idempotency_key {
        let encoded = serde_json::to_string(&resp)?;
        state
            .store
            .put_idempotency_key(
                IDEMPOTENCY_SCOPE_DRAFT,
                key,
                &encoded,
                DEFAULT_IDEMPOTENCY_TTL_SECS,
            )
            .await?;
    }

    state
        .record_audit(
            principal.as_ref(),
            channel,
            "draft",
            vec![draft.id.clone(), draft.message.id.clone()],
            "ok",
            None,
        )
        .await;

    Ok(resp)
}

/// Execute sending an existing draft (shared across `/v1/drafts/{id}/send` and MCP `send_draft`).
pub async fn execute_send_draft(
    state: &AppState,
    draft_id: &str,
    req: AiSendDraftRequest,
) -> AppResult<Value> {
    execute_send_draft_with_context(state, draft_id, req, None, EventSource::Api).await
}

/// Internal variant allowing callers to tag the published [`EventSource`].
pub async fn execute_send_draft_with_source(
    state: &AppState,
    draft_id: &str,
    req: AiSendDraftRequest,
    source: EventSource,
) -> AppResult<Value> {
    execute_send_draft_with_context(state, draft_id, req, None, source).await
}

/// Variant accepting the authenticated [`Principal`] for approval requester attribution
/// and per-agent [`crate::auth::AgentPolicyOverride`] enforcement.
pub async fn execute_send_draft_with_context(
    state: &AppState,
    draft_id: &str,
    req: AiSendDraftRequest,
    principal: Option<Principal>,
    source: EventSource,
) -> AppResult<Value> {
    let channel = channel_for_source(source);
    let agent_policy = principal.as_ref().and_then(|p| p.agent_policy.clone());
    validate_resource_id(draft_id)?;

    let draft = state
        .store
        .get_draft(draft_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Draft '{draft_id}' not found")))?;

    let msg = &draft.message;
    let attachment_filenames: Vec<String> = if msg.has_attachments {
        state
            .store
            .list_attachment_meta(&msg.id)
            .await?
            .into_iter()
            .filter_map(|m| m.filename)
            .collect()
    } else {
        Vec::new()
    };

    if req.dry_run {
        let preview = safety::evaluate_resolved_dry_run(
            state,
            &msg.to_addrs,
            &msg.cc_addrs,
            &msg.bcc_addrs,
            Some(&msg.subject),
            (!msg.text_body.is_empty()).then_some(msg.text_body.as_str()),
            msg.html_body.as_deref(),
            &attachment_filenames,
            None,
            Some(&msg.thread_id),
            msg.in_reply_to.as_deref(),
            msg.references_header.as_deref(),
            Some(msg.raw_rfc2822.len()),
            agent_policy.as_ref(),
        )
        .await?;
        state
            .record_audit(
                principal.as_ref(),
                channel,
                "send",
                vec![draft_id.to_string()],
                "dry_run",
                Some(format!("would_succeed={}", preview.would_succeed)),
            )
            .await;
        return Ok(serde_json::to_value(preview)?);
    }

    validate_email_header("subject", &msg.subject)?;
    if msg.to_addrs.is_empty() {
        return Err(AppError::validation(
            "Draft has no 'to' recipients and cannot be sent",
            Some("Update the draft with at least one recipient before sending.".to_string()),
        ));
    }

    validate_recipients_syntax(&msg.to_addrs, &msg.cc_addrs, &msg.bcc_addrs)?;

    let resolved = safety::ResolvedOutbound {
        from: if msg.from_addr.trim().is_empty() {
            state.config.user_email.clone()
        } else {
            msg.from_addr.clone()
        },
        to: msg.to_addrs.clone(),
        cc: msg.cc_addrs.clone(),
        bcc: msg.bcc_addrs.clone(),
        subject: msg.subject.clone(),
        text: (!msg.text_body.is_empty()).then(|| msg.text_body.clone()),
        html: msg.html_body.clone(),
        thread_id: Some(msg.thread_id.clone()),
        in_reply_to: msg.in_reply_to.clone(),
        references: msg.references_header.clone(),
    };

    let policy_check = OutboundCheck {
        from: resolved.from.clone(),
        to: resolved.to.clone(),
        cc: resolved.cc.clone(),
        bcc: resolved.bcc.clone(),
        subject: resolved.subject.clone(),
        text: resolved.text.clone(),
        html: resolved.html.clone(),
        attachment_filenames,
        thread_id: resolved.thread_id.clone(),
        mailbox_id: Some(state.mailbox_id().to_string()),
        is_draft_send: true,
        agent_policy,
    };
    let decision = state.evaluate_outbound_policy(&policy_check).await?;
    match decision {
        OutboundDecision::Deny { code, reason, hint } => {
            state
                .record_audit(
                    principal.as_ref(),
                    channel,
                    "send",
                    vec![draft_id.to_string()],
                    "denied",
                    Some(format!("{code}: {reason}")),
                )
                .await;
            return Err(policy_deny_to_error(code, reason, hint));
        }
        OutboundDecision::DowngradeToDraft { .. } => {
            state
                .record_audit(
                    principal.as_ref(),
                    channel,
                    "send",
                    vec![draft.id.clone(), msg.id.clone()],
                    "downgraded_to_draft",
                    None,
                )
                .await;
            return Ok(json!({
                "status": "draft_created",
                "downgraded_from_send": true,
                "draft_id": draft.id,
                "message_id": msg.id,
                "thread_id": msg.thread_id,
                "to": msg.to_addrs,
                "subject": msg.subject,
            }));
        }
        OutboundDecision::HoldForApproval { reason } => {
            let rfc_message_id = msg
                .rfc822_message_id
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| format!("<{}@{}>", Uuid::new_v4(), state.config.default_domain));

            let raw_rfc2822 = if msg.raw_rfc2822.is_empty() {
                build_outbound_rfc2822(&resolved, &rfc_message_id)?
            } else {
                state.load_raw_rfc2822(msg).await?
            };

            let mut outbound_msg = build_outbound_message(&resolved, &rfc_message_id, &raw_rfc2822);
            if msg.has_attachments {
                let metas = state.store.list_attachment_meta(&msg.id).await?;
                for meta in metas {
                    if let Some(att) = state.store.get_attachment(&msg.id, &meta.id).await? {
                        let data = state.load_attachment_bytes(&att).await?;
                        outbound_msg.attachments.push(OutboundAttachment {
                            filename: att.filename,
                            content_type: att.content_type,
                            content_id: att.content_id,
                            data,
                        });
                    }
                }
            }

            let now_ms = Utc::now().timestamp_millis();
            let preview_snippet = safe_hold_preview_snippet(&state.config, &msg.snippet);
            let approval = enqueue_pending_approval(
                state,
                reason,
                principal.clone(),
                outbound_msg,
                None,
                Some(msg.thread_id.clone()),
                Some(draft.id.clone()),
                now_ms,
                preview_snippet,
                source,
            )
            .await?;

            state
                .record_audit(
                    principal.as_ref(),
                    channel,
                    "send",
                    vec![approval.id.clone(), draft.id.clone()],
                    "pending_approval",
                    Some(approval.reason.clone()),
                )
                .await;

            return Ok(build_hold_response(
                &approval,
                Some(&draft.id),
                Some(&msg.id),
                Some(&msg.thread_id),
                preview_snippet,
            ));
        }
        OutboundDecision::Allow => {}
    }

    let rfc_message_id = msg
        .rfc822_message_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("<{}@{}>", Uuid::new_v4(), state.config.default_domain));

    let raw_rfc2822 = if msg.raw_rfc2822.is_empty() {
        build_outbound_rfc2822(&resolved, &rfc_message_id)?
    } else {
        state.load_raw_rfc2822(msg).await?
    };

    let outbound_msg = build_outbound_message(&resolved, &rfc_message_id, &raw_rfc2822);
    let send_outcome = state.transport.send(&outbound_msg, None).await?;

    let _ = state.store.delete_draft(draft_id).await?;
    let _ = state.post_delete_message(&msg.id, &[]).await;

    let stored = state
        .store
        .insert_message(NewMessageInput {
            id: None,
            thread_id: Some(msg.thread_id.clone()),
            label_ids: vec![LABEL_SENT.to_string()],
            raw_rfc2822,
            snippet: msg.snippet.clone(),
            internal_date_ms: Utc::now().timestamp_millis(),
            subject: resolved.subject.clone(),
            from_addr: resolved.from.clone(),
            to_addrs: resolved.to.clone(),
            cc_addrs: resolved.cc.clone(),
            bcc_addrs: resolved.bcc.clone(),
            text_body: msg.text_body.clone(),
            html_body: msg.html_body.clone(),
            rfc822_message_id: Some(rfc_message_id),
            in_reply_to: msg.in_reply_to.clone(),
            references_header: msg.references_header.clone(),
            resend_id: Some(send_outcome.provider_message_id.clone()),
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "local".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: Vec::new(),
        })
        .await?;

    state.post_store_message(&stored).await?;
    state.metrics.inc_messages_sent();

    state.events.publish(
        source,
        MailEvent::MessageSent {
            message_id: stored.id.clone(),
            thread_id: stored.thread_id.clone(),
            to: stored.to_addrs.clone(),
            subject: stored.subject.clone(),
            resend_id: Some(send_outcome.provider_message_id.clone()),
            labels: stored.label_ids.clone(),
        },
    );

    state
        .record_audit(
            principal.as_ref(),
            channel,
            "send",
            vec![stored.id.clone(), draft_id.to_string()],
            "ok",
            Some(format!("to={}", stored.to_addrs.join(","))),
        )
        .await;

    Ok(json!({
        "status": "sent",
        "provider": send_outcome.provider,
        "draft_id": draft_id,
        "message_id": stored.id,
        "thread_id": stored.thread_id,
        "resend_id": send_outcome.provider_message_id,
        "to": stored.to_addrs,
        "subject": stored.subject,
    }))
}

/// Execute thread triage (shared across `/v1/threads/{id}/triage`, MCP `triage_thread`, and CLI).
pub async fn execute_triage_thread(
    state: &AppState,
    thread_id: &str,
    req: AiTriageRequest,
) -> AppResult<Value> {
    execute_triage_thread_with_context(state, thread_id, req, None, EventSource::Api).await
}

/// Internal variant allowing callers to tag the published [`EventSource`].
pub async fn execute_triage_thread_with_source(
    state: &AppState,
    thread_id: &str,
    req: AiTriageRequest,
    source: EventSource,
) -> AppResult<Value> {
    execute_triage_thread_with_context(state, thread_id, req, None, source).await
}

/// Variant accepting the authenticated [`Principal`] for audit attribution.
pub async fn execute_triage_thread_with_context(
    state: &AppState,
    thread_id: &str,
    req: AiTriageRequest,
    principal: Option<Principal>,
    source: EventSource,
) -> AppResult<Value> {
    let channel = channel_for_source(source);
    validate_resource_id(thread_id)?;

    if req.mark_read == Some(true) && req.mark_unread == Some(true) {
        return Err(AppError::validation(
            "Cannot set both mark_read and mark_unread to true",
            Some("Specify only one of mark_read or mark_unread.".to_string()),
        ));
    }

    for lbl in req.add_labels.iter().chain(req.remove_labels.iter()) {
        validate_resource_id(lbl)?;
    }

    let (add_labels, remove_labels) = compute_triage_labels(
        req.archive,
        req.mark_read,
        req.mark_unread,
        req.star,
        req.trash,
        &req.add_labels,
        &req.remove_labels,
    );

    let thread = state
        .store
        .get_thread(thread_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Thread '{thread_id}' not found")))?;

    let affected_ids: Vec<String> = thread.messages.iter().map(|m| m.id.clone()).collect();

    if req.dry_run {
        state
            .record_audit(
                principal.as_ref(),
                channel,
                "triage",
                vec![thread.id.clone()],
                "dry_run",
                None,
            )
            .await;
        return Ok(json!({
            "dry_run": true,
            "would_succeed": true,
            "thread_id": thread.id,
            "affected_message_ids": affected_ids,
            "add_labels": add_labels,
            "remove_labels": remove_labels,
            "policy_checks": [
                {
                    "rule": "thread_exists",
                    "passed": true,
                    "detail": format!("Thread '{}' contains {} message(s)", thread.id, thread.messages.len()),
                }
            ]
        }));
    }

    let result = state
        .store
        .triage_thread(
            thread_id,
            &TriagePatch {
                add_labels: add_labels.clone(),
                remove_labels: remove_labels.clone(),
            },
        )
        .await?;

    if !add_labels.is_empty() || !remove_labels.is_empty() {
        for message_id in &result.affected_message_ids {
            state.events.publish(
                source,
                MailEvent::MessageUpdated {
                    message_id: message_id.clone(),
                    thread_id: result.thread_id.clone(),
                    added_labels: add_labels.clone(),
                    removed_labels: remove_labels.clone(),
                },
            );
        }
    }

    let mut target_ids = vec![result.thread_id.clone()];
    target_ids.extend(result.affected_message_ids.iter().cloned());
    state
        .record_audit(
            principal.as_ref(),
            channel,
            "triage",
            target_ids,
            "ok",
            Some(format!(
                "add=[{}] remove=[{}]",
                add_labels.join(","),
                remove_labels.join(",")
            )),
        )
        .await;

    Ok(json!({
        "thread_id": result.thread_id,
        "affected_message_ids": result.affected_message_ids,
        "labels": result.labels,
        "added_labels": add_labels,
        "removed_labels": remove_labels,
    }))
}

/// Execute atomic batch thread triage (shared across `/v1/threads/batch_triage`, MCP `batch_triage`, and CLI).
pub async fn execute_batch_triage(state: &AppState, req: AiBatchTriageRequest) -> AppResult<Value> {
    execute_batch_triage_with_context(state, req, None, EventSource::Api).await
}

/// Internal variant allowing callers (REST vs MCP) to tag the published [`EventSource`].
pub async fn execute_batch_triage_with_source(
    state: &AppState,
    req: AiBatchTriageRequest,
    source: EventSource,
) -> AppResult<Value> {
    execute_batch_triage_with_context(state, req, None, source).await
}

fn resolve_batch_shared_action(req: &AiBatchTriageRequest) -> Option<AiTriageRequest> {
    let has_top_level = req.archive.is_some()
        || req.mark_read.is_some()
        || req.mark_unread.is_some()
        || req.star.is_some()
        || req.trash.is_some()
        || !req.add_labels.is_empty()
        || !req.remove_labels.is_empty();

    match (&req.action, has_top_level) {
        (Some(action), false) => Some(action.clone()),
        (None, true) => Some(AiTriageRequest {
            archive: req.archive,
            mark_read: req.mark_read,
            mark_unread: req.mark_unread,
            star: req.star,
            trash: req.trash,
            add_labels: req.add_labels.clone(),
            remove_labels: req.remove_labels.clone(),
            dry_run: req.dry_run,
        }),
        (Some(action), true) => {
            let mut merged = action.clone();
            if merged.archive.is_none() {
                merged.archive = req.archive;
            }
            if merged.mark_read.is_none() {
                merged.mark_read = req.mark_read;
            }
            if merged.mark_unread.is_none() {
                merged.mark_unread = req.mark_unread;
            }
            if merged.star.is_none() {
                merged.star = req.star;
            }
            if merged.trash.is_none() {
                merged.trash = req.trash;
            }
            merged.add_labels.extend(req.add_labels.iter().cloned());
            merged
                .remove_labels
                .extend(req.remove_labels.iter().cloned());
            Some(merged)
        }
        (None, false) => None,
    }
}

fn resolve_mailbox_label_id(labels: &[StoredLabel], raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(exact) = labels.iter().find(|l| l.id == trimmed) {
        return Some(exact.id.clone());
    }
    labels
        .iter()
        .find(|l| l.name.eq_ignore_ascii_case(trimmed))
        .map(|l| l.id.clone())
}

#[allow(clippy::too_many_arguments)]
fn compute_resolved_triage_patch(
    mailbox_labels: &[StoredLabel],
    archive: Option<bool>,
    mark_read: Option<bool>,
    mark_unread: Option<bool>,
    star: Option<bool>,
    trash: Option<bool>,
    extra_add: &[String],
    extra_remove: &[String],
) -> AppResult<(Vec<String>, Vec<String>)> {
    if mark_read == Some(true) && mark_unread == Some(true) {
        return Err(AppError::validation(
            "Cannot set both mark_read and mark_unread to true",
            Some("Specify only one of mark_read or mark_unread.".to_string()),
        ));
    }

    for lbl in extra_add.iter().chain(extra_remove.iter()) {
        validate_resource_id(lbl)?;
    }

    let (raw_add, raw_remove) = compute_triage_labels(
        archive,
        mark_read,
        mark_unread,
        star,
        trash,
        extra_add,
        extra_remove,
    );

    let mut resolved_add = Vec::with_capacity(raw_add.len());
    for lbl in &raw_add {
        let lid = resolve_mailbox_label_id(mailbox_labels, lbl).ok_or_else(|| {
            AppError::validation(
                format!("Label not found: {lbl}"),
                Some("Create the label first or use an existing label ID or name.".to_string()),
            )
        })?;
        resolved_add.push(lid);
    }

    let mut resolved_remove = Vec::with_capacity(raw_remove.len());
    for lbl in &raw_remove {
        if let Some(lid) = resolve_mailbox_label_id(mailbox_labels, lbl) {
            resolved_remove.push(lid);
        }
    }

    dedup_preserve_order(&mut resolved_add);
    dedup_preserve_order(&mut resolved_remove);
    resolved_add.retain(|l| !resolved_remove.contains(l));

    Ok((resolved_add, resolved_remove))
}

fn merge_thread_label_patch(
    patches: &mut HashMap<String, (Vec<String>, Vec<String>)>,
    order: &mut Vec<String>,
    thread_id: String,
    add: Vec<String>,
    remove: Vec<String>,
) {
    if let Some((existing_add, existing_remove)) = patches.get_mut(&thread_id) {
        for lbl in add {
            existing_remove.retain(|r| r != &lbl);
            if !existing_add.contains(&lbl) {
                existing_add.push(lbl);
            }
        }
        for lbl in remove {
            existing_add.retain(|a| a != &lbl);
            if !existing_remove.contains(&lbl) {
                existing_remove.push(lbl);
            }
        }
    } else {
        order.push(thread_id.clone());
        patches.insert(thread_id, (add, remove));
    }
}

fn max_threads_exceeded_error(count_desc: String, effective_max: usize) -> AppError {
    AppError::validation(
        format!(
            "Batch triage resolved {count_desc} unique thread(s), exceeding max_threads limit of {effective_max}"
        ),
        Some(format!(
            "Narrow your query, split the batch, or raise max_threads (hard limit {HARD_MAX_BATCH_TRIAGE_THREADS})."
        )),
    )
}

fn thread_subject_for_triage(detail: &StoredThreadDetail, guard: bool) -> String {
    let raw = detail
        .messages
        .iter()
        .find_map(|m| (!m.subject.trim().is_empty()).then_some(m.subject.as_str()))
        .unwrap_or("");
    if guard {
        sanitize_untrusted_text(raw)
    } else {
        raw.to_string()
    }
}

fn thread_current_labels(detail: &StoredThreadDetail) -> Vec<String> {
    let mut set = HashSet::new();
    for msg in &detail.messages {
        for lbl in &msg.label_ids {
            set.insert(lbl.clone());
        }
    }
    let mut labels: Vec<String> = set.into_iter().collect();
    labels.sort();
    labels
}

/// Variant accepting the authenticated [`Principal`] for audit attribution.
pub async fn execute_batch_triage_with_context(
    state: &AppState,
    req: AiBatchTriageRequest,
    principal: Option<Principal>,
    source: EventSource,
) -> AppResult<Value> {
    let channel = channel_for_source(source);

    if req.max_threads == Some(0) {
        return Err(AppError::validation(
            "max_threads must be at least 1",
            Some(format!(
                "Provide a max_threads value between 1 and {HARD_MAX_BATCH_TRIAGE_THREADS}."
            )),
        ));
    }
    let effective_max_threads = req
        .max_threads
        .unwrap_or(DEFAULT_BATCH_TRIAGE_MAX_THREADS)
        .min(HARD_MAX_BATCH_TRIAGE_THREADS);

    let query_str = req
        .query
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if req.operations.is_empty() && req.thread_ids.is_empty() && query_str.is_none() {
        return Err(AppError::validation(
            "Batch triage requires at least one of 'operations', 'thread_ids', or 'query'",
            Some(
                "Provide 'operations' for per-thread actions, or 'thread_ids'/'query' with a shared triage action."
                    .to_string(),
            ),
        ));
    }

    let shared_action = resolve_batch_shared_action(&req);
    if (!req.thread_ids.is_empty() || query_str.is_some()) && shared_action.is_none() {
        return Err(AppError::validation(
            "A shared triage action is required when 'thread_ids' or 'query' is provided",
            Some(
                "Provide 'action' or top-level flags such as 'archive', 'mark_read', 'star', 'trash', 'add_labels', or 'remove_labels'."
                    .to_string(),
            ),
        ));
    }

    for tid in &req.thread_ids {
        validate_resource_id(tid)?;
    }
    for op in &req.operations {
        validate_resource_id(&op.thread_id)?;
    }

    let mailbox_labels = state.store.list_labels().await?;

    let shared_patch = match shared_action {
        Some(ref action) => Some(compute_resolved_triage_patch(
            &mailbox_labels,
            action.archive,
            action.mark_read,
            action.mark_unread,
            action.star,
            action.trash,
            &action.add_labels,
            &action.remove_labels,
        )?),
        None => None,
    };

    let mut resolved_ops: Vec<(String, Vec<String>, Vec<String>)> =
        Vec::with_capacity(req.operations.len());
    for op in &req.operations {
        let (add, remove) = compute_resolved_triage_patch(
            &mailbox_labels,
            op.archive,
            op.mark_read,
            op.mark_unread,
            op.star,
            op.trash,
            &op.add_labels,
            &op.remove_labels,
        )?;
        resolved_ops.push((op.thread_id.clone(), add, remove));
    }

    let mut order: Vec<String> = Vec::new();
    let mut patches: HashMap<String, (Vec<String>, Vec<String>)> = HashMap::new();
    let mut threads_by_id: HashMap<String, StoredThreadDetail> = HashMap::new();

    if let Some(q) = query_str {
        let (shared_add, shared_remove) = shared_patch
            .as_ref()
            .expect("validated shared_action presence for query");
        let page_size = (effective_max_threads + 1).min(HARD_MAX_BATCH_TRIAGE_THREADS);
        let mut page_token: Option<String> = None;

        loop {
            let page = state
                .store
                .list_threads(&MessageListQuery {
                    q: Some(q.to_string()),
                    label_ids: Vec::new(),
                    include_spam_trash: req.include_spam_trash,
                    max_results: page_size,
                    page_token: page_token.clone(),
                })
                .await?;

            for detail in page.threads {
                let tid = detail.id.clone();
                threads_by_id.entry(tid.clone()).or_insert(detail);
                merge_thread_label_patch(
                    &mut patches,
                    &mut order,
                    tid,
                    shared_add.clone(),
                    shared_remove.clone(),
                );
                if order.len() > effective_max_threads {
                    return Err(max_threads_exceeded_error(
                        order.len().to_string(),
                        effective_max_threads,
                    ));
                }
            }

            if let Some(next_token) = page.next_page_token {
                if order.len() >= effective_max_threads {
                    return Err(max_threads_exceeded_error(
                        format!("more than {effective_max_threads}"),
                        effective_max_threads,
                    ));
                }
                page_token = Some(next_token);
            } else {
                break;
            }
        }
    }

    if !req.thread_ids.is_empty() {
        let (shared_add, shared_remove) = shared_patch
            .as_ref()
            .expect("validated shared_action presence for thread_ids");
        for tid in &req.thread_ids {
            merge_thread_label_patch(
                &mut patches,
                &mut order,
                tid.clone(),
                shared_add.clone(),
                shared_remove.clone(),
            );
            if order.len() > effective_max_threads {
                return Err(max_threads_exceeded_error(
                    order.len().to_string(),
                    effective_max_threads,
                ));
            }
        }
    }

    for (tid, add, remove) in resolved_ops {
        merge_thread_label_patch(&mut patches, &mut order, tid, add, remove);
        if order.len() > effective_max_threads {
            return Err(max_threads_exceeded_error(
                order.len().to_string(),
                effective_max_threads,
            ));
        }
    }

    // Validate existence of every target thread upfront before mutating anything.
    for tid in &order {
        if !threads_by_id.contains_key(tid) {
            let detail = state
                .store
                .get_thread(tid)
                .await?
                .ok_or_else(|| AppError::NotFound(format!("Thread '{tid}' not found")))?;
            threads_by_id.insert(tid.clone(), detail);
        }
    }

    struct PlannedThreadTriage {
        thread_id: String,
        subject: String,
        current_labels: Vec<String>,
        labels_to_add: Vec<String>,
        labels_to_remove: Vec<String>,
        would_change: bool,
    }

    let guard = state.config.untrusted_content_guard;
    let mut plans: Vec<PlannedThreadTriage> = Vec::with_capacity(order.len());

    for tid in &order {
        let detail = &threads_by_id[tid];
        let (req_add, req_remove) = &patches[tid];
        let subject = thread_subject_for_triage(detail, guard);
        let current_labels = thread_current_labels(detail);

        let labels_to_add: Vec<String> = req_add
            .iter()
            .filter(|lbl| detail.messages.iter().any(|m| !m.label_ids.contains(lbl)))
            .cloned()
            .collect();
        let labels_to_remove: Vec<String> = req_remove
            .iter()
            .filter(|lbl| detail.messages.iter().any(|m| m.label_ids.contains(lbl)))
            .cloned()
            .collect();
        let would_change = !labels_to_add.is_empty() || !labels_to_remove.is_empty();

        plans.push(PlannedThreadTriage {
            thread_id: tid.clone(),
            subject,
            current_labels,
            labels_to_add,
            labels_to_remove,
            would_change,
        });
    }

    if req.dry_run {
        let preview: Vec<BatchTriagePreviewItem> = plans
            .into_iter()
            .map(|p| BatchTriagePreviewItem {
                thread_id: p.thread_id,
                subject: p.subject,
                current_labels: p.current_labels,
                labels_to_add: p.labels_to_add,
                labels_to_remove: p.labels_to_remove,
                would_change: p.would_change,
            })
            .collect();
        let would_change_count = preview.iter().filter(|p| p.would_change).count();
        let resp = BatchTriageDryRunResponse {
            dry_run: true,
            total_threads: preview.len(),
            would_change_count,
            preview,
        };
        return Ok(serde_json::to_value(resp)?);
    }

    let total_threads = plans.len();
    let mut applied_count = 0usize;
    let mut skipped_count = 0usize;
    let mut modified_thread_ids: Vec<String> = Vec::new();
    let mut errors: Vec<BatchTriageThreadError> = Vec::new();
    let mut results: Vec<BatchTriageThreadResult> = Vec::with_capacity(total_threads);

    for plan in plans {
        if !plan.would_change {
            skipped_count += 1;
            results.push(BatchTriageThreadResult {
                thread_id: plan.thread_id,
                subject: plan.subject,
                changed: false,
                affected_message_ids: Vec::new(),
                labels: plan.current_labels,
                added_labels: Vec::new(),
                removed_labels: Vec::new(),
            });
            continue;
        }

        match state
            .store
            .triage_thread(
                &plan.thread_id,
                &TriagePatch {
                    add_labels: plan.labels_to_add.clone(),
                    remove_labels: plan.labels_to_remove.clone(),
                },
            )
            .await
        {
            Ok(triage_res) => {
                applied_count += 1;
                modified_thread_ids.push(triage_res.thread_id.clone());
                for message_id in &triage_res.affected_message_ids {
                    state.events.publish(
                        source,
                        MailEvent::MessageUpdated {
                            message_id: message_id.clone(),
                            thread_id: triage_res.thread_id.clone(),
                            added_labels: plan.labels_to_add.clone(),
                            removed_labels: plan.labels_to_remove.clone(),
                        },
                    );
                }
                results.push(BatchTriageThreadResult {
                    thread_id: triage_res.thread_id,
                    subject: plan.subject,
                    changed: true,
                    affected_message_ids: triage_res.affected_message_ids,
                    labels: triage_res.labels,
                    added_labels: plan.labels_to_add,
                    removed_labels: plan.labels_to_remove,
                });
            }
            Err(err) => {
                errors.push(BatchTriageThreadError {
                    thread_id: plan.thread_id,
                    code: err.ai_code().to_string(),
                    message: err.to_string(),
                });
            }
        }
    }

    let outcome = if errors.is_empty() {
        "ok"
    } else {
        "partial_error"
    };
    state
        .record_audit(
            principal.as_ref(),
            channel,
            "batch_triage",
            modified_thread_ids,
            outcome,
            Some(format!(
                "total={total_threads} applied={applied_count} skipped={skipped_count} errors={}",
                errors.len()
            )),
        )
        .await;

    let resp = BatchTriageApplyResponse {
        dry_run: false,
        total_threads,
        applied_count,
        skipped_count,
        errors,
        results,
    };
    Ok(serde_json::to_value(resp)?)
}

/// Execute label modification (shared across `/v1/messages/modify` and MCP `modify_labels`).
pub async fn execute_modify_labels(
    state: &AppState,
    req: AiModifyLabelsRequest,
) -> AppResult<Value> {
    execute_modify_labels_with_context(state, req, None, EventSource::Api).await
}

/// Internal variant allowing callers to tag the published [`EventSource`].
pub async fn execute_modify_labels_with_source(
    state: &AppState,
    req: AiModifyLabelsRequest,
    source: EventSource,
) -> AppResult<Value> {
    execute_modify_labels_with_context(state, req, None, source).await
}

/// Variant accepting the authenticated [`Principal`] for audit attribution.
pub async fn execute_modify_labels_with_context(
    state: &AppState,
    req: AiModifyLabelsRequest,
    principal: Option<Principal>,
    source: EventSource,
) -> AppResult<Value> {
    let channel = channel_for_source(source);
    if req.message_ids.is_empty() && req.thread_ids.is_empty() {
        return Err(AppError::validation(
            "At least one of message_ids or thread_ids must be non-empty",
            Some("Provide message_ids and/or thread_ids to modify.".to_string()),
        ));
    }

    for id in req
        .message_ids
        .iter()
        .chain(req.thread_ids.iter())
        .chain(req.add_labels.iter())
        .chain(req.remove_labels.iter())
    {
        validate_resource_id(id)?;
    }

    let (add_labels, remove_labels) = compute_triage_labels(
        req.archive,
        req.mark_read,
        None,
        None,
        req.trash,
        &req.add_labels,
        &req.remove_labels,
    );

    let mut seen_ids = HashSet::new();
    let mut targets: Vec<(String, String)> = Vec::new(); // (message_id, thread_id)

    for mid in &req.message_ids {
        let msg = state
            .store
            .get_message(mid)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Message '{mid}' not found")))?;
        if seen_ids.insert(msg.id.clone()) {
            targets.push((msg.id, msg.thread_id));
        }
    }

    for tid in &req.thread_ids {
        let thread = state
            .store
            .get_thread(tid)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Thread '{tid}' not found")))?;
        for msg in thread.messages {
            if seen_ids.insert(msg.id.clone()) {
                targets.push((msg.id, msg.thread_id));
            }
        }
    }

    let target_ids: Vec<String> = targets.iter().map(|(mid, _)| mid.clone()).collect();

    if req.dry_run {
        state
            .record_audit(
                principal.as_ref(),
                channel,
                "modify",
                target_ids.clone(),
                "dry_run",
                None,
            )
            .await;
        return Ok(json!({
            "dry_run": true,
            "would_succeed": true,
            "affected_message_ids": target_ids,
            "affected_thread_ids": req.thread_ids,
            "add_labels": add_labels,
            "remove_labels": remove_labels,
            "policy_checks": [
                {
                    "rule": "targets_exist",
                    "passed": true,
                    "detail": format!("Validated {} target message(s)", target_ids.len()),
                }
            ]
        }));
    }

    state
        .store
        .batch_modify_labels(&target_ids, &add_labels, &remove_labels)
        .await?;

    if !add_labels.is_empty() || !remove_labels.is_empty() {
        for (message_id, thread_id) in &targets {
            state.events.publish(
                source,
                MailEvent::MessageUpdated {
                    message_id: message_id.clone(),
                    thread_id: thread_id.clone(),
                    added_labels: add_labels.clone(),
                    removed_labels: remove_labels.clone(),
                },
            );
        }
    }

    state
        .record_audit(
            principal.as_ref(),
            channel,
            "modify",
            target_ids.clone(),
            "ok",
            Some(format!(
                "add=[{}] remove=[{}]",
                add_labels.join(","),
                remove_labels.join(",")
            )),
        )
        .await;

    Ok(json!({
        "modified_count": target_ids.len(),
        "affected_message_ids": target_ids,
        "added_labels": add_labels,
        "removed_labels": remove_labels,
    }))
}

/// Parse a `waiting_on` query filter (`me`, `them`, `none`, or empty).
pub fn parse_waiting_on_filter(raw: Option<&str>) -> AppResult<Option<WaitingOn>> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some(s) => WaitingOn::parse_str(s).map(Some).ok_or_else(|| {
            AppError::validation(
                format!("Invalid waiting_on filter '{s}'"),
                Some("Use one of: me, them, or none.".to_string()),
            )
        }),
    }
}

/// Read persisted structured annotation for a thread (shared across REST and MCP).
pub async fn execute_get_thread_annotations(state: &AppState, thread_id: &str) -> AppResult<Value> {
    validate_resource_id(thread_id)?;
    let _ = state
        .store
        .get_thread(thread_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Thread '{thread_id}' not found")))?;
    let annotation = state.store.get_thread_annotation(thread_id).await?;
    Ok(json!({
        "thread_id": thread_id,
        "annotation": annotation,
    }))
}

/// Replace persisted structured annotation for a thread (`PUT /v1/threads/{id}/annotations`).
pub async fn execute_upsert_thread_annotation(
    state: &AppState,
    thread_id: &str,
    req: UpsertThreadAnnotationRequest,
    principal: Option<&Principal>,
) -> AppResult<Value> {
    validate_resource_id(thread_id)?;
    let _ = state
        .store
        .get_thread(thread_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Thread '{thread_id}' not found")))?;

    let updated_by = req
        .updated_by
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| principal.map(|p| p.mailbox_id.clone()));

    let annotation = ThreadAnnotation {
        thread_id: thread_id.to_string(),
        summary: req.summary,
        needs_reply: req.needs_reply,
        waiting_on: req.waiting_on,
        priority: req.priority,
        due_at: req.due_at.map(truncate_to_millis),
        extracted: req.extracted,
        updated_by,
        updated_at: truncate_to_millis(Utc::now()),
    };
    let saved = state
        .store
        .upsert_thread_annotation(thread_id, &annotation)
        .await?;
    Ok(json!({
        "thread_id": saved.thread_id,
        "annotation": saved,
    }))
}

/// Partially update persisted structured annotation for a thread (`PATCH /v1/threads/{id}/annotations` and MCP `annotate_thread`).
pub async fn execute_patch_thread_annotation(
    state: &AppState,
    thread_id: &str,
    req: PatchThreadAnnotationRequest,
    principal: Option<&Principal>,
) -> AppResult<Value> {
    validate_resource_id(thread_id)?;
    let _ = state
        .store
        .get_thread(thread_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Thread '{thread_id}' not found")))?;

    let updated_by = req
        .updated_by
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| principal.map(|p| p.mailbox_id.clone()));

    let saved = state
        .store
        .patch_thread_annotation(thread_id, &req.patch, updated_by.as_deref())
        .await?;
    Ok(json!({
        "thread_id": saved.thread_id,
        "annotation": saved,
    }))
}

/// Delete persisted structured annotation for a thread (`DELETE /v1/threads/{id}/annotations`).
pub async fn execute_delete_thread_annotation(
    state: &AppState,
    thread_id: &str,
) -> AppResult<Value> {
    validate_resource_id(thread_id)?;
    let _ = state
        .store
        .get_thread(thread_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Thread '{thread_id}' not found")))?;
    state.store.delete_thread_annotation(thread_id).await?;
    Ok(json!({
        "thread_id": thread_id,
        "deleted": true,
    }))
}

/// Parse an approval status query string (`pending`, `approved`, `rejected`, `expired`, `all`, or empty).
pub fn parse_approval_status_filter(raw: Option<&str>) -> AppResult<Option<ApprovalStatus>> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some(s) if s.eq_ignore_ascii_case("all") => Ok(None),
        Some(s) => ApprovalStatus::parse_str(s).map(Some).ok_or_else(|| {
            AppError::validation(
                format!("Invalid approval status filter '{s}'"),
                Some("Use one of: pending, approved, rejected, expired, or all.".to_string()),
            )
        }),
    }
}

/// List pending or decided approval requests (shared across `/v1/approvals` and CLI).
pub async fn execute_list_approvals(
    state: &AppState,
    status: Option<&str>,
    limit: usize,
) -> AppResult<Value> {
    let filter = parse_approval_status_filter(status)?;
    let clamped = limit.clamp(1, MAX_LIST_LIMIT);
    let approvals = state.store.list_pending_approvals(filter, clamped).await?;
    Ok(json!({
        "approvals": approvals,
        "count": approvals.len(),
    }))
}

/// Get a single approval request by ID (shared across `/v1/approvals/{id}` and CLI).
pub async fn execute_get_approval(state: &AppState, id: &str) -> AppResult<Value> {
    validate_resource_id(id)?;
    let approval = state
        .store
        .get_pending_approval(id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Approval '{id}' not found")))?;
    Ok(serde_json::to_value(approval)?)
}

/// Approve and dispatch a pending outbound email exactly once (shared across `/v1/approvals/{id}/approve` and CLI).
pub async fn execute_approve_approval(
    state: &AppState,
    id: &str,
    req: ApprovalDecisionRequest,
    principal: Option<&Principal>,
    source: EventSource,
) -> AppResult<Value> {
    validate_resource_id(id)?;
    let in_flight_key = format!("{}:{}", state.mailbox_id(), id);
    let _in_flight = ApprovalInFlightGuard::try_acquire(&state.approval_in_flight, &in_flight_key)?;

    let approval = state
        .store
        .get_pending_approval(id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Approval '{id}' not found")))?;

    let now_ms = Utc::now().timestamp_millis();
    if approval.status == ApprovalStatus::Expired || approval.expires_at_ms <= now_ms {
        // Persist expired status atomically in the store and return 409 Conflict.
        let _ = state
            .store
            .resolve_pending_approval(id, ApprovalStatus::Approved, None, None, None, None)
            .await;
        return Err(AppError::Conflict(format!("Approval '{id}' has expired")));
    }

    if approval.status != ApprovalStatus::Pending {
        return Err(AppError::Conflict(format!(
            "Approval '{id}' is already {}",
            approval.status
        )));
    }

    let outbound = &approval.outbound_message;
    let idempotency_key = format!("approval-{id}");
    let send_outcome = state
        .transport
        .send(outbound, Some(&idempotency_key))
        .await?;

    let raw_rfc2822 = crate::transport::ensure_raw_rfc2822(outbound, &state.config.user_email)?;
    let text_body = outbound.text.clone().unwrap_or_default();
    let snippet = generate_snippet(&text_body, outbound.html.as_deref());
    let rfc822_message_id = outbound
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("message-id"))
        .map(|(_, v)| v.clone());
    let in_reply_to = outbound
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("in-reply-to"))
        .map(|(_, v)| v.clone());
    let references_header = outbound
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("references"))
        .map(|(_, v)| v.clone());
    let attachments: Vec<NewAttachmentInput> = outbound
        .attachments
        .iter()
        .enumerate()
        .map(|(idx, att)| NewAttachmentInput {
            part_id: format!("att_{}", idx + 1),
            filename: att.filename.clone(),
            content_type: att.content_type.clone(),
            content_id: att.content_id.clone(),
            data: att.data.clone(),
        })
        .collect();

    if let Some(ref draft_id) = approval.draft_id {
        let draft_msg_id = state
            .store
            .get_draft(draft_id)
            .await
            .ok()
            .flatten()
            .map(|d| d.message.id);
        let _ = state.store.delete_draft(draft_id).await;
        if let Some(mid) = draft_msg_id {
            let _ = state.post_delete_message(&mid, &[]).await;
        }
    }

    let stored = state
        .store
        .insert_message(NewMessageInput {
            id: None,
            thread_id: approval.thread_id.clone(),
            label_ids: vec![LABEL_SENT.to_string()],
            raw_rfc2822,
            snippet,
            internal_date_ms: Utc::now().timestamp_millis(),
            subject: outbound.subject.clone(),
            from_addr: if outbound.from.trim().is_empty() {
                state.config.user_email.clone()
            } else {
                outbound.from.clone()
            },
            to_addrs: outbound.to.clone(),
            cc_addrs: outbound.cc.clone(),
            bcc_addrs: outbound.bcc.clone(),
            text_body,
            html_body: outbound.html.clone(),
            rfc822_message_id,
            in_reply_to,
            references_header,
            resend_id: Some(send_outcome.provider_message_id.clone()),
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "local".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments,
        })
        .await?;

    state.post_store_message(&stored).await?;

    let decided_by = req
        .decided_by
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| principal.map(|p| p.mailbox_id.clone()));

    let resolved = state
        .store
        .resolve_pending_approval(
            id,
            ApprovalStatus::Approved,
            decided_by.clone(),
            req.note.clone(),
            Some(stored.id.clone()),
            Some(send_outcome.provider_message_id.clone()),
        )
        .await?;

    state.metrics.inc_messages_sent();
    state.events.publish(
        source,
        MailEvent::MessageSent {
            message_id: stored.id.clone(),
            thread_id: stored.thread_id.clone(),
            to: stored.to_addrs.clone(),
            subject: stored.subject.clone(),
            resend_id: Some(send_outcome.provider_message_id.clone()),
            labels: stored.label_ids.clone(),
        },
    );
    state.events.publish(
        source,
        MailEvent::ApprovalResolved {
            approval_id: resolved.id.clone(),
            status: resolved.status.as_str().to_string(),
            decided_by,
            sent_message_id: Some(stored.id.clone()),
        },
    );

    state
        .record_audit(
            principal,
            channel_for_source(source),
            "approve",
            vec![resolved.id.clone(), stored.id.clone()],
            "ok",
            req.note.clone(),
        )
        .await;

    let compact = to_compact_message(
        &stored,
        &state.config,
        true,
        state.config.default_max_body_chars,
        false,
        false,
    );

    Ok(json!({
        "status": "approved",
        "approval": resolved,
        "provider": send_outcome.provider,
        "provider_message_id": send_outcome.provider_message_id,
        "sent_message_id": stored.id,
        "thread_id": stored.thread_id,
        "message": compact,
    }))
}

/// Reject a pending outbound email without ever invoking `MailTransport`.
pub async fn execute_reject_approval(
    state: &AppState,
    id: &str,
    req: ApprovalDecisionRequest,
    principal: Option<&Principal>,
    source: EventSource,
) -> AppResult<Value> {
    validate_resource_id(id)?;
    let in_flight_key = format!("{}:{}", state.mailbox_id(), id);
    let _in_flight = ApprovalInFlightGuard::try_acquire(&state.approval_in_flight, &in_flight_key)?;

    let decided_by = req
        .decided_by
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| principal.map(|p| p.mailbox_id.clone()));

    let resolved = state
        .store
        .resolve_pending_approval(
            id,
            ApprovalStatus::Rejected,
            decided_by.clone(),
            req.note.clone(),
            None,
            None,
        )
        .await?;

    state.events.publish(
        source,
        MailEvent::ApprovalResolved {
            approval_id: resolved.id.clone(),
            status: resolved.status.as_str().to_string(),
            decided_by,
            sent_message_id: None,
        },
    );

    state
        .record_audit(
            principal,
            channel_for_source(source),
            "reject",
            vec![resolved.id.clone()],
            "ok",
            req.note.clone(),
        )
        .await;

    Ok(json!({
        "status": "rejected",
        "approval": resolved,
    }))
}

/// List immutable audit log entries for the active mailbox (shared across `GET /v1/audit` and CLI).
pub async fn execute_list_audit_log(
    state: &AppState,
    action: Option<&str>,
    actor: Option<&str>,
    since: Option<&str>,
    limit: usize,
) -> AppResult<Value> {
    let since_ms = parse_since_ms(since)?;
    let clamped = if limit == 0 {
        DEFAULT_AUDIT_LIMIT
    } else {
        limit.clamp(1, MAX_AUDIT_LIMIT)
    };
    let entries = state
        .store
        .list_audit_log(&AuditLogQuery {
            action: action
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            actor: actor
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            since_ms,
            limit: clamped,
        })
        .await?;
    Ok(json!({
        "entries": entries,
        "count": entries.len(),
    }))
}

/// Project a [`StoredMessage`] into a token-efficient [`CompactMessage`].
pub fn to_compact_message(
    msg: &StoredMessage,
    config: &Config,
    include_body: bool,
    max_body_chars: usize,
    strip_quotes: bool,
    include_html: bool,
) -> CompactMessage {
    let guard = config.untrusted_content_guard;
    let clean = |s: &str| -> String {
        if guard {
            sanitize_untrusted_text(s)
        } else {
            s.to_string()
        }
    };

    let clean_addr = |raw: &str| -> EmailAddress {
        let mut parsed = parse_simple_email_address(raw);
        if guard {
            parsed.name = parsed.name.map(|n| sanitize_untrusted_text(&n));
            parsed.email = sanitize_untrusted_text(&parsed.email);
        }
        parsed
    };

    let date = DateTime::from_timestamp_millis(msg.internal_date_ms).unwrap_or_else(Utc::now);
    let effective_cap = max_body_chars.min(safety::HARD_MAX_BODY_CHARS);

    let (source_text, text_from_html) = if include_body {
        select_body_or_html_markdown(&msg.text_body, msg.html_body.as_deref())
    } else {
        (msg.text_body.clone(), false)
    };

    let processed_text = if strip_quotes {
        let stripped = strip_quoted_text(&source_text);
        clean(&stripped)
    } else {
        clean(&source_text)
    };
    let text_total_chars = processed_text.chars().count();

    let (text, text_truncated) = if include_body {
        if text_total_chars > effective_cap {
            let truncated: String = processed_text.chars().take(effective_cap).collect();
            (Some(truncated), true)
        } else {
            (Some(processed_text), false)
        }
    } else {
        (None, false)
    };

    let text_format = (include_body && text_from_html).then(|| "markdown".to_string());

    let html = if include_body && include_html {
        msg.html_body.as_deref().map(|raw_html| {
            let processed = if guard {
                strip_tracking_pixels(raw_html)
            } else {
                raw_html.to_string()
            };
            let cleaned = clean(&processed);
            if cleaned.chars().count() > effective_cap {
                cleaned.chars().take(effective_cap).collect()
            } else {
                cleaned
            }
        })
    } else {
        None
    };

    let links = if include_body {
        msg.html_body
            .as_deref()
            .map(|raw_html| {
                let mut extracted = extract_html_links(raw_html);
                if guard {
                    for link in &mut extracted {
                        link.display_text = sanitize_untrusted_text(&link.display_text);
                        link.href = sanitize_untrusted_text(&link.href);
                    }
                }
                extracted
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let unsubscribe = sanitize_unsubscribe(parse_unsubscribe_from_raw(&msg.raw_rfc2822), guard);

    CompactMessage {
        id: msg.id.clone(),
        thread_id: msg.thread_id.clone(),
        date,
        from: clean_addr(&msg.from_addr),
        sender_contact: None,
        to: msg.to_addrs.iter().map(|a| clean_addr(a)).collect(),
        cc: msg.cc_addrs.iter().map(|a| clean_addr(a)).collect(),
        subject: clean(&msg.subject),
        snippet: clean(&msg.snippet),
        labels: msg.label_ids.clone(),
        unread: msg.label_ids.iter().any(|l| l == LABEL_UNREAD),
        has_attachments: msg.has_attachments,
        attachments_meta: None,
        attachments_text: None,
        text,
        text_format,
        text_truncated,
        text_total_chars,
        html,
        links,
        in_reply_to: msg.in_reply_to.clone(),
        rfc_message_id: msg.rfc822_message_id.clone(),
        unsubscribe,
        meta: untrusted_meta(config),
    }
}

fn sanitize_unsubscribe(info: Option<UnsubscribeInfo>, guard: bool) -> Option<UnsubscribeInfo> {
    let mut info = info?;
    if guard {
        info.https_url = info.https_url.map(|u| sanitize_untrusted_text(&u));
        info.mailto = info.mailto.map(|m| sanitize_untrusted_text(&m));
    }
    Some(info)
}

/// Sanitize untrusted header-derived display names on a [`ContactRecord`] when
/// `untrusted_content_guard` is active.
pub fn sanitize_contact_record(mut record: ContactRecord, guard: bool) -> ContactRecord {
    if guard {
        record.display_name = record.display_name.map(|n| sanitize_untrusted_text(&n));
    }
    record
}

/// Populate `sender_contact` on each [`ThreadSummary`] from the mailbox contact graph
/// using the first non-self participant (or the first participant if all match self).
pub async fn enrich_thread_summaries_with_contacts(
    state: &AppState,
    threads: &mut [ThreadSummary],
) -> AppResult<()> {
    let self_email = state.store.mailbox_id().trim().to_ascii_lowercase();
    let guard = state.config.untrusted_content_guard;
    let mut cache: HashMap<String, Option<ContactSummary>> = HashMap::new();

    for thread in threads.iter_mut() {
        let candidate = thread
            .participants
            .iter()
            .find(|p| !p.email.eq_ignore_ascii_case(&self_email))
            .or_else(|| thread.participants.first());
        let Some(addr) = candidate else {
            continue;
        };
        let key = addr.email.trim().to_ascii_lowercase();
        if key.is_empty() {
            continue;
        }
        if let Some(cached) = cache.get(&key) {
            thread.sender_contact = cached.clone();
        } else {
            let summary = state
                .store
                .get_contact(&key)
                .await?
                .map(|c| sanitize_contact_record(c, guard).to_summary());
            cache.insert(key, summary.clone());
            thread.sender_contact = summary;
        }
    }
    Ok(())
}

/// Build a full [`ThreadDetail`] with compact messages, participants, labels, optional attachment metadata, and `_meta`.
pub async fn build_thread_detail(
    state: &AppState,
    detail: StoredThreadDetail,
    max_body_chars: usize,
    strip_quotes: bool,
    include_html: bool,
    include_attachments_meta: bool,
) -> AppResult<ThreadDetail> {
    let mut participants: Vec<EmailAddress> = Vec::new();
    let mut seen_emails: HashSet<String> = HashSet::new();
    let mut labels: Vec<String> = Vec::new();
    let mut seen_labels: HashSet<String> = HashSet::new();
    let mut unread = false;
    let mut last_ms = i64::MIN;
    let mut subject = String::new();
    let mut contact_cache: HashMap<String, Option<ContactSummary>> = HashMap::new();
    let guard = state.config.untrusted_content_guard;

    let mut compact_messages = Vec::with_capacity(detail.messages.len());

    for msg in &detail.messages {
        if subject.is_empty() && !msg.subject.trim().is_empty() {
            subject = if state.config.untrusted_content_guard {
                sanitize_untrusted_text(&msg.subject)
            } else {
                msg.subject.clone()
            };
        }
        if msg.internal_date_ms > last_ms {
            last_ms = msg.internal_date_ms;
        }
        for lbl in &msg.label_ids {
            if lbl == LABEL_UNREAD {
                unread = true;
            }
            if seen_labels.insert(lbl.clone()) {
                labels.push(lbl.clone());
            }
        }

        let mut compact = to_compact_message(
            msg,
            &state.config,
            true,
            max_body_chars,
            strip_quotes,
            include_html,
        );

        let sender_key = compact.from.email.trim().to_ascii_lowercase();
        if !sender_key.is_empty() {
            if let Some(cached) = contact_cache.get(&sender_key) {
                compact.sender_contact = cached.clone();
            } else {
                let summary = state
                    .store
                    .get_contact(&sender_key)
                    .await?
                    .map(|c| sanitize_contact_record(c, guard).to_summary());
                contact_cache.insert(sender_key, summary.clone());
                compact.sender_contact = summary;
            }
        }

        for addr in std::iter::once(&compact.from)
            .chain(compact.to.iter())
            .chain(compact.cc.iter())
        {
            let key = addr.email.to_ascii_lowercase();
            if !key.is_empty() && seen_emails.insert(key) {
                participants.push(addr.clone());
            }
        }

        if include_attachments_meta && msg.has_attachments {
            let meta = state.store.list_attachment_meta(&msg.id).await?;
            if !meta.is_empty() {
                compact.attachments_meta = Some(meta);
            }
        }
        if compact.unsubscribe.is_none()
            && msg.raw_rfc2822.is_empty()
            && let Ok(raw) = state.load_raw_rfc2822(msg).await
        {
            compact.unsubscribe = sanitize_unsubscribe(
                parse_unsubscribe_from_raw(&raw),
                state.config.untrusted_content_guard,
            );
        }

        compact_messages.push(compact);
    }

    let last_message_at = if last_ms == i64::MIN {
        Utc::now()
    } else {
        DateTime::from_timestamp_millis(last_ms).unwrap_or_else(Utc::now)
    };
    let annotation = state.store.get_thread_annotation(&detail.id).await?;

    Ok(ThreadDetail {
        id: detail.id,
        subject,
        participants,
        labels,
        unread,
        message_count: compact_messages.len(),
        last_message_at,
        messages: compact_messages,
        annotation,
        meta: untrusted_meta(&state.config),
    })
}

/// Build a compact message populated with attachment metadata and sender contact summary when available.
pub async fn build_compact_message_with_meta(
    state: &AppState,
    msg: &StoredMessage,
    include_body: bool,
    max_body_chars: usize,
    strip_quotes: bool,
    include_html: bool,
    include_attachments_meta: bool,
) -> AppResult<CompactMessage> {
    let mut compact = to_compact_message(
        msg,
        &state.config,
        include_body,
        max_body_chars,
        strip_quotes,
        include_html,
    );
    if !compact.from.email.trim().is_empty() {
        compact.sender_contact = state
            .store
            .get_contact(&compact.from.email)
            .await?
            .map(|c| sanitize_contact_record(c, state.config.untrusted_content_guard).to_summary());
    }
    if include_attachments_meta && msg.has_attachments {
        let meta = state.store.list_attachment_meta(&msg.id).await?;
        if !meta.is_empty() {
            compact.attachments_meta = Some(meta);
        }
    }
    if compact.unsubscribe.is_none()
        && msg.raw_rfc2822.is_empty()
        && let Ok(raw) = state.load_raw_rfc2822(msg).await
    {
        compact.unsubscribe = sanitize_unsubscribe(
            parse_unsubscribe_from_raw(&raw),
            state.config.untrusted_content_guard,
        );
    }
    Ok(compact)
}

/// Extract readable text / structured metadata for a single message attachment with strict
/// byte (`5 MiB`) and character (`default 20_000`, `hard cap 100_000`) ceilings and
/// `untrusted_content_guard` sanitization.
pub async fn execute_read_attachment_text(
    state: &AppState,
    message_id: &str,
    attachment_id: &str,
    max_chars: Option<usize>,
) -> AppResult<AttachmentTextExtraction> {
    validate_resource_id(message_id)?;
    validate_resource_id(attachment_id)?;

    let att = state
        .store
        .get_attachment(message_id, attachment_id)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "Attachment '{attachment_id}' on message '{message_id}' not found"
            ))
        })?;

    let guard = state.config.untrusted_content_guard;
    let safe_filename = att.filename.as_deref().map(|name| {
        if guard {
            sanitize_untrusted_text(name)
        } else {
            name.to_string()
        }
    });

    let mut extracted = if att.size_bytes > DEFAULT_ATTACHMENT_MAX_BYTES as u64 {
        oversize_attachment_extraction(
            safe_filename,
            att.content_type.clone(),
            att.size_bytes,
            DEFAULT_ATTACHMENT_MAX_BYTES,
        )
    } else {
        let data = state.load_attachment_bytes(&att).await?;
        extract_attachment_text(
            &data,
            &att.content_type,
            safe_filename.as_deref(),
            max_chars,
            DEFAULT_ATTACHMENT_MAX_BYTES,
            guard,
        )
    };

    extracted.attachment_id = Some(att.id);
    extracted.message_id = Some(att.message_id);
    if extracted.size_bytes == 0 {
        extracted.size_bytes = att.size_bytes;
    }
    extracted.meta = untrusted_meta(&state.config);
    Ok(extracted)
}

/// Populate `compact.attachments_text` for every attachment on `compact.id`.
pub async fn attach_extracted_attachment_texts(
    state: &AppState,
    compact: &mut CompactMessage,
    max_chars: Option<usize>,
) -> AppResult<()> {
    if !compact.has_attachments {
        return Ok(());
    }
    let metas = state.store.list_attachment_meta(&compact.id).await?;
    if metas.is_empty() {
        return Ok(());
    }
    let mut results = Vec::with_capacity(metas.len());
    for meta in metas {
        let extracted =
            execute_read_attachment_text(state, &compact.id, &meta.id, max_chars).await?;
        results.push(extracted);
    }
    compact.attachments_text = Some(results);
    Ok(())
}

/// Build the `GET /v1/sync/gmail` / MCP `sync_gmail` [`SyncRunOptions`] from a [`SyncTriggerRequest`].
pub fn parse_sync_trigger(req: SyncTriggerRequest) -> AppResult<SyncRunOptions> {
    let full = match req.mode.as_deref().map(str::trim) {
        None | Some("") | Some("incremental") => false,
        Some("full") => true,
        Some(other) => {
            return Err(AppError::validation(
                format!("Invalid sync mode '{other}'"),
                Some("Use 'incremental' or 'full'.".to_string()),
            ));
        }
    };

    let mode = match req.provider.as_deref().map(str::trim) {
        None | Some("") => None,
        Some("api") | Some("gmail_api") => Some(SyncMode::Api),
        Some("imap") | Some("gmail_imap") => Some(SyncMode::Imap),
        Some(other) => {
            return Err(AppError::validation(
                format!("Invalid sync provider '{other}'"),
                Some("Use 'api' or 'imap'.".to_string()),
            ));
        }
    };

    Ok(SyncRunOptions {
        mode,
        full,
        max_messages: req.max_messages,
        query: req.query,
        bidirectional: req.bidirectional,
    })
}

// ============================================================================
// Internal Helpers
// ============================================================================

struct ApprovalInFlightGuard {
    set: Arc<StdMutex<HashSet<String>>>,
    id: String,
}

impl ApprovalInFlightGuard {
    fn try_acquire(set: &Arc<StdMutex<HashSet<String>>>, id: &str) -> AppResult<Self> {
        let mut guard = set
            .lock()
            .map_err(|_| AppError::Internal("Approval lock poisoned".to_string()))?;
        if !guard.insert(id.to_string()) {
            return Err(AppError::Conflict(format!(
                "Approval '{id}' is already being processed"
            )));
        }
        Ok(Self {
            set: Arc::clone(set),
            id: id.to_string(),
        })
    }
}

impl Drop for ApprovalInFlightGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.set.lock() {
            guard.remove(&self.id);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn enqueue_pending_approval(
    state: &AppState,
    reason: String,
    principal: Option<Principal>,
    outbound_message: OutboundMessage,
    reply_to_message_id: Option<String>,
    thread_id: Option<String>,
    draft_id: Option<String>,
    now_ms: i64,
    snippet: &str,
    source: EventSource,
) -> AppResult<PendingApproval> {
    let ttl_ms = (state.config.approval_ttl_secs as i64).saturating_mul(1000);
    let expires_at_ms = now_ms.saturating_add(ttl_ms);
    let requester = principal.or_else(|| Some(Principal::full_access(&state.config.user_email)));

    let approval = state
        .store
        .create_pending_approval(NewPendingApprovalInput {
            id: None,
            reason,
            requester,
            outbound_message,
            reply_to_message_id,
            thread_id,
            draft_id,
            created_at_ms: now_ms,
            expires_at_ms,
        })
        .await?;

    let expires_at =
        DateTime::from_timestamp_millis(approval.expires_at_ms).unwrap_or_else(Utc::now);

    state.events.publish(
        source,
        MailEvent::ApprovalRequested {
            approval_id: approval.id.clone(),
            reason: approval.reason.clone(),
            to: approval.outbound_message.to.clone(),
            subject: approval.outbound_message.subject.clone(),
            thread_id: approval.thread_id.clone(),
            draft_id: approval.draft_id.clone(),
            expires_at,
        },
    );

    spawn_approval_webhook(&state.config, &approval, snippet);
    Ok(approval)
}

fn safe_hold_preview_snippet<'a>(config: &Config, snippet: &'a str) -> &'a str {
    if config.dlp_action != crate::config::DlpAction::Off
        && !safety::scan_dlp_text(snippet).is_empty()
    {
        "[redacted by DLP policy]"
    } else {
        snippet
    }
}

pub(crate) fn build_hold_response(
    approval: &PendingApproval,
    draft_id: Option<&str>,
    message_id: Option<&str>,
    thread_id: Option<&str>,
    snippet: &str,
) -> Value {
    let expires_at =
        DateTime::from_timestamp_millis(approval.expires_at_ms).unwrap_or_else(Utc::now);
    json!({
        "status": "pending_approval",
        "held_for_approval": true,
        "approval_id": approval.id,
        "reason": approval.reason,
        "expires_at": expires_at,
        "expires_at_ms": approval.expires_at_ms,
        "draft_id": draft_id,
        "message_id": message_id,
        "thread_id": thread_id,
        "to": approval.outbound_message.to,
        "cc": approval.outbound_message.cc,
        "bcc": approval.outbound_message.bcc,
        "subject": approval.outbound_message.subject,
        "preview": {
            "from": approval.outbound_message.from,
            "to": approval.outbound_message.to,
            "cc": approval.outbound_message.cc,
            "bcc": approval.outbound_message.bcc,
            "subject": approval.outbound_message.subject,
            "snippet": snippet,
        },
    })
}

fn spawn_approval_webhook(config: &Config, approval: &PendingApproval, snippet: &str) {
    let Some(webhook_url) = config
        .approval_webhook_url
        .clone()
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
    else {
        return;
    };

    let expires_at =
        DateTime::from_timestamp_millis(approval.expires_at_ms).unwrap_or_else(Utc::now);
    let to_summary = approval.outbound_message.to.join(", ");
    let slack_text = format!(
        "Email approval required ({}): To: {} | Subject: {} | Reason: {}",
        approval.id, to_summary, approval.outbound_message.subject, approval.reason
    );

    let payload = json!({
        "event": "approval_requested",
        "text": slack_text,
        "approval_id": approval.id,
        "status": approval.status,
        "reason": approval.reason,
        "requester": approval.requester,
        "expires_at": expires_at,
        "expires_at_ms": approval.expires_at_ms,
        "draft_id": approval.draft_id,
        "thread_id": approval.thread_id,
        "message": {
            "from": approval.outbound_message.from,
            "to": approval.outbound_message.to,
            "cc": approval.outbound_message.cc,
            "bcc": approval.outbound_message.bcc,
            "subject": approval.outbound_message.subject,
            "snippet": snippet,
        },
    });
    let approval_id = approval.id.clone();

    tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
        {
            Ok(c) => c,
            Err(err) => {
                warn!(%err, %approval_id, "Failed to build HTTP client for approval webhook");
                return;
            }
        };

        match client.post(&webhook_url).json(&payload).send().await {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => {
                warn!(
                    status = %resp.status(),
                    %webhook_url,
                    %approval_id,
                    "Approval webhook returned non-success status"
                );
            }
            Err(err) => {
                warn!(%err, %webhook_url, %approval_id, "Failed to deliver approval webhook");
            }
        }
    });
}

pub(crate) fn build_outbound_rfc2822(
    resolved: &safety::ResolvedOutbound,
    rfc_message_id: &str,
) -> AppResult<Vec<u8>> {
    let input = ComposeEmailInput {
        from: resolved.from.clone(),
        to: resolved.to.clone(),
        cc: resolved.cc.clone(),
        bcc: resolved.bcc.clone(),
        reply_to: Vec::new(),
        subject: resolved.subject.clone(),
        text: resolved.text.clone(),
        html: resolved.html.clone(),
        message_id: Some(rfc_message_id.to_string()),
        in_reply_to: resolved.in_reply_to.clone(),
        references: resolved.references.clone(),
        extra_headers: HashMap::new(),
        attachments: Vec::new(),
    };
    build_rfc2822(&input)
}

pub(crate) fn validate_recipients_syntax(
    to: &[String],
    cc: &[String],
    bcc: &[String],
) -> AppResult<()> {
    for (field, list) in [("to", to), ("cc", cc), ("bcc", bcc)] {
        for addr in list {
            validate_email_header(field, addr)?;
            if !safety::is_valid_email_syntax(addr) {
                return Err(AppError::validation(
                    format!("Invalid recipient email address(es): {addr}"),
                    Some("Provide valid email addresses such as user@example.com or \"Name <user@example.com>\".".to_string()),
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn policy_deny_to_error(code: String, reason: String, hint: Option<String>) -> AppError {
    if code == "draft_only_mode" {
        AppError::DraftOnlyBlocked {
            hint: hint.unwrap_or(reason),
        }
    } else {
        AppError::PolicyDenied {
            code,
            message: reason,
            hint,
            details: None,
        }
    }
}

pub(crate) fn build_outbound_message(
    resolved: &safety::ResolvedOutbound,
    rfc_message_id: &str,
    raw_rfc2822: &[u8],
) -> OutboundMessage {
    let mut headers = HashMap::new();
    headers.insert("Message-ID".to_string(), rfc_message_id.to_string());
    if let Some(in_reply_to) = &resolved.in_reply_to {
        headers.insert("In-Reply-To".to_string(), in_reply_to.clone());
    }
    if let Some(references) = &resolved.references {
        headers.insert("References".to_string(), references.clone());
    }

    OutboundMessage {
        from: resolved.from.clone(),
        to: resolved.to.clone(),
        cc: resolved.cc.clone(),
        bcc: resolved.bcc.clone(),
        reply_to: Vec::new(),
        subject: resolved.subject.clone(),
        text: resolved.text.clone(),
        html: resolved.html.clone(),
        headers,
        attachments: Vec::new(),
        raw_rfc2822: raw_rfc2822.to_vec(),
        idempotency_key: None,
        scheduled_at: None,
        tags: HashMap::new(),
    }
}

fn compute_triage_labels(
    archive: Option<bool>,
    mark_read: Option<bool>,
    mark_unread: Option<bool>,
    star: Option<bool>,
    trash: Option<bool>,
    extra_add: &[String],
    extra_remove: &[String],
) -> (Vec<String>, Vec<String>) {
    let mut add = Vec::new();
    let mut remove = Vec::new();

    match archive {
        Some(true) => remove.push(LABEL_INBOX.to_string()),
        Some(false) => add.push(LABEL_INBOX.to_string()),
        None => {}
    }
    if mark_read == Some(true) {
        remove.push(LABEL_UNREAD.to_string());
    } else if mark_read == Some(false) {
        add.push(LABEL_UNREAD.to_string());
    }
    if mark_unread == Some(true) {
        add.push(LABEL_UNREAD.to_string());
    } else if mark_unread == Some(false) {
        remove.push(LABEL_UNREAD.to_string());
    }
    match star {
        Some(true) => add.push(LABEL_STARRED.to_string()),
        Some(false) => remove.push(LABEL_STARRED.to_string()),
        None => {}
    }
    match trash {
        Some(true) => {
            add.push(LABEL_TRASH.to_string());
            remove.push(LABEL_INBOX.to_string());
        }
        Some(false) => remove.push(LABEL_TRASH.to_string()),
        None => {}
    }

    add.extend(extra_add.iter().cloned());
    remove.extend(extra_remove.iter().cloned());

    dedup_preserve_order(&mut add);
    dedup_preserve_order(&mut remove);

    // If a label was requested in both add and remove, explicit remove doesn't override explicit add,
    // or remove duplicates cleanly: remove takes precedence if archive+trash, etc.
    add.retain(|l| !remove.contains(l));

    (add, remove)
}

fn dedup_preserve_order(items: &mut Vec<String>) {
    let mut seen = HashSet::new();
    items.retain(|item| seen.insert(item.clone()));
}

fn project_fields(value: Value, fields: Option<&str>) -> AppResult<Value> {
    match fields {
        Some(mask) if !mask.trim().is_empty() => apply_fields_mask(value, mask),
        _ => Ok(value),
    }
}

fn parse_csv(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_optional_json<T: Default + serde::de::DeserializeOwned>(bytes: &Bytes) -> AppResult<T> {
    if bytes.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(T::default());
    }
    Ok(serde_json::from_slice(bytes)?)
}

fn event_matches_filter(
    env: &EventEnvelope,
    types: &[String],
    label: Option<&str>,
    thread_id: Option<&str>,
) -> bool {
    if !types.is_empty() && !types.iter().any(|t| t == env.event.event_type()) {
        return false;
    }

    if let Some(tid) = thread_id
        && env.event.thread_id() != Some(tid)
    {
        return false;
    }

    if let Some(lbl) = label {
        let matched = match &env.event {
            MailEvent::MessageReceived { labels, .. }
            | MailEvent::MessageSent { labels, .. }
            | MailEvent::MessageDeleted { labels, .. } => labels.iter().any(|l| l == lbl),
            MailEvent::MessageUpdated {
                added_labels,
                removed_labels,
                ..
            } => added_labels.iter().any(|l| l == lbl) || removed_labels.iter().any(|l| l == lbl),
            MailEvent::DraftCreated { .. } => lbl == LABEL_DRAFT,
            MailEvent::DeliveryStatus { .. }
            | MailEvent::SyncCompleted { .. }
            | MailEvent::ApprovalRequested { .. }
            | MailEvent::ApprovalResolved { .. } => false,
        };
        if !matched {
            return false;
        }
    }

    true
}

// ============================================================================
// HTTP Query Structs & Handlers
// ============================================================================

#[derive(Debug, Default, Deserialize)]
struct FieldsQuery {
    fields: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ListThreadsParams {
    q: Option<String>,
    label: Option<String>,
    #[serde(default)]
    unread_only: bool,
    needs_reply: Option<bool>,
    waiting_on: Option<String>,
    #[serde(default)]
    include_spam_trash: bool,
    limit: Option<usize>,
    cursor: Option<String>,
    fields: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ReadThreadParams {
    max_body_chars: Option<usize>,
    strip_quotes: Option<bool>,
    #[serde(default)]
    include_html: bool,
    include_attachments_meta: Option<bool>,
    fields: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ReplyContextParams {
    max_body_chars: Option<usize>,
    max_style_samples: Option<usize>,
    max_related_threads: Option<usize>,
    fields: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ListMessagesParams {
    q: Option<String>,
    label: Option<String>,
    labels: Option<String>,
    thread_id: Option<String>,
    #[serde(default)]
    include_spam_trash: bool,
    limit: Option<usize>,
    cursor: Option<String>,
    #[serde(default)]
    include_body: bool,
    max_body_chars: Option<usize>,
    #[serde(default)]
    strip_quotes: bool,
    #[serde(default)]
    include_html: bool,
    fields: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ReadMessageParams {
    max_body_chars: Option<usize>,
    #[serde(default)]
    strip_quotes: bool,
    #[serde(default)]
    include_html: bool,
    include_attachments_meta: Option<bool>,
    #[serde(default)]
    extract_attachment_text: bool,
    attachment_max_chars: Option<usize>,
    fields: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct AttachmentTextParams {
    max_chars: Option<usize>,
    fields: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SearchParams {
    q: Option<String>,
    label: Option<String>,
    labels: Option<String>,
    unread: Option<bool>,
    thread_id: Option<String>,
    from: Option<String>,
    to: Option<String>,
    after: Option<DateTime<Utc>>,
    before: Option<DateTime<Utc>>,
    has_attachment: Option<bool>,
    #[serde(default)]
    include_spam_trash: bool,
    limit: Option<usize>,
    cursor: Option<String>,
    #[serde(default)]
    include_body: bool,
    max_body_chars: Option<usize>,
    #[serde(default)]
    strip_quotes: bool,
    #[serde(default)]
    include_html: bool,
    fields: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ListDraftsParams {
    limit: Option<usize>,
    page_token: Option<String>,
    fields: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ListApprovalsParams {
    status: Option<String>,
    limit: Option<usize>,
    fields: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ListScheduledParams {
    status: Option<String>,
    limit: Option<usize>,
    fields: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ListContactsParams {
    q: Option<String>,
    #[serde(default)]
    vip_only: bool,
    #[serde(default)]
    replied_only: bool,
    domain: Option<String>,
    limit: Option<usize>,
    fields: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ListAuditParams {
    action: Option<String>,
    actor: Option<String>,
    since: Option<String>,
    limit: Option<usize>,
    fields: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct EventsParams {
    types: Option<String>,
    label: Option<String>,
    thread_id: Option<String>,
    since_id: Option<u64>,
}

async fn get_capabilities(
    MailboxState(state): MailboxState,
    Query(query): Query<FieldsQuery>,
) -> Result<Json<Value>, AiError> {
    let cfg = &state.config;
    let active_filters = state.filter.active_filters();
    let filter_backend = if active_filters.is_empty() {
        state.filter.backend_name().to_string()
    } else {
        active_filters.join(",")
    };
    let body = json!({
        "service": "nogml",
        "version": env!("CARGO_PKG_VERSION"),
        "user_email": cfg.user_email,
        "mcp_endpoint": "/mcp",
        "endpoints": [
            "GET /v1/capabilities",
            "GET /v1/briefing",
            "GET /v1/threads",
            "POST /v1/threads/batch_triage",
            "GET /v1/threads/{id}",
            "GET /v1/threads/{id}/reply-context",
            "POST /v1/threads/{id}/triage",
            "POST /v1/threads/{id}/snooze",
            "DELETE /v1/threads/{id}/snooze",
            "GET /v1/threads/{id}/annotations",
            "PUT /v1/threads/{id}/annotations",
            "PATCH /v1/threads/{id}/annotations",
            "DELETE /v1/threads/{id}/annotations",
            "GET /v1/scheduled",
            "DELETE /v1/scheduled/{id}",
            "GET /v1/messages",
            "GET /v1/messages/{id}",
            "POST /v1/messages/{id}/unsubscribe",
            "GET /v1/messages/{id}/attachments/{attachment_id}",
            "GET /v1/messages/{id}/attachments/{attachment_id}/text",
            "POST /v1/messages/send",
            "POST /v1/messages/modify",
            "GET /v1/drafts",
            "POST /v1/drafts",
            "POST /v1/drafts/{id}/send",
            "DELETE /v1/drafts/{id}",
            "GET /v1/approvals",
            "GET /v1/approvals/{id}",
            "POST /v1/approvals/{id}/approve",
            "POST /v1/approvals/{id}/reject",
            "GET /v1/contacts",
            "GET /v1/contacts/{email}",
            "PATCH /v1/contacts/{email}",
            "GET /v1/rules",
            "POST /v1/rules",
            "PATCH /v1/rules/{id}",
            "DELETE /v1/rules/{id}",
            "POST /v1/rules/{id}/test",
            "GET /v1/audit",
            "GET /v1/labels",
            "GET /v1/search",
            "GET /v1/events",
            "POST /v1/sync/gmail",
            "GET /v1/sync/status"
        ],
        "safety": {
            "draft_only": cfg.draft_only,
            "draft_only_action": cfg.draft_only_action,
            "require_approval": cfg.require_approval,
            "first_contact_approval": cfg.first_contact_approval,
            "dlp_action": cfg.dlp_action,
            "approval_ttl_secs": cfg.approval_ttl_secs,
            "approval_webhook_enabled": cfg.approval_webhook_url.as_deref().is_some_and(|u| !u.trim().is_empty()),
            "allowed_recipients_enabled": !cfg.allowed_recipients.is_empty(),
            "max_send_recipients": cfg.max_send_recipients,
            "default_max_body_chars": cfg.default_max_body_chars,
            "hard_max_body_chars": safety::HARD_MAX_BODY_CHARS,
            "untrusted_content_guard": cfg.untrusted_content_guard,
        },
        "search_operators": [
            "from:", "to:", "cc:", "bcc:", "subject:", "label:", "in:",
            "is:unread", "is:read", "is:starred", "has:attachment",
            "filename:", "before:", "after:", "older_than:", "newer_than:",
            "rfc822msgid:", "OR", "-"
        ],
        "sync_enabled": cfg.gmail_sync_configured(),
        "sync_mode": cfg.sync_mode,
        "imap_enabled": cfg.imap_bind.is_some() || cfg.imap_tls_bind.is_some(),
        "oauth2_enabled": cfg.oauth2_enabled(),
        "active_filters": active_filters,
        "active_outbound_policies": state.outbound_policy.active_policies(),
        "backends": {
            "storage": state.store.backend_name(),
            "blob": state.blobs.backend_name(),
            "transport": state.transport.name(),
            "filter": filter_backend,
            "auth": state.auth.backend_name(),
            "search": state.search.backend_name(),
            "outbound_policy": state.outbound_policy.backend_name(),
        },
    });
    Ok(Json(project_fields(body, query.fields.as_deref())?))
}

async fn list_threads(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Query(params): Query<ListThreadsParams>,
) -> Result<Json<Value>, AiError> {
    if let Some(lbl) = params.label.as_deref() {
        validate_resource_id(lbl)?;
    }
    let waiting_on = parse_waiting_on_filter(params.waiting_on.as_deref())?;
    let limit = params
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);

    let mut page = state
        .store
        .list_thread_summaries(&AiThreadQuery {
            q: params.q.clone(),
            label: params.label.clone(),
            unread_only: params.unread_only,
            needs_reply: params.needs_reply,
            waiting_on,
            include_spam_trash: params.include_spam_trash,
            limit,
            cursor: params.cursor,
        })
        .await?;

    enrich_thread_summaries_with_contacts(&state, &mut page.threads).await?;
    let target_ids: Vec<String> = page.threads.iter().map(|t| t.id.clone()).collect();
    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/v1",
            "read",
            target_ids,
            "ok",
            params.q.as_ref().map(|q| format!("threads q={q}")),
        )
        .await;

    let body = json!({
        "threads": page.threads,
        "next_cursor": page.next_cursor,
        "has_more": page.has_more,
    });
    Ok(Json(project_fields(body, params.fields.as_deref())?))
}

async fn get_thread(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(id): Path<String>,
    Query(params): Query<ReadThreadParams>,
) -> Result<Json<Value>, AiError> {
    validate_resource_id(&id)?;

    let detail = state
        .store
        .get_thread(&id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Thread '{id}' not found")))?;

    let max_body_chars = clamp_max_body_chars(params.max_body_chars, &state.config);
    let strip_quotes = params.strip_quotes.unwrap_or(true);
    let include_attachments_meta = params.include_attachments_meta.unwrap_or(true);

    let projected = build_thread_detail(
        &state,
        detail,
        max_body_chars,
        strip_quotes,
        params.include_html,
        include_attachments_meta,
    )
    .await?;

    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/v1",
            "read",
            vec![id],
            "ok",
            Some("thread".to_string()),
        )
        .await;

    let value = serde_json::to_value(projected).map_err(AppError::from)?;
    Ok(Json(project_fields(value, params.fields.as_deref())?))
}

async fn get_reply_context_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(id): Path<String>,
    Query(params): Query<ReplyContextParams>,
) -> Result<Json<Value>, AiError> {
    let ctx = execute_get_reply_context(
        &state,
        &id,
        ReplyContextOptions {
            max_body_chars: params.max_body_chars,
            max_style_samples: params.max_style_samples,
            max_related_threads: params.max_related_threads,
        },
    )
    .await?;

    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/v1",
            "read",
            vec![id],
            "ok",
            Some("reply_context".to_string()),
        )
        .await;

    let value = serde_json::to_value(ctx).map_err(AppError::from)?;
    Ok(Json(project_fields(value, params.fields.as_deref())?))
}

async fn batch_triage_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Query(query): Query<FieldsQuery>,
    Json(req): Json<AiBatchTriageRequest>,
) -> Result<Json<Value>, AiError> {
    let res = execute_batch_triage_with_context(
        &state,
        req,
        principal.map(|Extension(p)| p),
        EventSource::Api,
    )
    .await?;
    Ok(Json(project_fields(res, query.fields.as_deref())?))
}

async fn triage_thread_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(id): Path<String>,
    Query(query): Query<FieldsQuery>,
    Json(req): Json<AiTriageRequest>,
) -> Result<Json<Value>, AiError> {
    let res = execute_triage_thread_with_context(
        &state,
        &id,
        req,
        principal.map(|Extension(p)| p),
        EventSource::Api,
    )
    .await?;
    Ok(Json(project_fields(res, query.fields.as_deref())?))
}

async fn snooze_thread_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(id): Path<String>,
    Query(query): Query<FieldsQuery>,
    Json(req): Json<SnoozeThreadRequest>,
) -> Result<Json<Value>, AiError> {
    let res = execute_snooze_thread_with_context(
        &state,
        &id,
        req,
        principal.map(|Extension(p)| p),
        EventSource::Api,
    )
    .await?;
    Ok(Json(project_fields(res, query.fields.as_deref())?))
}

async fn unsnooze_thread_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(id): Path<String>,
    Query(query): Query<FieldsQuery>,
) -> Result<Json<Value>, AiError> {
    let res = execute_unsnooze_thread_with_context(
        &state,
        &id,
        principal.map(|Extension(p)| p),
        EventSource::Api,
    )
    .await?;
    Ok(Json(project_fields(res, query.fields.as_deref())?))
}

async fn list_scheduled_sends_handler(
    MailboxState(state): MailboxState,
    Query(params): Query<ListScheduledParams>,
) -> Result<Json<Value>, AiError> {
    let limit = params
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);
    let body = execute_list_scheduled_sends(&state, params.status.as_deref(), limit).await?;
    Ok(Json(project_fields(body, params.fields.as_deref())?))
}

async fn cancel_scheduled_send_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(id): Path<String>,
    Query(query): Query<FieldsQuery>,
) -> Result<Json<Value>, AiError> {
    let res = execute_cancel_scheduled_send_with_context(
        &state,
        &id,
        principal.map(|Extension(p)| p),
        EventSource::Api,
    )
    .await?;
    Ok(Json(project_fields(res, query.fields.as_deref())?))
}

async fn get_thread_annotations_handler(
    MailboxState(state): MailboxState,
    Path(id): Path<String>,
    Query(query): Query<FieldsQuery>,
) -> Result<Json<Value>, AiError> {
    let res = execute_get_thread_annotations(&state, &id).await?;
    Ok(Json(project_fields(res, query.fields.as_deref())?))
}

async fn put_thread_annotations_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(id): Path<String>,
    Query(query): Query<FieldsQuery>,
    Json(req): Json<UpsertThreadAnnotationRequest>,
) -> Result<Json<Value>, AiError> {
    let res = execute_upsert_thread_annotation(
        &state,
        &id,
        req,
        principal.as_ref().map(|Extension(p)| p),
    )
    .await?;
    Ok(Json(project_fields(res, query.fields.as_deref())?))
}

async fn patch_thread_annotations_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(id): Path<String>,
    Query(query): Query<FieldsQuery>,
    Json(req): Json<PatchThreadAnnotationRequest>,
) -> Result<Json<Value>, AiError> {
    let res =
        execute_patch_thread_annotation(&state, &id, req, principal.as_ref().map(|Extension(p)| p))
            .await?;
    Ok(Json(project_fields(res, query.fields.as_deref())?))
}

async fn delete_thread_annotations_handler(
    MailboxState(state): MailboxState,
    Path(id): Path<String>,
    Query(query): Query<FieldsQuery>,
) -> Result<Json<Value>, AiError> {
    let res = execute_delete_thread_annotation(&state, &id).await?;
    Ok(Json(project_fields(res, query.fields.as_deref())?))
}

async fn list_messages(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Query(params): Query<ListMessagesParams>,
) -> Result<Json<Value>, AiError> {
    let mut labels = parse_csv(params.labels.as_deref());
    if let Some(lbl) = params.label.as_deref()
        && !lbl.trim().is_empty()
    {
        labels.push(lbl.trim().to_string());
    }
    for lbl in &labels {
        validate_resource_id(lbl)?;
    }
    if let Some(tid) = params.thread_id.as_deref() {
        validate_resource_id(tid)?;
    }

    let limit = params
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);
    let max_body_chars = params
        .max_body_chars
        .unwrap_or(DEFAULT_LIST_BODY_CHARS)
        .min(safety::HARD_MAX_BODY_CHARS);

    let page = state
        .store
        .search_messages_ai(&AiSearchQuery {
            q: params.q.clone(),
            labels,
            thread_id: params.thread_id,
            include_spam_trash: params.include_spam_trash,
            limit,
            cursor: params.cursor,
            ..Default::default()
        })
        .await?;

    let target_ids: Vec<String> = page.messages.iter().map(|m| m.id.clone()).collect();
    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/v1",
            "read",
            target_ids,
            "ok",
            params.q.as_ref().map(|q| format!("messages q={q}")),
        )
        .await;

    let messages: Vec<CompactMessage> = page
        .messages
        .iter()
        .map(|m| {
            to_compact_message(
                m,
                &state.config,
                params.include_body,
                max_body_chars,
                params.strip_quotes,
                params.include_html,
            )
        })
        .collect();

    let body = json!({
        "messages": messages,
        "next_cursor": page.next_cursor,
        "has_more": page.has_more,
    });
    Ok(Json(project_fields(body, params.fields.as_deref())?))
}

async fn get_message(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(id): Path<String>,
    Query(params): Query<ReadMessageParams>,
) -> Result<Json<Value>, AiError> {
    validate_resource_id(&id)?;

    let msg = state
        .store
        .get_message(&id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Message '{id}' not found")))?;

    let max_body_chars = clamp_max_body_chars(params.max_body_chars, &state.config);
    let include_attachments_meta = params.include_attachments_meta.unwrap_or(true);

    let mut compact = build_compact_message_with_meta(
        &state,
        &msg,
        true,
        max_body_chars,
        params.strip_quotes,
        params.include_html,
        include_attachments_meta,
    )
    .await?;

    if params.extract_attachment_text {
        attach_extracted_attachment_texts(&state, &mut compact, params.attachment_max_chars)
            .await?;
    }

    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/v1",
            "read",
            vec![id],
            "ok",
            Some("message".to_string()),
        )
        .await;

    let value = serde_json::to_value(compact).map_err(AppError::from)?;
    Ok(Json(project_fields(value, params.fields.as_deref())?))
}

async fn unsubscribe_message_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(id): Path<String>,
    Query(query): Query<FieldsQuery>,
    body: Bytes,
) -> Result<Response, AiError> {
    let req: AiUnsubscribeRequest = parse_optional_json(&body)?;
    let res = execute_unsubscribe_with_source(
        &state,
        principal.map(|Extension(p)| p),
        &id,
        req.dry_run,
        req.prefer_mailto,
        EventSource::Api,
    )
    .await?;
    let status = match res.get("status").and_then(Value::as_str) {
        Some("pending_approval") | Some("scheduled") => StatusCode::ACCEPTED,
        _ => StatusCode::OK,
    };
    let projected = project_fields(res, query.fields.as_deref())?;
    Ok((status, Json(projected)).into_response())
}

async fn get_attachment_text_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path((id, attachment_id)): Path<(String, String)>,
    Query(params): Query<AttachmentTextParams>,
) -> Result<Json<Value>, AiError> {
    let extracted =
        execute_read_attachment_text(&state, &id, &attachment_id, params.max_chars).await?;
    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/v1",
            "read",
            vec![id, attachment_id],
            "ok",
            Some("attachment_text".to_string()),
        )
        .await;
    let value = serde_json::to_value(extracted).map_err(AppError::from)?;
    Ok(Json(project_fields(value, params.fields.as_deref())?))
}

async fn get_attachment_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path((id, attachment_id)): Path<(String, String)>,
) -> Result<Response, AiError> {
    validate_resource_id(&id)?;
    validate_resource_id(&attachment_id)?;

    let att = state
        .store
        .get_attachment(&id, &attachment_id)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "Attachment '{attachment_id}' on message '{id}' not found"
            ))
        })?;

    let mut headers = HeaderMap::new();
    let content_type = HeaderValue::from_str(&att.content_type)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    headers.insert(header::CONTENT_TYPE, content_type);

    if let Some(filename) = &att.filename {
        let safe_name: String = filename
            .chars()
            .filter(|c| !matches!(c, '"' | '\\' | '\r' | '\n' | '\0'))
            .collect();
        if let Ok(disposition) =
            HeaderValue::from_str(&format!("attachment; filename=\"{safe_name}\""))
        {
            headers.insert(header::CONTENT_DISPOSITION, disposition);
        }
    }

    let data = state.load_attachment_bytes(&att).await?;
    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/v1",
            "read",
            vec![id, attachment_id],
            "ok",
            Some("attachment".to_string()),
        )
        .await;
    Ok((StatusCode::OK, headers, data).into_response())
}

async fn send_message_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    headers: HeaderMap,
    Query(query): Query<FieldsQuery>,
    Json(mut req): Json<AiSendEmailRequest>,
) -> Result<Response, AiError> {
    if req
        .idempotency_key
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .is_empty()
        && let Some(hdr_key) = idempotency_key_header(&headers)
    {
        req.idempotency_key = Some(hdr_key.to_string());
    }
    let res = execute_send_email_with_context(
        &state,
        req,
        principal.map(|Extension(p)| p),
        EventSource::Api,
    )
    .await?;
    let status = match res.get("status").and_then(Value::as_str) {
        Some("pending_approval") | Some("scheduled") => StatusCode::ACCEPTED,
        _ => StatusCode::OK,
    };
    let projected = project_fields(res, query.fields.as_deref())?;
    Ok((status, Json(projected)).into_response())
}

async fn modify_messages_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Query(query): Query<FieldsQuery>,
    Json(req): Json<AiModifyLabelsRequest>,
) -> Result<Json<Value>, AiError> {
    let res = execute_modify_labels_with_context(
        &state,
        req,
        principal.map(|Extension(p)| p),
        EventSource::Api,
    )
    .await?;
    Ok(Json(project_fields(res, query.fields.as_deref())?))
}

async fn list_drafts(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Query(params): Query<ListDraftsParams>,
) -> Result<Json<Value>, AiError> {
    let limit = params
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);

    let page = state
        .store
        .list_drafts(&MessageListQuery {
            max_results: limit,
            page_token: params.page_token,
            ..Default::default()
        })
        .await?;

    let target_ids: Vec<String> = page.drafts.iter().map(|d| d.id.clone()).collect();
    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/v1",
            "read",
            target_ids,
            "ok",
            Some("drafts".to_string()),
        )
        .await;

    let drafts: Vec<Value> = page
        .drafts
        .iter()
        .map(|d| {
            let msg = to_compact_message(
                &d.message,
                &state.config,
                true,
                DEFAULT_LIST_BODY_CHARS,
                false,
                false,
            );
            json!({
                "id": d.id,
                "updated_at": d.updated_at,
                "message": msg,
            })
        })
        .collect();

    let body = json!({
        "drafts": drafts,
        "next_cursor": page.next_page_token,
        "has_more": page.next_page_token.is_some(),
    });
    Ok(Json(project_fields(body, params.fields.as_deref())?))
}

async fn create_draft_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    headers: HeaderMap,
    Query(query): Query<FieldsQuery>,
    Json(mut req): Json<AiCreateDraftRequest>,
) -> Result<Json<Value>, AiError> {
    if req
        .idempotency_key
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .is_empty()
        && let Some(hdr_key) = idempotency_key_header(&headers)
    {
        req.idempotency_key = Some(hdr_key.to_string());
    }
    let res = execute_create_draft_with_context(
        &state,
        req,
        principal.map(|Extension(p)| p),
        EventSource::Api,
    )
    .await?;
    Ok(Json(project_fields(res, query.fields.as_deref())?))
}

async fn send_draft_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(id): Path<String>,
    Query(query): Query<FieldsQuery>,
    body: Bytes,
) -> Result<Response, AiError> {
    let req: AiSendDraftRequest = parse_optional_json(&body)?;
    let res = execute_send_draft_with_context(
        &state,
        &id,
        req,
        principal.map(|Extension(p)| p),
        EventSource::Api,
    )
    .await?;
    let status = match res.get("status").and_then(Value::as_str) {
        Some("pending_approval") | Some("scheduled") => StatusCode::ACCEPTED,
        _ => StatusCode::OK,
    };
    let projected = project_fields(res, query.fields.as_deref())?;
    Ok((status, Json(projected)).into_response())
}

#[derive(Debug, Default, Deserialize)]
struct BriefingQueryParams {
    since: Option<String>,
    followup_days: Option<u32>,
    limit: Option<usize>,
    fields: Option<String>,
}

async fn briefing_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Query(params): Query<BriefingQueryParams>,
) -> Result<Json<Value>, AiError> {
    let since = parse_briefing_since(params.since.as_deref())?;
    let body = execute_briefing(
        &state,
        BriefingParams {
            since,
            followup_days: params.followup_days,
            limit: params.limit,
        },
    )
    .await?;
    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/v1",
            "read",
            Vec::new(),
            "ok",
            Some("briefing".to_string()),
        )
        .await;
    Ok(Json(project_fields(body, params.fields.as_deref())?))
}

async fn list_approvals_handler(
    MailboxState(state): MailboxState,
    Query(params): Query<ListApprovalsParams>,
) -> Result<Json<Value>, AiError> {
    let limit = params
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);
    let body = execute_list_approvals(&state, params.status.as_deref(), limit).await?;
    Ok(Json(project_fields(body, params.fields.as_deref())?))
}

async fn get_approval_handler(
    MailboxState(state): MailboxState,
    Path(id): Path<String>,
    Query(query): Query<FieldsQuery>,
) -> Result<Json<Value>, AiError> {
    let body = execute_get_approval(&state, &id).await?;
    Ok(Json(project_fields(body, query.fields.as_deref())?))
}

async fn approve_approval_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(id): Path<String>,
    Query(query): Query<FieldsQuery>,
    body: Bytes,
) -> Result<Json<Value>, AiError> {
    let req: ApprovalDecisionRequest = parse_optional_json(&body)?;
    let res = execute_approve_approval(
        &state,
        &id,
        req,
        principal.as_ref().map(|Extension(p)| p),
        EventSource::Api,
    )
    .await?;
    Ok(Json(project_fields(res, query.fields.as_deref())?))
}

async fn reject_approval_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(id): Path<String>,
    Query(query): Query<FieldsQuery>,
    body: Bytes,
) -> Result<Json<Value>, AiError> {
    let req: ApprovalDecisionRequest = parse_optional_json(&body)?;
    let res = execute_reject_approval(
        &state,
        &id,
        req,
        principal.as_ref().map(|Extension(p)| p),
        EventSource::Api,
    )
    .await?;
    Ok(Json(project_fields(res, query.fields.as_deref())?))
}

async fn delete_draft_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AiError> {
    validate_resource_id(&id)?;
    let deleted = state.store.delete_draft(&id).await?;
    if !deleted {
        return Err(AppError::NotFound(format!("Draft '{id}' not found")).into());
    }
    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/v1",
            "delete",
            vec![id.clone()],
            "ok",
            Some("draft".to_string()),
        )
        .await;
    Ok(Json(json!({ "deleted": true, "draft_id": id })))
}

async fn list_audit_handler(
    MailboxState(state): MailboxState,
    Query(params): Query<ListAuditParams>,
) -> Result<Json<Value>, AiError> {
    let limit = params.limit.unwrap_or(DEFAULT_AUDIT_LIMIT);
    let body = execute_list_audit_log(
        &state,
        params.action.as_deref(),
        params.actor.as_deref(),
        params.since.as_deref(),
        limit,
    )
    .await?;
    Ok(Json(project_fields(body, params.fields.as_deref())?))
}

async fn list_labels(
    MailboxState(state): MailboxState,
    Query(query): Query<FieldsQuery>,
) -> Result<Json<Value>, AiError> {
    let labels = state.store.list_labels().await?;
    let items: Vec<Value> = labels
        .into_iter()
        .map(|l| {
            json!({
                "id": l.id,
                "name": l.name,
                "kind": l.label_type,
                "messages_total": l.messages_total,
                "messages_unread": l.messages_unread,
                "threads_total": l.threads_total,
                "threads_unread": l.threads_unread,
            })
        })
        .collect();
    let body = json!({ "labels": items });
    Ok(Json(project_fields(body, query.fields.as_deref())?))
}

async fn search_messages(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Query(params): Query<SearchParams>,
) -> Result<Json<Value>, AiError> {
    let mut labels = parse_csv(params.labels.as_deref());
    if let Some(lbl) = params.label.as_deref()
        && !lbl.trim().is_empty()
    {
        labels.push(lbl.trim().to_string());
    }
    for lbl in &labels {
        validate_resource_id(lbl)?;
    }
    if let Some(tid) = params.thread_id.as_deref() {
        validate_resource_id(tid)?;
    }

    let limit = params
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);
    let max_body_chars = params
        .max_body_chars
        .unwrap_or(DEFAULT_LIST_BODY_CHARS)
        .min(safety::HARD_MAX_BODY_CHARS);

    let page = state
        .search
        .search(&AiSearchQuery {
            q: params.q.clone(),
            labels,
            unread: params.unread,
            thread_id: params.thread_id,
            from: params.from,
            to: params.to,
            after: params.after,
            before: params.before,
            has_attachment: params.has_attachment,
            include_spam_trash: params.include_spam_trash,
            limit,
            cursor: params.cursor,
        })
        .await?;

    let target_ids: Vec<String> = page.messages.iter().map(|m| m.id.clone()).collect();
    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/v1",
            "search",
            target_ids,
            "ok",
            params.q.clone(),
        )
        .await;

    let messages: Vec<CompactMessage> = page
        .messages
        .iter()
        .map(|m| {
            to_compact_message(
                m,
                &state.config,
                params.include_body,
                max_body_chars,
                params.strip_quotes,
                params.include_html,
            )
        })
        .collect();

    let body = json!({
        "messages": messages,
        "next_cursor": page.next_cursor,
        "has_more": page.has_more,
    });
    Ok(Json(project_fields(body, params.fields.as_deref())?))
}

async fn events_sse_handler(
    MailboxState(state): MailboxState,
    headers: HeaderMap,
    Query(params): Query<EventsParams>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, AiError> {
    if let Some(lbl) = params.label.as_deref() {
        validate_resource_id(lbl)?;
    }
    if let Some(tid) = params.thread_id.as_deref() {
        validate_resource_id(tid)?;
    }

    let types = parse_csv(params.types.as_deref());
    let label = params.label;
    let thread_id = params.thread_id;

    let since_id = params.since_id.or_else(|| {
        headers
            .get("last-event-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
    });

    // Subscribe BEFORE reading replay buffer so no events are missed across the boundary.
    let rx = state.events.subscribe();

    let mut last_replayed_id = since_id.unwrap_or(0);
    let replay_events: VecDeque<Event> = if let Some(since) = since_id {
        state
            .events
            .events_since(since, SSE_REPLAY_LIMIT)
            .into_iter()
            .filter_map(|env| {
                if env.id > last_replayed_id {
                    last_replayed_id = env.id;
                }
                if !event_matches_filter(&env, &types, label.as_deref(), thread_id.as_deref()) {
                    return None;
                }
                let data = serde_json::to_string(&env).ok()?;
                Some(
                    Event::default()
                        .id(env.id.to_string())
                        .event(env.event.event_type())
                        .data(data),
                )
            })
            .collect()
    } else {
        VecDeque::new()
    };

    struct SseStreamState {
        replay: VecDeque<Event>,
        rx: tokio::sync::broadcast::Receiver<EventEnvelope>,
        shutdown: tokio::sync::watch::Receiver<bool>,
        active_mailbox: String,
        last_replayed_id: u64,
        types: Vec<String>,
        label: Option<String>,
        thread_id: Option<String>,
        _conn_guard: crate::metrics::ActiveGaugeGuard,
    }

    let stream_state = SseStreamState {
        replay: replay_events,
        rx,
        shutdown: state.subscribe_shutdown(),
        active_mailbox: state.mailbox_id().to_string(),
        last_replayed_id,
        types,
        label,
        thread_id,
        _conn_guard: state.metrics.track_sse_connection(),
    };

    let combined = stream::unfold(stream_state, |mut st| async move {
        if *st.shutdown.borrow() {
            return None;
        }
        if let Some(ev) = st.replay.pop_front() {
            return Some((Ok(ev), st));
        }
        loop {
            if *st.shutdown.borrow() {
                return None;
            }
            tokio::select! {
                biased;
                changed = st.shutdown.changed() => {
                    if changed.is_err() || *st.shutdown.borrow() {
                        return None;
                    }
                }
                recv = st.rx.recv() => {
                    match recv {
                        Ok(env) => {
                            if !st.active_mailbox.is_empty()
                                && !env.mailbox_id.is_empty()
                                && !env.mailbox_id.eq_ignore_ascii_case(&st.active_mailbox)
                            {
                                continue;
                            }
                            if env.id <= st.last_replayed_id {
                                continue;
                            }
                            if !event_matches_filter(
                                &env,
                                &st.types,
                                st.label.as_deref(),
                                st.thread_id.as_deref(),
                            ) {
                                continue;
                            }
                            let Ok(data) = serde_json::to_string(&env) else {
                                continue;
                            };
                            let event = Event::default()
                                .id(env.id.to_string())
                                .event(env.event.event_type())
                                .data(data);
                            return Some((Ok(event), st));
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                    }
                }
            }
        }
    });

    Ok(Sse::new(combined).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

async fn sync_gmail_handler(
    MailboxState(state): MailboxState,
    Query(query): Query<FieldsQuery>,
    body: Bytes,
) -> Result<Json<Value>, AiError> {
    let req: SyncTriggerRequest = parse_optional_json(&body)?;
    let opts = parse_sync_trigger(req)?;
    let report = sync::run_gmail_sync(&state, opts).await?;
    let value = serde_json::to_value(report).map_err(AppError::from)?;
    Ok(Json(project_fields(value, query.fields.as_deref())?))
}

async fn sync_status_handler(
    MailboxState(state): MailboxState,
    Query(query): Query<FieldsQuery>,
) -> Result<Json<Value>, AiError> {
    let status = sync::get_sync_status(&state).await?;
    let value = serde_json::to_value(status).map_err(AppError::from)?;
    Ok(Json(project_fields(value, query.fields.as_deref())?))
}

async fn list_contacts_handler(
    MailboxState(state): MailboxState,
    Query(params): Query<ListContactsParams>,
) -> Result<Json<Value>, AiError> {
    let limit = params
        .limit
        .unwrap_or(DEFAULT_CONTACTS_LIMIT)
        .clamp(1, MAX_CONTACTS_LIMIT);
    let contacts: Vec<ContactRecord> = state
        .store
        .list_contacts(&ContactQuery {
            q: params.q,
            vip_only: params.vip_only,
            replied_only: params.replied_only,
            domain: params.domain,
            limit,
        })
        .await?
        .into_iter()
        .map(|c| sanitize_contact_record(c, state.config.untrusted_content_guard))
        .collect();

    let count = contacts.len();
    let body = json!({
        "contacts": contacts,
        "count": count,
    });
    Ok(Json(project_fields(body, params.fields.as_deref())?))
}

async fn get_contact_handler(
    MailboxState(state): MailboxState,
    Path(email): Path<String>,
    Query(query): Query<FieldsQuery>,
) -> Result<Json<Value>, AiError> {
    let (normalized, _) = validate_and_normalize_contact_email(&email).map_err(|_| {
        AppError::validation(
            format!("Invalid contact email address '{email}'"),
            Some("Provide a valid email address such as alice@example.com.".to_string()),
        )
    })?;

    let contact = state
        .store
        .get_contact(&normalized)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Contact '{normalized}' not found")))?;
    let contact = sanitize_contact_record(contact, state.config.untrusted_content_guard);
    let value = serde_json::to_value(contact).map_err(AppError::from)?;
    Ok(Json(project_fields(value, query.fields.as_deref())?))
}

async fn patch_contact_handler(
    MailboxState(state): MailboxState,
    Path(email): Path<String>,
    Query(query): Query<FieldsQuery>,
    Json(patch): Json<ContactPatch>,
) -> Result<Json<Value>, AiError> {
    let (normalized, _) = validate_and_normalize_contact_email(&email).map_err(|_| {
        AppError::validation(
            format!("Invalid contact email address '{email}'"),
            Some("Provide a valid email address such as alice@example.com.".to_string()),
        )
    })?;
    if let Some(ref display_name) = patch.display_name {
        validate_email_header("display_name", display_name)?;
    }

    let updated = state.store.patch_contact(&normalized, &patch).await?;
    let updated = sanitize_contact_record(updated, state.config.untrusted_content_guard);
    let value = serde_json::to_value(updated).map_err(AppError::from)?;
    Ok(Json(project_fields(value, query.fields.as_deref())?))
}

#[derive(Debug, Default, Deserialize)]
struct TestRuleParams {
    limit: Option<usize>,
    fields: Option<String>,
}

async fn list_rules_handler(
    MailboxState(state): MailboxState,
    Query(query): Query<FieldsQuery>,
) -> Result<Json<Value>, AiError> {
    let body = rules::execute_list_rules(&state).await?;
    Ok(Json(project_fields(body, query.fields.as_deref())?))
}

async fn create_rule_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Query(query): Query<FieldsQuery>,
    Json(req): Json<NewInboxRule>,
) -> Result<Json<Value>, AiError> {
    let body = rules::execute_create_rule_with_context(
        &state,
        req,
        principal.map(|Extension(p)| p),
        EventSource::Api,
    )
    .await?;
    Ok(Json(project_fields(body, query.fields.as_deref())?))
}

async fn patch_rule_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(id): Path<String>,
    Query(query): Query<FieldsQuery>,
    Json(req): Json<InboxRulePatch>,
) -> Result<Json<Value>, AiError> {
    let body = rules::execute_patch_rule_with_context(
        &state,
        &id,
        req,
        principal.map(|Extension(p)| p),
        EventSource::Api,
    )
    .await?;
    Ok(Json(project_fields(body, query.fields.as_deref())?))
}

async fn delete_rule_handler(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(id): Path<String>,
    Query(query): Query<FieldsQuery>,
) -> Result<Json<Value>, AiError> {
    let body = rules::execute_delete_rule_with_context(
        &state,
        &id,
        principal.map(|Extension(p)| p),
        EventSource::Api,
    )
    .await?;
    Ok(Json(project_fields(body, query.fields.as_deref())?))
}

async fn test_rule_handler(
    MailboxState(state): MailboxState,
    Path(id): Path<String>,
    Query(params): Query<TestRuleParams>,
) -> Result<Json<Value>, AiError> {
    let body = rules::execute_test_rule(&state, &id, params.limit).await?;
    Ok(Json(project_fields(body, params.fields.as_deref())?))
}
