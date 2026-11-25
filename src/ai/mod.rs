//! AI-first REST API (`/v1/...`), SSE event stream (`/v1/events`),
//! agent safety guardrails (`draft_only`, `allowed_recipients`, `dry_run`),
//! and Agent-DX CLI helpers.
//!
//! Owned by the `ai-mcp` worker.

pub mod safety;
pub mod schema;
#[cfg(test)]
pub(crate) mod tests;

use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    time::Duration,
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{delete, get, post},
};
use chrono::{DateTime, Utc};
use futures_util::stream::{self, Stream, StreamExt};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_stream::wrappers::BroadcastStream;
use uuid::Uuid;

use crate::{
    AppState,
    config::{Config, SyncMode},
    error::{AiError, AppError, AppResult},
    events::{EventEnvelope, EventSource, MailEvent},
    mime::{ComposeEmailInput, apply_fields_mask, build_rfc2822, generate_snippet, strip_quoted_text},
    models::{
        AiCreateDraftRequest, AiModifyLabelsRequest, AiSendDraftRequest, AiSendEmailRequest,
        AiTriageRequest, CompactMessage, EmailAddress, LABEL_DRAFT, LABEL_INBOX, LABEL_SENT,
        LABEL_STARRED, LABEL_TRASH, LABEL_UNREAD, SyncTriggerRequest, ThreadDetail,
    },
    storage::{
        AiSearchQuery, AiThreadQuery, MessageListQuery, NewMessageInput, StoredMessage,
        StoredThreadDetail, TriagePatch, parse_simple_email_address,
    },
    sync::{self, SyncRunOptions},
    transport::OutboundMessage,
};

pub use safety::{
    ConfigOutboundPolicy, OutboundCheck, OutboundDecision, OutboundPolicy, PolicyCheck,
    check_recipients_policy, clamp_max_body_chars, evaluate_send_dry_run, sanitize_untrusted_text,
    untrusted_meta, validate_email_header, validate_resource_id,
};
pub use schema::runtime_schema;

const DEFAULT_LIST_LIMIT: usize = 20;
const MAX_LIST_LIMIT: usize = 100;
const DEFAULT_LIST_BODY_CHARS: usize = 1000;
const SSE_REPLAY_LIMIT: usize = 1024;

/// Build the AI-first `/v1` router (alias for [`ai_router`]).
pub fn router() -> Router<AppState> {
    ai_router()
}

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
        .route("/v1/capabilities", get(get_capabilities))
        .route("/v1/threads", get(list_threads))
        .route("/v1/threads/{id}", get(get_thread))
        .route("/v1/threads/{id}/triage", post(triage_thread_handler))
        .route("/v1/messages", get(list_messages))
        .route("/v1/messages/send", post(send_message_handler))
        .route("/v1/messages/modify", post(modify_messages_handler))
        .route("/v1/messages/{id}", get(get_message))
        .route(
            "/v1/messages/{id}/attachments/{attachment_id}",
            get(get_attachment_handler),
        )
        .route("/v1/drafts", get(list_drafts).post(create_draft_handler))
        .route("/v1/drafts/{id}", delete(delete_draft_handler))
        .route("/v1/drafts/{id}/send", post(send_draft_handler))
        .route("/v1/labels", get(list_labels))
        .route("/v1/search", get(search_messages))
        .route("/v1/events", get(events_sse_handler))
        .route("/v1/sync/gmail", post(sync_gmail_handler))
        .route("/v1/sync/status", get(sync_status_handler))
}

// ============================================================================
// Shared Operations (used by REST `/v1`, MCP tools/resources, and CLI)
// ============================================================================

/// Execute an AI-first send (shared across `/v1/messages/send`, MCP `send_email`, and CLI `nogml mail send`).
pub async fn execute_send_email(state: &AppState, req: AiSendEmailRequest) -> AppResult<Value> {
    execute_send_email_with_source(state, req, EventSource::Api).await
}

/// Internal variant allowing callers (REST vs MCP) to tag the published [`EventSource`].
pub async fn execute_send_email_with_source(
    state: &AppState,
    req: AiSendEmailRequest,
    source: EventSource,
) -> AppResult<Value> {
    if req.dry_run {
        let preview = evaluate_send_dry_run(state, &req).await?;
        return Ok(serde_json::to_value(preview)?);
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
            Some("Provide at least one email address in 'to', or supply 'reply_to_message_id'.".to_string()),
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
        thread_id: resolved.thread_id.clone(),
        is_draft_send: false,
    };
    let decision = state.outbound_policy.evaluate(&policy_check).await?;

    let rfc_message_id = format!("<{}@{}>", Uuid::new_v4(), state.config.default_domain);
    let raw_rfc2822 = build_outbound_rfc2822(&resolved, &rfc_message_id)?;
    let text_body = resolved.text.clone().unwrap_or_default();
    let snippet = generate_snippet(&text_body, resolved.html.as_deref());
    let now_ms = Utc::now().timestamp_millis();

    match decision {
        OutboundDecision::Deny { code, reason, hint } => {
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
            return Ok(json!({
                "status": "draft_created",
                "downgraded_from_send": true,
                "draft_id": draft.id,
                "message_id": draft.message.id,
                "thread_id": draft.message.thread_id,
                "to": draft.message.to_addrs,
                "subject": draft.message.subject,
            }));
        }
        OutboundDecision::HoldForApproval { reason } => {
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
            return Ok(json!({
                "status": "pending_approval",
                "held_for_approval": true,
                "reason": reason,
                "draft_id": draft.id,
                "message_id": draft.message.id,
                "thread_id": draft.message.thread_id,
                "to": draft.message.to_addrs,
                "subject": draft.message.subject,
            }));
        }
        OutboundDecision::Allow => {}
    }

    let outbound_msg = build_outbound_message(&resolved, &rfc_message_id, &raw_rfc2822);
    let send_outcome = state.transport.send(&outbound_msg, None).await?;

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

    Ok(json!({
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
    }))
}

/// Execute an AI-first draft creation (shared across `/v1/drafts`, MCP `create_draft`, and CLI).
pub async fn execute_create_draft(
    state: &AppState,
    req: AiCreateDraftRequest,
) -> AppResult<Value> {
    execute_create_draft_with_source(state, req, EventSource::Api).await
}

/// Internal variant allowing callers to tag the published [`EventSource`].
pub async fn execute_create_draft_with_source(
    state: &AppState,
    req: AiCreateDraftRequest,
    source: EventSource,
) -> AppResult<Value> {
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

    Ok(json!({
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
    }))
}

/// Execute sending an existing draft (shared across `/v1/drafts/{id}/send` and MCP `send_draft`).
pub async fn execute_send_draft(
    state: &AppState,
    draft_id: &str,
    req: AiSendDraftRequest,
) -> AppResult<Value> {
    execute_send_draft_with_source(state, draft_id, req, EventSource::Api).await
}

/// Internal variant allowing callers to tag the published [`EventSource`].
pub async fn execute_send_draft_with_source(
    state: &AppState,
    draft_id: &str,
    req: AiSendDraftRequest,
    source: EventSource,
) -> AppResult<Value> {
    validate_resource_id(draft_id)?;

    let draft = state
        .store
        .get_draft(draft_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Draft '{draft_id}' not found")))?;

    let msg = &draft.message;

    if req.dry_run {
        let preview = safety::evaluate_resolved_dry_run(
            state,
            &msg.to_addrs,
            &msg.cc_addrs,
            &msg.bcc_addrs,
            Some(&msg.subject),
            (!msg.text_body.is_empty()).then_some(msg.text_body.as_str()),
            msg.html_body.as_deref(),
            None,
            Some(&msg.thread_id),
            msg.in_reply_to.as_deref(),
            msg.references_header.as_deref(),
            Some(msg.raw_rfc2822.len()),
        )
        .await?;
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
        thread_id: resolved.thread_id.clone(),
        is_draft_send: true,
    };
    match state.outbound_policy.evaluate(&policy_check).await? {
        OutboundDecision::Deny { code, reason, hint } => {
            return Err(policy_deny_to_error(code, reason, hint));
        }
        OutboundDecision::DowngradeToDraft { .. } => {
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
            return Ok(json!({
                "status": "pending_approval",
                "held_for_approval": true,
                "reason": reason,
                "draft_id": draft.id,
                "message_id": msg.id,
                "thread_id": msg.thread_id,
                "to": msg.to_addrs,
                "subject": msg.subject,
            }));
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
    execute_triage_thread_with_source(state, thread_id, req, EventSource::Api).await
}

/// Internal variant allowing callers to tag the published [`EventSource`].
pub async fn execute_triage_thread_with_source(
    state: &AppState,
    thread_id: &str,
    req: AiTriageRequest,
    source: EventSource,
) -> AppResult<Value> {
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

    Ok(json!({
        "thread_id": result.thread_id,
        "affected_message_ids": result.affected_message_ids,
        "labels": result.labels,
        "added_labels": add_labels,
        "removed_labels": remove_labels,
    }))
}

/// Execute label modification (shared across `/v1/messages/modify` and MCP `modify_labels`).
pub async fn execute_modify_labels(
    state: &AppState,
    req: AiModifyLabelsRequest,
) -> AppResult<Value> {
    execute_modify_labels_with_source(state, req, EventSource::Api).await
}

/// Internal variant allowing callers to tag the published [`EventSource`].
pub async fn execute_modify_labels_with_source(
    state: &AppState,
    req: AiModifyLabelsRequest,
    source: EventSource,
) -> AppResult<Value> {
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

    Ok(json!({
        "modified_count": target_ids.len(),
        "affected_message_ids": target_ids,
        "added_labels": add_labels,
        "removed_labels": remove_labels,
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

    let processed_text = if strip_quotes {
        let stripped = strip_quoted_text(&msg.text_body);
        clean(&stripped)
    } else {
        clean(&msg.text_body)
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

    let html = if include_body && include_html {
        msg.html_body.as_deref().map(|raw_html| {
            let cleaned = clean(raw_html);
            if cleaned.chars().count() > effective_cap {
                cleaned.chars().take(effective_cap).collect()
            } else {
                cleaned
            }
        })
    } else {
        None
    };

    CompactMessage {
        id: msg.id.clone(),
        thread_id: msg.thread_id.clone(),
        date,
        from: clean_addr(&msg.from_addr),
        to: msg.to_addrs.iter().map(|a| clean_addr(a)).collect(),
        cc: msg.cc_addrs.iter().map(|a| clean_addr(a)).collect(),
        subject: clean(&msg.subject),
        snippet: clean(&msg.snippet),
        labels: msg.label_ids.clone(),
        unread: msg.label_ids.iter().any(|l| l == LABEL_UNREAD),
        has_attachments: msg.has_attachments,
        attachments_meta: None,
        text,
        text_truncated,
        text_total_chars,
        html,
        in_reply_to: msg.in_reply_to.clone(),
        rfc_message_id: msg.rfc822_message_id.clone(),
        meta: untrusted_meta(config),
    }
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

        compact_messages.push(compact);
    }

    let last_message_at = if last_ms == i64::MIN {
        Utc::now()
    } else {
        DateTime::from_timestamp_millis(last_ms).unwrap_or_else(Utc::now)
    };

    Ok(ThreadDetail {
        id: detail.id,
        subject,
        participants,
        labels,
        unread,
        message_count: compact_messages.len(),
        last_message_at,
        messages: compact_messages,
        meta: untrusted_meta(&state.config),
    })
}

/// Build a compact message populated with attachment metadata when requested.
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
    if include_attachments_meta && msg.has_attachments {
        let meta = state.store.list_attachment_meta(&msg.id).await?;
        if !meta.is_empty() {
            compact.attachments_meta = Some(meta);
        }
    }
    Ok(compact)
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
    })
}

// ============================================================================
// Internal Helpers
// ============================================================================

fn build_outbound_rfc2822(
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

fn validate_recipients_syntax(to: &[String], cc: &[String], bcc: &[String]) -> AppResult<()> {
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

fn policy_deny_to_error(code: String, reason: String, hint: Option<String>) -> AppError {
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

fn build_outbound_message(
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
            MailEvent::DeliveryStatus { .. } | MailEvent::SyncCompleted { .. } => false,
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
    fields: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SearchParams {
    q: Option<String>,
    label: Option<String>,
    labels: Option<String>,
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
struct EventsParams {
    types: Option<String>,
    label: Option<String>,
    thread_id: Option<String>,
    since_id: Option<u64>,
}

async fn get_capabilities(
    State(state): State<AppState>,
    Query(query): Query<FieldsQuery>,
) -> Result<Json<Value>, AiError> {
    let cfg = &state.config;
    let body = json!({
        "service": "nogml",
        "version": env!("CARGO_PKG_VERSION"),
        "user_email": cfg.user_email,
        "mcp_endpoint": "/mcp",
        "endpoints": [
            "GET /v1/capabilities",
            "GET /v1/threads",
            "GET /v1/threads/{id}",
            "POST /v1/threads/{id}/triage",
            "GET /v1/messages",
            "GET /v1/messages/{id}",
            "GET /v1/messages/{id}/attachments/{attachment_id}",
            "POST /v1/messages/send",
            "POST /v1/messages/modify",
            "GET /v1/drafts",
            "POST /v1/drafts",
            "POST /v1/drafts/{id}/send",
            "DELETE /v1/drafts/{id}",
            "GET /v1/labels",
            "GET /v1/search",
            "GET /v1/events",
            "POST /v1/sync/gmail",
            "GET /v1/sync/status"
        ],
        "safety": {
            "draft_only": cfg.draft_only,
            "draft_only_action": cfg.draft_only_action,
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
        "backends": {
            "storage": state.store.backend_name(),
            "blob": state.blobs.backend_name(),
            "transport": state.transport.name(),
            "filter": state.filter.backend_name(),
            "auth": state.auth.backend_name(),
            "search": state.search.backend_name(),
            "outbound_policy": state.outbound_policy.backend_name(),
        },
    });
    Ok(Json(project_fields(body, query.fields.as_deref())?))
}

async fn list_threads(
    State(state): State<AppState>,
    Query(params): Query<ListThreadsParams>,
) -> Result<Json<Value>, AiError> {
    if let Some(lbl) = params.label.as_deref() {
        validate_resource_id(lbl)?;
    }
    let limit = params
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);

    let page = state
        .store
        .list_thread_summaries(&AiThreadQuery {
            q: params.q,
            label: params.label,
            unread_only: params.unread_only,
            include_spam_trash: params.include_spam_trash,
            limit,
            cursor: params.cursor,
        })
        .await?;

    let body = json!({
        "threads": page.threads,
        "next_cursor": page.next_cursor,
        "has_more": page.has_more,
    });
    Ok(Json(project_fields(body, params.fields.as_deref())?))
}

async fn get_thread(
    State(state): State<AppState>,
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

    let value = serde_json::to_value(projected).map_err(AppError::from)?;
    Ok(Json(project_fields(value, params.fields.as_deref())?))
}

async fn triage_thread_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<FieldsQuery>,
    Json(req): Json<AiTriageRequest>,
) -> Result<Json<Value>, AiError> {
    let res = execute_triage_thread_with_source(&state, &id, req, EventSource::Api).await?;
    Ok(Json(project_fields(res, query.fields.as_deref())?))
}

async fn list_messages(
    State(state): State<AppState>,
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
            q: params.q,
            labels,
            thread_id: params.thread_id,
            include_spam_trash: params.include_spam_trash,
            limit,
            cursor: params.cursor,
            ..Default::default()
        })
        .await?;

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
    State(state): State<AppState>,
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

    let compact = build_compact_message_with_meta(
        &state,
        &msg,
        true,
        max_body_chars,
        params.strip_quotes,
        params.include_html,
        include_attachments_meta,
    )
    .await?;

    let value = serde_json::to_value(compact).map_err(AppError::from)?;
    Ok(Json(project_fields(value, params.fields.as_deref())?))
}

async fn get_attachment_handler(
    State(state): State<AppState>,
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
    Ok((StatusCode::OK, headers, data).into_response())
}

async fn send_message_handler(
    State(state): State<AppState>,
    Query(query): Query<FieldsQuery>,
    Json(req): Json<AiSendEmailRequest>,
) -> Result<Response, AiError> {
    let res = execute_send_email_with_source(&state, req, EventSource::Api).await?;
    let status = if res.get("status").and_then(Value::as_str) == Some("pending_approval") {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    let projected = project_fields(res, query.fields.as_deref())?;
    Ok((status, Json(projected)).into_response())
}

async fn modify_messages_handler(
    State(state): State<AppState>,
    Query(query): Query<FieldsQuery>,
    Json(req): Json<AiModifyLabelsRequest>,
) -> Result<Json<Value>, AiError> {
    let res = execute_modify_labels_with_source(&state, req, EventSource::Api).await?;
    Ok(Json(project_fields(res, query.fields.as_deref())?))
}

async fn list_drafts(
    State(state): State<AppState>,
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
    State(state): State<AppState>,
    Query(query): Query<FieldsQuery>,
    Json(req): Json<AiCreateDraftRequest>,
) -> Result<Json<Value>, AiError> {
    let res = execute_create_draft_with_source(&state, req, EventSource::Api).await?;
    Ok(Json(project_fields(res, query.fields.as_deref())?))
}

async fn send_draft_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<FieldsQuery>,
    body: Bytes,
) -> Result<Response, AiError> {
    let req: AiSendDraftRequest = parse_optional_json(&body)?;
    let res = execute_send_draft_with_source(&state, &id, req, EventSource::Api).await?;
    let status = if res.get("status").and_then(Value::as_str) == Some("pending_approval") {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    let projected = project_fields(res, query.fields.as_deref())?;
    Ok((status, Json(projected)).into_response())
}

async fn delete_draft_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AiError> {
    validate_resource_id(&id)?;
    let deleted = state.store.delete_draft(&id).await?;
    if !deleted {
        return Err(AppError::NotFound(format!("Draft '{id}' not found")).into());
    }
    Ok(Json(json!({ "deleted": true, "draft_id": id })))
}

async fn list_labels(
    State(state): State<AppState>,
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
    State(state): State<AppState>,
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
            q: params.q,
            labels,
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
    State(state): State<AppState>,
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
    let replay_events: Vec<Result<Event, Infallible>> = if let Some(since) = since_id {
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
                Some(Ok(Event::default()
                    .id(env.id.to_string())
                    .event(env.event.event_type())
                    .data(data)))
            })
            .collect()
    } else {
        Vec::new()
    };

    let live_stream = BroadcastStream::new(rx).filter_map(move |item| {
        let env = match item {
            Ok(env) => env,
            Err(_) => return std::future::ready(None),
        };
        if env.id <= last_replayed_id {
            return std::future::ready(None);
        }
        if !event_matches_filter(&env, &types, label.as_deref(), thread_id.as_deref()) {
            return std::future::ready(None);
        }
        let Ok(data) = serde_json::to_string(&env) else {
            return std::future::ready(None);
        };
        let event = Event::default()
            .id(env.id.to_string())
            .event(env.event.event_type())
            .data(data);
        std::future::ready(Some(Ok(event)))
    });

    let combined = stream::iter(replay_events).chain(live_stream);

    Ok(Sse::new(combined).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

async fn sync_gmail_handler(
    State(state): State<AppState>,
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
    State(state): State<AppState>,
    Query(query): Query<FieldsQuery>,
) -> Result<Json<Value>, AiError> {
    let status = sync::get_sync_status(&state).await?;
    let value = serde_json::to_value(status).map_err(AppError::from)?;
    Ok(Json(project_fields(value, query.fields.as_deref())?))
}
