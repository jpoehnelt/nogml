//! Gmail REST API v1 routes, upload endpoints, HTTP batching (`/batch/gmail/v1`),
//! partial response `?fields=` filtering, push `watch`/`stop`, and `settings/*`.
//!
//! Owned by the `gmail-api` worker.

pub mod batch;
pub mod compat;
pub mod fields;
pub mod query;
pub mod settings;
pub mod upload;
pub mod watch;

pub use watch::run_watch_webhook_listener;

use std::collections::{BTreeMap, HashMap};

use axum::{
    Extension, Json, Router,
    body::{Body, Bytes},
    extract::{Path, RawQuery},
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use chrono::{Duration, Utc};

use crate::{
    AppState, MailboxState,
    ai::safety::{OutboundCheck, OutboundDecision},
    auth::{Principal, resolve_user_id, validate_email_header, validate_resource_id},
    blob::is_external_blob_store,
    error::{AppError, AppResult},
    events::{EventSource, MailEvent},
    filter::{FilterDecision, InboundMessage, apply_filter_labels},
    gmail::{
        fields::fields_and_alt_middleware,
        query::QueryParams,
        upload::{
            NewResumableUpload, ResumableChunkOutcome, ResumableEndpoint, ResumableUploadMetadata,
            ResumableUploadSession, ResumableUploadTarget, build_resumable_location,
            extract_draft_upload, extract_message_upload, extract_resumable_draft_metadata,
            extract_resumable_message_metadata, extract_upload_content_type, is_resumable_upload,
            parse_upload_content_length,
        },
    },
    mime,
    models::{
        BatchDeleteMessagesRequest, BatchModifyMessagesRequest, Draft, DraftRef, HistoryLabelAdded,
        HistoryLabelRemoved, HistoryMessageAdded, HistoryMessageDeleted, HistoryRecord,
        LABEL_DRAFT, LABEL_INBOX, LABEL_SENT, LABEL_SPAM, LABEL_TRASH, LABEL_UNREAD, Label,
        ListDraftsResponse, ListHistoryResponse, ListLabelsResponse, ListMessagesResponse,
        ListThreadsResponse, Message, MessageFormat, MessagePartBody, MessageRef,
        ModifyMessageRequest, ModifyThreadRequest, Profile, Thread, ThreadRef, WatchRequest,
        WatchResponse,
    },
    storage::{
        HistoryEventKind, NewLabelInput, NewMessageInput, StoredDraft, StoredLabel, StoredMessage,
        StoredThreadDetail, UpdateLabelInput, WatchSubscription,
    },
    transport::{OutboundAttachment, OutboundMessage},
};

/// Build the Gmail API routes under `/gmail/v1/...` and `/upload/gmail/v1/...`
/// with `?fields=` partial response and `alt=json` middleware applied.
///
/// Used both by [`gmail_router`] and internally by [`batch::batch_handler`] so
/// sub-requests inherit `?fields=` handling without permitting recursive `/batch/` calls.
pub(crate) fn gmail_api_routes() -> Router<AppState> {
    Router::new()
        // Profile
        .route("/gmail/v1/users/{userId}/profile", get(get_profile))
        // Messages
        .route(
            "/gmail/v1/users/{userId}/messages",
            get(list_messages).post(insert_message),
        )
        .route(
            "/upload/gmail/v1/users/{userId}/messages",
            post(insert_message)
                .put(insert_message_resumable_put)
                .delete(insert_message_resumable_delete),
        )
        .route("/gmail/v1/users/{userId}/messages/send", post(send_message))
        .route(
            "/upload/gmail/v1/users/{userId}/messages/send",
            post(send_message)
                .put(send_message_resumable_put)
                .delete(send_message_resumable_delete),
        )
        .route(
            "/gmail/v1/users/{userId}/messages/import",
            post(import_message),
        )
        .route(
            "/upload/gmail/v1/users/{userId}/messages/import",
            post(import_message)
                .put(import_message_resumable_put)
                .delete(import_message_resumable_delete),
        )
        .route(
            "/gmail/v1/users/{userId}/messages/batchModify",
            post(batch_modify_messages),
        )
        .route(
            "/gmail/v1/users/{userId}/messages/batchDelete",
            post(batch_delete_messages),
        )
        .route(
            "/gmail/v1/users/{userId}/messages/{id}",
            get(get_message).delete(delete_message),
        )
        .route(
            "/gmail/v1/users/{userId}/messages/{id}/modify",
            post(modify_message),
        )
        .route(
            "/gmail/v1/users/{userId}/messages/{id}/trash",
            post(trash_message),
        )
        .route(
            "/gmail/v1/users/{userId}/messages/{id}/untrash",
            post(untrash_message),
        )
        .route(
            "/gmail/v1/users/{userId}/messages/{messageId}/attachments/{id}",
            get(get_attachment),
        )
        // Threads
        .route("/gmail/v1/users/{userId}/threads", get(list_threads))
        .route(
            "/gmail/v1/users/{userId}/threads/{id}",
            get(get_thread).delete(delete_thread),
        )
        .route(
            "/gmail/v1/users/{userId}/threads/{id}/modify",
            post(modify_thread),
        )
        .route(
            "/gmail/v1/users/{userId}/threads/{id}/trash",
            post(trash_thread),
        )
        .route(
            "/gmail/v1/users/{userId}/threads/{id}/untrash",
            post(untrash_thread),
        )
        // Labels
        .route(
            "/gmail/v1/users/{userId}/labels",
            get(list_labels).post(create_label),
        )
        .route(
            "/gmail/v1/users/{userId}/labels/{id}",
            get(get_label)
                .put(update_label)
                .patch(patch_label)
                .delete(delete_label),
        )
        // Drafts
        .route(
            "/gmail/v1/users/{userId}/drafts",
            get(list_drafts).post(create_draft),
        )
        .route(
            "/upload/gmail/v1/users/{userId}/drafts",
            post(create_draft)
                .put(create_draft_resumable_put)
                .delete(create_draft_resumable_delete),
        )
        .route("/gmail/v1/users/{userId}/drafts/send", post(send_draft))
        .route(
            "/upload/gmail/v1/users/{userId}/drafts/send",
            post(send_draft)
                .put(send_draft_resumable_put)
                .delete(send_draft_resumable_delete),
        )
        .route(
            "/gmail/v1/users/{userId}/drafts/{id}",
            get(get_draft).put(update_draft).delete(delete_draft),
        )
        .route(
            "/upload/gmail/v1/users/{userId}/drafts/{id}",
            put(update_draft).delete(update_draft_resumable_delete),
        )
        // History
        .route("/gmail/v1/users/{userId}/history", get(list_history))
        // Watch / Stop
        .route("/gmail/v1/users/{userId}/watch", post(watch_mailbox))
        .route("/gmail/v1/users/{userId}/stop", post(stop_watch))
        // Settings
        .route(
            "/gmail/v1/users/{userId}/settings/sendAs",
            get(settings::list_send_as).post(settings::create_send_as),
        )
        .route(
            "/gmail/v1/users/{userId}/settings/sendAs/{sendAsEmail}",
            get(settings::get_send_as)
                .put(settings::update_send_as)
                .patch(settings::patch_send_as)
                .delete(settings::delete_send_as),
        )
        .route(
            "/gmail/v1/users/{userId}/settings/vacation",
            get(settings::get_vacation).put(settings::update_vacation),
        )
        .route(
            "/gmail/v1/users/{userId}/settings/autoForwarding",
            get(settings::get_auto_forwarding).put(settings::update_auto_forwarding),
        )
        .route(
            "/gmail/v1/users/{userId}/settings/imap",
            get(settings::get_imap).put(settings::update_imap),
        )
        .route(
            "/gmail/v1/users/{userId}/settings/pop",
            get(settings::get_pop).put(settings::update_pop),
        )
        // Google OAuth2 userinfo & People API client compatibility endpoints
        .route("/oauth2/v2/userinfo", get(compat::get_userinfo_v2))
        .route("/oauth2/v3/userinfo", get(compat::get_userinfo_v3))
        .route("/v1/people/me", get(compat::get_people_me))
        .layer(middleware::from_fn(fields_and_alt_middleware))
}

/// Build the full Gmail REST API v1 router covering `/gmail/v1/...`, `/upload/gmail/v1/...`,
/// and `/batch/gmail/v1`.
pub fn gmail_router() -> Router<AppState> {
    gmail_api_routes().route("/batch/gmail/v1", post(batch::batch_handler))
}

// ============================================================================
// Message / Label Projection Helpers
// ============================================================================

/// Project a [`StoredMessage`] into a Gmail API [`Message`] according to `format` and `metadata_headers`.
pub fn format_gmail_message(
    stored: &StoredMessage,
    format: MessageFormat,
    metadata_headers: &[String],
) -> AppResult<Message> {
    format_gmail_message_with_attachments(stored, format, metadata_headers, &HashMap::new())
}

fn format_gmail_message_with_attachments(
    stored: &StoredMessage,
    format: MessageFormat,
    metadata_headers: &[String],
    attachment_ids: &HashMap<String, String>,
) -> AppResult<Message> {
    let label_ids = (!stored.label_ids.is_empty()).then(|| stored.label_ids.clone());
    let base = Message {
        id: stored.id.clone(),
        thread_id: stored.thread_id.clone(),
        label_ids,
        snippet: Some(stored.snippet.clone()),
        history_id: Some(stored.history_id.to_string()),
        internal_date: Some(stored.internal_date_ms.to_string()),
        payload: None,
        size_estimate: Some(stored.size_estimate),
        raw: None,
    };

    match format {
        MessageFormat::Minimal => Ok(base),
        MessageFormat::Raw => Ok(Message {
            raw: Some(mime::encode_base64url(&stored.raw_rfc2822)),
            ..base
        }),
        MessageFormat::Metadata => {
            let payload = mime::build_gmail_payload(
                &stored.raw_rfc2822,
                MessageFormat::Metadata,
                metadata_headers,
                attachment_ids,
            )?;
            Ok(Message { payload, ..base })
        }
        MessageFormat::Full => {
            let payload = mime::build_gmail_payload(
                &stored.raw_rfc2822,
                MessageFormat::Full,
                metadata_headers,
                attachment_ids,
            )?;
            Ok(Message { payload, ..base })
        }
    }
}

async fn load_attachment_id_map(
    state: &AppState,
    stored: &StoredMessage,
    format: MessageFormat,
) -> AppResult<HashMap<String, String>> {
    let mut map = HashMap::new();
    if format != MessageFormat::Full || !stored.has_attachments {
        return Ok(map);
    }

    let metas = state.store.list_attachment_meta(&stored.id).await?;
    for meta in metas {
        if let Some(ref part_id) = meta.part_id
            && !part_id.is_empty()
        {
            map.insert(part_id.clone(), meta.id.clone());
        }
        if let Some(ref fname) = meta.filename
            && !fname.is_empty()
        {
            map.entry(fname.clone()).or_insert(meta.id);
        }
    }
    Ok(map)
}

async fn format_gmail_message_from_store(
    state: &AppState,
    stored: &StoredMessage,
    format: MessageFormat,
    metadata_headers: &[String],
) -> AppResult<Message> {
    let att_map = load_attachment_id_map(state, stored, format).await?;
    if format != MessageFormat::Minimal && is_external_blob_store(state.blobs.as_ref()) {
        let mut hydrated = stored.clone();
        hydrated.raw_rfc2822 = state.load_raw_rfc2822(stored).await?;
        return format_gmail_message_with_attachments(
            &hydrated,
            format,
            metadata_headers,
            &att_map,
        );
    }
    format_gmail_message_with_attachments(stored, format, metadata_headers, &att_map)
}

fn stored_label_to_api(label: StoredLabel, include_counts: bool) -> Label {
    Label {
        id: label.id,
        name: label.name,
        message_list_visibility: label.message_list_visibility,
        label_list_visibility: label.label_list_visibility,
        label_type: Some(label.label_type),
        messages_total: include_counts.then_some(label.messages_total),
        messages_unread: include_counts.then_some(label.messages_unread),
        threads_total: include_counts.then_some(label.threads_total),
        threads_unread: include_counts.then_some(label.threads_unread),
        color: label.color,
    }
}

async fn format_thread_detail(
    state: &AppState,
    detail: StoredThreadDetail,
    format: MessageFormat,
    metadata_headers: &[String],
) -> AppResult<Thread> {
    let mut messages = Vec::with_capacity(detail.messages.len());
    for m in &detail.messages {
        messages.push(format_gmail_message_from_store(state, m, format, metadata_headers).await?);
    }
    Ok(Thread {
        id: detail.id,
        snippet: Some(detail.snippet),
        history_id: Some(detail.history_id.to_string()),
        messages: Some(messages),
    })
}

fn validate_parsed_headers(parsed: &mime::ParsedEmail) -> AppResult<()> {
    validate_email_header("From", &parsed.from)?;
    validate_email_header("Subject", &parsed.subject)?;
    for addr in &parsed.to {
        validate_email_header("To", addr)?;
    }
    for addr in &parsed.cc {
        validate_email_header("Cc", addr)?;
    }
    for addr in &parsed.bcc {
        validate_email_header("Bcc", addr)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_new_message_input(
    parsed: &mime::ParsedEmail,
    raw_bytes: Vec<u8>,
    thread_id: Option<String>,
    label_ids: Vec<String>,
    internal_date_ms: i64,
    resend_id: Option<String>,
    is_deleted: bool,
    source: &str,
) -> NewMessageInput {
    NewMessageInput {
        id: None,
        thread_id: thread_id.filter(|s| !s.trim().is_empty()),
        label_ids,
        raw_rfc2822: raw_bytes,
        snippet: parsed.snippet.clone(),
        internal_date_ms,
        subject: parsed.subject.clone(),
        from_addr: parsed.from.clone(),
        to_addrs: parsed.to.clone(),
        cc_addrs: parsed.cc.clone(),
        bcc_addrs: parsed.bcc.clone(),
        text_body: parsed.text_body.clone(),
        html_body: parsed.html_body.clone(),
        rfc822_message_id: parsed.rfc822_message_id.clone(),
        in_reply_to: parsed.in_reply_to.clone(),
        references_header: parsed.references_header.clone(),
        resend_id,
        upstream_gmail_id: None,
        upstream_thread_id: None,
        source: source.to_string(),
        is_answered: false,
        is_deleted,
        attachments: parsed.attachments.clone(),
    }
}

fn validate_label_ids(ids: &[String]) -> AppResult<()> {
    for lid in ids {
        validate_resource_id(lid)?;
    }
    Ok(())
}

fn dedup_labels(labels: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out = Vec::new();
    for label in labels {
        if !label.is_empty() && !out.contains(&label) {
            out.push(label);
        }
    }
    out
}

fn idempotency_key_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn parsed_to_outbound_message(
    parsed: &mime::ParsedEmail,
    default_from: &str,
    raw_rfc2822: &[u8],
    idempotency_key: Option<&str>,
) -> AppResult<OutboundMessage> {
    let from = if !parsed.from.trim().is_empty() {
        parsed.from.trim().to_string()
    } else if !default_from.trim().is_empty() {
        default_from.trim().to_string()
    } else {
        return Err(AppError::validation(
            "Missing sender address in From header and no default_from configured",
            Some("Provide a From header or configure NOGML_USER_EMAIL.".to_string()),
        ));
    };

    if parsed.to.is_empty() {
        return Err(AppError::validation(
            "Missing recipient in To header",
            Some("Provide at least one recipient in the To header.".to_string()),
        ));
    }

    let mut headers = HashMap::new();
    for h in &parsed.headers {
        let lower = h.name.to_ascii_lowercase();
        if lower.starts_with("x-")
            || lower.starts_with("list-")
            || lower == "auto-submitted"
            || lower == "precedence"
        {
            headers.insert(h.name.clone(), h.value.clone());
        }
    }
    if let Some(ref irt) = parsed.in_reply_to
        && !irt.trim().is_empty()
    {
        headers.insert("In-Reply-To".to_string(), irt.clone());
    }
    if let Some(ref refs) = parsed.references_header
        && !refs.trim().is_empty()
    {
        headers.insert("References".to_string(), refs.clone());
    }

    let attachments: Vec<OutboundAttachment> = parsed
        .attachments
        .iter()
        .map(|att| OutboundAttachment {
            filename: att
                .filename
                .clone()
                .or_else(|| Some("attachment".to_string())),
            content_type: if att.content_type.trim().is_empty() {
                "application/octet-stream".to_string()
            } else {
                att.content_type.clone()
            },
            content_id: att.content_id.clone(),
            data: att.data.clone(),
        })
        .collect();

    let text = if !parsed.text_body.is_empty() {
        Some(parsed.text_body.clone())
    } else if parsed.html_body.is_none() {
        Some(String::new())
    } else {
        None
    };

    Ok(OutboundMessage {
        from,
        to: parsed.to.clone(),
        cc: parsed.cc.clone(),
        bcc: parsed.bcc.clone(),
        reply_to: parsed.reply_to.clone(),
        subject: parsed.subject.clone(),
        text,
        html: parsed.html_body.clone(),
        headers,
        attachments,
        raw_rfc2822: raw_rfc2822.to_vec(),
        idempotency_key: idempotency_key.map(str::to_string),
        scheduled_at: None,
        tags: HashMap::new(),
    })
}

/// Shared outbound send helper used by `messages.send` and `drafts.send`.
#[allow(clippy::too_many_arguments)]
async fn execute_gmail_send(
    state: &AppState,
    raw_bytes: Vec<u8>,
    thread_id: Option<String>,
    extra_labels: Vec<String>,
    idempotency_key: Option<&str>,
    principal: Option<&Principal>,
    is_draft_send: bool,
) -> AppResult<StoredMessage> {
    if raw_bytes.is_empty() {
        return Err(AppError::BadRequest(
            "Message payload is empty; provide base64url 'raw' or media upload".to_string(),
        ));
    }

    let parsed = mime::parse_rfc2822(&raw_bytes)?;
    validate_parsed_headers(&parsed)?;

    let outbound = parsed_to_outbound_message(
        &parsed,
        &state.config.user_email,
        &raw_bytes,
        idempotency_key,
    )?;

    let agent_policy = principal.and_then(|p| p.agent_policy.clone());
    let policy_check = OutboundCheck {
        from: outbound.from.clone(),
        to: outbound.to.clone(),
        cc: outbound.cc.clone(),
        bcc: outbound.bcc.clone(),
        subject: outbound.subject.clone(),
        text: outbound.text.clone(),
        html: outbound.html.clone(),
        attachment_filenames: outbound
            .attachments
            .iter()
            .filter_map(|a| a.filename.clone())
            .collect(),
        thread_id: thread_id.clone(),
        mailbox_id: Some(state.mailbox_id().to_string()),
        is_draft_send,
        agent_policy,
    };
    let decision = state.evaluate_outbound_policy(&policy_check).await?;
    match decision {
        OutboundDecision::Allow => {}
        OutboundDecision::Deny { code, reason, hint } => {
            state
                .record_audit(
                    principal,
                    "/gmail/v1",
                    "send",
                    Vec::new(),
                    "denied",
                    Some(format!("{code}: {reason}")),
                )
                .await;
            if code == "draft_only_mode" {
                return Err(AppError::DraftOnlyBlocked {
                    hint: hint.unwrap_or(reason),
                });
            }
            return Err(AppError::PolicyDenied {
                code,
                message: reason,
                hint,
                details: None,
            });
        }
        OutboundDecision::DowngradeToDraft { .. } => {
            state
                .record_audit(
                    principal,
                    "/gmail/v1",
                    "send",
                    Vec::new(),
                    "denied",
                    Some("draft_only_mode".to_string()),
                )
                .await;
            return Err(AppError::draft_only_blocked());
        }
        OutboundDecision::HoldForApproval { reason } => {
            state
                .record_audit(
                    principal,
                    "/gmail/v1",
                    "send",
                    Vec::new(),
                    "denied",
                    Some(format!("approval_required: {reason}")),
                )
                .await;
            return Err(AppError::Forbidden(format!(
                "Outbound send held for approval: {reason}"
            )));
        }
    }

    let send_outcome = state.transport.send(&outbound, idempotency_key).await?;

    let mut labels = vec![LABEL_SENT.to_string()];
    for l in extra_labels {
        if l != LABEL_DRAFT {
            validate_resource_id(&l)?;
            labels.push(l);
        }
    }
    let labels = dedup_labels(labels);

    let input = build_new_message_input(
        &parsed,
        raw_bytes,
        thread_id,
        labels,
        Utc::now().timestamp_millis(),
        Some(send_outcome.provider_message_id.clone()),
        false,
        "local",
    );
    let stored = state.store.insert_message(input).await?;
    state.post_store_message(&stored).await?;
    state.metrics.inc_messages_sent();

    state.events.publish(
        EventSource::Api,
        MailEvent::MessageSent {
            message_id: stored.id.clone(),
            thread_id: stored.thread_id.clone(),
            to: stored.to_addrs.clone(),
            subject: stored.subject.clone(),
            resend_id: Some(send_outcome.provider_message_id),
            labels: stored.label_ids.clone(),
        },
    );

    state
        .record_audit(
            principal,
            "/gmail/v1",
            "send",
            vec![stored.id.clone(), stored.thread_id.clone()],
            "ok",
            Some(format!("to={}", stored.to_addrs.join(","))),
        )
        .await;

    Ok(stored)
}

// ============================================================================
// Profile
// ============================================================================

/// `GET /gmail/v1/users/{userId}/profile`
async fn get_profile(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
) -> AppResult<Json<Profile>> {
    let email = resolve_user_id(&user_id, &state.config)?;
    let profile = state.store.get_profile(email).await?;
    Ok(Json(profile))
}

// ============================================================================
// Messages
// ============================================================================

/// `GET /gmail/v1/users/{userId}/messages`
async fn list_messages(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(user_id): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> AppResult<Json<ListMessagesResponse>> {
    resolve_user_id(&user_id, &state.config)?;
    let params = QueryParams::from_raw(raw_query.as_deref());
    let query = params.parse_message_list_query()?;
    let page = state.store.list_messages(&query).await?;

    let target_ids: Vec<String> = page.messages.iter().map(|m| m.id.clone()).collect();
    let action = if query.q.as_deref().is_some_and(|s| !s.trim().is_empty()) {
        "search"
    } else {
        "read"
    };
    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/gmail/v1",
            action,
            target_ids,
            "ok",
            query.q.clone(),
        )
        .await;

    let messages = if page.messages.is_empty() {
        None
    } else {
        Some(
            page.messages
                .into_iter()
                .map(|m| MessageRef {
                    id: m.id,
                    thread_id: m.thread_id,
                })
                .collect(),
        )
    };

    Ok(Json(ListMessagesResponse {
        messages,
        next_page_token: page.next_page_token,
        result_size_estimate: page.result_size_estimate,
    }))
}

/// `GET /gmail/v1/users/{userId}/messages/{id}`
async fn get_message(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path((user_id, id)): Path<(String, String)>,
    RawQuery(raw_query): RawQuery,
) -> AppResult<Json<Message>> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&id)?;
    let params = QueryParams::from_raw(raw_query.as_deref());
    let format = params.parse_format(MessageFormat::Full)?;
    let metadata_headers = params.metadata_headers();

    let stored = state
        .store
        .get_message(&id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Message '{id}' not found")))?;

    let msg = format_gmail_message_from_store(&state, &stored, format, &metadata_headers).await?;
    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/gmail/v1",
            "read",
            vec![id],
            "ok",
            Some("message".to_string()),
        )
        .await;
    Ok(Json(msg))
}

/// Validate optional `Message` metadata fields (`threadId`, `labelIds`) up front.
fn validate_message_metadata(metadata: &Message) -> AppResult<()> {
    if !metadata.thread_id.is_empty() {
        validate_resource_id(&metadata.thread_id)?;
    }
    if let Some(ref labels) = metadata.label_ids {
        validate_label_ids(labels)?;
    }
    Ok(())
}

/// Validate optional `Draft` metadata fields (`id`, `message.threadId`, `message.labelIds`) up front.
fn validate_draft_metadata(metadata: &Draft) -> AppResult<()> {
    if !metadata.id.trim().is_empty() {
        validate_resource_id(metadata.id.trim())?;
    }
    if let Some(ref msg) = metadata.message {
        validate_message_metadata(msg)?;
    }
    Ok(())
}

/// Shared `messages.send` completion logic used by JSON, `media`, `multipart`, and `resumable`.
async fn complete_send_message(
    state: &AppState,
    metadata: Message,
    raw_bytes: Option<Vec<u8>>,
    idempotency_key: Option<&str>,
    principal: Option<&Principal>,
) -> AppResult<Message> {
    let raw_bytes = raw_bytes.ok_or_else(|| {
        AppError::BadRequest(
            "Missing RFC 2822 message payload ('raw' field or media upload)".to_string(),
        )
    })?;

    let thread_id = (!metadata.thread_id.is_empty()).then_some(metadata.thread_id);
    if let Some(ref tid) = thread_id {
        validate_resource_id(tid)?;
    }

    let stored = execute_gmail_send(
        state,
        raw_bytes,
        thread_id,
        metadata.label_ids.unwrap_or_default(),
        idempotency_key,
        principal,
        false,
    )
    .await?;

    format_gmail_message(&stored, MessageFormat::Minimal, &[])
}

/// Shared `messages.insert` completion logic used by JSON, `media`, `multipart`, and `resumable`.
async fn complete_insert_message(
    state: &AppState,
    metadata: Message,
    raw_bytes: Option<Vec<u8>>,
    date_source: &str,
    deleted: bool,
    principal: Option<&Principal>,
) -> AppResult<Message> {
    let raw_bytes = raw_bytes.ok_or_else(|| {
        AppError::BadRequest(
            "Missing RFC 2822 message payload ('raw' field or media upload)".to_string(),
        )
    })?;

    let parsed = mime::parse_rfc2822(&raw_bytes)?;
    let now_ms = Utc::now().timestamp_millis();
    let internal_date_ms = if date_source == "dateheader" {
        parsed.date_ms.unwrap_or(now_ms)
    } else {
        now_ms
    };

    let labels = metadata.label_ids.unwrap_or_default();
    validate_label_ids(&labels)?;
    let thread_id = (!metadata.thread_id.is_empty()).then_some(metadata.thread_id);
    if let Some(ref tid) = thread_id {
        validate_resource_id(tid)?;
    }

    let input = build_new_message_input(
        &parsed,
        raw_bytes,
        thread_id,
        dedup_labels(labels),
        internal_date_ms,
        None,
        deleted,
        "local",
    );
    let stored = state.store.insert_message(input).await?;
    state.post_store_message(&stored).await?;
    state.metrics.inc_messages_received();

    state.events.publish(
        EventSource::Api,
        MailEvent::MessageReceived {
            message_id: stored.id.clone(),
            thread_id: stored.thread_id.clone(),
            from: stored.from_addr.clone(),
            subject: stored.subject.clone(),
            snippet: stored.snippet.clone(),
            labels: stored.label_ids.clone(),
        },
    );

    state
        .record_audit(
            principal,
            "/gmail/v1",
            "modify",
            vec![stored.id.clone()],
            "ok",
            Some("insert".to_string()),
        )
        .await;

    format_gmail_message(&stored, MessageFormat::Minimal, &[])
}

/// Shared `messages.import` completion logic used by JSON, `media`, `multipart`, and `resumable`.
#[allow(clippy::too_many_arguments)]
async fn complete_import_message(
    state: &AppState,
    metadata: Message,
    raw_bytes: Option<Vec<u8>>,
    date_source: &str,
    never_mark_spam: bool,
    _process_for_calendar: bool,
    deleted: bool,
    principal: Option<&Principal>,
) -> AppResult<Message> {
    let raw_bytes = raw_bytes.ok_or_else(|| {
        AppError::BadRequest(
            "Missing RFC 2822 message payload ('raw' field or media upload)".to_string(),
        )
    })?;

    let parsed = mime::parse_rfc2822(&raw_bytes)?;
    let now_ms = Utc::now().timestamp_millis();
    let internal_date_ms = if date_source == "dateheader" {
        parsed.date_ms.unwrap_or(now_ms)
    } else {
        now_ms
    };

    let initial_labels = match metadata.label_ids {
        Some(l) if !l.is_empty() => l,
        _ => vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
    };
    validate_label_ids(&initial_labels)?;

    // Evaluate pluggable InboundFilter prior to storage.
    let parsed_headers: Vec<(String, String)> = parsed
        .headers
        .iter()
        .map(|h| (h.name.clone(), h.value.clone()))
        .collect();
    let auth_results = parsed_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Authentication-Results"))
        .map(|(_, v)| v.clone());
    let inbound_msg = InboundMessage {
        raw_rfc2822: raw_bytes.clone(),
        headers: parsed_headers,
        text_body: parsed.text_body.clone(),
        html_body: parsed.html_body.clone(),
        from: parsed.from.clone(),
        to: parsed.to.clone(),
        subject: parsed.subject.clone(),
        authentication_results: auth_results,
        sender_ip: None,
        source: "gmail_import".to_string(),
        provider_id: None,
    };
    let decision = state.filter.evaluate(&inbound_msg).await?;
    state.metrics.record_filter_decision(&decision);
    if let FilterDecision::Reject { reason } = decision {
        return Err(AppError::Forbidden(format!(
            "Inbound message rejected by filter: {reason}"
        )));
    }
    let mut labels = if never_mark_spam && matches!(decision, FilterDecision::Spam { .. }) {
        initial_labels
    } else {
        apply_filter_labels(initial_labels, &decision)
    };
    if never_mark_spam {
        labels.retain(|l| l != LABEL_SPAM);
    }

    let thread_id = (!metadata.thread_id.is_empty()).then_some(metadata.thread_id);
    if let Some(ref tid) = thread_id {
        validate_resource_id(tid)?;
    }

    let input = build_new_message_input(
        &parsed,
        raw_bytes,
        thread_id,
        dedup_labels(labels),
        internal_date_ms,
        None,
        deleted,
        "local",
    );
    let stored = state.store.insert_message(input).await?;
    state.post_store_message(&stored).await?;
    state.metrics.inc_messages_received();

    state.events.publish(
        EventSource::Api,
        MailEvent::MessageReceived {
            message_id: stored.id.clone(),
            thread_id: stored.thread_id.clone(),
            from: stored.from_addr.clone(),
            subject: stored.subject.clone(),
            snippet: stored.snippet.clone(),
            labels: stored.label_ids.clone(),
        },
    );

    state
        .record_audit(
            principal,
            "/gmail/v1",
            "modify",
            vec![stored.id.clone()],
            "ok",
            Some("import".to_string()),
        )
        .await;

    format_gmail_message(&stored, MessageFormat::Minimal, &[])
}

/// Initiate an `uploadType=resumable` session, returning `200 OK` with a `Location` URL.
fn initiate_resumable_upload(
    state: &AppState,
    user_email: &str,
    target: ResumableUploadTarget,
    metadata: ResumableUploadMetadata,
    uri: &Uri,
    params: &QueryParams,
    headers: &HeaderMap,
) -> AppResult<Response> {
    let declared_total_bytes = parse_upload_content_length(headers, state.config.max_body_bytes)?;
    let content_type = extract_upload_content_type(headers);
    let idempotency_key = idempotency_key_header(headers).map(str::to_string);

    let upload_id = state.resumable_uploads.create_session(NewResumableUpload {
        user_email: user_email.to_string(),
        target,
        metadata,
        content_type,
        declared_total_bytes,
        idempotency_key,
    })?;

    let location = build_resumable_location(headers, uri, &upload_id, params.get("fields"))?;
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(header::LOCATION, location);
    if let Ok(uid_hdr) = HeaderValue::from_str(&upload_id) {
        resp.headers_mut().insert("x-guploader-uploadid", uid_hdr);
    }
    Ok(resp)
}

/// Build a `308 Resume Incomplete` response without a `Location` header.
fn build_resumable_incomplete_response(received: usize) -> AppResult<Response> {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::PERMANENT_REDIRECT;
    if received > 0 {
        let range_val = HeaderValue::from_str(&format!("bytes=0-{}", received - 1))
            .map_err(|e| AppError::Internal(format!("Invalid Range header: {e}")))?;
        resp.headers_mut().insert(header::RANGE, range_val);
    }
    Ok(resp)
}

/// Execute the Gmail API action for a completed resumable upload session.
async fn execute_completed_resumable(
    state: &AppState,
    session: ResumableUploadSession,
    headers: &HeaderMap,
    principal: Option<&Principal>,
) -> AppResult<Response> {
    let idempotency_key = session
        .idempotency_key
        .as_deref()
        .or_else(|| idempotency_key_header(headers));

    match (session.target, session.metadata) {
        (ResumableUploadTarget::MessagesSend, ResumableUploadMetadata::Message(metadata)) => {
            let raw_bytes = resolve_resumable_message_bytes(session.buffer, &metadata)?;
            let msg = complete_send_message(state, metadata, raw_bytes, idempotency_key, principal)
                .await?;
            Ok(Json(msg).into_response())
        }
        (
            ResumableUploadTarget::MessagesInsert {
                date_source,
                deleted,
            },
            ResumableUploadMetadata::Message(metadata),
        ) => {
            let raw_bytes = resolve_resumable_message_bytes(session.buffer, &metadata)?;
            let msg = complete_insert_message(
                state,
                metadata,
                raw_bytes,
                &date_source,
                deleted,
                principal,
            )
            .await?;
            Ok(Json(msg).into_response())
        }
        (
            ResumableUploadTarget::MessagesImport {
                date_source,
                never_mark_spam,
                process_for_calendar,
                deleted,
            },
            ResumableUploadMetadata::Message(metadata),
        ) => {
            let raw_bytes = resolve_resumable_message_bytes(session.buffer, &metadata)?;
            let msg = complete_import_message(
                state,
                metadata,
                raw_bytes,
                &date_source,
                never_mark_spam,
                process_for_calendar,
                deleted,
                principal,
            )
            .await?;
            Ok(Json(msg).into_response())
        }
        (ResumableUploadTarget::DraftsCreate, ResumableUploadMetadata::Draft(metadata)) => {
            let raw_bytes = resolve_resumable_draft_bytes(session.buffer, &metadata)?;
            let draft = complete_create_draft(state, metadata, raw_bytes, principal).await?;
            Ok(Json(draft).into_response())
        }
        (
            ResumableUploadTarget::DraftsUpdate { draft_id },
            ResumableUploadMetadata::Draft(metadata),
        ) => {
            let raw_bytes = resolve_resumable_draft_bytes(session.buffer, &metadata)?;
            let draft =
                complete_update_draft(state, &draft_id, metadata, raw_bytes, principal).await?;
            Ok(Json(draft).into_response())
        }
        (ResumableUploadTarget::DraftsSend, ResumableUploadMetadata::Draft(metadata)) => {
            let raw_bytes = resolve_resumable_draft_bytes(session.buffer, &metadata)?;
            let msg =
                complete_send_draft(state, metadata, raw_bytes, idempotency_key, principal).await?;
            Ok(Json(msg).into_response())
        }
        _ => Err(AppError::Internal(
            "Mismatched resumable upload session target and metadata".to_string(),
        )),
    }
}

fn resolve_resumable_message_bytes(
    buffer: Vec<u8>,
    metadata: &Message,
) -> AppResult<Option<Vec<u8>>> {
    if !buffer.is_empty() {
        return Ok(Some(buffer));
    }
    match metadata.raw.as_deref() {
        Some(raw) if !raw.trim().is_empty() => Ok(Some(mime::decode_base64url(raw)?)),
        _ => Ok(None),
    }
}

fn resolve_resumable_draft_bytes(buffer: Vec<u8>, metadata: &Draft) -> AppResult<Option<Vec<u8>>> {
    if !buffer.is_empty() {
        return Ok(Some(buffer));
    }
    match metadata.message.as_ref().and_then(|m| m.raw.as_deref()) {
        Some(raw) if !raw.trim().is_empty() => Ok(Some(mime::decode_base64url(raw)?)),
        _ => Ok(None),
    }
}

/// Handle a `PUT` chunk upload or `Content-Range: bytes */*` status query for an active session.
async fn handle_resumable_chunk(
    state: &AppState,
    user_id: &str,
    expected_endpoint: ResumableEndpoint,
    raw_query: Option<&str>,
    headers: &HeaderMap,
    body: Bytes,
    principal: Option<&Principal>,
) -> AppResult<Response> {
    let user_email = resolve_user_id(user_id, &state.config)?;
    let params = QueryParams::from_raw(raw_query);

    if let Some(upload_type) = params.get("uploadType")
        && !upload_type.eq_ignore_ascii_case("resumable")
    {
        return Err(AppError::BadRequest(format!(
            "Unsupported uploadType '{upload_type}' on resumable upload PUT"
        )));
    }

    let upload_id = params
        .get("upload_id")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::BadRequest(
                "Missing required 'upload_id' query parameter for resumable upload".to_string(),
            )
        })?;
    validate_resource_id(upload_id)?;

    let content_range = headers
        .get(header::CONTENT_RANGE)
        .map(|v| {
            v.to_str()
                .map_err(|_| AppError::BadRequest("Invalid Content-Range header".to_string()))
        })
        .transpose()?;

    match state.resumable_uploads.process_chunk(
        upload_id,
        user_email,
        &expected_endpoint,
        content_range,
        &body,
        state.config.max_body_bytes,
    )? {
        ResumableChunkOutcome::Incomplete { received } => {
            build_resumable_incomplete_response(received)
        }
        ResumableChunkOutcome::Complete(session) => {
            execute_completed_resumable(state, *session, headers, principal).await
        }
    }
}

/// Handle `DELETE` cancellation of an in-flight resumable upload session.
async fn handle_resumable_cancel(
    state: &AppState,
    user_id: &str,
    expected_endpoint: ResumableEndpoint,
    raw_query: Option<&str>,
) -> AppResult<StatusCode> {
    let user_email = resolve_user_id(user_id, &state.config)?;
    let params = QueryParams::from_raw(raw_query);
    let upload_id = params
        .get("upload_id")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::BadRequest(
                "Missing required 'upload_id' query parameter for resumable upload cancellation"
                    .to_string(),
            )
        })?;
    validate_resource_id(upload_id)?;

    let removed =
        state
            .resumable_uploads
            .cancel_session(upload_id, user_email, &expected_endpoint)?;
    if !removed {
        return Err(AppError::NotFound(format!(
            "Resumable upload session '{upload_id}' not found or expired"
        )));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn send_message_resumable_put(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(user_id): Path<String>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    handle_resumable_chunk(
        &state,
        &user_id,
        ResumableEndpoint::MessagesSend,
        raw_query.as_deref(),
        &headers,
        body,
        principal.as_ref().map(|Extension(p)| p),
    )
    .await
}

async fn send_message_resumable_delete(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> AppResult<StatusCode> {
    handle_resumable_cancel(
        &state,
        &user_id,
        ResumableEndpoint::MessagesSend,
        raw_query.as_deref(),
    )
    .await
}

async fn insert_message_resumable_put(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(user_id): Path<String>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    handle_resumable_chunk(
        &state,
        &user_id,
        ResumableEndpoint::MessagesInsert,
        raw_query.as_deref(),
        &headers,
        body,
        principal.as_ref().map(|Extension(p)| p),
    )
    .await
}

async fn insert_message_resumable_delete(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> AppResult<StatusCode> {
    handle_resumable_cancel(
        &state,
        &user_id,
        ResumableEndpoint::MessagesInsert,
        raw_query.as_deref(),
    )
    .await
}

async fn import_message_resumable_put(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(user_id): Path<String>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    handle_resumable_chunk(
        &state,
        &user_id,
        ResumableEndpoint::MessagesImport,
        raw_query.as_deref(),
        &headers,
        body,
        principal.as_ref().map(|Extension(p)| p),
    )
    .await
}

async fn import_message_resumable_delete(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> AppResult<StatusCode> {
    handle_resumable_cancel(
        &state,
        &user_id,
        ResumableEndpoint::MessagesImport,
        raw_query.as_deref(),
    )
    .await
}

async fn create_draft_resumable_put(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(user_id): Path<String>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    handle_resumable_chunk(
        &state,
        &user_id,
        ResumableEndpoint::DraftsCreate,
        raw_query.as_deref(),
        &headers,
        body,
        principal.as_ref().map(|Extension(p)| p),
    )
    .await
}

async fn create_draft_resumable_delete(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> AppResult<StatusCode> {
    handle_resumable_cancel(
        &state,
        &user_id,
        ResumableEndpoint::DraftsCreate,
        raw_query.as_deref(),
    )
    .await
}

async fn send_draft_resumable_put(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(user_id): Path<String>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    handle_resumable_chunk(
        &state,
        &user_id,
        ResumableEndpoint::DraftsSend,
        raw_query.as_deref(),
        &headers,
        body,
        principal.as_ref().map(|Extension(p)| p),
    )
    .await
}

async fn send_draft_resumable_delete(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> AppResult<StatusCode> {
    handle_resumable_cancel(
        &state,
        &user_id,
        ResumableEndpoint::DraftsSend,
        raw_query.as_deref(),
    )
    .await
}

async fn update_draft_resumable_delete(
    MailboxState(state): MailboxState,
    Path((user_id, id)): Path<(String, String)>,
    RawQuery(raw_query): RawQuery,
) -> AppResult<StatusCode> {
    validate_resource_id(&id)?;
    handle_resumable_cancel(
        &state,
        &user_id,
        ResumableEndpoint::DraftsUpdate(id),
        raw_query.as_deref(),
    )
    .await
}

/// `POST /gmail/v1/users/{userId}/messages/send` & `/upload/gmail/v1/users/{userId}/messages/send`
async fn send_message(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(user_id): Path<String>,
    uri: Uri,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let user_email = resolve_user_id(&user_id, &state.config)?;
    let params = QueryParams::from_raw(raw_query.as_deref());
    if is_resumable_upload(&params) {
        let metadata = extract_resumable_message_metadata(&body)?;
        validate_message_metadata(&metadata)?;
        return initiate_resumable_upload(
            &state,
            user_email,
            ResumableUploadTarget::MessagesSend,
            ResumableUploadMetadata::Message(metadata),
            &uri,
            &params,
            &headers,
        );
    }

    let extracted = extract_message_upload(&headers, &params, &body)?;
    let msg = complete_send_message(
        &state,
        extracted.metadata,
        extracted.raw_bytes,
        idempotency_key_header(&headers),
        principal.as_ref().map(|Extension(p)| p),
    )
    .await?;
    Ok(Json(msg).into_response())
}

/// `POST /gmail/v1/users/{userId}/messages` & `/upload/gmail/v1/users/{userId}/messages` (`insert`)
async fn insert_message(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(user_id): Path<String>,
    uri: Uri,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let user_email = resolve_user_id(&user_id, &state.config)?;
    let params = QueryParams::from_raw(raw_query.as_deref());
    let date_source = params
        .get("internalDateSource")
        .unwrap_or("receivedTime")
        .to_ascii_lowercase();
    if date_source != "receivedtime" && date_source != "dateheader" {
        return Err(AppError::BadRequest(format!(
            "Invalid internalDateSource '{date_source}'; expected receivedTime or dateHeader"
        )));
    }
    let deleted = params.get_bool("deleted", false)?;

    if is_resumable_upload(&params) {
        let metadata = extract_resumable_message_metadata(&body)?;
        validate_message_metadata(&metadata)?;
        return initiate_resumable_upload(
            &state,
            user_email,
            ResumableUploadTarget::MessagesInsert {
                date_source,
                deleted,
            },
            ResumableUploadMetadata::Message(metadata),
            &uri,
            &params,
            &headers,
        );
    }

    let extracted = extract_message_upload(&headers, &params, &body)?;
    let msg = complete_insert_message(
        &state,
        extracted.metadata,
        extracted.raw_bytes,
        &date_source,
        deleted,
        principal.as_ref().map(|Extension(p)| p),
    )
    .await?;
    Ok(Json(msg).into_response())
}

/// `POST /gmail/v1/users/{userId}/messages/import` & `/upload/gmail/v1/users/{userId}/messages/import`
async fn import_message(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(user_id): Path<String>,
    uri: Uri,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let user_email = resolve_user_id(&user_id, &state.config)?;
    let params = QueryParams::from_raw(raw_query.as_deref());
    let date_source = params
        .get("internalDateSource")
        .unwrap_or("dateHeader")
        .to_ascii_lowercase();
    if date_source != "receivedtime" && date_source != "dateheader" {
        return Err(AppError::BadRequest(format!(
            "Invalid internalDateSource '{date_source}'; expected dateHeader or receivedTime"
        )));
    }
    let never_mark_spam = params.get_bool("neverMarkSpam", false)?;
    let process_for_calendar = params.get_bool("processForCalendar", false)?;
    let deleted = params.get_bool("deleted", false)?;

    if is_resumable_upload(&params) {
        let metadata = extract_resumable_message_metadata(&body)?;
        validate_message_metadata(&metadata)?;
        return initiate_resumable_upload(
            &state,
            user_email,
            ResumableUploadTarget::MessagesImport {
                date_source,
                never_mark_spam,
                process_for_calendar,
                deleted,
            },
            ResumableUploadMetadata::Message(metadata),
            &uri,
            &params,
            &headers,
        );
    }

    let extracted = extract_message_upload(&headers, &params, &body)?;
    let msg = complete_import_message(
        &state,
        extracted.metadata,
        extracted.raw_bytes,
        &date_source,
        never_mark_spam,
        process_for_calendar,
        deleted,
        principal.as_ref().map(|Extension(p)| p),
    )
    .await?;
    Ok(Json(msg).into_response())
}

/// `POST /gmail/v1/users/{userId}/messages/{id}/modify`
async fn modify_message(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path((user_id, id)): Path<(String, String)>,
    Json(req): Json<ModifyMessageRequest>,
) -> AppResult<Json<Message>> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&id)?;
    validate_label_ids(&req.add_label_ids)?;
    validate_label_ids(&req.remove_label_ids)?;

    let stored = state
        .store
        .modify_message_labels(&id, &req.add_label_ids, &req.remove_label_ids)
        .await?;

    state.events.publish(
        EventSource::Api,
        MailEvent::MessageUpdated {
            message_id: stored.id.clone(),
            thread_id: stored.thread_id.clone(),
            added_labels: req.add_label_ids.clone(),
            removed_labels: req.remove_label_ids.clone(),
        },
    );

    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/gmail/v1",
            "modify",
            vec![stored.id.clone()],
            "ok",
            Some(format!(
                "add=[{}] remove=[{}]",
                req.add_label_ids.join(","),
                req.remove_label_ids.join(",")
            )),
        )
        .await;

    let msg = format_gmail_message(&stored, MessageFormat::Minimal, &[])?;
    Ok(Json(msg))
}

/// `POST /gmail/v1/users/{userId}/messages/{id}/trash`
async fn trash_message(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path((user_id, id)): Path<(String, String)>,
) -> AppResult<Json<Message>> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&id)?;

    let stored = state.store.trash_message(&id).await?;
    state.events.publish(
        EventSource::Api,
        MailEvent::MessageUpdated {
            message_id: stored.id.clone(),
            thread_id: stored.thread_id.clone(),
            added_labels: vec![LABEL_TRASH.to_string()],
            removed_labels: vec![LABEL_INBOX.to_string()],
        },
    );

    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/gmail/v1",
            "modify",
            vec![stored.id.clone()],
            "ok",
            Some("trash".to_string()),
        )
        .await;

    let msg = format_gmail_message(&stored, MessageFormat::Minimal, &[])?;
    Ok(Json(msg))
}

/// `POST /gmail/v1/users/{userId}/messages/{id}/untrash`
async fn untrash_message(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path((user_id, id)): Path<(String, String)>,
) -> AppResult<Json<Message>> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&id)?;

    let stored = state.store.untrash_message(&id).await?;
    state.events.publish(
        EventSource::Api,
        MailEvent::MessageUpdated {
            message_id: stored.id.clone(),
            thread_id: stored.thread_id.clone(),
            added_labels: Vec::new(),
            removed_labels: vec![LABEL_TRASH.to_string()],
        },
    );

    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/gmail/v1",
            "modify",
            vec![stored.id.clone()],
            "ok",
            Some("untrash".to_string()),
        )
        .await;

    let msg = format_gmail_message(&stored, MessageFormat::Minimal, &[])?;
    Ok(Json(msg))
}

/// `DELETE /gmail/v1/users/{userId}/messages/{id}`
async fn delete_message(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path((user_id, id)): Path<(String, String)>,
) -> AppResult<StatusCode> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&id)?;

    let existing = state.store.get_message(&id).await?;
    let att_ids: Vec<String> = if existing.is_some() && is_external_blob_store(state.blobs.as_ref())
    {
        state
            .store
            .list_attachment_meta(&id)
            .await?
            .into_iter()
            .map(|a| a.id)
            .collect()
    } else {
        Vec::new()
    };
    let deleted = state.store.delete_message(&id).await?;
    if !deleted {
        return Err(AppError::NotFound(format!("Message '{id}' not found")));
    }

    if let Some(msg) = existing {
        let _ = state.post_delete_message(&msg.id, &att_ids).await;
        state.events.publish(
            EventSource::Api,
            MailEvent::MessageDeleted {
                message_id: msg.id,
                thread_id: msg.thread_id,
                labels: msg.label_ids,
            },
        );
    }

    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/gmail/v1",
            "delete",
            vec![id],
            "ok",
            Some("message".to_string()),
        )
        .await;

    Ok(StatusCode::NO_CONTENT)
}

/// `POST /gmail/v1/users/{userId}/messages/batchModify`
async fn batch_modify_messages(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(user_id): Path<String>,
    Json(req): Json<BatchModifyMessagesRequest>,
) -> AppResult<StatusCode> {
    resolve_user_id(&user_id, &state.config)?;
    if req.ids.is_empty() {
        return Err(AppError::BadRequest(
            "batchModify requires at least one message id".to_string(),
        ));
    }
    if req.ids.len() > 1000 {
        return Err(AppError::BadRequest(
            "batchModify supports at most 1000 message ids".to_string(),
        ));
    }
    for id in &req.ids {
        validate_resource_id(id)?;
    }
    validate_label_ids(&req.add_label_ids)?;
    validate_label_ids(&req.remove_label_ids)?;

    state
        .store
        .batch_modify_labels(&req.ids, &req.add_label_ids, &req.remove_label_ids)
        .await?;

    for id in &req.ids {
        if let Some(msg) = state.store.get_message(id).await? {
            state.events.publish(
                EventSource::Api,
                MailEvent::MessageUpdated {
                    message_id: msg.id,
                    thread_id: msg.thread_id,
                    added_labels: req.add_label_ids.clone(),
                    removed_labels: req.remove_label_ids.clone(),
                },
            );
        }
    }

    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/gmail/v1",
            "modify",
            req.ids,
            "ok",
            Some("batchModify".to_string()),
        )
        .await;

    Ok(StatusCode::NO_CONTENT)
}

/// `POST /gmail/v1/users/{userId}/messages/batchDelete`
async fn batch_delete_messages(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(user_id): Path<String>,
    Json(req): Json<BatchDeleteMessagesRequest>,
) -> AppResult<StatusCode> {
    resolve_user_id(&user_id, &state.config)?;
    if req.ids.is_empty() {
        return Err(AppError::BadRequest(
            "batchDelete requires at least one message id".to_string(),
        ));
    }
    if req.ids.len() > 1000 {
        return Err(AppError::BadRequest(
            "batchDelete supports at most 1000 message ids".to_string(),
        ));
    }
    for id in &req.ids {
        validate_resource_id(id)?;
    }

    let mut existing_msgs = Vec::with_capacity(req.ids.len());
    for id in &req.ids {
        if let Some(msg) = state.store.get_message(id).await? {
            existing_msgs.push(msg);
        }
    }

    state.store.batch_delete_messages(&req.ids).await?;

    for msg in existing_msgs {
        let _ = state.post_delete_message(&msg.id, &[]).await;
        state.events.publish(
            EventSource::Api,
            MailEvent::MessageDeleted {
                message_id: msg.id,
                thread_id: msg.thread_id,
                labels: msg.label_ids,
            },
        );
    }

    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/gmail/v1",
            "delete",
            req.ids,
            "ok",
            Some("batchDelete".to_string()),
        )
        .await;

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /gmail/v1/users/{userId}/messages/{messageId}/attachments/{id}`
async fn get_attachment(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path((user_id, message_id, id)): Path<(String, String, String)>,
) -> AppResult<Json<MessagePartBody>> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&message_id)?;
    validate_resource_id(&id)?;

    let att = state
        .store
        .get_attachment(&message_id, &id)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "Attachment '{id}' on message '{message_id}' not found"
            ))
        })?;

    let data = state.load_attachment_bytes(&att).await?;

    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/gmail/v1",
            "read",
            vec![message_id, id],
            "ok",
            Some("attachment".to_string()),
        )
        .await;

    Ok(Json(MessagePartBody {
        attachment_id: None,
        size: data.len().min(i32::MAX as usize) as i32,
        data: Some(mime::encode_base64url(&data)),
    }))
}

// ============================================================================
// Threads
// ============================================================================

/// `GET /gmail/v1/users/{userId}/threads`
async fn list_threads(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(user_id): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> AppResult<Json<ListThreadsResponse>> {
    resolve_user_id(&user_id, &state.config)?;
    let params = QueryParams::from_raw(raw_query.as_deref());
    let query = params.parse_message_list_query()?;
    let page = state.store.list_threads(&query).await?;

    let target_ids: Vec<String> = page.threads.iter().map(|t| t.id.clone()).collect();
    let action = if query.q.as_deref().is_some_and(|s| !s.trim().is_empty()) {
        "search"
    } else {
        "read"
    };
    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/gmail/v1",
            action,
            target_ids,
            "ok",
            query.q.clone(),
        )
        .await;

    let threads = if page.threads.is_empty() {
        None
    } else {
        Some(
            page.threads
                .into_iter()
                .map(|t| ThreadRef {
                    id: t.id,
                    snippet: Some(t.snippet),
                    history_id: Some(t.history_id.to_string()),
                })
                .collect(),
        )
    };

    Ok(Json(ListThreadsResponse {
        threads,
        next_page_token: page.next_page_token,
        result_size_estimate: page.result_size_estimate,
    }))
}

/// `GET /gmail/v1/users/{userId}/threads/{id}`
async fn get_thread(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path((user_id, id)): Path<(String, String)>,
    RawQuery(raw_query): RawQuery,
) -> AppResult<Json<Thread>> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&id)?;
    let params = QueryParams::from_raw(raw_query.as_deref());
    let format = params.parse_format(MessageFormat::Full)?;
    let metadata_headers = params.metadata_headers();

    let detail = state
        .store
        .get_thread(&id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Thread '{id}' not found")))?;

    let thread = format_thread_detail(&state, detail, format, &metadata_headers).await?;
    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/gmail/v1",
            "read",
            vec![id],
            "ok",
            Some("thread".to_string()),
        )
        .await;
    Ok(Json(thread))
}

/// `POST /gmail/v1/users/{userId}/threads/{id}/modify`
async fn modify_thread(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path((user_id, id)): Path<(String, String)>,
    Json(req): Json<ModifyThreadRequest>,
) -> AppResult<Json<Thread>> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&id)?;
    validate_label_ids(&req.add_label_ids)?;
    validate_label_ids(&req.remove_label_ids)?;

    let detail = state
        .store
        .modify_thread_labels(&id, &req.add_label_ids, &req.remove_label_ids)
        .await?;

    for msg in &detail.messages {
        state.events.publish(
            EventSource::Api,
            MailEvent::MessageUpdated {
                message_id: msg.id.clone(),
                thread_id: msg.thread_id.clone(),
                added_labels: req.add_label_ids.clone(),
                removed_labels: req.remove_label_ids.clone(),
            },
        );
    }

    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/gmail/v1",
            "modify",
            vec![id],
            "ok",
            Some(format!(
                "thread add=[{}] remove=[{}]",
                req.add_label_ids.join(","),
                req.remove_label_ids.join(",")
            )),
        )
        .await;

    let thread = format_thread_detail(&state, detail, MessageFormat::Minimal, &[]).await?;
    Ok(Json(thread))
}

/// `POST /gmail/v1/users/{userId}/threads/{id}/trash`
async fn trash_thread(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path((user_id, id)): Path<(String, String)>,
) -> AppResult<Json<Thread>> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&id)?;

    let detail = state.store.trash_thread(&id).await?;
    for msg in &detail.messages {
        state.events.publish(
            EventSource::Api,
            MailEvent::MessageUpdated {
                message_id: msg.id.clone(),
                thread_id: msg.thread_id.clone(),
                added_labels: vec![LABEL_TRASH.to_string()],
                removed_labels: vec![LABEL_INBOX.to_string()],
            },
        );
    }

    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/gmail/v1",
            "modify",
            vec![id],
            "ok",
            Some("trash_thread".to_string()),
        )
        .await;

    let thread = format_thread_detail(&state, detail, MessageFormat::Minimal, &[]).await?;
    Ok(Json(thread))
}

/// `POST /gmail/v1/users/{userId}/threads/{id}/untrash`
async fn untrash_thread(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path((user_id, id)): Path<(String, String)>,
) -> AppResult<Json<Thread>> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&id)?;

    let detail = state.store.untrash_thread(&id).await?;
    for msg in &detail.messages {
        state.events.publish(
            EventSource::Api,
            MailEvent::MessageUpdated {
                message_id: msg.id.clone(),
                thread_id: msg.thread_id.clone(),
                added_labels: Vec::new(),
                removed_labels: vec![LABEL_TRASH.to_string()],
            },
        );
    }

    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/gmail/v1",
            "modify",
            vec![id],
            "ok",
            Some("untrash_thread".to_string()),
        )
        .await;

    let thread = format_thread_detail(&state, detail, MessageFormat::Minimal, &[]).await?;
    Ok(Json(thread))
}

/// `DELETE /gmail/v1/users/{userId}/threads/{id}`
async fn delete_thread(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path((user_id, id)): Path<(String, String)>,
) -> AppResult<StatusCode> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&id)?;

    let existing = state.store.get_thread(&id).await?;
    let deleted = state.store.delete_thread(&id).await?;
    if !deleted {
        return Err(AppError::NotFound(format!("Thread '{id}' not found")));
    }

    if let Some(detail) = existing {
        for msg in detail.messages {
            let _ = state.post_delete_message(&msg.id, &[]).await;
            state.events.publish(
                EventSource::Api,
                MailEvent::MessageDeleted {
                    message_id: msg.id,
                    thread_id: msg.thread_id,
                    labels: msg.label_ids,
                },
            );
        }
    }

    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/gmail/v1",
            "delete",
            vec![id],
            "ok",
            Some("thread".to_string()),
        )
        .await;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Labels
// ============================================================================

/// `GET /gmail/v1/users/{userId}/labels`
async fn list_labels(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
) -> AppResult<Json<ListLabelsResponse>> {
    resolve_user_id(&user_id, &state.config)?;
    let stored = state.store.list_labels().await?;
    let labels = stored
        .into_iter()
        .map(|l| stored_label_to_api(l, false))
        .collect();
    Ok(Json(ListLabelsResponse { labels }))
}

/// `GET /gmail/v1/users/{userId}/labels/{id}`
async fn get_label(
    MailboxState(state): MailboxState,
    Path((user_id, id)): Path<(String, String)>,
) -> AppResult<Json<Label>> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&id)?;
    let stored = state
        .store
        .get_label(&id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Label '{id}' not found")))?;
    Ok(Json(stored_label_to_api(stored, true)))
}

/// `POST /gmail/v1/users/{userId}/labels`
async fn create_label(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
    Json(payload): Json<Label>,
) -> AppResult<Json<Label>> {
    resolve_user_id(&user_id, &state.config)?;
    let name = payload.name.trim().to_string();
    if name.is_empty() {
        return Err(AppError::BadRequest(
            "Label name must not be empty".to_string(),
        ));
    }
    validate_email_header("X-Label-Name", &name)?;

    let stored = state
        .store
        .create_label(NewLabelInput {
            name,
            message_list_visibility: payload.message_list_visibility,
            label_list_visibility: payload.label_list_visibility,
            color: payload.color,
            upstream_label_id: None,
        })
        .await?;
    Ok(Json(stored_label_to_api(stored, true)))
}

/// `PUT /gmail/v1/users/{userId}/labels/{id}`
async fn update_label(
    MailboxState(state): MailboxState,
    Path((user_id, id)): Path<(String, String)>,
    Json(payload): Json<Label>,
) -> AppResult<Json<Label>> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&id)?;
    let name = (!payload.name.trim().is_empty()).then(|| payload.name.trim().to_string());
    if let Some(ref n) = name {
        validate_email_header("X-Label-Name", n)?;
    }
    let stored = state
        .store
        .update_label(
            &id,
            UpdateLabelInput {
                name,
                message_list_visibility: payload.message_list_visibility,
                label_list_visibility: payload.label_list_visibility,
                color: payload.color,
            },
            true,
        )
        .await?;
    Ok(Json(stored_label_to_api(stored, true)))
}

/// `PATCH /gmail/v1/users/{userId}/labels/{id}`
async fn patch_label(
    MailboxState(state): MailboxState,
    Path((user_id, id)): Path<(String, String)>,
    Json(payload): Json<Label>,
) -> AppResult<Json<Label>> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&id)?;
    let name = (!payload.name.trim().is_empty()).then(|| payload.name.trim().to_string());
    if let Some(ref n) = name {
        validate_email_header("X-Label-Name", n)?;
    }
    let stored = state
        .store
        .update_label(
            &id,
            UpdateLabelInput {
                name,
                message_list_visibility: payload.message_list_visibility,
                label_list_visibility: payload.label_list_visibility,
                color: payload.color,
            },
            false,
        )
        .await?;
    Ok(Json(stored_label_to_api(stored, true)))
}

/// `DELETE /gmail/v1/users/{userId}/labels/{id}`
async fn delete_label(
    MailboxState(state): MailboxState,
    Path((user_id, id)): Path<(String, String)>,
) -> AppResult<StatusCode> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&id)?;
    state.store.delete_label(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Drafts
// ============================================================================

fn build_draft_message_input(
    state: &AppState,
    draft_meta: &Draft,
    raw_bytes: Option<Vec<u8>>,
) -> AppResult<NewMessageInput> {
    let raw = match raw_bytes {
        Some(bytes) if !bytes.is_empty() => bytes,
        _ => format!("From: {}\r\nSubject: \r\n\r\n", state.config.user_email).into_bytes(),
    };
    let parsed = mime::parse_rfc2822(&raw)?;

    let msg_meta = draft_meta.message.as_ref();
    let thread_id = msg_meta
        .map(|m| m.thread_id.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(ToOwned::to_owned);
    if let Some(ref tid) = thread_id {
        validate_resource_id(tid)?;
    }

    let mut labels = vec![LABEL_DRAFT.to_string()];
    if let Some(extra) = msg_meta.and_then(|m| m.label_ids.as_ref()) {
        validate_label_ids(extra)?;
        labels.extend(extra.iter().cloned());
    }

    Ok(build_new_message_input(
        &parsed,
        raw,
        thread_id,
        dedup_labels(labels),
        Utc::now().timestamp_millis(),
        None,
        false,
        "local",
    ))
}

async fn format_stored_draft(
    state: &AppState,
    draft: &StoredDraft,
    format: MessageFormat,
    metadata_headers: &[String],
) -> AppResult<Draft> {
    let message =
        format_gmail_message_from_store(state, &draft.message, format, metadata_headers).await?;
    Ok(Draft {
        id: draft.id.clone(),
        message: Some(message),
    })
}

/// `GET /gmail/v1/users/{userId}/drafts`
async fn list_drafts(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(user_id): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> AppResult<Json<ListDraftsResponse>> {
    resolve_user_id(&user_id, &state.config)?;
    let params = QueryParams::from_raw(raw_query.as_deref());
    let query = params.parse_message_list_query()?;
    let page = state.store.list_drafts(&query).await?;

    let target_ids: Vec<String> = page.drafts.iter().map(|d| d.id.clone()).collect();
    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/gmail/v1",
            "read",
            target_ids,
            "ok",
            Some("drafts".to_string()),
        )
        .await;

    let drafts = if page.drafts.is_empty() {
        None
    } else {
        Some(
            page.drafts
                .into_iter()
                .map(|d| DraftRef {
                    id: d.id,
                    message: MessageRef {
                        id: d.message.id,
                        thread_id: d.message.thread_id,
                    },
                })
                .collect(),
        )
    };

    Ok(Json(ListDraftsResponse {
        drafts,
        next_page_token: page.next_page_token,
        result_size_estimate: page.result_size_estimate,
    }))
}

/// `GET /gmail/v1/users/{userId}/drafts/{id}`
async fn get_draft(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path((user_id, id)): Path<(String, String)>,
    RawQuery(raw_query): RawQuery,
) -> AppResult<Json<Draft>> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&id)?;
    let params = QueryParams::from_raw(raw_query.as_deref());
    let format = params.parse_format(MessageFormat::Full)?;
    let metadata_headers = params.metadata_headers();

    let draft = state
        .store
        .get_draft(&id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Draft '{id}' not found")))?;

    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/gmail/v1",
            "read",
            vec![id],
            "ok",
            Some("draft".to_string()),
        )
        .await;

    Ok(Json(
        format_stored_draft(&state, &draft, format, &metadata_headers).await?,
    ))
}

/// Shared `drafts.create` completion logic used by JSON, `media`, `multipart`, and `resumable`.
async fn complete_create_draft(
    state: &AppState,
    metadata: Draft,
    raw_bytes: Option<Vec<u8>>,
    principal: Option<&Principal>,
) -> AppResult<Draft> {
    let input = build_draft_message_input(state, &metadata, raw_bytes)?;
    let draft = state.store.create_draft(input).await?;
    state.post_store_message(&draft.message).await?;
    state.events.publish(
        EventSource::Api,
        MailEvent::DraftCreated {
            draft_id: draft.id.clone(),
            message_id: draft.message.id.clone(),
            thread_id: draft.message.thread_id.clone(),
        },
    );

    state
        .record_audit(
            principal,
            "/gmail/v1",
            "draft",
            vec![draft.id.clone(), draft.message.id.clone()],
            "ok",
            None,
        )
        .await;

    format_stored_draft(state, &draft, MessageFormat::Minimal, &[]).await
}

/// Shared `drafts.update` completion logic used by JSON, `media`, `multipart`, and `resumable`.
async fn complete_update_draft(
    state: &AppState,
    draft_id: &str,
    metadata: Draft,
    raw_bytes: Option<Vec<u8>>,
    principal: Option<&Principal>,
) -> AppResult<Draft> {
    let input = build_draft_message_input(state, &metadata, raw_bytes)?;
    let draft = state.store.update_draft(draft_id, input).await?;
    state.post_store_message(&draft.message).await?;
    state.events.publish(
        EventSource::Api,
        MailEvent::DraftCreated {
            draft_id: draft.id.clone(),
            message_id: draft.message.id.clone(),
            thread_id: draft.message.thread_id.clone(),
        },
    );

    state
        .record_audit(
            principal,
            "/gmail/v1",
            "draft",
            vec![draft.id.clone(), draft.message.id.clone()],
            "ok",
            Some("update".to_string()),
        )
        .await;

    format_stored_draft(state, &draft, MessageFormat::Minimal, &[]).await
}

/// Shared `drafts.send` completion logic used by JSON, `media`, `multipart`, and `resumable`.
async fn complete_send_draft(
    state: &AppState,
    metadata: Draft,
    raw_bytes: Option<Vec<u8>>,
    idempotency_key: Option<&str>,
    principal: Option<&Principal>,
) -> AppResult<Message> {
    let draft_id = (!metadata.id.trim().is_empty()).then(|| metadata.id.trim().to_string());
    if let Some(ref did) = draft_id {
        validate_resource_id(did)?;
    }

    let existing_draft = match draft_id.as_deref() {
        Some(did) => Some(
            state
                .store
                .get_draft(did)
                .await?
                .ok_or_else(|| AppError::NotFound(format!("Draft '{did}' not found")))?,
        ),
        None => None,
    };

    let raw_bytes = match raw_bytes {
        Some(bytes) if !bytes.is_empty() => bytes,
        _ => match existing_draft.as_ref() {
            Some(d) => d.message.raw_rfc2822.clone(),
            None => {
                return Err(AppError::BadRequest(
                    "drafts.send requires either an existing draft 'id' or a raw RFC 2822 message"
                        .to_string(),
                ));
            }
        },
    };

    let thread_id = metadata
        .message
        .as_ref()
        .map(|m| m.thread_id.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| existing_draft.as_ref().map(|d| d.message.thread_id.clone()));

    let extra_labels = metadata
        .message
        .as_ref()
        .and_then(|m| m.label_ids.clone())
        .unwrap_or_default();

    let stored = execute_gmail_send(
        state,
        raw_bytes,
        thread_id,
        extra_labels,
        idempotency_key,
        principal,
        true,
    )
    .await?;

    if let Some(ref did) = draft_id {
        let _ = state.store.delete_draft(did).await?;
    }

    format_gmail_message(&stored, MessageFormat::Minimal, &[])
}

/// `POST /gmail/v1/users/{userId}/drafts` & `/upload/gmail/v1/users/{userId}/drafts`
async fn create_draft(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(user_id): Path<String>,
    uri: Uri,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let user_email = resolve_user_id(&user_id, &state.config)?;
    let params = QueryParams::from_raw(raw_query.as_deref());
    if is_resumable_upload(&params) {
        let metadata = extract_resumable_draft_metadata(&body)?;
        validate_draft_metadata(&metadata)?;
        return initiate_resumable_upload(
            &state,
            user_email,
            ResumableUploadTarget::DraftsCreate,
            ResumableUploadMetadata::Draft(metadata),
            &uri,
            &params,
            &headers,
        );
    }

    let extracted = extract_draft_upload(&headers, &params, &body)?;
    let draft = complete_create_draft(
        &state,
        extracted.metadata,
        extracted.raw_bytes,
        principal.as_ref().map(|Extension(p)| p),
    )
    .await?;
    Ok(Json(draft).into_response())
}

/// `PUT /gmail/v1/users/{userId}/drafts/{id}` & `/upload/gmail/v1/users/{userId}/drafts/{id}`
async fn update_draft(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path((user_id, id)): Path<(String, String)>,
    uri: Uri,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let user_email = resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&id)?;
    let params = QueryParams::from_raw(raw_query.as_deref());

    if params
        .get("upload_id")
        .is_some_and(|s| !s.trim().is_empty())
    {
        return handle_resumable_chunk(
            &state,
            &user_id,
            ResumableEndpoint::DraftsUpdate(id),
            raw_query.as_deref(),
            &headers,
            body,
            principal.as_ref().map(|Extension(p)| p),
        )
        .await;
    }

    if is_resumable_upload(&params) {
        let metadata = extract_resumable_draft_metadata(&body)?;
        validate_draft_metadata(&metadata)?;
        return initiate_resumable_upload(
            &state,
            user_email,
            ResumableUploadTarget::DraftsUpdate { draft_id: id },
            ResumableUploadMetadata::Draft(metadata),
            &uri,
            &params,
            &headers,
        );
    }

    let extracted = extract_draft_upload(&headers, &params, &body)?;
    let draft = complete_update_draft(
        &state,
        &id,
        extracted.metadata,
        extracted.raw_bytes,
        principal.as_ref().map(|Extension(p)| p),
    )
    .await?;
    Ok(Json(draft).into_response())
}

/// `DELETE /gmail/v1/users/{userId}/drafts/{id}`
async fn delete_draft(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path((user_id, id)): Path<(String, String)>,
) -> AppResult<StatusCode> {
    resolve_user_id(&user_id, &state.config)?;
    validate_resource_id(&id)?;

    let existing = state.store.get_draft(&id).await?;
    let deleted = state.store.delete_draft(&id).await?;
    if !deleted {
        return Err(AppError::NotFound(format!("Draft '{id}' not found")));
    }

    if let Some(d) = existing {
        let _ = state.post_delete_message(&d.message.id, &[]).await;
        state.events.publish(
            EventSource::Api,
            MailEvent::MessageDeleted {
                message_id: d.message.id,
                thread_id: d.message.thread_id,
                labels: d.message.label_ids,
            },
        );
    }

    state
        .record_audit(
            principal.as_ref().map(|Extension(p)| p),
            "/gmail/v1",
            "delete",
            vec![id],
            "ok",
            Some("draft".to_string()),
        )
        .await;

    Ok(StatusCode::NO_CONTENT)
}

/// `POST /gmail/v1/users/{userId}/drafts/send` & `/upload/gmail/v1/users/{userId}/drafts/send`
async fn send_draft(
    MailboxState(state): MailboxState,
    principal: Option<Extension<Principal>>,
    Path(user_id): Path<String>,
    uri: Uri,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    let user_email = resolve_user_id(&user_id, &state.config)?;
    let params = QueryParams::from_raw(raw_query.as_deref());
    if is_resumable_upload(&params) {
        let metadata = extract_resumable_draft_metadata(&body)?;
        validate_draft_metadata(&metadata)?;
        return initiate_resumable_upload(
            &state,
            user_email,
            ResumableUploadTarget::DraftsSend,
            ResumableUploadMetadata::Draft(metadata),
            &uri,
            &params,
            &headers,
        );
    }

    let extracted = extract_draft_upload(&headers, &params, &body)?;
    let msg = complete_send_draft(
        &state,
        extracted.metadata,
        extracted.raw_bytes,
        idempotency_key_header(&headers),
        principal.as_ref().map(|Extension(p)| p),
    )
    .await?;
    Ok(Json(msg).into_response())
}

// ============================================================================
// History
// ============================================================================

#[derive(Default)]
struct HistoryRecordAcc {
    messages: Vec<Message>,
    messages_added: Vec<HistoryMessageAdded>,
    messages_deleted: Vec<HistoryMessageDeleted>,
    labels_added: Vec<HistoryLabelAdded>,
    labels_removed: Vec<HistoryLabelRemoved>,
}

/// `GET /gmail/v1/users/{userId}/history`
async fn list_history(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> AppResult<Json<ListHistoryResponse>> {
    resolve_user_id(&user_id, &state.config)?;
    let params = QueryParams::from_raw(raw_query.as_deref());
    let query = params.parse_history_list_query()?;
    let page = state.store.list_history(&query).await?;

    let mut grouped: BTreeMap<u64, HistoryRecordAcc> = BTreeMap::new();
    for entry in page.entries {
        let acc = grouped.entry(entry.history_id).or_default();
        let msg = Message {
            id: entry.message_id.clone(),
            thread_id: entry.thread_id.clone(),
            label_ids: (!entry.label_ids.is_empty()).then(|| entry.label_ids.clone()),
            ..Default::default()
        };

        if !acc.messages.iter().any(|m| m.id == msg.id) {
            acc.messages.push(msg.clone());
        }

        match entry.kind {
            HistoryEventKind::MessageAdded => {
                acc.messages_added
                    .push(HistoryMessageAdded { message: msg });
            }
            HistoryEventKind::MessageDeleted => {
                acc.messages_deleted
                    .push(HistoryMessageDeleted { message: msg });
            }
            HistoryEventKind::LabelAdded => {
                acc.labels_added.push(HistoryLabelAdded {
                    message: msg,
                    label_ids: entry.label_ids,
                });
            }
            HistoryEventKind::LabelRemoved => {
                acc.labels_removed.push(HistoryLabelRemoved {
                    message: msg,
                    label_ids: entry.label_ids,
                });
            }
        }
    }

    let records: Vec<HistoryRecord> = grouped
        .into_iter()
        .map(|(hid, acc)| HistoryRecord {
            id: hid.to_string(),
            messages: (!acc.messages.is_empty()).then_some(acc.messages),
            messages_added: (!acc.messages_added.is_empty()).then_some(acc.messages_added),
            messages_deleted: (!acc.messages_deleted.is_empty()).then_some(acc.messages_deleted),
            labels_added: (!acc.labels_added.is_empty()).then_some(acc.labels_added),
            labels_removed: (!acc.labels_removed.is_empty()).then_some(acc.labels_removed),
        })
        .collect();

    Ok(Json(ListHistoryResponse {
        history: (!records.is_empty()).then_some(records),
        next_page_token: page.next_page_token,
        history_id: page.current_history_id.to_string(),
    }))
}

// ============================================================================
// Watch / Stop
// ============================================================================

/// `POST /gmail/v1/users/{userId}/watch`
async fn watch_mailbox(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
    Json(req): Json<WatchRequest>,
) -> AppResult<Json<WatchResponse>> {
    resolve_user_id(&user_id, &state.config)?;
    let topic_name = req.topic_name.trim().to_string();
    if topic_name.is_empty() {
        return Err(AppError::BadRequest(
            "topicName must not be empty".to_string(),
        ));
    }
    validate_label_ids(&req.label_ids)?;

    let behavior = req
        .label_filter_behavior
        .or(req.label_filter_action)
        .unwrap_or_else(|| "include".to_string())
        .to_ascii_lowercase();
    if behavior != "include" && behavior != "exclude" {
        return Err(AppError::BadRequest(format!(
            "Invalid labelFilterBehavior '{behavior}'; expected 'include' or 'exclude'"
        )));
    }

    let history_id = state.store.current_history_id().await?;
    let expiration_ms = (Utc::now() + Duration::days(7)).timestamp_millis();

    let sub = state
        .store
        .set_watch(WatchSubscription {
            topic_name,
            label_ids: req.label_ids,
            label_filter_behavior: behavior,
            history_id,
            expiration_ms,
        })
        .await?;

    Ok(Json(WatchResponse {
        history_id: sub.history_id.to_string(),
        expiration: sub.expiration_ms.to_string(),
    }))
}

/// `POST /gmail/v1/users/{userId}/stop`
async fn stop_watch(
    MailboxState(state): MailboxState,
    Path(user_id): Path<String>,
    body: Bytes,
) -> AppResult<StatusCode> {
    resolve_user_id(&user_id, &state.config)?;
    if !body.is_empty() {
        let _: serde_json::Value = serde_json::from_slice(&body)?;
    }
    state.store.clear_watch().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests;
