//! Axum webhook router and handler (`POST /webhooks/resend`) for Resend inbound
//! receiving (`email.received`) and delivery status webhooks.

use std::collections::HashMap;

use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use chrono::{DateTime, Utc};
use serde_json::json;

use crate::{
    AppState,
    error::AppResult,
    events::{EventSource, MailEvent},
    mime::ComposeEmailInput,
    models::{
        LABEL_INBOX, LABEL_UNREAD, ResendBounceInfo, ResendReceivedEmail, ResendWebhookEvent,
    },
    resend::{
        filter::{FilterDecision, InboundFilter},
        svix::verify_svix_signature,
        transport::{InboundEnvelope, IngestOutcome, ingest_inbound_rfc2822},
    },
    storage::NewAttachmentInput,
};

/// Headers managed directly by `mail-builder` that should not be duplicated via `extra_headers`.
const STANDARD_COMPOSED_HEADERS: &[&str] = &[
    "from",
    "to",
    "cc",
    "bcc",
    "reply-to",
    "subject",
    "message-id",
    "in-reply-to",
    "references",
    "date",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
    "content-disposition",
];

/// Mount Resend webhook routes (`/webhooks/resend`).
pub fn resend_router() -> Router<AppState> {
    Router::new().route("/webhooks/resend", post(webhook_handler))
}

/// Axum handler for `POST /webhooks/resend`.
///
/// Enforces Svix HMAC-SHA256 verification (401 on failure) when `config.resend_webhook_secret`
/// is configured, and allows a warning-only dev bypass when `None`.
pub async fn webhook_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Response> {
    if let Some(secret) = state
        .config
        .resend_webhook_secret
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        verify_svix_signature(&headers, &body, secret, Utc::now().timestamp())?;
    } else {
        tracing::warn!(
            "Resend webhook secret is not configured; accepting webhook without Svix signature verification (dev mode)"
        );
    }

    let event: ResendWebhookEvent = serde_json::from_slice(&body)?;

    match event.event_type.as_str() {
        "email.received" => handle_email_received(&state, &event, state.filter.as_ref()).await,
        "email.sent" => handle_delivery_status(&state, &event, "sent").await,
        "email.delivered" => handle_delivery_status(&state, &event, "delivered").await,
        "email.delivery_delayed" => {
            handle_delivery_status(&state, &event, "delivery_delayed").await
        }
        "email.bounced" => handle_delivery_status(&state, &event, "bounced").await,
        "email.complained" => handle_delivery_status(&state, &event, "complained").await,
        "email.opened" => handle_delivery_status(&state, &event, "opened").await,
        "email.clicked" => handle_delivery_status(&state, &event, "clicked").await,
        "email.failed" => handle_delivery_status(&state, &event, "failed").await,
        "email.scheduled" => handle_delivery_status(&state, &event, "scheduled").await,
        other => {
            tracing::debug!(event_type = %other, "Ignoring unrecognized Resend webhook event");
            Ok((
                StatusCode::OK,
                Json(json!({
                    "status": "ignored",
                    "event_type": other,
                })),
            )
                .into_response())
        }
    }
}

fn find_header_ci<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty())
}

fn parse_timestamp_ms(candidates: &[Option<&str>]) -> Option<i64> {
    for candidate in candidates.iter().flatten() {
        if let Ok(dt) = DateTime::parse_from_rfc3339(candidate.trim()) {
            return Some(dt.timestamp_millis());
        }
    }
    None
}

fn format_bounce_detail(bounce: Option<&ResendBounceInfo>) -> Option<String> {
    let bounce = bounce?;
    let mut prefix_parts = Vec::new();
    if let Some(bt) = bounce
        .bounce_type
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        prefix_parts.push(bt);
    }
    if let Some(st) = bounce
        .sub_type
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        prefix_parts.push(st);
    }
    let msg = bounce
        .message
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    match (prefix_parts.is_empty(), msg) {
        (false, Some(m)) => Some(format!("{}: {m}", prefix_parts.join("/"))),
        (false, None) => Some(prefix_parts.join("/")),
        (true, Some(m)) => Some(m.to_string()),
        (true, None) => None,
    }
}

/// Synthesize minimal valid RFC 2822 bytes as a last-resort fallback if `mail-builder` rejects
/// unusual external header values.
fn build_minimal_rfc2822_fallback(input: &ComposeEmailInput) -> Vec<u8> {
    let mut out = String::new();
    if !input.from.is_empty() {
        out.push_str(&format!(
            "From: {}\r\n",
            input.from.replace(['\r', '\n'], " ")
        ));
    }
    if !input.to.is_empty() {
        out.push_str(&format!(
            "To: {}\r\n",
            input.to.join(", ").replace(['\r', '\n'], " ")
        ));
    }
    if !input.cc.is_empty() {
        out.push_str(&format!(
            "Cc: {}\r\n",
            input.cc.join(", ").replace(['\r', '\n'], " ")
        ));
    }
    out.push_str(&format!(
        "Subject: {}\r\n",
        input.subject.replace(['\r', '\n'], " ")
    ));
    if let Some(mid) = &input.message_id {
        out.push_str(&format!(
            "Message-ID: {}\r\n",
            mid.replace(['\r', '\n'], "")
        ));
    }
    if let Some(irt) = &input.in_reply_to {
        out.push_str(&format!(
            "In-Reply-To: {}\r\n",
            irt.replace(['\r', '\n'], "")
        ));
    }
    if let Some(refs) = &input.references {
        out.push_str(&format!(
            "References: {}\r\n",
            refs.replace(['\r', '\n'], " ")
        ));
    }
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n\r\n");
    if let Some(text) = &input.text {
        out.push_str(text);
    } else if let Some(html) = &input.html {
        out.push_str(html);
    }
    out.into_bytes()
}

fn collect_resend_recipient_candidates(
    event: &ResendWebhookEvent,
    fetched: Option<&ResendReceivedEmail>,
    raw_bytes: Option<&[u8]>,
) -> Vec<String> {
    let mut candidates = Vec::new();
    candidates.extend(event.data.to.iter().cloned());
    if let Some(ref cc) = event.data.cc {
        candidates.extend(cc.iter().cloned());
    }
    if let Some(ref bcc) = event.data.bcc {
        candidates.extend(bcc.iter().cloned());
    }
    if let Some(email) = fetched {
        candidates.extend(email.to.iter().cloned());
        candidates.extend(email.cc.iter().cloned());
        candidates.extend(email.bcc.iter().cloned());
        for hdr in [
            "delivered-to",
            "x-original-to",
            "envelope-to",
            "to",
            "cc",
            "bcc",
        ] {
            if let Some(val) = find_header_ci(&email.headers, hdr) {
                candidates.push(val.to_string());
            }
        }
    }
    if let Some(raw) = raw_bytes
        && let Ok(parsed) = crate::mime::parse_rfc2822(raw)
    {
        candidates.extend(parsed.to);
        candidates.extend(parsed.cc);
        candidates.extend(parsed.bcc);
        for hdr in parsed.headers {
            if matches!(
                hdr.name.to_ascii_lowercase().as_str(),
                "delivered-to" | "x-original-to" | "envelope-to"
            ) {
                candidates.push(hdr.value);
            }
        }
    }
    candidates
}

/// Ingest a Resend `email.received` webhook event, fetching full email content and attachments
/// via the Resend Receiving API (gracefully falling back to webhook metadata on API failure)
/// and delegating to [`ingest_inbound_rfc2822`] for each matching local mailbox.
pub async fn handle_email_received(
    state: &AppState,
    event: &ResendWebhookEvent,
    filter: &dyn InboundFilter,
) -> AppResult<Response> {
    let email_id = event.data.email_id.trim();

    // Fast-path dedup before calling the Resend Receiving API (only when single-mailbox or
    // every pre-matched target mailbox already has the message).
    let initial_candidates = collect_resend_recipient_candidates(event, None, None);
    let initial_targets = state.config.resolve_inbound_mailboxes(&initial_candidates);
    if !initial_targets.is_empty()
        && (!state.config.has_explicit_mailbox_routing() || initial_targets.len() == 1)
    {
        let mut first_dup: Option<(String, String, String)> = None;
        let mut all_dups = true;
        let norm_mid = event
            .data
            .message_id
            .as_deref()
            .and_then(crate::mime::normalize_message_id);

        for mb in &initial_targets {
            let mb_store = state.for_mailbox(mb).store;
            let mut found = None;
            if let Some(ref mid) = norm_mid {
                found = mb_store.find_message_by_rfc_message_id(mid).await?;
            }
            if found.is_none() && !email_id.is_empty() {
                found = mb_store.find_message_by_resend_id(email_id).await?;
            }
            if let Some(existing) = found {
                if first_dup.is_none() {
                    first_dup = Some((mb.clone(), existing.id, existing.thread_id));
                }
            } else {
                all_dups = false;
                break;
            }
        }

        if all_dups && let Some((mb, msg_id, thread_id)) = first_dup {
            return Ok((
                StatusCode::OK,
                Json(json!({
                    "status": "duplicate",
                    "mailbox_id": mb,
                    "message_id": msg_id,
                    "thread_id": thread_id,
                })),
            )
                .into_response());
        }
    }

    // Attempt to fetch the full received email from Resend Receiving API.
    let fetched: Option<ResendReceivedEmail> = if email_id.is_empty() {
        None
    } else {
        match state.resend.get_received_email(email_id).await {
            Ok(email) => Some(email),
            Err(err) => {
                tracing::warn!(
                    email_id = %email_id,
                    error = %err,
                    "Failed to fetch received email from Resend Receiving API; falling back to webhook metadata"
                );
                None
            }
        }
    };

    // Attempt to download verbatim raw RFC 2822 if provided by Resend Receiving API.
    let mut raw_rfc2822: Option<Vec<u8>> = None;
    if let Some(received) = fetched.as_ref()
        && let Some(raw_ref) = received.raw.as_ref()
    {
        let raw_url = raw_ref.download_url.trim();
        if !raw_url.is_empty() {
            match state.resend.download_bytes(raw_url).await {
                Ok(bytes) if !bytes.is_empty() => {
                    raw_rfc2822 = Some(bytes);
                }
                Ok(_) => {
                    tracing::warn!(
                        email_id = %email_id,
                        "Resend raw.download_url returned empty body; synthesizing RFC 2822"
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        email_id = %email_id,
                        error = %err,
                        "Failed to download raw RFC 2822 from Resend; synthesizing RFC 2822"
                    );
                }
            }
        }
    }

    // Resolve target local mailbox(es) from webhook + fetched metadata + raw RFC 2822 headers.
    let recipient_candidates =
        collect_resend_recipient_candidates(event, fetched.as_ref(), raw_rfc2822.as_deref());
    let target_mailboxes = state
        .config
        .resolve_inbound_mailboxes(&recipient_candidates);
    if target_mailboxes.is_empty() {
        tracing::info!(
            email_id = %email_id,
            "Ignoring Resend inbound email with no matching local mailbox"
        );
        return Ok((
            StatusCode::OK,
            Json(json!({
                "status": "ignored",
                "reason": "no_matching_local_mailbox",
            })),
        )
            .into_response());
    }

    // Fetch & download attachments when raw RFC 2822 wasn't downloaded and attachments are indicated.
    let has_attachments_hint = fetched.as_ref().is_some_and(|e| !e.attachments.is_empty())
        || event
            .data
            .attachments
            .as_ref()
            .is_some_and(|a| !a.is_empty());

    let mut downloaded_attachments: Vec<NewAttachmentInput> = Vec::new();
    if raw_rfc2822.is_none() && has_attachments_hint && !email_id.is_empty() {
        match state.resend.list_received_attachments(email_id).await {
            Ok(att_list) => {
                for (idx, att) in att_list.into_iter().enumerate() {
                    match state.resend.download_bytes(&att.download_url).await {
                        Ok(data) => {
                            downloaded_attachments.push(NewAttachmentInput {
                                part_id: format!("att-{}", idx + 1),
                                filename: att.filename,
                                content_type: att
                                    .content_type
                                    .unwrap_or_else(|| "application/octet-stream".to_string()),
                                content_id: att.content_id,
                                data,
                            });
                        }
                        Err(err) => {
                            tracing::warn!(
                                email_id = %email_id,
                                attachment_id = %att.id,
                                error = %err,
                                "Failed to download received attachment bytes; skipping attachment"
                            );
                        }
                    }
                }
            }
            Err(err) => {
                tracing::warn!(
                    email_id = %email_id,
                    error = %err,
                    "Failed to list received attachments from Resend Receiving API; continuing without attachment bytes"
                );
            }
        }
    }

    // Merge structured metadata from fetched email and webhook payload.
    let from = fetched
        .as_ref()
        .map(|e| e.from.clone())
        .filter(|s| !s.trim().is_empty())
        .or_else(|| event.data.from.clone())
        .unwrap_or_default();

    let to = fetched
        .as_ref()
        .map(|e| e.to.clone())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| event.data.to.clone());

    let cc = fetched
        .as_ref()
        .map(|e| e.cc.clone())
        .filter(|v| !v.is_empty())
        .or_else(|| event.data.cc.clone())
        .unwrap_or_default();

    let bcc = fetched
        .as_ref()
        .map(|e| e.bcc.clone())
        .filter(|v| !v.is_empty())
        .or_else(|| event.data.bcc.clone())
        .unwrap_or_default();

    let reply_to = fetched
        .as_ref()
        .map(|e| e.reply_to.clone())
        .unwrap_or_default();

    let subject = fetched
        .as_ref()
        .map(|e| e.subject.clone())
        .filter(|s| !s.is_empty())
        .or_else(|| event.data.subject.clone())
        .unwrap_or_default();

    let text = fetched.as_ref().and_then(|e| e.text.clone());
    let html = fetched.as_ref().and_then(|e| e.html.clone());

    let rfc822_message_id = fetched
        .as_ref()
        .and_then(|e| e.message_id.as_deref())
        .or_else(|| {
            fetched
                .as_ref()
                .and_then(|e| find_header_ci(&e.headers, "message-id"))
        })
        .or(event.data.message_id.as_deref())
        .and_then(crate::mime::normalize_message_id);

    let in_reply_to = fetched
        .as_ref()
        .and_then(|e| find_header_ci(&e.headers, "in-reply-to"))
        .and_then(crate::mime::normalize_message_id);

    let references_header = fetched
        .as_ref()
        .and_then(|e| find_header_ci(&e.headers, "references"))
        .map(ToString::to_string);

    let authentication_results = fetched
        .as_ref()
        .and_then(|e| find_header_ci(&e.headers, "authentication-results"))
        .map(ToString::to_string);

    let received_at_ms = parse_timestamp_ms(&[
        fetched.as_ref().and_then(|e| e.created_at.as_deref()),
        event.data.created_at.as_deref(),
        Some(event.created_at.as_str()),
    ]);

    // If raw RFC 2822 bytes were not downloaded, build RFC 2822 via crate::mime.
    let raw_bytes = match raw_rfc2822 {
        Some(bytes) => bytes,
        None => {
            let mut extra_headers = HashMap::new();
            if let Some(received) = fetched.as_ref() {
                for (k, v) in &received.headers {
                    if !STANDARD_COMPOSED_HEADERS
                        .iter()
                        .any(|std_hdr| k.eq_ignore_ascii_case(std_hdr))
                    {
                        extra_headers.insert(k.clone(), v.clone());
                    }
                }
            }

            let compose = ComposeEmailInput {
                from: from.clone(),
                to: to.clone(),
                cc: cc.clone(),
                bcc: bcc.clone(),
                reply_to,
                subject: subject.clone(),
                text: text.clone(),
                html: html.clone(),
                message_id: rfc822_message_id.clone(),
                in_reply_to: in_reply_to.clone(),
                references: references_header.clone(),
                extra_headers,
                attachments: downloaded_attachments.clone(),
            };

            match crate::mime::build_rfc2822(&compose) {
                Ok(bytes) => bytes,
                Err(err) => {
                    tracing::warn!(
                        email_id = %email_id,
                        error = %err,
                        "Failed to build RFC 2822 with crate::mime::build_rfc2822; using minimal fallback"
                    );
                    build_minimal_rfc2822_fallback(&compose)
                }
            }
        }
    };

    let base_envelope = InboundEnvelope {
        raw_rfc2822: raw_bytes,
        source: "resend_inbound".to_string(),
        provider_id: (!email_id.is_empty()).then(|| email_id.to_string()),
        sender_ip: None,
        authentication_results,
        received_at_ms,
        default_labels: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
        extra_attachments: downloaded_attachments,
        fallback_from: (!from.is_empty()).then_some(from),
        fallback_to: to,
        fallback_cc: cc,
        fallback_bcc: bcc,
        fallback_subject: (!subject.is_empty()).then_some(subject),
        fallback_text: text,
        fallback_html: html,
        fallback_rfc822_message_id: rfc822_message_id,
        fallback_in_reply_to: in_reply_to,
        fallback_references: references_header,
    };

    if target_mailboxes.len() == 1 {
        let mb = &target_mailboxes[0];
        let mb_state = state.for_mailbox(mb);
        let outcome = ingest_inbound_rfc2822(
            mb_state.store.as_ref(),
            &mb_state.events,
            filter,
            base_envelope,
        )
        .await?;

        return match outcome {
            IngestOutcome::Stored { message, decision } => {
                mb_state.post_store_message(&message).await?;
                let filter_label = match decision {
                    FilterDecision::Allow => "allow",
                    FilterDecision::Spam { .. } => "spam",
                    FilterDecision::Reject { .. } => "reject",
                    FilterDecision::Mutate { .. } => "mutate",
                };
                Ok((
                    StatusCode::OK,
                    Json(json!({
                        "status": "received",
                        "mailbox_id": mb,
                        "message_id": message.id,
                        "thread_id": message.thread_id,
                        "labels": message.label_ids,
                        "filter_decision": filter_label,
                    })),
                )
                    .into_response())
            }
            IngestOutcome::Duplicate { message } => Ok((
                StatusCode::OK,
                Json(json!({
                    "status": "duplicate",
                    "mailbox_id": mb,
                    "message_id": message.id,
                    "thread_id": message.thread_id,
                })),
            )
                .into_response()),
            IngestOutcome::Rejected { reason } => Ok((
                StatusCode::OK,
                Json(json!({
                    "status": "rejected",
                    "mailbox_id": mb,
                    "reason": reason,
                })),
            )
                .into_response()),
        };
    }

    // Multiple local mailboxes matched (e.g. To: alice@example.com, Cc: bob@example.com).
    let mut deliveries = Vec::with_capacity(target_mailboxes.len());
    let mut first_received: Option<(String, String, Vec<String>, &'static str)> = None;
    let mut any_received = false;
    let mut any_duplicate = false;
    let mut first_rejected: Option<String> = None;

    for mb in &target_mailboxes {
        let mb_state = state.for_mailbox(mb);
        let outcome = ingest_inbound_rfc2822(
            mb_state.store.as_ref(),
            &mb_state.events,
            filter,
            base_envelope.clone(),
        )
        .await?;

        match outcome {
            IngestOutcome::Stored { message, decision } => {
                mb_state.post_store_message(&message).await?;
                let filter_label = match decision {
                    FilterDecision::Allow => "allow",
                    FilterDecision::Spam { .. } => "spam",
                    FilterDecision::Reject { .. } => "reject",
                    FilterDecision::Mutate { .. } => "mutate",
                };
                any_received = true;
                if first_received.is_none() {
                    first_received = Some((
                        message.id.clone(),
                        message.thread_id.clone(),
                        message.label_ids.clone(),
                        filter_label,
                    ));
                }
                deliveries.push(json!({
                    "mailbox_id": mb,
                    "status": "received",
                    "message_id": message.id,
                    "thread_id": message.thread_id,
                    "labels": message.label_ids,
                    "filter_decision": filter_label,
                }));
            }
            IngestOutcome::Duplicate { message } => {
                any_duplicate = true;
                deliveries.push(json!({
                    "mailbox_id": mb,
                    "status": "duplicate",
                    "message_id": message.id,
                    "thread_id": message.thread_id,
                }));
            }
            IngestOutcome::Rejected { reason } => {
                if first_rejected.is_none() {
                    first_rejected = Some(reason.clone());
                }
                deliveries.push(json!({
                    "mailbox_id": mb,
                    "status": "rejected",
                    "reason": reason,
                }));
            }
        }
    }

    if let Some((msg_id, thread_id, labels, filter_label)) = first_received {
        Ok((
            StatusCode::OK,
            Json(json!({
                "status": "received",
                "message_id": msg_id,
                "thread_id": thread_id,
                "labels": labels,
                "filter_decision": filter_label,
                "deliveries": deliveries,
            })),
        )
            .into_response())
    } else if any_duplicate && !any_received {
        Ok((
            StatusCode::OK,
            Json(json!({
                "status": "duplicate",
                "deliveries": deliveries,
            })),
        )
            .into_response())
    } else {
        Ok((
            StatusCode::OK,
            Json(json!({
                "status": "rejected",
                "reason": first_rejected.unwrap_or_else(|| "rejected".to_string()),
                "deliveries": deliveries,
            })),
        )
            .into_response())
    }
}

async fn handle_delivery_status(
    state: &AppState,
    event: &ResendWebhookEvent,
    status: &str,
) -> AppResult<Response> {
    let resend_id = event.data.email_id.trim();
    let detail = format_bounce_detail(event.data.bounce.as_ref());
    let norm_mid = event
        .data
        .message_id
        .as_deref()
        .and_then(crate::mime::normalize_message_id);

    let mut target_state: Option<AppState> = None;
    let mut message_id = String::new();

    for mb in state.config.known_mailboxes() {
        let mb_state = state.for_mailbox(&mb);
        if !resend_id.is_empty()
            && let Some(msg) = mb_state
                .store
                .record_delivery_status(resend_id, status)
                .await?
        {
            message_id = msg.id;
            target_state = Some(mb_state);
            break;
        }
        if let Some(ref mid) = norm_mid
            && let Some(msg) = mb_state.store.find_message_by_rfc_message_id(mid).await?
        {
            message_id = msg.id;
            target_state = Some(mb_state);
            break;
        }
    }

    let publish_state = target_state.as_ref().unwrap_or(state);
    publish_state.events.publish(
        EventSource::ResendWebhook,
        MailEvent::DeliveryStatus {
            message_id: message_id.clone(),
            resend_id: resend_id.to_string(),
            status: status.to_string(),
            detail: detail.clone(),
        },
    );

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "recorded",
            "delivery_status": status,
            "resend_id": resend_id,
            "message_id": message_id,
            "detail": detail,
        })),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::*;
    use crate::{
        config::Config,
        models::{AttachmentMeta, LABEL_SPAM, Profile},
        resend::{
            HttpResendClient, ResendClient,
            filter::{FilterDecision, InboundFilter, InboundMessage},
            svix::sign_svix_payload,
            transport::{InboundEnvelope, IngestOutcome, ingest_inbound_rfc2822},
        },
        storage::{
            AiMessagePage, AiSearchQuery, AiThreadPage, AiThreadQuery, DraftListPage,
            HistoryListPage, HistoryListQuery, ImapMailboxInfo, ImapMessageEntry, MailStore,
            MessageListPage, MessageListQuery, NewLabelInput, NewMessageInput, StoredAttachment,
            StoredDraft, StoredLabel, StoredMessage, StoredThreadDetail, SyncState, ThreadListPage,
            TriagePatch, TriageResult, UpdateLabelInput, UpsertOutcome, UserSettings,
            WatchSubscription,
        },
    };
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    const WEBHOOK_SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";

    /// Minimal self-contained in-memory `MailStore` for isolated `resend` unit tests.
    #[derive(Clone, Default)]
    struct MockStore {
        messages: Arc<Mutex<Vec<StoredMessage>>>,
        next_id: Arc<Mutex<u64>>,
    }

    impl MockStore {
        fn push_existing(&self, msg: StoredMessage) {
            self.messages.lock().unwrap().push(msg);
        }

        fn all_messages(&self) -> Vec<StoredMessage> {
            self.messages.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl MailStore for MockStore {
        fn mailbox_id(&self) -> &str {
            "agent@example.com"
        }
        fn for_mailbox(&self, _mailbox_id: &str) -> Arc<dyn MailStore> {
            Arc::new(self.clone())
        }
        async fn get_profile(&self, _email_address: &str) -> AppResult<Profile> {
            unreachable!()
        }
        async fn current_history_id(&self) -> AppResult<u64> {
            Ok(1)
        }
        async fn list_history(&self, _query: &HistoryListQuery) -> AppResult<HistoryListPage> {
            unreachable!()
        }
        async fn insert_message(&self, input: NewMessageInput) -> AppResult<StoredMessage> {
            let mut seq = self.next_id.lock().unwrap();
            *seq += 1;
            let id = input.id.unwrap_or_else(|| format!("msg_{}", *seq));
            let thread_id = input.thread_id.unwrap_or_else(|| format!("thr_{}", *seq));
            let stored = StoredMessage {
                id,
                thread_id,
                label_ids: input.label_ids,
                size_estimate: input.raw_rfc2822.len() as i32,
                raw_rfc2822: input.raw_rfc2822,
                snippet: input.snippet,
                history_id: *seq,
                internal_date_ms: input.internal_date_ms,
                subject: input.subject,
                from_addr: input.from_addr,
                to_addrs: input.to_addrs,
                cc_addrs: input.cc_addrs,
                bcc_addrs: input.bcc_addrs,
                text_body: input.text_body,
                html_body: input.html_body,
                has_attachments: !input.attachments.is_empty(),
                rfc822_message_id: input.rfc822_message_id,
                in_reply_to: input.in_reply_to,
                references_header: input.references_header,
                resend_id: input.resend_id,
                delivery_status: None,
                upstream_gmail_id: input.upstream_gmail_id,
                upstream_thread_id: input.upstream_thread_id,
                source: input.source,
                all_mail_uid: *seq as u32,
                is_answered: input.is_answered,
                is_deleted: input.is_deleted,
            };
            self.messages.lock().unwrap().push(stored.clone());
            Ok(stored)
        }
        async fn get_message(&self, id: &str) -> AppResult<Option<StoredMessage>> {
            Ok(self
                .messages
                .lock()
                .unwrap()
                .iter()
                .find(|m| m.id == id)
                .cloned())
        }
        async fn list_messages(&self, _query: &MessageListQuery) -> AppResult<MessageListPage> {
            unreachable!()
        }
        async fn modify_message_labels(
            &self,
            _id: &str,
            _add_labels: &[String],
            _remove_labels: &[String],
        ) -> AppResult<StoredMessage> {
            unreachable!()
        }
        async fn batch_modify_labels(
            &self,
            _ids: &[String],
            _add_labels: &[String],
            _remove_labels: &[String],
        ) -> AppResult<()> {
            unreachable!()
        }
        async fn trash_message(&self, _id: &str) -> AppResult<StoredMessage> {
            unreachable!()
        }
        async fn untrash_message(&self, _id: &str) -> AppResult<StoredMessage> {
            unreachable!()
        }
        async fn delete_message(&self, _id: &str) -> AppResult<bool> {
            unreachable!()
        }
        async fn batch_delete_messages(&self, _ids: &[String]) -> AppResult<()> {
            unreachable!()
        }
        async fn get_attachment(
            &self,
            _message_id: &str,
            _attachment_id: &str,
        ) -> AppResult<Option<StoredAttachment>> {
            unreachable!()
        }
        async fn list_attachment_meta(&self, _message_id: &str) -> AppResult<Vec<AttachmentMeta>> {
            unreachable!()
        }
        async fn list_threads(&self, _query: &MessageListQuery) -> AppResult<ThreadListPage> {
            unreachable!()
        }
        async fn get_thread(&self, _thread_id: &str) -> AppResult<Option<StoredThreadDetail>> {
            unreachable!()
        }
        async fn modify_thread_labels(
            &self,
            _thread_id: &str,
            _add_labels: &[String],
            _remove_labels: &[String],
        ) -> AppResult<StoredThreadDetail> {
            unreachable!()
        }
        async fn trash_thread(&self, _thread_id: &str) -> AppResult<StoredThreadDetail> {
            unreachable!()
        }
        async fn untrash_thread(&self, _thread_id: &str) -> AppResult<StoredThreadDetail> {
            unreachable!()
        }
        async fn delete_thread(&self, _thread_id: &str) -> AppResult<bool> {
            unreachable!()
        }
        async fn list_labels(&self) -> AppResult<Vec<StoredLabel>> {
            unreachable!()
        }
        async fn get_label(&self, _id: &str) -> AppResult<Option<StoredLabel>> {
            unreachable!()
        }
        async fn create_label(&self, _input: NewLabelInput) -> AppResult<StoredLabel> {
            unreachable!()
        }
        async fn update_label(
            &self,
            _id: &str,
            _input: UpdateLabelInput,
            _full_replace: bool,
        ) -> AppResult<StoredLabel> {
            unreachable!()
        }
        async fn delete_label(&self, _id: &str) -> AppResult<()> {
            unreachable!()
        }
        async fn upsert_upstream_label(&self, _input: NewLabelInput) -> AppResult<StoredLabel> {
            unreachable!()
        }
        async fn list_drafts(&self, _query: &MessageListQuery) -> AppResult<DraftListPage> {
            unreachable!()
        }
        async fn get_draft(&self, _id: &str) -> AppResult<Option<StoredDraft>> {
            unreachable!()
        }
        async fn create_draft(&self, _message: NewMessageInput) -> AppResult<StoredDraft> {
            unreachable!()
        }
        async fn update_draft(
            &self,
            _draft_id: &str,
            _message: NewMessageInput,
        ) -> AppResult<StoredDraft> {
            unreachable!()
        }
        async fn delete_draft(&self, _draft_id: &str) -> AppResult<bool> {
            unreachable!()
        }
        async fn search_messages_ai(&self, _query: &AiSearchQuery) -> AppResult<AiMessagePage> {
            unreachable!()
        }
        async fn list_thread_summaries(&self, _query: &AiThreadQuery) -> AppResult<AiThreadPage> {
            unreachable!()
        }
        async fn triage_thread(
            &self,
            _thread_id: &str,
            _patch: &TriagePatch,
        ) -> AppResult<TriageResult> {
            unreachable!()
        }
        async fn find_message_by_resend_id(
            &self,
            resend_id: &str,
        ) -> AppResult<Option<StoredMessage>> {
            Ok(self
                .messages
                .lock()
                .unwrap()
                .iter()
                .find(|m| m.resend_id.as_deref() == Some(resend_id))
                .cloned())
        }
        async fn find_message_by_rfc_message_id(
            &self,
            rfc822_message_id: &str,
        ) -> AppResult<Option<StoredMessage>> {
            Ok(self
                .messages
                .lock()
                .unwrap()
                .iter()
                .find(|m| {
                    m.rfc822_message_id
                        .as_deref()
                        .is_some_and(|mid| mid.eq_ignore_ascii_case(rfc822_message_id))
                })
                .cloned())
        }
        async fn record_delivery_status(
            &self,
            resend_id: &str,
            status: &str,
        ) -> AppResult<Option<StoredMessage>> {
            let mut msgs = self.messages.lock().unwrap();
            if let Some(msg) = msgs
                .iter_mut()
                .find(|m| m.resend_id.as_deref() == Some(resend_id))
            {
                msg.delivery_status = Some(status.to_string());
                return Ok(Some(msg.clone()));
            }
            Ok(None)
        }
        async fn imap_list_mailboxes(&self) -> AppResult<Vec<ImapMailboxInfo>> {
            unreachable!()
        }
        async fn imap_mailbox_info(
            &self,
            _mailbox_name: &str,
        ) -> AppResult<Option<ImapMailboxInfo>> {
            unreachable!()
        }
        async fn imap_list_messages(
            &self,
            _mailbox_name: &str,
        ) -> AppResult<Vec<ImapMessageEntry>> {
            unreachable!()
        }
        async fn imap_set_flags(
            &self,
            _message_id: &str,
            _is_seen: bool,
            _is_flagged: bool,
            _is_draft: bool,
            _is_answered: bool,
            _is_deleted: bool,
        ) -> AppResult<StoredMessage> {
            unreachable!()
        }
        async fn imap_expunge(&self, _mailbox_name: &str) -> AppResult<Vec<u32>> {
            unreachable!()
        }
        async fn imap_copy_or_move(
            &self,
            _src_mailbox: &str,
            _dst_mailbox: &str,
            _message_ids: &[String],
            _is_move: bool,
        ) -> AppResult<Vec<(u32, u32)>> {
            unreachable!()
        }
        async fn imap_append(
            &self,
            _mailbox_name: &str,
            _input: NewMessageInput,
        ) -> AppResult<(u32, u32, StoredMessage)> {
            unreachable!()
        }
        async fn upsert_synced_message(&self, _input: NewMessageInput) -> AppResult<UpsertOutcome> {
            unreachable!()
        }
        async fn find_message_by_upstream_id(
            &self,
            _upstream_gmail_id: &str,
        ) -> AppResult<Option<StoredMessage>> {
            unreachable!()
        }
        async fn delete_message_by_upstream_id(
            &self,
            _upstream_gmail_id: &str,
        ) -> AppResult<Option<StoredMessage>> {
            unreachable!()
        }
        async fn get_sync_state(&self, _account_key: &str) -> AppResult<Option<SyncState>> {
            unreachable!()
        }
        async fn save_sync_state(&self, _state: SyncState) -> AppResult<()> {
            unreachable!()
        }
        async fn list_sync_states(&self) -> AppResult<Vec<SyncState>> {
            unreachable!()
        }
        async fn set_watch(&self, _watch: WatchSubscription) -> AppResult<WatchSubscription> {
            unreachable!()
        }
        async fn get_watch(&self) -> AppResult<Option<WatchSubscription>> {
            unreachable!()
        }
        async fn clear_watch(&self) -> AppResult<()> {
            unreachable!()
        }
        async fn get_settings(&self) -> AppResult<UserSettings> {
            unreachable!()
        }
        async fn save_settings(&self, _settings: UserSettings) -> AppResult<UserSettings> {
            unreachable!()
        }
        async fn create_pending_approval(
            &self,
            _input: crate::storage::NewPendingApprovalInput,
        ) -> AppResult<crate::storage::PendingApproval> {
            unreachable!()
        }
        async fn get_pending_approval(
            &self,
            _id: &str,
        ) -> AppResult<Option<crate::storage::PendingApproval>> {
            unreachable!()
        }
        async fn list_pending_approvals(
            &self,
            _status: Option<crate::storage::ApprovalStatus>,
            _limit: usize,
        ) -> AppResult<Vec<crate::storage::PendingApproval>> {
            unreachable!()
        }
        async fn resolve_pending_approval(
            &self,
            _id: &str,
            _status: crate::storage::ApprovalStatus,
            _decided_by: Option<String>,
            _note: Option<String>,
            _sent_message_id: Option<String>,
            _provider_message_id: Option<String>,
        ) -> AppResult<crate::storage::PendingApproval> {
            unreachable!()
        }
        async fn record_contact_interaction(
            &self,
            interaction: &crate::storage::ContactInteraction,
        ) -> AppResult<crate::storage::ContactRecord> {
            let (email, domain) =
                crate::storage::validate_and_normalize_contact_email(&interaction.email)?;
            Ok(crate::storage::ContactRecord {
                email,
                display_name: interaction.display_name.clone(),
                domain,
                sent_count: u64::from(
                    interaction.direction == crate::storage::ContactDirection::Sent,
                ),
                received_count: u64::from(
                    interaction.direction == crate::storage::ContactDirection::Received,
                ),
                replied_by_me_count: u64::from(
                    interaction.direction == crate::storage::ContactDirection::Sent
                        && interaction.is_reply,
                ),
                first_seen_at_ms: interaction.timestamp_ms,
                last_seen_at_ms: interaction.timestamp_ms,
                last_replied_at_ms: None,
                is_vip: false,
                vip_override: None,
                notes: None,
            })
        }
        async fn get_contact(
            &self,
            _email: &str,
        ) -> AppResult<Option<crate::storage::ContactRecord>> {
            Ok(None)
        }
        async fn list_contacts(
            &self,
            _query: &crate::storage::ContactQuery,
        ) -> AppResult<Vec<crate::storage::ContactRecord>> {
            Ok(Vec::new())
        }
        async fn patch_contact(
            &self,
            email: &str,
            patch: &crate::storage::ContactPatch,
        ) -> AppResult<crate::storage::ContactRecord> {
            let (email, domain) = crate::storage::validate_and_normalize_contact_email(email)?;
            Ok(crate::storage::ContactRecord {
                email,
                display_name: patch.display_name.clone(),
                domain,
                sent_count: 0,
                received_count: 0,
                replied_by_me_count: 0,
                first_seen_at_ms: 0,
                last_seen_at_ms: 0,
                last_replied_at_ms: None,
                is_vip: patch.is_vip.unwrap_or(false),
                vip_override: patch.is_vip,
                notes: patch.notes.clone(),
            })
        }
        async fn get_thread_annotation(
            &self,
            _thread_id: &str,
        ) -> AppResult<Option<crate::models::ThreadAnnotation>> {
            unreachable!()
        }
        async fn upsert_thread_annotation(
            &self,
            _thread_id: &str,
            _annotation: &crate::models::ThreadAnnotation,
        ) -> AppResult<crate::models::ThreadAnnotation> {
            unreachable!()
        }
        async fn patch_thread_annotation(
            &self,
            _thread_id: &str,
            _patch: &crate::models::ThreadAnnotationPatch,
            _updated_by: Option<&str>,
        ) -> AppResult<crate::models::ThreadAnnotation> {
            unreachable!()
        }
        async fn delete_thread_annotation(&self, _thread_id: &str) -> AppResult<()> {
            unreachable!()
        }
        async fn get_idempotency_key(
            &self,
            _scope: &str,
            _key: &str,
            _now_ms: i64,
        ) -> AppResult<Option<crate::storage::IdempotencyRecord>> {
            Ok(None)
        }
        async fn put_idempotency_key(
            &self,
            _scope: &str,
            _key: &str,
            _response_json: &str,
            _ttl_secs: i64,
        ) -> AppResult<()> {
            Ok(())
        }
        async fn append_audit_log(
            &self,
            entry: &crate::storage::NewAuditLogEntry,
        ) -> AppResult<crate::storage::AuditLogEntry> {
            Ok(crate::storage::AuditLogEntry {
                id: format!("aud_{}", uuid::Uuid::new_v4().simple()),
                mailbox_id: self.mailbox_id().to_string(),
                timestamp_ms: entry
                    .timestamp_ms
                    .unwrap_or_else(|| Utc::now().timestamp_millis()),
                actor: entry.actor.clone(),
                scopes: entry.scopes.clone(),
                channel: entry.channel.clone(),
                action: entry.action.clone(),
                target_ids: entry.target_ids.clone(),
                outcome: entry.outcome.clone(),
                detail: entry.detail.clone(),
            })
        }
        async fn list_audit_log(
            &self,
            _query: &crate::storage::AuditLogQuery,
        ) -> AppResult<Vec<crate::storage::AuditLogEntry>> {
            Ok(Vec::new())
        }
        async fn snooze_thread(
            &self,
            _thread_id: &str,
            _until_ms: i64,
        ) -> AppResult<crate::storage::SnoozedThread> {
            unreachable!()
        }
        async fn unsnooze_thread(&self, _thread_id: &str) -> AppResult<bool> {
            Ok(false)
        }
        async fn list_snoozed_threads(
            &self,
            _due_before_ms: Option<i64>,
        ) -> AppResult<Vec<crate::storage::SnoozedThread>> {
            Ok(Vec::new())
        }
        async fn list_all_due_snoozes(
            &self,
            _now_ms: i64,
        ) -> AppResult<Vec<crate::storage::SnoozedThread>> {
            Ok(Vec::new())
        }
        async fn create_scheduled_send(
            &self,
            _input: &crate::storage::NewScheduledSend,
        ) -> AppResult<crate::storage::ScheduledSend> {
            unreachable!()
        }
        async fn get_scheduled_send(
            &self,
            _id: &str,
        ) -> AppResult<Option<crate::storage::ScheduledSend>> {
            Ok(None)
        }
        async fn list_scheduled_sends(
            &self,
            _status: Option<crate::storage::ScheduledSendStatus>,
            _limit: usize,
        ) -> AppResult<Vec<crate::storage::ScheduledSend>> {
            Ok(Vec::new())
        }
        async fn cancel_scheduled_send(
            &self,
            _id: &str,
        ) -> AppResult<crate::storage::ScheduledSend> {
            unreachable!()
        }
        async fn claim_due_scheduled_sends(
            &self,
            _now_ms: i64,
        ) -> AppResult<Vec<crate::storage::ScheduledSend>> {
            Ok(Vec::new())
        }
        async fn complete_scheduled_send(
            &self,
            _id: &str,
            _sent_message_id: &str,
            _provider_message_id: &str,
        ) -> AppResult<crate::storage::ScheduledSend> {
            unreachable!()
        }
        async fn fail_scheduled_send(
            &self,
            _id: &str,
            _error: &str,
        ) -> AppResult<crate::storage::ScheduledSend> {
            unreachable!()
        }

        async fn create_inbox_rule(
            &self,
            _input: &crate::storage::NewInboxRule,
        ) -> AppResult<crate::storage::InboxRule> {
            Err(crate::error::AppError::Storage(
                "unimplemented in mock".to_string(),
            ))
        }

        async fn get_inbox_rule(&self, _id: &str) -> AppResult<Option<crate::storage::InboxRule>> {
            Ok(None)
        }

        async fn list_inbox_rules(&self) -> AppResult<Vec<crate::storage::InboxRule>> {
            Ok(Vec::new())
        }

        async fn patch_inbox_rule(
            &self,
            id: &str,
            _patch: &crate::storage::InboxRulePatch,
        ) -> AppResult<crate::storage::InboxRule> {
            Err(crate::error::AppError::NotFound(format!(
                "Inbox rule not found: {id}"
            )))
        }

        async fn delete_inbox_rule(&self, id: &str) -> AppResult<()> {
            Err(crate::error::AppError::NotFound(format!(
                "Inbox rule not found: {id}"
            )))
        }
    }

    fn test_state(
        secret: Option<String>,
        store: Arc<MockStore>,
        resend: Arc<dyn ResendClient>,
    ) -> AppState {
        let mut config = Config::for_test();
        config.resend_webhook_secret = secret;
        AppState::with_backends(config, store, resend)
    }

    async fn read_json(resp: Response) -> Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn webhook_rejects_unsigned_when_secret_configured() {
        let store = Arc::new(MockStore::default());
        let resend = Arc::new(HttpResendClient::new("http://127.0.0.1:9", None));
        let state = test_state(Some(WEBHOOK_SECRET.to_string()), store, resend);
        let app = resend_router().with_state(state);

        let payload = json!({
            "type": "email.delivered",
            "created_at": "2026-01-01T00:00:00Z",
            "data": { "email_id": "em_1" }
        })
        .to_string();

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/resend")
                    .header("content-type", "application/json")
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn webhook_handles_delivery_status_events_and_publishes_event() {
        let store = Arc::new(MockStore::default());
        store.push_existing(StoredMessage {
            id: "local_msg_1".to_string(),
            thread_id: "thr_1".to_string(),
            label_ids: vec!["SENT".to_string()],
            raw_rfc2822: Vec::new(),
            snippet: "Hello".to_string(),
            history_id: 1,
            internal_date_ms: 1_700_000_000_000,
            size_estimate: 10,
            subject: "Hello".to_string(),
            from_addr: "agent@example.com".to_string(),
            to_addrs: vec!["alice@example.com".to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: "Hello".to_string(),
            html_body: None,
            has_attachments: false,
            rfc822_message_id: Some("<sent-1@example.com>".to_string()),
            in_reply_to: None,
            references_header: None,
            resend_id: Some("re_outbound_1".to_string()),
            delivery_status: None,
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "local".to_string(),
            all_mail_uid: 1,
            is_answered: false,
            is_deleted: false,
        });

        let resend = Arc::new(HttpResendClient::new("http://127.0.0.1:9", None));
        let state = test_state(Some(WEBHOOK_SECRET.to_string()), store.clone(), resend);
        let mut rx = state.events.subscribe();
        let app = resend_router().with_state(state);

        let payload = json!({
            "type": "email.bounced",
            "created_at": "2026-01-01T00:05:00Z",
            "data": {
                "email_id": "re_outbound_1",
                "bounce": {
                    "type": "Permanent",
                    "subType": "General",
                    "message": "Mailbox does not exist"
                }
            }
        })
        .to_string();

        let now = Utc::now().timestamp();
        let sig =
            sign_svix_payload("msg_bounce_1", now, payload.as_bytes(), WEBHOOK_SECRET).unwrap();

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/resend")
                    .header("content-type", "application/json")
                    .header("svix-id", "msg_bounce_1")
                    .header("svix-timestamp", now.to_string())
                    .header("svix-signature", sig)
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_json(resp).await;
        assert_eq!(body["delivery_status"], "bounced");
        assert_eq!(body["message_id"], "local_msg_1");
        assert_eq!(body["detail"], "Permanent/General: Mailbox does not exist");

        let stored = store.all_messages();
        assert_eq!(stored[0].delivery_status.as_deref(), Some("bounced"));

        let env = rx
            .try_recv()
            .expect("DeliveryStatus event should be published");
        assert_eq!(env.source, EventSource::ResendWebhook);
        match env.event {
            MailEvent::DeliveryStatus {
                message_id,
                resend_id,
                status,
                detail,
            } => {
                assert_eq!(message_id, "local_msg_1");
                assert_eq!(resend_id, "re_outbound_1");
                assert_eq!(status, "bounced");
                assert_eq!(
                    detail.as_deref(),
                    Some("Permanent/General: Mailbox does not exist")
                );
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn webhook_dev_bypass_works_when_secret_is_none() {
        let store = Arc::new(MockStore::default());
        let resend = Arc::new(HttpResendClient::new("http://127.0.0.1:9", None));
        let state = test_state(None, store, resend);
        let mut rx = state.events.subscribe();
        let app = resend_router().with_state(state);

        for (event_type, expected_status) in [
            ("email.sent", "sent"),
            ("email.delivered", "delivered"),
            ("email.delivery_delayed", "delivery_delayed"),
            ("email.complained", "complained"),
            ("email.opened", "opened"),
            ("email.clicked", "clicked"),
            ("email.failed", "failed"),
            ("email.scheduled", "scheduled"),
        ] {
            let payload = json!({
                "type": event_type,
                "created_at": "2026-01-01T00:00:00Z",
                "data": { "email_id": "re_dev_1" }
            })
            .to_string();

            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/webhooks/resend")
                        .header("content-type", "application/json")
                        .body(Body::from(payload))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            let env = rx.try_recv().expect("event published");
            match env.event {
                MailEvent::DeliveryStatus { status, .. } => assert_eq!(status, expected_status),
                other => panic!("unexpected event: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn webhook_ignores_unknown_event_type_with_200() {
        let store = Arc::new(MockStore::default());
        let resend = Arc::new(HttpResendClient::new("http://127.0.0.1:9", None));
        let state = test_state(None, store, resend);
        let app = resend_router().with_state(state);

        let payload = json!({
            "type": "domain.updated",
            "created_at": "2026-01-01T00:00:00Z",
            "data": {}
        })
        .to_string();

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/resend")
                    .header("content-type", "application/json")
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_json(resp).await;
        assert_eq!(body["status"], "ignored");
    }

    #[test]
    fn bounce_detail_formatting_handles_partial_fields() {
        assert_eq!(format_bounce_detail(None), None);
        assert_eq!(
            format_bounce_detail(Some(&ResendBounceInfo {
                message: Some("Rejected".into()),
                sub_type: None,
                bounce_type: Some("Permanent".into()),
            })),
            Some("Permanent: Rejected".to_string())
        );
        assert_eq!(
            format_bounce_detail(Some(&ResendBounceInfo {
                message: None,
                sub_type: Some("Suppressed".into()),
                bounce_type: Some("Permanent".into()),
            })),
            Some("Permanent/Suppressed".to_string())
        );
    }

    #[tokio::test]
    async fn webhook_rejects_malformed_json_with_400() {
        let store = Arc::new(MockStore::default());
        let resend = Arc::new(HttpResendClient::new("http://127.0.0.1:9", None));
        let state = test_state(None, store, resend);
        let app = resend_router().with_state(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/resend")
                    .header("content-type", "application/json")
                    .body(Body::from("{not-json"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn webhook_email_received_fetches_full_email_attachments_threads_and_dedups() {
        let server = MockServer::start().await;
        let att_url = format!("{}/downloads/doc.txt", server.uri());

        Mock::given(method("GET"))
            .and(path("/emails/receiving/re_in_1"))
            .and(header("authorization", "Bearer re_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "object": "email",
                "id": "re_in_1",
                "from": "Alice <alice@external.com>",
                "to": ["agent@example.com"],
                "subject": "Re: Project Plan",
                "text": "Looks great, see attachment!",
                "html": "<p>Looks great, see attachment!</p>",
                "created_at": "2026-01-02T10:00:00Z",
                "message_id": "<reply-1@external.com>",
                "headers": {
                    "In-Reply-To": "<orig-plan@example.com>",
                    "References": "<orig-plan@example.com>"
                },
                "attachments": [{
                    "id": "att_1",
                    "filename": "doc.txt",
                    "content_type": "text/plain",
                    "content_disposition": "attachment"
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/emails/receiving/re_in_1/attachments"))
            .and(header("authorization", "Bearer re_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "object": "list",
                "has_more": false,
                "data": [{
                    "id": "att_1",
                    "filename": "doc.txt",
                    "size": 11,
                    "content_type": "text/plain",
                    "download_url": att_url
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/downloads/doc.txt"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"hello world"))
            .expect(1)
            .mount(&server)
            .await;

        let store = Arc::new(MockStore::default());
        // Seed parent message so In-Reply-To resolves to "thr_parent".
        store.push_existing(StoredMessage {
            id: "msg_parent".to_string(),
            thread_id: "thr_parent".to_string(),
            label_ids: vec!["SENT".to_string()],
            raw_rfc2822: Vec::new(),
            snippet: "Initial plan".to_string(),
            history_id: 1,
            internal_date_ms: 1_700_000_000_000,
            size_estimate: 10,
            subject: "Project Plan".to_string(),
            from_addr: "agent@example.com".to_string(),
            to_addrs: vec!["alice@external.com".to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: "Initial plan".to_string(),
            html_body: None,
            has_attachments: false,
            rfc822_message_id: Some("<orig-plan@example.com>".to_string()),
            in_reply_to: None,
            references_header: None,
            resend_id: Some("re_orig".to_string()),
            delivery_status: Some("delivered".to_string()),
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "local".to_string(),
            all_mail_uid: 1,
            is_answered: false,
            is_deleted: false,
        });

        let resend = Arc::new(HttpResendClient::new(server.uri(), Some("re_key".into())));
        let state = test_state(Some(WEBHOOK_SECRET.into()), store.clone(), resend);
        let mut rx = state.events.subscribe();
        let app = resend_router().with_state(state);

        let payload = json!({
            "type": "email.received",
            "created_at": "2026-01-02T10:00:00Z",
            "data": {
                "email_id": "re_in_1",
                "from": "Alice <alice@external.com>",
                "to": ["agent@example.com"],
                "subject": "Re: Project Plan",
                "message_id": "<reply-1@external.com>",
                "attachments": [{
                    "id": "att_1",
                    "filename": "doc.txt",
                    "content_type": "text/plain"
                }]
            }
        })
        .to_string();

        let now = Utc::now().timestamp();
        let sig = sign_svix_payload("msg_in_1", now, payload.as_bytes(), WEBHOOK_SECRET).unwrap();

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/resend")
                    .header("content-type", "application/json")
                    .header("webhook-id", "msg_in_1")
                    .header("webhook-timestamp", now.to_string())
                    .header("webhook-signature", sig.clone())
                    .body(Body::from(payload.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_json(resp).await;
        assert_eq!(body["status"], "received");
        assert_eq!(body["thread_id"], "thr_parent");

        let msgs = store.all_messages();
        assert_eq!(msgs.len(), 2);
        let stored = &msgs[1];
        assert_eq!(stored.thread_id, "thr_parent");
        assert_eq!(stored.label_ids, vec![LABEL_INBOX, LABEL_UNREAD]);
        assert!(stored.has_attachments);
        assert_eq!(stored.source, "resend_inbound");
        assert!(stored.text_body.contains("Looks great"));
        assert!(!stored.raw_rfc2822.is_empty());

        let env = rx
            .try_recv()
            .expect("MessageReceived event should be published");
        assert_eq!(env.source, EventSource::ResendInbound);
        match env.event {
            MailEvent::MessageReceived {
                thread_id,
                subject,
                labels,
                ..
            } => {
                assert_eq!(thread_id, "thr_parent");
                assert_eq!(subject, "Re: Project Plan");
                assert_eq!(labels, vec![LABEL_INBOX, LABEL_UNREAD]);
            }
            other => panic!("unexpected event: {other:?}"),
        }

        // Sending the exact same webhook again deduplicates cleanly (no second Receiving API call, no second event).
        let dup_resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/resend")
                    .header("content-type", "application/json")
                    .header("webhook-id", "msg_in_1")
                    .header("webhook-timestamp", now.to_string())
                    .header("webhook-signature", sig)
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(dup_resp.status(), StatusCode::OK);
        let dup_body = read_json(dup_resp).await;
        assert_eq!(dup_body["status"], "duplicate");
        assert_eq!(store.all_messages().len(), 2);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn webhook_email_received_falls_back_gracefully_when_receiving_api_fails() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/emails/receiving/re_fail_1"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "statusCode": 500,
                "name": "application_error",
                "message": "temporary outage"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let store = Arc::new(MockStore::default());
        let resend = Arc::new(HttpResendClient::new(server.uri(), Some("re_key".into())));
        let state = test_state(None, store.clone(), resend);
        let mut rx = state.events.subscribe();
        let app = resend_router().with_state(state);

        let payload = json!({
            "type": "email.received",
            "created_at": "2026-01-03T12:00:00Z",
            "data": {
                "email_id": "re_fail_1",
                "from": "bob@external.com",
                "to": ["agent@example.com"],
                "subject": "Fallback Subject",
                "message_id": "<fallback-1@external.com>"
            }
        })
        .to_string();

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/resend")
                    .header("content-type", "application/json")
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_json(resp).await;
        assert_eq!(body["status"], "received");

        let msgs = store.all_messages();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].subject, "Fallback Subject");
        assert_eq!(msgs[0].label_ids, vec![LABEL_INBOX, LABEL_UNREAD]);
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn ingest_inbound_rfc2822_applies_inbound_filter_spam_reject_and_mutate() {
        struct FixedFilter(FilterDecision);
        #[async_trait]
        impl InboundFilter for FixedFilter {
            async fn evaluate(&self, _msg: &InboundMessage) -> AppResult<FilterDecision> {
                Ok(self.0.clone())
            }
        }

        let raw_msg = b"From: sender@example.com\r\nTo: agent@example.com\r\nSubject: Filtered\r\nMessage-ID: <f1@example.com>\r\n\r\nBody text";
        let store = Arc::new(MockStore::default());
        let events = crate::events::EventBus::new();
        let mut rx = events.subscribe();

        // 1. Reject drops before storage and publishes nothing.
        let rejected = ingest_inbound_rfc2822(
            store.as_ref(),
            &events,
            &FixedFilter(FilterDecision::Reject {
                reason: "blocked".into(),
            }),
            InboundEnvelope {
                raw_rfc2822: raw_msg.to_vec(),
                source: "smtp".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(matches!(rejected, IngestOutcome::Rejected { .. }));
        assert!(store.all_messages().is_empty());
        assert!(rx.try_recv().is_err());

        // 2. Spam routes to SPAM and removes INBOX.
        let spam = ingest_inbound_rfc2822(
            store.as_ref(),
            &events,
            &FixedFilter(FilterDecision::Spam {
                score: 9.2,
                reason: "phish".into(),
            }),
            InboundEnvelope {
                raw_rfc2822: raw_msg.to_vec(),
                source: "ses_s3".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        match spam {
            IngestOutcome::Stored { message, .. } => {
                assert!(!message.label_ids.contains(&LABEL_INBOX.to_string()));
                assert!(message.label_ids.contains(&LABEL_SPAM.to_string()));
            }
            other => panic!("expected Stored spam, got {other:?}"),
        }
        assert!(rx.try_recv().is_ok());

        // 3. Mutate applies custom labels and skip_inbox.
        let raw_msg2 = b"From: news@example.com\r\nTo: agent@example.com\r\nSubject: Digest\r\nMessage-ID: <f2@example.com>\r\n\r\nDigest body";
        let mutated = ingest_inbound_rfc2822(
            store.as_ref(),
            &events,
            &FixedFilter(FilterDecision::Mutate {
                add_labels: vec!["NEWSLETTERS".into()],
                remove_labels: vec![LABEL_UNREAD.into()],
                skip_inbox: true,
            }),
            InboundEnvelope {
                raw_rfc2822: raw_msg2.to_vec(),
                source: "resend_inbound".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        match mutated {
            IngestOutcome::Stored { message, .. } => {
                assert_eq!(message.label_ids, vec!["NEWSLETTERS".to_string()]);
            }
            other => panic!("expected Stored mutated, got {other:?}"),
        }
    }
}
