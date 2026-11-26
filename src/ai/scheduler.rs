//! Thread snooze, scheduled outbound send management, and background scheduler loop.

use std::{
    collections::HashSet,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::{
    AppState,
    ai::{
        MAX_LIST_LIMIT, channel_for_source,
        safety::{OutboundCheck, OutboundDecision},
        validate_resource_id,
    },
    auth::Principal,
    error::{AppError, AppResult},
    events::{EventSource, MailEvent},
    mime::generate_snippet,
    models::{
        LABEL_INBOX, LABEL_SENT, LABEL_SNOOZED, LABEL_UNREAD, SnoozeThreadRequest,
        truncate_to_millis,
    },
    storage::{
        DEFAULT_SCHEDULED_SEND_STALE_LEASE_MS, NewAttachmentInput, NewLabelInput, NewMessageInput,
        ScheduledSendStatus, TriagePatch,
    },
};

/// Default background scheduler polling interval in seconds.
pub const DEFAULT_SCHEDULER_INTERVAL_SECS: u64 = 15;

/// Summary of work performed during a single scheduler tick.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerTickReport {
    pub snoozes_woken: usize,
    pub scheduled_sent: usize,
    pub scheduled_failed: usize,
}

struct ScheduledInFlightGuard {
    set: Arc<StdMutex<HashSet<String>>>,
    id: String,
}

impl ScheduledInFlightGuard {
    fn try_acquire(set: &Arc<StdMutex<HashSet<String>>>, id: &str) -> AppResult<Self> {
        let mut guard = set
            .lock()
            .map_err(|_| AppError::Internal("Scheduled send lock poisoned".to_string()))?;
        if !guard.insert(id.to_string()) {
            return Err(AppError::Conflict(format!(
                "Scheduled send '{id}' is already being processed"
            )));
        }
        Ok(Self {
            set: Arc::clone(set),
            id: id.to_string(),
        })
    }
}

impl Drop for ScheduledInFlightGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.set.lock() {
            guard.remove(&self.id);
        }
    }
}

/// Ensure the `SNOOZED` label exists in the active mailbox store (auto-creating it if absent).
async fn ensure_snoozed_label(state: &AppState) -> AppResult<()> {
    if state.store.get_label(LABEL_SNOOZED).await?.is_none() {
        let _ = state
            .store
            .create_label(NewLabelInput {
                name: LABEL_SNOOZED.to_string(),
                message_list_visibility: Some("show".to_string()),
                label_list_visibility: Some("labelShow".to_string()),
                ..Default::default()
            })
            .await;
    }
    Ok(())
}

/// Parse a scheduled send status query string (`pending`, `sending`, `sent`, `canceled`, `failed`, `all`, or empty).
pub fn parse_scheduled_send_status_filter(
    raw: Option<&str>,
) -> AppResult<Option<ScheduledSendStatus>> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some(s) if s.eq_ignore_ascii_case("all") => Ok(None),
        Some(s) => ScheduledSendStatus::parse_str(s).map(Some).ok_or_else(|| {
            AppError::validation(
                format!("Invalid scheduled send status filter '{s}'"),
                Some("Use one of: pending, sending, sent, canceled, failed, or all.".to_string()),
            )
        }),
    }
}

/// Snooze a conversation thread until a future timestamp (shared across REST and MCP).
pub async fn execute_snooze_thread(
    state: &AppState,
    thread_id: &str,
    req: SnoozeThreadRequest,
) -> AppResult<Value> {
    execute_snooze_thread_with_context(state, thread_id, req, None, EventSource::Api).await
}

/// Snooze a conversation thread with authenticated principal and event source attribution.
pub async fn execute_snooze_thread_with_context(
    state: &AppState,
    thread_id: &str,
    req: SnoozeThreadRequest,
    principal: Option<Principal>,
    source: EventSource,
) -> AppResult<Value> {
    let channel = channel_for_source(source);
    validate_resource_id(thread_id)?;

    let until = truncate_to_millis(req.until);
    let until_ms = until.timestamp_millis();
    let now_ms = Utc::now().timestamp_millis();
    if until_ms <= now_ms {
        return Err(AppError::validation(
            "Snooze 'until' timestamp must be in the future",
            Some("Provide a future RFC 3339 timestamp (e.g. 2026-12-01T09:00:00Z).".to_string()),
        ));
    }

    let _ = state
        .store
        .get_thread(thread_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Thread '{thread_id}' not found")))?;

    ensure_snoozed_label(state).await?;

    let add_labels = vec![LABEL_SNOOZED.to_string()];
    let remove_labels = vec![LABEL_INBOX.to_string()];

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

    let snooze = state.store.snooze_thread(thread_id, until_ms).await?;

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

    let mut target_ids = vec![result.thread_id.clone()];
    target_ids.extend(result.affected_message_ids.iter().cloned());
    state
        .record_audit(
            principal.as_ref(),
            channel,
            "snooze",
            target_ids,
            "ok",
            Some(format!("until={}", until.to_rfc3339())),
        )
        .await;

    Ok(json!({
        "status": "snoozed",
        "thread_id": result.thread_id,
        "snooze_until": until,
        "snooze_until_ms": snooze.snooze_until_ms,
        "affected_message_ids": result.affected_message_ids,
        "labels": result.labels,
        "added_labels": add_labels,
        "removed_labels": remove_labels,
    }))
}

/// Unsnooze a conversation thread immediately, removing `SNOOZED` and restoring `INBOX`.
pub async fn execute_unsnooze_thread(state: &AppState, thread_id: &str) -> AppResult<Value> {
    execute_unsnooze_thread_with_context(state, thread_id, None, EventSource::Api).await
}

/// Unsnooze a conversation thread with authenticated principal and event source attribution.
pub async fn execute_unsnooze_thread_with_context(
    state: &AppState,
    thread_id: &str,
    principal: Option<Principal>,
    source: EventSource,
) -> AppResult<Value> {
    let channel = channel_for_source(source);
    validate_resource_id(thread_id)?;

    let _ = state
        .store
        .get_thread(thread_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Thread '{thread_id}' not found")))?;

    let was_snoozed = state.store.unsnooze_thread(thread_id).await?;

    let add_labels = vec![LABEL_INBOX.to_string()];
    let remove_labels = vec![LABEL_SNOOZED.to_string()];

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

    let mut target_ids = vec![result.thread_id.clone()];
    target_ids.extend(result.affected_message_ids.iter().cloned());
    state
        .record_audit(
            principal.as_ref(),
            channel,
            "unsnooze",
            target_ids,
            "ok",
            Some(format!("was_snoozed={was_snoozed}")),
        )
        .await;

    Ok(json!({
        "status": "unsnoozed",
        "thread_id": result.thread_id,
        "was_snoozed": was_snoozed,
        "affected_message_ids": result.affected_message_ids,
        "labels": result.labels,
        "added_labels": add_labels,
        "removed_labels": remove_labels,
    }))
}

/// List scheduled outbound emails for the active mailbox (shared across REST and MCP).
pub async fn execute_list_scheduled_sends(
    state: &AppState,
    status: Option<&str>,
    limit: usize,
) -> AppResult<Value> {
    let filter = parse_scheduled_send_status_filter(status)?;
    let clamped = if limit == 0 {
        20
    } else {
        limit.clamp(1, MAX_LIST_LIMIT)
    };
    let items = state.store.list_scheduled_sends(filter, clamped).await?;
    Ok(json!({
        "scheduled_sends": items,
        "count": items.len(),
    }))
}

/// Cancel a pending scheduled outbound email before dispatch (shared across REST and MCP).
pub async fn execute_cancel_scheduled_send(state: &AppState, id: &str) -> AppResult<Value> {
    execute_cancel_scheduled_send_with_context(state, id, None, EventSource::Api).await
}

/// Cancel a pending scheduled outbound email with principal and source attribution.
pub async fn execute_cancel_scheduled_send_with_context(
    state: &AppState,
    id: &str,
    principal: Option<Principal>,
    source: EventSource,
) -> AppResult<Value> {
    let channel = channel_for_source(source);
    validate_resource_id(id)?;

    let in_flight_key = format!("{}:{}", state.mailbox_id(), id);
    let _in_flight =
        ScheduledInFlightGuard::try_acquire(&state.scheduled_in_flight, &in_flight_key)?;

    let canceled = state.store.cancel_scheduled_send(id).await?;

    state
        .record_audit(
            principal.as_ref(),
            channel,
            "cancel_scheduled_send",
            vec![canceled.id.clone()],
            "canceled",
            None,
        )
        .await;

    let send_at = DateTime::from_timestamp_millis(canceled.send_at_ms);
    Ok(json!({
        "status": "canceled",
        "scheduled_id": canceled.id,
        "send_at": send_at,
        "scheduled_send": canceled,
    }))
}

/// Process all due thread snoozes and due scheduled outbound sends across all mailboxes at `now_ms`.
///
/// Exposed publicly so integration tests can drive deterministic time progression without waiting
/// for wall-clock intervals.
pub async fn process_due_scheduler_items(
    state: &AppState,
    now_ms: i64,
) -> AppResult<SchedulerTickReport> {
    let mut report = SchedulerTickReport::default();

    // 1. Wake due snoozed threads across all mailboxes.
    let due_snoozes = state.store.list_all_due_snoozes(now_ms).await?;
    for snooze in due_snoozes {
        let mb_state = state.for_mailbox(&snooze.mailbox_id);
        match mb_state.store.get_thread(&snooze.thread_id).await {
            Ok(None) => {
                // Thread was deleted; clean up stale snooze record.
                let _ = mb_state.store.unsnooze_thread(&snooze.thread_id).await;
                continue;
            }
            Err(err) => {
                warn!(
                    %err,
                    mailbox_id = %snooze.mailbox_id,
                    thread_id = %snooze.thread_id,
                    "Failed to load due snoozed thread"
                );
                continue;
            }
            Ok(Some(_)) => {}
        }

        let add_labels = vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()];
        let remove_labels = vec![LABEL_SNOOZED.to_string()];

        let result = match mb_state
            .store
            .triage_thread(
                &snooze.thread_id,
                &TriagePatch {
                    add_labels: add_labels.clone(),
                    remove_labels: remove_labels.clone(),
                },
            )
            .await
        {
            Ok(res) => res,
            Err(err) => {
                warn!(
                    %err,
                    mailbox_id = %snooze.mailbox_id,
                    thread_id = %snooze.thread_id,
                    "Failed to restore labels for due snoozed thread"
                );
                continue;
            }
        };

        if let Err(err) = mb_state.store.unsnooze_thread(&snooze.thread_id).await {
            warn!(
                %err,
                mailbox_id = %snooze.mailbox_id,
                thread_id = %snooze.thread_id,
                "Failed to delete due snooze record"
            );
            continue;
        }

        for message_id in &result.affected_message_ids {
            mb_state.events.publish(
                EventSource::System,
                MailEvent::MessageUpdated {
                    message_id: message_id.clone(),
                    thread_id: result.thread_id.clone(),
                    added_labels: add_labels.clone(),
                    removed_labels: remove_labels.clone(),
                },
            );
        }

        let mut target_ids = vec![result.thread_id.clone()];
        target_ids.extend(result.affected_message_ids.iter().cloned());
        mb_state
            .record_audit(
                None,
                "system",
                "unsnooze",
                target_ids,
                "ok",
                Some("scheduler_wake".to_string()),
            )
            .await;

        report.snoozes_woken += 1;
    }

    // 2. Atomically claim and dispatch due scheduled sends across all mailboxes.
    let due_sends = state
        .store
        .claim_due_scheduled_sends(now_ms, DEFAULT_SCHEDULED_SEND_STALE_LEASE_MS)
        .await?;
    for current in due_sends {
        let mb_state = state.for_mailbox(&current.mailbox_id);
        let in_flight_key = format!("{}:{}", mb_state.mailbox_id(), current.id);
        let Ok(_in_flight) =
            ScheduledInFlightGuard::try_acquire(&state.scheduled_in_flight, &in_flight_key)
        else {
            continue;
        };

        let outbound = &current.outbound_message;

        // Re-evaluate outbound safety/policy at dispatch time so policy tightenings
        // made after scheduling are enforced before contacting the upstream transport.
        let policy_check = OutboundCheck {
            from: if outbound.from.trim().is_empty() {
                mb_state.config.user_email.clone()
            } else {
                outbound.from.clone()
            },
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
            thread_id: current.thread_id.clone(),
            mailbox_id: Some(mb_state.mailbox_id().to_string()),
            is_draft_send: false,
            agent_policy: None,
        };
        match mb_state.evaluate_outbound_policy(&policy_check).await {
            Ok(OutboundDecision::Allow) => {}
            Ok(OutboundDecision::Deny { code, reason, .. }) => {
                let err_msg = format!("Blocked by outbound policy ({code}): {reason}");
                warn!(
                    mailbox_id = %current.mailbox_id,
                    scheduled_id = %current.id,
                    code = %code,
                    "Scheduled send blocked by outbound policy at dispatch"
                );
                let _ = mb_state
                    .store
                    .fail_scheduled_send(&current.id, &err_msg)
                    .await;
                mb_state
                    .record_audit(
                        None,
                        "system",
                        "send",
                        vec![current.id.clone()],
                        "denied",
                        Some(err_msg),
                    )
                    .await;
                report.scheduled_failed += 1;
                continue;
            }
            Ok(OutboundDecision::HoldForApproval { reason }) => {
                let err_msg = format!("Blocked by outbound policy (hold_for_approval): {reason}");
                warn!(
                    mailbox_id = %current.mailbox_id,
                    scheduled_id = %current.id,
                    "Scheduled send requires approval under current outbound policy; marking failed"
                );
                let _ = mb_state
                    .store
                    .fail_scheduled_send(&current.id, &err_msg)
                    .await;
                mb_state
                    .record_audit(
                        None,
                        "system",
                        "send",
                        vec![current.id.clone()],
                        "denied",
                        Some(err_msg),
                    )
                    .await;
                report.scheduled_failed += 1;
                continue;
            }
            Ok(OutboundDecision::DowngradeToDraft { reason }) => {
                let err_msg = format!("Blocked by outbound policy (downgrade_to_draft): {reason}");
                warn!(
                    mailbox_id = %current.mailbox_id,
                    scheduled_id = %current.id,
                    "Scheduled send downgraded by current outbound policy; marking failed"
                );
                let _ = mb_state
                    .store
                    .fail_scheduled_send(&current.id, &err_msg)
                    .await;
                mb_state
                    .record_audit(
                        None,
                        "system",
                        "send",
                        vec![current.id.clone()],
                        "denied",
                        Some(err_msg),
                    )
                    .await;
                report.scheduled_failed += 1;
                continue;
            }
            Err(err) => {
                let err_msg = format!("Outbound policy evaluation failed at dispatch: {err}");
                warn!(
                    %err,
                    mailbox_id = %current.mailbox_id,
                    scheduled_id = %current.id,
                    "Scheduled send outbound policy evaluation errored"
                );
                let _ = mb_state
                    .store
                    .fail_scheduled_send(&current.id, &err_msg)
                    .await;
                mb_state
                    .record_audit(
                        None,
                        "system",
                        "send",
                        vec![current.id.clone()],
                        "failed",
                        Some(err_msg),
                    )
                    .await;
                report.scheduled_failed += 1;
                continue;
            }
        }

        let mut outbound_owned = outbound.clone();
        let irt_lookup = outbound_owned
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("in-reply-to"))
            .map(|(_, v)| v.clone());
        let refs_lookup = outbound_owned
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("references"))
            .map(|(_, v)| v.clone());
        let resolved_upstream_tid = crate::transport::resolve_outbound_upstream_thread_id(
            mb_state.store.as_ref(),
            current.thread_id.as_deref(),
            irt_lookup.as_deref(),
            refs_lookup.as_deref(),
        )
        .await;
        if let Some(ref up_tid) = resolved_upstream_tid {
            outbound_owned.set_upstream_thread_id(up_tid);
        }
        let outbound = &outbound_owned;

        let transport_idem_key = format!("scheduled-{}", current.id);
        let send_outcome = match mb_state
            .transport
            .send(outbound, Some(&transport_idem_key))
            .await
        {
            Ok(outcome) => outcome,
            Err(err) => {
                let err_msg = err.to_string();
                warn!(
                    %err,
                    mailbox_id = %current.mailbox_id,
                    scheduled_id = %current.id,
                    "Scheduled send transport dispatch failed"
                );
                let _ = mb_state
                    .store
                    .fail_scheduled_send(&current.id, &err_msg)
                    .await;
                mb_state
                    .record_audit(
                        None,
                        "system",
                        "send",
                        vec![current.id.clone()],
                        "failed",
                        Some(err_msg),
                    )
                    .await;
                report.scheduled_failed += 1;
                continue;
            }
        };
        let (upstream_gmail_id, upstream_thread_id) =
            crate::transport::upstream_gmail_ids_from_send(&send_outcome, resolved_upstream_tid);

        let raw_rfc2822 =
            match crate::transport::ensure_raw_rfc2822(outbound, &mb_state.config.user_email) {
                Ok(raw) => raw,
                Err(err) => {
                    let err_msg = format!(
                        "Post-send RFC2822 serialization failed (provider_message_id={}): {err}",
                        send_outcome.provider_message_id
                    );
                    error!(
                        %err,
                        mailbox_id = %current.mailbox_id,
                        scheduled_id = %current.id,
                        provider_message_id = %send_outcome.provider_message_id,
                        "Scheduled send succeeded on transport but failed to build RFC2822 copy"
                    );
                    let _ = mb_state
                        .store
                        .fail_scheduled_send(&current.id, &err_msg)
                        .await;
                    report.scheduled_failed += 1;
                    continue;
                }
            };
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

        let stored = match mb_state
            .store
            .insert_message(NewMessageInput {
                id: None,
                thread_id: current.thread_id.clone(),
                label_ids: vec![LABEL_SENT.to_string()],
                raw_rfc2822,
                snippet,
                internal_date_ms: now_ms,
                subject: outbound.subject.clone(),
                from_addr: if outbound.from.trim().is_empty() {
                    mb_state.config.user_email.clone()
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
                upstream_gmail_id,
                upstream_thread_id,
                source: "local".to_string(),
                is_answered: false,
                is_deleted: false,
                attachments,
            })
            .await
        {
            Ok(msg) => msg,
            Err(err) => {
                let err_msg = format!(
                    "Post-send SENT message persistence failed (provider_message_id={}): {err}",
                    send_outcome.provider_message_id
                );
                error!(
                    %err,
                    mailbox_id = %current.mailbox_id,
                    scheduled_id = %current.id,
                    provider_message_id = %send_outcome.provider_message_id,
                    "Scheduled send dispatched on transport but failed to persist SENT copy"
                );
                let _ = mb_state
                    .store
                    .fail_scheduled_send(&current.id, &err_msg)
                    .await;
                report.scheduled_failed += 1;
                continue;
            }
        };

        if let Err(err) = mb_state.post_store_message(&stored).await {
            warn!(
                %err,
                mailbox_id = %current.mailbox_id,
                scheduled_id = %current.id,
                message_id = %stored.id,
                "Scheduled send post_store_message (blob/search/contacts) failed after send"
            );
        }
        mb_state
            .record_outbound_sent(&stored.from_addr, &stored.to_addrs, &send_outcome.provider)
            .await;

        if let Err(err) = mb_state
            .store
            .complete_scheduled_send(&current.id, &stored.id, &send_outcome.provider_message_id)
            .await
        {
            let err_msg = format!(
                "Post-send completion failed (sent_message_id={}, provider_message_id={}): {err}",
                stored.id, send_outcome.provider_message_id
            );
            error!(
                %err,
                mailbox_id = %current.mailbox_id,
                scheduled_id = %current.id,
                sent_message_id = %stored.id,
                provider_message_id = %send_outcome.provider_message_id,
                "Scheduled send dispatched and stored but complete_scheduled_send failed"
            );
            let _ = mb_state
                .store
                .fail_scheduled_send(&current.id, &err_msg)
                .await;
            report.scheduled_failed += 1;
            continue;
        }

        mb_state.events.publish(
            EventSource::System,
            MailEvent::MessageSent {
                message_id: stored.id.clone(),
                thread_id: stored.thread_id.clone(),
                to: stored.to_addrs.clone(),
                subject: stored.subject.clone(),
                resend_id: Some(send_outcome.provider_message_id.clone()),
                labels: stored.label_ids.clone(),
            },
        );

        mb_state
            .record_audit(
                None,
                "system",
                "send",
                vec![
                    current.id.clone(),
                    stored.id.clone(),
                    stored.thread_id.clone(),
                ],
                "ok",
                Some(format!(
                    "scheduled_dispatch to={}",
                    stored.to_addrs.join(",")
                )),
            )
            .await;

        report.scheduled_sent += 1;
    }

    Ok(report)
}

/// Long-running background scheduler loop spawned by `nogml serve` (ticks every 15 seconds).
pub async fn run_background_scheduler(state: AppState, mut shutdown_rx: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(DEFAULT_SCHEDULER_INTERVAL_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            _ = interval.tick() => {
                let now_ms = Utc::now().timestamp_millis();
                match process_due_scheduler_items(&state, now_ms).await {
                    Ok(report) => {
                        if report.snoozes_woken > 0
                            || report.scheduled_sent > 0
                            || report.scheduled_failed > 0
                        {
                            info!(
                                snoozes_woken = report.snoozes_woken,
                                scheduled_sent = report.scheduled_sent,
                                scheduled_failed = report.scheduled_failed,
                                "Background scheduler tick completed"
                            );
                        }
                    }
                    Err(err) => {
                        warn!(%err, "Background scheduler tick failed");
                    }
                }
            }
        }
    }
}
