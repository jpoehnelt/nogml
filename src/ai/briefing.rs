//! Daily briefing and follow-up detector shared by `GET /v1/briefing`, the MCP
//! `get_briefing` tool and `nogml://briefing` resource, and `nogml mail briefing`.
//!
//! The briefing is built only from existing [`MailStore`](crate::storage::MailStore)
//! reads and returns compact summaries. Raw MIME and full bodies are never included.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    AppState,
    ai::{
        MAX_LIST_LIMIT, enrich_thread_summaries_with_contacts, parse_since_ms,
        sanitize_untrusted_text,
    },
    error::{AppError, AppResult},
    models::{
        LABEL_DRAFT, LABEL_INBOX, LABEL_SENT, LABEL_SPAM, LABEL_TRASH, ThreadSummary, WaitingOn,
    },
    storage::{
        AiThreadQuery, ApprovalStatus, ContactQuery, MessageListQuery, SnoozedThread,
        parse_simple_email_address,
    },
};

/// Default `followup_days` threshold.
pub const DEFAULT_FOLLOWUP_DAYS: u32 = 3;
/// Default number of items per briefing section.
pub const DEFAULT_BRIEFING_LIMIT: usize = 20;
/// Maximum number of items per briefing section.
pub const MAX_BRIEFING_LIMIT: usize = 100;
/// Longest `followup_days` accepted (ten years).
const MAX_FOLLOWUP_DAYS: u32 = 3650;
/// Maximum snippet length (characters) returned for any briefing item.
const BRIEFING_SNIPPET_CHARS: usize = 200;
/// Maximum participants returned per briefing thread.
const BRIEFING_MAX_PARTICIPANTS: usize = 5;
/// Maximum unread inbox threads scanned when looking for VIP senders.
const MAX_VIP_SCAN_THREADS: usize = 1000;
/// Maximum sent messages scanned when looking for unanswered threads.
const MAX_SENT_SCAN_MESSAGES: usize = 500;
/// Window for upcoming snoozes included in the briefing.
const UPCOMING_SNOOZE_HOURS: i64 = 24;

/// Input for [`execute_briefing`].
#[derive(Debug, Clone, Default)]
pub struct BriefingParams {
    pub since: Option<DateTime<Utc>>,
    pub followup_days: Option<u32>,
    pub limit: Option<usize>,
}

/// Aggregate counts for the whole mailbox (not truncated by `limit`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BriefingCounts {
    pub unread_total: usize,
    pub inbox_total: usize,
    pub pending_approvals_count: usize,
    pub snoozed_count: usize,
    pub vip_unread_count: usize,
    pub followup_due_count: usize,
}

/// A sent thread that has had no reply for at least `followup_days`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowUpCandidate {
    pub thread_id: String,
    pub subject: String,
    pub to: Vec<String>,
    pub last_sent_at: DateTime<Utc>,
    pub days_since_sent: i64,
    pub snippet: String,
}

/// Compact view of a pending outbound approval (no message body).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalBriefingItem {
    pub id: String,
    pub reason: String,
    pub to: Vec<String>,
    pub subject: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Token-bounded daily briefing payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BriefingResponse {
    pub generated_at: DateTime<Utc>,
    pub counts: BriefingCounts,
    pub vip_unread_threads: Vec<ThreadSummary>,
    pub needs_reply_threads: Vec<ThreadSummary>,
    pub follow_up_due: Vec<FollowUpCandidate>,
    pub pending_approvals: Vec<ApprovalBriefingItem>,
    pub due_snoozes: Vec<SnoozedThread>,
}

/// Parse an optional RFC 3339 (or epoch milliseconds) `since` value.
pub fn parse_briefing_since(raw: Option<&str>) -> AppResult<Option<DateTime<Utc>>> {
    let Some(ms) = parse_since_ms(raw)? else {
        return Ok(None);
    };
    DateTime::from_timestamp_millis(ms)
        .map(Some)
        .ok_or_else(|| AppError::validation("'since' timestamp is out of range", None))
}

fn ms_to_datetime(ms: i64) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(ms).unwrap_or_else(Utc::now)
}

fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        let mut out: String = text.chars().take(max).collect();
        out.push('…');
        out
    }
}

fn bound_thread(mut thread: ThreadSummary, guard: bool) -> ThreadSummary {
    if guard {
        thread.subject = sanitize_untrusted_text(&thread.subject);
        thread.snippet = sanitize_untrusted_text(&thread.snippet);
        for p in &mut thread.participants {
            p.name = p.name.as_deref().map(sanitize_untrusted_text);
            p.email = sanitize_untrusted_text(&p.email);
        }
    }
    thread.snippet = truncate_chars(&thread.snippet, BRIEFING_SNIPPET_CHARS);
    thread.participants.truncate(BRIEFING_MAX_PARTICIPANTS);
    thread
}

/// Build the briefing for the active mailbox.
pub async fn build_briefing(
    state: &AppState,
    params: BriefingParams,
) -> AppResult<BriefingResponse> {
    let now = Utc::now();
    let limit = params
        .limit
        .unwrap_or(DEFAULT_BRIEFING_LIMIT)
        .clamp(1, MAX_BRIEFING_LIMIT.min(MAX_LIST_LIMIT));
    let followup_days = params
        .followup_days
        .unwrap_or(DEFAULT_FOLLOWUP_DAYS)
        .min(MAX_FOLLOWUP_DAYS);
    let self_email = state.store.mailbox_id().trim().to_ascii_lowercase();

    // Counts from label totals (INBOX thread totals).
    let labels = state.store.list_labels().await?;
    let (inbox_total, unread_total) = labels
        .iter()
        .find(|l| l.id == LABEL_INBOX)
        .map(|l| {
            (
                l.threads_total.max(0) as usize,
                l.threads_unread.max(0) as usize,
            )
        })
        .unwrap_or((0, 0));

    // VIP unread threads.
    let mut vip_threads = vip_unread_threads(state, &self_email, params.since).await?;
    let vip_unread_count = vip_threads.len();
    vip_threads.truncate(limit);
    enrich_thread_summaries_with_contacts(state, &mut vip_threads).await?;

    // Threads flagged needs_reply or waiting_on == me.
    let mut needs_reply = needs_reply_threads(state, limit).await?;
    enrich_thread_summaries_with_contacts(state, &mut needs_reply).await?;

    // Follow-up candidates.
    let mut follow_ups = follow_up_candidates(state, followup_days, now).await?;
    let followup_due_count = follow_ups.len();
    follow_ups.truncate(limit);

    // Pending approvals (expired items are reported as `expired` by the store).
    let approvals = state
        .store
        .list_pending_approvals(Some(ApprovalStatus::Pending), 500)
        .await?;
    let pending_approvals_count = approvals.len();
    let pending_approvals: Vec<ApprovalBriefingItem> = approvals
        .into_iter()
        .take(limit)
        .map(|a| ApprovalBriefingItem {
            id: a.id,
            reason: truncate_chars(&a.reason, BRIEFING_SNIPPET_CHARS),
            to: a.outbound_message.to,
            subject: truncate_chars(&a.outbound_message.subject, BRIEFING_SNIPPET_CHARS),
            created_at: ms_to_datetime(a.created_at_ms),
            expires_at: ms_to_datetime(a.expires_at_ms),
        })
        .collect();

    // Snoozes that are due or wake within the next 24 hours.
    let snoozed_count = state.store.list_snoozed_threads(None).await?.len();
    let horizon_ms = (now + Duration::hours(UPCOMING_SNOOZE_HOURS)).timestamp_millis();
    let mut due_snoozes = state.store.list_snoozed_threads(Some(horizon_ms)).await?;
    due_snoozes.retain(|s| s.snooze_until_ms <= horizon_ms);
    due_snoozes.truncate(limit);

    let guard = state.config.untrusted_content_guard;
    Ok(BriefingResponse {
        generated_at: now,
        counts: BriefingCounts {
            unread_total,
            inbox_total,
            pending_approvals_count,
            snoozed_count,
            vip_unread_count,
            followup_due_count,
        },
        vip_unread_threads: vip_threads
            .into_iter()
            .map(|t| bound_thread(t, guard))
            .collect(),
        needs_reply_threads: needs_reply
            .into_iter()
            .map(|t| bound_thread(t, guard))
            .collect(),
        follow_up_due: follow_ups,
        pending_approvals,
        due_snoozes,
    })
}

/// Shared entry point returning JSON (used by REST, MCP, and CLI).
pub async fn execute_briefing(state: &AppState, params: BriefingParams) -> AppResult<Value> {
    let briefing = build_briefing(state, params).await?;
    Ok(serde_json::to_value(briefing)?)
}

async fn vip_unread_threads(
    state: &AppState,
    self_email: &str,
    since: Option<DateTime<Utc>>,
) -> AppResult<Vec<ThreadSummary>> {
    let vips: HashSet<String> = state
        .store
        .list_contacts(&ContactQuery {
            vip_only: true,
            limit: 1000,
            ..Default::default()
        })
        .await?
        .into_iter()
        .map(|c| c.email.trim().to_ascii_lowercase())
        .collect();
    if vips.is_empty() {
        return Ok(Vec::new());
    }

    let mut matched = Vec::new();
    let mut scanned = 0usize;
    let mut cursor: Option<String> = None;
    loop {
        let page = state
            .store
            .list_thread_summaries(&AiThreadQuery {
                label: Some(LABEL_INBOX.to_string()),
                unread_only: true,
                limit: MAX_LIST_LIMIT,
                cursor: cursor.clone(),
                ..Default::default()
            })
            .await?;
        for thread in page.threads {
            scanned += 1;
            if since.is_some_and(|s| thread.last_message_at < s) {
                continue;
            }
            // Cheap pre-filter on participants before loading the thread.
            let may_match = thread
                .participants
                .iter()
                .any(|p| vips.contains(&p.email.trim().to_ascii_lowercase()));
            if !may_match {
                continue;
            }
            let Some(detail) = state.store.get_thread(&thread.id).await? else {
                continue;
            };
            let latest_sender = detail
                .messages
                .iter()
                .filter(|m| !m.label_ids.iter().any(|l| l == LABEL_DRAFT))
                .filter(|m| {
                    !m.label_ids.iter().any(|l| l == LABEL_SENT)
                        && !parse_simple_email_address(&m.from_addr)
                            .email
                            .eq_ignore_ascii_case(self_email)
                })
                .max_by(|a, b| {
                    a.internal_date_ms
                        .cmp(&b.internal_date_ms)
                        .then_with(|| a.id.cmp(&b.id))
                })
                .map(|m| {
                    parse_simple_email_address(&m.from_addr)
                        .email
                        .trim()
                        .to_ascii_lowercase()
                });
            if latest_sender.is_some_and(|s| vips.contains(&s)) {
                matched.push(thread);
            }
        }
        if !page.has_more || page.next_cursor.is_none() || scanned >= MAX_VIP_SCAN_THREADS {
            break;
        }
        cursor = page.next_cursor;
    }
    Ok(matched)
}

async fn needs_reply_threads(state: &AppState, limit: usize) -> AppResult<Vec<ThreadSummary>> {
    let flagged = state
        .store
        .list_thread_summaries(&AiThreadQuery {
            needs_reply: Some(true),
            limit,
            ..Default::default()
        })
        .await?;
    let waiting_me = state
        .store
        .list_thread_summaries(&AiThreadQuery {
            waiting_on: Some(WaitingOn::Me),
            limit,
            ..Default::default()
        })
        .await?;
    let mut seen = HashSet::new();
    let mut merged: Vec<ThreadSummary> = flagged
        .threads
        .into_iter()
        .chain(waiting_me.threads)
        .filter(|t| seen.insert(t.id.clone()))
        .filter(|t| !t.labels.iter().any(|l| l == LABEL_TRASH || l == LABEL_SPAM))
        .collect();
    merged.sort_by(|a, b| {
        b.last_message_at
            .cmp(&a.last_message_at)
            .then_with(|| b.id.cmp(&a.id))
    });
    merged.truncate(limit);
    Ok(merged)
}

async fn follow_up_candidates(
    state: &AppState,
    followup_days: u32,
    now: DateTime<Utc>,
) -> AppResult<Vec<FollowUpCandidate>> {
    let cutoff = now - Duration::days(i64::from(followup_days));
    let sent = state
        .store
        .list_messages(&MessageListQuery {
            label_ids: vec![LABEL_SENT.to_string()],
            max_results: MAX_SENT_SCAN_MESSAGES,
            ..Default::default()
        })
        .await?;

    // Unique sent threads whose newest sent message is old enough to be a candidate.
    let mut newest_sent: HashMap<String, i64> = HashMap::new();
    for msg in &sent.messages {
        let entry = newest_sent.entry(msg.thread_id.clone()).or_insert(i64::MIN);
        *entry = (*entry).max(msg.internal_date_ms);
    }

    let mut out = Vec::new();
    for (thread_id, newest_ms) in newest_sent {
        if ms_to_datetime(newest_ms) > cutoff {
            continue;
        }
        let Some(detail) = state.store.get_thread(&thread_id).await? else {
            continue;
        };
        if detail.messages.iter().any(|m| {
            m.label_ids
                .iter()
                .any(|l| l == LABEL_TRASH || l == LABEL_SPAM)
        }) {
            continue;
        }
        let Some(last) = detail
            .messages
            .iter()
            .filter(|m| !m.label_ids.iter().any(|l| l == LABEL_DRAFT))
            .max_by(|a, b| {
                a.internal_date_ms
                    .cmp(&b.internal_date_ms)
                    .then_with(|| a.id.cmp(&b.id))
            })
        else {
            continue;
        };
        if !last.label_ids.iter().any(|l| l == LABEL_SENT) {
            continue;
        }
        let last_sent_at = ms_to_datetime(last.internal_date_ms);
        if last_sent_at > cutoff {
            continue;
        }
        if let Some(annotation) = state.store.get_thread_annotation(&thread_id).await?
            && annotation.waiting_on == Some(WaitingOn::None)
        {
            continue;
        }
        let guard = state.config.untrusted_content_guard;
        let subject = detail
            .messages
            .iter()
            .find(|m| !m.subject.is_empty())
            .map(|m| m.subject.clone())
            .unwrap_or_default();
        let subject = if guard {
            sanitize_untrusted_text(&subject)
        } else {
            subject
        };
        let snippet = if guard {
            sanitize_untrusted_text(&last.snippet)
        } else {
            last.snippet.clone()
        };
        out.push(FollowUpCandidate {
            thread_id,
            subject: truncate_chars(&subject, BRIEFING_SNIPPET_CHARS),
            to: last.to_addrs.iter().take(10).cloned().collect(),
            last_sent_at,
            days_since_sent: (now - last_sent_at).num_days(),
            snippet: truncate_chars(&snippet, BRIEFING_SNIPPET_CHARS),
        });
    }

    // Most overdue first.
    out.sort_by(|a, b| {
        a.last_sent_at
            .cmp(&b.last_sent_at)
            .then_with(|| a.thread_id.cmp(&b.thread_id))
    });
    Ok(out)
}
