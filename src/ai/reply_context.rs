//! Single-call reply context for agents (`GET /v1/threads/{id}/reply-context` and MCP
//! `get_reply_context`).
//!
//! Gathers the quote-stripped thread, its annotation, participant contact profiles, recent
//! `SENT` style samples to the primary recipient, and related threads in one round trip.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{
    enrich_thread_summaries_with_contacts, sanitize_contact_record, to_compact_message,
    untrusted_meta, validate_resource_id,
};
use crate::{
    AppState,
    error::{AppError, AppResult},
    models::{
        CompactMessage, EmailAddress, LABEL_SENT, LABEL_UNREAD, ThreadAnnotation, ThreadDetail,
        ThreadSummary, UntrustedMeta,
    },
    storage::{AiSearchQuery, ContactRecord, StoredMessage, parse_simple_email_address},
};

use super::safety::{clamp_max_body_chars, sanitize_untrusted_text};

/// Default number of style samples returned when `max_style_samples` is omitted.
pub const DEFAULT_MAX_STYLE_SAMPLES: usize = 3;
/// Hard cap on `max_style_samples`.
pub const HARD_MAX_STYLE_SAMPLES: usize = 10;
/// Default number of related threads returned when `max_related_threads` is omitted.
pub const DEFAULT_MAX_RELATED_THREADS: usize = 5;
/// Hard cap on `max_related_threads`.
pub const HARD_MAX_RELATED_THREADS: usize = 20;
/// Maximum number of participant contact profiles returned.
const MAX_PARTICIPANTS: usize = 50;
/// Page size used when scanning search results.
const SEARCH_PAGE: usize = 50;
/// Maximum number of search pages scanned per query.
const MAX_SEARCH_PAGES: usize = 4;

/// Caller-supplied limits for [`execute_get_reply_context`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ReplyContextOptions {
    pub max_body_chars: Option<usize>,
    pub max_style_samples: Option<usize>,
    pub max_related_threads: Option<usize>,
}

/// Everything an agent needs to draft an accurate, in-voice reply to one thread.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplyContextResponse {
    /// Quote-stripped thread with bounded bodies.
    pub thread: ThreadDetail,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotation: Option<ThreadAnnotation>,
    /// Contact profiles for thread participants, excluding the mailbox owner.
    pub participants: Vec<ContactRecord>,
    /// Address replies are most likely to go to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_recipient: Option<String>,
    /// Recent `SENT` messages from the mailbox owner to the primary recipient.
    pub style_samples: Vec<CompactMessage>,
    /// Other threads that match the cleaned subject or the primary recipient.
    pub related_threads: Vec<ThreadSummary>,
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<UntrustedMeta>,
}

/// Strip leading `Re:`, `Fwd:`, and `Fw:` prefixes (repeated, case-insensitive) from a subject.
pub fn clean_subject(subject: &str) -> String {
    let mut current = subject.trim();
    loop {
        let lower = current.to_ascii_lowercase();
        let prefix_len = ["re:", "fwd:", "fw:"]
            .iter()
            .find(|p| lower.starts_with(**p))
            .map(|p| p.len());
        match prefix_len {
            Some(len) => current = current[len..].trim_start(),
            None => break,
        }
    }
    current.to_string()
}

fn is_self(email: &str, self_email: &str) -> bool {
    email.trim().eq_ignore_ascii_case(self_email)
}

/// Pick the address a reply should go to: the sender of the latest non-self message, else the
/// first non-self recipient of the latest sent message.
fn primary_recipient(messages: &[&StoredMessage], self_email: &str) -> Option<String> {
    let latest_sender = messages
        .iter()
        .rev()
        .map(|m| {
            parse_simple_email_address(&m.from_addr)
                .email
                .to_ascii_lowercase()
        })
        .find(|e| !e.is_empty() && !is_self(e, self_email));
    if latest_sender.is_some() {
        return latest_sender;
    }
    messages.iter().rev().find_map(|m| {
        m.to_addrs
            .iter()
            .chain(m.cc_addrs.iter())
            .map(|a| parse_simple_email_address(a).email.to_ascii_lowercase())
            .find(|e| !e.is_empty() && !is_self(e, self_email))
    })
}

async fn collect_participants(
    state: &AppState,
    messages: &[&StoredMessage],
    self_email: &str,
) -> AppResult<Vec<ContactRecord>> {
    let guard = state.config.untrusted_content_guard;
    // email -> (display name, latest message ms)
    let mut order: Vec<String> = Vec::new();
    let mut seen: HashMap<String, (Option<String>, i64)> = HashMap::new();
    for msg in messages {
        let addrs = std::iter::once(msg.from_addr.as_str())
            .chain(msg.to_addrs.iter().map(String::as_str))
            .chain(msg.cc_addrs.iter().map(String::as_str));
        for raw in addrs {
            let parsed = parse_simple_email_address(raw);
            let key = parsed.email.trim().to_ascii_lowercase();
            if key.is_empty() || is_self(&key, self_email) {
                continue;
            }
            match seen.get_mut(&key) {
                Some(entry) => {
                    entry.1 = entry.1.max(msg.internal_date_ms);
                    if entry.0.is_none() {
                        entry.0 = parsed.name;
                    }
                }
                None => {
                    order.push(key.clone());
                    seen.insert(key, (parsed.name, msg.internal_date_ms));
                }
            }
        }
    }

    let mut out = Vec::new();
    for key in order.into_iter().take(MAX_PARTICIPANTS) {
        let record = match state.store.get_contact(&key).await? {
            Some(record) => record,
            None => {
                let (name, last_ms) = seen.remove(&key).unwrap_or((None, 0));
                let domain = key.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
                ContactRecord {
                    email: key.clone(),
                    display_name: name.filter(|n| !n.trim().is_empty()),
                    domain: domain.to_string(),
                    sent_count: 0,
                    received_count: 0,
                    replied_by_me_count: 0,
                    first_seen_at_ms: last_ms,
                    last_seen_at_ms: last_ms,
                    last_replied_at_ms: None,
                    is_vip: false,
                    vip_override: None,
                    notes: None,
                }
            }
        };
        out.push(sanitize_contact_record(record, guard));
    }
    Ok(out)
}

async fn collect_style_samples(
    state: &AppState,
    thread_id: &str,
    self_email: &str,
    recipient: &str,
    limit: usize,
    max_body_chars: usize,
) -> AppResult<Vec<CompactMessage>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let mut samples = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_SEARCH_PAGES {
        let page = state
            .store
            .search_messages_ai(&AiSearchQuery {
                labels: vec![LABEL_SENT.to_string()],
                from: Some(self_email.to_string()),
                to: Some(recipient.to_string()),
                limit: SEARCH_PAGE,
                cursor: cursor.clone(),
                ..Default::default()
            })
            .await?;
        for msg in &page.messages {
            if msg.thread_id == thread_id {
                continue;
            }
            let addressed = msg.to_addrs.iter().any(|a| {
                parse_simple_email_address(a)
                    .email
                    .eq_ignore_ascii_case(recipient)
            });
            if !addressed {
                continue;
            }
            samples.push(to_compact_message(
                msg,
                &state.config,
                true,
                max_body_chars,
                true,
                false,
            ));
            if samples.len() >= limit {
                return Ok(samples);
            }
        }
        if !page.has_more {
            break;
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    Ok(samples)
}

/// Collect distinct thread ids (excluding `current`) from a search query, newest first.
async fn scan_thread_ids(
    state: &AppState,
    query: AiSearchQuery,
    current: &str,
    seen: &mut HashSet<String>,
    ids: &mut Vec<String>,
    want: usize,
) -> AppResult<()> {
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_SEARCH_PAGES {
        if ids.len() >= want {
            return Ok(());
        }
        let page = state
            .search
            .search(&AiSearchQuery {
                limit: SEARCH_PAGE,
                cursor: cursor.clone(),
                ..query.clone()
            })
            .await?;
        for msg in &page.messages {
            if msg.thread_id == current {
                continue;
            }
            if seen.insert(msg.thread_id.clone()) {
                ids.push(msg.thread_id.clone());
                if ids.len() >= want {
                    return Ok(());
                }
            }
        }
        if !page.has_more {
            break;
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    Ok(())
}

async fn collect_related_threads(
    state: &AppState,
    thread_id: &str,
    subject: &str,
    recipient: Option<&str>,
    limit: usize,
) -> AppResult<Vec<ThreadSummary>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let mut ids: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let cleaned = clean_subject(subject);
    if cleaned.chars().any(char::is_alphanumeric) {
        scan_thread_ids(
            state,
            AiSearchQuery {
                q: Some(cleaned),
                ..Default::default()
            },
            thread_id,
            &mut seen,
            &mut ids,
            limit,
        )
        .await?;
    }
    if let Some(email) = recipient {
        for (from, to) in [(Some(email), None), (None, Some(email))] {
            scan_thread_ids(
                state,
                AiSearchQuery {
                    from: from.map(str::to_string),
                    to: to.map(str::to_string),
                    ..Default::default()
                },
                thread_id,
                &mut seen,
                &mut ids,
                limit,
            )
            .await?;
        }
    }

    let guard = state.config.untrusted_content_guard;
    let mut summaries = Vec::new();
    for id in ids {
        let Some(detail) = state.store.get_thread(&id).await? else {
            continue;
        };
        if detail.messages.is_empty() {
            continue;
        }
        let annotation = state.store.get_thread_annotation(&id).await?;
        summaries.push(summarize_thread(&id, &detail.messages, annotation, guard));
    }
    enrich_thread_summaries_with_contacts(state, &mut summaries).await?;
    Ok(summaries)
}

fn summarize_thread(
    thread_id: &str,
    messages: &[StoredMessage],
    annotation: Option<ThreadAnnotation>,
    guard: bool,
) -> ThreadSummary {
    let clean = |s: &str| {
        if guard {
            sanitize_untrusted_text(s)
        } else {
            s.to_string()
        }
    };
    let mut sorted: Vec<&StoredMessage> = messages.iter().collect();
    sorted.sort_by(|a, b| {
        a.internal_date_ms
            .cmp(&b.internal_date_ms)
            .then_with(|| a.id.cmp(&b.id))
    });

    let subject = sorted
        .iter()
        .find(|m| !m.subject.trim().is_empty())
        .map(|m| clean(&m.subject))
        .unwrap_or_default();
    let mut participants: Vec<EmailAddress> = Vec::new();
    let mut seen = HashSet::new();
    let mut labels: Vec<String> = Vec::new();
    let mut has_attachments = false;
    for msg in &sorted {
        let parsed = parse_simple_email_address(&msg.from_addr);
        let key = parsed.email.to_ascii_lowercase();
        if !key.is_empty() && seen.insert(key) {
            participants.push(EmailAddress {
                name: parsed.name.map(|n| clean(&n)),
                email: clean(&parsed.email),
            });
        }
        for l in &msg.label_ids {
            if !labels.contains(l) {
                labels.push(l.clone());
            }
        }
        has_attachments |= msg.has_attachments;
    }
    labels.sort();
    let last_ms = sorted.last().map(|m| m.internal_date_ms).unwrap_or(0);
    ThreadSummary {
        id: thread_id.to_string(),
        subject,
        participants,
        sender_contact: None,
        snippet: sorted.last().map(|m| clean(&m.snippet)).unwrap_or_default(),
        unread: labels.iter().any(|l| l == LABEL_UNREAD),
        labels,
        has_attachments,
        message_count: sorted.len(),
        last_message_at: DateTime::from_timestamp_millis(last_ms).unwrap_or_else(Utc::now),
        annotation,
    }
}

/// Build the reply context for `thread_id` (shared by REST and MCP).
pub async fn execute_get_reply_context(
    state: &AppState,
    thread_id: &str,
    opts: ReplyContextOptions,
) -> AppResult<ReplyContextResponse> {
    validate_resource_id(thread_id)?;
    let stored = state
        .store
        .get_thread(thread_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Thread '{thread_id}' not found")))?;

    let max_body_chars = clamp_max_body_chars(opts.max_body_chars, &state.config);
    let max_style_samples = opts
        .max_style_samples
        .unwrap_or(DEFAULT_MAX_STYLE_SAMPLES)
        .min(HARD_MAX_STYLE_SAMPLES);
    let max_related_threads = opts
        .max_related_threads
        .unwrap_or(DEFAULT_MAX_RELATED_THREADS)
        .min(HARD_MAX_RELATED_THREADS);

    let self_email = state.store.mailbox_id().trim().to_ascii_lowercase();
    let mut ordered: Vec<&StoredMessage> = stored.messages.iter().collect();
    ordered.sort_by(|a, b| {
        a.internal_date_ms
            .cmp(&b.internal_date_ms)
            .then_with(|| a.id.cmp(&b.id))
    });
    let recipient = primary_recipient(&ordered, &self_email);
    let raw_subject = ordered
        .iter()
        .find(|m| !m.subject.trim().is_empty())
        .map(|m| m.subject.clone())
        .unwrap_or_default();

    let participants = collect_participants(state, &ordered, &self_email).await?;
    let style_samples = match recipient.as_deref() {
        Some(r) => {
            collect_style_samples(
                state,
                thread_id,
                &self_email,
                r,
                max_style_samples,
                max_body_chars,
            )
            .await?
        }
        None => Vec::new(),
    };
    let related_threads = collect_related_threads(
        state,
        thread_id,
        &raw_subject,
        recipient.as_deref(),
        max_related_threads,
    )
    .await?;

    let thread =
        super::build_thread_detail(state, stored, max_body_chars, true, false, true).await?;
    let annotation = state.store.get_thread_annotation(thread_id).await?;

    Ok(ReplyContextResponse {
        thread,
        annotation,
        participants,
        primary_recipient: recipient,
        style_samples,
        related_threads,
        meta: untrusted_meta(&state.config),
    })
}

#[cfg(test)]
mod tests {
    use super::clean_subject;

    #[test]
    fn clean_subject_strips_repeated_prefixes() {
        assert_eq!(clean_subject("Re: Fwd: RE: Budget plan"), "Budget plan");
        assert_eq!(clean_subject("  fw:Hello"), "Hello");
        assert_eq!(clean_subject("Regarding Re: x"), "Regarding Re: x");
        assert_eq!(clean_subject("Re:"), "");
    }
}
