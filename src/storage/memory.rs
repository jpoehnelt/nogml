//! Pure in-memory `MailStore` implementation for fast tests and backend portability.
//!
//! Owned by the `storage` worker.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    error::{AppError, AppResult},
    models::{
        AttachmentMeta, EmailAddress, LABEL_DRAFT, LABEL_INBOX, LABEL_SENT, LABEL_SPAM,
        LABEL_STARRED, LABEL_TRASH, LABEL_UNREAD, LabelColor, Profile, SYSTEM_LABEL_IDS,
        ThreadSummary, is_system_label,
    },
    storage::{
        AiMessagePage, AiSearchQuery, AiThreadPage, AiThreadQuery, DraftListPage, HistoryEventKind,
        HistoryListPage, HistoryListQuery, ImapMailboxInfo, ImapMessageEntry, MailStore,
        MessageListPage, MessageListQuery, NewLabelInput, NewMessageInput, StoredAttachment,
        StoredDraft, StoredHistoryEntry, StoredLabel, StoredMessage, StoredThreadDetail, SyncState,
        ThreadListPage, TriagePatch, TriageResult, UpdateLabelInput, UpsertOutcome,
        UpsertOutcomeKind, UserSettings, WatchSubscription, parse_simple_email_address,
    },
};

const ALL_MAIL_MAILBOX: &str = "[Gmail]/All Mail";
const SENT_MAILBOX: &str = "[Gmail]/Sent Mail";
const DRAFTS_MAILBOX: &str = "[Gmail]/Drafts";
const TRASH_MAILBOX: &str = "[Gmail]/Trash";
const SPAM_MAILBOX: &str = "[Gmail]/Spam";
const STARRED_MAILBOX: &str = "[Gmail]/Starred";

#[derive(Debug, Clone)]
struct MemLabel {
    id: String,
    name: String,
    label_type: String,
    message_list_visibility: Option<String>,
    label_list_visibility: Option<String>,
    color: Option<LabelColor>,
    uid_validity: u32,
    uid_next: u32,
    upstream_label_id: Option<String>,
}

#[derive(Debug, Clone)]
struct MemDraft {
    id: String,
    message_id: String,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct MemHistoryEvent {
    seq_id: u64,
    entry: StoredHistoryEntry,
    context_labels: Vec<String>,
}

#[derive(Debug)]
struct MemoryState {
    default_email: String,
    history_seq: u64,
    history_event_seq: u64,
    next_uid_validity: u32,
    all_mail_uid_validity: u32,
    all_mail_uid_next: u32,
    labels: HashMap<String, MemLabel>,
    messages: HashMap<String, StoredMessage>,
    /// Per-label monotonic IMAP UIDs keyed by `(message_id, label_id)`.
    message_label_uids: HashMap<(String, String), u32>,
    attachments: HashMap<String, Vec<StoredAttachment>>,
    drafts: HashMap<String, MemDraft>,
    history_events: Vec<MemHistoryEvent>,
    sync_states: HashMap<String, SyncState>,
    watch: Option<WatchSubscription>,
    settings: UserSettings,
}

impl MemoryState {
    fn new(default_email: &str) -> Self {
        let mut next_uid_validity: u32 = 1;
        let all_mail_uid_validity = next_uid_validity;
        next_uid_validity += 1;

        let mut labels = HashMap::new();
        for &label_id in SYSTEM_LABEL_IDS {
            let uv = next_uid_validity;
            next_uid_validity += 1;
            let (msg_vis, lbl_vis) = if label_id == LABEL_TRASH || label_id == LABEL_SPAM {
                ("hide", "labelHide")
            } else {
                ("show", "labelShow")
            };
            labels.insert(
                label_id.to_string(),
                MemLabel {
                    id: label_id.to_string(),
                    name: label_id.to_string(),
                    label_type: "system".to_string(),
                    message_list_visibility: Some(msg_vis.to_string()),
                    label_list_visibility: Some(lbl_vis.to_string()),
                    color: None,
                    uid_validity: uv,
                    uid_next: 1,
                    upstream_label_id: None,
                },
            );
        }

        Self {
            default_email: default_email.to_string(),
            history_seq: 1,
            history_event_seq: 0,
            next_uid_validity,
            all_mail_uid_validity,
            all_mail_uid_next: 1,
            labels,
            messages: HashMap::new(),
            message_label_uids: HashMap::new(),
            attachments: HashMap::new(),
            drafts: HashMap::new(),
            history_events: Vec::new(),
            sync_states: HashMap::new(),
            watch: None,
            settings: UserSettings::default_for_email(default_email),
        }
    }

    fn alloc_uid_validity(&mut self) -> u32 {
        let uv = self.next_uid_validity.max(1);
        self.next_uid_validity = uv.saturating_add(1);
        uv
    }

    fn bump_history_id(&mut self) -> u64 {
        self.history_seq += 1;
        self.history_seq
    }

    #[allow(clippy::too_many_arguments)]
    fn record_history_event(
        &mut self,
        history_id: u64,
        kind: HistoryEventKind,
        message_id: &str,
        thread_id: &str,
        label_ids: Vec<String>,
        context_labels: Vec<String>,
        upstream_gmail_id: Option<String>,
    ) {
        self.history_event_seq += 1;
        self.history_events.push(MemHistoryEvent {
            seq_id: self.history_event_seq,
            entry: StoredHistoryEntry {
                history_id,
                kind,
                message_id: message_id.to_string(),
                thread_id: thread_id.to_string(),
                label_ids,
                upstream_gmail_id,
            },
            context_labels,
        });
    }

    fn alloc_all_mail_uid(&mut self) -> u32 {
        let uid = self.all_mail_uid_next.max(1);
        self.all_mail_uid_next = uid.saturating_add(1);
        uid
    }

    fn alloc_label_uid(&mut self, label_id: &str) -> AppResult<u32> {
        let lbl = self
            .labels
            .get_mut(label_id)
            .ok_or_else(|| AppError::BadRequest(format!("Label not found: {label_id}")))?;
        let uid = lbl.uid_next.max(1);
        lbl.uid_next = uid.saturating_add(1);
        Ok(uid)
    }

    fn resolve_existing_label_id(&self, raw_label: &str) -> Option<String> {
        let trimmed = raw_label.trim();
        if trimmed.is_empty() {
            return None;
        }
        if self.labels.contains_key(trimmed) {
            return Some(trimmed.to_string());
        }
        self.labels
            .values()
            .find(|l| l.name.eq_ignore_ascii_case(trimmed))
            .map(|l| l.id.clone())
    }

    fn ensure_label_exists(&mut self, raw_label: &str) -> AppResult<String> {
        let trimmed = raw_label.trim();
        if trimmed.is_empty() {
            return Err(AppError::BadRequest("Label ID cannot be empty".into()));
        }
        if let Some(id) = self.resolve_existing_label_id(trimmed) {
            return Ok(id);
        }
        if let Some(lbl) = self
            .labels
            .values()
            .find(|l| l.upstream_label_id.as_deref() == Some(trimmed))
        {
            return Ok(lbl.id.clone());
        }
        let uv = self.alloc_uid_validity();
        self.labels.insert(
            trimmed.to_string(),
            MemLabel {
                id: trimmed.to_string(),
                name: trimmed.to_string(),
                label_type: "user".to_string(),
                message_list_visibility: Some("show".to_string()),
                label_list_visibility: Some("labelShow".to_string()),
                color: None,
                uid_validity: uv,
                uid_next: 1,
                upstream_label_id: None,
            },
        );
        Ok(trimmed.to_string())
    }

    fn resolve_thread_id(&self, input: &NewMessageInput, msg_id: &str) -> String {
        if let Some(ref tid) = input.thread_id
            && !tid.trim().is_empty()
        {
            return tid.trim().to_string();
        }
        if let Some(ref utid) = input.upstream_thread_id
            && !utid.trim().is_empty()
            && let Some(existing) = self
                .messages
                .values()
                .find(|m| m.upstream_thread_id.as_deref() == Some(utid.trim()))
        {
            return existing.thread_id.clone();
        }
        if let Some(ref irt) = input.in_reply_to
            && let Some(norm) = normalize_rfc_message_id(irt)
            && let Some(existing) = self.find_msg_by_norm_rfc_id(&norm)
        {
            return existing.thread_id.clone();
        }
        if let Some(ref refs) = input.references_header {
            for token in refs.split_whitespace().rev() {
                if let Some(norm) = normalize_rfc_message_id(token)
                    && let Some(existing) = self.find_msg_by_norm_rfc_id(&norm)
                {
                    return existing.thread_id.clone();
                }
            }
        }
        msg_id.to_string()
    }

    fn find_msg_by_norm_rfc_id(&self, norm: &str) -> Option<&StoredMessage> {
        self.messages.values().find(|m| {
            m.rfc822_message_id
                .as_deref()
                .and_then(normalize_rfc_message_id)
                .as_deref()
                == Some(norm)
        })
    }

    fn insert_message_inner(&mut self, input: NewMessageInput) -> AppResult<StoredMessage> {
        let msg_id = input
            .id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(new_hex_id);
        let thread_id = self.resolve_thread_id(&input, &msg_id);

        let mut label_set = HashSet::new();
        let mut resolved_labels = Vec::new();
        for raw_l in &input.label_ids {
            let lid = self.ensure_label_exists(raw_l)?;
            if label_set.insert(lid.clone()) {
                resolved_labels.push(lid);
            }
        }
        resolved_labels.sort();

        let history_id = self.bump_history_id();
        let all_mail_uid = self.alloc_all_mail_uid();
        let size_estimate = input.raw_rfc2822.len().min(i32::MAX as usize) as i32;
        let has_attachments = !input.attachments.is_empty();
        let source = if input.source.trim().is_empty() {
            "local".to_string()
        } else {
            input.source.clone()
        };

        for lid in &resolved_labels {
            let imap_uid = self.alloc_label_uid(lid)?;
            self.message_label_uids
                .insert((msg_id.clone(), lid.clone()), imap_uid);
        }

        let mut stored_atts = Vec::with_capacity(input.attachments.len());
        for att in input.attachments {
            let size_bytes = att.data.len() as u64;
            stored_atts.push(StoredAttachment {
                id: format!("att_{}", new_hex_id()),
                message_id: msg_id.clone(),
                part_id: att.part_id,
                filename: att.filename,
                content_type: att.content_type,
                content_id: att.content_id,
                size_bytes,
                data: att.data,
            });
        }
        if !stored_atts.is_empty() {
            self.attachments.insert(msg_id.clone(), stored_atts);
        }

        let stored = StoredMessage {
            id: msg_id.clone(),
            thread_id: thread_id.clone(),
            label_ids: resolved_labels.clone(),
            raw_rfc2822: input.raw_rfc2822,
            snippet: input.snippet,
            history_id,
            internal_date_ms: input.internal_date_ms,
            size_estimate,
            subject: input.subject,
            from_addr: input.from_addr,
            to_addrs: input.to_addrs,
            cc_addrs: input.cc_addrs,
            bcc_addrs: input.bcc_addrs,
            text_body: input.text_body,
            html_body: input.html_body,
            has_attachments,
            rfc822_message_id: input.rfc822_message_id,
            in_reply_to: input.in_reply_to,
            references_header: input.references_header,
            resend_id: input.resend_id,
            delivery_status: None,
            upstream_gmail_id: input.upstream_gmail_id,
            upstream_thread_id: input.upstream_thread_id,
            source,
            all_mail_uid,
            is_answered: input.is_answered,
            is_deleted: input.is_deleted,
        };

        self.messages.insert(msg_id.clone(), stored.clone());
        self.record_history_event(
            history_id,
            HistoryEventKind::MessageAdded,
            &msg_id,
            &thread_id,
            resolved_labels.clone(),
            resolved_labels,
            stored.upstream_gmail_id.clone(),
        );
        Ok(stored)
    }

    fn modify_message_labels_resolved(
        &mut self,
        message_id: &str,
        resolved_add: &[String],
        resolved_remove: &[String],
    ) -> AppResult<StoredMessage> {
        let (thread_id, current_labels, upstream_gmail_id) = {
            let msg = self
                .messages
                .get(message_id)
                .ok_or_else(|| AppError::NotFound(format!("Message not found: {message_id}")))?;
            (
                msg.thread_id.clone(),
                msg.label_ids.clone(),
                msg.upstream_gmail_id.clone(),
            )
        };

        let current_set: HashSet<String> = current_labels.iter().cloned().collect();
        let remove_set: HashSet<&String> = resolved_remove.iter().collect();

        let mut actually_added = Vec::new();
        let mut add_seen = HashSet::new();
        for lid in resolved_add {
            if !remove_set.contains(lid)
                && !current_set.contains(lid)
                && add_seen.insert(lid.clone())
            {
                actually_added.push(lid.clone());
            }
        }

        let mut actually_removed = Vec::new();
        let mut rem_seen = HashSet::new();
        for lid in resolved_remove {
            if current_set.contains(lid) && rem_seen.insert(lid.clone()) {
                actually_removed.push(lid.clone());
            }
        }

        if !actually_added.is_empty() || !actually_removed.is_empty() {
            let new_hid = self.bump_history_id();
            for lid in &actually_added {
                let imap_uid = self.alloc_label_uid(lid)?;
                self.message_label_uids
                    .insert((message_id.to_string(), lid.clone()), imap_uid);
            }
            for lid in &actually_removed {
                self.message_label_uids
                    .remove(&(message_id.to_string(), lid.clone()));
            }

            let mut new_set = current_set.clone();
            for lid in &actually_added {
                new_set.insert(lid.clone());
            }
            for lid in &actually_removed {
                new_set.remove(lid);
            }
            let mut new_labels: Vec<String> = new_set.into_iter().collect();
            new_labels.sort();

            if let Some(msg) = self.messages.get_mut(message_id) {
                msg.label_ids = new_labels;
                msg.history_id = new_hid;
            }

            let mut ctx_set = current_set;
            for lid in &actually_added {
                ctx_set.insert(lid.clone());
            }
            let mut context_labels: Vec<String> = ctx_set.into_iter().collect();
            context_labels.sort();

            if !actually_added.is_empty() {
                self.record_history_event(
                    new_hid,
                    HistoryEventKind::LabelAdded,
                    message_id,
                    &thread_id,
                    actually_added,
                    context_labels.clone(),
                    upstream_gmail_id.clone(),
                );
            }
            if !actually_removed.is_empty() {
                self.record_history_event(
                    new_hid,
                    HistoryEventKind::LabelRemoved,
                    message_id,
                    &thread_id,
                    actually_removed,
                    context_labels,
                    upstream_gmail_id,
                );
            }
        }

        self.messages
            .get(message_id)
            .cloned()
            .ok_or_else(|| AppError::NotFound(format!("Message not found: {message_id}")))
    }

    fn delete_message_inner(&mut self, id: &str) -> Option<StoredMessage> {
        let msg = self.messages.remove(id)?;
        self.attachments.remove(id);
        self.message_label_uids.retain(|(mid, _), _| mid != id);
        self.drafts.retain(|_, d| d.message_id != id);
        let hid = self.bump_history_id();
        self.record_history_event(
            hid,
            HistoryEventKind::MessageDeleted,
            &msg.id,
            &msg.thread_id,
            msg.label_ids.clone(),
            msg.label_ids.clone(),
            msg.upstream_gmail_id.clone(),
        );
        Some(msg)
    }

    fn build_stored_label(&self, lbl: &MemLabel) -> StoredLabel {
        let mut messages_total = 0_i32;
        let mut messages_unread = 0_i32;
        let mut threads = HashSet::new();
        let mut unread_threads = HashSet::new();

        for msg in self.messages.values() {
            if msg.label_ids.iter().any(|l| l == &lbl.id) {
                messages_total += 1;
                threads.insert(msg.thread_id.as_str());
                if msg.label_ids.iter().any(|l| l == LABEL_UNREAD) {
                    messages_unread += 1;
                    unread_threads.insert(msg.thread_id.as_str());
                }
            }
        }

        StoredLabel {
            id: lbl.id.clone(),
            name: lbl.name.clone(),
            label_type: lbl.label_type.clone(),
            message_list_visibility: lbl.message_list_visibility.clone(),
            label_list_visibility: lbl.label_list_visibility.clone(),
            color: lbl.color.clone(),
            messages_total,
            messages_unread,
            threads_total: threads.len() as i32,
            threads_unread: unread_threads.len() as i32,
            uid_validity: lbl.uid_validity,
            uid_next: lbl.uid_next,
            upstream_label_id: lbl.upstream_label_id.clone(),
        }
    }

    fn get_thread_detail_inner(&self, thread_id: &str) -> Option<StoredThreadDetail> {
        let mut msgs: Vec<StoredMessage> = self
            .messages
            .values()
            .filter(|m| m.thread_id == thread_id)
            .cloned()
            .collect();
        if msgs.is_empty() {
            return None;
        }
        msgs.sort_by(|a, b| {
            a.internal_date_ms
                .cmp(&b.internal_date_ms)
                .then_with(|| a.id.cmp(&b.id))
        });
        let snippet = msgs.last().map(|m| m.snippet.clone()).unwrap_or_default();
        let history_id = msgs.iter().map(|m| m.history_id).max().unwrap_or(1);
        Some(StoredThreadDetail {
            id: thread_id.to_string(),
            snippet,
            history_id,
            messages: msgs,
        })
    }

    fn resolve_imap_mailbox(&self, mailbox_name: &str) -> Option<ResolvedMailbox> {
        if mailbox_name.eq_ignore_ascii_case("INBOX") {
            return Some(ResolvedMailbox::Label {
                id: LABEL_INBOX.to_string(),
                name: "INBOX".to_string(),
                special_use: None,
            });
        }
        if mailbox_name == ALL_MAIL_MAILBOX {
            return Some(ResolvedMailbox::AllMail);
        }
        if mailbox_name == SENT_MAILBOX {
            return Some(ResolvedMailbox::Label {
                id: LABEL_SENT.to_string(),
                name: SENT_MAILBOX.to_string(),
                special_use: Some("\\Sent"),
            });
        }
        if mailbox_name == DRAFTS_MAILBOX {
            return Some(ResolvedMailbox::Label {
                id: LABEL_DRAFT.to_string(),
                name: DRAFTS_MAILBOX.to_string(),
                special_use: Some("\\Drafts"),
            });
        }
        if mailbox_name == TRASH_MAILBOX {
            return Some(ResolvedMailbox::Label {
                id: LABEL_TRASH.to_string(),
                name: TRASH_MAILBOX.to_string(),
                special_use: Some("\\Trash"),
            });
        }
        if mailbox_name == SPAM_MAILBOX {
            return Some(ResolvedMailbox::Label {
                id: LABEL_SPAM.to_string(),
                name: SPAM_MAILBOX.to_string(),
                special_use: Some("\\Junk"),
            });
        }
        if mailbox_name == STARRED_MAILBOX {
            return Some(ResolvedMailbox::Label {
                id: LABEL_STARRED.to_string(),
                name: STARRED_MAILBOX.to_string(),
                special_use: Some("\\Flagged"),
            });
        }
        self.labels
            .values()
            .find(|l| l.label_type == "user" && l.name == mailbox_name)
            .map(|l| ResolvedMailbox::Label {
                id: l.id.clone(),
                name: l.name.clone(),
                special_use: None,
            })
    }

    fn imap_mailbox_info_resolved(&self, resolved: &ResolvedMailbox) -> ImapMailboxInfo {
        match resolved {
            ResolvedMailbox::AllMail => {
                let mut messages = 0_u32;
                let mut unseen = 0_u32;
                for m in self.messages.values() {
                    if !m
                        .label_ids
                        .iter()
                        .any(|l| l == LABEL_TRASH || l == LABEL_SPAM)
                    {
                        messages += 1;
                        if m.label_ids.iter().any(|l| l == LABEL_UNREAD) {
                            unseen += 1;
                        }
                    }
                }
                ImapMailboxInfo {
                    name: ALL_MAIL_MAILBOX.to_string(),
                    label_id: None,
                    special_use: Some("\\All".to_string()),
                    uid_validity: self.all_mail_uid_validity,
                    uid_next: self.all_mail_uid_next,
                    messages,
                    unseen,
                }
            }
            ResolvedMailbox::Label {
                id,
                name,
                special_use,
            } => {
                let (uid_validity, uid_next) = self
                    .labels
                    .get(id)
                    .map(|l| (l.uid_validity, l.uid_next))
                    .unwrap_or((1, 1));
                let mut messages = 0_u32;
                let mut unseen = 0_u32;
                for m in self.messages.values() {
                    if m.label_ids.iter().any(|l| l == id) {
                        messages += 1;
                        if m.label_ids.iter().any(|l| l == LABEL_UNREAD) {
                            unseen += 1;
                        }
                    }
                }
                ImapMailboxInfo {
                    name: name.clone(),
                    label_id: Some(id.clone()),
                    special_use: special_use.map(ToString::to_string),
                    uid_validity,
                    uid_next,
                    messages,
                    unseen,
                }
            }
        }
    }

    fn imap_list_messages_resolved(&self, resolved: &ResolvedMailbox) -> Vec<ImapMessageEntry> {
        let mut pairs: Vec<(u32, &StoredMessage)> = match resolved {
            ResolvedMailbox::AllMail => self
                .messages
                .values()
                .filter(|m| {
                    !m.label_ids
                        .iter()
                        .any(|l| l == LABEL_TRASH || l == LABEL_SPAM)
                })
                .map(|m| (m.all_mail_uid, m))
                .collect(),
            ResolvedMailbox::Label { id, .. } => self
                .messages
                .values()
                .filter_map(|m| {
                    self.message_label_uids
                        .get(&(m.id.clone(), id.clone()))
                        .map(|&uid| (uid, m))
                })
                .collect(),
        };
        pairs.sort_by_key(|(uid, _)| *uid);
        pairs
            .into_iter()
            .enumerate()
            .map(|(idx, (uid, m))| ImapMessageEntry {
                seq: (idx + 1) as u32,
                uid,
                message_id: m.id.clone(),
                thread_id: m.thread_id.clone(),
                internal_date_ms: m.internal_date_ms,
                size_estimate: m.size_estimate,
                label_ids: m.label_ids.clone(),
                is_answered: m.is_answered,
                is_deleted: m.is_deleted,
            })
            .collect()
    }
}

enum ResolvedMailbox {
    AllMail,
    Label {
        id: String,
        name: String,
        special_use: Option<&'static str>,
    },
}

/// In-memory implementation of [`MailStore`].
#[derive(Clone)]
pub struct MemoryStore {
    state: Arc<RwLock<MemoryState>>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new("me@localhost")
    }
}

impl MemoryStore {
    pub fn new(default_email: &str) -> Self {
        Self {
            state: Arc::new(RwLock::new(MemoryState::new(default_email))),
        }
    }

    fn read_state(&self) -> AppResult<std::sync::RwLockReadGuard<'_, MemoryState>> {
        self.state
            .read()
            .map_err(|_| AppError::Storage("MemoryStore read lock poisoned".into()))
    }

    fn write_state(&self) -> AppResult<std::sync::RwLockWriteGuard<'_, MemoryState>> {
        self.state
            .write()
            .map_err(|_| AppError::Storage("MemoryStore write lock poisoned".into()))
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn new_hex_id() -> String {
    Uuid::new_v4().simple().to_string()[..16].to_string()
}

fn normalize_rfc_message_id(raw: &str) -> Option<String> {
    let inner = raw
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim()
        .to_ascii_lowercase();
    if inner.is_empty() {
        None
    } else {
        Some(format!("<{inner}>"))
    }
}

fn parse_offset_token(token: Option<&str>) -> AppResult<usize> {
    match token {
        None => Ok(0),
        Some(s) if s.trim().is_empty() => Ok(0),
        Some(s) => s
            .trim()
            .parse::<usize>()
            .map_err(|_| AppError::BadRequest(format!("Invalid pageToken: {s}"))),
    }
}

fn encode_keyset_cursor(ts_ms: i64, id: &str) -> String {
    format!("{ts_ms}:{id}")
}

fn decode_keyset_cursor(cursor: &str) -> AppResult<(i64, String)> {
    let (ts_part, id_part) = cursor
        .split_once(':')
        .ok_or_else(|| AppError::BadRequest(format!("Invalid cursor: {cursor}")))?;
    let ts_ms = ts_part
        .parse::<i64>()
        .map_err(|_| AppError::BadRequest(format!("Invalid cursor timestamp: {cursor}")))?;
    if id_part.is_empty() {
        return Err(AppError::BadRequest(format!("Invalid cursor id: {cursor}")));
    }
    Ok((ts_ms, id_part.to_string()))
}

fn rewrite_search_term_labels(
    term: crate::search::SearchTerm,
    name_to_id: &HashMap<String, String>,
) -> crate::search::SearchTerm {
    use crate::search::SearchTerm;
    match term {
        SearchTerm::Label(val) => {
            let key_exact = val.to_ascii_lowercase();
            let key_hyphen = key_exact.replace('/', "-");
            if let Some(id) = name_to_id
                .get(&key_exact)
                .or_else(|| name_to_id.get(&key_hyphen))
            {
                SearchTerm::Or(vec![SearchTerm::Label(val), SearchTerm::Label(id.clone())])
            } else {
                SearchTerm::Label(val)
            }
        }
        SearchTerm::InMailbox(val) => {
            let key_exact = val.to_ascii_lowercase();
            let key_hyphen = key_exact.replace('/', "-");
            if let Some(id) = name_to_id
                .get(&key_exact)
                .or_else(|| name_to_id.get(&key_hyphen))
            {
                SearchTerm::Or(vec![
                    SearchTerm::InMailbox(val),
                    SearchTerm::Label(id.clone()),
                ])
            } else {
                SearchTerm::InMailbox(val)
            }
        }
        SearchTerm::Not(inner) => {
            SearchTerm::Not(Box::new(rewrite_search_term_labels(*inner, name_to_id)))
        }
        SearchTerm::And(terms) => SearchTerm::And(
            terms
                .into_iter()
                .map(|t| rewrite_search_term_labels(t, name_to_id))
                .collect(),
        ),
        SearchTerm::Or(terms) => SearchTerm::Or(
            terms
                .into_iter()
                .map(|t| rewrite_search_term_labels(t, name_to_id))
                .collect(),
        ),
        other => other,
    }
}

fn parse_query_with_labels(state: &MemoryState, raw_q: &str) -> crate::search::SearchQuery {
    let mut parsed = crate::search::parse_query(raw_q);
    if !parsed.terms.is_empty() {
        let mut map = HashMap::new();
        for lbl in state.labels.values() {
            let lower = lbl.name.to_ascii_lowercase();
            let hyphen = lower.replace('/', "-");
            map.insert(lower, lbl.id.clone());
            map.insert(hyphen, lbl.id.clone());
        }
        parsed.terms = parsed
            .terms
            .into_iter()
            .map(|t| rewrite_search_term_labels(t, &map))
            .collect();
    }
    parsed
}

/// Tokenize an AI search query into case-insensitive phrases and terms,
/// matching across `(subject, from_addr, to_addrs, cc_addrs, text_body, snippet)`.
fn parse_ai_query_terms(raw: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let mut chars = raw.chars().peekable();
    while let Some(&ch) = chars.peek() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }
        if ch == '"' {
            chars.next();
            let mut phrase = String::new();
            for c in chars.by_ref() {
                if c == '"' {
                    break;
                }
                phrase.push(c);
            }
            let trimmed = phrase.trim().to_ascii_lowercase();
            if !trimmed.is_empty() {
                terms.push(trimmed);
            }
        } else {
            let mut word = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() || c == '"' {
                    break;
                }
                word.push(c);
                chars.next();
            }
            let lower = word.to_ascii_lowercase();
            if !lower.is_empty() {
                terms.push(lower);
            }
        }
    }
    terms
}

fn matches_ai_text_query(msg: &StoredMessage, raw_q: &str) -> bool {
    let terms = parse_ai_query_terms(raw_q);
    if terms.is_empty() {
        return true;
    }
    let haystack = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        msg.subject,
        msg.from_addr,
        msg.to_addrs.join(" "),
        msg.cc_addrs.join(" "),
        msg.text_body,
        msg.snippet
    )
    .to_ascii_lowercase();

    terms.iter().all(|term| {
        if haystack.contains(term) {
            return true;
        }
        // Fallback: check sub-tokens split on punctuation (mirrors FTS5 unicode61 behavior for e.g. `alice@acme.com`)
        let sub_tokens: Vec<&str> = term
            .split(|c: char| !c.is_alphanumeric())
            .filter(|s| !s.is_empty())
            .collect();
        !sub_tokens.is_empty() && sub_tokens.iter().all(|st| haystack.contains(st))
    })
}

fn build_thread_summary(thread_id: &str, messages: &[StoredMessage]) -> ThreadSummary {
    let subject = messages
        .first()
        .map(|m| m.subject.clone())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            messages
                .iter()
                .rev()
                .find(|m| !m.subject.is_empty())
                .map(|m| m.subject.clone())
        })
        .unwrap_or_default();

    let mut seen_emails = HashSet::new();
    let mut participants: Vec<EmailAddress> = Vec::new();
    for msg in messages {
        if !msg.from_addr.trim().is_empty() {
            let parsed = parse_simple_email_address(&msg.from_addr);
            let key = parsed.email.to_ascii_lowercase();
            if !key.is_empty() && seen_emails.insert(key) {
                participants.push(parsed);
            }
        }
    }

    let snippet = messages
        .last()
        .map(|m| m.snippet.clone())
        .unwrap_or_default();

    let mut label_set = HashSet::new();
    let mut has_attachments = false;
    let mut max_ts = i64::MIN;
    for msg in messages {
        for l in &msg.label_ids {
            label_set.insert(l.clone());
        }
        if msg.has_attachments {
            has_attachments = true;
        }
        if msg.internal_date_ms > max_ts {
            max_ts = msg.internal_date_ms;
        }
    }
    let mut labels: Vec<String> = label_set.into_iter().collect();
    labels.sort();
    let unread = labels.iter().any(|l| l == LABEL_UNREAD);
    let last_message_at = DateTime::from_timestamp_millis(max_ts).unwrap_or_else(Utc::now);

    ThreadSummary {
        id: thread_id.to_string(),
        subject,
        participants,
        snippet,
        labels,
        unread,
        has_attachments,
        message_count: messages.len(),
        last_message_at,
    }
}

// ============================================================================
// `MailStore` Implementation
// ============================================================================

#[async_trait]
impl MailStore for MemoryStore {
    fn backend_name(&self) -> &'static str {
        "memory"
    }
    async fn get_profile(&self, email_address: &str) -> AppResult<Profile> {
        let state = self.read_state()?;
        let email = if email_address.trim().is_empty() {
            state.default_email.clone()
        } else {
            email_address.to_string()
        };
        let messages_total = state.messages.len() as i32;
        let threads_total = state
            .messages
            .values()
            .map(|m| m.thread_id.as_str())
            .collect::<HashSet<_>>()
            .len() as i32;
        Ok(Profile {
            email_address: email,
            messages_total,
            threads_total,
            history_id: state.history_seq.to_string(),
        })
    }

    async fn current_history_id(&self) -> AppResult<u64> {
        let state = self.read_state()?;
        Ok(state.history_seq)
    }

    async fn list_history(&self, query: &HistoryListQuery) -> AppResult<HistoryListPage> {
        if query.start_history_id == 0 {
            return Err(AppError::NotFound(
                "Invalid startHistoryId: must be greater than 0".into(),
            ));
        }
        let state = self.read_state()?;
        let after_seq_id: u64 = match query.page_token.as_deref() {
            None => 0,
            Some(s) if s.trim().is_empty() => 0,
            Some(s) => s
                .trim()
                .parse::<u64>()
                .map_err(|_| AppError::BadRequest(format!("Invalid pageToken: {s}")))?,
        };
        let max_results = if query.max_results == 0 {
            100
        } else {
            query.max_results.min(500)
        };
        let resolved_label_filter = match query.label_id.as_deref() {
            Some(l) if !l.trim().is_empty() => Some(
                state
                    .resolve_existing_label_id(l)
                    .unwrap_or_else(|| l.to_string()),
            ),
            _ => None,
        };

        let mut matched: Vec<(u64, StoredHistoryEntry)> = Vec::new();
        for ev in &state.history_events {
            if ev.entry.history_id <= query.start_history_id || ev.seq_id <= after_seq_id {
                continue;
            }
            if !query.history_types.is_empty() && !query.history_types.contains(&ev.entry.kind) {
                continue;
            }
            if let Some(ref filter_lid) = resolved_label_filter
                && !ev.entry.label_ids.contains(filter_lid)
                && !ev.context_labels.contains(filter_lid)
            {
                continue;
            }
            matched.push((ev.seq_id, ev.entry.clone()));
            if matched.len() > max_results {
                break;
            }
        }

        let has_more = matched.len() > max_results;
        if has_more {
            matched.truncate(max_results);
        }
        let next_page_token = if has_more {
            matched.last().map(|(seq_id, _)| seq_id.to_string())
        } else {
            None
        };
        let entries = matched.into_iter().map(|(_, e)| e).collect();

        Ok(HistoryListPage {
            entries,
            next_page_token,
            current_history_id: state.history_seq,
        })
    }

    async fn insert_message(&self, input: NewMessageInput) -> AppResult<StoredMessage> {
        let mut state = self.write_state()?;
        state.insert_message_inner(input)
    }

    async fn get_message(&self, id: &str) -> AppResult<Option<StoredMessage>> {
        let state = self.read_state()?;
        Ok(state.messages.get(id).cloned())
    }

    async fn list_messages(&self, query: &MessageListQuery) -> AppResult<MessageListPage> {
        let state = self.read_state()?;
        let max_results = if query.max_results == 0 {
            100
        } else {
            query.max_results.min(500)
        };
        let offset = parse_offset_token(query.page_token.as_deref())?;

        let parsed_q = query
            .q
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|raw| parse_query_with_labels(&state, raw));

        let resolved_labels: Vec<String> = query
            .label_ids
            .iter()
            .map(|l| {
                state
                    .resolve_existing_label_id(l)
                    .unwrap_or_else(|| l.clone())
            })
            .collect();
        let explicit_spam_trash = resolved_labels
            .iter()
            .any(|l| l == LABEL_TRASH || l == LABEL_SPAM);
        let effective_include_spam_trash = query.include_spam_trash
            || explicit_spam_trash
            || parsed_q.as_ref().is_some_and(|pq| pq.include_spam_trash);

        let mut matching: Vec<StoredMessage> = state
            .messages
            .values()
            .filter(|m| {
                if !effective_include_spam_trash
                    && m.label_ids
                        .iter()
                        .any(|l| l == LABEL_TRASH || l == LABEL_SPAM)
                {
                    return false;
                }
                if !resolved_labels
                    .iter()
                    .all(|req| m.label_ids.iter().any(|l| l == req))
                {
                    return false;
                }
                if let Some(ref pq) = parsed_q
                    && !crate::search::matches_message(pq, m)
                {
                    return false;
                }
                true
            })
            .cloned()
            .collect();

        matching.sort_by(|a, b| {
            b.internal_date_ms
                .cmp(&a.internal_date_ms)
                .then_with(|| b.id.cmp(&a.id))
        });

        let total = matching.len();
        let page: Vec<StoredMessage> = matching
            .into_iter()
            .skip(offset)
            .take(max_results)
            .collect();
        let next_page_token = if offset + page.len() < total {
            Some((offset + page.len()).to_string())
        } else {
            None
        };

        Ok(MessageListPage {
            messages: page,
            next_page_token,
            result_size_estimate: total as u32,
        })
    }

    async fn modify_message_labels(
        &self,
        id: &str,
        add_labels: &[String],
        remove_labels: &[String],
    ) -> AppResult<StoredMessage> {
        let mut state = self.write_state()?;
        let mut resolved_add = Vec::with_capacity(add_labels.len());
        for l in add_labels {
            let lid = state
                .resolve_existing_label_id(l)
                .ok_or_else(|| AppError::BadRequest(format!("Label not found: {l}")))?;
            resolved_add.push(lid);
        }
        let mut resolved_remove = Vec::with_capacity(remove_labels.len());
        for l in remove_labels {
            if let Some(lid) = state.resolve_existing_label_id(l) {
                resolved_remove.push(lid);
            }
        }
        state.modify_message_labels_resolved(id, &resolved_add, &resolved_remove)
    }

    async fn batch_modify_labels(
        &self,
        ids: &[String],
        add_labels: &[String],
        remove_labels: &[String],
    ) -> AppResult<()> {
        let mut state = self.write_state()?;
        let mut resolved_add = Vec::with_capacity(add_labels.len());
        for l in add_labels {
            let lid = state
                .resolve_existing_label_id(l)
                .ok_or_else(|| AppError::BadRequest(format!("Label not found: {l}")))?;
            resolved_add.push(lid);
        }
        let mut resolved_remove = Vec::with_capacity(remove_labels.len());
        for l in remove_labels {
            if let Some(lid) = state.resolve_existing_label_id(l) {
                resolved_remove.push(lid);
            }
        }
        for id in ids {
            if state.messages.contains_key(id) {
                state.modify_message_labels_resolved(id, &resolved_add, &resolved_remove)?;
            }
        }
        Ok(())
    }

    async fn trash_message(&self, id: &str) -> AppResult<StoredMessage> {
        self.modify_message_labels(id, &[LABEL_TRASH.to_string()], &[LABEL_INBOX.to_string()])
            .await
    }

    async fn untrash_message(&self, id: &str) -> AppResult<StoredMessage> {
        self.modify_message_labels(id, &[], &[LABEL_TRASH.to_string()])
            .await
    }

    async fn delete_message(&self, id: &str) -> AppResult<bool> {
        let mut state = self.write_state()?;
        Ok(state.delete_message_inner(id).is_some())
    }

    async fn batch_delete_messages(&self, ids: &[String]) -> AppResult<()> {
        let mut state = self.write_state()?;
        for id in ids {
            state.delete_message_inner(id);
        }
        Ok(())
    }

    async fn get_attachment(
        &self,
        message_id: &str,
        attachment_id: &str,
    ) -> AppResult<Option<StoredAttachment>> {
        let state = self.read_state()?;
        Ok(state
            .attachments
            .get(message_id)
            .and_then(|list| list.iter().find(|a| a.id == attachment_id).cloned()))
    }

    async fn list_attachment_meta(&self, message_id: &str) -> AppResult<Vec<AttachmentMeta>> {
        let state = self.read_state()?;
        let mut atts = state
            .attachments
            .get(message_id)
            .cloned()
            .unwrap_or_default();
        atts.sort_by(|a, b| a.part_id.cmp(&b.part_id).then_with(|| a.id.cmp(&b.id)));
        Ok(atts
            .into_iter()
            .map(|a| AttachmentMeta {
                id: a.id,
                filename: a.filename,
                content_type: a.content_type,
                size_bytes: a.size_bytes,
            })
            .collect())
    }

    async fn list_threads(&self, query: &MessageListQuery) -> AppResult<ThreadListPage> {
        let state = self.read_state()?;
        let max_results = if query.max_results == 0 {
            100
        } else {
            query.max_results.min(500)
        };
        let offset = parse_offset_token(query.page_token.as_deref())?;

        let parsed_q = query
            .q
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|raw| parse_query_with_labels(&state, raw));

        let required_labels: Vec<String> = query
            .label_ids
            .iter()
            .map(|l| {
                state
                    .resolve_existing_label_id(l)
                    .unwrap_or_else(|| l.clone())
            })
            .collect();
        let explicit_spam_trash = required_labels
            .iter()
            .any(|l| l == LABEL_TRASH || l == LABEL_SPAM);
        let effective_include_spam_trash = query.include_spam_trash
            || explicit_spam_trash
            || parsed_q.as_ref().is_some_and(|pq| pq.include_spam_trash);

        let mut by_thread: BTreeMap<String, Vec<StoredMessage>> = BTreeMap::new();
        for msg in state.messages.values() {
            if !effective_include_spam_trash
                && msg
                    .label_ids
                    .iter()
                    .any(|l| l == LABEL_TRASH || l == LABEL_SPAM)
            {
                continue;
            }
            by_thread
                .entry(msg.thread_id.clone())
                .or_default()
                .push(msg.clone());
        }

        let mut matching: Vec<(i64, StoredThreadDetail)> = Vec::new();
        for (tid, mut msgs) in by_thread {
            msgs.sort_by(|a, b| {
                a.internal_date_ms
                    .cmp(&b.internal_date_ms)
                    .then_with(|| a.id.cmp(&b.id))
            });
            if !required_labels.is_empty() {
                let thread_labels: HashSet<&String> =
                    msgs.iter().flat_map(|m| m.label_ids.iter()).collect();
                if !required_labels
                    .iter()
                    .all(|req| thread_labels.contains(req))
                {
                    continue;
                }
            }
            if let Some(ref pq) = parsed_q
                && !msgs.iter().any(|m| crate::search::matches_message(pq, m))
            {
                continue;
            }
            let max_ts = msgs.iter().map(|m| m.internal_date_ms).max().unwrap_or(0);
            let snippet = msgs.last().map(|m| m.snippet.clone()).unwrap_or_default();
            let history_id = msgs.iter().map(|m| m.history_id).max().unwrap_or(1);
            matching.push((
                max_ts,
                StoredThreadDetail {
                    id: tid,
                    snippet,
                    history_id,
                    messages: msgs,
                },
            ));
        }

        matching.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.id.cmp(&a.1.id)));
        let total = matching.len();
        let page: Vec<StoredThreadDetail> = matching
            .into_iter()
            .skip(offset)
            .take(max_results)
            .map(|(_, t)| t)
            .collect();
        let next_page_token = if offset + page.len() < total {
            Some((offset + page.len()).to_string())
        } else {
            None
        };

        Ok(ThreadListPage {
            threads: page,
            next_page_token,
            result_size_estimate: total as u32,
        })
    }

    async fn get_thread(&self, thread_id: &str) -> AppResult<Option<StoredThreadDetail>> {
        let state = self.read_state()?;
        Ok(state.get_thread_detail_inner(thread_id))
    }

    async fn modify_thread_labels(
        &self,
        thread_id: &str,
        add_labels: &[String],
        remove_labels: &[String],
    ) -> AppResult<StoredThreadDetail> {
        let mut state = self.write_state()?;
        let mut msg_ids: Vec<(i64, String)> = state
            .messages
            .values()
            .filter(|m| m.thread_id == thread_id)
            .map(|m| (m.internal_date_ms, m.id.clone()))
            .collect();
        if msg_ids.is_empty() {
            return Err(AppError::NotFound(format!("Thread not found: {thread_id}")));
        }
        msg_ids.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        let mut resolved_add = Vec::with_capacity(add_labels.len());
        for l in add_labels {
            let lid = state
                .resolve_existing_label_id(l)
                .ok_or_else(|| AppError::BadRequest(format!("Label not found: {l}")))?;
            resolved_add.push(lid);
        }
        let mut resolved_remove = Vec::with_capacity(remove_labels.len());
        for l in remove_labels {
            if let Some(lid) = state.resolve_existing_label_id(l) {
                resolved_remove.push(lid);
            }
        }

        for (_, mid) in msg_ids {
            state.modify_message_labels_resolved(&mid, &resolved_add, &resolved_remove)?;
        }

        state
            .get_thread_detail_inner(thread_id)
            .ok_or_else(|| AppError::NotFound(format!("Thread not found: {thread_id}")))
    }

    async fn trash_thread(&self, thread_id: &str) -> AppResult<StoredThreadDetail> {
        self.modify_thread_labels(
            thread_id,
            &[LABEL_TRASH.to_string()],
            &[LABEL_INBOX.to_string()],
        )
        .await
    }

    async fn untrash_thread(&self, thread_id: &str) -> AppResult<StoredThreadDetail> {
        self.modify_thread_labels(thread_id, &[], &[LABEL_TRASH.to_string()])
            .await
    }

    async fn delete_thread(&self, thread_id: &str) -> AppResult<bool> {
        let mut state = self.write_state()?;
        let msg_ids: Vec<String> = state
            .messages
            .values()
            .filter(|m| m.thread_id == thread_id)
            .map(|m| m.id.clone())
            .collect();
        if msg_ids.is_empty() {
            return Ok(false);
        }
        for mid in msg_ids {
            state.delete_message_inner(&mid);
        }
        Ok(true)
    }

    async fn list_labels(&self) -> AppResult<Vec<StoredLabel>> {
        let state = self.read_state()?;
        let mut labels: Vec<StoredLabel> = state
            .labels
            .values()
            .map(|l| state.build_stored_label(l))
            .collect();
        labels.sort_by(|a, b| {
            let a_sys = if a.label_type == "system" { 0 } else { 1 };
            let b_sys = if b.label_type == "system" { 0 } else { 1 };
            a_sys.cmp(&b_sys).then_with(|| a.name.cmp(&b.name))
        });
        Ok(labels)
    }

    async fn get_label(&self, id: &str) -> AppResult<Option<StoredLabel>> {
        let state = self.read_state()?;
        Ok(state.labels.get(id).map(|l| state.build_stored_label(l)))
    }

    async fn create_label(&self, input: NewLabelInput) -> AppResult<StoredLabel> {
        let name = input.name.trim().to_string();
        if name.is_empty() {
            return Err(AppError::BadRequest("Label name cannot be empty".into()));
        }
        let mut state = self.write_state()?;
        if state
            .labels
            .values()
            .any(|l| l.name.eq_ignore_ascii_case(&name) || l.id == name)
        {
            return Err(AppError::Conflict(format!("Label already exists: {name}")));
        }

        let id = format!("Label_{}", &new_hex_id()[..8]);
        let uv = state.alloc_uid_validity();
        let mem_lbl = MemLabel {
            id: id.clone(),
            name,
            label_type: "user".to_string(),
            message_list_visibility: Some(
                input
                    .message_list_visibility
                    .unwrap_or_else(|| "show".to_string()),
            ),
            label_list_visibility: Some(
                input
                    .label_list_visibility
                    .unwrap_or_else(|| "labelShow".to_string()),
            ),
            color: input.color,
            uid_validity: uv,
            uid_next: 1,
            upstream_label_id: input.upstream_label_id,
        };
        state.labels.insert(id.clone(), mem_lbl);
        let lbl = state
            .labels
            .get(&id)
            .map(|l| state.build_stored_label(l))
            .ok_or_else(|| AppError::Storage("Failed to load created label".into()))?;
        Ok(lbl)
    }

    async fn update_label(
        &self,
        id: &str,
        input: UpdateLabelInput,
        full_replace: bool,
    ) -> AppResult<StoredLabel> {
        let mut state = self.write_state()?;
        let existing = state
            .labels
            .get(id)
            .cloned()
            .ok_or_else(|| AppError::NotFound(format!("Label not found: {id}")))?;
        if existing.label_type == "system" || is_system_label(&existing.id) {
            return Err(AppError::BadRequest(format!(
                "Cannot modify system label: {id}"
            )));
        }

        let new_name = match input.name {
            Some(ref n) => {
                let trimmed = n.trim();
                if trimmed.is_empty() {
                    return Err(AppError::BadRequest("Label name cannot be empty".into()));
                }
                if state.labels.values().any(|l| {
                    l.id != id && (l.name.eq_ignore_ascii_case(trimmed) || l.id == trimmed)
                }) {
                    return Err(AppError::Conflict(format!(
                        "Label name already exists: {trimmed}"
                    )));
                }
                trimmed.to_string()
            }
            None => existing.name.clone(),
        };

        let (msg_vis, lbl_vis, color) = if full_replace {
            (
                input.message_list_visibility,
                input.label_list_visibility,
                input.color,
            )
        } else {
            (
                input
                    .message_list_visibility
                    .or(existing.message_list_visibility),
                input
                    .label_list_visibility
                    .or(existing.label_list_visibility),
                input.color.or(existing.color),
            )
        };

        if let Some(lbl) = state.labels.get_mut(id) {
            lbl.name = new_name;
            lbl.message_list_visibility = msg_vis;
            lbl.label_list_visibility = lbl_vis;
            lbl.color = color;
        }

        let updated = state
            .labels
            .get(id)
            .map(|l| state.build_stored_label(l))
            .ok_or_else(|| AppError::NotFound(format!("Label not found: {id}")))?;
        Ok(updated)
    }

    async fn delete_label(&self, id: &str) -> AppResult<()> {
        let mut state = self.write_state()?;
        let existing = state
            .labels
            .get(id)
            .cloned()
            .ok_or_else(|| AppError::NotFound(format!("Label not found: {id}")))?;
        if existing.label_type == "system" || is_system_label(&existing.id) {
            return Err(AppError::BadRequest(format!(
                "Cannot delete system label: {id}"
            )));
        }

        let affected: Vec<(String, String, Vec<String>, Option<String>)> = state
            .messages
            .values()
            .filter(|m| m.label_ids.iter().any(|l| l == id))
            .map(|m| {
                (
                    m.id.clone(),
                    m.thread_id.clone(),
                    m.label_ids.clone(),
                    m.upstream_gmail_id.clone(),
                )
            })
            .collect();

        for (mid, tid, ctx, up_id) in affected {
            let hid = state.bump_history_id();
            if let Some(msg) = state.messages.get_mut(&mid) {
                msg.label_ids.retain(|l| l != id);
                msg.history_id = hid;
            }
            state
                .message_label_uids
                .remove(&(mid.clone(), id.to_string()));
            state.record_history_event(
                hid,
                HistoryEventKind::LabelRemoved,
                &mid,
                &tid,
                vec![id.to_string()],
                ctx,
                up_id,
            );
        }

        state.labels.remove(id);
        Ok(())
    }

    async fn upsert_upstream_label(&self, input: NewLabelInput) -> AppResult<StoredLabel> {
        let name = input.name.trim().to_string();
        let mut state = self.write_state()?;

        if let Some(ref ulid) = input.upstream_label_id
            && !ulid.trim().is_empty()
        {
            if is_system_label(ulid.trim())
                && let Some(sys) = state.labels.get(ulid.trim())
            {
                return Ok(state.build_stored_label(sys));
            }
            if let Some(existing_id) = state
                .labels
                .values()
                .find(|l| l.upstream_label_id.as_deref() == Some(ulid.trim()))
                .map(|l| l.id.clone())
            {
                if !name.is_empty()
                    && let Some(lbl) = state.labels.get_mut(&existing_id)
                    && lbl.label_type == "user"
                {
                    lbl.name = name;
                }
                let lbl = state
                    .labels
                    .get(&existing_id)
                    .map(|l| state.build_stored_label(l))
                    .ok_or_else(|| AppError::Storage("Missing upstream label".into()))?;
                return Ok(lbl);
            }
        }

        if !name.is_empty()
            && let Some(existing_id) = state.resolve_existing_label_id(&name)
        {
            let is_sys = state
                .labels
                .get(&existing_id)
                .is_some_and(|l| l.label_type == "system");
            if !is_sys
                && input.upstream_label_id.is_some()
                && let Some(lbl) = state.labels.get_mut(&existing_id)
                && lbl.upstream_label_id.is_none()
            {
                lbl.upstream_label_id = input.upstream_label_id;
            }
            let lbl = state
                .labels
                .get(&existing_id)
                .map(|l| state.build_stored_label(l))
                .ok_or_else(|| AppError::Storage("Missing existing label".into()))?;
            return Ok(lbl);
        }

        if name.is_empty() {
            return Err(AppError::BadRequest("Label name cannot be empty".into()));
        }

        let id = format!("Label_{}", &new_hex_id()[..8]);
        let uv = state.alloc_uid_validity();
        state.labels.insert(
            id.clone(),
            MemLabel {
                id: id.clone(),
                name,
                label_type: "user".to_string(),
                message_list_visibility: Some(
                    input
                        .message_list_visibility
                        .unwrap_or_else(|| "show".to_string()),
                ),
                label_list_visibility: Some(
                    input
                        .label_list_visibility
                        .unwrap_or_else(|| "labelShow".to_string()),
                ),
                color: input.color,
                uid_validity: uv,
                uid_next: 1,
                upstream_label_id: input.upstream_label_id,
            },
        );
        let lbl = state
            .labels
            .get(&id)
            .map(|l| state.build_stored_label(l))
            .ok_or_else(|| AppError::Storage("Failed to load created upstream label".into()))?;
        Ok(lbl)
    }

    async fn list_drafts(&self, query: &MessageListQuery) -> AppResult<DraftListPage> {
        let state = self.read_state()?;
        let max_results = if query.max_results == 0 {
            100
        } else {
            query.max_results.min(500)
        };
        let offset = parse_offset_token(query.page_token.as_deref())?;
        let parsed_q = query
            .q
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|raw| parse_query_with_labels(&state, raw));
        let effective_include_spam_trash =
            query.include_spam_trash || parsed_q.as_ref().is_some_and(|pq| pq.include_spam_trash);

        let mut drafts: Vec<StoredDraft> = Vec::new();
        for d in state.drafts.values() {
            let Some(msg) = state.messages.get(&d.message_id) else {
                continue;
            };
            if !effective_include_spam_trash
                && msg
                    .label_ids
                    .iter()
                    .any(|l| l == LABEL_TRASH || l == LABEL_SPAM)
            {
                continue;
            }
            if let Some(ref pq) = parsed_q
                && !crate::search::matches_message(pq, msg)
            {
                continue;
            }
            drafts.push(StoredDraft {
                id: d.id.clone(),
                message: msg.clone(),
                updated_at: d.updated_at,
            });
        }
        drafts.sort_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then_with(|| b.id.cmp(&a.id))
        });

        let total = drafts.len();
        let page: Vec<StoredDraft> = drafts.into_iter().skip(offset).take(max_results).collect();
        let next_page_token = if offset + page.len() < total {
            Some((offset + page.len()).to_string())
        } else {
            None
        };

        Ok(DraftListPage {
            drafts: page,
            next_page_token,
            result_size_estimate: total as u32,
        })
    }

    async fn get_draft(&self, id: &str) -> AppResult<Option<StoredDraft>> {
        let state = self.read_state()?;
        let Some(d) = state.drafts.get(id) else {
            return Ok(None);
        };
        let Some(msg) = state.messages.get(&d.message_id) else {
            return Ok(None);
        };
        Ok(Some(StoredDraft {
            id: d.id.clone(),
            message: msg.clone(),
            updated_at: d.updated_at,
        }))
    }

    async fn create_draft(&self, mut message: NewMessageInput) -> AppResult<StoredDraft> {
        if !message.label_ids.iter().any(|l| l == LABEL_DRAFT) {
            message.label_ids.push(LABEL_DRAFT.to_string());
        }
        let mut state = self.write_state()?;
        let stored_msg = state.insert_message_inner(message)?;
        let draft_id = format!("r{}", new_hex_id());
        let now = Utc::now();
        state.drafts.insert(
            draft_id.clone(),
            MemDraft {
                id: draft_id.clone(),
                message_id: stored_msg.id.clone(),
                updated_at: now,
            },
        );
        Ok(StoredDraft {
            id: draft_id,
            message: stored_msg,
            updated_at: now,
        })
    }

    async fn update_draft(
        &self,
        draft_id: &str,
        mut message: NewMessageInput,
    ) -> AppResult<StoredDraft> {
        if !message.label_ids.iter().any(|l| l == LABEL_DRAFT) {
            message.label_ids.push(LABEL_DRAFT.to_string());
        }
        let mut state = self.write_state()?;
        let old_msg_id = state
            .drafts
            .get(draft_id)
            .map(|d| d.message_id.clone())
            .ok_or_else(|| AppError::NotFound(format!("Draft not found: {draft_id}")))?;

        let new_msg = state.insert_message_inner(message)?;
        let now = Utc::now();
        if let Some(d) = state.drafts.get_mut(draft_id) {
            d.message_id = new_msg.id.clone();
            d.updated_at = now;
        }
        state.delete_message_inner(&old_msg_id);

        Ok(StoredDraft {
            id: draft_id.to_string(),
            message: new_msg,
            updated_at: now,
        })
    }

    async fn delete_draft(&self, draft_id: &str) -> AppResult<bool> {
        let mut state = self.write_state()?;
        let Some(d) = state.drafts.remove(draft_id) else {
            return Ok(false);
        };
        state.delete_message_inner(&d.message_id);
        Ok(true)
    }

    async fn search_messages_ai(&self, query: &AiSearchQuery) -> AppResult<AiMessagePage> {
        let state = self.read_state()?;
        let limit = if query.limit == 0 {
            20
        } else {
            query.limit.min(100)
        };
        let cursor = match query.cursor.as_deref() {
            Some(c) if !c.trim().is_empty() => Some(decode_keyset_cursor(c.trim())?),
            _ => None,
        };

        let resolved_labels: Vec<String> = query
            .labels
            .iter()
            .map(|l| {
                state
                    .resolve_existing_label_id(l)
                    .unwrap_or_else(|| l.clone())
            })
            .collect();
        let explicit_spam_trash = resolved_labels
            .iter()
            .any(|l| l == LABEL_TRASH || l == LABEL_SPAM);
        let effective_include_spam_trash = query.include_spam_trash || explicit_spam_trash;

        let from_filter = query
            .from
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase);
        let to_filter = query
            .to
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase);
        let q_filter = query.q.as_deref().map(str::trim).filter(|s| !s.is_empty());

        let mut matching: Vec<StoredMessage> = state
            .messages
            .values()
            .filter(|m| {
                if !effective_include_spam_trash
                    && m.label_ids
                        .iter()
                        .any(|l| l == LABEL_TRASH || l == LABEL_SPAM)
                {
                    return false;
                }
                if !resolved_labels
                    .iter()
                    .all(|req| m.label_ids.iter().any(|l| l == req))
                {
                    return false;
                }
                if let Some(want_unread) = query.unread {
                    let is_unread = m.label_ids.iter().any(|l| l == LABEL_UNREAD);
                    if is_unread != want_unread {
                        return false;
                    }
                }
                if let Some(ref tid) = query.thread_id
                    && !tid.trim().is_empty()
                    && m.thread_id != tid.trim()
                {
                    return false;
                }
                if let Some(ref f) = from_filter
                    && !m.from_addr.to_ascii_lowercase().contains(f)
                {
                    return false;
                }
                if let Some(ref t) = to_filter
                    && !m
                        .to_addrs
                        .iter()
                        .any(|addr| addr.to_ascii_lowercase().contains(t))
                {
                    return false;
                }
                if let Some(after) = query.after
                    && m.internal_date_ms < after.timestamp_millis()
                {
                    return false;
                }
                if let Some(before) = query.before
                    && m.internal_date_ms > before.timestamp_millis()
                {
                    return false;
                }
                if let Some(has_att) = query.has_attachment
                    && m.has_attachments != has_att
                {
                    return false;
                }
                if let Some(raw_q) = q_filter
                    && !matches_ai_text_query(m, raw_q)
                {
                    return false;
                }
                if let Some((cursor_ts, ref cursor_id)) = cursor
                    && !(m.internal_date_ms < cursor_ts
                        || (m.internal_date_ms == cursor_ts && m.id.as_str() < cursor_id.as_str()))
                {
                    return false;
                }
                true
            })
            .cloned()
            .collect();

        matching.sort_by(|a, b| {
            b.internal_date_ms
                .cmp(&a.internal_date_ms)
                .then_with(|| b.id.cmp(&a.id))
        });

        let has_more = matching.len() > limit;
        if has_more {
            matching.truncate(limit);
        }
        let next_cursor = if has_more {
            matching
                .last()
                .map(|m| encode_keyset_cursor(m.internal_date_ms, &m.id))
        } else {
            None
        };

        Ok(AiMessagePage {
            messages: matching,
            next_cursor,
            has_more,
        })
    }

    async fn list_thread_summaries(&self, query: &AiThreadQuery) -> AppResult<AiThreadPage> {
        let state = self.read_state()?;
        let limit = if query.limit == 0 {
            20
        } else {
            query.limit.min(100)
        };
        let cursor = match query.cursor.as_deref() {
            Some(c) if !c.trim().is_empty() => Some(decode_keyset_cursor(c.trim())?),
            _ => None,
        };

        let resolved_label = match query.label.as_deref() {
            Some(l) if !l.trim().is_empty() => Some(
                state
                    .resolve_existing_label_id(l)
                    .unwrap_or_else(|| l.to_string()),
            ),
            _ => None,
        };
        let explicit_spam_trash = resolved_label
            .as_deref()
            .is_some_and(|l| l == LABEL_TRASH || l == LABEL_SPAM);
        let effective_include_spam_trash = query.include_spam_trash || explicit_spam_trash;
        let q_filter = query.q.as_deref().map(str::trim).filter(|s| !s.is_empty());

        let mut by_thread: BTreeMap<String, Vec<StoredMessage>> = BTreeMap::new();
        for msg in state.messages.values() {
            if !effective_include_spam_trash
                && msg
                    .label_ids
                    .iter()
                    .any(|l| l == LABEL_TRASH || l == LABEL_SPAM)
            {
                continue;
            }
            by_thread
                .entry(msg.thread_id.clone())
                .or_default()
                .push(msg.clone());
        }

        let mut summaries: Vec<(i64, ThreadSummary)> = Vec::new();
        for (tid, mut msgs) in by_thread {
            if let Some(raw_q) = q_filter
                && !msgs.iter().any(|m| matches_ai_text_query(m, raw_q))
            {
                continue;
            }
            msgs.sort_by(|a, b| {
                a.internal_date_ms
                    .cmp(&b.internal_date_ms)
                    .then_with(|| a.id.cmp(&b.id))
            });
            let summary = build_thread_summary(&tid, &msgs);
            if let Some(ref req_label) = resolved_label
                && !summary.labels.contains(req_label)
            {
                continue;
            }
            if query.unread_only && !summary.unread {
                continue;
            }
            let max_ts = msgs.iter().map(|m| m.internal_date_ms).max().unwrap_or(0);
            if let Some((cursor_ts, ref cursor_id)) = cursor
                && !(max_ts < cursor_ts
                    || (max_ts == cursor_ts && tid.as_str() < cursor_id.as_str()))
            {
                continue;
            }
            summaries.push((max_ts, summary));
        }

        summaries.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.id.cmp(&a.1.id)));
        let has_more = summaries.len() > limit;
        if has_more {
            summaries.truncate(limit);
        }
        let next_cursor = if has_more {
            summaries
                .last()
                .map(|(ts, s)| encode_keyset_cursor(*ts, &s.id))
        } else {
            None
        };
        let threads = summaries.into_iter().map(|(_, s)| s).collect();

        Ok(AiThreadPage {
            threads,
            next_cursor,
            has_more,
        })
    }

    async fn triage_thread(&self, thread_id: &str, patch: &TriagePatch) -> AppResult<TriageResult> {
        let detail = self
            .modify_thread_labels(thread_id, &patch.add_labels, &patch.remove_labels)
            .await?;
        let affected_message_ids: Vec<String> =
            detail.messages.iter().map(|m| m.id.clone()).collect();
        let mut label_set = HashSet::new();
        for m in &detail.messages {
            for l in &m.label_ids {
                label_set.insert(l.clone());
            }
        }
        let mut labels: Vec<String> = label_set.into_iter().collect();
        labels.sort();
        Ok(TriageResult {
            thread_id: detail.id,
            affected_message_ids,
            labels,
        })
    }

    async fn find_message_by_resend_id(&self, resend_id: &str) -> AppResult<Option<StoredMessage>> {
        let state = self.read_state()?;
        Ok(state
            .messages
            .values()
            .find(|m| m.resend_id.as_deref() == Some(resend_id))
            .cloned())
    }

    async fn find_message_by_rfc_message_id(
        &self,
        rfc822_message_id: &str,
    ) -> AppResult<Option<StoredMessage>> {
        let Some(norm) = normalize_rfc_message_id(rfc822_message_id) else {
            return Ok(None);
        };
        let state = self.read_state()?;
        Ok(state.find_msg_by_norm_rfc_id(&norm).cloned())
    }

    async fn record_delivery_status(
        &self,
        resend_id: &str,
        status: &str,
    ) -> AppResult<Option<StoredMessage>> {
        let mut state = self.write_state()?;
        let found_id = state
            .messages
            .values()
            .find(|m| m.resend_id.as_deref() == Some(resend_id))
            .map(|m| m.id.clone());
        let Some(mid) = found_id else {
            return Ok(None);
        };
        if let Some(msg) = state.messages.get_mut(&mid) {
            msg.delivery_status = Some(status.to_string());
            return Ok(Some(msg.clone()));
        }
        Ok(None)
    }

    async fn imap_list_mailboxes(&self) -> AppResult<Vec<ImapMailboxInfo>> {
        let state = self.read_state()?;
        let builtins = [
            ResolvedMailbox::Label {
                id: LABEL_INBOX.to_string(),
                name: "INBOX".to_string(),
                special_use: None,
            },
            ResolvedMailbox::AllMail,
            ResolvedMailbox::Label {
                id: LABEL_SENT.to_string(),
                name: SENT_MAILBOX.to_string(),
                special_use: Some("\\Sent"),
            },
            ResolvedMailbox::Label {
                id: LABEL_DRAFT.to_string(),
                name: DRAFTS_MAILBOX.to_string(),
                special_use: Some("\\Drafts"),
            },
            ResolvedMailbox::Label {
                id: LABEL_TRASH.to_string(),
                name: TRASH_MAILBOX.to_string(),
                special_use: Some("\\Trash"),
            },
            ResolvedMailbox::Label {
                id: LABEL_SPAM.to_string(),
                name: SPAM_MAILBOX.to_string(),
                special_use: Some("\\Junk"),
            },
            ResolvedMailbox::Label {
                id: LABEL_STARRED.to_string(),
                name: STARRED_MAILBOX.to_string(),
                special_use: Some("\\Flagged"),
            },
        ];

        let mut mailboxes: Vec<ImapMailboxInfo> = builtins
            .iter()
            .map(|mb| state.imap_mailbox_info_resolved(mb))
            .collect();

        let mut user_labels: Vec<(&String, &String)> = state
            .labels
            .values()
            .filter(|l| l.label_type == "user")
            .map(|l| (&l.id, &l.name))
            .collect();
        user_labels.sort_by(|a, b| a.1.cmp(b.1));

        for (id, name) in user_labels {
            let mb = ResolvedMailbox::Label {
                id: id.clone(),
                name: name.clone(),
                special_use: None,
            };
            mailboxes.push(state.imap_mailbox_info_resolved(&mb));
        }

        Ok(mailboxes)
    }

    async fn imap_mailbox_info(&self, mailbox_name: &str) -> AppResult<Option<ImapMailboxInfo>> {
        let state = self.read_state()?;
        Ok(state
            .resolve_imap_mailbox(mailbox_name)
            .map(|mb| state.imap_mailbox_info_resolved(&mb)))
    }

    async fn imap_list_messages(&self, mailbox_name: &str) -> AppResult<Vec<ImapMessageEntry>> {
        let state = self.read_state()?;
        let resolved = state
            .resolve_imap_mailbox(mailbox_name)
            .ok_or_else(|| AppError::NotFound(format!("Mailbox not found: {mailbox_name}")))?;
        Ok(state.imap_list_messages_resolved(&resolved))
    }

    async fn imap_set_flags(
        &self,
        message_id: &str,
        is_seen: bool,
        is_flagged: bool,
        is_draft: bool,
        is_answered: bool,
        is_deleted: bool,
    ) -> AppResult<StoredMessage> {
        let mut state = self.write_state()?;
        {
            let msg = state
                .messages
                .get_mut(message_id)
                .ok_or_else(|| AppError::NotFound(format!("Message not found: {message_id}")))?;
            msg.is_answered = is_answered;
            msg.is_deleted = is_deleted;
        }
        let mut add = Vec::new();
        let mut rem = Vec::new();
        if is_seen {
            rem.push(LABEL_UNREAD.to_string());
        } else {
            add.push(LABEL_UNREAD.to_string());
        }
        if is_flagged {
            add.push(LABEL_STARRED.to_string());
        } else {
            rem.push(LABEL_STARRED.to_string());
        }
        if is_draft {
            add.push(LABEL_DRAFT.to_string());
        } else {
            rem.push(LABEL_DRAFT.to_string());
        }
        state.modify_message_labels_resolved(message_id, &add, &rem)
    }

    async fn imap_expunge(&self, mailbox_name: &str) -> AppResult<Vec<u32>> {
        let mut state = self.write_state()?;
        let resolved = state
            .resolve_imap_mailbox(mailbox_name)
            .ok_or_else(|| AppError::NotFound(format!("Mailbox not found: {mailbox_name}")))?;
        let entries = state.imap_list_messages_resolved(&resolved);

        let mut expunged_seqs = Vec::new();
        for entry in entries {
            if !entry.is_deleted {
                continue;
            }
            expunged_seqs.push(entry.seq);
            match &resolved {
                ResolvedMailbox::Label { id, .. } if id == LABEL_TRASH => {
                    state.delete_message_inner(&entry.message_id);
                }
                ResolvedMailbox::AllMail => {
                    if let Some(m) = state.messages.get_mut(&entry.message_id) {
                        m.is_deleted = false;
                    }
                    state.modify_message_labels_resolved(
                        &entry.message_id,
                        &[LABEL_TRASH.to_string()],
                        &[LABEL_INBOX.to_string()],
                    )?;
                }
                ResolvedMailbox::Label { id, .. } => {
                    if let Some(m) = state.messages.get_mut(&entry.message_id) {
                        m.is_deleted = false;
                    }
                    state.modify_message_labels_resolved(
                        &entry.message_id,
                        &[LABEL_TRASH.to_string()],
                        std::slice::from_ref(id),
                    )?;
                }
            }
        }
        Ok(expunged_seqs)
    }

    async fn imap_copy_or_move(
        &self,
        src_mailbox: &str,
        dst_mailbox: &str,
        message_ids: &[String],
        is_move: bool,
    ) -> AppResult<Vec<(u32, u32)>> {
        let mut state = self.write_state()?;
        let src = state
            .resolve_imap_mailbox(src_mailbox)
            .ok_or_else(|| AppError::NotFound(format!("Mailbox not found: {src_mailbox}")))?;
        let dst = state
            .resolve_imap_mailbox(dst_mailbox)
            .ok_or_else(|| AppError::NotFound(format!("Mailbox not found: {dst_mailbox}")))?;

        let same_mailbox = match (&src, &dst) {
            (ResolvedMailbox::AllMail, ResolvedMailbox::AllMail) => true,
            (ResolvedMailbox::Label { id: a, .. }, ResolvedMailbox::Label { id: b, .. }) => a == b,
            _ => false,
        };

        let src_uid_map: HashMap<String, u32> = state
            .imap_list_messages_resolved(&src)
            .into_iter()
            .map(|e| (e.message_id, e.uid))
            .collect();

        let mut pairs = Vec::new();
        for mid in message_ids {
            let Some(&src_uid) = src_uid_map.get(mid) else {
                continue;
            };
            let mut add = Vec::new();
            let mut rem = Vec::new();

            match &dst {
                ResolvedMailbox::AllMail => {
                    rem.push(LABEL_TRASH.to_string());
                    rem.push(LABEL_SPAM.to_string());
                }
                ResolvedMailbox::Label { id: dst_id, .. } => {
                    add.push(dst_id.clone());
                }
            }

            if is_move
                && !same_mailbox
                && let ResolvedMailbox::Label { id: src_id, .. } = &src
            {
                rem.push(src_id.clone());
            }

            let updated = state.modify_message_labels_resolved(mid, &add, &rem)?;
            let dst_uid = match &dst {
                ResolvedMailbox::AllMail => updated.all_mail_uid,
                ResolvedMailbox::Label { id: dst_id, .. } => state
                    .message_label_uids
                    .get(&(mid.clone(), dst_id.clone()))
                    .copied()
                    .unwrap_or(1),
            };
            pairs.push((src_uid, dst_uid));
        }

        Ok(pairs)
    }

    async fn imap_append(
        &self,
        mailbox_name: &str,
        mut input: NewMessageInput,
    ) -> AppResult<(u32, u32, StoredMessage)> {
        if input.source.trim().is_empty() {
            input.source = "imap_append".to_string();
        }
        let mut state = self.write_state()?;
        let resolved = state
            .resolve_imap_mailbox(mailbox_name)
            .ok_or_else(|| AppError::NotFound(format!("Mailbox not found: {mailbox_name}")))?;

        match &resolved {
            ResolvedMailbox::AllMail => {
                input
                    .label_ids
                    .retain(|l| l != LABEL_TRASH && l != LABEL_SPAM);
            }
            ResolvedMailbox::Label { id, .. } => {
                if !input.label_ids.iter().any(|l| l == id) {
                    input.label_ids.push(id.clone());
                }
            }
        }

        let msg = state.insert_message_inner(input)?;
        let (uid_validity, assigned_uid) = match &resolved {
            ResolvedMailbox::AllMail => (state.all_mail_uid_validity, msg.all_mail_uid),
            ResolvedMailbox::Label { id, .. } => {
                let uv = state.labels.get(id).map(|l| l.uid_validity).unwrap_or(1);
                let uid = state
                    .message_label_uids
                    .get(&(msg.id.clone(), id.clone()))
                    .copied()
                    .unwrap_or(1);
                (uv, uid)
            }
        };
        Ok((uid_validity, assigned_uid, msg))
    }

    async fn upsert_synced_message(&self, input: NewMessageInput) -> AppResult<UpsertOutcome> {
        let mut state = self.write_state()?;

        // 1. Match by upstream_gmail_id
        if let Some(ref ugid) = input.upstream_gmail_id
            && !ugid.trim().is_empty()
            && let Some(existing_id) = state
                .messages
                .values()
                .find(|m| m.upstream_gmail_id.as_deref() == Some(ugid.trim()))
                .map(|m| m.id.clone())
        {
            let mut desired_labels = Vec::new();
            let mut seen = HashSet::new();
            for raw_l in &input.label_ids {
                let lid = state.ensure_label_exists(raw_l)?;
                if seen.insert(lid.clone()) {
                    desired_labels.push(lid);
                }
            }
            desired_labels.sort();

            let (existing_labels, flags_changed) = {
                let m = state
                    .messages
                    .get(&existing_id)
                    .ok_or_else(|| AppError::Storage("Missing matched upstream message".into()))?;
                (
                    m.label_ids.clone(),
                    m.is_answered != input.is_answered || m.is_deleted != input.is_deleted,
                )
            };

            let to_add: Vec<String> = desired_labels
                .iter()
                .filter(|l| !existing_labels.contains(l))
                .cloned()
                .collect();
            let to_remove: Vec<String> = existing_labels
                .iter()
                .filter(|l| !desired_labels.contains(l))
                .cloned()
                .collect();
            let labels_changed = !to_add.is_empty() || !to_remove.is_empty();

            if flags_changed && let Some(m) = state.messages.get_mut(&existing_id) {
                m.is_answered = input.is_answered;
                m.is_deleted = input.is_deleted;
            }

            let updated =
                if labels_changed {
                    state.modify_message_labels_resolved(&existing_id, &to_add, &to_remove)?
                } else {
                    state.messages.get(&existing_id).cloned().ok_or_else(|| {
                        AppError::Storage("Missing message after sync update".into())
                    })?
                };

            let kind = if labels_changed || flags_changed {
                UpsertOutcomeKind::Updated
            } else {
                UpsertOutcomeKind::Deduplicated
            };
            return Ok(UpsertOutcome {
                kind,
                message: updated,
            });
        }

        // 2. Match by normalized rfc822_message_id
        if let Some(norm) = input
            .rfc822_message_id
            .as_deref()
            .and_then(normalize_rfc_message_id)
            && let Some(existing_id) = state.find_msg_by_norm_rfc_id(&norm).map(|m| m.id.clone())
        {
            if let Some(m) = state.messages.get_mut(&existing_id) {
                if m.upstream_gmail_id.is_none() && input.upstream_gmail_id.is_some() {
                    m.upstream_gmail_id = input.upstream_gmail_id.clone();
                }
                if m.upstream_thread_id.is_none() && input.upstream_thread_id.is_some() {
                    m.upstream_thread_id = input.upstream_thread_id.clone();
                }
            }

            let existing_labels = state
                .messages
                .get(&existing_id)
                .map(|m| m.label_ids.clone())
                .unwrap_or_default();
            let mut to_add = Vec::new();
            for raw_l in &input.label_ids {
                let lid = state.ensure_label_exists(raw_l)?;
                if !existing_labels.contains(&lid) && !to_add.contains(&lid) {
                    to_add.push(lid);
                }
            }
            let updated = if !to_add.is_empty() {
                state.modify_message_labels_resolved(&existing_id, &to_add, &[])?
            } else {
                state
                    .messages
                    .get(&existing_id)
                    .cloned()
                    .ok_or_else(|| AppError::Storage("Missing message after dedup".into()))?
            };
            return Ok(UpsertOutcome {
                kind: UpsertOutcomeKind::Deduplicated,
                message: updated,
            });
        }

        // 3. Insert new message
        let inserted = state.insert_message_inner(input)?;
        Ok(UpsertOutcome {
            kind: UpsertOutcomeKind::Inserted,
            message: inserted,
        })
    }

    async fn find_message_by_upstream_id(
        &self,
        upstream_gmail_id: &str,
    ) -> AppResult<Option<StoredMessage>> {
        let state = self.read_state()?;
        Ok(state
            .messages
            .values()
            .find(|m| m.upstream_gmail_id.as_deref() == Some(upstream_gmail_id))
            .cloned())
    }

    async fn delete_message_by_upstream_id(
        &self,
        upstream_gmail_id: &str,
    ) -> AppResult<Option<StoredMessage>> {
        let mut state = self.write_state()?;
        let found_id = state
            .messages
            .values()
            .find(|m| m.upstream_gmail_id.as_deref() == Some(upstream_gmail_id))
            .map(|m| m.id.clone());
        Ok(found_id.and_then(|id| state.delete_message_inner(&id)))
    }

    async fn get_sync_state(&self, account_key: &str) -> AppResult<Option<SyncState>> {
        let state = self.read_state()?;
        Ok(state.sync_states.get(account_key).cloned())
    }

    async fn save_sync_state(&self, sync_state: SyncState) -> AppResult<()> {
        let mut state = self.write_state()?;
        state
            .sync_states
            .insert(sync_state.account_key.clone(), sync_state);
        Ok(())
    }

    async fn list_sync_states(&self) -> AppResult<Vec<SyncState>> {
        let state = self.read_state()?;
        let mut list: Vec<SyncState> = state.sync_states.values().cloned().collect();
        list.sort_by(|a, b| a.account_key.cmp(&b.account_key));
        Ok(list)
    }

    async fn set_watch(&self, watch: WatchSubscription) -> AppResult<WatchSubscription> {
        let mut state = self.write_state()?;
        state.watch = Some(watch.clone());
        Ok(watch)
    }

    async fn get_watch(&self) -> AppResult<Option<WatchSubscription>> {
        let state = self.read_state()?;
        Ok(state.watch.clone())
    }

    async fn clear_watch(&self) -> AppResult<()> {
        let mut state = self.write_state()?;
        state.watch = None;
        Ok(())
    }

    async fn get_settings(&self) -> AppResult<UserSettings> {
        let state = self.read_state()?;
        Ok(state.settings.clone())
    }

    async fn save_settings(&self, settings: UserSettings) -> AppResult<UserSettings> {
        let mut state = self.write_state()?;
        state.settings = settings.clone();
        Ok(settings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{NewAttachmentInput, SqliteStore};

    fn sample_msg(subject: &str, from: &str, text: &str, ts_ms: i64) -> NewMessageInput {
        NewMessageInput {
            id: None,
            thread_id: None,
            label_ids: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            raw_rfc2822: format!(
                "From: {from}\r\nTo: me@example.com\r\nSubject: {subject}\r\n\r\n{text}"
            )
            .into_bytes(),
            snippet: text.chars().take(120).collect(),
            internal_date_ms: ts_ms,
            subject: subject.to_string(),
            from_addr: from.to_string(),
            to_addrs: vec!["me@example.com".to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: text.to_string(),
            html_body: None,
            rfc822_message_id: None,
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "local".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: vec![],
        }
    }

    /// Runs the exact same full MailStore contract suite against any backend.
    async fn run_contract_suite(store: &dyn MailStore) {
        // 1. Seeded system labels & default settings
        let labels = store.list_labels().await.unwrap();
        assert_eq!(labels.len(), SYSTEM_LABEL_IDS.len());
        let settings = store.get_settings().await.unwrap();
        assert_eq!(settings.send_as[0].send_as_email, "user@example.com");

        // 2. Custom label CRUD & duplicate conflict & system protection
        let custom = store
            .create_label(NewLabelInput {
                name: "Projects/Alpha".to_string(),
                color: Some(LabelColor {
                    text_color: "#ffffff".to_string(),
                    background_color: "#16a766".to_string(),
                }),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(custom.label_type, "user");
        assert!(matches!(
            store
                .create_label(NewLabelInput {
                    name: "projects/alpha".to_string(),
                    ..Default::default()
                })
                .await,
            Err(AppError::Conflict(_))
        ));
        let patched = store
            .update_label(
                &custom.id,
                UpdateLabelInput {
                    name: Some("Projects/Beta".to_string()),
                    ..Default::default()
                },
                false,
            )
            .await
            .unwrap();
        assert_eq!(patched.name, "Projects/Beta");
        assert!(patched.color.is_some()); // PATCH kept color

        let replaced = store
            .update_label(
                &custom.id,
                UpdateLabelInput {
                    name: Some("Projects/Gamma".to_string()),
                    ..Default::default()
                },
                true,
            )
            .await
            .unwrap();
        assert_eq!(replaced.name, "Projects/Gamma");
        assert!(replaced.color.is_none()); // PUT cleared color

        // 3. Messages, attachments, threading via References/In-Reply-To
        let start_hid = store.current_history_id().await.unwrap();
        assert!(matches!(
            store
                .list_history(&HistoryListQuery {
                    start_history_id: 0,
                    ..Default::default()
                })
                .await,
            Err(AppError::NotFound(_))
        ));

        let mut m1 = sample_msg(
            "Launch checklist",
            "Alice <alice@example.com>",
            "Please review the launch checklist attached.",
            1_700_000_010_000,
        );
        m1.rfc822_message_id = Some("<launch-1@example.com>".to_string());
        m1.attachments.push(NewAttachmentInput {
            part_id: "2".to_string(),
            filename: Some("checklist.txt".to_string()),
            content_type: "text/plain".to_string(),
            content_id: None,
            data: b"item1\nitem2".to_vec(),
        });
        let s1 = store.insert_message(m1).await.unwrap();
        assert!(s1.has_attachments);

        let mut m2 = sample_msg(
            "Re: Launch checklist",
            "Bob <bob@example.com>",
            "Looks great, ship it!",
            1_700_000_020_000,
        );
        m2.references_header = Some("<other@ex.com> <LAUNCH-1@EXAMPLE.COM>".to_string());
        m2.label_ids = vec![LABEL_INBOX.to_string(), custom.id.clone()];
        let s2 = store.insert_message(m2).await.unwrap();
        assert_eq!(s1.thread_id, s2.thread_id);

        // Attachment lookup
        let metas = store.list_attachment_meta(&s1.id).await.unwrap();
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].size_bytes, 11);
        let att = store
            .get_attachment(&s1.id, &metas[0].id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(att.data, b"item1\nitem2");

        // 4. List messages pagination & spam/trash exclusion
        let page1 = store
            .list_messages(&MessageListQuery {
                max_results: 1,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page1.messages.len(), 1);
        assert_eq!(page1.messages[0].id, s2.id);
        assert_eq!(page1.result_size_estimate, 2);
        let page2 = store
            .list_messages(&MessageListQuery {
                max_results: 1,
                page_token: page1.next_page_token.clone(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page2.messages.len(), 1);
        assert_eq!(page2.messages[0].id, s1.id);
        assert!(page2.next_page_token.is_none());

        // Trash & untrash
        let trashed = store.trash_message(&s1.id).await.unwrap();
        assert!(trashed.label_ids.contains(&LABEL_TRASH.to_string()));
        assert!(!trashed.label_ids.contains(&LABEL_INBOX.to_string()));
        let without_trash = store
            .list_messages(&MessageListQuery::default())
            .await
            .unwrap();
        assert_eq!(without_trash.messages.len(), 1);
        let trash_only = store
            .list_messages(&MessageListQuery {
                label_ids: vec![LABEL_TRASH.to_string()],
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(trash_only.messages.len(), 1);
        let untrashed = store.untrash_message(&s1.id).await.unwrap();
        assert!(!untrashed.label_ids.contains(&LABEL_TRASH.to_string()));
        store
            .modify_message_labels(&s1.id, &[LABEL_INBOX.to_string()], &[])
            .await
            .unwrap();

        // 4b. Gmail q= search across list_messages & list_threads (including custom label name)
        let q_by_label_name = store
            .list_messages(&MessageListQuery {
                q: Some("label:Projects/Gamma from:bob".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(q_by_label_name.messages.len(), 1);
        assert_eq!(q_by_label_name.messages[0].id, s2.id);

        let q_threads = store
            .list_threads(&MessageListQuery {
                q: Some("has:attachment".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(q_threads.threads.len(), 1);
        assert_eq!(q_threads.threads[0].id, s1.thread_id);

        // 4c. Batch label modify, trash_thread/untrash_thread, lookup helpers, batch_delete
        store
            .batch_modify_labels(
                &[s1.id.clone(), s2.id.clone()],
                &[LABEL_STARRED.to_string()],
                &[],
            )
            .await
            .unwrap();
        assert!(
            store
                .get_message(&s1.id)
                .await
                .unwrap()
                .unwrap()
                .label_ids
                .contains(&LABEL_STARRED.to_string())
        );
        store
            .batch_modify_labels(
                &[s1.id.clone(), s2.id.clone()],
                &[],
                &[LABEL_STARRED.to_string()],
            )
            .await
            .unwrap();

        let th_trashed = store.trash_thread(&s1.thread_id).await.unwrap();
        assert!(
            th_trashed
                .messages
                .iter()
                .all(|m| m.label_ids.contains(&LABEL_TRASH.to_string()))
        );
        let q_in_trash = store
            .list_messages(&MessageListQuery {
                q: Some("in:trash".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(q_in_trash.messages.len(), 2);
        let th_untrashed = store.untrash_thread(&s1.thread_id).await.unwrap();
        assert!(
            th_untrashed
                .messages
                .iter()
                .all(|m| !m.label_ids.contains(&LABEL_TRASH.to_string()))
        );
        store
            .modify_thread_labels(&s1.thread_id, &[LABEL_INBOX.to_string()], &[])
            .await
            .unwrap();

        let by_rfc = store
            .find_message_by_rfc_message_id("LAUNCH-1@EXAMPLE.COM")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_rfc.id, s1.id);

        let mut temp_msg = sample_msg("Temp", "x@ex.com", "temp body", 1_700_000_005_000);
        temp_msg.resend_id = Some("re_temp_1".to_string());
        temp_msg.upstream_gmail_id = Some("gm_temp_1".to_string());
        let temp_stored = store.insert_message(temp_msg).await.unwrap();
        assert_eq!(
            store
                .find_message_by_resend_id("re_temp_1")
                .await
                .unwrap()
                .unwrap()
                .id,
            temp_stored.id
        );
        let del_up = store
            .delete_message_by_upstream_id("gm_temp_1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(del_up.id, temp_stored.id);
        assert!(store.get_message(&temp_stored.id).await.unwrap().is_none());

        let b1 = store
            .insert_message(sample_msg("B1", "x@ex.com", "b1", 1_700_000_006_000))
            .await
            .unwrap();
        let b2 = store
            .insert_message(sample_msg("B2", "x@ex.com", "b2", 1_700_000_007_000))
            .await
            .unwrap();
        store
            .batch_delete_messages(&[b1.id.clone(), b2.id.clone()])
            .await
            .unwrap();
        assert!(store.get_message(&b1.id).await.unwrap().is_none());
        assert!(store.get_message(&b2.id).await.unwrap().is_none());

        // 5. AI search + cursor + thread summaries + triage
        let ai_page = store
            .search_messages_ai(&AiSearchQuery {
                q: Some("checklist".to_string()),
                has_attachment: Some(true),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(ai_page.messages.len(), 1);
        assert_eq!(ai_page.messages[0].id, s1.id);

        let thread_pages = store
            .list_thread_summaries(&AiThreadQuery {
                unread_only: true,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(thread_pages.threads.len(), 1);
        assert_eq!(thread_pages.threads[0].message_count, 2);
        assert_eq!(thread_pages.threads[0].participants.len(), 2);

        let triaged = store
            .triage_thread(
                &s1.thread_id,
                &TriagePatch {
                    add_labels: vec![LABEL_STARRED.to_string()],
                    remove_labels: vec![LABEL_UNREAD.to_string()],
                },
            )
            .await
            .unwrap();
        assert_eq!(triaged.affected_message_ids.len(), 2);
        assert!(triaged.labels.contains(&LABEL_STARRED.to_string()));
        assert!(!triaged.labels.contains(&LABEL_UNREAD.to_string()));

        // 6. IMAP mailboxes, append, flags, copy/move, expunge
        let mbs = store.imap_list_mailboxes().await.unwrap();
        assert!(mbs.iter().any(|m| m.name == "INBOX"));
        assert!(mbs.iter().any(|m| m.name == ALL_MAIL_MAILBOX));
        assert!(mbs.iter().any(|m| m.name == "Projects/Gamma"));

        let (_uv, app_uid, appended) = store
            .imap_append(
                "INBOX",
                sample_msg("Appended", "c@ex.com", "via imap", 1_700_000_030_000),
            )
            .await
            .unwrap();
        assert!(app_uid >= 1);
        let moved = store
            .imap_copy_or_move(
                "INBOX",
                "Projects/Gamma",
                std::slice::from_ref(&appended.id),
                true,
            )
            .await
            .unwrap();
        assert_eq!(moved.len(), 1);
        assert_eq!(moved[0].0, app_uid);

        store
            .imap_set_flags(&appended.id, true, false, false, true, true)
            .await
            .unwrap();
        let expunged = store.imap_expunge("Projects/Gamma").await.unwrap();
        assert_eq!(expunged.len(), 1);

        // 7. Upstream sync upsert deduplication + upstream label upsert
        let ulbl = store
            .upsert_upstream_label(NewLabelInput {
                name: "SyncedTag".to_string(),
                upstream_label_id: Some("Label_Upstream_1".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        let ulbl_again = store
            .upsert_upstream_label(NewLabelInput {
                name: "SyncedTag".to_string(),
                upstream_label_id: Some("Label_Upstream_1".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(ulbl.id, ulbl_again.id);

        let mut synced = sample_msg(
            "Launch checklist",
            "Alice <alice@example.com>",
            "body",
            1_700_000_010_000,
        );
        synced.rfc822_message_id = Some("launch-1@example.com".to_string());
        synced.upstream_gmail_id = Some("gm_100".to_string());
        synced.upstream_thread_id = Some("gm_th_100".to_string());
        synced.label_ids = vec![LABEL_INBOX.to_string(), ulbl.id.clone()];
        let up1 = store.upsert_synced_message(synced.clone()).await.unwrap();
        assert_eq!(up1.kind, UpsertOutcomeKind::Deduplicated);
        assert_eq!(up1.message.id, s1.id);

        let found_up = store
            .find_message_by_upstream_id("gm_100")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found_up.id, s1.id);

        // 8. History pagination & filtering
        let hist = store
            .list_history(&HistoryListQuery {
                start_history_id: start_hid,
                max_results: 2,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(hist.entries.len(), 2);
        assert!(hist.next_page_token.is_some());
        let hist2 = store
            .list_history(&HistoryListQuery {
                start_history_id: start_hid,
                max_results: 50,
                page_token: hist.next_page_token,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(!hist2.entries.is_empty());

        // 9. Drafts, settings, watch, sync state, delete label, delete thread
        let draft = store
            .create_draft(sample_msg(
                "Draft subj",
                "user@example.com",
                "draft text",
                1_700_000_040_000,
            ))
            .await
            .unwrap();
        let drafts = store
            .list_drafts(&MessageListQuery::default())
            .await
            .unwrap();
        assert_eq!(drafts.drafts.len(), 1);
        assert_eq!(drafts.drafts[0].id, draft.id);
        let updated_draft = store
            .update_draft(
                &draft.id,
                sample_msg(
                    "Draft subj v2",
                    "user@example.com",
                    "draft v2",
                    1_700_000_050_000,
                ),
            )
            .await
            .unwrap();
        assert_eq!(updated_draft.message.subject, "Draft subj v2");
        assert!(store.delete_draft(&draft.id).await.unwrap());

        let mut new_settings = settings;
        new_settings.vacation.enable_auto_reply = Some(true);
        store.save_settings(new_settings).await.unwrap();
        assert_eq!(
            store
                .get_settings()
                .await
                .unwrap()
                .vacation
                .enable_auto_reply,
            Some(true)
        );

        store.delete_label(&custom.id).await.unwrap();
        assert!(store.get_label(&custom.id).await.unwrap().is_none());

        assert!(store.delete_thread(&s1.thread_id).await.unwrap());
        assert!(store.get_thread(&s1.thread_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn memory_store_full_contract() {
        let store = MemoryStore::new("user@example.com");
        run_contract_suite(&store).await;
    }

    #[tokio::test]
    async fn sqlite_store_full_contract() {
        let store = SqliteStore::open_in_memory("user@example.com").unwrap();
        run_contract_suite(&store).await;
    }

    #[tokio::test]
    async fn memory_store_clone_shares_state() {
        let s1 = MemoryStore::new("shared@example.com");
        let s2 = s1.clone();
        let inserted = s1
            .insert_message(sample_msg("Shared", "a@b.com", "hello", 1000))
            .await
            .unwrap();
        let fetched = s2.get_message(&inserted.id).await.unwrap().unwrap();
        assert_eq!(fetched.subject, "Shared");
    }
}
