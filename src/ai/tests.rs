//! Unit tests for `src/ai/` (safety guardrails, shared operations, REST `/v1`, SSE `/v1/events`)
//! plus shared in-memory test fakes (`TestMailStore`, `MockResendClient`) reused by `src/mcp/` tests.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::{
    AppState,
    ai::{
        self, ai_router, check_recipients_policy, evaluate_send_dry_run, execute_create_draft,
        execute_modify_labels, execute_send_draft, execute_send_email, execute_triage_thread,
        parse_sync_trigger, runtime_schema, safety, to_compact_message, validate_email_header,
        validate_resource_id,
    },
    config::{Config, DraftOnlyAction, SyncMode},
    error::{AppError, AppResult},
    events::{EventSource, MailEvent},
    models::{
        AiCreateDraftRequest, AiModifyLabelsRequest, AiSendDraftRequest, AiSendEmailRequest,
        AiTriageRequest, AttachmentMeta, LABEL_DRAFT, LABEL_INBOX, LABEL_SENT, LABEL_STARRED,
        LABEL_TRASH, LABEL_UNREAD, Profile, ResendReceivedAttachment, ResendReceivedEmail,
        ResendSendEmailRequest, ResendSendEmailResponse, SYSTEM_LABEL_IDS, SyncTriggerRequest,
        ThreadSummary,
    },
    resend::ResendClient,
    storage::{
        AiMessagePage, AiSearchQuery, AiThreadPage, AiThreadQuery, DraftListPage, HistoryListPage,
        HistoryListQuery, ImapMailboxInfo, ImapMessageEntry, MailStore, MessageListPage,
        MessageListQuery, NewAttachmentInput, NewLabelInput, NewMessageInput, StoredAttachment,
        StoredDraft, StoredLabel, StoredMessage, StoredThreadDetail, SyncState, ThreadListPage,
        TriagePatch, TriageResult, UpdateLabelInput, UpsertOutcome, UpsertOutcomeKind,
        UserSettings, WatchSubscription, parse_simple_email_address,
    },
};

// ============================================================================
// Self-contained Test Fakes (`TestMailStore` & `MockResendClient`)
// ============================================================================

#[derive(Default)]
struct StoreData {
    messages: HashMap<String, StoredMessage>,
    attachments: HashMap<(String, String), StoredAttachment>,
    drafts: HashMap<String, StoredDraft>,
    labels: HashMap<String, StoredLabel>,
    sync_states: HashMap<String, SyncState>,
    settings: Option<UserSettings>,
}

#[derive(Clone)]
pub(crate) struct TestMailStore {
    data: Arc<RwLock<StoreData>>,
    seq: Arc<AtomicU64>,
    user_email: String,
}

impl TestMailStore {
    pub(crate) fn new(user_email: &str) -> Self {
        let mut labels = HashMap::new();
        for &id in SYSTEM_LABEL_IDS {
            labels.insert(
                id.to_string(),
                StoredLabel {
                    id: id.to_string(),
                    name: id.to_string(),
                    label_type: "system".to_string(),
                    message_list_visibility: Some("show".to_string()),
                    label_list_visibility: Some("labelShow".to_string()),
                    color: None,
                    messages_total: 0,
                    messages_unread: 0,
                    threads_total: 0,
                    threads_unread: 0,
                    uid_validity: 1,
                    uid_next: 1,
                    upstream_label_id: None,
                },
            );
        }
        Self {
            data: Arc::new(RwLock::new(StoreData {
                labels,
                settings: Some(UserSettings::default_for_email(user_email)),
                ..Default::default()
            })),
            seq: Arc::new(AtomicU64::new(1)),
            user_email: crate::config::normalize_mailbox_id(user_email),
        }
    }

    fn next_id(&self, prefix: &str) -> String {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}_{n:04}")
    }
}

#[async_trait]
impl MailStore for TestMailStore {
    fn mailbox_id(&self) -> &str {
        &self.user_email
    }

    fn for_mailbox(&self, _mailbox_id: &str) -> Arc<dyn MailStore> {
        Arc::new(self.clone())
    }

    async fn get_profile(&self, email_address: &str) -> AppResult<Profile> {
        let data = self.data.read().unwrap();
        let threads: HashSet<&str> = data
            .messages
            .values()
            .map(|m| m.thread_id.as_str())
            .collect();
        Ok(Profile {
            email_address: email_address.to_string(),
            messages_total: data.messages.len() as i32,
            threads_total: threads.len() as i32,
            history_id: self.seq.load(Ordering::Relaxed).to_string(),
        })
    }

    async fn current_history_id(&self) -> AppResult<u64> {
        Ok(self.seq.load(Ordering::Relaxed))
    }

    async fn list_history(&self, _query: &HistoryListQuery) -> AppResult<HistoryListPage> {
        Ok(HistoryListPage {
            entries: Vec::new(),
            next_page_token: None,
            current_history_id: self.seq.load(Ordering::Relaxed),
        })
    }

    async fn insert_message(&self, input: NewMessageInput) -> AppResult<StoredMessage> {
        let id = input.id.unwrap_or_else(|| self.next_id("msg"));
        let thread_id = input.thread_id.unwrap_or_else(|| self.next_id("thr"));
        let history_id = self.seq.fetch_add(1, Ordering::Relaxed);
        let has_attachments = !input.attachments.is_empty();

        let msg = StoredMessage {
            id: id.clone(),
            thread_id,
            label_ids: input.label_ids,
            size_estimate: input.raw_rfc2822.len() as i32,
            raw_rfc2822: input.raw_rfc2822,
            snippet: input.snippet,
            history_id,
            internal_date_ms: input.internal_date_ms,
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
            source: input.source,
            all_mail_uid: history_id as u32,
            is_answered: input.is_answered,
            is_deleted: input.is_deleted,
        };

        let mut data = self.data.write().unwrap();
        for att in input.attachments {
            let att_id = self.next_id("att");
            let stored_att = StoredAttachment {
                id: att_id.clone(),
                message_id: id.clone(),
                part_id: att.part_id,
                filename: att.filename,
                content_type: att.content_type,
                content_id: att.content_id,
                size_bytes: att.data.len() as u64,
                data: att.data,
            };
            data.attachments.insert((id.clone(), att_id), stored_att);
        }
        data.messages.insert(id, msg.clone());
        Ok(msg)
    }

    async fn get_message(&self, id: &str) -> AppResult<Option<StoredMessage>> {
        Ok(self.data.read().unwrap().messages.get(id).cloned())
    }

    async fn list_messages(&self, _query: &MessageListQuery) -> AppResult<MessageListPage> {
        let msgs: Vec<StoredMessage> = self
            .data
            .read()
            .unwrap()
            .messages
            .values()
            .cloned()
            .collect();
        let est = msgs.len() as u32;
        Ok(MessageListPage {
            messages: msgs,
            next_page_token: None,
            result_size_estimate: est,
        })
    }

    async fn modify_message_labels(
        &self,
        id: &str,
        add_labels: &[String],
        remove_labels: &[String],
    ) -> AppResult<StoredMessage> {
        let mut data = self.data.write().unwrap();
        let msg = data
            .messages
            .get_mut(id)
            .ok_or_else(|| AppError::NotFound(format!("Message {id} not found")))?;
        for l in add_labels {
            if !msg.label_ids.contains(l) {
                msg.label_ids.push(l.clone());
            }
        }
        msg.label_ids.retain(|l| !remove_labels.contains(l));
        Ok(msg.clone())
    }

    async fn batch_modify_labels(
        &self,
        ids: &[String],
        add_labels: &[String],
        remove_labels: &[String],
    ) -> AppResult<()> {
        let mut data = self.data.write().unwrap();
        for id in ids {
            if let Some(msg) = data.messages.get_mut(id) {
                for l in add_labels {
                    if !msg.label_ids.contains(l) {
                        msg.label_ids.push(l.clone());
                    }
                }
                msg.label_ids.retain(|l| !remove_labels.contains(l));
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
        Ok(self.data.write().unwrap().messages.remove(id).is_some())
    }

    async fn batch_delete_messages(&self, ids: &[String]) -> AppResult<()> {
        let mut data = self.data.write().unwrap();
        for id in ids {
            data.messages.remove(id);
        }
        Ok(())
    }

    async fn get_attachment(
        &self,
        message_id: &str,
        attachment_id: &str,
    ) -> AppResult<Option<StoredAttachment>> {
        Ok(self
            .data
            .read()
            .unwrap()
            .attachments
            .get(&(message_id.to_string(), attachment_id.to_string()))
            .cloned())
    }

    async fn list_attachment_meta(&self, message_id: &str) -> AppResult<Vec<AttachmentMeta>> {
        let data = self.data.read().unwrap();
        Ok(data
            .attachments
            .values()
            .filter(|a| a.message_id == message_id)
            .map(|a| AttachmentMeta {
                id: a.id.clone(),
                filename: a.filename.clone(),
                content_type: a.content_type.clone(),
                size_bytes: a.size_bytes,
            })
            .collect())
    }

    async fn list_threads(&self, _query: &MessageListQuery) -> AppResult<ThreadListPage> {
        Ok(ThreadListPage {
            threads: Vec::new(),
            next_page_token: None,
            result_size_estimate: 0,
        })
    }

    async fn get_thread(&self, thread_id: &str) -> AppResult<Option<StoredThreadDetail>> {
        let data = self.data.read().unwrap();
        let mut msgs: Vec<StoredMessage> = data
            .messages
            .values()
            .filter(|m| m.thread_id == thread_id)
            .cloned()
            .collect();
        if msgs.is_empty() {
            return Ok(None);
        }
        msgs.sort_by_key(|m| m.internal_date_ms);
        let snippet = msgs.last().map(|m| m.snippet.clone()).unwrap_or_default();
        let history_id = msgs.iter().map(|m| m.history_id).max().unwrap_or(0);
        Ok(Some(StoredThreadDetail {
            id: thread_id.to_string(),
            snippet,
            history_id,
            messages: msgs,
        }))
    }

    async fn modify_thread_labels(
        &self,
        thread_id: &str,
        add_labels: &[String],
        remove_labels: &[String],
    ) -> AppResult<StoredThreadDetail> {
        let _ = self
            .triage_thread(
                thread_id,
                &TriagePatch {
                    add_labels: add_labels.to_vec(),
                    remove_labels: remove_labels.to_vec(),
                },
            )
            .await?;
        self.get_thread(thread_id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Thread {thread_id} not found")))
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
        let mut data = self.data.write().unwrap();
        let before = data.messages.len();
        data.messages.retain(|_, m| m.thread_id != thread_id);
        Ok(data.messages.len() < before)
    }

    async fn list_labels(&self) -> AppResult<Vec<StoredLabel>> {
        let data = self.data.read().unwrap();
        let mut labels: Vec<StoredLabel> = data.labels.values().cloned().collect();
        for lbl in &mut labels {
            let matching: Vec<&StoredMessage> = data
                .messages
                .values()
                .filter(|m| m.label_ids.iter().any(|l| l == &lbl.id))
                .collect();
            lbl.messages_total = matching.len() as i32;
            lbl.messages_unread = matching
                .iter()
                .filter(|m| m.label_ids.iter().any(|l| l == LABEL_UNREAD))
                .count() as i32;
            let threads: HashSet<&str> = matching.iter().map(|m| m.thread_id.as_str()).collect();
            lbl.threads_total = threads.len() as i32;
            let unread_threads: HashSet<&str> = matching
                .iter()
                .filter(|m| m.label_ids.iter().any(|l| l == LABEL_UNREAD))
                .map(|m| m.thread_id.as_str())
                .collect();
            lbl.threads_unread = unread_threads.len() as i32;
        }
        labels.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(labels)
    }

    async fn get_label(&self, id: &str) -> AppResult<Option<StoredLabel>> {
        Ok(self.data.read().unwrap().labels.get(id).cloned())
    }

    async fn create_label(&self, input: NewLabelInput) -> AppResult<StoredLabel> {
        let id = self.next_id("Label");
        let lbl = StoredLabel {
            id: id.clone(),
            name: input.name,
            label_type: "user".to_string(),
            message_list_visibility: input.message_list_visibility,
            label_list_visibility: input.label_list_visibility,
            color: input.color,
            messages_total: 0,
            messages_unread: 0,
            threads_total: 0,
            threads_unread: 0,
            uid_validity: 1,
            uid_next: 1,
            upstream_label_id: input.upstream_label_id,
        };
        self.data.write().unwrap().labels.insert(id, lbl.clone());
        Ok(lbl)
    }

    async fn update_label(
        &self,
        id: &str,
        _input: UpdateLabelInput,
        _full_replace: bool,
    ) -> AppResult<StoredLabel> {
        self.get_label(id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Label {id} not found")))
    }

    async fn delete_label(&self, id: &str) -> AppResult<()> {
        self.data.write().unwrap().labels.remove(id);
        Ok(())
    }

    async fn upsert_upstream_label(&self, input: NewLabelInput) -> AppResult<StoredLabel> {
        self.create_label(input).await
    }

    async fn list_drafts(&self, query: &MessageListQuery) -> AppResult<DraftListPage> {
        let mut drafts: Vec<StoredDraft> =
            self.data.read().unwrap().drafts.values().cloned().collect();
        drafts.sort_by_key(|d| std::cmp::Reverse(d.updated_at));
        let total = drafts.len() as u32;
        let limit = if query.max_results == 0 {
            20
        } else {
            query.max_results
        };
        drafts.truncate(limit);
        Ok(DraftListPage {
            drafts,
            next_page_token: None,
            result_size_estimate: total,
        })
    }

    async fn get_draft(&self, id: &str) -> AppResult<Option<StoredDraft>> {
        Ok(self.data.read().unwrap().drafts.get(id).cloned())
    }

    async fn create_draft(&self, mut message: NewMessageInput) -> AppResult<StoredDraft> {
        if !message.label_ids.iter().any(|l| l == LABEL_DRAFT) {
            message.label_ids.push(LABEL_DRAFT.to_string());
        }
        let stored_msg = self.insert_message(message).await?;
        let draft_id = self.next_id("drf");
        let draft = StoredDraft {
            id: draft_id.clone(),
            message: stored_msg,
            updated_at: Utc::now(),
        };
        self.data
            .write()
            .unwrap()
            .drafts
            .insert(draft_id, draft.clone());
        Ok(draft)
    }

    async fn update_draft(
        &self,
        draft_id: &str,
        message: NewMessageInput,
    ) -> AppResult<StoredDraft> {
        let stored_msg = self.insert_message(message).await?;
        let draft = StoredDraft {
            id: draft_id.to_string(),
            message: stored_msg,
            updated_at: Utc::now(),
        };
        self.data
            .write()
            .unwrap()
            .drafts
            .insert(draft_id.to_string(), draft.clone());
        Ok(draft)
    }

    async fn delete_draft(&self, draft_id: &str) -> AppResult<bool> {
        let mut data = self.data.write().unwrap();
        if let Some(d) = data.drafts.remove(draft_id) {
            data.messages.remove(&d.message.id);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn search_messages_ai(&self, query: &AiSearchQuery) -> AppResult<AiMessagePage> {
        let data = self.data.read().unwrap();
        let mut msgs: Vec<StoredMessage> = data
            .messages
            .values()
            .filter(|m| {
                if !query.include_spam_trash
                    && (m.label_ids.iter().any(|l| l == LABEL_TRASH || l == "SPAM"))
                {
                    return false;
                }
                if let Some(tid) = &query.thread_id
                    && &m.thread_id != tid
                {
                    return false;
                }
                for req_lbl in &query.labels {
                    if !m.label_ids.iter().any(|l| l == req_lbl) {
                        return false;
                    }
                }
                if let Some(want_unread) = query.unread {
                    let is_unread = m.label_ids.iter().any(|l| l == LABEL_UNREAD);
                    if is_unread != want_unread {
                        return false;
                    }
                }
                if let Some(from) = &query.from
                    && !m
                        .from_addr
                        .to_ascii_lowercase()
                        .contains(&from.to_ascii_lowercase())
                {
                    return false;
                }
                if let Some(to) = &query.to
                    && !m
                        .to_addrs
                        .iter()
                        .any(|a| a.to_ascii_lowercase().contains(&to.to_ascii_lowercase()))
                {
                    return false;
                }
                if let Some(has_att) = query.has_attachment
                    && m.has_attachments != has_att
                {
                    return false;
                }
                if let Some(q) = &query.q
                    && !q.trim().is_empty()
                {
                    let needle = q.to_ascii_lowercase();
                    let hay = format!(
                        "{} {} {} {}",
                        m.subject, m.from_addr, m.text_body, m.snippet
                    )
                    .to_ascii_lowercase();
                    if !hay.contains(&needle) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        msgs.sort_by_key(|m| std::cmp::Reverse(m.internal_date_ms));
        let limit = if query.limit == 0 { 20 } else { query.limit };
        let has_more = msgs.len() > limit;
        msgs.truncate(limit);
        Ok(AiMessagePage {
            messages: msgs,
            next_cursor: None,
            has_more,
        })
    }

    async fn list_thread_summaries(&self, query: &AiThreadQuery) -> AppResult<AiThreadPage> {
        let data = self.data.read().unwrap();
        let mut by_thread: HashMap<String, Vec<&StoredMessage>> = HashMap::new();
        for msg in data.messages.values() {
            if !query.include_spam_trash
                && msg
                    .label_ids
                    .iter()
                    .any(|l| l == LABEL_TRASH || l == "SPAM")
            {
                continue;
            }
            by_thread
                .entry(msg.thread_id.clone())
                .or_default()
                .push(msg);
        }

        let mut threads: Vec<ThreadSummary> = Vec::new();
        for (tid, mut msgs) in by_thread {
            msgs.sort_by_key(|m| m.internal_date_ms);
            let mut labels: Vec<String> = Vec::new();
            for m in &msgs {
                for l in &m.label_ids {
                    if !labels.contains(l) {
                        labels.push(l.clone());
                    }
                }
            }
            let unread = labels.iter().any(|l| l == LABEL_UNREAD);
            if query.unread_only && !unread {
                continue;
            }
            if let Some(lbl) = &query.label
                && !labels.iter().any(|l| l == lbl)
            {
                continue;
            }
            if let Some(q) = &query.q
                && !q.trim().is_empty()
            {
                let needle = q.to_ascii_lowercase();
                let matched = msgs.iter().any(|m| {
                    format!("{} {} {}", m.subject, m.from_addr, m.text_body)
                        .to_ascii_lowercase()
                        .contains(&needle)
                });
                if !matched {
                    continue;
                }
            }

            let subject = msgs.first().map(|m| m.subject.clone()).unwrap_or_default();
            let snippet = msgs.last().map(|m| m.snippet.clone()).unwrap_or_default();
            let last_ms = msgs.iter().map(|m| m.internal_date_ms).max().unwrap_or(0);
            let participants = msgs
                .iter()
                .map(|m| parse_simple_email_address(&m.from_addr))
                .collect();

            threads.push(ThreadSummary {
                id: tid,
                subject,
                participants,
                snippet,
                labels,
                unread,
                has_attachments: msgs.iter().any(|m| m.has_attachments),
                message_count: msgs.len(),
                last_message_at: DateTime::from_timestamp_millis(last_ms).unwrap_or_else(Utc::now),
            });
        }

        threads.sort_by_key(|t| std::cmp::Reverse(t.last_message_at));
        let limit = if query.limit == 0 { 20 } else { query.limit };
        let has_more = threads.len() > limit;
        threads.truncate(limit);
        Ok(AiThreadPage {
            threads,
            next_cursor: None,
            has_more,
        })
    }

    async fn triage_thread(&self, thread_id: &str, patch: &TriagePatch) -> AppResult<TriageResult> {
        let mut data = self.data.write().unwrap();
        let mut affected = Vec::new();
        let mut combined_labels = Vec::new();
        for msg in data.messages.values_mut() {
            if msg.thread_id == thread_id {
                for l in &patch.add_labels {
                    if !msg.label_ids.contains(l) {
                        msg.label_ids.push(l.clone());
                    }
                }
                msg.label_ids.retain(|l| !patch.remove_labels.contains(l));
                affected.push(msg.id.clone());
                for l in &msg.label_ids {
                    if !combined_labels.contains(l) {
                        combined_labels.push(l.clone());
                    }
                }
            }
        }
        if affected.is_empty() {
            return Err(AppError::NotFound(format!(
                "Thread '{thread_id}' not found"
            )));
        }
        affected.sort();
        Ok(TriageResult {
            thread_id: thread_id.to_string(),
            affected_message_ids: affected,
            labels: combined_labels,
        })
    }

    async fn find_message_by_resend_id(
        &self,
        _resend_id: &str,
    ) -> AppResult<Option<StoredMessage>> {
        Ok(None)
    }

    async fn find_message_by_rfc_message_id(
        &self,
        _rfc822_message_id: &str,
    ) -> AppResult<Option<StoredMessage>> {
        Ok(None)
    }

    async fn record_delivery_status(
        &self,
        _resend_id: &str,
        _status: &str,
    ) -> AppResult<Option<StoredMessage>> {
        Ok(None)
    }

    async fn imap_list_mailboxes(&self) -> AppResult<Vec<ImapMailboxInfo>> {
        Ok(Vec::new())
    }

    async fn imap_mailbox_info(&self, _mailbox_name: &str) -> AppResult<Option<ImapMailboxInfo>> {
        Ok(None)
    }

    async fn imap_list_messages(&self, _mailbox_name: &str) -> AppResult<Vec<ImapMessageEntry>> {
        Ok(Vec::new())
    }

    async fn imap_set_flags(
        &self,
        id: &str,
        _is_seen: bool,
        _is_flagged: bool,
        _is_draft: bool,
        _is_answered: bool,
        _is_deleted: bool,
    ) -> AppResult<StoredMessage> {
        self.get_message(id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Message {id} not found")))
    }

    async fn imap_expunge(&self, _mailbox_name: &str) -> AppResult<Vec<u32>> {
        Ok(Vec::new())
    }

    async fn imap_copy_or_move(
        &self,
        _src_mailbox: &str,
        _dst_mailbox: &str,
        _message_ids: &[String],
        _is_move: bool,
    ) -> AppResult<Vec<(u32, u32)>> {
        Ok(Vec::new())
    }

    async fn imap_append(
        &self,
        _mailbox_name: &str,
        input: NewMessageInput,
    ) -> AppResult<(u32, u32, StoredMessage)> {
        let msg = self.insert_message(input).await?;
        Ok((1, 1, msg))
    }

    async fn upsert_synced_message(&self, input: NewMessageInput) -> AppResult<UpsertOutcome> {
        let msg = self.insert_message(input).await?;
        Ok(UpsertOutcome {
            kind: UpsertOutcomeKind::Inserted,
            message: msg,
        })
    }

    async fn find_message_by_upstream_id(
        &self,
        _upstream_gmail_id: &str,
    ) -> AppResult<Option<StoredMessage>> {
        Ok(None)
    }

    async fn delete_message_by_upstream_id(
        &self,
        _upstream_gmail_id: &str,
    ) -> AppResult<Option<StoredMessage>> {
        Ok(None)
    }

    async fn get_sync_state(&self, account_key: &str) -> AppResult<Option<SyncState>> {
        Ok(self
            .data
            .read()
            .unwrap()
            .sync_states
            .get(account_key)
            .cloned())
    }

    async fn save_sync_state(&self, state: SyncState) -> AppResult<()> {
        self.data
            .write()
            .unwrap()
            .sync_states
            .insert(state.account_key.clone(), state);
        Ok(())
    }

    async fn list_sync_states(&self) -> AppResult<Vec<SyncState>> {
        Ok(self
            .data
            .read()
            .unwrap()
            .sync_states
            .values()
            .cloned()
            .collect())
    }

    async fn set_watch(&self, watch: WatchSubscription) -> AppResult<WatchSubscription> {
        Ok(watch)
    }

    async fn get_watch(&self) -> AppResult<Option<WatchSubscription>> {
        Ok(None)
    }

    async fn clear_watch(&self) -> AppResult<()> {
        Ok(())
    }

    async fn get_settings(&self) -> AppResult<UserSettings> {
        Ok(self
            .data
            .read()
            .unwrap()
            .settings
            .clone()
            .unwrap_or_else(|| UserSettings::default_for_email(&self.user_email)))
    }

    async fn save_settings(&self, settings: UserSettings) -> AppResult<UserSettings> {
        self.data.write().unwrap().settings = Some(settings.clone());
        Ok(settings)
    }

    async fn create_pending_approval(
        &self,
        _input: crate::storage::NewPendingApprovalInput,
    ) -> AppResult<crate::storage::PendingApproval> {
        unimplemented!()
    }

    async fn get_pending_approval(
        &self,
        _id: &str,
    ) -> AppResult<Option<crate::storage::PendingApproval>> {
        Ok(None)
    }

    async fn list_pending_approvals(
        &self,
        _status: Option<crate::storage::ApprovalStatus>,
        _limit: usize,
    ) -> AppResult<Vec<crate::storage::PendingApproval>> {
        Ok(Vec::new())
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
        unimplemented!()
    }
}

#[derive(Default)]
pub(crate) struct MockResendClient {
    pub(crate) sent: RwLock<Vec<ResendSendEmailRequest>>,
    counter: AtomicU64,
}

impl MockResendClient {
    pub(crate) fn sent_count(&self) -> usize {
        self.sent.read().unwrap().len()
    }

    pub(crate) fn last_sent(&self) -> Option<ResendSendEmailRequest> {
        self.sent.read().unwrap().last().cloned()
    }
}

#[async_trait]
impl ResendClient for MockResendClient {
    async fn send_email(
        &self,
        req: &ResendSendEmailRequest,
        _idempotency_key: Option<&str>,
    ) -> AppResult<ResendSendEmailResponse> {
        self.sent.write().unwrap().push(req.clone());
        let n = self.counter.fetch_add(1, Ordering::Relaxed) + 1;
        Ok(ResendSendEmailResponse {
            id: format!("re_mock_{n:04}"),
        })
    }

    async fn get_received_email(&self, _email_id: &str) -> AppResult<ResendReceivedEmail> {
        Err(AppError::NotFound("mock not implemented".to_string()))
    }

    async fn list_received_attachments(
        &self,
        _email_id: &str,
    ) -> AppResult<Vec<ResendReceivedAttachment>> {
        Ok(Vec::new())
    }

    async fn download_bytes(&self, _url: &str) -> AppResult<Vec<u8>> {
        Ok(Vec::new())
    }
}

pub(crate) fn make_test_state(
    config: Config,
) -> (AppState, Arc<TestMailStore>, Arc<MockResendClient>) {
    let store = Arc::new(TestMailStore::new(&config.user_email));
    let resend = Arc::new(MockResendClient::default());
    let state = AppState::with_backends(config, store.clone(), resend.clone());
    (state, store, resend)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn seed_sample_message(
    store: &TestMailStore,
    id: &str,
    thread_id: &str,
    from: &str,
    subject: &str,
    text: &str,
    labels: Vec<&str>,
    attachments: Vec<NewAttachmentInput>,
) -> StoredMessage {
    store
        .insert_message(NewMessageInput {
            id: Some(id.to_string()),
            thread_id: Some(thread_id.to_string()),
            label_ids: labels.into_iter().map(str::to_string).collect(),
            raw_rfc2822: format!("From: {from}\r\nSubject: {subject}\r\n\r\n{text}").into_bytes(),
            snippet: text.chars().take(120).collect(),
            internal_date_ms: 1_730_000_000_000,
            subject: subject.to_string(),
            from_addr: from.to_string(),
            to_addrs: vec!["agent@example.com".to_string()],
            cc_addrs: Vec::new(),
            bcc_addrs: Vec::new(),
            text_body: text.to_string(),
            html_body: Some(format!("<p>{text}</p>")),
            rfc822_message_id: Some(format!("<{id}@remote.example.com>")),
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "resend_inbound".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments,
        })
        .await
        .expect("seed message")
}

// ============================================================================
// Safety Guardrail Unit Tests
// ============================================================================

#[test]
fn resource_id_and_header_validation_blocks_injection() {
    assert!(validate_resource_id("msg_0001").is_ok());
    assert!(validate_resource_id("INBOX").is_ok());
    assert!(validate_resource_id("Label-123").is_ok());

    for bad in [
        "",
        "   ",
        " msg_1",
        "../secret",
        "a/b",
        "a\\b",
        "msg?foo=1",
        "msg#frag",
        "msg%2e%2e",
        "msg%2Fpath",
        "msg\x00null",
        "msg\x1fctrl",
        "msg\x7fdel",
    ] {
        assert!(
            validate_resource_id(bad).is_err(),
            "expected '{bad:?}' to fail validation"
        );
    }

    assert!(validate_email_header("subject", "Hello world").is_ok());
    assert!(validate_email_header("subject", "Injected\r\nBcc: evil@attacker.com").is_err());
    assert!(validate_email_header("to", "user@example.com\nX-Bad: 1").is_err());
    assert!(validate_email_header("to", "user@example.com\0").is_err());
}

#[test]
fn allowed_recipients_supports_exact_domain_and_wildcard() {
    let mut cfg = Config::for_test();
    cfg.allowed_recipients = vec![
        "boss@partner.org".to_string(),
        "@company.com".to_string(),
        "*.trusted.io".to_string(),
    ];
    cfg.max_send_recipients = 4;

    // Exact match (case-insensitive with display name), @domain, and *.subdomain
    assert!(
        check_recipients_policy(
            &cfg,
            &[
                "Boss <BOSS@partner.org>".to_string(),
                "alice@company.com".to_string(),
            ],
            &["eng@mail.trusted.io".to_string()],
            &["ops@a.b.trusted.io".to_string()],
        )
        .is_ok()
    );

    // Subdomain does not match bare @company.com
    let err =
        check_recipients_policy(&cfg, &["x@sub.company.com".to_string()], &[], &[]).unwrap_err();
    match err {
        AppError::RecipientNotAllowed { disallowed } => {
            assert_eq!(disallowed, vec!["x@sub.company.com"]);
        }
        other => panic!("expected RecipientNotAllowed, got {other:?}"),
    }

    // Bare domain does not match *.trusted.io; suffix-spoofed domain does not match
    let err = check_recipients_policy(
        &cfg,
        &["x@trusted.io".to_string()],
        &["y@eviltrusted.io".to_string()],
        &["z@other.partner.org".to_string()],
    )
    .unwrap_err();
    match err {
        AppError::RecipientNotAllowed { disallowed } => {
            assert_eq!(disallowed.len(), 3);
        }
        other => panic!("expected RecipientNotAllowed, got {other:?}"),
    }

    // max_send_recipients limit enforced across to + cc + bcc
    let err = check_recipients_policy(
        &cfg,
        &["a@company.com".to_string(), "b@company.com".to_string()],
        &["c@company.com".to_string(), "d@company.com".to_string()],
        &["e@company.com".to_string()],
    )
    .unwrap_err();
    assert_eq!(err.ai_code(), "validation_error");
}

#[test]
fn untrusted_content_guard_sanitizes_and_tags_meta() {
    let dirty = "Hello\x00\x07 \u{202E}dlrow\u{2066}\u{E0041}\nLine 2\tTab";
    let clean = safety::sanitize_untrusted_text(dirty);
    assert_eq!(clean, "Hello dlrow\nLine 2\tTab");

    let cfg_guard = Config::for_test(); // untrusted_content_guard = true
    let msg = StoredMessage {
        id: "m1".to_string(),
        thread_id: "t1".to_string(),
        label_ids: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
        raw_rfc2822: Vec::new(),
        snippet: "Hi\u{202E}".to_string(),
        history_id: 1,
        internal_date_ms: 1_730_000_000_000,
        size_estimate: 100,
        subject: "Alert\x1b[31m".to_string(),
        from_addr: "Mallory\u{202E} <m@evil.test>".to_string(),
        to_addrs: vec!["agent@example.com".to_string()],
        cc_addrs: Vec::new(),
        bcc_addrs: Vec::new(),
        text_body: "Top reply\n\nOn Mon, Jan 1, Alice wrote:\n> old quoted line\n".to_string(),
        html_body: Some("<p>HTML\x00</p>".to_string()),
        has_attachments: false,
        rfc822_message_id: Some("<m1@evil.test>".to_string()),
        in_reply_to: None,
        references_header: None,
        resend_id: None,
        delivery_status: None,
        upstream_gmail_id: None,
        upstream_thread_id: None,
        source: "resend_inbound".to_string(),
        all_mail_uid: 1,
        is_answered: false,
        is_deleted: false,
    };

    let compact = to_compact_message(&msg, &cfg_guard, true, 5, true, true);
    assert_eq!(compact.subject, "Alert[31m");
    assert_eq!(compact.from.name.as_deref(), Some("Mallory"));
    assert_eq!(compact.text.as_deref(), Some("Top r"));
    assert!(compact.text_truncated);
    assert_eq!(compact.text_total_chars, "Top reply".len());
    assert!(compact.unread);
    assert!(
        compact
            .meta
            .as_ref()
            .is_some_and(|m| m.untrusted_external_content)
    );

    let mut cfg_off = Config::for_test();
    cfg_off.untrusted_content_guard = false;
    let compact_off = to_compact_message(&msg, &cfg_off, false, 100, false, false);
    assert!(compact_off.text.is_none());
    assert!(compact_off.html.is_none());
    assert!(compact_off.meta.is_none());
}

// ============================================================================
// Shared Operations: Send, DraftOnly, DryRun, Reply Threading, Triage
// ============================================================================

#[tokio::test]
async fn send_email_respects_draft_only_block_downgrade_and_dry_run() {
    // 1. draft_only = true, action = Block
    let mut cfg = Config::for_test();
    cfg.draft_only = true;
    cfg.draft_only_action = DraftOnlyAction::Block;
    let (state, store, resend) = make_test_state(cfg);

    // dry_run reports would_succeed=false with zero side effects
    let dry = evaluate_send_dry_run(
        &state,
        &AiSendEmailRequest {
            to: vec!["bob@example.com".to_string()],
            subject: Some("Test".to_string()),
            text: Some("Hello".to_string()),
            dry_run: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(dry.dry_run);
    assert!(!dry.would_succeed);
    assert!(
        dry.policy_checks
            .iter()
            .any(|c| c.rule == "draft_only" && !c.passed)
    );
    assert_eq!(resend.sent_count(), 0);
    assert_eq!(
        store
            .list_drafts(&MessageListQuery::default())
            .await
            .unwrap()
            .drafts
            .len(),
        0
    );

    // real send returns DraftOnlyBlocked
    let err = execute_send_email(
        &state,
        AiSendEmailRequest {
            to: vec!["bob@example.com".to_string()],
            subject: Some("Test".to_string()),
            text: Some("Hello".to_string()),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.ai_code(), "draft_only_mode");
    assert_eq!(resend.sent_count(), 0);

    // 2. draft_only = true, action = Downgrade
    let mut cfg2 = Config::for_test();
    cfg2.draft_only = true;
    cfg2.draft_only_action = DraftOnlyAction::Downgrade;
    let (state2, store2, resend2) = make_test_state(cfg2);

    let res = execute_send_email(
        &state2,
        AiSendEmailRequest {
            to: vec!["bob@example.com".to_string()],
            subject: Some("Downgraded".to_string()),
            text: Some("Saved as draft".to_string()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(res["status"], "draft_created");
    assert_eq!(res["downgraded_from_send"], true);
    assert_eq!(resend2.sent_count(), 0);
    assert_eq!(
        store2
            .list_drafts(&MessageListQuery::default())
            .await
            .unwrap()
            .drafts
            .len(),
        1
    );
}

#[tokio::test]
async fn send_email_auto_threads_reply_headers_and_subject() {
    let (state, store, resend) = make_test_state(Config::for_test());
    let parent = seed_sample_message(
        &store,
        "msg_parent",
        "thr_42",
        "Alice <alice@example.com>",
        "Quarterly Budget",
        "Can you review?",
        vec![LABEL_INBOX, LABEL_UNREAD],
        Vec::new(),
    )
    .await;

    // Reply omitting `to` and `subject` should inherit from parent
    let res = execute_send_email(
        &state,
        AiSendEmailRequest {
            reply_to_message_id: Some(parent.id.clone()),
            text: Some("Looks great!".to_string()),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(res["status"], "sent");
    assert_eq!(res["thread_id"], "thr_42");
    assert_eq!(res["subject"], "Re: Quarterly Budget");
    assert_eq!(res["in_reply_to"], "<msg_parent@remote.example.com>");
    assert_eq!(res["references"], "<msg_parent@remote.example.com>");
    assert_eq!(res["to"][0], "Alice <alice@example.com>");

    let sent_req = resend.last_sent().expect("resend called");
    let headers = sent_req.headers.expect("headers set");
    assert_eq!(
        headers.get("In-Reply-To").map(String::as_str),
        Some("<msg_parent@remote.example.com>")
    );
    assert_eq!(
        headers.get("References").map(String::as_str),
        Some("<msg_parent@remote.example.com>")
    );
}

#[tokio::test]
async fn draft_create_send_and_triage_lifecycle() {
    let (state, store, resend) = make_test_state(Config::for_test());
    let _msg = seed_sample_message(
        &store,
        "msg_1",
        "thr_1",
        "alice@example.com",
        "Hello",
        "Body",
        vec![LABEL_INBOX, LABEL_UNREAD],
        Vec::new(),
    )
    .await;

    // Create draft
    let created = execute_create_draft(
        &state,
        AiCreateDraftRequest {
            to: vec!["alice@example.com".to_string()],
            subject: Some("Drafted reply".to_string()),
            text: Some("Draft body".to_string()),
            reply_to_message_id: Some("msg_1".to_string()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let draft_id = created["draft_id"].as_str().unwrap().to_string();
    assert_eq!(created["thread_id"], "thr_1");

    // Dry-run send_draft has zero side effects
    let dry = execute_send_draft(&state, &draft_id, AiSendDraftRequest { dry_run: true })
        .await
        .unwrap();
    assert_eq!(dry["dry_run"], true);
    assert_eq!(dry["would_succeed"], true);
    assert_eq!(resend.sent_count(), 0);
    assert!(store.get_draft(&draft_id).await.unwrap().is_some());

    // Live send_draft deletes draft and delivers via Resend
    let sent = execute_send_draft(&state, &draft_id, AiSendDraftRequest { dry_run: false })
        .await
        .unwrap();
    assert_eq!(sent["status"], "sent");
    assert_eq!(resend.sent_count(), 1);
    assert!(store.get_draft(&draft_id).await.unwrap().is_none());

    // Triage thread dry-run -> zero mutation
    let dry_triage = execute_triage_thread(
        &state,
        "thr_1",
        AiTriageRequest {
            archive: Some(true),
            mark_read: Some(true),
            star: Some(true),
            dry_run: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(dry_triage["dry_run"], true);
    assert!(
        store
            .get_message("msg_1")
            .await
            .unwrap()
            .unwrap()
            .label_ids
            .contains(&LABEL_INBOX.to_string())
    );

    // Live triage applies labels
    let triaged = execute_triage_thread(
        &state,
        "thr_1",
        AiTriageRequest {
            archive: Some(true),
            mark_read: Some(true),
            star: Some(true),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(triaged["thread_id"], "thr_1");
    let updated = store.get_message("msg_1").await.unwrap().unwrap();
    assert!(!updated.label_ids.contains(&LABEL_INBOX.to_string()));
    assert!(!updated.label_ids.contains(&LABEL_UNREAD.to_string()));
    assert!(updated.label_ids.contains(&LABEL_STARRED.to_string()));

    // modify_labels across message_ids
    let modified = execute_modify_labels(
        &state,
        AiModifyLabelsRequest {
            message_ids: vec!["msg_1".to_string()],
            add_labels: vec!["IMPORTANT".to_string()],
            remove_labels: vec![LABEL_STARRED.to_string()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(modified["modified_count"], 1);
    let updated2 = store.get_message("msg_1").await.unwrap().unwrap();
    assert!(updated2.label_ids.contains(&"IMPORTANT".to_string()));
    assert!(!updated2.label_ids.contains(&LABEL_STARRED.to_string()));
}

#[test]
fn runtime_schema_and_sync_trigger_helpers() {
    let all = runtime_schema(None);
    assert_eq!(all["service"], "nogml");
    assert!(all["commands"]["mail.send"].is_object());

    let single = runtime_schema(Some("send"));
    assert_eq!(single["command"], "mail.send");

    let opts = parse_sync_trigger(SyncTriggerRequest {
        mode: Some("full".to_string()),
        provider: Some("imap".to_string()),
        max_messages: Some(50),
        query: None,
        bidirectional: Some(true),
    })
    .unwrap();
    assert!(opts.full);
    assert_eq!(opts.mode, Some(SyncMode::Imap));
    assert_eq!(opts.max_messages, Some(50));
    assert_eq!(opts.bidirectional, Some(true));

    assert!(
        parse_sync_trigger(SyncTriggerRequest {
            mode: Some("bogus".to_string()),
            ..Default::default()
        })
        .is_err()
    );
}

// ============================================================================
// Axum `/v1/*` REST Router & SSE Tests
// ============================================================================

#[tokio::test]
async fn rest_v1_endpoints_fields_mask_attachments_and_errors() {
    let mut cfg = Config::for_test();
    cfg.allowed_recipients = vec!["@example.com".to_string()];
    let (state, store, _resend) = make_test_state(cfg);

    let seeded = seed_sample_message(
        &store,
        "msg_rest_1",
        "thr_rest_1",
        "Alice <alice@example.com>",
        "Project Phoenix",
        "Please find report attached.",
        vec![LABEL_INBOX, LABEL_UNREAD],
        vec![NewAttachmentInput {
            part_id: "1".to_string(),
            filename: Some("report.txt".to_string()),
            content_type: "text/plain".to_string(),
            content_id: None,
            data: b"report-bytes".to_vec(),
        }],
    )
    .await;
    let att_meta = store.list_attachment_meta(&seeded.id).await.unwrap();
    let att_id = att_meta[0].id.clone();

    let app = ai_router().with_state(state.clone());

    // GET /v1/capabilities with ?fields= projection
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/capabilities?fields=service,safety.allowed_recipients_enabled")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["service"], "nogml");
    assert_eq!(body["safety"]["allowed_recipients_enabled"], true);
    assert!(body.get("endpoints").is_none());

    // GET /v1/threads/{id}?fields=id,messages(id,subject)
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/threads/thr_rest_1?fields=id,messages(id,subject)")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["id"], "thr_rest_1");
    assert_eq!(body["messages"][0]["subject"], "Project Phoenix");
    assert!(body["messages"][0].get("text").is_none());

    // GET /v1/messages/{id}/attachments/{attachment_id} streams raw bytes
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/messages/msg_rest_1/attachments/{att_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/plain"
    );
    let raw = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&raw[..], b"report-bytes");

    // GET /v1/search?q=Phoenix
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/search?q=Phoenix&has_attachment=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["messages"].as_array().unwrap().len(), 1);

    // POST /v1/messages/send blocked by allowed_recipients -> 403 AI error envelope
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/messages/send")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "to": ["intruder@outside.org"],
                        "subject": "Exfil",
                        "text": "nope"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["error"]["code"], "recipient_not_allowed");
    assert_eq!(
        body["error"]["details"]["disallowed"][0],
        "intruder@outside.org"
    );

    // GET /v1/labels
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/labels")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(body["labels"].as_array().unwrap().len() >= SYSTEM_LABEL_IDS.len());
}

#[tokio::test]
async fn sse_events_replays_last_event_id_filters_and_streams_live() {
    let (state, _store, _resend) = make_test_state(Config::for_test());

    // Publish 3 events prior to connecting
    let e1 = state.events.publish(
        EventSource::ResendInbound,
        MailEvent::MessageReceived {
            message_id: "m1".to_string(),
            thread_id: "t1".to_string(),
            from: "a@example.com".to_string(),
            subject: "First".to_string(),
            snippet: "One".to_string(),
            labels: vec![LABEL_INBOX.to_string()],
        },
    );
    let _e2 = state.events.publish(
        EventSource::Api,
        MailEvent::MessageSent {
            message_id: "m2".to_string(),
            thread_id: "t2".to_string(),
            to: vec!["b@example.com".to_string()],
            subject: "Second".to_string(),
            resend_id: Some("re_2".to_string()),
            labels: vec![LABEL_SENT.to_string()],
        },
    );
    let e3 = state.events.publish(
        EventSource::ResendInbound,
        MailEvent::MessageReceived {
            message_id: "m3".to_string(),
            thread_id: "t1".to_string(),
            from: "c@example.com".to_string(),
            subject: "Third".to_string(),
            snippet: "Three".to_string(),
            labels: vec![LABEL_INBOX.to_string()],
        },
    );

    let app = ai::router().with_state(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/events?types=message_received&thread_id=t1&label=INBOX")
                .header("last-event-id", e1.id.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/event-stream"),
        "unexpected content-type: {ct}"
    );

    // Publish a live event matching the filter after stream creation
    let state_clone = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        state_clone.events.publish(
            EventSource::ResendInbound,
            MailEvent::MessageReceived {
                message_id: "m4".to_string(),
                thread_id: "t1".to_string(),
                from: "d@example.com".to_string(),
                subject: "Fourth".to_string(),
                snippet: "Four".to_string(),
                labels: vec![LABEL_INBOX.to_string()],
            },
        );
    });

    let mut stream = resp.into_body().into_data_stream();
    let mut collected = String::new();
    for _ in 0..4 {
        let chunk = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
            .await
            .expect("SSE chunk timeout")
            .expect("stream ended")
            .expect("body error");
        collected.push_str(&String::from_utf8_lossy(&chunk));
        if collected.contains("\"m4\"") {
            break;
        }
    }

    // e1 skipped (id == Last-Event-ID), e2 filtered out (message_sent / t2), e3 replayed, m4 live!
    assert!(!collected.contains("\"m1\""));
    assert!(!collected.contains("\"m2\""));
    assert!(collected.contains(&format!("id: {}", e3.id)));
    assert!(collected.contains("\"m3\""));
    assert!(collected.contains("\"m4\""));
}
