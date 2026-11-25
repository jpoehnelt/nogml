use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use base64::Engine as _;
use futures_util::TryStreamExt;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::watch,
};

use crate::{
    AppState,
    config::Config,
    error::{AppError, AppResult},
    events::{EventSource, MailEvent},
    imap::{
        mime_fmt::{
            extract_body_section, format_bodystructure, format_envelope, parse_body_section,
        },
        parser::{
            ImapArg, ReadCommandOutcome, format_internal_date, imap_wildcard_match,
            parse_command_line, parse_imap_date_time, parse_imap_search_date, parse_sequence_set,
            read_command, seq_set_contains,
        },
        serve_plain_listener,
    },
    models::{
        AttachmentMeta, LABEL_DRAFT, LABEL_INBOX, LABEL_SENT, LABEL_SPAM, LABEL_STARRED,
        LABEL_TRASH, LABEL_UNREAD, Profile, ResendReceivedAttachment, ResendReceivedEmail,
        ResendSendEmailRequest, ResendSendEmailResponse, SYSTEM_LABEL_IDS,
    },
    resend::ResendClient,
    storage::{
        AiMessagePage, AiSearchQuery, AiThreadPage, AiThreadQuery, DraftListPage, HistoryListPage,
        HistoryListQuery, ImapMailboxInfo, ImapMessageEntry, MailStore, MessageListPage,
        MessageListQuery, NewLabelInput, NewMessageInput, StoredAttachment, StoredDraft,
        StoredLabel, StoredMessage, StoredThreadDetail, SyncState, ThreadListPage, TriagePatch,
        TriageResult, UpdateLabelInput, UpsertOutcome, UpsertOutcomeKind, UserSettings,
        WatchSubscription,
    },
};

// ============================================================================
// Self-contained test harness (`TestMailStore` + `DummyResendClient`)
// ============================================================================

pub(crate) struct DummyResendClient;

#[async_trait]
impl ResendClient for DummyResendClient {
    async fn send_email(
        &self,
        _req: &ResendSendEmailRequest,
        _idempotency_key: Option<&str>,
    ) -> AppResult<ResendSendEmailResponse> {
        Ok(ResendSendEmailResponse {
            id: "re_test".to_string(),
        })
    }

    async fn get_received_email(&self, _email_id: &str) -> AppResult<ResendReceivedEmail> {
        Err(AppError::NotFound("not used".to_string()))
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

#[derive(Default)]
struct StoreInner {
    next_id: u64,
    all_mail_uid_next: u32,
    messages: HashMap<String, StoredMessage>,
    labels: HashMap<String, StoredLabel>,
    /// `(label_id, message_id) -> per-mailbox UID`
    label_uids: HashMap<(String, String), u32>,
    sync_states: HashMap<String, SyncState>,
}

/// Pure in-memory `MailStore` for `imap` & `sync` unit tests.
pub(crate) struct TestMailStore {
    inner: Mutex<StoreInner>,
}

impl TestMailStore {
    pub(crate) fn new() -> Self {
        let mut labels = HashMap::new();
        for (i, &id) in SYSTEM_LABEL_IDS.iter().enumerate() {
            labels.insert(
                id.to_string(),
                StoredLabel {
                    id: id.to_string(),
                    name: id.to_string(),
                    label_type: "system".to_string(),
                    message_list_visibility: None,
                    label_list_visibility: None,
                    color: None,
                    messages_total: 0,
                    messages_unread: 0,
                    threads_total: 0,
                    threads_unread: 0,
                    uid_validity: 100 + i as u32,
                    uid_next: 1,
                    upstream_label_id: None,
                },
            );
        }
        Self {
            inner: Mutex::new(StoreInner {
                next_id: 1,
                all_mail_uid_next: 1,
                messages: HashMap::new(),
                labels,
                label_uids: HashMap::new(),
                sync_states: HashMap::new(),
            }),
        }
    }

    fn mailbox_to_label(inner: &StoreInner, name: &str) -> Option<(String, Option<String>)> {
        if name.eq_ignore_ascii_case("INBOX") {
            return Some(("INBOX".to_string(), Some(LABEL_INBOX.to_string())));
        }
        match name {
            "[Gmail]/All Mail" => Some(("[Gmail]/All Mail".to_string(), None)),
            "[Gmail]/Sent Mail" => Some((
                "[Gmail]/Sent Mail".to_string(),
                Some(LABEL_SENT.to_string()),
            )),
            "[Gmail]/Drafts" => Some(("[Gmail]/Drafts".to_string(), Some(LABEL_DRAFT.to_string()))),
            "[Gmail]/Trash" => Some(("[Gmail]/Trash".to_string(), Some(LABEL_TRASH.to_string()))),
            "[Gmail]/Spam" => Some(("[Gmail]/Spam".to_string(), Some(LABEL_SPAM.to_string()))),
            "[Gmail]/Starred" => Some((
                "[Gmail]/Starred".to_string(),
                Some(LABEL_STARRED.to_string()),
            )),
            other => inner
                .labels
                .values()
                .find(|l| l.label_type == "user" && l.name == other)
                .map(|l| (l.name.clone(), Some(l.id.clone()))),
        }
    }

    fn alloc_label_uid(inner: &mut StoreInner, label_id: &str, msg_id: &str) -> u32 {
        if let Some(&existing) = inner
            .label_uids
            .get(&(label_id.to_string(), msg_id.to_string()))
        {
            return existing;
        }
        let uid = if let Some(lbl) = inner.labels.get_mut(label_id) {
            let u = lbl.uid_next;
            lbl.uid_next += 1;
            u
        } else {
            1
        };
        inner
            .label_uids
            .insert((label_id.to_string(), msg_id.to_string()), uid);
        uid
    }

    fn insert_locked(inner: &mut StoreInner, input: NewMessageInput) -> StoredMessage {
        let id = input.id.unwrap_or_else(|| {
            let n = inner.next_id;
            inner.next_id += 1;
            format!("{n:016x}")
        });
        let thread_id = input.thread_id.unwrap_or_else(|| {
            input
                .upstream_thread_id
                .clone()
                .unwrap_or_else(|| format!("th_{id}"))
        });
        let all_mail_uid = inner.all_mail_uid_next;
        inner.all_mail_uid_next += 1;

        for lbl in &input.label_ids {
            Self::alloc_label_uid(inner, lbl, &id);
        }

        let stored = StoredMessage {
            id: id.clone(),
            thread_id,
            label_ids: input.label_ids,
            size_estimate: input.raw_rfc2822.len() as i32,
            raw_rfc2822: input.raw_rfc2822,
            snippet: input.snippet,
            history_id: all_mail_uid as u64,
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
            all_mail_uid,
            is_answered: input.is_answered,
            is_deleted: input.is_deleted,
        };
        inner.messages.insert(id, stored.clone());
        stored
    }

    fn list_mailbox_entries_locked(
        inner: &StoreInner,
        mailbox_name: &str,
    ) -> AppResult<Vec<ImapMessageEntry>> {
        let Some((_, label_opt)) = Self::mailbox_to_label(inner, mailbox_name) else {
            return Err(AppError::NotFound(format!(
                "Mailbox not found: {mailbox_name}"
            )));
        };

        let mut items: Vec<(u32, &StoredMessage)> = Vec::new();
        for msg in inner.messages.values() {
            match &label_opt {
                None => {
                    if !msg
                        .label_ids
                        .iter()
                        .any(|l| l == LABEL_TRASH || l == LABEL_SPAM)
                    {
                        items.push((msg.all_mail_uid, msg));
                    }
                }
                Some(lid) => {
                    if msg.label_ids.iter().any(|l| l == lid) {
                        let uid = inner
                            .label_uids
                            .get(&(lid.clone(), msg.id.clone()))
                            .copied()
                            .unwrap_or(msg.all_mail_uid);
                        items.push((uid, msg));
                    }
                }
            }
        }
        items.sort_by_key(|(uid, _)| *uid);
        Ok(items
            .into_iter()
            .enumerate()
            .map(|(idx, (uid, msg))| ImapMessageEntry {
                seq: (idx + 1) as u32,
                uid,
                message_id: msg.id.clone(),
                thread_id: msg.thread_id.clone(),
                history_id: msg.history_id.max(1),
                internal_date_ms: msg.internal_date_ms,
                size_estimate: msg.size_estimate,
                label_ids: msg.label_ids.clone(),
                is_answered: msg.is_answered,
                is_deleted: msg.is_deleted,
            })
            .collect())
    }
}

#[async_trait]
impl MailStore for TestMailStore {
    async fn get_profile(&self, email_address: &str) -> AppResult<Profile> {
        let inner = self.inner.lock().unwrap();
        let threads: HashSet<&str> = inner
            .messages
            .values()
            .map(|m| m.thread_id.as_str())
            .collect();
        Ok(Profile {
            email_address: email_address.to_string(),
            messages_total: inner.messages.len() as i32,
            threads_total: threads.len() as i32,
            history_id: inner.all_mail_uid_next.to_string(),
        })
    }
    async fn current_history_id(&self) -> AppResult<u64> {
        Ok(self.inner.lock().unwrap().all_mail_uid_next as u64)
    }
    async fn list_history(&self, _: &HistoryListQuery) -> AppResult<HistoryListPage> {
        unimplemented!()
    }
    async fn insert_message(&self, input: NewMessageInput) -> AppResult<StoredMessage> {
        let mut inner = self.inner.lock().unwrap();
        Ok(Self::insert_locked(&mut inner, input))
    }
    async fn get_message(&self, id: &str) -> AppResult<Option<StoredMessage>> {
        Ok(self.inner.lock().unwrap().messages.get(id).cloned())
    }
    async fn list_messages(&self, _: &MessageListQuery) -> AppResult<MessageListPage> {
        let inner = self.inner.lock().unwrap();
        let msgs: Vec<_> = inner.messages.values().cloned().collect();
        let len = msgs.len() as u32;
        Ok(MessageListPage {
            messages: msgs,
            next_page_token: None,
            result_size_estimate: len,
        })
    }
    async fn modify_message_labels(
        &self,
        id: &str,
        add_labels: &[String],
        remove_labels: &[String],
    ) -> AppResult<StoredMessage> {
        let mut inner = self.inner.lock().unwrap();
        let mut msg = inner
            .messages
            .get(id)
            .cloned()
            .ok_or_else(|| AppError::NotFound(id.to_string()))?;
        for r in remove_labels {
            msg.label_ids.retain(|l| l != r);
        }
        for a in add_labels {
            if !msg.label_ids.contains(a) {
                msg.label_ids.push(a.clone());
                Self::alloc_label_uid(&mut inner, a, id);
            }
        }
        inner.messages.insert(id.to_string(), msg.clone());
        Ok(msg)
    }
    async fn batch_modify_labels(&self, _: &[String], _: &[String], _: &[String]) -> AppResult<()> {
        unimplemented!()
    }
    async fn trash_message(&self, _: &str) -> AppResult<StoredMessage> {
        unimplemented!()
    }
    async fn untrash_message(&self, _: &str) -> AppResult<StoredMessage> {
        unimplemented!()
    }
    async fn delete_message(&self, id: &str) -> AppResult<bool> {
        Ok(self.inner.lock().unwrap().messages.remove(id).is_some())
    }
    async fn batch_delete_messages(&self, _: &[String]) -> AppResult<()> {
        unimplemented!()
    }
    async fn get_attachment(&self, _: &str, _: &str) -> AppResult<Option<StoredAttachment>> {
        Ok(None)
    }
    async fn list_attachment_meta(&self, _: &str) -> AppResult<Vec<AttachmentMeta>> {
        Ok(Vec::new())
    }
    async fn list_threads(&self, _: &MessageListQuery) -> AppResult<ThreadListPage> {
        unimplemented!()
    }
    async fn get_thread(&self, _: &str) -> AppResult<Option<StoredThreadDetail>> {
        unimplemented!()
    }
    async fn modify_thread_labels(
        &self,
        _: &str,
        _: &[String],
        _: &[String],
    ) -> AppResult<StoredThreadDetail> {
        unimplemented!()
    }
    async fn trash_thread(&self, _: &str) -> AppResult<StoredThreadDetail> {
        unimplemented!()
    }
    async fn untrash_thread(&self, _: &str) -> AppResult<StoredThreadDetail> {
        unimplemented!()
    }
    async fn delete_thread(&self, _: &str) -> AppResult<bool> {
        unimplemented!()
    }
    async fn list_labels(&self) -> AppResult<Vec<StoredLabel>> {
        let inner = self.inner.lock().unwrap();
        let mut out: Vec<StoredLabel> = inner.labels.values().cloned().collect();
        for lbl in &mut out {
            let count = inner
                .messages
                .values()
                .filter(|m| m.label_ids.contains(&lbl.id))
                .count() as i32;
            lbl.messages_total = count;
        }
        Ok(out)
    }
    async fn get_label(&self, id: &str) -> AppResult<Option<StoredLabel>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.labels.get(id).cloned().map(|mut lbl| {
            lbl.messages_total = inner
                .messages
                .values()
                .filter(|m| m.label_ids.contains(&lbl.id))
                .count() as i32;
            lbl
        }))
    }
    async fn create_label(&self, input: NewLabelInput) -> AppResult<StoredLabel> {
        let mut inner = self.inner.lock().unwrap();
        if inner.labels.values().any(|l| l.name == input.name) {
            return Err(AppError::Conflict(format!(
                "Label already exists: {}",
                input.name
            )));
        }
        let id = format!("Label_{}", inner.next_id);
        inner.next_id += 1;
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
            uid_validity: 500 + inner.next_id as u32,
            uid_next: 1,
            upstream_label_id: input.upstream_label_id,
        };
        inner.labels.insert(id, lbl.clone());
        Ok(lbl)
    }
    async fn update_label(
        &self,
        id: &str,
        input: UpdateLabelInput,
        _: bool,
    ) -> AppResult<StoredLabel> {
        let mut inner = self.inner.lock().unwrap();
        let lbl = inner
            .labels
            .get_mut(id)
            .ok_or_else(|| AppError::NotFound(id.to_string()))?;
        if let Some(name) = input.name {
            lbl.name = name;
        }
        Ok(lbl.clone())
    }
    async fn delete_label(&self, id: &str) -> AppResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner
            .labels
            .remove(id)
            .ok_or_else(|| AppError::NotFound(id.to_string()))?;
        Ok(())
    }
    async fn upsert_upstream_label(&self, input: NewLabelInput) -> AppResult<StoredLabel> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(ref up) = input.upstream_label_id
            && let Some(existing) = inner
                .labels
                .values_mut()
                .find(|l| l.upstream_label_id.as_deref() == Some(up.as_str()))
        {
            existing.name = input.name;
            return Ok(existing.clone());
        }
        if let Some(existing) = inner
            .labels
            .values_mut()
            .find(|l| l.label_type == "user" && l.name == input.name)
        {
            existing.upstream_label_id = input.upstream_label_id;
            return Ok(existing.clone());
        }
        let id = format!("Label_{}", inner.next_id);
        inner.next_id += 1;
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
            uid_validity: 700 + inner.next_id as u32,
            uid_next: 1,
            upstream_label_id: input.upstream_label_id,
        };
        inner.labels.insert(id, lbl.clone());
        Ok(lbl)
    }
    async fn list_drafts(&self, _: &MessageListQuery) -> AppResult<DraftListPage> {
        unimplemented!()
    }
    async fn get_draft(&self, _: &str) -> AppResult<Option<StoredDraft>> {
        unimplemented!()
    }
    async fn create_draft(&self, _: NewMessageInput) -> AppResult<StoredDraft> {
        unimplemented!()
    }
    async fn update_draft(&self, _: &str, _: NewMessageInput) -> AppResult<StoredDraft> {
        unimplemented!()
    }
    async fn delete_draft(&self, _: &str) -> AppResult<bool> {
        unimplemented!()
    }
    async fn search_messages_ai(&self, _: &AiSearchQuery) -> AppResult<AiMessagePage> {
        unimplemented!()
    }
    async fn list_thread_summaries(&self, _: &AiThreadQuery) -> AppResult<AiThreadPage> {
        unimplemented!()
    }
    async fn triage_thread(&self, _: &str, _: &TriagePatch) -> AppResult<TriageResult> {
        unimplemented!()
    }
    async fn find_message_by_resend_id(&self, _: &str) -> AppResult<Option<StoredMessage>> {
        Ok(None)
    }
    async fn find_message_by_rfc_message_id(&self, rfc: &str) -> AppResult<Option<StoredMessage>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .messages
            .values()
            .find(|m| m.rfc822_message_id.as_deref() == Some(rfc))
            .cloned())
    }
    async fn record_delivery_status(&self, _: &str, _: &str) -> AppResult<Option<StoredMessage>> {
        Ok(None)
    }
    async fn imap_list_mailboxes(&self) -> AppResult<Vec<ImapMailboxInfo>> {
        let inner = self.inner.lock().unwrap();
        let mut names = vec![
            ("INBOX".to_string(), Some(LABEL_INBOX.to_string()), None),
            (
                "[Gmail]/All Mail".to_string(),
                None,
                Some("\\All".to_string()),
            ),
            (
                "[Gmail]/Sent Mail".to_string(),
                Some(LABEL_SENT.to_string()),
                Some("\\Sent".to_string()),
            ),
            (
                "[Gmail]/Drafts".to_string(),
                Some(LABEL_DRAFT.to_string()),
                Some("\\Drafts".to_string()),
            ),
            (
                "[Gmail]/Trash".to_string(),
                Some(LABEL_TRASH.to_string()),
                Some("\\Trash".to_string()),
            ),
            (
                "[Gmail]/Spam".to_string(),
                Some(LABEL_SPAM.to_string()),
                Some("\\Junk".to_string()),
            ),
            (
                "[Gmail]/Starred".to_string(),
                Some(LABEL_STARRED.to_string()),
                Some("\\Flagged".to_string()),
            ),
        ];
        let mut user_labels: Vec<_> = inner
            .labels
            .values()
            .filter(|l| l.label_type == "user")
            .cloned()
            .collect();
        user_labels.sort_by(|a, b| a.name.cmp(&b.name));
        for ul in user_labels {
            names.push((ul.name, Some(ul.id), None));
        }

        let mut out = Vec::new();
        for (name, label_id, special_use) in names {
            let entries = Self::list_mailbox_entries_locked(&inner, &name)?;
            let unseen = entries
                .iter()
                .filter(|e| e.label_ids.iter().any(|l| l == LABEL_UNREAD))
                .count() as u32;
            let (uid_validity, uid_next) = match &label_id {
                Some(lid) => inner
                    .labels
                    .get(lid)
                    .map(|l| (l.uid_validity, l.uid_next))
                    .unwrap_or((1, 1)),
                None => (999, inner.all_mail_uid_next),
            };
            out.push(ImapMailboxInfo {
                name,
                label_id,
                special_use,
                uid_validity,
                uid_next,
                messages: entries.len() as u32,
                unseen,
            });
        }
        Ok(out)
    }
    async fn imap_mailbox_info(&self, mailbox_name: &str) -> AppResult<Option<ImapMailboxInfo>> {
        let list = self.imap_list_mailboxes().await?;
        Ok(list.into_iter().find(|m| {
            m.name == mailbox_name
                || (mailbox_name.eq_ignore_ascii_case("INBOX") && m.name == "INBOX")
        }))
    }
    async fn imap_list_messages(&self, mailbox_name: &str) -> AppResult<Vec<ImapMessageEntry>> {
        let inner = self.inner.lock().unwrap();
        Self::list_mailbox_entries_locked(&inner, mailbox_name)
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
        let mut inner = self.inner.lock().unwrap();
        let mut msg = inner
            .messages
            .get(message_id)
            .cloned()
            .ok_or_else(|| AppError::NotFound(message_id.to_string()))?;

        if is_seen {
            msg.label_ids.retain(|l| l != LABEL_UNREAD);
        } else if !msg.label_ids.iter().any(|l| l == LABEL_UNREAD) {
            msg.label_ids.push(LABEL_UNREAD.to_string());
        }

        if is_flagged {
            if !msg.label_ids.iter().any(|l| l == LABEL_STARRED) {
                msg.label_ids.push(LABEL_STARRED.to_string());
                Self::alloc_label_uid(&mut inner, LABEL_STARRED, message_id);
            }
        } else {
            msg.label_ids.retain(|l| l != LABEL_STARRED);
        }

        if is_draft {
            if !msg.label_ids.iter().any(|l| l == LABEL_DRAFT) {
                msg.label_ids.push(LABEL_DRAFT.to_string());
                Self::alloc_label_uid(&mut inner, LABEL_DRAFT, message_id);
            }
        } else {
            msg.label_ids.retain(|l| l != LABEL_DRAFT);
        }

        msg.is_answered = is_answered;
        msg.is_deleted = is_deleted;
        inner.messages.insert(message_id.to_string(), msg.clone());
        Ok(msg)
    }
    async fn imap_expunge(&self, mailbox_name: &str) -> AppResult<Vec<u32>> {
        let mut inner = self.inner.lock().unwrap();
        let entries = Self::list_mailbox_entries_locked(&inner, mailbox_name)?;
        let Some((_, label_opt)) = Self::mailbox_to_label(&inner, mailbox_name) else {
            return Err(AppError::NotFound(mailbox_name.to_string()));
        };
        let mut expunged_seqs = Vec::new();
        for entry in entries {
            if !entry.is_deleted {
                continue;
            }
            expunged_seqs.push(entry.seq);
            if label_opt.as_deref() == Some(LABEL_TRASH) {
                inner.messages.remove(&entry.message_id);
            } else if let Some(mut msg) = inner.messages.get(&entry.message_id).cloned() {
                if let Some(ref lid) = label_opt {
                    msg.label_ids.retain(|l| l != lid);
                }
                if !msg.label_ids.iter().any(|l| l == LABEL_TRASH) {
                    msg.label_ids.push(LABEL_TRASH.to_string());
                    Self::alloc_label_uid(&mut inner, LABEL_TRASH, &entry.message_id);
                }
                msg.is_deleted = false;
                inner.messages.insert(entry.message_id.clone(), msg);
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
        let mut inner = self.inner.lock().unwrap();
        let Some((_, src_lbl)) = Self::mailbox_to_label(&inner, src_mailbox) else {
            return Err(AppError::NotFound(src_mailbox.to_string()));
        };
        let Some((_, dst_lbl)) = Self::mailbox_to_label(&inner, dst_mailbox) else {
            return Err(AppError::NotFound(dst_mailbox.to_string()));
        };

        let mut pairs = Vec::new();
        for mid in message_ids {
            let Some(mut msg) = inner.messages.get(mid).cloned() else {
                continue;
            };
            let src_uid = match &src_lbl {
                Some(lid) => inner
                    .label_uids
                    .get(&(lid.clone(), mid.clone()))
                    .copied()
                    .unwrap_or(msg.all_mail_uid),
                None => msg.all_mail_uid,
            };
            let dst_uid = match &dst_lbl {
                Some(lid) => {
                    if !msg.label_ids.contains(lid) {
                        msg.label_ids.push(lid.clone());
                    }
                    Self::alloc_label_uid(&mut inner, lid, mid)
                }
                None => msg.all_mail_uid,
            };
            if is_move
                && let Some(ref s_lid) = src_lbl
                && src_lbl != dst_lbl
            {
                msg.label_ids.retain(|l| l != s_lid);
            }
            inner.messages.insert(mid.clone(), msg);
            pairs.push((src_uid, dst_uid));
        }
        Ok(pairs)
    }
    async fn imap_append(
        &self,
        mailbox_name: &str,
        mut input: NewMessageInput,
    ) -> AppResult<(u32, u32, StoredMessage)> {
        let mut inner = self.inner.lock().unwrap();
        let Some((_, lbl_opt)) = Self::mailbox_to_label(&inner, mailbox_name) else {
            return Err(AppError::NotFound(format!(
                "Mailbox does not exist: {mailbox_name}"
            )));
        };
        if let Some(ref lid) = lbl_opt
            && !input.label_ids.contains(lid)
        {
            input.label_ids.push(lid.clone());
        }
        let stored = Self::insert_locked(&mut inner, input);
        let (uv, uid) = match lbl_opt {
            Some(ref lid) => {
                let uv = inner.labels.get(lid).map(|l| l.uid_validity).unwrap_or(1);
                let u = inner
                    .label_uids
                    .get(&(lid.clone(), stored.id.clone()))
                    .copied()
                    .unwrap_or(stored.all_mail_uid);
                (uv, u)
            }
            None => (999, stored.all_mail_uid),
        };
        Ok((uv, uid, stored))
    }
    async fn upsert_synced_message(&self, input: NewMessageInput) -> AppResult<UpsertOutcome> {
        let mut inner = self.inner.lock().unwrap();
        // 1. Match by upstream_gmail_id
        if let Some(ref up_id) = input.upstream_gmail_id
            && let Some(existing_id) = inner
                .messages
                .values()
                .find(|m| m.upstream_gmail_id.as_deref() == Some(up_id.as_str()))
                .map(|m| m.id.clone())
        {
            let mut msg = inner.messages.get(&existing_id).cloned().unwrap();
            let changed = msg.label_ids != input.label_ids;
            msg.label_ids = input.label_ids;
            for l in &msg.label_ids {
                Self::alloc_label_uid(&mut inner, l, &existing_id);
            }
            inner.messages.insert(existing_id, msg.clone());
            return Ok(UpsertOutcome {
                kind: if changed {
                    UpsertOutcomeKind::Updated
                } else {
                    UpsertOutcomeKind::Deduplicated
                },
                message: msg,
            });
        }
        // 2. Match by rfc822_message_id
        if let Some(ref rfc_id) = input.rfc822_message_id
            && let Some(existing_id) = inner
                .messages
                .values()
                .find(|m| m.rfc822_message_id.as_deref() == Some(rfc_id.as_str()))
                .map(|m| m.id.clone())
        {
            let mut msg = inner.messages.get(&existing_id).cloned().unwrap();
            msg.upstream_gmail_id = input.upstream_gmail_id.or(msg.upstream_gmail_id);
            msg.upstream_thread_id = input.upstream_thread_id.or(msg.upstream_thread_id);
            for l in input.label_ids {
                if !msg.label_ids.contains(&l) {
                    msg.label_ids.push(l.clone());
                    Self::alloc_label_uid(&mut inner, &l, &existing_id);
                }
            }
            inner.messages.insert(existing_id, msg.clone());
            return Ok(UpsertOutcome {
                kind: UpsertOutcomeKind::Deduplicated,
                message: msg,
            });
        }
        // 3. Insert new
        let msg = Self::insert_locked(&mut inner, input);
        Ok(UpsertOutcome {
            kind: UpsertOutcomeKind::Inserted,
            message: msg,
        })
    }
    async fn find_message_by_upstream_id(
        &self,
        upstream_gmail_id: &str,
    ) -> AppResult<Option<StoredMessage>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .messages
            .values()
            .find(|m| m.upstream_gmail_id.as_deref() == Some(upstream_gmail_id))
            .cloned())
    }
    async fn delete_message_by_upstream_id(
        &self,
        upstream_gmail_id: &str,
    ) -> AppResult<Option<StoredMessage>> {
        let mut inner = self.inner.lock().unwrap();
        let id = inner
            .messages
            .values()
            .find(|m| m.upstream_gmail_id.as_deref() == Some(upstream_gmail_id))
            .map(|m| m.id.clone());
        Ok(id.and_then(|k| inner.messages.remove(&k)))
    }
    async fn get_sync_state(&self, account_key: &str) -> AppResult<Option<SyncState>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .sync_states
            .get(account_key)
            .cloned())
    }
    async fn save_sync_state(&self, state: SyncState) -> AppResult<()> {
        self.inner
            .lock()
            .unwrap()
            .sync_states
            .insert(state.account_key.clone(), state);
        Ok(())
    }
    async fn list_sync_states(&self) -> AppResult<Vec<SyncState>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .sync_states
            .values()
            .cloned()
            .collect())
    }
    async fn set_watch(&self, _: WatchSubscription) -> AppResult<WatchSubscription> {
        unimplemented!()
    }
    async fn get_watch(&self) -> AppResult<Option<WatchSubscription>> {
        Ok(None)
    }
    async fn clear_watch(&self) -> AppResult<()> {
        Ok(())
    }
    async fn get_settings(&self) -> AppResult<UserSettings> {
        unimplemented!()
    }
    async fn save_settings(&self, _: UserSettings) -> AppResult<UserSettings> {
        unimplemented!()
    }
}

pub(crate) fn test_app_state(mut config: Config) -> AppState {
    if config.imap_username.is_none() {
        config.imap_username = Some("agent@example.com".to_string());
    }
    if config.imap_password.is_none() {
        config.imap_password = Some("secret-pass".to_string());
    }
    AppState::with_backends(
        config,
        Arc::new(TestMailStore::new()),
        Arc::new(DummyResendClient),
    )
}

// ============================================================================
// Parser & MIME Formatter Unit Tests
// ============================================================================

#[test]
fn test_command_parser_brackets_quotes_and_lists() {
    let cmd = parse_command_line(
        r#"A01 UID FETCH 1:5,8:* (UID FLAGS BODY.PEEK[HEADER.FIELDS (Subject From)]<0.128>)"#,
    )
    .unwrap();
    assert_eq!(cmd.tag, "A01");
    assert_eq!(cmd.name, "UID");
    assert_eq!(cmd.args[0], ImapArg::Atom("FETCH".to_string()));
    assert_eq!(cmd.args[1], ImapArg::Atom("1:5,8:*".to_string()));
    let items = cmd.args[2].as_list().unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(
        items[2],
        ImapArg::Atom("BODY.PEEK[HEADER.FIELDS (Subject From)]<0.128>".to_string())
    );
}

#[tokio::test]
async fn test_read_command_sync_and_literal_plus() {
    let (mut client, server) = tokio::io::duplex(4096);
    let mut server_reader = BufReader::new(server);

    // Synchronizing literal `{5}` should trigger `+ Ready\r\n`.
    let client_task = tokio::spawn(async move {
        client.write_all(b"A1 APPEND INBOX {5}\r\n").await.unwrap();
        let mut resp = [0u8; 9];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut resp)
            .await
            .unwrap();
        assert_eq!(&resp, b"+ Ready\r\n");
        client.write_all(b"hello\r\n").await.unwrap();

        // Non-synchronizing LITERAL+ `{3+}` sends bytes immediately.
        client
            .write_all(b"A2 APPEND INBOX {3+}\r\nbye\r\n")
            .await
            .unwrap();
    });

    let ReadCommandOutcome::Command(c1) = read_command(&mut server_reader, 1024).await.unwrap()
    else {
        panic!("expected command");
    };
    assert_eq!(c1.tag, "A1");
    assert_eq!(c1.name, "APPEND");
    assert_eq!(c1.args[1], ImapArg::Literal(b"hello".to_vec()));

    let ReadCommandOutcome::Command(c2) = read_command(&mut server_reader, 1024).await.unwrap()
    else {
        panic!("expected command");
    };
    assert_eq!(c2.tag, "A2");
    assert_eq!(c2.args[1], ImapArg::Literal(b"bye".to_vec()));

    client_task.await.unwrap();
}

#[test]
fn test_sequence_set_and_wildcards_and_dates() {
    let ranges = parse_sequence_set("1,5:3,8:*", 10).unwrap();
    assert!(seq_set_contains(&ranges, 1));
    assert!(!seq_set_contains(&ranges, 2));
    assert!(seq_set_contains(&ranges, 4));
    assert!(seq_set_contains(&ranges, 9));
    assert!(seq_set_contains(&ranges, 10));

    assert!(imap_wildcard_match("*", "[Gmail]/All Mail", '/'));
    assert!(!imap_wildcard_match("%", "[Gmail]/All Mail", '/'));
    assert!(imap_wildcard_match("%", "[Gmail]", '/'));
    assert!(imap_wildcard_match("inbox", "INBOX", '/'));

    let ms = parse_imap_date_time("15-Mar-2025 10:20:30 +0000").unwrap();
    assert_eq!(format_internal_date(ms), "15-Mar-2025 10:20:30 +0000");
    assert_eq!(
        parse_imap_search_date("5-Jan-2025").unwrap().to_string(),
        "2025-01-05"
    );
}

#[test]
fn test_mime_envelope_bodystructure_and_sections() {
    let raw = concat!(
        "Date: Mon, 06 Jan 2025 12:00:00 +0000\r\n",
        "From: Alice <alice@example.com>\r\n",
        "To: Bob <bob@example.com>\r\n",
        "Subject: Multipart Test\r\n",
        "Message-ID: <msg-1@example.com>\r\n",
        "Content-Type: multipart/mixed; boundary=\"bnd\"\r\n",
        "\r\n",
        "--bnd\r\n",
        "Content-Type: text/plain; charset=\"utf-8\"\r\n",
        "\r\n",
        "Hello World!\r\n",
        "--bnd\r\n",
        "Content-Type: text/html; charset=\"utf-8\"\r\n",
        "\r\n",
        "<p>Hello HTML</p>\r\n",
        "--bnd--\r\n",
    )
    .as_bytes();

    let env = format_envelope(raw);
    assert!(env.contains("\"Multipart Test\""));
    assert!(env.contains("\"alice\" \"example.com\""));
    assert!(env.contains("\"<msg-1@example.com>\""));

    let bs = format_bodystructure(raw, true);
    assert!(bs.contains("\"TEXT\" \"PLAIN\""));
    assert!(bs.contains("\"TEXT\" \"HTML\""));
    assert!(bs.contains("\"MIXED\""));

    let hdr_subj = extract_body_section(raw, &parse_body_section("HEADER.FIELDS (Subject)"), None);
    let hdr_str = String::from_utf8_lossy(&hdr_subj);
    assert!(hdr_str.contains("Subject: Multipart Test"));
    assert!(!hdr_str.contains("From: Alice"));

    let part1 = extract_body_section(raw, &parse_body_section("1"), Some((0, 5)));
    assert_eq!(part1, b"Hello");
}

// ============================================================================
// End-to-End IMAP4rev1 Server Tests (Raw TCP + `async-imap` + `IDLE`)
// ============================================================================

async fn spawn_test_imap(state: AppState) -> (std::net::SocketAddr, watch::Sender<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = serve_plain_listener(listener, state, None, rx).await;
    });
    (addr, tx)
}

async fn send_cmd(reader: &mut BufReader<TcpStream>, tag: &str, cmd: &str) -> Vec<String> {
    reader
        .get_mut()
        .write_all(format!("{tag} {cmd}\r\n").as_bytes())
        .await
        .unwrap();
    let mut lines = Vec::new();
    let prefix = format!("{tag} ");
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await.unwrap();
        assert!(n > 0, "unexpected EOF waiting for {tag}");
        lines.push(line.clone());
        if line.starts_with(&prefix) {
            break;
        }
    }
    lines
}

#[tokio::test]
async fn test_imap_full_protocol_flow_and_async_imap_client() {
    let state = test_app_state(Config::for_test());
    let (addr, shutdown_tx) = spawn_test_imap(state.clone()).await;

    // 1. Raw TCP test for AUTHENTICATE PLAIN, CREATE/RENAME/DELETE, APPEND LITERAL+, SEARCH, STORE, COPY, MOVE, EXPUNGE, LOGOUT
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.unwrap();
    assert!(greeting.contains("* OK [CAPABILITY"));
    assert!(greeting.contains("X-GM-EXT-1"));

    // ID & CAPABILITY
    let id_res = send_cmd(&mut reader, "T0", "ID (\"name\" \"test\")").await;
    assert!(id_res.iter().any(|l| l.starts_with("* ID ")));
    assert!(id_res.last().unwrap().starts_with("T0 OK"));

    // AUTHENTICATE PLAIN with SASL-IR
    let sasl = base64::engine::general_purpose::STANDARD.encode("\0agent@example.com\0secret-pass");
    let auth_res = send_cmd(&mut reader, "T1", &format!("AUTHENTICATE PLAIN {sasl}")).await;
    assert!(auth_res.last().unwrap().starts_with("T1 OK"));

    // NAMESPACE & LIST
    let ns_res = send_cmd(&mut reader, "T2", "NAMESPACE").await;
    assert!(ns_res.iter().any(|l| l.contains("* NAMESPACE")));

    let list_res = send_cmd(&mut reader, "T3", r#"LIST "" "*""#).await;
    assert!(list_res.iter().any(|l| l.contains(r#""INBOX""#)));
    assert!(list_res.iter().any(|l| l.contains(r#"\All"#)));
    assert!(
        list_res
            .iter()
            .any(|l| l.contains(r#"\Noselect \HasChildren"#))
    );

    // CREATE / RENAME / DELETE user label + reject system folder
    assert!(
        send_cmd(&mut reader, "T4", r#"CREATE "Work""#)
            .await
            .last()
            .unwrap()
            .starts_with("T4 OK")
    );
    assert!(
        send_cmd(&mut reader, "T5", r#"RENAME "Work" "Projects""#)
            .await
            .last()
            .unwrap()
            .starts_with("T5 OK")
    );
    assert!(
        send_cmd(&mut reader, "T6", r#"DELETE "INBOX""#)
            .await
            .last()
            .unwrap()
            .starts_with("T6 NO")
    );

    // APPEND with LITERAL+
    let raw_msg = concat!(
        "From: alice@example.com\r\n",
        "To: agent@example.com\r\n",
        "Subject: Quarterly Plan\r\n",
        "Message-ID: <plan-1@example.com>\r\n",
        "\r\n",
        "Let us ship nogml today.\r\n"
    );
    let append_cmd = format!(
        "T7 APPEND INBOX (\\Flagged) \"10-Feb-2025 09:00:00 +0000\" {{{}+}}\r\n{raw_msg}\r\n",
        raw_msg.len()
    );
    reader
        .get_mut()
        .write_all(append_cmd.as_bytes())
        .await
        .unwrap();
    let mut append_line = String::new();
    reader.read_line(&mut append_line).await.unwrap();
    assert!(append_line.starts_with("T7 OK [APPENDUID "));

    // STATUS & SELECT
    let status_res = send_cmd(&mut reader, "T8", "STATUS INBOX (MESSAGES UNSEEN UIDNEXT)").await;
    assert!(status_res.iter().any(|l| l.contains("MESSAGES 1 UNSEEN 1")));

    let select_res = send_cmd(&mut reader, "T9", "SELECT INBOX").await;
    assert!(select_res.iter().any(|l| l.contains("* 1 EXISTS")));
    assert!(select_res.last().unwrap().contains("[READ-WRITE]"));

    // UID SEARCH
    let search_res = send_cmd(
        &mut reader,
        "T10",
        r#"UID SEARCH FLAGGED SUBJECT "Quarterly""#,
    )
    .await;
    assert!(search_res.iter().any(|l| l.trim() == "* SEARCH 1"));

    // UID STORE +FLAGS (\Seen \Deleted)
    let store_res = send_cmd(&mut reader, "T11", r#"UID STORE 1 +FLAGS (\Seen)"#).await;
    assert!(store_res.iter().any(|l| l.contains("\\Seen")));

    // UID COPY to Projects
    let copy_res = send_cmd(&mut reader, "T12", r#"UID COPY 1 "Projects""#).await;
    assert!(copy_res.last().unwrap().contains("[COPYUID "));

    // UID MOVE to [Gmail]/Trash
    let move_res = send_cmd(&mut reader, "T13", r#"UID MOVE 1 "[Gmail]/Trash""#).await;
    assert!(move_res.iter().any(|l| l.contains("EXPUNGE")));
    assert!(move_res.last().unwrap().starts_with("T13 OK"));

    // LOGOUT
    let bye = send_cmd(&mut reader, "T14", "LOGOUT").await;
    assert!(bye.iter().any(|l| l.starts_with("* BYE")));

    // 2. Real `async-imap` client connecting to verify RFC 3501 + X-GM-EXT-1 interoperability
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut client = async_imap::Client::new(tcp);
    let _ = client.read_response().await.unwrap();
    let mut session = client
        .login("agent@example.com", "secret-pass")
        .await
        .map_err(|(e, _)| e)
        .unwrap();

    let caps = session.capabilities().await.unwrap();
    assert!(caps.has_str("X-GM-EXT-1"));
    assert!(caps.has_str("IDLE"));
    assert!(caps.has_str("MOVE"));

    let mbx = session.select("Projects").await.unwrap();
    assert_eq!(mbx.exists, 1);

    let fetches: Vec<_> = session
        .uid_fetch(
            "1:*",
            "(UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODYSTRUCTURE BODY.PEEK[] X-GM-MSGID X-GM-LABELS)",
        )
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap();
    assert_eq!(fetches.len(), 1);
    let f = &fetches[0];
    assert_eq!(f.uid, Some(1));
    assert!(f.gmail_msg_id().is_some());
    assert!(
        f.body()
            .unwrap()
            .windows(b"Quarterly Plan".len())
            .any(|w| w == b"Quarterly Plan")
    );
    assert!(f.envelope().is_some());
    assert!(f.bodystructure().is_some());

    session.logout().await.unwrap();
    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn test_imap_idle_live_exists_push() {
    let state = test_app_state(Config::for_test());
    let (addr, shutdown_tx) = spawn_test_imap(state.clone()).await;

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();

    let _ = send_cmd(&mut reader, "A1", "LOGIN agent@example.com secret-pass").await;
    let _ = send_cmd(&mut reader, "A2", "SELECT INBOX").await;

    // Start IDLE
    reader.get_mut().write_all(b"A3 IDLE\r\n").await.unwrap();
    let mut cont = String::new();
    reader.read_line(&mut cont).await.unwrap();
    assert!(cont.starts_with("+ idling"), "unexpected cont: {cont}");

    // Inject a new message into INBOX and publish MailEvent::MessageReceived
    let raw = b"From: sender@example.com\r\nSubject: Live Push\r\n\r\nHello IDLE!\r\n".to_vec();
    let input = crate::imap::mime_fmt::parse_raw_to_new_message_input(
        raw,
        vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
        None,
        "local",
        None,
        None,
        false,
        false,
    );
    let stored = state.store.insert_message(input).await.unwrap();
    state.events.publish(
        EventSource::Api,
        MailEvent::MessageReceived {
            message_id: stored.id,
            thread_id: stored.thread_id,
            from: stored.from_addr,
            subject: stored.subject,
            snippet: stored.snippet,
            labels: stored.label_ids,
        },
    );

    // Client should receive `* 1 EXISTS` immediately while idling
    let mut push_line = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        reader.read_line(&mut push_line),
    )
    .await
    .expect("IDLE EXISTS timeout")
    .unwrap();
    assert_eq!(push_line.trim(), "* 1 EXISTS");

    // End IDLE with DONE
    reader.get_mut().write_all(b"DONE\r\n").await.unwrap();
    let mut done_line = String::new();
    reader.read_line(&mut done_line).await.unwrap();
    assert!(done_line.starts_with("A3 OK"));

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn test_imap_auth_continuation_examine_expunge_search_and_body_peek_vs_body() {
    // Exercise against the real `MemoryStore` backend to verify full trait integration!
    let mut cfg = Config::for_test();
    cfg.imap_username = Some("agent@example.com".to_string());
    cfg.imap_password = Some("secret-pass".to_string());
    let state = AppState::with_backends(
        cfg,
        Arc::new(crate::storage::MemoryStore::new("agent@example.com")),
        Arc::new(DummyResendClient),
    );
    let (addr, shutdown_tx) = spawn_test_imap(state.clone()).await;

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.unwrap();

    // AUTHENTICATE PLAIN with server continuation `+ \r\n`
    reader
        .get_mut()
        .write_all(b"A1 AUTHENTICATE PLAIN\r\n")
        .await
        .unwrap();
    let mut cont = String::new();
    reader.read_line(&mut cont).await.unwrap();
    assert!(cont.starts_with("+ "), "expected continuation, got: {cont}");

    let sasl = base64::engine::general_purpose::STANDARD.encode("\0agent@example.com\0secret-pass");
    reader
        .get_mut()
        .write_all(format!("{sasl}\r\n").as_bytes())
        .await
        .unwrap();
    let mut auth_done = String::new();
    reader.read_line(&mut auth_done).await.unwrap();
    assert!(auth_done.starts_with("A1 OK"));

    // APPEND two messages using synchronizing literal `{N}`
    let m1 = "From: one@example.com\r\nSubject: Alpha\r\n\r\nFirst message body\r\n";
    reader
        .get_mut()
        .write_all(format!("A2 APPEND INBOX {{{}}}\r\n", m1.len()).as_bytes())
        .await
        .unwrap();
    let mut ready = String::new();
    reader.read_line(&mut ready).await.unwrap();
    assert_eq!(ready, "+ Ready\r\n");
    reader
        .get_mut()
        .write_all(format!("{m1}\r\n").as_bytes())
        .await
        .unwrap();
    let mut app1 = String::new();
    reader.read_line(&mut app1).await.unwrap();
    assert!(app1.starts_with("A2 OK [APPENDUID "));

    let m2 = "From: two@example.com\r\nSubject: Beta\r\n\r\nSecond longer message body here\r\n";
    let app2 = send_cmd(
        &mut reader,
        "A3",
        &format!("APPEND INBOX {{{}+}}\r\n{m2}", m2.len()),
    )
    .await;
    assert!(app2.last().unwrap().starts_with("A3 OK [APPENDUID "));

    // EXAMINE INBOX (read-only) should reject STORE / EXPUNGE
    let ex = send_cmd(&mut reader, "A4", "EXAMINE INBOX").await;
    assert!(ex.last().unwrap().contains("[READ-ONLY]"));
    let ro_store = send_cmd(&mut reader, "A5", r#"STORE 1 +FLAGS (\Seen)"#).await;
    assert!(ro_store.last().unwrap().starts_with("A5 NO"));

    // SELECT INBOX (read-write)
    let sel = send_cmd(&mut reader, "A6", "SELECT INBOX").await;
    assert!(sel.iter().any(|l| l.contains("* 2 EXISTS")));

    // BODY.PEEK[TEXT] must NOT set \Seen
    let peek = send_cmd(&mut reader, "A7", "FETCH 1 (FLAGS BODY.PEEK[TEXT])").await;
    assert!(!peek.iter().any(|l| l.contains("\\Seen")));

    // BODY[TEXT] (non-peek) MUST set \Seen in read-write mode
    let body = send_cmd(&mut reader, "A8", "FETCH 1 (BODY[TEXT]<0.5>)").await;
    assert!(body.iter().any(|l| l.contains("BODY[TEXT]<0>")));
    assert!(body.iter().any(|l| l.contains("\\Seen")));

    // SEARCH with NOT / OR / FROM / UNSEEN
    let s1 = send_cmd(&mut reader, "A9", r#"SEARCH UNSEEN"#).await;
    assert!(s1.iter().any(|l| l.trim() == "* SEARCH 2"));
    let s2 = send_cmd(
        &mut reader,
        "A10",
        r#"SEARCH OR FROM "one@example.com" SUBJECT "Beta""#,
    )
    .await;
    assert!(s2.iter().any(|l| l.trim() == "* SEARCH 1 2"));
    let s3 = send_cmd(&mut reader, "A11", r#"SEARCH NOT FROM "one@example.com""#).await;
    assert!(s3.iter().any(|l| l.trim() == "* SEARCH 2"));

    // Mark message 1 \Deleted and EXPUNGE
    let _ = send_cmd(&mut reader, "A12", r#"STORE 1 +FLAGS.SILENT (\Deleted)"#).await;
    let exp = send_cmd(&mut reader, "A13", "EXPUNGE").await;
    assert!(exp.iter().any(|l| l.trim() == "* 1 EXPUNGE"));
    assert!(exp.last().unwrap().starts_with("A13 OK"));

    // CLOSE & LOGOUT
    assert!(
        send_cmd(&mut reader, "A14", "CLOSE")
            .await
            .last()
            .unwrap()
            .starts_with("A14 OK")
    );
    let _ = send_cmd(&mut reader, "A15", "LOGOUT").await;
    let _ = shutdown_tx.send(true);
}

#[test]
fn test_format_sequence_set_compact_ranges() {
    use crate::imap::parser::format_sequence_set;

    assert_eq!(format_sequence_set(&[]), "");
    assert_eq!(format_sequence_set(&[0]), "");
    assert_eq!(format_sequence_set(&[5]), "5");
    assert_eq!(format_sequence_set(&[1, 2, 3]), "1:3");
    assert_eq!(format_sequence_set(&[8, 2, 1, 3, 5, 7, 3, 0]), "1:3,5,7:8");
}

#[tokio::test]
async fn test_imap_condstore_qresync_enable_and_edge_cases() {
    use crate::storage::MemoryStore;

    let store = Arc::new(MemoryStore::new("agent@example.com"));
    let cfg = Config {
        imap_username: Some("agent@example.com".to_string()),
        imap_password: Some("secret-pass".to_string()),
        ..Config::default()
    };
    let state = AppState::with_backends(cfg, store.clone(), Arc::new(DummyResendClient));
    let (addr, shutdown_tx) = spawn_test_imap(state).await;

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.unwrap();
    // Pre-auth greeting should not advertise post-auth CONDSTORE/QRESYNC.
    assert!(!greeting.contains("CONDSTORE"));
    assert!(!greeting.contains("QRESYNC"));

    // ENABLE before authentication is rejected with NO.
    let pre_enable = send_cmd(&mut reader, "E0", "ENABLE CONDSTORE").await;
    assert!(pre_enable.last().unwrap().starts_with("E0 NO"));

    // Authenticate and confirm post-auth CAPABILITY advertises ENABLE, CONDSTORE, QRESYNC.
    let login = send_cmd(&mut reader, "L1", "LOGIN agent@example.com secret-pass").await;
    let login_line = login.last().unwrap();
    assert!(login_line.starts_with("L1 OK"));
    assert!(login_line.contains("ENABLE"));
    assert!(login_line.contains("CONDSTORE"));
    assert!(login_line.contains("QRESYNC"));

    let cap = send_cmd(&mut reader, "C1", "CAPABILITY").await;
    let cap_joined = cap.join("");
    assert!(cap_joined.contains("ENABLE"));
    assert!(cap_joined.contains("CONDSTORE"));
    assert!(cap_joined.contains("QRESYNC"));

    // SELECT ... (QRESYNC ...) before ENABLE QRESYNC must fail with BAD (RFC 7162 §3.2.5.1).
    let bad_qresync = send_cmd(&mut reader, "Q0", "SELECT INBOX (QRESYNC (1 1))").await;
    assert!(bad_qresync.last().unwrap().starts_with("Q0 BAD"));

    // ENABLE ignores unknown extensions and returns enabled ones.
    let en = send_cmd(&mut reader, "E1", "ENABLE CONDSTORE QRESYNC X-UNKNOWN-EXT").await;
    assert!(
        en.iter().any(|l| l.trim() == "* ENABLED CONDSTORE QRESYNC"),
        "expected * ENABLED CONDSTORE QRESYNC, got {en:?}"
    );
    assert!(en.last().unwrap().starts_with("E1 OK"));

    // Append 3 messages into INBOX.
    for (idx, subj) in ["One", "Two", "Three"].iter().enumerate() {
        let raw = format!("From: s{idx}@example.com\r\nSubject: {subj}\r\n\r\nBody {subj}\r\n");
        let app = send_cmd(
            &mut reader,
            &format!("AP{idx}"),
            &format!("APPEND INBOX {{{}+}}\r\n{raw}", raw.len()),
        )
        .await;
        assert!(app.last().unwrap().contains("OK [APPENDUID "));
    }

    // STATUS INBOX (HIGHESTMODSEQ UIDVALIDITY MESSAGES)
    let st = send_cmd(
        &mut reader,
        "S1",
        "STATUS INBOX (MESSAGES UIDVALIDITY HIGHESTMODSEQ)",
    )
    .await;
    let st_line = st
        .iter()
        .find(|l| l.starts_with("* STATUS "))
        .expect("STATUS response");
    assert!(st_line.contains("MESSAGES 3"), "got {st_line}");
    assert!(st_line.contains("HIGHESTMODSEQ "), "got {st_line}");

    // SELECT INBOX (CONDSTORE) emits HIGHESTMODSEQ.
    let sel = send_cmd(&mut reader, "SEL1", "SELECT INBOX (CONDSTORE)").await;
    let hms_line = sel
        .iter()
        .find(|l| l.contains("[HIGHESTMODSEQ "))
        .expect("HIGHESTMODSEQ in SELECT");
    let uv_line = sel
        .iter()
        .find(|l| l.contains("[UIDVALIDITY "))
        .expect("UIDVALIDITY in SELECT");
    let extract_bracket_num = |line: &str, key: &str| -> u64 {
        let start = line.find(key).unwrap() + key.len();
        let rest = &line[start..];
        let end = rest.find(']').unwrap();
        rest[..end].trim().parse::<u64>().unwrap()
    };
    let uid_validity = extract_bracket_num(uv_line, "[UIDVALIDITY ");
    let initial_modseq = extract_bracket_num(hms_line, "[HIGHESTMODSEQ ");
    assert!(initial_modseq >= 1);

    // ENABLE while Selected must fail with BAD per RFC 5161.
    let bad_en = send_cmd(&mut reader, "E2", "ENABLE CONDSTORE").await;
    assert!(bad_en.last().unwrap().starts_with("E2 BAD"));

    // Modify ONLY UID 2 flags -> bumps UID 2 modseq above initial_modseq and returns MODSEQ.
    let st2 = send_cmd(&mut reader, "ST1", r#"UID STORE 2 +FLAGS (\Seen \Flagged)"#).await;
    assert!(
        st2.iter()
            .any(|l| l.contains("UID 2") && l.contains("\\Flagged") && l.contains("MODSEQ (")),
        "expected MODSEQ in STORE response, got {st2:?}"
    );
    assert!(st2.last().unwrap().starts_with("ST1 OK"));

    // UID FETCH 1:* (FLAGS MODSEQ) (CHANGEDSINCE <initial_modseq>) returns ONLY UID 2!
    let delta = send_cmd(
        &mut reader,
        "F1",
        &format!("UID FETCH 1:* (FLAGS MODSEQ) (CHANGEDSINCE {initial_modseq})"),
    )
    .await;
    let fetch_lines: Vec<&String> = delta.iter().filter(|l| l.contains(" FETCH (")).collect();
    assert_eq!(fetch_lines.len(), 1, "expected only UID 2, got {delta:?}");
    assert!(fetch_lines[0].contains("UID 2"));
    assert!(fetch_lines[0].contains("MODSEQ ("));

    // SEARCH MODSEQ returns only messages with modseq >= initial_modseq + 1 and includes (MODSEQ <max>).
    let srch = send_cmd(
        &mut reader,
        "SR1",
        &format!("UID SEARCH MODSEQ {}", initial_modseq + 1),
    )
    .await;
    assert!(
        srch.iter().any(|l| l.starts_with("* SEARCH 2 (MODSEQ ")),
        "expected UID 2 with MODSEQ in SEARCH, got {srch:?}"
    );

    // UID STORE 2 (UNCHANGEDSINCE <initial_modseq>) must NOT modify UID 2 and report [MODIFIED 2].
    let stale = send_cmd(
        &mut reader,
        "ST2",
        &format!(r#"UID STORE 2 (UNCHANGEDSINCE {initial_modseq}) +FLAGS (\Answered)"#),
    )
    .await;
    assert!(
        stale.last().unwrap().contains("[MODIFIED 2]"),
        "expected [MODIFIED 2], got {stale:?}"
    );
    // Confirm \Answered was NOT applied to UID 2.
    let chk = send_cmd(&mut reader, "F2", "UID FETCH 2 (FLAGS)").await;
    assert!(!chk.join("").contains("\\Answered"));

    // UID STORE 1 (UNCHANGEDSINCE <initial_modseq>) succeeds because UID 1 <= initial_modseq.
    let ok_store = send_cmd(
        &mut reader,
        "ST3",
        &format!(r#"UID STORE 1 (UNCHANGEDSINCE {initial_modseq}) +FLAGS.SILENT (\Answered)"#),
    )
    .await;
    assert!(
        ok_store
            .iter()
            .any(|l| l.contains("UID 1") && l.contains("MODSEQ (")),
        "RFC 7162 .SILENT + UNCHANGEDSINCE must return MODSEQ, got {ok_store:?}"
    );
    assert!(!ok_store.last().unwrap().contains("[MODIFIED"));

    // Mark UID 3 \Deleted and EXPUNGE -> with QRESYNC enabled, emits `* VANISHED 3` instead of EXPUNGE!
    let before_expunge_modseq = store.current_history_id().await.unwrap();
    let _ = send_cmd(&mut reader, "ST4", r#"UID STORE 3 +FLAGS (\Deleted)"#).await;
    let exp = send_cmd(&mut reader, "EX1", "EXPUNGE").await;
    assert!(
        exp.iter().any(|l| l.trim() == "* VANISHED 3"),
        "expected * VANISHED 3 with QRESYNC enabled, got {exp:?}"
    );
    assert!(
        !exp.iter()
            .any(|l| l.starts_with("* ") && l.contains(" EXPUNGE")),
        "expected no untagged EXPUNGE with QRESYNC enabled, got {exp:?}"
    );

    // UID FETCH 1:* (FLAGS) (CHANGEDSINCE <before_expunge_modseq> VANISHED) emits * VANISHED (EARLIER) 3
    let vf = send_cmd(
        &mut reader,
        "F3",
        &format!("UID FETCH 1:* (FLAGS) (CHANGEDSINCE {before_expunge_modseq} VANISHED)"),
    )
    .await;
    assert!(
        vf.iter().any(|l| l.trim() == "* VANISHED (EARLIER) 3"),
        "expected * VANISHED (EARLIER) 3, got {vf:?}"
    );

    // Non-UID FETCH with VANISHED must be rejected with BAD.
    let bad_vf = send_cmd(
        &mut reader,
        "F4",
        &format!("FETCH 1:* (FLAGS) (CHANGEDSINCE {before_expunge_modseq} VANISHED)"),
    )
    .await;
    assert!(bad_vf.last().unwrap().starts_with("F4 BAD"));

    // Re-SELECT INBOX with QRESYNC (<uid_validity> <initial_modseq>) emits:
    //   * OK [CLOSED] ...
    //   * VANISHED (EARLIER) 3
    //   * FETCH for UID 1 and UID 2 (both modified after initial_modseq)
    let qsel = send_cmd(
        &mut reader,
        "Q1",
        &format!("SELECT INBOX (QRESYNC ({uid_validity} {initial_modseq}))"),
    )
    .await;
    assert!(
        qsel.iter().any(|l| l.contains("[CLOSED]")),
        "expected [CLOSED], got {qsel:?}"
    );
    assert!(
        qsel.iter().any(|l| l.trim() == "* VANISHED (EARLIER) 3"),
        "expected * VANISHED (EARLIER) 3 in QRESYNC SELECT, got {qsel:?}"
    );
    assert!(
        qsel.iter()
            .any(|l| l.contains("FETCH (UID 1") && l.contains("MODSEQ (")),
        "expected UID 1 FETCH in QRESYNC SELECT, got {qsel:?}"
    );
    assert!(
        qsel.iter()
            .any(|l| l.contains("FETCH (UID 2") && l.contains("MODSEQ (")),
        "expected UID 2 FETCH in QRESYNC SELECT, got {qsel:?}"
    );

    // QRESYNC with mismatched UIDVALIDITY must ignore QRESYNC and emit NO VANISHED / FETCH.
    let qmismatch = send_cmd(
        &mut reader,
        "Q2",
        &format!(
            "SELECT INBOX (QRESYNC ({} {initial_modseq}))",
            uid_validity + 999
        ),
    )
    .await;
    assert!(!qmismatch.iter().any(|l| l.contains("VANISHED")));
    assert!(!qmismatch.iter().any(|l| l.contains(" FETCH ")));
    assert!(qmismatch.last().unwrap().starts_with("Q2 OK"));

    let _ = send_cmd(&mut reader, "BYE1", "LOGOUT").await;
    let _ = shutdown_tx.send(true);
}
