//! Comprehensive unit & HTTP integration tests for Gmail REST API v1, uploads, batching,
//! `?fields=` projection, settings, watch/stop, events, CORS, and body limits.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::Utc;
use http_body_util::BodyExt;
use tower::ServiceExt;

use crate::{
    AppState,
    config::Config,
    error::{AppError, AppResult},
    events::MailEvent,
    gmail::{query::QueryParams, upload::parse_multipart_parts},
    mime,
    models::{
        AttachmentMeta, AutoForwarding, ImapSettings, LABEL_DRAFT, LABEL_INBOX, LABEL_SENT,
        LABEL_TRASH, LABEL_UNREAD, PopSettings, Profile, ResendReceivedAttachment,
        ResendReceivedEmail, ResendSendEmailRequest, ResendSendEmailResponse, SendAs,
        VacationSettings,
    },
    resend::ResendClient,
    storage::{
        AiMessagePage, AiSearchQuery, AiThreadPage, AiThreadQuery, DraftListPage,
        HistoryEventKind, HistoryListPage, HistoryListQuery, ImapMailboxInfo, ImapMessageEntry,
        MailStore, MessageListPage, MessageListQuery, NewLabelInput, NewMessageInput,
        StoredAttachment, StoredDraft, StoredHistoryEntry, StoredLabel, StoredMessage,
        StoredThreadDetail, SyncState, ThreadListPage, TriagePatch, TriageResult,
        UpdateLabelInput, UpsertOutcome, UserSettings, WatchSubscription,
    },
};

#[derive(Default)]
struct MockResend {
    sent: Mutex<Vec<ResendSendEmailRequest>>,
}

#[async_trait]
impl ResendClient for MockResend {
    async fn send_email(
        &self,
        req: &ResendSendEmailRequest,
        _idempotency_key: Option<&str>,
    ) -> AppResult<ResendSendEmailResponse> {
        self.sent.lock().unwrap().push(req.clone());
        Ok(ResendSendEmailResponse {
            id: format!("re_mock_{}", self.sent.lock().unwrap().len()),
        })
    }
    async fn get_received_email(&self, _id: &str) -> AppResult<ResendReceivedEmail> {
        Err(AppError::NotFound("not found".into()))
    }
    async fn list_received_attachments(
        &self,
        _id: &str,
    ) -> AppResult<Vec<ResendReceivedAttachment>> {
        Ok(Vec::new())
    }
    async fn download_bytes(&self, _url: &str) -> AppResult<Vec<u8>> {
        Ok(Vec::new())
    }
}

struct MockStore {
    inner: Mutex<MockStoreState>,
}

struct MockStoreState {
    next_id: u64,
    history_id: u64,
    messages: Vec<StoredMessage>,
    attachments: Vec<StoredAttachment>,
    labels: Vec<StoredLabel>,
    drafts: Vec<StoredDraft>,
    history: Vec<StoredHistoryEntry>,
    watch: Option<WatchSubscription>,
    settings: UserSettings,
}

impl MockStore {
    fn new(email: &str) -> Self {
        let system_labels = [
            LABEL_INBOX,
            LABEL_SENT,
            LABEL_DRAFT,
            LABEL_TRASH,
            LABEL_UNREAD,
        ]
        .into_iter()
        .map(|id| StoredLabel {
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
        })
        .collect();
        Self {
            inner: Mutex::new(MockStoreState {
                next_id: 1,
                history_id: 10,
                messages: Vec::new(),
                attachments: Vec::new(),
                labels: system_labels,
                drafts: Vec::new(),
                history: Vec::new(),
                watch: None,
                settings: UserSettings::default_for_email(email),
            }),
        }
    }
}

#[async_trait]
impl MailStore for MockStore {
    async fn get_profile(&self, email_address: &str) -> AppResult<Profile> {
        let s = self.inner.lock().unwrap();
        Ok(Profile {
            email_address: email_address.to_string(),
            messages_total: s.messages.len() as i32,
            threads_total: s.messages.len() as i32,
            history_id: s.history_id.to_string(),
        })
    }
    async fn current_history_id(&self) -> AppResult<u64> {
        Ok(self.inner.lock().unwrap().history_id)
    }
    async fn list_history(&self, query: &HistoryListQuery) -> AppResult<HistoryListPage> {
        let s = self.inner.lock().unwrap();
        let entries: Vec<_> = s
            .history
            .iter()
            .filter(|e| e.history_id > query.start_history_id)
            .filter(|e| query.history_types.is_empty() || query.history_types.contains(&e.kind))
            .filter(|e| {
                query
                    .label_id
                    .as_ref()
                    .is_none_or(|lid| e.label_ids.contains(lid))
            })
            .take(query.max_results)
            .cloned()
            .collect();
        Ok(HistoryListPage {
            entries,
            next_page_token: None,
            current_history_id: s.history_id,
        })
    }
    async fn insert_message(&self, input: NewMessageInput) -> AppResult<StoredMessage> {
        let mut s = self.inner.lock().unwrap();
        let id = input.id.unwrap_or_else(|| {
            let n = s.next_id;
            s.next_id += 1;
            format!("msg_{n}")
        });
        let thread_id = input.thread_id.unwrap_or_else(|| format!("thr_{id}"));
        s.history_id += 1;
        let hid = s.history_id;
        for (idx, att) in input.attachments.iter().enumerate() {
            s.attachments.push(StoredAttachment {
                id: format!("att_{id}_{idx}"),
                message_id: id.clone(),
                part_id: att.part_id.clone(),
                filename: att.filename.clone(),
                content_type: att.content_type.clone(),
                content_id: att.content_id.clone(),
                size_bytes: att.data.len() as u64,
                data: att.data.clone(),
            });
        }
        let stored = StoredMessage {
            id: id.clone(),
            thread_id: thread_id.clone(),
            label_ids: input.label_ids.clone(),
            size_estimate: input.raw_rfc2822.len() as i32,
            raw_rfc2822: input.raw_rfc2822,
            snippet: input.snippet,
            history_id: hid,
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
            all_mail_uid: s.next_id as u32,
            is_answered: input.is_answered,
            is_deleted: input.is_deleted,
        };
        s.history.push(StoredHistoryEntry {
            history_id: hid,
            kind: HistoryEventKind::MessageAdded,
            message_id: id,
            thread_id,
            label_ids: input.label_ids,
        });
        s.messages.push(stored.clone());
        Ok(stored)
    }
    async fn get_message(&self, id: &str) -> AppResult<Option<StoredMessage>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .messages
            .iter()
            .find(|m| m.id == id)
            .cloned())
    }
    async fn list_messages(&self, query: &MessageListQuery) -> AppResult<MessageListPage> {
        let s = self.inner.lock().unwrap();
        let msgs: Vec<_> = s
            .messages
            .iter()
            .filter(|m| {
                query.label_ids.is_empty()
                    || query.label_ids.iter().all(|l| m.label_ids.contains(l))
            })
            .take(query.max_results)
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
        let mut s = self.inner.lock().unwrap();
        s.history_id += 1;
        let hid = s.history_id;
        let msg = s
            .messages
            .iter_mut()
            .find(|m| m.id == id)
            .ok_or_else(|| AppError::NotFound(format!("Message '{id}' not found")))?;
        for l in add_labels {
            if !msg.label_ids.contains(l) {
                msg.label_ids.push(l.clone());
            }
        }
        msg.label_ids.retain(|l| !remove_labels.contains(l));
        msg.history_id = hid;
        let cloned = msg.clone();
        if !add_labels.is_empty() {
            s.history.push(StoredHistoryEntry {
                history_id: hid,
                kind: HistoryEventKind::LabelAdded,
                message_id: cloned.id.clone(),
                thread_id: cloned.thread_id.clone(),
                label_ids: add_labels.to_vec(),
            });
        }
        if !remove_labels.is_empty() {
            s.history.push(StoredHistoryEntry {
                history_id: hid,
                kind: HistoryEventKind::LabelRemoved,
                message_id: cloned.id.clone(),
                thread_id: cloned.thread_id.clone(),
                label_ids: remove_labels.to_vec(),
            });
        }
        Ok(cloned)
    }
    async fn batch_modify_labels(
        &self,
        ids: &[String],
        add_labels: &[String],
        remove_labels: &[String],
    ) -> AppResult<()> {
        for id in ids {
            let _ = self
                .modify_message_labels(id, add_labels, remove_labels)
                .await?;
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
        let mut s = self.inner.lock().unwrap();
        let before = s.messages.len();
        if let Some(m) = s.messages.iter().find(|m| m.id == id).cloned() {
            s.history_id += 1;
            let hid = s.history_id;
            s.history.push(StoredHistoryEntry {
                history_id: hid,
                kind: HistoryEventKind::MessageDeleted,
                message_id: m.id,
                thread_id: m.thread_id,
                label_ids: m.label_ids,
            });
        }
        s.messages.retain(|m| m.id != id);
        s.attachments.retain(|a| a.message_id != id);
        Ok(s.messages.len() < before)
    }
    async fn batch_delete_messages(&self, ids: &[String]) -> AppResult<()> {
        let mut s = self.inner.lock().unwrap();
        s.messages.retain(|m| !ids.contains(&m.id));
        s.attachments.retain(|a| !ids.contains(&a.message_id));
        Ok(())
    }
    async fn get_attachment(
        &self,
        message_id: &str,
        attachment_id: &str,
    ) -> AppResult<Option<StoredAttachment>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .attachments
            .iter()
            .find(|a| a.message_id == message_id && a.id == attachment_id)
            .cloned())
    }
    async fn list_attachment_meta(&self, message_id: &str) -> AppResult<Vec<AttachmentMeta>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .attachments
            .iter()
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
        let s = self.inner.lock().unwrap();
        let mut seen = Vec::new();
        let mut threads = Vec::new();
        for m in &s.messages {
            if !seen.contains(&m.thread_id) {
                seen.push(m.thread_id.clone());
                let t_msgs: Vec<_> = s
                    .messages
                    .iter()
                    .filter(|x| x.thread_id == m.thread_id)
                    .cloned()
                    .collect();
                threads.push(StoredThreadDetail {
                    id: m.thread_id.clone(),
                    snippet: m.snippet.clone(),
                    history_id: t_msgs.last().map(|x| x.history_id).unwrap_or(m.history_id),
                    messages: t_msgs,
                });
            }
        }
        let est = threads.len() as u32;
        Ok(ThreadListPage {
            threads,
            next_page_token: None,
            result_size_estimate: est,
        })
    }
    async fn get_thread(&self, thread_id: &str) -> AppResult<Option<StoredThreadDetail>> {
        let s = self.inner.lock().unwrap();
        let msgs: Vec<_> = s
            .messages
            .iter()
            .filter(|m| m.thread_id == thread_id)
            .cloned()
            .collect();
        if msgs.is_empty() {
            return Ok(None);
        }
        Ok(Some(StoredThreadDetail {
            id: thread_id.to_string(),
            snippet: msgs[0].snippet.clone(),
            history_id: msgs.last().map(|m| m.history_id).unwrap_or(s.history_id),
            messages: msgs,
        }))
    }
    async fn modify_thread_labels(
        &self,
        thread_id: &str,
        add_labels: &[String],
        remove_labels: &[String],
    ) -> AppResult<StoredThreadDetail> {
        let ids: Vec<String> = {
            let s = self.inner.lock().unwrap();
            s.messages
                .iter()
                .filter(|m| m.thread_id == thread_id)
                .map(|m| m.id.clone())
                .collect()
        };
        if ids.is_empty() {
            return Err(AppError::NotFound(format!("Thread '{thread_id}' not found")));
        }
        for id in ids {
            self.modify_message_labels(&id, add_labels, remove_labels)
                .await?;
        }
        self.get_thread(thread_id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Thread '{thread_id}' not found")))
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
        let mut s = self.inner.lock().unwrap();
        let before = s.messages.len();
        s.messages.retain(|m| m.thread_id != thread_id);
        Ok(s.messages.len() < before)
    }
    async fn list_labels(&self) -> AppResult<Vec<StoredLabel>> {
        Ok(self.inner.lock().unwrap().labels.clone())
    }
    async fn get_label(&self, id: &str) -> AppResult<Option<StoredLabel>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .labels
            .iter()
            .find(|l| l.id == id)
            .cloned())
    }
    async fn create_label(&self, input: NewLabelInput) -> AppResult<StoredLabel> {
        let mut s = self.inner.lock().unwrap();
        let id = format!("Label_{}", s.next_id);
        s.next_id += 1;
        let lbl = StoredLabel {
            id,
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
        s.labels.push(lbl.clone());
        Ok(lbl)
    }
    async fn update_label(
        &self,
        id: &str,
        input: UpdateLabelInput,
        full_replace: bool,
    ) -> AppResult<StoredLabel> {
        let mut s = self.inner.lock().unwrap();
        let lbl = s
            .labels
            .iter_mut()
            .find(|l| l.id == id)
            .ok_or_else(|| AppError::NotFound(format!("Label '{id}' not found")))?;
        if let Some(name) = input.name {
            lbl.name = name;
        }
        if full_replace {
            lbl.message_list_visibility = input.message_list_visibility;
            lbl.label_list_visibility = input.label_list_visibility;
            lbl.color = input.color;
        } else {
            if input.message_list_visibility.is_some() {
                lbl.message_list_visibility = input.message_list_visibility;
            }
            if input.label_list_visibility.is_some() {
                lbl.label_list_visibility = input.label_list_visibility;
            }
            if input.color.is_some() {
                lbl.color = input.color;
            }
        }
        Ok(lbl.clone())
    }
    async fn delete_label(&self, id: &str) -> AppResult<()> {
        let mut s = self.inner.lock().unwrap();
        let before = s.labels.len();
        s.labels.retain(|l| l.id != id);
        if s.labels.len() == before {
            return Err(AppError::NotFound(format!("Label '{id}' not found")));
        }
        Ok(())
    }
    async fn upsert_upstream_label(&self, input: NewLabelInput) -> AppResult<StoredLabel> {
        self.create_label(input).await
    }
    async fn list_drafts(&self, _query: &MessageListQuery) -> AppResult<DraftListPage> {
        let s = self.inner.lock().unwrap();
        let est = s.drafts.len() as u32;
        Ok(DraftListPage {
            drafts: s.drafts.clone(),
            next_page_token: None,
            result_size_estimate: est,
        })
    }
    async fn get_draft(&self, id: &str) -> AppResult<Option<StoredDraft>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .drafts
            .iter()
            .find(|d| d.id == id)
            .cloned())
    }
    async fn create_draft(&self, message: NewMessageInput) -> AppResult<StoredDraft> {
        let msg = self.insert_message(message).await?;
        let mut s = self.inner.lock().unwrap();
        let id = format!("r_{}", s.next_id);
        s.next_id += 1;
        let draft = StoredDraft {
            id,
            message: msg,
            updated_at: Utc::now(),
        };
        s.drafts.push(draft.clone());
        Ok(draft)
    }
    async fn update_draft(
        &self,
        draft_id: &str,
        message: NewMessageInput,
    ) -> AppResult<StoredDraft> {
        let msg = self.insert_message(message).await?;
        let mut s = self.inner.lock().unwrap();
        let draft = s
            .drafts
            .iter_mut()
            .find(|d| d.id == draft_id)
            .ok_or_else(|| AppError::NotFound(format!("Draft '{draft_id}' not found")))?;
        draft.message = msg;
        draft.updated_at = Utc::now();
        Ok(draft.clone())
    }
    async fn delete_draft(&self, draft_id: &str) -> AppResult<bool> {
        let mut s = self.inner.lock().unwrap();
        let before = s.drafts.len();
        s.drafts.retain(|d| d.id != draft_id);
        Ok(s.drafts.len() < before)
    }
    async fn search_messages_ai(&self, _q: &AiSearchQuery) -> AppResult<AiMessagePage> {
        Ok(AiMessagePage {
            messages: Vec::new(),
            next_cursor: None,
            has_more: false,
        })
    }
    async fn list_thread_summaries(&self, _q: &AiThreadQuery) -> AppResult<AiThreadPage> {
        Ok(AiThreadPage {
            threads: Vec::new(),
            next_cursor: None,
            has_more: false,
        })
    }
    async fn triage_thread(&self, tid: &str, _p: &TriagePatch) -> AppResult<TriageResult> {
        Ok(TriageResult {
            thread_id: tid.to_string(),
            affected_message_ids: Vec::new(),
            labels: Vec::new(),
        })
    }
    async fn find_message_by_resend_id(&self, _id: &str) -> AppResult<Option<StoredMessage>> {
        Ok(None)
    }
    async fn find_message_by_rfc_message_id(&self, _id: &str) -> AppResult<Option<StoredMessage>> {
        Ok(None)
    }
    async fn record_delivery_status(
        &self,
        _id: &str,
        _status: &str,
    ) -> AppResult<Option<StoredMessage>> {
        Ok(None)
    }
    async fn imap_list_mailboxes(&self) -> AppResult<Vec<ImapMailboxInfo>> {
        Ok(Vec::new())
    }
    async fn imap_mailbox_info(&self, _name: &str) -> AppResult<Option<ImapMailboxInfo>> {
        Ok(None)
    }
    async fn imap_list_messages(&self, _name: &str) -> AppResult<Vec<ImapMessageEntry>> {
        Ok(Vec::new())
    }
    async fn imap_set_flags(
        &self,
        id: &str,
        _seen: bool,
        _flagged: bool,
        _draft: bool,
        _answered: bool,
        _deleted: bool,
    ) -> AppResult<StoredMessage> {
        self.get_message(id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Message '{id}' not found")))
    }
    async fn imap_expunge(&self, _name: &str) -> AppResult<Vec<u32>> {
        Ok(Vec::new())
    }
    async fn imap_copy_or_move(
        &self,
        _src: &str,
        _dst: &str,
        _ids: &[String],
        _is_move: bool,
    ) -> AppResult<Vec<(u32, u32)>> {
        Ok(Vec::new())
    }
    async fn imap_append(
        &self,
        _mailbox: &str,
        input: NewMessageInput,
    ) -> AppResult<(u32, u32, StoredMessage)> {
        let msg = self.insert_message(input).await?;
        Ok((1, 1, msg))
    }
    async fn upsert_synced_message(&self, input: NewMessageInput) -> AppResult<UpsertOutcome> {
        let msg = self.insert_message(input).await?;
        Ok(UpsertOutcome {
            kind: crate::storage::UpsertOutcomeKind::Inserted,
            message: msg,
        })
    }
    async fn find_message_by_upstream_id(&self, _id: &str) -> AppResult<Option<StoredMessage>> {
        Ok(None)
    }
    async fn delete_message_by_upstream_id(&self, _id: &str) -> AppResult<Option<StoredMessage>> {
        Ok(None)
    }
    async fn get_sync_state(&self, _key: &str) -> AppResult<Option<SyncState>> {
        Ok(None)
    }
    async fn save_sync_state(&self, _state: SyncState) -> AppResult<()> {
        Ok(())
    }
    async fn list_sync_states(&self) -> AppResult<Vec<SyncState>> {
        Ok(Vec::new())
    }
    async fn set_watch(&self, watch: WatchSubscription) -> AppResult<WatchSubscription> {
        self.inner.lock().unwrap().watch = Some(watch.clone());
        Ok(watch)
    }
    async fn get_watch(&self) -> AppResult<Option<WatchSubscription>> {
        Ok(self.inner.lock().unwrap().watch.clone())
    }
    async fn clear_watch(&self) -> AppResult<()> {
        self.inner.lock().unwrap().watch = None;
        Ok(())
    }
    async fn get_settings(&self) -> AppResult<UserSettings> {
        Ok(self.inner.lock().unwrap().settings.clone())
    }
    async fn save_settings(&self, settings: UserSettings) -> AppResult<UserSettings> {
        self.inner.lock().unwrap().settings = settings.clone();
        Ok(settings)
    }
}

fn test_app_with_config(cfg: Config) -> (AppState, Arc<MockResend>, Router) {
    let store = Arc::new(MockStore::new(&cfg.user_email));
    let resend = Arc::new(MockResend::default());
    let state = AppState::with_backends(cfg, store, resend.clone());
    let router = crate::server::build_router(state.clone());
    (state, resend, router)
}

fn test_app() -> (AppState, Arc<MockResend>, Router) {
    test_app_with_config(Config::for_test())
}

async fn json_body(res: axum::response::Response) -> serde_json::Value {
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn sample_rfc2822(subject: &str) -> Vec<u8> {
    format!(
        "From: Agent <agent@example.com>\r\nTo: Bob <bob@example.com>\r\nSubject: {subject}\r\nDate: Wed, 25 Nov 2026 10:00:00 +0000\r\nMessage-ID: <test-1@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello Bob, this is the email body."
    )
    .into_bytes()
}

fn sample_rfc2822_with_attachment() -> Vec<u8> {
    concat!(
        "From: Alice <alice@example.com>\r\n",
        "To: Agent <agent@example.com>\r\n",
        "Subject: With Attachment\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=\"attbound\"\r\n",
        "\r\n",
        "--attbound\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "See attached file.\r\n",
        "--attbound\r\n",
        "Content-Type: text/plain; name=\"note.txt\"\r\n",
        "Content-Disposition: attachment; filename=\"note.txt\"\r\n",
        "\r\n",
        "ATTACHMENT_DATA_123\r\n",
        "--attbound--\r\n"
    )
    .as_bytes()
    .to_vec()
}

#[test]
fn query_params_repeatable_and_validation() {
    let q = QueryParams::from_raw(Some(
        "labelIds=INBOX&labelIds=UNREAD&maxResults=25&includeSpamTrash=true&metadataHeaders=From&metadataHeaders=Subject&historyTypes=messageAdded&historyTypes=labelAdded&startHistoryId=42",
    ));
    let list = q.parse_message_list_query().unwrap();
    assert_eq!(list.label_ids, vec!["INBOX", "UNREAD"]);
    assert_eq!(list.max_results, 25);
    assert!(list.include_spam_trash);
    assert_eq!(q.metadata_headers(), vec!["From", "Subject"]);

    let hist = q.parse_history_list_query().unwrap();
    assert_eq!(hist.start_history_id, 42);
    assert_eq!(
        hist.history_types,
        vec![HistoryEventKind::MessageAdded, HistoryEventKind::LabelAdded]
    );
}

#[test]
fn multipart_parser_handles_mixed_and_related() {
    let raw = concat!(
        "--b123\r\n",
        "Content-Type: application/json\r\n",
        "\r\n",
        "{\"threadId\":\"t1\"}\r\n",
        "--b123\r\n",
        "Content-Type: message/rfc822\r\n",
        "\r\n",
        "From: a@b.com\r\nSubject: Hi\r\n\r\nBody\r\n",
        "--b123--\r\n"
    );
    let parts =
        parse_multipart_parts("multipart/related; boundary=\"b123\"", raw.as_bytes()).unwrap();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].header("content-type"), Some("application/json"));
    assert_eq!(parts[0].body, b"{\"threadId\":\"t1\"}");
    assert_eq!(parts[1].header("content-type"), Some("message/rfc822"));
    assert_eq!(parts[1].body, b"From: a@b.com\r\nSubject: Hi\r\n\r\nBody");
}

#[tokio::test]
async fn profile_health_readyz_and_user_id_enforcement() {
    let (_state, _resend, app) = test_app();

    let res = app
        .clone()
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = app
        .clone()
        .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let ready = json_body(res).await;
    assert_eq!(ready["status"], "ready");

    // GET /profile with ?fields= and alt=json
    let res = app
        .clone()
        .oneshot(
            Request::get("/gmail/v1/users/me/profile?alt=json&fields=emailAddress,historyId")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let prof = json_body(res).await;
    assert_eq!(prof["emailAddress"], "agent@example.com");
    assert_eq!(prof["historyId"], "10");
    assert!(prof.get("messagesTotal").is_none());

    // Unsupported alt returns 400
    let res = app
        .clone()
        .oneshot(
            Request::get("/gmail/v1/users/me/profile?alt=xml")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Delegation denied for other user
    let res = app
        .oneshot(
            Request::get("/gmail/v1/users/other@example.com/profile")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn messages_send_json_media_multipart_and_events() {
    let (state, resend, app) = test_app();
    let mut rx = state.events.subscribe();

    // 1. JSON send
    let raw_b64 = mime::encode_base64url(&sample_rfc2822("JSON Send"));
    let res = app
        .clone()
        .oneshot(
            Request::post("/gmail/v1/users/me/messages/send")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(r#"{{"raw":"{raw_b64}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let sent1 = json_body(res).await;
    assert!(sent1["labelIds"].as_array().unwrap().contains(&serde_json::json!("SENT")));
    let ev = rx.try_recv().unwrap();
    assert!(matches!(ev.event, MailEvent::MessageSent { .. }));

    // 2. uploadType=media send
    let res = app
        .clone()
        .oneshot(
            Request::post("/upload/gmail/v1/users/me/messages/send?uploadType=media")
                .header(header::CONTENT_TYPE, "message/rfc822")
                .body(Body::from(sample_rfc2822("Media Send")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let _ = rx.try_recv().unwrap();

    // 3. uploadType=multipart send with explicit threadId
    let mp_body = format!(
        "--mp_b\r\nContent-Type: application/json\r\n\r\n{{\"threadId\":\"thr_custom\"}}\r\n--mp_b\r\nContent-Type: message/rfc822\r\n\r\n{}\r\n--mp_b--\r\n",
        String::from_utf8(sample_rfc2822("Multipart Send")).unwrap()
    );
    let res = app
        .oneshot(
            Request::post("/upload/gmail/v1/users/me/messages/send?uploadType=multipart")
                .header(header::CONTENT_TYPE, "multipart/related; boundary=mp_b")
                .body(Body::from(mp_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let sent3 = json_body(res).await;
    assert_eq!(sent3["threadId"], "thr_custom");

    assert_eq!(resend.sent.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn messages_insert_import_formats_attachments_modify_trash_delete_and_history() {
    let (state, _resend, app) = test_app();

    // Import message with attachment
    let raw_att = mime::encode_base64url(&sample_rfc2822_with_attachment());
    let res = app
        .clone()
        .oneshot(
            Request::post("/gmail/v1/users/me/messages/import?internalDateSource=receivedTime&neverMarkSpam=true")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(r#"{{"raw":"{raw_att}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let imported = json_body(res).await;
    let msg_id = imported["id"].as_str().unwrap().to_string();

    // GET format=full should expose attachmentId on the attachment part
    let res = app
        .clone()
        .oneshot(
            Request::get(format!("/gmail/v1/users/me/messages/{msg_id}?format=full"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let full = json_body(res).await;
    let parts = full["payload"]["parts"].as_array().unwrap();
    let att_id = parts[1]["body"]["attachmentId"].as_str().unwrap().to_string();

    // GET attachment bytes
    let res = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/gmail/v1/users/me/messages/{msg_id}/attachments/{att_id}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let att_body = json_body(res).await;
    let decoded = mime::decode_base64url(att_body["data"].as_str().unwrap()).unwrap();
    assert_eq!(decoded, b"ATTACHMENT_DATA_123");

    // GET format=metadata with repeatable metadataHeaders
    let res = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/gmail/v1/users/me/messages/{msg_id}?format=metadata&metadataHeaders=From&metadataHeaders=Subject"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let meta = json_body(res).await;
    let hdrs = meta["payload"]["headers"].as_array().unwrap();
    assert_eq!(hdrs.len(), 2);

    // GET format=raw
    let res = app
        .clone()
        .oneshot(
            Request::get(format!("/gmail/v1/users/me/messages/{msg_id}?format=raw"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let raw_msg = json_body(res).await;
    assert!(raw_msg.get("raw").is_some());
    assert!(raw_msg.get("payload").is_none());

    // Modify, trash, untrash
    let res = app
        .clone()
        .oneshot(
            Request::post(format!("/gmail/v1/users/me/messages/{msg_id}/modify"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"addLabelIds":["STARRED"],"removeLabelIds":["UNREAD"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let modified = json_body(res).await;
    let labels: Vec<&str> = modified["labelIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(labels.contains(&"STARRED"));
    assert!(!labels.contains(&"UNREAD"));

    let res = app
        .clone()
        .oneshot(
            Request::post(format!("/gmail/v1/users/me/messages/{msg_id}/trash"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = app
        .clone()
        .oneshot(
            Request::post(format!("/gmail/v1/users/me/messages/{msg_id}/untrash"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // History list with startHistoryId & historyTypes
    let res = app
        .clone()
        .oneshot(
            Request::get(
                "/gmail/v1/users/me/history?startHistoryId=10&historyTypes=messageAdded&historyTypes=labelAdded",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let hist = json_body(res).await;
    assert!(!hist["history"].as_array().unwrap().is_empty());

    // Messages list with ?fields= projection
    let res = app
        .clone()
        .oneshot(
            Request::get("/gmail/v1/users/me/messages?fields=messages(id),resultSizeEstimate")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let listed = json_body(res).await;
    assert_eq!(listed["resultSizeEstimate"], 1);
    assert!(listed["messages"][0].get("id").is_some());
    assert!(listed["messages"][0].get("threadId").is_none());

    // batchModify & batchDelete
    let res = app
        .clone()
        .oneshot(
            Request::post("/gmail/v1/users/me/messages/batchModify")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(
                    r#"{{"ids":["{msg_id}"],"addLabelIds":["IMPORTANT"]}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let res = app
        .oneshot(
            Request::post("/gmail/v1/users/me/messages/batchDelete")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(r#"{{"ids":["{msg_id}"]}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert!(state.store.get_message(&msg_id).await.unwrap().is_none());
}

#[tokio::test]
async fn threads_and_drafts_full_lifecycle() {
    let (state, resend, app) = test_app();

    // Insert a message into a thread
    let raw_b64 = mime::encode_base64url(&sample_rfc2822("Thread msg"));
    let res = app
        .clone()
        .oneshot(
            Request::post("/gmail/v1/users/me/messages")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(
                    r#"{{"raw":"{raw_b64}","threadId":"thr_1","labelIds":["INBOX"]}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // List, get, modify, trash, untrash, delete thread
    let res = app
        .clone()
        .oneshot(
            Request::get("/gmail/v1/users/me/threads")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let list = json_body(res).await;
    assert_eq!(list["threads"][0]["id"], "thr_1");

    let res = app
        .clone()
        .oneshot(
            Request::post("/gmail/v1/users/me/threads/thr_1/modify")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"addLabelIds":["STARRED"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = app
        .clone()
        .oneshot(
            Request::delete("/gmail/v1/users/me/threads/thr_1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    // Draft create (uploadType=media), get, update, send by ID
    let res = app
        .clone()
        .oneshot(
            Request::post("/upload/gmail/v1/users/me/drafts?uploadType=media")
                .header(header::CONTENT_TYPE, "message/rfc822")
                .body(Body::from(sample_rfc2822("Draft v1")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let draft = json_body(res).await;
    let draft_id = draft["id"].as_str().unwrap().to_string();

    // Update draft via PUT
    let raw_v2 = mime::encode_base64url(&sample_rfc2822("Draft v2"));
    let res = app
        .clone()
        .oneshot(
            Request::put(format!("/gmail/v1/users/me/drafts/{draft_id}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(
                    r#"{{"message":{{"raw":"{raw_v2}"}}}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Send existing draft by ID
    let res = app
        .oneshot(
            Request::post("/gmail/v1/users/me/drafts/send")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(r#"{{"id":"{draft_id}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(state.store.get_draft(&draft_id).await.unwrap().is_none());
    assert_eq!(resend.sent.lock().unwrap().len(), 1);
    assert_eq!(resend.sent.lock().unwrap()[0].subject, "Draft v2");
}

#[tokio::test]
async fn labels_crud_and_list_omits_counts() {
    let (_state, _resend, app) = test_app();

    let res = app
        .clone()
        .oneshot(
            Request::get("/gmail/v1/users/me/labels")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let list = json_body(res).await;
    assert!(list["labels"][0].get("messagesTotal").is_none());

    let res = app
        .clone()
        .oneshot(
            Request::post("/gmail/v1/users/me/labels")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"name":"Projects"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let created = json_body(res).await;
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["name"], "Projects");
    assert!(created.get("messagesTotal").is_some());

    let res = app
        .clone()
        .oneshot(
            Request::patch(format!("/gmail/v1/users/me/labels/{id}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"name":"Work/Projects"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let patched = json_body(res).await;
    assert_eq!(patched["name"], "Work/Projects");

    let res = app
        .oneshot(
            Request::delete(format!("/gmail/v1/users/me/labels/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn watch_stop_and_all_settings_crud() {
    let (state, _resend, app) = test_app();

    // Watch with deprecated labelFilterAction
    let res = app
        .clone()
        .oneshot(
            Request::post("/gmail/v1/users/me/watch")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"topicName":"projects/p/topics/gmail","labelIds":["INBOX"],"labelFilterAction":"include"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let watch = json_body(res).await;
    assert_eq!(watch["historyId"], "10");
    assert!(watch["expiration"].as_str().unwrap().parse::<i64>().is_ok());
    assert!(state.store.get_watch().await.unwrap().is_some());

    // Stop watch (empty body allowed)
    let res = app
        .clone()
        .oneshot(
            Request::post("/gmail/v1/users/me/stop")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert!(state.store.get_watch().await.unwrap().is_none());

    // SendAs CRUD
    let alias = SendAs {
        send_as_email: "alias@example.com".to_string(),
        display_name: Some("Alias".to_string()),
        signature: Some("<p>Sig</p>".to_string()),
        ..Default::default()
    };
    let res = app
        .clone()
        .oneshot(
            Request::post("/gmail/v1/users/me/settings/sendAs")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&alias).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = app
        .clone()
        .oneshot(
            Request::patch("/gmail/v1/users/me/settings/sendAs/alias@example.com")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"displayName":"Updated Alias"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let updated = json_body(res).await;
    assert_eq!(updated["displayName"], "Updated Alias");
    assert_eq!(updated["signature"], "<p>Sig</p>");

    // Cannot delete primary sendAs
    let res = app
        .clone()
        .oneshot(
            Request::delete("/gmail/v1/users/me/settings/sendAs/agent@example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Can delete alias
    let res = app
        .clone()
        .oneshot(
            Request::delete("/gmail/v1/users/me/settings/sendAs/alias@example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    // Vacation, AutoForwarding, IMAP, POP PUT + GET
    let vac = VacationSettings {
        enable_auto_reply: Some(true),
        response_subject: Some("OOO".to_string()),
        response_body_plain_text: Some("Back Monday".to_string()),
        ..Default::default()
    };
    let res = app
        .clone()
        .oneshot(
            Request::put("/gmail/v1/users/me/settings/vacation")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&vac).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(json_body(res).await["responseSubject"], "OOO");

    let fwd = AutoForwarding {
        enabled: Some(true),
        email_address: Some("fwd@example.com".to_string()),
        disposition: Some("archive".to_string()),
    };
    let res = app
        .clone()
        .oneshot(
            Request::put("/gmail/v1/users/me/settings/autoForwarding")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&fwd).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(json_body(res).await["emailAddress"], "fwd@example.com");

    let imap = ImapSettings {
        enabled: Some(true),
        auto_expunge: Some(false),
        expunge_behavior: Some("trash".to_string()),
        max_folder_size: Some(1000),
    };
    let res = app
        .clone()
        .oneshot(
            Request::put("/gmail/v1/users/me/settings/imap")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&imap).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(json_body(res).await["maxFolderSize"], 1000);

    let pop = PopSettings {
        access_window: Some("allMail".to_string()),
        disposition: Some("markRead".to_string()),
    };
    let res = app
        .oneshot(
            Request::put("/gmail/v1/users/me/settings/pop")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&pop).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(json_body(res).await["accessWindow"], "allMail");
}

#[tokio::test]
async fn batch_gmail_v1_dispatches_fields_auth_and_isolates_part_errors() {
    let mut cfg = Config::for_test();
    cfg.auth_tokens = vec!["super-secret".to_string()];
    let (_state, _resend, app) = test_app_with_config(cfg);

    let batch_body = concat!(
        "--batch_req\r\n",
        "Content-Type: application/http\r\n",
        "Content-ID: <item1>\r\n",
        "\r\n",
        "GET /gmail/v1/users/me/profile?fields=emailAddress HTTP/1.1\r\n",
        "\r\n",
        "--batch_req\r\n",
        "Content-Type: application/http\r\n",
        "Content-ID: <item2>\r\n",
        "\r\n",
        "GET /gmail/v1/users/me/messages/does_not_exist HTTP/1.1\r\n",
        "\r\n",
        "--batch_req\r\n",
        "Content-Type: application/http\r\n",
        "Content-ID: <item3>\r\n",
        "\r\n",
        "POST /batch/gmail/v1 HTTP/1.1\r\n",
        "\r\n",
        "--batch_req--\r\n"
    );

    // Without auth -> 401
    let res = app
        .clone()
        .oneshot(
            Request::post("/batch/gmail/v1")
                .header(header::CONTENT_TYPE, "multipart/mixed; boundary=batch_req")
                .body(Body::from(batch_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // With outer Bearer auth -> 200 multipart/mixed
    let res = app
        .oneshot(
            Request::post("/batch/gmail/v1")
                .header(header::AUTHORIZATION, "Bearer super-secret")
                .header(header::CONTENT_TYPE, "multipart/mixed; boundary=batch_req")
                .body(Body::from(batch_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let ct = res
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(ct.starts_with("multipart/mixed; boundary="));

    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let parts = parse_multipart_parts(&ct, &bytes).unwrap();
    assert_eq!(parts.len(), 3);

    assert_eq!(parts[0].header("content-id"), Some("response-item1"));
    let p0_text = String::from_utf8_lossy(&parts[0].body);
    assert!(p0_text.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(p0_text.contains("\"emailAddress\":\"agent@example.com\""));
    assert!(!p0_text.contains("historyId"));

    assert_eq!(parts[1].header("content-id"), Some("response-item2"));
    let p1_text = String::from_utf8_lossy(&parts[1].body);
    assert!(p1_text.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(p1_text.contains("\"status\":\"NOT_FOUND\""));

    // Recursive batch rejected cleanly inside part 3
    assert_eq!(parts[2].header("content-id"), Some("response-item3"));
    let p2_text = String::from_utf8_lossy(&parts[2].body);
    assert!(p2_text.starts_with("HTTP/1.1 400 Bad Request\r\n"));
}

#[tokio::test]
async fn server_cors_and_body_limit_enforced() {
    let mut cfg = Config::for_test();
    cfg.cors_allow_origins = vec!["https://mail.example.com".to_string()];
    cfg.max_body_bytes = 64;
    let (_state, _resend, app) = test_app_with_config(cfg);

    let res = app
        .clone()
        .oneshot(
            Request::get("/healthz")
                .header(header::ORIGIN, "https://mail.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok()),
        Some("https://mail.example.com")
    );

    // Oversized body (> 64 bytes) -> 413 Payload Too Large
    let res = app
        .oneshot(
            Request::post("/gmail/v1/users/me/labels")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(vec![b'a'; 128]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
