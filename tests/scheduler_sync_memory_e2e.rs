//! Regression tests for Issue #60:
//! - Atomic scheduled send claiming and approval claiming across concurrent replicas
//! - OutboundPolicy re-evaluation and per-item error isolation in the scheduler
//! - Aggregate memory caps in ResumableUploadStore, /batch/gmail/v1, and POST /mcp
//! - Bidirectional sync concurrent-edit preservation, push-failure retry without echo loops,
//!   and mid-sync Gmail API HTTP 401 token refresh
//! - Upstream IMAP sync bounded UID SEARCH + batched UID FETCH, X-GM-THRID preservation,
//!   and network timeouts preventing sync_lock deadlocks
//! - External blob cleanup across Gmail delete paths, load_raw_rfc2822 in complete_send_draft,
//!   and current message labels in Gmail list_history

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64::Engine as _;
use chrono::Utc;
use serde_json::{Value, json};
use tokio::{
    net::TcpListener,
    sync::{Notify, watch},
};
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, header as wm_header, method, path, query_param},
};

use nogml::{
    AppState,
    ai::{
        safety::{OutboundCheck, OutboundDecision, OutboundPolicy},
        scheduler::process_due_scheduler_items,
    },
    blob::{BlobStore, FsBlobStore, attachment_blob_key, raw_message_blob_key},
    config::{Config, SyncMode},
    error::{AppError, AppResult},
    gmail::upload::ResumableUploadStore,
    imap::{mime_fmt::parse_raw_to_new_message_input, serve_plain_listener},
    models::{
        AttachmentMeta, LABEL_INBOX, LABEL_STARRED, LABEL_UNREAD, PolicyCheckResult, Profile,
        ThreadAnnotation, ThreadAnnotationPatch,
    },
    resend::HttpResendClient,
    server::build_router,
    storage::{
        AiMessagePage, AiSearchQuery, AiThreadPage, AiThreadQuery, ApprovalStatus, AuditLogEntry,
        AuditLogQuery, ContactInteraction, ContactPatch, ContactQuery, ContactRecord,
        DraftListPage, HistoryListPage, HistoryListQuery, IdempotencyRecord, ImapMailboxInfo,
        ImapMessageEntry, InboxRule, InboxRulePatch, MailStore, MemoryStore, MessageListPage,
        MessageListQuery, NewAttachmentInput, NewAuditLogEntry, NewInboxRule, NewLabelInput,
        NewMessageInput, NewPendingApprovalInput, NewScheduledSend, PendingApproval, ScheduledSend,
        ScheduledSendStatus, SnoozedThread, SqliteStore, StoredAttachment, StoredDraft,
        StoredLabel, StoredMessage, StoredThreadDetail, SyncState, ThreadListPage, TriagePatch,
        TriageResult, UpdateLabelInput, UpsertOutcome, UserSettings, WatchSubscription,
    },
    sync::{
        GmailImapSyncSource, LocalMutation, PullReport, PushReport, SyncRunOptions, SyncSource,
        ingest_synced_message, run_gmail_sync, run_sync_source,
    },
    transport::{MailTransport, OutboundMessage, SendOutcome, TransportCapabilities},
};

fn b64url(raw: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

#[derive(Clone)]
struct DelayedRecordingTransport {
    sent: Arc<Mutex<Vec<OutboundMessage>>>,
    delay: Duration,
}

impl DelayedRecordingTransport {
    fn new(delay: Duration) -> (Self, Arc<Mutex<Vec<OutboundMessage>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                sent: sent.clone(),
                delay,
            },
            sent,
        )
    }
}

#[async_trait]
impl MailTransport for DelayedRecordingTransport {
    fn name(&self) -> &'static str {
        "delayed-recording"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            provider: "delayed-recording".to_string(),
            supports_raw_mime: true,
            supports_scheduled_send: false,
            supports_idempotency_key: true,
            supports_inbound_webhooks: false,
            supports_delivery_webhooks: false,
            max_message_bytes: 40 * 1024 * 1024,
        }
    }

    async fn send(
        &self,
        msg: &OutboundMessage,
        _idempotency_key: Option<&str>,
    ) -> AppResult<SendOutcome> {
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        let mut guard = self.sent.lock().unwrap();
        guard.push(msg.clone());
        Ok(SendOutcome {
            provider: "delayed-recording".to_string(),
            provider_message_id: format!("prov_{}", guard.len()),
        })
    }
}

async fn http_req(
    app: &Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut builder = Request::builder().method(method).uri(uri);
    for &(k, v) in headers {
        builder = builder.header(k, v);
    }
    let req = builder.body(Body::from(body)).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap()
        .to_vec();
    (status, resp_headers, bytes)
}

async fn http_json(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let (headers, raw): (Vec<(&str, &str)>, Vec<u8>) = match body {
        Some(v) => (
            vec![("content-type", "application/json")],
            serde_json::to_vec(&v).unwrap(),
        ),
        None => (Vec::new(), Vec::new()),
    };
    let (status, _, bytes) = http_req(app, method, uri, &headers, raw).await;
    let parsed = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, parsed)
}

fn sample_outbound(from: &str, to: &str, subject: &str) -> OutboundMessage {
    OutboundMessage {
        from: from.to_string(),
        to: vec![to.to_string()],
        subject: subject.to_string(),
        text: Some(format!("Body for {subject}")),
        ..Default::default()
    }
}

// ============================================================================
// 1. Atomic Scheduled Sends & Approvals across Independent Replicas
// ============================================================================

#[tokio::test]
async fn concurrent_scheduler_replicas_send_scheduled_email_exactly_once() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("sched_race.db");

    let mut cfg = Config::for_test();
    cfg.db_path = db_path.clone();
    let store_a = Arc::new(SqliteStore::open(&db_path, &cfg.user_email).unwrap());
    let store_b = Arc::new(SqliteStore::open(&db_path, &cfg.user_email).unwrap());
    let (transport, sent_log) = DelayedRecordingTransport::new(Duration::from_millis(80));
    let transport = Arc::new(transport);
    let resend = Arc::new(HttpResendClient::from_config(&cfg));

    // Two completely independent AppState instances (separate in-memory `scheduled_in_flight` sets)
    let replica_a = AppState::with_backends(cfg.clone(), store_a.clone(), resend.clone())
        .with_transport(transport.clone());
    let replica_b = AppState::with_backends(cfg.clone(), store_b, resend).with_transport(transport);

    let now_ms = Utc::now().timestamp_millis();
    let sch = store_a
        .create_scheduled_send(&NewScheduledSend {
            id: Some("sch_atomic_race".to_string()),
            send_at_ms: now_ms - 1_000,
            outbound_message: sample_outbound(&cfg.user_email, "dest@example.com", "Race once"),
            reply_to_message_id: None,
            thread_id: None,
            created_at_ms: now_ms - 5_000,
        })
        .await
        .unwrap();

    let (rep_a, rep_b) = tokio::join!(
        process_due_scheduler_items(&replica_a, now_ms),
        process_due_scheduler_items(&replica_b, now_ms),
    );
    let rep_a = rep_a.unwrap();
    let rep_b = rep_b.unwrap();

    assert_eq!(
        rep_a.scheduled_sent + rep_b.scheduled_sent,
        1,
        "exactly one replica must send the scheduled email (a={rep_a:?}, b={rep_b:?})"
    );
    assert_eq!(
        sent_log.lock().unwrap().len(),
        1,
        "transport must be invoked exactly once across concurrent replicas"
    );

    let final_rec = store_a.get_scheduled_send(&sch.id).await.unwrap().unwrap();
    assert_eq!(final_rec.status, ScheduledSendStatus::Sent);
}

#[tokio::test]
async fn concurrent_approve_across_independent_replicas_sends_exactly_once() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("approve_race.db");

    let mut cfg = Config::for_test();
    cfg.db_path = db_path.clone();
    cfg.require_approval = true;

    let store_a = Arc::new(SqliteStore::open(&db_path, &cfg.user_email).unwrap());
    let store_b = Arc::new(SqliteStore::open(&db_path, &cfg.user_email).unwrap());
    let (transport, sent_log) = DelayedRecordingTransport::new(Duration::from_millis(80));
    let transport = Arc::new(transport);
    let resend = Arc::new(HttpResendClient::from_config(&cfg));

    // Two independent routers with separate `approval_in_flight` sets sharing the same SQLite DB.
    let app_a = build_router(
        AppState::with_backends(cfg.clone(), store_a.clone(), resend.clone())
            .with_transport(transport.clone()),
    );
    let app_b = build_router(
        AppState::with_backends(cfg.clone(), store_b, resend).with_transport(transport),
    );

    let now_ms = Utc::now().timestamp_millis();
    let apr = store_a
        .create_pending_approval(NewPendingApprovalInput {
            id: Some("apr_multi_node_1".to_string()),
            reason: "external recipient".to_string(),
            requester: None,
            outbound_message: sample_outbound(
                &cfg.user_email,
                "ext@partner.example",
                "Approve once",
            ),
            reply_to_message_id: None,
            thread_id: None,
            draft_id: None,
            created_at_ms: now_ms,
            expires_at_ms: now_ms + 3_600_000,
        })
        .await
        .unwrap();

    let uri = format!("/v1/approvals/{}/approve", apr.id);
    let ((s1, _), (s2, _)) = tokio::join!(
        http_json(&app_a, "POST", &uri, None),
        http_json(&app_b, "POST", &uri, None),
    );

    let statuses = [s1, s2];
    assert!(
        statuses.contains(&StatusCode::OK) && statuses.contains(&StatusCode::CONFLICT),
        "expected one 200 OK and one 409 Conflict across independent replicas, got {statuses:?}"
    );
    assert_eq!(
        sent_log.lock().unwrap().len(),
        1,
        "multi-node concurrent approvals must send at most once"
    );
}

// ============================================================================
// 2. OutboundPolicy Re-evaluation & Per-Item Error Isolation in Scheduler
// ============================================================================

struct ToggleOutboundPolicy {
    mode: Arc<Mutex<String>>, // "allow" | "deny" | "hold"
}

#[async_trait]
impl OutboundPolicy for ToggleOutboundPolicy {
    async fn evaluate(&self, _check: &OutboundCheck) -> AppResult<OutboundDecision> {
        match self.mode.lock().unwrap().as_str() {
            "deny" => Ok(OutboundDecision::Deny {
                code: "recipient_blocked".to_string(),
                reason: "Policy tightened after scheduling".to_string(),
                hint: None,
            }),
            "hold" => Ok(OutboundDecision::HoldForApproval {
                reason: "Approval now required".to_string(),
            }),
            _ => Ok(OutboundDecision::Allow),
        }
    }

    fn policy_checks(&self, _check: &OutboundCheck) -> Vec<PolicyCheckResult> {
        Vec::new()
    }
}

#[tokio::test]
async fn scheduler_reevaluates_outbound_policy_before_dispatch() {
    let cfg = Config::for_test();
    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let (transport, sent_log) = DelayedRecordingTransport::new(Duration::ZERO);
    let mode = Arc::new(Mutex::new("allow".to_string()));
    let policy = Arc::new(ToggleOutboundPolicy { mode: mode.clone() });
    let state = AppState::with_backends(
        cfg.clone(),
        store.clone(),
        Arc::new(HttpResendClient::from_config(&cfg)),
    )
    .with_transport(Arc::new(transport))
    .with_outbound_policy(policy);

    let now_ms = Utc::now().timestamp_millis();
    let sch_deny = store
        .create_scheduled_send(&NewScheduledSend {
            id: Some("sch_pol_deny".to_string()),
            send_at_ms: now_ms + 1_000,
            outbound_message: sample_outbound(&cfg.user_email, "blocked@example.com", "Deny me"),
            reply_to_message_id: None,
            thread_id: None,
            created_at_ms: now_ms,
        })
        .await
        .unwrap();

    // Tighten policy to Deny before send_at arrives
    *mode.lock().unwrap() = "deny".to_string();
    let rep1 = process_due_scheduler_items(&state, now_ms + 2_000)
        .await
        .unwrap();
    assert_eq!(rep1.scheduled_sent, 0);
    assert_eq!(rep1.scheduled_failed, 1);
    assert_eq!(sent_log.lock().unwrap().len(), 0);
    let rec_deny = store
        .get_scheduled_send(&sch_deny.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rec_deny.status, ScheduledSendStatus::Failed);
    assert!(
        rec_deny
            .last_error
            .as_deref()
            .unwrap_or("")
            .contains("outbound policy")
    );

    // Also verify HoldForApproval at dispatch time blocks sending
    let sch_hold = store
        .create_scheduled_send(&NewScheduledSend {
            id: Some("sch_pol_hold".to_string()),
            send_at_ms: now_ms + 3_000,
            outbound_message: sample_outbound(&cfg.user_email, "hold@example.com", "Hold me"),
            reply_to_message_id: None,
            thread_id: None,
            created_at_ms: now_ms,
        })
        .await
        .unwrap();
    *mode.lock().unwrap() = "hold".to_string();
    let rep2 = process_due_scheduler_items(&state, now_ms + 4_000)
        .await
        .unwrap();
    assert_eq!(rep2.scheduled_sent, 0);
    assert_eq!(rep2.scheduled_failed, 1);
    assert_eq!(sent_log.lock().unwrap().len(), 0);
    let rec_hold = store
        .get_scheduled_send(&sch_hold.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rec_hold.status, ScheduledSendStatus::Failed);
}

/// Wrapper MailStore that fails `insert_message` when subject == `fail_subject` to prove
/// per-item scheduler error isolation without starving remaining items or retrying forever.
struct FailingInsertStore {
    inner: Arc<dyn MailStore>,
    fail_subject: String,
}

#[async_trait]
impl MailStore for FailingInsertStore {
    fn mailbox_id(&self) -> &str {
        self.inner.mailbox_id()
    }
    fn for_mailbox(&self, mailbox_id: &str) -> Arc<dyn MailStore> {
        Arc::new(Self {
            inner: self.inner.for_mailbox(mailbox_id),
            fail_subject: self.fail_subject.clone(),
        })
    }
    async fn get_profile(&self, email_address: &str) -> AppResult<Profile> {
        self.inner.get_profile(email_address).await
    }
    async fn current_history_id(&self) -> AppResult<u64> {
        self.inner.current_history_id().await
    }
    async fn list_history(&self, query: &HistoryListQuery) -> AppResult<HistoryListPage> {
        self.inner.list_history(query).await
    }
    async fn insert_message(&self, input: NewMessageInput) -> AppResult<StoredMessage> {
        if input.subject == self.fail_subject {
            return Err(AppError::Storage(
                "simulated post-send DB failure".to_string(),
            ));
        }
        self.inner.insert_message(input).await
    }
    async fn get_message(&self, id: &str) -> AppResult<Option<StoredMessage>> {
        self.inner.get_message(id).await
    }
    async fn list_messages(&self, query: &MessageListQuery) -> AppResult<MessageListPage> {
        self.inner.list_messages(query).await
    }
    async fn modify_message_labels(
        &self,
        id: &str,
        add: &[String],
        rem: &[String],
    ) -> AppResult<StoredMessage> {
        self.inner.modify_message_labels(id, add, rem).await
    }
    async fn batch_modify_labels(
        &self,
        ids: &[String],
        add: &[String],
        rem: &[String],
    ) -> AppResult<()> {
        self.inner.batch_modify_labels(ids, add, rem).await
    }
    async fn trash_message(&self, id: &str) -> AppResult<StoredMessage> {
        self.inner.trash_message(id).await
    }
    async fn untrash_message(&self, id: &str) -> AppResult<StoredMessage> {
        self.inner.untrash_message(id).await
    }
    async fn delete_message(&self, id: &str) -> AppResult<bool> {
        self.inner.delete_message(id).await
    }
    async fn batch_delete_messages(&self, ids: &[String]) -> AppResult<()> {
        self.inner.batch_delete_messages(ids).await
    }
    async fn get_attachment(
        &self,
        message_id: &str,
        attachment_id: &str,
    ) -> AppResult<Option<StoredAttachment>> {
        self.inner.get_attachment(message_id, attachment_id).await
    }
    async fn list_attachment_meta(&self, message_id: &str) -> AppResult<Vec<AttachmentMeta>> {
        self.inner.list_attachment_meta(message_id).await
    }
    async fn list_threads(&self, query: &MessageListQuery) -> AppResult<ThreadListPage> {
        self.inner.list_threads(query).await
    }
    async fn get_thread(&self, thread_id: &str) -> AppResult<Option<StoredThreadDetail>> {
        self.inner.get_thread(thread_id).await
    }
    async fn modify_thread_labels(
        &self,
        thread_id: &str,
        add: &[String],
        rem: &[String],
    ) -> AppResult<StoredThreadDetail> {
        self.inner.modify_thread_labels(thread_id, add, rem).await
    }
    async fn trash_thread(&self, thread_id: &str) -> AppResult<StoredThreadDetail> {
        self.inner.trash_thread(thread_id).await
    }
    async fn untrash_thread(&self, thread_id: &str) -> AppResult<StoredThreadDetail> {
        self.inner.untrash_thread(thread_id).await
    }
    async fn delete_thread(&self, thread_id: &str) -> AppResult<bool> {
        self.inner.delete_thread(thread_id).await
    }
    async fn list_labels(&self) -> AppResult<Vec<StoredLabel>> {
        self.inner.list_labels().await
    }
    async fn get_label(&self, id: &str) -> AppResult<Option<StoredLabel>> {
        self.inner.get_label(id).await
    }
    async fn create_label(&self, input: NewLabelInput) -> AppResult<StoredLabel> {
        self.inner.create_label(input).await
    }
    async fn update_label(
        &self,
        id: &str,
        input: UpdateLabelInput,
        full_replace: bool,
    ) -> AppResult<StoredLabel> {
        self.inner.update_label(id, input, full_replace).await
    }
    async fn delete_label(&self, id: &str) -> AppResult<()> {
        self.inner.delete_label(id).await
    }
    async fn upsert_upstream_label(&self, input: NewLabelInput) -> AppResult<StoredLabel> {
        self.inner.upsert_upstream_label(input).await
    }
    async fn list_drafts(&self, query: &MessageListQuery) -> AppResult<DraftListPage> {
        self.inner.list_drafts(query).await
    }
    async fn get_draft(&self, id: &str) -> AppResult<Option<StoredDraft>> {
        self.inner.get_draft(id).await
    }
    async fn create_draft(&self, message: NewMessageInput) -> AppResult<StoredDraft> {
        self.inner.create_draft(message).await
    }
    async fn update_draft(
        &self,
        draft_id: &str,
        message: NewMessageInput,
    ) -> AppResult<StoredDraft> {
        self.inner.update_draft(draft_id, message).await
    }
    async fn delete_draft(&self, draft_id: &str) -> AppResult<bool> {
        self.inner.delete_draft(draft_id).await
    }
    async fn search_messages_ai(&self, query: &AiSearchQuery) -> AppResult<AiMessagePage> {
        self.inner.search_messages_ai(query).await
    }
    async fn list_thread_summaries(&self, query: &AiThreadQuery) -> AppResult<AiThreadPage> {
        self.inner.list_thread_summaries(query).await
    }
    async fn triage_thread(&self, thread_id: &str, patch: &TriagePatch) -> AppResult<TriageResult> {
        self.inner.triage_thread(thread_id, patch).await
    }
    async fn get_thread_annotation(&self, thread_id: &str) -> AppResult<Option<ThreadAnnotation>> {
        self.inner.get_thread_annotation(thread_id).await
    }
    async fn upsert_thread_annotation(
        &self,
        thread_id: &str,
        annotation: &ThreadAnnotation,
    ) -> AppResult<ThreadAnnotation> {
        self.inner
            .upsert_thread_annotation(thread_id, annotation)
            .await
    }
    async fn patch_thread_annotation(
        &self,
        thread_id: &str,
        patch: &ThreadAnnotationPatch,
        updated_by: Option<&str>,
    ) -> AppResult<ThreadAnnotation> {
        self.inner
            .patch_thread_annotation(thread_id, patch, updated_by)
            .await
    }
    async fn delete_thread_annotation(&self, thread_id: &str) -> AppResult<()> {
        self.inner.delete_thread_annotation(thread_id).await
    }
    async fn find_message_by_resend_id(&self, resend_id: &str) -> AppResult<Option<StoredMessage>> {
        self.inner.find_message_by_resend_id(resend_id).await
    }
    async fn find_message_by_rfc_message_id(
        &self,
        rfc822_message_id: &str,
    ) -> AppResult<Option<StoredMessage>> {
        self.inner
            .find_message_by_rfc_message_id(rfc822_message_id)
            .await
    }
    async fn record_delivery_status(
        &self,
        resend_id: &str,
        status: &str,
    ) -> AppResult<Option<StoredMessage>> {
        self.inner.record_delivery_status(resend_id, status).await
    }
    async fn imap_list_mailboxes(&self) -> AppResult<Vec<ImapMailboxInfo>> {
        self.inner.imap_list_mailboxes().await
    }
    async fn imap_mailbox_info(&self, mailbox_name: &str) -> AppResult<Option<ImapMailboxInfo>> {
        self.inner.imap_mailbox_info(mailbox_name).await
    }
    async fn imap_list_messages(&self, mailbox_name: &str) -> AppResult<Vec<ImapMessageEntry>> {
        self.inner.imap_list_messages(mailbox_name).await
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
        self.inner
            .imap_set_flags(
                message_id,
                is_seen,
                is_flagged,
                is_draft,
                is_answered,
                is_deleted,
            )
            .await
    }
    async fn imap_expunge(&self, mailbox_name: &str) -> AppResult<Vec<u32>> {
        self.inner.imap_expunge(mailbox_name).await
    }
    async fn imap_copy_or_move(
        &self,
        src: &str,
        dst: &str,
        ids: &[String],
        is_move: bool,
    ) -> AppResult<Vec<(u32, u32)>> {
        self.inner.imap_copy_or_move(src, dst, ids, is_move).await
    }
    async fn imap_append(
        &self,
        mailbox_name: &str,
        input: NewMessageInput,
    ) -> AppResult<(u32, u32, StoredMessage)> {
        self.inner.imap_append(mailbox_name, input).await
    }
    async fn upsert_synced_message(&self, input: NewMessageInput) -> AppResult<UpsertOutcome> {
        self.inner.upsert_synced_message(input).await
    }
    async fn find_message_by_upstream_id(&self, uid: &str) -> AppResult<Option<StoredMessage>> {
        self.inner.find_message_by_upstream_id(uid).await
    }
    async fn delete_message_by_upstream_id(&self, uid: &str) -> AppResult<Option<StoredMessage>> {
        self.inner.delete_message_by_upstream_id(uid).await
    }
    async fn get_sync_state(&self, account_key: &str) -> AppResult<Option<SyncState>> {
        self.inner.get_sync_state(account_key).await
    }
    async fn save_sync_state(&self, state: SyncState) -> AppResult<()> {
        self.inner.save_sync_state(state).await
    }
    async fn list_sync_states(&self) -> AppResult<Vec<SyncState>> {
        self.inner.list_sync_states().await
    }
    async fn set_watch(&self, watch: WatchSubscription) -> AppResult<WatchSubscription> {
        self.inner.set_watch(watch).await
    }
    async fn get_watch(&self) -> AppResult<Option<WatchSubscription>> {
        self.inner.get_watch().await
    }
    async fn clear_watch(&self) -> AppResult<()> {
        self.inner.clear_watch().await
    }
    async fn get_settings(&self) -> AppResult<UserSettings> {
        self.inner.get_settings().await
    }
    async fn save_settings(&self, settings: UserSettings) -> AppResult<UserSettings> {
        self.inner.save_settings(settings).await
    }
    async fn create_pending_approval(
        &self,
        input: NewPendingApprovalInput,
    ) -> AppResult<PendingApproval> {
        self.inner.create_pending_approval(input).await
    }
    async fn get_pending_approval(&self, id: &str) -> AppResult<Option<PendingApproval>> {
        self.inner.get_pending_approval(id).await
    }
    async fn list_pending_approvals(
        &self,
        status: Option<ApprovalStatus>,
        limit: usize,
    ) -> AppResult<Vec<PendingApproval>> {
        self.inner.list_pending_approvals(status, limit).await
    }
    async fn resolve_pending_approval(
        &self,
        id: &str,
        status: ApprovalStatus,
        decided_by: Option<String>,
        note: Option<String>,
        sent_message_id: Option<String>,
        provider_message_id: Option<String>,
    ) -> AppResult<PendingApproval> {
        self.inner
            .resolve_pending_approval(
                id,
                status,
                decided_by,
                note,
                sent_message_id,
                provider_message_id,
            )
            .await
    }
    async fn record_contact_interaction(
        &self,
        interaction: &ContactInteraction,
    ) -> AppResult<ContactRecord> {
        self.inner.record_contact_interaction(interaction).await
    }
    async fn get_contact(&self, email: &str) -> AppResult<Option<ContactRecord>> {
        self.inner.get_contact(email).await
    }
    async fn list_contacts(&self, query: &ContactQuery) -> AppResult<Vec<ContactRecord>> {
        self.inner.list_contacts(query).await
    }
    async fn patch_contact(&self, email: &str, patch: &ContactPatch) -> AppResult<ContactRecord> {
        self.inner.patch_contact(email, patch).await
    }
    async fn get_idempotency_key(
        &self,
        scope: &str,
        key: &str,
        now_ms: i64,
    ) -> AppResult<Option<IdempotencyRecord>> {
        self.inner.get_idempotency_key(scope, key, now_ms).await
    }
    async fn put_idempotency_key(
        &self,
        scope: &str,
        key: &str,
        response_json: &str,
        ttl_secs: i64,
    ) -> AppResult<()> {
        self.inner
            .put_idempotency_key(scope, key, response_json, ttl_secs)
            .await
    }
    async fn append_audit_log(&self, entry: &NewAuditLogEntry) -> AppResult<AuditLogEntry> {
        self.inner.append_audit_log(entry).await
    }
    async fn list_audit_log(&self, query: &AuditLogQuery) -> AppResult<Vec<AuditLogEntry>> {
        self.inner.list_audit_log(query).await
    }
    async fn snooze_thread(&self, thread_id: &str, until_ms: i64) -> AppResult<SnoozedThread> {
        self.inner.snooze_thread(thread_id, until_ms).await
    }
    async fn unsnooze_thread(&self, thread_id: &str) -> AppResult<bool> {
        self.inner.unsnooze_thread(thread_id).await
    }
    async fn list_snoozed_threads(
        &self,
        due_before_ms: Option<i64>,
    ) -> AppResult<Vec<SnoozedThread>> {
        self.inner.list_snoozed_threads(due_before_ms).await
    }
    async fn list_all_due_snoozes(&self, now_ms: i64) -> AppResult<Vec<SnoozedThread>> {
        self.inner.list_all_due_snoozes(now_ms).await
    }
    async fn create_scheduled_send(&self, input: &NewScheduledSend) -> AppResult<ScheduledSend> {
        self.inner.create_scheduled_send(input).await
    }
    async fn get_scheduled_send(&self, id: &str) -> AppResult<Option<ScheduledSend>> {
        self.inner.get_scheduled_send(id).await
    }
    async fn list_scheduled_sends(
        &self,
        status: Option<ScheduledSendStatus>,
        limit: usize,
    ) -> AppResult<Vec<ScheduledSend>> {
        self.inner.list_scheduled_sends(status, limit).await
    }
    async fn cancel_scheduled_send(&self, id: &str) -> AppResult<ScheduledSend> {
        self.inner.cancel_scheduled_send(id).await
    }
    async fn claim_due_scheduled_sends(
        &self,
        now_ms: i64,
        stale_lease_ms: i64,
    ) -> AppResult<Vec<ScheduledSend>> {
        self.inner
            .claim_due_scheduled_sends(now_ms, stale_lease_ms)
            .await
    }
    async fn complete_scheduled_send(
        &self,
        id: &str,
        sent_message_id: &str,
        provider_message_id: &str,
    ) -> AppResult<ScheduledSend> {
        self.inner
            .complete_scheduled_send(id, sent_message_id, provider_message_id)
            .await
    }
    async fn fail_scheduled_send(&self, id: &str, error: &str) -> AppResult<ScheduledSend> {
        self.inner.fail_scheduled_send(id, error).await
    }
    async fn create_inbox_rule(&self, input: &NewInboxRule) -> AppResult<InboxRule> {
        self.inner.create_inbox_rule(input).await
    }
    async fn get_inbox_rule(&self, id: &str) -> AppResult<Option<InboxRule>> {
        self.inner.get_inbox_rule(id).await
    }
    async fn list_inbox_rules(&self) -> AppResult<Vec<InboxRule>> {
        self.inner.list_inbox_rules().await
    }
    async fn patch_inbox_rule(&self, id: &str, patch: &InboxRulePatch) -> AppResult<InboxRule> {
        self.inner.patch_inbox_rule(id, patch).await
    }
    async fn delete_inbox_rule(&self, id: &str) -> AppResult<()> {
        self.inner.delete_inbox_rule(id).await
    }

    async fn create_domain(
        &self,
        input: nogml::storage::NewDomainInput,
    ) -> AppResult<nogml::storage::DomainRecord> {
        self.inner.create_domain(input).await
    }

    async fn get_domain(&self, domain: &str) -> AppResult<Option<nogml::storage::DomainRecord>> {
        self.inner.get_domain(domain).await
    }

    async fn list_domains(
        &self,
        mailbox_id: Option<&str>,
    ) -> AppResult<Vec<nogml::storage::DomainRecord>> {
        self.inner.list_domains(mailbox_id).await
    }

    async fn update_domain(
        &self,
        domain: &str,
        update: &nogml::storage::DomainUpdate,
    ) -> AppResult<nogml::storage::DomainRecord> {
        self.inner.update_domain(domain, update).await
    }

    async fn delete_domain(&self, domain: &str) -> AppResult<bool> {
        self.inner.delete_domain(domain).await
    }
    async fn upsert_suppression(
        &self,
        input: nogml::storage::NewSuppressionInput,
    ) -> AppResult<nogml::storage::SuppressionEntry> {
        self.inner.upsert_suppression(input).await
    }
    async fn get_suppression(
        &self,
        email: &str,
        now_ms: i64,
    ) -> AppResult<Option<nogml::storage::SuppressionEntry>> {
        self.inner.get_suppression(email, now_ms).await
    }
    async fn find_suppressed_emails(
        &self,
        emails: &[String],
        now_ms: i64,
    ) -> AppResult<Vec<nogml::storage::SuppressionEntry>> {
        self.inner.find_suppressed_emails(emails, now_ms).await
    }
    async fn list_suppressions(
        &self,
        query: &nogml::storage::SuppressionQuery,
        now_ms: i64,
    ) -> AppResult<Vec<nogml::storage::SuppressionEntry>> {
        self.inner.list_suppressions(query, now_ms).await
    }
    async fn delete_suppression(&self, email: &str) -> AppResult<bool> {
        self.inner.delete_suppression(email).await
    }
    async fn record_deliverability_event(
        &self,
        input: nogml::storage::NewDeliverabilityEvent,
    ) -> AppResult<nogml::storage::DeliverabilityEvent> {
        self.inner.record_deliverability_event(input).await
    }
    async fn count_deliverability_events(
        &self,
        domain: &str,
        since_ms: i64,
    ) -> AppResult<nogml::storage::DeliverabilityCounts> {
        self.inner
            .count_deliverability_events(domain, since_ms)
            .await
    }
    async fn list_deliverability_domains(&self) -> AppResult<Vec<String>> {
        self.inner.list_deliverability_domains().await
    }
    async fn get_domain_deliverability_state(
        &self,
        domain: &str,
    ) -> AppResult<Option<nogml::storage::DomainDeliverabilityState>> {
        self.inner.get_domain_deliverability_state(domain).await
    }
    async fn set_domain_deliverability_paused(
        &self,
        domain: &str,
        paused: bool,
        reason: Option<String>,
        now_ms: i64,
    ) -> AppResult<nogml::storage::DomainDeliverabilityState> {
        self.inner
            .set_domain_deliverability_paused(domain, paused, reason, now_ms)
            .await
    }
}

#[tokio::test]
async fn scheduler_isolates_per_item_post_send_db_errors_without_starving_or_retrying() {
    let cfg = Config::for_test();
    let mem = Arc::new(MemoryStore::new(&cfg.user_email));
    let store: Arc<dyn MailStore> = Arc::new(FailingInsertStore {
        inner: mem.clone(),
        fail_subject: "fail-persist".to_string(),
    });
    let (transport, sent_log) = DelayedRecordingTransport::new(Duration::ZERO);
    let state = AppState::with_backends(
        cfg.clone(),
        store.clone(),
        Arc::new(HttpResendClient::from_config(&cfg)),
    )
    .with_transport(Arc::new(transport));

    let now_ms = Utc::now().timestamp_millis();
    let first = store
        .create_scheduled_send(&NewScheduledSend {
            id: Some("sch_err_1".to_string()),
            send_at_ms: now_ms - 2_000,
            outbound_message: sample_outbound(&cfg.user_email, "a@example.com", "fail-persist"),
            reply_to_message_id: None,
            thread_id: None,
            created_at_ms: now_ms - 5_000,
        })
        .await
        .unwrap();
    let second = store
        .create_scheduled_send(&NewScheduledSend {
            id: Some("sch_ok_2".to_string()),
            send_at_ms: now_ms - 1_000,
            outbound_message: sample_outbound(&cfg.user_email, "b@example.com", "succeed-second"),
            reply_to_message_id: None,
            thread_id: None,
            created_at_ms: now_ms - 4_000,
        })
        .await
        .unwrap();

    let rep = process_due_scheduler_items(&state, now_ms).await.unwrap();
    assert_eq!(rep.scheduled_failed, 1);
    assert_eq!(
        rep.scheduled_sent, 1,
        "second item must still dispatch when first item hits post-send DB failure"
    );

    let first_after = store.get_scheduled_send(&first.id).await.unwrap().unwrap();
    assert_eq!(first_after.status, ScheduledSendStatus::Failed);
    let second_after = store.get_scheduled_send(&second.id).await.unwrap().unwrap();
    assert_eq!(second_after.status, ScheduledSendStatus::Sent);

    // Subsequent tick (even far past stale lease) must NEVER re-send the failed item
    let sends_before = sent_log.lock().unwrap().len();
    let rep2 = process_due_scheduler_items(&state, now_ms + 600_000)
        .await
        .unwrap();
    assert_eq!(rep2.scheduled_sent, 0);
    assert_eq!(rep2.scheduled_failed, 0);
    assert_eq!(sent_log.lock().unwrap().len(), sends_before);
}

// ============================================================================
// 3. Memory Caps: ResumableUploadStore, /batch/gmail/v1, and POST /mcp
// ============================================================================

#[tokio::test]
async fn resumable_upload_enforces_aggregate_memory_cap_and_does_not_extend_ttl_on_status_probes() {
    let cfg = Config::for_test();
    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let uploads = Arc::new(ResumableUploadStore::with_limits(
        Duration::from_millis(90),
        64,
    ));
    let state = AppState::with_backends(
        cfg.clone(),
        store,
        Arc::new(HttpResendClient::from_config(&cfg)),
    )
    .with_resumable_uploads(uploads);
    let app = build_router(state);

    // Start upload session A and buffer 48 bytes (incomplete)
    let (s_init_a, hdrs_a, _) = http_req(
        &app,
        "POST",
        "/upload/gmail/v1/users/me/messages?uploadType=resumable",
        &[("content-type", "application/json")],
        br#"{"labelIds":["INBOX"]}"#.to_vec(),
    )
    .await;
    assert_eq!(s_init_a, StatusCode::OK);
    let loc_a = hdrs_a
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let (s_chunk_a, _, _) = http_req(
        &app,
        "PUT",
        &loc_a,
        &[("content-range", "bytes 0-47/*")],
        vec![b'a'; 48],
    )
    .await;
    assert_eq!(s_chunk_a, StatusCode::PERMANENT_REDIRECT); // 308 Resume Incomplete

    // Start session B and attempt to upload 32 bytes -> 48 + 32 = 80 > 64 -> 413 Payload Too Large
    let (s_init_b, hdrs_b, _) = http_req(
        &app,
        "POST",
        "/upload/gmail/v1/users/me/messages?uploadType=resumable",
        &[("content-type", "application/json")],
        br#"{"labelIds":["INBOX"]}"#.to_vec(),
    )
    .await;
    assert_eq!(s_init_b, StatusCode::OK);
    let loc_b = hdrs_b
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let (s_chunk_b, _, _) = http_req(
        &app,
        "PUT",
        &loc_b,
        &[("content-range", "bytes 0-31/*")],
        vec![b'b'; 32],
    )
    .await;
    assert_eq!(
        s_chunk_b,
        StatusCode::PAYLOAD_TOO_LARGE,
        "aggregate resumable upload memory cap must reject with 413"
    );

    // Verify status probe (`bytes */*`) does NOT extend TTL past 90ms
    tokio::time::sleep(Duration::from_millis(55)).await;
    let (s_probe1, _, _) = http_req(
        &app,
        "PUT",
        &loc_a,
        &[("content-range", "bytes */*")],
        Vec::new(),
    )
    .await;
    assert_eq!(s_probe1, StatusCode::PERMANENT_REDIRECT);

    tokio::time::sleep(Duration::from_millis(55)).await;
    let (s_probe2, _, _) = http_req(
        &app,
        "PUT",
        &loc_a,
        &[("content-range", "bytes */*")],
        Vec::new(),
    )
    .await;
    assert_eq!(
        s_probe2,
        StatusCode::NOT_FOUND,
        "status probe must NOT refresh session TTL"
    );
}

#[tokio::test]
async fn gmail_batch_response_enforces_aggregate_byte_cap_with_413() {
    let cfg = Config::for_test();
    let store = Arc::new(MemoryStore::new(&cfg.user_email));

    let large_body = "X".repeat(2_000);
    let raw = format!("From: a@example.com\r\nSubject: Big\r\n\r\n{large_body}").into_bytes();
    let msg = store
        .insert_message(parse_raw_to_new_message_input(
            raw,
            vec![LABEL_INBOX.to_string()],
            None,
            "local",
            None,
            None,
            false,
            false,
        ))
        .await
        .unwrap();

    let state = AppState::with_backends(
        cfg.clone(),
        store,
        Arc::new(HttpResendClient::from_config(&cfg)),
    )
    .with_max_batch_response_bytes(1_500);
    let app = build_router(state);

    let batch_body = format!(
        "--b1\r\nContent-Type: application/http\r\nContent-ID: <1>\r\n\r\nGET /gmail/v1/users/me/messages/{}?format=raw HTTP/1.1\r\n\r\n--b1\r\nContent-Type: application/http\r\nContent-ID: <2>\r\n\r\nGET /gmail/v1/users/me/messages/{}?format=raw HTTP/1.1\r\n\r\n--b1--\r\n",
        msg.id, msg.id
    );

    let (status, _, _) = http_req(
        &app,
        "POST",
        "/batch/gmail/v1",
        &[("content-type", "multipart/mixed; boundary=b1")],
        batch_body.into_bytes(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "/batch/gmail/v1 must return 413 when aggregate response exceeds cap"
    );

    // A small batch under the cap succeeds cleanly
    let small_batch = "--b2\r\nContent-Type: application/http\r\nContent-ID: <1>\r\n\r\nGET /gmail/v1/users/me/profile HTTP/1.1\r\n\r\n--b2--\r\n";
    let (ok_status, _, _) = http_req(
        &app,
        "POST",
        "/batch/gmail/v1",
        &[("content-type", "multipart/mixed; boundary=b2")],
        small_batch.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(ok_status, StatusCode::OK);
}

#[tokio::test]
async fn mcp_http_post_caps_jsonrpc_batch_to_100_requests() {
    let cfg = Config::for_test();
    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let state = AppState::with_backends(
        cfg.clone(),
        store,
        Arc::new(HttpResendClient::from_config(&cfg)),
    );
    let app = build_router(state);

    let oversize: Vec<Value> = (0..101)
        .map(|i| json!({"jsonrpc": "2.0", "id": i, "method": "tools/list"}))
        .collect();
    let (status, body) = http_json(&app, "POST", "/mcp", Some(Value::Array(oversize))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["error"]["code"],
        json!(-32600),
        "oversize MCP batch (>100) must return JSON-RPC -32600 Invalid Request, got {body}"
    );

    let valid_batch = Value::Array(vec![
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ]);
    let (ok_status, ok_body) = http_json(&app, "POST", "/mcp", Some(valid_batch)).await;
    assert_eq!(ok_status, StatusCode::OK);
    assert_eq!(ok_body.as_array().map(Vec::len), Some(2));
}

// ============================================================================
// 4. Bidirectional Sync: Concurrent Local Edits & Push Failure Retry (No Echo)
// ============================================================================

struct RacingBidirectionalSource {
    pull_started: Arc<Notify>,
    allow_pull_finish: Arc<Notify>,
    fail_first_push: AtomicBool,
    pushed_log: Arc<Mutex<Vec<LocalMutation>>>,
    pull_count: AtomicUsize,
}

#[async_trait]
impl SyncSource for RacingBidirectionalSource {
    fn provider_name(&self) -> &'static str {
        "mock_race"
    }

    fn account_key(&self, _config: &Config) -> String {
        "mock_race:me".to_string()
    }

    async fn pull(
        &self,
        state: &AppState,
        _sync_state: &mut SyncState,
        _opts: &SyncRunOptions,
    ) -> AppResult<PullReport> {
        let idx = self.pull_count.fetch_add(1, Ordering::SeqCst);
        let mut report = PullReport::default();

        if idx == 0 {
            // Initial pull seeds two upstream-linked messages
            for (up_id, subj) in [("up_1", "Initial 1"), ("up_2", "Initial 2")] {
                let raw = format!("From: a@ex.com\r\nSubject: {subj}\r\n\r\nBody").into_bytes();
                let input = parse_raw_to_new_message_input(
                    raw,
                    vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
                    None,
                    "mock_race",
                    Some(up_id.to_string()),
                    None,
                    false,
                    false,
                );
                let _ = ingest_synced_message(state, input, &mut report).await?;
            }
            return Ok(report);
        }

        if idx == 1 {
            // Pull an upstream label update on `up_1` (only removes `UNREAD`, recording `source = "sync"` history)
            let updated_input = parse_raw_to_new_message_input(
                b"From: a@ex.com\r\nSubject: Initial 1\r\n\r\nBody".to_vec(),
                vec![LABEL_INBOX.to_string(), LABEL_STARRED.to_string()], // upstream marked read without touching STARRED
                None,
                "mock_race",
                Some("up_1".to_string()),
                None,
                false,
                false,
            );
            let _ = ingest_synced_message(state, updated_input, &mut report).await?;

            // Pause mid-pull so test can perform a concurrent local edit on `up_2`!
            self.pull_started.notify_one();
            self.allow_pull_finish.notified().await;
        }

        Ok(report)
    }

    async fn push_changes(
        &self,
        _state: &AppState,
        changes: &[LocalMutation],
    ) -> AppResult<PushReport> {
        if self.fail_first_push.swap(false, Ordering::SeqCst) {
            return Err(AppError::Upstream {
                status: 503,
                message: "simulated transient push failure".to_string(),
            });
        }
        self.pushed_log
            .lock()
            .unwrap()
            .extend(changes.iter().cloned());
        Ok(PushReport {
            messages_pushed: changes.len() as u64,
        })
    }
}

#[tokio::test]
async fn bidirectional_sync_preserves_concurrent_local_edits_and_never_echoes_pulled_rows_on_retry()
{
    let mut cfg = Config::for_test();
    cfg.sync_bidirectional = true;
    let store = Arc::new(SqliteStore::open_in_memory(&cfg.user_email).unwrap());
    let state = AppState::with_backends(
        cfg.clone(),
        store.clone(),
        Arc::new(HttpResendClient::from_config(&cfg)),
    );

    let pull_started = Arc::new(Notify::new());
    let allow_pull_finish = Arc::new(Notify::new());
    let pushed_log = Arc::new(Mutex::new(Vec::new()));
    let source = Arc::new(RacingBidirectionalSource {
        pull_started: pull_started.clone(),
        allow_pull_finish: allow_pull_finish.clone(),
        fail_first_push: AtomicBool::new(true),
        pushed_log: pushed_log.clone(),
        pull_count: AtomicUsize::new(0),
    });

    // Run 1: Initial pull seeds `up_1` and `up_2`
    let r1 = run_sync_source(&state, source.as_ref(), SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r1.messages_added, 2);

    let m1 = store
        .find_message_by_upstream_id("up_1")
        .await
        .unwrap()
        .unwrap();
    let m2 = store
        .find_message_by_upstream_id("up_2")
        .await
        .unwrap()
        .unwrap();

    // Local edit BEFORE run 2: star `up_1`
    store
        .modify_message_labels(&m1.id, &[LABEL_STARRED.to_string()], &[])
        .await
        .unwrap();

    // Run 2: During `pull()`, `up_1` receives a pulled upstream edit (remove UNREAD, source='sync'),
    // AND concurrently a local API edit stars `up_2` (source='local'). Then `push_changes()` FAILS.
    let state_run2 = state.clone();
    let source_run2 = source.clone();
    let run2_handle = tokio::spawn(async move {
        run_sync_source(&state_run2, source_run2.as_ref(), SyncRunOptions::default()).await
    });

    pull_started.notified().await;
    // Concurrent local write while `pull()` is in-flight!
    store
        .modify_message_labels(&m2.id, &[LABEL_STARRED.to_string()], &[])
        .await
        .unwrap();
    allow_pull_finish.notify_one();

    let run2_res = run2_handle.await.unwrap();
    assert!(
        run2_res.is_err(),
        "run 2 push_changes should fail as simulated"
    );

    // Run 3: Retry sync. Must push BOTH `up_1` (+STARRED) and concurrent `up_2` (+STARRED),
    // and MUST NOT echo the pulled `up_1` (-UNREAD) back upstream!
    let r3 = run_sync_source(&state, source.as_ref(), SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r3.messages_pushed, 2);

    let pushed = pushed_log.lock().unwrap();
    let m1_push = pushed.iter().find(|m| m.upstream_id == "up_1").unwrap();
    let m2_push = pushed.iter().find(|m| m.upstream_id == "up_2").unwrap();
    match &m1_push.kind {
        nogml::sync::LocalMutationKind::ModifyLabels {
            add_labels,
            remove_labels,
        } => {
            assert_eq!(add_labels, &vec![LABEL_STARRED.to_string()]);
            assert!(
                remove_labels.is_empty(),
                "pulled UNREAD removal must NOT echo back upstream, got {remove_labels:?}"
            );
        }
        other => panic!("expected ModifyLabels for up_1, got {other:?}"),
    }
    match &m2_push.kind {
        nogml::sync::LocalMutationKind::ModifyLabels {
            add_labels,
            remove_labels,
        } => {
            assert_eq!(add_labels, &vec![LABEL_STARRED.to_string()]);
            assert!(remove_labels.is_empty());
        }
        other => panic!("expected ModifyLabels for concurrent up_2 edit, got {other:?}"),
    }
}

// ============================================================================
// 5. Gmail API Mid-Sync HTTP 401 Token Refresh & Retry
// ============================================================================

#[tokio::test]
async fn gmail_api_sync_invalidates_token_cache_and_retries_on_mid_sync_401() {
    let mock_server = MockServer::start().await;

    // First token call returns `tok-expired`, second returns `tok-fresh`
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("refresh_token=rtok_401"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok-expired",
            "expires_in": 3600
        })))
        .up_to_n_times(1)
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("refresh_token=rtok_401"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok-fresh",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // labels.list succeeds with `tok-expired`
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .and(wm_header("authorization", "Bearer tok-expired"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "labels": [] })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // profile returns 401 with `tok-expired` (mid-sync expiry!), then 200 with `tok-fresh`
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/profile"))
        .and(wm_header("authorization", "Bearer tok-expired"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": { "code": 401, "message": "Invalid Credentials" }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/profile"))
        .and(wm_header("authorization", "Bearer tok-fresh"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "emailAddress": "agent@example.com",
            "messagesTotal": 1,
            "threadsTotal": 1,
            "historyId": "7000"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // messages.list and messages.get require `tok-fresh`
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .and(wm_header("authorization", "Bearer tok-fresh"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [{ "id": "gm_401_msg", "threadId": "gm_401_thr" }],
            "resultSizeEstimate": 1
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let raw = b"From: alice@example.com\r\nSubject: Recovered 401\r\n\r\nHello after refresh";
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/gm_401_msg"))
        .and(query_param("format", "raw"))
        .and(wm_header("authorization", "Bearer tok-fresh"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "gm_401_msg",
            "threadId": "gm_401_thr",
            "labelIds": ["INBOX"],
            "raw": b64url(raw)
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut cfg = Config::for_test();
    cfg.sync_mode = SyncMode::Api;
    cfg.gmail_api_base_url = mock_server.uri();
    cfg.gmail_oauth_token_url = format!("{}/token", mock_server.uri());
    cfg.gmail_client_id = Some("cid_401".to_string());
    cfg.gmail_client_secret = Some("csec_401".to_string());
    cfg.gmail_refresh_token = Some("rtok_401".to_string());

    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let state = AppState::with_backends(
        cfg.clone(),
        store.clone(),
        Arc::new(HttpResendClient::from_config(&cfg)),
    );

    let report = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .expect("sync should recover from mid-sync 401 by refreshing token");
    assert_eq!(report.messages_added, 1);
    assert!(
        store
            .find_message_by_upstream_id("gm_401_msg")
            .await
            .unwrap()
            .is_some()
    );
}

// ============================================================================
// 6. Upstream IMAP Sync: Bounded Batches, X-GM-THRID, and Timeout on Hung Server
// ============================================================================

#[tokio::test]
async fn imap_sync_fetches_in_bounded_batches_preserves_xgm_thrid_and_times_out_on_hung_server() {
    // Part A: 28 upstream messages (> IMAP_FETCH_BATCH_SIZE=25) with max_messages=27
    let up_cfg = Config::for_test();
    let up_store = Arc::new(MemoryStore::new(&up_cfg.user_email));
    let upstream_state = AppState::with_backends(
        up_cfg.clone(),
        up_store.clone(),
        Arc::new(HttpResendClient::from_config(&up_cfg)),
    );

    for i in 1..=28 {
        let raw = format!(
            "From: sender{i}@upstream.test\r\nTo: agent@example.com\r\nSubject: Batch Msg {i}\r\nMessage-ID: <batch-{i}@upstream.test>\r\n\r\nBody {i}"
        )
        .into_bytes();
        let input = parse_raw_to_new_message_input(
            raw,
            vec![LABEL_INBOX.to_string()],
            None,
            "local",
            Some(format!("{:016x}", 0x18f0_0000_0000_0000u64 + i as u64)),
            None,
            false,
            false,
        );
        up_store.insert_message(input).await.unwrap();
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let up_clone = upstream_state.clone();
    tokio::spawn(async move {
        let _ = serve_plain_listener(listener, up_clone, None, shutdown_rx).await;
    });

    let mut local_cfg = Config::for_test();
    local_cfg.sync_mode = SyncMode::Imap;
    local_cfg.gmail_imap_host = addr.ip().to_string();
    local_cfg.gmail_imap_port = addr.port();
    local_cfg.gmail_imap_tls = false;
    local_cfg.gmail_imap_user = Some("agent@example.com".to_string());
    local_cfg.gmail_imap_password = Some("secret".to_string());
    local_cfg.gmail_imap_mailbox = "[Gmail]/All Mail".to_string();
    let local_store = Arc::new(MemoryStore::new(&local_cfg.user_email));
    let local_state = AppState::with_backends(
        local_cfg.clone(),
        local_store.clone(),
        Arc::new(HttpResendClient::from_config(&local_cfg)),
    );

    let r1 = run_gmail_sync(
        &local_state,
        SyncRunOptions {
            max_messages: Some(27),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(r1.messages_added, 27);

    // Verify X-GM-THRID was preserved on synced messages
    let first_synced = local_store
        .find_message_by_upstream_id(&format!("{:016x}", 0x18f0_0000_0000_0001u64))
        .await
        .unwrap()
        .unwrap();
    assert!(
        first_synced.upstream_thread_id.is_some(),
        "X-GM-THRID must be preserved in upstream_thread_id"
    );

    // Incremental sync fetches the remaining 1 message without skipping any UIDs
    let r2 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert!(!r2.full_resync);
    assert_eq!(r2.messages_added, 1);

    let _ = shutdown_tx.send(true);

    // Part B: Hung upstream IMAP server (accepts TCP, never sends greeting) must time out cleanly
    let hung_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hung_addr = hung_listener.local_addr().unwrap();
    let _hung_task = tokio::spawn(async move {
        if let Ok((_sock, _)) = hung_listener.accept().await {
            // Keep socket open without writing a single byte
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });

    let mut hung_cfg = Config::for_test();
    hung_cfg.sync_mode = SyncMode::Imap;
    hung_cfg.gmail_imap_host = hung_addr.ip().to_string();
    hung_cfg.gmail_imap_port = hung_addr.port();
    hung_cfg.gmail_imap_tls = false;
    hung_cfg.gmail_imap_user = Some("agent@example.com".to_string());
    hung_cfg.gmail_imap_password = Some("secret".to_string());
    let hung_state = AppState::with_backends(
        hung_cfg.clone(),
        Arc::new(MemoryStore::new(&hung_cfg.user_email)),
        Arc::new(HttpResendClient::from_config(&hung_cfg)),
    );

    let fast_imap =
        GmailImapSyncSource::with_timeouts(Duration::from_millis(200), Duration::from_millis(200));
    let err = run_sync_source(&hung_state, &fast_imap, SyncRunOptions::default())
        .await
        .unwrap_err();
    match err {
        AppError::Upstream { status, message } => {
            assert_eq!(status, 504);
            assert!(message.contains("timed out"), "got: {message}");
        }
        other => panic!("expected 504 timeout error, got {other:?}"),
    }
    // Verify sync_lock was released cleanly
    assert!(hung_state.sync_lock.try_lock().is_ok());
}

// ============================================================================
// 7. External Blob Cleanup, Draft Send Raw Load, & Gmail History Fidelity
// ============================================================================

async fn insert_msg_with_attachment(
    state: &AppState,
    thread_id: Option<&str>,
    upstream_id: Option<&str>,
) -> (StoredMessage, String) {
    let raw = b"From: alice@example.com\r\nSubject: With Att\r\n\r\nBody text".to_vec();
    let stored = state
        .store
        .insert_message(NewMessageInput {
            id: None,
            thread_id: thread_id.map(str::to_string),
            label_ids: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            raw_rfc2822: raw,
            snippet: "Body text".to_string(),
            internal_date_ms: Utc::now().timestamp_millis(),
            subject: "With Att".to_string(),
            from_addr: "alice@example.com".to_string(),
            to_addrs: vec![state.config.user_email.clone()],
            cc_addrs: Vec::new(),
            bcc_addrs: Vec::new(),
            text_body: "Body text".to_string(),
            html_body: None,
            rfc822_message_id: None,
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id: upstream_id.map(str::to_string),
            upstream_thread_id: None,
            source: "local".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: vec![NewAttachmentInput {
                part_id: "att_1".to_string(),
                filename: Some("report.txt".to_string()),
                content_type: "text/plain".to_string(),
                content_id: None,
                data: b"attachment-payload".to_vec(),
            }],
        })
        .await
        .unwrap();
    state.post_store_message(&stored).await.unwrap();
    let metas = state.store.list_attachment_meta(&stored.id).await.unwrap();
    let att_id = metas[0].id.clone();
    (stored, att_id)
}

#[tokio::test]
async fn gmail_deletes_and_sync_delete_clean_up_fs_blob_store_attachments() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(FsBlobStore::open(tmp.path()).unwrap());
    let cfg = Config::for_test();
    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let state = AppState::with_backends(
        cfg.clone(),
        store.clone(),
        Arc::new(HttpResendClient::from_config(&cfg)),
    )
    .with_blobs(blobs.clone());
    let app = build_router(state.clone());

    // 1. batchDelete cleans up both raw + attachment blobs
    let (m_batch, att_batch) = insert_msg_with_attachment(&state, None, None).await;
    assert!(
        blobs
            .get(&raw_message_blob_key(&m_batch.id))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        blobs
            .get(&attachment_blob_key(&m_batch.id, &att_batch))
            .await
            .unwrap()
            .is_some()
    );

    let (st_batch, _) = http_json(
        &app,
        "POST",
        "/gmail/v1/users/me/messages/batchDelete",
        Some(json!({ "ids": [m_batch.id] })),
    )
    .await;
    assert_eq!(st_batch, StatusCode::NO_CONTENT);
    assert!(
        blobs
            .get(&raw_message_blob_key(&m_batch.id))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        blobs
            .get(&attachment_blob_key(&m_batch.id, &att_batch))
            .await
            .unwrap()
            .is_none(),
        "batchDelete must remove external attachment blob"
    );

    // 2. delete_thread cleans up attachment blobs for every message in the thread
    let (m_thr, att_thr) = insert_msg_with_attachment(&state, Some("thr_blob_del"), None).await;
    assert!(
        blobs
            .get(&attachment_blob_key(&m_thr.id, &att_thr))
            .await
            .unwrap()
            .is_some()
    );

    let (st_thr, _) = http_json(
        &app,
        "DELETE",
        "/gmail/v1/users/me/threads/thr_blob_del",
        None,
    )
    .await;
    assert_eq!(st_thr, StatusCode::NO_CONTENT);
    assert!(
        blobs
            .get(&attachment_blob_key(&m_thr.id, &att_thr))
            .await
            .unwrap()
            .is_none(),
        "delete_thread must remove external attachment blob"
    );

    // 3. delete_draft cleans up draft attachment blob
    let draft = store
        .create_draft(NewMessageInput {
            id: None,
            thread_id: None,
            label_ids: vec!["DRAFT".to_string()],
            raw_rfc2822:
                b"From: agent@example.com\r\nTo: bob@example.com\r\nSubject: Draft\r\n\r\nHi"
                    .to_vec(),
            snippet: "Hi".to_string(),
            internal_date_ms: Utc::now().timestamp_millis(),
            subject: "Draft".to_string(),
            from_addr: "agent@example.com".to_string(),
            to_addrs: vec!["bob@example.com".to_string()],
            cc_addrs: Vec::new(),
            bcc_addrs: Vec::new(),
            text_body: "Hi".to_string(),
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
            attachments: vec![NewAttachmentInput {
                part_id: "att_1".to_string(),
                filename: Some("draft.pdf".to_string()),
                content_type: "application/pdf".to_string(),
                content_id: None,
                data: b"%PDF-1.4".to_vec(),
            }],
        })
        .await
        .unwrap();
    state.post_store_message(&draft.message).await.unwrap();
    let draft_att_id = store.list_attachment_meta(&draft.message.id).await.unwrap()[0]
        .id
        .clone();
    assert!(
        blobs
            .get(&attachment_blob_key(&draft.message.id, &draft_att_id))
            .await
            .unwrap()
            .is_some()
    );

    let (st_draft, _) = http_json(
        &app,
        "DELETE",
        &format!("/gmail/v1/users/me/drafts/{}", draft.id),
        None,
    )
    .await;
    assert_eq!(st_draft, StatusCode::NO_CONTENT);
    assert!(
        blobs
            .get(&attachment_blob_key(&draft.message.id, &draft_att_id))
            .await
            .unwrap()
            .is_none(),
        "delete_draft must remove external attachment blob"
    );

    // 4. Gmail API incremental sync delete cleans up external attachment blob
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "labels": [] })))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/history"))
        .and(query_param("startHistoryId", "900"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "historyId": "901",
            "history": [{
                "id": "901",
                "messagesDeleted": [{ "message": { "id": "gm_sync_del_1", "threadId": "t1" } }]
            }]
        })))
        .mount(&mock_server)
        .await;

    let mut sync_cfg = Config::for_test();
    sync_cfg.sync_mode = SyncMode::Api;
    sync_cfg.gmail_api_base_url = mock_server.uri();
    sync_cfg.gmail_access_token = Some("tok".to_string());
    let sync_state = AppState::with_backends(
        sync_cfg.clone(),
        store.clone(),
        Arc::new(HttpResendClient::from_config(&sync_cfg)),
    )
    .with_blobs(blobs.clone());
    store
        .save_sync_state(SyncState {
            account_key: "gmail_api:me".to_string(),
            provider: "gmail_api".to_string(),
            last_history_id: Some("900".to_string()),
            status: "idle".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();

    let (m_sync, att_sync) =
        insert_msg_with_attachment(&sync_state, None, Some("gm_sync_del_1")).await;
    assert!(
        blobs
            .get(&attachment_blob_key(&m_sync.id, &att_sync))
            .await
            .unwrap()
            .is_some()
    );

    let rep = run_gmail_sync(&sync_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(rep.messages_deleted, 1);
    assert!(
        blobs
            .get(&attachment_blob_key(&m_sync.id, &att_sync))
            .await
            .unwrap()
            .is_none(),
        "Gmail sync incremental delete must remove external attachment blob"
    );
}

#[tokio::test]
async fn gmail_send_draft_loads_offloaded_raw_blob_and_list_history_populates_current_labels() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(FsBlobStore::open(tmp.path()).unwrap());
    let cfg = Config::for_test();
    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let (transport, sent_log) = DelayedRecordingTransport::new(Duration::ZERO);
    let state = AppState::with_backends(
        cfg.clone(),
        store.clone(),
        Arc::new(HttpResendClient::from_config(&cfg)),
    )
    .with_blobs(blobs.clone())
    .with_transport(Arc::new(transport));
    let app = build_router(state.clone());

    // 1. Draft with empty inline raw_rfc2822 but real raw RFC 2822 stored in external FsBlobStore
    let draft = store
        .create_draft(NewMessageInput {
            id: None,
            thread_id: None,
            label_ids: vec!["DRAFT".to_string()],
            raw_rfc2822: Vec::new(), // offloaded out of DB
            snippet: "Offloaded".to_string(),
            internal_date_ms: Utc::now().timestamp_millis(),
            subject: "Offloaded Draft".to_string(),
            from_addr: cfg.user_email.clone(),
            to_addrs: vec!["dest@example.com".to_string()],
            cc_addrs: Vec::new(),
            bcc_addrs: Vec::new(),
            text_body: "Offloaded".to_string(),
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
            attachments: Vec::new(),
        })
        .await
        .unwrap();
    let offloaded_raw = b"From: agent@example.com\r\nTo: dest@example.com\r\nSubject: From BlobStore\r\n\r\nLoaded from FsBlobStore!";
    blobs
        .put(&raw_message_blob_key(&draft.message.id), offloaded_raw)
        .await
        .unwrap();

    let (send_status, _) = http_json(
        &app,
        "POST",
        "/gmail/v1/users/me/drafts/send",
        Some(json!({ "id": draft.id })),
    )
    .await;
    assert_eq!(send_status, StatusCode::OK);
    {
        let sent = sent_log.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].subject, "From BlobStore");
        assert!(
            sent[0]
                .text
                .as_deref()
                .unwrap_or("")
                .contains("Loaded from FsBlobStore!")
        );
    }

    // 2. Gmail list_history populates labelsAdded[].message.labelIds & labelsRemoved[].message.labelIds
    // with the message's CURRENT labels (not just delta labels), falling back to entry labels when deleted.
    let start_hid = store.current_history_id().await.unwrap();
    let msg = store
        .insert_message(parse_raw_to_new_message_input(
            b"From: bob@example.com\r\nSubject: History Labels\r\n\r\nHello".to_vec(),
            vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            None,
            "local",
            None,
            None,
            false,
            false,
        ))
        .await
        .unwrap();
    store
        .modify_message_labels(&msg.id, &[LABEL_STARRED.to_string()], &[])
        .await
        .unwrap();
    store
        .modify_message_labels(&msg.id, &[], &[LABEL_UNREAD.to_string()])
        .await
        .unwrap();

    // Current labels on `msg` are now ["INBOX", "STARRED"]
    let (h_status, h_body) = http_json(
        &app,
        "GET",
        &format!("/gmail/v1/users/me/history?startHistoryId={start_hid}"),
        None,
    )
    .await;
    assert_eq!(h_status, StatusCode::OK);
    let records = h_body["history"].as_array().unwrap();

    let added_rec = records
        .iter()
        .find(|r| r.get("labelsAdded").is_some())
        .expect("expected labelsAdded record");
    let added_entry = &added_rec["labelsAdded"][0];
    assert_eq!(added_entry["labelIds"], json!(["STARRED"]));
    let mut added_msg_labels: Vec<String> = added_entry["message"]["labelIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    added_msg_labels.sort();
    assert_eq!(
        added_msg_labels,
        vec![LABEL_INBOX.to_string(), LABEL_STARRED.to_string()],
        "labelsAdded[].message.labelIds must contain message's current labels"
    );

    let removed_rec = records
        .iter()
        .find(|r| r.get("labelsRemoved").is_some())
        .expect("expected labelsRemoved record");
    let removed_entry = &removed_rec["labelsRemoved"][0];
    assert_eq!(removed_entry["labelIds"], json!(["UNREAD"]));
    let mut removed_msg_labels: Vec<String> = removed_entry["message"]["labelIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    removed_msg_labels.sort();
    assert_eq!(
        removed_msg_labels,
        vec![LABEL_INBOX.to_string(), LABEL_STARRED.to_string()],
        "labelsRemoved[].message.labelIds must contain message's current labels"
    );

    // After message deletion, list_history gracefully falls back to entry labels
    store.delete_message(&msg.id).await.unwrap();
    let (h_del_status, h_del_body) = http_json(
        &app,
        "GET",
        &format!("/gmail/v1/users/me/history?startHistoryId={start_hid}"),
        None,
    )
    .await;
    assert_eq!(h_del_status, StatusCode::OK);
    let added_after_del = h_del_body["history"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r.get("labelsAdded").is_some())
        .unwrap();
    assert_eq!(
        added_after_del["labelsAdded"][0]["message"]["labelIds"],
        json!(["STARRED"])
    );
}
