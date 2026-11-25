//! Pluggable storage abstraction (`MailStore`) and backend factory.
//!
//! No SQLite types or SQL statements are exposed from this module. All HTTP, MCP,
//! IMAP, Resend, and Sync modules depend solely on `Arc<dyn MailStore>`.

pub mod memory;
pub mod sqlite;

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    config::{Config, StorageBackend},
    error::AppResult,
    models::{
        AttachmentMeta, AutoForwarding, EmailAddress, ImapSettings, LabelColor, PopSettings,
        Profile, SendAs, ThreadSummary, VacationSettings,
    },
};

pub use memory::MemoryStore;
pub use sqlite::SqliteStore;

// ============================================================================
// Domain Records Stored & Returned by `MailStore`
// ============================================================================

/// Pre-parsed and raw representation of a stored email message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: String,
    pub thread_id: String,
    pub label_ids: Vec<String>,
    pub raw_rfc2822: Vec<u8>,
    pub snippet: String,
    pub history_id: u64,
    /// Epoch milliseconds.
    pub internal_date_ms: i64,
    pub size_estimate: i32,

    // Pre-parsed fields for fast AI/MCP reads and search without re-parsing MIME.
    pub subject: String,
    pub from_addr: String,
    pub to_addrs: Vec<String>,
    pub cc_addrs: Vec<String>,
    pub bcc_addrs: Vec<String>,
    pub text_body: String,
    pub html_body: Option<String>,
    pub has_attachments: bool,

    // Threading, deduplication & external provider links.
    pub rfc822_message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references_header: Option<String>,
    pub resend_id: Option<String>,
    pub delivery_status: Option<String>,
    pub upstream_gmail_id: Option<String>,
    pub upstream_thread_id: Option<String>,
    /// Origin: `"local"`, `"resend_inbound"`, `"gmail_api"`, `"gmail_imap"`, `"imap_append"`.
    pub source: String,

    // IMAP metadata (`all_mail_uid` for `[Gmail]/All Mail`; per-label UIDs live on associations).
    pub all_mail_uid: u32,
    pub is_answered: bool,
    pub is_deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAttachment {
    pub id: String,
    pub message_id: String,
    pub part_id: String,
    pub filename: Option<String>,
    pub content_type: String,
    pub content_id: Option<String>,
    pub size_bytes: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredLabel {
    pub id: String,
    pub name: String,
    /// `"system"` or `"user"`.
    pub label_type: String,
    pub message_list_visibility: Option<String>,
    pub label_list_visibility: Option<String>,
    pub color: Option<LabelColor>,
    pub messages_total: i32,
    pub messages_unread: i32,
    pub threads_total: i32,
    pub threads_unread: i32,
    pub uid_validity: u32,
    pub uid_next: u32,
    pub upstream_label_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredDraft {
    pub id: String,
    pub message: StoredMessage,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HistoryEventKind {
    MessageAdded,
    MessageDeleted,
    LabelAdded,
    LabelRemoved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredHistoryEntry {
    pub history_id: u64,
    pub kind: HistoryEventKind,
    pub message_id: String,
    pub thread_id: String,
    pub label_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredThreadDetail {
    pub id: String,
    pub snippet: String,
    pub history_id: u64,
    pub messages: Vec<StoredMessage>,
}

// ============================================================================
// Write Inputs
// ============================================================================

#[derive(Debug, Clone)]
pub struct NewAttachmentInput {
    pub part_id: String,
    pub filename: Option<String>,
    pub content_type: String,
    pub content_id: Option<String>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct NewMessageInput {
    /// Optional explicit ID; if `None`, store generates a compact hex ID.
    pub id: Option<String>,
    /// Optional explicit thread ID; if `None`, store resolves via `in_reply_to`/`references_header` or creates a new one.
    pub thread_id: Option<String>,
    pub label_ids: Vec<String>,
    pub raw_rfc2822: Vec<u8>,
    pub snippet: String,
    pub internal_date_ms: i64,
    pub subject: String,
    pub from_addr: String,
    pub to_addrs: Vec<String>,
    pub cc_addrs: Vec<String>,
    pub bcc_addrs: Vec<String>,
    pub text_body: String,
    pub html_body: Option<String>,
    pub rfc822_message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references_header: Option<String>,
    pub resend_id: Option<String>,
    pub upstream_gmail_id: Option<String>,
    pub upstream_thread_id: Option<String>,
    pub source: String,
    pub is_answered: bool,
    pub is_deleted: bool,
    pub attachments: Vec<NewAttachmentInput>,
}

#[derive(Debug, Clone, Default)]
pub struct NewLabelInput {
    pub name: String,
    pub message_list_visibility: Option<String>,
    pub label_list_visibility: Option<String>,
    pub color: Option<LabelColor>,
    pub upstream_label_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct UpdateLabelInput {
    pub name: Option<String>,
    pub message_list_visibility: Option<String>,
    pub label_list_visibility: Option<String>,
    pub color: Option<LabelColor>,
}

// ============================================================================
// Query & Pagination Types
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct MessageListQuery {
    pub q: Option<String>,
    pub label_ids: Vec<String>,
    pub include_spam_trash: bool,
    pub max_results: usize,
    pub page_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MessageListPage {
    pub messages: Vec<StoredMessage>,
    pub next_page_token: Option<String>,
    pub result_size_estimate: u32,
}

#[derive(Debug, Clone)]
pub struct ThreadListPage {
    pub threads: Vec<StoredThreadDetail>,
    pub next_page_token: Option<String>,
    pub result_size_estimate: u32,
}

#[derive(Debug, Clone)]
pub struct DraftListPage {
    pub drafts: Vec<StoredDraft>,
    pub next_page_token: Option<String>,
    pub result_size_estimate: u32,
}

#[derive(Debug, Clone, Default)]
pub struct HistoryListQuery {
    pub start_history_id: u64,
    pub max_results: usize,
    pub page_token: Option<String>,
    pub label_id: Option<String>,
    pub history_types: Vec<HistoryEventKind>,
}

#[derive(Debug, Clone)]
pub struct HistoryListPage {
    pub entries: Vec<StoredHistoryEntry>,
    pub next_page_token: Option<String>,
    pub current_history_id: u64,
}

// --- AI-First Search & Thread Queries ---

#[derive(Debug, Clone, Default)]
pub struct AiSearchQuery {
    pub q: Option<String>,
    pub labels: Vec<String>,
    pub thread_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub after: Option<DateTime<Utc>>,
    pub before: Option<DateTime<Utc>>,
    pub has_attachment: Option<bool>,
    pub include_spam_trash: bool,
    pub limit: usize,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AiMessagePage {
    pub messages: Vec<StoredMessage>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AiThreadQuery {
    pub q: Option<String>,
    pub label: Option<String>,
    pub unread_only: bool,
    pub include_spam_trash: bool,
    pub limit: usize,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AiThreadPage {
    pub threads: Vec<ThreadSummary>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TriagePatch {
    pub add_labels: Vec<String>,
    pub remove_labels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResult {
    pub thread_id: String,
    pub affected_message_ids: Vec<String>,
    pub labels: Vec<String>,
}

// ============================================================================
// IMAP & Sync Storage Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImapMailboxInfo {
    pub name: String,
    /// `None` for virtual `[Gmail]/All Mail`.
    pub label_id: Option<String>,
    /// RFC 6154 special-use attribute, e.g. `Some("\\Sent")`, `Some("\\All")`.
    pub special_use: Option<String>,
    pub uid_validity: u32,
    pub uid_next: u32,
    pub messages: u32,
    pub unseen: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImapMessageEntry {
    /// 1-based sequence number in the selected mailbox.
    pub seq: u32,
    /// Monotonic per-mailbox UID.
    pub uid: u32,
    pub message_id: String,
    pub thread_id: String,
    pub internal_date_ms: i64,
    pub size_estimate: i32,
    pub label_ids: Vec<String>,
    pub is_answered: bool,
    pub is_deleted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpsertOutcomeKind {
    Inserted,
    Updated,
    Deduplicated,
}

#[derive(Debug, Clone)]
pub struct UpsertOutcome {
    pub kind: UpsertOutcomeKind,
    pub message: StoredMessage,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncState {
    pub account_key: String,
    /// `"gmail_api"` or `"gmail_imap"`.
    pub provider: String,
    pub last_history_id: Option<String>,
    pub imap_mailbox: Option<String>,
    pub imap_uid_validity: Option<u32>,
    pub imap_last_uid: Option<u32>,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_full_sync_at: Option<DateTime<Utc>>,
    pub status: String,
    pub last_error: Option<String>,
    pub messages_synced: u64,
}

// ============================================================================
// Gmail Watch & Settings Storage Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchSubscription {
    pub topic_name: String,
    pub label_ids: Vec<String>,
    pub label_filter_behavior: String,
    pub history_id: u64,
    pub expiration_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSettings {
    pub send_as: Vec<SendAs>,
    pub vacation: VacationSettings,
    pub auto_forwarding: AutoForwarding,
    pub imap: ImapSettings,
    pub pop: PopSettings,
}

impl UserSettings {
    pub fn default_for_email(email: &str) -> Self {
        Self {
            send_as: vec![SendAs {
                send_as_email: email.to_string(),
                display_name: None,
                reply_to_address: None,
                signature: None,
                is_primary: Some(true),
                is_default: Some(true),
                treat_as_alias: Some(false),
                smtp_msa: None,
                verification_status: Some("accepted".to_string()),
            }],
            vacation: VacationSettings {
                enable_auto_reply: Some(false),
                ..Default::default()
            },
            auto_forwarding: AutoForwarding {
                enabled: Some(false),
                ..Default::default()
            },
            imap: ImapSettings {
                enabled: Some(true),
                auto_expunge: Some(true),
                expunge_behavior: Some("archive".to_string()),
                max_folder_size: Some(0),
            },
            pop: PopSettings {
                access_window: Some("disabled".to_string()),
                disposition: Some("leaveInInbox".to_string()),
            },
        }
    }
}

/// Helper to parse `"Name <a@b.com>"` or `"a@b.com"` into an `EmailAddress` for storage summaries.
pub fn parse_simple_email_address(raw: &str) -> EmailAddress {
    let trimmed = raw.trim();
    if let (Some(lt), Some(gt)) = (trimmed.find('<'), trimmed.rfind('>'))
        && lt < gt
    {
        let name = trimmed[..lt].trim().trim_matches('"').trim();
        let email = trimmed[lt + 1..gt].trim();
        return EmailAddress {
            name: (!name.is_empty()).then(|| name.to_string()),
            email: email.to_string(),
        };
    }
    EmailAddress {
        name: None,
        email: trimmed.to_string(),
    }
}

// ============================================================================
// Pluggable Async `MailStore` Trait
// ============================================================================

#[async_trait]
pub trait MailStore: Send + Sync {
    // --- Profile & History ---
    async fn get_profile(&self, email_address: &str) -> AppResult<Profile>;
    async fn current_history_id(&self) -> AppResult<u64>;
    async fn list_history(&self, query: &HistoryListQuery) -> AppResult<HistoryListPage>;

    // --- Messages ---
    async fn insert_message(&self, input: NewMessageInput) -> AppResult<StoredMessage>;
    async fn get_message(&self, id: &str) -> AppResult<Option<StoredMessage>>;
    async fn list_messages(&self, query: &MessageListQuery) -> AppResult<MessageListPage>;
    async fn modify_message_labels(
        &self,
        id: &str,
        add_labels: &[String],
        remove_labels: &[String],
    ) -> AppResult<StoredMessage>;
    async fn batch_modify_labels(
        &self,
        ids: &[String],
        add_labels: &[String],
        remove_labels: &[String],
    ) -> AppResult<()>;
    async fn trash_message(&self, id: &str) -> AppResult<StoredMessage>;
    async fn untrash_message(&self, id: &str) -> AppResult<StoredMessage>;
    async fn delete_message(&self, id: &str) -> AppResult<bool>;
    async fn batch_delete_messages(&self, ids: &[String]) -> AppResult<()>;

    // --- Attachments ---
    async fn get_attachment(
        &self,
        message_id: &str,
        attachment_id: &str,
    ) -> AppResult<Option<StoredAttachment>>;
    async fn list_attachment_meta(&self, message_id: &str) -> AppResult<Vec<AttachmentMeta>>;

    // --- Threads ---
    async fn list_threads(&self, query: &MessageListQuery) -> AppResult<ThreadListPage>;
    async fn get_thread(&self, thread_id: &str) -> AppResult<Option<StoredThreadDetail>>;
    async fn modify_thread_labels(
        &self,
        thread_id: &str,
        add_labels: &[String],
        remove_labels: &[String],
    ) -> AppResult<StoredThreadDetail>;
    async fn trash_thread(&self, thread_id: &str) -> AppResult<StoredThreadDetail>;
    async fn untrash_thread(&self, thread_id: &str) -> AppResult<StoredThreadDetail>;
    async fn delete_thread(&self, thread_id: &str) -> AppResult<bool>;

    // --- Labels ---
    async fn list_labels(&self) -> AppResult<Vec<StoredLabel>>;
    async fn get_label(&self, id: &str) -> AppResult<Option<StoredLabel>>;
    async fn create_label(&self, input: NewLabelInput) -> AppResult<StoredLabel>;
    async fn update_label(
        &self,
        id: &str,
        input: UpdateLabelInput,
        full_replace: bool,
    ) -> AppResult<StoredLabel>;
    async fn delete_label(&self, id: &str) -> AppResult<()>;
    async fn upsert_upstream_label(&self, input: NewLabelInput) -> AppResult<StoredLabel>;

    // --- Drafts ---
    async fn list_drafts(&self, query: &MessageListQuery) -> AppResult<DraftListPage>;
    async fn get_draft(&self, id: &str) -> AppResult<Option<StoredDraft>>;
    async fn create_draft(&self, message: NewMessageInput) -> AppResult<StoredDraft>;
    async fn update_draft(&self, draft_id: &str, message: NewMessageInput)
        -> AppResult<StoredDraft>;
    async fn delete_draft(&self, draft_id: &str) -> AppResult<bool>;

    // --- AI-First Search & Triage ---
    async fn search_messages_ai(&self, query: &AiSearchQuery) -> AppResult<AiMessagePage>;
    async fn list_thread_summaries(&self, query: &AiThreadQuery) -> AppResult<AiThreadPage>;
    async fn triage_thread(&self, thread_id: &str, patch: &TriagePatch) -> AppResult<TriageResult>;

    // --- Resend Webhook & Lookup Helpers ---
    async fn find_message_by_resend_id(&self, resend_id: &str) -> AppResult<Option<StoredMessage>>;
    async fn find_message_by_rfc_message_id(
        &self,
        rfc822_message_id: &str,
    ) -> AppResult<Option<StoredMessage>>;
    async fn record_delivery_status(
        &self,
        resend_id: &str,
        status: &str,
    ) -> AppResult<Option<StoredMessage>>;

    // --- IMAP Operations (per-mailbox monotonic UIDs) ---
    async fn imap_list_mailboxes(&self) -> AppResult<Vec<ImapMailboxInfo>>;
    async fn imap_mailbox_info(&self, mailbox_name: &str) -> AppResult<Option<ImapMailboxInfo>>;
    async fn imap_list_messages(&self, mailbox_name: &str) -> AppResult<Vec<ImapMessageEntry>>;
    async fn imap_set_flags(
        &self,
        message_id: &str,
        is_seen: bool,
        is_flagged: bool,
        is_draft: bool,
        is_answered: bool,
        is_deleted: bool,
    ) -> AppResult<StoredMessage>;
    /// Expunges messages marked `is_deleted` in `mailbox_name` and returns their 1-based sequence numbers (pre-expunge).
    async fn imap_expunge(&self, mailbox_name: &str) -> AppResult<Vec<u32>>;
    /// Copies or moves `message_ids` from `src_mailbox` to `dst_mailbox`; returns `(src_uid, dst_uid)` pairs.
    async fn imap_copy_or_move(
        &self,
        src_mailbox: &str,
        dst_mailbox: &str,
        message_ids: &[String],
        is_move: bool,
    ) -> AppResult<Vec<(u32, u32)>>;
    /// Appends a raw message directly into `mailbox_name`, returning `(uid_validity, assigned_uid, StoredMessage)`.
    async fn imap_append(
        &self,
        mailbox_name: &str,
        input: NewMessageInput,
    ) -> AppResult<(u32, u32, StoredMessage)>;

    // --- Upstream Sync & Deduplication ---
    async fn upsert_synced_message(&self, input: NewMessageInput) -> AppResult<UpsertOutcome>;
    async fn find_message_by_upstream_id(
        &self,
        upstream_gmail_id: &str,
    ) -> AppResult<Option<StoredMessage>>;
    async fn delete_message_by_upstream_id(
        &self,
        upstream_gmail_id: &str,
    ) -> AppResult<Option<StoredMessage>>;
    async fn get_sync_state(&self, account_key: &str) -> AppResult<Option<SyncState>>;
    async fn save_sync_state(&self, state: SyncState) -> AppResult<()>;
    async fn list_sync_states(&self) -> AppResult<Vec<SyncState>>;

    // --- Gmail Watch & User Settings (Superhuman compatibility) ---
    async fn set_watch(&self, watch: WatchSubscription) -> AppResult<WatchSubscription>;
    async fn get_watch(&self) -> AppResult<Option<WatchSubscription>>;
    async fn clear_watch(&self) -> AppResult<()>;
    async fn get_settings(&self) -> AppResult<UserSettings>;
    async fn save_settings(&self, settings: UserSettings) -> AppResult<UserSettings>;
}

/// Construct the configured `MailStore` implementation (`sqlite` or `memory`).
pub fn open_store(config: &Config) -> AppResult<Arc<dyn MailStore>> {
    match config.storage {
        StorageBackend::Sqlite => {
            let store = SqliteStore::open(&config.db_path, &config.user_email)?;
            Ok(Arc::new(store))
        }
        StorageBackend::Memory => Ok(Arc::new(MemoryStore::new(&config.user_email))),
    }
}
