//! Pluggable storage abstraction (`MailStore`) and backend factory.
//!
//! No SQLite types or SQL statements are exposed from this module. All HTTP, MCP,
//! IMAP, Resend, and Sync modules depend solely on `Arc<dyn MailStore>`.

pub mod memory;
#[cfg(feature = "postgres")]
pub mod postgres;
pub mod sqlite;

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    auth::Principal,
    config::{Config, StorageBackend},
    error::{AppError, AppResult},
    models::{
        AttachmentMeta, AutoForwarding, ContactSummary, EmailAddress, ImapSettings, LABEL_DRAFT,
        LABEL_STARRED, LABEL_UNREAD, LabelColor, PopSettings, Profile, SendAs, ThreadSummary,
        UnsubscribeInfo, VacationSettings,
    },
    transport::OutboundMessage,
};

pub use crate::models::{ThreadAnnotation, ThreadAnnotationPatch, WaitingOn};
pub use memory::MemoryStore;
#[cfg(feature = "postgres")]
pub use postgres::{PG_EVENTS_CHANNEL, PostgresEventBridge, PostgresStore};
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

    /// Pre-parsed RFC 2369 / 8058 `List-Unsubscribe` metadata captured at ingest time so
    /// thread/message reads never need to download offloaded raw RFC 2822 blobs just to
    /// inspect unsubscribe headers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsubscribe: Option<UnsubscribeInfo>,
}

/// Hard ceiling applied to caller-supplied SQL `LIMIT` values before casting to `i64`
/// so extreme values like `usize::MAX` never wrap negative.
pub const MAX_SQL_LIMIT: usize = 10_000;

/// Clamp a caller-supplied `limit` (`0` -> `default`) into `[1, max]` before casting to `i64`.
pub fn clamp_sql_limit(limit: usize, default: usize, max: usize) -> i64 {
    let effective = if limit == 0 { default } else { limit };
    effective.clamp(1, max.max(1)) as i64
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

/// History event origin: local API/MCP/IMAP/rule mutation.
pub const HISTORY_SOURCE_LOCAL: &str = "local";
/// History event origin: upstream sync pull (`upsert_synced_message`, upstream delete/modify).
pub const HISTORY_SOURCE_SYNC: &str = "sync";

/// Default stale-lease threshold (5 minutes) for reclaiming orphaned `Sending` scheduled sends.
pub const DEFAULT_SCHEDULED_SEND_STALE_LEASE_MS: i64 = 5 * 60 * 1000;

fn default_history_source() -> String {
    HISTORY_SOURCE_LOCAL.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredHistoryEntry {
    pub history_id: u64,
    pub kind: HistoryEventKind,
    pub message_id: String,
    pub thread_id: String,
    pub label_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_gmail_id: Option<String>,
    #[serde(default = "default_history_source")]
    pub source: String,
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
    pub unread: Option<bool>,
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
    pub needs_reply: Option<bool>,
    pub waiting_on: Option<WaitingOn>,
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
    /// Monotonic store `history_id` backing RFC 7162 `MODSEQ`.
    pub history_id: u64,
    pub internal_date_ms: i64,
    pub size_estimate: i32,
    pub label_ids: Vec<String>,
    pub is_answered: bool,
    pub is_deleted: bool,
}

impl ImapMessageEntry {
    /// RFC 7162 non-zero modification sequence (`MODSEQ`) derived from `history_id`.
    pub fn modseq(&self) -> u64 {
        self.history_id.max(1)
    }
}

/// Result of expunging a single `\Deleted` message from an IMAP mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImapExpungedEntry {
    /// 1-based sequence number in the mailbox immediately before expunge.
    pub seq: u32,
    /// Mailbox-specific UID of the expunged message.
    pub uid: u32,
    pub message_id: String,
    pub thread_id: String,
    pub label_ids: Vec<String>,
    /// `true` when permanently deleted from storage (Trash expunge), `false` when moved to Trash.
    pub permanently_deleted: bool,
    /// Attachment IDs belonging to the message when `permanently_deleted` is `true`,
    /// enabling callers to clean up external `BlobStore` objects.
    pub attachment_ids: Vec<String>,
}

/// Mode for an IMAP `STORE` / `UID STORE` flag update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImapFlagAction {
    Replace,
    Add,
    Remove,
}

/// Set of IMAP system flags (`\Seen`, `\Flagged`, `\Draft`, `\Answered`, `\Deleted`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImapFlagSet {
    pub seen: bool,
    pub flagged: bool,
    pub draft: bool,
    pub answered: bool,
    pub deleted: bool,
}

impl ImapFlagSet {
    /// Compute resulting flags given `current` message flags and an `action`.
    pub fn apply(self, current: Self, action: ImapFlagAction) -> Self {
        match action {
            ImapFlagAction::Replace => self,
            ImapFlagAction::Add => Self {
                seen: current.seen || self.seen,
                flagged: current.flagged || self.flagged,
                draft: current.draft || self.draft,
                answered: current.answered || self.answered,
                deleted: current.deleted || self.deleted,
            },
            ImapFlagAction::Remove => Self {
                seen: current.seen && !self.seen,
                flagged: current.flagged && !self.flagged,
                draft: current.draft && !self.draft,
                answered: current.answered && !self.answered,
                deleted: current.deleted && !self.deleted,
            },
        }
    }

    /// Derive the current [`ImapFlagSet`] from a [`StoredMessage`].
    pub fn from_message(msg: &StoredMessage) -> Self {
        Self {
            seen: !msg.label_ids.iter().any(|l| l == LABEL_UNREAD),
            flagged: msg.label_ids.iter().any(|l| l == LABEL_STARRED),
            draft: msg.label_ids.iter().any(|l| l == LABEL_DRAFT),
            answered: msg.is_answered,
            deleted: msg.is_deleted,
        }
    }
}

/// Outcome of an atomic [`MailStore::imap_store_flags`] operation.
#[derive(Debug, Clone)]
pub enum ImapStoreFlagsOutcome {
    Updated(Box<StoredMessage>),
    /// Atomic `UNCHANGEDSINCE` precondition failed because current `MODSEQ > unchanged_since`.
    Modified,
    /// Message was concurrently deleted before flags could be updated.
    NotFound,
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
    /// `"gmail_api"`, `"gmail_imap"`, or a custom `SyncSource` provider name.
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
    /// Local `MailStore` history checkpoint up to which local mutations have been pushed upstream.
    #[serde(default)]
    pub last_pushed_history_id: Option<u64>,
    /// Cumulative count of local message mutations pushed back upstream.
    #[serde(default)]
    pub messages_pushed: u64,
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

// ============================================================================
// Human-in-the-Loop Outbound Approval Queue Types
// ============================================================================

/// Lifecycle status of a held outbound email awaiting human approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approving,
    Approved,
    Rejected,
    Expired,
}

impl ApprovalStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approving => "approving",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn parse_str(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "pending" => Some(Self::Pending),
            "approving" => Some(Self::Approving),
            "approved" => Some(Self::Approved),
            "rejected" => Some(Self::Rejected),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }
}

impl std::fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Persistent record for an outbound send held by `OutboundPolicy::HoldForApproval`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApproval {
    pub id: String,
    pub status: ApprovalStatus,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<Principal>,
    pub outbound_message: OutboundMessage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to_message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_note: Option<String>,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at_ms: Option<i64>,
}

/// Input used to enqueue a new pending human-in-the-loop approval.
#[derive(Debug, Clone)]
pub struct NewPendingApprovalInput {
    pub id: Option<String>,
    pub reason: String,
    pub requester: Option<Principal>,
    pub outbound_message: OutboundMessage,
    pub reply_to_message_id: Option<String>,
    pub thread_id: Option<String>,
    pub draft_id: Option<String>,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

// ============================================================================
// Per-Mailbox Contact Graph & VIP Detection Types
// ============================================================================

/// Minimum `replied_by_me_count` required to infer VIP status automatically when
/// no manual `vip_override` has been set.
pub const VIP_REPLY_THRESHOLD: u64 = 3;

/// Direction of an observed email interaction with a contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactDirection {
    Sent,
    Received,
}

/// Single observed contact interaction recorded when storing sent or received mail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInteraction {
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub direction: ContactDirection,
    #[serde(default)]
    pub is_reply: bool,
    pub timestamp_ms: i64,
}

/// Per-mailbox contact profile derived from sent/received mail and optional user overrides.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactRecord {
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub domain: String,
    pub sent_count: u64,
    pub received_count: u64,
    pub replied_by_me_count: u64,
    pub first_seen_at_ms: i64,
    pub last_seen_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_replied_at_ms: Option<i64>,
    pub is_vip: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vip_override: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl ContactRecord {
    pub fn to_summary(&self) -> ContactSummary {
        ContactSummary {
            email: self.email.clone(),
            display_name: self.display_name.clone(),
            domain: self.domain.clone(),
            sent_count: self.sent_count,
            received_count: self.received_count,
            replied_by_me_count: self.replied_by_me_count,
            is_vip: self.is_vip,
            last_replied_at_ms: self.last_replied_at_ms,
            notes: self.notes.clone(),
        }
    }
}

impl From<&ContactRecord> for ContactSummary {
    fn from(value: &ContactRecord) -> Self {
        value.to_summary()
    }
}

impl From<ContactRecord> for ContactSummary {
    fn from(value: ContactRecord) -> Self {
        ContactSummary {
            email: value.email,
            display_name: value.display_name,
            domain: value.domain,
            sent_count: value.sent_count,
            received_count: value.received_count,
            replied_by_me_count: value.replied_by_me_count,
            is_vip: value.is_vip,
            last_replied_at_ms: value.last_replied_at_ms,
            notes: value.notes,
        }
    }
}

/// Filter parameters for `MailStore::list_contacts`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContactQuery {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub vip_only: bool,
    #[serde(default)]
    pub replied_only: bool,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub limit: usize,
}

/// Partial update payload for `MailStore::patch_contact`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContactPatch {
    #[serde(default)]
    pub is_vip: Option<bool>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

/// Compute effective VIP status from an optional manual override and reply count.
pub fn compute_contact_is_vip(vip_override: Option<bool>, replied_by_me_count: u64) -> bool {
    vip_override.unwrap_or(replied_by_me_count >= VIP_REPLY_THRESHOLD)
}

/// Normalize a raw email string or `"Name <email>"` header into a lowercase bare email address.
pub fn normalize_contact_email(raw: &str) -> String {
    let parsed = parse_simple_email_address(raw);
    parsed.email.trim().to_ascii_lowercase()
}

/// Extract the lowercase domain portion of an email address (empty if `@` is absent).
pub fn extract_email_domain(email: &str) -> String {
    email
        .rsplit_once('@')
        .map(|(_, d)| d.trim().to_ascii_lowercase())
        .unwrap_or_default()
}

/// Normalize an optional string field by trimming whitespace and turning empty strings into `None`.
pub fn normalize_optional_text(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Normalize a contact email and validate that it contains a non-empty local part and domain.
pub fn validate_and_normalize_contact_email(raw: &str) -> AppResult<(String, String)> {
    let email = normalize_contact_email(raw);
    let Some((local, domain)) = email.split_once('@') else {
        return Err(AppError::BadRequest(format!(
            "Invalid contact email address: '{raw}'"
        )));
    };
    if local.is_empty()
        || domain.is_empty()
        || domain.contains('@')
        || email.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(AppError::BadRequest(format!(
            "Invalid contact email address: '{raw}'"
        )));
    }
    Ok((email.clone(), domain.to_string()))
}

// ============================================================================
// Idempotency Keys & Immutable Audit Log Types
// ============================================================================

/// Persisted JSON response cached under `(mailbox_id, scope, key)` until `expires_at_ms`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdempotencyRecord {
    pub key: String,
    pub scope: String,
    pub response_json: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

/// Immutable append-only audit log entry recording an agent or API operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub mailbox_id: String,
    pub timestamp_ms: i64,
    pub actor: String,
    pub scopes: Vec<String>,
    pub channel: String,
    pub action: String,
    pub target_ids: Vec<String>,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Input used to append a new immutable audit log entry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewAuditLogEntry {
    #[serde(default)]
    pub timestamp_ms: Option<i64>,
    pub actor: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub channel: String,
    pub action: String,
    #[serde(default)]
    pub target_ids: Vec<String>,
    pub outcome: String,
    #[serde(default)]
    pub detail: Option<String>,
}

/// Filter parameters for querying the append-only audit log (newest-first).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLogQuery {
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub since_ms: Option<i64>,
    #[serde(default)]
    pub limit: usize,
}

// ============================================================================
// Thread Snooze & Scheduled Outbound Send Types
// ============================================================================

/// Persisted snooze record for a conversation thread scoped to `(mailbox_id, thread_id)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnoozedThread {
    pub thread_id: String,
    pub mailbox_id: String,
    pub snooze_until_ms: i64,
    pub created_at_ms: i64,
}

/// Lifecycle status of a scheduled outbound email (`send_at`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduledSendStatus {
    Pending,
    Sending,
    Sent,
    Canceled,
    Failed,
}

impl ScheduledSendStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sending => "sending",
            Self::Sent => "sent",
            Self::Canceled => "canceled",
            Self::Failed => "failed",
        }
    }

    pub fn parse_str(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "pending" => Some(Self::Pending),
            "sending" => Some(Self::Sending),
            "sent" => Some(Self::Sent),
            "canceled" | "cancelled" => Some(Self::Canceled),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

impl std::fmt::Display for ScheduledSendStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Persistent record for an outbound email scheduled for future delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledSend {
    pub id: String,
    pub mailbox_id: String,
    pub status: ScheduledSendStatus,
    pub send_at_ms: i64,
    pub outbound_message: OutboundMessage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to_message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

/// Input used to enqueue a new scheduled outbound email.
#[derive(Debug, Clone)]
pub struct NewScheduledSend {
    pub id: Option<String>,
    pub send_at_ms: i64,
    pub outbound_message: OutboundMessage,
    pub reply_to_message_id: Option<String>,
    pub thread_id: Option<String>,
    pub created_at_ms: i64,
}

// ============================================================================
// Per-Mailbox Event-Driven Inbox Rules Types
// ============================================================================

fn default_inbox_rule_enabled() -> bool {
    true
}

/// Actions applied when an [`InboxRule`] matches an inbound message.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxRuleActions {
    #[serde(default)]
    pub add_labels: Vec<String>,
    #[serde(default)]
    pub remove_labels: Vec<String>,
    #[serde(default)]
    pub archive: bool,
    #[serde(default)]
    pub mark_read: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_secret: Option<String>,
}

impl std::fmt::Debug for InboxRuleActions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboxRuleActions")
            .field("add_labels", &self.add_labels)
            .field("remove_labels", &self.remove_labels)
            .field("archive", &self.archive)
            .field("mark_read", &self.mark_read)
            .field("webhook_url", &self.webhook_url)
            .field(
                "webhook_secret",
                &self
                    .webhook_secret
                    .as_ref()
                    .map(|_| crate::secrets::REDACTED),
            )
            .finish()
    }
}

/// Persistent per-mailbox declarative inbox rule evaluated on inbound ingestion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxRule {
    pub id: String,
    pub mailbox_id: String,
    pub name: String,
    pub enabled: bool,
    pub match_query: String,
    pub vip_only: bool,
    pub actions: InboxRuleActions,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

/// Input payload used to create a new [`InboxRule`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewInboxRule {
    pub name: String,
    #[serde(default = "default_inbox_rule_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub match_query: String,
    #[serde(default)]
    pub vip_only: bool,
    #[serde(default)]
    pub actions: InboxRuleActions,
}

impl Default for NewInboxRule {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            match_query: String::new(),
            vip_only: false,
            actions: InboxRuleActions::default(),
        }
    }
}

/// Partial update payload for [`MailStore::patch_inbox_rule`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxRulePatch {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub match_query: Option<String>,
    #[serde(default)]
    pub vip_only: Option<bool>,
    #[serde(default)]
    pub actions: Option<InboxRuleActions>,
}

/// Redacted API projection of [`InboxRuleActions`] that never exposes `webhook_secret`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxRuleActionsView {
    pub add_labels: Vec<String>,
    pub remove_labels: Vec<String>,
    pub archive: bool,
    pub mark_read: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    pub has_webhook_secret: bool,
}

/// Redacted API projection of [`InboxRule`] returned by REST `/v1/rules` and MCP tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxRuleView {
    pub id: String,
    pub mailbox_id: String,
    pub name: String,
    pub enabled: bool,
    pub match_query: String,
    pub vip_only: bool,
    pub actions: InboxRuleActionsView,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl InboxRule {
    /// Convert this rule into a redacted API view that replaces `webhook_secret` with
    /// `has_webhook_secret: bool`.
    pub fn to_view(&self) -> InboxRuleView {
        InboxRuleView {
            id: self.id.clone(),
            mailbox_id: self.mailbox_id.clone(),
            name: self.name.clone(),
            enabled: self.enabled,
            match_query: self.match_query.clone(),
            vip_only: self.vip_only,
            actions: InboxRuleActionsView {
                add_labels: self.actions.add_labels.clone(),
                remove_labels: self.actions.remove_labels.clone(),
                archive: self.actions.archive,
                mark_read: self.actions.mark_read,
                webhook_url: self.actions.webhook_url.clone(),
                has_webhook_secret: self
                    .actions
                    .webhook_secret
                    .as_deref()
                    .is_some_and(|s| !s.is_empty()),
            },
            created_at_ms: self.created_at_ms,
            updated_at_ms: self.updated_at_ms,
        }
    }
}

impl From<InboxRule> for InboxRuleView {
    fn from(rule: InboxRule) -> Self {
        rule.to_view()
    }
}

impl From<&InboxRule> for InboxRuleView {
    fn from(rule: &InboxRule) -> Self {
        rule.to_view()
    }
}

fn normalize_label_list(labels: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(labels.len());
    for raw in labels {
        let trimmed = raw.trim();
        if !trimmed.is_empty() && !out.iter().any(|existing: &String| existing == trimmed) {
            out.push(trimmed.to_string());
        }
    }
    out
}

/// Normalize [`InboxRuleActions`] by trimming/deduplicating labels and turning blank URLs/secrets
/// into `None`.
pub fn normalize_inbox_rule_actions(actions: &InboxRuleActions) -> InboxRuleActions {
    InboxRuleActions {
        add_labels: normalize_label_list(&actions.add_labels),
        remove_labels: normalize_label_list(&actions.remove_labels),
        archive: actions.archive,
        mark_read: actions.mark_read,
        webhook_url: normalize_optional_text(actions.webhook_url.as_deref()),
        webhook_secret: normalize_optional_text(actions.webhook_secret.as_deref()),
    }
}

/// Apply an [`InboxRulePatch`] onto an existing [`InboxRule`], returning the updated rule.
pub fn apply_inbox_rule_patch(
    mut existing: InboxRule,
    patch: &InboxRulePatch,
    now_ms: i64,
) -> InboxRule {
    if let Some(ref name) = patch.name {
        existing.name = name.trim().to_string();
    }
    if let Some(enabled) = patch.enabled {
        existing.enabled = enabled;
    }
    if let Some(ref match_query) = patch.match_query {
        existing.match_query = match_query.trim().to_string();
    }
    if let Some(vip_only) = patch.vip_only {
        existing.vip_only = vip_only;
    }
    if let Some(ref actions) = patch.actions {
        existing.actions = normalize_inbox_rule_actions(actions);
    }
    existing.updated_at_ms = now_ms;
    existing
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

fn is_valid_bare_addr_spec(email: &str) -> bool {
    let mut parts = email.split('@');
    let Some(local) = parts.next() else {
        return false;
    };
    let Some(domain) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    if local.is_empty() || local.len() > 64 || domain.is_empty() || domain.len() > 255 {
        return false;
    }
    if local.chars().any(|c| {
        c.is_whitespace()
            || c.is_control()
            || matches!(
                c,
                ',' | ';' | '<' | '>' | '"' | '\\' | '(' | ')' | ':' | '[' | ']'
            )
    }) || domain.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return false;
    }
    domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

fn parse_quoted_display_name(raw: &str) -> Result<String, String> {
    let mut chars = raw.chars();
    if chars.next() != Some('"') {
        return Err("Display name does not start with '\"'".to_string());
    }
    let mut unescaped = String::new();
    let mut escaped = false;
    let mut closed = false;
    for ch in chars {
        if closed {
            return Err("Unexpected characters after closing quote in display name".to_string());
        }
        if escaped {
            if matches!(ch, '<' | '>' | '@' | '\r' | '\n' | '\0') || ch.is_control() {
                return Err("Disallowed character in quoted display name".to_string());
            }
            unescaped.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            closed = true;
        } else {
            if matches!(ch, '<' | '>' | '@' | '\r' | '\n' | '\0') || ch.is_control() {
                return Err("Disallowed character in quoted display name".to_string());
            }
            unescaped.push(ch);
        }
    }
    if !closed || escaped {
        return Err("Unclosed quoted display name".to_string());
    }
    Ok(unescaped.trim().to_string())
}

/// Strictly parse a single RFC 5322 mailbox (`"addr@example.com"`, `"<addr@example.com>"`,
/// `"Name <addr@example.com>"`, or `"\"Last, First\" <addr@example.com>"`).
///
/// Rejects multi-address lists, trailing tokens after `>`, multiple `<...>` pairs,
/// and unquoted `,`, `;`, `<`, `>`, `@`, `"`, `\`, `(`, `)` inside display names.
pub fn parse_strict_single_mailbox(raw: &str) -> Result<EmailAddress, String> {
    if raw.contains('\r') || raw.contains('\n') || raw.contains('\0') {
        return Err("Recipient contains disallowed CR/LF/NUL characters".to_string());
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Recipient address must not be empty".to_string());
    }
    if trimmed
        .bytes()
        .any(|b| (b < 0x20 && b != b'\t') || b == 0x7f)
    {
        return Err("Recipient contains disallowed control characters".to_string());
    }

    let has_lt = trimmed.contains('<');
    let has_gt = trimmed.contains('>');
    if !has_lt && !has_gt {
        if !is_valid_bare_addr_spec(trimmed) {
            return Err(format!("Invalid email address '{trimmed}'"));
        }
        return Ok(EmailAddress {
            name: None,
            email: trimmed.to_string(),
        });
    }

    if !trimmed.ends_with('>') {
        return Err(format!(
            "Recipient '{trimmed}' has unexpected trailing characters after '>'"
        ));
    }
    let lt_count = trimmed.bytes().filter(|&b| b == b'<').count();
    let gt_count = trimmed.bytes().filter(|&b| b == b'>').count();
    if lt_count != 1 || gt_count != 1 {
        return Err(format!(
            "Recipient '{trimmed}' must contain exactly one '<...>' mailbox"
        ));
    }

    let lt = trimmed.find('<').expect("checked lt_count == 1");
    let gt = trimmed.len() - 1;
    if lt >= gt {
        return Err(format!("Malformed angle-bracket recipient '{trimmed}'"));
    }

    let display_raw = trimmed[..lt].trim();
    let email_raw = trimmed[lt + 1..gt].trim();
    if !is_valid_bare_addr_spec(email_raw) {
        return Err(format!(
            "Invalid email address '{email_raw}' inside '<...>'"
        ));
    }

    let name = if display_raw.is_empty() {
        None
    } else if display_raw.starts_with('"') {
        let parsed = parse_quoted_display_name(display_raw)?;
        (!parsed.is_empty()).then_some(parsed)
    } else {
        if display_raw.chars().any(|c| {
            matches!(c, ',' | ';' | '<' | '>' | '@' | '"' | '\\' | '(' | ')') || c.is_control()
        }) {
            return Err(format!(
                "Recipient display name '{display_raw}' contains disallowed unquoted characters"
            ));
        }
        Some(display_raw.to_string())
    };

    Ok(EmailAddress {
        name,
        email: email_raw.to_string(),
    })
}

/// Helper to parse `"Name <a@b.com>"` or `"a@b.com"` into an `EmailAddress` for storage summaries.
///
/// Enforces single-mailbox parsing so multi-address strings like
/// `"external@other.example, <alice@company.com>"` are never silently truncated to
/// `alice@company.com`.
pub fn parse_simple_email_address(raw: &str) -> EmailAddress {
    if let Ok(parsed) = parse_strict_single_mailbox(raw) {
        return parsed;
    }
    EmailAddress {
        name: None,
        email: raw.trim().to_string(),
    }
}

// ============================================================================
// Pluggable Async `MailStore` Trait
// ============================================================================

#[async_trait]
pub trait MailStore: Send + Sync {
    /// Short backend identifier reported by `GET /v1/capabilities`.
    fn backend_name(&self) -> &'static str {
        "custom"
    }

    /// Normalized lowercase mailbox identifier this store handle is scoped to.
    fn mailbox_id(&self) -> &str;

    /// Return a lightweight `MailStore` handle sharing the underlying backend state/pool
    /// while isolating all reads and writes strictly to `mailbox_id`.
    fn for_mailbox(&self, mailbox_id: &str) -> Arc<dyn MailStore>;

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
    async fn update_draft(
        &self,
        draft_id: &str,
        message: NewMessageInput,
    ) -> AppResult<StoredDraft>;
    async fn delete_draft(&self, draft_id: &str) -> AppResult<bool>;

    // --- AI-First Search & Triage ---
    async fn search_messages_ai(&self, query: &AiSearchQuery) -> AppResult<AiMessagePage>;
    async fn list_thread_summaries(&self, query: &AiThreadQuery) -> AppResult<AiThreadPage>;
    async fn triage_thread(&self, thread_id: &str, patch: &TriagePatch) -> AppResult<TriageResult>;

    // --- Thread Annotations ---
    async fn get_thread_annotation(&self, thread_id: &str) -> AppResult<Option<ThreadAnnotation>>;
    async fn upsert_thread_annotation(
        &self,
        thread_id: &str,
        annotation: &ThreadAnnotation,
    ) -> AppResult<ThreadAnnotation>;
    async fn patch_thread_annotation(
        &self,
        thread_id: &str,
        patch: &ThreadAnnotationPatch,
        updated_by: Option<&str>,
    ) -> AppResult<ThreadAnnotation>;
    async fn delete_thread_annotation(&self, thread_id: &str) -> AppResult<()>;

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
    /// Record delivery status directly by local message ID (used when matching a delivery
    /// webhook via `rfc822_message_id` fallback even if `resend_id` is unset or differs).
    async fn record_delivery_status_by_message_id(
        &self,
        message_id: &str,
        status: &str,
    ) -> AppResult<Option<StoredMessage>> {
        if let Some(msg) = self.get_message(message_id).await?
            && let Some(rid) = msg.resend_id.as_deref()
        {
            return self.record_delivery_status(rid, status).await;
        }
        Ok(None)
    }

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
    /// Atomically apply an IMAP `STORE` flag mutation with optional RFC 7162 `UNCHANGEDSINCE` CAS.
    async fn imap_store_flags(
        &self,
        message_id: &str,
        action: ImapFlagAction,
        flags: ImapFlagSet,
        unchanged_since: Option<u64>,
    ) -> AppResult<ImapStoreFlagsOutcome> {
        let Some(old_msg) = self.get_message(message_id).await? else {
            return Ok(ImapStoreFlagsOutcome::NotFound);
        };
        if let Some(limit) = unchanged_since
            && old_msg.history_id.max(1) > limit
        {
            return Ok(ImapStoreFlagsOutcome::Modified);
        }
        let next = flags.apply(ImapFlagSet::from_message(&old_msg), action);
        let updated = self
            .imap_set_flags(
                message_id,
                next.seen,
                next.flagged,
                next.draft,
                next.answered,
                next.deleted,
            )
            .await?;
        Ok(ImapStoreFlagsOutcome::Updated(Box::new(updated)))
    }
    /// Expunges messages marked `is_deleted` in `mailbox_name` and returns their 1-based sequence numbers (pre-expunge).
    async fn imap_expunge(&self, mailbox_name: &str) -> AppResult<Vec<u32>>;
    /// Expunges `\Deleted` messages in `mailbox_name` matching `uid_ranges` (or all `\Deleted` messages
    /// when `uid_ranges` is `None`), returning rich [`ImapExpungedEntry`] records including attachment IDs
    /// for permanently deleted messages (Trash expunge).
    async fn imap_expunge_uids(
        &self,
        mailbox_name: &str,
        uid_ranges: Option<&[(u32, u32)]>,
    ) -> AppResult<Vec<ImapExpungedEntry>> {
        let _ = (mailbox_name, uid_ranges);
        Ok(Vec::new())
    }
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
    /// Return UIDs removed or expunged from `mailbox_name` with `modseq > since_modseq`, sorted ascending.
    ///
    /// Used by RFC 7162 `QRESYNC` (`SELECT ... (QRESYNC ...)` and `UID FETCH ... (CHANGEDSINCE ... VANISHED)`).
    async fn imap_vanished_uids(
        &self,
        mailbox_name: &str,
        since_modseq: u64,
    ) -> AppResult<Vec<u32>> {
        let _ = (mailbox_name, since_modseq);
        Ok(Vec::new())
    }

    // --- Upstream Sync & Deduplication ---
    async fn upsert_synced_message(&self, input: NewMessageInput) -> AppResult<UpsertOutcome>;
    /// Modify labels on a message due to an upstream sync pull, recording history with `source = "sync"`.
    async fn modify_synced_message_labels(
        &self,
        id: &str,
        add_labels: &[String],
        remove_labels: &[String],
    ) -> AppResult<StoredMessage> {
        self.modify_message_labels(id, add_labels, remove_labels)
            .await
    }
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

    // --- Human-in-the-Loop Outbound Approval Queue ---
    async fn create_pending_approval(
        &self,
        input: NewPendingApprovalInput,
    ) -> AppResult<PendingApproval>;
    async fn get_pending_approval(&self, id: &str) -> AppResult<Option<PendingApproval>>;
    async fn list_pending_approvals(
        &self,
        status: Option<ApprovalStatus>,
        limit: usize,
    ) -> AppResult<Vec<PendingApproval>>;
    /// Atomically claim a `Pending` non-expired approval for dispatch (transitioning to `Approving`)
    /// so concurrent replicas can never double-send.
    /// Returns `AppError::NotFound` if missing, or `AppError::Conflict` if already claimed/decided/expired.
    async fn claim_pending_approval(&self, id: &str, now_ms: i64) -> AppResult<PendingApproval> {
        let approval = self
            .get_pending_approval(id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Approval '{id}' not found")))?;
        if approval.status == ApprovalStatus::Expired || approval.expires_at_ms <= now_ms {
            let _ = self
                .resolve_pending_approval(id, ApprovalStatus::Approved, None, None, None, None)
                .await;
            return Err(AppError::Conflict(format!("Approval '{id}' has expired")));
        }
        if approval.status != ApprovalStatus::Pending {
            return Err(AppError::Conflict(format!(
                "Approval '{id}' is already {}",
                approval.status
            )));
        }
        Ok(approval)
    }
    /// Best-effort revert an `Approving` claim back to `Pending` when transport dispatch fails before sending.
    async fn release_claimed_approval(&self, _id: &str) -> AppResult<()> {
        Ok(())
    }
    /// Atomically transition a `Pending` (or `Approving` when finalizing `Approved`) approval to `Approved` or `Rejected`.
    /// Returns `AppError::NotFound` if missing, or `AppError::Conflict` if already decided or expired.
    async fn resolve_pending_approval(
        &self,
        id: &str,
        status: ApprovalStatus,
        decided_by: Option<String>,
        note: Option<String>,
        sent_message_id: Option<String>,
        provider_message_id: Option<String>,
    ) -> AppResult<PendingApproval>;

    // --- Per-Mailbox Contact Graph & VIP Detection ---
    async fn record_contact_interaction(
        &self,
        interaction: &ContactInteraction,
    ) -> AppResult<ContactRecord>;
    async fn get_contact(&self, email: &str) -> AppResult<Option<ContactRecord>>;
    async fn list_contacts(&self, query: &ContactQuery) -> AppResult<Vec<ContactRecord>>;
    async fn patch_contact(&self, email: &str, patch: &ContactPatch) -> AppResult<ContactRecord>;

    // --- Idempotency Keys ---
    /// Look up a non-expired idempotency record scoped to `(self.mailbox_id(), scope, key)`.
    /// Entries with `expires_at_ms <= now_ms` are ignored and return `Ok(None)`.
    async fn get_idempotency_key(
        &self,
        scope: &str,
        key: &str,
        now_ms: i64,
    ) -> AppResult<Option<IdempotencyRecord>>;
    /// Persist (or overwrite) an idempotency record scoped to `(self.mailbox_id(), scope, key)` with TTL in seconds.
    async fn put_idempotency_key(
        &self,
        scope: &str,
        key: &str,
        response_json: &str,
        ttl_secs: i64,
    ) -> AppResult<()>;

    // --- Immutable Audit Log (append-only; no update/delete API) ---
    async fn append_audit_log(&self, entry: &NewAuditLogEntry) -> AppResult<AuditLogEntry>;
    async fn list_audit_log(&self, query: &AuditLogQuery) -> AppResult<Vec<AuditLogEntry>>;

    // --- Thread Snooze ---
    async fn snooze_thread(&self, thread_id: &str, until_ms: i64) -> AppResult<SnoozedThread>;
    async fn unsnooze_thread(&self, thread_id: &str) -> AppResult<bool>;
    async fn list_snoozed_threads(
        &self,
        due_before_ms: Option<i64>,
    ) -> AppResult<Vec<SnoozedThread>>;
    /// Scan all mailboxes for snoozed threads due at or before `now_ms`.
    async fn list_all_due_snoozes(&self, now_ms: i64) -> AppResult<Vec<SnoozedThread>>;

    // --- Scheduled Outbound Sends ---
    async fn create_scheduled_send(&self, input: &NewScheduledSend) -> AppResult<ScheduledSend>;
    async fn get_scheduled_send(&self, id: &str) -> AppResult<Option<ScheduledSend>>;
    async fn list_scheduled_sends(
        &self,
        status: Option<ScheduledSendStatus>,
        limit: usize,
    ) -> AppResult<Vec<ScheduledSend>>;
    /// Atomically transition a `Pending` scheduled send to `Canceled`.
    /// Returns `AppError::NotFound` if missing, or `AppError::Conflict` if already sent/canceled/failed.
    async fn cancel_scheduled_send(&self, id: &str) -> AppResult<ScheduledSend>;
    /// Atomically claim due `Pending` scheduled sends (`send_at_ms <= now_ms`) and stale `Sending`
    /// leases (`stale_lease_ms > 0` and `updated_at_ms <= now_ms - stale_lease_ms`) across all
    /// mailboxes, transitioning them to `Sending` and returning ONLY rows claimed by this caller.
    async fn claim_due_scheduled_sends(
        &self,
        now_ms: i64,
        stale_lease_ms: i64,
    ) -> AppResult<Vec<ScheduledSend>>;
    /// Atomically transition a `Pending` or `Sending` scheduled send to `Sent`.
    async fn complete_scheduled_send(
        &self,
        id: &str,
        sent_message_id: &str,
        provider_message_id: &str,
    ) -> AppResult<ScheduledSend>;
    /// Atomically transition a `Pending` or `Sending` scheduled send to `Failed`.
    async fn fail_scheduled_send(&self, id: &str, error: &str) -> AppResult<ScheduledSend>;

    // --- Per-Mailbox Event-Driven Inbox Rules ---
    async fn create_inbox_rule(&self, input: &NewInboxRule) -> AppResult<InboxRule>;
    async fn get_inbox_rule(&self, id: &str) -> AppResult<Option<InboxRule>>;
    async fn list_inbox_rules(&self) -> AppResult<Vec<InboxRule>>;
    async fn patch_inbox_rule(&self, id: &str, patch: &InboxRulePatch) -> AppResult<InboxRule>;
    async fn delete_inbox_rule(&self, id: &str) -> AppResult<()>;
}

/// Construct the configured `MailStore` implementation (`sqlite`, `memory`, or `postgres`).
pub fn open_store(config: &Config) -> AppResult<Arc<dyn MailStore>> {
    match config.storage {
        StorageBackend::Sqlite => {
            let store = SqliteStore::open(&config.db_path, &config.user_email)?;
            Ok(Arc::new(store))
        }
        StorageBackend::Memory => Ok(Arc::new(MemoryStore::new(&config.user_email))),
        StorageBackend::Postgres => open_postgres_store_sync(config),
    }
}

/// Asynchronously construct and eagerly initialize the configured `MailStore` implementation.
///
/// For `StorageBackend::Postgres`, this eagerly connects, runs idempotent DDL schema creation,
/// and seeds the default mailbox so startup fails fast on connectivity or configuration errors.
pub async fn open_store_async(config: &Config) -> AppResult<Arc<dyn MailStore>> {
    match config.storage {
        StorageBackend::Postgres => open_postgres_store_async(config).await,
        _ => open_store(config),
    }
}

#[cfg(feature = "postgres")]
fn require_database_url(config: &Config) -> AppResult<&str> {
    config
        .database_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::Config(
                "NOGML_DATABASE_URL / --database-url is required when NOGML_STORAGE=postgres"
                    .to_string(),
            )
        })
}

#[cfg(feature = "postgres")]
fn open_postgres_store_sync(config: &Config) -> AppResult<Arc<dyn MailStore>> {
    let url = require_database_url(config)?;
    let store = PostgresStore::from_url(url, &config.user_email)?;
    Ok(Arc::new(store))
}

#[cfg(not(feature = "postgres"))]
fn open_postgres_store_sync(_config: &Config) -> AppResult<Arc<dyn MailStore>> {
    Err(AppError::Config(
        "Rebuild nogml with --features postgres to use the Postgres storage backend".to_string(),
    ))
}

#[cfg(feature = "postgres")]
async fn open_postgres_store_async(config: &Config) -> AppResult<Arc<dyn MailStore>> {
    let url = require_database_url(config)?;
    let store = PostgresStore::connect(url, &config.user_email).await?;
    Ok(Arc::new(store))
}

#[cfg(not(feature = "postgres"))]
async fn open_postgres_store_async(config: &Config) -> AppResult<Arc<dyn MailStore>> {
    open_postgres_store_sync(config)
}

#[cfg(feature = "postgres")]
pub(crate) fn open_postgres_with_bridge_sync(
    config: &Config,
) -> AppResult<(Arc<dyn MailStore>, Arc<PostgresEventBridge>)> {
    let url = require_database_url(config)?;
    let store = PostgresStore::from_url(url, &config.user_email)?;
    let bridge = Arc::new(store.event_bridge());
    Ok((Arc::new(store), bridge))
}

#[cfg(feature = "postgres")]
pub(crate) async fn open_postgres_with_bridge_async(
    config: &Config,
) -> AppResult<(Arc<dyn MailStore>, Arc<PostgresEventBridge>)> {
    let url = require_database_url(config)?;
    let store = PostgresStore::connect(url, &config.user_email).await?;
    let bridge = Arc::new(store.event_bridge());
    Ok((Arc::new(store), bridge))
}
