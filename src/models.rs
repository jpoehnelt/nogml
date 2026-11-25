use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ============================================================================
// System Label ID Constants (Gmail REST API v1)
// ============================================================================

pub const LABEL_INBOX: &str = "INBOX";
pub const LABEL_SENT: &str = "SENT";
pub const LABEL_DRAFT: &str = "DRAFT";
pub const LABEL_TRASH: &str = "TRASH";
pub const LABEL_SPAM: &str = "SPAM";
pub const LABEL_UNREAD: &str = "UNREAD";
pub const LABEL_STARRED: &str = "STARRED";
pub const LABEL_IMPORTANT: &str = "IMPORTANT";
pub const LABEL_CATEGORY_PERSONAL: &str = "CATEGORY_PERSONAL";
pub const LABEL_CATEGORY_SOCIAL: &str = "CATEGORY_SOCIAL";
pub const LABEL_CATEGORY_PROMOTIONS: &str = "CATEGORY_PROMOTIONS";
pub const LABEL_CATEGORY_UPDATES: &str = "CATEGORY_UPDATES";
pub const LABEL_CATEGORY_FORUMS: &str = "CATEGORY_FORUMS";

pub const SYSTEM_LABEL_IDS: &[&str] = &[
    LABEL_INBOX,
    LABEL_SENT,
    LABEL_DRAFT,
    LABEL_TRASH,
    LABEL_SPAM,
    LABEL_UNREAD,
    LABEL_STARRED,
    LABEL_IMPORTANT,
    LABEL_CATEGORY_PERSONAL,
    LABEL_CATEGORY_SOCIAL,
    LABEL_CATEGORY_PROMOTIONS,
    LABEL_CATEGORY_UPDATES,
    LABEL_CATEGORY_FORUMS,
];

pub fn is_system_label(id: &str) -> bool {
    SYSTEM_LABEL_IDS.contains(&id)
}

// ============================================================================
// Gmail REST API v1 Models (strict camelCase, omit None fields)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageFormat {
    #[default]
    Full,
    Metadata,
    Minimal,
    Raw,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub email_address: String,
    pub messages_total: i32,
    pub threads_total: i32,
    pub history_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MessagePartHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MessagePartBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment_id: Option<String>,
    pub size: i32,
    /// Base64url-encoded data (no padding when encoding).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MessagePart {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub part_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<Vec<MessagePartHeader>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<MessagePartBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parts: Option<Vec<MessagePart>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub thread_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    /// uint64 formatted as string in Gmail API.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_id: Option<String>,
    /// Epoch milliseconds formatted as string in Gmail API.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<MessagePart>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_estimate: Option<i32>,
    /// Base64url-encoded RFC 2822 message (only present for `format=raw` or send/insert/import input).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MessageRef {
    pub id: String,
    pub thread_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ListMessagesResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messages: Option<Vec<MessageRef>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
    pub result_size_estimate: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModifyMessageRequest {
    #[serde(default)]
    pub add_label_ids: Vec<String>,
    #[serde(default)]
    pub remove_label_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchModifyMessagesRequest {
    #[serde(default)]
    pub ids: Vec<String>,
    #[serde(default)]
    pub add_label_ids: Vec<String>,
    #[serde(default)]
    pub remove_label_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchDeleteMessagesRequest {
    #[serde(default)]
    pub ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Thread {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messages: Option<Vec<Message>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ThreadRef {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ListThreadsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threads: Option<Vec<ThreadRef>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
    pub result_size_estimate: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModifyThreadRequest {
    #[serde(default)]
    pub add_label_ids: Vec<String>,
    #[serde(default)]
    pub remove_label_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LabelColor {
    pub text_color: String,
    pub background_color: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Label {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_list_visibility: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label_list_visibility: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub label_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messages_total: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messages_unread: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threads_total: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threads_unread: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<LabelColor>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ListLabelsResponse {
    pub labels: Vec<Label>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Draft {
    #[serde(default)]
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DraftRef {
    pub id: String,
    pub message: MessageRef,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ListDraftsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drafts: Option<Vec<DraftRef>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
    pub result_size_estimate: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HistoryMessageAdded {
    pub message: Message,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HistoryMessageDeleted {
    pub message: Message,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HistoryLabelAdded {
    pub message: Message,
    pub label_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HistoryLabelRemoved {
    pub message: Message,
    pub label_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HistoryRecord {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messages: Option<Vec<Message>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messages_added: Option<Vec<HistoryMessageAdded>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messages_deleted: Option<Vec<HistoryMessageDeleted>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels_added: Option<Vec<HistoryLabelAdded>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels_removed: Option<Vec<HistoryLabelRemoved>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ListHistoryResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<HistoryRecord>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
    pub history_id: String,
}

// --- Gmail Watch / Stop (Superhuman compatibility) ---

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchRequest {
    pub topic_name: String,
    #[serde(default)]
    pub label_ids: Vec<String>,
    /// Accepts `include` or `exclude`.
    #[serde(default)]
    pub label_filter_behavior: Option<String>,
    /// Deprecated Gmail alias for `labelFilterBehavior`.
    #[serde(default)]
    pub label_filter_action: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WatchResponse {
    pub history_id: String,
    /// Epoch ms as string (typically +7 days).
    pub expiration: String,
}

// --- Gmail Settings (Superhuman compatibility) ---

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SmtpMsa {
    pub host: String,
    pub port: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SendAs {
    #[serde(default)]
    pub send_as_email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_primary: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub treat_as_alias: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smtp_msa: Option<SmtpMsa>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_status: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ListSendAsResponse {
    pub send_as: Vec<SendAs>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VacationSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_auto_reply: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body_plain_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body_html: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restrict_to_contacts: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restrict_to_domain: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AutoForwarding {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImapSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_expunge: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expunge_behavior: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_folder_size: Option<i32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PopSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_window: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition: Option<String>,
}

// ============================================================================
// Resend API & Webhook Models
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResendAttachment {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// Standard base64 encoded attachment bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResendTag {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResendSendEmailRequest {
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bcc: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<ResendAttachment>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<ResendTag>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduled_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResendSendEmailResponse {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResendErrorResponse {
    #[serde(rename = "statusCode")]
    pub status_code: u16,
    pub name: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResendWebhookAttachment {
    pub id: String,
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub content_disposition: Option<String>,
    #[serde(default)]
    pub content_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResendBounceInfo {
    #[serde(default)]
    pub message: Option<String>,
    #[serde(rename = "subType", default)]
    pub sub_type: Option<String>,
    #[serde(rename = "type", default)]
    pub bounce_type: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResendWebhookData {
    #[serde(default)]
    pub email_id: String,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Option<Vec<String>>,
    #[serde(default)]
    pub bcc: Option<Vec<String>>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub message_id: Option<String>,
    #[serde(default)]
    pub broadcast_id: Option<String>,
    #[serde(default)]
    pub template_id: Option<String>,
    #[serde(default)]
    pub tags: Option<HashMap<String, String>>,
    #[serde(default)]
    pub attachments: Option<Vec<ResendWebhookAttachment>>,
    #[serde(default)]
    pub bounce: Option<ResendBounceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResendWebhookEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub created_at: String,
    pub data: ResendWebhookData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResendRawRef {
    pub download_url: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResendReceivedEmail {
    #[serde(default)]
    pub object: Option<String>,
    pub id: String,
    #[serde(default)]
    pub to: Vec<String>,
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub html: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub cc: Vec<String>,
    #[serde(default)]
    pub bcc: Vec<String>,
    #[serde(default)]
    pub reply_to: Vec<String>,
    #[serde(default)]
    pub message_id: Option<String>,
    #[serde(default)]
    pub raw: Option<ResendRawRef>,
    #[serde(default)]
    pub attachments: Vec<ResendWebhookAttachment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResendReceivedAttachment {
    pub id: String,
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub content_disposition: Option<String>,
    #[serde(default)]
    pub content_id: Option<String>,
    pub download_url: String,
    #[serde(default)]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResendReceivedAttachmentsResponse {
    #[serde(default)]
    pub object: Option<String>,
    #[serde(default)]
    pub has_more: bool,
    #[serde(default)]
    pub data: Vec<ResendReceivedAttachment>,
}

// ============================================================================
// AI-First Compact & Safety Models (snake_case)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmailAddress {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub email: String,
}

impl EmailAddress {
    pub fn new(email: impl Into<String>, name: Option<String>) -> Self {
        Self {
            name,
            email: email.into(),
        }
    }

    pub fn format_header(&self) -> String {
        match &self.name {
            Some(name) if !name.is_empty() => format!("{name} <{}>", self.email),
            _ => self.email.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachmentMeta {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    pub content_type: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UntrustedMeta {
    pub untrusted_external_content: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactMessage {
    pub id: String,
    pub thread_id: String,
    pub date: DateTime<Utc>,
    pub from: EmailAddress,
    pub to: Vec<EmailAddress>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cc: Vec<EmailAddress>,
    pub subject: String,
    pub snippet: String,
    pub labels: Vec<String>,
    pub unread: bool,
    pub has_attachments: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments_meta: Option<Vec<AttachmentMeta>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub text_truncated: bool,
    pub text_total_chars: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rfc_message_id: Option<String>,
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<UntrustedMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadSummary {
    pub id: String,
    pub subject: String,
    pub participants: Vec<EmailAddress>,
    pub snippet: String,
    pub labels: Vec<String>,
    pub unread: bool,
    pub has_attachments: bool,
    pub message_count: usize,
    pub last_message_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadDetail {
    pub id: String,
    pub subject: String,
    pub participants: Vec<EmailAddress>,
    pub labels: Vec<String>,
    pub unread: bool,
    pub message_count: usize,
    pub last_message_at: DateTime<Utc>,
    pub messages: Vec<CompactMessage>,
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<UntrustedMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCheckResult {
    pub rule: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunPreview {
    pub from: String,
    pub to: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cc: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bcc: Vec<String>,
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    pub estimated_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunResponse {
    pub dry_run: bool,
    pub would_succeed: bool,
    pub policy_checks: Vec<PolicyCheckResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<DryRunPreview>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiSendEmailRequest {
    #[serde(default)]
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Vec<String>,
    #[serde(default)]
    pub bcc: Vec<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub html: Option<String>,
    #[serde(default)]
    pub reply_to_message_id: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiCreateDraftRequest {
    #[serde(default)]
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Vec<String>,
    #[serde(default)]
    pub bcc: Vec<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub html: Option<String>,
    #[serde(default)]
    pub reply_to_message_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiSendDraftRequest {
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiTriageRequest {
    #[serde(default)]
    pub archive: Option<bool>,
    #[serde(default)]
    pub mark_read: Option<bool>,
    #[serde(default)]
    pub mark_unread: Option<bool>,
    #[serde(default)]
    pub star: Option<bool>,
    #[serde(default)]
    pub trash: Option<bool>,
    #[serde(default)]
    pub add_labels: Vec<String>,
    #[serde(default)]
    pub remove_labels: Vec<String>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiModifyLabelsRequest {
    #[serde(default)]
    pub message_ids: Vec<String>,
    #[serde(default)]
    pub thread_ids: Vec<String>,
    #[serde(default)]
    pub add_labels: Vec<String>,
    #[serde(default)]
    pub remove_labels: Vec<String>,
    #[serde(default)]
    pub archive: Option<bool>,
    #[serde(default)]
    pub mark_read: Option<bool>,
    #[serde(default)]
    pub trash: Option<bool>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncTriggerRequest {
    /// `"incremental"` (default) or `"full"`.
    #[serde(default)]
    pub mode: Option<String>,
    /// Optional provider override: `"api"` or `"imap"`.
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub max_messages: Option<usize>,
    #[serde(default)]
    pub query: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatusResponse {
    pub enabled: bool,
    pub provider: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sync_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_history_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub total_messages: i64,
    pub unread_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}
