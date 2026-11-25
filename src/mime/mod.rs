//! MIME parsing/building, base64url helpers, Gmail `MessagePart` conversion,
//! quote stripping, untrusted-content sanitization, and JSON `?fields=` projection.
//!
//! Owned by the `mime-search` worker.

use std::collections::HashMap;

use serde_json::Value;

use crate::{
    error::AppResult,
    models::{MessageFormat, MessagePart, MessagePartHeader, ResendSendEmailRequest},
    storage::NewAttachmentInput,
};

/// Result of parsing raw RFC 2822 bytes into structured headers, bodies, and attachments.
#[derive(Debug, Clone)]
pub struct ParsedEmail {
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub reply_to: Vec<String>,
    pub subject: String,
    pub date_ms: Option<i64>,
    pub rfc822_message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references_header: Option<String>,
    pub headers: Vec<MessagePartHeader>,
    pub text_body: String,
    pub html_body: Option<String>,
    pub snippet: String,
    pub attachments: Vec<NewAttachmentInput>,
}

/// Structured input for constructing an RFC 2822 message (used by AI `/v1`, MCP, and Resend inbound fallback).
#[derive(Debug, Clone, Default)]
pub struct ComposeEmailInput {
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub reply_to: Vec<String>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Option<String>,
    pub extra_headers: HashMap<String, String>,
    pub attachments: Vec<NewAttachmentInput>,
}

/// Encode bytes as Gmail-standard unpadded base64url (`URL_SAFE_NO_PAD`).
pub fn encode_base64url(_bytes: &[u8]) -> String {
    todo!("mime-search worker: encode URL_SAFE_NO_PAD")
}

/// Decode base64url accepting both unpadded and padded URL-safe (and tolerating standard base64).
pub fn decode_base64url(_input: &str) -> AppResult<Vec<u8>> {
    todo!("mime-search worker: decode base64url tolerantly")
}

/// Parse raw RFC 2822 message bytes into a [`ParsedEmail`].
pub fn parse_rfc2822(_raw: &[u8]) -> AppResult<ParsedEmail> {
    todo!("mime-search worker: parse RFC 2822 with mail-parser")
}

/// Build an RFC 2822 message from structured fields using `mail-builder`.
pub fn build_rfc2822(_input: &ComposeEmailInput) -> AppResult<Vec<u8>> {
    todo!("mime-search worker: build RFC 2822 with mail-builder")
}

/// Convert raw RFC 2822 bytes into a Gmail REST API v1 [`MessagePart`] tree for `format` and optional `metadata_headers`.
pub fn build_gmail_payload(
    _raw: &[u8],
    _format: MessageFormat,
    _metadata_headers: &[String],
    _attachment_ids: &HashMap<String, String>,
) -> AppResult<Option<MessagePart>> {
    todo!("mime-search worker: build Gmail MessagePart payload")
}

/// Convert a parsed RFC 2822 email into a Resend outbound send payload.
pub fn parsed_to_resend_request(
    _parsed: &ParsedEmail,
    _default_from: &str,
) -> AppResult<ResendSendEmailRequest> {
    todo!("mime-search worker: convert ParsedEmail into ResendSendEmailRequest")
}

/// Generate a plain-text Gmail-style snippet (<= 200 chars, normalized whitespace).
pub fn generate_snippet(_text: &str, _html: Option<&str>) -> String {
    todo!("mime-search worker: generate snippet")
}

/// Deterministically strip quoted reply blocks (`>` lines, `On ... wrote:`, `-----Original Message-----`).
/// Falls back to original text if stripping removes all content.
pub fn strip_quoted_text(_text: &str) -> String {
    todo!("mime-search worker: strip quoted replies")
}

/// Strip dangerous ASCII control chars and Unicode BiDi override chars to guard against prompt injection.
pub fn sanitize_untrusted_text(_input: &str) -> String {
    todo!("mime-search worker: sanitize control/BiDi characters")
}

/// Normalize an RFC 2822 `Message-ID` header (trim whitespace, lowercase, ensure `<...>` canonical form).
pub fn normalize_message_id(_raw: &str) -> Option<String> {
    todo!("mime-search worker: normalize Message-ID")
}

/// Apply a Google/Gmail partial response `?fields=` mask or dot-notation projection to a JSON value.
///
/// Supports `,`, `/`, `.`, `(...)` on objects and arrays, and `*` wildcards.
/// Missing fields are silently omitted; empty mask returns `value` unchanged.
pub fn apply_fields_mask(_value: Value, _fields: &str) -> AppResult<Value> {
    todo!("mime-search worker: parse and apply JSON field mask")
}
