//! Provider-agnostic outbound mail transport (`MailTransport`) and reusable inbound
//! RFC 2822 ingestion pipeline (`ingest_inbound_rfc2822`).
//!
//! Designed so Resend, AWS SES (`SendRawEmail` + S3 inbound), raw SMTP, Postmark, or Stalwart
//! can drop in behind `Arc<dyn MailTransport>` without leaking provider types into `gmail`,
//! `ai`, `mcp`, `imap`, or `storage`.

pub mod ses;
pub mod smtp;

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    config::{Config, TransportBackend},
    error::{AppError, AppResult},
    events::{EventBus, EventSource, MailEvent},
    filter::{FilterDecision, InboundFilter, InboundMessage, apply_filter_labels},
    resend::{ResendClient, ResendTransport},
    storage::{MailStore, NewAttachmentInput, NewMessageInput, StoredMessage},
};

pub use ses::{
    SesConfig, SesTransport, SigV4Headers, ses_router, ses_webhook_handler, sign_aws_v4,
};
pub use smtp::{SmtpConfig, SmtpTransport, dot_stuff_rfc5321};

/// Construct the active [`MailTransport`] selected by [`Config::transport`].
pub fn open_transport(
    config: &Config,
    resend: Arc<dyn ResendClient>,
) -> AppResult<Arc<dyn MailTransport>> {
    match config.transport {
        TransportBackend::Resend => Ok(Arc::new(ResendTransport::new(
            resend,
            config.user_email.clone(),
        ))),
        TransportBackend::Ses => Ok(Arc::new(SesTransport::from_config(config)?)),
        TransportBackend::Smtp => Ok(Arc::new(SmtpTransport::from_config(config)?)),
    }
}

/// Return `msg.raw_rfc2822` verbatim when populated, or synthesize RFC 2822 bytes from
/// structured fields as a fallback.
pub(crate) fn ensure_raw_rfc2822(msg: &OutboundMessage, default_from: &str) -> AppResult<Vec<u8>> {
    if !msg.raw_rfc2822.is_empty() {
        return Ok(msg.raw_rfc2822.clone());
    }

    let from = if msg.from.trim().is_empty() {
        default_from.trim().to_string()
    } else {
        msg.from.trim().to_string()
    };

    let compose = crate::mime::ComposeEmailInput {
        from,
        to: msg.to.clone(),
        cc: msg.cc.clone(),
        bcc: msg.bcc.clone(),
        reply_to: msg.reply_to.clone(),
        subject: msg.subject.clone(),
        text: msg.text.clone(),
        html: msg.html.clone(),
        message_id: msg
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("message-id"))
            .map(|(_, v)| v.clone()),
        in_reply_to: msg
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("in-reply-to"))
            .map(|(_, v)| v.clone()),
        references: msg
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("references"))
            .map(|(_, v)| v.clone()),
        extra_headers: msg.headers.clone(),
        attachments: msg
            .attachments
            .iter()
            .enumerate()
            .map(|(idx, att)| NewAttachmentInput {
                part_id: format!("att_{}", idx + 1),
                filename: att.filename.clone(),
                content_type: att.content_type.clone(),
                content_id: att.content_id.clone(),
                data: att.data.clone(),
            })
            .collect(),
    };
    crate::mime::build_rfc2822(&compose)
}

mod serde_bytes_b64 {
    use super::*;
    use serde::de;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesOrBase64Visitor;

        impl<'de> de::Visitor<'de> for BytesOrBase64Visitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a base64-encoded string or byte array")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                general_purpose::STANDARD
                    .decode(v)
                    .map_err(|e| E::custom(format!("invalid base64 bytes: {e}")))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut out = Vec::new();
                while let Some(byte) = seq.next_element::<u8>()? {
                    out.push(byte);
                }
                Ok(out)
            }
        }

        deserializer.deserialize_any(BytesOrBase64Visitor)
    }
}

/// Attachment carried on an [`OutboundMessage`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundAttachment {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    pub content_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_id: Option<String>,
    #[serde(default, with = "serde_bytes_b64")]
    pub data: Vec<u8>,
}

impl From<NewAttachmentInput> for OutboundAttachment {
    fn from(att: NewAttachmentInput) -> Self {
        Self {
            filename: att.filename,
            content_type: att.content_type,
            content_id: att.content_id,
            data: att.data,
        }
    }
}

impl From<&NewAttachmentInput> for OutboundAttachment {
    fn from(att: &NewAttachmentInput) -> Self {
        Self {
            filename: att.filename.clone(),
            content_type: att.content_type.clone(),
            content_id: att.content_id.clone(),
            data: att.data.clone(),
        }
    }
}

/// Provider-agnostic outbound email payload carrying both structured fields
/// (for REST transports like Resend) and verbatim `raw_rfc2822` bytes
/// (for raw MIME transports like AWS SES `SendRawEmail`, SMTP, or Stalwart).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundMessage {
    pub from: String,
    #[serde(default)]
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Vec<String>,
    #[serde(default)]
    pub bcc: Vec<String>,
    #[serde(default)]
    pub reply_to: Vec<String>,
    #[serde(default)]
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub attachments: Vec<OutboundAttachment>,
    #[serde(default, with = "serde_bytes_b64")]
    pub raw_rfc2822: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduled_at: Option<String>,
    #[serde(default)]
    pub tags: HashMap<String, String>,
}

/// Result returned by [`MailTransport::send`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendOutcome {
    pub provider: String,
    pub provider_message_id: String,
}

/// Declared transport capabilities for runtime inspection and routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportCapabilities {
    pub provider: String,
    pub supports_raw_mime: bool,
    pub supports_scheduled_send: bool,
    pub supports_idempotency_key: bool,
    pub supports_inbound_webhooks: bool,
    pub supports_delivery_webhooks: bool,
    pub max_message_bytes: usize,
}

/// Pluggable outbound mail transport (parallel to [`MailStore`]).
#[async_trait]
pub trait MailTransport: Send + Sync {
    /// Short provider identifier (e.g. `"resend"`, `"ses"`, `"smtp"`).
    fn name(&self) -> &'static str;

    /// Capabilities exposed by this transport backend.
    fn capabilities(&self) -> TransportCapabilities;

    /// Deliver an outbound email via this transport.
    async fn send(
        &self,
        msg: &OutboundMessage,
        idempotency_key: Option<&str>,
    ) -> AppResult<SendOutcome>;
}

/// Provider-agnostic inbound email envelope passed to [`ingest_inbound_rfc2822`].
#[derive(Debug, Clone, Default)]
pub struct InboundEnvelope {
    pub raw_rfc2822: Vec<u8>,
    /// Origin identifier (e.g. `"resend_inbound"`, `"ses_s3"`, `"smtp"`, `"imap_append"`).
    pub source: String,
    /// Provider-assigned email ID (e.g. Resend `email_id`).
    pub provider_id: Option<String>,
    pub sender_ip: Option<String>,
    pub authentication_results: Option<String>,
    pub received_at_ms: Option<i64>,
    /// Default labels applied before [`InboundFilter`]; defaults to `[INBOX, UNREAD]` if empty.
    pub default_labels: Vec<String>,
    /// Additional attachments supplied out-of-band by the provider (used if parsed MIME has none).
    pub extra_attachments: Vec<NewAttachmentInput>,

    // Optional fallback metadata when provider metadata supplements raw MIME.
    pub fallback_from: Option<String>,
    pub fallback_to: Vec<String>,
    pub fallback_cc: Vec<String>,
    pub fallback_bcc: Vec<String>,
    pub fallback_subject: Option<String>,
    pub fallback_text: Option<String>,
    pub fallback_html: Option<String>,
    pub fallback_rfc822_message_id: Option<String>,
    pub fallback_in_reply_to: Option<String>,
    pub fallback_references: Option<String>,
}

/// Outcome of running an inbound RFC 2822 message through filtering, threading, dedup, and storage.
#[derive(Debug, Clone)]
pub enum IngestOutcome {
    Stored {
        message: StoredMessage,
        decision: FilterDecision,
    },
    Duplicate {
        message: StoredMessage,
    },
    Rejected {
        reason: String,
    },
}

fn source_to_event_source(source: &str) -> EventSource {
    match source {
        "resend_inbound" => EventSource::ResendInbound,
        "resend_webhook" => EventSource::ResendWebhook,
        "ses_inbound" | "ses_s3" => EventSource::SesInbound,
        "gmail_api" | "gmail_imap" | "gmail_sync" => EventSource::GmailSync,
        "imap_append" | "imap" => EventSource::Imap,
        "mcp" => EventSource::Mcp,
        _ => EventSource::Api,
    }
}

fn extract_parent_message_ids(
    in_reply_to: Option<&str>,
    references_header: Option<&str>,
) -> Vec<String> {
    let mut candidates = Vec::new();

    if let Some(irt) = in_reply_to {
        for token in irt.split_whitespace() {
            let trimmed = token.trim_matches(',');
            if let Some(norm) = crate::mime::normalize_message_id(trimmed)
                && !candidates.contains(&norm)
            {
                candidates.push(norm);
            }
        }
    }

    if let Some(refs) = references_header {
        // Walk References from most recent ancestor backwards.
        for token in refs.split_whitespace().rev() {
            let trimmed = token.trim_matches(',');
            if let Some(norm) = crate::mime::normalize_message_id(trimmed)
                && !candidates.contains(&norm)
            {
                candidates.push(norm);
            }
        }
    }

    candidates
}

async fn resolve_thread_id(
    store: &dyn MailStore,
    in_reply_to: Option<&str>,
    references_header: Option<&str>,
) -> AppResult<Option<String>> {
    for candidate in extract_parent_message_ids(in_reply_to, references_header) {
        if let Some(parent) = store.find_message_by_rfc_message_id(&candidate).await? {
            return Ok(Some(parent.thread_id));
        }
    }
    Ok(None)
}

/// Provider-agnostic inbound RFC 2822 ingestion pipeline.
///
/// 1. Parses `envelope.raw_rfc2822` via `crate::mime::parse_rfc2822` (merging optional fallbacks).
/// 2. Deduplicates against `store` by normalized `rfc822_message_id` (and `provider_id` for Resend).
/// 3. Evaluates `filter` (`Reject` drops before storage; `Spam` adds `SPAM` & skips `INBOX`;
///    `Mutate` applies label edits & `skip_inbox`).
/// 4. Resolves existing thread via `In-Reply-To` / `References`.
/// 5. Persists into `store` and publishes `MailEvent::MessageReceived` to `events`.
pub async fn ingest_inbound_rfc2822(
    store: &dyn MailStore,
    events: &EventBus,
    filter: &dyn InboundFilter,
    envelope: InboundEnvelope,
) -> AppResult<IngestOutcome> {
    let parsed = match crate::mime::parse_rfc2822(&envelope.raw_rfc2822) {
        Ok(p) => Some(p),
        Err(err) => {
            tracing::warn!(
                source = %envelope.source,
                error = %err,
                "Failed to parse raw RFC 2822 during inbound ingestion; falling back to envelope metadata"
            );
            None
        }
    };

    let from_addr = parsed
        .as_ref()
        .map(|p| p.from.clone())
        .filter(|s| !s.trim().is_empty())
        .or_else(|| envelope.fallback_from.clone())
        .unwrap_or_default();

    let to_addrs = parsed
        .as_ref()
        .map(|p| p.to.clone())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| envelope.fallback_to.clone());

    let cc_addrs = parsed
        .as_ref()
        .map(|p| p.cc.clone())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| envelope.fallback_cc.clone());

    let bcc_addrs = parsed
        .as_ref()
        .map(|p| p.bcc.clone())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| envelope.fallback_bcc.clone());

    let subject = parsed
        .as_ref()
        .map(|p| p.subject.clone())
        .filter(|s| !s.is_empty())
        .or_else(|| envelope.fallback_subject.clone())
        .unwrap_or_default();

    let text_body = parsed
        .as_ref()
        .map(|p| p.text_body.clone())
        .filter(|s| !s.is_empty())
        .or_else(|| envelope.fallback_text.clone())
        .unwrap_or_default();

    let html_body = parsed
        .as_ref()
        .and_then(|p| p.html_body.clone())
        .or_else(|| envelope.fallback_html.clone());

    let raw_message_id = parsed
        .as_ref()
        .and_then(|p| p.rfc822_message_id.clone())
        .or_else(|| envelope.fallback_rfc822_message_id.clone());
    let rfc822_message_id = raw_message_id
        .as_deref()
        .and_then(crate::mime::normalize_message_id);

    let raw_in_reply_to = parsed
        .as_ref()
        .and_then(|p| p.in_reply_to.clone())
        .or_else(|| envelope.fallback_in_reply_to.clone());
    let in_reply_to = raw_in_reply_to
        .as_deref()
        .and_then(|s| s.split_whitespace().next())
        .and_then(|tok| crate::mime::normalize_message_id(tok.trim_matches(',')));

    let references_header = parsed
        .as_ref()
        .and_then(|p| p.references_header.clone())
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            envelope
                .fallback_references
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
        });

    let attachments = parsed
        .as_ref()
        .map(|p| p.attachments.clone())
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| envelope.extra_attachments.clone());

    let snippet = parsed
        .as_ref()
        .map(|p| p.snippet.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| crate::mime::generate_snippet(&text_body, html_body.as_deref()));

    let internal_date_ms = envelope
        .received_at_ms
        .or_else(|| parsed.as_ref().and_then(|p| p.date_ms))
        .unwrap_or_else(|| Utc::now().timestamp_millis());

    let headers: Vec<(String, String)> = parsed
        .as_ref()
        .map(|p| {
            p.headers
                .iter()
                .map(|h| (h.name.clone(), h.value.clone()))
                .collect()
        })
        .unwrap_or_default();

    // 1. Deduplicate by RFC 2822 Message-ID or Resend provider ID before filtering/storing.
    if let Some(mid) = rfc822_message_id.as_deref()
        && let Some(existing) = store.find_message_by_rfc_message_id(mid).await?
    {
        return Ok(IngestOutcome::Duplicate { message: existing });
    }
    if envelope.source == "resend_inbound"
        && let Some(pid) = envelope.provider_id.as_deref().filter(|s| !s.is_empty())
        && let Some(existing) = store.find_message_by_resend_id(pid).await?
    {
        return Ok(IngestOutcome::Duplicate { message: existing });
    }

    // 2. Run pluggable InboundFilter before persisting into MailStore.
    let auth_results = envelope.authentication_results.clone().or_else(|| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Authentication-Results"))
            .map(|(_, v)| v.clone())
    });

    let inbound_msg = InboundMessage {
        raw_rfc2822: envelope.raw_rfc2822.clone(),
        headers,
        text_body: text_body.clone(),
        html_body: html_body.clone(),
        from: from_addr.clone(),
        to: to_addrs.clone(),
        subject: subject.clone(),
        authentication_results: auth_results,
        sender_ip: envelope.sender_ip.clone(),
        source: envelope.source.clone(),
        provider_id: envelope.provider_id.clone(),
    };

    let decision = filter.evaluate(&inbound_msg).await?;
    if let FilterDecision::Reject { reason } = decision {
        tracing::info!(
            source = %envelope.source,
            from = %from_addr,
            reason = %reason,
            "Inbound message rejected by filter prior to storage"
        );
        return Ok(IngestOutcome::Rejected { reason });
    }

    let label_ids = apply_filter_labels(envelope.default_labels, &decision);

    // 3. Resolve existing thread via In-Reply-To / References.
    let thread_id = resolve_thread_id(
        store,
        raw_in_reply_to.as_deref(),
        references_header.as_deref(),
    )
    .await?;

    let resend_id = if envelope.source == "resend_inbound" {
        envelope.provider_id.filter(|s| !s.is_empty())
    } else {
        None
    };

    let source_name = if envelope.source.is_empty() {
        "resend_inbound".to_string()
    } else {
        envelope.source
    };

    let input = NewMessageInput {
        id: None,
        thread_id,
        label_ids,
        raw_rfc2822: envelope.raw_rfc2822,
        snippet,
        internal_date_ms,
        subject,
        from_addr,
        to_addrs,
        cc_addrs,
        bcc_addrs,
        text_body,
        html_body,
        rfc822_message_id: rfc822_message_id.clone(),
        in_reply_to,
        references_header,
        resend_id,
        upstream_gmail_id: None,
        upstream_thread_id: None,
        source: source_name.clone(),
        is_answered: false,
        is_deleted: false,
        attachments,
    };

    // 4. Persist into MailStore (handle concurrent dedup races idempotently).
    let stored = match store.insert_message(input).await {
        Ok(msg) => msg,
        Err(AppError::Conflict(_)) => {
            if let Some(mid) = rfc822_message_id.as_deref()
                && let Some(existing) = store.find_message_by_rfc_message_id(mid).await?
            {
                return Ok(IngestOutcome::Duplicate { message: existing });
            }
            return Err(AppError::Conflict(
                "Duplicate inbound message conflict".to_string(),
            ));
        }
        Err(err) => return Err(err),
    };

    // 5. Publish unified domain event scoped to the receiving mailbox.
    let event_mailbox = if !events.mailbox_id().is_empty() {
        events.mailbox_id()
    } else {
        store.mailbox_id()
    };
    events.publish_for_mailbox(
        event_mailbox,
        source_to_event_source(&source_name),
        MailEvent::MessageReceived {
            message_id: stored.id.clone(),
            thread_id: stored.thread_id.clone(),
            from: stored.from_addr.clone(),
            subject: stored.subject.clone(),
            snippet: stored.snippet.clone(),
            labels: stored.label_ids.clone(),
        },
    );

    Ok(IngestOutcome::Stored {
        message: stored,
        decision,
    })
}
