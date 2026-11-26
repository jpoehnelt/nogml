//! Resend adapter (`ResendTransport`) implementing [`crate::transport::MailTransport`],
//! plus backwards-compatible re-exports of the promoted transport primitives from [`crate::transport`].

use std::sync::Arc;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};

use crate::{
    error::{AppError, AppResult},
    models::{ResendAttachment, ResendSendEmailRequest, ResendTag},
    resend::ResendClient,
};

pub use crate::transport::{
    InboundEnvelope, IngestOutcome, MailTransport, OutboundAttachment, OutboundMessage,
    SendOutcome, TransportCapabilities, ingest_inbound_rfc2822,
};

const RESEND_MAX_MESSAGE_BYTES: usize = 40 * 1024 * 1024;

/// Built-in [`MailTransport`] backed by `Arc<dyn ResendClient>`.
#[derive(Clone)]
pub struct ResendTransport {
    client: Arc<dyn ResendClient>,
    default_from: String,
}

impl ResendTransport {
    pub fn new(client: Arc<dyn ResendClient>, default_from: impl Into<String>) -> Self {
        Self {
            client,
            default_from: default_from.into(),
        }
    }

    pub fn client(&self) -> &Arc<dyn ResendClient> {
        &self.client
    }
}

fn canonicalize_recipients(list: &[String]) -> AppResult<Vec<String>> {
    list.iter()
        .map(|addr| crate::ai::safety::canonicalize_recipient(addr))
        .collect()
}

fn outbound_to_resend_request(
    msg: &OutboundMessage,
    default_from: &str,
) -> AppResult<ResendSendEmailRequest> {
    // If structured fields are empty but raw_rfc2822 is provided, parse via crate::mime.
    if msg.to.is_empty() && !msg.raw_rfc2822.is_empty() {
        let parsed = crate::mime::parse_rfc2822(&msg.raw_rfc2822)?;
        let mut req = crate::mime::parsed_to_resend_request(&parsed, default_from)?;
        req.to = canonicalize_recipients(&req.to)?;
        if let Some(ref cc) = req.cc {
            req.cc = Some(canonicalize_recipients(cc)?);
        }
        if let Some(ref bcc) = req.bcc {
            req.bcc = Some(canonicalize_recipients(bcc)?);
        }
        if let Some(ref reply_to) = req.reply_to {
            req.reply_to = Some(canonicalize_recipients(reply_to)?);
        }
        if req.scheduled_at.is_none() {
            req.scheduled_at = msg.scheduled_at.clone();
        }
        let public_tags: Vec<ResendTag> = msg
            .tags
            .iter()
            .filter(|(name, _)| !name.starts_with("_nogml_"))
            .map(|(name, value)| ResendTag {
                name: name.clone(),
                value: value.clone(),
            })
            .collect();
        if !public_tags.is_empty() {
            req.tags = Some(public_tags);
        }
        return Ok(req);
    }

    let from = if msg.from.trim().is_empty() {
        default_from.trim().to_string()
    } else {
        msg.from.trim().to_string()
    };

    if from.is_empty() {
        return Err(AppError::BadRequest(
            "Outbound message requires a non-empty From address".to_string(),
        ));
    }
    if msg.to.is_empty() {
        return Err(AppError::BadRequest(
            "Outbound message requires at least one To recipient".to_string(),
        ));
    }

    let to = canonicalize_recipients(&msg.to)?;
    let cc = canonicalize_recipients(&msg.cc)?;
    let bcc = canonicalize_recipients(&msg.bcc)?;
    let reply_to = canonicalize_recipients(&msg.reply_to)?;

    let attachments = if msg.attachments.is_empty() {
        None
    } else {
        Some(
            msg.attachments
                .iter()
                .map(|att| ResendAttachment {
                    filename: att.filename.clone(),
                    content: Some(general_purpose::STANDARD.encode(&att.data)),
                    path: None,
                    content_type: Some(att.content_type.clone()),
                    content_id: att.content_id.clone(),
                })
                .collect(),
        )
    };

    let public_tags: Vec<ResendTag> = msg
        .tags
        .iter()
        .filter(|(name, _)| !name.starts_with("_nogml_"))
        .map(|(name, value)| ResendTag {
            name: name.clone(),
            value: value.clone(),
        })
        .collect();
    let tags = (!public_tags.is_empty()).then_some(public_tags);

    let text = if msg.text.is_none() && msg.html.is_none() {
        Some(String::new())
    } else {
        msg.text.clone()
    };

    Ok(ResendSendEmailRequest {
        from,
        to,
        subject: msg.subject.clone(),
        cc: (!cc.is_empty()).then_some(cc),
        bcc: (!bcc.is_empty()).then_some(bcc),
        reply_to: (!reply_to.is_empty()).then_some(reply_to),
        html: msg.html.clone(),
        text,
        headers: (!msg.headers.is_empty()).then(|| msg.headers.clone()),
        attachments,
        tags,
        scheduled_at: msg.scheduled_at.clone(),
    })
}

#[async_trait]
impl MailTransport for ResendTransport {
    fn name(&self) -> &'static str {
        "resend"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            provider: "resend".to_string(),
            supports_raw_mime: false,
            supports_scheduled_send: true,
            supports_idempotency_key: true,
            supports_inbound_webhooks: true,
            supports_delivery_webhooks: true,
            max_message_bytes: RESEND_MAX_MESSAGE_BYTES,
        }
    }

    async fn send(
        &self,
        msg: &OutboundMessage,
        idempotency_key: Option<&str>,
    ) -> AppResult<SendOutcome> {
        let req = outbound_to_resend_request(msg, &self.default_from)?;
        let effective_key = idempotency_key.or(msg.idempotency_key.as_deref());
        let resp = self.client.send_email(&req, effective_key).await?;
        Ok(SendOutcome {
            provider: self.name().to_string(),
            provider_message_id: resp.id,
            provider_thread_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_partial_json, header, method, path},
    };

    use super::*;
    use crate::resend::HttpResendClient;

    #[tokio::test]
    async fn resend_transport_sends_outbound_message_and_reports_capabilities() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/emails"))
            .and(header("authorization", "Bearer re_transport"))
            .and(header("idempotency-key", "send-1"))
            .and(body_partial_json(json!({
                "from": "agent@example.com",
                "to": ["alice@example.com"],
                "subject": "Status update",
                "text": "All systems green"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "resend-msg-001"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client: Arc<dyn ResendClient> = Arc::new(HttpResendClient::new(
            server.uri(),
            Some("re_transport".into()),
        ));
        let transport = ResendTransport::new(client, "agent@example.com");

        assert_eq!(transport.name(), "resend");
        let caps = transport.capabilities();
        assert_eq!(caps.provider, "resend");
        assert!(caps.supports_idempotency_key);
        assert!(caps.supports_inbound_webhooks);
        assert!(caps.supports_delivery_webhooks);
        assert!(!caps.supports_raw_mime);

        let outcome = transport
            .send(
                &OutboundMessage {
                    from: String::new(), // falls back to default_from
                    to: vec!["alice@example.com".into()],
                    subject: "Status update".into(),
                    text: Some("All systems green".into()),
                    attachments: vec![OutboundAttachment {
                        filename: Some("log.txt".into()),
                        content_type: "text/plain".into(),
                        content_id: None,
                        data: b"ok".to_vec(),
                    }],
                    ..Default::default()
                },
                Some("send-1"),
            )
            .await
            .expect("transport send should succeed");

        assert_eq!(outcome.provider, "resend");
        assert_eq!(outcome.provider_message_id, "resend-msg-001");
    }

    #[test]
    fn resend_transport_rejects_multi_address_and_canonicalizes_single_recipients() {
        let bad = OutboundMessage {
            from: "agent@example.com".into(),
            to: vec!["external@other.example, <alice@company.com>".into()],
            subject: "Bad".into(),
            text: Some("Hi".into()),
            ..Default::default()
        };
        assert!(outbound_to_resend_request(&bad, "agent@example.com").is_err());

        let good = OutboundMessage {
            from: "agent@example.com".into(),
            to: vec!["  \"Smith, Alice\"  <alice@company.com> ".into()],
            cc: vec!["  Bob Jones <bob@company.com>  ".into()],
            subject: "Good".into(),
            text: Some("Hi".into()),
            ..Default::default()
        };
        let req = outbound_to_resend_request(&good, "agent@example.com").unwrap();
        assert_eq!(req.to, vec!["\"Smith, Alice\" <alice@company.com>"]);
        assert_eq!(
            req.cc.as_deref(),
            Some(&["Bob Jones <bob@company.com>".to_string()][..])
        );
    }
}
