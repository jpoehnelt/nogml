//! MIME parsing/building, base64url helpers, Gmail `MessagePart` conversion,
//! quote stripping, untrusted-content sanitization, and JSON `?fields=` projection.
//!
//! Owned by the `mime-search` worker.

mod fields;
mod payload;
mod text;

use std::collections::HashMap;

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use mail_builder::{
    MessageBuilder,
    headers::{
        address::Address as BuilderAddress, content_type::ContentType as BuilderContentType,
        message_id::MessageId as BuilderMessageId, text::Text as BuilderText,
    },
    mime::MimePart as BuilderMimePart,
};
use mail_parser::{MessageParser, PartKind};

use crate::{
    error::{AppError, AppResult},
    models::{MessagePartHeader, ResendAttachment, ResendSendEmailRequest},
    storage::{NewAttachmentInput, parse_simple_email_address},
};

pub use fields::apply_fields_mask;
pub use payload::build_gmail_payload;
pub use text::{generate_snippet, sanitize_untrusted_text, strip_quoted_text};

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
pub fn encode_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode base64url accepting both unpadded and padded URL-safe (and tolerating standard base64).
pub fn decode_base64url(input: &str) -> AppResult<Vec<u8>> {
    let cleaned: String = input
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect();

    if cleaned.is_empty() {
        return Ok(Vec::new());
    }

    URL_SAFE_NO_PAD
        .decode(&cleaned)
        .or_else(|_| URL_SAFE.decode(&cleaned))
        .or_else(|_| STANDARD.decode(&cleaned))
        .or_else(|_| STANDARD_NO_PAD.decode(&cleaned))
        .map_err(|err| AppError::Mime(format!("Invalid base64/base64url encoding: {err}")))
}

/// Normalize an RFC 2822 `Message-ID` header (trim whitespace, lowercase, ensure `<...>` canonical form).
pub fn normalize_message_id(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let inner = if let (Some(lt), Some(gt)) = (trimmed.find('<'), trimmed.find('>'))
        && lt < gt
    {
        trimmed[lt + 1..gt].trim()
    } else {
        trimmed.trim_matches(|c| c == '<' || c == '>').trim()
    };

    if inner.is_empty() {
        return None;
    }

    Some(format!("<{}>", inner.to_ascii_lowercase()))
}

fn strip_angle_brackets(raw: &str) -> &str {
    raw.trim().trim_matches(|c| c == '<' || c == '>').trim()
}

fn extract_bare_message_ids(raw: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut remaining = raw.trim();

    if remaining.contains('<') && remaining.contains('>') {
        while let Some(lt) = remaining.find('<') {
            let after_lt = &remaining[lt + 1..];
            if let Some(gt) = after_lt.find('>') {
                let candidate = after_lt[..gt].trim();
                if !candidate.is_empty() {
                    ids.push(candidate.to_string());
                }
                remaining = &after_lt[gt + 1..];
            } else {
                break;
            }
        }
    }

    if ids.is_empty() {
        for token in raw.split_whitespace() {
            let bare = strip_angle_brackets(token);
            if !bare.is_empty() {
                ids.push(bare.to_string());
            }
        }
    }

    ids
}

fn parse_builder_address(raw: &str) -> Option<BuilderAddress<'static>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let parsed = parse_simple_email_address(trimmed);
    if parsed.email.is_empty() {
        return None;
    }
    Some(BuilderAddress::new_address(parsed.name, parsed.email))
}

/// Parse raw RFC 2822 message bytes into a [`ParsedEmail`].
pub fn parse_rfc2822(raw: &[u8]) -> AppResult<ParsedEmail> {
    if raw.is_empty() {
        return Err(AppError::Mime("Empty RFC 2822 message".to_string()));
    }

    let message = MessageParser::new()
        .parse(raw)
        .ok_or_else(|| AppError::Mime("Failed to parse RFC 2822 message".to_string()))?;

    let from = message
        .from()
        .and_then(|list| list.first())
        .and_then(payload::format_mailbox)
        .unwrap_or_default();

    let to: Vec<String> = message
        .all_to()
        .flat_map(|list| list.mailboxes())
        .filter_map(payload::format_mailbox)
        .collect();

    let cc: Vec<String> = message
        .all_cc()
        .flat_map(|list| list.mailboxes())
        .filter_map(payload::format_mailbox)
        .collect();

    let bcc: Vec<String> = message
        .all_bcc()
        .flat_map(|list| list.mailboxes())
        .filter_map(payload::format_mailbox)
        .collect();

    let reply_to: Vec<String> = message
        .reply_to()
        .into_iter()
        .flat_map(|list| list.mailboxes())
        .filter_map(payload::format_mailbox)
        .collect();

    let subject = message.subject().unwrap_or_default().to_string();
    let date_ms = message
        .date()
        .map(|dt| dt.to_timestamp().saturating_mul(1000));

    let rfc822_message_id = message.message_id().and_then(normalize_message_id);
    let in_reply_to = message
        .in_reply_to()
        .and_then(|list| list.first())
        .and_then(normalize_message_id);

    let references_header = message.references().and_then(|list| {
        let normalized: Vec<String> = list.iter().filter_map(normalize_message_id).collect();
        if normalized.is_empty() {
            None
        } else {
            Some(normalized.join(" "))
        }
    });

    let headers = payload::extract_part_headers(&message.root_part());

    let text_parts: Vec<String> = message
        .text_body()
        .filter(|part| matches!(part.kind(), PartKind::Text))
        .filter_map(|part| part.text().map(|t| t.into_owned()))
        .collect();

    let html_parts: Vec<String> = message
        .html_body()
        .filter(|part| matches!(part.kind(), PartKind::Html))
        .filter_map(|part| part.text().map(|h| h.into_owned()))
        .collect();

    let html_body = (!html_parts.is_empty()).then(|| html_parts.join("\n"));

    let text_body = if !text_parts.is_empty() {
        text_parts.join("\n")
    } else if let Some(ref html) = html_body {
        mail_parser::html_to_text(html).trim().to_string()
    } else {
        String::new()
    };

    let snippet = generate_snippet(&text_body, html_body.as_deref());
    let attachments = payload::collect_attachments_with_part_ids(message.root_part());

    Ok(ParsedEmail {
        from,
        to,
        cc,
        bcc,
        reply_to,
        subject,
        date_ms,
        rfc822_message_id,
        in_reply_to,
        references_header,
        headers,
        text_body,
        html_body,
        snippet,
        attachments,
    })
}

/// Build an RFC 2822 message from structured fields using `mail-builder`.
pub fn build_rfc2822(input: &ComposeEmailInput) -> AppResult<Vec<u8>> {
    let mut builder = MessageBuilder::new();

    if let Some(from_addr) = parse_builder_address(&input.from) {
        builder = builder.from(from_addr);
    }

    let to_addrs: Vec<BuilderAddress<'static>> = input
        .to
        .iter()
        .filter_map(|s| parse_builder_address(s))
        .collect();
    if !to_addrs.is_empty() {
        builder = builder.to(to_addrs);
    }

    let cc_addrs: Vec<BuilderAddress<'static>> = input
        .cc
        .iter()
        .filter_map(|s| parse_builder_address(s))
        .collect();
    if !cc_addrs.is_empty() {
        builder = builder.cc(cc_addrs);
    }

    let bcc_addrs: Vec<BuilderAddress<'static>> = input
        .bcc
        .iter()
        .filter_map(|s| parse_builder_address(s))
        .collect();
    if !bcc_addrs.is_empty() {
        builder = builder.bcc(bcc_addrs);
    }

    let reply_to_addrs: Vec<BuilderAddress<'static>> = input
        .reply_to
        .iter()
        .filter_map(|s| parse_builder_address(s))
        .collect();
    if !reply_to_addrs.is_empty() {
        builder = builder.reply_to(reply_to_addrs);
    }

    builder = builder.subject(input.subject.as_str());

    if let Some(ref mid) = input.message_id {
        let bare = strip_angle_brackets(mid);
        if !bare.is_empty() {
            builder = builder.message_id(BuilderMessageId::new(bare));
        }
    }

    if let Some(ref irt) = input.in_reply_to {
        let ids = extract_bare_message_ids(irt);
        if !ids.is_empty() {
            builder = builder.in_reply_to(BuilderMessageId::from(ids));
        }
    }

    if let Some(ref refs) = input.references {
        let ids = extract_bare_message_ids(refs);
        if !ids.is_empty() {
            builder = builder.references(BuilderMessageId::from(ids));
        }
    }

    let mut extra_keys: Vec<&String> = input.extra_headers.keys().collect();
    extra_keys.sort();
    for key in extra_keys {
        if key.is_empty() || key.contains('\r') || key.contains('\n') || key.contains(':') {
            return Err(AppError::Mime(format!("Invalid header name: {key:?}")));
        }
        let value = &input.extra_headers[key];
        if value.contains('\r') || value.contains('\n') {
            return Err(AppError::Mime(format!(
                "Header value for {key:?} must not contain CR/LF"
            )));
        }
        builder = builder.header(key.as_str(), BuilderText::new(value.as_str()));
    }

    if let Some(ref text) = input.text {
        builder = builder.text_body(text.as_str());
    }
    if let Some(ref html) = input.html {
        builder = builder.html_body(html.as_str());
    }

    for att in &input.attachments {
        let ct_str = if att.content_type.trim().is_empty() {
            "application/octet-stream"
        } else {
            att.content_type.trim()
        };

        if let Some(ref cid) = att.content_id
            && !cid.trim().is_empty()
        {
            let bare_cid = strip_angle_brackets(cid);
            let content_type = if let Some(ref name) = att.filename
                && !name.trim().is_empty()
            {
                BuilderContentType::new(ct_str).attribute("name", name.as_str())
            } else {
                BuilderContentType::new(ct_str)
            };
            let part = BuilderMimePart::new(content_type, att.data.as_slice())
                .inline()
                .cid(bare_cid);
            builder.attachments.get_or_insert_with(Vec::new).push(part);
        } else {
            let filename = att
                .filename
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("attachment");
            builder = builder.attachment(ct_str, filename, att.data.as_slice());
        }
    }

    builder
        .write_to_vec()
        .map_err(|err| AppError::Mime(format!("Failed to serialize RFC 2822 message: {err}")))
}

const RESERVED_RESEND_HEADERS: &[&str] = &[
    "from",
    "to",
    "cc",
    "bcc",
    "reply-to",
    "subject",
    "date",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
    "content-disposition",
    "dkim-signature",
    "received",
    "return-path",
    "message-id",
    "in-reply-to",
    "references",
];

/// Convert a parsed RFC 2822 email into a Resend outbound send payload.
pub fn parsed_to_resend_request(
    parsed: &ParsedEmail,
    default_from: &str,
) -> AppResult<ResendSendEmailRequest> {
    let from = if !parsed.from.trim().is_empty() {
        parsed.from.trim().to_string()
    } else if !default_from.trim().is_empty() {
        default_from.trim().to_string()
    } else {
        return Err(AppError::validation(
            "Missing sender address in From header and no default_from configured",
            Some("Provide a From header or configure NOGML_USER_EMAIL.".to_string()),
        ));
    };

    if parsed.to.is_empty() {
        return Err(AppError::validation(
            "Missing recipient in To header",
            Some("Provide at least one recipient in the To header.".to_string()),
        ));
    }

    let mut headers = HashMap::new();
    for h in &parsed.headers {
        let lower = h.name.to_ascii_lowercase();
        if RESERVED_RESEND_HEADERS.contains(&lower.as_str()) {
            continue;
        }
        if lower.starts_with("x-")
            || lower.starts_with("list-")
            || lower == "auto-submitted"
            || lower == "precedence"
        {
            headers.insert(h.name.clone(), h.value.clone());
        }
    }

    if let Some(ref irt) = parsed.in_reply_to
        && !irt.trim().is_empty()
    {
        headers.insert("In-Reply-To".to_string(), irt.clone());
    }
    if let Some(ref refs) = parsed.references_header
        && !refs.trim().is_empty()
    {
        headers.insert("References".to_string(), refs.clone());
    }

    let attachments: Vec<ResendAttachment> = parsed
        .attachments
        .iter()
        .map(|att| ResendAttachment {
            filename: att
                .filename
                .clone()
                .or_else(|| Some("attachment".to_string())),
            content: Some(STANDARD.encode(&att.data)),
            path: None,
            content_type: (!att.content_type.trim().is_empty()).then(|| att.content_type.clone()),
            content_id: att.content_id.clone(),
        })
        .collect();

    let text = if !parsed.text_body.is_empty() {
        Some(parsed.text_body.clone())
    } else if parsed.html_body.is_none() {
        Some(String::new())
    } else {
        None
    };

    Ok(ResendSendEmailRequest {
        from,
        to: parsed.to.clone(),
        subject: parsed.subject.clone(),
        cc: (!parsed.cc.is_empty()).then(|| parsed.cc.clone()),
        bcc: (!parsed.bcc.is_empty()).then(|| parsed.bcc.clone()),
        reply_to: (!parsed.reply_to.is_empty()).then(|| parsed.reply_to.clone()),
        html: parsed.html_body.clone(),
        text,
        headers: (!headers.is_empty()).then_some(headers),
        attachments: (!attachments.is_empty()).then_some(attachments),
        tags: None,
        scheduled_at: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::MessageFormat;

    #[test]
    fn base64url_encode_and_tolerant_decode() {
        let payload = b"\xff\xfe\xfdHello, Gmail API?!";
        let encoded = encode_base64url(payload);
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));

        // Unpadded URL-safe
        assert_eq!(decode_base64url(&encoded).unwrap(), payload);
        // Padded URL-safe
        let padded = URL_SAFE.encode(payload);
        assert_eq!(decode_base64url(&padded).unwrap(), payload);
        // Standard base64 fallback with whitespace
        let std_b64 = format!("  {}\r\n", STANDARD.encode(payload));
        assert_eq!(decode_base64url(&std_b64).unwrap(), payload);
        // Invalid base64 errors
        assert!(decode_base64url("!!!not-base64!!!").is_err());
    }

    #[test]
    fn normalize_message_id_canonicalizes_case_and_brackets() {
        assert_eq!(
            normalize_message_id("  <AbC.123@Example.COM>  "),
            Some("<abc.123@example.com>".to_string())
        );
        assert_eq!(
            normalize_message_id("raw-id@Example.org"),
            Some("<raw-id@example.org>".to_string())
        );
        assert_eq!(normalize_message_id("   "), None);
        assert_eq!(normalize_message_id("<>"), None);
    }

    #[test]
    fn build_and_parse_roundtrip_multipart_mixed_and_alternative() {
        let mut extra = HashMap::new();
        extra.insert("X-Custom-Tag".to_string(), "alpha-42".to_string());

        let compose = ComposeEmailInput {
            from: "Alice Smith <alice@example.com>".to_string(),
            to: vec![
                "Bob Jones <bob@example.com>".to_string(),
                "carol@example.com".to_string(),
            ],
            cc: vec!["dave@example.com".to_string()],
            bcc: vec!["audit@example.com".to_string()],
            reply_to: vec!["replies@example.com".to_string()],
            subject: "Q4 Report — Final".to_string(),
            text: Some("Hi Bob,\n\nPlease find the Q4 report attached.".to_string()),
            html: Some(
                "<p>Hi Bob,</p><p>Please find the <b>Q4 report</b> attached.</p>".to_string(),
            ),
            message_id: Some("<MSG-100@Example.COM>".to_string()),
            in_reply_to: Some("<MSG-99@Example.COM>".to_string()),
            references: Some("<MSG-98@Example.COM> <MSG-99@Example.COM>".to_string()),
            extra_headers: extra,
            attachments: vec![
                NewAttachmentInput {
                    part_id: String::new(),
                    filename: Some("report.pdf".to_string()),
                    content_type: "application/pdf".to_string(),
                    content_id: None,
                    data: b"%PDF-1.4\nfake-pdf-data".to_vec(),
                },
                NewAttachmentInput {
                    part_id: String::new(),
                    filename: Some("logo.png".to_string()),
                    content_type: "image/png".to_string(),
                    content_id: Some("<logo-cid@example.com>".to_string()),
                    data: vec![0x89, 0x50, 0x4E, 0x47],
                },
            ],
        };

        let raw = build_rfc2822(&compose).expect("build rfc2822");
        let parsed = parse_rfc2822(&raw).expect("parse rfc2822");

        assert_eq!(parsed.from, "Alice Smith <alice@example.com>");
        assert_eq!(
            parsed.to,
            vec!["Bob Jones <bob@example.com>", "carol@example.com"]
        );
        assert_eq!(parsed.cc, vec!["dave@example.com"]);
        assert_eq!(parsed.bcc, vec!["audit@example.com"]);
        assert_eq!(parsed.reply_to, vec!["replies@example.com"]);
        assert_eq!(parsed.subject, "Q4 Report — Final");
        assert!(parsed.date_ms.is_some());
        assert_eq!(
            parsed.rfc822_message_id.as_deref(),
            Some("<msg-100@example.com>")
        );
        assert_eq!(parsed.in_reply_to.as_deref(), Some("<msg-99@example.com>"));
        assert_eq!(
            parsed.references_header.as_deref(),
            Some("<msg-98@example.com> <msg-99@example.com>")
        );
        assert!(
            parsed
                .text_body
                .contains("Please find the Q4 report attached.")
        );
        assert!(
            parsed
                .html_body
                .as_deref()
                .unwrap()
                .contains("<b>Q4 report</b>")
        );
        assert!(parsed.snippet.contains("Hi Bob,"));
        assert!(parsed.snippet.chars().count() <= 200);
        assert_eq!(parsed.attachments.len(), 2);

        let pdf = parsed
            .attachments
            .iter()
            .find(|a| a.filename.as_deref() == Some("report.pdf"))
            .expect("pdf attachment");
        assert_eq!(pdf.content_type, "application/pdf");
        assert_eq!(pdf.data, b"%PDF-1.4\nfake-pdf-data");

        let logo = parsed
            .attachments
            .iter()
            .find(|a| a.content_id.as_deref() == Some("logo-cid@example.com"))
            .expect("inline logo");
        assert_eq!(logo.content_type, "image/png");
        assert_eq!(logo.data, vec![0x89, 0x50, 0x4E, 0x47]);

        // Verify Gmail payload tree matches the exact attachment part_ids.
        let mut att_map = HashMap::new();
        for (i, att) in parsed.attachments.iter().enumerate() {
            att_map.insert(att.part_id.clone(), format!("att_{i}"));
        }

        let full = build_gmail_payload(&raw, MessageFormat::Full, &[], &att_map)
            .unwrap()
            .expect("full payload");
        assert_eq!(full.part_id.as_deref(), Some(""));
        assert_eq!(full.mime_type.as_deref(), Some("multipart/mixed"));
        let top_parts = full.parts.as_ref().expect("top parts");
        assert_eq!(top_parts.len(), 3); // multipart/alternative + 2 attachments

        // Verify text/plain inline data & attachment uses attachmentId with no data.
        let alt = &top_parts[0];
        assert_eq!(alt.mime_type.as_deref(), Some("multipart/alternative"));
        let alt_parts = alt.parts.as_ref().expect("alt parts");
        assert_eq!(alt_parts[0].part_id.as_deref(), Some("0.0"));
        assert_eq!(alt_parts[0].mime_type.as_deref(), Some("text/plain"));
        let decoded_text =
            decode_base64url(alt_parts[0].body.as_ref().unwrap().data.as_deref().unwrap()).unwrap();
        assert!(
            String::from_utf8(decoded_text)
                .unwrap()
                .contains("Q4 report")
        );

        let att_part = &top_parts[1];
        assert_eq!(att_part.filename.as_deref(), Some("report.pdf"));
        let att_body = att_part.body.as_ref().unwrap();
        assert_eq!(att_body.attachment_id.as_deref(), Some("att_0"));
        assert!(att_body.data.is_none());
        assert_eq!(att_body.size, b"%PDF-1.4\nfake-pdf-data".len() as i32);

        // Verify metadata format with case-insensitive metadataHeaders filter.
        let meta = build_gmail_payload(
            &raw,
            MessageFormat::Metadata,
            &["subject".to_string(), "X-CUSTOM-TAG".to_string()],
            &att_map,
        )
        .unwrap()
        .expect("metadata payload");
        assert!(meta.parts.is_none());
        assert!(meta.body.is_none());
        let meta_headers = meta.headers.unwrap();
        assert_eq!(meta_headers.len(), 2);
        assert!(
            meta_headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("subject") && h.value == "Q4 Report — Final")
        );
        assert!(
            meta_headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("x-custom-tag") && h.value == "alpha-42")
        );

        // Verify minimal & raw formats return None payload.
        assert!(
            build_gmail_payload(&raw, MessageFormat::Minimal, &[], &att_map)
                .unwrap()
                .is_none()
        );
        assert!(
            build_gmail_payload(&raw, MessageFormat::Raw, &[], &att_map)
                .unwrap()
                .is_none()
        );

        // Verify Resend mapping.
        let resend_req = parsed_to_resend_request(&parsed, "fallback@example.com").unwrap();
        assert_eq!(resend_req.from, "Alice Smith <alice@example.com>");
        assert_eq!(resend_req.to.len(), 2);
        assert_eq!(resend_req.cc.as_ref().unwrap(), &vec!["dave@example.com"]);
        assert_eq!(resend_req.bcc.as_ref().unwrap(), &vec!["audit@example.com"]);
        assert_eq!(
            resend_req.reply_to.as_ref().unwrap(),
            &vec!["replies@example.com"]
        );
        assert_eq!(resend_req.subject, "Q4 Report — Final");
        let req_headers = resend_req.headers.as_ref().unwrap();
        assert_eq!(
            req_headers.get("In-Reply-To").map(String::as_str),
            Some("<msg-99@example.com>")
        );
        assert_eq!(
            req_headers.get("References").map(String::as_str),
            Some("<msg-98@example.com> <msg-99@example.com>")
        );
        assert_eq!(
            req_headers.get("X-Custom-Tag").map(String::as_str),
            Some("alpha-42")
        );
        let req_atts = resend_req.attachments.as_ref().unwrap();
        assert_eq!(req_atts.len(), 2);
        assert_eq!(
            STANDARD
                .decode(req_atts[0].content.as_deref().unwrap())
                .unwrap(),
            b"%PDF-1.4\nfake-pdf-data"
        );
    }

    #[test]
    fn parse_html_only_email_populates_text_fallback_and_snippet() {
        let raw = b"From: news@example.com\r\nTo: me@example.com\r\nSubject: Digest\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<div><h1>Top Story</h1><p>Rust is fast.</p></div>";
        let parsed = parse_rfc2822(raw).unwrap();
        assert!(parsed.html_body.is_some());
        assert!(parsed.text_body.contains("Top Story"));
        assert!(parsed.text_body.contains("Rust is fast."));
        assert!(parsed.snippet.contains("Top Story"));
    }

    #[test]
    fn parse_plain_text_only_email_keeps_html_body_none() {
        let raw =
            b"From: a@example.com\r\nTo: b@example.com\r\nSubject: Plain\r\n\r\nJust plain text.";
        let parsed = parse_rfc2822(raw).unwrap();
        assert!(parsed.html_body.is_none());
        assert_eq!(parsed.text_body.trim(), "Just plain text.");
    }

    #[test]
    fn build_multipart_alternative_without_attachments() {
        let compose = ComposeEmailInput {
            from: "sender@example.com".to_string(),
            to: vec!["rcpt@example.com".to_string()],
            subject: "Alt Test".to_string(),
            text: Some("Plain version".to_string()),
            html: Some("<p>HTML version</p>".to_string()),
            ..Default::default()
        };
        let raw = build_rfc2822(&compose).unwrap();
        let payload = build_gmail_payload(&raw, MessageFormat::Full, &[], &HashMap::new())
            .unwrap()
            .expect("payload");
        assert_eq!(payload.mime_type.as_deref(), Some("multipart/alternative"));
        let parts = payload.parts.as_ref().unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].part_id.as_deref(), Some("0"));
        assert_eq!(parts[0].mime_type.as_deref(), Some("text/plain"));
        assert_eq!(parts[1].part_id.as_deref(), Some("1"));
        assert_eq!(parts[1].mime_type.as_deref(), Some("text/html"));
    }

    #[test]
    fn parse_text_attachment_and_rfc2047_qp_headers() {
        let raw = concat!(
            "From: =?UTF-8?B?QWxpY2Ug8J+YgA==?= <alice@example.com>\r\n",
            "To: bob@example.com\r\n",
            "Subject: =?UTF-8?Q?Caf=C3=A9_Notes?=\r\n",
            "Date: Wed, 25 Nov 2026 10:00:00 +0000\r\n",
            "Content-Type: multipart/mixed; boundary=\"mix1\"\r\n",
            "\r\n",
            "--mix1\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            "Meet at Caf=C3=A9!\r\n",
            "--mix1\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Content-Disposition: attachment; filename=\"notes.txt\"\r\n",
            "\r\n",
            "secret notes\r\n",
            "--mix1--\r\n",
        );

        let parsed = parse_rfc2822(raw.as_bytes()).unwrap();
        assert_eq!(parsed.subject, "Café Notes");
        assert!(parsed.text_body.contains("Meet at Café!"));
        assert_eq!(parsed.attachments.len(), 1);
        assert_eq!(parsed.attachments[0].filename.as_deref(), Some("notes.txt"));
        assert_eq!(parsed.attachments[0].part_id, "1");
        assert_eq!(parsed.attachments[0].data, b"secret notes");

        let mut att_ids = HashMap::new();
        att_ids.insert("1".to_string(), "att-notes".to_string());
        let payload = build_gmail_payload(raw.as_bytes(), MessageFormat::Full, &[], &att_ids)
            .unwrap()
            .unwrap();
        let parts = payload.parts.unwrap();
        assert_eq!(
            parts[1].body.as_ref().unwrap().attachment_id.as_deref(),
            Some("att-notes")
        );
        assert!(parts[1].body.as_ref().unwrap().data.is_none());
    }

    #[test]
    fn resend_mapping_fallback_from_and_validation() {
        let parsed = parse_rfc2822(b"To: dest@example.com\r\nSubject: Hi\r\n\r\nHello").unwrap();
        let req = parsed_to_resend_request(&parsed, "default@example.com").unwrap();
        assert_eq!(req.from, "default@example.com");
        assert_eq!(req.to, vec!["dest@example.com"]);

        let no_to = parse_rfc2822(b"From: a@example.com\r\nSubject: Hi\r\n\r\nHello").unwrap();
        assert!(parsed_to_resend_request(&no_to, "default@example.com").is_err());

        let mut bad_compose = ComposeEmailInput {
            from: "a@example.com".to_string(),
            to: vec!["b@example.com".to_string()],
            subject: "Hi".to_string(),
            text: Some("body".to_string()),
            ..Default::default()
        };
        bad_compose.extra_headers.insert(
            "X-Evil".to_string(),
            "ok\r\nBcc: attacker@evil.com".to_string(),
        );
        assert!(build_rfc2822(&bad_compose).is_err());
    }
}
