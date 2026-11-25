//! Gmail REST API v1 [`MessagePart`] tree builder and shared MIME part-ID traversal.

use std::collections::HashMap;

use mail_parser::{Header, HeaderValue, MessageParser, PartKind};

use crate::{
    error::{AppError, AppResult},
    mime::encode_base64url,
    models::{MessageFormat, MessagePart, MessagePartBody, MessagePartHeader},
    storage::NewAttachmentInput,
};

/// Determine whether a parsed MIME part should be treated as an attachment
/// (non-inline binary, inline binary media, or explicitly `Content-Disposition: attachment`).
pub(crate) fn is_attachment_part(part: &mail_parser::MessagePart<'_>) -> bool {
    if part.is_multipart() {
        return false;
    }
    if part.is_attachment() {
        return true;
    }
    if part
        .content_disposition()
        .is_some_and(|cd| cd.is_attachment())
    {
        return true;
    }
    matches!(part.kind(), PartKind::Binary | PartKind::InlineBinary)
}

/// Format a MIME part's `Content-Type` as `type/subtype` (defaults to `text/plain` per RFC 2045).
pub(crate) fn part_mime_type(part: &mail_parser::MessagePart<'_>) -> String {
    match part.content_type() {
        Some(ct) => match ct.subtype() {
            Some(sub) if !sub.is_empty() => format!("{}/{}", ct.ctype(), sub),
            _ => ct.ctype().to_string(),
        },
        None => "text/plain".to_string(),
    }
}

/// Format a single `mail_parser::Mailbox` as `"Name <addr>"` or `"addr"`.
pub(crate) fn format_mailbox(mailbox: mail_parser::Mailbox<'_>) -> Option<String> {
    let name = mailbox.name().map(str::trim).filter(|s| !s.is_empty());
    let addr = mailbox.address().map(str::trim).filter(|s| !s.is_empty());
    match (name, addr) {
        (Some(n), Some(a)) => Some(format!("{n} <{a}>")),
        (None, Some(a)) => Some(a.to_string()),
        (Some(n), None) => Some(n.to_string()),
        (None, None) => None,
    }
}

/// Unfold raw RFC 5322 header value bytes into a clean single-line string.
pub(crate) fn unfold_raw_header(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\r' || ch == '\n' {
            if ch == '\r' && chars.peek() == Some(&'\n') {
                chars.next();
            }
            // RFC 5322 folding: CRLF followed by WSP (space/tab) collapses to a single space.
            let mut had_wsp = false;
            while matches!(chars.peek(), Some(' ') | Some('\t')) {
                chars.next();
                had_wsp = true;
            }
            if had_wsp && !out.is_empty() && !out.ends_with(' ') {
                out.push(' ');
            }
        } else {
            out.push(ch);
        }
    }
    out.trim().to_string()
}

/// Extract a Gmail-style header value string (RFC 2047 decoded when encoded words are present).
pub(crate) fn extract_header_value(header: &Header<'_>) -> String {
    let raw = header.raw_value();
    let unfolded = unfold_raw_header(raw);
    let has_encoded_word = unfolded.contains("=?");

    if header.raw_name().eq_ignore_ascii_case("subject")
        && let Some(decoded) = header.value().as_text()
    {
        return decoded.trim().to_string();
    }

    if has_encoded_word {
        match header.value() {
            HeaderValue::Text(decoded) => return decoded.trim().to_string(),
            HeaderValue::Address(list) => {
                let formatted: Vec<String> =
                    list.mailboxes().filter_map(format_mailbox).collect();
                if !formatted.is_empty() {
                    return formatted.join(", ");
                }
            }
            _ => {}
        }
    }

    unfolded
}

/// Extract all headers from a `mail_parser::MessagePart` in document order.
pub(crate) fn extract_part_headers(part: &mail_parser::MessagePart<'_>) -> Vec<MessagePartHeader> {
    part.headers()
        .iter()
        .map(|h| MessagePartHeader {
            name: h.raw_name().to_string(),
            value: extract_header_value(&h),
        })
        .collect()
}

/// Collect attachments using the exact Gmail hierarchical `partId` scheme (`""`, `"0"`, `"0.1"`, ...).
pub(crate) fn collect_attachments_with_part_ids(
    root: mail_parser::MessagePart<'_>,
) -> Vec<NewAttachmentInput> {
    let mut out = Vec::new();
    collect_attachments_rec(root, "", &mut out);
    out
}

fn collect_attachments_rec(
    part: mail_parser::MessagePart<'_>,
    part_id: &str,
    out: &mut Vec<NewAttachmentInput>,
) {
    if part.is_multipart() {
        for (idx, child) in part.children().enumerate() {
            let child_id = child_part_id(part_id, idx);
            collect_attachments_rec(child, &child_id, out);
        }
        return;
    }

    if is_attachment_part(&part) {
        let data = part.decoded().into_owned();
        let content_type = part_mime_type(&part);
        let filename = part.attachment_name().map(str::to_string);
        let content_id = part
            .content_id()
            .map(|cid| cid.trim().trim_matches(|c| c == '<' || c == '>').to_string())
            .filter(|s| !s.is_empty());

        out.push(NewAttachmentInput {
            part_id: part_id.to_string(),
            filename,
            content_type,
            content_id,
            data,
        });
    }
}

fn child_part_id(parent_id: &str, idx: usize) -> String {
    if parent_id.is_empty() {
        idx.to_string()
    } else {
        format!("{parent_id}.{idx}")
    }
}

fn build_part_tree(
    part: mail_parser::MessagePart<'_>,
    part_id: &str,
    attachment_ids: &HashMap<String, String>,
) -> MessagePart {
    let mime_type = Some(part_mime_type(&part));
    let filename = part.attachment_name().map(str::to_string);
    let headers = extract_part_headers(&part);
    let headers_opt = (!headers.is_empty()).then_some(headers);

    if part.is_multipart() {
        let children: Vec<MessagePart> = part
            .children()
            .enumerate()
            .map(|(idx, child)| {
                let child_id = child_part_id(part_id, idx);
                build_part_tree(child, &child_id, attachment_ids)
            })
            .collect();

        return MessagePart {
            part_id: Some(part_id.to_string()),
            mime_type,
            filename,
            headers: headers_opt,
            body: Some(MessagePartBody {
                attachment_id: None,
                size: 0,
                data: None,
            }),
            parts: (!children.is_empty()).then_some(children),
        };
    }

    let decoded = part.decoded();
    let size = i32::try_from(decoded.len()).unwrap_or(i32::MAX);

    let body = if is_attachment_part(&part) {
        let att_id = attachment_ids.get(part_id).cloned().or_else(|| {
            filename
                .as_deref()
                .and_then(|name| attachment_ids.get(name))
                .cloned()
        });

        match att_id {
            Some(id) => MessagePartBody {
                attachment_id: Some(id),
                size,
                data: None,
            },
            None => MessagePartBody {
                attachment_id: None,
                size,
                data: Some(encode_base64url(&decoded)),
            },
        }
    } else {
        MessagePartBody {
            attachment_id: None,
            size,
            data: Some(encode_base64url(&decoded)),
        }
    };

    MessagePart {
        part_id: Some(part_id.to_string()),
        mime_type,
        filename,
        headers: headers_opt,
        body: Some(body),
        parts: None,
    }
}

/// Convert raw RFC 2822 bytes into a Gmail REST API v1 [`MessagePart`] tree for `format`
/// and optional case-insensitive `metadata_headers` filter.
pub fn build_gmail_payload(
    raw: &[u8],
    format: MessageFormat,
    metadata_headers: &[String],
    attachment_ids: &HashMap<String, String>,
) -> AppResult<Option<MessagePart>> {
    match format {
        MessageFormat::Minimal | MessageFormat::Raw => Ok(None),
        MessageFormat::Metadata => {
            if raw.is_empty() {
                return Err(AppError::Mime("Empty RFC 2822 message".to_string()));
            }
            let message = MessageParser::new()
                .parse(raw)
                .ok_or_else(|| AppError::Mime("Failed to parse RFC 2822 message".to_string()))?;
            let root = message.root_part();
            let all_headers = extract_part_headers(&root);
            let filtered = if metadata_headers.is_empty() {
                all_headers
            } else {
                all_headers
                    .into_iter()
                    .filter(|h| {
                        metadata_headers
                            .iter()
                            .any(|wanted| h.name.eq_ignore_ascii_case(wanted))
                    })
                    .collect()
            };

            Ok(Some(MessagePart {
                part_id: Some(String::new()),
                mime_type: Some(part_mime_type(&root)),
                filename: None,
                headers: Some(filtered),
                body: None,
                parts: None,
            }))
        }
        MessageFormat::Full => {
            if raw.is_empty() {
                return Err(AppError::Mime("Empty RFC 2822 message".to_string()));
            }
            let message = MessageParser::new()
                .parse(raw)
                .ok_or_else(|| AppError::Mime("Failed to parse RFC 2822 message".to_string()))?;
            Ok(Some(build_part_tree(message.root_part(), "", attachment_ids)))
        }
    }
}
