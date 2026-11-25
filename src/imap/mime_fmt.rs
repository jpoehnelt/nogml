//! RFC 3501 MIME inspection and response formatting for `FETCH` (`ENVELOPE`,
//! `BODYSTRUCTURE`, `BODY`, `BODY[...]`, `RFC822*`) and `APPEND` message parsing.

use std::collections::HashSet;

use chrono::Utc;
use mail_parser::{AddressList, MessageParser, MessagePart, MessageRef, PartKind};

use crate::{
    imap::parser::{imap_nstring, imap_quote, imap_string},
    storage::{NewAttachmentInput, NewMessageInput},
};

/// Parsed `BODY[...]` section selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodySection {
    /// Whole message (`BODY[]`).
    Entire,
    /// Top-level or part header (`HEADER` or `1.2.HEADER`).
    Header(Vec<usize>),
    /// Filtered headers (`HEADER.FIELDS (...)` or `1.HEADER.FIELDS (...)`).
    HeaderFields {
        part_path: Vec<usize>,
        fields: Vec<String>,
        negate: bool,
    },
    /// Top-level or part body text (`TEXT` or `1.2.TEXT`).
    Text(Vec<usize>),
    /// MIME header of a specific part (`1.2.MIME`).
    Mime(Vec<usize>),
    /// Raw body of a specific MIME part (`1`, `1.2`, etc.).
    Part(Vec<usize>),
}

/// Parse a `BODY[section]` specification (the text inside `[...]`).
pub fn parse_body_section(inner: &str) -> BodySection {
    let trimmed = inner.trim();
    if trimmed.is_empty() {
        return BodySection::Entire;
    }

    // Check for HEADER.FIELDS / HEADER.FIELDS.NOT with parenthesized header list.
    let upper = trimmed.to_ascii_uppercase();
    if let Some(pos) = upper.find("HEADER.FIELDS.NOT") {
        let prefix = trimmed[..pos].trim_end_matches('.');
        let rest = trimmed[pos + "HEADER.FIELDS.NOT".len()..].trim();
        return BodySection::HeaderFields {
            part_path: parse_part_path(prefix),
            fields: parse_field_list(rest),
            negate: true,
        };
    }
    if let Some(pos) = upper.find("HEADER.FIELDS") {
        let prefix = trimmed[..pos].trim_end_matches('.');
        let rest = trimmed[pos + "HEADER.FIELDS".len()..].trim();
        return BodySection::HeaderFields {
            part_path: parse_part_path(prefix),
            fields: parse_field_list(rest),
            negate: false,
        };
    }

    if upper == "HEADER" {
        return BodySection::Header(Vec::new());
    }
    if let Some(prefix) = upper.strip_suffix(".HEADER") {
        return BodySection::Header(parse_part_path(prefix));
    }
    if upper == "TEXT" {
        return BodySection::Text(Vec::new());
    }
    if let Some(prefix) = upper.strip_suffix(".TEXT") {
        return BodySection::Text(parse_part_path(prefix));
    }
    if upper == "MIME" {
        return BodySection::Mime(Vec::new());
    }
    if let Some(prefix) = upper.strip_suffix(".MIME") {
        return BodySection::Mime(parse_part_path(prefix));
    }

    let path = parse_part_path(trimmed);
    if path.is_empty() {
        BodySection::Entire
    } else {
        BodySection::Part(path)
    }
}

fn parse_part_path(s: &str) -> Vec<usize> {
    if s.trim().is_empty() {
        return Vec::new();
    }
    s.trim()
        .split('.')
        .filter_map(|p| p.parse::<usize>().ok().filter(|&n| n >= 1))
        .collect()
}

fn parse_field_list(s: &str) -> Vec<String> {
    let inner = s
        .trim()
        .strip_prefix('(')
        .and_then(|x| x.strip_suffix(')'))
        .unwrap_or(s);
    inner
        .split_whitespace()
        .map(|tok| tok.trim_matches('"').to_ascii_lowercase())
        .filter(|tok| !tok.is_empty())
        .collect()
}

/// Extract bytes for a `BODY[section]<partial>` request from raw RFC 2822 bytes.
pub fn extract_body_section(
    raw: &[u8],
    section: &BodySection,
    partial: Option<(usize, usize)>,
) -> Vec<u8> {
    let full = match section {
        BodySection::Entire => raw.to_vec(),
        BodySection::Header(path) => {
            if path.is_empty() {
                split_raw_header_and_body(raw).0.to_vec()
            } else {
                find_part_by_path(raw, path)
                    .map(|p| p.header)
                    .unwrap_or_default()
            }
        }
        BodySection::HeaderFields {
            part_path,
            fields,
            negate,
        } => {
            let hdr_bytes = if part_path.is_empty() {
                split_raw_header_and_body(raw).0.to_vec()
            } else {
                find_part_by_path(raw, part_path)
                    .map(|p| p.header)
                    .unwrap_or_default()
            };
            filter_header_fields(&hdr_bytes, fields, *negate)
        }
        BodySection::Text(path) => {
            if path.is_empty() {
                split_raw_header_and_body(raw).1.to_vec()
            } else {
                find_part_by_path(raw, path)
                    .map(|p| p.body)
                    .unwrap_or_default()
            }
        }
        BodySection::Mime(path) => {
            if path.is_empty() {
                split_raw_header_and_body(raw).0.to_vec()
            } else {
                find_part_by_path(raw, path)
                    .map(|p| p.header)
                    .unwrap_or_default()
            }
        }
        BodySection::Part(path) => find_part_by_path(raw, path)
            .map(|p| p.body)
            .unwrap_or_default(),
    };

    if let Some((offset, count)) = partial {
        if offset >= full.len() || count == 0 {
            return Vec::new();
        }
        let end = offset.saturating_add(count).min(full.len());
        full[offset..end].to_vec()
    } else {
        full
    }
}

struct ExtractedPart {
    header: Vec<u8>,
    body: Vec<u8>,
}

fn find_part_by_path(raw: &[u8], path: &[usize]) -> Option<ExtractedPart> {
    let parsed = MessageParser::new().parse(raw)?;
    let root = parsed.root_part();
    let part = resolve_mime_part(root, path)?;
    Some(ExtractedPart {
        header: part.raw_headers().to_vec(),
        body: part.raw_body().to_vec(),
    })
}

fn resolve_mime_part<'m>(current: MessagePart<'m>, path: &[usize]) -> Option<MessagePart<'m>> {
    if path.is_empty() {
        return Some(current);
    }
    let idx = path[0].checked_sub(1)?;
    if current.is_multipart() {
        let child = current.children().nth(idx)?;
        resolve_mime_part(child, &path[1..])
    } else if let Some(nested) = current.nested() {
        resolve_mime_part(nested.root_part(), path)
    } else if path == [1] {
        // RFC 3501: non-multipart message has a single implicit part "1".
        Some(current)
    } else {
        None
    }
}

/// Split raw RFC 2822 bytes into `(header_including_blank_line, body)`.
pub fn split_raw_header_and_body(raw: &[u8]) -> (&[u8], &[u8]) {
    for i in 0..raw.len() {
        if i + 3 < raw.len()
            && raw[i] == b'\r'
            && raw[i + 1] == b'\n'
            && raw[i + 2] == b'\r'
            && raw[i + 3] == b'\n'
        {
            return (&raw[..i + 4], &raw[i + 4..]);
        }
        if i + 1 < raw.len() && raw[i] == b'\n' && raw[i + 1] == b'\n' {
            return (&raw[..i + 2], &raw[i + 2..]);
        }
    }
    (raw, &[])
}

/// Filter raw RFC 2822 header lines by field names (unfolding continuation lines properly).
pub fn filter_header_fields(header_bytes: &[u8], fields: &[String], negate: bool) -> Vec<u8> {
    let wanted: HashSet<String> = fields.iter().map(|f| f.to_ascii_lowercase()).collect();
    let text = String::from_utf8_lossy(header_bytes);
    let mut out = String::new();
    let mut include_current = false;

    for raw_line in text.split('\n') {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if include_current {
                out.push_str(line);
                out.push_str("\r\n");
            }
            continue;
        }
        if let Some((name, _)) = line.split_once(':') {
            let lower = name.trim().to_ascii_lowercase();
            let matched = wanted.contains(&lower);
            include_current = if negate { !matched } else { matched };
            if include_current {
                out.push_str(line);
                out.push_str("\r\n");
            }
        } else {
            include_current = false;
        }
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// Format an RFC 3501 `ENVELOPE` S-expression from raw RFC 2822 bytes.
///
/// `(date subject from sender reply-to to cc bcc in-reply-to message-id)`
pub fn format_envelope(raw: &[u8]) -> String {
    let Some(parsed) = MessageParser::new().parse(raw) else {
        return "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)".to_string();
    };
    format_envelope_ref(parsed.root())
}

fn format_envelope_ref(msg: MessageRef<'_>) -> String {
    let date = msg
        .date()
        .map(|d| d.to_rfc822())
        .or_else(|| {
            msg.headers()
                .get(mail_parser::HeaderName::Date)
                .map(|h| String::from_utf8_lossy(h.raw_value()).trim().to_string())
        });
    let subject = msg.subject();
    let from = format_addr_list(msg.from());
    let sender = msg
        .sender()
        .map(|s| format_addr_list(Some(s)))
        .unwrap_or_else(|| from.clone());
    let reply_to = msg
        .reply_to()
        .map(|r| format_addr_list(Some(r)))
        .unwrap_or_else(|| from.clone());
    let to = format_addr_list(msg.to());
    let cc = format_addr_list(msg.cc());
    let bcc = format_addr_list(msg.bcc());
    let in_reply_to = msg
        .in_reply_to()
        .and_then(|l| l.first())
        .map(format_angle_id);
    let message_id = msg.message_id().map(format_angle_id);

    format!(
        "({} {} {} {} {} {} {} {} {} {})",
        imap_nstring(date.as_deref()),
        imap_nstring(subject),
        from,
        sender,
        reply_to,
        to,
        cc,
        bcc,
        imap_nstring(in_reply_to.as_deref()),
        imap_nstring(message_id.as_deref()),
    )
}

fn format_angle_id(id: &str) -> String {
    let trimmed = id.trim();
    if trimmed.starts_with('<') && trimmed.ends_with('>') {
        trimmed.to_string()
    } else {
        format!("<{trimmed}>")
    }
}

fn format_addr_list(list: Option<AddressList<'_>>) -> String {
    let Some(list) = list else {
        return "NIL".to_string();
    };
    let mut entries = Vec::new();
    for mbx in list.mailboxes() {
        let name = imap_nstring(mbx.name());
        let (local, host) = match mbx.address() {
            Some(addr) => match addr.split_once('@') {
                Some((l, h)) => (imap_nstring(Some(l)), imap_nstring(Some(h))),
                None => (imap_nstring(Some(addr)), "NIL".to_string()),
            },
            None => ("NIL".to_string(), "NIL".to_string()),
        };
        entries.push(format!("({name} NIL {local} {host})"));
    }
    if entries.is_empty() {
        "NIL".to_string()
    } else {
        format!("({})", entries.join(" "))
    }
}

/// Format an RFC 3501 `BODYSTRUCTURE` (when `extended == true`) or `BODY` (when `extended == false`).
pub fn format_bodystructure(raw: &[u8], extended: bool) -> String {
    let Some(parsed) = MessageParser::new().parse(raw) else {
        return if extended {
            r#"("TEXT" "PLAIN" ("CHARSET" "UTF-8") NIL NIL "7BIT" 0 0 NIL NIL NIL NIL)"#.to_string()
        } else {
            r#"("TEXT" "PLAIN" ("CHARSET" "UTF-8") NIL NIL "7BIT" 0 0)"#.to_string()
        };
    };
    format_part_bodystructure(parsed.root_part(), extended)
}

fn format_part_bodystructure(part: MessagePart<'_>, extended: bool) -> String {
    if part.is_multipart() {
        let mut children_str = String::new();
        for child in part.children() {
            children_str.push_str(&format_part_bodystructure(child, extended));
        }
        let subtype = part
            .content_type()
            .and_then(|ct| ct.subtype())
            .unwrap_or("mixed")
            .to_ascii_uppercase();
        if !extended {
            return format!("({children_str} {})", imap_quote(&subtype));
        }
        let params = format_ct_params(part.content_type());
        let disp = format_disposition(part.content_disposition());
        return format!("({children_str} {} {params} {disp} NIL NIL)", imap_quote(&subtype));
    }

    let (ctype, subtype) = match part.content_type() {
        Some(ct) => (
            ct.ctype().to_ascii_uppercase(),
            ct.subtype().unwrap_or("plain").to_ascii_uppercase(),
        ),
        None => ("TEXT".to_string(), "PLAIN".to_string()),
    };

    let params = format_ct_params(part.content_type());
    let content_id = imap_nstring(part.content_id().map(format_angle_id).as_deref());
    let desc = imap_nstring(part.content_description());
    let encoding = part
        .content_transfer_encoding()
        .map(|s| s.trim().to_ascii_uppercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "7BIT".to_string());
    let raw_body = part.raw_body();
    let octets = raw_body.len();

    let mut fields = vec![
        imap_quote(&ctype),
        imap_quote(&subtype),
        params,
        content_id,
        desc,
        imap_quote(&encoding),
        octets.to_string(),
    ];

    if ctype == "TEXT" {
        let lines = raw_body.iter().filter(|&&b| b == b'\n').count();
        fields.push(lines.to_string());
    } else if ctype == "MESSAGE" && subtype == "RFC822" {
        if let Some(nested) = part.nested() {
            fields.push(format_envelope_ref(nested));
            fields.push(format_part_bodystructure(nested.root_part(), extended));
        } else {
            fields.push("(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)".to_string());
            fields.push(r#"("TEXT" "PLAIN" NIL NIL NIL "7BIT" 0 0)"#.to_string());
        }
        let lines = raw_body.iter().filter(|&&b| b == b'\n').count();
        fields.push(lines.to_string());
    }

    if extended {
        // md5, disposition, language, location
        fields.push("NIL".to_string());
        fields.push(format_disposition(part.content_disposition()));
        fields.push("NIL".to_string());
        fields.push(imap_nstring(part.content_location()));
    }

    format!("({})", fields.join(" "))
}

fn format_ct_params(ct: Option<mail_parser::ContentType<'_>>) -> String {
    let Some(ct) = ct else {
        return "NIL".to_string();
    };
    let mut pairs = Vec::new();
    for (k, v) in ct.attributes() {
        pairs.push(imap_quote(&k.to_ascii_uppercase()));
        pairs.push(imap_string(v));
    }
    if pairs.is_empty() {
        "NIL".to_string()
    } else {
        format!("({})", pairs.join(" "))
    }
}

fn format_disposition(cd: Option<mail_parser::ContentType<'_>>) -> String {
    let Some(cd) = cd else {
        return "NIL".to_string();
    };
    let params = format_ct_params(Some(cd));
    format!("({} {params})", imap_quote(&cd.ctype().to_ascii_uppercase()))
}

/// Parse raw RFC 2822 bytes into a [`NewMessageInput`] suitable for `MailStore::imap_append` or sync upsert.
#[allow(clippy::too_many_arguments)]
pub fn parse_raw_to_new_message_input(
    raw: Vec<u8>,
    label_ids: Vec<String>,
    internal_date_ms: Option<i64>,
    source: &str,
    upstream_gmail_id: Option<String>,
    upstream_thread_id: Option<String>,
    is_answered: bool,
    is_deleted: bool,
) -> NewMessageInput {
    let parsed = MessageParser::new().parse(&raw);
    let now_ms = Utc::now().timestamp_millis();

    let Some(msg) = parsed else {
        let text = String::from_utf8_lossy(&raw).into_owned();
        let snippet = make_snippet(&text);
        return NewMessageInput {
            id: None,
            thread_id: None,
            label_ids,
            raw_rfc2822: raw,
            snippet,
            internal_date_ms: internal_date_ms.unwrap_or(now_ms),
            subject: String::new(),
            from_addr: String::new(),
            to_addrs: Vec::new(),
            cc_addrs: Vec::new(),
            bcc_addrs: Vec::new(),
            text_body: text,
            html_body: None,
            rfc822_message_id: None,
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id,
            upstream_thread_id,
            source: source.to_string(),
            is_answered,
            is_deleted,
            attachments: Vec::new(),
        };
    };

    let subject = msg.subject().unwrap_or_default().to_string();
    let from_addr = format_first_address(msg.from());
    let to_addrs = collect_addresses(msg.to());
    let cc_addrs = collect_addresses(msg.cc());
    let bcc_addrs = collect_addresses(msg.bcc());

    let text_parts: Vec<String> = msg.text_bodies().map(|s| s.into_owned()).collect();
    let html_parts: Vec<String> = msg.html_bodies().map(|s| s.into_owned()).collect();
    let html_body = if html_parts.is_empty() {
        None
    } else {
        Some(html_parts.join("\n"))
    };
    let text_body = if !text_parts.is_empty() {
        text_parts.join("\n")
    } else if let Some(ref html) = html_body {
        mail_parser::html_to_text(html)
    } else {
        String::new()
    };
    let snippet = make_snippet(&text_body);

    let date_ms = internal_date_ms
        .or_else(|| msg.date().map(|d| d.to_timestamp() * 1000))
        .unwrap_or(now_ms);

    let rfc822_message_id = msg.message_id().map(normalize_msg_id);
    let in_reply_to = msg
        .in_reply_to()
        .and_then(|l| l.first())
        .map(normalize_msg_id);
    let references_header = msg.references().map(|l| {
        l.iter()
            .map(normalize_msg_id)
            .collect::<Vec<_>>()
            .join(" ")
    });

    let mut attachments = Vec::new();
    for (idx, att) in msg.attachments().enumerate() {
        let content_type = match att.content_type() {
            Some(ct) => match ct.subtype() {
                Some(sub) => format!("{}/{sub}", ct.ctype()),
                None => ct.ctype().to_string(),
            },
            None => "application/octet-stream".to_string(),
        };
        let filename = att.attachment_name().map(str::to_string);
        let content_id = att.content_id().map(str::to_string);
        let data = att.decoded().into_owned();
        if matches!(att.kind(), PartKind::Multipart) {
            continue;
        }
        attachments.push(NewAttachmentInput {
            part_id: format!("att-{}", idx + 1),
            filename,
            content_type,
            content_id,
            data,
        });
    }

    NewMessageInput {
        id: None,
        thread_id: None,
        label_ids,
        raw_rfc2822: raw,
        snippet,
        internal_date_ms: date_ms,
        subject,
        from_addr,
        to_addrs,
        cc_addrs,
        bcc_addrs,
        text_body,
        html_body,
        rfc822_message_id,
        in_reply_to,
        references_header,
        resend_id: None,
        upstream_gmail_id,
        upstream_thread_id,
        source: source.to_string(),
        is_answered,
        is_deleted,
        attachments,
    }
}

fn format_first_address(list: Option<AddressList<'_>>) -> String {
    let Some(mbx) = list.and_then(|l| l.first()) else {
        return String::new();
    };
    match (mbx.name(), mbx.address()) {
        (Some(name), Some(addr)) if !name.is_empty() => format!("{name} <{addr}>"),
        (_, Some(addr)) => addr.to_string(),
        (Some(name), None) => name.to_string(),
        (None, None) => String::new(),
    }
}

fn collect_addresses(list: Option<AddressList<'_>>) -> Vec<String> {
    let Some(list) = list else {
        return Vec::new();
    };
    list.mailboxes()
        .filter_map(|mbx| match (mbx.name(), mbx.address()) {
            (Some(name), Some(addr)) if !name.is_empty() => Some(format!("{name} <{addr}>")),
            (_, Some(addr)) => Some(addr.to_string()),
            _ => None,
        })
        .collect()
}

fn normalize_msg_id(raw: &str) -> String {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.starts_with('<') && trimmed.ends_with('>') {
        trimmed
    } else {
        format!("<{trimmed}>")
    }
}

fn make_snippet(text: &str) -> String {
    let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.chars().take(200).collect()
}
