//! Pure-Rust attachment text extraction for AI agents with strict byte and character ceilings.
//!
//! Supported formats:
//! - Plain & structured text (`text/plain`, `text/markdown`, `text/csv`, `application/json`,
//!   `application/xml`, `.txt`, `.csv`, `.md`, `.json`, `.log`, etc.)
//! - HTML attachments (`text/html`, `.html`, `.htm`) converted to Markdown
//! - RFC 5545 iCalendar (`text/calendar`, `.ics`) parsed into structured `VEVENT` fields + summary
//! - PDF (`application/pdf`, `.pdf`) text stream extraction (including bounded `FlateDecode`
//!   decompression) with clean fallback for image-only/scanned PDFs
//! - Unsupported binary attachments return `extracted: false` with a descriptive reason

use std::io::Read;

use flate2::read::ZlibDecoder;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    mime::{html_to_markdown, sanitize_untrusted_text},
    models::AttachmentTextExtraction,
};

/// Default byte ceiling for attachment extraction (5 MiB).
pub const DEFAULT_ATTACHMENT_MAX_BYTES: usize = 5 * 1024 * 1024;
/// Default character ceiling for extracted attachment text.
pub const DEFAULT_ATTACHMENT_MAX_CHARS: usize = 20_000;
/// Hard upper bound on extracted attachment text characters.
pub const HARD_ATTACHMENT_MAX_CHARS: usize = 100_000;

/// Maximum decompressed size per PDF stream (guards against zip/PDF bombs).
const MAX_PDF_STREAM_DECOMPRESSED_BYTES: usize = 4 * 1024 * 1024;
/// Maximum cumulative decompressed/scanned bytes across all streams in a single PDF.
const MAX_PDF_TOTAL_DECOMPRESSED_BYTES: usize = 8 * 1024 * 1024;
/// Maximum tokens tokenized from a single PDF content stream (guards against OOM/CPU DoS).
const MAX_PDF_TOKENS: usize = 200_000;

/// Clamp an optional requested `max_chars` value to `[0, HARD_ATTACHMENT_MAX_CHARS]`.
pub fn clamp_attachment_max_chars(requested: Option<usize>) -> usize {
    requested
        .unwrap_or(DEFAULT_ATTACHMENT_MAX_CHARS)
        .min(HARD_ATTACHMENT_MAX_CHARS)
}

/// Build an oversize refusal payload without loading raw attachment bytes into memory.
pub fn oversize_attachment_extraction(
    filename: Option<String>,
    content_type: String,
    size_bytes: u64,
    max_bytes: usize,
) -> AttachmentTextExtraction {
    AttachmentTextExtraction {
        attachment_id: None,
        message_id: None,
        filename,
        content_type,
        size_bytes,
        extracted: false,
        format: None,
        text: None,
        truncated: false,
        total_chars: 0,
        structured: None,
        reason: Some(format!(
            "attachment exceeds maximum extraction size ({size_bytes} bytes > {max_bytes} bytes)"
        )),
        meta: None,
    }
}

/// Extract readable text and/or structured metadata from attachment bytes with strict
/// `max_bytes` and `max_chars` ceilings and optional untrusted-content sanitization.
pub fn extract_attachment_text(
    data: &[u8],
    content_type: &str,
    filename: Option<&str>,
    max_chars: Option<usize>,
    max_bytes: usize,
    sanitize: bool,
) -> AttachmentTextExtraction {
    let effective_max_chars = clamp_attachment_max_chars(max_chars);
    let clean_ct = normalize_content_type(content_type);
    let size_bytes = data.len() as u64;
    let filename_owned = filename.map(str::to_string);

    if data.len() > max_bytes {
        return oversize_attachment_extraction(filename_owned, clean_ct, size_bytes, max_bytes);
    }

    let kind = classify_attachment(&clean_ct, filename);

    match kind {
        AttachmentKind::Calendar => extract_ics_attachment(
            data,
            clean_ct,
            filename_owned,
            size_bytes,
            effective_max_chars,
            sanitize,
        ),
        AttachmentKind::Html => {
            let raw = decode_utf8_text(data);
            let md = html_to_markdown(&raw);
            let cleaned = maybe_sanitize(&md, sanitize);
            build_text_result(
                filename_owned,
                clean_ct,
                size_bytes,
                "markdown",
                cleaned,
                effective_max_chars,
                None,
            )
        }
        AttachmentKind::Plain(fmt) => {
            let raw = decode_utf8_text(data);
            let cleaned = maybe_sanitize(&raw, sanitize);
            build_text_result(
                filename_owned,
                clean_ct,
                size_bytes,
                fmt,
                cleaned,
                effective_max_chars,
                None,
            )
        }
        AttachmentKind::Pdf => extract_pdf_attachment(
            data,
            clean_ct,
            filename_owned,
            size_bytes,
            effective_max_chars,
            sanitize,
        ),
        AttachmentKind::UnsupportedBinary => AttachmentTextExtraction {
            attachment_id: None,
            message_id: None,
            filename: filename_owned,
            content_type: clean_ct,
            size_bytes,
            extracted: false,
            format: None,
            text: None,
            truncated: false,
            total_chars: 0,
            structured: None,
            reason: Some("unsupported binary attachment type".to_string()),
            meta: None,
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttachmentKind {
    Plain(&'static str),
    Html,
    Calendar,
    Pdf,
    UnsupportedBinary,
}

fn normalize_content_type(content_type: &str) -> String {
    let base = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if base.is_empty() {
        "application/octet-stream".to_string()
    } else {
        base
    }
}

fn filename_extension(filename: Option<&str>) -> Option<String> {
    let name = filename?.trim();
    let dot = name.rfind('.')?;
    if dot + 1 >= name.len() {
        return None;
    }
    Some(name[dot + 1..].to_ascii_lowercase())
}

fn classify_attachment(content_type: &str, filename: Option<&str>) -> AttachmentKind {
    let ext = filename_extension(filename);

    // Calendar (.ics)
    if matches!(content_type, "text/calendar" | "application/ics")
        || matches!(ext.as_deref(), Some("ics" | "ical" | "ifb"))
    {
        return AttachmentKind::Calendar;
    }

    // PDF
    if content_type == "application/pdf" || ext.as_deref() == Some("pdf") {
        return AttachmentKind::Pdf;
    }

    // HTML
    if matches!(content_type, "text/html" | "application/xhtml+xml")
        || matches!(ext.as_deref(), Some("html" | "htm" | "xhtml"))
    {
        return AttachmentKind::Html;
    }

    // Known plain/structured text MIME types
    match content_type {
        "text/plain" => return AttachmentKind::Plain("text"),
        "text/markdown" | "text/x-markdown" => return AttachmentKind::Plain("markdown"),
        "text/csv" | "application/csv" => return AttachmentKind::Plain("csv"),
        "text/tab-separated-values" => return AttachmentKind::Plain("tsv"),
        "application/json" | "application/ld+json" | "text/json" => {
            return AttachmentKind::Plain("json");
        }
        "application/xml" | "text/xml" => return AttachmentKind::Plain("xml"),
        "application/x-yaml" | "text/yaml" | "text/x-yaml" => {
            return AttachmentKind::Plain("yaml");
        }
        ct if ct.starts_with("text/") => return AttachmentKind::Plain("text"),
        _ => {}
    }

    // Filename extension fallback for generic `application/octet-stream` attachments
    match ext.as_deref() {
        Some("txt" | "log") => AttachmentKind::Plain("text"),
        Some("md" | "markdown") => AttachmentKind::Plain("markdown"),
        Some("csv") => AttachmentKind::Plain("csv"),
        Some("tsv") => AttachmentKind::Plain("tsv"),
        Some("json") => AttachmentKind::Plain("json"),
        Some("xml") => AttachmentKind::Plain("xml"),
        Some("yaml" | "yml") => AttachmentKind::Plain("yaml"),
        Some("toml") => AttachmentKind::Plain("toml"),
        _ => AttachmentKind::UnsupportedBinary,
    }
}

fn decode_utf8_text(data: &[u8]) -> String {
    let text = String::from_utf8_lossy(data);
    text.strip_prefix('\u{FEFF}').unwrap_or(&text).to_string()
}

fn maybe_sanitize(input: &str, sanitize: bool) -> String {
    if sanitize {
        sanitize_untrusted_text(input)
    } else {
        input.to_string()
    }
}

fn build_text_result(
    filename: Option<String>,
    content_type: String,
    size_bytes: u64,
    format: &str,
    full_text: String,
    max_chars: usize,
    structured: Option<Value>,
) -> AttachmentTextExtraction {
    let total_chars = full_text.chars().count();
    let (text, truncated) = if total_chars > max_chars {
        (full_text.chars().take(max_chars).collect(), true)
    } else {
        (full_text, false)
    };

    AttachmentTextExtraction {
        attachment_id: None,
        message_id: None,
        filename,
        content_type,
        size_bytes,
        extracted: true,
        format: Some(format.to_string()),
        text: Some(text),
        truncated,
        total_chars,
        structured,
        reason: None,
        meta: None,
    }
}

// ============================================================================
// RFC 5545 iCalendar (.ics) VEVENT Parser
// ============================================================================

/// Parsed RFC 5545 `VEVENT` calendar event.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CalendarEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dtstart: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dtend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organizer: Option<String>,
    #[serde(default)]
    pub attendees: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Unfold RFC 5545 folded lines (`CRLF` or `LF` followed by a single space or horizontal tab).
pub fn unfold_ics_lines(input: &str) -> Vec<String> {
    let normalized = input.replace("\r\n", "\n");
    let mut unfolded: Vec<String> = Vec::new();

    for line in normalized.split('\n') {
        if let Some(cont) = line.strip_prefix(' ').or_else(|| line.strip_prefix('\t')) {
            if let Some(prev) = unfolded.last_mut() {
                prev.push_str(cont);
            } else {
                unfolded.push(cont.to_string());
            }
        } else {
            unfolded.push(line.to_string());
        }
    }

    unfolded
}

/// Parse all `VEVENT` blocks from an RFC 5545 `.ics` payload.
pub fn parse_ics_events(ics: &str) -> Vec<CalendarEvent> {
    let lines = unfold_ics_lines(ics);
    let mut events = Vec::new();
    let mut current: Option<CalendarEvent> = None;
    let mut nested_component_depth: usize = 0;

    for raw_line in lines {
        let line = raw_line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }

        let Some(IcsProperty {
            name,
            params,
            value,
        }) = parse_ics_property_line(line)
        else {
            continue;
        };

        if name == "BEGIN" {
            let comp = value.trim().to_ascii_uppercase();
            if comp == "VEVENT" {
                current = Some(CalendarEvent::default());
                nested_component_depth = 0;
            } else if current.is_some() {
                nested_component_depth += 1;
            }
            continue;
        }

        if name == "END" {
            let comp = value.trim().to_ascii_uppercase();
            if comp == "VEVENT" && nested_component_depth == 0 {
                if let Some(ev) = current.take() {
                    events.push(ev);
                }
            } else if current.is_some() && nested_component_depth > 0 {
                nested_component_depth -= 1;
            }
            continue;
        }

        // Ignore properties belonging to nested components (e.g. VALARM inside VEVENT).
        if nested_component_depth > 0 {
            continue;
        }

        let Some(ev) = current.as_mut() else {
            continue;
        };

        match name.as_str() {
            "UID" => ev.uid = Some(unescape_ics_text(value.trim())),
            "SUMMARY" => ev.summary = Some(unescape_ics_text(value.trim())),
            "DTSTART" => ev.dtstart = Some(format_ics_datetime(&params, value.trim())),
            "DTEND" => ev.dtend = Some(format_ics_datetime(&params, value.trim())),
            "LOCATION" => ev.location = Some(unescape_ics_text(value.trim())),
            "STATUS" => ev.status = Some(unescape_ics_text(value.trim())),
            "DESCRIPTION" => ev.description = Some(unescape_ics_text(value)),
            "ORGANIZER" => ev.organizer = Some(format_ics_participant(&params, value.trim())),
            "ATTENDEE" => ev
                .attendees
                .push(format_ics_participant(&params, value.trim())),
            _ => {}
        }
    }

    events
}

struct IcsProperty<'a> {
    name: String,
    params: Vec<(String, String)>,
    value: &'a str,
}

fn parse_ics_property_line(line: &str) -> Option<IcsProperty<'_>> {
    // Find first ':' outside double quotes.
    let mut in_quotes = false;
    let mut colon_idx = None;
    for (idx, ch) in line.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ':' if !in_quotes => {
                colon_idx = Some(idx);
                break;
            }
            _ => {}
        }
    }
    let colon = colon_idx?;
    let left = &line[..colon];
    let value = &line[colon + 1..];

    // Split left part on ';' outside double quotes.
    let mut segments = Vec::new();
    let mut seg_start = 0;
    in_quotes = false;
    for (idx, ch) in left.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ';' if !in_quotes => {
                segments.push(&left[seg_start..idx]);
                seg_start = idx + 1;
            }
            _ => {}
        }
    }
    segments.push(&left[seg_start..]);

    let prop_name = segments.first()?.trim().to_ascii_uppercase();
    if prop_name.is_empty() {
        return None;
    }

    let mut params = Vec::new();
    for seg in segments.iter().skip(1) {
        if let Some((k, v)) = seg.split_once('=') {
            let key = k.trim().to_ascii_uppercase();
            let val = v.trim().trim_matches('"').to_string();
            params.push((key, val));
        }
    }

    Some(IcsProperty {
        name: prop_name,
        params,
        value,
    })
}

fn find_param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}

fn format_ics_datetime(params: &[(String, String)], raw_val: &str) -> String {
    if let Some(tzid) = find_param(params, "TZID")
        && !tzid.is_empty()
        && !raw_val.ends_with('Z')
    {
        format!("{raw_val} ({tzid})")
    } else {
        raw_val.to_string()
    }
}

fn format_ics_participant(params: &[(String, String)], raw_val: &str) -> String {
    let addr = raw_val
        .strip_prefix("mailto:")
        .or_else(|| raw_val.strip_prefix("MAILTO:"))
        .unwrap_or(raw_val)
        .trim();
    let cn = find_param(params, "CN")
        .map(unescape_ics_text)
        .filter(|s| !s.trim().is_empty());

    match cn {
        Some(name) if !addr.is_empty() && !name.eq_ignore_ascii_case(addr) => {
            format!("{name} <{addr}>")
        }
        Some(name) => name,
        None => addr.to_string(),
    }
}

fn unescape_ics_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n' | 'N') => out.push('\n'),
                Some('\\') => out.push('\\'),
                Some(',') => out.push(','),
                Some(';') => out.push(';'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn sanitize_calendar_event(ev: &mut CalendarEvent) {
    ev.uid = ev.uid.as_deref().map(sanitize_untrusted_text);
    ev.summary = ev.summary.as_deref().map(sanitize_untrusted_text);
    ev.dtstart = ev.dtstart.as_deref().map(sanitize_untrusted_text);
    ev.dtend = ev.dtend.as_deref().map(sanitize_untrusted_text);
    ev.location = ev.location.as_deref().map(sanitize_untrusted_text);
    ev.organizer = ev.organizer.as_deref().map(sanitize_untrusted_text);
    ev.attendees = ev
        .attendees
        .iter()
        .map(|a| sanitize_untrusted_text(a))
        .collect();
    ev.status = ev.status.as_deref().map(sanitize_untrusted_text);
    ev.description = ev.description.as_deref().map(sanitize_untrusted_text);
}

fn format_events_summary(events: &[CalendarEvent]) -> String {
    let mut blocks = Vec::with_capacity(events.len());
    for ev in events {
        let mut lines = Vec::new();
        if let Some(ref summary) = ev.summary {
            lines.push(format!("Event: {summary}"));
        }
        if let Some(ref start) = ev.dtstart {
            lines.push(format!("Start: {start}"));
        }
        if let Some(ref end) = ev.dtend {
            lines.push(format!("End: {end}"));
        }
        if let Some(ref location) = ev.location {
            lines.push(format!("Location: {location}"));
        }
        if let Some(ref organizer) = ev.organizer {
            lines.push(format!("Organizer: {organizer}"));
        }
        if !ev.attendees.is_empty() {
            lines.push(format!("Attendees: {}", ev.attendees.join(", ")));
        }
        if let Some(ref status) = ev.status {
            lines.push(format!("Status: {status}"));
        }
        if let Some(ref uid) = ev.uid {
            lines.push(format!("UID: {uid}"));
        }
        if let Some(ref desc) = ev.description
            && !desc.trim().is_empty()
        {
            lines.push(format!("Description:\n{}", desc.trim()));
        }
        blocks.push(lines.join("\n"));
    }
    blocks.join("\n\n---\n\n")
}

fn extract_ics_attachment(
    data: &[u8],
    content_type: String,
    filename: Option<String>,
    size_bytes: u64,
    max_chars: usize,
    sanitize: bool,
) -> AttachmentTextExtraction {
    let raw = decode_utf8_text(data);
    let mut events = parse_ics_events(&raw);

    if events.is_empty() {
        let cleaned = maybe_sanitize(&raw, sanitize);
        return build_text_result(
            filename,
            content_type,
            size_bytes,
            "calendar",
            cleaned,
            max_chars,
            Some(json!({ "events": [] })),
        );
    }

    if sanitize {
        for ev in &mut events {
            sanitize_calendar_event(ev);
        }
    }

    let summary_text = format_events_summary(&events);
    let first = &events[0];
    let structured = json!({
        "events": events,
        "uid": first.uid,
        "summary": first.summary,
        "dtstart": first.dtstart,
        "dtend": first.dtend,
        "location": first.location,
        "organizer": first.organizer,
        "attendees": first.attendees,
        "status": first.status,
        "description": first.description,
    });

    build_text_result(
        filename,
        content_type,
        size_bytes,
        "calendar",
        summary_text,
        max_chars,
        Some(structured),
    )
}

// ============================================================================
// Pure-Rust PDF Text Stream Extractor
// ============================================================================

fn extract_pdf_attachment(
    data: &[u8],
    content_type: String,
    filename: Option<String>,
    size_bytes: u64,
    max_chars: usize,
    sanitize: bool,
) -> AttachmentTextExtraction {
    let extracted = extract_pdf_text_streams(data);
    let cleaned = maybe_sanitize(&extracted, sanitize);
    let trimmed = cleaned.trim().to_string();

    if trimmed.is_empty() {
        return AttachmentTextExtraction {
            attachment_id: None,
            message_id: None,
            filename,
            content_type,
            size_bytes,
            extracted: false,
            format: Some("pdf".to_string()),
            text: None,
            truncated: false,
            total_chars: 0,
            structured: None,
            reason: Some("binary or scanned PDF without text stream".to_string()),
            meta: None,
        };
    }

    build_text_result(
        filename,
        content_type,
        size_bytes,
        "pdf",
        trimmed,
        max_chars,
        None,
    )
}

/// Extract readable text from PDF `BT ... ET` content streams (both uncompressed and
/// `/FlateDecode` zlib-compressed streams).
pub fn extract_pdf_text_streams(data: &[u8]) -> String {
    if data.is_empty() || !find_bytes(data, b"%PDF-").is_some_and(|pos| pos < 1024) {
        return String::new();
    }

    let mut chunks: Vec<String> = Vec::new();
    let mut total_decompressed = 0usize;
    let mut cursor = 0usize;
    let mut found_stream = false;

    while let Some(rel_start) = find_bytes(&data[cursor..], b"stream") {
        let kw_pos = cursor + rel_start;
        let after_kw = kw_pos + b"stream".len();

        // Must be preceded by delimiter/whitespace and followed by \r\n or \n.
        let prev_ok =
            kw_pos == 0 || matches!(data[kw_pos - 1], b' ' | b'\t' | b'\r' | b'\n' | b'>' | b']');
        let stream_start = if after_kw + 1 < data.len()
            && data[after_kw] == b'\r'
            && data[after_kw + 1] == b'\n'
        {
            Some(after_kw + 2)
        } else if after_kw < data.len() && data[after_kw] == b'\n' {
            Some(after_kw + 1)
        } else {
            None
        };

        if !prev_ok {
            cursor = after_kw;
            continue;
        }
        let Some(content_start) = stream_start else {
            cursor = after_kw;
            continue;
        };

        let Some(rel_end) = find_bytes(&data[content_start..], b"endstream") else {
            break;
        };
        found_stream = true;
        let mut content_end = content_start + rel_end;
        if content_end > content_start && data[content_end - 1] == b'\n' {
            content_end -= 1;
            if content_end > content_start && data[content_end - 1] == b'\r' {
                content_end -= 1;
            }
        }

        let dict_window_start = kw_pos.saturating_sub(1024);
        let dict_bytes = &data[dict_window_start..kw_pos];
        let is_image = find_bytes(dict_bytes, b"/Image").is_some()
            && find_bytes(dict_bytes, b"/Subtype").is_some();

        if !is_image {
            let stream_bytes = &data[content_start..content_end];
            let is_flate = find_bytes(dict_bytes, b"/FlateDecode").is_some();

            if is_flate {
                if total_decompressed < MAX_PDF_TOTAL_DECOMPRESSED_BYTES {
                    let remaining_budget = MAX_PDF_TOTAL_DECOMPRESSED_BYTES - total_decompressed;
                    let limit = remaining_budget.min(MAX_PDF_STREAM_DECOMPRESSED_BYTES);
                    if let Some(inflated) = inflate_zlib_bounded(stream_bytes, limit) {
                        total_decompressed += inflated.len();
                        let text = parse_pdf_content_stream_text(&inflated);
                        if !text.trim().is_empty() {
                            chunks.push(text);
                        }
                    }
                }
            } else if total_decompressed < MAX_PDF_TOTAL_DECOMPRESSED_BYTES {
                let remaining_budget = MAX_PDF_TOTAL_DECOMPRESSED_BYTES - total_decompressed;
                let limit = remaining_budget.min(MAX_PDF_STREAM_DECOMPRESSED_BYTES);
                let bounded_stream = &stream_bytes[..stream_bytes.len().min(limit)];
                total_decompressed += bounded_stream.len();
                let text = parse_pdf_content_stream_text(bounded_stream);
                if !text.trim().is_empty() {
                    chunks.push(text);
                }
            }
        }

        cursor = content_start + rel_end + b"endstream".len();
    }

    // Fallback for minimal synthetic PDFs that put `BT ... ET` directly without `stream`/`endstream`.
    if !found_stream {
        let bounded_data = &data[..data.len().min(MAX_PDF_STREAM_DECOMPRESSED_BYTES)];
        let direct = parse_pdf_content_stream_text(bounded_data);
        if !direct.trim().is_empty() {
            chunks.push(direct);
        }
    }

    normalize_pdf_text(&chunks.join("\n"))
}

fn inflate_zlib_bounded(input: &[u8], max_out: usize) -> Option<Vec<u8>> {
    let decoder = ZlibDecoder::new(input);
    let mut bounded = decoder.take(max_out as u64);
    let mut out = Vec::new();
    match bounded.read_to_end(&mut out) {
        Ok(_) if !out.is_empty() => Some(out),
        _ => None,
    }
}

#[derive(Debug, Clone)]
enum PdfToken {
    Str(String),
    Number(f64),
    Array(Vec<PdfToken>),
    Word(String),
}

fn parse_pdf_content_stream_text(stream: &[u8]) -> String {
    let tokens = tokenize_pdf_stream(stream);
    let mut out = String::new();
    let mut in_text_object = false;
    let mut operands: Vec<PdfToken> = Vec::new();

    for tok in tokens {
        match tok {
            PdfToken::Word(op) => {
                match op.as_str() {
                    "BT" => {
                        in_text_object = true;
                        if !out.is_empty() && !out.ends_with('\n') {
                            out.push('\n');
                        }
                    }
                    "ET" => {
                        in_text_object = false;
                        if !out.is_empty() && !out.ends_with('\n') {
                            out.push('\n');
                        }
                    }
                    "Tj" if in_text_object => {
                        if let Some(PdfToken::Str(s)) = operands.last() {
                            out.push_str(s);
                        }
                    }
                    "'" | "\"" if in_text_object => {
                        if !out.is_empty() && !out.ends_with('\n') {
                            out.push('\n');
                        }
                        if let Some(PdfToken::Str(s)) = operands.last() {
                            out.push_str(s);
                        }
                    }
                    "TJ" if in_text_object => {
                        if let Some(PdfToken::Array(items)) = operands.last() {
                            for item in items {
                                match item {
                                    PdfToken::Str(s) => out.push_str(s),
                                    PdfToken::Number(n)
                                        if *n <= -100.0 && !out.ends_with([' ', '\n', '\t']) =>
                                    {
                                        out.push(' ');
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    "T*" if in_text_object => {
                        if !out.is_empty() && !out.ends_with('\n') {
                            out.push('\n');
                        }
                    }
                    "Td" | "TD" if in_text_object => {
                        if let Some(PdfToken::Number(ty)) = operands.last() {
                            if ty.abs() > 1.0 && !out.is_empty() && !out.ends_with('\n') {
                                out.push('\n');
                            } else if !out.is_empty() && !out.ends_with([' ', '\n']) {
                                out.push(' ');
                            }
                        }
                    }
                    "Tm" if in_text_object && !out.is_empty() && !out.ends_with('\n') => {
                        out.push('\n');
                    }
                    _ => {}
                }
                operands.clear();
            }
            other => {
                if in_text_object {
                    if operands.len() >= 16 {
                        operands.remove(0);
                    }
                    operands.push(other);
                }
            }
        }
    }

    out
}

fn tokenize_pdf_stream(bytes: &[u8]) -> Vec<PdfToken> {
    let mut tokens = Vec::new();
    let mut token_budget = MAX_PDF_TOKENS;
    let mut i = 0;
    let len = bytes.len();

    while i < len && token_budget > 0 {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // PDF comment: % ... \n
        if b == b'%' {
            while i < len && bytes[i] != b'\n' && bytes[i] != b'\r' {
                i += 1;
            }
            continue;
        }
        // Literal string (...)
        if b == b'(' {
            let (s, next) = parse_pdf_literal_string(bytes, i);
            tokens.push(PdfToken::Str(s));
            token_budget -= 1;
            i = next.max(i + 1);
            continue;
        }
        // Dictionary << ... >> or hex string <...>
        if b == b'<' {
            if i + 1 < len && bytes[i + 1] == b'<' {
                i += 2;
                continue;
            }
            let (s, next) = parse_pdf_hex_string(bytes, i);
            tokens.push(PdfToken::Str(s));
            token_budget -= 1;
            i = next.max(i + 1);
            continue;
        }
        if b == b'>' {
            i += 1;
            continue;
        }
        // Array [...]
        if b == b'[' {
            token_budget -= 1;
            let (arr, next) = parse_pdf_array(bytes, i, &mut token_budget);
            tokens.push(PdfToken::Array(arr));
            i = next.max(i + 1);
            continue;
        }
        if matches!(b, b']' | b')' | b'{' | b'}') {
            i += 1;
            continue;
        }
        // PDF name /Font
        if b == b'/' {
            i += 1;
            while i < len && !is_pdf_delimiter(bytes[i]) && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            continue;
        }
        // Quote operators `'` and `"`
        if b == b'\'' || b == b'"' {
            tokens.push(PdfToken::Word((b as char).to_string()));
            token_budget -= 1;
            i += 1;
            continue;
        }

        // Number or operator word
        let start = i;
        while i < len && !is_pdf_delimiter(bytes[i]) && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i == start {
            i += 1;
            continue;
        }
        let word = String::from_utf8_lossy(&bytes[start..i]).into_owned();
        if let Ok(num) = word.parse::<f64>() {
            tokens.push(PdfToken::Number(num));
        } else {
            tokens.push(PdfToken::Word(word));
        }
        token_budget -= 1;
    }

    tokens
}

fn is_pdf_delimiter(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

fn parse_pdf_array(bytes: &[u8], start: usize, token_budget: &mut usize) -> (Vec<PdfToken>, usize) {
    let mut items = Vec::new();
    let mut i = start + 1;
    let len = bytes.len();

    while i < len && *token_budget > 0 {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b == b']' {
            return (items, i + 1);
        }
        if b == b'(' {
            let (s, next) = parse_pdf_literal_string(bytes, i);
            items.push(PdfToken::Str(s));
            *token_budget -= 1;
            i = next.max(i + 1);
        } else if b == b'<' && (i + 1 >= len || bytes[i + 1] != b'<') {
            let (s, next) = parse_pdf_hex_string(bytes, i);
            items.push(PdfToken::Str(s));
            *token_budget -= 1;
            i = next.max(i + 1);
        } else {
            let tok_start = i;
            while i < len && !is_pdf_delimiter(bytes[i]) && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i == tok_start {
                i += 1;
                continue;
            }
            if let Ok(num) = std::str::from_utf8(&bytes[tok_start..i])
                .unwrap_or("")
                .parse::<f64>()
            {
                items.push(PdfToken::Number(num));
                *token_budget -= 1;
            }
        }
    }

    (items, i)
}

fn parse_pdf_literal_string(bytes: &[u8], start: usize) -> (String, usize) {
    let mut raw = Vec::new();
    let mut i = start + 1;
    let len = bytes.len();
    let mut depth = 1usize;

    while i < len && depth > 0 {
        let b = bytes[i];
        if b == b'\\' && i + 1 < len {
            i += 1;
            match bytes[i] {
                b'n' => raw.push(b'\n'),
                b'r' => raw.push(b'\r'),
                b't' => raw.push(b'\t'),
                b'b' => raw.push(0x08),
                b'f' => raw.push(0x0C),
                b'(' => raw.push(b'('),
                b')' => raw.push(b')'),
                b'\\' => raw.push(b'\\'),
                b'\r' => {
                    if i + 1 < len && bytes[i + 1] == b'\n' {
                        i += 1;
                    }
                }
                b'\n' => {}
                d @ b'0'..=b'7' => {
                    let mut val = (d - b'0') as u32;
                    for _ in 0..2 {
                        if i + 1 < len && (b'0'..=b'7').contains(&bytes[i + 1]) {
                            i += 1;
                            val = val * 8 + (bytes[i] - b'0') as u32;
                        } else {
                            break;
                        }
                    }
                    raw.push((val & 0xFF) as u8);
                }
                other => raw.push(other),
            }
            i += 1;
        } else if b == b'(' {
            depth += 1;
            raw.push(b);
            i += 1;
        } else if b == b')' {
            depth -= 1;
            if depth > 0 {
                raw.push(b);
            }
            i += 1;
        } else {
            raw.push(b);
            i += 1;
        }
    }

    (decode_pdf_bytes(&raw), i)
}

fn parse_pdf_hex_string(bytes: &[u8], start: usize) -> (String, usize) {
    let mut hex_digits = Vec::new();
    let mut i = start + 1;
    let len = bytes.len();

    while i < len && bytes[i] != b'>' {
        let b = bytes[i];
        if b.is_ascii_hexdigit() {
            hex_digits.push(b);
        }
        i += 1;
    }
    if i < len && bytes[i] == b'>' {
        i += 1;
    }

    if hex_digits.len() % 2 == 1 {
        hex_digits.push(b'0');
    }

    let mut decoded = Vec::with_capacity(hex_digits.len() / 2);
    for pair in hex_digits.as_chunks::<2>().0 {
        if let Ok(s) = std::str::from_utf8(pair)
            && let Ok(byte) = u8::from_str_radix(s, 16)
        {
            decoded.push(byte);
        }
    }

    (decode_pdf_bytes(&decoded), i)
}

fn decode_pdf_bytes(raw: &[u8]) -> String {
    // UTF-16BE with BOM (FE FF)
    if raw.len() >= 2 && raw[0] == 0xFE && raw[1] == 0xFF {
        let units: Vec<u16> = raw[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }

    if let Ok(utf8) = std::str::from_utf8(raw) {
        return utf8.to_string();
    }

    // Fallback to ISO-8859-1 / WinAnsi printable mapping
    raw.iter().map(|&b| b as char).collect()
}

fn normalize_pdf_text(raw: &str) -> String {
    let mut lines = Vec::new();
    let mut blank_run = 0usize;
    for line in raw.replace("\r\n", "\n").lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if !lines.is_empty() && blank_run == 0 {
                lines.push(String::new());
            }
            blank_run += 1;
        } else {
            blank_run = 0;
            lines.push(trimmed.to_string());
        }
    }
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    lines.join("\n")
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;

    #[test]
    fn extracts_txt_csv_json_and_enforces_max_chars_and_sanitization() {
        let csv = b"sku,qty,price\nWIDGET-1,2,19.99\nCABLE-2,1,5.00\n";
        let res = extract_attachment_text(
            csv,
            "text/csv; charset=utf-8",
            Some("order.csv"),
            Some(25),
            DEFAULT_ATTACHMENT_MAX_BYTES,
            true,
        );
        assert!(res.extracted);
        assert_eq!(res.format.as_deref(), Some("csv"));
        assert!(res.truncated);
        assert_eq!(res.text.as_deref().unwrap().chars().count(), 25);
        assert_eq!(res.total_chars, csv.len());

        let dirty_txt = "Hello\x00\u{202E}world\nLine 2".as_bytes();
        let clean_res = extract_attachment_text(
            dirty_txt,
            "application/octet-stream",
            Some("notes.txt"),
            None,
            DEFAULT_ATTACHMENT_MAX_BYTES,
            true,
        );
        assert!(clean_res.extracted);
        assert_eq!(clean_res.format.as_deref(), Some("text"));
        assert_eq!(clean_res.text.as_deref(), Some("Helloworld\nLine 2"));
        assert!(!clean_res.truncated);
    }

    #[test]
    fn extracts_ics_with_folded_lines_organizer_attendees_and_valarm_isolation() {
        let ics = concat!(
            "BEGIN:VCALENDAR\r\n",
            "VERSION:2.0\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:evt-2026-01@example.com\r\n",
            "SUMMARY:Q4 Roadmap Revi\r\n",
            " ew & Planning\r\n",
            "DTSTART;TZID=America/New_York:20261126T100000\r\n",
            "DTEND;TZID=America/New_York:20261126T110000\r\n",
            "LOCATION:HQ Room 4B\\, Floor 2\r\n",
            "ORGANIZER;CN=\"Alice Smith\":mailto:alice@example.com\r\n",
            "ATTENDEE;CN=Bob Jones;PARTSTAT=ACCEPTED:mailto:bob@example.com\r\n",
            "ATTENDEE:mailto:carol@example.com\r\n",
            "STATUS:CONFIRMED\r\n",
            "DESCRIPTION:Bring Q4 metrics.\\nSee agenda\r\n",
            "\t link inside.\r\n",
            "BEGIN:VALARM\r\n",
            "ACTION:DISPLAY\r\n",
            "DESCRIPTION:Alarm reminder should not overwrite event description\r\n",
            "END:VALARM\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n"
        );

        let res = extract_attachment_text(
            ics.as_bytes(),
            "text/calendar",
            Some("invite.ics"),
            None,
            DEFAULT_ATTACHMENT_MAX_BYTES,
            true,
        );
        assert!(res.extracted);
        assert_eq!(res.format.as_deref(), Some("calendar"));

        let structured = res.structured.expect("structured calendar payload");
        assert_eq!(structured["uid"], "evt-2026-01@example.com");
        assert_eq!(structured["summary"], "Q4 Roadmap Review & Planning");
        assert_eq!(structured["dtstart"], "20261126T100000 (America/New_York)");
        assert_eq!(structured["dtend"], "20261126T110000 (America/New_York)");
        assert_eq!(structured["location"], "HQ Room 4B, Floor 2");
        assert_eq!(structured["organizer"], "Alice Smith <alice@example.com>");
        assert_eq!(
            structured["attendees"],
            json!(["Bob Jones <bob@example.com>", "carol@example.com"])
        );
        assert_eq!(structured["status"], "CONFIRMED");
        assert_eq!(
            structured["description"],
            "Bring Q4 metrics.\nSee agenda link inside."
        );

        let text = res.text.expect("readable summary");
        assert!(text.contains("Event: Q4 Roadmap Review & Planning"));
        assert!(text.contains("Organizer: Alice Smith <alice@example.com>"));
        assert!(text.contains("Attendees: Bob Jones <bob@example.com>, carol@example.com"));
        assert!(!text.contains("Alarm reminder"));
    }

    #[test]
    fn extracts_minimal_and_flate_pdf_and_handles_scanned_pdf_cleanly() {
        let minimal_pdf = b"%PDF-1.4\n1 0 obj << /Length 28 >>\nstream\nBT /F1 12 Tf (Hello PDF) Tj ET\nendstream\nendobj\n%%EOF";
        let res = extract_attachment_text(
            minimal_pdf,
            "application/pdf",
            Some("receipt.pdf"),
            None,
            DEFAULT_ATTACHMENT_MAX_BYTES,
            true,
        );
        assert!(res.extracted);
        assert_eq!(res.format.as_deref(), Some("pdf"));
        assert_eq!(res.text.as_deref(), Some("Hello PDF"));

        // FlateDecode compressed stream with TJ array
        let content = b"BT /F1 12 Tf [(Total) -180 (Due:) -180 ($42.00)] TJ ET";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(content).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut flate_pdf = Vec::new();
        flate_pdf.extend_from_slice(b"%PDF-1.4\n1 0 obj << /Filter /FlateDecode >>\nstream\n");
        flate_pdf.extend_from_slice(&compressed);
        flate_pdf.extend_from_slice(b"\nendstream\nendobj\n%%EOF");

        let flate_res = extract_attachment_text(
            &flate_pdf,
            "application/pdf",
            Some("invoice.pdf"),
            None,
            DEFAULT_ATTACHMENT_MAX_BYTES,
            true,
        );
        assert!(flate_res.extracted);
        assert_eq!(flate_res.text.as_deref(), Some("Total Due: $42.00"));

        // Image-only / scanned PDF returns extracted: false cleanly
        let scanned_pdf = b"%PDF-1.4\n1 0 obj << /Subtype /Image /Width 10 /Height 10 >>\nstream\n\xFF\xD8\xFF\xE0binary\nendstream\nendobj\n%%EOF";
        let scanned_res = extract_attachment_text(
            scanned_pdf,
            "application/pdf",
            Some("scan.pdf"),
            None,
            DEFAULT_ATTACHMENT_MAX_BYTES,
            true,
        );
        assert!(!scanned_res.extracted);
        assert_eq!(
            scanned_res.reason.as_deref(),
            Some("binary or scanned PDF without text stream")
        );
        assert!(scanned_res.text.is_none());
    }

    #[test]
    fn converts_html_attachment_to_markdown_and_rejects_unsupported_binary_and_oversize() {
        let html_att = b"<h2>Receipt</h2><p><a href=\"https://pay.example/1\">Download</a></p>";
        let html_res = extract_attachment_text(
            html_att,
            "text/html",
            Some("receipt.html"),
            None,
            DEFAULT_ATTACHMENT_MAX_BYTES,
            true,
        );
        assert!(html_res.extracted);
        assert_eq!(html_res.format.as_deref(), Some("markdown"));
        assert!(html_res.text.as_deref().unwrap().contains("## Receipt"));
        assert!(
            html_res
                .text
                .as_deref()
                .unwrap()
                .contains("[Download](https://pay.example/1)")
        );

        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let bin_res = extract_attachment_text(
            &png,
            "image/png",
            Some("logo.png"),
            None,
            DEFAULT_ATTACHMENT_MAX_BYTES,
            true,
        );
        assert!(!bin_res.extracted);
        assert_eq!(bin_res.content_type, "image/png");
        assert_eq!(
            bin_res.reason.as_deref(),
            Some("unsupported binary attachment type")
        );

        // Exceeds max_bytes ceiling
        let big = vec![b'a'; 64];
        let over_res = extract_attachment_text(&big, "text/plain", Some("big.txt"), None, 32, true);
        assert!(!over_res.extracted);
        assert!(
            over_res
                .reason
                .as_deref()
                .unwrap()
                .contains("exceeds maximum")
        );
    }

    #[test]
    fn pdf_tokenizer_handles_stray_delimiters_and_caps_tokens_without_hanging() {
        // Stray `{`, `}`, and `)` previously caused an infinite loop + OOM in tokenize_pdf_stream.
        for payload in [
            b"%PDF-1.4\n{" as &[u8],
            b"%PDF-1.4\n}",
            b"%PDF-1.4\n)",
            b"%PDF-1.4\n{{{}}}))) BT (Hello after braces) Tj ET",
        ] {
            let text = extract_pdf_text_streams(payload);
            if payload.ends_with(b"ET") {
                assert_eq!(text, "Hello after braces");
            }
        }

        // Token count cap: more than MAX_PDF_TOKENS tokens must terminate cleanly and stay bounded.
        let mut huge_stream = Vec::with_capacity((MAX_PDF_TOKENS + 5_000) * 2);
        for _ in 0..(MAX_PDF_TOKENS + 5_000) {
            huge_stream.extend_from_slice(b"a ");
        }
        let tokens = tokenize_pdf_stream(&huge_stream);
        assert_eq!(tokens.len(), MAX_PDF_TOKENS);

        // Array elements also count against MAX_PDF_TOKENS.
        let mut huge_array = Vec::with_capacity((MAX_PDF_TOKENS + 1_000) * 3);
        huge_array.push(b'[');
        for _ in 0..(MAX_PDF_TOKENS + 1_000) {
            huge_array.extend_from_slice(b"1 ");
        }
        huge_array.push(b']');
        let array_tokens = tokenize_pdf_stream(&huge_array);
        assert_eq!(array_tokens.len(), 1);
        match &array_tokens[0] {
            PdfToken::Array(items) => assert!(items.len() <= MAX_PDF_TOKENS),
            other => panic!("expected PdfToken::Array, got {other:?}"),
        }
    }
}
