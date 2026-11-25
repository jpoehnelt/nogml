//! RFC 2046 multipart boundary parser and Gmail upload extractors
//! supporting JSON, `uploadType=media`, and `uploadType=multipart`.

use axum::{
    body::Bytes,
    http::{HeaderMap, header},
};

use crate::{
    error::{AppError, AppResult},
    gmail::query::QueryParams,
    mime,
    models::{Draft, Message},
};

/// One decoded part of a MIME `multipart/*` request body.
#[derive(Debug, Clone)]
pub struct MultipartPart {
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl MultipartPart {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Extract the `boundary` parameter from a `Content-Type: multipart/...; boundary=...` header.
pub fn extract_multipart_boundary(content_type: &str) -> AppResult<String> {
    let mut segments = content_type.split(';');
    let media_type = segments.next().unwrap_or_default().trim();
    if !media_type.to_ascii_lowercase().starts_with("multipart/") {
        return Err(AppError::BadRequest(format!(
            "Expected multipart/* Content-Type, got '{content_type}'"
        )));
    }

    for param in segments {
        let param = param.trim();
        if let Some((k, v)) = param.split_once('=')
            && k.trim().eq_ignore_ascii_case("boundary")
        {
            let mut val = v.trim();
            if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
                val = &val[1..val.len() - 1];
            }
            if !val.is_empty() {
                return Ok(val.to_string());
            }
        }
    }

    Err(AppError::BadRequest(
        "Missing boundary parameter in multipart Content-Type header".to_string(),
    ))
}

/// Parse an RFC 2046 multipart body into its constituent parts, preserving raw bytes cleanly.
pub fn parse_multipart_parts(content_type: &str, body: &[u8]) -> AppResult<Vec<MultipartPart>> {
    let boundary = extract_multipart_boundary(content_type)?;
    let delimiter = format!("--{boundary}").into_bytes();

    let mut positions = Vec::new();
    let mut search_from = 0;
    while search_from < body.len() {
        let Some(rel) = find_subslice(&body[search_from..], &delimiter) else {
            break;
        };
        let pos = search_from + rel;
        // Boundary must appear at start of body or immediately after `\n`.
        let at_line_start = pos == 0 || body[pos - 1] == b'\n';
        let after = pos + delimiter.len();
        let valid_after = after == body.len()
            || body[after] == b'\r'
            || body[after] == b'\n'
            || (after + 1 < body.len() && &body[after..after + 2] == b"--");

        if at_line_start && valid_after {
            positions.push(pos);
        }
        search_from = pos + delimiter.len();
    }

    if positions.len() < 2 {
        return Err(AppError::BadRequest(
            "Malformed multipart body: missing boundary delimiters".to_string(),
        ));
    }

    let mut parts = Vec::new();
    for window in positions.windows(2) {
        let start_delim = window[0];
        let next_delim = window[1];

        let mut cursor = start_delim + delimiter.len();
        // Check if this delimiter is actually the closing `--boundary--`.
        if cursor + 2 <= body.len() && &body[cursor..cursor + 2] == b"--" {
            break;
        }
        // Skip optional trailing horizontal whitespace and CRLF / LF after boundary line.
        while cursor < next_delim && (body[cursor] == b' ' || body[cursor] == b'\t') {
            cursor += 1;
        }
        if cursor + 1 < next_delim && body[cursor] == b'\r' && body[cursor + 1] == b'\n' {
            cursor += 2;
        } else if cursor < next_delim && body[cursor] == b'\n' {
            cursor += 1;
        }

        // Trim the single CRLF or LF that precedes the next `--boundary`.
        let mut end = next_delim;
        if end >= cursor + 2 && body[end - 2] == b'\r' && body[end - 1] == b'\n' {
            end -= 2;
        } else if end > cursor && body[end - 1] == b'\n' {
            end -= 1;
        }

        if cursor > end {
            continue;
        }

        let raw_part = &body[cursor..end];
        let (headers, part_body) = split_headers_and_body(raw_part);
        parts.push(MultipartPart {
            headers,
            body: part_body.to_vec(),
        });
    }

    Ok(parts)
}

/// Split raw MIME/HTTP bytes into parsed `(header_name, header_value)` pairs and body slice.
pub fn split_headers_and_body(raw: &[u8]) -> (Vec<(String, String)>, &[u8]) {
    let sep = if let Some(idx) = find_subslice(raw, b"\r\n\r\n") {
        Some((idx, 4))
    } else if let Some(idx) = find_subslice(raw, b"\n\n") {
        Some((idx, 2))
    } else if raw.starts_with(b"\r\n") {
        return (Vec::new(), &raw[2..]);
    } else if raw.starts_with(b"\n") {
        return (Vec::new(), &raw[1..]);
    } else {
        None
    };

    let Some((header_end, sep_len)) = sep else {
        // No blank line: treat entire slice as body if first line doesn't look like a header.
        return (Vec::new(), raw);
    };

    let header_bytes = &raw[..header_end];
    let body = &raw[header_end + sep_len..];
    let header_text = String::from_utf8_lossy(header_bytes);
    let mut headers = Vec::new();
    for line in header_text.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if let Some((name, val)) = line.split_once(':') {
            headers.push((name.trim().to_string(), val.trim().to_string()));
        }
    }

    (headers, body)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Extracted metadata + optional raw RFC 2822 bytes for message upload endpoints.
pub struct ExtractedMessageUpload {
    pub metadata: Message,
    pub raw_bytes: Option<Vec<u8>>,
}

/// Extracted metadata + optional raw RFC 2822 bytes for draft upload endpoints.
pub struct ExtractedDraftUpload {
    pub metadata: Draft,
    pub raw_bytes: Option<Vec<u8>>,
}

fn content_type_str(headers: &HeaderMap) -> &str {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// Parse a `messages.send`, `messages.insert`, or `messages.import` request body supporting:
/// - Standard JSON (`Message` with base64url `raw`)
/// - `uploadType=media` (or `Content-Type: message/rfc822`)
/// - `uploadType=multipart` (or `Content-Type: multipart/related|multipart/mixed`)
pub fn extract_message_upload(
    headers: &HeaderMap,
    query: &QueryParams,
    body: &Bytes,
) -> AppResult<ExtractedMessageUpload> {
    let ct = content_type_str(headers);
    let ct_lower = ct.to_ascii_lowercase();
    let upload_type = query.get("uploadType").map(|s| s.to_ascii_lowercase());

    match upload_type.as_deref() {
        Some("media") => {
            let raw_bytes = (!body.is_empty()).then(|| body.to_vec());
            return Ok(ExtractedMessageUpload {
                metadata: Message::default(),
                raw_bytes,
            });
        }
        Some("multipart") => {
            return extract_multipart_message(ct, body);
        }
        Some("resumable") => {
            return Err(AppError::BadRequest(
                "uploadType=resumable is not supported; use JSON, uploadType=media, or uploadType=multipart"
                    .to_string(),
            ));
        }
        Some(other) => {
            return Err(AppError::BadRequest(format!(
                "Unsupported uploadType '{other}'"
            )));
        }
        None => {}
    }

    if ct_lower.starts_with("multipart/") {
        return extract_multipart_message(ct, body);
    }

    if ct_lower.starts_with("message/rfc822") {
        let raw_bytes = (!body.is_empty()).then(|| body.to_vec());
        return Ok(ExtractedMessageUpload {
            metadata: Message::default(),
            raw_bytes,
        });
    }

    if body.is_empty() {
        return Ok(ExtractedMessageUpload {
            metadata: Message::default(),
            raw_bytes: None,
        });
    }

    let metadata: Message = serde_json::from_slice(body)?;
    let raw_bytes = match metadata.raw.as_deref() {
        Some(raw) if !raw.trim().is_empty() => Some(mime::decode_base64url(raw)?),
        _ => None,
    };

    Ok(ExtractedMessageUpload {
        metadata,
        raw_bytes,
    })
}

fn extract_multipart_message(content_type: &str, body: &[u8]) -> AppResult<ExtractedMessageUpload> {
    let parts = parse_multipart_parts(content_type, body)?;
    if parts.is_empty() {
        return Err(AppError::BadRequest(
            "Multipart upload contains no parts".to_string(),
        ));
    }

    let mut metadata = Message::default();
    let mut media_bytes: Option<Vec<u8>> = None;

    for (idx, part) in parts.iter().enumerate() {
        let part_ct = part
            .header("content-type")
            .unwrap_or("")
            .to_ascii_lowercase();
        if part_ct.starts_with("application/json") || (idx == 0 && part_ct.is_empty() && part.body.first() == Some(&b'{')) {
            if !part.body.is_empty() {
                metadata = serde_json::from_slice(&part.body)?;
            }
        } else if part_ct.starts_with("message/rfc822")
            || part_ct.starts_with("application/octet-stream")
            || media_bytes.is_none()
        {
            media_bytes = Some(part.body.clone());
        }
    }

    let raw_bytes = match media_bytes {
        Some(bytes) if !bytes.is_empty() => Some(bytes),
        _ => match metadata.raw.as_deref() {
            Some(raw) if !raw.trim().is_empty() => Some(mime::decode_base64url(raw)?),
            _ => None,
        },
    };

    Ok(ExtractedMessageUpload {
        metadata,
        raw_bytes,
    })
}

/// Parse a `drafts.create`, `drafts.update`, or `drafts.send` request body supporting:
/// - Standard JSON (`Draft` containing optional `id` and `message`)
/// - `uploadType=media` (raw RFC 2822 bytes)
/// - `uploadType=multipart` (JSON `Draft` metadata part + raw RFC 2822 media part)
pub fn extract_draft_upload(
    headers: &HeaderMap,
    query: &QueryParams,
    body: &Bytes,
) -> AppResult<ExtractedDraftUpload> {
    let ct = content_type_str(headers);
    let ct_lower = ct.to_ascii_lowercase();
    let upload_type = query.get("uploadType").map(|s| s.to_ascii_lowercase());

    match upload_type.as_deref() {
        Some("media") => {
            let raw_bytes = (!body.is_empty()).then(|| body.to_vec());
            return Ok(ExtractedDraftUpload {
                metadata: Draft::default(),
                raw_bytes,
            });
        }
        Some("multipart") => {
            return extract_multipart_draft(ct, body);
        }
        Some("resumable") => {
            return Err(AppError::BadRequest(
                "uploadType=resumable is not supported; use JSON, uploadType=media, or uploadType=multipart"
                    .to_string(),
            ));
        }
        Some(other) => {
            return Err(AppError::BadRequest(format!(
                "Unsupported uploadType '{other}'"
            )));
        }
        None => {}
    }

    if ct_lower.starts_with("multipart/") {
        return extract_multipart_draft(ct, body);
    }

    if ct_lower.starts_with("message/rfc822") {
        let raw_bytes = (!body.is_empty()).then(|| body.to_vec());
        return Ok(ExtractedDraftUpload {
            metadata: Draft::default(),
            raw_bytes,
        });
    }

    if body.is_empty() {
        return Ok(ExtractedDraftUpload {
            metadata: Draft::default(),
            raw_bytes: None,
        });
    }

    let metadata: Draft = serde_json::from_slice(body)?;
    let raw_bytes = match metadata
        .message
        .as_ref()
        .and_then(|m| m.raw.as_deref())
    {
        Some(raw) if !raw.trim().is_empty() => Some(mime::decode_base64url(raw)?),
        _ => None,
    };

    Ok(ExtractedDraftUpload {
        metadata,
        raw_bytes,
    })
}

fn extract_multipart_draft(content_type: &str, body: &[u8]) -> AppResult<ExtractedDraftUpload> {
    let parts = parse_multipart_parts(content_type, body)?;
    if parts.is_empty() {
        return Err(AppError::BadRequest(
            "Multipart draft upload contains no parts".to_string(),
        ));
    }

    let mut metadata = Draft::default();
    let mut media_bytes: Option<Vec<u8>> = None;

    for (idx, part) in parts.iter().enumerate() {
        let part_ct = part
            .header("content-type")
            .unwrap_or("")
            .to_ascii_lowercase();
        if part_ct.starts_with("application/json")
            || (idx == 0 && part_ct.is_empty() && part.body.first() == Some(&b'{'))
        {
            if !part.body.is_empty() {
                metadata = serde_json::from_slice(&part.body)?;
            }
        } else if part_ct.starts_with("message/rfc822")
            || part_ct.starts_with("application/octet-stream")
            || media_bytes.is_none()
        {
            media_bytes = Some(part.body.clone());
        }
    }

    let raw_bytes = match media_bytes {
        Some(bytes) if !bytes.is_empty() => Some(bytes),
        _ => match metadata.message.as_ref().and_then(|m| m.raw.as_deref()) {
            Some(raw) if !raw.trim().is_empty() => Some(mime::decode_base64url(raw)?),
            _ => None,
        },
    };

    Ok(ExtractedDraftUpload {
        metadata,
        raw_bytes,
    })
}
