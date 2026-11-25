//! RFC 2046 multipart boundary parser and Gmail upload extractors
//! supporting JSON, `uploadType=media`, `uploadType=multipart`, and `uploadType=resumable`.

use std::{
    collections::HashMap,
    sync::RwLock,
    time::{Duration, Instant},
};

use axum::{
    body::Bytes,
    http::{HeaderMap, HeaderValue, Uri, header},
};
use uuid::Uuid;

use crate::{
    error::{AppError, AppResult},
    gmail::query::QueryParams,
    mime,
    models::{Draft, Message},
};

/// Default lifetime for idle resumable upload sessions before automatic eviction.
pub const DEFAULT_RESUMABLE_UPLOAD_TTL: Duration = Duration::from_secs(3600);

/// Maximum number of concurrent in-flight resumable upload sessions held in memory.
const MAX_CONCURRENT_RESUMABLE_SESSIONS: usize = 1024;

/// Maximum initial buffer pre-allocation derived from `X-Upload-Content-Length`.
const MAX_INITIAL_BUFFER_PREALLOC: usize = 1024 * 1024;

/// Target endpoint discriminator used to ensure a resumable `upload_id` is only
/// resumed against the endpoint that initiated it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumableEndpoint {
    MessagesSend,
    MessagesInsert,
    MessagesImport,
    DraftsCreate,
    DraftsUpdate(String),
    DraftsSend,
}

/// Target Gmail operation and captured initiation query options for a resumable upload session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumableUploadTarget {
    MessagesSend,
    MessagesInsert {
        date_source: String,
        deleted: bool,
    },
    MessagesImport {
        date_source: String,
        never_mark_spam: bool,
        process_for_calendar: bool,
        deleted: bool,
    },
    DraftsCreate,
    DraftsUpdate {
        draft_id: String,
    },
    DraftsSend,
}

impl ResumableUploadTarget {
    pub fn endpoint(&self) -> ResumableEndpoint {
        match self {
            Self::MessagesSend => ResumableEndpoint::MessagesSend,
            Self::MessagesInsert { .. } => ResumableEndpoint::MessagesInsert,
            Self::MessagesImport { .. } => ResumableEndpoint::MessagesImport,
            Self::DraftsCreate => ResumableEndpoint::DraftsCreate,
            Self::DraftsUpdate { draft_id } => ResumableEndpoint::DraftsUpdate(draft_id.clone()),
            Self::DraftsSend => ResumableEndpoint::DraftsSend,
        }
    }
}

/// Optional JSON metadata supplied on resumable upload initiation.
#[derive(Debug, Clone)]
pub enum ResumableUploadMetadata {
    Message(Message),
    Draft(Draft),
}

/// In-memory state of an active `uploadType=resumable` session.
#[derive(Debug, Clone)]
pub struct ResumableUploadSession {
    pub id: String,
    pub user_email: String,
    pub target: ResumableUploadTarget,
    pub metadata: ResumableUploadMetadata,
    pub content_type: Option<String>,
    pub declared_total_bytes: Option<usize>,
    pub known_total_bytes: Option<usize>,
    pub idempotency_key: Option<String>,
    pub buffer: Vec<u8>,
    pub created_at: Instant,
    pub updated_at: Instant,
}

/// Parameters for creating a new resumable upload session.
#[derive(Debug, Clone)]
pub struct NewResumableUpload {
    pub user_email: String,
    pub target: ResumableUploadTarget,
    pub metadata: ResumableUploadMetadata,
    pub content_type: Option<String>,
    pub declared_total_bytes: Option<usize>,
    pub idempotency_key: Option<String>,
}

/// Result of applying a `PUT` chunk or status query to a resumable upload session.
#[derive(Debug)]
pub enum ResumableChunkOutcome {
    /// Upload still needs more bytes (respond `308 Resume Incomplete`, with `Range` if `received > 0`).
    Incomplete { received: usize },
    /// Final byte received; session was removed from the store and is ready to execute.
    Complete(Box<ResumableUploadSession>),
}

/// Parsed HTTP `Content-Range` header for Google's resumable upload protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentRange {
    /// `bytes */*` (status probe) or `bytes */<total>` (status probe / finalize when complete).
    StatusQuery { total: Option<usize> },
    /// `bytes <start>-<end>/<total_or_star>`
    Chunk {
        start: usize,
        end: usize,
        total: Option<usize>,
    },
}

/// Parse an HTTP `Content-Range` header according to Google's resumable upload protocol.
///
/// Accepts:
/// - `bytes */*`
/// - `bytes */<total>`
/// - `bytes <start>-<end>/<total>`
/// - `bytes <start>-<end>/*`
pub fn parse_content_range(raw: &str) -> AppResult<ContentRange> {
    let trimmed = raw.trim();
    if trimmed.len() < 6 || !trimmed[..5].eq_ignore_ascii_case("bytes") {
        return Err(AppError::BadRequest(format!(
            "Invalid Content-Range header '{raw}': expected 'bytes ...'"
        )));
    }
    let after_unit = &trimmed[5..];
    if !after_unit.starts_with(|c: char| c.is_ascii_whitespace()) {
        return Err(AppError::BadRequest(format!(
            "Invalid Content-Range header '{raw}': missing whitespace after 'bytes'"
        )));
    }
    let spec = after_unit.trim();
    let (range_part, total_part) = spec.split_once('/').ok_or_else(|| {
        AppError::BadRequest(format!(
            "Invalid Content-Range header '{raw}': missing '/' separator"
        ))
    })?;

    let range_part = range_part.trim();
    let total_part = total_part.trim();

    let total = if total_part == "*" {
        None
    } else {
        let parsed = total_part.parse::<usize>().map_err(|_| {
            AppError::BadRequest(format!(
                "Invalid Content-Range total '{total_part}' in '{raw}'"
            ))
        })?;
        Some(parsed)
    };

    if range_part == "*" {
        return Ok(ContentRange::StatusQuery { total });
    }

    let (start_str, end_str) = range_part.split_once('-').ok_or_else(|| {
        AppError::BadRequest(format!(
            "Invalid Content-Range range '{range_part}' in '{raw}'"
        ))
    })?;

    let start = start_str.trim().parse::<usize>().map_err(|_| {
        AppError::BadRequest(format!(
            "Invalid Content-Range start '{start_str}' in '{raw}'"
        ))
    })?;
    let end = end_str.trim().parse::<usize>().map_err(|_| {
        AppError::BadRequest(format!("Invalid Content-Range end '{end_str}' in '{raw}'"))
    })?;

    if start > end {
        return Err(AppError::BadRequest(format!(
            "Invalid Content-Range '{raw}': start ({start}) > end ({end})"
        )));
    }

    if let Some(t) = total
        && (t == 0 || end >= t)
    {
        return Err(AppError::BadRequest(format!(
            "Invalid Content-Range '{raw}': end ({end}) must be less than total ({t})"
        )));
    }

    Ok(ContentRange::Chunk { start, end, total })
}

/// Thread-safe in-memory store for active Gmail `uploadType=resumable` sessions with TTL cleanup.
#[derive(Debug)]
pub struct ResumableUploadStore {
    ttl: Duration,
    sessions: RwLock<HashMap<String, ResumableUploadSession>>,
}

impl Default for ResumableUploadStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ResumableUploadStore {
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_RESUMABLE_UPLOAD_TTL)
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            ttl,
            sessions: RwLock::new(HashMap::new()),
        }
    }

    fn sweep_expired(
        sessions: &mut HashMap<String, ResumableUploadSession>,
        ttl: Duration,
        now: Instant,
    ) {
        sessions.retain(|_, session| now.saturating_duration_since(session.updated_at) <= ttl);
    }

    /// Create and persist a new resumable upload session, returning its generated `upload_id`.
    pub fn create_session(&self, init: NewResumableUpload) -> AppResult<String> {
        let now = Instant::now();
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| AppError::Internal("Resumable upload store lock poisoned".to_string()))?;

        Self::sweep_expired(&mut sessions, self.ttl, now);

        if sessions.len() >= MAX_CONCURRENT_RESUMABLE_SESSIONS {
            return Err(AppError::RateLimited(
                "Too many concurrent resumable upload sessions".to_string(),
            ));
        }

        let id = Uuid::new_v4().simple().to_string();
        let initial_cap = init
            .declared_total_bytes
            .unwrap_or(0)
            .min(MAX_INITIAL_BUFFER_PREALLOC);

        sessions.insert(
            id.clone(),
            ResumableUploadSession {
                id: id.clone(),
                user_email: init.user_email,
                target: init.target,
                metadata: init.metadata,
                content_type: init.content_type,
                declared_total_bytes: init.declared_total_bytes,
                known_total_bytes: None,
                idempotency_key: init.idempotency_key,
                buffer: Vec::with_capacity(initial_cap),
                created_at: now,
                updated_at: now,
            },
        );

        Ok(id)
    }

    /// Apply a chunk upload or status query (`PUT`) against an existing resumable upload session.
    pub fn process_chunk(
        &self,
        upload_id: &str,
        user_email: &str,
        expected_endpoint: &ResumableEndpoint,
        content_range_header: Option<&str>,
        body: &[u8],
        max_body_bytes: usize,
    ) -> AppResult<ResumableChunkOutcome> {
        let now = Instant::now();
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| AppError::Internal("Resumable upload store lock poisoned".to_string()))?;

        Self::sweep_expired(&mut sessions, self.ttl, now);

        let matches_target = sessions.get(upload_id).is_some_and(|s| {
            s.user_email.eq_ignore_ascii_case(user_email)
                && s.target.endpoint() == *expected_endpoint
        });
        if !matches_target {
            return Err(AppError::NotFound(format!(
                "Resumable upload session '{upload_id}' not found or expired"
            )));
        }

        match content_range_header {
            None => {
                let session = sessions.get(upload_id).expect("checked above");
                if !session.buffer.is_empty() {
                    return Err(AppError::BadRequest(
                        "Missing Content-Range header on subsequent resumable upload chunk"
                            .to_string(),
                    ));
                }
                if body.len() > max_body_bytes {
                    return Err(AppError::PayloadTooLarge(format!(
                        "Upload size {} bytes exceeds maximum allowed body size of {max_body_bytes} bytes",
                        body.len()
                    )));
                }
                let mut session = sessions.remove(upload_id).expect("checked above");
                session.buffer.extend_from_slice(body);
                session.updated_at = now;
                Ok(ResumableChunkOutcome::Complete(Box::new(session)))
            }
            Some(raw_range) => {
                let parsed = parse_content_range(raw_range)?;
                match parsed {
                    ContentRange::StatusQuery { total } => {
                        if !body.is_empty() {
                            return Err(AppError::BadRequest(
                                "Content-Range status query must have an empty request body"
                                    .to_string(),
                            ));
                        }
                        if let Some(t) = total
                            && t > max_body_bytes
                        {
                            return Err(AppError::PayloadTooLarge(format!(
                                "Declared upload size {t} bytes exceeds maximum allowed body size of {max_body_bytes} bytes"
                            )));
                        }
                        let received = sessions.get(upload_id).expect("checked above").buffer.len();
                        if let Some(t) = total {
                            if received > t {
                                return Err(AppError::BadRequest(format!(
                                    "Content-Range total ({t}) is smaller than bytes already uploaded ({received})"
                                )));
                            }
                            if received == t {
                                let mut session =
                                    sessions.remove(upload_id).expect("checked above");
                                session.updated_at = now;
                                return Ok(ResumableChunkOutcome::Complete(Box::new(session)));
                            }
                        }
                        if let Some(session) = sessions.get_mut(upload_id) {
                            session.updated_at = now;
                        }
                        Ok(ResumableChunkOutcome::Incomplete { received })
                    }
                    ContentRange::Chunk { start, end, total } => {
                        let expected_len = end
                            .checked_sub(start)
                            .and_then(|d| d.checked_add(1))
                            .ok_or_else(|| {
                                AppError::BadRequest(format!(
                                    "Invalid Content-Range byte span {start}-{end}"
                                ))
                            })?;
                        if body.len() != expected_len {
                            return Err(AppError::BadRequest(format!(
                                "Chunk body length ({}) does not match Content-Range length ({expected_len})",
                                body.len()
                            )));
                        }
                        if let Some(t) = total
                            && t > max_body_bytes
                        {
                            return Err(AppError::PayloadTooLarge(format!(
                                "Upload total size {t} bytes exceeds maximum allowed body size of {max_body_bytes} bytes"
                            )));
                        }

                        let (current_len, prev_total) = {
                            let s = sessions.get(upload_id).expect("checked above");
                            (s.buffer.len(), s.known_total_bytes)
                        };

                        if let (Some(prev), Some(t)) = (prev_total, total)
                            && prev != t
                        {
                            return Err(AppError::BadRequest(format!(
                                "Conflicting Content-Range total: expected {prev}, got {t}"
                            )));
                        }

                        if start != current_len {
                            return Err(AppError::BadRequest(format!(
                                "Non-contiguous Content-Range: expected start offset {current_len}, got {start}"
                            )));
                        }

                        let new_len = current_len.checked_add(body.len()).ok_or_else(|| {
                            AppError::PayloadTooLarge("Resumable upload size overflow".to_string())
                        })?;
                        if new_len > max_body_bytes {
                            return Err(AppError::PayloadTooLarge(format!(
                                "Cumulative upload size {new_len} bytes exceeds maximum allowed body size of {max_body_bytes} bytes"
                            )));
                        }

                        if total == Some(new_len) {
                            let mut session = sessions.remove(upload_id).expect("checked above");
                            session.known_total_bytes = total;
                            session.buffer.extend_from_slice(body);
                            session.updated_at = now;
                            Ok(ResumableChunkOutcome::Complete(Box::new(session)))
                        } else {
                            let session = sessions.get_mut(upload_id).expect("checked above");
                            if total.is_some() {
                                session.known_total_bytes = total;
                            }
                            session.buffer.extend_from_slice(body);
                            session.updated_at = now;
                            Ok(ResumableChunkOutcome::Incomplete { received: new_len })
                        }
                    }
                }
            }
        }
    }

    /// Cancel and remove an in-flight resumable upload session.
    pub fn cancel_session(
        &self,
        upload_id: &str,
        user_email: &str,
        expected_endpoint: &ResumableEndpoint,
    ) -> AppResult<bool> {
        let now = Instant::now();
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| AppError::Internal("Resumable upload store lock poisoned".to_string()))?;

        Self::sweep_expired(&mut sessions, self.ttl, now);

        let matches_target = sessions.get(upload_id).is_some_and(|s| {
            s.user_email.eq_ignore_ascii_case(user_email)
                && s.target.endpoint() == *expected_endpoint
        });
        if matches_target {
            sessions.remove(upload_id);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Returns `true` when the request's `uploadType` query parameter is `resumable`.
pub fn is_resumable_upload(query: &QueryParams) -> bool {
    query
        .get("uploadType")
        .is_some_and(|v| v.eq_ignore_ascii_case("resumable"))
}

/// Extract and validate `X-Upload-Content-Length` against `max_body_bytes`.
pub fn parse_upload_content_length(
    headers: &HeaderMap,
    max_body_bytes: usize,
) -> AppResult<Option<usize>> {
    let Some(raw) = headers.get("x-upload-content-length") else {
        return Ok(None);
    };
    let text = raw
        .to_str()
        .map_err(|_| AppError::BadRequest("Invalid X-Upload-Content-Length header".to_string()))?
        .trim();
    if text.is_empty() {
        return Ok(None);
    }
    let len = text.parse::<usize>().map_err(|_| {
        AppError::BadRequest(format!(
            "Invalid X-Upload-Content-Length value '{text}'; expected non-negative integer"
        ))
    })?;
    if len > max_body_bytes {
        return Err(AppError::PayloadTooLarge(format!(
            "X-Upload-Content-Length ({len} bytes) exceeds maximum allowed body size of {max_body_bytes} bytes"
        )));
    }
    Ok(Some(len))
}

/// Extract optional `X-Upload-Content-Type` header string.
pub fn extract_upload_content_type(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-upload-content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

/// Extract optional JSON [`Message`] metadata from a resumable upload initiation request body.
pub fn extract_resumable_message_metadata(body: &Bytes) -> AppResult<Message> {
    if body.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(Message::default());
    }
    Ok(serde_json::from_slice(body)?)
}

/// Extract optional JSON [`Draft`] metadata from a resumable upload initiation request body.
pub fn extract_resumable_draft_metadata(body: &Bytes) -> AppResult<Draft> {
    if body.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(Draft::default());
    }
    Ok(serde_json::from_slice(body)?)
}

/// Build the `Location` header returned by a `200 OK` resumable upload initiation response.
///
/// Derives an absolute URL from `Host` (plus `X-Forwarded-Proto`, defaulting to `http`) when
/// present, and falls back to a path-relative URL otherwise. Rewrites `/gmail/v1/...` paths to
/// `/upload/gmail/v1/...` so clients resume against the upload route.
pub fn build_resumable_location(
    headers: &HeaderMap,
    uri: &Uri,
    upload_id: &str,
    fields: Option<&str>,
) -> AppResult<HeaderValue> {
    let raw_path = uri.path();
    let upload_path = if raw_path.starts_with("/gmail/v1/") {
        format!("/upload{raw_path}")
    } else {
        raw_path.to_string()
    };

    let mut query = format!("uploadType=resumable&upload_id={upload_id}");
    if let Some(mask) = fields.map(str::trim).filter(|s| !s.is_empty()) {
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        ser.append_pair("fields", mask);
        query.push('&');
        query.push_str(&ser.finish());
    }

    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .and_then(|proto| {
            let first = proto.split(',').next().unwrap_or("").trim();
            if first.eq_ignore_ascii_case("https") {
                Some("https")
            } else if first.eq_ignore_ascii_case("http") {
                Some("http")
            } else {
                None
            }
        })
        .or_else(|| {
            uri.scheme_str().and_then(|s| {
                if s.eq_ignore_ascii_case("https") {
                    Some("https")
                } else if s.eq_ignore_ascii_case("http") {
                    Some("http")
                } else {
                    None
                }
            })
        })
        .unwrap_or("http");

    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|h| !h.is_empty() && !h.contains('\r') && !h.contains('\n'))
        .or_else(|| uri.authority().map(|a| a.as_str()));

    let location = match host {
        Some(h) => format!("{scheme}://{h}{upload_path}?{query}"),
        None => format!("{upload_path}?{query}"),
    };

    HeaderValue::from_str(&location)
        .map_err(|e| AppError::Internal(format!("Invalid resumable Location header: {e}")))
}

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
                "uploadType=resumable must be initiated via the /upload/gmail/v1/... resumable upload protocol"
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
                "uploadType=resumable must be initiated via the /upload/gmail/v1/... resumable upload protocol"
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
    let raw_bytes = match metadata.message.as_ref().and_then(|m| m.raw.as_deref()) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_content_range_valid_and_invalid_cases() {
        assert_eq!(
            parse_content_range("bytes */*").unwrap(),
            ContentRange::StatusQuery { total: None }
        );
        assert_eq!(
            parse_content_range("BYTES */0").unwrap(),
            ContentRange::StatusQuery { total: Some(0) }
        );
        assert_eq!(
            parse_content_range("bytes */1024").unwrap(),
            ContentRange::StatusQuery { total: Some(1024) }
        );
        assert_eq!(
            parse_content_range("bytes 0-99/250").unwrap(),
            ContentRange::Chunk {
                start: 0,
                end: 99,
                total: Some(250),
            }
        );
        assert_eq!(
            parse_content_range("bytes 100-199/*").unwrap(),
            ContentRange::Chunk {
                start: 100,
                end: 199,
                total: None,
            }
        );

        for invalid in [
            "",
            "items 0-10/20",
            "bytes0-10/20",
            "bytes 0-10",
            "bytes 10-5/20",
            "bytes 0-20/20",
            "bytes 0-0/0",
            "bytes a-b/10",
            "bytes 0-5/abc",
        ] {
            assert!(
                parse_content_range(invalid).is_err(),
                "expected '{invalid}' to fail Content-Range parsing"
            );
        }
    }

    #[test]
    fn build_resumable_location_derives_origin_and_preserves_fields() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("127.0.0.1:8080"));
        let uri: Uri = "/upload/gmail/v1/users/me/messages/send?uploadType=resumable"
            .parse()
            .unwrap();
        let loc = build_resumable_location(&headers, &uri, "abc123", None).unwrap();
        assert_eq!(
            loc.to_str().unwrap(),
            "http://127.0.0.1:8080/upload/gmail/v1/users/me/messages/send?uploadType=resumable&upload_id=abc123"
        );

        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        let api_uri: Uri = "/gmail/v1/users/me/drafts?uploadType=resumable&fields=id,message/id"
            .parse()
            .unwrap();
        let loc_https =
            build_resumable_location(&headers, &api_uri, "def456", Some("id,message/id")).unwrap();
        assert_eq!(
            loc_https.to_str().unwrap(),
            "https://127.0.0.1:8080/upload/gmail/v1/users/me/drafts?uploadType=resumable&upload_id=def456&fields=id%2Cmessage%2Fid"
        );

        let bare_loc = build_resumable_location(&HeaderMap::new(), &uri, "xyz", None).unwrap();
        assert_eq!(
            bare_loc.to_str().unwrap(),
            "/upload/gmail/v1/users/me/messages/send?uploadType=resumable&upload_id=xyz"
        );
    }

    #[test]
    fn resumable_store_chunking_status_validation_and_ttl_expiry() {
        let store = ResumableUploadStore::with_ttl(Duration::from_secs(60));
        let uid = store
            .create_session(NewResumableUpload {
                user_email: "agent@example.com".to_string(),
                target: ResumableUploadTarget::MessagesSend,
                metadata: ResumableUploadMetadata::Message(Message::default()),
                content_type: Some("message/rfc822".to_string()),
                declared_total_bytes: Some(10),
                idempotency_key: Some("idem-1".to_string()),
            })
            .unwrap();

        // Status probe before any data
        let step = store
            .process_chunk(
                &uid,
                "agent@example.com",
                &ResumableEndpoint::MessagesSend,
                Some("bytes */*"),
                &[],
                100,
            )
            .unwrap();
        assert!(matches!(
            step,
            ResumableChunkOutcome::Incomplete { received: 0 }
        ));

        // Wrong endpoint returns 404
        let wrong_ep = store.process_chunk(
            &uid,
            "agent@example.com",
            &ResumableEndpoint::DraftsCreate,
            Some("bytes */*"),
            &[],
            100,
        );
        assert!(matches!(wrong_ep, Err(AppError::NotFound(_))));

        // Chunk 1 with unknown total
        let step = store
            .process_chunk(
                &uid,
                "agent@example.com",
                &ResumableEndpoint::MessagesSend,
                Some("bytes 0-3/*"),
                b"abcd",
                100,
            )
            .unwrap();
        assert!(matches!(
            step,
            ResumableChunkOutcome::Incomplete { received: 4 }
        ));

        // Non-contiguous gap rejected without corrupting session
        let gap = store.process_chunk(
            &uid,
            "agent@example.com",
            &ResumableEndpoint::MessagesSend,
            Some("bytes 5-6/*"),
            b"fg",
            100,
        );
        assert!(matches!(gap, Err(AppError::BadRequest(_))));

        // Oversize chunk rejected with 413
        let big = store.process_chunk(
            &uid,
            "agent@example.com",
            &ResumableEndpoint::MessagesSend,
            Some("bytes 4-9/10"),
            b"efghij",
            8,
        );
        assert!(matches!(big, Err(AppError::PayloadTooLarge(_))));

        // Chunk 2 unknown total
        let step = store
            .process_chunk(
                &uid,
                "agent@example.com",
                &ResumableEndpoint::MessagesSend,
                Some("bytes 4-9/*"),
                b"efghij",
                100,
            )
            .unwrap();
        assert!(matches!(
            step,
            ResumableChunkOutcome::Incomplete { received: 10 }
        ));

        // Finalize via empty PUT with Content-Range: bytes */10
        let done = store
            .process_chunk(
                &uid,
                "agent@example.com",
                &ResumableEndpoint::MessagesSend,
                Some("bytes */10"),
                &[],
                100,
            )
            .unwrap();
        match done {
            ResumableChunkOutcome::Complete(session) => {
                assert_eq!(session.buffer, b"abcdefghij");
                assert_eq!(session.idempotency_key.as_deref(), Some("idem-1"));
            }
            ResumableChunkOutcome::Incomplete { .. } => panic!("expected completion"),
        }

        // TTL expiry evicts idle sessions
        let short_store = ResumableUploadStore::with_ttl(Duration::from_millis(10));
        let expiring_id = short_store
            .create_session(NewResumableUpload {
                user_email: "agent@example.com".to_string(),
                target: ResumableUploadTarget::DraftsCreate,
                metadata: ResumableUploadMetadata::Draft(Draft::default()),
                content_type: None,
                declared_total_bytes: None,
                idempotency_key: None,
            })
            .unwrap();
        std::thread::sleep(Duration::from_millis(25));
        let expired = short_store.process_chunk(
            &expiring_id,
            "agent@example.com",
            &ResumableEndpoint::DraftsCreate,
            Some("bytes */*"),
            &[],
            100,
        );
        assert!(matches!(expired, Err(AppError::NotFound(_))));
    }
}
