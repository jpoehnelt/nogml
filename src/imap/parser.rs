//! RFC 3501 / 7888 (`LITERAL+`) IMAP4rev1 wire-format reader, tokenizer,
//! sequence-set parser, date helpers, and response formatting utilities.

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{AppError, AppResult};

/// Maximum length of a single command line segment (excluding literal payloads).
const MAX_LINE_BYTES: usize = 64 * 1024;

/// A piece of a raw IMAP command before tokenization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawChunk {
    Text(String),
    Literal(Vec<u8>),
}

/// Parsed IMAP command argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImapArg {
    Atom(String),
    Quoted(String),
    Literal(Vec<u8>),
    List(Vec<ImapArg>),
}

impl ImapArg {
    /// Extract argument as UTF-8 text (lossy for binary literals).
    pub fn as_str_lossy(&self) -> Option<String> {
        match self {
            Self::Atom(s) | Self::Quoted(s) => Some(s.clone()),
            Self::Literal(b) => Some(String::from_utf8_lossy(b).into_owned()),
            Self::List(_) => None,
        }
    }

    /// Extract raw bytes of an atom, quoted string, or literal.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Atom(s) | Self::Quoted(s) => Some(s.as_bytes()),
            Self::Literal(b) => Some(b.as_slice()),
            Self::List(_) => None,
        }
    }

    pub fn as_list(&self) -> Option<&[ImapArg]> {
        match self {
            Self::List(items) => Some(items.as_slice()),
            _ => None,
        }
    }

    pub fn is_nil(&self) -> bool {
        matches!(self, Self::Atom(s) if s.eq_ignore_ascii_case("NIL"))
    }
}

/// A parsed IMAP command: `<tag> <name> <args...>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImapCommand {
    pub tag: String,
    pub name: String,
    pub args: Vec<ImapArg>,
}

/// Result of reading the next command frame from an IMAP client.
#[derive(Debug)]
pub enum ReadCommandOutcome {
    Command(ImapCommand),
    /// Client sent an empty line; ignore and continue reading.
    Empty,
    /// Client closed the connection cleanly.
    Eof,
    /// Client sent a literal larger than `max_literal_bytes` (with parsed tag if available).
    LiteralTooLarge {
        tag: Option<String>,
        size: usize,
    },
}

/// Read one complete IMAP command (handling synchronizing `{N}` and `LITERAL+` `{N+}` literals).
pub async fn read_command<S>(
    stream: &mut S,
    max_literal_bytes: usize,
) -> AppResult<ReadCommandOutcome>
where
    S: AsyncBufRead + AsyncWrite + Unpin,
{
    let mut chunks: Vec<RawChunk> = Vec::new();
    let mut first_tag: Option<String> = None;

    loop {
        let line = match read_crlf_line(stream, MAX_LINE_BYTES).await? {
            Some(l) => l,
            None => {
                if chunks.is_empty() {
                    return Ok(ReadCommandOutcome::Eof);
                }
                return Err(AppError::BadRequest(
                    "Unexpected EOF while reading IMAP command".to_string(),
                ));
            }
        };

        if chunks.is_empty() && line.trim().is_empty() {
            return Ok(ReadCommandOutcome::Empty);
        }

        if first_tag.is_none() {
            first_tag = line.split_whitespace().next().map(str::to_string);
        }

        if let Some((prefix, lit_len, non_sync)) = parse_trailing_literal(&line) {
            if !prefix.is_empty() {
                chunks.push(RawChunk::Text(prefix.to_string()));
            }
            if lit_len > max_literal_bytes {
                // For synchronizing literals we haven't sent continuation, so client won't send payload.
                // For non-sync literals, abort connection since stream framing would desync.
                if non_sync {
                    return Err(AppError::PayloadTooLarge(format!(
                        "IMAP literal size {lit_len} exceeds limit {max_literal_bytes}"
                    )));
                }
                return Ok(ReadCommandOutcome::LiteralTooLarge {
                    tag: first_tag,
                    size: lit_len,
                });
            }
            if !non_sync {
                stream
                    .write_all(b"+ Ready\r\n")
                    .await
                    .map_err(|e| AppError::Internal(format!("IMAP write error: {e}")))?;
                stream
                    .flush()
                    .await
                    .map_err(|e| AppError::Internal(format!("IMAP flush error: {e}")))?;
            }
            let mut buf = vec![0u8; lit_len];
            stream
                .read_exact(&mut buf)
                .await
                .map_err(|e| AppError::BadRequest(format!("IMAP literal read error: {e}")))?;
            chunks.push(RawChunk::Literal(buf));
        } else {
            if !line.is_empty() {
                chunks.push(RawChunk::Text(line));
            }
            break;
        }
    }

    let cmd = parse_command_chunks(&chunks)?;
    Ok(ReadCommandOutcome::Command(cmd))
}

/// Read a single line terminated by `\n` (stripping trailing `\r\n` or `\n`).
pub async fn read_crlf_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> AppResult<Option<String>> {
    let mut buf = Vec::new();
    let mut total = 0usize;
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|e| AppError::Internal(format!("IMAP read error: {e}")))?;
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            break;
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            let take = pos + 1;
            total += take;
            if total > max_bytes {
                return Err(AppError::BadRequest(
                    "IMAP command line too long".to_string(),
                ));
            }
            buf.extend_from_slice(&available[..take]);
            reader.consume(take);
            break;
        } else {
            let len = available.len();
            total += len;
            if total > max_bytes {
                return Err(AppError::BadRequest(
                    "IMAP command line too long".to_string(),
                ));
            }
            buf.extend_from_slice(available);
            reader.consume(len);
        }
    }

    while matches!(buf.last(), Some(b'\n' | b'\r')) {
        buf.pop();
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

/// Check if a line ends with `{N}` or `{N+}`.
/// Returns `(prefix_before_brace, byte_length, is_literal_plus)`.
pub fn parse_trailing_literal(line: &str) -> Option<(&str, usize, bool)> {
    let without_close = line.strip_suffix('}')?;
    let open_idx = without_close.rfind('{')?;
    let inside = &without_close[open_idx + 1..];
    if inside.is_empty() {
        return None;
    }
    let (digits, non_sync) = match inside.strip_suffix('+') {
        Some(d) => (d, true),
        None => (inside, false),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let len = digits.parse::<usize>().ok()?;
    Some((&line[..open_idx], len, non_sync))
}

/// Tokenize raw chunks into an [`ImapCommand`].
pub fn parse_command_chunks(chunks: &[RawChunk]) -> AppResult<ImapCommand> {
    let tokens = tokenize_chunks(chunks)?;
    if tokens.len() < 2 {
        return Err(AppError::BadRequest(
            "IMAP command requires at least tag and command name".to_string(),
        ));
    }
    let tag = match &tokens[0] {
        ImapArg::Atom(s) => s.clone(),
        _ => {
            return Err(AppError::BadRequest("IMAP tag must be an atom".to_string()));
        }
    };
    let name = match &tokens[1] {
        ImapArg::Atom(s) => s.to_ascii_uppercase(),
        _ => {
            return Err(AppError::BadRequest(
                "IMAP command name must be an atom".to_string(),
            ));
        }
    };
    Ok(ImapCommand {
        tag,
        name,
        args: tokens[2..].to_vec(),
    })
}

/// Convenience helper for parsing a single-line IMAP command (for tests).
pub fn parse_command_line(line: &str) -> AppResult<ImapCommand> {
    parse_command_chunks(&[RawChunk::Text(line.to_string())])
}

/// Tokenize a sequence of text and literal chunks into nested `ImapArg`s.
pub fn tokenize_chunks(chunks: &[RawChunk]) -> AppResult<Vec<ImapArg>> {
    let mut stack: Vec<Vec<ImapArg>> = vec![Vec::new()];

    for chunk in chunks {
        match chunk {
            RawChunk::Literal(bytes) => {
                stack
                    .last_mut()
                    .expect("root stack frame")
                    .push(ImapArg::Literal(bytes.clone()));
            }
            RawChunk::Text(text) => {
                let bytes = text.as_bytes();
                let mut i = 0;
                while i < bytes.len() {
                    let b = bytes[i];
                    if b.is_ascii_whitespace() {
                        i += 1;
                        continue;
                    }
                    if b == b'(' {
                        stack.push(Vec::new());
                        i += 1;
                        continue;
                    }
                    if b == b')' {
                        if stack.len() <= 1 {
                            return Err(AppError::BadRequest(
                                "Unmatched ')' in IMAP command".to_string(),
                            ));
                        }
                        let list = stack.pop().expect("non-root frame");
                        stack
                            .last_mut()
                            .expect("parent frame")
                            .push(ImapArg::List(list));
                        i += 1;
                        continue;
                    }
                    if b == b'"' {
                        i += 1;
                        let mut out = String::new();
                        let mut closed = false;
                        while i < bytes.len() {
                            let c = bytes[i];
                            if c == b'\\' && i + 1 < bytes.len() {
                                out.push(bytes[i + 1] as char);
                                i += 2;
                            } else if c == b'"' {
                                i += 1;
                                closed = true;
                                break;
                            } else {
                                // Preserve UTF-8 characters cleanly.
                                let ch = text[i..].chars().next().unwrap();
                                out.push(ch);
                                i += ch.len_utf8();
                            }
                        }
                        if !closed {
                            return Err(AppError::BadRequest(
                                "Unterminated quoted string in IMAP command".to_string(),
                            ));
                        }
                        stack.last_mut().expect("frame").push(ImapArg::Quoted(out));
                        continue;
                    }

                    // Atom (including section specs like BODY.PEEK[HEADER.FIELDS (Subject From)]<0.50>).
                    let start = i;
                    let mut bracket_depth = 0usize;
                    let mut in_quote = false;
                    while i < bytes.len() {
                        let c = bytes[i];
                        if in_quote {
                            if c == b'\\' && i + 1 < bytes.len() {
                                i += 2;
                                continue;
                            }
                            if c == b'"' {
                                in_quote = false;
                            }
                            i += 1;
                            continue;
                        }
                        if bracket_depth > 0 {
                            if c == b'"' {
                                in_quote = true;
                            } else if c == b'[' {
                                bracket_depth += 1;
                            } else if c == b']' {
                                bracket_depth -= 1;
                            }
                            i += 1;
                            continue;
                        }
                        if c == b'[' {
                            bracket_depth += 1;
                            i += 1;
                            continue;
                        }
                        if c.is_ascii_whitespace() || c == b'(' || c == b')' {
                            break;
                        }
                        i += 1;
                    }
                    let atom = text[start..i].to_string();
                    stack.last_mut().expect("frame").push(ImapArg::Atom(atom));
                }
            }
        }
    }

    if stack.len() != 1 {
        return Err(AppError::BadRequest(
            "Unclosed '(' in IMAP command".to_string(),
        ));
    }
    Ok(stack.pop().expect("root frame"))
}

/// Parse an RFC 3501 sequence set (e.g. `1,3:5,7:*`) into inclusive `(start, end)` ranges.
///
/// `max_val` is the highest sequence number or UID in the selected mailbox (used to resolve `*`).
/// If `max_val == 0`, returns an empty list (no messages can match).
pub fn parse_sequence_set(spec: &str, max_val: u32) -> AppResult<Vec<(u32, u32)>> {
    if spec.is_empty() {
        return Err(AppError::BadRequest("Empty IMAP sequence set".to_string()));
    }
    let mut ranges = Vec::new();
    for part in spec.split(',') {
        if part.is_empty() {
            return Err(AppError::BadRequest(format!(
                "Invalid IMAP sequence set: {spec}"
            )));
        }
        if let Some((left, right)) = part.split_once(':') {
            let a = parse_seq_num(left, max_val)?;
            let b = parse_seq_num(right, max_val)?;
            if max_val > 0 {
                ranges.push((a.min(b), a.max(b)));
            }
        } else {
            let v = parse_seq_num(part, max_val)?;
            if max_val > 0 {
                ranges.push((v, v));
            }
        }
    }
    Ok(ranges)
}

fn parse_seq_num(token: &str, max_val: u32) -> AppResult<u32> {
    if token == "*" {
        return Ok(max_val.max(1));
    }
    let v = token
        .parse::<u32>()
        .map_err(|_| AppError::BadRequest(format!("Invalid sequence number: {token}")))?;
    if v == 0 {
        return Err(AppError::BadRequest(
            "IMAP sequence numbers and UIDs must be >= 1".to_string(),
        ));
    }
    Ok(v)
}

/// Check if `value` falls within any inclusive `(start, end)` range.
pub fn seq_set_contains(ranges: &[(u32, u32)], value: u32) -> bool {
    ranges.iter().any(|&(lo, hi)| value >= lo && value <= hi)
}

/// Format a list of positive sequence numbers or UIDs as a compact RFC 3501 sequence set
/// (e.g. `[1, 2, 3, 5, 7, 8]` -> `"1:3,5,7:8"`). Deduplicates and sorts ascending.
pub fn format_sequence_set(nums: &[u32]) -> String {
    let mut sorted: Vec<u32> = nums.iter().copied().filter(|&n| n > 0).collect();
    if sorted.is_empty() {
        return String::new();
    }
    sorted.sort_unstable();
    sorted.dedup();

    let mut parts: Vec<String> = Vec::new();
    let mut start = sorted[0];
    let mut prev = sorted[0];
    for &n in &sorted[1..] {
        if n == prev.saturating_add(1) {
            prev = n;
        } else {
            if start == prev {
                parts.push(start.to_string());
            } else {
                parts.push(format!("{start}:{prev}"));
            }
            start = n;
            prev = n;
        }
    }
    if start == prev {
        parts.push(start.to_string());
    } else {
        parts.push(format!("{start}:{prev}"));
    }
    parts.join(",")
}

/// Match an IMAP mailbox name against a `LIST`/`LSUB` pattern with delimiter `delim` (`'/'`).
///
/// `*` matches zero or more characters including `delim`.
/// `%` matches zero or more characters excluding `delim`.
/// `INBOX` is matched case-insensitively per RFC 3501.
pub fn imap_wildcard_match(pattern: &str, name: &str, delim: char) -> bool {
    if pattern.eq_ignore_ascii_case("INBOX") && name.eq_ignore_ascii_case("INBOX") {
        return true;
    }
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = name.chars().collect();
    wildcard_match_rec(&p, &s, delim)
}

fn wildcard_match_rec(p: &[char], s: &[char], delim: char) -> bool {
    if p.is_empty() {
        return s.is_empty();
    }
    match p[0] {
        '*' => {
            if wildcard_match_rec(&p[1..], s, delim) {
                return true;
            }
            if !s.is_empty() {
                return wildcard_match_rec(p, &s[1..], delim);
            }
            false
        }
        '%' => {
            if wildcard_match_rec(&p[1..], s, delim) {
                return true;
            }
            if !s.is_empty() && s[0] != delim {
                return wildcard_match_rec(p, &s[1..], delim);
            }
            false
        }
        c => {
            if !s.is_empty() && s[0] == c {
                wildcard_match_rec(&p[1..], &s[1..], delim)
            } else {
                false
            }
        }
    }
}

/// Format an IMAP quoted string (escaping `\` and `"`), or a literal `{N}\r\n...` if it contains CR/LF or non-ASCII.
pub fn imap_string(s: &str) -> String {
    if s.bytes()
        .any(|b| b == b'\r' || b == b'\n' || b == 0 || !b.is_ascii())
    {
        format!("{{{}}}\r\n{}", s.len(), s)
    } else {
        imap_quote(s)
    }
}

/// Format a guaranteed-ASCII string as an IMAP quoted string `"..."`.
pub fn imap_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        if ch == '\\' || ch == '"' {
            out.push('\\');
        }
        if ch != '\r' && ch != '\n' {
            out.push(ch);
        }
    }
    out.push('"');
    out
}

/// Format an optional string as IMAP `nstring` (`NIL` or quoted/literal string).
pub fn imap_nstring(opt: Option<&str>) -> String {
    match opt {
        Some(s) => imap_string(s),
        None => "NIL".to_string(),
    }
}

/// Format an IMAP literal header + bytes.
pub fn append_literal(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(format!("{{{}}}\r\n", data.len()).as_bytes());
    out.extend_from_slice(data);
}

/// Format epoch milliseconds as RFC 3501 `INTERNALDATE` (`"DD-Mon-YYYY HH:MM:SS +0000"`).
pub fn format_internal_date(epoch_ms: i64) -> String {
    let dt: DateTime<Utc> = Utc
        .timestamp_millis_opt(epoch_ms)
        .single()
        .unwrap_or_else(Utc::now);
    dt.format("%d-%b-%Y %H:%M:%S +0000").to_string()
}

/// Parse an RFC 3501 `date-time` string (`"DD-Mon-YYYY HH:MM:SS +ZZZZ"`) into epoch ms.
pub fn parse_imap_date_time(raw: &str) -> Option<i64> {
    let trimmed = raw.trim();
    if let Ok(dt) = DateTime::parse_from_str(trimmed, "%d-%b-%Y %H:%M:%S %z") {
        return Some(dt.timestamp_millis());
    }
    if let Ok(dt) = DateTime::parse_from_str(trimmed, "%e-%b-%Y %H:%M:%S %z") {
        return Some(dt.timestamp_millis());
    }
    if let Ok(dt) = DateTime::parse_from_rfc2822(trimmed) {
        return Some(dt.timestamp_millis());
    }
    None
}

/// Parse an RFC 3501 `SEARCH` date (`"DD-Mon-YYYY"` or `"D-Mon-YYYY"`).
pub fn parse_imap_search_date(raw: &str) -> Option<NaiveDate> {
    let trimmed = raw.trim();
    NaiveDate::parse_from_str(trimmed, "%d-%b-%Y")
        .or_else(|_| NaiveDate::parse_from_str(trimmed, "%e-%b-%Y"))
        .ok()
}

/// Normalize mailbox names (`INBOX` is case-insensitive in RFC 3501).
pub fn normalize_mailbox_name(name: &str) -> String {
    if name.eq_ignore_ascii_case("INBOX") {
        "INBOX".to_string()
    } else {
        name.to_string()
    }
}
