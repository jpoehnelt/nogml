//! RFC 3501 / 7888 (`LITERAL-`) IMAP4rev1 wire-format reader, tokenizer,
//! sequence-set parser, date helpers, and response formatting utilities.

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{AppError, AppResult};

/// Maximum length of a single command line segment (excluding literal payloads).
const MAX_LINE_BYTES: usize = 64 * 1024;
/// Maximum parenthesized list nesting depth in IMAP commands.
pub const MAX_IMAP_LIST_DEPTH: usize = 32;
/// Pre-authentication maximum size of a single synchronizing IMAP literal (16 KiB).
pub const PRE_AUTH_MAX_LITERAL_BYTES: usize = 16 * 1024;
/// RFC 7888 `LITERAL-` maximum size of a single non-synchronizing literal `{N+}` (4096 bytes).
pub const LITERAL_MINUS_MAX_BYTES: usize = 4096;
/// Pre-authentication cumulative command byte cap (32 KiB).
pub const PRE_AUTH_MAX_COMMAND_BYTES: usize = 32 * 1024;
/// Maximum number of literals allowed in a single IMAP command.
pub const MAX_COMMAND_LITERALS: usize = 16;
/// Extra framing headroom above `max_body_bytes` for authenticated commands (64 KiB).
pub const POST_AUTH_COMMAND_OVERHEAD_BYTES: usize = 64 * 1024;

/// Resource limits enforced while reading a single IMAP command frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadCommandLimits {
    /// Maximum byte length of any single synchronizing `{N}` literal.
    pub max_literal_bytes: usize,
    /// Maximum byte length of any single non-synchronizing `{N+}` literal (RFC 7888 `LITERAL-`).
    pub max_non_sync_literal_bytes: usize,
    /// Maximum number of literals allowed in one command.
    pub max_literals: usize,
    /// Maximum cumulative bytes across all lines and literal payloads in one command.
    pub max_command_bytes: usize,
}

impl ReadCommandLimits {
    /// Tight pre-authentication limits to prevent unauthenticated OOM DoS.
    pub fn pre_auth(config_max_body_bytes: usize) -> Self {
        let max_literal_bytes = config_max_body_bytes.min(PRE_AUTH_MAX_LITERAL_BYTES);
        Self {
            max_literal_bytes,
            max_non_sync_literal_bytes: max_literal_bytes.min(LITERAL_MINUS_MAX_BYTES),
            max_literals: MAX_COMMAND_LITERALS,
            max_command_bytes: PRE_AUTH_MAX_COMMAND_BYTES,
        }
    }

    /// Authenticated limits bounded by `max_body_bytes + 64 KiB` (with `LITERAL-` capped at 4096 bytes).
    pub fn authenticated(max_body_bytes: usize) -> Self {
        Self {
            max_literal_bytes: max_body_bytes,
            max_non_sync_literal_bytes: max_body_bytes.min(LITERAL_MINUS_MAX_BYTES),
            max_literals: MAX_COMMAND_LITERALS,
            max_command_bytes: max_body_bytes.saturating_add(POST_AUTH_COMMAND_OVERHEAD_BYTES),
        }
    }
}

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
    /// Client sent a synchronizing `{N}` literal larger than `max_literal_bytes` (with parsed tag
    /// if available). Connection remains synchronized because `+ Ready` was not sent.
    LiteralTooLarge {
        tag: Option<String>,
        size: usize,
    },
    /// Client sent a non-synchronizing `{N+}` literal exceeding RFC 7888 `LITERAL-` or command
    /// limits (with parsed tag if available). The server must reply with `<tag> NO [TOOBIG] ...`
    /// and `* BYE [TOOBIG] ...` and close the connection because stream framing may have desynced.
    NonSyncLiteralTooLarge {
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
    read_command_with_limits(stream, ReadCommandLimits::authenticated(max_literal_bytes)).await
}

/// Read one complete IMAP command enforcing per-literal, literal-count, and cumulative byte limits.
pub async fn read_command_with_limits<S>(
    stream: &mut S,
    limits: ReadCommandLimits,
) -> AppResult<ReadCommandOutcome>
where
    S: AsyncBufRead + AsyncWrite + Unpin,
{
    let mut chunks: Vec<RawChunk> = Vec::new();
    let mut first_tag: Option<String> = None;
    let mut literal_count = 0usize;
    let mut total_bytes = 0usize;

    loop {
        let remaining_budget = limits.max_command_bytes.saturating_sub(total_bytes);
        if remaining_budget == 0 {
            return Err(AppError::PayloadTooLarge(format!(
                "IMAP command exceeds cumulative limit of {} bytes",
                limits.max_command_bytes
            )));
        }
        let line_cap = MAX_LINE_BYTES.min(remaining_budget);
        let line = match read_crlf_line(stream, line_cap).await {
            Ok(Some(l)) => l,
            Ok(None) => {
                if chunks.is_empty() {
                    return Ok(ReadCommandOutcome::Eof);
                }
                return Err(AppError::BadRequest(
                    "Unexpected EOF while reading IMAP command".to_string(),
                ));
            }
            Err(AppError::BadRequest(msg)) if remaining_budget < MAX_LINE_BYTES => {
                return Err(AppError::PayloadTooLarge(msg));
            }
            Err(err) => return Err(err),
        };

        if chunks.is_empty() && line.trim().is_empty() {
            return Ok(ReadCommandOutcome::Empty);
        }

        // Count text line plus its CRLF terminator against the cumulative command budget.
        total_bytes = total_bytes.saturating_add(line.len().saturating_add(2));
        if total_bytes > limits.max_command_bytes {
            return Err(AppError::PayloadTooLarge(format!(
                "IMAP command exceeds cumulative limit of {} bytes",
                limits.max_command_bytes
            )));
        }

        if let Some((prefix, lit_len, non_sync)) = parse_trailing_literal(&line) {
            if first_tag.is_none() {
                first_tag = prefix.split_whitespace().next().map(str::to_string);
            }
            if !prefix.is_empty() {
                chunks.push(RawChunk::Text(prefix.to_string()));
            }
            literal_count += 1;
            if literal_count > limits.max_literals {
                if non_sync {
                    return Err(AppError::PayloadTooLarge(format!(
                        "IMAP command exceeds maximum literal count of {}",
                        limits.max_literals
                    )));
                }
                return Ok(ReadCommandOutcome::LiteralTooLarge {
                    tag: first_tag,
                    size: lit_len,
                });
            }
            if non_sync && lit_len > limits.max_non_sync_literal_bytes {
                // RFC 7888 LITERAL-: non-synchronizing literals > 4096 bytes are rejected
                // with [TOOBIG]; caller emits `<tag> NO [TOOBIG] ...` + `* BYE [TOOBIG] ...`
                // and closes the connection since the client may already be streaming payload bytes.
                return Ok(ReadCommandOutcome::NonSyncLiteralTooLarge {
                    tag: first_tag,
                    size: lit_len,
                });
            }
            if lit_len > limits.max_literal_bytes
                || total_bytes.saturating_add(lit_len) > limits.max_command_bytes
            {
                // For synchronizing literals we haven't sent continuation, so client won't send payload.
                // For non-sync literals, emit [TOOBIG] and abort connection since stream framing would desync.
                if non_sync {
                    return Ok(ReadCommandOutcome::NonSyncLiteralTooLarge {
                        tag: first_tag,
                        size: lit_len,
                    });
                }
                return Ok(ReadCommandOutcome::LiteralTooLarge {
                    tag: first_tag,
                    size: lit_len,
                });
            }
            total_bytes = total_bytes.saturating_add(lit_len);
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
    read_crlf_line_into(reader, &mut buf, max_bytes).await
}

/// Cancel-safe variant of [`read_crlf_line`] that accumulates partial line bytes in caller-owned
/// `buf`. If the returned future is dropped inside `tokio::select!` before `\n` arrives, already
/// consumed bytes remain in `buf` and are preserved on the next call.
pub async fn read_crlf_line_into<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max_bytes: usize,
) -> AppResult<Option<String>> {
    if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
        let mut raw: Vec<u8> = buf.drain(..=pos).collect();
        while matches!(raw.last(), Some(b'\n' | b'\r')) {
            raw.pop();
        }
        return Ok(Some(String::from_utf8_lossy(&raw).into_owned()));
    }

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
            if buf.len().saturating_add(take) > max_bytes {
                buf.clear();
                return Err(AppError::BadRequest(
                    "IMAP command line too long".to_string(),
                ));
            }
            buf.extend_from_slice(&available[..take]);
            reader.consume(take);
            break;
        } else {
            let len = available.len();
            if buf.len().saturating_add(len) > max_bytes {
                buf.clear();
                return Err(AppError::BadRequest(
                    "IMAP command line too long".to_string(),
                ));
            }
            buf.extend_from_slice(available);
            reader.consume(len);
        }
    }

    let mut raw = std::mem::take(buf);
    while matches!(raw.last(), Some(b'\n' | b'\r')) {
        raw.pop();
    }
    Ok(Some(String::from_utf8_lossy(&raw).into_owned()))
}

/// Check if a line ends with `{N}`, `{N+}`, `~{N}`, or `~{N+}` (RFC 3501 / 7888 / 6855 `literal8`).
/// Returns `(prefix_before_literal, byte_length, is_literal_plus)`.
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
    let prefix = &line[..open_idx];
    let prefix = prefix.strip_suffix('~').unwrap_or(prefix);
    Some((prefix, len, non_sync))
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
                        if stack.len() > MAX_IMAP_LIST_DEPTH {
                            return Err(AppError::BadRequest(format!(
                                "IMAP command exceeds maximum list nesting depth of {MAX_IMAP_LIST_DEPTH}"
                            )));
                        }
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
                                let ch = text[i + 1..].chars().next().unwrap();
                                out.push(ch);
                                i += 1 + ch.len_utf8();
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
                                let ch = text[i + 1..].chars().next().unwrap();
                                i += 1 + ch.len_utf8();
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
                                if bracket_depth > MAX_IMAP_LIST_DEPTH {
                                    return Err(AppError::BadRequest(format!(
                                        "IMAP command exceeds maximum bracket nesting depth of {MAX_IMAP_LIST_DEPTH}"
                                    )));
                                }
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
///
/// Runs in O(n*m) time and O(n) space via dynamic programming (immune to wildcard backtracking ReDoS).
pub fn imap_wildcard_match(pattern: &str, name: &str, delim: char) -> bool {
    if pattern.eq_ignore_ascii_case("INBOX") && name.eq_ignore_ascii_case("INBOX") {
        return true;
    }
    let s: Vec<char> = name.chars().collect();
    let n = s.len();
    let mut prev = vec![false; n + 1];
    let mut curr = vec![false; n + 1];
    prev[0] = true;

    for pch in pattern.chars() {
        curr.fill(false);
        match pch {
            '*' => {
                curr[0] = prev[0];
                for j in 1..=n {
                    curr[j] = prev[j] || curr[j - 1];
                }
            }
            '%' => {
                curr[0] = prev[0];
                for j in 1..=n {
                    curr[j] = prev[j] || (curr[j - 1] && s[j - 1] != delim);
                }
            }
            c => {
                for j in 1..=n {
                    curr[j] = prev[j - 1] && s[j - 1] == c;
                }
            }
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[n]
}

/// Format an IMAP quoted string (escaping `\` and `"`), or a literal `{N}\r\n...` if it contains
/// CR/LF, control characters, or non-ASCII bytes. NUL bytes are stripped because RFC 3501 forbids
/// NUL octets in both quoted strings and literals.
pub fn imap_string(s: &str) -> String {
    imap_string_with_utf8(s, false)
}

/// Format an IMAP string, permitting unescaped UTF-8 inside quoted strings when `utf8_accept`
/// is `true` (RFC 6855 `UTF8=ACCEPT`), and falling back to `{N}\r\n...` literals only for CR/LF
/// or ASCII control characters (or non-ASCII bytes when `utf8_accept` is `false`).
pub fn imap_string_with_utf8(s: &str, utf8_accept: bool) -> String {
    let sanitized: std::borrow::Cow<'_, str> = if s.contains('\0') {
        std::borrow::Cow::Owned(s.replace('\0', ""))
    } else {
        std::borrow::Cow::Borrowed(s)
    };
    let needs_literal = sanitized.bytes().any(|b| {
        b == b'\r'
            || b == b'\n'
            || b == 0x7f
            || (b < 0x20 && b != b'\t')
            || (!utf8_accept && !b.is_ascii())
    });
    if needs_literal {
        format!("{{{}}}\r\n{}", sanitized.len(), sanitized)
    } else {
        imap_quote(&sanitized)
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
        if ch != '\r' && ch != '\n' && ch != '\0' {
            out.push(ch);
        }
    }
    out.push('"');
    out
}

/// Sanitize arbitrary human-readable text for an IMAP single-line response (stripping CR/LF/NUL).
pub fn sanitize_imap_text(s: &str) -> String {
    s.chars()
        .map(|ch| match ch {
            '\r' | '\n' | '\0' => ' ',
            other => other,
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_escaped_multibyte_utf8_in_quoted_strings_and_atoms() {
        let cmd = parse_command_line(r#"A1 LOGIN "a\é" "p\日s""#).expect("valid command");
        assert_eq!(cmd.tag, "A1");
        assert_eq!(cmd.name, "LOGIN");
        assert_eq!(
            cmd.args,
            vec![
                ImapArg::Quoted("aé".to_string()),
                ImapArg::Quoted("p日s".to_string()),
            ]
        );

        let atom_cmd =
            parse_command_line(r#"A2 FETCH 1 BODY.PEEK[HEADER.FIELDS ("a\é")]"#).expect("atom");
        assert_eq!(atom_cmd.name, "FETCH");
        assert_eq!(atom_cmd.args.len(), 2);
    }

    #[test]
    fn rejects_deeply_nested_imap_lists() {
        let deep = format!("A1 SEARCH {}", "(".repeat(3_000));
        let err = parse_command_line(&deep).expect_err("deep nesting must fail");
        assert!(matches!(err, AppError::BadRequest(_)));

        // Exactly MAX_IMAP_LIST_DEPTH (32) nested lists succeeds; 33 fails.
        let ok_line = format!("A1 SEARCH {}ALL{}", "(".repeat(32), ")".repeat(32));
        assert!(parse_command_line(&ok_line).is_ok());
        let too_deep = format!("A1 SEARCH {}ALL{}", "(".repeat(33), ")".repeat(33));
        assert!(matches!(
            parse_command_line(&too_deep),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn imap_wildcard_match_dp_avoids_exponential_backtracking() {
        // Pathological pattern that triggers O(2^n) backtracking in recursive matchers.
        let pattern = format!("{}b", "a*".repeat(40));
        let input = "a".repeat(80);
        assert!(!imap_wildcard_match(&pattern, &input, '/'));

        let match_pattern = format!("{}x", "*".repeat(30));
        let match_input = format!("{}x", "y".repeat(60));
        assert!(imap_wildcard_match(&match_pattern, &match_input, '/'));

        // Percent wildcard must not cross hierarchy delimiter.
        assert!(imap_wildcard_match("Work/%", "Work/Alpha", '/'));
        assert!(!imap_wildcard_match("Work/%", "Work/Alpha/Beta", '/'));
        assert!(imap_wildcard_match("Work/%/%", "Work/Alpha/Beta", '/'));
        assert!(imap_wildcard_match("inbox", "INBOX", '/'));
    }

    #[tokio::test]
    async fn read_command_with_limits_enforces_pre_auth_and_cumulative_caps() {
        use tokio::io::{AsyncWriteExt, BufReader};

        // 1. Pre-auth sync literal > 16 KiB returns LiteralTooLarge without "+ Ready".
        let (mut client, server) = tokio::io::duplex(4096);
        let mut reader = BufReader::new(server);
        client.write_all(b"A1 LOGIN {20000}\r\n").await.unwrap();
        let outcome =
            read_command_with_limits(&mut reader, ReadCommandLimits::pre_auth(40_000_000))
                .await
                .unwrap();
        assert!(matches!(
            outcome,
            ReadCommandOutcome::LiteralTooLarge {
                tag: Some(ref t),
                size: 20000
            } if t == "A1"
        ));

        // 2. Pre-auth LITERAL- > 4096 returns NonSyncLiteralTooLarge so caller sends [TOOBIG] + BYE.
        let (mut client, server) = tokio::io::duplex(4096);
        let mut reader = BufReader::new(server);
        client.write_all(b"A2 LOGIN {20000+}\r\n").await.unwrap();
        let outcome =
            read_command_with_limits(&mut reader, ReadCommandLimits::pre_auth(40_000_000))
                .await
                .expect("oversized LITERAL- should return structured outcome");
        assert!(matches!(
            outcome,
            ReadCommandOutcome::NonSyncLiteralTooLarge {
                tag: Some(ref t),
                size: 20000
            } if t == "A2"
        ));

        // 3. Cumulative command byte cap across multiple literals.
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut reader = BufReader::new(server);
        let limits = ReadCommandLimits {
            max_literal_bytes: 16 * 1024,
            max_non_sync_literal_bytes: LITERAL_MINUS_MAX_BYTES,
            max_literals: 16,
            max_command_bytes: 6 * 1024,
        };
        let writer = tokio::spawn(async move {
            client
                .write_all(
                    format!("A3 CMD {{4000+}}\r\n{} {{4000+}}\r\n", "x".repeat(4000)).as_bytes(),
                )
                .await
                .unwrap();
        });
        let outcome = read_command_with_limits(&mut reader, limits)
            .await
            .expect("cumulative cap should return NonSyncLiteralTooLarge");
        assert!(matches!(
            outcome,
            ReadCommandOutcome::NonSyncLiteralTooLarge {
                tag: Some(ref t),
                size: 4000
            } if t == "A3"
        ));
        let _ = writer.await;

        // 4. RFC 7888 LITERAL-: {4096+} succeeds, {4097+} returns NonSyncLiteralTooLarge.
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let mut reader = BufReader::new(server);
        let payload_4096 = "a".repeat(LITERAL_MINUS_MAX_BYTES);
        let writer = tokio::spawn(async move {
            client
                .write_all(format!("A4B CMD {{4096+}}\r\n{payload_4096}\r\n").as_bytes())
                .await
                .unwrap();
        });
        let ok_4096 =
            read_command_with_limits(&mut reader, ReadCommandLimits::authenticated(40_000_000))
                .await
                .expect("4096-byte LITERAL- must succeed");
        match ok_4096 {
            ReadCommandOutcome::Command(cmd) => {
                assert_eq!(cmd.tag, "A4B");
                assert_eq!(cmd.args[0].as_bytes().unwrap().len(), 4096);
            }
            other => panic!("expected Command, got {other:?}"),
        }
        let _ = writer.await;

        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let mut reader = BufReader::new(server);
        client.write_all(b"A4C CMD {4097+}\r\n").await.unwrap();
        let outcome =
            read_command_with_limits(&mut reader, ReadCommandLimits::authenticated(40_000_000))
                .await
                .expect("4097-byte LITERAL- should return structured NonSyncLiteralTooLarge");
        assert!(matches!(
            outcome,
            ReadCommandOutcome::NonSyncLiteralTooLarge {
                tag: Some(ref t),
                size: 4097
            } if t == "A4C"
        ));

        // 4. Max literal count cap (> 16 literals).
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut reader = BufReader::new(server);
        let mut payload = String::from("A4 CMD ");
        for _ in 0..17 {
            payload.push_str("{1+}\r\na ");
        }
        payload.push_str("\r\n");
        let writer = tokio::spawn(async move {
            client.write_all(payload.as_bytes()).await.unwrap();
        });
        let err = read_command_with_limits(&mut reader, ReadCommandLimits::pre_auth(40_000_000))
            .await
            .expect_err("excessive literal count must fail");
        assert!(matches!(err, AppError::PayloadTooLarge(_)));
        let _ = writer.await;
    }

    #[tokio::test]
    async fn read_crlf_line_into_is_cancel_safe() {
        use tokio::io::{AsyncWriteExt, BufReader};

        let (mut client, server) = tokio::io::duplex(256);
        let mut reader = BufReader::new(server);
        let mut buf = Vec::new();

        client.write_all(b"DO").await.unwrap();
        // Cancel mid-line after consuming "DO".
        let timed = tokio::time::timeout(
            std::time::Duration::from_millis(25),
            read_crlf_line_into(&mut reader, &mut buf, 1024),
        )
        .await;
        assert!(timed.is_err(), "partial line should time out cleanly");
        assert_eq!(buf, b"DO");

        client.write_all(b"NE\r\n").await.unwrap();
        let line = read_crlf_line_into(&mut reader, &mut buf, 1024)
            .await
            .unwrap();
        assert_eq!(line.as_deref(), Some("DONE"));
        assert!(buf.is_empty());
    }
}
