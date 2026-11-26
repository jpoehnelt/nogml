//! Gmail-compatible search query parser and evaluator.
//!
//! Owned by the `mime-search` worker.

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use mail_parser::MessageParser;

use crate::{
    error::{AppError, AppResult},
    mime::normalize_message_id,
    models::{
        LABEL_DRAFT, LABEL_IMPORTANT, LABEL_INBOX, LABEL_SENT, LABEL_SNOOZED, LABEL_SPAM,
        LABEL_STARRED, LABEL_TRASH, LABEL_UNREAD,
    },
    storage::StoredMessage,
};

/// Maximum nesting depth allowed for grouped or negated search expressions (`(`, `{`, `-`).
pub const MAX_SEARCH_QUERY_DEPTH: usize = 32;
/// Maximum AST nodes allowed in a single parsed search query.
pub const MAX_SEARCH_QUERY_NODES: usize = 512;

/// Parsed representation of a Gmail search query (`q=...`).
#[derive(Debug, Clone, Default)]
pub struct SearchQuery {
    pub raw: String,
    pub include_spam_trash: bool,
    pub terms: Vec<SearchTerm>,
}

/// Individual search expression node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchTerm {
    Text(String),
    From(String),
    To(String),
    Cc(String),
    Bcc(String),
    Subject(String),
    Label(String),
    HasAttachment,
    Filename(String),
    IsUnread,
    IsRead,
    IsStarred,
    IsImportant,
    IsDraft,
    InMailbox(String),
    AfterEpochMs(i64),
    BeforeEpochMs(i64),
    LargerThanBytes(usize),
    SmallerThanBytes(usize),
    Rfc822MsgId(String),
    Not(Box<SearchTerm>),
    And(Vec<SearchTerm>),
    Or(Vec<SearchTerm>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    LParen,
    RParen,
    LBrace,
    RBrace,
    Minus,
    Or,
    Word { key: Option<String>, value: String },
}

fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // Skip whitespace.
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }

        match chars[i] {
            '(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            '{' => {
                tokens.push(Token::LBrace);
                i += 1;
            }
            '}' => {
                tokens.push(Token::RBrace);
                i += 1;
            }
            '-' if i + 1 < len && !chars[i + 1].is_whitespace() => {
                tokens.push(Token::Minus);
                i += 1;
            }
            '"' => {
                let phrase = read_quoted(&chars, &mut i);
                if !phrase.is_empty() {
                    tokens.push(Token::Word {
                        key: None,
                        value: phrase,
                    });
                }
            }
            _ => {
                let start = i;
                // Read until whitespace, delimiter, or ':' (which might start a quoted value).
                let mut colon_pos: Option<usize> = None;
                let mut emitted = false;
                while i < len
                    && !chars[i].is_whitespace()
                    && !matches!(chars[i], '(' | ')' | '{' | '}')
                {
                    if chars[i] == ':' && colon_pos.is_none() {
                        colon_pos = Some(i);
                        i += 1;
                        // If the operator value starts with a quote (e.g. `subject:"foo bar"`), read it.
                        if i < len && chars[i] == '"' {
                            let key: String = chars[start..colon_pos.unwrap()].iter().collect();
                            let value = read_quoted(&chars, &mut i);
                            tokens.push(Token::Word {
                                key: Some(key),
                                value,
                            });
                            emitted = true;
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }

                if emitted {
                    continue;
                }

                let raw_word: String = chars[start..i].iter().collect();
                if raw_word.is_empty() {
                    continue;
                }

                if let Some(cpos) = colon_pos {
                    let key: String = chars[start..cpos].iter().collect();
                    let val: String = chars[cpos + 1..i].iter().collect();
                    if !key.is_empty() && !val.is_empty() {
                        tokens.push(Token::Word {
                            key: Some(key),
                            value: val,
                        });
                    } else {
                        tokens.push(Token::Word {
                            key: None,
                            value: raw_word,
                        });
                    }
                } else if raw_word == "OR" {
                    tokens.push(Token::Or);
                } else {
                    tokens.push(Token::Word {
                        key: None,
                        value: raw_word,
                    });
                }
            }
        }
    }

    tokens
}

fn read_quoted(chars: &[char], i: &mut usize) -> String {
    debug_assert_eq!(chars[*i], '"');
    *i += 1; // consume opening quote
    let mut out = String::new();
    while *i < chars.len() {
        let ch = chars[*i];
        *i += 1;
        if ch == '\\' && *i < chars.len() && matches!(chars[*i], '"' | '\\') {
            out.push(chars[*i]);
            *i += 1;
        } else if ch == '"' {
            break;
        } else {
            out.push(ch);
        }
    }
    out
}

struct QueryParser {
    tokens: Vec<Token>,
    pos: usize,
    now_ms: i64,
    include_spam_trash: bool,
    node_count: usize,
}

impl QueryParser {
    fn new(tokens: Vec<Token>, now_ms: i64) -> Self {
        Self {
            tokens,
            pos: 0,
            now_ms,
            include_spam_trash: false,
            node_count: 0,
        }
    }

    fn bump_nodes(&mut self) -> AppResult<()> {
        self.node_count += 1;
        if self.node_count > MAX_SEARCH_QUERY_NODES {
            return Err(AppError::BadRequest(format!(
                "Search query exceeds maximum expression limit of {MAX_SEARCH_QUERY_NODES} nodes"
            )));
        }
        Ok(())
    }

    fn check_depth(depth: usize) -> AppResult<()> {
        if depth > MAX_SEARCH_QUERY_DEPTH {
            return Err(AppError::BadRequest(format!(
                "Search query exceeds maximum nesting depth of {MAX_SEARCH_QUERY_DEPTH}"
            )));
        }
        Ok(())
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<Token> {
        if self.pos < self.tokens.len() {
            let tok = self.tokens[self.pos].clone();
            self.pos += 1;
            Some(tok)
        } else {
            None
        }
    }

    fn parse_sequence(
        &mut self,
        stop_at: Option<&Token>,
        negated: bool,
        depth: usize,
    ) -> AppResult<Vec<SearchTerm>> {
        Self::check_depth(depth)?;
        let mut terms = Vec::new();
        while let Some(tok) = self.peek() {
            if stop_at == Some(tok) {
                break;
            }
            // Skip stray closing brackets or leading OR at top level.
            if matches!(tok, Token::RParen | Token::RBrace) {
                self.advance();
                continue;
            }
            if let Some(term) = self.parse_or_expr(negated, depth)? {
                terms.push(term);
            }
        }
        Ok(terms)
    }

    fn parse_or_expr(&mut self, negated: bool, depth: usize) -> AppResult<Option<SearchTerm>> {
        let Some(first) = self.parse_unary(negated, depth)? else {
            return Ok(None);
        };
        if self.peek() != Some(&Token::Or) {
            return Ok(Some(first));
        }

        let mut branches = vec![first];
        while self.peek() == Some(&Token::Or) {
            self.advance(); // consume OR
            if let Some(next_term) = self.parse_unary(negated, depth)? {
                branches.push(next_term);
            } else {
                break;
            }
        }

        if branches.len() == 1 {
            Ok(branches.pop())
        } else {
            self.bump_nodes()?;
            Ok(Some(SearchTerm::Or(branches)))
        }
    }

    fn parse_unary(&mut self, negated: bool, depth: usize) -> AppResult<Option<SearchTerm>> {
        if self.peek() == Some(&Token::Minus) {
            Self::check_depth(depth + 1)?;
            self.advance();
            let Some(inner) = self.parse_unary(!negated, depth + 1)? else {
                return Ok(None);
            };
            self.bump_nodes()?;
            return Ok(Some(SearchTerm::Not(Box::new(inner))));
        }
        self.parse_primary(negated, depth)
    }

    fn parse_primary(&mut self, negated: bool, depth: usize) -> AppResult<Option<SearchTerm>> {
        let Some(tok) = self.advance() else {
            return Ok(None);
        };
        match tok {
            Token::LParen => {
                Self::check_depth(depth + 1)?;
                self.bump_nodes()?;
                let mut inner = self.parse_sequence(Some(&Token::RParen), negated, depth + 1)?;
                if self.peek() == Some(&Token::RParen) {
                    self.advance();
                }
                match inner.len() {
                    0 => Ok(None),
                    1 => Ok(inner.pop()),
                    _ => {
                        self.bump_nodes()?;
                        Ok(Some(SearchTerm::And(inner)))
                    }
                }
            }
            Token::LBrace => {
                Self::check_depth(depth + 1)?;
                self.bump_nodes()?;
                let mut branches = Vec::new();
                while let Some(next_tok) = self.peek() {
                    if next_tok == &Token::RBrace {
                        self.advance();
                        break;
                    }
                    if next_tok == &Token::Or {
                        self.advance();
                        continue;
                    }
                    if let Some(term) = self.parse_unary(negated, depth + 1)? {
                        branches.push(term);
                    } else {
                        break;
                    }
                }
                match branches.len() {
                    0 => Ok(None),
                    1 => Ok(branches.pop()),
                    _ => {
                        self.bump_nodes()?;
                        Ok(Some(SearchTerm::Or(branches)))
                    }
                }
            }
            Token::Or => {
                self.bump_nodes()?;
                Ok(Some(SearchTerm::Text("OR".to_string())))
            }
            Token::Minus => Ok(None),
            Token::RParen | Token::RBrace => Ok(None),
            Token::Word { key, value } => {
                self.bump_nodes()?;
                Ok(Some(self.build_word_term(key, value, negated)))
            }
        }
    }

    fn build_word_term(&mut self, key: Option<String>, value: String, negated: bool) -> SearchTerm {
        let Some(k) = key else {
            return SearchTerm::Text(value);
        };

        let lower_key = k.to_ascii_lowercase();
        match lower_key.as_str() {
            "from" => SearchTerm::From(value),
            "to" => SearchTerm::To(value),
            "cc" => SearchTerm::Cc(value),
            "bcc" => SearchTerm::Bcc(value),
            "subject" => SearchTerm::Subject(value),
            "label" | "l" => {
                let lower_val = value.to_ascii_lowercase();
                if !negated && matches!(lower_val.as_str(), "trash" | "spam") {
                    self.include_spam_trash = true;
                }
                SearchTerm::Label(value)
            }
            "in" => {
                let lower_val = value.to_ascii_lowercase();
                if !negated && matches!(lower_val.as_str(), "anywhere" | "trash" | "spam") {
                    self.include_spam_trash = true;
                }
                SearchTerm::InMailbox(lower_val)
            }
            "is" => match value.to_ascii_lowercase().as_str() {
                "unread" => SearchTerm::IsUnread,
                "read" => SearchTerm::IsRead,
                "starred" => SearchTerm::IsStarred,
                "important" => SearchTerm::IsImportant,
                "draft" | "drafts" => SearchTerm::IsDraft,
                other => SearchTerm::Label(other.to_string()),
            },
            "has" => match value.to_ascii_lowercase().as_str() {
                "attachment" | "attachments" => SearchTerm::HasAttachment,
                "star" | "starred" => SearchTerm::IsStarred,
                _ => SearchTerm::Text(format!("{k}:{value}")),
            },
            "filename" => SearchTerm::Filename(value),
            "after" => match parse_date_epoch_ms(&value) {
                Some(ms) => SearchTerm::AfterEpochMs(ms),
                None => SearchTerm::Text(format!("{k}:{value}")),
            },
            "before" => match parse_date_epoch_ms(&value) {
                Some(ms) => SearchTerm::BeforeEpochMs(ms),
                None => SearchTerm::Text(format!("{k}:{value}")),
            },
            "older_than" => match parse_relative_duration_ms(&value) {
                Some(delta_ms) => SearchTerm::BeforeEpochMs(self.now_ms.saturating_sub(delta_ms)),
                None => SearchTerm::Text(format!("{k}:{value}")),
            },
            "newer_than" => match parse_relative_duration_ms(&value) {
                Some(delta_ms) => SearchTerm::AfterEpochMs(self.now_ms.saturating_sub(delta_ms)),
                None => SearchTerm::Text(format!("{k}:{value}")),
            },
            "larger" | "size" => match parse_size_bytes(&value) {
                Some(bytes) => SearchTerm::LargerThanBytes(bytes),
                None => SearchTerm::Text(format!("{k}:{value}")),
            },
            "smaller" => match parse_size_bytes(&value) {
                Some(bytes) => SearchTerm::SmallerThanBytes(bytes),
                None => SearchTerm::Text(format!("{k}:{value}")),
            },
            "rfc822msgid" => SearchTerm::Rfc822MsgId(value),
            _ => SearchTerm::Text(format!("{k}:{value}")),
        }
    }
}

fn parse_date_epoch_ms(raw: &str) -> Option<i64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Numeric epoch seconds or milliseconds.
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        let num = trimmed.parse::<i64>().ok()?;
        return if num >= 100_000_000_000 {
            Some(num)
        } else {
            Some(num.saturating_mul(1000))
        };
    }

    // RFC 3339 timestamp.
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.timestamp_millis());
    }

    // Gmail `YYYY/MM/DD` or ISO `YYYY-MM-DD`.
    let normalized = trimmed.replace('/', "-");
    let parts: Vec<&str> = normalized.split('-').collect();
    if parts.len() == 3 {
        let year = parts[0].parse::<i32>().ok()?;
        let month = parts[1].parse::<u32>().ok()?;
        let day = parts[2].parse::<u32>().ok()?;
        let date = NaiveDate::from_ymd_opt(year, month, day)?;
        let dt = Utc.from_utc_datetime(&date.and_hms_opt(0, 0, 0)?);
        return Some(dt.timestamp_millis());
    }

    None
}

fn parse_relative_duration_ms(raw: &str) -> Option<i64> {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.len() < 2 {
        return None;
    }
    let unit = trimmed.chars().last()?;
    let count_str = &trimmed[..trimmed.len() - unit.len_utf8()];
    let count = count_str.parse::<i64>().ok()?;
    if count < 0 {
        return None;
    }

    const HOUR_MS: i64 = 3_600_000;
    const DAY_MS: i64 = 86_400_000;

    let multiplier = match unit {
        'h' => HOUR_MS,
        'd' => DAY_MS,
        'w' => 7 * DAY_MS,
        'm' => 30 * DAY_MS,
        'y' => 365 * DAY_MS,
        _ => return None,
    };

    Some(count.saturating_mul(multiplier))
}

fn parse_size_bytes(raw: &str) -> Option<usize> {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return None;
    }

    let split_idx = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let num_str = &trimmed[..split_idx];
    let suffix = &trimmed[split_idx..];

    let num = num_str.parse::<usize>().ok()?;
    let multiplier = match suffix {
        "" | "b" => 1,
        "k" | "kb" => 1024,
        "m" | "mb" => 1024 * 1024,
        "g" | "gb" => 1024 * 1024 * 1024,
        _ => return None,
    };

    num.checked_mul(multiplier)
}

/// Parse a Gmail-style search query string, rejecting queries that exceed
/// [`MAX_SEARCH_QUERY_DEPTH`] or [`MAX_SEARCH_QUERY_NODES`] with [`AppError::BadRequest`].
pub fn try_parse_query(q: &str) -> AppResult<SearchQuery> {
    try_parse_query_at(q, Utc::now().timestamp_millis())
}

/// Parse a Gmail-style search query string (supporting `from:`, `to:`, `cc:`, `bcc:`,
/// `subject:`, `label:`/`l:`, `is:unread|read|starred|important|draft`,
/// `in:inbox|sent|trash|spam|draft|drafts|anywhere`, `has:attachment`, `filename:`,
/// `after:`, `before:`, `older_than:`, `newer_than:`, `larger:`, `smaller:`,
/// `rfc822msgid:`, quoted phrases, `-negation`, `OR`, `{...}`, and `(...)`).
///
/// Queries that exceed [`MAX_SEARCH_QUERY_DEPTH`] or [`MAX_SEARCH_QUERY_NODES`] return
/// an empty [`SearchQuery`] safely without overflowing the stack; prefer [`try_parse_query`]
/// on request boundaries to return `400 Bad Request`.
pub fn parse_query(q: &str) -> SearchQuery {
    parse_query_at(q, Utc::now().timestamp_millis())
}

/// Deterministic helper allowing tests to pin "now" for `older_than:` / `newer_than:`.
fn try_parse_query_at(q: &str, now_ms: i64) -> AppResult<SearchQuery> {
    let tokens = tokenize(q);
    let mut parser = QueryParser::new(tokens, now_ms);
    let terms = parser.parse_sequence(None, false, 0)?;
    Ok(SearchQuery {
        raw: q.to_string(),
        include_spam_trash: parser.include_spam_trash,
        terms,
    })
}

fn parse_query_at(q: &str, now_ms: i64) -> SearchQuery {
    try_parse_query_at(q, now_ms).unwrap_or_else(|_| SearchQuery {
        raw: q.to_string(),
        include_spam_trash: false,
        terms: Vec::new(),
    })
}

/// Evaluate a parsed [`SearchQuery`] against a [`StoredMessage`].
pub fn matches_message(query: &SearchQuery, msg: &StoredMessage) -> bool {
    query.terms.iter().all(|term| eval_term(term, msg))
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

fn has_label_exact(msg: &StoredMessage, expected: &str) -> bool {
    msg.label_ids
        .iter()
        .any(|label| label.eq_ignore_ascii_case(expected))
}

fn matches_label_name(msg: &StoredMessage, wanted: &str) -> bool {
    let normalized = match wanted.to_ascii_lowercase().as_str() {
        "inbox" => LABEL_INBOX,
        "sent" => LABEL_SENT,
        "draft" | "drafts" => LABEL_DRAFT,
        "trash" => LABEL_TRASH,
        "spam" => LABEL_SPAM,
        "unread" => LABEL_UNREAD,
        "starred" => LABEL_STARRED,
        "important" => LABEL_IMPORTANT,
        "snoozed" => LABEL_SNOOZED,
        _ => wanted,
    };

    let wanted_hyphen = normalized.replace('/', "-");
    msg.label_ids.iter().any(|label| {
        label.eq_ignore_ascii_case(normalized)
            || label.replace('/', "-").eq_ignore_ascii_case(&wanted_hyphen)
    })
}

fn matches_filename(msg: &StoredMessage, pattern: &str) -> bool {
    if msg.raw_rfc2822.is_empty() {
        return false;
    }
    let Some(parsed) = MessageParser::new().parse(&msg.raw_rfc2822) else {
        return false;
    };

    for part in parsed.parts() {
        if let Some(name) = part.attachment_name()
            && contains_ci(name, pattern)
        {
            return true;
        }
    }
    false
}

fn eval_term(term: &SearchTerm, msg: &StoredMessage) -> bool {
    match term {
        SearchTerm::Text(needle) => {
            contains_ci(&msg.subject, needle)
                || contains_ci(&msg.from_addr, needle)
                || msg.to_addrs.iter().any(|a| contains_ci(a, needle))
                || msg.cc_addrs.iter().any(|a| contains_ci(a, needle))
                || msg.bcc_addrs.iter().any(|a| contains_ci(a, needle))
                || contains_ci(&msg.text_body, needle)
                || contains_ci(&msg.snippet, needle)
        }
        SearchTerm::From(needle) => contains_ci(&msg.from_addr, needle),
        SearchTerm::To(needle) => msg.to_addrs.iter().any(|a| contains_ci(a, needle)),
        SearchTerm::Cc(needle) => msg.cc_addrs.iter().any(|a| contains_ci(a, needle)),
        SearchTerm::Bcc(needle) => msg.bcc_addrs.iter().any(|a| contains_ci(a, needle)),
        SearchTerm::Subject(needle) => contains_ci(&msg.subject, needle),
        SearchTerm::Label(label) => matches_label_name(msg, label),
        SearchTerm::HasAttachment => msg.has_attachments,
        SearchTerm::Filename(pattern) => matches_filename(msg, pattern),
        SearchTerm::IsUnread => has_label_exact(msg, LABEL_UNREAD),
        SearchTerm::IsRead => !has_label_exact(msg, LABEL_UNREAD),
        SearchTerm::IsStarred => has_label_exact(msg, LABEL_STARRED),
        SearchTerm::IsImportant => has_label_exact(msg, LABEL_IMPORTANT),
        SearchTerm::IsDraft => has_label_exact(msg, LABEL_DRAFT),
        SearchTerm::InMailbox(mailbox) => match mailbox.as_str() {
            "anywhere" => true,
            "inbox" => has_label_exact(msg, LABEL_INBOX),
            "sent" => has_label_exact(msg, LABEL_SENT),
            "draft" | "drafts" => has_label_exact(msg, LABEL_DRAFT),
            "trash" => has_label_exact(msg, LABEL_TRASH),
            "spam" => has_label_exact(msg, LABEL_SPAM),
            "starred" => has_label_exact(msg, LABEL_STARRED),
            "important" => has_label_exact(msg, LABEL_IMPORTANT),
            "snoozed" => has_label_exact(msg, LABEL_SNOOZED),
            "unread" => has_label_exact(msg, LABEL_UNREAD),
            "read" => !has_label_exact(msg, LABEL_UNREAD),
            other => matches_label_name(msg, other),
        },
        SearchTerm::AfterEpochMs(ms) => msg.internal_date_ms >= *ms,
        SearchTerm::BeforeEpochMs(ms) => msg.internal_date_ms < *ms,
        SearchTerm::LargerThanBytes(bytes) => {
            usize::try_from(msg.size_estimate).unwrap_or(0) > *bytes
        }
        SearchTerm::SmallerThanBytes(bytes) => {
            usize::try_from(msg.size_estimate).unwrap_or(0) < *bytes
        }
        SearchTerm::Rfc822MsgId(wanted) => {
            let Some(ref actual) = msg.rfc822_message_id else {
                return false;
            };
            match (normalize_message_id(wanted), normalize_message_id(actual)) {
                (Some(w), Some(a)) => w == a,
                _ => actual.eq_ignore_ascii_case(wanted.trim()),
            }
        }
        SearchTerm::Not(inner) => !eval_term(inner, msg),
        SearchTerm::And(terms) => terms.iter().all(|t| eval_term(t, msg)),
        SearchTerm::Or(terms) => terms.iter().any(|t| eval_term(t, msg)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        mime::{ComposeEmailInput, build_rfc2822},
        storage::NewAttachmentInput,
    };

    fn sample_message() -> StoredMessage {
        let raw = build_rfc2822(&ComposeEmailInput {
            from: "Alice <alice@example.com>".to_string(),
            to: vec!["Bob <bob@example.com>".to_string()],
            cc: vec!["carol@example.com".to_string()],
            bcc: vec!["secret@example.com".to_string()],
            subject: "Quarterly Budget Review".to_string(),
            text: Some("Please review the attached Q4 budget spreadsheet.".to_string()),
            message_id: Some("<Budget-2026@Example.COM>".to_string()),
            attachments: vec![NewAttachmentInput {
                part_id: "1".to_string(),
                filename: Some("Q4_Budget_Report.pdf".to_string()),
                content_type: "application/pdf".to_string(),
                content_id: None,
                data: b"%PDF-1.4\nhello".to_vec(),
            }],
            ..Default::default()
        })
        .unwrap();

        StoredMessage {
            id: "msg1".to_string(),
            thread_id: "thr1".to_string(),
            label_ids: vec![
                LABEL_INBOX.to_string(),
                LABEL_UNREAD.to_string(),
                LABEL_STARRED.to_string(),
                LABEL_IMPORTANT.to_string(),
                "Work/Finance".to_string(),
            ],
            raw_rfc2822: raw,
            snippet: "Please review the attached Q4 budget spreadsheet.".to_string(),
            history_id: 10,
            // 2026-06-15T12:00:00Z
            internal_date_ms: 1_781_524_800_000,
            size_estimate: 50_000,
            subject: "Quarterly Budget Review".to_string(),
            from_addr: "Alice <alice@example.com>".to_string(),
            to_addrs: vec!["Bob <bob@example.com>".to_string()],
            cc_addrs: vec!["carol@example.com".to_string()],
            bcc_addrs: vec!["secret@example.com".to_string()],
            text_body: "Please review the attached Q4 budget spreadsheet.".to_string(),
            html_body: None,
            has_attachments: true,
            rfc822_message_id: Some("<budget-2026@example.com>".to_string()),
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            delivery_status: None,
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "local".to_string(),
            all_mail_uid: 1,
            is_answered: false,
            is_deleted: false,
        }
    }

    #[test]
    fn addresses_subject_and_quoted_phrases() {
        let msg = sample_message();
        assert!(matches_message(
            &parse_query("from:alice@example.com"),
            &msg
        ));
        assert!(matches_message(&parse_query("to:bob"), &msg));
        assert!(matches_message(&parse_query("cc:carol"), &msg));
        assert!(matches_message(&parse_query("bcc:secret"), &msg));
        assert!(matches_message(
            &parse_query(r#"subject:"Quarterly Budget""#),
            &msg
        ));
        assert!(!matches_message(
            &parse_query(r#"subject:"Annual Plan""#),
            &msg
        ));
        assert!(matches_message(
            &parse_query(r#""attached Q4 budget""#),
            &msg
        ));
        assert!(!matches_message(&parse_query(r#""missing phrase""#), &msg));
    }

    #[test]
    fn labels_in_is_and_include_spam_trash_flags() {
        let msg = sample_message();
        assert!(matches_message(
            &parse_query("in:inbox is:unread is:starred is:important"),
            &msg
        ));
        assert!(!matches_message(&parse_query("is:read"), &msg));
        assert!(!matches_message(&parse_query("is:draft"), &msg));
        assert!(matches_message(&parse_query("label:Work/Finance"), &msg));
        assert!(matches_message(&parse_query("l:work-finance"), &msg));
        assert!(matches_message(&parse_query("in:anywhere"), &msg));

        assert!(!parse_query("in:inbox").include_spam_trash);
        assert!(parse_query("in:anywhere").include_spam_trash);
        assert!(parse_query("in:trash").include_spam_trash);
        assert!(parse_query("in:spam").include_spam_trash);
        assert!(parse_query("label:spam").include_spam_trash);
        assert!(!parse_query("-in:trash").include_spam_trash);
    }

    #[test]
    fn attachments_filename_size_and_rfc822msgid() {
        let msg = sample_message();
        assert!(matches_message(&parse_query("has:attachment"), &msg));
        assert!(matches_message(&parse_query("filename:pdf"), &msg));
        assert!(matches_message(
            &parse_query("filename:Q4_Budget_Report.pdf"),
            &msg
        ));
        assert!(!matches_message(&parse_query("filename:xlsx"), &msg));

        assert!(matches_message(&parse_query("larger:10k smaller:1m"), &msg));
        assert!(!matches_message(&parse_query("larger:100k"), &msg));
        assert!(!matches_message(&parse_query("smaller:10k"), &msg));

        assert!(matches_message(
            &parse_query("rfc822msgid:BUDGET-2026@example.com"),
            &msg
        ));
        assert!(matches_message(
            &parse_query("rfc822msgid:<budget-2026@example.com>"),
            &msg
        ));
        assert!(!matches_message(
            &parse_query("rfc822msgid:<other@example.com>"),
            &msg
        ));
    }

    #[test]
    fn dates_and_relative_time_filters() {
        let msg = sample_message(); // 2026-06-15T12:00:00Z
        assert!(matches_message(
            &parse_query("after:2026/06/01 before:2026/07/01"),
            &msg
        ));
        assert!(matches_message(
            &parse_query("after:2026-06-15 before:2026-06-16"),
            &msg
        ));
        assert!(!matches_message(&parse_query("after:2026/06/16"), &msg));
        assert!(!matches_message(&parse_query("before:2026/06/15"), &msg));

        // Pin "now" to 2026-06-20T12:00:00Z (5 days after msg).
        let now_ms = msg.internal_date_ms + 5 * 86_400_000;
        assert!(matches_message(
            &parse_query_at("older_than:3d", now_ms),
            &msg
        ));
        assert!(!matches_message(
            &parse_query_at("older_than:10d", now_ms),
            &msg
        ));
        assert!(matches_message(
            &parse_query_at("newer_than:10d", now_ms),
            &msg
        ));
        assert!(!matches_message(
            &parse_query_at("newer_than:2d", now_ms),
            &msg
        ));
    }

    #[test]
    fn boolean_negation_or_and_brace_groups() {
        let msg = sample_message();
        assert!(matches_message(&parse_query("-from:eve@example.com"), &msg));
        assert!(!matches_message(
            &parse_query("-from:alice@example.com"),
            &msg
        ));
        assert!(matches_message(
            &parse_query("from:eve@example.com OR from:alice@example.com"),
            &msg
        ));
        assert!(matches_message(
            &parse_query("{from:eve from:alice} is:unread"),
            &msg
        ));
        assert!(!matches_message(
            &parse_query("{from:eve from:mallory} is:unread"),
            &msg
        ));
        assert!(matches_message(
            &parse_query("-(from:eve OR from:mallory) subject:budget"),
            &msg
        ));
        assert!(!matches_message(
            &parse_query("-(from:alice OR from:mallory)"),
            &msg
        ));
    }

    #[test]
    fn free_text_case_sensitive_or_and_malformed_queries_never_panic() {
        let mut msg = sample_message();
        assert!(matches_message(&parse_query(""), &msg));
        assert!(matches_message(&parse_query("spreadsheet"), &msg));
        assert!(!matches_message(&parse_query("nonexistentword"), &msg));

        // Lowercase "or" is a literal word, not boolean OR.
        msg.text_body = "yes or no".to_string();
        assert!(matches_message(&parse_query("yes or no"), &msg));
        assert!(!matches_message(&parse_query("nonexistent or yes"), &msg));

        // Sent/draft/trash/spam mailboxes.
        msg.label_ids = vec![LABEL_SENT.to_string(), LABEL_DRAFT.to_string()];
        assert!(matches_message(
            &parse_query("in:sent is:draft in:drafts"),
            &msg
        ));
        msg.label_ids = vec![LABEL_TRASH.to_string()];
        assert!(matches_message(&parse_query("in:trash"), &msg));
        msg.label_ids = vec![LABEL_SPAM.to_string()];
        assert!(matches_message(&parse_query("in:spam"), &msg));

        // Epoch seconds & months/years relative filters.
        assert!(matches_message(
            &parse_query("after:1781500000 before:1781600000"),
            &msg
        ));
        let one_year_later = msg.internal_date_ms + 366 * 86_400_000;
        assert!(matches_message(
            &parse_query_at("older_than:1y", one_year_later),
            &msg
        ));
        assert!(matches_message(
            &parse_query_at("older_than:2m", one_year_later),
            &msg
        ));

        // Malformed inputs must parse gracefully without panicking.
        for weird in [
            "OR",
            "OR foo",
            "foo OR",
            "(unclosed",
            "((a)",
            "{a b",
            "foo:",
            r#"subject:"unclosed"#,
        ] {
            let parsed = parse_query(weird);
            let _ = matches_message(&parsed, &msg);
        }
    }

    #[test]
    fn multibyte_utf8_before_colon_never_panics() {
        let mut msg = sample_message();
        msg.text_body = "Meet at café:10am with é:a".to_string();

        for q in ["é:a", "café:10am", "日本語:値", "café:\"10am sharp\""] {
            let parsed = try_parse_query(q).expect("valid utf8 query");
            let _ = matches_message(&parsed, &msg);
        }
        assert!(matches_message(
            &try_parse_query("café:10am").unwrap(),
            &msg
        ));
        assert!(matches_message(&try_parse_query("é:a").unwrap(), &msg));
    }

    #[test]
    fn deeply_nested_and_oversized_queries_return_bad_request_without_stack_overflow() {
        let msg = sample_message();

        for pathological in [
            format!("{}a{}", "(".repeat(3_000), ")".repeat(3_000)),
            format!("{}a{}", "{".repeat(3_000), "}".repeat(3_000)),
            format!("{}a", "-".repeat(3_000)),
            (0..600)
                .map(|i| format!("word{i}"))
                .collect::<Vec<_>>()
                .join(" OR "),
        ] {
            let err = try_parse_query(&pathological).unwrap_err();
            assert!(
                matches!(err, AppError::BadRequest(_)),
                "expected BadRequest, got {err:?}"
            );

            // Infallible parse_query must also terminate safely without overflowing the stack.
            let fallback = parse_query(&pathological);
            let _ = matches_message(&fallback, &msg);
        }
    }
}
