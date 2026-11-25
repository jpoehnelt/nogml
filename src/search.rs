//! Gmail-compatible search query parser and evaluator.
//!
//! Owned by the `mime-search` worker.

use crate::storage::StoredMessage;

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
    InMailbox(String),
    AfterEpochMs(i64),
    BeforeEpochMs(i64),
    LargerThanBytes(usize),
    SmallerThanBytes(usize),
    Not(Box<SearchTerm>),
    Or(Vec<SearchTerm>),
}

/// Parse a Gmail-style search query string (supporting `from:`, `to:`, `subject:`, `label:`,
/// `is:unread|read|starred`, `in:inbox|sent|trash|spam|draft|anywhere`, `has:attachment`,
/// `filename:`, `after:`, `before:`, `older_than:`, `newer_than:`, `larger:`, `smaller:`,
/// quoted phrases, `-negation`, and `OR`).
pub fn parse_query(_q: &str) -> SearchQuery {
    todo!("mime-search worker: parse Gmail search query")
}

/// Evaluate a parsed [`SearchQuery`] against a [`StoredMessage`].
pub fn matches_message(_query: &SearchQuery, _msg: &StoredMessage) -> bool {
    todo!("mime-search worker: evaluate search query against StoredMessage")
}
