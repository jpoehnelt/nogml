//! Upstream Gmail IMAP [`SyncSource`] (`SyncMode::Imap`) using `async-imap` over `tokio-rustls`
//! (or plain TCP when `gmail_imap_tls == false`), with `X-GM-EXT-1` bidirectional label pushback,
//! IMAP `APPEND` + `APPENDUID` for locally created Sent/Draft messages, `CONDSTORE`/`QRESYNC`
//! incremental flag/label/deletion updates (plus bounded fallback for non-`CONDSTORE` servers),
//! `AUTHENTICATE XOAUTH2` (with `LOGIN` fallback), multi-folder checkpoints, and optional
//! background `IDLE` wakeup.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use async_imap::{
    Authenticator, Session,
    extensions::idle::IdleResponse,
    imap_proto::{
        AttributeValue, Capability as ImapCapability, MailboxDatum, Response as ImapResponse,
        ResponseCode, Status as ImapStatus, rfc4315::UidSetMember,
    },
};
use async_trait::async_trait;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use futures_util::TryStreamExt;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    sync::watch,
};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use crate::{
    AppState,
    config::Config,
    ensure_crypto_provider,
    error::{AppError, AppResult},
    imap::mime_fmt::parse_raw_to_new_message_input,
    models::{
        LABEL_DRAFT, LABEL_IMPORTANT, LABEL_INBOX, LABEL_SENT, LABEL_SPAM, LABEL_STARRED,
        LABEL_TRASH, LABEL_UNREAD, is_system_label,
    },
    storage::{ImapFolderSyncState, NewLabelInput, StoredMessage, SyncState},
    sync::{
        LocalMutation, LocalMutationKind, PullReport, PushReport, SyncRunOptions, SyncSource,
        gmail_api::{acquire_access_token, invalidate_access_token},
        ingest_synced_message, run_gmail_sync,
    },
};

/// Default TCP + TLS connect timeout for upstream IMAP sync.
pub const IMAP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default per-command timeout for upstream IMAP sync operations.
pub const IMAP_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum number of UIDs fetched per `UID FETCH` full-body batch to bound peak memory usage.
pub const IMAP_FETCH_BATCH_SIZE: usize = 25;

/// Maximum number of UIDs fetched per metadata-only (`FLAGS`/`X-GM-LABELS`) reconciliation batch.
pub const IMAP_METADATA_BATCH_SIZE: usize = 100;

/// Maximum number of existing UIDs reconciled per pull on servers without `CONDSTORE`.
pub const IMAP_RECONCILE_MAX_UIDS: usize = 500;

/// Maximum number of `uid -> local_message_id` entries retained per folder checkpoint.
pub const IMAP_UID_MAP_MAX_ENTRIES: usize = 10_000;

/// Maximum number of expanded UIDs accepted from a single `VANISHED` response (guards against
/// malformed/adversarial ranges like `1:4294967295`).
pub const IMAP_VANISHED_MAX_EXPAND: usize = 50_000;

/// Keepalive re-IDLE interval (RFC 2177 recommends <= 29 min; we use 24 min).
pub const IMAP_IDLE_KEEPALIVE: Duration = Duration::from_secs(24 * 60);

/// Initial reconnect backoff for the background IMAP `IDLE` listener.
pub const IMAP_IDLE_BACKOFF_INITIAL: Duration = Duration::from_secs(1);

/// Maximum reconnect backoff for the background IMAP `IDLE` listener.
pub const IMAP_IDLE_BACKOFF_MAX: Duration = Duration::from_secs(60);

enum UpstreamImapStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl fmt::Debug for UpstreamImapStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(_) => f.write_str("UpstreamImapStream::Plain"),
            Self::Tls(_) => f.write_str("UpstreamImapStream::Tls"),
        }
    }
}

impl AsyncRead for UpstreamImapStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamImapStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

#[derive(Debug, Default)]
struct FetchedImapMessage {
    uid: Option<u32>,
    modseq: Option<u64>,
    raw_bytes: Vec<u8>,
    internal_date_ms: Option<i64>,
    is_seen: bool,
    is_flagged: bool,
    is_draft: bool,
    is_answered: bool,
    is_deleted: bool,
    gmail_labels: Option<Vec<String>>,
    gmail_msg_id: Option<u64>,
    gmail_thr_id: Option<u64>,
}

#[derive(Debug, Default)]
struct UidFetchBatchResult {
    messages: Vec<FetchedImapMessage>,
    vanished_uids: Vec<u32>,
}

#[derive(Debug, Clone, Copy, Default)]
struct ImapServerCaps {
    has_xgm: bool,
    has_move: bool,
    has_uidplus: bool,
    has_condstore: bool,
    has_qresync: bool,
    has_enable: bool,
    has_utf8_accept: bool,
    has_idle: bool,
}

/// Build the raw Google SASL `XOAUTH2` payload:
/// `user=<username>\x01auth=Bearer <access_token>\x01\x01`.
pub fn build_xoauth2_sasl_payload(user: &str, access_token: &str) -> Vec<u8> {
    format!("user={user}\x01auth=Bearer {access_token}\x01\x01").into_bytes()
}

/// SASL `XOAUTH2` authenticator for `async-imap`.
///
/// Sends the `XOAUTH2` initial response on the first continuation challenge and an empty
/// response on any subsequent error challenge (per Google's XOAUTH2 SASL error protocol)
/// so invalid/expired tokens terminate cleanly with `NO` instead of looping.
struct XOAuth2Authenticator {
    payload: Vec<u8>,
    sent: bool,
}

impl XOAuth2Authenticator {
    fn new(user: &str, access_token: &str) -> Self {
        Self {
            payload: build_xoauth2_sasl_payload(user, access_token),
            sent: false,
        }
    }
}

impl Authenticator for XOAuth2Authenticator {
    type Response = Vec<u8>;

    fn process(&mut self, _challenge: &[u8]) -> Self::Response {
        if self.sent {
            Vec::new()
        } else {
            self.sent = true;
            self.payload.clone()
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct EnabledImapExtensions {
    qresync: bool,
    utf8_accept: bool,
}

/// Encode a UTF-8 IMAP mailbox or `X-GM-LABELS` string into RFC 3501 section 5.1.3 Modified UTF-7.
///
/// Printable US-ASCII (`0x20..=0x7E`) except `&` is preserved verbatim, `&` is encoded as `&-`,
/// and runs of non-printable/non-ASCII Unicode characters are encoded as big-endian UTF-16 in
/// unpadded Modified Base64 (`,` instead of `/`) wrapped in `&...-`.
pub fn encode_imap_mutf7(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut non_ascii_utf16: Vec<u16> = Vec::new();

    let flush_non_ascii = |buf: &mut Vec<u16>, out: &mut String| {
        if buf.is_empty() {
            return;
        }
        let mut bytes = Vec::with_capacity(buf.len() * 2);
        for unit in buf.drain(..) {
            bytes.extend_from_slice(&unit.to_be_bytes());
        }
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD
            .encode(&bytes)
            .replace('/', ",");
        out.push('&');
        out.push_str(&encoded);
        out.push('-');
    };

    for ch in input.chars() {
        let code = ch as u32;
        if (0x20..=0x7e).contains(&code) {
            flush_non_ascii(&mut non_ascii_utf16, &mut out);
            if ch == '&' {
                out.push_str("&-");
            } else {
                out.push(ch);
            }
        } else {
            let mut units = [0u16; 2];
            for unit in ch.encode_utf16(&mut units) {
                non_ascii_utf16.push(*unit);
            }
        }
    }
    flush_non_ascii(&mut non_ascii_utf16, &mut out);
    out
}

/// Decode an RFC 3501 section 5.1.3 Modified UTF-7 IMAP mailbox or `X-GM-LABELS` string back to UTF-8.
///
/// Falls back to returning `input` verbatim if any shift sequence is malformed so already-UTF-8
/// strings containing `&` are preserved safely.
pub fn decode_imap_mutf7(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }

    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] != b'&' {
            let rest = &input[i..];
            let ch = rest.chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }

        // Shift sequence starts at `&`.
        let start = i + 1;
        let Some(rel_end) = bytes[start..].iter().position(|&b| b == b'-') else {
            return input.to_string();
        };
        let end = start + rel_end;
        if end == start {
            // `&-` represents a literal `&`.
            out.push('&');
            i = end + 1;
            continue;
        }

        let b64_slice = &input[start..end];
        if !b64_slice
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b',')
        {
            return input.to_string();
        }
        let std_b64 = b64_slice.replace(',', "/");
        let Ok(decoded_bytes) = base64::engine::general_purpose::STANDARD_NO_PAD.decode(&std_b64)
        else {
            return input.to_string();
        };
        let (pairs, remainder) = decoded_bytes.as_chunks::<2>();
        if !remainder.is_empty() {
            return input.to_string();
        }
        let units: Vec<u16> = pairs.iter().map(|&pair| u16::from_be_bytes(pair)).collect();
        for res in char::decode_utf16(units) {
            match res {
                Ok(ch) => out.push(ch),
                Err(_) => return input.to_string(),
            }
        }
        i = end + 1;
    }

    out
}

/// Safely quote an IMAP string (mailbox name or custom Gmail `X-GM-LABELS` label).
///
/// Rejects empty strings and any string containing CR, LF, NUL, or ASCII control bytes to prevent
/// IMAP command injection. Escapes `\` and `"` and preserves multibyte UTF-8 safely.
pub fn quote_imap_string(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed
        .bytes()
        .any(|b| b == b'\r' || b == b'\n' || b == 0 || b < 0x20 || b == 0x7f)
    {
        return None;
    }
    let mut out = String::with_capacity(trimmed.len() + 2);
    out.push('"');
    for ch in trimmed.chars() {
        match ch {
            '\\' | '"' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out.push('"');
    Some(out)
}

/// Map a local `nogml` label ID to a Gmail IMAP `X-GM-LABELS` wire token using RFC 3501
/// Modified UTF-7 encoding for non-ASCII custom labels (safe when `UTF8=ACCEPT` is not enabled).
///
/// - System labels map to unquoted Gmail special-use tokens (`\Inbox`, `\Starred`, `\Important`,
///   `\Junk`, `\Trash`, `\Sent`, `\Draft`).
/// - `UNREAD` returns `None` because read/unread state is governed by the `\Seen` IMAP flag.
/// - Custom user labels are resolved via `user_label_names`, encoded as Modified UTF-7, and quoted
///   safely via [`quote_imap_string`].
pub fn map_local_label_to_xgm_token(
    label_id: &str,
    user_label_names: &HashMap<String, String>,
) -> Option<String> {
    map_local_label_to_xgm_token_with_utf8(label_id, user_label_names, false)
}

/// Map a local `nogml` label ID to a Gmail IMAP `X-GM-LABELS` wire token, emitting raw UTF-8 when
/// `utf8_accept` is `true` (RFC 6855 `ENABLE UTF8=ACCEPT`) or RFC 3501 Modified UTF-7 when `false`.
pub fn map_local_label_to_xgm_token_with_utf8(
    label_id: &str,
    user_label_names: &HashMap<String, String>,
    utf8_accept: bool,
) -> Option<String> {
    match label_id {
        LABEL_UNREAD => None,
        LABEL_INBOX => Some("\\Inbox".to_string()),
        LABEL_STARRED => Some("\\Starred".to_string()),
        LABEL_IMPORTANT => Some("\\Important".to_string()),
        LABEL_SPAM => Some("\\Junk".to_string()),
        LABEL_TRASH => Some("\\Trash".to_string()),
        LABEL_SENT => Some("\\Sent".to_string()),
        LABEL_DRAFT => Some("\\Draft".to_string()),
        other => {
            if is_system_label(other) {
                return None;
            }
            let name = user_label_names
                .get(other)
                .map(String::as_str)
                .unwrap_or(other)
                .trim();
            if name.is_empty()
                || name
                    .bytes()
                    .any(|b| b == b'\r' || b == b'\n' || b == 0 || b < 0x20 || b == 0x7f)
            {
                return None;
            }
            if utf8_accept {
                quote_imap_string(name)
            } else {
                let wire = encode_imap_mutf7(name);
                quote_imap_string(&wire)
            }
        }
    }
}

/// Format an epoch-millisecond timestamp as an RFC 3501 `APPEND` `INTERNALDATE` string
/// (`DD-Mon-YYYY HH:MM:SS +0000`, e.g. `04-Jan-2025 12:34:56 +0000`).
pub fn format_imap_internaldate(internal_date_ms: i64) -> String {
    let dt = DateTime::from_timestamp_millis(internal_date_ms).unwrap_or_else(Utc::now);
    dt.format("%d-%b-%Y %H:%M:%S +0000").to_string()
}

/// Extract `(uid_validity, assigned_uid)` from an RFC 4315 `ResponseCode::AppendUid`.
pub fn parse_appenduid_response_code(code: Option<&ResponseCode<'_>>) -> Option<(u32, u32)> {
    let Some(ResponseCode::AppendUid(uid_validity, members)) = code else {
        return None;
    };
    let uid = members.iter().find_map(|member| match member {
        UidSetMember::Uid(u) if *u > 0 => Some(*u),
        UidSetMember::UidRange(range) if *range.start() > 0 => Some(*range.start()),
        _ => None,
    })?;
    Some((*uid_validity, uid))
}

/// Expand RFC 7162 `VANISHED` UID ranges into sorted unique UIDs `<= max_uid`, bounded to `cap`.
pub fn expand_uid_ranges(
    ranges: &[std::ops::RangeInclusive<u32>],
    max_uid: u32,
    cap: usize,
) -> Vec<u32> {
    if max_uid == 0 || cap == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    'outer: for range in ranges {
        let lo = (*range.start()).max(1);
        let hi = (*range.end()).min(max_uid);
        if lo > hi {
            continue;
        }
        for uid in lo..=hi {
            if seen.insert(uid) {
                out.push(uid);
                if out.len() >= cap {
                    break 'outer;
                }
            }
        }
    }
    out.sort_unstable();
    out
}

/// Parse a fallback `imap:<mailbox>:<uidvalidity>:<uid>` upstream identifier.
pub fn parse_imap_fallback_upstream_id(upstream_id: &str) -> Option<(&str, u32, u32)> {
    let rest = upstream_id.strip_prefix("imap:")?;
    let (prefix, uid_s) = rest.rsplit_once(':')?;
    let (mbx, uv_s) = prefix.rsplit_once(':')?;
    if mbx.is_empty() {
        return None;
    }
    let uv = uv_s.parse::<u32>().ok()?;
    let uid = uid_s.parse::<u32>().ok()?;
    Some((mbx, uv, uid))
}

fn folder_name_to_system_label(folder: &str) -> Option<&'static str> {
    let lower = folder.trim().to_ascii_lowercase();
    match lower.as_str() {
        "inbox" => Some(LABEL_INBOX),
        "sent" | "[gmail]/sent mail" | "sent messages" | "sent items" => Some(LABEL_SENT),
        "drafts" | "[gmail]/drafts" => Some(LABEL_DRAFT),
        "trash" | "[gmail]/trash" | "deleted messages" | "deleted items" | "bin" => {
            Some(LABEL_TRASH)
        }
        "spam" | "junk" | "junk e-mail" | "[gmail]/spam" => Some(LABEL_SPAM),
        "[gmail]/starred" => Some(LABEL_STARRED),
        "[gmail]/important" => Some(LABEL_IMPORTANT),
        _ => None,
    }
}

fn is_all_mail_or_archive_folder(folder: &str, archive_mailbox: &str) -> bool {
    let trimmed = folder.trim();
    trimmed.eq_ignore_ascii_case("[Gmail]/All Mail")
        || trimmed.eq_ignore_ascii_case("All Mail")
        || trimmed.eq_ignore_ascii_case("Archive")
        || (!archive_mailbox.trim().is_empty()
            && trimmed.eq_ignore_ascii_case(archive_mailbox.trim()))
}

fn configured_sync_folders(config: &Config) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for raw in &config.gmail_imap_folders {
        let trimmed = raw.trim();
        if !trimmed.is_empty() && seen.insert(trimmed.to_ascii_lowercase()) {
            out.push(trimmed.to_string());
        }
    }
    if out.is_empty() {
        let fallback = config.gmail_imap_mailbox.trim();
        out.push(if fallback.is_empty() {
            "[Gmail]/All Mail".to_string()
        } else {
            fallback.to_string()
        });
    }
    out
}

fn prune_uid_map(map: &mut BTreeMap<u32, String>, max_entries: usize) {
    while map.len() > max_entries {
        if let Some((&oldest_uid, _)) = map.iter().next() {
            map.remove(&oldest_uid);
        } else {
            break;
        }
    }
}

async fn resolve_folder_label_id(
    state: &AppState,
    folder: &str,
    archive_mailbox: &str,
    user_label_cache: &mut HashMap<String, String>,
    report: &mut PullReport,
) -> AppResult<Option<String>> {
    if let Some(sys) = folder_name_to_system_label(folder) {
        return Ok(Some(sys.to_string()));
    }
    if is_all_mail_or_archive_folder(folder, archive_mailbox) {
        return Ok(None);
    }
    let name = folder.trim();
    if name.is_empty() {
        return Ok(None);
    }
    if let Some(existing) = user_label_cache.get(name) {
        return Ok(Some(existing.clone()));
    }
    let stored = state
        .store
        .upsert_upstream_label(NewLabelInput {
            name: name.to_string(),
            upstream_label_id: Some(format!("imap:{name}")),
            ..Default::default()
        })
        .await?;
    report.labels_synced += 1;
    user_label_cache.insert(name.to_string(), stored.id.clone());
    Ok(Some(stored.id))
}

async fn collect_labels_from_fetch(
    state: &AppState,
    fetch: &FetchedImapMessage,
    selected_mailbox: &str,
    archive_mailbox: &str,
    utf8_accept: bool,
    user_label_cache: &mut HashMap<String, String>,
    report: &mut PullReport,
) -> AppResult<HashSet<String>> {
    let mut label_set: HashSet<String> = HashSet::new();
    if !fetch.is_seen {
        label_set.insert(LABEL_UNREAD.to_string());
    }
    if fetch.is_flagged {
        label_set.insert(LABEL_STARRED.to_string());
    }
    if fetch.is_draft {
        label_set.insert(LABEL_DRAFT.to_string());
    }

    if let Some(ref xgm_labels) = fetch.gmail_labels {
        for raw_lbl in xgm_labels {
            let s = raw_lbl.trim();
            if s.is_empty() {
                continue;
            }
            match s {
                "\\Inbox" => {
                    label_set.insert(LABEL_INBOX.to_string());
                }
                "\\Sent" => {
                    label_set.insert(LABEL_SENT.to_string());
                }
                "\\Draft" | "\\Drafts" => {
                    label_set.insert(LABEL_DRAFT.to_string());
                }
                "\\Trash" => {
                    label_set.insert(LABEL_TRASH.to_string());
                }
                "\\Junk" | "\\Spam" => {
                    label_set.insert(LABEL_SPAM.to_string());
                }
                "\\Important" => {
                    label_set.insert(LABEL_IMPORTANT.to_string());
                }
                "\\Starred" => {
                    label_set.insert(LABEL_STARRED.to_string());
                }
                "\\All" | "\\AllMail" => {}
                other if other.starts_with('\\') => {}
                raw_user_name => {
                    let decoded_name = if utf8_accept {
                        raw_user_name.to_string()
                    } else {
                        decode_imap_mutf7(raw_user_name)
                    };
                    let user_name = decoded_name.trim();
                    if user_name.is_empty() {
                        continue;
                    }
                    let local_id = if let Some(existing) = user_label_cache.get(user_name) {
                        existing.clone()
                    } else {
                        let stored = state
                            .store
                            .upsert_upstream_label(NewLabelInput {
                                name: user_name.to_string(),
                                upstream_label_id: Some(format!("imap:{user_name}")),
                                ..Default::default()
                            })
                            .await?;
                        report.labels_synced += 1;
                        user_label_cache.insert(user_name.to_string(), stored.id.clone());
                        stored.id
                    };
                    label_set.insert(local_id);
                }
            }
        }
    } else if let Some(folder_lbl) = resolve_folder_label_id(
        state,
        selected_mailbox,
        archive_mailbox,
        user_label_cache,
        report,
    )
    .await?
    {
        label_set.insert(folder_lbl);
    }

    Ok(label_set)
}

#[allow(clippy::too_many_arguments)]
async fn apply_fetched_metadata_delta(
    state: &AppState,
    existing: &StoredMessage,
    fetch: &FetchedImapMessage,
    selected_mailbox: &str,
    archive_mailbox: &str,
    has_xgm: bool,
    utf8_accept: bool,
    skip_labels: Option<&HashSet<String>>,
    user_label_cache: &mut HashMap<String, String>,
    report: &mut PullReport,
) -> AppResult<bool> {
    let current: HashSet<&str> = existing.label_ids.iter().map(String::as_str).collect();
    let mut to_add: Vec<String> = Vec::new();
    let mut to_remove: Vec<String> = Vec::new();
    let is_skipped = |lbl: &str| skip_labels.is_some_and(|s| s.contains(lbl));

    if has_xgm && fetch.gmail_labels.is_some() {
        let desired = collect_labels_from_fetch(
            state,
            fetch,
            selected_mailbox,
            archive_mailbox,
            utf8_accept,
            user_label_cache,
            report,
        )
        .await?;

        for lbl in &desired {
            if !current.contains(lbl.as_str()) && !is_skipped(lbl) {
                to_add.push(lbl.clone());
            }
        }
        for lbl in &existing.label_ids {
            if !desired.contains(lbl.as_str()) && !is_skipped(lbl) {
                to_remove.push(lbl.clone());
            }
        }
    } else {
        // Non-Gmail IMAP server without `X-GM-LABELS`: synchronize flag-derived labels
        // (`UNREAD`, `STARRED`, `DRAFT`) without stripping unrelated folder labels or re-adding
        // the current folder label on already-synced UIDs.
        let want_unread = !fetch.is_seen;
        if want_unread && !current.contains(LABEL_UNREAD) && !is_skipped(LABEL_UNREAD) {
            to_add.push(LABEL_UNREAD.to_string());
        } else if !want_unread && current.contains(LABEL_UNREAD) && !is_skipped(LABEL_UNREAD) {
            to_remove.push(LABEL_UNREAD.to_string());
        }

        if fetch.is_flagged && !current.contains(LABEL_STARRED) && !is_skipped(LABEL_STARRED) {
            to_add.push(LABEL_STARRED.to_string());
        } else if !fetch.is_flagged && current.contains(LABEL_STARRED) && !is_skipped(LABEL_STARRED)
        {
            to_remove.push(LABEL_STARRED.to_string());
        }

        if fetch.is_draft && !current.contains(LABEL_DRAFT) && !is_skipped(LABEL_DRAFT) {
            to_add.push(LABEL_DRAFT.to_string());
        } else if !fetch.is_draft && current.contains(LABEL_DRAFT) && !is_skipped(LABEL_DRAFT) {
            to_remove.push(LABEL_DRAFT.to_string());
        }
    }

    let mut changed = false;
    if !to_add.is_empty() || !to_remove.is_empty() {
        to_add.sort();
        to_remove.sort();
        state
            .store
            .modify_synced_message_labels(&existing.id, &to_add, &to_remove)
            .await?;
        changed = true;
    }

    if existing.is_answered != fetch.is_answered || existing.is_deleted != fetch.is_deleted {
        state
            .store
            .update_synced_message_flags(&existing.id, fetch.is_answered, fetch.is_deleted)
            .await?;
        changed = true;
    }

    Ok(changed)
}

async fn uid_fetch_batch_ext(
    session: &mut Session<UpstreamImapStream>,
    seq_set: &str,
    query: &str,
    modifier: Option<&str>,
    max_vanished_uid: u32,
    command_timeout: Duration,
) -> AppResult<UidFetchBatchResult> {
    let cmd = match modifier {
        Some(m) if !m.trim().is_empty() => format!("UID FETCH {seq_set} {query} {m}"),
        _ => format!("UID FETCH {seq_set} {query}"),
    };
    with_imap_timeout(
        command_timeout,
        "IMAP UID FETCH",
        async {
            let cmd_tag = session
                .run_command(&cmd)
                .await
                .map_err(|e| AppError::Upstream {
                    status: 502,
                    message: format!("IMAP UID FETCH send failed: {e}"),
                })?;

            let mut out = UidFetchBatchResult::default();
            let mut vanished_ranges: Vec<std::ops::RangeInclusive<u32>> = Vec::new();
            while let Some(resp) =
                session
                    .read_response()
                    .await
                    .map_err(|e| AppError::Upstream {
                        status: 502,
                        message: format!("IMAP UID FETCH read error: {e}"),
                    })?
            {
                match resp.parsed() {
                    ImapResponse::Fetch(_, attrs) => {
                        let mut item = FetchedImapMessage::default();
                        for attr in attrs {
                            match attr {
                                AttributeValue::Uid(u) => item.uid = Some(*u),
                                AttributeValue::ModSeq(ms) => item.modseq = Some(*ms),
                                AttributeValue::Flags(raw_flags) => {
                                    for flag in raw_flags {
                                        let f = flag.as_ref();
                                        if f.eq_ignore_ascii_case("\\Seen") {
                                            item.is_seen = true;
                                        } else if f.eq_ignore_ascii_case("\\Flagged") {
                                            item.is_flagged = true;
                                        } else if f.eq_ignore_ascii_case("\\Draft") {
                                            item.is_draft = true;
                                        } else if f.eq_ignore_ascii_case("\\Answered") {
                                            item.is_answered = true;
                                        } else if f.eq_ignore_ascii_case("\\Deleted") {
                                            item.is_deleted = true;
                                        }
                                    }
                                }
                                AttributeValue::InternalDate(dt) => {
                                    item.internal_date_ms = DateTime::parse_from_str(
                                        dt.as_ref(),
                                        "%d-%b-%Y %H:%M:%S %z",
                                    )
                                    .ok()
                                    .map(|d| d.timestamp_millis());
                                }
                                AttributeValue::BodySection {
                                    section: None,
                                    data: Some(body),
                                    ..
                                }
                                | AttributeValue::Rfc822(Some(body)) => {
                                    item.raw_bytes = body.as_ref().to_vec();
                                }
                                AttributeValue::GmailLabels(labels) => {
                                    item.gmail_labels = Some(
                                        labels.iter().map(|s| s.as_ref().to_string()).collect(),
                                    );
                                }
                                AttributeValue::GmailMsgId(id) => item.gmail_msg_id = Some(*id),
                                AttributeValue::GmailThrId(id) => item.gmail_thr_id = Some(*id),
                                _ => {}
                            }
                        }
                        out.messages.push(item);
                    }
                    ImapResponse::Vanished { uids, .. } => {
                        vanished_ranges.extend(uids.iter().cloned());
                    }
                    ImapResponse::Done {
                        tag,
                        status,
                        outcome,
                        ..
                    } if tag == &cmd_tag => {
                        if matches!(status, ImapStatus::Ok) {
                            if !vanished_ranges.is_empty() {
                                out.vanished_uids = expand_uid_ranges(
                                    &vanished_ranges,
                                    max_vanished_uid,
                                    IMAP_VANISHED_MAX_EXPAND,
                                );
                            }
                            return Ok(out);
                        }
                        return Err(AppError::Upstream {
                            status: 502,
                            message: format!("IMAP UID FETCH rejected ({status:?}): {outcome:?}"),
                        });
                    }
                    _ => {}
                }
            }

            Err(AppError::Upstream {
                status: 502,
                message: "IMAP connection closed before UID FETCH completion".to_string(),
            })
        },
        |err| err,
    )
    .await
}

async fn with_imap_timeout<F, T, E>(
    timeout: Duration,
    op: &str,
    fut: F,
    map_err: impl FnOnce(E) -> AppError,
) -> AppResult<T>
where
    F: Future<Output = Result<T, E>>,
{
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(val)) => Ok(val),
        Ok(Err(err)) => Err(map_err(err)),
        Err(_) => Err(AppError::Upstream {
            status: 504,
            message: format!("{op} timed out after {}ms", timeout.as_millis()),
        }),
    }
}

/// Upstream Gmail IMAP [`SyncSource`] implementation.
#[derive(Debug, Clone, Copy)]
pub struct GmailImapSyncSource {
    connect_timeout: Duration,
    command_timeout: Duration,
}

impl Default for GmailImapSyncSource {
    fn default() -> Self {
        Self {
            connect_timeout: IMAP_CONNECT_TIMEOUT,
            command_timeout: IMAP_COMMAND_TIMEOUT,
        }
    }
}

impl GmailImapSyncSource {
    /// Construct a [`GmailImapSyncSource`] with custom connect and per-command timeouts.
    pub fn with_timeouts(connect_timeout: Duration, command_timeout: Duration) -> Self {
        Self {
            connect_timeout,
            command_timeout,
        }
    }
}

#[async_trait]
impl SyncSource for GmailImapSyncSource {
    fn provider_name(&self) -> &'static str {
        "gmail_imap"
    }

    fn account_key(&self, config: &Config) -> String {
        let user = config
            .gmail_imap_user
            .as_deref()
            .unwrap_or(&config.user_email);
        if config.is_multi_mailbox() {
            format!(
                "gmail_imap:{}:{user}",
                crate::config::normalize_mailbox_id(&config.user_email)
            )
        } else {
            format!("gmail_imap:{user}")
        }
    }

    async fn pull(
        &self,
        state: &AppState,
        sync_state: &mut SyncState,
        opts: &SyncRunOptions,
    ) -> AppResult<PullReport> {
        let connect_timeout = self.connect_timeout;
        let command_timeout = self.command_timeout;
        let mut session =
            connect_imap_session(&state.config, connect_timeout, command_timeout).await?;

        let caps = query_imap_capabilities(&mut session, command_timeout).await?;
        let enabled_ext = enable_imap_extensions(&mut session, &caps, command_timeout).await;
        let qresync_enabled = enabled_ext.qresync;
        let utf8_accept = enabled_ext.utf8_accept;

        let mut user_label_cache: HashMap<String, String> = HashMap::new();
        for lbl in state.store.list_labels().await? {
            if lbl.label_type == "user" {
                user_label_cache.insert(lbl.name.clone(), lbl.id.clone());
            }
        }

        let folders = configured_sync_folders(&state.config);
        let multi_folder = folders.len() > 1;
        let archive_mailbox = state.config.gmail_imap_archive_mailbox.clone();
        let max_messages = opts.max_messages.or(state.config.sync_max_messages);
        let mut remaining_budget = max_messages;
        let mut report = PullReport::default();

        // Track messages that vanished from a folder during multi-folder sync so we only delete
        // them locally if they no longer exist in any synced folder after all folders are processed.
        let mut multi_folder_vanished_candidates: HashSet<String> = HashSet::new();

        for (idx, configured_folder) in folders.iter().enumerate() {
            let allow_inbox_fallback = !multi_folder;
            let selected = select_imap_mailbox(
                &mut session,
                configured_folder,
                caps.has_condstore,
                allow_inbox_fallback,
                command_timeout,
            )
            .await;
            let (selected_mailbox, mailbox) = match selected {
                Ok(pair) => pair,
                Err(err) if multi_folder => {
                    warn!(
                        folder = %configured_folder,
                        %err,
                        "Skipping unavailable folder during multi-folder IMAP sync"
                    );
                    continue;
                }
                Err(err) => return Err(err),
            };

            let prev_folder_state = sync_state
                .imap_folder_states
                .get(&selected_mailbox)
                .cloned()
                .or_else(|| {
                    if sync_state.imap_mailbox.as_deref() == Some(selected_mailbox.as_str()) {
                        Some(ImapFolderSyncState {
                            uid_validity: sync_state.imap_uid_validity,
                            last_uid: sync_state.imap_last_uid,
                            highest_modseq: sync_state.imap_highest_modseq,
                            uid_to_message_id: BTreeMap::new(),
                        })
                    } else {
                        None
                    }
                })
                .unwrap_or_default();

            let uid_validity = mailbox.uid_validity;
            let uid_validity_changed = prev_folder_state.uid_validity != uid_validity;
            let folder_full =
                opts.full || uid_validity_changed || prev_folder_state.last_uid.is_none();

            let mut folder_state = if folder_full {
                report.full_resync = true;
                ImapFolderSyncState {
                    uid_validity,
                    last_uid: Some(0),
                    highest_modseq: mailbox.highest_modseq,
                    uid_to_message_id: BTreeMap::new(),
                }
            } else {
                prev_folder_state
            };

            let prev_last_uid = if folder_full {
                0
            } else {
                folder_state.last_uid.unwrap_or(0)
            };
            let prev_highest_modseq = if folder_full {
                None
            } else {
                folder_state.highest_modseq
            };
            let mut last_uid = prev_last_uid;
            let mut highest_modseq = mailbox.highest_modseq.max(prev_highest_modseq);

            // 1. Reconcile flag, label, and deletion updates on already-synced UIDs (1..=prev_last_uid).
            if !folder_full && prev_last_uid > 0 {
                let mut vanished_uids: Vec<u32> = Vec::new();
                let mut updated_fetches: Vec<FetchedImapMessage> = Vec::new();
                let mut used_snapshot_reconcile = false;

                if caps.has_condstore
                    && let Some(since_modseq) = prev_highest_modseq.filter(|&m| m > 0)
                {
                    let server_unchanged = mailbox
                        .highest_modseq
                        .is_some_and(|server_ms| server_ms <= since_modseq);

                    if !server_unchanged {
                        let meta_query = if caps.has_xgm {
                            "(UID FLAGS MODSEQ X-GM-LABELS X-GM-MSGID)"
                        } else {
                            "(UID FLAGS MODSEQ)"
                        };
                        let modifier = if qresync_enabled {
                            format!("(CHANGEDSINCE {since_modseq} VANISHED)")
                        } else {
                            format!("(CHANGEDSINCE {since_modseq})")
                        };
                        let seq_set = format!("1:{prev_last_uid}");
                        match uid_fetch_batch_ext(
                            &mut session,
                            &seq_set,
                            meta_query,
                            Some(&modifier),
                            prev_last_uid,
                            command_timeout,
                        )
                        .await
                        {
                            Ok(batch) => {
                                updated_fetches = batch.messages;
                                vanished_uids.extend(batch.vanished_uids);
                            }
                            Err(err) => {
                                warn!(
                                    mailbox = %selected_mailbox,
                                    %err,
                                    "IMAP CONDSTORE CHANGEDSINCE fetch failed; falling back to bounded reconciliation"
                                );
                                let (fetches, vanished) = reconcile_without_condstore(
                                    &mut session,
                                    prev_last_uid,
                                    &folder_state.uid_to_message_id,
                                    caps.has_xgm,
                                    command_timeout,
                                )
                                .await?;
                                updated_fetches = fetches;
                                vanished_uids.extend(vanished);
                                used_snapshot_reconcile = true;
                            }
                        }
                    }

                    // Servers supporting CONDSTORE without QRESYNC (such as Gmail IMAP) do not
                    // emit `VANISHED` and per RFC 7162 section 3.1.2 are not required to bump
                    // HIGHESTMODSEQ on expunge. Run deletion reconciliation outside
                    // `if !server_unchanged` whenever HIGHESTMODSEQ changed, EXISTS differs from
                    // our tracked count, or UIDNEXT indicates new arrivals that could mask an
                    // expunge.
                    if !qresync_enabled
                        && !used_snapshot_reconcile
                        && !folder_state.uid_to_message_id.is_empty()
                    {
                        let tracked_count = folder_state
                            .uid_to_message_id
                            .keys()
                            .filter(|&&u| u <= prev_last_uid)
                            .count();
                        let maybe_new_arrivals = mailbox
                            .uid_next
                            .is_none_or(|uid_next| uid_next > prev_last_uid.saturating_add(1));
                        let should_sweep_deletions = !server_unchanged
                            || (mailbox.exists as usize) != tracked_count
                            || maybe_new_arrivals;
                        if should_sweep_deletions {
                            let surviving =
                                search_existing_uids(&mut session, prev_last_uid, command_timeout)
                                    .await?;
                            for &tracked_uid in folder_state.uid_to_message_id.keys() {
                                if tracked_uid <= prev_last_uid && !surviving.contains(&tracked_uid)
                                {
                                    vanished_uids.push(tracked_uid);
                                }
                            }
                        }
                    }
                } else {
                    // Non-CONDSTORE fallback: bounded UID-set + metadata reconciliation.
                    let (fetches, vanished) = reconcile_without_condstore(
                        &mut session,
                        prev_last_uid,
                        &folder_state.uid_to_message_id,
                        caps.has_xgm,
                        command_timeout,
                    )
                    .await?;
                    updated_fetches = fetches;
                    vanished_uids.extend(vanished);
                    used_snapshot_reconcile = true;
                }

                // When falling back to a full snapshot scan (no CONDSTORE), avoid clobbering
                // labels that have unpushed local mutations waiting for `push_changes()`.
                let pending_local_touches = if used_snapshot_reconcile
                    && opts
                        .bidirectional
                        .unwrap_or(state.config.sync_bidirectional)
                    && let Some(last_pushed) = sync_state.last_pushed_history_id
                {
                    crate::sync::pending_local_label_touches(state, last_pushed).await?
                } else {
                    HashMap::new()
                };

                // Apply updated flags/labels on existing synced UIDs with HistorySource::Sync.
                for fetch in updated_fetches {
                    if let Some(ms) = fetch.modseq {
                        highest_modseq = Some(highest_modseq.unwrap_or(0).max(ms));
                    }
                    let Some(uid) = fetch.uid else {
                        continue;
                    };
                    let existing = find_local_message_for_imap_uid(
                        state,
                        &folder_state.uid_to_message_id,
                        &selected_mailbox,
                        uid_validity,
                        uid,
                        fetch.gmail_msg_id,
                    )
                    .await?;
                    let Some(existing) = existing else {
                        continue;
                    };
                    folder_state
                        .uid_to_message_id
                        .insert(uid, existing.id.clone());

                    let skip_labels = pending_local_touches.get(&existing.id);
                    if apply_fetched_metadata_delta(
                        state,
                        &existing,
                        &fetch,
                        &selected_mailbox,
                        &archive_mailbox,
                        caps.has_xgm,
                        utf8_accept,
                        skip_labels,
                        &mut user_label_cache,
                        &mut report,
                    )
                    .await?
                    {
                        report.messages_updated += 1;
                    }
                }

                // Process vanished / expunged UIDs.
                vanished_uids.sort_unstable();
                vanished_uids.dedup();
                for v_uid in vanished_uids {
                    if v_uid > prev_last_uid {
                        continue;
                    }
                    let local_id = folder_state.uid_to_message_id.remove(&v_uid);
                    let existing = match local_id {
                        Some(id) => state.store.get_message(&id).await?,
                        None => {
                            let fallback_id = format!(
                                "imap:{}:{}:{v_uid}",
                                selected_mailbox,
                                uid_validity.unwrap_or(0)
                            );
                            state
                                .store
                                .find_message_by_upstream_id(&fallback_id)
                                .await?
                        }
                    };
                    let Some(existing) = existing else {
                        continue;
                    };

                    if multi_folder && !selected_mailbox.eq_ignore_ascii_case("[Gmail]/All Mail") {
                        if let Some(folder_lbl) = resolve_folder_label_id(
                            state,
                            &selected_mailbox,
                            &archive_mailbox,
                            &mut user_label_cache,
                            &mut report,
                        )
                        .await?
                            && existing.label_ids.iter().any(|l| l == &folder_lbl)
                        {
                            state
                                .store
                                .modify_synced_message_labels(&existing.id, &[], &[folder_lbl])
                                .await?;
                            report.messages_updated += 1;
                        }
                        multi_folder_vanished_candidates.insert(existing.id);
                    } else if let Some(ref up_id) = existing.upstream_gmail_id {
                        let att_ids = state.collect_external_attachment_ids(&existing.id).await;
                        if let Some(removed) =
                            state.store.delete_message_by_upstream_id(up_id).await?
                        {
                            let _ = state.post_delete_message(&removed.id, &att_ids).await;
                            report.messages_deleted += 1;
                        }
                    }
                }
            }

            // 2. Fetch newly arrived UIDs (`last_uid + 1 .. *`) in bounded batches.
            let should_fetch_new = mailbox.exists > 0
                && mailbox
                    .uid_next
                    .is_none_or(|uid_next| uid_next > last_uid.saturating_add(1))
                && remaining_budget.is_none_or(|b| b > 0);

            if should_fetch_new {
                let start_uid = last_uid.saturating_add(1);
                let search_query = format!("UID {start_uid}:*");
                let uid_set = with_imap_timeout(
                    command_timeout,
                    "IMAP UID SEARCH",
                    session.uid_search(&search_query),
                    |e| AppError::Upstream {
                        status: 502,
                        message: format!("IMAP UID SEARCH failed: {e}"),
                    },
                )
                .await?;

                let mut uids: Vec<u32> = uid_set.into_iter().filter(|&u| u > last_uid).collect();
                uids.sort_unstable();
                if let Some(cap) = remaining_budget {
                    uids.truncate(cap);
                }

                let query = match (caps.has_xgm, caps.has_condstore) {
                    (true, true) => {
                        "(UID FLAGS MODSEQ INTERNALDATE BODY.PEEK[] X-GM-MSGID X-GM-THRID X-GM-LABELS)"
                    }
                    (true, false) => {
                        "(UID FLAGS INTERNALDATE BODY.PEEK[] X-GM-MSGID X-GM-THRID X-GM-LABELS)"
                    }
                    (false, true) => "(UID FLAGS MODSEQ INTERNALDATE BODY.PEEK[])",
                    (false, false) => "(UID FLAGS INTERNALDATE BODY.PEEK[])",
                };

                info!(
                    mailbox = %selected_mailbox,
                    uid_count = uids.len(),
                    start_uid,
                    has_xgm = caps.has_xgm,
                    has_condstore = caps.has_condstore,
                    "Fetching upstream IMAP messages in bounded batches"
                );

                for chunk in uids.chunks(IMAP_FETCH_BATCH_SIZE) {
                    let seq_set = chunk
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(",");

                    let mut batch = uid_fetch_batch_ext(
                        &mut session,
                        &seq_set,
                        query,
                        None,
                        0,
                        command_timeout,
                    )
                    .await?;

                    batch.messages.sort_by_key(|f| f.uid.unwrap_or(0));

                    for fetch in batch.messages {
                        if let Some(ms) = fetch.modseq {
                            highest_modseq = Some(highest_modseq.unwrap_or(0).max(ms));
                        }
                        let Some(uid) = fetch.uid else {
                            continue;
                        };
                        if uid <= last_uid {
                            continue;
                        }

                        let label_set = collect_labels_from_fetch(
                            state,
                            &fetch,
                            &selected_mailbox,
                            &archive_mailbox,
                            utf8_accept,
                            &mut user_label_cache,
                            &mut report,
                        )
                        .await?;

                        let upstream_gmail_id = match fetch.gmail_msg_id {
                            Some(id) => Some(format!("{id:x}")),
                            None => Some(format!(
                                "imap:{}:{}:{uid}",
                                selected_mailbox,
                                uid_validity.unwrap_or(0)
                            )),
                        };
                        let upstream_thread_id = fetch.gmail_thr_id.map(|id| format!("{id:x}"));

                        let input = parse_raw_to_new_message_input(
                            fetch.raw_bytes,
                            label_set.into_iter().collect(),
                            fetch.internal_date_ms,
                            "gmail_imap",
                            upstream_gmail_id,
                            upstream_thread_id,
                            fetch.is_answered,
                            fetch.is_deleted,
                        );

                        if let Some(outcome) =
                            ingest_synced_message(state, input, &mut report).await?
                        {
                            folder_state
                                .uid_to_message_id
                                .insert(uid, outcome.message.id);
                        }

                        if uid > last_uid {
                            last_uid = uid;
                        }
                        if let Some(ref mut rem) = remaining_budget {
                            *rem = rem.saturating_sub(1);
                        }
                    }
                }
            }

            prune_uid_map(
                &mut folder_state.uid_to_message_id,
                IMAP_UID_MAP_MAX_ENTRIES,
            );
            folder_state.uid_validity = uid_validity;
            folder_state.last_uid = Some(last_uid);
            folder_state.highest_modseq = highest_modseq;

            sync_state
                .imap_folder_states
                .insert(selected_mailbox.clone(), folder_state);

            if idx == 0 {
                sync_state.imap_mailbox = Some(selected_mailbox);
                sync_state.imap_uid_validity = uid_validity;
                sync_state.imap_last_uid = Some(last_uid);
                sync_state.imap_highest_modseq = highest_modseq;
            }
        }

        // In multi-folder sync, permanently delete vanished candidates only when no synced folder
        // still tracks them (preserving messages moved from one synced folder to another).
        if multi_folder && !multi_folder_vanished_candidates.is_empty() {
            let still_tracked: HashSet<&str> = sync_state
                .imap_folder_states
                .values()
                .flat_map(|fs| fs.uid_to_message_id.values().map(String::as_str))
                .collect();
            for candidate_id in multi_folder_vanished_candidates {
                if still_tracked.contains(candidate_id.as_str()) {
                    continue;
                }
                if let Some(msg) = state.store.get_message(&candidate_id).await?
                    && let Some(ref up_id) = msg.upstream_gmail_id
                {
                    let att_ids = state.collect_external_attachment_ids(&msg.id).await;
                    if let Some(removed) = state.store.delete_message_by_upstream_id(up_id).await? {
                        let _ = state.post_delete_message(&removed.id, &att_ids).await;
                        report.messages_deleted += 1;
                    }
                }
            }
        }

        let _ = tokio::time::timeout(
            command_timeout.min(Duration::from_secs(5)),
            session.logout(),
        )
        .await;

        if report.full_resync {
            sync_state.last_full_sync_at = Some(Utc::now());
        }
        sync_state.messages_synced = sync_state
            .messages_synced
            .saturating_add(report.messages_added);

        Ok(report)
    }

    async fn push_changes(
        &self,
        state: &AppState,
        changes: &[LocalMutation],
    ) -> AppResult<PushReport> {
        if changes.is_empty() {
            return Ok(PushReport::default());
        }

        let connect_timeout = self.connect_timeout;
        let command_timeout = self.command_timeout;
        let mut session =
            connect_imap_session(&state.config, connect_timeout, command_timeout).await?;
        let caps = query_imap_capabilities(&mut session, command_timeout).await?;
        let enabled_ext = enable_imap_extensions(&mut session, &caps, command_timeout).await;
        let utf8_accept = enabled_ext.utf8_accept;

        let mut user_label_names: HashMap<String, String> = HashMap::new();
        for lbl in state.store.list_labels().await? {
            if lbl.label_type == "user" {
                user_label_names.insert(lbl.id, lbl.name);
            }
        }

        let stored_sync_state = state
            .store
            .get_sync_state(&self.account_key(&state.config))
            .await?;
        let preferred_mailbox = stored_sync_state
            .as_ref()
            .and_then(|s| s.imap_mailbox.clone())
            .unwrap_or_else(|| configured_sync_folders(&state.config)[0].clone());
        let known_folders: Vec<String> = {
            let mut list = vec![preferred_mailbox.clone()];
            if let Some(ref ss) = stored_sync_state {
                for folder in ss.imap_folder_states.keys() {
                    if !list.iter().any(|existing| existing == folder) {
                        list.push(folder.clone());
                    }
                }
            }
            for folder in configured_sync_folders(&state.config) {
                if !list.iter().any(|existing| existing == &folder) {
                    list.push(folder);
                }
            }
            list
        };

        let mut current_selected: Option<(String, u32)> = None;
        let archive_mailbox = state.config.gmail_imap_archive_mailbox.clone();
        let mut pushed = 0u64;

        for mutation in changes {
            // 1. Handle locally created Sent / Draft messages via IMAP APPEND.
            if let LocalMutationKind::AppendMessage { is_draft } = mutation.kind {
                let Some(msg) = state.store.get_message(&mutation.local_message_id).await? else {
                    continue;
                };
                if msg
                    .upstream_gmail_id
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty())
                {
                    continue;
                }

                let pushed_append = push_local_message_via_append(
                    &mut session,
                    state,
                    &msg,
                    is_draft,
                    &caps,
                    command_timeout,
                )
                .await?;
                // EXAMINE inside append resolution may change the selected mailbox.
                current_selected = None;
                if pushed_append {
                    pushed += 1;
                }
                continue;
            }

            // 2. Ensure the right mailbox is selected for this mutation.
            let desired_mailbox = parse_imap_fallback_upstream_id(&mutation.upstream_id)
                .map(|(mbx, _, _)| mbx.to_string())
                .unwrap_or_else(|| preferred_mailbox.clone());

            let (mut selected_mailbox, selected_uid_validity) = ensure_selected_mailbox(
                &mut session,
                &mut current_selected,
                &desired_mailbox,
                command_timeout,
            )
            .await?;

            let mut uid_opt = resolve_imap_uid(
                &mut session,
                mutation,
                &selected_mailbox,
                selected_uid_validity,
                caps.has_xgm,
                command_timeout,
            )
            .await?;

            // If not found in the primary mailbox, check alternate synced folders (and Drafts for deletes).
            if uid_opt.is_none() {
                let mut fallback_folders: Vec<String> = known_folders
                    .iter()
                    .filter(|f| *f != &selected_mailbox)
                    .cloned()
                    .collect();
                if matches!(mutation.kind, LocalMutationKind::Delete) {
                    for draft_mbx in ["[Gmail]/Drafts", "Drafts"] {
                        if !fallback_folders
                            .iter()
                            .any(|f| f.eq_ignore_ascii_case(draft_mbx))
                            && !selected_mailbox.eq_ignore_ascii_case(draft_mbx)
                        {
                            fallback_folders.push(draft_mbx.to_string());
                        }
                    }
                }
                for folder in fallback_folders {
                    if let Ok((mbx_name, mbx)) =
                        select_imap_mailbox(&mut session, &folder, false, false, command_timeout)
                            .await
                    {
                        let uv = mbx.uid_validity.unwrap_or(0);
                        current_selected = Some((mbx_name.clone(), uv));
                        if let Some(found_uid) = resolve_imap_uid(
                            &mut session,
                            mutation,
                            &mbx_name,
                            uv,
                            caps.has_xgm,
                            command_timeout,
                        )
                        .await?
                        {
                            selected_mailbox = mbx_name;
                            uid_opt = Some(found_uid);
                            break;
                        }
                    }
                }
            }

            let Some(uid) = uid_opt else {
                warn!(
                    upstream_id = %mutation.upstream_id,
                    mailbox = %selected_mailbox,
                    "Skipping upstream IMAP pushback: message UID not found"
                );
                continue;
            };

            let uid_str = uid.to_string();
            let mut performed_op = false;

            match &mutation.kind {
                LocalMutationKind::ModifyLabels {
                    add_labels,
                    remove_labels,
                } => {
                    performed_op |= apply_imap_flag_deltas(
                        &mut session,
                        &uid_str,
                        add_labels,
                        remove_labels,
                        command_timeout,
                    )
                    .await?;

                    if caps.has_xgm {
                        performed_op |= apply_xgm_label_deltas(
                            &mut session,
                            &uid_str,
                            add_labels,
                            remove_labels,
                            &user_label_names,
                            utf8_accept,
                            command_timeout,
                        )
                        .await?;
                    } else {
                        // Non-Gmail IMAP server without X-GM-EXT-1:
                        // 1) Copy to custom label folders (auto-creating if missing).
                        performed_op |= apply_generic_folder_copies(
                            &mut session,
                            &uid_str,
                            add_labels,
                            &user_label_names,
                            command_timeout,
                        )
                        .await?;

                        // 2) Removing INBOX while INBOX is selected moves the message to Archive.
                        if remove_labels.iter().any(|l| l == LABEL_INBOX)
                            && selected_mailbox.eq_ignore_ascii_case("INBOX")
                        {
                            performed_op |= move_uid_to_archive(
                                &mut session,
                                &uid_str,
                                &archive_mailbox,
                                caps.has_move,
                                caps.has_uidplus,
                                command_timeout,
                            )
                            .await?;
                        }
                    }
                }
                LocalMutationKind::Trash {
                    add_labels,
                    remove_labels,
                } => {
                    let _ = apply_imap_flag_deltas(
                        &mut session,
                        &uid_str,
                        add_labels,
                        remove_labels,
                        command_timeout,
                    )
                    .await?;
                    if caps.has_xgm {
                        let _ = apply_xgm_label_deltas(
                            &mut session,
                            &uid_str,
                            add_labels,
                            remove_labels,
                            &user_label_names,
                            utf8_accept,
                            command_timeout,
                        )
                        .await?;
                    }

                    if !selected_mailbox.eq_ignore_ascii_case("[Gmail]/Trash")
                        && !selected_mailbox.eq_ignore_ascii_case("Trash")
                    {
                        let moved = move_uid_to_trash(
                            &mut session,
                            &uid_str,
                            caps.has_move,
                            command_timeout,
                        )
                        .await?;
                        if !moved {
                            if caps.has_xgm {
                                let _ = apply_xgm_label_deltas(
                                    &mut session,
                                    &uid_str,
                                    &[LABEL_TRASH.to_string()],
                                    &[LABEL_INBOX.to_string()],
                                    &user_label_names,
                                    utf8_accept,
                                    command_timeout,
                                )
                                .await?;
                            } else {
                                mark_deleted_and_expunge(
                                    &mut session,
                                    &uid_str,
                                    caps.has_uidplus,
                                    command_timeout,
                                )
                                .await?;
                            }
                        }
                    }
                    performed_op = true;
                }
                LocalMutationKind::Delete => {
                    let in_trash = selected_mailbox.eq_ignore_ascii_case("[Gmail]/Trash")
                        || selected_mailbox.eq_ignore_ascii_case("Trash");
                    if caps.has_xgm && !in_trash && caps.has_move {
                        // On Gmail IMAP (and nogml embedded IMAP), moving to [Gmail]/Trash and
                        // expunging there guarantees permanent deletion instead of only archiving.
                        let moved_trash = move_uid_to_trash(
                            &mut session,
                            &uid_str,
                            caps.has_move,
                            command_timeout,
                        )
                        .await?;
                        if moved_trash {
                            let mut expunged_from_trash = false;
                            for trash_mbx in ["[Gmail]/Trash", "Trash"] {
                                if let Ok((trash_name, mbx)) = select_imap_mailbox(
                                    &mut session,
                                    trash_mbx,
                                    false,
                                    false,
                                    command_timeout,
                                )
                                .await
                                {
                                    let uv = mbx.uid_validity.unwrap_or(0);
                                    current_selected = Some((trash_name.clone(), uv));
                                    if let Some(trash_uid) = resolve_imap_uid(
                                        &mut session,
                                        mutation,
                                        &trash_name,
                                        uv,
                                        caps.has_xgm,
                                        command_timeout,
                                    )
                                    .await?
                                    {
                                        mark_deleted_and_expunge(
                                            &mut session,
                                            &trash_uid.to_string(),
                                            caps.has_uidplus,
                                            command_timeout,
                                        )
                                        .await?;
                                        expunged_from_trash = true;
                                        break;
                                    }
                                }
                            }
                            if !expunged_from_trash {
                                debug!(
                                    upstream_id = %mutation.upstream_id,
                                    "Moved message to Trash during delete; Trash UID not re-resolved"
                                );
                            }
                        } else {
                            mark_deleted_and_expunge(
                                &mut session,
                                &uid_str,
                                caps.has_uidplus,
                                command_timeout,
                            )
                            .await?;
                        }
                    } else {
                        mark_deleted_and_expunge(
                            &mut session,
                            &uid_str,
                            caps.has_uidplus,
                            command_timeout,
                        )
                        .await?;
                    }
                    performed_op = true;
                }
                LocalMutationKind::AppendMessage { .. } => unreachable!("handled above"),
            }

            if performed_op {
                pushed += 1;
            }
        }

        let _ = tokio::time::timeout(
            command_timeout.min(Duration::from_secs(5)),
            session.logout(),
        )
        .await;
        Ok(PushReport {
            messages_pushed: pushed,
        })
    }
}

/// Maintain a dedicated read-only IMAP `IDLE` background listener for `state`, triggering an
/// immediate incremental sync whenever the server notifies `EXISTS`, `EXPUNGE`, `FETCH`, or
/// `VANISHED`, re-idling every `<= 25 min` (`IMAP_IDLE_KEEPALIVE`), backing off exponentially on
/// disconnects, and stopping cleanly when `shutdown` signals `true`.
pub async fn run_imap_idle_listener(state: AppState, shutdown: watch::Receiver<bool>) {
    run_imap_idle_listener_with_options(
        state,
        shutdown,
        IMAP_IDLE_KEEPALIVE,
        IMAP_IDLE_BACKOFF_INITIAL,
        IMAP_IDLE_BACKOFF_MAX,
        IMAP_CONNECT_TIMEOUT,
        IMAP_COMMAND_TIMEOUT,
    )
    .await;
}

/// Configurable entrypoint for the background IMAP `IDLE` listener (used by production with
/// standard RFC 2177 constants and by tests with tight timeouts).
pub async fn run_imap_idle_listener_with_options(
    state: AppState,
    mut shutdown: watch::Receiver<bool>,
    keepalive: Duration,
    backoff_initial: Duration,
    backoff_max: Duration,
    connect_timeout: Duration,
    command_timeout: Duration,
) {
    let keepalive = keepalive.min(Duration::from_secs(25 * 60));
    let mut backoff = backoff_initial.max(Duration::from_millis(25));
    let backoff_max = backoff_max.max(backoff);

    info!(
        mailbox = %state.mailbox_id(),
        keepalive_secs = keepalive.as_secs(),
        "Starting background upstream IMAP IDLE listener"
    );

    loop {
        if *shutdown.borrow() {
            break;
        }
        if !state.config.gmail_sync_configured() {
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {
                    backoff = (backoff * 2).min(backoff_max);
                    continue;
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                    continue;
                }
            }
        }

        let session_res = tokio::select! {
            res = connect_imap_session(&state.config, connect_timeout, command_timeout) => res,
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
        };

        let mut session = match session_res {
            Ok(s) => s,
            Err(err) => {
                warn!(
                    mailbox = %state.mailbox_id(),
                    %err,
                    backoff_ms = backoff.as_millis(),
                    "IMAP IDLE connect failed; backing off"
                );
                if wait_backoff_or_shutdown(backoff, &mut shutdown).await {
                    break;
                }
                backoff = (backoff * 2).min(backoff_max);
                continue;
            }
        };

        let caps = match query_imap_capabilities(&mut session, command_timeout).await {
            Ok(c) => c,
            Err(err) => {
                warn!(mailbox = %state.mailbox_id(), %err, "IMAP IDLE capability check failed");
                if wait_backoff_or_shutdown(backoff, &mut shutdown).await {
                    break;
                }
                backoff = (backoff * 2).min(backoff_max);
                continue;
            }
        };
        if !caps.has_idle {
            warn!(
                mailbox = %state.mailbox_id(),
                "Upstream IMAP server does not advertise IDLE; pausing IDLE listener"
            );
            let _ = session.logout().await;
            if wait_backoff_or_shutdown(backoff_max, &mut shutdown).await {
                break;
            }
            continue;
        }
        let _ = enable_imap_extensions(&mut session, &caps, command_timeout).await;

        let primary_folder = configured_sync_folders(&state.config)[0].clone();
        if let Err(err) = examine_imap_mailbox(&mut session, &primary_folder, command_timeout).await
        {
            warn!(
                mailbox = %state.mailbox_id(),
                folder = %primary_folder,
                %err,
                "IMAP IDLE EXAMINE failed; backing off"
            );
            if wait_backoff_or_shutdown(backoff, &mut shutdown).await {
                break;
            }
            backoff = (backoff * 2).min(backoff_max);
            continue;
        }

        // Connected and idling cleanly -> reset backoff.
        backoff = backoff_initial.max(Duration::from_millis(25));

        loop {
            if *shutdown.borrow() {
                let _ = tokio::time::timeout(Duration::from_secs(2), session.logout()).await;
                info!(
                    mailbox = %state.mailbox_id(),
                    "Background IMAP IDLE listener shutting down"
                );
                return;
            }

            let mut idle = session.idle();
            if let Err(err) =
                with_imap_timeout(command_timeout, "IMAP IDLE init", idle.init(), |e| {
                    AppError::Upstream {
                        status: 502,
                        message: format!("IMAP IDLE init failed: {e}"),
                    }
                })
                .await
            {
                warn!(mailbox = %state.mailbox_id(), %err, "IMAP IDLE init error; reconnecting");
                break;
            }

            let (idle_wait_fut, interrupt) = idle.wait_with_timeout(keepalive);
            let wait_outcome = tokio::select! {
                res = idle_wait_fut => Some(res),
                changed = shutdown.changed() => {
                    drop(interrupt);
                    if changed.is_err() || *shutdown.borrow() {
                        let _ = tokio::time::timeout(Duration::from_secs(2), idle.done()).await;
                        info!(
                            mailbox = %state.mailbox_id(),
                            "Background IMAP IDLE listener shutting down"
                        );
                        return;
                    }
                    None
                }
            };

            let should_trigger_sync = match wait_outcome {
                Some(Ok(IdleResponse::NewData(resp))) => {
                    let trigger = is_idle_sync_trigger(resp.parsed());
                    debug!(
                        mailbox = %state.mailbox_id(),
                        trigger,
                        "IMAP IDLE received server notification"
                    );
                    trigger
                }
                Some(Ok(IdleResponse::Timeout)) => {
                    debug!(
                        mailbox = %state.mailbox_id(),
                        "IMAP IDLE keepalive window elapsed; refreshing IDLE"
                    );
                    false
                }
                Some(Ok(IdleResponse::ManualInterrupt)) => false,
                Some(Err(err)) => {
                    warn!(mailbox = %state.mailbox_id(), %err, "IMAP IDLE wait failed; reconnecting");
                    break;
                }
                None => false,
            };

            session = match with_imap_timeout(
                command_timeout.min(Duration::from_secs(15)),
                "IMAP IDLE DONE",
                idle.done(),
                |e| AppError::Upstream {
                    status: 502,
                    message: format!("IMAP IDLE DONE failed: {e}"),
                },
            )
            .await
            {
                Ok(s) => s,
                Err(err) => {
                    warn!(mailbox = %state.mailbox_id(), %err, "IMAP IDLE DONE failed; reconnecting");
                    break;
                }
            };

            if should_trigger_sync && !*shutdown.borrow() {
                match run_gmail_sync(&state, SyncRunOptions::default()).await {
                    Ok(report) => {
                        info!(
                            mailbox = %state.mailbox_id(),
                            added = report.messages_added,
                            updated = report.messages_updated,
                            deleted = report.messages_deleted,
                            pushed = report.messages_pushed,
                            "IMAP IDLE triggered incremental sync completed"
                        );
                    }
                    Err(err) => {
                        warn!(
                            mailbox = %state.mailbox_id(),
                            %err,
                            "IMAP IDLE triggered incremental sync failed"
                        );
                    }
                }
            }
        }

        if wait_backoff_or_shutdown(backoff, &mut shutdown).await {
            break;
        }
        backoff = (backoff * 2).min(backoff_max);
    }

    info!(
        mailbox = %state.mailbox_id(),
        "Background IMAP IDLE listener stopped"
    );
}

fn is_idle_sync_trigger(resp: &ImapResponse<'_>) -> bool {
    matches!(
        resp,
        ImapResponse::MailboxData(MailboxDatum::Exists(_) | MailboxDatum::Recent(_))
            | ImapResponse::Expunge(_)
            | ImapResponse::Fetch(_, _)
            | ImapResponse::Vanished { .. }
    )
}

async fn wait_backoff_or_shutdown(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(delay) => *shutdown.borrow(),
        changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
    }
}

async fn query_imap_capabilities(
    session: &mut Session<UpstreamImapStream>,
    command_timeout: Duration,
) -> AppResult<ImapServerCaps> {
    match tokio::time::timeout(command_timeout, session.capabilities()).await {
        Ok(Ok(caps)) => Ok(ImapServerCaps {
            has_xgm: caps.has_str("X-GM-EXT-1"),
            has_move: caps.has_str("MOVE"),
            has_uidplus: caps.has_str("UIDPLUS"),
            has_condstore: caps.has_str("CONDSTORE"),
            has_qresync: caps.has_str("QRESYNC"),
            has_enable: caps.has_str("ENABLE"),
            has_utf8_accept: caps.has_str("UTF8=ACCEPT"),
            has_idle: caps.has_str("IDLE"),
        }),
        Ok(Err(err)) => {
            warn!(%err, "Failed to query IMAP capabilities; using conservative defaults");
            Ok(ImapServerCaps::default())
        }
        Err(_) => Err(AppError::Upstream {
            status: 504,
            message: format!(
                "IMAP CAPABILITY timed out after {}ms",
                command_timeout.as_millis()
            ),
        }),
    }
}

/// Enable `QRESYNC` / `CONDSTORE` / `UTF8=ACCEPT` when advertised by the server, parsing the
/// untagged `* ENABLED ...` response per RFC 5161 §3.2 so only server-confirmed extensions are
/// treated as active.
async fn enable_imap_extensions(
    session: &mut Session<UpstreamImapStream>,
    caps: &ImapServerCaps,
    command_timeout: Duration,
) -> EnabledImapExtensions {
    if !caps.has_enable {
        return EnabledImapExtensions::default();
    }
    let mut to_enable: Vec<&'static str> = Vec::new();
    if caps.has_qresync {
        to_enable.push("CONDSTORE");
        to_enable.push("QRESYNC");
    } else if caps.has_condstore {
        to_enable.push("CONDSTORE");
    }
    if caps.has_utf8_accept {
        to_enable.push("UTF8=ACCEPT");
    }
    if to_enable.is_empty() {
        return EnabledImapExtensions::default();
    }

    let cmd = format!("ENABLE {}", to_enable.join(" "));
    let fut = async {
        let cmd_tag = session.run_command(&cmd).await?;
        let mut enabled = EnabledImapExtensions::default();
        while let Some(resp) = session.read_response().await? {
            match resp.parsed() {
                ImapResponse::Capabilities(enabled_caps) => {
                    for cap in enabled_caps {
                        if let ImapCapability::Atom(atom) = cap {
                            if atom.eq_ignore_ascii_case("QRESYNC") {
                                enabled.qresync = true;
                            } else if atom.eq_ignore_ascii_case("UTF8=ACCEPT") {
                                enabled.utf8_accept = true;
                            }
                        }
                    }
                }
                ImapResponse::Done { tag, status, .. } if tag == &cmd_tag => {
                    if matches!(status, ImapStatus::Ok) {
                        return Ok(enabled);
                    }
                    return Ok(EnabledImapExtensions::default());
                }
                _ => {}
            }
        }
        Ok::<EnabledImapExtensions, async_imap::error::Error>(EnabledImapExtensions::default())
    };

    match tokio::time::timeout(command_timeout, fut).await {
        Ok(Ok(enabled)) => enabled,
        Ok(Err(err)) => {
            debug!(%err, cmd = %cmd, "IMAP ENABLE rejected; continuing without optional extensions");
            EnabledImapExtensions::default()
        }
        Err(_) => {
            warn!(cmd = %cmd, "IMAP ENABLE timed out; continuing without optional extensions");
            EnabledImapExtensions::default()
        }
    }
}

async fn search_existing_uids(
    session: &mut Session<UpstreamImapStream>,
    max_uid: u32,
    command_timeout: Duration,
) -> AppResult<HashSet<u32>> {
    let query = format!("UID 1:{max_uid}");
    let uids = with_imap_timeout(
        command_timeout,
        "IMAP UID SEARCH (reconcile)",
        session.uid_search(&query),
        |e| AppError::Upstream {
            status: 502,
            message: format!("IMAP UID SEARCH failed: {e}"),
        },
    )
    .await?;
    Ok(uids.into_iter().filter(|&u| u <= max_uid).collect())
}

async fn reconcile_without_condstore(
    session: &mut Session<UpstreamImapStream>,
    prev_last_uid: u32,
    tracked_uids: &BTreeMap<u32, String>,
    has_xgm: bool,
    command_timeout: Duration,
) -> AppResult<(Vec<FetchedImapMessage>, Vec<u32>)> {
    let surviving = search_existing_uids(session, prev_last_uid, command_timeout).await?;

    let mut vanished: Vec<u32> = tracked_uids
        .keys()
        .copied()
        .filter(|&u| u <= prev_last_uid && !surviving.contains(&u))
        .collect();
    vanished.sort_unstable();

    // Bound metadata reconciliation to the most recent `IMAP_RECONCILE_MAX_UIDS` surviving UIDs.
    let mut to_check: Vec<u32> = surviving.into_iter().collect();
    to_check.sort_unstable();
    if to_check.len() > IMAP_RECONCILE_MAX_UIDS {
        let start = to_check.len() - IMAP_RECONCILE_MAX_UIDS;
        to_check = to_check.split_off(start);
    }

    let query = if has_xgm {
        "(UID FLAGS X-GM-LABELS X-GM-MSGID)"
    } else {
        "(UID FLAGS)"
    };
    let mut fetched = Vec::new();
    for chunk in to_check.chunks(IMAP_METADATA_BATCH_SIZE) {
        let seq_set = chunk
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let batch = uid_fetch_batch_ext(session, &seq_set, query, None, 0, command_timeout).await?;
        fetched.extend(batch.messages);
    }

    Ok((fetched, vanished))
}

async fn find_local_message_for_imap_uid(
    state: &AppState,
    uid_map: &BTreeMap<u32, String>,
    selected_mailbox: &str,
    uid_validity: Option<u32>,
    uid: u32,
    gmail_msg_id: Option<u64>,
) -> AppResult<Option<StoredMessage>> {
    if let Some(gm_id) = gmail_msg_id {
        let hex_id = format!("{gm_id:x}");
        if let Some(msg) = state.store.find_message_by_upstream_id(&hex_id).await? {
            return Ok(Some(msg));
        }
    }
    if let Some(local_id) = uid_map.get(&uid)
        && let Some(msg) = state.store.get_message(local_id).await?
    {
        return Ok(Some(msg));
    }
    let fallback_id = format!(
        "imap:{}:{}:{uid}",
        selected_mailbox,
        uid_validity.unwrap_or(0)
    );
    state.store.find_message_by_upstream_id(&fallback_id).await
}

pub(crate) fn is_loopback_imap_host(host: &str) -> bool {
    let trimmed = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.');
    trimmed.eq_ignore_ascii_case("localhost")
        || trimmed
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

pub(crate) fn is_gmail_imap_host(host: &str) -> bool {
    let lower = host.trim().trim_end_matches('.').to_ascii_lowercase();
    lower == "imap.gmail.com"
        || lower == "imap.googlemail.com"
        || lower.ends_with(".gmail.com")
        || lower.ends_with(".googlemail.com")
}

/// Validate that sending a Google OAuth2 bearer token to the configured IMAP server is safe:
/// requires TLS (except loopback for local tests) and a Gmail IMAP host (or loopback).
pub(crate) fn validate_imap_xoauth2_target(config: &Config) -> AppResult<()> {
    let host = config.gmail_imap_host.trim();
    if is_loopback_imap_host(host) {
        return Ok(());
    }
    if !config.gmail_imap_tls {
        return Err(AppError::Config(format!(
            "Refusing to send Gmail OAuth2 bearer token over non-TLS IMAP connection to '{host}'; enable gmail_imap_tls or configure gmail_imap_password"
        )));
    }
    if !is_gmail_imap_host(host) {
        return Err(AppError::Config(format!(
            "Refusing to send Gmail OAuth2 bearer token to non-Gmail IMAP host '{host}'; configure gmail_imap_password for third-party IMAP servers"
        )));
    }
    Ok(())
}

fn caps_list_has_xoauth2(caps: &[ImapCapability<'_>]) -> bool {
    caps.iter().any(|cap| match cap {
        ImapCapability::Auth(mech) => mech.eq_ignore_ascii_case("XOAUTH2"),
        ImapCapability::Atom(atom) => atom.eq_ignore_ascii_case("AUTH=XOAUTH2"),
        ImapCapability::Imap4rev1 => false,
    })
}

fn greeting_advertises_xoauth2(parsed: Option<&ImapResponse<'_>>) -> Option<bool> {
    match parsed? {
        ImapResponse::Data { outcome, .. } => match outcome.code.as_ref() {
            Some(ResponseCode::Capabilities(caps)) => Some(caps_list_has_xoauth2(caps)),
            _ => None,
        },
        ImapResponse::Capabilities(caps) => Some(caps_list_has_xoauth2(caps)),
        _ => None,
    }
}

async fn read_crlf_line_bounded(
    stream: &mut UpstreamImapStream,
    max_bytes: usize,
) -> std::io::Result<String> {
    let mut buf = Vec::with_capacity(256);
    loop {
        let b = stream.read_u8().await?;
        buf.push(b);
        if b == b'\n' {
            break;
        }
        if buf.len() >= max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "IMAP pre-auth capability line exceeded maximum length",
            ));
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

async fn query_preauth_xoauth2_capability(
    client: async_imap::Client<UpstreamImapStream>,
    greeting_xoauth2: Option<bool>,
    command_timeout: Duration,
) -> AppResult<(async_imap::Client<UpstreamImapStream>, bool)> {
    if let Some(supported) = greeting_xoauth2 {
        return Ok((client, supported));
    }

    let mut stream = client.into_inner();
    let supported = with_imap_timeout(
        command_timeout,
        "IMAP pre-auth CAPABILITY",
        async {
            stream.write_all(b"C0 CAPABILITY\r\n").await?;
            stream.flush().await?;
            let mut found = false;
            for _ in 0..32 {
                let line = read_crlf_line_bounded(&mut stream, 16 * 1024).await?;
                let trimmed = line.trim();
                let upper = trimmed.to_ascii_uppercase();
                if upper.starts_with("* CAPABILITY ") {
                    if trimmed
                        .split_whitespace()
                        .skip(2)
                        .any(|tok| tok.eq_ignore_ascii_case("AUTH=XOAUTH2"))
                    {
                        found = true;
                    }
                } else if upper.starts_with("C0 ") {
                    if let Some(bracket_start) = trimmed.find('[')
                        && let Some(bracket_end) = trimmed[bracket_start + 1..].find(']')
                    {
                        let inner = &trimmed[bracket_start + 1..bracket_start + 1 + bracket_end];
                        if inner
                            .split_whitespace()
                            .any(|tok| tok.eq_ignore_ascii_case("AUTH=XOAUTH2"))
                        {
                            found = true;
                        }
                    }
                    break;
                }
            }
            Ok::<bool, std::io::Error>(found)
        },
        |e| AppError::Upstream {
            status: 502,
            message: format!("IMAP pre-auth CAPABILITY failed: {e}"),
        },
    )
    .await?;

    Ok((async_imap::Client::new(stream), supported))
}

async fn connect_imap_client(
    config: &Config,
    connect_timeout: Duration,
    command_timeout: Duration,
) -> AppResult<(async_imap::Client<UpstreamImapStream>, Option<bool>)> {
    ensure_crypto_provider();

    let host = &config.gmail_imap_host;
    let port = config.gmail_imap_port;
    let tcp = with_imap_timeout(
        connect_timeout,
        "IMAP TCP connect",
        TcpStream::connect((host.as_str(), port)),
        |e| AppError::Upstream {
            status: 502,
            message: format!("Failed to connect to IMAP server {host}:{port}: {e}"),
        },
    )
    .await?;

    let stream = if config.gmail_imap_tls {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_cfg = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(tls_cfg));
        let server_name = ServerName::try_from(host.clone())
            .map_err(|e| AppError::Config(format!("Invalid IMAP TLS hostname '{host}': {e}")))?;
        let tls = with_imap_timeout(
            connect_timeout,
            "IMAP TLS handshake",
            connector.connect(server_name, tcp),
            |e| AppError::Upstream {
                status: 502,
                message: format!("IMAP TLS handshake failed with {host}:{port}: {e}"),
            },
        )
        .await?;
        UpstreamImapStream::Tls(Box::new(tls))
    } else {
        UpstreamImapStream::Plain(tcp)
    };

    let mut client = async_imap::Client::new(stream);
    let greeting = with_imap_timeout(
        command_timeout,
        "IMAP greeting",
        client.read_response(),
        |e| AppError::Upstream {
            status: 502,
            message: format!("Failed reading IMAP greeting: {e}"),
        },
    )
    .await?;
    let greeting_xoauth2 = greeting_advertises_xoauth2(greeting.as_ref().map(|r| r.parsed()));

    Ok((client, greeting_xoauth2))
}

async fn connect_imap_session(
    config: &Config,
    connect_timeout: Duration,
    command_timeout: Duration,
) -> AppResult<Session<UpstreamImapStream>> {
    let user = config
        .gmail_imap_user
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| AppError::Config("Gmail IMAP sync requires gmail_imap_user".to_string()))?;

    let password = config
        .gmail_imap_password
        .as_deref()
        .filter(|s| !s.is_empty());

    // Prefer explicit `gmail_imap_password` over Gmail OAuth2 (matching `SmtpConfig::from_config`)
    // so deployments configuring Gmail OAuth2 for outbound transport never leak Google bearer
    // tokens to third-party IMAP servers and password auth is never blocked by OAuth refresh failures.
    if let Some(pass) = password {
        let (client, _) = connect_imap_client(config, connect_timeout, command_timeout).await?;
        return with_imap_timeout(
            command_timeout,
            "IMAP LOGIN",
            client.login(user, pass),
            |(err, _)| AppError::Unauthorized(format!("IMAP login failed: {err}")),
        )
        .await;
    }

    if !config.has_gmail_oauth2() {
        return Err(AppError::Config(
            "Gmail IMAP sync requires gmail_imap_password or Gmail OAuth2 credentials".to_string(),
        ));
    }

    validate_imap_xoauth2_target(config)?;

    let http_client = reqwest::Client::builder()
        .timeout(connect_timeout)
        .build()
        .map_err(|e| AppError::Internal(format!("Failed to build OAuth2 HTTP client: {e}")))?;
    let can_refresh = config
        .gmail_access_token
        .as_deref()
        .is_none_or(|s| s.trim().is_empty())
        && config
            .gmail_refresh_token
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty());

    let (client, greeting_xoauth2) =
        connect_imap_client(config, connect_timeout, command_timeout).await?;
    let (mut client, supports_xoauth2) =
        query_preauth_xoauth2_capability(client, greeting_xoauth2, command_timeout).await?;
    if !supports_xoauth2 {
        return Err(AppError::Unauthorized(format!(
            "IMAP server {}:{} did not advertise AUTH=XOAUTH2; refusing to send OAuth2 bearer token",
            config.gmail_imap_host, config.gmail_imap_port
        )));
    }

    let mut token = acquire_access_token(&http_client, config).await?;
    let mut refreshed = false;

    loop {
        let auth = XOAuth2Authenticator::new(user, &token);
        match tokio::time::timeout(command_timeout, client.authenticate("XOAUTH2", auth)).await {
            Ok(Ok(session)) => return Ok(session),
            Ok(Err((err, _client))) => {
                if can_refresh && !refreshed {
                    refreshed = true;
                    warn!(%err, "IMAP XOAUTH2 authentication failed; refreshing OAuth2 token and retrying once");
                    invalidate_access_token(config);
                    token = acquire_access_token(&http_client, config).await?;
                    let (retry_client, retry_greeting) =
                        connect_imap_client(config, connect_timeout, command_timeout).await?;
                    let (verified_client, retry_supports_xoauth2) =
                        query_preauth_xoauth2_capability(
                            retry_client,
                            retry_greeting,
                            command_timeout,
                        )
                        .await?;
                    if !retry_supports_xoauth2 {
                        return Err(AppError::Unauthorized(format!(
                            "IMAP server {}:{} did not advertise AUTH=XOAUTH2 on retry",
                            config.gmail_imap_host, config.gmail_imap_port
                        )));
                    }
                    client = verified_client;
                    continue;
                }
                return Err(AppError::Unauthorized(format!(
                    "IMAP XOAUTH2 authentication failed: {err}"
                )));
            }
            Err(_) => {
                return Err(AppError::Upstream {
                    status: 504,
                    message: format!(
                        "IMAP AUTHENTICATE XOAUTH2 timed out after {}ms",
                        command_timeout.as_millis()
                    ),
                });
            }
        }
    }
}

async fn select_imap_mailbox(
    session: &mut Session<UpstreamImapStream>,
    configured_mbx: &str,
    use_condstore: bool,
    allow_inbox_fallback: bool,
    command_timeout: Duration,
) -> AppResult<(String, async_imap::types::Mailbox)> {
    let select_res = if use_condstore {
        tokio::time::timeout(command_timeout, session.select_condstore(configured_mbx)).await
    } else {
        tokio::time::timeout(command_timeout, session.select(configured_mbx)).await
    };

    match select_res {
        Ok(Ok(mbx)) => Ok((configured_mbx.to_string(), mbx)),
        Ok(Err(err)) if allow_inbox_fallback && !configured_mbx.eq_ignore_ascii_case("INBOX") => {
            warn!(
                mailbox = %configured_mbx,
                %err,
                "Failed to select configured IMAP mailbox; falling back to INBOX"
            );
            let mbx = if use_condstore {
                with_imap_timeout(
                    command_timeout,
                    "IMAP SELECT INBOX (CONDSTORE)",
                    session.select_condstore("INBOX"),
                    |e| AppError::Upstream {
                        status: 502,
                        message: format!("Failed to select INBOX: {e}"),
                    },
                )
                .await?
            } else {
                with_imap_timeout(
                    command_timeout,
                    "IMAP SELECT INBOX",
                    session.select("INBOX"),
                    |e| AppError::Upstream {
                        status: 502,
                        message: format!("Failed to select INBOX: {e}"),
                    },
                )
                .await?
            };
            Ok(("INBOX".to_string(), mbx))
        }
        Ok(Err(err)) => Err(AppError::Upstream {
            status: 502,
            message: format!("Failed to select IMAP mailbox '{configured_mbx}': {err}"),
        }),
        Err(_) => Err(AppError::Upstream {
            status: 504,
            message: format!(
                "IMAP SELECT timed out after {}ms",
                command_timeout.as_millis()
            ),
        }),
    }
}

async fn examine_imap_mailbox(
    session: &mut Session<UpstreamImapStream>,
    configured_mbx: &str,
    command_timeout: Duration,
) -> AppResult<(String, async_imap::types::Mailbox)> {
    match tokio::time::timeout(command_timeout, session.examine(configured_mbx)).await {
        Ok(Ok(mbx)) => Ok((configured_mbx.to_string(), mbx)),
        Ok(Err(err)) if !configured_mbx.eq_ignore_ascii_case("INBOX") => {
            warn!(
                mailbox = %configured_mbx,
                %err,
                "Failed to EXAMINE configured IMAP mailbox; falling back to INBOX"
            );
            let mbx = with_imap_timeout(
                command_timeout,
                "IMAP EXAMINE INBOX",
                session.examine("INBOX"),
                |e| AppError::Upstream {
                    status: 502,
                    message: format!("Failed to EXAMINE INBOX: {e}"),
                },
            )
            .await?;
            Ok(("INBOX".to_string(), mbx))
        }
        Ok(Err(err)) => Err(AppError::Upstream {
            status: 502,
            message: format!("Failed to EXAMINE IMAP mailbox '{configured_mbx}': {err}"),
        }),
        Err(_) => Err(AppError::Upstream {
            status: 504,
            message: format!(
                "IMAP EXAMINE timed out after {}ms",
                command_timeout.as_millis()
            ),
        }),
    }
}

async fn ensure_selected_mailbox(
    session: &mut Session<UpstreamImapStream>,
    current_selected: &mut Option<(String, u32)>,
    desired_mailbox: &str,
    command_timeout: Duration,
) -> AppResult<(String, u32)> {
    if let Some((ref cur_name, cur_uv)) = *current_selected
        && cur_name == desired_mailbox
    {
        return Ok((cur_name.clone(), cur_uv));
    }
    let (selected_name, mbx) =
        select_imap_mailbox(session, desired_mailbox, false, true, command_timeout).await?;
    let uv = mbx.uid_validity.unwrap_or(0);
    *current_selected = Some((selected_name.clone(), uv));
    Ok((selected_name, uv))
}

async fn resolve_imap_uid(
    session: &mut Session<UpstreamImapStream>,
    mutation: &LocalMutation,
    selected_mailbox: &str,
    selected_uid_validity: u32,
    has_xgm: bool,
    command_timeout: Duration,
) -> AppResult<Option<u32>> {
    // 1. Direct fallback format `imap:<mailbox>:<uidvalidity>:<uid>`.
    if let Some((mbx, uv, uid)) = parse_imap_fallback_upstream_id(&mutation.upstream_id)
        && mbx == selected_mailbox
        && (selected_uid_validity == 0 || uv == selected_uid_validity)
    {
        return Ok(Some(uid));
    }

    // 2. Gmail `X-GM-MSGID` search (hex upstream_id -> decimal u64).
    if has_xgm
        && let Ok(xgm_id) = u64::from_str_radix(mutation.upstream_id.trim(), 16)
        && xgm_id > 0
    {
        match tokio::time::timeout(
            command_timeout,
            session.uid_search(format!("X-GM-MSGID {xgm_id}")),
        )
        .await
        {
            Ok(Ok(uids)) => {
                if let Some(&uid) = uids.iter().min() {
                    return Ok(Some(uid));
                }
            }
            Ok(Err(err)) => {
                debug!(%err, xgm_id, "IMAP X-GM-MSGID search failed");
            }
            Err(_) => {
                return Err(AppError::Upstream {
                    status: 504,
                    message: format!(
                        "IMAP X-GM-MSGID search timed out after {}ms",
                        command_timeout.as_millis()
                    ),
                });
            }
        }
    }

    // 3. RFC 2822 Message-ID header search fallback.
    if let Some(ref mid) = mutation.rfc822_message_id {
        let safe_mid = mid.replace(['"', '\\', '\r', '\n'], "");
        if !safe_mid.is_empty() {
            match tokio::time::timeout(
                command_timeout,
                session.uid_search(format!("HEADER Message-ID \"{safe_mid}\"")),
            )
            .await
            {
                Ok(Ok(uids)) => {
                    if let Some(&uid) = uids.iter().min() {
                        return Ok(Some(uid));
                    }
                }
                Ok(Err(err)) => {
                    debug!(%err, message_id = %safe_mid, "IMAP HEADER Message-ID search failed");
                }
                Err(_) => {
                    return Err(AppError::Upstream {
                        status: 504,
                        message: format!(
                            "IMAP HEADER Message-ID search timed out after {}ms",
                            command_timeout.as_millis()
                        ),
                    });
                }
            }
        }
    }

    Ok(None)
}

async fn apply_imap_flag_deltas(
    session: &mut Session<UpstreamImapStream>,
    uid_str: &str,
    add_labels: &[String],
    remove_labels: &[String],
    command_timeout: Duration,
) -> AppResult<bool> {
    let mut add_flags: Vec<&'static str> = Vec::new();
    let mut remove_flags: Vec<&'static str> = Vec::new();

    if remove_labels.iter().any(|l| l == LABEL_UNREAD) {
        add_flags.push("\\Seen");
    }
    if add_labels.iter().any(|l| l == LABEL_UNREAD) {
        remove_flags.push("\\Seen");
    }
    if add_labels.iter().any(|l| l == LABEL_STARRED) {
        add_flags.push("\\Flagged");
    }
    if remove_labels.iter().any(|l| l == LABEL_STARRED) {
        remove_flags.push("\\Flagged");
    }
    if add_labels.iter().any(|l| l == LABEL_DRAFT) {
        add_flags.push("\\Draft");
    }
    if remove_labels.iter().any(|l| l == LABEL_DRAFT) {
        remove_flags.push("\\Draft");
    }

    let mut did_store = false;
    if !add_flags.is_empty() {
        let query = format!("+FLAGS ({})", add_flags.join(" "));
        let _: Vec<_> = with_imap_timeout(
            command_timeout,
            "IMAP UID STORE +FLAGS",
            async {
                let stream = session.uid_store(uid_str, query).await?;
                stream.try_collect().await
            },
            |e| AppError::Upstream {
                status: 502,
                message: format!("IMAP UID STORE +FLAGS failed: {e}"),
            },
        )
        .await?;
        did_store = true;
    }

    if !remove_flags.is_empty() {
        let query = format!("-FLAGS ({})", remove_flags.join(" "));
        let _: Vec<_> = with_imap_timeout(
            command_timeout,
            "IMAP UID STORE -FLAGS",
            async {
                let stream = session.uid_store(uid_str, query).await?;
                stream.try_collect().await
            },
            |e| AppError::Upstream {
                status: 502,
                message: format!("IMAP UID STORE -FLAGS failed: {e}"),
            },
        )
        .await?;
        did_store = true;
    }

    Ok(did_store)
}

#[allow(clippy::too_many_arguments)]
async fn apply_xgm_label_deltas(
    session: &mut Session<UpstreamImapStream>,
    uid_str: &str,
    add_labels: &[String],
    remove_labels: &[String],
    user_label_names: &HashMap<String, String>,
    utf8_accept: bool,
    command_timeout: Duration,
) -> AppResult<bool> {
    let mut add_tokens: Vec<String> = Vec::new();
    let mut add_seen: HashSet<String> = HashSet::new();
    for lid in add_labels {
        if let Some(tok) =
            map_local_label_to_xgm_token_with_utf8(lid, user_label_names, utf8_accept)
            && add_seen.insert(tok.clone())
        {
            add_tokens.push(tok);
        }
    }

    let mut remove_tokens: Vec<String> = Vec::new();
    let mut remove_seen: HashSet<String> = HashSet::new();
    for lid in remove_labels {
        if let Some(tok) =
            map_local_label_to_xgm_token_with_utf8(lid, user_label_names, utf8_accept)
            && remove_seen.insert(tok.clone())
        {
            remove_tokens.push(tok);
        }
    }

    let mut did_store = false;
    if !add_tokens.is_empty() {
        let query = format!("+X-GM-LABELS ({})", add_tokens.join(" "));
        let _: Vec<_> = with_imap_timeout(
            command_timeout,
            "IMAP UID STORE +X-GM-LABELS",
            async {
                let stream = session.uid_store(uid_str, query).await?;
                stream.try_collect().await
            },
            |e| AppError::Upstream {
                status: 502,
                message: format!("IMAP UID STORE +X-GM-LABELS failed: {e}"),
            },
        )
        .await?;
        did_store = true;
    }

    if !remove_tokens.is_empty() {
        let query = format!("-X-GM-LABELS ({})", remove_tokens.join(" "));
        let _: Vec<_> = with_imap_timeout(
            command_timeout,
            "IMAP UID STORE -X-GM-LABELS",
            async {
                let stream = session.uid_store(uid_str, query).await?;
                stream.try_collect().await
            },
            |e| AppError::Upstream {
                status: 502,
                message: format!("IMAP UID STORE -X-GM-LABELS failed: {e}"),
            },
        )
        .await?;
        did_store = true;
    }

    Ok(did_store)
}

async fn apply_generic_folder_copies(
    session: &mut Session<UpstreamImapStream>,
    uid_str: &str,
    add_labels: &[String],
    user_label_names: &HashMap<String, String>,
    command_timeout: Duration,
) -> AppResult<bool> {
    let mut did_copy = false;
    for lid in add_labels {
        if is_system_label(lid) {
            continue;
        }
        let folder_name = user_label_names
            .get(lid)
            .map(String::as_str)
            .unwrap_or(lid)
            .trim();
        if folder_name.is_empty() || quote_imap_string(folder_name).is_none() {
            continue;
        }

        match tokio::time::timeout(command_timeout, session.uid_copy(uid_str, folder_name)).await {
            Ok(Ok(())) => {
                did_copy = true;
            }
            Ok(Err(copy_err)) => {
                debug!(
                    %copy_err,
                    folder = %folder_name,
                    "IMAP UID COPY failed; attempting CREATE then retry"
                );
                let _ = tokio::time::timeout(command_timeout, session.create(folder_name)).await;
                match tokio::time::timeout(command_timeout, session.uid_copy(uid_str, folder_name))
                    .await
                {
                    Ok(Ok(())) => did_copy = true,
                    Ok(Err(retry_err)) => {
                        warn!(
                            %retry_err,
                            folder = %folder_name,
                            "IMAP UID COPY retry failed after CREATE"
                        );
                    }
                    Err(_) => {
                        return Err(AppError::Upstream {
                            status: 504,
                            message: format!(
                                "IMAP UID COPY timed out after {}ms",
                                command_timeout.as_millis()
                            ),
                        });
                    }
                }
            }
            Err(_) => {
                return Err(AppError::Upstream {
                    status: 504,
                    message: format!(
                        "IMAP UID COPY timed out after {}ms",
                        command_timeout.as_millis()
                    ),
                });
            }
        }
    }
    Ok(did_copy)
}

async fn move_uid_to_archive(
    session: &mut Session<UpstreamImapStream>,
    uid_str: &str,
    archive_mailbox: &str,
    has_move: bool,
    has_uidplus: bool,
    command_timeout: Duration,
) -> AppResult<bool> {
    let target = if archive_mailbox.trim().is_empty() {
        "Archive"
    } else {
        archive_mailbox.trim()
    };

    if has_move {
        match tokio::time::timeout(command_timeout, session.uid_mv(uid_str, target)).await {
            Ok(Ok(())) => return Ok(true),
            Ok(Err(_)) => {
                let _ = tokio::time::timeout(command_timeout, session.create(target)).await;
                match tokio::time::timeout(command_timeout, session.uid_mv(uid_str, target)).await {
                    Ok(Ok(())) => return Ok(true),
                    Ok(Err(err)) => {
                        debug!(%err, target, "IMAP UID MOVE to archive failed after CREATE");
                    }
                    Err(_) => {
                        return Err(AppError::Upstream {
                            status: 504,
                            message: format!(
                                "IMAP UID MOVE to {target} timed out after {}ms",
                                command_timeout.as_millis()
                            ),
                        });
                    }
                }
            }
            Err(_) => {
                return Err(AppError::Upstream {
                    status: 504,
                    message: format!(
                        "IMAP UID MOVE to {target} timed out after {}ms",
                        command_timeout.as_millis()
                    ),
                });
            }
        }
    } else {
        let copied = match tokio::time::timeout(command_timeout, session.uid_copy(uid_str, target))
            .await
        {
            Ok(Ok(())) => true,
            Ok(Err(_)) => {
                let _ = tokio::time::timeout(command_timeout, session.create(target)).await;
                matches!(
                    tokio::time::timeout(command_timeout, session.uid_copy(uid_str, target)).await,
                    Ok(Ok(()))
                )
            }
            Err(_) => {
                return Err(AppError::Upstream {
                    status: 504,
                    message: format!(
                        "IMAP UID COPY to {target} timed out after {}ms",
                        command_timeout.as_millis()
                    ),
                });
            }
        };
        if copied {
            mark_deleted_and_expunge(session, uid_str, has_uidplus, command_timeout).await?;
            return Ok(true);
        }
    }

    Ok(false)
}

async fn move_uid_to_trash(
    session: &mut Session<UpstreamImapStream>,
    uid_str: &str,
    has_move: bool,
    command_timeout: Duration,
) -> AppResult<bool> {
    if !has_move {
        return Ok(false);
    }
    for trash_mbx in ["[Gmail]/Trash", "Trash"] {
        match tokio::time::timeout(command_timeout, session.uid_mv(uid_str, trash_mbx)).await {
            Ok(Ok(())) => return Ok(true),
            Ok(Err(_)) => continue,
            Err(_) => {
                return Err(AppError::Upstream {
                    status: 504,
                    message: format!(
                        "IMAP UID MOVE to Trash timed out after {}ms",
                        command_timeout.as_millis()
                    ),
                });
            }
        }
    }
    Ok(false)
}

struct AppendOutcome {
    uid_validity: Option<u32>,
    uid: Option<u32>,
}

async fn append_imap_message_with_uid(
    session: &mut Session<UpstreamImapStream>,
    mailbox: &str,
    flags: &str,
    internaldate: &str,
    raw_bytes: &[u8],
    command_timeout: Duration,
) -> AppResult<AppendOutcome> {
    let quoted_mbx = quote_imap_string(mailbox).ok_or_else(|| {
        AppError::BadRequest(format!("Invalid IMAP APPEND target mailbox: '{mailbox}'"))
    })?;
    let cmd = if flags.is_empty() {
        format!(
            "APPEND {quoted_mbx} \"{internaldate}\" {{{}}}",
            raw_bytes.len()
        )
    } else {
        format!(
            "APPEND {quoted_mbx} ({flags}) \"{internaldate}\" {{{}}}",
            raw_bytes.len()
        )
    };

    with_imap_timeout(
        command_timeout,
        "IMAP APPEND",
        async {
            let cmd_tag = session
                .run_command(&cmd)
                .await
                .map_err(|e| AppError::Upstream {
                    status: 502,
                    message: format!("IMAP APPEND send failed: {e}"),
                })?;

            // Wait for server literal continuation `+`.
            loop {
                let Some(resp) = session
                    .read_response()
                    .await
                    .map_err(|e| AppError::Upstream {
                        status: 502,
                        message: format!("IMAP APPEND continuation read error: {e}"),
                    })?
                else {
                    return Err(AppError::Upstream {
                        status: 502,
                        message: "IMAP connection closed waiting for APPEND continuation"
                            .to_string(),
                    });
                };
                match resp.parsed() {
                    ImapResponse::Continue(_) => break,
                    ImapResponse::Done {
                        tag,
                        status,
                        outcome,
                        ..
                    } if tag == &cmd_tag => {
                        return Err(AppError::Upstream {
                            status: 502,
                            message: format!("IMAP APPEND rejected ({status:?}): {outcome:?}"),
                        });
                    }
                    _ => {}
                }
            }

            let stream = session.get_mut();
            stream
                .write_all(raw_bytes)
                .await
                .map_err(|e| AppError::Upstream {
                    status: 502,
                    message: format!("IMAP APPEND literal write failed: {e}"),
                })?;
            stream
                .write_all(b"\r\n")
                .await
                .map_err(|e| AppError::Upstream {
                    status: 502,
                    message: format!("IMAP APPEND terminator write failed: {e}"),
                })?;
            stream.flush().await.map_err(|e| AppError::Upstream {
                status: 502,
                message: format!("IMAP APPEND flush failed: {e}"),
            })?;

            while let Some(resp) =
                session
                    .read_response()
                    .await
                    .map_err(|e| AppError::Upstream {
                        status: 502,
                        message: format!("IMAP APPEND completion read error: {e}"),
                    })?
            {
                if let ImapResponse::Done {
                    tag,
                    status,
                    outcome,
                    ..
                } = resp.parsed()
                    && tag == &cmd_tag
                {
                    if matches!(status, ImapStatus::Ok) {
                        let (uid_validity, uid) =
                            match parse_appenduid_response_code(outcome.code.as_ref()) {
                                Some((uv, u)) => (Some(uv), Some(u)),
                                None => (None, None),
                            };
                        return Ok(AppendOutcome { uid_validity, uid });
                    }
                    return Err(AppError::Upstream {
                        status: 502,
                        message: format!("IMAP APPEND failed ({status:?}): {outcome:?}"),
                    });
                }
            }

            Err(AppError::Upstream {
                status: 502,
                message: "IMAP connection closed before APPEND completion".to_string(),
            })
        },
        |err| err,
    )
    .await
}

fn build_append_flags(msg: &StoredMessage, is_draft: bool) -> String {
    let mut flags: Vec<&'static str> = Vec::new();
    if !msg.label_ids.iter().any(|l| l == LABEL_UNREAD) {
        flags.push("\\Seen");
    }
    if is_draft || msg.label_ids.iter().any(|l| l == LABEL_DRAFT) {
        flags.push("\\Draft");
    }
    if msg.label_ids.iter().any(|l| l == LABEL_STARRED) {
        flags.push("\\Flagged");
    }
    if msg.is_answered {
        flags.push("\\Answered");
    }
    flags.join(" ")
}

fn build_append_raw_bytes(msg: &StoredMessage) -> Vec<u8> {
    if !msg.raw_rfc2822.is_empty() {
        return msg.raw_rfc2822.clone();
    }
    let mut raw = String::new();
    if !msg.from_addr.is_empty() {
        raw.push_str(&format!("From: {}\r\n", msg.from_addr));
    }
    if !msg.to_addrs.is_empty() {
        raw.push_str(&format!("To: {}\r\n", msg.to_addrs.join(", ")));
    }
    if !msg.subject.is_empty() {
        raw.push_str(&format!("Subject: {}\r\n", msg.subject));
    }
    if let Some(ref mid) = msg.rfc822_message_id {
        raw.push_str(&format!("Message-ID: {mid}\r\n"));
    }
    raw.push_str("\r\n");
    raw.push_str(&msg.text_body);
    raw.into_bytes()
}

async fn push_local_message_via_append(
    session: &mut Session<UpstreamImapStream>,
    state: &AppState,
    msg: &StoredMessage,
    is_draft: bool,
    caps: &ImapServerCaps,
    command_timeout: Duration,
) -> AppResult<bool> {
    let candidates: &[&str] = match (is_draft, caps.has_xgm) {
        (true, true) => &["[Gmail]/Drafts", "Drafts"],
        (true, false) => &["Drafts", "[Gmail]/Drafts"],
        (false, true) => &["[Gmail]/Sent Mail", "Sent", "Sent Messages", "Sent Items"],
        (false, false) => &["Sent", "[Gmail]/Sent Mail", "Sent Messages", "Sent Items"],
    };

    let flags = build_append_flags(msg, is_draft);
    let internaldate = format_imap_internaldate(msg.internal_date_ms);
    let hydrated_raw = state.load_raw_rfc2822(msg).await?;
    let raw_bytes = if !hydrated_raw.is_empty() {
        hydrated_raw
    } else {
        build_append_raw_bytes(msg)
    };

    let mut appended: Option<(String, AppendOutcome)> = None;
    let mut last_err: Option<AppError> = None;
    for &mbx in candidates {
        match append_imap_message_with_uid(
            session,
            mbx,
            &flags,
            &internaldate,
            &raw_bytes,
            command_timeout,
        )
        .await
        {
            Ok(outcome) => {
                appended = Some((mbx.to_string(), outcome));
                break;
            }
            Err(err) => {
                debug!(mailbox = %mbx, %err, "IMAP APPEND candidate failed; trying next");
                last_err = Some(err);
            }
        }
    }

    // For non-Gmail servers where neither Sent nor Drafts existed yet, create the default folder
    // and retry once.
    if appended.is_none() && !caps.has_xgm {
        let default_mbx = if is_draft { "Drafts" } else { "Sent" };
        if matches!(
            tokio::time::timeout(command_timeout, session.create(default_mbx)).await,
            Ok(Ok(()))
        ) && let Ok(outcome) = append_imap_message_with_uid(
            session,
            default_mbx,
            &flags,
            &internaldate,
            &raw_bytes,
            command_timeout,
        )
        .await
        {
            appended = Some((default_mbx.to_string(), outcome));
        }
    }

    let Some((target_mailbox, outcome)) = appended else {
        if let Some(err) = last_err {
            return Err(err);
        }
        return Ok(false);
    };

    // Resolve canonical upstream_id (preferring X-GM-MSGID on Gmail servers so subsequent
    // `[Gmail]/All Mail` pulls deduplicate cleanly, falling back to `APPENDUID` or `Message-ID`).
    let mut resolved_upstream_id: Option<String> = None;
    let mut resolved_thread_id: Option<String> = None;

    let mut uid_validity = outcome.uid_validity;
    let mut assigned_uid = outcome.uid;

    if (caps.has_xgm || assigned_uid.is_none())
        && let Ok((_, examined_mbx)) =
            examine_imap_mailbox(session, &target_mailbox, command_timeout).await
    {
        if uid_validity.is_none() {
            uid_validity = examined_mbx.uid_validity;
        }
        if assigned_uid.is_none()
            && let Some(ref mid) = msg.rfc822_message_id
        {
            let safe_mid = mid.replace(['"', '\\', '\r', '\n'], "");
            if !safe_mid.is_empty()
                && let Ok(Ok(uids)) = tokio::time::timeout(
                    command_timeout,
                    session.uid_search(format!("HEADER Message-ID \"{safe_mid}\"")),
                )
                .await
            {
                assigned_uid = uids.into_iter().max();
            }
        }
        if caps.has_xgm
            && let Some(uid) = assigned_uid
            && let Ok(batch) = uid_fetch_batch_ext(
                session,
                &uid.to_string(),
                "(UID X-GM-MSGID X-GM-THRID)",
                None,
                0,
                command_timeout,
            )
            .await
            && let Some(fetched) = batch.messages.into_iter().next()
            && let Some(gm_id) = fetched.gmail_msg_id
        {
            resolved_upstream_id = Some(format!("{gm_id:x}"));
            resolved_thread_id = fetched.gmail_thr_id.map(|t| format!("{t:x}"));
        }
    }

    if resolved_upstream_id.is_none()
        && let Some(uid) = assigned_uid
    {
        resolved_upstream_id = Some(format!(
            "imap:{}:{}:{uid}",
            target_mailbox,
            uid_validity.unwrap_or(0)
        ));
    }

    if let Some(ref up_id) = resolved_upstream_id {
        let _ = state
            .store
            .link_message_upstream_id(&msg.id, up_id, resolved_thread_id.as_deref())
            .await?;
    }

    Ok(true)
}

async fn mark_deleted_and_expunge(
    session: &mut Session<UpstreamImapStream>,
    uid_str: &str,
    has_uidplus: bool,
    command_timeout: Duration,
) -> AppResult<()> {
    let _: Vec<_> = with_imap_timeout(
        command_timeout,
        "IMAP UID STORE (\\Deleted)",
        async {
            let stream = session.uid_store(uid_str, "+FLAGS (\\Deleted)").await?;
            stream.try_collect().await
        },
        |e| AppError::Upstream {
            status: 502,
            message: format!("IMAP UID STORE +FLAGS (\\Deleted) failed: {e}"),
        },
    )
    .await?;

    if has_uidplus {
        let _: Vec<_> = with_imap_timeout(
            command_timeout,
            "IMAP UID EXPUNGE",
            async {
                let exp = session.uid_expunge(uid_str).await?;
                exp.try_collect().await
            },
            |e| AppError::Upstream {
                status: 502,
                message: format!("IMAP UID EXPUNGE failed: {e}"),
            },
        )
        .await?;
    } else {
        let _: Vec<_> = with_imap_timeout(
            command_timeout,
            "IMAP EXPUNGE",
            async {
                let exp = session.expunge().await?;
                exp.try_collect().await
            },
            |e| AppError::Upstream {
                status: 502,
                message: format!("IMAP EXPUNGE failed: {e}"),
            },
        )
        .await?;
    }

    Ok(())
}
