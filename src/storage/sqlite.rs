//! SQLite-backed `MailStore` implementation (WAL mode + FTS5 + per-mailbox IMAP UIDs).
//!
//! Owned by the `storage` worker.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::Path,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior, params,
    types::Value as SqlValue,
};
use uuid::Uuid;

use crate::{
    error::{AppError, AppResult},
    models::{
        AttachmentMeta, AutoForwarding, EmailAddress, ImapSettings, LABEL_DRAFT, LABEL_INBOX,
        LABEL_SENT, LABEL_SPAM, LABEL_STARRED, LABEL_TRASH, LABEL_UNREAD, LabelColor, PopSettings,
        Profile, SYSTEM_LABEL_IDS, SendAs, ThreadSummary, VacationSettings, is_system_label,
    },
    storage::{
        AiMessagePage, AiSearchQuery, AiThreadPage, AiThreadQuery, DraftListPage, HistoryEventKind,
        HistoryListPage, HistoryListQuery, ImapMailboxInfo, ImapMessageEntry, MailStore,
        MessageListPage, MessageListQuery, NewLabelInput, NewMessageInput, StoredAttachment,
        StoredDraft, StoredHistoryEntry, StoredLabel, StoredMessage, StoredThreadDetail, SyncState,
        ThreadListPage, TriagePatch, TriageResult, UpdateLabelInput, UpsertOutcome,
        UpsertOutcomeKind, UserSettings, WatchSubscription, parse_simple_email_address,
    },
};

const ALL_MAIL_MAILBOX: &str = "[Gmail]/All Mail";
const SENT_MAILBOX: &str = "[Gmail]/Sent Mail";
const DRAFTS_MAILBOX: &str = "[Gmail]/Drafts";
const TRASH_MAILBOX: &str = "[Gmail]/Trash";
const SPAM_MAILBOX: &str = "[Gmail]/Spam";
const STARRED_MAILBOX: &str = "[Gmail]/Starred";

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    int_val INTEGER,
    text_val TEXT
);

CREATE TABLE IF NOT EXISTS labels (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    label_type TEXT NOT NULL,
    message_list_visibility TEXT,
    label_list_visibility TEXT,
    color_text TEXT,
    color_background TEXT,
    uid_validity INTEGER NOT NULL,
    uid_next INTEGER NOT NULL DEFAULT 1,
    upstream_label_id TEXT UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_labels_name_nocase ON labels (name COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS imap_meta (
    mailbox_name TEXT PRIMARY KEY,
    uid_validity INTEGER NOT NULL,
    uid_next INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    thread_id TEXT NOT NULL,
    raw_rfc2822 BLOB NOT NULL,
    snippet TEXT NOT NULL,
    history_id INTEGER NOT NULL,
    internal_date_ms INTEGER NOT NULL,
    size_estimate INTEGER NOT NULL,
    subject TEXT NOT NULL,
    from_addr TEXT NOT NULL,
    to_addrs_json TEXT NOT NULL,
    cc_addrs_json TEXT NOT NULL,
    bcc_addrs_json TEXT NOT NULL,
    text_body TEXT NOT NULL,
    html_body TEXT,
    has_attachments INTEGER NOT NULL DEFAULT 0,
    rfc822_message_id TEXT,
    rfc822_message_id_norm TEXT,
    in_reply_to TEXT,
    references_header TEXT,
    resend_id TEXT,
    delivery_status TEXT,
    upstream_gmail_id TEXT UNIQUE,
    upstream_thread_id TEXT,
    source TEXT NOT NULL DEFAULT 'local',
    all_mail_uid INTEGER NOT NULL,
    is_answered INTEGER NOT NULL DEFAULT 0,
    is_deleted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_messages_thread_id ON messages (thread_id, internal_date_ms, id);
CREATE INDEX IF NOT EXISTS idx_messages_date_id ON messages (internal_date_ms DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_messages_rfc822_norm ON messages (rfc822_message_id_norm);
CREATE INDEX IF NOT EXISTS idx_messages_resend_id ON messages (resend_id);
CREATE INDEX IF NOT EXISTS idx_messages_upstream_thread ON messages (upstream_thread_id);
CREATE INDEX IF NOT EXISTS idx_messages_all_mail_uid ON messages (all_mail_uid);

CREATE TABLE IF NOT EXISTS message_labels (
    message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    label_id TEXT NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
    imap_uid INTEGER NOT NULL,
    PRIMARY KEY (message_id, label_id)
);
CREATE INDEX IF NOT EXISTS idx_message_labels_label_uid ON message_labels (label_id, imap_uid);

CREATE TABLE IF NOT EXISTS attachments (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    part_id TEXT NOT NULL,
    filename TEXT,
    content_type TEXT NOT NULL,
    content_id TEXT,
    size_bytes INTEGER NOT NULL,
    data BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attachments_message_id ON attachments (message_id, part_id, id);

CREATE TABLE IF NOT EXISTS drafts (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL UNIQUE REFERENCES messages(id) ON DELETE CASCADE,
    updated_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_drafts_updated ON drafts (updated_at_ms DESC, id DESC);

CREATE TABLE IF NOT EXISTS history_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    history_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    message_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    label_ids_json TEXT NOT NULL,
    context_labels_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_history_events_hid ON history_events (history_id, id);

CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
    message_id UNINDEXED,
    subject,
    from_addr,
    to_addrs,
    cc_addrs,
    text_body,
    snippet,
    tokenize = 'porter unicode61'
);

CREATE TABLE IF NOT EXISTS sync_state (
    account_key TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    last_history_id TEXT,
    imap_mailbox TEXT,
    imap_uid_validity INTEGER,
    imap_last_uid INTEGER,
    last_sync_at_ms INTEGER,
    last_full_sync_at_ms INTEGER,
    status TEXT NOT NULL,
    last_error TEXT,
    messages_synced INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS watch_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    topic_name TEXT NOT NULL,
    label_ids_json TEXT NOT NULL,
    label_filter_behavior TEXT NOT NULL,
    history_id INTEGER NOT NULL,
    expiration_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL
);
"#;

/// SQLite-backed implementation of [`MailStore`].
#[derive(Clone)]
pub struct SqliteStore {
    pool: Pool<SqliteConnectionManager>,
    default_email: String,
}

impl SqliteStore {
    /// Open (or create) a SQLite database at `path`, run migrations, and seed system labels.
    pub fn open(path: &Path, default_email: &str) -> AppResult<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .map_err(|e| AppError::Storage(format!("Failed to create DB directory: {e}")))?;
        }

        let manager = SqliteConnectionManager::file(path).with_init(|conn| {
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA foreign_keys = ON;
                 PRAGMA synchronous = NORMAL;
                 PRAGMA busy_timeout = 5000;",
            )
        });
        let pool = Pool::builder()
            .max_size(16)
            .build(manager)
            .map_err(|e| AppError::Storage(format!("Failed to build SQLite pool: {e}")))?;

        let store = Self {
            pool,
            default_email: default_email.to_string(),
        };
        store.initialize()?;
        Ok(store)
    }

    /// Open an in-memory SQLite database (useful for SQLite-specific unit tests).
    pub fn open_in_memory(default_email: &str) -> AppResult<Self> {
        let manager = SqliteConnectionManager::memory().with_init(|conn| {
            conn.execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA synchronous = NORMAL;
                 PRAGMA busy_timeout = 5000;",
            )
        });
        // Single connection ensures all operations share the same `:memory:` database.
        let pool = Pool::builder().max_size(1).build(manager).map_err(|e| {
            AppError::Storage(format!("Failed to build in-memory SQLite pool: {e}"))
        })?;

        let store = Self {
            pool,
            default_email: default_email.to_string(),
        };
        store.initialize()?;
        Ok(store)
    }

    fn initialize(&self) -> AppResult<()> {
        let mut conn = self
            .pool
            .get()
            .map_err(|e| AppError::Storage(format!("SQLite pool error: {e}")))?;
        conn.execute_batch(SCHEMA_SQL).map_err(sql_err)?;

        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_err)?;

        tx.execute(
            "INSERT OR IGNORE INTO meta (key, int_val) VALUES ('history_id', 1)",
            [],
        )
        .map_err(sql_err)?;
        tx.execute(
            "INSERT OR IGNORE INTO meta (key, int_val) VALUES ('next_uid_validity', 1)",
            [],
        )
        .map_err(sql_err)?;

        // Seed [Gmail]/All Mail IMAP metadata
        let all_mail_exists: Option<i64> = tx
            .query_row(
                "SELECT uid_validity FROM imap_meta WHERE mailbox_name = ?1",
                params![ALL_MAIL_MAILBOX],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_err)?;
        if all_mail_exists.is_none() {
            let uv = alloc_uid_validity(&tx)?;
            tx.execute(
                "INSERT INTO imap_meta (mailbox_name, uid_validity, uid_next) VALUES (?1, ?2, 1)",
                params![ALL_MAIL_MAILBOX, uv as i64],
            )
            .map_err(sql_err)?;
        }

        // Seed system labels
        for &label_id in SYSTEM_LABEL_IDS {
            let exists: Option<String> = tx
                .query_row(
                    "SELECT id FROM labels WHERE id = ?1",
                    params![label_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?;
            if exists.is_none() {
                let uv = alloc_uid_validity(&tx)?;
                let (msg_vis, lbl_vis) = if label_id == LABEL_TRASH || label_id == LABEL_SPAM {
                    ("hide", "labelHide")
                } else {
                    ("show", "labelShow")
                };
                tx.execute(
                    "INSERT INTO labels
                     (id, name, label_type, message_list_visibility, label_list_visibility, uid_validity, uid_next)
                     VALUES (?1, ?2, 'system', ?3, ?4, ?5, 1)",
                    params![label_id, label_id, msg_vis, lbl_vis, uv as i64],
                )
                .map_err(sql_err)?;
            }
        }

        // Seed default user settings (primary sendAs, vacation, autoForwarding, imap, pop)
        let defaults = UserSettings::default_for_email(&self.default_email);
        seed_setting_if_missing(&tx, "send_as", &defaults.send_as)?;
        seed_setting_if_missing(&tx, "vacation", &defaults.vacation)?;
        seed_setting_if_missing(&tx, "auto_forwarding", &defaults.auto_forwarding)?;
        seed_setting_if_missing(&tx, "imap", &defaults.imap)?;
        seed_setting_if_missing(&tx, "pop", &defaults.pop)?;

        tx.commit().map_err(sql_err)?;
        Ok(())
    }

    async fn run_blocking<F, T>(&self, f: F) -> AppResult<T>
    where
        F: FnOnce(&mut Connection) -> AppResult<T> + Send + 'static,
        T: Send + 'static,
    {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool
                .get()
                .map_err(|e| AppError::Storage(format!("SQLite pool error: {e}")))?;
            f(&mut conn)
        })
        .await
        .map_err(|e| AppError::Storage(format!("SQLite blocking task failed: {e}")))?
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn sql_err(err: rusqlite::Error) -> AppError {
    AppError::Storage(err.to_string())
}

fn new_hex_id() -> String {
    Uuid::new_v4().simple().to_string()[..16].to_string()
}

fn normalize_rfc_message_id(raw: &str) -> Option<String> {
    let inner = raw
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim()
        .to_ascii_lowercase();
    if inner.is_empty() {
        None
    } else {
        Some(format!("<{inner}>"))
    }
}

fn seed_setting_if_missing<T: serde::Serialize>(
    tx: &Transaction<'_>,
    key: &str,
    value: &T,
) -> AppResult<()> {
    let json = serde_json::to_string(value)
        .map_err(|e| AppError::Storage(format!("Failed to serialize setting {key}: {e}")))?;
    tx.execute(
        "INSERT OR IGNORE INTO settings (key, value_json) VALUES (?1, ?2)",
        params![key, json],
    )
    .map_err(sql_err)?;
    Ok(())
}

fn alloc_uid_validity(tx: &Transaction<'_>) -> AppResult<u32> {
    let current: i64 = tx
        .query_row(
            "SELECT int_val FROM meta WHERE key = 'next_uid_validity'",
            [],
            |row| row.get(0),
        )
        .map_err(sql_err)?;
    tx.execute(
        "UPDATE meta SET int_val = ?1 WHERE key = 'next_uid_validity'",
        params![current + 1],
    )
    .map_err(sql_err)?;
    Ok(current.max(1) as u32)
}

fn bump_history_id(tx: &Transaction<'_>) -> AppResult<u64> {
    tx.execute(
        "UPDATE meta SET int_val = int_val + 1 WHERE key = 'history_id'",
        [],
    )
    .map_err(sql_err)?;
    let hid: i64 = tx
        .query_row(
            "SELECT int_val FROM meta WHERE key = 'history_id'",
            [],
            |row| row.get(0),
        )
        .map_err(sql_err)?;
    Ok(hid.max(1) as u64)
}

fn read_current_history_id(conn: &Connection) -> AppResult<u64> {
    let hid: i64 = conn
        .query_row(
            "SELECT int_val FROM meta WHERE key = 'history_id'",
            [],
            |row| row.get(0),
        )
        .map_err(sql_err)?;
    Ok(hid.max(1) as u64)
}

fn history_kind_to_str(kind: HistoryEventKind) -> &'static str {
    match kind {
        HistoryEventKind::MessageAdded => "messageAdded",
        HistoryEventKind::MessageDeleted => "messageDeleted",
        HistoryEventKind::LabelAdded => "labelAdded",
        HistoryEventKind::LabelRemoved => "labelRemoved",
    }
}

fn str_to_history_kind(s: &str) -> AppResult<HistoryEventKind> {
    match s {
        "messageAdded" => Ok(HistoryEventKind::MessageAdded),
        "messageDeleted" => Ok(HistoryEventKind::MessageDeleted),
        "labelAdded" => Ok(HistoryEventKind::LabelAdded),
        "labelRemoved" => Ok(HistoryEventKind::LabelRemoved),
        other => Err(AppError::Storage(format!(
            "Unknown history event kind: {other}"
        ))),
    }
}

fn record_history_event(
    tx: &Transaction<'_>,
    history_id: u64,
    kind: HistoryEventKind,
    message_id: &str,
    thread_id: &str,
    label_ids: &[String],
    context_labels: &[String],
) -> AppResult<()> {
    let labels_json = serde_json::to_string(label_ids)
        .map_err(|e| AppError::Storage(format!("JSON encode error: {e}")))?;
    let ctx_json = serde_json::to_string(context_labels)
        .map_err(|e| AppError::Storage(format!("JSON encode error: {e}")))?;
    tx.execute(
        "INSERT INTO history_events (history_id, kind, message_id, thread_id, label_ids_json, context_labels_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            history_id as i64,
            history_kind_to_str(kind),
            message_id,
            thread_id,
            labels_json,
            ctx_json
        ],
    )
    .map_err(sql_err)?;
    Ok(())
}

fn alloc_all_mail_uid(tx: &Transaction<'_>) -> AppResult<u32> {
    let uid: i64 = tx
        .query_row(
            "SELECT uid_next FROM imap_meta WHERE mailbox_name = ?1",
            params![ALL_MAIL_MAILBOX],
            |row| row.get(0),
        )
        .map_err(sql_err)?;
    tx.execute(
        "UPDATE imap_meta SET uid_next = ?1 WHERE mailbox_name = ?2",
        params![uid + 1, ALL_MAIL_MAILBOX],
    )
    .map_err(sql_err)?;
    Ok(uid.max(1) as u32)
}

fn alloc_label_uid(tx: &Transaction<'_>, label_id: &str) -> AppResult<u32> {
    let uid: i64 = tx
        .query_row(
            "SELECT uid_next FROM labels WHERE id = ?1",
            params![label_id],
            |row| row.get(0),
        )
        .map_err(sql_err)?;
    tx.execute(
        "UPDATE labels SET uid_next = ?1 WHERE id = ?2",
        params![uid + 1, label_id],
    )
    .map_err(sql_err)?;
    Ok(uid.max(1) as u32)
}

fn ensure_label_exists_tx(tx: &Transaction<'_>, raw_label: &str) -> AppResult<String> {
    let trimmed = raw_label.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest("Label ID cannot be empty".into()));
    }
    if let Some(id) = tx
        .query_row(
            "SELECT id FROM labels WHERE id = ?1",
            params![trimmed],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sql_err)?
    {
        return Ok(id);
    }
    if let Some(id) = tx
        .query_row(
            "SELECT id FROM labels WHERE name = ?1 COLLATE NOCASE",
            params![trimmed],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sql_err)?
    {
        return Ok(id);
    }
    if let Some(id) = tx
        .query_row(
            "SELECT id FROM labels WHERE upstream_label_id = ?1",
            params![trimmed],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sql_err)?
    {
        return Ok(id);
    }

    let uv = alloc_uid_validity(tx)?;
    tx.execute(
        "INSERT INTO labels (id, name, label_type, message_list_visibility, label_list_visibility, uid_validity, uid_next)
         VALUES (?1, ?2, 'user', 'show', 'labelShow', ?3, 1)",
        params![trimmed, trimmed, uv as i64],
    )
    .map_err(sql_err)?;
    Ok(trimmed.to_string())
}

fn resolve_existing_label_id(conn: &Connection, raw_label: &str) -> AppResult<Option<String>> {
    let trimmed = raw_label.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if let Some(id) = conn
        .query_row(
            "SELECT id FROM labels WHERE id = ?1",
            params![trimmed],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sql_err)?
    {
        return Ok(Some(id));
    }
    conn.query_row(
        "SELECT id FROM labels WHERE name = ?1 COLLATE NOCASE",
        params![trimmed],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(sql_err)
}

fn load_message_labels(conn: &Connection, message_id: &str) -> AppResult<Vec<String>> {
    let mut stmt = conn
        .prepare("SELECT label_id FROM message_labels WHERE message_id = ?1 ORDER BY label_id ASC")
        .map_err(sql_err)?;
    let rows = stmt
        .query_map(params![message_id], |row| row.get::<_, String>(0))
        .map_err(sql_err)?;
    let mut labels = Vec::new();
    for r in rows {
        labels.push(r.map_err(sql_err)?);
    }
    Ok(labels)
}

fn load_labels_for_messages(
    conn: &Connection,
    message_ids: &[String],
) -> AppResult<HashMap<String, Vec<String>>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    if message_ids.is_empty() {
        return Ok(map);
    }
    // Batch in chunks of 500 to stay well below SQLite's bind parameter limit.
    for chunk in message_ids.chunks(500) {
        let placeholders = (0..chunk.len())
            .map(|i| format!("?{}", i + 1))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT message_id, label_id FROM message_labels WHERE message_id IN ({placeholders}) ORDER BY label_id ASC"
        );
        let mut stmt = conn.prepare(&sql).map_err(sql_err)?;
        let params_vec: Vec<SqlValue> = chunk.iter().map(|id| SqlValue::Text(id.clone())).collect();
        let rows = stmt
            .query_map(rusqlite::params_from_iter(params_vec.iter()), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sql_err)?;
        for row in rows {
            let (mid, lid) = row.map_err(sql_err)?;
            map.entry(mid).or_default().push(lid);
        }
    }
    Ok(map)
}

fn message_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMessage> {
    let to_json: String = row.get("to_addrs_json")?;
    let cc_json: String = row.get("cc_addrs_json")?;
    let bcc_json: String = row.get("bcc_addrs_json")?;
    let to_addrs: Vec<String> = serde_json::from_str(&to_json).unwrap_or_default();
    let cc_addrs: Vec<String> = serde_json::from_str(&cc_json).unwrap_or_default();
    let bcc_addrs: Vec<String> = serde_json::from_str(&bcc_json).unwrap_or_default();

    Ok(StoredMessage {
        id: row.get("id")?,
        thread_id: row.get("thread_id")?,
        label_ids: Vec::new(),
        raw_rfc2822: row.get("raw_rfc2822")?,
        snippet: row.get("snippet")?,
        history_id: row.get::<_, i64>("history_id")?.max(0) as u64,
        internal_date_ms: row.get("internal_date_ms")?,
        size_estimate: row.get("size_estimate")?,
        subject: row.get("subject")?,
        from_addr: row.get("from_addr")?,
        to_addrs,
        cc_addrs,
        bcc_addrs,
        text_body: row.get("text_body")?,
        html_body: row.get("html_body")?,
        has_attachments: row.get::<_, i64>("has_attachments")? != 0,
        rfc822_message_id: row.get("rfc822_message_id")?,
        in_reply_to: row.get("in_reply_to")?,
        references_header: row.get("references_header")?,
        resend_id: row.get("resend_id")?,
        delivery_status: row.get("delivery_status")?,
        upstream_gmail_id: row.get("upstream_gmail_id")?,
        upstream_thread_id: row.get("upstream_thread_id")?,
        source: row.get("source")?,
        all_mail_uid: row.get::<_, i64>("all_mail_uid")?.max(0) as u32,
        is_answered: row.get::<_, i64>("is_answered")? != 0,
        is_deleted: row.get::<_, i64>("is_deleted")? != 0,
    })
}

fn load_message_by_id(conn: &Connection, id: &str) -> AppResult<Option<StoredMessage>> {
    let mut msg = match conn
        .query_row(
            "SELECT * FROM messages WHERE id = ?1",
            params![id],
            message_from_row,
        )
        .optional()
        .map_err(sql_err)?
    {
        Some(m) => m,
        None => return Ok(None),
    };
    msg.label_ids = load_message_labels(conn, &msg.id)?;
    Ok(Some(msg))
}

fn resolve_thread_id_tx(
    tx: &Transaction<'_>,
    input: &NewMessageInput,
    msg_id: &str,
) -> AppResult<String> {
    if let Some(ref tid) = input.thread_id
        && !tid.trim().is_empty()
    {
        return Ok(tid.trim().to_string());
    }
    if let Some(ref utid) = input.upstream_thread_id
        && !utid.trim().is_empty()
        && let Some(existing) = tx
            .query_row(
                "SELECT thread_id FROM messages WHERE upstream_thread_id = ?1 LIMIT 1",
                params![utid.trim()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(sql_err)?
    {
        return Ok(existing);
    }
    if let Some(ref irt) = input.in_reply_to
        && let Some(norm) = normalize_rfc_message_id(irt)
        && let Some(existing) = tx
            .query_row(
                "SELECT thread_id FROM messages WHERE rfc822_message_id_norm = ?1 LIMIT 1",
                params![norm],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(sql_err)?
    {
        return Ok(existing);
    }
    if let Some(ref refs) = input.references_header {
        for token in refs.split_whitespace().rev() {
            if let Some(norm) = normalize_rfc_message_id(token)
                && let Some(existing) = tx
                    .query_row(
                        "SELECT thread_id FROM messages WHERE rfc822_message_id_norm = ?1 LIMIT 1",
                        params![norm],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .map_err(sql_err)?
            {
                return Ok(existing);
            }
        }
    }
    Ok(msg_id.to_string())
}

fn insert_message_tx(tx: &Transaction<'_>, input: NewMessageInput) -> AppResult<StoredMessage> {
    let msg_id = input
        .id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(new_hex_id);
    let thread_id = resolve_thread_id_tx(tx, &input, &msg_id)?;

    // Resolve / ensure labels (deduplicated & sorted)
    let mut label_set = HashSet::new();
    let mut resolved_labels = Vec::new();
    for raw_label in &input.label_ids {
        let lid = ensure_label_exists_tx(tx, raw_label)?;
        if label_set.insert(lid.clone()) {
            resolved_labels.push(lid);
        }
    }
    resolved_labels.sort();

    let history_id = bump_history_id(tx)?;
    let all_mail_uid = alloc_all_mail_uid(tx)?;
    let size_estimate = input.raw_rfc2822.len().min(i32::MAX as usize) as i32;
    let has_attachments = !input.attachments.is_empty();
    let rfc_norm = input
        .rfc822_message_id
        .as_deref()
        .and_then(normalize_rfc_message_id);
    let source = if input.source.trim().is_empty() {
        "local".to_string()
    } else {
        input.source.clone()
    };

    let to_json = serde_json::to_string(&input.to_addrs)
        .map_err(|e| AppError::Storage(format!("JSON encode error: {e}")))?;
    let cc_json = serde_json::to_string(&input.cc_addrs)
        .map_err(|e| AppError::Storage(format!("JSON encode error: {e}")))?;
    let bcc_json = serde_json::to_string(&input.bcc_addrs)
        .map_err(|e| AppError::Storage(format!("JSON encode error: {e}")))?;

    tx.execute(
        "INSERT INTO messages (
            id, thread_id, raw_rfc2822, snippet, history_id, internal_date_ms, size_estimate,
            subject, from_addr, to_addrs_json, cc_addrs_json, bcc_addrs_json,
            text_body, html_body, has_attachments,
            rfc822_message_id, rfc822_message_id_norm, in_reply_to, references_header,
            resend_id, delivery_status, upstream_gmail_id, upstream_thread_id,
            source, all_mail_uid, is_answered, is_deleted
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7,
            ?8, ?9, ?10, ?11, ?12,
            ?13, ?14, ?15,
            ?16, ?17, ?18, ?19,
            ?20, NULL, ?21, ?22,
            ?23, ?24, ?25, ?26
        )",
        params![
            &msg_id,
            &thread_id,
            &input.raw_rfc2822,
            &input.snippet,
            history_id as i64,
            input.internal_date_ms,
            size_estimate,
            &input.subject,
            &input.from_addr,
            &to_json,
            &cc_json,
            &bcc_json,
            &input.text_body,
            &input.html_body,
            if has_attachments { 1_i64 } else { 0_i64 },
            &input.rfc822_message_id,
            &rfc_norm,
            &input.in_reply_to,
            &input.references_header,
            &input.resend_id,
            &input.upstream_gmail_id,
            &input.upstream_thread_id,
            &source,
            all_mail_uid as i64,
            if input.is_answered { 1_i64 } else { 0_i64 },
            if input.is_deleted { 1_i64 } else { 0_i64 },
        ],
    )
    .map_err(sql_err)?;

    for lid in &resolved_labels {
        let imap_uid = alloc_label_uid(tx, lid)?;
        tx.execute(
            "INSERT INTO message_labels (message_id, label_id, imap_uid) VALUES (?1, ?2, ?3)",
            params![&msg_id, lid, imap_uid as i64],
        )
        .map_err(sql_err)?;
    }

    for att in &input.attachments {
        let att_id = format!("att_{}", new_hex_id());
        tx.execute(
            "INSERT INTO attachments (id, message_id, part_id, filename, content_type, content_id, size_bytes, data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                att_id,
                &msg_id,
                &att.part_id,
                &att.filename,
                &att.content_type,
                &att.content_id,
                att.data.len() as i64,
                &att.data,
            ],
        )
        .map_err(sql_err)?;
    }

    // Index in FTS5 transactionally
    let to_joined = input.to_addrs.join(" ");
    let cc_joined = input.cc_addrs.join(" ");
    tx.execute(
        "INSERT INTO messages_fts (message_id, subject, from_addr, to_addrs, cc_addrs, text_body, snippet)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            &msg_id,
            &input.subject,
            &input.from_addr,
            &to_joined,
            &cc_joined,
            &input.text_body,
            &input.snippet,
        ],
    )
    .map_err(sql_err)?;

    record_history_event(
        tx,
        history_id,
        HistoryEventKind::MessageAdded,
        &msg_id,
        &thread_id,
        &resolved_labels,
        &resolved_labels,
    )?;

    Ok(StoredMessage {
        id: msg_id,
        thread_id,
        label_ids: resolved_labels,
        raw_rfc2822: input.raw_rfc2822,
        snippet: input.snippet,
        history_id,
        internal_date_ms: input.internal_date_ms,
        size_estimate,
        subject: input.subject,
        from_addr: input.from_addr,
        to_addrs: input.to_addrs,
        cc_addrs: input.cc_addrs,
        bcc_addrs: input.bcc_addrs,
        text_body: input.text_body,
        html_body: input.html_body,
        has_attachments,
        rfc822_message_id: input.rfc822_message_id,
        in_reply_to: input.in_reply_to,
        references_header: input.references_header,
        resend_id: input.resend_id,
        delivery_status: None,
        upstream_gmail_id: input.upstream_gmail_id,
        upstream_thread_id: input.upstream_thread_id,
        source,
        all_mail_uid,
        is_answered: input.is_answered,
        is_deleted: input.is_deleted,
    })
}

fn modify_message_labels_resolved_tx(
    tx: &Transaction<'_>,
    message_id: &str,
    resolved_add: &[String],
    resolved_remove: &[String],
) -> AppResult<StoredMessage> {
    let mut msg = load_message_by_id(tx, message_id)?
        .ok_or_else(|| AppError::NotFound(format!("Message not found: {message_id}")))?;

    let current_set: HashSet<String> = msg.label_ids.iter().cloned().collect();
    let remove_set: HashSet<&String> = resolved_remove.iter().collect();

    let mut actually_added = Vec::new();
    let mut add_seen = HashSet::new();
    for lid in resolved_add {
        if !remove_set.contains(lid) && !current_set.contains(lid) && add_seen.insert(lid.clone()) {
            actually_added.push(lid.clone());
        }
    }

    let mut actually_removed = Vec::new();
    let mut rem_seen = HashSet::new();
    for lid in resolved_remove {
        if current_set.contains(lid) && rem_seen.insert(lid.clone()) {
            actually_removed.push(lid.clone());
        }
    }

    if !actually_added.is_empty() || !actually_removed.is_empty() {
        let new_hid = bump_history_id(tx)?;
        tx.execute(
            "UPDATE messages SET history_id = ?1 WHERE id = ?2",
            params![new_hid as i64, message_id],
        )
        .map_err(sql_err)?;

        for lid in &actually_added {
            let imap_uid = alloc_label_uid(tx, lid)?;
            tx.execute(
                "INSERT OR IGNORE INTO message_labels (message_id, label_id, imap_uid) VALUES (?1, ?2, ?3)",
                params![message_id, lid, imap_uid as i64],
            )
            .map_err(sql_err)?;
        }

        for lid in &actually_removed {
            tx.execute(
                "DELETE FROM message_labels WHERE message_id = ?1 AND label_id = ?2",
                params![message_id, lid],
            )
            .map_err(sql_err)?;
        }

        let mut context_set = current_set.clone();
        for lid in &actually_added {
            context_set.insert(lid.clone());
        }
        let mut context_labels: Vec<String> = context_set.into_iter().collect();
        context_labels.sort();

        if !actually_added.is_empty() {
            record_history_event(
                tx,
                new_hid,
                HistoryEventKind::LabelAdded,
                message_id,
                &msg.thread_id,
                &actually_added,
                &context_labels,
            )?;
        }
        if !actually_removed.is_empty() {
            record_history_event(
                tx,
                new_hid,
                HistoryEventKind::LabelRemoved,
                message_id,
                &msg.thread_id,
                &actually_removed,
                &context_labels,
            )?;
        }

        msg.history_id = new_hid;
        msg.label_ids = load_message_labels(tx, message_id)?;
    }

    Ok(msg)
}

fn delete_message_tx(tx: &Transaction<'_>, id: &str) -> AppResult<Option<StoredMessage>> {
    let Some(msg) = load_message_by_id(tx, id)? else {
        return Ok(None);
    };
    let hid = bump_history_id(tx)?;
    tx.execute(
        "DELETE FROM messages_fts WHERE message_id = ?1",
        params![id],
    )
    .map_err(sql_err)?;
    tx.execute("DELETE FROM messages WHERE id = ?1", params![id])
        .map_err(sql_err)?;
    record_history_event(
        tx,
        hid,
        HistoryEventKind::MessageDeleted,
        &msg.id,
        &msg.thread_id,
        &msg.label_ids,
        &msg.label_ids,
    )?;
    Ok(Some(msg))
}

fn load_label_with_counts(conn: &Connection, id: &str) -> AppResult<Option<StoredLabel>> {
    let row = conn
        .query_row(
            "SELECT
                l.id, l.name, l.label_type, l.message_list_visibility, l.label_list_visibility,
                l.color_text, l.color_background, l.uid_validity, l.uid_next, l.upstream_label_id,
                (SELECT COUNT(*) FROM message_labels ml WHERE ml.label_id = l.id) AS messages_total,
                (SELECT COUNT(*) FROM message_labels ml
                 INNER JOIN message_labels mu ON mu.message_id = ml.message_id AND mu.label_id = ?2
                 WHERE ml.label_id = l.id) AS messages_unread,
                (SELECT COUNT(DISTINCT m.thread_id) FROM message_labels ml
                 INNER JOIN messages m ON m.id = ml.message_id
                 WHERE ml.label_id = l.id) AS threads_total,
                (SELECT COUNT(DISTINCT m.thread_id) FROM message_labels ml
                 INNER JOIN messages m ON m.id = ml.message_id
                 INNER JOIN message_labels mu ON mu.message_id = ml.message_id AND mu.label_id = ?2
                 WHERE ml.label_id = l.id) AS threads_unread
             FROM labels l
             WHERE l.id = ?1",
            params![id, LABEL_UNREAD],
            label_from_row,
        )
        .optional()
        .map_err(sql_err)?;
    Ok(row)
}

fn label_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredLabel> {
    let color_text: Option<String> = row.get("color_text")?;
    let color_bg: Option<String> = row.get("color_background")?;
    let color = match (color_text, color_bg) {
        (Some(text_color), Some(background_color)) => Some(LabelColor {
            text_color,
            background_color,
        }),
        _ => None,
    };
    Ok(StoredLabel {
        id: row.get("id")?,
        name: row.get("name")?,
        label_type: row.get("label_type")?,
        message_list_visibility: row.get("message_list_visibility")?,
        label_list_visibility: row.get("label_list_visibility")?,
        color,
        messages_total: row.get("messages_total")?,
        messages_unread: row.get("messages_unread")?,
        threads_total: row.get("threads_total")?,
        threads_unread: row.get("threads_unread")?,
        uid_validity: row.get::<_, i64>("uid_validity")?.max(1) as u32,
        uid_next: row.get::<_, i64>("uid_next")?.max(1) as u32,
        upstream_label_id: row.get("upstream_label_id")?,
    })
}

fn load_thread_detail_conn(
    conn: &Connection,
    thread_id: &str,
) -> AppResult<Option<StoredThreadDetail>> {
    let mut stmt = conn
        .prepare(
            "SELECT * FROM messages WHERE thread_id = ?1 ORDER BY internal_date_ms ASC, id ASC",
        )
        .map_err(sql_err)?;
    let rows = stmt
        .query_map(params![thread_id], message_from_row)
        .map_err(sql_err)?;
    let mut messages = Vec::new();
    for r in rows {
        messages.push(r.map_err(sql_err)?);
    }
    if messages.is_empty() {
        return Ok(None);
    }
    let ids: Vec<String> = messages.iter().map(|m| m.id.clone()).collect();
    let mut label_map = load_labels_for_messages(conn, &ids)?;
    for m in &mut messages {
        m.label_ids = label_map.remove(&m.id).unwrap_or_default();
    }
    let snippet = messages
        .last()
        .map(|m| m.snippet.clone())
        .unwrap_or_default();
    let history_id = messages.iter().map(|m| m.history_id).max().unwrap_or(1);
    Ok(Some(StoredThreadDetail {
        id: thread_id.to_string(),
        snippet,
        history_id,
        messages,
    }))
}

fn parse_offset_token(token: Option<&str>) -> AppResult<usize> {
    match token {
        None => Ok(0),
        Some(s) if s.trim().is_empty() => Ok(0),
        Some(s) => s
            .trim()
            .parse::<usize>()
            .map_err(|_| AppError::BadRequest(format!("Invalid pageToken: {s}"))),
    }
}

fn encode_keyset_cursor(ts_ms: i64, id: &str) -> String {
    format!("{ts_ms}:{id}")
}

fn decode_keyset_cursor(cursor: &str) -> AppResult<(i64, String)> {
    let (ts_part, id_part) = cursor
        .split_once(':')
        .ok_or_else(|| AppError::BadRequest(format!("Invalid cursor: {cursor}")))?;
    let ts_ms = ts_part
        .parse::<i64>()
        .map_err(|_| AppError::BadRequest(format!("Invalid cursor timestamp: {cursor}")))?;
    if id_part.is_empty() {
        return Err(AppError::BadRequest(format!("Invalid cursor id: {cursor}")));
    }
    Ok((ts_ms, id_part.to_string()))
}

/// Build a safe FTS5 MATCH expression from arbitrary user text.
/// Returns `None` if the query has no alphanumeric terms (caller falls back to LIKE).
fn build_fts5_query(raw: &str) -> Option<String> {
    let mut tokens = Vec::new();
    let mut chars = raw.chars().peekable();
    while let Some(&ch) = chars.peek() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }
        if ch == '"' {
            chars.next();
            let mut phrase = String::new();
            for c in chars.by_ref() {
                if c == '"' {
                    break;
                }
                phrase.push(c);
            }
            let trimmed = phrase.trim();
            if trimmed.chars().any(|c| c.is_alphanumeric()) {
                tokens.push(format!("\"{}\"", trimmed.replace('"', "\"\"")));
            }
        } else {
            let mut word = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() || c == '"' {
                    break;
                }
                word.push(c);
                chars.next();
            }
            if word.chars().any(|c| c.is_alphanumeric()) {
                tokens.push(format!("\"{}\"", word.replace('"', "\"\"")));
            }
        }
    }
    if tokens.is_empty() {
        None
    } else {
        Some(tokens.join(" "))
    }
}

fn build_thread_summary(thread_id: &str, messages: &[StoredMessage]) -> ThreadSummary {
    let subject = messages
        .first()
        .map(|m| m.subject.clone())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            messages
                .iter()
                .rev()
                .find(|m| !m.subject.is_empty())
                .map(|m| m.subject.clone())
        })
        .unwrap_or_default();

    let mut seen_emails = HashSet::new();
    let mut participants: Vec<EmailAddress> = Vec::new();
    for msg in messages {
        if !msg.from_addr.trim().is_empty() {
            let parsed = parse_simple_email_address(&msg.from_addr);
            let key = parsed.email.to_ascii_lowercase();
            if !key.is_empty() && seen_emails.insert(key) {
                participants.push(parsed);
            }
        }
    }

    let snippet = messages
        .last()
        .map(|m| m.snippet.clone())
        .unwrap_or_default();

    let mut label_set = HashSet::new();
    let mut has_attachments = false;
    let mut max_ts = i64::MIN;
    for msg in messages {
        for l in &msg.label_ids {
            label_set.insert(l.clone());
        }
        if msg.has_attachments {
            has_attachments = true;
        }
        if msg.internal_date_ms > max_ts {
            max_ts = msg.internal_date_ms;
        }
    }
    let mut labels: Vec<String> = label_set.into_iter().collect();
    labels.sort();
    let unread = labels.iter().any(|l| l == LABEL_UNREAD);
    let last_message_at = DateTime::from_timestamp_millis(max_ts).unwrap_or_else(Utc::now);

    ThreadSummary {
        id: thread_id.to_string(),
        subject,
        participants,
        snippet,
        labels,
        unread,
        has_attachments,
        message_count: messages.len(),
        last_message_at,
    }
}

enum ResolvedMailbox {
    AllMail,
    Label {
        id: String,
        name: String,
        special_use: Option<&'static str>,
    },
}

fn resolve_imap_mailbox(
    conn: &Connection,
    mailbox_name: &str,
) -> AppResult<Option<ResolvedMailbox>> {
    if mailbox_name.eq_ignore_ascii_case("INBOX") {
        return Ok(Some(ResolvedMailbox::Label {
            id: LABEL_INBOX.to_string(),
            name: "INBOX".to_string(),
            special_use: None,
        }));
    }
    if mailbox_name == ALL_MAIL_MAILBOX {
        return Ok(Some(ResolvedMailbox::AllMail));
    }
    if mailbox_name == SENT_MAILBOX {
        return Ok(Some(ResolvedMailbox::Label {
            id: LABEL_SENT.to_string(),
            name: SENT_MAILBOX.to_string(),
            special_use: Some("\\Sent"),
        }));
    }
    if mailbox_name == DRAFTS_MAILBOX {
        return Ok(Some(ResolvedMailbox::Label {
            id: LABEL_DRAFT.to_string(),
            name: DRAFTS_MAILBOX.to_string(),
            special_use: Some("\\Drafts"),
        }));
    }
    if mailbox_name == TRASH_MAILBOX {
        return Ok(Some(ResolvedMailbox::Label {
            id: LABEL_TRASH.to_string(),
            name: TRASH_MAILBOX.to_string(),
            special_use: Some("\\Trash"),
        }));
    }
    if mailbox_name == SPAM_MAILBOX {
        return Ok(Some(ResolvedMailbox::Label {
            id: LABEL_SPAM.to_string(),
            name: SPAM_MAILBOX.to_string(),
            special_use: Some("\\Junk"),
        }));
    }
    if mailbox_name == STARRED_MAILBOX {
        return Ok(Some(ResolvedMailbox::Label {
            id: LABEL_STARRED.to_string(),
            name: STARRED_MAILBOX.to_string(),
            special_use: Some("\\Flagged"),
        }));
    }

    let user_label: Option<(String, String)> = conn
        .query_row(
            "SELECT id, name FROM labels WHERE label_type = 'user' AND name = ?1",
            params![mailbox_name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sql_err)?;
    Ok(user_label.map(|(id, name)| ResolvedMailbox::Label {
        id,
        name,
        special_use: None,
    }))
}

fn load_imap_mailbox_info_resolved(
    conn: &Connection,
    resolved: &ResolvedMailbox,
) -> AppResult<ImapMailboxInfo> {
    match resolved {
        ResolvedMailbox::AllMail => {
            let (uv, un): (i64, i64) = conn
                .query_row(
                    "SELECT uid_validity, uid_next FROM imap_meta WHERE mailbox_name = ?1",
                    params![ALL_MAIL_MAILBOX],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(sql_err)?;
            let messages: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM messages m
                     WHERE NOT EXISTS (
                         SELECT 1 FROM message_labels ml
                         WHERE ml.message_id = m.id AND ml.label_id IN (?1, ?2)
                     )",
                    params![LABEL_TRASH, LABEL_SPAM],
                    |row| row.get(0),
                )
                .map_err(sql_err)?;
            let unseen: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM messages m
                     WHERE EXISTS (
                         SELECT 1 FROM message_labels mu
                         WHERE mu.message_id = m.id AND mu.label_id = ?3
                     )
                     AND NOT EXISTS (
                         SELECT 1 FROM message_labels ml
                         WHERE ml.message_id = m.id AND ml.label_id IN (?1, ?2)
                     )",
                    params![LABEL_TRASH, LABEL_SPAM, LABEL_UNREAD],
                    |row| row.get(0),
                )
                .map_err(sql_err)?;
            Ok(ImapMailboxInfo {
                name: ALL_MAIL_MAILBOX.to_string(),
                label_id: None,
                special_use: Some("\\All".to_string()),
                uid_validity: uv.max(1) as u32,
                uid_next: un.max(1) as u32,
                messages: messages.max(0) as u32,
                unseen: unseen.max(0) as u32,
            })
        }
        ResolvedMailbox::Label {
            id,
            name,
            special_use,
        } => {
            let (uv, un): (i64, i64) = conn
                .query_row(
                    "SELECT uid_validity, uid_next FROM labels WHERE id = ?1",
                    params![id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(sql_err)?;
            let messages: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM message_labels WHERE label_id = ?1",
                    params![id],
                    |row| row.get(0),
                )
                .map_err(sql_err)?;
            let unseen: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM message_labels ml
                     INNER JOIN message_labels mu ON mu.message_id = ml.message_id AND mu.label_id = ?2
                     WHERE ml.label_id = ?1",
                    params![id, LABEL_UNREAD],
                    |row| row.get(0),
                )
                .map_err(sql_err)?;
            Ok(ImapMailboxInfo {
                name: name.clone(),
                label_id: Some(id.clone()),
                special_use: special_use.map(ToString::to_string),
                uid_validity: uv.max(1) as u32,
                uid_next: un.max(1) as u32,
                messages: messages.max(0) as u32,
                unseen: unseen.max(0) as u32,
            })
        }
    }
}

fn load_imap_messages_resolved(
    conn: &Connection,
    resolved: &ResolvedMailbox,
) -> AppResult<Vec<ImapMessageEntry>> {
    let raw_entries: Vec<(u32, String, String, i64, i32, bool, bool)> = match resolved {
        ResolvedMailbox::AllMail => {
            let mut stmt = conn
                .prepare(
                    "SELECT m.all_mail_uid, m.id, m.thread_id, m.internal_date_ms, m.size_estimate, m.is_answered, m.is_deleted
                     FROM messages m
                     WHERE NOT EXISTS (
                         SELECT 1 FROM message_labels ml
                         WHERE ml.message_id = m.id AND ml.label_id IN (?1, ?2)
                     )
                     ORDER BY m.all_mail_uid ASC",
                )
                .map_err(sql_err)?;
            let rows = stmt
                .query_map(params![LABEL_TRASH, LABEL_SPAM], |row| {
                    Ok((
                        row.get::<_, i64>(0)?.max(1) as u32,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i32>(4)?,
                        row.get::<_, i64>(5)? != 0,
                        row.get::<_, i64>(6)? != 0,
                    ))
                })
                .map_err(sql_err)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(sql_err)?);
            }
            out
        }
        ResolvedMailbox::Label { id, .. } => {
            let mut stmt = conn
                .prepare(
                    "SELECT ml.imap_uid, m.id, m.thread_id, m.internal_date_ms, m.size_estimate, m.is_answered, m.is_deleted
                     FROM message_labels ml
                     INNER JOIN messages m ON m.id = ml.message_id
                     WHERE ml.label_id = ?1
                     ORDER BY ml.imap_uid ASC",
                )
                .map_err(sql_err)?;
            let rows = stmt
                .query_map(params![id], |row| {
                    Ok((
                        row.get::<_, i64>(0)?.max(1) as u32,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i32>(4)?,
                        row.get::<_, i64>(5)? != 0,
                        row.get::<_, i64>(6)? != 0,
                    ))
                })
                .map_err(sql_err)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(sql_err)?);
            }
            out
        }
    };

    let ids: Vec<String> = raw_entries.iter().map(|e| e.1.clone()).collect();
    let mut label_map = load_labels_for_messages(conn, &ids)?;

    let mut entries = Vec::with_capacity(raw_entries.len());
    for (
        idx,
        (uid, message_id, thread_id, internal_date_ms, size_estimate, is_answered, is_deleted),
    ) in raw_entries.into_iter().enumerate()
    {
        let label_ids = label_map.remove(&message_id).unwrap_or_default();
        entries.push(ImapMessageEntry {
            seq: (idx + 1) as u32,
            uid,
            message_id,
            thread_id,
            internal_date_ms,
            size_estimate,
            label_ids,
            is_answered,
            is_deleted,
        });
    }
    Ok(entries)
}

fn rewrite_search_term_labels(
    term: crate::search::SearchTerm,
    name_to_id: &HashMap<String, String>,
) -> crate::search::SearchTerm {
    use crate::search::SearchTerm;
    match term {
        SearchTerm::Label(val) => {
            let key_exact = val.to_ascii_lowercase();
            let key_hyphen = key_exact.replace('/', "-");
            if let Some(id) = name_to_id
                .get(&key_exact)
                .or_else(|| name_to_id.get(&key_hyphen))
            {
                SearchTerm::Or(vec![SearchTerm::Label(val), SearchTerm::Label(id.clone())])
            } else {
                SearchTerm::Label(val)
            }
        }
        SearchTerm::InMailbox(val) => {
            let key_exact = val.to_ascii_lowercase();
            let key_hyphen = key_exact.replace('/', "-");
            if let Some(id) = name_to_id
                .get(&key_exact)
                .or_else(|| name_to_id.get(&key_hyphen))
            {
                SearchTerm::Or(vec![
                    SearchTerm::InMailbox(val),
                    SearchTerm::Label(id.clone()),
                ])
            } else {
                SearchTerm::InMailbox(val)
            }
        }
        SearchTerm::Not(inner) => {
            SearchTerm::Not(Box::new(rewrite_search_term_labels(*inner, name_to_id)))
        }
        SearchTerm::And(terms) => SearchTerm::And(
            terms
                .into_iter()
                .map(|t| rewrite_search_term_labels(t, name_to_id))
                .collect(),
        ),
        SearchTerm::Or(terms) => SearchTerm::Or(
            terms
                .into_iter()
                .map(|t| rewrite_search_term_labels(t, name_to_id))
                .collect(),
        ),
        other => other,
    }
}

fn load_label_name_to_id_map(conn: &Connection) -> AppResult<HashMap<String, String>> {
    let mut stmt = conn
        .prepare("SELECT id, name FROM labels")
        .map_err(sql_err)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sql_err)?;
    let mut map = HashMap::new();
    for r in rows {
        let (id, name) = r.map_err(sql_err)?;
        let lower = name.to_ascii_lowercase();
        let hyphen = lower.replace('/', "-");
        map.insert(lower, id.clone());
        map.insert(hyphen, id);
    }
    Ok(map)
}

fn parse_query_with_labels(
    conn: &Connection,
    raw_q: &str,
) -> AppResult<crate::search::SearchQuery> {
    let mut parsed = crate::search::parse_query(raw_q);
    if !parsed.terms.is_empty() {
        let map = load_label_name_to_id_map(conn)?;
        parsed.terms = parsed
            .terms
            .into_iter()
            .map(|t| rewrite_search_term_labels(t, &map))
            .collect();
    }
    Ok(parsed)
}

fn load_all_messages_filtered(
    conn: &Connection,
    label_ids: &[String],
    include_spam_trash: bool,
    q: Option<&str>,
) -> AppResult<Vec<StoredMessage>> {
    let parsed_q = match q.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => Some(parse_query_with_labels(conn, raw)?),
        None => None,
    };

    let explicit_spam_trash = label_ids
        .iter()
        .any(|l| l == LABEL_TRASH || l == LABEL_SPAM);
    let effective_include_spam_trash = include_spam_trash
        || explicit_spam_trash
        || parsed_q.as_ref().is_some_and(|pq| pq.include_spam_trash);

    let mut sql = String::from("SELECT m.* FROM messages m WHERE 1=1");
    let mut bind_values: Vec<SqlValue> = Vec::new();

    if !effective_include_spam_trash {
        bind_values.push(SqlValue::Text(LABEL_TRASH.to_string()));
        let p1 = bind_values.len();
        bind_values.push(SqlValue::Text(LABEL_SPAM.to_string()));
        let p2 = bind_values.len();
        sql.push_str(&format!(
            " AND NOT EXISTS (SELECT 1 FROM message_labels ml_ex WHERE ml_ex.message_id = m.id AND ml_ex.label_id IN (?{p1}, ?{p2}))"
        ));
    }

    for lid in label_ids {
        let resolved = resolve_existing_label_id(conn, lid)?.unwrap_or_else(|| lid.clone());
        bind_values.push(SqlValue::Text(resolved));
        let p = bind_values.len();
        sql.push_str(&format!(
            " AND EXISTS (SELECT 1 FROM message_labels ml_in WHERE ml_in.message_id = m.id AND ml_in.label_id = ?{p})"
        ));
    }

    sql.push_str(" ORDER BY m.internal_date_ms DESC, m.id DESC");

    let mut stmt = conn.prepare(&sql).map_err(sql_err)?;
    let rows = stmt
        .query_map(
            rusqlite::params_from_iter(bind_values.iter()),
            message_from_row,
        )
        .map_err(sql_err)?;
    let mut messages = Vec::new();
    for r in rows {
        messages.push(r.map_err(sql_err)?);
    }

    let ids: Vec<String> = messages.iter().map(|m| m.id.clone()).collect();
    let mut label_map = load_labels_for_messages(conn, &ids)?;
    for m in &mut messages {
        m.label_ids = label_map.remove(&m.id).unwrap_or_default();
    }

    if let Some(ref pq) = parsed_q {
        messages.retain(|m| crate::search::matches_message(pq, m));
    }

    Ok(messages)
}

fn read_setting<T: serde::de::DeserializeOwned>(
    conn: &Connection,
    key: &str,
) -> AppResult<Option<T>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value_json FROM settings WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql_err)?;
    match raw {
        Some(json) => serde_json::from_str(&json)
            .map(Some)
            .map_err(|e| AppError::Storage(format!("Failed to decode setting {key}: {e}"))),
        None => Ok(None),
    }
}

fn write_setting<T: serde::Serialize>(tx: &Transaction<'_>, key: &str, value: &T) -> AppResult<()> {
    let json = serde_json::to_string(value)
        .map_err(|e| AppError::Storage(format!("Failed to encode setting {key}: {e}")))?;
    tx.execute(
        "INSERT INTO settings (key, value_json) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json",
        params![key, json],
    )
    .map_err(sql_err)?;
    Ok(())
}

// ============================================================================
// `MailStore` Implementation
// ============================================================================

#[async_trait]
impl MailStore for SqliteStore {
    fn backend_name(&self) -> &'static str {
        "sqlite"
    }
    async fn get_profile(&self, email_address: &str) -> AppResult<Profile> {
        let email = if email_address.trim().is_empty() {
            self.default_email.clone()
        } else {
            email_address.to_string()
        };
        self.run_blocking(move |conn| {
            let messages_total: i32 = conn
                .query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
                .map_err(sql_err)?;
            let threads_total: i32 = conn
                .query_row(
                    "SELECT COUNT(DISTINCT thread_id) FROM messages",
                    [],
                    |row| row.get(0),
                )
                .map_err(sql_err)?;
            let history_id = read_current_history_id(conn)?;
            Ok(Profile {
                email_address: email,
                messages_total,
                threads_total,
                history_id: history_id.to_string(),
            })
        })
        .await
    }

    async fn current_history_id(&self) -> AppResult<u64> {
        self.run_blocking(|conn| read_current_history_id(conn))
            .await
    }

    async fn list_history(&self, query: &HistoryListQuery) -> AppResult<HistoryListPage> {
        let query = query.clone();
        self.run_blocking(move |conn| {
            if query.start_history_id == 0 {
                return Err(AppError::NotFound(
                    "Invalid startHistoryId: must be greater than 0".into(),
                ));
            }
            let current_hid = read_current_history_id(conn)?;
            let after_row_id: i64 = match query.page_token.as_deref() {
                None => 0,
                Some(s) if s.trim().is_empty() => 0,
                Some(s) => s
                    .trim()
                    .parse::<i64>()
                    .map_err(|_| AppError::BadRequest(format!("Invalid pageToken: {s}")))?,
            };
            let max_results = if query.max_results == 0 {
                100
            } else {
                query.max_results.min(500)
            };

            let resolved_label_filter = match query.label_id.as_deref() {
                Some(l) if !l.trim().is_empty() => {
                    Some(resolve_existing_label_id(conn, l)?.unwrap_or_else(|| l.to_string()))
                }
                _ => None,
            };

            let mut stmt = conn
                .prepare(
                    "SELECT id, history_id, kind, message_id, thread_id, label_ids_json, context_labels_json
                     FROM history_events
                     WHERE history_id > ?1 AND id > ?2
                     ORDER BY id ASC",
                )
                .map_err(sql_err)?;

            let rows = stmt
                .query_map(params![query.start_history_id as i64, after_row_id], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                })
                .map_err(sql_err)?;

            let mut matched: Vec<(i64, StoredHistoryEntry)> = Vec::new();
            for row in rows {
                let (row_id, hid, kind_str, message_id, thread_id, labels_json, ctx_json) =
                    row.map_err(sql_err)?;
                let kind = str_to_history_kind(&kind_str)?;
                if !query.history_types.is_empty() && !query.history_types.contains(&kind) {
                    continue;
                }
                let label_ids: Vec<String> = serde_json::from_str(&labels_json).unwrap_or_default();
                let ctx_labels: Vec<String> = serde_json::from_str(&ctx_json).unwrap_or_default();
                if let Some(ref filter_lid) = resolved_label_filter
                    && !label_ids.contains(filter_lid)
                    && !ctx_labels.contains(filter_lid)
                {
                    continue;
                }
                matched.push((
                    row_id,
                    StoredHistoryEntry {
                        history_id: hid.max(1) as u64,
                        kind,
                        message_id,
                        thread_id,
                        label_ids,
                    },
                ));
                if matched.len() > max_results {
                    break;
                }
            }

            let has_more = matched.len() > max_results;
            if has_more {
                matched.truncate(max_results);
            }
            let next_page_token = if has_more {
                matched.last().map(|(row_id, _)| row_id.to_string())
            } else {
                None
            };
            let entries = matched.into_iter().map(|(_, e)| e).collect();

            Ok(HistoryListPage {
                entries,
                next_page_token,
                current_history_id: current_hid,
            })
        })
        .await
    }

    async fn insert_message(&self, input: NewMessageInput) -> AppResult<StoredMessage> {
        self.run_blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let msg = insert_message_tx(&tx, input)?;
            tx.commit().map_err(sql_err)?;
            Ok(msg)
        })
        .await
    }

    async fn get_message(&self, id: &str) -> AppResult<Option<StoredMessage>> {
        let id = id.to_string();
        self.run_blocking(move |conn| load_message_by_id(conn, &id))
            .await
    }

    async fn list_messages(&self, query: &MessageListQuery) -> AppResult<MessageListPage> {
        let query = query.clone();
        self.run_blocking(move |conn| {
            let max_results = if query.max_results == 0 {
                100
            } else {
                query.max_results.min(500)
            };
            let offset = parse_offset_token(query.page_token.as_deref())?;
            let all = load_all_messages_filtered(
                conn,
                &query.label_ids,
                query.include_spam_trash,
                query.q.as_deref(),
            )?;
            let total = all.len();
            let page_msgs: Vec<StoredMessage> =
                all.into_iter().skip(offset).take(max_results).collect();
            let next_page_token = if offset + page_msgs.len() < total {
                Some((offset + page_msgs.len()).to_string())
            } else {
                None
            };
            Ok(MessageListPage {
                messages: page_msgs,
                next_page_token,
                result_size_estimate: total as u32,
            })
        })
        .await
    }

    async fn modify_message_labels(
        &self,
        id: &str,
        add_labels: &[String],
        remove_labels: &[String],
    ) -> AppResult<StoredMessage> {
        let id = id.to_string();
        let add_labels = add_labels.to_vec();
        let remove_labels = remove_labels.to_vec();
        self.run_blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let mut resolved_add = Vec::with_capacity(add_labels.len());
            for l in &add_labels {
                let lid = resolve_existing_label_id(&tx, l)?
                    .ok_or_else(|| AppError::BadRequest(format!("Label not found: {l}")))?;
                resolved_add.push(lid);
            }
            let mut resolved_remove = Vec::with_capacity(remove_labels.len());
            for l in &remove_labels {
                if let Some(lid) = resolve_existing_label_id(&tx, l)? {
                    resolved_remove.push(lid);
                }
            }
            let msg = modify_message_labels_resolved_tx(&tx, &id, &resolved_add, &resolved_remove)?;
            tx.commit().map_err(sql_err)?;
            Ok(msg)
        })
        .await
    }

    async fn batch_modify_labels(
        &self,
        ids: &[String],
        add_labels: &[String],
        remove_labels: &[String],
    ) -> AppResult<()> {
        let ids = ids.to_vec();
        let add_labels = add_labels.to_vec();
        let remove_labels = remove_labels.to_vec();
        self.run_blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let mut resolved_add = Vec::with_capacity(add_labels.len());
            for l in &add_labels {
                let lid = resolve_existing_label_id(&tx, l)?
                    .ok_or_else(|| AppError::BadRequest(format!("Label not found: {l}")))?;
                resolved_add.push(lid);
            }
            let mut resolved_remove = Vec::with_capacity(remove_labels.len());
            for l in &remove_labels {
                if let Some(lid) = resolve_existing_label_id(&tx, l)? {
                    resolved_remove.push(lid);
                }
            }
            for id in &ids {
                if load_message_by_id(&tx, id)?.is_some() {
                    modify_message_labels_resolved_tx(&tx, id, &resolved_add, &resolved_remove)?;
                }
            }
            tx.commit().map_err(sql_err)?;
            Ok(())
        })
        .await
    }

    async fn trash_message(&self, id: &str) -> AppResult<StoredMessage> {
        self.modify_message_labels(id, &[LABEL_TRASH.to_string()], &[LABEL_INBOX.to_string()])
            .await
    }

    async fn untrash_message(&self, id: &str) -> AppResult<StoredMessage> {
        self.modify_message_labels(id, &[], &[LABEL_TRASH.to_string()])
            .await
    }

    async fn delete_message(&self, id: &str) -> AppResult<bool> {
        let id = id.to_string();
        self.run_blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let deleted = delete_message_tx(&tx, &id)?.is_some();
            tx.commit().map_err(sql_err)?;
            Ok(deleted)
        })
        .await
    }

    async fn batch_delete_messages(&self, ids: &[String]) -> AppResult<()> {
        let ids = ids.to_vec();
        self.run_blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            for id in &ids {
                delete_message_tx(&tx, id)?;
            }
            tx.commit().map_err(sql_err)?;
            Ok(())
        })
        .await
    }

    async fn get_attachment(
        &self,
        message_id: &str,
        attachment_id: &str,
    ) -> AppResult<Option<StoredAttachment>> {
        let message_id = message_id.to_string();
        let attachment_id = attachment_id.to_string();
        self.run_blocking(move |conn| {
            conn.query_row(
                "SELECT id, message_id, part_id, filename, content_type, content_id, size_bytes, data
                 FROM attachments
                 WHERE message_id = ?1 AND id = ?2",
                params![message_id, attachment_id],
                |row| {
                    Ok(StoredAttachment {
                        id: row.get(0)?,
                        message_id: row.get(1)?,
                        part_id: row.get(2)?,
                        filename: row.get(3)?,
                        content_type: row.get(4)?,
                        content_id: row.get(5)?,
                        size_bytes: row.get::<_, i64>(6)?.max(0) as u64,
                        data: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(sql_err)
        })
        .await
    }

    async fn list_attachment_meta(&self, message_id: &str) -> AppResult<Vec<AttachmentMeta>> {
        let message_id = message_id.to_string();
        self.run_blocking(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, filename, content_type, size_bytes
                     FROM attachments
                     WHERE message_id = ?1
                     ORDER BY part_id ASC, id ASC",
                )
                .map_err(sql_err)?;
            let rows = stmt
                .query_map(params![message_id], |row| {
                    Ok(AttachmentMeta {
                        id: row.get(0)?,
                        filename: row.get(1)?,
                        content_type: row.get(2)?,
                        size_bytes: row.get::<_, i64>(3)?.max(0) as u64,
                    })
                })
                .map_err(sql_err)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(sql_err)?);
            }
            Ok(out)
        })
        .await
    }

    async fn list_threads(&self, query: &MessageListQuery) -> AppResult<ThreadListPage> {
        let query = query.clone();
        self.run_blocking(move |conn| {
            let max_results = if query.max_results == 0 {
                100
            } else {
                query.max_results.min(500)
            };
            let offset = parse_offset_token(query.page_token.as_deref())?;

            let parsed_q = match query.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                Some(raw) => Some(parse_query_with_labels(conn, raw)?),
                None => None,
            };

            let explicit_spam_trash = query
                .label_ids
                .iter()
                .any(|l| l == LABEL_TRASH || l == LABEL_SPAM);
            let effective_include_spam_trash = query.include_spam_trash
                || explicit_spam_trash
                || parsed_q.as_ref().is_some_and(|pq| pq.include_spam_trash);

            let mut required_labels = Vec::new();
            for l in &query.label_ids {
                required_labels
                    .push(resolve_existing_label_id(conn, l)?.unwrap_or_else(|| l.clone()));
            }

            // Load visible messages (filtered only by spam/trash visibility) so threads contain all visible messages.
            let visible_msgs =
                load_all_messages_filtered(conn, &[], effective_include_spam_trash, None)?;

            let mut by_thread: BTreeMap<String, Vec<StoredMessage>> = BTreeMap::new();
            for msg in visible_msgs {
                by_thread
                    .entry(msg.thread_id.clone())
                    .or_default()
                    .push(msg);
            }

            let mut matching_threads: Vec<(i64, StoredThreadDetail)> = Vec::new();
            for (tid, mut msgs) in by_thread {
                msgs.sort_by(|a, b| {
                    a.internal_date_ms
                        .cmp(&b.internal_date_ms)
                        .then_with(|| a.id.cmp(&b.id))
                });

                if !required_labels.is_empty() {
                    let thread_labels: HashSet<&String> =
                        msgs.iter().flat_map(|m| m.label_ids.iter()).collect();
                    if !required_labels
                        .iter()
                        .all(|req| thread_labels.contains(req))
                    {
                        continue;
                    }
                }
                if let Some(ref pq) = parsed_q
                    && !msgs.iter().any(|m| crate::search::matches_message(pq, m))
                {
                    continue;
                }

                let max_ts = msgs.iter().map(|m| m.internal_date_ms).max().unwrap_or(0);
                let snippet = msgs.last().map(|m| m.snippet.clone()).unwrap_or_default();
                let history_id = msgs.iter().map(|m| m.history_id).max().unwrap_or(1);
                matching_threads.push((
                    max_ts,
                    StoredThreadDetail {
                        id: tid,
                        snippet,
                        history_id,
                        messages: msgs,
                    },
                ));
            }

            matching_threads.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.id.cmp(&a.1.id)));
            let total = matching_threads.len();
            let page: Vec<StoredThreadDetail> = matching_threads
                .into_iter()
                .skip(offset)
                .take(max_results)
                .map(|(_, t)| t)
                .collect();
            let next_page_token = if offset + page.len() < total {
                Some((offset + page.len()).to_string())
            } else {
                None
            };

            Ok(ThreadListPage {
                threads: page,
                next_page_token,
                result_size_estimate: total as u32,
            })
        })
        .await
    }

    async fn get_thread(&self, thread_id: &str) -> AppResult<Option<StoredThreadDetail>> {
        let thread_id = thread_id.to_string();
        self.run_blocking(move |conn| load_thread_detail_conn(conn, &thread_id))
            .await
    }

    async fn modify_thread_labels(
        &self,
        thread_id: &str,
        add_labels: &[String],
        remove_labels: &[String],
    ) -> AppResult<StoredThreadDetail> {
        let thread_id = thread_id.to_string();
        let add_labels = add_labels.to_vec();
        let remove_labels = remove_labels.to_vec();
        self.run_blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let mut stmt = tx
                .prepare("SELECT id FROM messages WHERE thread_id = ?1 ORDER BY internal_date_ms ASC, id ASC")
                .map_err(sql_err)?;
            let msg_ids: Vec<String> = stmt
                .query_map(params![&thread_id], |row| row.get(0))
                .map_err(sql_err)?
                .collect::<Result<_, _>>()
                .map_err(sql_err)?;
            drop(stmt);

            if msg_ids.is_empty() {
                return Err(AppError::NotFound(format!("Thread not found: {thread_id}")));
            }

            let mut resolved_add = Vec::with_capacity(add_labels.len());
            for l in &add_labels {
                let lid = resolve_existing_label_id(&tx, l)?
                    .ok_or_else(|| AppError::BadRequest(format!("Label not found: {l}")))?;
                resolved_add.push(lid);
            }
            let mut resolved_remove = Vec::with_capacity(remove_labels.len());
            for l in &remove_labels {
                if let Some(lid) = resolve_existing_label_id(&tx, l)? {
                    resolved_remove.push(lid);
                }
            }

            for mid in &msg_ids {
                modify_message_labels_resolved_tx(&tx, mid, &resolved_add, &resolved_remove)?;
            }

            let detail = load_thread_detail_conn(&tx, &thread_id)?
                .ok_or_else(|| AppError::NotFound(format!("Thread not found: {thread_id}")))?;
            tx.commit().map_err(sql_err)?;
            Ok(detail)
        })
        .await
    }

    async fn trash_thread(&self, thread_id: &str) -> AppResult<StoredThreadDetail> {
        self.modify_thread_labels(
            thread_id,
            &[LABEL_TRASH.to_string()],
            &[LABEL_INBOX.to_string()],
        )
        .await
    }

    async fn untrash_thread(&self, thread_id: &str) -> AppResult<StoredThreadDetail> {
        self.modify_thread_labels(thread_id, &[], &[LABEL_TRASH.to_string()])
            .await
    }

    async fn delete_thread(&self, thread_id: &str) -> AppResult<bool> {
        let thread_id = thread_id.to_string();
        self.run_blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let mut stmt = tx
                .prepare("SELECT id FROM messages WHERE thread_id = ?1")
                .map_err(sql_err)?;
            let msg_ids: Vec<String> = stmt
                .query_map(params![&thread_id], |row| row.get(0))
                .map_err(sql_err)?
                .collect::<Result<_, _>>()
                .map_err(sql_err)?;
            drop(stmt);

            if msg_ids.is_empty() {
                return Ok(false);
            }
            for mid in &msg_ids {
                delete_message_tx(&tx, mid)?;
            }
            tx.commit().map_err(sql_err)?;
            Ok(true)
        })
        .await
    }

    async fn list_labels(&self) -> AppResult<Vec<StoredLabel>> {
        self.run_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT
                        l.id, l.name, l.label_type, l.message_list_visibility, l.label_list_visibility,
                        l.color_text, l.color_background, l.uid_validity, l.uid_next, l.upstream_label_id,
                        (SELECT COUNT(*) FROM message_labels ml WHERE ml.label_id = l.id) AS messages_total,
                        (SELECT COUNT(*) FROM message_labels ml
                         INNER JOIN message_labels mu ON mu.message_id = ml.message_id AND mu.label_id = ?1
                         WHERE ml.label_id = l.id) AS messages_unread,
                        (SELECT COUNT(DISTINCT m.thread_id) FROM message_labels ml
                         INNER JOIN messages m ON m.id = ml.message_id
                         WHERE ml.label_id = l.id) AS threads_total,
                        (SELECT COUNT(DISTINCT m.thread_id) FROM message_labels ml
                         INNER JOIN messages m ON m.id = ml.message_id
                         INNER JOIN message_labels mu ON mu.message_id = ml.message_id AND mu.label_id = ?1
                         WHERE ml.label_id = l.id) AS threads_unread
                     FROM labels l
                     ORDER BY CASE WHEN l.label_type = 'system' THEN 0 ELSE 1 END, l.name ASC",
                )
                .map_err(sql_err)?;
            let rows = stmt
                .query_map(params![LABEL_UNREAD], label_from_row)
                .map_err(sql_err)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(sql_err)?);
            }
            Ok(out)
        })
        .await
    }

    async fn get_label(&self, id: &str) -> AppResult<Option<StoredLabel>> {
        let id = id.to_string();
        self.run_blocking(move |conn| load_label_with_counts(conn, &id))
            .await
    }

    async fn create_label(&self, input: NewLabelInput) -> AppResult<StoredLabel> {
        self.run_blocking(move |conn| {
            let name = input.name.trim().to_string();
            if name.is_empty() {
                return Err(AppError::BadRequest("Label name cannot be empty".into()));
            }
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;

            let conflict: Option<String> = tx
                .query_row(
                    "SELECT id FROM labels WHERE name = ?1 COLLATE NOCASE OR id = ?1",
                    params![&name],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?;
            if conflict.is_some() {
                return Err(AppError::Conflict(format!("Label already exists: {name}")));
            }

            let id = format!("Label_{}", &new_hex_id()[..8]);
            let uv = alloc_uid_validity(&tx)?;
            let msg_vis = input
                .message_list_visibility
                .unwrap_or_else(|| "show".to_string());
            let lbl_vis = input
                .label_list_visibility
                .unwrap_or_else(|| "labelShow".to_string());
            let (color_text, color_bg) = match input.color {
                Some(ref c) => (
                    Some(c.text_color.as_str()),
                    Some(c.background_color.as_str()),
                ),
                None => (None, None),
            };

            tx.execute(
                "INSERT INTO labels (
                    id, name, label_type, message_list_visibility, label_list_visibility,
                    color_text, color_background, uid_validity, uid_next, upstream_label_id
                 ) VALUES (?1, ?2, 'user', ?3, ?4, ?5, ?6, ?7, 1, ?8)",
                params![
                    &id,
                    &name,
                    &msg_vis,
                    &lbl_vis,
                    color_text,
                    color_bg,
                    uv as i64,
                    &input.upstream_label_id
                ],
            )
            .map_err(sql_err)?;

            let created = load_label_with_counts(&tx, &id)?
                .ok_or_else(|| AppError::Storage("Failed to load created label".into()))?;
            tx.commit().map_err(sql_err)?;
            Ok(created)
        })
        .await
    }

    async fn update_label(
        &self,
        id: &str,
        input: UpdateLabelInput,
        full_replace: bool,
    ) -> AppResult<StoredLabel> {
        let id = id.to_string();
        self.run_blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let existing = load_label_with_counts(&tx, &id)?
                .ok_or_else(|| AppError::NotFound(format!("Label not found: {id}")))?;
            if existing.label_type == "system" || is_system_label(&existing.id) {
                return Err(AppError::BadRequest(format!(
                    "Cannot modify system label: {id}"
                )));
            }

            let new_name = match input.name {
                Some(ref n) => {
                    let trimmed = n.trim();
                    if trimmed.is_empty() {
                        return Err(AppError::BadRequest("Label name cannot be empty".into()));
                    }
                    let conflict: Option<String> = tx
                        .query_row(
                            "SELECT id FROM labels WHERE (name = ?1 COLLATE NOCASE OR id = ?1) AND id != ?2",
                            params![trimmed, &id],
                            |row| row.get(0),
                        )
                        .optional()
                        .map_err(sql_err)?;
                    if conflict.is_some() {
                        return Err(AppError::Conflict(format!(
                            "Label name already exists: {trimmed}"
                        )));
                    }
                    trimmed.to_string()
                }
                None => existing.name.clone(),
            };

            let (msg_vis, lbl_vis, color) = if full_replace {
                (
                    input.message_list_visibility,
                    input.label_list_visibility,
                    input.color,
                )
            } else {
                (
                    input.message_list_visibility.or(existing.message_list_visibility),
                    input.label_list_visibility.or(existing.label_list_visibility),
                    input.color.or(existing.color),
                )
            };

            let (color_text, color_bg) = match color {
                Some(ref c) => (Some(c.text_color.as_str()), Some(c.background_color.as_str())),
                None => (None, None),
            };

            tx.execute(
                "UPDATE labels
                 SET name = ?1, message_list_visibility = ?2, label_list_visibility = ?3,
                     color_text = ?4, color_background = ?5
                 WHERE id = ?6",
                params![new_name, msg_vis, lbl_vis, color_text, color_bg, &id],
            )
            .map_err(sql_err)?;

            let updated = load_label_with_counts(&tx, &id)?
                .ok_or_else(|| AppError::NotFound(format!("Label not found: {id}")))?;
            tx.commit().map_err(sql_err)?;
            Ok(updated)
        })
        .await
    }

    async fn delete_label(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        self.run_blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let existing = load_label_with_counts(&tx, &id)?
                .ok_or_else(|| AppError::NotFound(format!("Label not found: {id}")))?;
            if existing.label_type == "system" || is_system_label(&existing.id) {
                return Err(AppError::BadRequest(format!(
                    "Cannot delete system label: {id}"
                )));
            }

            // Record LabelRemoved history events for messages carrying this label
            let mut stmt = tx
                .prepare(
                    "SELECT m.id, m.thread_id
                     FROM message_labels ml
                     INNER JOIN messages m ON m.id = ml.message_id
                     WHERE ml.label_id = ?1",
                )
                .map_err(sql_err)?;
            let affected: Vec<(String, String)> = stmt
                .query_map(params![&id], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(sql_err)?
                .collect::<Result<_, _>>()
                .map_err(sql_err)?;
            drop(stmt);

            for (mid, tid) in affected {
                let ctx = load_message_labels(&tx, &mid)?;
                let hid = bump_history_id(&tx)?;
                tx.execute(
                    "UPDATE messages SET history_id = ?1 WHERE id = ?2",
                    params![hid as i64, &mid],
                )
                .map_err(sql_err)?;
                record_history_event(
                    &tx,
                    hid,
                    HistoryEventKind::LabelRemoved,
                    &mid,
                    &tid,
                    std::slice::from_ref(&id),
                    &ctx,
                )?;
            }

            tx.execute("DELETE FROM labels WHERE id = ?1", params![&id])
                .map_err(sql_err)?;
            tx.commit().map_err(sql_err)?;
            Ok(())
        })
        .await
    }

    async fn upsert_upstream_label(&self, input: NewLabelInput) -> AppResult<StoredLabel> {
        self.run_blocking(move |conn| {
            let name = input.name.trim().to_string();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;

            // 1. Check upstream_label_id
            if let Some(ref ulid) = input.upstream_label_id
                && !ulid.trim().is_empty()
            {
                if is_system_label(ulid.trim())
                    && let Some(sys) = load_label_with_counts(&tx, ulid.trim())?
                {
                    tx.commit().map_err(sql_err)?;
                    return Ok(sys);
                }
                if let Some(existing_id) = tx
                    .query_row(
                        "SELECT id FROM labels WHERE upstream_label_id = ?1",
                        params![ulid.trim()],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .map_err(sql_err)?
                {
                    if !name.is_empty() {
                        tx.execute(
                            "UPDATE labels SET name = ?1 WHERE id = ?2 AND label_type = 'user'",
                            params![&name, &existing_id],
                        )
                        .map_err(sql_err)?;
                    }
                    let lbl = load_label_with_counts(&tx, &existing_id)?
                        .ok_or_else(|| AppError::Storage("Failed to load upstream label".into()))?;
                    tx.commit().map_err(sql_err)?;
                    return Ok(lbl);
                }
            }

            // 2. Check by existing id or case-insensitive name
            if !name.is_empty()
                && let Some(existing_id) = resolve_existing_label_id(&tx, &name)?
            {
                let existing = load_label_with_counts(&tx, &existing_id)?
                    .ok_or_else(|| AppError::Storage("Failed to load existing label".into()))?;
                if existing.label_type == "system" {
                    tx.commit().map_err(sql_err)?;
                    return Ok(existing);
                }
                if input.upstream_label_id.is_some() && existing.upstream_label_id.is_none() {
                    tx.execute(
                        "UPDATE labels SET upstream_label_id = ?1 WHERE id = ?2",
                        params![&input.upstream_label_id, &existing_id],
                    )
                    .map_err(sql_err)?;
                }
                let updated = load_label_with_counts(&tx, &existing_id)?
                    .ok_or_else(|| AppError::Storage("Failed to load updated label".into()))?;
                tx.commit().map_err(sql_err)?;
                return Ok(updated);
            }

            if name.is_empty() {
                return Err(AppError::BadRequest("Label name cannot be empty".into()));
            }

            // 3. Create new user label
            let id = format!("Label_{}", &new_hex_id()[..8]);
            let uv = alloc_uid_validity(&tx)?;
            let msg_vis = input
                .message_list_visibility
                .unwrap_or_else(|| "show".to_string());
            let lbl_vis = input
                .label_list_visibility
                .unwrap_or_else(|| "labelShow".to_string());
            let (color_text, color_bg) = match input.color {
                Some(ref c) => (
                    Some(c.text_color.as_str()),
                    Some(c.background_color.as_str()),
                ),
                None => (None, None),
            };
            tx.execute(
                "INSERT INTO labels (
                    id, name, label_type, message_list_visibility, label_list_visibility,
                    color_text, color_background, uid_validity, uid_next, upstream_label_id
                 ) VALUES (?1, ?2, 'user', ?3, ?4, ?5, ?6, ?7, 1, ?8)",
                params![
                    &id,
                    &name,
                    &msg_vis,
                    &lbl_vis,
                    color_text,
                    color_bg,
                    uv as i64,
                    &input.upstream_label_id
                ],
            )
            .map_err(sql_err)?;
            let created = load_label_with_counts(&tx, &id)?
                .ok_or_else(|| AppError::Storage("Failed to load created upstream label".into()))?;
            tx.commit().map_err(sql_err)?;
            Ok(created)
        })
        .await
    }

    async fn list_drafts(&self, query: &MessageListQuery) -> AppResult<DraftListPage> {
        let query = query.clone();
        self.run_blocking(move |conn| {
            let max_results = if query.max_results == 0 {
                100
            } else {
                query.max_results.min(500)
            };
            let offset = parse_offset_token(query.page_token.as_deref())?;
            let parsed_q = match query.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                Some(raw) => Some(parse_query_with_labels(conn, raw)?),
                None => None,
            };
            let effective_include_spam_trash = query.include_spam_trash
                || parsed_q.as_ref().is_some_and(|pq| pq.include_spam_trash);

            let mut stmt = conn
                .prepare(
                    "SELECT d.id AS draft_id, d.updated_at_ms, m.*
                     FROM drafts d
                     INNER JOIN messages m ON m.id = d.message_id
                     ORDER BY d.updated_at_ms DESC, d.id DESC",
                )
                .map_err(sql_err)?;
            let rows = stmt
                .query_map([], |row| {
                    let draft_id: String = row.get("draft_id")?;
                    let updated_ms: i64 = row.get("updated_at_ms")?;
                    let msg = message_from_row(row)?;
                    Ok((draft_id, updated_ms, msg))
                })
                .map_err(sql_err)?;

            let mut raw = Vec::new();
            for r in rows {
                raw.push(r.map_err(sql_err)?);
            }
            let msg_ids: Vec<String> = raw.iter().map(|(_, _, m)| m.id.clone()).collect();
            let mut label_map = load_labels_for_messages(conn, &msg_ids)?;

            let mut drafts = Vec::new();
            for (draft_id, updated_ms, mut msg) in raw {
                msg.label_ids = label_map.remove(&msg.id).unwrap_or_default();
                if !effective_include_spam_trash
                    && msg
                        .label_ids
                        .iter()
                        .any(|l| l == LABEL_TRASH || l == LABEL_SPAM)
                {
                    continue;
                }
                if let Some(ref pq) = parsed_q
                    && !crate::search::matches_message(pq, &msg)
                {
                    continue;
                }
                drafts.push(StoredDraft {
                    id: draft_id,
                    message: msg,
                    updated_at: DateTime::from_timestamp_millis(updated_ms)
                        .unwrap_or_else(Utc::now),
                });
            }

            let total = drafts.len();
            let page: Vec<StoredDraft> =
                drafts.into_iter().skip(offset).take(max_results).collect();
            let next_page_token = if offset + page.len() < total {
                Some((offset + page.len()).to_string())
            } else {
                None
            };

            Ok(DraftListPage {
                drafts: page,
                next_page_token,
                result_size_estimate: total as u32,
            })
        })
        .await
    }

    async fn get_draft(&self, id: &str) -> AppResult<Option<StoredDraft>> {
        let id = id.to_string();
        self.run_blocking(move |conn| {
            let row: Option<(String, i64)> = conn
                .query_row(
                    "SELECT message_id, updated_at_ms FROM drafts WHERE id = ?1",
                    params![&id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(sql_err)?;
            let Some((message_id, updated_ms)) = row else {
                return Ok(None);
            };
            let Some(message) = load_message_by_id(conn, &message_id)? else {
                return Ok(None);
            };
            Ok(Some(StoredDraft {
                id,
                message,
                updated_at: DateTime::from_timestamp_millis(updated_ms).unwrap_or_else(Utc::now),
            }))
        })
        .await
    }

    async fn create_draft(&self, mut message: NewMessageInput) -> AppResult<StoredDraft> {
        if !message.label_ids.iter().any(|l| l == LABEL_DRAFT) {
            message.label_ids.push(LABEL_DRAFT.to_string());
        }
        self.run_blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let stored_msg = insert_message_tx(&tx, message)?;
            let draft_id = format!("r{}", new_hex_id());
            let now = Utc::now();
            tx.execute(
                "INSERT INTO drafts (id, message_id, updated_at_ms) VALUES (?1, ?2, ?3)",
                params![&draft_id, &stored_msg.id, now.timestamp_millis()],
            )
            .map_err(sql_err)?;
            tx.commit().map_err(sql_err)?;
            Ok(StoredDraft {
                id: draft_id,
                message: stored_msg,
                updated_at: now,
            })
        })
        .await
    }

    async fn update_draft(
        &self,
        draft_id: &str,
        mut message: NewMessageInput,
    ) -> AppResult<StoredDraft> {
        let draft_id = draft_id.to_string();
        if !message.label_ids.iter().any(|l| l == LABEL_DRAFT) {
            message.label_ids.push(LABEL_DRAFT.to_string());
        }
        self.run_blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let old_msg_id: String = tx
                .query_row(
                    "SELECT message_id FROM drafts WHERE id = ?1",
                    params![&draft_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?
                .ok_or_else(|| AppError::NotFound(format!("Draft not found: {draft_id}")))?;

            // Insert replacement message BEFORE deleting old message so ON DELETE CASCADE won't drop the draft row.
            let new_msg = insert_message_tx(&tx, message)?;
            let now = Utc::now();
            tx.execute(
                "UPDATE drafts SET message_id = ?1, updated_at_ms = ?2 WHERE id = ?3",
                params![&new_msg.id, now.timestamp_millis(), &draft_id],
            )
            .map_err(sql_err)?;
            delete_message_tx(&tx, &old_msg_id)?;

            tx.commit().map_err(sql_err)?;
            Ok(StoredDraft {
                id: draft_id,
                message: new_msg,
                updated_at: now,
            })
        })
        .await
    }

    async fn delete_draft(&self, draft_id: &str) -> AppResult<bool> {
        let draft_id = draft_id.to_string();
        self.run_blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let msg_id: Option<String> = tx
                .query_row(
                    "SELECT message_id FROM drafts WHERE id = ?1",
                    params![&draft_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?;
            let Some(msg_id) = msg_id else {
                return Ok(false);
            };
            tx.execute("DELETE FROM drafts WHERE id = ?1", params![&draft_id])
                .map_err(sql_err)?;
            delete_message_tx(&tx, &msg_id)?;
            tx.commit().map_err(sql_err)?;
            Ok(true)
        })
        .await
    }

    async fn search_messages_ai(&self, query: &AiSearchQuery) -> AppResult<AiMessagePage> {
        let query = query.clone();
        self.run_blocking(move |conn| {
            let limit = if query.limit == 0 {
                20
            } else {
                query.limit.min(100)
            };
            let cursor = match query.cursor.as_deref() {
                Some(c) if !c.trim().is_empty() => Some(decode_keyset_cursor(c.trim())?),
                _ => None,
            };

            let mut resolved_labels = Vec::new();
            for l in &query.labels {
                resolved_labels
                    .push(resolve_existing_label_id(conn, l)?.unwrap_or_else(|| l.clone()));
            }
            let explicit_spam_trash = resolved_labels
                .iter()
                .any(|l| l == LABEL_TRASH || l == LABEL_SPAM);
            let effective_include_spam_trash = query.include_spam_trash || explicit_spam_trash;

            let mut sql = String::from("SELECT m.* FROM messages m");
            let mut where_clauses: Vec<String> = Vec::new();
            let mut bind_values: Vec<SqlValue> = Vec::new();

            if let Some(ref raw_q) = query.q {
                let trimmed = raw_q.trim();
                if !trimmed.is_empty() {
                    if let Some(fts_query) = build_fts5_query(trimmed) {
                        sql.push_str(" INNER JOIN messages_fts f ON f.message_id = m.id");
                        bind_values.push(SqlValue::Text(fts_query));
                        let p = bind_values.len();
                        where_clauses.push(format!("messages_fts MATCH ?{p}"));
                    } else {
                        let like_pat = format!("%{}%", trimmed.to_ascii_lowercase());
                        bind_values.push(SqlValue::Text(like_pat));
                        let p = bind_values.len();
                        where_clauses.push(format!(
                            "(LOWER(m.subject) LIKE ?{p} OR LOWER(m.from_addr) LIKE ?{p} OR LOWER(m.to_addrs_json) LIKE ?{p} OR LOWER(m.cc_addrs_json) LIKE ?{p} OR LOWER(m.text_body) LIKE ?{p} OR LOWER(m.snippet) LIKE ?{p})"
                        ));
                    }
                }
            }

            if !effective_include_spam_trash {
                bind_values.push(SqlValue::Text(LABEL_TRASH.to_string()));
                let p1 = bind_values.len();
                bind_values.push(SqlValue::Text(LABEL_SPAM.to_string()));
                let p2 = bind_values.len();
                where_clauses.push(format!(
                    "NOT EXISTS (SELECT 1 FROM message_labels ml_ex WHERE ml_ex.message_id = m.id AND ml_ex.label_id IN (?{p1}, ?{p2}))"
                ));
            }

            for lid in &resolved_labels {
                bind_values.push(SqlValue::Text(lid.clone()));
                let p = bind_values.len();
                where_clauses.push(format!(
                    "EXISTS (SELECT 1 FROM message_labels ml_in WHERE ml_in.message_id = m.id AND ml_in.label_id = ?{p})"
                ));
            }

            if let Some(want_unread) = query.unread {
                bind_values.push(SqlValue::Text(LABEL_UNREAD.to_string()));
                let p = bind_values.len();
                if want_unread {
                    where_clauses.push(format!(
                        "EXISTS (SELECT 1 FROM message_labels ml_unr WHERE ml_unr.message_id = m.id AND ml_unr.label_id = ?{p})"
                    ));
                } else {
                    where_clauses.push(format!(
                        "NOT EXISTS (SELECT 1 FROM message_labels ml_unr WHERE ml_unr.message_id = m.id AND ml_unr.label_id = ?{p})"
                    ));
                }
            }

            if let Some(ref tid) = query.thread_id
                && !tid.trim().is_empty()
            {
                bind_values.push(SqlValue::Text(tid.trim().to_string()));
                let p = bind_values.len();
                where_clauses.push(format!("m.thread_id = ?{p}"));
            }

            if let Some(ref from_filter) = query.from
                && !from_filter.trim().is_empty()
            {
                bind_values.push(SqlValue::Text(format!(
                    "%{}%",
                    from_filter.trim().to_ascii_lowercase()
                )));
                let p = bind_values.len();
                where_clauses.push(format!("LOWER(m.from_addr) LIKE ?{p}"));
            }

            if let Some(ref to_filter) = query.to
                && !to_filter.trim().is_empty()
            {
                bind_values.push(SqlValue::Text(format!(
                    "%{}%",
                    to_filter.trim().to_ascii_lowercase()
                )));
                let p = bind_values.len();
                where_clauses.push(format!("LOWER(m.to_addrs_json) LIKE ?{p}"));
            }

            if let Some(after) = query.after {
                bind_values.push(SqlValue::Integer(after.timestamp_millis()));
                let p = bind_values.len();
                where_clauses.push(format!("m.internal_date_ms >= ?{p}"));
            }

            if let Some(before) = query.before {
                bind_values.push(SqlValue::Integer(before.timestamp_millis()));
                let p = bind_values.len();
                where_clauses.push(format!("m.internal_date_ms <= ?{p}"));
            }

            if let Some(has_att) = query.has_attachment {
                bind_values.push(SqlValue::Integer(if has_att { 1 } else { 0 }));
                let p = bind_values.len();
                where_clauses.push(format!("m.has_attachments = ?{p}"));
            }

            if let Some((cursor_ts, cursor_id)) = cursor {
                bind_values.push(SqlValue::Integer(cursor_ts));
                let p_ts = bind_values.len();
                bind_values.push(SqlValue::Text(cursor_id));
                let p_id = bind_values.len();
                where_clauses.push(format!(
                    "(m.internal_date_ms < ?{p_ts} OR (m.internal_date_ms = ?{p_ts} AND m.id < ?{p_id}))"
                ));
            }

            if !where_clauses.is_empty() {
                sql.push_str(" WHERE ");
                sql.push_str(&where_clauses.join(" AND "));
            }
            bind_values.push(SqlValue::Integer((limit + 1) as i64));
            let p_lim = bind_values.len();
            sql.push_str(&format!(
                " ORDER BY m.internal_date_ms DESC, m.id DESC LIMIT ?{p_lim}"
            ));

            let mut stmt = conn.prepare(&sql).map_err(sql_err)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(bind_values.iter()), message_from_row)
                .map_err(sql_err)?;
            let mut messages = Vec::new();
            for r in rows {
                messages.push(r.map_err(sql_err)?);
            }

            let has_more = messages.len() > limit;
            if has_more {
                messages.truncate(limit);
            }

            let ids: Vec<String> = messages.iter().map(|m| m.id.clone()).collect();
            let mut label_map = load_labels_for_messages(conn, &ids)?;
            for m in &mut messages {
                m.label_ids = label_map.remove(&m.id).unwrap_or_default();
            }

            let next_cursor = if has_more {
                messages
                    .last()
                    .map(|m| encode_keyset_cursor(m.internal_date_ms, &m.id))
            } else {
                None
            };

            Ok(AiMessagePage {
                messages,
                next_cursor,
                has_more,
            })
        })
        .await
    }

    async fn list_thread_summaries(&self, query: &AiThreadQuery) -> AppResult<AiThreadPage> {
        let query = query.clone();
        self.run_blocking(move |conn| {
            let limit = if query.limit == 0 {
                20
            } else {
                query.limit.min(100)
            };
            let cursor = match query.cursor.as_deref() {
                Some(c) if !c.trim().is_empty() => Some(decode_keyset_cursor(c.trim())?),
                _ => None,
            };

            let resolved_label = match query.label.as_deref() {
                Some(l) if !l.trim().is_empty() => {
                    Some(resolve_existing_label_id(conn, l)?.unwrap_or_else(|| l.to_string()))
                }
                _ => None,
            };
            let explicit_spam_trash = resolved_label
                .as_deref()
                .is_some_and(|l| l == LABEL_TRASH || l == LABEL_SPAM);
            let effective_include_spam_trash = query.include_spam_trash || explicit_spam_trash;

            // Optional FTS5 candidate thread set when `q` is provided
            let fts_matching_threads: Option<HashSet<String>> = match query.q.as_deref() {
                Some(raw_q) if !raw_q.trim().is_empty() => {
                    let trimmed = raw_q.trim();
                    let mut set = HashSet::new();
                    if let Some(fts_query) = build_fts5_query(trimmed) {
                        let mut stmt = conn
                            .prepare(
                                "SELECT DISTINCT m.thread_id
                                 FROM messages m
                                 INNER JOIN messages_fts f ON f.message_id = m.id
                                 WHERE messages_fts MATCH ?1",
                            )
                            .map_err(sql_err)?;
                        let rows = stmt
                            .query_map(params![fts_query], |row| row.get::<_, String>(0))
                            .map_err(sql_err)?;
                        for r in rows {
                            set.insert(r.map_err(sql_err)?);
                        }
                    } else {
                        let pat = format!("%{}%", trimmed.to_ascii_lowercase());
                        let mut stmt = conn
                            .prepare(
                                "SELECT DISTINCT thread_id FROM messages
                                 WHERE LOWER(subject) LIKE ?1 OR LOWER(from_addr) LIKE ?1 OR LOWER(text_body) LIKE ?1 OR LOWER(snippet) LIKE ?1",
                            )
                            .map_err(sql_err)?;
                        let rows = stmt
                            .query_map(params![pat], |row| row.get::<_, String>(0))
                            .map_err(sql_err)?;
                        for r in rows {
                            set.insert(r.map_err(sql_err)?);
                        }
                    }
                    Some(set)
                }
                _ => None,
            };

            let visible_msgs =
                load_all_messages_filtered(conn, &[], effective_include_spam_trash, None)?;

            let mut by_thread: BTreeMap<String, Vec<StoredMessage>> = BTreeMap::new();
            for msg in visible_msgs {
                by_thread.entry(msg.thread_id.clone()).or_default().push(msg);
            }

            let mut summaries: Vec<(i64, ThreadSummary)> = Vec::new();
            for (tid, mut msgs) in by_thread {
                if let Some(ref fts_set) = fts_matching_threads
                    && !fts_set.contains(&tid)
                {
                    continue;
                }
                msgs.sort_by(|a, b| {
                    a.internal_date_ms
                        .cmp(&b.internal_date_ms)
                        .then_with(|| a.id.cmp(&b.id))
                });
                let summary = build_thread_summary(&tid, &msgs);
                if let Some(ref req_label) = resolved_label
                    && !summary.labels.contains(req_label)
                {
                    continue;
                }
                if query.unread_only && !summary.unread {
                    continue;
                }
                let max_ts = msgs
                    .iter()
                    .map(|m| m.internal_date_ms)
                    .max()
                    .unwrap_or(0);
                if let Some((cursor_ts, ref cursor_id)) = cursor
                    && !(max_ts < cursor_ts || (max_ts == cursor_ts && tid.as_str() < cursor_id.as_str()))
                {
                    continue;
                }
                summaries.push((max_ts, summary));
            }

            summaries.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.id.cmp(&a.1.id)));
            let has_more = summaries.len() > limit;
            if has_more {
                summaries.truncate(limit);
            }
            let next_cursor = if has_more {
                summaries
                    .last()
                    .map(|(ts, s)| encode_keyset_cursor(*ts, &s.id))
            } else {
                None
            };
            let threads = summaries.into_iter().map(|(_, s)| s).collect();

            Ok(AiThreadPage {
                threads,
                next_cursor,
                has_more,
            })
        })
        .await
    }

    async fn triage_thread(&self, thread_id: &str, patch: &TriagePatch) -> AppResult<TriageResult> {
        let detail = self
            .modify_thread_labels(thread_id, &patch.add_labels, &patch.remove_labels)
            .await?;
        let affected_message_ids: Vec<String> =
            detail.messages.iter().map(|m| m.id.clone()).collect();
        let mut label_set = HashSet::new();
        for m in &detail.messages {
            for l in &m.label_ids {
                label_set.insert(l.clone());
            }
        }
        let mut labels: Vec<String> = label_set.into_iter().collect();
        labels.sort();
        Ok(TriageResult {
            thread_id: detail.id,
            affected_message_ids,
            labels,
        })
    }

    async fn find_message_by_resend_id(&self, resend_id: &str) -> AppResult<Option<StoredMessage>> {
        let resend_id = resend_id.to_string();
        self.run_blocking(move |conn| {
            let id: Option<String> = conn
                .query_row(
                    "SELECT id FROM messages WHERE resend_id = ?1 LIMIT 1",
                    params![resend_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?;
            match id {
                Some(mid) => load_message_by_id(conn, &mid),
                None => Ok(None),
            }
        })
        .await
    }

    async fn find_message_by_rfc_message_id(
        &self,
        rfc822_message_id: &str,
    ) -> AppResult<Option<StoredMessage>> {
        let Some(norm) = normalize_rfc_message_id(rfc822_message_id) else {
            return Ok(None);
        };
        self.run_blocking(move |conn| {
            let id: Option<String> = conn
                .query_row(
                    "SELECT id FROM messages WHERE rfc822_message_id_norm = ?1 LIMIT 1",
                    params![norm],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?;
            match id {
                Some(mid) => load_message_by_id(conn, &mid),
                None => Ok(None),
            }
        })
        .await
    }

    async fn record_delivery_status(
        &self,
        resend_id: &str,
        status: &str,
    ) -> AppResult<Option<StoredMessage>> {
        let resend_id = resend_id.to_string();
        let status = status.to_string();
        self.run_blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let id: Option<String> = tx
                .query_row(
                    "SELECT id FROM messages WHERE resend_id = ?1 LIMIT 1",
                    params![&resend_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?;
            let Some(mid) = id else {
                return Ok(None);
            };
            tx.execute(
                "UPDATE messages SET delivery_status = ?1 WHERE id = ?2",
                params![&status, &mid],
            )
            .map_err(sql_err)?;
            let msg = load_message_by_id(&tx, &mid)?;
            tx.commit().map_err(sql_err)?;
            Ok(msg)
        })
        .await
    }

    async fn imap_list_mailboxes(&self) -> AppResult<Vec<ImapMailboxInfo>> {
        self.run_blocking(|conn| {
            let mut mailboxes = Vec::new();
            let builtins = [
                ResolvedMailbox::Label {
                    id: LABEL_INBOX.to_string(),
                    name: "INBOX".to_string(),
                    special_use: None,
                },
                ResolvedMailbox::AllMail,
                ResolvedMailbox::Label {
                    id: LABEL_SENT.to_string(),
                    name: SENT_MAILBOX.to_string(),
                    special_use: Some("\\Sent"),
                },
                ResolvedMailbox::Label {
                    id: LABEL_DRAFT.to_string(),
                    name: DRAFTS_MAILBOX.to_string(),
                    special_use: Some("\\Drafts"),
                },
                ResolvedMailbox::Label {
                    id: LABEL_TRASH.to_string(),
                    name: TRASH_MAILBOX.to_string(),
                    special_use: Some("\\Trash"),
                },
                ResolvedMailbox::Label {
                    id: LABEL_SPAM.to_string(),
                    name: SPAM_MAILBOX.to_string(),
                    special_use: Some("\\Junk"),
                },
                ResolvedMailbox::Label {
                    id: LABEL_STARRED.to_string(),
                    name: STARRED_MAILBOX.to_string(),
                    special_use: Some("\\Flagged"),
                },
            ];
            for mb in &builtins {
                mailboxes.push(load_imap_mailbox_info_resolved(conn, mb)?);
            }

            let mut stmt = conn
                .prepare("SELECT id, name FROM labels WHERE label_type = 'user' ORDER BY name ASC")
                .map_err(sql_err)?;
            let user_labels: Vec<(String, String)> = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(sql_err)?
                .collect::<Result<_, _>>()
                .map_err(sql_err)?;
            drop(stmt);

            for (id, name) in user_labels {
                let mb = ResolvedMailbox::Label {
                    id,
                    name,
                    special_use: None,
                };
                mailboxes.push(load_imap_mailbox_info_resolved(conn, &mb)?);
            }
            Ok(mailboxes)
        })
        .await
    }

    async fn imap_mailbox_info(&self, mailbox_name: &str) -> AppResult<Option<ImapMailboxInfo>> {
        let mailbox_name = mailbox_name.to_string();
        self.run_blocking(move |conn| {
            let Some(resolved) = resolve_imap_mailbox(conn, &mailbox_name)? else {
                return Ok(None);
            };
            Ok(Some(load_imap_mailbox_info_resolved(conn, &resolved)?))
        })
        .await
    }

    async fn imap_list_messages(&self, mailbox_name: &str) -> AppResult<Vec<ImapMessageEntry>> {
        let mailbox_name = mailbox_name.to_string();
        self.run_blocking(move |conn| {
            let resolved = resolve_imap_mailbox(conn, &mailbox_name)?
                .ok_or_else(|| AppError::NotFound(format!("Mailbox not found: {mailbox_name}")))?;
            load_imap_messages_resolved(conn, &resolved)
        })
        .await
    }

    async fn imap_set_flags(
        &self,
        message_id: &str,
        is_seen: bool,
        is_flagged: bool,
        is_draft: bool,
        is_answered: bool,
        is_deleted: bool,
    ) -> AppResult<StoredMessage> {
        let message_id = message_id.to_string();
        self.run_blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            if load_message_by_id(&tx, &message_id)?.is_none() {
                return Err(AppError::NotFound(format!(
                    "Message not found: {message_id}"
                )));
            }

            let mut add = Vec::new();
            let mut rem = Vec::new();
            if is_seen {
                rem.push(LABEL_UNREAD.to_string());
            } else {
                add.push(LABEL_UNREAD.to_string());
            }
            if is_flagged {
                add.push(LABEL_STARRED.to_string());
            } else {
                rem.push(LABEL_STARRED.to_string());
            }
            if is_draft {
                add.push(LABEL_DRAFT.to_string());
            } else {
                rem.push(LABEL_DRAFT.to_string());
            }

            tx.execute(
                "UPDATE messages SET is_answered = ?1, is_deleted = ?2 WHERE id = ?3",
                params![
                    if is_answered { 1_i64 } else { 0_i64 },
                    if is_deleted { 1_i64 } else { 0_i64 },
                    &message_id
                ],
            )
            .map_err(sql_err)?;

            let msg = modify_message_labels_resolved_tx(&tx, &message_id, &add, &rem)?;
            tx.commit().map_err(sql_err)?;
            Ok(msg)
        })
        .await
    }

    async fn imap_expunge(&self, mailbox_name: &str) -> AppResult<Vec<u32>> {
        let mailbox_name = mailbox_name.to_string();
        self.run_blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let resolved = resolve_imap_mailbox(&tx, &mailbox_name)?
                .ok_or_else(|| AppError::NotFound(format!("Mailbox not found: {mailbox_name}")))?;
            let entries = load_imap_messages_resolved(&tx, &resolved)?;

            let mut expunged_seqs = Vec::new();
            for entry in entries {
                if !entry.is_deleted {
                    continue;
                }
                expunged_seqs.push(entry.seq);
                match &resolved {
                    ResolvedMailbox::Label { id, .. } if id == LABEL_TRASH => {
                        delete_message_tx(&tx, &entry.message_id)?;
                    }
                    ResolvedMailbox::AllMail => {
                        tx.execute(
                            "UPDATE messages SET is_deleted = 0 WHERE id = ?1",
                            params![&entry.message_id],
                        )
                        .map_err(sql_err)?;
                        modify_message_labels_resolved_tx(
                            &tx,
                            &entry.message_id,
                            &[LABEL_TRASH.to_string()],
                            &[LABEL_INBOX.to_string()],
                        )?;
                    }
                    ResolvedMailbox::Label { id, .. } => {
                        tx.execute(
                            "UPDATE messages SET is_deleted = 0 WHERE id = ?1",
                            params![&entry.message_id],
                        )
                        .map_err(sql_err)?;
                        modify_message_labels_resolved_tx(
                            &tx,
                            &entry.message_id,
                            &[LABEL_TRASH.to_string()],
                            std::slice::from_ref(id),
                        )?;
                    }
                }
            }
            tx.commit().map_err(sql_err)?;
            Ok(expunged_seqs)
        })
        .await
    }

    async fn imap_copy_or_move(
        &self,
        src_mailbox: &str,
        dst_mailbox: &str,
        message_ids: &[String],
        is_move: bool,
    ) -> AppResult<Vec<(u32, u32)>> {
        let src_mailbox = src_mailbox.to_string();
        let dst_mailbox = dst_mailbox.to_string();
        let message_ids = message_ids.to_vec();
        self.run_blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let src = resolve_imap_mailbox(&tx, &src_mailbox)?
                .ok_or_else(|| AppError::NotFound(format!("Mailbox not found: {src_mailbox}")))?;
            let dst = resolve_imap_mailbox(&tx, &dst_mailbox)?
                .ok_or_else(|| AppError::NotFound(format!("Mailbox not found: {dst_mailbox}")))?;

            let same_mailbox = match (&src, &dst) {
                (ResolvedMailbox::AllMail, ResolvedMailbox::AllMail) => true,
                (
                    ResolvedMailbox::Label { id: a, .. },
                    ResolvedMailbox::Label { id: b, .. },
                ) => a == b,
                _ => false,
            };

            let src_entries = load_imap_messages_resolved(&tx, &src)?;
            let src_uid_map: HashMap<String, u32> = src_entries
                .into_iter()
                .map(|e| (e.message_id, e.uid))
                .collect();

            let mut pairs = Vec::new();
            for mid in &message_ids {
                let Some(&src_uid) = src_uid_map.get(mid) else {
                    continue;
                };

                let mut add_labels = Vec::new();
                let mut remove_labels = Vec::new();

                match &dst {
                    ResolvedMailbox::AllMail => {
                        remove_labels.push(LABEL_TRASH.to_string());
                        remove_labels.push(LABEL_SPAM.to_string());
                    }
                    ResolvedMailbox::Label { id: dst_id, .. } => {
                        add_labels.push(dst_id.clone());
                    }
                }

                if is_move && !same_mailbox
                    && let ResolvedMailbox::Label { id: src_id, .. } = &src
                {
                    remove_labels.push(src_id.clone());
                }

                let updated_msg =
                    modify_message_labels_resolved_tx(&tx, mid, &add_labels, &remove_labels)?;

                let dst_uid = match &dst {
                    ResolvedMailbox::AllMail => updated_msg.all_mail_uid,
                    ResolvedMailbox::Label { id: dst_id, .. } => tx
                        .query_row(
                            "SELECT imap_uid FROM message_labels WHERE message_id = ?1 AND label_id = ?2",
                            params![mid, dst_id],
                            |row| row.get::<_, i64>(0),
                        )
                        .map_err(sql_err)?
                        .max(1) as u32,
                };

                pairs.push((src_uid, dst_uid));
            }

            tx.commit().map_err(sql_err)?;
            Ok(pairs)
        })
        .await
    }

    async fn imap_append(
        &self,
        mailbox_name: &str,
        mut input: NewMessageInput,
    ) -> AppResult<(u32, u32, StoredMessage)> {
        let mailbox_name = mailbox_name.to_string();
        if input.source.trim().is_empty() {
            input.source = "imap_append".to_string();
        }
        self.run_blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let resolved = resolve_imap_mailbox(&tx, &mailbox_name)?
                .ok_or_else(|| AppError::NotFound(format!("Mailbox not found: {mailbox_name}")))?;

            match &resolved {
                ResolvedMailbox::AllMail => {
                    input
                        .label_ids
                        .retain(|l| l != LABEL_TRASH && l != LABEL_SPAM);
                }
                ResolvedMailbox::Label { id, .. } => {
                    if !input.label_ids.iter().any(|l| l == id) {
                        input.label_ids.push(id.clone());
                    }
                }
            }

            let msg = insert_message_tx(&tx, input)?;
            let (uid_validity, assigned_uid) = match &resolved {
                ResolvedMailbox::AllMail => {
                    let uv: i64 = tx
                        .query_row(
                            "SELECT uid_validity FROM imap_meta WHERE mailbox_name = ?1",
                            params![ALL_MAIL_MAILBOX],
                            |row| row.get(0),
                        )
                        .map_err(sql_err)?;
                    (uv.max(1) as u32, msg.all_mail_uid)
                }
                ResolvedMailbox::Label { id, .. } => {
                    let uv: i64 = tx
                        .query_row(
                            "SELECT uid_validity FROM labels WHERE id = ?1",
                            params![id],
                            |row| row.get(0),
                        )
                        .map_err(sql_err)?;
                    let uid: i64 = tx
                        .query_row(
                            "SELECT imap_uid FROM message_labels WHERE message_id = ?1 AND label_id = ?2",
                            params![&msg.id, id],
                            |row| row.get(0),
                        )
                        .map_err(sql_err)?;
                    (uv.max(1) as u32, uid.max(1) as u32)
                }
            };

            tx.commit().map_err(sql_err)?;
            Ok((uid_validity, assigned_uid, msg))
        })
        .await
    }

    async fn upsert_synced_message(&self, input: NewMessageInput) -> AppResult<UpsertOutcome> {
        self.run_blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;

            // 1. Match by upstream_gmail_id
            if let Some(ref ugid) = input.upstream_gmail_id
                && !ugid.trim().is_empty()
                && let Some(existing_id) = tx
                    .query_row(
                        "SELECT id FROM messages WHERE upstream_gmail_id = ?1 LIMIT 1",
                        params![ugid.trim()],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .map_err(sql_err)?
            {
                let existing = load_message_by_id(&tx, &existing_id)?
                    .ok_or_else(|| AppError::Storage("Missing matched upstream message".into()))?;

                let mut desired_labels = Vec::new();
                let mut seen = HashSet::new();
                for raw_l in &input.label_ids {
                    let lid = ensure_label_exists_tx(&tx, raw_l)?;
                    if seen.insert(lid.clone()) {
                        desired_labels.push(lid);
                    }
                }
                desired_labels.sort();

                let to_add: Vec<String> = desired_labels
                    .iter()
                    .filter(|l| !existing.label_ids.contains(l))
                    .cloned()
                    .collect();
                let to_remove: Vec<String> = existing
                    .label_ids
                    .iter()
                    .filter(|l| !desired_labels.contains(l))
                    .cloned()
                    .collect();

                let flags_changed = existing.is_answered != input.is_answered
                    || existing.is_deleted != input.is_deleted;
                let labels_changed = !to_add.is_empty() || !to_remove.is_empty();

                if flags_changed {
                    tx.execute(
                        "UPDATE messages SET is_answered = ?1, is_deleted = ?2 WHERE id = ?3",
                        params![
                            if input.is_answered { 1_i64 } else { 0_i64 },
                            if input.is_deleted { 1_i64 } else { 0_i64 },
                            &existing_id
                        ],
                    )
                    .map_err(sql_err)?;
                }

                let updated = if labels_changed {
                    modify_message_labels_resolved_tx(&tx, &existing_id, &to_add, &to_remove)?
                } else {
                    load_message_by_id(&tx, &existing_id)?.ok_or_else(|| {
                        AppError::Storage("Missing message after sync update".into())
                    })?
                };

                let kind = if labels_changed || flags_changed {
                    UpsertOutcomeKind::Updated
                } else {
                    UpsertOutcomeKind::Deduplicated
                };
                tx.commit().map_err(sql_err)?;
                return Ok(UpsertOutcome {
                    kind,
                    message: updated,
                });
            }

            // 2. Match by normalized rfc822_message_id (dedup across Resend <-> Gmail)
            if let Some(norm) = input
                .rfc822_message_id
                .as_deref()
                .and_then(normalize_rfc_message_id)
                && let Some(existing_id) = tx
                    .query_row(
                        "SELECT id FROM messages WHERE rfc822_message_id_norm = ?1 LIMIT 1",
                        params![norm],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .map_err(sql_err)?
            {
                let existing = load_message_by_id(&tx, &existing_id)?
                    .ok_or_else(|| AppError::Storage("Missing matched rfc822 message".into()))?;

                // Backfill upstream IDs if absent
                if existing.upstream_gmail_id.is_none() && input.upstream_gmail_id.is_some() {
                    tx.execute(
                        "UPDATE messages SET upstream_gmail_id = ?1 WHERE id = ?2",
                        params![&input.upstream_gmail_id, &existing_id],
                    )
                    .map_err(sql_err)?;
                }
                if existing.upstream_thread_id.is_none() && input.upstream_thread_id.is_some() {
                    tx.execute(
                        "UPDATE messages SET upstream_thread_id = ?1 WHERE id = ?2",
                        params![&input.upstream_thread_id, &existing_id],
                    )
                    .map_err(sql_err)?;
                }

                // Merge incoming labels into existing labels
                let mut to_add = Vec::new();
                for raw_l in &input.label_ids {
                    let lid = ensure_label_exists_tx(&tx, raw_l)?;
                    if !existing.label_ids.contains(&lid) && !to_add.contains(&lid) {
                        to_add.push(lid);
                    }
                }
                let updated = if !to_add.is_empty() {
                    modify_message_labels_resolved_tx(&tx, &existing_id, &to_add, &[])?
                } else {
                    load_message_by_id(&tx, &existing_id)?
                        .ok_or_else(|| AppError::Storage("Missing message after dedup".into()))?
                };
                tx.commit().map_err(sql_err)?;
                return Ok(UpsertOutcome {
                    kind: UpsertOutcomeKind::Deduplicated,
                    message: updated,
                });
            }

            // 3. Insert new message
            let inserted = insert_message_tx(&tx, input)?;
            tx.commit().map_err(sql_err)?;
            Ok(UpsertOutcome {
                kind: UpsertOutcomeKind::Inserted,
                message: inserted,
            })
        })
        .await
    }

    async fn find_message_by_upstream_id(
        &self,
        upstream_gmail_id: &str,
    ) -> AppResult<Option<StoredMessage>> {
        let upstream_gmail_id = upstream_gmail_id.to_string();
        self.run_blocking(move |conn| {
            let id: Option<String> = conn
                .query_row(
                    "SELECT id FROM messages WHERE upstream_gmail_id = ?1 LIMIT 1",
                    params![upstream_gmail_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?;
            match id {
                Some(mid) => load_message_by_id(conn, &mid),
                None => Ok(None),
            }
        })
        .await
    }

    async fn delete_message_by_upstream_id(
        &self,
        upstream_gmail_id: &str,
    ) -> AppResult<Option<StoredMessage>> {
        let upstream_gmail_id = upstream_gmail_id.to_string();
        self.run_blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let id: Option<String> = tx
                .query_row(
                    "SELECT id FROM messages WHERE upstream_gmail_id = ?1 LIMIT 1",
                    params![upstream_gmail_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?;
            let deleted = match id {
                Some(mid) => delete_message_tx(&tx, &mid)?,
                None => None,
            };
            tx.commit().map_err(sql_err)?;
            Ok(deleted)
        })
        .await
    }

    async fn get_sync_state(&self, account_key: &str) -> AppResult<Option<SyncState>> {
        let account_key = account_key.to_string();
        self.run_blocking(move |conn| {
            conn.query_row(
                "SELECT account_key, provider, last_history_id, imap_mailbox, imap_uid_validity,
                        imap_last_uid, last_sync_at_ms, last_full_sync_at_ms, status, last_error, messages_synced
                 FROM sync_state WHERE account_key = ?1",
                params![account_key],
                sync_state_from_row,
            )
            .optional()
            .map_err(sql_err)
        })
        .await
    }

    async fn save_sync_state(&self, state: SyncState) -> AppResult<()> {
        self.run_blocking(move |conn| {
            conn.execute(
                "INSERT INTO sync_state (
                    account_key, provider, last_history_id, imap_mailbox, imap_uid_validity,
                    imap_last_uid, last_sync_at_ms, last_full_sync_at_ms, status, last_error, messages_synced
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(account_key) DO UPDATE SET
                    provider = excluded.provider,
                    last_history_id = excluded.last_history_id,
                    imap_mailbox = excluded.imap_mailbox,
                    imap_uid_validity = excluded.imap_uid_validity,
                    imap_last_uid = excluded.imap_last_uid,
                    last_sync_at_ms = excluded.last_sync_at_ms,
                    last_full_sync_at_ms = excluded.last_full_sync_at_ms,
                    status = excluded.status,
                    last_error = excluded.last_error,
                    messages_synced = excluded.messages_synced",
                params![
                    &state.account_key,
                    &state.provider,
                    &state.last_history_id,
                    &state.imap_mailbox,
                    state.imap_uid_validity.map(|v| v as i64),
                    state.imap_last_uid.map(|v| v as i64),
                    state.last_sync_at.map(|dt| dt.timestamp_millis()),
                    state.last_full_sync_at.map(|dt| dt.timestamp_millis()),
                    &state.status,
                    &state.last_error,
                    state.messages_synced as i64,
                ],
            )
            .map_err(sql_err)?;
            Ok(())
        })
        .await
    }

    async fn list_sync_states(&self) -> AppResult<Vec<SyncState>> {
        self.run_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT account_key, provider, last_history_id, imap_mailbox, imap_uid_validity,
                            imap_last_uid, last_sync_at_ms, last_full_sync_at_ms, status, last_error, messages_synced
                     FROM sync_state ORDER BY account_key ASC",
                )
                .map_err(sql_err)?;
            let rows = stmt
                .query_map([], sync_state_from_row)
                .map_err(sql_err)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(sql_err)?);
            }
            Ok(out)
        })
        .await
    }

    async fn set_watch(&self, watch: WatchSubscription) -> AppResult<WatchSubscription> {
        self.run_blocking(move |conn| {
            let labels_json = serde_json::to_string(&watch.label_ids)
                .map_err(|e| AppError::Storage(format!("JSON encode error: {e}")))?;
            conn.execute(
                "INSERT INTO watch_state (id, topic_name, label_ids_json, label_filter_behavior, history_id, expiration_ms)
                 VALUES (1, ?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(id) DO UPDATE SET
                    topic_name = excluded.topic_name,
                    label_ids_json = excluded.label_ids_json,
                    label_filter_behavior = excluded.label_filter_behavior,
                    history_id = excluded.history_id,
                    expiration_ms = excluded.expiration_ms",
                params![
                    &watch.topic_name,
                    labels_json,
                    &watch.label_filter_behavior,
                    watch.history_id as i64,
                    watch.expiration_ms,
                ],
            )
            .map_err(sql_err)?;
            Ok(watch)
        })
        .await
    }

    async fn get_watch(&self) -> AppResult<Option<WatchSubscription>> {
        self.run_blocking(|conn| {
            conn.query_row(
                "SELECT topic_name, label_ids_json, label_filter_behavior, history_id, expiration_ms
                 FROM watch_state WHERE id = 1",
                [],
                |row| {
                    let labels_json: String = row.get(1)?;
                    let label_ids: Vec<String> =
                        serde_json::from_str(&labels_json).unwrap_or_default();
                    Ok(WatchSubscription {
                        topic_name: row.get(0)?,
                        label_ids,
                        label_filter_behavior: row.get(2)?,
                        history_id: row.get::<_, i64>(3)?.max(0) as u64,
                        expiration_ms: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(sql_err)
        })
        .await
    }

    async fn clear_watch(&self) -> AppResult<()> {
        self.run_blocking(|conn| {
            conn.execute("DELETE FROM watch_state WHERE id = 1", [])
                .map_err(sql_err)?;
            Ok(())
        })
        .await
    }

    async fn get_settings(&self) -> AppResult<UserSettings> {
        let default_email = self.default_email.clone();
        self.run_blocking(move |conn| {
            let defaults = UserSettings::default_for_email(&default_email);
            let send_as: Vec<SendAs> = read_setting(conn, "send_as")?.unwrap_or(defaults.send_as);
            let vacation: VacationSettings =
                read_setting(conn, "vacation")?.unwrap_or(defaults.vacation);
            let auto_forwarding: AutoForwarding =
                read_setting(conn, "auto_forwarding")?.unwrap_or(defaults.auto_forwarding);
            let imap: ImapSettings = read_setting(conn, "imap")?.unwrap_or(defaults.imap);
            let pop: PopSettings = read_setting(conn, "pop")?.unwrap_or(defaults.pop);
            Ok(UserSettings {
                send_as,
                vacation,
                auto_forwarding,
                imap,
                pop,
            })
        })
        .await
    }

    async fn save_settings(&self, settings: UserSettings) -> AppResult<UserSettings> {
        self.run_blocking(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            write_setting(&tx, "send_as", &settings.send_as)?;
            write_setting(&tx, "vacation", &settings.vacation)?;
            write_setting(&tx, "auto_forwarding", &settings.auto_forwarding)?;
            write_setting(&tx, "imap", &settings.imap)?;
            write_setting(&tx, "pop", &settings.pop)?;
            tx.commit().map_err(sql_err)?;
            Ok(settings)
        })
        .await
    }
}

fn sync_state_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SyncState> {
    let last_sync_ms: Option<i64> = row.get(6)?;
    let last_full_ms: Option<i64> = row.get(7)?;
    Ok(SyncState {
        account_key: row.get(0)?,
        provider: row.get(1)?,
        last_history_id: row.get(2)?,
        imap_mailbox: row.get(3)?,
        imap_uid_validity: row.get::<_, Option<i64>>(4)?.map(|v| v.max(0) as u32),
        imap_last_uid: row.get::<_, Option<i64>>(5)?.map(|v| v.max(0) as u32),
        last_sync_at: last_sync_ms.and_then(DateTime::from_timestamp_millis),
        last_full_sync_at: last_full_ms.and_then(DateTime::from_timestamp_millis),
        status: row.get(8)?,
        last_error: row.get(9)?,
        messages_synced: row.get::<_, i64>(10)?.max(0) as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::NewAttachmentInput;

    fn sample_message(subject: &str, from: &str, text: &str, ts_ms: i64) -> NewMessageInput {
        NewMessageInput {
            id: None,
            thread_id: None,
            label_ids: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            raw_rfc2822: format!(
                "From: {from}\r\nTo: me@example.com\r\nSubject: {subject}\r\n\r\n{text}"
            )
            .into_bytes(),
            snippet: text.chars().take(120).collect(),
            internal_date_ms: ts_ms,
            subject: subject.to_string(),
            from_addr: from.to_string(),
            to_addrs: vec!["me@example.com".to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: text.to_string(),
            html_body: None,
            rfc822_message_id: None,
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "local".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: vec![],
        }
    }

    #[tokio::test]
    async fn sqlite_wal_file_persistence_and_seeding() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("nogml.db");

        {
            let store = SqliteStore::open(&db_path, "alice@example.com").unwrap();
            let journal_mode: String = store
                .pool
                .get()
                .unwrap()
                .query_row("PRAGMA journal_mode", [], |r| r.get(0))
                .unwrap();
            assert_eq!(journal_mode.to_ascii_lowercase(), "wal");

            let labels = store.list_labels().await.unwrap();
            assert_eq!(labels.len(), SYSTEM_LABEL_IDS.len());
            for sys in SYSTEM_LABEL_IDS {
                assert!(
                    labels
                        .iter()
                        .any(|l| l.id == *sys && l.label_type == "system")
                );
            }

            let settings = store.get_settings().await.unwrap();
            assert_eq!(settings.send_as.len(), 1);
            assert_eq!(settings.send_as[0].send_as_email, "alice@example.com");
            assert_eq!(settings.send_as[0].is_primary, Some(true));

            store
                .insert_message(sample_message(
                    "Persist check",
                    "bob@example.com",
                    "Persisted across reopen",
                    1_700_000_000_000,
                ))
                .await
                .unwrap();
        }

        // Reopen from disk and confirm data + history + settings persist
        let store = SqliteStore::open(&db_path, "alice@example.com").unwrap();
        let profile = store.get_profile("alice@example.com").await.unwrap();
        assert_eq!(profile.messages_total, 1);
        assert_eq!(profile.threads_total, 1);
        assert!(store.current_history_id().await.unwrap() >= 2);
    }

    #[tokio::test]
    async fn sqlite_fts5_search_filters_and_cursor_pagination() {
        let store = SqliteStore::open_in_memory("me@example.com").unwrap();

        let mut m1 = sample_message(
            "Quarterly financial report",
            "Alice <alice@acme.com>",
            "Here are the Q3 revenue numbers and budgets.",
            1_700_000_001_000,
        );
        m1.attachments.push(NewAttachmentInput {
            part_id: "2".to_string(),
            filename: Some("q3.pdf".to_string()),
            content_type: "application/pdf".to_string(),
            content_id: None,
            data: b"%PDF-1.7 fake".to_vec(),
        });
        let stored1 = store.insert_message(m1).await.unwrap();

        let m2 = sample_message(
            "Quarterly planning notes",
            "Bob <bob@acme.com>",
            "Let us review quarterly goals tomorrow.",
            1_700_000_002_000,
        );
        let stored2 = store.insert_message(m2).await.unwrap();

        let m3 = sample_message(
            "Weekend hike",
            "Carol <carol@other.org>",
            "Trailhead opens at 8am.",
            1_700_000_003_000,
        );
        let stored3 = store.insert_message(m3).await.unwrap();

        // FTS5 stemmed search + pagination (limit=1)
        let p1 = store
            .search_messages_ai(&AiSearchQuery {
                q: Some("quarterly".to_string()),
                limit: 1,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(p1.messages.len(), 1);
        assert_eq!(p1.messages[0].id, stored2.id);
        assert!(p1.has_more);
        assert!(p1.next_cursor.is_some());

        let p2 = store
            .search_messages_ai(&AiSearchQuery {
                q: Some("quarterly".to_string()),
                limit: 1,
                cursor: p1.next_cursor.clone(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(p2.messages.len(), 1);
        assert_eq!(p2.messages[0].id, stored1.id);
        assert!(!p2.has_more);

        // Structured filters: from + has_attachment + punctuation-safe FTS5 query
        let filtered = store
            .search_messages_ai(&AiSearchQuery {
                q: Some("alice@acme.com".to_string()),
                from: Some("acme.com".to_string()),
                has_attachment: Some(true),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(filtered.messages.len(), 1);
        assert_eq!(filtered.messages[0].id, stored1.id);

        // Attachment retrieval & metadata
        let meta = store.list_attachment_meta(&stored1.id).await.unwrap();
        assert_eq!(meta.len(), 1);
        assert_eq!(meta[0].filename.as_deref(), Some("q3.pdf"));
        let att = store
            .get_attachment(&stored1.id, &meta[0].id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(att.data, b"%PDF-1.7 fake");

        // Deleting removes from FTS5 index too
        assert!(store.delete_message(&stored3.id).await.unwrap());
        let after_del = store
            .search_messages_ai(&AiSearchQuery {
                q: Some("trailhead".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(after_del.messages.is_empty());
    }

    #[tokio::test]
    async fn sqlite_history_labels_threads_and_drafts() {
        let store = SqliteStore::open_in_memory("me@example.com").unwrap();
        let start_hid = store.current_history_id().await.unwrap();
        assert_eq!(start_hid, 1);

        // startHistoryId == 0 must return NotFound
        let err = store
            .list_history(&HistoryListQuery {
                start_history_id: 0,
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)));

        let work = store
            .create_label(NewLabelInput {
                name: "Work".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(work.label_type, "user");

        // Threading via In-Reply-To
        let mut m1 = sample_message("Project Kickoff", "a@ex.com", "First msg", 1000);
        m1.rfc822_message_id = Some("<MSG-1@EX.COM>".to_string());
        let s1 = store.insert_message(m1).await.unwrap();

        let mut m2 = sample_message("Re: Project Kickoff", "b@ex.com", "Second msg", 2000);
        m2.in_reply_to = Some("msg-1@ex.com".to_string());
        m2.label_ids = vec![LABEL_INBOX.to_string()]; // read
        let s2 = store.insert_message(m2).await.unwrap();
        assert_eq!(s1.thread_id, s2.thread_id);

        // Label counts: 2 msgs in INBOX, 1 unread; 1 thread in INBOX, 1 unread
        let inbox = store.get_label(LABEL_INBOX).await.unwrap().unwrap();
        assert_eq!(inbox.messages_total, 2);
        assert_eq!(inbox.messages_unread, 1);
        assert_eq!(inbox.threads_total, 1);
        assert_eq!(inbox.threads_unread, 1);

        // Triage thread: add Work, mark read
        let triage = store
            .triage_thread(
                &s1.thread_id,
                &TriagePatch {
                    add_labels: vec![work.id.clone()],
                    remove_labels: vec![LABEL_UNREAD.to_string()],
                },
            )
            .await
            .unwrap();
        assert_eq!(triage.affected_message_ids.len(), 2);
        assert!(triage.labels.contains(&work.id));
        assert!(!triage.labels.contains(&LABEL_UNREAD.to_string()));

        // Thread summaries
        let summaries = store
            .list_thread_summaries(&AiThreadQuery {
                label: Some("Work".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(summaries.threads.len(), 1);
        assert_eq!(summaries.threads[0].message_count, 2);
        assert!(!summaries.threads[0].unread);

        // History events captured additions + label changes
        let hist = store
            .list_history(&HistoryListQuery {
                start_history_id: start_hid,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(hist.entries.len() >= 4);
        assert!(
            hist.entries
                .iter()
                .any(|e| e.kind == HistoryEventKind::MessageAdded)
        );
        assert!(
            hist.entries
                .iter()
                .any(|e| e.kind == HistoryEventKind::LabelAdded)
        );
        assert!(
            hist.entries
                .iter()
                .any(|e| e.kind == HistoryEventKind::LabelRemoved)
        );

        // Draft lifecycle
        let d = store
            .create_draft(sample_message("Draft 1", "me@example.com", "v1", 3000))
            .await
            .unwrap();
        assert!(d.message.label_ids.contains(&LABEL_DRAFT.to_string()));
        let d_upd = store
            .update_draft(
                &d.id,
                sample_message("Draft 1 edited", "me@example.com", "v2", 4000),
            )
            .await
            .unwrap();
        assert_eq!(d_upd.id, d.id);
        assert_ne!(d_upd.message.id, d.message.id);
        assert_eq!(d_upd.message.text_body, "v2");
        assert!(store.get_message(&d.message.id).await.unwrap().is_none());
        assert!(store.delete_draft(&d.id).await.unwrap());
        assert!(store.get_draft(&d.id).await.unwrap().is_none());

        // Cannot delete system label
        assert!(matches!(
            store.delete_label(LABEL_INBOX).await,
            Err(AppError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn sqlite_imap_per_mailbox_uids_flags_move_expunge() {
        let store = SqliteStore::open_in_memory("me@example.com").unwrap();
        let work = store
            .create_label(NewLabelInput {
                name: "Work".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();

        let (uv, uid1, m1) = store
            .imap_append("INBOX", sample_message("One", "a@ex.com", "body1", 1000))
            .await
            .unwrap();
        assert!(uv >= 1);
        assert_eq!(uid1, 1);

        let (_, uid2, m2) = store
            .imap_append("INBOX", sample_message("Two", "b@ex.com", "body2", 2000))
            .await
            .unwrap();
        assert_eq!(uid2, 2);

        // Attach Work to m2 first, then m1 -> UIDs in Work must still be strictly monotonic (m2=1, m1=2)!
        store
            .modify_message_labels(&m2.id, std::slice::from_ref(&work.id), &[])
            .await
            .unwrap();
        store
            .modify_message_labels(&m1.id, std::slice::from_ref(&work.id), &[])
            .await
            .unwrap();

        let work_entries = store.imap_list_messages("Work").await.unwrap();
        assert_eq!(work_entries.len(), 2);
        assert_eq!(work_entries[0].message_id, m2.id);
        assert_eq!(work_entries[0].uid, 1);
        assert_eq!(work_entries[1].message_id, m1.id);
        assert_eq!(work_entries[1].uid, 2);

        // Set flags on m1
        let flagged = store
            .imap_set_flags(&m1.id, true, true, false, true, true)
            .await
            .unwrap();
        assert!(!flagged.label_ids.contains(&LABEL_UNREAD.to_string()));
        assert!(flagged.label_ids.contains(&LABEL_STARRED.to_string()));
        assert!(flagged.is_answered);
        assert!(flagged.is_deleted);

        // Expunge INBOX -> moves m1 to TRASH, returns seq 1
        let expunged = store.imap_expunge("INBOX").await.unwrap();
        assert_eq!(expunged, vec![1]);
        let m1_after = store.get_message(&m1.id).await.unwrap().unwrap();
        assert!(m1_after.label_ids.contains(&LABEL_TRASH.to_string()));
        assert!(!m1_after.label_ids.contains(&LABEL_INBOX.to_string()));
        assert!(!m1_after.is_deleted);

        // All Mail excludes TRASH
        let all_mail = store.imap_list_messages(ALL_MAIL_MAILBOX).await.unwrap();
        assert_eq!(all_mail.len(), 1);
        assert_eq!(all_mail[0].message_id, m2.id);

        // Move m2 from INBOX to [Gmail]/Starred
        let moved = store
            .imap_copy_or_move("INBOX", STARRED_MAILBOX, std::slice::from_ref(&m2.id), true)
            .await
            .unwrap();
        assert_eq!(moved.len(), 1);
        assert_eq!(moved[0].0, 2); // src UID in INBOX
        let inbox_after = store.imap_list_messages("INBOX").await.unwrap();
        assert!(inbox_after.is_empty());

        // Expunge in Trash permanently deletes
        store
            .imap_set_flags(&m1.id, true, false, false, false, true)
            .await
            .unwrap();
        let trash_expunged = store.imap_expunge(TRASH_MAILBOX).await.unwrap();
        assert_eq!(trash_expunged, vec![1]);
        assert!(store.get_message(&m1.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn sqlite_upsert_synced_message_dedup_and_watch_sync_state() {
        let store = SqliteStore::open_in_memory("me@example.com").unwrap();

        // Local message sent via Resend with RFC Message-ID
        let mut local = sample_message("Hello", "me@example.com", "Sent locally", 1000);
        local.label_ids = vec![LABEL_SENT.to_string()];
        local.rfc822_message_id = Some("<abc-123@example.com>".to_string());
        local.resend_id = Some("re_999".to_string());
        let local_stored = store.insert_message(local).await.unwrap();

        // Resend webhook delivery status update
        let delivered = store
            .record_delivery_status("re_999", "delivered")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(delivered.delivery_status.as_deref(), Some("delivered"));

        // Upstream Gmail sync sees same RFC Message-ID (different case, no brackets) -> deduplicates!
        let mut synced = sample_message("Hello", "me@example.com", "Sent locally", 1000);
        synced.label_ids = vec![LABEL_SENT.to_string(), LABEL_STARRED.to_string()];
        synced.rfc822_message_id = Some("ABC-123@EXAMPLE.COM".to_string());
        synced.upstream_gmail_id = Some("18f0001".to_string());
        synced.upstream_thread_id = Some("18f0001".to_string());
        synced.source = "gmail_api".to_string();

        let outcome = store.upsert_synced_message(synced.clone()).await.unwrap();
        assert_eq!(outcome.kind, UpsertOutcomeKind::Deduplicated);
        assert_eq!(outcome.message.id, local_stored.id);
        assert_eq!(
            outcome.message.upstream_gmail_id.as_deref(),
            Some("18f0001")
        );
        assert!(
            outcome
                .message
                .label_ids
                .contains(&LABEL_STARRED.to_string())
        );

        // Re-syncing same upstream_gmail_id with changed labels -> Updated
        let mut synced2 = synced;
        synced2.label_ids = vec![LABEL_SENT.to_string()];
        let outcome2 = store.upsert_synced_message(synced2).await.unwrap();
        assert_eq!(outcome2.kind, UpsertOutcomeKind::Updated);
        assert!(
            !outcome2
                .message
                .label_ids
                .contains(&LABEL_STARRED.to_string())
        );

        // Watch & SyncState round-trip
        let watch = WatchSubscription {
            topic_name: "projects/p/topics/t".to_string(),
            label_ids: vec![LABEL_INBOX.to_string()],
            label_filter_behavior: "include".to_string(),
            history_id: 42,
            expiration_ms: 9_999_999,
        };
        store.set_watch(watch.clone()).await.unwrap();
        assert_eq!(
            store.get_watch().await.unwrap().unwrap().topic_name,
            watch.topic_name
        );
        store.clear_watch().await.unwrap();
        assert!(store.get_watch().await.unwrap().is_none());

        let st = SyncState {
            account_key: "primary".to_string(),
            provider: "gmail_api".to_string(),
            last_history_id: Some("12345".to_string()),
            status: "ok".to_string(),
            messages_synced: 10,
            ..Default::default()
        };
        store.save_sync_state(st).await.unwrap();
        assert_eq!(
            store
                .get_sync_state("primary")
                .await
                .unwrap()
                .unwrap()
                .last_history_id
                .as_deref(),
            Some("12345")
        );
        assert_eq!(store.list_sync_states().await.unwrap().len(), 1);
    }
}
