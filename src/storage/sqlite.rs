//! SQLite-backed `MailStore` implementation (WAL mode + FTS5 + per-mailbox IMAP UIDs).
//!
//! Owned by the `storage` worker.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::Path,
    sync::{Arc, Mutex},
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
        AiMessagePage, AiSearchQuery, AiThreadPage, AiThreadQuery, ApprovalStatus, DraftListPage,
        HistoryEventKind, HistoryListPage, HistoryListQuery, ImapMailboxInfo, ImapMessageEntry,
        MailStore, MessageListPage, MessageListQuery, NewLabelInput, NewMessageInput,
        NewPendingApprovalInput, PendingApproval, StoredAttachment, StoredDraft,
        StoredHistoryEntry, StoredLabel, StoredMessage, StoredThreadDetail, SyncState,
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
    mailbox_id TEXT NOT NULL,
    key TEXT NOT NULL,
    int_val INTEGER,
    text_val TEXT,
    PRIMARY KEY (mailbox_id, key)
);

CREATE TABLE IF NOT EXISTS labels (
    mailbox_id TEXT NOT NULL,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    label_type TEXT NOT NULL,
    message_list_visibility TEXT,
    label_list_visibility TEXT,
    color_text TEXT,
    color_background TEXT,
    uid_validity INTEGER NOT NULL,
    uid_next INTEGER NOT NULL DEFAULT 1,
    upstream_label_id TEXT,
    PRIMARY KEY (mailbox_id, id)
);
CREATE INDEX IF NOT EXISTS idx_labels_mailbox_name_nocase ON labels (mailbox_id, name COLLATE NOCASE);
CREATE UNIQUE INDEX IF NOT EXISTS idx_labels_mailbox_upstream
    ON labels (mailbox_id, upstream_label_id) WHERE upstream_label_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS imap_meta (
    mailbox_id TEXT NOT NULL,
    mailbox_name TEXT NOT NULL,
    uid_validity INTEGER NOT NULL,
    uid_next INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (mailbox_id, mailbox_name)
);

CREATE TABLE IF NOT EXISTS imap_expunged_uids (
    mailbox_id TEXT NOT NULL,
    mailbox_key TEXT NOT NULL,
    imap_uid INTEGER NOT NULL,
    modseq INTEGER NOT NULL,
    PRIMARY KEY (mailbox_id, mailbox_key, imap_uid)
);
CREATE INDEX IF NOT EXISTS idx_imap_expunged_mailbox_modseq
    ON imap_expunged_uids (mailbox_id, mailbox_key, modseq);

CREATE TABLE IF NOT EXISTS messages (
    mailbox_id TEXT NOT NULL,
    id TEXT NOT NULL,
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
    upstream_gmail_id TEXT,
    upstream_thread_id TEXT,
    source TEXT NOT NULL DEFAULT 'local',
    all_mail_uid INTEGER NOT NULL,
    is_answered INTEGER NOT NULL DEFAULT 0,
    is_deleted INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (mailbox_id, id)
);
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_thread_id
    ON messages (mailbox_id, thread_id, internal_date_ms, id);
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_date_id
    ON messages (mailbox_id, internal_date_ms DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_rfc822_norm
    ON messages (mailbox_id, rfc822_message_id_norm);
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_resend_id
    ON messages (mailbox_id, resend_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_mailbox_upstream_gmail
    ON messages (mailbox_id, upstream_gmail_id) WHERE upstream_gmail_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_upstream_thread
    ON messages (mailbox_id, upstream_thread_id);
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_all_mail_uid
    ON messages (mailbox_id, all_mail_uid);

CREATE TABLE IF NOT EXISTS message_labels (
    mailbox_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    label_id TEXT NOT NULL,
    imap_uid INTEGER NOT NULL,
    PRIMARY KEY (mailbox_id, message_id, label_id),
    FOREIGN KEY (mailbox_id, message_id) REFERENCES messages(mailbox_id, id) ON DELETE CASCADE,
    FOREIGN KEY (mailbox_id, label_id) REFERENCES labels(mailbox_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_message_labels_mailbox_label_uid
    ON message_labels (mailbox_id, label_id, imap_uid);

CREATE TABLE IF NOT EXISTS attachments (
    mailbox_id TEXT NOT NULL,
    id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    part_id TEXT NOT NULL,
    filename TEXT,
    content_type TEXT NOT NULL,
    content_id TEXT,
    size_bytes INTEGER NOT NULL,
    data BLOB NOT NULL,
    PRIMARY KEY (mailbox_id, id),
    FOREIGN KEY (mailbox_id, message_id) REFERENCES messages(mailbox_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_attachments_mailbox_message_id
    ON attachments (mailbox_id, message_id, part_id, id);

CREATE TABLE IF NOT EXISTS drafts (
    mailbox_id TEXT NOT NULL,
    id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (mailbox_id, id),
    UNIQUE (mailbox_id, message_id),
    FOREIGN KEY (mailbox_id, message_id) REFERENCES messages(mailbox_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_drafts_mailbox_updated
    ON drafts (mailbox_id, updated_at_ms DESC, id DESC);

CREATE TABLE IF NOT EXISTS history_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox_id TEXT NOT NULL,
    history_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    message_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    label_ids_json TEXT NOT NULL,
    context_labels_json TEXT NOT NULL DEFAULT '[]',
    upstream_gmail_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_history_events_mailbox_hid
    ON history_events (mailbox_id, history_id, id);

CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
    mailbox_id UNINDEXED,
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
    mailbox_id TEXT NOT NULL,
    account_key TEXT NOT NULL,
    provider TEXT NOT NULL,
    last_history_id TEXT,
    imap_mailbox TEXT,
    imap_uid_validity INTEGER,
    imap_last_uid INTEGER,
    last_sync_at_ms INTEGER,
    last_full_sync_at_ms INTEGER,
    status TEXT NOT NULL,
    last_error TEXT,
    messages_synced INTEGER NOT NULL DEFAULT 0,
    last_pushed_history_id INTEGER,
    messages_pushed INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (mailbox_id, account_key)
);

CREATE TABLE IF NOT EXISTS watch_state (
    mailbox_id TEXT PRIMARY KEY,
    topic_name TEXT NOT NULL,
    label_ids_json TEXT NOT NULL,
    label_filter_behavior TEXT NOT NULL,
    history_id INTEGER NOT NULL,
    expiration_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    mailbox_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    PRIMARY KEY (mailbox_id, key)
);

CREATE TABLE IF NOT EXISTS pending_approvals (
    mailbox_id TEXT NOT NULL,
    id TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL,
    requester_json TEXT,
    outbound_message_json TEXT NOT NULL,
    reply_to_message_id TEXT,
    thread_id TEXT,
    draft_id TEXT,
    sent_message_id TEXT,
    provider_message_id TEXT,
    decided_by TEXT,
    decision_note TEXT,
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    decided_at_ms INTEGER,
    PRIMARY KEY (mailbox_id, id)
);
CREATE INDEX IF NOT EXISTS idx_pending_approvals_mailbox_status_created
    ON pending_approvals (mailbox_id, status, created_at_ms DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_pending_approvals_mailbox_created
    ON pending_approvals (mailbox_id, created_at_ms DESC, id DESC);
"#;

/// SQLite-backed implementation of [`MailStore`], partitioned by `mailbox_id`.
#[derive(Clone)]
pub struct SqliteStore {
    pool: Pool<SqliteConnectionManager>,
    mailbox_id: String,
    seeded_mailboxes: Arc<Mutex<HashSet<String>>>,
}

impl SqliteStore {
    /// Inspect an existing SQLite database file at `path` and return all distinct `mailbox_id`
    /// values stored in `meta` (sorted). Returns an empty list if the file does not exist or
    /// uses a legacy v1 schema without a `mailbox_id` column.
    pub fn list_mailbox_ids(path: &Path) -> AppResult<Vec<String>> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        let conn = Connection::open(path).map_err(sql_err)?;
        if !table_exists(&conn, "meta")? || !column_exists_conn(&conn, "meta", "mailbox_id")? {
            return Ok(Vec::new());
        }
        let mut stmt = conn
            .prepare("SELECT DISTINCT mailbox_id FROM meta ORDER BY mailbox_id ASC")
            .map_err(sql_err)?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(sql_err)?;
        let mut out = Vec::new();
        for r in rows {
            let mb = r.map_err(sql_err)?;
            if !mb.trim().is_empty() {
                out.push(mb);
            }
        }
        Ok(out)
    }

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

        let mailbox_id = crate::config::normalize_mailbox_id(default_email);
        let store = Self {
            pool,
            mailbox_id,
            seeded_mailboxes: Arc::new(Mutex::new(HashSet::new())),
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

        let mailbox_id = crate::config::normalize_mailbox_id(default_email);
        let store = Self {
            pool,
            mailbox_id,
            seeded_mailboxes: Arc::new(Mutex::new(HashSet::new())),
        };
        store.initialize()?;
        Ok(store)
    }

    fn initialize(&self) -> AppResult<()> {
        let mut conn = self
            .pool
            .get()
            .map_err(|e| AppError::Storage(format!("SQLite pool error: {e}")))?;

        if needs_v1_multi_mailbox_migration(&conn)? {
            migrate_v1_to_multi_mailbox(&mut conn, &self.mailbox_id)?;
        }

        conn.execute_batch(SCHEMA_SQL).map_err(sql_err)?;
        ensure_mailbox_seeded(&mut conn, &self.mailbox_id)?;
        if let Ok(mut seeded) = self.seeded_mailboxes.lock() {
            seeded.insert(self.mailbox_id.clone());
        }
        Ok(())
    }

    async fn run_blocking<F, T>(&self, f: F) -> AppResult<T>
    where
        F: FnOnce(&mut Connection, &str) -> AppResult<T> + Send + 'static,
        T: Send + 'static,
    {
        let pool = self.pool.clone();
        let mailbox_id = self.mailbox_id.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = pool
                .get()
                .map_err(|e| AppError::Storage(format!("SQLite pool error: {e}")))?;
            f(&mut conn, &mailbox_id)
        })
        .await
        .map_err(|e| AppError::Storage(format!("SQLite blocking task failed: {e}")))?
    }
}

fn table_exists(conn: &Connection, table: &str) -> AppResult<bool> {
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![table],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql_err)?;
    Ok(exists.is_some())
}

fn column_exists_conn(conn: &Connection, table: &str, column: &str) -> AppResult<bool> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(sql_err)?;
    let exists = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(sql_err)?
        .filter_map(Result::ok)
        .any(|name| name == column);
    Ok(exists)
}

const MULTI_MAILBOX_TABLES: &[&str] = &[
    "meta",
    "labels",
    "imap_meta",
    "imap_expunged_uids",
    "messages",
    "message_labels",
    "attachments",
    "drafts",
    "history_events",
    "sync_state",
    "watch_state",
    "settings",
    "pending_approvals",
];

fn needs_v1_multi_mailbox_migration(conn: &Connection) -> AppResult<bool> {
    for &tbl in MULTI_MAILBOX_TABLES {
        if table_exists(conn, tbl)? && !column_exists_conn(conn, tbl, "mailbox_id")? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn migrate_v1_to_multi_mailbox(conn: &mut Connection, default_mailbox: &str) -> AppResult<()> {
    conn.execute_batch("PRAGMA foreign_keys = OFF;")
        .map_err(sql_err)?;

    let result = (|| -> AppResult<()> {
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_err)?;

        // Backfill optional legacy columns on v1 tables before renaming/copying.
        if table_exists(&tx, "history_events")?
            && !column_exists_conn(&tx, "history_events", "mailbox_id")?
        {
            ensure_column_exists(
                &tx,
                "history_events",
                "context_labels_json",
                "TEXT NOT NULL DEFAULT '[]'",
            )?;
            ensure_column_exists(&tx, "history_events", "upstream_gmail_id", "TEXT")?;
        }
        if table_exists(&tx, "sync_state")? && !column_exists_conn(&tx, "sync_state", "mailbox_id")?
        {
            ensure_column_exists(&tx, "sync_state", "last_pushed_history_id", "INTEGER")?;
            ensure_column_exists(
                &tx,
                "sync_state",
                "messages_pushed",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
        }

        let mut renamed = Vec::new();
        for &tbl in MULTI_MAILBOX_TABLES {
            if table_exists(&tx, tbl)? && !column_exists_conn(&tx, tbl, "mailbox_id")? {
                tx.execute(&format!("ALTER TABLE {tbl} RENAME TO {tbl}__v1_legacy"), [])
                    .map_err(sql_err)?;
                renamed.push(tbl);
            }
        }
        tx.execute("DROP TABLE IF EXISTS messages_fts", [])
            .map_err(sql_err)?;

        tx.execute_batch(SCHEMA_SQL).map_err(sql_err)?;

        if renamed.contains(&"meta") {
            tx.execute(
                "INSERT INTO meta (mailbox_id, key, int_val, text_val)
                 SELECT ?1, key, int_val, text_val FROM meta__v1_legacy",
                params![default_mailbox],
            )
            .map_err(sql_err)?;
        }
        if renamed.contains(&"labels") {
            tx.execute(
                "INSERT INTO labels (
                    mailbox_id, id, name, label_type, message_list_visibility, label_list_visibility,
                    color_text, color_background, uid_validity, uid_next, upstream_label_id
                 )
                 SELECT ?1, id, name, label_type, message_list_visibility, label_list_visibility,
                        color_text, color_background, uid_validity, uid_next, upstream_label_id
                 FROM labels__v1_legacy",
                params![default_mailbox],
            )
            .map_err(sql_err)?;
        }
        if renamed.contains(&"imap_meta") {
            tx.execute(
                "INSERT INTO imap_meta (mailbox_id, mailbox_name, uid_validity, uid_next)
                 SELECT ?1, mailbox_name, uid_validity, uid_next FROM imap_meta__v1_legacy",
                params![default_mailbox],
            )
            .map_err(sql_err)?;
        }
        if renamed.contains(&"imap_expunged_uids") {
            tx.execute(
                "INSERT INTO imap_expunged_uids (mailbox_id, mailbox_key, imap_uid, modseq)
                 SELECT ?1, mailbox_key, imap_uid, modseq FROM imap_expunged_uids__v1_legacy",
                params![default_mailbox],
            )
            .map_err(sql_err)?;
        }
        if renamed.contains(&"messages") {
            tx.execute(
                "INSERT INTO messages (
                    mailbox_id, id, thread_id, raw_rfc2822, snippet, history_id, internal_date_ms,
                    size_estimate, subject, from_addr, to_addrs_json, cc_addrs_json, bcc_addrs_json,
                    text_body, html_body, has_attachments, rfc822_message_id, rfc822_message_id_norm,
                    in_reply_to, references_header, resend_id, delivery_status, upstream_gmail_id,
                    upstream_thread_id, source, all_mail_uid, is_answered, is_deleted
                 )
                 SELECT ?1, id, thread_id, raw_rfc2822, snippet, history_id, internal_date_ms,
                        size_estimate, subject, from_addr, to_addrs_json, cc_addrs_json, bcc_addrs_json,
                        text_body, html_body, has_attachments, rfc822_message_id, rfc822_message_id_norm,
                        in_reply_to, references_header, resend_id, delivery_status, upstream_gmail_id,
                        upstream_thread_id, source, all_mail_uid, is_answered, is_deleted
                 FROM messages__v1_legacy",
                params![default_mailbox],
            )
            .map_err(sql_err)?;

            // Rebuild FTS5 index with mailbox_id.
            let mut stmt = tx
                .prepare(
                    "SELECT id, subject, from_addr, to_addrs_json, cc_addrs_json, text_body, snippet
                     FROM messages WHERE mailbox_id = ?1",
                )
                .map_err(sql_err)?;
            let rows: Vec<(String, String, String, String, String, String, String)> = stmt
                .query_map(params![default_mailbox], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                })
                .map_err(sql_err)?
                .collect::<Result<_, _>>()
                .map_err(sql_err)?;
            drop(stmt);

            for (mid, subject, from_addr, to_json, cc_json, text_body, snippet) in rows {
                let to_joined = serde_json::from_str::<Vec<String>>(&to_json)
                    .unwrap_or_default()
                    .join(" ");
                let cc_joined = serde_json::from_str::<Vec<String>>(&cc_json)
                    .unwrap_or_default()
                    .join(" ");
                tx.execute(
                    "INSERT INTO messages_fts (mailbox_id, message_id, subject, from_addr, to_addrs, cc_addrs, text_body, snippet)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        default_mailbox,
                        mid,
                        subject,
                        from_addr,
                        to_joined,
                        cc_joined,
                        text_body,
                        snippet,
                    ],
                )
                .map_err(sql_err)?;
            }
        }
        if renamed.contains(&"message_labels") {
            tx.execute(
                "INSERT INTO message_labels (mailbox_id, message_id, label_id, imap_uid)
                 SELECT ?1, message_id, label_id, imap_uid FROM message_labels__v1_legacy",
                params![default_mailbox],
            )
            .map_err(sql_err)?;
        }
        if renamed.contains(&"attachments") {
            tx.execute(
                "INSERT INTO attachments (
                    mailbox_id, id, message_id, part_id, filename, content_type, content_id, size_bytes, data
                 )
                 SELECT ?1, id, message_id, part_id, filename, content_type, content_id, size_bytes, data
                 FROM attachments__v1_legacy",
                params![default_mailbox],
            )
            .map_err(sql_err)?;
        }
        if renamed.contains(&"drafts") {
            tx.execute(
                "INSERT INTO drafts (mailbox_id, id, message_id, updated_at_ms)
                 SELECT ?1, id, message_id, updated_at_ms FROM drafts__v1_legacy",
                params![default_mailbox],
            )
            .map_err(sql_err)?;
        }
        if renamed.contains(&"history_events") {
            tx.execute(
                "INSERT INTO history_events (
                    id, mailbox_id, history_id, kind, message_id, thread_id,
                    label_ids_json, context_labels_json, upstream_gmail_id
                 )
                 SELECT id, ?1, history_id, kind, message_id, thread_id,
                        label_ids_json, context_labels_json, upstream_gmail_id
                 FROM history_events__v1_legacy",
                params![default_mailbox],
            )
            .map_err(sql_err)?;
        }
        if renamed.contains(&"sync_state") {
            tx.execute(
                "INSERT INTO sync_state (
                    mailbox_id, account_key, provider, last_history_id, imap_mailbox, imap_uid_validity,
                    imap_last_uid, last_sync_at_ms, last_full_sync_at_ms, status, last_error,
                    messages_synced, last_pushed_history_id, messages_pushed
                 )
                 SELECT ?1, account_key, provider, last_history_id, imap_mailbox, imap_uid_validity,
                        imap_last_uid, last_sync_at_ms, last_full_sync_at_ms, status, last_error,
                        messages_synced, last_pushed_history_id, messages_pushed
                 FROM sync_state__v1_legacy",
                params![default_mailbox],
            )
            .map_err(sql_err)?;
        }
        if renamed.contains(&"watch_state") {
            tx.execute(
                "INSERT INTO watch_state (
                    mailbox_id, topic_name, label_ids_json, label_filter_behavior, history_id, expiration_ms
                 )
                 SELECT ?1, topic_name, label_ids_json, label_filter_behavior, history_id, expiration_ms
                 FROM watch_state__v1_legacy",
                params![default_mailbox],
            )
            .map_err(sql_err)?;
        }
        if renamed.contains(&"settings") {
            tx.execute(
                "INSERT INTO settings (mailbox_id, key, value_json)
                 SELECT ?1, key, value_json FROM settings__v1_legacy",
                params![default_mailbox],
            )
            .map_err(sql_err)?;
        }
        if renamed.contains(&"pending_approvals") {
            tx.execute(
                "INSERT INTO pending_approvals (
                    mailbox_id, id, status, reason, requester_json, outbound_message_json,
                    reply_to_message_id, thread_id, draft_id, sent_message_id, provider_message_id,
                    decided_by, decision_note, created_at_ms, expires_at_ms, decided_at_ms
                 )
                 SELECT ?1, id, status, reason, requester_json, outbound_message_json,
                        reply_to_message_id, thread_id, draft_id, sent_message_id, provider_message_id,
                        decided_by, decision_note, created_at_ms, expires_at_ms, decided_at_ms
                 FROM pending_approvals__v1_legacy",
                params![default_mailbox],
            )
            .map_err(sql_err)?;
        }

        for tbl in renamed {
            tx.execute(&format!("DROP TABLE IF EXISTS {tbl}__v1_legacy"), [])
                .map_err(sql_err)?;
        }

        tx.commit().map_err(sql_err)?;
        Ok(())
    })();

    let _ = conn.execute_batch("PRAGMA foreign_keys = ON;");
    result
}

fn ensure_mailbox_seeded(conn: &mut Connection, mailbox_id: &str) -> AppResult<()> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sql_err)?;

    tx.execute(
        "INSERT OR IGNORE INTO meta (mailbox_id, key, int_val) VALUES (?1, 'history_id', 1)",
        params![mailbox_id],
    )
    .map_err(sql_err)?;
    tx.execute(
        "INSERT OR IGNORE INTO meta (mailbox_id, key, int_val) VALUES (?1, 'next_uid_validity', 1)",
        params![mailbox_id],
    )
    .map_err(sql_err)?;

    // Seed [Gmail]/All Mail IMAP metadata
    let all_mail_exists: Option<i64> = tx
        .query_row(
            "SELECT uid_validity FROM imap_meta WHERE mailbox_id = ?1 AND mailbox_name = ?2",
            params![mailbox_id, ALL_MAIL_MAILBOX],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql_err)?;
    if all_mail_exists.is_none() {
        let uv = alloc_uid_validity(&tx, mailbox_id)?;
        tx.execute(
            "INSERT INTO imap_meta (mailbox_id, mailbox_name, uid_validity, uid_next) VALUES (?1, ?2, ?3, 1)",
            params![mailbox_id, ALL_MAIL_MAILBOX, uv as i64],
        )
        .map_err(sql_err)?;
    }

    // Seed system labels
    for &label_id in SYSTEM_LABEL_IDS {
        let exists: Option<String> = tx
            .query_row(
                "SELECT id FROM labels WHERE mailbox_id = ?1 AND id = ?2",
                params![mailbox_id, label_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_err)?;
        if exists.is_none() {
            let uv = alloc_uid_validity(&tx, mailbox_id)?;
            let (msg_vis, lbl_vis) = if label_id == LABEL_TRASH || label_id == LABEL_SPAM {
                ("hide", "labelHide")
            } else {
                ("show", "labelShow")
            };
            tx.execute(
                "INSERT INTO labels
                 (mailbox_id, id, name, label_type, message_list_visibility, label_list_visibility, uid_validity, uid_next)
                 VALUES (?1, ?2, ?3, 'system', ?4, ?5, ?6, 1)",
                params![mailbox_id, label_id, label_id, msg_vis, lbl_vis, uv as i64],
            )
            .map_err(sql_err)?;
        }
    }

    // Seed default user settings (primary sendAs, vacation, autoForwarding, imap, pop)
    let defaults = UserSettings::default_for_email(mailbox_id);
    seed_setting_if_missing(&tx, mailbox_id, "send_as", &defaults.send_as)?;
    seed_setting_if_missing(&tx, mailbox_id, "vacation", &defaults.vacation)?;
    seed_setting_if_missing(
        &tx,
        mailbox_id,
        "auto_forwarding",
        &defaults.auto_forwarding,
    )?;
    seed_setting_if_missing(&tx, mailbox_id, "imap", &defaults.imap)?;
    seed_setting_if_missing(&tx, mailbox_id, "pop", &defaults.pop)?;

    tx.commit().map_err(sql_err)?;
    Ok(())
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
    mailbox_id: &str,
    key: &str,
    value: &T,
) -> AppResult<()> {
    let json = serde_json::to_string(value)
        .map_err(|e| AppError::Storage(format!("Failed to serialize setting {key}: {e}")))?;
    tx.execute(
        "INSERT OR IGNORE INTO settings (mailbox_id, key, value_json) VALUES (?1, ?2, ?3)",
        params![mailbox_id, key, json],
    )
    .map_err(sql_err)?;
    Ok(())
}

fn alloc_uid_validity(tx: &Transaction<'_>, mailbox_id: &str) -> AppResult<u32> {
    let current: i64 = tx
        .query_row(
            "SELECT int_val FROM meta WHERE mailbox_id = ?1 AND key = 'next_uid_validity'",
            params![mailbox_id],
            |row| row.get(0),
        )
        .map_err(sql_err)?;
    tx.execute(
        "UPDATE meta SET int_val = ?1 WHERE mailbox_id = ?2 AND key = 'next_uid_validity'",
        params![current + 1, mailbox_id],
    )
    .map_err(sql_err)?;
    Ok(current.max(1) as u32)
}

fn bump_history_id(tx: &Transaction<'_>, mailbox_id: &str) -> AppResult<u64> {
    tx.execute(
        "UPDATE meta SET int_val = int_val + 1 WHERE mailbox_id = ?1 AND key = 'history_id'",
        params![mailbox_id],
    )
    .map_err(sql_err)?;
    let hid: i64 = tx
        .query_row(
            "SELECT int_val FROM meta WHERE mailbox_id = ?1 AND key = 'history_id'",
            params![mailbox_id],
            |row| row.get(0),
        )
        .map_err(sql_err)?;
    Ok(hid.max(1) as u64)
}

fn read_current_history_id(conn: &Connection, mailbox_id: &str) -> AppResult<u64> {
    let hid: i64 = conn
        .query_row(
            "SELECT int_val FROM meta WHERE mailbox_id = ?1 AND key = 'history_id'",
            params![mailbox_id],
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

fn ensure_column_exists(
    tx: &Transaction<'_>,
    table: &str,
    column: &str,
    definition: &str,
) -> AppResult<()> {
    let mut stmt = tx
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(sql_err)?;
    let exists = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(sql_err)?
        .filter_map(Result::ok)
        .any(|name| name == column);
    drop(stmt);
    if !exists {
        tx.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
            [],
        )
        .map_err(sql_err)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn record_history_event(
    tx: &Transaction<'_>,
    mailbox_id: &str,
    history_id: u64,
    kind: HistoryEventKind,
    message_id: &str,
    thread_id: &str,
    label_ids: &[String],
    context_labels: &[String],
    upstream_gmail_id: Option<&str>,
) -> AppResult<()> {
    let labels_json = serde_json::to_string(label_ids)
        .map_err(|e| AppError::Storage(format!("JSON encode error: {e}")))?;
    let ctx_json = serde_json::to_string(context_labels)
        .map_err(|e| AppError::Storage(format!("JSON encode error: {e}")))?;
    tx.execute(
        "INSERT INTO history_events (mailbox_id, history_id, kind, message_id, thread_id, label_ids_json, context_labels_json, upstream_gmail_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            mailbox_id,
            history_id as i64,
            history_kind_to_str(kind),
            message_id,
            thread_id,
            labels_json,
            ctx_json,
            upstream_gmail_id,
        ],
    )
    .map_err(sql_err)?;
    Ok(())
}

fn alloc_all_mail_uid(tx: &Transaction<'_>, mailbox_id: &str) -> AppResult<u32> {
    let uid: i64 = tx
        .query_row(
            "SELECT uid_next FROM imap_meta WHERE mailbox_id = ?1 AND mailbox_name = ?2",
            params![mailbox_id, ALL_MAIL_MAILBOX],
            |row| row.get(0),
        )
        .map_err(sql_err)?;
    tx.execute(
        "UPDATE imap_meta SET uid_next = ?1 WHERE mailbox_id = ?2 AND mailbox_name = ?3",
        params![uid + 1, mailbox_id, ALL_MAIL_MAILBOX],
    )
    .map_err(sql_err)?;
    Ok(uid.max(1) as u32)
}

fn alloc_label_uid(tx: &Transaction<'_>, mailbox_id: &str, label_id: &str) -> AppResult<u32> {
    let uid: i64 = tx
        .query_row(
            "SELECT uid_next FROM labels WHERE mailbox_id = ?1 AND id = ?2",
            params![mailbox_id, label_id],
            |row| row.get(0),
        )
        .map_err(sql_err)?;
    tx.execute(
        "UPDATE labels SET uid_next = ?1 WHERE mailbox_id = ?2 AND id = ?3",
        params![uid + 1, mailbox_id, label_id],
    )
    .map_err(sql_err)?;
    Ok(uid.max(1) as u32)
}

fn ensure_label_exists_tx(
    tx: &Transaction<'_>,
    mailbox_id: &str,
    raw_label: &str,
) -> AppResult<String> {
    let trimmed = raw_label.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest("Label ID cannot be empty".into()));
    }
    if let Some(id) = tx
        .query_row(
            "SELECT id FROM labels WHERE mailbox_id = ?1 AND id = ?2",
            params![mailbox_id, trimmed],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sql_err)?
    {
        return Ok(id);
    }
    if let Some(id) = tx
        .query_row(
            "SELECT id FROM labels WHERE mailbox_id = ?1 AND name = ?2 COLLATE NOCASE",
            params![mailbox_id, trimmed],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sql_err)?
    {
        return Ok(id);
    }
    if let Some(id) = tx
        .query_row(
            "SELECT id FROM labels WHERE mailbox_id = ?1 AND upstream_label_id = ?2",
            params![mailbox_id, trimmed],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sql_err)?
    {
        return Ok(id);
    }

    let uv = alloc_uid_validity(tx, mailbox_id)?;
    tx.execute(
        "INSERT INTO labels (mailbox_id, id, name, label_type, message_list_visibility, label_list_visibility, uid_validity, uid_next)
         VALUES (?1, ?2, ?3, 'user', 'show', 'labelShow', ?4, 1)",
        params![mailbox_id, trimmed, trimmed, uv as i64],
    )
    .map_err(sql_err)?;
    Ok(trimmed.to_string())
}

fn resolve_existing_label_id(
    conn: &Connection,
    mailbox_id: &str,
    raw_label: &str,
) -> AppResult<Option<String>> {
    let trimmed = raw_label.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if let Some(id) = conn
        .query_row(
            "SELECT id FROM labels WHERE mailbox_id = ?1 AND id = ?2",
            params![mailbox_id, trimmed],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sql_err)?
    {
        return Ok(Some(id));
    }
    conn.query_row(
        "SELECT id FROM labels WHERE mailbox_id = ?1 AND name = ?2 COLLATE NOCASE",
        params![mailbox_id, trimmed],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(sql_err)
}

fn load_message_labels(
    conn: &Connection,
    mailbox_id: &str,
    message_id: &str,
) -> AppResult<Vec<String>> {
    let mut stmt = conn
        .prepare(
            "SELECT label_id FROM message_labels WHERE mailbox_id = ?1 AND message_id = ?2 ORDER BY label_id ASC",
        )
        .map_err(sql_err)?;
    let rows = stmt
        .query_map(params![mailbox_id, message_id], |row| {
            row.get::<_, String>(0)
        })
        .map_err(sql_err)?;
    let mut labels = Vec::new();
    for r in rows {
        labels.push(r.map_err(sql_err)?);
    }
    Ok(labels)
}

fn load_labels_for_messages(
    conn: &Connection,
    mailbox_id: &str,
    message_ids: &[String],
) -> AppResult<HashMap<String, Vec<String>>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    if message_ids.is_empty() {
        return Ok(map);
    }
    // Batch in chunks of 500 to stay well below SQLite's bind parameter limit.
    for chunk in message_ids.chunks(500) {
        let placeholders = (0..chunk.len())
            .map(|i| format!("?{}", i + 2))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT message_id, label_id FROM message_labels WHERE mailbox_id = ?1 AND message_id IN ({placeholders}) ORDER BY label_id ASC"
        );
        let mut stmt = conn.prepare(&sql).map_err(sql_err)?;
        let mut params_vec: Vec<SqlValue> = Vec::with_capacity(chunk.len() + 1);
        params_vec.push(SqlValue::Text(mailbox_id.to_string()));
        params_vec.extend(chunk.iter().map(|id| SqlValue::Text(id.clone())));
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

fn load_message_by_id(
    conn: &Connection,
    mailbox_id: &str,
    id: &str,
) -> AppResult<Option<StoredMessage>> {
    let mut msg = match conn
        .query_row(
            "SELECT * FROM messages WHERE mailbox_id = ?1 AND id = ?2",
            params![mailbox_id, id],
            message_from_row,
        )
        .optional()
        .map_err(sql_err)?
    {
        Some(m) => m,
        None => return Ok(None),
    };
    msg.label_ids = load_message_labels(conn, mailbox_id, &msg.id)?;
    Ok(Some(msg))
}

fn resolve_thread_id_tx(
    tx: &Transaction<'_>,
    mailbox_id: &str,
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
                "SELECT thread_id FROM messages WHERE mailbox_id = ?1 AND upstream_thread_id = ?2 LIMIT 1",
                params![mailbox_id, utid.trim()],
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
                "SELECT thread_id FROM messages WHERE mailbox_id = ?1 AND rfc822_message_id_norm = ?2 LIMIT 1",
                params![mailbox_id, norm],
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
                        "SELECT thread_id FROM messages WHERE mailbox_id = ?1 AND rfc822_message_id_norm = ?2 LIMIT 1",
                        params![mailbox_id, norm],
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

fn insert_message_tx(
    tx: &Transaction<'_>,
    mailbox_id: &str,
    input: NewMessageInput,
) -> AppResult<StoredMessage> {
    let msg_id = input
        .id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(new_hex_id);
    let thread_id = resolve_thread_id_tx(tx, mailbox_id, &input, &msg_id)?;

    // Resolve / ensure labels (deduplicated & sorted)
    let mut label_set = HashSet::new();
    let mut resolved_labels = Vec::new();
    for raw_label in &input.label_ids {
        let lid = ensure_label_exists_tx(tx, mailbox_id, raw_label)?;
        if label_set.insert(lid.clone()) {
            resolved_labels.push(lid);
        }
    }
    resolved_labels.sort();

    let history_id = bump_history_id(tx, mailbox_id)?;
    let all_mail_uid = alloc_all_mail_uid(tx, mailbox_id)?;
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
            mailbox_id, id, thread_id, raw_rfc2822, snippet, history_id, internal_date_ms, size_estimate,
            subject, from_addr, to_addrs_json, cc_addrs_json, bcc_addrs_json,
            text_body, html_body, has_attachments,
            rfc822_message_id, rfc822_message_id_norm, in_reply_to, references_header,
            resend_id, delivery_status, upstream_gmail_id, upstream_thread_id,
            source, all_mail_uid, is_answered, is_deleted
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
            ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16,
            ?17, ?18, ?19, ?20,
            ?21, NULL, ?22, ?23,
            ?24, ?25, ?26, ?27
        )",
        params![
            mailbox_id,
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
        let imap_uid = alloc_label_uid(tx, mailbox_id, lid)?;
        tx.execute(
            "INSERT INTO message_labels (mailbox_id, message_id, label_id, imap_uid) VALUES (?1, ?2, ?3, ?4)",
            params![mailbox_id, &msg_id, lid, imap_uid as i64],
        )
        .map_err(sql_err)?;
    }

    for att in &input.attachments {
        let att_id = format!("att_{}", new_hex_id());
        tx.execute(
            "INSERT INTO attachments (mailbox_id, id, message_id, part_id, filename, content_type, content_id, size_bytes, data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                mailbox_id,
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
        "INSERT INTO messages_fts (mailbox_id, message_id, subject, from_addr, to_addrs, cc_addrs, text_body, snippet)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            mailbox_id,
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
        mailbox_id,
        history_id,
        HistoryEventKind::MessageAdded,
        &msg_id,
        &thread_id,
        &resolved_labels,
        &resolved_labels,
        input.upstream_gmail_id.as_deref(),
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

fn record_expunged_uid_tx(
    tx: &Transaction<'_>,
    mailbox_id: &str,
    mailbox_key: &str,
    imap_uid: u32,
    modseq: u64,
) -> AppResult<()> {
    tx.execute(
        "INSERT OR REPLACE INTO imap_expunged_uids (mailbox_id, mailbox_key, imap_uid, modseq) VALUES (?1, ?2, ?3, ?4)",
        params![mailbox_id, mailbox_key, imap_uid as i64, modseq as i64],
    )
    .map_err(sql_err)?;
    Ok(())
}

fn clear_expunged_uid_tx(
    tx: &Transaction<'_>,
    mailbox_id: &str,
    mailbox_key: &str,
    imap_uid: u32,
) -> AppResult<()> {
    tx.execute(
        "DELETE FROM imap_expunged_uids WHERE mailbox_id = ?1 AND mailbox_key = ?2 AND imap_uid = ?3",
        params![mailbox_id, mailbox_key, imap_uid as i64],
    )
    .map_err(sql_err)?;
    Ok(())
}

fn modify_message_labels_resolved_tx(
    tx: &Transaction<'_>,
    mailbox_id: &str,
    message_id: &str,
    resolved_add: &[String],
    resolved_remove: &[String],
) -> AppResult<StoredMessage> {
    let mut msg = load_message_by_id(tx, mailbox_id, message_id)?
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
        let new_hid = bump_history_id(tx, mailbox_id)?;
        tx.execute(
            "UPDATE messages SET history_id = ?1 WHERE mailbox_id = ?2 AND id = ?3",
            params![new_hid as i64, mailbox_id, message_id],
        )
        .map_err(sql_err)?;

        for lid in &actually_added {
            let imap_uid = alloc_label_uid(tx, mailbox_id, lid)?;
            tx.execute(
                "INSERT OR IGNORE INTO message_labels (mailbox_id, message_id, label_id, imap_uid) VALUES (?1, ?2, ?3, ?4)",
                params![mailbox_id, message_id, lid, imap_uid as i64],
            )
            .map_err(sql_err)?;
            clear_expunged_uid_tx(tx, mailbox_id, lid, imap_uid)?;
        }

        for lid in &actually_removed {
            let removed_uid: Option<i64> = tx
                .query_row(
                    "SELECT imap_uid FROM message_labels WHERE mailbox_id = ?1 AND message_id = ?2 AND label_id = ?3",
                    params![mailbox_id, message_id, lid],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?;
            tx.execute(
                "DELETE FROM message_labels WHERE mailbox_id = ?1 AND message_id = ?2 AND label_id = ?3",
                params![mailbox_id, message_id, lid],
            )
            .map_err(sql_err)?;
            if let Some(uid) = removed_uid {
                record_expunged_uid_tx(tx, mailbox_id, lid, uid.max(1) as u32, new_hid)?;
            }
        }

        let was_in_all_mail =
            !current_set.contains(LABEL_TRASH) && !current_set.contains(LABEL_SPAM);
        let mut new_set = current_set.clone();
        for lid in &actually_added {
            new_set.insert(lid.clone());
        }
        for lid in &actually_removed {
            new_set.remove(lid);
        }
        let is_in_all_mail = !new_set.contains(LABEL_TRASH) && !new_set.contains(LABEL_SPAM);
        if was_in_all_mail && !is_in_all_mail {
            record_expunged_uid_tx(tx, mailbox_id, ALL_MAIL_MAILBOX, msg.all_mail_uid, new_hid)?;
        } else if !was_in_all_mail && is_in_all_mail {
            clear_expunged_uid_tx(tx, mailbox_id, ALL_MAIL_MAILBOX, msg.all_mail_uid)?;
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
                mailbox_id,
                new_hid,
                HistoryEventKind::LabelAdded,
                message_id,
                &msg.thread_id,
                &actually_added,
                &context_labels,
                msg.upstream_gmail_id.as_deref(),
            )?;
        }
        if !actually_removed.is_empty() {
            record_history_event(
                tx,
                mailbox_id,
                new_hid,
                HistoryEventKind::LabelRemoved,
                message_id,
                &msg.thread_id,
                &actually_removed,
                &context_labels,
                msg.upstream_gmail_id.as_deref(),
            )?;
        }

        msg.history_id = new_hid;
        msg.label_ids = load_message_labels(tx, mailbox_id, message_id)?;
    }

    Ok(msg)
}

fn delete_message_tx(
    tx: &Transaction<'_>,
    mailbox_id: &str,
    id: &str,
) -> AppResult<Option<StoredMessage>> {
    let Some(msg) = load_message_by_id(tx, mailbox_id, id)? else {
        return Ok(None);
    };
    let label_uids: Vec<(String, u32)> = {
        let mut stmt = tx
            .prepare(
                "SELECT label_id, imap_uid FROM message_labels WHERE mailbox_id = ?1 AND message_id = ?2",
            )
            .map_err(sql_err)?;
        let rows = stmt
            .query_map(params![mailbox_id, id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?.max(1) as u32,
                ))
            })
            .map_err(sql_err)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(sql_err)?);
        }
        out
    };
    let hid = bump_history_id(tx, mailbox_id)?;
    for (lid, uid) in label_uids {
        record_expunged_uid_tx(tx, mailbox_id, &lid, uid, hid)?;
    }
    if !msg
        .label_ids
        .iter()
        .any(|l| l == LABEL_TRASH || l == LABEL_SPAM)
    {
        record_expunged_uid_tx(tx, mailbox_id, ALL_MAIL_MAILBOX, msg.all_mail_uid, hid)?;
    }
    tx.execute(
        "DELETE FROM messages_fts WHERE mailbox_id = ?1 AND message_id = ?2",
        params![mailbox_id, id],
    )
    .map_err(sql_err)?;
    tx.execute(
        "DELETE FROM messages WHERE mailbox_id = ?1 AND id = ?2",
        params![mailbox_id, id],
    )
    .map_err(sql_err)?;
    record_history_event(
        tx,
        mailbox_id,
        hid,
        HistoryEventKind::MessageDeleted,
        &msg.id,
        &msg.thread_id,
        &msg.label_ids,
        &msg.label_ids,
        msg.upstream_gmail_id.as_deref(),
    )?;
    Ok(Some(msg))
}

fn load_label_with_counts(
    conn: &Connection,
    mailbox_id: &str,
    id: &str,
) -> AppResult<Option<StoredLabel>> {
    let row = conn
        .query_row(
            "SELECT
                l.id, l.name, l.label_type, l.message_list_visibility, l.label_list_visibility,
                l.color_text, l.color_background, l.uid_validity, l.uid_next, l.upstream_label_id,
                (SELECT COUNT(*) FROM message_labels ml
                 WHERE ml.mailbox_id = l.mailbox_id AND ml.label_id = l.id) AS messages_total,
                (SELECT COUNT(*) FROM message_labels ml
                 INNER JOIN message_labels mu
                    ON mu.mailbox_id = ml.mailbox_id AND mu.message_id = ml.message_id AND mu.label_id = ?3
                 WHERE ml.mailbox_id = l.mailbox_id AND ml.label_id = l.id) AS messages_unread,
                (SELECT COUNT(DISTINCT m.thread_id) FROM message_labels ml
                 INNER JOIN messages m
                    ON m.mailbox_id = ml.mailbox_id AND m.id = ml.message_id
                 WHERE ml.mailbox_id = l.mailbox_id AND ml.label_id = l.id) AS threads_total,
                (SELECT COUNT(DISTINCT m.thread_id) FROM message_labels ml
                 INNER JOIN messages m
                    ON m.mailbox_id = ml.mailbox_id AND m.id = ml.message_id
                 INNER JOIN message_labels mu
                    ON mu.mailbox_id = ml.mailbox_id AND mu.message_id = ml.message_id AND mu.label_id = ?3
                 WHERE ml.mailbox_id = l.mailbox_id AND ml.label_id = l.id) AS threads_unread
             FROM labels l
             WHERE l.mailbox_id = ?1 AND l.id = ?2",
            params![mailbox_id, id, LABEL_UNREAD],
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
    mailbox_id: &str,
    thread_id: &str,
) -> AppResult<Option<StoredThreadDetail>> {
    let mut stmt = conn
        .prepare(
            "SELECT * FROM messages WHERE mailbox_id = ?1 AND thread_id = ?2 ORDER BY internal_date_ms ASC, id ASC",
        )
        .map_err(sql_err)?;
    let rows = stmt
        .query_map(params![mailbox_id, thread_id], message_from_row)
        .map_err(sql_err)?;
    let mut messages = Vec::new();
    for r in rows {
        messages.push(r.map_err(sql_err)?);
    }
    if messages.is_empty() {
        return Ok(None);
    }
    let ids: Vec<String> = messages.iter().map(|m| m.id.clone()).collect();
    let mut label_map = load_labels_for_messages(conn, mailbox_id, &ids)?;
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
    mailbox_id: &str,
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
            "SELECT id, name FROM labels WHERE mailbox_id = ?1 AND label_type = 'user' AND name = ?2",
            params![mailbox_id, mailbox_name],
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
    mailbox_id: &str,
    resolved: &ResolvedMailbox,
) -> AppResult<ImapMailboxInfo> {
    match resolved {
        ResolvedMailbox::AllMail => {
            let (uv, un): (i64, i64) = conn
                .query_row(
                    "SELECT uid_validity, uid_next FROM imap_meta WHERE mailbox_id = ?1 AND mailbox_name = ?2",
                    params![mailbox_id, ALL_MAIL_MAILBOX],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(sql_err)?;
            let messages: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM messages m
                     WHERE m.mailbox_id = ?1
                       AND NOT EXISTS (
                           SELECT 1 FROM message_labels ml
                           WHERE ml.mailbox_id = m.mailbox_id AND ml.message_id = m.id AND ml.label_id IN (?2, ?3)
                       )",
                    params![mailbox_id, LABEL_TRASH, LABEL_SPAM],
                    |row| row.get(0),
                )
                .map_err(sql_err)?;
            let unseen: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM messages m
                     WHERE m.mailbox_id = ?1
                       AND EXISTS (
                           SELECT 1 FROM message_labels mu
                           WHERE mu.mailbox_id = m.mailbox_id AND mu.message_id = m.id AND mu.label_id = ?4
                       )
                       AND NOT EXISTS (
                           SELECT 1 FROM message_labels ml
                           WHERE ml.mailbox_id = m.mailbox_id AND ml.message_id = m.id AND ml.label_id IN (?2, ?3)
                       )",
                    params![mailbox_id, LABEL_TRASH, LABEL_SPAM, LABEL_UNREAD],
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
                    "SELECT uid_validity, uid_next FROM labels WHERE mailbox_id = ?1 AND id = ?2",
                    params![mailbox_id, id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(sql_err)?;
            let messages: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM message_labels WHERE mailbox_id = ?1 AND label_id = ?2",
                    params![mailbox_id, id],
                    |row| row.get(0),
                )
                .map_err(sql_err)?;
            let unseen: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM message_labels ml
                     INNER JOIN message_labels mu
                        ON mu.mailbox_id = ml.mailbox_id AND mu.message_id = ml.message_id AND mu.label_id = ?3
                     WHERE ml.mailbox_id = ?1 AND ml.label_id = ?2",
                    params![mailbox_id, id, LABEL_UNREAD],
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

struct RawImapEntry {
    uid: u32,
    message_id: String,
    thread_id: String,
    history_id: u64,
    internal_date_ms: i64,
    size_estimate: i32,
    is_answered: bool,
    is_deleted: bool,
}

fn load_imap_messages_resolved(
    conn: &Connection,
    mailbox_id: &str,
    resolved: &ResolvedMailbox,
) -> AppResult<Vec<ImapMessageEntry>> {
    let raw_entries: Vec<RawImapEntry> = match resolved {
        ResolvedMailbox::AllMail => {
            let mut stmt = conn
                .prepare(
                    "SELECT m.all_mail_uid, m.id, m.thread_id, m.history_id, m.internal_date_ms, m.size_estimate, m.is_answered, m.is_deleted
                     FROM messages m
                     WHERE m.mailbox_id = ?1
                       AND NOT EXISTS (
                           SELECT 1 FROM message_labels ml
                           WHERE ml.mailbox_id = m.mailbox_id AND ml.message_id = m.id AND ml.label_id IN (?2, ?3)
                       )
                     ORDER BY m.all_mail_uid ASC",
                )
                .map_err(sql_err)?;
            let rows = stmt
                .query_map(params![mailbox_id, LABEL_TRASH, LABEL_SPAM], |row| {
                    Ok(RawImapEntry {
                        uid: row.get::<_, i64>(0)?.max(1) as u32,
                        message_id: row.get::<_, String>(1)?,
                        thread_id: row.get::<_, String>(2)?,
                        history_id: row.get::<_, i64>(3)?.max(1) as u64,
                        internal_date_ms: row.get::<_, i64>(4)?,
                        size_estimate: row.get::<_, i32>(5)?,
                        is_answered: row.get::<_, i64>(6)? != 0,
                        is_deleted: row.get::<_, i64>(7)? != 0,
                    })
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
                    "SELECT ml.imap_uid, m.id, m.thread_id, m.history_id, m.internal_date_ms, m.size_estimate, m.is_answered, m.is_deleted
                     FROM message_labels ml
                     INNER JOIN messages m ON m.mailbox_id = ml.mailbox_id AND m.id = ml.message_id
                     WHERE ml.mailbox_id = ?1 AND ml.label_id = ?2
                     ORDER BY ml.imap_uid ASC",
                )
                .map_err(sql_err)?;
            let rows = stmt
                .query_map(params![mailbox_id, id], |row| {
                    Ok(RawImapEntry {
                        uid: row.get::<_, i64>(0)?.max(1) as u32,
                        message_id: row.get::<_, String>(1)?,
                        thread_id: row.get::<_, String>(2)?,
                        history_id: row.get::<_, i64>(3)?.max(1) as u64,
                        internal_date_ms: row.get::<_, i64>(4)?,
                        size_estimate: row.get::<_, i32>(5)?,
                        is_answered: row.get::<_, i64>(6)? != 0,
                        is_deleted: row.get::<_, i64>(7)? != 0,
                    })
                })
                .map_err(sql_err)?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(sql_err)?);
            }
            out
        }
    };

    let ids: Vec<String> = raw_entries.iter().map(|e| e.message_id.clone()).collect();
    let mut label_map = load_labels_for_messages(conn, mailbox_id, &ids)?;

    let mut entries = Vec::with_capacity(raw_entries.len());
    for (idx, raw) in raw_entries.into_iter().enumerate() {
        let label_ids = label_map.remove(&raw.message_id).unwrap_or_default();
        entries.push(ImapMessageEntry {
            seq: (idx + 1) as u32,
            uid: raw.uid,
            message_id: raw.message_id,
            thread_id: raw.thread_id,
            history_id: raw.history_id,
            internal_date_ms: raw.internal_date_ms,
            size_estimate: raw.size_estimate,
            label_ids,
            is_answered: raw.is_answered,
            is_deleted: raw.is_deleted,
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

fn load_label_name_to_id_map(
    conn: &Connection,
    mailbox_id: &str,
) -> AppResult<HashMap<String, String>> {
    let mut stmt = conn
        .prepare("SELECT id, name FROM labels WHERE mailbox_id = ?1")
        .map_err(sql_err)?;
    let rows = stmt
        .query_map(params![mailbox_id], |row| {
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
    mailbox_id: &str,
    raw_q: &str,
) -> AppResult<crate::search::SearchQuery> {
    let mut parsed = crate::search::parse_query(raw_q);
    if !parsed.terms.is_empty() {
        let map = load_label_name_to_id_map(conn, mailbox_id)?;
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
    mailbox_id: &str,
    label_ids: &[String],
    include_spam_trash: bool,
    q: Option<&str>,
) -> AppResult<Vec<StoredMessage>> {
    let parsed_q = match q.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => Some(parse_query_with_labels(conn, mailbox_id, raw)?),
        None => None,
    };

    let explicit_spam_trash = label_ids
        .iter()
        .any(|l| l == LABEL_TRASH || l == LABEL_SPAM);
    let effective_include_spam_trash = include_spam_trash
        || explicit_spam_trash
        || parsed_q.as_ref().is_some_and(|pq| pq.include_spam_trash);

    let mut sql = String::from("SELECT m.* FROM messages m WHERE m.mailbox_id = ?1");
    let mut bind_values: Vec<SqlValue> = vec![SqlValue::Text(mailbox_id.to_string())];

    if !effective_include_spam_trash {
        bind_values.push(SqlValue::Text(LABEL_TRASH.to_string()));
        let p1 = bind_values.len();
        bind_values.push(SqlValue::Text(LABEL_SPAM.to_string()));
        let p2 = bind_values.len();
        sql.push_str(&format!(
            " AND NOT EXISTS (SELECT 1 FROM message_labels ml_ex WHERE ml_ex.mailbox_id = m.mailbox_id AND ml_ex.message_id = m.id AND ml_ex.label_id IN (?{p1}, ?{p2}))"
        ));
    }

    for lid in label_ids {
        let resolved =
            resolve_existing_label_id(conn, mailbox_id, lid)?.unwrap_or_else(|| lid.clone());
        bind_values.push(SqlValue::Text(resolved));
        let p = bind_values.len();
        sql.push_str(&format!(
            " AND EXISTS (SELECT 1 FROM message_labels ml_in WHERE ml_in.mailbox_id = m.mailbox_id AND ml_in.message_id = m.id AND ml_in.label_id = ?{p})"
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
    let mut label_map = load_labels_for_messages(conn, mailbox_id, &ids)?;
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
    mailbox_id: &str,
    key: &str,
) -> AppResult<Option<T>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value_json FROM settings WHERE mailbox_id = ?1 AND key = ?2",
            params![mailbox_id, key],
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

fn write_setting<T: serde::Serialize>(
    tx: &Transaction<'_>,
    mailbox_id: &str,
    key: &str,
    value: &T,
) -> AppResult<()> {
    let json = serde_json::to_string(value)
        .map_err(|e| AppError::Storage(format!("Failed to encode setting {key}: {e}")))?;
    tx.execute(
        "INSERT INTO settings (mailbox_id, key, value_json) VALUES (?1, ?2, ?3)
         ON CONFLICT(mailbox_id, key) DO UPDATE SET value_json = excluded.value_json",
        params![mailbox_id, key, json],
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

    fn mailbox_id(&self) -> &str {
        &self.mailbox_id
    }

    fn for_mailbox(&self, mailbox_id: &str) -> Arc<dyn MailStore> {
        let normalized = crate::config::normalize_mailbox_id(mailbox_id);
        let target = if normalized.is_empty() {
            self.mailbox_id.clone()
        } else {
            normalized
        };

        let already_seeded = self
            .seeded_mailboxes
            .lock()
            .map(|s| s.contains(&target))
            .unwrap_or(false);

        if !already_seeded {
            match self.pool.get() {
                Ok(mut conn) => {
                    if let Err(err) = ensure_mailbox_seeded(&mut conn, &target) {
                        tracing::warn!(
                            mailbox_id = %target,
                            error = %err,
                            "Failed to seed SQLite mailbox metadata"
                        );
                    } else if let Ok(mut seeded) = self.seeded_mailboxes.lock() {
                        seeded.insert(target.clone());
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        mailbox_id = %target,
                        error = %err,
                        "Failed to acquire SQLite pool connection to seed mailbox"
                    );
                }
            }
        }

        Arc::new(Self {
            pool: self.pool.clone(),
            mailbox_id: target,
            seeded_mailboxes: self.seeded_mailboxes.clone(),
        })
    }

    async fn get_profile(&self, email_address: &str) -> AppResult<Profile> {
        let email = if email_address.trim().is_empty() {
            self.mailbox_id.clone()
        } else {
            email_address.to_string()
        };
        self.run_blocking(move |conn, mb| {
            let messages_total: i32 = conn
                .query_row(
                    "SELECT COUNT(*) FROM messages WHERE mailbox_id = ?1",
                    params![mb],
                    |row| row.get(0),
                )
                .map_err(sql_err)?;
            let threads_total: i32 = conn
                .query_row(
                    "SELECT COUNT(DISTINCT thread_id) FROM messages WHERE mailbox_id = ?1",
                    params![mb],
                    |row| row.get(0),
                )
                .map_err(sql_err)?;
            let history_id = read_current_history_id(conn, mb)?;
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
        self.run_blocking(|conn, mb| read_current_history_id(conn, mb))
            .await
    }

    async fn list_history(&self, query: &HistoryListQuery) -> AppResult<HistoryListPage> {
        let query = query.clone();
        self.run_blocking(move |conn, mb| {
            if query.start_history_id == 0 {
                return Err(AppError::NotFound(
                    "Invalid startHistoryId: must be greater than 0".into(),
                ));
            }
            let current_hid = read_current_history_id(conn, mb)?;
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
                Some(l) if !l.trim().is_empty() => Some(
                    resolve_existing_label_id(conn, mb, l)?.unwrap_or_else(|| l.to_string()),
                ),
                _ => None,
            };

            let mut stmt = conn
                .prepare(
                    "SELECT id, history_id, kind, message_id, thread_id, label_ids_json, context_labels_json, upstream_gmail_id
                     FROM history_events
                     WHERE mailbox_id = ?1 AND history_id > ?2 AND id > ?3
                     ORDER BY id ASC",
                )
                .map_err(sql_err)?;

            let rows = stmt
                .query_map(
                    params![mb, query.start_history_id as i64, after_row_id],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, String>(6)?,
                            row.get::<_, Option<String>>(7)?,
                        ))
                    },
                )
                .map_err(sql_err)?;

            let mut matched: Vec<(i64, StoredHistoryEntry)> = Vec::new();
            for row in rows {
                let (
                    row_id,
                    hid,
                    kind_str,
                    message_id,
                    thread_id,
                    labels_json,
                    ctx_json,
                    upstream_gmail_id,
                ) = row.map_err(sql_err)?;
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
                        upstream_gmail_id,
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
        self.run_blocking(move |conn, mb| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let msg = insert_message_tx(&tx, mb, input)?;
            tx.commit().map_err(sql_err)?;
            Ok(msg)
        })
        .await
    }

    async fn get_message(&self, id: &str) -> AppResult<Option<StoredMessage>> {
        let id = id.to_string();
        self.run_blocking(move |conn, mb| load_message_by_id(conn, mb, &id))
            .await
    }

    async fn list_messages(&self, query: &MessageListQuery) -> AppResult<MessageListPage> {
        let query = query.clone();
        self.run_blocking(move |conn, mb| {
            let max_results = if query.max_results == 0 {
                100
            } else {
                query.max_results.min(500)
            };
            let offset = parse_offset_token(query.page_token.as_deref())?;
            let all = load_all_messages_filtered(
                conn,
                mb,
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
        self.run_blocking(move |conn, mb| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let mut resolved_add = Vec::with_capacity(add_labels.len());
            for l in &add_labels {
                let lid = resolve_existing_label_id(&tx, mb, l)?
                    .ok_or_else(|| AppError::BadRequest(format!("Label not found: {l}")))?;
                resolved_add.push(lid);
            }
            let mut resolved_remove = Vec::with_capacity(remove_labels.len());
            for l in &remove_labels {
                if let Some(lid) = resolve_existing_label_id(&tx, mb, l)? {
                    resolved_remove.push(lid);
                }
            }
            let msg =
                modify_message_labels_resolved_tx(&tx, mb, &id, &resolved_add, &resolved_remove)?;
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
        self.run_blocking(move |conn, mb| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let mut resolved_add = Vec::with_capacity(add_labels.len());
            for l in &add_labels {
                let lid = resolve_existing_label_id(&tx, mb, l)?
                    .ok_or_else(|| AppError::BadRequest(format!("Label not found: {l}")))?;
                resolved_add.push(lid);
            }
            let mut resolved_remove = Vec::with_capacity(remove_labels.len());
            for l in &remove_labels {
                if let Some(lid) = resolve_existing_label_id(&tx, mb, l)? {
                    resolved_remove.push(lid);
                }
            }
            for id in &ids {
                if load_message_by_id(&tx, mb, id)?.is_some() {
                    modify_message_labels_resolved_tx(
                        &tx,
                        mb,
                        id,
                        &resolved_add,
                        &resolved_remove,
                    )?;
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
        self.run_blocking(move |conn, mb| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let deleted = delete_message_tx(&tx, mb, &id)?.is_some();
            tx.commit().map_err(sql_err)?;
            Ok(deleted)
        })
        .await
    }

    async fn batch_delete_messages(&self, ids: &[String]) -> AppResult<()> {
        let ids = ids.to_vec();
        self.run_blocking(move |conn, mb| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            for id in &ids {
                delete_message_tx(&tx, mb, id)?;
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
        self.run_blocking(move |conn, mb| {
            conn.query_row(
                "SELECT id, message_id, part_id, filename, content_type, content_id, size_bytes, data
                 FROM attachments
                 WHERE mailbox_id = ?1 AND message_id = ?2 AND id = ?3",
                params![mb, message_id, attachment_id],
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
        self.run_blocking(move |conn, mb| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, filename, content_type, size_bytes
                     FROM attachments
                     WHERE mailbox_id = ?1 AND message_id = ?2
                     ORDER BY part_id ASC, id ASC",
                )
                .map_err(sql_err)?;
            let rows = stmt
                .query_map(params![mb, message_id], |row| {
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
        self.run_blocking(move |conn, mb| {
            let max_results = if query.max_results == 0 {
                100
            } else {
                query.max_results.min(500)
            };
            let offset = parse_offset_token(query.page_token.as_deref())?;

            let parsed_q = match query.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                Some(raw) => Some(parse_query_with_labels(conn, mb, raw)?),
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
                    .push(resolve_existing_label_id(conn, mb, l)?.unwrap_or_else(|| l.clone()));
            }

            // Load visible messages (filtered only by spam/trash visibility) so threads contain all visible messages.
            let visible_msgs =
                load_all_messages_filtered(conn, mb, &[], effective_include_spam_trash, None)?;

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
        self.run_blocking(move |conn, mb| load_thread_detail_conn(conn, mb, &thread_id))
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
        self.run_blocking(move |conn, mb| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let mut stmt = tx
                .prepare("SELECT id FROM messages WHERE mailbox_id = ?1 AND thread_id = ?2 ORDER BY internal_date_ms ASC, id ASC")
                .map_err(sql_err)?;
            let msg_ids: Vec<String> = stmt
                .query_map(params![mb, &thread_id], |row| row.get(0))
                .map_err(sql_err)?
                .collect::<Result<_, _>>()
                .map_err(sql_err)?;
            drop(stmt);

            if msg_ids.is_empty() {
                return Err(AppError::NotFound(format!("Thread not found: {thread_id}")));
            }

            let mut resolved_add = Vec::with_capacity(add_labels.len());
            for l in &add_labels {
                let lid = resolve_existing_label_id(&tx, mb, l)?
                    .ok_or_else(|| AppError::BadRequest(format!("Label not found: {l}")))?;
                resolved_add.push(lid);
            }
            let mut resolved_remove = Vec::with_capacity(remove_labels.len());
            for l in &remove_labels {
                if let Some(lid) = resolve_existing_label_id(&tx, mb, l)? {
                    resolved_remove.push(lid);
                }
            }

            for mid in &msg_ids {
                modify_message_labels_resolved_tx(&tx, mb, mid, &resolved_add, &resolved_remove)?;
            }

            let detail = load_thread_detail_conn(&tx, mb, &thread_id)?
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
        self.run_blocking(move |conn, mb| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let mut stmt = tx
                .prepare("SELECT id FROM messages WHERE mailbox_id = ?1 AND thread_id = ?2")
                .map_err(sql_err)?;
            let msg_ids: Vec<String> = stmt
                .query_map(params![mb, &thread_id], |row| row.get(0))
                .map_err(sql_err)?
                .collect::<Result<_, _>>()
                .map_err(sql_err)?;
            drop(stmt);

            if msg_ids.is_empty() {
                return Ok(false);
            }
            for mid in &msg_ids {
                delete_message_tx(&tx, mb, mid)?;
            }
            tx.commit().map_err(sql_err)?;
            Ok(true)
        })
        .await
    }

    async fn list_labels(&self) -> AppResult<Vec<StoredLabel>> {
        self.run_blocking(|conn, mb| {
            let mut stmt = conn
                .prepare(
                    "SELECT
                        l.id, l.name, l.label_type, l.message_list_visibility, l.label_list_visibility,
                        l.color_text, l.color_background, l.uid_validity, l.uid_next, l.upstream_label_id,
                        (SELECT COUNT(*) FROM message_labels ml
                         WHERE ml.mailbox_id = l.mailbox_id AND ml.label_id = l.id) AS messages_total,
                        (SELECT COUNT(*) FROM message_labels ml
                         INNER JOIN message_labels mu
                            ON mu.mailbox_id = ml.mailbox_id AND mu.message_id = ml.message_id AND mu.label_id = ?2
                         WHERE ml.mailbox_id = l.mailbox_id AND ml.label_id = l.id) AS messages_unread,
                        (SELECT COUNT(DISTINCT m.thread_id) FROM message_labels ml
                         INNER JOIN messages m
                            ON m.mailbox_id = ml.mailbox_id AND m.id = ml.message_id
                         WHERE ml.mailbox_id = l.mailbox_id AND ml.label_id = l.id) AS threads_total,
                        (SELECT COUNT(DISTINCT m.thread_id) FROM message_labels ml
                         INNER JOIN messages m
                            ON m.mailbox_id = ml.mailbox_id AND m.id = ml.message_id
                         INNER JOIN message_labels mu
                            ON mu.mailbox_id = ml.mailbox_id AND mu.message_id = ml.message_id AND mu.label_id = ?2
                         WHERE ml.mailbox_id = l.mailbox_id AND ml.label_id = l.id) AS threads_unread
                     FROM labels l
                     WHERE l.mailbox_id = ?1
                     ORDER BY CASE WHEN l.label_type = 'system' THEN 0 ELSE 1 END, l.name ASC",
                )
                .map_err(sql_err)?;
            let rows = stmt
                .query_map(params![mb, LABEL_UNREAD], label_from_row)
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
        self.run_blocking(move |conn, mb| load_label_with_counts(conn, mb, &id))
            .await
    }

    async fn create_label(&self, input: NewLabelInput) -> AppResult<StoredLabel> {
        self.run_blocking(move |conn, mb| {
            let name = input.name.trim().to_string();
            if name.is_empty() {
                return Err(AppError::BadRequest("Label name cannot be empty".into()));
            }
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;

            let conflict: Option<String> = tx
                .query_row(
                    "SELECT id FROM labels WHERE mailbox_id = ?1 AND (name = ?2 COLLATE NOCASE OR id = ?2)",
                    params![mb, &name],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?;
            if conflict.is_some() {
                return Err(AppError::Conflict(format!("Label already exists: {name}")));
            }

            let id = format!("Label_{}", &new_hex_id()[..8]);
            let uv = alloc_uid_validity(&tx, mb)?;
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
                    mailbox_id, id, name, label_type, message_list_visibility, label_list_visibility,
                    color_text, color_background, uid_validity, uid_next, upstream_label_id
                 ) VALUES (?1, ?2, ?3, 'user', ?4, ?5, ?6, ?7, ?8, 1, ?9)",
                params![
                    mb,
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

            let created = load_label_with_counts(&tx, mb, &id)?
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
        self.run_blocking(move |conn, mb| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let existing = load_label_with_counts(&tx, mb, &id)?
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
                            "SELECT id FROM labels WHERE mailbox_id = ?1 AND (name = ?2 COLLATE NOCASE OR id = ?2) AND id != ?3",
                            params![mb, trimmed, &id],
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
                 WHERE mailbox_id = ?6 AND id = ?7",
                params![new_name, msg_vis, lbl_vis, color_text, color_bg, mb, &id],
            )
            .map_err(sql_err)?;

            let updated = load_label_with_counts(&tx, mb, &id)?
                .ok_or_else(|| AppError::NotFound(format!("Label not found: {id}")))?;
            tx.commit().map_err(sql_err)?;
            Ok(updated)
        })
        .await
    }

    async fn delete_label(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        self.run_blocking(move |conn, mb| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let existing = load_label_with_counts(&tx, mb, &id)?
                .ok_or_else(|| AppError::NotFound(format!("Label not found: {id}")))?;
            if existing.label_type == "system" || is_system_label(&existing.id) {
                return Err(AppError::BadRequest(format!(
                    "Cannot delete system label: {id}"
                )));
            }

            // Record LabelRemoved history events for messages carrying this label
            let mut stmt = tx
                .prepare(
                    "SELECT m.id, m.thread_id, m.upstream_gmail_id
                     FROM message_labels ml
                     INNER JOIN messages m ON m.mailbox_id = ml.mailbox_id AND m.id = ml.message_id
                     WHERE ml.mailbox_id = ?1 AND ml.label_id = ?2",
                )
                .map_err(sql_err)?;
            let affected: Vec<(String, String, Option<String>)> = stmt
                .query_map(params![mb, &id], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .map_err(sql_err)?
                .collect::<Result<_, _>>()
                .map_err(sql_err)?;
            drop(stmt);

            for (mid, tid, up_id) in affected {
                let ctx = load_message_labels(&tx, mb, &mid)?;
                let hid = bump_history_id(&tx, mb)?;
                tx.execute(
                    "UPDATE messages SET history_id = ?1 WHERE mailbox_id = ?2 AND id = ?3",
                    params![hid as i64, mb, &mid],
                )
                .map_err(sql_err)?;
                record_history_event(
                    &tx,
                    mb,
                    hid,
                    HistoryEventKind::LabelRemoved,
                    &mid,
                    &tid,
                    std::slice::from_ref(&id),
                    &ctx,
                    up_id.as_deref(),
                )?;
            }

            tx.execute(
                "DELETE FROM labels WHERE mailbox_id = ?1 AND id = ?2",
                params![mb, &id],
            )
            .map_err(sql_err)?;
            tx.commit().map_err(sql_err)?;
            Ok(())
        })
        .await
    }

    async fn upsert_upstream_label(&self, input: NewLabelInput) -> AppResult<StoredLabel> {
        self.run_blocking(move |conn, mb| {
            let name = input.name.trim().to_string();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;

            // 1. Check upstream_label_id
            if let Some(ref ulid) = input.upstream_label_id
                && !ulid.trim().is_empty()
            {
                if is_system_label(ulid.trim())
                    && let Some(sys) = load_label_with_counts(&tx, mb, ulid.trim())?
                {
                    tx.commit().map_err(sql_err)?;
                    return Ok(sys);
                }
                if let Some(existing_id) = tx
                    .query_row(
                        "SELECT id FROM labels WHERE mailbox_id = ?1 AND upstream_label_id = ?2",
                        params![mb, ulid.trim()],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .map_err(sql_err)?
                {
                    if !name.is_empty() {
                        tx.execute(
                            "UPDATE labels SET name = ?1 WHERE mailbox_id = ?2 AND id = ?3 AND label_type = 'user'",
                            params![&name, mb, &existing_id],
                        )
                        .map_err(sql_err)?;
                    }
                    let lbl = load_label_with_counts(&tx, mb, &existing_id)?
                        .ok_or_else(|| AppError::Storage("Failed to load upstream label".into()))?;
                    tx.commit().map_err(sql_err)?;
                    return Ok(lbl);
                }
            }

            // 2. Check by existing id or case-insensitive name
            if !name.is_empty()
                && let Some(existing_id) = resolve_existing_label_id(&tx, mb, &name)?
            {
                let existing = load_label_with_counts(&tx, mb, &existing_id)?
                    .ok_or_else(|| AppError::Storage("Failed to load existing label".into()))?;
                if existing.label_type == "system" {
                    tx.commit().map_err(sql_err)?;
                    return Ok(existing);
                }
                if input.upstream_label_id.is_some() && existing.upstream_label_id.is_none() {
                    tx.execute(
                        "UPDATE labels SET upstream_label_id = ?1 WHERE mailbox_id = ?2 AND id = ?3",
                        params![&input.upstream_label_id, mb, &existing_id],
                    )
                    .map_err(sql_err)?;
                }
                let updated = load_label_with_counts(&tx, mb, &existing_id)?
                    .ok_or_else(|| AppError::Storage("Failed to load updated label".into()))?;
                tx.commit().map_err(sql_err)?;
                return Ok(updated);
            }

            if name.is_empty() {
                return Err(AppError::BadRequest("Label name cannot be empty".into()));
            }

            // 3. Create new user label
            let id = format!("Label_{}", &new_hex_id()[..8]);
            let uv = alloc_uid_validity(&tx, mb)?;
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
                    mailbox_id, id, name, label_type, message_list_visibility, label_list_visibility,
                    color_text, color_background, uid_validity, uid_next, upstream_label_id
                 ) VALUES (?1, ?2, ?3, 'user', ?4, ?5, ?6, ?7, ?8, 1, ?9)",
                params![
                    mb,
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
            let created = load_label_with_counts(&tx, mb, &id)?
                .ok_or_else(|| AppError::Storage("Failed to load created upstream label".into()))?;
            tx.commit().map_err(sql_err)?;
            Ok(created)
        })
        .await
    }

    async fn list_drafts(&self, query: &MessageListQuery) -> AppResult<DraftListPage> {
        let query = query.clone();
        self.run_blocking(move |conn, mb| {
            let max_results = if query.max_results == 0 {
                100
            } else {
                query.max_results.min(500)
            };
            let offset = parse_offset_token(query.page_token.as_deref())?;
            let parsed_q = match query.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                Some(raw) => Some(parse_query_with_labels(conn, mb, raw)?),
                None => None,
            };
            let effective_include_spam_trash = query.include_spam_trash
                || parsed_q.as_ref().is_some_and(|pq| pq.include_spam_trash);

            let mut stmt = conn
                .prepare(
                    "SELECT d.id AS draft_id, d.updated_at_ms, m.*
                     FROM drafts d
                     INNER JOIN messages m ON m.mailbox_id = d.mailbox_id AND m.id = d.message_id
                     WHERE d.mailbox_id = ?1
                     ORDER BY d.updated_at_ms DESC, d.id DESC",
                )
                .map_err(sql_err)?;
            let rows = stmt
                .query_map(params![mb], |row| {
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
            let mut label_map = load_labels_for_messages(conn, mb, &msg_ids)?;

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
        self.run_blocking(move |conn, mb| {
            let row: Option<(String, i64)> = conn
                .query_row(
                    "SELECT message_id, updated_at_ms FROM drafts WHERE mailbox_id = ?1 AND id = ?2",
                    params![mb, &id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(sql_err)?;
            let Some((message_id, updated_ms)) = row else {
                return Ok(None);
            };
            let Some(message) = load_message_by_id(conn, mb, &message_id)? else {
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
        self.run_blocking(move |conn, mb| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let stored_msg = insert_message_tx(&tx, mb, message)?;
            let draft_id = format!("r{}", new_hex_id());
            let now = Utc::now();
            tx.execute(
                "INSERT INTO drafts (mailbox_id, id, message_id, updated_at_ms) VALUES (?1, ?2, ?3, ?4)",
                params![mb, &draft_id, &stored_msg.id, now.timestamp_millis()],
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
        self.run_blocking(move |conn, mb| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let old_msg_id: String = tx
                .query_row(
                    "SELECT message_id FROM drafts WHERE mailbox_id = ?1 AND id = ?2",
                    params![mb, &draft_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?
                .ok_or_else(|| AppError::NotFound(format!("Draft not found: {draft_id}")))?;

            // Insert replacement message BEFORE deleting old message so ON DELETE CASCADE won't drop the draft row.
            let new_msg = insert_message_tx(&tx, mb, message)?;
            let now = Utc::now();
            tx.execute(
                "UPDATE drafts SET message_id = ?1, updated_at_ms = ?2 WHERE mailbox_id = ?3 AND id = ?4",
                params![&new_msg.id, now.timestamp_millis(), mb, &draft_id],
            )
            .map_err(sql_err)?;
            delete_message_tx(&tx, mb, &old_msg_id)?;

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
        self.run_blocking(move |conn, mb| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let msg_id: Option<String> = tx
                .query_row(
                    "SELECT message_id FROM drafts WHERE mailbox_id = ?1 AND id = ?2",
                    params![mb, &draft_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?;
            let Some(msg_id) = msg_id else {
                return Ok(false);
            };
            tx.execute(
                "DELETE FROM drafts WHERE mailbox_id = ?1 AND id = ?2",
                params![mb, &draft_id],
            )
            .map_err(sql_err)?;
            delete_message_tx(&tx, mb, &msg_id)?;
            tx.commit().map_err(sql_err)?;
            Ok(true)
        })
        .await
    }

    async fn search_messages_ai(&self, query: &AiSearchQuery) -> AppResult<AiMessagePage> {
        let query = query.clone();
        self.run_blocking(move |conn, mb| {
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
                    .push(resolve_existing_label_id(conn, mb, l)?.unwrap_or_else(|| l.clone()));
            }
            let explicit_spam_trash = resolved_labels
                .iter()
                .any(|l| l == LABEL_TRASH || l == LABEL_SPAM);
            let effective_include_spam_trash = query.include_spam_trash || explicit_spam_trash;

            let mut sql = String::from("SELECT m.* FROM messages m");
            let mut bind_values: Vec<SqlValue> = vec![SqlValue::Text(mb.to_string())];
            let mut where_clauses: Vec<String> = vec!["m.mailbox_id = ?1".to_string()];

            if let Some(ref raw_q) = query.q {
                let trimmed = raw_q.trim();
                if !trimmed.is_empty() {
                    if let Some(fts_query) = build_fts5_query(trimmed) {
                        sql.push_str(
                            " INNER JOIN messages_fts f ON f.mailbox_id = m.mailbox_id AND f.message_id = m.id",
                        );
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
                    "NOT EXISTS (SELECT 1 FROM message_labels ml_ex WHERE ml_ex.mailbox_id = m.mailbox_id AND ml_ex.message_id = m.id AND ml_ex.label_id IN (?{p1}, ?{p2}))"
                ));
            }

            for lid in &resolved_labels {
                bind_values.push(SqlValue::Text(lid.clone()));
                let p = bind_values.len();
                where_clauses.push(format!(
                    "EXISTS (SELECT 1 FROM message_labels ml_in WHERE ml_in.mailbox_id = m.mailbox_id AND ml_in.message_id = m.id AND ml_in.label_id = ?{p})"
                ));
            }

            if let Some(want_unread) = query.unread {
                bind_values.push(SqlValue::Text(LABEL_UNREAD.to_string()));
                let p = bind_values.len();
                if want_unread {
                    where_clauses.push(format!(
                        "EXISTS (SELECT 1 FROM message_labels ml_unr WHERE ml_unr.mailbox_id = m.mailbox_id AND ml_unr.message_id = m.id AND ml_unr.label_id = ?{p})"
                    ));
                } else {
                    where_clauses.push(format!(
                        "NOT EXISTS (SELECT 1 FROM message_labels ml_unr WHERE ml_unr.mailbox_id = m.mailbox_id AND ml_unr.message_id = m.id AND ml_unr.label_id = ?{p})"
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
            let mut label_map = load_labels_for_messages(conn, mb, &ids)?;
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
        self.run_blocking(move |conn, mb| {
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
                Some(l) if !l.trim().is_empty() => Some(
                    resolve_existing_label_id(conn, mb, l)?.unwrap_or_else(|| l.to_string()),
                ),
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
                                 INNER JOIN messages_fts f ON f.mailbox_id = m.mailbox_id AND f.message_id = m.id
                                 WHERE m.mailbox_id = ?1 AND messages_fts MATCH ?2",
                            )
                            .map_err(sql_err)?;
                        let rows = stmt
                            .query_map(params![mb, fts_query], |row| row.get::<_, String>(0))
                            .map_err(sql_err)?;
                        for r in rows {
                            set.insert(r.map_err(sql_err)?);
                        }
                    } else {
                        let pat = format!("%{}%", trimmed.to_ascii_lowercase());
                        let mut stmt = conn
                            .prepare(
                                "SELECT DISTINCT thread_id FROM messages
                                 WHERE mailbox_id = ?1
                                   AND (LOWER(subject) LIKE ?2 OR LOWER(from_addr) LIKE ?2 OR LOWER(text_body) LIKE ?2 OR LOWER(snippet) LIKE ?2)",
                            )
                            .map_err(sql_err)?;
                        let rows = stmt
                            .query_map(params![mb, pat], |row| row.get::<_, String>(0))
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
                load_all_messages_filtered(conn, mb, &[], effective_include_spam_trash, None)?;

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
        self.run_blocking(move |conn, mb| {
            let id: Option<String> = conn
                .query_row(
                    "SELECT id FROM messages WHERE mailbox_id = ?1 AND resend_id = ?2 LIMIT 1",
                    params![mb, resend_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?;
            match id {
                Some(mid) => load_message_by_id(conn, mb, &mid),
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
        self.run_blocking(move |conn, mb| {
            let id: Option<String> = conn
                .query_row(
                    "SELECT id FROM messages WHERE mailbox_id = ?1 AND rfc822_message_id_norm = ?2 LIMIT 1",
                    params![mb, norm],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?;
            match id {
                Some(mid) => load_message_by_id(conn, mb, &mid),
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
        self.run_blocking(move |conn, mb| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let id: Option<String> = tx
                .query_row(
                    "SELECT id FROM messages WHERE mailbox_id = ?1 AND resend_id = ?2 LIMIT 1",
                    params![mb, &resend_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?;
            let Some(mid) = id else {
                return Ok(None);
            };
            tx.execute(
                "UPDATE messages SET delivery_status = ?1 WHERE mailbox_id = ?2 AND id = ?3",
                params![&status, mb, &mid],
            )
            .map_err(sql_err)?;
            let msg = load_message_by_id(&tx, mb, &mid)?;
            tx.commit().map_err(sql_err)?;
            Ok(msg)
        })
        .await
    }

    async fn imap_list_mailboxes(&self) -> AppResult<Vec<ImapMailboxInfo>> {
        self.run_blocking(|conn, mb| {
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
            for item in &builtins {
                mailboxes.push(load_imap_mailbox_info_resolved(conn, mb, item)?);
            }

            let mut stmt = conn
                .prepare(
                    "SELECT id, name FROM labels WHERE mailbox_id = ?1 AND label_type = 'user' ORDER BY name ASC",
                )
                .map_err(sql_err)?;
            let user_labels: Vec<(String, String)> = stmt
                .query_map(params![mb], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(sql_err)?
                .collect::<Result<_, _>>()
                .map_err(sql_err)?;
            drop(stmt);

            for (id, name) in user_labels {
                let item = ResolvedMailbox::Label {
                    id,
                    name,
                    special_use: None,
                };
                mailboxes.push(load_imap_mailbox_info_resolved(conn, mb, &item)?);
            }
            Ok(mailboxes)
        })
        .await
    }

    async fn imap_mailbox_info(&self, mailbox_name: &str) -> AppResult<Option<ImapMailboxInfo>> {
        let mailbox_name = mailbox_name.to_string();
        self.run_blocking(move |conn, mb| {
            let Some(resolved) = resolve_imap_mailbox(conn, mb, &mailbox_name)? else {
                return Ok(None);
            };
            Ok(Some(load_imap_mailbox_info_resolved(conn, mb, &resolved)?))
        })
        .await
    }

    async fn imap_list_messages(&self, mailbox_name: &str) -> AppResult<Vec<ImapMessageEntry>> {
        let mailbox_name = mailbox_name.to_string();
        self.run_blocking(move |conn, mb| {
            let resolved = resolve_imap_mailbox(conn, mb, &mailbox_name)?
                .ok_or_else(|| AppError::NotFound(format!("Mailbox not found: {mailbox_name}")))?;
            load_imap_messages_resolved(conn, mb, &resolved)
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
        self.run_blocking(move |conn, mb| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let Some(old_msg) = load_message_by_id(&tx, mb, &message_id)? else {
                return Err(AppError::NotFound(format!(
                    "Message not found: {message_id}"
                )));
            };
            let flags_changed =
                old_msg.is_answered != is_answered || old_msg.is_deleted != is_deleted;

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
                "UPDATE messages SET is_answered = ?1, is_deleted = ?2 WHERE mailbox_id = ?3 AND id = ?4",
                params![
                    if is_answered { 1_i64 } else { 0_i64 },
                    if is_deleted { 1_i64 } else { 0_i64 },
                    mb,
                    &message_id
                ],
            )
            .map_err(sql_err)?;

            let mut msg = modify_message_labels_resolved_tx(&tx, mb, &message_id, &add, &rem)?;
            if flags_changed && msg.history_id == old_msg.history_id {
                let new_hid = bump_history_id(&tx, mb)?;
                tx.execute(
                    "UPDATE messages SET history_id = ?1 WHERE mailbox_id = ?2 AND id = ?3",
                    params![new_hid as i64, mb, &message_id],
                )
                .map_err(sql_err)?;
                msg.history_id = new_hid;
            }
            tx.commit().map_err(sql_err)?;
            Ok(msg)
        })
        .await
    }

    async fn imap_expunge(&self, mailbox_name: &str) -> AppResult<Vec<u32>> {
        let mailbox_name = mailbox_name.to_string();
        self.run_blocking(move |conn, mb| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let resolved = resolve_imap_mailbox(&tx, mb, &mailbox_name)?
                .ok_or_else(|| AppError::NotFound(format!("Mailbox not found: {mailbox_name}")))?;
            let entries = load_imap_messages_resolved(&tx, mb, &resolved)?;

            let mut expunged_seqs = Vec::new();
            for entry in entries {
                if !entry.is_deleted {
                    continue;
                }
                expunged_seqs.push(entry.seq);
                match &resolved {
                    ResolvedMailbox::Label { id, .. } if id == LABEL_TRASH => {
                        delete_message_tx(&tx, mb, &entry.message_id)?;
                    }
                    ResolvedMailbox::AllMail => {
                        tx.execute(
                            "UPDATE messages SET is_deleted = 0 WHERE mailbox_id = ?1 AND id = ?2",
                            params![mb, &entry.message_id],
                        )
                        .map_err(sql_err)?;
                        modify_message_labels_resolved_tx(
                            &tx,
                            mb,
                            &entry.message_id,
                            &[LABEL_TRASH.to_string()],
                            &[LABEL_INBOX.to_string()],
                        )?;
                    }
                    ResolvedMailbox::Label { id, .. } => {
                        tx.execute(
                            "UPDATE messages SET is_deleted = 0 WHERE mailbox_id = ?1 AND id = ?2",
                            params![mb, &entry.message_id],
                        )
                        .map_err(sql_err)?;
                        modify_message_labels_resolved_tx(
                            &tx,
                            mb,
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
        self.run_blocking(move |conn, mb| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let src = resolve_imap_mailbox(&tx, mb, &src_mailbox)?
                .ok_or_else(|| AppError::NotFound(format!("Mailbox not found: {src_mailbox}")))?;
            let dst = resolve_imap_mailbox(&tx, mb, &dst_mailbox)?
                .ok_or_else(|| AppError::NotFound(format!("Mailbox not found: {dst_mailbox}")))?;

            let same_mailbox = match (&src, &dst) {
                (ResolvedMailbox::AllMail, ResolvedMailbox::AllMail) => true,
                (
                    ResolvedMailbox::Label { id: a, .. },
                    ResolvedMailbox::Label { id: b, .. },
                ) => a == b,
                _ => false,
            };

            let src_entries = load_imap_messages_resolved(&tx, mb, &src)?;
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
                    modify_message_labels_resolved_tx(&tx, mb, mid, &add_labels, &remove_labels)?;

                let dst_uid = match &dst {
                    ResolvedMailbox::AllMail => updated_msg.all_mail_uid,
                    ResolvedMailbox::Label { id: dst_id, .. } => tx
                        .query_row(
                            "SELECT imap_uid FROM message_labels WHERE mailbox_id = ?1 AND message_id = ?2 AND label_id = ?3",
                            params![mb, mid, dst_id],
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
        self.run_blocking(move |conn, mb| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let resolved = resolve_imap_mailbox(&tx, mb, &mailbox_name)?
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

            let msg = insert_message_tx(&tx, mb, input)?;
            let (uid_validity, assigned_uid) = match &resolved {
                ResolvedMailbox::AllMail => {
                    let uv: i64 = tx
                        .query_row(
                            "SELECT uid_validity FROM imap_meta WHERE mailbox_id = ?1 AND mailbox_name = ?2",
                            params![mb, ALL_MAIL_MAILBOX],
                            |row| row.get(0),
                        )
                        .map_err(sql_err)?;
                    (uv.max(1) as u32, msg.all_mail_uid)
                }
                ResolvedMailbox::Label { id, .. } => {
                    let uv: i64 = tx
                        .query_row(
                            "SELECT uid_validity FROM labels WHERE mailbox_id = ?1 AND id = ?2",
                            params![mb, id],
                            |row| row.get(0),
                        )
                        .map_err(sql_err)?;
                    let uid: i64 = tx
                        .query_row(
                            "SELECT imap_uid FROM message_labels WHERE mailbox_id = ?1 AND message_id = ?2 AND label_id = ?3",
                            params![mb, &msg.id, id],
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

    async fn imap_vanished_uids(
        &self,
        mailbox_name: &str,
        since_modseq: u64,
    ) -> AppResult<Vec<u32>> {
        let mailbox_name = mailbox_name.to_string();
        self.run_blocking(move |conn, mb| {
            let resolved = resolve_imap_mailbox(conn, mb, &mailbox_name)?
                .ok_or_else(|| AppError::NotFound(format!("Mailbox not found: {mailbox_name}")))?;
            let mailbox_key = match &resolved {
                ResolvedMailbox::AllMail => ALL_MAIL_MAILBOX.to_string(),
                ResolvedMailbox::Label { id, .. } => id.clone(),
            };
            let mut stmt = conn
                .prepare(
                    "SELECT imap_uid FROM imap_expunged_uids
                     WHERE mailbox_id = ?1 AND mailbox_key = ?2 AND modseq > ?3
                     ORDER BY imap_uid ASC",
                )
                .map_err(sql_err)?;
            let rows = stmt
                .query_map(params![mb, mailbox_key, since_modseq as i64], |row| {
                    Ok(row.get::<_, i64>(0)?.max(1) as u32)
                })
                .map_err(sql_err)?;
            let mut uids = Vec::new();
            for r in rows {
                uids.push(r.map_err(sql_err)?);
            }
            Ok(uids)
        })
        .await
    }

    async fn upsert_synced_message(&self, input: NewMessageInput) -> AppResult<UpsertOutcome> {
        self.run_blocking(move |conn, mb| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;

            // 1. Match by upstream_gmail_id
            if let Some(ref ugid) = input.upstream_gmail_id
                && !ugid.trim().is_empty()
                && let Some(existing_id) = tx
                    .query_row(
                        "SELECT id FROM messages WHERE mailbox_id = ?1 AND upstream_gmail_id = ?2 LIMIT 1",
                        params![mb, ugid.trim()],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .map_err(sql_err)?
            {
                let existing = load_message_by_id(&tx, mb, &existing_id)?
                    .ok_or_else(|| AppError::Storage("Missing matched upstream message".into()))?;

                let mut desired_labels = Vec::new();
                let mut seen = HashSet::new();
                for raw_l in &input.label_ids {
                    let lid = ensure_label_exists_tx(&tx, mb, raw_l)?;
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
                        "UPDATE messages SET is_answered = ?1, is_deleted = ?2 WHERE mailbox_id = ?3 AND id = ?4",
                        params![
                            if input.is_answered { 1_i64 } else { 0_i64 },
                            if input.is_deleted { 1_i64 } else { 0_i64 },
                            mb,
                            &existing_id
                        ],
                    )
                    .map_err(sql_err)?;
                }

                let updated = if labels_changed {
                    modify_message_labels_resolved_tx(&tx, mb, &existing_id, &to_add, &to_remove)?
                } else {
                    load_message_by_id(&tx, mb, &existing_id)?.ok_or_else(|| {
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
                        "SELECT id FROM messages WHERE mailbox_id = ?1 AND rfc822_message_id_norm = ?2 LIMIT 1",
                        params![mb, norm],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .map_err(sql_err)?
            {
                let existing = load_message_by_id(&tx, mb, &existing_id)?
                    .ok_or_else(|| AppError::Storage("Missing matched rfc822 message".into()))?;

                // Backfill upstream IDs if absent
                if existing.upstream_gmail_id.is_none() && input.upstream_gmail_id.is_some() {
                    tx.execute(
                        "UPDATE messages SET upstream_gmail_id = ?1 WHERE mailbox_id = ?2 AND id = ?3",
                        params![&input.upstream_gmail_id, mb, &existing_id],
                    )
                    .map_err(sql_err)?;
                }
                if existing.upstream_thread_id.is_none() && input.upstream_thread_id.is_some() {
                    tx.execute(
                        "UPDATE messages SET upstream_thread_id = ?1 WHERE mailbox_id = ?2 AND id = ?3",
                        params![&input.upstream_thread_id, mb, &existing_id],
                    )
                    .map_err(sql_err)?;
                }

                // Merge incoming labels into existing labels
                let mut to_add = Vec::new();
                for raw_l in &input.label_ids {
                    let lid = ensure_label_exists_tx(&tx, mb, raw_l)?;
                    if !existing.label_ids.contains(&lid) && !to_add.contains(&lid) {
                        to_add.push(lid);
                    }
                }
                let updated = if !to_add.is_empty() {
                    modify_message_labels_resolved_tx(&tx, mb, &existing_id, &to_add, &[])?
                } else {
                    load_message_by_id(&tx, mb, &existing_id)?
                        .ok_or_else(|| AppError::Storage("Missing message after dedup".into()))?
                };
                tx.commit().map_err(sql_err)?;
                return Ok(UpsertOutcome {
                    kind: UpsertOutcomeKind::Deduplicated,
                    message: updated,
                });
            }

            // 3. Insert new message
            let inserted = insert_message_tx(&tx, mb, input)?;
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
        self.run_blocking(move |conn, mb| {
            let id: Option<String> = conn
                .query_row(
                    "SELECT id FROM messages WHERE mailbox_id = ?1 AND upstream_gmail_id = ?2 LIMIT 1",
                    params![mb, upstream_gmail_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?;
            match id {
                Some(mid) => load_message_by_id(conn, mb, &mid),
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
        self.run_blocking(move |conn, mb| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let id: Option<String> = tx
                .query_row(
                    "SELECT id FROM messages WHERE mailbox_id = ?1 AND upstream_gmail_id = ?2 LIMIT 1",
                    params![mb, upstream_gmail_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_err)?;
            let deleted = match id {
                Some(mid) => delete_message_tx(&tx, mb, &mid)?,
                None => None,
            };
            tx.commit().map_err(sql_err)?;
            Ok(deleted)
        })
        .await
    }

    async fn get_sync_state(&self, account_key: &str) -> AppResult<Option<SyncState>> {
        let account_key = account_key.to_string();
        self.run_blocking(move |conn, mb| {
            conn.query_row(
                "SELECT account_key, provider, last_history_id, imap_mailbox, imap_uid_validity,
                        imap_last_uid, last_sync_at_ms, last_full_sync_at_ms, status, last_error,
                        messages_synced, last_pushed_history_id, messages_pushed
                 FROM sync_state WHERE mailbox_id = ?1 AND account_key = ?2",
                params![mb, account_key],
                sync_state_from_row,
            )
            .optional()
            .map_err(sql_err)
        })
        .await
    }

    async fn save_sync_state(&self, state: SyncState) -> AppResult<()> {
        self.run_blocking(move |conn, mb| {
            conn.execute(
                "INSERT INTO sync_state (
                    mailbox_id, account_key, provider, last_history_id, imap_mailbox, imap_uid_validity,
                    imap_last_uid, last_sync_at_ms, last_full_sync_at_ms, status, last_error,
                    messages_synced, last_pushed_history_id, messages_pushed
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                 ON CONFLICT(mailbox_id, account_key) DO UPDATE SET
                    provider = excluded.provider,
                    last_history_id = excluded.last_history_id,
                    imap_mailbox = excluded.imap_mailbox,
                    imap_uid_validity = excluded.imap_uid_validity,
                    imap_last_uid = excluded.imap_last_uid,
                    last_sync_at_ms = excluded.last_sync_at_ms,
                    last_full_sync_at_ms = excluded.last_full_sync_at_ms,
                    status = excluded.status,
                    last_error = excluded.last_error,
                    messages_synced = excluded.messages_synced,
                    last_pushed_history_id = excluded.last_pushed_history_id,
                    messages_pushed = excluded.messages_pushed",
                params![
                    mb,
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
                    state.last_pushed_history_id.map(|v| v as i64),
                    state.messages_pushed as i64,
                ],
            )
            .map_err(sql_err)?;
            Ok(())
        })
        .await
    }

    async fn list_sync_states(&self) -> AppResult<Vec<SyncState>> {
        self.run_blocking(|conn, mb| {
            let mut stmt = conn
                .prepare(
                    "SELECT account_key, provider, last_history_id, imap_mailbox, imap_uid_validity,
                            imap_last_uid, last_sync_at_ms, last_full_sync_at_ms, status, last_error,
                            messages_synced, last_pushed_history_id, messages_pushed
                     FROM sync_state WHERE mailbox_id = ?1 ORDER BY account_key ASC",
                )
                .map_err(sql_err)?;
            let rows = stmt
                .query_map(params![mb], sync_state_from_row)
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
        self.run_blocking(move |conn, mb| {
            let labels_json = serde_json::to_string(&watch.label_ids)
                .map_err(|e| AppError::Storage(format!("JSON encode error: {e}")))?;
            conn.execute(
                "INSERT INTO watch_state (mailbox_id, topic_name, label_ids_json, label_filter_behavior, history_id, expiration_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(mailbox_id) DO UPDATE SET
                    topic_name = excluded.topic_name,
                    label_ids_json = excluded.label_ids_json,
                    label_filter_behavior = excluded.label_filter_behavior,
                    history_id = excluded.history_id,
                    expiration_ms = excluded.expiration_ms",
                params![
                    mb,
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
        self.run_blocking(|conn, mb| {
            conn.query_row(
                "SELECT topic_name, label_ids_json, label_filter_behavior, history_id, expiration_ms
                 FROM watch_state WHERE mailbox_id = ?1",
                params![mb],
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
        self.run_blocking(|conn, mb| {
            conn.execute("DELETE FROM watch_state WHERE mailbox_id = ?1", params![mb])
                .map_err(sql_err)?;
            Ok(())
        })
        .await
    }

    async fn get_settings(&self) -> AppResult<UserSettings> {
        self.run_blocking(move |conn, mb| {
            let defaults = UserSettings::default_for_email(mb);
            let send_as: Vec<SendAs> =
                read_setting(conn, mb, "send_as")?.unwrap_or(defaults.send_as);
            let vacation: VacationSettings =
                read_setting(conn, mb, "vacation")?.unwrap_or(defaults.vacation);
            let auto_forwarding: AutoForwarding =
                read_setting(conn, mb, "auto_forwarding")?.unwrap_or(defaults.auto_forwarding);
            let imap: ImapSettings = read_setting(conn, mb, "imap")?.unwrap_or(defaults.imap);
            let pop: PopSettings = read_setting(conn, mb, "pop")?.unwrap_or(defaults.pop);
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
        self.run_blocking(move |conn, mb| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            write_setting(&tx, mb, "send_as", &settings.send_as)?;
            write_setting(&tx, mb, "vacation", &settings.vacation)?;
            write_setting(&tx, mb, "auto_forwarding", &settings.auto_forwarding)?;
            write_setting(&tx, mb, "imap", &settings.imap)?;
            write_setting(&tx, mb, "pop", &settings.pop)?;
            tx.commit().map_err(sql_err)?;
            Ok(settings)
        })
        .await
    }

    async fn create_pending_approval(
        &self,
        input: NewPendingApprovalInput,
    ) -> AppResult<PendingApproval> {
        self.run_blocking(move |conn, mb| {
            let id = input
                .id
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| format!("apr_{}", Uuid::new_v4().simple()));
            let requester_json = input
                .requester
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let outbound_json = serde_json::to_string(&input.outbound_message)?;

            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;
            let inserted = tx.execute(
                "INSERT INTO pending_approvals (
                    mailbox_id, id, status, reason, requester_json, outbound_message_json,
                    reply_to_message_id, thread_id, draft_id,
                    sent_message_id, provider_message_id, decided_by, decision_note,
                    created_at_ms, expires_at_ms, decided_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, NULL, NULL, NULL, ?10, ?11, NULL)",
                params![
                    mb,
                    id,
                    ApprovalStatus::Pending.as_str(),
                    input.reason,
                    requester_json,
                    outbound_json,
                    input.reply_to_message_id,
                    input.thread_id,
                    input.draft_id,
                    input.created_at_ms,
                    input.expires_at_ms,
                ],
            );
            if let Err(err) = inserted {
                if let rusqlite::Error::SqliteFailure(ref sf, _) = err
                    && sf.code == rusqlite::ErrorCode::ConstraintViolation
                {
                    return Err(AppError::Conflict(format!(
                        "Approval '{id}' already exists"
                    )));
                }
                return Err(sql_err(err));
            }
            tx.commit().map_err(sql_err)?;

            Ok(PendingApproval {
                id,
                status: ApprovalStatus::Pending,
                reason: input.reason,
                requester: input.requester,
                outbound_message: input.outbound_message,
                reply_to_message_id: input.reply_to_message_id,
                thread_id: input.thread_id,
                draft_id: input.draft_id,
                sent_message_id: None,
                provider_message_id: None,
                decided_by: None,
                decision_note: None,
                created_at_ms: input.created_at_ms,
                expires_at_ms: input.expires_at_ms,
                decided_at_ms: None,
            })
        })
        .await
    }

    async fn get_pending_approval(&self, id: &str) -> AppResult<Option<PendingApproval>> {
        let id = id.to_string();
        self.run_blocking(move |conn, mb| {
            let now_ms = Utc::now().timestamp_millis();
            let row = conn
                .query_row(
                    "SELECT id, status, reason, requester_json, outbound_message_json,
                            reply_to_message_id, thread_id, draft_id,
                            sent_message_id, provider_message_id, decided_by, decision_note,
                            created_at_ms, expires_at_ms, decided_at_ms
                     FROM pending_approvals
                     WHERE mailbox_id = ?1 AND id = ?2",
                    params![mb, id],
                    pending_approval_from_row,
                )
                .optional()
                .map_err(sql_err)?;
            row.map(|parsed| normalize_pending_approval(parsed?, now_ms))
                .transpose()
        })
        .await
    }

    async fn list_pending_approvals(
        &self,
        status: Option<ApprovalStatus>,
        limit: usize,
    ) -> AppResult<Vec<PendingApproval>> {
        let limit = if limit == 0 { 20 } else { limit } as i64;
        self.run_blocking(move |conn, mb| {
            let now_ms = Utc::now().timestamp_millis();
            let mut results = Vec::new();
            match status {
                None => {
                    let mut stmt = conn
                        .prepare(
                            "SELECT id, status, reason, requester_json, outbound_message_json,
                                    reply_to_message_id, thread_id, draft_id,
                                    sent_message_id, provider_message_id, decided_by, decision_note,
                                    created_at_ms, expires_at_ms, decided_at_ms
                             FROM pending_approvals
                             WHERE mailbox_id = ?1
                             ORDER BY created_at_ms DESC, id DESC
                             LIMIT ?2",
                        )
                        .map_err(sql_err)?;
                    let rows = stmt
                        .query_map(params![mb, limit], pending_approval_from_row)
                        .map_err(sql_err)?;
                    for row in rows {
                        let parsed = row.map_err(sql_err)??;
                        results.push(normalize_pending_approval(parsed, now_ms)?);
                    }
                }
                Some(ApprovalStatus::Pending) => {
                    let mut stmt = conn
                        .prepare(
                            "SELECT id, status, reason, requester_json, outbound_message_json,
                                    reply_to_message_id, thread_id, draft_id,
                                    sent_message_id, provider_message_id, decided_by, decision_note,
                                    created_at_ms, expires_at_ms, decided_at_ms
                             FROM pending_approvals
                             WHERE mailbox_id = ?1 AND status = 'pending' AND expires_at_ms > ?2
                             ORDER BY created_at_ms DESC, id DESC
                             LIMIT ?3",
                        )
                        .map_err(sql_err)?;
                    let rows = stmt
                        .query_map(params![mb, now_ms, limit], pending_approval_from_row)
                        .map_err(sql_err)?;
                    for row in rows {
                        let parsed = row.map_err(sql_err)??;
                        results.push(normalize_pending_approval(parsed, now_ms)?);
                    }
                }
                Some(ApprovalStatus::Expired) => {
                    let mut stmt = conn
                        .prepare(
                            "SELECT id, status, reason, requester_json, outbound_message_json,
                                    reply_to_message_id, thread_id, draft_id,
                                    sent_message_id, provider_message_id, decided_by, decision_note,
                                    created_at_ms, expires_at_ms, decided_at_ms
                             FROM pending_approvals
                             WHERE mailbox_id = ?1
                               AND (status = 'expired' OR (status = 'pending' AND expires_at_ms <= ?2))
                             ORDER BY created_at_ms DESC, id DESC
                             LIMIT ?3",
                        )
                        .map_err(sql_err)?;
                    let rows = stmt
                        .query_map(params![mb, now_ms, limit], pending_approval_from_row)
                        .map_err(sql_err)?;
                    for row in rows {
                        let parsed = row.map_err(sql_err)??;
                        results.push(normalize_pending_approval(parsed, now_ms)?);
                    }
                }
                Some(other @ (ApprovalStatus::Approved | ApprovalStatus::Rejected)) => {
                    let mut stmt = conn
                        .prepare(
                            "SELECT id, status, reason, requester_json, outbound_message_json,
                                    reply_to_message_id, thread_id, draft_id,
                                    sent_message_id, provider_message_id, decided_by, decision_note,
                                    created_at_ms, expires_at_ms, decided_at_ms
                             FROM pending_approvals
                             WHERE mailbox_id = ?1 AND status = ?2
                             ORDER BY created_at_ms DESC, id DESC
                             LIMIT ?3",
                        )
                        .map_err(sql_err)?;
                    let rows = stmt
                        .query_map(
                            params![mb, other.as_str(), limit],
                            pending_approval_from_row,
                        )
                        .map_err(sql_err)?;
                    for row in rows {
                        let parsed = row.map_err(sql_err)??;
                        results.push(normalize_pending_approval(parsed, now_ms)?);
                    }
                }
            }
            Ok(results)
        })
        .await
    }

    async fn resolve_pending_approval(
        &self,
        id: &str,
        status: ApprovalStatus,
        decided_by: Option<String>,
        note: Option<String>,
        sent_message_id: Option<String>,
        provider_message_id: Option<String>,
    ) -> AppResult<PendingApproval> {
        if !matches!(status, ApprovalStatus::Approved | ApprovalStatus::Rejected) {
            return Err(AppError::BadRequest(
                "Target approval resolution status must be 'approved' or 'rejected'".to_string(),
            ));
        }

        let id = id.to_string();
        self.run_blocking(move |conn, mb| {
            let now_ms = Utc::now().timestamp_millis();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_err)?;

            let existing = tx
                .query_row(
                    "SELECT id, status, reason, requester_json, outbound_message_json,
                            reply_to_message_id, thread_id, draft_id,
                            sent_message_id, provider_message_id, decided_by, decision_note,
                            created_at_ms, expires_at_ms, decided_at_ms
                     FROM pending_approvals
                     WHERE mailbox_id = ?1 AND id = ?2",
                    params![mb, id],
                    pending_approval_from_row,
                )
                .optional()
                .map_err(sql_err)?
                .ok_or_else(|| AppError::NotFound(format!("Approval '{id}' not found")))??;

            if existing.status != ApprovalStatus::Pending {
                return Err(AppError::Conflict(format!(
                    "Approval '{id}' is already {}",
                    existing.status
                )));
            }

            if existing.expires_at_ms <= now_ms {
                tx.execute(
                    "UPDATE pending_approvals
                     SET status = 'expired', decided_at_ms = COALESCE(decided_at_ms, ?1)
                     WHERE mailbox_id = ?2 AND id = ?3 AND status = 'pending'",
                    params![now_ms, mb, id],
                )
                .map_err(sql_err)?;
                tx.commit().map_err(sql_err)?;
                return Err(AppError::Conflict(format!("Approval '{id}' has expired")));
            }

            let changed = tx
                .execute(
                    "UPDATE pending_approvals
                     SET status = ?1,
                         decided_by = ?2,
                         decision_note = ?3,
                         sent_message_id = ?4,
                         provider_message_id = ?5,
                         decided_at_ms = ?6
                     WHERE mailbox_id = ?7 AND id = ?8 AND status = 'pending'",
                    params![
                        status.as_str(),
                        decided_by,
                        note,
                        sent_message_id,
                        provider_message_id,
                        now_ms,
                        mb,
                        id,
                    ],
                )
                .map_err(sql_err)?;

            if changed != 1 {
                return Err(AppError::Conflict(format!(
                    "Approval '{id}' was already resolved"
                )));
            }

            tx.commit().map_err(sql_err)?;

            Ok(PendingApproval {
                status,
                decided_by,
                decision_note: note,
                sent_message_id,
                provider_message_id,
                decided_at_ms: Some(now_ms),
                ..existing
            })
        })
        .await
    }
}

fn pending_approval_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<AppResult<PendingApproval>> {
    let id: String = row.get(0)?;
    let status_raw: String = row.get(1)?;
    let reason: String = row.get(2)?;
    let requester_json: Option<String> = row.get(3)?;
    let outbound_json: String = row.get(4)?;
    let reply_to_message_id: Option<String> = row.get(5)?;
    let thread_id: Option<String> = row.get(6)?;
    let draft_id: Option<String> = row.get(7)?;
    let sent_message_id: Option<String> = row.get(8)?;
    let provider_message_id: Option<String> = row.get(9)?;
    let decided_by: Option<String> = row.get(10)?;
    let decision_note: Option<String> = row.get(11)?;
    let created_at_ms: i64 = row.get(12)?;
    let expires_at_ms: i64 = row.get(13)?;
    let decided_at_ms: Option<i64> = row.get(14)?;

    let parsed = (|| -> AppResult<PendingApproval> {
        let status = ApprovalStatus::parse_str(&status_raw).ok_or_else(|| {
            AppError::Storage(format!("Invalid approval status in DB: '{status_raw}'"))
        })?;
        let requester = requester_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|e| AppError::Storage(format!("Corrupt requester_json: {e}")))?;
        let outbound_message = serde_json::from_str(&outbound_json)
            .map_err(|e| AppError::Storage(format!("Corrupt outbound_message_json: {e}")))?;
        Ok(PendingApproval {
            id,
            status,
            reason,
            requester,
            outbound_message,
            reply_to_message_id,
            thread_id,
            draft_id,
            sent_message_id,
            provider_message_id,
            decided_by,
            decision_note,
            created_at_ms,
            expires_at_ms,
            decided_at_ms,
        })
    })();

    Ok(parsed)
}

fn normalize_pending_approval(
    mut item: PendingApproval,
    now_ms: i64,
) -> AppResult<PendingApproval> {
    if item.status == ApprovalStatus::Pending && item.expires_at_ms <= now_ms {
        item.status = ApprovalStatus::Expired;
    }
    Ok(item)
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
        last_pushed_history_id: row.get::<_, Option<i64>>(11)?.map(|v| v.max(0) as u64),
        messages_pushed: row.get::<_, i64>(12)?.max(0) as u64,
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
