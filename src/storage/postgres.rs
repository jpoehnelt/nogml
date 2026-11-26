//! PostgreSQL-backed `MailStore` implementation and `LISTEN`/`NOTIFY` distributed `EventBus` bridge.
//!
//! Compiled only when the optional `postgres` Cargo feature is enabled (`--features postgres`).

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use deadpool_postgres::{
    GenericClient, Manager, ManagerConfig, Pool, RecyclingMethod, Runtime, Transaction,
};
use futures_util::future::poll_fn;
use serde::{Deserialize, Serialize};
use tokio::sync::{OnceCell, RwLock, mpsc, oneshot, watch};
use tokio_postgres::{AsyncMessage, NoTls, Row, error::SqlState, types::ToSql};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::{
    error::{AppError, AppResult},
    events::{EventBridge, EventBus, EventEnvelope, MailEvent},
    models::{
        AttachmentMeta, AutoForwarding, EmailAddress, ImapSettings, LABEL_DRAFT, LABEL_INBOX,
        LABEL_SENT, LABEL_SPAM, LABEL_STARRED, LABEL_TRASH, LABEL_UNREAD, LabelColor, PopSettings,
        Profile, SYSTEM_LABEL_IDS, SendAs, ThreadAnnotation, ThreadAnnotationPatch, ThreadSummary,
        VacationSettings, WaitingOn, apply_thread_annotation_patch, default_extracted_object,
        is_system_label, truncate_to_millis,
    },
    storage::{
        AiMessagePage, AiSearchQuery, AiThreadPage, AiThreadQuery, ApprovalStatus, AuditLogEntry,
        AuditLogQuery, ContactDirection, ContactInteraction, ContactPatch, ContactQuery,
        ContactRecord, DraftListPage, HistoryEventKind, HistoryListPage, HistoryListQuery,
        IdempotencyRecord, ImapMailboxInfo, ImapMessageEntry, MailStore, MessageListPage,
        MessageListQuery, NewAuditLogEntry, NewLabelInput, NewMessageInput,
        NewPendingApprovalInput, PendingApproval, StoredAttachment, StoredDraft,
        StoredHistoryEntry, StoredLabel, StoredMessage, StoredThreadDetail, SyncState,
        ThreadListPage, TriagePatch, TriageResult, UpdateLabelInput, UpsertOutcome,
        UpsertOutcomeKind, UserSettings, VIP_REPLY_THRESHOLD, WatchSubscription,
        compute_contact_is_vip, normalize_contact_email, normalize_optional_text,
        parse_simple_email_address, validate_and_normalize_contact_email,
    },
};

const ALL_MAIL_MAILBOX: &str = "[Gmail]/All Mail";
const SENT_MAILBOX: &str = "[Gmail]/Sent Mail";
const DRAFTS_MAILBOX: &str = "[Gmail]/Drafts";
const TRASH_MAILBOX: &str = "[Gmail]/Trash";
const SPAM_MAILBOX: &str = "[Gmail]/Spam";
const STARRED_MAILBOX: &str = "[Gmail]/Starred";

/// Default PostgreSQL `LISTEN`/`NOTIFY` channel used for cross-node `EventBus` fan-out.
pub const PG_EVENTS_CHANNEL: &str = "nogml_events";

/// Advisory lock key serializing idempotent DDL startup across concurrent nodes.
const SCHEMA_ADVISORY_LOCK_KEY: i64 = 78_912_345_601;

/// Monotonic schema version tracked in `nogml_schema_meta`.
///
/// Bump this whenever `SCHEMA_SQL` adds or changes tables, columns, or indexes so existing
/// databases apply the idempotent DDL once under the advisory lock and skip `SCHEMA_SQL` on
/// subsequent startups (avoiding `ShareLock` deadlocks against concurrent DML).
const CURRENT_SCHEMA_VERSION: i32 = 4;

/// Default per-mailbox setting keys created by `ensure_mailbox_seeded`.
const SEEDED_SETTING_KEYS: &[&str] = &["send_as", "vacation", "auto_forwarding", "imap", "pop"];

/// Safe payload size threshold under PostgreSQL's 8000-byte `NOTIFY` limit.
const MAX_PG_NOTIFY_BYTES: usize = 7_500;

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS nogml_schema_meta (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS meta (
    mailbox_id TEXT NOT NULL,
    key TEXT NOT NULL,
    int_val BIGINT,
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
    uid_validity BIGINT NOT NULL,
    uid_next BIGINT NOT NULL DEFAULT 1,
    upstream_label_id TEXT,
    PRIMARY KEY (mailbox_id, id)
);
CREATE INDEX IF NOT EXISTS idx_labels_mailbox_name_lower
    ON labels (mailbox_id, LOWER(name));
CREATE UNIQUE INDEX IF NOT EXISTS idx_labels_mailbox_upstream
    ON labels (mailbox_id, upstream_label_id) WHERE upstream_label_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS imap_meta (
    mailbox_id TEXT NOT NULL,
    mailbox_name TEXT NOT NULL,
    uid_validity BIGINT NOT NULL,
    uid_next BIGINT NOT NULL DEFAULT 1,
    PRIMARY KEY (mailbox_id, mailbox_name)
);

CREATE TABLE IF NOT EXISTS imap_expunged_uids (
    mailbox_id TEXT NOT NULL,
    mailbox_key TEXT NOT NULL,
    imap_uid BIGINT NOT NULL,
    modseq BIGINT NOT NULL,
    PRIMARY KEY (mailbox_id, mailbox_key, imap_uid)
);
CREATE INDEX IF NOT EXISTS idx_imap_expunged_mailbox_modseq
    ON imap_expunged_uids (mailbox_id, mailbox_key, modseq);

CREATE TABLE IF NOT EXISTS messages (
    mailbox_id TEXT NOT NULL,
    id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    raw_rfc2822 BYTEA NOT NULL,
    snippet TEXT NOT NULL,
    history_id BIGINT NOT NULL,
    internal_date_ms BIGINT NOT NULL,
    size_estimate INTEGER NOT NULL,
    subject TEXT NOT NULL,
    from_addr TEXT NOT NULL,
    to_addrs_json TEXT NOT NULL,
    cc_addrs_json TEXT NOT NULL,
    bcc_addrs_json TEXT NOT NULL,
    text_body TEXT NOT NULL,
    html_body TEXT,
    has_attachments BOOLEAN NOT NULL DEFAULT FALSE,
    rfc822_message_id TEXT,
    rfc822_message_id_norm TEXT,
    in_reply_to TEXT,
    references_header TEXT,
    resend_id TEXT,
    delivery_status TEXT,
    upstream_gmail_id TEXT,
    upstream_thread_id TEXT,
    source TEXT NOT NULL DEFAULT 'local',
    all_mail_uid BIGINT NOT NULL,
    is_answered BOOLEAN NOT NULL DEFAULT FALSE,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    search_tsv TSVECTOR GENERATED ALWAYS AS (
        to_tsvector(
            'english',
            coalesce(subject, '') || ' ' ||
            coalesce(from_addr, '') || ' ' ||
            coalesce(to_addrs_json, '') || ' ' ||
            coalesce(cc_addrs_json, '') || ' ' ||
            coalesce(text_body, '') || ' ' ||
            coalesce(snippet, '')
        )
    ) STORED,
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
CREATE INDEX IF NOT EXISTS idx_messages_search_tsv
    ON messages USING GIN (search_tsv);

CREATE TABLE IF NOT EXISTS message_labels (
    mailbox_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    label_id TEXT NOT NULL,
    imap_uid BIGINT NOT NULL,
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
    size_bytes BIGINT NOT NULL,
    data BYTEA NOT NULL,
    PRIMARY KEY (mailbox_id, id),
    FOREIGN KEY (mailbox_id, message_id) REFERENCES messages(mailbox_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_attachments_mailbox_message_id
    ON attachments (mailbox_id, message_id, part_id, id);

CREATE TABLE IF NOT EXISTS drafts (
    mailbox_id TEXT NOT NULL,
    id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (mailbox_id, id),
    UNIQUE (mailbox_id, message_id),
    FOREIGN KEY (mailbox_id, message_id) REFERENCES messages(mailbox_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_drafts_mailbox_updated
    ON drafts (mailbox_id, updated_at_ms DESC, id DESC);

CREATE TABLE IF NOT EXISTS history_events (
    id BIGSERIAL PRIMARY KEY,
    mailbox_id TEXT NOT NULL,
    history_id BIGINT NOT NULL,
    kind TEXT NOT NULL,
    message_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    label_ids_json TEXT NOT NULL,
    context_labels_json TEXT NOT NULL DEFAULT '[]',
    upstream_gmail_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_history_events_mailbox_hid
    ON history_events (mailbox_id, history_id, id);

CREATE TABLE IF NOT EXISTS sync_state (
    mailbox_id TEXT NOT NULL,
    account_key TEXT NOT NULL,
    provider TEXT NOT NULL,
    last_history_id TEXT,
    imap_mailbox TEXT,
    imap_uid_validity BIGINT,
    imap_last_uid BIGINT,
    last_sync_at_ms BIGINT,
    last_full_sync_at_ms BIGINT,
    status TEXT NOT NULL,
    last_error TEXT,
    messages_synced BIGINT NOT NULL DEFAULT 0,
    last_pushed_history_id BIGINT,
    messages_pushed BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (mailbox_id, account_key)
);

CREATE TABLE IF NOT EXISTS watch_state (
    mailbox_id TEXT PRIMARY KEY,
    topic_name TEXT NOT NULL,
    label_ids_json TEXT NOT NULL,
    label_filter_behavior TEXT NOT NULL,
    history_id BIGINT NOT NULL,
    expiration_ms BIGINT NOT NULL
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
    created_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    decided_at_ms BIGINT,
    PRIMARY KEY (mailbox_id, id)
);
CREATE INDEX IF NOT EXISTS idx_pending_approvals_mailbox_status_created
    ON pending_approvals (mailbox_id, status, created_at_ms DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_pending_approvals_mailbox_created
    ON pending_approvals (mailbox_id, created_at_ms DESC, id DESC);

CREATE TABLE IF NOT EXISTS contacts (
    mailbox_id TEXT NOT NULL,
    email TEXT NOT NULL,
    display_name TEXT,
    domain TEXT NOT NULL,
    sent_count BIGINT NOT NULL DEFAULT 0,
    received_count BIGINT NOT NULL DEFAULT 0,
    replied_by_me_count BIGINT NOT NULL DEFAULT 0,
    first_seen_at_ms BIGINT NOT NULL,
    last_seen_at_ms BIGINT NOT NULL,
    last_replied_at_ms BIGINT,
    is_vip BOOLEAN NOT NULL DEFAULT FALSE,
    vip_override BOOLEAN,
    notes TEXT,
    PRIMARY KEY (mailbox_id, email)
);
CREATE INDEX IF NOT EXISTS idx_contacts_mailbox_vip_activity
    ON contacts (mailbox_id, is_vip DESC, replied_by_me_count DESC, last_seen_at_ms DESC, email ASC);
CREATE INDEX IF NOT EXISTS idx_contacts_mailbox_domain
    ON contacts (mailbox_id, domain);

CREATE TABLE IF NOT EXISTS thread_annotations (
    mailbox_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    summary TEXT,
    needs_reply BOOLEAN,
    waiting_on TEXT,
    priority TEXT,
    due_at_ms BIGINT,
    extracted_json TEXT NOT NULL DEFAULT '{}',
    updated_by TEXT,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (mailbox_id, thread_id)
);
CREATE INDEX IF NOT EXISTS idx_thread_annotations_mailbox_triage
    ON thread_annotations (mailbox_id, needs_reply, waiting_on);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    mailbox_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    PRIMARY KEY (mailbox_id, scope, key)
);
CREATE INDEX IF NOT EXISTS idx_idempotency_keys_expires
    ON idempotency_keys (mailbox_id, expires_at_ms);

CREATE TABLE IF NOT EXISTS audit_log (
    seq BIGSERIAL PRIMARY KEY,
    id TEXT NOT NULL,
    mailbox_id TEXT NOT NULL,
    timestamp_ms BIGINT NOT NULL,
    actor TEXT NOT NULL,
    scopes_json TEXT NOT NULL,
    channel TEXT NOT NULL,
    action TEXT NOT NULL,
    target_ids_json TEXT NOT NULL,
    outcome TEXT NOT NULL,
    detail TEXT,
    UNIQUE (mailbox_id, id)
);
CREATE INDEX IF NOT EXISTS idx_audit_log_mailbox_ts_seq
    ON audit_log (mailbox_id, timestamp_ms DESC, seq DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_mailbox_action_ts
    ON audit_log (mailbox_id, action, timestamp_ms DESC, seq DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_mailbox_actor_ts
    ON audit_log (mailbox_id, actor, timestamp_ms DESC, seq DESC);
"#;

/// Build a `deadpool-postgres` pool from a PostgreSQL connection URL or libpq string.
pub fn build_postgres_pool(database_url: &str) -> AppResult<Pool> {
    let trimmed = database_url.trim();
    if trimmed.is_empty() {
        return Err(AppError::Config(
            "NOGML_DATABASE_URL / --database-url is required when NOGML_STORAGE=postgres"
                .to_string(),
        ));
    }
    let pg_config: tokio_postgres::Config = trimmed
        .parse()
        .map_err(|e| AppError::Config(format!("Invalid PostgreSQL database URL: {e}")))?;
    let mgr_config = ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    };
    let mgr = Manager::from_config(pg_config, NoTls, mgr_config);
    Pool::builder(mgr)
        .max_size(16)
        .runtime(Runtime::Tokio1)
        .build()
        .map_err(|e| AppError::Storage(format!("Failed to build Postgres pool: {e}")))
}

/// PostgreSQL-backed implementation of [`MailStore`], partitioned by `mailbox_id`.
#[derive(Clone)]
pub struct PostgresStore {
    pool: Pool,
    database_url: String,
    mailbox_id: String,
    schema_ready: Arc<OnceCell<()>>,
    seeded_mailboxes: Arc<RwLock<HashSet<String>>>,
}

impl PostgresStore {
    /// Construct a `PostgresStore` pool synchronously without issuing network I/O yet.
    ///
    /// Schema initialization and mailbox seeding execute automatically and idempotently on
    /// the first async operation (or eagerly via [`Self::connect`]).
    pub fn from_url(database_url: &str, default_email: &str) -> AppResult<Self> {
        let pool = build_postgres_pool(database_url)?;
        let mailbox_id = crate::config::normalize_mailbox_id(default_email);
        Ok(Self {
            pool,
            database_url: database_url.trim().to_string(),
            mailbox_id,
            schema_ready: Arc::new(OnceCell::new()),
            seeded_mailboxes: Arc::new(RwLock::new(HashSet::new())),
        })
    }

    /// Connect to PostgreSQL, run idempotent DDL schema creation, and seed `default_email`.
    pub async fn connect(database_url: &str, default_email: &str) -> AppResult<Self> {
        let store = Self::from_url(database_url, default_email)?;
        store.ensure_ready().await?;
        Ok(store)
    }

    /// Access the underlying connection pool.
    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    /// Access the configured database connection URL.
    pub fn database_url(&self) -> &str {
        &self.database_url
    }

    /// Create a [`PostgresEventBridge`] sharing this store's connection pool and database URL.
    pub fn event_bridge(&self) -> PostgresEventBridge {
        PostgresEventBridge::new(self.database_url.clone(), self.pool.clone())
    }

    /// Ensure DDL schema exists and `self.mailbox_id` has been seeded.
    pub async fn ensure_ready(&self) -> AppResult<()> {
        self.schema_ready
            .get_or_try_init(|| async {
                let mut conn = self.get_conn().await?;
                if is_schema_current(&conn).await? {
                    return Ok::<(), AppError>(());
                }
                let tx = conn.transaction().await.map_err(pg_err)?;
                tx.execute(
                    "SELECT pg_advisory_xact_lock($1)",
                    &[&SCHEMA_ADVISORY_LOCK_KEY],
                )
                .await
                .map_err(pg_err)?;
                if !is_schema_current(&tx).await? {
                    tx.batch_execute(SCHEMA_SQL).await.map_err(pg_err)?;
                    tx.execute(
                        "INSERT INTO nogml_schema_meta (version) VALUES ($1)
                         ON CONFLICT (version) DO NOTHING",
                        &[&CURRENT_SCHEMA_VERSION],
                    )
                    .await
                    .map_err(pg_err)?;
                }
                tx.commit().await.map_err(pg_err)?;
                Ok::<(), AppError>(())
            })
            .await?;

        if !self
            .seeded_mailboxes
            .read()
            .await
            .contains(&self.mailbox_id)
        {
            let mut conn = self.get_conn().await?;
            ensure_mailbox_seeded(&mut conn, &self.mailbox_id).await?;
            self.seeded_mailboxes
                .write()
                .await
                .insert(self.mailbox_id.clone());
        }
        Ok(())
    }

    async fn get_conn(&self) -> AppResult<deadpool_postgres::Object> {
        self.pool
            .get()
            .await
            .map_err(|e| AppError::Storage(format!("Postgres pool error: {e}")))
    }

    async fn ready_conn(&self) -> AppResult<deadpool_postgres::Object> {
        self.ensure_ready().await?;
        self.get_conn().await
    }
}

// ============================================================================
// Distributed EventBus Bridge (PostgreSQL LISTEN / NOTIFY)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PgNotifyPayload {
    node_id: Uuid,
    envelope: EventEnvelope,
}

fn validate_pg_channel(channel: &str) -> AppResult<String> {
    let trimmed = channel.trim();
    if trimmed.is_empty()
        || !trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(AppError::Config(format!(
            "Invalid PostgreSQL LISTEN/NOTIFY channel name: '{channel}'"
        )));
    }
    Ok(trimmed.to_string())
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        s.chars().take(max_chars).collect()
    }
}

fn encode_pg_notify_payload(node_id: Uuid, envelope: &EventEnvelope) -> Option<String> {
    let mut payload = PgNotifyPayload {
        node_id,
        envelope: envelope.clone(),
    };
    let json = serde_json::to_string(&payload).ok()?;
    if json.len() <= MAX_PG_NOTIFY_BYTES {
        return Some(json);
    }
    // Truncate variable-length preview fields so NOTIFY stays well under PG's 8000-byte cap.
    match &mut payload.envelope.event {
        MailEvent::MessageReceived {
            subject, snippet, ..
        } => {
            *subject = truncate_chars(subject, 256);
            *snippet = truncate_chars(snippet, 512);
        }
        MailEvent::MessageSent { subject, to, .. } => {
            *subject = truncate_chars(subject, 256);
            to.truncate(32);
        }
        MailEvent::DeliveryStatus { detail, .. } => {
            if let Some(d) = detail.as_mut() {
                *d = truncate_chars(d, 512);
            }
        }
        MailEvent::ApprovalRequested {
            reason,
            subject,
            to,
            ..
        } => {
            *reason = truncate_chars(reason, 256);
            *subject = truncate_chars(subject, 256);
            to.truncate(32);
        }
        _ => {}
    }
    let trimmed = serde_json::to_string(&payload).ok()?;
    if trimmed.len() <= 7_900 {
        Some(trimmed)
    } else {
        warn!(
            bytes = trimmed.len(),
            "Skipping PostgreSQL NOTIFY: serialized EventEnvelope exceeds 8000-byte limit"
        );
        None
    }
}

/// PostgreSQL `LISTEN`/`NOTIFY` bridge for cross-node [`EventBus`] fan-out.
///
/// Each node generates a random `node_id: Uuid` so echoed notifications originating from
/// itself are ignored while remote nodes' events are republished locally via
/// [`EventBus::publish_remote_envelope`].
#[derive(Clone)]
pub struct PostgresEventBridge {
    node_id: Uuid,
    channel: String,
    database_url: String,
    pool: Pool,
    notify_tx: Option<mpsc::UnboundedSender<String>>,
}

impl PostgresEventBridge {
    /// Create a bridge on the default [`PG_EVENTS_CHANNEL`] (`nogml_events`) channel.
    pub fn new(database_url: String, pool: Pool) -> Self {
        Self::with_channel(database_url, pool, PG_EVENTS_CHANNEL.to_string())
            .expect("default PG_EVENTS_CHANNEL is valid")
    }

    /// Create a bridge on a custom PostgreSQL `LISTEN`/`NOTIFY` channel name.
    pub fn with_channel(database_url: String, pool: Pool, channel: String) -> AppResult<Self> {
        let channel = validate_pg_channel(&channel)?;
        let node_id = Uuid::new_v4();

        // Spawn a FIFO publisher task when created inside a Tokio runtime so NOTIFY
        // frames preserve local publish order and shut down cleanly on drop.
        let notify_tx = match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                let (tx, mut rx) = mpsc::unbounded_channel::<String>();
                let pub_pool = pool.clone();
                let pub_channel = channel.clone();
                handle.spawn(async move {
                    while let Some(payload) = rx.recv().await {
                        if let Err(err) = send_pg_notify(&pub_pool, &pub_channel, &payload).await {
                            warn!(
                                channel = %pub_channel,
                                error = %err,
                                "Failed to send PostgreSQL NOTIFY event"
                            );
                        }
                    }
                });
                Some(tx)
            }
            Err(_) => None,
        };

        Ok(Self {
            node_id,
            channel,
            database_url,
            pool,
            notify_tx,
        })
    }

    /// Unique random identifier for this node instance.
    pub fn node_id(&self) -> Uuid {
        self.node_id
    }

    /// PostgreSQL `LISTEN`/`NOTIFY` channel name.
    pub fn channel(&self) -> &str {
        &self.channel
    }

    /// Run the background `LISTEN` loop until `shutdown_rx` signals `true`.
    pub async fn run_listener(&self, events: EventBus, shutdown_rx: watch::Receiver<bool>) {
        self.run_listener_with_ready(events, shutdown_rx, None)
            .await;
    }

    /// Run the background `LISTEN` loop, firing `ready_tx` once `LISTEN` is active.
    pub async fn run_listener_with_ready(
        &self,
        events: EventBus,
        mut shutdown_rx: watch::Receiver<bool>,
        mut ready_tx: Option<oneshot::Sender<()>>,
    ) {
        let listen_sql = format!("LISTEN {}", self.channel);
        loop {
            if *shutdown_rx.borrow() {
                break;
            }

            let connect_res = tokio_postgres::connect(&self.database_url, NoTls).await;
            let (client, mut connection) = match connect_res {
                Ok(pair) => pair,
                Err(err) => {
                    warn!(
                        channel = %self.channel,
                        error = %err,
                        "Postgres EventBus listener failed to connect; retrying"
                    );
                    tokio::select! {
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                break;
                            }
                        }
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                    }
                    continue;
                }
            };

            let (notif_tx, mut notif_rx) = mpsc::unbounded_channel();
            let channel_for_driver = self.channel.clone();
            let driver_handle = tokio::spawn(async move {
                loop {
                    match poll_fn(|cx| connection.poll_message(cx)).await {
                        Some(Ok(AsyncMessage::Notification(notif))) => {
                            if notif_tx.send(notif).is_err() {
                                break;
                            }
                        }
                        Some(Ok(_)) => {}
                        Some(Err(err)) => {
                            warn!(
                                channel = %channel_for_driver,
                                error = %err,
                                "Postgres EventBus listener connection error"
                            );
                            break;
                        }
                        None => break,
                    }
                }
            });

            if let Err(err) = client.batch_execute(&listen_sql).await {
                warn!(
                    channel = %self.channel,
                    error = %err,
                    "Postgres LISTEN command failed; retrying"
                );
                driver_handle.abort();
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
                continue;
            }

            debug!(
                node_id = %self.node_id,
                channel = %self.channel,
                "Postgres EventBus LISTEN active"
            );
            if let Some(tx) = ready_tx.take() {
                let _ = tx.send(());
            }

            let mut should_exit = false;
            loop {
                tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            should_exit = true;
                            break;
                        }
                    }
                    maybe_notif = notif_rx.recv() => {
                        match maybe_notif {
                            Some(notif) => {
                                match serde_json::from_str::<PgNotifyPayload>(notif.payload()) {
                                    Ok(payload) => {
                                        if payload.node_id == self.node_id {
                                            continue;
                                        }
                                        events.publish_remote_envelope(payload.envelope);
                                    }
                                    Err(err) => {
                                        warn!(
                                            channel = %self.channel,
                                            error = %err,
                                            "Ignoring malformed Postgres NOTIFY event payload"
                                        );
                                    }
                                }
                            }
                            None => {
                                // Connection closed; reconnect unless shutting down.
                                break;
                            }
                        }
                    }
                }
            }

            drop(client);
            driver_handle.abort();
            if should_exit {
                break;
            }
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            }
        }
    }
}

impl EventBridge for PostgresEventBridge {
    fn publish(&self, envelope: &EventEnvelope) {
        let Some(payload) = encode_pg_notify_payload(self.node_id, envelope) else {
            return;
        };
        if let Some(ref tx) = self.notify_tx
            && tx.send(payload.clone()).is_ok()
        {
            return;
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let pool = self.pool.clone();
            let channel = self.channel.clone();
            handle.spawn(async move {
                if let Err(err) = send_pg_notify(&pool, &channel, &payload).await {
                    warn!(
                        channel = %channel,
                        error = %err,
                        "Failed to send PostgreSQL NOTIFY event"
                    );
                }
            });
        }
    }

    fn backend_name(&self) -> &'static str {
        "postgres"
    }
}

async fn send_pg_notify(pool: &Pool, channel: &str, payload: &str) -> AppResult<()> {
    let conn = pool
        .get()
        .await
        .map_err(|e| AppError::Storage(format!("Postgres pool error: {e}")))?;
    conn.execute("SELECT pg_notify($1, $2)", &[&channel, &payload])
        .await
        .map_err(pg_err)?;
    Ok(())
}

// ============================================================================
// Seeding & Helper Functions
// ============================================================================

async fn is_schema_current(client: &impl GenericClient) -> AppResult<bool> {
    let meta_exists: bool = client
        .query_one("SELECT to_regclass('nogml_schema_meta') IS NOT NULL", &[])
        .await
        .map_err(pg_err)?
        .get(0);
    if !meta_exists {
        return Ok(false);
    }
    let current: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM nogml_schema_meta WHERE version >= $1)",
            &[&CURRENT_SCHEMA_VERSION],
        )
        .await
        .map_err(pg_err)?
        .get(0);
    Ok(current)
}

async fn is_mailbox_seeded(client: &impl GenericClient, mailbox_id: &str) -> AppResult<bool> {
    let expected_labels = SYSTEM_LABEL_IDS.len() as i64;
    let expected_settings = SEEDED_SETTING_KEYS.len() as i64;
    let seeded: bool = client
        .query_one(
            "SELECT
                EXISTS (SELECT 1 FROM meta WHERE mailbox_id = $1 AND key = 'history_id')
                AND EXISTS (SELECT 1 FROM meta WHERE mailbox_id = $1 AND key = 'next_uid_validity')
                AND EXISTS (SELECT 1 FROM imap_meta WHERE mailbox_id = $1 AND mailbox_name = $2)
                AND (SELECT COUNT(*) FROM labels WHERE mailbox_id = $1 AND id = ANY($3)) = $4
                AND (SELECT COUNT(*) FROM settings WHERE mailbox_id = $1 AND key = ANY($5)) = $6",
            &[
                &mailbox_id,
                &ALL_MAIL_MAILBOX,
                &SYSTEM_LABEL_IDS,
                &expected_labels,
                &SEEDED_SETTING_KEYS,
                &expected_settings,
            ],
        )
        .await
        .map_err(pg_err)?
        .get(0);
    Ok(seeded)
}

async fn ensure_mailbox_seeded(
    conn: &mut deadpool_postgres::Object,
    mailbox_id: &str,
) -> AppResult<()> {
    // Fast path: skip advisory lock and write statements when already seeded.
    if is_mailbox_seeded(conn, mailbox_id).await? {
        return Ok(());
    }

    let tx = conn.transaction().await.map_err(pg_err)?;
    // Serialize per-mailbox seeding across concurrent nodes.
    tx.execute(
        "SELECT pg_advisory_xact_lock(hashtext($1)::bigint)",
        &[&mailbox_id],
    )
    .await
    .map_err(pg_err)?;

    if is_mailbox_seeded(&tx, mailbox_id).await? {
        tx.commit().await.map_err(pg_err)?;
        return Ok(());
    }

    tx.execute(
        "INSERT INTO meta (mailbox_id, key, int_val) VALUES ($1, 'history_id', 1)
         ON CONFLICT (mailbox_id, key) DO NOTHING",
        &[&mailbox_id],
    )
    .await
    .map_err(pg_err)?;
    tx.execute(
        "INSERT INTO meta (mailbox_id, key, int_val) VALUES ($1, 'next_uid_validity', 1)
         ON CONFLICT (mailbox_id, key) DO NOTHING",
        &[&mailbox_id],
    )
    .await
    .map_err(pg_err)?;

    // Seed [Gmail]/All Mail IMAP metadata
    let all_mail_exists = tx
        .query_opt(
            "SELECT uid_validity FROM imap_meta WHERE mailbox_id = $1 AND mailbox_name = $2",
            &[&mailbox_id, &ALL_MAIL_MAILBOX],
        )
        .await
        .map_err(pg_err)?;
    if all_mail_exists.is_none() {
        let uv = alloc_uid_validity(&tx, mailbox_id).await?;
        let uv_i64 = uv as i64;
        tx.execute(
            "INSERT INTO imap_meta (mailbox_id, mailbox_name, uid_validity, uid_next)
             VALUES ($1, $2, $3, 1)
             ON CONFLICT (mailbox_id, mailbox_name) DO NOTHING",
            &[&mailbox_id, &ALL_MAIL_MAILBOX, &uv_i64],
        )
        .await
        .map_err(pg_err)?;
    }

    // Seed system labels
    for &label_id in SYSTEM_LABEL_IDS {
        let exists = tx
            .query_opt(
                "SELECT id FROM labels WHERE mailbox_id = $1 AND id = $2",
                &[&mailbox_id, &label_id],
            )
            .await
            .map_err(pg_err)?;
        if exists.is_none() {
            let uv = alloc_uid_validity(&tx, mailbox_id).await?;
            let uv_i64 = uv as i64;
            let (msg_vis, lbl_vis) = if label_id == LABEL_TRASH || label_id == LABEL_SPAM {
                ("hide", "labelHide")
            } else {
                ("show", "labelShow")
            };
            tx.execute(
                "INSERT INTO labels
                 (mailbox_id, id, name, label_type, message_list_visibility, label_list_visibility, uid_validity, uid_next)
                 VALUES ($1, $2, $3, 'system', $4, $5, $6, 1)
                 ON CONFLICT (mailbox_id, id) DO NOTHING",
                &[&mailbox_id, &label_id, &label_id, &msg_vis, &lbl_vis, &uv_i64],
            )
            .await
            .map_err(pg_err)?;
        }
    }

    // Seed default user settings
    let defaults = UserSettings::default_for_email(mailbox_id);
    seed_setting_if_missing(&tx, mailbox_id, "send_as", &defaults.send_as).await?;
    seed_setting_if_missing(&tx, mailbox_id, "vacation", &defaults.vacation).await?;
    seed_setting_if_missing(
        &tx,
        mailbox_id,
        "auto_forwarding",
        &defaults.auto_forwarding,
    )
    .await?;
    seed_setting_if_missing(&tx, mailbox_id, "imap", &defaults.imap).await?;
    seed_setting_if_missing(&tx, mailbox_id, "pop", &defaults.pop).await?;

    tx.commit().await.map_err(pg_err)?;
    Ok(())
}

fn pg_err(err: tokio_postgres::Error) -> AppError {
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

fn escape_like_pattern(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('%');
    for ch in raw.chars() {
        match ch {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out.push('%');
    out
}

async fn seed_setting_if_missing<T: serde::Serialize>(
    tx: &Transaction<'_>,
    mailbox_id: &str,
    key: &str,
    value: &T,
) -> AppResult<()> {
    let json = serde_json::to_string(value)
        .map_err(|e| AppError::Storage(format!("Failed to serialize setting {key}: {e}")))?;
    tx.execute(
        "INSERT INTO settings (mailbox_id, key, value_json) VALUES ($1, $2, $3)
         ON CONFLICT (mailbox_id, key) DO NOTHING",
        &[&mailbox_id, &key, &json],
    )
    .await
    .map_err(pg_err)?;
    Ok(())
}

async fn alloc_uid_validity(tx: &Transaction<'_>, mailbox_id: &str) -> AppResult<u32> {
    let row = tx
        .query_one(
            "UPDATE meta
             SET int_val = int_val + 1
             WHERE mailbox_id = $1 AND key = 'next_uid_validity'
             RETURNING int_val - 1",
            &[&mailbox_id],
        )
        .await
        .map_err(pg_err)?;
    let allocated: i64 = row.get(0);
    Ok(allocated.max(1) as u32)
}

async fn bump_history_id(tx: &Transaction<'_>, mailbox_id: &str) -> AppResult<u64> {
    let row = tx
        .query_one(
            "UPDATE meta
             SET int_val = int_val + 1
             WHERE mailbox_id = $1 AND key = 'history_id'
             RETURNING int_val",
            &[&mailbox_id],
        )
        .await
        .map_err(pg_err)?;
    let hid: i64 = row.get(0);
    Ok(hid.max(1) as u64)
}

async fn read_current_history_id(client: &impl GenericClient, mailbox_id: &str) -> AppResult<u64> {
    let row = client
        .query_one(
            "SELECT int_val FROM meta WHERE mailbox_id = $1 AND key = 'history_id'",
            &[&mailbox_id],
        )
        .await
        .map_err(pg_err)?;
    let hid: i64 = row.get(0);
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

#[allow(clippy::too_many_arguments)]
async fn record_history_event(
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
    let hid_i64 = history_id as i64;
    let kind_str = history_kind_to_str(kind);
    tx.execute(
        "INSERT INTO history_events (mailbox_id, history_id, kind, message_id, thread_id, label_ids_json, context_labels_json, upstream_gmail_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        &[
            &mailbox_id,
            &hid_i64,
            &kind_str,
            &message_id,
            &thread_id,
            &labels_json,
            &ctx_json,
            &upstream_gmail_id,
        ],
    )
    .await
    .map_err(pg_err)?;
    Ok(())
}

async fn alloc_all_mail_uid(tx: &Transaction<'_>, mailbox_id: &str) -> AppResult<u32> {
    let row = tx
        .query_one(
            "UPDATE imap_meta
             SET uid_next = uid_next + 1
             WHERE mailbox_id = $1 AND mailbox_name = $2
             RETURNING uid_next - 1",
            &[&mailbox_id, &ALL_MAIL_MAILBOX],
        )
        .await
        .map_err(pg_err)?;
    let uid: i64 = row.get(0);
    Ok(uid.max(1) as u32)
}

async fn alloc_label_uid(tx: &Transaction<'_>, mailbox_id: &str, label_id: &str) -> AppResult<u32> {
    let row = tx
        .query_one(
            "UPDATE labels
             SET uid_next = uid_next + 1
             WHERE mailbox_id = $1 AND id = $2
             RETURNING uid_next - 1",
            &[&mailbox_id, &label_id],
        )
        .await
        .map_err(pg_err)?;
    let uid: i64 = row.get(0);
    Ok(uid.max(1) as u32)
}

async fn ensure_label_exists_tx(
    tx: &Transaction<'_>,
    mailbox_id: &str,
    raw_label: &str,
) -> AppResult<String> {
    let trimmed = raw_label.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest("Label ID cannot be empty".into()));
    }
    if let Some(row) = tx
        .query_opt(
            "SELECT id FROM labels WHERE mailbox_id = $1 AND id = $2",
            &[&mailbox_id, &trimmed],
        )
        .await
        .map_err(pg_err)?
    {
        return Ok(row.get(0));
    }
    if let Some(row) = tx
        .query_opt(
            "SELECT id FROM labels WHERE mailbox_id = $1 AND LOWER(name) = LOWER($2)",
            &[&mailbox_id, &trimmed],
        )
        .await
        .map_err(pg_err)?
    {
        return Ok(row.get(0));
    }
    if let Some(row) = tx
        .query_opt(
            "SELECT id FROM labels WHERE mailbox_id = $1 AND upstream_label_id = $2",
            &[&mailbox_id, &trimmed],
        )
        .await
        .map_err(pg_err)?
    {
        return Ok(row.get(0));
    }

    let uv = alloc_uid_validity(tx, mailbox_id).await?;
    let uv_i64 = uv as i64;
    tx.execute(
        "INSERT INTO labels (mailbox_id, id, name, label_type, message_list_visibility, label_list_visibility, uid_validity, uid_next)
         VALUES ($1, $2, $3, 'user', 'show', 'labelShow', $4, 1)
         ON CONFLICT (mailbox_id, id) DO NOTHING",
        &[&mailbox_id, &trimmed, &trimmed, &uv_i64],
    )
    .await
    .map_err(pg_err)?;
    Ok(trimmed.to_string())
}

async fn resolve_existing_label_id(
    client: &impl GenericClient,
    mailbox_id: &str,
    raw_label: &str,
) -> AppResult<Option<String>> {
    let trimmed = raw_label.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if let Some(row) = client
        .query_opt(
            "SELECT id FROM labels WHERE mailbox_id = $1 AND id = $2",
            &[&mailbox_id, &trimmed],
        )
        .await
        .map_err(pg_err)?
    {
        return Ok(Some(row.get(0)));
    }
    let row = client
        .query_opt(
            "SELECT id FROM labels WHERE mailbox_id = $1 AND LOWER(name) = LOWER($2)",
            &[&mailbox_id, &trimmed],
        )
        .await
        .map_err(pg_err)?;
    Ok(row.map(|r| r.get(0)))
}

async fn load_message_labels(
    client: &impl GenericClient,
    mailbox_id: &str,
    message_id: &str,
) -> AppResult<Vec<String>> {
    let rows = client
        .query(
            "SELECT label_id FROM message_labels WHERE mailbox_id = $1 AND message_id = $2 ORDER BY label_id ASC",
            &[&mailbox_id, &message_id],
        )
        .await
        .map_err(pg_err)?;
    Ok(rows.into_iter().map(|r| r.get(0)).collect())
}

async fn load_labels_for_messages(
    client: &impl GenericClient,
    mailbox_id: &str,
    message_ids: &[String],
) -> AppResult<HashMap<String, Vec<String>>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    if message_ids.is_empty() {
        return Ok(map);
    }
    let rows = client
        .query(
            "SELECT message_id, label_id FROM message_labels
             WHERE mailbox_id = $1 AND message_id = ANY($2)
             ORDER BY label_id ASC",
            &[&mailbox_id, &message_ids],
        )
        .await
        .map_err(pg_err)?;
    for row in rows {
        let mid: String = row.get(0);
        let lid: String = row.get(1);
        map.entry(mid).or_default().push(lid);
    }
    Ok(map)
}

fn message_from_row(row: &Row) -> StoredMessage {
    let to_json: String = row.get("to_addrs_json");
    let cc_json: String = row.get("cc_addrs_json");
    let bcc_json: String = row.get("bcc_addrs_json");
    let to_addrs: Vec<String> = serde_json::from_str(&to_json).unwrap_or_default();
    let cc_addrs: Vec<String> = serde_json::from_str(&cc_json).unwrap_or_default();
    let bcc_addrs: Vec<String> = serde_json::from_str(&bcc_json).unwrap_or_default();

    StoredMessage {
        id: row.get("id"),
        thread_id: row.get("thread_id"),
        label_ids: Vec::new(),
        raw_rfc2822: row.get("raw_rfc2822"),
        snippet: row.get("snippet"),
        history_id: row.get::<_, i64>("history_id").max(0) as u64,
        internal_date_ms: row.get("internal_date_ms"),
        size_estimate: row.get("size_estimate"),
        subject: row.get("subject"),
        from_addr: row.get("from_addr"),
        to_addrs,
        cc_addrs,
        bcc_addrs,
        text_body: row.get("text_body"),
        html_body: row.get("html_body"),
        has_attachments: row.get("has_attachments"),
        rfc822_message_id: row.get("rfc822_message_id"),
        in_reply_to: row.get("in_reply_to"),
        references_header: row.get("references_header"),
        resend_id: row.get("resend_id"),
        delivery_status: row.get("delivery_status"),
        upstream_gmail_id: row.get("upstream_gmail_id"),
        upstream_thread_id: row.get("upstream_thread_id"),
        source: row.get("source"),
        all_mail_uid: row.get::<_, i64>("all_mail_uid").max(0) as u32,
        is_answered: row.get("is_answered"),
        is_deleted: row.get("is_deleted"),
    }
}

async fn load_message_by_id(
    client: &impl GenericClient,
    mailbox_id: &str,
    id: &str,
) -> AppResult<Option<StoredMessage>> {
    let Some(row) = client
        .query_opt(
            "SELECT * FROM messages WHERE mailbox_id = $1 AND id = $2",
            &[&mailbox_id, &id],
        )
        .await
        .map_err(pg_err)?
    else {
        return Ok(None);
    };
    let mut msg = message_from_row(&row);
    msg.label_ids = load_message_labels(client, mailbox_id, &msg.id).await?;
    Ok(Some(msg))
}

async fn resolve_thread_id_tx(
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
    if let Some(ref utid) = input.upstream_thread_id {
        let trimmed = utid.trim();
        if !trimmed.is_empty()
            && let Some(row) = tx
                .query_opt(
                    "SELECT thread_id FROM messages WHERE mailbox_id = $1 AND upstream_thread_id = $2 LIMIT 1",
                    &[&mailbox_id, &trimmed],
                )
                .await
                .map_err(pg_err)?
        {
            return Ok(row.get(0));
        }
    }
    if let Some(ref irt) = input.in_reply_to
        && let Some(norm) = normalize_rfc_message_id(irt)
        && let Some(row) = tx
            .query_opt(
                "SELECT thread_id FROM messages WHERE mailbox_id = $1 AND rfc822_message_id_norm = $2 LIMIT 1",
                &[&mailbox_id, &norm],
            )
            .await
            .map_err(pg_err)?
    {
        return Ok(row.get(0));
    }
    if let Some(ref refs) = input.references_header {
        for token in refs.split_whitespace().rev() {
            if let Some(norm) = normalize_rfc_message_id(token)
                && let Some(row) = tx
                    .query_opt(
                        "SELECT thread_id FROM messages WHERE mailbox_id = $1 AND rfc822_message_id_norm = $2 LIMIT 1",
                        &[&mailbox_id, &norm],
                    )
                    .await
                    .map_err(pg_err)?
            {
                return Ok(row.get(0));
            }
        }
    }
    Ok(msg_id.to_string())
}

async fn insert_message_tx(
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
    let thread_id = resolve_thread_id_tx(tx, mailbox_id, &input, &msg_id).await?;

    let mut label_set = HashSet::new();
    let mut resolved_labels = Vec::new();
    for raw_label in &input.label_ids {
        let lid = ensure_label_exists_tx(tx, mailbox_id, raw_label).await?;
        if label_set.insert(lid.clone()) {
            resolved_labels.push(lid);
        }
    }
    resolved_labels.sort();

    let history_id = bump_history_id(tx, mailbox_id).await?;
    let all_mail_uid = alloc_all_mail_uid(tx, mailbox_id).await?;
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

    let history_id_i64 = history_id as i64;
    let all_mail_uid_i64 = all_mail_uid as i64;

    tx.execute(
        "INSERT INTO messages (
            mailbox_id, id, thread_id, raw_rfc2822, snippet, history_id, internal_date_ms, size_estimate,
            subject, from_addr, to_addrs_json, cc_addrs_json, bcc_addrs_json,
            text_body, html_body, has_attachments,
            rfc822_message_id, rfc822_message_id_norm, in_reply_to, references_header,
            resend_id, delivery_status, upstream_gmail_id, upstream_thread_id,
            source, all_mail_uid, is_answered, is_deleted
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8,
            $9, $10, $11, $12, $13,
            $14, $15, $16,
            $17, $18, $19, $20,
            $21, NULL, $22, $23,
            $24, $25, $26, $27
        )",
        &[
            &mailbox_id,
            &msg_id,
            &thread_id,
            &input.raw_rfc2822,
            &input.snippet,
            &history_id_i64,
            &input.internal_date_ms,
            &size_estimate,
            &input.subject,
            &input.from_addr,
            &to_json,
            &cc_json,
            &bcc_json,
            &input.text_body,
            &input.html_body,
            &has_attachments,
            &input.rfc822_message_id,
            &rfc_norm,
            &input.in_reply_to,
            &input.references_header,
            &input.resend_id,
            &input.upstream_gmail_id,
            &input.upstream_thread_id,
            &source,
            &all_mail_uid_i64,
            &input.is_answered,
            &input.is_deleted,
        ],
    )
    .await
    .map_err(pg_err)?;

    for lid in &resolved_labels {
        let imap_uid = alloc_label_uid(tx, mailbox_id, lid).await? as i64;
        tx.execute(
            "INSERT INTO message_labels (mailbox_id, message_id, label_id, imap_uid) VALUES ($1, $2, $3, $4)",
            &[&mailbox_id, &msg_id, lid, &imap_uid],
        )
        .await
        .map_err(pg_err)?;
    }

    for att in &input.attachments {
        let att_id = format!("att_{}", new_hex_id());
        let att_size = att.data.len() as i64;
        tx.execute(
            "INSERT INTO attachments (mailbox_id, id, message_id, part_id, filename, content_type, content_id, size_bytes, data)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            &[
                &mailbox_id,
                &att_id,
                &msg_id,
                &att.part_id,
                &att.filename,
                &att.content_type,
                &att.content_id,
                &att_size,
                &att.data,
            ],
        )
        .await
        .map_err(pg_err)?;
    }

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
    )
    .await?;

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

async fn record_expunged_uid_tx(
    tx: &Transaction<'_>,
    mailbox_id: &str,
    mailbox_key: &str,
    imap_uid: u32,
    modseq: u64,
) -> AppResult<()> {
    let uid_i64 = imap_uid as i64;
    let modseq_i64 = modseq as i64;
    tx.execute(
        "INSERT INTO imap_expunged_uids (mailbox_id, mailbox_key, imap_uid, modseq)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (mailbox_id, mailbox_key, imap_uid)
         DO UPDATE SET modseq = EXCLUDED.modseq",
        &[&mailbox_id, &mailbox_key, &uid_i64, &modseq_i64],
    )
    .await
    .map_err(pg_err)?;
    Ok(())
}

async fn clear_expunged_uid_tx(
    tx: &Transaction<'_>,
    mailbox_id: &str,
    mailbox_key: &str,
    imap_uid: u32,
) -> AppResult<()> {
    let uid_i64 = imap_uid as i64;
    tx.execute(
        "DELETE FROM imap_expunged_uids WHERE mailbox_id = $1 AND mailbox_key = $2 AND imap_uid = $3",
        &[&mailbox_id, &mailbox_key, &uid_i64],
    )
    .await
    .map_err(pg_err)?;
    Ok(())
}

async fn modify_message_labels_resolved_tx(
    tx: &Transaction<'_>,
    mailbox_id: &str,
    message_id: &str,
    resolved_add: &[String],
    resolved_remove: &[String],
) -> AppResult<StoredMessage> {
    let mut msg = load_message_by_id(tx, mailbox_id, message_id)
        .await?
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
        let new_hid = bump_history_id(tx, mailbox_id).await?;
        let new_hid_i64 = new_hid as i64;
        tx.execute(
            "UPDATE messages SET history_id = $1 WHERE mailbox_id = $2 AND id = $3",
            &[&new_hid_i64, &mailbox_id, &message_id],
        )
        .await
        .map_err(pg_err)?;

        for lid in &actually_added {
            let imap_uid = alloc_label_uid(tx, mailbox_id, lid).await?;
            let imap_uid_i64 = imap_uid as i64;
            tx.execute(
                "INSERT INTO message_labels (mailbox_id, message_id, label_id, imap_uid)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (mailbox_id, message_id, label_id) DO NOTHING",
                &[&mailbox_id, &message_id, lid, &imap_uid_i64],
            )
            .await
            .map_err(pg_err)?;
            clear_expunged_uid_tx(tx, mailbox_id, lid, imap_uid).await?;
        }

        for lid in &actually_removed {
            let removed_row = tx
                .query_opt(
                    "SELECT imap_uid FROM message_labels WHERE mailbox_id = $1 AND message_id = $2 AND label_id = $3",
                    &[&mailbox_id, &message_id, lid],
                )
                .await
                .map_err(pg_err)?;
            tx.execute(
                "DELETE FROM message_labels WHERE mailbox_id = $1 AND message_id = $2 AND label_id = $3",
                &[&mailbox_id, &message_id, lid],
            )
            .await
            .map_err(pg_err)?;
            if let Some(row) = removed_row {
                let uid: i64 = row.get(0);
                record_expunged_uid_tx(tx, mailbox_id, lid, uid.max(1) as u32, new_hid).await?;
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
            record_expunged_uid_tx(tx, mailbox_id, ALL_MAIL_MAILBOX, msg.all_mail_uid, new_hid)
                .await?;
        } else if !was_in_all_mail && is_in_all_mail {
            clear_expunged_uid_tx(tx, mailbox_id, ALL_MAIL_MAILBOX, msg.all_mail_uid).await?;
        }

        let mut context_set = current_set;
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
            )
            .await?;
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
            )
            .await?;
        }

        msg.history_id = new_hid;
        msg.label_ids = load_message_labels(tx, mailbox_id, message_id).await?;
    }

    Ok(msg)
}

async fn delete_message_tx(
    tx: &Transaction<'_>,
    mailbox_id: &str,
    id: &str,
) -> AppResult<Option<StoredMessage>> {
    let Some(msg) = load_message_by_id(tx, mailbox_id, id).await? else {
        return Ok(None);
    };
    let rows = tx
        .query(
            "SELECT label_id, imap_uid FROM message_labels WHERE mailbox_id = $1 AND message_id = $2",
            &[&mailbox_id, &id],
        )
        .await
        .map_err(pg_err)?;
    let label_uids: Vec<(String, u32)> = rows
        .into_iter()
        .map(|row| (row.get::<_, String>(0), row.get::<_, i64>(1).max(1) as u32))
        .collect();

    let hid = bump_history_id(tx, mailbox_id).await?;
    for (lid, uid) in label_uids {
        record_expunged_uid_tx(tx, mailbox_id, &lid, uid, hid).await?;
    }
    if !msg
        .label_ids
        .iter()
        .any(|l| l == LABEL_TRASH || l == LABEL_SPAM)
    {
        record_expunged_uid_tx(tx, mailbox_id, ALL_MAIL_MAILBOX, msg.all_mail_uid, hid).await?;
    }

    tx.execute(
        "DELETE FROM messages WHERE mailbox_id = $1 AND id = $2",
        &[&mailbox_id, &id],
    )
    .await
    .map_err(pg_err)?;

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
    )
    .await?;

    Ok(Some(msg))
}

fn label_from_row(row: &Row) -> StoredLabel {
    let color_text: Option<String> = row.get("color_text");
    let color_bg: Option<String> = row.get("color_background");
    let color = match (color_text, color_bg) {
        (Some(text_color), Some(background_color)) => Some(LabelColor {
            text_color,
            background_color,
        }),
        _ => None,
    };
    StoredLabel {
        id: row.get("id"),
        name: row.get("name"),
        label_type: row.get("label_type"),
        message_list_visibility: row.get("message_list_visibility"),
        label_list_visibility: row.get("label_list_visibility"),
        color,
        messages_total: row.get::<_, i64>("messages_total").max(0) as i32,
        messages_unread: row.get::<_, i64>("messages_unread").max(0) as i32,
        threads_total: row.get::<_, i64>("threads_total").max(0) as i32,
        threads_unread: row.get::<_, i64>("threads_unread").max(0) as i32,
        uid_validity: row.get::<_, i64>("uid_validity").max(1) as u32,
        uid_next: row.get::<_, i64>("uid_next").max(1) as u32,
        upstream_label_id: row.get("upstream_label_id"),
    }
}

async fn load_label_with_counts(
    client: &impl GenericClient,
    mailbox_id: &str,
    id: &str,
) -> AppResult<Option<StoredLabel>> {
    let row = client
        .query_opt(
            "SELECT
                l.id, l.name, l.label_type, l.message_list_visibility, l.label_list_visibility,
                l.color_text, l.color_background, l.uid_validity, l.uid_next, l.upstream_label_id,
                (SELECT COUNT(*) FROM message_labels ml
                 WHERE ml.mailbox_id = l.mailbox_id AND ml.label_id = l.id) AS messages_total,
                (SELECT COUNT(*) FROM message_labels ml
                 INNER JOIN message_labels mu
                    ON mu.mailbox_id = ml.mailbox_id AND mu.message_id = ml.message_id AND mu.label_id = $3
                 WHERE ml.mailbox_id = l.mailbox_id AND ml.label_id = l.id) AS messages_unread,
                (SELECT COUNT(DISTINCT m.thread_id) FROM message_labels ml
                 INNER JOIN messages m
                    ON m.mailbox_id = ml.mailbox_id AND m.id = ml.message_id
                 WHERE ml.mailbox_id = l.mailbox_id AND ml.label_id = l.id) AS threads_total,
                (SELECT COUNT(DISTINCT m.thread_id) FROM message_labels ml
                 INNER JOIN messages m
                    ON m.mailbox_id = ml.mailbox_id AND m.id = ml.message_id
                 INNER JOIN message_labels mu
                    ON mu.mailbox_id = ml.mailbox_id AND mu.message_id = ml.message_id AND mu.label_id = $3
                 WHERE ml.mailbox_id = l.mailbox_id AND ml.label_id = l.id) AS threads_unread
             FROM labels l
             WHERE l.mailbox_id = $1 AND l.id = $2",
            &[&mailbox_id, &id, &LABEL_UNREAD],
        )
        .await
        .map_err(pg_err)?;
    Ok(row.as_ref().map(label_from_row))
}

async fn load_thread_detail_client(
    client: &impl GenericClient,
    mailbox_id: &str,
    thread_id: &str,
) -> AppResult<Option<StoredThreadDetail>> {
    let rows = client
        .query(
            "SELECT * FROM messages WHERE mailbox_id = $1 AND thread_id = $2 ORDER BY internal_date_ms ASC, id ASC",
            &[&mailbox_id, &thread_id],
        )
        .await
        .map_err(pg_err)?;
    let mut messages: Vec<StoredMessage> = rows.iter().map(message_from_row).collect();
    if messages.is_empty() {
        return Ok(None);
    }
    let ids: Vec<String> = messages.iter().map(|m| m.id.clone()).collect();
    let mut label_map = load_labels_for_messages(client, mailbox_id, &ids).await?;
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

fn build_thread_summary(
    thread_id: &str,
    messages: &[StoredMessage],
    annotation: Option<ThreadAnnotation>,
) -> ThreadSummary {
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
        sender_contact: None,
        snippet,
        labels,
        unread,
        has_attachments,
        message_count: messages.len(),
        last_message_at,
        annotation,
    }
}

fn thread_annotation_from_row(row: &Row) -> ThreadAnnotation {
    let waiting_on: Option<String> = row.get(3);
    let due_at_ms: Option<i64> = row.get(5);
    let extracted_json: String = row.get(6);
    let updated_at_ms: i64 = row.get(8);

    ThreadAnnotation {
        thread_id: row.get(0),
        summary: row.get(1),
        needs_reply: row.get(2),
        waiting_on: waiting_on.as_deref().and_then(WaitingOn::parse_str),
        priority: row.get(4),
        due_at: due_at_ms.and_then(DateTime::from_timestamp_millis),
        extracted: serde_json::from_str(&extracted_json)
            .unwrap_or_else(|_| default_extracted_object()),
        updated_by: row.get(7),
        updated_at: DateTime::from_timestamp_millis(updated_at_ms).unwrap_or_else(Utc::now),
    }
}

async fn load_thread_annotation_client<C: GenericClient>(
    client: &C,
    mb: &str,
    thread_id: &str,
    for_update: bool,
) -> AppResult<Option<ThreadAnnotation>> {
    let sql = if for_update {
        "SELECT thread_id, summary, needs_reply, waiting_on, priority, due_at_ms,
                extracted_json, updated_by, updated_at_ms
         FROM thread_annotations
         WHERE mailbox_id = $1 AND thread_id = $2
         FOR UPDATE"
    } else {
        "SELECT thread_id, summary, needs_reply, waiting_on, priority, due_at_ms,
                extracted_json, updated_by, updated_at_ms
         FROM thread_annotations
         WHERE mailbox_id = $1 AND thread_id = $2"
    };
    let row = client
        .query_opt(sql, &[&mb, &thread_id])
        .await
        .map_err(pg_err)?;
    Ok(row.as_ref().map(thread_annotation_from_row))
}

async fn upsert_thread_annotation_client<C: GenericClient>(
    client: &C,
    mb: &str,
    annotation: &ThreadAnnotation,
) -> AppResult<()> {
    let extracted_json = serde_json::to_string(&annotation.extracted)
        .map_err(|e| AppError::Storage(format!("JSON encode error: {e}")))?;
    let waiting_on_str = annotation.waiting_on.map(|w| w.as_str().to_string());
    let due_at_ms = annotation.due_at.map(|dt| dt.timestamp_millis());
    let updated_at_ms = annotation.updated_at.timestamp_millis();

    client
        .execute(
            "INSERT INTO thread_annotations (
                mailbox_id, thread_id, summary, needs_reply, waiting_on, priority,
                due_at_ms, extracted_json, updated_by, updated_at_ms
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (mailbox_id, thread_id) DO UPDATE SET
                summary = EXCLUDED.summary,
                needs_reply = EXCLUDED.needs_reply,
                waiting_on = EXCLUDED.waiting_on,
                priority = EXCLUDED.priority,
                due_at_ms = EXCLUDED.due_at_ms,
                extracted_json = EXCLUDED.extracted_json,
                updated_by = EXCLUDED.updated_by,
                updated_at_ms = EXCLUDED.updated_at_ms",
            &[
                &mb,
                &annotation.thread_id,
                &annotation.summary,
                &annotation.needs_reply,
                &waiting_on_str,
                &annotation.priority,
                &due_at_ms,
                &extracted_json,
                &annotation.updated_by,
                &updated_at_ms,
            ],
        )
        .await
        .map_err(pg_err)?;
    Ok(())
}

async fn load_thread_annotations_filtered<C: GenericClient>(
    client: &C,
    mb: &str,
    needs_reply: Option<bool>,
    waiting_on: Option<WaitingOn>,
) -> AppResult<HashMap<String, ThreadAnnotation>> {
    let waiting_on_str = waiting_on.map(|w| w.as_str().to_string());
    let mut sql = String::from(
        "SELECT thread_id, summary, needs_reply, waiting_on, priority, due_at_ms,
                extracted_json, updated_by, updated_at_ms
         FROM thread_annotations
         WHERE mailbox_id = $1",
    );
    let mut params: Vec<&(dyn ToSql + Sync)> = vec![&mb];
    if let Some(ref nr) = needs_reply {
        params.push(nr);
        sql.push_str(&format!(" AND needs_reply = ${}", params.len()));
    }
    if let Some(ref wo) = waiting_on_str {
        params.push(wo);
        sql.push_str(&format!(" AND waiting_on = ${}", params.len()));
    }

    let rows = client.query(&sql, &params).await.map_err(pg_err)?;
    let mut map = HashMap::with_capacity(rows.len());
    for row in &rows {
        let ann = thread_annotation_from_row(row);
        map.insert(ann.thread_id.clone(), ann);
    }
    Ok(map)
}

async fn load_thread_annotations_for_ids<C: GenericClient>(
    client: &C,
    mb: &str,
    thread_ids: &[String],
) -> AppResult<HashMap<String, ThreadAnnotation>> {
    if thread_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = client
        .query(
            "SELECT thread_id, summary, needs_reply, waiting_on, priority, due_at_ms,
                    extracted_json, updated_by, updated_at_ms
             FROM thread_annotations
             WHERE mailbox_id = $1 AND thread_id = ANY($2)",
            &[&mb, &thread_ids],
        )
        .await
        .map_err(pg_err)?;
    let mut map = HashMap::with_capacity(rows.len());
    for row in &rows {
        let ann = thread_annotation_from_row(row);
        map.insert(ann.thread_id.clone(), ann);
    }
    Ok(map)
}

enum ResolvedMailbox {
    AllMail,
    Label {
        id: String,
        name: String,
        special_use: Option<&'static str>,
    },
}

async fn resolve_imap_mailbox(
    client: &impl GenericClient,
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

    let row = client
        .query_opt(
            "SELECT id, name FROM labels WHERE mailbox_id = $1 AND label_type = 'user' AND name = $2",
            &[&mailbox_id, &mailbox_name],
        )
        .await
        .map_err(pg_err)?;
    Ok(row.map(|r| ResolvedMailbox::Label {
        id: r.get(0),
        name: r.get(1),
        special_use: None,
    }))
}

async fn load_imap_mailbox_info_resolved(
    client: &impl GenericClient,
    mailbox_id: &str,
    resolved: &ResolvedMailbox,
) -> AppResult<ImapMailboxInfo> {
    match resolved {
        ResolvedMailbox::AllMail => {
            let row = client
                .query_one(
                    "SELECT uid_validity, uid_next FROM imap_meta WHERE mailbox_id = $1 AND mailbox_name = $2",
                    &[&mailbox_id, &ALL_MAIL_MAILBOX],
                )
                .await
                .map_err(pg_err)?;
            let uv: i64 = row.get(0);
            let un: i64 = row.get(1);

            let messages: i64 = client
                .query_one(
                    "SELECT COUNT(*) FROM messages m
                     WHERE m.mailbox_id = $1
                       AND NOT EXISTS (
                           SELECT 1 FROM message_labels ml
                           WHERE ml.mailbox_id = m.mailbox_id AND ml.message_id = m.id AND ml.label_id IN ($2, $3)
                       )",
                    &[&mailbox_id, &LABEL_TRASH, &LABEL_SPAM],
                )
                .await
                .map_err(pg_err)?
                .get(0);
            let unseen: i64 = client
                .query_one(
                    "SELECT COUNT(*) FROM messages m
                     WHERE m.mailbox_id = $1
                       AND EXISTS (
                           SELECT 1 FROM message_labels mu
                           WHERE mu.mailbox_id = m.mailbox_id AND mu.message_id = m.id AND mu.label_id = $4
                       )
                       AND NOT EXISTS (
                           SELECT 1 FROM message_labels ml
                           WHERE ml.mailbox_id = m.mailbox_id AND ml.message_id = m.id AND ml.label_id IN ($2, $3)
                       )",
                    &[&mailbox_id, &LABEL_TRASH, &LABEL_SPAM, &LABEL_UNREAD],
                )
                .await
                .map_err(pg_err)?
                .get(0);

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
            let row = client
                .query_one(
                    "SELECT uid_validity, uid_next FROM labels WHERE mailbox_id = $1 AND id = $2",
                    &[&mailbox_id, id],
                )
                .await
                .map_err(pg_err)?;
            let uv: i64 = row.get(0);
            let un: i64 = row.get(1);

            let messages: i64 = client
                .query_one(
                    "SELECT COUNT(*) FROM message_labels WHERE mailbox_id = $1 AND label_id = $2",
                    &[&mailbox_id, id],
                )
                .await
                .map_err(pg_err)?
                .get(0);
            let unseen: i64 = client
                .query_one(
                    "SELECT COUNT(*) FROM message_labels ml
                     INNER JOIN message_labels mu
                        ON mu.mailbox_id = ml.mailbox_id AND mu.message_id = ml.message_id AND mu.label_id = $3
                     WHERE ml.mailbox_id = $1 AND ml.label_id = $2",
                    &[&mailbox_id, id, &LABEL_UNREAD],
                )
                .await
                .map_err(pg_err)?
                .get(0);

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

async fn load_imap_messages_resolved(
    client: &impl GenericClient,
    mailbox_id: &str,
    resolved: &ResolvedMailbox,
) -> AppResult<Vec<ImapMessageEntry>> {
    let rows = match resolved {
        ResolvedMailbox::AllMail => {
            client
                .query(
                    "SELECT m.all_mail_uid, m.id, m.thread_id, m.history_id, m.internal_date_ms, m.size_estimate, m.is_answered, m.is_deleted
                     FROM messages m
                     WHERE m.mailbox_id = $1
                       AND NOT EXISTS (
                           SELECT 1 FROM message_labels ml
                           WHERE ml.mailbox_id = m.mailbox_id AND ml.message_id = m.id AND ml.label_id IN ($2, $3)
                       )
                     ORDER BY m.all_mail_uid ASC",
                    &[&mailbox_id, &LABEL_TRASH, &LABEL_SPAM],
                )
                .await
                .map_err(pg_err)?
        }
        ResolvedMailbox::Label { id, .. } => {
            client
                .query(
                    "SELECT ml.imap_uid, m.id, m.thread_id, m.history_id, m.internal_date_ms, m.size_estimate, m.is_answered, m.is_deleted
                     FROM message_labels ml
                     INNER JOIN messages m ON m.mailbox_id = ml.mailbox_id AND m.id = ml.message_id
                     WHERE ml.mailbox_id = $1 AND ml.label_id = $2
                     ORDER BY ml.imap_uid ASC",
                    &[&mailbox_id, id],
                )
                .await
                .map_err(pg_err)?
        }
    };

    let raw_entries: Vec<RawImapEntry> = rows
        .into_iter()
        .map(|row| RawImapEntry {
            uid: row.get::<_, i64>(0).max(1) as u32,
            message_id: row.get(1),
            thread_id: row.get(2),
            history_id: row.get::<_, i64>(3).max(1) as u64,
            internal_date_ms: row.get(4),
            size_estimate: row.get(5),
            is_answered: row.get(6),
            is_deleted: row.get(7),
        })
        .collect();

    let ids: Vec<String> = raw_entries.iter().map(|e| e.message_id.clone()).collect();
    let mut label_map = load_labels_for_messages(client, mailbox_id, &ids).await?;

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

async fn load_label_name_to_id_map(
    client: &impl GenericClient,
    mailbox_id: &str,
) -> AppResult<HashMap<String, String>> {
    let rows = client
        .query(
            "SELECT id, name FROM labels WHERE mailbox_id = $1",
            &[&mailbox_id],
        )
        .await
        .map_err(pg_err)?;
    let mut map = HashMap::new();
    for r in rows {
        let id: String = r.get(0);
        let name: String = r.get(1);
        let lower = name.to_ascii_lowercase();
        let hyphen = lower.replace('/', "-");
        map.insert(lower, id.clone());
        map.insert(hyphen, id);
    }
    Ok(map)
}

async fn parse_query_with_labels(
    client: &impl GenericClient,
    mailbox_id: &str,
    raw_q: &str,
) -> AppResult<crate::search::SearchQuery> {
    let mut parsed = crate::search::parse_query(raw_q);
    if !parsed.terms.is_empty() {
        let map = load_label_name_to_id_map(client, mailbox_id).await?;
        parsed.terms = parsed
            .terms
            .into_iter()
            .map(|t| rewrite_search_term_labels(t, &map))
            .collect();
    }
    Ok(parsed)
}

async fn load_all_messages_filtered(
    client: &impl GenericClient,
    mailbox_id: &str,
    label_ids: &[String],
    include_spam_trash: bool,
    q: Option<&str>,
) -> AppResult<Vec<StoredMessage>> {
    let parsed_q = match q.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => Some(parse_query_with_labels(client, mailbox_id, raw).await?),
        None => None,
    };

    let explicit_spam_trash = label_ids
        .iter()
        .any(|l| l == LABEL_TRASH || l == LABEL_SPAM);
    let effective_include_spam_trash = include_spam_trash
        || explicit_spam_trash
        || parsed_q.as_ref().is_some_and(|pq| pq.include_spam_trash);

    let mut sql = String::from("SELECT m.* FROM messages m WHERE m.mailbox_id = $1");
    let mut bind_values: Vec<Box<dyn ToSql + Sync + Send>> = vec![Box::new(mailbox_id.to_string())];

    if !effective_include_spam_trash {
        bind_values.push(Box::new(LABEL_TRASH.to_string()));
        let p1 = bind_values.len();
        bind_values.push(Box::new(LABEL_SPAM.to_string()));
        let p2 = bind_values.len();
        sql.push_str(&format!(
            " AND NOT EXISTS (SELECT 1 FROM message_labels ml_ex WHERE ml_ex.mailbox_id = m.mailbox_id AND ml_ex.message_id = m.id AND ml_ex.label_id IN (${p1}, ${p2}))"
        ));
    }

    for lid in label_ids {
        let resolved = resolve_existing_label_id(client, mailbox_id, lid)
            .await?
            .unwrap_or_else(|| lid.clone());
        bind_values.push(Box::new(resolved));
        let p = bind_values.len();
        sql.push_str(&format!(
            " AND EXISTS (SELECT 1 FROM message_labels ml_in WHERE ml_in.mailbox_id = m.mailbox_id AND ml_in.message_id = m.id AND ml_in.label_id = ${p})"
        ));
    }

    sql.push_str(" ORDER BY m.internal_date_ms DESC, m.id DESC");

    let param_refs: Vec<&(dyn ToSql + Sync)> = bind_values
        .iter()
        .map(|b| b.as_ref() as &(dyn ToSql + Sync))
        .collect();
    let rows = client.query(&sql, &param_refs).await.map_err(pg_err)?;
    let mut messages: Vec<StoredMessage> = rows.iter().map(message_from_row).collect();

    let ids: Vec<String> = messages.iter().map(|m| m.id.clone()).collect();
    let mut label_map = load_labels_for_messages(client, mailbox_id, &ids).await?;
    for m in &mut messages {
        m.label_ids = label_map.remove(&m.id).unwrap_or_default();
    }

    if let Some(ref pq) = parsed_q {
        messages.retain(|m| crate::search::matches_message(pq, m));
    }

    Ok(messages)
}

async fn read_setting<T: serde::de::DeserializeOwned>(
    client: &impl GenericClient,
    mailbox_id: &str,
    key: &str,
) -> AppResult<Option<T>> {
    let row = client
        .query_opt(
            "SELECT value_json FROM settings WHERE mailbox_id = $1 AND key = $2",
            &[&mailbox_id, &key],
        )
        .await
        .map_err(pg_err)?;
    match row {
        Some(r) => {
            let json: String = r.get(0);
            serde_json::from_str(&json)
                .map(Some)
                .map_err(|e| AppError::Storage(format!("Failed to decode setting {key}: {e}")))
        }
        None => Ok(None),
    }
}

async fn write_setting<T: serde::Serialize>(
    tx: &Transaction<'_>,
    mailbox_id: &str,
    key: &str,
    value: &T,
) -> AppResult<()> {
    let json = serde_json::to_string(value)
        .map_err(|e| AppError::Storage(format!("Failed to encode setting {key}: {e}")))?;
    tx.execute(
        "INSERT INTO settings (mailbox_id, key, value_json) VALUES ($1, $2, $3)
         ON CONFLICT (mailbox_id, key) DO UPDATE SET value_json = EXCLUDED.value_json",
        &[&mailbox_id, &key, &json],
    )
    .await
    .map_err(pg_err)?;
    Ok(())
}

fn pending_approval_from_row(row: &Row) -> AppResult<PendingApproval> {
    let id: String = row.get(0);
    let status_raw: String = row.get(1);
    let reason: String = row.get(2);
    let requester_json: Option<String> = row.get(3);
    let outbound_json: String = row.get(4);
    let reply_to_message_id: Option<String> = row.get(5);
    let thread_id: Option<String> = row.get(6);
    let draft_id: Option<String> = row.get(7);
    let sent_message_id: Option<String> = row.get(8);
    let provider_message_id: Option<String> = row.get(9);
    let decided_by: Option<String> = row.get(10);
    let decision_note: Option<String> = row.get(11);
    let created_at_ms: i64 = row.get(12);
    let expires_at_ms: i64 = row.get(13);
    let decided_at_ms: Option<i64> = row.get(14);

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

fn sync_state_from_row(row: &Row) -> SyncState {
    let last_sync_ms: Option<i64> = row.get(6);
    let last_full_ms: Option<i64> = row.get(7);
    SyncState {
        account_key: row.get(0),
        provider: row.get(1),
        last_history_id: row.get(2),
        imap_mailbox: row.get(3),
        imap_uid_validity: row.get::<_, Option<i64>>(4).map(|v| v.max(0) as u32),
        imap_last_uid: row.get::<_, Option<i64>>(5).map(|v| v.max(0) as u32),
        last_sync_at: last_sync_ms.and_then(DateTime::from_timestamp_millis),
        last_full_sync_at: last_full_ms.and_then(DateTime::from_timestamp_millis),
        status: row.get(8),
        last_error: row.get(9),
        messages_synced: row.get::<_, i64>(10).max(0) as u64,
        last_pushed_history_id: row.get::<_, Option<i64>>(11).map(|v| v.max(0) as u64),
        messages_pushed: row.get::<_, i64>(12).max(0) as u64,
    }
}

// ============================================================================
// `MailStore` Implementation
// ============================================================================

#[async_trait]
impl MailStore for PostgresStore {
    fn backend_name(&self) -> &'static str {
        "postgres"
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
        Arc::new(Self {
            pool: self.pool.clone(),
            database_url: self.database_url.clone(),
            mailbox_id: target,
            schema_ready: self.schema_ready.clone(),
            seeded_mailboxes: self.seeded_mailboxes.clone(),
        })
    }

    async fn get_profile(&self, email_address: &str) -> AppResult<Profile> {
        let conn = self.ready_conn().await?;
        let email = if email_address.trim().is_empty() {
            self.mailbox_id.clone()
        } else {
            email_address.to_string()
        };
        let mb = self.mailbox_id.as_str();
        let messages_total: i64 = conn
            .query_one(
                "SELECT COUNT(*) FROM messages WHERE mailbox_id = $1",
                &[&mb],
            )
            .await
            .map_err(pg_err)?
            .get(0);
        let threads_total: i64 = conn
            .query_one(
                "SELECT COUNT(DISTINCT thread_id) FROM messages WHERE mailbox_id = $1",
                &[&mb],
            )
            .await
            .map_err(pg_err)?
            .get(0);
        let history_id = read_current_history_id(&conn, mb).await?;
        Ok(Profile {
            email_address: email,
            messages_total: messages_total.max(0) as i32,
            threads_total: threads_total.max(0) as i32,
            history_id: history_id.to_string(),
        })
    }

    async fn current_history_id(&self) -> AppResult<u64> {
        let conn = self.ready_conn().await?;
        read_current_history_id(&conn, &self.mailbox_id).await
    }

    async fn list_history(&self, query: &HistoryListQuery) -> AppResult<HistoryListPage> {
        if query.start_history_id == 0 {
            return Err(AppError::NotFound(
                "Invalid startHistoryId: must be greater than 0".into(),
            ));
        }
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let current_hid = read_current_history_id(&conn, mb).await?;
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
                resolve_existing_label_id(&conn, mb, l)
                    .await?
                    .unwrap_or_else(|| l.to_string()),
            ),
            _ => None,
        };

        let start_hid_i64 = query.start_history_id as i64;
        let rows = conn
            .query(
                "SELECT id, history_id, kind, message_id, thread_id, label_ids_json, context_labels_json, upstream_gmail_id
                 FROM history_events
                 WHERE mailbox_id = $1 AND history_id > $2 AND id > $3
                 ORDER BY id ASC",
                &[&mb, &start_hid_i64, &after_row_id],
            )
            .await
            .map_err(pg_err)?;

        let mut matched: Vec<(i64, StoredHistoryEntry)> = Vec::new();
        for row in rows {
            let row_id: i64 = row.get(0);
            let hid: i64 = row.get(1);
            let kind_str: String = row.get(2);
            let message_id: String = row.get(3);
            let thread_id: String = row.get(4);
            let labels_json: String = row.get(5);
            let ctx_json: String = row.get(6);
            let upstream_gmail_id: Option<String> = row.get(7);

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
    }

    async fn insert_message(&self, input: NewMessageInput) -> AppResult<StoredMessage> {
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let msg = insert_message_tx(&tx, &self.mailbox_id, input).await?;
        tx.commit().await.map_err(pg_err)?;
        Ok(msg)
    }

    async fn get_message(&self, id: &str) -> AppResult<Option<StoredMessage>> {
        let conn = self.ready_conn().await?;
        load_message_by_id(&conn, &self.mailbox_id, id).await
    }

    async fn list_messages(&self, query: &MessageListQuery) -> AppResult<MessageListPage> {
        let conn = self.ready_conn().await?;
        let max_results = if query.max_results == 0 {
            100
        } else {
            query.max_results.min(500)
        };
        let offset = parse_offset_token(query.page_token.as_deref())?;
        let all = load_all_messages_filtered(
            &conn,
            &self.mailbox_id,
            &query.label_ids,
            query.include_spam_trash,
            query.q.as_deref(),
        )
        .await?;
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
    }

    async fn modify_message_labels(
        &self,
        id: &str,
        add_labels: &[String],
        remove_labels: &[String],
    ) -> AppResult<StoredMessage> {
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let mb = self.mailbox_id.as_str();

        let mut resolved_add = Vec::with_capacity(add_labels.len());
        for l in add_labels {
            let lid = resolve_existing_label_id(&tx, mb, l)
                .await?
                .ok_or_else(|| AppError::BadRequest(format!("Label not found: {l}")))?;
            resolved_add.push(lid);
        }
        let mut resolved_remove = Vec::with_capacity(remove_labels.len());
        for l in remove_labels {
            if let Some(lid) = resolve_existing_label_id(&tx, mb, l).await? {
                resolved_remove.push(lid);
            }
        }
        let msg =
            modify_message_labels_resolved_tx(&tx, mb, id, &resolved_add, &resolved_remove).await?;
        tx.commit().await.map_err(pg_err)?;
        Ok(msg)
    }

    async fn batch_modify_labels(
        &self,
        ids: &[String],
        add_labels: &[String],
        remove_labels: &[String],
    ) -> AppResult<()> {
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let mb = self.mailbox_id.as_str();

        let mut resolved_add = Vec::with_capacity(add_labels.len());
        for l in add_labels {
            let lid = resolve_existing_label_id(&tx, mb, l)
                .await?
                .ok_or_else(|| AppError::BadRequest(format!("Label not found: {l}")))?;
            resolved_add.push(lid);
        }
        let mut resolved_remove = Vec::with_capacity(remove_labels.len());
        for l in remove_labels {
            if let Some(lid) = resolve_existing_label_id(&tx, mb, l).await? {
                resolved_remove.push(lid);
            }
        }
        for id in ids {
            if load_message_by_id(&tx, mb, id).await?.is_some() {
                modify_message_labels_resolved_tx(&tx, mb, id, &resolved_add, &resolved_remove)
                    .await?;
            }
        }
        tx.commit().await.map_err(pg_err)?;
        Ok(())
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
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let deleted = delete_message_tx(&tx, &self.mailbox_id, id)
            .await?
            .is_some();
        tx.commit().await.map_err(pg_err)?;
        Ok(deleted)
    }

    async fn batch_delete_messages(&self, ids: &[String]) -> AppResult<()> {
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        for id in ids {
            delete_message_tx(&tx, &self.mailbox_id, id).await?;
        }
        tx.commit().await.map_err(pg_err)?;
        Ok(())
    }

    async fn get_attachment(
        &self,
        message_id: &str,
        attachment_id: &str,
    ) -> AppResult<Option<StoredAttachment>> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let row = conn
            .query_opt(
                "SELECT id, message_id, part_id, filename, content_type, content_id, size_bytes, data
                 FROM attachments
                 WHERE mailbox_id = $1 AND message_id = $2 AND id = $3",
                &[&mb, &message_id, &attachment_id],
            )
            .await
            .map_err(pg_err)?;
        Ok(row.map(|r| StoredAttachment {
            id: r.get(0),
            message_id: r.get(1),
            part_id: r.get(2),
            filename: r.get(3),
            content_type: r.get(4),
            content_id: r.get(5),
            size_bytes: r.get::<_, i64>(6).max(0) as u64,
            data: r.get(7),
        }))
    }

    async fn list_attachment_meta(&self, message_id: &str) -> AppResult<Vec<AttachmentMeta>> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let rows = conn
            .query(
                "SELECT id, filename, content_type, size_bytes
                 FROM attachments
                 WHERE mailbox_id = $1 AND message_id = $2
                 ORDER BY part_id ASC, id ASC",
                &[&mb, &message_id],
            )
            .await
            .map_err(pg_err)?;
        Ok(rows
            .into_iter()
            .map(|r| AttachmentMeta {
                id: r.get(0),
                filename: r.get(1),
                content_type: r.get(2),
                size_bytes: r.get::<_, i64>(3).max(0) as u64,
            })
            .collect())
    }

    async fn list_threads(&self, query: &MessageListQuery) -> AppResult<ThreadListPage> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let max_results = if query.max_results == 0 {
            100
        } else {
            query.max_results.min(500)
        };
        let offset = parse_offset_token(query.page_token.as_deref())?;

        let parsed_q = match query.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(raw) => Some(parse_query_with_labels(&conn, mb, raw).await?),
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
            required_labels.push(
                resolve_existing_label_id(&conn, mb, l)
                    .await?
                    .unwrap_or_else(|| l.clone()),
            );
        }

        let visible_msgs =
            load_all_messages_filtered(&conn, mb, &[], effective_include_spam_trash, None).await?;

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
    }

    async fn get_thread(&self, thread_id: &str) -> AppResult<Option<StoredThreadDetail>> {
        let conn = self.ready_conn().await?;
        load_thread_detail_client(&conn, &self.mailbox_id, thread_id).await
    }

    async fn modify_thread_labels(
        &self,
        thread_id: &str,
        add_labels: &[String],
        remove_labels: &[String],
    ) -> AppResult<StoredThreadDetail> {
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let mb = self.mailbox_id.as_str();

        let rows = tx
            .query(
                "SELECT id FROM messages WHERE mailbox_id = $1 AND thread_id = $2 ORDER BY internal_date_ms ASC, id ASC",
                &[&mb, &thread_id],
            )
            .await
            .map_err(pg_err)?;
        let msg_ids: Vec<String> = rows.into_iter().map(|r| r.get(0)).collect();
        if msg_ids.is_empty() {
            return Err(AppError::NotFound(format!("Thread not found: {thread_id}")));
        }

        let mut resolved_add = Vec::with_capacity(add_labels.len());
        for l in add_labels {
            let lid = resolve_existing_label_id(&tx, mb, l)
                .await?
                .ok_or_else(|| AppError::BadRequest(format!("Label not found: {l}")))?;
            resolved_add.push(lid);
        }
        let mut resolved_remove = Vec::with_capacity(remove_labels.len());
        for l in remove_labels {
            if let Some(lid) = resolve_existing_label_id(&tx, mb, l).await? {
                resolved_remove.push(lid);
            }
        }

        for mid in &msg_ids {
            modify_message_labels_resolved_tx(&tx, mb, mid, &resolved_add, &resolved_remove)
                .await?;
        }

        let detail = load_thread_detail_client(&tx, mb, thread_id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Thread not found: {thread_id}")))?;
        tx.commit().await.map_err(pg_err)?;
        Ok(detail)
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
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let mb = self.mailbox_id.as_str();

        let rows = tx
            .query(
                "SELECT id FROM messages WHERE mailbox_id = $1 AND thread_id = $2",
                &[&mb, &thread_id],
            )
            .await
            .map_err(pg_err)?;
        let msg_ids: Vec<String> = rows.into_iter().map(|r| r.get(0)).collect();
        if msg_ids.is_empty() {
            return Ok(false);
        }
        for mid in &msg_ids {
            delete_message_tx(&tx, mb, mid).await?;
        }
        tx.execute(
            "DELETE FROM thread_annotations WHERE mailbox_id = $1 AND thread_id = $2",
            &[&mb, &thread_id],
        )
        .await
        .map_err(pg_err)?;
        tx.commit().await.map_err(pg_err)?;
        Ok(true)
    }

    async fn list_labels(&self) -> AppResult<Vec<StoredLabel>> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let rows = conn
            .query(
                "SELECT
                    l.id, l.name, l.label_type, l.message_list_visibility, l.label_list_visibility,
                    l.color_text, l.color_background, l.uid_validity, l.uid_next, l.upstream_label_id,
                    (SELECT COUNT(*) FROM message_labels ml
                     WHERE ml.mailbox_id = l.mailbox_id AND ml.label_id = l.id) AS messages_total,
                    (SELECT COUNT(*) FROM message_labels ml
                     INNER JOIN message_labels mu
                        ON mu.mailbox_id = ml.mailbox_id AND mu.message_id = ml.message_id AND mu.label_id = $2
                     WHERE ml.mailbox_id = l.mailbox_id AND ml.label_id = l.id) AS messages_unread,
                    (SELECT COUNT(DISTINCT m.thread_id) FROM message_labels ml
                     INNER JOIN messages m
                        ON m.mailbox_id = ml.mailbox_id AND m.id = ml.message_id
                     WHERE ml.mailbox_id = l.mailbox_id AND ml.label_id = l.id) AS threads_total,
                    (SELECT COUNT(DISTINCT m.thread_id) FROM message_labels ml
                     INNER JOIN messages m
                        ON m.mailbox_id = ml.mailbox_id AND m.id = ml.message_id
                     INNER JOIN message_labels mu
                        ON mu.mailbox_id = ml.mailbox_id AND mu.message_id = ml.message_id AND mu.label_id = $2
                     WHERE ml.mailbox_id = l.mailbox_id AND ml.label_id = l.id) AS threads_unread
                 FROM labels l
                 WHERE l.mailbox_id = $1
                 ORDER BY CASE WHEN l.label_type = 'system' THEN 0 ELSE 1 END, l.name ASC",
                &[&mb, &LABEL_UNREAD],
            )
            .await
            .map_err(pg_err)?;
        Ok(rows.iter().map(label_from_row).collect())
    }

    async fn get_label(&self, id: &str) -> AppResult<Option<StoredLabel>> {
        let conn = self.ready_conn().await?;
        load_label_with_counts(&conn, &self.mailbox_id, id).await
    }

    async fn create_label(&self, input: NewLabelInput) -> AppResult<StoredLabel> {
        let name = input.name.trim().to_string();
        if name.is_empty() {
            return Err(AppError::BadRequest("Label name cannot be empty".into()));
        }
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let mb = self.mailbox_id.as_str();

        let conflict = tx
            .query_opt(
                "SELECT id FROM labels WHERE mailbox_id = $1 AND (LOWER(name) = LOWER($2) OR id = $2)",
                &[&mb, &name],
            )
            .await
            .map_err(pg_err)?;
        if conflict.is_some() {
            return Err(AppError::Conflict(format!("Label already exists: {name}")));
        }

        let id = format!("Label_{}", &new_hex_id()[..8]);
        let uv = alloc_uid_validity(&tx, mb).await? as i64;
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
             ) VALUES ($1, $2, $3, 'user', $4, $5, $6, $7, $8, 1, $9)",
            &[
                &mb,
                &id,
                &name,
                &msg_vis,
                &lbl_vis,
                &color_text,
                &color_bg,
                &uv,
                &input.upstream_label_id,
            ],
        )
        .await
        .map_err(pg_err)?;

        let created = load_label_with_counts(&tx, mb, &id)
            .await?
            .ok_or_else(|| AppError::Storage("Failed to load created label".into()))?;
        tx.commit().await.map_err(pg_err)?;
        Ok(created)
    }

    async fn update_label(
        &self,
        id: &str,
        input: UpdateLabelInput,
        full_replace: bool,
    ) -> AppResult<StoredLabel> {
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let mb = self.mailbox_id.as_str();

        let existing = load_label_with_counts(&tx, mb, id)
            .await?
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
                let conflict = tx
                    .query_opt(
                        "SELECT id FROM labels WHERE mailbox_id = $1 AND (LOWER(name) = LOWER($2) OR id = $2) AND id != $3",
                        &[&mb, &trimmed, &id],
                    )
                    .await
                    .map_err(pg_err)?;
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
                input
                    .message_list_visibility
                    .or(existing.message_list_visibility),
                input
                    .label_list_visibility
                    .or(existing.label_list_visibility),
                input.color.or(existing.color),
            )
        };

        let (color_text, color_bg) = match color {
            Some(ref c) => (
                Some(c.text_color.as_str()),
                Some(c.background_color.as_str()),
            ),
            None => (None, None),
        };

        tx.execute(
            "UPDATE labels
             SET name = $1, message_list_visibility = $2, label_list_visibility = $3,
                 color_text = $4, color_background = $5
             WHERE mailbox_id = $6 AND id = $7",
            &[
                &new_name,
                &msg_vis,
                &lbl_vis,
                &color_text,
                &color_bg,
                &mb,
                &id,
            ],
        )
        .await
        .map_err(pg_err)?;

        let updated = load_label_with_counts(&tx, mb, id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Label not found: {id}")))?;
        tx.commit().await.map_err(pg_err)?;
        Ok(updated)
    }

    async fn delete_label(&self, id: &str) -> AppResult<()> {
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let mb = self.mailbox_id.as_str();

        let existing = load_label_with_counts(&tx, mb, id)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Label not found: {id}")))?;
        if existing.label_type == "system" || is_system_label(&existing.id) {
            return Err(AppError::BadRequest(format!(
                "Cannot delete system label: {id}"
            )));
        }

        let rows = tx
            .query(
                "SELECT m.id, m.thread_id, m.upstream_gmail_id
                 FROM message_labels ml
                 INNER JOIN messages m ON m.mailbox_id = ml.mailbox_id AND m.id = ml.message_id
                 WHERE ml.mailbox_id = $1 AND ml.label_id = $2",
                &[&mb, &id],
            )
            .await
            .map_err(pg_err)?;
        let affected: Vec<(String, String, Option<String>)> = rows
            .into_iter()
            .map(|r| (r.get(0), r.get(1), r.get(2)))
            .collect();

        let id_owned = id.to_string();
        for (mid, tid, up_id) in affected {
            let ctx = load_message_labels(&tx, mb, &mid).await?;
            let hid = bump_history_id(&tx, mb).await?;
            let hid_i64 = hid as i64;
            tx.execute(
                "UPDATE messages SET history_id = $1 WHERE mailbox_id = $2 AND id = $3",
                &[&hid_i64, &mb, &mid],
            )
            .await
            .map_err(pg_err)?;
            record_history_event(
                &tx,
                mb,
                hid,
                HistoryEventKind::LabelRemoved,
                &mid,
                &tid,
                std::slice::from_ref(&id_owned),
                &ctx,
                up_id.as_deref(),
            )
            .await?;
        }

        tx.execute(
            "DELETE FROM labels WHERE mailbox_id = $1 AND id = $2",
            &[&mb, &id],
        )
        .await
        .map_err(pg_err)?;
        tx.commit().await.map_err(pg_err)?;
        Ok(())
    }

    async fn upsert_upstream_label(&self, input: NewLabelInput) -> AppResult<StoredLabel> {
        let name = input.name.trim().to_string();
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let mb = self.mailbox_id.as_str();

        // 1. Check upstream_label_id
        if let Some(ref ulid) = input.upstream_label_id {
            let trimmed_ulid = ulid.trim();
            if !trimmed_ulid.is_empty() {
                if is_system_label(trimmed_ulid)
                    && let Some(sys) = load_label_with_counts(&tx, mb, trimmed_ulid).await?
                {
                    tx.commit().await.map_err(pg_err)?;
                    return Ok(sys);
                }
                if let Some(row) = tx
                    .query_opt(
                        "SELECT id FROM labels WHERE mailbox_id = $1 AND upstream_label_id = $2",
                        &[&mb, &trimmed_ulid],
                    )
                    .await
                    .map_err(pg_err)?
                {
                    let existing_id: String = row.get(0);
                    if !name.is_empty() {
                        tx.execute(
                            "UPDATE labels SET name = $1 WHERE mailbox_id = $2 AND id = $3 AND label_type = 'user'",
                            &[&name, &mb, &existing_id],
                        )
                        .await
                        .map_err(pg_err)?;
                    }
                    let lbl = load_label_with_counts(&tx, mb, &existing_id)
                        .await?
                        .ok_or_else(|| AppError::Storage("Failed to load upstream label".into()))?;
                    tx.commit().await.map_err(pg_err)?;
                    return Ok(lbl);
                }
            }
        }

        // 2. Check by existing id or case-insensitive name
        if !name.is_empty()
            && let Some(existing_id) = resolve_existing_label_id(&tx, mb, &name).await?
        {
            let existing = load_label_with_counts(&tx, mb, &existing_id)
                .await?
                .ok_or_else(|| AppError::Storage("Failed to load existing label".into()))?;
            if existing.label_type == "system" {
                tx.commit().await.map_err(pg_err)?;
                return Ok(existing);
            }
            if input.upstream_label_id.is_some() && existing.upstream_label_id.is_none() {
                tx.execute(
                    "UPDATE labels SET upstream_label_id = $1 WHERE mailbox_id = $2 AND id = $3",
                    &[&input.upstream_label_id, &mb, &existing_id],
                )
                .await
                .map_err(pg_err)?;
            }
            let updated = load_label_with_counts(&tx, mb, &existing_id)
                .await?
                .ok_or_else(|| AppError::Storage("Failed to load updated label".into()))?;
            tx.commit().await.map_err(pg_err)?;
            return Ok(updated);
        }

        if name.is_empty() {
            return Err(AppError::BadRequest("Label name cannot be empty".into()));
        }

        // 3. Create new user label
        let id = format!("Label_{}", &new_hex_id()[..8]);
        let uv = alloc_uid_validity(&tx, mb).await? as i64;
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
             ) VALUES ($1, $2, $3, 'user', $4, $5, $6, $7, $8, 1, $9)",
            &[
                &mb,
                &id,
                &name,
                &msg_vis,
                &lbl_vis,
                &color_text,
                &color_bg,
                &uv,
                &input.upstream_label_id,
            ],
        )
        .await
        .map_err(pg_err)?;
        let created = load_label_with_counts(&tx, mb, &id)
            .await?
            .ok_or_else(|| AppError::Storage("Failed to load created upstream label".into()))?;
        tx.commit().await.map_err(pg_err)?;
        Ok(created)
    }

    async fn list_drafts(&self, query: &MessageListQuery) -> AppResult<DraftListPage> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let max_results = if query.max_results == 0 {
            100
        } else {
            query.max_results.min(500)
        };
        let offset = parse_offset_token(query.page_token.as_deref())?;
        let parsed_q = match query.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(raw) => Some(parse_query_with_labels(&conn, mb, raw).await?),
            None => None,
        };
        let effective_include_spam_trash =
            query.include_spam_trash || parsed_q.as_ref().is_some_and(|pq| pq.include_spam_trash);

        let rows = conn
            .query(
                "SELECT d.id AS draft_id, d.updated_at_ms, m.*
                 FROM drafts d
                 INNER JOIN messages m ON m.mailbox_id = d.mailbox_id AND m.id = d.message_id
                 WHERE d.mailbox_id = $1
                 ORDER BY d.updated_at_ms DESC, d.id DESC",
                &[&mb],
            )
            .await
            .map_err(pg_err)?;

        let raw: Vec<(String, i64, StoredMessage)> = rows
            .iter()
            .map(|r| {
                (
                    r.get::<_, String>("draft_id"),
                    r.get::<_, i64>("updated_at_ms"),
                    message_from_row(r),
                )
            })
            .collect();

        let msg_ids: Vec<String> = raw.iter().map(|(_, _, m)| m.id.clone()).collect();
        let mut label_map = load_labels_for_messages(&conn, mb, &msg_ids).await?;

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
                updated_at: DateTime::from_timestamp_millis(updated_ms).unwrap_or_else(Utc::now),
            });
        }

        let total = drafts.len();
        let page: Vec<StoredDraft> = drafts.into_iter().skip(offset).take(max_results).collect();
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
    }

    async fn get_draft(&self, id: &str) -> AppResult<Option<StoredDraft>> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let Some(row) = conn
            .query_opt(
                "SELECT message_id, updated_at_ms FROM drafts WHERE mailbox_id = $1 AND id = $2",
                &[&mb, &id],
            )
            .await
            .map_err(pg_err)?
        else {
            return Ok(None);
        };
        let message_id: String = row.get(0);
        let updated_ms: i64 = row.get(1);
        let Some(message) = load_message_by_id(&conn, mb, &message_id).await? else {
            return Ok(None);
        };
        Ok(Some(StoredDraft {
            id: id.to_string(),
            message,
            updated_at: DateTime::from_timestamp_millis(updated_ms).unwrap_or_else(Utc::now),
        }))
    }

    async fn create_draft(&self, mut message: NewMessageInput) -> AppResult<StoredDraft> {
        if !message.label_ids.iter().any(|l| l == LABEL_DRAFT) {
            message.label_ids.push(LABEL_DRAFT.to_string());
        }
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let mb = self.mailbox_id.as_str();

        let stored_msg = insert_message_tx(&tx, mb, message).await?;
        let draft_id = format!("r{}", new_hex_id());
        let now = Utc::now();
        let now_ms = now.timestamp_millis();
        tx.execute(
            "INSERT INTO drafts (mailbox_id, id, message_id, updated_at_ms) VALUES ($1, $2, $3, $4)",
            &[&mb, &draft_id, &stored_msg.id, &now_ms],
        )
        .await
        .map_err(pg_err)?;
        tx.commit().await.map_err(pg_err)?;
        Ok(StoredDraft {
            id: draft_id,
            message: stored_msg,
            updated_at: now,
        })
    }

    async fn update_draft(
        &self,
        draft_id: &str,
        mut message: NewMessageInput,
    ) -> AppResult<StoredDraft> {
        if !message.label_ids.iter().any(|l| l == LABEL_DRAFT) {
            message.label_ids.push(LABEL_DRAFT.to_string());
        }
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let mb = self.mailbox_id.as_str();

        let old_msg_id: String = tx
            .query_opt(
                "SELECT message_id FROM drafts WHERE mailbox_id = $1 AND id = $2",
                &[&mb, &draft_id],
            )
            .await
            .map_err(pg_err)?
            .ok_or_else(|| AppError::NotFound(format!("Draft not found: {draft_id}")))?
            .get(0);

        let new_msg = insert_message_tx(&tx, mb, message).await?;
        let now = Utc::now();
        let now_ms = now.timestamp_millis();
        tx.execute(
            "UPDATE drafts SET message_id = $1, updated_at_ms = $2 WHERE mailbox_id = $3 AND id = $4",
            &[&new_msg.id, &now_ms, &mb, &draft_id],
        )
        .await
        .map_err(pg_err)?;
        delete_message_tx(&tx, mb, &old_msg_id).await?;

        tx.commit().await.map_err(pg_err)?;
        Ok(StoredDraft {
            id: draft_id.to_string(),
            message: new_msg,
            updated_at: now,
        })
    }

    async fn delete_draft(&self, draft_id: &str) -> AppResult<bool> {
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let mb = self.mailbox_id.as_str();

        let Some(row) = tx
            .query_opt(
                "SELECT message_id FROM drafts WHERE mailbox_id = $1 AND id = $2",
                &[&mb, &draft_id],
            )
            .await
            .map_err(pg_err)?
        else {
            return Ok(false);
        };
        let msg_id: String = row.get(0);
        tx.execute(
            "DELETE FROM drafts WHERE mailbox_id = $1 AND id = $2",
            &[&mb, &draft_id],
        )
        .await
        .map_err(pg_err)?;
        delete_message_tx(&tx, mb, &msg_id).await?;
        tx.commit().await.map_err(pg_err)?;
        Ok(true)
    }

    async fn search_messages_ai(&self, query: &AiSearchQuery) -> AppResult<AiMessagePage> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
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
            resolved_labels.push(
                resolve_existing_label_id(&conn, mb, l)
                    .await?
                    .unwrap_or_else(|| l.clone()),
            );
        }
        let explicit_spam_trash = resolved_labels
            .iter()
            .any(|l| l == LABEL_TRASH || l == LABEL_SPAM);
        let effective_include_spam_trash = query.include_spam_trash || explicit_spam_trash;

        let mut sql = String::from("SELECT m.* FROM messages m");
        let mut bind_values: Vec<Box<dyn ToSql + Sync + Send>> = vec![Box::new(mb.to_string())];
        let mut where_clauses: Vec<String> = vec!["m.mailbox_id = $1".to_string()];

        if let Some(ref raw_q) = query.q {
            let trimmed = raw_q.trim();
            if !trimmed.is_empty() {
                bind_values.push(Box::new(trimmed.to_string()));
                let p_q = bind_values.len();
                bind_values.push(Box::new(escape_like_pattern(trimmed)));
                let p_like = bind_values.len();
                where_clauses.push(format!(
                    "((plainto_tsquery('english', ${p_q}) <> ''::tsquery AND m.search_tsv @@ plainto_tsquery('english', ${p_q})) \
                      OR m.subject ILIKE ${p_like} ESCAPE '\\' \
                      OR m.from_addr ILIKE ${p_like} ESCAPE '\\' \
                      OR m.to_addrs_json ILIKE ${p_like} ESCAPE '\\' \
                      OR m.cc_addrs_json ILIKE ${p_like} ESCAPE '\\' \
                      OR m.text_body ILIKE ${p_like} ESCAPE '\\' \
                      OR m.snippet ILIKE ${p_like} ESCAPE '\\')"
                ));
            }
        }

        if !effective_include_spam_trash {
            bind_values.push(Box::new(LABEL_TRASH.to_string()));
            let p1 = bind_values.len();
            bind_values.push(Box::new(LABEL_SPAM.to_string()));
            let p2 = bind_values.len();
            where_clauses.push(format!(
                "NOT EXISTS (SELECT 1 FROM message_labels ml_ex WHERE ml_ex.mailbox_id = m.mailbox_id AND ml_ex.message_id = m.id AND ml_ex.label_id IN (${p1}, ${p2}))"
            ));
        }

        for lid in &resolved_labels {
            bind_values.push(Box::new(lid.clone()));
            let p = bind_values.len();
            where_clauses.push(format!(
                "EXISTS (SELECT 1 FROM message_labels ml_in WHERE ml_in.mailbox_id = m.mailbox_id AND ml_in.message_id = m.id AND ml_in.label_id = ${p})"
            ));
        }

        if let Some(want_unread) = query.unread {
            bind_values.push(Box::new(LABEL_UNREAD.to_string()));
            let p = bind_values.len();
            if want_unread {
                where_clauses.push(format!(
                    "EXISTS (SELECT 1 FROM message_labels ml_unr WHERE ml_unr.mailbox_id = m.mailbox_id AND ml_unr.message_id = m.id AND ml_unr.label_id = ${p})"
                ));
            } else {
                where_clauses.push(format!(
                    "NOT EXISTS (SELECT 1 FROM message_labels ml_unr WHERE ml_unr.mailbox_id = m.mailbox_id AND ml_unr.message_id = m.id AND ml_unr.label_id = ${p})"
                ));
            }
        }

        if let Some(ref tid) = query.thread_id
            && !tid.trim().is_empty()
        {
            bind_values.push(Box::new(tid.trim().to_string()));
            let p = bind_values.len();
            where_clauses.push(format!("m.thread_id = ${p}"));
        }

        if let Some(ref from_filter) = query.from
            && !from_filter.trim().is_empty()
        {
            bind_values.push(Box::new(escape_like_pattern(from_filter.trim())));
            let p = bind_values.len();
            where_clauses.push(format!("m.from_addr ILIKE ${p} ESCAPE '\\'"));
        }

        if let Some(ref to_filter) = query.to
            && !to_filter.trim().is_empty()
        {
            bind_values.push(Box::new(escape_like_pattern(to_filter.trim())));
            let p = bind_values.len();
            where_clauses.push(format!("m.to_addrs_json ILIKE ${p} ESCAPE '\\'"));
        }

        if let Some(after) = query.after {
            bind_values.push(Box::new(after.timestamp_millis()));
            let p = bind_values.len();
            where_clauses.push(format!("m.internal_date_ms >= ${p}"));
        }

        if let Some(before) = query.before {
            bind_values.push(Box::new(before.timestamp_millis()));
            let p = bind_values.len();
            where_clauses.push(format!("m.internal_date_ms <= ${p}"));
        }

        if let Some(has_att) = query.has_attachment {
            bind_values.push(Box::new(has_att));
            let p = bind_values.len();
            where_clauses.push(format!("m.has_attachments = ${p}"));
        }

        if let Some((cursor_ts, cursor_id)) = cursor {
            bind_values.push(Box::new(cursor_ts));
            let p_ts = bind_values.len();
            bind_values.push(Box::new(cursor_id));
            let p_id = bind_values.len();
            where_clauses.push(format!(
                "(m.internal_date_ms < ${p_ts} OR (m.internal_date_ms = ${p_ts} AND m.id < ${p_id}))"
            ));
        }

        sql.push_str(" WHERE ");
        sql.push_str(&where_clauses.join(" AND "));
        bind_values.push(Box::new((limit + 1) as i64));
        let p_lim = bind_values.len();
        sql.push_str(&format!(
            " ORDER BY m.internal_date_ms DESC, m.id DESC LIMIT ${p_lim}"
        ));

        let param_refs: Vec<&(dyn ToSql + Sync)> = bind_values
            .iter()
            .map(|b| b.as_ref() as &(dyn ToSql + Sync))
            .collect();
        let rows = conn.query(&sql, &param_refs).await.map_err(pg_err)?;
        let mut messages: Vec<StoredMessage> = rows.iter().map(message_from_row).collect();

        let has_more = messages.len() > limit;
        if has_more {
            messages.truncate(limit);
        }

        let ids: Vec<String> = messages.iter().map(|m| m.id.clone()).collect();
        let mut label_map = load_labels_for_messages(&conn, mb, &ids).await?;
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
    }

    async fn list_thread_summaries(&self, query: &AiThreadQuery) -> AppResult<AiThreadPage> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
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
                resolve_existing_label_id(&conn, mb, l)
                    .await?
                    .unwrap_or_else(|| l.to_string()),
            ),
            _ => None,
        };
        let explicit_spam_trash = resolved_label
            .as_deref()
            .is_some_and(|l| l == LABEL_TRASH || l == LABEL_SPAM);
        let effective_include_spam_trash = query.include_spam_trash || explicit_spam_trash;

        let fts_matching_threads: Option<HashSet<String>> = match query.q.as_deref() {
            Some(raw_q) if !raw_q.trim().is_empty() => {
                let trimmed = raw_q.trim();
                let like_pat = escape_like_pattern(trimmed);
                let rows = conn
                    .query(
                        "SELECT DISTINCT thread_id FROM messages
                         WHERE mailbox_id = $1
                           AND ((plainto_tsquery('english', $2) <> ''::tsquery AND search_tsv @@ plainto_tsquery('english', $2))
                                OR subject ILIKE $3 ESCAPE '\\'
                                OR from_addr ILIKE $3 ESCAPE '\\'
                                OR to_addrs_json ILIKE $3 ESCAPE '\\'
                                OR cc_addrs_json ILIKE $3 ESCAPE '\\'
                                OR text_body ILIKE $3 ESCAPE '\\'
                                OR snippet ILIKE $3 ESCAPE '\\')",
                        &[&mb, &trimmed, &like_pat],
                    )
                    .await
                    .map_err(pg_err)?;
                Some(rows.into_iter().map(|r| r.get(0)).collect())
            }
            _ => None,
        };

        let filtered_annotations: Option<HashMap<String, ThreadAnnotation>> = if query
            .needs_reply
            .is_some()
            || query.waiting_on.is_some()
        {
            let map =
                load_thread_annotations_filtered(&conn, mb, query.needs_reply, query.waiting_on)
                    .await?;
            if map.is_empty() {
                return Ok(AiThreadPage {
                    threads: Vec::new(),
                    next_cursor: None,
                    has_more: false,
                });
            }
            Some(map)
        } else {
            None
        };

        let visible_msgs =
            load_all_messages_filtered(&conn, mb, &[], effective_include_spam_trash, None).await?;

        let mut by_thread: BTreeMap<String, Vec<StoredMessage>> = BTreeMap::new();
        for msg in visible_msgs {
            by_thread
                .entry(msg.thread_id.clone())
                .or_default()
                .push(msg);
        }

        let mut summaries: Vec<(i64, ThreadSummary)> = Vec::new();
        for (tid, mut msgs) in by_thread {
            if let Some(ref fts_set) = fts_matching_threads
                && !fts_set.contains(&tid)
            {
                continue;
            }
            let annotation = if let Some(ref ann_map) = filtered_annotations {
                let Some(ann) = ann_map.get(&tid) else {
                    continue;
                };
                Some(ann.clone())
            } else {
                None
            };
            msgs.sort_by(|a, b| {
                a.internal_date_ms
                    .cmp(&b.internal_date_ms)
                    .then_with(|| a.id.cmp(&b.id))
            });
            let summary = build_thread_summary(&tid, &msgs, annotation);
            if let Some(ref req_label) = resolved_label
                && !summary.labels.contains(req_label)
            {
                continue;
            }
            if query.unread_only && !summary.unread {
                continue;
            }
            let max_ts = msgs.iter().map(|m| m.internal_date_ms).max().unwrap_or(0);
            if let Some((cursor_ts, ref cursor_id)) = cursor
                && !(max_ts < cursor_ts
                    || (max_ts == cursor_ts && tid.as_str() < cursor_id.as_str()))
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
        let mut threads: Vec<ThreadSummary> = summaries.into_iter().map(|(_, s)| s).collect();
        if filtered_annotations.is_none() && !threads.is_empty() {
            let ids: Vec<String> = threads.iter().map(|t| t.id.clone()).collect();
            let mut ann_map = load_thread_annotations_for_ids(&conn, mb, &ids).await?;
            for thread in &mut threads {
                thread.annotation = ann_map.remove(&thread.id);
            }
        }

        Ok(AiThreadPage {
            threads,
            next_cursor,
            has_more,
        })
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

    async fn get_thread_annotation(&self, thread_id: &str) -> AppResult<Option<ThreadAnnotation>> {
        let conn = self.ready_conn().await?;
        load_thread_annotation_client(&conn, &self.mailbox_id, thread_id, false).await
    }

    async fn upsert_thread_annotation(
        &self,
        thread_id: &str,
        annotation: &ThreadAnnotation,
    ) -> AppResult<ThreadAnnotation> {
        let conn = self.ready_conn().await?;
        let mut stored = annotation.clone();
        stored.thread_id = thread_id.to_string();
        stored.due_at = stored.due_at.map(truncate_to_millis);
        stored.updated_at = truncate_to_millis(stored.updated_at);
        upsert_thread_annotation_client(&conn, &self.mailbox_id, &stored).await?;
        Ok(stored)
    }

    async fn patch_thread_annotation(
        &self,
        thread_id: &str,
        patch: &ThreadAnnotationPatch,
        updated_by: Option<&str>,
    ) -> AppResult<ThreadAnnotation> {
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let existing =
            load_thread_annotation_client(&tx, &self.mailbox_id, thread_id, true).await?;
        let merged =
            apply_thread_annotation_patch(existing, thread_id, patch, updated_by, Utc::now());
        upsert_thread_annotation_client(&tx, &self.mailbox_id, &merged).await?;
        tx.commit().await.map_err(pg_err)?;
        Ok(merged)
    }

    async fn delete_thread_annotation(&self, thread_id: &str) -> AppResult<()> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        conn.execute(
            "DELETE FROM thread_annotations WHERE mailbox_id = $1 AND thread_id = $2",
            &[&mb, &thread_id],
        )
        .await
        .map_err(pg_err)?;
        Ok(())
    }

    async fn find_message_by_resend_id(&self, resend_id: &str) -> AppResult<Option<StoredMessage>> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let Some(row) = conn
            .query_opt(
                "SELECT id FROM messages WHERE mailbox_id = $1 AND resend_id = $2 LIMIT 1",
                &[&mb, &resend_id],
            )
            .await
            .map_err(pg_err)?
        else {
            return Ok(None);
        };
        let mid: String = row.get(0);
        load_message_by_id(&conn, mb, &mid).await
    }

    async fn find_message_by_rfc_message_id(
        &self,
        rfc822_message_id: &str,
    ) -> AppResult<Option<StoredMessage>> {
        let Some(norm) = normalize_rfc_message_id(rfc822_message_id) else {
            return Ok(None);
        };
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let Some(row) = conn
            .query_opt(
                "SELECT id FROM messages WHERE mailbox_id = $1 AND rfc822_message_id_norm = $2 LIMIT 1",
                &[&mb, &norm],
            )
            .await
            .map_err(pg_err)?
        else {
            return Ok(None);
        };
        let mid: String = row.get(0);
        load_message_by_id(&conn, mb, &mid).await
    }

    async fn record_delivery_status(
        &self,
        resend_id: &str,
        status: &str,
    ) -> AppResult<Option<StoredMessage>> {
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let mb = self.mailbox_id.as_str();

        let Some(row) = tx
            .query_opt(
                "SELECT id FROM messages WHERE mailbox_id = $1 AND resend_id = $2 LIMIT 1",
                &[&mb, &resend_id],
            )
            .await
            .map_err(pg_err)?
        else {
            return Ok(None);
        };
        let mid: String = row.get(0);
        tx.execute(
            "UPDATE messages SET delivery_status = $1 WHERE mailbox_id = $2 AND id = $3",
            &[&status, &mb, &mid],
        )
        .await
        .map_err(pg_err)?;
        let msg = load_message_by_id(&tx, mb, &mid).await?;
        tx.commit().await.map_err(pg_err)?;
        Ok(msg)
    }

    async fn imap_list_mailboxes(&self) -> AppResult<Vec<ImapMailboxInfo>> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
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
            mailboxes.push(load_imap_mailbox_info_resolved(&conn, mb, item).await?);
        }

        let rows = conn
            .query(
                "SELECT id, name FROM labels WHERE mailbox_id = $1 AND label_type = 'user' ORDER BY name ASC",
                &[&mb],
            )
            .await
            .map_err(pg_err)?;
        for row in rows {
            let item = ResolvedMailbox::Label {
                id: row.get(0),
                name: row.get(1),
                special_use: None,
            };
            mailboxes.push(load_imap_mailbox_info_resolved(&conn, mb, &item).await?);
        }
        Ok(mailboxes)
    }

    async fn imap_mailbox_info(&self, mailbox_name: &str) -> AppResult<Option<ImapMailboxInfo>> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let Some(resolved) = resolve_imap_mailbox(&conn, mb, mailbox_name).await? else {
            return Ok(None);
        };
        Ok(Some(
            load_imap_mailbox_info_resolved(&conn, mb, &resolved).await?,
        ))
    }

    async fn imap_list_messages(&self, mailbox_name: &str) -> AppResult<Vec<ImapMessageEntry>> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let resolved = resolve_imap_mailbox(&conn, mb, mailbox_name)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Mailbox not found: {mailbox_name}")))?;
        load_imap_messages_resolved(&conn, mb, &resolved).await
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
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let mb = self.mailbox_id.as_str();

        let Some(old_msg) = load_message_by_id(&tx, mb, message_id).await? else {
            return Err(AppError::NotFound(format!(
                "Message not found: {message_id}"
            )));
        };
        let flags_changed = old_msg.is_answered != is_answered || old_msg.is_deleted != is_deleted;

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
            "UPDATE messages SET is_answered = $1, is_deleted = $2 WHERE mailbox_id = $3 AND id = $4",
            &[&is_answered, &is_deleted, &mb, &message_id],
        )
        .await
        .map_err(pg_err)?;

        let mut msg = modify_message_labels_resolved_tx(&tx, mb, message_id, &add, &rem).await?;
        if flags_changed && msg.history_id == old_msg.history_id {
            let new_hid = bump_history_id(&tx, mb).await?;
            let new_hid_i64 = new_hid as i64;
            tx.execute(
                "UPDATE messages SET history_id = $1 WHERE mailbox_id = $2 AND id = $3",
                &[&new_hid_i64, &mb, &message_id],
            )
            .await
            .map_err(pg_err)?;
            msg.history_id = new_hid;
        }
        tx.commit().await.map_err(pg_err)?;
        Ok(msg)
    }

    async fn imap_expunge(&self, mailbox_name: &str) -> AppResult<Vec<u32>> {
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let mb = self.mailbox_id.as_str();

        let resolved = resolve_imap_mailbox(&tx, mb, mailbox_name)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Mailbox not found: {mailbox_name}")))?;
        let entries = load_imap_messages_resolved(&tx, mb, &resolved).await?;

        let mut expunged_seqs = Vec::new();
        for entry in entries {
            if !entry.is_deleted {
                continue;
            }
            expunged_seqs.push(entry.seq);
            match &resolved {
                ResolvedMailbox::Label { id, .. } if id == LABEL_TRASH => {
                    delete_message_tx(&tx, mb, &entry.message_id).await?;
                }
                ResolvedMailbox::AllMail => {
                    tx.execute(
                        "UPDATE messages SET is_deleted = FALSE WHERE mailbox_id = $1 AND id = $2",
                        &[&mb, &entry.message_id],
                    )
                    .await
                    .map_err(pg_err)?;
                    modify_message_labels_resolved_tx(
                        &tx,
                        mb,
                        &entry.message_id,
                        &[LABEL_TRASH.to_string()],
                        &[LABEL_INBOX.to_string()],
                    )
                    .await?;
                }
                ResolvedMailbox::Label { id, .. } => {
                    tx.execute(
                        "UPDATE messages SET is_deleted = FALSE WHERE mailbox_id = $1 AND id = $2",
                        &[&mb, &entry.message_id],
                    )
                    .await
                    .map_err(pg_err)?;
                    modify_message_labels_resolved_tx(
                        &tx,
                        mb,
                        &entry.message_id,
                        &[LABEL_TRASH.to_string()],
                        std::slice::from_ref(id),
                    )
                    .await?;
                }
            }
        }
        tx.commit().await.map_err(pg_err)?;
        Ok(expunged_seqs)
    }

    async fn imap_copy_or_move(
        &self,
        src_mailbox: &str,
        dst_mailbox: &str,
        message_ids: &[String],
        is_move: bool,
    ) -> AppResult<Vec<(u32, u32)>> {
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let mb = self.mailbox_id.as_str();

        let src = resolve_imap_mailbox(&tx, mb, src_mailbox)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Mailbox not found: {src_mailbox}")))?;
        let dst = resolve_imap_mailbox(&tx, mb, dst_mailbox)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Mailbox not found: {dst_mailbox}")))?;

        let same_mailbox = match (&src, &dst) {
            (ResolvedMailbox::AllMail, ResolvedMailbox::AllMail) => true,
            (ResolvedMailbox::Label { id: a, .. }, ResolvedMailbox::Label { id: b, .. }) => a == b,
            _ => false,
        };

        let src_entries = load_imap_messages_resolved(&tx, mb, &src).await?;
        let src_uid_map: HashMap<String, u32> = src_entries
            .into_iter()
            .map(|e| (e.message_id, e.uid))
            .collect();

        let mut pairs = Vec::new();
        for mid in message_ids {
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

            if is_move
                && !same_mailbox
                && let ResolvedMailbox::Label { id: src_id, .. } = &src
            {
                remove_labels.push(src_id.clone());
            }

            let updated_msg =
                modify_message_labels_resolved_tx(&tx, mb, mid, &add_labels, &remove_labels)
                    .await?;

            let dst_uid = match &dst {
                ResolvedMailbox::AllMail => updated_msg.all_mail_uid,
                ResolvedMailbox::Label { id: dst_id, .. } => tx
                    .query_one(
                        "SELECT imap_uid FROM message_labels WHERE mailbox_id = $1 AND message_id = $2 AND label_id = $3",
                        &[&mb, mid, dst_id],
                    )
                    .await
                    .map_err(pg_err)?
                    .get::<_, i64>(0)
                    .max(1) as u32,
            };

            pairs.push((src_uid, dst_uid));
        }

        tx.commit().await.map_err(pg_err)?;
        Ok(pairs)
    }

    async fn imap_append(
        &self,
        mailbox_name: &str,
        mut input: NewMessageInput,
    ) -> AppResult<(u32, u32, StoredMessage)> {
        if input.source.trim().is_empty() {
            input.source = "imap_append".to_string();
        }
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let mb = self.mailbox_id.as_str();

        let resolved = resolve_imap_mailbox(&tx, mb, mailbox_name)
            .await?
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

        let msg = insert_message_tx(&tx, mb, input).await?;
        let (uid_validity, assigned_uid) = match &resolved {
            ResolvedMailbox::AllMail => {
                let uv: i64 = tx
                    .query_one(
                        "SELECT uid_validity FROM imap_meta WHERE mailbox_id = $1 AND mailbox_name = $2",
                        &[&mb, &ALL_MAIL_MAILBOX],
                    )
                    .await
                    .map_err(pg_err)?
                    .get(0);
                (uv.max(1) as u32, msg.all_mail_uid)
            }
            ResolvedMailbox::Label { id, .. } => {
                let uv: i64 = tx
                    .query_one(
                        "SELECT uid_validity FROM labels WHERE mailbox_id = $1 AND id = $2",
                        &[&mb, id],
                    )
                    .await
                    .map_err(pg_err)?
                    .get(0);
                let uid: i64 = tx
                    .query_one(
                        "SELECT imap_uid FROM message_labels WHERE mailbox_id = $1 AND message_id = $2 AND label_id = $3",
                        &[&mb, &msg.id, id],
                    )
                    .await
                    .map_err(pg_err)?
                    .get(0);
                (uv.max(1) as u32, uid.max(1) as u32)
            }
        };

        tx.commit().await.map_err(pg_err)?;
        Ok((uid_validity, assigned_uid, msg))
    }

    async fn imap_vanished_uids(
        &self,
        mailbox_name: &str,
        since_modseq: u64,
    ) -> AppResult<Vec<u32>> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let resolved = resolve_imap_mailbox(&conn, mb, mailbox_name)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Mailbox not found: {mailbox_name}")))?;
        let mailbox_key = match &resolved {
            ResolvedMailbox::AllMail => ALL_MAIL_MAILBOX.to_string(),
            ResolvedMailbox::Label { id, .. } => id.clone(),
        };
        let since_i64 = since_modseq as i64;
        let rows = conn
            .query(
                "SELECT imap_uid FROM imap_expunged_uids
                 WHERE mailbox_id = $1 AND mailbox_key = $2 AND modseq > $3
                 ORDER BY imap_uid ASC",
                &[&mb, &mailbox_key, &since_i64],
            )
            .await
            .map_err(pg_err)?;
        Ok(rows
            .into_iter()
            .map(|r| r.get::<_, i64>(0).max(1) as u32)
            .collect())
    }

    async fn upsert_synced_message(&self, input: NewMessageInput) -> AppResult<UpsertOutcome> {
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let mb = self.mailbox_id.as_str();

        // 1. Match by upstream_gmail_id
        if let Some(ref ugid) = input.upstream_gmail_id {
            let trimmed_ugid = ugid.trim();
            if !trimmed_ugid.is_empty()
                && let Some(row) = tx
                    .query_opt(
                        "SELECT id FROM messages WHERE mailbox_id = $1 AND upstream_gmail_id = $2 LIMIT 1",
                        &[&mb, &trimmed_ugid],
                    )
                    .await
                    .map_err(pg_err)?
            {
                let existing_id: String = row.get(0);
                let existing = load_message_by_id(&tx, mb, &existing_id)
                    .await?
                    .ok_or_else(|| AppError::Storage("Missing matched upstream message".into()))?;

                let mut desired_labels = Vec::new();
                let mut seen = HashSet::new();
                for raw_l in &input.label_ids {
                    let lid = ensure_label_exists_tx(&tx, mb, raw_l).await?;
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
                        "UPDATE messages SET is_answered = $1, is_deleted = $2 WHERE mailbox_id = $3 AND id = $4",
                        &[&input.is_answered, &input.is_deleted, &mb, &existing_id],
                    )
                    .await
                    .map_err(pg_err)?;
                }

                let updated = if labels_changed {
                    modify_message_labels_resolved_tx(&tx, mb, &existing_id, &to_add, &to_remove)
                        .await?
                } else {
                    load_message_by_id(&tx, mb, &existing_id)
                        .await?
                        .ok_or_else(|| {
                            AppError::Storage("Missing message after sync update".into())
                        })?
                };

                let kind = if labels_changed || flags_changed {
                    UpsertOutcomeKind::Updated
                } else {
                    UpsertOutcomeKind::Deduplicated
                };
                tx.commit().await.map_err(pg_err)?;
                return Ok(UpsertOutcome {
                    kind,
                    message: updated,
                });
            }
        }

        // 2. Match by normalized rfc822_message_id (dedup across Resend <-> Gmail)
        if let Some(norm) = input
            .rfc822_message_id
            .as_deref()
            .and_then(normalize_rfc_message_id)
            && let Some(row) = tx
                .query_opt(
                    "SELECT id FROM messages WHERE mailbox_id = $1 AND rfc822_message_id_norm = $2 LIMIT 1",
                    &[&mb, &norm],
                )
                .await
                .map_err(pg_err)?
        {
            let existing_id: String = row.get(0);
            let existing = load_message_by_id(&tx, mb, &existing_id)
                .await?
                .ok_or_else(|| AppError::Storage("Missing matched rfc822 message".into()))?;

            if existing.upstream_gmail_id.is_none() && input.upstream_gmail_id.is_some() {
                tx.execute(
                    "UPDATE messages SET upstream_gmail_id = $1 WHERE mailbox_id = $2 AND id = $3",
                    &[&input.upstream_gmail_id, &mb, &existing_id],
                )
                .await
                .map_err(pg_err)?;
            }
            if existing.upstream_thread_id.is_none() && input.upstream_thread_id.is_some() {
                tx.execute(
                    "UPDATE messages SET upstream_thread_id = $1 WHERE mailbox_id = $2 AND id = $3",
                    &[&input.upstream_thread_id, &mb, &existing_id],
                )
                .await
                .map_err(pg_err)?;
            }

            let mut to_add = Vec::new();
            for raw_l in &input.label_ids {
                let lid = ensure_label_exists_tx(&tx, mb, raw_l).await?;
                if !existing.label_ids.contains(&lid) && !to_add.contains(&lid) {
                    to_add.push(lid);
                }
            }
            let updated = if !to_add.is_empty() {
                modify_message_labels_resolved_tx(&tx, mb, &existing_id, &to_add, &[]).await?
            } else {
                load_message_by_id(&tx, mb, &existing_id)
                    .await?
                    .ok_or_else(|| AppError::Storage("Missing message after dedup".into()))?
            };
            tx.commit().await.map_err(pg_err)?;
            return Ok(UpsertOutcome {
                kind: UpsertOutcomeKind::Deduplicated,
                message: updated,
            });
        }

        // 3. Insert new message
        let inserted = insert_message_tx(&tx, mb, input).await?;
        tx.commit().await.map_err(pg_err)?;
        Ok(UpsertOutcome {
            kind: UpsertOutcomeKind::Inserted,
            message: inserted,
        })
    }

    async fn find_message_by_upstream_id(
        &self,
        upstream_gmail_id: &str,
    ) -> AppResult<Option<StoredMessage>> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let Some(row) = conn
            .query_opt(
                "SELECT id FROM messages WHERE mailbox_id = $1 AND upstream_gmail_id = $2 LIMIT 1",
                &[&mb, &upstream_gmail_id],
            )
            .await
            .map_err(pg_err)?
        else {
            return Ok(None);
        };
        let mid: String = row.get(0);
        load_message_by_id(&conn, mb, &mid).await
    }

    async fn delete_message_by_upstream_id(
        &self,
        upstream_gmail_id: &str,
    ) -> AppResult<Option<StoredMessage>> {
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let mb = self.mailbox_id.as_str();

        let row = tx
            .query_opt(
                "SELECT id FROM messages WHERE mailbox_id = $1 AND upstream_gmail_id = $2 LIMIT 1",
                &[&mb, &upstream_gmail_id],
            )
            .await
            .map_err(pg_err)?;
        let deleted = match row {
            Some(r) => {
                let mid: String = r.get(0);
                delete_message_tx(&tx, mb, &mid).await?
            }
            None => None,
        };
        tx.commit().await.map_err(pg_err)?;
        Ok(deleted)
    }

    async fn get_sync_state(&self, account_key: &str) -> AppResult<Option<SyncState>> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let row = conn
            .query_opt(
                "SELECT account_key, provider, last_history_id, imap_mailbox, imap_uid_validity,
                        imap_last_uid, last_sync_at_ms, last_full_sync_at_ms, status, last_error,
                        messages_synced, last_pushed_history_id, messages_pushed
                 FROM sync_state WHERE mailbox_id = $1 AND account_key = $2",
                &[&mb, &account_key],
            )
            .await
            .map_err(pg_err)?;
        Ok(row.as_ref().map(sync_state_from_row))
    }

    async fn save_sync_state(&self, state: SyncState) -> AppResult<()> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let uv = state.imap_uid_validity.map(|v| v as i64);
        let last_uid = state.imap_last_uid.map(|v| v as i64);
        let last_sync_ms = state.last_sync_at.map(|dt| dt.timestamp_millis());
        let last_full_ms = state.last_full_sync_at.map(|dt| dt.timestamp_millis());
        let messages_synced = state.messages_synced as i64;
        let last_pushed_hid = state.last_pushed_history_id.map(|v| v as i64);
        let messages_pushed = state.messages_pushed as i64;

        conn.execute(
            "INSERT INTO sync_state (
                mailbox_id, account_key, provider, last_history_id, imap_mailbox, imap_uid_validity,
                imap_last_uid, last_sync_at_ms, last_full_sync_at_ms, status, last_error,
                messages_synced, last_pushed_history_id, messages_pushed
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
             ON CONFLICT (mailbox_id, account_key) DO UPDATE SET
                provider = EXCLUDED.provider,
                last_history_id = EXCLUDED.last_history_id,
                imap_mailbox = EXCLUDED.imap_mailbox,
                imap_uid_validity = EXCLUDED.imap_uid_validity,
                imap_last_uid = EXCLUDED.imap_last_uid,
                last_sync_at_ms = EXCLUDED.last_sync_at_ms,
                last_full_sync_at_ms = EXCLUDED.last_full_sync_at_ms,
                status = EXCLUDED.status,
                last_error = EXCLUDED.last_error,
                messages_synced = EXCLUDED.messages_synced,
                last_pushed_history_id = EXCLUDED.last_pushed_history_id,
                messages_pushed = EXCLUDED.messages_pushed",
            &[
                &mb,
                &state.account_key,
                &state.provider,
                &state.last_history_id,
                &state.imap_mailbox,
                &uv,
                &last_uid,
                &last_sync_ms,
                &last_full_ms,
                &state.status,
                &state.last_error,
                &messages_synced,
                &last_pushed_hid,
                &messages_pushed,
            ],
        )
        .await
        .map_err(pg_err)?;
        Ok(())
    }

    async fn list_sync_states(&self) -> AppResult<Vec<SyncState>> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let rows = conn
            .query(
                "SELECT account_key, provider, last_history_id, imap_mailbox, imap_uid_validity,
                        imap_last_uid, last_sync_at_ms, last_full_sync_at_ms, status, last_error,
                        messages_synced, last_pushed_history_id, messages_pushed
                 FROM sync_state WHERE mailbox_id = $1 ORDER BY account_key ASC",
                &[&mb],
            )
            .await
            .map_err(pg_err)?;
        Ok(rows.iter().map(sync_state_from_row).collect())
    }

    async fn set_watch(&self, watch: WatchSubscription) -> AppResult<WatchSubscription> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let labels_json = serde_json::to_string(&watch.label_ids)
            .map_err(|e| AppError::Storage(format!("JSON encode error: {e}")))?;
        let hid_i64 = watch.history_id as i64;
        conn.execute(
            "INSERT INTO watch_state (mailbox_id, topic_name, label_ids_json, label_filter_behavior, history_id, expiration_ms)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (mailbox_id) DO UPDATE SET
                topic_name = EXCLUDED.topic_name,
                label_ids_json = EXCLUDED.label_ids_json,
                label_filter_behavior = EXCLUDED.label_filter_behavior,
                history_id = EXCLUDED.history_id,
                expiration_ms = EXCLUDED.expiration_ms",
            &[
                &mb,
                &watch.topic_name,
                &labels_json,
                &watch.label_filter_behavior,
                &hid_i64,
                &watch.expiration_ms,
            ],
        )
        .await
        .map_err(pg_err)?;
        Ok(watch)
    }

    async fn get_watch(&self) -> AppResult<Option<WatchSubscription>> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let row = conn
            .query_opt(
                "SELECT topic_name, label_ids_json, label_filter_behavior, history_id, expiration_ms
                 FROM watch_state WHERE mailbox_id = $1",
                &[&mb],
            )
            .await
            .map_err(pg_err)?;
        Ok(row.map(|r| {
            let labels_json: String = r.get(1);
            let label_ids: Vec<String> = serde_json::from_str(&labels_json).unwrap_or_default();
            WatchSubscription {
                topic_name: r.get(0),
                label_ids,
                label_filter_behavior: r.get(2),
                history_id: r.get::<_, i64>(3).max(0) as u64,
                expiration_ms: r.get(4),
            }
        }))
    }

    async fn clear_watch(&self) -> AppResult<()> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        conn.execute("DELETE FROM watch_state WHERE mailbox_id = $1", &[&mb])
            .await
            .map_err(pg_err)?;
        Ok(())
    }

    async fn get_settings(&self) -> AppResult<UserSettings> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let defaults = UserSettings::default_for_email(mb);
        let send_as: Vec<SendAs> = read_setting(&conn, mb, "send_as")
            .await?
            .unwrap_or(defaults.send_as);
        let vacation: VacationSettings = read_setting(&conn, mb, "vacation")
            .await?
            .unwrap_or(defaults.vacation);
        let auto_forwarding: AutoForwarding = read_setting(&conn, mb, "auto_forwarding")
            .await?
            .unwrap_or(defaults.auto_forwarding);
        let imap: ImapSettings = read_setting(&conn, mb, "imap")
            .await?
            .unwrap_or(defaults.imap);
        let pop: PopSettings = read_setting(&conn, mb, "pop")
            .await?
            .unwrap_or(defaults.pop);
        Ok(UserSettings {
            send_as,
            vacation,
            auto_forwarding,
            imap,
            pop,
        })
    }

    async fn save_settings(&self, settings: UserSettings) -> AppResult<UserSettings> {
        let mut conn = self.ready_conn().await?;
        let tx = conn.transaction().await.map_err(pg_err)?;
        let mb = self.mailbox_id.as_str();
        write_setting(&tx, mb, "send_as", &settings.send_as).await?;
        write_setting(&tx, mb, "vacation", &settings.vacation).await?;
        write_setting(&tx, mb, "auto_forwarding", &settings.auto_forwarding).await?;
        write_setting(&tx, mb, "imap", &settings.imap).await?;
        write_setting(&tx, mb, "pop", &settings.pop).await?;
        tx.commit().await.map_err(pg_err)?;
        Ok(settings)
    }

    async fn create_pending_approval(
        &self,
        input: NewPendingApprovalInput,
    ) -> AppResult<PendingApproval> {
        let mut conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
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
        let status_str = ApprovalStatus::Pending.as_str();

        let tx = conn.transaction().await.map_err(pg_err)?;
        let inserted = tx
            .execute(
                "INSERT INTO pending_approvals (
                    mailbox_id, id, status, reason, requester_json, outbound_message_json,
                    reply_to_message_id, thread_id, draft_id,
                    sent_message_id, provider_message_id, decided_by, decision_note,
                    created_at_ms, expires_at_ms, decided_at_ms
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL, NULL, NULL, NULL, $10, $11, NULL)",
                &[
                    &mb,
                    &id,
                    &status_str,
                    &input.reason,
                    &requester_json,
                    &outbound_json,
                    &input.reply_to_message_id,
                    &input.thread_id,
                    &input.draft_id,
                    &input.created_at_ms,
                    &input.expires_at_ms,
                ],
            )
            .await;

        if let Err(err) = inserted {
            if err.code() == Some(&SqlState::UNIQUE_VIOLATION) {
                return Err(AppError::Conflict(format!(
                    "Approval '{id}' already exists"
                )));
            }
            return Err(pg_err(err));
        }
        tx.commit().await.map_err(pg_err)?;

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
    }

    async fn get_pending_approval(&self, id: &str) -> AppResult<Option<PendingApproval>> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let now_ms = Utc::now().timestamp_millis();
        let row = conn
            .query_opt(
                "SELECT id, status, reason, requester_json, outbound_message_json,
                        reply_to_message_id, thread_id, draft_id,
                        sent_message_id, provider_message_id, decided_by, decision_note,
                        created_at_ms, expires_at_ms, decided_at_ms
                 FROM pending_approvals
                 WHERE mailbox_id = $1 AND id = $2",
                &[&mb, &id],
            )
            .await
            .map_err(pg_err)?;
        row.map(|r| normalize_pending_approval(pending_approval_from_row(&r)?, now_ms))
            .transpose()
    }

    async fn list_pending_approvals(
        &self,
        status: Option<ApprovalStatus>,
        limit: usize,
    ) -> AppResult<Vec<PendingApproval>> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let limit_i64 = if limit == 0 { 20 } else { limit } as i64;
        let now_ms = Utc::now().timestamp_millis();

        let rows = match status {
            None => conn
                .query(
                    "SELECT id, status, reason, requester_json, outbound_message_json,
                            reply_to_message_id, thread_id, draft_id,
                            sent_message_id, provider_message_id, decided_by, decision_note,
                            created_at_ms, expires_at_ms, decided_at_ms
                     FROM pending_approvals
                     WHERE mailbox_id = $1
                     ORDER BY created_at_ms DESC, id DESC
                     LIMIT $2",
                    &[&mb, &limit_i64],
                )
                .await
                .map_err(pg_err)?,
            Some(ApprovalStatus::Pending) => conn
                .query(
                    "SELECT id, status, reason, requester_json, outbound_message_json,
                            reply_to_message_id, thread_id, draft_id,
                            sent_message_id, provider_message_id, decided_by, decision_note,
                            created_at_ms, expires_at_ms, decided_at_ms
                     FROM pending_approvals
                     WHERE mailbox_id = $1 AND status = 'pending' AND expires_at_ms > $2
                     ORDER BY created_at_ms DESC, id DESC
                     LIMIT $3",
                    &[&mb, &now_ms, &limit_i64],
                )
                .await
                .map_err(pg_err)?,
            Some(ApprovalStatus::Expired) => conn
                .query(
                    "SELECT id, status, reason, requester_json, outbound_message_json,
                            reply_to_message_id, thread_id, draft_id,
                            sent_message_id, provider_message_id, decided_by, decision_note,
                            created_at_ms, expires_at_ms, decided_at_ms
                     FROM pending_approvals
                     WHERE mailbox_id = $1
                       AND (status = 'expired' OR (status = 'pending' AND expires_at_ms <= $2))
                     ORDER BY created_at_ms DESC, id DESC
                     LIMIT $3",
                    &[&mb, &now_ms, &limit_i64],
                )
                .await
                .map_err(pg_err)?,
            Some(other @ (ApprovalStatus::Approved | ApprovalStatus::Rejected)) => {
                let status_str = other.as_str();
                conn.query(
                    "SELECT id, status, reason, requester_json, outbound_message_json,
                            reply_to_message_id, thread_id, draft_id,
                            sent_message_id, provider_message_id, decided_by, decision_note,
                            created_at_ms, expires_at_ms, decided_at_ms
                     FROM pending_approvals
                     WHERE mailbox_id = $1 AND status = $2
                     ORDER BY created_at_ms DESC, id DESC
                     LIMIT $3",
                    &[&mb, &status_str, &limit_i64],
                )
                .await
                .map_err(pg_err)?
            }
        };

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            results.push(normalize_pending_approval(
                pending_approval_from_row(&row)?,
                now_ms,
            )?);
        }
        Ok(results)
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

        let mut conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let now_ms = Utc::now().timestamp_millis();
        let tx = conn.transaction().await.map_err(pg_err)?;

        let existing_row = tx
            .query_opt(
                "SELECT id, status, reason, requester_json, outbound_message_json,
                        reply_to_message_id, thread_id, draft_id,
                        sent_message_id, provider_message_id, decided_by, decision_note,
                        created_at_ms, expires_at_ms, decided_at_ms
                 FROM pending_approvals
                 WHERE mailbox_id = $1 AND id = $2
                 FOR UPDATE",
                &[&mb, &id],
            )
            .await
            .map_err(pg_err)?
            .ok_or_else(|| AppError::NotFound(format!("Approval '{id}' not found")))?;
        let existing = pending_approval_from_row(&existing_row)?;

        if existing.status != ApprovalStatus::Pending {
            return Err(AppError::Conflict(format!(
                "Approval '{id}' is already {}",
                existing.status
            )));
        }

        if existing.expires_at_ms <= now_ms {
            tx.execute(
                "UPDATE pending_approvals
                 SET status = 'expired', decided_at_ms = COALESCE(decided_at_ms, $1)
                 WHERE mailbox_id = $2 AND id = $3 AND status = 'pending'",
                &[&now_ms, &mb, &id],
            )
            .await
            .map_err(pg_err)?;
            tx.commit().await.map_err(pg_err)?;
            return Err(AppError::Conflict(format!("Approval '{id}' has expired")));
        }

        let status_str = status.as_str();
        let changed = tx
            .execute(
                "UPDATE pending_approvals
                 SET status = $1,
                     decided_by = $2,
                     decision_note = $3,
                     sent_message_id = $4,
                     provider_message_id = $5,
                     decided_at_ms = $6
                 WHERE mailbox_id = $7 AND id = $8 AND status = 'pending'",
                &[
                    &status_str,
                    &decided_by,
                    &note,
                    &sent_message_id,
                    &provider_message_id,
                    &now_ms,
                    &mb,
                    &id,
                ],
            )
            .await
            .map_err(pg_err)?;

        if changed != 1 {
            return Err(AppError::Conflict(format!(
                "Approval '{id}' was already resolved"
            )));
        }

        tx.commit().await.map_err(pg_err)?;

        Ok(PendingApproval {
            status,
            decided_by,
            decision_note: note,
            sent_message_id,
            provider_message_id,
            decided_at_ms: Some(now_ms),
            ..existing
        })
    }

    async fn record_contact_interaction(
        &self,
        interaction: &ContactInteraction,
    ) -> AppResult<ContactRecord> {
        let (email, domain) = validate_and_normalize_contact_email(&interaction.email)?;
        let parsed_name =
            normalize_optional_text(interaction.display_name.as_deref()).or_else(|| {
                let parsed = parse_simple_email_address(&interaction.email);
                normalize_optional_text(parsed.name.as_deref())
            });
        let is_sent = interaction.direction == ContactDirection::Sent;
        let is_received = interaction.direction == ContactDirection::Received;
        let is_reply = is_sent && interaction.is_reply;
        let ts = interaction.timestamp_ms;

        let sent_inc: i64 = if is_sent { 1 } else { 0 };
        let recv_inc: i64 = if is_received { 1 } else { 0 };
        let reply_inc: i64 = if is_reply { 1 } else { 0 };
        let replied_ts: Option<i64> = is_reply.then_some(ts);
        let initial_vip = compute_contact_is_vip(None, reply_inc as u64);
        let vip_threshold = VIP_REPLY_THRESHOLD as i64;

        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let row = conn
            .query_one(
                "INSERT INTO contacts (
                    mailbox_id, email, display_name, domain,
                    sent_count, received_count, replied_by_me_count,
                    first_seen_at_ms, last_seen_at_ms, last_replied_at_ms,
                    is_vip, vip_override, notes
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, $9, $10, NULL, NULL)
                 ON CONFLICT (mailbox_id, email) DO UPDATE SET
                    display_name = COALESCE(contacts.display_name, EXCLUDED.display_name),
                    sent_count = contacts.sent_count + EXCLUDED.sent_count,
                    received_count = contacts.received_count + EXCLUDED.received_count,
                    replied_by_me_count = contacts.replied_by_me_count + EXCLUDED.replied_by_me_count,
                    first_seen_at_ms = LEAST(contacts.first_seen_at_ms, EXCLUDED.first_seen_at_ms),
                    last_seen_at_ms = GREATEST(contacts.last_seen_at_ms, EXCLUDED.last_seen_at_ms),
                    last_replied_at_ms = CASE
                        WHEN EXCLUDED.last_replied_at_ms IS NULL THEN contacts.last_replied_at_ms
                        WHEN contacts.last_replied_at_ms IS NULL THEN EXCLUDED.last_replied_at_ms
                        ELSE GREATEST(contacts.last_replied_at_ms, EXCLUDED.last_replied_at_ms)
                    END,
                    is_vip = COALESCE(
                        contacts.vip_override,
                        (contacts.replied_by_me_count + EXCLUDED.replied_by_me_count) >= $11
                    )
                 RETURNING email, display_name, domain, sent_count, received_count,
                           replied_by_me_count, first_seen_at_ms, last_seen_at_ms,
                           last_replied_at_ms, is_vip, vip_override, notes",
                &[
                    &mb,
                    &email,
                    &parsed_name,
                    &domain,
                    &sent_inc,
                    &recv_inc,
                    &reply_inc,
                    &ts,
                    &replied_ts,
                    &initial_vip,
                    &vip_threshold,
                ],
            )
            .await
            .map_err(pg_err)?;

        Ok(contact_from_row(&row))
    }

    async fn get_contact(&self, email: &str) -> AppResult<Option<ContactRecord>> {
        let normalized = normalize_contact_email(email);
        if normalized.is_empty() {
            return Ok(None);
        }
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let row = conn
            .query_opt(
                "SELECT email, display_name, domain, sent_count, received_count,
                        replied_by_me_count, first_seen_at_ms, last_seen_at_ms,
                        last_replied_at_ms, is_vip, vip_override, notes
                 FROM contacts
                 WHERE mailbox_id = $1 AND email = $2",
                &[&mb, &normalized],
            )
            .await
            .map_err(pg_err)?;
        Ok(row.as_ref().map(contact_from_row))
    }

    async fn list_contacts(&self, query: &ContactQuery) -> AppResult<Vec<ContactRecord>> {
        let limit = if query.limit == 0 { 50 } else { query.limit } as i64;
        let q_pattern = query
            .q
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| format!("%{}%", escape_pg_like(s)));
        let domain_filter = query
            .domain
            .as_deref()
            .map(|d| d.trim().trim_start_matches('@').to_ascii_lowercase())
            .filter(|s| !s.is_empty());

        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.clone();

        let mut sql = String::from(
            "SELECT email, display_name, domain, sent_count, received_count,
                    replied_by_me_count, first_seen_at_ms, last_seen_at_ms,
                    last_replied_at_ms, is_vip, vip_override, notes
             FROM contacts
             WHERE mailbox_id = $1",
        );
        let mut params_vec: Vec<&(dyn ToSql + Sync)> = vec![&mb];

        if query.vip_only {
            sql.push_str(" AND is_vip = TRUE");
        }
        if query.replied_only {
            sql.push_str(" AND replied_by_me_count > 0");
        }
        if let Some(ref dom) = domain_filter {
            params_vec.push(dom);
            sql.push_str(&format!(" AND domain = ${}", params_vec.len()));
        }
        if let Some(ref pat) = q_pattern {
            params_vec.push(pat);
            let idx = params_vec.len();
            sql.push_str(&format!(
                " AND (email ILIKE ${idx} ESCAPE '\\' \
                       OR COALESCE(display_name, '') ILIKE ${idx} ESCAPE '\\' \
                       OR domain ILIKE ${idx} ESCAPE '\\' \
                       OR COALESCE(notes, '') ILIKE ${idx} ESCAPE '\\')"
            ));
        }

        params_vec.push(&limit);
        sql.push_str(&format!(
            " ORDER BY is_vip DESC, replied_by_me_count DESC, last_seen_at_ms DESC, email ASC \
              LIMIT ${}",
            params_vec.len()
        ));

        let rows = conn.query(&sql, &params_vec).await.map_err(pg_err)?;
        Ok(rows.iter().map(contact_from_row).collect())
    }

    async fn patch_contact(&self, email: &str, patch: &ContactPatch) -> AppResult<ContactRecord> {
        let (email, domain) = validate_and_normalize_contact_email(email)?;
        let now_ms = Utc::now().timestamp_millis();
        let set_vip = patch.is_vip.is_some();
        let vip_override = patch.is_vip;
        let initial_vip = compute_contact_is_vip(vip_override, 0);
        let set_name = patch.display_name.is_some();
        let display_name = patch
            .display_name
            .as_deref()
            .and_then(|s| normalize_optional_text(Some(s)));
        let set_notes = patch.notes.is_some();
        let notes = patch
            .notes
            .as_deref()
            .and_then(|s| normalize_optional_text(Some(s)));
        let vip_threshold = VIP_REPLY_THRESHOLD as i64;

        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let row = conn
            .query_one(
                "INSERT INTO contacts (
                    mailbox_id, email, display_name, domain,
                    sent_count, received_count, replied_by_me_count,
                    first_seen_at_ms, last_seen_at_ms, last_replied_at_ms,
                    is_vip, vip_override, notes
                 ) VALUES ($1, $2, $3, $4, 0, 0, 0, $5, $5, NULL, $6, $7, $8)
                 ON CONFLICT (mailbox_id, email) DO UPDATE SET
                    display_name = CASE WHEN $9 THEN EXCLUDED.display_name ELSE contacts.display_name END,
                    vip_override = CASE WHEN $10 THEN EXCLUDED.vip_override ELSE contacts.vip_override END,
                    is_vip = COALESCE(
                        CASE WHEN $10 THEN EXCLUDED.vip_override ELSE contacts.vip_override END,
                        contacts.replied_by_me_count >= $12
                    ),
                    notes = CASE WHEN $11 THEN EXCLUDED.notes ELSE contacts.notes END
                 RETURNING email, display_name, domain, sent_count, received_count,
                           replied_by_me_count, first_seen_at_ms, last_seen_at_ms,
                           last_replied_at_ms, is_vip, vip_override, notes",
                &[
                    &mb,
                    &email,
                    &display_name,
                    &domain,
                    &now_ms,
                    &initial_vip,
                    &vip_override,
                    &notes,
                    &set_name,
                    &set_vip,
                    &set_notes,
                    &vip_threshold,
                ],
            )
            .await
            .map_err(pg_err)?;

        Ok(contact_from_row(&row))
    }

    async fn get_idempotency_key(
        &self,
        scope: &str,
        key: &str,
        now_ms: i64,
    ) -> AppResult<Option<IdempotencyRecord>> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let row = conn
            .query_opt(
                "SELECT scope, key, response_json, created_at_ms, expires_at_ms
                 FROM idempotency_keys
                 WHERE mailbox_id = $1 AND scope = $2 AND key = $3 AND expires_at_ms > $4",
                &[&mb, &scope, &key, &now_ms],
            )
            .await
            .map_err(pg_err)?;
        Ok(row.map(|r| IdempotencyRecord {
            scope: r.get(0),
            key: r.get(1),
            response_json: r.get(2),
            created_at_ms: r.get(3),
            expires_at_ms: r.get(4),
        }))
    }

    async fn put_idempotency_key(
        &self,
        scope: &str,
        key: &str,
        response_json: &str,
        ttl_secs: i64,
    ) -> AppResult<()> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let created_at_ms = Utc::now().timestamp_millis();
        let expires_at_ms = created_at_ms.saturating_add(ttl_secs.saturating_mul(1000));
        conn.execute(
            "INSERT INTO idempotency_keys (
                mailbox_id, scope, key, response_json, created_at_ms, expires_at_ms
             ) VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (mailbox_id, scope, key) DO UPDATE SET
                response_json = EXCLUDED.response_json,
                created_at_ms = EXCLUDED.created_at_ms,
                expires_at_ms = EXCLUDED.expires_at_ms",
            &[
                &mb,
                &scope,
                &key,
                &response_json,
                &created_at_ms,
                &expires_at_ms,
            ],
        )
        .await
        .map_err(pg_err)?;
        Ok(())
    }

    async fn append_audit_log(&self, entry: &NewAuditLogEntry) -> AppResult<AuditLogEntry> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.as_str();
        let id = format!("aud_{}", Uuid::new_v4().simple());
        let timestamp_ms = entry
            .timestamp_ms
            .unwrap_or_else(|| Utc::now().timestamp_millis());
        let scopes_json = serde_json::to_string(&entry.scopes)?;
        let target_ids_json = serde_json::to_string(&entry.target_ids)?;

        conn.execute(
            "INSERT INTO audit_log (
                id, mailbox_id, timestamp_ms, actor, scopes_json, channel,
                action, target_ids_json, outcome, detail
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            &[
                &id,
                &mb,
                &timestamp_ms,
                &entry.actor,
                &scopes_json,
                &entry.channel,
                &entry.action,
                &target_ids_json,
                &entry.outcome,
                &entry.detail,
            ],
        )
        .await
        .map_err(pg_err)?;

        Ok(AuditLogEntry {
            id,
            mailbox_id: self.mailbox_id.clone(),
            timestamp_ms,
            actor: entry.actor.clone(),
            scopes: entry.scopes.clone(),
            channel: entry.channel.clone(),
            action: entry.action.clone(),
            target_ids: entry.target_ids.clone(),
            outcome: entry.outcome.clone(),
            detail: entry.detail.clone(),
        })
    }

    async fn list_audit_log(&self, query: &AuditLogQuery) -> AppResult<Vec<AuditLogEntry>> {
        let conn = self.ready_conn().await?;
        let mb = self.mailbox_id.clone();
        let limit = if query.limit == 0 { 50 } else { query.limit } as i64;
        let action_filter = query
            .action
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let actor_filter = query
            .actor
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let since_ms = query.since_ms;

        let mut sql = String::from(
            "SELECT id, mailbox_id, timestamp_ms, actor, scopes_json, channel,
                    action, target_ids_json, outcome, detail
             FROM audit_log
             WHERE mailbox_id = $1",
        );
        let mut params: Vec<&(dyn ToSql + Sync)> = vec![&mb];
        let mut next_idx = 2usize;

        if let Some(ref action) = action_filter {
            sql.push_str(&format!(" AND LOWER(action) = LOWER(${next_idx})"));
            params.push(action);
            next_idx += 1;
        }
        if let Some(ref actor) = actor_filter {
            sql.push_str(&format!(" AND LOWER(actor) = LOWER(${next_idx})"));
            params.push(actor);
            next_idx += 1;
        }
        if let Some(ref since) = since_ms {
            sql.push_str(&format!(" AND timestamp_ms >= ${next_idx}"));
            params.push(since);
            next_idx += 1;
        }
        sql.push_str(&format!(
            " ORDER BY timestamp_ms DESC, seq DESC LIMIT ${next_idx}"
        ));
        params.push(&limit);

        let rows = conn.query(&sql, &params).await.map_err(pg_err)?;
        let mut results = Vec::with_capacity(rows.len());
        for r in rows {
            let scopes_json: String = r.get(4);
            let target_ids_json: String = r.get(7);
            let scopes: Vec<String> = serde_json::from_str(&scopes_json)
                .map_err(|e| AppError::Storage(format!("Corrupt scopes_json: {e}")))?;
            let target_ids: Vec<String> = serde_json::from_str(&target_ids_json)
                .map_err(|e| AppError::Storage(format!("Corrupt target_ids_json: {e}")))?;
            results.push(AuditLogEntry {
                id: r.get(0),
                mailbox_id: r.get(1),
                timestamp_ms: r.get(2),
                actor: r.get(3),
                scopes,
                channel: r.get(5),
                action: r.get(6),
                target_ids,
                outcome: r.get(8),
                detail: r.get(9),
            });
        }
        Ok(results)
    }
}

fn contact_from_row(row: &Row) -> ContactRecord {
    let sent_count: i64 = row.get(3);
    let received_count: i64 = row.get(4);
    let replied_by_me_count: i64 = row.get(5);
    ContactRecord {
        email: row.get(0),
        display_name: row.get(1),
        domain: row.get(2),
        sent_count: sent_count.max(0) as u64,
        received_count: received_count.max(0) as u64,
        replied_by_me_count: replied_by_me_count.max(0) as u64,
        first_seen_at_ms: row.get(6),
        last_seen_at_ms: row.get(7),
        last_replied_at_ms: row.get(8),
        is_vip: row.get(9),
        vip_override: row.get(10),
        notes: row.get(11),
    }
}

fn escape_pg_like(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out
}
