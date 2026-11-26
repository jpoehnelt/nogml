//! `nogml`: headless Rust email server with MCP, Gmail REST API v1,
//! embedded IMAP4rev1, Resend delivery and webhooks, and upstream Gmail sync.

pub mod ai;
pub mod auth;
pub mod auth_wizard;
pub mod blob;
pub mod config;
pub mod crypto;
pub mod doctor;
pub mod error;
pub mod events;
pub mod filter;
pub mod gmail;
pub mod imap;
pub mod mcp;
pub mod metrics;
pub mod mime;
pub mod models;
pub mod net_guard;
pub mod oauth2;
pub mod resend;
pub mod search;
pub mod search_index;
pub mod secrets;
pub mod server;
pub mod storage;
pub mod sync;
pub mod transport;

use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    sync::{Arc, Mutex as StdMutex, Once, Weak},
};

use axum::{
    Router,
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use tokio::sync::{Mutex, watch};

use crate::{
    ai::safety::{OutboundPolicy, open_outbound_policy},
    auth::{AuthProvider, Principal, ResolvedMailbox, StaticTokenAuthProvider},
    blob::{
        BlobStore, InlineBlobStore, PrefixedBlobStore, attachment_blob_key, is_external_blob_store,
        open_blob_store, raw_message_blob_key,
    },
    config::{Config, SyncAccountConfig, normalize_mailbox_id},
    crypto::SecretCipher,
    error::AppResult,
    events::EventBus,
    filter::{InboundFilter, open_filter},
    gmail::upload::ResumableUploadStore,
    metrics::Metrics,
    models::{LABEL_DRAFT, LABEL_SENT},
    resend::{HttpResendClient, ResendClient, ResendTransport},
    search_index::{SearchIndex, StoreSearchIndex, open_search_index},
    storage::{
        ContactDirection, ContactInteraction, MailStore, StoredAttachment, StoredMessage,
        open_store, parse_simple_email_address, validate_and_normalize_contact_email,
    },
    transport::{MailTransport, open_transport},
};

static CRYPTO_INIT: Once = Once::new();

/// Install the `ring` rustls crypto provider once per process.
pub fn ensure_crypto_provider() {
    CRYPTO_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Shared application state injected into HTTP, MCP, IMAP, Resend, and Sync subsystems.
///
/// Every external dependency sits behind a pluggable async trait object:
/// - [`MailStore`]: metadata, threads, labels, history, IMAP UIDs, sync state
/// - [`BlobStore`]: raw RFC 2822 & attachment binary blobs (`inline` | `fs` | `memory` | S3/R2)
/// - [`MailTransport`]: outbound email delivery (`ResendTransport`, SES, SMTP, etc.)
/// - [`InboundFilter`]: inbound spam/auth/routing pipeline across all ingest paths
/// - [`AuthProvider`]: HTTP bearer & IMAP authentication returning [`auth::Principal`]
/// - [`SearchIndex`]: full-text or semantic search used by `/v1/search` and MCP `search_emails`
/// - [`OutboundPolicy`]: agent send guardrails (`Allow`, `DowngradeToDraft`, `HoldForApproval`, `Deny`)
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn MailStore>,
    pub blobs: Arc<dyn BlobStore>,
    pub transport: Arc<dyn MailTransport>,
    pub filter: Arc<dyn InboundFilter>,
    pub auth: Arc<dyn AuthProvider>,
    pub search: Arc<dyn SearchIndex>,
    pub outbound_policy: Arc<dyn OutboundPolicy>,
    /// AES-256-GCM encryption-at-rest cipher for stored secrets and credentials.
    pub cipher: Arc<SecretCipher>,
    /// Underlying Resend client used by `POST /webhooks/resend` Receiving API fetches.
    pub resend: Arc<dyn ResendClient>,
    pub events: EventBus,
    pub sync_lock: Arc<Mutex<()>>,
    pub resumable_uploads: Arc<ResumableUploadStore>,
    /// Maximum aggregate serialized response bytes permitted for `POST /batch/gmail/v1`.
    pub max_batch_response_bytes: usize,
    /// Tracks approval IDs currently being approved/rejected to prevent concurrent double-sends.
    pub approval_in_flight: Arc<StdMutex<HashSet<String>>>,
    /// Tracks scheduled send IDs currently being dispatched or canceled to prevent concurrent races.
    pub scheduled_in_flight: Arc<StdMutex<HashSet<String>>>,
    /// Tracks redeemed single-use local OAuth2 authorization code JTIs mapped to their expiry
    /// Unix timestamp (seconds), pruned on write to prevent unbounded growth.
    pub used_oauth_codes: Arc<Mutex<HashMap<String, i64>>>,
    /// Shared operational metrics exported at `GET /metrics`.
    pub metrics: Arc<Metrics>,
    /// Broadcast receiver signaled (`true`) when the server begins graceful shutdown.
    pub shutdown: watch::Receiver<bool>,
    shutdown_tx: Arc<watch::Sender<bool>>,
    /// Bounded expiring cache of seen Svix webhook IDs (`svix-id`) preventing replay attacks.
    pub svix_replay_cache: Arc<crate::resend::svix::SvixReplayCache>,
    /// Per-`(mailbox_id, scope, idempotency_key)` single-flight locks preventing concurrent double-sends.
    idempotency_locks: Arc<StdMutex<HashMap<String, Weak<Mutex<()>>>>>,
    primary_mailbox_id: String,
    base_blobs: Arc<dyn BlobStore>,
    sync_locks: Arc<StdMutex<HashMap<String, Arc<Mutex<()>>>>>,
    #[cfg(feature = "postgres")]
    pg_event_bridge: Option<Arc<crate::storage::PostgresEventBridge>>,
}

fn scope_blobs_for_mailbox(
    base_blobs: &Arc<dyn BlobStore>,
    config: &Config,
    primary_mailbox_id: &str,
    target_mailbox_id: &str,
) -> Arc<dyn BlobStore> {
    let use_prefix = config.is_multi_mailbox() || target_mailbox_id != primary_mailbox_id;
    if use_prefix && is_external_blob_store(base_blobs.as_ref()) {
        Arc::new(PrefixedBlobStore::for_mailbox(
            base_blobs.clone(),
            target_mailbox_id,
        ))
    } else {
        base_blobs.clone()
    }
}

impl AppState {
    /// Construct application state from `Config`, opening the configured `MailStore`,
    /// `BlobStore`, `MailTransport`, and `SearchIndex`.
    pub fn from_config(config: Config) -> AppResult<Self> {
        ensure_crypto_provider();
        #[cfg(feature = "postgres")]
        let (store, pg_event_bridge) = if config.storage == crate::config::StorageBackend::Postgres
        {
            let (s, bridge) = crate::storage::open_postgres_with_bridge_sync(&config)?;
            (s, Some(bridge))
        } else {
            (open_store(&config)?, None)
        };
        #[cfg(not(feature = "postgres"))]
        let store = open_store(&config)?;

        Self::finish_from_config(
            config,
            store,
            #[cfg(feature = "postgres")]
            pg_event_bridge,
        )
    }

    /// Asynchronously construct application state from `Config`, eagerly initializing
    /// network storage backends (such as `PostgresStore`) and attaching distributed
    /// `EventBus` bridges.
    pub async fn from_config_async(config: Config) -> AppResult<Self> {
        ensure_crypto_provider();
        #[cfg(feature = "postgres")]
        let (store, pg_event_bridge) = if config.storage == crate::config::StorageBackend::Postgres
        {
            let (s, bridge) = crate::storage::open_postgres_with_bridge_async(&config).await?;
            (s, Some(bridge))
        } else {
            (crate::storage::open_store_async(&config).await?, None)
        };
        #[cfg(not(feature = "postgres"))]
        let store = crate::storage::open_store_async(&config).await?;

        Self::finish_from_config(
            config,
            store,
            #[cfg(feature = "postgres")]
            pg_event_bridge,
        )
    }

    fn finish_from_config(
        config: Config,
        store: Arc<dyn MailStore>,
        #[cfg(feature = "postgres")] pg_event_bridge: Option<
            Arc<crate::storage::PostgresEventBridge>,
        >,
    ) -> AppResult<Self> {
        let primary_mailbox_id = normalize_mailbox_id(&config.user_email);
        let cipher = Arc::new(SecretCipher::from_config(&config)?);
        let base_blobs = open_blob_store(&config)?;
        let blobs = scope_blobs_for_mailbox(
            &base_blobs,
            &config,
            &primary_mailbox_id,
            &primary_mailbox_id,
        );
        let resend: Arc<dyn ResendClient> = Arc::new(HttpResendClient::from_config(&config));
        let transport = open_transport(&config, resend.clone())?;
        let search = open_search_index(&config, store.clone())?;
        let filter: Arc<dyn InboundFilter> = open_filter(&config);
        let auth: Arc<dyn AuthProvider> = Arc::new(StaticTokenAuthProvider::from_config(&config));
        let outbound_policy: Arc<dyn OutboundPolicy> = open_outbound_policy(&config, store.clone());
        let sync_lock = Arc::new(Mutex::new(()));
        let mut locks = HashMap::new();
        locks.insert(primary_mailbox_id.clone(), sync_lock.clone());

        #[allow(unused_mut)]
        let mut events = EventBus::with_mailbox(&primary_mailbox_id);
        #[cfg(feature = "postgres")]
        if let Some(ref bridge) = pg_event_bridge {
            events = events.with_bridge(bridge.clone());
        }

        let (shutdown_tx, shutdown) = watch::channel(false);

        Ok(Self {
            config: Arc::new(config),
            store,
            blobs,
            transport,
            filter,
            auth,
            search,
            outbound_policy,
            cipher,
            resend,
            events,
            sync_lock,
            resumable_uploads: Arc::new(ResumableUploadStore::new()),
            max_batch_response_bytes: crate::gmail::batch::MAX_BATCH_RESPONSE_BYTES,
            approval_in_flight: Arc::new(StdMutex::new(HashSet::new())),
            scheduled_in_flight: Arc::new(StdMutex::new(HashSet::new())),
            used_oauth_codes: Arc::new(Mutex::new(HashMap::new())),
            metrics: Arc::new(Metrics::new()),
            shutdown,
            shutdown_tx: Arc::new(shutdown_tx),
            svix_replay_cache: Arc::new(crate::resend::svix::SvixReplayCache::new()),
            idempotency_locks: Arc::new(StdMutex::new(HashMap::new())),
            primary_mailbox_id,
            base_blobs,
            sync_locks: Arc::new(StdMutex::new(locks)),
            #[cfg(feature = "postgres")]
            pg_event_bridge,
        })
    }

    /// Spawn the background distributed `EventBus` listener (e.g. Postgres `LISTEN nogml_events`)
    /// when a networked storage backend with a bridge is active.
    pub fn spawn_event_bridge_listener(
        &self,
        shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        #[cfg(feature = "postgres")]
        if let Some(ref bridge) = self.pg_event_bridge {
            let bridge = bridge.clone();
            let events = self.events.clone();
            return Some(tokio::spawn(async move {
                bridge.run_listener(events, shutdown_rx).await;
            }));
        }
        #[cfg(not(feature = "postgres"))]
        let _ = shutdown_rx;
        None
    }

    /// Construct application state with explicit `MailStore` and `ResendClient` implementations
    /// (ideal for integration tests with `MemoryStore` / mock Resend). All other pluggable traits
    /// default cleanly from `config` and `store` and can be swapped via `.with_*` builders.
    pub fn with_backends(
        config: Config,
        store: Arc<dyn MailStore>,
        resend: Arc<dyn ResendClient>,
    ) -> Self {
        ensure_crypto_provider();
        let primary_mailbox_id = normalize_mailbox_id(&config.user_email);
        let cipher = Arc::new(
            SecretCipher::from_config(&config).unwrap_or_else(|_| SecretCipher::disabled()),
        );
        let base_blobs: Arc<dyn BlobStore> = match open_blob_store(&config) {
            Ok(b) => b,
            Err(_) => Arc::new(InlineBlobStore),
        };
        let blobs = scope_blobs_for_mailbox(
            &base_blobs,
            &config,
            &primary_mailbox_id,
            &primary_mailbox_id,
        );
        let transport: Arc<dyn MailTransport> = match open_transport(&config, resend.clone()) {
            Ok(t) => t,
            Err(_) => Arc::new(ResendTransport::new(
                resend.clone(),
                config.user_email.clone(),
            )),
        };
        let filter: Arc<dyn InboundFilter> = open_filter(&config);
        let auth: Arc<dyn AuthProvider> = Arc::new(StaticTokenAuthProvider::from_config(&config));
        let search: Arc<dyn SearchIndex> = match open_search_index(&config, store.clone()) {
            Ok(s) => s,
            Err(_) => Arc::new(StoreSearchIndex::new(store.clone())),
        };
        let outbound_policy: Arc<dyn OutboundPolicy> = open_outbound_policy(&config, store.clone());
        let sync_lock = Arc::new(Mutex::new(()));
        let mut locks = HashMap::new();
        locks.insert(primary_mailbox_id.clone(), sync_lock.clone());
        let (shutdown_tx, shutdown) = watch::channel(false);

        Self {
            config: Arc::new(config),
            store,
            blobs,
            transport,
            filter,
            auth,
            search,
            outbound_policy,
            cipher,
            resend,
            events: EventBus::with_mailbox(&primary_mailbox_id),
            sync_lock,
            resumable_uploads: Arc::new(ResumableUploadStore::new()),
            max_batch_response_bytes: crate::gmail::batch::MAX_BATCH_RESPONSE_BYTES,
            approval_in_flight: Arc::new(StdMutex::new(HashSet::new())),
            scheduled_in_flight: Arc::new(StdMutex::new(HashSet::new())),
            used_oauth_codes: Arc::new(Mutex::new(HashMap::new())),
            metrics: Arc::new(Metrics::new()),
            shutdown,
            shutdown_tx: Arc::new(shutdown_tx),
            svix_replay_cache: Arc::new(crate::resend::svix::SvixReplayCache::new()),
            idempotency_locks: Arc::new(StdMutex::new(HashMap::new())),
            primary_mailbox_id,
            base_blobs,
            sync_locks: Arc::new(StdMutex::new(locks)),
            #[cfg(feature = "postgres")]
            pg_event_bridge: None,
        }
    }

    /// Evaluate `self.outbound_policy` and record the resulting decision in `self.metrics`.
    pub async fn evaluate_outbound_policy(
        &self,
        check: &crate::ai::safety::OutboundCheck,
    ) -> AppResult<crate::ai::safety::OutboundDecision> {
        let res = self.outbound_policy.evaluate(check).await;
        match &res {
            Ok(decision) => self.metrics.record_policy_decision(decision),
            Err(
                crate::error::AppError::RecipientNotAllowed { .. }
                | crate::error::AppError::PolicyDenied { .. }
                | crate::error::AppError::DraftOnlyBlocked { .. }
                | crate::error::AppError::Validation { .. },
            ) => self.metrics.inc_policy_deny(),
            Err(_) => {}
        }
        res
    }

    /// Signal graceful shutdown to all active long-lived handlers (such as `/v1/events` SSE streams).
    pub fn trigger_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Subscribe to the server shutdown signal channel.
    pub fn subscribe_shutdown(&self) -> watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }

    /// Return the normalized mailbox ID active on this `AppState`.
    pub fn mailbox_id(&self) -> &str {
        self.events.mailbox_id()
    }

    /// Return a lightweight `AppState` scoped strictly to `mailbox_id`:
    /// - `store` is partitioned via [`MailStore::for_mailbox`]
    /// - `blobs` is prefixed with `mailboxes/<sanitized_mb>/...` in multi-mailbox mode or
    ///   for non-primary mailboxes (never double-prefixing)
    /// - `search` is scoped via [`SearchIndex::for_mailbox`]
    /// - `events` shares the broadcast/replay bus, tagged and filtered to `mailbox_id`
    /// - `config.user_email` reflects `mailbox_id` so profile, sendAs, and outbound `From`
    ///   match the active mailbox
    /// - `sync_lock` is scoped per mailbox so mailboxes can sync independently
    pub fn for_mailbox(&self, mailbox_id: &str) -> Self {
        let normalized = normalize_mailbox_id(mailbox_id);
        let target = if normalized.is_empty() {
            self.primary_mailbox_id.clone()
        } else {
            normalized
        };

        let store = self.store.for_mailbox(&target);
        let blobs = scope_blobs_for_mailbox(
            &self.base_blobs,
            &self.config,
            &self.primary_mailbox_id,
            &target,
        );
        let search = self
            .search
            .for_mailbox(&target)
            .unwrap_or_else(|| self.search.clone());
        let outbound_policy = self
            .outbound_policy
            .for_mailbox(&target)
            .unwrap_or_else(|| self.outbound_policy.clone());
        let events = self.events.for_mailbox(&target);

        let config = if self.config.user_email.eq_ignore_ascii_case(&target) {
            self.config.clone()
        } else {
            let mut cloned = (*self.config).clone();
            if !target.eq_ignore_ascii_case(&self.primary_mailbox_id)
                && !cloned
                    .mailboxes
                    .iter()
                    .any(|m| m.eq_ignore_ascii_case(&self.primary_mailbox_id))
            {
                cloned.mailboxes.push(self.primary_mailbox_id.clone());
            }
            cloned.user_email = target.clone();
            Arc::new(cloned)
        };

        let sync_lock = {
            let mut locks = self.sync_locks.lock().unwrap_or_else(|e| e.into_inner());
            locks
                .entry(target)
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };

        Self {
            config,
            store,
            blobs,
            transport: self.transport.clone(),
            filter: self.filter.clone(),
            auth: self.auth.clone(),
            search,
            outbound_policy,
            cipher: self.cipher.clone(),
            resend: self.resend.clone(),
            events,
            sync_lock,
            resumable_uploads: self.resumable_uploads.clone(),
            max_batch_response_bytes: self.max_batch_response_bytes,
            approval_in_flight: self.approval_in_flight.clone(),
            scheduled_in_flight: self.scheduled_in_flight.clone(),
            used_oauth_codes: self.used_oauth_codes.clone(),
            metrics: self.metrics.clone(),
            shutdown: self.shutdown_tx.subscribe(),
            shutdown_tx: self.shutdown_tx.clone(),
            svix_replay_cache: self.svix_replay_cache.clone(),
            idempotency_locks: self.idempotency_locks.clone(),
            primary_mailbox_id: self.primary_mailbox_id.clone(),
            base_blobs: self.base_blobs.clone(),
            sync_locks: self.sync_locks.clone(),
            #[cfg(feature = "postgres")]
            pg_event_bridge: self.pg_event_bridge.clone(),
        }
    }

    /// Return a lightweight `AppState` scoped strictly to `account.mailbox_id` with all upstream
    /// sync settings overridden from `account`.
    pub fn for_sync_account(&self, account: &SyncAccountConfig) -> Self {
        let mut scoped = self.for_mailbox(&account.mailbox_id);
        scoped.config = Arc::new(account.apply_to_config(&scoped.config));
        scoped
    }

    /// Replace the [`BlobStore`] backend on this `AppState`.
    pub fn with_blobs(mut self, blobs: Arc<dyn BlobStore>) -> Self {
        let active_mb = self.mailbox_id().to_string();
        self.base_blobs = blobs;
        self.blobs = scope_blobs_for_mailbox(
            &self.base_blobs,
            &self.config,
            &self.primary_mailbox_id,
            &active_mb,
        );
        self
    }

    /// Replace the [`MailTransport`] backend on this `AppState`.
    pub fn with_transport(mut self, transport: Arc<dyn MailTransport>) -> Self {
        self.transport = transport;
        self
    }

    /// Replace the [`InboundFilter`] backend on this `AppState`.
    pub fn with_filter(mut self, filter: Arc<dyn InboundFilter>) -> Self {
        self.filter = filter;
        self
    }

    /// Replace the [`AuthProvider`] backend on this `AppState`.
    pub fn with_auth(mut self, auth: Arc<dyn AuthProvider>) -> Self {
        self.auth = auth;
        self
    }

    /// Replace the [`SearchIndex`] backend on this `AppState`.
    pub fn with_search(mut self, search: Arc<dyn SearchIndex>) -> Self {
        self.search = search;
        self
    }

    /// Replace the [`OutboundPolicy`] backend on this `AppState`.
    pub fn with_outbound_policy(mut self, outbound_policy: Arc<dyn OutboundPolicy>) -> Self {
        self.outbound_policy = outbound_policy;
        self
    }

    /// Replace the [`SecretCipher`] used for encryption at rest on this `AppState`.
    pub fn with_cipher(mut self, cipher: Arc<SecretCipher>) -> Self {
        self.cipher = cipher;
        self
    }

    /// Encrypt `send_as.smtp_msa.password` in place using `self.cipher` when present and non-empty.
    pub fn encrypt_send_as_password(&self, send_as: &mut crate::models::SendAs) -> AppResult<()> {
        if let Some(ref mut msa) = send_as.smtp_msa
            && let Some(ref password) = msa.password
            && !password.is_empty()
        {
            msa.password = Some(self.cipher.encrypt(password)?);
        }
        Ok(())
    }

    /// Decrypt `send_as.smtp_msa.password` in place using `self.cipher` when present and non-empty.
    pub fn decrypt_send_as_password(&self, send_as: &mut crate::models::SendAs) -> AppResult<()> {
        if let Some(ref mut msa) = send_as.smtp_msa
            && let Some(ref password) = msa.password
            && !password.is_empty()
        {
            msa.password = Some(self.cipher.decrypt(password)?);
        }
        Ok(())
    }

    /// Load user settings from `self.store` and transparently decrypt stored `sendAs.smtp_msa.password` values.
    pub async fn get_decrypted_settings(&self) -> AppResult<crate::storage::UserSettings> {
        let mut settings = self.store.get_settings().await?;
        for entry in &mut settings.send_as {
            self.decrypt_send_as_password(entry)?;
        }
        Ok(settings)
    }

    /// Replace the [`ResumableUploadStore`] on this `AppState`.
    pub fn with_resumable_uploads(mut self, resumable_uploads: Arc<ResumableUploadStore>) -> Self {
        self.resumable_uploads = resumable_uploads;
        self
    }

    /// Override the maximum aggregate response byte cap for `POST /batch/gmail/v1`.
    pub fn with_max_batch_response_bytes(mut self, max_batch_response_bytes: usize) -> Self {
        self.max_batch_response_bytes = max_batch_response_bytes;
        self
    }

    /// Mirror a stored message's raw RFC 2822 bytes and attachments to `self.blobs`
    /// when an external `BlobStore` (`fs`, `memory`, S3/R2, etc.) is active, and index
    /// the message in `self.search`.
    pub async fn post_store_message(&self, msg: &StoredMessage) -> AppResult<()> {
        if is_external_blob_store(self.blobs.as_ref()) {
            if !msg.raw_rfc2822.is_empty() {
                self.blobs
                    .put(&raw_message_blob_key(&msg.id), &msg.raw_rfc2822)
                    .await?;
            }
            if msg.has_attachments {
                let metas = self.store.list_attachment_meta(&msg.id).await?;
                for meta in metas {
                    if let Some(att) = self.store.get_attachment(&msg.id, &meta.id).await? {
                        self.blobs
                            .put(&attachment_blob_key(&msg.id, &att.id), &att.data)
                            .await?;
                    }
                }
            }
        }
        self.search.index(msg).await?;
        self.record_contacts_for_message(msg).await?;
        Ok(())
    }

    /// Update the local per-mailbox contact graph from a newly stored message.
    ///
    /// - Messages carrying `DRAFT` are skipped.
    /// - Messages carrying `SENT` record `ContactDirection::Sent` (with
    ///   `is_reply = in_reply_to.is_some()`) for each unique recipient in `to_addrs` and
    ///   `cc_addrs`, skipping the mailbox's own address.
    /// - All other messages record `ContactDirection::Received` for `from_addr`, skipping the
    ///   mailbox's own address.
    async fn record_contacts_for_message(&self, msg: &StoredMessage) -> AppResult<()> {
        if msg.label_ids.iter().any(|l| l == LABEL_DRAFT) {
            return Ok(());
        }

        let self_email = self.store.mailbox_id().trim().to_ascii_lowercase();
        let config_email = self.config.user_email.trim().to_ascii_lowercase();
        let is_self = |addr: &str| {
            (!self_email.is_empty() && addr == self_email)
                || (!config_email.is_empty() && addr == config_email)
                || (!self_email.is_empty()
                    && self.config.resolve_alias_target(addr).as_deref()
                        == Some(self_email.as_str()))
        };

        if msg.label_ids.iter().any(|l| l == LABEL_SENT) {
            let is_reply = msg
                .in_reply_to
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty());
            let mut seen = HashSet::new();
            for raw in msg.to_addrs.iter().chain(msg.cc_addrs.iter()) {
                let parsed = parse_simple_email_address(raw);
                let Ok((email, _)) = validate_and_normalize_contact_email(&parsed.email) else {
                    continue;
                };
                if is_self(&email) || !seen.insert(email.clone()) {
                    continue;
                }
                let interaction = ContactInteraction {
                    email,
                    display_name: parsed.name,
                    direction: ContactDirection::Sent,
                    is_reply,
                    timestamp_ms: msg.internal_date_ms,
                };
                self.store.record_contact_interaction(&interaction).await?;
            }
        } else {
            let parsed = parse_simple_email_address(&msg.from_addr);
            if let Ok((email, _)) = validate_and_normalize_contact_email(&parsed.email)
                && !is_self(&email)
            {
                let interaction = ContactInteraction {
                    email,
                    display_name: parsed.name,
                    direction: ContactDirection::Received,
                    is_reply: false,
                    timestamp_ms: msg.internal_date_ms,
                };
                self.store.record_contact_interaction(&interaction).await?;
            }
        }
        Ok(())
    }

    /// Load a message's raw RFC 2822 bytes, serving from external `BlobStore` when present
    /// and falling back to `msg.raw_rfc2822`.
    pub async fn load_raw_rfc2822(&self, msg: &StoredMessage) -> AppResult<Vec<u8>> {
        if is_external_blob_store(self.blobs.as_ref())
            && let Some(bytes) = self.blobs.get(&raw_message_blob_key(&msg.id)).await?
        {
            return Ok(bytes);
        }
        Ok(msg.raw_rfc2822.clone())
    }

    /// Load an attachment's raw bytes, serving from external `BlobStore` when present
    /// and falling back to `att.data`.
    pub async fn load_attachment_bytes(&self, att: &StoredAttachment) -> AppResult<Vec<u8>> {
        if is_external_blob_store(self.blobs.as_ref())
            && let Some(bytes) = self
                .blobs
                .get(&attachment_blob_key(&att.message_id, &att.id))
                .await?
        {
            return Ok(bytes);
        }
        Ok(att.data.clone())
    }

    /// Collect attachment IDs for `message_id` when an external `BlobStore` is active,
    /// so callers can pass them to [`Self::post_delete_message`] after deleting the DB row.
    pub async fn collect_external_attachment_ids(&self, message_id: &str) -> Vec<String> {
        if !is_external_blob_store(self.blobs.as_ref()) {
            return Vec::new();
        }
        self.store
            .list_attachment_meta(message_id)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|a| a.id)
            .collect()
    }

    /// Clean up external blobs and search index entry for a deleted message.
    pub async fn post_delete_message(
        &self,
        message_id: &str,
        attachment_ids: &[String],
    ) -> AppResult<()> {
        if is_external_blob_store(self.blobs.as_ref()) {
            let _ = self.blobs.delete(&raw_message_blob_key(message_id)).await;
            for att_id in attachment_ids {
                let _ = self
                    .blobs
                    .delete(&attachment_blob_key(message_id, att_id))
                    .await;
            }
        }
        let _ = self.search.remove(message_id).await;
        Ok(())
    }

    /// Return a per-`(mailbox_id, scope, key)` async mutex so concurrent retries with the same
    /// idempotency key serialize cleanly and the second caller observes the first caller's cached result.
    pub fn idempotency_key_lock(&self, scope: &str, key: &str) -> Arc<Mutex<()>> {
        let composite = format!("{}\x1f{}\x1f{}", self.mailbox_id(), scope, key);
        let mut map = self
            .idempotency_locks
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if map.len() > 256 {
            map.retain(|_, v| v.strong_count() > 0);
        }
        if let Some(existing) = map.get(&composite).and_then(Weak::upgrade) {
            return existing;
        }
        let lock = Arc::new(Mutex::new(()));
        map.insert(composite, Arc::downgrade(&lock));
        lock
    }

    /// Append an immutable audit log entry for an operation executed on this mailbox.
    pub async fn record_audit(
        &self,
        principal: Option<&Principal>,
        channel: &str,
        action: &str,
        target_ids: Vec<String>,
        outcome: &str,
        detail: Option<String>,
    ) {
        let actor = principal
            .map(|p| p.mailbox_id.clone())
            .unwrap_or_else(|| self.mailbox_id().to_string());
        let scopes: Vec<String> = match principal {
            Some(p) => p.scopes.iter().map(|s| s.as_str().to_string()).collect(),
            None => vec![
                "read".to_string(),
                "write".to_string(),
                "send".to_string(),
                "admin".to_string(),
            ],
        };
        let entry = crate::storage::NewAuditLogEntry {
            timestamp_ms: None,
            actor,
            scopes,
            channel: channel.to_string(),
            action: action.to_string(),
            target_ids,
            outcome: outcome.to_string(),
            detail,
        };
        if let Err(err) = self.store.append_audit_log(&entry).await {
            tracing::warn!(%err, action, channel, "Failed to append audit log entry");
        }
    }
}

/// Axum extractor that resolves the target mailbox from request extensions
/// (`ResolvedMailbox` or `Principal`, populated by [`auth::require_auth`]) and scopes
/// [`AppState`] strictly to that mailbox.
///
/// Falls back to the router's default [`AppState`] when neither extension is present.
pub struct MailboxState(pub AppState);

impl<S> FromRequestParts<S> for MailboxState
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let base = AppState::from_ref(state);
        let scoped =
            if let Some(ResolvedMailbox(mailbox_id)) = parts.extensions.get::<ResolvedMailbox>() {
                base.for_mailbox(mailbox_id)
            } else if let Some(principal) = parts.extensions.get::<Principal>() {
                base.for_mailbox(&principal.mailbox_id)
            } else {
                base
            };
        Ok(Self(scoped))
    }
}

/// Convenience helper to construct the full Axum HTTP [`Router`].
pub fn build_router(state: AppState) -> Router {
    server::build_router(state)
}

#[cfg(test)]
mod pluggable_seam_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::*;
    use crate::{
        ai::safety::{OutboundCheck, OutboundDecision, PolicyCheck},
        auth::{AuthScope, Principal},
        blob::MemoryBlobStore,
        error::AppError,
        filter::{FilterDecision, InboundMessage},
        mcp::McpServer,
        models::LABEL_INBOX,
        storage::{AiMessagePage, AiSearchQuery, MemoryStore, NewMessageInput},
        transport::{OutboundMessage, SendOutcome, TransportCapabilities},
    };

    struct RecordingTransport {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl MailTransport for RecordingTransport {
        fn name(&self) -> &'static str {
            "custom_smtp"
        }

        fn capabilities(&self) -> TransportCapabilities {
            TransportCapabilities {
                provider: "custom_smtp".to_string(),
                supports_raw_mime: true,
                supports_scheduled_send: false,
                supports_idempotency_key: true,
                supports_inbound_webhooks: false,
                supports_delivery_webhooks: false,
                max_message_bytes: 25 * 1024 * 1024,
            }
        }

        async fn send(
            &self,
            _msg: &OutboundMessage,
            _idempotency_key: Option<&str>,
        ) -> AppResult<SendOutcome> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(SendOutcome {
                provider: "custom_smtp".to_string(),
                provider_message_id: format!("smtp_{n}"),
            })
        }
    }

    struct RejectKeywordFilter {
        keyword: String,
    }

    #[async_trait]
    impl InboundFilter for RejectKeywordFilter {
        async fn evaluate(&self, msg: &InboundMessage) -> AppResult<FilterDecision> {
            if msg.subject.contains(&self.keyword) {
                Ok(FilterDecision::Reject {
                    reason: format!("blocked keyword: {}", self.keyword),
                })
            } else {
                Ok(FilterDecision::Mutate {
                    add_labels: vec!["VERIFIED".to_string()],
                    remove_labels: vec![],
                    skip_inbox: false,
                })
            }
        }

        fn backend_name(&self) -> &'static str {
            "keyword_filter"
        }
    }

    struct CustomAuthProvider;

    #[async_trait]
    impl AuthProvider for CustomAuthProvider {
        async fn authenticate_bearer(&self, token: Option<&str>) -> AppResult<Principal> {
            if token == Some("jwt-valid") {
                Ok(Principal {
                    mailbox_id: "agent@example.com".to_string(),
                    shared_mailboxes: Vec::new(),
                    scopes: vec![AuthScope::Read, AuthScope::Write, AuthScope::Send],
                    agent_policy: None,
                })
            } else {
                Err(AppError::Unauthorized("custom auth denied".to_string()))
            }
        }

        async fn authenticate_imap(&self, username: &str, password: &str) -> AppResult<Principal> {
            if username == "imap-custom" && password == "secret-pass" {
                Ok(Principal::full_access("agent@example.com"))
            } else {
                Err(AppError::Unauthorized("bad imap creds".to_string()))
            }
        }

        fn backend_name(&self) -> &'static str {
            "custom_jwt"
        }
    }

    struct CountingSearchIndex {
        inner: StoreSearchIndex,
        searches: Arc<AtomicUsize>,
        indexed: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl SearchIndex for CountingSearchIndex {
        async fn index(&self, msg: &StoredMessage) -> AppResult<()> {
            self.indexed.fetch_add(1, Ordering::SeqCst);
            self.inner.index(msg).await
        }

        async fn remove(&self, message_id: &str) -> AppResult<()> {
            self.inner.remove(message_id).await
        }

        async fn search(&self, query: &AiSearchQuery) -> AppResult<AiMessagePage> {
            self.searches.fetch_add(1, Ordering::SeqCst);
            self.inner.search(query).await
        }

        fn backend_name(&self) -> &'static str {
            "counting_vector"
        }
    }

    struct ApprovalOrDenyPolicy {
        hold: bool,
    }

    #[async_trait]
    impl OutboundPolicy for ApprovalOrDenyPolicy {
        async fn evaluate(&self, _check: &OutboundCheck) -> AppResult<OutboundDecision> {
            if self.hold {
                Ok(OutboundDecision::HoldForApproval {
                    reason: "human sign-off required".to_string(),
                })
            } else {
                Ok(OutboundDecision::Deny {
                    code: "dlp_blocked".to_string(),
                    reason: "sensitive payload detected".to_string(),
                    hint: Some("Redact secrets before sending.".to_string()),
                })
            }
        }

        fn policy_checks(&self, _check: &OutboundCheck) -> Vec<PolicyCheck> {
            vec![PolicyCheck {
                rule: "custom_dlp".to_string(),
                passed: false,
                detail: "custom policy active".to_string(),
            }]
        }

        fn backend_name(&self) -> &'static str {
            "approval_policy"
        }
    }

    #[tokio::test]
    async fn capabilities_and_custom_auth_transport_search_blobs_filter_policy_seams() {
        let cfg = Config::for_test();
        let store = Arc::new(MemoryStore::new(&cfg.user_email));
        let resend = Arc::new(HttpResendClient::from_config(&cfg));
        let blobs = Arc::new(MemoryBlobStore::new());
        let transport_calls = Arc::new(AtomicUsize::new(0));
        let search_calls = Arc::new(AtomicUsize::new(0));
        let indexed_calls = Arc::new(AtomicUsize::new(0));

        let state = AppState::with_backends(cfg, store.clone(), resend)
            .with_blobs(blobs.clone())
            .with_transport(Arc::new(RecordingTransport {
                calls: transport_calls.clone(),
            }))
            .with_filter(Arc::new(RejectKeywordFilter {
                keyword: "BLOCKME".to_string(),
            }))
            .with_auth(Arc::new(CustomAuthProvider))
            .with_search(Arc::new(CountingSearchIndex {
                inner: StoreSearchIndex::new(store.clone()),
                searches: search_calls.clone(),
                indexed: indexed_calls.clone(),
            }));

        let app = build_router(state.clone());

        // 1. Custom AuthProvider blocks unauthenticated even when config.auth_tokens is empty.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/capabilities")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // 2. Custom AuthProvider accepts valid bearer token and /v1/capabilities advertises all 7 backends.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/capabilities")
                    .header("authorization", "Bearer jwt-valid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let caps: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(caps["backends"]["storage"], "memory");
        assert_eq!(caps["backends"]["blob"], "memory");
        assert_eq!(caps["backends"]["transport"], "custom_smtp");
        assert_eq!(caps["backends"]["filter"], "keyword_filter");
        assert_eq!(caps["backends"]["auth"], "custom_jwt");
        assert_eq!(caps["backends"]["search"], "counting_vector");
        assert_eq!(caps["backends"]["outbound_policy"], "config");

        // 3. Both /v1/messages/send and /gmail/v1/users/me/messages/send use custom MailTransport
        //    AND mirror raw RFC 2822 into MemoryBlobStore + index into SearchIndex.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages/send")
                    .header("authorization", "Bearer jwt-valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "to": ["alice@example.com"],
                            "subject": "Via custom transport",
                            "text": "Hello world"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let sent: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(sent["provider"], "custom_smtp");
        assert_eq!(sent["resend_id"], "smtp_1");
        let sent_msg_id = sent["message_id"].as_str().unwrap();
        assert!(
            blobs
                .get(&raw_message_blob_key(sent_msg_id))
                .await
                .unwrap()
                .is_some(),
            "raw RFC 2822 should be mirrored into external BlobStore"
        );

        let raw_gmail = mime::encode_base64url(
            b"From: agent@example.com\r\nTo: bob@example.com\r\nSubject: Gmail send\r\n\r\nBody",
        );
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/gmail/v1/users/me/messages/send")
                    .header("authorization", "Bearer jwt-valid")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "raw": raw_gmail }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(transport_calls.load(Ordering::SeqCst), 2);
        assert_eq!(indexed_calls.load(Ordering::SeqCst), 2);

        // 4. Gmail messages.import invokes InboundFilter (reject + mutate).
        let raw_blocked = mime::encode_base64url(
            b"From: bad@example.com\r\nTo: agent@example.com\r\nSubject: BLOCKME now\r\n\r\nSpam",
        );
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/gmail/v1/users/me/messages/import")
                    .header("authorization", "Bearer jwt-valid")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "raw": raw_blocked }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        let raw_ok = mime::encode_base64url(
            b"From: good@example.com\r\nTo: agent@example.com\r\nSubject: Allowed import\r\n\r\nHi",
        );
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/gmail/v1/users/me/messages/import")
                    .header("authorization", "Bearer jwt-valid")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "raw": raw_ok }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let imported: Value =
            serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
        let imported_labels: Vec<&str> = imported["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(imported_labels.contains(&"VERIFIED"));
        assert!(imported_labels.contains(&LABEL_INBOX));

        // 5. /v1/search AND MCP search_emails route through SearchIndex.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/search?q=transport")
                    .header("authorization", "Bearer jwt-valid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let mcp = McpServer::new(state.clone());
        let mcp_res = mcp
            .handle_request(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "search_emails",
                    "arguments": { "query": "transport" }
                }
            }))
            .await
            .unwrap()
            .unwrap();
        assert!(mcp_res.get("result").is_some());
        assert_eq!(search_calls.load(Ordering::SeqCst), 2);

        // 6. Sync inbound filter helper respects Reject.
        let mut sync_input = NewMessageInput {
            id: None,
            thread_id: None,
            label_ids: vec![LABEL_INBOX.to_string()],
            raw_rfc2822: b"From: a@b.com\r\nSubject: BLOCKME sync\r\n\r\nhi".to_vec(),
            snippet: "hi".into(),
            internal_date_ms: 1_700_000_000_000,
            subject: "BLOCKME sync".into(),
            from_addr: "a@b.com".into(),
            to_addrs: vec!["agent@example.com".into()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: "hi".into(),
            html_body: None,
            rfc822_message_id: None,
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id: Some("up_1".into()),
            upstream_thread_id: None,
            source: "gmail_api".into(),
            is_answered: false,
            is_deleted: false,
            attachments: vec![],
        };
        assert!(
            !sync::apply_sync_inbound_filter(&state, &mut sync_input)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn custom_outbound_policy_hold_for_approval_202_and_deny_403() {
        let cfg = Config::for_test();
        let store = Arc::new(MemoryStore::new(&cfg.user_email));
        let resend = Arc::new(HttpResendClient::from_config(&cfg));

        // HoldForApproval -> HTTP 202 Accepted
        let hold_state = AppState::with_backends(cfg.clone(), store.clone(), resend.clone())
            .with_outbound_policy(Arc::new(ApprovalOrDenyPolicy { hold: true }));
        let hold_app = build_router(hold_state);

        let res = hold_app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages/send")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "to": ["alice@example.com"],
                            "subject": "Needs approval",
                            "text": "Please review"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let body: Value =
            serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(body["status"], "pending_approval");
        assert_eq!(body["held_for_approval"], true);
        assert_eq!(body["reason"], "human sign-off required");
        assert!(body["draft_id"].as_str().is_some());

        // Deny -> HTTP 403 Forbidden with custom AI error code and hint
        let deny_state = AppState::with_backends(cfg, store, resend)
            .with_outbound_policy(Arc::new(ApprovalOrDenyPolicy { hold: false }));
        let deny_app = build_router(deny_state);

        let res = deny_app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages/send")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "to": ["alice@example.com"],
                            "subject": "Secret leak",
                            "text": "API_KEY=123"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let body: Value =
            serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(body["error"]["code"], "dlp_blocked");
        assert_eq!(body["error"]["hint"], "Redact secrets before sending.");
    }

    #[tokio::test]
    async fn capabilities_reports_configured_transport_backend() {
        use crate::config::TransportBackend;

        for (backend, expected_name) in [
            (TransportBackend::Resend, "resend"),
            (TransportBackend::Ses, "ses"),
            (TransportBackend::Smtp, "smtp"),
        ] {
            let mut cfg = Config::for_test();
            cfg.transport = backend;
            let state = AppState::from_config(cfg).expect("from_config should succeed");
            let app = build_router(state);

            let res = app
                .oneshot(
                    Request::builder()
                        .uri("/v1/capabilities")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let body = res.into_body().collect().await.unwrap().to_bytes();
            let caps: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(caps["backends"]["transport"], expected_name);
        }
    }
}
