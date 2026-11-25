use std::{net::SocketAddr, path::PathBuf};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

/// Selectable storage backend behind `MailStore`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageBackend {
    #[default]
    Sqlite,
    Memory,
}

/// Selectable blob storage backend behind `BlobStore`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobBackend {
    /// Store raw RFC 2822 and attachments inline inside `MailStore`.
    #[default]
    Inline,
    /// Mirror and serve raw RFC 2822 and attachments from local filesystem (`blob_dir`).
    Fs,
    /// Mirror and serve raw RFC 2822 and attachments from an in-memory blob store.
    Memory,
    /// Mirror and serve raw RFC 2822 and attachments from S3-compatible object storage (AWS S3, Cloudflare R2, MinIO).
    S3,
}

/// Selectable search index backend behind `SearchIndex`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchBackend {
    /// Default lexical search backed directly by `MailStore` (SQLite FTS5 or Memory).
    #[default]
    Store,
    /// Hybrid lexical + vector semantic search fused with Reciprocal Rank Fusion (RRF).
    Hybrid,
}

/// Selectable outbound mail transport backend behind `MailTransport`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportBackend {
    #[default]
    Resend,
    Ses,
    Smtp,
}

/// TLS mode for `SmtpTransport`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpTlsMode {
    /// Upgrade plaintext TCP connection with `STARTTLS` (typical port 587).
    #[default]
    Starttls,
    /// Implicit TLS / SMTPS from connection start (typical port 465).
    Tls,
    /// Plaintext TCP without TLS (for local relays and testing).
    None,
}

/// Behavior when `draft_only` is enabled and an agent attempts to send mail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftOnlyAction {
    #[default]
    Block,
    Downgrade,
}

/// Upstream Gmail sync transport mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncMode {
    #[default]
    Api,
    Imap,
}

/// Action taken by `AuthResultsFilter` when an SPF, DKIM, or DMARC check fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthFailAction {
    /// Do not alter the message on failure.
    Allow,
    /// Keep the message and add the `AUTH_FAIL` label.
    #[default]
    Tag,
    /// Route the message to `SPAM` (removing `INBOX`).
    Spam,
    /// Reject and drop the message prior to storage.
    Reject,
}

/// Action taken by `RspamdFilter` when Rspamd responds with `reject` or `soft reject`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RspamdRejectAction {
    /// Drop the message before storing in `MailStore`.
    #[default]
    Reject,
    /// Route the message to `SPAM` instead of dropping it.
    Spam,
}

/// Central runtime configuration for `nogml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    // --- HTTP server ---
    pub bind: SocketAddr,
    pub max_body_bytes: usize,
    pub cors_allow_origins: Vec<String>,

    // --- Pluggable storage ---
    pub storage: StorageBackend,
    pub db_path: PathBuf,
    pub blob_backend: BlobBackend,
    pub blob_dir: PathBuf,
    pub blob_s3_bucket: Option<String>,
    pub blob_s3_region: String,
    pub blob_s3_endpoint: Option<String>,
    pub blob_s3_prefix: Option<String>,
    pub blob_s3_access_key_id: Option<String>,
    pub blob_s3_secret_access_key: Option<String>,
    pub blob_s3_session_token: Option<String>,
    pub blob_s3_force_path_style: Option<bool>,

    // --- Auth & mailbox identity ---
    /// Allowed bearer tokens. Empty means dev unauthenticated mode.
    pub auth_tokens: Vec<String>,
    /// Primary mailbox email address (returned by `/profile` and used as default `From`).
    pub user_email: String,
    /// Default domain for generated Message-IDs and fallback sender addresses.
    pub default_domain: String,

    // --- Outbound mail transport ---
    pub transport: TransportBackend,

    // --- Resend outbound & inbound ---
    pub resend_api_key: Option<String>,
    pub resend_base_url: String,
    pub resend_webhook_secret: Option<String>,

    // --- AWS SES outbound & SNS/S3 inbound ---
    pub ses_region: String,
    pub ses_endpoint: Option<String>,
    pub ses_access_key_id: Option<String>,
    pub ses_secret_access_key: Option<String>,
    pub ses_session_token: Option<String>,
    pub ses_s3_endpoint: Option<String>,
    pub ses_webhook_secret: Option<String>,

    // --- SMTP outbound submission ---
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_tls_mode: SmtpTlsMode,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub smtp_helo_domain: Option<String>,

    // --- AI-first safety guardrails ---
    pub draft_only: bool,
    pub draft_only_action: DraftOnlyAction,
    /// When `true`, `ConfigOutboundPolicy` holds all outbound sends for human approval (HTTP `202`).
    pub require_approval: bool,
    /// Time-to-live in seconds for pending human approval requests (default 86400s / 24h).
    pub approval_ttl_secs: u64,
    /// Optional webhook URL notified via HTTP POST whenever a send enters `HoldForApproval`.
    pub approval_webhook_url: Option<String>,
    /// Empty = allow all recipients. Entries match exact email (case-insensitive) or `@domain` / `*.domain`.
    pub allowed_recipients: Vec<String>,
    pub max_send_recipients: usize,
    pub default_max_body_chars: usize,
    pub untrusted_content_guard: bool,

    // --- Embedded IMAP4rev1 server ---
    pub imap_bind: Option<SocketAddr>,
    pub imap_tls_bind: Option<SocketAddr>,
    pub imap_tls_cert: Option<PathBuf>,
    pub imap_tls_key: Option<PathBuf>,
    pub imap_username: Option<String>,
    pub imap_password: Option<String>,

    // --- Upstream Gmail sync ---
    pub sync_mode: SyncMode,
    pub gmail_client_id: Option<String>,
    pub gmail_client_secret: Option<String>,
    pub gmail_refresh_token: Option<String>,
    pub gmail_access_token: Option<String>,
    pub gmail_user_id: String,
    pub gmail_api_base_url: String,
    pub gmail_oauth_token_url: String,
    pub gmail_imap_host: String,
    pub gmail_imap_port: u16,
    pub gmail_imap_tls: bool,
    pub gmail_imap_user: Option<String>,
    pub gmail_imap_password: Option<String>,
    pub gmail_imap_mailbox: String,
    pub sync_interval_secs: u64,
    pub sync_query: Option<String>,
    pub sync_max_messages: Option<usize>,
    /// When `true`, push local label/flag/trash/delete changes back to the upstream account.
    pub sync_bidirectional: bool,

    // --- Optional Gmail /watch push webhook ---
    pub watch_webhook_url: Option<String>,

    // --- Inbound filter pipeline ---
    /// Enable `AuthResultsFilter` to evaluate `Authentication-Results` headers.
    pub filter_auth_results: bool,
    /// Action on `dmarc=fail` (`spam`, `reject`, `tag`, `allow`).
    pub filter_dmarc_fail_action: AuthFailAction,
    /// Action on `spf=fail` (`spam`, `reject`, `tag`, `allow`).
    pub filter_spf_fail_action: AuthFailAction,
    /// Action on `dkim=fail` (`spam`, `reject`, `tag`, `allow`).
    pub filter_dkim_fail_action: AuthFailAction,

    /// Base URL for Rspamd (`{rspamd_url}/checkv2`). Enables `RspamdFilter` when set.
    pub rspamd_url: Option<String>,
    /// Optional Rspamd controller/scan `Password` header value.
    pub rspamd_password: Option<String>,
    /// HTTP timeout for Rspamd `/checkv2` calls in milliseconds (default 5000).
    pub rspamd_timeout_ms: u64,
    /// Optional score threshold override for classifying as `Spam`.
    pub rspamd_spam_threshold: Option<f32>,
    /// Action on Rspamd `reject` / `soft reject` (`reject` or `spam`).
    pub rspamd_reject_action: RspamdRejectAction,
    /// When `true`, reject mail if Rspamd is unreachable or times out (default `false`, fail-open).
    pub rspamd_fail_closed: bool,

    /// Base URL for an OpenAI-compatible chat completions API (`{url}/chat/completions`).
    /// Setting either `llm_triage_base_url` or `llm_triage_api_key` enables `LlmTriageFilter`.
    pub llm_triage_base_url: Option<String>,
    /// Optional Bearer API key for the LLM triage endpoint.
    pub llm_triage_api_key: Option<String>,
    /// Model name passed to `/chat/completions` for inbound triage.
    pub llm_triage_model: String,
    /// HTTP timeout for LLM triage calls in milliseconds (default 10000).
    pub llm_triage_timeout_ms: u64,
    /// Maximum plain-text body characters included in the LLM triage prompt (default 2000).
    pub llm_triage_max_body_chars: usize,

    // --- Pluggable search & embeddings ---
    /// Search index backend (`store` [default] or `hybrid`).
    pub search_backend: SearchBackend,
    /// OpenAI-compatible embeddings base URL (`{url}/embeddings`, e.g. OpenAI, Ollama `/v1`).
    pub embedding_base_url: Option<String>,
    /// Optional Bearer API key for the embeddings endpoint.
    pub embedding_api_key: Option<String>,
    /// Embedding model name sent to `/embeddings`.
    pub embedding_model: String,
    /// HTTP timeout for embedding requests in seconds (default 15).
    pub embedding_timeout_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080".parse().expect("valid default bind"),
            max_body_bytes: 40 * 1024 * 1024, // 40 MB (Resend attachment ceiling)
            cors_allow_origins: Vec::new(),

            storage: StorageBackend::Sqlite,
            db_path: PathBuf::from("nogml.db"),
            blob_backend: BlobBackend::Inline,
            blob_dir: PathBuf::from("nogml-blobs"),
            blob_s3_bucket: None,
            blob_s3_region: "us-east-1".to_string(),
            blob_s3_endpoint: None,
            blob_s3_prefix: None,
            blob_s3_access_key_id: None,
            blob_s3_secret_access_key: None,
            blob_s3_session_token: None,
            blob_s3_force_path_style: None,

            auth_tokens: Vec::new(),
            user_email: "me@localhost".to_string(),
            default_domain: "localhost".to_string(),

            transport: TransportBackend::Resend,

            resend_api_key: None,
            resend_base_url: "https://api.resend.com".to_string(),
            resend_webhook_secret: None,

            ses_region: "us-east-1".to_string(),
            ses_endpoint: None,
            ses_access_key_id: None,
            ses_secret_access_key: None,
            ses_session_token: None,
            ses_s3_endpoint: None,
            ses_webhook_secret: None,

            smtp_host: "127.0.0.1".to_string(),
            smtp_port: 587,
            smtp_tls_mode: SmtpTlsMode::Starttls,
            smtp_username: None,
            smtp_password: None,
            smtp_helo_domain: None,

            draft_only: false,
            draft_only_action: DraftOnlyAction::Block,
            require_approval: false,
            approval_ttl_secs: 86_400,
            approval_webhook_url: None,
            allowed_recipients: Vec::new(),
            max_send_recipients: 50,
            default_max_body_chars: 4000,
            untrusted_content_guard: true,

            imap_bind: None,
            imap_tls_bind: None,
            imap_tls_cert: None,
            imap_tls_key: None,
            imap_username: None,
            imap_password: None,

            sync_mode: SyncMode::Api,
            gmail_client_id: None,
            gmail_client_secret: None,
            gmail_refresh_token: None,
            gmail_access_token: None,
            gmail_user_id: "me".to_string(),
            gmail_api_base_url: "https://gmail.googleapis.com".to_string(),
            gmail_oauth_token_url: "https://oauth2.googleapis.com/token".to_string(),
            gmail_imap_host: "imap.gmail.com".to_string(),
            gmail_imap_port: 993,
            gmail_imap_tls: true,
            gmail_imap_user: None,
            gmail_imap_password: None,
            gmail_imap_mailbox: "[Gmail]/All Mail".to_string(),
            sync_interval_secs: 0,
            sync_query: None,
            sync_max_messages: None,
            sync_bidirectional: false,

            watch_webhook_url: None,

            filter_auth_results: false,
            filter_dmarc_fail_action: AuthFailAction::Spam,
            filter_spf_fail_action: AuthFailAction::Tag,
            filter_dkim_fail_action: AuthFailAction::Tag,

            rspamd_url: None,
            rspamd_password: None,
            rspamd_timeout_ms: 5_000,
            rspamd_spam_threshold: None,
            rspamd_reject_action: RspamdRejectAction::Reject,
            rspamd_fail_closed: false,

            llm_triage_base_url: None,
            llm_triage_api_key: None,
            llm_triage_model: "gpt-4o-mini".to_string(),
            llm_triage_timeout_ms: 10_000,
            llm_triage_max_body_chars: 2_000,

            search_backend: SearchBackend::Store,
            embedding_base_url: None,
            embedding_api_key: None,
            embedding_model: "text-embedding-3-small".to_string(),
            embedding_timeout_secs: 15,
        }
    }
}

impl Config {
    /// Convenient in-memory test configuration with unauthenticated dev mode enabled.
    pub fn for_test() -> Self {
        Self {
            storage: StorageBackend::Memory,
            user_email: "agent@example.com".to_string(),
            default_domain: "example.com".to_string(),
            ..Self::default()
        }
    }

    /// Returns `true` when bearer token authentication is enforced.
    pub fn auth_required(&self) -> bool {
        !self.auth_tokens.is_empty()
    }

    /// Returns `true` when any upstream Gmail sync credentials are configured.
    pub fn gmail_sync_configured(&self) -> bool {
        match self.sync_mode {
            SyncMode::Api => {
                self.gmail_access_token.is_some()
                    || (self.gmail_client_id.is_some()
                        && self.gmail_client_secret.is_some()
                        && self.gmail_refresh_token.is_some())
            }
            SyncMode::Imap => self.gmail_imap_user.is_some() && self.gmail_imap_password.is_some(),
        }
    }

    /// Effective IMAP username (falls back to `user_email`).
    pub fn effective_imap_username(&self) -> &str {
        self.imap_username.as_deref().unwrap_or(&self.user_email)
    }

    /// Effective IMAP password (falls back to first configured bearer token if any).
    pub fn effective_imap_password(&self) -> Option<&str> {
        self.imap_password
            .as_deref()
            .or_else(|| self.auth_tokens.first().map(String::as_str))
    }

    /// Returns `true` when `RspamdFilter` is configured with a non-empty URL.
    pub fn rspamd_enabled(&self) -> bool {
        self.rspamd_url
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
    }

    /// Returns `true` when `LlmTriageFilter` is enabled via base URL or API key.
    pub fn llm_triage_enabled(&self) -> bool {
        self.llm_triage_base_url
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
            || self
                .llm_triage_api_key
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
    }
}
