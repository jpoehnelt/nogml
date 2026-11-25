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

    // --- Auth & mailbox identity ---
    /// Allowed bearer tokens. Empty means dev unauthenticated mode.
    pub auth_tokens: Vec<String>,
    /// Primary mailbox email address (returned by `/profile` and used as default `From`).
    pub user_email: String,
    /// Default domain for generated Message-IDs and fallback sender addresses.
    pub default_domain: String,

    // --- Resend outbound & inbound ---
    pub resend_api_key: Option<String>,
    pub resend_base_url: String,
    pub resend_webhook_secret: Option<String>,

    // --- AI-first safety guardrails ---
    pub draft_only: bool,
    pub draft_only_action: DraftOnlyAction,
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

    // --- Optional Gmail /watch push webhook ---
    pub watch_webhook_url: Option<String>,
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

            auth_tokens: Vec::new(),
            user_email: "me@localhost".to_string(),
            default_domain: "localhost".to_string(),

            resend_api_key: None,
            resend_base_url: "https://api.resend.com".to_string(),
            resend_webhook_secret: None,

            draft_only: false,
            draft_only_action: DraftOnlyAction::Block,
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

            watch_webhook_url: None,
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
}
