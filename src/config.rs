use std::{
    collections::{HashMap, HashSet},
    fmt, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

use crate::{
    auth::ScopedTokenConfig,
    blob::S3BlobConfig,
    error::{AppError, AppResult},
    search_index::OpenAiEmbeddingConfig,
    secrets::{
        REDACTED, SecretResolutionReport, ValueOrigin, check_secret_file_permissions,
        read_secret_file, resolve_secret_tokens, resolve_secret_value, split_token_list,
        system_env_lookup,
    },
    transport::{SesConfig, SmtpConfig},
};

/// Normalize a mailbox identifier (email address) by trimming whitespace and lowercasing ASCII.
pub fn normalize_mailbox_id(mailbox_id: &str) -> String {
    mailbox_id.trim().to_ascii_lowercase()
}

/// Parse a comma-separated list of mailbox alias mappings (`alias@example.com=target@example.com`)
/// into a normalized lowercase `HashMap<alias, target>`.
pub fn parse_mailbox_aliases(raw: &str) -> AppResult<HashMap<String, String>> {
    let mut out = HashMap::new();
    for entry in raw.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((alias_raw, target_raw)) = trimmed.split_once('=') else {
            return Err(AppError::Config(format!(
                "Invalid mailbox alias mapping '{trimmed}': expected 'alias@domain=target@domain'"
            )));
        };
        let alias = normalize_mailbox_id(alias_raw);
        let target = normalize_mailbox_id(target_raw);
        if alias.is_empty() || !alias.contains('@') || alias.contains(char::is_whitespace) {
            return Err(AppError::Config(format!(
                "Invalid mailbox alias address '{alias_raw}' in '{trimmed}'"
            )));
        }
        if target.is_empty() || !target.contains('@') || target.contains(char::is_whitespace) {
            return Err(AppError::Config(format!(
                "Invalid mailbox alias target '{target_raw}' in '{trimmed}'"
            )));
        }
        out.insert(alias, target);
    }
    Ok(out)
}

/// Normalize all keys and target values in a mailbox alias map to trimmed lowercase strings.
pub fn normalize_mailbox_aliases(aliases: &HashMap<String, String>) -> HashMap<String, String> {
    let mut out = HashMap::with_capacity(aliases.len());
    for (k, v) in aliases {
        let key = normalize_mailbox_id(k);
        let val = normalize_mailbox_id(v);
        if !key.is_empty() && !val.is_empty() {
            out.insert(key, val);
        }
    }
    out
}

/// Extract normalized lowercase email addresses from raw header/recipient entries
/// (supporting `"Display Name <user@example.com>"`, comma-separated address lists,
/// angle-bracketed addresses, and bare email strings).
pub fn extract_email_addresses(raw_entries: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut push_addr = |candidate: &str| {
        let trimmed = candidate.trim().trim_matches(|c| c == '"' || c == '\'');
        let email = if let (Some(lt), Some(gt)) = (trimmed.find('<'), trimmed.rfind('>'))
            && lt < gt
        {
            trimmed[lt + 1..gt].trim()
        } else {
            trimmed
        };
        let norm = normalize_mailbox_id(email);
        if norm.contains('@') && !norm.contains(char::is_whitespace) && !out.contains(&norm) {
            out.push(norm);
        }
    };

    for entry in raw_entries {
        // Split comma-separated lists while ignoring commas inside quotes.
        let mut current = String::new();
        let mut in_quotes = false;
        for ch in entry.chars() {
            match ch {
                '"' => {
                    in_quotes = !in_quotes;
                    current.push(ch);
                }
                ',' if !in_quotes => {
                    push_addr(&current);
                    current.clear();
                }
                _ => current.push(ch),
            }
        }
        if !current.is_empty() {
            push_addr(&current);
        }
    }

    out
}

/// Selectable storage backend behind `MailStore`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageBackend {
    #[default]
    Sqlite,
    Memory,
    Postgres,
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

/// Action taken by `DlpOutboundPolicy` when outbound mail matches a secret or PII pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DlpAction {
    /// Disable outbound secret and PII DLP scanning.
    #[default]
    Off,
    /// Hold matching sends in the persistent approval queue (HTTP `202`).
    Hold,
    /// Reject matching sends immediately (HTTP `403`).
    Deny,
}

/// Upstream Gmail sync transport mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncMode {
    #[default]
    Api,
    Imap,
}

fn default_gmail_user_id() -> String {
    "me".to_string()
}

fn default_gmail_api_base_url() -> String {
    "https://gmail.googleapis.com".to_string()
}

fn default_gmail_oauth_token_url() -> String {
    "https://oauth2.googleapis.com/token".to_string()
}

fn default_gmail_imap_host() -> String {
    "imap.gmail.com".to_string()
}

fn default_gmail_imap_port() -> u16 {
    993
}

fn default_true() -> bool {
    true
}

fn default_gmail_imap_mailbox() -> String {
    "[Gmail]/All Mail".to_string()
}

fn default_gmail_imap_archive_mailbox() -> String {
    "Archive".to_string()
}

/// Per-account upstream Gmail sync configuration entry parsed from `[[sync.accounts]]`.
///
/// Implements a custom [`fmt::Debug`] that replaces all credential and token fields
/// with `"[REDACTED]"`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SyncAccountConfig {
    pub mailbox_id: String,
    pub mode: SyncMode,
    pub interval_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_messages: Option<usize>,
    pub bidirectional: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gmail_client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gmail_client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gmail_refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gmail_access_token: Option<String>,
    #[serde(default = "default_gmail_user_id")]
    pub gmail_user_id: String,
    #[serde(default = "default_gmail_api_base_url")]
    pub gmail_api_base_url: String,
    #[serde(default = "default_gmail_oauth_token_url")]
    pub gmail_oauth_token_url: String,
    #[serde(default = "default_gmail_imap_host")]
    pub gmail_imap_host: String,
    #[serde(default = "default_gmail_imap_port")]
    pub gmail_imap_port: u16,
    #[serde(default = "default_true")]
    pub gmail_imap_tls: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gmail_imap_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gmail_imap_password: Option<String>,
    #[serde(default = "default_gmail_imap_mailbox")]
    pub gmail_imap_mailbox: String,
    #[serde(default)]
    pub gmail_imap_folders: Vec<String>,
    #[serde(default = "default_gmail_imap_archive_mailbox")]
    pub gmail_imap_archive_mailbox: String,
    #[serde(default)]
    pub gmail_imap_idle: bool,
}

impl Default for SyncAccountConfig {
    fn default() -> Self {
        Self {
            mailbox_id: String::new(),
            mode: SyncMode::Api,
            interval_secs: 0,
            query: None,
            max_messages: None,
            bidirectional: false,
            gmail_client_id: None,
            gmail_client_secret: None,
            gmail_refresh_token: None,
            gmail_access_token: None,
            gmail_user_id: default_gmail_user_id(),
            gmail_api_base_url: default_gmail_api_base_url(),
            gmail_oauth_token_url: default_gmail_oauth_token_url(),
            gmail_imap_host: default_gmail_imap_host(),
            gmail_imap_port: default_gmail_imap_port(),
            gmail_imap_tls: default_true(),
            gmail_imap_user: None,
            gmail_imap_password: None,
            gmail_imap_mailbox: default_gmail_imap_mailbox(),
            gmail_imap_folders: Vec::new(),
            gmail_imap_archive_mailbox: default_gmail_imap_archive_mailbox(),
            gmail_imap_idle: false,
        }
    }
}

impl fmt::Debug for SyncAccountConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyncAccountConfig")
            .field("mailbox_id", &self.mailbox_id)
            .field("mode", &self.mode)
            .field("interval_secs", &self.interval_secs)
            .field("query", &self.query)
            .field("max_messages", &self.max_messages)
            .field("bidirectional", &self.bidirectional)
            .field("gmail_client_id", &self.gmail_client_id)
            .field(
                "gmail_client_secret",
                &redacted_opt_debug(&self.gmail_client_secret),
            )
            .field(
                "gmail_refresh_token",
                &redacted_opt_debug(&self.gmail_refresh_token),
            )
            .field(
                "gmail_access_token",
                &redacted_opt_debug(&self.gmail_access_token),
            )
            .field("gmail_user_id", &self.gmail_user_id)
            .field("gmail_api_base_url", &self.gmail_api_base_url)
            .field("gmail_oauth_token_url", &self.gmail_oauth_token_url)
            .field("gmail_imap_host", &self.gmail_imap_host)
            .field("gmail_imap_port", &self.gmail_imap_port)
            .field("gmail_imap_tls", &self.gmail_imap_tls)
            .field("gmail_imap_user", &self.gmail_imap_user)
            .field(
                "gmail_imap_password",
                &redacted_opt_debug(&self.gmail_imap_password),
            )
            .field("gmail_imap_mailbox", &self.gmail_imap_mailbox)
            .field("gmail_imap_folders", &self.gmail_imap_folders)
            .field(
                "gmail_imap_archive_mailbox",
                &self.gmail_imap_archive_mailbox,
            )
            .field("gmail_imap_idle", &self.gmail_imap_idle)
            .finish()
    }
}

impl SyncAccountConfig {
    /// Returns `true` when Gmail OAuth2 credentials (static access token or refresh flow) are set.
    pub fn has_gmail_oauth2(&self) -> bool {
        self.gmail_access_token
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
            || (self
                .gmail_client_id
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
                && self
                    .gmail_client_secret
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty())
                && self
                    .gmail_refresh_token
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty()))
    }

    /// Returns `true` when upstream Gmail sync credentials are configured for this account.
    pub fn is_configured(&self) -> bool {
        match self.mode {
            SyncMode::Api => self.has_gmail_oauth2(),
            SyncMode::Imap => {
                self.gmail_imap_user
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty())
                    && (self
                        .gmail_imap_password
                        .as_deref()
                        .is_some_and(|s| !s.is_empty())
                        || self.has_gmail_oauth2())
            }
        }
    }

    /// Return a cloned [`Config`] scoped to `self.mailbox_id` with all sync settings overridden
    /// from this account entry.
    pub fn apply_to_config(&self, base: &Config) -> Config {
        let mut cfg = base.clone();
        let target = normalize_mailbox_id(&self.mailbox_id);
        if !target.is_empty() {
            let base_primary = normalize_mailbox_id(&base.user_email);
            if !base_primary.is_empty()
                && base_primary != target
                && !cfg
                    .mailboxes
                    .iter()
                    .any(|m| normalize_mailbox_id(m) == base_primary)
            {
                cfg.mailboxes.push(base_primary);
            }
            cfg.user_email = target;
        }
        cfg.sync_mode = self.mode;
        cfg.sync_interval_secs = self.interval_secs;
        cfg.sync_query = self.query.clone();
        cfg.sync_max_messages = self.max_messages;
        cfg.sync_bidirectional = self.bidirectional;
        cfg.gmail_client_id = self.gmail_client_id.clone();
        cfg.gmail_client_secret = self.gmail_client_secret.clone();
        cfg.gmail_refresh_token = self.gmail_refresh_token.clone();
        cfg.gmail_access_token = self.gmail_access_token.clone();
        cfg.gmail_user_id = self.gmail_user_id.clone();
        cfg.gmail_api_base_url = self.gmail_api_base_url.clone();
        cfg.gmail_oauth_token_url = self.gmail_oauth_token_url.clone();
        cfg.gmail_imap_host = self.gmail_imap_host.clone();
        cfg.gmail_imap_port = self.gmail_imap_port;
        cfg.gmail_imap_tls = self.gmail_imap_tls;
        cfg.gmail_imap_user = self.gmail_imap_user.clone();
        cfg.gmail_imap_password = self.gmail_imap_password.clone();
        cfg.gmail_imap_mailbox = self.gmail_imap_mailbox.clone();
        cfg.gmail_imap_folders = self.gmail_imap_folders.clone();
        cfg.gmail_imap_archive_mailbox = self.gmail_imap_archive_mailbox.clone();
        cfg.gmail_imap_idle = self.gmail_imap_idle;
        cfg
    }

    /// Return a redacted JSON summary of this account for `nogml config check`.
    pub fn redacted_summary(&self) -> Value {
        let redact_opt = |opt: &Option<String>| -> Value {
            if opt.is_some() {
                Value::String(REDACTED.to_string())
            } else {
                Value::Null
            }
        };
        json!({
            "mailbox_id": self.mailbox_id,
            "mode": self.mode,
            "interval_secs": self.interval_secs,
            "query": self.query,
            "max_messages": self.max_messages,
            "bidirectional": self.bidirectional,
            "gmail_client_id": self.gmail_client_id,
            "gmail_client_secret": redact_opt(&self.gmail_client_secret),
            "gmail_refresh_token": redact_opt(&self.gmail_refresh_token),
            "gmail_access_token": redact_opt(&self.gmail_access_token),
            "gmail_user_id": self.gmail_user_id,
            "gmail_api_base_url": self.gmail_api_base_url,
            "gmail_oauth_token_url": self.gmail_oauth_token_url,
            "gmail_imap_host": self.gmail_imap_host,
            "gmail_imap_port": self.gmail_imap_port,
            "gmail_imap_tls": self.gmail_imap_tls,
            "gmail_imap_user": self.gmail_imap_user,
            "gmail_imap_password": redact_opt(&self.gmail_imap_password),
            "gmail_imap_mailbox": self.gmail_imap_mailbox,
            "gmail_imap_folders": self.gmail_imap_folders,
            "gmail_imap_archive_mailbox": self.gmail_imap_archive_mailbox,
            "gmail_imap_idle": self.gmail_imap_idle,
        })
    }
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
///
/// Implements a custom [`fmt::Debug`] that replaces all secret, password, token, and
/// credential fields with `"[REDACTED]"`.
#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    // --- HTTP server ---
    pub bind: SocketAddr,
    pub max_body_bytes: usize,
    pub cors_allow_origins: Vec<String>,

    // --- Pluggable storage ---
    pub storage: StorageBackend,
    pub db_path: PathBuf,
    pub database_url: Option<String>,
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
    /// Allowed bearer tokens (full scopes). Empty means dev unauthenticated mode unless
    /// `scoped_tokens` or local OAuth2 is configured.
    pub auth_tokens: Vec<String>,
    /// Scoped API keys with explicit scopes and optional per-agent outbound safety overrides.
    pub scoped_tokens: Vec<ScopedTokenConfig>,
    /// Optional local OAuth2 client ID (enables `/oauth2/*` and JWT verification when paired
    /// with `oauth2_signing_secret`).
    pub oauth2_client_id: Option<String>,
    /// Optional local OAuth2 client secret verified on `POST /oauth2/token` when set.
    pub oauth2_client_secret: Option<String>,
    /// HMAC-SHA256 (`HS256`) signing secret for local OAuth2 JWT access/refresh tokens.
    pub oauth2_signing_secret: Option<String>,
    /// Allowlisted OAuth2 `redirect_uri` values permitted on `GET /oauth2/authorize`
    /// (`NOGML_OAUTH2_REDIRECT_URIS` / `--oauth2-redirect-uris` / `[oauth2].redirect_uris`).
    #[serde(default)]
    pub oauth2_redirect_uris: Vec<String>,
    /// Primary mailbox email address (returned by `/profile` and used as default `From`).
    pub user_email: String,
    /// Additional local mailbox email addresses hosted by this instance (`NOGML_MAILBOXES` / `--mailboxes`).
    #[serde(default)]
    pub mailboxes: Vec<String>,
    /// Mailbox alias map (`alias@example.com` -> `target@example.com`) configured via
    /// `[mailboxes.aliases]` or `NOGML_MAILBOX_ALIASES`.
    #[serde(default)]
    pub mailbox_aliases: HashMap<String, String>,
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
    /// Optional AWS SNS TopicArn allowlist for `POST /webhooks/ses`.
    #[serde(default)]
    pub ses_allowed_topic_arns: Vec<String>,
    /// Optional S3 bucket name allowlist for SES S3 inbound receipt actions.
    #[serde(default)]
    pub ses_allowed_s3_buckets: Vec<String>,

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
    /// When `true`, `FirstContactPolicy` holds outbound sends to recipients with no prior sent history.
    pub first_contact_approval: bool,
    /// When `true`, outbound sends reject `From` domains that are neither the configured
    /// primary domain nor a `verified` BYOD domain owned by the sender's mailbox.
    #[serde(default)]
    pub require_verified_from_domain: bool,
    /// Action taken by `DlpOutboundPolicy` when secrets or sensitive PII are detected (`off`, `hold`, `deny`).
    pub dlp_action: DlpAction,
    /// Time-to-live in seconds for pending human approval requests (default 86400s / 24h).
    pub approval_ttl_secs: u64,
    /// Optional webhook URL notified via HTTP POST whenever a send enters `HoldForApproval`.
    pub approval_webhook_url: Option<String>,
    /// Empty = allow all recipients. Entries match exact email (case-insensitive) or `@domain` / `*.domain`.
    pub allowed_recipients: Vec<String>,
    pub max_send_recipients: usize,
    pub default_max_body_chars: usize,
    pub untrusted_content_guard: bool,
    /// Optional host allowlist for outbound inbox rule webhooks (exact host or `*.domain`).
    #[serde(default)]
    pub webhook_allowed_hosts: Vec<String>,
    /// Explicit dev/test opt-in allowing private/loopback/HTTP webhook & download endpoints.
    /// Must remain `false` in production.
    #[serde(default)]
    pub allow_private_endpoints: bool,
    /// Explicit dev/test opt-in allowing unsigned `/webhooks/resend` and `/webhooks/ses`
    /// requests when webhook secrets are unset. Must remain `false` in production.
    #[serde(default)]
    pub allow_insecure_webhooks: bool,

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
    /// Optional list of IMAP folders to sync with independent per-folder checkpoints
    /// (`NOGML_GMAIL_IMAP_FOLDERS` / `[sync].gmail_imap_folders`). When non-empty, supersedes
    /// the single `gmail_imap_mailbox` setting for multi-folder IMAP servers.
    #[serde(default)]
    pub gmail_imap_folders: Vec<String>,
    /// Target archive folder for non-Gmail IMAP servers without `X-GM-EXT-1` (default `"Archive"`).
    #[serde(default = "default_gmail_imap_archive_mailbox")]
    pub gmail_imap_archive_mailbox: String,
    /// When `true`, maintain a dedicated read-only background IMAP `IDLE` connection to trigger
    /// immediate incremental sync on server updates (default `false`).
    #[serde(default)]
    pub gmail_imap_idle: bool,
    pub sync_interval_secs: u64,
    pub sync_query: Option<String>,
    pub sync_max_messages: Option<usize>,
    /// When `true`, push local label/flag/trash/delete changes back to the upstream account.
    pub sync_bidirectional: bool,
    /// Optional multi-account upstream Gmail sync configurations (`[[sync.accounts]]`).
    #[serde(default)]
    pub sync_accounts: Vec<SyncAccountConfig>,

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

    // --- Security & encryption at rest ---
    /// Master AES-256-GCM encryption key for stored secrets (`<kid>:<key>` or bare 32-byte
    /// base64/hex key defaulting to `kid = "k1"`). Supports `file://`, `env://`, and
    /// `NOGML_ENCRYPTION_KEY_FILE`.
    #[serde(default)]
    pub encryption_key: Option<String>,
    /// Previous encryption keys (`<kid>:<key>`) retained for zero-downtime key rotation
    /// (`NOGML_ENCRYPTION_PREVIOUS_KEYS` / `NOGML_ENCRYPTION_PREVIOUS_KEYS_FILE`).
    #[serde(default)]
    pub encryption_previous_keys: Vec<String>,

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
            database_url: None,
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
            scoped_tokens: Vec::new(),
            oauth2_client_id: None,
            oauth2_client_secret: None,
            oauth2_signing_secret: None,
            oauth2_redirect_uris: Vec::new(),
            user_email: "me@localhost".to_string(),
            mailboxes: Vec::new(),
            mailbox_aliases: HashMap::new(),
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
            ses_allowed_topic_arns: Vec::new(),
            ses_allowed_s3_buckets: Vec::new(),

            smtp_host: "127.0.0.1".to_string(),
            smtp_port: 587,
            smtp_tls_mode: SmtpTlsMode::Starttls,
            smtp_username: None,
            smtp_password: None,
            smtp_helo_domain: None,

            draft_only: false,
            draft_only_action: DraftOnlyAction::Block,
            require_approval: false,
            first_contact_approval: false,
            require_verified_from_domain: false,
            dlp_action: DlpAction::Off,
            approval_ttl_secs: 86_400,
            approval_webhook_url: None,
            allowed_recipients: Vec::new(),
            max_send_recipients: 50,
            default_max_body_chars: 4000,
            untrusted_content_guard: true,
            webhook_allowed_hosts: Vec::new(),
            allow_private_endpoints: false,
            allow_insecure_webhooks: false,

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
            gmail_imap_folders: Vec::new(),
            gmail_imap_archive_mailbox: default_gmail_imap_archive_mailbox(),
            gmail_imap_idle: false,
            sync_interval_secs: 0,
            sync_query: None,
            sync_max_messages: None,
            sync_bidirectional: false,
            sync_accounts: Vec::new(),

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

            encryption_key: None,
            encryption_previous_keys: Vec::new(),

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

    /// Returns `true` when the optional local OAuth2 provider is enabled
    /// (`oauth2_client_id` and `oauth2_signing_secret` are both non-empty).
    pub fn oauth2_enabled(&self) -> bool {
        self.oauth2_client_id
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
            && self
                .oauth2_signing_secret
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
    }

    /// Returns `true` when bearer token authentication is enforced.
    pub fn auth_required(&self) -> bool {
        !self.auth_tokens.is_empty() || !self.scoped_tokens.is_empty() || self.oauth2_enabled()
    }

    /// Return the deduplicated, normalized list of all local mailboxes known to this instance:
    /// `user_email`, `mailboxes`, `mailbox_aliases` targets, `scoped_tokens` (`mailbox_id` and
    /// `shared_mailboxes`), and `sync_accounts` `mailbox_id` entries.
    pub fn known_mailboxes(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut push_unique = |raw: &str| {
            let norm = normalize_mailbox_id(raw);
            if !norm.is_empty() && !out.contains(&norm) {
                out.push(norm);
            }
        };

        push_unique(&self.user_email);
        for mb in &self.mailboxes {
            push_unique(mb);
        }
        for target in self.mailbox_aliases.values() {
            push_unique(target);
        }
        for st in &self.scoped_tokens {
            if let Some(ref mb) = st.mailbox_id {
                push_unique(mb);
            }
            for shared in &st.shared_mailboxes {
                push_unique(shared);
            }
        }
        for acct in &self.sync_accounts {
            push_unique(&acct.mailbox_id);
        }
        out
    }

    /// Returns `true` when more than one local mailbox is configured across `user_email`,
    /// `mailboxes`, `mailbox_aliases`, `scoped_tokens`, and `sync_accounts`.
    pub fn is_multi_mailbox(&self) -> bool {
        self.known_mailboxes().len() > 1
    }

    /// Returns `true` when inbound webhooks should strictly route by recipient address
    /// (true whenever `mailboxes` or `mailbox_aliases` is non-empty, or more than one mailbox is known).
    pub fn has_explicit_mailbox_routing(&self) -> bool {
        !self.mailboxes.is_empty() || !self.mailbox_aliases.is_empty() || self.is_multi_mailbox()
    }

    /// Look up the target mailbox for `address` in `mailbox_aliases` (case-insensitive).
    pub fn resolve_alias_target(&self, address: &str) -> Option<String> {
        let norm = normalize_mailbox_id(address);
        if norm.is_empty() {
            return None;
        }
        if let Some(target) = self.mailbox_aliases.get(&norm) {
            let norm_target = normalize_mailbox_id(target);
            return (!norm_target.is_empty()).then_some(norm_target);
        }
        self.mailbox_aliases
            .iter()
            .find(|(k, _)| normalize_mailbox_id(k) == norm)
            .map(|(_, v)| normalize_mailbox_id(v))
            .filter(|v| !v.is_empty())
    }

    /// Return all normalized alias addresses configured to target `mailbox_id`.
    pub fn aliases_for_mailbox(&self, mailbox_id: &str) -> Vec<String> {
        let target_norm = normalize_mailbox_id(mailbox_id);
        if target_norm.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        for (alias, target) in &self.mailbox_aliases {
            if normalize_mailbox_id(target) == target_norm {
                let alias_norm = normalize_mailbox_id(alias);
                if !alias_norm.is_empty() && alias_norm != target_norm && !out.contains(&alias_norm)
                {
                    out.push(alias_norm);
                }
            }
        }
        out.sort();
        out
    }

    /// Returns `true` when `candidate_from` (bare email or `"Display Name <email>"`) matches
    /// `mailbox_id` itself or a configured alias targeting `mailbox_id`.
    pub fn is_authorized_sender_for_mailbox(&self, mailbox_id: &str, candidate_from: &str) -> bool {
        let target_norm = normalize_mailbox_id(mailbox_id);
        if target_norm.is_empty() {
            return false;
        }
        let Ok(parsed) = crate::storage::parse_strict_single_mailbox(candidate_from) else {
            return false;
        };
        let from_norm = normalize_mailbox_id(&parsed.email);
        if from_norm == target_norm {
            return true;
        }
        self.resolve_alias_target(&from_norm)
            .is_some_and(|resolved| resolved == target_norm)
    }

    /// Resolve which local mailbox(es) should receive an inbound message addressed to
    /// `recipient_candidates`, applying configured `mailbox_aliases` mappings.
    ///
    /// When explicit mailbox routing is active (`has_explicit_mailbox_routing()`), returns ONLY
    /// matching local mailboxes from `known_mailboxes()` (empty if none match).
    /// When running in default single-mailbox mode, falls back to `[normalize_mailbox_id(&user_email)]`.
    pub fn resolve_inbound_mailboxes(&self, recipient_candidates: &[String]) -> Vec<String> {
        let known = self.known_mailboxes();
        if !self.has_explicit_mailbox_routing() {
            return known;
        }
        let extracted = extract_email_addresses(recipient_candidates);
        let mut resolved_recipients = Vec::with_capacity(extracted.len());
        for rcpt in extracted {
            if let Some(target) = self.resolve_alias_target(&rcpt) {
                resolved_recipients.push(target);
            } else {
                resolved_recipients.push(rcpt);
            }
        }
        known
            .into_iter()
            .filter(|mb| resolved_recipients.iter().any(|rcpt| rcpt == mb))
            .collect()
    }

    /// Return the matching `[[sync.accounts]]` entry for `mailbox_id` (case-insensitive), if any.
    pub fn sync_account_for_mailbox(&self, mailbox_id: &str) -> Option<&SyncAccountConfig> {
        let target = normalize_mailbox_id(mailbox_id);
        if target.is_empty() {
            return None;
        }
        self.sync_accounts
            .iter()
            .find(|acct| normalize_mailbox_id(&acct.mailbox_id) == target)
    }

    /// Returns `true` when either legacy `[sync]` or any `[[sync.accounts]]` entry has
    /// background sync enabled (`interval_secs > 0` or IMAP `IDLE` enabled).
    pub fn has_background_sync(&self) -> bool {
        self.sync_interval_secs > 0
            || (self.sync_mode == SyncMode::Imap && self.gmail_imap_idle)
            || self
                .sync_accounts
                .iter()
                .any(|a| a.interval_secs > 0 || (a.mode == SyncMode::Imap && a.gmail_imap_idle))
    }

    /// Returns `true` when Gmail OAuth2 credentials (static access token or refresh flow) are set.
    pub fn has_gmail_oauth2(&self) -> bool {
        self.gmail_access_token
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
            || (self
                .gmail_client_id
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
                && self
                    .gmail_client_secret
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty())
                && self
                    .gmail_refresh_token
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty()))
    }

    /// Returns `true` when any upstream Gmail sync credentials are configured.
    pub fn gmail_sync_configured(&self) -> bool {
        match self.sync_mode {
            SyncMode::Api => self.has_gmail_oauth2(),
            SyncMode::Imap => {
                self.gmail_imap_user
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty())
                    && (self
                        .gmail_imap_password
                        .as_deref()
                        .is_some_and(|s| !s.is_empty())
                        || self.has_gmail_oauth2())
            }
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

    /// Returns `true` when AES-256-GCM encryption at rest is configured.
    pub fn encryption_at_rest_enabled(&self) -> bool {
        self.encryption_key
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
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

    /// Return a structured JSON view of the effective configuration with every secret,
    /// password, token, and credential field replaced by `"[REDACTED]"` (or `null` when unset).
    pub fn redacted_summary(&self) -> Value {
        let Self {
            bind,
            max_body_bytes,
            cors_allow_origins,
            storage,
            db_path,
            database_url,
            blob_backend,
            blob_dir,
            blob_s3_bucket,
            blob_s3_region,
            blob_s3_endpoint,
            blob_s3_prefix,
            blob_s3_access_key_id,
            blob_s3_secret_access_key,
            blob_s3_session_token,
            blob_s3_force_path_style,
            auth_tokens,
            scoped_tokens,
            oauth2_client_id,
            oauth2_client_secret,
            oauth2_signing_secret,
            oauth2_redirect_uris,
            user_email,
            mailboxes,
            mailbox_aliases,
            default_domain,
            transport,
            resend_api_key,
            resend_base_url,
            resend_webhook_secret,
            ses_region,
            ses_endpoint,
            ses_access_key_id,
            ses_secret_access_key,
            ses_session_token,
            ses_s3_endpoint,
            ses_webhook_secret,
            ses_allowed_topic_arns,
            ses_allowed_s3_buckets,
            smtp_host,
            smtp_port,
            smtp_tls_mode,
            smtp_username,
            smtp_password,
            smtp_helo_domain,
            draft_only,
            draft_only_action,
            require_approval,
            first_contact_approval,
            require_verified_from_domain,
            dlp_action,
            approval_ttl_secs,
            approval_webhook_url,
            allowed_recipients,
            max_send_recipients,
            default_max_body_chars,
            untrusted_content_guard,
            webhook_allowed_hosts,
            allow_private_endpoints,
            allow_insecure_webhooks,
            imap_bind,
            imap_tls_bind,
            imap_tls_cert,
            imap_tls_key,
            imap_username,
            imap_password,
            sync_mode,
            gmail_client_id,
            gmail_client_secret,
            gmail_refresh_token,
            gmail_access_token,
            gmail_user_id,
            gmail_api_base_url,
            gmail_oauth_token_url,
            gmail_imap_host,
            gmail_imap_port,
            gmail_imap_tls,
            gmail_imap_user,
            gmail_imap_password,
            gmail_imap_mailbox,
            gmail_imap_folders,
            gmail_imap_archive_mailbox,
            gmail_imap_idle,
            sync_interval_secs,
            sync_query,
            sync_max_messages,
            sync_bidirectional,
            sync_accounts,
            watch_webhook_url,
            filter_auth_results,
            filter_dmarc_fail_action,
            filter_spf_fail_action,
            filter_dkim_fail_action,
            rspamd_url,
            rspamd_password,
            rspamd_timeout_ms,
            rspamd_spam_threshold,
            rspamd_reject_action,
            rspamd_fail_closed,
            llm_triage_base_url,
            llm_triage_api_key,
            llm_triage_model,
            llm_triage_timeout_ms,
            llm_triage_max_body_chars,
            encryption_key,
            encryption_previous_keys,
            search_backend,
            embedding_base_url,
            embedding_api_key,
            embedding_model,
            embedding_timeout_secs,
        } = self;

        let redact_opt = |opt: &Option<String>| -> Value {
            if opt.is_some() {
                Value::String(REDACTED.to_string())
            } else {
                Value::Null
            }
        };

        let redacted_auth_tokens: Vec<&str> = auth_tokens.iter().map(|_| REDACTED).collect();
        let redacted_encryption_previous_keys: Vec<&str> =
            encryption_previous_keys.iter().map(|_| REDACTED).collect();
        let redacted_scoped_tokens: Vec<Value> = scoped_tokens
            .iter()
            .map(|st| {
                json!({
                    "token": REDACTED,
                    "mailbox_id": st.mailbox_id,
                    "shared_mailboxes": st.shared_mailboxes,
                    "scopes": st.scopes,
                    "draft_only": st.draft_only,
                    "allowed_recipients": st.allowed_recipients,
                    "max_send_recipients": st.max_send_recipients,
                })
            })
            .collect();
        let redacted_sync_accounts: Vec<Value> = sync_accounts
            .iter()
            .map(SyncAccountConfig::redacted_summary)
            .collect();

        json!({
            "server": {
                "bind": bind.to_string(),
                "max_body_bytes": max_body_bytes,
                "cors_allow_origins": cors_allow_origins,
            },
            "storage": {
                "backend": storage,
                "db_path": db_path,
                "database_url": redact_opt(database_url),
            },
            "blob": {
                "backend": blob_backend,
                "dir": blob_dir,
                "s3_bucket": blob_s3_bucket,
                "s3_region": blob_s3_region,
                "s3_endpoint": blob_s3_endpoint,
                "s3_prefix": blob_s3_prefix,
                "s3_access_key_id": blob_s3_access_key_id,
                "s3_secret_access_key": redact_opt(blob_s3_secret_access_key),
                "s3_session_token": redact_opt(blob_s3_session_token),
                "s3_force_path_style": blob_s3_force_path_style,
            },
            "auth": {
                "user_email": user_email,
                "mailboxes": mailboxes,
                "default_domain": default_domain,
                "tokens": redacted_auth_tokens,
                "scoped_tokens": redacted_scoped_tokens,
            },
            "mailboxes": {
                "aliases": mailbox_aliases,
            },
            "oauth2": {
                "client_id": oauth2_client_id,
                "client_secret": redact_opt(oauth2_client_secret),
                "signing_secret": redact_opt(oauth2_signing_secret),
                "redirect_uris": oauth2_redirect_uris,
            },
            "transport": {
                "backend": transport,
            },
            "resend": {
                "api_key": redact_opt(resend_api_key),
                "base_url": resend_base_url,
                "webhook_secret": redact_opt(resend_webhook_secret),
            },
            "ses": {
                "region": ses_region,
                "endpoint": ses_endpoint,
                "access_key_id": ses_access_key_id,
                "secret_access_key": redact_opt(ses_secret_access_key),
                "session_token": redact_opt(ses_session_token),
                "s3_endpoint": ses_s3_endpoint,
                "webhook_secret": redact_opt(ses_webhook_secret),
                "allowed_topic_arns": ses_allowed_topic_arns,
                "allowed_s3_buckets": ses_allowed_s3_buckets,
            },
            "smtp": {
                "host": smtp_host,
                "port": smtp_port,
                "tls_mode": smtp_tls_mode,
                "username": smtp_username,
                "password": redact_opt(smtp_password),
                "helo_domain": smtp_helo_domain,
            },
            "safety": {
                "draft_only": draft_only,
                "draft_only_action": draft_only_action,
                "require_approval": require_approval,
                "first_contact_approval": first_contact_approval,
                "require_verified_from_domain": require_verified_from_domain,
                "dlp_action": dlp_action,
                "approval_ttl_secs": approval_ttl_secs,
                "approval_webhook_url": approval_webhook_url
                    .as_deref()
                    .filter(|s| !s.trim().is_empty())
                    .map(crate::secrets::redact_url_for_log),
                "allowed_recipients": allowed_recipients,
                "max_send_recipients": max_send_recipients,
                "default_max_body_chars": default_max_body_chars,
                "untrusted_content_guard": untrusted_content_guard,
                "webhook_allowed_hosts": webhook_allowed_hosts,
                "allow_private_endpoints": allow_private_endpoints,
                "allow_insecure_webhooks": allow_insecure_webhooks,
            },
            "imap": {
                "bind": imap_bind.map(|a| a.to_string()),
                "tls_bind": imap_tls_bind.map(|a| a.to_string()),
                "tls_cert": imap_tls_cert,
                "tls_key": imap_tls_key,
                "username": imap_username,
                "password": redact_opt(imap_password),
            },
            "sync": {
                "mode": sync_mode,
                "interval_secs": sync_interval_secs,
                "query": sync_query,
                "max_messages": sync_max_messages,
                "bidirectional": sync_bidirectional,
                "gmail_client_id": gmail_client_id,
                "gmail_client_secret": redact_opt(gmail_client_secret),
                "gmail_refresh_token": redact_opt(gmail_refresh_token),
                "gmail_access_token": redact_opt(gmail_access_token),
                "gmail_user_id": gmail_user_id,
                "gmail_api_base_url": gmail_api_base_url,
                "gmail_oauth_token_url": gmail_oauth_token_url,
                "gmail_imap_host": gmail_imap_host,
                "gmail_imap_port": gmail_imap_port,
                "gmail_imap_tls": gmail_imap_tls,
                "gmail_imap_user": gmail_imap_user,
                "gmail_imap_password": redact_opt(gmail_imap_password),
                "gmail_imap_mailbox": gmail_imap_mailbox,
                "gmail_imap_folders": gmail_imap_folders,
                "gmail_imap_archive_mailbox": gmail_imap_archive_mailbox,
                "gmail_imap_idle": gmail_imap_idle,
                "accounts": redacted_sync_accounts,
            },
            "watch": {
                "webhook_url": watch_webhook_url
                    .as_deref()
                    .filter(|s| !s.trim().is_empty())
                    .map(crate::secrets::redact_url_for_log),
            },
            "filters": {
                "auth_results": filter_auth_results,
                "dmarc_fail_action": filter_dmarc_fail_action,
                "spf_fail_action": filter_spf_fail_action,
                "dkim_fail_action": filter_dkim_fail_action,
                "rspamd": {
                    "url": rspamd_url,
                    "password": redact_opt(rspamd_password),
                    "timeout_ms": rspamd_timeout_ms,
                    "spam_threshold": rspamd_spam_threshold,
                    "reject_action": rspamd_reject_action,
                    "fail_closed": rspamd_fail_closed,
                },
                "llm_triage": {
                    "base_url": llm_triage_base_url,
                    "api_key": redact_opt(llm_triage_api_key),
                    "model": llm_triage_model,
                    "timeout_ms": llm_triage_timeout_ms,
                    "max_body_chars": llm_triage_max_body_chars,
                },
            },
            "security": {
                "encryption_at_rest": encryption_key
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty()),
                "encryption_key": redact_opt(encryption_key),
                "encryption_previous_keys": redacted_encryption_previous_keys,
            },
            "search": {
                "backend": search_backend,
                "embedding_base_url": embedding_base_url,
                "embedding_api_key": redact_opt(embedding_api_key),
                "embedding_model": embedding_model,
                "embedding_timeout_secs": embedding_timeout_secs,
            },
        })
    }

    /// Apply `*_FILE` environment variables (when not overridden by CLI or direct env vars)
    /// and resolve all `file://` and `env://` secret references across every secret field.
    pub fn apply_env_file_secrets_and_resolve(
        &mut self,
        base_dir: Option<&Path>,
        origin_of: &dyn Fn(&str) -> ValueOrigin,
        env_lookup: &dyn Fn(&str) -> Option<String>,
    ) -> SecretResolutionReport {
        let mut report = SecretResolutionReport::default();
        let mut loaded_from_env_file: HashSet<&'static str> = HashSet::new();

        macro_rules! load_opt_env_file {
            ($arg_id:expr, $field_name:expr, $direct_env:expr, $file_env:expr, $slot:expr) => {
                if let Some(path_str) = env_lookup($file_env)
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                {
                    match origin_of($arg_id) {
                        ValueOrigin::Cli => {}
                        ValueOrigin::DirectEnv => {
                            report.push_warning_unique(format!(
                                "Both {} and {} are set; using {}",
                                $direct_env, $file_env, $direct_env
                            ));
                        }
                        ValueOrigin::Unset => {
                            if let Some(val) =
                                read_secret_file($field_name, Path::new(&path_str), &mut report)
                            {
                                $slot = Some(val);
                                loaded_from_env_file.insert($field_name);
                            } else {
                                $slot = None;
                                loaded_from_env_file.insert($field_name);
                            }
                        }
                    }
                }
            };
        }

        load_opt_env_file!(
            "database_url",
            "storage.database_url",
            "NOGML_DATABASE_URL",
            "NOGML_DATABASE_URL_FILE",
            self.database_url
        );
        load_opt_env_file!(
            "blob_s3_secret_access_key",
            "blob.s3_secret_access_key",
            "NOGML_BLOB_S3_SECRET_ACCESS_KEY",
            "NOGML_BLOB_S3_SECRET_ACCESS_KEY_FILE",
            self.blob_s3_secret_access_key
        );
        load_opt_env_file!(
            "blob_s3_session_token",
            "blob.s3_session_token",
            "NOGML_BLOB_S3_SESSION_TOKEN",
            "NOGML_BLOB_S3_SESSION_TOKEN_FILE",
            self.blob_s3_session_token
        );
        load_opt_env_file!(
            "oauth2_client_secret",
            "oauth2.client_secret",
            "NOGML_OAUTH2_CLIENT_SECRET",
            "NOGML_OAUTH2_CLIENT_SECRET_FILE",
            self.oauth2_client_secret
        );
        load_opt_env_file!(
            "oauth2_signing_secret",
            "oauth2.signing_secret",
            "NOGML_OAUTH2_SIGNING_SECRET",
            "NOGML_OAUTH2_SIGNING_SECRET_FILE",
            self.oauth2_signing_secret
        );
        load_opt_env_file!(
            "resend_api_key",
            "resend.api_key",
            "RESEND_API_KEY",
            "RESEND_API_KEY_FILE",
            self.resend_api_key
        );
        load_opt_env_file!(
            "resend_webhook_secret",
            "resend.webhook_secret",
            "RESEND_WEBHOOK_SECRET",
            "RESEND_WEBHOOK_SECRET_FILE",
            self.resend_webhook_secret
        );
        load_opt_env_file!(
            "ses_secret_access_key",
            "ses.secret_access_key",
            "NOGML_SES_SECRET_ACCESS_KEY",
            "NOGML_SES_SECRET_ACCESS_KEY_FILE",
            self.ses_secret_access_key
        );
        load_opt_env_file!(
            "ses_session_token",
            "ses.session_token",
            "NOGML_SES_SESSION_TOKEN",
            "NOGML_SES_SESSION_TOKEN_FILE",
            self.ses_session_token
        );
        load_opt_env_file!(
            "ses_webhook_secret",
            "ses.webhook_secret",
            "NOGML_SES_WEBHOOK_SECRET",
            "NOGML_SES_WEBHOOK_SECRET_FILE",
            self.ses_webhook_secret
        );
        load_opt_env_file!(
            "smtp_password",
            "smtp.password",
            "NOGML_SMTP_PASSWORD",
            "NOGML_SMTP_PASSWORD_FILE",
            self.smtp_password
        );
        load_opt_env_file!(
            "imap_password",
            "imap.password",
            "NOGML_IMAP_PASSWORD",
            "NOGML_IMAP_PASSWORD_FILE",
            self.imap_password
        );
        load_opt_env_file!(
            "gmail_client_secret",
            "sync.gmail_client_secret",
            "GMAIL_CLIENT_SECRET",
            "GMAIL_CLIENT_SECRET_FILE",
            self.gmail_client_secret
        );
        load_opt_env_file!(
            "gmail_refresh_token",
            "sync.gmail_refresh_token",
            "GMAIL_REFRESH_TOKEN",
            "GMAIL_REFRESH_TOKEN_FILE",
            self.gmail_refresh_token
        );
        load_opt_env_file!(
            "gmail_access_token",
            "sync.gmail_access_token",
            "GMAIL_ACCESS_TOKEN",
            "GMAIL_ACCESS_TOKEN_FILE",
            self.gmail_access_token
        );
        load_opt_env_file!(
            "gmail_imap_password",
            "sync.gmail_imap_password",
            "GMAIL_IMAP_PASSWORD",
            "GMAIL_IMAP_PASSWORD_FILE",
            self.gmail_imap_password
        );
        load_opt_env_file!(
            "rspamd_password",
            "filters.rspamd.password",
            "NOGML_RSPAMD_PASSWORD",
            "NOGML_RSPAMD_PASSWORD_FILE",
            self.rspamd_password
        );
        load_opt_env_file!(
            "llm_triage_api_key",
            "filters.llm_triage.api_key",
            "NOGML_LLM_TRIAGE_API_KEY",
            "NOGML_LLM_TRIAGE_API_KEY_FILE",
            self.llm_triage_api_key
        );
        load_opt_env_file!(
            "embedding_api_key",
            "search.embedding_api_key",
            "NOGML_EMBEDDING_API_KEY",
            "NOGML_EMBEDDING_API_KEY_FILE",
            self.embedding_api_key
        );
        load_opt_env_file!(
            "encryption_key",
            "security.encryption_key",
            "NOGML_ENCRYPTION_KEY",
            "NOGML_ENCRYPTION_KEY_FILE",
            self.encryption_key
        );

        // NOGML_ENCRYPTION_PREVIOUS_KEYS_FILE
        if let Some(path_str) = env_lookup("NOGML_ENCRYPTION_PREVIOUS_KEYS_FILE")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            match origin_of("encryption_previous_keys") {
                ValueOrigin::Cli => {}
                ValueOrigin::DirectEnv => {
                    report.push_warning_unique(
                        "Both NOGML_ENCRYPTION_PREVIOUS_KEYS and NOGML_ENCRYPTION_PREVIOUS_KEYS_FILE are set; using NOGML_ENCRYPTION_PREVIOUS_KEYS"
                            .to_string(),
                    );
                }
                ValueOrigin::Unset => {
                    if let Some(raw) = read_secret_file(
                        "security.encryption_previous_keys",
                        Path::new(&path_str),
                        &mut report,
                    ) {
                        self.encryption_previous_keys = split_token_list(&raw);
                    } else {
                        self.encryption_previous_keys.clear();
                    }
                    loaded_from_env_file.insert("security.encryption_previous_keys");
                }
            }
        }

        // NOGML_AUTH_TOKENS_FILE
        if let Some(path_str) = env_lookup("NOGML_AUTH_TOKENS_FILE")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            match origin_of("auth_tokens") {
                ValueOrigin::Cli => {}
                ValueOrigin::DirectEnv => {
                    report.push_warning_unique(
                        "Both NOGML_AUTH_TOKENS and NOGML_AUTH_TOKENS_FILE are set; using NOGML_AUTH_TOKENS"
                            .to_string(),
                    );
                }
                ValueOrigin::Unset => {
                    if let Some(raw) =
                        read_secret_file("auth.tokens", Path::new(&path_str), &mut report)
                    {
                        self.auth_tokens = split_token_list(&raw);
                    } else {
                        self.auth_tokens.clear();
                    }
                    loaded_from_env_file.insert("auth.tokens");
                }
            }
        }

        // NOGML_SCOPED_TOKENS_FILE
        if let Some(path_str) = env_lookup("NOGML_SCOPED_TOKENS_FILE")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            match origin_of("scoped_tokens") {
                ValueOrigin::Cli => {}
                ValueOrigin::DirectEnv => {
                    report.push_warning_unique(
                        "Both NOGML_SCOPED_TOKENS and NOGML_SCOPED_TOKENS_FILE are set; using NOGML_SCOPED_TOKENS"
                            .to_string(),
                    );
                }
                ValueOrigin::Unset => {
                    if let Some(raw) =
                        read_secret_file("auth.scoped_tokens", Path::new(&path_str), &mut report)
                    {
                        let trimmed = raw.trim();
                        if trimmed.is_empty() {
                            self.scoped_tokens.clear();
                        } else {
                            match serde_json::from_str::<Vec<ScopedTokenConfig>>(trimmed) {
                                Ok(parsed) => self.scoped_tokens = parsed,
                                Err(err) => {
                                    report.errors.push(format!(
                                        "Invalid JSON in NOGML_SCOPED_TOKENS_FILE '{path_str}': {err}"
                                    ));
                                    self.scoped_tokens.clear();
                                }
                            }
                        }
                    } else {
                        self.scoped_tokens.clear();
                    }
                }
            }
        }

        // Resolve file:// and env:// URIs across all scalar secrets not already read from *_FILE.
        macro_rules! resolve_opt_uri {
            ($field_name:expr, $slot:expr) => {
                if !loaded_from_env_file.contains($field_name)
                    && let Some(raw) = $slot.clone()
                {
                    if raw.starts_with("file://") || raw.starts_with("env://") {
                        $slot = resolve_secret_value(
                            $field_name,
                            &raw,
                            base_dir,
                            env_lookup,
                            &mut report,
                        );
                    }
                }
            };
        }

        resolve_opt_uri!("storage.database_url", self.database_url);
        resolve_opt_uri!("blob.s3_secret_access_key", self.blob_s3_secret_access_key);
        resolve_opt_uri!("blob.s3_session_token", self.blob_s3_session_token);
        resolve_opt_uri!("oauth2.client_secret", self.oauth2_client_secret);
        resolve_opt_uri!("oauth2.signing_secret", self.oauth2_signing_secret);
        resolve_opt_uri!("resend.api_key", self.resend_api_key);
        resolve_opt_uri!("resend.webhook_secret", self.resend_webhook_secret);
        resolve_opt_uri!("ses.secret_access_key", self.ses_secret_access_key);
        resolve_opt_uri!("ses.session_token", self.ses_session_token);
        resolve_opt_uri!("ses.webhook_secret", self.ses_webhook_secret);
        resolve_opt_uri!("smtp.password", self.smtp_password);
        resolve_opt_uri!("imap.password", self.imap_password);
        resolve_opt_uri!("sync.gmail_client_secret", self.gmail_client_secret);
        resolve_opt_uri!("sync.gmail_refresh_token", self.gmail_refresh_token);
        resolve_opt_uri!("sync.gmail_access_token", self.gmail_access_token);
        resolve_opt_uri!("sync.gmail_imap_password", self.gmail_imap_password);
        resolve_opt_uri!("filters.rspamd.password", self.rspamd_password);
        resolve_opt_uri!("filters.llm_triage.api_key", self.llm_triage_api_key);
        resolve_opt_uri!("search.embedding_api_key", self.embedding_api_key);
        resolve_opt_uri!("security.encryption_key", self.encryption_key);

        if !loaded_from_env_file.contains("security.encryption_previous_keys") {
            self.encryption_previous_keys = resolve_secret_tokens(
                "security.encryption_previous_keys",
                &self.encryption_previous_keys,
                base_dir,
                env_lookup,
                &mut report,
            );
        }

        if !loaded_from_env_file.contains("auth.tokens") {
            self.auth_tokens = resolve_secret_tokens(
                "auth.tokens",
                &self.auth_tokens,
                base_dir,
                env_lookup,
                &mut report,
            );
        }

        for (idx, st) in self.scoped_tokens.iter_mut().enumerate() {
            if st.token.starts_with("file://") || st.token.starts_with("env://") {
                let field_name = format!("auth.scoped_tokens[{idx}].token");
                match resolve_secret_value(
                    &field_name,
                    &st.token,
                    base_dir,
                    env_lookup,
                    &mut report,
                ) {
                    Some(val) => st.token = val,
                    None => st.token.clear(),
                }
            }
        }

        for (idx, acct) in self.sync_accounts.iter_mut().enumerate() {
            macro_rules! resolve_acct_secret {
                ($field_suffix:expr, $slot:expr) => {
                    if let Some(raw) = $slot.clone()
                        && (raw.starts_with("file://") || raw.starts_with("env://"))
                    {
                        let field_name = format!("sync.accounts[{idx}].{}", $field_suffix);
                        $slot = resolve_secret_value(
                            &field_name,
                            &raw,
                            base_dir,
                            env_lookup,
                            &mut report,
                        );
                    }
                };
            }

            resolve_acct_secret!("gmail_client_secret", acct.gmail_client_secret);
            resolve_acct_secret!("gmail_refresh_token", acct.gmail_refresh_token);
            resolve_acct_secret!("gmail_access_token", acct.gmail_access_token);
            resolve_acct_secret!("gmail_imap_password", acct.gmail_imap_password);
        }

        report
    }

    /// Resolve `file://` and `env://` secret references using the process environment.
    pub fn resolve_secrets(&mut self, base_dir: Option<&Path>) -> SecretResolutionReport {
        self.apply_env_file_secrets_and_resolve(
            base_dir,
            &|_| ValueOrigin::Unset,
            &system_env_lookup,
        )
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            bind,
            max_body_bytes,
            cors_allow_origins,
            storage,
            db_path,
            database_url,
            blob_backend,
            blob_dir,
            blob_s3_bucket,
            blob_s3_region,
            blob_s3_endpoint,
            blob_s3_prefix,
            blob_s3_access_key_id,
            blob_s3_secret_access_key,
            blob_s3_session_token,
            blob_s3_force_path_style,
            auth_tokens,
            scoped_tokens,
            oauth2_client_id,
            oauth2_client_secret,
            oauth2_signing_secret,
            oauth2_redirect_uris,
            user_email,
            mailboxes,
            mailbox_aliases,
            default_domain,
            transport,
            resend_api_key,
            resend_base_url,
            resend_webhook_secret,
            ses_region,
            ses_endpoint,
            ses_access_key_id,
            ses_secret_access_key,
            ses_session_token,
            ses_s3_endpoint,
            ses_webhook_secret,
            ses_allowed_topic_arns,
            ses_allowed_s3_buckets,
            smtp_host,
            smtp_port,
            smtp_tls_mode,
            smtp_username,
            smtp_password,
            smtp_helo_domain,
            draft_only,
            draft_only_action,
            require_approval,
            first_contact_approval,
            require_verified_from_domain,
            dlp_action,
            approval_ttl_secs,
            approval_webhook_url,
            allowed_recipients,
            max_send_recipients,
            default_max_body_chars,
            untrusted_content_guard,
            webhook_allowed_hosts,
            allow_private_endpoints,
            allow_insecure_webhooks,
            imap_bind,
            imap_tls_bind,
            imap_tls_cert,
            imap_tls_key,
            imap_username,
            imap_password,
            sync_mode,
            gmail_client_id,
            gmail_client_secret,
            gmail_refresh_token,
            gmail_access_token,
            gmail_user_id,
            gmail_api_base_url,
            gmail_oauth_token_url,
            gmail_imap_host,
            gmail_imap_port,
            gmail_imap_tls,
            gmail_imap_user,
            gmail_imap_password,
            gmail_imap_mailbox,
            gmail_imap_folders,
            gmail_imap_archive_mailbox,
            gmail_imap_idle,
            sync_interval_secs,
            sync_query,
            sync_max_messages,
            sync_bidirectional,
            sync_accounts,
            watch_webhook_url,
            filter_auth_results,
            filter_dmarc_fail_action,
            filter_spf_fail_action,
            filter_dkim_fail_action,
            rspamd_url,
            rspamd_password,
            rspamd_timeout_ms,
            rspamd_spam_threshold,
            rspamd_reject_action,
            rspamd_fail_closed,
            llm_triage_base_url,
            llm_triage_api_key,
            llm_triage_model,
            llm_triage_timeout_ms,
            llm_triage_max_body_chars,
            encryption_key,
            encryption_previous_keys,
            search_backend,
            embedding_base_url,
            embedding_api_key,
            embedding_model,
            embedding_timeout_secs,
        } = self;

        let redacted_opt = |opt: &Option<String>| opt.as_ref().map(|_| REDACTED);
        let redacted_tokens: Vec<&str> = auth_tokens.iter().map(|_| REDACTED).collect();
        let redacted_encryption_previous_keys: Vec<&str> =
            encryption_previous_keys.iter().map(|_| REDACTED).collect();

        f.debug_struct("Config")
            .field("bind", bind)
            .field("max_body_bytes", max_body_bytes)
            .field("cors_allow_origins", cors_allow_origins)
            .field("storage", storage)
            .field("db_path", db_path)
            .field("database_url", &redacted_opt(database_url))
            .field("blob_backend", blob_backend)
            .field("blob_dir", blob_dir)
            .field("blob_s3_bucket", blob_s3_bucket)
            .field("blob_s3_region", blob_s3_region)
            .field("blob_s3_endpoint", blob_s3_endpoint)
            .field("blob_s3_prefix", blob_s3_prefix)
            .field("blob_s3_access_key_id", blob_s3_access_key_id)
            .field(
                "blob_s3_secret_access_key",
                &redacted_opt(blob_s3_secret_access_key),
            )
            .field(
                "blob_s3_session_token",
                &redacted_opt(blob_s3_session_token),
            )
            .field("blob_s3_force_path_style", blob_s3_force_path_style)
            .field("auth_tokens", &redacted_tokens)
            .field("scoped_tokens", scoped_tokens)
            .field("oauth2_client_id", oauth2_client_id)
            .field("oauth2_client_secret", &redacted_opt(oauth2_client_secret))
            .field(
                "oauth2_signing_secret",
                &redacted_opt(oauth2_signing_secret),
            )
            .field("oauth2_redirect_uris", oauth2_redirect_uris)
            .field("user_email", user_email)
            .field("mailboxes", mailboxes)
            .field("mailbox_aliases", mailbox_aliases)
            .field("default_domain", default_domain)
            .field("transport", transport)
            .field("resend_api_key", &redacted_opt(resend_api_key))
            .field("resend_base_url", resend_base_url)
            .field(
                "resend_webhook_secret",
                &redacted_opt(resend_webhook_secret),
            )
            .field("ses_region", ses_region)
            .field("ses_endpoint", ses_endpoint)
            .field("ses_access_key_id", ses_access_key_id)
            .field(
                "ses_secret_access_key",
                &redacted_opt(ses_secret_access_key),
            )
            .field("ses_session_token", &redacted_opt(ses_session_token))
            .field("ses_s3_endpoint", ses_s3_endpoint)
            .field("ses_webhook_secret", &redacted_opt(ses_webhook_secret))
            .field("ses_allowed_topic_arns", ses_allowed_topic_arns)
            .field("ses_allowed_s3_buckets", ses_allowed_s3_buckets)
            .field("smtp_host", smtp_host)
            .field("smtp_port", smtp_port)
            .field("smtp_tls_mode", smtp_tls_mode)
            .field("smtp_username", smtp_username)
            .field("smtp_password", &redacted_opt(smtp_password))
            .field("smtp_helo_domain", smtp_helo_domain)
            .field("draft_only", draft_only)
            .field("draft_only_action", draft_only_action)
            .field("require_approval", require_approval)
            .field("first_contact_approval", first_contact_approval)
            .field("require_verified_from_domain", require_verified_from_domain)
            .field("dlp_action", dlp_action)
            .field("approval_ttl_secs", approval_ttl_secs)
            .field(
                "approval_webhook_url",
                &approval_webhook_url
                    .as_deref()
                    .filter(|s| !s.trim().is_empty())
                    .map(crate::secrets::redact_url_for_log),
            )
            .field("allowed_recipients", allowed_recipients)
            .field("max_send_recipients", max_send_recipients)
            .field("default_max_body_chars", default_max_body_chars)
            .field("untrusted_content_guard", untrusted_content_guard)
            .field("webhook_allowed_hosts", webhook_allowed_hosts)
            .field("allow_private_endpoints", allow_private_endpoints)
            .field("allow_insecure_webhooks", allow_insecure_webhooks)
            .field("imap_bind", imap_bind)
            .field("imap_tls_bind", imap_tls_bind)
            .field("imap_tls_cert", imap_tls_cert)
            .field("imap_tls_key", imap_tls_key)
            .field("imap_username", imap_username)
            .field("imap_password", &redacted_opt(imap_password))
            .field("sync_mode", sync_mode)
            .field("gmail_client_id", gmail_client_id)
            .field("gmail_client_secret", &redacted_opt(gmail_client_secret))
            .field("gmail_refresh_token", &redacted_opt(gmail_refresh_token))
            .field("gmail_access_token", &redacted_opt(gmail_access_token))
            .field("gmail_user_id", gmail_user_id)
            .field("gmail_api_base_url", gmail_api_base_url)
            .field("gmail_oauth_token_url", gmail_oauth_token_url)
            .field("gmail_imap_host", gmail_imap_host)
            .field("gmail_imap_port", gmail_imap_port)
            .field("gmail_imap_tls", gmail_imap_tls)
            .field("gmail_imap_user", gmail_imap_user)
            .field("gmail_imap_password", &redacted_opt(gmail_imap_password))
            .field("gmail_imap_mailbox", gmail_imap_mailbox)
            .field("gmail_imap_folders", gmail_imap_folders)
            .field("gmail_imap_archive_mailbox", gmail_imap_archive_mailbox)
            .field("gmail_imap_idle", gmail_imap_idle)
            .field("sync_interval_secs", sync_interval_secs)
            .field("sync_query", sync_query)
            .field("sync_max_messages", sync_max_messages)
            .field("sync_bidirectional", sync_bidirectional)
            .field("sync_accounts", sync_accounts)
            .field(
                "watch_webhook_url",
                &watch_webhook_url
                    .as_deref()
                    .filter(|s| !s.trim().is_empty())
                    .map(crate::secrets::redact_url_for_log),
            )
            .field("filter_auth_results", filter_auth_results)
            .field("filter_dmarc_fail_action", filter_dmarc_fail_action)
            .field("filter_spf_fail_action", filter_spf_fail_action)
            .field("filter_dkim_fail_action", filter_dkim_fail_action)
            .field("rspamd_url", rspamd_url)
            .field("rspamd_password", &redacted_opt(rspamd_password))
            .field("rspamd_timeout_ms", rspamd_timeout_ms)
            .field("rspamd_spam_threshold", rspamd_spam_threshold)
            .field("rspamd_reject_action", rspamd_reject_action)
            .field("rspamd_fail_closed", rspamd_fail_closed)
            .field("llm_triage_base_url", llm_triage_base_url)
            .field("llm_triage_api_key", &redacted_opt(llm_triage_api_key))
            .field("llm_triage_model", llm_triage_model)
            .field("llm_triage_timeout_ms", llm_triage_timeout_ms)
            .field("llm_triage_max_body_chars", llm_triage_max_body_chars)
            .field("encryption_key", &redacted_opt(encryption_key))
            .field(
                "encryption_previous_keys",
                &redacted_encryption_previous_keys,
            )
            .field("search_backend", search_backend)
            .field("embedding_base_url", embedding_base_url)
            .field("embedding_api_key", &redacted_opt(embedding_api_key))
            .field("embedding_model", embedding_model)
            .field("embedding_timeout_secs", embedding_timeout_secs)
            .finish()
    }
}

// ============================================================================
// Structured `nogml.toml` configuration file schema
// ============================================================================

/// Root schema for `nogml.toml`.
///
/// Unknown fields are rejected so configuration typos fail fast during startup and
/// `nogml config check`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TomlConfig {
    pub server: ServerTomlConfig,
    pub storage: StorageTomlConfig,
    pub blob: BlobTomlConfig,
    pub auth: AuthTomlConfig,
    pub mailboxes: MailboxesTomlConfig,
    pub oauth2: OAuth2TomlConfig,
    pub transport: TransportTomlConfig,
    pub resend: ResendTomlConfig,
    pub ses: SesTomlConfig,
    pub smtp: SmtpTomlConfig,
    pub safety: SafetyTomlConfig,
    pub imap: ImapTomlConfig,
    pub sync: SyncTomlConfig,
    pub watch: WatchTomlConfig,
    pub filters: FiltersTomlConfig,
    pub security: SecurityTomlConfig,
    pub search: SearchTomlConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MailboxesTomlConfig {
    pub aliases: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerTomlConfig {
    pub bind: Option<SocketAddr>,
    pub max_body_bytes: Option<usize>,
    #[serde(alias = "cors_origins")]
    pub cors_allow_origins: Option<Vec<String>>,
    pub log_json: Option<bool>,
}

fn redacted_opt_debug(opt: &Option<String>) -> Option<&'static str> {
    opt.as_deref()
        .filter(|s| !s.is_empty())
        .map(|_| crate::secrets::REDACTED)
}

fn redacted_url_opt_debug(opt: &Option<String>) -> Option<String> {
    opt.as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(crate::secrets::redact_url_for_log)
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageTomlConfig {
    pub backend: Option<StorageBackend>,
    pub db_path: Option<PathBuf>,
    pub database_url: Option<String>,
}

impl std::fmt::Debug for StorageTomlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageTomlConfig")
            .field("backend", &self.backend)
            .field("db_path", &self.db_path)
            .field("database_url", &redacted_opt_debug(&self.database_url))
            .finish()
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BlobTomlConfig {
    pub backend: Option<BlobBackend>,
    pub dir: Option<PathBuf>,
    pub s3_bucket: Option<String>,
    pub s3_region: Option<String>,
    pub s3_endpoint: Option<String>,
    pub s3_prefix: Option<String>,
    pub s3_access_key_id: Option<String>,
    pub s3_secret_access_key: Option<String>,
    pub s3_session_token: Option<String>,
    pub s3_force_path_style: Option<bool>,
}

impl std::fmt::Debug for BlobTomlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlobTomlConfig")
            .field("backend", &self.backend)
            .field("dir", &self.dir)
            .field("s3_bucket", &self.s3_bucket)
            .field("s3_region", &self.s3_region)
            .field("s3_endpoint", &self.s3_endpoint)
            .field("s3_prefix", &self.s3_prefix)
            .field("s3_access_key_id", &self.s3_access_key_id)
            .field(
                "s3_secret_access_key",
                &redacted_opt_debug(&self.s3_secret_access_key),
            )
            .field(
                "s3_session_token",
                &redacted_opt_debug(&self.s3_session_token),
            )
            .field("s3_force_path_style", &self.s3_force_path_style)
            .finish()
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthTomlConfig {
    pub user_email: Option<String>,
    pub mailboxes: Option<Vec<String>>,
    pub default_domain: Option<String>,
    #[serde(alias = "auth_tokens")]
    pub tokens: Option<Vec<String>>,
    pub scoped_tokens: Option<Vec<ScopedTokenConfig>>,
}

impl std::fmt::Debug for AuthTomlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted_tokens: Option<Vec<&'static str>> = self
            .tokens
            .as_ref()
            .map(|list| list.iter().map(|_| crate::secrets::REDACTED).collect());
        f.debug_struct("AuthTomlConfig")
            .field("user_email", &self.user_email)
            .field("mailboxes", &self.mailboxes)
            .field("default_domain", &self.default_domain)
            .field("tokens", &redacted_tokens)
            .field("scoped_tokens", &self.scoped_tokens)
            .finish()
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OAuth2TomlConfig {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub signing_secret: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
}

impl std::fmt::Debug for OAuth2TomlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth2TomlConfig")
            .field("client_id", &self.client_id)
            .field("client_secret", &redacted_opt_debug(&self.client_secret))
            .field("signing_secret", &redacted_opt_debug(&self.signing_secret))
            .field("redirect_uris", &self.redirect_uris)
            .finish()
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransportTomlConfig {
    pub backend: Option<TransportBackend>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResendTomlConfig {
    pub api_key: Option<String>,
    pub base_url: Option<String>,
    pub webhook_secret: Option<String>,
}

impl std::fmt::Debug for ResendTomlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResendTomlConfig")
            .field("api_key", &redacted_opt_debug(&self.api_key))
            .field("base_url", &self.base_url)
            .field("webhook_secret", &redacted_opt_debug(&self.webhook_secret))
            .finish()
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SesTomlConfig {
    pub region: Option<String>,
    pub endpoint: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub session_token: Option<String>,
    pub s3_endpoint: Option<String>,
    pub webhook_secret: Option<String>,
    pub allowed_topic_arns: Option<Vec<String>>,
    pub allowed_s3_buckets: Option<Vec<String>>,
}

impl std::fmt::Debug for SesTomlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SesTomlConfig")
            .field("region", &self.region)
            .field("endpoint", &self.endpoint)
            .field("access_key_id", &self.access_key_id)
            .field(
                "secret_access_key",
                &redacted_opt_debug(&self.secret_access_key),
            )
            .field("session_token", &redacted_opt_debug(&self.session_token))
            .field("s3_endpoint", &self.s3_endpoint)
            .field("webhook_secret", &redacted_opt_debug(&self.webhook_secret))
            .field("allowed_topic_arns", &self.allowed_topic_arns)
            .field("allowed_s3_buckets", &self.allowed_s3_buckets)
            .finish()
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SmtpTomlConfig {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub tls_mode: Option<SmtpTlsMode>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub helo_domain: Option<String>,
}

impl std::fmt::Debug for SmtpTomlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpTomlConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls_mode", &self.tls_mode)
            .field("username", &self.username)
            .field("password", &redacted_opt_debug(&self.password))
            .field("helo_domain", &self.helo_domain)
            .finish()
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SafetyTomlConfig {
    pub draft_only: Option<bool>,
    pub draft_only_action: Option<DraftOnlyAction>,
    pub require_approval: Option<bool>,
    pub first_contact_approval: Option<bool>,
    pub require_verified_from_domain: Option<bool>,
    pub dlp_action: Option<DlpAction>,
    pub approval_ttl_secs: Option<u64>,
    pub approval_webhook_url: Option<String>,
    pub allowed_recipients: Option<Vec<String>>,
    pub max_send_recipients: Option<usize>,
    pub default_max_body_chars: Option<usize>,
    pub untrusted_content_guard: Option<bool>,
    pub webhook_allowed_hosts: Option<Vec<String>>,
    pub allow_private_endpoints: Option<bool>,
    pub allow_insecure_webhooks: Option<bool>,
}

impl std::fmt::Debug for SafetyTomlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SafetyTomlConfig")
            .field("draft_only", &self.draft_only)
            .field("draft_only_action", &self.draft_only_action)
            .field("require_approval", &self.require_approval)
            .field("first_contact_approval", &self.first_contact_approval)
            .field(
                "require_verified_from_domain",
                &self.require_verified_from_domain,
            )
            .field("dlp_action", &self.dlp_action)
            .field("approval_ttl_secs", &self.approval_ttl_secs)
            .field(
                "approval_webhook_url",
                &redacted_url_opt_debug(&self.approval_webhook_url),
            )
            .field("allowed_recipients", &self.allowed_recipients)
            .field("max_send_recipients", &self.max_send_recipients)
            .field("default_max_body_chars", &self.default_max_body_chars)
            .field("untrusted_content_guard", &self.untrusted_content_guard)
            .field("webhook_allowed_hosts", &self.webhook_allowed_hosts)
            .field("allow_private_endpoints", &self.allow_private_endpoints)
            .field("allow_insecure_webhooks", &self.allow_insecure_webhooks)
            .finish()
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ImapTomlConfig {
    pub bind: Option<SocketAddr>,
    pub tls_bind: Option<SocketAddr>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl std::fmt::Debug for ImapTomlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImapTomlConfig")
            .field("bind", &self.bind)
            .field("tls_bind", &self.tls_bind)
            .field("tls_cert", &self.tls_cert)
            .field("tls_key", &self.tls_key)
            .field("username", &self.username)
            .field("password", &redacted_opt_debug(&self.password))
            .finish()
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SyncTomlConfig {
    pub mode: Option<SyncMode>,
    pub interval_secs: Option<u64>,
    pub query: Option<String>,
    pub max_messages: Option<usize>,
    pub bidirectional: Option<bool>,
    pub gmail_client_id: Option<String>,
    pub gmail_client_secret: Option<String>,
    pub gmail_refresh_token: Option<String>,
    pub gmail_access_token: Option<String>,
    pub gmail_user_id: Option<String>,
    pub gmail_api_base_url: Option<String>,
    pub gmail_oauth_token_url: Option<String>,
    pub gmail_imap_host: Option<String>,
    pub gmail_imap_port: Option<u16>,
    pub gmail_imap_tls: Option<bool>,
    pub gmail_imap_user: Option<String>,
    pub gmail_imap_password: Option<String>,
    pub gmail_imap_mailbox: Option<String>,
    pub gmail_imap_folders: Option<Vec<String>>,
    pub gmail_imap_archive_mailbox: Option<String>,
    pub gmail_imap_idle: Option<bool>,
    pub accounts: Option<Vec<SyncAccountConfig>>,
}

impl std::fmt::Debug for SyncTomlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncTomlConfig")
            .field("mode", &self.mode)
            .field("interval_secs", &self.interval_secs)
            .field("query", &self.query)
            .field("max_messages", &self.max_messages)
            .field("bidirectional", &self.bidirectional)
            .field("gmail_client_id", &self.gmail_client_id)
            .field(
                "gmail_client_secret",
                &redacted_opt_debug(&self.gmail_client_secret),
            )
            .field(
                "gmail_refresh_token",
                &redacted_opt_debug(&self.gmail_refresh_token),
            )
            .field(
                "gmail_access_token",
                &redacted_opt_debug(&self.gmail_access_token),
            )
            .field("gmail_user_id", &self.gmail_user_id)
            .field("gmail_api_base_url", &self.gmail_api_base_url)
            .field("gmail_oauth_token_url", &self.gmail_oauth_token_url)
            .field("gmail_imap_host", &self.gmail_imap_host)
            .field("gmail_imap_port", &self.gmail_imap_port)
            .field("gmail_imap_tls", &self.gmail_imap_tls)
            .field("gmail_imap_user", &self.gmail_imap_user)
            .field(
                "gmail_imap_password",
                &redacted_opt_debug(&self.gmail_imap_password),
            )
            .field("gmail_imap_mailbox", &self.gmail_imap_mailbox)
            .field("gmail_imap_folders", &self.gmail_imap_folders)
            .field(
                "gmail_imap_archive_mailbox",
                &self.gmail_imap_archive_mailbox,
            )
            .field("gmail_imap_idle", &self.gmail_imap_idle)
            .field("accounts", &self.accounts)
            .finish()
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WatchTomlConfig {
    pub webhook_url: Option<String>,
}

impl std::fmt::Debug for WatchTomlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchTomlConfig")
            .field("webhook_url", &redacted_url_opt_debug(&self.webhook_url))
            .finish()
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FiltersTomlConfig {
    pub auth_results: Option<bool>,
    pub dmarc_fail_action: Option<AuthFailAction>,
    pub spf_fail_action: Option<AuthFailAction>,
    pub dkim_fail_action: Option<AuthFailAction>,
    pub rspamd: RspamdTomlConfig,
    pub llm_triage: LlmTriageTomlConfig,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RspamdTomlConfig {
    pub url: Option<String>,
    pub password: Option<String>,
    pub timeout_ms: Option<u64>,
    pub spam_threshold: Option<f32>,
    pub reject_action: Option<RspamdRejectAction>,
    pub fail_closed: Option<bool>,
}

impl std::fmt::Debug for RspamdTomlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RspamdTomlConfig")
            .field("url", &self.url)
            .field("password", &redacted_opt_debug(&self.password))
            .field("timeout_ms", &self.timeout_ms)
            .field("spam_threshold", &self.spam_threshold)
            .field("reject_action", &self.reject_action)
            .field("fail_closed", &self.fail_closed)
            .finish()
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LlmTriageTomlConfig {
    pub base_url: Option<String>,
    pub api_key: Option<String>,
    pub model: Option<String>,
    pub timeout_ms: Option<u64>,
    pub max_body_chars: Option<usize>,
}

impl std::fmt::Debug for LlmTriageTomlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmTriageTomlConfig")
            .field("base_url", &self.base_url)
            .field("api_key", &redacted_opt_debug(&self.api_key))
            .field("model", &self.model)
            .field("timeout_ms", &self.timeout_ms)
            .field("max_body_chars", &self.max_body_chars)
            .finish()
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityTomlConfig {
    pub encryption_key: Option<String>,
    pub encryption_previous_keys: Option<Vec<String>>,
}

impl std::fmt::Debug for SecurityTomlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted_previous: Option<Vec<&'static str>> = self
            .encryption_previous_keys
            .as_ref()
            .map(|list| list.iter().map(|_| crate::secrets::REDACTED).collect());
        f.debug_struct("SecurityTomlConfig")
            .field("encryption_key", &redacted_opt_debug(&self.encryption_key))
            .field("encryption_previous_keys", &redacted_previous)
            .finish()
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SearchTomlConfig {
    pub backend: Option<SearchBackend>,
    pub embedding_base_url: Option<String>,
    pub embedding_api_key: Option<String>,
    pub embedding_model: Option<String>,
    pub embedding_timeout_secs: Option<u64>,
}

impl std::fmt::Debug for SearchTomlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchTomlConfig")
            .field("backend", &self.backend)
            .field("embedding_base_url", &self.embedding_base_url)
            .field(
                "embedding_api_key",
                &redacted_opt_debug(&self.embedding_api_key),
            )
            .field("embedding_model", &self.embedding_model)
            .field("embedding_timeout_secs", &self.embedding_timeout_secs)
            .finish()
    }
}

/// Metadata returned when applying a [`TomlConfig`] onto a [`Config`].
#[derive(Debug, Clone, Default)]
pub struct TomlApplyMeta {
    pub user_email_set: bool,
    pub log_json: Option<bool>,
}

impl TomlConfig {
    /// Parse a `nogml.toml` string into [`TomlConfig`].
    pub fn from_toml_str(input: &str) -> AppResult<Self> {
        toml::from_str(input).map_err(|e| AppError::Config(format!("Invalid TOML config: {e}")))
    }

    /// Read and parse a `nogml.toml` file from disk.
    pub fn from_file(path: &Path) -> AppResult<Self> {
        let raw = fs::read_to_string(path).map_err(|e| {
            AppError::Config(format!(
                "Failed to read config file '{}': {e}",
                path.display()
            ))
        })?;
        Self::from_toml_str(&raw).map_err(|e| {
            AppError::Config(format!(
                "Failed to parse config file '{}': {e}",
                path.display()
            ))
        })
    }

    /// Overlay all fields set in this TOML document onto `cfg`.
    pub fn apply_to(&self, cfg: &mut Config) -> TomlApplyMeta {
        let mut meta = TomlApplyMeta {
            user_email_set: false,
            log_json: self.server.log_json,
        };

        // [server]
        if let Some(v) = self.server.bind {
            cfg.bind = v;
        }
        if let Some(v) = self.server.max_body_bytes {
            cfg.max_body_bytes = v;
        }
        if let Some(ref v) = self.server.cors_allow_origins {
            cfg.cors_allow_origins = v.clone();
        }

        // [storage]
        if let Some(v) = self.storage.backend {
            cfg.storage = v;
        }
        if let Some(ref v) = self.storage.db_path {
            cfg.db_path = v.clone();
        }
        if let Some(ref v) = self.storage.database_url {
            cfg.database_url = Some(v.clone());
        }

        // [blob]
        if let Some(v) = self.blob.backend {
            cfg.blob_backend = v;
        }
        if let Some(ref v) = self.blob.dir {
            cfg.blob_dir = v.clone();
        }
        if let Some(ref v) = self.blob.s3_bucket {
            cfg.blob_s3_bucket = Some(v.clone());
        }
        if let Some(ref v) = self.blob.s3_region {
            cfg.blob_s3_region = v.clone();
        }
        if let Some(ref v) = self.blob.s3_endpoint {
            cfg.blob_s3_endpoint = Some(v.clone());
        }
        if let Some(ref v) = self.blob.s3_prefix {
            cfg.blob_s3_prefix = Some(v.clone());
        }
        if let Some(ref v) = self.blob.s3_access_key_id {
            cfg.blob_s3_access_key_id = Some(v.clone());
        }
        if let Some(ref v) = self.blob.s3_secret_access_key {
            cfg.blob_s3_secret_access_key = Some(v.clone());
        }
        if let Some(ref v) = self.blob.s3_session_token {
            cfg.blob_s3_session_token = Some(v.clone());
        }
        if let Some(v) = self.blob.s3_force_path_style {
            cfg.blob_s3_force_path_style = Some(v);
        }

        // [auth]
        if let Some(ref v) = self.auth.user_email
            && !v.trim().is_empty()
        {
            cfg.user_email = v.clone();
            meta.user_email_set = true;
        }
        if let Some(ref v) = self.auth.mailboxes {
            cfg.mailboxes = v.clone();
        }
        if let Some(ref v) = self.auth.default_domain {
            cfg.default_domain = v.clone();
        }
        if let Some(ref v) = self.auth.tokens {
            cfg.auth_tokens = v.clone();
        }
        if let Some(ref v) = self.auth.scoped_tokens {
            cfg.scoped_tokens = v.clone();
        }

        // [mailboxes]
        if let Some(ref aliases) = self.mailboxes.aliases {
            cfg.mailbox_aliases = normalize_mailbox_aliases(aliases);
        }

        // [oauth2]
        if let Some(ref v) = self.oauth2.client_id {
            cfg.oauth2_client_id = Some(v.clone());
        }
        if let Some(ref v) = self.oauth2.client_secret {
            cfg.oauth2_client_secret = Some(v.clone());
        }
        if let Some(ref v) = self.oauth2.signing_secret {
            cfg.oauth2_signing_secret = Some(v.clone());
        }
        if let Some(ref v) = self.oauth2.redirect_uris {
            cfg.oauth2_redirect_uris = v
                .iter()
                .map(|u| u.trim().to_string())
                .filter(|u| !u.is_empty())
                .collect();
        }

        // [transport]
        if let Some(v) = self.transport.backend {
            cfg.transport = v;
        }

        // [resend]
        if let Some(ref v) = self.resend.api_key {
            cfg.resend_api_key = Some(v.clone());
        }
        if let Some(ref v) = self.resend.base_url {
            cfg.resend_base_url = v.clone();
        }
        if let Some(ref v) = self.resend.webhook_secret {
            cfg.resend_webhook_secret = Some(v.clone());
        }

        // [ses]
        if let Some(ref v) = self.ses.region {
            cfg.ses_region = v.clone();
        }
        if let Some(ref v) = self.ses.endpoint {
            cfg.ses_endpoint = Some(v.clone());
        }
        if let Some(ref v) = self.ses.access_key_id {
            cfg.ses_access_key_id = Some(v.clone());
        }
        if let Some(ref v) = self.ses.secret_access_key {
            cfg.ses_secret_access_key = Some(v.clone());
        }
        if let Some(ref v) = self.ses.session_token {
            cfg.ses_session_token = Some(v.clone());
        }
        if let Some(ref v) = self.ses.s3_endpoint {
            cfg.ses_s3_endpoint = Some(v.clone());
        }
        if let Some(ref v) = self.ses.webhook_secret {
            cfg.ses_webhook_secret = Some(v.clone());
        }
        if let Some(ref v) = self.ses.allowed_topic_arns {
            cfg.ses_allowed_topic_arns = v.clone();
        }
        if let Some(ref v) = self.ses.allowed_s3_buckets {
            cfg.ses_allowed_s3_buckets = v.clone();
        }

        // [smtp]
        if let Some(ref v) = self.smtp.host {
            cfg.smtp_host = v.clone();
        }
        if let Some(v) = self.smtp.port {
            cfg.smtp_port = v;
        }
        if let Some(v) = self.smtp.tls_mode {
            cfg.smtp_tls_mode = v;
        }
        if let Some(ref v) = self.smtp.username {
            cfg.smtp_username = Some(v.clone());
        }
        if let Some(ref v) = self.smtp.password {
            cfg.smtp_password = Some(v.clone());
        }
        if let Some(ref v) = self.smtp.helo_domain {
            cfg.smtp_helo_domain = Some(v.clone());
        }

        // [safety]
        if let Some(v) = self.safety.draft_only {
            cfg.draft_only = v;
        }
        if let Some(v) = self.safety.draft_only_action {
            cfg.draft_only_action = v;
        }
        if let Some(v) = self.safety.require_approval {
            cfg.require_approval = v;
        }
        if let Some(v) = self.safety.first_contact_approval {
            cfg.first_contact_approval = v;
        }
        if let Some(v) = self.safety.require_verified_from_domain {
            cfg.require_verified_from_domain = v;
        }
        if let Some(v) = self.safety.dlp_action {
            cfg.dlp_action = v;
        }
        if let Some(v) = self.safety.approval_ttl_secs {
            cfg.approval_ttl_secs = v;
        }
        if let Some(ref v) = self.safety.approval_webhook_url {
            cfg.approval_webhook_url = Some(v.clone());
        }
        if let Some(ref v) = self.safety.allowed_recipients {
            cfg.allowed_recipients = v.clone();
        }
        if let Some(v) = self.safety.max_send_recipients {
            cfg.max_send_recipients = v;
        }
        if let Some(v) = self.safety.default_max_body_chars {
            cfg.default_max_body_chars = v;
        }
        if let Some(v) = self.safety.untrusted_content_guard {
            cfg.untrusted_content_guard = v;
        }
        if let Some(ref v) = self.safety.webhook_allowed_hosts {
            cfg.webhook_allowed_hosts = v.clone();
        }
        if let Some(v) = self.safety.allow_private_endpoints {
            cfg.allow_private_endpoints = v;
        }
        if let Some(v) = self.safety.allow_insecure_webhooks {
            cfg.allow_insecure_webhooks = v;
        }

        // [imap]
        if let Some(v) = self.imap.bind {
            cfg.imap_bind = Some(v);
        }
        if let Some(v) = self.imap.tls_bind {
            cfg.imap_tls_bind = Some(v);
        }
        if let Some(ref v) = self.imap.tls_cert {
            cfg.imap_tls_cert = Some(v.clone());
        }
        if let Some(ref v) = self.imap.tls_key {
            cfg.imap_tls_key = Some(v.clone());
        }
        if let Some(ref v) = self.imap.username {
            cfg.imap_username = Some(v.clone());
        }
        if let Some(ref v) = self.imap.password {
            cfg.imap_password = Some(v.clone());
        }

        // [sync]
        if let Some(v) = self.sync.mode {
            cfg.sync_mode = v;
        }
        if let Some(v) = self.sync.interval_secs {
            cfg.sync_interval_secs = v;
        }
        if let Some(ref v) = self.sync.query {
            cfg.sync_query = Some(v.clone());
        }
        if let Some(v) = self.sync.max_messages {
            cfg.sync_max_messages = Some(v);
        }
        if let Some(v) = self.sync.bidirectional {
            cfg.sync_bidirectional = v;
        }
        if let Some(ref v) = self.sync.gmail_client_id {
            cfg.gmail_client_id = Some(v.clone());
        }
        if let Some(ref v) = self.sync.gmail_client_secret {
            cfg.gmail_client_secret = Some(v.clone());
        }
        if let Some(ref v) = self.sync.gmail_refresh_token {
            cfg.gmail_refresh_token = Some(v.clone());
        }
        if let Some(ref v) = self.sync.gmail_access_token {
            cfg.gmail_access_token = Some(v.clone());
        }
        if let Some(ref v) = self.sync.gmail_user_id {
            cfg.gmail_user_id = v.clone();
        }
        if let Some(ref v) = self.sync.gmail_api_base_url {
            cfg.gmail_api_base_url = v.clone();
        }
        if let Some(ref v) = self.sync.gmail_oauth_token_url {
            cfg.gmail_oauth_token_url = v.clone();
        }
        if let Some(ref v) = self.sync.gmail_imap_host {
            cfg.gmail_imap_host = v.clone();
        }
        if let Some(v) = self.sync.gmail_imap_port {
            cfg.gmail_imap_port = v;
        }
        if let Some(v) = self.sync.gmail_imap_tls {
            cfg.gmail_imap_tls = v;
        }
        if let Some(ref v) = self.sync.gmail_imap_user {
            cfg.gmail_imap_user = Some(v.clone());
        }
        if let Some(ref v) = self.sync.gmail_imap_password {
            cfg.gmail_imap_password = Some(v.clone());
        }
        if let Some(ref v) = self.sync.gmail_imap_mailbox {
            cfg.gmail_imap_mailbox = v.clone();
        }
        if let Some(ref v) = self.sync.gmail_imap_folders {
            cfg.gmail_imap_folders = v.clone();
        }
        if let Some(ref v) = self.sync.gmail_imap_archive_mailbox {
            cfg.gmail_imap_archive_mailbox = v.clone();
        }
        if let Some(v) = self.sync.gmail_imap_idle {
            cfg.gmail_imap_idle = v;
        }
        if let Some(ref accounts) = self.sync.accounts {
            cfg.sync_accounts = accounts
                .iter()
                .cloned()
                .map(|mut acct| {
                    acct.mailbox_id = normalize_mailbox_id(&acct.mailbox_id);
                    acct
                })
                .collect();
        }

        // [watch]
        if let Some(ref v) = self.watch.webhook_url {
            cfg.watch_webhook_url = Some(v.clone());
        }

        // [filters]
        if let Some(v) = self.filters.auth_results {
            cfg.filter_auth_results = v;
        }
        if let Some(v) = self.filters.dmarc_fail_action {
            cfg.filter_dmarc_fail_action = v;
        }
        if let Some(v) = self.filters.spf_fail_action {
            cfg.filter_spf_fail_action = v;
        }
        if let Some(v) = self.filters.dkim_fail_action {
            cfg.filter_dkim_fail_action = v;
        }
        if let Some(ref v) = self.filters.rspamd.url {
            cfg.rspamd_url = Some(v.clone());
        }
        if let Some(ref v) = self.filters.rspamd.password {
            cfg.rspamd_password = Some(v.clone());
        }
        if let Some(v) = self.filters.rspamd.timeout_ms {
            cfg.rspamd_timeout_ms = v;
        }
        if let Some(v) = self.filters.rspamd.spam_threshold {
            cfg.rspamd_spam_threshold = Some(v);
        }
        if let Some(v) = self.filters.rspamd.reject_action {
            cfg.rspamd_reject_action = v;
        }
        if let Some(v) = self.filters.rspamd.fail_closed {
            cfg.rspamd_fail_closed = v;
        }
        if let Some(ref v) = self.filters.llm_triage.base_url {
            cfg.llm_triage_base_url = Some(v.clone());
        }
        if let Some(ref v) = self.filters.llm_triage.api_key {
            cfg.llm_triage_api_key = Some(v.clone());
        }
        if let Some(ref v) = self.filters.llm_triage.model {
            cfg.llm_triage_model = v.clone();
        }
        if let Some(v) = self.filters.llm_triage.timeout_ms {
            cfg.llm_triage_timeout_ms = v;
        }
        if let Some(v) = self.filters.llm_triage.max_body_chars {
            cfg.llm_triage_max_body_chars = v;
        }

        // [security]
        if let Some(ref v) = self.security.encryption_key {
            cfg.encryption_key = Some(v.clone());
        }
        if let Some(ref v) = self.security.encryption_previous_keys {
            cfg.encryption_previous_keys = v.clone();
        }

        // [search]
        if let Some(v) = self.search.backend {
            cfg.search_backend = v;
        }
        if let Some(ref v) = self.search.embedding_base_url {
            cfg.embedding_base_url = Some(v.clone());
        }
        if let Some(ref v) = self.search.embedding_api_key {
            cfg.embedding_api_key = Some(v.clone());
        }
        if let Some(ref v) = self.search.embedding_model {
            cfg.embedding_model = v.clone();
        }
        if let Some(v) = self.search.embedding_timeout_secs {
            cfg.embedding_timeout_secs = v;
        }

        meta
    }
}

// ============================================================================
// Configuration validation (`nogml config check`) & starter template (`init`)
// ============================================================================

/// Structured validation report emitted by `nogml config check`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigCheckReport {
    pub ok: bool,
    pub config_file: Option<PathBuf>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub effective_config: Option<Value>,
}

fn validate_optional_url(label: &str, value: Option<&str>, errors: &mut Vec<String>) {
    if let Some(raw) = value.map(str::trim).filter(|s| !s.is_empty())
        && let Err(err) = Url::parse(raw)
    {
        errors.push(format!("Invalid URL for {label} ('{raw}'): {err}"));
    }
}

/// Validate a resolved [`Config`] across storage, blob, transport, auth/OAuth2, IMAP TLS,
/// safety, filter, search, and sync settings without leaking any secrets.
pub fn validate_config(
    config: &Config,
    config_file: Option<PathBuf>,
    resolution: SecretResolutionReport,
) -> ConfigCheckReport {
    let mut warnings = resolution.warnings;
    let mut errors = resolution.errors;

    // --- Server & safety bounds ---
    if config.max_body_bytes == 0 {
        errors.push("server.max_body_bytes must be greater than 0".to_string());
    }
    if config.max_send_recipients == 0 {
        errors.push("safety.max_send_recipients must be greater than 0".to_string());
    }
    if config.approval_ttl_secs == 0 {
        errors.push("safety.approval_ttl_secs must be greater than 0".to_string());
    }

    // --- Storage ---
    if config.storage == StorageBackend::Postgres {
        match config
            .database_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            None => {
                if !errors.iter().any(|e| e.contains("storage.database_url")) {
                    errors.push(
                        "storage.database_url (NOGML_DATABASE_URL / NOGML_DATABASE_URL_FILE) is required when storage.backend = \"postgres\""
                            .to_string(),
                    );
                }
            }
            Some(url) => {
                if !url.starts_with("postgres://") && !url.starts_with("postgresql://") {
                    errors.push(
                        "storage.database_url must start with postgres:// or postgresql://"
                            .to_string(),
                    );
                }
            }
        }
        #[cfg(not(feature = "postgres"))]
        errors.push(
            "storage.backend = \"postgres\" requires building nogml with --features postgres"
                .to_string(),
        );
    }

    // --- BlobStore ---
    if config.blob_backend == BlobBackend::S3
        && let Err(err) = S3BlobConfig::from_config(config)
    {
        errors.push(err.to_string());
    }

    if config.allow_insecure_webhooks {
        warnings.push(
            "safety.allow_insecure_webhooks is enabled; unsigned webhooks on /webhooks/resend and /webhooks/ses will be accepted without verification"
                .to_string(),
        );
    }
    if config.allow_private_endpoints {
        warnings.push(
            "safety.allow_private_endpoints is enabled; SSRF private IP protections are relaxed"
                .to_string(),
        );
    }

    // --- Outbound transport ---
    match config.transport {
        TransportBackend::Resend => {
            validate_optional_url(
                "resend.base_url",
                Some(config.resend_base_url.as_str()),
                &mut errors,
            );
            if config
                .resend_api_key
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .is_none()
            {
                warnings.push(
                    "resend.api_key is not set; outbound Resend sends and Receiving API fetches will fail"
                        .to_string(),
                );
            }
            if config
                .resend_webhook_secret
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .is_none()
            {
                warnings.push(
                    "resend.webhook_secret is not set; POST /webhooks/resend signature verification is not configured"
                        .to_string(),
                );
            }
        }
        TransportBackend::Ses => {
            if let Err(err) = SesConfig::from_config(config) {
                errors.push(err.to_string());
            }
            if config
                .ses_access_key_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .is_none()
                || config
                    .ses_secret_access_key
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .is_none()
            {
                warnings.push(
                    "ses.access_key_id or ses.secret_access_key is missing; outbound AWS SES sends will fail"
                        .to_string(),
                );
            }
        }
        TransportBackend::Smtp => {
            if let Err(err) = SmtpConfig::from_config(config) {
                errors.push(err.to_string());
            }
            let has_user = config
                .smtp_username
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty());
            let has_pass = config
                .smtp_password
                .as_deref()
                .is_some_and(|s| !s.is_empty());
            if has_user != has_pass {
                warnings.push(
                    "Only one of smtp.username and smtp.password is set; SMTP AUTH requires both"
                        .to_string(),
                );
            }
        }
    }

    // --- Auth & OAuth2 ---
    if !config.auth_required() {
        warnings.push(
            "No auth.tokens, auth.scoped_tokens, or oauth2 credentials configured; HTTP server will run in unauthenticated dev mode"
                .to_string(),
        );
    }

    let has_oauth_client = config
        .oauth2_client_id
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty());
    let has_oauth_signing = config
        .oauth2_signing_secret
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty());
    if has_oauth_client != has_oauth_signing {
        errors.push(
            "OAuth2 requires both oauth2.client_id and oauth2.signing_secret to be set together"
                .to_string(),
        );
    }
    if config
        .oauth2_client_secret
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty())
        && !config.oauth2_enabled()
    {
        warnings.push(
            "oauth2.client_secret is set, but local OAuth2 is inactive until both oauth2.client_id and oauth2.signing_secret are configured"
                .to_string(),
        );
    }
    for (idx, uri) in config.oauth2_redirect_uris.iter().enumerate() {
        let trimmed = uri.trim();
        if trimmed.is_empty() || trimmed.contains('\r') || trimmed.contains('\n') {
            errors.push(format!(
                "oauth2.redirect_uris[{idx}] must be a non-empty single-line URI"
            ));
        } else if url::Url::parse(trimmed).is_err() {
            errors.push(format!(
                "oauth2.redirect_uris[{idx}] ('{trimmed}') must be a valid absolute URI"
            ));
        }
    }

    for (idx, st) in config.scoped_tokens.iter().enumerate() {
        if st.token.trim().is_empty() {
            let tag = format!("auth.scoped_tokens[{idx}].token");
            if !errors.iter().any(|e| e.contains(&tag)) {
                errors.push(format!("{tag} must not be empty"));
            }
        }
        if st.scopes.is_empty() {
            warnings.push(format!(
                "auth.scoped_tokens[{idx}] has no scopes; requests using this token will receive 403 Forbidden"
            ));
        }
    }

    // --- IMAP TLS / STARTTLS ---
    match (
        config.imap_tls_cert.as_deref(),
        config.imap_tls_key.as_deref(),
    ) {
        (Some(cert), Some(key)) => {
            if let Err(err) = crate::imap::build_tls_acceptor(cert, key) {
                errors.push(err.to_string());
            } else if let Some(warn) = check_secret_file_permissions(key)
                && !warnings.contains(&warn)
            {
                warnings.push(warn);
            }
        }
        (Some(_), None) | (None, Some(_)) => {
            errors.push(
                "Both imap.tls_cert and imap.tls_key must be set together for IMAP TLS/STARTTLS"
                    .to_string(),
            );
        }
        (None, None) => {
            if config.imap_tls_bind.is_some() {
                errors.push(
                    "imap.tls_bind requires both imap.tls_cert and imap.tls_key to be configured"
                        .to_string(),
                );
            }
        }
    }

    // --- URLs, filters, search, sync ---
    validate_optional_url(
        "safety.approval_webhook_url",
        config.approval_webhook_url.as_deref(),
        &mut errors,
    );
    validate_optional_url(
        "watch.webhook_url",
        config.watch_webhook_url.as_deref(),
        &mut errors,
    );
    validate_optional_url(
        "filters.rspamd.url",
        config.rspamd_url.as_deref(),
        &mut errors,
    );
    validate_optional_url(
        "filters.llm_triage.base_url",
        config.llm_triage_base_url.as_deref(),
        &mut errors,
    );
    validate_optional_url(
        "sync.gmail_api_base_url",
        Some(config.gmail_api_base_url.as_str()),
        &mut errors,
    );
    validate_optional_url(
        "sync.gmail_oauth_token_url",
        Some(config.gmail_oauth_token_url.as_str()),
        &mut errors,
    );
    validate_optional_url(
        "search.embedding_base_url",
        config.embedding_base_url.as_deref(),
        &mut errors,
    );

    if config.search_backend == SearchBackend::Hybrid
        && let Err(err) = OpenAiEmbeddingConfig::from_config(config)
    {
        errors.push(err.to_string());
    }

    // --- Encryption at rest ---
    if !errors.iter().any(|e| e.contains("security.encryption_"))
        && let Err(err) = crate::crypto::SecretCipher::from_config(config)
    {
        errors.push(err.to_string());
    }

    if config.sync_interval_secs > 0 && !config.gmail_sync_configured() {
        warnings.push(
            "sync.interval_secs > 0, but no upstream Gmail sync credentials are configured"
                .to_string(),
        );
    }

    let mut seen_sync_mailboxes = HashSet::new();
    for (idx, acct) in config.sync_accounts.iter().enumerate() {
        let mb = normalize_mailbox_id(&acct.mailbox_id);
        if mb.is_empty() {
            errors.push(format!("sync.accounts[{idx}].mailbox_id must not be empty"));
        } else if !seen_sync_mailboxes.insert(mb.clone()) {
            warnings.push(format!("sync.accounts[{idx}] duplicates mailbox_id '{mb}'"));
        }
        validate_optional_url(
            &format!("sync.accounts[{idx}].gmail_api_base_url"),
            Some(acct.gmail_api_base_url.as_str()),
            &mut errors,
        );
        validate_optional_url(
            &format!("sync.accounts[{idx}].gmail_oauth_token_url"),
            Some(acct.gmail_oauth_token_url.as_str()),
            &mut errors,
        );
        if acct.interval_secs > 0 && !acct.is_configured() {
            warnings.push(format!(
                "sync.accounts[{idx}] ('{}') has interval_secs > 0, but no upstream Gmail sync credentials are configured",
                acct.mailbox_id
            ));
        }
    }

    for (alias, target) in &config.mailbox_aliases {
        let norm_alias = normalize_mailbox_id(alias);
        let norm_target = normalize_mailbox_id(target);
        if norm_alias.is_empty()
            || !norm_alias.contains('@')
            || norm_alias.contains(char::is_whitespace)
        {
            errors.push(format!(
                "mailboxes.aliases key '{alias}' must be a valid email address"
            ));
        }
        if norm_target.is_empty()
            || !norm_target.contains('@')
            || norm_target.contains(char::is_whitespace)
        {
            errors.push(format!(
                "mailboxes.aliases target '{target}' for '{alias}' must be a valid email address"
            ));
        }
    }

    ConfigCheckReport {
        ok: errors.is_empty(),
        config_file,
        warnings,
        errors,
        effective_config: Some(config.redacted_summary()),
    }
}

/// Render a cleanly annotated starter `nogml.toml` using `env://` and `file://` secret references
/// instead of hardcoded secrets.
pub fn render_starter_toml(
    user_email: &str,
    default_domain: &str,
    token_file: Option<&Path>,
) -> String {
    let tokens_line = match token_file {
        Some(path) => {
            let escaped = path.display().to_string().replace('\\', "\\\\").replace('"', "\\\"");
            format!("tokens = [\"file://{escaped}\"]")
        }
        None => {
            "# Set NOGML_AUTH_TOKENS or NOGML_AUTH_TOKENS_FILE, or reference a secret file:\n# tokens = [\"env://NOGML_AUTH_TOKENS\"]\n# tokens = [\"file:///etc/nogml/secrets/auth_token\"]".to_string()
        }
    };

    format!(
        r#"# nogml configuration file
# Precedence: CLI flags > environment variables > nogml.toml > defaults
# Secret values support "file:///path/to/secret", "env://VAR_NAME",
# "file://$CREDENTIALS_DIRECTORY/secret", or *_FILE environment variables.

[server]
bind = "127.0.0.1:8080"
max_body_bytes = 41943040
# cors_allow_origins = ["https://app.example.com"]
# log_json = true

[storage]
backend = "sqlite"
db_path = "nogml.db"
# For multi-node deployments (--features postgres):
# backend = "postgres"
# database_url = "file:///run/secrets/database_url"

[blob]
backend = "inline"
dir = "nogml-blobs"
# For local disk or S3/R2 blobs:
# backend = "fs"
# backend = "s3"
# s3_bucket = "my-mail-blobs"
# s3_region = "us-east-1"
# s3_secret_access_key = "env://NOGML_BLOB_S3_SECRET_ACCESS_KEY"

[auth]
user_email = "{user_email}"
default_domain = "{default_domain}"
# mailboxes = ["support@{default_domain}"]
{tokens_line}

# Example least-privilege scoped token:
# [[auth.scoped_tokens]]
# token = "file:///etc/nogml/secrets/agent_ro_token"
# mailbox_id = "{user_email}"
# scopes = ["read"]
# draft_only = true

[transport]
backend = "resend"

[resend]
# api_key = "env://RESEND_API_KEY"
# webhook_secret = "env://RESEND_WEBHOOK_SECRET"
base_url = "https://api.resend.com"

[safety]
# Start in draft-only mode until outbound recipients and webhooks are verified.
draft_only = true
draft_only_action = "block"
require_approval = false
first_contact_approval = false
require_verified_from_domain = false
dlp_action = "off"
approval_ttl_secs = 86400
# allowed_recipients = ["@{default_domain}"]
max_send_recipients = 50
default_max_body_chars = 4000
untrusted_content_guard = true

[imap]
# bind = "127.0.0.1:1143"
# tls_bind = "0.0.0.0:1993"
# tls_cert = "/etc/nogml/tls/fullchain.pem"
# tls_key = "/etc/nogml/tls/privkey.pem"
# password = "file:///etc/nogml/secrets/imap_password"

[security]
# Optional AES-256-GCM encryption at rest for stored SMTP and webhook secrets.
# Generate a key with: nogml crypto generate-key --kid k1 --output-file /etc/nogml/secrets/encryption_key
# encryption_key = "file:///etc/nogml/secrets/encryption_key"
# encryption_previous_keys = ["file:///etc/nogml/secrets/encryption_key_old"]

[search]
backend = "store"
# backend = "hybrid"
# embedding_base_url = "http://127.0.0.1:11434/v1"
# embedding_api_key = "env://NOGML_EMBEDDING_API_KEY"
# embedding_model = "text-embedding-3-small"
"#
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        auth::AuthScope,
        secrets::{ValueOrigin, write_secret_file},
    };

    use super::*;

    #[test]
    fn debug_and_redacted_summary_never_leak_secrets() {
        let mut cfg = Config::for_test();
        cfg.database_url = Some("postgres://u:super-secret-db-pass@db/nogml".to_string());
        cfg.blob_s3_secret_access_key = Some("super-secret-s3-key".to_string());
        cfg.blob_s3_session_token = Some("super-secret-s3-session".to_string());
        cfg.auth_tokens = vec!["super-secret-bearer-token".to_string()];
        cfg.scoped_tokens = vec![ScopedTokenConfig {
            token: "super-secret-scoped-token".to_string(),
            mailbox_id: Some("agent@example.com".to_string()),
            shared_mailboxes: vec!["team@example.com".to_string()],
            scopes: vec![AuthScope::Read],
            draft_only: Some(true),
            allowed_recipients: None,
            max_send_recipients: None,
        }];
        cfg.sync_accounts = vec![SyncAccountConfig {
            mailbox_id: "alice@example.com".to_string(),
            gmail_client_secret: Some("super-secret-acct-client".to_string()),
            gmail_refresh_token: Some("super-secret-acct-refresh".to_string()),
            gmail_access_token: Some("super-secret-acct-access".to_string()),
            gmail_imap_password: Some("super-secret-acct-imap".to_string()),
            ..SyncAccountConfig::default()
        }];
        cfg.oauth2_client_secret = Some("super-secret-oauth-client".to_string());
        cfg.oauth2_signing_secret = Some("super-secret-oauth-sign".to_string());
        cfg.resend_api_key = Some("super-secret-resend-key".to_string());
        cfg.resend_webhook_secret = Some("super-secret-resend-whsec".to_string());
        cfg.ses_secret_access_key = Some("super-secret-ses-key".to_string());
        cfg.ses_session_token = Some("super-secret-ses-session".to_string());
        cfg.ses_webhook_secret = Some("super-secret-ses-whsec".to_string());
        cfg.smtp_password = Some("super-secret-smtp-pass".to_string());
        cfg.imap_password = Some("super-secret-imap-pass".to_string());
        cfg.gmail_client_secret = Some("super-secret-gmail-client".to_string());
        cfg.gmail_refresh_token = Some("super-secret-gmail-refresh".to_string());
        cfg.gmail_access_token = Some("super-secret-gmail-access".to_string());
        cfg.gmail_imap_password = Some("super-secret-gmail-imap".to_string());
        cfg.rspamd_password = Some("super-secret-rspamd".to_string());
        cfg.llm_triage_api_key = Some("super-secret-llm".to_string());
        cfg.embedding_api_key = Some("super-secret-embed".to_string());
        cfg.encryption_key = Some("k2:super-secret-enc-primary".to_string());
        cfg.encryption_previous_keys = vec!["k1:super-secret-enc-prev".to_string()];
        cfg.approval_webhook_url = Some(
            "https://user:approval-pass@hooks.slack.com/services/T0/B0/SUPER_SECRET_APPROVAL?token=qsec"
                .to_string(),
        );
        cfg.watch_webhook_url = Some(
            "https://watch-user:watch-pass@discord.com:8443/api/webhooks/123/SUPER_SECRET_WATCH?wait=true"
                .to_string(),
        );

        let debug_out = format!("{cfg:?}");
        let summary_out = cfg.redacted_summary().to_string();

        for leaked in [
            "super-secret-db-pass",
            "super-secret-s3-key",
            "super-secret-s3-session",
            "super-secret-bearer-token",
            "super-secret-scoped-token",
            "super-secret-oauth-client",
            "super-secret-oauth-sign",
            "super-secret-resend-key",
            "super-secret-resend-whsec",
            "super-secret-ses-key",
            "super-secret-ses-session",
            "super-secret-ses-whsec",
            "super-secret-smtp-pass",
            "super-secret-imap-pass",
            "super-secret-gmail-client",
            "super-secret-gmail-refresh",
            "super-secret-gmail-access",
            "super-secret-gmail-imap",
            "super-secret-acct-client",
            "super-secret-acct-refresh",
            "super-secret-acct-access",
            "super-secret-acct-imap",
            "super-secret-rspamd",
            "super-secret-llm",
            "super-secret-embed",
            "super-secret-enc-primary",
            "super-secret-enc-prev",
            "approval-pass",
            "SUPER_SECRET_APPROVAL",
            "qsec",
            "watch-pass",
            "SUPER_SECRET_WATCH",
        ] {
            assert!(
                !debug_out.contains(leaked),
                "Debug output leaked secret '{leaked}'"
            );
            assert!(
                !summary_out.contains(leaked),
                "redacted_summary leaked secret '{leaked}'"
            );
        }

        assert!(debug_out.contains("https://hooks.slack.com/[REDACTED]"));
        assert!(debug_out.contains("https://discord.com:8443/[REDACTED]"));
        assert!(summary_out.contains("https://hooks.slack.com/[REDACTED]"));
        assert!(summary_out.contains("https://discord.com:8443/[REDACTED]"));
        assert!(debug_out.contains(REDACTED));
        assert!(summary_out.contains(REDACTED));
    }

    #[test]
    fn redacted_debug_across_toml_oauth2_transport_filter_and_model_structs() {
        let toml_raw = r#"
[storage]
database_url = "postgres://u:toml-db-secret@localhost/db"
[blob]
s3_secret_access_key = "toml-s3-secret"
s3_session_token = "toml-s3-session"
[auth]
tokens = ["toml-auth-tok"]
[oauth2]
client_id = "cid"
client_secret = "toml-oauth-csec"
signing_secret = "toml-oauth-ssec"
redirect_uris = ["http://127.0.0.1:8080/cb"]
[resend]
api_key = "toml-resend-key"
webhook_secret = "toml-resend-whsec"
[ses]
secret_access_key = "toml-ses-secret"
session_token = "toml-ses-session"
webhook_secret = "toml-ses-whsec"
[smtp]
password = "toml-smtp-pass"
[safety]
approval_webhook_url = "https://hooks.slack.com/services/T/B/toml-approval-secret"
[imap]
password = "toml-imap-pass"
[sync]
gmail_client_secret = "toml-gmail-csec"
gmail_refresh_token = "toml-gmail-rt"
gmail_access_token = "toml-gmail-at"
gmail_imap_password = "toml-gmail-imap"
[watch]
webhook_url = "https://discord.com/api/webhooks/1/toml-watch-secret"
[filters.rspamd]
password = "toml-rspamd-pass"
[filters.llm_triage]
api_key = "toml-llm-key"
[security]
encryption_key = "k2:toml-enc-primary"
encryption_previous_keys = ["k1:toml-enc-prev"]
[search]
embedding_api_key = "toml-embed-key"
"#;
        let parsed = TomlConfig::from_toml_str(toml_raw).unwrap();
        let toml_dbg = format!("{parsed:?}");
        for secret in [
            "toml-db-secret",
            "toml-s3-secret",
            "toml-s3-session",
            "toml-auth-tok",
            "toml-oauth-csec",
            "toml-oauth-ssec",
            "toml-resend-key",
            "toml-resend-whsec",
            "toml-ses-secret",
            "toml-ses-session",
            "toml-ses-whsec",
            "toml-smtp-pass",
            "toml-approval-secret",
            "toml-imap-pass",
            "toml-gmail-csec",
            "toml-gmail-rt",
            "toml-gmail-at",
            "toml-gmail-imap",
            "toml-watch-secret",
            "toml-rspamd-pass",
            "toml-llm-key",
            "toml-enc-primary",
            "toml-enc-prev",
            "toml-embed-key",
        ] {
            assert!(
                !toml_dbg.contains(secret),
                "TomlConfig Debug leaked '{secret}': {toml_dbg}"
            );
        }

        let mut cfg = Config::for_test();
        parsed.apply_to(&mut cfg);
        assert_eq!(
            cfg.oauth2_redirect_uris,
            vec!["http://127.0.0.1:8080/cb".to_string()]
        );

        let verifier = crate::oauth2::OAuth2Verifier::from_config(&cfg).unwrap();
        let verifier_dbg = format!("{verifier:?}");
        assert!(!verifier_dbg.contains("toml-oauth-ssec"));
        assert!(verifier_dbg.contains(REDACTED));

        let ses_cfg = crate::transport::ses::SesConfig::from_config(&cfg).unwrap();
        let ses_dbg = format!("{ses_cfg:?}");
        assert!(!ses_dbg.contains("toml-ses-secret"));
        assert!(!ses_dbg.contains("toml-ses-session"));
        assert!(!ses_dbg.contains("toml-ses-whsec"));
        assert!(ses_dbg.contains(REDACTED));

        let smtp_cfg = crate::transport::smtp::SmtpConfig::from_config(&cfg).unwrap();
        let smtp_dbg = format!("{smtp_cfg:?}");
        assert!(!smtp_dbg.contains("toml-smtp-pass"));
        assert!(smtp_dbg.contains(REDACTED));

        let resend_client = crate::resend::HttpResendClient::from_config(&cfg);
        let resend_dbg = format!("{resend_client:?}");
        assert!(!resend_dbg.contains("toml-resend-key"));
        assert!(resend_dbg.contains(REDACTED));

        let mut rspamd = crate::filter::rspamd::RspamdConfig::new("http://127.0.0.1:11333");
        rspamd.password = Some("rspamd-direct-secret".to_string());
        let rspamd_dbg = format!("{rspamd:?}");
        assert!(!rspamd_dbg.contains("rspamd-direct-secret"));
        assert!(rspamd_dbg.contains(REDACTED));

        let mut llm = crate::filter::llm::LlmTriageConfig::new("https://api.example.com/v1", "m1");
        llm.api_key = Some("llm-direct-secret".to_string());
        let llm_dbg = format!("{llm:?}");
        assert!(!llm_dbg.contains("llm-direct-secret"));
        assert!(llm_dbg.contains(REDACTED));

        let msa = crate::models::SmtpMsa {
            host: "smtp.example.com".to_string(),
            port: 587,
            security_mode: Some("starttls".to_string()),
            username: Some("u".to_string()),
            password: Some("msa-direct-secret".to_string()),
        };
        let msa_dbg = format!("{msa:?}");
        assert!(!msa_dbg.contains("msa-direct-secret"));
        assert!(msa_dbg.contains(REDACTED));
    }

    #[test]
    fn starter_toml_parses_cleanly() {
        let rendered = render_starter_toml("agent@example.com", "example.com", None);
        let parsed = TomlConfig::from_toml_str(&rendered).expect("starter toml must parse");
        let mut cfg = Config::default();
        let meta = parsed.apply_to(&mut cfg);
        assert!(meta.user_email_set);
        assert_eq!(cfg.user_email, "agent@example.com");
        assert_eq!(cfg.default_domain, "example.com");
        assert!(cfg.draft_only);
    }

    #[test]
    fn env_file_and_uri_resolution_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let resend_file = dir.path().join("resend_key");
        let tokens_file = dir.path().join("tokens");
        let scoped_token_file = dir.path().join("scoped_tok");
        write_secret_file(&resend_file, "re_from_env_file", false).unwrap();
        write_secret_file(&tokens_file, "tok_a\ntok_b", false).unwrap();
        write_secret_file(&scoped_token_file, "tok_scoped_secret", false).unwrap();

        let toml_src = format!(
            r#"
[auth]
user_email = "bot@example.com"
tokens = ["file://{}"]

[[auth.scoped_tokens]]
token = "file://{}"
scopes = ["read"]

[resend]
api_key = "env://RESEND_FROM_TOML"
webhook_secret = "env://WEBHOOK_ENV"
"#,
            tokens_file.display(),
            scoped_token_file.display()
        );
        let parsed = TomlConfig::from_toml_str(&toml_src).unwrap();
        let mut cfg = Config::default();
        parsed.apply_to(&mut cfg);

        let vars: HashMap<String, String> = [
            (
                "RESEND_API_KEY_FILE".to_string(),
                resend_file.display().to_string(),
            ),
            ("WEBHOOK_ENV".to_string(), "whsec_from_env".to_string()),
        ]
        .into_iter()
        .collect();

        let report = cfg.apply_env_file_secrets_and_resolve(
            Some(dir.path()),
            &|_| ValueOrigin::Unset,
            &|k| vars.get(k).cloned(),
        );
        assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
        assert_eq!(cfg.resend_api_key.as_deref(), Some("re_from_env_file"));
        assert_eq!(cfg.resend_webhook_secret.as_deref(), Some("whsec_from_env"));
        assert_eq!(cfg.auth_tokens, vec!["tok_a", "tok_b"]);
        assert_eq!(cfg.scoped_tokens[0].token, "tok_scoped_secret");
    }

    #[test]
    fn unknown_toml_key_fails_parse() {
        let bad = "[safety]\ndraft_olny = true\n";
        let err = TomlConfig::from_toml_str(bad).unwrap_err();
        assert!(err.to_string().contains("draft_olny"));
    }
}
