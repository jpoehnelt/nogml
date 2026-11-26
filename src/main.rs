use std::{
    fs,
    io::{IsTerminal, Read},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use clap::{
    ArgMatches, Args, CommandFactory, FromArgMatches, Parser, Subcommand, parser::ValueSource,
};
use serde_json::{Value, json};
use tokio::sync::watch;
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, fmt};

use nogml::{
    AppState,
    ai::{self, ApprovalDecisionRequest},
    auth::{AuthScope, ScopedTokenConfig},
    auth_wizard::{
        DEFAULT_GMAIL_AUTH_URL, DEFAULT_GMAIL_SCOPE, DEFAULT_GMAIL_TOKEN_URL,
        DEFAULT_OAUTH_TIMEOUT_SECS, GmailAuthOptions, MintTokenOptions, mint_scoped_token,
        parse_auth_scope, render_scoped_token_json, render_scoped_token_toml, run_gmail_oauth_flow,
    },
    blob::{migrate_blobs, open_blob_store},
    build_router,
    config::{
        AuthFailAction, BlobBackend, Config, ConfigCheckReport, DlpAction, DraftOnlyAction,
        RspamdRejectAction, SearchBackend, SmtpTlsMode, StorageBackend, SyncMode, TomlConfig,
        TransportBackend, render_starter_toml, validate_config,
    },
    crypto::{DEFAULT_KEY_ID, generate_formatted_key, rotate_secrets},
    doctor::{DoctorReport, run_doctor},
    ensure_crypto_provider,
    error::{AppError, AppResult},
    events::EventSource,
    gmail, imap, mcp,
    models::{AiBatchTriageRequest, AiCreateDraftRequest, AiSendEmailRequest, AiTriageRequest},
    search_index::reindex_mailbox,
    secrets::{
        SecretResolutionReport, ValueOrigin, generate_bearer_token, read_secret_file,
        resolve_secret_value, system_env_lookup, write_secret_file,
    },
    storage::{AiSearchQuery, AiThreadQuery, SqliteStore},
    sync::{self, SyncRunOptions},
};

#[derive(Debug, Clone)]
struct ScopedTokenList(Vec<ScopedTokenConfig>);

fn parse_scoped_tokens_arg(raw: &str) -> Result<ScopedTokenList, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(ScopedTokenList(Vec::new()));
    }
    let parsed: Vec<ScopedTokenConfig> = serde_json::from_str(trimmed)
        .map_err(|e| format!("Invalid JSON for NOGML_SCOPED_TOKENS / --scoped-tokens: {e}"))?;
    Ok(ScopedTokenList(parsed))
}

#[derive(Debug, Parser)]
#[command(
    name = "nogml",
    version,
    about = "AI-first headless Rust email server (MCP, Gmail REST API v1, IMAP4rev1, Resend, Gmail sync)"
)]
struct Cli {
    /// Emit structured JSON logs to stderr.
    #[arg(long, env = "NOGML_LOG_JSON", global = true)]
    log_json: bool,

    /// Common storage/config options shared across subcommands.
    #[command(flatten)]
    common: CommonConfigArgs,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Args)]
struct CommonConfigArgs {
    /// Path to a structured TOML configuration file (`nogml.toml`).
    #[arg(long, env = "NOGML_CONFIG", global = true)]
    config: Option<PathBuf>,

    /// Storage backend (`sqlite`, `memory`, or `postgres`).
    #[arg(long, env = "NOGML_STORAGE", default_value = "sqlite", global = true)]
    storage: StorageBackend,

    /// SQLite database file path (when `--storage=sqlite`).
    #[arg(long, env = "NOGML_DB_PATH", default_value = "nogml.db", global = true)]
    db_path: PathBuf,

    /// PostgreSQL connection URL (when `--storage=postgres`; requires `--features postgres`).
    #[arg(long, env = "NOGML_DATABASE_URL", global = true)]
    database_url: Option<String>,

    /// Blob storage backend (`inline`, `fs`, `memory`, or `s3`).
    #[arg(
        long,
        env = "NOGML_BLOB_BACKEND",
        default_value = "inline",
        global = true
    )]
    blob_backend: BlobBackend,

    /// Filesystem blob directory (when `--blob-backend=fs`).
    #[arg(
        long,
        env = "NOGML_BLOB_DIR",
        default_value = "nogml-blobs",
        global = true
    )]
    blob_dir: PathBuf,

    /// S3 bucket name (when `--blob-backend=s3`).
    #[arg(long, env = "NOGML_BLOB_S3_BUCKET", global = true)]
    blob_s3_bucket: Option<String>,

    /// S3 region (e.g. `us-east-1` or `auto` for Cloudflare R2).
    #[arg(
        long,
        env = "NOGML_BLOB_S3_REGION",
        default_value = "us-east-1",
        global = true
    )]
    blob_s3_region: String,

    /// Optional custom S3-compatible endpoint URL (e.g. Cloudflare R2 or MinIO).
    #[arg(long, env = "NOGML_BLOB_S3_ENDPOINT", global = true)]
    blob_s3_endpoint: Option<String>,

    /// Optional key prefix applied to all S3 object keys.
    #[arg(long, env = "NOGML_BLOB_S3_PREFIX", global = true)]
    blob_s3_prefix: Option<String>,

    /// S3 access key ID.
    #[arg(long, env = "NOGML_BLOB_S3_ACCESS_KEY_ID", global = true)]
    blob_s3_access_key_id: Option<String>,

    /// S3 secret access key.
    #[arg(long, env = "NOGML_BLOB_S3_SECRET_ACCESS_KEY", global = true)]
    blob_s3_secret_access_key: Option<String>,

    /// Optional S3 STS session token.
    #[arg(long, env = "NOGML_BLOB_S3_SESSION_TOKEN", global = true)]
    blob_s3_session_token: Option<String>,

    /// Force path-style S3 URLs (`true` by default when `--blob-s3-endpoint` is set).
    #[arg(long, env = "NOGML_BLOB_S3_FORCE_PATH_STYLE", global = true)]
    blob_s3_force_path_style: Option<bool>,

    /// Primary mailbox email address (defaults to sole existing mailbox in SQLite DB or `me@localhost`).
    #[arg(long, env = "NOGML_USER_EMAIL", global = true)]
    user_email: Option<String>,

    /// Comma-separated additional local mailboxes hosted by this instance.
    #[arg(long, env = "NOGML_MAILBOXES", value_delimiter = ',', global = true)]
    mailboxes: Vec<String>,

    /// Comma-separated mailbox alias mappings (`alias@example.com=target@example.com`).
    #[arg(long, env = "NOGML_MAILBOX_ALIASES", global = true)]
    mailbox_aliases: Option<String>,

    /// Default domain for generated Message-IDs and fallback sender addresses.
    #[arg(
        long,
        env = "NOGML_DEFAULT_DOMAIN",
        default_value = "localhost",
        global = true
    )]
    default_domain: String,

    /// Outbound mail transport backend (`resend`, `ses`, `smtp`, or `gmail`).
    #[arg(long, env = "NOGML_TRANSPORT", default_value = "resend", global = true)]
    transport: TransportBackend,

    /// Resend API key (`re_...`).
    #[arg(long, env = "RESEND_API_KEY", global = true)]
    resend_api_key: Option<String>,

    /// Resend API base URL (override for testing).
    #[arg(
        long,
        env = "RESEND_BASE_URL",
        default_value = "https://api.resend.com",
        global = true
    )]
    resend_base_url: String,

    /// Resend Svix webhook signing secret (`whsec_...`).
    #[arg(long, env = "RESEND_WEBHOOK_SECRET", global = true)]
    resend_webhook_secret: Option<String>,

    // --- AWS SES outbound & SNS/S3 inbound ---
    /// AWS region for SESv2 outbound sends and S3 inbound fetches.
    #[arg(
        long,
        env = "NOGML_SES_REGION",
        default_value = "us-east-1",
        global = true
    )]
    ses_region: String,

    /// Custom AWS SESv2 API endpoint URL (defaults to `https://email.<region>.amazonaws.com`).
    #[arg(long, env = "NOGML_SES_ENDPOINT", global = true)]
    ses_endpoint: Option<String>,

    /// AWS access key ID for SigV4 signing of SES and S3 requests.
    #[arg(long, env = "NOGML_SES_ACCESS_KEY_ID", global = true)]
    ses_access_key_id: Option<String>,

    /// AWS secret access key for SigV4 signing of SES and S3 requests.
    #[arg(long, env = "NOGML_SES_SECRET_ACCESS_KEY", global = true)]
    ses_secret_access_key: Option<String>,

    /// Optional AWS STS session token for SigV4 signing.
    #[arg(long, env = "NOGML_SES_SESSION_TOKEN", global = true)]
    ses_session_token: Option<String>,

    /// Custom S3 endpoint URL for SES inbound S3 fetches (defaults to `https://s3.<region>.amazonaws.com`).
    #[arg(long, env = "NOGML_SES_S3_ENDPOINT", global = true)]
    ses_s3_endpoint: Option<String>,

    /// Shared secret required by `POST /webhooks/ses` (via headers only:
    /// `X-Nogml-Webhook-Secret`, `X-SES-Webhook-Secret`, `X-Webhook-Secret`, or `Authorization: Bearer`).
    #[arg(long, env = "NOGML_SES_WEBHOOK_SECRET", global = true)]
    ses_webhook_secret: Option<String>,

    /// Comma-separated AWS SNS TopicArn allowlist for `POST /webhooks/ses`.
    #[arg(
        long,
        env = "NOGML_SES_ALLOWED_TOPIC_ARNS",
        value_delimiter = ',',
        global = true
    )]
    ses_allowed_topic_arns: Vec<String>,

    /// Comma-separated S3 bucket name allowlist for SES S3 inbound receipt actions.
    #[arg(
        long,
        env = "NOGML_SES_ALLOWED_S3_BUCKETS",
        value_delimiter = ',',
        global = true
    )]
    ses_allowed_s3_buckets: Vec<String>,

    // --- SMTP outbound submission ---
    /// Upstream SMTP relay host.
    #[arg(
        long,
        env = "NOGML_SMTP_HOST",
        default_value = "127.0.0.1",
        global = true
    )]
    smtp_host: String,

    /// Upstream SMTP relay TCP port.
    #[arg(long, env = "NOGML_SMTP_PORT", default_value_t = 587, global = true)]
    smtp_port: u16,

    /// SMTP TLS mode (`starttls`, `tls`, or `none`).
    #[arg(
        long,
        env = "NOGML_SMTP_TLS_MODE",
        default_value = "starttls",
        global = true
    )]
    smtp_tls_mode: SmtpTlsMode,

    /// Optional SMTP AUTH username.
    #[arg(long, env = "NOGML_SMTP_USERNAME", global = true)]
    smtp_username: Option<String>,

    /// Optional SMTP AUTH password.
    #[arg(long, env = "NOGML_SMTP_PASSWORD", global = true)]
    smtp_password: Option<String>,

    /// Optional SMTP `XOAUTH2` OAuth2 access token.
    #[arg(long, env = "NOGML_SMTP_OAUTH_TOKEN", global = true)]
    smtp_oauth_token: Option<String>,

    /// Optional `EHLO` domain name (defaults to `--default-domain`).
    #[arg(long, env = "NOGML_SMTP_HELO_DOMAIN", global = true)]
    smtp_helo_domain: Option<String>,

    /// Comma-separated bearer auth tokens (empty = dev unauthenticated mode).
    #[arg(long, env = "NOGML_AUTH_TOKENS", value_delimiter = ',', global = true)]
    auth_tokens: Vec<String>,

    /// JSON array of scoped API key definitions (e.g. `[{"token":"...","scopes":["read"],"draft_only":true}]`).
    #[arg(
        long,
        env = "NOGML_SCOPED_TOKENS",
        value_parser = parse_scoped_tokens_arg,
        global = true
    )]
    scoped_tokens: Option<ScopedTokenList>,

    /// Optional local OAuth2 client ID (auto-enables `/oauth2/*` when paired with `--oauth2-signing-secret`).
    #[arg(long, env = "NOGML_OAUTH2_CLIENT_ID", global = true)]
    oauth2_client_id: Option<String>,

    /// Optional local OAuth2 client secret required on `POST /oauth2/token`.
    #[arg(long, env = "NOGML_OAUTH2_CLIENT_SECRET", global = true)]
    oauth2_client_secret: Option<String>,

    /// HMAC-SHA256 signing secret for local OAuth2 JWT access and refresh tokens.
    #[arg(long, env = "NOGML_OAUTH2_SIGNING_SECRET", global = true)]
    oauth2_signing_secret: Option<String>,

    /// Comma-separated allowlist of permitted OAuth2 `redirect_uri` values on `GET /oauth2/authorize`.
    #[arg(
        long,
        env = "NOGML_OAUTH2_REDIRECT_URIS",
        value_delimiter = ',',
        global = true
    )]
    oauth2_redirect_uris: Vec<String>,

    /// Enable draft-only safety mode (prevent direct agent sends).
    #[arg(long, env = "NOGML_DRAFT_ONLY", default_value_t = false, global = true)]
    draft_only: bool,

    /// Action when `draft_only` is active (`block` or `downgrade`).
    #[arg(
        long,
        env = "NOGML_DRAFT_ONLY_ACTION",
        default_value = "block",
        global = true
    )]
    draft_only_action: DraftOnlyAction,

    /// Hold all outbound sends in the persistent approval queue until a human approves them.
    #[arg(
        long,
        env = "NOGML_REQUIRE_APPROVAL",
        default_value_t = false,
        global = true
    )]
    require_approval: bool,

    /// Hold outbound sends to recipients with no prior sent history for human approval.
    #[arg(
        long,
        env = "NOGML_FIRST_CONTACT_APPROVAL",
        default_value_t = false,
        global = true
    )]
    first_contact_approval: bool,

    /// Reject outbound sends whose From domain is neither the primary domain nor a verified BYOD domain owned by the sender's mailbox.
    #[arg(
        long,
        env = "NOGML_REQUIRE_VERIFIED_FROM_DOMAIN",
        default_value_t = false,
        global = true
    )]
    require_verified_from_domain: bool,

    /// Per-domain daily outbound send cap (`0` disables daily send cap enforcement).
    #[arg(
        long,
        alias = "daily-send-limit",
        env = "NOGML_DAILY_SEND_LIMIT_PER_DOMAIN",
        default_value_t = 0,
        global = true
    )]
    daily_send_limit_per_domain: u64,

    /// Rolling hard-bounce rate threshold above which a domain circuit breaker opens (default 0.05 = 5%; 0 disables).
    #[arg(
        long = "max-bounce-rate",
        env = "NOGML_MAX_BOUNCE_RATE",
        default_value_t = nogml::deliverability::DEFAULT_MAX_BOUNCE_RATE,
        global = true
    )]
    deliverability_max_bounce_rate: f64,

    /// Rolling complaint rate threshold above which a domain circuit breaker opens (default 0.001 = 0.1%; 0 disables).
    #[arg(
        long = "max-complaint-rate",
        env = "NOGML_MAX_COMPLAINT_RATE",
        default_value_t = nogml::deliverability::DEFAULT_MAX_COMPLAINT_RATE,
        global = true
    )]
    deliverability_max_complaint_rate: f64,

    /// Minimum rolling sample size before bounce/complaint rates trip a domain circuit breaker (default 20).
    #[arg(
        long = "deliverability-min-samples",
        env = "NOGML_DELIVERABILITY_MIN_SAMPLES",
        default_value_t = nogml::deliverability::DEFAULT_DELIVERABILITY_MIN_SAMPLES,
        global = true
    )]
    deliverability_min_samples: u64,

    /// Rolling window in seconds for bounce/complaint rate calculations (default 86400).
    #[arg(
        long = "deliverability-window-secs",
        env = "NOGML_DELIVERABILITY_WINDOW_SECS",
        default_value_t = nogml::deliverability::DEFAULT_DELIVERABILITY_WINDOW_SECS,
        global = true
    )]
    deliverability_window_secs: u64,

    /// Outbound secret/PII DLP scanner action (`off`, `hold`, or `deny`).
    #[arg(long, env = "NOGML_DLP_ACTION", default_value = "off", global = true)]
    dlp_action: DlpAction,

    /// Time-to-live in seconds for pending outbound approval requests (default 86400s).
    #[arg(
        long,
        env = "NOGML_APPROVAL_TTL_SECS",
        default_value_t = 86_400,
        global = true
    )]
    approval_ttl_secs: u64,

    /// Optional webhook URL notified via HTTP POST (Slack/generic JSON) when a send enters approval.
    #[arg(long, env = "NOGML_APPROVAL_WEBHOOK_URL", global = true)]
    approval_webhook_url: Option<String>,

    /// Comma-separated recipient allowlist (exact email, `@domain`, or `*.domain`).
    #[arg(
        long,
        env = "NOGML_ALLOWED_RECIPIENTS",
        value_delimiter = ',',
        global = true
    )]
    allowed_recipients: Vec<String>,

    /// Maximum recipients permitted per outbound send.
    #[arg(
        long,
        env = "NOGML_MAX_SEND_RECIPIENTS",
        default_value_t = 50,
        global = true
    )]
    max_send_recipients: usize,

    /// Default body character limit for AI/MCP reads.
    #[arg(
        long,
        env = "NOGML_DEFAULT_MAX_BODY_CHARS",
        default_value_t = 4000,
        global = true
    )]
    default_max_body_chars: usize,

    /// Strip control/BiDi override chars and tag external content on AI/MCP reads.
    #[arg(
        long,
        env = "NOGML_UNTRUSTED_CONTENT_GUARD",
        default_value_t = true,
        global = true
    )]
    untrusted_content_guard: bool,

    /// Comma-separated host allowlist for outbound inbox rule webhooks (exact host or `*.domain`).
    #[arg(
        long,
        env = "NOGML_WEBHOOK_ALLOWED_HOSTS",
        value_delimiter = ',',
        global = true
    )]
    webhook_allowed_hosts: Vec<String>,

    /// Allow private/loopback/HTTP webhook and download endpoints (dev/test only; NEVER enable in production).
    #[arg(
        long,
        env = "NOGML_ALLOW_PRIVATE_ENDPOINTS",
        default_value_t = false,
        global = true
    )]
    allow_private_endpoints: bool,

    /// Allow unsigned `/webhooks/resend` and `/webhooks/ses` requests when webhook secrets are unset (dev/test only).
    #[arg(
        long,
        env = "NOGML_ALLOW_INSECURE_WEBHOOKS",
        default_value_t = false,
        global = true
    )]
    allow_insecure_webhooks: bool,

    // --- Upstream Gmail Sync ---
    #[arg(long, env = "NOGML_SYNC_MODE", default_value = "api", global = true)]
    sync_mode: SyncMode,

    #[arg(long, env = "GMAIL_CLIENT_ID", global = true)]
    gmail_client_id: Option<String>,

    #[arg(long, env = "GMAIL_CLIENT_SECRET", global = true)]
    gmail_client_secret: Option<String>,

    #[arg(long, env = "GMAIL_REFRESH_TOKEN", global = true)]
    gmail_refresh_token: Option<String>,

    #[arg(long, env = "GMAIL_ACCESS_TOKEN", global = true)]
    gmail_access_token: Option<String>,

    #[arg(long, env = "GMAIL_USER_ID", default_value = "me", global = true)]
    gmail_user_id: String,

    #[arg(
        long,
        env = "GMAIL_API_BASE_URL",
        default_value = "https://gmail.googleapis.com",
        global = true
    )]
    gmail_api_base_url: String,

    #[arg(
        long,
        env = "GMAIL_OAUTH_TOKEN_URL",
        default_value = "https://oauth2.googleapis.com/token",
        global = true
    )]
    gmail_oauth_token_url: String,

    #[arg(
        long,
        env = "GMAIL_IMAP_HOST",
        default_value = "imap.gmail.com",
        global = true
    )]
    gmail_imap_host: String,

    #[arg(long, env = "GMAIL_IMAP_PORT", default_value_t = 993, global = true)]
    gmail_imap_port: u16,

    #[arg(long, env = "GMAIL_IMAP_TLS", default_value_t = true, global = true)]
    gmail_imap_tls: bool,

    #[arg(long, env = "GMAIL_IMAP_USER", global = true)]
    gmail_imap_user: Option<String>,

    #[arg(long, env = "GMAIL_IMAP_PASSWORD", global = true)]
    gmail_imap_password: Option<String>,

    #[arg(
        long,
        env = "GMAIL_IMAP_MAILBOX",
        default_value = "[Gmail]/All Mail",
        global = true
    )]
    gmail_imap_mailbox: String,

    /// Comma-separated IMAP folders to sync with independent per-folder checkpoints
    /// (for non-Gmail IMAP servers lacking `[Gmail]/All Mail`).
    #[arg(
        long,
        env = "NOGML_GMAIL_IMAP_FOLDERS",
        value_delimiter = ',',
        global = true
    )]
    gmail_imap_folders: Vec<String>,

    /// Target archive folder for non-Gmail IMAP servers without `X-GM-EXT-1`.
    #[arg(
        long,
        env = "NOGML_GMAIL_IMAP_ARCHIVE_MAILBOX",
        default_value = "Archive",
        global = true
    )]
    gmail_imap_archive_mailbox: String,

    /// Maintain a dedicated read-only IMAP IDLE connection to trigger immediate incremental sync.
    #[arg(
        long,
        env = "NOGML_GMAIL_IMAP_IDLE",
        default_value_t = false,
        global = true
    )]
    gmail_imap_idle: bool,

    #[arg(long, env = "NOGML_SYNC_QUERY", global = true)]
    sync_query: Option<String>,

    #[arg(long, env = "NOGML_SYNC_MAX_MESSAGES", global = true)]
    sync_max_messages: Option<usize>,

    /// Push local label, flag, trash, and delete changes back to the upstream account.
    #[arg(
        long,
        env = "NOGML_SYNC_BIDIRECTIONAL",
        default_value_t = false,
        global = true
    )]
    sync_bidirectional: bool,

    // --- Inbound filter pipeline ---
    /// Enable `AuthResultsFilter` to parse `Authentication-Results` headers.
    #[arg(
        long,
        env = "NOGML_FILTER_AUTH_RESULTS",
        default_value_t = false,
        global = true
    )]
    filter_auth_results: bool,

    /// Action on DMARC failure (`spam`, `reject`, `tag`, `allow`).
    #[arg(
        long,
        env = "NOGML_FILTER_DMARC_FAIL_ACTION",
        default_value = "spam",
        global = true
    )]
    filter_dmarc_fail_action: AuthFailAction,

    /// Action on SPF failure (`spam`, `reject`, `tag`, `allow`).
    #[arg(
        long,
        env = "NOGML_FILTER_SPF_FAIL_ACTION",
        default_value = "tag",
        global = true
    )]
    filter_spf_fail_action: AuthFailAction,

    /// Action on DKIM failure (`spam`, `reject`, `tag`, `allow`).
    #[arg(
        long,
        env = "NOGML_FILTER_DKIM_FAIL_ACTION",
        default_value = "tag",
        global = true
    )]
    filter_dkim_fail_action: AuthFailAction,

    /// Rspamd base URL (`{url}/checkv2`). Enables `RspamdFilter` when set.
    #[arg(long, env = "NOGML_RSPAMD_URL", global = true)]
    rspamd_url: Option<String>,

    /// Optional Rspamd `Password` header value.
    #[arg(long, env = "NOGML_RSPAMD_PASSWORD", global = true)]
    rspamd_password: Option<String>,

    /// Timeout for Rspamd `/checkv2` calls in milliseconds.
    #[arg(
        long,
        env = "NOGML_RSPAMD_TIMEOUT_MS",
        default_value_t = 5_000,
        global = true
    )]
    rspamd_timeout_ms: u64,

    /// Optional Rspamd spam score threshold override.
    #[arg(long, env = "NOGML_RSPAMD_SPAM_THRESHOLD", global = true)]
    rspamd_spam_threshold: Option<f32>,

    /// Action on Rspamd `reject` / `soft reject` (`reject` or `spam`).
    #[arg(
        long,
        env = "NOGML_RSPAMD_REJECT_ACTION",
        default_value = "reject",
        global = true
    )]
    rspamd_reject_action: RspamdRejectAction,

    /// Reject inbound mail when Rspamd is unreachable or times out (default false, fail-open).
    #[arg(
        long,
        env = "NOGML_RSPAMD_FAIL_CLOSED",
        default_value_t = false,
        global = true
    )]
    rspamd_fail_closed: bool,

    /// OpenAI-compatible chat completions base URL (`{url}/chat/completions`).
    #[arg(long, env = "NOGML_LLM_TRIAGE_BASE_URL", global = true)]
    llm_triage_base_url: Option<String>,

    /// Bearer API key for the LLM triage endpoint.
    #[arg(long, env = "NOGML_LLM_TRIAGE_API_KEY", global = true)]
    llm_triage_api_key: Option<String>,

    /// Model name passed to `/chat/completions` for inbound triage.
    #[arg(
        long,
        env = "NOGML_LLM_TRIAGE_MODEL",
        default_value = "gpt-4o-mini",
        global = true
    )]
    llm_triage_model: String,

    /// Timeout for LLM triage calls in milliseconds.
    #[arg(
        long,
        env = "NOGML_LLM_TRIAGE_TIMEOUT_MS",
        default_value_t = 10_000,
        global = true
    )]
    llm_triage_timeout_ms: u64,

    /// Maximum plain-text body characters sent to the LLM triage prompt.
    #[arg(
        long,
        env = "NOGML_LLM_TRIAGE_MAX_BODY_CHARS",
        default_value_t = 2_000,
        global = true
    )]
    llm_triage_max_body_chars: usize,

    // --- Encryption at rest ---
    /// Master AES-256-GCM encryption key (`<kid>:<base64_or_hex_key>` or bare 32-byte key).
    #[arg(long, env = "NOGML_ENCRYPTION_KEY", global = true)]
    encryption_key: Option<String>,

    /// Comma-separated previous AES-256-GCM encryption keys (`<kid>:<key>`) for zero-downtime key rotation.
    #[arg(
        long,
        env = "NOGML_ENCRYPTION_PREVIOUS_KEYS",
        value_delimiter = ',',
        global = true
    )]
    encryption_previous_keys: Vec<String>,

    // --- Pluggable search & embeddings ---
    /// Search index backend (`store` [default] or `hybrid`).
    #[arg(
        long,
        env = "NOGML_SEARCH_BACKEND",
        default_value = "store",
        global = true
    )]
    search_backend: SearchBackend,

    /// OpenAI-compatible embeddings base URL (`{url}/embeddings`, e.g. OpenAI or Ollama `/v1`).
    #[arg(long, env = "NOGML_EMBEDDING_BASE_URL", global = true)]
    embedding_base_url: Option<String>,

    /// Optional Bearer API key for the embeddings endpoint.
    #[arg(long, env = "NOGML_EMBEDDING_API_KEY", global = true)]
    embedding_api_key: Option<String>,

    /// Embedding model name sent to `/embeddings`.
    #[arg(
        long,
        env = "NOGML_EMBEDDING_MODEL",
        default_value = "text-embedding-3-small",
        global = true
    )]
    embedding_model: String,

    /// HTTP timeout for embedding requests in seconds.
    #[arg(
        long,
        env = "NOGML_EMBEDDING_TIMEOUT_SECS",
        default_value_t = 15,
        global = true
    )]
    embedding_timeout_secs: u64,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the HTTP server (Gmail API, AI `/v1`, MCP `/mcp`, Resend webhooks), optional IMAP server, and optional background Gmail sync.
    Serve(ServeArgs),

    /// Run the built-in MCP JSON-RPC 2.0 server over stdio (logs strictly to stderr).
    Mcp,

    /// Synchronize upstream email into the local store.
    Sync {
        #[command(subcommand)]
        provider: SyncCommand,
    },

    /// Storage maintenance operations (e.g. migrating blobs across backends).
    Storage {
        #[command(subcommand)]
        action: StorageCommand,
    },

    /// Search index maintenance operations (e.g. backfilling embeddings).
    Search {
        #[command(subcommand)]
        action: SearchCommand,
    },

    /// Configuration file management (`init` starter config, `check` validation and redacted output).
    Config {
        #[command(subcommand)]
        action: ConfigCommand,
    },

    /// Encryption at rest key management (`generate-key`, `rotate-key`).
    Crypto {
        #[command(subcommand)]
        action: CryptoCommand,
    },

    /// Interactive Gmail OAuth2 consent and least-privilege scoped token setup (`gmail`, `mint-token`).
    Auth {
        #[command(subcommand)]
        action: AuthCommand,
    },

    /// Print runtime JSON schemas for CLI commands and `/v1/` endpoints (or OpenAPI 3.1 with `--openapi`).
    Schema {
        /// Optional command or endpoint name to inspect.
        #[arg(long)]
        command: Option<String>,

        /// Print the OpenAPI 3.1.0 JSON specification instead of the CLI schema manifest.
        #[arg(long, default_value_t = false)]
        openapi: bool,
    },

    /// Run live operational diagnostics (config, secrets, storage, blobs, IMAP TLS, transport, security posture).
    Doctor(Box<ServeArgs>),

    /// Generate shell completions for `bash`, `zsh`, `fish`, `elvish`, or `powershell`.
    Completions {
        /// Target shell (`bash`, `zsh`, `fish`, `elvish`, or `powershell`).
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Manage BYOD custom sending and receiving domains (`add`, `list`, `get`, `verify`, `delete`).
    Domains {
        #[command(subcommand)]
        action: DomainCommand,
    },

    /// Mail operations (auto-JSON when piped or `--json` is passed).
    Mail {
        /// Target a running `nogml` server instead of opening the local store directly.
        #[arg(long, env = "NOGML_URL")]
        url: Option<String>,

        /// Force JSON output.
        #[arg(long)]
        json: bool,

        /// Emit newline-delimited JSON for list/stream commands.
        #[arg(long)]
        ndjson: bool,

        /// Optional field projection mask (e.g. `id,subject,messages.text`).
        #[arg(long)]
        fields: Option<String>,

        #[command(subcommand)]
        action: MailAction,
    },
}

#[derive(Debug, Subcommand)]
enum DomainCommand {
    /// Register a custom domain and print required DNS records.
    Add {
        /// Domain name (e.g. `example.com`).
        domain: String,
        /// Provider (`ses`, `resend`, or `manual`; defaults to active transport).
        #[arg(long)]
        provider: Option<String>,
        /// Owner mailbox email address (defaults to configured `user_email`).
        #[arg(long)]
        mailbox: Option<String>,
        /// Optional catch-all mailbox receiving unmatched inbound mail once verified.
        #[arg(long)]
        catch_all: Option<String>,
    },
    /// List registered custom domains.
    List {
        /// Optional owner mailbox filter.
        #[arg(long)]
        mailbox: Option<String>,
    },
    /// Inspect status and DNS records for a custom domain.
    Get {
        /// Domain name.
        domain: String,
    },
    /// Trigger or refresh live verification status against the domain's provider.
    Verify {
        /// Domain name.
        domain: String,
    },
    /// Remove a custom domain from its upstream provider and local store.
    Delete {
        /// Domain name.
        domain: String,
    },
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// HTTP listen address.
    #[arg(long, env = "NOGML_BIND", default_value = "127.0.0.1:8080")]
    bind: SocketAddr,

    /// Max HTTP request body size in bytes (default 40 MiB).
    #[arg(long, env = "NOGML_MAX_BODY_BYTES", default_value_t = 40 * 1024 * 1024)]
    max_body_bytes: usize,

    /// Comma-separated allowed CORS origins (empty = allow any origin).
    #[arg(long, env = "NOGML_CORS_ORIGINS", value_delimiter = ',')]
    cors_allow_origins: Vec<String>,

    /// Optional embedded IMAP4rev1 plain TCP (with STARTTLS if certs provided) listen address.
    #[arg(long, env = "NOGML_IMAP_BIND")]
    imap_bind: Option<SocketAddr>,

    /// Optional embedded IMAP4rev1 implicit TLS listen address.
    #[arg(long, env = "NOGML_IMAP_TLS_BIND")]
    imap_tls_bind: Option<SocketAddr>,

    /// PEM certificate chain path for IMAP TLS / STARTTLS.
    #[arg(long, env = "NOGML_IMAP_TLS_CERT")]
    imap_tls_cert: Option<PathBuf>,

    /// PEM private key path for IMAP TLS / STARTTLS.
    #[arg(long, env = "NOGML_IMAP_TLS_KEY")]
    imap_tls_key: Option<PathBuf>,

    /// Optional IMAP username override (defaults to `--user-email`).
    #[arg(long, env = "NOGML_IMAP_USERNAME")]
    imap_username: Option<String>,

    /// Optional IMAP password override (defaults to first auth token if set).
    #[arg(long, env = "NOGML_IMAP_PASSWORD")]
    imap_password: Option<String>,

    /// Background upstream Gmail sync interval in seconds (`0` disables background sync).
    #[arg(long, env = "NOGML_SYNC_INTERVAL_SECS", default_value_t = 0)]
    sync_interval_secs: u64,

    /// Optional push webhook URL triggered on Gmail `/watch` notifications.
    #[arg(long, env = "NOGML_WATCH_WEBHOOK_URL")]
    watch_webhook_url: Option<String>,
}

#[derive(Debug, Subcommand)]
enum SyncCommand {
    /// Sync messages & labels from upstream Gmail (REST API or IMAP).
    Gmail {
        /// Sync transport mode (`api` or `imap`).
        #[arg(long)]
        mode: Option<SyncMode>,

        /// Force a full backfill even when a checkpoint exists.
        #[arg(long, default_value_t = false)]
        full: bool,

        /// Maximum messages to fetch in this pass.
        #[arg(long)]
        max_messages: Option<usize>,

        /// Optional Gmail search query filter.
        #[arg(long)]
        query: Option<String>,

        /// Target local mailbox email address (defaults to `--user-email`).
        #[arg(long)]
        mailbox: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum StorageCommand {
    /// Copy existing raw `.eml` messages and attachments into a target blob backend.
    MigrateBlobs {
        /// Target blob backend (`inline`, `fs`, `memory`, or `s3`).
        #[arg(long)]
        to: BlobBackend,
    },
}

#[derive(Debug, Subcommand)]
enum SearchCommand {
    /// Re-index all stored messages into the active SearchIndex backend.
    Reindex,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Write an annotated starter `nogml.toml` and generate a cryptographically random bearer token.
    Init {
        /// Output path for the generated `nogml.toml` file.
        #[arg(short, long, default_value = "nogml.toml")]
        output: PathBuf,

        /// Write the generated bearer token to a 0600 secret file and reference it with `file://`.
        #[arg(long)]
        token_file: Option<PathBuf>,

        /// Overwrite an existing config or token file.
        #[arg(long, default_value_t = false)]
        force: bool,
    },

    /// Validate layered config, secret references, and IMAP TLS files, printing redacted JSON.
    Check(Box<ServeArgs>),
}

#[derive(Debug, Subcommand)]
enum CryptoCommand {
    /// Generate a cryptographically random 32-byte AES-256-GCM key (`<kid>:<base64>`).
    GenerateKey {
        /// Key identifier prefix stored in `enc:v1:<kid>:...` envelopes.
        #[arg(long, default_value = DEFAULT_KEY_ID)]
        kid: String,

        /// Write the generated `<kid>:<key>` to a mode 0600 file and omit raw key material from stdout.
        #[arg(long)]
        output_file: Option<PathBuf>,

        /// Overwrite an existing `--output-file`.
        #[arg(long, default_value_t = false)]
        force: bool,
    },

    /// Re-encrypt stored `sendAs` SMTP passwords and inbox rule webhook secrets under the active primary key.
    RotateKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
enum MintTokenFormat {
    #[default]
    Toml,
    Json,
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    /// Generate a high-entropy least-privilege scoped token (`[[auth.scoped_tokens]]` TOML or `NOGML_SCOPED_TOKENS` JSON).
    ///
    /// Also honors global flags `--user-email`, `--draft-only`, `--allowed-recipients`,
    /// and `--max-send-recipients` when passed on the command line.
    MintToken {
        /// Target mailbox email address (defaults to `--user-email` or `nogml.toml` `auth.user_email`).
        #[arg(long)]
        mailbox: Option<String>,

        /// Comma-separated scopes (`read`, `write`, `send`, `admin`).
        #[arg(
            long,
            value_delimiter = ',',
            default_value = "read,write",
            value_parser = parse_auth_scope
        )]
        scopes: Vec<AuthScope>,

        /// Write the raw token to a mode 0600 secret file and emit a `file://` reference instead of plaintext.
        #[arg(long)]
        output_file: Option<PathBuf>,

        /// Overwrite an existing `--output-file`.
        #[arg(long, default_value_t = false)]
        force: bool,

        /// Output format (`toml` or `json`).
        #[arg(long, value_enum, default_value_t = MintTokenFormat::Toml)]
        format: MintTokenFormat,

        /// Emit JSON array output compatible with `NOGML_SCOPED_TOKENS` (shorthand for `--format json`).
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Run a loopback OAuth2 PKCE consent flow against Google and save the refresh token with mode 0600.
    Gmail {
        /// Google OAuth2 client ID (defaults to `GMAIL_CLIENT_ID` or `nogml.toml` `sync.gmail_client_id`).
        #[arg(long, env = "GMAIL_CLIENT_ID")]
        client_id: Option<String>,

        /// Optional Google OAuth2 client secret (defaults to `GMAIL_CLIENT_SECRET`, `GMAIL_CLIENT_SECRET_FILE`, or `nogml.toml`).
        #[arg(long, env = "GMAIL_CLIENT_SECRET")]
        client_secret: Option<String>,

        /// OAuth2 authorization endpoint URL.
        #[arg(long, default_value = DEFAULT_GMAIL_AUTH_URL)]
        auth_url: String,

        /// OAuth2 token exchange endpoint URL (overridable for automated tests).
        #[arg(long, default_value = DEFAULT_GMAIL_TOKEN_URL)]
        token_url: String,

        /// Comma- or space-separated Gmail OAuth2 scopes.
        #[arg(long, default_value = DEFAULT_GMAIL_SCOPE)]
        scopes: String,

        /// Loopback listen address for the one-shot `/callback` HTTP server.
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: SocketAddr,

        /// Path to write the obtained `refresh_token` (mode 0600 on Unix).
        #[arg(long)]
        output_file: PathBuf,

        /// Overwrite an existing `--output-file`.
        #[arg(long, default_value_t = false)]
        force: bool,

        /// Print the authorization URL to stderr without launching a local browser.
        #[arg(long, default_value_t = false)]
        no_browser: bool,

        /// Maximum seconds to wait for the OAuth2 callback before timing out.
        #[arg(long, default_value_t = DEFAULT_OAUTH_TIMEOUT_SECS)]
        timeout_secs: u64,
    },
}

#[derive(Debug, Subcommand)]
enum MailAction {
    /// Search messages using FTS5 or hybrid semantic search and structured filters.
    Search {
        #[arg(long)]
        q: Option<String>,
        #[arg(long, value_delimiter = ',')]
        labels: Vec<String>,
        #[arg(long)]
        unread: Option<bool>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = false)]
        include_body: bool,
        #[arg(long, default_value_t = 1000)]
        max_chars: usize,
    },
    /// List conversation threads.
    Threads {
        #[arg(long)]
        q: Option<String>,
        #[arg(long)]
        label: Option<String>,
        #[arg(long, default_value_t = false)]
        unread_only: bool,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Read a message or thread by ID.
    Read {
        /// Message or thread ID.
        id: String,
        /// Interpret `id` as a thread ID instead of a message ID.
        #[arg(long, default_value_t = false)]
        thread: bool,
        #[arg(long, default_value_t = 4000)]
        max_chars: usize,
        #[arg(long, default_value_t = false)]
        strip_quotes: bool,
        #[arg(long, default_value_t = false)]
        include_html: bool,
    },
    /// Send an email (or preview with `--dry-run`).
    Send {
        /// Raw JSON payload (`{...}` or `@-` to read from stdin).
        #[arg(long)]
        payload: Option<String>,
        #[arg(long, value_delimiter = ',')]
        to: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        cc: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        bcc: Vec<String>,
        #[arg(long)]
        subject: Option<String>,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        html: Option<String>,
        #[arg(long)]
        reply_to: Option<String>,
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Optional idempotency key to deduplicate retries for 24h.
        #[arg(long)]
        idempotency_key: Option<String>,
        /// Optional future RFC 3339 timestamp to schedule outbound delivery.
        #[arg(long)]
        send_at: Option<chrono::DateTime<chrono::Utc>>,
    },
    /// Create a draft email.
    Draft {
        #[arg(long)]
        payload: Option<String>,
        #[arg(long, value_delimiter = ',')]
        to: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        cc: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        bcc: Vec<String>,
        #[arg(long)]
        subject: Option<String>,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        html: Option<String>,
        #[arg(long)]
        reply_to: Option<String>,
        /// Optional idempotency key to deduplicate retries for 24h.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Triage a thread (archive, mark read, star, trash, or modify labels).
    Triage {
        thread_id: String,
        #[arg(long)]
        archive: Option<bool>,
        #[arg(long)]
        mark_read: Option<bool>,
        #[arg(long)]
        mark_unread: Option<bool>,
        #[arg(long)]
        star: Option<bool>,
        #[arg(long)]
        trash: Option<bool>,
        #[arg(long, value_delimiter = ',')]
        add_labels: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        remove_labels: Vec<String>,
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Batch triage multiple threads via query, thread IDs, or raw JSON payload (supports `--dry-run`).
    BatchTriage {
        /// Raw JSON payload (`{...}` or `@-` to read from stdin).
        #[arg(long)]
        payload: Option<String>,
        /// Optional Gmail `q=` search query selecting threads.
        #[arg(long)]
        query: Option<String>,
        /// Comma-separated thread IDs to apply the shared action to.
        #[arg(long, value_delimiter = ',')]
        thread_ids: Vec<String>,
        /// Include SPAM and TRASH threads when resolving `--query`.
        #[arg(long, default_value_t = false)]
        include_spam_trash: bool,
        #[arg(long)]
        archive: Option<bool>,
        #[arg(long)]
        mark_read: Option<bool>,
        #[arg(long)]
        mark_unread: Option<bool>,
        #[arg(long)]
        star: Option<bool>,
        #[arg(long)]
        trash: Option<bool>,
        #[arg(long, value_delimiter = ',')]
        add_labels: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        remove_labels: Vec<String>,
        /// Safety ceiling on unique target threads (default 100, max 500).
        #[arg(long)]
        max_threads: Option<usize>,
        /// Preview per-thread diffs with zero store writes, events, or audit logs.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// List available labels.
    Labels,
    /// Daily briefing: unread VIP threads, needs-reply threads, follow-ups due, pending approvals, and due snoozes.
    Briefing {
        /// Only include unread VIP threads active at or after this RFC 3339 timestamp.
        #[arg(long)]
        since: Option<String>,
        /// Days without a reply before a sent thread counts as a follow-up (default 3).
        #[arg(long)]
        followup_days: Option<u32>,
        /// Maximum items per section (default 20, max 100).
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Manage pending human-in-the-loop outbound approvals.
    Approvals {
        #[command(subcommand)]
        action: ApprovalsAction,
    },
    /// Query the immutable agent and API audit log (newest-first).
    Audit {
        /// Filter by action (`read`, `search`, `send`, `draft`, `triage`, `batch_triage`, `approve`, `reject`, `unsubscribe`, `modify`, `delete`).
        #[arg(long)]
        action: Option<String>,
        /// Filter by actor identity.
        #[arg(long)]
        actor: Option<String>,
        /// Filter entries at or after this Unix epoch ms or RFC 3339 timestamp.
        #[arg(long)]
        since: Option<String>,
        /// Maximum number of audit log entries to return.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Stream real-time mail events as NDJSON.
    Watch,
}

#[derive(Debug, Subcommand)]
enum ApprovalsAction {
    /// List outbound approval requests.
    List {
        /// Filter by status (`pending`, `approved`, `rejected`, `expired`, or `all`).
        #[arg(long, default_value = "pending")]
        status: String,
        /// Maximum number of approvals to return.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Fetch a single approval request by ID.
    Get {
        /// Approval ID.
        id: String,
    },
    /// Approve and dispatch a pending outbound email once.
    Approve {
        /// Approval ID.
        id: String,
        /// Optional reviewer name or email recorded on the decision.
        #[arg(long)]
        decided_by: Option<String>,
        /// Optional decision note.
        #[arg(long)]
        note: Option<String>,
    },
    /// Reject a pending outbound email without sending it.
    Reject {
        /// Approval ID.
        id: String,
        /// Optional reviewer name or email recorded on the decision.
        #[arg(long)]
        decided_by: Option<String>,
        /// Optional decision note.
        #[arg(long)]
        note: Option<String>,
    },
}

fn arg_origin(matches: &ArgMatches, id: &str) -> ValueOrigin {
    if matches.try_contains_id(id).unwrap_or(false) {
        match matches.value_source(id) {
            Some(ValueSource::CommandLine) => ValueOrigin::Cli,
            Some(ValueSource::EnvVariable) => ValueOrigin::DirectEnv,
            _ => ValueOrigin::Unset,
        }
    } else {
        ValueOrigin::Unset
    }
}

fn is_explicit(matches: &ArgMatches, id: &str) -> bool {
    arg_origin(matches, id) != ValueOrigin::Unset
}

struct LoadedConfig {
    config: Config,
    log_json: bool,
    config_file: Option<PathBuf>,
    resolution: SecretResolutionReport,
}

impl CommonConfigArgs {
    fn load_layered(
        self,
        serve: Option<ServeArgs>,
        root_matches: &ArgMatches,
        serve_matches: Option<&ArgMatches>,
        cli_log_json: bool,
    ) -> AppResult<LoadedConfig> {
        let mut cfg = Config::default();
        let config_file = self.config.clone();
        let mut base_dir: Option<PathBuf> = None;
        let mut user_email_set = false;
        let mut toml_log_json: Option<bool> = None;

        if let Some(ref path) = config_file {
            let toml_cfg = TomlConfig::from_file(path)?;
            let meta = toml_cfg.apply_to(&mut cfg);
            user_email_set = meta.user_email_set;
            toml_log_json = meta.log_json;
            base_dir = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map(Path::to_path_buf);
        }

        // Overlay CLI flags and direct environment variables (strictly beating nogml.toml and defaults).
        if is_explicit(root_matches, "storage") {
            cfg.storage = self.storage;
        }
        if is_explicit(root_matches, "db_path") {
            cfg.db_path = self.db_path;
        }
        if is_explicit(root_matches, "database_url") {
            cfg.database_url = self.database_url;
        }
        if is_explicit(root_matches, "blob_backend") {
            cfg.blob_backend = self.blob_backend;
        }
        if is_explicit(root_matches, "blob_dir") {
            cfg.blob_dir = self.blob_dir;
        }
        if is_explicit(root_matches, "blob_s3_bucket") {
            cfg.blob_s3_bucket = self.blob_s3_bucket;
        }
        if is_explicit(root_matches, "blob_s3_region") {
            cfg.blob_s3_region = self.blob_s3_region;
        }
        if is_explicit(root_matches, "blob_s3_endpoint") {
            cfg.blob_s3_endpoint = self.blob_s3_endpoint;
        }
        if is_explicit(root_matches, "blob_s3_prefix") {
            cfg.blob_s3_prefix = self.blob_s3_prefix;
        }
        if is_explicit(root_matches, "blob_s3_access_key_id") {
            cfg.blob_s3_access_key_id = self.blob_s3_access_key_id;
        }
        if is_explicit(root_matches, "blob_s3_secret_access_key") {
            cfg.blob_s3_secret_access_key = self.blob_s3_secret_access_key;
        }
        if is_explicit(root_matches, "blob_s3_session_token") {
            cfg.blob_s3_session_token = self.blob_s3_session_token;
        }
        if is_explicit(root_matches, "blob_s3_force_path_style") {
            cfg.blob_s3_force_path_style = self.blob_s3_force_path_style;
        }
        if is_explicit(root_matches, "user_email")
            && let Some(email) = self.user_email
            && !email.trim().is_empty()
        {
            cfg.user_email = email;
            user_email_set = true;
        }
        if is_explicit(root_matches, "mailboxes") {
            cfg.mailboxes = self.mailboxes;
        }
        if is_explicit(root_matches, "mailbox_aliases") {
            cfg.mailbox_aliases = match self.mailbox_aliases.as_deref() {
                Some(raw) => nogml::config::parse_mailbox_aliases(raw)?,
                None => Default::default(),
            };
        }
        if is_explicit(root_matches, "default_domain") {
            cfg.default_domain = self.default_domain;
        }
        if is_explicit(root_matches, "transport") {
            cfg.transport = self.transport;
        }
        if is_explicit(root_matches, "resend_api_key") {
            cfg.resend_api_key = self.resend_api_key;
        }
        if is_explicit(root_matches, "resend_base_url") {
            cfg.resend_base_url = self.resend_base_url;
        }
        if is_explicit(root_matches, "resend_webhook_secret") {
            cfg.resend_webhook_secret = self.resend_webhook_secret;
        }
        if is_explicit(root_matches, "ses_region") {
            cfg.ses_region = self.ses_region;
        }
        if is_explicit(root_matches, "ses_endpoint") {
            cfg.ses_endpoint = self.ses_endpoint;
        }
        if is_explicit(root_matches, "ses_access_key_id") {
            cfg.ses_access_key_id = self.ses_access_key_id;
        }
        if is_explicit(root_matches, "ses_secret_access_key") {
            cfg.ses_secret_access_key = self.ses_secret_access_key;
        }
        if is_explicit(root_matches, "ses_session_token") {
            cfg.ses_session_token = self.ses_session_token;
        }
        if is_explicit(root_matches, "ses_s3_endpoint") {
            cfg.ses_s3_endpoint = self.ses_s3_endpoint;
        }
        if is_explicit(root_matches, "ses_webhook_secret") {
            cfg.ses_webhook_secret = self.ses_webhook_secret;
        }
        if is_explicit(root_matches, "ses_allowed_topic_arns") {
            cfg.ses_allowed_topic_arns = self.ses_allowed_topic_arns;
        }
        if is_explicit(root_matches, "ses_allowed_s3_buckets") {
            cfg.ses_allowed_s3_buckets = self.ses_allowed_s3_buckets;
        }
        if is_explicit(root_matches, "smtp_host") {
            cfg.smtp_host = self.smtp_host;
        }
        if is_explicit(root_matches, "smtp_port") {
            cfg.smtp_port = self.smtp_port;
        }
        if is_explicit(root_matches, "smtp_tls_mode") {
            cfg.smtp_tls_mode = self.smtp_tls_mode;
        }
        if is_explicit(root_matches, "smtp_username") {
            cfg.smtp_username = self.smtp_username;
        }
        if is_explicit(root_matches, "smtp_password") {
            cfg.smtp_password = self.smtp_password;
        }
        if is_explicit(root_matches, "smtp_oauth_token") {
            cfg.smtp_oauth_token = self.smtp_oauth_token;
        }
        if is_explicit(root_matches, "smtp_helo_domain") {
            cfg.smtp_helo_domain = self.smtp_helo_domain;
        }
        if is_explicit(root_matches, "auth_tokens") {
            cfg.auth_tokens = self.auth_tokens;
        }
        if is_explicit(root_matches, "scoped_tokens") {
            cfg.scoped_tokens = self.scoped_tokens.map(|l| l.0).unwrap_or_default();
        }
        if is_explicit(root_matches, "oauth2_client_id") {
            cfg.oauth2_client_id = self.oauth2_client_id;
        }
        if is_explicit(root_matches, "oauth2_client_secret") {
            cfg.oauth2_client_secret = self.oauth2_client_secret;
        }
        if is_explicit(root_matches, "oauth2_signing_secret") {
            cfg.oauth2_signing_secret = self.oauth2_signing_secret;
        }
        if is_explicit(root_matches, "oauth2_redirect_uris") {
            cfg.oauth2_redirect_uris = self
                .oauth2_redirect_uris
                .into_iter()
                .map(|u| u.trim().to_string())
                .filter(|u| !u.is_empty())
                .collect();
        }
        if is_explicit(root_matches, "draft_only") {
            cfg.draft_only = self.draft_only;
        }
        if is_explicit(root_matches, "draft_only_action") {
            cfg.draft_only_action = self.draft_only_action;
        }
        if is_explicit(root_matches, "require_approval") {
            cfg.require_approval = self.require_approval;
        }
        if is_explicit(root_matches, "first_contact_approval") {
            cfg.first_contact_approval = self.first_contact_approval;
        }
        if is_explicit(root_matches, "require_verified_from_domain") {
            cfg.require_verified_from_domain = self.require_verified_from_domain;
        }
        if is_explicit(root_matches, "daily_send_limit_per_domain") {
            cfg.daily_send_limit_per_domain = self.daily_send_limit_per_domain;
        } else if let Ok(raw) = std::env::var("NOGML_DAILY_SEND_LIMIT")
            && !raw.trim().is_empty()
        {
            cfg.daily_send_limit_per_domain = raw.trim().parse::<u64>().map_err(|e| {
                AppError::Config(format!("Invalid NOGML_DAILY_SEND_LIMIT '{raw}': {e}"))
            })?;
        }
        if is_explicit(root_matches, "deliverability_max_bounce_rate") {
            cfg.deliverability_max_bounce_rate = self.deliverability_max_bounce_rate;
        }
        if is_explicit(root_matches, "deliverability_max_complaint_rate") {
            cfg.deliverability_max_complaint_rate = self.deliverability_max_complaint_rate;
        }
        if is_explicit(root_matches, "deliverability_min_samples") {
            cfg.deliverability_min_samples = self.deliverability_min_samples;
        }
        if is_explicit(root_matches, "deliverability_window_secs") {
            cfg.deliverability_window_secs = self.deliverability_window_secs;
        }
        if is_explicit(root_matches, "dlp_action") {
            cfg.dlp_action = self.dlp_action;
        }
        if is_explicit(root_matches, "approval_ttl_secs") {
            cfg.approval_ttl_secs = self.approval_ttl_secs;
        }
        if is_explicit(root_matches, "approval_webhook_url") {
            cfg.approval_webhook_url = self.approval_webhook_url;
        }
        if is_explicit(root_matches, "allowed_recipients") {
            cfg.allowed_recipients = self.allowed_recipients;
        }
        if is_explicit(root_matches, "max_send_recipients") {
            cfg.max_send_recipients = self.max_send_recipients;
        }
        if is_explicit(root_matches, "default_max_body_chars") {
            cfg.default_max_body_chars = self.default_max_body_chars;
        }
        if is_explicit(root_matches, "untrusted_content_guard") {
            cfg.untrusted_content_guard = self.untrusted_content_guard;
        }
        if is_explicit(root_matches, "webhook_allowed_hosts") {
            cfg.webhook_allowed_hosts = self.webhook_allowed_hosts;
        }
        if is_explicit(root_matches, "allow_private_endpoints") {
            cfg.allow_private_endpoints = self.allow_private_endpoints;
        }
        if is_explicit(root_matches, "allow_insecure_webhooks") {
            cfg.allow_insecure_webhooks = self.allow_insecure_webhooks;
        }
        if is_explicit(root_matches, "sync_mode") {
            cfg.sync_mode = self.sync_mode;
        }
        if is_explicit(root_matches, "gmail_client_id") {
            cfg.gmail_client_id = self.gmail_client_id;
        }
        if is_explicit(root_matches, "gmail_client_secret") {
            cfg.gmail_client_secret = self.gmail_client_secret;
        }
        if is_explicit(root_matches, "gmail_refresh_token") {
            cfg.gmail_refresh_token = self.gmail_refresh_token;
        }
        if is_explicit(root_matches, "gmail_access_token") {
            cfg.gmail_access_token = self.gmail_access_token;
        }
        if is_explicit(root_matches, "gmail_user_id") {
            cfg.gmail_user_id = self.gmail_user_id;
        }
        if is_explicit(root_matches, "gmail_api_base_url") {
            cfg.gmail_api_base_url = self.gmail_api_base_url;
        }
        if is_explicit(root_matches, "gmail_oauth_token_url") {
            cfg.gmail_oauth_token_url = self.gmail_oauth_token_url;
        }
        if is_explicit(root_matches, "gmail_imap_host") {
            cfg.gmail_imap_host = self.gmail_imap_host;
        }
        if is_explicit(root_matches, "gmail_imap_port") {
            cfg.gmail_imap_port = self.gmail_imap_port;
        }
        if is_explicit(root_matches, "gmail_imap_tls") {
            cfg.gmail_imap_tls = self.gmail_imap_tls;
        }
        if is_explicit(root_matches, "gmail_imap_user") {
            cfg.gmail_imap_user = self.gmail_imap_user;
        }
        if is_explicit(root_matches, "gmail_imap_password") {
            cfg.gmail_imap_password = self.gmail_imap_password;
        }
        if is_explicit(root_matches, "gmail_imap_mailbox") {
            cfg.gmail_imap_mailbox = self.gmail_imap_mailbox;
        }
        if is_explicit(root_matches, "gmail_imap_folders") {
            cfg.gmail_imap_folders = self
                .gmail_imap_folders
                .into_iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if is_explicit(root_matches, "gmail_imap_archive_mailbox") {
            cfg.gmail_imap_archive_mailbox = self.gmail_imap_archive_mailbox;
        }
        if is_explicit(root_matches, "gmail_imap_idle") {
            cfg.gmail_imap_idle = self.gmail_imap_idle;
        }
        if is_explicit(root_matches, "sync_query") {
            cfg.sync_query = self.sync_query;
        }
        if is_explicit(root_matches, "sync_max_messages") {
            cfg.sync_max_messages = self.sync_max_messages;
        }
        if is_explicit(root_matches, "sync_bidirectional") {
            cfg.sync_bidirectional = self.sync_bidirectional;
        }
        if is_explicit(root_matches, "filter_auth_results") {
            cfg.filter_auth_results = self.filter_auth_results;
        }
        if is_explicit(root_matches, "filter_dmarc_fail_action") {
            cfg.filter_dmarc_fail_action = self.filter_dmarc_fail_action;
        }
        if is_explicit(root_matches, "filter_spf_fail_action") {
            cfg.filter_spf_fail_action = self.filter_spf_fail_action;
        }
        if is_explicit(root_matches, "filter_dkim_fail_action") {
            cfg.filter_dkim_fail_action = self.filter_dkim_fail_action;
        }
        if is_explicit(root_matches, "rspamd_url") {
            cfg.rspamd_url = self.rspamd_url;
        }
        if is_explicit(root_matches, "rspamd_password") {
            cfg.rspamd_password = self.rspamd_password;
        }
        if is_explicit(root_matches, "rspamd_timeout_ms") {
            cfg.rspamd_timeout_ms = self.rspamd_timeout_ms;
        }
        if is_explicit(root_matches, "rspamd_spam_threshold") {
            cfg.rspamd_spam_threshold = self.rspamd_spam_threshold;
        }
        if is_explicit(root_matches, "rspamd_reject_action") {
            cfg.rspamd_reject_action = self.rspamd_reject_action;
        }
        if is_explicit(root_matches, "rspamd_fail_closed") {
            cfg.rspamd_fail_closed = self.rspamd_fail_closed;
        }
        if is_explicit(root_matches, "llm_triage_base_url") {
            cfg.llm_triage_base_url = self.llm_triage_base_url;
        }
        if is_explicit(root_matches, "llm_triage_api_key") {
            cfg.llm_triage_api_key = self.llm_triage_api_key;
        }
        if is_explicit(root_matches, "llm_triage_model") {
            cfg.llm_triage_model = self.llm_triage_model;
        }
        if is_explicit(root_matches, "llm_triage_timeout_ms") {
            cfg.llm_triage_timeout_ms = self.llm_triage_timeout_ms;
        }
        if is_explicit(root_matches, "llm_triage_max_body_chars") {
            cfg.llm_triage_max_body_chars = self.llm_triage_max_body_chars;
        }
        if is_explicit(root_matches, "encryption_key") {
            cfg.encryption_key = self.encryption_key;
        }
        if is_explicit(root_matches, "encryption_previous_keys") {
            cfg.encryption_previous_keys = self.encryption_previous_keys;
        }
        if is_explicit(root_matches, "search_backend") {
            cfg.search_backend = self.search_backend;
        }
        if is_explicit(root_matches, "embedding_base_url") {
            cfg.embedding_base_url = self.embedding_base_url;
        }
        if is_explicit(root_matches, "embedding_api_key") {
            cfg.embedding_api_key = self.embedding_api_key;
        }
        if is_explicit(root_matches, "embedding_model") {
            cfg.embedding_model = self.embedding_model;
        }
        if is_explicit(root_matches, "embedding_timeout_secs") {
            cfg.embedding_timeout_secs = self.embedding_timeout_secs;
        }

        if let (Some(s), Some(sm)) = (serve, serve_matches) {
            if is_explicit(sm, "bind") {
                cfg.bind = s.bind;
            }
            if is_explicit(sm, "max_body_bytes") {
                cfg.max_body_bytes = s.max_body_bytes;
            }
            if is_explicit(sm, "cors_allow_origins") {
                cfg.cors_allow_origins = s.cors_allow_origins;
            }
            if is_explicit(sm, "imap_bind") {
                cfg.imap_bind = s.imap_bind;
            }
            if is_explicit(sm, "imap_tls_bind") {
                cfg.imap_tls_bind = s.imap_tls_bind;
            }
            if is_explicit(sm, "imap_tls_cert") {
                cfg.imap_tls_cert = s.imap_tls_cert;
            }
            if is_explicit(sm, "imap_tls_key") {
                cfg.imap_tls_key = s.imap_tls_key;
            }
            if is_explicit(sm, "imap_username") {
                cfg.imap_username = s.imap_username;
            }
            if is_explicit(sm, "imap_password") {
                cfg.imap_password = s.imap_password;
            }
            if is_explicit(sm, "sync_interval_secs") {
                cfg.sync_interval_secs = s.sync_interval_secs;
            }
            if is_explicit(sm, "watch_webhook_url") {
                cfg.watch_webhook_url = s.watch_webhook_url;
            }
        }

        // Preserve SQLite sole-mailbox auto-detection when user_email was not explicitly set
        // by CLI, env, or nogml.toml.
        if !user_email_set
            && cfg.storage == StorageBackend::Sqlite
            && cfg.mailboxes.is_empty()
            && cfg.db_path.exists()
            && let Some(detected) = SqliteStore::list_mailbox_ids(&cfg.db_path)
                .ok()
                .and_then(|mut mbs| (mbs.len() == 1).then(|| mbs.remove(0)))
        {
            cfg.user_email = detected;
        }

        let origin_of = |id: &str| -> ValueOrigin {
            if let Some(sm) = serve_matches {
                let o = arg_origin(sm, id);
                if o != ValueOrigin::Unset {
                    return o;
                }
            }
            arg_origin(root_matches, id)
        };

        let resolution = cfg.apply_env_file_secrets_and_resolve(
            base_dir.as_deref(),
            &origin_of,
            &system_env_lookup,
        );

        let log_json = if is_explicit(root_matches, "log_json") {
            cli_log_json
        } else {
            toml_log_json.unwrap_or(false)
        };

        Ok(LoadedConfig {
            config: cfg,
            log_json,
            config_file,
            resolution,
        })
    }
}

fn finalize_runtime_config(loaded: LoadedConfig, force_stderr: bool) -> AppResult<Config> {
    init_tracing(loaded.log_json, force_stderr);
    for warning in &loaded.resolution.warnings {
        warn!("{warning}");
    }
    loaded.resolution.into_result()?;
    Ok(loaded.config)
}

fn init_tracing(json_logs: bool, force_stderr: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if force_stderr {
        if json_logs {
            let _ = fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .json()
                .try_init();
        } else {
            let _ = fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .try_init();
        }
    } else if json_logs {
        let _ = fmt().with_env_filter(filter).json().try_init();
    } else {
        let _ = fmt().with_env_filter(filter).try_init();
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

fn read_json_payload(raw: &str) -> AppResult<Value> {
    let text = if raw == "@-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| AppError::BadRequest(format!("Failed to read stdin payload: {e}")))?;
        buf
    } else {
        raw.to_string()
    };
    Ok(serde_json::from_str(&text)?)
}

fn emit_output(value: Value, fields: Option<&str>, json_mode: bool) -> AppResult<()> {
    let value = match fields {
        Some(mask) if !mask.trim().is_empty() => nogml::mime::apply_fields_mask(value, mask)?,
        _ => value,
    };
    let use_json = json_mode || !std::io::stdout().is_terminal();
    if use_json {
        println!("{}", serde_json::to_string(&value)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&value)?);
    }
    Ok(())
}

fn map_remote_http_error(status: reqwest::StatusCode, body: &str) -> AppError {
    if let Ok(parsed) = serde_json::from_str::<Value>(body)
        && let Some(err_obj) = parsed.get("error").and_then(Value::as_object)
    {
        let code = err_obj
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("upstream_error")
            .to_string();
        let message = err_obj
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or(body)
            .to_string();
        let hint = err_obj
            .get("hint")
            .and_then(Value::as_str)
            .map(str::to_string);
        let details = err_obj.get("details").cloned();

        return match status.as_u16() {
            400 => AppError::Validation { message, hint },
            401 => AppError::Unauthorized(message),
            403 => AppError::PolicyDenied {
                code,
                message,
                hint,
                details,
            },
            404 => AppError::NotFound(message),
            409 => AppError::Conflict(message),
            413 => AppError::PayloadTooLarge(message),
            429 => AppError::RateLimited(message),
            code_num => AppError::Upstream {
                status: code_num,
                message,
            },
        };
    }

    match status.as_u16() {
        400 => AppError::BadRequest(body.to_string()),
        401 => AppError::Unauthorized(body.to_string()),
        403 => AppError::Forbidden(body.to_string()),
        404 => AppError::NotFound(body.to_string()),
        409 => AppError::Conflict(body.to_string()),
        429 => AppError::RateLimited(body.to_string()),
        code_num => AppError::Upstream {
            status: code_num,
            message: body.to_string(),
        },
    }
}

async fn parse_remote_json(resp: reqwest::Response) -> AppResult<Value> {
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        return Err(map_remote_http_error(status, &body));
    }
    if body.trim().is_empty() {
        return Ok(json!({}));
    }
    Ok(serde_json::from_str(&body)?)
}

fn with_optional_bearer(
    req: reqwest::RequestBuilder,
    token: Option<&str>,
) -> reqwest::RequestBuilder {
    match token.map(str::trim).filter(|t| !t.is_empty()) {
        Some(t) => req.bearer_auth(t),
        None => req,
    }
}

async fn run_remote_mail(
    base_url: &str,
    bearer_token: Option<&str>,
    action: MailAction,
    fields: Option<&str>,
    json_flag: bool,
    ndjson: bool,
) -> AppResult<()> {
    let base = base_url.trim_end_matches('/');
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| AppError::Internal(format!("Failed to build HTTP client: {e}")))?;

    match action {
        MailAction::Search {
            q,
            labels,
            unread,
            limit,
            include_body,
            max_chars,
        } => {
            let mut params: Vec<(String, String)> = vec![
                ("limit".to_string(), limit.to_string()),
                ("include_body".to_string(), include_body.to_string()),
                ("max_body_chars".to_string(), max_chars.to_string()),
            ];
            if let Some(q) = q {
                params.push(("q".to_string(), q));
            }
            if !labels.is_empty() {
                params.push(("labels".to_string(), labels.join(",")));
            }
            if let Some(unread) = unread {
                params.push(("unread".to_string(), unread.to_string()));
            }
            let resp = with_optional_bearer(
                client.get(format!("{base}/v1/search")).query(&params),
                bearer_token,
            )
            .send()
            .await?;
            let val = parse_remote_json(resp).await?;
            if ndjson && let Some(items) = val.get("messages").and_then(Value::as_array) {
                for item in items {
                    emit_output(item.clone(), fields, true)?;
                }
                Ok(())
            } else {
                emit_output(val, fields, json_flag)
            }
        }
        MailAction::Threads {
            q,
            label,
            unread_only,
            limit,
        } => {
            let mut params: Vec<(String, String)> = vec![
                ("limit".to_string(), limit.to_string()),
                ("unread_only".to_string(), unread_only.to_string()),
            ];
            if let Some(q) = q {
                params.push(("q".to_string(), q));
            }
            if let Some(label) = label {
                params.push(("label".to_string(), label));
            }
            let resp = with_optional_bearer(
                client.get(format!("{base}/v1/threads")).query(&params),
                bearer_token,
            )
            .send()
            .await?;
            let val = parse_remote_json(resp).await?;
            if ndjson && let Some(items) = val.get("threads").and_then(Value::as_array) {
                for item in items {
                    emit_output(item.clone(), fields, true)?;
                }
                Ok(())
            } else {
                emit_output(val, fields, json_flag)
            }
        }
        MailAction::Read {
            id,
            thread,
            max_chars,
            strip_quotes,
            include_html,
        } => {
            let encoded_id: String = url::form_urlencoded::byte_serialize(id.as_bytes()).collect();
            let path = if thread {
                format!("{base}/v1/threads/{encoded_id}")
            } else {
                format!("{base}/v1/messages/{encoded_id}")
            };
            let params = [
                ("max_body_chars", max_chars.to_string()),
                ("strip_quotes", strip_quotes.to_string()),
                ("include_html", include_html.to_string()),
            ];
            let resp = with_optional_bearer(client.get(path).query(&params), bearer_token)
                .send()
                .await?;
            let val = parse_remote_json(resp).await?;
            emit_output(val, fields, json_flag)
        }
        MailAction::Send {
            payload,
            to,
            cc,
            bcc,
            subject,
            text,
            html,
            reply_to,
            dry_run,
            idempotency_key,
            send_at,
        } => {
            let mut req: AiSendEmailRequest = match payload {
                Some(raw) => serde_json::from_value(read_json_payload(&raw)?)?,
                None => AiSendEmailRequest {
                    from: None,
                    to,
                    cc,
                    bcc,
                    subject,
                    text,
                    html,
                    reply_to_message_id: reply_to,
                    dry_run,
                    idempotency_key: idempotency_key.clone(),
                    send_at,
                },
            };
            if dry_run {
                req.dry_run = true;
            }
            if req.idempotency_key.is_none() && idempotency_key.is_some() {
                req.idempotency_key = idempotency_key;
            }
            if req.send_at.is_none() && send_at.is_some() {
                req.send_at = send_at;
            }
            let resp = with_optional_bearer(
                client.post(format!("{base}/v1/messages/send")).json(&req),
                bearer_token,
            )
            .send()
            .await?;
            let val = parse_remote_json(resp).await?;
            emit_output(val, fields, json_flag)
        }
        MailAction::Draft {
            payload,
            to,
            cc,
            bcc,
            subject,
            text,
            html,
            reply_to,
            idempotency_key,
        } => {
            let mut req: AiCreateDraftRequest = match payload {
                Some(raw) => serde_json::from_value(read_json_payload(&raw)?)?,
                None => AiCreateDraftRequest {
                    from: None,
                    to,
                    cc,
                    bcc,
                    subject,
                    text,
                    html,
                    reply_to_message_id: reply_to,
                    idempotency_key: idempotency_key.clone(),
                },
            };
            if req.idempotency_key.is_none() && idempotency_key.is_some() {
                req.idempotency_key = idempotency_key;
            }
            let resp = with_optional_bearer(
                client.post(format!("{base}/v1/drafts")).json(&req),
                bearer_token,
            )
            .send()
            .await?;
            let val = parse_remote_json(resp).await?;
            emit_output(val, fields, json_flag)
        }
        MailAction::Triage {
            thread_id,
            archive,
            mark_read,
            mark_unread,
            star,
            trash,
            add_labels,
            remove_labels,
            dry_run,
        } => {
            let encoded_tid: String =
                url::form_urlencoded::byte_serialize(thread_id.as_bytes()).collect();
            let req = AiTriageRequest {
                archive,
                mark_read,
                mark_unread,
                star,
                trash,
                add_labels,
                remove_labels,
                dry_run,
            };
            let resp = with_optional_bearer(
                client
                    .post(format!("{base}/v1/threads/{encoded_tid}/triage"))
                    .json(&req),
                bearer_token,
            )
            .send()
            .await?;
            let val = parse_remote_json(resp).await?;
            emit_output(val, fields, json_flag)
        }
        MailAction::BatchTriage {
            payload,
            query,
            thread_ids,
            include_spam_trash,
            archive,
            mark_read,
            mark_unread,
            star,
            trash,
            add_labels,
            remove_labels,
            max_threads,
            dry_run,
        } => {
            let mut req: AiBatchTriageRequest = match payload {
                Some(raw) => serde_json::from_value(read_json_payload(&raw)?)?,
                None => AiBatchTriageRequest {
                    operations: Vec::new(),
                    thread_ids,
                    query,
                    include_spam_trash,
                    action: None,
                    archive,
                    mark_read,
                    mark_unread,
                    star,
                    trash,
                    add_labels,
                    remove_labels,
                    dry_run,
                    max_threads,
                },
            };
            if dry_run {
                req.dry_run = true;
            }
            if max_threads.is_some() && req.max_threads.is_none() {
                req.max_threads = max_threads;
            }
            let resp = with_optional_bearer(
                client
                    .post(format!("{base}/v1/threads/batch_triage"))
                    .json(&req),
                bearer_token,
            )
            .send()
            .await?;
            let val = parse_remote_json(resp).await?;
            emit_output(val, fields, json_flag)
        }
        MailAction::Labels => {
            let resp = with_optional_bearer(client.get(format!("{base}/v1/labels")), bearer_token)
                .send()
                .await?;
            let val = parse_remote_json(resp).await?;
            emit_output(val, fields, json_flag)
        }
        MailAction::Briefing {
            since,
            followup_days,
            limit,
        } => {
            let mut params: Vec<(String, String)> = Vec::new();
            if let Some(since) = since {
                params.push(("since".to_string(), since));
            }
            if let Some(days) = followup_days {
                params.push(("followup_days".to_string(), days.to_string()));
            }
            if let Some(limit) = limit {
                params.push(("limit".to_string(), limit.to_string()));
            }
            let resp = with_optional_bearer(
                client.get(format!("{base}/v1/briefing")).query(&params),
                bearer_token,
            )
            .send()
            .await?;
            let val = parse_remote_json(resp).await?;
            emit_output(val, fields, json_flag)
        }
        MailAction::Approvals { action } => match action {
            ApprovalsAction::List { status, limit } => {
                let params = [("status", status), ("limit", limit.to_string())];
                let resp = with_optional_bearer(
                    client.get(format!("{base}/v1/approvals")).query(&params),
                    bearer_token,
                )
                .send()
                .await?;
                let val = parse_remote_json(resp).await?;
                if ndjson && let Some(items) = val.get("approvals").and_then(Value::as_array) {
                    for item in items {
                        emit_output(item.clone(), fields, true)?;
                    }
                    Ok(())
                } else {
                    emit_output(val, fields, json_flag)
                }
            }
            ApprovalsAction::Get { id } => {
                let encoded_id: String =
                    url::form_urlencoded::byte_serialize(id.as_bytes()).collect();
                let resp = with_optional_bearer(
                    client.get(format!("{base}/v1/approvals/{encoded_id}")),
                    bearer_token,
                )
                .send()
                .await?;
                let val = parse_remote_json(resp).await?;
                emit_output(val, fields, json_flag)
            }
            ApprovalsAction::Approve {
                id,
                decided_by,
                note,
            } => {
                let encoded_id: String =
                    url::form_urlencoded::byte_serialize(id.as_bytes()).collect();
                let req = ApprovalDecisionRequest { decided_by, note };
                let resp = with_optional_bearer(
                    client
                        .post(format!("{base}/v1/approvals/{encoded_id}/approve"))
                        .json(&req),
                    bearer_token,
                )
                .send()
                .await?;
                let val = parse_remote_json(resp).await?;
                emit_output(val, fields, json_flag)
            }
            ApprovalsAction::Reject {
                id,
                decided_by,
                note,
            } => {
                let encoded_id: String =
                    url::form_urlencoded::byte_serialize(id.as_bytes()).collect();
                let req = ApprovalDecisionRequest { decided_by, note };
                let resp = with_optional_bearer(
                    client
                        .post(format!("{base}/v1/approvals/{encoded_id}/reject"))
                        .json(&req),
                    bearer_token,
                )
                .send()
                .await?;
                let val = parse_remote_json(resp).await?;
                emit_output(val, fields, json_flag)
            }
        },
        MailAction::Audit {
            action,
            actor,
            since,
            limit,
        } => {
            let mut params: Vec<(String, String)> = vec![("limit".to_string(), limit.to_string())];
            if let Some(action) = action {
                params.push(("action".to_string(), action));
            }
            if let Some(actor) = actor {
                params.push(("actor".to_string(), actor));
            }
            if let Some(since) = since {
                params.push(("since".to_string(), since));
            }
            let resp = with_optional_bearer(
                client.get(format!("{base}/v1/audit")).query(&params),
                bearer_token,
            )
            .send()
            .await?;
            let val = parse_remote_json(resp).await?;
            if ndjson && let Some(items) = val.get("entries").and_then(Value::as_array) {
                for item in items {
                    emit_output(item.clone(), fields, true)?;
                }
                Ok(())
            } else {
                emit_output(val, fields, json_flag)
            }
        }
        MailAction::Watch => {
            // Stream `/v1/events` SSE frames and emit each `data:` payload as NDJSON.
            let stream_client = reqwest::Client::builder()
                .build()
                .map_err(|e| AppError::Internal(format!("Failed to build HTTP client: {e}")))?;
            let mut resp = with_optional_bearer(
                stream_client
                    .get(format!("{base}/v1/events"))
                    .header("accept", "text/event-stream"),
                bearer_token,
            )
            .send()
            .await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(map_remote_http_error(status, &body));
            }
            let mut buf = String::new();
            while let Some(chunk) = resp.chunk().await? {
                buf.push_str(&String::from_utf8_lossy(&chunk));
                while let Some(pos) = buf.find('\n') {
                    let line = buf[..pos].trim_end_matches('\r').to_string();
                    buf.drain(..=pos);
                    if let Some(data) = line.strip_prefix("data:") {
                        let trimmed = data.trim();
                        if !trimmed.is_empty() {
                            println!("{trimmed}");
                        }
                    }
                }
            }
            Ok(())
        }
    }
}

async fn run(cli: Cli, matches: ArgMatches) -> AppResult<ExitCode> {
    ensure_crypto_provider();

    match cli.command {
        Command::Serve(serve_args) => {
            let serve_matches = matches.subcommand_matches("serve");
            let loaded =
                cli.common
                    .load_layered(Some(serve_args), &matches, serve_matches, cli.log_json)?;
            let config = finalize_runtime_config(loaded, false)?;
            let bind = config.bind;
            let has_imap = config.imap_bind.is_some() || config.imap_tls_bind.is_some();
            let has_bg_sync = config.has_background_sync();
            let has_watch_webhook = config
                .watch_webhook_url
                .as_deref()
                .is_some_and(|u| !u.trim().is_empty());
            let state = AppState::from_config_async(config).await?;

            let (shutdown_tx, shutdown_rx) = watch::channel(false);

            let event_bridge_handle = state.spawn_event_bridge_listener(shutdown_rx.clone());

            let imap_handle = if has_imap {
                let imap_state = state.clone();
                let imap_rx = shutdown_rx.clone();
                Some(tokio::spawn(async move {
                    if let Err(err) = imap::serve_imap(imap_state, imap_rx).await {
                        error!(%err, "IMAP server exited with error");
                    }
                }))
            } else {
                None
            };

            let sync_handle = if has_bg_sync {
                let sync_state = state.clone();
                let sync_rx = shutdown_rx.clone();
                Some(tokio::spawn(async move {
                    sync::run_background_sync(sync_state, sync_rx).await;
                }))
            } else {
                None
            };

            let watch_handle = if has_watch_webhook {
                let watch_state = state.clone();
                let watch_rx = shutdown_rx.clone();
                Some(tokio::spawn(async move {
                    gmail::run_watch_webhook_listener(watch_state, watch_rx).await;
                }))
            } else {
                None
            };

            let scheduler_handle = {
                let scheduler_state = state.clone();
                let scheduler_rx = shutdown_rx.clone();
                tokio::spawn(async move {
                    ai::run_background_scheduler(scheduler_state, scheduler_rx).await;
                })
            };

            let shutdown_state = state.clone();
            let router = build_router(state);
            let listener = tokio::net::TcpListener::bind(bind)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to bind HTTP {bind}: {e}")))?;
            info!(%bind, "nogml HTTP server listening");

            let serve_res = axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    shutdown_signal().await;
                    info!("Shutdown signal received, draining subsystems");
                    shutdown_state.trigger_shutdown();
                    let _ = shutdown_tx.send(true);
                })
                .await;

            let _ = scheduler_handle.await;
            if let Some(h) = imap_handle {
                let _ = h.await;
            }
            if let Some(h) = sync_handle {
                let _ = h.await;
            }
            if let Some(h) = watch_handle {
                let _ = h.await;
            }
            if let Some(h) = event_bridge_handle {
                let _ = h.await;
            }

            serve_res.map_err(|e| AppError::Internal(format!("HTTP server error: {e}")))?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Mcp => {
            // MCP stdio MUST keep stdout strictly clean for JSON-RPC frames.
            let loaded = cli
                .common
                .load_layered(None, &matches, None, cli.log_json)?;
            let config = finalize_runtime_config(loaded, true)?;
            let state = AppState::from_config_async(config).await?;
            mcp::run_stdio(state).await?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Sync { provider } => {
            let loaded = cli
                .common
                .load_layered(None, &matches, None, cli.log_json)?;
            let config = finalize_runtime_config(loaded, true)?;
            let state = AppState::from_config_async(config).await?;
            match provider {
                SyncCommand::Gmail {
                    mode,
                    full,
                    max_messages,
                    query,
                    mailbox,
                } => {
                    let target_state =
                        match mailbox.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                            Some(mb) => match state.config.sync_account_for_mailbox(mb) {
                                Some(acct) => state.for_sync_account(acct),
                                None => state.for_mailbox(mb),
                            },
                            None => match state.config.sync_account_for_mailbox(state.mailbox_id())
                            {
                                Some(acct) => state.for_sync_account(acct),
                                None => state,
                            },
                        };
                    let report = sync::run_gmail_sync(
                        &target_state,
                        SyncRunOptions {
                            mode,
                            full,
                            max_messages,
                            query,
                            bidirectional: None,
                        },
                    )
                    .await?;
                    emit_output(serde_json::to_value(report)?, None, false)?;
                    Ok(ExitCode::SUCCESS)
                }
            }
        }

        Command::Storage { action } => {
            let loaded = cli
                .common
                .load_layered(None, &matches, None, cli.log_json)?;
            let config = finalize_runtime_config(loaded, true)?;
            match action {
                StorageCommand::MigrateBlobs { to } => {
                    let mailboxes = config.known_mailboxes();
                    let mut target_config = config.clone();
                    target_config.blob_backend = to;
                    let target_base = open_blob_store(&target_config)?;
                    let state = AppState::from_config_async(config).await?;
                    let source_backend = state.blobs.backend_name().to_string();
                    let target_backend = target_base.backend_name().to_string();

                    let mut per_mailbox = Vec::with_capacity(mailboxes.len());
                    let mut total_messages = 0u64;
                    let mut total_attachments = 0u64;
                    let mut total_bytes = 0u64;

                    for mb in &mailboxes {
                        let mb_state = state.for_mailbox(mb);
                        let target_state = mb_state.clone().with_blobs(target_base.clone());
                        let report = migrate_blobs(
                            mb_state.store.as_ref(),
                            mb_state.blobs.as_ref(),
                            target_state.blobs.as_ref(),
                        )
                        .await?;
                        total_messages += report.messages_migrated;
                        total_attachments += report.attachments_migrated;
                        total_bytes += report.bytes_copied;
                        per_mailbox.push(serde_json::json!({
                            "mailbox_id": mb,
                            "messages_migrated": report.messages_migrated,
                            "attachments_migrated": report.attachments_migrated,
                            "bytes_copied": report.bytes_copied,
                        }));
                    }

                    let summary = serde_json::json!({
                        "source_backend": source_backend,
                        "target_backend": target_backend,
                        "messages_migrated": total_messages,
                        "attachments_migrated": total_attachments,
                        "bytes_copied": total_bytes,
                        "mailboxes": per_mailbox,
                    });
                    emit_output(summary, None, false)?;
                    Ok(ExitCode::SUCCESS)
                }
            }
        }

        Command::Search { action } => {
            let loaded = cli
                .common
                .load_layered(None, &matches, None, cli.log_json)?;
            let config = finalize_runtime_config(loaded, true)?;
            let state = AppState::from_config_async(config).await?;
            match action {
                SearchCommand::Reindex => {
                    let mailboxes = state.config.known_mailboxes();
                    let backend = state.search.backend_name().to_string();
                    let mut per_mailbox = Vec::with_capacity(mailboxes.len());
                    let mut total_indexed = 0u64;
                    let mut total_failed = 0u64;

                    for mb in &mailboxes {
                        let mb_state = state.for_mailbox(mb);
                        let report =
                            reindex_mailbox(mb_state.store.as_ref(), mb_state.search.as_ref())
                                .await?;
                        total_indexed += report.indexed;
                        total_failed += report.failed;
                        per_mailbox.push(serde_json::json!({
                            "mailbox_id": mb,
                            "indexed": report.indexed,
                            "failed": report.failed,
                        }));
                    }

                    let summary = serde_json::json!({
                        "backend": backend,
                        "indexed": total_indexed,
                        "failed": total_failed,
                        "mailboxes": per_mailbox,
                    });
                    emit_output(summary, None, false)?;
                    Ok(ExitCode::SUCCESS)
                }
            }
        }

        Command::Config { action } => match action {
            ConfigCommand::Init {
                output,
                token_file,
                force,
            } => {
                if output.exists() && !force {
                    return Err(AppError::Config(format!(
                        "Config file '{}' already exists; pass --force to overwrite",
                        output.display()
                    )));
                }

                let user_email = if is_explicit(&matches, "user_email") {
                    cli.common
                        .user_email
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("agent@example.com")
                        .to_string()
                } else {
                    "agent@example.com".to_string()
                };

                let default_domain = if is_explicit(&matches, "default_domain") {
                    cli.common.default_domain.clone()
                } else {
                    user_email
                        .split_once('@')
                        .map(|(_, d)| d.to_string())
                        .filter(|d| !d.is_empty())
                        .unwrap_or_else(|| "example.com".to_string())
                };

                let token = generate_bearer_token();
                let resolved_token_file = if let Some(ref tf) = token_file {
                    write_secret_file(tf, &token, force)?;
                    Some(fs::canonicalize(tf).unwrap_or_else(|_| tf.clone()))
                } else {
                    None
                };

                let rendered = render_starter_toml(
                    &user_email,
                    &default_domain,
                    resolved_token_file.as_deref(),
                );

                if let Some(parent) = output.parent()
                    && !parent.as_os_str().is_empty()
                {
                    fs::create_dir_all(parent).map_err(|e| {
                        AppError::Config(format!(
                            "Failed to create directory '{}' for config file: {e}",
                            parent.display()
                        ))
                    })?;
                }
                fs::write(&output, rendered).map_err(|e| {
                    AppError::Config(format!(
                        "Failed to write config file '{}': {e}",
                        output.display()
                    ))
                })?;

                let note = if let Some(ref tf) = resolved_token_file {
                    format!(
                        "Generated starter config and wrote bearer token with mode 0600 to '{}'.",
                        tf.display()
                    )
                } else {
                    eprintln!("Generated bearer token (printed once, not written to config file):");
                    eprintln!("  {token}");
                    eprintln!();
                    eprintln!("Enable authentication by exporting:");
                    eprintln!("  export NOGML_AUTH_TOKENS=\"{token}\"");
                    eprintln!(
                        "Or save it to a mode 0600 secret file and reference it via file:///path/to/token."
                    );
                    "Generated starter config; bearer token printed once to stderr (not written to config file)."
                        .to_string()
                };

                emit_output(
                    json!({
                        "ok": true,
                        "path": output,
                        "token_file": resolved_token_file,
                        "note": note,
                    }),
                    None,
                    false,
                )?;
                Ok(ExitCode::SUCCESS)
            }

            ConfigCommand::Check(serve_args) => {
                init_tracing(cli.log_json, true);
                let check_matches = matches
                    .subcommand_matches("config")
                    .and_then(|m| m.subcommand_matches("check"));
                let config_path = cli.common.config.clone();

                let report = match cli.common.load_layered(
                    Some(*serve_args),
                    &matches,
                    check_matches,
                    cli.log_json,
                ) {
                    Ok(loaded) => {
                        validate_config(&loaded.config, loaded.config_file, loaded.resolution)
                    }
                    Err(err) => ConfigCheckReport {
                        ok: false,
                        config_file: config_path,
                        warnings: Vec::new(),
                        errors: vec![err.to_string()],
                        effective_config: None,
                    },
                };

                let exit = if report.ok {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(2)
                };
                emit_output(serde_json::to_value(&report)?, None, false)?;
                Ok(exit)
            }
        },

        Command::Crypto { action } => match action {
            CryptoCommand::GenerateKey {
                kid,
                output_file,
                force,
            } => {
                let (validated_kid, formatted) = generate_formatted_key(&kid)?;
                if let Some(path) = output_file {
                    write_secret_file(&path, &formatted, force)?;
                    let saved_to = fs::canonicalize(&path).unwrap_or(path);
                    emit_output(
                        json!({
                            "ok": true,
                            "kid": validated_kid,
                            "saved_to": saved_to,
                        }),
                        None,
                        false,
                    )?;
                } else {
                    emit_output(
                        json!({
                            "ok": true,
                            "kid": validated_kid,
                            "key": formatted,
                        }),
                        None,
                        false,
                    )?;
                }
                Ok(ExitCode::SUCCESS)
            }

            CryptoCommand::RotateKey => {
                let loaded = cli
                    .common
                    .load_layered(None, &matches, None, cli.log_json)?;
                let config = finalize_runtime_config(loaded, true)?;
                let state = AppState::from_config_async(config).await?;
                let report = rotate_secrets(&state).await?;
                emit_output(serde_json::to_value(report)?, None, false)?;
                Ok(ExitCode::SUCCESS)
            }
        },

        Command::Auth { action } => match action {
            AuthCommand::MintToken {
                mailbox,
                scopes,
                output_file,
                force,
                format,
                json: json_flag,
            } => {
                let resolved_mailbox =
                    if let Some(mb) = mailbox.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                        Some(mb.to_string())
                    } else if is_explicit(&matches, "user_email") {
                        cli.common
                            .user_email
                            .as_deref()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(ToString::to_string)
                    } else if let Some(ref cfg_path) = cli.common.config {
                        let toml_cfg = TomlConfig::from_file(cfg_path)?;
                        toml_cfg
                            .auth
                            .user_email
                            .as_deref()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(ToString::to_string)
                    } else {
                        None
                    };

                let draft_only = (arg_origin(&matches, "draft_only") == ValueOrigin::Cli)
                    .then_some(cli.common.draft_only);
                let allowed_recipients = (arg_origin(&matches, "allowed_recipients")
                    == ValueOrigin::Cli)
                    .then(|| cli.common.allowed_recipients.clone());
                let max_send_recipients = (arg_origin(&matches, "max_send_recipients")
                    == ValueOrigin::Cli)
                    .then_some(cli.common.max_send_recipients);

                let minted = mint_scoped_token(&MintTokenOptions {
                    mailbox: resolved_mailbox,
                    scopes,
                    draft_only,
                    allowed_recipients,
                    max_send_recipients,
                    output_file,
                    force,
                })?;

                if let Some(ref saved_to) = minted.saved_to {
                    eprintln!(
                        "Wrote scoped token (mode 0600) to '{}'.",
                        saved_to.display()
                    );
                }

                let effective_format = if json_flag {
                    MintTokenFormat::Json
                } else {
                    format
                };
                match effective_format {
                    MintTokenFormat::Toml => {
                        println!("{}", render_scoped_token_toml(&minted.entry));
                    }
                    MintTokenFormat::Json => {
                        let pretty = std::io::stdout().is_terminal();
                        println!("{}", render_scoped_token_json(&minted.entry, pretty)?);
                    }
                }
                Ok(ExitCode::SUCCESS)
            }

            AuthCommand::Gmail {
                client_id,
                client_secret,
                auth_url,
                token_url,
                scopes,
                listen,
                output_file,
                force,
                no_browser,
                timeout_secs,
            } => {
                let gmail_matches = matches
                    .subcommand_matches("auth")
                    .and_then(|m| m.subcommand_matches("gmail"));

                let (cfg_client_id, cfg_client_secret, cfg_token_url) =
                    if cli.common.config.is_some() {
                        let loaded = cli
                            .common
                            .load_layered(None, &matches, None, cli.log_json)?;
                        loaded.resolution.into_result()?;
                        (
                            loaded.config.gmail_client_id,
                            loaded.config.gmail_client_secret,
                            Some(loaded.config.gmail_oauth_token_url),
                        )
                    } else {
                        (
                            cli.common.gmail_client_id,
                            cli.common.gmail_client_secret,
                            is_explicit(&matches, "gmail_oauth_token_url")
                                .then_some(cli.common.gmail_oauth_token_url),
                        )
                    };

                let resolved_client_id = client_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string)
                    .or_else(|| {
                        cfg_client_id
                            .as_deref()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(ToString::to_string)
                    })
                    .ok_or_else(|| {
                        AppError::Config(
                            "GMAIL_CLIENT_ID / --client-id is required for `nogml auth gmail`"
                                .to_string(),
                        )
                    })?;

                let raw_client_secret = client_secret
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string)
                    .or_else(|| {
                        cfg_client_secret
                            .as_deref()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(ToString::to_string)
                    });

                let resolved_client_secret = match raw_client_secret {
                    Some(raw) if raw.starts_with("file://") || raw.starts_with("env://") => {
                        let mut report = SecretResolutionReport::default();
                        let val = resolve_secret_value(
                            "sync.gmail_client_secret",
                            &raw,
                            None,
                            &system_env_lookup,
                            &mut report,
                        );
                        report.into_result()?;
                        val.filter(|s| !s.trim().is_empty())
                    }
                    Some(raw) => Some(raw),
                    None => {
                        if let Some(path_str) = system_env_lookup("GMAIL_CLIENT_SECRET_FILE")
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                        {
                            let mut report = SecretResolutionReport::default();
                            let val = read_secret_file(
                                "sync.gmail_client_secret",
                                Path::new(&path_str),
                                &mut report,
                            );
                            report.into_result()?;
                            val.filter(|s| !s.trim().is_empty())
                        } else {
                            None
                        }
                    }
                };

                let resolved_token_url =
                    if gmail_matches.is_some_and(|gm| is_explicit(gm, "token_url")) {
                        token_url
                    } else if let Some(url) = cfg_token_url {
                        url
                    } else {
                        token_url
                    };

                let summary = run_gmail_oauth_flow(GmailAuthOptions {
                    client_id: resolved_client_id,
                    client_secret: resolved_client_secret,
                    auth_url,
                    token_url: resolved_token_url,
                    scopes,
                    listen,
                    output_file,
                    force,
                    no_browser,
                    timeout: Duration::from_secs(timeout_secs.max(1)),
                })
                .await?;

                emit_output(serde_json::to_value(&summary)?, None, false)?;
                Ok(ExitCode::SUCCESS)
            }
        },

        Command::Schema { command, openapi } => {
            let schema = if openapi {
                ai::openapi_spec()
            } else {
                ai::runtime_schema(command.as_deref())
            };
            emit_output(schema, None, true)?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Doctor(serve_args) => {
            init_tracing(cli.log_json, true);
            let doctor_matches = matches.subcommand_matches("doctor");
            let report = match cli.common.load_layered(
                Some(*serve_args),
                &matches,
                doctor_matches,
                cli.log_json,
            ) {
                Ok(loaded) => {
                    run_doctor(&loaded.config, loaded.config_file, loaded.resolution).await
                }
                Err(err) => DoctorReport::config_load_failure(err.to_string()),
            };

            let exit = if report.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            };
            emit_output(serde_json::to_value(&report)?, None, false)?;
            Ok(exit)
        }

        Command::Completions { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "nogml", &mut std::io::stdout());
            Ok(ExitCode::SUCCESS)
        }

        Command::Domains { action } => {
            let loaded = cli
                .common
                .load_layered(None, &matches, None, cli.log_json)?;
            let config = finalize_runtime_config(loaded, true)?;
            let state = AppState::from_config_async(config).await?;
            let out = match action {
                DomainCommand::Add {
                    domain,
                    provider,
                    mailbox,
                    catch_all,
                } => {
                    let provider_kind = match provider.as_deref() {
                        Some(raw) => {
                            let parsed = nogml::domains::DomainProviderKind::parse_str(raw)
                                .ok_or_else(|| {
                                    AppError::validation(
                                        format!(
                                            "Invalid domain provider '{raw}': expected 'ses', 'resend', or 'manual'"
                                        ),
                                        None,
                                    )
                                })?;
                            Some(parsed)
                        }
                        None => None,
                    };
                    let rec = nogml::domains::execute_create_domain(
                        &state,
                        nogml::domains::CreateDomainRequest {
                            domain,
                            provider: provider_kind,
                            mailbox_id: mailbox,
                            catch_all_mailbox: catch_all,
                        },
                        None,
                        "cli",
                    )
                    .await?;
                    serde_json::to_value(rec)?
                }
                DomainCommand::List { mailbox } => {
                    let domains =
                        nogml::domains::execute_list_domains(&state, mailbox.as_deref(), None)
                            .await?;
                    json!({
                        "domains": domains,
                        "count": domains.len(),
                    })
                }
                DomainCommand::Get { domain } => {
                    let rec = nogml::domains::execute_get_domain(&state, &domain, None).await?;
                    serde_json::to_value(rec)?
                }
                DomainCommand::Verify { domain } => {
                    let rec =
                        nogml::domains::execute_verify_domain(&state, &domain, None, "cli").await?;
                    serde_json::to_value(rec)?
                }
                DomainCommand::Delete { domain } => {
                    nogml::domains::execute_delete_domain(&state, &domain, None, "cli").await?
                }
            };
            emit_output(out, None, false)?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Mail {
            url,
            json: json_flag,
            ndjson,
            fields,
            action,
        } => {
            let loaded = cli
                .common
                .load_layered(None, &matches, None, cli.log_json)?;
            let config = finalize_runtime_config(loaded, true)?;

            if let Some(remote_url) = url {
                let token = config.auth_tokens.first().cloned();
                run_remote_mail(
                    &remote_url,
                    token.as_deref(),
                    action,
                    fields.as_deref(),
                    json_flag,
                    ndjson,
                )
                .await?;
                return Ok(ExitCode::SUCCESS);
            }

            let state = AppState::from_config_async(config).await?;

            match action {
                MailAction::Search {
                    q,
                    labels,
                    unread,
                    limit,
                    include_body,
                    max_chars,
                } => {
                    let page = state
                        .search
                        .search(&AiSearchQuery {
                            q,
                            labels,
                            unread,
                            limit,
                            ..Default::default()
                        })
                        .await?;
                    let items: Vec<_> = page
                        .messages
                        .iter()
                        .map(|m| {
                            ai::to_compact_message(
                                m,
                                &state.config,
                                include_body,
                                max_chars,
                                false,
                                false,
                            )
                        })
                        .collect();
                    if ndjson {
                        for item in items {
                            emit_output(serde_json::to_value(item)?, fields.as_deref(), true)?;
                        }
                    } else {
                        emit_output(
                            json!({ "messages": items, "next_cursor": page.next_cursor, "has_more": page.has_more }),
                            fields.as_deref(),
                            json_flag,
                        )?;
                    }
                }
                MailAction::Threads {
                    q,
                    label,
                    unread_only,
                    limit,
                } => {
                    let page = state
                        .store
                        .list_thread_summaries(&AiThreadQuery {
                            q,
                            label,
                            unread_only,
                            limit,
                            ..Default::default()
                        })
                        .await?;
                    if ndjson {
                        for item in page.threads {
                            emit_output(serde_json::to_value(item)?, fields.as_deref(), true)?;
                        }
                    } else {
                        emit_output(
                            json!({ "threads": page.threads, "next_cursor": page.next_cursor, "has_more": page.has_more }),
                            fields.as_deref(),
                            json_flag,
                        )?;
                    }
                }
                MailAction::Read {
                    id,
                    thread,
                    max_chars,
                    strip_quotes,
                    include_html,
                } => {
                    if thread {
                        let detail =
                            state.store.get_thread(&id).await?.ok_or_else(|| {
                                AppError::NotFound(format!("Thread {id} not found"))
                            })?;
                        let messages: Vec<_> = detail
                            .messages
                            .iter()
                            .map(|m| {
                                ai::to_compact_message(
                                    m,
                                    &state.config,
                                    true,
                                    max_chars,
                                    strip_quotes,
                                    include_html,
                                )
                            })
                            .collect();
                        emit_output(
                            json!({ "id": detail.id, "messages": messages }),
                            fields.as_deref(),
                            json_flag,
                        )?;
                    } else {
                        let msg =
                            state.store.get_message(&id).await?.ok_or_else(|| {
                                AppError::NotFound(format!("Message {id} not found"))
                            })?;
                        let compact = ai::to_compact_message(
                            &msg,
                            &state.config,
                            true,
                            max_chars,
                            strip_quotes,
                            include_html,
                        );
                        emit_output(serde_json::to_value(compact)?, fields.as_deref(), json_flag)?;
                    }
                }
                MailAction::Send {
                    payload,
                    to,
                    cc,
                    bcc,
                    subject,
                    text,
                    html,
                    reply_to,
                    dry_run,
                    idempotency_key,
                    send_at,
                } => {
                    let mut req: AiSendEmailRequest = match payload {
                        Some(raw) => serde_json::from_value(read_json_payload(&raw)?)?,
                        None => AiSendEmailRequest {
                            from: None,
                            to,
                            cc,
                            bcc,
                            subject,
                            text,
                            html,
                            reply_to_message_id: reply_to,
                            dry_run,
                            idempotency_key: idempotency_key.clone(),
                            send_at,
                        },
                    };
                    if dry_run {
                        req.dry_run = true;
                    }
                    if req.idempotency_key.is_none() && idempotency_key.is_some() {
                        req.idempotency_key = idempotency_key;
                    }
                    if req.send_at.is_none() && send_at.is_some() {
                        req.send_at = send_at;
                    }
                    let res = ai::execute_send_email(&state, req).await?;
                    emit_output(res, fields.as_deref(), json_flag)?;
                }
                MailAction::Draft {
                    payload,
                    to,
                    cc,
                    bcc,
                    subject,
                    text,
                    html,
                    reply_to,
                    idempotency_key,
                } => {
                    let mut req: AiCreateDraftRequest = match payload {
                        Some(raw) => serde_json::from_value(read_json_payload(&raw)?)?,
                        None => AiCreateDraftRequest {
                            from: None,
                            to,
                            cc,
                            bcc,
                            subject,
                            text,
                            html,
                            reply_to_message_id: reply_to,
                            idempotency_key: idempotency_key.clone(),
                        },
                    };
                    if req.idempotency_key.is_none() && idempotency_key.is_some() {
                        req.idempotency_key = idempotency_key;
                    }
                    let res = ai::execute_create_draft(&state, req).await?;
                    emit_output(res, fields.as_deref(), json_flag)?;
                }
                MailAction::Triage {
                    thread_id,
                    archive,
                    mark_read,
                    mark_unread,
                    star,
                    trash,
                    add_labels,
                    remove_labels,
                    dry_run,
                } => {
                    let res = ai::execute_triage_thread(
                        &state,
                        &thread_id,
                        AiTriageRequest {
                            archive,
                            mark_read,
                            mark_unread,
                            star,
                            trash,
                            add_labels,
                            remove_labels,
                            dry_run,
                        },
                    )
                    .await?;
                    emit_output(res, fields.as_deref(), json_flag)?;
                }
                MailAction::BatchTriage {
                    payload,
                    query,
                    thread_ids,
                    include_spam_trash,
                    archive,
                    mark_read,
                    mark_unread,
                    star,
                    trash,
                    add_labels,
                    remove_labels,
                    max_threads,
                    dry_run,
                } => {
                    let mut req: AiBatchTriageRequest = match payload {
                        Some(raw) => serde_json::from_value(read_json_payload(&raw)?)?,
                        None => AiBatchTriageRequest {
                            operations: Vec::new(),
                            thread_ids,
                            query,
                            include_spam_trash,
                            action: None,
                            archive,
                            mark_read,
                            mark_unread,
                            star,
                            trash,
                            add_labels,
                            remove_labels,
                            dry_run,
                            max_threads,
                        },
                    };
                    if dry_run {
                        req.dry_run = true;
                    }
                    if max_threads.is_some() && req.max_threads.is_none() {
                        req.max_threads = max_threads;
                    }
                    let res = ai::execute_batch_triage(&state, req).await?;
                    emit_output(res, fields.as_deref(), json_flag)?;
                }
                MailAction::Labels => {
                    let labels = state.store.list_labels().await?;
                    emit_output(json!({ "labels": labels }), fields.as_deref(), json_flag)?;
                }
                MailAction::Briefing {
                    since,
                    followup_days,
                    limit,
                } => {
                    let since = ai::parse_briefing_since(since.as_deref())?;
                    let val = ai::execute_briefing(
                        &state,
                        ai::BriefingParams {
                            since,
                            followup_days,
                            limit,
                        },
                    )
                    .await?;
                    emit_output(val, fields.as_deref(), json_flag)?;
                }
                MailAction::Approvals { action } => match action {
                    ApprovalsAction::List { status, limit } => {
                        let val = ai::execute_list_approvals(&state, Some(&status), limit).await?;
                        if ndjson
                            && let Some(items) = val.get("approvals").and_then(Value::as_array)
                        {
                            for item in items {
                                emit_output(item.clone(), fields.as_deref(), true)?;
                            }
                        } else {
                            emit_output(val, fields.as_deref(), json_flag)?;
                        }
                    }
                    ApprovalsAction::Get { id } => {
                        let val = ai::execute_get_approval(&state, &id).await?;
                        emit_output(val, fields.as_deref(), json_flag)?;
                    }
                    ApprovalsAction::Approve {
                        id,
                        decided_by,
                        note,
                    } => {
                        let val = ai::execute_approve_approval(
                            &state,
                            &id,
                            ApprovalDecisionRequest { decided_by, note },
                            None,
                            EventSource::Api,
                        )
                        .await?;
                        emit_output(val, fields.as_deref(), json_flag)?;
                    }
                    ApprovalsAction::Reject {
                        id,
                        decided_by,
                        note,
                    } => {
                        let val = ai::execute_reject_approval(
                            &state,
                            &id,
                            ApprovalDecisionRequest { decided_by, note },
                            None,
                            EventSource::Api,
                        )
                        .await?;
                        emit_output(val, fields.as_deref(), json_flag)?;
                    }
                },
                MailAction::Audit {
                    action,
                    actor,
                    since,
                    limit,
                } => {
                    let val = ai::execute_list_audit_log(
                        &state,
                        action.as_deref(),
                        actor.as_deref(),
                        since.as_deref(),
                        limit,
                    )
                    .await?;
                    if ndjson && let Some(items) = val.get("entries").and_then(Value::as_array) {
                        for item in items {
                            emit_output(item.clone(), fields.as_deref(), true)?;
                        }
                    } else {
                        emit_output(val, fields.as_deref(), json_flag)?;
                    }
                }
                MailAction::Watch => {
                    let mut rx = state.events.subscribe();
                    while let Ok(env) = rx.recv().await {
                        println!("{}", serde_json::to_string(&env)?);
                    }
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    match run(cli, matches).await {
        Ok(code) => code,
        Err(err) => {
            let code = err.exit_code();
            let envelope = err.to_ai_envelope();
            if let Ok(json_str) = serde_json::to_string(&envelope) {
                eprintln!("{json_str}");
            } else {
                eprintln!("{err}");
            }
            ExitCode::from(code as u8)
        }
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn clap_cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
