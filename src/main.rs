use std::{
    io::{IsTerminal, Read},
    net::SocketAddr,
    path::PathBuf,
    process::ExitCode,
    time::Duration,
};

use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};
use tokio::sync::watch;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt};

use nogml::{
    AppState, ai, build_router,
    config::{BlobBackend, Config, DraftOnlyAction, StorageBackend, SyncMode},
    ensure_crypto_provider,
    error::{AppError, AppResult},
    gmail, imap, mcp,
    models::{AiCreateDraftRequest, AiSendEmailRequest, AiTriageRequest},
    storage::{AiSearchQuery, AiThreadQuery},
    sync::{self, SyncRunOptions},
};

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
    /// Storage backend (`sqlite` or `memory`).
    #[arg(long, env = "NOGML_STORAGE", default_value = "sqlite", global = true)]
    storage: StorageBackend,

    /// SQLite database file path (when `--storage=sqlite`).
    #[arg(long, env = "NOGML_DB_PATH", default_value = "nogml.db", global = true)]
    db_path: PathBuf,

    /// Blob storage backend (`inline`, `fs`, or `memory`).
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

    /// Primary mailbox email address.
    #[arg(
        long,
        env = "NOGML_USER_EMAIL",
        default_value = "me@localhost",
        global = true
    )]
    user_email: String,

    /// Default domain for generated Message-IDs and fallback sender addresses.
    #[arg(
        long,
        env = "NOGML_DEFAULT_DOMAIN",
        default_value = "localhost",
        global = true
    )]
    default_domain: String,

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

    /// Comma-separated bearer auth tokens (empty = dev unauthenticated mode).
    #[arg(long, env = "NOGML_AUTH_TOKENS", value_delimiter = ',', global = true)]
    auth_tokens: Vec<String>,

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

    #[arg(long, env = "NOGML_SYNC_QUERY", global = true)]
    sync_query: Option<String>,

    #[arg(long, env = "NOGML_SYNC_MAX_MESSAGES", global = true)]
    sync_max_messages: Option<usize>,
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

    /// Print runtime JSON schemas for CLI commands and `/v1/` endpoints.
    Schema {
        /// Optional command or endpoint name to inspect.
        #[arg(long)]
        command: Option<String>,
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
    },
}

#[derive(Debug, Subcommand)]
enum MailAction {
    /// Search messages using FTS5 and structured filters.
    Search {
        #[arg(long)]
        q: Option<String>,
        #[arg(long, value_delimiter = ',')]
        labels: Vec<String>,
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
    /// List available labels.
    Labels,
    /// Stream real-time mail events as NDJSON.
    Watch,
}

impl CommonConfigArgs {
    fn into_config(self, serve: Option<ServeArgs>) -> Config {
        let mut cfg = Config {
            storage: self.storage,
            db_path: self.db_path,
            blob_backend: self.blob_backend,
            blob_dir: self.blob_dir,
            user_email: self.user_email,
            default_domain: self.default_domain,
            resend_api_key: self.resend_api_key,
            resend_base_url: self.resend_base_url,
            resend_webhook_secret: self.resend_webhook_secret,
            auth_tokens: self.auth_tokens,
            draft_only: self.draft_only,
            draft_only_action: self.draft_only_action,
            allowed_recipients: self.allowed_recipients,
            max_send_recipients: self.max_send_recipients,
            default_max_body_chars: self.default_max_body_chars,
            untrusted_content_guard: self.untrusted_content_guard,
            sync_mode: self.sync_mode,
            gmail_client_id: self.gmail_client_id,
            gmail_client_secret: self.gmail_client_secret,
            gmail_refresh_token: self.gmail_refresh_token,
            gmail_access_token: self.gmail_access_token,
            gmail_user_id: self.gmail_user_id,
            gmail_api_base_url: self.gmail_api_base_url,
            gmail_oauth_token_url: self.gmail_oauth_token_url,
            gmail_imap_host: self.gmail_imap_host,
            gmail_imap_port: self.gmail_imap_port,
            gmail_imap_tls: self.gmail_imap_tls,
            gmail_imap_user: self.gmail_imap_user,
            gmail_imap_password: self.gmail_imap_password,
            gmail_imap_mailbox: self.gmail_imap_mailbox,
            sync_query: self.sync_query,
            sync_max_messages: self.sync_max_messages,
            ..Config::default()
        };

        if let Some(s) = serve {
            cfg.bind = s.bind;
            cfg.max_body_bytes = s.max_body_bytes;
            cfg.cors_allow_origins = s.cors_allow_origins;
            cfg.imap_bind = s.imap_bind;
            cfg.imap_tls_bind = s.imap_tls_bind;
            cfg.imap_tls_cert = s.imap_tls_cert;
            cfg.imap_tls_key = s.imap_tls_key;
            cfg.imap_username = s.imap_username;
            cfg.imap_password = s.imap_password;
            cfg.sync_interval_secs = s.sync_interval_secs;
            cfg.watch_webhook_url = s.watch_webhook_url;
        }

        cfg
    }
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
        } => {
            let mut req: AiSendEmailRequest = match payload {
                Some(raw) => serde_json::from_value(read_json_payload(&raw)?)?,
                None => AiSendEmailRequest {
                    to,
                    cc,
                    bcc,
                    subject,
                    text,
                    html,
                    reply_to_message_id: reply_to,
                    dry_run,
                },
            };
            if dry_run {
                req.dry_run = true;
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
        } => {
            let req: AiCreateDraftRequest = match payload {
                Some(raw) => serde_json::from_value(read_json_payload(&raw)?)?,
                None => AiCreateDraftRequest {
                    to,
                    cc,
                    bcc,
                    subject,
                    text,
                    html,
                    reply_to_message_id: reply_to,
                },
            };
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
        MailAction::Labels => {
            let resp = with_optional_bearer(client.get(format!("{base}/v1/labels")), bearer_token)
                .send()
                .await?;
            let val = parse_remote_json(resp).await?;
            emit_output(val, fields, json_flag)
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

async fn run(cli: Cli) -> AppResult<()> {
    ensure_crypto_provider();

    match cli.command {
        Command::Serve(serve_args) => {
            init_tracing(cli.log_json, false);
            let config = cli.common.into_config(Some(serve_args));
            let bind = config.bind;
            let has_imap = config.imap_bind.is_some() || config.imap_tls_bind.is_some();
            let has_bg_sync = config.sync_interval_secs > 0;
            let has_watch_webhook = config
                .watch_webhook_url
                .as_deref()
                .is_some_and(|u| !u.trim().is_empty());
            let state = AppState::from_config(config)?;

            let (shutdown_tx, shutdown_rx) = watch::channel(false);

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

            let router = build_router(state);
            let listener = tokio::net::TcpListener::bind(bind)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to bind HTTP {bind}: {e}")))?;
            info!(%bind, "nogml HTTP server listening");

            let serve_res = axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    shutdown_signal().await;
                    info!("Shutdown signal received, draining subsystems");
                    let _ = shutdown_tx.send(true);
                })
                .await;

            if let Some(h) = imap_handle {
                let _ = h.await;
            }
            if let Some(h) = sync_handle {
                let _ = h.await;
            }
            if let Some(h) = watch_handle {
                let _ = h.await;
            }

            serve_res.map_err(|e| AppError::Internal(format!("HTTP server error: {e}")))?;
            Ok(())
        }

        Command::Mcp => {
            // MCP stdio MUST keep stdout strictly clean for JSON-RPC frames.
            init_tracing(cli.log_json, true);
            let config = cli.common.into_config(None);
            let state = AppState::from_config(config)?;
            mcp::run_stdio(state).await
        }

        Command::Sync { provider } => {
            init_tracing(cli.log_json, true);
            let config = cli.common.into_config(None);
            let state = AppState::from_config(config)?;
            match provider {
                SyncCommand::Gmail {
                    mode,
                    full,
                    max_messages,
                    query,
                } => {
                    let report = sync::run_gmail_sync(
                        &state,
                        SyncRunOptions {
                            mode,
                            full,
                            max_messages,
                            query,
                        },
                    )
                    .await?;
                    emit_output(serde_json::to_value(report)?, None, false)
                }
            }
        }

        Command::Schema { command } => {
            let schema = ai::runtime_schema(command.as_deref());
            emit_output(schema, None, true)
        }

        Command::Mail {
            url,
            json: json_flag,
            ndjson,
            fields,
            action,
        } => {
            init_tracing(cli.log_json, true);
            if let Some(remote_url) = url {
                let token = cli.common.auth_tokens.first().cloned();
                return run_remote_mail(
                    &remote_url,
                    token.as_deref(),
                    action,
                    fields.as_deref(),
                    json_flag,
                    ndjson,
                )
                .await;
            }

            let config = cli.common.into_config(None);
            let state = AppState::from_config(config)?;

            match action {
                MailAction::Search {
                    q,
                    labels,
                    limit,
                    include_body,
                    max_chars,
                } => {
                    let page = state
                        .search
                        .search(&AiSearchQuery {
                            q,
                            labels,
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
                        Ok(())
                    } else {
                        emit_output(
                            json!({ "messages": items, "next_cursor": page.next_cursor, "has_more": page.has_more }),
                            fields.as_deref(),
                            json_flag,
                        )
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
                        Ok(())
                    } else {
                        emit_output(
                            json!({ "threads": page.threads, "next_cursor": page.next_cursor, "has_more": page.has_more }),
                            fields.as_deref(),
                            json_flag,
                        )
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
                        )
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
                        emit_output(serde_json::to_value(compact)?, fields.as_deref(), json_flag)
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
                } => {
                    let mut req: AiSendEmailRequest = match payload {
                        Some(raw) => serde_json::from_value(read_json_payload(&raw)?)?,
                        None => AiSendEmailRequest {
                            to,
                            cc,
                            bcc,
                            subject,
                            text,
                            html,
                            reply_to_message_id: reply_to,
                            dry_run,
                        },
                    };
                    if dry_run {
                        req.dry_run = true;
                    }
                    let res = ai::execute_send_email(&state, req).await?;
                    emit_output(res, fields.as_deref(), json_flag)
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
                } => {
                    let req: AiCreateDraftRequest = match payload {
                        Some(raw) => serde_json::from_value(read_json_payload(&raw)?)?,
                        None => AiCreateDraftRequest {
                            to,
                            cc,
                            bcc,
                            subject,
                            text,
                            html,
                            reply_to_message_id: reply_to,
                        },
                    };
                    let res = ai::execute_create_draft(&state, req).await?;
                    emit_output(res, fields.as_deref(), json_flag)
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
                    emit_output(res, fields.as_deref(), json_flag)
                }
                MailAction::Labels => {
                    let labels = state.store.list_labels().await?;
                    emit_output(json!({ "labels": labels }), fields.as_deref(), json_flag)
                }
                MailAction::Watch => {
                    let mut rx = state.events.subscribe();
                    while let Ok(env) = rx.recv().await {
                        println!("{}", serde_json::to_string(&env)?);
                    }
                    Ok(())
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
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
