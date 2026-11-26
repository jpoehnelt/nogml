//! Interactive and scriptable auth setup helpers (`nogml auth`):
//! - `nogml auth mint-token`: generate high-entropy least-privilege scoped tokens
//!   as `[[auth.scoped_tokens]]` TOML or `NOGML_SCOPED_TOKENS` JSON, optionally
//!   storing the raw secret in a mode `0600` file referenced via `file://`.
//! - `nogml auth gmail`: RFC 8252 loopback OAuth2 + RFC 7636 PKCE (`S256`) consent
//!   flow for upstream Gmail sync, saving the `refresh_token` to a mode `0600` file
//!   without ever printing or logging raw token values.

use std::{
    fs,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::{net::TcpListener, sync::oneshot};
use url::Url;
use uuid::Uuid;

use crate::{
    auth::{AuthScope, ScopedTokenConfig},
    error::{AppError, AppResult},
    secrets::{REDACTED, generate_bearer_token, write_secret_file},
};

/// Default Google OAuth2 authorization endpoint.
pub const DEFAULT_GMAIL_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";

/// Default Google OAuth2 token endpoint.
pub const DEFAULT_GMAIL_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// Default Gmail API OAuth2 scope for upstream sync and label/flag updates.
pub const DEFAULT_GMAIL_SCOPE: &str = "https://www.googleapis.com/auth/gmail.modify";

/// Default timeout in seconds while waiting for the loopback OAuth2 callback.
pub const DEFAULT_OAUTH_TIMEOUT_SECS: u64 = 300;

/// RFC 7636 PKCE verifier/challenge pair using the `S256` method.
#[derive(Clone, PartialEq, Eq)]
pub struct PkcePair {
    pub code_verifier: String,
    pub code_challenge: String,
    pub method: &'static str,
}

impl std::fmt::Debug for PkcePair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PkcePair")
            .field("code_verifier", &REDACTED)
            .field("code_challenge", &self.code_challenge)
            .field("method", &self.method)
            .finish()
    }
}

impl PkcePair {
    /// Generate a fresh high-entropy RFC 7636 PKCE `S256` verifier/challenge pair.
    ///
    /// Uses 64 bytes of OS-backed UUIDv4 randomness encoded with URL-safe base64
    /// (86 unreserved characters, within RFC 7636's 43..=128 character range).
    pub fn generate() -> Self {
        let mut bytes = [0u8; 64];
        for chunk in bytes.as_chunks_mut::<16>().0 {
            chunk.copy_from_slice(Uuid::new_v4().as_bytes());
        }
        let code_verifier = URL_SAFE_NO_PAD.encode(bytes);
        let code_challenge = pkce_s256_challenge(&code_verifier);
        Self {
            code_verifier,
            code_challenge,
            method: "S256",
        }
    }
}

/// Compute the RFC 7636 `S256` PKCE challenge (`BASE64URL-NOPAD(SHA256(ASCII(code_verifier)))`).
pub fn pkce_s256_challenge(code_verifier: &str) -> String {
    let digest = Sha256::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Generate a high-entropy random OAuth2 CSRF `state` token (43 URL-safe characters).
pub fn generate_oauth_state() -> String {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Parse a single authorization scope string (`read`, `write`, `send`, or `admin`).
pub fn parse_auth_scope(raw: &str) -> Result<AuthScope, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "read" => Ok(AuthScope::Read),
        "write" => Ok(AuthScope::Write),
        "send" => Ok(AuthScope::Send),
        "admin" => Ok(AuthScope::Admin),
        other => Err(format!(
            "Invalid scope '{other}'. Expected one of: read, write, send, admin"
        )),
    }
}

/// Normalize comma- or whitespace-separated OAuth2 scope strings into a single
/// space-delimited OAuth2 `scope` parameter value.
pub fn normalize_oauth_scopes(raw: &str) -> AppResult<String> {
    let mut scopes: Vec<&str> = Vec::new();
    for part in raw.split(|c: char| c == ',' || c.is_whitespace()) {
        let trimmed = part.trim();
        if !trimmed.is_empty() && !scopes.contains(&trimmed) {
            scopes.push(trimmed);
        }
    }
    if scopes.is_empty() {
        return Err(AppError::validation(
            "At least one OAuth2 scope must be provided",
            Some(format!("For example: --scopes {DEFAULT_GMAIL_SCOPE}")),
        ));
    }
    Ok(scopes.join(" "))
}

/// Options for minting a least-privilege scoped token via `nogml auth mint-token`.
#[derive(Debug, Clone)]
pub struct MintTokenOptions {
    pub mailbox: Option<String>,
    pub scopes: Vec<AuthScope>,
    pub draft_only: Option<bool>,
    pub allowed_recipients: Option<Vec<String>>,
    pub max_send_recipients: Option<usize>,
    pub output_file: Option<PathBuf>,
    pub force: bool,
}

/// Result of minting a scoped token.
#[derive(Debug, Clone)]
pub struct MintedTokenResult {
    /// Entry ready for `[[auth.scoped_tokens]]` or `NOGML_SCOPED_TOKENS`.
    /// When `output_file` was provided, `entry.token` is a `file://<abs_path>` reference.
    pub entry: ScopedTokenConfig,
    /// Canonical path where the raw token was written (mode `0600` on Unix), if any.
    pub saved_to: Option<PathBuf>,
}

/// Generate a high-entropy scoped token and optionally save the raw token to a
/// mode `0600` file, returning a [`ScopedTokenConfig`] that references the file
/// via `file://<abs_path>` (or carries the raw token directly when no file is requested).
pub fn mint_scoped_token(opts: &MintTokenOptions) -> AppResult<MintedTokenResult> {
    let mut scopes = Vec::new();
    for scope in &opts.scopes {
        if !scopes.contains(scope) {
            scopes.push(*scope);
        }
    }
    if scopes.is_empty() {
        return Err(AppError::validation(
            "At least one scope must be specified (read, write, send, or admin)",
            Some("Pass --scopes read,write (or another combination of scopes).".to_string()),
        ));
    }

    if let Some(max_rcpts) = opts.max_send_recipients
        && max_rcpts == 0
    {
        return Err(AppError::validation(
            "max_send_recipients must be greater than 0",
            None,
        ));
    }

    let mailbox_id = opts
        .mailbox
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    let allowed_recipients = opts.allowed_recipients.as_ref().and_then(|list| {
        let cleaned: Vec<String> = list
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
        (!cleaned.is_empty()).then_some(cleaned)
    });

    let raw_token = generate_bearer_token();

    let (token_field, saved_to) = if let Some(ref path) = opts.output_file {
        write_secret_file(path, &raw_token, opts.force)?;
        let abs = resolve_absolute_path(path);
        let uri = format!("file://{}", abs.display());
        (uri, Some(abs))
    } else {
        (raw_token, None)
    };

    let entry = ScopedTokenConfig {
        token: token_field,
        mailbox_id,
        shared_mailboxes: Vec::new(),
        scopes,
        draft_only: opts.draft_only,
        allowed_recipients,
        max_send_recipients: opts.max_send_recipients,
    };

    Ok(MintedTokenResult { entry, saved_to })
}

/// Render a [`ScopedTokenConfig`] as a standalone `[[auth.scoped_tokens]]` TOML array-of-tables
/// entry that can be appended directly to `nogml.toml` without duplicating `[auth]`.
pub fn render_scoped_token_toml(entry: &ScopedTokenConfig) -> String {
    let mut lines = Vec::new();
    lines.push("[[auth.scoped_tokens]]".to_string());
    lines.push(format!("token = {}", toml_string(&entry.token)));
    if let Some(ref mailbox) = entry.mailbox_id {
        lines.push(format!("mailbox_id = {}", toml_string(mailbox)));
    }
    let scope_items: Vec<String> = entry
        .scopes
        .iter()
        .map(|s| toml_string(s.as_str()))
        .collect();
    lines.push(format!("scopes = [{}]", scope_items.join(", ")));
    if let Some(draft_only) = entry.draft_only {
        lines.push(format!("draft_only = {draft_only}"));
    }
    if let Some(ref recipients) = entry.allowed_recipients {
        let items: Vec<String> = recipients.iter().map(|r| toml_string(r)).collect();
        lines.push(format!("allowed_recipients = [{}]", items.join(", ")));
    }
    if let Some(max_rcpts) = entry.max_send_recipients {
        lines.push(format!("max_send_recipients = {max_rcpts}"));
    }
    lines.join("\n")
}

/// Render a [`ScopedTokenConfig`] as a JSON array compatible with `NOGML_SCOPED_TOKENS`
/// and `NOGML_SCOPED_TOKENS_FILE`.
pub fn render_scoped_token_json(entry: &ScopedTokenConfig, pretty: bool) -> AppResult<String> {
    let slice = [entry];
    let rendered = if pretty {
        serde_json::to_string_pretty(&slice)?
    } else {
        serde_json::to_string(&slice)?
    };
    Ok(rendered)
}

fn toml_string(val: &str) -> String {
    toml::Value::String(val.to_string()).to_string()
}

fn resolve_absolute_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(path))
                .unwrap_or_else(|_| path.to_path_buf())
        }
    })
}

/// Options for running the loopback Gmail OAuth2 PKCE consent flow (`nogml auth gmail`).
#[derive(Clone)]
pub struct GmailAuthOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub auth_url: String,
    pub token_url: String,
    pub scopes: String,
    pub listen: SocketAddr,
    pub output_file: PathBuf,
    pub force: bool,
    pub no_browser: bool,
    pub timeout: Duration,
}

impl std::fmt::Debug for GmailAuthOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GmailAuthOptions")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| REDACTED),
            )
            .field("auth_url", &self.auth_url)
            .field("token_url", &self.token_url)
            .field("scopes", &self.scopes)
            .field("listen", &self.listen)
            .field("output_file", &self.output_file)
            .field("force", &self.force)
            .field("no_browser", &self.no_browser)
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// Redacted summary returned after a successful `nogml auth gmail` run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GmailAuthSummary {
    pub ok: bool,
    pub saved_to: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    pub config_snippet: String,
}

/// Build the Google OAuth2 authorization URL with PKCE `S256`, CSRF `state`,
/// `access_type=offline`, and `prompt=consent`.
pub fn build_gmail_auth_url(
    auth_url: &str,
    client_id: &str,
    redirect_uri: &str,
    scopes: &str,
    state: &str,
    pkce: &PkcePair,
) -> AppResult<Url> {
    let mut url = Url::parse(auth_url)
        .map_err(|e| AppError::Config(format!("Invalid --auth-url '{auth_url}': {e}")))?;
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", scopes)
        .append_pair("state", state)
        .append_pair("code_challenge", &pkce.code_challenge)
        .append_pair("code_challenge_method", pkce.method)
        .append_pair("access_type", "offline")
        .append_pair("prompt", "consent");
    Ok(url)
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Clone)]
struct CallbackState {
    expected_state: String,
    tx: Arc<Mutex<Option<oneshot::Sender<AppResult<String>>>>>,
}

fn constant_time_str_eq(a: &str, b: &str) -> bool {
    let a_hash = Sha256::digest(a.as_bytes());
    let b_hash = Sha256::digest(b.as_bytes());
    bool::from(a_hash.as_slice().ct_eq(b_hash.as_slice()))
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

async fn oauth_callback_handler(
    State(cb): State<CallbackState>,
    Query(query): Query<CallbackQuery>,
) -> impl IntoResponse {
    // Reject missing or mismatched CSRF state without terminating the listener.
    let provided_state = query.state.as_deref().unwrap_or_default();
    if provided_state.is_empty() || !constant_time_str_eq(provided_state, &cb.expected_state) {
        return (
            StatusCode::BAD_REQUEST,
            Html(
                "<!doctype html><html><body><h1>Authorization failed</h1>\
                 <p>Invalid or missing OAuth2 state parameter.</p></body></html>"
                    .to_string(),
            ),
        );
    }

    if let Some(err_code) = query.error.filter(|s| !s.trim().is_empty()) {
        let desc = query
            .error_description
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| err_code.clone());
        if let Some(tx) = cb.tx.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = tx.send(Err(AppError::Unauthorized(format!(
                "OAuth2 authorization error ({err_code}): {desc}"
            ))));
        }
        let escaped = escape_html(&desc);
        return (
            StatusCode::BAD_REQUEST,
            Html(format!(
                "<!doctype html><html><body><h1>Authorization denied</h1>\
                 <p>{escaped}</p></body></html>"
            )),
        );
    }

    let Some(code) = query.code.filter(|s| !s.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Html(
                "<!doctype html><html><body><h1>Authorization failed</h1>\
                 <p>Missing OAuth2 authorization code.</p></body></html>"
                    .to_string(),
            ),
        );
    };

    let sender = cb.tx.lock().unwrap_or_else(|e| e.into_inner()).take();
    match sender {
        Some(tx) => {
            let _ = tx.send(Ok(code));
            (
                StatusCode::OK,
                Html(
                    "<!doctype html><html><body><h1>Authorization complete</h1>\
                     <p>You may close this browser tab and return to nogml.</p></body></html>"
                        .to_string(),
                ),
            )
        }
        None => (
            StatusCode::CONFLICT,
            Html(
                "<!doctype html><html><body><h1>Authorization already completed</h1>\
                 <p>You may close this browser tab.</p></body></html>"
                    .to_string(),
            ),
        ),
    }
}

#[derive(Deserialize)]
struct OAuthTokenExchangeResponse {
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct OAuthErrorResponse {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

fn format_oauth_error(status: u16, body: &str) -> AppError {
    if let Ok(parsed) = serde_json::from_str::<OAuthErrorResponse>(body)
        && let Some(err) = parsed.error.filter(|s| !s.trim().is_empty())
    {
        let msg = match parsed.error_description.filter(|s| !s.trim().is_empty()) {
            Some(desc) => format!("OAuth2 token exchange failed ({err}): {desc}"),
            None => format!("OAuth2 token exchange failed ({err})"),
        };
        return AppError::Upstream {
            status,
            message: msg,
        };
    }
    AppError::Upstream {
        status,
        message: format!("OAuth2 token endpoint returned HTTP {status}"),
    }
}

/// Exchange an OAuth2 authorization code and PKCE `code_verifier` at `token_url`.
async fn exchange_authorization_code(
    token_url: &str,
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> AppResult<OAuthTokenExchangeResponse> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| AppError::Internal(format!("Failed to build HTTP client: {e}")))?;

    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("code_verifier", code_verifier),
    ];
    if let Some(secret) = client_secret.map(str::trim).filter(|s| !s.is_empty()) {
        form.push(("client_secret", secret));
    }

    let resp = client.post(token_url).form(&form).send().await?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        return Err(format_oauth_error(status.as_u16(), &body));
    }

    serde_json::from_str::<OAuthTokenExchangeResponse>(&body).map_err(|_| AppError::Upstream {
        status: status.as_u16(),
        message: "OAuth2 token endpoint returned invalid JSON".to_string(),
    })
}

fn try_open_browser(url: &str) -> bool {
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = Command::new("open");
        c.arg(url);
        c
    };

    #[cfg(target_os = "linux")]
    let mut cmd = {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };

    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    };

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = url;
        return false;
    }

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .is_ok()
}

/// Run the full loopback Gmail OAuth2 PKCE consent flow:
/// 1. Validate inputs and check `output_file` overwrite guard up front.
/// 2. Bind an ephemeral loopback callback server at `http://<loopback>:<port>/callback`.
/// 3. Print the authorization URL to stderr (and open the browser unless `--no-browser`).
/// 4. Wait for one valid callback (verifying CSRF `state` in constant time).
/// 5. Exchange `code` + PKCE `code_verifier` at `token_url`.
/// 6. Save `refresh_token` to `output_file` with `0600` permissions and return a redacted summary.
pub async fn run_gmail_oauth_flow(opts: GmailAuthOptions) -> AppResult<GmailAuthSummary> {
    let client_id = opts.client_id.trim().to_string();
    if client_id.is_empty() {
        return Err(AppError::Config(
            "GMAIL_CLIENT_ID / --client-id is required for `nogml auth gmail`".to_string(),
        ));
    }

    if !opts.listen.ip().is_loopback() {
        return Err(AppError::validation(
            format!(
                "OAuth2 callback --listen address '{}' must be a loopback address (e.g. 127.0.0.1:0)",
                opts.listen
            ),
            None,
        ));
    }

    Url::parse(&opts.token_url)
        .map_err(|e| AppError::Config(format!("Invalid --token-url '{}': {e}", opts.token_url)))?;

    let normalized_scopes = normalize_oauth_scopes(&opts.scopes)?;

    if opts.output_file.exists() && !opts.force {
        return Err(AppError::Config(format!(
            "Secret file '{}' already exists; pass --force to overwrite",
            opts.output_file.display()
        )));
    }

    let pkce = PkcePair::generate();
    let state = generate_oauth_state();

    let listener = TcpListener::bind(opts.listen).await.map_err(|e| {
        AppError::Internal(format!(
            "Failed to bind loopback OAuth2 callback listener on {}: {e}",
            opts.listen
        ))
    })?;
    let local_addr = listener.local_addr().map_err(|e| {
        AppError::Internal(format!("Failed to read callback listener address: {e}"))
    })?;
    let redirect_uri = match local_addr {
        SocketAddr::V4(v4) => format!("http://{}:{}/callback", v4.ip(), v4.port()),
        SocketAddr::V6(v6) => format!("http://[{}]:{}/callback", v6.ip(), v6.port()),
    };

    let auth_url = build_gmail_auth_url(
        &opts.auth_url,
        &client_id,
        &redirect_uri,
        &normalized_scopes,
        &state,
        &pkce,
    )?;

    let (code_tx, code_rx) = oneshot::channel::<AppResult<String>>();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let router = Router::new()
        .route("/callback", get(oauth_callback_handler))
        .with_state(CallbackState {
            expected_state: state,
            tx: Arc::new(Mutex::new(Some(code_tx))),
        });

    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "Listening for OAuth2 callback on {redirect_uri}");
        let _ = writeln!(
            stderr,
            "Open the following URL in your browser to authorize Gmail access:"
        );
        let _ = writeln!(stderr, "{auth_url}");
        let _ = stderr.flush();
    }

    if !opts.no_browser {
        let _ = try_open_browser(auth_url.as_str());
    }

    let code_result = tokio::select! {
        res = tokio::time::timeout(opts.timeout, code_rx) => {
            match res {
                Ok(Ok(inner)) => inner,
                Ok(Err(_)) => Err(AppError::Internal("OAuth2 callback channel closed unexpectedly".to_string())),
                Err(_) => Err(AppError::Unauthorized(format!(
                    "Timed out after {}s waiting for OAuth2 callback",
                    opts.timeout.as_secs()
                ))),
            }
        }
        _ = tokio::signal::ctrl_c() => {
            Err(AppError::Unauthorized("OAuth2 authorization cancelled by user".to_string()))
        }
    };

    let _ = shutdown_tx.send(());
    let _ = server_handle.await;

    let code = code_result?;

    let token_resp = exchange_authorization_code(
        &opts.token_url,
        &client_id,
        opts.client_secret.as_deref(),
        &code,
        &redirect_uri,
        &pkce.code_verifier,
    )
    .await?;

    let refresh_token = token_resp
        .refresh_token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Upstream {
            status: 502,
            message: "OAuth2 token endpoint did not return a refresh_token. \
                      Revoke prior app consent in your Google Account or re-run with prompt=consent."
                .to_string(),
        })?;

    write_secret_file(&opts.output_file, refresh_token, opts.force)?;
    let saved_to = resolve_absolute_path(&opts.output_file);
    let uri = format!("file://{}", saved_to.display());
    let config_snippet = format!("gmail_refresh_token = {}", toml_string(&uri));

    Ok(GmailAuthSummary {
        ok: true,
        saved_to,
        token_type: token_resp.token_type,
        scope: token_resp.scope,
        expires_in: token_resp.expires_in,
        config_snippet,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, TomlConfig, render_starter_toml, validate_config};

    #[test]
    fn pkce_s256_matches_rfc7636_appendix_b_vector() {
        // RFC 7636 Appendix B official test vector:
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(pkce_s256_challenge(verifier), expected_challenge);
    }

    #[test]
    fn pkce_generate_and_state_have_high_entropy_and_valid_charset() {
        let a = PkcePair::generate();
        let b = PkcePair::generate();
        assert_eq!(a.method, "S256");
        assert_ne!(a.code_verifier, b.code_verifier);
        assert_ne!(a.code_challenge, b.code_challenge);
        assert!((43..=128).contains(&a.code_verifier.len()));
        assert_eq!(pkce_s256_challenge(&a.code_verifier), a.code_challenge);
        assert!(
            a.code_verifier
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
        // Debug representation must redact code_verifier.
        let dbg = format!("{a:?}");
        assert!(!dbg.contains(&a.code_verifier));
        assert!(dbg.contains(REDACTED));

        let s1 = generate_oauth_state();
        let s2 = generate_oauth_state();
        assert_ne!(s1, s2);
        assert_eq!(s1.len(), 43);
    }

    #[test]
    fn mint_scoped_token_entropy_and_toml_roundtrip_with_file_ref() {
        let dir = tempfile::tempdir().unwrap();
        let token_path = dir.path().join("agent_ro.token");

        let res = mint_scoped_token(&MintTokenOptions {
            mailbox: Some("agent@example.com".to_string()),
            scopes: vec![AuthScope::Read, AuthScope::Write, AuthScope::Read],
            draft_only: Some(true),
            allowed_recipients: Some(vec!["@example.com".to_string(), "bob@acme.org".to_string()]),
            max_send_recipients: Some(5),
            output_file: Some(token_path.clone()),
            force: false,
        })
        .unwrap();

        let saved_raw = fs::read_to_string(&token_path).unwrap();
        let trimmed = saved_raw.trim();
        assert!(trimmed.starts_with("nogml_"));
        assert_eq!(trimmed.len(), "nogml_".len() + 64);
        assert!(
            trimmed["nogml_".len()..]
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        );

        assert!(res.entry.token.starts_with("file://"));
        assert!(!res.entry.token.contains(trimmed));
        assert_eq!(res.entry.scopes, vec![AuthScope::Read, AuthScope::Write]);

        let snippet = render_scoped_token_toml(&res.entry);
        assert!(snippet.starts_with("[[auth.scoped_tokens]]"));
        assert!(!snippet.contains(trimmed));

        // Append snippet to starter nogml.toml and validate through TomlConfig + validate_config.
        let full_toml = format!(
            "{}\n\n{snippet}\n",
            render_starter_toml("agent@example.com", "example.com", None)
        );
        let parsed = TomlConfig::from_toml_str(&full_toml).unwrap();
        let mut cfg = Config::default();
        parsed.apply_to(&mut cfg);
        let resolution = cfg.resolve_secrets(Some(dir.path()));
        let report = validate_config(&cfg, None, resolution);
        assert!(report.ok, "errors: {:?}", report.errors);
        assert_eq!(cfg.scoped_tokens.len(), 1);
        assert_eq!(cfg.scoped_tokens[0].token, trimmed);
        assert_eq!(
            cfg.scoped_tokens[0].mailbox_id.as_deref(),
            Some("agent@example.com")
        );
        assert_eq!(cfg.scoped_tokens[0].draft_only, Some(true));
        assert_eq!(
            cfg.scoped_tokens[0].allowed_recipients,
            Some(vec!["@example.com".to_string(), "bob@acme.org".to_string()])
        );
        assert_eq!(cfg.scoped_tokens[0].max_send_recipients, Some(5));
    }

    #[test]
    fn mint_scoped_token_json_roundtrips_for_env_var() {
        let res = mint_scoped_token(&MintTokenOptions {
            mailbox: Some("triage@example.com".to_string()),
            scopes: vec![AuthScope::Read],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
            output_file: None,
            force: false,
        })
        .unwrap();

        assert!(res.entry.token.starts_with("nogml_"));
        assert_eq!(res.entry.token.len(), "nogml_".len() + 64);

        let json_str = render_scoped_token_json(&res.entry, false).unwrap();
        let parsed: Vec<ScopedTokenConfig> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], res.entry);

        let mut cfg = Config::for_test();
        cfg.scoped_tokens = parsed;
        let report = validate_config(&cfg, None, Default::default());
        assert!(report.ok, "errors: {:?}", report.errors);
    }

    #[test]
    fn build_gmail_auth_url_contains_pkce_offline_consent_params() {
        let pkce = PkcePair::generate();
        let url = build_gmail_auth_url(
            DEFAULT_GMAIL_AUTH_URL,
            "my-client.apps.googleusercontent.com",
            "http://127.0.0.1:43210/callback",
            DEFAULT_GMAIL_SCOPE,
            "csrf-state-123",
            &pkce,
        )
        .unwrap();

        let pairs: std::collections::HashMap<String, String> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(
            pairs.get("client_id").map(String::as_str),
            Some("my-client.apps.googleusercontent.com")
        );
        assert_eq!(
            pairs.get("redirect_uri").map(String::as_str),
            Some("http://127.0.0.1:43210/callback")
        );
        assert_eq!(pairs.get("response_type").map(String::as_str), Some("code"));
        assert_eq!(
            pairs.get("scope").map(String::as_str),
            Some(DEFAULT_GMAIL_SCOPE)
        );
        assert_eq!(
            pairs.get("state").map(String::as_str),
            Some("csrf-state-123")
        );
        assert_eq!(
            pairs.get("code_challenge").map(String::as_str),
            Some(pkce.code_challenge.as_str())
        );
        assert_eq!(
            pairs.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert_eq!(
            pairs.get("access_type").map(String::as_str),
            Some("offline")
        );
        assert_eq!(pairs.get("prompt").map(String::as_str), Some("consent"));
        assert!(!url.as_str().contains(&pkce.code_verifier));
    }

    #[tokio::test]
    async fn run_gmail_oauth_flow_rejects_non_loopback_listen_address() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_gmail_oauth_flow(GmailAuthOptions {
            client_id: "cid".to_string(),
            client_secret: None,
            auth_url: DEFAULT_GMAIL_AUTH_URL.to_string(),
            token_url: DEFAULT_GMAIL_TOKEN_URL.to_string(),
            scopes: DEFAULT_GMAIL_SCOPE.to_string(),
            listen: "0.0.0.0:0".parse().unwrap(),
            output_file: dir.path().join("refresh_token"),
            force: false,
            no_browser: true,
            timeout: Duration::from_secs(5),
        })
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Validation { .. }));
    }
}
