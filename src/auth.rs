//! Pluggable authentication (`AuthProvider`), bearer token middleware,
//! `userId` resolution, and input hardening validators.

use async_trait::async_trait;
use axum::{
    extract::{Request, State},
    http::{HeaderMap, Method, header},
    middleware::Next,
    response::Response,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};

use crate::{
    AppState,
    config::Config,
    error::{AppError, AppResult},
    oauth2::OAuth2Verifier,
};

/// Paths that are always exempt from bearer token authentication.
const AUTH_EXEMPT_PATHS: &[&str] = &[
    "/healthz",
    "/readyz",
    "/webhooks/resend",
    "/webhooks/ses",
    "/oauth2/token",
    "/.well-known/oauth-authorization-server",
];

/// Maximum permitted length for resource identifiers (`message_id`, `thread_id`, `draft_id`, `label_id`).
const MAX_RESOURCE_ID_LEN: usize = 256;

/// Fine-grained authorization scopes attached to an authenticated [`Principal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthScope {
    Read,
    Write,
    Send,
    Admin,
}

impl AuthScope {
    /// Canonical lowercase scope string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Send => "send",
            Self::Admin => "admin",
        }
    }
}

/// Optional per-principal agent safety overrides (e.g. from JWT claims or API key metadata).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPolicyOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub draft_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_recipients: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_send_recipients: Option<usize>,
}

/// Configuration entry for a least-privilege scoped API key parsed from
/// `NOGML_SCOPED_TOKENS` / `--scoped-tokens` / `[[auth.scoped_tokens]]`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedTokenConfig {
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mailbox_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_mailboxes: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<AuthScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_recipients: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_send_recipients: Option<usize>,
}

impl std::fmt::Debug for ScopedTokenConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScopedTokenConfig")
            .field("token", &crate::secrets::REDACTED)
            .field("mailbox_id", &self.mailbox_id)
            .field("shared_mailboxes", &self.shared_mailboxes)
            .field("scopes", &self.scopes)
            .field("draft_only", &self.draft_only)
            .field("allowed_recipients", &self.allowed_recipients)
            .field("max_send_recipients", &self.max_send_recipients)
            .finish()
    }
}

impl ScopedTokenConfig {
    /// Project this token definition into an authenticated [`Principal`].
    pub fn to_principal(&self, default_mailbox: &str) -> Principal {
        let mailbox_id = self
            .mailbox_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(default_mailbox)
            .to_string();

        let primary_norm = crate::config::normalize_mailbox_id(&mailbox_id);
        let mut shared_mailboxes = Vec::new();
        for raw in &self.shared_mailboxes {
            let norm = crate::config::normalize_mailbox_id(raw);
            if !norm.is_empty() && norm != primary_norm && !shared_mailboxes.contains(&norm) {
                shared_mailboxes.push(norm);
            }
        }

        let agent_policy = if self.draft_only.is_some()
            || self.allowed_recipients.is_some()
            || self.max_send_recipients.is_some()
        {
            Some(AgentPolicyOverride {
                draft_only: self.draft_only,
                allowed_recipients: self.allowed_recipients.clone(),
                max_send_recipients: self.max_send_recipients,
            })
        } else {
            None
        };

        Principal {
            mailbox_id,
            shared_mailboxes,
            scopes: self.scopes.clone(),
            agent_policy,
        }
    }
}

/// Authenticated caller identity inserted into HTTP request extensions and IMAP sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub mailbox_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_mailboxes: Vec<String>,
    pub scopes: Vec<AuthScope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_policy: Option<AgentPolicyOverride>,
}

/// Target mailbox resolved for an authenticated HTTP request (either `principal.mailbox_id`
/// or an authorized shared mailbox requested via Gmail `{userId}` or `X-Nogml-Mailbox`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMailbox(pub String);

/// HTTP header selecting a target mailbox for `/v1/*` and `/mcp` requests.
pub const MAILBOX_HEADER: &str = "x-nogml-mailbox";

impl Principal {
    /// Construct a full-access principal for `mailbox_id`.
    pub fn full_access(mailbox_id: impl Into<String>) -> Self {
        Self {
            mailbox_id: mailbox_id.into(),
            shared_mailboxes: Vec::new(),
            scopes: vec![
                AuthScope::Read,
                AuthScope::Write,
                AuthScope::Send,
                AuthScope::Admin,
            ],
            agent_policy: None,
        }
    }

    /// Returns `true` if this principal is authorized to access `target` mailbox
    /// (either `target` equals `self.mailbox_id` or `target` is listed in `self.shared_mailboxes`,
    /// compared case-insensitively).
    pub fn can_access_mailbox(&self, target: &str) -> bool {
        let target_norm = crate::config::normalize_mailbox_id(target);
        if target_norm.is_empty() {
            return false;
        }
        if self.mailbox_id.trim().eq_ignore_ascii_case(&target_norm) {
            return true;
        }
        self.shared_mailboxes
            .iter()
            .any(|mb| mb.trim().eq_ignore_ascii_case(&target_norm))
    }

    pub fn has_scope(&self, scope: AuthScope) -> bool {
        self.scopes.contains(&AuthScope::Admin) || self.scopes.contains(&scope)
    }

    /// Return `Ok(())` if the principal holds `scope` (or `Admin`), otherwise `403 Forbidden`.
    pub fn require_scope(&self, scope: AuthScope) -> AppResult<()> {
        if self.has_scope(scope) {
            Ok(())
        } else {
            Err(AppError::Forbidden(format!(
                "Insufficient scope: '{}' scope required",
                scope.as_str()
            )))
        }
    }
}

/// Pluggable authentication provider for HTTP bearer tokens and IMAP credentials.
///
/// Swap in OAuth2/JWT verification, multi-tenant API key lookups, or OIDC introspection
/// without touching HTTP middleware or IMAP session handlers.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn authenticate_bearer(&self, token: Option<&str>) -> AppResult<Principal>;
    async fn authenticate_imap(&self, username: &str, password: &str) -> AppResult<Principal>;

    /// Authenticate an IMAP `AUTHENTICATE XOAUTH2` exchange (`user=<user>\x01auth=Bearer <token>\x01\x01`).
    ///
    /// Defaults to validating `access_token` via [`Self::authenticate_bearer`] and verifying
    /// `username` is authorized by [`Principal::can_access_mailbox`].
    async fn authenticate_xoauth2(
        &self,
        username: &str,
        access_token: &str,
    ) -> AppResult<Principal> {
        if access_token.trim().is_empty() {
            return Err(AppError::Unauthorized(
                "Missing XOAUTH2 access token".to_string(),
            ));
        }
        let mut principal = self.authenticate_bearer(Some(access_token)).await?;
        if username.eq_ignore_ascii_case(&principal.mailbox_id) {
            return Ok(principal);
        }
        if principal.can_access_mailbox(username) {
            principal.mailbox_id = crate::config::normalize_mailbox_id(username);
            return Ok(principal);
        }
        Err(AppError::Unauthorized(
            "XOAUTH2 username does not match token mailbox".to_string(),
        ))
    }

    fn backend_name(&self) -> &'static str;
}

/// Default [`AuthProvider`] backed by static tokens, scoped API keys, optional local OAuth2
/// HS256 JWTs, and IMAP credentials from [`Config`].
///
/// Preserves constant-time SHA-256 token verification, open dev mode when no tokens or OAuth2
/// settings are configured, and IMAP username/password fallback rules.
#[derive(Clone)]
pub struct StaticTokenAuthProvider {
    mailbox_id: String,
    auth_tokens: Vec<String>,
    scoped_tokens: Vec<ScopedTokenConfig>,
    oauth2: Option<OAuth2Verifier>,
    imap_username: String,
    imap_password: Option<String>,
}

impl std::fmt::Debug for StaticTokenAuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted_tokens: Vec<&str> = self
            .auth_tokens
            .iter()
            .map(|_| crate::secrets::REDACTED)
            .collect();
        f.debug_struct("StaticTokenAuthProvider")
            .field("mailbox_id", &self.mailbox_id)
            .field("auth_tokens", &redacted_tokens)
            .field("scoped_tokens", &self.scoped_tokens)
            .field("oauth2_enabled", &self.oauth2.is_some())
            .field("imap_username", &self.imap_username)
            .field(
                "imap_password",
                &self
                    .imap_password
                    .as_ref()
                    .map(|_| crate::secrets::REDACTED),
            )
            .finish()
    }
}

impl StaticTokenAuthProvider {
    pub fn from_config(config: &Config) -> Self {
        Self {
            mailbox_id: config.user_email.clone(),
            auth_tokens: config.auth_tokens.clone(),
            scoped_tokens: config.scoped_tokens.clone(),
            oauth2: OAuth2Verifier::from_config(config),
            imap_username: config.effective_imap_username().to_string(),
            imap_password: config.effective_imap_password().map(str::to_string),
        }
    }

    fn auth_required(&self) -> bool {
        !self.auth_tokens.is_empty() || !self.scoped_tokens.is_empty() || self.oauth2.is_some()
    }

    /// Compare `candidate` against all configured scoped tokens in constant time.
    fn match_scoped_token(&self, candidate: &str) -> Option<Principal> {
        if candidate.is_empty() || self.scoped_tokens.is_empty() {
            return None;
        }
        let candidate_hash = Sha256::digest(candidate.as_bytes());
        let mut matched_idx: Option<usize> = None;
        for (idx, entry) in self.scoped_tokens.iter().enumerate() {
            if entry.token.is_empty() {
                continue;
            }
            let token_hash = Sha256::digest(entry.token.as_bytes());
            if bool::from(candidate_hash.as_slice().ct_eq(token_hash.as_slice())) {
                matched_idx = Some(idx);
            }
        }
        matched_idx.map(|i| self.scoped_tokens[i].to_principal(&self.mailbox_id))
    }
}

#[async_trait]
impl AuthProvider for StaticTokenAuthProvider {
    async fn authenticate_bearer(&self, token: Option<&str>) -> AppResult<Principal> {
        if !self.auth_required() {
            return Ok(Principal::full_access(&self.mailbox_id));
        }

        if let Some(candidate) = token {
            if constant_time_token_matches(candidate, &self.auth_tokens) {
                return Ok(Principal::full_access(&self.mailbox_id));
            }
            if let Some(principal) = self.match_scoped_token(candidate) {
                return Ok(principal);
            }
            if let Some(ref verifier) = self.oauth2
                && let Ok(principal) = verifier.verify_access_token(candidate)
            {
                return Ok(principal);
            }
        }

        Err(AppError::Unauthorized(
            "Invalid or missing credentials. Provide 'Authorization: Bearer <token>', 'X-API-Key', or '?access_token='."
                .to_string(),
        ))
    }

    async fn authenticate_imap(&self, username: &str, password: &str) -> AppResult<Principal> {
        if let Some(mut principal) = self.match_scoped_token(password) {
            let is_primary_token = principal.mailbox_id.eq_ignore_ascii_case(&self.mailbox_id);
            if username.eq_ignore_ascii_case(&principal.mailbox_id)
                || (is_primary_token && username.eq_ignore_ascii_case(&self.imap_username))
            {
                return Ok(principal);
            }
            if principal.can_access_mailbox(username) {
                principal.mailbox_id = crate::config::normalize_mailbox_id(username);
                return Ok(principal);
            }
            return Err(AppError::Unauthorized(
                "Invalid IMAP credentials".to_string(),
            ));
        }

        if !username.eq_ignore_ascii_case(&self.imap_username) {
            return Err(AppError::Unauthorized(
                "Invalid IMAP credentials".to_string(),
            ));
        }

        let valid = match self.imap_password.as_deref() {
            Some(expected_pass) => {
                let expected_hash = Sha256::digest(expected_pass.as_bytes());
                let candidate_hash = Sha256::digest(password.as_bytes());
                bool::from(expected_hash.as_slice().ct_eq(candidate_hash.as_slice()))
            }
            None => !self.auth_required(),
        };

        if valid {
            Ok(Principal::full_access(&self.mailbox_id))
        } else {
            Err(AppError::Unauthorized(
                "Invalid IMAP credentials".to_string(),
            ))
        }
    }

    async fn authenticate_xoauth2(
        &self,
        username: &str,
        access_token: &str,
    ) -> AppResult<Principal> {
        if access_token.trim().is_empty() {
            return Err(AppError::Unauthorized(
                "Missing XOAUTH2 access token".to_string(),
            ));
        }
        let mut principal = self.authenticate_bearer(Some(access_token)).await?;
        let is_primary_token = principal.mailbox_id.eq_ignore_ascii_case(&self.mailbox_id);
        if username.eq_ignore_ascii_case(&principal.mailbox_id)
            || (is_primary_token && username.eq_ignore_ascii_case(&self.imap_username))
        {
            Ok(principal)
        } else if principal.can_access_mailbox(username) {
            principal.mailbox_id = crate::config::normalize_mailbox_id(username);
            Ok(principal)
        } else {
            Err(AppError::Unauthorized(
                "XOAUTH2 username does not match token mailbox".to_string(),
            ))
        }
    }

    fn backend_name(&self) -> &'static str {
        if self.oauth2.is_some() {
            "oauth2"
        } else {
            "static_token"
        }
    }
}

/// Returns `true` if `path` is exempt from bearer token authentication.
pub fn is_auth_exempt_path(path: &str) -> bool {
    let trimmed = path.trim_end_matches('/');
    let normalized = if trimmed.is_empty() { "/" } else { trimmed };
    AUTH_EXEMPT_PATHS.contains(&normalized)
}

/// Compare `candidate` against every configured token in `allowed` using constant-time SHA-256
/// digest equality so neither token length nor match position leaks via timing.
pub fn constant_time_token_matches(candidate: &str, allowed: &[String]) -> bool {
    if candidate.is_empty() {
        return false;
    }
    let candidate_hash = Sha256::digest(candidate.as_bytes());
    let mut matched = Choice::from(0u8);
    for token in allowed {
        if token.is_empty() {
            continue;
        }
        let token_hash = Sha256::digest(token.as_bytes());
        matched |= candidate_hash.as_slice().ct_eq(token_hash.as_slice());
    }
    bool::from(matched)
}

/// Extract a bearer/API token from:
/// 1. `Authorization: Bearer <token>`
/// 2. `X-API-Key: <token>`
/// 3. `?access_token=<token>`
pub fn extract_request_token(headers: &HeaderMap, query: Option<&str>) -> Option<String> {
    if let Some(auth_val) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        let trimmed = auth_val.trim();
        if trimmed.len() > 7 && trimmed[..7].eq_ignore_ascii_case("bearer ") {
            let token = trimmed[7..].trim();
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }

    if let Some(api_key) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        let token = api_key.trim();
        if !token.is_empty() {
            return Some(token.to_string());
        }
    }

    if let Some(q) = query {
        for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
            if k == "access_token" {
                let token = v.trim();
                if !token.is_empty() {
                    return Some(token.to_string());
                }
            }
        }
    }

    None
}

/// Determine the minimum [`AuthScope`] required for an HTTP `method` + `path`.
///
/// Returns `None` for endpoints that enforce per-operation scopes internally
/// (`/mcp` tools/resources, `/batch/gmail/v1` sub-requests) or CORS preflight (`OPTIONS`).
pub fn required_http_scope(method: &Method, path: &str) -> Option<AuthScope> {
    if method == Method::OPTIONS {
        return None;
    }

    let trimmed = path.trim_end_matches('/');
    let normalized = if trimmed.is_empty() { "/" } else { trimmed };

    if normalized == "/mcp" || normalized == "/batch/gmail/v1" || normalized == "/oauth2/authorize"
    {
        return None;
    }

    // Human-in-the-loop approval queue inspection and decisions require `Admin`
    // so restricted tokens cannot read held DLP-flagged payloads or self-approve.
    if normalized == "/v1/approvals" || normalized.starts_with("/v1/approvals/") {
        return Some(AuthScope::Admin);
    }

    // Suppression mutations and deliverability circuit-breaker overrides require `Admin`
    // because they protect shared sender reputation across all mailboxes.
    if method != Method::GET
        && method != Method::HEAD
        && (normalized == "/v1/suppression"
            || normalized.starts_with("/v1/suppression/")
            || normalized == "/v1/deliverability"
            || normalized.starts_with("/v1/deliverability/"))
    {
        return Some(AuthScope::Admin);
    }

    // `POST /v1/messages/{id}/unsubscribe` enforces `Write` (for `dry_run: true`) or `Send`
    // (for execution) inside the handler after parsing the JSON body.
    if method == Method::POST
        && let Some(rest) = normalized
            .strip_prefix("/v1/messages/")
            .and_then(|s| s.strip_suffix("/unsubscribe"))
        && !rest.is_empty()
        && !rest.contains('/')
    {
        return None;
    }

    if method == Method::GET || method == Method::HEAD {
        return Some(AuthScope::Read);
    }

    // `POST /v1/rules/{id}/test` is a read-only dry-run against recent messages.
    if method == Method::POST
        && let Some(rest) = normalized
            .strip_prefix("/v1/rules/")
            .and_then(|s| s.strip_suffix("/test"))
        && !rest.is_empty()
        && !rest.contains('/')
    {
        return Some(AuthScope::Read);
    }

    // Outbound send endpoints require `Send`.
    if normalized == "/v1/messages/send"
        || (normalized.starts_with("/v1/drafts/") && normalized.ends_with("/send"))
        || ((normalized.starts_with("/gmail/v1/users/")
            || normalized.starts_with("/upload/gmail/v1/users/"))
            && (normalized.ends_with("/messages/send") || normalized.ends_with("/drafts/send")))
    {
        return Some(AuthScope::Send);
    }

    // Account settings mutations require `Admin`.
    if normalized.starts_with("/gmail/v1/users/") && normalized.contains("/settings/") {
        return Some(AuthScope::Admin);
    }

    // All other mutating endpoints (drafts, labels, triage, modify, insert/import,
    // delete, watch/stop, sync) require `Write` (satisfied by `Write` or `Admin`).
    Some(AuthScope::Write)
}

fn is_ai_v1_path(path: &str) -> bool {
    (path == "/v1" || path.starts_with("/v1/"))
        && path != "/v1/people"
        && !path.starts_with("/v1/people/")
}

fn extract_gmail_user_id_from_path(path: &str) -> Option<&str> {
    let rest = path
        .strip_prefix("/gmail/v1/users/")
        .or_else(|| path.strip_prefix("/upload/gmail/v1/users/"))?;
    let seg = rest.split('/').next()?;
    (!seg.is_empty()).then_some(seg)
}

fn percent_decode_path_segment(raw: &str) -> AppResult<String> {
    validate_resource_id(raw)?;
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    let decoded = String::from_utf8(out).map_err(|_| {
        AppError::validation(
            "Path userId is not valid UTF-8",
            Some("Provide a valid UTF-8 email address or 'me'.".to_string()),
        )
    })?;
    validate_resource_id(&decoded)?;
    Ok(decoded)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Extract and validate the optional `X-Nogml-Mailbox` request header.
pub fn extract_mailbox_header(headers: &HeaderMap) -> AppResult<Option<String>> {
    let Some(val) = headers.get(MAILBOX_HEADER) else {
        return Ok(None);
    };
    let raw = val.to_str().map_err(|_| {
        AppError::validation(
            "Invalid X-Nogml-Mailbox header encoding",
            Some("Provide a valid ASCII/UTF-8 mailbox email address.".to_string()),
        )
    })?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    validate_resource_id(trimmed)?;
    Ok(Some(trimmed.to_string()))
}

/// Axum middleware authenticating requests via `state.auth` (`Authorization: Bearer <token>`,
/// `X-API-Key`, or `?access_token=`), enforcing [`required_http_scope`] (`403 Forbidden` on
/// insufficient scope), validating target mailbox access (Gmail `{userId}` and optional
/// `X-Nogml-Mailbox` header against [`Principal::can_access_mailbox`]), and inserting the
/// resolved [`Principal`] and [`ResolvedMailbox`] into request extensions.
///
/// Always exempts `/healthz`, `/readyz`, `/webhooks/resend`, `/webhooks/ses`,
/// `/oauth2/token`, and `/.well-known/oauth-authorization-server`.
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> AppResult<Response> {
    let path = req.uri().path().to_string();
    if is_auth_exempt_path(&path) {
        return Ok(next.run(req).await);
    }

    let token = extract_request_token(req.headers(), req.uri().query());
    let principal = if token.is_none()
        && let Some(existing) = req.extensions().get::<Principal>().cloned()
    {
        existing
    } else {
        match state.auth.authenticate_bearer(token.as_deref()).await {
            Ok(p) => p,
            Err(err) => {
                if is_ai_v1_path(&path) {
                    return Ok(err.into_ai_response());
                }
                return Err(err);
            }
        }
    };

    if let Some(required_scope) = required_http_scope(req.method(), &path)
        && let Err(err) = principal.require_scope(required_scope)
    {
        if is_ai_v1_path(&path) {
            return Ok(err.into_ai_response());
        }
        return Err(err);
    }

    let resolved_mailbox = if let Some(raw_user_id) = extract_gmail_user_id_from_path(&path) {
        let decoded = percent_decode_path_segment(raw_user_id)?;
        let authorized = resolve_user_id_for_principal(&decoded, &principal)?;
        crate::config::normalize_mailbox_id(authorized)
    } else {
        match extract_mailbox_header(req.headers()) {
            Ok(Some(requested)) => {
                if !principal.can_access_mailbox(&requested) {
                    let err =
                        AppError::Forbidden(format!("Access denied for mailbox '{requested}'"));
                    if is_ai_v1_path(&path) {
                        return Ok(err.into_ai_response());
                    }
                    return Err(err);
                }
                crate::config::normalize_mailbox_id(&requested)
            }
            Ok(None) => crate::config::normalize_mailbox_id(&principal.mailbox_id),
            Err(err) => {
                if is_ai_v1_path(&path) {
                    return Ok(err.into_ai_response());
                }
                return Err(err);
            }
        }
    };

    req.extensions_mut()
        .insert(ResolvedMailbox(resolved_mailbox));
    req.extensions_mut().insert(principal);
    Ok(next.run(req).await)
}

/// Reject control chars (`0x00..=0x1f`, `0x7f`), Unicode control chars, `..`, `/`, `\`,
/// percent-encoded traversal/separators (`%2e`, `%2f`, `%5c`, `%00`, `%0a`, `%0d`, `%3f`, `%23`),
/// `?`, and `#` in resource IDs (`message_id`, `thread_id`, `draft_id`, `label_id`).
pub fn validate_resource_id(id: &str) -> AppResult<()> {
    if id.is_empty() || id.trim().is_empty() {
        return Err(AppError::validation(
            "Resource ID must not be empty",
            Some("Provide a non-empty alphanumeric or identifier value.".to_string()),
        ));
    }

    if id.len() > MAX_RESOURCE_ID_LEN {
        return Err(AppError::validation(
            format!("Resource ID exceeds maximum length of {MAX_RESOURCE_ID_LEN} bytes"),
            None,
        ));
    }

    if id.bytes().any(|b| b <= 0x1f || b == 0x7f) || id.chars().any(char::is_control) {
        return Err(AppError::validation(
            "Resource ID contains disallowed control characters",
            None,
        ));
    }

    if id.contains("..")
        || id.contains('/')
        || id.contains('\\')
        || id.contains('?')
        || id.contains('#')
    {
        return Err(AppError::validation(
            "Resource ID contains disallowed path or query characters",
            None,
        ));
    }

    let lower = id.to_ascii_lowercase();
    for forbidden in ["%2e", "%2f", "%5c", "%00", "%0a", "%0d", "%3f", "%23"] {
        if lower.contains(forbidden) {
            return Err(AppError::validation(
                format!("Resource ID contains disallowed encoded sequence '{forbidden}'"),
                None,
            ));
        }
    }

    Ok(())
}

/// Reject CR/LF header injection and control characters in email headers
/// (`subject`, `to`, `cc`, `bcc`, `from`, custom headers).
pub fn validate_email_header(name: &str, value: &str) -> AppResult<()> {
    if name.is_empty() || name.len() > 128 {
        return Err(AppError::validation(
            "Email header name must be between 1 and 128 bytes",
            None,
        ));
    }

    if name.bytes().any(|b| b <= 0x20 || b >= 0x7f || b == b':') {
        return Err(AppError::validation(
            format!("Invalid email header name '{name}'"),
            Some(
                "Header names must consist of visible ASCII characters excluding ':'.".to_string(),
            ),
        ));
    }

    if value.contains('\r') || value.contains('\n') || value.contains('\0') {
        return Err(AppError::validation(
            format!("Header '{name}' contains disallowed CR, LF, or NUL character"),
            Some(
                "Remove newline characters from email headers to prevent header injection."
                    .to_string(),
            ),
        ));
    }

    if value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return Err(AppError::validation(
            format!("Header '{name}' contains disallowed control characters"),
            None,
        ));
    }

    Ok(())
}

/// Resolve Gmail `{userId}` path parameter to the configured mailbox email address.
///
/// Accepts `"me"` or `config.user_email` (case-insensitive). Returns `403 Forbidden` for
/// any other user ID, or `400 Bad Request` if `user_id` fails input hardening checks.
pub fn resolve_user_id<'a>(user_id: &str, config: &'a Config) -> AppResult<&'a str> {
    validate_resource_id(user_id)?;

    if user_id == "me" || user_id.eq_ignore_ascii_case(&config.user_email) {
        Ok(config.user_email.as_str())
    } else {
        Err(AppError::Forbidden(format!(
            "Delegation denied for userId '{user_id}'"
        )))
    }
}

/// Resolve Gmail `{userId}` path parameter against an authenticated [`Principal`]'s
/// `mailbox_id` and `shared_mailboxes`.
///
/// Accepts `"me"`, `principal.mailbox_id`, or any mailbox authorized by
/// [`Principal::can_access_mailbox`] (case-insensitive). Returns `403 Forbidden` for
/// any other user ID, or `400 Bad Request` if `user_id` fails input hardening checks.
pub fn resolve_user_id_for_principal<'a>(
    user_id: &str,
    principal: &'a Principal,
) -> AppResult<&'a str> {
    validate_resource_id(user_id)?;

    if user_id == "me" || user_id.eq_ignore_ascii_case(&principal.mailbox_id) {
        Ok(principal.mailbox_id.as_str())
    } else if let Some(shared) = principal
        .shared_mailboxes
        .iter()
        .find(|mb| mb.trim().eq_ignore_ascii_case(user_id))
    {
        Ok(shared.as_str())
    } else {
        Err(AppError::Forbidden(format!(
            "Delegation denied for userId '{user_id}'"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        models::{
            ResendReceivedAttachment, ResendReceivedEmail, ResendSendEmailRequest,
            ResendSendEmailResponse,
        },
        resend::ResendClient,
        storage::MemoryStore,
    };
    use async_trait::async_trait;
    use axum::{
        Router,
        body::Body,
        http::{Request as HttpRequest, StatusCode},
        middleware,
        routing::get,
    };
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    struct DummyResend;

    #[async_trait]
    impl ResendClient for DummyResend {
        async fn send_email(
            &self,
            _req: &ResendSendEmailRequest,
            _idempotency_key: Option<&str>,
        ) -> AppResult<ResendSendEmailResponse> {
            Ok(ResendSendEmailResponse {
                id: "re_dummy".to_string(),
            })
        }
        async fn get_received_email(&self, _id: &str) -> AppResult<ResendReceivedEmail> {
            Err(AppError::NotFound("not found".into()))
        }
        async fn list_received_attachments(
            &self,
            _id: &str,
        ) -> AppResult<Vec<ResendReceivedAttachment>> {
            Ok(Vec::new())
        }
        async fn download_bytes(&self, _url: &str) -> AppResult<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    fn test_state(tokens: Vec<&str>) -> AppState {
        let mut cfg = Config::for_test();
        cfg.auth_tokens = tokens.into_iter().map(String::from).collect();
        let store = Arc::new(MemoryStore::new(&cfg.user_email));
        AppState::with_backends(cfg, store, Arc::new(DummyResend))
    }

    fn test_router(state: AppState) -> Router {
        Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .route("/readyz", get(|| async { "ready" }))
            .route("/webhooks/resend", get(|| async { "hook" }))
            .route("/webhooks/ses", get(|| async { "ses-hook" }))
            .route("/gmail/v1/users/me/profile", get(|| async { "profile" }))
            .route("/v1/capabilities", get(|| async { "caps" }))
            .layer(middleware::from_fn_with_state(state.clone(), require_auth))
            .with_state(state)
    }

    #[test]
    fn constant_time_matching() {
        let allowed = vec!["secret-one".to_string(), "secret-two-longer".to_string()];
        assert!(constant_time_token_matches("secret-one", &allowed));
        assert!(constant_time_token_matches("secret-two-longer", &allowed));
        assert!(!constant_time_token_matches("secret-on", &allowed));
        assert!(!constant_time_token_matches("", &allowed));
        assert!(!constant_time_token_matches("wrong", &allowed));
    }

    #[test]
    fn validate_resource_id_hardening() {
        assert!(validate_resource_id("msg_123-abc.def").is_ok());
        assert!(validate_resource_id("INBOX").is_ok());
        assert!(validate_resource_id("user@example.com").is_ok());

        for bad in [
            "",
            "   ",
            "../etc/passwd",
            "a/b",
            "a\\b",
            "id?foo=1",
            "id#frag",
            "bad\x00id",
            "bad\nid",
            "bad\rid",
            "bad\x7fid",
            "foo%2ebar",
            "foo%2Fbar",
            "foo%5cbar",
            "foo%00bar",
        ] {
            assert!(
                validate_resource_id(bad).is_err(),
                "expected '{bad}' to be rejected"
            );
        }
    }

    #[test]
    fn validate_email_header_hardening() {
        assert!(validate_email_header("Subject", "Hello World\t(tab ok)").is_ok());
        assert!(validate_email_header("From", "Alice <alice@example.com>").is_ok());
        assert!(validate_email_header("Subject", "Hello\r\nBcc: evil@attacker.com").is_err());
        assert!(validate_email_header("Subject", "Line\nBreak").is_err());
        assert!(validate_email_header("To", "a@b.com\0").is_err());
        assert!(validate_email_header("Bad:Name", "value").is_err());
        assert!(validate_email_header("", "value").is_err());
    }

    #[test]
    fn resolve_user_id_rules() {
        let cfg = Config::for_test();
        assert_eq!(resolve_user_id("me", &cfg).unwrap(), "agent@example.com");
        assert_eq!(
            resolve_user_id("agent@example.com", &cfg).unwrap(),
            "agent@example.com"
        );
        assert_eq!(
            resolve_user_id("AGENT@EXAMPLE.COM", &cfg).unwrap(),
            "agent@example.com"
        );
        assert!(matches!(
            resolve_user_id("other@example.com", &cfg),
            Err(AppError::Forbidden(_))
        ));
        assert!(matches!(
            resolve_user_id("../me", &cfg),
            Err(AppError::Validation { .. })
        ));
    }

    #[tokio::test]
    async fn dev_mode_allows_unauthenticated() {
        let app = test_router(test_state(vec![]));
        let res = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/gmail/v1/users/me/profile")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn bearer_x_api_key_query_and_exempt_paths() {
        let app = test_router(test_state(vec!["tok-123", "tok-456"]));

        // Exempt endpoints bypass auth
        for path in [
            "/healthz",
            "/readyz",
            "/webhooks/resend",
            "/webhooks/ses",
            "/oauth2/token",
            "/.well-known/oauth-authorization-server",
        ] {
            assert!(
                is_auth_exempt_path(path),
                "path {path} should be marked auth-exempt"
            );
        }
        assert!(
            !is_auth_exempt_path("/oauth2/authorize"),
            "/oauth2/authorize must require authentication"
        );
        for path in ["/healthz", "/readyz", "/webhooks/resend", "/webhooks/ses"] {
            let res = app
                .clone()
                .oneshot(
                    HttpRequest::builder()
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK, "path {path} should be exempt");
        }

        // Missing token -> 401 Gmail envelope on /gmail/v1/...
        let res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/gmail/v1/users/me/profile")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["status"], "UNAUTHENTICATED");

        // Missing token -> 401 AI envelope on /v1/...
        let res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/v1/capabilities")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "unauthorized");

        // Authorization: Bearer
        let res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/gmail/v1/users/me/profile")
                    .header("authorization", "Bearer tok-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // X-API-Key
        let res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/gmail/v1/users/me/profile")
                    .header("x-api-key", "tok-456")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // ?access_token=
        let res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/gmail/v1/users/me/profile?access_token=tok-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // Wrong token -> 401
        let res = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/gmail/v1/users/me/profile")
                    .header("authorization", "Bearer wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn required_http_scope_classification() {
        assert_eq!(
            required_http_scope(&Method::GET, "/v1/messages"),
            Some(AuthScope::Read)
        );
        assert_eq!(
            required_http_scope(&Method::GET, "/gmail/v1/users/me/messages"),
            Some(AuthScope::Read)
        );
        assert_eq!(
            required_http_scope(&Method::POST, "/v1/messages/send"),
            Some(AuthScope::Send)
        );
        assert_eq!(
            required_http_scope(&Method::POST, "/v1/drafts/dr_1/send"),
            Some(AuthScope::Send)
        );
        assert_eq!(
            required_http_scope(&Method::POST, "/gmail/v1/users/me/messages/send"),
            Some(AuthScope::Send)
        );
        assert_eq!(
            required_http_scope(&Method::POST, "/upload/gmail/v1/users/me/drafts/send"),
            Some(AuthScope::Send)
        );
        assert_eq!(
            required_http_scope(&Method::POST, "/v1/drafts"),
            Some(AuthScope::Write)
        );
        assert_eq!(
            required_http_scope(&Method::POST, "/gmail/v1/users/me/messages/m1/modify"),
            Some(AuthScope::Write)
        );
        assert_eq!(
            required_http_scope(&Method::PUT, "/gmail/v1/users/me/settings/vacation"),
            Some(AuthScope::Admin)
        );
        assert_eq!(
            required_http_scope(&Method::GET, "/gmail/v1/users/me/settings/vacation"),
            Some(AuthScope::Read)
        );
        assert_eq!(required_http_scope(&Method::POST, "/mcp"), None);
        assert_eq!(required_http_scope(&Method::POST, "/batch/gmail/v1"), None);
        assert_eq!(
            required_http_scope(&Method::POST, "/v1/messages/m1/unsubscribe"),
            None
        );
    }

    #[tokio::test]
    async fn scoped_tokens_and_xoauth2_provider_checks() {
        let mut cfg = Config::for_test();
        cfg.scoped_tokens = vec![ScopedTokenConfig {
            token: "ro-tok".to_string(),
            mailbox_id: None,
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read],
            draft_only: Some(true),
            allowed_recipients: Some(vec!["@example.com".to_string()]),
            max_send_recipients: Some(3),
        }];
        let provider = StaticTokenAuthProvider::from_config(&cfg);

        // Missing token rejected when scoped_tokens is non-empty
        assert!(provider.authenticate_bearer(None).await.is_err());

        // Scoped token resolves Principal + agent_policy
        let p = provider.authenticate_bearer(Some("ro-tok")).await.unwrap();
        assert_eq!(p.mailbox_id, "agent@example.com");
        assert!(p.has_scope(AuthScope::Read));
        assert!(!p.has_scope(AuthScope::Write));
        assert!(!p.has_scope(AuthScope::Send));
        assert_eq!(p.agent_policy.as_ref().unwrap().draft_only, Some(true));
        assert_eq!(
            p.agent_policy.as_ref().unwrap().max_send_recipients,
            Some(3)
        );

        // XOAUTH2 delegates to bearer auth and checks username
        let xp = provider
            .authenticate_xoauth2("agent@example.com", "ro-tok")
            .await
            .unwrap();
        assert_eq!(xp, p);
        assert!(
            provider
                .authenticate_xoauth2("wrong@example.com", "ro-tok")
                .await
                .is_err()
        );
        assert!(
            provider
                .authenticate_xoauth2("agent@example.com", "bad-tok")
                .await
                .is_err()
        );
    }
}
