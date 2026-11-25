//! Optional local OAuth2 authorization/token server and pure-Rust HS256 JWT
//! signing and verification.
//!
//! Enables Gmail API clients (official Google SDKs, Superhuman-style clients)
//! and IMAP `AUTHENTICATE XOAUTH2` clients to complete standard OAuth2 flows
//! (`authorization_code`, `refresh_token`, `client_credentials`) against `nogml`
//! without an external identity provider.

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
    AppState,
    auth::{AgentPolicyOverride, AuthScope, Principal},
    config::Config,
    error::{AppError, AppResult},
};

type HmacSha256 = Hmac<Sha256>;

/// Default lifetime for issued OAuth2 `access_token` JWTs (1 hour).
pub const DEFAULT_ACCESS_TOKEN_TTL_SECS: i64 = 3_600;

/// Default lifetime for issued OAuth2 `refresh_token` JWTs (30 days).
pub const DEFAULT_REFRESH_TOKEN_TTL_SECS: i64 = 30 * 24 * 3_600;

/// Default lifetime for short-lived `authorization_code` JWTs (5 minutes).
pub const DEFAULT_AUTH_CODE_TTL_SECS: i64 = 300;

const TOKEN_TYPE_ACCESS: &str = "access";
const TOKEN_TYPE_REFRESH: &str = "refresh";
const TOKEN_TYPE_AUTH_CODE: &str = "auth_code";

/// Claims embedded in `nogml`-issued HS256 JWT tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuth2Claims {
    /// Subject (mailbox email address).
    pub sub: String,
    /// Issuer identifier (`"nogml"`).
    pub iss: String,
    /// Audience (`oauth2_client_id`).
    pub aud: String,
    /// Token kind: `"access"`, `"refresh"`, or `"auth_code"`.
    pub typ: String,
    /// Issued-at Unix timestamp in seconds.
    pub iat: i64,
    /// Expiration Unix timestamp in seconds.
    pub exp: i64,
    /// Unique JWT identifier.
    pub jti: String,
    /// Granted authorization scopes.
    pub scopes: Vec<AuthScope>,
    /// Optional OAuth2 space-delimited scope string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Redirect URI bound to an authorization code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    /// Optional PKCE challenge bound to an authorization code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<String>,
    /// Optional PKCE challenge method (`"S256"` or `"plain"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge_method: Option<String>,
    /// Optional per-token outbound agent safety overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_policy: Option<AgentPolicyOverride>,
}

/// Runtime HS256 JWT verifier derived from [`Config`] for [`crate::auth::StaticTokenAuthProvider`].
#[derive(Debug, Clone)]
pub struct OAuth2Verifier {
    client_id: String,
    signing_secret: String,
}

impl OAuth2Verifier {
    pub fn from_config(config: &Config) -> Option<Self> {
        if !config.oauth2_enabled() {
            return None;
        }
        Some(Self {
            client_id: config.oauth2_client_id.clone()?.trim().to_string(),
            signing_secret: config.oauth2_signing_secret.clone()?,
        })
    }

    /// Verify a Bearer `access_token` JWT and project its claims into a [`Principal`].
    pub fn verify_access_token(&self, token: &str) -> AppResult<Principal> {
        let claims = verify_jwt(token, &self.signing_secret, TOKEN_TYPE_ACCESS)?;
        if !constant_time_str_eq(&claims.aud, &self.client_id) {
            return Err(AppError::Unauthorized(
                "OAuth2 token audience mismatch".to_string(),
            ));
        }
        Ok(Principal {
            mailbox_id: claims.sub,
            scopes: claims.scopes,
            agent_policy: claims.agent_policy,
        })
    }
}

/// Sign `claims` into a compact `HS256` JWT (`header.payload.signature`).
pub fn sign_jwt(claims: &OAuth2Claims, secret: &str) -> AppResult<String> {
    if secret.is_empty() {
        return Err(AppError::Config(
            "OAuth2 signing secret must not be empty".to_string(),
        ));
    }
    let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload_json = serde_json::to_vec(claims)?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);
    let signing_input = format!("{header_b64}.{payload_b64}");

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| AppError::Internal(format!("HMAC key error: {e}")))?;
    mac.update(signing_input.as_bytes());
    let signature = mac.finalize().into_bytes();
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature);

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Verify an `HS256` JWT's algorithm header, HMAC-SHA256 signature (constant-time),
/// token type (`expected_typ`), and expiration timestamp.
pub fn verify_jwt(token: &str, secret: &str, expected_typ: &str) -> AppResult<OAuth2Claims> {
    if secret.is_empty() {
        return Err(AppError::Unauthorized(
            "OAuth2 verification is not configured".to_string(),
        ));
    }

    let mut parts = token.split('.');
    let Some(header_b64) = parts.next() else {
        return Err(AppError::Unauthorized("Malformed JWT".to_string()));
    };
    let Some(payload_b64) = parts.next() else {
        return Err(AppError::Unauthorized("Malformed JWT".to_string()));
    };
    let Some(sig_b64) = parts.next() else {
        return Err(AppError::Unauthorized("Malformed JWT".to_string()));
    };
    if parts.next().is_some() {
        return Err(AppError::Unauthorized("Malformed JWT".to_string()));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64.as_bytes())
        .map_err(|_| AppError::Unauthorized("Invalid JWT header encoding".to_string()))?;
    let header_val: Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| AppError::Unauthorized("Invalid JWT header JSON".to_string()))?;
    if header_val.get("alg").and_then(Value::as_str) != Some("HS256") {
        return Err(AppError::Unauthorized(
            "Unsupported JWT algorithm; expected HS256".to_string(),
        ));
    }

    let provided_sig = URL_SAFE_NO_PAD
        .decode(sig_b64.as_bytes())
        .map_err(|_| AppError::Unauthorized("Invalid JWT signature encoding".to_string()))?;

    let signing_input = format!("{header_b64}.{payload_b64}");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| AppError::Internal(format!("HMAC key error: {e}")))?;
    mac.update(signing_input.as_bytes());
    let expected_sig = mac.finalize().into_bytes();

    if provided_sig.len() != expected_sig.len()
        || !bool::from(provided_sig.as_slice().ct_eq(expected_sig.as_slice()))
    {
        return Err(AppError::Unauthorized("Invalid JWT signature".to_string()));
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64.as_bytes())
        .map_err(|_| AppError::Unauthorized("Invalid JWT payload encoding".to_string()))?;
    let claims: OAuth2Claims = serde_json::from_slice(&payload_bytes)
        .map_err(|_| AppError::Unauthorized("Invalid JWT claims payload".to_string()))?;

    if claims.typ != expected_typ {
        return Err(AppError::Unauthorized(format!(
            "Unexpected JWT token type '{}'",
            claims.typ
        )));
    }

    let now = Utc::now().timestamp();
    if claims.exp <= now {
        return Err(AppError::Unauthorized("JWT token has expired".to_string()));
    }

    Ok(claims)
}

/// Mint a signed OAuth2 `access_token` JWT for `config.user_email`.
pub fn mint_access_token(
    config: &Config,
    scopes: Vec<AuthScope>,
    scope_str: Option<String>,
    agent_policy: Option<AgentPolicyOverride>,
    ttl_secs: i64,
) -> AppResult<String> {
    mint_access_token_for_mailbox(
        config,
        &config.user_email,
        scopes,
        scope_str,
        agent_policy,
        ttl_secs,
    )
}

/// Mint a signed OAuth2 `access_token` JWT for an explicit `mailbox_id`.
pub fn mint_access_token_for_mailbox(
    config: &Config,
    mailbox_id: &str,
    scopes: Vec<AuthScope>,
    scope_str: Option<String>,
    agent_policy: Option<AgentPolicyOverride>,
    ttl_secs: i64,
) -> AppResult<String> {
    let client_id = config
        .oauth2_client_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Config("NOGML_OAUTH2_CLIENT_ID is not set".to_string()))?;
    let secret = config
        .oauth2_signing_secret
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Config("NOGML_OAUTH2_SIGNING_SECRET is not set".to_string()))?;

    let now = Utc::now().timestamp();
    let claims = OAuth2Claims {
        sub: mailbox_id.to_string(),
        iss: "nogml".to_string(),
        aud: client_id.to_string(),
        typ: TOKEN_TYPE_ACCESS.to_string(),
        iat: now,
        exp: now + ttl_secs.max(1),
        jti: Uuid::new_v4().to_string(),
        scope: scope_str.or_else(|| Some(format_oauth2_scopes(&scopes))),
        scopes,
        redirect_uri: None,
        code_challenge: None,
        code_challenge_method: None,
        agent_policy,
    };
    sign_jwt(&claims, secret)
}

/// Mint a signed OAuth2 `refresh_token` JWT for `config.user_email`.
pub fn mint_refresh_token(
    config: &Config,
    scopes: Vec<AuthScope>,
    scope_str: Option<String>,
    agent_policy: Option<AgentPolicyOverride>,
) -> AppResult<String> {
    mint_refresh_token_for_mailbox(config, &config.user_email, scopes, scope_str, agent_policy)
}

/// Mint a signed OAuth2 `refresh_token` JWT for an explicit `mailbox_id`.
pub fn mint_refresh_token_for_mailbox(
    config: &Config,
    mailbox_id: &str,
    scopes: Vec<AuthScope>,
    scope_str: Option<String>,
    agent_policy: Option<AgentPolicyOverride>,
) -> AppResult<String> {
    let client_id = config
        .oauth2_client_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Config("NOGML_OAUTH2_CLIENT_ID is not set".to_string()))?;
    let secret = config
        .oauth2_signing_secret
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Config("NOGML_OAUTH2_SIGNING_SECRET is not set".to_string()))?;

    let now = Utc::now().timestamp();
    let claims = OAuth2Claims {
        sub: mailbox_id.to_string(),
        iss: "nogml".to_string(),
        aud: client_id.to_string(),
        typ: TOKEN_TYPE_REFRESH.to_string(),
        iat: now,
        exp: now + DEFAULT_REFRESH_TOKEN_TTL_SECS,
        jti: Uuid::new_v4().to_string(),
        scope: scope_str.or_else(|| Some(format_oauth2_scopes(&scopes))),
        scopes,
        redirect_uri: None,
        code_challenge: None,
        code_challenge_method: None,
        agent_policy,
    };
    sign_jwt(&claims, secret)
}

fn mint_auth_code(
    config: &Config,
    mailbox_id: &str,
    scopes: Vec<AuthScope>,
    scope_str: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
) -> AppResult<String> {
    let client_id = config
        .oauth2_client_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Config("NOGML_OAUTH2_CLIENT_ID is not set".to_string()))?;
    let secret = config
        .oauth2_signing_secret
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Config("NOGML_OAUTH2_SIGNING_SECRET is not set".to_string()))?;

    let now = Utc::now().timestamp();
    let claims = OAuth2Claims {
        sub: mailbox_id.to_string(),
        iss: "nogml".to_string(),
        aud: client_id.to_string(),
        typ: TOKEN_TYPE_AUTH_CODE.to_string(),
        iat: now,
        exp: now + DEFAULT_AUTH_CODE_TTL_SECS,
        jti: Uuid::new_v4().to_string(),
        scope: scope_str.or_else(|| Some(format_oauth2_scopes(&scopes))),
        scopes,
        redirect_uri,
        code_challenge,
        code_challenge_method,
        agent_policy: None,
    };
    sign_jwt(&claims, secret)
}

fn resolve_oauth2_mailbox(config: &Config, requested: Option<&str>) -> Result<String, String> {
    let Some(raw) = requested.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(config.user_email.clone());
    };
    let norm = crate::config::normalize_mailbox_id(raw);
    if config.known_mailboxes().iter().any(|m| m == &norm) {
        Ok(norm)
    } else {
        Err(format!("Unknown mailbox '{raw}'"))
    }
}

/// Map a space-delimited OAuth2 `scope` string (supporting both `nogml` short scopes
/// and Google Gmail OAuth2 scope URLs) to [`AuthScope`] values.
///
/// When `raw` is `None` or blank, defaults to full mailbox scopes.
pub fn parse_oauth2_scopes(raw: Option<&str>) -> Result<Vec<AuthScope>, String> {
    let Some(text) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(vec![
            AuthScope::Read,
            AuthScope::Write,
            AuthScope::Send,
            AuthScope::Admin,
        ]);
    };

    let mut scopes = Vec::new();
    let mut push_unique = |s: AuthScope| {
        if !scopes.contains(&s) {
            scopes.push(s);
        }
    };

    for token in text.split_whitespace() {
        match token.to_ascii_lowercase().as_str() {
            "read"
            | "https://www.googleapis.com/auth/gmail.readonly"
            | "https://www.googleapis.com/auth/gmail.metadata" => {
                push_unique(AuthScope::Read);
            }
            "write" | "https://www.googleapis.com/auth/gmail.insert" => {
                push_unique(AuthScope::Write);
            }
            "https://www.googleapis.com/auth/gmail.modify"
            | "https://www.googleapis.com/auth/gmail.labels" => {
                push_unique(AuthScope::Read);
                push_unique(AuthScope::Write);
            }
            "https://www.googleapis.com/auth/gmail.compose" => {
                push_unique(AuthScope::Read);
                push_unique(AuthScope::Write);
                push_unique(AuthScope::Send);
            }
            "send" | "https://www.googleapis.com/auth/gmail.send" => {
                push_unique(AuthScope::Send);
            }
            "admin"
            | "https://mail.google.com/"
            | "https://mail.google.com"
            | "https://www.googleapis.com/auth/gmail.settings.basic"
            | "https://www.googleapis.com/auth/gmail.settings.sharing" => {
                push_unique(AuthScope::Read);
                push_unique(AuthScope::Write);
                push_unique(AuthScope::Send);
                push_unique(AuthScope::Admin);
            }
            "openid" | "email" | "profile" | "offline_access" => {}
            other => {
                return Err(format!("Unsupported OAuth2 scope '{other}'"));
            }
        }
    }

    drop(push_unique);
    if scopes.is_empty() {
        scopes.push(AuthScope::Read);
    }

    Ok(scopes)
}

/// Format [`AuthScope`] list into a canonical space-delimited OAuth2 `scope` string.
pub fn format_oauth2_scopes(scopes: &[AuthScope]) -> String {
    scopes
        .iter()
        .map(AuthScope::as_str)
        .collect::<Vec<_>>()
        .join(" ")
}

fn constant_time_str_eq(a: &str, b: &str) -> bool {
    let ha = Sha256::digest(a.as_bytes());
    let hb = Sha256::digest(b.as_bytes());
    bool::from(ha.as_slice().ct_eq(hb.as_slice()))
}

fn oauth2_error(status: StatusCode, code: &str, description: impl Into<String>) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    (
        status,
        headers,
        Json(json!({
            "error": code,
            "error_description": description.into(),
        })),
    )
        .into_response()
}

fn oauth2_disabled_response() -> Response {
    oauth2_error(
        StatusCode::NOT_FOUND,
        "oauth2_disabled",
        "Local OAuth2 provider is not enabled. Set NOGML_OAUTH2_CLIENT_ID and NOGML_OAUTH2_SIGNING_SECRET.",
    )
}

fn derive_origin(headers: &HeaderMap, config: &Config) -> String {
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(str::trim)
        .filter(|s| matches!(*s, "http" | "https"))
        .unwrap_or("http");

    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| config.bind.to_string());

    format!("{proto}://{host}")
}

/// Mount the local OAuth2 discovery, authorization, and token endpoints:
/// - `GET /.well-known/oauth-authorization-server`
/// - `GET /oauth2/authorize`
/// - `POST /oauth2/token`
pub fn oauth2_router() -> Router<AppState> {
    Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(well_known_metadata),
        )
        .route("/oauth2/authorize", get(authorize_handler))
        .route("/oauth2/token", post(token_handler))
}

async fn well_known_metadata(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !state.config.oauth2_enabled() {
        return oauth2_disabled_response();
    }

    let origin = derive_origin(&headers, &state.config);
    (
        StatusCode::OK,
        Json(json!({
            "issuer": origin,
            "authorization_endpoint": format!("{origin}/oauth2/authorize"),
            "token_endpoint": format!("{origin}/oauth2/token"),
            "response_types_supported": ["code"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "client_credentials"
            ],
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
                "none"
            ],
            "scopes_supported": [
                "read",
                "write",
                "send",
                "admin",
                "https://mail.google.com/",
                "https://www.googleapis.com/auth/gmail.readonly",
                "https://www.googleapis.com/auth/gmail.modify",
                "https://www.googleapis.com/auth/gmail.compose",
                "https://www.googleapis.com/auth/gmail.send"
            ],
            "code_challenge_methods_supported": ["S256", "plain"],
        })),
    )
        .into_response()
}

#[derive(Debug, Default, Deserialize)]
struct AuthorizeParams {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    login_hint: Option<String>,
}

async fn authorize_handler(
    State(state): State<AppState>,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    if !state.config.oauth2_enabled() {
        return oauth2_disabled_response();
    }

    if params.response_type.as_deref() != Some("code") {
        return oauth2_error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "Only response_type=code is supported",
        );
    }

    let expected_client_id = state
        .config
        .oauth2_client_id
        .as_deref()
        .map(str::trim)
        .unwrap_or("");
    let Some(client_id) = params
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return oauth2_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Missing required client_id parameter",
        );
    };
    if !constant_time_str_eq(client_id, expected_client_id) {
        return oauth2_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "Unknown client_id",
        );
    }

    let scopes = match parse_oauth2_scopes(params.scope.as_deref()) {
        Ok(s) => s,
        Err(msg) => return oauth2_error(StatusCode::BAD_REQUEST, "invalid_scope", msg),
    };

    if let Some(ref method) = params.code_challenge_method
        && !matches!(method.as_str(), "S256" | "plain")
    {
        return oauth2_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Unsupported code_challenge_method; expected S256 or plain",
        );
    }

    let parsed_redirect = if let Some(ref raw_uri) = params.redirect_uri {
        if raw_uri.contains('\r') || raw_uri.contains('\n') {
            return oauth2_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid redirect_uri",
            );
        }
        match url::Url::parse(raw_uri) {
            Ok(parsed) => Some(parsed),
            Err(_) => {
                return oauth2_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "redirect_uri must be a valid absolute URI",
                );
            }
        }
    } else {
        None
    };

    let target_mailbox = match resolve_oauth2_mailbox(&state.config, params.login_hint.as_deref()) {
        Ok(mb) => mb,
        Err(msg) => return oauth2_error(StatusCode::BAD_REQUEST, "invalid_request", msg),
    };

    let code = match mint_auth_code(
        &state.config,
        &target_mailbox,
        scopes.clone(),
        params.scope.clone(),
        params.redirect_uri.clone(),
        params.code_challenge.clone(),
        params.code_challenge_method.clone(),
    ) {
        Ok(c) => c,
        Err(err) => {
            return oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                err.to_string(),
            );
        }
    };

    if let Some(mut target) = parsed_redirect {
        {
            let mut pairs = target.query_pairs_mut();
            pairs.append_pair("code", &code);
            if let Some(ref st) = params.state {
                pairs.append_pair("state", st);
            }
        }
        let Ok(loc) = HeaderValue::from_str(target.as_str()) else {
            return oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to build redirect Location header",
            );
        };
        let mut headers = HeaderMap::new();
        headers.insert(header::LOCATION, loc);
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return (StatusCode::FOUND, headers).into_response();
    }

    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    (
        StatusCode::OK,
        headers,
        Json(json!({
            "code": code,
            "state": params.state,
            "scope": format_oauth2_scopes(&scopes),
            "expires_in": DEFAULT_AUTH_CODE_TTL_SECS,
        })),
    )
        .into_response()
}

#[derive(Debug, Default, Deserialize)]
struct TokenRequest {
    grant_type: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    scope: Option<String>,
    mailbox: Option<String>,
}

fn parse_basic_client_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    if raw.len() <= 6 || !raw[..6].eq_ignore_ascii_case("basic ") {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw[6..].trim().as_bytes())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (id, secret) = text.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

fn parse_token_request(headers: &HeaderMap, body: &[u8]) -> Result<TokenRequest, String> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    if content_type.contains("application/json")
        || body
            .iter()
            .find(|b| !b.is_ascii_whitespace())
            .is_some_and(|&b| b == b'{')
    {
        serde_json::from_slice(body).map_err(|e| format!("Invalid JSON token request: {e}"))
    } else {
        let mut req = TokenRequest::default();
        for (k, v) in url::form_urlencoded::parse(body) {
            let val = v.into_owned();
            match k.as_ref() {
                "grant_type" => req.grant_type = Some(val),
                "client_id" => req.client_id = Some(val),
                "client_secret" => req.client_secret = Some(val),
                "code" => req.code = Some(val),
                "redirect_uri" => req.redirect_uri = Some(val),
                "code_verifier" => req.code_verifier = Some(val),
                "refresh_token" => req.refresh_token = Some(val),
                "scope" => req.scope = Some(val),
                "mailbox" => req.mailbox = Some(val),
                _ => {}
            }
        }
        Ok(req)
    }
}

fn verify_pkce(verifier: &str, challenge: &str, method: &str) -> bool {
    match method {
        "S256" => {
            let digest = Sha256::digest(verifier.as_bytes());
            let computed = URL_SAFE_NO_PAD.encode(digest);
            constant_time_str_eq(&computed, challenge)
        }
        "plain" => constant_time_str_eq(verifier, challenge),
        _ => false,
    }
}

async fn token_handler(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if !state.config.oauth2_enabled() {
        return oauth2_disabled_response();
    }

    let req = match parse_token_request(&headers, &body) {
        Ok(r) => r,
        Err(msg) => return oauth2_error(StatusCode::BAD_REQUEST, "invalid_request", msg),
    };

    let basic = parse_basic_client_auth(&headers);
    let client_id = req
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| basic.as_ref().map(|(id, _)| id.as_str()));
    let client_secret = req
        .client_secret
        .as_deref()
        .filter(|s| !s.is_empty())
        .or_else(|| basic.as_ref().map(|(_, sec)| sec.as_str()));

    let expected_client_id = state
        .config
        .oauth2_client_id
        .as_deref()
        .map(str::trim)
        .unwrap_or("");
    let Some(provided_client_id) = client_id else {
        return oauth2_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Missing client_id",
        );
    };
    if !constant_time_str_eq(provided_client_id, expected_client_id) {
        return oauth2_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Invalid client_id",
        );
    }

    if let Some(expected_secret) = state
        .config
        .oauth2_client_secret
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        let Some(provided_secret) = client_secret else {
            return oauth2_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Missing client_secret",
            );
        };
        if !constant_time_str_eq(provided_secret, expected_secret) {
            return oauth2_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Invalid client_secret",
            );
        }
    }

    let signing_secret = state
        .config
        .oauth2_signing_secret
        .as_deref()
        .unwrap_or_default();

    let Some(grant_type) = req.grant_type.as_deref() else {
        return oauth2_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Missing required grant_type parameter",
        );
    };

    let (subject_mailbox, scopes, scope_str, agent_policy) = match grant_type {
        "authorization_code" => {
            let Some(code) = req.code.as_deref().filter(|s| !s.is_empty()) else {
                return oauth2_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Missing required code parameter",
                );
            };
            let claims = match verify_jwt(code, signing_secret, TOKEN_TYPE_AUTH_CODE) {
                Ok(c) => c,
                Err(_) => {
                    return oauth2_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "Authorization code is invalid or expired",
                    );
                }
            };
            if !constant_time_str_eq(&claims.aud, expected_client_id) {
                return oauth2_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "Authorization code was not issued for this client",
                );
            }
            if let Some(ref bound_uri) = claims.redirect_uri
                && req.redirect_uri.as_deref() != Some(bound_uri.as_str())
            {
                return oauth2_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "redirect_uri does not match authorization request",
                );
            }
            if let Some(ref challenge) = claims.code_challenge {
                let method = claims.code_challenge_method.as_deref().unwrap_or("plain");
                let Some(verifier) = req.code_verifier.as_deref().filter(|s| !s.is_empty()) else {
                    return oauth2_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "Missing PKCE code_verifier",
                    );
                };
                if !verify_pkce(verifier, challenge, method) {
                    return oauth2_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "Invalid PKCE code_verifier",
                    );
                }
            }
            // Enforce single-use authorization codes.
            {
                let mut used = state.used_oauth_codes.lock().await;
                if !used.insert(claims.jti.clone()) {
                    return oauth2_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "Authorization code has already been redeemed",
                    );
                }
            }
            (claims.sub, claims.scopes, claims.scope, claims.agent_policy)
        }
        "refresh_token" => {
            let Some(rt) = req.refresh_token.as_deref().filter(|s| !s.is_empty()) else {
                return oauth2_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Missing required refresh_token parameter",
                );
            };
            let claims = match verify_jwt(rt, signing_secret, TOKEN_TYPE_REFRESH) {
                Ok(c) => c,
                Err(_) => {
                    return oauth2_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "Refresh token is invalid or expired",
                    );
                }
            };
            if !constant_time_str_eq(&claims.aud, expected_client_id) {
                return oauth2_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "Refresh token was not issued for this client",
                );
            }
            // Allow narrowing scopes on refresh, never escalating.
            let granted_scopes = if req.scope.as_deref().is_some_and(|s| !s.trim().is_empty()) {
                let requested = match parse_oauth2_scopes(req.scope.as_deref()) {
                    Ok(s) => s,
                    Err(msg) => {
                        return oauth2_error(StatusCode::BAD_REQUEST, "invalid_scope", msg);
                    }
                };
                let orig = Principal {
                    mailbox_id: claims.sub.clone(),
                    scopes: claims.scopes.clone(),
                    agent_policy: claims.agent_policy.clone(),
                };
                if !requested.iter().all(|s| orig.has_scope(*s)) {
                    return oauth2_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_scope",
                        "Requested scope exceeds refresh_token grant",
                    );
                }
                requested
            } else {
                claims.scopes
            };
            let scope_out = req.scope.clone().or(claims.scope);
            (claims.sub, granted_scopes, scope_out, claims.agent_policy)
        }
        "client_credentials" => {
            let scopes = match parse_oauth2_scopes(req.scope.as_deref()) {
                Ok(s) => s,
                Err(msg) => return oauth2_error(StatusCode::BAD_REQUEST, "invalid_scope", msg),
            };
            let target_mailbox = match resolve_oauth2_mailbox(&state.config, req.mailbox.as_deref())
            {
                Ok(mb) => mb,
                Err(msg) => return oauth2_error(StatusCode::BAD_REQUEST, "invalid_request", msg),
            };
            (target_mailbox, scopes, req.scope.clone(), None)
        }
        other => {
            return oauth2_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                format!("Unsupported grant_type '{other}'"),
            );
        }
    };

    let canonical_scope = scope_str.unwrap_or_else(|| format_oauth2_scopes(&scopes));
    let access_token = match mint_access_token_for_mailbox(
        &state.config,
        &subject_mailbox,
        scopes.clone(),
        Some(canonical_scope.clone()),
        agent_policy.clone(),
        DEFAULT_ACCESS_TOKEN_TTL_SECS,
    ) {
        Ok(tok) => tok,
        Err(err) => {
            return oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                err.to_string(),
            );
        }
    };
    let refresh_token = match mint_refresh_token_for_mailbox(
        &state.config,
        &subject_mailbox,
        scopes,
        Some(canonical_scope.clone()),
        agent_policy,
    ) {
        Ok(tok) => tok,
        Err(err) => {
            return oauth2_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                err.to_string(),
            );
        }
    };

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp_headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));

    (
        StatusCode::OK,
        resp_headers,
        Json(json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": DEFAULT_ACCESS_TOKEN_TTL_SECS,
            "refresh_token": refresh_token,
            "scope": canonical_scope,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oauth2_config() -> Config {
        let mut cfg = Config::for_test();
        cfg.oauth2_client_id = Some("test-client".to_string());
        cfg.oauth2_client_secret = Some("test-secret".to_string());
        cfg.oauth2_signing_secret = Some("super-signing-secret-key-32bytes!".to_string());
        cfg
    }

    #[test]
    fn jwt_sign_verify_roundtrip_and_tamper_rejection() {
        let cfg = oauth2_config();
        let token = mint_access_token(
            &cfg,
            vec![AuthScope::Read, AuthScope::Send],
            None,
            Some(AgentPolicyOverride {
                draft_only: Some(true),
                allowed_recipients: Some(vec!["@example.com".to_string()]),
                max_send_recipients: Some(3),
            }),
            3600,
        )
        .unwrap();

        let verifier = OAuth2Verifier::from_config(&cfg).unwrap();
        let principal = verifier.verify_access_token(&token).unwrap();
        assert_eq!(principal.mailbox_id, "agent@example.com");
        assert_eq!(principal.scopes, vec![AuthScope::Read, AuthScope::Send]);
        assert_eq!(
            principal.agent_policy.as_ref().unwrap().draft_only,
            Some(true)
        );

        // Tampered payload rejected
        let parts: Vec<&str> = token.split('.').collect();
        let tampered = format!("{}.{}a.{}", parts[0], parts[1], parts[2]);
        assert!(verifier.verify_access_token(&tampered).is_err());

        // Refresh token cannot be used as access token
        let refresh = mint_refresh_token(&cfg, vec![AuthScope::Read], None, None).unwrap();
        assert!(verifier.verify_access_token(&refresh).is_err());
    }

    #[test]
    fn jwt_rejects_expired_token() {
        let cfg = oauth2_config();
        let now = Utc::now().timestamp();
        let expired = OAuth2Claims {
            sub: cfg.user_email.clone(),
            iss: "nogml".to_string(),
            aud: "test-client".to_string(),
            typ: TOKEN_TYPE_ACCESS.to_string(),
            iat: now - 120,
            exp: now - 10,
            jti: "expired-1".to_string(),
            scopes: vec![AuthScope::Read],
            scope: Some("read".to_string()),
            redirect_uri: None,
            code_challenge: None,
            code_challenge_method: None,
            agent_policy: None,
        };
        let jwt = sign_jwt(&expired, cfg.oauth2_signing_secret.as_deref().unwrap()).unwrap();
        let verifier = OAuth2Verifier::from_config(&cfg).unwrap();
        assert!(verifier.verify_access_token(&jwt).is_err());
    }

    #[test]
    fn scope_mapping_supports_gmail_urls_and_short_names() {
        assert_eq!(
            parse_oauth2_scopes(Some("https://www.googleapis.com/auth/gmail.readonly")).unwrap(),
            vec![AuthScope::Read]
        );
        assert_eq!(
            parse_oauth2_scopes(Some("https://www.googleapis.com/auth/gmail.modify")).unwrap(),
            vec![AuthScope::Read, AuthScope::Write]
        );
        assert_eq!(
            parse_oauth2_scopes(Some("https://www.googleapis.com/auth/gmail.send")).unwrap(),
            vec![AuthScope::Send]
        );
        assert_eq!(
            parse_oauth2_scopes(Some("https://mail.google.com/")).unwrap(),
            vec![
                AuthScope::Read,
                AuthScope::Write,
                AuthScope::Send,
                AuthScope::Admin
            ]
        );
        assert_eq!(
            parse_oauth2_scopes(Some("read write")).unwrap(),
            vec![AuthScope::Read, AuthScope::Write]
        );
        assert!(parse_oauth2_scopes(Some("unknown:scope")).is_err());
    }
}
