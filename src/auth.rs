//! Pluggable authentication (`AuthProvider`), bearer token middleware,
//! `userId` resolution, and input hardening validators.

use async_trait::async_trait;
use axum::{
    extract::{Request, State},
    http::{HeaderMap, header},
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
};

/// Paths that are always exempt from bearer token authentication.
const AUTH_EXEMPT_PATHS: &[&str] = &["/healthz", "/readyz", "/webhooks/resend"];

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

/// Authenticated caller identity inserted into HTTP request extensions and IMAP sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub mailbox_id: String,
    pub scopes: Vec<AuthScope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_policy: Option<AgentPolicyOverride>,
}

impl Principal {
    /// Construct a full-access principal for `mailbox_id`.
    pub fn full_access(mailbox_id: impl Into<String>) -> Self {
        Self {
            mailbox_id: mailbox_id.into(),
            scopes: vec![
                AuthScope::Read,
                AuthScope::Write,
                AuthScope::Send,
                AuthScope::Admin,
            ],
            agent_policy: None,
        }
    }

    pub fn has_scope(&self, scope: AuthScope) -> bool {
        self.scopes.contains(&AuthScope::Admin) || self.scopes.contains(&scope)
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
    fn backend_name(&self) -> &'static str;
}

/// Default [`AuthProvider`] backed by static tokens and IMAP credentials from [`Config`].
///
/// Preserves constant-time SHA-256 token verification, open dev mode when `auth_tokens`
/// is empty, and IMAP username/password fallback rules.
#[derive(Debug, Clone)]
pub struct StaticTokenAuthProvider {
    mailbox_id: String,
    auth_tokens: Vec<String>,
    imap_username: String,
    imap_password: Option<String>,
}

impl StaticTokenAuthProvider {
    pub fn from_config(config: &Config) -> Self {
        Self {
            mailbox_id: config.user_email.clone(),
            auth_tokens: config.auth_tokens.clone(),
            imap_username: config.effective_imap_username().to_string(),
            imap_password: config.effective_imap_password().map(str::to_string),
        }
    }
}

#[async_trait]
impl AuthProvider for StaticTokenAuthProvider {
    async fn authenticate_bearer(&self, token: Option<&str>) -> AppResult<Principal> {
        if self.auth_tokens.is_empty() {
            return Ok(Principal::full_access(&self.mailbox_id));
        }

        let authorized = token
            .is_some_and(|candidate| constant_time_token_matches(candidate, &self.auth_tokens));
        if authorized {
            Ok(Principal::full_access(&self.mailbox_id))
        } else {
            Err(AppError::Unauthorized(
                "Invalid or missing credentials. Provide 'Authorization: Bearer <token>', 'X-API-Key', or '?access_token='."
                    .to_string(),
            ))
        }
    }

    async fn authenticate_imap(&self, username: &str, password: &str) -> AppResult<Principal> {
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
            None => self.auth_tokens.is_empty(),
        };

        if valid {
            Ok(Principal::full_access(&self.mailbox_id))
        } else {
            Err(AppError::Unauthorized(
                "Invalid IMAP credentials".to_string(),
            ))
        }
    }

    fn backend_name(&self) -> &'static str {
        "static_token"
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

/// Axum middleware authenticating requests via `state.auth` (`Authorization: Bearer <token>`,
/// `X-API-Key`, or `?access_token=`) and inserting the resolved [`Principal`] into request
/// extensions.
///
/// Always exempts `/healthz`, `/readyz`, and `/webhooks/resend`.
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
    match state.auth.authenticate_bearer(token.as_deref()).await {
        Ok(principal) => {
            req.extensions_mut().insert(principal);
            Ok(next.run(req).await)
        }
        Err(err) => {
            if path == "/v1" || path.starts_with("/v1/") {
                return Ok(err.into_ai_response());
            }
            Err(err)
        }
    }
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
        for path in ["/healthz", "/readyz", "/webhooks/resend"] {
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
}
