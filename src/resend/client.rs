//! Live HTTP implementation of [`ResendClient`] backed by `reqwest`.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::{StatusCode, header};
use url::Url;

use crate::{
    config::Config,
    error::{AppError, AppResult},
    models::{
        ResendErrorResponse, ResendReceivedAttachment, ResendReceivedAttachmentsResponse,
        ResendReceivedEmail, ResendSendEmailRequest, ResendSendEmailResponse,
    },
    net_guard::{
        UrlGuardOptions, build_pinned_http_client, read_bounded_bytes, same_origin, ssrf_error,
        validate_and_pin_url,
    },
    resend::ResendClient,
};

const DEFAULT_TIMEOUT_SECS: u64 = 30;
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_MAX_DOWNLOAD_BYTES: usize = 40 * 1024 * 1024;
const MAX_IDEMPOTENCY_KEY_LEN: usize = 256;
const MAX_RAW_ERROR_SNIPPET_CHARS: usize = 512;

/// Live HTTP implementation of [`ResendClient`] backed by `reqwest`.
#[derive(Clone, Debug)]
pub struct HttpResendClient {
    http: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
    max_body_bytes: usize,
    allow_private_endpoints: bool,
}

impl HttpResendClient {
    /// Construct a client from application [`Config`].
    pub fn from_config(config: &Config) -> Self {
        Self::new(&config.resend_base_url, config.resend_api_key.clone())
            .with_max_body_bytes(config.max_body_bytes)
            .with_allow_private_endpoints(config.allow_private_endpoints)
    }

    /// Construct a client targeting `base_url` with an optional Resend API key.
    pub fn new(base_url: impl Into<String>, api_key: Option<String>) -> Self {
        crate::ensure_crypto_provider();
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS))
            .user_agent(concat!("nogml/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self::with_http_client(http, base_url, api_key)
    }

    /// Construct a client using an explicit `reqwest::Client`.
    pub fn with_http_client(
        http: reqwest::Client,
        base_url: impl Into<String>,
        api_key: Option<String>,
    ) -> Self {
        crate::ensure_crypto_provider();
        Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key,
            max_body_bytes: DEFAULT_MAX_DOWNLOAD_BYTES,
            allow_private_endpoints: false,
        }
    }

    /// Override the maximum response size permitted by [`ResendClient::download_bytes`].
    pub fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes.max(1);
        self
    }

    /// Allow private/loopback/HTTP download endpoints (for local dev/tests only).
    pub fn with_allow_private_endpoints(mut self, allow: bool) -> Self {
        self.allow_private_endpoints = allow;
        self
    }

    /// Return the configured base URL (without trailing slash).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Convenience helper to download bytes from a received attachment's `download_url`.
    pub async fn download_attachment(
        &self,
        attachment: &ResendReceivedAttachment,
    ) -> AppResult<Vec<u8>> {
        self.download_bytes(&attachment.download_url).await
    }

    /// Convenience helper to download raw RFC 2822 bytes from `email.raw.download_url` if present.
    pub async fn download_raw_email(
        &self,
        email: &ResendReceivedEmail,
    ) -> AppResult<Option<Vec<u8>>> {
        let Some(raw) = email.raw.as_ref() else {
            return Ok(None);
        };
        let url = raw.download_url.trim();
        if url.is_empty() {
            return Ok(None);
        }
        let bytes = self.download_bytes(url).await?;
        Ok(Some(bytes))
    }

    fn require_api_key(&self, operation: &str) -> AppResult<&str> {
        self.api_key
            .as_deref()
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .ok_or_else(|| {
                AppError::Config(format!(
                    "Resend API key is not configured for {operation}; set RESEND_API_KEY or --resend-api-key"
                ))
            })
    }
}

fn validate_email_id(email_id: &str) -> AppResult<&str> {
    let trimmed = email_id.trim();
    if trimmed.is_empty()
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || trimmed.contains('?')
        || trimmed.contains('#')
        || trimmed.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(AppError::BadRequest(format!(
            "Invalid Resend email_id: {email_id:?}"
        )));
    }
    Ok(trimmed)
}

/// Map a non-2xx Resend HTTP response into a typed [`AppError`].
pub(crate) fn map_resend_error(http_status: StatusCode, body: &[u8]) -> AppError {
    if let Ok(err) = serde_json::from_slice::<ResendErrorResponse>(body) {
        let status = if err.status_code != 0 {
            err.status_code
        } else {
            http_status.as_u16()
        };
        let formatted = format!("Resend {}: {}", err.name, err.message);

        return match (err.name.as_str(), status) {
            ("missing_api_key" | "invalid_api_key", _) | (_, 401) => {
                AppError::Unauthorized(formatted)
            }
            ("restricted_api_key" | "security_error", _) | (_, 403) => {
                AppError::Forbidden(formatted)
            }
            ("not_found", _) | (_, 404) => AppError::NotFound(formatted),
            ("rate_limit_exceeded" | "daily_quota_exceeded" | "monthly_quota_exceeded", _)
            | (_, 429) => AppError::RateLimited(formatted),
            (
                "concurrent_idempotent_requests"
                | "invalid_idempotency_key"
                | "invalid_idempotent_request",
                _,
            )
            | (_, 409) => AppError::Conflict(formatted),
            (_, 413) => AppError::PayloadTooLarge(formatted),
            (
                "validation_error"
                | "missing_required_field"
                | "invalid_attachment"
                | "invalid_from_address"
                | "invalid_access"
                | "invalid_parameter"
                | "invalid_region",
                _,
            )
            | (_, 400 | 422) => AppError::Validation {
                message: formatted,
                hint: Some(format!("Resend rejected request ({})", err.name)),
            },
            _ => AppError::Upstream {
                status,
                message: formatted,
            },
        };
    }

    let raw_text = String::from_utf8_lossy(body);
    let snippet: String = raw_text
        .trim()
        .chars()
        .take(MAX_RAW_ERROR_SNIPPET_CHARS)
        .collect();
    let message = if snippet.is_empty() {
        format!("Resend returned HTTP {}", http_status.as_u16())
    } else {
        format!("Resend returned HTTP {}: {snippet}", http_status.as_u16())
    };

    match http_status.as_u16() {
        401 => AppError::Unauthorized(message),
        403 => AppError::Forbidden(message),
        404 => AppError::NotFound(message),
        409 => AppError::Conflict(message),
        413 => AppError::PayloadTooLarge(message),
        429 => AppError::RateLimited(message),
        status => AppError::Upstream { status, message },
    }
}

#[async_trait]
impl ResendClient for HttpResendClient {
    async fn send_email(
        &self,
        req: &ResendSendEmailRequest,
        idempotency_key: Option<&str>,
    ) -> AppResult<ResendSendEmailResponse> {
        let api_key = self.require_api_key("outbound email send")?;
        let url = format!("{}/emails", self.base_url);

        let mut builder = self
            .http
            .post(&url)
            .bearer_auth(api_key)
            .header(header::ACCEPT, "application/json")
            .json(req);

        if let Some(key) = idempotency_key {
            let trimmed = key.trim();
            if trimmed.is_empty() || trimmed.len() > MAX_IDEMPOTENCY_KEY_LEN {
                return Err(AppError::BadRequest(format!(
                    "Idempotency-Key must be between 1 and {MAX_IDEMPOTENCY_KEY_LEN} characters"
                )));
            }
            builder = builder.header("Idempotency-Key", trimmed);
        }

        let resp = builder.send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;

        if !status.is_success() {
            return Err(map_resend_error(status, &body));
        }

        serde_json::from_slice::<ResendSendEmailResponse>(&body).map_err(|err| AppError::Upstream {
            status: StatusCode::BAD_GATEWAY.as_u16(),
            message: format!("Failed to decode Resend send_email response: {err}"),
        })
    }

    async fn get_received_email(&self, email_id: &str) -> AppResult<ResendReceivedEmail> {
        let api_key = self.require_api_key("receiving email fetch")?;
        let email_id = validate_email_id(email_id)?;
        let url = format!("{}/emails/receiving/{email_id}", self.base_url);

        let resp = self
            .http
            .get(&url)
            .bearer_auth(api_key)
            .header(header::ACCEPT, "application/json")
            .send()
            .await?;

        let status = resp.status();
        let body = resp.bytes().await?;

        if !status.is_success() {
            return Err(map_resend_error(status, &body));
        }

        serde_json::from_slice::<ResendReceivedEmail>(&body).map_err(|err| AppError::Upstream {
            status: StatusCode::BAD_GATEWAY.as_u16(),
            message: format!("Failed to decode Resend received email response: {err}"),
        })
    }

    async fn list_received_attachments(
        &self,
        email_id: &str,
    ) -> AppResult<Vec<ResendReceivedAttachment>> {
        let api_key = self.require_api_key("receiving attachments list")?;
        let email_id = validate_email_id(email_id)?;
        let url = format!("{}/emails/receiving/{email_id}/attachments", self.base_url);

        let resp = self
            .http
            .get(&url)
            .bearer_auth(api_key)
            .header(header::ACCEPT, "application/json")
            .send()
            .await?;

        let status = resp.status();
        let body = resp.bytes().await?;

        if !status.is_success() {
            return Err(map_resend_error(status, &body));
        }

        let parsed =
            serde_json::from_slice::<ResendReceivedAttachmentsResponse>(&body).map_err(|err| {
                AppError::Upstream {
                    status: StatusCode::BAD_GATEWAY.as_u16(),
                    message: format!(
                        "Failed to decode Resend received attachments response: {err}"
                    ),
                }
            })?;

        Ok(parsed.data)
    }

    async fn download_bytes(&self, url: &str) -> AppResult<Vec<u8>> {
        let parsed = Url::parse(url.trim())
            .map_err(|err| AppError::BadRequest(format!("Invalid download URL: {err}")))?;
        let allow_private =
            self.allow_private_endpoints || same_origin(&parsed, self.base_url.as_str());

        let pinned = validate_and_pin_url(
            url,
            UrlGuardOptions {
                allow_private_endpoints: allow_private,
                allow_http: allow_private,
                allowed_hosts: &[],
                context: "Resend download URL",
            },
        )
        .await?;

        let client = build_pinned_http_client(
            &pinned,
            Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            Some(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS)),
        )?;

        // Presigned download URLs (S3/R2) reject extra Authorization headers; do not attach bearer auth.
        let resp = client.get(pinned.url.as_str()).send().await?;
        let status = resp.status();
        if status.is_redirection() {
            return Err(ssrf_error(
                format!(
                    "Resend download URL returned HTTP {} redirect; redirects are disabled for SSRF protection",
                    status.as_u16()
                ),
                "Presigned download URLs must respond directly without redirecting.",
            ));
        }

        let body = read_bounded_bytes(resp, self.max_body_bytes, "Resend download").await?;

        if !status.is_success() {
            return Err(map_resend_error(status, &body));
        }

        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_partial_json, header, header_exists, method, path},
    };

    use super::*;
    use crate::models::{ResendAttachment, ResendTag};

    fn sample_send_request() -> ResendSendEmailRequest {
        ResendSendEmailRequest {
            from: "Agent <agent@example.com>".to_string(),
            to: vec!["alice@example.com".to_string()],
            subject: "Hello from nogml".to_string(),
            cc: Some(vec!["bob@example.com".to_string()]),
            bcc: None,
            reply_to: Some(vec!["reply@example.com".to_string()]),
            html: Some("<p>Hello</p>".to_string()),
            text: Some("Hello".to_string()),
            headers: Some(HashMap::from([(
                "In-Reply-To".to_string(),
                "<prev@example.com>".to_string(),
            )])),
            attachments: Some(vec![ResendAttachment {
                filename: Some("note.txt".to_string()),
                content: Some("SGVsbG8=".to_string()),
                path: None,
                content_type: Some("text/plain".to_string()),
                content_id: None,
            }]),
            tags: Some(vec![ResendTag {
                name: "env".to_string(),
                value: "test".to_string(),
            }]),
            scheduled_at: None,
        }
    }

    #[tokio::test]
    async fn send_email_success_with_idempotency_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/emails"))
            .and(header("authorization", "Bearer re_test_123"))
            .and(header("idempotency-key", "idem-key-42"))
            .and(body_partial_json(json!({
                "from": "Agent <agent@example.com>",
                "to": ["alice@example.com"],
                "subject": "Hello from nogml",
                "text": "Hello"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "49a3999c-0ce1-4ea6-ab68-afcd6dc2e794"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = HttpResendClient::new(server.uri(), Some("re_test_123".to_string()));
        let resp = client
            .send_email(&sample_send_request(), Some("idem-key-42"))
            .await
            .expect("send_email should succeed");

        assert_eq!(resp.id, "49a3999c-0ce1-4ea6-ab68-afcd6dc2e794");
    }

    #[tokio::test]
    async fn send_email_missing_api_key_returns_config_error() {
        let client = HttpResendClient::new("http://127.0.0.1:9", None);
        let err = client
            .send_email(&sample_send_request(), None)
            .await
            .expect_err("missing API key should fail");

        assert!(matches!(err, AppError::Config(_)));
        assert!(err.to_string().contains("RESEND_API_KEY"));
    }

    #[tokio::test]
    async fn send_email_rejects_overlong_idempotency_key() {
        let client = HttpResendClient::new("http://127.0.0.1:9", Some("re_test".to_string()));
        let long_key = "x".repeat(257);
        let err = client
            .send_email(&sample_send_request(), Some(&long_key))
            .await
            .expect_err("overlong idempotency key should fail");

        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[tokio::test]
    async fn send_email_maps_resend_error_codes_accurately() {
        let server = MockServer::start().await;

        let cases = [
            (401, "missing_api_key", "Missing API key", "unauthorized"),
            (403, "restricted_api_key", "Restricted key", "forbidden"),
            (404, "not_found", "Not found", "not_found"),
            (
                409,
                "concurrent_idempotent_requests",
                "Duplicate",
                "conflict",
            ),
            (
                422,
                "validation_error",
                "Invalid to field",
                "validation_error",
            ),
            (
                429,
                "rate_limit_exceeded",
                "Too many requests",
                "rate_limited",
            ),
            (
                500,
                "application_error",
                "Internal failure",
                "upstream_error",
            ),
        ];

        for (status, name, msg, expected_code) in cases {
            server.reset().await;
            Mock::given(method("POST"))
                .and(path("/emails"))
                .respond_with(ResponseTemplate::new(status).set_body_json(json!({
                    "statusCode": status,
                    "name": name,
                    "message": msg
                })))
                .expect(1)
                .mount(&server)
                .await;

            let client = HttpResendClient::new(server.uri(), Some("re_test".to_string()));
            let err = client
                .send_email(&sample_send_request(), None)
                .await
                .expect_err("error response should map to Err");

            assert_eq!(err.ai_code(), expected_code, "status={status} name={name}");
            assert!(err.to_string().contains(msg));
        }
    }

    #[tokio::test]
    async fn send_email_maps_non_json_upstream_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/emails"))
            .respond_with(ResponseTemplate::new(502).set_body_string("<html>Bad Gateway</html>"))
            .expect(1)
            .mount(&server)
            .await;

        let client = HttpResendClient::new(server.uri(), Some("re_test".to_string()));
        let err = client
            .send_email(&sample_send_request(), None)
            .await
            .expect_err("502 should fail");

        assert!(matches!(err, AppError::Upstream { status: 502, .. }));
        assert!(err.to_string().contains("Bad Gateway"));
    }

    #[tokio::test]
    async fn receiving_api_fetch_email_attachments_and_downloads() {
        let server = MockServer::start().await;
        let raw_url = format!("{}/downloads/raw-eml", server.uri());
        let att_url = format!("{}/downloads/att-1", server.uri());

        Mock::given(method("GET"))
            .and(path("/emails/receiving/em_123"))
            .and(header("authorization", "Bearer re_recv_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "object": "email",
                "id": "em_123",
                "to": ["agent@example.com"],
                "from": "Sender <sender@external.com>",
                "created_at": "2026-01-02T03:04:05Z",
                "subject": "Invoice #99",
                "html": "<p>See attached</p>",
                "text": "See attached",
                "headers": {
                    "In-Reply-To": "<orig@example.com>",
                    "References": "<root@example.com> <orig@example.com>"
                },
                "cc": [],
                "bcc": [],
                "reply_to": ["billing@external.com"],
                "message_id": "<inv-99@external.com>",
                "raw": { "download_url": raw_url },
                "attachments": [{
                    "id": "att_1",
                    "filename": "invoice.pdf",
                    "content_type": "application/pdf",
                    "content_disposition": "attachment"
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/emails/receiving/em_123/attachments"))
            .and(header("authorization", "Bearer re_recv_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "object": "list",
                "has_more": false,
                "data": [{
                    "id": "att_1",
                    "filename": "invoice.pdf",
                    "size": 12,
                    "content_type": "application/pdf",
                    "content_disposition": "attachment",
                    "download_url": att_url,
                    "expires_at": "2026-01-02T04:04:05Z"
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/downloads/raw-eml"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(b"From: sender@external.com\r\n\r\nRaw body"),
            )
            .expect(1)
            .mount(&server)
            .await;

        // Verify download_bytes does NOT leak Authorization header to presigned URLs.
        Mock::given(method("GET"))
            .and(path("/downloads/att-1"))
            .and(header_exists("authorization"))
            .respond_with(ResponseTemplate::new(400).set_body_string("unexpected auth header"))
            .expect(0)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/downloads/att-1"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"%PDF-1.7-abc"))
            .expect(1)
            .mount(&server)
            .await;

        let client = HttpResendClient::new(server.uri(), Some("re_recv_key".to_string()));
        let email = client
            .get_received_email("em_123")
            .await
            .expect("get_received_email should succeed");
        assert_eq!(email.id, "em_123");
        assert_eq!(email.subject, "Invoice #99");
        assert_eq!(
            email.headers.get("In-Reply-To").map(String::as_str),
            Some("<orig@example.com>")
        );

        let raw = client
            .download_raw_email(&email)
            .await
            .expect("download_raw_email should succeed")
            .expect("raw bytes should be Some");
        assert_eq!(raw, b"From: sender@external.com\r\n\r\nRaw body");

        let attachments = client
            .list_received_attachments("em_123")
            .await
            .expect("list_received_attachments should succeed");
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].filename.as_deref(), Some("invoice.pdf"));

        let att_bytes = client
            .download_attachment(&attachments[0])
            .await
            .expect("download_attachment should succeed");
        assert_eq!(att_bytes, b"%PDF-1.7-abc");
    }

    #[tokio::test]
    async fn receiving_api_rejects_path_traversal_email_id() {
        let client = HttpResendClient::new("http://127.0.0.1:9", Some("re_test".to_string()));
        let err = client
            .get_received_email("../admin")
            .await
            .expect_err("path traversal email_id should be rejected");
        assert!(matches!(err, AppError::BadRequest(_)));
    }
}
