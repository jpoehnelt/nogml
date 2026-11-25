//! Resend outbound API client, inbound receiving fetcher, and Svix webhook ingestion.
//!
//! Owned by the `resend` worker.

use async_trait::async_trait;
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::HeaderMap,
    response::Response,
    routing::post,
};

use crate::{
    AppState,
    config::Config,
    error::AppResult,
    models::{
        ResendReceivedAttachment, ResendReceivedEmail, ResendSendEmailRequest,
        ResendSendEmailResponse,
    },
};

/// Object-safe Resend API client trait (enables `wiremock` / fake clients in tests).
#[async_trait]
pub trait ResendClient: Send + Sync {
    async fn send_email(
        &self,
        req: &ResendSendEmailRequest,
        idempotency_key: Option<&str>,
    ) -> AppResult<ResendSendEmailResponse>;

    async fn get_received_email(&self, email_id: &str) -> AppResult<ResendReceivedEmail>;

    async fn list_received_attachments(
        &self,
        email_id: &str,
    ) -> AppResult<Vec<ResendReceivedAttachment>>;

    async fn download_bytes(&self, url: &str) -> AppResult<Vec<u8>>;
}

/// Live HTTP implementation of [`ResendClient`] backed by `reqwest`.
#[derive(Clone)]
pub struct HttpResendClient {
    _http: reqwest::Client,
    _base_url: String,
    _api_key: Option<String>,
}

impl HttpResendClient {
    pub fn from_config(config: &Config) -> Self {
        Self {
            _http: reqwest::Client::new(),
            _base_url: config.resend_base_url.trim_end_matches('/').to_string(),
            _api_key: config.resend_api_key.clone(),
        }
    }
}

#[async_trait]
impl ResendClient for HttpResendClient {
    async fn send_email(
        &self,
        _req: &ResendSendEmailRequest,
        _idempotency_key: Option<&str>,
    ) -> AppResult<ResendSendEmailResponse> {
        todo!("resend worker: POST /emails")
    }

    async fn get_received_email(&self, _email_id: &str) -> AppResult<ResendReceivedEmail> {
        todo!("resend worker: GET /emails/receiving/:id")
    }

    async fn list_received_attachments(
        &self,
        _email_id: &str,
    ) -> AppResult<Vec<ResendReceivedAttachment>> {
        todo!("resend worker: GET /emails/receiving/:id/attachments")
    }

    async fn download_bytes(&self, _url: &str) -> AppResult<Vec<u8>> {
        todo!("resend worker: GET download_url")
    }
}

/// Verify Svix webhook HMAC-SHA256 signature (`svix-id`, `svix-timestamp`, `svix-signature`,
/// with fallback to `webhook-*` headers) using constant-time comparison and 5-minute tolerance.
pub fn verify_svix_signature(
    _headers: &HeaderMap,
    _raw_body: &[u8],
    _secret: &str,
    _now_epoch_secs: i64,
) -> AppResult<()> {
    todo!("resend worker: Svix HMAC-SHA256 verification")
}

/// Axum handler for `POST /webhooks/resend`.
pub async fn webhook_handler(
    State(_state): State<AppState>,
    _headers: HeaderMap,
    _body: Bytes,
) -> AppResult<Response> {
    todo!("resend worker: handle Resend inbound & delivery webhooks")
}

/// Mount Resend webhook routes (`/webhooks/resend`).
pub fn resend_router() -> Router<AppState> {
    Router::new().route("/webhooks/resend", post(webhook_handler))
}
