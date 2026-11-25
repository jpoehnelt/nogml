//! Resend outbound API client, inbound receiving fetcher, Svix webhook ingestion,
//! plus provider-agnostic `MailTransport` and `InboundFilter` abstractions.
//!
//! Owned by the `resend` worker.

pub mod client;
pub mod filter;
pub mod svix;
pub mod transport;
pub mod webhook;

use async_trait::async_trait;

use crate::{
    error::AppResult,
    models::{
        ResendReceivedAttachment, ResendReceivedEmail, ResendSendEmailRequest,
        ResendSendEmailResponse,
    },
};

pub use client::HttpResendClient;
pub use filter::{FilterChain, FilterDecision, InboundFilter, InboundMessage, NoopFilter};
pub use svix::{SVIX_TIMESTAMP_TOLERANCE_SECS, sign_svix_payload, verify_svix_signature};
pub use transport::{
    InboundEnvelope, IngestOutcome, MailTransport, OutboundAttachment, OutboundMessage,
    ResendTransport, SendOutcome, TransportCapabilities, ingest_inbound_rfc2822,
};
pub use webhook::{handle_email_received, resend_router, webhook_handler};

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
