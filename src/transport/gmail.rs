//! Native Gmail REST API v1 outbound mail transport (`GmailApiTransport`).
//!
//! Sends RFC 5322 MIME messages directly through
//! `POST {gmail_api_base_url}/gmail/v1/users/{userId}/messages/send` using base64url-encoded
//! `raw` (and optional `threadId` when replying to a synced Gmail thread), reusing the shared
//! OAuth2 token acquisition (`acquire_access_token`) with automatic HTTP 401 refresh retry.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use tracing::debug;

use crate::{
    auth::validate_resource_id,
    config::Config,
    error::{AppError, AppResult},
    models::Message,
    sync::gmail_api::{acquire_access_token, encode_path_segment, invalidate_access_token},
    transport::{
        MailTransport, OutboundMessage, SendOutcome, TransportCapabilities, ensure_raw_rfc2822,
    },
};

/// Gmail API documented maximum message upload size (35 MiB).
const GMAIL_MAX_MESSAGE_BYTES: usize = 35 * 1024 * 1024;
const GMAIL_HTTP_TIMEOUT: Duration = Duration::from_secs(60);

/// Configuration for [`GmailApiTransport`].
///
/// Implements a custom [`std::fmt::Debug`] that replaces all OAuth2 tokens and secrets
/// with `"[REDACTED]"`.
#[derive(Clone)]
pub struct GmailTransportConfig {
    pub api_base_url: String,
    pub oauth_token_url: String,
    pub user_id: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token: Option<String>,
    pub default_from: String,
}

impl std::fmt::Debug for GmailTransportConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact = |opt: &Option<String>| {
            opt.as_deref()
                .filter(|s| !s.is_empty())
                .map(|_| crate::secrets::REDACTED)
        };
        f.debug_struct("GmailTransportConfig")
            .field("api_base_url", &self.api_base_url)
            .field("oauth_token_url", &self.oauth_token_url)
            .field("user_id", &self.user_id)
            .field("client_id", &self.client_id)
            .field("client_secret", &redact(&self.client_secret))
            .field("refresh_token", &redact(&self.refresh_token))
            .field("access_token", &redact(&self.access_token))
            .field("default_from", &self.default_from)
            .finish()
    }
}

impl GmailTransportConfig {
    /// Build [`GmailTransportConfig`] from application [`Config`].
    pub fn from_config(config: &Config) -> AppResult<Self> {
        let api_base_url = config
            .gmail_api_base_url
            .trim()
            .trim_end_matches('/')
            .to_string();
        if api_base_url.is_empty() || url::Url::parse(&api_base_url).is_err() {
            return Err(AppError::Config(format!(
                "Invalid GMAIL_API_BASE_URL '{api_base_url}' for Gmail transport"
            )));
        }

        let oauth_token_url = config.gmail_oauth_token_url.trim().to_string();
        if oauth_token_url.is_empty() || url::Url::parse(&oauth_token_url).is_err() {
            return Err(AppError::Config(format!(
                "Invalid GMAIL_OAUTH_TOKEN_URL '{oauth_token_url}' for Gmail transport"
            )));
        }

        let user_id = config.gmail_user_id.trim().to_string();
        if user_id.is_empty() {
            return Err(AppError::Config(
                "GMAIL_USER_ID must not be empty for Gmail transport".to_string(),
            ));
        }
        validate_resource_id(&user_id)?;

        Ok(Self {
            api_base_url,
            oauth_token_url,
            user_id,
            client_id: config.gmail_client_id.clone(),
            client_secret: config.gmail_client_secret.clone(),
            refresh_token: config.gmail_refresh_token.clone(),
            access_token: config.gmail_access_token.clone(),
            default_from: config.user_email.clone(),
        })
    }

    /// Returns `true` when OAuth2 refresh credentials are configured and no static token override is set.
    pub fn can_refresh(&self) -> bool {
        let has_static = self
            .access_token
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty());
        !has_static
            && self
                .client_id
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
            && self
                .client_secret
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
            && self
                .refresh_token
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
    }

    /// Returns `true` when either a static access token or complete OAuth2 refresh credentials are configured.
    pub fn has_credentials(&self) -> bool {
        self.access_token
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
            || self.can_refresh()
    }

    fn to_oauth_config(&self) -> Config {
        Config {
            gmail_api_base_url: self.api_base_url.clone(),
            gmail_oauth_token_url: self.oauth_token_url.clone(),
            gmail_user_id: self.user_id.clone(),
            gmail_client_id: self.client_id.clone(),
            gmail_client_secret: self.client_secret.clone(),
            gmail_refresh_token: self.refresh_token.clone(),
            gmail_access_token: self.access_token.clone(),
            ..Config::default()
        }
    }
}

/// Outbound [`MailTransport`] delivering RFC 5322 messages through Gmail REST API v1
/// (`POST /gmail/v1/users/{userId}/messages/send`).
#[derive(Clone)]
pub struct GmailApiTransport {
    config: GmailTransportConfig,
    oauth_config: Config,
    client: Client,
}

impl std::fmt::Debug for GmailApiTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GmailApiTransport")
            .field("config", &self.config)
            .finish()
    }
}

impl GmailApiTransport {
    /// Construct a [`GmailApiTransport`] from an explicit [`GmailTransportConfig`].
    pub fn new(config: GmailTransportConfig) -> AppResult<Self> {
        let client = Client::builder()
            .timeout(GMAIL_HTTP_TIMEOUT)
            .build()
            .map_err(|e| AppError::Internal(format!("Failed to build Gmail HTTP client: {e}")))?;
        let oauth_config = config.to_oauth_config();
        Ok(Self {
            config,
            oauth_config,
            client,
        })
    }

    /// Construct a [`GmailApiTransport`] from application [`Config`].
    pub fn from_config(config: &Config) -> AppResult<Self> {
        Self::new(GmailTransportConfig::from_config(config)?)
    }

    /// Return the resolved [`GmailTransportConfig`].
    pub fn config(&self) -> &GmailTransportConfig {
        &self.config
    }
}

#[async_trait]
impl MailTransport for GmailApiTransport {
    fn name(&self) -> &'static str {
        "gmail"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            provider: "gmail".to_string(),
            supports_raw_mime: true,
            supports_scheduled_send: false,
            supports_idempotency_key: false,
            supports_inbound_webhooks: false,
            supports_delivery_webhooks: false,
            max_message_bytes: GMAIL_MAX_MESSAGE_BYTES,
        }
    }

    async fn send(
        &self,
        msg: &OutboundMessage,
        _idempotency_key: Option<&str>,
    ) -> AppResult<SendOutcome> {
        let raw_bytes = ensure_raw_rfc2822(msg, &self.config.default_from)?;
        if raw_bytes.len() > GMAIL_MAX_MESSAGE_BYTES {
            return Err(AppError::BadRequest(format!(
                "Message size {} bytes exceeds Gmail API limit of {} bytes",
                raw_bytes.len(),
                GMAIL_MAX_MESSAGE_BYTES
            )));
        }

        let raw_b64 = crate::mime::encode_base64url(&raw_bytes);
        let mut payload = json!({ "raw": raw_b64 });
        if let Some(thread_id) = msg.upstream_thread_id() {
            payload["threadId"] = Value::String(thread_id.to_string());
        }
        let body_bytes = serde_json::to_vec(&payload)?;

        let url = format!(
            "{}/gmail/v1/users/{}/messages/send",
            self.config.api_base_url,
            encode_path_segment(&self.config.user_id)
        );

        let mut token = acquire_access_token(&self.client, &self.oauth_config).await?;
        let mut refreshed_on_401 = false;

        loop {
            let resp = self
                .client
                .post(&url)
                .bearer_auth(&token)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body_bytes.clone())
                .send()
                .await?;

            let status = resp.status();
            let resp_bytes = resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default();

            if status == StatusCode::UNAUTHORIZED && !refreshed_on_401 && self.config.can_refresh()
            {
                refreshed_on_401 = true;
                invalidate_access_token(&self.oauth_config);
                token = acquire_access_token(&self.client, &self.oauth_config).await?;
                debug!("Refreshed Gmail OAuth2 token after HTTP 401 on messages.send; retrying");
                continue;
            }

            if !status.is_success() {
                return Err(AppError::Upstream {
                    status: status.as_u16(),
                    message: format!(
                        "Gmail messages.send failed ({}): {}",
                        status.as_u16(),
                        String::from_utf8_lossy(&resp_bytes)
                    ),
                });
            }

            let sent: Message =
                serde_json::from_slice(&resp_bytes).map_err(|e| AppError::Upstream {
                    status: 502,
                    message: format!("Invalid Gmail messages.send response JSON: {e}"),
                })?;

            if sent.id.trim().is_empty() {
                return Err(AppError::Upstream {
                    status: 502,
                    message: "Gmail messages.send response missing 'id'".to_string(),
                });
            }

            let provider_thread_id = (!sent.thread_id.trim().is_empty()).then_some(sent.thread_id);
            return Ok(SendOutcome {
                provider: self.name().to_string(),
                provider_message_id: sent.id,
                provider_thread_id,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_partial_json, header, method, path},
    };

    use super::*;

    #[test]
    fn gmail_transport_config_debug_redacts_secrets() {
        let mut cfg = Config::for_test();
        cfg.gmail_client_id = Some("cid-123".to_string());
        cfg.gmail_client_secret = Some("super-secret-client-secret".to_string());
        cfg.gmail_refresh_token = Some("super-secret-refresh-token".to_string());
        cfg.gmail_access_token = Some("super-secret-access-token".to_string());

        let tcfg = GmailTransportConfig::from_config(&cfg).unwrap();
        let dbg = format!("{tcfg:?}");
        assert!(dbg.contains("cid-123"));
        assert!(!dbg.contains("super-secret-client-secret"));
        assert!(!dbg.contains("super-secret-refresh-token"));
        assert!(!dbg.contains("super-secret-access-token"));
        assert!(dbg.contains(crate::secrets::REDACTED));

        let transport = GmailApiTransport::new(tcfg).unwrap();
        let tdbg = format!("{transport:?}");
        assert!(!tdbg.contains("super-secret"));
    }

    #[tokio::test]
    async fn gmail_api_transport_sends_raw_and_thread_id_with_401_refresh_retry() {
        let server = MockServer::start().await;

        // First token refresh returns stale token; second returns fresh token.
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "expired-token-1",
                "expires_in": 3600
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "fresh-token-2",
                "expires_in": 3600
            })))
            .expect(1)
            .mount(&server)
            .await;

        // First send with stale token -> 401
        Mock::given(method("POST"))
            .and(path("/gmail/v1/users/me/messages/send"))
            .and(header("authorization", "Bearer expired-token-1"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "error": { "code": 401, "message": "Invalid Credentials" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let raw =
            b"From: me@example.com\r\nTo: bob@example.com\r\nSubject: Re: Sync\r\n\r\nReply body"
                .to_vec();
        let expected_raw = crate::mime::encode_base64url(&raw);

        // Retry send with fresh token -> 200 with Gmail message ID
        Mock::given(method("POST"))
            .and(path("/gmail/v1/users/me/messages/send"))
            .and(header("authorization", "Bearer fresh-token-2"))
            .and(body_partial_json(json!({
                "raw": expected_raw,
                "threadId": "18f_gmail_thr_42"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "18f_gmail_sent_99",
                "threadId": "18f_gmail_thr_42",
                "labelIds": ["SENT"]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut cfg = Config::for_test();
        cfg.gmail_api_base_url = server.uri();
        cfg.gmail_oauth_token_url = format!("{}/token", server.uri());
        cfg.gmail_client_id = Some("cid-send-test".to_string());
        cfg.gmail_client_secret = Some("csec-send-test".to_string());
        cfg.gmail_refresh_token = Some("rtok-send-test".to_string());

        let transport = GmailApiTransport::from_config(&cfg).unwrap();
        assert_eq!(transport.name(), "gmail");
        assert!(transport.capabilities().supports_raw_mime);

        let mut msg = OutboundMessage {
            from: "me@example.com".to_string(),
            to: vec!["bob@example.com".to_string()],
            subject: "Re: Sync".to_string(),
            text: Some("Reply body".to_string()),
            raw_rfc2822: raw,
            ..Default::default()
        };
        msg.set_upstream_thread_id("18f_gmail_thr_42");

        let outcome = transport.send(&msg, None).await.unwrap();
        assert_eq!(outcome.provider, "gmail");
        assert_eq!(outcome.provider_message_id, "18f_gmail_sent_99");
        assert_eq!(
            outcome.provider_thread_id.as_deref(),
            Some("18f_gmail_thr_42")
        );
    }

    #[tokio::test]
    async fn gmail_transport_send_new_thread_populates_provider_thread_id() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/gmail/v1/users/me/messages/send"))
            .and(header("authorization", "Bearer static-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "18f_new_msg_1",
                "threadId": "18f_new_thr_1",
                "labelIds": ["SENT"]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut cfg = Config::for_test();
        cfg.gmail_api_base_url = server.uri();
        cfg.gmail_access_token = Some("static-tok".to_string());

        let transport = GmailApiTransport::from_config(&cfg).unwrap();
        let msg = OutboundMessage {
            from: "me@example.com".to_string(),
            to: vec!["alice@example.com".to_string()],
            subject: "Brand New Thread".to_string(),
            text: Some("Hello new thread".to_string()),
            ..Default::default()
        };

        let outcome = transport.send(&msg, None).await.unwrap();
        assert_eq!(outcome.provider, "gmail");
        assert_eq!(outcome.provider_message_id, "18f_new_msg_1");
        assert_eq!(outcome.provider_thread_id.as_deref(), Some("18f_new_thr_1"));

        let (up_mid, up_tid) = crate::transport::upstream_gmail_ids_from_send(&outcome, None);
        assert_eq!(up_mid.as_deref(), Some("18f_new_msg_1"));
        assert_eq!(up_tid.as_deref(), Some("18f_new_thr_1"));
    }
}
