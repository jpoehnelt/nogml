//! AWS SESv2 raw MIME outbound transport (`SesTransport`) with pure-Rust AWS SigV4
//! request signing and an inbound SNS/SES webhook handler (`POST /webhooks/ses`) supporting
//! inline base64 payloads and SigV4-authenticated S3 `.eml` fetches.

use std::time::Duration;

use async_trait::async_trait;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    AppState,
    auth::constant_time_token_matches,
    config::Config,
    error::{AppError, AppResult},
    filter::FilterDecision,
    models::{LABEL_INBOX, LABEL_UNREAD},
    transport::{
        InboundEnvelope, IngestOutcome, MailTransport, OutboundMessage, SendOutcome,
        TransportCapabilities, ensure_raw_rfc2822, ingest_inbound_rfc2822,
    },
};

type HmacSha256 = Hmac<Sha256>;

const DEFAULT_TIMEOUT_SECS: u64 = 30;
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
const SES_MAX_MESSAGE_BYTES: usize = 40 * 1024 * 1024;
const MAX_ERROR_SNIPPET_CHARS: usize = 512;

/// Configuration for [`SesTransport`] and S3 inbound fetches.
#[derive(Debug, Clone)]
pub struct SesConfig {
    pub region: String,
    pub endpoint: String,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub session_token: Option<String>,
    pub s3_endpoint: String,
    pub webhook_secret: Option<String>,
    pub default_from: String,
}

impl SesConfig {
    /// Build [`SesConfig`] from application [`Config`], validating custom endpoint URLs.
    pub fn from_config(config: &Config) -> AppResult<Self> {
        let region = non_empty_trimmed(Some(config.ses_region.as_str()))
            .unwrap_or("us-east-1")
            .to_string();

        let endpoint = match non_empty_trimmed(config.ses_endpoint.as_deref()) {
            Some(ep) => {
                Url::parse(ep).map_err(|e| {
                    AppError::Config(format!("Invalid NOGML_SES_ENDPOINT '{ep}': {e}"))
                })?;
                ep.trim_end_matches('/').to_string()
            }
            None => format!("https://email.{region}.amazonaws.com"),
        };

        let s3_endpoint = match non_empty_trimmed(config.ses_s3_endpoint.as_deref()) {
            Some(ep) => {
                Url::parse(ep).map_err(|e| {
                    AppError::Config(format!("Invalid NOGML_SES_S3_ENDPOINT '{ep}': {e}"))
                })?;
                ep.trim_end_matches('/').to_string()
            }
            None => format!("https://s3.{region}.amazonaws.com"),
        };

        Ok(Self {
            region,
            endpoint,
            access_key_id: non_empty_trimmed(config.ses_access_key_id.as_deref())
                .map(ToString::to_string),
            secret_access_key: non_empty_trimmed(config.ses_secret_access_key.as_deref())
                .map(ToString::to_string),
            session_token: non_empty_trimmed(config.ses_session_token.as_deref())
                .map(ToString::to_string),
            s3_endpoint,
            webhook_secret: non_empty_trimmed(config.ses_webhook_secret.as_deref())
                .map(ToString::to_string),
            default_from: config.user_email.clone(),
        })
    }

    fn credentials(&self) -> AppResult<AwsCredentials<'_>> {
        let access_key_id = self
            .access_key_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AppError::Config(
                    "NOGML_SES_ACCESS_KEY_ID must be configured for AWS SES/S3 requests"
                        .to_string(),
                )
            })?;
        let secret_access_key = self
            .secret_access_key
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AppError::Config(
                    "NOGML_SES_SECRET_ACCESS_KEY must be configured for AWS SES/S3 requests"
                        .to_string(),
                )
            })?;
        Ok(AwsCredentials {
            access_key_id,
            secret_access_key,
            session_token: self.session_token.as_deref().filter(|s| !s.is_empty()),
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct AwsCredentials<'a> {
    access_key_id: &'a str,
    secret_access_key: &'a str,
    session_token: Option<&'a str>,
}

/// Headers produced by AWS Signature Version 4 signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigV4Headers {
    pub authorization: String,
    pub amz_date: String,
    pub payload_hash: String,
    pub session_token: Option<String>,
}

fn non_empty_trimmed(val: Option<&str>) -> Option<&str> {
    val.map(str::trim).filter(|s| !s.is_empty())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn aws_uri_encode_bytes(bytes: &[u8], encode_slash: bool) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        let is_unreserved = b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'_' | b'.' | b'~')
            || (!encode_slash && b == b'/');
        if is_unreserved {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
    out
}

fn aws_uri_encode(input: &str, encode_slash: bool) -> String {
    aws_uri_encode_bytes(input.as_bytes(), encode_slash)
}

fn percent_decode_bytes(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn collapse_header_value(raw: &str) -> String {
    let trimmed = raw.trim();
    let mut out = String::with_capacity(trimmed.len());
    let mut in_space = false;
    for ch in trimmed.chars() {
        if ch == ' ' || ch == '\t' {
            if !in_space {
                out.push(' ');
                in_space = true;
            }
        } else {
            out.push(ch);
            in_space = false;
        }
    }
    out
}

fn canonical_query_string(url: &Url) -> String {
    let Some(raw_query) = url.query() else {
        return String::new();
    };
    if raw_query.is_empty() {
        return String::new();
    }

    let mut pairs: Vec<(String, String)> = raw_query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (k, v) = part.split_once('=').unwrap_or((part, ""));
            let k_dec = percent_decode_bytes(k);
            let v_dec = percent_decode_bytes(v);
            (
                aws_uri_encode_bytes(&k_dec, true),
                aws_uri_encode_bytes(&v_dec, true),
            )
        })
        .collect();

    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Sign an HTTP request using AWS Signature Version 4 (HMAC-SHA256).
#[allow(clippy::too_many_arguments)]
pub fn sign_aws_v4(
    method: &str,
    url: &Url,
    extra_headers: &[(&str, &str)],
    payload: &[u8],
    access_key_id: &str,
    secret_access_key: &str,
    session_token: Option<&str>,
    region: &str,
    service: &str,
    now: DateTime<Utc>,
) -> AppResult<SigV4Headers> {
    let host_str = url
        .host_str()
        .ok_or_else(|| AppError::Config(format!("AWS request URL '{url}' is missing a host")))?;
    let host_header = match url.port() {
        Some(port) => format!("{host_str}:{port}"),
        None => host_str.to_string(),
    };

    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();
    let payload_hash = hex_encode(&Sha256::digest(payload));

    let raw_path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let canonical_uri = aws_uri_encode_bytes(&percent_decode_bytes(raw_path), false);
    let canonical_query = canonical_query_string(url);

    let mut headers: Vec<(String, String)> = vec![
        ("host".to_string(), host_header),
        ("x-amz-content-sha256".to_string(), payload_hash.clone()),
        ("x-amz-date".to_string(), amz_date.clone()),
    ];

    let clean_token = session_token.map(str::trim).filter(|s| !s.is_empty());
    if let Some(tok) = clean_token {
        headers.push((
            "x-amz-security-token".to_string(),
            collapse_header_value(tok),
        ));
    }

    for (name, value) in extra_headers {
        let lower = name.trim().to_ascii_lowercase();
        if !lower.is_empty()
            && !matches!(
                lower.as_str(),
                "host" | "x-amz-date" | "x-amz-content-sha256" | "x-amz-security-token"
            )
        {
            headers.push((lower, collapse_header_value(value)));
        }
    }

    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let mut canonical_headers = String::new();
    let mut signed_names = Vec::with_capacity(headers.len());
    for (k, v) in &headers {
        canonical_headers.push_str(k);
        canonical_headers.push(':');
        canonical_headers.push_str(v);
        canonical_headers.push('\n');
        signed_names.push(k.as_str());
    }
    let signed_headers = signed_names.join(";");

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        canonical_uri,
        canonical_query,
        canonical_headers,
        signed_headers,
        payload_hash
    );

    let hashed_canonical_request = hex_encode(&Sha256::digest(canonical_request.as_bytes()));
    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{hashed_canonical_request}");

    let mut k_secret = Vec::with_capacity(4 + secret_access_key.len());
    k_secret.extend_from_slice(b"AWS4");
    k_secret.extend_from_slice(secret_access_key.as_bytes());
    let k_date = hmac_sha256(&k_secret, date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex_encode(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );

    Ok(SigV4Headers {
        authorization,
        amz_date,
        payload_hash,
        session_token: clean_token.map(ToString::to_string),
    })
}

fn build_http_client() -> reqwest::Client {
    crate::ensure_crypto_provider();
    reqwest::Client::builder()
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .connect_timeout(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS))
        .user_agent(concat!("nogml/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn truncate_snippet(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.chars().count() <= MAX_ERROR_SNIPPET_CHARS {
        trimmed.to_string()
    } else {
        let mut s: String = trimmed.chars().take(MAX_ERROR_SNIPPET_CHARS).collect();
        s.push_str("...");
        s
    }
}

/// AWS SESv2 [`MailTransport`] sending verbatim raw RFC 2822 bytes via
/// `POST {endpoint}/v2/email/outbound-emails`.
#[derive(Clone, Debug)]
pub struct SesTransport {
    config: SesConfig,
    http: reqwest::Client,
}

impl SesTransport {
    /// Construct a [`SesTransport`] from explicit [`SesConfig`].
    pub fn new(config: SesConfig) -> Self {
        Self {
            config,
            http: build_http_client(),
        }
    }

    /// Construct a [`SesTransport`] from application [`Config`].
    pub fn from_config(config: &Config) -> AppResult<Self> {
        Ok(Self::new(SesConfig::from_config(config)?))
    }

    /// Return the resolved [`SesConfig`].
    pub fn config(&self) -> &SesConfig {
        &self.config
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct SesSendEmailRequest {
    from_email_address: String,
    destination: SesDestination,
    content: SesEmailContent,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct SesDestination {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    to_addresses: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cc_addresses: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    bcc_addresses: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct SesEmailContent {
    raw: SesRawMessage,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct SesRawMessage {
    data: String,
}

#[derive(Debug, Deserialize)]
struct SesSendEmailResponse {
    #[serde(alias = "MessageId", alias = "messageId")]
    message_id: Option<String>,
}

#[async_trait]
impl MailTransport for SesTransport {
    fn name(&self) -> &'static str {
        "ses"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            provider: "ses".to_string(),
            supports_raw_mime: true,
            supports_scheduled_send: false,
            supports_idempotency_key: false,
            supports_inbound_webhooks: true,
            supports_delivery_webhooks: false,
            max_message_bytes: SES_MAX_MESSAGE_BYTES,
        }
    }

    async fn send(
        &self,
        msg: &OutboundMessage,
        _idempotency_key: Option<&str>,
    ) -> AppResult<SendOutcome> {
        let creds = self.config.credentials()?;
        let raw_bytes = ensure_raw_rfc2822(msg, &self.config.default_from)?;

        let mut from = if msg.from.trim().is_empty() {
            self.config.default_from.trim().to_string()
        } else {
            msg.from.trim().to_string()
        };
        let mut to = msg.to.clone();
        let mut cc = msg.cc.clone();
        let mut bcc = msg.bcc.clone();

        if (from.is_empty() || (to.is_empty() && cc.is_empty() && bcc.is_empty()))
            && let Ok(parsed) = crate::mime::parse_rfc2822(&raw_bytes)
        {
            if from.is_empty() && !parsed.from.trim().is_empty() {
                from = parsed.from;
            }
            if to.is_empty() && cc.is_empty() && bcc.is_empty() {
                to = parsed.to;
                cc = parsed.cc;
                bcc = parsed.bcc;
            }
        }

        if from.is_empty() {
            return Err(AppError::BadRequest(
                "Outbound message requires a non-empty From address".to_string(),
            ));
        }
        if to.is_empty() && cc.is_empty() && bcc.is_empty() {
            return Err(AppError::BadRequest(
                "Outbound message requires at least one recipient".to_string(),
            ));
        }

        let payload_obj = SesSendEmailRequest {
            from_email_address: from,
            destination: SesDestination {
                to_addresses: to,
                cc_addresses: cc,
                bcc_addresses: bcc,
            },
            content: SesEmailContent {
                raw: SesRawMessage {
                    data: general_purpose::STANDARD.encode(&raw_bytes),
                },
            },
        };
        let payload_bytes = serde_json::to_vec(&payload_obj)?;

        let url_str = format!(
            "{}/v2/email/outbound-emails",
            self.config.endpoint.trim_end_matches('/')
        );
        let url = Url::parse(&url_str)
            .map_err(|e| AppError::Config(format!("Invalid SES outbound URL '{url_str}': {e}")))?;

        let sig = sign_aws_v4(
            "POST",
            &url,
            &[("content-type", "application/json")],
            &payload_bytes,
            creds.access_key_id,
            creds.secret_access_key,
            creds.session_token,
            &self.config.region,
            "ses",
            Utc::now(),
        )?;

        let mut req = self
            .http
            .post(url)
            .header("content-type", "application/json")
            .header("authorization", sig.authorization)
            .header("x-amz-date", sig.amz_date)
            .header("x-amz-content-sha256", sig.payload_hash)
            .body(payload_bytes);

        if let Some(tok) = sig.session_token {
            req = req.header("x-amz-security-token", tok);
        }

        let resp = req.send().await?;
        let status = resp.status();
        let body = resp.text().await?;

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(AppError::RateLimited(format!(
                "AWS SES rate limited: {}",
                truncate_snippet(&body)
            )));
        }
        if !status.is_success() {
            return Err(AppError::Upstream {
                status: status.as_u16(),
                message: format!("AWS SES send failed: {}", truncate_snippet(&body)),
            });
        }

        let parsed: SesSendEmailResponse =
            serde_json::from_str(&body).map_err(|e| AppError::Upstream {
                status: status.as_u16(),
                message: format!("Invalid AWS SES JSON response: {e}"),
            })?;
        let provider_message_id = parsed
            .message_id
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| AppError::Upstream {
                status: status.as_u16(),
                message: "AWS SES response missing MessageId".to_string(),
            })?;

        Ok(SendOutcome {
            provider: self.name().to_string(),
            provider_message_id,
        })
    }
}

// ============================================================================
// Inbound SNS / SES Webhook (`POST /webhooks/ses`)
// ============================================================================

/// Mount AWS SES/SNS inbound webhook routes (`POST /webhooks/ses`).
pub fn ses_router() -> Router<AppState> {
    Router::new().route("/webhooks/ses", post(ses_webhook_handler))
}

#[derive(Debug, Deserialize)]
struct SnsEnvelope {
    #[serde(rename = "Type")]
    envelope_type: Option<String>,
    #[serde(rename = "MessageId")]
    message_id: Option<String>,
    #[serde(rename = "TopicArn")]
    topic_arn: Option<String>,
    #[serde(rename = "Message")]
    message: Option<String>,
    #[serde(rename = "SubscribeURL")]
    subscribe_url: Option<String>,
    #[serde(rename = "Timestamp")]
    timestamp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SesNotification {
    #[serde(alias = "eventType")]
    notification_type: String,
    #[serde(default)]
    mail: Option<SesMailMetadata>,
    #[serde(default)]
    receipt: Option<SesReceipt>,
    #[serde(default)]
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SesMailMetadata {
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    message_id: Option<String>,
    #[serde(default)]
    destination: Vec<String>,
    #[serde(default)]
    common_headers: Option<SesCommonHeaders>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SesCommonHeaders {
    #[serde(default)]
    from: Vec<String>,
    #[serde(default)]
    to: Vec<String>,
    #[serde(default)]
    cc: Vec<String>,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    message_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SesReceipt {
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    spf_verdict: Option<SesVerdict>,
    #[serde(default)]
    dkim_verdict: Option<SesVerdict>,
    #[serde(default)]
    dmarc_verdict: Option<SesVerdict>,
    #[serde(default)]
    spam_verdict: Option<SesVerdict>,
    #[serde(default)]
    virus_verdict: Option<SesVerdict>,
    #[serde(default)]
    action: Option<SesReceiptAction>,
}

#[derive(Debug, Deserialize)]
struct SesVerdict {
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SesReceiptAction {
    #[serde(rename = "type", default)]
    action_type: Option<String>,
    #[serde(default)]
    bucket_name: Option<String>,
    #[serde(default)]
    object_key: Option<String>,
    #[serde(default)]
    encoding: Option<String>,
}

fn verify_ses_webhook_secret(
    headers: &HeaderMap,
    raw_query: Option<&str>,
    expected_secret: &str,
) -> AppResult<()> {
    let allowed = [expected_secret.to_string()];

    for header_name in [
        "x-nogml-webhook-secret",
        "x-ses-webhook-secret",
        "x-webhook-secret",
    ] {
        if let Some(val) = headers.get(header_name).and_then(|v| v.to_str().ok())
            && constant_time_token_matches(val.trim(), &allowed)
        {
            return Ok(());
        }
    }

    if let Some(query) = raw_query {
        for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
            if (k == "secret" || k == "token") && constant_time_token_matches(v.trim(), &allowed) {
                return Ok(());
            }
        }
    }

    Err(AppError::Unauthorized(
        "Invalid or missing SES webhook secret".to_string(),
    ))
}

fn build_s3_object_url(s3_endpoint: &str, bucket: &str, object_key: &str) -> AppResult<Url> {
    let encoded_bucket = aws_uri_encode(bucket.trim(), true);
    let trimmed_key = object_key.trim_start_matches('/');
    let encoded_key = trimmed_key
        .split('/')
        .map(|seg| aws_uri_encode(seg, true))
        .collect::<Vec<_>>()
        .join("/");

    let url_str = format!(
        "{}/{}/{}",
        s3_endpoint.trim_end_matches('/'),
        encoded_bucket,
        encoded_key
    );
    Url::parse(&url_str)
        .map_err(|e| AppError::Config(format!("Invalid S3 object URL '{url_str}': {e}")))
}

async fn fetch_s3_object_bytes(
    ses_cfg: &SesConfig,
    bucket: &str,
    object_key: &str,
) -> AppResult<Vec<u8>> {
    let creds = ses_cfg.credentials()?;
    let url = build_s3_object_url(&ses_cfg.s3_endpoint, bucket, object_key)?;
    let sig = sign_aws_v4(
        "GET",
        &url,
        &[],
        b"",
        creds.access_key_id,
        creds.secret_access_key,
        creds.session_token,
        &ses_cfg.region,
        "s3",
        Utc::now(),
    )?;

    let http = build_http_client();
    let mut req = http
        .get(url)
        .header("authorization", sig.authorization)
        .header("x-amz-date", sig.amz_date)
        .header("x-amz-content-sha256", sig.payload_hash);
    if let Some(tok) = sig.session_token {
        req = req.header("x-amz-security-token", tok);
    }

    let resp = req.send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Upstream {
            status: status.as_u16(),
            message: format!(
                "Failed to fetch S3 object s3://{bucket}/{object_key}: {}",
                truncate_snippet(&body)
            ),
        });
    }

    Ok(resp.bytes().await?.to_vec())
}

fn decode_inline_ses_content(content: &str, encoding: Option<&str>) -> AppResult<Vec<u8>> {
    if encoding.is_some_and(|e| e.eq_ignore_ascii_case("utf8") || e.eq_ignore_ascii_case("utf-8")) {
        return Ok(content.as_bytes().to_vec());
    }
    let cleaned: String = content
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    general_purpose::STANDARD
        .decode(cleaned.as_bytes())
        .map_err(|e| AppError::BadRequest(format!("Invalid base64 SES content payload: {e}")))
}

fn format_ses_auth_results(receipt: &SesReceipt) -> Option<String> {
    let mut parts = Vec::new();
    for (label, verdict) in [
        ("spf", receipt.spf_verdict.as_ref()),
        ("dkim", receipt.dkim_verdict.as_ref()),
        ("dmarc", receipt.dmarc_verdict.as_ref()),
        ("spam", receipt.spam_verdict.as_ref()),
        ("virus", receipt.virus_verdict.as_ref()),
    ] {
        if let Some(v) = verdict {
            let status = v.status.trim().to_ascii_lowercase();
            if !status.is_empty() {
                parts.push(format!("{label}={status}"));
            }
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(format!("ses; {}", parts.join("; ")))
    }
}

fn parse_timestamp_ms(candidates: &[Option<&str>]) -> Option<i64> {
    for candidate in candidates.iter().flatten() {
        if let Ok(dt) = DateTime::parse_from_rfc3339(candidate.trim()) {
            return Some(dt.timestamp_millis());
        }
    }
    None
}

/// Axum handler for `POST /webhooks/ses`.
///
/// Exempt from bearer auth; enforces optional shared secret verification via
/// `NOGML_SES_WEBHOOK_SECRET` (header `X-Nogml-Webhook-Secret` / `X-SES-Webhook-Secret` /
/// `X-Webhook-Secret`, or `?secret=` / `?token=`). Handles SNS `SubscriptionConfirmation`
/// and `Notification` payloads carrying SES `Received` events (both inline base64 `content`
/// and S3 action downloads signed with SigV4).
pub async fn ses_webhook_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    body: Bytes,
) -> AppResult<Response> {
    if let Some(secret) = non_empty_trimmed(state.config.ses_webhook_secret.as_deref()) {
        verify_ses_webhook_secret(&headers, raw_query.as_deref(), secret)?;
    } else {
        tracing::warn!(
            "SES webhook secret is not configured; accepting webhook without shared-secret check (dev mode)"
        );
    }

    let sns: SnsEnvelope = serde_json::from_slice(&body)?;
    let notification: SesNotification = match sns.envelope_type.as_deref() {
        Some("SubscriptionConfirmation") => {
            tracing::info!(
                topic_arn = sns.topic_arn.as_deref().unwrap_or(""),
                message_id = sns.message_id.as_deref().unwrap_or(""),
                subscribe_url = sns.subscribe_url.as_deref().unwrap_or(""),
                "Received AWS SNS SubscriptionConfirmation for SES webhook"
            );
            return Ok((
                StatusCode::OK,
                Json(json!({
                    "status": "subscription_confirmation",
                    "topic_arn": sns.topic_arn,
                    "subscribe_url": sns.subscribe_url,
                })),
            )
                .into_response());
        }
        Some("UnsubscribeConfirmation") => {
            tracing::info!(
                topic_arn = sns.topic_arn.as_deref().unwrap_or(""),
                "Received AWS SNS UnsubscribeConfirmation for SES webhook"
            );
            return Ok((
                StatusCode::OK,
                Json(json!({
                    "status": "unsubscribe_confirmation",
                    "topic_arn": sns.topic_arn,
                })),
            )
                .into_response());
        }
        Some("Notification") => {
            let msg_str = sns.message.as_deref().ok_or_else(|| {
                AppError::BadRequest("SNS Notification payload missing 'Message' field".to_string())
            })?;
            serde_json::from_str(msg_str)?
        }
        Some(other) => {
            tracing::debug!(sns_type = %other, "Ignoring unrecognized SNS envelope type");
            return Ok((
                StatusCode::OK,
                Json(json!({
                    "status": "ignored",
                    "sns_type": other,
                })),
            )
                .into_response());
        }
        None => serde_json::from_slice(&body)?,
    };

    if !notification
        .notification_type
        .eq_ignore_ascii_case("received")
    {
        tracing::debug!(
            notification_type = %notification.notification_type,
            "Ignoring non-Received SES notification"
        );
        return Ok((
            StatusCode::OK,
            Json(json!({
                "status": "ignored",
                "notification_type": notification.notification_type,
            })),
        )
            .into_response());
    }

    let action = notification
        .receipt
        .as_ref()
        .and_then(|r| r.action.as_ref());

    let (raw_rfc2822, source) = if let Some(inline) = notification
        .content
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        let encoding = action.and_then(|a| a.encoding.as_deref());
        let bytes = decode_inline_ses_content(inline, encoding)?;
        (bytes, "ses_inbound".to_string())
    } else if let Some(act) = action
        && let (Some(bucket), Some(key)) = (
            non_empty_trimmed(act.bucket_name.as_deref()),
            non_empty_trimmed(act.object_key.as_deref()),
        )
    {
        let _action_type = act.action_type.as_deref().unwrap_or("S3");
        let ses_cfg = SesConfig::from_config(&state.config)?;
        let bytes = fetch_s3_object_bytes(&ses_cfg, bucket, key).await?;
        (bytes, "ses_s3".to_string())
    } else {
        return Err(AppError::BadRequest(
            "SES Received notification must contain either inline 'content' or an S3 'receipt.action' with bucketName and objectKey"
                .to_string(),
        ));
    };

    let mail = notification.mail.as_ref();
    let common = mail.and_then(|m| m.common_headers.as_ref());
    let received_at_ms = parse_timestamp_ms(&[
        notification
            .receipt
            .as_ref()
            .and_then(|r| r.timestamp.as_deref()),
        mail.and_then(|m| m.timestamp.as_deref()),
        sns.timestamp.as_deref(),
    ]);

    let fallback_from = common
        .and_then(|c| c.from.first().cloned())
        .or_else(|| mail.and_then(|m| m.source.clone()));
    let fallback_to = common
        .map(|c| c.to.clone())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| mail.map(|m| m.destination.clone()).unwrap_or_default());
    let fallback_cc = common.map(|c| c.cc.clone()).unwrap_or_default();
    let fallback_subject = common.and_then(|c| c.subject.clone());
    let fallback_rfc822_message_id = common.and_then(|c| c.message_id.clone());
    let provider_id = mail
        .and_then(|m| m.message_id.clone())
        .filter(|s| !s.trim().is_empty());

    let auth_results = notification
        .receipt
        .as_ref()
        .and_then(format_ses_auth_results);

    let mut recipient_candidates: Vec<String> = Vec::new();
    if let Some(m) = mail {
        recipient_candidates.extend(m.destination.iter().cloned());
    }
    if let Some(c) = common {
        recipient_candidates.extend(c.to.iter().cloned());
        recipient_candidates.extend(c.cc.iter().cloned());
    }
    if let Ok(parsed) = crate::mime::parse_rfc2822(&raw_rfc2822) {
        recipient_candidates.extend(parsed.to);
        recipient_candidates.extend(parsed.cc);
        recipient_candidates.extend(parsed.bcc);
        for hdr in parsed.headers {
            if matches!(
                hdr.name.to_ascii_lowercase().as_str(),
                "delivered-to" | "x-original-to" | "envelope-to"
            ) {
                recipient_candidates.push(hdr.value);
            }
        }
    }

    let target_mailboxes = state
        .config
        .resolve_inbound_mailboxes(&recipient_candidates);
    if target_mailboxes.is_empty() {
        tracing::info!("Ignoring SES inbound email with no matching local mailbox");
        return Ok((
            StatusCode::OK,
            Json(json!({
                "status": "ignored",
                "reason": "no_matching_local_mailbox",
            })),
        )
            .into_response());
    }

    let base_envelope = InboundEnvelope {
        raw_rfc2822,
        source,
        provider_id,
        sender_ip: None,
        authentication_results: auth_results,
        received_at_ms,
        default_labels: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
        extra_attachments: Vec::new(),
        fallback_from,
        fallback_to,
        fallback_cc,
        fallback_bcc: Vec::new(),
        fallback_subject,
        fallback_text: None,
        fallback_html: None,
        fallback_rfc822_message_id,
        fallback_in_reply_to: None,
        fallback_references: None,
    };

    if target_mailboxes.len() == 1 {
        let mb = &target_mailboxes[0];
        let mb_state = state.for_mailbox(mb);
        let outcome = ingest_inbound_rfc2822(
            mb_state.store.as_ref(),
            &mb_state.events,
            mb_state.filter.as_ref(),
            base_envelope,
        )
        .await?;

        return match outcome {
            IngestOutcome::Stored { message, decision } => {
                mb_state.post_store_message(&message).await?;
                let filter_label = match decision {
                    FilterDecision::Allow => "allow",
                    FilterDecision::Spam { .. } => "spam",
                    FilterDecision::Reject { .. } => "reject",
                    FilterDecision::Mutate { .. } => "mutate",
                };
                Ok((
                    StatusCode::OK,
                    Json(json!({
                        "status": "received",
                        "mailbox_id": mb,
                        "message_id": message.id,
                        "thread_id": message.thread_id,
                        "labels": message.label_ids,
                        "filter_decision": filter_label,
                    })),
                )
                    .into_response())
            }
            IngestOutcome::Duplicate { message } => Ok((
                StatusCode::OK,
                Json(json!({
                    "status": "duplicate",
                    "mailbox_id": mb,
                    "message_id": message.id,
                    "thread_id": message.thread_id,
                })),
            )
                .into_response()),
            IngestOutcome::Rejected { reason } => Ok((
                StatusCode::OK,
                Json(json!({
                    "status": "rejected",
                    "mailbox_id": mb,
                    "reason": reason,
                })),
            )
                .into_response()),
        };
    }

    let mut deliveries = Vec::with_capacity(target_mailboxes.len());
    let mut first_received: Option<(String, String, Vec<String>, &'static str)> = None;
    let mut any_received = false;
    let mut any_duplicate = false;
    let mut first_rejected: Option<String> = None;

    for mb in &target_mailboxes {
        let mb_state = state.for_mailbox(mb);
        let outcome = ingest_inbound_rfc2822(
            mb_state.store.as_ref(),
            &mb_state.events,
            mb_state.filter.as_ref(),
            base_envelope.clone(),
        )
        .await?;

        match outcome {
            IngestOutcome::Stored { message, decision } => {
                mb_state.post_store_message(&message).await?;
                let filter_label = match decision {
                    FilterDecision::Allow => "allow",
                    FilterDecision::Spam { .. } => "spam",
                    FilterDecision::Reject { .. } => "reject",
                    FilterDecision::Mutate { .. } => "mutate",
                };
                any_received = true;
                if first_received.is_none() {
                    first_received = Some((
                        message.id.clone(),
                        message.thread_id.clone(),
                        message.label_ids.clone(),
                        filter_label,
                    ));
                }
                deliveries.push(json!({
                    "mailbox_id": mb,
                    "status": "received",
                    "message_id": message.id,
                    "thread_id": message.thread_id,
                    "labels": message.label_ids,
                    "filter_decision": filter_label,
                }));
            }
            IngestOutcome::Duplicate { message } => {
                any_duplicate = true;
                deliveries.push(json!({
                    "mailbox_id": mb,
                    "status": "duplicate",
                    "message_id": message.id,
                    "thread_id": message.thread_id,
                }));
            }
            IngestOutcome::Rejected { reason } => {
                if first_rejected.is_none() {
                    first_rejected = Some(reason.clone());
                }
                deliveries.push(json!({
                    "mailbox_id": mb,
                    "status": "rejected",
                    "reason": reason,
                }));
            }
        }
    }

    if let Some((msg_id, thread_id, labels, filter_label)) = first_received {
        Ok((
            StatusCode::OK,
            Json(json!({
                "status": "received",
                "message_id": msg_id,
                "thread_id": thread_id,
                "labels": labels,
                "filter_decision": filter_label,
                "deliveries": deliveries,
            })),
        )
            .into_response())
    } else if any_duplicate && !any_received {
        Ok((
            StatusCode::OK,
            Json(json!({
                "status": "duplicate",
                "deliveries": deliveries,
            })),
        )
            .into_response())
    } else {
        Ok((
            StatusCode::OK,
            Json(json!({
                "status": "rejected",
                "reason": first_rejected.unwrap_or_else(|| "rejected".to_string()),
                "deliveries": deliveries,
            })),
        )
            .into_response())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use chrono::TimeZone;
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use tower::ServiceExt;
    use wiremock::{
        Match, Mock, MockServer, Request as WiremockRequest, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;
    use crate::{
        blob::{BlobStore, MemoryBlobStore, raw_message_blob_key},
        build_router,
        events::{EventSource, MailEvent},
        filter::{InboundFilter, InboundMessage},
        resend::{HttpResendClient, ResendClient},
        storage::{MailStore, MemoryStore},
    };

    struct SigV4AuthMatcher {
        region: String,
        service: String,
        access_key: String,
    }

    impl Match for SigV4AuthMatcher {
        fn matches(&self, req: &WiremockRequest) -> bool {
            let Some(auth) = req
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
            else {
                return false;
            };
            let has_date = req.headers.get("x-amz-date").is_some();
            let has_hash = req.headers.get("x-amz-content-sha256").is_some();
            let scope_fragment = format!("/{}/{}/aws4_request", self.region, self.service);
            auth.starts_with(&format!("AWS4-HMAC-SHA256 Credential={}/", self.access_key))
                && auth.contains(&scope_fragment)
                && auth.contains("SignedHeaders=")
                && auth.contains("Signature=")
                && has_date
                && has_hash
        }
    }

    struct RejectAndTagFilter;

    #[async_trait]
    impl InboundFilter for RejectAndTagFilter {
        async fn evaluate(&self, msg: &InboundMessage) -> AppResult<FilterDecision> {
            if msg.subject.contains("DROP_ME") {
                Ok(FilterDecision::Reject {
                    reason: "matched DROP_ME".to_string(),
                })
            } else {
                Ok(FilterDecision::Mutate {
                    add_labels: vec!["SES_VERIFIED".to_string()],
                    remove_labels: vec![],
                    skip_inbox: false,
                })
            }
        }

        fn backend_name(&self) -> &'static str {
            "reject_and_tag"
        }
    }

    #[test]
    fn sigv4_matches_aws_reference_vector() {
        // Standard AWS SigV4 test vector (GET S3 object).
        let url = Url::parse("https://examplebucket.s3.amazonaws.com/test.txt").unwrap();
        let now = Utc.with_ymd_and_hms(2013, 5, 24, 0, 0, 0).unwrap();
        let sig = sign_aws_v4(
            "GET",
            &url,
            &[("range", "bytes=0-9")],
            b"",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            None,
            "us-east-1",
            "s3",
            now,
        )
        .unwrap();

        assert_eq!(sig.amz_date, "20130524T000000Z");
        assert_eq!(
            sig.payload_hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sig.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[tokio::test]
    async fn ses_transport_sends_verbatim_raw_mime_with_sigv4() {
        let server = MockServer::start().await;
        let raw_mime = concat!(
            "From: Agent <agent@example.com>\r\n",
            "To: Alice <alice@example.com>\r\n",
            "Cc: Bob <bob@example.com>\r\n",
            "Subject: Verbatim SES MIME\r\n",
            "Message-ID: <ses-raw-1@example.com>\r\n",
            "X-Custom-Signature: keep-exact-bytes-0123456789\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "Hello via SESv2 raw MIME!\r\n"
        )
        .as_bytes()
        .to_vec();

        let expected_b64 = general_purpose::STANDARD.encode(&raw_mime);

        Mock::given(method("POST"))
            .and(path("/v2/email/outbound-emails"))
            .and(SigV4AuthMatcher {
                region: "us-west-2".to_string(),
                service: "ses".to_string(),
                access_key: "AKIA_TEST_SES".to_string(),
            })
            .respond_with(move |req: &WiremockRequest| {
                assert_eq!(
                    req.headers
                        .get("x-amz-security-token")
                        .and_then(|v| v.to_str().ok()),
                    Some("session-tok-1")
                );
                let body: Value = serde_json::from_slice(&req.body).unwrap();
                assert_eq!(body["FromEmailAddress"], "agent@example.com");
                assert_eq!(
                    body["Destination"]["ToAddresses"],
                    json!(["alice@example.com"])
                );
                assert_eq!(
                    body["Destination"]["CcAddresses"],
                    json!(["bob@example.com"])
                );
                assert_eq!(
                    body["Destination"]["BccAddresses"],
                    json!(["audit@example.com"])
                );
                assert_eq!(body["Content"]["Raw"]["Data"], expected_b64);

                let decoded = general_purpose::STANDARD
                    .decode(body["Content"]["Raw"]["Data"].as_str().unwrap())
                    .unwrap();
                assert_eq!(decoded, raw_mime);

                ResponseTemplate::new(200).set_body_json(json!({
                    "MessageId": "0101018f-ses-msg-id"
                }))
            })
            .expect(1)
            .mount(&server)
            .await;

        let mut cfg = Config::for_test();
        cfg.ses_region = "us-west-2".to_string();
        cfg.ses_endpoint = Some(server.uri());
        cfg.ses_access_key_id = Some("AKIA_TEST_SES".to_string());
        cfg.ses_secret_access_key = Some("secret-key-xyz".to_string());
        cfg.ses_session_token = Some("session-tok-1".to_string());

        let transport = SesTransport::from_config(&cfg).unwrap();
        assert_eq!(transport.name(), "ses");
        let caps = transport.capabilities();
        assert_eq!(caps.provider, "ses");
        assert!(caps.supports_raw_mime);
        assert!(caps.supports_inbound_webhooks);

        let outcome = transport
            .send(
                &OutboundMessage {
                    from: "agent@example.com".to_string(),
                    to: vec!["alice@example.com".to_string()],
                    cc: vec!["bob@example.com".to_string()],
                    bcc: vec!["audit@example.com".to_string()],
                    subject: "Verbatim SES MIME".to_string(),
                    raw_rfc2822: general_purpose::STANDARD
                        .decode(
                            general_purpose::STANDARD.encode(
                                concat!(
                                    "From: Agent <agent@example.com>\r\n",
                                    "To: Alice <alice@example.com>\r\n",
                                    "Cc: Bob <bob@example.com>\r\n",
                                    "Subject: Verbatim SES MIME\r\n",
                                    "Message-ID: <ses-raw-1@example.com>\r\n",
                                    "X-Custom-Signature: keep-exact-bytes-0123456789\r\n",
                                    "MIME-Version: 1.0\r\n",
                                    "Content-Type: text/plain; charset=utf-8\r\n",
                                    "\r\n",
                                    "Hello via SESv2 raw MIME!\r\n"
                                )
                                .as_bytes(),
                            ),
                        )
                        .unwrap(),
                    ..Default::default()
                },
                None,
            )
            .await
            .expect("SES send should succeed");

        assert_eq!(outcome.provider, "ses");
        assert_eq!(outcome.provider_message_id, "0101018f-ses-msg-id");
    }

    #[tokio::test]
    async fn ses_webhook_handles_secret_subscription_inline_and_s3_ingestion() {
        let s3_server = MockServer::start().await;

        let s3_raw_eml = concat!(
            "From: Carol <carol@external.org>\r\n",
            "To: agent@example.com\r\n",
            "Subject: Re: Inline SES thread\r\n",
            "Message-ID: <ses-s3-reply@external.org>\r\n",
            "In-Reply-To: <ses-inline-root@external.org>\r\n",
            "References: <ses-inline-root@external.org>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "Fetched verbatim from S3!\r\n"
        )
        .as_bytes()
        .to_vec();

        Mock::given(method("GET"))
            .and(path("/mail-archive/inbound/msg-2.eml"))
            .and(SigV4AuthMatcher {
                region: "us-east-1".to_string(),
                service: "s3".to_string(),
                access_key: "AKIA_S3_KEY".to_string(),
            })
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(s3_raw_eml.clone(), "message/rfc822"),
            )
            .expect(1)
            .mount(&s3_server)
            .await;

        let mut cfg = Config::for_test();
        cfg.auth_tokens = vec!["bearer-only-for-api".to_string()];
        cfg.ses_region = "us-east-1".to_string();
        cfg.ses_s3_endpoint = Some(s3_server.uri());
        cfg.ses_access_key_id = Some("AKIA_S3_KEY".to_string());
        cfg.ses_secret_access_key = Some("s3-secret-key".to_string());
        cfg.ses_webhook_secret = Some("ses-shared-secret".to_string());

        let store = Arc::new(MemoryStore::new(&cfg.user_email));
        let blobs = Arc::new(MemoryBlobStore::new());
        let resend: Arc<dyn ResendClient> = Arc::new(HttpResendClient::from_config(&cfg));
        let state = AppState::with_backends(cfg, store.clone(), resend)
            .with_blobs(blobs.clone())
            .with_filter(Arc::new(RejectAndTagFilter));

        let mut events_rx = state.events.subscribe();
        let app = build_router(state.clone());

        // 1. Missing shared secret -> 401 (even though route is exempt from bearer auth)
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/ses")
                    .header("content-type", "text/plain; charset=UTF-8")
                    .body(Body::from(
                        json!({
                            "Type": "SubscriptionConfirmation",
                            "TopicArn": "arn:aws:sns:us-east-1:123456789012:ses-in",
                            "SubscribeURL": "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // 2. SNS SubscriptionConfirmation with secret header & text/plain content-type -> 200
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/ses")
                    .header("content-type", "text/plain; charset=UTF-8")
                    .header("x-nogml-webhook-secret", "ses-shared-secret")
                    .body(Body::from(
                        json!({
                            "Type": "SubscriptionConfirmation",
                            "TopicArn": "arn:aws:sns:us-east-1:123456789012:ses-in",
                            "SubscribeURL": "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&Token=abc"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(body["status"], "subscription_confirmation");

        // 3. Inline base64 SES Notification (with ?secret= query param) -> stored + blob mirrored + event published
        let inline_raw = concat!(
            "From: Alice <alice@external.org>\r\n",
            "To: agent@example.com\r\n",
            "Subject: Inline SES thread\r\n",
            "Message-ID: <ses-inline-root@external.org>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "Hello from inline SNS!\r\n"
        );
        let ses_inline_msg = json!({
            "notificationType": "Received",
            "mail": {
                "timestamp": "2026-05-01T12:00:00.000Z",
                "source": "alice@external.org",
                "messageId": "ses-inline-1",
                "destination": ["agent@example.com"]
            },
            "receipt": {
                "timestamp": "2026-05-01T12:00:01.000Z",
                "spfVerdict": { "status": "PASS" },
                "dkimVerdict": { "status": "PASS" },
                "action": { "type": "SNS", "encoding": "Base64" }
            },
            "content": general_purpose::STANDARD.encode(inline_raw.as_bytes())
        });
        let sns_inline = json!({
            "Type": "Notification",
            "MessageId": "sns-1",
            "TopicArn": "arn:aws:sns:us-east-1:123456789012:ses-in",
            "Message": ses_inline_msg.to_string()
        });

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/ses?secret=ses-shared-secret")
                    .header("content-type", "text/plain; charset=UTF-8")
                    .body(Body::from(sns_inline.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let inline_resp: Value =
            serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(inline_resp["status"], "received");
        assert_eq!(inline_resp["filter_decision"], "mutate");
        let root_msg_id = inline_resp["message_id"].as_str().unwrap().to_string();
        let root_thread_id = inline_resp["thread_id"].as_str().unwrap().to_string();

        // Check MailStore + BlobStore + EventBus
        let stored_root = store.get_message(&root_msg_id).await.unwrap().unwrap();
        assert_eq!(stored_root.raw_rfc2822, inline_raw.as_bytes());
        assert!(stored_root.label_ids.contains(&"SES_VERIFIED".to_string()));
        assert_eq!(
            blobs
                .get(&raw_message_blob_key(&root_msg_id))
                .await
                .unwrap(),
            Some(inline_raw.as_bytes().to_vec())
        );
        let ev = events_rx.try_recv().unwrap();
        assert_eq!(ev.source, EventSource::SesInbound);
        assert!(matches!(ev.event, MailEvent::MessageReceived { .. }));

        // 4. Duplicate replay returns status=duplicate
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/ses?secret=ses-shared-secret")
                    .header("content-type", "application/json")
                    .body(Body::from(sns_inline.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let dup_resp: Value =
            serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(dup_resp["status"], "duplicate");
        assert_eq!(dup_resp["message_id"], root_msg_id);

        // 5. S3 action Notification fetches via SigV4 S3 GET, threads with root message, mirrors blob
        let ses_s3_msg = json!({
            "notificationType": "Received",
            "mail": {
                "timestamp": "2026-05-01T12:05:00.000Z",
                "source": "carol@external.org",
                "messageId": "ses-s3-2",
                "destination": ["agent@example.com"]
            },
            "receipt": {
                "timestamp": "2026-05-01T12:05:01.000Z",
                "action": {
                    "type": "S3",
                    "bucketName": "mail-archive",
                    "objectKey": "inbound/msg-2.eml"
                }
            }
        });
        let sns_s3 = json!({
            "Type": "Notification",
            "MessageId": "sns-2",
            "TopicArn": "arn:aws:sns:us-east-1:123456789012:ses-in",
            "Message": ses_s3_msg.to_string()
        });

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/ses")
                    .header("x-ses-webhook-secret", "ses-shared-secret")
                    .header("content-type", "text/plain; charset=UTF-8")
                    .body(Body::from(sns_s3.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let s3_resp: Value =
            serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(s3_resp["status"], "received");
        assert_eq!(s3_resp["thread_id"], root_thread_id);
        let s3_msg_id = s3_resp["message_id"].as_str().unwrap();
        let stored_s3 = store.get_message(s3_msg_id).await.unwrap().unwrap();
        assert_eq!(stored_s3.raw_rfc2822, s3_raw_eml);
        assert_eq!(stored_s3.source, "ses_s3");
        assert_eq!(
            blobs.get(&raw_message_blob_key(s3_msg_id)).await.unwrap(),
            Some(s3_raw_eml)
        );

        // 6. InboundFilter Reject drops message before MailStore
        let rejected_raw = b"From: spam@bad.org\r\nTo: agent@example.com\r\nSubject: DROP_ME spam\r\nMessage-ID: <drop@bad.org>\r\n\r\nbuy now\r\n";
        let ses_reject_msg = json!({
            "notificationType": "Received",
            "mail": { "messageId": "ses-rej-3" },
            "receipt": { "action": { "type": "SNS", "encoding": "Base64" } },
            "content": general_purpose::STANDARD.encode(rejected_raw)
        });
        let sns_reject = json!({
            "Type": "Notification",
            "Message": ses_reject_msg.to_string()
        });

        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/ses")
                    .header("x-webhook-secret", "ses-shared-secret")
                    .header("content-type", "application/json")
                    .body(Body::from(sns_reject.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let rej_resp: Value =
            serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(rej_resp["status"], "rejected");
        assert_eq!(rej_resp["reason"], "matched DROP_ME");
        assert!(
            store
                .find_message_by_rfc_message_id("<drop@bad.org>")
                .await
                .unwrap()
                .is_none()
        );
    }
}
