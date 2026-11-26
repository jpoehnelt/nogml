//! Rspamd `/checkv2` HTTP spam-scoring filter (`RspamdFilter`).
//!
//! Sends raw RFC 2822 bytes to an Rspamd HTTP worker (`POST {rspamd_url}/checkv2`),
//! maps Rspamd's action and score to `Allow`, `Spam`, or `Reject`, and fails open
//! on network/timeout errors unless `fail_closed = true`.

use std::{collections::HashMap, time::Duration};

use async_trait::async_trait;
use reqwest::header::HeaderValue;
use serde::Deserialize;
use serde_json::Value;

use crate::{
    config::{Config, RspamdRejectAction},
    error::AppResult,
    filter::{FilterDecision, InboundFilter, InboundMessage},
    net_guard::{DEFAULT_FILTER_MAX_BODY_BYTES, read_bounded_bytes},
};

/// Configuration for [`RspamdFilter`].
#[derive(Debug, Clone)]
pub struct RspamdConfig {
    pub base_url: String,
    pub password: Option<String>,
    pub timeout: Duration,
    pub spam_threshold: Option<f32>,
    pub reject_action: RspamdRejectAction,
    pub fail_closed: bool,
}

impl RspamdConfig {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            password: None,
            timeout: Duration::from_secs(5),
            spam_threshold: None,
            reject_action: RspamdRejectAction::Reject,
            fail_closed: false,
        }
    }

    pub fn from_config(config: &Config) -> Option<Self> {
        let url = config
            .rspamd_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())?;
        Some(Self {
            base_url: url.to_string(),
            password: config
                .rspamd_password
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            timeout: Duration::from_millis(config.rspamd_timeout_ms.max(1)),
            spam_threshold: config.rspamd_spam_threshold,
            reject_action: config.rspamd_reject_action,
            fail_closed: config.rspamd_fail_closed,
        })
    }
}

#[derive(Debug, Deserialize)]
struct RspamdResponse {
    #[serde(default)]
    score: f32,
    #[serde(default)]
    required_score: Option<f32>,
    #[serde(default)]
    action: String,
    #[serde(default)]
    symbols: HashMap<String, Value>,
}

/// [`InboundFilter`] backed by an Rspamd HTTP `/checkv2` scanner.
#[derive(Clone)]
pub struct RspamdFilter {
    config: RspamdConfig,
    client: reqwest::Client,
}

impl RspamdFilter {
    pub fn new(config: RspamdConfig) -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(config.timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { config, client }
    }

    pub fn from_config(config: &Config) -> Option<Self> {
        RspamdConfig::from_config(config).map(Self::new)
    }

    fn endpoint(&self) -> String {
        format!("{}/checkv2", self.config.base_url.trim_end_matches('/'))
    }

    fn on_error(&self, detail: &str) -> FilterDecision {
        tracing::warn!(
            rspamd_url = %self.config.base_url,
            fail_closed = self.config.fail_closed,
            error = %detail,
            "Rspamd filter check failed"
        );
        if self.config.fail_closed {
            FilterDecision::Reject {
                reason: format!("Rspamd unavailable (fail_closed): {detail}"),
            }
        } else {
            FilterDecision::Allow
        }
    }

    fn format_reason(resp: &RspamdResponse) -> String {
        let mut ranked: Vec<(&str, f64)> = resp
            .symbols
            .iter()
            .map(|(name, val)| {
                let s = val.get("score").and_then(Value::as_f64).unwrap_or(0.0);
                (name.as_str(), s)
            })
            .collect();
        ranked.sort_by(|(n1, s1), (n2, s2)| s2.abs().total_cmp(&s1.abs()).then_with(|| n1.cmp(n2)));

        let top: Vec<&str> = ranked.into_iter().take(5).map(|(n, _)| n).collect();
        let action = if resp.action.trim().is_empty() {
            "unknown"
        } else {
            resp.action.trim()
        };

        if top.is_empty() {
            format!("rspamd action={action} score={:.2}", resp.score)
        } else {
            format!(
                "rspamd action={action} score={:.2} symbols={}",
                resp.score,
                top.join(",")
            )
        }
    }
}

#[async_trait]
impl InboundFilter for RspamdFilter {
    async fn evaluate(&self, msg: &InboundMessage) -> AppResult<FilterDecision> {
        let mut req = self
            .client
            .post(self.endpoint())
            .header("Content-Type", "message/rfc822")
            .body(msg.raw_rfc2822.clone());

        if let Some(password) = self.config.password.as_deref()
            && let Ok(val) = HeaderValue::from_str(password)
        {
            req = req.header("Password", val);
        }

        if let Some(ip) = msg
            .sender_ip
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            && let Ok(val) = HeaderValue::from_str(ip)
        {
            req = req.header("IP", val);
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(err) => return Ok(self.on_error(&err.to_string())),
        };

        let status = resp.status();
        if status.is_redirection() {
            return Ok(self.on_error(&format!(
                "HTTP {} redirect rejected (redirects disabled)",
                status.as_u16()
            )));
        }

        let body_bytes =
            match read_bounded_bytes(resp, DEFAULT_FILTER_MAX_BODY_BYTES, "Rspamd").await {
                Ok(b) => b,
                Err(err) => return Ok(self.on_error(&err.to_string())),
            };

        if !status.is_success() {
            let body = String::from_utf8_lossy(&body_bytes);
            return Ok(self.on_error(&format!("HTTP {status}: {body}")));
        }

        let parsed: RspamdResponse = match serde_json::from_slice(&body_bytes) {
            Ok(p) => p,
            Err(err) => return Ok(self.on_error(&format!("invalid JSON response: {err}"))),
        };

        let action = parsed.action.trim().to_ascii_lowercase();
        let reason = Self::format_reason(&parsed);

        match action.as_str() {
            "reject" | "soft reject" => match self.config.reject_action {
                RspamdRejectAction::Reject => Ok(FilterDecision::Reject { reason }),
                RspamdRejectAction::Spam => Ok(FilterDecision::Spam {
                    score: parsed.score,
                    reason,
                }),
            },
            "add header" | "rewrite subject" => Ok(FilterDecision::Spam {
                score: parsed.score,
                reason,
            }),
            _ => {
                let threshold = self.config.spam_threshold.or(parsed.required_score);
                if threshold.is_some_and(|t| parsed.score >= t) {
                    Ok(FilterDecision::Spam {
                        score: parsed.score,
                        reason,
                    })
                } else {
                    Ok(FilterDecision::Allow)
                }
            }
        }
    }

    fn backend_name(&self) -> &'static str {
        "rspamd"
    }
}
