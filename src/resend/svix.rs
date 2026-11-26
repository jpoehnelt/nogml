//! Svix / Standard Webhooks HMAC-SHA256 signature verification.

use std::{
    collections::HashMap,
    sync::Mutex as StdMutex,
    time::{Duration, Instant},
};

use axum::http::HeaderMap;
use base64::{Engine as _, engine::general_purpose};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::{AppError, AppResult};

type HmacSha256 = Hmac<Sha256>;

/// Maximum allowed clock skew between webhook timestamp and current time (5 minutes).
pub const SVIX_TIMESTAMP_TOLERANCE_SECS: u64 = 300;

/// Minimum replay deduplication TTL (>= 600s, covering the full +/- 300s timestamp tolerance window).
pub const SVIX_REPLAY_TTL_SECS: u64 = 660;

/// Upper bound on cached `svix-id` entries to prevent unbounded memory growth.
pub const SVIX_REPLAY_MAX_ENTRIES: usize = 50_000;

/// Bounded, expiring in-memory cache of processed `svix-id` / `webhook-id` values
/// preventing replay attacks within the Svix signature validity window.
#[derive(Debug)]
pub struct SvixReplayCache {
    ttl: Duration,
    max_entries: usize,
    entries: StdMutex<HashMap<String, Instant>>,
}

impl Default for SvixReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SvixReplayCache {
    /// Construct a replay cache with default TTL (`660s`) and capacity (`50,000`).
    pub fn new() -> Self {
        Self::with_ttl_and_capacity(
            Duration::from_secs(SVIX_REPLAY_TTL_SECS),
            SVIX_REPLAY_MAX_ENTRIES,
        )
    }

    /// Construct a replay cache with custom TTL and maximum entry capacity.
    pub fn with_ttl_and_capacity(ttl: Duration, max_entries: usize) -> Self {
        Self {
            ttl,
            max_entries: max_entries.max(1),
            entries: StdMutex::new(HashMap::new()),
        }
    }

    /// Check whether `svix_id` was already seen within the active TTL window; if not,
    /// record it and return `true` (fresh). Returns `false` if this is a replay.
    pub fn check_and_record(&self, svix_id: &str) -> bool {
        let now = Instant::now();
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());

        if map.len() >= self.max_entries || map.len() > 1024 {
            map.retain(|_, expires_at| *expires_at > now);
        }

        if let Some(&expires_at) = map.get(svix_id)
            && expires_at > now
        {
            return false;
        }

        if map.len() >= self.max_entries {
            map.retain(|_, expires_at| *expires_at > now);
            if map.len() >= self.max_entries
                && let Some(oldest_key) = map
                    .iter()
                    .min_by_key(|(_, exp)| **exp)
                    .map(|(k, _)| k.clone())
            {
                map.remove(&oldest_key);
            }
        }

        map.insert(svix_id.to_string(), now + self.ttl);
        true
    }

    /// Remove a previously recorded `svix_id` (e.g. if downstream processing returned an error
    /// so legitimate webhook retries can be processed).
    pub fn remove(&self, svix_id: &str) {
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(svix_id);
    }
}

/// Extract an optional `svix-id` (or `webhook-id`) header if present and non-empty.
pub fn extract_optional_svix_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("svix-id")
        .or_else(|| headers.get("webhook-id"))
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

/// Decode a Svix webhook secret (`whsec_<base64>` or raw `<base64>`) into raw HMAC key bytes.
fn decode_svix_secret(secret: &str) -> AppResult<Vec<u8>> {
    let trimmed = secret.trim();
    let b64 = trimmed.strip_prefix("whsec_").unwrap_or(trimmed);
    if b64.is_empty() {
        return Err(AppError::Config(
            "Resend webhook secret is empty".to_string(),
        ));
    }

    general_purpose::STANDARD
        .decode(b64)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(b64))
        .map_err(|err| {
            AppError::Config(format!(
                "Invalid Resend webhook secret (expected base64 with optional whsec_ prefix): {err}"
            ))
        })
}

/// Extract a required header checking the `svix-*` name first, then falling back to `webhook-*`.
fn extract_header<'a>(
    headers: &'a HeaderMap,
    svix_name: &str,
    webhook_name: &str,
) -> AppResult<&'a str> {
    let value = headers
        .get(svix_name)
        .or_else(|| headers.get(webhook_name))
        .ok_or_else(|| {
            AppError::Unauthorized(format!(
                "Missing required webhook signature header ({svix_name} / {webhook_name})"
            ))
        })?;

    let text = value.to_str().map_err(|_| {
        AppError::Unauthorized(format!(
            "Invalid non-ASCII webhook header ({svix_name} / {webhook_name})"
        ))
    })?;

    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(AppError::Unauthorized(format!(
            "Empty required webhook header ({svix_name} / {webhook_name})"
        )));
    }
    Ok(trimmed)
}

/// Collect all signature header values (`svix-signature`, falling back to `webhook-signature`).
fn collect_signature_values(headers: &HeaderMap) -> AppResult<Vec<&str>> {
    let mut values = Vec::new();

    for val in headers.get_all("svix-signature") {
        let s = val.to_str().map_err(|_| {
            AppError::Unauthorized("Invalid non-ASCII svix-signature header".to_string())
        })?;
        if !s.trim().is_empty() {
            values.push(s);
        }
    }

    if values.is_empty() {
        for val in headers.get_all("webhook-signature") {
            let s = val.to_str().map_err(|_| {
                AppError::Unauthorized("Invalid non-ASCII webhook-signature header".to_string())
            })?;
            if !s.trim().is_empty() {
                values.push(s);
            }
        }
    }

    if values.is_empty() {
        return Err(AppError::Unauthorized(
            "Missing required webhook signature header (svix-signature / webhook-signature)"
                .to_string(),
        ));
    }

    Ok(values)
}

/// Compute the raw 32-byte HMAC-SHA256 digest over `"{id}.{timestamp}.{raw_body}"`.
fn compute_hmac_bytes(
    key: &[u8],
    msg_id: &str,
    timestamp: &str,
    raw_body: &[u8],
) -> AppResult<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|err| AppError::Config(format!("Invalid webhook HMAC key: {err}")))?;
    mac.update(msg_id.as_bytes());
    mac.update(b".");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(raw_body);
    Ok(mac.finalize().into_bytes().into())
}

/// Sign a webhook payload in Svix `v1,<base64>` format (useful for testing and local tooling).
pub fn sign_svix_payload(
    msg_id: &str,
    timestamp_secs: i64,
    raw_body: &[u8],
    secret: &str,
) -> AppResult<String> {
    let key = decode_svix_secret(secret)?;
    let ts_str = timestamp_secs.to_string();
    let digest = compute_hmac_bytes(&key, msg_id, &ts_str, raw_body)?;
    Ok(format!("v1,{}", general_purpose::STANDARD.encode(digest)))
}

/// Verify Svix webhook HMAC-SHA256 signature (`svix-id`, `svix-timestamp`, `svix-signature`,
/// with fallback to `webhook-id`, `webhook-timestamp`, `webhook-signature`) using constant-time
/// comparison (`subtle::ConstantTimeEq`) and a 5-minute (`<= 300s`) timestamp tolerance.
pub fn verify_svix_signature(
    headers: &HeaderMap,
    raw_body: &[u8],
    secret: &str,
    now_epoch_secs: i64,
) -> AppResult<()> {
    verify_svix_signature_and_id(headers, raw_body, secret, now_epoch_secs).map(|_| ())
}

/// Verify Svix webhook HMAC-SHA256 signature and return the verified `svix-id` / `webhook-id`.
pub fn verify_svix_signature_and_id(
    headers: &HeaderMap,
    raw_body: &[u8],
    secret: &str,
    now_epoch_secs: i64,
) -> AppResult<String> {
    let key = decode_svix_secret(secret)?;

    let msg_id = extract_header(headers, "svix-id", "webhook-id")?;
    let timestamp_str = extract_header(headers, "svix-timestamp", "webhook-timestamp")?;
    let sig_headers = collect_signature_values(headers)?;

    let timestamp_secs = timestamp_str
        .parse::<i64>()
        .map_err(|_| AppError::Unauthorized("Invalid webhook timestamp header".to_string()))?;

    if now_epoch_secs.abs_diff(timestamp_secs) > SVIX_TIMESTAMP_TOLERANCE_SECS {
        return Err(AppError::Unauthorized(format!(
            "Webhook timestamp outside {SVIX_TIMESTAMP_TOLERANCE_SECS}-second tolerance"
        )));
    }

    let expected = compute_hmac_bytes(&key, msg_id, timestamp_str, raw_body)?;

    let mut matched = false;
    for header_val in sig_headers {
        for token in header_val.split_ascii_whitespace() {
            let Some((version, sig_b64)) = token.split_once(',') else {
                continue;
            };
            if version != "v1" {
                continue;
            }
            if let Ok(candidate) = general_purpose::STANDARD.decode(sig_b64)
                && bool::from(expected.as_slice().ct_eq(candidate.as_slice()))
            {
                matched = true;
            }
        }
    }

    if matched {
        Ok(msg_id.to_string())
    } else {
        Err(AppError::Unauthorized(
            "Invalid webhook signature".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::*;

    const TEST_SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    const ALT_SECRET: &str = "whsec_YW5vdGhlci1zZWNyZXQta2V5LWZvci1yb3RhdGlvbg==";
    const NOW: i64 = 1_700_000_000;

    fn build_headers(prefix: &str, id: &str, ts: &str, sig: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(
            format!("{prefix}-id")
                .parse::<axum::http::HeaderName>()
                .unwrap(),
            HeaderValue::from_str(id).unwrap(),
        );
        map.insert(
            format!("{prefix}-timestamp")
                .parse::<axum::http::HeaderName>()
                .unwrap(),
            HeaderValue::from_str(ts).unwrap(),
        );
        map.insert(
            format!("{prefix}-signature")
                .parse::<axum::http::HeaderName>()
                .unwrap(),
            HeaderValue::from_str(sig).unwrap(),
        );
        map
    }

    #[test]
    fn verifies_valid_svix_headers() {
        let body = br#"{"type":"email.received","created_at":"2026-01-01T00:00:00Z","data":{}}"#;
        let sig = sign_svix_payload("msg_123", NOW, body, TEST_SECRET).unwrap();
        let headers = build_headers("svix", "msg_123", &NOW.to_string(), &sig);

        verify_svix_signature(&headers, body, TEST_SECRET, NOW).expect("valid signature");
    }

    #[test]
    fn verifies_valid_webhook_fallback_headers() {
        let body = br#"{"type":"email.delivered","data":{"email_id":"e1"}}"#;
        let sig = sign_svix_payload("msg_std_1", NOW - 120, body, TEST_SECRET).unwrap();
        let headers = build_headers("webhook", "msg_std_1", &(NOW - 120).to_string(), &sig);

        verify_svix_signature(&headers, body, TEST_SECRET, NOW)
            .expect("webhook-* headers should be accepted");
    }

    #[test]
    fn verifies_rotated_multi_key_signature_list() {
        let body = br#"{"event":"rotated"}"#;
        let old_sig = sign_svix_payload("msg_rot", NOW, body, ALT_SECRET).unwrap();
        let good_sig = sign_svix_payload("msg_rot", NOW, body, TEST_SECRET).unwrap();
        let combined = format!("{old_sig} v2,ignoredPayload== {good_sig}");
        let headers = build_headers("svix", "msg_rot", &NOW.to_string(), &combined);

        verify_svix_signature(&headers, body, TEST_SECRET, NOW)
            .expect("matching v1 signature in rotated list should pass");
    }

    #[test]
    fn rejects_tampered_body() {
        let body = br#"{"type":"email.sent","amount":100}"#;
        let tampered = br#"{"type":"email.sent","amount":999}"#;
        let sig = sign_svix_payload("msg_tamper", NOW, body, TEST_SECRET).unwrap();
        let headers = build_headers("svix", "msg_tamper", &NOW.to_string(), &sig);

        let err = verify_svix_signature(&headers, tampered, TEST_SECRET, NOW)
            .expect_err("tampered body must be rejected");
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[test]
    fn rejects_expired_and_future_timestamps_beyond_300s() {
        let body = b"{}";

        // Exactly at +/- 300s boundary succeeds.
        for ts in [NOW - 300, NOW + 300] {
            let sig = sign_svix_payload("msg_ok", ts, body, TEST_SECRET).unwrap();
            let headers = build_headers("svix", "msg_ok", &ts.to_string(), &sig);
            verify_svix_signature(&headers, body, TEST_SECRET, NOW)
                .expect("300s boundary should pass");
        }

        // 301s past or future fails.
        for ts in [NOW - 301, NOW + 301] {
            let sig = sign_svix_payload("msg_exp", ts, body, TEST_SECRET).unwrap();
            let headers = build_headers("svix", "msg_exp", &ts.to_string(), &sig);
            let err = verify_svix_signature(&headers, body, TEST_SECRET, NOW)
                .expect_err("beyond 300s must be rejected");
            assert!(matches!(err, AppError::Unauthorized(_)));
        }
    }

    #[test]
    fn rejects_missing_headers() {
        let body = b"{}";
        let sig = sign_svix_payload("msg_1", NOW, body, TEST_SECRET).unwrap();

        for missing in ["svix-id", "svix-timestamp", "svix-signature"] {
            let mut headers = build_headers("svix", "msg_1", &NOW.to_string(), &sig);
            headers.remove(missing);
            let err = verify_svix_signature(&headers, body, TEST_SECRET, NOW)
                .expect_err("missing header must fail");
            assert!(matches!(err, AppError::Unauthorized(_)));
        }
    }

    #[test]
    fn rejects_non_v1_signatures() {
        let body = b"{}";
        let v1_sig = sign_svix_payload("msg_v2", NOW, body, TEST_SECRET).unwrap();
        let v2_only = v1_sig.replacen("v1,", "v2,", 1);
        let headers = build_headers("svix", "msg_v2", &NOW.to_string(), &v2_only);

        let err = verify_svix_signature(&headers, body, TEST_SECRET, NOW)
            .expect_err("non-v1 signature must be rejected");
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[test]
    fn rejects_invalid_secret_base64() {
        let body = b"{}";
        let headers = build_headers("svix", "msg_1", &NOW.to_string(), "v1,AAAA");
        let err = verify_svix_signature(&headers, body, "whsec_***not-base64***", NOW)
            .expect_err("invalid secret should fail");
        assert!(matches!(err, AppError::Config(_)));
    }
}
