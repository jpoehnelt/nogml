//! Pure-Rust S3-compatible [`BlobStore`] backend using AWS Signature Version 4.
//!
//! Works with AWS S3, Cloudflare R2, MinIO, and any S3-compatible object store
//! without pulling in heavy cloud SDK dependencies.

use std::{fmt, time::Duration};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use http::{HeaderName, HeaderValue, Method, header::HOST};
use reqwest::StatusCode;
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    blob::{BlobStore, sanitize_blob_key},
    config::Config,
    error::{AppError, AppResult},
};

type HmacSha256 = Hmac<Sha256>;

const DEFAULT_S3_REGION: &str = "us-east-1";
const S3_SERVICE: &str = "s3";
const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Configuration for [`S3BlobStore`].
#[derive(Clone)]
pub struct S3BlobConfig {
    pub bucket: String,
    pub region: String,
    pub endpoint_url: Option<String>,
    pub key_prefix: Option<String>,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    /// Use path-style URLs (`/{bucket}/{key}`) instead of virtual-host style (`{bucket}.{host}/{key}`).
    /// Defaults to `true` when `endpoint_url` is set, and `false` otherwise.
    pub force_path_style: bool,
}

impl fmt::Debug for S3BlobConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3BlobConfig")
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("endpoint_url", &self.endpoint_url)
            .field("key_prefix", &self.key_prefix)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("force_path_style", &self.force_path_style)
            .finish()
    }
}

impl S3BlobConfig {
    /// Extract and validate S3 blob configuration from runtime [`Config`].
    pub fn from_config(config: &Config) -> AppResult<Self> {
        let bucket = config
            .blob_s3_bucket
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AppError::Config(
                    "NOGML_BLOB_S3_BUCKET (--blob-s3-bucket) is required when blob_backend=s3"
                        .to_string(),
                )
            })?
            .to_string();

        let access_key_id = config
            .blob_s3_access_key_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AppError::Config(
                    "NOGML_BLOB_S3_ACCESS_KEY_ID (--blob-s3-access-key-id) is required when blob_backend=s3"
                        .to_string(),
                )
            })?
            .to_string();

        let secret_access_key = config
            .blob_s3_secret_access_key
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AppError::Config(
                    "NOGML_BLOB_S3_SECRET_ACCESS_KEY (--blob-s3-secret-access-key) is required when blob_backend=s3"
                        .to_string(),
                )
            })?
            .to_string();

        let region = {
            let trimmed = config.blob_s3_region.trim();
            if trimmed.is_empty() {
                DEFAULT_S3_REGION.to_string()
            } else {
                trimmed.to_string()
            }
        };

        let endpoint_url = config
            .blob_s3_endpoint
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let key_prefix = config
            .blob_s3_prefix
            .as_deref()
            .map(str::trim)
            .map(|s| s.trim_matches('/'))
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let session_token = config
            .blob_s3_session_token
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let force_path_style = config
            .blob_s3_force_path_style
            .unwrap_or_else(|| endpoint_url.is_some());

        Ok(Self {
            bucket,
            region,
            endpoint_url,
            key_prefix,
            access_key_id,
            secret_access_key,
            session_token,
            force_path_style,
        })
    }
}

/// S3 / Cloudflare R2 / MinIO [`BlobStore`] backed by `reqwest` + pure-Rust AWS SigV4.
#[derive(Clone)]
pub struct S3BlobStore {
    client: reqwest::Client,
    config: S3BlobConfig,
    base_url: Url,
    normalized_prefix: Option<String>,
}

impl fmt::Debug for S3BlobStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3BlobStore")
            .field("config", &self.config)
            .field("base_url", &self.base_url.as_str())
            .field("normalized_prefix", &self.normalized_prefix)
            .finish()
    }
}

impl S3BlobStore {
    /// Construct an [`S3BlobStore`] from an explicit [`S3BlobConfig`].
    pub fn new(config: S3BlobConfig) -> AppResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| AppError::Config(format!("Failed to build S3 HTTP client: {e}")))?;
        Self::with_client(config, client)
    }

    /// Construct an [`S3BlobStore`] using a caller-supplied `reqwest::Client`.
    pub fn with_client(mut config: S3BlobConfig, client: reqwest::Client) -> AppResult<Self> {
        config.bucket = config.bucket.trim().to_string();
        validate_bucket_name(&config.bucket)?;

        config.region = config.region.trim().to_string();
        if config.region.is_empty() {
            config.region = DEFAULT_S3_REGION.to_string();
        }

        config.access_key_id = config.access_key_id.trim().to_string();
        if config.access_key_id.is_empty() {
            return Err(AppError::Config(
                "S3 access_key_id must not be empty".to_string(),
            ));
        }

        config.secret_access_key = config.secret_access_key.trim().to_string();
        if config.secret_access_key.is_empty() {
            return Err(AppError::Config(
                "S3 secret_access_key must not be empty".to_string(),
            ));
        }

        config.session_token = config
            .session_token
            .take()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty());

        let normalized_prefix = match config
            .key_prefix
            .as_deref()
            .map(str::trim)
            .map(|s| s.trim_matches('/'))
            .filter(|s| !s.is_empty())
        {
            Some(prefix) => Some(normalize_sanitized_key(prefix)?),
            None => None,
        };
        config.key_prefix = normalized_prefix.clone();

        let base_url = build_base_url(
            &config.bucket,
            &config.region,
            config.endpoint_url.as_deref(),
            config.force_path_style,
        )?;

        Ok(Self {
            client,
            config,
            base_url,
            normalized_prefix,
        })
    }

    /// Construct an [`S3BlobStore`] from runtime [`Config`].
    pub fn from_config(config: &Config) -> AppResult<Self> {
        Self::new(S3BlobConfig::from_config(config)?)
    }

    /// Return the configured S3 settings (with secrets redacted in `Debug`).
    pub fn config(&self) -> &S3BlobConfig {
        &self.config
    }

    /// Resolve a logical blob key with safe sanitization and optional `key_prefix`.
    pub fn resolve_object_key(&self, key: &str) -> AppResult<String> {
        let clean_key = normalize_sanitized_key(key)?;
        match &self.normalized_prefix {
            Some(prefix) => Ok(format!("{prefix}/{clean_key}")),
            None => Ok(clean_key),
        }
    }

    /// Build the full target [`Url`] for a logical blob key.
    pub fn object_url(&self, key: &str) -> AppResult<Url> {
        let object_key = self.resolve_object_key(key)?;
        let mut url = self.base_url.clone();
        {
            let mut segments = url.path_segments_mut().map_err(|_| {
                AppError::Config(format!(
                    "S3 base URL '{}' cannot be a base",
                    self.base_url.as_str()
                ))
            })?;
            segments.pop_if_empty();
            if self.config.force_path_style {
                segments.push(&self.config.bucket);
            }
            for seg in object_key.split('/') {
                segments.push(seg);
            }
        }
        Ok(url)
    }

    async fn send_signed(
        &self,
        method: Method,
        key: &str,
        body: Option<&[u8]>,
    ) -> AppResult<(String, reqwest::Response)> {
        let object_key = self.resolve_object_key(key)?;
        let url = self.object_url(key)?;
        let host = url_host_header(&url)?;
        let payload_bytes = body.unwrap_or(&[]);
        let payload_hash = if payload_bytes.is_empty() {
            EMPTY_PAYLOAD_SHA256.to_string()
        } else {
            sha256_hex(payload_bytes)
        };

        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

        let mut sig_headers: Vec<(&str, &str)> = vec![
            ("host", host.as_str()),
            ("x-amz-content-sha256", payload_hash.as_str()),
            ("x-amz-date", amz_date.as_str()),
        ];
        if let Some(ref token) = self.config.session_token {
            sig_headers.push(("x-amz-security-token", token.as_str()));
        }

        let canonical_uri = canonical_uri_from_url(&url);
        let canonical_query = canonical_query_from_url(&url);
        let signed = sign_v4_request(
            method.as_str(),
            &canonical_uri,
            &canonical_query,
            &sig_headers,
            &payload_hash,
            &self.config.access_key_id,
            &self.config.secret_access_key,
            &self.config.region,
            S3_SERVICE,
            now,
        );

        let mut req = self
            .client
            .request(method, url)
            .header(HOST, &host)
            .header("x-amz-content-sha256", &payload_hash)
            .header("x-amz-date", &amz_date)
            .header("authorization", &signed.authorization);

        if let Some(ref token) = self.config.session_token {
            let header_name = HeaderName::from_static("x-amz-security-token");
            let header_val = HeaderValue::from_str(token).map_err(|e| {
                AppError::Config(format!("Invalid S3 session token header value: {e}"))
            })?;
            req = req.header(header_name, header_val);
        }

        if let Some(bytes) = body {
            req = req
                .header("content-type", "application/octet-stream")
                .body(bytes.to_vec());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("S3 request for '{object_key}' failed: {e}")))?;

        Ok((object_key, resp))
    }
}

#[async_trait]
impl BlobStore for S3BlobStore {
    async fn put(&self, key: &str, bytes: &[u8]) -> AppResult<()> {
        let (object_key, resp) = self.send_signed(Method::PUT, key, Some(bytes)).await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let err_body = resp.text().await.unwrap_or_default();
        Err(AppError::Storage(format!(
            "S3 PUT '{object_key}' failed (HTTP {status}): {err_body}"
        )))
    }

    async fn get(&self, key: &str) -> AppResult<Option<Vec<u8>>> {
        let (object_key, resp) = self.send_signed(Method::GET, key, None).await?;
        let status = resp.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if status.is_success() {
            let bytes = resp.bytes().await.map_err(|e| {
                AppError::Storage(format!("Failed reading S3 GET '{object_key}' body: {e}"))
            })?;
            return Ok(Some(bytes.to_vec()));
        }
        let err_body = resp.text().await.unwrap_or_default();
        Err(AppError::Storage(format!(
            "S3 GET '{object_key}' failed (HTTP {status}): {err_body}"
        )))
    }

    async fn delete(&self, key: &str) -> AppResult<()> {
        let (object_key, resp) = self.send_signed(Method::DELETE, key, None).await?;
        let status = resp.status();
        if status.is_success() || status == StatusCode::NOT_FOUND {
            return Ok(());
        }
        let err_body = resp.text().await.unwrap_or_default();
        Err(AppError::Storage(format!(
            "S3 DELETE '{object_key}' failed (HTTP {status}): {err_body}"
        )))
    }

    fn backend_name(&self) -> &'static str {
        "s3"
    }
}

// ============================================================================
// URL & Validation Helpers
// ============================================================================

fn validate_bucket_name(bucket: &str) -> AppResult<()> {
    if bucket.is_empty() || bucket.len() > 255 {
        return Err(AppError::Config(
            "S3 bucket name must be between 1 and 255 characters".to_string(),
        ));
    }
    if bucket.starts_with('.') || bucket.ends_with('.') || bucket.contains("..") {
        return Err(AppError::Config(format!(
            "Invalid S3 bucket name '{bucket}'"
        )));
    }
    if !bucket
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(AppError::Config(format!(
            "S3 bucket name '{bucket}' contains disallowed characters"
        )));
    }
    Ok(())
}

fn normalize_sanitized_key(key: &str) -> AppResult<String> {
    let rel = sanitize_blob_key(key)?;
    let mut parts = Vec::new();
    for component in rel.components() {
        let seg = component.as_os_str().to_str().ok_or_else(|| {
            AppError::validation(format!("Blob key '{key}' is not valid UTF-8"), None)
        })?;
        parts.push(seg);
    }
    Ok(parts.join("/"))
}

fn build_base_url(
    bucket: &str,
    region: &str,
    endpoint_url: Option<&str>,
    force_path_style: bool,
) -> AppResult<Url> {
    let mut url = match endpoint_url.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => Url::parse(raw)
            .map_err(|e| AppError::Config(format!("Invalid S3 endpoint URL '{raw}': {e}")))?,
        None => {
            let default_url = if force_path_style {
                format!("https://s3.{region}.amazonaws.com")
            } else {
                format!("https://{bucket}.s3.{region}.amazonaws.com")
            };
            Url::parse(&default_url).map_err(|e| {
                AppError::Config(format!("Invalid default S3 URL '{default_url}': {e}"))
            })?
        }
    };

    if !matches!(url.scheme(), "http" | "https") {
        return Err(AppError::Config(format!(
            "S3 endpoint URL '{}' must use http or https scheme",
            url.as_str()
        )));
    }

    if url.host_str().is_none() {
        return Err(AppError::Config(format!(
            "S3 endpoint URL '{}' is missing a host",
            url.as_str()
        )));
    }

    if !force_path_style && endpoint_url.is_some() {
        let existing_host = url.host_str().unwrap_or_default().to_string();
        if existing_host.parse::<std::net::IpAddr>().is_ok()
            || (existing_host.starts_with('[') && existing_host.ends_with(']'))
        {
            return Err(AppError::Config(format!(
                "Cannot use virtual-host addressing with IP endpoint '{existing_host}'; set force_path_style=true"
            )));
        }
        let vhost = format!("{bucket}.{existing_host}");
        url.set_host(Some(&vhost)).map_err(|e| {
            AppError::Config(format!(
                "Failed to build virtual-host S3 endpoint '{vhost}': {e}"
            ))
        })?;
    }

    Ok(url)
}

fn url_host_header(url: &Url) -> AppResult<String> {
    let host = url
        .host_str()
        .ok_or_else(|| AppError::Config("S3 request URL missing host".to_string()))?;
    match url.port() {
        Some(port) => Ok(format!("{host}:{port}")),
        None => Ok(host.to_string()),
    }
}

// ============================================================================
// Pure-Rust AWS Signature Version 4 Signer
// ============================================================================

/// Result of signing an S3 HTTP request with AWS Signature Version 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SigV4Output {
    pub canonical_request: String,
    pub string_to_sign: String,
    pub signed_headers: String,
    pub signature: String,
    pub authorization: String,
}

/// Sign an HTTP request using AWS Signature Version 4 (`AWS4-HMAC-SHA256`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_v4_request(
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    headers: &[(&str, &str)],
    payload_hash: &str,
    access_key_id: &str,
    secret_access_key: &str,
    region: &str,
    service: &str,
    timestamp: DateTime<Utc>,
) -> SigV4Output {
    let amz_date = timestamp.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = timestamp.format("%Y%m%d").to_string();

    let mut normalized_headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), normalize_header_value(v)))
        .collect();
    normalized_headers.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let mut canonical_headers = String::new();
    let mut signed_header_names = Vec::with_capacity(normalized_headers.len());
    for (name, value) in &normalized_headers {
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(value);
        canonical_headers.push('\n');
        if signed_header_names.last().map(String::as_str) != Some(name.as_str()) {
            signed_header_names.push(name.clone());
        }
    }
    let signed_headers = signed_header_names.join(";");

    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );

    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let hashed_canonical_request = sha256_hex(canonical_request.as_bytes());
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{hashed_canonical_request}");

    let k_secret = format!("AWS4{secret_access_key}");
    let k_date = hmac_sha256(k_secret.as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex_encode(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );

    SigV4Output {
        canonical_request,
        string_to_sign,
        signed_headers,
        signature,
        authorization,
    }
}

fn canonical_uri_from_url(url: &Url) -> String {
    let raw_path = url.path();
    if raw_path.is_empty() || raw_path == "/" {
        return "/".to_string();
    }
    // `url::Url::path()` is already percent-encoded for non-URL chars; decode any percent
    // escapes per segment and re-encode with strict AWS SigV4 RFC 3986 rules.
    let mut encoded = String::with_capacity(raw_path.len());
    for (idx, segment) in raw_path.split('/').enumerate() {
        if idx > 0 {
            encoded.push('/');
        }
        let decoded = percent_decode(segment);
        encoded.push_str(&aws_uri_encode_bytes(&decoded, true));
    }
    if !encoded.starts_with('/') {
        encoded.insert(0, '/');
    }
    encoded
}

fn canonical_query_from_url(url: &Url) -> String {
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (aws_uri_encode(&k, true), aws_uri_encode(&v, true)))
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Percent-encode according to AWS SigV4 RFC 3986 unreserved character rules.
pub(crate) fn aws_uri_encode(input: &str, encode_slash: bool) -> String {
    aws_uri_encode_bytes(input.as_bytes(), encode_slash)
}

fn aws_uri_encode_bytes(bytes: &[u8], encode_slash: bool) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        let is_unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if is_unreserved || (!encode_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
    out
}

fn percent_decode(input: &str) -> Vec<u8> {
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

fn normalize_header_value(val: &str) -> String {
    let mut out = String::with_capacity(val.len());
    let mut prev_space = false;
    for ch in val.trim().chars() {
        if ch == ' ' || ch == '\t' {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key size");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex_encode(&digest)
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

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn sigv4_matches_aws_official_get_object_vector() {
        // Official AWS S3 SigV4 documentation example: GET Object
        let ts = Utc.with_ymd_and_hms(2013, 5, 24, 0, 0, 0).unwrap();
        let out = sign_v4_request(
            "GET",
            "/test.txt",
            "",
            &[
                ("host", "examplebucket.s3.amazonaws.com"),
                ("range", "bytes=0-9"),
                ("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256),
                ("x-amz-date", "20130524T000000Z"),
            ],
            EMPTY_PAYLOAD_SHA256,
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "s3",
            ts,
        );

        assert_eq!(
            out.signed_headers,
            "host;range;x-amz-content-sha256;x-amz-date"
        );
        assert_eq!(
            out.signature,
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
        assert_eq!(
            out.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn sigv4_matches_aws_official_put_object_vector() {
        // Official AWS S3 SigV4 documentation example: PUT Object
        let ts = Utc.with_ymd_and_hms(2013, 5, 24, 0, 0, 0).unwrap();
        let payload_hash = sha256_hex(b"Welcome to Amazon S3.");
        assert_eq!(
            payload_hash,
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );

        let canonical_uri = aws_uri_encode("/test$file.text", false);
        assert_eq!(canonical_uri, "/test%24file.text");

        let out = sign_v4_request(
            "PUT",
            &canonical_uri,
            "",
            &[
                ("Date", "Fri, 24 May 2013 00:00:00 GMT"),
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
                ("x-amz-content-sha256", &payload_hash),
                ("x-amz-date", "20130524T000000Z"),
            ],
            &payload_hash,
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "s3",
            ts,
        );

        assert_eq!(
            out.signed_headers,
            "date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class"
        );
        assert_eq!(
            out.signature,
            "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        );
    }

    #[test]
    fn sigv4_includes_session_token_in_signed_headers() {
        let ts = Utc.with_ymd_and_hms(2025, 1, 15, 12, 30, 0).unwrap();
        let out = sign_v4_request(
            "GET",
            "/my-bucket/messages/m1/raw.eml",
            "",
            &[
                ("host", "127.0.0.1:9000"),
                ("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256),
                ("x-amz-date", "20250115T123000Z"),
                ("x-amz-security-token", "sts-temp-token"),
            ],
            EMPTY_PAYLOAD_SHA256,
            "ASIAEXAMPLE",
            "secret",
            "auto",
            "s3",
            ts,
        );

        assert_eq!(
            out.signed_headers,
            "host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
        );
        assert!(
            out.canonical_request
                .contains("x-amz-security-token:sts-temp-token\n")
        );
        assert!(
            out.authorization
                .contains("Credential=ASIAEXAMPLE/20250115/auto/s3/aws4_request")
        );
    }

    #[test]
    fn url_construction_supports_virtual_host_path_style_custom_endpoints_and_prefixes() {
        // 1. AWS virtual-host style (default when endpoint_url is None)
        let vhost_store = S3BlobStore::new(S3BlobConfig {
            bucket: "mail-blobs".to_string(),
            region: "us-west-2".to_string(),
            endpoint_url: None,
            key_prefix: None,
            access_key_id: "AKIA".to_string(),
            secret_access_key: "SECRET".to_string(),
            session_token: None,
            force_path_style: false,
        })
        .unwrap();
        assert_eq!(
            vhost_store
                .object_url("messages/msg_1/raw.eml")
                .unwrap()
                .as_str(),
            "https://mail-blobs.s3.us-west-2.amazonaws.com/messages/msg_1/raw.eml"
        );

        // 2. AWS path style
        let path_store = S3BlobStore::new(S3BlobConfig {
            bucket: "mail-blobs".to_string(),
            region: "us-west-2".to_string(),
            endpoint_url: None,
            key_prefix: Some("/prod/tenant-a/".to_string()),
            access_key_id: "AKIA".to_string(),
            secret_access_key: "SECRET".to_string(),
            session_token: None,
            force_path_style: true,
        })
        .unwrap();
        assert_eq!(
            path_store
                .resolve_object_key("messages/msg_1/raw.eml")
                .unwrap(),
            "prod/tenant-a/messages/msg_1/raw.eml"
        );
        assert_eq!(
            path_store
                .object_url("messages/msg_1/raw.eml")
                .unwrap()
                .as_str(),
            "https://s3.us-west-2.amazonaws.com/mail-blobs/prod/tenant-a/messages/msg_1/raw.eml"
        );

        // 3. Cloudflare R2 custom endpoint (path-style by default via from_config)
        let mut cfg = Config::for_test();
        cfg.blob_s3_bucket = Some("r2-mail".to_string());
        cfg.blob_s3_region = "auto".to_string();
        cfg.blob_s3_endpoint = Some("https://acct123.r2.cloudflarestorage.com/".to_string());
        cfg.blob_s3_prefix = Some("nogml".to_string());
        cfg.blob_s3_access_key_id = Some("r2-key".to_string());
        cfg.blob_s3_secret_access_key = Some("r2-secret".to_string());
        let r2_store = S3BlobStore::from_config(&cfg).unwrap();
        assert!(r2_store.config().force_path_style);
        assert_eq!(
            r2_store
                .object_url("attachments/msg_1/att_2")
                .unwrap()
                .as_str(),
            "https://acct123.r2.cloudflarestorage.com/r2-mail/nogml/attachments/msg_1/att_2"
        );

        // 4. Custom endpoint with virtual-host style explicitly requested
        cfg.blob_s3_force_path_style = Some(false);
        let r2_vhost = S3BlobStore::from_config(&cfg).unwrap();
        assert!(!r2_vhost.config().force_path_style);
        assert_eq!(
            r2_vhost
                .object_url("attachments/msg_1/att_2")
                .unwrap()
                .as_str(),
            "https://r2-mail.acct123.r2.cloudflarestorage.com/nogml/attachments/msg_1/att_2"
        );
    }

    #[test]
    fn key_and_prefix_sanitization_blocks_traversal() {
        let store = S3BlobStore::new(S3BlobConfig {
            bucket: "mail-blobs".to_string(),
            region: "us-east-1".to_string(),
            endpoint_url: Some("http://127.0.0.1:9000".to_string()),
            key_prefix: Some("env/prod".to_string()),
            access_key_id: "AKIA".to_string(),
            secret_access_key: "SECRET".to_string(),
            session_token: None,
            force_path_style: true,
        })
        .unwrap();

        assert!(store.object_url("../escape").is_err());
        assert!(store.object_url("/leading/slash").is_err());
        assert!(store.object_url("messages/bad space/raw.eml").is_err());

        // Unsafe prefix rejected on construction
        let bad_prefix = S3BlobStore::new(S3BlobConfig {
            bucket: "mail-blobs".to_string(),
            region: "us-east-1".to_string(),
            endpoint_url: Some("http://127.0.0.1:9000".to_string()),
            key_prefix: Some("../escape".to_string()),
            access_key_id: "AKIA".to_string(),
            secret_access_key: "SECRET".to_string(),
            session_token: None,
            force_path_style: true,
        });
        assert!(bad_prefix.is_err());
    }

    #[test]
    fn debug_redacts_secrets() {
        let store = S3BlobStore::new(S3BlobConfig {
            bucket: "mail-blobs".to_string(),
            region: "us-east-1".to_string(),
            endpoint_url: None,
            key_prefix: None,
            access_key_id: "AKIA_PUBLIC".to_string(),
            secret_access_key: "SUPER_SECRET_KEY".to_string(),
            session_token: Some("SUPER_SECRET_TOKEN".to_string()),
            force_path_style: false,
        })
        .unwrap();

        let dbg = format!("{store:?}");
        assert!(dbg.contains("AKIA_PUBLIC"));
        assert!(!dbg.contains("SUPER_SECRET_KEY"));
        assert!(!dbg.contains("SUPER_SECRET_TOKEN"));
        assert!(dbg.contains("[REDACTED]"));
    }
}
