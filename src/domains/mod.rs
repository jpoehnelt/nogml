//! Bring-your-own-domain (BYOD) onboarding, strict domain validation,
//! pluggable [`DomainProvider`] trait, and concrete providers for AWS SESv2,
//! Resend, and manual/self-hosted DNS configurations.

pub mod service;

pub use service::{
    CreateDomainRequest, PatchDomainRequest, execute_create_domain, execute_delete_domain,
    execute_get_domain, execute_list_domains, execute_patch_domain, execute_verify_domain,
};

use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    config::{Config, TransportBackend, normalize_mailbox_id},
    error::{AppError, AppResult},
    resend::client::map_resend_error,
    transport::ses::{SesConfig, sign_aws_v4},
};

const DEFAULT_TIMEOUT_SECS: u64 = 30;
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
const MAX_ERROR_SNIPPET_CHARS: usize = 512;
const MAX_DOMAIN_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

// ============================================================================
// Domain Model Types
// ============================================================================

/// DNS / sending provider managing verification for a custom domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainProviderKind {
    Ses,
    Resend,
    Manual,
}

impl DomainProviderKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ses => "ses",
            Self::Resend => "resend",
            Self::Manual => "manual",
        }
    }

    pub fn parse_str(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "ses" | "aws_ses" => Some(Self::Ses),
            "resend" => Some(Self::Resend),
            "manual" | "smtp" => Some(Self::Manual),
            _ => None,
        }
    }

    /// Default provider inferred from the active outbound [`TransportBackend`].
    pub fn from_transport(transport: TransportBackend) -> Self {
        match transport {
            TransportBackend::Ses => Self::Ses,
            TransportBackend::Resend => Self::Resend,
            TransportBackend::Smtp | TransportBackend::Gmail => Self::Manual,
        }
    }
}

impl std::fmt::Display for DomainProviderKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle verification status for a custom BYOD domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStatus {
    Pending,
    Verifying,
    Verified,
    Failed,
}

impl DomainStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verifying => "verifying",
            Self::Verified => "verified",
            Self::Failed => "failed",
        }
    }

    pub fn parse_str(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "pending" | "pending_dns" | "not_started" => Some(Self::Pending),
            "verifying" | "in_progress" => Some(Self::Verifying),
            "verified" | "success" => Some(Self::Verified),
            "failed" | "temporary_failure" | "suspended" => Some(Self::Failed),
            _ => None,
        }
    }
}

impl std::fmt::Display for DomainStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Functional role of a required DNS record for domain onboarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsRecordPurpose {
    Dkim,
    Spf,
    Dmarc,
    Mx,
    MailFrom,
    Verification,
    Other,
}

impl DnsRecordPurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dkim => "dkim",
            Self::Spf => "spf",
            Self::Dmarc => "dmarc",
            Self::Mx => "mx",
            Self::MailFrom => "mail_from",
            Self::Verification => "verification",
            Self::Other => "other",
        }
    }
}

/// Structured DNS record returned to operators for configuring a custom domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    pub purpose: DnsRecordPurpose,
    #[serde(default)]
    pub verified: bool,
}

/// Persisted BYOD custom domain record stored in `MailStore`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainRecord {
    pub id: String,
    pub domain: String,
    pub mailbox_id: String,
    pub provider: DomainProviderKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_domain_id: Option<String>,
    pub status: DomainStatus,
    pub dns_records: Vec<DnsRecord>,
    pub dkim_verified: bool,
    pub spf_verified: bool,
    pub dmarc_verified: bool,
    pub mx_verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catch_all_mailbox: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_checked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Input payload for inserting a new [`DomainRecord`] into `MailStore`.
#[derive(Debug, Clone)]
pub struct NewDomainInput {
    pub id: Option<String>,
    pub domain: String,
    pub mailbox_id: String,
    pub provider: DomainProviderKind,
    pub provider_domain_id: Option<String>,
    pub status: DomainStatus,
    pub dns_records: Vec<DnsRecord>,
    pub dkim_verified: bool,
    pub spf_verified: bool,
    pub dmarc_verified: bool,
    pub mx_verified: bool,
    pub catch_all_mailbox: Option<String>,
    pub last_error: Option<String>,
}

/// Partial update payload for [`crate::storage::MailStore::update_domain`].
#[derive(Debug, Clone, Default)]
pub struct DomainUpdate {
    pub provider_domain_id: Option<Option<String>>,
    pub status: Option<DomainStatus>,
    pub dns_records: Option<Vec<DnsRecord>>,
    pub dkim_verified: Option<bool>,
    pub spf_verified: Option<bool>,
    pub dmarc_verified: Option<bool>,
    pub mx_verified: Option<bool>,
    pub catch_all_mailbox: Option<Option<String>>,
    pub verified_at: Option<Option<DateTime<Utc>>>,
    pub last_checked_at: Option<Option<DateTime<Utc>>>,
    pub last_error: Option<Option<String>>,
}

/// Apply a [`DomainUpdate`] onto an existing [`DomainRecord`].
pub fn apply_domain_update(mut record: DomainRecord, update: &DomainUpdate) -> DomainRecord {
    if let Some(ref provider_domain_id) = update.provider_domain_id {
        record.provider_domain_id = provider_domain_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);
    }
    if let Some(status) = update.status {
        record.status = status;
    }
    if let Some(ref dns_records) = update.dns_records {
        record.dns_records = dns_records.clone();
    }
    if let Some(v) = update.dkim_verified {
        record.dkim_verified = v;
    }
    if let Some(v) = update.spf_verified {
        record.spf_verified = v;
    }
    if let Some(v) = update.dmarc_verified {
        record.dmarc_verified = v;
    }
    if let Some(v) = update.mx_verified {
        record.mx_verified = v;
    }
    if let Some(ref catch_all) = update.catch_all_mailbox {
        record.catch_all_mailbox = catch_all
            .as_deref()
            .map(normalize_mailbox_id)
            .filter(|s| !s.is_empty());
    }
    if let Some(verified_at) = update.verified_at {
        record.verified_at = verified_at.map(crate::models::truncate_to_millis);
    }
    if let Some(last_checked_at) = update.last_checked_at {
        record.last_checked_at = last_checked_at.map(crate::models::truncate_to_millis);
    }
    if let Some(ref last_error) = update.last_error {
        record.last_error = last_error
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);
    }
    record
}

// ============================================================================
// Strict Domain Normalization & Validation (ASCII / Punycode)
// ============================================================================

/// Strictly validate and normalize a DNS domain name to lowercase ASCII/punycode.
///
/// Rejects empty strings, IP literals, single-label domains, wildcards, schemes/paths,
/// control characters, consecutive/leading dots, overlong labels (> 63 bytes) or
/// names (> 253 bytes), leading/trailing hyphens in labels, and all-numeric TLDs.
pub fn normalize_and_validate_domain(raw: &str) -> AppResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::validation(
            "Domain must not be empty",
            Some("Provide a fully qualified domain name such as 'example.com'.".to_string()),
        ));
    }

    if trimmed.bytes().any(|b| b <= 0x20 || b == 0x7f)
        || trimmed.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(AppError::validation(
            format!("Domain '{trimmed}' contains disallowed whitespace or control characters"),
            Some("Provide a bare DNS hostname without spaces or control characters.".to_string()),
        ));
    }

    for forbidden in [
        '@', '/', '\\', ':', '?', '#', '%', '*', '_', '"', '\'', '<', '>', ',', ';', '[', ']',
    ] {
        if trimmed.contains(forbidden) {
            return Err(AppError::validation(
                format!("Domain '{trimmed}' contains disallowed character '{forbidden}'"),
                Some(
                    "Provide a bare DNS hostname such as 'mail.example.com' without schemes, ports, wildcards, or paths."
                        .to_string(),
                ),
            ));
        }
    }

    // Allow at most one trailing root dot.
    let without_trailing = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if without_trailing.is_empty()
        || without_trailing.starts_with('.')
        || without_trailing.ends_with('.')
        || without_trailing.contains("..")
    {
        return Err(AppError::validation(
            format!("Domain '{trimmed}' has invalid dot placement"),
            Some("Provide a valid domain name without leading or consecutive dots.".to_string()),
        ));
    }

    // Parse via `url::Host::parse` to handle IDNA/punycode conversion cleanly and reject IP literals.
    let host = url::Host::parse(without_trailing).map_err(|_| {
        AppError::validation(
            format!("Invalid domain syntax: '{trimmed}'"),
            Some(
                "Provide a valid DNS domain name (ASCII or internationalized domain).".to_string(),
            ),
        )
    })?;

    let ascii = match host {
        url::Host::Domain(d) => d.to_ascii_lowercase(),
        url::Host::Ipv4(_) | url::Host::Ipv6(_) => {
            return Err(AppError::validation(
                format!("Domain '{trimmed}' must be a DNS hostname, not an IP address"),
                Some("Provide a valid domain name such as 'example.com'.".to_string()),
            ));
        }
    };

    if ascii.is_empty() || ascii.len() > MAX_DOMAIN_LEN {
        return Err(AppError::validation(
            format!(
                "Domain '{ascii}' length must be between 1 and {MAX_DOMAIN_LEN} ASCII characters"
            ),
            None,
        ));
    }

    let labels: Vec<&str> = ascii.split('.').collect();
    if labels.len() < 2 {
        return Err(AppError::validation(
            format!("Domain '{ascii}' must contain at least two labels (e.g. 'example.com')"),
            Some("Single-label hostnames are not permitted for BYOD domains.".to_string()),
        ));
    }

    for label in &labels {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return Err(AppError::validation(
                format!("Domain '{ascii}' has an invalid label length"),
                Some("Each DNS label must be 1 to 63 ASCII characters.".to_string()),
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(AppError::validation(
                format!("Domain label '{label}' cannot start or end with '-'"),
                None,
            ));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(AppError::validation(
                format!("Domain label '{label}' contains disallowed characters"),
                None,
            ));
        }
    }

    let tld = labels[labels.len() - 1];
    if tld.len() < 2 || tld.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AppError::validation(
            format!("Domain '{ascii}' has an invalid top-level domain '{tld}'"),
            Some("Use a valid alphabetic or punycode TLD (at least 2 characters).".to_string()),
        ));
    }
    if !tld.starts_with("xn--") && !tld.bytes().all(|b| b.is_ascii_lowercase()) {
        return Err(AppError::validation(
            format!("Domain '{ascii}' has an invalid top-level domain '{tld}'"),
            Some(
                "Top-level domains must contain only ASCII letters or punycode ('xn--...')."
                    .to_string(),
            ),
        ));
    }

    Ok(ascii)
}

/// Best-effort normalization for storage lookup keys (returns lowercase punycode when valid,
/// or trimmed lowercase fallback without failing).
pub fn normalize_domain_lookup_key(raw: &str) -> String {
    normalize_and_validate_domain(raw)
        .unwrap_or_else(|_| raw.trim().trim_end_matches('.').to_ascii_lowercase())
}

// ============================================================================
// Pluggable `DomainProvider` Trait & Registry
// ============================================================================

/// Provider response returned by [`DomainProvider::create_domain`],
/// [`DomainProvider::get_verification_status`], and [`DomainProvider::verify_domain`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderDomainResult {
    pub provider_domain_id: Option<String>,
    pub status: DomainStatus,
    pub dns_records: Vec<DnsRecord>,
    pub dkim_verified: bool,
    pub spf_verified: bool,
    pub dmarc_verified: bool,
    pub mx_verified: bool,
    pub last_error: Option<String>,
}

/// Pluggable DNS / sending provider abstraction for BYOD domain onboarding.
#[async_trait]
pub trait DomainProvider: Send + Sync {
    /// Short provider identifier (`ses`, `resend`, or `manual`).
    fn provider_kind(&self) -> DomainProviderKind;

    /// Register a domain identity with the upstream provider and return required DNS records.
    async fn create_domain(&self, domain: &str) -> AppResult<ProviderDomainResult>;

    /// Fetch current DNS verification status and record details from the provider.
    async fn get_verification_status(
        &self,
        domain: &str,
        provider_domain_id: Option<&str>,
    ) -> AppResult<ProviderDomainResult>;

    /// Trigger provider-side re-verification when supported and return the latest status.
    async fn verify_domain(
        &self,
        domain: &str,
        provider_domain_id: Option<&str>,
    ) -> AppResult<ProviderDomainResult> {
        self.get_verification_status(domain, provider_domain_id)
            .await
    }

    /// Delete the domain identity from the upstream provider (idempotent on missing).
    async fn delete_domain(&self, domain: &str, provider_domain_id: Option<&str>) -> AppResult<()>;
}

/// Registry holding configured [`DomainProvider`] implementations keyed by [`DomainProviderKind`].
#[derive(Clone, Default)]
pub struct DomainProviderRegistry {
    providers: HashMap<DomainProviderKind, Arc<dyn DomainProvider>>,
}

impl std::fmt::Debug for DomainProviderRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut kinds: Vec<&str> = self.providers.keys().map(|k| k.as_str()).collect();
        kinds.sort();
        f.debug_struct("DomainProviderRegistry")
            .field("providers", &kinds)
            .finish()
    }
}

impl DomainProviderRegistry {
    /// Build a registry populated with SES, Resend, and Manual providers from [`Config`].
    pub fn from_config(config: &Config) -> Self {
        let mut providers: HashMap<DomainProviderKind, Arc<dyn DomainProvider>> = HashMap::new();
        if let Ok(ses) = SesDomainProvider::from_config(config) {
            providers.insert(DomainProviderKind::Ses, Arc::new(ses));
        }
        providers.insert(
            DomainProviderKind::Resend,
            Arc::new(ResendDomainProvider::from_config(config)),
        );
        providers.insert(
            DomainProviderKind::Manual,
            Arc::new(ManualDomainProvider::new()),
        );
        Self { providers }
    }

    /// Register or override a provider implementation for `provider.provider_kind()`.
    pub fn insert(&mut self, provider: Arc<dyn DomainProvider>) {
        self.providers.insert(provider.provider_kind(), provider);
    }

    /// Look up the provider for `kind`.
    pub fn get(&self, kind: DomainProviderKind) -> AppResult<Arc<dyn DomainProvider>> {
        self.providers.get(&kind).cloned().ok_or_else(|| {
            AppError::Config(format!(
                "Domain provider '{}' is not configured",
                kind.as_str()
            ))
        })
    }
}

fn build_http_client() -> reqwest::Client {
    crate::ensure_crypto_provider();
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
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

// ============================================================================
// AWS SESv2 `DomainProvider` (`SesDomainProvider`)
// ============================================================================

/// AWS SESv2 [`DomainProvider`] calling `CreateEmailIdentity`, `GetEmailIdentity`,
/// and `DeleteEmailIdentity` with AWS Signature Version 4 signing.
#[derive(Clone, Debug)]
pub struct SesDomainProvider {
    config: SesConfig,
    http: reqwest::Client,
}

impl SesDomainProvider {
    pub fn new(config: SesConfig) -> Self {
        Self {
            config,
            http: build_http_client(),
        }
    }

    pub fn from_config(config: &Config) -> AppResult<Self> {
        Ok(Self::new(SesConfig::from_config(config)?))
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.config.endpoint = endpoint.into().trim_end_matches('/').to_string();
        self
    }

    fn require_credentials(&self) -> AppResult<(&str, &str, Option<&str>)> {
        let access_key_id = self
            .config
            .access_key_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AppError::Config(
                    "NOGML_SES_ACCESS_KEY_ID must be configured for AWS SES domain operations"
                        .to_string(),
                )
            })?;
        let secret_access_key = self
            .config
            .secret_access_key
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AppError::Config(
                    "NOGML_SES_SECRET_ACCESS_KEY must be configured for AWS SES domain operations"
                        .to_string(),
                )
            })?;
        let session_token = self
            .config
            .session_token
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        Ok((access_key_id, secret_access_key, session_token))
    }

    async fn send_signed(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> AppResult<(reqwest::StatusCode, String)> {
        let (access_key_id, secret_access_key, session_token) = self.require_credentials()?;
        let url_str = format!("{}{}", self.config.endpoint.trim_end_matches('/'), path);
        let url = Url::parse(&url_str)
            .map_err(|e| AppError::Config(format!("Invalid SES domain URL '{url_str}': {e}")))?;

        let payload = body.unwrap_or_default();
        let extra_headers: &[(&str, &str)] = if payload.is_empty() {
            &[]
        } else {
            &[("content-type", "application/json")]
        };

        let sig = sign_aws_v4(
            method.as_str(),
            &url,
            extra_headers,
            &payload,
            access_key_id,
            secret_access_key,
            session_token,
            &self.config.region,
            "ses",
            Utc::now(),
        )?;

        let mut req = self
            .http
            .request(method, url)
            .header("authorization", sig.authorization)
            .header("x-amz-date", sig.amz_date)
            .header("x-amz-content-sha256", sig.payload_hash);

        if !payload.is_empty() {
            req = req.header("content-type", "application/json").body(payload);
        }
        if let Some(tok) = sig.session_token {
            req = req.header("x-amz-security-token", tok);
        }

        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        Ok((status, text))
    }

    fn build_records_from_ses(
        &self,
        domain: &str,
        resp: &SesIdentityResponse,
    ) -> ProviderDomainResult {
        let dkim_status = resp
            .dkim_attributes
            .as_ref()
            .and_then(|d| d.status.as_deref())
            .unwrap_or("")
            .to_ascii_uppercase();
        let verification_status = resp
            .verification_status
            .as_deref()
            .unwrap_or("")
            .to_ascii_uppercase();
        let mail_from_status = resp
            .mail_from_attributes
            .as_ref()
            .and_then(|m| m.mail_from_domain_status.as_deref())
            .unwrap_or("")
            .to_ascii_uppercase();

        let dkim_verified = dkim_status == "SUCCESS";
        let verified_for_sending = resp.verified_for_sending_status.unwrap_or(false);
        let spf_verified = mail_from_status == "SUCCESS" || verified_for_sending;
        let mx_verified = mail_from_status == "SUCCESS";
        let dmarc_verified = false;

        let status = if verified_for_sending || verification_status == "SUCCESS" {
            DomainStatus::Verified
        } else if verification_status == "FAILED"
            || verification_status == "TEMPORARY_FAILURE"
            || dkim_status == "FAILED"
            || dkim_status == "TEMPORARY_FAILURE"
        {
            DomainStatus::Failed
        } else {
            DomainStatus::Pending
        };

        let mut dns_records = Vec::new();

        if let Some(dkim) = &resp.dkim_attributes {
            for token in &dkim.tokens {
                let clean = token.trim();
                if clean.is_empty() {
                    continue;
                }
                dns_records.push(DnsRecord {
                    record_type: "CNAME".to_string(),
                    name: format!("{clean}._domainkey.{domain}"),
                    value: format!("{clean}.dkim.amazonses.com"),
                    priority: None,
                    purpose: DnsRecordPurpose::Dkim,
                    verified: dkim_verified,
                });
            }
        }

        // Inbound MX record for AWS SES receiving in this region.
        dns_records.push(DnsRecord {
            record_type: "MX".to_string(),
            name: domain.to_string(),
            value: format!("inbound-smtp.{}.amazonaws.com", self.config.region),
            priority: Some(10),
            purpose: DnsRecordPurpose::Mx,
            verified: mx_verified,
        });

        // Recommended SPF record for SES sending.
        dns_records.push(DnsRecord {
            record_type: "TXT".to_string(),
            name: domain.to_string(),
            value: "v=spf1 include:amazonses.com ~all".to_string(),
            priority: None,
            purpose: DnsRecordPurpose::Spf,
            verified: spf_verified,
        });

        // Optional custom MAIL FROM records when SES reports MailFromAttributes.
        if let Some(mf) = &resp.mail_from_attributes
            && let Some(mf_domain) = mf
                .mail_from_domain
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
        {
            let mf_ok = mail_from_status == "SUCCESS";
            dns_records.push(DnsRecord {
                record_type: "MX".to_string(),
                name: mf_domain.to_string(),
                value: format!("feedback-smtp.{}.amazonaws.com", self.config.region),
                priority: Some(10),
                purpose: DnsRecordPurpose::MailFrom,
                verified: mf_ok,
            });
            dns_records.push(DnsRecord {
                record_type: "TXT".to_string(),
                name: mf_domain.to_string(),
                value: "v=spf1 include:amazonses.com ~all".to_string(),
                priority: None,
                purpose: DnsRecordPurpose::MailFrom,
                verified: mf_ok,
            });
        }

        // Baseline DMARC policy record.
        dns_records.push(DnsRecord {
            record_type: "TXT".to_string(),
            name: format!("_dmarc.{domain}"),
            value: "v=DMARC1; p=none;".to_string(),
            priority: None,
            purpose: DnsRecordPurpose::Dmarc,
            verified: dmarc_verified,
        });

        let last_error = resp
            .verification_info
            .as_ref()
            .and_then(|v| v.error_type.clone())
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                (status == DomainStatus::Failed).then(|| {
                    if !verification_status.is_empty() {
                        format!("SES verification status: {verification_status}")
                    } else {
                        format!("SES DKIM status: {dkim_status}")
                    }
                })
            });

        ProviderDomainResult {
            provider_domain_id: Some(domain.to_string()),
            status,
            dns_records,
            dkim_verified,
            spf_verified,
            dmarc_verified,
            mx_verified,
            last_error,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct SesCreateEmailIdentityRequest<'a> {
    email_identity: &'a str,
}

#[derive(Debug, Default, Deserialize)]
struct SesIdentityResponse {
    #[serde(
        default,
        alias = "VerifiedForSendingStatus",
        alias = "verifiedForSendingStatus"
    )]
    verified_for_sending_status: Option<bool>,
    #[serde(default, alias = "VerificationStatus", alias = "verificationStatus")]
    verification_status: Option<String>,
    #[serde(default, alias = "DkimAttributes", alias = "dkimAttributes")]
    dkim_attributes: Option<SesDkimAttributes>,
    #[serde(default, alias = "MailFromAttributes", alias = "mailFromAttributes")]
    mail_from_attributes: Option<SesMailFromAttributes>,
    #[serde(default, alias = "VerificationInfo", alias = "verificationInfo")]
    verification_info: Option<SesVerificationInfo>,
}

#[derive(Debug, Default, Deserialize)]
struct SesDkimAttributes {
    #[serde(default, alias = "Status", alias = "status")]
    status: Option<String>,
    #[serde(default, alias = "Tokens", alias = "tokens")]
    tokens: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SesMailFromAttributes {
    #[serde(default, alias = "MailFromDomain", alias = "mailFromDomain")]
    mail_from_domain: Option<String>,
    #[serde(
        default,
        alias = "MailFromDomainStatus",
        alias = "mailFromDomainStatus"
    )]
    mail_from_domain_status: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SesVerificationInfo {
    #[serde(default, alias = "ErrorType", alias = "errorType")]
    error_type: Option<String>,
}

fn map_ses_http_error(operation: &str, status: reqwest::StatusCode, body: &str) -> AppError {
    let snippet = truncate_snippet(body);
    match status.as_u16() {
        401 => AppError::Unauthorized(format!("AWS SES {operation} unauthorized: {snippet}")),
        403 => AppError::Forbidden(format!("AWS SES {operation} forbidden: {snippet}")),
        404 => AppError::NotFound(format!("AWS SES {operation} not found: {snippet}")),
        409 => AppError::Conflict(format!("AWS SES {operation} conflict: {snippet}")),
        429 => AppError::RateLimited(format!("AWS SES {operation} rate limited: {snippet}")),
        code => AppError::Upstream {
            status: code,
            message: format!("AWS SES {operation} failed (HTTP {code}): {snippet}"),
        },
    }
}

#[async_trait]
impl DomainProvider for SesDomainProvider {
    fn provider_kind(&self) -> DomainProviderKind {
        DomainProviderKind::Ses
    }

    async fn create_domain(&self, domain: &str) -> AppResult<ProviderDomainResult> {
        let domain = normalize_and_validate_domain(domain)?;
        let payload = serde_json::to_vec(&SesCreateEmailIdentityRequest {
            email_identity: &domain,
        })?;
        let (status, body) = self
            .send_signed(reqwest::Method::POST, "/v2/email/identities", Some(payload))
            .await?;

        if !status.is_success() {
            return Err(map_ses_http_error("CreateEmailIdentity", status, &body));
        }

        let parsed: SesIdentityResponse =
            serde_json::from_str(&body).map_err(|e| AppError::Upstream {
                status: status.as_u16(),
                message: format!("Invalid AWS SES CreateEmailIdentity JSON response: {e}"),
            })?;
        Ok(self.build_records_from_ses(&domain, &parsed))
    }

    async fn get_verification_status(
        &self,
        domain: &str,
        _provider_domain_id: Option<&str>,
    ) -> AppResult<ProviderDomainResult> {
        let domain = normalize_and_validate_domain(domain)?;
        let path = format!("/v2/email/identities/{domain}");
        let (status, body) = self.send_signed(reqwest::Method::GET, &path, None).await?;

        if !status.is_success() {
            return Err(map_ses_http_error("GetEmailIdentity", status, &body));
        }

        let parsed: SesIdentityResponse =
            serde_json::from_str(&body).map_err(|e| AppError::Upstream {
                status: status.as_u16(),
                message: format!("Invalid AWS SES GetEmailIdentity JSON response: {e}"),
            })?;
        Ok(self.build_records_from_ses(&domain, &parsed))
    }

    async fn delete_domain(
        &self,
        domain: &str,
        _provider_domain_id: Option<&str>,
    ) -> AppResult<()> {
        let domain = normalize_and_validate_domain(domain)?;
        let path = format!("/v2/email/identities/{domain}");
        let (status, body) = self
            .send_signed(reqwest::Method::DELETE, &path, None)
            .await?;

        if status.is_success() || status == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        Err(map_ses_http_error("DeleteEmailIdentity", status, &body))
    }
}

// ============================================================================
// Resend `DomainProvider` (`ResendDomainProvider`)
// ============================================================================

/// Resend [`DomainProvider`] calling `POST /domains`, `POST /domains/{id}/verify`,
/// `GET /domains/{id}`, and `DELETE /domains/{id}`.
#[derive(Clone)]
pub struct ResendDomainProvider {
    base_url: String,
    api_key: Option<String>,
    region: Option<String>,
    http: reqwest::Client,
}

impl std::fmt::Debug for ResendDomainProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResendDomainProvider")
            .field("base_url", &self.base_url)
            .field(
                "api_key",
                &self
                    .api_key
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .map(|_| crate::secrets::REDACTED),
            )
            .field("region", &self.region)
            .finish()
    }
}

impl ResendDomainProvider {
    pub fn new(base_url: impl Into<String>, api_key: Option<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key,
            region: None,
            http: build_http_client(),
        }
    }

    pub fn from_config(config: &Config) -> Self {
        Self::new(&config.resend_base_url, config.resend_api_key.clone())
    }

    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        let trimmed = region.into().trim().to_string();
        self.region = (!trimmed.is_empty()).then_some(trimmed);
        self
    }

    fn require_api_key(&self, operation: &str) -> AppResult<&str> {
        self.api_key
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AppError::Config(format!(
                    "Resend API key is not configured for {operation}; set RESEND_API_KEY or --resend-api-key"
                ))
            })
    }

    fn validate_provider_id<'a>(&self, provider_domain_id: Option<&'a str>) -> AppResult<&'a str> {
        let id = provider_domain_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AppError::BadRequest("Missing Resend provider_domain_id for domain".to_string())
            })?;
        if id.contains('/')
            || id.contains('\\')
            || id.contains("..")
            || id.contains('?')
            || id.contains('#')
            || id.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(AppError::BadRequest(format!(
                "Invalid Resend domain ID '{id}'"
            )));
        }
        Ok(id)
    }
}

#[derive(Debug, Serialize)]
struct ResendCreateDomainRequest<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<&'a str>,
}

#[derive(Debug, Default, Deserialize)]
struct ResendDomainResponse {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    records: Vec<ResendDnsRecord>,
}

#[derive(Debug, Default, Deserialize)]
struct ResendDnsRecord {
    #[serde(default)]
    record: String,
    #[serde(default)]
    name: String,
    #[serde(rename = "type", default)]
    record_type: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    priority: Option<u16>,
    #[serde(default)]
    status: Option<String>,
}

fn classify_resend_record_purpose(rec: &ResendDnsRecord) -> DnsRecordPurpose {
    let label = rec.record.trim().to_ascii_lowercase();
    let rtype = rec.record_type.trim().to_ascii_uppercase();
    let name = rec.name.trim().to_ascii_lowercase();
    let val = rec.value.trim().to_ascii_lowercase();

    if label.contains("dkim") || name.contains("_domainkey") || val.contains("v=dkim1") {
        DnsRecordPurpose::Dkim
    } else if label.contains("dmarc") || name.starts_with("_dmarc") || val.starts_with("v=dmarc1") {
        DnsRecordPurpose::Dmarc
    } else if label.contains("receiving") || (rtype == "MX" && !label.contains("spf")) {
        DnsRecordPurpose::Mx
    } else if label.contains("spf") && rtype == "MX" {
        DnsRecordPurpose::MailFrom
    } else if label.contains("spf") || val.starts_with("v=spf1") {
        DnsRecordPurpose::Spf
    } else if rtype == "MX" {
        DnsRecordPurpose::Mx
    } else {
        DnsRecordPurpose::Other
    }
}

fn resend_response_to_result(
    resp: ResendDomainResponse,
    fallback_id: Option<&str>,
) -> ProviderDomainResult {
    let provider_domain_id = resp
        .id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .or_else(|| fallback_id.map(ToString::to_string));

    let status = resp
        .status
        .as_deref()
        .and_then(DomainStatus::parse_str)
        .unwrap_or(DomainStatus::Pending);

    let mut dns_records = Vec::with_capacity(resp.records.len());
    let mut dkim_total = 0usize;
    let mut dkim_ok = 0usize;
    let mut spf_total = 0usize;
    let mut spf_ok = 0usize;
    let mut dmarc_total = 0usize;
    let mut dmarc_ok = 0usize;
    let mut mx_total = 0usize;
    let mut mx_ok = 0usize;

    for rec in &resp.records {
        let purpose = classify_resend_record_purpose(rec);
        let verified = rec
            .status
            .as_deref()
            .is_some_and(|s| s.trim().eq_ignore_ascii_case("verified"));
        match purpose {
            DnsRecordPurpose::Dkim => {
                dkim_total += 1;
                if verified {
                    dkim_ok += 1;
                }
            }
            DnsRecordPurpose::Spf | DnsRecordPurpose::MailFrom => {
                spf_total += 1;
                if verified {
                    spf_ok += 1;
                }
            }
            DnsRecordPurpose::Dmarc => {
                dmarc_total += 1;
                if verified {
                    dmarc_ok += 1;
                }
            }
            DnsRecordPurpose::Mx => {
                mx_total += 1;
                if verified {
                    mx_ok += 1;
                }
            }
            DnsRecordPurpose::Verification | DnsRecordPurpose::Other => {}
        }

        dns_records.push(DnsRecord {
            record_type: rec.record_type.trim().to_ascii_uppercase(),
            name: rec.name.trim().to_string(),
            value: rec.value.trim().to_string(),
            priority: rec.priority,
            purpose,
            verified,
        });
    }

    let dkim_verified = if dkim_total > 0 {
        dkim_ok == dkim_total
    } else {
        status == DomainStatus::Verified
    };
    let spf_verified = if spf_total > 0 {
        spf_ok == spf_total
    } else {
        status == DomainStatus::Verified
    };
    let dmarc_verified = dmarc_total > 0 && dmarc_ok == dmarc_total;
    let mx_verified = mx_total > 0 && mx_ok == mx_total;

    let last_error = (status == DomainStatus::Failed).then(|| {
        format!(
            "Resend domain verification status: {}",
            resp.status.as_deref().unwrap_or("failed")
        )
    });

    ProviderDomainResult {
        provider_domain_id,
        status,
        dns_records,
        dkim_verified,
        spf_verified,
        dmarc_verified,
        mx_verified,
        last_error,
    }
}

#[async_trait]
impl DomainProvider for ResendDomainProvider {
    fn provider_kind(&self) -> DomainProviderKind {
        DomainProviderKind::Resend
    }

    async fn create_domain(&self, domain: &str) -> AppResult<ProviderDomainResult> {
        let domain = normalize_and_validate_domain(domain)?;
        let api_key = self.require_api_key("Resend domain creation")?;
        let url = format!("{}/domains", self.base_url);

        let resp = self
            .http
            .post(&url)
            .bearer_auth(api_key)
            .json(&ResendCreateDomainRequest {
                name: &domain,
                region: self.region.as_deref(),
            })
            .send()
            .await?;

        let status = resp.status();
        let bytes = resp.bytes().await?;
        if !status.is_success() {
            return Err(map_resend_error(status, &bytes));
        }

        let parsed: ResendDomainResponse =
            serde_json::from_slice(&bytes).map_err(|e| AppError::Upstream {
                status: status.as_u16(),
                message: format!("Invalid Resend POST /domains response: {e}"),
            })?;
        Ok(resend_response_to_result(parsed, None))
    }

    async fn get_verification_status(
        &self,
        _domain: &str,
        provider_domain_id: Option<&str>,
    ) -> AppResult<ProviderDomainResult> {
        let api_key = self.require_api_key("Resend domain lookup")?;
        let id = self.validate_provider_id(provider_domain_id)?;
        let url = format!("{}/domains/{id}", self.base_url);

        let resp = self.http.get(&url).bearer_auth(api_key).send().await?;
        let status = resp.status();
        let bytes = resp.bytes().await?;
        if !status.is_success() {
            return Err(map_resend_error(status, &bytes));
        }

        let parsed: ResendDomainResponse =
            serde_json::from_slice(&bytes).map_err(|e| AppError::Upstream {
                status: status.as_u16(),
                message: format!("Invalid Resend GET /domains/{id} response: {e}"),
            })?;
        Ok(resend_response_to_result(parsed, Some(id)))
    }

    async fn verify_domain(
        &self,
        domain: &str,
        provider_domain_id: Option<&str>,
    ) -> AppResult<ProviderDomainResult> {
        let api_key = self.require_api_key("Resend domain verification")?;
        let id = self.validate_provider_id(provider_domain_id)?;
        let verify_url = format!("{}/domains/{id}/verify", self.base_url);

        let resp = self
            .http
            .post(&verify_url)
            .bearer_auth(api_key)
            .send()
            .await?;
        let status = resp.status();
        let bytes = resp.bytes().await?;
        if !status.is_success() {
            return Err(map_resend_error(status, &bytes));
        }

        self.get_verification_status(domain, Some(id)).await
    }

    async fn delete_domain(
        &self,
        _domain: &str,
        provider_domain_id: Option<&str>,
    ) -> AppResult<()> {
        let Some(id) = provider_domain_id.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(());
        };
        let id = self.validate_provider_id(Some(id))?;
        let api_key = self.require_api_key("Resend domain deletion")?;
        let url = format!("{}/domains/{id}", self.base_url);

        let resp = self.http.delete(&url).bearer_auth(api_key).send().await?;
        let status = resp.status();
        if status.is_success() || status == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        let bytes = resp.bytes().await?;
        Err(map_resend_error(status, &bytes))
    }
}

// ============================================================================
// Manual / Self-Hosted SMTP `DomainProvider` (`ManualDomainProvider`)
// ============================================================================

/// Manual [`DomainProvider`] for self-hosted SMTP or externally managed DNS setups.
#[derive(Debug, Clone, Default)]
pub struct ManualDomainProvider {
    mx_host_override: Option<String>,
}

impl ManualDomainProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_mx_host(mut self, mx_host: impl Into<String>) -> Self {
        let trimmed = mx_host.into().trim().to_string();
        self.mx_host_override = (!trimmed.is_empty()).then_some(trimmed);
        self
    }

    fn recommended_records(&self, domain: &str) -> Vec<DnsRecord> {
        let mx_target = self
            .mx_host_override
            .clone()
            .unwrap_or_else(|| format!("mail.{domain}"));
        vec![
            DnsRecord {
                record_type: "MX".to_string(),
                name: domain.to_string(),
                value: mx_target,
                priority: Some(10),
                purpose: DnsRecordPurpose::Mx,
                verified: false,
            },
            DnsRecord {
                record_type: "TXT".to_string(),
                name: domain.to_string(),
                value: "v=spf1 mx a ~all".to_string(),
                priority: None,
                purpose: DnsRecordPurpose::Spf,
                verified: false,
            },
            DnsRecord {
                record_type: "TXT".to_string(),
                name: format!("default._domainkey.{domain}"),
                value: "v=DKIM1; k=rsa; p=<YOUR_DKIM_PUBLIC_KEY>".to_string(),
                priority: None,
                purpose: DnsRecordPurpose::Dkim,
                verified: false,
            },
            DnsRecord {
                record_type: "TXT".to_string(),
                name: format!("_dmarc.{domain}"),
                value: "v=DMARC1; p=none;".to_string(),
                priority: None,
                purpose: DnsRecordPurpose::Dmarc,
                verified: false,
            },
        ]
    }
}

#[async_trait]
impl DomainProvider for ManualDomainProvider {
    fn provider_kind(&self) -> DomainProviderKind {
        DomainProviderKind::Manual
    }

    async fn create_domain(&self, domain: &str) -> AppResult<ProviderDomainResult> {
        let domain = normalize_and_validate_domain(domain)?;
        Ok(ProviderDomainResult {
            provider_domain_id: None,
            status: DomainStatus::Pending,
            dns_records: self.recommended_records(&domain),
            dkim_verified: false,
            spf_verified: false,
            dmarc_verified: false,
            mx_verified: false,
            last_error: None,
        })
    }

    async fn get_verification_status(
        &self,
        domain: &str,
        _provider_domain_id: Option<&str>,
    ) -> AppResult<ProviderDomainResult> {
        let domain = normalize_and_validate_domain(domain)?;
        Ok(ProviderDomainResult {
            provider_domain_id: None,
            status: DomainStatus::Pending,
            dns_records: self.recommended_records(&domain),
            dkim_verified: false,
            spf_verified: false,
            dmarc_verified: false,
            mx_verified: false,
            last_error: None,
        })
    }

    async fn delete_domain(
        &self,
        _domain: &str,
        _provider_domain_id: Option<&str>,
    ) -> AppResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_and_validate_domain_accepts_valid_and_punycode() {
        assert_eq!(
            normalize_and_validate_domain("Example.COM").unwrap(),
            "example.com"
        );
        assert_eq!(
            normalize_and_validate_domain("  mail.sub-1.example.co.uk. ").unwrap(),
            "mail.sub-1.example.co.uk"
        );
        assert_eq!(
            normalize_and_validate_domain("münchen.de").unwrap(),
            "xn--mnchen-3ya.de"
        );
        assert_eq!(
            normalize_and_validate_domain("XN--MNCHEN-3YA.DE").unwrap(),
            "xn--mnchen-3ya.de"
        );
    }

    #[test]
    fn normalize_and_validate_domain_rejects_invalid_inputs() {
        for bad in [
            "",
            "   ",
            "localhost",
            "com",
            ".example.com",
            "example..com",
            "example.com..",
            "-bad.example.com",
            "bad-.example.com",
            "*.example.com",
            "https://example.com",
            "example.com/path",
            "user@example.com",
            "example.com:443",
            "127.0.0.1",
            "[::1]",
            "123.456",
            "example.123",
            "example.c",
            "bad_label.example.com",
            "bad\r\n.example.com",
        ] {
            assert!(
                normalize_and_validate_domain(bad).is_err(),
                "expected '{bad}' to be rejected"
            );
        }

        let overlong_label = format!("{}.com", "a".repeat(64));
        assert!(normalize_and_validate_domain(&overlong_label).is_err());

        let overlong_domain = format!(
            "{}.{}.{}.{}.com",
            "a".repeat(60),
            "b".repeat(60),
            "c".repeat(60),
            "d".repeat(60)
        );
        assert!(overlong_domain.len() <= 253);
        assert!(normalize_and_validate_domain(&overlong_domain).is_ok());

        let too_long_domain = format!(
            "{}.{}.{}.{}.{}.com",
            "a".repeat(60),
            "b".repeat(60),
            "c".repeat(60),
            "d".repeat(60),
            "e".repeat(20)
        );
        assert!(too_long_domain.len() > 253);
        assert!(normalize_and_validate_domain(&too_long_domain).is_err());
    }

    #[tokio::test]
    async fn manual_domain_provider_returns_expected_dns_records() {
        let provider = ManualDomainProvider::new();
        let res = provider.create_domain("Acme.IO").await.unwrap();
        assert_eq!(res.status, DomainStatus::Pending);
        assert!(res.provider_domain_id.is_none());
        assert_eq!(res.dns_records.len(), 4);
        assert!(
            res.dns_records
                .iter()
                .any(|r| r.purpose == DnsRecordPurpose::Mx && r.value == "mail.acme.io")
        );
        assert!(
            res.dns_records
                .iter()
                .any(|r| r.purpose == DnsRecordPurpose::Spf && r.name == "acme.io")
        );
        assert!(
            res.dns_records
                .iter()
                .any(|r| r.purpose == DnsRecordPurpose::Dkim
                    && r.name == "default._domainkey.acme.io")
        );
        assert!(
            res.dns_records
                .iter()
                .any(|r| r.purpose == DnsRecordPurpose::Dmarc && r.name == "_dmarc.acme.io")
        );
    }
}
