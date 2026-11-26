//! Deliverability protection: persistent suppression lists, per-domain daily send
//! quotas, rolling bounce/complaint circuit breakers, and outbound safety policies.

use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    ai::safety::{
        OutboundCheck, OutboundDecision, OutboundPolicy, PolicyCheck, extract_email_address,
    },
    config::Config,
    error::{AppError, AppResult},
    storage::{
        MailStore, extract_email_domain, normalize_domain_lookup_key, normalize_optional_text,
    },
};

/// Default rolling maximum hard-bounce rate before tripping a domain circuit breaker (5%).
pub const DEFAULT_MAX_BOUNCE_RATE: f64 = 0.05;
/// Default rolling maximum complaint rate before tripping a domain circuit breaker (0.1%).
pub const DEFAULT_MAX_COMPLAINT_RATE: f64 = 0.001;
/// Default minimum sample size before bounce/complaint rates can trip a circuit breaker.
pub const DEFAULT_DELIVERABILITY_MIN_SAMPLES: u64 = 20;
/// Default rolling window (24 hours) for bounce/complaint rate evaluation.
pub const DEFAULT_DELIVERABILITY_WINDOW_SECS: u64 = 86_400;
/// Milliseconds in a UTC day.
pub const MILLIS_PER_DAY: i64 = 86_400_000;

/// Reason an email address was placed on the suppression list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionReason {
    HardBounce,
    Complaint,
    Unsubscribe,
    Manual,
}

impl SuppressionReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HardBounce => "hard_bounce",
            Self::Complaint => "complaint",
            Self::Unsubscribe => "unsubscribe",
            Self::Manual => "manual",
        }
    }

    pub fn parse_str(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "hard_bounce" | "hardbounce" | "bounce" => Some(Self::HardBounce),
            "complaint" | "complained" | "spam" => Some(Self::Complaint),
            "unsubscribe" | "unsubscribed" => Some(Self::Unsubscribe),
            "manual" => Some(Self::Manual),
            _ => None,
        }
    }
}

impl std::fmt::Display for SuppressionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Origin system that added a suppression entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionSource {
    SesSns,
    Resend,
    Manual,
}

impl SuppressionSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SesSns => "ses_sns",
            Self::Resend => "resend",
            Self::Manual => "manual",
        }
    }

    pub fn parse_str(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "ses_sns" | "ses" | "sns" => Some(Self::SesSns),
            "resend" => Some(Self::Resend),
            "manual" => Some(Self::Manual),
            _ => None,
        }
    }
}

impl std::fmt::Display for SuppressionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Persistent suppression record blocking outbound delivery to `email`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressionEntry {
    pub email: String,
    pub reason: SuppressionReason,
    pub source: SuppressionSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub created_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<i64>,
}

impl SuppressionEntry {
    /// Returns `true` when this suppression entry is active at `now_ms`.
    pub fn is_active(&self, now_ms: i64) -> bool {
        self.expires_at_ms.is_none_or(|exp| exp > now_ms)
    }
}

/// Input used to insert or update a suppression entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSuppressionInput {
    pub email: String,
    pub reason: SuppressionReason,
    pub source: SuppressionSource,
    pub detail: Option<String>,
    pub created_at_ms: Option<i64>,
    pub expires_at_ms: Option<i64>,
}

/// Filter parameters for [`MailStore::list_suppressions`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuppressionQuery {
    pub q: Option<String>,
    pub reason: Option<SuppressionReason>,
    pub source: Option<SuppressionSource>,
    pub include_expired: bool,
    pub limit: usize,
}

/// Category of deliverability telemetry event recorded per sender domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliverabilityEventKind {
    Sent,
    HardBounce,
    SoftBounce,
    Complaint,
}

impl DeliverabilityEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::HardBounce => "hard_bounce",
            Self::SoftBounce => "soft_bounce",
            Self::Complaint => "complaint",
        }
    }

    pub fn parse_str(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "sent" => Some(Self::Sent),
            "hard_bounce" => Some(Self::HardBounce),
            "soft_bounce" => Some(Self::SoftBounce),
            "complaint" => Some(Self::Complaint),
            _ => None,
        }
    }
}

impl std::fmt::Display for DeliverabilityEventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Persistent deliverability telemetry event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliverabilityEvent {
    pub id: String,
    pub domain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mailbox_id: Option<String>,
    pub kind: DeliverabilityEventKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub created_at_ms: i64,
}

/// Input used to record a new [`DeliverabilityEvent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDeliverabilityEvent {
    pub domain: String,
    pub mailbox_id: Option<String>,
    pub kind: DeliverabilityEventKind,
    pub recipient: Option<String>,
    pub provider: Option<String>,
    pub detail: Option<String>,
    pub created_at_ms: Option<i64>,
}

/// Aggregated deliverability event counts for a sender domain over a time window.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliverabilityCounts {
    pub domain: String,
    pub sent: u64,
    pub hard_bounce: u64,
    pub soft_bounce: u64,
    pub complaint: u64,
}

/// Persisted manual pause/resume override state for a sender domain's circuit breaker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainDeliverabilityState {
    pub domain: String,
    pub manually_paused: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pause_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resumed_at_ms: Option<i64>,
    pub updated_at_ms: i64,
}

/// Evaluated state of a sender domain's outbound circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitBreakerState {
    Closed,
    OpenBounceRate,
    OpenComplaintRate,
    Paused,
}

/// Detailed circuit breaker evaluation for a sender domain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CircuitBreakerStatus {
    pub state: CircuitBreakerState,
    pub tripped: bool,
    pub manually_paused: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resumed_at_ms: Option<i64>,
}

/// Active deliverability threshold settings used for circuit breaking and quotas.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DeliverabilityThresholds {
    pub daily_send_limit_per_domain: u64,
    pub max_bounce_rate: f64,
    pub max_complaint_rate: f64,
    pub min_samples: u64,
    pub window_secs: u64,
}

impl Default for DeliverabilityThresholds {
    fn default() -> Self {
        Self {
            daily_send_limit_per_domain: 0,
            max_bounce_rate: DEFAULT_MAX_BOUNCE_RATE,
            max_complaint_rate: DEFAULT_MAX_COMPLAINT_RATE,
            min_samples: DEFAULT_DELIVERABILITY_MIN_SAMPLES,
            window_secs: DEFAULT_DELIVERABILITY_WINDOW_SECS,
        }
    }
}

impl DeliverabilityThresholds {
    pub fn from_config(config: &Config) -> Self {
        Self {
            daily_send_limit_per_domain: config.daily_send_limit_per_domain,
            max_bounce_rate: config.deliverability_max_bounce_rate,
            max_complaint_rate: config.deliverability_max_complaint_rate,
            min_samples: config.deliverability_min_samples,
            window_secs: config.deliverability_window_secs,
        }
    }

    pub fn window_ms(&self) -> i64 {
        (self.window_secs.saturating_mul(1000)).min(i64::MAX as u64) as i64
    }
}

/// Computed deliverability statistics and circuit-breaker status for a single sender domain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DomainDeliverabilityStats {
    pub domain: String,
    pub sent: u64,
    pub hard_bounce: u64,
    pub soft_bounce: u64,
    pub complaint: u64,
    pub bounce_rate: f64,
    pub complaint_rate: f64,
    pub daily_sent: u64,
    pub daily_limit: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daily_remaining: Option<u64>,
    pub circuit_breaker: CircuitBreakerStatus,
}

/// Response body returned by `GET /v1/deliverability/stats`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeliverabilityStatsResponse {
    pub config: DeliverabilityThresholds,
    pub suppression_count: usize,
    pub domains: Vec<DomainDeliverabilityStats>,
}

/// Normalize and validate an email address for suppression list storage.
pub fn validate_and_normalize_suppression_email(raw: &str) -> AppResult<String> {
    let (email, _) = crate::storage::validate_and_normalize_contact_email(raw).map_err(|_| {
        AppError::validation(
            format!("Invalid email address for suppression list: '{raw}'"),
            Some("Provide a valid bare email address such as user@example.com.".to_string()),
        )
    })?;
    Ok(email)
}

/// Normalize a domain key for deliverability counters and overrides.
pub fn normalize_deliverability_domain(raw: &str) -> String {
    normalize_domain_lookup_key(raw)
}

/// Validate and normalize a sender domain path/query parameter.
pub fn validate_deliverability_domain(raw: &str) -> AppResult<String> {
    let norm = normalize_deliverability_domain(raw);
    if norm.is_empty()
        || norm.len() > 255
        || norm.starts_with('.')
        || norm.ends_with('.')
        || norm.contains("..")
        || !norm
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return Err(AppError::validation(
            format!("Invalid sender domain '{raw}'"),
            Some("Provide a valid DNS domain name such as example.com.".to_string()),
        ));
    }
    Ok(norm)
}

/// Extract normalized sender domain from a raw `From:` value, falling back to `default_domain`.
pub fn resolve_sender_domain(from: &str, default_domain: &str) -> String {
    let email = extract_email_address(from);
    let from_domain = normalize_deliverability_domain(&extract_email_domain(&email));
    if !from_domain.is_empty() {
        from_domain
    } else {
        normalize_deliverability_domain(default_domain)
    }
}

/// Return Unix epoch milliseconds for the start of the UTC calendar day containing `now_ms`.
pub fn utc_day_start_ms(now_ms: i64) -> i64 {
    now_ms - now_ms.rem_euclid(MILLIS_PER_DAY)
}

/// Evaluate bounce/complaint rates and circuit-breaker status from rolling counts, daily sent
/// count, manual state override, and configured thresholds.
pub fn evaluate_domain_stats(
    domain: &str,
    rolling: &DeliverabilityCounts,
    daily_sent: u64,
    override_state: Option<&DomainDeliverabilityState>,
    thresholds: DeliverabilityThresholds,
) -> DomainDeliverabilityStats {
    let denominator = rolling
        .sent
        .max(rolling.hard_bounce.saturating_add(rolling.complaint));
    let bounce_rate = if denominator > 0 {
        rolling.hard_bounce as f64 / denominator as f64
    } else {
        0.0
    };
    let complaint_rate = if denominator > 0 {
        rolling.complaint as f64 / denominator as f64
    } else {
        0.0
    };

    let manually_paused = override_state.is_some_and(|s| s.manually_paused);
    let resumed_at_ms = override_state.and_then(|s| s.resumed_at_ms);

    let circuit_breaker = if manually_paused {
        let reason = override_state
            .and_then(|s| normalize_optional_text(s.pause_reason.as_deref()))
            .unwrap_or_else(|| {
                format!("Sending from domain '{domain}' is manually paused by an administrator")
            });
        CircuitBreakerStatus {
            state: CircuitBreakerState::Paused,
            tripped: true,
            manually_paused: true,
            reason: Some(reason),
            resumed_at_ms,
        }
    } else if thresholds.max_complaint_rate > 0.0
        && denominator >= thresholds.min_samples
        && complaint_rate > thresholds.max_complaint_rate
    {
        CircuitBreakerStatus {
            state: CircuitBreakerState::OpenComplaintRate,
            tripped: true,
            manually_paused: false,
            reason: Some(format!(
                "Domain '{domain}' complaint rate {:.2}% ({}/{}) exceeds max_complaint_rate {:.2}%",
                complaint_rate * 100.0,
                rolling.complaint,
                denominator,
                thresholds.max_complaint_rate * 100.0
            )),
            resumed_at_ms,
        }
    } else if thresholds.max_bounce_rate > 0.0
        && denominator >= thresholds.min_samples
        && bounce_rate > thresholds.max_bounce_rate
    {
        CircuitBreakerStatus {
            state: CircuitBreakerState::OpenBounceRate,
            tripped: true,
            manually_paused: false,
            reason: Some(format!(
                "Domain '{domain}' hard bounce rate {:.2}% ({}/{}) exceeds max_bounce_rate {:.2}%",
                bounce_rate * 100.0,
                rolling.hard_bounce,
                denominator,
                thresholds.max_bounce_rate * 100.0
            )),
            resumed_at_ms,
        }
    } else {
        CircuitBreakerStatus {
            state: CircuitBreakerState::Closed,
            tripped: false,
            manually_paused: false,
            reason: None,
            resumed_at_ms,
        }
    };

    let daily_remaining = (thresholds.daily_send_limit_per_domain > 0).then(|| {
        thresholds
            .daily_send_limit_per_domain
            .saturating_sub(daily_sent)
    });

    DomainDeliverabilityStats {
        domain: domain.to_string(),
        sent: rolling.sent,
        hard_bounce: rolling.hard_bounce,
        soft_bounce: rolling.soft_bounce,
        complaint: rolling.complaint,
        bounce_rate,
        complaint_rate,
        daily_sent,
        daily_limit: thresholds.daily_send_limit_per_domain,
        daily_remaining,
        circuit_breaker,
    }
}

/// Compute live [`DomainDeliverabilityStats`] for `domain` from `store` at `now_ms`.
pub async fn compute_domain_stats(
    store: &dyn MailStore,
    domain: &str,
    thresholds: DeliverabilityThresholds,
    now_ms: i64,
) -> AppResult<DomainDeliverabilityStats> {
    let norm_domain = normalize_deliverability_domain(domain);
    let override_state = store.get_domain_deliverability_state(&norm_domain).await?;
    let window_start = now_ms.saturating_sub(thresholds.window_ms());
    let effective_since = override_state
        .as_ref()
        .and_then(|s| s.resumed_at_ms)
        .map_or(window_start, |resumed| window_start.max(resumed));

    let rolling = store
        .count_deliverability_events(&norm_domain, effective_since)
        .await?;
    let daily = store
        .count_deliverability_events(&norm_domain, utc_day_start_ms(now_ms))
        .await?;

    Ok(evaluate_domain_stats(
        &norm_domain,
        &rolling,
        daily.sent,
        override_state.as_ref(),
        thresholds,
    ))
}

// ============================================================================
// Outbound Deliverability Policies
// ============================================================================

/// Outbound policy rejecting sends to any recipient (`to`, `cc`, `bcc`) currently active on
/// `suppression_list`.
#[derive(Clone)]
pub struct SuppressionListPolicy {
    store: Arc<dyn MailStore>,
}

impl SuppressionListPolicy {
    pub fn new(store: Arc<dyn MailStore>) -> Self {
        Self { store }
    }

    /// Return all active suppressed recipients across `recipients` (normalized, deduplicated).
    pub async fn find_suppressed(
        store: &dyn MailStore,
        recipients: &[String],
        now_ms: i64,
    ) -> AppResult<Vec<SuppressionEntry>> {
        let mut normalized = Vec::new();
        let mut seen = HashSet::new();
        for raw in recipients {
            let email = extract_email_address(raw);
            if !email.is_empty() && seen.insert(email.clone()) {
                normalized.push(email);
            }
        }
        if normalized.is_empty() {
            return Ok(Vec::new());
        }
        store.find_suppressed_emails(&normalized, now_ms).await
    }
}

#[async_trait]
impl OutboundPolicy for SuppressionListPolicy {
    async fn evaluate(&self, check: &OutboundCheck) -> AppResult<OutboundDecision> {
        let now_ms = Utc::now().timestamp_millis();
        let all = check.all_recipients();
        let suppressed = Self::find_suppressed(self.store.as_ref(), &all, now_ms).await?;
        if suppressed.is_empty() {
            return Ok(OutboundDecision::Allow);
        }

        let emails: Vec<String> = suppressed.iter().map(|e| e.email.clone()).collect();
        Ok(OutboundDecision::Deny {
            code: "recipient_suppressed".to_string(),
            reason: format!(
                "Outbound send blocked: suppressed recipient(s): {}",
                emails.join(", ")
            ),
            hint: Some(
                "Remove suppressed recipient(s) from to/cc/bcc or delete them via DELETE /v1/suppression/{email} before retrying."
                    .to_string(),
            ),
        })
    }

    fn policy_checks(&self, _check: &OutboundCheck) -> Vec<PolicyCheck> {
        vec![PolicyCheck {
            rule: "suppression_list".to_string(),
            passed: true,
            detail: "Suppression list guard is active; suppressed recipients are blocked before transport delivery".to_string(),
        }]
    }

    fn backend_name(&self) -> &'static str {
        "suppression_list"
    }
}

/// Outbound policy enforcing a per-domain daily send cap (`daily_send_limit_per_domain`).
///
/// Disabled when `daily_send_limit_per_domain == 0`.
#[derive(Clone)]
pub struct DomainQuotaPolicy {
    store: Arc<dyn MailStore>,
    default_domain: String,
    daily_send_limit_per_domain: u64,
}

impl DomainQuotaPolicy {
    pub fn new(
        store: Arc<dyn MailStore>,
        default_domain: impl Into<String>,
        daily_send_limit_per_domain: u64,
    ) -> Self {
        Self {
            store,
            default_domain: normalize_deliverability_domain(&default_domain.into()),
            daily_send_limit_per_domain,
        }
    }

    pub fn from_config(config: &Config, store: Arc<dyn MailStore>) -> Self {
        Self::new(
            store,
            config.default_domain.clone(),
            config.daily_send_limit_per_domain,
        )
    }
}

#[async_trait]
impl OutboundPolicy for DomainQuotaPolicy {
    async fn evaluate(&self, check: &OutboundCheck) -> AppResult<OutboundDecision> {
        if self.daily_send_limit_per_domain == 0 {
            return Ok(OutboundDecision::Allow);
        }

        let domain = resolve_sender_domain(&check.from, &self.default_domain);
        if domain.is_empty() {
            return Ok(OutboundDecision::Allow);
        }

        let now_ms = Utc::now().timestamp_millis();
        let counts = self
            .store
            .count_deliverability_events(&domain, utc_day_start_ms(now_ms))
            .await?;

        if counts.sent >= self.daily_send_limit_per_domain {
            return Ok(OutboundDecision::Deny {
                code: "daily_send_limit_exceeded".to_string(),
                reason: format!(
                    "Outbound send blocked: domain '{domain}' reached daily send limit ({}/{})",
                    counts.sent, self.daily_send_limit_per_domain
                ),
                hint: Some(
                    "Wait until the next UTC day or increase NOGML_DAILY_SEND_LIMIT_PER_DOMAIN."
                        .to_string(),
                ),
            });
        }

        Ok(OutboundDecision::Allow)
    }

    fn policy_checks(&self, _check: &OutboundCheck) -> Vec<PolicyCheck> {
        if self.daily_send_limit_per_domain == 0 {
            return Vec::new();
        }
        vec![PolicyCheck {
            rule: "domain_daily_send_limit".to_string(),
            passed: true,
            detail: format!(
                "Per-domain daily send limit is configured ({} messages/day)",
                self.daily_send_limit_per_domain
            ),
        }]
    }

    fn backend_name(&self) -> &'static str {
        "domain_quota"
    }
}

/// Outbound policy enforcing rolling bounce-rate / complaint-rate circuit breaking and
/// manual pause/resume overrides per sender domain.
#[derive(Clone)]
pub struct DeliverabilityCircuitBreakerPolicy {
    store: Arc<dyn MailStore>,
    default_domain: String,
    thresholds: DeliverabilityThresholds,
}

impl DeliverabilityCircuitBreakerPolicy {
    pub fn new(
        store: Arc<dyn MailStore>,
        default_domain: impl Into<String>,
        thresholds: DeliverabilityThresholds,
    ) -> Self {
        Self {
            store,
            default_domain: normalize_deliverability_domain(&default_domain.into()),
            thresholds,
        }
    }

    pub fn from_config(config: &Config, store: Arc<dyn MailStore>) -> Self {
        Self::new(
            store,
            config.default_domain.clone(),
            DeliverabilityThresholds::from_config(config),
        )
    }
}

#[async_trait]
impl OutboundPolicy for DeliverabilityCircuitBreakerPolicy {
    async fn evaluate(&self, check: &OutboundCheck) -> AppResult<OutboundDecision> {
        let domain = resolve_sender_domain(&check.from, &self.default_domain);
        if domain.is_empty() {
            return Ok(OutboundDecision::Allow);
        }

        let now_ms = Utc::now().timestamp_millis();
        let stats =
            compute_domain_stats(self.store.as_ref(), &domain, self.thresholds, now_ms).await?;

        if stats.circuit_breaker.tripped {
            let reason = stats.circuit_breaker.reason.unwrap_or_else(|| {
                format!("Outbound send blocked: circuit breaker is open for domain '{domain}'")
            });
            return Ok(OutboundDecision::Deny {
                code: "deliverability_circuit_open".to_string(),
                reason: format!("Outbound send blocked: {reason}"),
                hint: Some(format!(
                    "Inspect GET /v1/deliverability/stats and resume via POST /v1/deliverability/domains/{domain}/resume once remediated."
                )),
            });
        }

        Ok(OutboundDecision::Allow)
    }

    fn policy_checks(&self, _check: &OutboundCheck) -> Vec<PolicyCheck> {
        vec![PolicyCheck {
            rule: "deliverability_circuit_breaker".to_string(),
            passed: true,
            detail: format!(
                "Circuit breaker active (max_bounce_rate={:.2}%, max_complaint_rate={:.2}%, min_samples={})",
                self.thresholds.max_bounce_rate * 100.0,
                self.thresholds.max_complaint_rate * 100.0,
                self.thresholds.min_samples
            ),
        }]
    }

    fn backend_name(&self) -> &'static str {
        "deliverability_circuit_breaker"
    }
}

/// Composite deliverability protection policy running:
/// 1. [`SuppressionListPolicy`]
/// 2. [`DeliverabilityCircuitBreakerPolicy`]
/// 3. [`DomainQuotaPolicy`]
#[derive(Clone)]
pub struct DeliverabilityPolicy {
    suppression: SuppressionListPolicy,
    circuit_breaker: DeliverabilityCircuitBreakerPolicy,
    quota: DomainQuotaPolicy,
}

impl DeliverabilityPolicy {
    pub fn from_config(config: &Config, store: Arc<dyn MailStore>) -> Self {
        Self {
            suppression: SuppressionListPolicy::new(store.clone()),
            circuit_breaker: DeliverabilityCircuitBreakerPolicy::from_config(config, store.clone()),
            quota: DomainQuotaPolicy::from_config(config, store),
        }
    }

    /// Evaluate live async dry-run checks against suppression list, circuit breaker, and daily quota.
    pub async fn evaluate_dry_run_checks(
        &self,
        check: &OutboundCheck,
        now_ms: i64,
    ) -> AppResult<Vec<PolicyCheck>> {
        let mut checks = Vec::new();
        let all = check.all_recipients();

        // 1. Suppression list check
        let suppressed =
            SuppressionListPolicy::find_suppressed(self.suppression.store.as_ref(), &all, now_ms)
                .await?;
        if suppressed.is_empty() {
            checks.push(PolicyCheck {
                rule: "suppression_list".to_string(),
                passed: true,
                detail: "No recipients are on the suppression list".to_string(),
            });
        } else {
            let list: Vec<String> = suppressed.iter().map(|s| s.email.clone()).collect();
            checks.push(PolicyCheck {
                rule: "suppression_list".to_string(),
                passed: false,
                detail: format!("Suppressed recipient(s): {}", list.join(", ")),
            });
        }

        // 2. Circuit breaker + daily send limit checks for sender domain
        let domain = resolve_sender_domain(&check.from, &self.circuit_breaker.default_domain);
        if !domain.is_empty() {
            let stats = compute_domain_stats(
                self.circuit_breaker.store.as_ref(),
                &domain,
                self.circuit_breaker.thresholds,
                now_ms,
            )
            .await?;

            checks.push(PolicyCheck {
                rule: "deliverability_circuit_breaker".to_string(),
                passed: !stats.circuit_breaker.tripped,
                detail: if stats.circuit_breaker.tripped {
                    stats.circuit_breaker.reason.unwrap_or_else(|| {
                        format!("Circuit breaker is open for domain '{domain}'")
                    })
                } else {
                    format!(
                        "Domain '{domain}' circuit breaker is closed (bounce_rate={:.2}%, complaint_rate={:.2}%)",
                        stats.bounce_rate * 100.0,
                        stats.complaint_rate * 100.0
                    )
                },
            });

            if self.quota.daily_send_limit_per_domain > 0 {
                let within_quota = stats.daily_sent < self.quota.daily_send_limit_per_domain;
                checks.push(PolicyCheck {
                    rule: "domain_daily_send_limit".to_string(),
                    passed: within_quota,
                    detail: if within_quota {
                        format!(
                            "Domain '{domain}' daily send usage {}/{}",
                            stats.daily_sent, self.quota.daily_send_limit_per_domain
                        )
                    } else {
                        format!(
                            "Domain '{domain}' reached daily send limit ({}/{})",
                            stats.daily_sent, self.quota.daily_send_limit_per_domain
                        )
                    },
                });
            }
        }

        Ok(checks)
    }
}

#[async_trait]
impl OutboundPolicy for DeliverabilityPolicy {
    async fn evaluate(&self, check: &OutboundCheck) -> AppResult<OutboundDecision> {
        let d = self.suppression.evaluate(check).await?;
        if matches!(d, OutboundDecision::Deny { .. }) {
            return Ok(d);
        }

        let d = self.circuit_breaker.evaluate(check).await?;
        if matches!(d, OutboundDecision::Deny { .. }) {
            return Ok(d);
        }

        self.quota.evaluate(check).await
    }

    fn policy_checks(&self, check: &OutboundCheck) -> Vec<PolicyCheck> {
        let mut out = self.suppression.policy_checks(check);
        out.extend(self.circuit_breaker.policy_checks(check));
        out.extend(self.quota.policy_checks(check));
        out
    }

    fn backend_name(&self) -> &'static str {
        "deliverability"
    }
}

/// Extract the comma-separated suppressed email list from a `recipient_suppressed` denial reason
/// so REST/MCP error envelopes can populate `error.details.suppressed`.
pub fn extract_suppressed_from_reason(reason: &str) -> Vec<String> {
    const PREFIX: &str = "suppressed recipient(s):";
    let Some(pos) = reason.find(PREFIX) else {
        return Vec::new();
    };
    reason[pos + PREFIX.len()..]
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_day_start_rounds_down_to_midnight() {
        let ts = 1_732_650_123_456i64;
        let start = utc_day_start_ms(ts);
        assert_eq!(start % MILLIS_PER_DAY, 0);
        assert!(start <= ts);
        assert!(ts - start < MILLIS_PER_DAY);
    }

    #[test]
    fn circuit_breaker_respects_min_samples_and_thresholds() {
        let thresholds = DeliverabilityThresholds {
            daily_send_limit_per_domain: 100,
            max_bounce_rate: 0.05,
            max_complaint_rate: 0.001,
            min_samples: 20,
            window_secs: 86_400,
        };

        // Single test bounce below min_samples does NOT trip.
        let small = DeliverabilityCounts {
            domain: "example.com".into(),
            sent: 1,
            hard_bounce: 1,
            soft_bounce: 0,
            complaint: 0,
        };
        let stats = evaluate_domain_stats("example.com", &small, 1, None, thresholds);
        assert!(!stats.circuit_breaker.tripped);
        assert_eq!(stats.circuit_breaker.state, CircuitBreakerState::Closed);

        // 2 bounces out of 20 sends (10% > 5%) trips bounce circuit breaker.
        let high_bounce = DeliverabilityCounts {
            domain: "example.com".into(),
            sent: 20,
            hard_bounce: 2,
            soft_bounce: 3,
            complaint: 0,
        };
        let stats = evaluate_domain_stats("example.com", &high_bounce, 20, None, thresholds);
        assert!(stats.circuit_breaker.tripped);
        assert_eq!(
            stats.circuit_breaker.state,
            CircuitBreakerState::OpenBounceRate
        );
        assert_eq!(stats.daily_remaining, Some(80));

        // 1 complaint out of 20 sends (5% > 0.1%) trips complaint circuit breaker.
        let high_complaint = DeliverabilityCounts {
            domain: "example.com".into(),
            sent: 20,
            hard_bounce: 0,
            soft_bounce: 0,
            complaint: 1,
        };
        let stats = evaluate_domain_stats("example.com", &high_complaint, 20, None, thresholds);
        assert!(stats.circuit_breaker.tripped);
        assert_eq!(
            stats.circuit_breaker.state,
            CircuitBreakerState::OpenComplaintRate
        );

        // Manual pause overrides closed state even with zero events.
        let paused = DomainDeliverabilityState {
            domain: "example.com".into(),
            manually_paused: true,
            pause_reason: Some("investigating DNS".into()),
            resumed_at_ms: None,
            updated_at_ms: 1000,
        };
        let stats = evaluate_domain_stats(
            "example.com",
            &DeliverabilityCounts::default(),
            0,
            Some(&paused),
            thresholds,
        );
        assert!(stats.circuit_breaker.tripped);
        assert!(stats.circuit_breaker.manually_paused);
        assert_eq!(stats.circuit_breaker.state, CircuitBreakerState::Paused);
        assert_eq!(
            stats.circuit_breaker.reason.as_deref(),
            Some("investigating DNS")
        );
    }

    #[test]
    fn extract_suppressed_from_reason_parses_addresses() {
        let list = extract_suppressed_from_reason(
            "Outbound send blocked: suppressed recipient(s): a@example.com, B@example.com",
        );
        assert_eq!(list, vec!["a@example.com", "b@example.com"]);
    }
}
