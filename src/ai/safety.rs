//! Agent safety guardrails, pluggable [`OutboundPolicy`], input hardening,
//! untrusted-content sanitization, recipient allowlists, `draft_only` enforcement,
//! and `dry_run` policy evaluation.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use async_trait::async_trait;

use crate::{
    AppState,
    auth::AgentPolicyOverride,
    config::{Config, DlpAction, DraftOnlyAction},
    error::{AppError, AppResult},
    mime::{ComposeEmailInput, build_rfc2822},
    models::{AiSendEmailRequest, DryRunPreview, DryRunResponse, PolicyCheckResult, UntrustedMeta},
    storage::{MailStore, parse_simple_email_address},
};

/// Alias for [`PolicyCheckResult`] exposed alongside [`OutboundPolicy`].
pub type PolicyCheck = PolicyCheckResult;

/// Outbound email metadata evaluated by [`OutboundPolicy`].
#[derive(Debug, Clone, Default)]
pub struct OutboundCheck {
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    pub attachment_filenames: Vec<String>,
    pub thread_id: Option<String>,
    pub mailbox_id: Option<String>,
    pub is_draft_send: bool,
    pub agent_policy: Option<AgentPolicyOverride>,
}

impl OutboundCheck {
    pub fn all_recipients(&self) -> Vec<String> {
        self.to
            .iter()
            .chain(self.cc.iter())
            .chain(self.bcc.iter())
            .cloned()
            .collect()
    }
}

/// Decision returned by [`OutboundPolicy::evaluate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundDecision {
    /// Proceed with outbound transport delivery.
    Allow,
    /// Save or retain the message as a local draft instead of sending externally.
    DowngradeToDraft { reason: String },
    /// Save or retain the message as a pending draft awaiting human approval (HTTP `202 Accepted`).
    HoldForApproval { reason: String },
    /// Reject the outbound send with HTTP `403 Forbidden` and structured AI error payload.
    Deny {
        code: String,
        reason: String,
        hint: Option<String>,
    },
}

/// Pluggable outbound send policy evaluated before any external email delivery.
///
/// Swap in human-in-the-loop approval queues, DLP scanners, rate/budget guards,
/// or per-agent policy engines without modifying AI/MCP/Gmail handlers.
#[async_trait]
pub trait OutboundPolicy: Send + Sync {
    async fn evaluate(&self, check: &OutboundCheck) -> AppResult<OutboundDecision>;

    /// Return structured policy checks for `dry_run` previews without side effects.
    fn policy_checks(&self, check: &OutboundCheck) -> Vec<PolicyCheck>;

    /// Return a mailbox-scoped view of this policy when backed by per-mailbox state
    /// (such as [`FirstContactPolicy`]).
    fn for_mailbox(&self, _mailbox_id: &str) -> Option<Arc<dyn OutboundPolicy>> {
        None
    }

    /// Active policy backend names in execution order.
    fn active_policies(&self) -> Vec<String> {
        vec![self.backend_name().to_string()]
    }

    /// Short backend identifier reported by `GET /v1/capabilities`.
    fn backend_name(&self) -> &'static str {
        "custom"
    }
}

fn decision_severity(decision: &OutboundDecision) -> u8 {
    match decision {
        OutboundDecision::Allow => 0,
        OutboundDecision::HoldForApproval { .. } => 1,
        OutboundDecision::DowngradeToDraft { .. } => 2,
        OutboundDecision::Deny { .. } => 3,
    }
}

/// Composable ordered chain of [`OutboundPolicy`] implementations (parallel to `FilterChain`).
///
/// Evaluates member policies in order:
/// - `Deny` short-circuits immediately.
/// - Errors propagate immediately.
/// - Otherwise returns the highest-severity (first on ties) non-`Allow` decision
///   (`Deny` > `DowngradeToDraft` > `HoldForApproval` > `Allow`), so a `draft_only`
///   downgrade is never promoted into the approval queue.
#[derive(Clone, Default)]
pub struct OutboundPolicyChain(pub Vec<Arc<dyn OutboundPolicy>>);

impl OutboundPolicyChain {
    pub fn new(policies: Vec<Arc<dyn OutboundPolicy>>) -> Self {
        Self(policies)
    }

    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn push(&mut self, policy: Arc<dyn OutboundPolicy>) {
        self.0.push(policy);
    }

    pub fn active_policy_names(&self) -> Vec<String> {
        self.0.iter().flat_map(|p| p.active_policies()).collect()
    }
}

#[async_trait]
impl OutboundPolicy for OutboundPolicyChain {
    async fn evaluate(&self, check: &OutboundCheck) -> AppResult<OutboundDecision> {
        let mut best: Option<OutboundDecision> = None;

        for policy in &self.0 {
            let decision = policy.evaluate(check).await?;
            if matches!(decision, OutboundDecision::Deny { .. }) {
                return Ok(decision);
            }
            let sev = decision_severity(&decision);
            if sev > 0 {
                let replace = best
                    .as_ref()
                    .is_none_or(|current| sev > decision_severity(current));
                if replace {
                    best = Some(decision);
                }
            }
        }

        Ok(best.unwrap_or(OutboundDecision::Allow))
    }

    fn policy_checks(&self, check: &OutboundCheck) -> Vec<PolicyCheck> {
        self.0
            .iter()
            .flat_map(|policy| policy.policy_checks(check))
            .collect()
    }

    fn for_mailbox(&self, mailbox_id: &str) -> Option<Arc<dyn OutboundPolicy>> {
        let mut changed = false;
        let scoped: Vec<Arc<dyn OutboundPolicy>> = self
            .0
            .iter()
            .map(|p| match p.for_mailbox(mailbox_id) {
                Some(next) => {
                    changed = true;
                    next
                }
                None => p.clone(),
            })
            .collect();
        changed.then(|| Arc::new(Self::new(scoped)) as Arc<dyn OutboundPolicy>)
    }

    fn active_policies(&self) -> Vec<String> {
        self.active_policy_names()
    }

    fn backend_name(&self) -> &'static str {
        match self.0.as_slice() {
            [] => "noop",
            [single] => single.backend_name(),
            _ => "chain",
        }
    }
}

/// Outbound policy that holds sends for human approval whenever any recipient in
/// `to`, `cc`, or `bcc` has no prior sent mail history (`sent_count == 0`) in the
/// active mailbox's contact graph.
#[derive(Clone)]
pub struct FirstContactPolicy {
    store: Arc<dyn MailStore>,
}

impl FirstContactPolicy {
    pub fn new(store: Arc<dyn MailStore>) -> Self {
        Self { store }
    }

    async fn find_first_contact_recipients(
        store: &dyn MailStore,
        from: &str,
        recipients: &[String],
    ) -> AppResult<Vec<String>> {
        let self_mailbox = store.mailbox_id().trim().to_ascii_lowercase();
        let from_addr = extract_email_address(from);
        let mut seen = HashSet::new();
        let mut first_contacts = Vec::new();

        for raw in recipients {
            let parsed = validate_single_recipient(raw)?;
            let addr = parsed.email.trim().to_ascii_lowercase();
            if addr.is_empty() || !seen.insert(addr.clone()) {
                continue;
            }
            if (!self_mailbox.is_empty() && addr == self_mailbox)
                || (!from_addr.is_empty() && addr == from_addr)
            {
                continue;
            }
            let contact = store.get_contact(&addr).await?;
            if contact.is_none_or(|c| c.sent_count == 0) {
                first_contacts.push(addr);
            }
        }

        Ok(first_contacts)
    }
}

#[async_trait]
impl OutboundPolicy for FirstContactPolicy {
    async fn evaluate(&self, check: &OutboundCheck) -> AppResult<OutboundDecision> {
        let scoped_store = match check
            .mailbox_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(mb) if !mb.eq_ignore_ascii_case(self.store.mailbox_id()) => {
                self.store.for_mailbox(mb)
            }
            _ => self.store.clone(),
        };

        let all = check.all_recipients();
        let first_contacts =
            Self::find_first_contact_recipients(scoped_store.as_ref(), &check.from, &all).await?;

        if first_contacts.is_empty() {
            Ok(OutboundDecision::Allow)
        } else {
            Ok(OutboundDecision::HoldForApproval {
                reason: format!(
                    "First-contact recipient requires approval: {}",
                    first_contacts.join(", ")
                ),
            })
        }
    }

    fn policy_checks(&self, _check: &OutboundCheck) -> Vec<PolicyCheck> {
        vec![PolicyCheck {
            rule: "first_contact_approval".to_string(),
            passed: true,
            detail: "first_contact_approval is enabled; recipients without prior sent history will be held for human approval (HTTP 202)".to_string(),
        }]
    }

    fn for_mailbox(&self, mailbox_id: &str) -> Option<Arc<dyn OutboundPolicy>> {
        Some(Arc::new(Self::new(self.store.for_mailbox(mailbox_id))))
    }

    fn backend_name(&self) -> &'static str {
        "first_contact"
    }
}

/// Outbound Data Loss Prevention (DLP) scanner that inspects `subject`, `text`,
/// `html`, and attachment filenames for common secret and sensitive PII patterns
/// without echoing raw secrets in error messages or logs.
#[derive(Debug, Clone)]
pub struct DlpOutboundPolicy {
    action: DlpAction,
}

impl DlpOutboundPolicy {
    pub fn new(action: DlpAction) -> Self {
        Self { action }
    }

    pub fn from_config(config: &Config) -> Option<Self> {
        (config.dlp_action != DlpAction::Off).then(|| Self::new(config.dlp_action))
    }
}

#[async_trait]
impl OutboundPolicy for DlpOutboundPolicy {
    async fn evaluate(&self, check: &OutboundCheck) -> AppResult<OutboundDecision> {
        if self.action == DlpAction::Off {
            return Ok(OutboundDecision::Allow);
        }

        let findings = scan_dlp_findings(check);
        if findings.is_empty() {
            return Ok(OutboundDecision::Allow);
        }

        let rules = findings.join(", ");
        match self.action {
            DlpAction::Off => Ok(OutboundDecision::Allow),
            DlpAction::Hold => Ok(OutboundDecision::HoldForApproval {
                reason: format!("Outbound DLP policy held message matching rule(s): {rules}"),
            }),
            DlpAction::Deny => Ok(OutboundDecision::Deny {
                code: "dlp_blocked".to_string(),
                reason: format!("Outbound send blocked by DLP policy: matched rule(s): {rules}"),
                hint: Some(
                    "Remove sensitive secrets or PII from the message subject, body, or attachment names before sending."
                        .to_string(),
                ),
            }),
        }
    }

    fn policy_checks(&self, check: &OutboundCheck) -> Vec<PolicyCheck> {
        if self.action == DlpAction::Off {
            return Vec::new();
        }
        let findings = scan_dlp_findings(check);
        if findings.is_empty() {
            return vec![PolicyCheck {
                rule: "dlp_scan".to_string(),
                passed: true,
                detail: "No secrets or sensitive PII patterns detected".to_string(),
            }];
        }

        let rules = findings.join(", ");
        match self.action {
            DlpAction::Off => Vec::new(),
            DlpAction::Deny => vec![PolicyCheck {
                rule: "dlp_scan".to_string(),
                passed: false,
                detail: format!(
                    "DLP scanner matched rule(s): {rules} (action=deny; send would be rejected with 403)"
                ),
            }],
            DlpAction::Hold => vec![PolicyCheck {
                rule: "dlp_scan".to_string(),
                passed: true,
                detail: format!(
                    "DLP scanner matched rule(s): {rules} (action=hold; send will be held for human approval with HTTP 202)"
                ),
            }],
        }
    }

    fn backend_name(&self) -> &'static str {
        "dlp"
    }
}

/// Build the configured [`OutboundPolicy`] pipeline from [`Config`] and [`MailStore`]:
/// 1. [`ConfigOutboundPolicy`] (`max_send_recipients`, `allowed_recipients`, `draft_only`, `require_approval`)
/// 2. Optional [`DlpOutboundPolicy`] (when `dlp_action != DlpAction::Off`)
/// 3. Optional [`FirstContactPolicy`] (when `first_contact_approval = true`)
///
/// Returns [`ConfigOutboundPolicy`] directly when no optional policies are enabled so
/// `backends.outbound_policy` reports `"config"` by default, or [`OutboundPolicyChain`]
/// when multiple policies are active.
pub fn open_outbound_policy(config: &Config, store: Arc<dyn MailStore>) -> Arc<dyn OutboundPolicy> {
    let mut policies: Vec<Arc<dyn OutboundPolicy>> =
        vec![Arc::new(ConfigOutboundPolicy::from_config(config))];

    if let Some(dlp) = DlpOutboundPolicy::from_config(config) {
        policies.push(Arc::new(dlp));
    }

    if config.first_contact_approval {
        policies.push(Arc::new(FirstContactPolicy::new(store)));
    }

    if policies.len() == 1 {
        policies.pop().expect("single policy")
    } else {
        Arc::new(OutboundPolicyChain::new(policies))
    }
}

// ============================================================================
// Pure-Rust Secret & PII DLP Scanner
// ============================================================================

/// Scan all outbound fields (`subject`, `text`, `html`, and `attachment_filenames`)
/// and return the deduplicated list of matched DLP rule names.
pub fn scan_dlp_findings(check: &OutboundCheck) -> Vec<&'static str> {
    let mut findings: Vec<&'static str> = Vec::new();
    let mut collect = |text: &str| {
        for rule in scan_dlp_text(text) {
            if !findings.contains(&rule) {
                findings.push(rule);
            }
        }
    };

    if !check.subject.is_empty() {
        collect(&check.subject);
    }
    if let Some(ref text) = check.text {
        collect(text);
    }
    if let Some(ref html) = check.html {
        collect(html);
    }
    for filename in &check.attachment_filenames {
        collect(filename);
    }

    findings
}

/// Scan a single text string for secret and sensitive PII patterns and return matched rule names.
pub fn scan_dlp_text(input: &str) -> Vec<&'static str> {
    if input.is_empty() {
        return Vec::new();
    }

    let mut rules = Vec::new();
    if has_private_key_block(input) {
        rules.push("private_key_block");
    }
    if has_aws_access_key_id(input) {
        rules.push("aws_access_key_id");
    }
    if has_github_token(input) {
        rules.push("github_token");
    }
    if has_resend_api_key(input) {
        rules.push("resend_api_key");
    }
    if has_secret_api_key(input) {
        rules.push("secret_api_key");
    }
    if has_us_ssn(input) {
        rules.push("us_ssn");
    }
    if has_credit_card(input) {
        rules.push("credit_card");
    }
    rules
}

fn is_ident_boundary_before(bytes: &[u8], idx: usize) -> bool {
    idx == 0 || !(bytes[idx - 1].is_ascii_alphanumeric() || bytes[idx - 1] == b'_')
}

fn is_ident_boundary_after(bytes: &[u8], idx: usize) -> bool {
    idx >= bytes.len() || !(bytes[idx].is_ascii_alphanumeric() || bytes[idx] == b'_')
}

fn has_private_key_block(input: &str) -> bool {
    let upper = input.to_ascii_uppercase();
    let mut search_from = 0;
    while let Some(rel) = upper[search_from..].find("-----BEGIN ") {
        let header_start = search_from + rel + "-----BEGIN ".len();
        let rest = &upper[header_start..];
        let line_end = rest.find(['\r', '\n']).unwrap_or(rest.len());
        let safe_end = rest.floor_char_boundary(line_end.min(96));
        let line = &rest[..safe_end];
        if let Some(end_dashes) = line.find("-----") {
            let label = &line[..end_dashes];
            if label.contains("PRIVATE KEY") {
                return true;
            }
        }
        search_from = header_start;
    }
    false
}

fn has_aws_access_key_id(input: &str) -> bool {
    let bytes = input.as_bytes();
    if bytes.len() < 20 {
        return false;
    }
    for i in 0..=bytes.len() - 20 {
        if &bytes[i..i + 4] == b"AKIA"
            && is_ident_boundary_before(bytes, i)
            && is_ident_boundary_after(bytes, i + 20)
            && bytes[i + 4..i + 20]
                .iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        {
            return true;
        }
    }
    false
}

fn has_prefixed_token(
    input: &str,
    prefixes: &[&[u8]],
    min_suffix_len: usize,
    allow_hyphen_in_suffix: bool,
    reject_preceding_hyphen: bool,
) -> bool {
    let bytes = input.as_bytes();
    let len = bytes.len();
    for &prefix in prefixes {
        let plen = prefix.len();
        if len < plen + min_suffix_len {
            continue;
        }
        let mut i = 0;
        while i + plen + min_suffix_len <= len {
            if &bytes[i..i + plen] == prefix
                && is_ident_boundary_before(bytes, i)
                && (!reject_preceding_hyphen || i == 0 || bytes[i - 1] != b'-')
            {
                let mut j = i + plen;
                while j < len
                    && (bytes[j].is_ascii_alphanumeric()
                        || bytes[j] == b'_'
                        || (allow_hyphen_in_suffix && bytes[j] == b'-'))
                {
                    j += 1;
                }
                if j - (i + plen) >= min_suffix_len {
                    return true;
                }
                i = j;
                continue;
            }
            i += 1;
        }
    }
    false
}

fn has_github_token(input: &str) -> bool {
    has_prefixed_token(
        input,
        &[b"github_pat_", b"ghp_", b"gho_", b"ghs_"],
        20,
        false,
        false,
    )
}

fn has_resend_api_key(input: &str) -> bool {
    has_prefixed_token(input, &[b"re_"], 20, false, false)
}

fn has_secret_api_key(input: &str) -> bool {
    has_prefixed_token(input, &[b"sk_live_", b"rk_live_", b"sk-"], 20, true, true)
}

fn has_us_ssn(input: &str) -> bool {
    let bytes = input.as_bytes();
    if bytes.len() < 11 {
        return false;
    }
    for i in 0..=bytes.len() - 11 {
        if bytes[i + 3] != b'-' || bytes[i + 6] != b'-' {
            continue;
        }
        if i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'-') {
            continue;
        }
        if i + 11 < bytes.len() && (bytes[i + 11].is_ascii_alphanumeric() || bytes[i + 11] == b'-')
        {
            continue;
        }
        let g1 = &bytes[i..i + 3];
        let g2 = &bytes[i + 4..i + 6];
        let g3 = &bytes[i + 7..i + 11];
        if !(g1.iter().all(u8::is_ascii_digit)
            && g2.iter().all(u8::is_ascii_digit)
            && g3.iter().all(u8::is_ascii_digit))
        {
            continue;
        }
        let area: u16 =
            u16::from(g1[0] - b'0') * 100 + u16::from(g1[1] - b'0') * 10 + u16::from(g1[2] - b'0');
        let group: u16 = u16::from(g2[0] - b'0') * 10 + u16::from(g2[1] - b'0');
        let serial: u16 = u16::from(g3[0] - b'0') * 1000
            + u16::from(g3[1] - b'0') * 100
            + u16::from(g3[2] - b'0') * 10
            + u16::from(g3[3] - b'0');
        if area != 0 && area != 666 && area < 900 && group != 0 && serial != 0 {
            return true;
        }
    }
    false
}

fn has_credit_card(input: &str) -> bool {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if !bytes[i].is_ascii_digit() || (i > 0 && bytes[i - 1].is_ascii_alphanumeric()) {
            i += 1;
            continue;
        }

        // Advance `first_run_end` past the initial contiguous digit group so if a prefix
        // digit group (e.g. `ID 123 4111 1111 1111 1111`) fails, scanning resumes at `4111`.
        let mut first_run_end = i;
        while first_run_end < len && bytes[first_run_end].is_ascii_digit() {
            first_run_end += 1;
        }

        let mut digits: Vec<u8> = Vec::with_capacity(20);
        let mut sep: Option<u8> = None;
        let mut j = i;

        while j < len && digits.len() <= 20 {
            let b = bytes[j];
            if b.is_ascii_digit() {
                digits.push(b - b'0');
                j += 1;
            } else if (b == b' ' || b == b'-')
                && j + 1 < len
                && bytes[j + 1].is_ascii_digit()
                && sep.is_none_or(|s| s == b)
            {
                sep = Some(b);
                j += 1;
            } else {
                break;
            }
        }

        let trailing_alnum = j < len && bytes[j].is_ascii_alphanumeric();
        if !trailing_alnum
            && (13..=19).contains(&digits.len())
            && is_plausible_card_iin(&digits)
            && passes_luhn(&digits)
        {
            return true;
        }

        i = first_run_end;
    }

    false
}

fn is_plausible_card_iin(digits: &[u8]) -> bool {
    if digits.len() < 4 || digits.iter().all(|&d| d == 0) {
        return false;
    }
    match digits[0] {
        3..=6 => true,
        2 => {
            let prefix4 = u16::from(digits[0]) * 1000
                + u16::from(digits[1]) * 100
                + u16::from(digits[2]) * 10
                + u16::from(digits[3]);
            (2221..=2720).contains(&prefix4)
        }
        _ => false,
    }
}

/// Validate a sequence of decimal digits (`0..=9`) with the Luhn checksum algorithm.
pub fn passes_luhn(digits: &[u8]) -> bool {
    if digits.is_empty() {
        return false;
    }
    let mut sum: u32 = 0;
    for (idx_from_right, &d) in digits.iter().rev().enumerate() {
        let mut v = u32::from(d);
        if idx_from_right % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum.is_multiple_of(10)
}

/// Default [`OutboundPolicy`] driven by [`Config`] (`draft_only`, `draft_only_action`,
/// `require_approval`, `allowed_recipients`, `max_send_recipients`).
#[derive(Debug, Clone)]
pub struct ConfigOutboundPolicy {
    draft_only: bool,
    draft_only_action: DraftOnlyAction,
    require_approval: bool,
    allowed_recipients: Vec<String>,
    max_send_recipients: usize,
}

impl ConfigOutboundPolicy {
    pub fn from_config(config: &Config) -> Self {
        Self {
            draft_only: config.draft_only,
            draft_only_action: config.draft_only_action,
            require_approval: config.require_approval,
            allowed_recipients: config.allowed_recipients.clone(),
            max_send_recipients: config.max_send_recipients,
        }
    }

    fn effective_draft_only(&self, policy: Option<&AgentPolicyOverride>) -> bool {
        self.draft_only || policy.and_then(|p| p.draft_only).unwrap_or(false)
    }

    fn effective_max_send_recipients(&self, policy: Option<&AgentPolicyOverride>) -> usize {
        match policy.and_then(|p| p.max_send_recipients) {
            Some(override_max) => self.max_send_recipients.min(override_max),
            None => self.max_send_recipients,
        }
    }

    fn find_disallowed(
        &self,
        recipients: &[String],
        policy: Option<&AgentPolicyOverride>,
    ) -> Vec<String> {
        let token_rules = policy
            .and_then(|p| p.allowed_recipients.as_deref())
            .filter(|rules| !rules.is_empty());

        if self.allowed_recipients.is_empty() && token_rules.is_none() {
            return Vec::new();
        }
        recipients
            .iter()
            .filter(|addr| {
                let allowed_by_global = self.allowed_recipients.is_empty()
                    || self
                        .allowed_recipients
                        .iter()
                        .any(|rule| recipient_matches_rule(addr, rule));
                let allowed_by_token = token_rules.is_none_or(|rules| {
                    rules.iter().any(|rule| recipient_matches_rule(addr, rule))
                });
                !(allowed_by_global && allowed_by_token)
            })
            .cloned()
            .collect()
    }
}

#[async_trait]
impl OutboundPolicy for ConfigOutboundPolicy {
    async fn evaluate(&self, check: &OutboundCheck) -> AppResult<OutboundDecision> {
        let policy = check.agent_policy.as_ref();
        let all = check.all_recipients();
        for addr in &all {
            validate_single_recipient(addr)?;
        }
        let total = all.len();
        let max_recipients = self.effective_max_send_recipients(policy);
        if total > max_recipients {
            return Err(AppError::validation(
                format!("Recipient count ({total}) exceeds max_send_recipients ({max_recipients})"),
                Some(
                    "Reduce total recipients across to/cc/bcc or adjust NOGML_MAX_SEND_RECIPIENTS."
                        .to_string(),
                ),
            ));
        }

        let disallowed = self.find_disallowed(&all, policy);
        if !disallowed.is_empty() {
            return Err(AppError::RecipientNotAllowed { disallowed });
        }

        if self.effective_draft_only(policy) {
            let reason = if !self.draft_only {
                "Outbound send blocked: token policy enforces draft_only mode".to_string()
            } else {
                "Outbound send blocked: server is in draft_only mode".to_string()
            };
            return match self.draft_only_action {
                DraftOnlyAction::Block => Ok(OutboundDecision::Deny {
                    code: "draft_only_mode".to_string(),
                    reason,
                    hint: Some(
                        "Direct send is blocked by draft_only policy. Call create_draft instead, or pass dry_run: true to preview."
                            .to_string(),
                    ),
                }),
                DraftOnlyAction::Downgrade => Ok(OutboundDecision::DowngradeToDraft {
                    reason: "draft_only mode (action=downgrade)".to_string(),
                }),
            };
        }

        if self.require_approval {
            return Ok(OutboundDecision::HoldForApproval {
                reason: "Server requires human approval for outbound sends (require_approval=true)"
                    .to_string(),
            });
        }

        Ok(OutboundDecision::Allow)
    }

    fn policy_checks(&self, check: &OutboundCheck) -> Vec<PolicyCheck> {
        let policy = check.agent_policy.as_ref();
        let all_recipients = check.all_recipients();
        let total_recipients = all_recipients.len();
        let max_recipients = self.effective_max_send_recipients(policy);
        let within_limit = total_recipients <= max_recipients;
        let disallowed = self.find_disallowed(&all_recipients, policy);
        let allowlist_active = !self.allowed_recipients.is_empty()
            || policy
                .and_then(|p| p.allowed_recipients.as_deref())
                .is_some_and(|r| !r.is_empty());
        let draft_only = self.effective_draft_only(policy);

        let mut checks = vec![
            PolicyCheck {
                rule: "max_send_recipients".to_string(),
                passed: within_limit,
                detail: if within_limit {
                    format!(
                        "{total_recipients} recipient(s) within max_send_recipients ({max_recipients})"
                    )
                } else {
                    format!(
                        "{total_recipients} recipients exceed max_send_recipients ({max_recipients})"
                    )
                },
            },
            PolicyCheck {
                rule: "allowed_recipients".to_string(),
                passed: disallowed.is_empty(),
                detail: if !allowlist_active {
                    "Recipient allowlist is disabled (all recipients permitted)".to_string()
                } else if disallowed.is_empty() {
                    "All recipients match allowed_recipients policy".to_string()
                } else {
                    format!("Disallowed recipient(s): {}", disallowed.join(", "))
                },
            },
        ];

        if !draft_only {
            checks.push(PolicyCheck {
                rule: "draft_only".to_string(),
                passed: true,
                detail: "draft_only mode is disabled; outbound send is permitted".to_string(),
            });
        } else {
            match self.draft_only_action {
                DraftOnlyAction::Block => {
                    checks.push(PolicyCheck {
                        rule: "draft_only".to_string(),
                        passed: false,
                        detail: "draft_only mode is active (action=block); outbound send would be rejected with 403 draft_only_mode".to_string(),
                    });
                }
                DraftOnlyAction::Downgrade => {
                    checks.push(PolicyCheck {
                        rule: "draft_only".to_string(),
                        passed: true,
                        detail: "draft_only mode is active (action=downgrade); send would be saved as a draft instead of sent".to_string(),
                    });
                }
            }
        }

        if self.require_approval {
            checks.push(PolicyCheck {
                rule: "require_approval".to_string(),
                passed: true,
                detail: "require_approval is enabled; outbound send will be queued for human approval (HTTP 202)".to_string(),
            });
        }

        checks
    }

    fn backend_name(&self) -> &'static str {
        "config"
    }
}

/// Hard upper bound on body character extraction to protect agent context windows.
pub const HARD_MAX_BODY_CHARS: usize = 100_000;

/// Validate a resource ID (`message_id`, `thread_id`, `draft_id`, `label_id`, `attachment_id`)
/// against control characters, path traversal, and URL delimiter injection.
pub fn validate_resource_id(id: &str) -> AppResult<()> {
    let trimmed = id.trim();
    if trimmed.is_empty() || trimmed != id {
        return Err(AppError::validation(
            "Resource ID must be non-empty and must not contain leading or trailing whitespace",
            Some("Provide a valid resource identifier without surrounding spaces.".to_string()),
        ));
    }

    if id.len() > 256 {
        return Err(AppError::validation(
            "Resource ID exceeds maximum length (256 characters)",
            None,
        ));
    }

    if id.chars().any(|c| c <= '\x1f' || c == '\x7f') {
        return Err(AppError::validation(
            "Resource ID contains forbidden control characters",
            Some("Remove control characters from the resource identifier.".to_string()),
        ));
    }

    let lower = id.to_ascii_lowercase();
    for forbidden in ["..", "/", "\\", "?", "#", "%2e", "%2f", "%5c"] {
        if lower.contains(forbidden) {
            return Err(AppError::validation(
                format!("Resource ID '{id}' contains forbidden sequence '{forbidden}'"),
                Some("Use an opaque resource ID returned by the API without path or query characters.".to_string()),
            ));
        }
    }

    Ok(())
}

/// Reject CR/LF/NUL characters in email headers to block header injection.
pub fn validate_email_header(name: &str, value: &str) -> AppResult<()> {
    if value.contains('\r') || value.contains('\n') || value.contains('\0') {
        return Err(AppError::validation(
            format!("Email header '{name}' contains forbidden CR/LF/NUL characters"),
            Some(
                "Header values must be single-line strings without CR/LF or NUL bytes.".to_string(),
            ),
        ));
    }
    Ok(())
}

/// Strictly validate a single recipient mailbox (`"user@example.com"` or `"Name <user@example.com>"`).
///
/// Rejects multi-address lists, trailing tokens after `>`, multiple `<...>` pairs, and
/// unquoted `,`, `;`, `<`, `>`, or `@` in display names.
pub fn validate_single_recipient(raw: &str) -> AppResult<crate::models::EmailAddress> {
    crate::storage::parse_strict_single_mailbox(raw).map_err(|reason| {
        AppError::validation(
            format!("Invalid recipient email address: {reason}"),
            Some(
                "Provide a single valid email address per recipient entry such as user@example.com or \"Name <user@example.com>\"."
                    .to_string(),
            ),
        )
    })
}

/// Validate and canonicalize a single recipient into `"user@example.com"` or `"Name <user@example.com>"`
/// (quoting display names containing `,`, `;`, `"`, or `\`).
pub fn canonicalize_recipient(raw: &str) -> AppResult<String> {
    let parsed = validate_single_recipient(raw)?;
    match parsed.name {
        None => Ok(parsed.email),
        Some(name) => {
            if name.contains(',') || name.contains(';') || name.contains('"') || name.contains('\\')
            {
                let escaped = name.replace('\\', "\\\\").replace('"', "\\\"");
                Ok(format!("\"{escaped}\" <{}>", parsed.email))
            } else {
                Ok(format!("{name} <{}>", parsed.email))
            }
        }
    }
}

/// Extract a normalized lowercase bare email address from either `"Name <a@b.com>"` or `"a@b.com"`.
pub fn extract_email_address(raw: &str) -> String {
    parse_simple_email_address(raw)
        .email
        .trim()
        .to_ascii_lowercase()
}

/// Validate strict single-mailbox RFC 5322 email syntax (allowing `@localhost` for local testing).
pub fn is_valid_email_syntax(raw: &str) -> bool {
    validate_single_recipient(raw).is_ok()
}

/// Check whether `recipient` matches an allowlist rule:
/// - Exact address (case-insensitive): `alice@example.com`
/// - Exact domain: `@example.com`
/// - Subdomain wildcard: `*.example.com` (or `@*.example.com`)
pub fn recipient_matches_rule(recipient: &str, rule: &str) -> bool {
    let Ok(parsed) = validate_single_recipient(recipient) else {
        return false;
    };
    let email = parsed.email.to_ascii_lowercase();
    let Some((_, domain)) = email.split_once('@') else {
        return false;
    };
    let rule = rule.trim().to_ascii_lowercase();
    if rule.is_empty() {
        return false;
    }

    if let Some(rest) = rule.strip_prefix("@*.") {
        let suffix = format!(".{rest}");
        !rest.is_empty() && domain.ends_with(&suffix) && domain.len() > suffix.len()
    } else if let Some(rest) = rule.strip_prefix("*.") {
        let suffix = format!(".{rest}");
        !rest.is_empty() && domain.ends_with(&suffix) && domain.len() > suffix.len()
    } else if let Some(target_domain) = rule.strip_prefix('@') {
        !target_domain.is_empty() && domain == target_domain
    } else {
        email == rule
    }
}

/// Return recipients not permitted by `config.allowed_recipients`.
/// Empty `allowed_recipients` permits all addresses.
pub fn find_disallowed_recipients(config: &Config, recipients: &[String]) -> Vec<String> {
    if config.allowed_recipients.is_empty() {
        return Vec::new();
    }
    recipients
        .iter()
        .filter(|addr| {
            !config
                .allowed_recipients
                .iter()
                .any(|rule| recipient_matches_rule(addr, rule))
        })
        .cloned()
        .collect()
}

/// Enforce header safety, syntax, `max_send_recipients`, and `allowed_recipients`
/// across all `to`, `cc`, and `bcc` recipients.
pub fn check_recipients_policy(
    config: &Config,
    to: &[String],
    cc: &[String],
    bcc: &[String],
) -> AppResult<()> {
    for (field, list) in [("to", to), ("cc", cc), ("bcc", bcc)] {
        for addr in list {
            validate_email_header(field, addr)?;
        }
    }

    let total = to.len() + cc.len() + bcc.len();
    if total > config.max_send_recipients {
        return Err(AppError::validation(
            format!(
                "Recipient count ({total}) exceeds max_send_recipients ({})",
                config.max_send_recipients
            ),
            Some(
                "Reduce total recipients across to/cc/bcc or adjust NOGML_MAX_SEND_RECIPIENTS."
                    .to_string(),
            ),
        ));
    }

    let all: Vec<String> = to
        .iter()
        .chain(cc.iter())
        .chain(bcc.iter())
        .cloned()
        .collect();

    let invalid: Vec<String> = all
        .iter()
        .filter(|addr| !is_valid_email_syntax(addr))
        .cloned()
        .collect();
    if !invalid.is_empty() {
        return Err(AppError::validation(
            format!("Invalid recipient email address(es): {}", invalid.join(", ")),
            Some("Provide valid email addresses such as user@example.com or \"Name <user@example.com>\".".to_string()),
        ));
    }

    let disallowed = find_disallowed_recipients(config, &all);
    if !disallowed.is_empty() {
        return Err(AppError::RecipientNotAllowed { disallowed });
    }

    Ok(())
}

/// Strip dangerous ASCII/C1 control chars, Unicode BiDi override/isolate chars,
/// and invisible Unicode tag characters to guard LLM prompts against injection smuggling.
pub fn sanitize_untrusted_text(input: &str) -> String {
    input
        .chars()
        .filter(|&c| {
            let is_allowed_ctrl = matches!(c, '\t' | '\n' | '\r');
            let is_ascii_ctrl = (c as u32) < 0x20 || c == '\x7f';
            let is_c1_ctrl = ('\u{0080}'..='\u{009F}').contains(&c);
            let is_bidi = matches!(
                c,
                '\u{061C}'
                    | '\u{200E}'
                    | '\u{200F}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2066}'..='\u{2069}'
            );
            let is_tag = ('\u{E0000}'..='\u{E007F}').contains(&c);
            !(is_ascii_ctrl && !is_allowed_ctrl) && !is_c1_ctrl && !is_bidi && !is_tag
        })
        .collect()
}

/// Return `_meta` tagging when `untrusted_content_guard` is active.
pub fn untrusted_meta(config: &Config) -> Option<UntrustedMeta> {
    config.untrusted_content_guard.then_some(UntrustedMeta {
        untrusted_external_content: true,
    })
}

/// Clamp requested `max_body_chars` to the hard ceiling (`100_000`).
pub fn clamp_max_body_chars(requested: Option<usize>, config: &Config) -> usize {
    requested
        .unwrap_or(config.default_max_body_chars)
        .min(HARD_MAX_BODY_CHARS)
}

/// Resolved outbound parameters after applying `reply_to_message_id` threading.
#[derive(Debug, Clone)]
pub struct ResolvedOutbound {
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    pub thread_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Option<String>,
}

/// Prefix a subject with `Re: ` unless it already starts with `Re:` (case-insensitive).
pub fn ensure_reply_subject(parent_subject: &str) -> String {
    let trimmed = parent_subject.trim();
    if trimmed.is_empty() {
        return "Re:".to_string();
    }
    if trimmed.len() >= 3 && trimmed[..3].eq_ignore_ascii_case("re:") {
        trimmed.to_string()
    } else {
        format!("Re: {trimmed}")
    }
}

/// Resolve and authorize an optional outbound `From` address for the active mailbox.
///
/// When `requested_from` is `None` or blank, defaults to `state.config.user_email`.
/// Otherwise validates header safety and single-mailbox syntax and requires the email to match:
/// - `state.mailbox_id()` or `state.config.user_email` (case-insensitive),
/// - a configured alias in `state.config.mailbox_aliases` targeting `state.mailbox_id()`, or
/// - a stored `SendAs` alias in `state.store.get_settings()`.
pub async fn resolve_authorized_from(
    state: &AppState,
    requested_from: Option<&str>,
) -> AppResult<String> {
    let Some(raw) = requested_from.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(state.config.user_email.clone());
    };

    validate_email_header("from", raw)?;
    let parsed = validate_single_recipient(raw)?;
    let mailbox_id = state.mailbox_id();
    if parsed.email.eq_ignore_ascii_case(&state.config.user_email)
        || state
            .config
            .is_authorized_sender_for_mailbox(mailbox_id, raw)
    {
        return Ok(raw.to_string());
    }

    if let Ok(settings) = state.store.get_settings().await
        && settings
            .send_as
            .iter()
            .any(|s| s.send_as_email.eq_ignore_ascii_case(&parsed.email))
    {
        return Ok(raw.to_string());
    }

    Err(AppError::Forbidden(format!(
        "Sender address '{}' is not authorized for mailbox '{}'",
        parsed.email, mailbox_id
    )))
}

/// Resolve `reply_to_message_id` against `MailStore`, auto-populating `thread_id`,
/// `In-Reply-To`, `References`, `Re:` subject, and default `to` recipient if omitted.
#[allow(clippy::too_many_arguments)]
pub async fn resolve_reply_threading(
    state: &AppState,
    to: &[String],
    cc: &[String],
    bcc: &[String],
    subject: Option<&str>,
    text: Option<&str>,
    html: Option<&str>,
    reply_to_message_id: Option<&str>,
) -> AppResult<ResolvedOutbound> {
    let mut resolved_to = to.to_vec();
    let mut resolved_subject = subject.map(str::to_string);
    let mut thread_id = None;
    let mut in_reply_to = None;
    let mut references = None;

    if let Some(reply_id) = reply_to_message_id {
        validate_resource_id(reply_id)?;
        let parent = state.store.get_message(reply_id).await?.ok_or_else(|| {
            AppError::NotFound(format!("Reply target message '{reply_id}' not found"))
        })?;

        thread_id = Some(parent.thread_id.clone());

        let parent_mid = parent
            .rfc822_message_id
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("<{}@{}>", parent.id, state.config.default_domain));

        in_reply_to = Some(parent_mid.clone());

        let refs = match parent
            .references_header
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(existing) if existing.split_whitespace().any(|tok| tok == parent_mid) => {
                existing.to_string()
            }
            Some(existing) => format!("{existing} {parent_mid}"),
            None => parent_mid,
        };
        references = Some(refs);

        let needs_subject = resolved_subject
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .is_empty();
        if needs_subject {
            resolved_subject = Some(ensure_reply_subject(&parent.subject));
        }

        if resolved_to.is_empty() && !parent.from_addr.trim().is_empty() {
            resolved_to.push(parent.from_addr.clone());
        }
    }

    Ok(ResolvedOutbound {
        from: state.config.user_email.clone(),
        to: resolved_to,
        cc: cc.to_vec(),
        bcc: bcc.to_vec(),
        subject: resolved_subject.unwrap_or_default(),
        text: text.map(str::to_string),
        html: html.map(str::to_string),
        thread_id,
        in_reply_to,
        references,
    })
}

/// Evaluate all send guardrails (`headers`, `reply_target`, `recipients`, `max_send_recipients`,
/// `allowed_recipients`, `draft_only`, and MIME size estimation) with ZERO side effects.
pub async fn evaluate_send_dry_run(
    state: &AppState,
    req: &AiSendEmailRequest,
) -> AppResult<DryRunResponse> {
    evaluate_send_dry_run_with_policy(state, req, None).await
}

/// Evaluate send dry-run with an optional per-principal [`AgentPolicyOverride`].
pub async fn evaluate_send_dry_run_with_policy(
    state: &AppState,
    req: &AiSendEmailRequest,
    agent_policy: Option<&AgentPolicyOverride>,
) -> AppResult<DryRunResponse> {
    let resolved_from = resolve_authorized_from(state, req.from.as_deref()).await?;
    let mut res = evaluate_resolved_dry_run(
        state,
        &req.to,
        &req.cc,
        &req.bcc,
        req.subject.as_deref(),
        req.text.as_deref(),
        req.html.as_deref(),
        &[],
        req.reply_to_message_id.as_deref(),
        None,
        None,
        None,
        None,
        agent_policy,
    )
    .await?;
    if let Some(ref mut preview) = res.preview {
        preview.from = resolved_from;
    }
    Ok(res)
}

#[allow(clippy::too_many_arguments)]
pub async fn evaluate_resolved_dry_run(
    state: &AppState,
    to: &[String],
    cc: &[String],
    bcc: &[String],
    subject: Option<&str>,
    text: Option<&str>,
    html: Option<&str>,
    attachment_filenames: &[String],
    reply_to_message_id: Option<&str>,
    existing_thread_id: Option<&str>,
    existing_in_reply_to: Option<&str>,
    existing_references: Option<&str>,
    existing_raw_len: Option<usize>,
    agent_policy: Option<&AgentPolicyOverride>,
) -> AppResult<DryRunResponse> {
    let mut checks = Vec::new();
    let mut warnings = Vec::new();

    // 1. Validate headers for CR/LF injection.
    let mut header_errors = Vec::new();
    if let Some(subj) = subject
        && let Err(err) = validate_email_header("subject", subj)
    {
        header_errors.push(err.to_string());
    }
    for (field, list) in [("to", to), ("cc", cc), ("bcc", bcc)] {
        for addr in list {
            if let Err(err) = validate_email_header(field, addr) {
                header_errors.push(err.to_string());
            }
        }
    }
    checks.push(PolicyCheckResult {
        rule: "headers_valid".to_string(),
        passed: header_errors.is_empty(),
        detail: if header_errors.is_empty() {
            "All email headers are free of CR/LF/NUL injection characters".to_string()
        } else {
            header_errors.join("; ")
        },
    });

    // 2. Resolve reply threading if reply_to_message_id is supplied.
    let mut resolved = ResolvedOutbound {
        from: state.config.user_email.clone(),
        to: to.to_vec(),
        cc: cc.to_vec(),
        bcc: bcc.to_vec(),
        subject: subject.unwrap_or_default().to_string(),
        text: text.map(str::to_string),
        html: html.map(str::to_string),
        thread_id: existing_thread_id.map(str::to_string),
        in_reply_to: existing_in_reply_to.map(str::to_string),
        references: existing_references.map(str::to_string),
    };

    if let Some(reply_id) = reply_to_message_id {
        match resolve_reply_threading(state, to, cc, bcc, subject, text, html, Some(reply_id)).await
        {
            Ok(r) => {
                resolved = r;
                checks.push(PolicyCheckResult {
                    rule: "reply_target".to_string(),
                    passed: true,
                    detail: format!(
                        "Resolved reply target '{reply_id}' into thread '{}'",
                        resolved.thread_id.as_deref().unwrap_or("")
                    ),
                });
            }
            Err(err) => {
                checks.push(PolicyCheckResult {
                    rule: "reply_target".to_string(),
                    passed: false,
                    detail: err.to_string(),
                });
            }
        }
    }

    // 3. Recipients presence & syntax.
    let all_recipients: Vec<String> = resolved
        .to
        .iter()
        .chain(resolved.cc.iter())
        .chain(resolved.bcc.iter())
        .cloned()
        .collect();

    checks.push(PolicyCheckResult {
        rule: "recipients_present".to_string(),
        passed: !resolved.to.is_empty(),
        detail: if resolved.to.is_empty() {
            "At least one 'to' recipient is required".to_string()
        } else {
            format!("{} primary 'to' recipient(s) provided", resolved.to.len())
        },
    });

    let invalid_addrs: Vec<String> = all_recipients
        .iter()
        .filter(|addr| !is_valid_email_syntax(addr))
        .cloned()
        .collect();
    checks.push(PolicyCheckResult {
        rule: "recipient_syntax".to_string(),
        passed: invalid_addrs.is_empty(),
        detail: if invalid_addrs.is_empty() {
            "All recipient addresses passed syntax validation".to_string()
        } else {
            format!("Invalid address(es): {}", invalid_addrs.join(", "))
        },
    });

    // 4-6. Delegate configurable/pluggable outbound policy checks to `state.outbound_policy`.
    let outbound_check = OutboundCheck {
        from: resolved.from.clone(),
        to: resolved.to.clone(),
        cc: resolved.cc.clone(),
        bcc: resolved.bcc.clone(),
        subject: resolved.subject.clone(),
        text: resolved.text.clone(),
        html: resolved.html.clone(),
        attachment_filenames: attachment_filenames.to_vec(),
        thread_id: resolved.thread_id.clone(),
        mailbox_id: Some(state.mailbox_id().to_string()),
        is_draft_send: existing_raw_len.is_some(),
        agent_policy: agent_policy.cloned(),
    };
    checks.extend(state.outbound_policy.policy_checks(&outbound_check));

    let effective_draft_only =
        state.config.draft_only || agent_policy.and_then(|p| p.draft_only).unwrap_or(false);
    if effective_draft_only && state.config.draft_only_action == DraftOnlyAction::Downgrade {
        warnings.push(
            "draft_only=true with action=downgrade: executing this send will create/retain a draft instead of sending externally.".to_string(),
        );
    }

    if state.config.require_approval && !effective_draft_only {
        warnings.push(
            "require_approval=true: executing this send will hold the email in the pending approval queue until a human approves it.".to_string(),
        );
    }

    if state.config.first_contact_approval && !effective_draft_only {
        let valid_recipients: Vec<String> = all_recipients
            .iter()
            .filter(|addr| is_valid_email_syntax(addr))
            .cloned()
            .collect();
        let first_contacts = FirstContactPolicy::find_first_contact_recipients(
            state.store.as_ref(),
            &resolved.from,
            &valid_recipients,
        )
        .await?;
        if !first_contacts.is_empty() {
            warnings.push(format!(
                "first_contact_approval=true: executing this send will hold for human approval for first-contact recipient(s): {}",
                first_contacts.join(", ")
            ));
        }
    }

    if state.config.dlp_action == DlpAction::Hold && !effective_draft_only {
        let findings = scan_dlp_findings(&outbound_check);
        if !findings.is_empty() {
            warnings.push(format!(
                "dlp_action=hold: executing this send will hold for human approval (matched rule(s): {}).",
                findings.join(", ")
            ));
        }
    }

    if resolved.text.as_deref().unwrap_or("").is_empty()
        && resolved.html.as_deref().unwrap_or("").is_empty()
    {
        warnings.push("Message has neither text nor html body.".to_string());
    }

    if state.config.resend_api_key.is_none()
        && (!state.config.draft_only || state.config.draft_only_action == DraftOnlyAction::Block)
    {
        warnings.push(
            "RESEND_API_KEY is not set in config; live HTTP Resend delivery requires credentials."
                .to_string(),
        );
    }

    // 7. Estimate RFC 2822 byte size without mutating state.
    let estimated_bytes = if let Some(len) = existing_raw_len {
        len
    } else if header_errors.is_empty() {
        let compose = ComposeEmailInput {
            from: resolved.from.clone(),
            to: resolved.to.clone(),
            cc: resolved.cc.clone(),
            bcc: resolved.bcc.clone(),
            reply_to: Vec::new(),
            subject: resolved.subject.clone(),
            text: resolved.text.clone(),
            html: resolved.html.clone(),
            message_id: Some(
                format!("<preview@{} >", state.config.default_domain).replace(' ', ""),
            ),
            in_reply_to: resolved.in_reply_to.clone(),
            references: resolved.references.clone(),
            extra_headers: HashMap::new(),
            attachments: Vec::new(),
        };
        build_rfc2822(&compose)
            .map(|b| b.len())
            .unwrap_or_else(|_| {
                resolved.subject.len()
                    + resolved.text.as_deref().map_or(0, str::len)
                    + resolved.html.as_deref().map_or(0, str::len)
                    + 256
            })
    } else {
        resolved.subject.len()
            + resolved.text.as_deref().map_or(0, str::len)
            + resolved.html.as_deref().map_or(0, str::len)
            + 256
    };

    let would_succeed = checks.iter().all(|c| c.passed);

    Ok(DryRunResponse {
        dry_run: true,
        would_succeed,
        policy_checks: checks,
        preview: Some(DryRunPreview {
            from: resolved.from,
            to: resolved.to,
            cc: resolved.cc,
            bcc: resolved.bcc,
            subject: resolved.subject,
            thread_id: resolved.thread_id,
            in_reply_to: resolved.in_reply_to,
            estimated_bytes,
        }),
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::storage::{ContactDirection, ContactInteraction, MemoryStore};

    struct CountingPolicy {
        name: &'static str,
        decision: OutboundDecision,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl OutboundPolicy for CountingPolicy {
        async fn evaluate(&self, _check: &OutboundCheck) -> AppResult<OutboundDecision> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.decision.clone())
        }

        fn policy_checks(&self, _check: &OutboundCheck) -> Vec<PolicyCheck> {
            vec![PolicyCheck {
                rule: self.name.to_string(),
                passed: !matches!(self.decision, OutboundDecision::Deny { .. }),
                detail: format!("check from {}", self.name),
            }]
        }

        fn backend_name(&self) -> &'static str {
            self.name
        }
    }

    #[tokio::test]
    async fn outbound_policy_chain_short_circuits_on_deny_and_orders_severity() {
        let calls1 = Arc::new(AtomicUsize::new(0));
        let calls2 = Arc::new(AtomicUsize::new(0));
        let calls3 = Arc::new(AtomicUsize::new(0));

        let deny_chain = OutboundPolicyChain::new(vec![
            Arc::new(CountingPolicy {
                name: "p1",
                decision: OutboundDecision::DowngradeToDraft {
                    reason: "downgraded".into(),
                },
                calls: calls1.clone(),
            }),
            Arc::new(CountingPolicy {
                name: "p2",
                decision: OutboundDecision::Deny {
                    code: "blocked".into(),
                    reason: "denied".into(),
                    hint: None,
                },
                calls: calls2.clone(),
            }),
            Arc::new(CountingPolicy {
                name: "p3",
                decision: OutboundDecision::HoldForApproval {
                    reason: "held".into(),
                },
                calls: calls3.clone(),
            }),
        ]);

        assert_eq!(deny_chain.backend_name(), "chain");
        let decision = deny_chain
            .evaluate(&OutboundCheck::default())
            .await
            .unwrap();
        assert!(matches!(decision, OutboundDecision::Deny { code, .. } if code == "blocked"));
        assert_eq!(calls1.load(Ordering::SeqCst), 1);
        assert_eq!(calls2.load(Ordering::SeqCst), 1);
        assert_eq!(calls3.load(Ordering::SeqCst), 0);

        let checks = deny_chain.policy_checks(&OutboundCheck::default());
        assert_eq!(checks.len(), 3);
        assert_eq!(checks[0].rule, "p1");
        assert_eq!(checks[1].rule, "p2");
        assert_eq!(checks[2].rule, "p3");

        // DowngradeToDraft outranks HoldForApproval so draft_only is never promoted into approvals;
        // first decision wins on ties.
        let downgrade_chain = OutboundPolicyChain::new(vec![
            Arc::new(CountingPolicy {
                name: "hold1",
                decision: OutboundDecision::HoldForApproval {
                    reason: "first hold".into(),
                },
                calls: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(CountingPolicy {
                name: "draft",
                decision: OutboundDecision::DowngradeToDraft {
                    reason: "downgrade".into(),
                },
                calls: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(CountingPolicy {
                name: "hold2",
                decision: OutboundDecision::HoldForApproval {
                    reason: "second hold".into(),
                },
                calls: Arc::new(AtomicUsize::new(0)),
            }),
        ]);
        assert_eq!(
            downgrade_chain
                .evaluate(&OutboundCheck::default())
                .await
                .unwrap(),
            OutboundDecision::DowngradeToDraft {
                reason: "downgrade".into()
            }
        );

        let hold_tie_chain = OutboundPolicyChain::new(vec![
            Arc::new(CountingPolicy {
                name: "hold1",
                decision: OutboundDecision::HoldForApproval {
                    reason: "first hold".into(),
                },
                calls: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(CountingPolicy {
                name: "hold2",
                decision: OutboundDecision::HoldForApproval {
                    reason: "second hold".into(),
                },
                calls: Arc::new(AtomicUsize::new(0)),
            }),
        ]);
        assert_eq!(
            hold_tie_chain
                .evaluate(&OutboundCheck::default())
                .await
                .unwrap(),
            OutboundDecision::HoldForApproval {
                reason: "first hold".into()
            }
        );

        // Single-policy chain reports its member's backend_name.
        let single = OutboundPolicyChain::new(vec![Arc::new(CountingPolicy {
            name: "solo",
            decision: OutboundDecision::Allow,
            calls: Arc::new(AtomicUsize::new(0)),
        })]);
        assert_eq!(single.backend_name(), "solo");
        assert_eq!(
            single.evaluate(&OutboundCheck::default()).await.unwrap(),
            OutboundDecision::Allow
        );
    }

    #[tokio::test]
    async fn first_contact_policy_checks_sent_history_and_mailbox_scope() {
        let store: Arc<dyn MailStore> = Arc::new(MemoryStore::new("alice@example.com"));
        let policy = FirstContactPolicy::new(store.clone());

        // Unknown external recipient triggers HoldForApproval.
        let check_unknown = OutboundCheck {
            from: "alice@example.com".into(),
            to: vec!["stranger@external.example".into()],
            ..Default::default()
        };
        let dec = policy.evaluate(&check_unknown).await.unwrap();
        assert_eq!(
            dec,
            OutboundDecision::HoldForApproval {
                reason: "First-contact recipient requires approval: stranger@external.example"
                    .into()
            }
        );

        // Receiving mail from them (sent_count == 0) still requires first-contact approval.
        store
            .record_contact_interaction(&ContactInteraction {
                email: "stranger@external.example".into(),
                display_name: Some("Stranger".into()),
                direction: ContactDirection::Received,
                is_reply: false,
                timestamp_ms: 1_700_000_000_000,
            })
            .await
            .unwrap();
        assert!(matches!(
            policy.evaluate(&check_unknown).await.unwrap(),
            OutboundDecision::HoldForApproval { .. }
        ));

        // Once sent_count > 0, subsequent sends are allowed.
        store
            .record_contact_interaction(&ContactInteraction {
                email: "stranger@external.example".into(),
                display_name: None,
                direction: ContactDirection::Sent,
                is_reply: false,
                timestamp_ms: 1_700_000_001_000,
            })
            .await
            .unwrap();
        assert_eq!(
            policy.evaluate(&check_unknown).await.unwrap(),
            OutboundDecision::Allow
        );

        // Self-send is always allowed.
        let check_self = OutboundCheck {
            from: "alice@example.com".into(),
            to: vec!["alice@example.com".into()],
            ..Default::default()
        };
        assert_eq!(
            policy.evaluate(&check_self).await.unwrap(),
            OutboundDecision::Allow
        );

        // Another mailbox via `for_mailbox` does NOT inherit alice's sent contacts.
        let bob_policy = policy.for_mailbox("bob@example.com").expect("scoped");
        let check_bob = OutboundCheck {
            from: "bob@example.com".into(),
            to: vec!["stranger@external.example".into()],
            mailbox_id: Some("bob@example.com".into()),
            ..Default::default()
        };
        assert!(matches!(
            bob_policy.evaluate(&check_bob).await.unwrap(),
            OutboundDecision::HoldForApproval { .. }
        ));
    }

    #[tokio::test]
    async fn dlp_scanner_detects_secrets_and_pii_without_echoing_values() {
        let aws_key = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        let gh_token = format!("ghp_{}", "a1B2c3D4e5F6g7H8i9J0k1L2");
        let gh_pat = format!("github_pat_{}", "11ABCDEFG_0123456789abcdef");
        let resend_key = format!("re_{}", "AbCdEf1234567890_XyZwVu");
        let openai_key = format!("sk-{}", "proj1234567890abcdefghij");
        let stripe_key = format!("sk_live_{}", "51AbCdEfGhIjKlMnOpQrStUv");
        let private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...";
        let ssn = "123-45-6789";
        let visa_card = "4111-1111-1111-1111";

        assert_eq!(scan_dlp_text(&aws_key), vec!["aws_access_key_id"]);
        assert_eq!(scan_dlp_text(&gh_token), vec!["github_token"]);
        assert_eq!(scan_dlp_text(&gh_pat), vec!["github_token"]);
        assert_eq!(scan_dlp_text(&resend_key), vec!["resend_api_key"]);
        assert_eq!(scan_dlp_text(&openai_key), vec!["secret_api_key"]);
        assert_eq!(scan_dlp_text(&stripe_key), vec!["secret_api_key"]);
        assert_eq!(scan_dlp_text(private_key), vec!["private_key_block"]);
        assert_eq!(scan_dlp_text(ssn), vec!["us_ssn"]);
        assert_eq!(scan_dlp_text(visa_card), vec!["credit_card"]);
        assert_eq!(
            scan_dlp_text("Ref 123 4242 4242 4242 4242 ok"),
            vec!["credit_card"]
        );

        // False-positive checks: benign text, timestamps, invalid SSNs, invalid Luhn cards.
        assert!(scan_dlp_text("Hello world, timestamp 1700000000006, order 12345").is_empty());
        assert!(
            scan_dlp_text("Invalid SSN 000-45-6789 and 666-12-3456 and 123-00-6789").is_empty()
        );
        assert!(scan_dlp_text("Bad card 4242-4242-4242-4243").is_empty());
        assert!(scan_dlp_text("All zeros 0000-0000-0000-0000").is_empty());

        // Attachment filename scanning & never echoing raw secret.
        let policy = DlpOutboundPolicy::new(DlpAction::Deny);
        let check = OutboundCheck {
            subject: "Quarterly report".into(),
            text: Some(format!("Key: {aws_key}")),
            attachment_filenames: vec![format!("{resend_key}.txt")],
            ..Default::default()
        };
        let dec = policy.evaluate(&check).await.unwrap();
        match dec {
            OutboundDecision::Deny { code, reason, .. } => {
                assert_eq!(code, "dlp_blocked");
                assert!(reason.contains("aws_access_key_id"));
                assert!(reason.contains("resend_api_key"));
                assert!(!reason.contains(&aws_key));
                assert!(!reason.contains(&resend_key));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn dlp_pem_scanner_handles_multibyte_utf8_across_byte_96_without_panicking() {
        // 50 two-byte 'é' characters = 100 bytes; byte 96 lands in the middle of a char if shifted by 1.
        let non_boundary_padding = format!("x{}", "é".repeat(50));
        let harmless = format!("-----BEGIN {non_boundary_padding}-----");
        assert!(scan_dlp_text(&harmless).is_empty());

        // Real private key header preceded by multi-byte UTF-8 still detected.
        let with_key =
            format!("-----BEGIN {non_boundary_padding}\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...");
        assert_eq!(scan_dlp_text(&with_key), vec!["private_key_block"]);
    }
}
