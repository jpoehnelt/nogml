//! Agent safety guardrails, pluggable [`OutboundPolicy`], input hardening,
//! untrusted-content sanitization, recipient allowlists, `draft_only` enforcement,
//! and `dry_run` policy evaluation.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::{
    AppState,
    auth::AgentPolicyOverride,
    config::{Config, DraftOnlyAction},
    error::{AppError, AppResult},
    mime::{ComposeEmailInput, build_rfc2822},
    models::{AiSendEmailRequest, DryRunPreview, DryRunResponse, PolicyCheckResult, UntrustedMeta},
    storage::parse_simple_email_address,
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
    pub thread_id: Option<String>,
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

    /// Short backend identifier reported by `GET /v1/capabilities`.
    fn backend_name(&self) -> &'static str {
        "custom"
    }
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

/// Extract a normalized lowercase bare email address from either `"Name <a@b.com>"` or `"a@b.com"`.
pub fn extract_email_address(raw: &str) -> String {
    parse_simple_email_address(raw)
        .email
        .trim()
        .to_ascii_lowercase()
}

/// Validate basic RFC 5322 email syntax (allowing `@localhost` for local testing).
pub fn is_valid_email_syntax(raw: &str) -> bool {
    if raw.trim().is_empty() || raw.contains('\r') || raw.contains('\n') || raw.contains('\0') {
        return false;
    }
    let email = extract_email_address(raw);
    let mut parts = email.split('@');
    let Some(local) = parts.next() else {
        return false;
    };
    let Some(domain) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    if local.is_empty() || local.len() > 64 || domain.is_empty() || domain.len() > 255 {
        return false;
    }
    if local.chars().any(|c| c.is_whitespace() || c.is_control())
        || domain.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return false;
    }
    domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Check whether `recipient` matches an allowlist rule:
/// - Exact address (case-insensitive): `alice@example.com`
/// - Exact domain: `@example.com`
/// - Subdomain wildcard: `*.example.com` (or `@*.example.com`)
pub fn recipient_matches_rule(recipient: &str, rule: &str) -> bool {
    let email = extract_email_address(recipient);
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
    evaluate_resolved_dry_run(
        state,
        &req.to,
        &req.cc,
        &req.bcc,
        req.subject.as_deref(),
        req.text.as_deref(),
        req.html.as_deref(),
        req.reply_to_message_id.as_deref(),
        None,
        None,
        None,
        None,
        agent_policy,
    )
    .await
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
        thread_id: resolved.thread_id.clone(),
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

    if state.config.require_approval && !state.config.draft_only {
        warnings.push(
            "require_approval=true: executing this send will hold the email in the pending approval queue until a human approves it.".to_string(),
        );
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
