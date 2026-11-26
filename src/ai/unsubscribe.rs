//! Safe RFC 8058 one-click HTTP POST and RFC 2369 `mailto:` unsubscribe execution
//! with strict SSRF protection, `dry_run` preview, and [`OutboundPolicy`] enforcement.

use std::{net::SocketAddr, time::Duration};

use chrono::Utc;
use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;

pub use crate::net_guard::is_globally_routable_ip;
use crate::{
    AppState,
    ai::{
        build_hold_response, build_outbound_message, build_outbound_rfc2822,
        enqueue_pending_approval, policy_deny_to_error,
        safety::{
            OutboundCheck, OutboundDecision, ResolvedOutbound, is_valid_email_syntax,
            validate_email_header, validate_resource_id,
        },
        validate_recipients_syntax,
    },
    auth::{AuthScope, Principal},
    config::DraftOnlyAction,
    error::{AppError, AppResult},
    events::{EventSource, MailEvent},
    mime::{RFC8058_ONE_CLICK_BODY, generate_snippet, parse_unsubscribe_from_raw},
    models::{LABEL_DRAFT, LABEL_SENT, PolicyCheckResult, UnsubscribeInfo},
    net_guard::{
        PinnedUrl, UrlGuardOptions, build_pinned_http_client, ssrf_error, validate_and_pin_url,
        validate_url_static,
    },
    storage::NewMessageInput,
};

/// Hard timeout enforced on RFC 8058 one-click HTTP POST requests.
const UNSUBSCRIBE_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Validated RFC 8058 HTTPS target with pre-resolved global IP addresses.
#[derive(Debug, Clone)]
pub struct ValidatedUnsubscribeUrl {
    pub url: Url,
    pub domain: Option<String>,
    pub resolved_addrs: Vec<SocketAddr>,
}

/// Parsed fields of an RFC 6068 `mailto:` unsubscribe URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMailto {
    pub to: Vec<String>,
    pub subject: String,
    pub body: String,
}

#[derive(Debug, Clone)]
enum SelectedMethod {
    OneClickPost(String),
    Mailto(String),
}

/// Perform zero-network static SSRF validation on an unsubscribe URL.
///
/// Rejects non-`https://` schemes, embedded credentials, local hostnames, and
/// non-globally-routable IP literals (unless `allow_private_for_tests` is `true`).
pub fn validate_unsubscribe_https_url_static(
    raw_url: &str,
    allow_private_for_tests: bool,
) -> AppResult<Url> {
    validate_url_static(
        raw_url,
        UrlGuardOptions {
            allow_private_endpoints: allow_private_for_tests,
            allow_http: false,
            allowed_hosts: &[],
            context: "Unsubscribe URL",
        },
    )
}

/// Validate an RFC 8058 unsubscribe HTTPS URL including DNS resolution via
/// `tokio::net::lookup_host` and strict non-global IP rejection.
pub async fn validate_unsubscribe_https_url(
    raw_url: &str,
    allow_private_for_tests: bool,
) -> AppResult<ValidatedUnsubscribeUrl> {
    let pinned = validate_and_pin_url(
        raw_url,
        UrlGuardOptions {
            allow_private_endpoints: allow_private_for_tests,
            allow_http: false,
            allowed_hosts: &[],
            context: "Unsubscribe URL",
        },
    )
    .await?;
    Ok(ValidatedUnsubscribeUrl {
        url: pinned.url,
        domain: pinned.domain,
        resolved_addrs: pinned.resolved_addrs,
    })
}

/// Parse an RFC 6068 `mailto:` URI into recipient address(es), subject, and text body.
pub fn parse_mailto_uri(raw: &str) -> AppResult<ParsedMailto> {
    let trimmed = raw.trim();
    let parsed = Url::parse(trimmed).map_err(|err| {
        AppError::validation(
            format!("Invalid mailto URI: {err}"),
            Some("List-Unsubscribe mailto URI could not be parsed.".to_string()),
        )
    })?;

    if !parsed.scheme().eq_ignore_ascii_case("mailto") {
        return Err(AppError::validation(
            format!("Expected mailto: URI, got '{}'", parsed.scheme()),
            None,
        ));
    }

    let mut recipients: Vec<String> = Vec::new();
    let raw_path = percent_decode(parsed.path());
    for part in raw_path.split(',') {
        let addr = part.trim();
        if !addr.is_empty() {
            recipients.push(addr.to_string());
        }
    }

    let mut subject: Option<String> = None;
    let mut body: Option<String> = None;

    for (key, value) in parsed.query_pairs() {
        let val = value.into_owned();
        if key.eq_ignore_ascii_case("to") {
            for part in val.split(',') {
                let addr = part.trim();
                if !addr.is_empty() {
                    recipients.push(addr.to_string());
                }
            }
        } else if key.eq_ignore_ascii_case("subject") && subject.is_none() {
            subject = Some(val);
        } else if key.eq_ignore_ascii_case("body") && body.is_none() {
            body = Some(val);
        }
    }

    if recipients.is_empty() {
        return Err(AppError::validation(
            "List-Unsubscribe mailto URI contains no recipient address",
            None,
        ));
    }

    for addr in &recipients {
        validate_email_header("to", addr)?;
        if !is_valid_email_syntax(addr) {
            return Err(AppError::validation(
                format!("Invalid mailto unsubscribe recipient '{addr}'"),
                None,
            ));
        }
    }

    let final_subject = subject
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Unsubscribe".to_string());
    validate_email_header("subject", &final_subject)?;

    let final_body = body
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "Unsubscribe".to_string());

    Ok(ParsedMailto {
        to: recipients,
        subject: final_subject,
        body: final_body,
    })
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Execute safe unsubscribe for `message_id` (shared across `/v1/messages/{id}/unsubscribe` and MCP `unsubscribe`).
pub async fn execute_unsubscribe(
    state: &AppState,
    principal: Option<Principal>,
    message_id: &str,
    dry_run: bool,
    prefer_mailto: bool,
) -> AppResult<Value> {
    execute_unsubscribe_with_source(
        state,
        principal,
        message_id,
        dry_run,
        prefer_mailto,
        EventSource::Api,
    )
    .await
}

/// Variant allowing callers (REST vs MCP) to tag the published [`EventSource`].
pub async fn execute_unsubscribe_with_source(
    state: &AppState,
    principal: Option<Principal>,
    message_id: &str,
    dry_run: bool,
    prefer_mailto: bool,
    source: EventSource,
) -> AppResult<Value> {
    // Scope enforcement: `Write` (or `Send`) suffices for `dry_run`, `Send` is required to execute.
    if let Some(p) = principal.as_ref() {
        if dry_run {
            if !p.has_scope(AuthScope::Write) && !p.has_scope(AuthScope::Send) {
                p.require_scope(AuthScope::Write)?;
            }
        } else {
            p.require_scope(AuthScope::Send)?;
        }
    }

    validate_resource_id(message_id)?;

    let msg = state
        .store
        .get_message(message_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Message '{message_id}' not found")))?;

    let raw_bytes = if msg.raw_rfc2822.is_empty() {
        state.load_raw_rfc2822(&msg).await?
    } else {
        msg.raw_rfc2822.clone()
    };

    let info = parse_unsubscribe_from_raw(&raw_bytes).ok_or_else(|| {
        AppError::validation(
            format!("Message '{message_id}' does not contain supported List-Unsubscribe headers"),
            Some(
                "Only messages with RFC 2369/8058 List-Unsubscribe headers can be unsubscribed automatically."
                    .to_string(),
            ),
        )
    })?;

    let (method, mut warnings) = select_method(&info, prefer_mailto)?;
    let agent_policy = principal.as_ref().and_then(|p| p.agent_policy.clone());
    let audit_principal = principal.clone();

    let result = match method {
        SelectedMethod::OneClickPost(url) => {
            execute_one_click_post(
                state,
                &msg.id,
                &msg.subject,
                &url,
                &info,
                dry_run,
                agent_policy,
                &mut warnings,
            )
            .await
        }
        SelectedMethod::Mailto(mailto_uri) => {
            execute_mailto_unsubscribe(
                state,
                &msg.id,
                &mailto_uri,
                &info,
                dry_run,
                principal,
                agent_policy,
                source,
                &mut warnings,
            )
            .await
        }
    };

    let channel = crate::ai::channel_for_source(source);
    match &result {
        Ok(val) => {
            let outcome = if dry_run {
                "dry_run"
            } else {
                match val.get("status").and_then(Value::as_str) {
                    Some("pending_approval") => "pending_approval",
                    Some("draft_created") => "downgraded_to_draft",
                    _ => "ok",
                }
            };
            let detail = val
                .get("method")
                .and_then(Value::as_str)
                .map(|m| format!("method={m}"));
            state
                .record_audit(
                    audit_principal.as_ref(),
                    channel,
                    "unsubscribe",
                    vec![msg.id.clone()],
                    outcome,
                    detail,
                )
                .await;
        }
        Err(err) => {
            let outcome = match err {
                AppError::PolicyDenied { .. }
                | AppError::DraftOnlyBlocked { .. }
                | AppError::Forbidden(_) => "denied",
                _ => "error",
            };
            state
                .record_audit(
                    audit_principal.as_ref(),
                    channel,
                    "unsubscribe",
                    vec![msg.id.clone()],
                    outcome,
                    Some(err.to_string()),
                )
                .await;
        }
    }

    result
}

fn select_method(
    info: &UnsubscribeInfo,
    prefer_mailto: bool,
) -> AppResult<(SelectedMethod, Vec<String>)> {
    let mut warnings = Vec::new();

    if prefer_mailto {
        if let Some(ref mailto) = info.mailto {
            return Ok((SelectedMethod::Mailto(mailto.clone()), warnings));
        }
        if info.one_click
            && let Some(ref https_url) = info.https_url
        {
            warnings.push(
                "prefer_mailto=true requested but message has no mailto: List-Unsubscribe URI; falling back to RFC 8058 one-click POST."
                    .to_string(),
            );
            return Ok((SelectedMethod::OneClickPost(https_url.clone()), warnings));
        }
    } else {
        if info.one_click
            && let Some(ref https_url) = info.https_url
        {
            return Ok((SelectedMethod::OneClickPost(https_url.clone()), warnings));
        }
        if let Some(ref mailto) = info.mailto {
            return Ok((SelectedMethod::Mailto(mailto.clone()), warnings));
        }
    }

    // Only a non-one-click HTTP(S) link exists and no mailto: fallback.
    // Surface SSRF violation first if the URL itself violates scheme/IP rules.
    if let Some(ref url) = info.https_url {
        validate_unsubscribe_https_url_static(url, false)?;
    }

    Err(AppError::validation(
        "Message does not support RFC 8058 one-click POST and has no mailto: unsubscribe fallback",
        Some(
            "Non-one-click HTTPS unsubscribe URLs require interactive confirmation and are not submitted automatically."
                .to_string(),
        ),
    ))
}

#[allow(clippy::too_many_arguments)]
async fn execute_one_click_post(
    state: &AppState,
    message_id: &str,
    message_subject: &str,
    url: &str,
    info: &UnsubscribeInfo,
    dry_run: bool,
    agent_policy: Option<crate::auth::AgentPolicyOverride>,
    warnings: &mut Vec<String>,
) -> AppResult<Value> {
    let outbound_check = OutboundCheck {
        from: state.config.user_email.clone(),
        to: Vec::new(),
        cc: Vec::new(),
        bcc: Vec::new(),
        subject: format!("Unsubscribe: {message_subject}"),
        text: Some(RFC8058_ONE_CLICK_BODY.to_string()),
        html: None,
        attachment_filenames: Vec::new(),
        thread_id: None,
        mailbox_id: Some(state.mailbox_id().to_string()),
        is_draft_send: false,
        agent_policy: agent_policy.clone(),
    };

    if dry_run {
        let mut checks = Vec::new();
        match validate_unsubscribe_https_url_static(url, false) {
            Ok(_) => {
                checks.push(PolicyCheckResult {
                    rule: "ssrf_protection".to_string(),
                    passed: true,
                    detail: "URL uses https:// and passes static SSRF checks (DNS IP validation runs on execute)".to_string(),
                });
            }
            Err(err) => {
                checks.push(PolicyCheckResult {
                    rule: "ssrf_protection".to_string(),
                    passed: false,
                    detail: err.to_string(),
                });
                warnings.push(format!("SSRF guard would block this target: {err}"));
            }
        }

        checks.push(PolicyCheckResult {
            rule: "rfc8058_one_click".to_string(),
            passed: info.one_click,
            detail: "List-Unsubscribe-Post: List-Unsubscribe=One-Click header present".to_string(),
        });

        let effective_draft_only = state.config.draft_only
            || agent_policy
                .as_ref()
                .and_then(|p| p.draft_only)
                .unwrap_or(false);

        for mut check in state.outbound_policy.policy_checks(&outbound_check) {
            if check.rule == "draft_only"
                && effective_draft_only
                && state.config.draft_only_action == DraftOnlyAction::Downgrade
            {
                check.passed = false;
                check.detail = "draft_only mode is active; RFC 8058 one-click HTTP POST cannot be downgraded to a local draft".to_string();
                warnings.push(
                    "draft_only=true blocks direct one-click HTTP POST; pass prefer_mailto: true if a mailto: target is available."
                        .to_string(),
                );
            } else if check.rule == "require_approval" && state.config.require_approval {
                check.passed = false;
                check.detail = "require_approval is enabled; direct RFC 8058 one-click HTTP POST is blocked without approval".to_string();
                warnings.push(
                    "require_approval=true blocks direct one-click HTTP POST; pass prefer_mailto: true to queue a mailto: unsubscribe for human approval."
                        .to_string(),
                );
            }
            checks.push(check);
        }

        let would_succeed = checks.iter().all(|c| c.passed);
        return Ok(json!({
            "dry_run": true,
            "message_id": message_id,
            "method": "one_click_post",
            "target": url,
            "one_click": info.one_click,
            "post_body": RFC8058_ONE_CLICK_BODY,
            "would_succeed": would_succeed,
            "policy_checks": checks,
            "warnings": warnings,
        }));
    }

    // 1. Static SSRF check before policy or any DNS lookup.
    validate_unsubscribe_https_url_static(url, false)?;

    // 2. Enforce OutboundPolicy (draft_only, require_approval, custom policies) BEFORE DNS/HTTP.
    let decision = state.evaluate_outbound_policy(&outbound_check).await?;
    match decision {
        OutboundDecision::Allow => {}
        OutboundDecision::Deny { code, reason, hint } => {
            return Err(policy_deny_to_error(code, reason, hint));
        }
        OutboundDecision::DowngradeToDraft { .. } => {
            return Err(AppError::DraftOnlyBlocked {
                hint: "RFC 8058 one-click HTTP POST cannot be downgraded to a local draft while draft_only=true. Pass prefer_mailto: true (if mailto: is available) or dry_run: true."
                    .to_string(),
            });
        }
        OutboundDecision::HoldForApproval { reason } => {
            return Err(AppError::PolicyDenied {
                code: "approval_required".to_string(),
                message: reason,
                hint: Some(
                    "One-click HTTPS unsubscribe is blocked while require_approval=true. Pass prefer_mailto: true (if mailto: is available) to queue for human approval, or dry_run: true to preview."
                        .to_string(),
                ),
                details: None,
            });
        }
    }

    // 3. Full DNS resolution + SSRF IP check, pinning validated SocketAddrs to prevent DNS rebinding.
    let validated = validate_unsubscribe_https_url(url, false).await?;
    let http_status = send_one_click_post_request(&validated).await?;

    Ok(json!({
        "status": "unsubscribed",
        "method": "one_click_post",
        "message_id": message_id,
        "target": url,
        "one_click": true,
        "post_body": RFC8058_ONE_CLICK_BODY,
        "http_status": http_status,
    }))
}

async fn send_one_click_post_request(target: &ValidatedUnsubscribeUrl) -> AppResult<u16> {
    let pinned = PinnedUrl {
        url: target.url.clone(),
        domain: target.domain.clone(),
        resolved_addrs: target.resolved_addrs.clone(),
    };
    let client = build_pinned_http_client(&pinned, UNSUBSCRIBE_HTTP_TIMEOUT, None)?;

    let response = client
        .post(target.url.as_str())
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(
            reqwest::header::USER_AGENT,
            format!("nogml/{}", env!("CARGO_PKG_VERSION")),
        )
        .body(RFC8058_ONE_CLICK_BODY)
        .send()
        .await
        .map_err(|err| AppError::Upstream {
            status: err.status().map(|s| s.as_u16()).unwrap_or(502),
            message: format!("One-click unsubscribe HTTP POST failed: {err}"),
        })?;

    let status = response.status();
    if status.is_redirection() {
        return Err(ssrf_error(
            format!(
                "Unsubscribe endpoint returned HTTP {} redirect; automatic redirects are disabled for SSRF protection",
                status.as_u16()
            ),
            "RFC 8058 one-click endpoints must accept POST directly without redirecting.",
        ));
    }
    if !status.is_success() {
        return Err(AppError::Upstream {
            status: status.as_u16(),
            message: format!(
                "Unsubscribe endpoint returned non-success HTTP status {}",
                status.as_u16()
            ),
        });
    }

    Ok(status.as_u16())
}

#[allow(clippy::too_many_arguments)]
async fn execute_mailto_unsubscribe(
    state: &AppState,
    message_id: &str,
    mailto_uri: &str,
    info: &UnsubscribeInfo,
    dry_run: bool,
    principal: Option<Principal>,
    agent_policy: Option<crate::auth::AgentPolicyOverride>,
    source: EventSource,
    warnings: &mut Vec<String>,
) -> AppResult<Value> {
    let parsed = parse_mailto_uri(mailto_uri)?;

    let resolved = ResolvedOutbound {
        from: state.config.user_email.clone(),
        to: parsed.to.clone(),
        cc: Vec::new(),
        bcc: Vec::new(),
        subject: parsed.subject.clone(),
        text: Some(parsed.body.clone()),
        html: None,
        thread_id: None,
        in_reply_to: None,
        references: None,
    };

    let policy_check = OutboundCheck {
        from: resolved.from.clone(),
        to: resolved.to.clone(),
        cc: Vec::new(),
        bcc: Vec::new(),
        subject: resolved.subject.clone(),
        text: resolved.text.clone(),
        html: None,
        attachment_filenames: Vec::new(),
        thread_id: None,
        mailbox_id: Some(state.mailbox_id().to_string()),
        is_draft_send: false,
        agent_policy: agent_policy.clone(),
    };

    if dry_run {
        let mut checks = vec![
            PolicyCheckResult {
                rule: "mailto_parsed".to_string(),
                passed: true,
                detail: format!(
                    "Parsed {} recipient(s) from mailto: List-Unsubscribe URI",
                    parsed.to.len()
                ),
            },
            PolicyCheckResult {
                rule: "recipient_syntax".to_string(),
                passed: true,
                detail: "All mailto recipient addresses passed syntax validation".to_string(),
            },
        ];
        checks.extend(state.outbound_policy.policy_checks(&policy_check));

        let effective_draft_only = state.config.draft_only
            || agent_policy
                .as_ref()
                .and_then(|p| p.draft_only)
                .unwrap_or(false);
        if effective_draft_only && state.config.draft_only_action == DraftOnlyAction::Downgrade {
            warnings.push(
                "draft_only=true with action=downgrade: executing this unsubscribe will save a local draft instead of sending externally."
                    .to_string(),
            );
        }
        if state.config.require_approval && !effective_draft_only {
            warnings.push(
                "require_approval=true: executing this unsubscribe will hold the mailto email in the pending approval queue until a human approves it."
                    .to_string(),
            );
        }

        let would_succeed = checks.iter().all(|c| c.passed);
        return Ok(json!({
            "dry_run": true,
            "message_id": message_id,
            "method": "mailto",
            "target": mailto_uri,
            "one_click": info.one_click,
            "would_succeed": would_succeed,
            "policy_checks": checks,
            "warnings": warnings,
            "preview": {
                "from": resolved.from,
                "to": resolved.to,
                "subject": resolved.subject,
                "body": parsed.body,
            },
        }));
    }

    validate_recipients_syntax(&resolved.to, &resolved.cc, &resolved.bcc)?;

    let decision = state.evaluate_outbound_policy(&policy_check).await?;

    let rfc_message_id = format!("<{}@{}>", Uuid::new_v4(), state.config.default_domain);
    let raw_rfc2822 = build_outbound_rfc2822(&resolved, &rfc_message_id)?;
    let text_body = resolved.text.clone().unwrap_or_default();
    let snippet = generate_snippet(&text_body, None);
    let now_ms = Utc::now().timestamp_millis();

    match decision {
        OutboundDecision::Deny { code, reason, hint } => {
            return Err(policy_deny_to_error(code, reason, hint));
        }
        OutboundDecision::DowngradeToDraft { .. } => {
            let draft = state
                .store
                .create_draft(NewMessageInput {
                    id: None,
                    thread_id: None,
                    label_ids: vec![LABEL_DRAFT.to_string()],
                    raw_rfc2822,
                    snippet,
                    internal_date_ms: now_ms,
                    subject: resolved.subject.clone(),
                    from_addr: resolved.from.clone(),
                    to_addrs: resolved.to.clone(),
                    cc_addrs: Vec::new(),
                    bcc_addrs: Vec::new(),
                    text_body,
                    html_body: None,
                    rfc822_message_id: Some(rfc_message_id),
                    in_reply_to: None,
                    references_header: None,
                    resend_id: None,
                    upstream_gmail_id: None,
                    upstream_thread_id: None,
                    source: "local".to_string(),
                    is_answered: false,
                    is_deleted: false,
                    attachments: Vec::new(),
                })
                .await?;
            state.post_store_message(&draft.message).await?;
            state.events.publish(
                source,
                MailEvent::DraftCreated {
                    draft_id: draft.id.clone(),
                    message_id: draft.message.id.clone(),
                    thread_id: draft.message.thread_id.clone(),
                },
            );
            return Ok(json!({
                "status": "draft_created",
                "downgraded_from_send": true,
                "method": "mailto",
                "source_message_id": message_id,
                "target": mailto_uri,
                "one_click": info.one_click,
                "draft_id": draft.id,
                "message_id": draft.message.id,
                "thread_id": draft.message.thread_id,
                "to": draft.message.to_addrs,
                "subject": draft.message.subject,
            }));
        }
        OutboundDecision::HoldForApproval { reason } => {
            let outbound_msg = build_outbound_message(&resolved, &rfc_message_id, &raw_rfc2822);
            let draft = state
                .store
                .create_draft(NewMessageInput {
                    id: None,
                    thread_id: None,
                    label_ids: vec![LABEL_DRAFT.to_string()],
                    raw_rfc2822,
                    snippet: snippet.clone(),
                    internal_date_ms: now_ms,
                    subject: resolved.subject.clone(),
                    from_addr: resolved.from.clone(),
                    to_addrs: resolved.to.clone(),
                    cc_addrs: Vec::new(),
                    bcc_addrs: Vec::new(),
                    text_body,
                    html_body: None,
                    rfc822_message_id: Some(rfc_message_id),
                    in_reply_to: None,
                    references_header: None,
                    resend_id: None,
                    upstream_gmail_id: None,
                    upstream_thread_id: None,
                    source: "local".to_string(),
                    is_answered: false,
                    is_deleted: false,
                    attachments: Vec::new(),
                })
                .await?;
            state.post_store_message(&draft.message).await?;
            state.events.publish(
                source,
                MailEvent::DraftCreated {
                    draft_id: draft.id.clone(),
                    message_id: draft.message.id.clone(),
                    thread_id: draft.message.thread_id.clone(),
                },
            );

            let approval = enqueue_pending_approval(
                state,
                reason,
                principal,
                outbound_msg,
                None,
                Some(draft.message.thread_id.clone()),
                Some(draft.id.clone()),
                now_ms,
                &snippet,
                source,
            )
            .await?;

            let mut resp = build_hold_response(
                &approval,
                Some(&draft.id),
                Some(&draft.message.id),
                Some(&draft.message.thread_id),
                &snippet,
            );
            if let Some(obj) = resp.as_object_mut() {
                obj.insert("method".to_string(), json!("mailto"));
                obj.insert("target".to_string(), json!(mailto_uri));
                obj.insert("source_message_id".to_string(), json!(message_id));
                obj.insert("one_click".to_string(), json!(info.one_click));
            }
            return Ok(resp);
        }
        OutboundDecision::Allow => {}
    }

    let outbound_msg = build_outbound_message(&resolved, &rfc_message_id, &raw_rfc2822);
    let send_outcome = state.transport.send(&outbound_msg, None).await?;

    let stored = state
        .store
        .insert_message(NewMessageInput {
            id: None,
            thread_id: None,
            label_ids: vec![LABEL_SENT.to_string()],
            raw_rfc2822,
            snippet,
            internal_date_ms: now_ms,
            subject: resolved.subject.clone(),
            from_addr: resolved.from.clone(),
            to_addrs: resolved.to.clone(),
            cc_addrs: Vec::new(),
            bcc_addrs: Vec::new(),
            text_body,
            html_body: None,
            rfc822_message_id: Some(rfc_message_id),
            in_reply_to: None,
            references_header: None,
            resend_id: Some(send_outcome.provider_message_id.clone()),
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "local".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: Vec::new(),
        })
        .await?;

    state.post_store_message(&stored).await?;
    state.metrics.inc_messages_sent();

    state.events.publish(
        source,
        MailEvent::MessageSent {
            message_id: stored.id.clone(),
            thread_id: stored.thread_id.clone(),
            to: stored.to_addrs.clone(),
            subject: stored.subject.clone(),
            resend_id: Some(send_outcome.provider_message_id.clone()),
            labels: stored.label_ids.clone(),
        },
    );

    Ok(json!({
        "status": "unsubscribed",
        "method": "mailto",
        "source_message_id": message_id,
        "target": mailto_uri,
        "one_click": info.one_click,
        "provider": send_outcome.provider,
        "message_id": stored.id,
        "thread_id": stored.thread_id,
        "resend_id": send_outcome.provider_message_id,
        "from": stored.from_addr,
        "to": stored.to_addrs,
        "subject": stored.subject,
    }))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn ip_global_routability_blocks_all_private_and_special_ranges() {
        let blocked = [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "10.255.255.254",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "127.1.2.3",
            "169.254.169.254",
            "169.254.0.1",
            "172.16.0.1",
            "172.31.255.254",
            "192.0.0.1",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:192.168.1.10",
            "::127.0.0.1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "64:ff9b::127.0.0.1",
            "64:ff9b::169.254.169.254",
            "2002:7f00:0001::1",
        ];

        for ip_str in blocked {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert!(
                !is_globally_routable_ip(ip),
                "expected {ip_str} to be blocked as non-global"
            );
        }

        let allowed = [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "172.32.0.1",
            "100.128.0.1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "::ffff:93.184.216.34",
        ];

        for ip_str in allowed {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert!(
                is_globally_routable_ip(ip),
                "expected {ip_str} to be allowed as globally routable"
            );
        }
    }

    #[tokio::test]
    async fn validate_unsubscribe_https_url_blocks_ssrf_targets_and_bad_schemes() {
        let blocked_urls = [
            "http://example.com/unsub",
            "file:///etc/passwd",
            "ftp://example.com/unsub",
            "https://user:pass@example.com/unsub",
            "https://127.0.0.1/unsub",
            "https://127.0.0.1:8443/unsub",
            "https://169.254.169.254/latest/meta-data/",
            "https://10.0.0.1/internal",
            "https://172.16.0.5/internal",
            "https://192.168.1.1/admin",
            "https://100.64.0.1/cgnat",
            "https://0.0.0.0/unsub",
            "https://[::1]/unsub",
            "https://[::ffff:127.0.0.1]/unsub",
            "https://[::ffff:169.254.169.254]/unsub",
            "https://[fc00::1]/unsub",
            "https://[fe80::1]/unsub",
            "https://localhost/unsub",
            "https://api.localhost/unsub",
            "https://metadata.google.internal/computeMetadata/v1/",
        ];

        for bad in blocked_urls {
            let err = validate_unsubscribe_https_url(bad, false)
                .await
                .expect_err(&format!("expected '{bad}' to be blocked"));
            assert_eq!(
                err.status_code(),
                StatusCode::FORBIDDEN,
                "expected 403 Forbidden for '{bad}', got {err:?}"
            );
            assert_eq!(err.ai_code(), "ssrf_blocked", "bad code for '{bad}'");
        }

        // Public literal IP succeeds with zero DNS dependency.
        let ok = validate_unsubscribe_https_url("https://93.184.216.34/unsub?id=1", false)
            .await
            .expect("public https IP should pass");
        assert_eq!(ok.resolved_addrs.len(), 1);
        assert_eq!(ok.resolved_addrs[0].ip().to_string(), "93.184.216.34");
        assert_eq!(ok.resolved_addrs[0].port(), 443);

        // allow_private_for_tests permits https://127.0.0.1 but still rejects http:// and file://.
        let local_ok = validate_unsubscribe_https_url("https://127.0.0.1:8443/unsub", true)
            .await
            .expect("private https allowed when test flag set");
        assert_eq!(local_ok.resolved_addrs[0].port(), 8443);

        assert!(
            validate_unsubscribe_https_url("http://127.0.0.1:8080/unsub", true)
                .await
                .is_err()
        );
        assert!(
            validate_unsubscribe_https_url("file:///etc/passwd", true)
                .await
                .is_err()
        );
    }

    #[test]
    fn parse_mailto_uri_extracts_recipient_subject_and_body() {
        let parsed = parse_mailto_uri(
            "mailto:unsub%2B123@example.com?subject=Unsubscribe%20Me&body=Please%20remove%20me",
        )
        .expect("parse mailto");
        assert_eq!(parsed.to, vec!["unsub+123@example.com"]);
        assert_eq!(parsed.subject, "Unsubscribe Me");
        assert_eq!(parsed.body, "Please remove me");

        // Defaults subject and body when omitted.
        let minimal = parse_mailto_uri("mailto:leave@lists.example.org").expect("minimal mailto");
        assert_eq!(minimal.to, vec!["leave@lists.example.org"]);
        assert_eq!(minimal.subject, "Unsubscribe");
        assert_eq!(minimal.body, "Unsubscribe");

        // Rejects header injection in subject.
        assert!(
            parse_mailto_uri("mailto:unsub@example.com?subject=Hi%0D%0ABcc:evil@x.com").is_err()
        );
        // Rejects invalid email syntax.
        assert!(parse_mailto_uri("mailto:not-an-email").is_err());
    }
}
