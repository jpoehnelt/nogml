//! Event-driven per-mailbox inbox rules evaluation, dry-run testing, and
//! asynchronous HMAC-SHA256 signed webhook delivery.

use std::{collections::HashMap, time::Duration};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use tracing::warn;

use crate::{
    AppState,
    ai::{channel_for_source, sanitize_untrusted_text, to_compact_message, validate_resource_id},
    auth::{AuthScope, Principal},
    config::Config,
    crypto::SecretCipher,
    error::{AppError, AppResult},
    events::{EventBus, EventSource, MailEvent},
    models::{LABEL_DRAFT, LABEL_INBOX, LABEL_SENT, LABEL_UNREAD},
    net_guard::{
        UrlGuardOptions, build_pinned_http_client, validate_and_pin_url, validate_url_static,
    },
    search::{SearchQuery, matches_message, parse_query, try_parse_query},
    storage::{
        InboxRule, InboxRuleActions, InboxRulePatch, InboxRuleView, MailStore, MessageListQuery,
        NewInboxRule, NewLabelInput, StoredMessage, normalize_inbox_rule_actions,
        parse_simple_email_address, validate_and_normalize_contact_email,
    },
};

type HmacSha256 = Hmac<Sha256>;

/// HTTP header carrying the HMAC-SHA256 signature (`sha256=<hex>`) when `webhook_secret` is set.
pub const WEBHOOK_SIGNATURE_HEADER: &str = "X-Nogml-Signature";
/// HTTP header identifying the webhook event type (`rule.matched`).
pub const WEBHOOK_EVENT_HEADER: &str = "X-Nogml-Event";
/// Event name placed in the JSON envelope and `X-Nogml-Event` header.
pub const RULE_MATCHED_EVENT: &str = "rule.matched";

const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);
const WEBHOOK_RETRY_BACKOFF_MS: [u64; 2] = [100, 300];
const WEBHOOK_BODY_MAX_CHARS: usize = 1000;
const MAX_RULE_NAME_LEN: usize = 200;
const MAX_RULE_LABEL_LEN: usize = 256;
const DEFAULT_TEST_LIMIT: usize = 20;
const MAX_TEST_LIMIT: usize = 100;

/// Compact match summary entry returned by `POST /v1/rules/{id}/test`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleTestMatchedMessage {
    pub id: String,
    pub thread_id: String,
    pub from: String,
    pub subject: String,
    pub snippet: String,
}

/// Compute `sha256=<lowercase-hex>` HMAC-SHA256 signature for a webhook payload body.
pub fn compute_webhook_signature(secret: &str, body: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC-SHA256 accepts any key length");
    mac.update(body);
    let digest = mac.finalize().into_bytes();
    format!("sha256={}", hex_encode(&digest))
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

fn has_control_chars(s: &str) -> bool {
    s.bytes().any(|b| b <= 0x1f || b == 0x7f) || s.chars().any(char::is_control)
}

/// Validate an inbox rule's display name.
pub fn validate_rule_name(name: &str) -> AppResult<String> {
    if has_control_chars(name) {
        return Err(AppError::validation(
            "Rule name contains disallowed control characters",
            None,
        ));
    }
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(AppError::validation(
            "Rule name must not be empty",
            Some("Provide a descriptive name for the inbox rule.".to_string()),
        ));
    }
    if trimmed.chars().count() > MAX_RULE_NAME_LEN {
        return Err(AppError::validation(
            format!("Rule name exceeds maximum length of {MAX_RULE_NAME_LEN} characters"),
            None,
        ));
    }
    Ok(trimmed.to_string())
}

/// Validate a Gmail-style `match_query` expression and parse it with [`crate::search::parse_query`].
///
/// An empty query is accepted only when `vip_only` is `true` (matching all VIP senders).
/// Unbalanced quotes, parentheses, braces, dangling `OR` / `-` operators, empty operator values,
/// and control characters are rejected with `400 Validation`.
pub fn validate_match_query(raw: &str, vip_only: bool) -> AppResult<SearchQuery> {
    if has_control_chars(raw) {
        return Err(AppError::validation(
            "match_query contains disallowed control characters",
            None,
        ));
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        if vip_only {
            return Ok(parse_query(""));
        }
        return Err(AppError::validation(
            "match_query must not be empty unless vip_only is true",
            Some(
                "Provide a Gmail search query such as 'from:@stripe.com subject:dispute', or set vip_only: true."
                    .to_string(),
            ),
        ));
    }

    // Validate balanced quotes, parentheses, braces, and well-formed operator tokens.
    let chars: Vec<char> = trimmed.chars().collect();
    let len = chars.len();
    let mut i = 0usize;
    let mut stack: Vec<char> = Vec::new();
    let mut last_was_or = false;
    let mut last_was_minus = false;
    let mut saw_term_in_group: Vec<bool> = vec![false];

    while i < len {
        let ch = chars[i];
        if ch.is_whitespace() {
            if last_was_minus {
                return Err(AppError::validation(
                    "Invalid match_query: dangling '-' negation operator",
                    Some(
                        "Attach '-' directly to a search term such as '-from:spam.com'."
                            .to_string(),
                    ),
                ));
            }
            i += 1;
            continue;
        }

        match ch {
            '"' => {
                i += 1;
                let mut closed = false;
                while i < len {
                    if chars[i] == '\\' && i + 1 < len && matches!(chars[i + 1], '"' | '\\') {
                        i += 2;
                    } else if chars[i] == '"' {
                        i += 1;
                        closed = true;
                        break;
                    } else {
                        i += 1;
                    }
                }
                if !closed {
                    return Err(AppError::validation(
                        "Invalid match_query: unclosed double quote",
                        Some("Close all quoted phrases with a matching '\"'.".to_string()),
                    ));
                }
                last_was_or = false;
                last_was_minus = false;
                if let Some(flag) = saw_term_in_group.last_mut() {
                    *flag = true;
                }
            }
            '(' | '{' => {
                stack.push(ch);
                saw_term_in_group.push(false);
                last_was_or = false;
                last_was_minus = false;
                i += 1;
            }
            ')' | '}' => {
                let expected = if ch == ')' { '(' } else { '{' };
                if stack.pop() != Some(expected) {
                    return Err(AppError::validation(
                        format!("Invalid match_query: unmatched closing '{ch}'"),
                        Some("Ensure all parentheses and braces are balanced.".to_string()),
                    ));
                }
                if last_was_or || last_was_minus {
                    return Err(AppError::validation(
                        format!("Invalid match_query: dangling operator before '{ch}'"),
                        None,
                    ));
                }
                let had_term = saw_term_in_group.pop().unwrap_or(false);
                if !had_term {
                    return Err(AppError::validation(
                        "Invalid match_query: empty group",
                        Some("Provide at least one search term inside every group.".to_string()),
                    ));
                }
                if let Some(flag) = saw_term_in_group.last_mut() {
                    *flag = true;
                }
                i += 1;
            }
            '-' => {
                if i + 1 >= len || chars[i + 1].is_whitespace() || matches!(chars[i + 1], ')' | '}')
                {
                    return Err(AppError::validation(
                        "Invalid match_query: dangling '-' negation operator",
                        Some(
                            "Attach '-' directly to a search term such as '-from:spam.com'."
                                .to_string(),
                        ),
                    ));
                }
                last_was_minus = true;
                last_was_or = false;
                i += 1;
            }
            _ => {
                let start = i;
                let mut colon_pos: Option<usize> = None;
                while i < len
                    && !chars[i].is_whitespace()
                    && !matches!(chars[i], '(' | ')' | '{' | '}')
                {
                    if chars[i] == ':' && colon_pos.is_none() {
                        colon_pos = Some(i);
                        i += 1;
                        if i < len && chars[i] == '"' {
                            i += 1;
                            let mut closed = false;
                            while i < len {
                                if chars[i] == '\\'
                                    && i + 1 < len
                                    && matches!(chars[i + 1], '"' | '\\')
                                {
                                    i += 2;
                                } else if chars[i] == '"' {
                                    i += 1;
                                    closed = true;
                                    break;
                                } else {
                                    i += 1;
                                }
                            }
                            if !closed {
                                return Err(AppError::validation(
                                    "Invalid match_query: unclosed double quote in operator value",
                                    Some(
                                        "Close all quoted operator values with a matching '\"'."
                                            .to_string(),
                                    ),
                                ));
                            }
                            break;
                        }
                    } else if chars[i] == '"' {
                        return Err(AppError::validation(
                            "Invalid match_query: unexpected quote inside token",
                            None,
                        ));
                    } else {
                        i += 1;
                    }
                }
                let word: String = chars[start..i].iter().collect();
                if let Some(cpos) = colon_pos {
                    let key_empty = cpos == start;
                    let val_empty = cpos + 1 >= i;
                    if key_empty || val_empty {
                        return Err(AppError::validation(
                            format!("Invalid match_query: incomplete operator '{word}'"),
                            Some(
                                "Provide both operator name and value, e.g. 'from:@stripe.com'."
                                    .to_string(),
                            ),
                        ));
                    }
                }
                if word == "OR" {
                    let group_has_term = saw_term_in_group.last().copied().unwrap_or(false);
                    if !group_has_term || last_was_or || last_was_minus {
                        return Err(AppError::validation(
                            "Invalid match_query: misplaced 'OR' operator",
                            Some(
                                "Place 'OR' between two search terms, e.g. 'from:a@x.com OR from:b@x.com'."
                                    .to_string(),
                            ),
                        ));
                    }
                    last_was_or = true;
                } else {
                    last_was_or = false;
                    last_was_minus = false;
                    if let Some(flag) = saw_term_in_group.last_mut() {
                        *flag = true;
                    }
                }
            }
        }
    }

    if let Some(unclosed) = stack.pop() {
        return Err(AppError::validation(
            format!("Invalid match_query: unclosed '{unclosed}'"),
            Some("Ensure all parentheses and braces are balanced.".to_string()),
        ));
    }
    if last_was_or || last_was_minus {
        return Err(AppError::validation(
            "Invalid match_query: trailing operator",
            None,
        ));
    }

    let parsed = try_parse_query(trimmed)?;
    if parsed.terms.is_empty() {
        return Err(AppError::validation(
            "Invalid match_query: query produced no searchable terms",
            Some(
                "Provide a valid Gmail query such as 'from:@stripe.com subject:dispute'."
                    .to_string(),
            ),
        ));
    }
    Ok(parsed)
}

/// Runtime SSRF and host-allowlist policy applied to inbox rule webhooks.
#[derive(Debug, Clone, Default)]
pub struct RuleWebhookPolicy {
    pub allow_private_endpoints: bool,
    pub allowed_hosts: Vec<String>,
}

impl RuleWebhookPolicy {
    /// Build a [`RuleWebhookPolicy`] from application [`Config`].
    pub fn from_config(config: &Config) -> Self {
        Self {
            allow_private_endpoints: config.allow_private_endpoints,
            allowed_hosts: config.webhook_allowed_hosts.clone(),
        }
    }
}

/// Validate a rule webhook URL with strict production SSRF rules (HTTPS-only,
/// globally routable host, no embedded credentials).
pub fn validate_webhook_url(raw: &str) -> AppResult<String> {
    validate_webhook_url_with_policy(raw, &RuleWebhookPolicy::default())
}

/// Validate a rule webhook URL under the given [`RuleWebhookPolicy`].
pub fn validate_webhook_url_with_policy(
    raw: &str,
    policy: &RuleWebhookPolicy,
) -> AppResult<String> {
    if has_control_chars(raw) {
        return Err(AppError::validation(
            "webhook_url contains disallowed control characters",
            None,
        ));
    }
    let trimmed = raw.trim();
    validate_url_static(
        trimmed,
        UrlGuardOptions {
            allow_private_endpoints: policy.allow_private_endpoints,
            allow_http: policy.allow_private_endpoints,
            allowed_hosts: &policy.allowed_hosts,
            context: "webhook_url",
        },
    )?;
    Ok(trimmed.to_string())
}

fn validate_label_token(label: &str) -> AppResult<()> {
    if has_control_chars(label) {
        return Err(AppError::validation(
            "Rule label contains disallowed control characters",
            None,
        ));
    }
    if label.len() > MAX_RULE_LABEL_LEN {
        return Err(AppError::validation(
            format!("Rule label exceeds maximum length of {MAX_RULE_LABEL_LEN} bytes"),
            None,
        ));
    }
    Ok(())
}

/// Validate and normalize [`InboxRuleActions`] using strict production SSRF defaults.
pub fn validate_rule_actions(actions: &InboxRuleActions) -> AppResult<InboxRuleActions> {
    validate_rule_actions_with_policy(actions, &RuleWebhookPolicy::default())
}

/// Validate and normalize [`InboxRuleActions`] under the given [`RuleWebhookPolicy`].
pub fn validate_rule_actions_with_policy(
    actions: &InboxRuleActions,
    policy: &RuleWebhookPolicy,
) -> AppResult<InboxRuleActions> {
    let normalized = normalize_inbox_rule_actions(actions);
    for lbl in normalized
        .add_labels
        .iter()
        .chain(normalized.remove_labels.iter())
    {
        validate_label_token(lbl)?;
    }
    if let Some(ref url) = normalized.webhook_url {
        validate_webhook_url_with_policy(url, policy)?;
    }
    if let Some(ref secret) = normalized.webhook_secret
        && has_control_chars(secret)
    {
        return Err(AppError::validation(
            "webhook_secret contains disallowed control characters",
            None,
        ));
    }
    Ok(normalized)
}

/// Validate a [`NewInboxRule`] input before storing it using strict production SSRF defaults.
pub fn validate_new_inbox_rule(input: &NewInboxRule) -> AppResult<NewInboxRule> {
    validate_new_inbox_rule_with_policy(input, &RuleWebhookPolicy::default())
}

/// Validate a [`NewInboxRule`] input under the given [`RuleWebhookPolicy`].
pub fn validate_new_inbox_rule_with_policy(
    input: &NewInboxRule,
    policy: &RuleWebhookPolicy,
) -> AppResult<NewInboxRule> {
    let name = validate_rule_name(&input.name)?;
    validate_match_query(&input.match_query, input.vip_only)?;
    let actions = validate_rule_actions_with_policy(&input.actions, policy)?;
    Ok(NewInboxRule {
        name,
        enabled: input.enabled,
        match_query: input.match_query.trim().to_string(),
        vip_only: input.vip_only,
        actions,
    })
}

async fn is_sender_vip(store: &dyn MailStore, from_addr: &str) -> bool {
    let parsed = parse_simple_email_address(from_addr);
    let Ok((email, _)) = validate_and_normalize_contact_email(&parsed.email) else {
        return false;
    };
    match store.get_contact(&email).await {
        Ok(Some(contact)) => contact.is_vip,
        Ok(None) => false,
        Err(err) => {
            warn!(%err, sender = %email, "Failed to look up sender contact for vip_only inbox rule");
            false
        }
    }
}

fn rule_matches_query(rule: &InboxRule, msg: &StoredMessage) -> bool {
    let trimmed = rule.match_query.trim();
    if trimmed.is_empty() {
        return rule.vip_only;
    }
    let query = parse_query(trimmed);
    matches_message(&query, msg)
}

async fn ensure_labels_exist(store: &dyn MailStore, labels: &[String]) {
    if labels.is_empty() {
        return;
    }
    let existing = match store.list_labels().await {
        Ok(l) => l,
        Err(err) => {
            warn!(%err, "Failed to list labels while applying inbox rule");
            return;
        }
    };
    for wanted in labels {
        let found = existing
            .iter()
            .any(|l| l.id == *wanted || l.name.eq_ignore_ascii_case(wanted));
        if !found {
            match store
                .create_label(NewLabelInput {
                    name: wanted.clone(),
                    ..Default::default()
                })
                .await
            {
                Ok(_) | Err(AppError::Conflict(_)) => {}
                Err(err) => {
                    warn!(%err, label = %wanted, "Failed to auto-create custom label for inbox rule");
                }
            }
        }
    }
}

/// Evaluate all enabled per-mailbox inbox rules for a newly ingested inbound message.
///
/// - Skips messages carrying `SENT` or `DRAFT` labels.
/// - Applies label mutations (`add_labels`, `remove_labels`, `archive`, `mark_read`) via
///   `store.modify_message_labels(...)` and publishes `MailEvent::MessageUpdated`.
/// - Spawns bounded async webhook delivery tasks (10s timeout, up to 2 retries with short
///   backoff, HMAC-SHA256 `X-Nogml-Signature` header) for matching rules with `webhook_url`.
/// - Logs warnings on storage/webhook failures and NEVER fails message storage.
pub async fn evaluate_inbox_rules(
    store: &dyn MailStore,
    events: &EventBus,
    msg: &StoredMessage,
    untrusted_content_guard: bool,
) -> StoredMessage {
    evaluate_inbox_rules_with_policy(
        store,
        events,
        msg,
        untrusted_content_guard,
        &RuleWebhookPolicy::default(),
    )
    .await
}

/// Evaluate all enabled per-mailbox inbox rules for a newly ingested inbound message
/// using an explicit [`RuleWebhookPolicy`].
pub async fn evaluate_inbox_rules_with_policy(
    store: &dyn MailStore,
    events: &EventBus,
    msg: &StoredMessage,
    untrusted_content_guard: bool,
    webhook_policy: &RuleWebhookPolicy,
) -> StoredMessage {
    evaluate_inbox_rules_with_cipher(
        store,
        events,
        msg,
        untrusted_content_guard,
        webhook_policy,
        &SecretCipher::disabled(),
    )
    .await
}

/// Evaluate all enabled per-mailbox inbox rules for a newly ingested inbound message
/// using an explicit [`RuleWebhookPolicy`] and [`SecretCipher`] for decrypting stored
/// `webhook_secret` envelopes prior to HMAC-SHA256 signing.
pub async fn evaluate_inbox_rules_with_cipher(
    store: &dyn MailStore,
    events: &EventBus,
    msg: &StoredMessage,
    untrusted_content_guard: bool,
    webhook_policy: &RuleWebhookPolicy,
    cipher: &SecretCipher,
) -> StoredMessage {
    // Never fire inbox rules on outbound SENT or DRAFT messages.
    if msg
        .label_ids
        .iter()
        .any(|l| l == LABEL_SENT || l == LABEL_DRAFT)
    {
        return msg.clone();
    }

    let rules = match store.list_inbox_rules().await {
        Ok(r) => r,
        Err(err) => {
            warn!(%err, message_id = %msg.id, "Failed to load inbox rules; skipping rule evaluation");
            return msg.clone();
        }
    };

    let enabled_rules: Vec<InboxRule> = rules.into_iter().filter(|r| r.enabled).collect();
    if enabled_rules.is_empty() {
        return msg.clone();
    }

    let mut sender_vip_cache: Option<bool> = None;
    let mut matched_rules: Vec<InboxRule> = Vec::new();

    for rule in enabled_rules {
        if rule.vip_only {
            let is_vip = match sender_vip_cache {
                Some(v) => v,
                None => {
                    let v = is_sender_vip(store, &msg.from_addr).await;
                    sender_vip_cache = Some(v);
                    v
                }
            };
            if !is_vip {
                continue;
            }
        }

        if rule_matches_query(&rule, msg) {
            matched_rules.push(rule);
        }
    }

    if matched_rules.is_empty() {
        return msg.clone();
    }

    // Aggregate label mutations in rule creation order.
    let mut add_labels: Vec<String> = Vec::new();
    let mut remove_labels: Vec<String> = Vec::new();

    for rule in &matched_rules {
        for lbl in &rule.actions.add_labels {
            let trimmed = lbl.trim();
            if trimmed.is_empty() {
                continue;
            }
            remove_labels.retain(|r| !r.eq_ignore_ascii_case(trimmed));
            if !add_labels.iter().any(|a| a.eq_ignore_ascii_case(trimmed)) {
                add_labels.push(trimmed.to_string());
            }
        }
        for lbl in &rule.actions.remove_labels {
            let trimmed = lbl.trim();
            if trimmed.is_empty() {
                continue;
            }
            add_labels.retain(|a| !a.eq_ignore_ascii_case(trimmed));
            if !remove_labels
                .iter()
                .any(|r| r.eq_ignore_ascii_case(trimmed))
            {
                remove_labels.push(trimmed.to_string());
            }
        }
        if rule.actions.archive {
            add_labels.retain(|a| a != LABEL_INBOX);
            if !remove_labels.iter().any(|r| r == LABEL_INBOX) {
                remove_labels.push(LABEL_INBOX.to_string());
            }
        }
        if rule.actions.mark_read {
            add_labels.retain(|a| a != LABEL_UNREAD);
            if !remove_labels.iter().any(|r| r == LABEL_UNREAD) {
                remove_labels.push(LABEL_UNREAD.to_string());
            }
        }
    }

    let event_mailbox = if !events.mailbox_id().is_empty() {
        events.mailbox_id().to_string()
    } else {
        store.mailbox_id().to_string()
    };

    let mut current_msg = msg.clone();

    if !add_labels.is_empty() || !remove_labels.is_empty() {
        ensure_labels_exist(store, &add_labels).await;
        match store
            .modify_message_labels(&msg.id, &add_labels, &remove_labels)
            .await
        {
            Ok(updated) => {
                let added: Vec<String> = updated
                    .label_ids
                    .iter()
                    .filter(|l| !msg.label_ids.contains(l))
                    .cloned()
                    .collect();
                let removed: Vec<String> = msg
                    .label_ids
                    .iter()
                    .filter(|l| !updated.label_ids.contains(l))
                    .cloned()
                    .collect();
                if !added.is_empty() || !removed.is_empty() {
                    events.publish_for_mailbox(
                        &event_mailbox,
                        EventSource::System,
                        MailEvent::MessageUpdated {
                            message_id: updated.id.clone(),
                            thread_id: updated.thread_id.clone(),
                            added_labels: added,
                            removed_labels: removed,
                        },
                    );
                }
                current_msg = updated;
            }
            Err(err) => {
                warn!(
                    %err,
                    message_id = %msg.id,
                    "Failed to apply inbox rule label mutations; preserving stored message"
                );
            }
        }
    }

    // Spawn bounded async signed webhooks for matching rules with a webhook_url.
    let compact_cfg = Config {
        untrusted_content_guard,
        ..Config::default()
    };

    for rule in matched_rules {
        let Some(webhook_url) = rule
            .actions
            .webhook_url
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .map(str::to_string)
        else {
            continue;
        };

        let compact_message = to_compact_message(
            &current_msg,
            &compact_cfg,
            true,
            WEBHOOK_BODY_MAX_CHARS,
            true,
            false,
        );
        let payload = json!({
            "event": RULE_MATCHED_EVENT,
            "rule_id": rule.id,
            "rule_name": rule.name,
            "mailbox_id": event_mailbox,
            "message": compact_message,
        });

        let body_bytes = match serde_json::to_vec(&payload) {
            Ok(b) => b,
            Err(err) => {
                warn!(%err, rule_id = %rule.id, "Failed to serialize inbox rule webhook payload");
                continue;
            }
        };

        let signature = match rule
            .actions
            .webhook_secret
            .as_deref()
            .filter(|s| !s.is_empty())
        {
            Some(raw_secret) => match cipher.decrypt(raw_secret) {
                Ok(plain) if !plain.is_empty() => {
                    Some(compute_webhook_signature(&plain, &body_bytes))
                }
                Ok(_) => None,
                Err(err) => {
                    warn!(
                        %err,
                        rule_id = %rule.id,
                        rule_name = %rule.name,
                        mailbox_id = %event_mailbox,
                        "Failed to decrypt inbox rule webhook_secret; skipping unsigned webhook delivery"
                    );
                    continue;
                }
            },
            None => None,
        };

        spawn_rule_webhook(
            rule.id,
            rule.name,
            event_mailbox.clone(),
            webhook_url,
            body_bytes,
            signature,
            webhook_policy.clone(),
        );
    }

    current_msg
}

fn spawn_rule_webhook(
    rule_id: String,
    rule_name: String,
    mailbox_id: String,
    webhook_url: String,
    body_bytes: Vec<u8>,
    signature: Option<String>,
    webhook_policy: RuleWebhookPolicy,
) {
    tokio::spawn(async move {
        let pinned = match validate_and_pin_url(
            &webhook_url,
            UrlGuardOptions {
                allow_private_endpoints: webhook_policy.allow_private_endpoints,
                allow_http: webhook_policy.allow_private_endpoints,
                allowed_hosts: &webhook_policy.allowed_hosts,
                context: "inbox rule webhook",
            },
        )
        .await
        {
            Ok(p) => p,
            Err(err) => {
                warn!(
                    %err,
                    %rule_id,
                    %rule_name,
                    %mailbox_id,
                    "Blocked inbox rule webhook delivery by SSRF/allowlist policy"
                );
                return;
            }
        };

        let client = match build_pinned_http_client(
            &pinned,
            WEBHOOK_TIMEOUT,
            Some(Duration::from_secs(5)),
        ) {
            Ok(c) => c,
            Err(err) => {
                warn!(%err, %rule_id, %rule_name, %mailbox_id, "Failed to build HTTP client for inbox rule webhook");
                return;
            }
        };

        let total_attempts = 1 + WEBHOOK_RETRY_BACKOFF_MS.len();
        for attempt in 0..total_attempts {
            let mut req = client
                .post(pinned.url.as_str())
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header(WEBHOOK_EVENT_HEADER, RULE_MATCHED_EVENT)
                .body(body_bytes.clone());

            if let Some(ref sig) = signature {
                req = req.header(WEBHOOK_SIGNATURE_HEADER, sig);
            }

            match req.send().await {
                Ok(resp) if resp.status().is_success() => return,
                Ok(resp) if resp.status().is_redirection() => {
                    warn!(
                        status = %resp.status(),
                        %rule_id,
                        %rule_name,
                        %mailbox_id,
                        "Inbox rule webhook returned redirect; refusing to follow for SSRF protection"
                    );
                    return;
                }
                Ok(resp) => {
                    let status = resp.status();
                    let retryable = status.is_server_error()
                        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
                        || status == reqwest::StatusCode::REQUEST_TIMEOUT;
                    if !retryable || attempt + 1 >= total_attempts {
                        warn!(
                            status = %status,
                            attempts = attempt + 1,
                            %rule_id,
                            %rule_name,
                            %mailbox_id,
                            "Inbox rule webhook delivery failed with non-success status"
                        );
                        return;
                    }
                    warn!(
                        status = %status,
                        attempt = attempt + 1,
                        %rule_id,
                        "Inbox rule webhook returned retryable status; retrying"
                    );
                }
                Err(err) => {
                    if attempt + 1 >= total_attempts {
                        warn!(
                            %err,
                            attempts = attempt + 1,
                            %rule_id,
                            %rule_name,
                            %mailbox_id,
                            "Inbox rule webhook delivery failed after retries"
                        );
                        return;
                    }
                    warn!(
                        %err,
                        attempt = attempt + 1,
                        %rule_id,
                        "Inbox rule webhook request failed; retrying"
                    );
                }
            }

            if let Some(&delay_ms) = WEBHOOK_RETRY_BACKOFF_MS.get(attempt) {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        }
    });
}

// ============================================================================
// Shared Operations for REST `/v1/rules` and MCP Tools
// ============================================================================

/// List all inbox rules in the active mailbox (with `webhook_secret` redacted).
pub async fn execute_list_rules(state: &AppState) -> AppResult<Value> {
    let rules: Vec<InboxRuleView> = state
        .store
        .list_inbox_rules()
        .await?
        .into_iter()
        .map(InboxRuleView::from)
        .collect();
    let count = rules.len();
    Ok(json!({
        "rules": rules,
        "count": count,
    }))
}

/// Validate and create a new inbox rule in the active mailbox (returning redacted view).
pub async fn execute_create_rule_with_context(
    state: &AppState,
    input: NewInboxRule,
    principal: Option<Principal>,
    source: EventSource,
) -> AppResult<Value> {
    let sets_webhook = input
        .actions
        .webhook_url
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty())
        || input
            .actions
            .webhook_secret
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty());
    if sets_webhook && let Some(ref p) = principal {
        p.require_scope(AuthScope::Admin)?;
    }

    let policy = RuleWebhookPolicy::from_config(&state.config);
    let mut validated = validate_new_inbox_rule_with_policy(&input, &policy)?;
    if let Some(ref secret) = validated.actions.webhook_secret
        && !secret.is_empty()
    {
        validated.actions.webhook_secret = Some(state.cipher.encrypt(secret)?);
    }
    let created = state.store.create_inbox_rule(&validated).await?;
    state
        .record_audit(
            principal.as_ref(),
            channel_for_source(source),
            "create_rule",
            vec![created.id.clone()],
            "ok",
            Some(created.name.clone()),
        )
        .await;
    Ok(serde_json::to_value(created.to_view())?)
}

/// Validate and partially update an existing inbox rule (returning redacted view).
pub async fn execute_patch_rule_with_context(
    state: &AppState,
    id: &str,
    mut patch: InboxRulePatch,
    principal: Option<Principal>,
    source: EventSource,
) -> AppResult<Value> {
    validate_resource_id(id)?;
    let existing = state
        .store
        .get_inbox_rule(id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Inbox rule '{id}' not found")))?;

    let existing_plain_secret = existing
        .actions
        .webhook_secret
        .as_deref()
        .and_then(|s| state.cipher.decrypt(s).ok());
    let touches_webhook = patch.actions.as_ref().is_some_and(|actions| {
        let normalized = normalize_inbox_rule_actions(actions);
        normalized.webhook_url != existing.actions.webhook_url
            || normalized.webhook_secret != existing_plain_secret
    });
    let modifies_webhook_rule_trigger = existing.actions.webhook_url.is_some()
        && (patch.match_query.is_some() || patch.vip_only.is_some() || patch.enabled.is_some());
    if (touches_webhook || modifies_webhook_rule_trigger)
        && let Some(ref p) = principal
    {
        p.require_scope(AuthScope::Admin)?;
    }

    if let Some(ref name) = patch.name {
        patch.name = Some(validate_rule_name(name)?);
    }

    let next_vip_only = patch.vip_only.unwrap_or(existing.vip_only);
    let next_query = patch
        .match_query
        .as_deref()
        .unwrap_or(existing.match_query.as_str());
    validate_match_query(next_query, next_vip_only)?;
    if let Some(ref q) = patch.match_query {
        patch.match_query = Some(q.trim().to_string());
    }

    let policy = RuleWebhookPolicy::from_config(&state.config);
    if let Some(ref actions) = patch.actions {
        let mut validated_actions = validate_rule_actions_with_policy(actions, &policy)?;
        if let Some(ref secret) = validated_actions.webhook_secret
            && !secret.is_empty()
        {
            validated_actions.webhook_secret = Some(state.cipher.encrypt(secret)?);
        }
        patch.actions = Some(validated_actions);
    }

    let updated = state.store.patch_inbox_rule(id, &patch).await?;
    state
        .record_audit(
            principal.as_ref(),
            channel_for_source(source),
            "patch_rule",
            vec![updated.id.clone()],
            "ok",
            Some(updated.name.clone()),
        )
        .await;
    Ok(serde_json::to_value(updated.to_view())?)
}

/// Delete an inbox rule by ID.
pub async fn execute_delete_rule_with_context(
    state: &AppState,
    id: &str,
    principal: Option<Principal>,
    source: EventSource,
) -> AppResult<Value> {
    validate_resource_id(id)?;
    state.store.delete_inbox_rule(id).await?;
    state
        .record_audit(
            principal.as_ref(),
            channel_for_source(source),
            "delete_rule",
            vec![id.to_string()],
            "ok",
            None,
        )
        .await;
    Ok(json!({
        "deleted": true,
        "id": id,
    }))
}

/// Dry-run an inbox rule against recent messages in the mailbox without mutating labels
/// or firing webhooks.
pub async fn execute_test_rule(
    state: &AppState,
    id: &str,
    limit: Option<usize>,
) -> AppResult<Value> {
    validate_resource_id(id)?;
    let rule = state
        .store
        .get_inbox_rule(id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Inbox rule '{id}' not found")))?;

    let effective_limit = limit.unwrap_or(DEFAULT_TEST_LIMIT).clamp(1, MAX_TEST_LIMIT);
    let parsed_query = parse_query(rule.match_query.trim());

    let page = state
        .store
        .list_messages(&MessageListQuery {
            include_spam_trash: parsed_query.include_spam_trash,
            max_results: effective_limit,
            ..Default::default()
        })
        .await?;

    let guard = state.config.untrusted_content_guard;
    let clean = |s: &str| -> String {
        if guard {
            sanitize_untrusted_text(s)
        } else {
            s.to_string()
        }
    };

    let mut vip_cache: HashMap<String, bool> = HashMap::new();
    let mut matched_messages = Vec::new();

    for msg in &page.messages {
        if msg
            .label_ids
            .iter()
            .any(|l| l == LABEL_SENT || l == LABEL_DRAFT)
        {
            continue;
        }

        if rule.vip_only {
            let parsed_from = parse_simple_email_address(&msg.from_addr);
            let is_vip = match validate_and_normalize_contact_email(&parsed_from.email) {
                Ok((email, _)) => {
                    if let Some(&cached) = vip_cache.get(&email) {
                        cached
                    } else {
                        let v = state
                            .store
                            .get_contact(&email)
                            .await?
                            .is_some_and(|c| c.is_vip);
                        vip_cache.insert(email, v);
                        v
                    }
                }
                Err(_) => false,
            };
            if !is_vip {
                continue;
            }
        }

        let matched = if rule.match_query.trim().is_empty() {
            rule.vip_only
        } else if crate::search::query_uses_filename(&parsed_query) && msg.raw_rfc2822.is_empty() {
            let mut hydrated = msg.clone();
            if let Ok(Some(full)) = state.store.get_message(&msg.id).await {
                hydrated.raw_rfc2822 = full.raw_rfc2822;
            }
            if hydrated.raw_rfc2822.is_empty()
                && let Ok(raw) = state.load_raw_rfc2822(&hydrated).await
            {
                hydrated.raw_rfc2822 = raw;
            }
            matches_message(&parsed_query, &hydrated)
        } else {
            matches_message(&parsed_query, msg)
        };

        if matched {
            matched_messages.push(RuleTestMatchedMessage {
                id: msg.id.clone(),
                thread_id: msg.thread_id.clone(),
                from: clean(&msg.from_addr),
                subject: clean(&msg.subject),
                snippet: clean(&msg.snippet),
            });
        }
    }

    let matched_count = matched_messages.len();
    Ok(json!({
        "rule_id": rule.id,
        "matched_count": matched_count,
        "matched_messages": matched_messages,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_query_validation_accepts_valid_gmail_queries() {
        assert!(validate_match_query("from:@stripe.com subject:dispute", false).is_ok());
        assert!(
            validate_match_query(r#"subject:"chargeback alert" has:attachment"#, false).is_ok()
        );
        assert!(
            validate_match_query("(from:@github.com OR from:@gitlab.com) -label:noise", false)
                .is_ok()
        );
        assert!(validate_match_query("{from:a@x.com from:b@x.com}", false).is_ok());
        assert!(validate_match_query("", true).is_ok());
    }

    #[test]
    fn match_query_validation_rejects_malformed_queries() {
        assert!(validate_match_query("", false).is_err());
        assert!(validate_match_query("   ", false).is_err());
        assert!(validate_match_query("subject:\"unclosed", false).is_err());
        assert!(validate_match_query("(from:alice@example.com", false).is_err());
        assert!(validate_match_query("from:alice@example.com)", false).is_err());
        assert!(validate_match_query("()", false).is_err());
        assert!(validate_match_query("OR from:alice@example.com", false).is_err());
        assert!(validate_match_query("from:alice@example.com OR", false).is_err());
        assert!(validate_match_query("from:", false).is_err());
        assert!(validate_match_query("-", false).is_err());
        assert!(validate_match_query("from:alice\n", false).is_err());
    }

    #[test]
    fn webhook_url_validation_enforces_https_and_ssrf_guards() {
        assert!(validate_webhook_url("https://hooks.example.com/nogml").is_ok());
        assert!(validate_webhook_url("http://127.0.0.1:8080/hook").is_err());
        assert!(validate_webhook_url("https://127.0.0.1/hook").is_err());
        assert!(validate_webhook_url("https://169.254.169.254/latest/meta-data").is_err());
        assert!(validate_webhook_url("https://10.0.0.1/hook").is_err());
        assert!(validate_webhook_url("https://[::1]/hook").is_err());
        assert!(validate_webhook_url("https://user:pass@hooks.example.com/hook").is_err());
        assert!(validate_webhook_url("http://hooks.example.com/hook").is_err());
        assert!(validate_webhook_url("ftp://example.com/hook").is_err());
        assert!(validate_webhook_url("javascript:alert(1)").is_err());
        assert!(validate_webhook_url("/relative/path").is_err());
        assert!(validate_webhook_url("https:///missing-host").is_err());

        // Dev/test policy allows local HTTP mock endpoints while respecting host allowlist.
        let dev_policy = RuleWebhookPolicy {
            allow_private_endpoints: true,
            allowed_hosts: vec![],
        };
        assert!(
            validate_webhook_url_with_policy("http://127.0.0.1:8080/hook", &dev_policy).is_ok()
        );

        let allowlist_policy = RuleWebhookPolicy {
            allow_private_endpoints: false,
            allowed_hosts: vec!["*.trusted.example".to_string()],
        };
        assert!(
            validate_webhook_url_with_policy("https://hooks.trusted.example/in", &allowlist_policy)
                .is_ok()
        );
        assert!(
            validate_webhook_url_with_policy("https://evil.example/in", &allowlist_policy).is_err()
        );
    }

    #[test]
    fn webhook_signature_matches_rfc2104_hmac_sha256() {
        let sig = compute_webhook_signature("my-secret", br#"{"event":"rule.matched"}"#);
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), "sha256=".len() + 64);
        // Deterministic for same secret + body, distinct for different secret.
        assert_eq!(
            sig,
            compute_webhook_signature("my-secret", br#"{"event":"rule.matched"}"#)
        );
        assert_ne!(
            sig,
            compute_webhook_signature("other-secret", br#"{"event":"rule.matched"}"#)
        );
    }
}
