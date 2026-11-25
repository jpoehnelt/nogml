//! RFC 8601 `Authentication-Results` header parser and policy filter (`AuthResultsFilter`).
//!
//! Fast, deterministic, zero-I/O filter that inspects SPF, DKIM, and DMARC
//! results and maps failures to `Reject`, `Spam`, `Mutate` (label tagging), or `Allow`.

use async_trait::async_trait;

use crate::{
    config::{AuthFailAction, Config},
    error::AppResult,
    filter::{FilterDecision, InboundFilter, InboundMessage},
};

/// Default label added when `AuthResultsFilter` triggers a `Tag` action.
pub const LABEL_AUTH_FAIL: &str = "AUTH_FAIL";

/// Parsed authentication outcome for a single mechanism (`spf`, `dkim`, or `dmarc`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthOutcome {
    Pass,
    Fail,
    SoftFail,
    #[default]
    None,
}

impl AuthOutcome {
    /// Merge multiple results for the same mechanism within one `Authentication-Results` header.
    ///
    /// A passing signature/check takes precedence over failures (e.g. dual DKIM signatures where
    /// the second signature passes), followed by `Fail`, `SoftFail`, and `None`.
    fn merge(self, other: Self) -> Self {
        use AuthOutcome::{Fail, None, Pass, SoftFail};
        match (self, other) {
            (Pass, _) | (_, Pass) => Pass,
            (Fail, _) | (_, Fail) => Fail,
            (SoftFail, _) | (_, SoftFail) => SoftFail,
            (None, None) => None,
        }
    }

    fn parse(raw: &str) -> Self {
        let cleaned = raw
            .trim()
            .trim_end_matches([';', ',', ')'])
            .to_ascii_lowercase();
        match cleaned.as_str() {
            "pass" => Self::Pass,
            "fail" | "hardfail" | "policy" => Self::Fail,
            "softfail" => Self::SoftFail,
            _ => Self::None,
        }
    }
}

/// Parsed SPF, DKIM, and DMARC outcomes extracted from an `Authentication-Results` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ParsedAuthResults {
    pub spf: AuthOutcome,
    pub dkim: AuthOutcome,
    pub dmarc: AuthOutcome,
}

/// Strip RFC 5322 comments `(...)` (including nested parentheses) and double-quoted strings
/// `"..."` so tokens inside comments or quoted reasons cannot spoof mechanism verdicts.
fn strip_comments_and_quotes(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut paren_depth: usize = 0;
    let mut in_quotes = false;

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '\\' {
                let _ = chars.next();
            } else if c == '"' {
                in_quotes = false;
            }
            continue;
        }
        if paren_depth > 0 {
            match c {
                '\\' => {
                    let _ = chars.next();
                }
                '(' => paren_depth += 1,
                ')' => paren_depth -= 1,
                _ => {}
            }
            continue;
        }

        match c {
            '(' => {
                paren_depth = 1;
                out.push(' ');
            }
            '"' => {
                in_quotes = true;
                out.push(' ');
            }
            _ => out.push(c),
        }
    }

    out
}

/// Parse an RFC 8601 `Authentication-Results` header value for `spf`, `dkim`, and `dmarc`.
pub fn parse_authentication_results(header: &str) -> ParsedAuthResults {
    let cleaned = strip_comments_and_quotes(header);
    let mut result = ParsedAuthResults::default();

    for clause in cleaned.split(';') {
        for token in clause.split_whitespace() {
            let Some((raw_key, raw_val)) = token.split_once('=') else {
                continue;
            };
            // RFC 8601 allows optional `/version` suffix on method names (e.g. `dkim/1=pass`).
            let method = raw_key
                .split('/')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let outcome = AuthOutcome::parse(raw_val);
            match method.as_str() {
                "spf" => result.spf = result.spf.merge(outcome),
                "dkim" => result.dkim = result.dkim.merge(outcome),
                "dmarc" => result.dmarc = result.dmarc.merge(outcome),
                _ => {}
            }
        }
    }

    result
}

/// Configurable policy mapping SPF, DKIM, and DMARC failures to filter actions.
#[derive(Debug, Clone)]
pub struct AuthResultsPolicy {
    pub dmarc_fail_action: AuthFailAction,
    pub spf_fail_action: AuthFailAction,
    /// Optional explicit action for `spf=softfail`. When `None`, downgrades `Reject`/`Spam`
    /// to `Tag` while preserving `Allow`.
    pub spf_softfail_action: Option<AuthFailAction>,
    pub dkim_fail_action: AuthFailAction,
    pub fail_label: String,
}

impl Default for AuthResultsPolicy {
    fn default() -> Self {
        Self {
            dmarc_fail_action: AuthFailAction::Spam,
            spf_fail_action: AuthFailAction::Tag,
            spf_softfail_action: None,
            dkim_fail_action: AuthFailAction::Tag,
            fail_label: LABEL_AUTH_FAIL.to_string(),
        }
    }
}

impl AuthResultsPolicy {
    pub fn from_config(config: &Config) -> Self {
        Self {
            dmarc_fail_action: config.filter_dmarc_fail_action,
            spf_fail_action: config.filter_spf_fail_action,
            spf_softfail_action: None,
            dkim_fail_action: config.filter_dkim_fail_action,
            fail_label: LABEL_AUTH_FAIL.to_string(),
        }
    }

    fn effective_spf_softfail_action(&self) -> AuthFailAction {
        if let Some(explicit) = self.spf_softfail_action {
            return explicit;
        }
        match self.spf_fail_action {
            AuthFailAction::Allow => AuthFailAction::Allow,
            AuthFailAction::Tag | AuthFailAction::Spam | AuthFailAction::Reject => {
                AuthFailAction::Tag
            }
        }
    }
}

/// Deterministic `InboundFilter` that parses `Authentication-Results` headers
/// and enforces configured SPF/DKIM/DMARC failure policies.
#[derive(Debug, Clone, Default)]
pub struct AuthResultsFilter {
    policy: AuthResultsPolicy,
}

impl AuthResultsFilter {
    pub fn new(policy: AuthResultsPolicy) -> Self {
        Self { policy }
    }

    pub fn from_config(config: &Config) -> Self {
        Self::new(AuthResultsPolicy::from_config(config))
    }

    pub fn policy(&self) -> &AuthResultsPolicy {
        &self.policy
    }
}

#[async_trait]
impl InboundFilter for AuthResultsFilter {
    async fn evaluate(&self, msg: &InboundMessage) -> AppResult<FilterDecision> {
        let header_value = msg
            .authentication_results
            .as_deref()
            .or_else(|| msg.header("Authentication-Results"))
            .map(str::trim)
            .filter(|v| !v.is_empty());

        let Some(raw) = header_value else {
            return Ok(FilterDecision::Allow);
        };

        let parsed = parse_authentication_results(raw);
        let mut reject_reasons: Vec<&'static str> = Vec::new();
        let mut spam_reasons: Vec<&'static str> = Vec::new();
        let mut spam_score: f32 = 0.0;
        let mut should_tag = false;

        let checks: [(bool, AuthFailAction, &'static str, f32); 4] = [
            (
                parsed.dmarc == AuthOutcome::Fail,
                self.policy.dmarc_fail_action,
                "dmarc=fail",
                8.0,
            ),
            (
                parsed.spf == AuthOutcome::Fail,
                self.policy.spf_fail_action,
                "spf=fail",
                6.0,
            ),
            (
                parsed.spf == AuthOutcome::SoftFail,
                self.policy.effective_spf_softfail_action(),
                "spf=softfail",
                3.0,
            ),
            (
                parsed.dkim == AuthOutcome::Fail,
                self.policy.dkim_fail_action,
                "dkim=fail",
                5.0,
            ),
        ];

        for (triggered, action, reason, score_weight) in checks {
            if !triggered {
                continue;
            }
            match action {
                AuthFailAction::Allow => {}
                AuthFailAction::Tag => should_tag = true,
                AuthFailAction::Spam => {
                    spam_reasons.push(reason);
                    spam_score += score_weight;
                }
                AuthFailAction::Reject => {
                    reject_reasons.push(reason);
                }
            }
        }

        if !reject_reasons.is_empty() {
            return Ok(FilterDecision::Reject {
                reason: format!(
                    "Authentication-Results check failed ({})",
                    reject_reasons.join(", ")
                ),
            });
        }

        if !spam_reasons.is_empty() {
            return Ok(FilterDecision::Spam {
                score: spam_score,
                reason: format!(
                    "Authentication-Results check failed ({})",
                    spam_reasons.join(", ")
                ),
            });
        }

        if should_tag {
            return Ok(FilterDecision::Mutate {
                add_labels: vec![self.policy.fail_label.clone()],
                remove_labels: Vec::new(),
                skip_inbox: false,
            });
        }

        Ok(FilterDecision::Allow)
    }

    fn backend_name(&self) -> &'static str {
        "auth_results"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg_with_auth_header(value: &str) -> InboundMessage {
        InboundMessage {
            authentication_results: Some(value.to_string()),
            ..InboundMessage::default()
        }
    }

    #[test]
    fn parses_real_world_rfc8601_header_ignoring_comments() {
        let header = "mx.google.com;\r\n\t\
            dkim=pass (comment claiming spf=fail dmarc=fail) header.i=@example.com header.s=2024;\r\n\t\
            spf=pass (google.com: domain of a@example.com designates 1.2.3.4) smtp.mailfrom=a@example.com;\r\n\t\
            dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com";
        let parsed = parse_authentication_results(header);
        assert_eq!(parsed.spf, AuthOutcome::Pass);
        assert_eq!(parsed.dkim, AuthOutcome::Pass);
        assert_eq!(parsed.dmarc, AuthOutcome::Pass);
    }

    #[test]
    fn parses_dual_dkim_pass_over_fail_and_softfail() {
        let header = "mx.example.com; dkim=fail header.d=old.example; dkim=pass header.d=new.example; spf=softfail; dmarc=none";
        let parsed = parse_authentication_results(header);
        assert_eq!(parsed.dkim, AuthOutcome::Pass);
        assert_eq!(parsed.spf, AuthOutcome::SoftFail);
        assert_eq!(parsed.dmarc, AuthOutcome::None);
    }

    #[tokio::test]
    async fn missing_header_and_all_pass_allow() {
        let filter = AuthResultsFilter::default();
        assert_eq!(filter.backend_name(), "auth_results");

        let missing = filter.evaluate(&InboundMessage::default()).await.unwrap();
        assert_eq!(missing, FilterDecision::Allow);

        let pass = filter
            .evaluate(&msg_with_auth_header(
                "mx.example.com; spf=pass; dkim=pass; dmarc=pass",
            ))
            .await
            .unwrap();
        assert_eq!(pass, FilterDecision::Allow);
    }

    #[tokio::test]
    async fn reads_from_headers_vec_when_authentication_results_field_is_none() {
        let filter = AuthResultsFilter::default();
        let msg = InboundMessage {
            headers: vec![(
                "authentication-results".to_string(),
                "mx.example.com; spf=pass; dkim=pass; dmarc=fail".to_string(),
            )],
            ..InboundMessage::default()
        };
        let decision = filter.evaluate(&msg).await.unwrap();
        assert!(matches!(decision, FilterDecision::Spam { .. }));
    }

    #[tokio::test]
    async fn spf_dkim_dmarc_fail_and_softfail_policy_combinations() {
        // Default policy: dmarc=fail -> Spam, spf=fail -> Tag, spf=softfail -> Tag, dkim=fail -> Tag
        let default_filter = AuthResultsFilter::default();

        let dmarc_fail = default_filter
            .evaluate(&msg_with_auth_header(
                "mx.example.com; spf=pass; dkim=pass; dmarc=fail",
            ))
            .await
            .unwrap();
        assert!(matches!(
            dmarc_fail,
            FilterDecision::Spam { score, ref reason }
                if score >= 8.0 && reason.contains("dmarc=fail")
        ));

        let spf_softfail = default_filter
            .evaluate(&msg_with_auth_header(
                "mx.example.com; spf=softfail; dkim=pass; dmarc=pass",
            ))
            .await
            .unwrap();
        assert_eq!(
            spf_softfail,
            FilterDecision::Mutate {
                add_labels: vec![LABEL_AUTH_FAIL.to_string()],
                remove_labels: vec![],
                skip_inbox: false,
            }
        );

        let dkim_fail = default_filter
            .evaluate(&msg_with_auth_header(
                "mx.example.com; spf=pass; dkim=fail; dmarc=none",
            ))
            .await
            .unwrap();
        assert_eq!(
            dkim_fail,
            FilterDecision::Mutate {
                add_labels: vec![LABEL_AUTH_FAIL.to_string()],
                remove_labels: vec![],
                skip_inbox: false,
            }
        );

        // Strict policy: dmarc=fail -> Reject overrides spf=fail -> Spam
        let strict_filter = AuthResultsFilter::new(AuthResultsPolicy {
            dmarc_fail_action: AuthFailAction::Reject,
            spf_fail_action: AuthFailAction::Spam,
            spf_softfail_action: None,
            dkim_fail_action: AuthFailAction::Tag,
            fail_label: LABEL_AUTH_FAIL.to_string(),
        });

        let both_fail = strict_filter
            .evaluate(&msg_with_auth_header(
                "mx.example.com; spf=fail; dkim=fail; dmarc=fail",
            ))
            .await
            .unwrap();
        assert!(matches!(
            both_fail,
            FilterDecision::Reject { ref reason } if reason.contains("dmarc=fail")
        ));

        let spf_only_fail = strict_filter
            .evaluate(&msg_with_auth_header(
                "mx.example.com; spf=fail; dkim=pass; dmarc=pass",
            ))
            .await
            .unwrap();
        assert!(matches!(
            spf_only_fail,
            FilterDecision::Spam { ref reason, .. } if reason.contains("spf=fail")
        ));

        // Softfail downgrades Spam to Tag unless explicitly overridden
        let spf_softfail_downgraded = strict_filter
            .evaluate(&msg_with_auth_header(
                "mx.example.com; spf=softfail; dkim=pass; dmarc=pass",
            ))
            .await
            .unwrap();
        assert_eq!(
            spf_softfail_downgraded,
            FilterDecision::Mutate {
                add_labels: vec![LABEL_AUTH_FAIL.to_string()],
                remove_labels: vec![],
                skip_inbox: false,
            }
        );

        // Permissive policy: all Allow
        let allow_filter = AuthResultsFilter::new(AuthResultsPolicy {
            dmarc_fail_action: AuthFailAction::Allow,
            spf_fail_action: AuthFailAction::Allow,
            spf_softfail_action: None,
            dkim_fail_action: AuthFailAction::Allow,
            fail_label: LABEL_AUTH_FAIL.to_string(),
        });
        let allowed = allow_filter
            .evaluate(&msg_with_auth_header(
                "mx.example.com; spf=fail; dkim=fail; dmarc=fail",
            ))
            .await
            .unwrap();
        assert_eq!(allowed, FilterDecision::Allow);
    }
}
