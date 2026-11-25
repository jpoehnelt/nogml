//! Pluggable inbound message filtering (`InboundFilter`, `NoopFilter`, `FilterChain`,
//! `AuthResultsFilter`, `RspamdFilter`, and `LlmTriageFilter`).
//!
//! Provider-agnostic hook executed across all inbound ingestion paths:
//! - Resend `email.received` webhooks
//! - Gmail REST `messages.import`
//! - Upstream Gmail sync (`gmail_api` and `gmail_imap`)
//! - Embedded IMAP `APPEND`

pub mod auth_results;
pub mod llm;
pub mod rspamd;

use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    config::Config,
    error::AppResult,
    models::{LABEL_INBOX, LABEL_SPAM, LABEL_UNREAD},
};

pub use auth_results::{
    AuthOutcome, AuthResultsFilter, AuthResultsPolicy, LABEL_AUTH_FAIL, ParsedAuthResults,
    parse_authentication_results,
};
pub use llm::{LlmTriageConfig, LlmTriageFilter};
pub use rspamd::{RspamdConfig, RspamdFilter};

/// Provider-agnostic inbound message view passed to [`InboundFilter`] implementations
/// before persistence into `MailStore`.
#[derive(Debug, Clone, Default)]
pub struct InboundMessage {
    pub raw_rfc2822: Vec<u8>,
    pub headers: Vec<(String, String)>,
    pub text_body: String,
    pub html_body: Option<String>,
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub authentication_results: Option<String>,
    pub sender_ip: Option<String>,
    pub source: String,
    pub provider_id: Option<String>,
}

impl InboundMessage {
    /// Case-insensitive lookup for the first matching header value.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Action returned by an [`InboundFilter`] for a candidate inbound email.
#[derive(Debug, Clone, PartialEq)]
pub enum FilterDecision {
    /// Accept the message with its default labels (`INBOX`, `UNREAD`).
    Allow,
    /// Route the message to `SPAM` (removing `INBOX`).
    Spam { score: f32, reason: String },
    /// Drop the message before storing in `MailStore`.
    Reject { reason: String },
    /// Accept the message with label mutations and optional `skip_inbox` (archive).
    Mutate {
        add_labels: Vec<String>,
        remove_labels: Vec<String>,
        skip_inbox: bool,
    },
}

/// Pluggable inbound filtering / spam / routing hook executed prior to storage.
#[async_trait]
pub trait InboundFilter: Send + Sync {
    async fn evaluate(&self, msg: &InboundMessage) -> AppResult<FilterDecision>;

    fn backend_name(&self) -> &'static str {
        "custom"
    }

    /// Active filter backend names in execution order.
    ///
    /// Leaf filters return `[self.backend_name()]`; [`FilterChain`] expands to its
    /// member filters in order.
    fn active_filters(&self) -> Vec<String> {
        vec![self.backend_name().to_string()]
    }
}

/// Apply a [`FilterDecision`] onto an initial label set.
///
/// If `initial_labels` is empty, defaults to `[INBOX, UNREAD]` before applying mutations.
pub fn apply_filter_labels(initial_labels: Vec<String>, decision: &FilterDecision) -> Vec<String> {
    let mut labels = if initial_labels.is_empty() {
        vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()]
    } else {
        initial_labels
    };

    match decision {
        FilterDecision::Allow | FilterDecision::Reject { .. } => {}
        FilterDecision::Spam { .. } => {
            labels.retain(|l| l != LABEL_INBOX);
            if !labels.iter().any(|l| l == LABEL_SPAM) {
                labels.push(LABEL_SPAM.to_string());
            }
        }
        FilterDecision::Mutate {
            add_labels,
            remove_labels,
            skip_inbox,
        } => {
            if *skip_inbox {
                labels.retain(|l| l != LABEL_INBOX);
            }
            if !remove_labels.is_empty() {
                labels.retain(|l| !remove_labels.contains(l));
            }
            for add in add_labels {
                if !labels.contains(add) {
                    labels.push(add.clone());
                }
            }
        }
    }

    labels
}

/// Default filter that allows all messages unchanged.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopFilter;

#[async_trait]
impl InboundFilter for NoopFilter {
    async fn evaluate(&self, _msg: &InboundMessage) -> AppResult<FilterDecision> {
        Ok(FilterDecision::Allow)
    }

    fn backend_name(&self) -> &'static str {
        "noop"
    }
}

/// Ordered chain of [`InboundFilter`]s.
///
/// Short-circuits immediately on `Reject` or `Spam`, and accumulates `Mutate`
/// label changes and `skip_inbox` across filters.
#[derive(Clone, Default)]
pub struct FilterChain(pub Vec<Arc<dyn InboundFilter>>);

impl FilterChain {
    pub fn new(filters: Vec<Arc<dyn InboundFilter>>) -> Self {
        Self(filters)
    }

    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn push(&mut self, filter: Arc<dyn InboundFilter>) {
        self.0.push(filter);
    }

    /// Active filter names in deterministic execution order.
    pub fn active_filter_names(&self) -> Vec<String> {
        if self.0.is_empty() {
            return vec!["noop".to_string()];
        }
        self.0.iter().flat_map(|f| f.active_filters()).collect()
    }
}

/// Build the configured [`InboundFilter`] pipeline from [`Config`] in deterministic order:
/// 1. Fast deterministic [`AuthResultsFilter`] (when `filter_auth_results = true`)
/// 2. External [`RspamdFilter`] (when `rspamd_url` is set)
/// 3. Optional [`LlmTriageFilter`] (when `llm_triage_base_url` or `llm_triage_api_key` is set)
///
/// Falls back to [`NoopFilter`] when no filters are enabled.
pub fn open_filter(config: &Config) -> Arc<dyn InboundFilter> {
    let mut filters: Vec<Arc<dyn InboundFilter>> = Vec::new();

    if config.filter_auth_results {
        filters.push(Arc::new(AuthResultsFilter::from_config(config)));
    }
    if let Some(rspamd) = RspamdFilter::from_config(config) {
        filters.push(Arc::new(rspamd));
    }
    if let Some(llm) = LlmTriageFilter::from_config(config) {
        filters.push(Arc::new(llm));
    }

    if filters.is_empty() {
        Arc::new(NoopFilter)
    } else {
        Arc::new(FilterChain::new(filters))
    }
}

#[async_trait]
impl InboundFilter for FilterChain {
    async fn evaluate(&self, msg: &InboundMessage) -> AppResult<FilterDecision> {
        let mut any_mutated = false;
        let mut add_labels: Vec<String> = Vec::new();
        let mut remove_labels: Vec<String> = Vec::new();
        let mut skip_inbox = false;

        for filter in &self.0 {
            match filter.evaluate(msg).await? {
                FilterDecision::Allow => {}
                decision @ (FilterDecision::Reject { .. } | FilterDecision::Spam { .. }) => {
                    return Ok(decision);
                }
                FilterDecision::Mutate {
                    add_labels: adds,
                    remove_labels: removes,
                    skip_inbox: skip,
                } => {
                    any_mutated = true;
                    skip_inbox |= skip;
                    for label in adds {
                        remove_labels.retain(|l| l != &label);
                        if !add_labels.contains(&label) {
                            add_labels.push(label);
                        }
                    }
                    for label in removes {
                        add_labels.retain(|l| l != &label);
                        if !remove_labels.contains(&label) {
                            remove_labels.push(label);
                        }
                    }
                }
            }
        }

        if any_mutated {
            Ok(FilterDecision::Mutate {
                add_labels,
                remove_labels,
                skip_inbox,
            })
        } else {
            Ok(FilterDecision::Allow)
        }
    }

    fn backend_name(&self) -> &'static str {
        "chain"
    }

    fn active_filters(&self) -> Vec<String> {
        self.active_filter_names()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct StaticFilter {
        decision: FilterDecision,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl InboundFilter for StaticFilter {
        async fn evaluate(&self, _msg: &InboundMessage) -> AppResult<FilterDecision> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.decision.clone())
        }
    }

    #[tokio::test]
    async fn noop_filter_allows() {
        assert_eq!(NoopFilter.backend_name(), "noop");
        let decision = NoopFilter
            .evaluate(&InboundMessage::default())
            .await
            .unwrap();
        assert_eq!(decision, FilterDecision::Allow);
    }

    #[tokio::test]
    async fn chain_accumulates_mutations_and_resolves_conflicts() {
        let calls1 = Arc::new(AtomicUsize::new(0));
        let calls2 = Arc::new(AtomicUsize::new(0));

        let chain = FilterChain::new(vec![
            Arc::new(StaticFilter {
                decision: FilterDecision::Mutate {
                    add_labels: vec!["VIP".into(), "TEMP".into()],
                    remove_labels: vec!["UNREAD".into()],
                    skip_inbox: false,
                },
                calls: calls1.clone(),
            }),
            Arc::new(StaticFilter {
                decision: FilterDecision::Mutate {
                    add_labels: vec!["STARRED".into(), "UNREAD".into()],
                    remove_labels: vec!["TEMP".into()],
                    skip_inbox: true,
                },
                calls: calls2.clone(),
            }),
        ]);
        assert_eq!(chain.backend_name(), "chain");

        let decision = chain.evaluate(&InboundMessage::default()).await.unwrap();
        assert_eq!(
            decision,
            FilterDecision::Mutate {
                add_labels: vec!["VIP".into(), "STARRED".into(), "UNREAD".into()],
                remove_labels: vec!["TEMP".into()],
                skip_inbox: true,
            }
        );
        assert_eq!(calls1.load(Ordering::SeqCst), 1);
        assert_eq!(calls2.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn chain_short_circuits_on_spam_and_reject() {
        let calls_after_spam = Arc::new(AtomicUsize::new(0));
        let spam_chain = FilterChain::new(vec![
            Arc::new(StaticFilter {
                decision: FilterDecision::Spam {
                    score: 9.5,
                    reason: "dmarc fail".into(),
                },
                calls: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(StaticFilter {
                decision: FilterDecision::Reject {
                    reason: "should not run".into(),
                },
                calls: calls_after_spam.clone(),
            }),
        ]);

        let decision = spam_chain
            .evaluate(&InboundMessage::default())
            .await
            .unwrap();
        assert_eq!(
            decision,
            FilterDecision::Spam {
                score: 9.5,
                reason: "dmarc fail".into(),
            }
        );
        assert_eq!(calls_after_spam.load(Ordering::SeqCst), 0);

        let calls_after_reject = Arc::new(AtomicUsize::new(0));
        let reject_chain = FilterChain::new(vec![
            Arc::new(StaticFilter {
                decision: FilterDecision::Reject {
                    reason: "blocked sender".into(),
                },
                calls: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(StaticFilter {
                decision: FilterDecision::Allow,
                calls: calls_after_reject.clone(),
            }),
        ]);

        let decision = reject_chain
            .evaluate(&InboundMessage::default())
            .await
            .unwrap();
        assert_eq!(
            decision,
            FilterDecision::Reject {
                reason: "blocked sender".into(),
            }
        );
        assert_eq!(calls_after_reject.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn filter_label_application_handles_allow_spam_and_mutate() {
        let allow = apply_filter_labels(vec![], &FilterDecision::Allow);
        assert_eq!(allow, vec![LABEL_INBOX, LABEL_UNREAD]);

        let spam = apply_filter_labels(
            vec![],
            &FilterDecision::Spam {
                score: 8.0,
                reason: "spam".into(),
            },
        );
        assert!(!spam.contains(&LABEL_INBOX.to_string()));
        assert!(spam.contains(&LABEL_SPAM.to_string()));
        assert!(spam.contains(&LABEL_UNREAD.to_string()));

        let mutated = apply_filter_labels(
            vec![],
            &FilterDecision::Mutate {
                add_labels: vec!["NEWSLETTER".into()],
                remove_labels: vec![LABEL_UNREAD.into()],
                skip_inbox: true,
            },
        );
        assert_eq!(mutated, vec!["NEWSLETTER".to_string()]);
    }

    #[test]
    fn open_filter_defaults_to_noop_and_orders_enabled_filters() {
        let default_cfg = Config::for_test();
        let noop = open_filter(&default_cfg);
        assert_eq!(noop.backend_name(), "noop");
        assert_eq!(noop.active_filters(), vec!["noop"]);

        let empty_chain = FilterChain::empty();
        assert_eq!(empty_chain.active_filters(), vec!["noop"]);

        let mut all_cfg = Config::for_test();
        all_cfg.filter_auth_results = true;
        all_cfg.rspamd_url = Some("http://127.0.0.1:11333".to_string());
        all_cfg.llm_triage_api_key = Some("sk-test".to_string());
        let chain = open_filter(&all_cfg);
        assert_eq!(chain.backend_name(), "chain");
        assert_eq!(
            chain.active_filters(),
            vec!["auth_results", "rspamd", "llm_triage"]
        );
    }
}
