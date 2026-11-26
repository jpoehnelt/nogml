//! Lightweight zero-dependency atomic metrics rendered in Prometheus text exposition format.

use std::{
    fmt::Write,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
};

use crate::{ai::safety::OutboundDecision, filter::FilterDecision};

/// Standard Prometheus text exposition content type (version 0.0.4).
pub const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// RAII guard that decrements an active-connection gauge when dropped.
#[derive(Debug)]
pub struct ActiveGaugeGuard {
    gauge: Arc<AtomicI64>,
}

impl Drop for ActiveGaugeGuard {
    fn drop(&mut self) {
        self.gauge.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Process-wide atomic operational metrics exposed on `GET /metrics`.
#[derive(Debug)]
pub struct Metrics {
    http_requests_total: AtomicU64,
    messages_sent_total: AtomicU64,
    messages_received_total: AtomicU64,
    imap_active_connections: Arc<AtomicI64>,
    sse_active_connections: Arc<AtomicI64>,
    sync_runs_ok_total: AtomicU64,
    sync_runs_error_total: AtomicU64,
    filter_allow_total: AtomicU64,
    filter_spam_total: AtomicU64,
    filter_reject_total: AtomicU64,
    filter_mutate_total: AtomicU64,
    policy_allow_total: AtomicU64,
    policy_downgrade_total: AtomicU64,
    policy_hold_total: AtomicU64,
    policy_deny_total: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    /// Create a fresh zeroed [`Metrics`] registry.
    pub fn new() -> Self {
        Self {
            http_requests_total: AtomicU64::new(0),
            messages_sent_total: AtomicU64::new(0),
            messages_received_total: AtomicU64::new(0),
            imap_active_connections: Arc::new(AtomicI64::new(0)),
            sse_active_connections: Arc::new(AtomicI64::new(0)),
            sync_runs_ok_total: AtomicU64::new(0),
            sync_runs_error_total: AtomicU64::new(0),
            filter_allow_total: AtomicU64::new(0),
            filter_spam_total: AtomicU64::new(0),
            filter_reject_total: AtomicU64::new(0),
            filter_mutate_total: AtomicU64::new(0),
            policy_allow_total: AtomicU64::new(0),
            policy_downgrade_total: AtomicU64::new(0),
            policy_hold_total: AtomicU64::new(0),
            policy_deny_total: AtomicU64::new(0),
        }
    }

    /// Increment `nogml_http_requests_total`.
    pub fn inc_http_requests(&self) {
        self.http_requests_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment `nogml_messages_sent_total`.
    pub fn inc_messages_sent(&self) {
        self.messages_sent_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment `nogml_messages_received_total`.
    pub fn inc_messages_received(&self) {
        self.messages_received_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment `nogml_imap_active_connections` and return an RAII guard that
    /// decrements the gauge when the connection closes.
    pub fn track_imap_connection(&self) -> ActiveGaugeGuard {
        self.imap_active_connections.fetch_add(1, Ordering::Relaxed);
        ActiveGaugeGuard {
            gauge: self.imap_active_connections.clone(),
        }
    }

    /// Increment `nogml_sse_active_connections` and return an RAII guard that
    /// decrements the gauge when the SSE stream closes or drops.
    pub fn track_sse_connection(&self) -> ActiveGaugeGuard {
        self.sse_active_connections.fetch_add(1, Ordering::Relaxed);
        ActiveGaugeGuard {
            gauge: self.sse_active_connections.clone(),
        }
    }

    /// Record an upstream sync run outcome (`status="ok"` or `status="error"`).
    pub fn record_sync_run(&self, ok: bool) {
        if ok {
            self.sync_runs_ok_total.fetch_add(1, Ordering::Relaxed);
        } else {
            self.sync_runs_error_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record an inbound [`FilterDecision`] outcome.
    pub fn record_filter_decision(&self, decision: &FilterDecision) {
        match decision {
            FilterDecision::Allow => {
                self.filter_allow_total.fetch_add(1, Ordering::Relaxed);
            }
            FilterDecision::Spam { .. } => {
                self.filter_spam_total.fetch_add(1, Ordering::Relaxed);
            }
            FilterDecision::Reject { .. } => {
                self.filter_reject_total.fetch_add(1, Ordering::Relaxed);
            }
            FilterDecision::Mutate { .. } => {
                self.filter_mutate_total.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Record a rejected inbound filter decision when only the rejection outcome is available.
    pub fn inc_filter_reject(&self) {
        self.filter_reject_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an outbound [`OutboundDecision`] policy outcome.
    pub fn record_policy_decision(&self, decision: &OutboundDecision) {
        match decision {
            OutboundDecision::Allow => {
                self.policy_allow_total.fetch_add(1, Ordering::Relaxed);
            }
            OutboundDecision::DowngradeToDraft { .. } => {
                self.policy_downgrade_total.fetch_add(1, Ordering::Relaxed);
            }
            OutboundDecision::HoldForApproval { .. } => {
                self.policy_hold_total.fetch_add(1, Ordering::Relaxed);
            }
            OutboundDecision::Deny { .. } => {
                self.policy_deny_total.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Record a denied outbound policy outcome (including policy errors such as disallowed recipients).
    pub fn inc_policy_deny(&self) {
        self.policy_deny_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Current value of `nogml_http_requests_total`.
    pub fn http_requests_total(&self) -> u64 {
        self.http_requests_total.load(Ordering::Relaxed)
    }

    /// Current value of `nogml_messages_sent_total`.
    pub fn messages_sent_total(&self) -> u64 {
        self.messages_sent_total.load(Ordering::Relaxed)
    }

    /// Current value of `nogml_messages_received_total`.
    pub fn messages_received_total(&self) -> u64 {
        self.messages_received_total.load(Ordering::Relaxed)
    }

    /// Current value of `nogml_imap_active_connections`.
    pub fn imap_active_connections(&self) -> i64 {
        self.imap_active_connections.load(Ordering::Relaxed)
    }

    /// Current value of `nogml_sse_active_connections`.
    pub fn sse_active_connections(&self) -> i64 {
        self.sse_active_connections.load(Ordering::Relaxed)
    }

    /// Render all registered metrics in Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(1024);

        let _ = writeln!(
            out,
            "# HELP nogml_http_requests_total Total number of HTTP requests handled."
        );
        let _ = writeln!(out, "# TYPE nogml_http_requests_total counter");
        let _ = writeln!(
            out,
            "nogml_http_requests_total {}",
            self.http_requests_total.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP nogml_messages_sent_total Total number of outbound messages sent."
        );
        let _ = writeln!(out, "# TYPE nogml_messages_sent_total counter");
        let _ = writeln!(
            out,
            "nogml_messages_sent_total {}",
            self.messages_sent_total.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP nogml_messages_received_total Total number of inbound messages received."
        );
        let _ = writeln!(out, "# TYPE nogml_messages_received_total counter");
        let _ = writeln!(
            out,
            "nogml_messages_received_total {}",
            self.messages_received_total.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP nogml_imap_active_connections Current number of active IMAP connections."
        );
        let _ = writeln!(out, "# TYPE nogml_imap_active_connections gauge");
        let _ = writeln!(
            out,
            "nogml_imap_active_connections {}",
            self.imap_active_connections.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP nogml_sse_active_connections Current number of active SSE event stream connections."
        );
        let _ = writeln!(out, "# TYPE nogml_sse_active_connections gauge");
        let _ = writeln!(
            out,
            "nogml_sse_active_connections {}",
            self.sse_active_connections.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP nogml_sync_runs_total Total number of upstream sync runs by status."
        );
        let _ = writeln!(out, "# TYPE nogml_sync_runs_total counter");
        let _ = writeln!(
            out,
            "nogml_sync_runs_total{{status=\"ok\"}} {}",
            self.sync_runs_ok_total.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "nogml_sync_runs_total{{status=\"error\"}} {}",
            self.sync_runs_error_total.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP nogml_filter_decisions_total Total number of inbound filter decisions."
        );
        let _ = writeln!(out, "# TYPE nogml_filter_decisions_total counter");
        let _ = writeln!(
            out,
            "nogml_filter_decisions_total{{decision=\"allow\"}} {}",
            self.filter_allow_total.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "nogml_filter_decisions_total{{decision=\"spam\"}} {}",
            self.filter_spam_total.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "nogml_filter_decisions_total{{decision=\"reject\"}} {}",
            self.filter_reject_total.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "nogml_filter_decisions_total{{decision=\"mutate\"}} {}",
            self.filter_mutate_total.load(Ordering::Relaxed)
        );

        let _ = writeln!(
            out,
            "# HELP nogml_policy_decisions_total Total number of outbound policy decisions."
        );
        let _ = writeln!(out, "# TYPE nogml_policy_decisions_total counter");
        let _ = writeln!(
            out,
            "nogml_policy_decisions_total{{decision=\"allow\"}} {}",
            self.policy_allow_total.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "nogml_policy_decisions_total{{decision=\"downgrade\"}} {}",
            self.policy_downgrade_total.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "nogml_policy_decisions_total{{decision=\"hold\"}} {}",
            self.policy_hold_total.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "nogml_policy_decisions_total{{decision=\"deny\"}} {}",
            self.policy_deny_total.load(Ordering::Relaxed)
        );

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_valid_prometheus_text_and_tracks_raii_gauges() {
        let metrics = Metrics::new();
        metrics.inc_http_requests();
        metrics.inc_http_requests();
        metrics.inc_messages_sent();
        metrics.inc_messages_received();
        metrics.record_sync_run(true);
        metrics.record_sync_run(false);
        metrics.record_filter_decision(&FilterDecision::Allow);
        metrics.record_filter_decision(&FilterDecision::Spam {
            reason: "score".into(),
            score: 8.5,
        });
        metrics.record_filter_decision(&FilterDecision::Reject {
            reason: "blocked".into(),
        });
        metrics.record_filter_decision(&FilterDecision::Mutate {
            add_labels: vec!["VIP".into()],
            remove_labels: vec![],
            skip_inbox: false,
        });
        metrics.record_policy_decision(&OutboundDecision::Allow);
        metrics.record_policy_decision(&OutboundDecision::DowngradeToDraft {
            reason: "draft only".into(),
        });
        metrics.record_policy_decision(&OutboundDecision::HoldForApproval {
            reason: "needs review".into(),
        });
        metrics.record_policy_decision(&OutboundDecision::Deny {
            code: "recipient_not_allowed".into(),
            reason: "blocked".into(),
            hint: None,
        });

        let imap_guard = metrics.track_imap_connection();
        let sse_guard = metrics.track_sse_connection();
        assert_eq!(metrics.imap_active_connections(), 1);
        assert_eq!(metrics.sse_active_connections(), 1);

        let text = metrics.render_prometheus();
        assert!(text.contains("nogml_http_requests_total 2\n"));
        assert!(text.contains("nogml_messages_sent_total 1\n"));
        assert!(text.contains("nogml_messages_received_total 1\n"));
        assert!(text.contains("nogml_imap_active_connections 1\n"));
        assert!(text.contains("nogml_sse_active_connections 1\n"));
        assert!(text.contains("nogml_sync_runs_total{status=\"ok\"} 1\n"));
        assert!(text.contains("nogml_sync_runs_total{status=\"error\"} 1\n"));
        assert!(text.contains("nogml_filter_decisions_total{decision=\"allow\"} 1\n"));
        assert!(text.contains("nogml_filter_decisions_total{decision=\"spam\"} 1\n"));
        assert!(text.contains("nogml_filter_decisions_total{decision=\"reject\"} 1\n"));
        assert!(text.contains("nogml_filter_decisions_total{decision=\"mutate\"} 1\n"));
        assert!(text.contains("nogml_policy_decisions_total{decision=\"allow\"} 1\n"));
        assert!(text.contains("nogml_policy_decisions_total{decision=\"downgrade\"} 1\n"));
        assert!(text.contains("nogml_policy_decisions_total{decision=\"hold\"} 1\n"));
        assert!(text.contains("nogml_policy_decisions_total{decision=\"deny\"} 1\n"));

        drop(imap_guard);
        drop(sse_guard);
        assert_eq!(metrics.imap_active_connections(), 0);
        assert_eq!(metrics.sse_active_connections(), 0);

        let after_drop = metrics.render_prometheus();
        assert!(after_drop.contains("nogml_imap_active_connections 0\n"));
        assert!(after_drop.contains("nogml_sse_active_connections 0\n"));
    }
}
