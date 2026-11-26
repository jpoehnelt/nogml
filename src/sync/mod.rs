//! Pluggable upstream mail sync engine (`SyncSource`) with optional bidirectional pushback:
//! - Mode A: [`gmail_api::GmailApiSyncSource`] (Gmail REST API v1 OAuth2 + paginated backfill + `history.list` + `messages.modify`/`trash`/`delete` pushback)
//! - Mode B: [`gmail_imap::GmailImapSyncSource`] (Upstream Gmail IMAP via `async-imap` with `X-GM-EXT-1`, UID checkpointing, and `UID STORE`/`UID MOVE`/`EXPUNGE` pushback)
//!
//! All [`SyncSource`] connectors share `AppState::sync_lock` for single-flight safety, `SyncState`
//! checkpointing, the `InboundFilter` + `MailStore::upsert_synced_message` deduplication pipeline,
//! deterministic pull-first conflict resolution, and `EventBus` notifications.

pub mod gmail_api;
pub mod gmail_imap;
#[cfg(test)]
mod tests;

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    time::Duration,
};

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::watch;
use tracing::{error, info};

use crate::{
    AppState,
    config::{Config, SyncMode},
    error::AppResult,
    events::{EventSource, MailEvent},
    filter::{FilterDecision, InboundMessage, apply_filter_labels},
    models::{LABEL_DRAFT, LABEL_INBOX, LABEL_SENT, LABEL_TRASH, LABEL_UNREAD, SyncStatusResponse},
    storage::{
        HISTORY_SOURCE_SYNC, HistoryEventKind, HistoryListQuery, NewMessageInput, SyncState,
        UpsertOutcome, UpsertOutcomeKind,
    },
};

pub use gmail_api::GmailApiSyncSource;
pub use gmail_imap::GmailImapSyncSource;

/// Kind of local mutation to push back to an upstream account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalMutationKind {
    /// Add and/or remove labels/flags on an upstream message.
    ModifyLabels {
        add_labels: Vec<String>,
        remove_labels: Vec<String>,
    },
    /// Move the upstream message to Trash (optionally carrying extra label changes).
    Trash {
        add_labels: Vec<String>,
        remove_labels: Vec<String>,
    },
    /// Permanently delete the upstream message.
    Delete,
    /// Append a locally created Sent or Draft message (without an `upstream_id`) upstream.
    AppendMessage {
        /// `true` for Drafts (`[Gmail]/Drafts` / `Drafts`), `false` for Sent (`[Gmail]/Sent Mail` / `Sent`).
        is_draft: bool,
    },
}

/// Collapsed local mutation on a single upstream-linked message ready to replay upstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalMutation {
    /// Local `MailStore` message ID.
    pub local_message_id: String,
    /// Upstream message identifier (`StoredMessage::upstream_gmail_id`).
    pub upstream_id: String,
    /// Optional RFC 2822 `Message-ID` header (fallback identifier for IMAP lookups).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rfc822_message_id: Option<String>,
    /// Highest local `history_id` contributing to this mutation.
    pub history_id: u64,
    /// Action to replay upstream.
    pub kind: LocalMutationKind,
}

/// Summary returned by [`SyncSource::pull`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PullReport {
    pub full_resync: bool,
    pub messages_added: u64,
    pub messages_updated: u64,
    pub messages_deduplicated: u64,
    pub messages_deleted: u64,
    pub labels_synced: u64,
    pub history_id: Option<String>,
}

/// Summary returned by [`SyncSource::push_changes`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PushReport {
    pub messages_pushed: u64,
}

/// Pluggable upstream mail connector unified behind [`run_sync_source`].
///
/// Built-in implementations:
/// - [`GmailApiSyncSource`] (`"gmail_api"`)
/// - [`GmailImapSyncSource`] (`"gmail_imap"`)
#[async_trait]
pub trait SyncSource: Send + Sync {
    /// Short provider identifier persisted in `SyncState::provider` and `SyncRunReport::provider`.
    fn provider_name(&self) -> &'static str;

    /// Deterministic `SyncState::account_key` for this connector and runtime `Config`.
    fn account_key(&self, config: &Config) -> String;

    /// Synchronize upstream labels and pull new, updated, or deleted messages (full or incremental).
    async fn pull(
        &self,
        state: &AppState,
        sync_state: &mut SyncState,
        opts: &SyncRunOptions,
    ) -> AppResult<PullReport>;

    /// Returns `true` when this connector handles additional bidirectional push work
    /// (such as drafts, locally created Sent/imported messages, or custom labels)
    /// even when message-level `LocalMutation`s are empty.
    fn supports_full_bidirectional_push(&self) -> bool {
        false
    }

    /// Replay local label, flag, trash, and delete mutations back to the upstream account.
    ///
    /// One-way connectors can rely on this default no-op implementation.
    async fn push_changes(
        &self,
        _state: &AppState,
        _changes: &[LocalMutation],
    ) -> AppResult<PushReport> {
        Ok(PushReport::default())
    }
}

/// Construct the built-in [`SyncSource`] for `mode`.
pub fn open_sync_source(mode: SyncMode) -> Box<dyn SyncSource> {
    match mode {
        SyncMode::Api => Box::new(GmailApiSyncSource),
        SyncMode::Imap => Box::new(GmailImapSyncSource::default()),
    }
}

/// Apply `state.filter` to a newly synced upstream message before inserting it into `MailStore`.
///
/// Existing messages (already present by `upstream_gmail_id` or `rfc822_message_id`) bypass
/// filtering so re-syncs only update labels cleanly. Returns `Ok(false)` when rejected.
pub(crate) async fn apply_sync_inbound_filter(
    state: &AppState,
    input: &mut NewMessageInput,
) -> AppResult<bool> {
    if let Some(ref uid) = input.upstream_gmail_id
        && state
            .store
            .find_message_by_upstream_id(uid)
            .await?
            .is_some()
    {
        return Ok(true);
    }
    if let Some(ref mid) = input.rfc822_message_id
        && state
            .store
            .find_message_by_rfc_message_id(mid)
            .await?
            .is_some()
    {
        return Ok(true);
    }

    let parsed_headers: Vec<(String, String)> = crate::mime::parse_rfc2822(&input.raw_rfc2822)
        .map(|p| p.headers.into_iter().map(|h| (h.name, h.value)).collect())
        .unwrap_or_default();
    let auth_results = parsed_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Authentication-Results"))
        .map(|(_, v)| v.clone());

    let inbound = InboundMessage {
        raw_rfc2822: input.raw_rfc2822.clone(),
        headers: parsed_headers,
        text_body: input.text_body.clone(),
        html_body: input.html_body.clone(),
        from: input.from_addr.clone(),
        to: input.to_addrs.clone(),
        subject: input.subject.clone(),
        authentication_results: auth_results,
        sender_ip: None,
        source: input.source.clone(),
        provider_id: input.upstream_gmail_id.clone(),
    };

    let decision = state.filter.evaluate(&inbound).await?;
    state.metrics.record_filter_decision(&decision);
    match decision {
        FilterDecision::Allow => Ok(true),
        FilterDecision::Reject { reason } => {
            tracing::info!(
                source = %input.source,
                from = %input.from_addr,
                reason = %reason,
                "Synced message rejected by inbound filter"
            );
            Ok(false)
        }
        decision @ (FilterDecision::Spam { .. } | FilterDecision::Mutate { .. }) => {
            let existing = std::mem::take(&mut input.label_ids);
            input.label_ids = apply_filter_labels(existing, &decision);
            Ok(true)
        }
    }
}

/// Shared ingest pipeline for all [`SyncSource`] connectors: runs `InboundFilter`, deduplicates
/// via `MailStore::upsert_synced_message`, mirrors blobs/search index, updates `PullReport`, and
/// publishes `MailEvent::MessageReceived` on insertion.
pub async fn ingest_synced_message(
    state: &AppState,
    mut input: NewMessageInput,
    report: &mut PullReport,
) -> AppResult<Option<UpsertOutcome>> {
    if !apply_sync_inbound_filter(state, &mut input).await? {
        return Ok(None);
    }

    let mut outcome = state.store.upsert_synced_message(input).await?;
    match outcome.kind {
        UpsertOutcomeKind::Inserted => {
            report.messages_added += 1;
            state.metrics.inc_messages_received();
            state.events.publish(
                EventSource::GmailSync,
                MailEvent::MessageReceived {
                    message_id: outcome.message.id.clone(),
                    thread_id: outcome.message.thread_id.clone(),
                    from: outcome.message.from_addr.clone(),
                    subject: outcome.message.subject.clone(),
                    snippet: outcome.message.snippet.clone(),
                    labels: outcome.message.label_ids.clone(),
                },
            );
            let webhook_policy = crate::ai::rules::RuleWebhookPolicy::from_config(&state.config);
            outcome.message = crate::ai::rules::evaluate_inbox_rules_with_cipher(
                state.store.as_ref(),
                &state.events,
                &outcome.message,
                state.config.untrusted_content_guard,
                &webhook_policy,
                state.cipher.as_ref(),
            )
            .await;
            let _ = state.post_store_message(&outcome.message).await;
        }
        UpsertOutcomeKind::Updated => {
            report.messages_updated += 1;
        }
        UpsertOutcomeKind::Deduplicated => {
            report.messages_deduplicated += 1;
        }
    }

    Ok(Some(outcome))
}

/// Options for one upstream sync run.
#[derive(Debug, Clone, Default)]
pub struct SyncRunOptions {
    /// Override transport mode (`api` or `imap`); defaults to `Config::sync_mode`.
    pub mode: Option<SyncMode>,
    /// Force a full backfill even when a history/UID checkpoint exists.
    pub full: bool,
    /// Optional cap on messages fetched in this run.
    pub max_messages: Option<usize>,
    /// Optional Gmail search query filter (API mode).
    pub query: Option<String>,
    /// Optional per-run override for bidirectional pushback (defaults to `Config::sync_bidirectional`).
    pub bidirectional: Option<bool>,
}

/// Summary returned after an upstream sync pass completes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncRunReport {
    pub provider: String,
    pub full_resync: bool,
    pub messages_added: u64,
    pub messages_updated: u64,
    pub messages_deduplicated: u64,
    pub messages_deleted: u64,
    pub messages_pushed: u64,
    pub bidirectional_enabled: bool,
    pub labels_synced: u64,
    pub history_id: Option<String>,
}

/// Alias for [`SyncRunReport`].
pub type SyncReport = SyncRunReport;

/// Compute the deterministic `SyncState::account_key` for the configured sync mode and user.
pub fn account_key_for_mode(state: &AppState, mode: SyncMode) -> String {
    open_sync_source(mode).account_key(&state.config)
}

/// Run a single upstream Gmail sync pass (guarded by the mailbox's `state.sync_lock`).
///
/// When `config.sync_accounts` contains an entry matching `state.mailbox_id()`, that account's
/// credentials and sync parameters are applied automatically.
pub async fn run_gmail_sync(state: &AppState, opts: SyncRunOptions) -> AppResult<SyncRunReport> {
    let effective_state = state
        .config
        .sync_account_for_mailbox(state.mailbox_id())
        .map(|acct| state.for_sync_account(acct));
    let target_state = effective_state.as_ref().unwrap_or(state);
    let mode = opts.mode.unwrap_or(target_state.config.sync_mode);
    let source = open_sync_source(mode);
    run_sync_source(target_state, source.as_ref(), opts).await
}

/// Run a single sync pass for any [`SyncSource`] implementation (guarded by `state.sync_lock`).
///
/// When bidirectional pushback is enabled (`opts.bidirectional` or `config.sync_bidirectional`),
/// local mutations recorded since `SyncState::last_pushed_history_id` are collected before pulling,
/// reconciled deterministically against any upstream changes applied by `pull` (pull-first /
/// last-write-wins so pulled changes never echo back), and pushed upstream via
/// [`SyncSource::push_changes`].
pub async fn run_sync_source(
    state: &AppState,
    source: &dyn SyncSource,
    opts: SyncRunOptions,
) -> AppResult<SyncRunReport> {
    let result = run_sync_source_inner(state, source, opts).await;
    state.metrics.record_sync_run(result.is_ok());
    result
}

async fn run_sync_source_inner(
    state: &AppState,
    source: &dyn SyncSource,
    opts: SyncRunOptions,
) -> AppResult<SyncRunReport> {
    let _guard = state.sync_lock.lock().await;

    let provider = source.provider_name();
    let account_key = source.account_key(&state.config);
    let bidirectional = opts
        .bidirectional
        .unwrap_or(state.config.sync_bidirectional);

    let mut sync_state = state
        .store
        .get_sync_state(&account_key)
        .await?
        .unwrap_or_else(|| SyncState {
            account_key: account_key.clone(),
            provider: provider.to_string(),
            status: "idle".to_string(),
            ..Default::default()
        });
    sync_state.provider = provider.to_string();
    sync_state.status = "running".to_string();
    sync_state.last_error = None;
    state.store.save_sync_state(sync_state.clone()).await?;

    // 1. Capture pre-pull local history checkpoint and collect genuinely local mutations.
    let skip_draft_mutations = source.supports_full_bidirectional_push();
    let pre_pull_hid = state.store.current_history_id().await?;
    let pending_mutations = if bidirectional
        && let Some(last_pushed_hid) = sync_state.last_pushed_history_id
        && pre_pull_hid > last_pushed_hid
    {
        match collect_local_mutations(state, last_pushed_hid, pre_pull_hid, skip_draft_mutations)
            .await
        {
            Ok(m) => m,
            Err(err) => {
                sync_state.status = "error".to_string();
                sync_state.last_error = Some(err.to_string());
                let _ = state.store.save_sync_state(sync_state).await;
                return Err(err);
            }
        }
    } else {
        Vec::new()
    };

    // 2. Pull upstream changes first (deterministic pull-first ordering).
    let pull_report = match source.pull(state, &mut sync_state, &opts).await {
        Ok(report) => report,
        Err(err) => {
            sync_state.status = "error".to_string();
            sync_state.last_error = Some(err.to_string());
            let _ = state.store.save_sync_state(sync_state).await;
            return Err(err);
        }
    };

    let post_pull_hid = state.store.current_history_id().await?;

    // 3. Resolve conflicts with pull-generated history events and push remaining local mutations
    // (including label, draft, and locally created Sent/imported message pushback).
    let push_report = if bidirectional {
        let resolved_mutations = if pending_mutations.is_empty() {
            Vec::new()
        } else {
            match resolve_pull_conflicts(state, pre_pull_hid, post_pull_hid, pending_mutations)
                .await
            {
                Ok(m) => m,
                Err(err) => {
                    sync_state.status = "error".to_string();
                    sync_state.last_error = Some(err.to_string());
                    let _ = state.store.save_sync_state(sync_state).await;
                    return Err(err);
                }
            }
        };

        if resolved_mutations.is_empty() && !source.supports_full_bidirectional_push() {
            PushReport::default()
        } else {
            match source.push_changes(state, &resolved_mutations).await {
                Ok(report) => report,
                Err(err) => {
                    sync_state.status = "error".to_string();
                    sync_state.last_error = Some(err.to_string());
                    let _ = state.store.save_sync_state(sync_state).await;
                    return Err(err);
                }
            }
        }
    } else {
        PushReport::default()
    };

    // 4. Advance local push checkpoint past pull-generated (`source = "sync"`) history events
    // without skipping any concurrent local (`source = "local"`) mutations created while `pull()`
    // was executing.
    let next_pushed_hid = if bidirectional {
        compute_next_pushed_history_id(state, pre_pull_hid, post_pull_hid, skip_draft_mutations)
            .await?
    } else {
        post_pull_hid
    };
    sync_state.last_pushed_history_id = Some(next_pushed_hid);
    sync_state.messages_pushed = sync_state
        .messages_pushed
        .saturating_add(push_report.messages_pushed);
    sync_state.status = "idle".to_string();
    sync_state.last_error = None;
    sync_state.last_sync_at = Some(Utc::now());
    state.store.save_sync_state(sync_state).await?;

    let report = SyncRunReport {
        provider: provider.to_string(),
        full_resync: pull_report.full_resync,
        messages_added: pull_report.messages_added,
        messages_updated: pull_report.messages_updated,
        messages_deduplicated: pull_report.messages_deduplicated,
        messages_deleted: pull_report.messages_deleted,
        messages_pushed: push_report.messages_pushed,
        bidirectional_enabled: bidirectional,
        labels_synced: pull_report.labels_synced,
        history_id: pull_report.history_id,
    };

    state.events.publish(
        EventSource::GmailSync,
        MailEvent::SyncCompleted {
            provider: report.provider.clone(),
            messages_added: report.messages_added,
            messages_updated: report.messages_updated,
            messages_deleted: report.messages_deleted,
            history_id: report.history_id.clone(),
        },
    );

    Ok(report)
}

#[derive(Default)]
struct PendingMutation {
    upstream_id: Option<String>,
    created: bool,
    deleted: bool,
    added: BTreeSet<String>,
    removed: BTreeSet<String>,
    max_history_id: u64,
}

async fn collect_local_mutations(
    state: &AppState,
    after_hid: u64,
    through_hid: u64,
    skip_draft_mutations: bool,
) -> AppResult<Vec<LocalMutation>> {
    if through_hid <= after_hid {
        return Ok(Vec::new());
    }

    let entries = load_mutation_history_range(state, after_hid, through_hid).await?;
    if entries.is_empty() {
        return Ok(Vec::new());
    }

    let mut order: Vec<String> = Vec::new();
    let mut by_msg: HashMap<String, PendingMutation> = HashMap::new();

    for entry in entries {
        if entry.source == HISTORY_SOURCE_SYNC {
            // Skip upstream-originated sync writes so retries never echo pulled rows back upstream.
            continue;
        }
        if skip_draft_mutations && entry.label_ids.iter().any(|l| l == LABEL_DRAFT) {
            // Gmail API draft lifecycle mutations are synchronized via `users.drafts.*`, not `users.messages.*`.
            continue;
        }
        let acc = by_msg.entry(entry.message_id.clone()).or_insert_with(|| {
            order.push(entry.message_id.clone());
            PendingMutation::default()
        });
        if acc.upstream_id.is_none() && entry.upstream_gmail_id.is_some() {
            acc.upstream_id = entry.upstream_gmail_id;
        }
        acc.max_history_id = acc.max_history_id.max(entry.history_id);

        match entry.kind {
            HistoryEventKind::MessageAdded => {
                acc.created = true;
            }
            HistoryEventKind::MessageDeleted => {
                acc.deleted = true;
                acc.added.clear();
                acc.removed.clear();
            }
            HistoryEventKind::LabelAdded if !acc.deleted => {
                for lid in entry.label_ids {
                    acc.removed.remove(&lid);
                    acc.added.insert(lid);
                }
            }
            HistoryEventKind::LabelRemoved if !acc.deleted => {
                for lid in entry.label_ids {
                    acc.added.remove(&lid);
                    acc.removed.insert(lid);
                }
            }
            _ => {}
        }
    }

    let mut mutations = Vec::new();
    for msg_id in order {
        let Some(mut acc) = by_msg.remove(&msg_id) else {
            continue;
        };

        let stored = state.store.get_message(&msg_id).await?;
        let upstream_id = acc
            .upstream_id
            .or_else(|| stored.as_ref().and_then(|m| m.upstream_gmail_id.clone()))
            .filter(|s| !s.trim().is_empty());
        let rfc822_message_id = stored.as_ref().and_then(|m| m.rfc822_message_id.clone());

        let Some(upstream_id) = upstream_id else {
            // Locally created Sent or Draft message with no upstream linkage yet -> APPEND upstream.
            if acc.created
                && !acc.deleted
                && let Some(ref msg) = stored
                && msg.source != "gmail_imap"
                && msg.source != "gmail_api"
                && !msg.label_ids.iter().any(|l| l == LABEL_TRASH)
            {
                let is_draft = msg.label_ids.iter().any(|l| l == LABEL_DRAFT);
                let is_sent = msg.label_ids.iter().any(|l| l == LABEL_SENT);
                if is_draft || is_sent {
                    mutations.push(LocalMutation {
                        local_message_id: msg_id,
                        upstream_id: String::new(),
                        rfc822_message_id,
                        history_id: acc.max_history_id,
                        kind: LocalMutationKind::AppendMessage { is_draft },
                    });
                }
            }
            continue;
        };

        if acc.deleted {
            mutations.push(LocalMutation {
                local_message_id: msg_id,
                upstream_id,
                rfc822_message_id,
                history_id: acc.max_history_id,
                kind: LocalMutationKind::Delete,
            });
            continue;
        }

        // Reconcile net label deltas against the current pre-pull message state so
        // cancelled toggles never push stale changes.
        if let Some(ref msg) = stored {
            let current: HashSet<&str> = msg.label_ids.iter().map(String::as_str).collect();
            acc.added.retain(|l| current.contains(l.as_str()));
            acc.removed.retain(|l| !current.contains(l.as_str()));
        }

        if acc.added.contains(LABEL_TRASH) {
            acc.added.remove(LABEL_TRASH);
            acc.removed.remove(LABEL_INBOX);
            mutations.push(LocalMutation {
                local_message_id: msg_id,
                upstream_id,
                rfc822_message_id,
                history_id: acc.max_history_id,
                kind: LocalMutationKind::Trash {
                    add_labels: acc.added.into_iter().collect(),
                    remove_labels: acc.removed.into_iter().collect(),
                },
            });
        } else if !acc.added.is_empty() || !acc.removed.is_empty() {
            mutations.push(LocalMutation {
                local_message_id: msg_id,
                upstream_id,
                rfc822_message_id,
                history_id: acc.max_history_id,
                kind: LocalMutationKind::ModifyLabels {
                    add_labels: acc.added.into_iter().collect(),
                    remove_labels: acc.removed.into_iter().collect(),
                },
            });
        }
    }

    Ok(mutations)
}

async fn resolve_pull_conflicts(
    state: &AppState,
    pre_pull_hid: u64,
    post_pull_hid: u64,
    mutations: Vec<LocalMutation>,
) -> AppResult<Vec<LocalMutation>> {
    if mutations.is_empty() || post_pull_hid <= pre_pull_hid {
        return Ok(mutations);
    }

    let pull_events = load_mutation_history_range(state, pre_pull_hid, post_pull_hid).await?;
    if pull_events.is_empty() {
        return Ok(mutations);
    }

    let mut pulled_deleted: HashSet<String> = HashSet::new();
    let mut pulled_labels: HashMap<String, HashSet<String>> = HashMap::new();

    for ev in pull_events {
        if ev.source != HISTORY_SOURCE_SYNC {
            // Concurrent local mutations occurring during `pull()` are NOT upstream pull conflicts.
            continue;
        }
        match ev.kind {
            HistoryEventKind::MessageDeleted => {
                pulled_deleted.insert(ev.message_id);
            }
            HistoryEventKind::LabelAdded | HistoryEventKind::LabelRemoved => {
                pulled_labels
                    .entry(ev.message_id)
                    .or_default()
                    .extend(ev.label_ids);
            }
            HistoryEventKind::MessageAdded => {}
        }
    }

    let mut resolved = Vec::with_capacity(mutations.len());
    for mut mutation in mutations {
        if pulled_deleted.contains(&mutation.local_message_id) {
            continue;
        }
        if let Some(touched) = pulled_labels.get(&mutation.local_message_id) {
            match &mut mutation.kind {
                LocalMutationKind::ModifyLabels {
                    add_labels,
                    remove_labels,
                } => {
                    add_labels.retain(|l| !touched.contains(l));
                    remove_labels.retain(|l| !touched.contains(l));
                    if add_labels.is_empty() && remove_labels.is_empty() {
                        continue;
                    }
                }
                LocalMutationKind::Trash {
                    add_labels,
                    remove_labels,
                } => {
                    add_labels.retain(|l| !touched.contains(l));
                    remove_labels.retain(|l| !touched.contains(l));
                    if touched.contains(LABEL_TRASH) {
                        if add_labels.is_empty() && remove_labels.is_empty() {
                            continue;
                        }
                        mutation.kind = LocalMutationKind::ModifyLabels {
                            add_labels: std::mem::take(add_labels),
                            remove_labels: std::mem::take(remove_labels),
                        };
                    }
                }
                LocalMutationKind::Delete => {}
                LocalMutationKind::AppendMessage { .. } => {}
            }
        }
        if matches!(mutation.kind, LocalMutationKind::AppendMessage { .. }) {
            // If `pull()` already matched and linked this local message by RFC 2822 Message-ID,
            // do not append a duplicate copy upstream.
            if let Some(msg) = state.store.get_message(&mutation.local_message_id).await?
                && msg
                    .upstream_gmail_id
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty())
            {
                continue;
            }
        }
        resolved.push(mutation);
    }

    Ok(resolved)
}

/// Compute the safe `last_pushed_history_id` after `pull()` completes: advance through
/// `post_pull_hid` if only sync-originated events occurred during `pull()`, or stop immediately
/// before the earliest concurrent local mutation so it will be pushed on the next sync.
async fn compute_next_pushed_history_id(
    state: &AppState,
    pre_pull_hid: u64,
    post_pull_hid: u64,
    skip_draft_mutations: bool,
) -> AppResult<u64> {
    if post_pull_hid <= pre_pull_hid {
        return Ok(post_pull_hid);
    }
    let range_events = load_mutation_history_range(state, pre_pull_hid, post_pull_hid).await?;
    if let Some(first_local_hid) = range_events
        .iter()
        .filter(|e| {
            e.source != HISTORY_SOURCE_SYNC
                && !(skip_draft_mutations && e.label_ids.iter().any(|l| l == LABEL_DRAFT))
        })
        .map(|e| e.history_id)
        .min()
    {
        Ok(first_local_hid.saturating_sub(1).max(pre_pull_hid))
    } else {
        Ok(post_pull_hid)
    }
}

/// Return the set of label IDs touched by unpushed local mutations since `after_hid`, keyed by
/// local message ID. Used by non-`CONDSTORE` IMAP reconciliation so stale flag snapshots do not
/// clobber pending local edits before `push_changes()` runs.
pub(crate) async fn pending_local_label_touches(
    state: &AppState,
    after_hid: u64,
) -> AppResult<HashMap<String, HashSet<String>>> {
    let cur_hid = state.store.current_history_id().await?;
    if cur_hid <= after_hid {
        return Ok(HashMap::new());
    }
    let entries = load_mutation_history_range(state, after_hid, cur_hid).await?;
    let mut touched: HashMap<String, HashSet<String>> = HashMap::new();
    for entry in entries {
        if entry.source == HISTORY_SOURCE_SYNC {
            continue;
        }
        match entry.kind {
            HistoryEventKind::LabelAdded | HistoryEventKind::LabelRemoved => {
                touched
                    .entry(entry.message_id)
                    .or_default()
                    .extend(entry.label_ids);
            }
            HistoryEventKind::MessageDeleted => {
                touched
                    .entry(entry.message_id)
                    .or_default()
                    .insert("__DELETED__".to_string());
            }
            HistoryEventKind::MessageAdded => {}
        }
    }
    Ok(touched)
}

async fn load_mutation_history_range(
    state: &AppState,
    after_hid: u64,
    through_hid: u64,
) -> AppResult<Vec<crate::storage::StoredHistoryEntry>> {
    let start_history_id = after_hid.max(1);
    let mut page_token: Option<String> = None;
    let mut out = Vec::new();

    loop {
        let page = state
            .store
            .list_history(&HistoryListQuery {
                start_history_id,
                max_results: 500,
                page_token: page_token.clone(),
                label_id: None,
                history_types: vec![
                    HistoryEventKind::MessageAdded,
                    HistoryEventKind::LabelAdded,
                    HistoryEventKind::LabelRemoved,
                    HistoryEventKind::MessageDeleted,
                ],
            })
            .await?;

        for entry in page.entries {
            if entry.history_id <= through_hid {
                out.push(entry);
            }
        }

        match page.next_page_token.filter(|s| !s.is_empty()) {
            Some(next) => page_token = Some(next),
            None => break,
        }
    }

    Ok(out)
}

/// Build the current sync status snapshot (used by `GET /v1/sync/status` and MCP `sync_status`).
pub async fn get_sync_status(state: &AppState) -> AppResult<SyncStatusResponse> {
    let effective_state = state
        .config
        .sync_account_for_mailbox(state.mailbox_id())
        .map(|acct| state.for_sync_account(acct));
    let state = effective_state.as_ref().unwrap_or(state);
    let mode = state.config.sync_mode;
    let source = open_sync_source(mode);
    let provider = source.provider_name();
    let account_key = source.account_key(&state.config);

    let active_state = match state.store.get_sync_state(&account_key).await? {
        Some(s) => Some(s),
        None => state.store.list_sync_states().await?.into_iter().next(),
    };

    let profile = state.store.get_profile(&state.config.user_email).await?;
    let unread_count = state
        .store
        .get_label(LABEL_UNREAD)
        .await?
        .map(|l| i64::from(l.messages_total))
        .unwrap_or(0);

    let messages_pushed = active_state
        .as_ref()
        .map(|s| s.messages_pushed)
        .unwrap_or(0);
    let bidirectional_enabled = state.config.sync_bidirectional;

    let extra = active_state.as_ref().map(|s| {
        let folder_summary: HashMap<&str, serde_json::Value> = s
            .imap_folder_states
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str(),
                    json!({
                        "uid_validity": v.uid_validity,
                        "last_uid": v.last_uid,
                        "highest_modseq": v.highest_modseq,
                        "tracked_uids": v.uid_to_message_id.len(),
                    }),
                )
            })
            .collect();
        json!({
            "account_key": s.account_key,
            "messages_synced": s.messages_synced,
            "messages_pushed": s.messages_pushed,
            "bidirectional_enabled": bidirectional_enabled,
            "last_pushed_history_id": s.last_pushed_history_id,
            "last_full_sync_at": s.last_full_sync_at,
            "imap_mailbox": s.imap_mailbox,
            "imap_uid_validity": s.imap_uid_validity,
            "imap_last_uid": s.imap_last_uid,
            "imap_highest_modseq": s.imap_highest_modseq,
            "imap_folders": folder_summary,
            "imap_idle_enabled": state.config.sync_mode == SyncMode::Imap && state.config.gmail_imap_idle,
            "sync_interval_secs": state.config.sync_interval_secs,
        })
    });

    Ok(SyncStatusResponse {
        enabled: state.config.gmail_sync_configured(),
        provider: active_state
            .as_ref()
            .map(|s| s.provider.clone())
            .unwrap_or_else(|| provider.to_string()),
        state: active_state
            .as_ref()
            .map(|s| s.status.clone())
            .unwrap_or_else(|| "idle".to_string()),
        last_sync_at: active_state.as_ref().and_then(|s| s.last_sync_at),
        last_history_id: active_state
            .as_ref()
            .and_then(|s| s.last_history_id.clone()),
        last_error: active_state.as_ref().and_then(|s| s.last_error.clone()),
        total_messages: i64::from(profile.messages_total),
        unread_count,
        bidirectional_enabled,
        messages_pushed,
        extra,
    })
}

/// Run periodic background sync loops for all configured `[[sync.accounts]]` entries
/// (each with its own independent per-mailbox lock and interval) and/or legacy `[sync]`
/// when `config.sync_interval_secs > 0`, stopping cleanly when `shutdown` signals `true`.
pub async fn run_background_sync(state: AppState, shutdown: watch::Receiver<bool>) {
    let mut handles = Vec::new();
    let mut covered_mailboxes = HashSet::new();

    for acct in &state.config.sync_accounts {
        let norm_mb = crate::config::normalize_mailbox_id(&acct.mailbox_id);
        if norm_mb.is_empty() {
            continue;
        }
        covered_mailboxes.insert(norm_mb);
        let acct_state = state.for_sync_account(acct);
        if acct.interval_secs > 0 {
            let loop_state = acct_state.clone();
            let acct_shutdown = shutdown.clone();
            let interval_secs = acct.interval_secs;
            handles.push(tokio::spawn(async move {
                run_single_sync_loop(loop_state, interval_secs, acct_shutdown).await;
            }));
        }
        if acct.mode == SyncMode::Imap && acct.gmail_imap_idle {
            let idle_shutdown = shutdown.clone();
            handles.push(tokio::spawn(async move {
                gmail_imap::run_imap_idle_listener(acct_state, idle_shutdown).await;
            }));
        }
    }

    let primary_mb = crate::config::normalize_mailbox_id(state.mailbox_id());
    if !covered_mailboxes.contains(&primary_mb) {
        if state.config.sync_interval_secs > 0 {
            let interval_secs = state.config.sync_interval_secs;
            let legacy_state = state.clone();
            let legacy_shutdown = shutdown.clone();
            handles.push(tokio::spawn(async move {
                run_single_sync_loop(legacy_state, interval_secs, legacy_shutdown).await;
            }));
        }
        if state.config.sync_mode == SyncMode::Imap && state.config.gmail_imap_idle {
            let idle_state = state.clone();
            let idle_shutdown = shutdown.clone();
            handles.push(tokio::spawn(async move {
                gmail_imap::run_imap_idle_listener(idle_state, idle_shutdown).await;
            }));
        }
    }

    for handle in handles {
        let _ = handle.await;
    }
}

async fn run_single_sync_loop(
    state: AppState,
    interval_secs: u64,
    mut shutdown: watch::Receiver<bool>,
) {
    if interval_secs == 0 {
        return;
    }

    info!(
        mailbox = %state.mailbox_id(),
        interval_secs,
        bidirectional = state.config.sync_bidirectional,
        "Starting background upstream Gmail sync loop"
    );
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if *shutdown.borrow() {
                    break;
                }
                if !state.config.gmail_sync_configured() {
                    continue;
                }
                match run_gmail_sync(&state, SyncRunOptions::default()).await {
                    Ok(report) => {
                        info!(
                            mailbox = %state.mailbox_id(),
                            provider = %report.provider,
                            added = report.messages_added,
                            updated = report.messages_updated,
                            deleted = report.messages_deleted,
                            pushed = report.messages_pushed,
                            "Background Gmail sync completed"
                        );
                    }
                    Err(err) => {
                        error!(
                            mailbox = %state.mailbox_id(),
                            %err,
                            "Background Gmail sync failed"
                        );
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    info!(
                        mailbox = %state.mailbox_id(),
                        "Background Gmail sync shutting down"
                    );
                    break;
                }
            }
        }
    }
}
