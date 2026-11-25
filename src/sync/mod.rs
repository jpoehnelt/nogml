//! Upstream Gmail sync engine supporting:
//! - Mode A: Gmail REST API v1 (OAuth2 refresh + paginated backfill + `history.list` incremental + 404 full resync)
//! - Mode B: Upstream Gmail IMAP via `async-imap` (`X-GM-EXT-1` ID/thread/label unification)
//!
//! All runs share `AppState::sync_lock` for single-flight safety and deduplicate idempotently via `MailStore`.
//!
//! Owned by the `imap-sync` worker.

pub mod gmail_api;
pub mod gmail_imap;
#[cfg(test)]
mod tests;

use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::watch;
use tracing::{error, info};

use crate::{
    AppState,
    config::SyncMode,
    error::AppResult,
    events::{EventSource, MailEvent},
    filter::{FilterDecision, InboundMessage, apply_filter_labels},
    models::{LABEL_UNREAD, SyncStatusResponse},
    storage::{NewMessageInput, SyncState},
};

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

    match state.filter.evaluate(&inbound).await? {
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

/// Options for one upstream Gmail sync run.
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
    pub labels_synced: u64,
    pub history_id: Option<String>,
}

/// Compute the deterministic `SyncState::account_key` for the configured sync mode and user.
pub fn account_key_for_mode(state: &AppState, mode: SyncMode) -> String {
    match mode {
        SyncMode::Api => format!("gmail_api:{}", state.config.gmail_user_id),
        SyncMode::Imap => format!(
            "gmail_imap:{}",
            state
                .config
                .gmail_imap_user
                .as_deref()
                .unwrap_or(&state.config.user_email)
        ),
    }
}

/// Run a single upstream Gmail sync pass (guarded by `state.sync_lock`).
pub async fn run_gmail_sync(state: &AppState, opts: SyncRunOptions) -> AppResult<SyncRunReport> {
    let _guard = state.sync_lock.lock().await;

    let mode = opts.mode.unwrap_or(state.config.sync_mode);
    let provider = match mode {
        SyncMode::Api => "gmail_api",
        SyncMode::Imap => "gmail_imap",
    };
    let account_key = account_key_for_mode(state, mode);

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

    let result = match mode {
        SyncMode::Api => gmail_api::sync_gmail_api(state, &opts, &mut sync_state).await,
        SyncMode::Imap => gmail_imap::sync_gmail_imap(state, &opts, &mut sync_state).await,
    };

    match result {
        Ok(report) => {
            sync_state.status = "idle".to_string();
            sync_state.last_error = None;
            sync_state.last_sync_at = Some(Utc::now());
            state.store.save_sync_state(sync_state).await?;

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
        Err(err) => {
            sync_state.status = "error".to_string();
            sync_state.last_error = Some(err.to_string());
            let _ = state.store.save_sync_state(sync_state).await;
            Err(err)
        }
    }
}

/// Build the current sync status snapshot (used by `GET /v1/sync/status` and MCP `sync_status`).
pub async fn get_sync_status(state: &AppState) -> AppResult<SyncStatusResponse> {
    let mode = state.config.sync_mode;
    let provider = match mode {
        SyncMode::Api => "gmail_api",
        SyncMode::Imap => "gmail_imap",
    };
    let account_key = account_key_for_mode(state, mode);

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

    let extra = active_state.as_ref().map(|s| {
        json!({
            "account_key": s.account_key,
            "messages_synced": s.messages_synced,
            "last_full_sync_at": s.last_full_sync_at,
            "imap_mailbox": s.imap_mailbox,
            "imap_uid_validity": s.imap_uid_validity,
            "imap_last_uid": s.imap_last_uid,
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
        extra,
    })
}

/// Spawn periodic background sync when `config.sync_interval_secs > 0`, stopping on `shutdown`.
pub async fn run_background_sync(state: AppState, mut shutdown: watch::Receiver<bool>) {
    let interval_secs = state.config.sync_interval_secs;
    if interval_secs == 0 {
        return;
    }

    info!(
        interval_secs,
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
                            provider = %report.provider,
                            added = report.messages_added,
                            updated = report.messages_updated,
                            deleted = report.messages_deleted,
                            "Background Gmail sync completed"
                        );
                    }
                    Err(err) => {
                        error!(%err, "Background Gmail sync failed");
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    info!("Background Gmail sync shutting down");
                    break;
                }
            }
        }
    }
}
