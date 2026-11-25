//! Upstream Gmail sync engine supporting:
//! - Mode A: Gmail REST API v1 (OAuth2 refresh + paginated backfill + `history.list` incremental + 404 full resync)
//! - Mode B: Upstream Gmail IMAP via `async-imap` (`X-GM-EXT-1` ID/thread/label unification)
//!
//! All runs share `AppState::sync_lock` for single-flight safety and deduplicate idempotently via `MailStore`.
//!
//! Owned by the `imap-sync` worker.

use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::{
    AppState,
    config::SyncMode,
    error::AppResult,
    models::SyncStatusResponse,
};

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

/// Run a single upstream Gmail sync pass (guarded by `state.sync_lock`).
pub async fn run_gmail_sync(_state: &AppState, _opts: SyncRunOptions) -> AppResult<SyncRunReport> {
    todo!("imap-sync worker: run Gmail API or IMAP upstream sync")
}

/// Build the current sync status snapshot (used by `GET /v1/sync/status` and MCP `sync_status`).
pub async fn get_sync_status(_state: &AppState) -> AppResult<SyncStatusResponse> {
    todo!("imap-sync worker: build SyncStatusResponse from MailStore")
}

/// Spawn periodic background sync when `config.sync_interval_secs > 0`, stopping on `shutdown`.
pub async fn run_background_sync(_state: AppState, _shutdown: watch::Receiver<bool>) {
    todo!("imap-sync worker: periodic background sync loop")
}
