//! Embedded IMAP4rev1 server (plain TCP + optional STARTTLS + optional implicit TLS),
//! supporting RFC 3501/2177/6851/6154/7888/4959 commands, Gmail virtual folders,
//! flags <-> labels mapping, and real-time `IDLE` via `AppState::events`.
//!
//! Owned by the `imap-sync` worker.

use tokio::sync::watch;

use crate::{AppState, error::AppResult};

/// Start the embedded IMAP4rev1 plain TCP (with optional STARTTLS) and/or implicit TLS listeners
/// configured in `state.config`, shutting down gracefully when `shutdown` signals `true`.
pub async fn serve_imap(_state: AppState, _shutdown: watch::Receiver<bool>) -> AppResult<()> {
    todo!("imap-sync worker: serve embedded IMAP4rev1 listeners")
}
