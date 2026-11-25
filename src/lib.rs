//! `nogml` — AI-first headless Rust email server with MCP, Gmail REST API v1,
//! embedded IMAP4rev1, Resend delivery/webhooks, and upstream Gmail sync.

pub mod ai;
pub mod auth;
pub mod config;
pub mod error;
pub mod events;
pub mod gmail;
pub mod imap;
pub mod mcp;
pub mod mime;
pub mod models;
pub mod resend;
pub mod search;
pub mod server;
pub mod storage;
pub mod sync;

use std::sync::{Arc, Once};

use axum::Router;
use tokio::sync::Mutex;

use crate::{
    config::Config,
    error::AppResult,
    events::EventBus,
    resend::{HttpResendClient, ResendClient},
    storage::{MailStore, open_store},
};

static CRYPTO_INIT: Once = Once::new();

/// Install the `ring` rustls crypto provider once per process.
pub fn ensure_crypto_provider() {
    CRYPTO_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Shared application state injected into HTTP, MCP, IMAP, Resend, and Sync subsystems.
///
/// Strictly decoupled from any specific storage backend via `Arc<dyn MailStore>`.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn MailStore>,
    pub resend: Arc<dyn ResendClient>,
    pub events: EventBus,
    pub sync_lock: Arc<Mutex<()>>,
}

impl AppState {
    /// Construct application state from `Config`, opening the configured `MailStore` backend.
    pub fn from_config(config: Config) -> AppResult<Self> {
        ensure_crypto_provider();
        let store = open_store(&config)?;
        let resend: Arc<dyn ResendClient> = Arc::new(HttpResendClient::from_config(&config));
        Ok(Self::with_backends(config, store, resend))
    }

    /// Construct application state with explicit `MailStore` and `ResendClient` implementations
    /// (ideal for integration tests with `MemoryStore` / mock Resend).
    pub fn with_backends(
        config: Config,
        store: Arc<dyn MailStore>,
        resend: Arc<dyn ResendClient>,
    ) -> Self {
        ensure_crypto_provider();
        Self {
            config: Arc::new(config),
            store,
            resend,
            events: EventBus::new(),
            sync_lock: Arc::new(Mutex::new(())),
        }
    }
}

/// Convenience helper to construct the full Axum HTTP [`Router`].
pub fn build_router(state: AppState) -> Router {
    server::build_router(state)
}
