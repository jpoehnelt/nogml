//! `nogml`: headless Rust email server with MCP, Gmail REST API v1,
//! embedded IMAP4rev1, Resend delivery and webhooks, and upstream Gmail sync.

pub mod ai;
pub mod auth;
pub mod blob;
pub mod config;
pub mod error;
pub mod events;
pub mod filter;
pub mod gmail;
pub mod imap;
pub mod mcp;
pub mod mime;
pub mod models;
pub mod resend;
pub mod search;
pub mod search_index;
pub mod server;
pub mod storage;
pub mod sync;
pub mod transport;

use std::sync::{Arc, Once};

use axum::Router;
use tokio::sync::Mutex;

use crate::{
    ai::safety::{ConfigOutboundPolicy, OutboundPolicy},
    auth::{AuthProvider, StaticTokenAuthProvider},
    blob::{
        BlobStore, InlineBlobStore, attachment_blob_key, is_external_blob_store, open_blob_store,
        raw_message_blob_key,
    },
    config::Config,
    error::AppResult,
    events::EventBus,
    filter::{InboundFilter, open_filter},
    resend::{HttpResendClient, ResendClient, ResendTransport},
    search_index::{SearchIndex, StoreSearchIndex},
    storage::{MailStore, StoredAttachment, StoredMessage, open_store},
    transport::{MailTransport, open_transport},
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
/// Every external dependency sits behind a pluggable async trait object:
/// - [`MailStore`]: metadata, threads, labels, history, IMAP UIDs, sync state
/// - [`BlobStore`]: raw RFC 2822 & attachment binary blobs (`inline` | `fs` | `memory` | S3/R2)
/// - [`MailTransport`]: outbound email delivery (`ResendTransport`, SES, SMTP, etc.)
/// - [`InboundFilter`]: inbound spam/auth/routing pipeline across all ingest paths
/// - [`AuthProvider`]: HTTP bearer & IMAP authentication returning [`auth::Principal`]
/// - [`SearchIndex`]: full-text or semantic search used by `/v1/search` and MCP `search_emails`
/// - [`OutboundPolicy`]: agent send guardrails (`Allow`, `DowngradeToDraft`, `HoldForApproval`, `Deny`)
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn MailStore>,
    pub blobs: Arc<dyn BlobStore>,
    pub transport: Arc<dyn MailTransport>,
    pub filter: Arc<dyn InboundFilter>,
    pub auth: Arc<dyn AuthProvider>,
    pub search: Arc<dyn SearchIndex>,
    pub outbound_policy: Arc<dyn OutboundPolicy>,
    /// Underlying Resend client used by `POST /webhooks/resend` Receiving API fetches.
    pub resend: Arc<dyn ResendClient>,
    pub events: EventBus,
    pub sync_lock: Arc<Mutex<()>>,
}

impl AppState {
    /// Construct application state from `Config`, opening the configured `MailStore`,
    /// `BlobStore`, and `MailTransport`.
    pub fn from_config(config: Config) -> AppResult<Self> {
        ensure_crypto_provider();
        let store = open_store(&config)?;
        let blobs = open_blob_store(&config)?;
        let resend: Arc<dyn ResendClient> = Arc::new(HttpResendClient::from_config(&config));
        let transport = open_transport(&config, resend.clone())?;
        Ok(Self::with_backends(config, store, resend)
            .with_blobs(blobs)
            .with_transport(transport))
    }

    /// Construct application state with explicit `MailStore` and `ResendClient` implementations
    /// (ideal for integration tests with `MemoryStore` / mock Resend). All other pluggable traits
    /// default cleanly from `config` and `store` and can be swapped via `.with_*` builders.
    pub fn with_backends(
        config: Config,
        store: Arc<dyn MailStore>,
        resend: Arc<dyn ResendClient>,
    ) -> Self {
        ensure_crypto_provider();
        let blobs: Arc<dyn BlobStore> = match open_blob_store(&config) {
            Ok(b) => b,
            Err(_) => Arc::new(InlineBlobStore),
        };
        let transport: Arc<dyn MailTransport> = match open_transport(&config, resend.clone()) {
            Ok(t) => t,
            Err(_) => Arc::new(ResendTransport::new(
                resend.clone(),
                config.user_email.clone(),
            )),
        };
        let filter: Arc<dyn InboundFilter> = open_filter(&config);
        let auth: Arc<dyn AuthProvider> = Arc::new(StaticTokenAuthProvider::from_config(&config));
        let search: Arc<dyn SearchIndex> = Arc::new(StoreSearchIndex::new(store.clone()));
        let outbound_policy: Arc<dyn OutboundPolicy> =
            Arc::new(ConfigOutboundPolicy::from_config(&config));

        Self {
            config: Arc::new(config),
            store,
            blobs,
            transport,
            filter,
            auth,
            search,
            outbound_policy,
            resend,
            events: EventBus::new(),
            sync_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Replace the [`BlobStore`] backend on this `AppState`.
    pub fn with_blobs(mut self, blobs: Arc<dyn BlobStore>) -> Self {
        self.blobs = blobs;
        self
    }

    /// Replace the [`MailTransport`] backend on this `AppState`.
    pub fn with_transport(mut self, transport: Arc<dyn MailTransport>) -> Self {
        self.transport = transport;
        self
    }

    /// Replace the [`InboundFilter`] backend on this `AppState`.
    pub fn with_filter(mut self, filter: Arc<dyn InboundFilter>) -> Self {
        self.filter = filter;
        self
    }

    /// Replace the [`AuthProvider`] backend on this `AppState`.
    pub fn with_auth(mut self, auth: Arc<dyn AuthProvider>) -> Self {
        self.auth = auth;
        self
    }

    /// Replace the [`SearchIndex`] backend on this `AppState`.
    pub fn with_search(mut self, search: Arc<dyn SearchIndex>) -> Self {
        self.search = search;
        self
    }

    /// Replace the [`OutboundPolicy`] backend on this `AppState`.
    pub fn with_outbound_policy(mut self, outbound_policy: Arc<dyn OutboundPolicy>) -> Self {
        self.outbound_policy = outbound_policy;
        self
    }

    /// Mirror a stored message's raw RFC 2822 bytes and attachments to `self.blobs`
    /// when an external `BlobStore` (`fs`, `memory`, S3/R2, etc.) is active, and index
    /// the message in `self.search`.
    pub async fn post_store_message(&self, msg: &StoredMessage) -> AppResult<()> {
        if is_external_blob_store(self.blobs.as_ref()) {
            if !msg.raw_rfc2822.is_empty() {
                self.blobs
                    .put(&raw_message_blob_key(&msg.id), &msg.raw_rfc2822)
                    .await?;
            }
            if msg.has_attachments {
                let metas = self.store.list_attachment_meta(&msg.id).await?;
                for meta in metas {
                    if let Some(att) = self.store.get_attachment(&msg.id, &meta.id).await? {
                        self.blobs
                            .put(&attachment_blob_key(&msg.id, &att.id), &att.data)
                            .await?;
                    }
                }
            }
        }
        self.search.index(msg).await?;
        Ok(())
    }

    /// Load a message's raw RFC 2822 bytes, serving from external `BlobStore` when present
    /// and falling back to `msg.raw_rfc2822`.
    pub async fn load_raw_rfc2822(&self, msg: &StoredMessage) -> AppResult<Vec<u8>> {
        if is_external_blob_store(self.blobs.as_ref())
            && let Some(bytes) = self.blobs.get(&raw_message_blob_key(&msg.id)).await?
        {
            return Ok(bytes);
        }
        Ok(msg.raw_rfc2822.clone())
    }

    /// Load an attachment's raw bytes, serving from external `BlobStore` when present
    /// and falling back to `att.data`.
    pub async fn load_attachment_bytes(&self, att: &StoredAttachment) -> AppResult<Vec<u8>> {
        if is_external_blob_store(self.blobs.as_ref())
            && let Some(bytes) = self
                .blobs
                .get(&attachment_blob_key(&att.message_id, &att.id))
                .await?
        {
            return Ok(bytes);
        }
        Ok(att.data.clone())
    }

    /// Clean up external blobs and search index entry for a deleted message.
    pub async fn post_delete_message(
        &self,
        message_id: &str,
        attachment_ids: &[String],
    ) -> AppResult<()> {
        if is_external_blob_store(self.blobs.as_ref()) {
            let _ = self.blobs.delete(&raw_message_blob_key(message_id)).await;
            for att_id in attachment_ids {
                let _ = self
                    .blobs
                    .delete(&attachment_blob_key(message_id, att_id))
                    .await;
            }
        }
        let _ = self.search.remove(message_id).await;
        Ok(())
    }
}

/// Convenience helper to construct the full Axum HTTP [`Router`].
pub fn build_router(state: AppState) -> Router {
    server::build_router(state)
}

#[cfg(test)]
mod pluggable_seam_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::*;
    use crate::{
        ai::safety::{OutboundCheck, OutboundDecision, PolicyCheck},
        auth::{AuthScope, Principal},
        blob::MemoryBlobStore,
        error::AppError,
        filter::{FilterDecision, InboundMessage},
        mcp::McpServer,
        models::LABEL_INBOX,
        storage::{AiMessagePage, AiSearchQuery, MemoryStore, NewMessageInput},
        transport::{OutboundMessage, SendOutcome, TransportCapabilities},
    };

    struct RecordingTransport {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl MailTransport for RecordingTransport {
        fn name(&self) -> &'static str {
            "custom_smtp"
        }

        fn capabilities(&self) -> TransportCapabilities {
            TransportCapabilities {
                provider: "custom_smtp".to_string(),
                supports_raw_mime: true,
                supports_scheduled_send: false,
                supports_idempotency_key: true,
                supports_inbound_webhooks: false,
                supports_delivery_webhooks: false,
                max_message_bytes: 25 * 1024 * 1024,
            }
        }

        async fn send(
            &self,
            _msg: &OutboundMessage,
            _idempotency_key: Option<&str>,
        ) -> AppResult<SendOutcome> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(SendOutcome {
                provider: "custom_smtp".to_string(),
                provider_message_id: format!("smtp_{n}"),
            })
        }
    }

    struct RejectKeywordFilter {
        keyword: String,
    }

    #[async_trait]
    impl InboundFilter for RejectKeywordFilter {
        async fn evaluate(&self, msg: &InboundMessage) -> AppResult<FilterDecision> {
            if msg.subject.contains(&self.keyword) {
                Ok(FilterDecision::Reject {
                    reason: format!("blocked keyword: {}", self.keyword),
                })
            } else {
                Ok(FilterDecision::Mutate {
                    add_labels: vec!["VERIFIED".to_string()],
                    remove_labels: vec![],
                    skip_inbox: false,
                })
            }
        }

        fn backend_name(&self) -> &'static str {
            "keyword_filter"
        }
    }

    struct CustomAuthProvider;

    #[async_trait]
    impl AuthProvider for CustomAuthProvider {
        async fn authenticate_bearer(&self, token: Option<&str>) -> AppResult<Principal> {
            if token == Some("jwt-valid") {
                Ok(Principal {
                    mailbox_id: "agent@example.com".to_string(),
                    scopes: vec![AuthScope::Read, AuthScope::Send],
                    agent_policy: None,
                })
            } else {
                Err(AppError::Unauthorized("custom auth denied".to_string()))
            }
        }

        async fn authenticate_imap(&self, username: &str, password: &str) -> AppResult<Principal> {
            if username == "imap-custom" && password == "secret-pass" {
                Ok(Principal::full_access("agent@example.com"))
            } else {
                Err(AppError::Unauthorized("bad imap creds".to_string()))
            }
        }

        fn backend_name(&self) -> &'static str {
            "custom_jwt"
        }
    }

    struct CountingSearchIndex {
        inner: StoreSearchIndex,
        searches: Arc<AtomicUsize>,
        indexed: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl SearchIndex for CountingSearchIndex {
        async fn index(&self, msg: &StoredMessage) -> AppResult<()> {
            self.indexed.fetch_add(1, Ordering::SeqCst);
            self.inner.index(msg).await
        }

        async fn remove(&self, message_id: &str) -> AppResult<()> {
            self.inner.remove(message_id).await
        }

        async fn search(&self, query: &AiSearchQuery) -> AppResult<AiMessagePage> {
            self.searches.fetch_add(1, Ordering::SeqCst);
            self.inner.search(query).await
        }

        fn backend_name(&self) -> &'static str {
            "counting_vector"
        }
    }

    struct ApprovalOrDenyPolicy {
        hold: bool,
    }

    #[async_trait]
    impl OutboundPolicy for ApprovalOrDenyPolicy {
        async fn evaluate(&self, _check: &OutboundCheck) -> AppResult<OutboundDecision> {
            if self.hold {
                Ok(OutboundDecision::HoldForApproval {
                    reason: "human sign-off required".to_string(),
                })
            } else {
                Ok(OutboundDecision::Deny {
                    code: "dlp_blocked".to_string(),
                    reason: "sensitive payload detected".to_string(),
                    hint: Some("Redact secrets before sending.".to_string()),
                })
            }
        }

        fn policy_checks(&self, _check: &OutboundCheck) -> Vec<PolicyCheck> {
            vec![PolicyCheck {
                rule: "custom_dlp".to_string(),
                passed: false,
                detail: "custom policy active".to_string(),
            }]
        }

        fn backend_name(&self) -> &'static str {
            "approval_policy"
        }
    }

    #[tokio::test]
    async fn capabilities_and_custom_auth_transport_search_blobs_filter_policy_seams() {
        let cfg = Config::for_test();
        let store = Arc::new(MemoryStore::new(&cfg.user_email));
        let resend = Arc::new(HttpResendClient::from_config(&cfg));
        let blobs = Arc::new(MemoryBlobStore::new());
        let transport_calls = Arc::new(AtomicUsize::new(0));
        let search_calls = Arc::new(AtomicUsize::new(0));
        let indexed_calls = Arc::new(AtomicUsize::new(0));

        let state = AppState::with_backends(cfg, store.clone(), resend)
            .with_blobs(blobs.clone())
            .with_transport(Arc::new(RecordingTransport {
                calls: transport_calls.clone(),
            }))
            .with_filter(Arc::new(RejectKeywordFilter {
                keyword: "BLOCKME".to_string(),
            }))
            .with_auth(Arc::new(CustomAuthProvider))
            .with_search(Arc::new(CountingSearchIndex {
                inner: StoreSearchIndex::new(store.clone()),
                searches: search_calls.clone(),
                indexed: indexed_calls.clone(),
            }));

        let app = build_router(state.clone());

        // 1. Custom AuthProvider blocks unauthenticated even when config.auth_tokens is empty.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/capabilities")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // 2. Custom AuthProvider accepts valid bearer token and /v1/capabilities advertises all 7 backends.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/capabilities")
                    .header("authorization", "Bearer jwt-valid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let caps: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(caps["backends"]["storage"], "memory");
        assert_eq!(caps["backends"]["blob"], "memory");
        assert_eq!(caps["backends"]["transport"], "custom_smtp");
        assert_eq!(caps["backends"]["filter"], "keyword_filter");
        assert_eq!(caps["backends"]["auth"], "custom_jwt");
        assert_eq!(caps["backends"]["search"], "counting_vector");
        assert_eq!(caps["backends"]["outbound_policy"], "config");

        // 3. Both /v1/messages/send and /gmail/v1/users/me/messages/send use custom MailTransport
        //    AND mirror raw RFC 2822 into MemoryBlobStore + index into SearchIndex.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages/send")
                    .header("authorization", "Bearer jwt-valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "to": ["alice@example.com"],
                            "subject": "Via custom transport",
                            "text": "Hello world"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let sent: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(sent["provider"], "custom_smtp");
        assert_eq!(sent["resend_id"], "smtp_1");
        let sent_msg_id = sent["message_id"].as_str().unwrap();
        assert!(
            blobs
                .get(&raw_message_blob_key(sent_msg_id))
                .await
                .unwrap()
                .is_some(),
            "raw RFC 2822 should be mirrored into external BlobStore"
        );

        let raw_gmail = mime::encode_base64url(
            b"From: agent@example.com\r\nTo: bob@example.com\r\nSubject: Gmail send\r\n\r\nBody",
        );
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/gmail/v1/users/me/messages/send")
                    .header("authorization", "Bearer jwt-valid")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "raw": raw_gmail }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(transport_calls.load(Ordering::SeqCst), 2);
        assert_eq!(indexed_calls.load(Ordering::SeqCst), 2);

        // 4. Gmail messages.import invokes InboundFilter (reject + mutate).
        let raw_blocked = mime::encode_base64url(
            b"From: bad@example.com\r\nTo: agent@example.com\r\nSubject: BLOCKME now\r\n\r\nSpam",
        );
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/gmail/v1/users/me/messages/import")
                    .header("authorization", "Bearer jwt-valid")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "raw": raw_blocked }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        let raw_ok = mime::encode_base64url(
            b"From: good@example.com\r\nTo: agent@example.com\r\nSubject: Allowed import\r\n\r\nHi",
        );
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/gmail/v1/users/me/messages/import")
                    .header("authorization", "Bearer jwt-valid")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "raw": raw_ok }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let imported: Value =
            serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
        let imported_labels: Vec<&str> = imported["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(imported_labels.contains(&"VERIFIED"));
        assert!(imported_labels.contains(&LABEL_INBOX));

        // 5. /v1/search AND MCP search_emails route through SearchIndex.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/search?q=transport")
                    .header("authorization", "Bearer jwt-valid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let mcp = McpServer::new(state.clone());
        let mcp_res = mcp
            .handle_request(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "search_emails",
                    "arguments": { "query": "transport" }
                }
            }))
            .await
            .unwrap()
            .unwrap();
        assert!(mcp_res.get("result").is_some());
        assert_eq!(search_calls.load(Ordering::SeqCst), 2);

        // 6. Sync inbound filter helper respects Reject.
        let mut sync_input = NewMessageInput {
            id: None,
            thread_id: None,
            label_ids: vec![LABEL_INBOX.to_string()],
            raw_rfc2822: b"From: a@b.com\r\nSubject: BLOCKME sync\r\n\r\nhi".to_vec(),
            snippet: "hi".into(),
            internal_date_ms: 1_700_000_000_000,
            subject: "BLOCKME sync".into(),
            from_addr: "a@b.com".into(),
            to_addrs: vec!["agent@example.com".into()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: "hi".into(),
            html_body: None,
            rfc822_message_id: None,
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id: Some("up_1".into()),
            upstream_thread_id: None,
            source: "gmail_api".into(),
            is_answered: false,
            is_deleted: false,
            attachments: vec![],
        };
        assert!(
            !sync::apply_sync_inbound_filter(&state, &mut sync_input)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn custom_outbound_policy_hold_for_approval_202_and_deny_403() {
        let cfg = Config::for_test();
        let store = Arc::new(MemoryStore::new(&cfg.user_email));
        let resend = Arc::new(HttpResendClient::from_config(&cfg));

        // HoldForApproval -> HTTP 202 Accepted
        let hold_state = AppState::with_backends(cfg.clone(), store.clone(), resend.clone())
            .with_outbound_policy(Arc::new(ApprovalOrDenyPolicy { hold: true }));
        let hold_app = build_router(hold_state);

        let res = hold_app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages/send")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "to": ["alice@example.com"],
                            "subject": "Needs approval",
                            "text": "Please review"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let body: Value =
            serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(body["status"], "pending_approval");
        assert_eq!(body["held_for_approval"], true);
        assert_eq!(body["reason"], "human sign-off required");
        assert!(body["draft_id"].as_str().is_some());

        // Deny -> HTTP 403 Forbidden with custom AI error code and hint
        let deny_state = AppState::with_backends(cfg, store, resend)
            .with_outbound_policy(Arc::new(ApprovalOrDenyPolicy { hold: false }));
        let deny_app = build_router(deny_state);

        let res = deny_app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages/send")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "to": ["alice@example.com"],
                            "subject": "Secret leak",
                            "text": "API_KEY=123"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let body: Value =
            serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(body["error"]["code"], "dlp_blocked");
        assert_eq!(body["error"]["hint"], "Redact secrets before sending.");
    }

    #[tokio::test]
    async fn capabilities_reports_configured_transport_backend() {
        use crate::config::TransportBackend;

        for (backend, expected_name) in [
            (TransportBackend::Resend, "resend"),
            (TransportBackend::Ses, "ses"),
            (TransportBackend::Smtp, "smtp"),
        ] {
            let mut cfg = Config::for_test();
            cfg.transport = backend;
            let state = AppState::from_config(cfg).expect("from_config should succeed");
            let app = build_router(state);

            let res = app
                .oneshot(
                    Request::builder()
                        .uri("/v1/capabilities")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let body = res.into_body().collect().await.unwrap().to_bytes();
            let caps: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(caps["backends"]["transport"], expected_name);
        }
    }
}
