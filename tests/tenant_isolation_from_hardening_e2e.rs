//! Regression tests for Issue #88:
//! 1. Cross-tenant upstream Gmail sync isolation (no legacy `[sync]` fallback + `bidirectional` guard)
//! 2. Mailbox-scoped `Admin` vs global admin separation (domains, OAuth2 `login_hint`, suppression, deliverability)
//! 3. `From:` authorization enforcement on `/v1/drafts/{id}/send` and MCP `send_draft`
//! 4. Raw RFC 2822 `From:` header spoofing protection (duplicate, multi-mailbox, folded, malformed)
//! 5. Dispatch-time policy re-evaluation on `POST /v1/approvals/{id}/approve`
//! 6. Compensating upstream `provider.delete_domain` on `execute_create_domain` DB failure
//! 7. Duplicate `[[sync.accounts]]` validation error and fail-fast startup
//! 8. IMAP `AUTHENTICATE PLAIN` unauthorized `authzid` rejection for `Admin` principals

use std::{
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path_regex},
};

use nogml::{
    AppState,
    auth::{AuthScope, Principal, ScopedTokenConfig},
    build_router,
    config::{Config, DlpAction, SyncAccountConfig, SyncMode, validate_config},
    domains::{
        DomainProvider, DomainProviderKind, DomainStatus, DomainUpdate, NewDomainInput,
        ProviderDomainResult,
        service::{CreateDomainRequest, execute_create_domain},
    },
    error::AppResult,
    imap,
    resend::HttpResendClient,
    storage::{MailStore, MemoryStore},
    transport::{MailTransport, OutboundMessage, SendOutcome, TransportCapabilities},
};

struct RecordingTransport {
    sent: Arc<AtomicUsize>,
    messages: Arc<Mutex<Vec<OutboundMessage>>>,
}

impl RecordingTransport {
    fn new() -> (Self, Arc<AtomicUsize>, Arc<Mutex<Vec<OutboundMessage>>>) {
        let sent = Arc::new(AtomicUsize::new(0));
        let messages = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                sent: sent.clone(),
                messages: messages.clone(),
            },
            sent,
            messages,
        )
    }
}

#[async_trait]
impl MailTransport for RecordingTransport {
    fn name(&self) -> &'static str {
        "recording"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            provider: "recording".to_string(),
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
        msg: &OutboundMessage,
        _idempotency_key: Option<&str>,
    ) -> AppResult<SendOutcome> {
        let n = self.sent.fetch_add(1, Ordering::SeqCst) + 1;
        self.messages.lock().unwrap().push(msg.clone());
        Ok(SendOutcome {
            provider: "recording".to_string(),
            provider_message_id: format!("rec_{n}"),
            provider_thread_id: None,
        })
    }
}

async fn http_req(
    app: &axum::Router,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(tok) = bearer {
        builder = builder.header("authorization", format!("Bearer {tok}"));
    }
    let req = match body {
        Some(val) => builder
            .header("content-type", "application/json")
            .body(Body::from(val.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({}));
    (status, json)
}

async fn mcp_call(
    app: &axum::Router,
    bearer: &str,
    tool_name: &str,
    arguments: Value,
) -> (StatusCode, Value) {
    http_req(
        app,
        Method::POST,
        "/mcp",
        Some(bearer),
        Some(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        })),
    )
    .await
}

// ============================================================================
// Finding 1: Cross-tenant legacy [sync] fallback & bidirectional override guard
// ============================================================================

#[tokio::test]
async fn finding1_non_primary_mailbox_cannot_sync_primary_gmail_or_override_bidirectional() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("^/gmail/v1/users/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "emailAddress": "alice@example.com",
            "historyId": "100",
            "messagesTotal": 0,
            "threadsTotal": 0,
            "labels": [],
            "messages": [],
            "drafts": [],
            "resultSizeEstimate": 0
        })))
        .mount(&upstream)
        .await;

    let mut cfg = Config::for_test();
    cfg.user_email = "alice@example.com".to_string();
    cfg.mailboxes = vec!["bob@example.com".to_string()];
    cfg.sync_mode = SyncMode::Api;
    cfg.sync_bidirectional = false;
    cfg.sync_interval_secs = 60;
    cfg.gmail_access_token = Some("alice-secret-oauth-token".to_string());
    cfg.gmail_client_id = Some("alice-client-id".to_string());
    cfg.gmail_client_secret = Some("alice-client-secret".to_string());
    cfg.gmail_refresh_token = Some("alice-refresh-token".to_string());
    cfg.gmail_imap_user = Some("alice@gmail.com".to_string());
    cfg.gmail_imap_password = Some("alice-imap-pass".to_string());
    cfg.gmail_imap_idle = true;
    cfg.gmail_api_base_url = upstream.uri();
    cfg.auth_tokens = vec!["tok_global_admin".to_string()];
    cfg.scoped_tokens = vec![
        ScopedTokenConfig {
            token: "tok_bob_write".to_string(),
            mailbox_id: Some("bob@example.com".to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read, AuthScope::Write],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_alice_write".to_string(),
            mailbox_id: Some("alice@example.com".to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read, AuthScope::Write],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_alice_scoped_admin".to_string(),
            mailbox_id: Some("alice@example.com".to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Admin],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
    ];

    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store, resend);

    // 1. AppState::for_mailbox strips legacy [sync] credentials for non-primary mailboxes.
    let bob_state = state.for_mailbox("bob@example.com");
    assert!(!bob_state.is_primary_mailbox());
    assert!(bob_state.config.gmail_access_token.is_none());
    assert!(bob_state.config.gmail_client_id.is_none());
    assert!(bob_state.config.gmail_client_secret.is_none());
    assert!(bob_state.config.gmail_refresh_token.is_none());
    assert!(bob_state.config.gmail_imap_user.is_none());
    assert!(bob_state.config.gmail_imap_password.is_none());
    assert_eq!(bob_state.config.sync_interval_secs, 0);
    assert!(!bob_state.config.sync_bidirectional);
    assert!(!bob_state.config.gmail_imap_idle);
    assert!(!bob_state.config.gmail_sync_configured());

    let app = build_router(state);

    // 2. Bob cannot trigger POST /v1/sync/gmail using Alice's legacy [sync] credentials.
    let (status, body) = http_req(
        &app,
        Method::POST,
        "/v1/sync/gmail",
        Some("tok_bob_write"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");

    // 3. Bob cannot trigger MCP sync_gmail either.
    let (status, mcp_body) = mcp_call(&app, "tok_bob_write", "sync_gmail", json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "mcp_body={mcp_body}");
    assert_eq!(
        mcp_body["result"]["isError"],
        json!(true),
        "mcp_body={mcp_body}"
    );

    // 4. Bob's GET /v1/sync/status does not leak Alice's legacy sync config or state.
    let (status, sync_status) = http_req(
        &app,
        Method::GET,
        "/v1/sync/status",
        Some("tok_bob_write"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sync_status["enabled"], false);
    assert_eq!(sync_status["bidirectional_enabled"], false);
    assert!(sync_status["extra"].is_null());

    // 5. Non-global-admin callers (both Write and mailbox-scoped Admin) cannot override
    //    bidirectional: true when sync.bidirectional is disabled.
    for tok in ["tok_alice_write", "tok_alice_scoped_admin"] {
        let (status, body) = http_req(
            &app,
            Method::POST,
            "/v1/sync/gmail",
            Some(tok),
            Some(json!({ "bidirectional": true })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "token={tok}, body={body}");

        let (status, mcp_body) =
            mcp_call(&app, tok, "sync_gmail", json!({ "bidirectional": true })).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "token={tok}, mcp_body={mcp_body}"
        );
        assert_eq!(
            mcp_body["result"]["isError"],
            json!(true),
            "token={tok}, mcp_body={mcp_body}"
        );
    }

    // Upstream Gmail API must have received ZERO requests from all blocked attempts.
    assert!(
        upstream.received_requests().await.unwrap().is_empty(),
        "blocked sync attempts must never contact upstream Gmail"
    );

    // 6. Global admin token CAN override bidirectional: true on the primary mailbox.
    let (status, body) = http_req(
        &app,
        Method::POST,
        "/v1/sync/gmail",
        Some("tok_global_admin"),
        Some(json!({ "bidirectional": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["bidirectional_enabled"], true);
}

// ============================================================================
// Finding 2: Mailbox-scoped Admin cannot mutate global suppression/deliverability
// ============================================================================

#[tokio::test]
async fn finding2_mailbox_scoped_admin_blocked_from_global_suppression_and_deliverability() {
    let mut cfg = Config::for_test();
    cfg.user_email = "alice@example.com".to_string();
    cfg.default_domain = "example.com".to_string();
    cfg.mailboxes = vec!["bob@example.com".to_string()];
    cfg.auth_tokens = vec!["tok_global_admin".to_string()];
    cfg.scoped_tokens = vec![ScopedTokenConfig {
        token: "tok_alice_scoped_admin".to_string(),
        mailbox_id: Some("alice@example.com".to_string()),
        shared_mailboxes: Vec::new(),
        scopes: vec![
            AuthScope::Read,
            AuthScope::Write,
            AuthScope::Send,
            AuthScope::Admin,
        ],
        draft_only: None,
        allowed_recipients: None,
        max_send_recipients: None,
    }];

    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store, resend);
    let app = build_router(state);

    // Mailbox-scoped Admin token is denied on all global suppression & deliverability mutations.
    let (status, _) = http_req(
        &app,
        Method::POST,
        "/v1/suppression",
        Some("tok_alice_scoped_admin"),
        Some(json!({ "email": "bounced@external.example", "reason": "manual" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = http_req(
        &app,
        Method::POST,
        "/v1/deliverability/domains/example.com/pause",
        Some("tok_alice_scoped_admin"),
        Some(json!({ "reason": "attempt" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = http_req(
        &app,
        Method::POST,
        "/v1/deliverability/domains/example.com/resume",
        Some("tok_alice_scoped_admin"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Global operator token succeeds on suppression add/delete and domain pause/resume.
    let (status, _) = http_req(
        &app,
        Method::POST,
        "/v1/suppression",
        Some("tok_global_admin"),
        Some(json!({ "email": "bounced@external.example", "reason": "manual" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Mailbox-scoped Admin still cannot delete that suppression entry.
    let (status, _) = http_req(
        &app,
        Method::DELETE,
        "/v1/suppression/bounced@external.example",
        Some("tok_alice_scoped_admin"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Global admin can delete it and pause/resume domain.
    let (status, _) = http_req(
        &app,
        Method::DELETE,
        "/v1/suppression/bounced@external.example",
        Some("tok_global_admin"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = http_req(
        &app,
        Method::POST,
        "/v1/deliverability/domains/example.com/pause",
        Some("tok_global_admin"),
        Some(json!({ "reason": "maintenance" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = http_req(
        &app,
        Method::POST,
        "/v1/deliverability/domains/example.com/resume",
        Some("tok_global_admin"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ============================================================================
// Finding 3 & Finding 4: Draft send From: auth & raw RFC 2822 From: hardening
// ============================================================================

#[tokio::test]
async fn finding3_and_4_draft_send_and_raw_mime_from_header_hardening() {
    let mut cfg = Config::for_test();
    cfg.user_email = "alice@example.com".to_string();
    cfg.default_domain = "example.com".to_string();
    cfg.mailboxes = vec!["bob@example.com".to_string()];
    cfg.require_verified_from_domain = true;
    cfg.scoped_tokens = vec![ScopedTokenConfig {
        token: "tok_alice_send".to_string(),
        mailbox_id: Some("alice@example.com".to_string()),
        shared_mailboxes: Vec::new(),
        scopes: vec![AuthScope::Read, AuthScope::Write, AuthScope::Send],
        draft_only: None,
        allowed_recipients: None,
        max_send_recipients: None,
    }];

    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let (transport, sent_count, _) = RecordingTransport::new();
    let state = AppState::with_backends(cfg, store, resend).with_transport(Arc::new(transport));
    let app = build_router(state);

    // Helper: create a draft via Gmail API with arbitrary raw MIME.
    async fn create_gmail_draft(app: &axum::Router, raw_mime: &str) -> String {
        let raw_b64 = general_purpose::URL_SAFE_NO_PAD.encode(raw_mime.as_bytes());
        let (status, body) = http_req(
            app,
            Method::POST,
            "/gmail/v1/users/me/drafts",
            Some("tok_alice_send"),
            Some(json!({ "message": { "raw": raw_b64 } })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "draft create failed: {body}");
        body["id"].as_str().unwrap().to_string()
    }

    // --- Finding 3: Spoofed single From: bob@example.com stored in a draft ---
    let spoof_draft_id = create_gmail_draft(
        &app,
        "From: bob@example.com\r\nTo: victim@external.example\r\nSubject: Spoof\r\n\r\nHello",
    )
    .await;

    // /v1/drafts/{id}/send must reject with 403 Forbidden.
    let (status, body) = http_req(
        &app,
        Method::POST,
        &format!("/v1/drafts/{spoof_draft_id}/send"),
        Some("tok_alice_send"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");

    // MCP send_draft must also reject.
    let (status, mcp_body) = mcp_call(
        &app,
        "tok_alice_send",
        "send_draft",
        json!({ "draft_id": spoof_draft_id }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "mcp_body={mcp_body}");
    assert_eq!(
        mcp_body["result"]["isError"],
        json!(true),
        "mcp_body={mcp_body}"
    );

    // --- Finding 4: Malicious raw RFC 2822 From: headers ---
    let malicious_raw_cases = [
        (
            "duplicate_from",
            "From: alice@example.com\r\nFrom: ceo@victim.example\r\nTo: target@external.example\r\nSubject: Dup\r\n\r\nBody",
        ),
        (
            "duplicate_from_spaced_colon",
            "From: alice@example.com\r\nFrom : ceo@victim.example\r\nTo: target@external.example\r\nSubject: DupSpace\r\n\r\nBody",
        ),
        (
            "multi_mailbox_from",
            "From: alice@example.com, ceo@victim.example\r\nTo: target@external.example\r\nSubject: Multi\r\n\r\nBody",
        ),
        (
            "folded_multi_mailbox_from",
            "From: alice@example.com,\r\n ceo@victim.example\r\nTo: target@external.example\r\nSubject: Folded\r\n\r\nBody",
        ),
        (
            "unparseable_from",
            "From: not-a-valid-email\r\nTo: target@external.example\r\nSubject: Bad\r\n\r\nBody",
        ),
        (
            "empty_from",
            "From:    \r\nTo: target@external.example\r\nSubject: Empty\r\n\r\nBody",
        ),
    ];

    for (label, raw_mime) in malicious_raw_cases {
        // 4a. Gmail messages.send must reject with 400 Bad Request.
        let raw_b64 = general_purpose::URL_SAFE_NO_PAD.encode(raw_mime.as_bytes());
        let (status, body) = http_req(
            &app,
            Method::POST,
            "/gmail/v1/users/me/messages/send",
            Some("tok_alice_send"),
            Some(json!({ "raw": raw_b64 })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "gmail messages.send should reject {label}, got {status}: {body}"
        );

        // 4b. Draft saved via Gmail API and sent via /v1/drafts/{id}/send must also reject with 400.
        let draft_id = create_gmail_draft(&app, raw_mime).await;
        let (status, body) = http_req(
            &app,
            Method::POST,
            &format!("/v1/drafts/{draft_id}/send"),
            Some("tok_alice_send"),
            Some(json!({})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "/v1/drafts/{{id}}/send should reject {label}, got {status}: {body}"
        );
    }

    assert_eq!(
        sent_count.load(Ordering::SeqCst),
        0,
        "no spoofed or malformed raw From message may reach transport"
    );

    // Valid single authorized From: header succeeds via both Gmail send and /v1/drafts/{id}/send.
    let valid_raw = "From: Alice Example <alice@example.com>\r\nTo: ok@external.example\r\nSubject: Legit\r\n\r\nHello";
    let valid_draft_id = create_gmail_draft(&app, valid_raw).await;
    let (status, body) = http_req(
        &app,
        Method::POST,
        &format!("/v1/drafts/{valid_draft_id}/send"),
        Some("tok_alice_send"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "valid draft send failed: {body}");
    assert_eq!(sent_count.load(Ordering::SeqCst), 1);
}

// ============================================================================
// Finding 5: Approved sends re-check From auth and hard-deny policies at dispatch
// ============================================================================

#[tokio::test]
async fn finding5_approve_approval_rechecks_from_domain_and_hard_deny_policies() {
    let mut cfg = Config::for_test();
    cfg.user_email = "alice@example.com".to_string();
    cfg.default_domain = "example.com".to_string();
    cfg.require_approval = true;
    cfg.require_verified_from_domain = true;
    cfg.auth_tokens = vec!["tok_admin".to_string()];

    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    // Register and verify brand.example for Alice.
    store
        .create_domain(NewDomainInput {
            id: None,
            domain: "brand.example".to_string(),
            mailbox_id: "alice@example.com".to_string(),
            provider: DomainProviderKind::Manual,
            provider_domain_id: None,
            status: DomainStatus::Verified,
            dns_records: Vec::new(),
            dkim_verified: true,
            spf_verified: true,
            dmarc_verified: true,
            mx_verified: true,
            catch_all_mailbox: None,
            last_error: None,
        })
        .await
        .unwrap();

    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let (transport, sent_count, _) = RecordingTransport::new();
    let state = AppState::with_backends(cfg.clone(), store.clone(), resend)
        .with_transport(Arc::new(transport));
    let app = build_router(state.clone());

    // 1. Send from verified brand.example -> held for approval (202 Accepted).
    let (status, held) = http_req(
        &app,
        Method::POST,
        "/v1/messages/send",
        Some("tok_admin"),
        Some(json!({
            "from": "hello@brand.example",
            "to": ["recipient@partner.example"],
            "subject": "From brand",
            "text": "Body"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "held={held}");
    let approval_id = held["approval_id"].as_str().unwrap().to_string();

    // 2. Revoke / unverify brand.example while the approval sits pending.
    store
        .update_domain(
            "brand.example",
            &DomainUpdate {
                status: Some(DomainStatus::Pending),
                verified_at: Some(None),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // 3. Approving MUST now be rejected with 403 Forbidden and transport stays at 0 sends.
    let (status, body) = http_req(
        &app,
        Method::POST,
        &format!("/v1/approvals/{approval_id}/approve"),
        Some("tok_admin"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    assert_eq!(body["error"]["code"], "unverified_from_domain");
    assert_eq!(sent_count.load(Ordering::SeqCst), 0);

    // 4. Re-verify brand.example, then verify tightening allowed_recipients / DLP Deny blocks approval.
    store
        .update_domain(
            "brand.example",
            &DomainUpdate {
                status: Some(DomainStatus::Verified),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Rebuild AppState sharing the same store with stricter allowed_recipients & DLP Deny.
    let mut strict_cfg = cfg.clone();
    strict_cfg.allowed_recipients = vec!["@allowed-only.example".to_string()];
    strict_cfg.dlp_action = DlpAction::Deny;
    let strict_resend = Arc::new(HttpResendClient::from_config(&strict_cfg));
    let (strict_transport, strict_sent, _) = RecordingTransport::new();
    let strict_state = AppState::with_backends(strict_cfg, store.clone(), strict_resend)
        .with_transport(Arc::new(strict_transport));
    let strict_app = build_router(strict_state);

    let (status, body) = http_req(
        &strict_app,
        Method::POST,
        &format!("/v1/approvals/{approval_id}/approve"),
        Some("tok_admin"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    assert_eq!(strict_sent.load(Ordering::SeqCst), 0);

    // 5. With original config (and domain re-verified), approval succeeds despite require_approval=true.
    let (status, approved) = http_req(
        &app,
        Method::POST,
        &format!("/v1/approvals/{approval_id}/approve"),
        Some("tok_admin"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "approved={approved}");
    assert_eq!(sent_count.load(Ordering::SeqCst), 1);
}

// ============================================================================
// Finding 6: Compensating upstream delete on execute_create_domain DB failure
// ============================================================================

type DeletedDomains = Arc<Mutex<Vec<(String, Option<String>)>>>;

struct RacingCreateDomainProvider {
    store: Arc<dyn MailStore>,
    deleted: DeletedDomains,
}

#[async_trait]
impl DomainProvider for RacingCreateDomainProvider {
    fn provider_kind(&self) -> DomainProviderKind {
        DomainProviderKind::Resend
    }

    async fn create_domain(&self, domain: &str) -> AppResult<ProviderDomainResult> {
        // Simulate a concurrent writer inserting the same domain right after the pre-check
        // and before execute_create_domain's store.create_domain call.
        let _ = self
            .store
            .create_domain(NewDomainInput {
                id: None,
                domain: domain.to_string(),
                mailbox_id: "other@example.com".to_string(),
                provider: DomainProviderKind::Manual,
                provider_domain_id: None,
                status: DomainStatus::Pending,
                dns_records: Vec::new(),
                dkim_verified: false,
                spf_verified: false,
                dmarc_verified: false,
                mx_verified: false,
                catch_all_mailbox: None,
                last_error: None,
            })
            .await;

        Ok(ProviderDomainResult {
            provider_domain_id: Some("prov_orphan_123".to_string()),
            status: DomainStatus::Pending,
            dns_records: Vec::new(),
            dkim_verified: false,
            spf_verified: false,
            dmarc_verified: false,
            mx_verified: false,
            last_error: None,
        })
    }

    async fn get_verification_status(
        &self,
        _domain: &str,
        _provider_domain_id: Option<&str>,
    ) -> AppResult<ProviderDomainResult> {
        unreachable!()
    }

    async fn delete_domain(&self, domain: &str, provider_domain_id: Option<&str>) -> AppResult<()> {
        self.deleted.lock().unwrap().push((
            domain.to_string(),
            provider_domain_id.map(ToString::to_string),
        ));
        Ok(())
    }
}

#[tokio::test]
async fn finding6_execute_create_domain_compensates_upstream_delete_on_store_error() {
    let cfg = Config::for_test();
    let store: Arc<dyn MailStore> = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let deleted = Arc::new(Mutex::new(Vec::new()));
    let provider = Arc::new(RacingCreateDomainProvider {
        store: store.clone(),
        deleted: deleted.clone(),
    });
    let state = AppState::with_backends(cfg, store, resend).with_domain_provider(provider);

    let principal = Principal::full_access("alice@example.com");
    let err = execute_create_domain(
        &state,
        CreateDomainRequest {
            domain: "raced.example".to_string(),
            provider: Some(DomainProviderKind::Resend),
            mailbox_id: Some("alice@example.com".to_string()),
            catch_all_mailbox: None,
        },
        Some(&principal),
        "/v1",
    )
    .await
    .expect_err("store conflict must fail execute_create_domain");
    assert!(
        err.to_string().contains("already") || err.to_string().contains("exists"),
        "unexpected error: {err}"
    );

    let deletions = deleted.lock().unwrap().clone();
    assert_eq!(
        deletions,
        vec![(
            "raced.example".to_string(),
            Some("prov_orphan_123".to_string())
        )],
        "compensating provider.delete_domain must be invoked on store insert failure"
    );
}

// ============================================================================
// Finding 7: Duplicate [[sync.accounts]] validation error & fail-fast startup
// ============================================================================

#[test]
fn finding7_duplicate_sync_accounts_rejected_by_validation_and_serve_startup() {
    let mut cfg = Config::for_test();
    cfg.sync_accounts = vec![
        SyncAccountConfig {
            mailbox_id: "Alice@example.com".to_string(),
            ..Default::default()
        },
        SyncAccountConfig {
            mailbox_id: "alice@example.com".to_string(),
            ..Default::default()
        },
    ];

    let report = validate_config(&cfg, None, Default::default());
    assert!(!report.ok, "duplicate sync.accounts must fail validation");
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("duplicates mailbox_id 'alice@example.com'")),
        "expected duplicate error, got errors={:?} warnings={:?}",
        report.errors,
        report.warnings
    );

    // Also verify `nogml serve` fails fast at startup when nogml.toml has duplicate [[sync.accounts]].
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = dir.path().join("nogml.toml");
    std::fs::write(
        &cfg_path,
        r#"
[server]
bind = "127.0.0.1:0"

[storage]
backend = "memory"

[[sync.accounts]]
mailbox_id = "alice@example.com"
mode = "api"

[[sync.accounts]]
mailbox_id = "ALICE@example.com"
mode = "api"
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_nogml"))
        .arg("--config")
        .arg(&cfg_path)
        .arg("serve")
        .output()
        .expect("run nogml serve");
    assert!(
        !output.status.success(),
        "nogml serve must fail fast on duplicate [[sync.accounts]]"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("duplicates mailbox_id 'alice@example.com'"),
        "expected duplicate sync account error on startup, got: {combined}"
    );
}

// ============================================================================
// Finding 8: IMAP AUTHENTICATE PLAIN rejects unauthorized authzid for Admin
// ============================================================================

async fn read_imap_tagged_response(reader: &mut BufReader<TcpStream>, tag: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let prefix = format!("{tag} ");
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await.unwrap();
        assert!(n > 0, "unexpected EOF waiting for {tag}");
        lines.push(line.clone());
        if line.starts_with(&prefix) {
            break;
        }
    }
    lines
}

async fn send_imap_cmd(reader: &mut BufReader<TcpStream>, tag: &str, cmd: &str) -> Vec<String> {
    let full = format!("{tag} {cmd}\r\n");
    reader.get_mut().write_all(full.as_bytes()).await.unwrap();
    reader.get_mut().flush().await.unwrap();
    read_imap_tagged_response(reader, tag).await
}

#[tokio::test]
async fn finding8_imap_authenticate_plain_rejects_unauthorized_authzid_for_admin() {
    let mut cfg = Config::for_test();
    cfg.user_email = "alice@example.com".to_string();
    cfg.mailboxes = vec![
        "bob@example.com".to_string(),
        "shared@example.com".to_string(),
    ];
    cfg.scoped_tokens = vec![ScopedTokenConfig {
        token: "tok_alice_admin".to_string(),
        mailbox_id: Some("alice@example.com".to_string()),
        shared_mailboxes: vec!["shared@example.com".to_string()],
        scopes: vec![AuthScope::Admin],
        draft_only: None,
        allowed_recipients: None,
        max_send_recipients: None,
    }];

    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store, resend);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_handle = tokio::spawn(async move {
        let _ = imap::serve_plain_listener(listener, state, None, shutdown_rx).await;
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.unwrap();
    assert!(greeting.starts_with("* OK"), "greeting={greeting}");

    // 1. Admin principal passing unauthorized authzid=bob@example.com MUST get AUTHORIZATIONFAILED
    //    instead of silently logging into alice@example.com.
    let bad_b64 =
        general_purpose::STANDARD.encode("bob@example.com\0alice@example.com\0tok_alice_admin");
    let resp = send_imap_cmd(&mut reader, "A1", &format!("AUTHENTICATE PLAIN {bad_b64}")).await;
    assert!(
        resp.last().unwrap().contains("A1 NO [AUTHORIZATIONFAILED]"),
        "expected AUTHORIZATIONFAILED for unauthorized Admin authzid, got {resp:?}"
    );

    // 2. Admin principal passing authorized shared mailbox authzid=shared@example.com succeeds.
    let ok_b64 =
        general_purpose::STANDARD.encode("shared@example.com\0alice@example.com\0tok_alice_admin");
    let resp = send_imap_cmd(&mut reader, "A2", &format!("AUTHENTICATE PLAIN {ok_b64}")).await;
    assert!(
        resp.last().unwrap().starts_with("A2 OK"),
        "expected OK for authorized shared authzid, got {resp:?}"
    );

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}
