//! End-to-end tests for per-mailbox event-driven inbox rules and signed webhook triggers (`Issue #37`):
//! - Automatic label mutations (`add_labels`, `remove_labels`, `archive`, `mark_read`) + `MessageUpdated` event
//! - HMAC-SHA256 signed compact JSON webhook delivery (without raw MIME or attachment payloads)
//! - Resend webhook inbound delivery, `ingest_inbound_rfc2822`, Gmail sync ingest, and IMAP `APPEND`
//! - `vip_only: true` gating against the per-mailbox contact graph
//! - Non-blocking warning-only behavior on 500 and unreachable webhooks (never failing storage)
//! - Non-firing on outbound `SENT` and `DRAFT` messages
//! - `POST /v1/rules/{id}/test` dry-run without mutating labels or firing webhooks
//! - Validation, secret redaction, scopes, and MCP `create_rule` / `list_rules` / `delete_rule`

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use nogml::{
    AppState,
    ai::rules::{
        RULE_MATCHED_EVENT, WEBHOOK_EVENT_HEADER, WEBHOOK_SIGNATURE_HEADER,
        compute_webhook_signature,
    },
    auth::{AuthScope, ScopedTokenConfig},
    build_router,
    config::Config,
    error::AppResult,
    events::MailEvent,
    mime::{ComposeEmailInput, build_rfc2822},
    models::{LABEL_DRAFT, LABEL_INBOX, LABEL_SENT, LABEL_UNREAD},
    resend::{HttpResendClient, svix},
    storage::{NewAttachmentInput, NewMessageInput, SqliteStore},
    sync::{PullReport, ingest_synced_message},
    transport::{
        InboundEnvelope, IngestOutcome, MailTransport, OutboundMessage, SendOutcome,
        TransportCapabilities, ingest_inbound_rfc2822_with_config,
    },
};

struct RecordingTransport {
    sent: Arc<Mutex<Vec<OutboundMessage>>>,
}

impl RecordingTransport {
    fn new() -> Self {
        Self {
            sent: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl MailTransport for RecordingTransport {
    fn name(&self) -> &'static str {
        "recording_test"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            provider: "recording_test".to_string(),
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
        let mut guard = self.sent.lock().unwrap();
        guard.push(msg.clone());
        let n = guard.len();
        Ok(SendOutcome {
            provider: "recording_test".to_string(),
            provider_message_id: format!("rec_{n}"),
        })
    }
}

async fn send_json(
    app: &Router,
    method: Method,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(tok) = token {
        builder = builder.header("authorization", format!("Bearer {tok}"));
    }
    let req = if let Some(payload) = body {
        builder
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap()
    } else {
        builder.body(Body::empty()).unwrap()
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let val = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, val)
}

async fn wait_for_requests(server: &MockServer, expected: usize) -> Vec<wiremock::Request> {
    for _ in 0..80 {
        let reqs = server.received_requests().await.unwrap_or_default();
        if reqs.len() >= expected {
            return reqs;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    server.received_requests().await.unwrap_or_default()
}

fn build_state(mut cfg: Config) -> (AppState, Router) {
    cfg.user_email = "agent@example.com".to_string();
    cfg.allow_private_endpoints = true;
    let store = Arc::new(SqliteStore::open_in_memory(&cfg.user_email).unwrap());
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store, resend)
        .with_transport(Arc::new(RecordingTransport::new()));
    let router = build_router(state.clone());
    (state, router)
}

#[tokio::test]
async fn stripe_dispute_rule_mutates_labels_and_posts_signed_compact_webhook() {
    let hook_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/disputes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&hook_server)
        .await;

    let (state, app) = build_state(Config::for_test());
    let secret = "whsec_stripe_rule_secret_123";
    let hook_url = format!("{}/disputes", hook_server.uri());

    // 1. Create rule via POST /v1/rules and verify webhook_secret is redacted.
    let (status, created) = send_json(
        &app,
        Method::POST,
        "/v1/rules",
        None,
        Some(json!({
            "name": "Stripe Disputes",
            "enabled": true,
            "match_query": "from:@stripe.com subject:dispute",
            "vip_only": false,
            "actions": {
                "add_labels": ["Disputes"],
                "remove_labels": [],
                "archive": true,
                "mark_read": true,
                "webhook_url": hook_url,
                "webhook_secret": secret
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create rule failed: {created}");
    let rule_id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["actions"]["has_webhook_secret"], true);
    assert!(created["actions"].get("webhook_secret").is_none());
    assert!(!created.to_string().contains(secret));

    // Verify GET /v1/rules also redacts webhook_secret.
    let (status, listed) = send_json(&app, Method::GET, "/v1/rules", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["count"], 1);
    assert_eq!(listed["rules"][0]["id"], rule_id);
    assert_eq!(listed["rules"][0]["actions"]["has_webhook_secret"], true);
    assert!(
        listed["rules"][0]["actions"]
            .get("webhook_secret")
            .is_none()
    );
    assert!(!listed.to_string().contains(secret));

    // 2. Subscribe to EventBus to verify MessageUpdated is emitted when rule mutates labels.
    let mut rx = state.events.subscribe();

    // 3. Deliver a matching Stripe dispute email WITH an attachment via ingest_inbound_rfc2822.
    let raw_match = build_rfc2822(&ComposeEmailInput {
        from: "Stripe Disputes <disputes@stripe.com>".to_string(),
        to: vec!["agent@example.com".to_string()],
        subject: "Action required: Payment dispute dp_12345".to_string(),
        text: Some("Customer filed a dispute for $49.00.".to_string()),
        message_id: Some("<dp-12345@stripe.com>".to_string()),
        attachments: vec![NewAttachmentInput {
            part_id: "2".to_string(),
            filename: Some("evidence.pdf".to_string()),
            content_type: "application/pdf".to_string(),
            content_id: None,
            data: b"SECRET_BINARY_ATTACHMENT_BYTES".to_vec(),
        }],
        ..Default::default()
    })
    .unwrap();

    let outcome = ingest_inbound_rfc2822_with_config(
        state.store.as_ref(),
        &state.events,
        state.filter.as_ref(),
        InboundEnvelope {
            raw_rfc2822: raw_match,
            source: "resend_inbound".to_string(),
            ..Default::default()
        },
        &state.config,
    )
    .await
    .unwrap();

    let stored_msg = match outcome {
        IngestOutcome::Stored { message, .. } => message,
        other => panic!("expected Stored, got {other:?}"),
    };

    // Rule added "Disputes", archived (removed INBOX), and marked read (removed UNREAD).
    let labels = state.store.list_labels().await.unwrap();
    let disputes_label = labels
        .iter()
        .find(|l| l.name == "Disputes")
        .expect("Disputes label should be auto-created");
    assert!(
        stored_msg.label_ids.contains(&disputes_label.id),
        "expected Disputes label on stored message, got {:?}",
        stored_msg.label_ids
    );
    assert!(!stored_msg.label_ids.contains(&LABEL_INBOX.to_string()));
    assert!(!stored_msg.label_ids.contains(&LABEL_UNREAD.to_string()));

    // Verify MessageReceived followed by MessageUpdated on EventBus.
    let mut saw_updated = false;
    for _ in 0..4 {
        if let Ok(Ok(env)) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await
            && let MailEvent::MessageUpdated {
                message_id,
                added_labels,
                removed_labels,
                ..
            } = env.event
        {
            assert_eq!(message_id, stored_msg.id);
            assert!(added_labels.contains(&disputes_label.id));
            assert!(removed_labels.contains(&LABEL_INBOX.to_string()));
            assert!(removed_labels.contains(&LABEL_UNREAD.to_string()));
            saw_updated = true;
            break;
        }
    }
    assert!(saw_updated, "expected MailEvent::MessageUpdated from rule");

    // 4. Deliver a non-matching message from Stripe (different subject): must NOT trigger rule.
    let raw_other = build_rfc2822(&ComposeEmailInput {
        from: "Stripe <receipts@stripe.com>".to_string(),
        to: vec!["agent@example.com".to_string()],
        subject: "Monthly statement ready".to_string(),
        text: Some("Your statement is available.".to_string()),
        message_id: Some("<stmt-1@stripe.com>".to_string()),
        ..Default::default()
    })
    .unwrap();
    let other_outcome = ingest_inbound_rfc2822_with_config(
        state.store.as_ref(),
        &state.events,
        state.filter.as_ref(),
        InboundEnvelope {
            raw_rfc2822: raw_other,
            source: "resend_inbound".to_string(),
            ..Default::default()
        },
        &state.config,
    )
    .await
    .unwrap();
    let other_msg = match other_outcome {
        IngestOutcome::Stored { message, .. } => message,
        other => panic!("expected Stored, got {other:?}"),
    };
    assert!(other_msg.label_ids.contains(&LABEL_INBOX.to_string()));
    assert!(other_msg.label_ids.contains(&LABEL_UNREAD.to_string()));
    assert!(!other_msg.label_ids.contains(&disputes_label.id));

    // 5. Verify signed webhook received exactly 1 request with valid HMAC-SHA256 and compact body.
    let reqs = wait_for_requests(&hook_server, 1).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let reqs_after = hook_server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs_after.len(), 1);

    let req = &reqs[0];
    let event_hdr = req
        .headers
        .get(WEBHOOK_EVENT_HEADER)
        .and_then(|v| v.to_str().ok());
    assert_eq!(event_hdr, Some(RULE_MATCHED_EVENT));

    let sig_hdr = req
        .headers
        .get(WEBHOOK_SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .expect("missing X-Nogml-Signature header");
    let expected_sig = compute_webhook_signature(secret, &req.body);
    assert_eq!(sig_hdr, expected_sig);

    let body_str = std::str::from_utf8(&req.body).unwrap();
    assert!(
        !body_str.contains("SECRET_BINARY_ATTACHMENT_BYTES"),
        "webhook must never leak attachment bytes"
    );
    let payload: Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(payload["event"], "rule.matched");
    assert_eq!(payload["rule_id"], rule_id);
    assert_eq!(payload["rule_name"], "Stripe Disputes");
    assert_eq!(payload["mailbox_id"], "agent@example.com");
    assert_eq!(payload["message"]["id"], stored_msg.id);
    assert_eq!(payload["message"]["thread_id"], stored_msg.thread_id);
    assert_eq!(payload["message"]["from"]["email"], "disputes@stripe.com");
    assert_eq!(payload["message"]["unread"], false);
    assert_eq!(payload["message"]["has_attachments"], true);
    assert!(payload["message"].get("raw").is_none());
    assert!(payload["message"].get("raw_rfc2822").is_none());
    assert!(payload["message"].get("attachments_meta").is_none());
    assert!(payload["message"].get("attachments_text").is_none());
}

#[tokio::test]
async fn resend_webhook_inbound_triggers_inbox_rule() {
    let resend_api = MockServer::start().await;
    let rule_hook = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/stripe-hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&rule_hook)
        .await;

    let raw_mime = "From: Stripe <alerts@stripe.com>\r\n\
                    To: agent@example.com\r\n\
                    Subject: Urgent dispute opened\r\n\
                    Message-ID: <resend-dispute-1@stripe.com>\r\n\
                    \r\n\
                    Dispute details inside.\r\n";

    Mock::given(method("GET"))
        .and(path("/emails/receiving/re_in_1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "re_in_1",
            "from": "Stripe <alerts@stripe.com>",
            "to": ["agent@example.com"],
            "subject": "Urgent dispute opened",
            "text": "Dispute details inside.",
            "message_id": "<resend-dispute-1@stripe.com>",
            "raw": { "download_url": format!("{}/raw/re_in_1.eml", resend_api.uri()) }
        })))
        .mount(&resend_api)
        .await;

    Mock::given(method("GET"))
        .and(path("/raw/re_in_1.eml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(raw_mime))
        .mount(&resend_api)
        .await;

    let whsec = format!(
        "whsec_{}",
        general_purpose::STANDARD.encode(b"resend_test_key")
    );
    let mut cfg = Config::for_test();
    cfg.resend_base_url = resend_api.uri();
    cfg.resend_api_key = Some("re_test_key".to_string());
    cfg.resend_webhook_secret = Some(whsec.clone());
    let (state, app) = build_state(cfg);

    let (status, _) = send_json(
        &app,
        Method::POST,
        "/v1/rules",
        None,
        Some(json!({
            "name": "Resend Stripe Rule",
            "match_query": "from:@stripe.com subject:dispute",
            "actions": {
                "add_labels": ["BillingDispute"],
                "archive": true,
                "webhook_url": format!("{}/stripe-hook", rule_hook.uri()),
                "webhook_secret": "rule_hmac_key"
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Send Svix-signed Resend webhook event.
    let event_body = json!({
        "type": "email.received",
        "created_at": "2026-11-26T00:00:00Z",
        "data": {
            "email_id": "re_in_1",
            "from": "Stripe <alerts@stripe.com>",
            "to": ["agent@example.com"],
            "subject": "Urgent dispute opened"
        }
    })
    .to_string();
    let msg_id = "msg_svix_1";
    let ts = chrono::Utc::now().timestamp();
    let sig = svix::sign_svix_payload(msg_id, ts, event_body.as_bytes(), &whsec).unwrap();

    let req = Request::builder()
        .method(Method::POST)
        .uri("/webhooks/resend")
        .header("content-type", "application/json")
        .header("svix-id", msg_id)
        .header("svix-timestamp", ts.to_string())
        .header("svix-signature", sig)
        .body(Body::from(event_body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let resp_json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(resp_json["status"], "received");
    let stored_id = resp_json["message_id"].as_str().unwrap();

    let stored = state.store.get_message(stored_id).await.unwrap().unwrap();
    assert!(!stored.label_ids.contains(&LABEL_INBOX.to_string()));
    assert!(
        state
            .store
            .list_labels()
            .await
            .unwrap()
            .iter()
            .any(|l| l.name == "BillingDispute" && stored.label_ids.contains(&l.id))
    );

    let reqs = wait_for_requests(&rule_hook, 1).await;
    assert_eq!(reqs.len(), 1);
    let expected = compute_webhook_signature("rule_hmac_key", &reqs[0].body);
    assert_eq!(
        reqs[0]
            .headers
            .get(WEBHOOK_SIGNATURE_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some(expected.as_str())
    );
}

#[tokio::test]
async fn vip_only_rule_fires_only_for_vip_senders() {
    let hook_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/vip"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&hook_server)
        .await;

    let (state, app) = build_state(Config::for_test());

    // Create a vip_only rule (with empty match_query -> matches any mail from a VIP).
    let (status, created) = send_json(
        &app,
        Method::POST,
        "/v1/rules",
        None,
        Some(json!({
            "name": "VIP Wakeup",
            "match_query": "",
            "vip_only": true,
            "actions": {
                "add_labels": ["STARRED"],
                "webhook_url": format!("{}/vip", hook_server.uri())
            }
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "failed to create vip_only rule: {created}"
    );

    // Non-VIP sender must NOT trigger the rule.
    let raw_non_vip = build_rfc2822(&ComposeEmailInput {
        from: "Random Person <random@example.com>".to_string(),
        to: vec!["agent@example.com".to_string()],
        subject: "Checking in".to_string(),
        text: Some("Hi there".to_string()),
        message_id: Some("<non-vip-1@example.com>".to_string()),
        ..Default::default()
    })
    .unwrap();
    let non_vip_res = ingest_inbound_rfc2822_with_config(
        state.store.as_ref(),
        &state.events,
        state.filter.as_ref(),
        InboundEnvelope {
            raw_rfc2822: raw_non_vip,
            source: "resend_inbound".to_string(),
            ..Default::default()
        },
        &state.config,
    )
    .await
    .unwrap();
    let non_vip_msg = match non_vip_res {
        IngestOutcome::Stored { message, .. } => message,
        other => panic!("expected Stored, got {other:?}"),
    };
    assert!(!non_vip_msg.label_ids.contains(&"STARRED".to_string()));

    // Promote ceo@acme.com to VIP via PATCH /v1/contacts/{email}.
    let (status, patched_contact) = send_json(
        &app,
        Method::PATCH,
        "/v1/contacts/ceo@acme.com",
        None,
        Some(json!({ "is_vip": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(patched_contact["is_vip"], true);

    // VIP sender MUST trigger the rule.
    let raw_vip = build_rfc2822(&ComposeEmailInput {
        from: "Acme CEO <ceo@acme.com>".to_string(),
        to: vec!["agent@example.com".to_string()],
        subject: "Board deck review".to_string(),
        text: Some("Please review ASAP.".to_string()),
        message_id: Some("<vip-1@acme.com>".to_string()),
        ..Default::default()
    })
    .unwrap();
    let vip_res = ingest_inbound_rfc2822_with_config(
        state.store.as_ref(),
        &state.events,
        state.filter.as_ref(),
        InboundEnvelope {
            raw_rfc2822: raw_vip,
            source: "resend_inbound".to_string(),
            ..Default::default()
        },
        &state.config,
    )
    .await
    .unwrap();
    let vip_msg = match vip_res {
        IngestOutcome::Stored { message, .. } => message,
        other => panic!("expected Stored, got {other:?}"),
    };
    assert!(vip_msg.label_ids.contains(&"STARRED".to_string()));

    let reqs = wait_for_requests(&hook_server, 1).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let all_reqs = hook_server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(all_reqs.len(), 1);
    let body: Value = serde_json::from_slice(&reqs[0].body).unwrap();
    assert_eq!(body["message"]["id"], vip_msg.id);
    assert_eq!(body["message"]["from"]["email"], "ceo@acme.com");
}

#[tokio::test]
async fn failing_and_unreachable_webhooks_never_fail_message_storage() {
    let failing_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/always-500"))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream boom"))
        .mount(&failing_server)
        .await;

    // Bind and immediately drop a TCP listener to obtain an unreachable local port.
    let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead_listener.local_addr().unwrap().port();
    drop(dead_listener);

    let (state, app) = build_state(Config::for_test());

    let (s1, _) = send_json(
        &app,
        Method::POST,
        "/v1/rules",
        None,
        Some(json!({
            "name": "500 Webhook Rule",
            "match_query": "from:@vendor.test",
            "actions": {
                "add_labels": ["Vendor500"],
                "webhook_url": format!("{}/always-500", failing_server.uri())
            }
        })),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);

    let (s2, _) = send_json(
        &app,
        Method::POST,
        "/v1/rules",
        None,
        Some(json!({
            "name": "Unreachable Webhook Rule",
            "match_query": "from:@vendor.test",
            "actions": {
                "add_labels": ["VendorDead"],
                "webhook_url": format!("http://127.0.0.1:{dead_port}/unreachable")
            }
        })),
    )
    .await;
    assert_eq!(s2, StatusCode::OK);

    let raw = build_rfc2822(&ComposeEmailInput {
        from: "Billing <billing@vendor.test>".to_string(),
        to: vec!["agent@example.com".to_string()],
        subject: "Invoice #99".to_string(),
        text: Some("Attached invoice.".to_string()),
        message_id: Some("<vendor-99@vendor.test>".to_string()),
        ..Default::default()
    })
    .unwrap();

    // Storage succeeds immediately even though both webhooks fail.
    let outcome = ingest_inbound_rfc2822_with_config(
        state.store.as_ref(),
        &state.events,
        state.filter.as_ref(),
        InboundEnvelope {
            raw_rfc2822: raw,
            source: "resend_inbound".to_string(),
            ..Default::default()
        },
        &state.config,
    )
    .await
    .unwrap();

    let stored = match outcome {
        IngestOutcome::Stored { message, .. } => message,
        other => panic!("expected Stored despite failing webhooks, got {other:?}"),
    };
    let fetched = state.store.get_message(&stored.id).await.unwrap().unwrap();
    assert_eq!(fetched.id, stored.id);

    // Both labels were applied despite webhook failures.
    let labels = state.store.list_labels().await.unwrap();
    for expected_name in ["Vendor500", "VendorDead"] {
        let lbl = labels
            .iter()
            .find(|l| l.name == expected_name)
            .unwrap_or_else(|| panic!("missing label {expected_name}"));
        assert!(fetched.label_ids.contains(&lbl.id));
    }

    // Verify the 500 webhook was attempted 1 initial + 2 retries = 3 times.
    let reqs = wait_for_requests(&failing_server, 3).await;
    assert_eq!(reqs.len(), 3, "expected 1 initial + 2 retries on 500");
}

#[tokio::test]
async fn sent_and_draft_messages_never_trigger_rules_while_sync_and_imap_append_do() {
    let hook_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/events"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&hook_server)
        .await;

    let (state, app) = build_state(Config::for_test());

    let (status, _) = send_json(
        &app,
        Method::POST,
        "/v1/rules",
        None,
        Some(json!({
            "name": "Match All Keyword",
            "match_query": "subject:trigger-rule",
            "actions": {
                "add_labels": ["Triggered"],
                "webhook_url": format!("{}/events", hook_server.uri())
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 1. Outbound send via POST /v1/messages/send MUST NOT trigger rule.
    let (status, sent_body) = send_json(
        &app,
        Method::POST,
        "/v1/messages/send",
        None,
        Some(json!({
            "to": ["recipient@example.com"],
            "subject": "trigger-rule outbound send",
            "text": "Should not fire inbox rules"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "send failed: {sent_body}");

    // 2. Draft creation via POST /v1/drafts MUST NOT trigger rule.
    let (status, draft_body) = send_json(
        &app,
        Method::POST,
        "/v1/drafts",
        None,
        Some(json!({
            "to": ["recipient@example.com"],
            "subject": "trigger-rule local draft",
            "text": "Should not fire inbox rules"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "draft failed: {draft_body}");

    // 3. Synced SENT message MUST NOT trigger rule, while synced INBOX message MUST trigger rule.
    let mut report = PullReport::default();
    let synced_sent = ingest_synced_message(
        &state,
        NewMessageInput {
            id: None,
            thread_id: None,
            label_ids: vec![LABEL_SENT.to_string()],
            raw_rfc2822: b"From: agent@example.com\r\nTo: peer@example.com\r\nSubject: trigger-rule synced sent\r\n\r\nBody".to_vec(),
            snippet: "Body".to_string(),
            internal_date_ms: 1_700_000_001_000,
            subject: "trigger-rule synced sent".to_string(),
            from_addr: "agent@example.com".to_string(),
            to_addrs: vec!["peer@example.com".to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: "Body".to_string(),
            html_body: None,
            rfc822_message_id: Some("<sync-sent-1@example.com>".to_string()),
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id: Some("up_sent_1".to_string()),
            upstream_thread_id: None,
            source: "gmail_api".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: vec![],
        },
        &mut report,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        !synced_sent
            .message
            .label_ids
            .iter()
            .any(|l| l == "Triggered")
    );

    let synced_inbox = ingest_synced_message(
        &state,
        NewMessageInput {
            id: None,
            thread_id: None,
            label_ids: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            raw_rfc2822: b"From: alice@external.test\r\nTo: agent@example.com\r\nSubject: trigger-rule synced inbox\r\n\r\nHello".to_vec(),
            snippet: "Hello".to_string(),
            internal_date_ms: 1_700_000_002_000,
            subject: "trigger-rule synced inbox".to_string(),
            from_addr: "alice@external.test".to_string(),
            to_addrs: vec!["agent@example.com".to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: "Hello".to_string(),
            html_body: None,
            rfc822_message_id: Some("<sync-inbox-1@external.test>".to_string()),
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id: Some("up_inbox_1".to_string()),
            upstream_thread_id: None,
            source: "gmail_api".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: vec![],
        },
        &mut report,
    )
    .await
    .unwrap()
    .unwrap();
    let labels = state.store.list_labels().await.unwrap();
    let triggered_label = labels
        .iter()
        .find(|l| l.name == "Triggered")
        .expect("Triggered label created by sync ingest rule");
    assert!(synced_inbox.message.label_ids.contains(&triggered_label.id));

    // 4. IMAP APPEND into INBOX triggers rule; IMAP APPEND into Drafts does NOT.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let imap_state = state.clone();
    let imap_task = tokio::spawn(async move {
        let _ = nogml::imap::serve_plain_listener(listener, imap_state, None, shutdown_rx).await;
    });

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (read_half, mut write_half) = tcp.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    // Greeting
    reader.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("* OK"));

    // LOGIN (dev mode open auth)
    write_half
        .write_all(b"a1 LOGIN \"agent@example.com\" \"any\"\r\n")
        .await
        .unwrap();
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line.starts_with("a1 ") {
            assert!(line.starts_with("a1 OK"), "login failed: {line}");
            break;
        }
    }

    // APPEND to INBOX -> should trigger rule
    let imap_msg = b"From: bob@imap.test\r\nTo: agent@example.com\r\nSubject: trigger-rule imap append\r\nMessage-ID: <imap-append-1@imap.test>\r\n\r\nVia IMAP\r\n";
    write_half
        .write_all(format!("a2 APPEND INBOX {{{}}}\r\n", imap_msg.len()).as_bytes())
        .await
        .unwrap();
    line.clear();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.starts_with('+'), "expected continuation, got: {line}");
    write_half.write_all(imap_msg).await.unwrap();
    write_half.write_all(b"\r\n").await.unwrap();
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line.starts_with("a2 ") {
            assert!(line.starts_with("a2 OK"), "append failed: {line}");
            break;
        }
    }

    // APPEND with \Draft flag -> must NOT trigger rule
    let imap_draft = b"From: agent@example.com\r\nTo: peer@imap.test\r\nSubject: trigger-rule imap draft\r\nMessage-ID: <imap-draft-1@imap.test>\r\n\r\nDraft body\r\n";
    write_half
        .write_all(
            format!(
                "a3 APPEND \"[Gmail]/Drafts\" (\\Draft) {{{}}}\r\n",
                imap_draft.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    line.clear();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.starts_with('+'));
    write_half.write_all(imap_draft).await.unwrap();
    write_half.write_all(b"\r\n").await.unwrap();
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line.starts_with("a3 ") {
            assert!(line.starts_with("a3 OK"), "draft append failed: {line}");
            break;
        }
    }
    write_half.write_all(b"a4 LOGOUT\r\n").await.unwrap();
    let _ = shutdown_tx.send(true);
    let _ = imap_task.await;

    // Verify IMAP INBOX message got the label, and IMAP Draft did not.
    let imap_stored = state
        .store
        .find_message_by_rfc_message_id("<imap-append-1@imap.test>")
        .await
        .unwrap()
        .unwrap();
    assert!(imap_stored.label_ids.contains(&triggered_label.id));
    let imap_draft_stored = state
        .store
        .find_message_by_rfc_message_id("<imap-draft-1@imap.test>")
        .await
        .unwrap()
        .unwrap();
    assert!(
        imap_draft_stored
            .label_ids
            .contains(&LABEL_DRAFT.to_string())
    );
    assert!(!imap_draft_stored.label_ids.contains(&triggered_label.id));

    // Exactly 2 webhook deliveries: synced INBOX + IMAP APPEND INBOX (0 from send/draft/synced-sent/imap-draft).
    let reqs = wait_for_requests(&hook_server, 2).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let all_reqs = hook_server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 2);
    assert_eq!(all_reqs.len(), 2);
}

#[tokio::test]
async fn dry_run_test_validation_patch_scopes_and_mcp_tools() {
    let hook_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/never-called"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&hook_server)
        .await;

    let mut cfg = Config::for_test();
    cfg.scoped_tokens = vec![
        ScopedTokenConfig {
            token: "tok_read".to_string(),
            mailbox_id: Some("agent@example.com".to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_write".to_string(),
            mailbox_id: Some("agent@example.com".to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read, AuthScope::Write],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_admin".to_string(),
            mailbox_id: Some("agent@example.com".to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read, AuthScope::Write, AuthScope::Admin],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
    ];
    let (state, app) = build_state(cfg);

    // Seed 3 messages before creating any rules.
    let m1 = state
        .store
        .insert_message(NewMessageInput {
            id: Some("m_dispute_1".to_string()),
            thread_id: None,
            label_ids: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            raw_rfc2822: b"From: disputes@stripe.com\r\nTo: agent@example.com\r\nSubject: New dispute #1\r\n\r\nDispute body 1".to_vec(),
            snippet: "Dispute body 1".to_string(),
            internal_date_ms: 1_700_000_010_000,
            subject: "New dispute #1".to_string(),
            from_addr: "Stripe <disputes@stripe.com>".to_string(),
            to_addrs: vec!["agent@example.com".to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: "Dispute body 1".to_string(),
            html_body: None,
            rfc822_message_id: None,
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "resend_inbound".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: vec![],
        })
        .await
        .unwrap();

    let _m2 = state
        .store
        .insert_message(NewMessageInput {
            id: Some("m_other_2".to_string()),
            thread_id: None,
            label_ids: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            raw_rfc2822: b"From: news@example.com\r\nTo: agent@example.com\r\nSubject: Weekly digest\r\n\r\nDigest".to_vec(),
            snippet: "Digest".to_string(),
            internal_date_ms: 1_700_000_020_000,
            subject: "Weekly digest".to_string(),
            from_addr: "News <news@example.com>".to_string(),
            to_addrs: vec!["agent@example.com".to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: "Digest".to_string(),
            html_body: None,
            rfc822_message_id: None,
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "resend_inbound".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: vec![],
        })
        .await
        .unwrap();

    // Validation errors on POST /v1/rules
    let (status, _) = send_json(
        &app,
        Method::POST,
        "/v1/rules",
        Some("tok_write"),
        Some(json!({
            "name": "Bad Query",
            "match_query": "(from:@stripe.com",
            "actions": {}
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = send_json(
        &app,
        Method::POST,
        "/v1/rules",
        Some("tok_write"),
        Some(json!({
            "name": "Empty Query Non-VIP",
            "match_query": "   ",
            "vip_only": false,
            "actions": {}
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Write-only token cannot set webhook_url (requires Admin scope).
    let (status, _) = send_json(
        &app,
        Method::POST,
        "/v1/rules",
        Some("tok_write"),
        Some(json!({
            "name": "Write Webhook Denied",
            "match_query": "from:@stripe.com",
            "actions": { "webhook_url": format!("{}/never-called", hook_server.uri()) }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Admin token gets SSRF policy rejection on unsupported scheme.
    let (status, _) = send_json(
        &app,
        Method::POST,
        "/v1/rules",
        Some("tok_admin"),
        Some(json!({
            "name": "Bad Scheme",
            "match_query": "from:@stripe.com",
            "actions": { "webhook_url": "ftp://hooks.example.com/bad" }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Read-only token cannot create rule
    let (status, _) = send_json(
        &app,
        Method::POST,
        "/v1/rules",
        Some("tok_read"),
        Some(json!({
            "name": "Denied",
            "match_query": "from:@stripe.com",
            "actions": {}
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Admin token creates rule with webhook_url
    let (status, created) = send_json(
        &app,
        Method::POST,
        "/v1/rules",
        Some("tok_admin"),
        Some(json!({
            "name": "Dry Run Stripe",
            "match_query": "from:@stripe.com subject:dispute",
            "actions": {
                "add_labels": ["Disputes"],
                "archive": true,
                "mark_read": true,
                "webhook_url": format!("{}/never-called", hook_server.uri()),
                "webhook_secret": "keep_me_hidden"
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rule_id = created["id"].as_str().unwrap().to_string();

    // Read-only token CAN list rules and dry-run POST /v1/rules/{id}/test!
    let (status, test_res) = send_json(
        &app,
        Method::POST,
        &format!("/v1/rules/{rule_id}/test?limit=20"),
        Some("tok_read"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "test rule failed: {test_res}");
    assert_eq!(test_res["rule_id"], rule_id);
    assert_eq!(test_res["matched_count"], 1);
    let matched = test_res["matched_messages"].as_array().unwrap();
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0]["id"], m1.id);
    assert_eq!(matched[0]["thread_id"], m1.thread_id);
    assert_eq!(matched[0]["from"], "Stripe <disputes@stripe.com>");
    assert_eq!(matched[0]["subject"], "New dispute #1");
    assert_eq!(matched[0]["snippet"], "Dispute body 1");

    // Dry-run MUST NOT mutate labels or fire webhooks.
    let m1_after = state.store.get_message(&m1.id).await.unwrap().unwrap();
    assert!(m1_after.label_ids.contains(&LABEL_INBOX.to_string()));
    assert!(m1_after.label_ids.contains(&LABEL_UNREAD.to_string()));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(hook_server.received_requests().await.unwrap().is_empty());

    // Write-only token cannot toggle enabled or match_query on an existing webhook rule.
    let (status, _) = send_json(
        &app,
        Method::PATCH,
        &format!("/v1/rules/{rule_id}"),
        Some("tok_write"),
        Some(json!({ "name": "Hijack Attempt", "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Admin PATCH rule updates name/enabled and preserves secret (still redacted).
    let (status, patched) = send_json(
        &app,
        Method::PATCH,
        &format!("/v1/rules/{rule_id}"),
        Some("tok_admin"),
        Some(json!({ "name": "Renamed Stripe", "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(patched["name"], "Renamed Stripe");
    assert_eq!(patched["enabled"], false);
    assert_eq!(patched["actions"]["has_webhook_secret"], true);
    assert!(!patched.to_string().contains("keep_me_hidden"));

    // MCP create_rule with webhook_url requires Admin scope (Write-only token is forbidden).
    let (status, _) = send_json(
        &app,
        Method::POST,
        "/mcp",
        Some("tok_write"),
        Some(json!({
            "jsonrpc": "2.0",
            "id": 100,
            "method": "tools/call",
            "params": {
                "name": "create_rule",
                "arguments": {
                    "name": "MCP Write Denied",
                    "match_query": "from:@billing.test",
                    "webhook_url": "https://hooks.example.com/mcp"
                }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // MCP create_rule / list_rules / delete_rule (Admin token can set webhook_url)
    let (status, mcp_create) = send_json(
        &app,
        Method::POST,
        "/mcp",
        Some("tok_admin"),
        Some(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "create_rule",
                "arguments": {
                    "name": "MCP Billing Rule",
                    "match_query": "from:@billing.test",
                    "add_labels": ["Billing"],
                    "archive": true,
                    "webhook_url": "https://hooks.example.com/mcp",
                    "webhook_secret": "mcp_secret_val"
                }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mcp_create["result"]["isError"], false);
    let mcp_rule_id = mcp_create["result"]["structuredContent"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        mcp_create["result"]["structuredContent"]["actions"]["has_webhook_secret"],
        true
    );
    assert!(!mcp_create.to_string().contains("mcp_secret_val"));

    // Read-only token can call MCP list_rules, but is forbidden from MCP create_rule / delete_rule
    let (status, mcp_list) = send_json(
        &app,
        Method::POST,
        "/mcp",
        Some("tok_read"),
        Some(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "list_rules", "arguments": {} }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mcp_list["result"]["structuredContent"]["count"], 2);
    assert!(!mcp_list.to_string().contains("mcp_secret_val"));
    assert!(!mcp_list.to_string().contains("keep_me_hidden"));

    let (status, _) = send_json(
        &app,
        Method::POST,
        "/mcp",
        Some("tok_read"),
        Some(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "delete_rule",
                "arguments": { "rule_id": mcp_rule_id }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Write token deletes via MCP delete_rule and REST DELETE /v1/rules/{id}
    let (status, mcp_del) = send_json(
        &app,
        Method::POST,
        "/mcp",
        Some("tok_write"),
        Some(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "delete_rule",
                "arguments": { "rule_id": mcp_rule_id }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mcp_del["result"]["structuredContent"]["deleted"], true);

    let (status, rest_del) = send_json(
        &app,
        Method::DELETE,
        &format!("/v1/rules/{rule_id}"),
        Some("tok_write"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rest_del["deleted"], true);

    // Confirm empty list and 404 on deleting again
    let (status, final_list) =
        send_json(&app, Method::GET, "/v1/rules", Some("tok_read"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(final_list["count"], 0);

    let (status, _) = send_json(
        &app,
        Method::DELETE,
        &format!("/v1/rules/{rule_id}"),
        Some("tok_write"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
