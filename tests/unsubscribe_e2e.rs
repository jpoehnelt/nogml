//! End-to-end tests for RFC 2369/8058 unsubscribe header detection, SSRF protection,
//! `POST /v1/messages/{id}/unsubscribe`, and MCP `unsubscribe` (`Issue #31`).

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use nogml::{
    AppState,
    auth::{AuthScope, ScopedTokenConfig},
    build_router,
    config::{Config, DraftOnlyAction},
    error::AppResult,
    models::LABEL_INBOX,
    resend::HttpResendClient,
    storage::{MailStore, MemoryStore, NewMessageInput},
    transport::{MailTransport, OutboundMessage, SendOutcome, TransportCapabilities},
};

type SentLog = Arc<Mutex<Vec<(OutboundMessage, Option<String>)>>>;

struct RecordingTransport {
    sent: SentLog,
}

impl RecordingTransport {
    fn new() -> (Self, SentLog) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (Self { sent: sent.clone() }, sent)
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
        idempotency_key: Option<&str>,
    ) -> AppResult<SendOutcome> {
        let mut guard = self.sent.lock().unwrap();
        guard.push((msg.clone(), idempotency_key.map(str::to_string)));
        let n = guard.len();
        Ok(SendOutcome {
            provider: "recording_test".to_string(),
            provider_message_id: format!("tx_{n}"),
            provider_thread_id: None,
        })
    }
}

fn build_test_app(cfg: Config) -> (Router, Arc<MemoryStore>, SentLog) {
    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let (transport, sent) = RecordingTransport::new();
    let state =
        AppState::with_backends(cfg, store.clone(), resend).with_transport(Arc::new(transport));
    (build_router(state), store, sent)
}

async fn seed_raw_message(
    store: &MemoryStore,
    id: &str,
    from: &str,
    subject: &str,
    raw: &[u8],
) -> String {
    let msg = store
        .insert_message(NewMessageInput {
            id: Some(id.to_string()),
            thread_id: Some(format!("thr_{id}")),
            label_ids: vec![LABEL_INBOX.to_string()],
            raw_rfc2822: raw.to_vec(),
            snippet: "Newsletter body".to_string(),
            internal_date_ms: 1_764_100_000_000,
            subject: subject.to_string(),
            from_addr: from.to_string(),
            to_addrs: vec!["agent@example.com".to_string()],
            cc_addrs: Vec::new(),
            bcc_addrs: Vec::new(),
            text_body: "Newsletter body".to_string(),
            html_body: None,
            rfc822_message_id: Some(format!("<{id}@newsletter.example.com>")),
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "local".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: Vec::new(),
        })
        .await
        .expect("seed message");
    msg.id
}

async fn json_request(
    app: &Router,
    method: &str,
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
    let json_val: Value = if bytes.is_empty() {
        json!(null)
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }))
    };
    (status, json_val)
}

#[tokio::test]
async fn newsletter_surfaces_unsubscribe_metadata_in_rest_and_mcp_read_email() {
    let (app, store, _sent) = build_test_app(Config::for_test());

    let newsletter_raw = concat!(
        "From: Weekly News <news@example.com>\r\n",
        "To: agent@example.com\r\n",
        "Subject: Issue #42\r\n",
        "List-Unsubscribe: <https://news.example.com/unsub?id=42>, <mailto:unsub@news.example.com?subject=stop%20news>\r\n",
        "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
        "\r\n",
        "Hello subscriber!\r\n"
    );
    seed_raw_message(
        &store,
        "m_news_1",
        "Weekly News <news@example.com>",
        "Issue #42",
        newsletter_raw.as_bytes(),
    )
    .await;

    let regular_raw = concat!(
        "From: Alice <alice@example.com>\r\n",
        "To: agent@example.com\r\n",
        "Subject: Lunch?\r\n",
        "\r\n",
        "Want to grab lunch?\r\n"
    );
    seed_raw_message(
        &store,
        "m_plain_1",
        "Alice <alice@example.com>",
        "Lunch?",
        regular_raw.as_bytes(),
    )
    .await;

    // 1. GET /v1/messages/{id} surfaces unsubscribe info for newsletter
    let (status, msg_json) = json_request(&app, "GET", "/v1/messages/m_news_1", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        msg_json["unsubscribe"]["https_url"],
        "https://news.example.com/unsub?id=42"
    );
    assert_eq!(
        msg_json["unsubscribe"]["mailto"],
        "mailto:unsub@news.example.com?subject=stop%20news"
    );
    assert_eq!(msg_json["unsubscribe"]["one_click"], true);
    assert_eq!(
        msg_json["unsubscribe"]["post_body"],
        "List-Unsubscribe=One-Click"
    );

    // 2. GET /v1/messages/{id} omits unsubscribe completely when absent
    let (status, plain_json) =
        json_request(&app, "GET", "/v1/messages/m_plain_1", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !plain_json.as_object().unwrap().contains_key("unsubscribe"),
        "regular message JSON must omit 'unsubscribe' field"
    );

    // 3. MCP read_email surfaces the exact same unsubscribe metadata
    let (status, mcp_resp) = json_request(
        &app,
        "POST",
        "/mcp",
        None,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "read_email",
                "arguments": { "message_id": "m_news_1" }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mcp_resp["result"]["isError"], false);
    let sc = &mcp_resp["result"]["structuredContent"];
    assert_eq!(
        sc["unsubscribe"]["https_url"],
        "https://news.example.com/unsub?id=42"
    );
    assert_eq!(
        sc["unsubscribe"]["mailto"],
        "mailto:unsub@news.example.com?subject=stop%20news"
    );
    assert_eq!(sc["unsubscribe"]["one_click"], true);
    assert_eq!(sc["unsubscribe"]["post_body"], "List-Unsubscribe=One-Click");

    // 4. Capabilities advertises POST /v1/messages/{id}/unsubscribe
    let (status, caps) = json_request(&app, "GET", "/v1/capabilities", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let endpoints = caps["endpoints"].as_array().unwrap();
    assert!(
        endpoints
            .iter()
            .any(|e| e.as_str() == Some("POST /v1/messages/{id}/unsubscribe")),
        "capabilities should list POST /v1/messages/{{id}}/unsubscribe"
    );
}

#[tokio::test]
async fn dry_run_previews_one_click_and_mailto_without_network_or_transport_calls() {
    let (app, store, sent) = build_test_app(Config::for_test());

    let raw = concat!(
        "From: Digest <digest@example.org>\r\n",
        "To: agent@example.com\r\n",
        "Subject: Daily Digest\r\n",
        "List-Unsubscribe: <https://digest.example.org/unsub?u=99>, <mailto:leave@digest.example.org?subject=Unsubscribe%2099&body=Remove%20me>\r\n",
        "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
        "\r\n",
        "Digest content.\r\n"
    );
    seed_raw_message(
        &store,
        "m_dry_1",
        "Digest <digest@example.org>",
        "Daily Digest",
        raw.as_bytes(),
    )
    .await;

    // 1. Default dry_run prefers one_click_post
    let (status, preview) = json_request(
        &app,
        "POST",
        "/v1/messages/m_dry_1/unsubscribe",
        None,
        Some(json!({ "dry_run": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(preview["dry_run"], true);
    assert_eq!(preview["method"], "one_click_post");
    assert_eq!(preview["target"], "https://digest.example.org/unsub?u=99");
    assert_eq!(preview["one_click"], true);
    assert_eq!(preview["post_body"], "List-Unsubscribe=One-Click");
    assert_eq!(preview["would_succeed"], true);
    assert!(preview["policy_checks"].as_array().unwrap().len() >= 2);
    assert!(sent.lock().unwrap().is_empty());

    // 2. prefer_mailto dry_run via MCP previews mailto target without sending
    let (status, mcp_resp) = json_request(
        &app,
        "POST",
        "/mcp",
        None,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "unsubscribe",
                "arguments": {
                    "message_id": "m_dry_1",
                    "dry_run": true,
                    "prefer_mailto": true
                }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mcp_resp["result"]["isError"], false);
    let sc = &mcp_resp["result"]["structuredContent"];
    assert_eq!(sc["dry_run"], true);
    assert_eq!(sc["method"], "mailto");
    assert_eq!(sc["would_succeed"], true);
    assert_eq!(sc["preview"]["to"], json!(["leave@digest.example.org"]));
    assert_eq!(sc["preview"]["subject"], "Unsubscribe 99");
    assert_eq!(sc["preview"]["body"], "Remove me");
    assert!(sent.lock().unwrap().is_empty());
}

#[tokio::test]
async fn ssrf_targets_and_non_https_urls_are_rejected_with_403() {
    let (app, store, sent) = build_test_app(Config::for_test());

    let cases = [
        ("m_ssrf_loopback", "https://127.0.0.1:8443/unsub"),
        (
            "m_ssrf_metadata",
            "https://169.254.169.254/latest/meta-data/",
        ),
        ("m_ssrf_http", "http://example.com/unsub"),
        ("m_ssrf_ipv6_mapped", "https://[::ffff:127.0.0.1]/unsub"),
        ("m_ssrf_rfc1918", "https://10.0.0.1/internal/unsub"),
    ];

    for (id, bad_url) in cases {
        let raw = format!(
            "From: Evil <evil@attacker.test>\r\n\
             To: agent@example.com\r\n\
             Subject: SSRF probe\r\n\
             List-Unsubscribe: <{bad_url}>\r\n\
             List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n\
             \r\n\
             Try to unsubscribe.\r\n"
        );
        seed_raw_message(
            &store,
            id,
            "Evil <evil@attacker.test>",
            "SSRF probe",
            raw.as_bytes(),
        )
        .await;

        let (status, body) = json_request(
            &app,
            "POST",
            &format!("/v1/messages/{id}/unsubscribe"),
            None,
            Some(json!({ "dry_run": false })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "expected 403 Forbidden for SSRF URL '{bad_url}', got {status} {body}"
        );
        assert_eq!(body["error"]["code"], "ssrf_blocked");

        // Dry-run also flags ssrf_protection as failed with zero network traffic.
        let (dry_status, dry_body) = json_request(
            &app,
            "POST",
            &format!("/v1/messages/{id}/unsubscribe"),
            None,
            Some(json!({ "dry_run": true })),
        )
        .await;
        assert_eq!(dry_status, StatusCode::OK);
        assert_eq!(dry_body["would_succeed"], false);
    }

    // MCP unsubscribe also returns structured ssrf_blocked error.
    let (status, mcp_resp) = json_request(
        &app,
        "POST",
        "/mcp",
        None,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "unsubscribe",
                "arguments": { "message_id": "m_ssrf_metadata" }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mcp_resp["result"]["isError"], true);
    assert_eq!(
        mcp_resp["result"]["structuredContent"]["error"]["code"],
        "ssrf_blocked"
    );
    assert!(sent.lock().unwrap().is_empty());
}

#[tokio::test]
async fn mailto_unsubscribe_routes_through_outbound_policy_and_transport() {
    let mailto_raw = concat!(
        "From: List <list@news.example.org>\r\n",
        "To: agent@example.com\r\n",
        "Subject: Monthly Updates\r\n",
        "List-Unsubscribe: <mailto:unsub@news.example.org?subject=Unsubscribe%20List&body=Please%20unsubscribe%20me>\r\n",
        "\r\n",
        "News content.\r\n"
    );

    // 1. Default Allow policy dispatches via MailTransport
    let (app, store, sent) = build_test_app(Config::for_test());
    seed_raw_message(
        &store,
        "m_mailto_ok",
        "List <list@news.example.org>",
        "Monthly Updates",
        mailto_raw.as_bytes(),
    )
    .await;

    let (status, body) = json_request(
        &app,
        "POST",
        "/v1/messages/m_mailto_ok/unsubscribe",
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unexpected error: {body}");
    assert_eq!(body["status"], "unsubscribed");
    assert_eq!(body["method"], "mailto");
    assert_eq!(body["provider"], "recording_test");
    assert_eq!(body["to"], json!(["unsub@news.example.org"]));
    assert_eq!(body["subject"], "Unsubscribe List");
    {
        let log = sent.lock().unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].0.to, vec!["unsub@news.example.org"]);
        assert_eq!(log[0].0.subject, "Unsubscribe List");
        assert_eq!(log[0].0.text.as_deref(), Some("Please unsubscribe me"));
    }

    // 2. draft_only=true (action=block) blocks BOTH mailto and one_click_post
    let mut cfg_block = Config::for_test();
    cfg_block.draft_only = true;
    cfg_block.draft_only_action = DraftOnlyAction::Block;
    let (app_block, store_block, sent_block) = build_test_app(cfg_block);
    seed_raw_message(
        &store_block,
        "m_block_mailto",
        "List <list@news.example.org>",
        "Monthly Updates",
        mailto_raw.as_bytes(),
    )
    .await;
    let one_click_raw = concat!(
        "From: OneClick <news@example.com>\r\n",
        "To: agent@example.com\r\n",
        "Subject: Promo\r\n",
        "List-Unsubscribe: <https://93.184.216.34/unsub>\r\n",
        "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
        "\r\n",
        "Promo.\r\n"
    );
    seed_raw_message(
        &store_block,
        "m_block_oneclick",
        "OneClick <news@example.com>",
        "Promo",
        one_click_raw.as_bytes(),
    )
    .await;

    let (st1, b1) = json_request(
        &app_block,
        "POST",
        "/v1/messages/m_block_mailto/unsubscribe",
        None,
        None,
    )
    .await;
    assert_eq!(st1, StatusCode::FORBIDDEN);
    assert_eq!(b1["error"]["code"], "draft_only_mode");

    let (st2, b2) = json_request(
        &app_block,
        "POST",
        "/v1/messages/m_block_oneclick/unsubscribe",
        None,
        None,
    )
    .await;
    assert_eq!(st2, StatusCode::FORBIDDEN);
    assert_eq!(b2["error"]["code"], "draft_only_mode");
    assert!(sent_block.lock().unwrap().is_empty());

    // 3. draft_only=true (action=downgrade) saves mailto as draft and never invokes transport
    let mut cfg_down = Config::for_test();
    cfg_down.draft_only = true;
    cfg_down.draft_only_action = DraftOnlyAction::Downgrade;
    let (app_down, store_down, sent_down) = build_test_app(cfg_down);
    seed_raw_message(
        &store_down,
        "m_down_mailto",
        "List <list@news.example.org>",
        "Monthly Updates",
        mailto_raw.as_bytes(),
    )
    .await;

    let (st3, b3) = json_request(
        &app_down,
        "POST",
        "/v1/messages/m_down_mailto/unsubscribe",
        None,
        None,
    )
    .await;
    assert_eq!(st3, StatusCode::OK);
    assert_eq!(b3["status"], "draft_created");
    assert_eq!(b3["downgraded_from_send"], true);
    assert_eq!(b3["method"], "mailto");
    assert!(b3["draft_id"].as_str().is_some());
    assert!(sent_down.lock().unwrap().is_empty());

    // 4. require_approval=true holds mailto for human approval (202 Accepted), then approves cleanly,
    //    and blocks direct one_click_post without firing any HTTP request!
    let mut cfg_appr = Config::for_test();
    cfg_appr.require_approval = true;
    let (app_appr, store_appr, sent_appr) = build_test_app(cfg_appr);
    seed_raw_message(
        &store_appr,
        "m_appr_mailto",
        "List <list@news.example.org>",
        "Monthly Updates",
        mailto_raw.as_bytes(),
    )
    .await;
    seed_raw_message(
        &store_appr,
        "m_appr_oneclick",
        "OneClick <news@example.com>",
        "Promo",
        one_click_raw.as_bytes(),
    )
    .await;

    // One-click is blocked before any HTTP request
    let (st_oc, b_oc) = json_request(
        &app_appr,
        "POST",
        "/v1/messages/m_appr_oneclick/unsubscribe",
        None,
        None,
    )
    .await;
    assert_eq!(st_oc, StatusCode::FORBIDDEN);
    assert_eq!(b_oc["error"]["code"], "approval_required");

    // Mailto is held in pending_approval queue (HTTP 202)
    let (st_hold, b_hold) = json_request(
        &app_appr,
        "POST",
        "/v1/messages/m_appr_mailto/unsubscribe",
        None,
        None,
    )
    .await;
    assert_eq!(st_hold, StatusCode::ACCEPTED);
    assert_eq!(b_hold["status"], "pending_approval");
    assert_eq!(b_hold["held_for_approval"], true);
    assert_eq!(b_hold["method"], "mailto");
    let approval_id = b_hold["approval_id"].as_str().unwrap().to_string();
    assert!(sent_appr.lock().unwrap().is_empty());

    // Approving dispatches the unsubscribe email exactly once
    let (st_approve, b_approve) = json_request(
        &app_appr,
        "POST",
        &format!("/v1/approvals/{approval_id}/approve"),
        None,
        Some(json!({ "note": "approved unsubscribe" })),
    )
    .await;
    assert_eq!(st_approve, StatusCode::OK, "approve failed: {b_approve}");
    assert_eq!(b_approve["status"], "approved");
    assert_eq!(sent_appr.lock().unwrap().len(), 1);
    assert_eq!(
        sent_appr.lock().unwrap()[0].0.to,
        vec!["unsub@news.example.org"]
    );
}

#[tokio::test]
async fn unsubscribe_enforces_scopes_and_rejects_messages_without_headers() {
    let mut cfg = Config::for_test();
    cfg.scoped_tokens = vec![
        ScopedTokenConfig {
            token: "tok_read".to_string(),
            mailbox_id: None,
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_write".to_string(),
            mailbox_id: None,
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read, AuthScope::Write],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_send".to_string(),
            mailbox_id: None,
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read, AuthScope::Send],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
    ];
    let (app, store, sent) = build_test_app(cfg);

    let mailto_raw = concat!(
        "From: List <list@example.org>\r\n",
        "To: agent@example.com\r\n",
        "Subject: Updates\r\n",
        "List-Unsubscribe: <mailto:unsub@example.org>\r\n",
        "\r\n",
        "Body\r\n"
    );
    seed_raw_message(
        &store,
        "m_scoped",
        "List <list@example.org>",
        "Updates",
        mailto_raw.as_bytes(),
    )
    .await;
    seed_raw_message(
        &store,
        "m_no_header",
        "Bob <bob@example.org>",
        "Hi",
        b"From: bob@example.org\r\nTo: agent@example.com\r\nSubject: Hi\r\n\r\nHello",
    )
    .await;

    // Read-only token denied for dry_run and execute
    let (st, _) = json_request(
        &app,
        "POST",
        "/v1/messages/m_scoped/unsubscribe",
        Some("tok_read"),
        Some(json!({ "dry_run": true })),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Write token allowed for dry_run, denied for execute
    let (st, preview) = json_request(
        &app,
        "POST",
        "/v1/messages/m_scoped/unsubscribe",
        Some("tok_write"),
        Some(json!({ "dry_run": true })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(preview["dry_run"], true);

    let (st, _) = json_request(
        &app,
        "POST",
        "/v1/messages/m_scoped/unsubscribe",
        Some("tok_write"),
        Some(json!({ "dry_run": false })),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(sent.lock().unwrap().is_empty());

    // Send token allowed for both dry_run and execute
    let (st, res) = json_request(
        &app,
        "POST",
        "/v1/messages/m_scoped/unsubscribe",
        Some("tok_send"),
        Some(json!({ "dry_run": false })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(res["status"], "unsubscribed");
    assert_eq!(sent.lock().unwrap().len(), 1);

    // Message without List-Unsubscribe header returns 400 Bad Request
    let (st, err) = json_request(
        &app,
        "POST",
        "/v1/messages/m_no_header/unsubscribe",
        Some("tok_send"),
        Some(json!({ "dry_run": true })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(err["error"]["code"], "validation_error");
}

#[tokio::test]
async fn one_click_unsubscribe_enforces_allowed_recipients_and_first_contact_policy() {
    let one_click_raw = concat!(
        "From: Promo <promo@external.example>\r\n",
        "To: agent@example.com\r\n",
        "Subject: Weekly deals\r\n",
        "List-Unsubscribe: <https://93.184.216.34/unsub>\r\n",
        "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
        "\r\n",
        "Deals.\r\n"
    );

    // 1. allowed_recipients blocks one-click POST targeting a non-allowlisted host
    let mut cfg_allow = Config::for_test();
    cfg_allow.allowed_recipients = vec!["@company.com".to_string()];
    let (app_allow, store_allow, _sent) = build_test_app(cfg_allow);
    seed_raw_message(
        &store_allow,
        "m_oc_allow",
        "Promo <promo@external.example>",
        "Weekly deals",
        one_click_raw.as_bytes(),
    )
    .await;

    let (st_dry, dry) = json_request(
        &app_allow,
        "POST",
        "/v1/messages/m_oc_allow/unsubscribe",
        None,
        Some(json!({ "dry_run": true })),
    )
    .await;
    assert_eq!(st_dry, StatusCode::OK);
    assert_eq!(dry["would_succeed"], false);

    let (st, err) = json_request(
        &app_allow,
        "POST",
        "/v1/messages/m_oc_allow/unsubscribe",
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(err["error"]["code"], "recipient_not_allowed");

    // 2. first_contact_approval blocks direct one-click POST without firing any HTTP request
    let mut cfg_fc = Config::for_test();
    cfg_fc.first_contact_approval = true;
    let (app_fc, store_fc, _sent_fc) = build_test_app(cfg_fc);
    seed_raw_message(
        &store_fc,
        "m_oc_fc",
        "Promo <promo@external.example>",
        "Weekly deals",
        one_click_raw.as_bytes(),
    )
    .await;

    let (st_dry, dry_fc) = json_request(
        &app_fc,
        "POST",
        "/v1/messages/m_oc_fc/unsubscribe",
        None,
        Some(json!({ "dry_run": true })),
    )
    .await;
    assert_eq!(st_dry, StatusCode::OK);
    assert_eq!(dry_fc["would_succeed"], false);

    let (st, err) = json_request(
        &app_fc,
        "POST",
        "/v1/messages/m_oc_fc/unsubscribe",
        None,
        Some(json!({})),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(err["error"]["code"], "approval_required");
}
