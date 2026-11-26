//! End-to-end tests for send/draft idempotency keys and the immutable agent audit log (`Issue #29`).

use std::{
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chrono::Utc;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use nogml::{
    AppState,
    auth::{AuthScope, ScopedTokenConfig},
    build_router,
    config::Config,
    error::AppResult,
    mime,
    models::{LABEL_INBOX, LABEL_UNREAD},
    resend::HttpResendClient,
    storage::{MailStore, MemoryStore, MessageListQuery, NewMessageInput, SqliteStore},
    transport::{MailTransport, OutboundMessage, SendOutcome, TransportCapabilities},
};

type SentLog = Arc<Mutex<Vec<(OutboundMessage, Option<String>)>>>;

struct RecordingTransport {
    sent: SentLog,
    delay: Duration,
}

impl RecordingTransport {
    fn new() -> (Self, SentLog) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                sent: sent.clone(),
                delay: Duration::ZERO,
            },
            sent,
        )
    }

    fn with_delay(delay: Duration) -> (Self, SentLog) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                sent: sent.clone(),
                delay,
            },
            sent,
        )
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
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        let mut guard = self.sent.lock().unwrap();
        guard.push((msg.clone(), idempotency_key.map(str::to_string)));
        let n = guard.len();
        Ok(SendOutcome {
            provider: "recording_test".to_string(),
            provider_message_id: format!("tx_{n}"),
        })
    }
}

async fn http_req(
    app: &Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let body = if let Some(val) = body {
        builder = builder.header("content-type", "application/json");
        Body::from(val.to_string())
    } else {
        Body::empty()
    };
    let resp = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .expect("oneshot failed");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&bytes).expect("valid json response")
    };
    (status, json)
}

async fn seed_message(
    store: &Arc<dyn MailStore>,
    id: &str,
    thread_id: &str,
    subject: &str,
    body: &str,
    extra_headers: &str,
) {
    let raw = format!(
        "From: Sender <sender@example.com>\r\nTo: {}\r\nSubject: {subject}\r\nMessage-ID: <{id}@example.com>\r\n{extra_headers}\r\n{body}",
        store.mailbox_id()
    );
    store
        .insert_message(NewMessageInput {
            id: Some(id.to_string()),
            thread_id: Some(thread_id.to_string()),
            label_ids: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            raw_rfc2822: raw.into_bytes(),
            snippet: body.to_string(),
            internal_date_ms: Utc::now().timestamp_millis(),
            subject: subject.to_string(),
            from_addr: "Sender <sender@example.com>".to_string(),
            to_addrs: vec![store.mailbox_id().to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: body.to_string(),
            html_body: None,
            rfc822_message_id: Some(format!("<{id}@example.com>")),
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "local".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: vec![],
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn e2e_send_and_draft_idempotency_body_header_mcp_and_concurrent() {
    let cfg = Config::for_test();
    let store: Arc<dyn MailStore> = Arc::new(SqliteStore::open_in_memory(&cfg.user_email).unwrap());
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let (transport, sent_log) = RecordingTransport::with_delay(Duration::from_millis(40));
    let state =
        AppState::with_backends(cfg, store.clone(), resend).with_transport(Arc::new(transport));
    let app = build_router(state);

    // 1. dry_run with idempotency_key must NOT cache or block the real send
    let (st, dry) = http_req(
        &app,
        "POST",
        "/v1/messages/send",
        &[],
        Some(json!({
            "to": ["alice@example.com"],
            "subject": "Quarterly Update",
            "text": "Preview only",
            "dry_run": true,
            "idempotency_key": "send-body-1"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(dry["dry_run"], true);
    assert_eq!(sent_log.lock().unwrap().len(), 0);

    // 2. First real send with body idempotency_key calls MailTransport once and forwards key
    let payload = json!({
        "to": ["alice@example.com"],
        "subject": "Quarterly Update",
        "text": "Actual send body",
        "idempotency_key": "send-body-1"
    });
    let (st1, res1) = http_req(
        &app,
        "POST",
        "/v1/messages/send",
        &[],
        Some(payload.clone()),
    )
    .await;
    assert_eq!(st1, StatusCode::OK);
    assert_eq!(res1["status"], "sent");
    let first_msg_id = res1["message_id"].as_str().unwrap().to_string();
    assert_eq!(sent_log.lock().unwrap().len(), 1);
    assert_eq!(
        sent_log.lock().unwrap()[0].1.as_deref(),
        Some("send-body-1"),
        "idempotency_key must be forwarded to MailTransport::send"
    );

    // Retry with same body idempotency_key returns exact original response without re-sending
    let (st2, res2) = http_req(&app, "POST", "/v1/messages/send", &[], Some(payload)).await;
    assert_eq!(st2, StatusCode::OK);
    assert_eq!(res2["message_id"], first_msg_id);
    assert_eq!(res2["resend_id"], res1["resend_id"]);
    assert_eq!(
        sent_log.lock().unwrap().len(),
        1,
        "MailTransport must NOT be invoked twice for same body idempotency_key"
    );

    // 3. Idempotency-Key HTTP header on POST /v1/messages/send
    let hdr_payload = json!({
        "to": ["bob@example.com"],
        "subject": "Header Idempotent",
        "text": "Sent with HTTP header key"
    });
    let (st3, res3) = http_req(
        &app,
        "POST",
        "/v1/messages/send",
        &[("Idempotency-Key", "send-hdr-1")],
        Some(hdr_payload.clone()),
    )
    .await;
    assert_eq!(st3, StatusCode::OK);
    let hdr_msg_id = res3["message_id"].as_str().unwrap().to_string();
    assert_eq!(sent_log.lock().unwrap().len(), 2);
    assert_eq!(sent_log.lock().unwrap()[1].1.as_deref(), Some("send-hdr-1"));

    let (st4, res4) = http_req(
        &app,
        "POST",
        "/v1/messages/send",
        &[("Idempotency-Key", "send-hdr-1")],
        Some(hdr_payload),
    )
    .await;
    assert_eq!(st4, StatusCode::OK);
    assert_eq!(res4["message_id"], hdr_msg_id);
    assert_eq!(sent_log.lock().unwrap().len(), 2);

    // 4. Concurrent retries on MCP send_email with the same idempotency_key send EXACTLY ONCE
    let mcp_req = json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "send_email",
            "arguments": {
                "to": ["carol@example.com"],
                "subject": "MCP Idempotent",
                "text": "Sent via MCP",
                "idempotency_key": "mcp-send-1"
            }
        }
    });
    let (mcp_r1, mcp_r2) = tokio::join!(
        http_req(&app, "POST", "/mcp", &[], Some(mcp_req.clone())),
        http_req(&app, "POST", "/mcp", &[], Some(mcp_req)),
    );
    assert_eq!(mcp_r1.0, StatusCode::OK);
    assert_eq!(mcp_r2.0, StatusCode::OK);
    let mcp_id_1 = mcp_r1.1["result"]["structuredContent"]["message_id"]
        .as_str()
        .unwrap()
        .to_string();
    let mcp_id_2 = mcp_r2.1["result"]["structuredContent"]["message_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(mcp_id_1, mcp_id_2);
    assert_eq!(
        sent_log.lock().unwrap().len(),
        3,
        "concurrent MCP send_email retries must invoke MailTransport once"
    );
    assert_eq!(sent_log.lock().unwrap()[2].1.as_deref(), Some("mcp-send-1"));

    // 5. create_draft idempotency via body, HTTP header, and MCP
    let (ds1, dr1) = http_req(
        &app,
        "POST",
        "/v1/drafts",
        &[("Idempotency-Key", "draft-hdr-1")],
        Some(json!({
            "to": ["alice@example.com"],
            "subject": "Draft Once",
            "text": "Draft content"
        })),
    )
    .await;
    assert_eq!(ds1, StatusCode::OK);
    let draft_id_1 = dr1["draft_id"].as_str().unwrap().to_string();

    let (ds2, dr2) = http_req(
        &app,
        "POST",
        "/v1/drafts",
        &[("Idempotency-Key", "draft-hdr-1")],
        Some(json!({
            "to": ["alice@example.com"],
            "subject": "Draft Once",
            "text": "Draft content"
        })),
    )
    .await;
    assert_eq!(ds2, StatusCode::OK);
    assert_eq!(dr2["draft_id"], draft_id_1);
    assert_eq!(dr2["message_id"], dr1["message_id"]);

    let mcp_draft_req = json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {
            "name": "create_draft",
            "arguments": {
                "to": ["bob@example.com"],
                "subject": "MCP Draft",
                "text": "Draft via MCP",
                "idempotency_key": "mcp-draft-1"
            }
        }
    });
    let (md1_st, md1) = http_req(&app, "POST", "/mcp", &[], Some(mcp_draft_req.clone())).await;
    let (md2_st, md2) = http_req(&app, "POST", "/mcp", &[], Some(mcp_draft_req)).await;
    assert_eq!(md1_st, StatusCode::OK);
    assert_eq!(md2_st, StatusCode::OK);
    assert_eq!(
        md1["result"]["structuredContent"]["draft_id"],
        md2["result"]["structuredContent"]["draft_id"]
    );

    // Exactly 2 drafts stored in total (not 4)
    let drafts = store
        .list_drafts(&MessageListQuery::default())
        .await
        .unwrap();
    assert_eq!(drafts.drafts.len(), 2);
}

#[tokio::test]
async fn e2e_audit_log_across_v1_mcp_gmail_scopes_and_mailbox_isolation() {
    let mut cfg = Config::for_test();
    cfg.user_email = "alice@example.com".to_string();
    cfg.mailboxes = vec!["bob@example.com".to_string()];
    cfg.scoped_tokens = vec![
        ScopedTokenConfig {
            token: "tok_alice_full".to_string(),
            mailbox_id: Some("alice@example.com".to_string()),
            scopes: vec![
                AuthScope::Read,
                AuthScope::Write,
                AuthScope::Send,
                AuthScope::Admin,
            ],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_alice_read".to_string(),
            mailbox_id: Some("alice@example.com".to_string()),
            scopes: vec![AuthScope::Read],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_alice_write_only".to_string(),
            mailbox_id: Some("alice@example.com".to_string()),
            scopes: vec![AuthScope::Write],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_bob_full".to_string(),
            mailbox_id: Some("bob@example.com".to_string()),
            scopes: vec![
                AuthScope::Read,
                AuthScope::Write,
                AuthScope::Send,
                AuthScope::Admin,
            ],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
    ];

    let store: Arc<dyn MailStore> = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let (transport, sent_log) = RecordingTransport::new();
    let state =
        AppState::with_backends(cfg, store.clone(), resend).with_transport(Arc::new(transport));

    seed_message(
        &store.for_mailbox("alice@example.com"),
        "msg_a1",
        "thr_a1",
        "Alice Newsletter",
        "Weekly digest about Rust",
        "List-Unsubscribe: <mailto:unsub@lists.example.com?subject=unsubscribe>\r\n",
    )
    .await;
    seed_message(
        &store.for_mailbox("bob@example.com"),
        "msg_b1",
        "thr_b1",
        "Bob Report",
        "Confidential Q4 numbers",
        "",
    )
    .await;

    let app = build_router(state);
    let alice_auth = [("authorization", "Bearer tok_alice_full")];
    let alice_read_auth = [("authorization", "Bearer tok_alice_read")];
    let alice_write_auth = [("authorization", "Bearer tok_alice_write_only")];
    let bob_auth = [("authorization", "Bearer tok_bob_full")];

    // 1. /v1 operations for Alice: read, search, triage, modify, draft, delete, unsubscribe (dry_run), send
    let (st, _) = http_req(&app, "GET", "/v1/messages/msg_a1", &alice_auth, None).await;
    assert_eq!(st, StatusCode::OK);
    let (st, _) = http_req(&app, "GET", "/v1/search?q=Rust", &alice_auth, None).await;
    assert_eq!(st, StatusCode::OK);
    let (st, _) = http_req(
        &app,
        "POST",
        "/v1/threads/thr_a1/triage",
        &alice_auth,
        Some(json!({ "mark_read": true })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _) = http_req(
        &app,
        "POST",
        "/v1/messages/modify",
        &alice_auth,
        Some(json!({ "message_ids": ["msg_a1"], "add_labels": ["STARRED"] })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, draft_res) = http_req(
        &app,
        "POST",
        "/v1/drafts",
        &alice_auth,
        Some(json!({ "to": ["x@example.com"], "subject": "Temp", "text": "Hi" })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let draft_id = draft_res["draft_id"].as_str().unwrap().to_string();
    let (st, _) = http_req(
        &app,
        "DELETE",
        &format!("/v1/drafts/{draft_id}"),
        &alice_auth,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _) = http_req(
        &app,
        "POST",
        "/v1/messages/msg_a1/unsubscribe",
        &alice_auth,
        Some(json!({ "dry_run": true })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, alice_sent) = http_req(
        &app,
        "POST",
        "/v1/messages/send",
        &alice_auth,
        Some(json!({
            "to": ["peer@example.com"],
            "subject": "Shared Key",
            "text": "From Alice",
            "idempotency_key": "shared-mailbox-key"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // 2. /mcp operations for Alice: read_email & search_emails
    let (st, _) = http_req(
        &app,
        "POST",
        "/mcp",
        &alice_auth,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "read_email", "arguments": { "message_id": "msg_a1" } }
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // 3. /gmail/v1 operations for Alice: messages.get & messages.send
    let (st, _) = http_req(
        &app,
        "GET",
        "/gmail/v1/users/me/messages/msg_a1",
        &alice_auth,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let raw_b64 = mime::encode_base64url(
        b"From: alice@example.com\r\nTo: peer@example.com\r\nSubject: Gmail Send\r\n\r\nHello from Gmail API",
    );
    let (st, _) = http_req(
        &app,
        "POST",
        "/gmail/v1/users/me/messages/send",
        &alice_auth,
        Some(json!({ "raw": raw_b64 })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // 4. Bob uses the SAME idempotency_key ("shared-mailbox-key") -> isolated per mailbox, so Bob sends independently!
    let (st, bob_sent) = http_req(
        &app,
        "POST",
        "/v1/messages/send",
        &bob_auth,
        Some(json!({
            "to": ["peer@example.com"],
            "subject": "Shared Key",
            "text": "From Bob",
            "idempotency_key": "shared-mailbox-key"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_ne!(alice_sent["message_id"], bob_sent["message_id"]);
    assert_eq!(
        sent_log.lock().unwrap().len(),
        3,
        "Alice v1 send + Alice gmail send + Bob v1 send"
    );

    // 5. Scope checks on GET /v1/audit: Write-only is 403, Read is 200, Admin is 200
    let (st_forbidden, _) = http_req(&app, "GET", "/v1/audit", &alice_write_auth, None).await;
    assert_eq!(st_forbidden, StatusCode::FORBIDDEN);

    let (st_read, alice_audit) =
        http_req(&app, "GET", "/v1/audit?limit=100", &alice_read_auth, None).await;
    assert_eq!(st_read, StatusCode::OK);
    let entries = alice_audit["entries"].as_array().unwrap();
    assert!(
        entries.len() >= 11,
        "expected >=11 audit entries for Alice, got {}",
        entries.len()
    );

    // Every entry belongs strictly to alice@example.com
    for entry in entries {
        assert_eq!(entry["mailbox_id"], "alice@example.com");
        assert_eq!(entry["actor"], "alice@example.com");
    }

    // Verify all 3 channels recorded
    assert!(entries.iter().any(|e| e["channel"] == "/v1"));
    assert!(entries.iter().any(|e| e["channel"] == "/mcp"));
    assert!(entries.iter().any(|e| e["channel"] == "/gmail/v1"));

    // Verify key action types recorded
    for expected_action in [
        "read",
        "search",
        "send",
        "draft",
        "triage",
        "modify",
        "delete",
        "unsubscribe",
    ] {
        assert!(
            entries.iter().any(|e| e["action"] == expected_action),
            "missing audit action '{expected_action}' in {entries:?}"
        );
    }

    // Filter by action=send on GET /v1/audit
    let (st_sends, alice_sends) = http_req(
        &app,
        "GET",
        "/v1/audit?action=send&limit=10",
        &alice_auth,
        None,
    )
    .await;
    assert_eq!(st_sends, StatusCode::OK);
    let send_entries = alice_sends["entries"].as_array().unwrap();
    assert_eq!(send_entries.len(), 2);
    assert!(send_entries.iter().all(|e| e["action"] == "send"));

    // Bob's audit log is completely isolated from Alice's
    let (st_bob, bob_audit) = http_req(&app, "GET", "/v1/audit?limit=100", &bob_auth, None).await;
    assert_eq!(st_bob, StatusCode::OK);
    let bob_entries = bob_audit["entries"].as_array().unwrap();
    assert_eq!(bob_entries.len(), 1);
    assert_eq!(bob_entries[0]["mailbox_id"], "bob@example.com");
    assert_eq!(bob_entries[0]["action"], "send");
}

#[tokio::test]
async fn e2e_approval_audit_and_cli_mail_audit_local_and_remote() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("audit_cli.db");

    // 1. Seed a SQLite DB with require_approval=true and exercise approve + reject audit entries
    let mut cfg = Config::for_test();
    cfg.db_path = db_path.clone();
    cfg.user_email = "ops@example.com".to_string();
    cfg.require_approval = true;
    cfg.auth_tokens = vec!["tok_cli_audit".to_string()];

    let store: Arc<dyn MailStore> = Arc::new(SqliteStore::open(&db_path, &cfg.user_email).unwrap());
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let (transport, sent_log) = RecordingTransport::new();
    let state = AppState::with_backends(cfg, store, resend).with_transport(Arc::new(transport));
    let app = build_router(state);

    let auth = [("authorization", "Bearer tok_cli_audit")];

    // Hold two outbound sends (with idempotency key on the first one!)
    let (st_h1, h1) = http_req(
        &app,
        "POST",
        "/v1/messages/send",
        &auth,
        Some(json!({
            "to": ["ext@partner.com"],
            "subject": "Approve Me",
            "text": "Please approve",
            "idempotency_key": "hold-key-1"
        })),
    )
    .await;
    assert_eq!(st_h1, StatusCode::ACCEPTED);
    let apr1_id = h1["approval_id"].as_str().unwrap().to_string();

    // Retrying the held send with the same idempotency_key returns the same approval_id with 202
    let (st_h1_retry, h1_retry) = http_req(
        &app,
        "POST",
        "/v1/messages/send",
        &auth,
        Some(json!({
            "to": ["ext@partner.com"],
            "subject": "Approve Me",
            "text": "Please approve",
            "idempotency_key": "hold-key-1"
        })),
    )
    .await;
    assert_eq!(st_h1_retry, StatusCode::ACCEPTED);
    assert_eq!(h1_retry["approval_id"], apr1_id);

    let (st_h2, h2) = http_req(
        &app,
        "POST",
        "/v1/messages/send",
        &auth,
        Some(json!({
            "to": ["ext@partner.com"],
            "subject": "Reject Me",
            "text": "Please reject"
        })),
    )
    .await;
    assert_eq!(st_h2, StatusCode::ACCEPTED);
    let apr2_id = h2["approval_id"].as_str().unwrap().to_string();

    // Approve apr1, reject apr2
    let (st_a, _) = http_req(
        &app,
        "POST",
        &format!("/v1/approvals/{apr1_id}/approve"),
        &auth,
        Some(json!({ "note": "approved" })),
    )
    .await;
    assert_eq!(st_a, StatusCode::OK);
    assert_eq!(sent_log.lock().unwrap().len(), 1);

    let (st_r, _) = http_req(
        &app,
        "POST",
        &format!("/v1/approvals/{apr2_id}/reject"),
        &auth,
        Some(json!({ "note": "rejected" })),
    )
    .await;
    assert_eq!(st_r, StatusCode::OK);

    // 2. Run `nogml mail audit` directly against the local SQLite DB
    let bin = env!("CARGO_BIN_EXE_nogml");
    let local_out = Command::new(bin)
        .args([
            "--storage",
            "sqlite",
            "--db-path",
            db_path.to_str().unwrap(),
            "--user-email",
            "ops@example.com",
            "mail",
            "--json",
            "audit",
            "--limit",
            "50",
        ])
        .output()
        .expect("run local nogml mail audit");
    assert!(
        local_out.status.success(),
        "local cli failed: {}",
        String::from_utf8_lossy(&local_out.stderr)
    );
    let local_json: Value = serde_json::from_slice(&local_out.stdout).unwrap();
    let local_entries = local_json["entries"].as_array().unwrap();
    assert!(local_entries.iter().any(|e| e["action"] == "approve"));
    assert!(local_entries.iter().any(|e| e["action"] == "reject"));
    assert!(
        local_entries
            .iter()
            .any(|e| e["outcome"] == "idempotent_replay")
    );

    // 3. Spin up a real TCP HTTP server and test `nogml mail --url ... audit --action approve`
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let remote_out = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .args([
                "--auth-tokens",
                "tok_cli_audit",
                "mail",
                "--url",
                &format!("http://{addr}"),
                "--json",
                "audit",
                "--action",
                "approve",
                "--limit",
                "10",
            ])
            .output()
            .expect("run remote nogml mail audit")
    })
    .await
    .unwrap();
    server_handle.abort();

    assert!(
        remote_out.status.success(),
        "remote cli failed: {}",
        String::from_utf8_lossy(&remote_out.stderr)
    );
    let remote_json: Value = serde_json::from_slice(&remote_out.stdout).unwrap();
    let remote_entries = remote_json["entries"].as_array().unwrap();
    assert_eq!(remote_entries.len(), 1);
    assert_eq!(remote_entries[0]["action"], "approve");
    assert_eq!(remote_entries[0]["mailbox_id"], "ops@example.com");
}
