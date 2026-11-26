//! End-to-end tests for per-mailbox contact graph and VIP detection:
//! - Automatic contact updates on send, reply, and inbound ingest via `AppState::post_store_message`
//! - `GET /v1/contacts`, `GET /v1/contacts/{email}`, `PATCH /v1/contacts/{email}`
//! - `sender_contact` enrichment on `GET /v1/messages/{id}`, `GET /v1/threads/{id}`, `GET /v1/threads`
//! - MCP tools `lookup_contact` and `list_vips`
//! - Strict multi-mailbox isolation and auth scopes (`Issue #33`)

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use nogml::{
    AppState,
    auth::{AuthScope, ScopedTokenConfig},
    build_router,
    config::Config,
    error::AppResult,
    models::{LABEL_INBOX, LABEL_UNREAD},
    resend::HttpResendClient,
    storage::{NewMessageInput, SqliteStore},
    transport::{MailTransport, OutboundMessage, SendOutcome, TransportCapabilities},
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

async fn ingest_inbound(
    state: &AppState,
    id: &str,
    from: &str,
    to: &str,
    subject: &str,
    ts_ms: i64,
) -> String {
    let msg = state
        .store
        .insert_message(NewMessageInput {
            id: Some(id.to_string()),
            thread_id: None,
            label_ids: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            raw_rfc2822: format!(
                "From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nMessage-ID: <{id}@example.com>\r\n\r\nHello from {from}"
            )
            .into_bytes(),
            snippet: format!("Hello from {from}"),
            internal_date_ms: ts_ms,
            subject: subject.to_string(),
            from_addr: from.to_string(),
            to_addrs: vec![to.to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: format!("Hello from {from}"),
            html_body: None,
            rfc822_message_id: Some(format!("<{id}@example.com>")),
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
    state.post_store_message(&msg).await.unwrap();
    msg.id
}

#[tokio::test]
async fn send_reply_receive_updates_contacts_vips_rest_compact_and_mcp() {
    let mut cfg = Config::for_test();
    cfg.user_email = "owner@example.com".to_string();
    cfg.default_domain = "example.com".to_string();

    let store = Arc::new(SqliteStore::open_in_memory(&cfg.user_email).unwrap());
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store, resend)
        .with_transport(Arc::new(RecordingTransport::new()));
    let app = build_router(state.clone());

    // 1. Capabilities advertise /v1/contacts endpoints
    let (status, caps) = send_json(&app, Method::GET, "/v1/capabilities", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let endpoints: Vec<&str> = caps["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(endpoints.contains(&"GET /v1/contacts"));
    assert!(endpoints.contains(&"GET /v1/contacts/{email}"));
    assert!(endpoints.contains(&"PATCH /v1/contacts/{email}"));

    // 2. Inbound mail from Alice and Cold Sender updates received_count (and skips self)
    let alice_in_id = ingest_inbound(
        &state,
        "msg_alice_1",
        "Alice Mercer <alice@acme.com>",
        "owner@example.com",
        "Q4 Roadmap",
        1_700_000_001_000,
    )
    .await;
    let _cold_in_id = ingest_inbound(
        &state,
        "msg_cold_1",
        "Cold Outreach <sales@coldmail.io>",
        "owner@example.com",
        "Quick question",
        1_700_000_002_000,
    )
    .await;
    // Self-sent inbound note must NOT create a contact for owner@example.com
    let _self_in_id = ingest_inbound(
        &state,
        "msg_self_1",
        "owner@example.com",
        "owner@example.com",
        "Reminder",
        1_700_000_003_000,
    )
    .await;

    let (status, _) = send_json(
        &app,
        Method::GET,
        "/v1/contacts/owner@example.com",
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "self address must be skipped"
    );

    // 3. Creating a draft must NOT increment sent_count or replied_by_me_count
    let (status, _) = send_json(
        &app,
        Method::POST,
        "/v1/drafts",
        None,
        Some(json!({
            "reply_to_message_id": alice_in_id,
            "text": "Draft reply not sent yet"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, alice_before) = send_json(
        &app,
        Method::GET,
        "/v1/contacts/alice%40acme.com",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(alice_before["email"], "alice@acme.com");
    assert_eq!(alice_before["display_name"], "Alice Mercer");
    assert_eq!(alice_before["domain"], "acme.com");
    assert_eq!(alice_before["received_count"], 1);
    assert_eq!(alice_before["sent_count"], 0);
    assert_eq!(alice_before["replied_by_me_count"], 0);
    assert_eq!(alice_before["is_vip"], false);

    // 4. Send a fresh email (not a reply) to bob@acme.com (CCing owner@example.com which is skipped)
    let (status, _) = send_json(
        &app,
        Method::POST,
        "/v1/messages/send",
        None,
        Some(json!({
            "to": ["Bob <bob@acme.com>"],
            "cc": ["owner@example.com"],
            "subject": "Intro",
            "text": "Nice to meet you"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, bob) = send_json(&app, Method::GET, "/v1/contacts/bob@acme.com", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bob["sent_count"], 1);
    assert_eq!(bob["received_count"], 0);
    assert_eq!(bob["replied_by_me_count"], 0);
    assert_eq!(bob["is_vip"], false);

    // 5. Reply 3 times to Alice -> replied_by_me_count reaches 3 -> automatic VIP detection!
    for i in 1..=3 {
        let (status, _) = send_json(
            &app,
            Method::POST,
            "/v1/messages/send",
            None,
            Some(json!({
                "reply_to_message_id": alice_in_id,
                "text": format!("Reply #{i}")
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    let (status, alice_after) = send_json(
        &app,
        Method::GET,
        "/v1/contacts/ALICE%40ACME.COM",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(alice_after["sent_count"], 3);
    assert_eq!(alice_after["received_count"], 1);
    assert_eq!(alice_after["replied_by_me_count"], 3);
    assert_eq!(alice_after["is_vip"], true);
    assert!(alice_after["last_replied_at_ms"].as_i64().is_some());

    // 6. CompactMessage on GET /v1/messages/{id} and GET /v1/threads/{id} includes sender_contact
    let (status, msg_json) = send_json(
        &app,
        Method::GET,
        &format!("/v1/messages/{alice_in_id}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(msg_json["sender_contact"]["email"], "alice@acme.com");
    assert_eq!(msg_json["sender_contact"]["is_vip"], true);
    assert_eq!(msg_json["sender_contact"]["replied_by_me_count"], 3);

    let thread_id = msg_json["thread_id"].as_str().unwrap();
    let (status, thread_json) = send_json(
        &app,
        Method::GET,
        &format!("/v1/threads/{thread_id}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        thread_json["messages"][0]["sender_contact"]["email"],
        "alice@acme.com"
    );
    assert_eq!(thread_json["messages"][0]["sender_contact"]["is_vip"], true);

    // GET /v1/threads also attaches sender_contact on ThreadSummary
    let (status, threads_json) = send_json(&app, Method::GET, "/v1/threads", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let alice_thread = threads_json["threads"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"] == thread_id)
        .unwrap();
    assert_eq!(alice_thread["sender_contact"]["email"], "alice@acme.com");
    assert_eq!(alice_thread["sender_contact"]["is_vip"], true);

    // 7. PATCH /v1/contacts/{email} updates manual VIP override, display_name, and notes
    let (status, patched_bob) = send_json(
        &app,
        Method::PATCH,
        "/v1/contacts/bob%40acme.com",
        None,
        Some(json!({
            "is_vip": true,
            "display_name": "Bob Investor",
            "notes": "Series A lead"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(patched_bob["is_vip"], true);
    assert_eq!(patched_bob["vip_override"], true);
    assert_eq!(patched_bob["display_name"], "Bob Investor");
    assert_eq!(patched_bob["notes"], "Series A lead");

    // 8. GET /v1/contacts query filters (vip_only, replied_only, domain, q, limit)
    let (status, vips_list) =
        send_json(&app, Method::GET, "/v1/contacts?vip_only=true", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(vips_list["count"], 2);
    let vip_emails: Vec<&str> = vips_list["contacts"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["email"].as_str())
        .collect();
    assert_eq!(vip_emails, vec!["alice@acme.com", "bob@acme.com"]);

    let (status, replied_list) = send_json(
        &app,
        Method::GET,
        "/v1/contacts?replied_only=true",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replied_list["count"], 1);
    assert_eq!(replied_list["contacts"][0]["email"], "alice@acme.com");

    let (status, domain_list) = send_json(
        &app,
        Method::GET,
        "/v1/contacts?domain=coldmail.io",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(domain_list["count"], 1);
    assert_eq!(domain_list["contacts"][0]["email"], "sales@coldmail.io");

    let (status, q_list) =
        send_json(&app, Method::GET, "/v1/contacts?q=Series+A", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(q_list["count"], 1);
    assert_eq!(q_list["contacts"][0]["email"], "bob@acme.com");

    // 9. MCP tools: lookup_contact (known + unknown) and list_vips
    let (status, mcp_lookup) = send_json(
        &app,
        Method::POST,
        "/mcp",
        None,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "lookup_contact",
                "arguments": { "email": "alice@acme.com" }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mcp_lookup["result"]["isError"], false);
    assert_eq!(mcp_lookup["result"]["structuredContent"]["found"], true);
    assert_eq!(mcp_lookup["result"]["structuredContent"]["is_vip"], true);
    assert_eq!(
        mcp_lookup["result"]["structuredContent"]["replied_by_me_count"],
        3
    );

    let (status, mcp_unknown) = send_json(
        &app,
        Method::POST,
        "/mcp",
        None,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "lookup_contact",
                "arguments": { "email": "stranger@unknown.org" }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mcp_unknown["result"]["isError"], false);
    assert_eq!(mcp_unknown["result"]["structuredContent"]["found"], false);
    assert_eq!(mcp_unknown["result"]["structuredContent"]["is_vip"], false);
    assert_eq!(
        mcp_unknown["result"]["structuredContent"]["replied_by_me_count"],
        0
    );

    let (status, mcp_vips) = send_json(
        &app,
        Method::POST,
        "/mcp",
        None,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "list_vips",
                "arguments": { "limit": 10 }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mcp_vips["result"]["isError"], false);
    assert_eq!(mcp_vips["result"]["structuredContent"]["count"], 2);
    let mcp_vip_emails: Vec<&str> = mcp_vips["result"]["structuredContent"]["vips"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["email"].as_str())
        .collect();
    assert_eq!(mcp_vip_emails, vec!["alice@acme.com", "bob@acme.com"]);
}

#[tokio::test]
async fn contacts_enforce_multi_mailbox_isolation_and_auth_scopes() {
    let mut cfg = Config::for_test();
    cfg.user_email = "alice@example.com".to_string();
    cfg.mailboxes = vec!["bob@example.com".to_string()];
    cfg.scoped_tokens = vec![
        ScopedTokenConfig {
            token: "tok_alice_rw".to_string(),
            mailbox_id: Some("alice@example.com".to_string()),
            scopes: vec![AuthScope::Read, AuthScope::Write, AuthScope::Send],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_alice_ro".to_string(),
            mailbox_id: Some("alice@example.com".to_string()),
            scopes: vec![AuthScope::Read],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_bob_rw".to_string(),
            mailbox_id: Some("bob@example.com".to_string()),
            scopes: vec![AuthScope::Read, AuthScope::Write, AuthScope::Send],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
    ];

    let store = Arc::new(SqliteStore::open_in_memory(&cfg.user_email).unwrap());
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store, resend)
        .with_transport(Arc::new(RecordingTransport::new()));
    let app = build_router(state.clone());

    // Alice sends to partner@vendor.com and marks them VIP with private notes
    let (status, _) = send_json(
        &app,
        Method::POST,
        "/v1/messages/send",
        Some("tok_alice_rw"),
        Some(json!({
            "to": ["Partner <partner@vendor.com>"],
            "subject": "Contract",
            "text": "Details attached"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send_json(
        &app,
        Method::PATCH,
        "/v1/contacts/partner%40vendor.com",
        Some("tok_alice_rw"),
        Some(json!({ "is_vip": true, "notes": "Alice only VIP" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Read-only token can GET contacts and call MCP lookup_contact/list_vips, but CANNOT PATCH
    let (status, ro_list) = send_json(
        &app,
        Method::GET,
        "/v1/contacts?vip_only=true",
        Some("tok_alice_ro"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ro_list["count"], 1);

    let (status, _) = send_json(
        &app,
        Method::PATCH,
        "/v1/contacts/partner%40vendor.com",
        Some("tok_alice_ro"),
        Some(json!({ "notes": "unauthorized edit" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Bob's mailbox sees ZERO of Alice's contacts over REST and MCP
    let (status, bob_list) =
        send_json(&app, Method::GET, "/v1/contacts", Some("tok_bob_rw"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bob_list["count"], 0);

    let (status, _) = send_json(
        &app,
        Method::GET,
        "/v1/contacts/partner%40vendor.com",
        Some("tok_bob_rw"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, bob_mcp_lookup) = send_json(
        &app,
        Method::POST,
        "/mcp",
        Some("tok_bob_rw"),
        Some(json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "lookup_contact",
                "arguments": { "email": "partner@vendor.com" }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        bob_mcp_lookup["result"]["structuredContent"]["found"],
        false
    );
    assert_eq!(
        bob_mcp_lookup["result"]["structuredContent"]["is_vip"],
        false
    );

    let (status, bob_mcp_vips) = send_json(
        &app,
        Method::POST,
        "/mcp",
        Some("tok_bob_rw"),
        Some(json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "list_vips",
                "arguments": {}
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bob_mcp_vips["result"]["structuredContent"]["count"], 0);
}
