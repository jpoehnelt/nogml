//! End-to-end integration tests for Issue #34:
//! - REST `GET`, `PUT`, `PATCH`, `DELETE /v1/threads/{id}/annotations`
//! - Persistence across SQLite database reopen
//! - `GET /v1/threads?needs_reply=...&waiting_on=...` filtering and `annotation` inclusion
//!   on `ThreadSummary` and `ThreadDetail`
//! - MCP `annotate_thread`, `get_thread_annotations`, `list_threads` filters, `read_thread`
//! - Scope enforcement and multi-mailbox isolation

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

use nogml::{
    AppState,
    auth::{AuthScope, ScopedTokenConfig},
    build_router,
    config::Config,
    models::{LABEL_INBOX, LABEL_UNREAD},
    resend::HttpResendClient,
    storage::{MailStore, MemoryStore, NewMessageInput, SqliteStore},
};

fn build_memory_app(mut cfg: Config) -> (AppState, Arc<MemoryStore>, Router) {
    cfg.auth_tokens = Vec::new();
    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store.clone(), resend);
    let app = build_router(state.clone());
    (state, store, app)
}

async fn seed_thread_message(
    store: &dyn MailStore,
    id: &str,
    thread_id: &str,
    from: &str,
    subject: &str,
    body: &str,
    ts_ms: i64,
) {
    let raw = format!(
        "From: {from}\r\nTo: agent@example.com\r\nSubject: {subject}\r\nMessage-ID: <{id}@example.test>\r\n\r\n{body}"
    );
    store
        .insert_message(NewMessageInput {
            id: Some(id.to_string()),
            thread_id: Some(thread_id.to_string()),
            label_ids: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            raw_rfc2822: raw.into_bytes(),
            snippet: body.chars().take(120).collect(),
            internal_date_ms: ts_ms,
            subject: subject.to_string(),
            from_addr: from.to_string(),
            to_addrs: vec!["agent@example.com".to_string()],
            cc_addrs: Vec::new(),
            bcc_addrs: Vec::new(),
            text_body: body.to_string(),
            html_body: None,
            rfc822_message_id: Some(format!("<{id}@example.test>")),
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
        .unwrap();
}

async fn http_json(
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
    let val = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, val)
}

#[tokio::test]
async fn rest_put_patch_get_delete_thread_annotations_and_thread_payloads() {
    let (_state, store, app) = build_memory_app(Config::for_test());

    seed_thread_message(
        store.as_ref(),
        "m_1",
        "thr_invoice",
        "billing@acme.test",
        "Invoice #9001 due Friday",
        "Please remit $450 for Invoice #9001.",
        1_700_000_001_000,
    )
    .await;
    seed_thread_message(
        store.as_ref(),
        "m_2",
        "thr_waiting_them",
        "partner@acme.test",
        "Contract redlines",
        "Sent over our edits; awaiting their signoff.",
        1_700_000_002_000,
    )
    .await;
    seed_thread_message(
        store.as_ref(),
        "m_3",
        "thr_unannotated",
        "news@digest.test",
        "Weekly digest",
        "Highlights from this week.",
        1_700_000_003_000,
    )
    .await;

    // Capabilities advertises annotation endpoints
    let (status, caps) = http_json(&app, "GET", "/v1/capabilities", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let endpoints: Vec<&str> = caps["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(endpoints.contains(&"GET /v1/threads/{id}/annotations"));
    assert!(endpoints.contains(&"PUT /v1/threads/{id}/annotations"));
    assert!(endpoints.contains(&"PATCH /v1/threads/{id}/annotations"));

    // Nonexistent thread returns 404 for GET, PUT, PATCH
    for (method, payload) in [
        ("GET", None),
        ("PUT", Some(json!({ "summary": "missing" }))),
        ("PATCH", Some(json!({ "summary": "missing" }))),
    ] {
        let (st, err) = http_json(
            &app,
            method,
            "/v1/threads/thr_missing/annotations",
            None,
            payload,
        )
        .await;
        assert_eq!(st, StatusCode::NOT_FOUND, "expected 404 for {method}");
        assert_eq!(err["error"]["code"], "not_found");
    }

    // Existing unannotated thread returns annotation: null, and ThreadSummary / ThreadDetail omit annotation
    let (status, initial_get) = http_json(
        &app,
        "GET",
        "/v1/threads/thr_invoice/annotations",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(initial_get["thread_id"], "thr_invoice");
    assert!(initial_get["annotation"].is_null());

    let (status, detail_before) =
        http_json(&app, "GET", "/v1/threads/thr_invoice", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(detail_before.get("annotation").is_none());

    // PUT full replace
    let (status, put_resp) = http_json(
        &app,
        "PUT",
        "/v1/threads/thr_invoice/annotations",
        None,
        Some(json!({
            "summary": "Pay Invoice #9001 ($450)",
            "needs_reply": true,
            "waiting_on": "me",
            "priority": "high",
            "due_at": "2026-12-01T17:00:00Z",
            "extracted": {
                "invoice_id": "INV-9001",
                "amount": 450,
                "currency": "USD"
            },
            "updated_by": "triage-cron"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(put_resp["thread_id"], "thr_invoice");
    assert_eq!(
        put_resp["annotation"]["summary"],
        "Pay Invoice #9001 ($450)"
    );
    assert_eq!(put_resp["annotation"]["needs_reply"], true);
    assert_eq!(put_resp["annotation"]["waiting_on"], "me");
    assert_eq!(put_resp["annotation"]["priority"], "high");
    assert_eq!(put_resp["annotation"]["due_at"], "2026-12-01T17:00:00Z");
    assert_eq!(
        put_resp["annotation"]["extracted"]["invoice_id"],
        "INV-9001"
    );
    assert_eq!(put_resp["annotation"]["updated_by"], "triage-cron");

    // PATCH partial update preserves untouched fields and shallow-merges `extracted`
    let (status, patch_resp) = http_json(
        &app,
        "PATCH",
        "/v1/threads/thr_invoice/annotations",
        None,
        Some(json!({
            "priority": "urgent",
            "extracted": {
                "amount": 475,
                "tracking_number": "1Z999AA101"
            },
            "updated_by": "briefing-agent"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        patch_resp["annotation"]["summary"],
        "Pay Invoice #9001 ($450)"
    );
    assert_eq!(patch_resp["annotation"]["needs_reply"], true);
    assert_eq!(patch_resp["annotation"]["waiting_on"], "me");
    assert_eq!(patch_resp["annotation"]["priority"], "urgent");
    assert_eq!(patch_resp["annotation"]["due_at"], "2026-12-01T17:00:00Z");
    assert_eq!(patch_resp["annotation"]["updated_by"], "briefing-agent");
    assert_eq!(
        patch_resp["annotation"]["extracted"],
        json!({
            "invoice_id": "INV-9001",
            "amount": 475,
            "currency": "USD",
            "tracking_number": "1Z999AA101"
        })
    );

    // Annotate second thread as waiting_on=them, needs_reply=false
    let (status, _) = http_json(
        &app,
        "PATCH",
        "/v1/threads/thr_waiting_them/annotations",
        None,
        Some(json!({
            "summary": "Waiting on partner redlines",
            "needs_reply": false,
            "waiting_on": "them"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // GET /v1/threads?needs_reply=true&waiting_on=me
    let (status, filtered) = http_json(
        &app,
        "GET",
        "/v1/threads?needs_reply=true&waiting_on=me",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let threads = filtered["threads"].as_array().unwrap();
    assert_eq!(threads.len(), 1);
    assert_eq!(threads[0]["id"], "thr_invoice");
    assert_eq!(threads[0]["annotation"]["priority"], "urgent");
    assert_eq!(
        threads[0]["annotation"]["extracted"]["tracking_number"],
        "1Z999AA101"
    );

    // GET /v1/threads?waiting_on=them
    let (status, them_filtered) =
        http_json(&app, "GET", "/v1/threads?waiting_on=them", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let them_threads = them_filtered["threads"].as_array().unwrap();
    assert_eq!(them_threads.len(), 1);
    assert_eq!(them_threads[0]["id"], "thr_waiting_them");

    // Invalid waiting_on returns 400 validation error
    let (status, bad_filter) =
        http_json(&app, "GET", "/v1/threads?waiting_on=invalid", None, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(bad_filter["error"]["code"], "validation_error");

    // Unfiltered GET /v1/threads includes annotation on annotated threads and omits it on unannotated ones
    let (status, all_threads) = http_json(&app, "GET", "/v1/threads", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let items = all_threads["threads"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    let unann = items.iter().find(|t| t["id"] == "thr_unannotated").unwrap();
    assert!(unann.get("annotation").is_none());

    // GET /v1/threads/{id} includes annotation on ThreadDetail
    let (status, detail_after) =
        http_json(&app, "GET", "/v1/threads/thr_invoice", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail_after["annotation"]["waiting_on"], "me");
    assert_eq!(
        detail_after["annotation"]["extracted"]["invoice_id"],
        "INV-9001"
    );

    // PUT replaces completely (clearing omitted priority & due_at)
    let (status, replaced) = http_json(
        &app,
        "PUT",
        "/v1/threads/thr_invoice/annotations",
        None,
        Some(json!({
            "summary": "Paid in full",
            "needs_reply": false,
            "waiting_on": "none",
            "extracted": { "paid": true }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(replaced["annotation"].get("priority").is_none());
    assert!(replaced["annotation"].get("due_at").is_none());
    assert_eq!(replaced["annotation"]["extracted"], json!({ "paid": true }));

    // DELETE clears the annotation
    let (status, deleted) = http_json(
        &app,
        "DELETE",
        "/v1/threads/thr_invoice/annotations",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(deleted["deleted"], true);

    let (status, after_del) = http_json(
        &app,
        "GET",
        "/v1/threads/thr_invoice/annotations",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(after_del["annotation"].is_null());
}

#[tokio::test]
async fn sqlite_reopen_persists_annotations_and_filters() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("annotations_persist.db");

    // Phase 1: open SQLite, seed threads, write annotations via REST
    {
        let mut cfg = Config::for_test();
        cfg.auth_tokens = Vec::new();
        cfg.db_path = db_path.clone();
        let store = Arc::new(SqliteStore::open(&db_path, &cfg.user_email).unwrap());
        let resend = Arc::new(HttpResendClient::from_config(&cfg));
        let state = AppState::with_backends(cfg, store.clone(), resend);
        let app = build_router(state);

        seed_thread_message(
            store.as_ref(),
            "m_persist_1",
            "thr_persist_1",
            "ops@vendor.test",
            "Action needed: renew certificate",
            "Your TLS certificate expires next week.",
            1_700_000_010_000,
        )
        .await;
        seed_thread_message(
            store.as_ref(),
            "m_persist_2",
            "thr_persist_2",
            "fyi@vendor.test",
            "Monthly newsletter",
            "Product updates.",
            1_700_000_020_000,
        )
        .await;

        let (status, _) = http_json(
            &app,
            "PUT",
            "/v1/threads/thr_persist_1/annotations",
            None,
            Some(json!({
                "summary": "Renew TLS cert before expiry",
                "needs_reply": true,
                "waiting_on": "me",
                "priority": "p1",
                "due_at": "2026-12-10T00:00:00Z",
                "extracted": { "domain": "mail.example.com" },
                "updated_by": "ops-bot"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = http_json(
            &app,
            "PATCH",
            "/v1/threads/thr_persist_1/annotations",
            None,
            Some(json!({
                "extracted": { "ticket_id": "OPS-42" },
                "updated_by": "ops-bot-patch"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    // Phase 2: reopen brand-new SqliteStore & router from the same file
    {
        let mut cfg = Config::for_test();
        cfg.auth_tokens = Vec::new();
        cfg.db_path = db_path.clone();
        let store = Arc::new(SqliteStore::open(&db_path, &cfg.user_email).unwrap());
        let resend = Arc::new(HttpResendClient::from_config(&cfg));
        let state = AppState::with_backends(cfg, store, resend);
        let app = build_router(state);

        let (status, ann) = http_json(
            &app,
            "GET",
            "/v1/threads/thr_persist_1/annotations",
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ann["annotation"]["summary"], "Renew TLS cert before expiry");
        assert_eq!(ann["annotation"]["needs_reply"], true);
        assert_eq!(ann["annotation"]["waiting_on"], "me");
        assert_eq!(ann["annotation"]["priority"], "p1");
        assert_eq!(ann["annotation"]["due_at"], "2026-12-10T00:00:00Z");
        assert_eq!(
            ann["annotation"]["extracted"],
            json!({
                "domain": "mail.example.com",
                "ticket_id": "OPS-42"
            })
        );

        let (status, filtered) = http_json(
            &app,
            "GET",
            "/v1/threads?needs_reply=true&waiting_on=me",
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let threads = filtered["threads"].as_array().unwrap();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0]["id"], "thr_persist_1");
        assert_eq!(threads[0]["annotation"]["extracted"]["ticket_id"], "OPS-42");

        let (status, detail) =
            http_json(&app, "GET", "/v1/threads/thr_persist_1", None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(detail["annotation"]["updated_by"], "ops-bot-patch");
    }
}

#[tokio::test]
async fn mcp_annotate_thread_get_annotations_list_threads_and_scopes() {
    let mut cfg = Config::for_test();
    cfg.auth_tokens = Vec::new();
    cfg.scoped_tokens = vec![
        ScopedTokenConfig {
            token: "tok_read_only".to_string(),
            mailbox_id: Some(cfg.user_email.clone()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_read_write".to_string(),
            mailbox_id: Some(cfg.user_email.clone()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read, AuthScope::Write],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
    ];
    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store.clone(), resend);
    let app = build_router(state);

    seed_thread_message(
        store.as_ref(),
        "m_mcp_1",
        "thr_mcp_1",
        "client@acme.test",
        "Proposal Q4",
        "Can you send the final quote by Wednesday?",
        1_700_000_100_000,
    )
    .await;
    seed_thread_message(
        store.as_ref(),
        "m_mcp_2",
        "thr_mcp_2",
        "team@acme.test",
        "Standup notes",
        "All done.",
        1_700_000_200_000,
    )
    .await;

    // 1. tools/list advertises annotate_thread, get_thread_annotations, and list_threads filters
    let (status, tools_resp) = http_json(
        &app,
        "POST",
        "/mcp",
        Some("tok_read_only"),
        Some(json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let tools = tools_resp["result"]["tools"].as_array().unwrap();
    let list_threads_tool = tools.iter().find(|t| t["name"] == "list_threads").unwrap();
    assert!(
        list_threads_tool["inputSchema"]["properties"]
            .get("needs_reply")
            .is_some()
    );
    assert!(
        list_threads_tool["inputSchema"]["properties"]
            .get("waiting_on")
            .is_some()
    );
    assert!(tools.iter().any(|t| t["name"] == "annotate_thread"));
    assert!(tools.iter().any(|t| t["name"] == "get_thread_annotations"));

    // 2. Read-only token can call get_thread_annotations but is forbidden from annotate_thread
    let (status, get_empty) = http_json(
        &app,
        "POST",
        "/mcp",
        Some("tok_read_only"),
        Some(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "get_thread_annotations",
                "arguments": { "thread_id": "thr_mcp_1" }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(get_empty["result"]["isError"], false);
    assert!(get_empty["result"]["structuredContent"]["annotation"].is_null());

    let (status, forbidden_write) = http_json(
        &app,
        "POST",
        "/mcp",
        Some("tok_read_only"),
        Some(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "annotate_thread",
                "arguments": { "thread_id": "thr_mcp_1", "needs_reply": true }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(forbidden_write["result"]["isError"], true);
    assert_eq!(
        forbidden_write["result"]["structuredContent"]["error"]["code"],
        "forbidden"
    );

    // 3. Write token annotates thread in two incremental patches
    let (status, ann1) = http_json(
        &app,
        "POST",
        "/mcp",
        Some("tok_read_write"),
        Some(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "annotate_thread",
                "arguments": {
                    "thread_id": "thr_mcp_1",
                    "summary": "Client requested Q4 quote",
                    "needs_reply": true,
                    "waiting_on": "me",
                    "priority": "high",
                    "extracted": { "quarter": "Q4", "client": "Acme" }
                }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ann1["result"]["isError"], false);
    assert_eq!(
        ann1["result"]["structuredContent"]["annotation"]["waiting_on"],
        "me"
    );

    let (status, ann2) = http_json(
        &app,
        "POST",
        "/mcp",
        Some("tok_read_write"),
        Some(json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "annotate_thread",
                "arguments": {
                    "thread_id": "thr_mcp_1",
                    "due_at": "2026-12-03T18:00:00Z",
                    "extracted": { "quote_amount": 12000 }
                }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let merged = &ann2["result"]["structuredContent"]["annotation"];
    assert_eq!(merged["summary"], "Client requested Q4 quote");
    assert_eq!(merged["needs_reply"], true);
    assert_eq!(merged["due_at"], "2026-12-03T18:00:00Z");
    assert_eq!(
        merged["extracted"],
        json!({ "quarter": "Q4", "client": "Acme", "quote_amount": 12000 })
    );

    // 4. MCP get_thread_annotations returns merged state
    let (status, got) = http_json(
        &app,
        "POST",
        "/mcp",
        Some("tok_read_only"),
        Some(json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "get_thread_annotations",
                "arguments": { "thread_id": "thr_mcp_1" }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        got["result"]["structuredContent"]["annotation"]["extracted"]["quote_amount"],
        12000
    );

    // 5. MCP list_threads filters by needs_reply and waiting_on and includes annotation
    let (status, listed) = http_json(
        &app,
        "POST",
        "/mcp",
        Some("tok_read_only"),
        Some(json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "list_threads",
                "arguments": { "needs_reply": true, "waiting_on": "me" }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let list_threads = listed["result"]["structuredContent"]["threads"]
        .as_array()
        .unwrap();
    assert_eq!(list_threads.len(), 1);
    assert_eq!(list_threads[0]["id"], "thr_mcp_1");
    assert_eq!(
        list_threads[0]["annotation"]["summary"],
        "Client requested Q4 quote"
    );

    // 6. MCP read_thread includes annotation on ThreadDetail
    let (status, read_thr) = http_json(
        &app,
        "POST",
        "/mcp",
        Some("tok_read_only"),
        Some(json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "read_thread",
                "arguments": { "thread_id": "thr_mcp_1" }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        read_thr["result"]["structuredContent"]["annotation"]["waiting_on"],
        "me"
    );

    // 7. Missing thread returns structured not_found error
    let (status, missing) = http_json(
        &app,
        "POST",
        "/mcp",
        Some("tok_read_only"),
        Some(json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "get_thread_annotations",
                "arguments": { "thread_id": "thr_does_not_exist" }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(missing["result"]["isError"], true);
    assert_eq!(
        missing["result"]["structuredContent"]["error"]["code"],
        "not_found"
    );
}

#[tokio::test]
async fn multi_mailbox_annotations_isolation_via_rest_and_mcp() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("multi_mailbox_annotations.db");

    let mut cfg = Config::for_test();
    cfg.user_email = "alice@example.com".to_string();
    cfg.mailboxes = vec!["bob@example.com".to_string()];
    cfg.auth_tokens = Vec::new();
    cfg.db_path = db_path.clone();
    cfg.scoped_tokens = vec![
        ScopedTokenConfig {
            token: "tok_alice".to_string(),
            mailbox_id: Some("alice@example.com".to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read, AuthScope::Write],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_bob".to_string(),
            mailbox_id: Some("bob@example.com".to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read, AuthScope::Write],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
    ];

    let store = Arc::new(SqliteStore::open(&db_path, &cfg.user_email).unwrap());
    let alice_store = store.for_mailbox("alice@example.com");
    let bob_store = store.for_mailbox("bob@example.com");

    seed_thread_message(
        alice_store.as_ref(),
        "m_alice",
        "thr_same",
        "ceo@acme.test",
        "Alice confidential",
        "Alice secret message",
        1_700_000_001_000,
    )
    .await;
    seed_thread_message(
        bob_store.as_ref(),
        "m_bob",
        "thr_same",
        "ops@acme.test",
        "Bob thread",
        "Bob regular message",
        1_700_000_002_000,
    )
    .await;

    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store, resend);
    let app = build_router(state);

    // Alice annotates thr_same via REST
    let (status, _) = http_json(
        &app,
        "PUT",
        "/v1/threads/thr_same/annotations",
        Some("tok_alice"),
        Some(json!({
            "summary": "Alice private triage note",
            "needs_reply": true,
            "waiting_on": "me",
            "extracted": { "secret": "alice-only" }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Bob sees NO annotation on his thr_same via REST or MCP
    let (status, bob_get) = http_json(
        &app,
        "GET",
        "/v1/threads/thr_same/annotations",
        Some("tok_bob"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(bob_get["annotation"].is_null());

    let (status, bob_list) = http_json(
        &app,
        "GET",
        "/v1/threads?needs_reply=true&waiting_on=me",
        Some("tok_bob"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(bob_list["threads"].as_array().unwrap().is_empty());

    // Bob annotates his own thr_same via MCP
    let (status, bob_mcp) = http_json(
        &app,
        "POST",
        "/mcp",
        Some("tok_bob"),
        Some(json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "annotate_thread",
                "arguments": {
                    "thread_id": "thr_same",
                    "summary": "Bob independent note",
                    "needs_reply": false,
                    "waiting_on": "them",
                    "extracted": { "owner": "bob" }
                }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bob_mcp["result"]["isError"], false);

    // Alice's annotation is untouched; each mailbox sees only its own
    let (status, alice_get) = http_json(
        &app,
        "GET",
        "/v1/threads/thr_same/annotations",
        Some("tok_alice"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        alice_get["annotation"]["summary"],
        "Alice private triage note"
    );
    assert_eq!(alice_get["annotation"]["waiting_on"], "me");
    assert_eq!(
        alice_get["annotation"]["extracted"],
        json!({ "secret": "alice-only" })
    );

    let (status, bob_detail) =
        http_json(&app, "GET", "/v1/threads/thr_same", Some("tok_bob"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bob_detail["annotation"]["summary"], "Bob independent note");
    assert_eq!(bob_detail["annotation"]["waiting_on"], "them");
}
