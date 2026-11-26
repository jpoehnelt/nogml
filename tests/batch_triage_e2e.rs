//! End-to-end tests for atomic batch thread triage (`POST /v1/threads/batch_triage`,
//! MCP `batch_triage`, CLI `nogml mail batch-triage`, and multi-mailbox isolation) (`Issue #39`).

use std::{process::Command, sync::Arc};

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
    events::MailEvent,
    models::{LABEL_INBOX, LABEL_STARRED, LABEL_TRASH, LABEL_UNREAD},
    resend::HttpResendClient,
    storage::{MailStore, NewLabelInput, NewMessageInput, SqliteStore},
};

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

#[allow(clippy::too_many_arguments)]
async fn seed_message(
    store: &Arc<dyn MailStore>,
    id: &str,
    thread_id: &str,
    from: &str,
    subject: &str,
    body: &str,
    labels: Vec<&str>,
) {
    let raw = format!(
        "From: {from}\r\nTo: {}\r\nSubject: {subject}\r\nMessage-ID: <{id}@example.com>\r\n\r\n{body}",
        store.mailbox_id()
    );
    store
        .insert_message(NewMessageInput {
            id: Some(id.to_string()),
            thread_id: Some(thread_id.to_string()),
            label_ids: labels.into_iter().map(str::to_string).collect(),
            raw_rfc2822: raw.into_bytes(),
            snippet: body.to_string(),
            internal_date_ms: Utc::now().timestamp_millis(),
            subject: subject.to_string(),
            from_addr: from.to_string(),
            to_addrs: vec![store.mailbox_id().to_string()],
            cc_addrs: Vec::new(),
            bcc_addrs: Vec::new(),
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
            attachments: Vec::new(),
        })
        .await
        .expect("seed message");
}

fn make_sqlite_state(cfg: Config) -> (AppState, Arc<dyn MailStore>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("batch_triage.db");
    let store: Arc<dyn MailStore> =
        Arc::new(SqliteStore::open(&db_path, &cfg.user_email).expect("open sqlite"));
    let resend = Arc::new(HttpResendClient::new(
        cfg.resend_base_url.clone(),
        cfg.resend_api_key.clone(),
    ));
    let state = AppState::with_backends(cfg, store.clone(), resend);
    (state, store, dir)
}

#[tokio::test]
async fn batch_triage_dry_run_previews_diffs_with_zero_writes_events_or_audit() {
    let cfg = Config::for_test();
    let (state, store, _dir) = make_sqlite_state(cfg);
    let vip_label = store
        .create_label(NewLabelInput {
            name: "VIP".to_string(),
            ..Default::default()
        })
        .await
        .expect("create VIP label");

    seed_message(
        &store,
        "m_dry_1",
        "t_dry_1",
        "News <news@example.com>",
        "Weekly Digest",
        "This week's newsletter highlights",
        vec![LABEL_INBOX, LABEL_UNREAD],
    )
    .await;
    seed_message(
        &store,
        "m_dry_2",
        "t_dry_2",
        "Boss <boss@example.com>",
        "Q4 Roadmap",
        "Please review before Friday",
        vec![LABEL_INBOX],
    )
    .await;
    seed_message(
        &store,
        "m_dry_3",
        "t_dry_3",
        "Already Done <done@example.com>",
        "Archived Note",
        "Nothing left to change here",
        vec![LABEL_STARRED],
    )
    .await;

    let history_before = store.current_history_id().await.unwrap();
    let mut events_rx = state.events.subscribe();
    let app = build_router(state.clone());

    let (status, body) = http_req(
        &app,
        "POST",
        "/v1/threads/batch_triage",
        &[],
        Some(json!({
            "dry_run": true,
            "operations": [
                {
                    "thread_id": "t_dry_1",
                    "archive": true,
                    "mark_read": true
                },
                {
                    "thread_id": "t_dry_2",
                    "star": true,
                    "add_labels": ["VIP"]
                },
                {
                    "thread_id": "t_dry_3",
                    "archive": true,
                    "star": true
                }
            ]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "dry_run failed: {body}");
    assert_eq!(body["dry_run"], true);
    assert_eq!(body["total_threads"], 3);
    assert_eq!(body["would_change_count"], 2);

    let preview = body["preview"].as_array().unwrap();
    assert_eq!(preview.len(), 3);

    assert_eq!(preview[0]["thread_id"], "t_dry_1");
    assert_eq!(preview[0]["subject"], "Weekly Digest");
    assert_eq!(preview[0]["current_labels"], json!(["INBOX", "UNREAD"]));
    assert_eq!(preview[0]["labels_to_add"], json!([]));
    assert_eq!(preview[0]["labels_to_remove"], json!(["INBOX", "UNREAD"]));
    assert_eq!(preview[0]["would_change"], true);

    assert_eq!(preview[1]["thread_id"], "t_dry_2");
    assert_eq!(preview[1]["subject"], "Q4 Roadmap");
    assert_eq!(preview[1]["current_labels"], json!(["INBOX"]));
    assert_eq!(
        preview[1]["labels_to_add"],
        json!([LABEL_STARRED, vip_label.id])
    );
    assert_eq!(preview[1]["labels_to_remove"], json!([]));
    assert_eq!(preview[1]["would_change"], true);

    // Already archived and starred -> would_change is false
    assert_eq!(preview[2]["thread_id"], "t_dry_3");
    assert_eq!(preview[2]["subject"], "Archived Note");
    assert_eq!(preview[2]["current_labels"], json!(["STARRED"]));
    assert_eq!(preview[2]["labels_to_add"], json!([]));
    assert_eq!(preview[2]["labels_to_remove"], json!([]));
    assert_eq!(preview[2]["would_change"], false);

    // Zero store writes: history_id unchanged, labels unchanged, zero audit entries
    let history_after = store.current_history_id().await.unwrap();
    assert_eq!(history_after, history_before, "dry_run mutated history_id");

    let m1 = store.get_message("m_dry_1").await.unwrap().unwrap();
    assert!(m1.label_ids.contains(&LABEL_INBOX.to_string()));
    assert!(m1.label_ids.contains(&LABEL_UNREAD.to_string()));

    let m2 = store.get_message("m_dry_2").await.unwrap().unwrap();
    assert!(!m2.label_ids.contains(&LABEL_STARRED.to_string()));

    // Zero SSE / EventBus events emitted
    assert!(
        events_rx.try_recv().is_err(),
        "dry_run must not emit any MailEvent"
    );

    // Zero audit entries written
    let (audit_status, audit_body) = http_req(&app, "GET", "/v1/audit", &[], None).await;
    assert_eq!(audit_status, StatusCode::OK);
    assert_eq!(
        audit_body["count"], 0,
        "dry_run must not write any audit entries: {audit_body}"
    );
}

#[tokio::test]
async fn batch_triage_apply_heterogeneous_operations_and_query_bulk_archive_with_audit() {
    let cfg = Config::for_test();
    let (state, store, _dir) = make_sqlite_state(cfg);
    let follow_up = store
        .create_label(NewLabelInput {
            name: "FollowUp".to_string(),
            ..Default::default()
        })
        .await
        .expect("create label");

    seed_message(
        &store,
        "m_op_1",
        "t_op_1",
        "Alice <alice@example.com>",
        "Project Kickoff",
        "Kickoff notes",
        vec![LABEL_INBOX, LABEL_UNREAD],
    )
    .await;
    seed_message(
        &store,
        "m_op_2",
        "t_op_2",
        "Bob <bob@example.com>",
        "Contract Draft",
        "Please sign today",
        vec![LABEL_INBOX],
    )
    .await;
    seed_message(
        &store,
        "m_op_3",
        "t_op_3",
        "Carol <carol@example.com>",
        "Already Archived",
        "Old thread",
        vec![LABEL_STARRED],
    )
    .await;

    // Two newsletter threads + one unrelated thread for query-based bulk archive
    seed_message(
        &store,
        "m_news_1",
        "t_news_1",
        "Digest <digest@news.example.com>",
        "Rust Newsletter #42",
        "Monthly newsletter roundup",
        vec![LABEL_INBOX, LABEL_UNREAD],
    )
    .await;
    seed_message(
        &store,
        "m_news_2",
        "t_news_2",
        "Updates <updates@news.example.com>",
        "Cloud Newsletter #99",
        "Weekly newsletter tips",
        vec![LABEL_INBOX, LABEL_UNREAD],
    )
    .await;
    seed_message(
        &store,
        "m_keep_1",
        "t_keep_1",
        "Direct <ceo@example.com>",
        "Urgent Invoice",
        "Needs immediate approval",
        vec![LABEL_INBOX, LABEL_UNREAD],
    )
    .await;

    let mut events_rx = state.events.subscribe();
    let app = build_router(state.clone());

    // 1. Heterogeneous per-thread operations + ?fields= check on a separate call
    let (status, body) = http_req(
        &app,
        "POST",
        "/v1/threads/batch_triage",
        &[],
        Some(json!({
            "dry_run": false,
            "operations": [
                {
                    "thread_id": "t_op_1",
                    "archive": true,
                    "mark_read": true
                },
                {
                    "thread_id": "t_op_2",
                    "star": true,
                    "add_labels": ["FollowUp"]
                },
                {
                    "thread_id": "t_op_3",
                    "archive": true,
                    "star": true
                }
            ]
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "apply ops failed: {body}");
    assert_eq!(body["dry_run"], false);
    assert_eq!(body["total_threads"], 3);
    assert_eq!(body["applied_count"], 2);
    assert_eq!(body["skipped_count"], 1);
    assert_eq!(body["errors"], json!([]));
    assert_eq!(body["results"].as_array().unwrap().len(), 3);

    // Verify stored mutations
    let m1 = store.get_message("m_op_1").await.unwrap().unwrap();
    assert!(!m1.label_ids.contains(&LABEL_INBOX.to_string()));
    assert!(!m1.label_ids.contains(&LABEL_UNREAD.to_string()));

    let m2 = store.get_message("m_op_2").await.unwrap().unwrap();
    assert!(m2.label_ids.contains(&LABEL_STARRED.to_string()));
    assert!(m2.label_ids.contains(&follow_up.id));

    // Verify exactly 2 MessageUpdated events emitted (skipped thread emitted none)
    let mut updated_threads = Vec::new();
    while let Ok(env) = events_rx.try_recv() {
        if let MailEvent::MessageUpdated { thread_id, .. } = env.event {
            updated_threads.push(thread_id);
        }
    }
    updated_threads.sort();
    assert_eq!(updated_threads, vec!["t_op_1", "t_op_2"]);

    // 2. Query-based bulk archive using shorthand flags (`query: "newsletter"`, `archive: true`, `mark_read: true`)
    //    and `?fields=` projection mask
    let (q_status, q_body) = http_req(
        &app,
        "POST",
        "/v1/threads/batch_triage?fields=dry_run,applied_count,skipped_count,errors",
        &[],
        Some(json!({
            "query": "newsletter",
            "archive": true,
            "mark_read": true,
            "dry_run": false
        })),
    )
    .await;

    assert_eq!(
        q_status,
        StatusCode::OK,
        "query bulk archive failed: {q_body}"
    );
    assert_eq!(q_body["dry_run"], false);
    assert_eq!(q_body["applied_count"], 2);
    assert_eq!(q_body["skipped_count"], 0);
    assert_eq!(q_body["errors"], json!([]));
    // Field mask omitted `results`
    assert!(q_body.get("results").is_none());

    for mid in ["m_news_1", "m_news_2"] {
        let msg = store.get_message(mid).await.unwrap().unwrap();
        assert!(!msg.label_ids.contains(&LABEL_INBOX.to_string()));
        assert!(!msg.label_ids.contains(&LABEL_UNREAD.to_string()));
    }
    // Unrelated thread remains untouched in INBOX + UNREAD
    let keep = store.get_message("m_keep_1").await.unwrap().unwrap();
    assert!(keep.label_ids.contains(&LABEL_INBOX.to_string()));
    assert!(keep.label_ids.contains(&LABEL_UNREAD.to_string()));

    // 3. Explicit `thread_ids` + `action` object mode
    let (t_status, t_body) = http_req(
        &app,
        "POST",
        "/v1/threads/batch_triage",
        &[],
        Some(json!({
            "thread_ids": ["t_keep_1"],
            "action": {
                "trash": true
            }
        })),
    )
    .await;
    assert_eq!(
        t_status,
        StatusCode::OK,
        "thread_ids+action failed: {t_body}"
    );
    assert_eq!(t_body["applied_count"], 1);
    let trashed = store.get_message("m_keep_1").await.unwrap().unwrap();
    assert!(trashed.label_ids.contains(&LABEL_TRASH.to_string()));
    assert!(!trashed.label_ids.contains(&LABEL_INBOX.to_string()));

    // 4. Immutable audit log contains all batch_triage runs with modified thread IDs
    let (audit_status, audit_body) =
        http_req(&app, "GET", "/v1/audit?action=batch_triage", &[], None).await;
    assert_eq!(audit_status, StatusCode::OK);
    let entries = audit_body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 3, "expected 3 batch_triage audit entries");
    // Newest first: entries[0] = t_keep_1, entries[1] = newsletters, entries[2] = t_op_1/t_op_2
    assert_eq!(entries[0]["action"], "batch_triage");
    assert_eq!(entries[0]["target_ids"], json!(["t_keep_1"]));
    let mut news_targets: Vec<String> = entries[1]["target_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    news_targets.sort();
    assert_eq!(news_targets, vec!["t_news_1", "t_news_2"]);
    assert_eq!(entries[2]["target_ids"], json!(["t_op_1", "t_op_2"]));
}

#[tokio::test]
async fn batch_triage_enforces_max_threads_and_upfront_atomic_validation() {
    let cfg = Config::for_test();
    let (state, store, _dir) = make_sqlite_state(cfg);

    for i in 1..=5 {
        seed_message(
            &store,
            &format!("m_cap_{i}"),
            &format!("t_cap_{i}"),
            "News <news@example.com>",
            &format!("Newsletter #{i}"),
            "Bulk newsletter body",
            vec![LABEL_INBOX, LABEL_UNREAD],
        )
        .await;
    }

    let history_before = store.current_history_id().await.unwrap();
    let mut events_rx = state.events.subscribe();
    let app = build_router(state.clone());

    // 1. Query matches 5 threads while max_threads=3 -> 400 Bad Request, zero mutations
    let (status, body) = http_req(
        &app,
        "POST",
        "/v1/threads/batch_triage",
        &[],
        Some(json!({
            "query": "newsletter",
            "archive": true,
            "max_threads": 3
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "expected 400: {body}");
    assert_eq!(body["error"]["code"], "validation_error");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("max_threads"),
        "expected clear max_threads message: {body}"
    );

    // 2. Explicit operations exceeding max_threads=2 -> 400 Bad Request
    let (status2, body2) = http_req(
        &app,
        "POST",
        "/v1/threads/batch_triage",
        &[],
        Some(json!({
            "max_threads": 2,
            "operations": [
                { "thread_id": "t_cap_1", "archive": true },
                { "thread_id": "t_cap_2", "archive": true },
                { "thread_id": "t_cap_3", "archive": true }
            ]
        })),
    )
    .await;
    assert_eq!(status2, StatusCode::BAD_REQUEST, "expected 400: {body2}");

    // 3. max_threads=0 -> 400 Bad Request
    let (status3, _) = http_req(
        &app,
        "POST",
        "/v1/threads/batch_triage",
        &[],
        Some(json!({
            "max_threads": 0,
            "operations": [
                { "thread_id": "t_cap_1", "archive": true }
            ]
        })),
    )
    .await;
    assert_eq!(status3, StatusCode::BAD_REQUEST);

    // 4. Atomic upfront validation: one valid thread + one missing thread -> 404 Not Found, ZERO mutations to t_cap_1!
    let (status4, body4) = http_req(
        &app,
        "POST",
        "/v1/threads/batch_triage",
        &[],
        Some(json!({
            "operations": [
                { "thread_id": "t_cap_1", "archive": true },
                { "thread_id": "t_does_not_exist", "archive": true }
            ]
        })),
    )
    .await;
    assert_eq!(status4, StatusCode::NOT_FOUND, "expected 404: {body4}");

    // 5. Atomic upfront label validation: valid op + unknown add_label -> 400 Bad Request, ZERO mutations!
    let (status5, body5) = http_req(
        &app,
        "POST",
        "/v1/threads/batch_triage",
        &[],
        Some(json!({
            "operations": [
                { "thread_id": "t_cap_1", "archive": true },
                { "thread_id": "t_cap_2", "add_labels": ["NonExistentLabel"] }
            ]
        })),
    )
    .await;
    assert_eq!(status5, StatusCode::BAD_REQUEST, "expected 400: {body5}");

    // Confirm ZERO store writes and ZERO events across all failed attempts
    assert_eq!(store.current_history_id().await.unwrap(), history_before);
    for i in 1..=5 {
        let msg = store
            .get_message(&format!("m_cap_{i}"))
            .await
            .unwrap()
            .unwrap();
        assert!(msg.label_ids.contains(&LABEL_INBOX.to_string()));
        assert!(msg.label_ids.contains(&LABEL_UNREAD.to_string()));
    }
    assert!(events_rx.try_recv().is_err());
}

#[tokio::test]
async fn batch_triage_mcp_scopes_and_multi_mailbox_isolation() {
    let mut cfg = Config::for_test();
    cfg.user_email = "alice@example.com".to_string();
    cfg.mailboxes = vec!["bob@example.com".to_string()];
    cfg.scoped_tokens = vec![
        ScopedTokenConfig {
            token: "tok_alice_rw".to_string(),
            mailbox_id: Some("alice@example.com".to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read, AuthScope::Write],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_alice_ro".to_string(),
            mailbox_id: Some("alice@example.com".to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_bob_rw".to_string(),
            mailbox_id: Some("bob@example.com".to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read, AuthScope::Write],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
    ];

    let (state, alice_store, _dir) = make_sqlite_state(cfg);
    let bob_store = alice_store.for_mailbox("bob@example.com");

    seed_message(
        &alice_store,
        "m_alice_1",
        "t_alice_1",
        "News <news@example.com>",
        "Alice Newsletter",
        "Alice's newsletter content",
        vec![LABEL_INBOX, LABEL_UNREAD],
    )
    .await;
    seed_message(
        &bob_store,
        "m_bob_1",
        "t_bob_1",
        "News <news@example.com>",
        "Bob Newsletter",
        "Bob's private newsletter content",
        vec![LABEL_INBOX, LABEL_UNREAD],
    )
    .await;

    let app = build_router(state);
    let alice_rw = [("authorization", "Bearer tok_alice_rw")];
    let alice_ro = [("authorization", "Bearer tok_alice_ro")];
    let bob_rw = [("authorization", "Bearer tok_bob_rw")];

    // 1. Read-only token is denied (403) on REST POST /v1/threads/batch_triage
    let (ro_status, _) = http_req(
        &app,
        "POST",
        "/v1/threads/batch_triage",
        &alice_ro,
        Some(json!({
            "query": "newsletter",
            "archive": true,
            "dry_run": true
        })),
    )
    .await;
    assert_eq!(ro_status, StatusCode::FORBIDDEN);

    // 2. Read-only token is denied (403 + isError: true) on MCP batch_triage
    let (mcp_ro_status, mcp_ro_body) = http_req(
        &app,
        "POST",
        "/mcp",
        &alice_ro,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "batch_triage",
                "arguments": {
                    "query": "newsletter",
                    "archive": true,
                    "dry_run": true
                }
            }
        })),
    )
    .await;
    assert_eq!(mcp_ro_status, StatusCode::FORBIDDEN);
    assert_eq!(mcp_ro_body["result"]["isError"], true);

    // 3. Alice cannot batch-triage Bob's thread via explicit thread_id over REST (404)
    let (cross_rest_status, _) = http_req(
        &app,
        "POST",
        "/v1/threads/batch_triage",
        &alice_rw,
        Some(json!({
            "operations": [
                { "thread_id": "t_bob_1", "trash": true }
            ]
        })),
    )
    .await;
    assert_eq!(cross_rest_status, StatusCode::NOT_FOUND);

    // 4. Alice cannot batch-triage Bob's thread via explicit thread_id over MCP (isError: true, not_found)
    let (cross_mcp_status, cross_mcp_body) = http_req(
        &app,
        "POST",
        "/mcp",
        &alice_rw,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "batch_triage",
                "arguments": {
                    "thread_ids": ["t_bob_1"],
                    "action": { "trash": true }
                }
            }
        })),
    )
    .await;
    assert_eq!(cross_mcp_status, StatusCode::OK);
    assert_eq!(cross_mcp_body["result"]["isError"], true);
    assert_eq!(
        cross_mcp_body["result"]["structuredContent"]["error"]["code"],
        "not_found"
    );

    // 5. Alice calls MCP batch_triage with query="newsletter" -> only Alice's thread is previewed & archived; Bob's is untouched!
    let (mcp_dry_status, mcp_dry_body) = http_req(
        &app,
        "POST",
        "/mcp",
        &alice_rw,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "batch_triage",
                "arguments": {
                    "query": "newsletter",
                    "archive": true,
                    "mark_read": true,
                    "dry_run": true
                }
            }
        })),
    )
    .await;
    assert_eq!(mcp_dry_status, StatusCode::OK);
    assert_eq!(mcp_dry_body["result"]["isError"], false);
    let dry_sc = &mcp_dry_body["result"]["structuredContent"];
    assert_eq!(dry_sc["dry_run"], true);
    assert_eq!(dry_sc["total_threads"], 1);
    assert_eq!(dry_sc["would_change_count"], 1);
    assert_eq!(dry_sc["preview"][0]["thread_id"], "t_alice_1");

    let (mcp_apply_status, mcp_apply_body) = http_req(
        &app,
        "POST",
        "/mcp",
        &alice_rw,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "batch_triage",
                "arguments": {
                    "query": "newsletter",
                    "archive": true,
                    "mark_read": true,
                    "dry_run": false
                }
            }
        })),
    )
    .await;
    assert_eq!(mcp_apply_status, StatusCode::OK);
    assert_eq!(mcp_apply_body["result"]["isError"], false);
    let apply_sc = &mcp_apply_body["result"]["structuredContent"];
    assert_eq!(apply_sc["dry_run"], false);
    assert_eq!(apply_sc["applied_count"], 1);
    assert_eq!(apply_sc["results"][0]["thread_id"], "t_alice_1");

    // Alice's message is archived & read
    let alice_msg = alice_store.get_message("m_alice_1").await.unwrap().unwrap();
    assert!(!alice_msg.label_ids.contains(&LABEL_INBOX.to_string()));
    assert!(!alice_msg.label_ids.contains(&LABEL_UNREAD.to_string()));

    // Bob's message is completely untouched
    let bob_msg = bob_store.get_message("m_bob_1").await.unwrap().unwrap();
    assert!(bob_msg.label_ids.contains(&LABEL_INBOX.to_string()));
    assert!(bob_msg.label_ids.contains(&LABEL_UNREAD.to_string()));

    // Bob's audit log does NOT see Alice's MCP batch_triage entries; Alice sees both the successful call and the earlier scope-denied call
    let (_, alice_audit) = http_req(
        &app,
        "GET",
        "/v1/audit?action=batch_triage",
        &alice_rw,
        None,
    )
    .await;
    assert_eq!(alice_audit["count"], 2);
    assert_eq!(alice_audit["entries"][0]["channel"], "/mcp");
    assert_eq!(alice_audit["entries"][0]["outcome"], "ok");
    assert_eq!(
        alice_audit["entries"][0]["target_ids"],
        json!(["t_alice_1"])
    );
    assert_eq!(alice_audit["entries"][1]["channel"], "/mcp");
    assert_eq!(alice_audit["entries"][1]["outcome"], "denied");

    let (_, bob_audit) =
        http_req(&app, "GET", "/v1/audit?action=batch_triage", &bob_rw, None).await;
    assert_eq!(bob_audit["count"], 0);
}

#[test]
fn cli_batch_triage_and_runtime_schema() {
    let bin = env!("CARGO_BIN_EXE_nogml");

    // 1. Runtime schema exposes mail.batch_triage
    let schema_out = Command::new(bin)
        .args(["schema", "--command", "batch_triage"])
        .output()
        .expect("run nogml schema");
    assert!(schema_out.status.success());
    let schema_json: Value = serde_json::from_slice(&schema_out.stdout).expect("valid schema json");
    assert_eq!(schema_json["command"], "mail.batch_triage");
    assert_eq!(
        schema_json["schema"]["endpoint"],
        "POST /v1/threads/batch_triage"
    );
    assert_eq!(schema_json["schema"]["mcp_tool"], "batch_triage");

    // 2. Local SQLite CLI `nogml mail batch-triage` dry-run and apply
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("cli_batch.db");
    let store = SqliteStore::open(&db_path, "cli@example.com").expect("open sqlite");

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let store_arc: Arc<dyn MailStore> = Arc::new(store);
        seed_message(
            &store_arc,
            "m_cli_1",
            "t_cli_1",
            "News <news@example.com>",
            "CLI Newsletter",
            "Newsletter via CLI",
            vec![LABEL_INBOX, LABEL_UNREAD],
        )
        .await;
    });

    let dry_out = Command::new(bin)
        .args([
            "--db-path",
            db_path.to_str().unwrap(),
            "--user-email",
            "cli@example.com",
            "mail",
            "--json",
            "batch-triage",
            "--query",
            "newsletter",
            "--archive",
            "true",
            "--mark-read",
            "true",
            "--dry-run",
        ])
        .output()
        .expect("run batch-triage dry-run");
    assert!(
        dry_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&dry_out.stderr)
    );
    let dry_json: Value = serde_json::from_slice(&dry_out.stdout).expect("valid dry_run json");
    assert_eq!(dry_json["dry_run"], true);
    assert_eq!(dry_json["total_threads"], 1);
    assert_eq!(dry_json["would_change_count"], 1);

    let apply_out = Command::new(bin)
        .args([
            "--db-path",
            db_path.to_str().unwrap(),
            "--user-email",
            "cli@example.com",
            "mail",
            "--json",
            "batch-triage",
            "--query",
            "newsletter",
            "--archive",
            "true",
            "--mark-read",
            "true",
        ])
        .output()
        .expect("run batch-triage apply");
    assert!(
        apply_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&apply_out.stderr)
    );
    let apply_json: Value = serde_json::from_slice(&apply_out.stdout).expect("valid apply json");
    assert_eq!(apply_json["dry_run"], false);
    assert_eq!(apply_json["applied_count"], 1);
}
