//! End-to-end tests for the daily briefing and follow-up detector (`Issue #36`):
//! - `GET /v1/briefing`
//! - MCP tool `get_briefing` and resource `nogml://briefing`
//! - `nogml mail briefing` (local store and `--url` remote)
//! - Compact output (no raw bodies) and strict multi-mailbox isolation

use std::{process::Command, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

use nogml::{
    AppState,
    auth::{AuthScope, ScopedTokenConfig},
    build_router,
    config::Config,
    models::{LABEL_INBOX, LABEL_SENT, LABEL_TRASH, LABEL_UNREAD, ThreadAnnotation, WaitingOn},
    resend::HttpResendClient,
    storage::{ContactPatch, MailStore, NewMessageInput, NewPendingApprovalInput, SqliteStore},
    transport::OutboundMessage,
};

const OWNER: &str = "owner@example.com";
const RAW_MARKER: &str = "RAW_BODY_MARKER_DO_NOT_LEAK";
const DAY_MS: i64 = 86_400_000;

#[allow(clippy::too_many_arguments)]
async fn put_msg(
    store: &Arc<dyn MailStore>,
    id: &str,
    thread: &str,
    labels: &[&str],
    from: &str,
    to: &str,
    subject: &str,
    snippet: &str,
    ts_ms: i64,
) {
    store
        .insert_message(NewMessageInput {
            id: Some(id.to_string()),
            thread_id: Some(thread.to_string()),
            label_ids: labels.iter().map(|l| l.to_string()).collect(),
            raw_rfc2822: format!(
                "From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nMessage-ID: <{id}@example.com>\r\n\r\n{RAW_MARKER} {id}"
            )
            .into_bytes(),
            snippet: snippet.to_string(),
            internal_date_ms: ts_ms,
            subject: subject.to_string(),
            from_addr: from.to_string(),
            to_addrs: vec![to.to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: format!("{RAW_MARKER} {id}"),
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
}

fn annotation(
    thread: &str,
    needs_reply: Option<bool>,
    waiting_on: Option<WaitingOn>,
) -> ThreadAnnotation {
    ThreadAnnotation {
        thread_id: thread.to_string(),
        summary: None,
        needs_reply,
        waiting_on,
        priority: None,
        due_at: None,
        extracted: json!({}),
        updated_by: Some("test".to_string()),
        updated_at: Utc::now(),
    }
}

async fn make_vip(store: &Arc<dyn MailStore>, email: &str) {
    store
        .patch_contact(
            email,
            &ContactPatch {
                is_vip: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

/// Seed one mailbox with every briefing scenario.
async fn seed_owner(store: &Arc<dyn MailStore>) {
    let now = Utc::now().timestamp_millis();
    let vip = "Vera Vip <vip@acme.com>";
    make_vip(store, "vip@acme.com").await;

    // VIP unread (recent), VIP unread (old), VIP already read, and a non-VIP unread.
    put_msg(
        store,
        "m_vip_new",
        "t_vip_new",
        &[LABEL_INBOX, LABEL_UNREAD],
        vip,
        OWNER,
        "Board deck",
        "Please review the deck",
        now - 2 * 3_600_000,
    )
    .await;
    put_msg(
        store,
        "m_vip_old",
        "t_vip_old",
        &[LABEL_INBOX, LABEL_UNREAD],
        vip,
        OWNER,
        "Old VIP note",
        "Older VIP note",
        now - 10 * DAY_MS,
    )
    .await;
    put_msg(
        store,
        "m_vip_read",
        "t_vip_read",
        &[LABEL_INBOX],
        vip,
        OWNER,
        "Already read",
        "Read already",
        now - 3_600_000,
    )
    .await;
    put_msg(
        store,
        "m_cold",
        "t_cold",
        &[LABEL_INBOX, LABEL_UNREAD],
        "Cold <cold@spam.io>",
        OWNER,
        "Buy now",
        "Limited offer",
        now - 3_600_000,
    )
    .await;

    // needs_reply and waiting_on=me threads, plus a decoy annotated needs_reply=false.
    put_msg(
        store,
        "m_nr",
        "t_needs_reply",
        &[LABEL_INBOX],
        "Bob <bob@acme.com>",
        OWNER,
        "Contract question",
        "Can you confirm?",
        now - 5 * 3_600_000,
    )
    .await;
    put_msg(
        store,
        "m_wm",
        "t_waiting_me",
        &[LABEL_INBOX],
        "Dana <dana@acme.com>",
        OWNER,
        "Waiting on you",
        "Need your sign off",
        now - 6 * 3_600_000,
    )
    .await;
    put_msg(
        store,
        "m_nr_false",
        "t_no_reply",
        &[LABEL_INBOX],
        "Eve <eve@acme.com>",
        OWNER,
        "FYI",
        "Just FYI",
        now - 7 * 3_600_000,
    )
    .await;
    store
        .upsert_thread_annotation(
            "t_needs_reply",
            &annotation("t_needs_reply", Some(true), None),
        )
        .await
        .unwrap();
    store
        .upsert_thread_annotation(
            "t_waiting_me",
            &annotation("t_waiting_me", None, Some(WaitingOn::Me)),
        )
        .await
        .unwrap();
    store
        .upsert_thread_annotation(
            "t_no_reply",
            &annotation("t_no_reply", Some(false), Some(WaitingOn::Them)),
        )
        .await
        .unwrap();

    // Follow-ups: unanswered 5 days ago (included), answered later (excluded),
    // sent 1 day ago (excluded), waiting_on=none (excluded), trashed (excluded).
    put_msg(
        store,
        "m_f1",
        "t_f1",
        &[LABEL_SENT],
        OWNER,
        "carol@example.org",
        "Proposal",
        "Sent the proposal",
        now - 5 * DAY_MS,
    )
    .await;
    put_msg(
        store,
        "m_f2_sent",
        "t_f2",
        &[LABEL_SENT],
        OWNER,
        "dave@example.org",
        "Pricing",
        "Pricing attached",
        now - 6 * DAY_MS,
    )
    .await;
    put_msg(
        store,
        "m_f2_reply",
        "t_f2",
        &[LABEL_INBOX],
        "Dave <dave@example.org>",
        OWNER,
        "Re: Pricing",
        "Thanks!",
        now - 4 * DAY_MS,
    )
    .await;
    put_msg(
        store,
        "m_f3",
        "t_f3",
        &[LABEL_SENT],
        OWNER,
        "erin@example.org",
        "Fresh",
        "Sent yesterday",
        now - DAY_MS,
    )
    .await;
    put_msg(
        store,
        "m_f4",
        "t_f4",
        &[LABEL_SENT],
        OWNER,
        "frank@example.org",
        "Closed",
        "No answer needed",
        now - 6 * DAY_MS,
    )
    .await;
    store
        .upsert_thread_annotation("t_f4", &annotation("t_f4", None, Some(WaitingOn::None)))
        .await
        .unwrap();
    put_msg(
        store,
        "m_f5",
        "t_f5",
        &[LABEL_SENT, LABEL_TRASH],
        OWNER,
        "gina@example.org",
        "Trashed",
        "Trashed thread",
        now - 7 * DAY_MS,
    )
    .await;

    // Pending approval and snoozes (past due, due soon, far future).
    store
        .create_pending_approval(NewPendingApprovalInput {
            id: Some("apr_1".to_string()),
            reason: "first contact".to_string(),
            requester: None,
            outbound_message: OutboundMessage {
                from: OWNER.to_string(),
                to: vec!["newperson@example.net".to_string()],
                subject: "Hello there".to_string(),
                text: Some(format!("{RAW_MARKER} approval body")),
                ..Default::default()
            },
            reply_to_message_id: None,
            thread_id: None,
            draft_id: None,
            created_at_ms: now,
            expires_at_ms: now + DAY_MS,
        })
        .await
        .unwrap();
    store
        .snooze_thread("t_cold", now - 3_600_000)
        .await
        .unwrap();
    store
        .snooze_thread("t_vip_read", now + 2 * 3_600_000)
        .await
        .unwrap();
    store
        .snooze_thread("t_no_reply", now + 3 * DAY_MS)
        .await
        .unwrap();
}

fn ids(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|t| {
            t.get("id")
                .or_else(|| t.get("thread_id"))
                .and_then(Value::as_str)
                .unwrap()
                .to_string()
        })
        .collect();
    out.sort();
    out
}

fn assert_full_briefing(b: &Value) {
    // Counts
    let c = &b["counts"];
    assert_eq!(c["vip_unread_count"], 2, "{c}");
    assert_eq!(c["followup_due_count"], 1, "{c}");
    assert_eq!(c["pending_approvals_count"], 1, "{c}");
    assert_eq!(c["snoozed_count"], 3, "{c}");
    assert_eq!(c["unread_total"], 3, "{c}");
    assert!(c["inbox_total"].as_u64().unwrap() >= 6, "{c}");
    assert!(b["generated_at"].as_str().is_some());

    assert_eq!(
        ids(&b["vip_unread_threads"]),
        vec!["t_vip_new", "t_vip_old"]
    );
    assert_eq!(
        ids(&b["needs_reply_threads"]),
        vec!["t_needs_reply", "t_waiting_me"]
    );

    let follow = b["follow_up_due"].as_array().unwrap();
    assert_eq!(follow.len(), 1, "{follow:?}");
    assert_eq!(follow[0]["thread_id"], "t_f1");
    assert_eq!(follow[0]["subject"], "Proposal");
    assert_eq!(follow[0]["to"], json!(["carol@example.org"]));
    assert_eq!(follow[0]["days_since_sent"], 5);
    assert_eq!(follow[0]["snippet"], "Sent the proposal");
    assert!(follow[0]["last_sent_at"].as_str().is_some());

    let approvals = b["pending_approvals"].as_array().unwrap();
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0]["id"], "apr_1");
    assert_eq!(approvals[0]["reason"], "first contact");
    assert_eq!(approvals[0]["to"], json!(["newperson@example.net"]));
    assert_eq!(approvals[0]["subject"], "Hello there");
    assert!(approvals[0]["created_at"].as_str().is_some());
    assert!(approvals[0]["expires_at"].as_str().is_some());
    assert!(approvals[0].get("outbound_message").is_none());

    // Past-due and due-within-24h snoozes are included; the 3-day snooze is not.
    assert_eq!(ids(&b["due_snoozes"]), vec!["t_cold", "t_vip_read"]);

    // Compact: no raw MIME bodies anywhere.
    let serialized = b.to_string();
    assert!(
        !serialized.contains(RAW_MARKER),
        "briefing leaked a raw body"
    );
    assert!(!serialized.contains("raw_rfc2822"));
    assert!(!serialized.contains("text_body"));
}

async fn http_json(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let req_body = match body {
        Some(v) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let resp = app
        .clone()
        .oneshot(builder.body(req_body).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn mcp(app: &Router, token: Option<&str>, method: &str, params: Value) -> Value {
    let (status, v) = http_json(
        app,
        "POST",
        "/mcp",
        token,
        Some(json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    v
}

fn local_state(tmp: &TempDir) -> (AppState, Arc<dyn MailStore>, std::path::PathBuf) {
    let db_path = tmp.path().join("briefing.db");
    let mut cfg = Config::for_test();
    cfg.user_email = OWNER.to_string();
    cfg.db_path = db_path.clone();
    let store: Arc<dyn MailStore> = Arc::new(SqliteStore::open(&db_path, OWNER).unwrap());
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store.clone(), resend);
    (state, store, db_path)
}

#[tokio::test]
async fn rest_mcp_tool_and_resource_return_briefing() {
    let tmp = TempDir::new().unwrap();
    let (state, store, _) = local_state(&tmp);
    seed_owner(&store).await;
    let app = build_router(state);

    // Capabilities
    let (status, caps) = http_json(&app, "GET", "/v1/capabilities", None, None).await;
    assert_eq!(status, StatusCode::OK, "{caps}");
    assert!(
        caps["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e == "GET /v1/briefing")
    );

    // REST
    let (status, rest) = http_json(&app, "GET", "/v1/briefing", None, None).await;
    assert_eq!(status, StatusCode::OK, "{rest}");
    assert_full_briefing(&rest);

    // Field projection
    let (status, projected) =
        http_json(&app, "GET", "/v1/briefing?fields=counts", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(projected.get("counts").is_some());
    assert!(projected.get("vip_unread_threads").is_none());

    // since filters unread VIP threads only
    let since = (Utc::now() - Duration::days(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let (status, recent) = http_json(
        &app,
        "GET",
        &format!("/v1/briefing?since={since}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{recent}");
    assert_eq!(ids(&recent["vip_unread_threads"]), vec!["t_vip_new"]);
    assert_eq!(recent["counts"]["vip_unread_count"], 1);
    assert_eq!(recent["counts"]["followup_due_count"], 1);

    // followup_days widens or narrows the follow-up window; limit bounds sections.
    let (_, narrow) = http_json(
        &app,
        "GET",
        "/v1/briefing?followup_days=0&limit=1",
        None,
        None,
    )
    .await;
    assert_eq!(narrow["counts"]["followup_due_count"], 2, "{narrow}");
    assert_eq!(narrow["follow_up_due"].as_array().unwrap().len(), 1);
    assert_eq!(narrow["vip_unread_threads"].as_array().unwrap().len(), 1);
    assert_eq!(narrow["counts"]["vip_unread_count"], 2);
    let (_, wide) = http_json(&app, "GET", "/v1/briefing?followup_days=30", None, None).await;
    assert_eq!(wide["counts"]["followup_due_count"], 0);

    // Invalid since is a validation error.
    let (status, _) = http_json(&app, "GET", "/v1/briefing?since=yesterday", None, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // MCP tools/list advertises get_briefing; resources/list advertises nogml://briefing.
    let tools = mcp(&app, None, "tools/list", json!({})).await;
    assert!(
        tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "get_briefing")
    );
    let resources = mcp(&app, None, "resources/list", json!({})).await;
    assert!(
        resources["result"]["resources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["uri"] == "nogml://briefing")
    );

    // MCP tools/call
    let call = mcp(
        &app,
        None,
        "tools/call",
        json!({"name": "get_briefing", "arguments": {}}),
    )
    .await;
    assert_ne!(call["result"]["isError"], json!(true), "{call}");
    assert_full_briefing(&call["result"]["structuredContent"]);

    let call_args = mcp(
        &app,
        None,
        "tools/call",
        json!({"name": "get_briefing", "arguments": {"since": since, "followup_days": 30, "limit": 5}}),
    )
    .await;
    let structured = &call_args["result"]["structuredContent"];
    assert_eq!(ids(&structured["vip_unread_threads"]), vec!["t_vip_new"]);
    assert_eq!(structured["counts"]["followup_due_count"], 0);

    // MCP resources/read
    let read = mcp(
        &app,
        None,
        "resources/read",
        json!({"uri": "nogml://briefing"}),
    )
    .await;
    let text = read["result"]["contents"][0]["text"].as_str().unwrap();
    let resource: Value = serde_json::from_str(text).unwrap();
    assert_full_briefing(&resource);
}

#[tokio::test]
async fn cli_local_and_remote_briefing() {
    let bin = env!("CARGO_BIN_EXE_nogml");
    let tmp = TempDir::new().unwrap();
    let (state, store, db_path) = local_state(&tmp);
    seed_owner(&store).await;

    // Local store
    let db = db_path.to_str().unwrap().to_string();
    let out = tokio::task::spawn_blocking({
        let db = db.clone();
        move || {
            Command::new(bin)
                .args([
                    "--db-path",
                    &db,
                    "--user-email",
                    OWNER,
                    "mail",
                    "--json",
                    "briefing",
                ])
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let local: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_full_briefing(&local);

    let out = tokio::task::spawn_blocking({
        let db = db.clone();
        move || {
            Command::new(bin)
                .args([
                    "--db-path",
                    &db,
                    "--user-email",
                    OWNER,
                    "mail",
                    "--json",
                    "briefing",
                    "--followup-days",
                    "30",
                    "--limit",
                    "1",
                ])
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();
    assert!(out.status.success());
    let narrowed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(narrowed["counts"]["followup_due_count"], 0);
    assert_eq!(narrowed["vip_unread_threads"].as_array().unwrap().len(), 1);

    let out = tokio::task::spawn_blocking({
        let db = db.clone();
        move || {
            Command::new(bin)
                .args([
                    "--db-path",
                    &db,
                    "--user-email",
                    OWNER,
                    "mail",
                    "--json",
                    "briefing",
                    "--since",
                    "not-a-date",
                ])
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();
    assert!(!out.status.success());

    // Remote --url
    let router = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    let url = format!("http://{addr}");
    let out = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .args(["mail", "--url", &url, "--json", "briefing"])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let remote: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_full_briefing(&remote);
    server.abort();
}

#[tokio::test]
async fn briefing_is_isolated_per_mailbox_and_requires_read_scope() {
    const ALICE: &str = "alice@example.com";
    const BOB: &str = "bob@example.com";
    let mut cfg = Config::for_test();
    cfg.user_email = ALICE.to_string();
    cfg.mailboxes = vec![BOB.to_string()];
    cfg.scoped_tokens = vec![
        ScopedTokenConfig {
            token: "tok_alice".to_string(),
            mailbox_id: Some(ALICE.to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_bob".to_string(),
            mailbox_id: Some(BOB.to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_nowrite".to_string(),
            mailbox_id: Some(ALICE.to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Write],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
    ];
    let store: Arc<dyn MailStore> = Arc::new(SqliteStore::open_in_memory(ALICE).unwrap());
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store, resend);
    let alice = state.for_mailbox(ALICE).store.clone();
    let bob = state.for_mailbox(BOB).store.clone();
    let now = Utc::now().timestamp_millis();

    make_vip(&alice, "vip@acme.com").await;
    put_msg(
        &alice,
        "a1",
        "t_alice_vip",
        &[LABEL_INBOX, LABEL_UNREAD],
        "Vip <vip@acme.com>",
        ALICE,
        "Alice VIP",
        "alice only",
        now - 1000,
    )
    .await;
    put_msg(
        &alice,
        "a2",
        "t_alice_sent",
        &[LABEL_SENT],
        ALICE,
        "x@example.org",
        "Alice follow up",
        "alice sent",
        now - 5 * DAY_MS,
    )
    .await;

    make_vip(&bob, "boss@corp.com").await;
    put_msg(
        &bob,
        "b1",
        "t_bob_vip",
        &[LABEL_INBOX, LABEL_UNREAD],
        "Boss <boss@corp.com>",
        BOB,
        "Bob VIP",
        "bob only",
        now - 1000,
    )
    .await;
    put_msg(
        &bob,
        "b2",
        "t_bob_sent",
        &[LABEL_SENT],
        BOB,
        "y@example.org",
        "Bob follow up",
        "bob sent",
        now - 6 * DAY_MS,
    )
    .await;
    bob.snooze_thread("t_bob_vip", now - 1000).await.unwrap();

    let app = build_router(state);

    let (status, a) = http_json(&app, "GET", "/v1/briefing", Some("tok_alice"), None).await;
    assert_eq!(status, StatusCode::OK, "{a}");
    assert_eq!(ids(&a["vip_unread_threads"]), vec!["t_alice_vip"]);
    assert_eq!(ids(&a["follow_up_due"]), vec!["t_alice_sent"]);
    assert_eq!(a["counts"]["snoozed_count"], 0);
    assert!(!a.to_string().contains("bob"));

    let (status, b) = http_json(&app, "GET", "/v1/briefing", Some("tok_bob"), None).await;
    assert_eq!(status, StatusCode::OK, "{b}");
    assert_eq!(ids(&b["vip_unread_threads"]), vec!["t_bob_vip"]);
    assert_eq!(ids(&b["follow_up_due"]), vec!["t_bob_sent"]);
    assert_eq!(ids(&b["due_snoozes"]), vec!["t_bob_vip"]);
    assert!(!b.to_string().contains("alice"));

    // MCP is isolated the same way.
    let call = mcp(
        &app,
        Some("tok_bob"),
        "tools/call",
        json!({"name": "get_briefing", "arguments": {}}),
    )
    .await;
    assert_eq!(
        ids(&call["result"]["structuredContent"]["vip_unread_threads"]),
        vec!["t_bob_vip"]
    );

    // A write-only token cannot read the briefing.
    let (status, _) = http_json(&app, "GET", "/v1/briefing", Some("tok_nowrite"), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = http_json(&app, "GET", "/v1/briefing", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
