//! End-to-end tests for Issue #35: single-call reply context.
//! - REST `GET /v1/threads/{id}/reply-context`
//! - MCP `get_reply_context`
//! - Quote stripping, truncation, `_meta` guard, annotations, contact profiles, sent style
//!   samples (excluding the current thread), related threads via `SearchIndex`
//! - Scope enforcement, `404`, and multi-mailbox isolation

use std::sync::Arc;

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
    config::Config,
    models::{LABEL_INBOX, LABEL_SENT, LABEL_UNREAD},
    resend::HttpResendClient,
    storage::{MailStore, MemoryStore, NewMessageInput, SqliteStore},
};

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
const TOK_ALICE: &str = "tok_alice";
const TOK_ALICE_RO: &str = "tok_alice_ro";
const TOK_BOB: &str = "tok_bob";
const DANA: &str = "dana@acme.test";

fn scoped(token: &str, mailbox: &str, scopes: Vec<AuthScope>) -> ScopedTokenConfig {
    ScopedTokenConfig {
        token: token.to_string(),
        mailbox_id: Some(mailbox.to_string()),
        shared_mailboxes: Vec::new(),
        scopes,
        draft_only: None,
        allowed_recipients: None,
        max_send_recipients: None,
    }
}

fn build_app(sqlite: bool) -> (AppState, Router) {
    let mut cfg = Config::for_test();
    cfg.user_email = ALICE.to_string();
    cfg.mailboxes = vec![BOB.to_string()];
    cfg.untrusted_content_guard = true;
    cfg.auth_tokens = Vec::new();
    cfg.scoped_tokens = vec![
        scoped(
            TOK_ALICE,
            ALICE,
            vec![AuthScope::Read, AuthScope::Write, AuthScope::Send],
        ),
        scoped(TOK_ALICE_RO, ALICE, vec![AuthScope::Read]),
        scoped(
            TOK_BOB,
            BOB,
            vec![AuthScope::Read, AuthScope::Write, AuthScope::Send],
        ),
    ];
    let store: Arc<dyn MailStore> = if sqlite {
        Arc::new(SqliteStore::open_in_memory(&cfg.user_email).unwrap())
    } else {
        Arc::new(MemoryStore::new(&cfg.user_email))
    };
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store, resend);
    let app = build_router(state.clone());
    (state, app)
}

#[allow(clippy::too_many_arguments)]
async fn seed(
    state: &AppState,
    mailbox: &str,
    id: &str,
    thread_id: &str,
    sent: bool,
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
    ts_ms: i64,
) {
    let st = state.for_mailbox(mailbox);
    let labels = if sent {
        vec![LABEL_SENT.to_string()]
    } else {
        vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()]
    };
    let raw = format!(
        "From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nMessage-ID: <{id}@example.test>\r\n\r\n{body}"
    );
    let msg = st
        .store
        .insert_message(NewMessageInput {
            id: Some(id.to_string()),
            thread_id: Some(thread_id.to_string()),
            label_ids: labels,
            raw_rfc2822: raw.into_bytes(),
            snippet: body.chars().take(80).collect(),
            internal_date_ms: ts_ms,
            subject: subject.to_string(),
            from_addr: from.to_string(),
            to_addrs: vec![to.to_string()],
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
    st.post_store_message(&msg).await.unwrap();
}

async fn http(
    app: &Router,
    method: &str,
    uri: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    let req = match body {
        Some(v) => {
            builder = builder.header("content-type", "application/json");
            builder.body(Body::from(v.to_string())).unwrap()
        }
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn mcp_reply_context(app: &Router, token: &str, args: Value) -> Value {
    let (status, resp) = http(
        app,
        "POST",
        "/mcp",
        token,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "get_reply_context", "arguments": args }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    resp["result"].clone()
}

fn thread_ids(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].as_str().unwrap().to_string())
        .collect()
}

async fn seed_alice(state: &AppState, app: &Router) {
    let quoted = "Can we move the budget review to Friday afternoon?\n\nOn Mon, Jan 1, 2024 at 9:00 AM Alice <alice@example.com> wrote:\n> QUOTED_HISTORY_MARKER earlier text";
    seed(
        state,
        ALICE,
        "m_cur_in",
        "thr_current",
        false,
        "Dana Lee <dana@acme.test>",
        ALICE,
        "Re: Budget review",
        quoted,
        1_700_000_100_000,
    )
    .await;
    seed(
        state,
        ALICE,
        "m_cur_sent",
        "thr_current",
        true,
        ALICE,
        DANA,
        "Re: Budget review",
        "Sent inside current thread, must not be a style sample.",
        1_700_000_050_000,
    )
    .await;
    for (i, ts) in [
        1_699_000_001_000i64,
        1_699_000_002_000,
        1_699_000_003_000,
        1_699_000_004_000,
    ]
    .iter()
    .enumerate()
    {
        seed(
            state,
            ALICE,
            &format!("m_sent_{i}"),
            &format!("thr_sent_{i}"),
            true,
            ALICE,
            DANA,
            &format!("Lunch plan {i}"),
            &format!("Hi Dana,\nSTYLE_SAMPLE_{i} sounds good.\nCheers,\nAlice"),
            *ts,
        )
        .await;
    }
    seed(
        state,
        ALICE,
        "m_sent_other",
        "thr_sent_other",
        true,
        ALICE,
        "erin@other.test",
        "Other recipient",
        "STYLE_OTHER_RECIPIENT should never appear.",
        1_699_000_005_000,
    )
    .await;
    seed(
        state,
        ALICE,
        "m_rel_subject",
        "thr_rel_subject",
        false,
        "Erin <erin@other.test>",
        ALICE,
        "Budget review kickoff notes",
        "Kickoff notes for the budget review.",
        1_698_000_001_000,
    )
    .await;
    seed(
        state,
        ALICE,
        "m_rel_person",
        "thr_rel_person",
        false,
        "Dana Lee <dana@acme.test>",
        ALICE,
        "Team offsite venue",
        "Venue options attached.",
        1_698_000_002_000,
    )
    .await;

    let (status, _) = http(
        app,
        "PUT",
        "/v1/threads/thr_current/annotations",
        TOK_ALICE,
        Some(json!({ "summary": "Dana wants Friday", "needs_reply": true, "waiting_on": "me" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = http(
        app,
        "PATCH",
        "/v1/contacts/dana%40acme.test",
        TOK_ALICE,
        Some(json!({ "is_vip": true, "notes": "Finance lead" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

fn assert_reply_context(ctx: &Value) {
    // Thread: quote-stripped, guarded.
    assert_eq!(ctx["_meta"]["untrusted_external_content"], true);
    assert_eq!(ctx["thread"]["id"], "thr_current");
    assert_eq!(ctx["thread"]["_meta"]["untrusted_external_content"], true);
    let messages = ctx["thread"]["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2);
    let inbound = messages.iter().find(|m| m["id"] == "m_cur_in").unwrap();
    let text = inbound["text"].as_str().unwrap();
    assert!(text.contains("budget review to Friday"));
    assert!(!text.contains("QUOTED_HISTORY_MARKER"));
    assert!(!text.contains("wrote:"));

    // Annotation.
    assert_eq!(ctx["annotation"]["summary"], "Dana wants Friday");
    assert_eq!(ctx["annotation"]["needs_reply"], true);

    // Participants: contact profile for Dana (VIP, reply stats), self excluded.
    assert_eq!(ctx["primary_recipient"], DANA);
    let participants = ctx["participants"].as_array().unwrap();
    assert!(participants.iter().all(|p| p["email"] != ALICE));
    let dana = participants.iter().find(|p| p["email"] == DANA).unwrap();
    assert_eq!(dana["is_vip"], true);
    assert_eq!(dana["notes"], "Finance lead");
    assert_eq!(dana["received_count"], 2);
    assert!(dana["sent_count"].as_u64().unwrap() >= 5);

    // Style samples: latest first, only SENT to Dana, never the current thread.
    let samples = ctx["style_samples"].as_array().unwrap();
    assert_eq!(samples.len(), 3);
    let sample_ids: Vec<&str> = samples.iter().map(|s| s["id"].as_str().unwrap()).collect();
    assert_eq!(sample_ids, vec!["m_sent_3", "m_sent_2", "m_sent_1"]);
    for s in samples {
        assert_ne!(s["thread_id"], "thr_current");
        assert!(
            !s["text"]
                .as_str()
                .unwrap()
                .contains("STYLE_OTHER_RECIPIENT")
        );
        assert_eq!(s["_meta"]["untrusted_external_content"], true);
    }

    // Related threads: found by subject and by participant, never the current thread.
    let related = thread_ids(&ctx["related_threads"]);
    assert!(related.contains(&"thr_rel_subject".to_string()));
    assert!(related.contains(&"thr_rel_person".to_string()));
    assert!(!related.contains(&"thr_current".to_string()));
    let mut dedup = related.clone();
    dedup.sort();
    dedup.dedup();
    assert_eq!(dedup.len(), related.len());
}

async fn run_suite(sqlite: bool) {
    let (state, app) = build_app(sqlite);
    seed_alice(&state, &app).await;

    // REST with a read-only token.
    let (status, ctx) = http(
        &app,
        "GET",
        "/v1/threads/thr_current/reply-context?max_related_threads=20",
        TOK_ALICE_RO,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{ctx}");
    assert_reply_context(&ctx);

    // MCP returns the same payload shape.
    let result = mcp_reply_context(
        &app,
        TOK_ALICE_RO,
        json!({ "thread_id": "thr_current", "max_related_threads": 20 }),
    )
    .await;
    assert_eq!(result["isError"], false, "{result}");
    assert_reply_context(&result["structuredContent"]);

    // Limits: truncation, style sample cap, related cap.
    let (status, small) = http(
        &app,
        "GET",
        "/v1/threads/thr_current/reply-context?max_body_chars=12&max_style_samples=1&max_related_threads=1",
        TOK_ALICE,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let inbound = small["thread"]["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == "m_cur_in")
        .unwrap()
        .clone();
    assert_eq!(inbound["text"].as_str().unwrap().chars().count(), 12);
    assert_eq!(inbound["text_truncated"], true);
    assert_eq!(small["style_samples"].as_array().unwrap().len(), 1);
    assert_eq!(small["style_samples"][0]["id"], "m_sent_3");
    assert!(
        small["style_samples"][0]["text"]
            .as_str()
            .unwrap()
            .chars()
            .count()
            <= 12
    );
    assert_eq!(small["related_threads"].as_array().unwrap().len(), 1);

    let (status, zero) = http(
        &app,
        "GET",
        "/v1/threads/thr_current/reply-context?max_style_samples=0&max_related_threads=0",
        TOK_ALICE,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(zero["style_samples"].as_array().unwrap().is_empty());
    assert!(zero["related_threads"].as_array().unwrap().is_empty());

    // Field projection.
    let (status, projected) = http(
        &app,
        "GET",
        "/v1/threads/thr_current/reply-context?fields=primary_recipient,annotation",
        TOK_ALICE,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(projected["primary_recipient"], DANA);
    assert!(projected.get("style_samples").is_none());

    // 404 for unknown threads on REST and MCP.
    let (status, _) = http(
        &app,
        "GET",
        "/v1/threads/thr_missing/reply-context",
        TOK_ALICE,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let missing = mcp_reply_context(&app, TOK_ALICE, json!({ "thread_id": "thr_missing" })).await;
    assert_eq!(missing["isError"], true);

    // Audit log records the read.
    let (status, audit) = http(&app, "GET", "/v1/audit?action=read", TOK_ALICE, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        audit["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["detail"] == "reply_context")
    );
}

#[tokio::test]
async fn reply_context_rest_and_mcp_memory() {
    run_suite(false).await;
}

#[tokio::test]
async fn reply_context_rest_and_mcp_sqlite() {
    run_suite(true).await;
}

#[tokio::test]
async fn reply_context_respects_multi_mailbox_isolation() {
    let (state, app) = build_app(false);
    seed_alice(&state, &app).await;

    // Bob has his own thread, sent mail to Dana, and a related subject.
    seed(
        &state,
        BOB,
        "b_in",
        "thr_bob",
        false,
        "Dana Lee <dana@acme.test>",
        BOB,
        "Budget review for Bob",
        "Bob thread body.",
        1_700_000_200_000,
    )
    .await;
    seed(
        &state,
        BOB,
        "b_sent",
        "thr_bob_sent",
        true,
        BOB,
        DANA,
        "Bob private note",
        "BOB_STYLE_SECRET sample.",
        1_699_500_000_000,
    )
    .await;

    // Alice cannot fetch Bob's thread, and Bob cannot fetch Alice's.
    let (status, _) = http(
        &app,
        "GET",
        "/v1/threads/thr_bob/reply-context",
        TOK_ALICE,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = http(
        &app,
        "GET",
        "/v1/threads/thr_current/reply-context",
        TOK_BOB,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let denied = mcp_reply_context(&app, TOK_ALICE, json!({ "thread_id": "thr_bob" })).await;
    assert_eq!(denied["isError"], true);

    // Alice's context contains none of Bob's samples or related threads.
    let (status, alice) = http(
        &app,
        "GET",
        "/v1/threads/thr_current/reply-context?max_related_threads=20&max_style_samples=10",
        TOK_ALICE,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let alice_text = alice.to_string();
    assert!(!alice_text.contains("BOB_STYLE_SECRET"));
    assert!(!alice_text.contains("thr_bob"));
    assert!(!alice_text.contains("Bob thread body"));

    // Bob's context only contains his own mail, even for the same recipient and subject terms.
    let (status, bob) = http(
        &app,
        "GET",
        "/v1/threads/thr_bob/reply-context?max_related_threads=20&max_style_samples=10",
        TOK_BOB,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let samples = bob["style_samples"].as_array().unwrap();
    assert_eq!(samples.len(), 1);
    assert_eq!(samples[0]["id"], "b_sent");
    let bob_text = bob.to_string();
    assert!(!bob_text.contains("STYLE_SAMPLE_"));
    assert!(!bob_text.contains("thr_rel_subject"));
    assert!(!bob_text.contains("thr_current"));
    let participants = bob["participants"].as_array().unwrap();
    let dana = participants.iter().find(|p| p["email"] == DANA).unwrap();
    assert_eq!(dana["is_vip"], false);
    assert!(dana.get("notes").is_none() || dana["notes"].is_null());
}
