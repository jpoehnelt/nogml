//! End-to-end tests for thread snooze (`POST`/`DELETE /v1/threads/{id}/snooze`, MCP `snooze_thread`),
//! scheduled outbound sends (`send_at`, `GET /v1/scheduled`, `DELETE /v1/scheduled/{id}`,
//! MCP `list_scheduled_sends` & `cancel_scheduled_send`), and the background scheduler tick
//! (`process_due_scheduler_items`).

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use nogml::{
    AppState, ai, build_router,
    config::{Config, DraftOnlyAction},
    error::{AppError, AppResult},
    events::{EventSource, MailEvent},
    imap,
    mcp::McpServer,
    models::{
        LABEL_INBOX, LABEL_SENT, LABEL_SNOOZED, LABEL_UNREAD, ResendReceivedAttachment,
        ResendReceivedEmail, ResendSendEmailRequest, ResendSendEmailResponse,
    },
    resend::ResendClient,
    storage::{MailStore, NewMessageInput, SqliteStore},
    transport::{MailTransport, OutboundMessage, SendOutcome, TransportCapabilities},
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::watch,
};
use tower::ServiceExt;

struct DummyResend;

#[async_trait]
impl ResendClient for DummyResend {
    async fn send_email(
        &self,
        _req: &ResendSendEmailRequest,
        _idempotency_key: Option<&str>,
    ) -> AppResult<ResendSendEmailResponse> {
        Ok(ResendSendEmailResponse {
            id: "re_unused".to_string(),
        })
    }
    async fn get_received_email(&self, _id: &str) -> AppResult<ResendReceivedEmail> {
        Err(AppError::NotFound("not found".into()))
    }
    async fn list_received_attachments(
        &self,
        _id: &str,
    ) -> AppResult<Vec<ResendReceivedAttachment>> {
        Ok(Vec::new())
    }
    async fn download_bytes(&self, _url: &str) -> AppResult<Vec<u8>> {
        Ok(Vec::new())
    }
}

#[derive(Default)]
struct CountingTransport {
    calls: AtomicUsize,
    sent: Mutex<Vec<OutboundMessage>>,
}

impl CountingTransport {
    fn sent_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn sent_messages(&self) -> Vec<OutboundMessage> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait]
impl MailTransport for CountingTransport {
    fn name(&self) -> &'static str {
        "counting_test"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            provider: "counting_test".to_string(),
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
        let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        self.sent.lock().unwrap().push(msg.clone());
        Ok(SendOutcome {
            provider: "counting_test".to_string(),
            provider_message_id: format!("prov_sched_{n}"),
        })
    }
}

fn make_state(cfg: Config) -> (AppState, Arc<SqliteStore>, Arc<CountingTransport>) {
    let store = Arc::new(SqliteStore::open_in_memory(&cfg.user_email).unwrap());
    let transport = Arc::new(CountingTransport::default());
    let state = AppState::with_backends(cfg, store.clone(), Arc::new(DummyResend))
        .with_transport(transport.clone());
    (state, store, transport)
}

async fn seed_inbox_message(
    store: &dyn MailStore,
    id: &str,
    thread_id: &str,
    subject: &str,
    labels: Vec<&str>,
) {
    let raw = format!(
        "From: Alice <alice@example.com>\r\nTo: {}\r\nSubject: {subject}\r\nMessage-ID: <{id}@example.com>\r\n\r\nBody for {subject}",
        store.mailbox_id()
    );
    store
        .insert_message(NewMessageInput {
            id: Some(id.to_string()),
            thread_id: Some(thread_id.to_string()),
            label_ids: labels.into_iter().map(String::from).collect(),
            raw_rfc2822: raw.into_bytes(),
            snippet: format!("Body for {subject}"),
            internal_date_ms: Utc::now().timestamp_millis(),
            subject: subject.to_string(),
            from_addr: "Alice <alice@example.com>".to_string(),
            to_addrs: vec![store.mailbox_id().to_string()],
            cc_addrs: Vec::new(),
            bcc_addrs: Vec::new(),
            text_body: format!("Body for {subject}"),
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
        .unwrap();
}

async fn json_response(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({}));
    (status, body)
}

#[tokio::test]
async fn snooze_and_unsnooze_lifecycle_with_scheduler_sse_and_imap_idle() {
    let mut cfg = Config::for_test();
    cfg.imap_username = Some(cfg.user_email.clone());
    cfg.imap_password = Some("imap-secret".to_string());

    // Bind ephemeral port for embedded IMAP to verify IDLE wakeup event on snooze expiry.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let imap_addr = probe.local_addr().unwrap();
    drop(probe);
    cfg.imap_bind = Some(imap_addr);

    let (state, store, _transport) = make_state(cfg);
    seed_inbox_message(
        store.as_ref(),
        "m_snz_1",
        "t_snz_1",
        "Follow up next week",
        vec![LABEL_INBOX], // read message in INBOX (no UNREAD initially)
    )
    .await;
    seed_inbox_message(
        store.as_ref(),
        "m_snz_2",
        "t_snz_2",
        "Cancel snooze early",
        vec![LABEL_INBOX],
    )
    .await;

    let app = build_router(state.clone());
    let mut event_rx = state.events.subscribe();

    // 1. Validation: past `until` -> 400; unknown thread -> 404
    let past = (Utc::now() - Duration::minutes(5)).to_rfc3339();
    let (st_past, body_past) = json_response(
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/threads/t_snz_1/snooze")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({ "until": past }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st_past, StatusCode::BAD_REQUEST);
    assert_eq!(body_past["error"]["code"], "validation_error");

    let future_until = Utc::now() + Duration::hours(1);
    let future_until_ms = future_until.timestamp_millis();
    let (st_missing, _) = json_response(
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/threads/t_does_not_exist/snooze")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({ "until": future_until.to_rfc3339() }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st_missing, StatusCode::NOT_FOUND);

    // 2. Snooze t_snz_1 via POST /v1/threads/{id}/snooze
    let (st_snz, body_snz) = json_response(
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/threads/t_snz_1/snooze")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({ "until": future_until.to_rfc3339() }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st_snz, StatusCode::OK);
    assert_eq!(body_snz["status"], "snoozed");
    assert_eq!(body_snz["thread_id"], "t_snz_1");
    assert_eq!(body_snz["snooze_until_ms"], future_until_ms);

    let msg_after_snz = store.get_message("m_snz_1").await.unwrap().unwrap();
    assert!(!msg_after_snz.label_ids.contains(&LABEL_INBOX.to_string()));
    assert!(msg_after_snz.label_ids.contains(&LABEL_SNOOZED.to_string()));

    // Verify snooze emitted MessageUpdated event
    let snz_ev = event_rx.recv().await.unwrap();
    assert_eq!(snz_ev.source, EventSource::Api);
    match snz_ev.event {
        MailEvent::MessageUpdated {
            thread_id,
            added_labels,
            removed_labels,
            ..
        } => {
            assert_eq!(thread_id, "t_snz_1");
            assert_eq!(added_labels, vec![LABEL_SNOOZED.to_string()]);
            assert_eq!(removed_labels, vec![LABEL_INBOX.to_string()]);
        }
        other => panic!("expected MessageUpdated on snooze, got {other:?}"),
    }

    // 3. Verify GET /v1/threads?label=INBOX hides t_snz_1 while label=SNOOZED includes it
    let (_, inbox_threads) = json_response(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/threads?label=INBOX")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    let inbox_ids: Vec<&str> = inbox_threads["threads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].as_str().unwrap())
        .collect();
    assert!(!inbox_ids.contains(&"t_snz_1"));
    assert!(inbox_ids.contains(&"t_snz_2"));

    let (_, snoozed_threads) = json_response(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/threads?label=SNOOZED")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    let snoozed_ids: Vec<&str> = snoozed_threads["threads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].as_str().unwrap())
        .collect();
    assert_eq!(snoozed_ids, vec!["t_snz_1"]);

    // 4. Snooze and manually unsnooze t_snz_2 via DELETE /v1/threads/{id}/snooze
    let (st_snz2, _) = json_response(
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/threads/t_snz_2/snooze")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({ "until": future_until.to_rfc3339() }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st_snz2, StatusCode::OK);
    let _ = event_rx.recv().await.unwrap();

    let (st_unsnz2, body_unsnz2) = json_response(
        app.clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/threads/t_snz_2/snooze")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st_unsnz2, StatusCode::OK);
    assert_eq!(body_unsnz2["status"], "unsnoozed");
    assert_eq!(body_unsnz2["was_snoozed"], true);
    let msg2 = store.get_message("m_snz_2").await.unwrap().unwrap();
    assert!(msg2.label_ids.contains(&LABEL_INBOX.to_string()));
    assert!(!msg2.label_ids.contains(&LABEL_SNOOZED.to_string()));
    let _ = event_rx.recv().await.unwrap();

    // 5. Start embedded IMAP server and enter IDLE on INBOX to verify IMAP wakeup notification
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let imap_state = state.clone();
    let imap_handle = tokio::spawn(async move {
        let _ = imap::serve_imap(imap_state, shutdown_rx).await;
    });

    // Wait briefly for IMAP listener
    let stream = loop {
        match TcpStream::connect(imap_addr).await {
            Ok(s) => break s,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    };
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    // Greeting
    reader.read_line(&mut line).await.unwrap();
    assert!(line.contains("OK"));

    // LOGIN
    write_half
        .write_all(b"A01 LOGIN agent@example.com imap-secret\r\n")
        .await
        .unwrap();
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line.starts_with("A01 OK") {
            break;
        }
    }

    // SELECT INBOX (currently 1 message: m_snz_2)
    write_half.write_all(b"A02 SELECT INBOX\r\n").await.unwrap();
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line.starts_with("A02 OK") {
            break;
        }
    }

    // Enter IDLE
    write_half.write_all(b"A03 IDLE\r\n").await.unwrap();
    line.clear();
    reader.read_line(&mut line).await.unwrap();
    assert!(
        line.starts_with('+'),
        "expected IDLE continuation, got {line}"
    );

    // 6. Scheduler tick BEFORE `until` wakes 0 threads
    let before_report = ai::process_due_scheduler_items(&state, future_until_ms - 1_000)
        .await
        .unwrap();
    assert_eq!(before_report.snoozes_woken, 0);

    let last_event_id_before_wake = state.events.latest_id();

    // 7. Scheduler tick AT `until` wakes t_snz_1 -> restores INBOX + UNREAD, removes SNOOZED
    let wake_report = ai::process_due_scheduler_items(&state, future_until_ms)
        .await
        .unwrap();
    assert_eq!(wake_report.snoozes_woken, 1);

    let msg_woken = store.get_message("m_snz_1").await.unwrap().unwrap();
    assert!(msg_woken.label_ids.contains(&LABEL_INBOX.to_string()));
    assert!(msg_woken.label_ids.contains(&LABEL_UNREAD.to_string()));
    assert!(!msg_woken.label_ids.contains(&LABEL_SNOOZED.to_string()));

    // Verify EventBus event (backing SSE /v1/events)
    let wake_ev = event_rx.recv().await.unwrap();
    assert_eq!(wake_ev.source, EventSource::System);
    match wake_ev.event {
        MailEvent::MessageUpdated {
            message_id,
            thread_id,
            added_labels,
            removed_labels,
        } => {
            assert_eq!(message_id, "m_snz_1");
            assert_eq!(thread_id, "t_snz_1");
            assert!(added_labels.contains(&LABEL_INBOX.to_string()));
            assert!(added_labels.contains(&LABEL_UNREAD.to_string()));
            assert_eq!(removed_labels, vec![LABEL_SNOOZED.to_string()]);
        }
        other => panic!("expected MessageUpdated on wake, got {other:?}"),
    }

    // Verify SSE replay buffer recorded the wake event
    let replayed = state.events.events_since(last_event_id_before_wake, 10);
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed[0].event.event_type(), "message_updated");

    // Verify IMAP IDLE pushed an untagged EXISTS update when t_snz_1 returned to INBOX
    line.clear();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        reader.read_line(&mut line),
    )
    .await
    .expect("IMAP IDLE should notify on snooze wake")
    .unwrap();
    assert!(
        line.contains("EXISTS"),
        "expected untagged EXISTS on IMAP IDLE, got: {line}"
    );

    write_half.write_all(b"DONE\r\n").await.unwrap();
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), imap_handle).await;

    // 8. Re-running scheduler tick is idempotent (0 woken)
    let repeat_report = ai::process_due_scheduler_items(&state, future_until_ms + 60_000)
        .await
        .unwrap();
    assert_eq!(repeat_report.snoozes_woken, 0);
}

#[tokio::test]
async fn scheduled_send_policy_dispatch_once_and_cancel_conflicts() {
    // 1. OutboundPolicy (draft_only=block) MUST reject BEFORE scheduling anything
    let mut blocked_cfg = Config::for_test();
    blocked_cfg.draft_only = true;
    blocked_cfg.draft_only_action = DraftOnlyAction::Block;
    let (blocked_state, blocked_store, blocked_transport) = make_state(blocked_cfg);
    let blocked_app = build_router(blocked_state);

    let send_at = Utc::now() + Duration::hours(2);
    let (st_blocked, body_blocked) = json_response(
        blocked_app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages/send")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "to": ["bob@example.com"],
                            "subject": "Should be blocked",
                            "text": "Blocked by draft_only",
                            "send_at": send_at.to_rfc3339(),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st_blocked, StatusCode::FORBIDDEN);
    assert_eq!(body_blocked["error"]["code"], "draft_only_mode");
    assert_eq!(blocked_transport.sent_count(), 0);
    assert!(
        blocked_store
            .list_scheduled_sends(None, 20)
            .await
            .unwrap()
            .is_empty()
    );

    // 2. Allowed scheduled send returns 202 Accepted with 0 immediate transport calls
    let (state, store, transport) = make_state(Config::for_test());
    let app = build_router(state.clone());
    let mut event_rx = state.events.subscribe();

    let send_at_ms = send_at.timestamp_millis();
    let (st_sched, body_sched) = json_response(
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages/send")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "to": ["bob@example.com"],
                            "subject": "Scheduled Hello",
                            "text": "Deliver later",
                            "send_at": send_at.to_rfc3339(),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st_sched, StatusCode::ACCEPTED);
    assert_eq!(body_sched["status"], "scheduled");
    let scheduled_id = body_sched["scheduled_id"].as_str().unwrap().to_string();
    assert!(!scheduled_id.is_empty());
    assert_eq!(body_sched["send_at_ms"], send_at_ms);
    assert_eq!(body_sched["preview"]["subject"], "Scheduled Hello");
    assert_eq!(transport.sent_count(), 0);

    // GET /v1/scheduled?status=pending lists the pending item
    let (st_list, body_list) = json_response(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/scheduled?status=pending")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st_list, StatusCode::OK);
    assert_eq!(body_list["count"], 1);
    assert_eq!(body_list["scheduled_sends"][0]["id"], scheduled_id);

    // Tick BEFORE send_at -> 0 sends
    let r_before = ai::process_due_scheduler_items(&state, send_at_ms - 1)
        .await
        .unwrap();
    assert_eq!(r_before.scheduled_sent, 0);
    assert_eq!(transport.sent_count(), 0);

    // Tick AT send_at -> dispatches ONCE, persists SENT message, emits MessageSent
    let r_due = ai::process_due_scheduler_items(&state, send_at_ms)
        .await
        .unwrap();
    assert_eq!(r_due.scheduled_sent, 1);
    assert_eq!(r_due.scheduled_failed, 0);
    assert_eq!(transport.sent_count(), 1);
    assert_eq!(transport.sent_messages()[0].subject, "Scheduled Hello");

    let ev = event_rx.recv().await.unwrap();
    assert_eq!(ev.source, EventSource::System);
    let sent_msg_id = match ev.event {
        MailEvent::MessageSent {
            message_id,
            subject,
            labels,
            ..
        } => {
            assert_eq!(subject, "Scheduled Hello");
            assert!(labels.contains(&LABEL_SENT.to_string()));
            message_id
        }
        other => panic!("expected MessageSent, got {other:?}"),
    };
    let stored_sent = store.get_message(&sent_msg_id).await.unwrap().unwrap();
    assert!(stored_sent.label_ids.contains(&LABEL_SENT.to_string()));

    // Subsequent tick sends 0 times
    let r_after = ai::process_due_scheduler_items(&state, send_at_ms + 60_000)
        .await
        .unwrap();
    assert_eq!(r_after.scheduled_sent, 0);
    assert_eq!(transport.sent_count(), 1);

    // Canceling an already-sent item returns 409 Conflict
    let (st_conflict, body_conflict) = json_response(
        app.clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/scheduled/{scheduled_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st_conflict, StatusCode::CONFLICT);
    assert_eq!(body_conflict["error"]["code"], "conflict");

    // 3. Schedule a second email and cancel it before dispatch
    let send_at_2 = Utc::now() + Duration::hours(3);
    let send_at_2_ms = send_at_2.timestamp_millis();
    let (st_sched2, body_sched2) = json_response(
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages/send")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "to": ["carol@example.com"],
                            "subject": "Will be canceled",
                            "text": "Never send this",
                            "send_at": send_at_2.to_rfc3339(),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st_sched2, StatusCode::ACCEPTED);
    let cancel_id = body_sched2["scheduled_id"].as_str().unwrap().to_string();

    let (st_cancel, body_cancel) = json_response(
        app.clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/scheduled/{cancel_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st_cancel, StatusCode::OK);
    assert_eq!(body_cancel["status"], "canceled");
    assert_eq!(body_cancel["scheduled_id"], cancel_id);

    // Canceling a second time returns 409 Conflict
    let (st_cancel_dup, _) = json_response(
        app.clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/scheduled/{cancel_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(st_cancel_dup, StatusCode::CONFLICT);

    // Tick past send_at_2 dispatches 0 times
    let r_canceled = ai::process_due_scheduler_items(&state, send_at_2_ms + 5_000)
        .await
        .unwrap();
    assert_eq!(r_canceled.scheduled_sent, 0);
    assert_eq!(transport.sent_count(), 1);
}

#[tokio::test]
async fn mcp_snooze_and_scheduled_send_tools_work_end_to_end() {
    let (state, store, transport) = make_state(Config::for_test());
    seed_inbox_message(
        store.as_ref(),
        "m_mcp_snz",
        "t_mcp_snz",
        "MCP Snooze Target",
        vec![LABEL_INBOX],
    )
    .await;

    let server = McpServer::new(state.clone());

    // 1. MCP snooze_thread
    let until = Utc::now() + Duration::hours(1);
    let until_ms = until.timestamp_millis();
    let snz_resp = server
        .handle_request(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "snooze_thread",
                "arguments": {
                    "thread_id": "t_mcp_snz",
                    "until": until.to_rfc3339()
                }
            }
        }))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snz_resp["result"]["isError"], false);
    assert_eq!(snz_resp["result"]["structuredContent"]["status"], "snoozed");

    // Wake via scheduler tick
    let report = ai::process_due_scheduler_items(&state, until_ms)
        .await
        .unwrap();
    assert_eq!(report.snoozes_woken, 1);
    let woken = store.get_message("m_mcp_snz").await.unwrap().unwrap();
    assert!(woken.label_ids.contains(&LABEL_INBOX.to_string()));
    assert!(woken.label_ids.contains(&LABEL_UNREAD.to_string()));
    assert!(!woken.label_ids.contains(&LABEL_SNOOZED.to_string()));

    // 2. MCP send_email with send_at
    let send_at = Utc::now() + Duration::hours(2);
    let send_at_ms = send_at.timestamp_millis();
    let sched_resp = server
        .handle_request(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "send_email",
                "arguments": {
                    "to": ["dave@example.com"],
                    "subject": "MCP Scheduled",
                    "text": "Sent via MCP send_at",
                    "send_at": send_at.to_rfc3339()
                }
            }
        }))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sched_resp["result"]["isError"], false);
    assert_eq!(
        sched_resp["result"]["structuredContent"]["status"],
        "scheduled"
    );
    let scheduled_id = sched_resp["result"]["structuredContent"]["scheduled_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(transport.sent_count(), 0);

    // 3. MCP list_scheduled_sends
    let list_resp = server
        .handle_request(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "list_scheduled_sends",
                "arguments": { "status": "pending", "limit": 10 }
            }
        }))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(list_resp["result"]["isError"], false);
    assert_eq!(list_resp["result"]["structuredContent"]["count"], 1);
    assert_eq!(
        list_resp["result"]["structuredContent"]["scheduled_sends"][0]["id"],
        scheduled_id
    );

    // 4. MCP cancel_scheduled_send
    let cancel_resp = server
        .handle_request(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "cancel_scheduled_send",
                "arguments": { "scheduled_id": scheduled_id }
            }
        }))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cancel_resp["result"]["isError"], false);
    assert_eq!(
        cancel_resp["result"]["structuredContent"]["status"],
        "canceled"
    );

    // Double cancel returns isError=true with conflict code
    let cancel_again = server
        .handle_request(json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "cancel_scheduled_send",
                "arguments": { "scheduled_id": scheduled_id }
            }
        }))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cancel_again["result"]["isError"], true);
    assert_eq!(
        cancel_again["result"]["structuredContent"]["error"]["code"],
        "conflict"
    );

    // Tick past send_at -> 0 sends
    let report2 = ai::process_due_scheduler_items(&state, send_at_ms + 1_000)
        .await
        .unwrap();
    assert_eq!(report2.scheduled_sent, 0);
    assert_eq!(transport.sent_count(), 0);
}

#[tokio::test]
async fn scheduler_processes_snoozes_and_scheduled_sends_across_multiple_mailboxes() {
    let mut cfg = Config::for_test();
    cfg.user_email = "alice@example.com".to_string();
    cfg.mailboxes = vec!["bob@example.com".to_string()];
    let (root_state, _store, transport) = make_state(cfg);

    let alice_state = root_state.for_mailbox("alice@example.com");
    let bob_state = root_state.for_mailbox("bob@example.com");

    seed_inbox_message(
        alice_state.store.as_ref(),
        "m_alice",
        "t_alice",
        "Alice snooze",
        vec![LABEL_INBOX],
    )
    .await;

    let due_at = Utc::now() + Duration::hours(1);
    let due_ms = due_at.timestamp_millis();

    ai::execute_snooze_thread(
        &alice_state,
        "t_alice",
        nogml::models::SnoozeThreadRequest { until: due_at },
    )
    .await
    .unwrap();

    let bob_sched = ai::execute_send_email(
        &bob_state,
        nogml::models::AiSendEmailRequest {
            to: vec!["external@partner.test".to_string()],
            subject: Some("From Bob Later".to_string()),
            text: Some("Bob's scheduled note".to_string()),
            send_at: Some(due_at),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(bob_sched["status"], "scheduled");
    assert_eq!(transport.sent_count(), 0);

    let mut rx = root_state.events.subscribe();

    // Single tick on root_state processes both alice's snooze and bob's scheduled send
    let report = ai::process_due_scheduler_items(&root_state, due_ms)
        .await
        .unwrap();
    assert_eq!(report.snoozes_woken, 1);
    assert_eq!(report.scheduled_sent, 1);
    assert_eq!(transport.sent_count(), 1);
    assert_eq!(transport.sent_messages()[0].from, "bob@example.com");

    // Alice's thread woke in Alice's mailbox
    let alice_msg = alice_state
        .store
        .get_message("m_alice")
        .await
        .unwrap()
        .unwrap();
    assert!(alice_msg.label_ids.contains(&LABEL_INBOX.to_string()));
    assert!(alice_msg.label_ids.contains(&LABEL_UNREAD.to_string()));

    // Bob's sent message landed in Bob's mailbox, NOT Alice's
    let bob_sent = bob_state
        .store
        .list_messages(&nogml::storage::MessageListQuery {
            label_ids: vec![LABEL_SENT.to_string()],
            max_results: 10,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(bob_sent.messages.len(), 1);
    let alice_sent = alice_state
        .store
        .list_messages(&nogml::storage::MessageListQuery {
            label_ids: vec![LABEL_SENT.to_string()],
            max_results: 10,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(alice_sent.messages.is_empty());

    // Events carry their respective mailbox_id tags
    let ev1 = rx.recv().await.unwrap();
    let ev2 = rx.recv().await.unwrap();
    let mailboxes: Vec<String> = vec![ev1.mailbox_id, ev2.mailbox_id];
    assert!(mailboxes.contains(&"alice@example.com".to_string()));
    assert!(mailboxes.contains(&"bob@example.com".to_string()));
}
