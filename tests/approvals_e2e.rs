//! End-to-end tests for the persistent human-in-the-loop approval queue (`Issue #8`).

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
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use nogml::{
    AppState,
    ai::safety::{OutboundCheck, OutboundDecision, OutboundPolicy, PolicyCheck},
    blob::{BlobStore, MemoryBlobStore},
    build_router,
    config::Config,
    error::AppResult,
    events::MailEvent,
    models::{LABEL_INBOX, LABEL_SENT},
    resend::HttpResendClient,
    storage::{ApprovalStatus, MailStore, MemoryStore, NewMessageInput, SqliteStore},
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

struct CustomHoldPolicy;

#[async_trait]
impl OutboundPolicy for CustomHoldPolicy {
    async fn evaluate(&self, check: &OutboundCheck) -> AppResult<OutboundDecision> {
        if check.to.iter().any(|r| r.contains("external")) || check.subject.contains("[HOLD]") {
            Ok(OutboundDecision::HoldForApproval {
                reason: "external recipient requires manager sign-off".to_string(),
            })
        } else {
            Ok(OutboundDecision::Allow)
        }
    }

    fn policy_checks(&self, _check: &OutboundCheck) -> Vec<PolicyCheck> {
        vec![PolicyCheck {
            rule: "external_approval_policy".to_string(),
            passed: true,
            detail: "External recipients are routed to the human approval queue".to_string(),
        }]
    }

    fn backend_name(&self) -> &'static str {
        "custom_hold_policy"
    }
}

async fn http_json(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri);
    let body = if let Some(val) = body {
        req = req.header("content-type", "application/json");
        Body::from(val.to_string())
    } else {
        Body::empty()
    };
    let resp = app
        .clone()
        .oneshot(req.body(body).unwrap())
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

#[tokio::test]
async fn e2e_require_approval_webhook_sqlite_persistence_and_single_approve() {
    let webhook_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/approvals-hook"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
        .expect(1)
        .mount(&webhook_server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("approvals.db");

    let mut cfg = Config::for_test();
    cfg.db_path = db_path.clone();
    cfg.require_approval = true;
    cfg.approval_ttl_secs = 3600;
    cfg.approval_webhook_url = Some(format!("{}/approvals-hook", webhook_server.uri()));

    // Phase 1: Send triggers HoldForApproval via ConfigOutboundPolicy (`require_approval=true`),
    // returns 202 with approval_id, makes 0 transport calls, emits ApprovalRequested, fires webhook.
    let approval_id: String;
    let draft_id: String;
    {
        let store = Arc::new(SqliteStore::open(&db_path, &cfg.user_email).unwrap());
        let (transport, sent_log) = RecordingTransport::new();
        let resend = Arc::new(HttpResendClient::from_config(&cfg));
        let state =
            AppState::with_backends(cfg.clone(), store, resend).with_transport(Arc::new(transport));
        let mut events_rx = state.events.subscribe();
        let app = build_router(state);

        let (status, body) = http_json(
            &app,
            "POST",
            "/v1/messages/send",
            Some(json!({
                "to": ["alice@external.test"],
                "cc": ["ops@example.com"],
                "bcc": ["audit@example.com"],
                "subject": "Quarterly wire transfer",
                "text": "Please confirm transfer of $5,000."
            })),
        )
        .await;

        assert_eq!(status, StatusCode::ACCEPTED, "expected 202: {body}");
        assert_eq!(body["status"], "pending_approval");
        assert_eq!(body["held_for_approval"], true);
        assert!(body["expires_at"].as_str().is_some());
        assert_eq!(body["to"], json!(["alice@external.test"]));
        assert_eq!(body["cc"], json!(["ops@example.com"]));
        assert_eq!(body["bcc"], json!(["audit@example.com"]));
        assert_eq!(body["subject"], "Quarterly wire transfer");
        assert_eq!(body["preview"]["subject"], "Quarterly wire transfer");

        approval_id = body["approval_id"].as_str().unwrap().to_string();
        draft_id = body["draft_id"].as_str().unwrap().to_string();
        assert_eq!(
            sent_log.lock().unwrap().len(),
            0,
            "transport MUST NOT be called when held for approval"
        );

        // Verify ApprovalRequested event was published on EventBus
        let mut saw_approval_requested = false;
        while let Ok(env) = events_rx.try_recv() {
            if let MailEvent::ApprovalRequested {
                approval_id: ev_id,
                subject,
                ..
            } = env.event
            {
                assert_eq!(ev_id, approval_id);
                assert_eq!(subject, "Quarterly wire transfer");
                saw_approval_requested = true;
            }
        }
        assert!(
            saw_approval_requested,
            "expected MailEvent::ApprovalRequested"
        );

        // Wait briefly for the async webhook POST to hit wiremock
        let mut webhook_reqs = Vec::new();
        for _ in 0..40 {
            let reqs = webhook_server.received_requests().await.unwrap();
            if !reqs.is_empty() {
                webhook_reqs = reqs;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(webhook_reqs.len(), 1, "expected 1 webhook POST");
        let hook_payload: Value = serde_json::from_slice(&webhook_reqs[0].body).unwrap();
        assert_eq!(hook_payload["event"], "approval_requested");
        assert_eq!(hook_payload["approval_id"], approval_id);
        assert!(
            hook_payload["text"]
                .as_str()
                .unwrap()
                .contains("Quarterly wire transfer"),
            "webhook should include Slack-compatible text payload"
        );
        assert_eq!(
            hook_payload["message"]["subject"],
            "Quarterly wire transfer"
        );
    }

    // Phase 2: Reopen SQLite from disk, confirm pending approval persisted intact,
    // approve it ONCE, verify exact OutboundMessage sent + stored in SENT + draft removed + blob mirrored,
    // and verify a second approve attempt returns 409 Conflict with zero resend!
    {
        let reopened_store = Arc::new(SqliteStore::open(&db_path, &cfg.user_email).unwrap());
        let (transport, sent_log) = RecordingTransport::new();
        let blobs = Arc::new(MemoryBlobStore::new());
        let resend = Arc::new(HttpResendClient::from_config(&cfg));
        let state = AppState::with_backends(cfg.clone(), reopened_store.clone(), resend)
            .with_transport(Arc::new(transport))
            .with_blobs(blobs.clone());
        let mut events_rx = state.events.subscribe();
        let app = build_router(state);

        // Persisted across SQLite reopen
        let (list_status, list_body) =
            http_json(&app, "GET", "/v1/approvals?status=pending", None).await;
        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(list_body["count"], 1);
        assert_eq!(list_body["approvals"][0]["id"], approval_id);

        let (get_status, get_body) =
            http_json(&app, "GET", &format!("/v1/approvals/{approval_id}"), None).await;
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(get_body["status"], "pending");
        assert_eq!(
            get_body["outbound_message"]["subject"],
            "Quarterly wire transfer"
        );

        // Approve once -> sends exact message via transport
        let (app_status, app_body) = http_json(
            &app,
            "POST",
            &format!("/v1/approvals/{approval_id}/approve"),
            Some(json!({
                "decided_by": "cfo@example.com",
                "note": "Verified wire details"
            })),
        )
        .await;
        assert_eq!(app_status, StatusCode::OK, "approve failed: {app_body}");
        assert_eq!(app_body["status"], "approved");
        assert_eq!(app_body["approval"]["status"], "approved");
        assert_eq!(app_body["approval"]["decided_by"], "cfo@example.com");
        assert_eq!(
            app_body["approval"]["decision_note"],
            "Verified wire details"
        );
        assert_eq!(app_body["provider"], "recording_test");
        assert_eq!(app_body["provider_message_id"], "tx_1");

        let sent_msg_id = app_body["sent_message_id"].as_str().unwrap().to_string();
        assert_eq!(app_body["approval"]["sent_message_id"], sent_msg_id);

        // Verify exact message dispatched once
        {
            let dispatches = sent_log.lock().unwrap();
            assert_eq!(dispatches.len(), 1);
            let (ref dispatched, ref idem_key) = dispatches[0];
            assert_eq!(dispatched.to, vec!["alice@external.test".to_string()]);
            assert_eq!(dispatched.cc, vec!["ops@example.com".to_string()]);
            assert_eq!(dispatched.bcc, vec!["audit@example.com".to_string()]);
            assert_eq!(dispatched.subject, "Quarterly wire transfer");
            assert_eq!(
                dispatched.text.as_deref(),
                Some("Please confirm transfer of $5,000.")
            );
            assert!(!dispatched.raw_rfc2822.is_empty());
            assert_eq!(
                idem_key.as_deref(),
                Some(format!("approval-{approval_id}").as_str())
            );
        }

        // Stored in SENT, mirrored to BlobStore, source draft deleted
        let stored = reopened_store
            .get_message(&sent_msg_id)
            .await
            .unwrap()
            .expect("sent message should exist");
        assert!(stored.label_ids.contains(&LABEL_SENT.to_string()));
        assert_eq!(stored.resend_id.as_deref(), Some("tx_1"));
        assert!(
            reopened_store.get_draft(&draft_id).await.unwrap().is_none(),
            "source draft should be deleted after approval send"
        );
        assert!(
            blobs
                .get(&nogml::blob::raw_message_blob_key(&sent_msg_id))
                .await
                .unwrap()
                .is_some(),
            "sent message raw RFC 2822 should be mirrored to BlobStore"
        );

        // Verify MessageSent event was published
        let mut saw_sent = false;
        while let Ok(env) = events_rx.try_recv() {
            if let MailEvent::MessageSent {
                message_id,
                subject,
                ..
            } = env.event
            {
                assert_eq!(message_id, sent_msg_id);
                assert_eq!(subject, "Quarterly wire transfer");
                saw_sent = true;
            }
        }
        assert!(saw_sent, "expected MailEvent::MessageSent after approval");

        // Second approve MUST return 409 Conflict without resending!
        let (dup_status, dup_body) = http_json(
            &app,
            "POST",
            &format!("/v1/approvals/{approval_id}/approve"),
            Some(json!({ "decided_by": "other@example.com" })),
        )
        .await;
        assert_eq!(dup_status, StatusCode::CONFLICT, "expected 409: {dup_body}");
        assert_eq!(dup_body["error"]["code"], "conflict");
        assert_eq!(
            sent_log.lock().unwrap().len(),
            1,
            "transport MUST NOT be called a second time"
        );

        // Rejecting an already-approved item also returns 409 Conflict
        let (rej_status, _) = http_json(
            &app,
            "POST",
            &format!("/v1/approvals/{approval_id}/reject"),
            None,
        )
        .await;
        assert_eq!(rej_status, StatusCode::CONFLICT);
    }
}

#[tokio::test]
async fn e2e_custom_policy_draft_send_hold_reject_and_expiration() {
    let cfg = Config::for_test();
    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let (transport, sent_log) = RecordingTransport::new();
    let resend = Arc::new(HttpResendClient::from_config(&cfg));

    // Seed parent message to verify reply threading is preserved across hold -> approve
    let parent = store
        .insert_message(NewMessageInput {
            id: None,
            thread_id: Some("thr_parent_1".to_string()),
            label_ids: vec![LABEL_INBOX.to_string()],
            raw_rfc2822: b"From: ceo@external.test\r\nTo: agent@example.com\r\nSubject: Contract\r\nMessage-ID: <parent@external.test>\r\n\r\nThoughts?".to_vec(),
            snippet: "Thoughts?".to_string(),
            internal_date_ms: 1_700_000_000_000,
            subject: "Contract".to_string(),
            from_addr: "ceo@external.test".to_string(),
            to_addrs: vec!["agent@example.com".to_string()],
            cc_addrs: Vec::new(),
            bcc_addrs: Vec::new(),
            text_body: "Thoughts?".to_string(),
            html_body: None,
            rfc822_message_id: Some("<parent@external.test>".to_string()),
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

    let state = AppState::with_backends(cfg.clone(), store.clone(), resend)
        .with_transport(Arc::new(transport))
        .with_outbound_policy(Arc::new(CustomHoldPolicy));
    let app = build_router(state);

    // 1. Create a draft replying to parent and attempt to send draft -> held for approval (202)
    let (drf_status, drf_body) = http_json(
        &app,
        "POST",
        "/v1/drafts",
        Some(json!({
            "reply_to_message_id": parent.id,
            "text": "Draft reply ready for review."
        })),
    )
    .await;
    assert_eq!(drf_status, StatusCode::OK);
    let draft_id = drf_body["draft_id"].as_str().unwrap().to_string();

    let (hold_status, hold_body) =
        http_json(&app, "POST", &format!("/v1/drafts/{draft_id}/send"), None).await;
    assert_eq!(
        hold_status,
        StatusCode::ACCEPTED,
        "expected 202: {hold_body}"
    );
    let draft_approval_id = hold_body["approval_id"].as_str().unwrap().to_string();
    assert_eq!(hold_body["draft_id"], draft_id);
    assert_eq!(sent_log.lock().unwrap().len(), 0);

    // Approve draft send -> preserves thread_id and deletes source draft
    let (ok_status, ok_body) = http_json(
        &app,
        "POST",
        &format!("/v1/approvals/{draft_approval_id}/approve"),
        None,
    )
    .await;
    assert_eq!(ok_status, StatusCode::OK, "approve failed: {ok_body}");
    assert_eq!(ok_body["thread_id"], "thr_parent_1");
    assert_eq!(sent_log.lock().unwrap().len(), 1);
    assert!(store.get_draft(&draft_id).await.unwrap().is_none());

    // 2. Reject flow: transitions to rejected, never calls transport
    let (h2_status, h2_body) = http_json(
        &app,
        "POST",
        "/v1/messages/send",
        Some(json!({
            "to": ["vendor@external.test"],
            "subject": "[HOLD] Do not send this",
            "text": "Sensitive content"
        })),
    )
    .await;
    assert_eq!(h2_status, StatusCode::ACCEPTED);
    let reject_id = h2_body["approval_id"].as_str().unwrap().to_string();

    let (rej_status, rej_body) = http_json(
        &app,
        "POST",
        &format!("/v1/approvals/{reject_id}/reject"),
        Some(json!({
            "decided_by": "security@example.com",
            "note": "Contains internal pricing"
        })),
    )
    .await;
    assert_eq!(rej_status, StatusCode::OK);
    assert_eq!(rej_body["status"], "rejected");
    assert_eq!(rej_body["approval"]["status"], "rejected");
    assert_eq!(rej_body["approval"]["decided_by"], "security@example.com");
    assert_eq!(
        rej_body["approval"]["decision_note"],
        "Contains internal pricing"
    );
    assert_eq!(
        sent_log.lock().unwrap().len(),
        1,
        "reject MUST NEVER call transport"
    );

    // Trying to approve after reject -> 409 Conflict
    let (post_rej_status, _) = http_json(
        &app,
        "POST",
        &format!("/v1/approvals/{reject_id}/approve"),
        None,
    )
    .await;
    assert_eq!(post_rej_status, StatusCode::CONFLICT);
    assert_eq!(sent_log.lock().unwrap().len(), 1);

    // 3. Expiration check: create an already-expired approval and verify 409 on approve
    let expired = store
        .create_pending_approval(nogml::storage::NewPendingApprovalInput {
            id: None,
            reason: "short ttl".to_string(),
            requester: None,
            outbound_message: OutboundMessage {
                from: "agent@example.com".to_string(),
                to: vec!["late@external.test".to_string()],
                subject: "Expired".to_string(),
                text: Some("Too late".to_string()),
                ..Default::default()
            },
            reply_to_message_id: None,
            thread_id: None,
            draft_id: None,
            created_at_ms: chrono::Utc::now().timestamp_millis() - 10_000,
            expires_at_ms: chrono::Utc::now().timestamp_millis() - 1_000,
        })
        .await
        .unwrap();

    let (exp_get_status, exp_get_body) =
        http_json(&app, "GET", &format!("/v1/approvals/{}", expired.id), None).await;
    assert_eq!(exp_get_status, StatusCode::OK);
    assert_eq!(exp_get_body["status"], "expired");

    let (exp_app_status, _) = http_json(
        &app,
        "POST",
        &format!("/v1/approvals/{}/approve", expired.id),
        None,
    )
    .await;
    assert_eq!(exp_app_status, StatusCode::CONFLICT);
    assert_eq!(sent_log.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn e2e_concurrent_approve_never_double_sends() {
    let mut cfg = Config::for_test();
    cfg.require_approval = true;
    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let (transport, sent_log) = RecordingTransport::with_delay(Duration::from_millis(60));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));

    let state = AppState::with_backends(cfg, store, resend).with_transport(Arc::new(transport));
    let app = build_router(state);

    let (status, body) = http_json(
        &app,
        "POST",
        "/v1/messages/send",
        Some(json!({
            "to": ["race@example.com"],
            "subject": "No double send",
            "text": "Exactly once"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let approval_id = body["approval_id"].as_str().unwrap().to_string();

    let uri = format!("/v1/approvals/{approval_id}/approve");
    let ((s1, _), (s2, _)) = tokio::join!(
        http_json(&app, "POST", &uri, None),
        http_json(&app, "POST", &uri, None),
    );

    let statuses = [s1, s2];
    assert!(
        statuses.contains(&StatusCode::OK) && statuses.contains(&StatusCode::CONFLICT),
        "expected one 200 OK and one 409 Conflict, got {statuses:?}"
    );
    assert_eq!(
        sent_log.lock().unwrap().len(),
        1,
        "concurrent approvals MUST invoke transport at most once"
    );
}

#[tokio::test]
async fn e2e_cli_mail_approvals_local_and_remote() {
    let bin = env!("CARGO_BIN_EXE_nogml");
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("cli_approvals.db");

    // 1. Local SQLite CLI workflow: send with --require-approval -> list -> get -> reject
    let send_out = Command::new(bin)
        .args([
            "--db-path",
            db_path.to_str().unwrap(),
            "--user-email",
            "agent@example.com",
            "--require-approval",
            "mail",
            "--json",
            "send",
            "--to",
            "cli-local@example.com",
            "--subject",
            "Local CLI hold",
            "--text",
            "Queued from local CLI",
        ])
        .output()
        .expect("run nogml mail send");
    assert!(
        send_out.status.success(),
        "local send failed: stderr={}",
        String::from_utf8_lossy(&send_out.stderr)
    );
    let send_json: Value = serde_json::from_slice(&send_out.stdout).unwrap();
    assert_eq!(send_json["status"], "pending_approval");
    let local_approval_id = send_json["approval_id"].as_str().unwrap().to_string();

    let list_out = Command::new(bin)
        .args([
            "--db-path",
            db_path.to_str().unwrap(),
            "mail",
            "--json",
            "approvals",
            "list",
            "--status",
            "pending",
        ])
        .output()
        .expect("run nogml mail approvals list");
    assert!(list_out.status.success());
    let list_json: Value = serde_json::from_slice(&list_out.stdout).unwrap();
    assert_eq!(list_json["count"], 1);
    assert_eq!(list_json["approvals"][0]["id"], local_approval_id);

    let get_out = Command::new(bin)
        .args([
            "--db-path",
            db_path.to_str().unwrap(),
            "mail",
            "--json",
            "approvals",
            "get",
            &local_approval_id,
        ])
        .output()
        .expect("run nogml mail approvals get");
    assert!(get_out.status.success());
    let get_json: Value = serde_json::from_slice(&get_out.stdout).unwrap();
    assert_eq!(get_json["id"], local_approval_id);
    assert_eq!(get_json["status"], "pending");

    let reject_out = Command::new(bin)
        .args([
            "--db-path",
            db_path.to_str().unwrap(),
            "mail",
            "--json",
            "approvals",
            "reject",
            &local_approval_id,
            "--note",
            "Rejected locally",
        ])
        .output()
        .expect("run nogml mail approvals reject");
    assert!(reject_out.status.success());
    let reject_json: Value = serde_json::from_slice(&reject_out.stdout).unwrap();
    assert_eq!(reject_json["status"], "rejected");
    assert_eq!(reject_json["approval"]["decision_note"], "Rejected locally");

    // 2. Remote --url CLI workflow against a live HTTP server backed by wiremock Resend
    let resend_mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/emails"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "re_cli_1" })))
        .expect(1)
        .mount(&resend_mock)
        .await;

    let mut cfg = Config::for_test();
    cfg.require_approval = true;
    cfg.resend_api_key = Some("re_test_key".to_string());
    cfg.resend_base_url = resend_mock.uri();
    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store.clone(), resend);
    let router = build_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let base_url = format!("http://{addr}");
    let bin_path = bin.to_string();

    // Send via remote CLI -> queued as pending_approval
    let base_url_clone = base_url.clone();
    let bin_clone = bin_path.clone();
    let remote_send = tokio::task::spawn_blocking(move || {
        Command::new(&bin_clone)
            .args([
                "mail",
                "--url",
                &base_url_clone,
                "--json",
                "send",
                "--to",
                "remote-cli@example.com",
                "--subject",
                "Remote CLI hold",
                "--text",
                "Approve me over HTTP",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        remote_send.status.success(),
        "remote send failed: {}",
        String::from_utf8_lossy(&remote_send.stderr)
    );
    let remote_send_json: Value = serde_json::from_slice(&remote_send.stdout).unwrap();
    let remote_approval_id = remote_send_json["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    // List via remote CLI
    let base_url_clone = base_url.clone();
    let bin_clone = bin_path.clone();
    let remote_list = tokio::task::spawn_blocking(move || {
        Command::new(&bin_clone)
            .args([
                "mail",
                "--url",
                &base_url_clone,
                "--json",
                "approvals",
                "list",
                "--status",
                "pending",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(remote_list.status.success());
    let remote_list_json: Value = serde_json::from_slice(&remote_list.stdout).unwrap();
    assert_eq!(remote_list_json["count"], 1);
    assert_eq!(remote_list_json["approvals"][0]["id"], remote_approval_id);

    // Approve via remote CLI -> dispatches to wiremock Resend once
    let base_url_clone = base_url.clone();
    let bin_clone = bin_path.clone();
    let approval_id_clone = remote_approval_id.clone();
    let remote_approve = tokio::task::spawn_blocking(move || {
        Command::new(&bin_clone)
            .args([
                "mail",
                "--url",
                &base_url_clone,
                "--json",
                "approvals",
                "approve",
                &approval_id_clone,
                "--note",
                "Approved from CLI",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        remote_approve.status.success(),
        "remote approve failed: {}",
        String::from_utf8_lossy(&remote_approve.stderr)
    );
    let remote_approve_json: Value = serde_json::from_slice(&remote_approve.stdout).unwrap();
    assert_eq!(remote_approve_json["status"], "approved");
    assert_eq!(remote_approve_json["provider_message_id"], "re_cli_1");
    assert_eq!(
        remote_approve_json["approval"]["decision_note"],
        "Approved from CLI"
    );

    // Second remote approve MUST fail (409 Conflict) and NOT resend
    let base_url_clone = base_url.clone();
    let bin_clone = bin_path.clone();
    let approval_id_clone = remote_approval_id.clone();
    let second_approve = tokio::task::spawn_blocking(move || {
        Command::new(&bin_clone)
            .args([
                "mail",
                "--url",
                &base_url_clone,
                "--json",
                "approvals",
                "approve",
                &approval_id_clone,
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        !second_approve.status.success(),
        "second approve must exit non-zero on 409 Conflict"
    );

    // Verify store status is Approved
    let final_record = store
        .get_pending_approval(&remote_approval_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(final_record.status, ApprovalStatus::Approved);

    server_handle.abort();
}
