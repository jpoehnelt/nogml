//! End-to-end tests for deliverability protection:
//! - AWS SES SNS Bounce (Permanent & Transient) and Complaint webhook ingestion
//! - Resend Svix-verified `email.bounced` and `email.complained` webhook ingestion
//! - Automatic suppression list blocking across to/cc/bcc + manual add/list/delete + auth scopes
//! - Per-domain daily send limits (`daily_send_limit_per_domain`)
//! - Rolling bounce-rate and complaint-rate circuit breaker with `min_samples` and manual pause/resume
//! - Dry-run deliverability checks, Prometheus `/metrics`, and SQLite persistence across restarts

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use http_body_util::BodyExt;
use nogml::{
    AppState,
    auth::{AuthScope, ScopedTokenConfig},
    config::Config,
    error::AppResult,
    resend::{HttpResendClient, svix::sign_svix_payload},
    server::build_router,
    storage::{MailStore, MemoryStore, SqliteStore},
    transport::{MailTransport, OutboundMessage, SendOutcome, TransportCapabilities},
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

const TEST_RESEND_SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
const TEST_SES_SECRET: &str = "ses-deliverability-test-secret";

#[derive(Clone, Default)]
struct RecordingTransport {
    sent: Arc<Mutex<Vec<OutboundMessage>>>,
}

impl RecordingTransport {
    fn count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }
}

#[async_trait]
impl MailTransport for RecordingTransport {
    fn name(&self) -> &'static str {
        "recording_mock"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            provider: "recording_mock".to_string(),
            supports_raw_mime: true,
            supports_scheduled_send: false,
            supports_idempotency_key: false,
            supports_inbound_webhooks: false,
            supports_delivery_webhooks: false,
            max_message_bytes: 10 * 1024 * 1024,
        }
    }

    async fn send(
        &self,
        msg: &OutboundMessage,
        _idempotency_key: Option<&str>,
    ) -> AppResult<SendOutcome> {
        let mut guard = self.sent.lock().unwrap();
        let idx = guard.len() + 1;
        guard.push(msg.clone());
        Ok(SendOutcome {
            provider: "recording_mock".to_string(),
            provider_message_id: format!("prov_msg_{idx}"),
        })
    }
}

fn base_config() -> Config {
    let mut cfg = Config::for_test();
    cfg.user_email = "sender@acme.example".to_string();
    cfg.default_domain = "acme.example".to_string();
    cfg.resend_webhook_secret = Some(TEST_RESEND_SECRET.to_string());
    cfg.ses_webhook_secret = Some(TEST_SES_SECRET.to_string());
    cfg.scoped_tokens = vec![
        ScopedTokenConfig {
            token: "tok_admin".to_string(),
            mailbox_id: Some("sender@acme.example".to_string()),
            shared_mailboxes: Vec::new(),
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
            token: "tok_read".to_string(),
            mailbox_id: Some("sender@acme.example".to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_send".to_string(),
            mailbox_id: Some("sender@acme.example".to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read, AuthScope::Write, AuthScope::Send],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
    ];
    cfg
}

fn build_app_with_store(
    cfg: Config,
    store: Arc<dyn MailStore>,
) -> (Router, AppState, RecordingTransport) {
    let resend = Arc::new(HttpResendClient::new("http://127.0.0.1:9", None));
    let transport = RecordingTransport::default();
    let state =
        AppState::with_backends(cfg, store, resend).with_transport(Arc::new(transport.clone()));
    let app = build_router(state.clone());
    (app, state, transport)
}

async fn send_json(
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
    let req_body = if let Some(val) = body {
        builder = builder.header("content-type", "application/json");
        Body::from(val.to_string())
    } else {
        Body::empty()
    };
    let resp = app
        .clone()
        .oneshot(builder.body(req_body).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({ "_raw": String::from_utf8_lossy(&bytes).to_string() }))
    };
    (status, json)
}

async fn post_ses_sns(app: &Router, inner_notification: Value) -> (StatusCode, Value) {
    let envelope = json!({
        "Type": "Notification",
        "MessageId": "sns-msg-1",
        "TopicArn": "arn:aws:sns:us-east-1:123456789012:ses-events",
        "Timestamp": Utc::now().to_rfc3339(),
        "Message": inner_notification.to_string(),
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhooks/ses")
                .header("content-type", "application/json")
                .header("x-ses-webhook-secret", TEST_SES_SECRET)
                .body(Body::from(envelope.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn post_resend_signed(app: &Router, svix_id: &str, payload: Value) -> (StatusCode, Value) {
    let body_str = payload.to_string();
    let ts = Utc::now().timestamp();
    let sig = sign_svix_payload(svix_id, ts, body_str.as_bytes(), TEST_RESEND_SECRET).unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhooks/resend")
                .header("content-type", "application/json")
                .header("svix-id", svix_id)
                .header("svix-timestamp", ts.to_string())
                .header("svix-signature", sig)
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn ses_bounce_and_complaint_webhooks_auto_suppress_and_block_sends() {
    let cfg = base_config();
    let store: Arc<dyn MailStore> = Arc::new(MemoryStore::new(&cfg.user_email));
    let (app, _state, transport) = build_app_with_store(cfg, store);

    // 1. SES Permanent Bounce -> auto-suppresses recipient and records hard_bounce event.
    let (status, bounce_resp) = post_ses_sns(
        &app,
        json!({
            "notificationType": "Bounce",
            "bounce": {
                "bounceType": "Permanent",
                "bounceSubType": "General",
                "bouncedRecipients": [
                    {
                        "emailAddress": "Hard.Bounce@Victim.Example",
                        "status": "5.1.1",
                        "diagnosticCode": "smtp; 550 5.1.1 user unknown"
                    }
                ],
                "timestamp": Utc::now().to_rfc3339()
            },
            "mail": {
                "source": "sender@acme.example",
                "messageId": "ses-msg-bounce-1",
                "destination": ["Hard.Bounce@Victim.Example"]
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bounce_resp["status"], "recorded");
    assert_eq!(
        bounce_resp["suppressed"],
        json!(["hard.bounce@victim.example"])
    );

    // 2. SES Transient Bounce -> records soft_bounce ONLY (does NOT suppress).
    let (status, soft_resp) = post_ses_sns(
        &app,
        json!({
            "notificationType": "Bounce",
            "bounce": {
                "bounceType": "Transient",
                "bounceSubType": "MailboxFull",
                "bouncedRecipients": [
                    { "emailAddress": "soft@victim.example" }
                ],
                "timestamp": Utc::now().to_rfc3339()
            },
            "mail": {
                "source": "sender@acme.example",
                "destination": ["soft@victim.example"]
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(soft_resp["suppressed"], json!([]));

    // 3. SES Complaint -> auto-suppresses recipient with reason=complaint.
    let (status, comp_resp) = post_ses_sns(
        &app,
        json!({
            "notificationType": "Complaint",
            "complaint": {
                "complainedRecipients": [
                    { "emailAddress": "complainer@victim.example" }
                ],
                "complaintFeedbackType": "abuse",
                "timestamp": Utc::now().to_rfc3339()
            },
            "mail": {
                "source": "sender@acme.example",
                "destination": ["complainer@victim.example"]
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        comp_resp["suppressed"],
        json!(["complainer@victim.example"])
    );

    // 4. Outbound send to hard-bounced recipient (via cc) is blocked with 403 + structured details, zero transport calls.
    let (status, deny) = send_json(
        &app,
        "POST",
        "/v1/messages/send",
        Some("tok_send"),
        Some(json!({
            "to": ["ok@victim.example"],
            "cc": ["HARD.BOUNCE@VICTIM.EXAMPLE"],
            "subject": "Should fail",
            "text": "Blocked by suppression list"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(deny["error"]["code"], "recipient_suppressed");
    assert_eq!(
        deny["error"]["details"]["suppressed"],
        json!(["hard.bounce@victim.example"])
    );
    assert_eq!(transport.count(), 0);

    // 5. Dry-run send to complained recipient reports suppression_list failed.
    let (status, dry) = send_json(
        &app,
        "POST",
        "/v1/messages/send",
        Some("tok_send"),
        Some(json!({
            "to": ["complainer@victim.example"],
            "subject": "Dry run check",
            "text": "Preview",
            "dry_run": true
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(dry["would_succeed"], false);
    assert!(
        dry["policy_checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["rule"] == "suppression_list" && c["passed"] == false)
    );

    // 6. Gmail API send to suppressed recipient is ALSO blocked without invoking transport.
    let raw_gmail = "From: sender@acme.example\r\nTo: hard.bounce@victim.example\r\nSubject: Gmail Send\r\n\r\nHi";
    let (status, _gmail_deny) = send_json(
        &app,
        "POST",
        "/gmail/v1/users/me/messages/send",
        Some("tok_send"),
        Some(json!({
            "raw": general_purpose::URL_SAFE_NO_PAD.encode(raw_gmail.as_bytes())
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(transport.count(), 0);

    // 7. Transiently soft-bounced recipient IS still allowed to send.
    let (status, ok_resp) = send_json(
        &app,
        "POST",
        "/v1/messages/send",
        Some("tok_send"),
        Some(json!({
            "to": ["soft@victim.example"],
            "subject": "Soft bounce allowed",
            "text": "Transient bounce is not suppressed"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={ok_resp}");
    assert_eq!(transport.count(), 1);

    // 8. Removing the suppressed address via DELETE /v1/suppression/{email} unblocks sending.
    // Non-admin token must get 403 Forbidden.
    let (status, _) = send_json(
        &app,
        "DELETE",
        "/v1/suppression/hard.bounce@victim.example",
        Some("tok_send"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Admin token succeeds.
    let (status, del_resp) = send_json(
        &app,
        "DELETE",
        "/v1/suppression/hard.bounce@victim.example",
        Some("tok_admin"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(del_resp["deleted"], true);

    let (status, unblocked) = send_json(
        &app,
        "POST",
        "/v1/messages/send",
        Some("tok_send"),
        Some(json!({
            "to": ["hard.bounce@victim.example"],
            "subject": "Now allowed",
            "text": "Removed from suppression list"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={unblocked}");
    assert_eq!(transport.count(), 2);

    // 9. Verify GET /v1/deliverability/stats reports counts accurately with read scope.
    let (status, stats) = send_json(
        &app,
        "GET",
        "/v1/deliverability/stats?domain=acme.example",
        Some("tok_read"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let dom = &stats["domains"][0];
    assert_eq!(dom["domain"], "acme.example");
    assert_eq!(dom["sent"], 2);
    assert_eq!(dom["hard_bounce"], 1);
    assert_eq!(dom["soft_bounce"], 1);
    assert_eq!(dom["complaint"], 1);
    assert_eq!(dom["circuit_breaker"]["tripped"], false); // below min_samples=20
    assert_eq!(stats["suppression_count"], 1); // complainer@victim.example still suppressed
}

#[tokio::test]
async fn resend_signed_bounce_and_complaint_webhooks_auto_suppress() {
    let cfg = base_config();
    let store: Arc<dyn MailStore> = Arc::new(MemoryStore::new(&cfg.user_email));
    let (app, _state, transport) = build_app_with_store(cfg, store);

    // 1. Signed Resend `email.bounced` (hard bounce) auto-suppresses recipient.
    let (status, resp) = post_resend_signed(
        &app,
        "svix_bounce_1",
        json!({
            "type": "email.bounced",
            "created_at": Utc::now().to_rfc3339(),
            "data": {
                "email_id": "re_bounce_1",
                "from": "sender@acme.example",
                "to": ["resend.bounced@partner.example"],
                "bounce": {
                    "type": "Permanent",
                    "subType": "Suppressed",
                    "message": "Mailbox does not exist"
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["status"], "recorded");
    assert_eq!(
        resp["suppressed"],
        json!(["resend.bounced@partner.example"])
    );

    // 2. Signed Resend `email.complained` auto-suppresses recipient.
    let (status, resp) = post_resend_signed(
        &app,
        "svix_complaint_1",
        json!({
            "type": "email.complained",
            "created_at": Utc::now().to_rfc3339(),
            "data": {
                "email_id": "re_complaint_1",
                "from": "sender@acme.example",
                "to": ["resend.complainer@partner.example"]
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["status"], "recorded");
    assert_eq!(
        resp["suppressed"],
        json!(["resend.complainer@partner.example"])
    );

    // 3. Subsequent sends to either address are rejected without calling transport.
    for addr in [
        "resend.bounced@partner.example",
        "resend.complainer@partner.example",
    ] {
        let (status, deny) = send_json(
            &app,
            "POST",
            "/v1/messages/send",
            Some("tok_send"),
            Some(json!({
                "to": [addr],
                "subject": "Blocked",
                "text": "Should be suppressed"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(deny["error"]["code"], "recipient_suppressed");
    }
    assert_eq!(transport.count(), 0);

    // 4. Listing suppressions with source=resend returns both entries.
    let (status, list) = send_json(
        &app,
        "GET",
        "/v1/suppression?source=resend",
        Some("tok_read"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["count"], 2);
}

#[tokio::test]
async fn daily_send_limit_blocks_excess_sends_per_domain() {
    let mut cfg = base_config();
    cfg.daily_send_limit_per_domain = 2;
    let store: Arc<dyn MailStore> = Arc::new(MemoryStore::new(&cfg.user_email));
    let (app, _state, transport) = build_app_with_store(cfg, store);

    // First 2 sends succeed.
    for i in 1..=2 {
        let (status, resp) = send_json(
            &app,
            "POST",
            "/v1/messages/send",
            Some("tok_send"),
            Some(json!({
                "to": [format!("user{i}@partner.example")],
                "subject": format!("Message {i}"),
                "text": "Within daily quota"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "send {i} failed: {resp}");
    }
    assert_eq!(transport.count(), 2);

    // 3rd send is rejected with 403 daily_send_limit_exceeded without invoking transport.
    let (status, deny) = send_json(
        &app,
        "POST",
        "/v1/messages/send",
        Some("tok_send"),
        Some(json!({
            "to": ["user3@partner.example"],
            "subject": "Message 3",
            "text": "Exceeds daily quota"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(deny["error"]["code"], "daily_send_limit_exceeded");
    assert_eq!(transport.count(), 2);

    // Stats show daily_sent=2, daily_limit=2, daily_remaining=0.
    let (status, stats) = send_json(
        &app,
        "GET",
        "/v1/deliverability/stats?domain=acme.example",
        Some("tok_read"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stats["domains"][0]["daily_sent"], 2);
    assert_eq!(stats["domains"][0]["daily_limit"], 2);
    assert_eq!(stats["domains"][0]["daily_remaining"], 0);
}

#[tokio::test]
async fn circuit_breaker_trips_on_bounce_rate_and_resumes_via_admin_api() {
    let mut cfg = base_config();
    cfg.deliverability_max_bounce_rate = 0.05;
    cfg.deliverability_max_complaint_rate = 0.001;
    cfg.deliverability_min_samples = 20;
    let store: Arc<dyn MailStore> = Arc::new(MemoryStore::new(&cfg.user_email));
    let (app, _state, transport) = build_app_with_store(cfg, store);

    // Send 20 emails (all succeed).
    for i in 1..=20 {
        let (status, resp) = send_json(
            &app,
            "POST",
            "/v1/messages/send",
            Some("tok_send"),
            Some(json!({
                "to": [format!("rcpt{i}@partner.example")],
                "subject": format!("Batch {i}"),
                "text": "Hello"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "send {i} failed: {resp}");
    }
    assert_eq!(transport.count(), 20);

    // 1 hard bounce -> 1/20 = 5.0% (does not exceed 5.0%).
    let (status, _) = post_ses_sns(
        &app,
        json!({
            "notificationType": "Bounce",
            "bounce": {
                "bounceType": "Permanent",
                "bouncedRecipients": [{ "emailAddress": "rcpt1@partner.example" }]
            },
            "mail": { "source": "sender@acme.example" }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 2nd hard bounce -> 2/20 = 10.0% > 5.0% -> trips circuit breaker!
    let (status, _) = post_ses_sns(
        &app,
        json!({
            "notificationType": "Bounce",
            "bounce": {
                "bounceType": "Permanent",
                "bouncedRecipients": [{ "emailAddress": "rcpt2@partner.example" }]
            },
            "mail": { "source": "sender@acme.example" }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Send to a brand-new clean recipient is blocked by circuit breaker!
    let (status, deny) = send_json(
        &app,
        "POST",
        "/v1/messages/send",
        Some("tok_send"),
        Some(json!({
            "to": ["fresh@partner.example"],
            "subject": "Blocked by circuit breaker",
            "text": "Should not dispatch"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(deny["error"]["code"], "deliverability_circuit_open");
    assert_eq!(transport.count(), 20);

    // Stats report open_bounce_rate.
    let (status, stats) = send_json(
        &app,
        "GET",
        "/v1/deliverability/stats?domain=acme.example",
        Some("tok_read"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stats["domains"][0]["circuit_breaker"]["tripped"], true);
    assert_eq!(
        stats["domains"][0]["circuit_breaker"]["state"],
        "open_bounce_rate"
    );

    // Non-admin resume is rejected with 403.
    let (status, _) = send_json(
        &app,
        "POST",
        "/v1/deliverability/domains/acme.example/resume",
        Some("tok_send"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Admin resume resets the circuit breaker cleanly.
    let (status, resumed) = send_json(
        &app,
        "POST",
        "/v1/deliverability/domains/acme.example/resume",
        Some("tok_admin"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resumed["resumed"], true);
    assert_eq!(resumed["stats"]["circuit_breaker"]["tripped"], false);

    // Sending to fresh recipient now succeeds!
    let (status, ok) = send_json(
        &app,
        "POST",
        "/v1/messages/send",
        Some("tok_send"),
        Some(json!({
            "to": ["fresh@partner.example"],
            "subject": "Resumed!",
            "text": "Works again"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={ok}");
    assert_eq!(transport.count(), 21);

    // Manual pause blocks sending immediately, and resume restores it.
    let (status, paused) = send_json(
        &app,
        "POST",
        "/v1/deliverability/domains/acme.example/pause",
        Some("tok_admin"),
        Some(json!({ "reason": "DNS maintenance" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(paused["paused"], true);
    assert_eq!(paused["stats"]["circuit_breaker"]["state"], "paused");

    let (status, deny_paused) = send_json(
        &app,
        "POST",
        "/v1/messages/send",
        Some("tok_send"),
        Some(json!({
            "to": ["fresh2@partner.example"],
            "subject": "Paused",
            "text": "Should fail"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(deny_paused["error"]["code"], "deliverability_circuit_open");
    assert!(
        deny_paused["error"]["message"]
            .as_str()
            .unwrap()
            .contains("DNS maintenance")
    );
    assert_eq!(transport.count(), 21);

    // Verify Prometheus /metrics exports deliverability counters.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/metrics")
                .header("authorization", "Bearer tok_read")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let metrics_text = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(metrics_text.contains("nogml_deliverability_events_total{kind=\"sent\"} 21\n"));
    assert!(metrics_text.contains("nogml_deliverability_events_total{kind=\"hard_bounce\"} 2\n"));
    assert!(metrics_text.contains("nogml_deliverability_suppression_added_total 2\n"));
    assert!(
        metrics_text.contains("nogml_deliverability_blocked_total{reason=\"circuit_breaker\"} 2\n")
    );
}

#[tokio::test]
async fn sqlite_persists_suppression_and_manual_pause_across_restart() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("deliverability.db");

    {
        let cfg = base_config();
        let store: Arc<dyn MailStore> =
            Arc::new(SqliteStore::open(&db_path, &cfg.user_email).unwrap());
        let (app, _state, _transport) = build_app_with_store(cfg, store);

        let (status, created) = send_json(
            &app,
            "POST",
            "/v1/suppression",
            Some("tok_admin"),
            Some(json!({
                "email": "Persisted@Example.COM",
                "reason": "manual",
                "detail": "Do not email"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created["suppression"]["email"], "persisted@example.com");

        let (status, _) = send_json(
            &app,
            "POST",
            "/v1/deliverability/domains/acme.example/pause",
            Some("tok_admin"),
            Some(json!({ "reason": "Warmup hold" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    // Reopen fresh SqliteStore and verify both suppression and pause persisted.
    {
        let cfg = base_config();
        let store: Arc<dyn MailStore> =
            Arc::new(SqliteStore::open(&db_path, &cfg.user_email).unwrap());
        let (app, _state, transport) = build_app_with_store(cfg, store);

        let (status, deny) = send_json(
            &app,
            "POST",
            "/v1/messages/send",
            Some("tok_send"),
            Some(json!({
                "to": ["persisted@example.com"],
                "subject": "Blocked after restart",
                "text": "Still suppressed"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(deny["error"]["code"], "recipient_suppressed");

        let (status, stats) = send_json(
            &app,
            "GET",
            "/v1/deliverability/stats?domain=acme.example",
            Some("tok_read"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(stats["domains"][0]["circuit_breaker"]["state"], "paused");
        assert_eq!(stats["suppression_count"], 1);
        assert_eq!(transport.count(), 0);
    }
}
