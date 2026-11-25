use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::oneshot,
};
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, Request as WiremockRequest, ResponseTemplate,
    matchers::{method, path},
};

use nogml::{
    AppState,
    blob::raw_message_blob_key,
    build_router,
    config::{BlobBackend, Config, SmtpTlsMode, TransportBackend},
    error::AppResult,
    filter::{FilterDecision, InboundFilter, InboundMessage},
    mime,
};

struct TagExternalFilter;

#[async_trait]
impl InboundFilter for TagExternalFilter {
    async fn evaluate(&self, msg: &InboundMessage) -> AppResult<FilterDecision> {
        if msg.subject.contains("REJECT_E2E") {
            Ok(FilterDecision::Reject {
                reason: "rejected by e2e filter".to_string(),
            })
        } else {
            Ok(FilterDecision::Mutate {
                add_labels: vec!["SES_E2E".to_string()],
                remove_labels: vec![],
                skip_inbox: false,
            })
        }
    }

    fn backend_name(&self) -> &'static str {
        "tag_external_e2e"
    }
}

async fn send_json_req(app: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({}));
    (status, body)
}

#[tokio::test]
async fn e2e_ses_transport_verbatim_gmail_and_ai_send_plus_s3_webhook() {
    let ses_mock = MockServer::start().await;
    let s3_mock = MockServer::start().await;

    let verbatim_raw = concat!(
        "From: Agent <agent@example.com>\r\n",
        "To: Alice <alice@example.com>\r\n",
        "Subject: Verbatim Gmail Send via SES\r\n",
        "Message-ID: <e2e-ses-verbatim-1@example.com>\r\n",
        "X-Exact-Token: keep-this-verbatim-987654\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "Exact body bytes over SESv2.\r\n"
    )
    .as_bytes()
    .to_vec();

    let expected_raw_clone = verbatim_raw.clone();
    Mock::given(method("POST"))
        .and(path("/v2/email/outbound-emails"))
        .respond_with(move |req: &WiremockRequest| {
            let auth = req
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIA_E2E/"));
            assert!(auth.contains("/us-east-1/ses/aws4_request"));

            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let raw_b64 = body["Content"]["Raw"]["Data"].as_str().unwrap();
            let decoded = general_purpose::STANDARD.decode(raw_b64).unwrap();
            if decoded
                .windows(26)
                .any(|w| w == b"X-Exact-Token: keep-this-v")
            {
                assert_eq!(decoded, expected_raw_clone);
            }
            ResponseTemplate::new(200).set_body_json(json!({
                "MessageId": "ses-e2e-msg-1"
            }))
        })
        .expect(2)
        .mount(&ses_mock)
        .await;

    let inbound_s3_raw = concat!(
        "From: Partner <partner@remote.test>\r\n",
        "To: agent@example.com\r\n",
        "Subject: S3 inbound e2e\r\n",
        "Message-ID: <e2e-s3-in-1@remote.test>\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "Delivered via SES + S3.\r\n"
    )
    .as_bytes()
    .to_vec();

    Mock::given(method("GET"))
        .and(path("/ses-inbound-bucket/2026/inbound.eml"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(inbound_s3_raw.clone(), "message/rfc822"),
        )
        .expect(1)
        .mount(&s3_mock)
        .await;

    let mut cfg = Config::for_test();
    cfg.transport = TransportBackend::Ses;
    cfg.blob_backend = BlobBackend::Memory;
    cfg.ses_region = "us-east-1".to_string();
    cfg.ses_endpoint = Some(ses_mock.uri());
    cfg.ses_s3_endpoint = Some(s3_mock.uri());
    cfg.ses_access_key_id = Some("AKIA_E2E".to_string());
    cfg.ses_secret_access_key = Some("secret_e2e".to_string());
    cfg.ses_webhook_secret = Some("hook-secret-e2e".to_string());

    let state = AppState::from_config(cfg)
        .unwrap()
        .with_filter(Arc::new(TagExternalFilter));
    let app = build_router(state.clone());

    // 1. /v1/capabilities reports transport="ses"
    let (status, caps) = send_json_req(
        &app,
        Request::builder()
            .uri("/v1/capabilities")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(caps["backends"]["transport"], "ses");

    // 2. Gmail API send preserves verbatim raw_rfc2822 bytes
    let (status, gmail_sent) = send_json_req(
        &app,
        Request::builder()
            .method("POST")
            .uri("/gmail/v1/users/me/messages/send")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "raw": mime::encode_base64url(&verbatim_raw) }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(gmail_sent["id"].as_str().is_some());

    // 3. AI /v1/messages/send routes through SesTransport
    let (status, ai_sent) = send_json_req(
        &app,
        Request::builder()
            .method("POST")
            .uri("/v1/messages/send")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "to": ["alice@example.com"],
                    "subject": "AI send via SES",
                    "text": "Hello from /v1"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ai_sent["provider"], "ses");
    assert_eq!(ai_sent["resend_id"], "ses-e2e-msg-1");

    // 4. POST /webhooks/ses ingests S3 object through filter -> store -> blobs -> readable via /v1
    let ses_notification = json!({
        "notificationType": "Received",
        "mail": {
            "source": "partner@remote.test",
            "messageId": "ses-in-e2e-1",
            "destination": ["agent@example.com"]
        },
        "receipt": {
            "action": {
                "type": "S3",
                "bucketName": "ses-inbound-bucket",
                "objectKey": "2026/inbound.eml"
            }
        }
    });
    let sns_body = json!({
        "Type": "Notification",
        "Message": ses_notification.to_string()
    });
    let (status, hook_resp) = send_json_req(
        &app,
        Request::builder()
            .method("POST")
            .uri("/webhooks/ses")
            .header("content-type", "text/plain; charset=UTF-8")
            .header("x-nogml-webhook-secret", "hook-secret-e2e")
            .body(Body::from(sns_body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(hook_resp["status"], "received");
    let msg_id = hook_resp["message_id"].as_str().unwrap();

    // Verify stored blob and readable through /v1/messages/{id}
    assert_eq!(
        state
            .blobs
            .get(&raw_message_blob_key(msg_id))
            .await
            .unwrap(),
        Some(inbound_s3_raw)
    );
    let (status, fetched_msg) = send_json_req(
        &app,
        Request::builder()
            .uri(format!("/v1/messages/{msg_id}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fetched_msg["subject"], "S3 inbound e2e");
    let labels: Vec<&str> = fetched_msg["labels"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(labels.contains(&"SES_E2E"));
}

#[tokio::test]
async fn e2e_smtp_transport_verbatim_gmail_send_with_dot_stuffing() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = oneshot::channel::<Vec<u8>>();

    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(socket);
        reader
            .get_mut()
            .write_all(b"220 smtp.e2e.local ESMTP\r\n")
            .await
            .unwrap();

        let mut unstuffed = Vec::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).await.unwrap() == 0 {
                break;
            }
            let cmd = line.trim_end_matches(['\r', '\n']);
            let upper = cmd.to_ascii_uppercase();
            if upper.starts_with("EHLO ") {
                reader
                    .get_mut()
                    .write_all(b"250-smtp.e2e.local\r\n250 AUTH PLAIN\r\n")
                    .await
                    .unwrap();
            } else if upper.starts_with("AUTH PLAIN ") {
                reader
                    .get_mut()
                    .write_all(b"235 Authenticated\r\n")
                    .await
                    .unwrap();
            } else if upper.starts_with("MAIL FROM:") || upper.starts_with("RCPT TO:") {
                reader.get_mut().write_all(b"250 Ok\r\n").await.unwrap();
            } else if upper == "DATA" {
                reader
                    .get_mut()
                    .write_all(b"354 Send data\r\n")
                    .await
                    .unwrap();
                loop {
                    let mut dline = Vec::new();
                    if reader.read_until(b'\n', &mut dline).await.unwrap() == 0 {
                        break;
                    }
                    if dline == b".\r\n" {
                        break;
                    }
                    if dline.starts_with(b"..") {
                        unstuffed.extend_from_slice(&dline[1..]);
                    } else {
                        unstuffed.extend_from_slice(&dline);
                    }
                }
                reader
                    .get_mut()
                    .write_all(b"250 2.0.0 Ok: queued as E2E-SMTP-1\r\n")
                    .await
                    .unwrap();
            } else if upper == "QUIT" {
                reader.get_mut().write_all(b"221 Bye\r\n").await.unwrap();
                break;
            }
        }
        let _ = tx.send(unstuffed);
    });

    let mut cfg = Config::for_test();
    cfg.transport = TransportBackend::Smtp;
    cfg.smtp_host = "127.0.0.1".to_string();
    cfg.smtp_port = port;
    cfg.smtp_tls_mode = SmtpTlsMode::None;
    cfg.smtp_username = Some("relay-user".to_string());
    cfg.smtp_password = Some("relay-pass".to_string());

    let state = AppState::from_config(cfg).unwrap();
    let app = build_router(state);

    let (status, caps) = send_json_req(
        &app,
        Request::builder()
            .uri("/v1/capabilities")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(caps["backends"]["transport"], "smtp");

    let verbatim_raw = concat!(
        "From: Agent <agent@example.com>\r\n",
        "To: Alice <alice@example.com>\r\n",
        "Subject: Verbatim SMTP MIME\r\n",
        "Message-ID: <e2e-smtp-1@example.com>\r\n",
        "X-SMTP-Check: preserved\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "Line one\r\n",
        ".Dot-prefixed line\r\n",
        "Final line\r\n"
    )
    .as_bytes()
    .to_vec();

    let (status, _) = send_json_req(
        &app,
        Request::builder()
            .method("POST")
            .uri("/gmail/v1/users/me/messages/send")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "raw": mime::encode_base64url(&verbatim_raw) }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let received = rx.await.unwrap();
    assert_eq!(received, verbatim_raw);
}
