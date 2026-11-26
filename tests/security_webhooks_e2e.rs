//! Comprehensive security regression tests for Issue #58:
//! - Shared SSRF guard (`net_guard`), inbox rule webhook Admin-scope + allowlist + redirect blocking
//! - `HttpResendClient::download_bytes` SSRF, redirect, and bounded body cap enforcement
//! - `RspamdFilter` and `LlmTriageFilter` redirect blocking (no secret forwarding) + body cap
//! - Fail-closed `/webhooks/ses`, header-only secrets, TopicArn & S3 bucket allowlists,
//!   SNS `SigningCertURL` pinning & RSA-SHA1/SHA256 verification, and S3 path traversal guards
//! - Fail-closed `/webhooks/resend`, Svix `svix-id` replay protection, unmatched delivery drop,
//!   and `rfc_message_id` fallback status persistence
//! - Envelope-only multi-mailbox routing ignoring forged `X-Original-To`/`Delivered-To`/`Envelope-To`
//! - Attachment download XSS security headers (`Content-Disposition`, `nosniff`, `CSP: sandbox`)
//! - SMTP bare-CR dot-stuffing anti-smuggling and bounded `SmtpStream::read_line`

use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::{io::AsyncWriteExt, net::TcpListener};
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use nogml::{
    AppState,
    auth::{AuthScope, ScopedTokenConfig},
    build_router,
    config::{Config, SmtpTlsMode},
    error::AppError,
    filter::{
        FilterDecision, InboundFilter, InboundMessage,
        llm::{LlmTriageConfig, LlmTriageFilter},
        rspamd::{RspamdConfig, RspamdFilter},
    },
    models::{LABEL_INBOX, LABEL_SENT, LABEL_UNREAD},
    resend::{
        HttpResendClient, ResendClient,
        svix::{SvixReplayCache, sign_svix_payload},
    },
    storage::{MailStore, MemoryStore, NewAttachmentInput, NewMessageInput, SqliteStore},
    transport::{
        InboundEnvelope, MailTransport, OutboundMessage, SmtpTransport, dot_stuff_rfc5321,
        ingest_inbound_rfc2822_with_config,
        ses::{
            validate_s3_bucket_and_key, validate_sns_signing_cert_url, verify_sns_rsa_signature,
        },
    },
};

const TEST_WHSEC: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";

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

fn svix_request(body: &str, msg_id: &str, ts: i64, secret: &str) -> Request<Body> {
    let sig = sign_svix_payload(msg_id, ts, body.as_bytes(), secret).unwrap();
    Request::builder()
        .method(Method::POST)
        .uri("/webhooks/resend")
        .header("content-type", "application/json")
        .header("svix-id", msg_id)
        .header("svix-timestamp", ts.to_string())
        .header("svix-signature", sig)
        .body(Body::from(body.to_string()))
        .unwrap()
}

// ============================================================================
// 1. Inbox Rule Webhooks: Admin-only scope, SSRF blocks, allowlist, no redirects
// ============================================================================

#[tokio::test]
async fn rule_webhooks_enforce_admin_scope_ssrf_allowlist_and_no_redirects() {
    let mut cfg = Config::for_test();
    cfg.scoped_tokens = vec![
        ScopedTokenConfig {
            token: "tok_write".to_string(),
            mailbox_id: Some("agent@example.com".to_string()),
            scopes: vec![AuthScope::Read, AuthScope::Write],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_admin".to_string(),
            mailbox_id: Some("agent@example.com".to_string()),
            scopes: vec![AuthScope::Read, AuthScope::Write, AuthScope::Admin],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
    ];
    cfg.webhook_allowed_hosts = vec!["*.trusted.example".to_string()];

    let store = Arc::new(SqliteStore::open_in_memory(&cfg.user_email).unwrap());
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store, resend);
    let app = build_router(state);

    // Write-only token CAN create a label-only rule without webhook_url.
    let (st, label_rule) = send_json(
        &app,
        Method::POST,
        "/v1/rules",
        Some("tok_write"),
        Some(json!({
            "name": "Label Only",
            "match_query": "from:@vendor.example",
            "actions": { "add_labels": ["Vendor"] }
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "label-only rule failed: {label_rule}");
    let label_rule_id = label_rule["id"].as_str().unwrap().to_string();

    // Write-only token CANNOT create a rule with webhook_url.
    let (st, _) = send_json(
        &app,
        Method::POST,
        "/v1/rules",
        Some("tok_write"),
        Some(json!({
            "name": "Exfil Rule",
            "match_query": "is:unread",
            "actions": { "webhook_url": "https://hooks.trusted.example/steal" }
        })),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Write-only token CANNOT patch an existing rule to attach webhook_url.
    let (st, _) = send_json(
        &app,
        Method::PATCH,
        &format!("/v1/rules/{label_rule_id}"),
        Some("tok_write"),
        Some(json!({
            "actions": { "webhook_url": "https://hooks.trusted.example/steal" }
        })),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Admin token gets SSRF blocks for private/metadata/http/userinfo/disallowed hosts.
    for bad_url in [
        "http://hooks.trusted.example/in",
        "https://127.0.0.1/hook",
        "https://169.254.169.254/latest/meta-data/",
        "https://10.0.0.1/internal",
        "https://192.168.1.5/internal",
        "https://[::1]/hook",
        "https://[::ffff:127.0.0.1]/hook",
        "https://localhost/hook",
        "https://metadata.google.internal/hook",
        "https://user:pass@hooks.trusted.example/hook",
        "https://evil.example/not-allowlisted",
    ] {
        let (st, body) = send_json(
            &app,
            Method::POST,
            "/v1/rules",
            Some("tok_admin"),
            Some(json!({
                "name": "Blocked Hook",
                "match_query": "from:@stripe.com",
                "actions": { "webhook_url": bad_url }
            })),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::FORBIDDEN,
            "expected 403 ssrf_blocked for {bad_url}, got {st}: {body}"
        );
        assert_eq!(body["error"]["code"], "ssrf_blocked");
    }

    // Admin token CAN create a rule targeting an allowlisted public HTTPS host.
    let (st, ok_rule) = send_json(
        &app,
        Method::POST,
        "/v1/rules",
        Some("tok_admin"),
        Some(json!({
            "name": "Trusted Hook",
            "match_query": "from:@stripe.com",
            "actions": { "webhook_url": "https://hooks.trusted.example/events" }
        })),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::OK,
        "admin allowlisted rule failed: {ok_rule}"
    );
    let hook_rule_id = ok_rule["id"].as_str().unwrap().to_string();

    // Write-only token CANNOT widen match_query on an admin-owned webhook rule.
    let (st, _) = send_json(
        &app,
        Method::PATCH,
        &format!("/v1/rules/{hook_rule_id}"),
        Some("tok_write"),
        Some(json!({ "match_query": "is:unread" })),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Redirect blocking on rule webhook dispatch.
    let redirector = MockServer::start().await;
    let secret_target = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/redir"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", format!("{}/stolen", secret_target.uri())),
        )
        .expect(1)
        .mount(&redirector)
        .await;
    Mock::given(method("POST"))
        .and(path("/stolen"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&secret_target)
        .await;
    Mock::given(method("GET"))
        .and(path("/stolen"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&secret_target)
        .await;

    let mut dev_cfg = Config::for_test();
    dev_cfg.allow_private_endpoints = true;
    let dev_store = Arc::new(SqliteStore::open_in_memory(&dev_cfg.user_email).unwrap());
    let dev_resend = Arc::new(HttpResendClient::from_config(&dev_cfg));
    let dev_state = AppState::with_backends(dev_cfg, dev_store, dev_resend);
    let dev_app = build_router(dev_state.clone());

    let (st, _) = send_json(
        &dev_app,
        Method::POST,
        "/v1/rules",
        None,
        Some(json!({
            "name": "Redirect Rule",
            "match_query": "from:@redir.test",
            "actions": { "webhook_url": format!("{}/redir", redirector.uri()) }
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let _ = ingest_inbound_rfc2822_with_config(
        dev_state.store.as_ref(),
        &dev_state.events,
        dev_state.filter.as_ref(),
        InboundEnvelope {
            raw_rfc2822: b"From: a@redir.test\r\nTo: agent@example.com\r\nSubject: Hi\r\n\r\nBody"
                .to_vec(),
            source: "resend_inbound".to_string(),
            ..Default::default()
        },
        &dev_state.config,
    )
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(secret_target.received_requests().await.unwrap().is_empty());
}

// ============================================================================
// 2. HttpResendClient::download_bytes: SSRF, Redirect Block, and Size Cap
// ============================================================================

#[tokio::test]
async fn resend_download_bytes_blocks_ssrf_redirects_and_oversized_bodies() {
    let base_mock = MockServer::start().await;
    let other_internal = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/internal-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_string("secret"))
        .expect(0)
        .mount(&other_internal)
        .await;

    Mock::given(method("GET"))
        .and(path("/redirect-to-internal"))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "Location",
            format!("{}/internal-secret", other_internal.uri()),
        ))
        .expect(1)
        .mount(&base_mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/huge"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'A'; 512]))
        .expect(1)
        .mount(&base_mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/ok"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"hello".to_vec()))
        .expect(1)
        .mount(&base_mock)
        .await;

    let client = HttpResendClient::new(base_mock.uri(), Some("re_test".to_string()))
        .with_max_body_bytes(128);

    // Same-origin configured mock succeeds within cap.
    let ok = client
        .download_bytes(&format!("{}/ok", base_mock.uri()))
        .await
        .unwrap();
    assert_eq!(ok, b"hello");

    // Different localhost port (cross-origin private IP) is blocked by SSRF policy.
    let err = client
        .download_bytes(&format!("{}/internal-secret", other_internal.uri()))
        .await
        .unwrap_err();
    assert!(matches!(err, AppError::PolicyDenied { ref code, .. } if code == "ssrf_blocked"));

    // Cloud metadata / IPv4-mapped / HTTP non-matching URLs are blocked.
    for bad in [
        "http://169.254.169.254/latest/meta-data/",
        "https://[::ffff:127.0.0.1]/secret",
        "https://user:pass@cdn.example.com/file",
        "http://cdn.example.com/file",
    ] {
        let err = client.download_bytes(bad).await.unwrap_err();
        assert!(
            matches!(err, AppError::PolicyDenied { ref code, .. } if code == "ssrf_blocked"),
            "expected ssrf_blocked for {bad}, got {err:?}"
        );
    }

    // Redirect from same-origin mock to another internal host is blocked and NEVER followed.
    let err = client
        .download_bytes(&format!("{}/redirect-to-internal", base_mock.uri()))
        .await
        .unwrap_err();
    assert!(matches!(err, AppError::PolicyDenied { ref code, .. } if code == "ssrf_blocked"));
    assert!(other_internal.received_requests().await.unwrap().is_empty());

    // Oversized body exceeding max_body_bytes returns PayloadTooLarge.
    let err = client
        .download_bytes(&format!("{}/huge", base_mock.uri()))
        .await
        .unwrap_err();
    assert!(matches!(err, AppError::PayloadTooLarge(_)));
}

// ============================================================================
// 3. RspamdFilter & LlmTriageFilter: No Redirect Secret Forwarding + Body Cap
// ============================================================================

#[tokio::test]
async fn rspamd_and_llm_filters_disable_redirects_and_cap_response_size() {
    let rspamd_redir = MockServer::start().await;
    let llm_redir = MockServer::start().await;
    let attacker = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/steal"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&attacker)
        .await;
    Mock::given(method("GET"))
        .and(path("/steal"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&attacker)
        .await;

    Mock::given(method("POST"))
        .and(path("/checkv2"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("Location", format!("{}/steal", attacker.uri())),
        )
        .expect(1)
        .mount(&rspamd_redir)
        .await;

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("Location", format!("{}/steal", attacker.uri())),
        )
        .expect(1)
        .mount(&llm_redir)
        .await;

    let msg = InboundMessage {
        from: "sender@example.com".to_string(),
        to: vec!["agent@example.com".to_string()],
        subject: "Test".to_string(),
        text_body: "Body".to_string(),
        html_body: None,
        raw_rfc2822: b"From: sender@example.com\r\nSubject: Test\r\n\r\nBody".to_vec(),
        sender_ip: None,
        authentication_results: None,
        headers: vec![],
        source: "test".to_string(),
        provider_id: None,
    };

    let mut rcfg = RspamdConfig::new(rspamd_redir.uri());
    rcfg.password = Some("super-secret-rspamd-password".to_string());
    rcfg.fail_closed = true;
    let rspamd = RspamdFilter::new(rcfg);
    let decision = rspamd.evaluate(&msg).await.unwrap();
    assert!(
        matches!(decision, FilterDecision::Reject { ref reason } if reason.contains("redirect")),
        "expected fail-closed reject on redirect, got {decision:?}"
    );

    let llm = LlmTriageFilter::new(LlmTriageConfig {
        base_url: llm_redir.uri(),
        api_key: Some("sk-secret-llm-key".to_string()),
        model: "gpt-4o-mini".to_string(),
        timeout: Duration::from_secs(5),
        max_body_chars: 1000,
    });
    let llm_decision = llm.evaluate(&msg).await.unwrap();
    assert!(matches!(llm_decision, FilterDecision::Allow));

    // Attacker server received ZERO redirected requests (neither Password nor Authorization leaked).
    assert!(attacker.received_requests().await.unwrap().is_empty());

    // Oversized (> 2 MiB) responses are rejected cleanly without OOM.
    let oversized_server = MockServer::start().await;
    let big_body = vec![b'x'; 2 * 1024 * 1024 + 1024];
    Mock::given(method("POST"))
        .and(path("/checkv2"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(big_body.clone()))
        .expect(1)
        .mount(&oversized_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(big_body))
        .expect(1)
        .mount(&oversized_server)
        .await;

    let mut rcfg2 = RspamdConfig::new(oversized_server.uri());
    rcfg2.fail_closed = true;
    let d2 = RspamdFilter::new(rcfg2).evaluate(&msg).await.unwrap();
    assert!(matches!(d2, FilterDecision::Reject { .. }));

    let llm2 = LlmTriageFilter::new(LlmTriageConfig {
        base_url: oversized_server.uri(),
        api_key: None,
        model: "gpt-4o-mini".to_string(),
        timeout: Duration::from_secs(5),
        max_body_chars: 1000,
    });
    assert!(matches!(
        llm2.evaluate(&msg).await.unwrap(),
        FilterDecision::Allow
    ));
}

// ============================================================================
// 4. SES Webhook: Fail-closed, Header-only, Allowlists, SNS Cert/Sig, S3 Traversal
// ============================================================================

#[tokio::test]
async fn ses_webhook_fail_closed_header_only_allowlists_and_s3_traversal_guard() {
    let s3_mock = MockServer::start().await;
    let s3_redir_target = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/stolen"))
        .respond_with(ResponseTemplate::new(200).set_body_string("nope"))
        .expect(0)
        .mount(&s3_redir_target)
        .await;

    Mock::given(method("GET"))
        .and(path("/allowed-bucket/redirect.eml"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", format!("{}/stolen", s3_redir_target.uri())),
        )
        .expect(1)
        .mount(&s3_mock)
        .await;

    // 1. Fail closed (401) when ses_webhook_secret is unset and allow_insecure_webhooks=false.
    let closed_cfg = Config::for_test();
    let closed_store = Arc::new(MemoryStore::new(&closed_cfg.user_email));
    let closed_resend = Arc::new(HttpResendClient::from_config(&closed_cfg));
    let closed_app = build_router(AppState::with_backends(
        closed_cfg,
        closed_store,
        closed_resend,
    ));

    let raw_mail = b"From: alice@ext.test\r\nTo: agent@example.com\r\nSubject: Hi\r\nMessage-ID: <ses-fc-1@ext.test>\r\n\r\nHello";
    let ses_inline = json!({
        "notificationType": "Received",
        "mail": { "messageId": "ses-1", "destination": ["agent@example.com"] },
        "content": STANDARD.encode(raw_mail)
    });
    let sns_body = json!({
        "Type": "Notification",
        "MessageId": "sns-1",
        "TopicArn": "arn:aws:sns:us-east-1:123456789012:allowed-topic",
        "Message": ses_inline.to_string()
    })
    .to_string();

    let resp = closed_app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/webhooks/ses")
                .header("content-type", "application/json")
                .body(Body::from(sns_body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 2. Configured secret + TopicArn & S3 bucket allowlists.
    let mut cfg = Config::for_test();
    cfg.ses_webhook_secret = Some("top-ses-secret".to_string());
    cfg.ses_allowed_topic_arns =
        vec!["arn:aws:sns:us-east-1:123456789012:allowed-topic".to_string()];
    cfg.ses_allowed_s3_buckets = vec!["allowed-bucket".to_string()];
    cfg.ses_s3_endpoint = Some(s3_mock.uri());
    cfg.ses_access_key_id = Some("AKIA_TEST".to_string());
    cfg.ses_secret_access_key = Some("secret_test".to_string());

    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let app = build_router(AppState::with_backends(cfg, store, resend));

    // Query params ?secret= and ?token= MUST be rejected (401).
    for q in ["?secret=top-ses-secret", "?token=top-ses-secret"] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/webhooks/ses{q}"))
                    .header("content-type", "application/json")
                    .body(Body::from(sns_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // Disallowed TopicArn returns 403.
    let bad_topic = json!({
        "Type": "Notification",
        "MessageId": "sns-bad-topic",
        "TopicArn": "arn:aws:sns:us-east-1:999999999999:evil-topic",
        "Message": ses_inline.to_string()
    })
    .to_string();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/webhooks/ses")
                .header("x-nogml-webhook-secret", "top-ses-secret")
                .header("content-type", "application/json")
                .body(Body::from(bad_topic))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Forged SNS SigningCertURL (non-AWS host) is blocked with 403 ssrf_blocked.
    let forged_cert = json!({
        "Type": "Notification",
        "MessageId": "sns-forged",
        "TopicArn": "arn:aws:sns:us-east-1:123456789012:allowed-topic",
        "Timestamp": "2026-11-26T12:00:00.000Z",
        "SignatureVersion": "2",
        "Signature": "AAAA",
        "SigningCertURL": "https://evil.example.com/SimpleNotificationService-fake.pem",
        "Message": ses_inline.to_string()
    })
    .to_string();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/webhooks/ses")
                .header("authorization", "Bearer top-ses-secret")
                .header("content-type", "application/json")
                .body(Body::from(forged_cert))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Disallowed S3 bucket returns 403.
    let bad_bucket_msg = json!({
        "notificationType": "Received",
        "mail": { "messageId": "ses-bad-bkt", "destination": ["agent@example.com"] },
        "receipt": {
            "action": {
                "type": "S3",
                "bucketName": "other-secret-bucket",
                "objectKey": "inbox/1.eml"
            }
        }
    });
    let sns_bad_bkt = json!({
        "Type": "Notification",
        "MessageId": "sns-bkt",
        "TopicArn": "arn:aws:sns:us-east-1:123456789012:allowed-topic",
        "Message": bad_bucket_msg.to_string()
    })
    .to_string();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/webhooks/ses")
                .header("x-nogml-webhook-secret", "top-ses-secret")
                .header("content-type", "application/json")
                .body(Body::from(sns_bad_bkt))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // S3 path traversal segments (raw and percent-encoded) return 400 Bad Request.
    for bad_key in [
        "../other-bucket/secret.eml",
        "inbound/../secret.eml",
        "inbound/./msg.eml",
        "%2e%2e/secret.eml",
        "inbound/%2E%2E/secret.eml",
        "%252e%252e/secret.eml",
        "inbound/a%2f..%2fsecret.eml",
        "inbound\\..\\secret.eml",
    ] {
        let trav_msg = json!({
            "notificationType": "Received",
            "mail": { "messageId": "ses-trav", "destination": ["agent@example.com"] },
            "receipt": {
                "action": {
                    "type": "S3",
                    "bucketName": "allowed-bucket",
                    "objectKey": bad_key
                }
            }
        });
        let sns_trav = json!({
            "Type": "Notification",
            "MessageId": "sns-trav",
            "TopicArn": "arn:aws:sns:us-east-1:123456789012:allowed-topic",
            "Message": trav_msg.to_string()
        })
        .to_string();
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/webhooks/ses")
                    .header("x-nogml-webhook-secret", "top-ses-secret")
                    .header("content-type", "application/json")
                    .body(Body::from(sns_trav))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "expected 400 for S3 traversal key {bad_key}"
        );
    }

    // S3 redirect is rejected and NEVER forwards AWS SigV4 Authorization header to redirect target.
    let redir_msg = json!({
        "notificationType": "Received",
        "mail": { "messageId": "ses-redir", "destination": ["agent@example.com"] },
        "receipt": {
            "action": {
                "type": "S3",
                "bucketName": "allowed-bucket",
                "objectKey": "redirect.eml"
            }
        }
    });
    let sns_redir = json!({
        "Type": "Notification",
        "MessageId": "sns-redir",
        "TopicArn": "arn:aws:sns:us-east-1:123456789012:allowed-topic",
        "Message": redir_msg.to_string()
    })
    .to_string();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/webhooks/ses")
                .header("x-nogml-webhook-secret", "top-ses-secret")
                .header("content-type", "application/json")
                .body(Body::from(sns_redir))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        s3_redir_target
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );

    // Valid Authorization: Bearer header + allowlisted TopicArn succeeds.
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/webhooks/ses")
                .header("authorization", "Bearer top-ses-secret")
                .header("content-type", "application/json")
                .body(Body::from(sns_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[test]
fn sns_signing_cert_url_pinning_and_rsa_signature_verification() {
    // Valid AWS SNS SigningCertURLs pass.
    assert!(
        validate_sns_signing_cert_url(
            "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-1234abcd.pem"
        )
        .is_ok()
    );
    assert!(
        validate_sns_signing_cert_url(
            "https://sns.eu-west-2.amazonaws.com/SimpleNotificationService-9999.pem"
        )
        .is_ok()
    );

    // Invalid / spoofed / SSRF SigningCertURLs fail.
    for bad in [
        "http://sns.us-east-1.amazonaws.com/SimpleNotificationService-1.pem",
        "https://sns.us-east-1.amazonaws.com.evil.com/cert.pem",
        "https://evil.com/SimpleNotificationService-1.pem",
        "https://sns.us-east-1.amazonaws.com:8443/cert.pem",
        "https://sns.us-east-1.amazonaws.com/not-a-pem.txt",
        "https://sns.us-east-1.amazonaws.com/../secret.pem",
        "https://169.254.169.254/cert.pem",
        "https://sns.us.east.1.amazonaws.com/cert.pem",
    ] {
        assert!(
            validate_sns_signing_cert_url(bad).is_err(),
            "expected SigningCertURL rejection for {bad}"
        );
    }

    // S3 bucket name validation rejects traversal & invalid chars.
    assert!(validate_s3_bucket_and_key("..", "a/b.eml", &[]).is_err());
    assert!(validate_s3_bucket_and_key("my..bucket", "a/b.eml", &[]).is_err());
    assert!(validate_s3_bucket_and_key("valid-bucket", "2026/msg.eml", &[]).is_ok());

    // Public-only X.509 RSA-2048 certificate and signatures over canonical SNS string.
    const TEST_PUBLIC_CERT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIICyDCCAbACCQDlca/MPd5PmTANBgkqhkiG9w0BAQsFADAmMSQwIgYDVQQDDBtz
bnMudXMtZWFzdC0xLmFtYXpvbmF3cy5jb20wHhcNMjYxMTI2MTY0MjQ4WhcNMzYx
MTIzMTY0MjQ4WjAmMSQwIgYDVQQDDBtzbnMudXMtZWFzdC0xLmFtYXpvbmF3cy5j
b20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDtoKkFUB8TgXybFQQ5
48rkwwJPftCYJ9jiPkPqs8Vc+yi5rvyfkld2pElFpB+SPnrUjynt/HKd8eQ5Hbav
BDx/6cUcyyLrYgnbUhW6vZoufymxMe3QBq6mccdRrAN4YRf4qfXWkdkTCndmbBps
/AzZ3eJmChK/rHk1FMMcEYf7+BpmzrA8DHWqzMNM5N/W69bxAAFTsNSkPPUidZo+
EuEPEnMm5lqbOCHW+8R9aI9VY5Xbvrxq7SqFl8lTgoAtdL3YcWBHJUnXTPM3dvSa
+4zFp+3EjNn3rx56k308uoU49j/Q3H0ouPkvFmASaAK2BR8I+2SgSsQU5pe65QjQ
mUdHAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAHBS3cZIxdpJ+RRyuCFOJ3PYOL54
6yBiZb/gIAx86kjDFZyJylt26nR0q9vEC/FYnh+sc1+nf4z37Wu197ZF7LeFLlrA
pN4NHJRPSqOqeYLFCY+BVWB21xnvA1iHRo3VBrqTUSw8jV/dg+YjaC/HIAnZaOO7
4SF4BZ0pL0tKEIH4vrRCgcBzjCn85vUbBR7EkgYKWZIdgN8Nze2tpBqSeYwls8rb
FBsZU/yWJbEd9F0MNAES/4QwLpTjFdlwAZdU8MkBixwAPb9sm+XHf4y5UIHW2LBp
4wpZXB+sU9lFIjdwIcqflrV0Op3ETU5ZXy1sI/VG1WU0CmDWe0XxX25OK6w=
-----END CERTIFICATE-----";

    const SIG_SHA256: &str = "jn2KPWcYQiZbKLsGCbvzFUR0Ed9jlDV6xppF72/DsnJ2cQeNqd0dTmLZdijj1w7eVHHXt3yonbxjouC+m+8dnICbh9Js85PFJA4c6eJuFopU5sb9I/wt/FxdyYMjcyJcsh7db9kSvNNynFf2STwUHYGG6ge+OhkjB6kiIPNNLNH84GzP2mR/cQNNMIcj3YinQifz0eUeHZSzxF13LbV5O+9Vq7SLOXikmAO8Gu05RGUbRXbcX8GRwuU0GmWrdN/4SgT0MSwTek2VpoIgA9TNDC0bLNTAqbStaleyAEkYA1pJL/kiWsq1Ns3J5Xw9SGkVhp9OJGE4KPf0OwQHQQq00w==";
    const SIG_SHA1: &str = "BWGqW3ME+egxCPpcNN3s0KcETebsgndAQ4d504zoxbW3l+YQOx+uTntYab6Xny1FkLZMjVnNIjfJrbxs2loDZzHwoyqpQ+5tbJodDIANck485Lnya7QxY+h7+WvXLgtwshHDloeaT5X29lsY+/2EuN+5K+crV2f83jqeg6K9grO0H0X2ux2q2xRXSmK5PAqRbSgHyRm8ZeunoPexnXntq9hHTgh2/hAdI0n8Vd0aa2yHt064JwOIxNsLVccYkhpYH6EU5vbtghRTebIRTXilD70tzD9SbKWh5nfq3V9xpeEKekmz8xhy2MOeDyYiqZKvZR2TD19Aw71nyChmVU8gjQ==";

    let canonical = concat!(
        "Message\n",
        "{\"notificationType\":\"Received\"}\n",
        "MessageId\n",
        "sns-msg-test-1\n",
        "Timestamp\n",
        "2026-11-26T12:00:00.000Z\n",
        "TopicArn\n",
        "arn:aws:sns:us-east-1:123456789012:ses-in\n",
        "Type\n",
        "Notification\n"
    );

    // Valid RSA-SHA256 (SignatureVersion "2") and RSA-SHA1 (SignatureVersion "1") pass.
    verify_sns_rsa_signature(TEST_PUBLIC_CERT_PEM, "2", SIG_SHA256, canonical.as_bytes())
        .expect("valid RSA-SHA256 SNS signature should verify");
    verify_sns_rsa_signature(TEST_PUBLIC_CERT_PEM, "1", SIG_SHA1, canonical.as_bytes())
        .expect("valid RSA-SHA1 SNS signature should verify");

    // Tampered payload, wrong version, or invalid signature fail.
    let tampered = canonical.replace("Received", "Tampered");
    assert!(
        verify_sns_rsa_signature(TEST_PUBLIC_CERT_PEM, "2", SIG_SHA256, tampered.as_bytes())
            .is_err()
    );
    assert!(
        verify_sns_rsa_signature(TEST_PUBLIC_CERT_PEM, "2", SIG_SHA1, canonical.as_bytes())
            .is_err()
    );
    assert!(
        verify_sns_rsa_signature(TEST_PUBLIC_CERT_PEM, "3", SIG_SHA256, canonical.as_bytes())
            .is_err()
    );
}

// ============================================================================
// 5. Resend Webhook: Fail-closed, Svix Replay Protection, Unmatched Drop & Fallback
// ============================================================================

#[tokio::test]
async fn resend_webhook_svix_replay_unmatched_drop_and_rfc_message_id_fallback() {
    let mut cfg = Config::for_test();
    cfg.resend_webhook_secret = Some(TEST_WHSEC.to_string());

    let store = Arc::new(SqliteStore::open_in_memory(&cfg.user_email).unwrap());
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store.clone(), resend);
    let mut rx = state.events.subscribe();
    let app = build_router(state.clone());

    // Seed two sent messages: one with resend_id, one matching only via rfc822_message_id.
    let m1 = store
        .insert_message(NewMessageInput {
            id: Some("sent_1".to_string()),
            thread_id: None,
            label_ids: vec![LABEL_SENT.to_string()],
            raw_rfc2822: b"From: agent@example.com\r\nTo: a@b.test\r\nSubject: S1\r\n\r\nHi"
                .to_vec(),
            snippet: "Hi".to_string(),
            internal_date_ms: 1_700_000_000_000,
            subject: "S1".to_string(),
            from_addr: "agent@example.com".to_string(),
            to_addrs: vec!["a@b.test".to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: "Hi".to_string(),
            html_body: None,
            rfc822_message_id: None,
            in_reply_to: None,
            references_header: None,
            resend_id: Some("re_out_1".to_string()),
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "local".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: vec![],
        })
        .await
        .unwrap();

    let m2 = store
        .insert_message(NewMessageInput {
            id: Some("sent_2".to_string()),
            thread_id: None,
            label_ids: vec![LABEL_SENT.to_string()],
            raw_rfc2822: b"From: agent@example.com\r\nTo: c@d.test\r\nSubject: S2\r\nMessage-ID: <fallback-deliv@example.com>\r\n\r\nHi".to_vec(),
            snippet: "Hi".to_string(),
            internal_date_ms: 1_700_000_001_000,
            subject: "S2".to_string(),
            from_addr: "agent@example.com".to_string(),
            to_addrs: vec!["c@d.test".to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: "Hi".to_string(),
            html_body: None,
            rfc822_message_id: Some("<fallback-deliv@example.com>".to_string()),
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

    let now = chrono::Utc::now().timestamp();

    // 1. Initial signed `email.delivered` for m1 -> recorded.
    let delivered_body = json!({
        "type": "email.delivered",
        "created_at": "2026-11-26T00:00:00Z",
        "data": { "email_id": "re_out_1" }
    })
    .to_string();
    let r1 = app
        .clone()
        .oneshot(svix_request(
            &delivered_body,
            "svix_replay_1",
            now,
            TEST_WHSEC,
        ))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::OK);
    assert_eq!(
        store
            .get_message(&m1.id)
            .await
            .unwrap()
            .unwrap()
            .delivery_status
            .as_deref(),
        Some("delivered")
    );
    assert!(rx.try_recv().is_ok());

    // 2. Newer signed `email.bounced` with a fresh svix-id -> updates status to bounced.
    let bounced_body = json!({
        "type": "email.bounced",
        "created_at": "2026-11-26T00:01:00Z",
        "data": { "email_id": "re_out_1" }
    })
    .to_string();
    let r2 = app
        .clone()
        .oneshot(svix_request(
            &bounced_body,
            "svix_replay_2",
            now,
            TEST_WHSEC,
        ))
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::OK);
    assert_eq!(
        store
            .get_message(&m1.id)
            .await
            .unwrap()
            .unwrap()
            .delivery_status
            .as_deref(),
        Some("bounced")
    );
    assert!(rx.try_recv().is_ok());

    // 3. Replaying `svix_replay_1` MUST return 200 {"duplicate": true}, publish NO event,
    //    and MUST NOT overwrite `bounced` back to `delivered`!
    let replay_resp = app
        .clone()
        .oneshot(svix_request(
            &delivered_body,
            "svix_replay_1",
            now,
            TEST_WHSEC,
        ))
        .await
        .unwrap();
    assert_eq!(replay_resp.status(), StatusCode::OK);
    let replay_json: Value =
        serde_json::from_slice(&replay_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(replay_json["duplicate"], true);
    assert_eq!(
        store
            .get_message(&m1.id)
            .await
            .unwrap()
            .unwrap()
            .delivery_status
            .as_deref(),
        Some("bounced"),
        "replayed webhook must not overwrite newer delivery_status"
    );
    assert!(
        rx.try_recv().is_err(),
        "replayed webhook must not emit EventBus event"
    );

    // 4. Unmatched delivery event MUST be dropped without publishing onto primary mailbox EventBus.
    let unmatched_body = json!({
        "type": "email.bounced",
        "created_at": "2026-11-26T00:02:00Z",
        "data": { "email_id": "re_nonexistent_999" }
    })
    .to_string();
    let unmatched_resp = app
        .clone()
        .oneshot(svix_request(
            &unmatched_body,
            "svix_unmatched_1",
            now,
            TEST_WHSEC,
        ))
        .await
        .unwrap();
    assert_eq!(unmatched_resp.status(), StatusCode::OK);
    let unmatched_json: Value = serde_json::from_slice(
        &unmatched_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert_eq!(unmatched_json["status"], "ignored");
    assert!(
        rx.try_recv().is_err(),
        "unmatched delivery event must NOT publish onto primary mailbox EventBus"
    );

    // 5. Fallback match via rfc_message_id MUST also persist delivery_status in storage.
    let fallback_body = json!({
        "type": "email.delivered",
        "created_at": "2026-11-26T00:03:00Z",
        "data": {
            "email_id": "re_untracked_alias",
            "message_id": "<fallback-deliv@example.com>"
        }
    })
    .to_string();
    let fb_resp = app
        .oneshot(svix_request(
            &fallback_body,
            "svix_fallback_1",
            now,
            TEST_WHSEC,
        ))
        .await
        .unwrap();
    assert_eq!(fb_resp.status(), StatusCode::OK);
    assert_eq!(
        store
            .get_message(&m2.id)
            .await
            .unwrap()
            .unwrap()
            .delivery_status
            .as_deref(),
        Some("delivered"),
        "rfc_message_id fallback match must persist delivery_status"
    );
    assert!(rx.try_recv().is_ok());

    // 6. SvixReplayCache TTL expiry & capacity bound unit check.
    let cache = SvixReplayCache::with_ttl_and_capacity(Duration::from_millis(40), 2);
    assert!(cache.check_and_record("id1"));
    assert!(!cache.check_and_record("id1"));
    assert!(cache.check_and_record("id2"));
    assert!(cache.check_and_record("id3")); // capacity bounded at 2
    std::thread::sleep(Duration::from_millis(60));
    assert!(cache.check_and_record("id3")); // expired -> accepted again
}

// ============================================================================
// 6. Envelope-Only Multi-Mailbox Routing (SES & Resend)
// ============================================================================

#[tokio::test]
async fn multi_mailbox_webhooks_ignore_forged_mime_routing_headers() {
    let resend_mock = MockServer::start().await;

    let forged_mime = concat!(
        "From: attacker@evil.test\r\n",
        "To: bob@example.com\r\n",
        "Cc: bob@example.com\r\n",
        "X-Original-To: bob@example.com\r\n",
        "Delivered-To: bob@example.com\r\n",
        "Envelope-To: bob@example.com\r\n",
        "Subject: Cross-Mailbox Spoof Attempt\r\n",
        "Message-ID: <spoof-resend-1@evil.test>\r\n",
        "\r\n",
        "Spoofed headers must not inject into Bob!\r\n"
    );

    Mock::given(method("GET"))
        .and(path("/emails/receiving/re_spoof_1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "re_spoof_1",
            "from": "attacker@evil.test",
            "to": ["alice@example.com", "bob@example.com"],
            "headers": {
                "X-Original-To": "bob@example.com",
                "Delivered-To": "bob@example.com",
                "Envelope-To": "bob@example.com"
            },
            "subject": "Cross-Mailbox Spoof Attempt",
            "raw": { "download_url": format!("{}/raw/spoof.eml", resend_mock.uri()) }
        })))
        .mount(&resend_mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/raw/spoof.eml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(forged_mime))
        .mount(&resend_mock)
        .await;

    let mut cfg = Config::for_test();
    cfg.user_email = "alice@example.com".to_string();
    cfg.mailboxes = vec!["bob@example.com".to_string()];
    cfg.resend_base_url = resend_mock.uri();
    cfg.resend_api_key = Some("re_key".to_string());
    cfg.resend_webhook_secret = Some(TEST_WHSEC.to_string());
    cfg.ses_webhook_secret = Some("ses-multi-secret".to_string());

    let store = Arc::new(SqliteStore::open_in_memory(&cfg.user_email).unwrap());
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store, resend);
    let app = build_router(state.clone());

    // 1. Resend webhook with envelope data.to = [alice@example.com] only, despite forged MIME headers for bob.
    let now = chrono::Utc::now().timestamp();
    let resend_payload = json!({
        "type": "email.received",
        "created_at": "2026-11-26T00:00:00Z",
        "data": {
            "email_id": "re_spoof_1",
            "from": "attacker@evil.test",
            "to": ["alice@example.com"],
            "subject": "Cross-Mailbox Spoof Attempt",
            "message_id": "<spoof-resend-1@evil.test>"
        }
    })
    .to_string();
    let resp = app
        .clone()
        .oneshot(svix_request(
            &resend_payload,
            "svix_spoof_1",
            now,
            TEST_WHSEC,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["mailbox_id"], "alice@example.com");

    // 2. SES webhook with mail.destination = [alice@example.com] only, despite forged MIME headers for bob.
    let ses_forged_mime =
        forged_mime.replace("<spoof-resend-1@evil.test>", "<spoof-ses-1@evil.test>");
    let ses_notification = json!({
        "notificationType": "Received",
        "mail": {
            "source": "attacker@evil.test",
            "messageId": "ses-spoof-1",
            "destination": ["alice@example.com"],
            "commonHeaders": {
                "from": ["attacker@evil.test"],
                "to": ["bob@example.com"],
                "cc": ["bob@example.com"],
                "subject": "SES Spoof"
            }
        },
        "content": STANDARD.encode(ses_forged_mime.as_bytes())
    });
    let sns_body = json!({
        "Type": "Notification",
        "MessageId": "sns-spoof-1",
        "Message": ses_notification.to_string()
    })
    .to_string();

    let ses_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/webhooks/ses")
                .header("x-nogml-webhook-secret", "ses-multi-secret")
                .header("content-type", "application/json")
                .body(Body::from(sns_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ses_resp.status(), StatusCode::OK);

    // Alice has 2 messages; Bob MUST have 0 messages!
    let alice_msgs = state
        .for_mailbox("alice@example.com")
        .store
        .list_messages(&Default::default())
        .await
        .unwrap();
    let bob_msgs = state
        .for_mailbox("bob@example.com")
        .store
        .list_messages(&Default::default())
        .await
        .unwrap();
    assert_eq!(alice_msgs.messages.len(), 2);
    assert!(
        bob_msgs.messages.is_empty(),
        "forged MIME headers injected messages into Bob's mailbox: {:?}",
        bob_msgs.messages
    );

    // 3. SES webhook routed via receipt.recipients = [bob@example.com] lands in Bob's mailbox only.
    let ses_bob_mime = b"From: partner@ok.test\r\nTo: hidden@ok.test\r\nSubject: Via Receipt Recipients\r\nMessage-ID: <ses-rcpt-bob@ok.test>\r\n\r\nHello Bob";
    let ses_bob_notif = json!({
        "notificationType": "Received",
        "mail": { "messageId": "ses-bob-rcpt" },
        "receipt": { "recipients": ["bob@example.com"] },
        "content": STANDARD.encode(ses_bob_mime)
    });
    let sns_bob = json!({
        "Type": "Notification",
        "MessageId": "sns-bob-1",
        "Message": ses_bob_notif.to_string()
    })
    .to_string();
    let bob_resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/webhooks/ses")
                .header("x-nogml-webhook-secret", "ses-multi-secret")
                .header("content-type", "application/json")
                .body(Body::from(sns_bob))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bob_resp.status(), StatusCode::OK);
    assert_eq!(
        state
            .for_mailbox("bob@example.com")
            .store
            .list_messages(&Default::default())
            .await
            .unwrap()
            .messages
            .len(),
        1
    );
}

// ============================================================================
// 7. Attachment Download XSS Security Headers
// ============================================================================

#[tokio::test]
async fn attachment_download_always_sets_xss_hardening_headers() {
    let cfg = Config::for_test();
    let store = Arc::new(SqliteStore::open_in_memory(&cfg.user_email).unwrap());
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store.clone(), resend);
    let app = build_router(state);

    let msg = store
        .insert_message(NewMessageInput {
            id: Some("msg_xss_1".to_string()),
            thread_id: None,
            label_ids: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            raw_rfc2822: b"From: a@b.test\r\nTo: agent@example.com\r\nSubject: XSS\r\n\r\nHi"
                .to_vec(),
            snippet: "Hi".to_string(),
            internal_date_ms: 1_700_000_000_000,
            subject: "XSS".to_string(),
            from_addr: "a@b.test".to_string(),
            to_addrs: vec!["agent@example.com".to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: "Hi".to_string(),
            html_body: None,
            rfc822_message_id: None,
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "resend_inbound".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: vec![
                NewAttachmentInput {
                    part_id: "att-1".to_string(),
                    filename: None,
                    content_type: "text/html".to_string(),
                    content_id: None,
                    data: b"<script>alert(1)</script>".to_vec(),
                },
                NewAttachmentInput {
                    part_id: "att-2".to_string(),
                    filename: Some("diagram.svg".to_string()),
                    content_type: "image/svg+xml".to_string(),
                    content_id: None,
                    data: b"<svg onload=alert(1)></svg>".to_vec(),
                },
            ],
        })
        .await
        .unwrap();

    let metas = store.list_attachment_meta(&msg.id).await.unwrap();
    let unnamed = metas.iter().find(|m| m.filename.is_none()).unwrap();
    let named = metas
        .iter()
        .find(|m| m.filename.as_deref() == Some("diagram.svg"))
        .unwrap();

    // Unnamed HTML attachment MUST still include Content-Disposition: attachment + nosniff + sandbox.
    let resp_unnamed = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/messages/{}/attachments/{}",
                    msg.id, unnamed.id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_unnamed.status(), StatusCode::OK);
    assert_eq!(
        resp_unnamed
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .unwrap(),
        "attachment"
    );
    assert_eq!(
        resp_unnamed
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .unwrap(),
        "nosniff"
    );
    assert_eq!(
        resp_unnamed
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap(),
        "sandbox"
    );

    // Named SVG attachment includes filename + nosniff + sandbox.
    let resp_named = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/messages/{}/attachments/{}", msg.id, named.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_named.status(), StatusCode::OK);
    assert_eq!(
        resp_named
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .unwrap(),
        "attachment; filename=\"diagram.svg\""
    );
    assert_eq!(
        resp_named
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .unwrap(),
        "nosniff"
    );
    assert_eq!(
        resp_named
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap(),
        "sandbox"
    );
}

// ============================================================================
// 8. SMTP Bare-CR Smuggling Prevention & Bounded Server Line Read
// ============================================================================

#[test]
fn smtp_dot_stuffing_normalizes_bare_cr_to_prevent_smuggling() {
    let smuggle = b"Subject: Test\r\n\r\nhello\r.\r\nMAIL FROM:<evil@attacker.test>\r\n";
    let stuffed = dot_stuff_rfc5321(smuggle);
    assert_eq!(
        stuffed,
        b"Subject: Test\r\n\r\nhello\r\n..\r\nMAIL FROM:<evil@attacker.test>\r\n.\r\n"
    );

    // Verify no bare CR or bare LF remains anywhere in the wire output.
    for i in 0..stuffed.len() {
        if stuffed[i] == b'\r' {
            assert_eq!(
                stuffed.get(i + 1),
                Some(&b'\n'),
                "bare CR found at offset {i}"
            );
        }
        if stuffed[i] == b'\n' {
            assert!(
                i > 0 && stuffed[i - 1] == b'\r',
                "bare LF found at offset {i}"
            );
        }
    }

    // Multiple bare CR / LF dot-smuggling combinations.
    assert_eq!(
        dot_stuff_rfc5321(b"a\r.b\nc\r.\r"),
        b"a\r\n..b\r\nc\r\n..\r\n.\r\n"
    );
}

#[tokio::test]
async fn smtp_stream_bounds_overlong_server_response_line() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            // Send 128 KiB with no newline (exceeds 64 KiB MAX_SMTP_LINE_BYTES).
            let mut junk = b"220 ".to_vec();
            junk.extend(std::iter::repeat_n(b'A', 128 * 1024));
            let _ = socket.write_all(&junk).await;
            let _ = socket.shutdown().await;
        }
    });

    let mut cfg = Config::for_test();
    cfg.smtp_host = "127.0.0.1".to_string();
    cfg.smtp_port = port;
    cfg.smtp_tls_mode = SmtpTlsMode::None;

    let transport = SmtpTransport::from_config(&cfg).unwrap();
    let err = transport
        .send(
            &OutboundMessage {
                from: "agent@example.com".to_string(),
                to: vec!["dest@example.com".to_string()],
                subject: "Hi".to_string(),
                text: Some("Body".to_string()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, AppError::Upstream { status: 502, ref message } if message.contains("size limit")),
        "expected bounded SMTP line size limit error, got {err:?}"
    );
}
