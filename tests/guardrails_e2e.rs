//! End-to-end tests for Issue #38 agent guardrails:
//! - `FirstContactPolicy` (HTTP 202 `HoldForApproval` -> approve -> HTTP 200 on repeat/reply, multi-mailbox isolation)
//! - `DlpOutboundPolicy` (`Deny` -> 403, `Hold` -> 202, zero raw secret leakage)
//! - `OutboundPolicyChain` (`dry_run` policy check aggregation, capabilities reporting, TOML parsing)
//! - HTML tracking-pixel stripping and `CompactMessage.links` `domain_mismatch` inspection.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
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
    config::{Config, DlpAction, TomlConfig},
    error::AppResult,
    mime::{ComposeEmailInput, build_rfc2822, encode_base64url},
    models::LABEL_INBOX,
    resend::HttpResendClient,
    storage::{MailStore, MemoryStore, NewAttachmentInput, NewMessageInput},
    transport::{MailTransport, OutboundMessage, SendOutcome, TransportCapabilities},
};

type SentLog = Arc<Mutex<Vec<(OutboundMessage, Option<String>)>>>;

struct RecordingTransport {
    sent: SentLog,
}

impl RecordingTransport {
    fn new() -> (Self, SentLog) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (Self { sent: sent.clone() }, sent)
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
        let mut guard = self.sent.lock().unwrap();
        guard.push((msg.clone(), idempotency_key.map(str::to_string)));
        let n = guard.len();
        Ok(SendOutcome {
            provider: "recording_test".to_string(),
            provider_message_id: format!("tx_{n}"),
        })
    }
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
    let req = if let Some(json_body) = body {
        builder
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&json_body).unwrap()))
            .unwrap()
    } else {
        builder.body(Body::empty()).unwrap()
    };

    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes).to_string() }));
    (status, parsed)
}

fn build_test_app(cfg: Config) -> (Router, AppState, SentLog) {
    let store: Arc<dyn MailStore> = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let (transport, sent_log) = RecordingTransport::new();
    let state = AppState::with_backends(cfg, store, resend).with_transport(Arc::new(transport));
    let router = build_router(state.clone());
    (router, state, sent_log)
}

#[tokio::test]
async fn e2e_first_contact_approval_gate_allows_after_prior_sent_and_isolates_mailboxes() {
    let mut cfg = Config::for_test();
    cfg.user_email = "alice@example.com".to_string();
    cfg.mailboxes = vec!["bob@example.com".to_string()];
    cfg.first_contact_approval = true;
    cfg.scoped_tokens = vec![
        ScopedTokenConfig {
            token: "tok_alice".to_string(),
            mailbox_id: Some("alice@example.com".to_string()),
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
            token: "tok_bob".to_string(),
            mailbox_id: Some("bob@example.com".to_string()),
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
    ];

    let (app, _state, sent_log) = build_test_app(cfg);

    // 0. Capabilities report active chain and first_contact_approval=true.
    let (status, caps) = send_json(&app, "GET", "/v1/capabilities", Some("tok_alice"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(caps["safety"]["first_contact_approval"], json!(true));
    assert_eq!(caps["backends"]["outbound_policy"], json!("chain"));
    assert_eq!(
        caps["active_outbound_policies"],
        json!(["config", "first_contact"])
    );

    // 1. First email from Alice to unknown external recipient triggers HTTP 202 HoldForApproval.
    let (status, held) = send_json(
        &app,
        "POST",
        "/v1/messages/send",
        Some("tok_alice"),
        Some(json!({
            "to": ["partner@external.example"],
            "subject": "Introduction",
            "text": "Nice to meet you."
        })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(held["status"], json!("pending_approval"));
    assert!(
        held["reason"]
            .as_str()
            .unwrap()
            .contains("First-contact recipient requires approval: partner@external.example")
    );
    assert!(sent_log.lock().unwrap().is_empty());

    // 2. Human approves the first-contact send -> delivers and records contact sent_count=1.
    let approval_id = held["approval_id"].as_str().unwrap().to_string();
    let (status, approved) = send_json(
        &app,
        "POST",
        &format!("/v1/approvals/{approval_id}/approve"),
        Some("tok_alice"),
        Some(json!({ "note": "Verified partner" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(approved["status"], json!("approved"));
    assert_eq!(sent_log.lock().unwrap().len(), 1);

    // 3. Subsequent send from Alice to partner@external.example succeeds immediately (HTTP 200).
    let (status, second) = send_json(
        &app,
        "POST",
        "/v1/messages/send",
        Some("tok_alice"),
        Some(json!({
            "to": ["partner@external.example"],
            "subject": "Follow-up",
            "text": "Following up on our intro."
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["status"], json!("sent"));
    assert_eq!(sent_log.lock().unwrap().len(), 2);

    // 4. CC'ing a brand new external recipient still triggers HoldForApproval.
    let (status, held_cc) = send_json(
        &app,
        "POST",
        "/v1/messages/send",
        Some("tok_alice"),
        Some(json!({
            "to": ["partner@external.example"],
            "cc": ["newcc@external.example"],
            "subject": "Looping in colleague",
            "text": "Adding a colleague."
        })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert!(
        held_cc["reason"]
            .as_str()
            .unwrap()
            .contains("newcc@external.example")
    );
    assert_eq!(sent_log.lock().unwrap().len(), 2);

    // 5. Mailbox isolation: Bob has never emailed partner@external.example, so Bob is held (202).
    let (status, bob_held) = send_json(
        &app,
        "POST",
        "/v1/messages/send",
        Some("tok_bob"),
        Some(json!({
            "to": ["partner@external.example"],
            "subject": "Hi from Bob",
            "text": "First email from Bob."
        })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(bob_held["status"], json!("pending_approval"));
    assert_eq!(sent_log.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn e2e_dlp_outbound_policy_blocks_and_holds_secrets_without_echoing_raw_values() {
    let aws_key = format!("AKIA{}", "IOSFODNN7EXAMPLE");
    let gh_token = format!("ghp_{}", "a1B2c3D4e5F6g7H8i9J0k1L2");
    let resend_key = format!("re_{}", "AbCdEf1234567890_XyZwVu");
    let openai_key = format!("sk-{}", "proj1234567890abcdefghij");
    let private_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA";
    let ssn = "123-45-6789";
    let card = "4111-1111-1111-1111";

    // Part A: dlp_action = Deny -> HTTP 403, transport never called, secret never echoed.
    let mut cfg_deny = Config::for_test();
    cfg_deny.dlp_action = DlpAction::Deny;
    let (app_deny, _state_deny, sent_deny) = build_test_app(cfg_deny);

    let cases: Vec<(&str, String, &str)> = vec![
        (
            "aws",
            format!("Use key {aws_key} to access S3"),
            "aws_access_key_id",
        ),
        ("github", format!("Token: {gh_token}"), "github_token"),
        (
            "resend",
            format!("Resend key: {resend_key}"),
            "resend_api_key",
        ),
        ("openai", format!("API key: {openai_key}"), "secret_api_key"),
        ("privkey", private_key.to_string(), "private_key_block"),
        ("ssn", format!("Employee SSN is {ssn}."), "us_ssn"),
        ("card", format!("Charge card {card} please."), "credit_card"),
    ];

    for (label, body, expected_rule) in &cases {
        let (status, resp) = send_json(
            &app_deny,
            "POST",
            "/v1/messages/send",
            None,
            Some(json!({
                "to": ["recipient@example.com"],
                "subject": format!("Test {label}"),
                "text": body,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "case {label} should be 403");
        let resp_str = resp.to_string();
        assert!(
            resp_str.contains(expected_rule),
            "case {label} should report rule {expected_rule}, got {resp_str}"
        );
        // Never echo any raw secret back in the HTTP response!
        for secret in [&aws_key, &gh_token, &resend_key, &openai_key] {
            assert!(
                !resp_str.contains(secret),
                "raw secret leaked in response for {label}: {resp_str}"
            );
        }
        assert!(!resp_str.contains(ssn), "raw SSN leaked: {resp_str}");
        assert!(!resp_str.contains(card), "raw card leaked: {resp_str}");
        assert!(
            !resp_str.contains("b3BlbnNzaC1rZXktdjEAAAAA"),
            "raw private key material leaked: {resp_str}"
        );
    }
    assert!(sent_deny.lock().unwrap().is_empty());

    // Attachment filename containing a secret is blocked on Gmail send too.
    let raw_mime = build_rfc2822(&ComposeEmailInput {
        from: "agent@example.com".to_string(),
        to: vec!["recipient@example.com".to_string()],
        subject: "Clean subject".to_string(),
        text: Some("Clean body".to_string()),
        attachments: vec![NewAttachmentInput {
            part_id: String::new(),
            filename: Some(format!("backup-{aws_key}.txt")),
            content_type: "text/plain".to_string(),
            content_id: None,
            data: b"safe attachment bytes".to_vec(),
        }],
        ..Default::default()
    })
    .unwrap();
    let (status, gmail_resp) = send_json(
        &app_deny,
        "POST",
        "/gmail/v1/users/me/messages/send",
        None,
        Some(json!({ "raw": encode_base64url(&raw_mime) })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let gmail_str = gmail_resp.to_string();
    assert!(gmail_str.contains("aws_access_key_id"));
    assert!(!gmail_str.contains(&aws_key));
    assert!(sent_deny.lock().unwrap().is_empty());

    // Audit log also must NOT contain the raw secret.
    let (status, audit) = send_json(&app_deny, "GET", "/v1/audit?action=send", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let audit_str = audit.to_string();
    assert!(!audit_str.contains(&aws_key));
    assert!(!audit_str.contains(&gh_token));
    assert!(!audit_str.contains(ssn));
    assert!(!audit_str.contains(card));

    // Clean message passes DLP and sends cleanly (HTTP 200).
    let (status, ok_resp) = send_json(
        &app_deny,
        "POST",
        "/v1/messages/send",
        None,
        Some(json!({
            "to": ["recipient@example.com"],
            "subject": "Weekly status",
            "text": "Everything is on track. Order 12345 at 1700000000006."
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ok_resp["status"], json!("sent"));
    assert_eq!(sent_deny.lock().unwrap().len(), 1);

    // Part B: dlp_action = Hold + first_contact_approval = true -> dry_run aggregates all checks
    // and DLP match returns HTTP 202 HoldForApproval without leaking the secret.
    let mut cfg_hold = Config::for_test();
    cfg_hold.dlp_action = DlpAction::Hold;
    cfg_hold.first_contact_approval = true;
    let (app_hold, _state_hold, sent_hold) = build_test_app(cfg_hold);

    let (status, dry) = send_json(
        &app_hold,
        "POST",
        "/v1/messages/send",
        None,
        Some(json!({
            "to": ["someone@external.example"],
            "subject": "Leak test",
            "text": format!("Here is {gh_token}"),
            "dry_run": true
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rules: Vec<&str> = dry["policy_checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["rule"].as_str())
        .collect();
    assert!(rules.contains(&"max_send_recipients"));
    assert!(rules.contains(&"dlp_scan"));
    assert!(rules.contains(&"first_contact_approval"));
    assert!(!dry.to_string().contains(&gh_token));

    let (status, held) = send_json(
        &app_hold,
        "POST",
        "/v1/messages/send",
        None,
        Some(json!({
            "to": ["someone@external.example"],
            "subject": "Leak test",
            "text": format!("Here is {gh_token}")
        })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(held["status"], json!("pending_approval"));
    assert!(held["reason"].as_str().unwrap().contains("github_token"));
    assert!(!held.to_string().contains(&gh_token));
    assert!(sent_hold.lock().unwrap().is_empty());
}

#[tokio::test]
async fn e2e_html_tracking_pixel_stripping_and_link_domain_mismatch_inspection() {
    let cfg = Config::for_test();
    let (app, state, _sent_log) = build_test_app(cfg);

    let html_body = concat!(
        "<html><body>",
        r#"<p>Urgent: verify at <a href="https://evil.example/login">https://bank.example/verify</a>.</p>"#,
        r#"<p>Legit docs: <a href="https://www.bank.example/docs">https://bank.example/docs</a> and <a href="https://help.example.org">Help Center</a>.</p>"#,
        r#"<img src="https://cdn.example.com/logo.png" width="240" height="80" alt="Logo">"#,
        r#"<img src="https://track.example.com/pixel.gif" width="1" height="1" alt="">"#,
        r#"<img src="https://track.example.com/hidden.png" style="display:none;width:1px;height:1px">"#,
        "</body></html>"
    );

    let stored = state
        .store
        .insert_message(NewMessageInput {
            id: None,
            thread_id: None,
            label_ids: vec![LABEL_INBOX.to_string()],
            raw_rfc2822: Vec::new(),
            snippet: "Urgent: verify".to_string(),
            internal_date_ms: 1_700_000_000_000,
            subject: "Verify your account".to_string(),
            from_addr: "alerts@external.example".to_string(),
            to_addrs: vec!["agent@example.com".to_string()],
            cc_addrs: Vec::new(),
            bcc_addrs: Vec::new(),
            text_body: "Urgent: verify your account.".to_string(),
            html_body: Some(html_body.to_string()),
            rfc822_message_id: Some("<phish-1@external.example>".to_string()),
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
    state.post_store_message(&stored).await.unwrap();

    // GET /v1/messages/{id}?include_html=true strips 1x1 & hidden pixels and populates `links`.
    let (status, msg) = send_json(
        &app,
        "GET",
        &format!("/v1/messages/{}?include_html=true", stored.id),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let returned_html = msg["html"].as_str().expect("html included");
    assert!(returned_html.contains("https://cdn.example.com/logo.png"));
    assert!(!returned_html.contains("pixel.gif"));
    assert!(!returned_html.contains("hidden.png"));

    let links = msg["links"].as_array().expect("links populated");
    assert_eq!(links.len(), 3);
    assert_eq!(
        links[0]["display_text"],
        json!("https://bank.example/verify")
    );
    assert_eq!(links[0]["href"], json!("https://evil.example/login"));
    assert_eq!(links[0]["domain_mismatch"], json!(true));

    assert_eq!(links[1]["display_text"], json!("https://bank.example/docs"));
    assert_eq!(links[1]["href"], json!("https://www.bank.example/docs"));
    assert_eq!(links[1]["domain_mismatch"], json!(false));

    assert_eq!(links[2]["display_text"], json!("Help Center"));
    assert_eq!(links[2]["href"], json!("https://help.example.org"));
    assert_eq!(links[2]["domain_mismatch"], json!(false));

    // GET /v1/threads/{id} also exposes `links` even without `include_html=true`.
    let (status, thread) = send_json(
        &app,
        "GET",
        &format!("/v1/threads/{}", stored.thread_id),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let thread_links = thread["messages"][0]["links"]
        .as_array()
        .expect("thread links");
    assert_eq!(thread_links.len(), 3);
    assert_eq!(thread_links[0]["domain_mismatch"], json!(true));

    // Plain-text-only message omits `links` key cleanly.
    let plain = state
        .store
        .insert_message(NewMessageInput {
            id: None,
            thread_id: None,
            label_ids: vec![LABEL_INBOX.to_string()],
            raw_rfc2822: Vec::new(),
            snippet: "Just text".to_string(),
            internal_date_ms: 1_700_000_005_000,
            subject: "Plain".to_string(),
            from_addr: "friend@example.com".to_string(),
            to_addrs: vec!["agent@example.com".to_string()],
            cc_addrs: Vec::new(),
            bcc_addrs: Vec::new(),
            text_body: "Just plain text, no HTML.".to_string(),
            html_body: None,
            rfc822_message_id: Some("<plain-1@example.com>".to_string()),
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
    let (status, plain_msg) = send_json(
        &app,
        "GET",
        &format!("/v1/messages/{}", plain.id),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(plain_msg.get("links").is_none());
}

#[test]
fn toml_config_parses_first_contact_approval_and_dlp_action() {
    let raw = r#"
[safety]
first_contact_approval = true
dlp_action = "deny"
"#;
    let parsed = TomlConfig::from_toml_str(raw).unwrap();
    let mut cfg = Config::default();
    assert!(!cfg.first_contact_approval);
    assert_eq!(cfg.dlp_action, DlpAction::Off);

    parsed.apply_to(&mut cfg);
    assert!(cfg.first_contact_approval);
    assert_eq!(cfg.dlp_action, DlpAction::Deny);
}

#[tokio::test]
async fn e2e_strict_single_recipient_parser_blocks_multi_address_bypass() {
    let mut cfg = Config::for_test();
    cfg.allowed_recipients = vec!["@company.com".to_string()];
    cfg.max_send_recipients = 1;
    cfg.first_contact_approval = true;
    let (app, _state, sent_log) = build_test_app(cfg);

    for malformed in [
        "external@other.example, <alice@company.com>",
        "<alice@company.com>, external@other.example",
        "<alice@company.com> trailing",
        "<alice@company.com> <evil@other.example>",
        "external@other.example <alice@company.com>",
        "Alice; Bob <alice@company.com>",
        "alice@company.com, evil@other.example",
        "\"evil@other.example\" <alice@company.com>",
    ] {
        let (status, body) = send_json(
            &app,
            "POST",
            "/v1/messages/send",
            None,
            Some(json!({
                "to": [malformed],
                "subject": "Bypass attempt",
                "text": "Must be rejected"
            })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "malformed recipient '{malformed}' must fail with 400, got {status}: {body}"
        );
    }
    assert!(sent_log.lock().unwrap().is_empty());

    // Valid quoted display name with comma and single allowed recipient passes syntax & allowlist
    // (held by first_contact_approval -> 202, not rejected as 400 or 403).
    let (status, body) = send_json(
        &app,
        "POST",
        "/v1/messages/send",
        None,
        Some(json!({
            "to": ["\"Smith, Alice\" <alice@company.com>"],
            "subject": "Legit single recipient",
            "text": "Hello Alice"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "expected 202, got {body}");
    assert!(sent_log.lock().unwrap().is_empty());
}

#[tokio::test]
async fn e2e_policy_precedence_draft_only_never_promoted_to_approval_queue() {
    use nogml::config::DraftOnlyAction;

    // 1. Server-level draft_only=true (Downgrade) + first_contact_approval=true + dlp_action=Hold
    //    MUST downgrade to local draft, NEVER create a pending approval!
    let mut cfg = Config::for_test();
    cfg.draft_only = true;
    cfg.draft_only_action = DraftOnlyAction::Downgrade;
    cfg.first_contact_approval = true;
    cfg.dlp_action = DlpAction::Hold;
    let (app, state, sent_log) = build_test_app(cfg);

    let (status, resp) = send_json(
        &app,
        "POST",
        "/v1/messages/send",
        None,
        Some(json!({
            "to": ["stranger@external.example"],
            "subject": "Draft only precedence test",
            "text": "SSN 123-45-6789 should still not promote draft_only into approval queue"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "expected downgrade 200, got {resp}");
    assert_eq!(resp["status"], json!("draft_created"));
    assert_eq!(resp["downgraded_from_send"], json!(true));
    assert!(sent_log.lock().unwrap().is_empty());
    let approvals = state.store.list_pending_approvals(None, 20).await.unwrap();
    assert!(
        approvals.is_empty(),
        "draft_only downgrade must never enqueue an approval"
    );

    // 2. Deny still outranks DowngradeToDraft (dlp_action=Deny + draft_only=Downgrade -> 403)
    let mut cfg_deny = Config::for_test();
    cfg_deny.draft_only = true;
    cfg_deny.draft_only_action = DraftOnlyAction::Downgrade;
    cfg_deny.dlp_action = DlpAction::Deny;
    let (app_deny, _state_deny, sent_deny) = build_test_app(cfg_deny);
    let (status, resp) = send_json(
        &app_deny,
        "POST",
        "/v1/messages/send",
        None,
        Some(json!({
            "to": ["stranger@external.example"],
            "subject": "DLP deny beats downgrade",
            "text": "SSN 123-45-6789"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(resp["error"]["code"], json!("dlp_blocked"));
    assert!(sent_deny.lock().unwrap().is_empty());
}

#[tokio::test]
async fn e2e_dlp_hold_redacts_subject_in_approval_webhook_and_events() {
    use nogml::events::MailEvent;
    use std::time::Duration;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    let webhook_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/dlp-hook"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
        .expect(1)
        .mount(&webhook_server)
        .await;

    let secret_in_subject = format!("AKIA{}", "IOSFODNN7EXAMPLE");
    let mut cfg = Config::for_test();
    cfg.dlp_action = DlpAction::Hold;
    cfg.approval_webhook_url = Some(format!("{}/dlp-hook", webhook_server.uri()));
    let (app, state, sent_log) = build_test_app(cfg);
    let mut events_rx = state.events.subscribe();

    let (status, held) = send_json(
        &app,
        "POST",
        "/v1/messages/send",
        None,
        Some(json!({
            "to": ["ops@example.com"],
            "subject": format!("Rotate key {secret_in_subject} ASAP"),
            "text": "Body text without secret"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(held["subject"], json!("[REDACTED: DLP policy hold]"));
    assert_eq!(
        held["preview"]["subject"],
        json!("[REDACTED: DLP policy hold]")
    );
    assert!(!held.to_string().contains(&secret_in_subject));
    assert!(sent_log.lock().unwrap().is_empty());

    // EventBus ApprovalRequested MUST carry redacted subject
    let mut saw_event = false;
    while let Ok(env) = events_rx.try_recv() {
        if let MailEvent::ApprovalRequested { subject, .. } = env.event {
            assert_eq!(subject, "[REDACTED: DLP policy hold]");
            assert!(!subject.contains(&secret_in_subject));
            saw_event = true;
        }
    }
    assert!(saw_event, "expected MailEvent::ApprovalRequested");

    // Approval webhook POST MUST carry redacted subject and never leak secret
    let mut reqs = Vec::new();
    for _ in 0..40 {
        let received = webhook_server.received_requests().await.unwrap();
        if !received.is_empty() {
            reqs = received;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(reqs.len(), 1);
    let hook_body = String::from_utf8(reqs[0].body.clone()).unwrap();
    assert!(
        !hook_body.contains(&secret_in_subject),
        "webhook leaked DLP subject secret: {hook_body}"
    );
    let hook_json: Value = serde_json::from_str(&hook_body).unwrap();
    assert_eq!(
        hook_json["message"]["subject"],
        json!("[REDACTED: DLP policy hold]")
    );
    assert!(
        hook_json["text"]
            .as_str()
            .unwrap()
            .contains("[REDACTED: DLP policy hold]")
    );
}
