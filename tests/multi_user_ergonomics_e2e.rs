//! End-to-end integration tests for Issue #70:
//! - Multi-account `[[sync.accounts]]` concurrent background sync & CLI selection
//! - Mailbox aliases (`[mailboxes.aliases]` & `NOGML_MAILBOX_ALIASES`) for inbound webhook routing and outbound alias sending
//! - Shared / team mailboxes (`shared_mailboxes`) across Gmail REST API, AI `/v1/*`, MCP `/mcp`, and IMAP (`LOGIN`, `PLAIN`, `XOAUTH2`)
//! - `nogml.toml` parsing, `file://`/`env://` secret resolution, and secret redaction in `Debug` and `nogml config check`

use std::{
    collections::HashMap,
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
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use nogml::{
    AppState,
    auth::{AuthScope, ScopedTokenConfig},
    build_router,
    config::{
        Config, StorageBackend, SyncAccountConfig, SyncMode, TomlConfig, parse_mailbox_aliases,
        validate_config,
    },
    error::{AppError, AppResult},
    imap::serve_imap,
    mime,
    models::{
        LABEL_INBOX, LABEL_UNREAD, ResendReceivedAttachment, ResendReceivedEmail,
        ResendSendEmailRequest, ResendSendEmailResponse,
    },
    resend::ResendClient,
    secrets::{REDACTED, ValueOrigin, write_secret_file},
    storage::{MailStore, MessageListQuery, NewMessageInput, SqliteStore},
    sync::{SyncRunOptions, get_sync_status, run_background_sync, run_gmail_sync},
    transport::{MailTransport, OutboundMessage, SendOutcome, TransportCapabilities},
};
use serde_json::{Value, json};
use sha2::Sha256;
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::watch,
};
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

#[derive(Default)]
struct NoopResendClient;

#[async_trait]
impl ResendClient for NoopResendClient {
    async fn send_email(
        &self,
        _req: &ResendSendEmailRequest,
        _idempotency_key: Option<&str>,
    ) -> AppResult<ResendSendEmailResponse> {
        Ok(ResendSendEmailResponse {
            id: "re_noop".to_string(),
        })
    }

    async fn get_received_email(&self, _id: &str) -> AppResult<ResendReceivedEmail> {
        Err(AppError::NotFound("noop resend".to_string()))
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

#[derive(Default, Clone)]
struct RecordingTransport {
    sent: Arc<Mutex<Vec<OutboundMessage>>>,
}

#[async_trait]
impl MailTransport for RecordingTransport {
    fn name(&self) -> &'static str {
        "recording"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            provider: "recording".to_string(),
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
        let mut guard = self.sent.lock().unwrap();
        let idx = guard.len() + 1;
        guard.push(msg.clone());
        Ok(SendOutcome {
            provider: "recording".to_string(),
            provider_message_id: format!("rec_msg_{idx}"),
            provider_thread_id: None,
        })
    }
}

async fn http_json(
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
    let req = match body {
        Some(val) => builder
            .header("content-type", "application/json")
            .body(Body::from(val.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw_text": String::from_utf8_lossy(&bytes).to_string() }));
    (status, json)
}

fn svix_signature(secret: &str, svix_id: &str, timestamp: &str, body: &[u8]) -> String {
    let raw_key = secret.strip_prefix("whsec_").unwrap_or(secret);
    let key = general_purpose::STANDARD.decode(raw_key).unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac.update(format!("{svix_id}.{timestamp}.").as_bytes());
    mac.update(body);
    let sig = general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    format!("v1,{sig}")
}

struct GmailMockSeed<'a> {
    access_token: &'a str,
    msg_id: &'a str,
    from: &'a str,
    to: &'a str,
    subject: &'a str,
    body_text: &'a str,
    delay: Duration,
}

async fn mount_gmail_mock(server: &MockServer, seed: GmailMockSeed<'_>) {
    let auth_val = format!("Bearer {}", seed.access_token);
    let raw_eml = format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\nMessage-ID: <{}@gmail.test>\r\nDate: Wed, 25 Nov 2026 12:00:00 +0000\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{}",
        seed.from, seed.to, seed.subject, seed.msg_id, seed.body_text
    );
    let raw_b64 = mime::encode_base64url(raw_eml.as_bytes());

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/profile"))
        .and(header("authorization", auth_val.as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(seed.delay)
                .set_body_json(json!({
                    "emailAddress": seed.to,
                    "messagesTotal": 1,
                    "threadsTotal": 1,
                    "historyId": "100"
                })),
        )
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .and(header("authorization", auth_val.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "labels": [
                { "id": "INBOX", "name": "INBOX", "type": "system" },
                { "id": "UNREAD", "name": "UNREAD", "type": "system" }
            ]
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .and(header("authorization", auth_val.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [{ "id": seed.msg_id, "threadId": format!("thr_{}", seed.msg_id) }],
            "resultSizeEstimate": 1
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/gmail/v1/users/me/messages/{}", seed.msg_id)))
        .and(header("authorization", auth_val.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": seed.msg_id,
            "threadId": format!("thr_{}", seed.msg_id),
            "labelIds": ["INBOX", "UNREAD"],
            "snippet": seed.body_text,
            "historyId": "100",
            "internalDate": "1764072000000",
            "raw": raw_b64
        })))
        .mount(server)
        .await;
}

async fn seed_message(
    store: &dyn MailStore,
    id: &str,
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
) {
    let raw = format!(
        "From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nMessage-ID: <{id}@seed.test>\r\nDate: Wed, 25 Nov 2026 12:00:00 +0000\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}"
    );
    store
        .insert_message(NewMessageInput {
            id: Some(id.to_string()),
            thread_id: Some(format!("thr_{id}")),
            label_ids: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            raw_rfc2822: raw.into_bytes(),
            snippet: body.to_string(),
            internal_date_ms: 1_764_072_000_000,
            subject: subject.to_string(),
            from_addr: from.to_string(),
            to_addrs: vec![to.to_string()],
            cc_addrs: Vec::new(),
            bcc_addrs: Vec::new(),
            text_body: body.to_string(),
            html_body: None,
            rfc822_message_id: Some(format!("<{id}@seed.test>")),
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "test".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: Vec::new(),
        })
        .await
        .unwrap();
}

async fn read_imap_until(reader: &mut BufReader<TcpStream>, tag: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let prefix = format!("{tag} ");
    loop {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .expect("IMAP read timeout")
            .unwrap();
        assert!(n > 0, "unexpected IMAP EOF before {tag}; lines={lines:?}");
        lines.push(line.clone());
        if line.starts_with(&prefix) {
            return lines;
        }
    }
}

async fn imap_cmd(reader: &mut BufReader<TcpStream>, tag: &str, cmd: &str) -> Vec<String> {
    let wire = format!("{tag} {cmd}\r\n");
    reader.get_mut().write_all(wire.as_bytes()).await.unwrap();
    reader.get_mut().flush().await.unwrap();
    read_imap_until(reader, tag).await
}

#[tokio::test]
async fn multi_account_sync_isolates_mailboxes_and_cli_selects_account() {
    let alice_gmail = MockServer::start().await;
    let bob_gmail = MockServer::start().await;

    // Alice's upstream endpoint is intentionally slower than Bob's to prove independent per-mailbox loops/locks.
    mount_gmail_mock(
        &alice_gmail,
        GmailMockSeed {
            access_token: "alice-access-token",
            msg_id: "gm_alice_1",
            from: "partner@vendor.test",
            to: "alice@example.com",
            subject: "Alice Quarterly Update",
            body_text: "Confidential Alice report",
            delay: Duration::from_millis(200),
        },
    )
    .await;
    mount_gmail_mock(
        &bob_gmail,
        GmailMockSeed {
            access_token: "bob-access-token",
            msg_id: "gm_bob_1",
            from: "ops@vendor.test",
            to: "bob@example.com",
            subject: "Bob Incident Digest",
            body_text: "Confidential Bob metrics",
            delay: Duration::from_millis(0),
        },
    )
    .await;

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("multi_sync.db");

    let mut cfg = Config::for_test();
    cfg.storage = StorageBackend::Sqlite;
    cfg.db_path = db_path.clone();
    cfg.user_email = "alice@example.com".to_string();
    cfg.sync_accounts = vec![
        SyncAccountConfig {
            mailbox_id: "alice@example.com".to_string(),
            mode: SyncMode::Api,
            interval_secs: 1,
            gmail_access_token: Some("alice-access-token".to_string()),
            gmail_api_base_url: alice_gmail.uri(),
            ..SyncAccountConfig::default()
        },
        SyncAccountConfig {
            mailbox_id: "bob@example.com".to_string(),
            mode: SyncMode::Api,
            interval_secs: 1,
            gmail_access_token: Some("bob-access-token".to_string()),
            gmail_api_base_url: bob_gmail.uri(),
            ..SyncAccountConfig::default()
        },
    ];
    assert!(cfg.has_background_sync());
    assert!(
        cfg.known_mailboxes()
            .contains(&"alice@example.com".to_string())
    );
    assert!(
        cfg.known_mailboxes()
            .contains(&"bob@example.com".to_string())
    );

    let store = Arc::new(SqliteStore::open(&db_path, &cfg.user_email).unwrap());
    let state = AppState::with_backends(cfg, store, Arc::new(NoopResendClient));

    // Spawn run_background_sync and verify both accounts sync independently into isolated mailboxes.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let bg_handle = tokio::spawn(run_background_sync(state.clone(), shutdown_rx));

    let alice_state = state.for_mailbox("alice@example.com");
    let bob_state = state.for_mailbox("bob@example.com");

    let mut synced_both = false;
    for _ in 0..40 {
        let a_msgs = alice_state
            .store
            .list_messages(&MessageListQuery::default())
            .await
            .unwrap();
        let b_msgs = bob_state
            .store
            .list_messages(&MessageListQuery::default())
            .await
            .unwrap();
        if !a_msgs.messages.is_empty() && !b_msgs.messages.is_empty() {
            synced_both = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let _ = shutdown_tx.send(true);
    bg_handle.await.unwrap();
    assert!(
        synced_both,
        "both [[sync.accounts]] must sync in background"
    );

    let alice_page = alice_state
        .store
        .list_messages(&MessageListQuery::default())
        .await
        .unwrap();
    assert_eq!(alice_page.messages.len(), 1);
    assert_eq!(alice_page.messages[0].subject, "Alice Quarterly Update");
    assert_eq!(
        alice_page.messages[0].upstream_gmail_id.as_deref(),
        Some("gm_alice_1")
    );

    let bob_page = bob_state
        .store
        .list_messages(&MessageListQuery::default())
        .await
        .unwrap();
    assert_eq!(bob_page.messages.len(), 1);
    assert_eq!(bob_page.messages[0].subject, "Bob Incident Digest");
    assert_eq!(
        bob_page.messages[0].upstream_gmail_id.as_deref(),
        Some("gm_bob_1")
    );

    // Status and manual run_gmail_sync on scoped mailbox states auto-select the matching account.
    let bob_status = get_sync_status(&bob_state).await.unwrap();
    assert!(bob_status.enabled);
    assert_eq!(bob_status.provider, "gmail_api");
    let bob_manual = run_gmail_sync(&bob_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(bob_manual.provider, "gmail_api");

    // Verify CLI `nogml sync gmail --mailbox bob@example.com` automatically picks Bob's [[sync.accounts]] entry.
    let cli_db = dir.path().join("cli_sync.db");
    let cli_toml = dir.path().join("nogml.toml");
    std::fs::write(
        &cli_toml,
        format!(
            r#"
[storage]
backend = "sqlite"
db_path = "{}"

[auth]
user_email = "alice@example.com"

[[sync.accounts]]
mailbox_id = "alice@example.com"
mode = "api"
gmail_access_token = "alice-access-token"
gmail_api_base_url = "{}"

[[sync.accounts]]
mailbox_id = "bob@example.com"
mode = "api"
gmail_access_token = "bob-access-token"
gmail_api_base_url = "{}"
"#,
            cli_db.display(),
            alice_gmail.uri(),
            bob_gmail.uri()
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_nogml"))
        .args([
            "--config",
            cli_toml.to_str().unwrap(),
            "sync",
            "gmail",
            "--mailbox",
            "bob@example.com",
        ])
        .output()
        .expect("run nogml sync gmail");
    assert!(
        output.status.success(),
        "nogml sync gmail failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["messages_added"], 1);

    let verify_store = SqliteStore::open(&cli_db, "alice@example.com").unwrap();
    assert!(
        verify_store
            .for_mailbox("alice@example.com")
            .list_messages(&MessageListQuery::default())
            .await
            .unwrap()
            .messages
            .is_empty(),
        "Alice mailbox must remain untouched when CLI syncs only --mailbox bob@example.com"
    );
    let cli_bob_msgs = verify_store
        .for_mailbox("bob@example.com")
        .list_messages(&MessageListQuery::default())
        .await
        .unwrap();
    assert_eq!(cli_bob_msgs.messages.len(), 1);
    assert_eq!(cli_bob_msgs.messages[0].subject, "Bob Incident Digest");
}

#[tokio::test]
async fn mailbox_aliases_route_webhooks_and_authorize_alias_sending() {
    let wh_secret_raw = general_purpose::STANDARD.encode(b"alias-webhook-signing-key-32byte");
    let wh_secret = format!("whsec_{wh_secret_raw}");

    let mut cfg = Config::for_test();
    cfg.user_email = "justin@example.com".to_string();
    cfg.mailboxes = vec!["team@example.com".to_string()];
    cfg.mailbox_aliases = HashMap::from([
        (
            "J@EXAMPLE.COM".to_string(),
            "justin@example.com".to_string(),
        ),
        (
            "sales@example.com".to_string(),
            "team@example.com".to_string(),
        ),
    ]);
    cfg.resend_webhook_secret = Some(wh_secret.clone());
    cfg.ses_webhook_secret = Some("ses-alias-secret".to_string());
    cfg.scoped_tokens = vec![ScopedTokenConfig {
        token: "tok-justin".to_string(),
        mailbox_id: Some("justin@example.com".to_string()),
        shared_mailboxes: Vec::new(),
        scopes: vec![AuthScope::Read, AuthScope::Write, AuthScope::Send],
        draft_only: None,
        allowed_recipients: None,
        max_send_recipients: None,
    }];

    let transport = RecordingTransport::default();
    let store = Arc::new(SqliteStore::open_in_memory(&cfg.user_email).unwrap());
    let state = AppState::with_backends(cfg, store, Arc::new(NoopResendClient))
        .with_transport(Arc::new(transport.clone()));
    let app = build_router(state.clone());

    // 1. Resend webhook addressed to alias `j@example.com` delivers into `justin@example.com`.
    let resend_payload = json!({
        "type": "email.received",
        "created_at": "2026-11-26T12:00:00Z",
        "data": {
            "email_id": "re_alias_1",
            "from": "external@sender.test",
            "to": ["Justin <J@EXAMPLE.COM>"],
            "subject": "Hello via Resend alias",
            "message_id": "<alias-resend-1@sender.test>"
        }
    });
    let resend_body = serde_json::to_vec(&resend_payload).unwrap();
    let ts = Utc::now().timestamp().to_string();
    let svix_id = "msg_alias_1";
    let sig = svix_signature(&wh_secret, svix_id, &ts, &resend_body);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhooks/resend")
                .header("content-type", "application/json")
                .header("svix-id", svix_id)
                .header("svix-timestamp", &ts)
                .header("svix-signature", &sig)
                .body(Body::from(resend_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body_json["status"], "received");
    assert_eq!(body_json["mailbox_id"], "justin@example.com");

    // 2. SES webhook addressed to alias `j@example.com` also delivers into `justin@example.com`.
    let ses_raw = b"From: ses-sender@external.test\r\nTo: j@example.com\r\nSubject: Hello via SES alias\r\nMessage-ID: <alias-ses-1@external.test>\r\n\r\nSES body";
    let ses_notification = json!({
        "notificationType": "Received",
        "mail": {
            "messageId": "ses-alias-1",
            "destination": ["j@example.com"]
        },
        "receipt": {
            "recipients": ["j@example.com"]
        },
        "content": general_purpose::STANDARD.encode(ses_raw)
    });
    let sns_payload = json!({
        "Type": "Notification",
        "MessageId": "sns-alias-1",
        "Message": ses_notification.to_string()
    });
    let (ses_status, ses_body) = http_json(
        &app,
        "POST",
        "/webhooks/ses",
        &[("x-nogml-webhook-secret", "ses-alias-secret")],
        Some(sns_payload),
    )
    .await;
    assert_eq!(ses_status, StatusCode::OK, "ses body: {ses_body}");
    assert_eq!(ses_body["status"], "received");
    assert_eq!(ses_body["mailbox_id"], "justin@example.com");

    // 3. Unknown recipient is ignored (not routed into Justin or Team).
    let unknown_payload = json!({
        "type": "email.received",
        "created_at": "2026-11-26T12:00:00Z",
        "data": {
            "email_id": "re_unknown_1",
            "from": "external@sender.test",
            "to": ["nobody@example.com"],
            "subject": "Should be ignored"
        }
    });
    let unknown_body = serde_json::to_vec(&unknown_payload).unwrap();
    let svix_id2 = "msg_alias_unknown";
    let sig2 = svix_signature(&wh_secret, svix_id2, &ts, &unknown_body);
    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhooks/resend")
                .header("content-type", "application/json")
                .header("svix-id", svix_id2)
                .header("svix-timestamp", &ts)
                .header("svix-signature", &sig2)
                .body(Body::from(unknown_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let body2: Value =
        serde_json::from_slice(&resp2.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body2["status"], "ignored");

    // Justin's mailbox received both alias emails; Team's mailbox received none.
    let justin_msgs = state
        .for_mailbox("justin@example.com")
        .store
        .list_messages(&MessageListQuery::default())
        .await
        .unwrap();
    assert_eq!(justin_msgs.messages.len(), 2);
    assert!(
        state
            .for_mailbox("team@example.com")
            .store
            .list_messages(&MessageListQuery::default())
            .await
            .unwrap()
            .messages
            .is_empty()
    );

    // 4. `settings/sendAs` exposes Justin's configured alias `j@example.com`.
    let (sa_status, sa_body) = http_json(
        &app,
        "GET",
        "/gmail/v1/users/me/settings/sendAs",
        &[("authorization", "Bearer tok-justin")],
        None,
    )
    .await;
    assert_eq!(sa_status, StatusCode::OK, "sendAs: {sa_body}");
    let send_as_emails: Vec<&str> = sa_body["sendAs"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["sendAsEmail"].as_str())
        .collect();
    assert!(
        send_as_emails.contains(&"j@example.com"),
        "expected j@example.com in sendAs: {send_as_emails:?}"
    );

    // 5. Justin can send from `j@example.com` via `/v1/messages/send` AND Gmail `/gmail/v1/users/me/messages/send`.
    let (v1_send_status, v1_send_body) = http_json(
        &app,
        "POST",
        "/v1/messages/send",
        &[("authorization", "Bearer tok-justin")],
        Some(json!({
            "from": "Justin <j@example.com>",
            "to": ["recipient@external.test"],
            "subject": "From my alias",
            "text": "Sent via alias"
        })),
    )
    .await;
    assert_eq!(v1_send_status, StatusCode::OK, "v1 send: {v1_send_body}");
    assert_eq!(v1_send_body["from"], "Justin <j@example.com>");

    let raw_alias_send = b"From: j@example.com\r\nTo: recipient@external.test\r\nSubject: Gmail alias send\r\n\r\nBody";
    let (gm_send_status, gm_send_body) = http_json(
        &app,
        "POST",
        "/gmail/v1/users/me/messages/send",
        &[("authorization", "Bearer tok-justin")],
        Some(json!({ "raw": mime::encode_base64url(raw_alias_send) })),
    )
    .await;
    assert_eq!(gm_send_status, StatusCode::OK, "gm send: {gm_send_body}");

    // 6. Justin CANNOT send from `sales@example.com` (alias of team, not Justin).
    let (forbid_v1, _) = http_json(
        &app,
        "POST",
        "/v1/messages/send",
        &[("authorization", "Bearer tok-justin")],
        Some(json!({
            "from": "sales@example.com",
            "to": ["recipient@external.test"],
            "subject": "Spoof attempt",
            "text": "Should fail"
        })),
    )
    .await;
    assert_eq!(forbid_v1, StatusCode::FORBIDDEN);

    let raw_spoof =
        b"From: sales@example.com\r\nTo: recipient@external.test\r\nSubject: Spoof\r\n\r\nNope";
    let (forbid_gm, _) = http_json(
        &app,
        "POST",
        "/gmail/v1/users/me/messages/send",
        &[("authorization", "Bearer tok-justin")],
        Some(json!({ "raw": mime::encode_base64url(raw_spoof) })),
    )
    .await;
    assert_eq!(forbid_gm, StatusCode::FORBIDDEN);

    let recorded = transport.sent.lock().unwrap();
    assert_eq!(recorded.len(), 2);
    assert_eq!(recorded[0].from, "Justin <j@example.com>");
    assert_eq!(recorded[1].from, "j@example.com");
}

#[tokio::test]
async fn shared_mailbox_access_works_across_gmail_ai_mcp_and_imap_while_blocking_other_mailboxes() {
    let mut cfg = Config::for_test();
    cfg.user_email = "alice@example.com".to_string();
    cfg.mailboxes = vec![
        "team@example.com".to_string(),
        "bob@example.com".to_string(),
    ];
    cfg.scoped_tokens = vec![
        ScopedTokenConfig {
            token: "tok-alice".to_string(),
            mailbox_id: Some("alice@example.com".to_string()),
            shared_mailboxes: vec!["team@example.com".to_string()],
            scopes: vec![AuthScope::Read, AuthScope::Write, AuthScope::Send],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok-bob".to_string(),
            mailbox_id: Some("bob@example.com".to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read, AuthScope::Write, AuthScope::Send],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
    ];

    // Pick a free ephemeral port for embedded IMAP.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let imap_addr = probe.local_addr().unwrap();
    drop(probe);
    cfg.imap_bind = Some(imap_addr);

    let transport = RecordingTransport::default();
    let store = Arc::new(SqliteStore::open_in_memory(&cfg.user_email).unwrap());
    let state = AppState::with_backends(cfg, store, Arc::new(NoopResendClient))
        .with_transport(Arc::new(transport.clone()));

    seed_message(
        state.for_mailbox("alice@example.com").store.as_ref(),
        "m_alice",
        "ceo@example.org",
        "alice@example.com",
        "Alice Private Note",
        "Only for Alice",
    )
    .await;
    seed_message(
        state.for_mailbox("team@example.com").store.as_ref(),
        "m_team",
        "customer@acme.test",
        "team@example.com",
        "Team Support Ticket #42",
        "Shared team inbox message",
    )
    .await;
    seed_message(
        state.for_mailbox("bob@example.com").store.as_ref(),
        "m_bob",
        "hr@example.org",
        "bob@example.com",
        "Bob Secret Payroll",
        "Strictly Bob only",
    )
    .await;

    let app = build_router(state.clone());
    let alice_auth = ("authorization", "Bearer tok-alice");

    // --- 1. Gmail REST API ---
    let (st, profile) = http_json(
        &app,
        "GET",
        "/gmail/v1/users/team@example.com/profile",
        &[alice_auth],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "team profile: {profile}");
    assert_eq!(profile["emailAddress"], "team@example.com");

    let (st, team_list) = http_json(
        &app,
        "GET",
        "/gmail/v1/users/team@example.com/messages",
        &[alice_auth],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "team list: {team_list}");
    let team_ids: Vec<&str> = team_list["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["id"].as_str())
        .collect();
    assert_eq!(team_ids, vec!["m_team"]);

    // Percent-encoded userId (`team%40example.com`) also works.
    let (st, _) = http_json(
        &app,
        "GET",
        "/gmail/v1/users/team%40example.com/messages/m_team",
        &[alice_auth],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // Sending from the shared mailbox via Gmail REST API works and stores in `team@example.com`.
    let team_reply_raw = b"From: team@example.com\r\nTo: customer@acme.test\r\nSubject: Re: Team Support Ticket #42\r\n\r\nWe are on it.";
    let (st, sent_gm) = http_json(
        &app,
        "POST",
        "/gmail/v1/users/team@example.com/messages/send",
        &[alice_auth],
        Some(json!({ "raw": mime::encode_base64url(team_reply_raw) })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "gmail team send: {sent_gm}");

    // Bob's mailbox is STILL forbidden (403) via Gmail REST API.
    let (st_bob, _) = http_json(
        &app,
        "GET",
        "/gmail/v1/users/bob@example.com/messages",
        &[alice_auth],
        None,
    )
    .await;
    assert_eq!(st_bob, StatusCode::FORBIDDEN);

    let (st_bob_send, _) = http_json(
        &app,
        "POST",
        "/gmail/v1/users/bob@example.com/messages/send",
        &[alice_auth],
        Some(json!({ "raw": mime::encode_base64url(b"From: bob@example.com\r\nTo: x@y.test\r\nSubject: No\r\n\r\nNo") })),
    )
    .await;
    assert_eq!(st_bob_send, StatusCode::FORBIDDEN);

    // --- 2. AI REST API (`/v1/*` with `X-Nogml-Mailbox`) ---
    let (st, v1_team) = http_json(
        &app,
        "GET",
        "/v1/messages",
        &[alice_auth, ("x-nogml-mailbox", "team@example.com")],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "v1 team messages: {v1_team}");
    let v1_subjects: Vec<&str> = v1_team["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["subject"].as_str())
        .collect();
    assert!(v1_subjects.contains(&"Team Support Ticket #42"));
    assert!(!v1_subjects.contains(&"Alice Private Note"));
    assert!(!v1_subjects.contains(&"Bob Secret Payroll"));

    let (st, v1_send) = http_json(
        &app,
        "POST",
        "/v1/messages/send",
        &[alice_auth, ("x-nogml-mailbox", "team@example.com")],
        Some(json!({
            "to": ["customer@acme.test"],
            "subject": "Team AI Reply",
            "text": "Resolved!"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "v1 team send: {v1_send}");
    assert_eq!(v1_send["from"], "team@example.com");

    // Unauthorized `X-Nogml-Mailbox: bob@example.com` returns 403 on `/v1/*`.
    let (st_v1_bob, v1_bob_err) = http_json(
        &app,
        "GET",
        "/v1/messages",
        &[alice_auth, ("x-nogml-mailbox", "bob@example.com")],
        None,
    )
    .await;
    assert_eq!(st_v1_bob, StatusCode::FORBIDDEN, "v1 bob err: {v1_bob_err}");

    // Without header, Alice sees only her own mailbox.
    let (st, v1_alice) = http_json(&app, "GET", "/v1/messages", &[alice_auth], None).await;
    assert_eq!(st, StatusCode::OK);
    let alice_subjects: Vec<&str> = v1_alice["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["subject"].as_str())
        .collect();
    assert_eq!(alice_subjects, vec!["Alice Private Note"]);

    // --- 3. MCP (`POST /mcp` with `X-Nogml-Mailbox`) ---
    let mcp_list_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "list_threads",
            "arguments": {}
        }
    });
    let (st, mcp_team) = http_json(
        &app,
        "POST",
        "/mcp",
        &[alice_auth, ("x-nogml-mailbox", "team@example.com")],
        Some(mcp_list_req.clone()),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "mcp team: {mcp_team}");
    let mcp_threads = mcp_team["result"]["structuredContent"]["threads"]
        .as_array()
        .unwrap();
    assert!(
        mcp_threads
            .iter()
            .any(|t| t["subject"] == "Team Support Ticket #42"),
        "expected Team thread in MCP response: {mcp_team}"
    );
    assert!(
        !mcp_threads
            .iter()
            .any(|t| t["subject"] == "Alice Private Note" || t["subject"] == "Bob Secret Payroll")
    );

    let (st_mcp_bob, _) = http_json(
        &app,
        "POST",
        "/mcp",
        &[alice_auth, ("x-nogml-mailbox", "bob@example.com")],
        Some(mcp_list_req),
    )
    .await;
    assert_eq!(st_mcp_bob, StatusCode::FORBIDDEN);

    // --- 4. IMAP (`LOGIN`, `AUTHENTICATE PLAIN`, `AUTHENTICATE XOAUTH2`) ---
    let (imap_shutdown_tx, imap_shutdown_rx) = watch::channel(false);
    let imap_state = state.clone();
    let imap_handle = tokio::spawn(async move {
        let _ = serve_imap(imap_state, imap_shutdown_rx).await;
    });

    // Wait briefly for TCP bind.
    let stream = loop {
        match TcpStream::connect(imap_addr).await {
            Ok(s) => break s,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    };
    let mut reader = BufReader::new(stream);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.unwrap();
    assert!(greeting.starts_with("* OK"));

    // 4a. IMAP `LOGIN team@example.com tok-alice` succeeds and exposes Team's inbox.
    let login_res = imap_cmd(&mut reader, "A1", r#"LOGIN "team@example.com" "tok-alice""#).await;
    assert!(
        login_res.last().unwrap().starts_with("A1 OK"),
        "IMAP LOGIN to shared mailbox failed: {login_res:?}"
    );
    let select_res = imap_cmd(&mut reader, "A2", "SELECT INBOX").await;
    assert!(select_res.last().unwrap().starts_with("A2 OK"));
    let fetch_res = imap_cmd(&mut reader, "A3", "FETCH 1 (BODY[HEADER.FIELDS (SUBJECT)])")
        .await
        .join("");
    assert!(
        fetch_res.contains("Team Support Ticket #42"),
        "expected Team message in IMAP FETCH, got: {fetch_res}"
    );
    assert!(!fetch_res.contains("Alice Private Note"));
    assert!(!fetch_res.contains("Bob Secret Payroll"));
    let _ = imap_cmd(&mut reader, "A4", "LOGOUT").await;

    // 4b. IMAP `AUTHENTICATE PLAIN` with `authzid=team@example.com`, `authcid=alice@example.com`.
    let mut reader_plain = BufReader::new(TcpStream::connect(imap_addr).await.unwrap());
    let mut g2 = String::new();
    reader_plain.read_line(&mut g2).await.unwrap();
    let plain_b64 =
        general_purpose::STANDARD.encode("team@example.com\0alice@example.com\0tok-alice");
    let plain_res = imap_cmd(
        &mut reader_plain,
        "P1",
        &format!("AUTHENTICATE PLAIN {plain_b64}"),
    )
    .await;
    assert!(
        plain_res.last().unwrap().starts_with("P1 OK"),
        "IMAP PLAIN to shared mailbox failed: {plain_res:?}"
    );
    let _ = imap_cmd(&mut reader_plain, "P2", "SELECT INBOX").await;
    let p_fetch = imap_cmd(
        &mut reader_plain,
        "P3",
        "FETCH 1 (BODY[HEADER.FIELDS (SUBJECT)])",
    )
    .await
    .join("");
    assert!(p_fetch.contains("Team Support Ticket #42"));
    let _ = imap_cmd(&mut reader_plain, "P4", "LOGOUT").await;

    // 4c. IMAP `AUTHENTICATE XOAUTH2` for `team@example.com` using Alice's token.
    let mut reader_xo = BufReader::new(TcpStream::connect(imap_addr).await.unwrap());
    let mut g3 = String::new();
    reader_xo.read_line(&mut g3).await.unwrap();
    let xo_b64 =
        general_purpose::STANDARD.encode("user=team@example.com\x01auth=Bearer tok-alice\x01\x01");
    let xo_res = imap_cmd(
        &mut reader_xo,
        "X1",
        &format!("AUTHENTICATE XOAUTH2 {xo_b64}"),
    )
    .await;
    assert!(
        xo_res.last().unwrap().starts_with("X1 OK"),
        "IMAP XOAUTH2 to shared mailbox failed: {xo_res:?}"
    );
    let _ = imap_cmd(&mut reader_xo, "X2", "SELECT INBOX").await;
    let x_fetch = imap_cmd(
        &mut reader_xo,
        "X3",
        "FETCH 1 (BODY[HEADER.FIELDS (SUBJECT)])",
    )
    .await
    .join("");
    assert!(x_fetch.contains("Team Support Ticket #42"));
    let _ = imap_cmd(&mut reader_xo, "X4", "LOGOUT").await;

    // 4d. IMAP attempts against Bob's mailbox with Alice's token MUST fail.
    let mut reader_deny = BufReader::new(TcpStream::connect(imap_addr).await.unwrap());
    let mut g4 = String::new();
    reader_deny.read_line(&mut g4).await.unwrap();
    let bob_login = imap_cmd(
        &mut reader_deny,
        "D1",
        r#"LOGIN "bob@example.com" "tok-alice""#,
    )
    .await;
    assert!(
        bob_login.last().unwrap().contains("D1 NO"),
        "LOGIN to Bob with Alice token must fail: {bob_login:?}"
    );
    let bob_plain_b64 =
        general_purpose::STANDARD.encode("bob@example.com\0alice@example.com\0tok-alice");
    let bob_plain = imap_cmd(
        &mut reader_deny,
        "D2",
        &format!("AUTHENTICATE PLAIN {bob_plain_b64}"),
    )
    .await;
    assert!(
        bob_plain.last().unwrap().contains("D2 NO"),
        "PLAIN authzid=bob with Alice token must fail: {bob_plain:?}"
    );
    let bob_xo_b64 =
        general_purpose::STANDARD.encode("user=bob@example.com\x01auth=Bearer tok-alice\x01\x01");
    let bob_xo = imap_cmd(
        &mut reader_deny,
        "D3",
        &format!("AUTHENTICATE XOAUTH2 {bob_xo_b64}"),
    )
    .await;
    assert!(
        bob_xo.last().unwrap().contains("D3 NO"),
        "XOAUTH2 for Bob with Alice token must fail: {bob_xo:?}"
    );
    let _ = imap_cmd(&mut reader_deny, "D4", "LOGOUT").await;

    let _ = imap_shutdown_tx.send(true);
    let _ = imap_handle.await;

    // Confirm both sends (Gmail + AI) targeted Team and recorded in transport.
    let sent = transport.sent.lock().unwrap();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].from, "team@example.com");
    assert_eq!(sent[1].from, "team@example.com");
}

#[test]
fn toml_parsing_env_aliases_and_secret_redaction_in_debug_and_config_check() {
    let dir = TempDir::new().unwrap();
    let refresh_file = dir.path().join("alice_refresh.secret");
    let imap_pass_file = dir.path().join("bob_imap.secret");
    let scoped_tok_file = dir.path().join("alice_scoped.secret");

    write_secret_file(&refresh_file, "SECRET_ALICE_REFRESH_TOKEN", false).unwrap();
    write_secret_file(&imap_pass_file, "SECRET_BOB_IMAP_PASSWORD", false).unwrap();
    write_secret_file(&scoped_tok_file, "SECRET_ALICE_SCOPED_TOKEN", false).unwrap();

    let toml_path = dir.path().join("nogml.toml");
    let toml_content = format!(
        r#"
[storage]
backend = "memory"

[auth]
user_email = "justin@example.com"
mailboxes = ["team@example.com"]

[[auth.scoped_tokens]]
token = "file://{}"
mailbox_id = "alice@example.com"
shared_mailboxes = ["team@example.com"]
scopes = ["read", "write", "send"]

[mailboxes.aliases]
"J@Example.COM" = "Justin@Example.com"
"sales@example.com" = "team@example.com"

[[sync.accounts]]
mailbox_id = "Alice@Example.com"
mode = "api"
interval_secs = 60
query = "newer_than:7d"
max_messages = 100
bidirectional = true
gmail_client_id = "alice-client-id"
gmail_client_secret = "env://TEST_ALICE_CLIENT_SECRET"
gmail_refresh_token = "file://{}"
gmail_access_token = "SECRET_ALICE_ACCESS_TOKEN"

[[sync.accounts]]
mailbox_id = "bob@example.com"
mode = "imap"
interval_secs = 120
gmail_imap_host = "imap.gmail.com"
gmail_imap_port = 993
gmail_imap_tls = true
gmail_imap_user = "bob@gmail.com"
gmail_imap_password = "file://{}"
"#,
        scoped_tok_file.display(),
        refresh_file.display(),
        imap_pass_file.display()
    );
    std::fs::write(&toml_path, &toml_content).unwrap();

    let parsed = TomlConfig::from_file(&toml_path).expect("nogml.toml must parse cleanly");
    let mut cfg = Config::default();
    parsed.apply_to(&mut cfg);

    let vars: HashMap<String, String> = [(
        "TEST_ALICE_CLIENT_SECRET".to_string(),
        "SECRET_ALICE_CLIENT_SECRET".to_string(),
    )]
    .into_iter()
    .collect();

    let resolution =
        cfg.apply_env_file_secrets_and_resolve(Some(dir.path()), &|_| ValueOrigin::Unset, &|k| {
            vars.get(k).cloned()
        });
    assert!(
        resolution.errors.is_empty(),
        "secret resolution errors: {:?}",
        resolution.errors
    );

    // Verify normalized aliases, shared_mailboxes, and sync_accounts.
    assert_eq!(
        cfg.mailbox_aliases.get("j@example.com").map(String::as_str),
        Some("justin@example.com")
    );
    assert_eq!(
        cfg.mailbox_aliases
            .get("sales@example.com")
            .map(String::as_str),
        Some("team@example.com")
    );
    assert_eq!(cfg.scoped_tokens.len(), 1);
    assert_eq!(
        cfg.scoped_tokens[0].shared_mailboxes,
        vec!["team@example.com".to_string()]
    );
    assert_eq!(cfg.scoped_tokens[0].token, "SECRET_ALICE_SCOPED_TOKEN");

    assert_eq!(cfg.sync_accounts.len(), 2);
    assert_eq!(cfg.sync_accounts[0].mailbox_id, "alice@example.com");
    assert_eq!(
        cfg.sync_accounts[0].gmail_client_secret.as_deref(),
        Some("SECRET_ALICE_CLIENT_SECRET")
    );
    assert_eq!(
        cfg.sync_accounts[0].gmail_refresh_token.as_deref(),
        Some("SECRET_ALICE_REFRESH_TOKEN")
    );
    assert_eq!(
        cfg.sync_accounts[1].gmail_imap_password.as_deref(),
        Some("SECRET_BOB_IMAP_PASSWORD")
    );

    let known = cfg.known_mailboxes();
    for expected in [
        "justin@example.com",
        "team@example.com",
        "alice@example.com",
        "bob@example.com",
    ] {
        assert!(
            known.contains(&expected.to_string()),
            "known_mailboxes missing {expected}: {known:?}"
        );
    }

    // Verify Debug and validate_config/redacted_summary never leak any sync or token secrets.
    let toml_dbg = format!("{parsed:?}");
    let cfg_dbg = format!("{cfg:?}");
    let check_report = validate_config(&cfg, Some(toml_path.clone()), resolution);
    assert!(
        check_report.ok,
        "config check errors: {:?}",
        check_report.errors
    );
    let summary_str = check_report.effective_config.unwrap().to_string();

    for secret in [
        "SECRET_ALICE_CLIENT_SECRET",
        "SECRET_ALICE_REFRESH_TOKEN",
        "SECRET_ALICE_ACCESS_TOKEN",
        "SECRET_BOB_IMAP_PASSWORD",
        "SECRET_ALICE_SCOPED_TOKEN",
    ] {
        assert!(
            !toml_dbg.contains(secret),
            "TomlConfig Debug leaked {secret}"
        );
        assert!(!cfg_dbg.contains(secret), "Config Debug leaked {secret}");
        assert!(
            !summary_str.contains(secret),
            "redacted_summary leaked {secret}"
        );
    }
    assert!(cfg_dbg.contains(REDACTED));
    assert!(summary_str.contains(REDACTED));

    // Verify CLI `nogml config check --config ...` + `NOGML_MAILBOX_ALIASES` redacts all secrets.
    let cli_out = Command::new(env!("CARGO_BIN_EXE_nogml"))
        .args(["config", "check", "--config", toml_path.to_str().unwrap()])
        .env("TEST_ALICE_CLIENT_SECRET", "SECRET_ALICE_CLIENT_SECRET")
        .env(
            "NOGML_MAILBOX_ALIASES",
            "j@example.com=justin@example.com,help@example.com=team@example.com",
        )
        .output()
        .expect("run nogml config check");
    let stdout = String::from_utf8_lossy(&cli_out.stdout);
    let stderr = String::from_utf8_lossy(&cli_out.stderr);
    assert!(
        cli_out.status.success(),
        "nogml config check failed: stdout={stdout} stderr={stderr}"
    );
    for secret in [
        "SECRET_ALICE_CLIENT_SECRET",
        "SECRET_ALICE_REFRESH_TOKEN",
        "SECRET_ALICE_ACCESS_TOKEN",
        "SECRET_BOB_IMAP_PASSWORD",
        "SECRET_ALICE_SCOPED_TOKEN",
    ] {
        assert!(
            !stdout.contains(secret) && !stderr.contains(secret),
            "nogml config check leaked {secret}"
        );
    }
    let cli_json: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(cli_json["ok"], true);
    assert_eq!(
        cli_json["effective_config"]["mailboxes"]["aliases"]["help@example.com"],
        "team@example.com"
    );
    assert_eq!(
        cli_json["effective_config"]["sync"]["accounts"][0]["gmail_refresh_token"],
        REDACTED
    );
    assert_eq!(
        cli_json["effective_config"]["sync"]["accounts"][1]["gmail_imap_password"],
        REDACTED
    );

    // Direct parser unit check for NOGML_MAILBOX_ALIASES.
    let parsed_env = parse_mailbox_aliases(
        " J@Example.COM = Justin@Example.com , sales@example.com=team@example.com ",
    )
    .unwrap();
    assert_eq!(
        parsed_env.get("j@example.com").map(String::as_str),
        Some("justin@example.com")
    );
    assert_eq!(
        parsed_env.get("sales@example.com").map(String::as_str),
        Some("team@example.com")
    );
    assert!(parse_mailbox_aliases("not-a-mapping").is_err());
}
