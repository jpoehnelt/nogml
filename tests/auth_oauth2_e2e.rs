//! End-to-end integration tests for Issue #2:
//! - Scoped API keys (`Read`, `Write`, `Send`, `Admin`) enforced across `/v1`, `/gmail/v1`,
//!   `/batch/gmail/v1`, `/mcp`, and IMAP4rev1
//! - Per-agent `AgentPolicyOverride` (`draft_only`, `allowed_recipients`, `max_send_recipients`)
//! - Optional local OAuth2 endpoints (`/.well-known/oauth-authorization-server`, `/oauth2/authorize`,
//!   `/oauth2/token` with `authorization_code` + PKCE, `refresh_token`, `client_credentials`)
//! - IMAP `AUTHENTICATE XOAUTH2` (SASL-IR and continuation)

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tower::ServiceExt;

use nogml::{
    AppState,
    auth::{AuthScope, ScopedTokenConfig},
    build_router,
    config::Config,
    error::{AppError, AppResult},
    imap::serve_imap,
    mime::encode_base64url,
    models::{
        LABEL_INBOX, LABEL_UNREAD, ResendReceivedAttachment, ResendReceivedEmail,
        ResendSendEmailRequest, ResendSendEmailResponse,
    },
    resend::ResendClient,
    storage::{MailStore, MemoryStore, NewLabelInput, NewMessageInput},
    transport::{MailTransport, OutboundMessage, SendOutcome, TransportCapabilities},
};

struct NoopResend;

#[async_trait]
impl ResendClient for NoopResend {
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

struct CountingTransport {
    sent: Arc<AtomicUsize>,
}

#[async_trait]
impl MailTransport for CountingTransport {
    fn name(&self) -> &'static str {
        "counting_mock"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            provider: "counting_mock".to_string(),
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
        _msg: &OutboundMessage,
        _idempotency_key: Option<&str>,
    ) -> AppResult<SendOutcome> {
        let n = self.sent.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(SendOutcome {
            provider: "counting_mock".to_string(),
            provider_message_id: format!("mock_{n}"),
        })
    }
}

async fn seed_inbox_message(store: &MemoryStore) -> (String, String) {
    let raw = concat!(
        "From: alice@partner.example\r\n",
        "To: agent@example.com\r\n",
        "Subject: Quarterly report\r\n",
        "Message-ID: <q1-report@partner.example>\r\n",
        "\r\n",
        "Here are the Q1 numbers.\r\n"
    )
    .as_bytes()
    .to_vec();

    let stored = store
        .insert_message(NewMessageInput {
            id: None,
            thread_id: None,
            label_ids: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            raw_rfc2822: raw,
            snippet: "Here are the Q1 numbers.".to_string(),
            internal_date_ms: 1_700_000_000_000,
            subject: "Quarterly report".to_string(),
            from_addr: "alice@partner.example".to_string(),
            to_addrs: vec!["agent@example.com".to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: "Here are the Q1 numbers.".to_string(),
            html_body: None,
            rfc822_message_id: Some("<q1-report@partner.example>".to_string()),
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

    (stored.id, stored.thread_id)
}

async fn http_json(
    app: &Router,
    method: &str,
    uri: &str,
    auth: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(a) = auth {
        builder = builder.header(header::AUTHORIZATION, a);
    }
    let req = if let Some(payload) = body {
        builder
            .header(header::CONTENT_TYPE, "application/json")
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

async fn spawn_imap(mut state: AppState) -> (SocketAddr, watch::Sender<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let mut cfg = (*state.config).clone();
    cfg.imap_bind = Some(addr);
    state.config = Arc::new(cfg);

    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = serve_imap(state, rx).await;
    });

    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            return (addr, tx);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("IMAP server did not bind in time");
}

async fn imap_cmd(reader: &mut BufReader<TcpStream>, tag: &str, cmd: &str) -> Vec<String> {
    let line = format!("{tag} {cmd}\r\n");
    reader.get_mut().write_all(line.as_bytes()).await.unwrap();
    reader.get_mut().flush().await.unwrap();

    let mut out = Vec::new();
    let prefix = format!("{tag} ");
    loop {
        let mut buf = String::new();
        let n = reader.read_line(&mut buf).await.unwrap();
        assert!(n > 0, "unexpected EOF while waiting for {tag}");
        let trimmed = buf.trim_end_matches(['\r', '\n']).to_string();
        let done = trimmed.starts_with(&prefix);
        out.push(trimmed);
        if done {
            break;
        }
    }
    out
}

fn xoauth2_b64(user: &str, token: &str) -> String {
    let raw = format!("user={user}\x01auth=Bearer {token}\x01\x01");
    STANDARD.encode(raw.as_bytes())
}

#[tokio::test]
async fn e2e_scoped_readonly_token_enforced_across_v1_gmail_batch_mcp_and_imap() {
    let mut cfg = Config::for_test();
    cfg.scoped_tokens = vec![
        ScopedTokenConfig {
            token: "tok-read-only".to_string(),
            mailbox_id: None,
            scopes: vec![AuthScope::Read],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok-read-write".to_string(),
            mailbox_id: None,
            scopes: vec![AuthScope::Read, AuthScope::Write],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok-admin".to_string(),
            mailbox_id: None,
            scopes: vec![AuthScope::Admin],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
    ];

    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let (_msg_id, thread_id) = seed_inbox_message(&store).await;
    store
        .create_label(NewLabelInput {
            name: "Work".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();

    let sent_calls = Arc::new(AtomicUsize::new(0));
    let state = AppState::with_backends(cfg, store.clone(), Arc::new(NoopResend)).with_transport(
        Arc::new(CountingTransport {
            sent: sent_calls.clone(),
        }),
    );
    let app = build_router(state.clone());

    // Unauthenticated rejected even though legacy auth_tokens is empty
    let (status, _) = http_json(&app, "GET", "/v1/messages", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // --- Read-only token: reads succeed ---
    let ro = Some("Bearer tok-read-only");
    let (s, body) = http_json(&app, "GET", "/v1/messages", ro, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["messages"].as_array().unwrap().len(), 1);

    let (s, body) = http_json(&app, "GET", "/gmail/v1/users/me/messages", ro, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["messages"].as_array().unwrap().len(), 1);

    let (s, body) = http_json(
        &app,
        "POST",
        "/mcp",
        ro,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "search_emails",
                "arguments": { "query": "Quarterly" }
            }
        })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["result"]["isError"], false);
    assert_eq!(
        body["result"]["structuredContent"]["messages"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // --- Read-only token: mutations and sends get 403 Forbidden ---
    let (s, body) = http_json(
        &app,
        "POST",
        "/v1/messages/send",
        ro,
        Some(json!({
            "to": ["bob@example.com"],
            "subject": "Blocked",
            "text": "Should fail"
        })),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "forbidden");

    let (s, _) = http_json(
        &app,
        "POST",
        "/v1/drafts",
        ro,
        Some(json!({ "to": ["bob@example.com"], "subject": "Draft" })),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    let raw_b64 = encode_base64url(
        b"From: agent@example.com\r\nTo: bob@example.com\r\nSubject: Hi\r\n\r\nBody",
    );
    let (s, body) = http_json(
        &app,
        "POST",
        "/gmail/v1/users/me/messages/send",
        ro,
        Some(json!({ "raw": raw_b64 })),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["status"], "PERMISSION_DENIED");

    // Batch mixes a permitted GET (200) with a denied POST send (403)
    let batch_body = format!(
        "--b1\r\nContent-Type: application/http\r\nContent-ID: <1>\r\n\r\n\
         GET /gmail/v1/users/me/profile HTTP/1.1\r\n\r\n\
         --b1\r\nContent-Type: application/http\r\nContent-ID: <2>\r\n\r\n\
         POST /gmail/v1/users/me/messages/send HTTP/1.1\r\nContent-Type: application/json\r\n\r\n\
         {{\"raw\":\"{raw_b64}\"}}\r\n\
         --b1--\r\n"
    );
    let batch_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/batch/gmail/v1")
                .header(header::AUTHORIZATION, "Bearer tok-read-only")
                .header(header::CONTENT_TYPE, "multipart/mixed; boundary=b1")
                .body(Body::from(batch_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(batch_resp.status(), StatusCode::OK);
    let batch_text = String::from_utf8(
        batch_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(batch_text.contains("HTTP/1.1 200 OK"));
    assert!(batch_text.contains("HTTP/1.1 403 Forbidden"));

    // MCP send_email & triage_thread denied with HTTP 403 and isError: true
    let (s, body) = http_json(
        &app,
        "POST",
        "/mcp",
        ro,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "send_email",
                "arguments": {
                    "to": ["bob@example.com"],
                    "subject": "Denied",
                    "text": "Nope"
                }
            }
        })),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(body["result"]["isError"], true);
    assert_eq!(
        body["result"]["structuredContent"]["error"]["code"],
        "forbidden"
    );

    let (s, _) = http_json(
        &app,
        "POST",
        "/mcp",
        ro,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "triage_thread",
                "arguments": { "thread_id": thread_id, "archive": true }
            }
        })),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // --- Read-write token: drafts allowed, send and settings denied ---
    let rw = Some("Bearer tok-read-write");
    let (s, _) = http_json(
        &app,
        "POST",
        "/v1/drafts",
        rw,
        Some(json!({ "to": ["bob@example.com"], "subject": "RW draft", "text": "ok" })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let (s, _) = http_json(
        &app,
        "POST",
        "/v1/messages/send",
        rw,
        Some(json!({ "to": ["bob@example.com"], "subject": "No send scope", "text": "nope" })),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    let (s, _) = http_json(
        &app,
        "PUT",
        "/gmail/v1/users/me/settings/vacation",
        rw,
        Some(json!({ "enableAutoReply": true, "responseSubject": "OOO" })),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // --- Admin token: settings mutation succeeds ---
    let (s, _) = http_json(
        &app,
        "PUT",
        "/gmail/v1/users/me/settings/vacation",
        Some("Bearer tok-admin"),
        Some(json!({ "enableAutoReply": true, "responseSubject": "OOO" })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // --- IMAP read-only token: FETCH succeeds, all mutations return NO [NOPERM] ---
    let (imap_addr, shutdown_tx) = spawn_imap(state.clone()).await;
    let stream = TcpStream::connect(imap_addr).await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.unwrap();
    assert!(greeting.contains("AUTH=XOAUTH2"));

    let login = imap_cmd(&mut reader, "A1", "LOGIN agent@example.com tok-read-only").await;
    assert!(login.last().unwrap().starts_with("A1 OK"));

    let sel = imap_cmd(&mut reader, "A2", "SELECT INBOX").await;
    assert!(
        sel.last().unwrap().contains("A2 OK [READ-ONLY]"),
        "expected READ-ONLY select, got: {sel:?}"
    );

    let fetch = imap_cmd(&mut reader, "A3", "FETCH 1 (FLAGS BODY[])").await;
    assert!(fetch.last().unwrap().starts_with("A3 OK"));
    assert!(fetch.iter().any(|l| l.contains("Quarterly report")));

    // Verify FETCH did NOT mutate \Seen on read-only session
    let flags_after = imap_cmd(&mut reader, "A4", "FETCH 1 (FLAGS)").await;
    assert!(
        !flags_after.iter().any(|l| l.contains("\\Seen")),
        "read-only FETCH must not add \\Seen: {flags_after:?}"
    );

    for (tag, cmd) in [
        ("A5", "STORE 1 +FLAGS (\\Seen)"),
        ("A6", "COPY 1 \"[Gmail]/Starred\""),
        ("A7", "MOVE 1 \"[Gmail]/Trash\""),
        ("A8", "EXPUNGE"),
        ("A9", "CREATE \"DeniedFolder\""),
        ("A10", "DELETE \"Work\""),
        ("A11", "RENAME \"Work\" \"Work2\""),
    ] {
        let resp = imap_cmd(&mut reader, tag, cmd).await;
        assert!(
            resp.last().unwrap().starts_with(&format!("{tag} NO")),
            "expected NO for `{cmd}` on read-only token, got: {resp:?}"
        );
    }

    // APPEND with literal also rejected with NO
    let append_raw = b"From: a@b.com\r\nSubject: Blocked\r\n\r\nhi";
    let append_cmd = format!("A12 APPEND INBOX {{{}+}}\r\n", append_raw.len());
    reader
        .get_mut()
        .write_all(append_cmd.as_bytes())
        .await
        .unwrap();
    reader.get_mut().write_all(append_raw).await.unwrap();
    reader.get_mut().write_all(b"\r\n").await.unwrap();
    reader.get_mut().flush().await.unwrap();
    let mut append_resp = String::new();
    reader.read_line(&mut append_resp).await.unwrap();
    assert!(
        append_resp.starts_with("A12 NO"),
        "expected A12 NO for APPEND on read-only token, got: {append_resp}"
    );

    let _ = imap_cmd(&mut reader, "A13", "LOGOUT").await;
    let _ = shutdown_tx.send(true);
    assert_eq!(sent_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn e2e_scoped_agent_policy_overrides_enforce_draft_only_allowlist_and_max_recipients() {
    let mut cfg = Config::for_test();
    // Global config is completely permissive!
    cfg.draft_only = false;
    cfg.allowed_recipients = vec![];
    cfg.max_send_recipients = 50;
    cfg.auth_tokens = vec!["legacy-full-token".to_string()];
    cfg.scoped_tokens = vec![
        ScopedTokenConfig {
            token: "tok-draft-only".to_string(),
            mailbox_id: None,
            scopes: vec![AuthScope::Read, AuthScope::Write, AuthScope::Send],
            draft_only: Some(true),
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok-narrow-rcpt".to_string(),
            mailbox_id: None,
            scopes: vec![AuthScope::Read, AuthScope::Write, AuthScope::Send],
            draft_only: Some(false),
            allowed_recipients: Some(vec!["@allowed.example".to_string()]),
            max_send_recipients: Some(2),
        },
    ];

    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let sent_calls = Arc::new(AtomicUsize::new(0));
    let state = AppState::with_backends(cfg, store, Arc::new(NoopResend)).with_transport(Arc::new(
        CountingTransport {
            sent: sent_calls.clone(),
        },
    ));
    let app = build_router(state);

    // 1. Draft-only token can create a draft, but cannot send on /v1, /gmail/v1, or /mcp
    let draft_tok = Some("Bearer tok-draft-only");
    let (s, created) = http_json(
        &app,
        "POST",
        "/v1/drafts",
        draft_tok,
        Some(json!({
            "to": ["alice@allowed.example"],
            "subject": "Draft OK",
            "text": "Saved as draft"
        })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let draft_id = created["draft_id"].as_str().unwrap().to_string();

    let (s, body) = http_json(
        &app,
        "POST",
        "/v1/messages/send",
        draft_tok,
        Some(json!({
            "to": ["alice@allowed.example"],
            "subject": "Blocked direct send",
            "text": "Nope"
        })),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "draft_only_mode");

    let (s, body) = http_json(
        &app,
        "POST",
        &format!("/v1/drafts/{draft_id}/send"),
        draft_tok,
        Some(json!({})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "draft_only_mode");

    let (s, dry) = http_json(
        &app,
        "POST",
        "/v1/messages/send",
        draft_tok,
        Some(json!({
            "to": ["alice@allowed.example"],
            "subject": "Dry run",
            "text": "Preview",
            "dry_run": true
        })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(dry["would_succeed"], false);

    let raw_ok = encode_base64url(
        b"From: agent@example.com\r\nTo: alice@allowed.example\r\nSubject: Hi\r\n\r\nBody",
    );
    let (s, _) = http_json(
        &app,
        "POST",
        "/gmail/v1/users/me/messages/send",
        draft_tok,
        Some(json!({ "raw": raw_ok })),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    let (s, _) = http_json(
        &app,
        "POST",
        "/gmail/v1/users/me/drafts/send",
        draft_tok,
        Some(json!({ "id": draft_id })),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    let (s, body) = http_json(
        &app,
        "POST",
        "/mcp",
        draft_tok,
        Some(json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "send_email",
                "arguments": {
                    "to": ["alice@allowed.example"],
                    "subject": "MCP blocked",
                    "text": "Nope"
                }
            }
        })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["result"]["isError"], true);
    assert_eq!(
        body["result"]["structuredContent"]["error"]["code"],
        "draft_only_mode"
    );

    // 2. Narrow recipient allowlist + max_send_recipients=2 token
    let narrow_tok = Some("Bearer tok-narrow-rcpt");
    let (s, body) = http_json(
        &app,
        "POST",
        "/v1/messages/send",
        narrow_tok,
        Some(json!({
            "to": ["external@other.org"],
            "subject": "Disallowed domain",
            "text": "Nope"
        })),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "recipient_not_allowed");

    let (s, _) = http_json(
        &app,
        "POST",
        "/v1/messages/send",
        narrow_tok,
        Some(json!({
            "to": ["a@allowed.example", "b@allowed.example", "c@allowed.example"],
            "subject": "Too many recipients",
            "text": "Nope"
        })),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (s, sent) = http_json(
        &app,
        "POST",
        "/v1/messages/send",
        narrow_tok,
        Some(json!({
            "to": ["alice@allowed.example"],
            "subject": "Allowed recipient",
            "text": "Delivered"
        })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(sent["status"], "sent");

    // 3. Legacy NOGML_AUTH_TOKENS full token remains backward compatible and unrestricted
    let (s, sent) = http_json(
        &app,
        "POST",
        "/v1/messages/send",
        Some("Bearer legacy-full-token"),
        Some(json!({
            "to": ["external@other.org"],
            "subject": "Legacy full send",
            "text": "Delivered"
        })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(sent["status"], "sent");
    assert_eq!(sent_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn e2e_local_oauth2_auth_code_pkce_refresh_and_imap_xoauth2() {
    let mut cfg = Config::for_test();
    cfg.auth_tokens = vec!["oauth-admin-session-tok".to_string()];
    cfg.oauth2_client_id = Some("nogml-gmail-client".to_string());
    cfg.oauth2_client_secret = Some("nogml-gmail-secret".to_string());
    cfg.oauth2_signing_secret = Some("local-hs256-signing-secret-material-42".to_string());
    cfg.oauth2_redirect_uris = vec!["http://127.0.0.1:9999/callback".to_string()];

    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    seed_inbox_message(&store).await;

    let state = AppState::with_backends(cfg, store, Arc::new(NoopResend));
    let app = build_router(state.clone());

    // 1. OAuth2 discovery document is unauthenticated
    let (s, meta) = http_json(
        &app,
        "GET",
        "/.well-known/oauth-authorization-server",
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        meta["token_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/oauth2/token")
    );
    assert!(
        meta["authorization_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/oauth2/authorize")
    );

    // Protected endpoint rejects unauthenticated when OAuth2 is enabled
    let (s, _) = http_json(&app, "GET", "/gmail/v1/users/me/profile", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // 2. Authorization code flow with PKCE S256
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let auth_url = format!(
        "/oauth2/authorize?response_type=code&client_id=nogml-gmail-client\
         &redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcallback\
         &scope=https%3A%2F%2Fmail.google.com%2F\
         &state=xyz123&code_challenge={challenge}&code_challenge_method=S256"
    );

    // Unauthenticated /oauth2/authorize MUST be rejected with 401
    let unauth_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&auth_url)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);

    // Authenticated /oauth2/authorize with allowlisted redirect_uri succeeds
    let auth_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&auth_url)
                .header(header::AUTHORIZATION, "Bearer oauth-admin-session-tok")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(auth_resp.status(), StatusCode::FOUND);
    let location = auth_resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    let parsed_loc = url::Url::parse(location).unwrap();
    let mut code = None;
    let mut returned_state = None;
    for (k, v) in parsed_loc.query_pairs() {
        if k == "code" {
            code = Some(v.into_owned());
        } else if k == "state" {
            returned_state = Some(v.into_owned());
        }
    }
    let code = code.expect("authorization code present in redirect");
    assert_eq!(returned_state.as_deref(), Some("xyz123"));

    // Wrong PKCE verifier rejected
    let bad_form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("client_id", "nogml-gmail-client")
        .append_pair("client_secret", "nogml-gmail-secret")
        .append_pair("code", &code)
        .append_pair("redirect_uri", "http://127.0.0.1:9999/callback")
        .append_pair("code_verifier", "wrong-verifier")
        .finish();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(bad_form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Exchange authorization_code with valid PKCE verifier
    let good_form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("client_id", "nogml-gmail-client")
        .append_pair("client_secret", "nogml-gmail-secret")
        .append_pair("code", &code)
        .append_pair("redirect_uri", "http://127.0.0.1:9999/callback")
        .append_pair("code_verifier", verifier)
        .finish();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(good_form.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let token_json: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(token_json["token_type"], "Bearer");
    let refresh_token = token_json["refresh_token"].as_str().unwrap().to_string();
    assert!(token_json["access_token"].as_str().is_some());

    // Replaying authorization_code is rejected
    let replay = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(good_form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);

    // 3. Refresh token grant mints a fresh access_token (standard Google SDK flow)
    let refresh_form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "refresh_token")
        .append_pair("client_id", "nogml-gmail-client")
        .append_pair("client_secret", "nogml-gmail-secret")
        .append_pair("refresh_token", &refresh_token)
        .finish();
    let refresh_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(refresh_form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refresh_resp.status(), StatusCode::OK);
    let refreshed: Value =
        serde_json::from_slice(&refresh_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    let access_token = refreshed["access_token"].as_str().unwrap().to_string();
    let bearer = format!("Bearer {access_token}");

    // Refresh token itself MUST NOT be accepted as a Bearer access_token
    let (s, _) = http_json(
        &app,
        "GET",
        "/gmail/v1/users/me/profile",
        Some(&format!("Bearer {refresh_token}")),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Minted access_token works on /gmail/v1/users/me/profile and /gmail/v1/users/me/messages
    let (s, profile) = http_json(
        &app,
        "GET",
        "/gmail/v1/users/me/profile",
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(profile["emailAddress"], "agent@example.com");

    let (s, list) = http_json(
        &app,
        "GET",
        "/gmail/v1/users/me/messages",
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(list["messages"].as_array().unwrap().len(), 1);

    // 4. client_credentials grant with Basic auth and gmail.readonly scope produces a read-only JWT
    let basic_creds = STANDARD.encode("nogml-gmail-client:nogml-gmail-secret");
    let cc_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/token")
                .header(header::AUTHORIZATION, format!("Basic {basic_creds}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    "grant_type=client_credentials&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fgmail.readonly",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cc_resp.status(), StatusCode::OK);
    let cc_json: Value =
        serde_json::from_slice(&cc_resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let ro_jwt = cc_json["access_token"].as_str().unwrap().to_string();

    let (s, _) = http_json(
        &app,
        "GET",
        "/gmail/v1/users/me/messages",
        Some(&format!("Bearer {ro_jwt}")),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let (s, _) = http_json(
        &app,
        "POST",
        "/v1/messages/send",
        Some(&format!("Bearer {ro_jwt}")),
        Some(json!({ "to": ["bob@example.com"], "subject": "No", "text": "No" })),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // 5. IMAP AUTHENTICATE XOAUTH2 (SASL-IR, continuation, and failure cases)
    let (imap_addr, shutdown_tx) = spawn_imap(state.clone()).await;

    // 5a. SASL-IR initial response with valid OAuth2 access_token
    {
        let stream = TcpStream::connect(imap_addr).await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.unwrap();
        assert!(greeting.contains("AUTH=XOAUTH2"));

        let b64 = xoauth2_b64("agent@example.com", &access_token);
        let auth = imap_cmd(&mut reader, "X1", &format!("AUTHENTICATE XOAUTH2 {b64}")).await;
        assert!(
            auth.last().unwrap().starts_with("X1 OK"),
            "expected X1 OK, got: {auth:?}"
        );

        let sel = imap_cmd(&mut reader, "X2", "SELECT INBOX").await;
        assert!(sel.last().unwrap().contains("X2 OK [READ-WRITE]"));

        let fetch = imap_cmd(&mut reader, "X3", "FETCH 1 (BODY[HEADER.FIELDS (SUBJECT)])").await;
        assert!(fetch.iter().any(|l| l.contains("Quarterly report")));
        let _ = imap_cmd(&mut reader, "X4", "LOGOUT").await;
    }

    // 5b. 2-step continuation (`+ \r\n`) with read-only OAuth2 JWT + rejection of STORE
    {
        let stream = TcpStream::connect(imap_addr).await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.unwrap();

        reader
            .get_mut()
            .write_all(b"Y1 AUTHENTICATE XOAUTH2\r\n")
            .await
            .unwrap();
        reader.get_mut().flush().await.unwrap();
        let mut cont = String::new();
        reader.read_line(&mut cont).await.unwrap();
        assert!(cont.starts_with("+ "), "expected continuation, got: {cont}");

        let b64 = xoauth2_b64("agent@example.com", &ro_jwt);
        reader
            .get_mut()
            .write_all(format!("{b64}\r\n").as_bytes())
            .await
            .unwrap();
        reader.get_mut().flush().await.unwrap();
        let mut resp = String::new();
        reader.read_line(&mut resp).await.unwrap();
        assert!(resp.starts_with("Y1 OK"), "expected Y1 OK, got: {resp}");

        let sel = imap_cmd(&mut reader, "Y2", "SELECT INBOX").await;
        assert!(sel.last().unwrap().contains("Y2 OK [READ-ONLY]"));
        let store_res = imap_cmd(&mut reader, "Y3", "STORE 1 +FLAGS (\\Flagged)").await;
        assert!(store_res.last().unwrap().starts_with("Y3 NO"));
        let _ = imap_cmd(&mut reader, "Y4", "LOGOUT").await;
    }

    // 5c. Reject invalid token, wrong username, and refresh_token used as access_token
    {
        let stream = TcpStream::connect(imap_addr).await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.unwrap();

        for (tag, payload) in [
            ("Z1", xoauth2_b64("agent@example.com", "invalid.jwt.token")),
            ("Z2", xoauth2_b64("other@example.com", &access_token)),
            ("Z3", xoauth2_b64("agent@example.com", &refresh_token)),
        ] {
            let res = imap_cmd(&mut reader, tag, &format!("AUTHENTICATE XOAUTH2 {payload}")).await;
            assert!(
                res.last()
                    .unwrap()
                    .contains(&format!("{tag} NO [AUTHENTICATIONFAILED]")),
                "expected auth failure for {tag}, got: {res:?}"
            );
        }
        let _ = imap_cmd(&mut reader, "Z4", "LOGOUT").await;
    }

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn e2e_oauth2_endpoints_return_404_when_disabled() {
    let cfg = Config::for_test();
    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let state = AppState::with_backends(cfg, store, Arc::new(NoopResend));
    let app = build_router(state);

    let (s, _) = http_json(
        &app,
        "GET",
        "/.well-known/oauth-authorization-server",
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (s, _) = http_json(&app, "POST", "/oauth2/token", None, Some(json!({}))).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn e2e_oauth2_hardening_auth_redirect_allowlist_scope_cap_pkce_and_code_pruning() {
    let mut cfg = Config::for_test();
    cfg.user_email = "alice@example.com".to_string();
    cfg.mailboxes = vec!["bob@example.com".to_string()];
    cfg.oauth2_client_id = Some("public-cli-client".to_string());
    // Intentionally unset oauth2_client_secret to test public-client hardening
    cfg.oauth2_client_secret = None;
    cfg.oauth2_signing_secret = Some("public-client-signing-secret-key-99".to_string());
    cfg.oauth2_redirect_uris = vec!["http://127.0.0.1:8765/cb".to_string()];
    cfg.scoped_tokens = vec![
        ScopedTokenConfig {
            token: "tok-alice-read".to_string(),
            mailbox_id: Some("alice@example.com".to_string()),
            scopes: vec![AuthScope::Read],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok-alice-admin".to_string(),
            mailbox_id: Some("alice@example.com".to_string()),
            scopes: vec![AuthScope::Admin],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
    ];

    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let state = AppState::with_backends(cfg, store, Arc::new(NoopResend));
    let app = build_router(state.clone());

    // 1. Discovery omits client_credentials & plain PKCE for public clients
    let (s, meta) = http_json(
        &app,
        "GET",
        "/.well-known/oauth-authorization-server",
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        meta["grant_types_supported"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(meta["code_challenge_methods_supported"], json!(["S256"]));

    // 2. grant_type=client_credentials is forbidden when oauth2_client_secret is unset (401 invalid_client)
    let cc_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    "grant_type=client_credentials&client_id=public-cli-client",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cc_resp.status(), StatusCode::UNAUTHORIZED);
    let cc_json: Value =
        serde_json::from_slice(&cc_resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(cc_json["error"], "invalid_client");

    let verifier = "pkce-verifier-with-sufficient-entropy-0123456789";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));

    // 3. Unauthenticated /oauth2/authorize returns 401
    let (s, _) = http_json(
        &app,
        "GET",
        &format!(
            "/oauth2/authorize?response_type=code&client_id=public-cli-client\
             &redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcb\
             &code_challenge={challenge}&code_challenge_method=S256"
        ),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // 4. Public client MUST provide PKCE S256 (missing or plain rejected with 400)
    let (s, err) = http_json(
        &app,
        "GET",
        "/oauth2/authorize?response_type=code&client_id=public-cli-client\
         &redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcb",
        Some("Bearer tok-alice-read"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(err["error"], "invalid_request");

    let (s, err) = http_json(
        &app,
        "GET",
        &format!(
            "/oauth2/authorize?response_type=code&client_id=public-cli-client\
             &redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcb\
             &code_challenge={verifier}&code_challenge_method=plain"
        ),
        Some("Bearer tok-alice-read"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(err["error"], "invalid_request");

    // 5. Open redirect & missing redirect_uri rejected with 400 when allowlist is set
    let (s, err) = http_json(
        &app,
        "GET",
        &format!(
            "/oauth2/authorize?response_type=code&client_id=public-cli-client\
             &redirect_uri=https%3A%2F%2Fevil.attacker.example%2Fsteal\
             &code_challenge={challenge}&code_challenge_method=S256"
        ),
        Some("Bearer tok-alice-read"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(err["error"], "invalid_request");

    let (s, err) = http_json(
        &app,
        "GET",
        &format!(
            "/oauth2/authorize?response_type=code&client_id=public-cli-client\
             &code_challenge={challenge}&code_challenge_method=S256"
        ),
        Some("Bearer tok-alice-read"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(err["error"], "invalid_request");

    // 6. Scope capping: Read-only principal cannot request send or admin
    let (s, err) = http_json(
        &app,
        "GET",
        &format!(
            "/oauth2/authorize?response_type=code&client_id=public-cli-client\
             &redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcb\
             &scope=admin&code_challenge={challenge}&code_challenge_method=S256"
        ),
        Some("Bearer tok-alice-read"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(err["error"], "invalid_scope");

    // 7. Mailbox binding & anti-enumeration: non-Admin gets identical 403 for existing and unknown login_hint
    for hint in ["bob@example.com", "does-not-exist@example.com"] {
        let (s, err) = http_json(
            &app,
            "GET",
            &format!(
                "/oauth2/authorize?response_type=code&client_id=public-cli-client\
                 &redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcb\
                 &login_hint={hint}&code_challenge={challenge}&code_challenge_method=S256"
            ),
            Some("Bearer tok-alice-read"),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(err["error"], "access_denied");
    }

    // 8. Omitting scope defaults to principal's own scopes ([Read]), NOT Admin!
    let auth_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/oauth2/authorize?response_type=code&client_id=public-cli-client\
                     &redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcb\
                     &code_challenge={challenge}&code_challenge_method=S256"
                ))
                .header(header::AUTHORIZATION, "Bearer tok-alice-read")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(auth_resp.status(), StatusCode::FOUND);
    let loc = auth_resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    let code = url::Url::parse(loc)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .unwrap();

    // Seed an already-expired JTI into used_oauth_codes to verify pruning on write
    {
        let mut used = state.used_oauth_codes.lock().await;
        used.insert("expired-jti-1".to_string(), 1);
    }

    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("client_id", "public-cli-client")
        .append_pair("code", &code)
        .append_pair("redirect_uri", "http://127.0.0.1:8765/cb")
        .append_pair("code_verifier", verifier)
        .finish();
    let tok_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(tok_resp.status(), StatusCode::OK);
    let tok_json: Value =
        serde_json::from_slice(&tok_resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let jwt = tok_json["access_token"].as_str().unwrap();

    // Expired JTI was pruned and only the fresh code remains
    {
        let used = state.used_oauth_codes.lock().await;
        assert!(!used.contains_key("expired-jti-1"));
        assert_eq!(used.len(), 1);
    }

    // Minted JWT has ONLY Read scope (can GET messages, cannot POST send)
    let (s, _) = http_json(
        &app,
        "GET",
        "/v1/messages",
        Some(&format!("Bearer {jwt}")),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = http_json(
        &app,
        "POST",
        "/v1/messages/send",
        Some(&format!("Bearer {jwt}")),
        Some(json!({ "to": ["bob@example.com"], "subject": "No", "text": "No" })),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // 9. Admin token CAN authorize another configured mailbox via login_hint
    let admin_auth = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/oauth2/authorize?response_type=code&client_id=public-cli-client\
                     &redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcb\
                     &login_hint=bob@example.com&scope=read\
                     &code_challenge={challenge}&code_challenge_method=S256"
                ))
                .header(header::AUTHORIZATION, "Bearer tok-alice-admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(admin_auth.status(), StatusCode::FOUND);

    // 10. When oauth2_redirect_uris is empty, supplying ANY redirect_uri is rejected with 400
    let mut cfg_no_allowlist = Config::for_test();
    cfg_no_allowlist.auth_tokens = vec!["tok-admin".to_string()];
    cfg_no_allowlist.oauth2_client_id = Some("cid".to_string());
    cfg_no_allowlist.oauth2_client_secret = Some("csec".to_string());
    cfg_no_allowlist.oauth2_signing_secret = Some("ssec-1234567890".to_string());
    let state_no = AppState::with_backends(
        cfg_no_allowlist,
        Arc::new(MemoryStore::new("agent@example.com")),
        Arc::new(NoopResend),
    );
    let app_no = build_router(state_no);
    let (s, err) = http_json(
        &app_no,
        "GET",
        "/oauth2/authorize?response_type=code&client_id=cid&redirect_uri=https%3A%2F%2Fevil.example%2Fcb",
        Some("Bearer tok-admin"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(err["error"], "invalid_request");
}
