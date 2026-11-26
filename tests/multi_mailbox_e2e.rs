//! End-to-end integration tests for Issue #3:
//! Multi-mailbox partitioning across `MailStore` (`SqliteStore` and `MemoryStore`),
//! `BlobStore` (`FsBlobStore`), `SearchIndex` (FTS5 and `HybridSearchIndex`),
//! `EventBus` (SSE `/v1/events`, IMAP `IDLE`, Gmail `/watch`), `AuthProvider`,
//! Resend and AWS SES inbound webhooks, MCP `/mcp`, IMAP4rev1, Sync, and
//! backward-compatible SQLite v1-to-v2 schema migration.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tower::ServiceExt;

use nogml::{
    AppState,
    auth::{AuthScope, ScopedTokenConfig},
    blob::{BlobStore, FsBlobStore, mailbox_attachment_blob_key, mailbox_raw_message_blob_key},
    build_router,
    config::{Config, StorageBackend},
    error::{AppError, AppResult},
    imap::serve_imap,
    mime::encode_base64url,
    models::{
        LABEL_INBOX, LABEL_UNREAD, ResendReceivedAttachment, ResendReceivedEmail,
        ResendSendEmailRequest, ResendSendEmailResponse,
    },
    resend::ResendClient,
    search_index::{EmbeddingProvider, HybridSearchIndex, MemoryVectorStore, SqliteVectorStore},
    storage::{
        AiSearchQuery, MailStore, MemoryStore, NewAttachmentInput, NewMessageInput, SqliteStore,
        SyncState,
    },
    transport::{MailTransport, OutboundMessage, SendOutcome, TransportCapabilities},
};

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
const TOK_ALICE: &str = "tok_alice_secret";
const TOK_BOB: &str = "tok_bob_secret";

struct NoopResend;

#[async_trait]
impl ResendClient for NoopResend {
    async fn send_email(
        &self,
        _req: &ResendSendEmailRequest,
        _idempotency_key: Option<&str>,
    ) -> AppResult<ResendSendEmailResponse> {
        Ok(ResendSendEmailResponse {
            id: "re_sent_1".to_string(),
        })
    }
    async fn get_received_email(&self, _id: &str) -> AppResult<ResendReceivedEmail> {
        Err(AppError::NotFound("mock resend disabled".into()))
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

struct RecordingTransport {
    calls: Arc<AtomicUsize>,
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
        let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(SendOutcome {
            provider: "recording_mock".to_string(),
            provider_message_id: format!("re_sent_{n}"),
        })
    }
}

fn multi_mailbox_config(storage: StorageBackend, require_approval: bool) -> Config {
    let mut cfg = Config::for_test();
    cfg.storage = storage;
    cfg.user_email = ALICE.to_string();
    cfg.mailboxes = vec![BOB.to_string()];
    cfg.require_approval = require_approval;
    cfg.scoped_tokens = vec![
        ScopedTokenConfig {
            token: TOK_ALICE.to_string(),
            mailbox_id: Some(ALICE.to_string()),
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
            token: TOK_BOB.to_string(),
            mailbox_id: Some(BOB.to_string()),
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
    cfg
}

async fn send_json_req(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(tok) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {tok}"));
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
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).to_string()))
    };
    (status, json)
}

async fn run_full_isolation_suite(storage: StorageBackend) {
    let tmp = TempDir::new().unwrap();
    let blob_dir = tmp.path().join("blobs");
    let fs_blobs = Arc::new(FsBlobStore::open(&blob_dir).unwrap());
    let mut cfg = multi_mailbox_config(storage, false);
    cfg.db_path = tmp.path().join("nogml.db");

    let store: Arc<dyn MailStore> = match storage {
        StorageBackend::Sqlite => {
            Arc::new(SqliteStore::open(&cfg.db_path, &cfg.user_email).unwrap())
        }
        StorageBackend::Memory => Arc::new(MemoryStore::new(&cfg.user_email)),
        StorageBackend::Postgres => unreachable!("multi_mailbox_e2e runs sqlite and memory"),
    };
    let transport_calls = Arc::new(AtomicUsize::new(0));
    let state = AppState::with_backends(cfg, store.clone(), Arc::new(NoopResend))
        .with_blobs(fs_blobs.clone())
        .with_transport(Arc::new(RecordingTransport {
            calls: transport_calls,
        }));
    let app = build_router(state.clone());

    // 1. Profile and Gmail userId delegation enforcement.
    let (st, alice_profile) = send_json_req(
        &app,
        "GET",
        "/gmail/v1/users/me/profile",
        Some(TOK_ALICE),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(alice_profile["emailAddress"], ALICE);

    let (st, alice_explicit) = send_json_req(
        &app,
        "GET",
        &format!("/gmail/v1/users/{ALICE}/profile"),
        Some(TOK_ALICE),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(alice_explicit["emailAddress"], ALICE);

    let (st, bob_profile) = send_json_req(
        &app,
        "GET",
        "/gmail/v1/users/me/profile",
        Some(TOK_BOB),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(bob_profile["emailAddress"], BOB);

    // Alice MUST get 403 Forbidden when requesting Bob's Gmail userId (and vice versa).
    for path in [
        format!("/gmail/v1/users/{BOB}/messages"),
        format!("/gmail/v1/users/{BOB}/profile"),
        format!("/gmail/v1/users/{BOB}/labels"),
        format!("/gmail/v1/users/{BOB}/settings/sendAs"),
    ] {
        let (st, _) = send_json_req(&app, "GET", &path, Some(TOK_ALICE), None).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "Alice must not access {path}");
    }
    let (st, _) = send_json_req(
        &app,
        "GET",
        &format!("/gmail/v1/users/{ALICE}/messages"),
        Some(TOK_BOB),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // 2. Insert distinct messages with attachments into Alice and Bob via Gmail API.
    let alice_raw = concat!(
        "From: partner@vendor.test\r\n",
        "To: alice@example.com\r\n",
        "Subject: Alice Secret Roadmap\r\n",
        "Message-ID: <alice-roadmap-1@vendor.test>\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=\"B1\"\r\n",
        "\r\n",
        "--B1\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "Alpha launch blueprint for Alice only.\r\n",
        "--B1\r\n",
        "Content-Type: text/plain; name=\"alice.txt\"\r\n",
        "Content-Disposition: attachment; filename=\"alice.txt\"\r\n",
        "\r\n",
        "ALICE-ATTACHMENT-BYTES\r\n",
        "--B1--\r\n"
    );
    let bob_raw = concat!(
        "From: finance@vendor.test\r\n",
        "To: bob@example.com\r\n",
        "Subject: Bob Confidential Budget\r\n",
        "Message-ID: <bob-budget-1@vendor.test>\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=\"B2\"\r\n",
        "\r\n",
        "--B2\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "Omega confidential budget for Bob only.\r\n",
        "--B2\r\n",
        "Content-Type: text/plain; name=\"bob.txt\"\r\n",
        "Content-Disposition: attachment; filename=\"bob.txt\"\r\n",
        "\r\n",
        "BOB-ATTACHMENT-BYTES\r\n",
        "--B2--\r\n"
    );

    let (st, alice_inserted) = send_json_req(
        &app,
        "POST",
        "/gmail/v1/users/me/messages",
        Some(TOK_ALICE),
        Some(json!({
            "raw": encode_base64url(alice_raw.as_bytes()),
            "labelIds": ["INBOX", "UNREAD"]
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let alice_msg_id = alice_inserted["id"].as_str().unwrap().to_string();
    let alice_thread_id = alice_inserted["threadId"].as_str().unwrap().to_string();

    let (st, bob_inserted) = send_json_req(
        &app,
        "POST",
        "/gmail/v1/users/me/messages",
        Some(TOK_BOB),
        Some(json!({
            "raw": encode_base64url(bob_raw.as_bytes()),
            "labelIds": ["INBOX", "UNREAD"]
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let bob_msg_id = bob_inserted["id"].as_str().unwrap().to_string();
    let bob_thread_id = bob_inserted["threadId"].as_str().unwrap().to_string();

    // Verify FsBlobStore prefixed keys on disk isolate Alice and Bob.
    assert!(
        fs_blobs
            .get(&mailbox_raw_message_blob_key(ALICE, &alice_msg_id))
            .await
            .unwrap()
            .is_some(),
        "Alice raw blob must live under Alice's mailbox prefix"
    );
    assert!(
        fs_blobs
            .get(&mailbox_raw_message_blob_key(BOB, &bob_msg_id))
            .await
            .unwrap()
            .is_some(),
        "Bob raw blob must live under Bob's mailbox prefix"
    );
    assert!(
        fs_blobs
            .get(&mailbox_raw_message_blob_key(ALICE, &bob_msg_id))
            .await
            .unwrap()
            .is_none()
    );

    let alice_atts = state
        .for_mailbox(ALICE)
        .store
        .list_attachment_meta(&alice_msg_id)
        .await
        .unwrap();
    assert_eq!(alice_atts.len(), 1);
    assert!(
        fs_blobs
            .get(&mailbox_attachment_blob_key(
                ALICE,
                &alice_msg_id,
                &alice_atts[0].id
            ))
            .await
            .unwrap()
            .is_some()
    );

    // 3. Messages & Threads isolation across Gmail API and /v1 API.
    let (st, alice_msgs) = send_json_req(
        &app,
        "GET",
        "/gmail/v1/users/me/messages",
        Some(TOK_ALICE),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let alice_ids: Vec<&str> = alice_msgs["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert_eq!(alice_ids, vec![alice_msg_id.as_str()]);

    let (st, _) = send_json_req(
        &app,
        "GET",
        &format!("/gmail/v1/users/me/messages/{bob_msg_id}"),
        Some(TOK_ALICE),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let (st, _) = send_json_req(
        &app,
        "POST",
        &format!("/gmail/v1/users/me/messages/{bob_msg_id}/modify"),
        Some(TOK_ALICE),
        Some(json!({ "removeLabelIds": ["UNREAD"] })),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let (st, _) = send_json_req(
        &app,
        "DELETE",
        &format!("/gmail/v1/users/me/messages/{bob_msg_id}"),
        Some(TOK_ALICE),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let (st, _) = send_json_req(
        &app,
        "GET",
        &format!("/v1/messages/{bob_msg_id}"),
        Some(TOK_ALICE),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let (st, _) = send_json_req(
        &app,
        "POST",
        &format!("/v1/threads/{bob_thread_id}/triage"),
        Some(TOK_ALICE),
        Some(json!({ "mark_read": true })),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // Bob's message is completely untouched and still UNREAD.
    let (st, bob_check) = send_json_req(
        &app,
        "GET",
        &format!("/gmail/v1/users/me/messages/{bob_msg_id}"),
        Some(TOK_BOB),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        bob_check["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "UNREAD")
    );

    // 4. Drafts isolation.
    let (st, alice_draft) = send_json_req(
        &app,
        "POST",
        "/v1/drafts",
        Some(TOK_ALICE),
        Some(json!({
            "to": ["someone@external.test"],
            "subject": "Alice Private Draft",
            "text": "Draft body for Alice"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let alice_draft_id = alice_draft["draft_id"].as_str().unwrap().to_string();

    let (st, bob_drafts) = send_json_req(&app, "GET", "/v1/drafts", Some(TOK_BOB), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(bob_drafts["drafts"].as_array().unwrap().len(), 0);

    let (st, _) = send_json_req(
        &app,
        "DELETE",
        &format!("/v1/drafts/{alice_draft_id}"),
        Some(TOK_BOB),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // 5. Labels & Settings isolation.
    let (st, alice_lbl) = send_json_req(
        &app,
        "POST",
        "/gmail/v1/users/me/labels",
        Some(TOK_ALICE),
        Some(json!({ "name": "SecretProject" })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let alice_lbl_id = alice_lbl["id"].as_str().unwrap().to_string();

    let (st, bob_lbls) = send_json_req(&app, "GET", "/v1/labels", Some(TOK_BOB), None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        !bob_lbls["labels"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l["name"] == "SecretProject"),
        "Bob must not see Alice's custom label"
    );

    // Bob can create a label with the same name independently, and cannot delete Alice's label ID.
    let (st, _) = send_json_req(
        &app,
        "DELETE",
        &format!("/gmail/v1/users/me/labels/{alice_lbl_id}"),
        Some(TOK_BOB),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let (st, bob_lbl) = send_json_req(
        &app,
        "POST",
        "/gmail/v1/users/me/labels",
        Some(TOK_BOB),
        Some(json!({ "name": "SecretProject" })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(bob_lbl["name"], "SecretProject");

    let (st, _) = send_json_req(
        &app,
        "PUT",
        "/gmail/v1/users/me/settings/vacation",
        Some(TOK_ALICE),
        Some(json!({ "enableAutoReply": true, "responseSubject": "Alice OOO" })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, bob_vac) = send_json_req(
        &app,
        "GET",
        "/gmail/v1/users/me/settings/vacation",
        Some(TOK_BOB),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(bob_vac["enableAutoReply"], false);

    let (st, bob_send_as) = send_json_req(
        &app,
        "GET",
        "/gmail/v1/users/me/settings/sendAs",
        Some(TOK_BOB),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(bob_send_as["sendAs"][0]["sendAsEmail"], BOB);

    // 6. History isolation.
    let (st, alice_hist) = send_json_req(
        &app,
        "GET",
        "/gmail/v1/users/me/history?startHistoryId=1",
        Some(TOK_ALICE),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let hist_str = alice_hist.to_string();
    assert!(!hist_str.contains(&bob_msg_id));
    assert!(!hist_str.contains(&bob_thread_id));

    // 7. FTS5 / `/v1/search` and MCP `/mcp` isolation.
    let (st, alice_search_bob) = send_json_req(
        &app,
        "GET",
        "/v1/search?q=Confidential",
        Some(TOK_ALICE),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(alice_search_bob["messages"].as_array().unwrap().is_empty());

    let (st, bob_search_bob) = send_json_req(
        &app,
        "GET",
        "/v1/search?q=Confidential",
        Some(TOK_BOB),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(bob_search_bob["messages"].as_array().unwrap().len(), 1);
    assert_eq!(bob_search_bob["messages"][0]["id"], bob_msg_id);

    // MCP search_emails as Alice must NOT find Bob's message, and read_email on Bob's ID fails.
    let (st, mcp_alice_search) = send_json_req(
        &app,
        "POST",
        "/mcp",
        Some(TOK_ALICE),
        Some(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "search_emails",
                "arguments": { "query": "Confidential" }
            }
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        mcp_alice_search["result"]["structuredContent"]["messages"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let (st, mcp_alice_read_bob) = send_json_req(
        &app,
        "POST",
        "/mcp",
        Some(TOK_ALICE),
        Some(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "read_email",
                "arguments": { "message_id": bob_msg_id }
            }
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(mcp_alice_read_bob["result"]["isError"], true);

    let (st, mcp_bob_search) = send_json_req(
        &app,
        "POST",
        "/mcp",
        Some(TOK_BOB),
        Some(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "search_emails",
                "arguments": { "query": "Confidential" }
            }
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        mcp_bob_search["result"]["structuredContent"]["messages"][0]["id"],
        bob_msg_id
    );

    // 8. Same explicit message ID in two mailboxes never collides in MailStore or FsBlobStore.
    let shared_id_input = |who: &str, body: &str| NewMessageInput {
        id: Some("shared_msg_id_42".to_string()),
        thread_id: None,
        label_ids: vec![LABEL_INBOX.to_string()],
        raw_rfc2822: format!("From: sys@test\r\nTo: {who}\r\nSubject: {who}\r\n\r\n{body}")
            .into_bytes(),
        snippet: body.to_string(),
        internal_date_ms: 1_700_000_050_000,
        subject: format!("Shared ID for {who}"),
        from_addr: "sys@test".to_string(),
        to_addrs: vec![who.to_string()],
        cc_addrs: vec![],
        bcc_addrs: vec![],
        text_body: body.to_string(),
        html_body: None,
        rfc822_message_id: None,
        in_reply_to: None,
        references_header: None,
        resend_id: None,
        upstream_gmail_id: None,
        upstream_thread_id: None,
        source: "local".to_string(),
        is_answered: false,
        is_deleted: false,
        attachments: vec![NewAttachmentInput {
            part_id: "1".to_string(),
            filename: Some("same.txt".to_string()),
            content_type: "text/plain".to_string(),
            content_id: None,
            data: body.as_bytes().to_vec(),
        }],
    };
    let alice_state = state.for_mailbox(ALICE);
    let bob_state = state.for_mailbox(BOB);
    let m_a = alice_state
        .store
        .insert_message(shared_id_input(ALICE, "ALICE_ONLY_BLOB"))
        .await
        .unwrap();
    alice_state.post_store_message(&m_a).await.unwrap();
    let m_b = bob_state
        .store
        .insert_message(shared_id_input(BOB, "BOB_ONLY_BLOB"))
        .await
        .unwrap();
    bob_state.post_store_message(&m_b).await.unwrap();

    let raw_a = String::from_utf8(alice_state.load_raw_rfc2822(&m_a).await.unwrap()).unwrap();
    let raw_b = String::from_utf8(bob_state.load_raw_rfc2822(&m_b).await.unwrap()).unwrap();
    assert!(raw_a.contains("ALICE_ONLY_BLOB"));
    assert!(raw_b.contains("BOB_ONLY_BLOB"));
    assert!(!raw_a.contains("BOB_ONLY_BLOB"));
    assert!(!raw_b.contains("ALICE_ONLY_BLOB"));

    // 9. Human-in-the-loop approvals queue isolation (fresh router with require_approval=true).
    let approval_cfg = multi_mailbox_config(storage, true);
    let approval_state = AppState::with_backends(approval_cfg, store.clone(), Arc::new(NoopResend))
        .with_transport(Arc::new(RecordingTransport {
            calls: Arc::new(AtomicUsize::new(0)),
        }));
    let approval_app = build_router(approval_state);

    let (st, held) = send_json_req(
        &approval_app,
        "POST",
        "/v1/messages/send",
        Some(TOK_ALICE),
        Some(json!({
            "to": ["external@partner.test"],
            "subject": "Alice Needs Approval",
            "text": "Please approve"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    let approval_id = held["approval_id"].as_str().unwrap().to_string();

    let (st, bob_approvals) =
        send_json_req(&approval_app, "GET", "/v1/approvals", Some(TOK_BOB), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(bob_approvals["count"], 0);

    let (st, _) = send_json_req(
        &approval_app,
        "POST",
        &format!("/v1/approvals/{approval_id}/approve"),
        Some(TOK_BOB),
        Some(json!({ "note": "unauthorized cross-mailbox approve" })),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let (st, alice_approvals) =
        send_json_req(&approval_app, "GET", "/v1/approvals", Some(TOK_ALICE), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(alice_approvals["count"], 1);
    assert_eq!(alice_approvals["approvals"][0]["id"], approval_id);

    // Keep thread_id used to silence any unused var warnings.
    assert!(!alice_thread_id.is_empty());
}

#[tokio::test]
async fn multi_mailbox_strict_isolation_sqlite_and_fs_blobs() {
    run_full_isolation_suite(StorageBackend::Sqlite).await;
}

#[tokio::test]
async fn multi_mailbox_strict_isolation_memory_and_fs_blobs() {
    run_full_isolation_suite(StorageBackend::Memory).await;
}

struct MockTopicEmbeddings;

#[async_trait]
impl EmbeddingProvider for MockTopicEmbeddings {
    async fn embed(&self, texts: &[String]) -> AppResult<Vec<Vec<f32>>> {
        Ok(texts
            .iter()
            .map(|t| {
                let lower = t.to_ascii_lowercase();
                if lower.contains("outage") || lower.contains("downtime") {
                    vec![1.0, 0.0, 0.0]
                } else if lower.contains("invoice") || lower.contains("billing") {
                    vec![0.0, 1.0, 0.0]
                } else {
                    vec![0.0, 0.0, 1.0]
                }
            })
            .collect())
    }

    fn model_name(&self) -> &str {
        "mock-multi-mailbox-embed"
    }
}

#[tokio::test]
async fn multi_mailbox_hybrid_vector_search_isolation() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("hybrid.db");

    for backend in [StorageBackend::Sqlite, StorageBackend::Memory] {
        let mut cfg = multi_mailbox_config(backend, false);
        cfg.db_path = db_path.clone();

        let (store, vectors): (
            Arc<dyn MailStore>,
            Arc<dyn nogml::search_index::VectorStore>,
        ) = match backend {
            StorageBackend::Sqlite => (
                Arc::new(SqliteStore::open(&db_path, ALICE).unwrap()),
                Arc::new(SqliteVectorStore::open_for_mailbox(&db_path, ALICE).unwrap()),
            ),
            StorageBackend::Memory => (
                Arc::new(MemoryStore::new(ALICE)),
                Arc::new(MemoryVectorStore::for_mailbox_new(ALICE)),
            ),
            StorageBackend::Postgres => unreachable!("hybrid test runs sqlite and memory"),
        };

        let search = Arc::new(HybridSearchIndex::new(
            store.clone(),
            Arc::new(MockTopicEmbeddings),
            vectors,
        ));
        let state = AppState::with_backends(cfg, store, Arc::new(NoopResend)).with_search(search);

        let alice_state = state.for_mailbox(ALICE);
        let bob_state = state.for_mailbox(BOB);

        let mk = |id: &str, subj: &str, body: &str| NewMessageInput {
            id: Some(id.to_string()),
            thread_id: None,
            label_ids: vec![LABEL_INBOX.to_string()],
            raw_rfc2822: format!("Subject: {subj}\r\n\r\n{body}").into_bytes(),
            snippet: body.to_string(),
            internal_date_ms: 1_700_000_000_000,
            subject: subj.to_string(),
            from_addr: "ops@vendor.test".to_string(),
            to_addrs: vec![],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: body.to_string(),
            html_body: None,
            rfc822_message_id: None,
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "local".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: vec![],
        };

        let m_alice = alice_state
            .store
            .insert_message(mk(
                "same_id_1",
                "Alice cluster outage",
                "Primary node outage",
            ))
            .await
            .unwrap();
        alice_state.post_store_message(&m_alice).await.unwrap();

        let m_bob_outage = bob_state
            .store
            .insert_message(mk("same_id_1", "Bob database outage", "Replica outage"))
            .await
            .unwrap();
        bob_state.post_store_message(&m_bob_outage).await.unwrap();

        let m_bob_inv = bob_state
            .store
            .insert_message(mk("bob_inv", "Bob Q4 invoice", "Invoice due"))
            .await
            .unwrap();
        bob_state.post_store_message(&m_bob_inv).await.unwrap();

        // Semantic query "downtime" (zero lexical overlap) returns strictly each mailbox's own message.
        let alice_hits = alice_state
            .search
            .search(&AiSearchQuery {
                q: Some("downtime".to_string()),
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(alice_hits.messages.len(), 1);
        assert_eq!(alice_hits.messages[0].subject, "Alice cluster outage");

        // Semantic query "billing" as Alice returns 0 hits (Bob's invoice is completely isolated).
        let alice_billing = alice_state
            .search
            .search(&AiSearchQuery {
                q: Some("billing".to_string()),
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(alice_billing.messages.is_empty());

        let bob_billing = bob_state
            .search
            .search(&AiSearchQuery {
                q: Some("billing".to_string()),
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(bob_billing.messages.len(), 1);
        assert_eq!(bob_billing.messages[0].id, "bob_inv");
    }
}

#[tokio::test]
async fn multi_mailbox_resend_and_ses_webhooks_and_sse_isolation() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("webhooks.db");
    let mut cfg = multi_mailbox_config(StorageBackend::Sqlite, false);
    cfg.db_path = db_path.clone();
    cfg.allow_insecure_webhooks = true;

    let store = Arc::new(SqliteStore::open(&db_path, ALICE).unwrap());
    let state = AppState::with_backends(cfg, store, Arc::new(NoopResend)).with_transport(Arc::new(
        RecordingTransport {
            calls: Arc::new(AtomicUsize::new(0)),
        },
    ));
    let app = build_router(state.clone());

    // Spawn real TCP HTTP server so we can open real concurrent SSE streams for Alice and Bob.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.changed().await;
            })
            .await
            .unwrap();
    });

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    // Open live SSE streams for BOTH Alice and Bob.
    let mut alice_sse = client
        .get(format!("{base}/v1/events"))
        .bearer_auth(TOK_ALICE)
        .send()
        .await
        .unwrap();
    assert_eq!(alice_sse.status(), StatusCode::OK);

    let mut bob_sse = client
        .get(format!("{base}/v1/events"))
        .bearer_auth(TOK_BOB)
        .send()
        .await
        .unwrap();
    assert_eq!(bob_sse.status(), StatusCode::OK);

    // Give SSE handlers a moment to subscribe to EventBus.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1. Resend inbound webhook addressed ONLY to Bob.
    let bob_webhook = json!({
        "type": "email.received",
        "created_at": "2026-01-02T10:00:00Z",
        "data": {
            "email_id": "re_in_bob_1",
            "from": "sender@external.test",
            "to": ["Bob <bob@example.com>"],
            "subject": "Only For Bob",
            "message_id": "<only-bob-1@external.test>"
        }
    });
    let resp = client
        .post(format!("{base}/webhooks/resend"))
        .json(&bob_webhook)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "received");
    assert_eq!(body["mailbox_id"], BOB);

    // Bob's SSE receives the event; Alice's SSE MUST NOT receive anything.
    let bob_chunk = tokio::time::timeout(Duration::from_secs(2), bob_sse.chunk())
        .await
        .expect("Bob SSE should receive event promptly")
        .unwrap()
        .unwrap();
    let bob_sse_text = String::from_utf8_lossy(&bob_chunk);
    assert!(
        bob_sse_text.contains("Only For Bob") && bob_sse_text.contains(BOB),
        "unexpected Bob SSE payload: {bob_sse_text}"
    );

    let alice_timeout = tokio::time::timeout(Duration::from_millis(250), alice_sse.chunk()).await;
    assert!(
        alice_timeout.is_err(),
        "Alice SSE must NOT receive Bob's inbound webhook event"
    );

    // Verify mailbox contents via HTTP API.
    let alice_msgs: Value = client
        .get(format!("{base}/v1/messages"))
        .bearer_auth(TOK_ALICE)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(alice_msgs["messages"].as_array().unwrap().is_empty());

    let bob_msgs: Value = client
        .get(format!("{base}/v1/messages"))
        .bearer_auth(TOK_BOB)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(bob_msgs["messages"].as_array().unwrap().len(), 1);
    assert_eq!(bob_msgs["messages"][0]["subject"], "Only For Bob");

    // 2. Resend webhook addressed to BOTH Alice (To) and Bob (Cc) delivers to both.
    let both_webhook = json!({
        "type": "email.received",
        "created_at": "2026-01-02T10:05:00Z",
        "data": {
            "email_id": "re_in_both_1",
            "from": "team@external.test",
            "to": [ALICE],
            "cc": [BOB],
            "subject": "Shared Team Notice",
            "message_id": "<shared-notice-1@external.test>"
        }
    });
    let both_resp: Value = client
        .post(format!("{base}/webhooks/resend"))
        .json(&both_webhook)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(both_resp["status"], "received");
    assert_eq!(both_resp["deliveries"].as_array().unwrap().len(), 2);

    // Alice's SSE now receives the shared notice.
    let alice_chunk = tokio::time::timeout(Duration::from_secs(2), alice_sse.chunk())
        .await
        .expect("Alice SSE should receive event addressed to Alice")
        .unwrap()
        .unwrap();
    let alice_sse_text = String::from_utf8_lossy(&alice_chunk);
    assert!(
        alice_sse_text.contains("Shared Team Notice") && alice_sse_text.contains(ALICE),
        "unexpected Alice SSE payload: {alice_sse_text}"
    );

    // 3. Resend webhook addressed to unknown recipient is ignored.
    let unknown_webhook = json!({
        "type": "email.received",
        "created_at": "2026-01-02T10:06:00Z",
        "data": {
            "email_id": "re_in_unknown_1",
            "from": "stranger@external.test",
            "to": ["nobody@other.test"],
            "subject": "Wrong Address"
        }
    });
    let unk_resp: Value = client
        .post(format!("{base}/webhooks/resend"))
        .json(&unknown_webhook)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(unk_resp["status"], "ignored");
    assert_eq!(unk_resp["reason"], "no_matching_local_mailbox");

    // 4. AWS SES webhook addressed ONLY to Bob lands ONLY in Bob's inbox.
    let ses_raw = concat!(
        "From: ses-sender@external.test\r\n",
        "To: bob@example.com\r\n",
        "Subject: SES Only For Bob\r\n",
        "Message-ID: <ses-bob-1@external.test>\r\n",
        "\r\n",
        "Hello Bob via SES!\r\n"
    );
    let ses_inner = json!({
        "notificationType": "Received",
        "mail": {
            "source": "ses-sender@external.test",
            "destination": [BOB],
            "messageId": "ses-id-bob-1",
            "commonHeaders": {
                "from": ["ses-sender@external.test"],
                "to": [BOB],
                "subject": "SES Only For Bob",
                "messageId": "<ses-bob-1@external.test>"
            }
        },
        "content": STANDARD.encode(ses_raw.as_bytes())
    });
    let sns_envelope = json!({
        "Type": "Notification",
        "MessageId": "sns-1",
        "Message": ses_inner.to_string()
    });
    let ses_resp: Value = client
        .post(format!("{base}/webhooks/ses"))
        .json(&sns_envelope)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ses_resp["status"], "received");
    assert_eq!(ses_resp["mailbox_id"], BOB);

    // Alice still has only 1 message (Shared Team Notice); Bob has 3.
    let alice_after: Value = client
        .get(format!("{base}/v1/messages"))
        .bearer_auth(TOK_ALICE)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(alice_after["messages"].as_array().unwrap().len(), 1);

    let bob_after: Value = client
        .get(format!("{base}/v1/messages"))
        .bearer_auth(TOK_BOB)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(bob_after["messages"].as_array().unwrap().len(), 3);

    // 5. SSE replay (`since_id=0`) as Alice NEVER leaks Bob's events.
    let replay_events = state.for_mailbox(ALICE).events.events_since(0, 100);
    assert!(!replay_events.is_empty());
    assert!(
        replay_events.iter().all(|e| e.mailbox_id == ALICE),
        "Alice replay buffer must never include Bob's events"
    );

    drop(alice_sse);
    drop(bob_sse);
    drop(client);
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

async fn read_imap_until_tag(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    tag: &str,
) -> String {
    let mut collected = String::new();
    let prefix = format!("{tag} ");
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await.unwrap();
        assert!(n > 0, "unexpected EOF while waiting for {tag}");
        collected.push_str(&line);
        if line.starts_with(&prefix) {
            return collected;
        }
    }
}

#[tokio::test]
async fn multi_mailbox_simultaneous_imap_clients_and_idle_isolation() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("imap.db");
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let imap_addr: SocketAddr = probe.local_addr().unwrap();
    drop(probe);

    let mut cfg = multi_mailbox_config(StorageBackend::Sqlite, false);
    cfg.db_path = db_path.clone();
    cfg.allow_insecure_webhooks = true;
    cfg.imap_bind = Some(imap_addr);

    let store = Arc::new(SqliteStore::open(&db_path, ALICE).unwrap());
    let state = AppState::with_backends(cfg, store, Arc::new(NoopResend));
    let app = build_router(state.clone());

    // Seed 1 message in Alice's inbox and 1 in Bob's inbox, plus a custom label for Alice only.
    let alice_state = state.for_mailbox(ALICE);
    let bob_state = state.for_mailbox(BOB);
    alice_state
        .store
        .create_label(nogml::storage::NewLabelInput {
            name: "AliceOnlyFolder".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    let seed_msg = |to: &str, subj: &str| NewMessageInput {
        id: None,
        thread_id: None,
        label_ids: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
        raw_rfc2822: format!("From: seed@test\r\nTo: {to}\r\nSubject: {subj}\r\n\r\nBody")
            .into_bytes(),
        snippet: "Body".to_string(),
        internal_date_ms: 1_700_000_000_000,
        subject: subj.to_string(),
        from_addr: "seed@test".to_string(),
        to_addrs: vec![to.to_string()],
        cc_addrs: vec![],
        bcc_addrs: vec![],
        text_body: "Body".to_string(),
        html_body: None,
        rfc822_message_id: None,
        in_reply_to: None,
        references_header: None,
        resend_id: None,
        upstream_gmail_id: None,
        upstream_thread_id: None,
        source: "local".to_string(),
        is_answered: false,
        is_deleted: false,
        attachments: vec![],
    };
    alice_state
        .store
        .insert_message(seed_msg(ALICE, "Alice Initial Mail"))
        .await
        .unwrap();
    bob_state
        .store
        .insert_message(seed_msg(BOB, "Bob Initial Mail"))
        .await
        .unwrap();

    // Start embedded IMAP server on the configured ephemeral port.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let imap_state = state.clone();
    let imap_handle = tokio::spawn(async move {
        let _ = serve_imap(imap_state, shutdown_rx).await;
    });

    // Connect Alice IMAP client with retry until listener binds.
    let alice_stream = loop {
        match TcpStream::connect(imap_addr).await {
            Ok(s) => break s,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    };
    let (a_r, mut a_w) = alice_stream.into_split();
    let mut a_reader = BufReader::new(a_r);
    let mut greeting = String::new();
    a_reader.read_line(&mut greeting).await.unwrap();
    assert!(greeting.starts_with("* OK"));

    // Cross-mailbox credential check: logging in as Alice with Bob's token MUST fail!
    a_w.write_all(format!("A0 LOGIN {ALICE} {TOK_BOB}\r\n").as_bytes())
        .await
        .unwrap();
    let bad_login = read_imap_until_tag(&mut a_reader, "A0").await;
    assert!(
        bad_login.contains("A0 NO"),
        "Bob's token must not log into Alice's IMAP mailbox: {bad_login}"
    );

    // Alice authenticates properly via LOGIN.
    a_w.write_all(format!("A1 LOGIN {ALICE} {TOK_ALICE}\r\n").as_bytes())
        .await
        .unwrap();
    let a_login = read_imap_until_tag(&mut a_reader, "A1").await;
    assert!(a_login.contains("A1 OK"));

    // Bob connects simultaneously and authenticates via AUTHENTICATE PLAIN.
    let bob_stream = TcpStream::connect(imap_addr).await.unwrap();
    let (b_r, mut b_w) = bob_stream.into_split();
    let mut b_reader = BufReader::new(b_r);
    let mut b_greeting = String::new();
    b_reader.read_line(&mut b_greeting).await.unwrap();
    let plain_b64 = STANDARD.encode(format!("\0{BOB}\0{TOK_BOB}").as_bytes());
    b_w.write_all(format!("B1 AUTHENTICATE PLAIN {plain_b64}\r\n").as_bytes())
        .await
        .unwrap();
    let b_auth = read_imap_until_tag(&mut b_reader, "B1").await;
    assert!(b_auth.contains("B1 OK"));

    // Verify LIST folder isolation: Alice sees AliceOnlyFolder, Bob does NOT.
    a_w.write_all(b"A2 LIST \"\" \"*\"\r\n").await.unwrap();
    let a_list = read_imap_until_tag(&mut a_reader, "A2").await;
    assert!(a_list.contains("AliceOnlyFolder"));

    b_w.write_all(b"B2 LIST \"\" \"*\"\r\n").await.unwrap();
    let b_list = read_imap_until_tag(&mut b_reader, "B2").await;
    assert!(!b_list.contains("AliceOnlyFolder"));

    // Both SELECT INBOX and verify subject isolation via FETCH.
    a_w.write_all(b"A3 SELECT INBOX\r\n").await.unwrap();
    let a_sel = read_imap_until_tag(&mut a_reader, "A3").await;
    assert!(a_sel.contains("* 1 EXISTS"));
    a_w.write_all(b"A4 FETCH 1 (BODY.PEEK[HEADER.FIELDS (SUBJECT)])\r\n")
        .await
        .unwrap();
    let a_fetch = read_imap_until_tag(&mut a_reader, "A4").await;
    assert!(a_fetch.contains("Alice Initial Mail"));
    assert!(!a_fetch.contains("Bob Initial Mail"));

    b_w.write_all(b"B3 SELECT INBOX\r\n").await.unwrap();
    let b_sel = read_imap_until_tag(&mut b_reader, "B3").await;
    assert!(b_sel.contains("* 1 EXISTS"));
    b_w.write_all(b"B4 FETCH 1 (BODY.PEEK[HEADER.FIELDS (SUBJECT)])\r\n")
        .await
        .unwrap();
    let b_fetch = read_imap_until_tag(&mut b_reader, "B4").await;
    assert!(b_fetch.contains("Bob Initial Mail"));
    assert!(!b_fetch.contains("Alice Initial Mail"));

    // Both Alice and Bob enter IDLE simultaneously.
    a_w.write_all(b"A5 IDLE\r\n").await.unwrap();
    let mut a_idle_ack = String::new();
    a_reader.read_line(&mut a_idle_ack).await.unwrap();
    assert!(a_idle_ack.starts_with("+ idling"));

    b_w.write_all(b"B5 IDLE\r\n").await.unwrap();
    let mut b_idle_ack = String::new();
    b_reader.read_line(&mut b_idle_ack).await.unwrap();
    assert!(b_idle_ack.starts_with("+ idling"));

    // Deliver a Resend inbound webhook addressed ONLY to Bob!
    let (st, hook_resp) = send_json_req(
        &app,
        "POST",
        "/webhooks/resend",
        None,
        Some(json!({
            "type": "email.received",
            "created_at": "2026-01-02T12:00:00Z",
            "data": {
                "email_id": "re_imap_bob_idle_1",
                "from": "notify@external.test",
                "to": [BOB],
                "subject": "Wake Only Bob IDLE"
            }
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(hook_resp["mailbox_id"], BOB);

    // Bob's IDLE MUST immediately push `* 2 EXISTS`.
    let mut b_push = String::new();
    tokio::time::timeout(Duration::from_secs(2), b_reader.read_line(&mut b_push))
        .await
        .expect("Bob IDLE should receive EXISTS")
        .unwrap();
    assert!(
        b_push.contains("2 EXISTS"),
        "expected `* 2 EXISTS` for Bob, got: {b_push}"
    );

    // Alice's IDLE MUST remain silent (no wake-up, no untagged EXISTS).
    let mut a_probe = String::new();
    let a_wait =
        tokio::time::timeout(Duration::from_millis(250), a_reader.read_line(&mut a_probe)).await;
    assert!(
        a_wait.is_err(),
        "Alice IDLE must NOT wake on Bob's inbound mail, got: {a_probe}"
    );

    // Clean DONE + LOGOUT for both clients.
    a_w.write_all(b"DONE\r\n").await.unwrap();
    let a_done = read_imap_until_tag(&mut a_reader, "A5").await;
    assert!(a_done.contains("A5 OK"));
    assert!(!a_done.contains("EXISTS"));

    b_w.write_all(b"DONE\r\n").await.unwrap();
    let b_done = read_imap_until_tag(&mut b_reader, "B5").await;
    assert!(b_done.contains("B5 OK"));

    let _ = shutdown_tx.send(true);
    let _ = imap_handle.await;
}

#[tokio::test]
async fn multi_mailbox_sync_state_isolation_and_sqlite_v1_migration() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("legacy_v1.db");

    // 1. Construct a legacy v1 SQLite database WITHOUT `mailbox_id` columns.
    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE meta (key TEXT PRIMARY KEY, int_val INTEGER, text_val TEXT);
            INSERT INTO meta (key, int_val) VALUES ('history_id', 7);
            INSERT INTO meta (key, int_val) VALUES ('next_uid_validity', 50);

            CREATE TABLE labels (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                label_type TEXT NOT NULL,
                message_list_visibility TEXT,
                label_list_visibility TEXT,
                color_text TEXT,
                color_background TEXT,
                uid_validity INTEGER NOT NULL,
                uid_next INTEGER NOT NULL DEFAULT 1,
                upstream_label_id TEXT UNIQUE
            );
            INSERT INTO labels (id, name, label_type, uid_validity, uid_next)
            VALUES ('INBOX', 'INBOX', 'system', 2, 2);

            CREATE TABLE imap_meta (mailbox_name TEXT PRIMARY KEY, uid_validity INTEGER NOT NULL, uid_next INTEGER NOT NULL DEFAULT 1);
            INSERT INTO imap_meta VALUES ('[Gmail]/All Mail', 1, 2);

            CREATE TABLE imap_expunged_uids (mailbox_key TEXT NOT NULL, imap_uid INTEGER NOT NULL, modseq INTEGER NOT NULL, PRIMARY KEY (mailbox_key, imap_uid));

            CREATE TABLE messages (
                id TEXT PRIMARY KEY,
                thread_id TEXT NOT NULL,
                raw_rfc2822 BLOB NOT NULL,
                snippet TEXT NOT NULL,
                history_id INTEGER NOT NULL,
                internal_date_ms INTEGER NOT NULL,
                size_estimate INTEGER NOT NULL,
                subject TEXT NOT NULL,
                from_addr TEXT NOT NULL,
                to_addrs_json TEXT NOT NULL,
                cc_addrs_json TEXT NOT NULL,
                bcc_addrs_json TEXT NOT NULL,
                text_body TEXT NOT NULL,
                html_body TEXT,
                has_attachments INTEGER NOT NULL DEFAULT 0,
                rfc822_message_id TEXT,
                rfc822_message_id_norm TEXT,
                in_reply_to TEXT,
                references_header TEXT,
                resend_id TEXT,
                delivery_status TEXT,
                upstream_gmail_id TEXT UNIQUE,
                upstream_thread_id TEXT,
                source TEXT NOT NULL DEFAULT 'local',
                all_mail_uid INTEGER NOT NULL,
                is_answered INTEGER NOT NULL DEFAULT 0,
                is_deleted INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO messages VALUES (
                'legacy_m1', 'legacy_t1', X'48656C6C6F', 'Legacy snippet', 7, 1700000000000, 5,
                'Legacy V1 Subject', 'old@vendor.test', '["alice@example.com"]', '[]', '[]',
                'Legacy searchable body content', NULL, 0, '<legacy-1@vendor.test>', '<legacy-1@vendor.test>',
                NULL, NULL, NULL, NULL, NULL, NULL, 'local', 1, 0, 0
            );

            CREATE TABLE message_labels (message_id TEXT NOT NULL, label_id TEXT NOT NULL, imap_uid INTEGER NOT NULL, PRIMARY KEY (message_id, label_id));
            INSERT INTO message_labels VALUES ('legacy_m1', 'INBOX', 1);

            CREATE TABLE attachments (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, part_id TEXT NOT NULL, filename TEXT, content_type TEXT NOT NULL, content_id TEXT, size_bytes INTEGER NOT NULL, data BLOB NOT NULL);
            CREATE TABLE drafts (id TEXT PRIMARY KEY, message_id TEXT NOT NULL UNIQUE, updated_at_ms INTEGER NOT NULL);
            CREATE TABLE history_events (id INTEGER PRIMARY KEY AUTOINCREMENT, history_id INTEGER NOT NULL, kind TEXT NOT NULL, message_id TEXT NOT NULL, thread_id TEXT NOT NULL, label_ids_json TEXT NOT NULL, context_labels_json TEXT NOT NULL DEFAULT '[]');
            CREATE VIRTUAL TABLE messages_fts USING fts5(message_id UNINDEXED, subject, from_addr, to_addrs, cc_addrs, text_body, snippet);
            CREATE TABLE sync_state (account_key TEXT PRIMARY KEY, provider TEXT NOT NULL, last_history_id TEXT, imap_mailbox TEXT, imap_uid_validity INTEGER, imap_last_uid INTEGER, last_sync_at_ms INTEGER, last_full_sync_at_ms INTEGER, status TEXT NOT NULL, last_error TEXT, messages_synced INTEGER NOT NULL DEFAULT 0);
            INSERT INTO sync_state (account_key, provider, last_history_id, status, messages_synced) VALUES ('gmail_api:me', 'gmail_api', '999', 'idle', 42);
            CREATE TABLE watch_state (id INTEGER PRIMARY KEY CHECK (id = 1), topic_name TEXT NOT NULL, label_ids_json TEXT NOT NULL, label_filter_behavior TEXT NOT NULL, history_id INTEGER NOT NULL, expiration_ms INTEGER NOT NULL);
            CREATE TABLE settings (key TEXT PRIMARY KEY, value_json TEXT NOT NULL);
            CREATE TABLE pending_approvals (id TEXT PRIMARY KEY, status TEXT NOT NULL, reason TEXT NOT NULL, requester_json TEXT, outbound_message_json TEXT NOT NULL, reply_to_message_id TEXT, thread_id TEXT, draft_id TEXT, sent_message_id TEXT, provider_message_id TEXT, decided_by TEXT, decision_note TEXT, created_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL, decided_at_ms INTEGER);
            "#,
        )
        .unwrap();
    }

    // 2. Reopen with SqliteStore::open -> migrates v1 rows to Alice seamlessly.
    let alice_store = SqliteStore::open(&db_path, ALICE).unwrap();
    let migrated_msg = alice_store
        .get_message("legacy_m1")
        .await
        .unwrap()
        .expect("legacy message should survive v1->v2 migration");
    assert_eq!(migrated_msg.subject, "Legacy V1 Subject");
    assert_eq!(alice_store.current_history_id().await.unwrap(), 7);

    // Rebuilt FTS5 index works for Alice.
    let fts_hits = alice_store
        .search_messages_ai(&AiSearchQuery {
            q: Some("searchable".to_string()),
            limit: 10,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(fts_hits.messages.len(), 1);
    assert_eq!(fts_hits.messages[0].id, "legacy_m1");

    let alice_sync = alice_store
        .get_sync_state("gmail_api:me")
        .await
        .unwrap()
        .expect("legacy sync_state should migrate to Alice");
    assert_eq!(alice_sync.last_history_id.as_deref(), Some("999"));

    // 3. Bob's mailbox handle on the SAME migrated SQLite DB is completely empty and isolated.
    let bob_store = alice_store.for_mailbox(BOB);
    assert!(bob_store.get_message("legacy_m1").await.unwrap().is_none());
    assert!(
        bob_store
            .get_sync_state("gmail_api:me")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(bob_store.current_history_id().await.unwrap(), 1);

    // Bob can save his own sync_state under the exact same account_key without colliding with Alice.
    bob_store
        .save_sync_state(SyncState {
            account_key: "gmail_api:me".to_string(),
            provider: "gmail_api".to_string(),
            last_history_id: Some("123".to_string()),
            status: "idle".to_string(),
            messages_synced: 3,
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(
        alice_store
            .get_sync_state("gmail_api:me")
            .await
            .unwrap()
            .unwrap()
            .last_history_id
            .as_deref(),
        Some("999")
    );
    assert_eq!(
        bob_store
            .get_sync_state("gmail_api:me")
            .await
            .unwrap()
            .unwrap()
            .last_history_id
            .as_deref(),
        Some("123")
    );
}
