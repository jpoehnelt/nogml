//! End-to-end tests for Issue #62:
//! - Graceful shutdown with an active `/v1/events` SSE client connected
//! - Prometheus `/metrics` exposition, auth gating, and live counters/gauges
//! - Hardened `/readyz` probing `MailStore` + external `BlobStore` with sanitized 503 responses
//! - Multi-mailbox CLI maintenance (`nogml storage migrate-blobs` and `nogml search reindex`)

use std::{
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose};
use http_body_util::BodyExt;
use nogml::{
    AppState,
    blob::{
        BlobStore, FsBlobStore, MemoryBlobStore, mailbox_attachment_blob_key,
        mailbox_raw_message_blob_key,
    },
    build_router,
    config::{Config, SearchBackend, StorageBackend},
    error::{AppError, AppResult},
    filter::{FilterDecision, InboundFilter, InboundMessage},
    imap::serve_plain_listener,
    metrics::PROMETHEUS_CONTENT_TYPE,
    models::LABEL_INBOX,
    resend::HttpResendClient,
    storage::{
        AiSearchQuery, MailStore, MemoryStore, NewAttachmentInput, NewMessageInput, SqliteStore,
        SyncState,
    },
    sync::{PullReport, SyncRunOptions, SyncSource, run_sync_source},
    transport::{MailTransport, OutboundMessage, SendOutcome, TransportCapabilities},
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{net::TcpListener, sync::watch};
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, Request as WiremockRequest, ResponseTemplate,
    matchers::{method, path},
};

struct NoopTransport;

#[async_trait]
impl MailTransport for NoopTransport {
    fn name(&self) -> &'static str {
        "noop"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            provider: "noop".to_string(),
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
        Ok(SendOutcome {
            provider: "noop".to_string(),
            provider_message_id: "msg_noop_1".to_string(),
        })
    }
}

struct KeywordTestFilter;

#[async_trait]
impl InboundFilter for KeywordTestFilter {
    async fn evaluate(&self, msg: &InboundMessage) -> AppResult<FilterDecision> {
        if msg.subject.contains("REJECT_ME") {
            Ok(FilterDecision::Reject {
                reason: "blocked by test filter".to_string(),
            })
        } else if msg.subject.contains("TAG_ME") {
            Ok(FilterDecision::Mutate {
                add_labels: vec!["TAGGED".to_string()],
                remove_labels: vec![],
                skip_inbox: false,
            })
        } else {
            Ok(FilterDecision::Allow)
        }
    }

    fn backend_name(&self) -> &'static str {
        "keyword_test"
    }
}

struct FailingBlobStore {
    secret_error: String,
}

#[async_trait]
impl BlobStore for FailingBlobStore {
    async fn put(&self, _key: &str, _bytes: &[u8]) -> AppResult<()> {
        Err(AppError::Storage(self.secret_error.clone()))
    }

    async fn get(&self, _key: &str) -> AppResult<Option<Vec<u8>>> {
        Err(AppError::Storage(self.secret_error.clone()))
    }

    async fn delete(&self, _key: &str) -> AppResult<()> {
        Err(AppError::Storage(self.secret_error.clone()))
    }

    fn backend_name(&self) -> &'static str {
        "s3"
    }
}

struct ToggleSyncSource {
    fail: Arc<AtomicBool>,
}

#[async_trait]
impl SyncSource for ToggleSyncSource {
    fn provider_name(&self) -> &'static str {
        "test_sync"
    }

    fn account_key(&self, config: &Config) -> String {
        format!("test:{}", config.user_email)
    }

    async fn pull(
        &self,
        _state: &AppState,
        _sync_state: &mut SyncState,
        _opts: &SyncRunOptions,
    ) -> AppResult<PullReport> {
        if self.fail.load(Ordering::SeqCst) {
            Err(AppError::Upstream {
                status: 503,
                message: "upstream unavailable".to_string(),
            })
        } else {
            Ok(PullReport::default())
        }
    }
}

fn parse_metric_value(text: &str, key: &str) -> Option<i64> {
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix(key)
            && let Some(val_str) = rest.strip_prefix(' ')
        {
            return val_str.trim().parse::<i64>().ok();
        }
    }
    None
}

#[tokio::test]
async fn sse_active_connection_shuts_down_promptly_on_trigger_shutdown() {
    let cfg = Config::for_test();
    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store, resend);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let server_state = state.clone();
    let server_handle = tokio::spawn(async move {
        let router = build_router(server_state);
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.changed().await;
            })
            .await
            .unwrap();
    });

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let sse_resp = client
        .get(format!("{base_url}/v1/events"))
        .send()
        .await
        .unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);

    // Wait briefly for handler registration and confirm active SSE gauge is 1.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let metrics_text = client
        .get(format!("{base_url}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        parse_metric_value(&metrics_text, "nogml_sse_active_connections"),
        Some(1)
    );

    // Keep the SSE client response alive while triggering graceful shutdown.
    let started = Instant::now();
    state.trigger_shutdown();
    let _ = shutdown_tx.send(true);

    tokio::time::timeout(Duration::from_secs(2), server_handle)
        .await
        .expect("axum::serve hung past 2s with an active SSE client connected")
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "shutdown took {:?}",
        started.elapsed()
    );

    // Drain/drop client stream and verify RAII gauge returned to 0.
    let _ = sse_resp.bytes().await;
    assert_eq!(state.metrics.sse_active_connections(), 0);
}

#[tokio::test]
async fn metrics_endpoint_requires_auth_and_tracks_live_counters_and_gauges() {
    let mut cfg = Config::for_test();
    cfg.auth_tokens = vec!["metrics-secret".to_string()];
    cfg.allowed_recipients = vec!["@allowed.example".to_string()];

    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store, resend)
        .with_transport(Arc::new(NoopTransport))
        .with_filter(Arc::new(KeywordTestFilter));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    let (http_tx, mut http_rx) = watch::channel(false);
    let http_state = state.clone();
    let http_handle = tokio::spawn(async move {
        let router = build_router(http_state);
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = http_rx.changed().await;
            })
            .await
            .unwrap();
    });

    // Also start an IMAP listener to verify `nogml_imap_active_connections` RAII gauge.
    let imap_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let imap_addr = imap_listener.local_addr().unwrap();
    let (imap_tx, imap_rx) = watch::channel(false);
    let imap_state = state.clone();
    let imap_handle = tokio::spawn(async move {
        let _ = serve_plain_listener(imap_listener, imap_state, None, imap_rx).await;
    });

    let client = reqwest::Client::builder().no_proxy().build().unwrap();

    // 1. `/metrics` must require bearer authentication when auth tokens are configured.
    let unauth = client
        .get(format!("{base_url}/metrics"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

    // 2. Active SSE connection increments `nogml_sse_active_connections` 0 -> 1 -> 0.
    let sse_resp = client
        .get(format!("{base_url}/v1/events"))
        .bearer_auth("metrics-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. Active IMAP connection increments `nogml_imap_active_connections` 0 -> 1 -> 0.
    let imap_stream = tokio::net::TcpStream::connect(imap_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let during = client
        .get(format!("{base_url}/metrics"))
        .bearer_auth("metrics-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(during.status(), StatusCode::OK);
    assert_eq!(
        during
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some(PROMETHEUS_CONTENT_TYPE)
    );
    let during_text = during.text().await.unwrap();
    assert_eq!(
        parse_metric_value(&during_text, "nogml_sse_active_connections"),
        Some(1)
    );
    assert_eq!(
        parse_metric_value(&during_text, "nogml_imap_active_connections"),
        Some(1)
    );

    // Drop SSE and IMAP client connections and verify gauges drop back to 0.
    drop(sse_resp);
    drop(imap_stream);
    for _ in 0..30 {
        if state.metrics.sse_active_connections() == 0
            && state.metrics.imap_active_connections() == 0
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(state.metrics.sse_active_connections(), 0);
    assert_eq!(state.metrics.imap_active_connections(), 0);

    // 4. Outbound send: one allowed, one denied by recipient allowlist.
    let send_ok = client
        .post(format!("{base_url}/v1/messages/send"))
        .bearer_auth("metrics-secret")
        .json(&json!({
            "to": ["partner@allowed.example"],
            "subject": "Allowed message",
            "text": "Hello"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(send_ok.status(), StatusCode::OK);

    let send_denied = client
        .post(format!("{base_url}/v1/messages/send"))
        .bearer_auth("metrics-secret")
        .json(&json!({
            "to": ["outsider@blocked.example"],
            "subject": "Blocked message",
            "text": "Hello"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(send_denied.status(), StatusCode::FORBIDDEN);

    // 5. Inbound import: one mutated (stored -> received), one rejected.
    let raw_mutate = general_purpose::URL_SAFE_NO_PAD.encode(
        b"From: sender@example.com\r\nTo: agent@example.com\r\nSubject: TAG_ME hello\r\n\r\nBody",
    );
    let import_ok = client
        .post(format!("{base_url}/gmail/v1/users/me/messages/import"))
        .bearer_auth("metrics-secret")
        .json(&json!({ "raw": raw_mutate }))
        .send()
        .await
        .unwrap();
    assert_eq!(import_ok.status(), StatusCode::OK);

    let raw_reject = general_purpose::URL_SAFE_NO_PAD.encode(
        b"From: sender@example.com\r\nTo: agent@example.com\r\nSubject: REJECT_ME spam\r\n\r\nBody",
    );
    let import_rej = client
        .post(format!("{base_url}/gmail/v1/users/me/messages/import"))
        .bearer_auth("metrics-secret")
        .json(&json!({ "raw": raw_reject }))
        .send()
        .await
        .unwrap();
    assert_eq!(import_rej.status(), StatusCode::FORBIDDEN);

    // 6. Sync runs: one ok, one error.
    let fail_flag = Arc::new(AtomicBool::new(false));
    let sync_src = ToggleSyncSource {
        fail: fail_flag.clone(),
    };
    run_sync_source(&state, &sync_src, SyncRunOptions::default())
        .await
        .unwrap();
    fail_flag.store(true, Ordering::SeqCst);
    assert!(
        run_sync_source(&state, &sync_src, SyncRunOptions::default())
            .await
            .is_err()
    );

    // Scrape `/metrics` and verify all live counters & gauges.
    let final_text = client
        .get(format!("{base_url}/metrics"))
        .bearer_auth("metrics-secret")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(
        parse_metric_value(&final_text, "nogml_http_requests_total").unwrap_or(0) >= 8,
        "expected >= 8 HTTP requests, got:\n{final_text}"
    );
    assert_eq!(
        parse_metric_value(&final_text, "nogml_messages_sent_total"),
        Some(1)
    );
    assert_eq!(
        parse_metric_value(&final_text, "nogml_messages_received_total"),
        Some(1)
    );
    assert_eq!(
        parse_metric_value(&final_text, "nogml_sse_active_connections"),
        Some(0)
    );
    assert_eq!(
        parse_metric_value(&final_text, "nogml_imap_active_connections"),
        Some(0)
    );
    assert_eq!(
        parse_metric_value(&final_text, "nogml_sync_runs_total{status=\"ok\"}"),
        Some(1)
    );
    assert_eq!(
        parse_metric_value(&final_text, "nogml_sync_runs_total{status=\"error\"}"),
        Some(1)
    );
    assert_eq!(
        parse_metric_value(
            &final_text,
            "nogml_filter_decisions_total{decision=\"mutate\"}"
        ),
        Some(1)
    );
    assert_eq!(
        parse_metric_value(
            &final_text,
            "nogml_filter_decisions_total{decision=\"reject\"}"
        ),
        Some(1)
    );
    assert_eq!(
        parse_metric_value(
            &final_text,
            "nogml_policy_decisions_total{decision=\"allow\"}"
        ),
        Some(1)
    );
    assert_eq!(
        parse_metric_value(
            &final_text,
            "nogml_policy_decisions_total{decision=\"deny\"}"
        ),
        Some(1)
    );

    state.trigger_shutdown();
    let _ = http_tx.send(true);
    let _ = imap_tx.send(true);
    http_handle.await.unwrap();
    imap_handle.await.unwrap();
}

#[tokio::test]
async fn readyz_probes_store_and_blobs_and_sanitizes_503_errors() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("readyz.db");

    // 1. Healthy MailStore + external BlobStore -> 200 OK.
    let cfg = Config::for_test();
    let sqlite_store = Arc::new(SqliteStore::open(&db_path, &cfg.user_email).unwrap());
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let healthy_state = AppState::with_backends(cfg.clone(), sqlite_store.clone(), resend.clone())
        .with_blobs(Arc::new(MemoryBlobStore::new()));
    let healthy_app = build_router(healthy_state);

    let res = healthy_app
        .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(body["status"], "ready");
    assert_eq!(body["store"], "ok");
    assert_eq!(body["blobs"], "ok");

    // 2. Failing external BlobStore -> 503 with sanitized JSON (no secret error leak).
    let bad_blob_state = AppState::with_backends(cfg.clone(), sqlite_store.clone(), resend.clone())
        .with_blobs(Arc::new(FailingBlobStore {
            secret_error: "SECRET_S3_CREDENTIALS_LEAK_XYZ".to_string(),
        }));
    let bad_blob_app = build_router(bad_blob_state);

    let res = bad_blob_app
        .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    let raw_text =
        String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(
        !raw_text.contains("SECRET_S3_CREDENTIALS_LEAK_XYZ"),
        "readyz leaked internal blob error: {raw_text}"
    );
    let body: Value = serde_json::from_str(&raw_text).unwrap();
    assert_eq!(body["status"], "not_ready");
    assert_eq!(body["store"], "ok");
    assert_eq!(body["blobs"], "error");
    assert!(body.get("error").is_none());

    // 3. Failing MailStore (drop internal `meta` table) -> 503 sanitized JSON.
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute("DROP TABLE meta", []).unwrap();
    drop(conn);

    let bad_store_state = AppState::with_backends(cfg, sqlite_store, resend);
    let bad_store_app = build_router(bad_store_state);

    let res = bad_store_app
        .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    let raw_text =
        String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(
        !raw_text.contains("no such table"),
        "readyz leaked internal SQLite error: {raw_text}"
    );
    let body: Value = serde_json::from_str(&raw_text).unwrap();
    assert_eq!(body["status"], "not_ready");
    assert_eq!(body["store"], "error");
    assert_eq!(body["blobs"], "ok");
    assert!(body.get("error").is_none());
}

fn sample_message(id: &str, to: &str, subject: &str, body: &str, att_id: &str) -> NewMessageInput {
    let raw = format!("From: sender@vendor.test\r\nTo: {to}\r\nSubject: {subject}\r\n\r\n{body}")
        .into_bytes();
    NewMessageInput {
        id: Some(id.to_string()),
        thread_id: None,
        label_ids: vec![LABEL_INBOX.to_string()],
        raw_rfc2822: raw,
        snippet: body.to_string(),
        internal_date_ms: 1_740_000_000_000,
        subject: subject.to_string(),
        from_addr: "sender@vendor.test".to_string(),
        to_addrs: vec![to.to_string()],
        cc_addrs: vec![],
        bcc_addrs: vec![],
        text_body: body.to_string(),
        html_body: None,
        rfc822_message_id: Some(format!("<{id}@vendor.test>")),
        in_reply_to: None,
        references_header: None,
        resend_id: None,
        upstream_gmail_id: None,
        upstream_thread_id: None,
        source: "local".to_string(),
        is_answered: false,
        is_deleted: false,
        attachments: vec![NewAttachmentInput {
            part_id: "1.2".to_string(),
            filename: Some(format!("{att_id}.txt")),
            content_type: "text/plain".to_string(),
            content_id: None,
            data: format!("attachment payload for {id}").into_bytes(),
        }],
    }
}

#[tokio::test]
async fn cli_migrate_blobs_and_search_reindex_cover_all_mailboxes() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("multi.db");
    let blob_dir = dir.path().join("blobs");

    // Seed two mailboxes in the same SQLite DB: alice@example.com and bob@example.com.
    let base_store = SqliteStore::open(&db_path, "alice@example.com").unwrap();
    let alice_store = base_store.for_mailbox("alice@example.com");
    let bob_store = base_store.for_mailbox("bob@example.com");

    let alice_msg = alice_store
        .insert_message(sample_message(
            "m_alice_1",
            "alice@example.com",
            "Flight departure update",
            "Gate B12 boarding soon",
            "att_alice",
        ))
        .await
        .unwrap();
    let bob_msg = bob_store
        .insert_message(sample_message(
            "m_bob_1",
            "bob@example.com",
            "Quarterly invoice notice",
            "Balance due on Friday",
            "att_bob",
        ))
        .await
        .unwrap();
    let alice_att_id = alice_store
        .list_attachment_meta(&alice_msg.id)
        .await
        .unwrap()[0]
        .id
        .clone();
    let bob_att_id = bob_store.list_attachment_meta(&bob_msg.id).await.unwrap()[0]
        .id
        .clone();
    drop(alice_store);
    drop(bob_store);
    drop(base_store);

    let bin = env!("CARGO_BIN_EXE_nogml");

    // 1. `nogml storage migrate-blobs` must migrate BOTH alice and bob with mailbox-prefixed keys.
    let migrate_out = Command::new(bin)
        .args([
            "storage",
            "migrate-blobs",
            "--to",
            "fs",
            "--storage",
            "sqlite",
            "--db-path",
            db_path.to_str().unwrap(),
            "--blob-backend",
            "inline",
            "--blob-dir",
            blob_dir.to_str().unwrap(),
            "--user-email",
            "alice@example.com",
            "--mailboxes",
            "alice@example.com,bob@example.com",
        ])
        .output()
        .unwrap();
    assert!(
        migrate_out.status.success(),
        "migrate-blobs failed: stderr={}",
        String::from_utf8_lossy(&migrate_out.stderr)
    );

    let migrate_report: Value = serde_json::from_slice(&migrate_out.stdout).unwrap();
    assert_eq!(migrate_report["source_backend"], "inline");
    assert_eq!(migrate_report["target_backend"], "fs");
    assert_eq!(migrate_report["messages_migrated"], 2);
    assert_eq!(migrate_report["attachments_migrated"], 2);

    let mb_reports = migrate_report["mailboxes"].as_array().unwrap();
    assert_eq!(mb_reports.len(), 2);
    assert_eq!(mb_reports[0]["mailbox_id"], "alice@example.com");
    assert_eq!(mb_reports[0]["messages_migrated"], 1);
    assert_eq!(mb_reports[0]["attachments_migrated"], 1);
    assert_eq!(mb_reports[1]["mailbox_id"], "bob@example.com");
    assert_eq!(mb_reports[1]["messages_migrated"], 1);
    assert_eq!(mb_reports[1]["attachments_migrated"], 1);

    let fs_blobs = FsBlobStore::open(&blob_dir).unwrap();
    assert_eq!(
        fs_blobs
            .get(&mailbox_raw_message_blob_key(
                "alice@example.com",
                &alice_msg.id
            ))
            .await
            .unwrap()
            .as_deref(),
        Some(alice_msg.raw_rfc2822.as_slice())
    );
    assert_eq!(
        fs_blobs
            .get(&mailbox_attachment_blob_key(
                "alice@example.com",
                &alice_msg.id,
                &alice_att_id
            ))
            .await
            .unwrap()
            .as_deref(),
        Some(b"attachment payload for m_alice_1".as_slice())
    );
    assert_eq!(
        fs_blobs
            .get(&mailbox_raw_message_blob_key(
                "bob@example.com",
                &bob_msg.id
            ))
            .await
            .unwrap()
            .as_deref(),
        Some(bob_msg.raw_rfc2822.as_slice())
    );
    assert_eq!(
        fs_blobs
            .get(&mailbox_attachment_blob_key(
                "bob@example.com",
                &bob_msg.id,
                &bob_att_id
            ))
            .await
            .unwrap()
            .as_deref(),
        Some(b"attachment payload for m_bob_1".as_slice())
    );

    // 2. `nogml search reindex` must reindex BOTH alice and bob into their scoped vector partitions.
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(|req: &WiremockRequest| {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let inputs: Vec<String> = match &body["input"] {
                Value::String(s) => vec![s.clone()],
                Value::Array(arr) => arr
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect(),
                _ => vec![],
            };
            let data: Vec<Value> = inputs
                .iter()
                .enumerate()
                .map(|(idx, text)| {
                    let lower = text.to_ascii_lowercase();
                    let emb = if lower.contains("flight")
                        || lower.contains("gate")
                        || lower.contains("itinerary")
                    {
                        vec![1.0, 0.0, 0.0]
                    } else if lower.contains("invoice")
                        || lower.contains("balance")
                        || lower.contains("billing")
                    {
                        vec![0.0, 1.0, 0.0]
                    } else {
                        vec![0.0, 0.0, 1.0]
                    };
                    json!({ "index": idx, "embedding": emb })
                })
                .collect();
            ResponseTemplate::new(200).set_body_json(json!({ "data": data }))
        })
        .mount(&mock)
        .await;

    let reindex_out = Command::new(bin)
        .args([
            "search",
            "reindex",
            "--storage",
            "sqlite",
            "--db-path",
            db_path.to_str().unwrap(),
            "--search-backend",
            "hybrid",
            "--user-email",
            "alice@example.com",
            "--mailboxes",
            "alice@example.com,bob@example.com",
        ])
        .env("NOGML_EMBEDDING_BASE_URL", format!("{}/v1", mock.uri()))
        .env("NOGML_EMBEDDING_MODEL", "nomic-embed-text")
        .output()
        .unwrap();
    assert!(
        reindex_out.status.success(),
        "search reindex failed: stderr={}",
        String::from_utf8_lossy(&reindex_out.stderr)
    );

    let reindex_report: Value = serde_json::from_slice(&reindex_out.stdout).unwrap();
    assert_eq!(reindex_report["backend"], "hybrid");
    assert_eq!(reindex_report["indexed"], 2);
    assert_eq!(reindex_report["failed"], 0);
    let reindex_mbs = reindex_report["mailboxes"].as_array().unwrap();
    assert_eq!(reindex_mbs.len(), 2);
    assert_eq!(reindex_mbs[0]["mailbox_id"], "alice@example.com");
    assert_eq!(reindex_mbs[0]["indexed"], 1);
    assert_eq!(reindex_mbs[1]["mailbox_id"], "bob@example.com");
    assert_eq!(reindex_mbs[1]["indexed"], 1);

    // Confirm semantic search works independently for BOTH Alice and Bob.
    let mut cfg = Config {
        storage: StorageBackend::Sqlite,
        db_path: db_path.clone(),
        user_email: "alice@example.com".to_string(),
        mailboxes: vec![
            "alice@example.com".to_string(),
            "bob@example.com".to_string(),
        ],
        search_backend: SearchBackend::Hybrid,
        embedding_base_url: Some(format!("{}/v1", mock.uri())),
        embedding_model: "nomic-embed-text".to_string(),
        ..Config::default()
    };
    cfg.embedding_api_key = None;
    let state = AppState::from_config(cfg).unwrap();

    let alice_hits = state
        .for_mailbox("alice@example.com")
        .search
        .search(&AiSearchQuery {
            q: Some("itinerary".to_string()),
            limit: 10,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        alice_hits
            .messages
            .iter()
            .map(|m| m.id.as_str())
            .collect::<Vec<_>>(),
        vec!["m_alice_1"]
    );

    let bob_hits = state
        .for_mailbox("bob@example.com")
        .search
        .search(&AiSearchQuery {
            q: Some("billing".to_string()),
            limit: 10,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        bob_hits
            .messages
            .iter()
            .map(|m| m.id.as_str())
            .collect::<Vec<_>>(),
        vec!["m_bob_1"]
    );
}
