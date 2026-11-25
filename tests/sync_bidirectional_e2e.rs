use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::Engine as _;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{net::TcpListener, sync::watch};
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path, query_param},
};

use nogml::{
    AppState, build_router,
    config::{Config, StorageBackend, SyncMode},
    error::AppResult,
    events::MailEvent,
    imap::{mime_fmt::parse_raw_to_new_message_input, serve_plain_listener},
    models::{LABEL_INBOX, LABEL_STARRED, LABEL_TRASH, LABEL_UNREAD},
    storage::{MailStore, SqliteStore, SyncState},
    sync::{
        LocalMutation, LocalMutationKind, PullReport, PushReport, SyncRunOptions, SyncSource,
        ingest_synced_message, run_gmail_sync, run_sync_source,
    },
};

fn b64url(raw: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_bytes())
}

fn make_sqlite_state(cfg: Config) -> (TempDir, AppState) {
    let dir = TempDir::new().expect("tempdir");
    let mut cfg = cfg;
    cfg.storage = StorageBackend::Sqlite;
    cfg.db_path = dir.path().join("nogml.db");
    let state = AppState::from_config(cfg).expect("AppState::from_config");
    (dir, state)
}

async fn http_json(app: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("valid JSON response")
    };
    (status, json)
}

// ============================================================================
// 1. Custom `SyncSource` through shared runner (`run_sync_source`)
// ============================================================================

struct CustomJmapSource {
    pushed: Arc<Mutex<Vec<LocalMutation>>>,
}

#[async_trait]
impl SyncSource for CustomJmapSource {
    fn provider_name(&self) -> &'static str {
        "fastmail_jmap"
    }

    fn account_key(&self, config: &Config) -> String {
        format!("fastmail_jmap:{}", config.user_email)
    }

    async fn pull(
        &self,
        state: &AppState,
        sync_state: &mut SyncState,
        _opts: &SyncRunOptions,
    ) -> AppResult<PullReport> {
        let mut report = PullReport::default();
        if sync_state.last_history_id.is_none() {
            report.full_resync = true;
            let raw = b"From: sender@fastmail.test\r\nTo: agent@example.com\r\nSubject: JMAP Hello\r\nMessage-ID: <jmap-1@fastmail.test>\r\n\r\nHello from custom SyncSource!".to_vec();
            let input = parse_raw_to_new_message_input(
                raw,
                vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
                None,
                "fastmail_jmap",
                Some("jmap_msg_1".to_string()),
                Some("jmap_thr_1".to_string()),
                false,
                false,
            );
            ingest_synced_message(state, input, &mut report).await?;
            sync_state.last_history_id = Some("state_1".to_string());
            sync_state.messages_synced += report.messages_added;
        }
        report.history_id = sync_state.last_history_id.clone();
        Ok(report)
    }

    async fn push_changes(
        &self,
        _state: &AppState,
        changes: &[LocalMutation],
    ) -> AppResult<PushReport> {
        self.pushed.lock().unwrap().extend(changes.iter().cloned());
        Ok(PushReport {
            messages_pushed: changes.len() as u64,
        })
    }
}

struct ReadOnlyCustomSource;

#[async_trait]
impl SyncSource for ReadOnlyCustomSource {
    fn provider_name(&self) -> &'static str {
        "readonly_source"
    }

    fn account_key(&self, config: &Config) -> String {
        format!("readonly_source:{}", config.user_email)
    }

    async fn pull(
        &self,
        _state: &AppState,
        sync_state: &mut SyncState,
        _opts: &SyncRunOptions,
    ) -> AppResult<PullReport> {
        sync_state.last_history_id = Some("ro_1".to_string());
        Ok(PullReport {
            full_resync: true,
            history_id: Some("ro_1".to_string()),
            ..Default::default()
        })
    }
}

#[tokio::test]
async fn custom_sync_source_runs_through_shared_runner_and_pushback() {
    let mut cfg = Config::for_test();
    cfg.sync_bidirectional = true;
    let (_dir, state) = make_sqlite_state(cfg);
    let mut events_rx = state.events.subscribe();

    let pushed = Arc::new(Mutex::new(Vec::new()));
    let source = CustomJmapSource {
        pushed: pushed.clone(),
    };

    // Pass 1: initial pull via shared runner -> ingests message, pushes nothing, emits SyncCompleted.
    let r1 = run_sync_source(&state, &source, SyncRunOptions::default())
        .await
        .expect("custom sync pull");
    assert_eq!(r1.provider, "fastmail_jmap");
    assert!(r1.full_resync);
    assert_eq!(r1.messages_added, 1);
    assert_eq!(r1.messages_pushed, 0);
    assert!(r1.bidirectional_enabled);
    assert_eq!(r1.history_id.as_deref(), Some("state_1"));
    assert!(pushed.lock().unwrap().is_empty());

    let mut saw_completed = false;
    while let Ok(env) = events_rx.try_recv() {
        if matches!(
            env.event,
            MailEvent::SyncCompleted {
                ref provider,
                messages_added: 1,
                ..
            } if provider == "fastmail_jmap"
        ) {
            saw_completed = true;
        }
    }
    assert!(saw_completed, "expected SyncCompleted event");

    // Local mutation on the pulled message: mark read and star.
    let local_msg = state
        .store
        .find_message_by_upstream_id("jmap_msg_1")
        .await
        .unwrap()
        .expect("jmap message stored");
    state
        .store
        .modify_message_labels(
            &local_msg.id,
            &[LABEL_STARRED.to_string()],
            &[LABEL_UNREAD.to_string()],
        )
        .await
        .unwrap();

    // Pass 2: pushes the collapsed local mutation to CustomJmapSource::push_changes.
    let r2 = run_sync_source(&state, &source, SyncRunOptions::default())
        .await
        .expect("custom sync push");
    assert!(!r2.full_resync);
    assert_eq!(r2.messages_added, 0);
    assert_eq!(r2.messages_pushed, 1);

    {
        let recorded = pushed.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].upstream_id, "jmap_msg_1");
        assert_eq!(
            recorded[0].kind,
            LocalMutationKind::ModifyLabels {
                add_labels: vec![LABEL_STARRED.to_string()],
                remove_labels: vec![LABEL_UNREAD.to_string()],
            }
        );
    }

    // Pass 3: no new local mutations -> pushes 0 (no echo loop).
    let r3 = run_sync_source(&state, &source, SyncRunOptions::default())
        .await
        .expect("custom sync idempotent");
    assert_eq!(r3.messages_pushed, 0);
    assert_eq!(pushed.lock().unwrap().len(), 1);

    // Verify SyncState persisted push count in SQLite.
    let saved_state = state
        .store
        .get_sync_state("fastmail_jmap:agent@example.com")
        .await
        .unwrap()
        .expect("sync state persisted");
    assert_eq!(saved_state.messages_pushed, 1);
    assert!(saved_state.last_pushed_history_id.is_some());

    // Default no-op push_changes compiles and succeeds for one-way connectors.
    let ro = ReadOnlyCustomSource;
    let r_ro = run_sync_source(&state, &ro, SyncRunOptions::default())
        .await
        .expect("readonly sync");
    assert_eq!(r_ro.provider, "readonly_source");
    assert_eq!(r_ro.messages_pushed, 0);
}

// ============================================================================
// 2. Gmail REST API bidirectional pushback + `/v1/sync/status` + no echo loop
// ============================================================================

#[tokio::test]
async fn gmail_api_bidirectional_pushback_modify_trash_delete_and_no_echo_loop() {
    let mock_server = MockServer::start().await;

    // Labels list (includes user label Label_99 = VIP)
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .and(header("authorization", "Bearer bidir-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "labels": [
                { "id": "INBOX", "name": "INBOX", "type": "system" },
                { "id": "Label_99", "name": "VIP", "type": "user" }
            ]
        })))
        .mount(&mock_server)
        .await;

    // Profile (baseline historyId = 1000)
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/profile"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "emailAddress": "agent@example.com",
            "messagesTotal": 3,
            "threadsTotal": 3,
            "historyId": "1000"
        })))
        .mount(&mock_server)
        .await;

    // Initial messages.list
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [
                { "id": "g_modify", "threadId": "t_modify" },
                { "id": "g_trash", "threadId": "t_trash" },
                { "id": "g_delete", "threadId": "t_delete" }
            ],
            "resultSizeEstimate": 3
        })))
        .mount(&mock_server)
        .await;

    let raw_mod = "From: alice@example.com\r\nTo: agent@example.com\r\nSubject: Modify Me\r\nMessage-ID: <mod@example.com>\r\n\r\nPlease archive and star.";
    let raw_trash = "From: bob@example.com\r\nTo: agent@example.com\r\nSubject: Trash Me\r\nMessage-ID: <trash@example.com>\r\n\r\nMove to trash.";
    let raw_del = "From: carol@example.com\r\nTo: agent@example.com\r\nSubject: Delete Me\r\nMessage-ID: <del@example.com>\r\n\r\nDelete forever.";

    for (id, tid, raw) in [
        ("g_modify", "t_modify", raw_mod),
        ("g_trash", "t_trash", raw_trash),
        ("g_delete", "t_delete", raw_del),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/gmail/v1/users/me/messages/{id}")))
            .and(query_param("format", "raw"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": id,
                "threadId": tid,
                "labelIds": ["INBOX", "UNREAD"],
                "internalDate": "1736000000000",
                "raw": b64url(raw)
            })))
            .mount(&mock_server)
            .await;
    }

    let mut cfg = Config::for_test();
    cfg.sync_mode = SyncMode::Api;
    cfg.sync_bidirectional = true;
    cfg.gmail_api_base_url = mock_server.uri();
    cfg.gmail_access_token = Some("bidir-token".to_string());
    let (_dir, state) = make_sqlite_state(cfg);
    let app = build_router(state.clone());

    // Sync #1: initial backfill (should NOT push anything back).
    let r1 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .expect("initial sync");
    assert!(r1.full_resync);
    assert_eq!(r1.messages_added, 3);
    assert_eq!(r1.messages_pushed, 0);
    assert!(r1.bidirectional_enabled);

    // Check GET /v1/sync/status backward-compatible + new pushback fields.
    let (st_code, status_json) = http_json(
        &app,
        Request::builder()
            .uri("/v1/sync/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st_code, StatusCode::OK);
    assert_eq!(status_json["enabled"], true);
    assert_eq!(status_json["provider"], "gmail_api");
    assert_eq!(status_json["state"], "idle");
    assert_eq!(status_json["last_history_id"], "1000");
    assert_eq!(status_json["total_messages"], 3);
    assert_eq!(status_json["unread_count"], 3);
    assert_eq!(status_json["bidirectional_enabled"], true);
    assert_eq!(status_json["messages_pushed"], 0);
    assert_eq!(status_json["extra"]["messages_pushed"], 0);
    assert_eq!(status_json["extra"]["bidirectional_enabled"], true);

    // Insert a purely local message and modify it -> must NEVER be pushed upstream.
    let local_only = state
        .store
        .insert_message(parse_raw_to_new_message_input(
            b"From: local@example.com\r\nSubject: Local Only\r\n\r\nNot synced".to_vec(),
            vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            None,
            "local",
            None,
            None,
            false,
            false,
        ))
        .await
        .unwrap();
    state
        .store
        .modify_message_labels(&local_only.id, &[], &[LABEL_UNREAD.to_string()])
        .await
        .unwrap();

    // Perform local mutations through HTTP APIs:
    // 1. Triage `g_modify` thread: mark_read + archive + star + add VIP label.
    let m_mod = state
        .store
        .find_message_by_upstream_id("g_modify")
        .await
        .unwrap()
        .unwrap();
    let vip_label = state
        .store
        .list_labels()
        .await
        .unwrap()
        .into_iter()
        .find(|l| l.name == "VIP")
        .expect("VIP label synced");

    let (triage_code, _) = http_json(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!("/v1/threads/{}/triage", m_mod.thread_id))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "mark_read": true,
                    "archive": true,
                    "star": true,
                    "add_labels": [vip_label.id]
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(triage_code, StatusCode::OK);

    // 2. Trash `g_trash` via Gmail REST API endpoint.
    let m_trash = state
        .store
        .find_message_by_upstream_id("g_trash")
        .await
        .unwrap()
        .unwrap();
    let (trash_code, _) = http_json(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!("/gmail/v1/users/me/messages/{}/trash", m_trash.id))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(trash_code, StatusCode::OK);

    // 3. Permanently delete `g_delete` via Gmail REST API endpoint.
    let m_del = state
        .store
        .find_message_by_upstream_id("g_delete")
        .await
        .unwrap()
        .unwrap();
    let (del_code, _) = http_json(
        &app,
        Request::builder()
            .method("DELETE")
            .uri(format!("/gmail/v1/users/me/messages/{}", m_del.id))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(del_code, StatusCode::NO_CONTENT);

    // Mount incremental history (no upstream changes yet at startHistoryId=1000).
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/history"))
        .and(query_param("startHistoryId", "1000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "historyId": "1010",
            "history": []
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Strict expect(1) mocks for exact upstream pushback requests!
    Mock::given(method("POST"))
        .and(path("/gmail/v1/users/me/messages/g_modify/modify"))
        .and(header("authorization", "Bearer bidir-token"))
        .and(body_json(json!({
            "addLabelIds": ["Label_99", "STARRED"],
            "removeLabelIds": ["INBOX", "UNREAD"]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "g_modify",
            "threadId": "t_modify",
            "labelIds": ["STARRED", "Label_99"]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/gmail/v1/users/me/messages/g_trash/trash"))
        .and(header("authorization", "Bearer bidir-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "g_trash",
            "threadId": "t_trash",
            "labelIds": ["TRASH", "UNREAD"]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/gmail/v1/users/me/messages/g_delete"))
        .and(header("authorization", "Bearer bidir-token"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Sync #2: pushes all 3 mutations upstream!
    let r2 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .expect("bidirectional sync #2");
    assert!(!r2.full_resync);
    assert_eq!(r2.messages_pushed, 3);
    assert!(r2.bidirectional_enabled);
    assert_eq!(r2.history_id.as_deref(), Some("1010"));

    // Verify GET /v1/sync/status reflects pushed count = 3.
    let (st_code2, status_json2) = http_json(
        &app,
        Request::builder()
            .uri("/v1/sync/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st_code2, StatusCode::OK);
    assert_eq!(status_json2["bidirectional_enabled"], true);
    assert_eq!(status_json2["messages_pushed"], 3);
    assert_eq!(status_json2["extra"]["messages_pushed"], 3);

    // Sync #3: upstream history echoes back our pushed changes PLUS a new upstream label change
    // on `g_modify` (adding IMPORTANT). Neither should echo back upstream on Sync #3 or Sync #4!
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/history"))
        .and(query_param("startHistoryId", "1010"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "historyId": "1020",
            "history": [
                {
                    "id": "1015",
                    "labelsAdded": [
                        {
                            "message": { "id": "g_modify", "threadId": "t_modify" },
                            "labelIds": ["STARRED", "Label_99", "IMPORTANT"]
                        }
                    ],
                    "labelsRemoved": [
                        {
                            "message": { "id": "g_modify", "threadId": "t_modify" },
                            "labelIds": ["INBOX", "UNREAD"]
                        }
                    ]
                }
            ]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let r3 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .expect("sync #3 no echo");
    assert_eq!(r3.messages_pushed, 0);
    assert_eq!(r3.history_id.as_deref(), Some("1020"));

    // Sync #4: verify the pull-generated `IMPORTANT` label addition from Sync #3 does NOT echo back!
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/history"))
        .and(query_param("startHistoryId", "1020"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "historyId": "1020",
            "history": []
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let r4 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .expect("sync #4 no echo after pull");
    assert_eq!(r4.messages_pushed, 0);

    // Verify local message received IMPORTANT from upstream pull.
    let m_mod_final = state
        .store
        .find_message_by_upstream_id("g_modify")
        .await
        .unwrap()
        .unwrap();
    assert!(m_mod_final.label_ids.contains(&"IMPORTANT".to_string()));
    assert!(m_mod_final.label_ids.contains(&LABEL_STARRED.to_string()));
    assert!(!m_mod_final.label_ids.contains(&LABEL_UNREAD.to_string()));
    assert!(!m_mod_final.label_ids.contains(&LABEL_INBOX.to_string()));
}

// ============================================================================
// 3. Deterministic conflict handling (pull-first / last-write-wins)
// ============================================================================

#[tokio::test]
async fn gmail_api_bidirectional_conflict_resolution_pull_wins_conflicting_label() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "labels": [] })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/profile"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "emailAddress": "agent@example.com",
            "messagesTotal": 1,
            "threadsTotal": 1,
            "historyId": "2000"
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [{ "id": "g_conflict", "threadId": "t_conflict" }],
            "resultSizeEstimate": 1
        })))
        .mount(&mock_server)
        .await;

    let raw = "From: conflict@example.com\r\nSubject: Conflict Test\r\nMessage-ID: <conflict@example.com>\r\n\r\nBody";
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/g_conflict"))
        .and(query_param("format", "raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "g_conflict",
            "threadId": "t_conflict",
            "labelIds": ["INBOX", "UNREAD"],
            "raw": b64url(raw)
        })))
        .mount(&mock_server)
        .await;

    let mut cfg = Config::for_test();
    cfg.sync_mode = SyncMode::Api;
    cfg.sync_bidirectional = true;
    cfg.gmail_api_base_url = mock_server.uri();
    cfg.gmail_access_token = Some("tok".to_string());
    let (_dir, state) = make_sqlite_state(cfg);

    // Sync #1 pulls g_conflict with [INBOX, UNREAD].
    let r1 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r1.messages_added, 1);

    // Locally: mark read (-UNREAD) and star (+STARRED).
    let local = state
        .store
        .find_message_by_upstream_id("g_conflict")
        .await
        .unwrap()
        .unwrap();
    state
        .store
        .modify_message_labels(
            &local.id,
            &[LABEL_STARRED.to_string()],
            &[LABEL_UNREAD.to_string()],
        )
        .await
        .unwrap();

    // Concurrently upstream marks it UNREAD again via history.list -> pull applies +UNREAD first.
    // Conflicting UNREAD must NOT be pushed back as removeLabelIds; only non-conflicting +STARRED pushes!
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/history"))
        .and(query_param("startHistoryId", "2000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "historyId": "2010",
            "history": [
                {
                    "id": "2005",
                    "labelsAdded": [
                        {
                            "message": { "id": "g_conflict", "threadId": "t_conflict" },
                            "labelIds": ["UNREAD"]
                        }
                    ]
                }
            ]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/gmail/v1/users/me/messages/g_conflict/modify"))
        .and(body_json(json!({
            "addLabelIds": ["STARRED"],
            "removeLabelIds": []
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "g_conflict",
            "threadId": "t_conflict",
            "labelIds": ["INBOX", "UNREAD", "STARRED"]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let r2 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r2.messages_pushed, 1);

    let after = state
        .store
        .find_message_by_upstream_id("g_conflict")
        .await
        .unwrap()
        .unwrap();
    assert!(after.label_ids.contains(&LABEL_UNREAD.to_string()));
    assert!(after.label_ids.contains(&LABEL_STARRED.to_string()));
}

// ============================================================================
// 4. IMAP bidirectional pushback against live embedded `nogml` IMAP server
// ============================================================================

#[tokio::test]
async fn gmail_imap_bidirectional_pushback_mirrors_seen_flagged_and_trash_upstream() {
    // 1. Start an upstream embedded `nogml` IMAP server backed by real SQLite.
    let upstream_dir = TempDir::new().unwrap();
    let mut up_cfg = Config::for_test();
    up_cfg.storage = StorageBackend::Sqlite;
    up_cfg.db_path = upstream_dir.path().join("upstream.db");
    let upstream_state = AppState::from_config(up_cfg).unwrap();

    let up_m1 = upstream_state
        .store
        .insert_message(parse_raw_to_new_message_input(
            b"From: alice@upstream.test\r\nTo: agent@example.com\r\nSubject: IMAP Bidir 1\r\nMessage-ID: <imap-bidir-1@upstream.test>\r\n\r\nMark me read and star me!".to_vec(),
            vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            None,
            "local",
            Some("18f123456789abcd".to_string()),
            None,
            false,
            false,
        ))
        .await
        .unwrap();

    let up_m2 = upstream_state
        .store
        .insert_message(parse_raw_to_new_message_input(
            b"From: bob@upstream.test\r\nTo: agent@example.com\r\nSubject: IMAP Bidir 2\r\nMessage-ID: <imap-bidir-2@upstream.test>\r\n\r\nTrash me via UID MOVE!".to_vec(),
            vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            None,
            "local",
            Some("18f123456789abce".to_string()),
            None,
            false,
            false,
        ))
        .await
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let up_clone = upstream_state.clone();
    tokio::spawn(async move {
        let _ = serve_plain_listener(listener, up_clone, None, shutdown_rx).await;
    });

    // 2. Configure local `nogml` node for bidirectional IMAP sync.
    let mut local_cfg = Config::for_test();
    local_cfg.sync_mode = SyncMode::Imap;
    local_cfg.sync_bidirectional = true;
    local_cfg.gmail_imap_host = addr.ip().to_string();
    local_cfg.gmail_imap_port = addr.port();
    local_cfg.gmail_imap_tls = false;
    local_cfg.gmail_imap_user = Some("agent@example.com".to_string());
    local_cfg.gmail_imap_password = Some("secret-pass".to_string());
    local_cfg.gmail_imap_mailbox = "[Gmail]/All Mail".to_string();
    let (_local_dir, local_state) = make_sqlite_state(local_cfg);

    // Sync #1: pull both messages.
    let r1 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .expect("initial IMAP sync");
    assert_eq!(r1.provider, "gmail_imap");
    assert_eq!(r1.messages_added, 2);
    assert_eq!(r1.messages_pushed, 0);
    assert!(r1.bidirectional_enabled);

    // Locally mutate m1 (mark read + star) and m2 (trash).
    let local_m1 = local_state
        .store
        .find_message_by_upstream_id("18f123456789abcd")
        .await
        .unwrap()
        .expect("m1 synced");
    let local_m2 = local_state
        .store
        .find_message_by_upstream_id("18f123456789abce")
        .await
        .unwrap()
        .expect("m2 synced");

    local_state
        .store
        .modify_message_labels(
            &local_m1.id,
            &[LABEL_STARRED.to_string()],
            &[LABEL_UNREAD.to_string()],
        )
        .await
        .unwrap();
    local_state.store.trash_message(&local_m2.id).await.unwrap();

    // Sync #2: pushes \Seen + \Flagged via UID STORE for m1 and UID MOVE [Gmail]/Trash for m2!
    let r2 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .expect("bidirectional IMAP sync #2");
    assert_eq!(r2.messages_pushed, 2);

    // Inspect upstream server store directly to confirm flags & Trash move landed!
    let up_m1_after = upstream_state
        .store
        .get_message(&up_m1.id)
        .await
        .unwrap()
        .expect("up_m1 still exists");
    assert!(
        !up_m1_after.label_ids.contains(&LABEL_UNREAD.to_string()),
        "expected \\Seen pushed upstream (UNREAD removed), got {:?}",
        up_m1_after.label_ids
    );
    assert!(
        up_m1_after.label_ids.contains(&LABEL_STARRED.to_string()),
        "expected \\Flagged pushed upstream (STARRED added), got {:?}",
        up_m1_after.label_ids
    );

    let up_m2_after = upstream_state
        .store
        .get_message(&up_m2.id)
        .await
        .unwrap()
        .expect("up_m2 still exists in trash");
    assert!(
        up_m2_after.label_ids.contains(&LABEL_TRASH.to_string()),
        "expected UID MOVE to [Gmail]/Trash pushed upstream, got {:?}",
        up_m2_after.label_ids
    );

    // Sync #3: verify no echo loop (0 pushed).
    let r3 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .expect("IMAP sync #3 idempotent");
    assert_eq!(r3.messages_pushed, 0);

    let _ = shutdown_tx.send(true);
}

// ============================================================================
// 5. Bidirectional disabled by default (`sync_bidirectional = false`)
// ============================================================================

#[tokio::test]
async fn bidirectional_disabled_by_default_does_not_push_changes() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "labels": [] })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/profile"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "emailAddress": "agent@example.com",
            "messagesTotal": 1,
            "threadsTotal": 1,
            "historyId": "3000"
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [{ "id": "g_oneway", "threadId": "t_oneway" }],
            "resultSizeEstimate": 1
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/g_oneway"))
        .and(query_param("format", "raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "g_oneway",
            "threadId": "t_oneway",
            "labelIds": ["INBOX", "UNREAD"],
            "raw": b64url("From: a@b.com\r\nSubject: One Way\r\n\r\nHi")
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/history"))
        .and(query_param("startHistoryId", "3000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "historyId": "3000",
            "history": []
        })))
        .mount(&mock_server)
        .await;

    // Must NOT receive any POST /modify calls when sync_bidirectional = false!
    Mock::given(method("POST"))
        .and(path("/gmail/v1/users/me/messages/g_oneway/modify"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    let mut cfg = Config::for_test();
    assert!(!cfg.sync_bidirectional, "default must be false");
    cfg.sync_mode = SyncMode::Api;
    cfg.gmail_api_base_url = mock_server.uri();
    cfg.gmail_access_token = Some("tok".to_string());
    let (_dir, state) = make_sqlite_state(cfg);
    let app = build_router(state.clone());

    let r1 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert!(!r1.bidirectional_enabled);
    assert_eq!(r1.messages_pushed, 0);

    let m = state
        .store
        .find_message_by_upstream_id("g_oneway")
        .await
        .unwrap()
        .unwrap();
    state
        .store
        .modify_message_labels(
            &m.id,
            &[LABEL_STARRED.to_string()],
            &[LABEL_UNREAD.to_string()],
        )
        .await
        .unwrap();

    let r2 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert!(!r2.bidirectional_enabled);
    assert_eq!(r2.messages_pushed, 0);

    let (code, status) = http_json(
        &app,
        Request::builder()
            .uri("/v1/sync/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(status["bidirectional_enabled"], false);
    assert_eq!(status["messages_pushed"], 0);
}

// ============================================================================
// 6. SQLite schema upgrade safety (existing DB without new columns)
// ============================================================================

#[tokio::test]
async fn sqlite_migrates_legacy_sync_state_and_history_events_tables() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("legacy.db");

    // Simulate a legacy database created prior to Issue #12 columns.
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE sync_state (
                account_key TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                last_history_id TEXT,
                imap_mailbox TEXT,
                imap_uid_validity INTEGER,
                imap_last_uid INTEGER,
                last_sync_at_ms INTEGER,
                last_full_sync_at_ms INTEGER,
                status TEXT NOT NULL,
                last_error TEXT,
                messages_synced INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE history_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                history_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                message_id TEXT NOT NULL,
                thread_id TEXT NOT NULL,
                label_ids_json TEXT NOT NULL,
                context_labels_json TEXT NOT NULL DEFAULT '[]'
            );
            INSERT INTO sync_state (account_key, provider, last_history_id, status, messages_synced)
            VALUES ('gmail_api:me', 'gmail_api', '777', 'idle', 4);",
        )
        .unwrap();
    }

    let store = SqliteStore::open(&db_path, "agent@example.com").expect("migrates cleanly");
    let st = store
        .get_sync_state("gmail_api:me")
        .await
        .unwrap()
        .expect("legacy row preserved");
    assert_eq!(st.last_history_id.as_deref(), Some("777"));
    assert_eq!(st.messages_synced, 4);
    assert_eq!(st.last_pushed_history_id, None);
    assert_eq!(st.messages_pushed, 0);
}
