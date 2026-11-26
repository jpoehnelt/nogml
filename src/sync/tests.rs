use base64::Engine as _;
use serde_json::json;
use tokio::{net::TcpListener, sync::watch};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, header, method, path, query_param},
};

use crate::{
    config::{Config, SyncMode},
    events::MailEvent,
    imap::{mime_fmt::parse_raw_to_new_message_input, serve_plain_listener, tests::test_app_state},
    models::{LABEL_INBOX, LABEL_STARRED, LABEL_UNREAD},
    sync::{SyncRunOptions, get_sync_status, run_background_sync, run_gmail_sync},
};

fn b64url(raw: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_bytes())
}

#[tokio::test]
async fn test_gmail_api_oauth_full_sync_and_incremental_history() {
    let mock_server = MockServer::start().await;

    // 1. OAuth2 token refresh endpoint
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("client_id=cid"))
        .and(body_string_contains("refresh_token=rtok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "oauth-access-123",
            "expires_in": 3600,
            "token_type": "Bearer"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // 2. Labels list
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .and(header("authorization", "Bearer oauth-access-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "labels": [
                { "id": "INBOX", "name": "INBOX", "type": "system" },
                { "id": "Label_99", "name": "VIP", "type": "user" }
            ]
        })))
        .mount(&mock_server)
        .await;

    // 3. Profile (baseline historyId = 1000)
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/profile"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "emailAddress": "agent@example.com",
            "messagesTotal": 2,
            "threadsTotal": 2,
            "historyId": "1000"
        })))
        .mount(&mock_server)
        .await;

    // 4. Paginated messages.list (page 1 -> page 2)
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .and(query_param("pageToken", "p2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [
                { "id": "18f0000000000002", "threadId": "18f0000000000002" }
            ],
            "resultSizeEstimate": 2
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [
                { "id": "18f0000000000001", "threadId": "18f0000000000001" }
            ],
            "nextPageToken": "p2",
            "resultSizeEstimate": 2
        })))
        .mount(&mock_server)
        .await;

    // 5. messages.get?format=raw for msg 1 and msg 2
    let raw1 = "From: alice@example.com\r\nTo: agent@example.com\r\nSubject: First\r\nMessage-ID: <m1@example.com>\r\n\r\nBody one";
    let raw2 = "From: bob@example.com\r\nTo: agent@example.com\r\nSubject: Second\r\nMessage-ID: <m2@example.com>\r\n\r\nBody two";

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/18f0000000000001"))
        .and(query_param("format", "raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "18f0000000000001",
            "threadId": "18f0000000000001",
            "labelIds": ["INBOX", "UNREAD", "Label_99"],
            "internalDate": "1736000000000",
            "raw": b64url(raw1)
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/18f0000000000002"))
        .and(query_param("format", "raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "18f0000000000002",
            "threadId": "18f0000000000002",
            "labelIds": ["INBOX"],
            "internalDate": "1736000060000",
            "raw": b64url(raw2)
        })))
        .mount(&mock_server)
        .await;

    let mut cfg = Config::for_test();
    cfg.sync_mode = SyncMode::Api;
    cfg.gmail_api_base_url = mock_server.uri();
    cfg.gmail_oauth_token_url = format!("{}/token", mock_server.uri());
    cfg.gmail_client_id = Some("cid".to_string());
    cfg.gmail_client_secret = Some("csec".to_string());
    cfg.gmail_refresh_token = Some("rtok".to_string());

    let state = test_app_state(cfg);
    let mut events_rx = state.events.subscribe();

    // Run initial full backfill
    let report = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(report.provider, "gmail_api");
    assert!(report.full_resync);
    assert_eq!(report.labels_synced, 1);
    assert_eq!(report.messages_added, 2);
    assert_eq!(report.history_id.as_deref(), Some("1000"));

    // Verify SyncCompleted event was published
    let mut saw_sync_completed = false;
    while let Ok(env) = events_rx.try_recv() {
        if matches!(
            env.event,
            MailEvent::SyncCompleted {
                messages_added: 2,
                ..
            }
        ) {
            saw_sync_completed = true;
        }
    }
    assert!(saw_sync_completed);

    // Verify SyncStatusResponse
    let status = get_sync_status(&state).await.unwrap();
    assert!(status.enabled);
    assert_eq!(status.provider, "gmail_api");
    assert_eq!(status.state, "idle");
    assert_eq!(status.last_history_id.as_deref(), Some("1000"));
    assert_eq!(status.total_messages, 2);
    assert_eq!(status.unread_count, 1);

    // Verify upstream label mapped to local VIP label
    let m1 = state
        .store
        .find_message_by_upstream_id("18f0000000000001")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(m1.subject, "First");
    let labels = state.store.list_labels().await.unwrap();
    let vip = labels.iter().find(|l| l.name == "VIP").unwrap();
    assert!(m1.label_ids.contains(&vip.id));

    // --- Incremental history.list pass ---
    let raw3 = "From: carol@example.com\r\nTo: agent@example.com\r\nSubject: Third\r\nMessage-ID: <m3@example.com>\r\n\r\nBody three";
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/18f0000000000003"))
        .and(query_param("format", "raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "18f0000000000003",
            "threadId": "18f0000000000003",
            "labelIds": ["INBOX", "UNREAD"],
            "internalDate": "1736000120000",
            "raw": b64url(raw3)
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/history"))
        .and(query_param("startHistoryId", "1000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "historyId": "1050",
            "history": [
                {
                    "id": "1010",
                    "messagesAdded": [
                        { "message": { "id": "18f0000000000003", "threadId": "18f0000000000003" } }
                    ]
                },
                {
                    "id": "1020",
                    "labelsAdded": [
                        {
                            "message": { "id": "18f0000000000001", "threadId": "18f0000000000001" },
                            "labelIds": ["STARRED"]
                        }
                    ],
                    "labelsRemoved": [
                        {
                            "message": { "id": "18f0000000000001", "threadId": "18f0000000000001" },
                            "labelIds": ["UNREAD"]
                        }
                    ]
                },
                {
                    "id": "1030",
                    "messagesDeleted": [
                        { "message": { "id": "18f0000000000002", "threadId": "18f0000000000002" } }
                    ]
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let inc_report = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert!(!inc_report.full_resync);
    assert_eq!(inc_report.messages_added, 1);
    assert_eq!(inc_report.messages_deleted, 1);
    assert!(inc_report.messages_updated >= 2);
    assert_eq!(inc_report.history_id.as_deref(), Some("1050"));

    let m1_after = state
        .store
        .find_message_by_upstream_id("18f0000000000001")
        .await
        .unwrap()
        .unwrap();
    assert!(m1_after.label_ids.contains(&LABEL_STARRED.to_string()));
    assert!(!m1_after.label_ids.contains(&LABEL_UNREAD.to_string()));
    assert!(
        state
            .store
            .find_message_by_upstream_id("18f0000000000002")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        state
            .store
            .find_message_by_upstream_id("18f0000000000003")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn test_gmail_api_history_404_automatic_full_fallback() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "labels": [] })))
        .mount(&mock_server)
        .await;

    // History returns 404 (expired startHistoryId)
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/history"))
        .and(query_param("startHistoryId", "500"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": { "code": 404, "message": "Requested entity was not found." }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Fallback full sync endpoints
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/profile"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "emailAddress": "agent@example.com",
            "messagesTotal": 2,
            "threadsTotal": 2,
            "historyId": "2000"
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [
                { "id": "existing_id", "threadId": "t1" },
                { "id": "new_id", "threadId": "t2" }
            ],
            "resultSizeEstimate": 2
        })))
        .mount(&mock_server)
        .await;

    let raw_new = "From: dave@example.com\r\nSubject: Recovered\r\n\r\nAfter 404 fallback";
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/new_id"))
        .and(query_param("format", "raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "new_id",
            "threadId": "t2",
            "labelIds": ["INBOX"],
            "raw": b64url(raw_new)
        })))
        .mount(&mock_server)
        .await;

    let mut cfg = Config::for_test();
    cfg.sync_mode = SyncMode::Api;
    cfg.gmail_api_base_url = mock_server.uri();
    cfg.gmail_access_token = Some("static-token".to_string());
    let state = test_app_state(cfg);

    // Seed pre-existing sync checkpoint and one already-synced message
    state
        .store
        .save_sync_state(crate::storage::SyncState {
            account_key: "gmail_api:me".to_string(),
            provider: "gmail_api".to_string(),
            last_history_id: Some("500".to_string()),
            status: "idle".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();

    let existing_input = parse_raw_to_new_message_input(
        b"From: old@example.com\r\nSubject: Already Here\r\n\r\nOld".to_vec(),
        vec![LABEL_INBOX.to_string()],
        None,
        "gmail_api",
        Some("existing_id".to_string()),
        Some("t1".to_string()),
        false,
        false,
    );
    state.store.insert_message(existing_input).await.unwrap();

    let report = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert!(report.full_resync);
    assert_eq!(report.messages_deduplicated, 1);
    assert_eq!(report.messages_added, 1);
    assert_eq!(report.history_id.as_deref(), Some("2000"));

    let recovered = state
        .store
        .find_message_by_upstream_id("new_id")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.subject, "Recovered");
}

#[tokio::test]
async fn test_gmail_imap_upstream_sync_against_embedded_imap_server() {
    // 1. Start an embedded IMAP server acting as the "upstream" Gmail IMAP server
    let upstream_state = test_app_state(Config::for_test());
    let raw1 = b"From: alice@upstream.test\r\nTo: me@upstream.test\r\nSubject: IMAP Sync 1\r\nMessage-ID: <imap-1@upstream.test>\r\n\r\nHello from IMAP!".to_vec();
    let msg1 = parse_raw_to_new_message_input(
        raw1,
        vec![
            LABEL_INBOX.to_string(),
            LABEL_UNREAD.to_string(),
            LABEL_STARRED.to_string(),
        ],
        None,
        "local",
        Some("18f123456789abcd".to_string()),
        None,
        false,
        false,
    );
    upstream_state.store.insert_message(msg1).await.unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let up_clone = upstream_state.clone();
    tokio::spawn(async move {
        let _ = serve_plain_listener(listener, up_clone, None, shutdown_rx).await;
    });

    // 2. Configure local node to sync via SyncMode::Imap (plain TCP for test)
    let mut local_cfg = Config::for_test();
    local_cfg.sync_mode = SyncMode::Imap;
    local_cfg.gmail_imap_host = addr.ip().to_string();
    local_cfg.gmail_imap_port = addr.port();
    local_cfg.gmail_imap_tls = false;
    local_cfg.gmail_imap_user = Some("agent@example.com".to_string());
    local_cfg.gmail_imap_password = Some("secret-pass".to_string());
    local_cfg.gmail_imap_mailbox = "[Gmail]/All Mail".to_string();
    let local_state = test_app_state(local_cfg);

    // Initial full IMAP sync
    let r1 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r1.provider, "gmail_imap");
    assert!(r1.full_resync);
    assert_eq!(r1.messages_added, 1);

    let synced = local_state
        .store
        .find_message_by_upstream_id("18f123456789abcd")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(synced.subject, "IMAP Sync 1");
    assert!(synced.label_ids.contains(&LABEL_INBOX.to_string()));
    assert!(synced.label_ids.contains(&LABEL_STARRED.to_string()));
    assert!(synced.label_ids.contains(&LABEL_UNREAD.to_string()));

    // Incremental run with no new messages -> 0 fetched
    let r2 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert!(!r2.full_resync);
    assert_eq!(r2.messages_added, 0);

    // Add a second message upstream -> incremental run fetches only message 2
    let raw2 = b"From: bob@upstream.test\r\nSubject: IMAP Sync 2\r\nMessage-ID: <imap-2@upstream.test>\r\n\r\nSecond msg".to_vec();
    let msg2 = parse_raw_to_new_message_input(
        raw2,
        vec![LABEL_INBOX.to_string()],
        None,
        "local",
        Some("18f123456789abce".to_string()),
        None,
        false,
        false,
    );
    upstream_state.store.insert_message(msg2).await.unwrap();

    let r3 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert!(!r3.full_resync);
    assert_eq!(r3.messages_added, 1);
    assert!(
        local_state
            .store
            .find_message_by_upstream_id("18f123456789abce")
            .await
            .unwrap()
            .is_some()
    );

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn test_background_sync_shutdown() {
    let mut cfg = Config::for_test();
    cfg.sync_interval_secs = 3600;
    let state = test_app_state(cfg);
    let (tx, rx) = watch::channel(false);

    let handle = tokio::spawn(run_background_sync(state, rx));
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let _ = tx.send(true);
    tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("background sync did not stop")
        .unwrap();
}

#[tokio::test]
async fn test_gmail_api_query_max_messages_and_error_state_persistence() {
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
            "messagesTotal": 3,
            "threadsTotal": 3,
            "historyId": "3000"
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .and(query_param("q", "from:vip@example.com"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [
                { "id": "m_a", "threadId": "t_a" },
                { "id": "m_b", "threadId": "t_b" }
            ],
            "resultSizeEstimate": 2
        })))
        .mount(&mock_server)
        .await;

    let raw_a = "From: vip@example.com\r\nSubject: VIP A\r\n\r\nHello A";
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/m_a"))
        .and(query_param("format", "raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "m_a",
            "threadId": "t_a",
            "labelIds": ["INBOX"],
            "raw": b64url(raw_a)
        })))
        .mount(&mock_server)
        .await;

    // Use real `MemoryStore` backend to verify full storage integration
    let mut cfg = Config::for_test();
    cfg.sync_mode = SyncMode::Api;
    cfg.gmail_api_base_url = mock_server.uri();
    cfg.gmail_access_token = Some("tok".to_string());
    let state = crate::AppState::with_backends(
        cfg,
        std::sync::Arc::new(crate::storage::MemoryStore::new("agent@example.com")),
        std::sync::Arc::new(crate::imap::tests::DummyResendClient),
    );

    let report = run_gmail_sync(
        &state,
        SyncRunOptions {
            max_messages: Some(1),
            query: Some("from:vip@example.com".to_string()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(report.messages_added, 1);
    assert!(
        state
            .store
            .find_message_by_upstream_id("m_a")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        state
            .store
            .find_message_by_upstream_id("m_b")
            .await
            .unwrap()
            .is_none()
    );

    // Trigger an error (missing credentials on a fresh state) and verify `status == "error"` persisted
    let mut bad_cfg = Config::for_test();
    bad_cfg.sync_mode = SyncMode::Api;
    let bad_state = test_app_state(bad_cfg);
    assert!(
        run_gmail_sync(&bad_state, SyncRunOptions::default())
            .await
            .is_err()
    );
    let status = get_sync_status(&bad_state).await.unwrap();
    assert_eq!(status.state, "error");
    assert!(status.last_error.is_some());
}

#[test]
fn test_xgm_labels_mapping_and_quoting() {
    use std::collections::HashMap;

    use crate::{
        models::{
            LABEL_DRAFT, LABEL_IMPORTANT, LABEL_INBOX, LABEL_SENT, LABEL_SPAM, LABEL_STARRED,
            LABEL_TRASH, LABEL_UNREAD,
        },
        sync::gmail_imap::{
            decode_imap_mutf7, encode_imap_mutf7, map_local_label_to_xgm_token,
            map_local_label_to_xgm_token_with_utf8, quote_imap_string,
        },
    };

    let mut user_names = HashMap::new();
    user_names.insert("Label_1".to_string(), "Work/Urgent".to_string());
    user_names.insert("Label_2".to_string(), "A \"B\" \\ C".to_string());
    user_names.insert("Label_3".to_string(), "Café/重要".to_string());
    user_names.insert("Label_bad_crlf".to_string(), "Bad\r\nLOGOUT".to_string());
    user_names.insert("Label_bad_nul".to_string(), "Bad\0Null".to_string());

    // System labels
    assert_eq!(
        map_local_label_to_xgm_token(LABEL_INBOX, &user_names).as_deref(),
        Some("\\Inbox")
    );
    assert_eq!(
        map_local_label_to_xgm_token(LABEL_STARRED, &user_names).as_deref(),
        Some("\\Starred")
    );
    assert_eq!(
        map_local_label_to_xgm_token(LABEL_IMPORTANT, &user_names).as_deref(),
        Some("\\Important")
    );
    assert_eq!(
        map_local_label_to_xgm_token(LABEL_SPAM, &user_names).as_deref(),
        Some("\\Junk")
    );
    assert_eq!(
        map_local_label_to_xgm_token(LABEL_TRASH, &user_names).as_deref(),
        Some("\\Trash")
    );
    assert_eq!(
        map_local_label_to_xgm_token(LABEL_SENT, &user_names).as_deref(),
        Some("\\Sent")
    );
    assert_eq!(
        map_local_label_to_xgm_token(LABEL_DRAFT, &user_names).as_deref(),
        Some("\\Draft")
    );
    assert_eq!(
        map_local_label_to_xgm_token(LABEL_UNREAD, &user_names),
        None
    );

    // Custom labels: escaping, UTF-8, and injection rejection
    assert_eq!(
        map_local_label_to_xgm_token("Label_1", &user_names).as_deref(),
        Some("\"Work/Urgent\"")
    );
    assert_eq!(
        map_local_label_to_xgm_token("Label_2", &user_names).as_deref(),
        Some("\"A \\\"B\\\" \\\\ C\"")
    );
    assert_eq!(
        map_local_label_to_xgm_token("Label_3", &user_names).as_deref(),
        Some("\"Caf&AOk-/&kc2JgQ-\"")
    );
    assert_eq!(
        map_local_label_to_xgm_token_with_utf8("Label_3", &user_names, true).as_deref(),
        Some("\"Café/重要\"")
    );
    assert_eq!(
        decode_imap_mutf7(&encode_imap_mutf7("Café/重要 & 🚀")),
        "Café/重要 & 🚀"
    );
    assert_eq!(
        map_local_label_to_xgm_token("Label_bad_crlf", &user_names),
        None
    );
    assert_eq!(
        map_local_label_to_xgm_token("Label_bad_nul", &user_names),
        None
    );
    assert_eq!(quote_imap_string("   "), None);
    assert_eq!(quote_imap_string("line1\nline2"), None);
}

#[test]
fn test_appenduid_vanished_xoauth2_and_internaldate_helpers() {
    use async_imap::imap_proto::{ResponseCode, rfc4315::UidSetMember};

    use crate::sync::gmail_imap::{
        build_xoauth2_sasl_payload, expand_uid_ranges, format_imap_internaldate,
        parse_appenduid_response_code, parse_imap_fallback_upstream_id,
    };

    // APPENDUID parsing
    let code_single = ResponseCode::AppendUid(42, vec![UidSetMember::Uid(99)]);
    assert_eq!(
        parse_appenduid_response_code(Some(&code_single)),
        Some((42, 99))
    );
    let code_range = ResponseCode::AppendUid(7, vec![UidSetMember::UidRange(10..=12)]);
    assert_eq!(
        parse_appenduid_response_code(Some(&code_range)),
        Some((7, 10))
    );
    assert_eq!(
        parse_appenduid_response_code(Some(&ResponseCode::TryCreate)),
        None
    );
    assert_eq!(parse_appenduid_response_code(None), None);

    // VANISHED expansion with upper bound & cap
    assert_eq!(
        expand_uid_ranges(&[2..=4, 7..=9], 8, 100),
        vec![2, 3, 4, 7, 8]
    );
    let huge_ranges = [1..=u32::MAX, 10..=20];
    assert_eq!(
        expand_uid_ranges(&huge_ranges, u32::MAX, 5),
        vec![1, 2, 3, 4, 5]
    );

    // XOAUTH2 SASL payload framing
    let sasl = build_xoauth2_sasl_payload("alice@example.com", "ya29.secret-tok");
    assert_eq!(
        sasl,
        b"user=alice@example.com\x01auth=Bearer ya29.secret-tok\x01\x01"
    );

    // RFC 3501 INTERNALDATE formatting (2025-01-04T12:34:56Z = 1735994096000)
    assert_eq!(
        format_imap_internaldate(1_735_994_096_000),
        "04-Jan-2025 12:34:56 +0000"
    );

    // Fallback upstream ID parser
    assert_eq!(
        parse_imap_fallback_upstream_id("imap:[Gmail]/Sent Mail:17:42"),
        Some(("[Gmail]/Sent Mail", 17, 42))
    );
    assert_eq!(parse_imap_fallback_upstream_id("18f123456789abcd"), None);
}

#[test]
fn test_config_imap_parity_fields_and_oauth2_configured() {
    use crate::config::{Config, SyncMode};

    let mut cfg = Config::for_test();
    cfg.sync_mode = SyncMode::Imap;
    cfg.gmail_imap_user = Some("oauth@example.com".to_string());
    cfg.gmail_imap_password = None;
    assert!(!cfg.gmail_sync_configured());

    // OAuth2 static token or refresh flow makes SyncMode::Imap configured without App Password.
    cfg.gmail_access_token = Some("ya29.tok".to_string());
    assert!(cfg.gmail_sync_configured());

    cfg.gmail_access_token = None;
    cfg.gmail_client_id = Some("cid".to_string());
    cfg.gmail_client_secret = Some("csec".to_string());
    cfg.gmail_refresh_token = Some("rtok".to_string());
    assert!(cfg.gmail_sync_configured());

    // IDLE alone activates background sync.
    cfg.sync_interval_secs = 0;
    cfg.gmail_imap_idle = false;
    assert!(!cfg.has_background_sync());
    cfg.gmail_imap_idle = true;
    assert!(cfg.has_background_sync());
}

#[test]
fn test_imap_xoauth2_target_validation_and_mutf7_roundtrip() {
    use crate::sync::gmail_imap::{
        decode_imap_mutf7, encode_imap_mutf7, validate_imap_xoauth2_target,
    };

    // Non-Gmail third-party IMAP host must never receive Google OAuth2 bearer tokens.
    let mut third_party = Config::for_test();
    third_party.gmail_imap_host = "imap.fastmail.com".to_string();
    third_party.gmail_imap_tls = true;
    assert!(validate_imap_xoauth2_target(&third_party).is_err());

    // Plaintext (non-TLS) non-loopback host must never receive OAuth2 bearer tokens.
    let mut plaintext_gmail = Config::for_test();
    plaintext_gmail.gmail_imap_host = "imap.gmail.com".to_string();
    plaintext_gmail.gmail_imap_tls = false;
    assert!(validate_imap_xoauth2_target(&plaintext_gmail).is_err());

    // TLS Gmail IMAP hosts and loopback test hosts are accepted.
    let mut tls_gmail = Config::for_test();
    tls_gmail.gmail_imap_host = "imap.gmail.com".to_string();
    tls_gmail.gmail_imap_tls = true;
    assert!(validate_imap_xoauth2_target(&tls_gmail).is_ok());

    let mut tls_googlemail = Config::for_test();
    tls_googlemail.gmail_imap_host = "imap.googlemail.com".to_string();
    tls_googlemail.gmail_imap_tls = true;
    assert!(validate_imap_xoauth2_target(&tls_googlemail).is_ok());

    let mut loopback = Config::for_test();
    loopback.gmail_imap_host = "127.0.0.1".to_string();
    loopback.gmail_imap_tls = false;
    assert!(validate_imap_xoauth2_target(&loopback).is_ok());

    // RFC 3501 section 5.1.3 Modified UTF-7 edge cases.
    assert_eq!(encode_imap_mutf7("Work/Urgent"), "Work/Urgent");
    assert_eq!(encode_imap_mutf7("R&D"), "R&-D");
    assert_eq!(decode_imap_mutf7("R&-D"), "R&D");
    // U+FFFF encodes in Modified Base64 with ',' instead of '/' (`&,,8-`).
    let ffff = "\u{ffff}";
    let enc_ffff = encode_imap_mutf7(ffff);
    assert!(
        enc_ffff.contains(','),
        "expected comma in Modified Base64, got {enc_ffff}"
    );
    assert!(!enc_ffff.contains('/'));
    assert_eq!(decode_imap_mutf7(&enc_ffff), ffff);

    for sample in [
        "",
        "ASCII Only 123",
        "A&B&&C",
        "Café",
        "日本語/プロジェクト",
        "Café/重要",
        "Rocket 🚀 Launch",
        "é&日本語&🎉",
    ] {
        let encoded = encode_imap_mutf7(sample);
        assert!(
            encoded.is_ascii(),
            "MUTF-7 output must be 7-bit ASCII for {sample:?}: {encoded:?}"
        );
        assert_eq!(
            decode_imap_mutf7(&encoded),
            sample,
            "round-trip failed for {sample:?} (encoded {encoded:?})"
        );
    }

    // Malformed shift sequence falls back safely instead of panicking or truncating.
    assert_eq!(decode_imap_mutf7("R&D"), "R&D");
    assert_eq!(decode_imap_mutf7("Bad&/invalid-"), "Bad&/invalid-");
}
