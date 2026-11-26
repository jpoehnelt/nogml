//! End-to-end tests for full upstream IMAP sync parity (Issue #75):
//! 1. Bidirectional `X-GM-LABELS` pushback (custom labels, UTF-8 labels, archive/unarchive from `[Gmail]/All Mail`)
//! 2. Non-Gmail IMAP pushback (`UID COPY` + `CREATE` for custom labels, `UID MOVE` to `Archive`) and non-`CONDSTORE` reconciliation fallback
//! 3. Pushing locally created Sent and Draft messages via IMAP `APPEND` + `APPENDUID` dedup, plus Draft update and delete
//! 4. Pulling flag, label, and expunge (`CONDSTORE` `CHANGEDSINCE` + `QRESYNC` `VANISHED`) updates on already-synced UIDs without echo loops
//! 5. Outbound `AUTHENTICATE XOAUTH2` using OAuth2 refresh flow against embedded IMAP server
//! 6. Multi-folder sync (`gmail_imap_folders`) with per-folder checkpoints and cross-folder moves
//! 7. Background read-only IMAP `IDLE` listener triggering immediate incremental sync + clean shutdown

use std::{
    collections::{BTreeMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use nogml::{
    AppState,
    config::{Config, StorageBackend, SyncMode},
    events::{EventSource, MailEvent},
    imap::{mime_fmt::parse_raw_to_new_message_input, serve_plain_listener},
    models::{LABEL_DRAFT, LABEL_IMPORTANT, LABEL_INBOX, LABEL_SENT, LABEL_STARRED, LABEL_UNREAD},
    storage::NewLabelInput,
    sync::{
        SyncRunOptions, get_sync_status, gmail_imap::run_imap_idle_listener_with_options,
        run_gmail_sync,
    },
};
use serde_json::json;
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::watch,
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, method, path},
};

fn make_sqlite_state(mut cfg: Config) -> (TempDir, AppState) {
    let dir = TempDir::new().unwrap();
    cfg.storage = StorageBackend::Sqlite;
    cfg.db_path = dir.path().join("nogml.db");
    let state = AppState::from_config(cfg).unwrap();
    (dir, state)
}

async fn start_embedded_imap_server(
    upstream_state: AppState,
) -> (std::net::SocketAddr, watch::Sender<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = serve_plain_listener(listener, upstream_state, None, shutdown_rx).await;
    });
    (addr, shutdown_tx)
}

fn imap_client_config(addr: std::net::SocketAddr, bidirectional: bool) -> Config {
    let mut cfg = Config::for_test();
    cfg.sync_mode = SyncMode::Imap;
    cfg.sync_bidirectional = bidirectional;
    cfg.gmail_imap_host = addr.ip().to_string();
    cfg.gmail_imap_port = addr.port();
    cfg.gmail_imap_tls = false;
    cfg.gmail_imap_user = Some("agent@example.com".to_string());
    cfg.gmail_imap_password = Some("secret-pass".to_string());
    cfg.gmail_imap_mailbox = "[Gmail]/All Mail".to_string();
    cfg
}

// ============================================================================
// 1. Bidirectional `X-GM-LABELS` pushback & archiving from `[Gmail]/All Mail`
// ============================================================================

#[tokio::test]
async fn xgm_labels_pushback_custom_utf8_and_archive_from_all_mail() {
    let (_up_dir, upstream_state) = make_sqlite_state(Config::for_test());

    let up_existing_lbl = upstream_state
        .store
        .create_label(NewLabelInput {
            name: "OldTag".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();

    let up_m1 = upstream_state
        .store
        .insert_message(parse_raw_to_new_message_input(
            b"From: alice@upstream.test\r\nTo: agent@example.com\r\nSubject: Archive & Tag Me\r\nMessage-ID: <xgm-1@upstream.test>\r\n\r\nBody 1".to_vec(),
            vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            None,
            "local",
            Some("1900000000000001".to_string()),
            None,
            false,
            false,
        ))
        .await
        .unwrap();

    let up_m2 = upstream_state
        .store
        .insert_message(parse_raw_to_new_message_input(
            b"From: bob@upstream.test\r\nTo: agent@example.com\r\nSubject: Unarchive & Untag Me\r\nMessage-ID: <xgm-2@upstream.test>\r\n\r\nBody 2".to_vec(),
            vec![up_existing_lbl.id.clone()],
            None,
            "local",
            Some("1900000000000002".to_string()),
            None,
            false,
            false,
        ))
        .await
        .unwrap();

    let (addr, shutdown_tx) = start_embedded_imap_server(upstream_state.clone()).await;
    let (_local_dir, local_state) = make_sqlite_state(imap_client_config(addr, true));

    // Sync #1: pull both messages from [Gmail]/All Mail.
    let r1 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r1.messages_added, 2);
    assert_eq!(r1.messages_pushed, 0);

    let local_m1 = local_state
        .store
        .find_message_by_upstream_id("1900000000000001")
        .await
        .unwrap()
        .unwrap();
    let local_m2 = local_state
        .store
        .find_message_by_upstream_id("1900000000000002")
        .await
        .unwrap()
        .unwrap();

    // Create custom labels (including nested slash + UTF-8) locally and mutate both messages.
    let lbl_work = local_state
        .store
        .create_label(NewLabelInput {
            name: "Work/Urgent".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    let lbl_utf8 = local_state
        .store
        .create_label(NewLabelInput {
            name: "Café/重要".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    let local_old_tag = local_state
        .store
        .list_labels()
        .await
        .unwrap()
        .into_iter()
        .find(|l| l.name == "OldTag")
        .expect("OldTag synced down");

    // Archive m1 (remove INBOX), mark IMPORTANT, add Work/Urgent and Café/重要.
    local_state
        .store
        .modify_message_labels(
            &local_m1.id,
            &[
                LABEL_IMPORTANT.to_string(),
                lbl_work.id.clone(),
                lbl_utf8.id.clone(),
            ],
            &[LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
        )
        .await
        .unwrap();

    // Unarchive m2 (add INBOX) and remove OldTag.
    local_state
        .store
        .modify_message_labels(
            &local_m2.id,
            &[LABEL_INBOX.to_string()],
            std::slice::from_ref(&local_old_tag.id),
        )
        .await
        .unwrap();

    // Sync #2: pushes +X-GM-LABELS / -X-GM-LABELS directly while [Gmail]/All Mail is selected.
    let r2 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r2.messages_pushed, 2);

    // Verify upstream state directly.
    let up_labels = upstream_state.store.list_labels().await.unwrap();
    let up_work = up_labels
        .iter()
        .find(|l| l.name == "Work/Urgent")
        .expect("Work/Urgent created upstream");
    let up_utf8 = up_labels
        .iter()
        .find(|l| l.name == "Café/重要")
        .expect("Café/重要 created upstream");

    let up_m1_after = upstream_state
        .store
        .get_message(&up_m1.id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !up_m1_after.label_ids.contains(&LABEL_INBOX.to_string()),
        "expected m1 archived (INBOX removed) via -X-GM-LABELS (\\Inbox), got {:?}",
        up_m1_after.label_ids
    );
    assert!(!up_m1_after.label_ids.contains(&LABEL_UNREAD.to_string()));
    assert!(up_m1_after.label_ids.contains(&LABEL_IMPORTANT.to_string()));
    assert!(up_m1_after.label_ids.contains(&up_work.id));
    assert!(up_m1_after.label_ids.contains(&up_utf8.id));

    let up_m2_after = upstream_state
        .store
        .get_message(&up_m2.id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        up_m2_after.label_ids.contains(&LABEL_INBOX.to_string()),
        "expected m2 unarchived (INBOX added) via +X-GM-LABELS (\\Inbox), got {:?}",
        up_m2_after.label_ids
    );
    assert!(
        !up_m2_after.label_ids.contains(&up_existing_lbl.id),
        "expected OldTag removed upstream, got {:?}",
        up_m2_after.label_ids
    );

    // Sync #3: idempotent, no echo loops.
    let r3 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r3.messages_added, 0);
    assert_eq!(r3.messages_updated, 0);
    assert_eq!(r3.messages_pushed, 0);

    let _ = shutdown_tx.send(true);
}

// ============================================================================
// 2. Local Sent & Draft pushback via IMAP APPEND + APPENDUID dedup + Draft update/delete
// ============================================================================

#[tokio::test]
async fn local_sent_and_draft_append_dedup_and_draft_update_delete() {
    let (_up_dir, upstream_state) = make_sqlite_state(Config::for_test());
    upstream_state
        .store
        .insert_message(parse_raw_to_new_message_input(
            b"From: seed@upstream.test\r\nTo: agent@example.com\r\nSubject: Seed\r\nMessage-ID: <seed@upstream.test>\r\n\r\nInitial seed".to_vec(),
            vec![LABEL_INBOX.to_string()],
            None,
            "local",
            Some("1900000000000010".to_string()),
            None,
            false,
            false,
        ))
        .await
        .unwrap();

    let (addr, shutdown_tx) = start_embedded_imap_server(upstream_state.clone()).await;
    let (_local_dir, local_state) = make_sqlite_state(imap_client_config(addr, true));

    // Sync #1: establish baseline history checkpoint.
    let r1 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r1.messages_added, 1);

    // Locally create a Sent message (e.g., sent via Resend/SES/SMTP, no upstream_gmail_id)
    // and a local Draft (starred).
    let local_sent = local_state
        .store
        .insert_message(parse_raw_to_new_message_input(
            b"From: agent@example.com\r\nTo: partner@example.com\r\nSubject: Local Sent Email\r\nMessage-ID: <local-sent-75@nogml.test>\r\n\r\nSent locally via SMTP".to_vec(),
            vec![LABEL_SENT.to_string()],
            Some(1_735_994_096_000),
            "local",
            None,
            None,
            false,
            false,
        ))
        .await
        .unwrap();
    assert!(local_sent.upstream_gmail_id.is_none());

    let local_draft = local_state
        .store
        .create_draft(parse_raw_to_new_message_input(
            b"From: agent@example.com\r\nTo: partner@example.com\r\nSubject: Draft v1\r\nMessage-ID: <local-draft-v1@nogml.test>\r\n\r\nFirst draft body".to_vec(),
            vec![LABEL_DRAFT.to_string(), LABEL_STARRED.to_string()],
            Some(1_735_994_100_000),
            "local",
            None,
            None,
            false,
            false,
        ))
        .await
        .unwrap();
    assert!(local_draft.message.upstream_gmail_id.is_none());

    // Sync #2: pushes both local Sent and Draft upstream via IMAP APPEND!
    let r2 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r2.messages_pushed, 2);

    // Verify both landed upstream with proper labels & flags.
    let up_sent = upstream_state
        .store
        .find_message_by_rfc_message_id("<local-sent-75@nogml.test>")
        .await
        .unwrap()
        .expect("Sent message appended upstream");
    assert!(up_sent.label_ids.contains(&LABEL_SENT.to_string()));
    assert!(!up_sent.label_ids.contains(&LABEL_UNREAD.to_string()));

    let up_draft_v1 = upstream_state
        .store
        .find_message_by_rfc_message_id("<local-draft-v1@nogml.test>")
        .await
        .unwrap()
        .expect("Draft v1 appended upstream");
    assert!(up_draft_v1.label_ids.contains(&LABEL_DRAFT.to_string()));
    assert!(up_draft_v1.label_ids.contains(&LABEL_STARRED.to_string()));

    // Verify local messages were linked to upstream_gmail_id after APPEND.
    let local_sent_linked = local_state
        .store
        .get_message(&local_sent.id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        local_sent_linked.upstream_gmail_id.is_some(),
        "expected upstream_gmail_id persisted on local Sent after APPEND"
    );
    let local_draft_linked = local_state
        .store
        .get_message(&local_draft.message.id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        local_draft_linked.upstream_gmail_id.is_some(),
        "expected upstream_gmail_id persisted on local Draft after APPEND"
    );

    // Sync #3: pulls upstream All Mail where appended messages now exist -> MUST deduplicate cleanly!
    let r3 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(
        r3.messages_added, 0,
        "APPENDed messages must not be re-ingested as duplicates"
    );
    assert_eq!(r3.messages_pushed, 0, "must not echo-loop");
    let local_profile = local_state
        .store
        .get_profile("agent@example.com")
        .await
        .unwrap();
    assert_eq!(local_profile.messages_total, 3);

    // Update the local draft -> Sync #4 appends v2 and deletes v1 upstream.
    let updated_draft = local_state
        .store
        .update_draft(
            &local_draft.id,
            parse_raw_to_new_message_input(
                b"From: agent@example.com\r\nTo: partner@example.com\r\nSubject: Draft v2\r\nMessage-ID: <local-draft-v2@nogml.test>\r\n\r\nUpdated draft body".to_vec(),
                vec![LABEL_DRAFT.to_string()],
                Some(1_735_994_200_000),
                "local",
                None,
                None,
                false,
                false,
            ),
        )
        .await
        .unwrap();

    let r4 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(
        r4.messages_pushed, 2,
        "expected 1 APPEND (v2) + 1 Delete (v1)"
    );
    assert!(
        upstream_state
            .store
            .find_message_by_rfc_message_id("<local-draft-v1@nogml.test>")
            .await
            .unwrap()
            .is_none(),
        "old upstream draft v1 must be expunged on update"
    );
    let up_draft_v2 = upstream_state
        .store
        .find_message_by_rfc_message_id("<local-draft-v2@nogml.test>")
        .await
        .unwrap()
        .expect("updated draft v2 appended upstream");
    assert!(up_draft_v2.label_ids.contains(&LABEL_DRAFT.to_string()));
    assert!(
        local_state
            .store
            .get_message(&updated_draft.message.id)
            .await
            .unwrap()
            .unwrap()
            .upstream_gmail_id
            .is_some()
    );

    // Delete the local draft -> Sync #5 deletes v2 upstream cleanly.
    assert!(
        local_state
            .store
            .delete_draft(&local_draft.id)
            .await
            .unwrap()
    );
    let r5 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r5.messages_pushed, 1);
    assert!(
        upstream_state
            .store
            .find_message_by_rfc_message_id("<local-draft-v2@nogml.test>")
            .await
            .unwrap()
            .is_none(),
        "deleted local draft must be expunged upstream"
    );

    // Final idempotent sync #6.
    let r6 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r6.messages_added, 0);
    assert_eq!(r6.messages_pushed, 0);

    let _ = shutdown_tx.send(true);
}

// ============================================================================
// 3. Pull flag, label, and expunge updates via CONDSTORE CHANGEDSINCE + VANISHED
// ============================================================================

#[tokio::test]
async fn condstore_changedsince_and_qresync_vanished_pull_without_echo_loops() {
    let (_up_dir, upstream_state) = make_sqlite_state(Config::for_test());

    let up_m1 = upstream_state
        .store
        .insert_message(parse_raw_to_new_message_input(
            b"From: web1@upstream.test\r\nTo: agent@example.com\r\nSubject: Mutate Upstream\r\nMessage-ID: <cs-1@upstream.test>\r\n\r\nBody 1".to_vec(),
            vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            None,
            "local",
            Some("1900000000000101".to_string()),
            None,
            false,
            false,
        ))
        .await
        .unwrap();

    let up_m2 = upstream_state
        .store
        .insert_message(parse_raw_to_new_message_input(
            b"From: web2@upstream.test\r\nTo: agent@example.com\r\nSubject: Delete Upstream\r\nMessage-ID: <cs-2@upstream.test>\r\n\r\nBody 2".to_vec(),
            vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            None,
            "local",
            Some("1900000000000102".to_string()),
            None,
            false,
            false,
        ))
        .await
        .unwrap();

    let (addr, shutdown_tx) = start_embedded_imap_server(upstream_state.clone()).await;
    let (_local_dir, local_state) = make_sqlite_state(imap_client_config(addr, true));

    // Sync #1: initial full pull.
    let r1 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r1.messages_added, 2);

    let sync_st = local_state
        .store
        .get_sync_state("gmail_imap:agent@example.com")
        .await
        .unwrap()
        .unwrap();
    assert!(
        sync_st.imap_highest_modseq.is_some_and(|ms| ms > 0),
        "expected highest_modseq persisted after CONDSTORE pull"
    );

    // Mutate upstream directly (simulating Gmail Web/mobile):
    // - m1: mark read, star, add custom label "FromWeb", archive (remove INBOX)
    // - m2: permanently delete (produces VANISHED (EARLIER) in QRESYNC)
    let web_lbl = upstream_state
        .store
        .create_label(NewLabelInput {
            name: "FromWeb".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    upstream_state
        .store
        .modify_message_labels(
            &up_m1.id,
            &[LABEL_STARRED.to_string(), web_lbl.id.clone()],
            &[LABEL_UNREAD.to_string(), LABEL_INBOX.to_string()],
        )
        .await
        .unwrap();
    assert!(
        upstream_state
            .store
            .delete_message(&up_m2.id)
            .await
            .unwrap()
    );

    // Sync #2: pulls CHANGEDSINCE flag/label deltas + VANISHED deletion; zero pushbacks!
    let r2 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert!(!r2.full_resync);
    assert_eq!(r2.messages_added, 0);
    assert_eq!(r2.messages_updated, 1);
    assert_eq!(r2.messages_deleted, 1);
    assert_eq!(
        r2.messages_pushed, 0,
        "pulled deltas must record HistorySource::Sync and never echo back"
    );

    let local_m1 = local_state
        .store
        .find_message_by_upstream_id("1900000000000101")
        .await
        .unwrap()
        .unwrap();
    let local_web_lbl = local_state
        .store
        .list_labels()
        .await
        .unwrap()
        .into_iter()
        .find(|l| l.name == "FromWeb")
        .expect("FromWeb label synced");
    assert!(!local_m1.label_ids.contains(&LABEL_UNREAD.to_string()));
    assert!(!local_m1.label_ids.contains(&LABEL_INBOX.to_string()));
    assert!(local_m1.label_ids.contains(&LABEL_STARRED.to_string()));
    assert!(local_m1.label_ids.contains(&local_web_lbl.id));

    assert!(
        local_state
            .store
            .find_message_by_upstream_id("1900000000000102")
            .await
            .unwrap()
            .is_none(),
        "VANISHED message must be deleted locally"
    );

    // Sync #3: completely quiet, no echo loops.
    let r3 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r3.messages_added, 0);
    assert_eq!(r3.messages_updated, 0);
    assert_eq!(r3.messages_deleted, 0);
    assert_eq!(r3.messages_pushed, 0);

    let _ = shutdown_tx.send(true);
}

// ============================================================================
// 4. Outbound AUTHENTICATE XOAUTH2 via OAuth2 refresh flow
// ============================================================================

#[tokio::test]
async fn xoauth2_authentication_via_refresh_token_against_embedded_imap() {
    let oauth_mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("client_id=imap-cid"))
        .and(body_string_contains("refresh_token=imap-rtok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "imap-xoauth2-bearer-token-75",
            "expires_in": 3600,
            "token_type": "Bearer"
        })))
        .expect(1)
        .mount(&oauth_mock)
        .await;

    // Upstream embedded IMAP server requires bearer token `imap-xoauth2-bearer-token-75` for XOAUTH2
    // and uses a DIFFERENT password for LOGIN so LOGIN could never succeed.
    let mut up_cfg = Config::for_test();
    up_cfg.user_email = "oauth-user@example.com".to_string();
    up_cfg.auth_tokens = vec!["imap-xoauth2-bearer-token-75".to_string()];
    up_cfg.imap_password = Some("different-app-password".to_string());
    let (_up_dir, upstream_state) = make_sqlite_state(up_cfg);
    upstream_state
        .store
        .insert_message(parse_raw_to_new_message_input(
            b"From: sender@upstream.test\r\nTo: oauth-user@example.com\r\nSubject: XOAUTH2 Works\r\nMessage-ID: <xoauth2-1@upstream.test>\r\n\r\nHello XOAUTH2!".to_vec(),
            vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            None,
            "local",
            Some("1900000000000201".to_string()),
            None,
            false,
            false,
        ))
        .await
        .unwrap();

    let (addr, shutdown_tx) = start_embedded_imap_server(upstream_state).await;

    let mut local_cfg = Config::for_test();
    local_cfg.user_email = "oauth-user@example.com".to_string();
    local_cfg.sync_mode = SyncMode::Imap;
    local_cfg.gmail_imap_host = addr.ip().to_string();
    local_cfg.gmail_imap_port = addr.port();
    local_cfg.gmail_imap_tls = false;
    local_cfg.gmail_imap_user = Some("oauth-user@example.com".to_string());
    local_cfg.gmail_imap_password = None; // No App Password! Pure XOAUTH2.
    local_cfg.gmail_client_id = Some("imap-cid".to_string());
    local_cfg.gmail_client_secret = Some("imap-csec".to_string());
    local_cfg.gmail_refresh_token = Some("imap-rtok".to_string());
    local_cfg.gmail_oauth_token_url = format!("{}/token", oauth_mock.uri());
    local_cfg.gmail_imap_mailbox = "[Gmail]/All Mail".to_string();
    assert!(local_cfg.gmail_sync_configured());

    let (_local_dir, local_state) = make_sqlite_state(local_cfg);
    let report = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .expect("XOAUTH2 IMAP sync should succeed");
    assert_eq!(report.messages_added, 1);

    let msg = local_state
        .store
        .find_message_by_upstream_id("1900000000000201")
        .await
        .unwrap()
        .expect("message synced via XOAUTH2");
    assert_eq!(msg.subject, "XOAUTH2 Works");

    let _ = shutdown_tx.send(true);
}

// ============================================================================
// 5. Multi-folder sync checkpoints & cross-folder moves
// ============================================================================

#[tokio::test]
async fn multi_folder_sync_tracks_independent_checkpoints_and_cross_folder_moves() {
    let (_up_dir, upstream_state) = make_sqlite_state(Config::for_test());
    let work_lbl = upstream_state
        .store
        .create_label(NewLabelInput {
            name: "Work".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();

    let up_inbox_msg = upstream_state
        .store
        .insert_message(parse_raw_to_new_message_input(
            b"From: a@upstream.test\r\nSubject: In Inbox\r\nMessage-ID: <mf-1@upstream.test>\r\n\r\nInbox body".to_vec(),
            vec![LABEL_INBOX.to_string()],
            None,
            "local",
            Some("1900000000000301".to_string()),
            None,
            false,
            false,
        ))
        .await
        .unwrap();

    upstream_state
        .store
        .insert_message(parse_raw_to_new_message_input(
            b"From: b@upstream.test\r\nSubject: In Work\r\nMessage-ID: <mf-2@upstream.test>\r\n\r\nWork body".to_vec(),
            vec![work_lbl.id.clone()],
            None,
            "local",
            Some("1900000000000302".to_string()),
            None,
            false,
            false,
        ))
        .await
        .unwrap();

    let (addr, shutdown_tx) = start_embedded_imap_server(upstream_state.clone()).await;

    let mut local_cfg = imap_client_config(addr, false);
    local_cfg.gmail_imap_folders = vec!["INBOX".to_string(), "Work".to_string()];
    let (_local_dir, local_state) = make_sqlite_state(local_cfg);

    // Sync #1: pulls both folders independently.
    let r1 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r1.messages_added, 2);

    let st1 = local_state
        .store
        .get_sync_state("gmail_imap:agent@example.com")
        .await
        .unwrap()
        .unwrap();
    let inbox_cp1 = st1
        .imap_folder_states
        .get("INBOX")
        .expect("INBOX checkpoint")
        .clone();
    let work_cp1 = st1
        .imap_folder_states
        .get("Work")
        .expect("Work checkpoint")
        .clone();
    assert_eq!(inbox_cp1.last_uid, Some(1));
    assert_eq!(work_cp1.last_uid, Some(1));
    assert!(inbox_cp1.uid_validity.is_some());
    assert!(work_cp1.uid_validity.is_some());
    assert_ne!(inbox_cp1.uid_validity, work_cp1.uid_validity);

    // Verify status extra surfaces per-folder checkpoints.
    let status = get_sync_status(&local_state).await.unwrap();
    let folders_json = status
        .extra
        .as_ref()
        .and_then(|e| e.get("imap_folders"))
        .and_then(|v| v.as_object())
        .expect("imap_folders present in sync status");
    assert!(folders_json.contains_key("INBOX"));
    assert!(folders_json.contains_key("Work"));

    // Move up_inbox_msg from INBOX -> Work on upstream, and add a brand-new message in Work.
    upstream_state
        .store
        .modify_message_labels(
            &up_inbox_msg.id,
            std::slice::from_ref(&work_lbl.id),
            &[LABEL_INBOX.to_string()],
        )
        .await
        .unwrap();
    upstream_state
        .store
        .insert_message(parse_raw_to_new_message_input(
            b"From: c@upstream.test\r\nSubject: Second Work\r\nMessage-ID: <mf-3@upstream.test>\r\n\r\nWork body 2".to_vec(),
            vec![work_lbl.id.clone()],
            None,
            "local",
            Some("1900000000000303".to_string()),
            None,
            false,
            false,
        ))
        .await
        .unwrap();

    // Sync #2: message moved from INBOX -> Work is NOT deleted locally; its labels update cleanly!
    let r2 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r2.messages_added, 1);
    assert_eq!(r2.messages_deleted, 0);

    let moved_local = local_state
        .store
        .find_message_by_upstream_id("1900000000000301")
        .await
        .unwrap()
        .expect("moved message preserved locally");
    let local_work_lbl = local_state
        .store
        .list_labels()
        .await
        .unwrap()
        .into_iter()
        .find(|l| l.name == "Work")
        .unwrap();
    assert!(!moved_local.label_ids.contains(&LABEL_INBOX.to_string()));
    assert!(moved_local.label_ids.contains(&local_work_lbl.id));

    let st2 = local_state
        .store
        .get_sync_state("gmail_imap:agent@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(st2.imap_folder_states["INBOX"].last_uid, Some(1));
    assert!(st2.imap_folder_states["Work"].last_uid.unwrap_or(0) >= 3);

    let _ = shutdown_tx.send(true);
}

// ============================================================================
// 6. Non-Gmail IMAP server (no X-GM-EXT-1, no CONDSTORE):
//    UID COPY (+ CREATE), UID MOVE Archive, and bounded reconciliation fallback
// ============================================================================

#[derive(Default)]
struct GenericImapState {
    folders: HashSet<String>,
    inbox_flags: BTreeMap<u32, HashSet<String>>,
    copied_to: Vec<(u32, String)>,
    moved_to: Vec<(u32, String)>,
}

async fn start_generic_non_condstore_imap_server(
    state: Arc<Mutex<GenericImapState>>,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let state = state.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(socket);
                let _ = reader
                    .get_mut()
                    .write_all(b"* OK Generic IMAP4rev1 Ready\r\n")
                    .await;
                let mut line = String::new();
                loop {
                    line.clear();
                    let n = match reader.read_line(&mut line).await {
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    if n == 0 {
                        break;
                    }
                    let trimmed = line.trim();
                    let Some((tag, rest)) = trimmed.split_once(' ') else {
                        continue;
                    };
                    let upper = rest.to_ascii_uppercase();
                    let resp = if upper.starts_with("LOGIN ") {
                        format!("{tag} OK LOGIN completed\r\n")
                    } else if upper == "CAPABILITY" {
                        // Explicitly NO X-GM-EXT-1 and NO CONDSTORE!
                        format!(
                            "* CAPABILITY IMAP4rev1 MOVE UIDPLUS\r\n{tag} OK CAPABILITY completed\r\n"
                        )
                    } else if upper.starts_with("SELECT ") {
                        let st = state.lock().unwrap();
                        let count = st.inbox_flags.len();
                        let uid_next = st.inbox_flags.keys().max().copied().unwrap_or(0) + 1;
                        format!(
                            "* {count} EXISTS\r\n* OK [UIDVALIDITY 77]\r\n* OK [UIDNEXT {uid_next}]\r\n{tag} OK [READ-WRITE] SELECT completed\r\n"
                        )
                    } else if upper.starts_with("UID SEARCH ") {
                        let st = state.lock().unwrap();
                        let query = upper.strip_prefix("UID SEARCH ").unwrap_or("");
                        let uids: Vec<String> = if query.contains("1:") {
                            let max_u: u32 = query
                                .split(':')
                                .nth(1)
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(u32::MAX);
                            st.inbox_flags
                                .keys()
                                .filter(|&&u| u <= max_u)
                                .map(u32::to_string)
                                .collect()
                        } else if let Some(start_str) = query
                            .strip_prefix("UID ")
                            .and_then(|q| q.strip_suffix(":*"))
                        {
                            let start_u: u32 = start_str.parse().unwrap_or(1);
                            st.inbox_flags
                                .keys()
                                .filter(|&&u| u >= start_u)
                                .map(u32::to_string)
                                .collect()
                        } else {
                            st.inbox_flags.keys().map(u32::to_string).collect()
                        };
                        if uids.is_empty() {
                            format!("* SEARCH\r\n{tag} OK UID SEARCH completed\r\n")
                        } else {
                            format!(
                                "* SEARCH {}\r\n{tag} OK UID SEARCH completed\r\n",
                                uids.join(" ")
                            )
                        }
                    } else if upper.starts_with("UID FETCH ") {
                        let st = state.lock().unwrap();
                        let parts: Vec<&str> = rest.split_whitespace().collect();
                        let req_uids: Vec<u32> = parts
                            .get(2)
                            .unwrap_or(&"")
                            .split(',')
                            .filter_map(|s| s.parse().ok())
                            .collect();
                        let wants_body = upper.contains("BODY.PEEK[]");
                        let mut out = String::new();
                        for (seq_idx, (&uid, flags)) in st.inbox_flags.iter().enumerate() {
                            if !req_uids.contains(&uid) {
                                continue;
                            }
                            let seq = seq_idx + 1;
                            let flag_str = flags.iter().cloned().collect::<Vec<_>>().join(" ");
                            if wants_body {
                                let raw = format!(
                                    "From: generic@example.net\r\nTo: agent@example.com\r\nSubject: Generic {uid}\r\nMessage-ID: <gen-{uid}@example.net>\r\n\r\nGeneric body {uid}"
                                );
                                out.push_str(&format!(
                                    "* {seq} FETCH (UID {uid} FLAGS ({flag_str}) INTERNALDATE \"04-Jan-2025 12:00:00 +0000\" BODY[] {{{}}}\r\n{raw})\r\n",
                                    raw.len()
                                ));
                            } else {
                                out.push_str(&format!(
                                    "* {seq} FETCH (UID {uid} FLAGS ({flag_str}))\r\n"
                                ));
                            }
                        }
                        out.push_str(&format!("{tag} OK UID FETCH completed\r\n"));
                        out
                    } else if upper.starts_with("UID STORE ") {
                        let parts: Vec<&str> = rest.split_whitespace().collect();
                        let uid: u32 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
                        let mut st = state.lock().unwrap();
                        if let Some(flags) = st.inbox_flags.get_mut(&uid) {
                            let is_add = upper.contains("+FLAGS");
                            for flag in ["\\Seen", "\\Flagged", "\\Draft", "\\Deleted"] {
                                if rest.contains(flag) {
                                    if is_add {
                                        flags.insert(flag.to_string());
                                    } else {
                                        flags.remove(flag);
                                    }
                                }
                            }
                        }
                        format!("{tag} OK UID STORE completed\r\n")
                    } else if upper.starts_with("CREATE ") {
                        let folder = rest[7..].trim().trim_matches('"').to_string();
                        state.lock().unwrap().folders.insert(folder);
                        format!("{tag} OK CREATE completed\r\n")
                    } else if upper.starts_with("UID COPY ") {
                        let rest_after = &rest[9..];
                        let (uid_s, mbx_raw) = rest_after.split_once(' ').unwrap_or(("0", ""));
                        let uid: u32 = uid_s.parse().unwrap_or(0);
                        let folder = mbx_raw.trim().trim_matches('"').to_string();
                        let mut st = state.lock().unwrap();
                        if !st.folders.contains(&folder) {
                            format!("{tag} NO [TRYCREATE] Folder does not exist\r\n")
                        } else {
                            st.copied_to.push((uid, folder));
                            format!("{tag} OK UID COPY completed\r\n")
                        }
                    } else if upper.starts_with("UID MOVE ") {
                        let rest_after = &rest[9..];
                        let (uid_s, mbx_raw) = rest_after.split_once(' ').unwrap_or(("0", ""));
                        let uid: u32 = uid_s.parse().unwrap_or(0);
                        let folder = mbx_raw.trim().trim_matches('"').to_string();
                        let mut st = state.lock().unwrap();
                        if !st.folders.contains(&folder) {
                            format!("{tag} NO [TRYCREATE] Folder does not exist\r\n")
                        } else {
                            st.inbox_flags.remove(&uid);
                            st.moved_to.push((uid, folder));
                            format!("{tag} OK UID MOVE completed\r\n")
                        }
                    } else if upper == "LOGOUT" {
                        let _ = reader
                            .get_mut()
                            .write_all(format!("* BYE\r\n{tag} OK LOGOUT\r\n").as_bytes())
                            .await;
                        break;
                    } else {
                        format!("{tag} OK\r\n")
                    };

                    if reader.get_mut().write_all(resp.as_bytes()).await.is_err() {
                        break;
                    }
                    let _ = reader.get_mut().flush().await;
                }
            });
        }
    });

    addr
}

#[tokio::test]
async fn generic_imap_without_xgm_or_condstore_supports_copy_create_archive_and_reconcile() {
    let server_state = Arc::new(Mutex::new(GenericImapState::default()));
    {
        let mut st = server_state.lock().unwrap();
        st.folders.insert("INBOX".to_string());
        // Note: neither "Projects" nor "Archive" exist initially -> client must CREATE them!
        st.inbox_flags.insert(1, HashSet::new()); // unread
        st.inbox_flags.insert(2, HashSet::new()); // unread
    }

    let addr = start_generic_non_condstore_imap_server(server_state.clone()).await;
    let mut cfg = imap_client_config(addr, true);
    cfg.gmail_imap_mailbox = "INBOX".to_string();
    cfg.gmail_imap_archive_mailbox = "Archive".to_string();
    let (_local_dir, local_state) = make_sqlite_state(cfg);

    // Sync #1: pulls UIDs 1 & 2 from INBOX.
    let r1 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r1.messages_added, 2);

    // Local mutation on UID 1: add custom label "Projects" + archive (remove INBOX).
    let local_m1 = local_state
        .store
        .find_message_by_upstream_id("imap:INBOX:77:1")
        .await
        .unwrap()
        .unwrap();
    let projects_lbl = local_state
        .store
        .create_label(NewLabelInput {
            name: "Projects".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    local_state
        .store
        .modify_message_labels(
            &local_m1.id,
            std::slice::from_ref(&projects_lbl.id),
            &[LABEL_INBOX.to_string()],
        )
        .await
        .unwrap();

    // Upstream mutation on UID 2 (without CONDSTORE!): mark \Seen and \Flagged.
    {
        let mut st = server_state.lock().unwrap();
        let flags = st.inbox_flags.get_mut(&2).unwrap();
        flags.insert("\\Seen".to_string());
        flags.insert("\\Flagged".to_string());
    }

    // Sync #2:
    // - Non-CONDSTORE reconciliation pulls UID 2's \Seen + \Flagged without echo loop!
    // - Pushback copies UID 1 to "Projects" (creating it) and moves UID 1 to "Archive" (creating it)!
    let r2 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r2.messages_updated, 1);
    assert_eq!(r2.messages_pushed, 1);

    let local_m2 = local_state
        .store
        .find_message_by_upstream_id("imap:INBOX:77:2")
        .await
        .unwrap()
        .unwrap();
    assert!(!local_m2.label_ids.contains(&LABEL_UNREAD.to_string()));
    assert!(local_m2.label_ids.contains(&LABEL_STARRED.to_string()));

    {
        let st = server_state.lock().unwrap();
        assert!(st.folders.contains("Projects"));
        assert!(st.folders.contains("Archive"));
        assert_eq!(st.copied_to, vec![(1, "Projects".to_string())]);
        assert_eq!(st.moved_to, vec![(1, "Archive".to_string())]);
    }
}

// ============================================================================
// 7. Background IMAP IDLE listener triggers immediate incremental sync & shuts down cleanly
// ============================================================================

#[tokio::test]
async fn background_imap_idle_listener_triggers_immediate_sync_and_shuts_down() {
    let (_up_dir, upstream_state) = make_sqlite_state(Config::for_test());
    upstream_state
        .store
        .insert_message(parse_raw_to_new_message_input(
            b"From: init@upstream.test\r\nSubject: Initial IDLE Msg\r\nMessage-ID: <idle-1@upstream.test>\r\n\r\nInit".to_vec(),
            vec![LABEL_INBOX.to_string()],
            None,
            "local",
            Some("1900000000000401".to_string()),
            None,
            false,
            false,
        ))
        .await
        .unwrap();

    let (addr, server_shutdown_tx) = start_embedded_imap_server(upstream_state.clone()).await;

    let mut local_cfg = imap_client_config(addr, false);
    local_cfg.gmail_imap_idle = true;
    let (_local_dir, local_state) = make_sqlite_state(local_cfg);

    // Initial sync pulls message 1.
    let r1 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r1.messages_added, 1);

    // Start IDLE background listener.
    let (idle_shutdown_tx, idle_shutdown_rx) = watch::channel(false);
    let listener_state = local_state.clone();
    let idle_handle = tokio::spawn(async move {
        run_imap_idle_listener_with_options(
            listener_state,
            idle_shutdown_rx,
            Duration::from_secs(30),
            Duration::from_millis(50),
            Duration::from_millis(200),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await;
    });

    // Give IDLE a moment to connect and enter IDLE state.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Deliver a new message upstream and publish MessageReceived so embedded IMAP pushes `* 2 EXISTS`.
    let up_m2 = upstream_state
        .store
        .insert_message(parse_raw_to_new_message_input(
            b"From: push@upstream.test\r\nSubject: Live IDLE Arrival\r\nMessage-ID: <idle-2@upstream.test>\r\n\r\nArrived via IDLE!".to_vec(),
            vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            None,
            "local",
            Some("1900000000000402".to_string()),
            None,
            false,
            false,
        ))
        .await
        .unwrap();
    upstream_state.events.publish(
        EventSource::Imap,
        MailEvent::MessageReceived {
            message_id: up_m2.id.clone(),
            thread_id: up_m2.thread_id.clone(),
            from: up_m2.from_addr.clone(),
            subject: up_m2.subject.clone(),
            snippet: up_m2.snippet.clone(),
            labels: up_m2.label_ids.clone(),
        },
    );

    // Wait up to 3s for IDLE wakeup to trigger incremental sync automatically.
    let mut synced = false;
    for _ in 0..60 {
        if local_state
            .store
            .find_message_by_upstream_id("1900000000000402")
            .await
            .unwrap()
            .is_some()
        {
            synced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        synced,
        "expected background IMAP IDLE listener to trigger immediate incremental sync"
    );

    // Verify clean shutdown.
    let _ = idle_shutdown_tx.send(true);
    tokio::time::timeout(Duration::from_secs(3), idle_handle)
        .await
        .expect("IDLE listener did not stop within 3s")
        .unwrap();

    let _ = server_shutdown_tx.send(true);
}
