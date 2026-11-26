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

// ============================================================================
// 8. Issue #86 Regression: OAuth2 bearer token safety & password preference
// ============================================================================

#[tokio::test]
async fn imap_oauth2_prefers_password_and_refuses_leak_without_auth_xoauth2() {
    // 1. Mock IMAP server that advertises AUTH=XOAUTH2 and records every command received.
    let listener1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr1 = listener1.local_addr().unwrap();
    let received_cmds1: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cmds1_clone = received_cmds1.clone();
    let srv1 = tokio::spawn(async move {
        let (stream, _) = listener1.accept().await.unwrap();
        let (rh, mut wh) = stream.into_split();
        let mut reader = BufReader::new(rh);
        wh.write_all(b"* OK [CAPABILITY IMAP4rev1 AUTH=XOAUTH2] Mock IMAP\r\n")
            .await
            .unwrap();
        let mut line = String::new();
        while reader.read_line(&mut line).await.unwrap() > 0 {
            let trimmed = line.trim().to_string();
            cmds1_clone.lock().unwrap().push(trimmed.clone());
            let mut parts = trimmed.splitn(3, ' ');
            let tag = parts.next().unwrap_or("A0");
            let cmd = parts.next().unwrap_or("").to_ascii_uppercase();
            match cmd.as_str() {
                "LOGIN" => {
                    wh.write_all(format!("{tag} OK LOGIN completed\r\n").as_bytes())
                        .await
                        .unwrap();
                }
                "CAPABILITY" => {
                    wh.write_all(b"* CAPABILITY IMAP4rev1\r\n").await.unwrap();
                    wh.write_all(format!("{tag} OK CAPABILITY completed\r\n").as_bytes())
                        .await
                        .unwrap();
                }
                "SELECT" => {
                    wh.write_all(
                        b"* 0 EXISTS\r\n* OK [UIDVALIDITY 1] ok\r\n* OK [UIDNEXT 1] ok\r\n",
                    )
                    .await
                    .unwrap();
                    wh.write_all(format!("{tag} OK [READ-WRITE] SELECT completed\r\n").as_bytes())
                        .await
                        .unwrap();
                }
                "LOGOUT" => {
                    wh.write_all(b"* BYE logout\r\n").await.unwrap();
                    wh.write_all(format!("{tag} OK LOGOUT completed\r\n").as_bytes())
                        .await
                        .unwrap();
                    break;
                }
                _ => {
                    wh.write_all(format!("{tag} OK done\r\n").as_bytes())
                        .await
                        .unwrap();
                }
            }
            line.clear();
        }
    });

    // Configure BOTH explicit gmail_imap_password AND Gmail OAuth2 creds (with broken refresh URL).
    let mut cfg1 = Config::for_test();
    cfg1.sync_mode = SyncMode::Imap;
    cfg1.gmail_imap_host = addr1.ip().to_string();
    cfg1.gmail_imap_port = addr1.port();
    cfg1.gmail_imap_tls = false;
    cfg1.gmail_imap_user = Some("user@thirdparty.test".to_string());
    cfg1.gmail_imap_password = Some("explicit-imap-pass".to_string());
    cfg1.gmail_access_token = Some("ya29.MUST_NEVER_BE_SENT".to_string());
    cfg1.gmail_oauth_token_url = "http://127.0.0.1:1/unreachable-token".to_string();
    cfg1.gmail_imap_mailbox = "INBOX".to_string();
    let (_d1, state1) = make_sqlite_state(cfg1);

    run_gmail_sync(&state1, SyncRunOptions::default())
        .await
        .expect("explicit gmail_imap_password should succeed via LOGIN without using OAuth2");
    let _ = srv1.await;

    let cmds1 = received_cmds1.lock().unwrap().clone();
    assert!(
        cmds1
            .iter()
            .any(|c| c.to_ascii_uppercase().contains(" LOGIN ")),
        "expected LOGIN command, got {cmds1:?}"
    );
    assert!(
        !cmds1.iter().any(|c| {
            c.to_ascii_uppercase().contains("XOAUTH2") || c.contains("MUST_NEVER_BE_SENT")
        }),
        "OAuth2 bearer token must NEVER be sent when gmail_imap_password is set: {cmds1:?}"
    );

    // 2. Mock IMAP server that does NOT advertise AUTH=XOAUTH2 (neither in greeting nor CAPABILITY).
    let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr2 = listener2.local_addr().unwrap();
    let received_cmds2: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cmds2_clone = received_cmds2.clone();
    let srv2 = tokio::spawn(async move {
        let (stream, _) = listener2.accept().await.unwrap();
        let (rh, mut wh) = stream.into_split();
        let mut reader = BufReader::new(rh);
        wh.write_all(b"* OK Plain third-party IMAP ready\r\n")
            .await
            .unwrap();
        let mut line = String::new();
        while reader.read_line(&mut line).await.unwrap() > 0 {
            let trimmed = line.trim().to_string();
            cmds2_clone.lock().unwrap().push(trimmed.clone());
            let mut parts = trimmed.splitn(3, ' ');
            let tag = parts.next().unwrap_or("C0");
            let cmd = parts.next().unwrap_or("").to_ascii_uppercase();
            if cmd == "CAPABILITY" {
                wh.write_all(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n")
                    .await
                    .unwrap();
                wh.write_all(format!("{tag} OK CAPABILITY completed\r\n").as_bytes())
                    .await
                    .unwrap();
            } else {
                wh.write_all(format!("{tag} NO unsupported\r\n").as_bytes())
                    .await
                    .unwrap();
            }
            line.clear();
        }
    });

    let mut cfg2 = Config::for_test();
    cfg2.sync_mode = SyncMode::Imap;
    cfg2.gmail_imap_host = addr2.ip().to_string();
    cfg2.gmail_imap_port = addr2.port();
    cfg2.gmail_imap_tls = false;
    cfg2.gmail_imap_user = Some("user@thirdparty.test".to_string());
    cfg2.gmail_imap_password = None;
    cfg2.gmail_access_token = Some("ya29.SECRET_OAUTH_TOKEN".to_string());
    cfg2.gmail_imap_mailbox = "INBOX".to_string();
    let (_d2, state2) = make_sqlite_state(cfg2);

    let err2 = run_gmail_sync(&state2, SyncRunOptions::default())
        .await
        .expect_err("sync must fail when server does not advertise AUTH=XOAUTH2");
    assert!(
        err2.to_string().contains("AUTH=XOAUTH2"),
        "unexpected error: {err2}"
    );
    let _ = srv2.await;

    let cmds2 = received_cmds2.lock().unwrap().clone();
    assert!(
        cmds2
            .iter()
            .any(|c| c.to_ascii_uppercase().contains("CAPABILITY")),
        "expected pre-auth CAPABILITY probe, got {cmds2:?}"
    );
    assert!(
        !cmds2.iter().any(|c| {
            c.to_ascii_uppercase().contains("AUTHENTICATE") || c.contains("SECRET_OAUTH_TOKEN")
        }),
        "must never send AUTHENTICATE XOAUTH2 when AUTH=XOAUTH2 is not advertised: {cmds2:?}"
    );

    // 3. Non-Gmail third-party host with OAuth2 only is rejected before opening any socket.
    let mut cfg3 = Config::for_test();
    cfg3.sync_mode = SyncMode::Imap;
    cfg3.gmail_imap_host = "imap.fastmail.com".to_string();
    cfg3.gmail_imap_port = 993;
    cfg3.gmail_imap_tls = true;
    cfg3.gmail_imap_user = Some("user@fastmail.com".to_string());
    cfg3.gmail_imap_password = None;
    cfg3.gmail_access_token = Some("ya29.GOOGLE_TOKEN".to_string());
    let (_d3, state3) = make_sqlite_state(cfg3);
    let err3 = run_gmail_sync(&state3, SyncRunOptions::default())
        .await
        .expect_err("non-Gmail host must be rejected for Google OAuth2");
    assert!(
        err3.to_string().contains("non-Gmail"),
        "unexpected error: {err3}"
    );
}

// ============================================================================
// 9. Issue #86 Regression: X-GM-LABELS uses \Junk + Modified UTF-7 when
//    UTF8=ACCEPT is absent
// ============================================================================

#[tokio::test]
async fn imap_xgm_labels_uses_junk_and_modified_utf7_without_utf8_accept() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let store_cmds: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let store_cmds_clone = store_cmds.clone();

    let raw_msg = b"From: alice@example.com\r\nTo: me@example.com\r\nSubject: MUTF7 Test\r\nMessage-ID: <mutf7-1@example.com>\r\n\r\nBody";
    let raw_len = raw_msg.len();

    let srv = tokio::spawn(async move {
        // Serve 2 connections: connection 1 for pull, connection 2 for push_changes.
        for _ in 0..3 {
            let Ok(Ok((stream, _))) =
                tokio::time::timeout(Duration::from_secs(5), listener.accept()).await
            else {
                break;
            };
            let (rh, mut wh) = stream.into_split();
            let mut reader = BufReader::new(rh);
            wh.write_all(b"* OK Mock Gmail IMAP without UTF8=ACCEPT\r\n")
                .await
                .unwrap();
            let mut line = String::new();
            while reader.read_line(&mut line).await.unwrap() > 0 {
                let trimmed = line.trim().to_string();
                let mut parts = trimmed.splitn(3, ' ');
                let tag = parts.next().unwrap_or("A0");
                let cmd = parts.next().unwrap_or("").to_ascii_uppercase();
                let rest = parts.next().unwrap_or("");
                let rest_upper = rest.to_ascii_uppercase();
                match cmd.as_str() {
                    "LOGIN" => {
                        wh.write_all(format!("{tag} OK LOGIN completed\r\n").as_bytes())
                            .await
                            .unwrap();
                    }
                    "CAPABILITY" => {
                        // Deliberately advertise X-GM-EXT-1 WITHOUT UTF8=ACCEPT!
                        wh.write_all(b"* CAPABILITY IMAP4rev1 X-GM-EXT-1 UIDPLUS\r\n")
                            .await
                            .unwrap();
                        wh.write_all(format!("{tag} OK CAPABILITY completed\r\n").as_bytes())
                            .await
                            .unwrap();
                    }
                    "SELECT" => {
                        wh.write_all(
                            b"* 1 EXISTS\r\n* OK [UIDVALIDITY 77] ok\r\n* OK [UIDNEXT 2] ok\r\n",
                        )
                        .await
                        .unwrap();
                        wh.write_all(
                            format!("{tag} OK [READ-WRITE] SELECT completed\r\n").as_bytes(),
                        )
                        .await
                        .unwrap();
                    }
                    "UID" if rest_upper.starts_with("SEARCH") => {
                        wh.write_all(b"* SEARCH 1\r\n").await.unwrap();
                        wh.write_all(format!("{tag} OK SEARCH completed\r\n").as_bytes())
                            .await
                            .unwrap();
                    }
                    "UID" if rest_upper.starts_with("FETCH") => {
                        if rest_upper.contains("BODY.PEEK[]") {
                            let header = format!(
                                "* 1 FETCH (UID 1 FLAGS (\\Seen) INTERNALDATE \"04-Jan-2025 12:00:00 +0000\" X-GM-MSGID 1001 X-GM-THRID 2001 X-GM-LABELS (\\Inbox \"Caf&AOk-/&kc2JgQ-\") BODY[] {{{raw_len}}}\r\n"
                            );
                            wh.write_all(header.as_bytes()).await.unwrap();
                            wh.write_all(raw_msg).await.unwrap();
                            wh.write_all(b")\r\n").await.unwrap();
                        } else {
                            wh.write_all(
                                b"* 1 FETCH (UID 1 FLAGS (\\Seen) X-GM-MSGID 1001 X-GM-LABELS (\\Inbox \"Caf&AOk-/&kc2JgQ-\"))\r\n",
                            )
                            .await
                            .unwrap();
                        }
                        wh.write_all(format!("{tag} OK FETCH completed\r\n").as_bytes())
                            .await
                            .unwrap();
                    }
                    "UID" if rest_upper.starts_with("STORE") => {
                        store_cmds_clone.lock().unwrap().push(trimmed.clone());
                        wh.write_all(format!("{tag} OK STORE completed\r\n").as_bytes())
                            .await
                            .unwrap();
                    }
                    "LOGOUT" => {
                        wh.write_all(b"* BYE logout\r\n").await.unwrap();
                        wh.write_all(format!("{tag} OK LOGOUT completed\r\n").as_bytes())
                            .await
                            .unwrap();
                        break;
                    }
                    _ => {
                        wh.write_all(format!("{tag} OK done\r\n").as_bytes())
                            .await
                            .unwrap();
                    }
                }
                line.clear();
            }
        }
    });

    let mut cfg = Config::for_test();
    cfg.sync_mode = SyncMode::Imap;
    cfg.sync_bidirectional = true;
    cfg.gmail_imap_host = addr.ip().to_string();
    cfg.gmail_imap_port = addr.port();
    cfg.gmail_imap_tls = false;
    cfg.gmail_imap_user = Some("me@example.com".to_string());
    cfg.gmail_imap_password = Some("pass".to_string());
    cfg.gmail_imap_mailbox = "[Gmail]/All Mail".to_string();
    let (_dir, state) = make_sqlite_state(cfg);

    // Pass 1: Pull message with MUTF-7 encoded X-GM-LABELS ("Caf&AOk-/&kc2JgQ-").
    let r1 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r1.messages_added, 1);

    let labels = state.store.list_labels().await.unwrap();
    let decoded_lbl = labels
        .iter()
        .find(|l| l.name == "Café/重要")
        .expect("MUTF-7 X-GM-LABELS must decode to UTF-8 label 'Café/重要'");
    let synced_msg = state
        .store
        .find_message_by_upstream_id("3e9")
        .await
        .unwrap()
        .expect("synced message by hex X-GM-MSGID 1001 == 0x3e9");
    assert!(synced_msg.label_ids.contains(&decoded_lbl.id));

    // Create another non-ASCII label "日本語" + add LABEL_SPAM locally, then push.
    let jp_lbl = state
        .store
        .create_label(NewLabelInput {
            name: "日本語".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    state
        .store
        .modify_message_labels(
            &synced_msg.id,
            &[nogml::models::LABEL_SPAM.to_string(), jp_lbl.id.clone()],
            &[],
        )
        .await
        .unwrap();

    let r2 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r2.messages_pushed, 1);
    srv.abort();

    let cmds = store_cmds.lock().unwrap().clone();
    let xgm_store = cmds
        .iter()
        .find(|c| c.contains("+X-GM-LABELS"))
        .expect("expected UID STORE +X-GM-LABELS command");
    assert!(
        xgm_store.contains("\\Junk"),
        "LABEL_SPAM must map to \\Junk on the wire, got: {xgm_store}"
    );
    assert!(
        !xgm_store.contains("\\Spam"),
        "invalid \\Spam token must never be sent: {xgm_store}"
    );
    assert!(
        xgm_store.is_ascii(),
        "without UTF8=ACCEPT, X-GM-LABELS command must be 7-bit ASCII MUTF-7, got: {xgm_store}"
    );
    let expected_jp_mutf7 = nogml::sync::gmail_imap::encode_imap_mutf7("日本語");
    assert!(
        xgm_store.contains(&expected_jp_mutf7),
        "expected MUTF-7 encoded label {expected_jp_mutf7} in {xgm_store}"
    );
}

// ============================================================================
// 10. Issue #86 Regression: CONDSTORE without QRESYNC detects expunged UIDs
//     even when HIGHESTMODSEQ does not change
// ============================================================================

#[tokio::test]
async fn imap_condstore_without_qresync_propagates_expunge_with_unchanged_highestmodseq() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let expunged = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let expunged_srv = expunged.clone();

    let raw1 =
        b"From: a@example.com\r\nSubject: Msg One\r\nMessage-ID: <cs-1@example.com>\r\n\r\nOne";
    let raw2 =
        b"From: b@example.com\r\nSubject: Msg Two\r\nMessage-ID: <cs-2@example.com>\r\n\r\nTwo";

    let srv = tokio::spawn(async move {
        for _ in 0..3 {
            let Ok(Ok((stream, _))) =
                tokio::time::timeout(Duration::from_secs(5), listener.accept()).await
            else {
                break;
            };
            let (rh, mut wh) = stream.into_split();
            let mut reader = BufReader::new(rh);
            wh.write_all(b"* OK Mock CONDSTORE-only IMAP\r\n")
                .await
                .unwrap();
            let mut line = String::new();
            while reader.read_line(&mut line).await.unwrap() > 0 {
                let trimmed = line.trim().to_string();
                let mut parts = trimmed.splitn(3, ' ');
                let tag = parts.next().unwrap_or("A0");
                let cmd = parts.next().unwrap_or("").to_ascii_uppercase();
                let rest = parts.next().unwrap_or("");
                let rest_upper = rest.to_ascii_uppercase();
                let is_expunged = expunged_srv.load(std::sync::atomic::Ordering::SeqCst);

                match cmd.as_str() {
                    "LOGIN" => {
                        wh.write_all(format!("{tag} OK LOGIN completed\r\n").as_bytes())
                            .await
                            .unwrap();
                    }
                    "CAPABILITY" => {
                        // CONDSTORE only (NO QRESYNC, like imap.gmail.com)
                        wh.write_all(b"* CAPABILITY IMAP4rev1 CONDSTORE ENABLE\r\n")
                            .await
                            .unwrap();
                        wh.write_all(format!("{tag} OK CAPABILITY completed\r\n").as_bytes())
                            .await
                            .unwrap();
                    }
                    "ENABLE" => {
                        wh.write_all(b"* ENABLED CONDSTORE\r\n").await.unwrap();
                        wh.write_all(format!("{tag} OK ENABLE completed\r\n").as_bytes())
                            .await
                            .unwrap();
                    }
                    "SELECT" => {
                        // Notice HIGHESTMODSEQ stays 50 both BEFORE and AFTER UID 1 is expunged!
                        let exists = if is_expunged { 1 } else { 2 };
                        wh.write_all(
                            format!(
                                "* {exists} EXISTS\r\n* OK [UIDVALIDITY 99] ok\r\n* OK [UIDNEXT 3] ok\r\n* OK [HIGHESTMODSEQ 50] ok\r\n"
                            )
                            .as_bytes(),
                        )
                        .await
                        .unwrap();
                        wh.write_all(
                            format!("{tag} OK [READ-WRITE] SELECT completed\r\n").as_bytes(),
                        )
                        .await
                        .unwrap();
                    }
                    "UID" if rest_upper.starts_with("SEARCH") => {
                        if is_expunged {
                            wh.write_all(b"* SEARCH 2\r\n").await.unwrap();
                        } else {
                            wh.write_all(b"* SEARCH 1 2\r\n").await.unwrap();
                        }
                        wh.write_all(format!("{tag} OK SEARCH completed\r\n").as_bytes())
                            .await
                            .unwrap();
                    }
                    "UID" if rest_upper.starts_with("FETCH") => {
                        if rest_upper.contains("BODY.PEEK[]") {
                            let h1 = format!(
                                "* 1 FETCH (UID 1 FLAGS (\\Seen) MODSEQ (49) INTERNALDATE \"04-Jan-2025 12:00:00 +0000\" BODY[] {{{}}}\r\n",
                                raw1.len()
                            );
                            wh.write_all(h1.as_bytes()).await.unwrap();
                            wh.write_all(raw1).await.unwrap();
                            wh.write_all(b")\r\n").await.unwrap();
                            let h2 = format!(
                                "* 2 FETCH (UID 2 FLAGS (\\Seen) MODSEQ (50) INTERNALDATE \"04-Jan-2025 12:01:00 +0000\" BODY[] {{{}}}\r\n",
                                raw2.len()
                            );
                            wh.write_all(h2.as_bytes()).await.unwrap();
                            wh.write_all(raw2).await.unwrap();
                            wh.write_all(b")\r\n").await.unwrap();
                        }
                        wh.write_all(format!("{tag} OK FETCH completed\r\n").as_bytes())
                            .await
                            .unwrap();
                    }
                    "LOGOUT" => {
                        wh.write_all(b"* BYE logout\r\n").await.unwrap();
                        wh.write_all(format!("{tag} OK LOGOUT completed\r\n").as_bytes())
                            .await
                            .unwrap();
                        break;
                    }
                    _ => {
                        wh.write_all(format!("{tag} OK done\r\n").as_bytes())
                            .await
                            .unwrap();
                    }
                }
                line.clear();
            }
        }
    });

    let mut cfg = Config::for_test();
    cfg.sync_mode = SyncMode::Imap;
    cfg.gmail_imap_host = addr.ip().to_string();
    cfg.gmail_imap_port = addr.port();
    cfg.gmail_imap_tls = false;
    cfg.gmail_imap_user = Some("me@example.com".to_string());
    cfg.gmail_imap_password = Some("pass".to_string());
    cfg.gmail_imap_mailbox = "INBOX".to_string();
    let (_dir, state) = make_sqlite_state(cfg);

    // Pass 1: Initial sync fetches UID 1 and UID 2 with HIGHESTMODSEQ = 50.
    let r1 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r1.messages_added, 2);
    assert!(
        state
            .store
            .find_message_by_upstream_id("imap:INBOX:99:1")
            .await
            .unwrap()
            .is_some()
    );

    // Expunge UID 1 upstream WITHOUT bumping HIGHESTMODSEQ (still 50!).
    expunged.store(true, std::sync::atomic::Ordering::SeqCst);

    // Pass 2: Incremental sync MUST still detect UID 1 vanished and delete it locally.
    let r2 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r2.messages_deleted, 1);
    assert!(
        state
            .store
            .find_message_by_upstream_id("imap:INBOX:99:1")
            .await
            .unwrap()
            .is_none(),
        "expunged UID 1 must be deleted locally even when HIGHESTMODSEQ is unchanged"
    );
    assert!(
        state
            .store
            .find_message_by_upstream_id("imap:INBOX:99:2")
            .await
            .unwrap()
            .is_some()
    );
    srv.abort();
}

// ============================================================================
// 11. Issue #86 Regression: External BlobStore hydration on IMAP APPEND and
//     external blob cleanup on IMAP sync-driven deletions
// ============================================================================

#[tokio::test]
async fn imap_sync_hydrates_external_blobs_on_append_and_cleans_blobs_on_vanish() {
    let (_up_dir, upstream_state) = make_sqlite_state(Config::for_test());
    let up_raw = b"From: alice@upstream.test\r\nTo: me@example.com\r\nSubject: Vanish Blob Test\r\nMessage-ID: <vanish-blob-1@upstream.test>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n--b1\r\nContent-Type: text/plain\r\n\r\nBody\r\n--b1\r\nContent-Type: text/plain; name=\"doc.txt\"\r\nContent-Disposition: attachment; filename=\"doc.txt\"\r\n\r\nattachment-bytes\r\n--b1--\r\n".to_vec();
    let up_msg = upstream_state
        .store
        .insert_message(parse_raw_to_new_message_input(
            up_raw,
            vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            None,
            "local",
            Some("1900000000000801".to_string()),
            None,
            false,
            false,
        ))
        .await
        .unwrap();
    let (addr, shutdown_tx) = start_embedded_imap_server(upstream_state.clone()).await;

    // Configure local node with an external FsBlobStore + bidirectional IMAP sync.
    let local_dir = TempDir::new().unwrap();
    let mut local_cfg = Config::for_test();
    local_cfg.storage = StorageBackend::Sqlite;
    local_cfg.db_path = local_dir.path().join("local.db");
    local_cfg.blob_backend = nogml::config::BlobBackend::Fs;
    local_cfg.blob_dir = local_dir.path().join("blobs");
    local_cfg.sync_mode = SyncMode::Imap;
    local_cfg.sync_bidirectional = true;
    local_cfg.gmail_imap_host = addr.ip().to_string();
    local_cfg.gmail_imap_port = addr.port();
    local_cfg.gmail_imap_tls = false;
    local_cfg.gmail_imap_user = Some("agent@example.com".to_string());
    local_cfg.gmail_imap_password = Some("secret-pass".to_string());
    local_cfg.gmail_imap_mailbox = "[Gmail]/All Mail".to_string();
    let local_state = AppState::from_config(local_cfg).unwrap();

    // Pass 1: Pull upstream message with attachment into local external FsBlobStore.
    let r1 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r1.messages_added, 1);

    let local_pulled = local_state
        .store
        .find_message_by_upstream_id("1900000000000801")
        .await
        .unwrap()
        .unwrap();
    let pulled_raw_key = nogml::blob::raw_message_blob_key(&local_pulled.id);
    let pulled_att_ids = local_state
        .collect_external_attachment_ids(&local_pulled.id)
        .await;
    assert!(
        !pulled_att_ids.is_empty(),
        "expected attachment on pulled message"
    );
    assert!(
        local_state
            .blobs
            .get(&pulled_raw_key)
            .await
            .unwrap()
            .is_some()
    );
    for att_id in &pulled_att_ids {
        let key = nogml::blob::attachment_blob_key(&local_pulled.id, att_id);
        assert!(local_state.blobs.get(&key).await.unwrap().is_some());
    }

    // Create a local Sent message whose rich HTML MIME lives ONLY in FsBlobStore
    // (DB `raw_rfc2822` is empty, simulating offloaded blob storage!).
    let rich_raw = b"From: me@example.com\r\nTo: bob@example.com\r\nSubject: Hydrated HTML Sent\r\nMessage-ID: <hydrated-sent-1@example.com>\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\nX-Custom-Header: preserved-from-blob\r\n\r\n<h1>Rich HTML from BlobStore</h1>".to_vec();
    let mut sent_input = parse_raw_to_new_message_input(
        rich_raw.clone(),
        vec![LABEL_SENT.to_string()],
        None,
        "local",
        None,
        None,
        false,
        false,
    );
    sent_input.raw_rfc2822 = Vec::new(); // Empty in DB; only present in external BlobStore!
    let local_sent = local_state.store.insert_message(sent_input).await.unwrap();
    local_state
        .blobs
        .put(
            &nogml::blob::raw_message_blob_key(&local_sent.id),
            &rich_raw,
        )
        .await
        .unwrap();

    // Also delete `up_msg` upstream so Pass 2 both:
    // (a) deletes `local_pulled` on vanish (cleaning up external blobs!), and
    // (b) pushes `local_sent` via IMAP APPEND hydrated from FsBlobStore!
    upstream_state
        .store
        .delete_message(&up_msg.id)
        .await
        .unwrap();

    let r2 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r2.messages_deleted, 1);
    assert_eq!(r2.messages_pushed, 1);

    // Verify external blobs for the vanished message were cleaned up (no leak!).
    assert!(
        local_state
            .blobs
            .get(&pulled_raw_key)
            .await
            .unwrap()
            .is_none(),
        "raw blob for vanished message must be deleted"
    );
    for att_id in &pulled_att_ids {
        let key = nogml::blob::attachment_blob_key(&local_pulled.id, att_id);
        assert!(
            local_state.blobs.get(&key).await.unwrap().is_none(),
            "attachment blob {att_id} for vanished message must be deleted"
        );
    }

    // Verify the upstream APPENDed message contains the full hydrated HTML + custom header from BlobStore!
    let appended_up = upstream_state
        .store
        .find_message_by_rfc_message_id("<hydrated-sent-1@example.com>")
        .await
        .unwrap()
        .expect("locally created Sent message should be APPENDed upstream");
    let appended_raw = String::from_utf8_lossy(&appended_up.raw_rfc2822);
    assert!(
        appended_raw.contains("<h1>Rich HTML from BlobStore</h1>"),
        "APPENDed message must preserve HTML hydrated from external BlobStore, got: {appended_raw}"
    );
    assert!(
        appended_raw.contains("X-Custom-Header: preserved-from-blob"),
        "APPENDed message must preserve headers hydrated from external BlobStore, got: {appended_raw}"
    );

    let _ = shutdown_tx.send(true);
}
