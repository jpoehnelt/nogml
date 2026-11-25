//! Shared `MailStore` contract test suite verifying identical semantics across
//! `SqliteStore`, `MemoryStore`, and `PostgresStore` (when `--features postgres`
//! and `NOGML_TEST_POSTGRES_URL` are set), plus distributed `EventBus` bridge tests.

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use nogml::{
    config::{Config, StorageBackend},
    error::AppError,
    events::{EventBridge, EventBus, EventEnvelope, EventSource, MailEvent},
    models::{
        LABEL_DRAFT, LABEL_INBOX, LABEL_SENT, LABEL_SPAM, LABEL_STARRED, LABEL_TRASH, LABEL_UNREAD,
        LabelColor, SYSTEM_LABEL_IDS,
    },
    storage::{
        AiSearchQuery, AiThreadQuery, ApprovalStatus, HistoryEventKind, HistoryListQuery,
        MailStore, MemoryStore, MessageListQuery, NewAttachmentInput, NewLabelInput,
        NewMessageInput, NewPendingApprovalInput, SqliteStore, SyncState, TriagePatch,
        UpdateLabelInput, UpsertOutcomeKind, WatchSubscription, open_store,
    },
    transport::OutboundMessage,
};

const ALL_MAIL_MAILBOX: &str = "[Gmail]/All Mail";
const TRASH_MAILBOX: &str = "[Gmail]/Trash";
const STARRED_MAILBOX: &str = "[Gmail]/Starred";

fn sample_message(subject: &str, from: &str, text: &str, ts_ms: i64) -> NewMessageInput {
    NewMessageInput {
        id: None,
        thread_id: None,
        label_ids: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
        raw_rfc2822: format!(
            "From: {from}\r\nTo: owner@example.com\r\nSubject: {subject}\r\n\r\n{text}"
        )
        .into_bytes(),
        snippet: text.chars().take(120).collect(),
        internal_date_ms: ts_ms,
        subject: subject.to_string(),
        from_addr: from.to_string(),
        to_addrs: vec!["owner@example.com".to_string()],
        cc_addrs: vec![],
        bcc_addrs: vec![],
        text_body: text.to_string(),
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
    }
}

fn sample_outbound(to: &str, subject: &str) -> OutboundMessage {
    OutboundMessage {
        from: "owner@example.com".to_string(),
        to: vec![to.to_string()],
        cc: vec![],
        bcc: vec![],
        reply_to: vec![],
        subject: subject.to_string(),
        text: Some("Approval body".to_string()),
        html: None,
        headers: Default::default(),
        attachments: vec![],
        tags: Default::default(),
        scheduled_at: None,
        idempotency_key: None,
        raw_rfc2822: b"From: owner@example.com\r\nSubject: Approval\r\n\r\nApproval body".to_vec(),
    }
}

// ============================================================================
// Reusable `MailStore` Contract Suite
// ============================================================================

async fn contract_messages_threads_labels_drafts_attachments(store: Arc<dyn MailStore>) {
    let mb = store.mailbox_id().to_string();

    // 1. Seeded system labels & initial history_id == 1
    let labels = store.list_labels().await.unwrap();
    assert_eq!(labels.len(), SYSTEM_LABEL_IDS.len());
    for sys in SYSTEM_LABEL_IDS {
        assert!(
            labels
                .iter()
                .any(|l| l.id == *sys && l.label_type == "system"),
            "missing system label {sys}"
        );
    }
    let start_hid = store.current_history_id().await.unwrap();
    assert_eq!(start_hid, 1);

    // startHistoryId == 0 must return NotFound
    let err = store
        .list_history(&HistoryListQuery {
            start_history_id: 0,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(matches!(err, AppError::NotFound(_)));

    // 2. Custom label CRUD + duplicate conflict + system label protection
    let work = store
        .create_label(NewLabelInput {
            name: "Work".to_string(),
            color: Some(LabelColor {
                text_color: "#ffffff".to_string(),
                background_color: "#000000".to_string(),
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(work.label_type, "user");
    assert_eq!(work.name, "Work");
    assert!(work.color.is_some());

    // Case-insensitive duplicate label conflict
    let dup = store
        .create_label(NewLabelInput {
            name: "work".to_string(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(matches!(dup, AppError::Conflict(_)));

    // Partial update preserves color; full_replace clears omitted fields
    let updated_partial = store
        .update_label(
            &work.id,
            UpdateLabelInput {
                name: Some("Work/Projects".to_string()),
                ..Default::default()
            },
            false,
        )
        .await
        .unwrap();
    assert_eq!(updated_partial.name, "Work/Projects");
    assert!(updated_partial.color.is_some());

    let updated_full = store
        .update_label(
            &work.id,
            UpdateLabelInput {
                name: Some("Work".to_string()),
                ..Default::default()
            },
            true,
        )
        .await
        .unwrap();
    assert_eq!(updated_full.name, "Work");
    assert!(updated_full.color.is_none());

    // System labels cannot be modified or deleted
    assert!(matches!(
        store
            .update_label(LABEL_INBOX, UpdateLabelInput::default(), false)
            .await,
        Err(AppError::BadRequest(_))
    ));
    assert!(matches!(
        store.delete_label(LABEL_INBOX).await,
        Err(AppError::BadRequest(_))
    ));

    // Upsert upstream label idempotency
    let up1 = store
        .upsert_upstream_label(NewLabelInput {
            name: "Receipts".to_string(),
            upstream_label_id: Some("Label_up_1".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    let up2 = store
        .upsert_upstream_label(NewLabelInput {
            name: "Receipts Renamed".to_string(),
            upstream_label_id: Some("Label_up_1".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(up1.id, up2.id);
    assert_eq!(up2.name, "Receipts Renamed");

    // 3. Messages, threading via In-Reply-To & References, attachments, and lookup helpers
    let mut m1 = sample_message(
        "Project Kickoff",
        "Alice <alice@acme.com>",
        "First message in thread with Q3 invoice attachment",
        1_700_000_001_000,
    );
    m1.rfc822_message_id = Some("<MSG-ROOT-1@ACME.COM>".to_string());
    m1.resend_id = Some("re_msg_1".to_string());
    m1.attachments.push(NewAttachmentInput {
        part_id: "2".to_string(),
        filename: Some("invoice.pdf".to_string()),
        content_type: "application/pdf".to_string(),
        content_id: Some("cid-1".to_string()),
        data: b"%PDF-1.7-contract-bytes".to_vec(),
    });
    let s1 = store.insert_message(m1).await.unwrap();
    assert!(s1.has_attachments);
    assert!(s1.history_id > start_hid);

    let mut m2 = sample_message(
        "Re: Project Kickoff",
        "Bob <bob@acme.com>",
        "Second message replying via In-Reply-To",
        1_700_000_002_000,
    );
    m2.in_reply_to = Some("msg-root-1@acme.com".to_string());
    m2.rfc822_message_id = Some("<msg-reply-2@acme.com>".to_string());
    m2.label_ids = vec![LABEL_INBOX.to_string()]; // read
    let s2 = store.insert_message(m2).await.unwrap();
    assert_eq!(s1.thread_id, s2.thread_id);
    assert!(s2.history_id > s1.history_id);

    let mut m3 = sample_message(
        "Re: Project Kickoff",
        "Carol <carol@acme.com>",
        "Third message replying via References header",
        1_700_000_003_000,
    );
    m3.references_header = Some("<other@x> <MSG-ROOT-1@ACME.COM>".to_string());
    let s3 = store.insert_message(m3).await.unwrap();
    assert_eq!(s1.thread_id, s3.thread_id);

    // Profile counts
    let profile = store.get_profile(&mb).await.unwrap();
    assert_eq!(profile.email_address, mb);
    assert_eq!(profile.messages_total, 3);
    assert_eq!(profile.threads_total, 1);
    assert_eq!(
        profile.history_id,
        store.current_history_id().await.unwrap().to_string()
    );

    // Attachment meta and binary retrieval
    let metas = store.list_attachment_meta(&s1.id).await.unwrap();
    assert_eq!(metas.len(), 1);
    assert_eq!(metas[0].filename.as_deref(), Some("invoice.pdf"));
    assert_eq!(metas[0].size_bytes, b"%PDF-1.7-contract-bytes".len() as u64);
    let att = store
        .get_attachment(&s1.id, &metas[0].id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(att.data, b"%PDF-1.7-contract-bytes");
    assert_eq!(att.content_id.as_deref(), Some("cid-1"));

    // Lookup by resend_id / rfc_message_id / delivery status
    assert_eq!(
        store
            .find_message_by_resend_id("re_msg_1")
            .await
            .unwrap()
            .unwrap()
            .id,
        s1.id
    );
    assert_eq!(
        store
            .find_message_by_rfc_message_id("msg-root-1@acme.com")
            .await
            .unwrap()
            .unwrap()
            .id,
        s1.id
    );
    let delivered = store
        .record_delivery_status("re_msg_1", "delivered")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delivered.delivery_status.as_deref(), Some("delivered"));

    // Label counts: 3 messages in INBOX, 2 unread; 1 thread in INBOX, 1 unread
    let inbox = store.get_label(LABEL_INBOX).await.unwrap().unwrap();
    assert_eq!(inbox.messages_total, 3);
    assert_eq!(inbox.messages_unread, 2);
    assert_eq!(inbox.threads_total, 1);
    assert_eq!(inbox.threads_unread, 1);

    // Message list pagination & Gmail q= filtering
    let page1 = store
        .list_messages(&MessageListQuery {
            max_results: 2,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(page1.messages.len(), 2);
    assert_eq!(page1.result_size_estimate, 3);
    assert!(page1.next_page_token.is_some());
    let page2 = store
        .list_messages(&MessageListQuery {
            max_results: 2,
            page_token: page1.next_page_token.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(page2.messages.len(), 1);
    assert!(page2.next_page_token.is_none());

    // Thread triage & summaries
    let triage = store
        .triage_thread(
            &s1.thread_id,
            &TriagePatch {
                add_labels: vec![work.id.clone()],
                remove_labels: vec![LABEL_UNREAD.to_string()],
            },
        )
        .await
        .unwrap();
    assert_eq!(triage.affected_message_ids.len(), 3);
    assert!(triage.labels.contains(&work.id));
    assert!(!triage.labels.contains(&LABEL_UNREAD.to_string()));

    let summaries = store
        .list_thread_summaries(&AiThreadQuery {
            label: Some("Work".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(summaries.threads.len(), 1);
    assert_eq!(summaries.threads[0].message_count, 3);
    assert!(!summaries.threads[0].unread);
    assert!(summaries.threads[0].has_attachments);

    // Trash / untrash message excludes from default list_messages unless include_spam_trash
    let trashed = store.trash_message(&s3.id).await.unwrap();
    assert!(trashed.label_ids.contains(&LABEL_TRASH.to_string()));
    assert!(!trashed.label_ids.contains(&LABEL_INBOX.to_string()));
    let visible = store
        .list_messages(&MessageListQuery::default())
        .await
        .unwrap();
    assert_eq!(visible.messages.len(), 2);
    let with_trash = store
        .list_messages(&MessageListQuery {
            include_spam_trash: true,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(with_trash.messages.len(), 3);
    let untrashed = store.untrash_message(&s3.id).await.unwrap();
    assert!(!untrashed.label_ids.contains(&LABEL_TRASH.to_string()));

    // Batch modify labels
    store
        .batch_modify_labels(
            &[s1.id.clone(), s2.id.clone()],
            &[LABEL_STARRED.to_string()],
            &[],
        )
        .await
        .unwrap();
    assert!(
        store
            .get_message(&s1.id)
            .await
            .unwrap()
            .unwrap()
            .label_ids
            .contains(&LABEL_STARRED.to_string())
    );
    assert!(
        store
            .get_message(&s2.id)
            .await
            .unwrap()
            .unwrap()
            .label_ids
            .contains(&LABEL_STARRED.to_string())
    );

    // Deleting a user label records LabelRemoved history events and removes label from messages
    let hid_before_del_lbl = store.current_history_id().await.unwrap();
    store.delete_label(&work.id).await.unwrap();
    assert!(store.get_label(&work.id).await.unwrap().is_none());
    let hist_del_lbl = store
        .list_history(&HistoryListQuery {
            start_history_id: hid_before_del_lbl,
            history_types: vec![HistoryEventKind::LabelRemoved],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(hist_del_lbl.entries.len(), 3);

    // History ordering & pagination
    let mut all_hist = Vec::new();
    let mut token = None;
    loop {
        let page = store
            .list_history(&HistoryListQuery {
                start_history_id: start_hid,
                max_results: 3,
                page_token: token,
                ..Default::default()
            })
            .await
            .unwrap();
        all_hist.extend(page.entries);
        match page.next_page_token {
            Some(next) => token = Some(next),
            None => break,
        }
    }
    assert!(all_hist.len() >= 6);
    for w in all_hist.windows(2) {
        assert!(
            w[0].history_id <= w[1].history_id,
            "history entries must be monotonically non-decreasing"
        );
    }

    // 4. Draft lifecycle (create, list, get, update replaces message, delete cleans up message)
    let draft = store
        .create_draft(sample_message(
            "Draft proposal",
            "owner@example.com",
            "Version 1",
            1_700_000_010_000,
        ))
        .await
        .unwrap();
    assert!(draft.message.label_ids.contains(&LABEL_DRAFT.to_string()));
    assert_eq!(
        store
            .list_drafts(&MessageListQuery::default())
            .await
            .unwrap()
            .drafts
            .len(),
        1
    );

    let draft_upd = store
        .update_draft(
            &draft.id,
            sample_message(
                "Draft proposal v2",
                "owner@example.com",
                "Version 2",
                1_700_000_011_000,
            ),
        )
        .await
        .unwrap();
    assert_eq!(draft_upd.id, draft.id);
    assert_ne!(draft_upd.message.id, draft.message.id);
    assert_eq!(draft_upd.message.text_body, "Version 2");
    assert!(
        store
            .get_message(&draft.message.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.delete_draft(&draft.id).await.unwrap());
    assert!(store.get_draft(&draft.id).await.unwrap().is_none());
    assert!(
        store
            .get_message(&draft_upd.message.id)
            .await
            .unwrap()
            .is_none()
    );

    // 5. Thread deletion removes messages and attachments
    assert!(store.delete_thread(&s1.thread_id).await.unwrap());
    assert!(store.get_thread(&s1.thread_id).await.unwrap().is_none());
    assert!(store.list_attachment_meta(&s1.id).await.unwrap().is_empty());
    assert!(!store.delete_thread(&s1.thread_id).await.unwrap());
}

async fn contract_imap_uids_flags_move_expunge_vanished(store: Arc<dyn MailStore>) {
    let project = store
        .create_label(NewLabelInput {
            name: "ProjectX".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();

    let mailboxes = store.imap_list_mailboxes().await.unwrap();
    assert!(mailboxes.iter().any(|m| m.name == "INBOX"));
    assert!(mailboxes.iter().any(|m| m.name == ALL_MAIL_MAILBOX));
    assert!(mailboxes.iter().any(|m| m.name == "ProjectX"));

    let (uv, uid1, m1) = store
        .imap_append("INBOX", sample_message("One", "a@ex.com", "body1", 1000))
        .await
        .unwrap();
    assert!(uv >= 1);
    assert_eq!(uid1, 1);

    let (_, uid2, m2) = store
        .imap_append("INBOX", sample_message("Two", "b@ex.com", "body2", 2000))
        .await
        .unwrap();
    assert_eq!(uid2, 2);

    let inbox_info = store.imap_mailbox_info("INBOX").await.unwrap().unwrap();
    assert_eq!(inbox_info.uid_validity, uv);
    assert_eq!(inbox_info.uid_next, 3);
    assert_eq!(inbox_info.messages, 2);
    assert_eq!(inbox_info.unseen, 2);

    // Attach ProjectX to m2 first, then m1 -> UIDs in ProjectX must be m2=1, m1=2
    store
        .modify_message_labels(&m2.id, std::slice::from_ref(&project.id), &[])
        .await
        .unwrap();
    store
        .modify_message_labels(&m1.id, std::slice::from_ref(&project.id), &[])
        .await
        .unwrap();

    let proj_entries = store.imap_list_messages("ProjectX").await.unwrap();
    assert_eq!(proj_entries.len(), 2);
    assert_eq!(proj_entries[0].message_id, m2.id);
    assert_eq!(proj_entries[0].uid, 1);
    assert_eq!(proj_entries[1].message_id, m1.id);
    assert_eq!(proj_entries[1].uid, 2);

    // Record baseline modseq before expunge
    let modseq_before_expunge = store.current_history_id().await.unwrap();

    // Mark m1 seen, flagged, answered, deleted
    let flagged = store
        .imap_set_flags(&m1.id, true, true, false, true, true)
        .await
        .unwrap();
    assert!(!flagged.label_ids.contains(&LABEL_UNREAD.to_string()));
    assert!(flagged.label_ids.contains(&LABEL_STARRED.to_string()));
    assert!(flagged.is_answered);
    assert!(flagged.is_deleted);
    assert!(flagged.history_id > modseq_before_expunge);

    // Expunge INBOX -> moves m1 to TRASH, returns seq 1, and records vanished UID 1 in INBOX & All Mail
    let expunged = store.imap_expunge("INBOX").await.unwrap();
    assert_eq!(expunged, vec![1]);
    let vanished_inbox = store
        .imap_vanished_uids("INBOX", modseq_before_expunge)
        .await
        .unwrap();
    assert_eq!(vanished_inbox, vec![uid1]);
    let vanished_all_mail = store
        .imap_vanished_uids(ALL_MAIL_MAILBOX, modseq_before_expunge)
        .await
        .unwrap();
    assert_eq!(vanished_all_mail, vec![m1.all_mail_uid]);

    // All Mail excludes trashed m1
    let all_mail = store.imap_list_messages(ALL_MAIL_MAILBOX).await.unwrap();
    assert_eq!(all_mail.len(), 1);
    assert_eq!(all_mail[0].message_id, m2.id);

    // Move m2 from INBOX to [Gmail]/Starred
    let modseq_before_move = store.current_history_id().await.unwrap();
    let moved = store
        .imap_copy_or_move("INBOX", STARRED_MAILBOX, std::slice::from_ref(&m2.id), true)
        .await
        .unwrap();
    assert_eq!(moved.len(), 1);
    assert_eq!(moved[0].0, uid2);
    assert!(store.imap_list_messages("INBOX").await.unwrap().is_empty());
    let vanished_after_move = store
        .imap_vanished_uids("INBOX", modseq_before_move)
        .await
        .unwrap();
    assert_eq!(vanished_after_move, vec![uid2]);

    // Expunge in Trash permanently deletes m1
    store
        .imap_set_flags(&m1.id, true, false, false, false, true)
        .await
        .unwrap();
    let trash_expunged = store.imap_expunge(TRASH_MAILBOX).await.unwrap();
    assert_eq!(trash_expunged, vec![1]);
    assert!(store.get_message(&m1.id).await.unwrap().is_none());
}

async fn contract_fts_ai_search_and_cursor_pagination(store: Arc<dyn MailStore>) {
    let mut m1 = sample_message(
        "Quarterly financial report",
        "Alice <alice@acme.com>",
        "Here are the Q3 revenue numbers and budgets.",
        1_700_000_001_000,
    );
    m1.to_addrs = vec!["finance@corp.test".to_string()];
    m1.attachments.push(NewAttachmentInput {
        part_id: "2".to_string(),
        filename: Some("q3.pdf".to_string()),
        content_type: "application/pdf".to_string(),
        content_id: None,
        data: b"%PDF-1.7".to_vec(),
    });
    let s1 = store.insert_message(m1).await.unwrap();

    let mut m2 = sample_message(
        "Quarterly planning notes",
        "Bob <bob@acme.com>",
        "Let us review quarterly goals tomorrow.",
        1_700_000_002_000,
    );
    m2.label_ids = vec![LABEL_INBOX.to_string()]; // read
    let s2 = store.insert_message(m2).await.unwrap();

    let mut m3 = sample_message(
        "Spam quarterly offer",
        "Spammer <spam@bad.test>",
        "Quarterly deal just for you.",
        1_700_000_003_000,
    );
    m3.label_ids = vec![LABEL_SPAM.to_string()];
    let _s3 = store.insert_message(m3).await.unwrap();

    let m4 = sample_message(
        "Weekend trailhead hike",
        "Carol <carol@other.org>",
        "Trailhead parking opens at 8am.",
        1_700_000_004_000,
    );
    let s4 = store.insert_message(m4).await.unwrap();

    // Full-text search + keyset cursor pagination (SPAM excluded by default)
    let p1 = store
        .search_messages_ai(&AiSearchQuery {
            q: Some("quarterly".to_string()),
            limit: 1,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(p1.messages.len(), 1);
    assert_eq!(p1.messages[0].id, s2.id);
    assert!(p1.has_more);
    assert!(p1.next_cursor.is_some());

    let p2 = store
        .search_messages_ai(&AiSearchQuery {
            q: Some("quarterly".to_string()),
            limit: 1,
            cursor: p1.next_cursor.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(p2.messages.len(), 1);
    assert_eq!(p2.messages[0].id, s1.id);
    assert!(!p2.has_more);
    assert!(p2.next_cursor.is_none());

    // Including spam returns all 3 quarterly matches
    let with_spam = store
        .search_messages_ai(&AiSearchQuery {
            q: Some("quarterly".to_string()),
            include_spam_trash: true,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(with_spam.messages.len(), 3);

    // Structured filters: email q fallback + from + to + unread + has_attachment + date window
    let filtered = store
        .search_messages_ai(&AiSearchQuery {
            q: Some("alice@acme.com".to_string()),
            from: Some("acme.com".to_string()),
            to: Some("finance@corp.test".to_string()),
            unread: Some(true),
            has_attachment: Some(true),
            after: DateTime::from_timestamp_millis(1_700_000_000_500),
            before: DateTime::from_timestamp_millis(1_700_000_001_500),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(filtered.messages.len(), 1);
    assert_eq!(filtered.messages[0].id, s1.id);

    // Deleting removes message from search index
    assert!(store.delete_message(&s4.id).await.unwrap());
    let after_del = store
        .search_messages_ai(&AiSearchQuery {
            q: Some("trailhead".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(after_del.messages.is_empty());
}

async fn contract_upsert_dedup_settings_watch_sync_state(store: Arc<dyn MailStore>) {
    let mb = store.mailbox_id().to_string();

    // 1. Local message sent with RFC Message-ID
    let mut local = sample_message("Sync test", &mb, "Sent locally", 1000);
    local.label_ids = vec![LABEL_SENT.to_string()];
    local.rfc822_message_id = Some("<sync-abc-123@example.com>".to_string());
    let local_stored = store.insert_message(local).await.unwrap();

    // 2. Step 2 dedup: matching normalized rfc822_message_id backfills upstream IDs & merges labels
    let mut synced = sample_message("Sync test", &mb, "Sent locally", 1000);
    synced.label_ids = vec![LABEL_SENT.to_string(), LABEL_STARRED.to_string()];
    synced.rfc822_message_id = Some("SYNC-ABC-123@EXAMPLE.COM".to_string());
    synced.upstream_gmail_id = Some("gm_1001".to_string());
    synced.upstream_thread_id = Some("gm_th_1001".to_string());
    synced.source = "gmail_api".to_string();

    let out1 = store.upsert_synced_message(synced.clone()).await.unwrap();
    assert_eq!(out1.kind, UpsertOutcomeKind::Deduplicated);
    assert_eq!(out1.message.id, local_stored.id);
    assert_eq!(out1.message.upstream_gmail_id.as_deref(), Some("gm_1001"));
    assert!(out1.message.label_ids.contains(&LABEL_STARRED.to_string()));

    // 3. Step 1 match by upstream_gmail_id: unchanged -> Deduplicated; changed labels -> Updated
    let out_same = store.upsert_synced_message(synced.clone()).await.unwrap();
    assert_eq!(out_same.kind, UpsertOutcomeKind::Deduplicated);

    let mut synced_changed = synced.clone();
    synced_changed.label_ids = vec![LABEL_SENT.to_string()];
    let out_upd = store.upsert_synced_message(synced_changed).await.unwrap();
    assert_eq!(out_upd.kind, UpsertOutcomeKind::Updated);
    assert!(
        !out_upd
            .message
            .label_ids
            .contains(&LABEL_STARRED.to_string())
    );

    // 4. Step 3 insert brand-new upstream message + find & delete by upstream_gmail_id
    let mut brand_new = sample_message("Brand new", "ext@ex.com", "Hello", 2000);
    brand_new.upstream_gmail_id = Some("gm_2002".to_string());
    let out_new = store.upsert_synced_message(brand_new).await.unwrap();
    assert_eq!(out_new.kind, UpsertOutcomeKind::Inserted);
    assert_eq!(
        store
            .find_message_by_upstream_id("gm_2002")
            .await
            .unwrap()
            .unwrap()
            .id,
        out_new.message.id
    );
    let del_up = store
        .delete_message_by_upstream_id("gm_2002")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(del_up.id, out_new.message.id);
    assert!(
        store
            .find_message_by_upstream_id("gm_2002")
            .await
            .unwrap()
            .is_none()
    );

    // 5. Settings round-trip
    let mut settings = store.get_settings().await.unwrap();
    assert_eq!(settings.send_as.len(), 1);
    assert_eq!(settings.send_as[0].send_as_email, mb);
    settings.vacation.enable_auto_reply = Some(true);
    settings.vacation.response_subject = Some("OOO".to_string());
    store.save_settings(settings).await.unwrap();
    let reloaded = store.get_settings().await.unwrap();
    assert_eq!(reloaded.vacation.enable_auto_reply, Some(true));
    assert_eq!(reloaded.vacation.response_subject.as_deref(), Some("OOO"));

    // 6. Watch state round-trip
    assert!(store.get_watch().await.unwrap().is_none());
    let watch = WatchSubscription {
        topic_name: "projects/demo/topics/mail".to_string(),
        label_ids: vec![LABEL_INBOX.to_string()],
        label_filter_behavior: "include".to_string(),
        history_id: 99,
        expiration_ms: 9_999_999_999,
    };
    store.set_watch(watch.clone()).await.unwrap();
    let got_watch = store.get_watch().await.unwrap().unwrap();
    assert_eq!(got_watch.topic_name, watch.topic_name);
    assert_eq!(got_watch.history_id, 99);
    store.clear_watch().await.unwrap();
    assert!(store.get_watch().await.unwrap().is_none());

    // 7. SyncState round-trip including bidirectional push checkpoints
    let st = SyncState {
        account_key: "primary".to_string(),
        provider: "gmail_api".to_string(),
        last_history_id: Some("555".to_string()),
        imap_mailbox: Some(ALL_MAIL_MAILBOX.to_string()),
        imap_uid_validity: Some(7),
        imap_last_uid: Some(42),
        last_sync_at: Some(Utc::now()),
        last_full_sync_at: None,
        status: "ok".to_string(),
        last_error: None,
        messages_synced: 12,
        last_pushed_history_id: Some(33),
        messages_pushed: 4,
    };
    store.save_sync_state(st).await.unwrap();
    let got_st = store.get_sync_state("primary").await.unwrap().unwrap();
    assert_eq!(got_st.last_history_id.as_deref(), Some("555"));
    assert_eq!(got_st.last_pushed_history_id, Some(33));
    assert_eq!(got_st.messages_pushed, 4);
    assert_eq!(store.list_sync_states().await.unwrap().len(), 1);
}

async fn contract_pending_approvals_atomic_transitions(store: Arc<dyn MailStore>) {
    let now_ms = Utc::now().timestamp_millis();

    let created = store
        .create_pending_approval(NewPendingApprovalInput {
            id: Some("apr_contract_1".to_string()),
            reason: "external recipient".to_string(),
            requester: None,
            outbound_message: sample_outbound("ext@partner.com", "Needs approval"),
            reply_to_message_id: None,
            thread_id: None,
            draft_id: None,
            created_at_ms: now_ms,
            expires_at_ms: now_ms + 3_600_000,
        })
        .await
        .unwrap();
    assert_eq!(created.status, ApprovalStatus::Pending);

    // Duplicate ID returns Conflict
    let dup = store
        .create_pending_approval(NewPendingApprovalInput {
            id: Some("apr_contract_1".to_string()),
            reason: "duplicate".to_string(),
            requester: None,
            outbound_message: sample_outbound("ext@partner.com", "Dup"),
            reply_to_message_id: None,
            thread_id: None,
            draft_id: None,
            created_at_ms: now_ms,
            expires_at_ms: now_ms + 3_600_000,
        })
        .await
        .unwrap_err();
    assert!(matches!(dup, AppError::Conflict(_)));

    // Expired approval cannot be resolved and transitions to Expired
    let expired = store
        .create_pending_approval(NewPendingApprovalInput {
            id: Some("apr_contract_exp".to_string()),
            reason: "expired".to_string(),
            requester: None,
            outbound_message: sample_outbound("ext@partner.com", "Too late"),
            reply_to_message_id: None,
            thread_id: None,
            draft_id: None,
            created_at_ms: now_ms - 10_000,
            expires_at_ms: now_ms - 1_000,
        })
        .await
        .unwrap();
    let fetched_exp = store
        .get_pending_approval(&expired.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched_exp.status, ApprovalStatus::Expired);
    let res_exp = store
        .resolve_pending_approval(
            &expired.id,
            ApprovalStatus::Approved,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(res_exp, AppError::Conflict(_)));

    // Pending list excludes expired; Expired list includes it
    let pending_list = store
        .list_pending_approvals(Some(ApprovalStatus::Pending), 20)
        .await
        .unwrap();
    assert_eq!(pending_list.len(), 1);
    assert_eq!(pending_list[0].id, "apr_contract_1");
    let expired_list = store
        .list_pending_approvals(Some(ApprovalStatus::Expired), 20)
        .await
        .unwrap();
    assert_eq!(expired_list.len(), 1);
    assert_eq!(expired_list[0].id, "apr_contract_exp");

    // Atomic concurrent transition: racing Approve vs Reject on the same ID lets EXACTLY ONE succeed
    let s_a = store.clone();
    let s_b = store.clone();
    let (res_a, res_b) = tokio::join!(
        s_a.resolve_pending_approval(
            "apr_contract_1",
            ApprovalStatus::Approved,
            Some("alice".to_string()),
            Some("lgtm".to_string()),
            Some("msg_sent_1".to_string()),
            Some("prov_1".to_string()),
        ),
        s_b.resolve_pending_approval(
            "apr_contract_1",
            ApprovalStatus::Rejected,
            Some("bob".to_string()),
            Some("nope".to_string()),
            None,
            None,
        ),
    );
    let ok_count = usize::from(res_a.is_ok()) + usize::from(res_b.is_ok());
    let conflict_count = usize::from(matches!(res_a, Err(AppError::Conflict(_))))
        + usize::from(matches!(res_b, Err(AppError::Conflict(_))));
    assert_eq!(ok_count, 1, "exactly one concurrent resolution must win");
    assert_eq!(
        conflict_count, 1,
        "the losing concurrent resolution must return Conflict"
    );

    // Subsequent resolution attempt must fail with Conflict
    let third = store
        .resolve_pending_approval(
            "apr_contract_1",
            ApprovalStatus::Approved,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(third, AppError::Conflict(_)));
}

async fn contract_multi_mailbox_isolation(
    base_store: Arc<dyn MailStore>,
    alice_mb: &str,
    bob_mb: &str,
) {
    let alice = base_store.for_mailbox(alice_mb);
    let bob = base_store.for_mailbox(bob_mb);

    assert_eq!(alice.mailbox_id(), alice_mb);
    assert_eq!(bob.mailbox_id(), bob_mb);

    // Alice inserts a message, custom label, watch, sync_state, and approval
    let a_lbl = alice
        .create_label(NewLabelInput {
            name: "Secret".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    let mut a_msg = sample_message(
        "Alice confidential",
        "ceo@acme.com",
        "Alice-only token XYZ987",
        1_700_000_050_000,
    );
    a_msg.label_ids = vec![LABEL_INBOX.to_string(), a_lbl.id.clone()];
    let a_stored = alice.insert_message(a_msg).await.unwrap();

    alice
        .set_watch(WatchSubscription {
            topic_name: "projects/a/topics/a".to_string(),
            label_ids: vec![],
            label_filter_behavior: "include".to_string(),
            history_id: 5,
            expiration_ms: 9_999_999,
        })
        .await
        .unwrap();
    alice
        .save_sync_state(SyncState {
            account_key: "primary".to_string(),
            provider: "gmail_api".to_string(),
            status: "ok".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    let now_ms = Utc::now().timestamp_millis();
    alice
        .create_pending_approval(NewPendingApprovalInput {
            id: Some("apr_shared_id".to_string()),
            reason: "alice approval".to_string(),
            requester: None,
            outbound_message: sample_outbound("x@y.com", "Alice mail"),
            reply_to_message_id: None,
            thread_id: None,
            draft_id: None,
            created_at_ms: now_ms,
            expires_at_ms: now_ms + 60_000,
        })
        .await
        .unwrap();

    // Bob sees NONE of Alice's data and starts with independent history_id, UIDs, and settings
    assert!(bob.get_message(&a_stored.id).await.unwrap().is_none());
    assert!(
        bob.list_messages(&MessageListQuery::default())
            .await
            .unwrap()
            .messages
            .is_empty()
    );
    assert!(
        bob.search_messages_ai(&AiSearchQuery {
            q: Some("XYZ987".to_string()),
            ..Default::default()
        })
        .await
        .unwrap()
        .messages
        .is_empty()
    );
    assert!(bob.get_label(&a_lbl.id).await.unwrap().is_none());
    assert!(bob.get_watch().await.unwrap().is_none());
    assert!(bob.get_sync_state("primary").await.unwrap().is_none());
    assert!(
        bob.get_pending_approval("apr_shared_id")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(bob.current_history_id().await.unwrap(), 1);
    assert_eq!(
        bob.get_settings().await.unwrap().send_as[0].send_as_email,
        bob_mb
    );

    // Bob can create the same approval ID and IMAP UID 1 independently
    bob.create_pending_approval(NewPendingApprovalInput {
        id: Some("apr_shared_id".to_string()),
        reason: "bob approval".to_string(),
        requester: None,
        outbound_message: sample_outbound("z@y.com", "Bob mail"),
        reply_to_message_id: None,
        thread_id: None,
        draft_id: None,
        created_at_ms: now_ms,
        expires_at_ms: now_ms + 60_000,
    })
    .await
    .unwrap();
    let (_, bob_uid, _) = bob
        .imap_append("INBOX", sample_message("Bob msg", "b@ex.com", "hi", 2000))
        .await
        .unwrap();
    assert_eq!(bob_uid, 1);
}

/// Master contract test runner executing every `MailStore` invariant suite on isolated mailboxes.
async fn run_mail_store_contract_suite(base_store: Arc<dyn MailStore>, prefix: &str) {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let mb_core = format!("{prefix}-core-{suffix}@contract.test");
    let mb_imap = format!("{prefix}-imap-{suffix}@contract.test");
    let mb_fts = format!("{prefix}-fts-{suffix}@contract.test");
    let mb_sync = format!("{prefix}-sync-{suffix}@contract.test");
    let mb_apr = format!("{prefix}-apr-{suffix}@contract.test");
    let mb_alice = format!("{prefix}-alice-{suffix}@contract.test");
    let mb_bob = format!("{prefix}-bob-{suffix}@contract.test");

    contract_messages_threads_labels_drafts_attachments(base_store.for_mailbox(&mb_core)).await;
    contract_imap_uids_flags_move_expunge_vanished(base_store.for_mailbox(&mb_imap)).await;
    contract_fts_ai_search_and_cursor_pagination(base_store.for_mailbox(&mb_fts)).await;
    contract_upsert_dedup_settings_watch_sync_state(base_store.for_mailbox(&mb_sync)).await;
    contract_pending_approvals_atomic_transitions(base_store.for_mailbox(&mb_apr)).await;
    contract_multi_mailbox_isolation(base_store, &mb_alice, &mb_bob).await;
}

// ============================================================================
// Backend Contract Suite Invocations
// ============================================================================

#[tokio::test]
async fn mail_store_contract_suite_sqlite() {
    let store: Arc<dyn MailStore> =
        Arc::new(SqliteStore::open_in_memory("root@sqlite.test").unwrap());
    assert_eq!(store.backend_name(), "sqlite");
    run_mail_store_contract_suite(store, "sqlite").await;
}

#[tokio::test]
async fn mail_store_contract_suite_memory() {
    let store: Arc<dyn MailStore> = Arc::new(MemoryStore::new("root@memory.test"));
    assert_eq!(store.backend_name(), "memory");
    run_mail_store_contract_suite(store, "memory").await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn mail_store_contract_suite_postgres() {
    let Ok(url) = std::env::var("NOGML_TEST_POSTGRES_URL") else {
        eprintln!("Skipping Postgres MailStore contract test (NOGML_TEST_POSTGRES_URL not set)");
        return;
    };
    let url = url.trim().to_string();
    if url.is_empty() {
        return;
    }

    let root_mb = format!("root-{}@postgres.test", uuid::Uuid::new_v4().simple());
    let store = nogml::storage::PostgresStore::connect(&url, &root_mb)
        .await
        .expect("connect PostgresStore");
    assert_eq!(store.backend_name(), "postgres");
    run_mail_store_contract_suite(Arc::new(store), "pg").await;
}

// ============================================================================
// Config & Feature Guard Tests
// ============================================================================

#[cfg(not(feature = "postgres"))]
#[test]
fn postgres_backend_without_feature_returns_clear_config_error() {
    let mut cfg = Config::for_test();
    cfg.storage = StorageBackend::Postgres;
    let err = match open_store(&cfg) {
        Ok(_) => panic!("expected AppError::Config when built without --features postgres"),
        Err(err) => err,
    };
    match err {
        AppError::Config(msg) => {
            assert!(
                msg.contains("--features postgres"),
                "expected rebuild hint, got: {msg}"
            );
        }
        other => panic!("expected AppError::Config, got: {other:?}"),
    }
}

#[cfg(feature = "postgres")]
#[test]
fn postgres_backend_requires_database_url() {
    let mut cfg = Config::for_test();
    cfg.storage = StorageBackend::Postgres;
    cfg.database_url = None;
    let err = match open_store(&cfg) {
        Ok(_) => panic!("expected AppError::Config when database_url is missing"),
        Err(err) => err,
    };
    assert!(matches!(err, AppError::Config(_)));
}

// ============================================================================
// Distributed `EventBus` Bridge Tests
// ============================================================================

struct RecordingBridge {
    forwarded: Arc<Mutex<Vec<EventEnvelope>>>,
}

impl EventBridge for RecordingBridge {
    fn publish(&self, envelope: &EventEnvelope) {
        self.forwarded.lock().unwrap().push(envelope.clone());
    }

    fn backend_name(&self) -> &'static str {
        "recording"
    }
}

#[tokio::test]
async fn event_bus_bridge_forwards_local_and_never_re_echoes_remote() {
    let forwarded = Arc::new(Mutex::new(Vec::new()));
    let bridge = Arc::new(RecordingBridge {
        forwarded: forwarded.clone(),
    });

    let bus = EventBus::with_mailbox("alice@example.com").with_bridge(bridge);
    let bob_bus = bus.for_mailbox("bob@example.com");
    let mut rx = bus.subscribe();

    // Local publish via scoped handle triggers bridge once and delivers locally
    let local_env = bob_bus.publish(
        EventSource::Api,
        MailEvent::MessageReceived {
            message_id: "m1".to_string(),
            thread_id: "t1".to_string(),
            from: "sender@ex.com".to_string(),
            subject: "Local".to_string(),
            snippet: "Local snippet".to_string(),
            labels: vec![LABEL_INBOX.to_string()],
        },
    );
    assert_eq!(forwarded.lock().unwrap().len(), 1);
    assert_eq!(forwarded.lock().unwrap()[0].mailbox_id, "bob@example.com");
    let got_local = rx.recv().await.unwrap();
    assert_eq!(got_local.id, local_env.id);

    // Remote envelope delivered via publish_remote_envelope fans out locally & enters replay
    // WITHOUT calling bridge.publish again (no infinite echo loop)
    let mut remote_env = local_env.clone();
    remote_env.mailbox_id = "alice@example.com".to_string();
    remote_env.id = 999;
    let replayed = bus.publish_remote_envelope(remote_env);
    assert_eq!(replayed.id, local_env.id + 1);
    assert_eq!(
        forwarded.lock().unwrap().len(),
        1,
        "remote event must not re-trigger outbound bridge"
    );
    let got_remote = rx.recv().await.unwrap();
    assert_eq!(got_remote.mailbox_id, "alice@example.com");
    assert_eq!(bus.events_since(0, 10).len(), 1);
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn postgres_listen_notify_event_bus_bridge_fans_out_across_nodes() {
    use std::time::Duration;

    use nogml::{
        AppState,
        storage::{PostgresEventBridge, PostgresStore},
    };
    use tokio::sync::{oneshot, watch};

    let Ok(url) = std::env::var("NOGML_TEST_POSTGRES_URL") else {
        eprintln!("Skipping Postgres LISTEN/NOTIFY bridge test (NOGML_TEST_POSTGRES_URL not set)");
        return;
    };
    let url = url.trim().to_string();
    if url.is_empty() {
        return;
    }

    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let mb = format!("bridge-{suffix}@postgres.test");
    let channel = format!("nogml_events_test_{}", &suffix[..8]);

    let store_a = PostgresStore::connect(&url, &mb).await.unwrap();
    let store_b = PostgresStore::connect(&url, &mb).await.unwrap();

    let bridge_a = Arc::new(
        PostgresEventBridge::with_channel(url.clone(), store_a.pool().clone(), channel.clone())
            .unwrap(),
    );
    let bridge_b = Arc::new(
        PostgresEventBridge::with_channel(url.clone(), store_b.pool().clone(), channel).unwrap(),
    );
    assert_ne!(bridge_a.node_id(), bridge_b.node_id());

    let bus_a = EventBus::with_mailbox(&mb).with_bridge(bridge_a.clone());
    let bus_b = EventBus::with_mailbox(&mb).with_bridge(bridge_b.clone());

    let mut rx_a = bus_a.subscribe();
    let mut rx_b = bus_b.subscribe();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (ready_a_tx, ready_a_rx) = oneshot::channel();
    let (ready_b_tx, ready_b_rx) = oneshot::channel();

    let handle_a = {
        let bridge = bridge_a.clone();
        let bus = bus_a.clone();
        let rx = shutdown_rx.clone();
        tokio::spawn(async move {
            bridge
                .run_listener_with_ready(bus, rx, Some(ready_a_tx))
                .await;
        })
    };
    let handle_b = {
        let bridge = bridge_b.clone();
        let bus = bus_b.clone();
        let rx = shutdown_rx.clone();
        tokio::spawn(async move {
            bridge
                .run_listener_with_ready(bus, rx, Some(ready_b_tx))
                .await;
        })
    };

    tokio::time::timeout(Duration::from_secs(10), ready_a_rx)
        .await
        .expect("node A listener ready timeout")
        .expect("node A listener ready");
    tokio::time::timeout(Duration::from_secs(10), ready_b_rx)
        .await
        .expect("node B listener ready timeout")
        .expect("node B listener ready");

    // Node A publishes an event -> Node B must receive it over LISTEN/NOTIFY,
    // while Node A must ignore its own echoed notification.
    bus_a.publish(
        EventSource::ResendInbound,
        MailEvent::MessageReceived {
            message_id: "pg_msg_1".to_string(),
            thread_id: "pg_thr_1".to_string(),
            from: "remote@sender.test".to_string(),
            subject: "Cross-node fanout".to_string(),
            snippet: "Delivered across nodes via Postgres NOTIFY".to_string(),
            labels: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
        },
    );

    let local_on_a = tokio::time::timeout(Duration::from_secs(5), rx_a.recv())
        .await
        .expect("node A local recv timeout")
        .expect("node A local event");
    assert_eq!(local_on_a.mailbox_id, mb);

    let remote_on_b = tokio::time::timeout(Duration::from_secs(10), rx_b.recv())
        .await
        .expect("node B remote recv timeout")
        .expect("node B remote event");
    assert_eq!(remote_on_b.mailbox_id, mb);
    assert_eq!(remote_on_b.source, EventSource::ResendInbound);
    match remote_on_b.event {
        MailEvent::MessageReceived {
            message_id,
            subject,
            ..
        } => {
            assert_eq!(message_id, "pg_msg_1");
            assert_eq!(subject, "Cross-node fanout");
        }
        other => panic!("expected MessageReceived on node B, got {other:?}"),
    }
    assert_eq!(bus_b.events_since(0, 10).len(), 1);

    // Ensure node A does NOT receive a duplicate echo of its own NOTIFY
    let echo_check = tokio::time::timeout(Duration::from_millis(300), rx_a.recv()).await;
    assert!(
        echo_check.is_err(),
        "node A must ignore its own echoed Postgres NOTIFY"
    );

    // Also verify AppState::from_config_async wires PostgresStore + postgres_fts + event bridge
    let mut cfg = Config::for_test();
    cfg.storage = StorageBackend::Postgres;
    cfg.database_url = Some(url);
    cfg.user_email = mb.clone();
    let state = AppState::from_config_async(cfg).await.unwrap();
    assert_eq!(state.store.backend_name(), "postgres");
    assert_eq!(state.search.backend_name(), "postgres_fts");
    let listener_handle = state
        .spawn_event_bridge_listener(shutdown_rx.clone())
        .expect("postgres AppState should spawn event bridge listener");

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), handle_a).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), handle_b).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), listener_handle).await;
}
