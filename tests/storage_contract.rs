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
        LabelColor, SYSTEM_LABEL_IDS, ThreadAnnotation, ThreadAnnotationPatch, WaitingOn,
    },
    storage::{
        AiSearchQuery, AiThreadQuery, ApprovalStatus, ContactDirection, ContactInteraction,
        ContactPatch, ContactQuery, HistoryEventKind, HistoryListQuery, MailStore, MemoryStore,
        MessageListQuery, NewAttachmentInput, NewLabelInput, NewMessageInput,
        NewPendingApprovalInput, SqliteStore, SyncState, TriagePatch, UpdateLabelInput,
        UpsertOutcomeKind, WatchSubscription, open_store,
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

async fn contract_thread_annotations(store: Arc<dyn MailStore>) {
    let mut m1 = sample_message(
        "Invoice #4021",
        "billing@vendor.test",
        "Please pay $1,250 by Friday.",
        1_700_000_001_000,
    );
    m1.thread_id = Some("thr_ann_1".to_string());
    let _s1 = store.insert_message(m1).await.unwrap();

    let mut m2 = sample_message(
        "Design review",
        "bob@acme.test",
        "Waiting for their updated mockups.",
        1_700_000_002_000,
    );
    m2.thread_id = Some("thr_ann_2".to_string());
    let _s2 = store.insert_message(m2).await.unwrap();

    let mut m3 = sample_message(
        "Weekly digest",
        "news@digest.test",
        "No reply needed.",
        1_700_000_003_000,
    );
    m3.thread_id = Some("thr_ann_3".to_string());
    let _s3 = store.insert_message(m3).await.unwrap();

    // 1. Initially absent
    assert!(
        store
            .get_thread_annotation("thr_ann_1")
            .await
            .unwrap()
            .is_none()
    );
    let empty_filtered = store
        .list_thread_summaries(&AiThreadQuery {
            needs_reply: Some(true),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(empty_filtered.threads.is_empty());

    // 2. Full upsert round-trip
    let due_at = DateTime::from_timestamp_millis(1_760_000_000_000).unwrap();
    let updated_at = DateTime::from_timestamp_millis(1_750_000_000_000).unwrap();
    let initial = ThreadAnnotation {
        thread_id: "thr_ann_1".to_string(),
        summary: Some("Vendor invoice #4021 due Friday".to_string()),
        needs_reply: Some(true),
        waiting_on: Some(WaitingOn::Me),
        priority: Some("high".to_string()),
        due_at: Some(due_at),
        extracted: serde_json::json!({
            "invoice_id": "INV-4021",
            "amount_usd": 1250
        }),
        updated_by: Some("triage-cron".to_string()),
        updated_at,
    };
    let saved = store
        .upsert_thread_annotation("thr_ann_1", &initial)
        .await
        .unwrap();
    assert_eq!(saved, initial);
    let fetched = store
        .get_thread_annotation("thr_ann_1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched, saved);

    // 3. Patch merges provided fields cleanly and shallow-merges JSON object keys in `extracted`
    let patched = store
        .patch_thread_annotation(
            "thr_ann_1",
            &ThreadAnnotationPatch {
                priority: Some("urgent".to_string()),
                extracted: Some(serde_json::json!({
                    "amount_usd": 1300,
                    "approved_by": "finance"
                })),
                ..Default::default()
            },
            Some("briefing-agent"),
        )
        .await
        .unwrap();
    assert_eq!(
        patched.summary.as_deref(),
        Some("Vendor invoice #4021 due Friday")
    );
    assert_eq!(patched.needs_reply, Some(true));
    assert_eq!(patched.waiting_on, Some(WaitingOn::Me));
    assert_eq!(patched.priority.as_deref(), Some("urgent"));
    assert_eq!(patched.due_at, Some(due_at));
    assert_eq!(patched.updated_by.as_deref(), Some("briefing-agent"));
    assert_eq!(
        patched.extracted,
        serde_json::json!({
            "invoice_id": "INV-4021",
            "amount_usd": 1300,
            "approved_by": "finance"
        })
    );

    // Patch on a thread without an existing annotation creates one
    let patched_2 = store
        .patch_thread_annotation(
            "thr_ann_2",
            &ThreadAnnotationPatch {
                summary: Some("Awaiting mockups from Bob".to_string()),
                needs_reply: Some(false),
                waiting_on: Some(WaitingOn::Them),
                ..Default::default()
            },
            Some("chat-agent"),
        )
        .await
        .unwrap();
    assert_eq!(patched_2.needs_reply, Some(false));
    assert_eq!(patched_2.waiting_on, Some(WaitingOn::Them));

    // 4. Filter by needs_reply and waiting_on in list_thread_summaries
    let need_reply = store
        .list_thread_summaries(&AiThreadQuery {
            needs_reply: Some(true),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(need_reply.threads.len(), 1);
    assert_eq!(need_reply.threads[0].id, "thr_ann_1");
    assert_eq!(
        need_reply.threads[0]
            .annotation
            .as_ref()
            .and_then(|a| a.waiting_on),
        Some(WaitingOn::Me)
    );

    let no_reply = store
        .list_thread_summaries(&AiThreadQuery {
            needs_reply: Some(false),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(no_reply.threads.len(), 1);
    assert_eq!(no_reply.threads[0].id, "thr_ann_2");

    let waiting_me = store
        .list_thread_summaries(&AiThreadQuery {
            waiting_on: Some(WaitingOn::Me),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(waiting_me.threads.len(), 1);
    assert_eq!(waiting_me.threads[0].id, "thr_ann_1");

    let combined = store
        .list_thread_summaries(&AiThreadQuery {
            needs_reply: Some(false),
            waiting_on: Some(WaitingOn::Them),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(combined.threads.len(), 1);
    assert_eq!(combined.threads[0].id, "thr_ann_2");

    let mismatch = store
        .list_thread_summaries(&AiThreadQuery {
            needs_reply: Some(true),
            waiting_on: Some(WaitingOn::Them),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(mismatch.threads.is_empty());

    // Unfiltered listing includes annotations on annotated threads and None on unannotated threads
    let all = store
        .list_thread_summaries(&AiThreadQuery::default())
        .await
        .unwrap();
    assert_eq!(all.threads.len(), 3);
    let t1 = all.threads.iter().find(|t| t.id == "thr_ann_1").unwrap();
    let t3 = all.threads.iter().find(|t| t.id == "thr_ann_3").unwrap();
    assert!(t1.annotation.is_some());
    assert!(t3.annotation.is_none());

    // 5. Full upsert replaces existing fields (clearing priority/due_at)
    let replaced = store
        .upsert_thread_annotation(
            "thr_ann_1",
            &ThreadAnnotation {
                thread_id: "thr_ann_1".to_string(),
                summary: Some("Replaced summary".to_string()),
                needs_reply: Some(false),
                waiting_on: Some(WaitingOn::None),
                priority: None,
                due_at: None,
                extracted: serde_json::json!({ "status": "paid" }),
                updated_by: Some("closer".to_string()),
                updated_at: Utc::now(),
            },
        )
        .await
        .unwrap();
    assert!(replaced.priority.is_none());
    assert!(replaced.due_at.is_none());
    assert_eq!(replaced.extracted, serde_json::json!({ "status": "paid" }));

    // 6. delete_thread_annotation removes annotation
    store.delete_thread_annotation("thr_ann_1").await.unwrap();
    assert!(
        store
            .get_thread_annotation("thr_ann_1")
            .await
            .unwrap()
            .is_none()
    );

    // 7. delete_thread cleans up its persisted annotation
    assert!(store.delete_thread("thr_ann_2").await.unwrap());
    assert!(
        store
            .get_thread_annotation("thr_ann_2")
            .await
            .unwrap()
            .is_none()
    );
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

    // Contacts are strictly isolated per mailbox
    alice
        .record_contact_interaction(&ContactInteraction {
            email: "Shared@Partner.com".to_string(),
            display_name: Some("Alice Partner".to_string()),
            direction: ContactDirection::Sent,
            is_reply: true,
            timestamp_ms: 1_700_000_100_000,
        })
        .await
        .unwrap();
    alice
        .patch_contact(
            "shared@partner.com",
            &ContactPatch {
                is_vip: Some(true),
                display_name: None,
                notes: Some("Alice secret note".to_string()),
            },
        )
        .await
        .unwrap();

    assert!(
        bob.get_contact("shared@partner.com")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        bob.list_contacts(&ContactQuery::default())
            .await
            .unwrap()
            .is_empty()
    );

    let bob_contact = bob
        .record_contact_interaction(&ContactInteraction {
            email: "shared@partner.com".to_string(),
            display_name: Some("Bob Partner".to_string()),
            direction: ContactDirection::Received,
            is_reply: false,
            timestamp_ms: 1_700_000_200_000,
        })
        .await
        .unwrap();
    assert!(!bob_contact.is_vip);
    assert_eq!(bob_contact.received_count, 1);
    assert_eq!(bob_contact.sent_count, 0);

    let alice_contact = alice
        .get_contact("shared@partner.com")
        .await
        .unwrap()
        .unwrap();
    assert!(alice_contact.is_vip);
    assert_eq!(alice_contact.notes.as_deref(), Some("Alice secret note"));
    assert_eq!(alice_contact.sent_count, 1);
    assert_eq!(alice_contact.received_count, 0);

    // Multi-mailbox thread annotation isolation on identical thread_id
    let mut a_ann_msg = sample_message("Shared ID Alice", "x@a.test", "Alice body", 3000);
    a_ann_msg.thread_id = Some("thr_shared_ann".to_string());
    alice.insert_message(a_ann_msg).await.unwrap();
    alice
        .patch_thread_annotation(
            "thr_shared_ann",
            &ThreadAnnotationPatch {
                summary: Some("Alice private summary".to_string()),
                needs_reply: Some(true),
                waiting_on: Some(WaitingOn::Me),
                extracted: Some(serde_json::json!({ "owner": "alice" })),
                ..Default::default()
            },
            Some("alice-agent"),
        )
        .await
        .unwrap();

    assert!(
        bob.get_thread_annotation("thr_shared_ann")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        bob.list_thread_summaries(&AiThreadQuery {
            needs_reply: Some(true),
            ..Default::default()
        })
        .await
        .unwrap()
        .threads
        .is_empty()
    );

    let mut b_ann_msg = sample_message("Shared ID Bob", "x@b.test", "Bob body", 4000);
    b_ann_msg.thread_id = Some("thr_shared_ann".to_string());
    bob.insert_message(b_ann_msg).await.unwrap();
    bob.patch_thread_annotation(
        "thr_shared_ann",
        &ThreadAnnotationPatch {
            summary: Some("Bob private summary".to_string()),
            needs_reply: Some(false),
            waiting_on: Some(WaitingOn::Them),
            extracted: Some(serde_json::json!({ "owner": "bob" })),
            ..Default::default()
        },
        Some("bob-agent"),
    )
    .await
    .unwrap();

    let alice_ann = alice
        .get_thread_annotation("thr_shared_ann")
        .await
        .unwrap()
        .unwrap();
    let bob_ann = bob
        .get_thread_annotation("thr_shared_ann")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alice_ann.summary.as_deref(), Some("Alice private summary"));
    assert_eq!(alice_ann.waiting_on, Some(WaitingOn::Me));
    assert_eq!(bob_ann.summary.as_deref(), Some("Bob private summary"));
    assert_eq!(bob_ann.waiting_on, Some(WaitingOn::Them));
}

async fn contract_contacts_stats_vip_filtering_and_patch(store: Arc<dyn MailStore>) {
    // 1. Invalid email rejected
    let bad = store
        .record_contact_interaction(&ContactInteraction {
            email: "not-an-email".to_string(),
            display_name: None,
            direction: ContactDirection::Received,
            is_reply: false,
            timestamp_ms: 1_000,
        })
        .await
        .unwrap_err();
    assert!(matches!(bad, AppError::BadRequest(_)));

    // 2. Receiving mail creates contact with normalized email/domain & received_count=1
    let c1 = store
        .record_contact_interaction(&ContactInteraction {
            email: "Alice <Alice.Smith@Acme.COM>".to_string(),
            display_name: None,
            direction: ContactDirection::Received,
            is_reply: false,
            timestamp_ms: 2_000,
        })
        .await
        .unwrap();
    assert_eq!(c1.email, "alice.smith@acme.com");
    assert_eq!(c1.domain, "acme.com");
    assert_eq!(c1.display_name.as_deref(), Some("Alice"));
    assert_eq!(c1.received_count, 1);
    assert_eq!(c1.sent_count, 0);
    assert_eq!(c1.replied_by_me_count, 0);
    assert_eq!(c1.first_seen_at_ms, 2_000);
    assert_eq!(c1.last_seen_at_ms, 2_000);
    assert_eq!(c1.last_replied_at_ms, None);
    assert!(!c1.is_vip);
    assert_eq!(c1.vip_override, None);

    // Earlier timestamp updates first_seen_at_ms without regressing last_seen_at_ms
    let c1 = store
        .record_contact_interaction(&ContactInteraction {
            email: "alice.smith@acme.com".to_string(),
            display_name: Some("Should Not Overwrite".to_string()),
            direction: ContactDirection::Sent,
            is_reply: false,
            timestamp_ms: 1_500,
        })
        .await
        .unwrap();
    assert_eq!(c1.display_name.as_deref(), Some("Alice"));
    assert_eq!(c1.sent_count, 1);
    assert_eq!(c1.replied_by_me_count, 0);
    assert_eq!(c1.first_seen_at_ms, 1_500);
    assert_eq!(c1.last_seen_at_ms, 2_000);
    assert!(!c1.is_vip);

    // 3. Three replies trigger automatic VIP inference (replied_by_me_count >= 3)
    for (i, ts) in [3_000_i64, 4_000, 5_000].into_iter().enumerate() {
        let rec = store
            .record_contact_interaction(&ContactInteraction {
                email: "alice.smith@acme.com".to_string(),
                display_name: None,
                direction: ContactDirection::Sent,
                is_reply: true,
                timestamp_ms: ts,
            })
            .await
            .unwrap();
        assert_eq!(rec.replied_by_me_count, (i + 1) as u64);
        assert_eq!(rec.last_replied_at_ms, Some(ts));
        assert_eq!(rec.is_vip, i + 1 >= 3);
        assert_eq!(rec.vip_override, None);
    }

    // 4. Manual override can demote an inferred VIP and stays false after further replies
    let demoted = store
        .patch_contact(
            "ALICE.SMITH@ACME.COM",
            &ContactPatch {
                is_vip: Some(false),
                display_name: Some("Alice Smith".to_string()),
                notes: Some("Former vendor_50%".to_string()),
            },
        )
        .await
        .unwrap();
    assert!(!demoted.is_vip);
    assert_eq!(demoted.vip_override, Some(false));
    assert_eq!(demoted.display_name.as_deref(), Some("Alice Smith"));
    assert_eq!(demoted.notes.as_deref(), Some("Former vendor_50%"));

    let after_reply = store
        .record_contact_interaction(&ContactInteraction {
            email: "alice.smith@acme.com".to_string(),
            display_name: None,
            direction: ContactDirection::Sent,
            is_reply: true,
            timestamp_ms: 6_000,
        })
        .await
        .unwrap();
    assert_eq!(after_reply.replied_by_me_count, 4);
    assert!(!after_reply.is_vip, "manual vip_override=false must stick");
    assert_eq!(after_reply.vip_override, Some(false));

    // 5. Cold sender & manual VIP promotion
    store
        .record_contact_interaction(&ContactInteraction {
            email: "cold@spammy.io".to_string(),
            display_name: Some("Cold Outreach".to_string()),
            direction: ContactDirection::Received,
            is_reply: false,
            timestamp_ms: 7_000,
        })
        .await
        .unwrap();

    let ceo = store
        .patch_contact(
            "ceo@acme.com",
            &ContactPatch {
                is_vip: Some(true),
                display_name: Some("Chief Exec".to_string()),
                notes: Some("Board member".to_string()),
            },
        )
        .await
        .unwrap();
    assert!(ceo.is_vip);
    assert_eq!(ceo.vip_override, Some(true));
    assert_eq!(ceo.sent_count, 0);
    assert_eq!(ceo.received_count, 0);

    // 6. Filtering: vip_only, replied_only, domain, q (including LIKE wildcards), limit, ordering
    let vips = store
        .list_contacts(&ContactQuery {
            vip_only: true,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(vips.len(), 1);
    assert_eq!(vips[0].email, "ceo@acme.com");

    let replied = store
        .list_contacts(&ContactQuery {
            replied_only: true,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(replied.len(), 1);
    assert_eq!(replied[0].email, "alice.smith@acme.com");

    let acme = store
        .list_contacts(&ContactQuery {
            domain: Some("@ACME.COM".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(acme.len(), 2);
    // VIPs always sort first
    assert_eq!(acme[0].email, "ceo@acme.com");
    assert_eq!(acme[1].email, "alice.smith@acme.com");

    // Search q matches notes and escapes literal % and _
    let wildcard_q = store
        .list_contacts(&ContactQuery {
            q: Some("vendor_50%".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(wildcard_q.len(), 1);
    assert_eq!(wildcard_q[0].email, "alice.smith@acme.com");

    let limited = store
        .list_contacts(&ContactQuery {
            limit: 1,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(limited.len(), 1);
    assert_eq!(limited[0].email, "ceo@acme.com");
}

/// Master contract test runner executing every `MailStore` invariant suite on isolated mailboxes.
async fn run_mail_store_contract_suite(base_store: Arc<dyn MailStore>, prefix: &str) {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let mb_core = format!("{prefix}-core-{suffix}@contract.test");
    let mb_imap = format!("{prefix}-imap-{suffix}@contract.test");
    let mb_fts = format!("{prefix}-fts-{suffix}@contract.test");
    let mb_sync = format!("{prefix}-sync-{suffix}@contract.test");
    let mb_apr = format!("{prefix}-apr-{suffix}@contract.test");
    let mb_contacts = format!("{prefix}-contacts-{suffix}@contract.test");
    let mb_ann = format!("{prefix}-ann-{suffix}@contract.test");
    let mb_alice = format!("{prefix}-alice-{suffix}@contract.test");
    let mb_bob = format!("{prefix}-bob-{suffix}@contract.test");

    contract_messages_threads_labels_drafts_attachments(base_store.for_mailbox(&mb_core)).await;
    contract_imap_uids_flags_move_expunge_vanished(base_store.for_mailbox(&mb_imap)).await;
    contract_fts_ai_search_and_cursor_pagination(base_store.for_mailbox(&mb_fts)).await;
    contract_upsert_dedup_settings_watch_sync_state(base_store.for_mailbox(&mb_sync)).await;
    contract_pending_approvals_atomic_transitions(base_store.for_mailbox(&mb_apr)).await;
    contract_contacts_stats_vip_filtering_and_patch(base_store.for_mailbox(&mb_contacts)).await;
    contract_thread_annotations(base_store.for_mailbox(&mb_ann)).await;
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

#[cfg(feature = "postgres")]
#[tokio::test]
async fn postgres_concurrent_connect_and_dml_never_deadlocks() {
    use nogml::storage::PostgresStore;

    let Ok(url) = std::env::var("NOGML_TEST_POSTGRES_URL") else {
        eprintln!("Skipping Postgres concurrency test (NOGML_TEST_POSTGRES_URL not set)");
        return;
    };
    let url = url.trim().to_string();
    if url.is_empty() {
        return;
    }

    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let writer_mb = format!("ddl-writer-{suffix}@postgres.test");
    let writer_store = Arc::new(
        PostgresStore::connect(&url, &writer_mb)
            .await
            .expect("initial PostgresStore::connect"),
    );

    // Verify schema version metadata was recorded.
    let conn = writer_store.pool().get().await.expect("pool conn");
    let max_version: Option<i32> = conn
        .query_one("SELECT MAX(version) FROM nogml_schema_meta", &[])
        .await
        .expect("query nogml_schema_meta")
        .get(0);
    assert!(
        max_version.unwrap_or(0) >= 1,
        "expected nogml_schema_meta version >= 1, got {max_version:?}"
    );
    drop(conn);

    // Run concurrent message/label DML alongside repeated fresh PostgresStore::connect calls
    // (which previously deadlocked between UPDATE labels and CREATE INDEX IF NOT EXISTS).
    let mut handles = Vec::new();

    for worker_idx in 0..3 {
        let store = writer_store.clone();
        handles.push(tokio::spawn(async move {
            for i in 0..10 {
                let ts = 1_700_000_000_000 + (worker_idx * 100 + i) as i64;
                let msg = store
                    .insert_message(sample_message(
                        &format!("Concurrent {worker_idx}-{i}"),
                        "sender@example.com",
                        "Testing concurrent DDL/DML safety",
                        ts,
                    ))
                    .await
                    .expect("insert_message during concurrent connect");
                store
                    .modify_message_labels(&msg.id, &[LABEL_STARRED.to_string()], &[])
                    .await
                    .expect("modify_message_labels during concurrent connect");
            }
        }));
    }

    for conn_idx in 0..4 {
        let url = url.clone();
        let shared_mb = writer_mb.clone();
        let fresh_mb = format!("ddl-peer-{suffix}-{conn_idx}@postgres.test");
        handles.push(tokio::spawn(async move {
            for iter in 0..4 {
                let target_mb = if iter % 2 == 0 { &shared_mb } else { &fresh_mb };
                let peer = PostgresStore::connect(&url, target_mb)
                    .await
                    .expect("concurrent PostgresStore::connect must not deadlock");
                let labels = peer.list_labels().await.expect("list_labels on peer");
                assert!(labels.len() >= SYSTEM_LABEL_IDS.len());
            }
        }));
    }

    for handle in handles {
        handle.await.expect("concurrent task panicked");
    }
}
