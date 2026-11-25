//! Pure in-memory `MailStore` implementation for fast tests and backend portability.
//!
//! Owned by the `storage` worker.

use async_trait::async_trait;

use crate::{
    error::AppResult,
    models::{AttachmentMeta, Profile},
    storage::{
        AiMessagePage, AiSearchQuery, AiThreadPage, AiThreadQuery, DraftListPage, HistoryListPage,
        HistoryListQuery, ImapMailboxInfo, ImapMessageEntry, MailStore, MessageListPage,
        MessageListQuery, NewLabelInput, NewMessageInput, StoredAttachment, StoredDraft,
        StoredLabel, StoredMessage, StoredThreadDetail, SyncState, ThreadListPage, TriagePatch,
        TriageResult, UpdateLabelInput, UpsertOutcome, UserSettings, WatchSubscription,
    },
};

/// In-memory implementation of [`MailStore`].
#[derive(Clone, Default)]
pub struct MemoryStore {
    _default_email: String,
}

impl MemoryStore {
    pub fn new(default_email: &str) -> Self {
        Self {
            _default_email: default_email.to_string(),
        }
    }
}

#[async_trait]
impl MailStore for MemoryStore {
    async fn get_profile(&self, _email_address: &str) -> AppResult<Profile> {
        todo!("storage worker")
    }
    async fn current_history_id(&self) -> AppResult<u64> {
        todo!("storage worker")
    }
    async fn list_history(&self, _query: &HistoryListQuery) -> AppResult<HistoryListPage> {
        todo!("storage worker")
    }
    async fn insert_message(&self, _input: NewMessageInput) -> AppResult<StoredMessage> {
        todo!("storage worker")
    }
    async fn get_message(&self, _id: &str) -> AppResult<Option<StoredMessage>> {
        todo!("storage worker")
    }
    async fn list_messages(&self, _query: &MessageListQuery) -> AppResult<MessageListPage> {
        todo!("storage worker")
    }
    async fn modify_message_labels(
        &self,
        _id: &str,
        _add_labels: &[String],
        _remove_labels: &[String],
    ) -> AppResult<StoredMessage> {
        todo!("storage worker")
    }
    async fn batch_modify_labels(
        &self,
        _ids: &[String],
        _add_labels: &[String],
        _remove_labels: &[String],
    ) -> AppResult<()> {
        todo!("storage worker")
    }
    async fn trash_message(&self, _id: &str) -> AppResult<StoredMessage> {
        todo!("storage worker")
    }
    async fn untrash_message(&self, _id: &str) -> AppResult<StoredMessage> {
        todo!("storage worker")
    }
    async fn delete_message(&self, _id: &str) -> AppResult<bool> {
        todo!("storage worker")
    }
    async fn batch_delete_messages(&self, _ids: &[String]) -> AppResult<()> {
        todo!("storage worker")
    }
    async fn get_attachment(
        &self,
        _message_id: &str,
        _attachment_id: &str,
    ) -> AppResult<Option<StoredAttachment>> {
        todo!("storage worker")
    }
    async fn list_attachment_meta(&self, _message_id: &str) -> AppResult<Vec<AttachmentMeta>> {
        todo!("storage worker")
    }
    async fn list_threads(&self, _query: &MessageListQuery) -> AppResult<ThreadListPage> {
        todo!("storage worker")
    }
    async fn get_thread(&self, _thread_id: &str) -> AppResult<Option<StoredThreadDetail>> {
        todo!("storage worker")
    }
    async fn modify_thread_labels(
        &self,
        _thread_id: &str,
        _add_labels: &[String],
        _remove_labels: &[String],
    ) -> AppResult<StoredThreadDetail> {
        todo!("storage worker")
    }
    async fn trash_thread(&self, _thread_id: &str) -> AppResult<StoredThreadDetail> {
        todo!("storage worker")
    }
    async fn untrash_thread(&self, _thread_id: &str) -> AppResult<StoredThreadDetail> {
        todo!("storage worker")
    }
    async fn delete_thread(&self, _thread_id: &str) -> AppResult<bool> {
        todo!("storage worker")
    }
    async fn list_labels(&self) -> AppResult<Vec<StoredLabel>> {
        todo!("storage worker")
    }
    async fn get_label(&self, _id: &str) -> AppResult<Option<StoredLabel>> {
        todo!("storage worker")
    }
    async fn create_label(&self, _input: NewLabelInput) -> AppResult<StoredLabel> {
        todo!("storage worker")
    }
    async fn update_label(
        &self,
        _id: &str,
        _input: UpdateLabelInput,
        _full_replace: bool,
    ) -> AppResult<StoredLabel> {
        todo!("storage worker")
    }
    async fn delete_label(&self, _id: &str) -> AppResult<()> {
        todo!("storage worker")
    }
    async fn upsert_upstream_label(&self, _input: NewLabelInput) -> AppResult<StoredLabel> {
        todo!("storage worker")
    }
    async fn list_drafts(&self, _query: &MessageListQuery) -> AppResult<DraftListPage> {
        todo!("storage worker")
    }
    async fn get_draft(&self, _id: &str) -> AppResult<Option<StoredDraft>> {
        todo!("storage worker")
    }
    async fn create_draft(&self, _message: NewMessageInput) -> AppResult<StoredDraft> {
        todo!("storage worker")
    }
    async fn update_draft(
        &self,
        _draft_id: &str,
        _message: NewMessageInput,
    ) -> AppResult<StoredDraft> {
        todo!("storage worker")
    }
    async fn delete_draft(&self, _draft_id: &str) -> AppResult<bool> {
        todo!("storage worker")
    }
    async fn search_messages_ai(&self, _query: &AiSearchQuery) -> AppResult<AiMessagePage> {
        todo!("storage worker")
    }
    async fn list_thread_summaries(&self, _query: &AiThreadQuery) -> AppResult<AiThreadPage> {
        todo!("storage worker")
    }
    async fn triage_thread(
        &self,
        _thread_id: &str,
        _patch: &TriagePatch,
    ) -> AppResult<TriageResult> {
        todo!("storage worker")
    }
    async fn find_message_by_resend_id(&self, _resend_id: &str) -> AppResult<Option<StoredMessage>> {
        todo!("storage worker")
    }
    async fn find_message_by_rfc_message_id(
        &self,
        _rfc822_message_id: &str,
    ) -> AppResult<Option<StoredMessage>> {
        todo!("storage worker")
    }
    async fn record_delivery_status(
        &self,
        _resend_id: &str,
        _status: &str,
    ) -> AppResult<Option<StoredMessage>> {
        todo!("storage worker")
    }
    async fn imap_list_mailboxes(&self) -> AppResult<Vec<ImapMailboxInfo>> {
        todo!("storage worker")
    }
    async fn imap_mailbox_info(&self, _mailbox_name: &str) -> AppResult<Option<ImapMailboxInfo>> {
        todo!("storage worker")
    }
    async fn imap_list_messages(&self, _mailbox_name: &str) -> AppResult<Vec<ImapMessageEntry>> {
        todo!("storage worker")
    }
    async fn imap_set_flags(
        &self,
        _message_id: &str,
        _is_seen: bool,
        _is_flagged: bool,
        _is_draft: bool,
        _is_answered: bool,
        _is_deleted: bool,
    ) -> AppResult<StoredMessage> {
        todo!("storage worker")
    }
    async fn imap_expunge(&self, _mailbox_name: &str) -> AppResult<Vec<u32>> {
        todo!("storage worker")
    }
    async fn imap_copy_or_move(
        &self,
        _src_mailbox: &str,
        _dst_mailbox: &str,
        _message_ids: &[String],
        _is_move: bool,
    ) -> AppResult<Vec<(u32, u32)>> {
        todo!("storage worker")
    }
    async fn imap_append(
        &self,
        _mailbox_name: &str,
        _input: NewMessageInput,
    ) -> AppResult<(u32, u32, StoredMessage)> {
        todo!("storage worker")
    }
    async fn upsert_synced_message(&self, _input: NewMessageInput) -> AppResult<UpsertOutcome> {
        todo!("storage worker")
    }
    async fn find_message_by_upstream_id(
        &self,
        _upstream_gmail_id: &str,
    ) -> AppResult<Option<StoredMessage>> {
        todo!("storage worker")
    }
    async fn delete_message_by_upstream_id(
        &self,
        _upstream_gmail_id: &str,
    ) -> AppResult<Option<StoredMessage>> {
        todo!("storage worker")
    }
    async fn get_sync_state(&self, _account_key: &str) -> AppResult<Option<SyncState>> {
        todo!("storage worker")
    }
    async fn save_sync_state(&self, _state: SyncState) -> AppResult<()> {
        todo!("storage worker")
    }
    async fn list_sync_states(&self) -> AppResult<Vec<SyncState>> {
        todo!("storage worker")
    }
    async fn set_watch(&self, _watch: WatchSubscription) -> AppResult<WatchSubscription> {
        todo!("storage worker")
    }
    async fn get_watch(&self) -> AppResult<Option<WatchSubscription>> {
        todo!("storage worker")
    }
    async fn clear_watch(&self) -> AppResult<()> {
        todo!("storage worker")
    }
    async fn get_settings(&self) -> AppResult<UserSettings> {
        todo!("storage worker")
    }
    async fn save_settings(&self, _settings: UserSettings) -> AppResult<UserSettings> {
        todo!("storage worker")
    }
}
