//! Pluggable search indexing abstraction (`SearchIndex`) and default `StoreSearchIndex`.
//!
//! Default `StoreSearchIndex` delegates cleanly to `Arc<dyn MailStore>` (SQLite FTS5 or
//! in-memory token search). Swap in Tantivy, pgvector, Qdrant, or hybrid semantic search
//! by implementing [`SearchIndex`] and attaching it to `AppState`.

use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    error::AppResult,
    storage::{AiMessagePage, AiSearchQuery, MailStore, StoredMessage},
};

/// Pluggable async search index abstraction powering `/v1/search`, MCP `search_emails`,
/// and CLI `nogml mail search`.
#[async_trait]
pub trait SearchIndex: Send + Sync {
    /// Index or re-index a stored message.
    async fn index(&self, msg: &StoredMessage) -> AppResult<()>;

    /// Remove a message from the index.
    async fn remove(&self, message_id: &str) -> AppResult<()>;

    /// Execute an AI-first structured/full-text search query.
    async fn search(&self, query: &AiSearchQuery) -> AppResult<AiMessagePage>;

    /// Short backend identifier reported by `GET /v1/capabilities`.
    fn backend_name(&self) -> &'static str;
}

/// Default [`SearchIndex`] backed directly by `Arc<dyn MailStore>` (SQLite FTS5 / Memory).
#[derive(Clone)]
pub struct StoreSearchIndex {
    store: Arc<dyn MailStore>,
}

impl StoreSearchIndex {
    pub fn new(store: Arc<dyn MailStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl SearchIndex for StoreSearchIndex {
    async fn index(&self, _msg: &StoredMessage) -> AppResult<()> {
        // `MailStore` maintains its FTS5 / in-memory index inline on write.
        Ok(())
    }

    async fn remove(&self, _message_id: &str) -> AppResult<()> {
        Ok(())
    }

    async fn search(&self, query: &AiSearchQuery) -> AppResult<AiMessagePage> {
        self.store.search_messages_ai(query).await
    }

    fn backend_name(&self) -> &'static str {
        match self.store.backend_name() {
            "sqlite" => "sqlite_fts5",
            "memory" => "memory",
            _ => "store",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{MemoryStore, NewMessageInput};

    #[tokio::test]
    async fn store_search_index_delegates_to_mail_store() {
        let store = Arc::new(MemoryStore::new("agent@example.com"));
        let msg = store
            .insert_message(NewMessageInput {
                id: None,
                thread_id: None,
                label_ids: vec!["INBOX".into(), "UNREAD".into()],
                raw_rfc2822: b"Subject: Quarterly Invoice\r\n\r\nPlease review Q4 numbers".to_vec(),
                snippet: "Please review Q4 numbers".into(),
                internal_date_ms: 1_700_000_000_000,
                subject: "Quarterly Invoice".into(),
                from_addr: "billing@vendor.test".into(),
                to_addrs: vec!["agent@example.com".into()],
                cc_addrs: vec![],
                bcc_addrs: vec![],
                text_body: "Please review Q4 numbers".into(),
                html_body: None,
                rfc822_message_id: None,
                in_reply_to: None,
                references_header: None,
                resend_id: None,
                upstream_gmail_id: None,
                upstream_thread_id: None,
                source: "local".into(),
                is_answered: false,
                is_deleted: false,
                attachments: vec![],
            })
            .await
            .unwrap();

        let index = StoreSearchIndex::new(store);
        assert_eq!(index.backend_name(), "memory");
        index.index(&msg).await.unwrap();

        let page = index
            .search(&AiSearchQuery {
                q: Some("Invoice".into()),
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page.messages.len(), 1);
        assert_eq!(page.messages[0].id, msg.id);

        index.remove(&msg.id).await.unwrap();
    }
}
