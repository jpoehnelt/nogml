//! Pluggable search indexing abstraction (`SearchIndex`), default [`StoreSearchIndex`],
//! and hybrid lexical + vector [`HybridSearchIndex`].
//!
//! Default `StoreSearchIndex` delegates cleanly to `Arc<dyn MailStore>` (SQLite FTS5 or
//! in-memory token search) with zero external API keys. Configure `NOGML_SEARCH_BACKEND=hybrid`
//! to combine lexical search with cosine similarity over message embeddings using
//! Reciprocal Rank Fusion (RRF).

pub mod embedding;
pub mod hybrid;
pub mod vector_store;

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{
    config::{Config, SearchBackend, StorageBackend},
    error::AppResult,
    storage::{AiMessagePage, AiSearchQuery, MailStore, MessageListQuery, StoredMessage},
};

pub use embedding::{EmbeddingProvider, OpenAiEmbeddingConfig, OpenAiEmbeddingProvider};
pub use hybrid::{
    DEFAULT_MIN_VECTOR_SIMILARITY, DEFAULT_RRF_K, HybridSearchIndex, cosine_similarity,
    normalize_l2, prepare_message_embedding_text, rrf_fuse,
};
#[cfg(feature = "postgres")]
pub use vector_store::PostgresVectorStore;
pub use vector_store::{
    MemoryVectorStore, SqliteVectorStore, VectorStore, decode_f32_le, encode_f32_le,
};

/// Pluggable async search index abstraction powering `/v1/search`, MCP `search_emails`,
/// and CLI `nogml mail search`.
#[async_trait]
pub trait SearchIndex: Send + Sync {
    /// Index or re-index a stored message during normal ingestion.
    async fn index(&self, msg: &StoredMessage) -> AppResult<()>;

    /// Index or re-index a stored message during explicit backfill (`nogml search reindex`),
    /// propagating errors so callers can track `indexed` vs `failed` counts.
    async fn reindex_message(&self, msg: &StoredMessage) -> AppResult<()> {
        self.index(msg).await
    }

    /// Remove a message from the index.
    async fn remove(&self, message_id: &str) -> AppResult<()>;

    /// Execute an AI-first structured/full-text/semantic search query.
    async fn search(&self, query: &AiSearchQuery) -> AppResult<AiMessagePage>;

    /// Return a lightweight `SearchIndex` handle scoped strictly to `mailbox_id`, if supported.
    fn for_mailbox(&self, _mailbox_id: &str) -> Option<Arc<dyn SearchIndex>> {
        None
    }

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

    fn for_mailbox(&self, mailbox_id: &str) -> Option<Arc<dyn SearchIndex>> {
        Some(Arc::new(Self::new(self.store.for_mailbox(mailbox_id))))
    }

    fn backend_name(&self) -> &'static str {
        match self.store.backend_name() {
            "sqlite" => "sqlite_fts5",
            "postgres" => "postgres_fts",
            "memory" => "memory",
            _ => "store",
        }
    }
}

/// Construct the configured [`SearchIndex`] backend (`store` or `hybrid`).
pub fn open_search_index(
    config: &Config,
    store: Arc<dyn MailStore>,
) -> AppResult<Arc<dyn SearchIndex>> {
    match config.search_backend {
        SearchBackend::Store => Ok(Arc::new(StoreSearchIndex::new(store))),
        SearchBackend::Hybrid => {
            let provider = Arc::new(OpenAiEmbeddingProvider::from_config(config)?);
            let vectors: Arc<dyn VectorStore> = match config.storage {
                StorageBackend::Sqlite => Arc::new(SqliteVectorStore::open_for_mailbox(
                    &config.db_path,
                    &config.user_email,
                )?),
                StorageBackend::Memory => {
                    Arc::new(MemoryVectorStore::for_mailbox_new(&config.user_email))
                }
                StorageBackend::Postgres => open_postgres_vector_store(config)?,
            };
            Ok(Arc::new(HybridSearchIndex::new(store, provider, vectors)))
        }
    }
}

#[cfg(feature = "postgres")]
fn open_postgres_vector_store(config: &Config) -> AppResult<Arc<dyn VectorStore>> {
    let url = config
        .database_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            crate::error::AppError::Config(
                "NOGML_DATABASE_URL / --database-url is required for hybrid search with NOGML_STORAGE=postgres"
                    .to_string(),
            )
        })?;
    Ok(Arc::new(PostgresVectorStore::from_url(
        url,
        &config.user_email,
    )?))
}

#[cfg(not(feature = "postgres"))]
fn open_postgres_vector_store(_config: &Config) -> AppResult<Arc<dyn VectorStore>> {
    Err(crate::error::AppError::Config(
        "Rebuild nogml with --features postgres to use hybrid search with Postgres storage"
            .to_string(),
    ))
}

/// Summary returned by [`reindex_mailbox`] and `nogml search reindex`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReindexReport {
    pub backend: String,
    pub indexed: u64,
    pub failed: u64,
}

/// Iterate every message in `store` and re-index it into `search`.
pub async fn reindex_mailbox(
    store: &dyn MailStore,
    search: &dyn SearchIndex,
) -> AppResult<ReindexReport> {
    let mut page_token: Option<String> = None;
    let mut indexed = 0u64;
    let mut failed = 0u64;

    loop {
        let page = store
            .list_messages(&MessageListQuery {
                include_spam_trash: true,
                max_results: 500,
                page_token: page_token.clone(),
                ..Default::default()
            })
            .await?;

        for msg in &page.messages {
            match search.reindex_message(msg).await {
                Ok(()) => indexed += 1,
                Err(err) => {
                    tracing::warn!(
                        message_id = %msg.id,
                        backend = search.backend_name(),
                        error = %err,
                        "Failed to reindex message"
                    );
                    failed += 1;
                }
            }
        }

        match page.next_page_token {
            Some(token) => page_token = Some(token),
            None => break,
        }
    }

    Ok(ReindexReport {
        backend: search.backend_name().to_string(),
        indexed,
        failed,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::{
        error::AppError,
        storage::{MemoryStore, NewMessageInput},
    };

    fn sample_input(
        id: &str,
        subject: &str,
        body: &str,
        labels: Vec<&str>,
        internal_date_ms: i64,
    ) -> NewMessageInput {
        NewMessageInput {
            id: Some(id.to_string()),
            thread_id: None,
            label_ids: labels.into_iter().map(str::to_string).collect(),
            raw_rfc2822: format!("Subject: {subject}\r\n\r\n{body}").into_bytes(),
            snippet: body.to_string(),
            internal_date_ms,
            subject: subject.to_string(),
            from_addr: "billing@vendor.test".to_string(),
            to_addrs: vec!["agent@example.com".to_string()],
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
        }
    }

    struct ToggleEmbeddingProvider {
        fail: Arc<AtomicBool>,
    }

    #[async_trait]
    impl EmbeddingProvider for ToggleEmbeddingProvider {
        async fn embed(&self, texts: &[String]) -> AppResult<Vec<Vec<f32>>> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(AppError::Upstream {
                    status: 503,
                    message: "embedding service unavailable".to_string(),
                });
            }
            let out = texts
                .iter()
                .map(|t| {
                    let lower = t.to_ascii_lowercase();
                    if lower.contains("outage")
                        || lower.contains("downtime")
                        || lower.contains("incident")
                    {
                        vec![1.0, 0.0, 0.0]
                    } else if lower.contains("invoice") || lower.contains("receipt") {
                        vec![0.0, 1.0, 0.0]
                    } else {
                        vec![0.0, 0.0, 1.0]
                    }
                })
                .collect();
            Ok(out)
        }

        fn model_name(&self) -> &str {
            "mock-embed-v1"
        }
    }

    #[test]
    fn cosine_similarity_and_normalization_edge_cases() {
        let a = normalize_l2(&[3.0, 4.0]);
        assert!((a[0] - 0.6).abs() < 1e-6);
        assert!((a[1] - 0.8).abs() < 1e-6);

        assert!((cosine_similarity(&[1.0, 0.0], &[1.0, 0.0]) - 1.0).abs() < 1e-6);
        assert!(cosine_similarity(&[1.0, 0.0], &[0.0, 1.0]).abs() < 1e-6);
        assert!((cosine_similarity(&[1.0, 0.0], &[-1.0, 0.0]) + 1.0).abs() < 1e-6);
        assert_eq!(cosine_similarity(&[], &[]), 0.0);
        assert_eq!(cosine_similarity(&[1.0, 2.0], &[1.0]), 0.0);
        assert_eq!(cosine_similarity(&[0.0, 0.0], &[1.0, 0.0]), 0.0);

        let zero = normalize_l2(&[0.0, 0.0]);
        assert_eq!(zero, vec![0.0, 0.0]);
    }

    #[test]
    fn rrf_fuse_ranks_overlap_above_single_list_hits() {
        let lexical = vec!["m1".to_string(), "m2".to_string(), "m3".to_string()];
        let vector = vec!["m3".to_string(), "m4".to_string(), "m1".to_string()];

        let fused = rrf_fuse(&lexical, &vector, DEFAULT_RRF_K);
        let ids: Vec<&str> = fused.iter().map(|(id, _)| id.as_str()).collect();

        // Both m1 (1/61 + 1/63) and m3 (1/63 + 1/61) appear in both lists -> tied at top, tie-broken by id.
        assert_eq!(&ids[..2], &["m1", "m3"]);
        // m2 and m4 appear at rank 2 in one list -> 1/62 each.
        assert_eq!(&ids[2..], &["m2", "m4"]);

        let expected_top = 1.0 / 61.0 + 1.0 / 63.0;
        assert!((fused[0].1 - expected_top).abs() < 1e-12);
        assert!((fused[2].1 - (1.0 / 62.0)).abs() < 1e-12);
    }

    #[test]
    fn f32_le_blob_roundtrip_and_invalid_len() {
        let orig = vec![-1.5_f32, 0.0, 0.25, 42.125];
        let encoded = encode_f32_le(&orig);
        assert_eq!(encoded.len(), 16);
        let decoded = decode_f32_le(&encoded).unwrap();
        assert_eq!(decoded, orig);
        assert!(decode_f32_le(&[1, 2, 3]).is_err());
    }

    #[tokio::test]
    async fn sqlite_vector_store_upsert_list_remove_and_model_isolation() {
        let vectors = SqliteVectorStore::open_in_memory().unwrap();
        vectors.upsert("m1", "model-a", &[0.6, 0.8]).await.unwrap();
        vectors.upsert("m2", "model-b", &[1.0, 0.0]).await.unwrap();

        let list_a = vectors.list_for_model("model-a").await.unwrap();
        assert_eq!(list_a.len(), 1);
        assert_eq!(list_a[0].0, "m1");
        assert!((list_a[0].1[0] - 0.6).abs() < 1e-6);

        // Overwrite existing entry
        vectors.upsert("m1", "model-a", &[1.0, 0.0]).await.unwrap();
        let list_a = vectors.list_for_model("model-a").await.unwrap();
        assert_eq!(list_a[0].1, vec![1.0, 0.0]);

        vectors.remove("m1").await.unwrap();
        assert!(vectors.list_for_model("model-a").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn store_search_index_delegates_to_mail_store() {
        let store = Arc::new(MemoryStore::new("agent@example.com"));
        let msg = store
            .insert_message(sample_input(
                "m_store_1",
                "Quarterly Invoice",
                "Please review Q4 numbers",
                vec!["INBOX", "UNREAD"],
                1_700_000_000_000,
            ))
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

    #[tokio::test]
    async fn hybrid_index_fails_open_on_index_and_falls_back_to_lexical_on_search() {
        let store = Arc::new(MemoryStore::new("agent@example.com"));
        let msg = store
            .insert_message(sample_input(
                "m_fail_1",
                "Quarterly Invoice",
                "Please review Q4 numbers",
                vec!["INBOX", "UNREAD"],
                1_700_000_000_000,
            ))
            .await
            .unwrap();

        let fail_flag = Arc::new(AtomicBool::new(true));
        let provider = Arc::new(ToggleEmbeddingProvider {
            fail: fail_flag.clone(),
        });
        let vectors = Arc::new(MemoryVectorStore::new());
        let index = HybridSearchIndex::new(store.clone(), provider, vectors.clone());
        assert_eq!(index.backend_name(), "hybrid");

        // index() fails open when embedding API is down
        index.index(&msg).await.unwrap();
        assert!(
            vectors
                .list_for_model("mock-embed-v1")
                .await
                .unwrap()
                .is_empty()
        );

        // search() falls back cleanly to lexical search when embedding API is down
        let page = index
            .search(&AiSearchQuery {
                q: Some("Invoice".into()),
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page.messages.len(), 1);
        assert_eq!(page.messages[0].id, "m_fail_1");

        // reindex_mailbox reports failures accurately while provider is down
        let failed_report = reindex_mailbox(store.as_ref(), &index).await.unwrap();
        assert_eq!(failed_report.indexed, 0);
        assert_eq!(failed_report.failed, 1);

        // Once provider recovers, reindex populates embeddings and semantic queries match
        fail_flag.store(false, Ordering::SeqCst);
        let ok_report = reindex_mailbox(store.as_ref(), &index).await.unwrap();
        assert_eq!(ok_report.indexed, 1);
        assert_eq!(ok_report.failed, 0);

        let semantic_page = index
            .search(&AiSearchQuery {
                q: Some("receipt".into()),
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(semantic_page.messages.len(), 1);
        assert_eq!(semantic_page.messages[0].id, "m_fail_1");
    }

    #[tokio::test]
    async fn hybrid_search_supports_cursor_pagination_and_structured_filters() {
        let store = Arc::new(MemoryStore::new("agent@example.com"));
        let m1 = store
            .insert_message(sample_input(
                "m1",
                "Server outage in us-east",
                "Primary cluster went offline",
                vec!["INBOX", "UNREAD"],
                1_700_000_001_000,
            ))
            .await
            .unwrap();
        let m2 = store
            .insert_message(sample_input(
                "m2",
                "Database outage report",
                "Replica lag spike",
                vec!["INBOX", "UNREAD"],
                1_700_000_002_000,
            ))
            .await
            .unwrap();
        let m3 = store
            .insert_message(sample_input(
                "m3",
                "Resolved outage postmortem",
                "Everything is green now",
                vec!["INBOX"], // read (no UNREAD)
                1_700_000_003_000,
            ))
            .await
            .unwrap();

        let provider = Arc::new(ToggleEmbeddingProvider {
            fail: Arc::new(AtomicBool::new(false)),
        });
        let vectors = Arc::new(MemoryVectorStore::new());
        let index = HybridSearchIndex::new(store, provider, vectors);

        for m in [&m1, &m2, &m3] {
            index.index(m).await.unwrap();
        }

        // Semantic query "downtime" (zero lexical overlap) + unread=Some(true) + limit=1 cursor pagination
        let page1 = index
            .search(&AiSearchQuery {
                q: Some("downtime".into()),
                unread: Some(true),
                limit: 1,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page1.messages.len(), 1);
        assert!(page1.has_more);
        assert!(page1.next_cursor.is_some());

        let page2 = index
            .search(&AiSearchQuery {
                q: Some("downtime".into()),
                unread: Some(true),
                limit: 1,
                cursor: page1.next_cursor.clone(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page2.messages.len(), 1);
        assert!(!page2.has_more);
        assert!(page2.next_cursor.is_none());

        let mut seen_ids = vec![page1.messages[0].id.clone(), page2.messages[0].id.clone()];
        seen_ids.sort();
        assert_eq!(seen_ids, vec!["m1", "m2"]);
    }
}
