//! Hybrid keyword + vector [`SearchIndex`] using Reciprocal Rank Fusion (RRF).
//!
//! Combines lexical retrieval from [`StoreSearchIndex`] (SQLite FTS5 / Memory token search)
//! with cosine similarity over normalized embeddings stored in [`VectorStore`], while
//! enforcing all structured [`AiSearchQuery`] filters and cursor pagination.

use std::{cmp::Ordering, collections::HashMap, sync::Arc};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::{
    ai::safety::sanitize_untrusted_text,
    error::{AppError, AppResult},
    mime::strip_quoted_text,
    models::{LABEL_SPAM, LABEL_TRASH, LABEL_UNREAD},
    search_index::{
        SearchIndex, StoreSearchIndex, embedding::EmbeddingProvider, vector_store::VectorStore,
    },
    storage::{AiMessagePage, AiSearchQuery, MailStore, StoredMessage},
};

/// Default Reciprocal Rank Fusion smoothing constant (`k = 60.0`).
pub const DEFAULT_RRF_K: f64 = 60.0;

/// Minimum cosine similarity required for a stored vector to count as a semantic hit.
/// Excludes orthogonal (`0.0`) and negatively aligned vectors while keeping all positively aligned matches.
pub const DEFAULT_MIN_VECTOR_SIMILARITY: f32 = 1e-6;

/// Maximum characters combined from `subject` + cleaned `text_body` before embedding.
const MAX_EMBED_CHARS: usize = 8_000;

const RRF_CURSOR_PREFIX: &str = "rrf:";
const SCORE_TIE_EPSILON: f64 = 1e-12;

/// L2-normalize an embedding vector. Returns a zero vector if the norm is zero or non-finite.
pub fn normalize_l2(vector: &[f32]) -> Vec<f32> {
    let norm_sq: f64 = vector
        .iter()
        .map(|&x| {
            let xd = f64::from(x);
            xd * xd
        })
        .sum();
    let norm = norm_sq.sqrt();
    if !norm.is_finite() || norm <= 0.0 {
        return vec![0.0; vector.len()];
    }
    vector
        .iter()
        .map(|&x| (f64::from(x) / norm) as f32)
        .collect()
}

/// Compute cosine similarity between two float vectors in `[-1.0, 1.0]`.
///
/// Returns `0.0` if vectors are empty, have mismatched dimensions, or either has zero norm.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.is_empty() || a.len() != b.len() {
        return 0.0;
    }
    let mut dot = 0.0_f64;
    let mut norm_a = 0.0_f64;
    let mut norm_b = 0.0_f64;
    for (&x, &y) in a.iter().zip(b.iter()) {
        let xd = f64::from(x);
        let yd = f64::from(y);
        dot += xd * yd;
        norm_a += xd * xd;
        norm_b += yd * yd;
    }
    let denom = norm_a.sqrt() * norm_b.sqrt();
    if !denom.is_finite() || denom <= 0.0 {
        return 0.0;
    }
    (dot / denom).clamp(-1.0, 1.0) as f32
}

/// Combine ranked lexical and vector message ID lists using Reciprocal Rank Fusion (RRF):
///
/// `score(d) = sum(1.0 / (k + rank_i(d)))` where `rank_i` is 1-based.
///
/// Returns `(message_id, score)` sorted descending by score (tie-broken by `message_id`).
pub fn rrf_fuse(lexical_ids: &[String], vector_ids: &[String], k: f64) -> Vec<(String, f64)> {
    let mut scores: HashMap<String, f64> =
        HashMap::with_capacity(lexical_ids.len() + vector_ids.len());

    for (idx, id) in lexical_ids.iter().enumerate() {
        let rank = (idx + 1) as f64;
        *scores.entry(id.clone()).or_insert(0.0) += 1.0 / (k + rank);
    }

    for (idx, id) in vector_ids.iter().enumerate() {
        let rank = (idx + 1) as f64;
        *scores.entry(id.clone()).or_insert(0.0) += 1.0 / (k + rank);
    }

    let mut ranked: Vec<(String, f64)> = scores.into_iter().collect();
    ranked.sort_by(|(id_a, score_a), (id_b, score_b)| {
        if (score_a - score_b).abs() <= SCORE_TIE_EPSILON {
            id_a.cmp(id_b)
        } else {
            score_b.total_cmp(score_a)
        }
    });
    ranked
}

/// Build the cleaned text (`subject` + quote-stripped, sanitized `text_body`) embedded for a message.
pub fn prepare_message_embedding_text(msg: &StoredMessage) -> String {
    let subject = sanitize_untrusted_text(&msg.subject).trim().to_string();

    let stripped = strip_quoted_text(&msg.text_body);
    let body_source = if stripped.trim().is_empty() {
        msg.text_body.as_str()
    } else {
        stripped.as_str()
    };
    let body = sanitize_untrusted_text(body_source).trim().to_string();

    let combined = match (subject.is_empty(), body.is_empty()) {
        (false, false) => format!("{subject}\n\n{body}"),
        (false, true) => subject,
        (true, false) => body,
        (true, true) => String::new(),
    };

    if combined.chars().count() > MAX_EMBED_CHARS {
        combined.chars().take(MAX_EMBED_CHARS).collect()
    } else {
        combined
    }
}

fn encode_rrf_cursor(offset: usize) -> String {
    URL_SAFE_NO_PAD.encode(format!("{RRF_CURSOR_PREFIX}{offset}").as_bytes())
}

enum ParsedCursor {
    None,
    RrfOffset(usize),
    KeysetFallback,
}

fn parse_cursor(raw: Option<&str>) -> AppResult<ParsedCursor> {
    let Some(trimmed) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(ParsedCursor::None);
    };

    let bytes = URL_SAFE_NO_PAD
        .decode(trimmed.as_bytes())
        .map_err(|_| AppError::BadRequest("Invalid pagination cursor".to_string()))?;
    let text = String::from_utf8(bytes)
        .map_err(|_| AppError::BadRequest("Invalid pagination cursor".to_string()))?;

    if let Some(rest) = text.strip_prefix(RRF_CURSOR_PREFIX) {
        let offset = rest
            .parse::<usize>()
            .map_err(|_| AppError::BadRequest("Invalid pagination cursor".to_string()))?;
        return Ok(ParsedCursor::RrfOffset(offset));
    }

    // Also allow keyset cursors (`<timestamp_ms>:<id>`) emitted if a prior page fell back to lexical search.
    if let Some((ts_str, id)) = text.split_once(':')
        && ts_str.parse::<i64>().is_ok()
        && !id.is_empty()
    {
        return Ok(ParsedCursor::KeysetFallback);
    }

    Err(AppError::BadRequest(
        "Invalid pagination cursor".to_string(),
    ))
}

fn matches_structured_filters(
    msg: &StoredMessage,
    query: &AiSearchQuery,
    resolved_labels: &[String],
) -> bool {
    let explicit_spam_trash = resolved_labels
        .iter()
        .any(|l| l == LABEL_TRASH || l == LABEL_SPAM);
    let effective_include_spam_trash = query.include_spam_trash || explicit_spam_trash;

    if !effective_include_spam_trash
        && msg
            .label_ids
            .iter()
            .any(|l| l == LABEL_TRASH || l == LABEL_SPAM)
    {
        return false;
    }

    if !resolved_labels
        .iter()
        .all(|req| msg.label_ids.iter().any(|l| l == req))
    {
        return false;
    }

    if let Some(want_unread) = query.unread {
        let is_unread = msg.label_ids.iter().any(|l| l == LABEL_UNREAD);
        if is_unread != want_unread {
            return false;
        }
    }

    if let Some(ref tid) = query.thread_id
        && !tid.trim().is_empty()
        && msg.thread_id != tid.trim()
    {
        return false;
    }

    if let Some(from_filter) = query
        .from
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        && !msg
            .from_addr
            .to_ascii_lowercase()
            .contains(&from_filter.to_ascii_lowercase())
    {
        return false;
    }

    if let Some(to_filter) = query.to.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let needle = to_filter.to_ascii_lowercase();
        if !msg
            .to_addrs
            .iter()
            .any(|addr| addr.to_ascii_lowercase().contains(&needle))
        {
            return false;
        }
    }

    if let Some(after) = query.after
        && msg.internal_date_ms < after.timestamp_millis()
    {
        return false;
    }

    if let Some(before) = query.before
        && msg.internal_date_ms > before.timestamp_millis()
    {
        return false;
    }

    if let Some(has_att) = query.has_attachment
        && msg.has_attachments != has_att
    {
        return false;
    }

    true
}

/// Hybrid lexical + vector [`SearchIndex`] combining [`StoreSearchIndex`] with cosine similarity
/// over stored message embeddings via Reciprocal Rank Fusion (RRF).
#[derive(Clone)]
pub struct HybridSearchIndex {
    store: Arc<dyn MailStore>,
    lexical: StoreSearchIndex,
    provider: Arc<dyn EmbeddingProvider>,
    vectors: Arc<dyn VectorStore>,
    rrf_k: f64,
    min_vector_similarity: f32,
}

impl HybridSearchIndex {
    pub fn new(
        store: Arc<dyn MailStore>,
        provider: Arc<dyn EmbeddingProvider>,
        vectors: Arc<dyn VectorStore>,
    ) -> Self {
        let lexical = StoreSearchIndex::new(store.clone());
        Self {
            store,
            lexical,
            provider,
            vectors,
            rrf_k: DEFAULT_RRF_K,
            min_vector_similarity: DEFAULT_MIN_VECTOR_SIMILARITY,
        }
    }

    /// Override the RRF smoothing constant `k` (defaults to `60.0`).
    pub fn with_rrf_k(mut self, k: f64) -> Self {
        self.rrf_k = k.max(1.0);
        self
    }

    /// Override the minimum cosine similarity threshold for vector hits.
    pub fn with_min_vector_similarity(mut self, min_similarity: f32) -> Self {
        self.min_vector_similarity = min_similarity;
        self
    }

    /// Compute and persist a normalized embedding for `msg`, propagating any embedding or storage error.
    pub async fn index_strict(&self, msg: &StoredMessage) -> AppResult<()> {
        let text = prepare_message_embedding_text(msg);
        if text.is_empty() {
            self.vectors.remove(&msg.id).await?;
            return Ok(());
        }

        let mut embeddings = self.provider.embed(&[text]).await?;
        let raw_vec = embeddings.pop().ok_or_else(|| AppError::Upstream {
            status: 502,
            message: "Embedding provider returned no vector for message".to_string(),
        })?;
        let normalized = normalize_l2(&raw_vec);
        if normalized.iter().all(|&v| v == 0.0) {
            self.vectors.remove(&msg.id).await?;
            return Ok(());
        }

        self.vectors
            .upsert(&msg.id, self.provider.model_name(), &normalized)
            .await?;
        Ok(())
    }

    async fn resolve_labels(&self, labels: &[String]) -> AppResult<Vec<String>> {
        if labels.is_empty() {
            return Ok(Vec::new());
        }
        let all_labels = self.store.list_labels().await?;
        let resolved = labels
            .iter()
            .map(|wanted| {
                all_labels
                    .iter()
                    .find(|l| {
                        l.id.eq_ignore_ascii_case(wanted) || l.name.eq_ignore_ascii_case(wanted)
                    })
                    .map(|l| l.id.clone())
                    .unwrap_or_else(|| wanted.clone())
            })
            .collect();
        Ok(resolved)
    }

    async fn fetch_lexical_candidates(
        &self,
        query: &AiSearchQuery,
        max_candidates: usize,
    ) -> AppResult<Vec<StoredMessage>> {
        let mut results = Vec::new();
        let mut cursor: Option<String> = None;

        while results.len() < max_candidates {
            let batch_limit = (max_candidates - results.len()).min(100);
            let page = self
                .lexical
                .search(&AiSearchQuery {
                    q: query.q.clone(),
                    labels: query.labels.clone(),
                    unread: query.unread,
                    thread_id: query.thread_id.clone(),
                    from: query.from.clone(),
                    to: query.to.clone(),
                    after: query.after,
                    before: query.before,
                    has_attachment: query.has_attachment,
                    include_spam_trash: query.include_spam_trash,
                    limit: batch_limit,
                    cursor: cursor.clone(),
                })
                .await?;

            results.extend(page.messages);
            match page.next_cursor {
                Some(next) if page.has_more => cursor = Some(next),
                _ => break,
            }
        }

        Ok(results)
    }
}

#[async_trait]
impl SearchIndex for HybridSearchIndex {
    async fn index(&self, msg: &StoredMessage) -> AppResult<()> {
        if let Err(err) = self.index_strict(msg).await {
            tracing::warn!(
                message_id = %msg.id,
                model = %self.provider.model_name(),
                error = %err,
                "HybridSearchIndex failed to embed message; failing open so ingestion continues"
            );
        }
        Ok(())
    }

    async fn reindex_message(&self, msg: &StoredMessage) -> AppResult<()> {
        self.index_strict(msg).await
    }

    async fn remove(&self, message_id: &str) -> AppResult<()> {
        self.vectors.remove(message_id).await?;
        self.lexical.remove(message_id).await
    }

    async fn search(&self, query: &AiSearchQuery) -> AppResult<AiMessagePage> {
        let Some(raw_q) = query.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
            return self.lexical.search(query).await;
        };

        let limit = if query.limit == 0 {
            20
        } else {
            query.limit.min(100)
        };

        let (offset, is_rrf_cursor) = match parse_cursor(query.cursor.as_deref())? {
            ParsedCursor::None => (0, false),
            ParsedCursor::RrfOffset(off) => (off, true),
            ParsedCursor::KeysetFallback => return self.lexical.search(query).await,
        };

        let candidate_k = (offset + limit).max(20).saturating_mul(4).clamp(100, 1000);

        let query_vec = match self.provider.embed(&[raw_q.to_string()]).await {
            Ok(mut vecs) => match vecs.pop() {
                Some(v) => {
                    let normalized = normalize_l2(&v);
                    if normalized.iter().all(|&x| x == 0.0) {
                        None
                    } else {
                        Some(normalized)
                    }
                }
                None => None,
            },
            Err(err) => {
                tracing::warn!(
                    model = %self.provider.model_name(),
                    error = %err,
                    "HybridSearchIndex query embedding failed; falling back to lexical search"
                );
                None
            }
        };

        let Some(query_vec) = query_vec else {
            if is_rrf_cursor {
                let lexical_msgs = self
                    .fetch_lexical_candidates(query, offset + limit + 1)
                    .await?;
                let mut sliced: Vec<StoredMessage> = lexical_msgs
                    .into_iter()
                    .skip(offset)
                    .take(limit + 1)
                    .collect();
                let has_more = sliced.len() > limit;
                if has_more {
                    sliced.truncate(limit);
                }
                let next_cursor = has_more.then(|| encode_rrf_cursor(offset + limit));
                return Ok(AiMessagePage {
                    messages: sliced,
                    next_cursor,
                    has_more,
                });
            }
            return self.lexical.search(query).await;
        };

        // 1. Lexical retrieval (respects all structured filters).
        let lexical_msgs = self.fetch_lexical_candidates(query, candidate_k).await?;
        let lexical_ids: Vec<String> = lexical_msgs.iter().map(|m| m.id.clone()).collect();
        let mut msg_cache: HashMap<String, StoredMessage> = lexical_msgs
            .into_iter()
            .map(|m| (m.id.clone(), m))
            .collect();

        // 2. Vector retrieval with cosine similarity + structured filters.
        let stored_vectors = self
            .vectors
            .list_for_model(self.provider.model_name())
            .await?;

        let mut scored: Vec<(String, f32)> = stored_vectors
            .into_iter()
            .filter_map(|(id, vec)| {
                let sim = cosine_similarity(&query_vec, &vec);
                (sim > self.min_vector_similarity).then_some((id, sim))
            })
            .collect();

        scored.sort_by(|(id_a, sim_a), (id_b, sim_b)| {
            sim_b.total_cmp(sim_a).then_with(|| id_b.cmp(id_a))
        });

        let resolved_labels = self.resolve_labels(&query.labels).await?;
        let mut vector_ids = Vec::new();
        for (msg_id, _sim) in scored {
            if vector_ids.len() >= candidate_k {
                break;
            }
            let msg = if let Some(existing) = msg_cache.get(&msg_id) {
                existing.clone()
            } else {
                let Some(loaded) = self.store.get_message(&msg_id).await? else {
                    continue;
                };
                if !matches_structured_filters(&loaded, query, &resolved_labels) {
                    continue;
                }
                msg_cache.insert(msg_id.clone(), loaded.clone());
                loaded
            };
            if matches_structured_filters(&msg, query, &resolved_labels) {
                vector_ids.push(msg_id);
            }
        }

        // 3. Fuse lexical and vector rankings via Reciprocal Rank Fusion (RRF).
        let mut fused: Vec<(StoredMessage, f64)> = rrf_fuse(&lexical_ids, &vector_ids, self.rrf_k)
            .into_iter()
            .filter_map(|(id, score)| msg_cache.remove(&id).map(|msg| (msg, score)))
            .collect();

        fused.sort_by(|(msg_a, score_a), (msg_b, score_b)| {
            if (score_a - score_b).abs() <= SCORE_TIE_EPSILON {
                msg_b
                    .internal_date_ms
                    .cmp(&msg_a.internal_date_ms)
                    .then_with(|| msg_b.id.cmp(&msg_a.id))
            } else {
                match score_b.total_cmp(score_a) {
                    Ordering::Equal => msg_b
                        .internal_date_ms
                        .cmp(&msg_a.internal_date_ms)
                        .then_with(|| msg_b.id.cmp(&msg_a.id)),
                    other => other,
                }
            }
        });

        let mut page_msgs: Vec<StoredMessage> = fused
            .into_iter()
            .skip(offset)
            .take(limit + 1)
            .map(|(msg, _)| msg)
            .collect();

        let has_more = page_msgs.len() > limit;
        if has_more {
            page_msgs.truncate(limit);
        }
        let next_cursor = has_more.then(|| encode_rrf_cursor(offset + limit));

        Ok(AiMessagePage {
            messages: page_msgs,
            next_cursor,
            has_more,
        })
    }

    fn backend_name(&self) -> &'static str {
        "hybrid"
    }
}
