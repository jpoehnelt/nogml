//! OpenAI-compatible embedding provider interface and HTTP implementation.
//!
//! Works with OpenAI (`/v1/embeddings`), Ollama (`/v1/embeddings`), Voyage, Mistral,
//! and any provider accepting `POST {base_url}/embeddings` with `{ "model", "input" }`.

use std::{fmt, time::Duration};

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

use crate::{
    config::Config,
    error::{AppError, AppResult},
};

const DEFAULT_OPENAI_EMBEDDING_BASE_URL: &str = "https://api.openai.com/v1";
const DEFAULT_EMBEDDING_MODEL: &str = "text-embedding-3-small";

/// Pluggable async text embedding provider for semantic / hybrid search.
#[async_trait]
pub trait EmbeddingProvider: Send + Sync {
    /// Embed one or more input texts in order, returning one float vector per input.
    async fn embed(&self, texts: &[String]) -> AppResult<Vec<Vec<f32>>>;

    /// Stable model identifier stored alongside vectors so model changes never mix dimensions.
    fn model_name(&self) -> &str;
}

/// Configuration for [`OpenAiEmbeddingProvider`].
#[derive(Clone)]
pub struct OpenAiEmbeddingConfig {
    pub base_url: String,
    pub api_key: Option<String>,
    pub model: String,
    pub timeout: Duration,
}

impl fmt::Debug for OpenAiEmbeddingConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenAiEmbeddingConfig")
            .field("base_url", &self.base_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("model", &self.model)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl OpenAiEmbeddingConfig {
    pub fn new(base_url: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            api_key: None,
            model: model.into(),
            timeout: Duration::from_secs(15),
        }
    }

    /// Build and validate embedding provider configuration from runtime [`Config`].
    pub fn from_config(config: &Config) -> AppResult<Self> {
        let base_url_opt = config
            .embedding_base_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let api_key = config
            .embedding_api_key
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        if base_url_opt.is_none() && api_key.is_none() {
            return Err(AppError::Config(
                "NOGML_EMBEDDING_BASE_URL (--embedding-base-url) or NOGML_EMBEDDING_API_KEY (--embedding-api-key) is required when search_backend=hybrid"
                    .to_string(),
            ));
        }

        let base_url = base_url_opt
            .unwrap_or(DEFAULT_OPENAI_EMBEDDING_BASE_URL)
            .to_string();

        let model = {
            let trimmed = config.embedding_model.trim();
            if trimmed.is_empty() {
                DEFAULT_EMBEDDING_MODEL.to_string()
            } else {
                trimmed.to_string()
            }
        };

        Ok(Self {
            base_url,
            api_key,
            model,
            timeout: Duration::from_secs(config.embedding_timeout_secs.max(1)),
        })
    }
}

#[derive(Debug, Deserialize)]
struct EmbeddingsResponse {
    #[serde(default)]
    data: Vec<EmbeddingItem>,
}

#[derive(Debug, Deserialize)]
struct EmbeddingItem {
    #[serde(default)]
    index: usize,
    embedding: Vec<f32>,
}

/// OpenAI-compatible HTTP [`EmbeddingProvider`] calling `POST {base_url}/embeddings`.
#[derive(Clone)]
pub struct OpenAiEmbeddingProvider {
    config: OpenAiEmbeddingConfig,
    client: reqwest::Client,
}

impl OpenAiEmbeddingProvider {
    pub fn new(config: OpenAiEmbeddingConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { config, client }
    }

    pub fn from_config(config: &Config) -> AppResult<Self> {
        Ok(Self::new(OpenAiEmbeddingConfig::from_config(config)?))
    }

    fn endpoint(&self) -> String {
        format!("{}/embeddings", self.config.base_url.trim_end_matches('/'))
    }
}

#[async_trait]
impl EmbeddingProvider for OpenAiEmbeddingProvider {
    async fn embed(&self, texts: &[String]) -> AppResult<Vec<Vec<f32>>> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        let payload = json!({
            "model": self.config.model,
            "input": texts,
        });

        let mut req = self.client.post(self.endpoint()).json(&payload);
        if let Some(key) = self.config.api_key.as_deref() {
            req = req.bearer_auth(key);
        }

        let resp = req.send().await.map_err(|err| AppError::Upstream {
            status: 502,
            message: format!("Embedding request to {} failed: {err}", self.endpoint()),
        })?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::Upstream {
                status: status.as_u16(),
                message: format!("Embedding API returned HTTP {status}: {body}"),
            });
        }

        let mut parsed: EmbeddingsResponse =
            resp.json().await.map_err(|err| AppError::Upstream {
                status: 502,
                message: format!("Failed to parse embeddings response JSON: {err}"),
            })?;

        if parsed.data.len() != texts.len() {
            return Err(AppError::Upstream {
                status: 502,
                message: format!(
                    "Embedding API returned {} vector(s) for {} input(s)",
                    parsed.data.len(),
                    texts.len()
                ),
            });
        }

        parsed.data.sort_by_key(|item| item.index);

        let mut vectors = Vec::with_capacity(parsed.data.len());
        for item in parsed.data {
            if item.embedding.is_empty() {
                return Err(AppError::Upstream {
                    status: 502,
                    message: "Embedding API returned an empty vector".to_string(),
                });
            }
            if item.embedding.iter().any(|v| !v.is_finite()) {
                return Err(AppError::Upstream {
                    status: 502,
                    message: "Embedding API returned non-finite vector values".to_string(),
                });
            }
            vectors.push(item.embedding);
        }

        Ok(vectors)
    }

    fn model_name(&self) -> &str {
        &self.config.model
    }
}
