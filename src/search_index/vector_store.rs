//! Pure-Rust persistence for message embedding vectors (`MemoryVectorStore` and `SqliteVectorStore`).
//!
//! Vectors are encoded as compact little-endian `f32` BLOBs inside a dedicated
//! `message_embeddings` SQLite table (or an in-memory map for `MemoryStore`),
//! avoiding any native C/C++ extension build requirements.

use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use chrono::Utc;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{Connection, params};

use crate::error::{AppError, AppResult};

const VECTOR_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS message_embeddings (
    message_id TEXT PRIMARY KEY,
    model TEXT NOT NULL,
    dims INTEGER NOT NULL,
    vector BLOB NOT NULL,
    updated_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_message_embeddings_model ON message_embeddings (model);
"#;

/// Encode a slice of `f32` values into a little-endian byte buffer.
pub fn encode_f32_le(vector: &[f32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(vector.len() * 4);
    for &v in vector {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    bytes
}

/// Decode a little-endian byte buffer back into `Vec<f32>`.
pub fn decode_f32_le(bytes: &[u8]) -> AppResult<Vec<f32>> {
    if !bytes.len().is_multiple_of(4) {
        return Err(AppError::Storage(format!(
            "Invalid f32 vector BLOB length: {} bytes (not a multiple of 4)",
            bytes.len()
        )));
    }
    let mut out = Vec::with_capacity(bytes.len() / 4);
    let (chunks, _) = bytes.as_chunks::<4>();
    for &arr in chunks {
        out.push(f32::from_le_bytes(arr));
    }
    Ok(out)
}

/// Pluggable storage for message embedding vectors.
#[async_trait]
pub trait VectorStore: Send + Sync {
    /// Insert or replace the normalized embedding vector for `message_id`.
    async fn upsert(&self, message_id: &str, model: &str, vector: &[f32]) -> AppResult<()>;

    /// Delete any stored embedding for `message_id`.
    async fn remove(&self, message_id: &str) -> AppResult<()>;

    /// Load all `(message_id, vector)` entries stored for `model`.
    async fn list_for_model(&self, model: &str) -> AppResult<Vec<(String, Vec<f32>)>>;
}

type MemoryVectorMap = HashMap<String, (String, Vec<f32>)>;

/// In-memory [`VectorStore`] paired with `MemoryStore` or unit tests.
#[derive(Debug, Clone, Default)]
pub struct MemoryVectorStore {
    entries: Arc<RwLock<MemoryVectorMap>>,
}

impl MemoryVectorStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl VectorStore for MemoryVectorStore {
    async fn upsert(&self, message_id: &str, model: &str, vector: &[f32]) -> AppResult<()> {
        let mut map = self
            .entries
            .write()
            .map_err(|_| AppError::Storage("MemoryVectorStore lock poisoned".to_string()))?;
        map.insert(message_id.to_string(), (model.to_string(), vector.to_vec()));
        Ok(())
    }

    async fn remove(&self, message_id: &str) -> AppResult<()> {
        let mut map = self
            .entries
            .write()
            .map_err(|_| AppError::Storage("MemoryVectorStore lock poisoned".to_string()))?;
        map.remove(message_id);
        Ok(())
    }

    async fn list_for_model(&self, model: &str) -> AppResult<Vec<(String, Vec<f32>)>> {
        let map = self
            .entries
            .read()
            .map_err(|_| AppError::Storage("MemoryVectorStore lock poisoned".to_string()))?;
        let out = map
            .iter()
            .filter(|(_, (m, _))| m == model)
            .map(|(id, (_, vec))| (id.clone(), vec.clone()))
            .collect();
        Ok(out)
    }
}

/// SQLite-backed [`VectorStore`] persisting little-endian `f32` BLOBs in `message_embeddings`.
#[derive(Clone)]
pub struct SqliteVectorStore {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteVectorStore {
    /// Open or create the `message_embeddings` table inside the SQLite database at `path`.
    pub fn open(path: &Path) -> AppResult<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .map_err(|e| AppError::Storage(format!("Failed to create DB directory: {e}")))?;
        }

        let manager = SqliteConnectionManager::file(path).with_init(|conn| {
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = NORMAL;
                 PRAGMA busy_timeout = 5000;",
            )
        });
        let pool = Pool::builder()
            .max_size(8)
            .build(manager)
            .map_err(|e| AppError::Storage(format!("Failed to build SQLite vector pool: {e}")))?;

        let store = Self { pool };
        store.initialize()?;
        Ok(store)
    }

    /// Open an in-memory SQLite vector store (for unit tests).
    pub fn open_in_memory() -> AppResult<Self> {
        let manager = SqliteConnectionManager::memory().with_init(|conn| {
            conn.execute_batch(
                "PRAGMA synchronous = NORMAL;
                 PRAGMA busy_timeout = 5000;",
            )
        });
        let pool = Pool::builder().max_size(1).build(manager).map_err(|e| {
            AppError::Storage(format!("Failed to build in-memory vector pool: {e}"))
        })?;

        let store = Self { pool };
        store.initialize()?;
        Ok(store)
    }

    fn initialize(&self) -> AppResult<()> {
        let conn = self
            .pool
            .get()
            .map_err(|e| AppError::Storage(format!("SQLite vector pool error: {e}")))?;
        conn.execute_batch(VECTOR_SCHEMA_SQL)
            .map_err(|e| AppError::Storage(format!("Failed to initialize vector schema: {e}")))?;
        Ok(())
    }

    async fn run_blocking<F, T>(&self, f: F) -> AppResult<T>
    where
        F: FnOnce(&Connection) -> AppResult<T> + Send + 'static,
        T: Send + 'static,
    {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| AppError::Storage(format!("SQLite vector pool error: {e}")))?;
            f(&conn)
        })
        .await
        .map_err(|e| AppError::Internal(format!("SQLite vector task join error: {e}")))?
    }
}

#[async_trait]
impl VectorStore for SqliteVectorStore {
    async fn upsert(&self, message_id: &str, model: &str, vector: &[f32]) -> AppResult<()> {
        let message_id = message_id.to_string();
        let model = model.to_string();
        let dims = i64::try_from(vector.len())
            .map_err(|_| AppError::Storage("Embedding vector exceeds i64 dims".to_string()))?;
        let blob = encode_f32_le(vector);
        let updated_at_ms = Utc::now().timestamp_millis();

        self.run_blocking(move |conn| {
            conn.execute(
                "INSERT INTO message_embeddings (message_id, model, dims, vector, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(message_id) DO UPDATE SET
                    model = excluded.model,
                    dims = excluded.dims,
                    vector = excluded.vector,
                    updated_at_ms = excluded.updated_at_ms",
                params![message_id, model, dims, blob, updated_at_ms],
            )
            .map_err(|e| AppError::Storage(format!("Failed to upsert message embedding: {e}")))?;
            Ok(())
        })
        .await
    }

    async fn remove(&self, message_id: &str) -> AppResult<()> {
        let message_id = message_id.to_string();
        self.run_blocking(move |conn| {
            conn.execute(
                "DELETE FROM message_embeddings WHERE message_id = ?1",
                params![message_id],
            )
            .map_err(|e| AppError::Storage(format!("Failed to delete message embedding: {e}")))?;
            Ok(())
        })
        .await
    }

    async fn list_for_model(&self, model: &str) -> AppResult<Vec<(String, Vec<f32>)>> {
        let model = model.to_string();
        self.run_blocking(move |conn| {
            let mut stmt = conn
                .prepare("SELECT message_id, dims, vector FROM message_embeddings WHERE model = ?1")
                .map_err(|e| {
                    AppError::Storage(format!("Failed to prepare vector list query: {e}"))
                })?;

            let rows = stmt
                .query_map(params![model], |row| {
                    let message_id: String = row.get(0)?;
                    let dims: i64 = row.get(1)?;
                    let blob: Vec<u8> = row.get(2)?;
                    Ok((message_id, dims, blob))
                })
                .map_err(|e| {
                    AppError::Storage(format!("Failed to query message embeddings: {e}"))
                })?;

            let mut out = Vec::new();
            for row in rows {
                let (message_id, dims, blob) = row
                    .map_err(|e| AppError::Storage(format!("Failed to read embedding row: {e}")))?;
                match decode_f32_le(&blob) {
                    Ok(vec) if vec.len() as i64 == dims => out.push((message_id, vec)),
                    Ok(vec) => {
                        tracing::warn!(
                            message_id = %message_id,
                            expected_dims = dims,
                            actual_dims = vec.len(),
                            "Skipping message embedding with mismatched dimensions"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            message_id = %message_id,
                            error = %err,
                            "Skipping corrupted message embedding BLOB"
                        );
                    }
                }
            }
            Ok(out)
        })
        .await
    }
}
