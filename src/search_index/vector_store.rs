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
    mailbox_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    model TEXT NOT NULL,
    dims INTEGER NOT NULL,
    vector BLOB NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (mailbox_id, message_id)
);
CREATE INDEX IF NOT EXISTS idx_message_embeddings_mailbox_model
    ON message_embeddings (mailbox_id, model);
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

/// Pluggable storage for message embedding vectors, partitioned by `mailbox_id`.
#[async_trait]
pub trait VectorStore: Send + Sync {
    /// Return a lightweight `VectorStore` handle scoped strictly to `mailbox_id`.
    fn for_mailbox(&self, mailbox_id: &str) -> Arc<dyn VectorStore>;

    /// Insert or replace the normalized embedding vector for `message_id`.
    async fn upsert(&self, message_id: &str, model: &str, vector: &[f32]) -> AppResult<()>;

    /// Delete any stored embedding for `message_id`.
    async fn remove(&self, message_id: &str) -> AppResult<()>;

    /// Load all `(message_id, vector)` entries stored for `model`.
    async fn list_for_model(&self, model: &str) -> AppResult<Vec<(String, Vec<f32>)>>;
}

type MemoryVectorMap = HashMap<(String, String), (String, Vec<f32>)>;

/// In-memory [`VectorStore`] paired with `MemoryStore` or unit tests.
#[derive(Debug, Clone, Default)]
pub struct MemoryVectorStore {
    mailbox_id: String,
    entries: Arc<RwLock<MemoryVectorMap>>,
}

impl MemoryVectorStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn for_mailbox_new(mailbox_id: &str) -> Self {
        Self {
            mailbox_id: crate::config::normalize_mailbox_id(mailbox_id),
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl VectorStore for MemoryVectorStore {
    fn for_mailbox(&self, mailbox_id: &str) -> Arc<dyn VectorStore> {
        Arc::new(Self {
            mailbox_id: crate::config::normalize_mailbox_id(mailbox_id),
            entries: self.entries.clone(),
        })
    }

    async fn upsert(&self, message_id: &str, model: &str, vector: &[f32]) -> AppResult<()> {
        let mut map = self
            .entries
            .write()
            .map_err(|_| AppError::Storage("MemoryVectorStore lock poisoned".to_string()))?;
        map.insert(
            (self.mailbox_id.clone(), message_id.to_string()),
            (model.to_string(), vector.to_vec()),
        );
        Ok(())
    }

    async fn remove(&self, message_id: &str) -> AppResult<()> {
        let mut map = self
            .entries
            .write()
            .map_err(|_| AppError::Storage("MemoryVectorStore lock poisoned".to_string()))?;
        map.remove(&(self.mailbox_id.clone(), message_id.to_string()));
        Ok(())
    }

    async fn list_for_model(&self, model: &str) -> AppResult<Vec<(String, Vec<f32>)>> {
        let map = self
            .entries
            .read()
            .map_err(|_| AppError::Storage("MemoryVectorStore lock poisoned".to_string()))?;
        let out = map
            .iter()
            .filter(|((mb, _), (m, _))| mb == &self.mailbox_id && m == model)
            .map(|((_, id), (_, vec))| (id.clone(), vec.clone()))
            .collect();
        Ok(out)
    }
}

/// SQLite-backed [`VectorStore`] persisting little-endian `f32` BLOBs in `message_embeddings`.
#[derive(Clone)]
pub struct SqliteVectorStore {
    pool: Pool<SqliteConnectionManager>,
    mailbox_id: String,
}

impl SqliteVectorStore {
    /// Open or create the `message_embeddings` table inside the SQLite database at `path`.
    pub fn open(path: &Path) -> AppResult<Self> {
        Self::open_for_mailbox(path, "")
    }

    /// Open or create the `message_embeddings` table scoped to `mailbox_id`.
    pub fn open_for_mailbox(path: &Path, mailbox_id: &str) -> AppResult<Self> {
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

        let store = Self {
            pool,
            mailbox_id: crate::config::normalize_mailbox_id(mailbox_id),
        };
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

        let store = Self {
            pool,
            mailbox_id: String::new(),
        };
        store.initialize()?;
        Ok(store)
    }

    fn initialize(&self) -> AppResult<()> {
        let mut conn = self
            .pool
            .get()
            .map_err(|e| AppError::Storage(format!("SQLite vector pool error: {e}")))?;

        let table_exists: bool = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'message_embeddings'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .ok()
            .is_some();

        if table_exists {
            let mut stmt = conn
                .prepare("PRAGMA table_info(message_embeddings)")
                .map_err(|e| AppError::Storage(format!("Failed to inspect vector schema: {e}")))?;
            let has_mailbox = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(|e| AppError::Storage(format!("Failed to query vector schema: {e}")))?
                .filter_map(Result::ok)
                .any(|name| name == "mailbox_id");
            drop(stmt);

            if !has_mailbox {
                let tx = conn.transaction().map_err(|e| {
                    AppError::Storage(format!("Failed to begin vector migration: {e}"))
                })?;
                tx.execute(
                    "ALTER TABLE message_embeddings RENAME TO message_embeddings__v1_legacy",
                    [],
                )
                .map_err(|e| AppError::Storage(format!("Failed to rename legacy vectors: {e}")))?;
                tx.execute_batch(VECTOR_SCHEMA_SQL).map_err(|e| {
                    AppError::Storage(format!("Failed to create v2 vector schema: {e}"))
                })?;
                tx.execute(
                    "INSERT INTO message_embeddings (mailbox_id, message_id, model, dims, vector, updated_at_ms)
                     SELECT ?1, message_id, model, dims, vector, updated_at_ms
                     FROM message_embeddings__v1_legacy",
                    params![&self.mailbox_id],
                )
                .map_err(|e| AppError::Storage(format!("Failed to copy legacy vectors: {e}")))?;
                tx.execute("DROP TABLE message_embeddings__v1_legacy", [])
                    .map_err(|e| {
                        AppError::Storage(format!("Failed to drop legacy vector table: {e}"))
                    })?;
                tx.commit().map_err(|e| {
                    AppError::Storage(format!("Failed to commit vector migration: {e}"))
                })?;
            }
        }

        conn.execute_batch(VECTOR_SCHEMA_SQL)
            .map_err(|e| AppError::Storage(format!("Failed to initialize vector schema: {e}")))?;
        Ok(())
    }

    async fn run_blocking<F, T>(&self, f: F) -> AppResult<T>
    where
        F: FnOnce(&Connection, &str) -> AppResult<T> + Send + 'static,
        T: Send + 'static,
    {
        let pool = self.pool.clone();
        let mailbox_id = self.mailbox_id.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool
                .get()
                .map_err(|e| AppError::Storage(format!("SQLite vector pool error: {e}")))?;
            f(&conn, &mailbox_id)
        })
        .await
        .map_err(|e| AppError::Internal(format!("SQLite vector task join error: {e}")))?
    }
}

#[async_trait]
impl VectorStore for SqliteVectorStore {
    fn for_mailbox(&self, mailbox_id: &str) -> Arc<dyn VectorStore> {
        Arc::new(Self {
            pool: self.pool.clone(),
            mailbox_id: crate::config::normalize_mailbox_id(mailbox_id),
        })
    }

    async fn upsert(&self, message_id: &str, model: &str, vector: &[f32]) -> AppResult<()> {
        let message_id = message_id.to_string();
        let model = model.to_string();
        let dims = i64::try_from(vector.len())
            .map_err(|_| AppError::Storage("Embedding vector exceeds i64 dims".to_string()))?;
        let blob = encode_f32_le(vector);
        let updated_at_ms = Utc::now().timestamp_millis();

        self.run_blocking(move |conn, mb| {
            conn.execute(
                "INSERT INTO message_embeddings (mailbox_id, message_id, model, dims, vector, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(mailbox_id, message_id) DO UPDATE SET
                    model = excluded.model,
                    dims = excluded.dims,
                    vector = excluded.vector,
                    updated_at_ms = excluded.updated_at_ms",
                params![mb, message_id, model, dims, blob, updated_at_ms],
            )
            .map_err(|e| AppError::Storage(format!("Failed to upsert message embedding: {e}")))?;
            Ok(())
        })
        .await
    }

    async fn remove(&self, message_id: &str) -> AppResult<()> {
        let message_id = message_id.to_string();
        self.run_blocking(move |conn, mb| {
            conn.execute(
                "DELETE FROM message_embeddings WHERE mailbox_id = ?1 AND message_id = ?2",
                params![mb, message_id],
            )
            .map_err(|e| AppError::Storage(format!("Failed to delete message embedding: {e}")))?;
            Ok(())
        })
        .await
    }

    async fn list_for_model(&self, model: &str) -> AppResult<Vec<(String, Vec<f32>)>> {
        let model = model.to_string();
        self.run_blocking(move |conn, mb| {
            let mut stmt = conn
                .prepare(
                    "SELECT message_id, dims, vector FROM message_embeddings WHERE mailbox_id = ?1 AND model = ?2",
                )
                .map_err(|e| {
                    AppError::Storage(format!("Failed to prepare vector list query: {e}"))
                })?;

            let rows = stmt
                .query_map(params![mb, model], |row| {
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

#[cfg(feature = "postgres")]
const PG_VECTOR_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS message_embeddings (
    mailbox_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    model TEXT NOT NULL,
    dims INTEGER NOT NULL,
    vector BYTEA NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (mailbox_id, message_id)
);
CREATE INDEX IF NOT EXISTS idx_message_embeddings_mailbox_model
    ON message_embeddings (mailbox_id, model);
"#;

/// PostgreSQL-backed [`VectorStore`] persisting little-endian `f32` BYTEAs in `message_embeddings`.
#[cfg(feature = "postgres")]
#[derive(Clone)]
pub struct PostgresVectorStore {
    pool: deadpool_postgres::Pool,
    mailbox_id: String,
    schema_ready: Arc<tokio::sync::OnceCell<()>>,
}

#[cfg(feature = "postgres")]
impl PostgresVectorStore {
    /// Construct a `PostgresVectorStore` from a PostgreSQL connection URL or libpq string.
    ///
    /// Uses [`crate::storage::postgres::build_postgres_pool`], inheriting TLS (`sslmode=require`)
    /// handling automatically. The `message_embeddings` table is created idempotently on first use.
    pub fn from_url(database_url: &str, mailbox_id: &str) -> AppResult<Self> {
        let pool = crate::storage::postgres::build_postgres_pool(database_url)?;
        Ok(Self::from_pool(pool, mailbox_id))
    }

    /// Construct a `PostgresVectorStore` reusing an existing `deadpool-postgres` pool.
    pub fn from_pool(pool: deadpool_postgres::Pool, mailbox_id: &str) -> Self {
        Self {
            pool,
            mailbox_id: crate::config::normalize_mailbox_id(mailbox_id),
            schema_ready: Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    async fn ensure_ready(&self) -> AppResult<deadpool_postgres::Object> {
        self.schema_ready
            .get_or_try_init(|| async {
                let mut conn =
                    self.pool.get().await.map_err(|e| {
                        AppError::Storage(format!("Postgres vector pool error: {e}"))
                    })?;

                let exists: bool = conn
                    .query_one("SELECT to_regclass('message_embeddings') IS NOT NULL", &[])
                    .await
                    .map_err(|e| {
                        AppError::Storage(format!("Failed to check Postgres vector schema: {e}"))
                    })?
                    .get(0);
                if exists {
                    return Ok::<(), AppError>(());
                }

                let tx = conn.transaction().await.map_err(|e| {
                    AppError::Storage(format!("Failed to begin Postgres vector DDL tx: {e}"))
                })?;
                tx.execute(
                    "SELECT pg_advisory_xact_lock($1)",
                    &[&crate::storage::postgres::SCHEMA_ADVISORY_LOCK_KEY],
                )
                .await
                .map_err(|e| {
                    AppError::Storage(format!("Failed to acquire Postgres DDL advisory lock: {e}"))
                })?;

                let exists_after_lock: bool = tx
                    .query_one("SELECT to_regclass('message_embeddings') IS NOT NULL", &[])
                    .await
                    .map_err(|e| {
                        AppError::Storage(format!("Failed to re-check Postgres vector schema: {e}"))
                    })?
                    .get(0);
                if !exists_after_lock {
                    tx.batch_execute(PG_VECTOR_SCHEMA_SQL).await.map_err(|e| {
                        AppError::Storage(format!(
                            "Failed to initialize Postgres vector schema: {e}"
                        ))
                    })?;
                }
                tx.commit().await.map_err(|e| {
                    AppError::Storage(format!("Failed to commit Postgres vector DDL tx: {e}"))
                })?;
                Ok::<(), AppError>(())
            })
            .await?;

        self.pool
            .get()
            .await
            .map_err(|e| AppError::Storage(format!("Postgres vector pool error: {e}")))
    }
}

#[cfg(feature = "postgres")]
#[async_trait]
impl VectorStore for PostgresVectorStore {
    fn for_mailbox(&self, mailbox_id: &str) -> Arc<dyn VectorStore> {
        Arc::new(Self {
            pool: self.pool.clone(),
            mailbox_id: crate::config::normalize_mailbox_id(mailbox_id),
            schema_ready: self.schema_ready.clone(),
        })
    }

    async fn upsert(&self, message_id: &str, model: &str, vector: &[f32]) -> AppResult<()> {
        let dims = i32::try_from(vector.len())
            .map_err(|_| AppError::Storage("Embedding vector exceeds i32 dims".to_string()))?;
        let blob = encode_f32_le(vector);
        let updated_at_ms = Utc::now().timestamp_millis();
        let conn = self.ensure_ready().await?;
        let mb = self.mailbox_id.as_str();

        conn.execute(
            "INSERT INTO message_embeddings (mailbox_id, message_id, model, dims, vector, updated_at_ms)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (mailbox_id, message_id) DO UPDATE SET
                model = EXCLUDED.model,
                dims = EXCLUDED.dims,
                vector = EXCLUDED.vector,
                updated_at_ms = EXCLUDED.updated_at_ms",
            &[&mb, &message_id, &model, &dims, &blob, &updated_at_ms],
        )
        .await
        .map_err(|e| AppError::Storage(format!("Failed to upsert Postgres message embedding: {e}")))?;
        Ok(())
    }

    async fn remove(&self, message_id: &str) -> AppResult<()> {
        let conn = self.ensure_ready().await?;
        let mb = self.mailbox_id.as_str();
        conn.execute(
            "DELETE FROM message_embeddings WHERE mailbox_id = $1 AND message_id = $2",
            &[&mb, &message_id],
        )
        .await
        .map_err(|e| {
            AppError::Storage(format!("Failed to delete Postgres message embedding: {e}"))
        })?;
        Ok(())
    }

    async fn list_for_model(&self, model: &str) -> AppResult<Vec<(String, Vec<f32>)>> {
        let conn = self.ensure_ready().await?;
        let mb = self.mailbox_id.as_str();
        let rows = conn
            .query(
                "SELECT message_id, dims, vector FROM message_embeddings WHERE mailbox_id = $1 AND model = $2",
                &[&mb, &model],
            )
            .await
            .map_err(|e| AppError::Storage(format!("Failed to query Postgres message embeddings: {e}")))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let message_id: String = row.get(0);
            let dims: i32 = row.get(1);
            let blob: Vec<u8> = row.get(2);
            match decode_f32_le(&blob) {
                Ok(vec) if i32::try_from(vec.len()).ok() == Some(dims) => {
                    out.push((message_id, vec));
                }
                Ok(vec) => {
                    tracing::warn!(
                        message_id = %message_id,
                        expected_dims = dims,
                        actual_dims = vec.len(),
                        "Skipping Postgres message embedding with mismatched dimensions"
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        message_id = %message_id,
                        error = %err,
                        "Skipping corrupted Postgres message embedding BYTEA"
                    );
                }
            }
        }
        Ok(out)
    }
}
