//! Pluggable binary blob storage (`BlobStore`) for raw RFC 2822 messages and attachments.
//!
//! Built-in implementations:
//! - [`InlineBlobStore`]: default no-op adapter indicating blobs remain inline inside `MailStore`.
//! - [`MemoryBlobStore`]: in-memory key-value blob store for testing and ephemeral deployments.
//! - [`FsBlobStore`]: atomic filesystem blob store with path-traversal protection and temp-file rename.
//!
//! External backends (S3, Cloudflare R2, GCS) only need to implement [`BlobStore`].

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::{
    config::{BlobBackend, Config},
    error::{AppError, AppResult},
};

/// Canonical blob key for a message's verbatim RFC 2822 bytes.
pub fn raw_message_blob_key(message_id: &str) -> String {
    format!("messages/{message_id}/raw.eml")
}

/// Canonical blob key for an individual message attachment.
pub fn attachment_blob_key(message_id: &str, attachment_id: &str) -> String {
    format!("attachments/{message_id}/{attachment_id}")
}

/// Validate and normalize a logical blob key into safe relative path segments,
/// blocking path traversal (`..`), absolute paths, backslashes, NUL bytes, and control chars.
pub fn sanitize_blob_key(key: &str) -> AppResult<PathBuf> {
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return Err(AppError::validation(
            "Blob key must not be empty",
            None,
        ));
    }
    if trimmed.starts_with('/') || trimmed.contains('\\') {
        return Err(AppError::validation(
            format!("Invalid blob key '{key}': must be a relative forward-slash path"),
            None,
        ));
    }
    if trimmed.bytes().any(|b| b <= 0x1f || b == 0x7f) {
        return Err(AppError::validation(
            "Blob key contains disallowed control characters",
            None,
        ));
    }

    let mut rel = PathBuf::new();
    let mut segment_count = 0usize;
    for segment in trimmed.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." || segment.contains("..") {
            return Err(AppError::validation(
                format!("Blob key '{key}' contains invalid path segment '{segment}'"),
                None,
            ));
        }
        if segment.len() > 255 {
            return Err(AppError::validation(
                format!("Blob key segment '{segment}' exceeds 255 bytes"),
                None,
            ));
        }
        if !segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return Err(AppError::validation(
                format!("Blob key segment '{segment}' contains disallowed characters"),
                None,
            ));
        }
        rel.push(segment);
        segment_count += 1;
    }

    if segment_count == 0 {
        return Err(AppError::validation("Blob key must contain at least one segment", None));
    }

    Ok(rel)
}

/// Pluggable async binary blob storage trait for raw RFC 2822 emails and attachments.
#[async_trait]
pub trait BlobStore: Send + Sync {
    async fn put(&self, key: &str, bytes: &[u8]) -> AppResult<()>;
    async fn get(&self, key: &str) -> AppResult<Option<Vec<u8>>>;
    async fn delete(&self, key: &str) -> AppResult<()>;
    fn backend_name(&self) -> &'static str;
}

/// Returns `true` when `blobs` is an external blob store (anything other than `"inline"`).
pub fn is_external_blob_store(blobs: &dyn BlobStore) -> bool {
    blobs.backend_name() != "inline"
}

/// Default inline placeholder backend: raw RFC 2822 and attachment bytes are stored directly in `MailStore`.
#[derive(Debug, Clone, Copy, Default)]
pub struct InlineBlobStore;

#[async_trait]
impl BlobStore for InlineBlobStore {
    async fn put(&self, key: &str, _bytes: &[u8]) -> AppResult<()> {
        let _ = sanitize_blob_key(key)?;
        Ok(())
    }

    async fn get(&self, key: &str) -> AppResult<Option<Vec<u8>>> {
        let _ = sanitize_blob_key(key)?;
        Ok(None)
    }

    async fn delete(&self, key: &str) -> AppResult<()> {
        let _ = sanitize_blob_key(key)?;
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "inline"
    }
}

/// In-memory [`BlobStore`] suitable for tests and ephemeral deployments.
#[derive(Debug, Clone, Default)]
pub struct MemoryBlobStore {
    data: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl MemoryBlobStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl BlobStore for MemoryBlobStore {
    async fn put(&self, key: &str, bytes: &[u8]) -> AppResult<()> {
        let _ = sanitize_blob_key(key)?;
        let mut map = self
            .data
            .write()
            .map_err(|_| AppError::Storage("MemoryBlobStore lock poisoned".to_string()))?;
        map.insert(key.to_string(), bytes.to_vec());
        Ok(())
    }

    async fn get(&self, key: &str) -> AppResult<Option<Vec<u8>>> {
        let _ = sanitize_blob_key(key)?;
        let map = self
            .data
            .read()
            .map_err(|_| AppError::Storage("MemoryBlobStore lock poisoned".to_string()))?;
        Ok(map.get(key).cloned())
    }

    async fn delete(&self, key: &str) -> AppResult<()> {
        let _ = sanitize_blob_key(key)?;
        let mut map = self
            .data
            .write()
            .map_err(|_| AppError::Storage("MemoryBlobStore lock poisoned".to_string()))?;
        map.remove(key);
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "memory"
    }
}

/// Filesystem-backed [`BlobStore`] using path-traversal sanitization and atomic temp-file + rename writes.
#[derive(Debug, Clone)]
pub struct FsBlobStore {
    root: PathBuf,
}

impl FsBlobStore {
    /// Open or create a filesystem blob store rooted at `root`.
    pub fn open(root: impl AsRef<Path>) -> AppResult<Self> {
        let root_path = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root_path).map_err(|e| {
            AppError::Storage(format!(
                "Failed to initialize blob directory '{}': {e}",
                root_path.display()
            ))
        })?;
        Ok(Self { root: root_path })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn resolve_path(&self, key: &str) -> AppResult<PathBuf> {
        let rel = sanitize_blob_key(key)?;
        Ok(self.root.join(rel))
    }
}

#[async_trait]
impl BlobStore for FsBlobStore {
    async fn put(&self, key: &str, bytes: &[u8]) -> AppResult<()> {
        let target = self.resolve_path(key)?;
        let parent = target.parent().ok_or_else(|| {
            AppError::Storage(format!("Blob path '{}' has no parent directory", target.display()))
        })?;
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            AppError::Storage(format!(
                "Failed to create blob parent dir '{}': {e}",
                parent.display()
            ))
        })?;

        let file_name = target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("blob");
        let tmp_path = parent.join(format!(".{file_name}.tmp.{}", Uuid::new_v4()));

        let write_result = async {
            let mut file = tokio::fs::File::create(&tmp_path).await?;
            file.write_all(bytes).await?;
            file.sync_all().await?;
            tokio::fs::rename(&tmp_path, &target).await?;
            Ok::<(), std::io::Error>(())
        }
        .await;

        if let Err(err) = write_result {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(AppError::Storage(format!(
                "Failed to write blob '{key}': {err}"
            )));
        }

        Ok(())
    }

    async fn get(&self, key: &str) -> AppResult<Option<Vec<u8>>> {
        let target = self.resolve_path(key)?;
        match tokio::fs::read(&target).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(AppError::Storage(format!(
                "Failed to read blob '{key}': {err}"
            ))),
        }
    }

    async fn delete(&self, key: &str) -> AppResult<()> {
        let target = self.resolve_path(key)?;
        match tokio::fs::remove_file(&target).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(AppError::Storage(format!(
                "Failed to delete blob '{key}': {err}"
            ))),
        }
    }

    fn backend_name(&self) -> &'static str {
        "fs"
    }
}

/// Construct the configured [`BlobStore`] backend (`inline`, `fs`, or `memory`).
pub fn open_blob_store(config: &Config) -> AppResult<Arc<dyn BlobStore>> {
    match config.blob_backend {
        BlobBackend::Inline => Ok(Arc::new(InlineBlobStore)),
        BlobBackend::Memory => Ok(Arc::new(MemoryBlobStore::new())),
        BlobBackend::Fs => Ok(Arc::new(FsBlobStore::open(&config.blob_dir)?)),
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn sanitize_blob_key_rejects_traversal_and_accepts_safe_keys() {
        assert!(sanitize_blob_key("messages/msg_123/raw.eml").is_ok());
        assert!(sanitize_blob_key("attachments/msg_1/att-2.bin").is_ok());

        for bad in [
            "",
            "   ",
            "/etc/passwd",
            "../secret",
            "messages/../secret",
            "messages/a..b/raw.eml",
            "messages/./raw.eml",
            "messages//raw.eml",
            "messages\\raw.eml",
            "messages/bad\x00key",
            "messages/bad\nkey",
            "messages/bad space/raw.eml",
        ] {
            assert!(
                sanitize_blob_key(bad).is_err(),
                "expected key '{bad}' to be rejected"
            );
        }
    }

    #[tokio::test]
    async fn memory_blob_store_put_get_delete_roundtrip() {
        let store = MemoryBlobStore::new();
        assert_eq!(store.backend_name(), "memory");
        assert!(is_external_blob_store(&store));

        let key = raw_message_blob_key("msg_1");
        assert_eq!(store.get(&key).await.unwrap(), None);

        store.put(&key, b"raw-email-bytes").await.unwrap();
        assert_eq!(store.get(&key).await.unwrap(), Some(b"raw-email-bytes".to_vec()));

        store.delete(&key).await.unwrap();
        assert_eq!(store.get(&key).await.unwrap(), None);
    }

    #[tokio::test]
    async fn fs_blob_store_atomic_put_get_delete_and_traversal_guard() {
        let dir = TempDir::new().unwrap();
        let store = FsBlobStore::open(dir.path()).unwrap();
        assert_eq!(store.backend_name(), "fs");
        assert!(is_external_blob_store(&store));

        let key = attachment_blob_key("msg_42", "att_9");
        assert_eq!(store.get(&key).await.unwrap(), None);

        store.put(&key, b"hello attachment").await.unwrap();
        assert_eq!(
            store.get(&key).await.unwrap(),
            Some(b"hello attachment".to_vec())
        );

        // Overwrite atomically
        store.put(&key, b"updated attachment").await.unwrap();
        assert_eq!(
            store.get(&key).await.unwrap(),
            Some(b"updated attachment".to_vec())
        );

        // Delete is idempotent
        store.delete(&key).await.unwrap();
        assert_eq!(store.get(&key).await.unwrap(), None);
        store.delete(&key).await.unwrap();

        // Path traversal rejected
        assert!(store.put("../escape.txt", b"nope").await.is_err());
        assert!(store.get("../../etc/passwd").await.is_err());
    }

    #[tokio::test]
    async fn inline_blob_store_reports_inline_and_returns_none() {
        let store = InlineBlobStore;
        assert_eq!(store.backend_name(), "inline");
        assert!(!is_external_blob_store(&store));
        store.put("messages/m1/raw.eml", b"abc").await.unwrap();
        assert_eq!(store.get("messages/m1/raw.eml").await.unwrap(), None);
        store.delete("messages/m1/raw.eml").await.unwrap();
    }
}
