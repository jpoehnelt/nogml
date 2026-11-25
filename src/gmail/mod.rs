//! Gmail REST API v1 routes, upload endpoints, HTTP batching (`/batch/gmail/v1`),
//! partial response `?fields=` filtering, push `watch`/`stop`, and `settings/*`.
//!
//! Owned by the `gmail-api` worker.

use axum::Router;

use crate::{
    AppState,
    error::AppResult,
    models::{Message, MessageFormat},
    storage::StoredMessage,
};

/// Build the Gmail REST API v1 router covering:
/// - `/gmail/v1/users/{userId}/profile`
/// - `/gmail/v1/users/{userId}/messages` (list, get, send, insert, import, modify, trash, untrash, delete, batchModify, batchDelete, attachments.get)
/// - `/gmail/v1/users/{userId}/threads` (list, get, modify, trash, untrash, delete)
/// - `/gmail/v1/users/{userId}/labels` (list, get, create, update, patch, delete)
/// - `/gmail/v1/users/{userId}/drafts` (list, get, create, update, delete, send)
/// - `/gmail/v1/users/{userId}/history` (list)
/// - `/gmail/v1/users/{userId}/watch` & `/stop`
/// - `/gmail/v1/users/{userId}/settings/{sendAs,vacation,autoForwarding,imap,pop}`
/// - `/upload/gmail/v1/users/{userId}/...`
/// - `/batch/gmail/v1`
pub fn gmail_router() -> Router<AppState> {
    Router::new()
}

/// Project a [`StoredMessage`] into a Gmail API [`Message`] according to `format` and `metadata_headers`.
pub fn format_gmail_message(
    _stored: &StoredMessage,
    _format: MessageFormat,
    _metadata_headers: &[String],
) -> AppResult<Message> {
    todo!("gmail-api worker: convert StoredMessage to Gmail API Message")
}
