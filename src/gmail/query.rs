//! Gmail query string parser supporting repeatable parameters (`labelIds`, `metadataHeaders`,
//! `historyTypes`) and standard Google API parameters (`alt`, `fields`, `uploadType`).

use crate::{
    auth::validate_resource_id,
    error::{AppError, AppResult},
    models::MessageFormat,
    storage::{HistoryEventKind, HistoryListQuery, MessageListQuery},
};

/// Parsed URL query key-value pairs preserving duplicates in order.
#[derive(Debug, Clone, Default)]
pub struct QueryParams {
    pairs: Vec<(String, String)>,
}

impl QueryParams {
    pub fn from_raw(raw: Option<&str>) -> Self {
        let Some(raw) = raw else {
            return Self::default();
        };
        let pairs = url::form_urlencoded::parse(raw.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        Self { pairs }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    pub fn get_all(&self, key: &str) -> Vec<String> {
        self.pairs
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .filter(|v| !v.is_empty())
            .collect()
    }

    pub fn get_bool(&self, key: &str, default: bool) -> AppResult<bool> {
        match self.get(key) {
            None => Ok(default),
            Some(v) if v.eq_ignore_ascii_case("true") || v == "1" => Ok(true),
            Some(v) if v.eq_ignore_ascii_case("false") || v == "0" => Ok(false),
            Some(other) => Err(AppError::BadRequest(format!(
                "Invalid boolean value '{other}' for query parameter '{key}'"
            ))),
        }
    }

    pub fn get_usize(&self, key: &str) -> AppResult<Option<usize>> {
        match self.get(key) {
            None => Ok(None),
            Some(v) => v
                .parse::<usize>()
                .map(Some)
                .map_err(|_| AppError::BadRequest(format!("Invalid integer value '{v}' for '{key}'"))),
        }
    }

    pub fn get_u64(&self, key: &str) -> AppResult<Option<u64>> {
        match self.get(key) {
            None => Ok(None),
            Some(v) => v
                .parse::<u64>()
                .map(Some)
                .map_err(|_| AppError::BadRequest(format!("Invalid uint64 value '{v}' for '{key}'"))),
        }
    }

    /// Parse `format` (`full` | `metadata` | `minimal` | `raw`), case-insensitive.
    pub fn parse_format(&self, default: MessageFormat) -> AppResult<MessageFormat> {
        match self.get("format") {
            None => Ok(default),
            Some(v) => match v.to_ascii_lowercase().as_str() {
                "full" => Ok(MessageFormat::Full),
                "metadata" => Ok(MessageFormat::Metadata),
                "minimal" => Ok(MessageFormat::Minimal),
                "raw" => Ok(MessageFormat::Raw),
                _ => Err(AppError::BadRequest(format!(
                    "Invalid format '{v}'; expected full, metadata, minimal, or raw"
                ))),
            },
        }
    }

    /// Parse repeatable `metadataHeaders` query parameters.
    pub fn metadata_headers(&self) -> Vec<String> {
        self.get_all("metadataHeaders")
    }

    /// Parse standard Gmail list query parameters (`maxResults`, `pageToken`, `q`, `labelIds`, `includeSpamTrash`).
    pub fn parse_message_list_query(&self) -> AppResult<MessageListQuery> {
        let max_results = match self.get_usize("maxResults")? {
            Some(0) => {
                return Err(AppError::BadRequest(
                    "maxResults must be between 1 and 500".to_string(),
                ));
            }
            Some(n) => n.min(500),
            None => 100,
        };

        let label_ids = self.get_all("labelIds");
        for lid in &label_ids {
            validate_resource_id(lid)?;
        }

        let page_token = self
            .get("pageToken")
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned);
        let q = self.get("q").filter(|s| !s.is_empty()).map(ToOwned::to_owned);
        let include_spam_trash = self.get_bool("includeSpamTrash", false)?;

        Ok(MessageListQuery {
            q,
            label_ids,
            include_spam_trash,
            max_results,
            page_token,
        })
    }

    /// Parse Gmail `history.list` query parameters (`startHistoryId`, `maxResults`, `pageToken`,
    /// `labelId`, repeatable `historyTypes`).
    pub fn parse_history_list_query(&self) -> AppResult<HistoryListQuery> {
        let start_history_id = self
            .get_u64("startHistoryId")?
            .ok_or_else(|| AppError::BadRequest("Missing required parameter 'startHistoryId'".to_string()))?;

        let max_results = match self.get_usize("maxResults")? {
            Some(0) => {
                return Err(AppError::BadRequest(
                    "maxResults must be between 1 and 500".to_string(),
                ));
            }
            Some(n) => n.min(500),
            None => 100,
        };

        let page_token = self
            .get("pageToken")
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned);

        let label_id = match self.get("labelId").filter(|s| !s.is_empty()) {
            Some(lid) => {
                validate_resource_id(lid)?;
                Some(lid.to_string())
            }
            None => None,
        };

        let mut history_types = Vec::new();
        for raw_kind in self.get_all("historyTypes") {
            let kind = match raw_kind.as_str() {
                "messageAdded" => HistoryEventKind::MessageAdded,
                "messageDeleted" => HistoryEventKind::MessageDeleted,
                "labelAdded" => HistoryEventKind::LabelAdded,
                "labelRemoved" => HistoryEventKind::LabelRemoved,
                other => {
                    return Err(AppError::BadRequest(format!(
                        "Invalid historyTypes value '{other}'; expected messageAdded, messageDeleted, labelAdded, or labelRemoved"
                    )));
                }
            };
            if !history_types.contains(&kind) {
                history_types.push(kind);
            }
        }

        Ok(HistoryListQuery {
            start_history_id,
            max_results,
            page_token,
            label_id,
            history_types,
        })
    }
}
