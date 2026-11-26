//! Upstream Gmail REST API v1 [`SyncSource`] (`SyncMode::Api`):
//! - OAuth2 refresh token exchange (with in-memory caching) or static access token
//! - Labels sync (`users.labels.list` -> `MailStore::upsert_upstream_label`) + custom label pushback (`create`/`patch`/`delete`)
//! - Full backfill (`profile` -> paginated `messages.list` -> bounded-concurrency `messages.get?format=raw`)
//! - Incremental sync (`history.list` with automatic HTTP 404 fallback to full backfill)
//! - Drafts sync (`users.drafts.list` + `users.drafts.get?format=raw` + `drafts.create`/`update`/`delete` pushback)
//! - Optional bidirectional pushback (`messages.modify`, `messages.trash`, `messages.delete`, `messages.import`)

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use base64::Engine as _;
use chrono::Utc;
use futures_util::stream::{self, StreamExt};
use reqwest::{Client, Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::{
    AppState,
    config::Config,
    error::{AppError, AppResult},
    events::{EventSource, MailEvent},
    imap::mime_fmt::parse_raw_to_new_message_input,
    models::{
        Draft, LABEL_DRAFT, LABEL_SENT, Label, LabelColor, ListDraftsResponse, ListHistoryResponse,
        ListLabelsResponse, ListMessagesResponse, Message, ModifyMessageRequest, Profile,
        is_system_label,
    },
    storage::{
        MessageListQuery, NewLabelInput, StoredDraft, StoredLabel, StoredMessage, SyncState,
    },
    sync::{
        LocalMutation, LocalMutationKind, PullReport, PushReport, SyncRunOptions, SyncSource,
        ingest_synced_message,
    },
};

const FETCH_CONCURRENCY: usize = 8;
const TOKEN_EXPIRY_MARGIN_SECS: u64 = 60;

#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    expires_at: Instant,
}

static TOKEN_CACHE: OnceLock<Mutex<HashMap<String, CachedToken>>> = OnceLock::new();

fn token_cache() -> &'static Mutex<HashMap<String, CachedToken>> {
    TOKEN_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn oauth_cache_key(config: &Config) -> Option<String> {
    let client_id = config
        .gmail_client_id
        .as_deref()
        .filter(|s| !s.is_empty())?;
    let refresh_token = config
        .gmail_refresh_token
        .as_deref()
        .filter(|s| !s.is_empty())?;
    Some(format!(
        "{}|{}|{}",
        config.gmail_oauth_token_url, client_id, refresh_token
    ))
}

/// Remove any cached OAuth2 access token for `config` so the next request refreshes it.
pub fn invalidate_access_token(config: &Config) {
    if let Some(key) = oauth_cache_key(config)
        && let Ok(mut guard) = token_cache().lock()
    {
        guard.remove(&key);
    }
}

#[derive(Clone)]
struct GmailAuth {
    config: Arc<Config>,
    current_token: Arc<tokio::sync::RwLock<String>>,
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

impl GmailAuth {
    async fn acquire(client: &Client, config: Arc<Config>) -> AppResult<Self> {
        let token = acquire_access_token(client, &config).await?;
        Ok(Self {
            config,
            current_token: Arc::new(tokio::sync::RwLock::new(token)),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    async fn token(&self) -> String {
        self.current_token.read().await.clone()
    }

    fn can_refresh(&self) -> bool {
        let has_static = self
            .config
            .gmail_access_token
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty());
        !has_static
            && self
                .config
                .gmail_client_id
                .as_deref()
                .is_some_and(|s| !s.is_empty())
            && self
                .config
                .gmail_client_secret
                .as_deref()
                .is_some_and(|s| !s.is_empty())
            && self
                .config
                .gmail_refresh_token
                .as_deref()
                .is_some_and(|s| !s.is_empty())
    }

    /// On HTTP 401 Unauthorized, invalidate `TOKEN_CACHE`, refresh the OAuth2 access token once
    /// (serialized across concurrent tasks), and return the fresh token.
    async fn refresh_after_401(
        &self,
        client: &Client,
        failed_token: &str,
    ) -> AppResult<Option<String>> {
        if !self.can_refresh() {
            return Ok(None);
        }
        let _guard = self.refresh_lock.lock().await;
        {
            let cur = self.current_token.read().await;
            if *cur != failed_token {
                return Ok(Some(cur.clone()));
            }
        }
        invalidate_access_token(&self.config);
        let refreshed = acquire_access_token(client, &self.config).await?;
        {
            let mut cur = self.current_token.write().await;
            *cur = refreshed.clone();
        }
        Ok(Some(refreshed))
    }
}

#[derive(Debug, Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct SyncedLabelRecord {
    pub upstream_label_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_list_visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_list_visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<LabelColor>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct SyncedDraftRecord {
    pub upstream_draft_id: String,
    pub upstream_message_id: String,
    pub content_hash: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct GmailSyncMeta {
    #[serde(default)]
    pub labels: HashMap<String, SyncedLabelRecord>,
    #[serde(default)]
    pub drafts: HashMap<String, SyncedDraftRecord>,
}

async fn load_sync_meta(state: &AppState, account_key: &str) -> AppResult<GmailSyncMeta> {
    let Some(raw) = state.store.get_sync_metadata(account_key).await? else {
        return Ok(GmailSyncMeta::default());
    };
    match serde_json::from_str::<GmailSyncMeta>(&raw) {
        Ok(meta) => Ok(meta),
        Err(err) => {
            warn!(%err, account_key, "Failed to parse stored GmailSyncMeta; starting fresh");
            Ok(GmailSyncMeta::default())
        }
    }
}

async fn save_sync_meta(
    state: &AppState,
    account_key: &str,
    meta: &GmailSyncMeta,
) -> AppResult<()> {
    let encoded = serde_json::to_string(meta)?;
    state.store.put_sync_metadata(account_key, &encoded).await
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

async fn resolve_upstream_thread_id(state: &AppState, msg: &StoredMessage) -> Option<String> {
    if let Some(ref utid) = msg.upstream_thread_id
        && !utid.trim().is_empty()
    {
        return Some(utid.clone());
    }
    if let Ok(Some(thread)) = state.store.get_thread(&msg.thread_id).await {
        for m in thread.messages {
            if let Some(utid) = m.upstream_thread_id
                && !utid.trim().is_empty()
            {
                return Some(utid);
            }
        }
    }
    None
}

async fn list_all_local_drafts(state: &AppState) -> AppResult<Vec<StoredDraft>> {
    let mut all = Vec::new();
    let mut page_token: Option<String> = None;
    loop {
        let page = state
            .store
            .list_drafts(&MessageListQuery {
                include_spam_trash: true,
                max_results: 500,
                page_token: page_token.clone(),
                ..Default::default()
            })
            .await?;
        all.extend(page.drafts);
        match page.next_page_token.filter(|s| !s.is_empty()) {
            Some(next) => page_token = Some(next),
            None => break,
        }
    }
    Ok(all)
}

async fn list_unsynced_import_messages(state: &AppState) -> AppResult<Vec<StoredMessage>> {
    let mut candidates = Vec::new();
    let mut page_token: Option<String> = None;
    loop {
        let page = state
            .store
            .list_messages(&MessageListQuery {
                include_spam_trash: true,
                max_results: 500,
                page_token: page_token.clone(),
                ..Default::default()
            })
            .await?;
        for msg in page.messages {
            if msg.upstream_gmail_id.is_some() {
                continue;
            }
            if msg.label_ids.iter().any(|l| l == LABEL_DRAFT) {
                continue;
            }
            let is_sent = msg.label_ids.iter().any(|l| l == LABEL_SENT);
            let is_imported = matches!(
                msg.source.as_str(),
                "gmail_import" | "import" | "imap_append"
            );
            if is_sent || is_imported {
                candidates.push(msg);
            }
        }
        match page.next_page_token.filter(|s| !s.is_empty()) {
            Some(next) => page_token = Some(next),
            None => break,
        }
    }
    Ok(candidates)
}

enum LabelPushAction {
    Create(StoredLabel),
    Patch {
        local: StoredLabel,
        upstream_id: String,
    },
    Delete {
        local_id: String,
        upstream_id: String,
    },
}

enum DraftPushAction {
    Create {
        draft: StoredDraft,
        raw_bytes: Vec<u8>,
        content_hash: String,
    },
    Update {
        draft: StoredDraft,
        upstream_draft_id: String,
        raw_bytes: Vec<u8>,
        content_hash: String,
    },
    Delete {
        local_draft_id: String,
        upstream_draft_id: String,
    },
}

fn plan_label_push_actions(
    local_labels: &[StoredLabel],
    meta: &GmailSyncMeta,
) -> Vec<LabelPushAction> {
    let mut actions = Vec::new();
    let mut present_local_ids = HashSet::new();

    for lbl in local_labels {
        if is_system_label(&lbl.id) || lbl.label_type == "system" {
            continue;
        }
        present_local_ids.insert(lbl.id.as_str());
        match lbl.upstream_label_id.as_deref() {
            None => {
                actions.push(LabelPushAction::Create(lbl.clone()));
            }
            Some(up_id) => {
                if let Some(prev) = meta.labels.get(&lbl.id) {
                    let changed = prev.name != lbl.name
                        || prev.message_list_visibility != lbl.message_list_visibility
                        || prev.label_list_visibility != lbl.label_list_visibility
                        || prev.color != lbl.color;
                    if changed {
                        actions.push(LabelPushAction::Patch {
                            local: lbl.clone(),
                            upstream_id: up_id.to_string(),
                        });
                    }
                }
            }
        }
    }

    for (local_id, rec) in &meta.labels {
        if !present_local_ids.contains(local_id.as_str()) {
            actions.push(LabelPushAction::Delete {
                local_id: local_id.clone(),
                upstream_id: rec.upstream_label_id.clone(),
            });
        }
    }

    actions
}

async fn plan_draft_push_actions(
    state: &AppState,
    meta: &GmailSyncMeta,
) -> AppResult<Vec<DraftPushAction>> {
    let local_drafts = list_all_local_drafts(state).await?;
    let mut actions = Vec::new();
    let mut present_ids = HashSet::new();

    for summary_draft in local_drafts {
        present_ids.insert(summary_draft.id.clone());
        let Some(draft) = state.store.get_draft(&summary_draft.id).await? else {
            continue;
        };
        let raw_bytes = state.load_raw_rfc2822(&draft.message).await?;
        let content_hash = sha256_hex(&raw_bytes);
        match meta.drafts.get(&draft.id) {
            None => {
                actions.push(DraftPushAction::Create {
                    draft,
                    raw_bytes,
                    content_hash,
                });
            }
            Some(prev) => {
                if prev.content_hash != content_hash {
                    actions.push(DraftPushAction::Update {
                        draft,
                        upstream_draft_id: prev.upstream_draft_id.clone(),
                        raw_bytes,
                        content_hash,
                    });
                }
            }
        }
    }

    for (local_draft_id, rec) in &meta.drafts {
        if !present_ids.contains(local_draft_id) {
            actions.push(DraftPushAction::Delete {
                local_draft_id: local_draft_id.clone(),
                upstream_draft_id: rec.upstream_draft_id.clone(),
            });
        }
    }

    Ok(actions)
}

/// Upstream Gmail REST API v1 [`SyncSource`] implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct GmailApiSyncSource;

#[async_trait]
impl SyncSource for GmailApiSyncSource {
    fn provider_name(&self) -> &'static str {
        "gmail_api"
    }

    fn supports_full_bidirectional_push(&self) -> bool {
        true
    }

    fn account_key(&self, config: &Config) -> String {
        if config.is_multi_mailbox() {
            format!(
                "gmail_api:{}:{}",
                crate::config::normalize_mailbox_id(&config.user_email),
                config.gmail_user_id
            )
        } else {
            format!("gmail_api:{}", config.gmail_user_id)
        }
    }

    async fn pull(
        &self,
        state: &AppState,
        sync_state: &mut SyncState,
        opts: &SyncRunOptions,
    ) -> AppResult<PullReport> {
        let client = build_http_client()?;
        let auth = GmailAuth::acquire(&client, state.config.clone()).await?;
        let base = state.config.gmail_api_base_url.trim_end_matches('/');
        let user_id = encode_path_segment(&state.config.gmail_user_id);
        let bidirectional = opts
            .bidirectional
            .unwrap_or(state.config.sync_bidirectional);
        let account_key = self.account_key(&state.config);
        let mut meta = load_sync_meta(state, &account_key).await?;

        let mut report = PullReport::default();

        // 1. Sync upstream user labels and build upstream_label_id -> local_label_id map.
        let label_map = sync_labels(
            &client,
            base,
            &user_id,
            &auth,
            state,
            bidirectional,
            &mut meta,
            &mut report,
        )
        .await?;

        // 2. Attempt incremental sync if we have a checkpoint and `full` was not requested.
        let mut need_full = opts.full || sync_state.last_history_id.is_none();
        if !need_full && let Some(start_history_id) = sync_state.last_history_id.clone() {
            match run_incremental(
                &client,
                base,
                &user_id,
                &auth,
                &start_history_id,
                &label_map,
                state,
                &mut report,
            )
            .await?
            {
                IncrementalOutcome::Applied { new_history_id } => {
                    sync_state.last_history_id = Some(new_history_id.clone());
                    report.history_id = Some(new_history_id);
                }
                IncrementalOutcome::HistoryExpired => {
                    warn!(
                        start_history_id,
                        "Gmail historyId expired (HTTP 404); falling back to full backfill"
                    );
                    sync_state.last_history_id = None;
                    need_full = true;
                }
            }
        }

        // 3. Full backfill (initial run, `--full`, or automatic 404 fallback).
        if need_full {
            report.full_resync = true;
            let baseline_history = run_full_backfill(
                &client,
                base,
                &user_id,
                &auth,
                opts,
                &label_map,
                state,
                &mut report,
            )
            .await?;
            sync_state.last_history_id = Some(baseline_history.clone());
            sync_state.last_full_sync_at = Some(Utc::now());
            report.history_id = Some(baseline_history);
        }

        // 4. Sync upstream drafts (`users.drafts.list` + `users.drafts.get?format=raw`).
        sync_drafts_pull(
            &client,
            base,
            &user_id,
            &auth,
            &label_map,
            state,
            bidirectional,
            &mut meta,
            &mut report,
        )
        .await?;

        save_sync_meta(state, &account_key, &meta).await?;

        sync_state.messages_synced = sync_state
            .messages_synced
            .saturating_add(report.messages_added);
        Ok(report)
    }

    async fn push_changes(
        &self,
        state: &AppState,
        changes: &[LocalMutation],
    ) -> AppResult<PushReport> {
        let account_key = self.account_key(&state.config);
        let mut meta = load_sync_meta(state, &account_key).await?;

        let local_labels = state.store.list_labels().await?;
        let label_actions = plan_label_push_actions(&local_labels, &meta);
        let import_candidates = list_unsynced_import_messages(state).await?;
        let draft_actions = plan_draft_push_actions(state, &meta).await?;

        if changes.is_empty()
            && label_actions.is_empty()
            && import_candidates.is_empty()
            && draft_actions.is_empty()
        {
            return Ok(PushReport::default());
        }

        let client = build_http_client()?;
        let auth = GmailAuth::acquire(&client, state.config.clone()).await?;
        let base = state.config.gmail_api_base_url.trim_end_matches('/');
        let user_id = encode_path_segment(&state.config.gmail_user_id);

        // Build local_label_id -> upstream_label_id reverse mapping.
        let mut reverse_labels: HashMap<String, String> = HashMap::new();
        for lbl in &local_labels {
            if is_system_label(&lbl.id) || lbl.label_type == "system" {
                reverse_labels.insert(lbl.id.clone(), lbl.id.clone());
            } else if let Some(ref up_id) = lbl.upstream_label_id {
                reverse_labels.insert(lbl.id.clone(), up_id.clone());
            }
        }

        let mut pushed = 0u64;

        // 1. Push custom label create / patch / delete actions first so message/import pushes can map them.
        for action in label_actions {
            match action {
                LabelPushAction::Create(local) => {
                    let url = format!("{base}/gmail/v1/users/{user_id}/labels");
                    let mut body_val = json!({
                        "name": local.name,
                    });
                    if let Some(ref vis) = local.message_list_visibility {
                        body_val["messageListVisibility"] = Value::String(vis.clone());
                    }
                    if let Some(ref vis) = local.label_list_visibility {
                        body_val["labelListVisibility"] = Value::String(vis.clone());
                    }
                    if let Some(ref color) = local.color {
                        body_val["color"] = serde_json::to_value(color)?;
                    }
                    let payload = serde_json::to_vec(&body_val)?;
                    let (status, body) =
                        request_with_retry(&client, Method::POST, &url, &auth, Some(payload))
                            .await?;
                    if !status.is_success() {
                        return Err(AppError::Upstream {
                            status: status.as_u16(),
                            message: format!(
                                "Gmail labels.create({}) failed: {}",
                                local.name,
                                String::from_utf8_lossy(&body)
                            ),
                        });
                    }
                    let created: Label = serde_json::from_slice(&body)?;
                    if !created.id.is_empty() {
                        let _ = state
                            .store
                            .set_label_upstream_id(&local.id, &created.id)
                            .await?;
                        reverse_labels.insert(local.id.clone(), created.id.clone());
                        meta.labels.insert(
                            local.id.clone(),
                            SyncedLabelRecord {
                                upstream_label_id: created.id,
                                name: local.name,
                                message_list_visibility: local.message_list_visibility,
                                label_list_visibility: local.label_list_visibility,
                                color: local.color,
                            },
                        );
                    }
                    pushed += 1;
                }
                LabelPushAction::Patch { local, upstream_id } => {
                    let url = format!(
                        "{base}/gmail/v1/users/{user_id}/labels/{}",
                        encode_path_segment(&upstream_id)
                    );
                    let mut body_val = json!({
                        "id": upstream_id,
                        "name": local.name,
                    });
                    if let Some(ref vis) = local.message_list_visibility {
                        body_val["messageListVisibility"] = Value::String(vis.clone());
                    }
                    if let Some(ref vis) = local.label_list_visibility {
                        body_val["labelListVisibility"] = Value::String(vis.clone());
                    }
                    if let Some(ref color) = local.color {
                        body_val["color"] = serde_json::to_value(color)?;
                    }
                    let payload = serde_json::to_vec(&body_val)?;
                    let (status, body) =
                        request_with_retry(&client, Method::PATCH, &url, &auth, Some(payload))
                            .await?;
                    if status == StatusCode::NOT_FOUND {
                        warn!(
                            upstream_label_id = %upstream_id,
                            "Skipping upstream Gmail label patch: label not found (404)"
                        );
                        continue;
                    }
                    if !status.is_success() {
                        return Err(AppError::Upstream {
                            status: status.as_u16(),
                            message: format!(
                                "Gmail labels.patch({upstream_id}) failed: {}",
                                String::from_utf8_lossy(&body)
                            ),
                        });
                    }
                    meta.labels.insert(
                        local.id.clone(),
                        SyncedLabelRecord {
                            upstream_label_id: upstream_id,
                            name: local.name,
                            message_list_visibility: local.message_list_visibility,
                            label_list_visibility: local.label_list_visibility,
                            color: local.color,
                        },
                    );
                    pushed += 1;
                }
                LabelPushAction::Delete {
                    local_id,
                    upstream_id,
                } => {
                    let url = format!(
                        "{base}/gmail/v1/users/{user_id}/labels/{}",
                        encode_path_segment(&upstream_id)
                    );
                    let (status, body) =
                        request_with_retry(&client, Method::DELETE, &url, &auth, None).await?;
                    if status != StatusCode::NOT_FOUND && !status.is_success() {
                        return Err(AppError::Upstream {
                            status: status.as_u16(),
                            message: format!(
                                "Gmail labels.delete({upstream_id}) failed: {}",
                                String::from_utf8_lossy(&body)
                            ),
                        });
                    }
                    meta.labels.remove(&local_id);
                    pushed += 1;
                }
            }
        }

        // 2. Push message label / trash / delete mutations.
        for mutation in changes {
            let encoded_id = encode_path_segment(&mutation.upstream_id);
            match &mutation.kind {
                LocalMutationKind::ModifyLabels {
                    add_labels,
                    remove_labels,
                } => {
                    let add_label_ids = map_local_to_upstream_labels(add_labels, &reverse_labels);
                    let remove_label_ids =
                        map_local_to_upstream_labels(remove_labels, &reverse_labels);
                    if add_label_ids.is_empty() && remove_label_ids.is_empty() {
                        continue;
                    }

                    let url =
                        format!("{base}/gmail/v1/users/{user_id}/messages/{encoded_id}/modify");
                    let payload = serde_json::to_vec(&ModifyMessageRequest {
                        add_label_ids,
                        remove_label_ids,
                    })?;
                    let (status, body) =
                        request_with_retry(&client, Method::POST, &url, &auth, Some(payload))
                            .await?;
                    if status == StatusCode::NOT_FOUND {
                        warn!(
                            upstream_id = %mutation.upstream_id,
                            "Skipping upstream Gmail modify push: message not found (404)"
                        );
                        continue;
                    }
                    if !status.is_success() {
                        return Err(AppError::Upstream {
                            status: status.as_u16(),
                            message: format!(
                                "Gmail messages.modify({}) failed: {}",
                                mutation.upstream_id,
                                String::from_utf8_lossy(&body)
                            ),
                        });
                    }
                    pushed += 1;
                }
                LocalMutationKind::Trash {
                    add_labels,
                    remove_labels,
                } => {
                    let add_label_ids = map_local_to_upstream_labels(add_labels, &reverse_labels);
                    let remove_label_ids =
                        map_local_to_upstream_labels(remove_labels, &reverse_labels);
                    if !add_label_ids.is_empty() || !remove_label_ids.is_empty() {
                        let modify_url =
                            format!("{base}/gmail/v1/users/{user_id}/messages/{encoded_id}/modify");
                        let payload = serde_json::to_vec(&ModifyMessageRequest {
                            add_label_ids,
                            remove_label_ids,
                        })?;
                        let (status, body) = request_with_retry(
                            &client,
                            Method::POST,
                            &modify_url,
                            &auth,
                            Some(payload),
                        )
                        .await?;
                        if status == StatusCode::NOT_FOUND {
                            warn!(
                                upstream_id = %mutation.upstream_id,
                                "Skipping upstream Gmail trash push: message not found (404)"
                            );
                            continue;
                        }
                        if !status.is_success() {
                            return Err(AppError::Upstream {
                                status: status.as_u16(),
                                message: format!(
                                    "Gmail messages.modify({}) before trash failed: {}",
                                    mutation.upstream_id,
                                    String::from_utf8_lossy(&body)
                                ),
                            });
                        }
                    }

                    let trash_url =
                        format!("{base}/gmail/v1/users/{user_id}/messages/{encoded_id}/trash");
                    let (status, body) =
                        request_with_retry(&client, Method::POST, &trash_url, &auth, None).await?;
                    if status == StatusCode::NOT_FOUND {
                        warn!(
                            upstream_id = %mutation.upstream_id,
                            "Skipping upstream Gmail trash push: message not found (404)"
                        );
                        continue;
                    }
                    if !status.is_success() {
                        return Err(AppError::Upstream {
                            status: status.as_u16(),
                            message: format!(
                                "Gmail messages.trash({}) failed: {}",
                                mutation.upstream_id,
                                String::from_utf8_lossy(&body)
                            ),
                        });
                    }
                    pushed += 1;
                }
                LocalMutationKind::Delete => {
                    let delete_url =
                        format!("{base}/gmail/v1/users/{user_id}/messages/{encoded_id}");
                    let (status, body) =
                        request_with_retry(&client, Method::DELETE, &delete_url, &auth, None)
                            .await?;
                    if status == StatusCode::NOT_FOUND {
                        debug!(
                            upstream_id = %mutation.upstream_id,
                            "Upstream Gmail message already deleted (404)"
                        );
                        pushed += 1;
                        continue;
                    }
                    if !status.is_success() {
                        return Err(AppError::Upstream {
                            status: status.as_u16(),
                            message: format!(
                                "Gmail messages.delete({}) failed: {}",
                                mutation.upstream_id,
                                String::from_utf8_lossy(&body)
                            ),
                        });
                    }
                    pushed += 1;
                }
                LocalMutationKind::AppendMessage { .. } => {
                    // Gmail API handles unsynced Sent/imported messages in step 3 (`messages.import`)
                    // and drafts in step 4 (`users.drafts.*`).
                }
            }
        }

        // 3. Push locally created Sent / imported messages without upstream_gmail_id via messages.import.
        for summary_msg in import_candidates {
            let Some(msg) = state.store.get_message(&summary_msg.id).await? else {
                continue;
            };
            let raw_bytes = state.load_raw_rfc2822(&msg).await?;
            let raw_b64 = crate::mime::encode_base64url(&raw_bytes);
            let mapped_labels = map_local_to_upstream_labels(&msg.label_ids, &reverse_labels);
            let mut body_val = json!({
                "raw": raw_b64,
            });
            if !mapped_labels.is_empty() {
                body_val["labelIds"] = serde_json::to_value(&mapped_labels)?;
            }
            if let Some(up_tid) = resolve_upstream_thread_id(state, &msg).await {
                body_val["threadId"] = Value::String(up_tid);
            }

            let import_url = format!(
                "{base}/gmail/v1/users/{user_id}/messages/import?internalDateSource=dateHeader&neverMarkSpam=true"
            );
            let payload = serde_json::to_vec(&body_val)?;
            let (status, body) =
                request_with_retry(&client, Method::POST, &import_url, &auth, Some(payload))
                    .await?;
            if !status.is_success() {
                return Err(AppError::Upstream {
                    status: status.as_u16(),
                    message: format!(
                        "Gmail messages.import({}) failed: {}",
                        msg.id,
                        String::from_utf8_lossy(&body)
                    ),
                });
            }
            let imported: Message = serde_json::from_slice(&body)?;
            if !imported.id.is_empty() {
                let up_tid =
                    (!imported.thread_id.is_empty()).then_some(imported.thread_id.as_str());
                let _ = state
                    .store
                    .set_message_upstream_ids(&msg.id, &imported.id, up_tid)
                    .await?;
            }
            pushed += 1;
        }

        // 4. Push local draft create / update / delete actions.
        for action in draft_actions {
            match action {
                DraftPushAction::Create {
                    draft,
                    raw_bytes,
                    content_hash,
                } => {
                    let up_tid = resolve_upstream_thread_id(state, &draft.message).await;
                    let created = push_create_draft(
                        &client,
                        base,
                        &user_id,
                        &auth,
                        &raw_bytes,
                        up_tid.as_deref(),
                    )
                    .await?;
                    record_pushed_draft(state, &draft, &created, content_hash, &mut meta).await?;
                    pushed += 1;
                }
                DraftPushAction::Update {
                    draft,
                    upstream_draft_id,
                    raw_bytes,
                    content_hash,
                } => {
                    let up_tid = resolve_upstream_thread_id(state, &draft.message).await;
                    let url = format!(
                        "{base}/gmail/v1/users/{user_id}/drafts/{}",
                        encode_path_segment(&upstream_draft_id)
                    );
                    let mut msg_val = json!({
                        "raw": crate::mime::encode_base64url(&raw_bytes),
                    });
                    if let Some(ref tid) = up_tid {
                        msg_val["threadId"] = Value::String(tid.clone());
                    }
                    let payload = serde_json::to_vec(&json!({
                        "id": upstream_draft_id,
                        "message": msg_val,
                    }))?;
                    let (status, body) =
                        request_with_retry(&client, Method::PUT, &url, &auth, Some(payload))
                            .await?;
                    let updated = if status == StatusCode::NOT_FOUND {
                        push_create_draft(
                            &client,
                            base,
                            &user_id,
                            &auth,
                            &raw_bytes,
                            up_tid.as_deref(),
                        )
                        .await?
                    } else if !status.is_success() {
                        return Err(AppError::Upstream {
                            status: status.as_u16(),
                            message: format!(
                                "Gmail drafts.update({upstream_draft_id}) failed: {}",
                                String::from_utf8_lossy(&body)
                            ),
                        });
                    } else {
                        serde_json::from_slice::<Draft>(&body)?
                    };
                    record_pushed_draft(state, &draft, &updated, content_hash, &mut meta).await?;
                    pushed += 1;
                }
                DraftPushAction::Delete {
                    local_draft_id,
                    upstream_draft_id,
                } => {
                    let url = format!(
                        "{base}/gmail/v1/users/{user_id}/drafts/{}",
                        encode_path_segment(&upstream_draft_id)
                    );
                    let (status, body) =
                        request_with_retry(&client, Method::DELETE, &url, &auth, None).await?;
                    if status != StatusCode::NOT_FOUND && !status.is_success() {
                        return Err(AppError::Upstream {
                            status: status.as_u16(),
                            message: format!(
                                "Gmail drafts.delete({upstream_draft_id}) failed: {}",
                                String::from_utf8_lossy(&body)
                            ),
                        });
                    }
                    meta.drafts.remove(&local_draft_id);
                    pushed += 1;
                }
            }
        }

        save_sync_meta(state, &account_key, &meta).await?;

        Ok(PushReport {
            messages_pushed: pushed,
        })
    }
}

fn build_http_client() -> AppResult<Client> {
    Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| AppError::Internal(format!("Failed to build HTTP client: {e}")))
}

pub(crate) fn encode_path_segment(seg: &str) -> String {
    url::form_urlencoded::byte_serialize(seg.as_bytes()).collect()
}

/// Acquire a Gmail API Bearer token via static config override or OAuth2 refresh flow.
pub async fn acquire_access_token(client: &Client, config: &Config) -> AppResult<String> {
    if let Some(tok) = config
        .gmail_access_token
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        return Ok(tok.trim().to_string());
    }

    let client_id = config
        .gmail_client_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::Config(
                "Gmail API sync requires gmail_access_token or (gmail_client_id, gmail_client_secret, gmail_refresh_token)".to_string(),
            )
        })?;
    let client_secret = config
        .gmail_client_secret
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Config("Missing gmail_client_secret for OAuth2".to_string()))?;
    let refresh_token = config
        .gmail_refresh_token
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Config("Missing gmail_refresh_token for OAuth2".to_string()))?;

    let cache_key = format!(
        "{}|{}|{}",
        config.gmail_oauth_token_url, client_id, refresh_token
    );
    if let Ok(guard) = token_cache().lock()
        && let Some(entry) = guard.get(&cache_key)
        && Instant::now() + Duration::from_secs(TOKEN_EXPIRY_MARGIN_SECS) < entry.expires_at
    {
        return Ok(entry.access_token.clone());
    }

    let resp = client
        .post(&config.gmail_oauth_token_url)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(AppError::Upstream {
            status: status.as_u16(),
            message: format!("Gmail OAuth2 token refresh failed: {body}"),
        });
    }

    let parsed: OAuthTokenResponse =
        serde_json::from_str(&body).map_err(|e| AppError::Upstream {
            status: 502,
            message: format!("Invalid OAuth2 token response: {e}"),
        })?;
    let ttl_secs = parsed.expires_in.unwrap_or(3600);
    let expires_at = Instant::now() + Duration::from_secs(ttl_secs);

    if let Ok(mut guard) = token_cache().lock() {
        guard.insert(
            cache_key,
            CachedToken {
                access_token: parsed.access_token.clone(),
                expires_at,
            },
        );
    }

    Ok(parsed.access_token)
}

#[allow(clippy::too_many_arguments)]
async fn sync_labels(
    client: &Client,
    base: &str,
    user_id: &str,
    auth: &GmailAuth,
    state: &AppState,
    bidirectional: bool,
    meta: &mut GmailSyncMeta,
    report: &mut PullReport,
) -> AppResult<HashMap<String, String>> {
    let url = format!("{base}/gmail/v1/users/{user_id}/labels");
    let (status, body) = get_with_retry(client, &url, auth).await?;
    if !status.is_success() {
        return Err(AppError::Upstream {
            status: status.as_u16(),
            message: format!(
                "Gmail labels.list failed: {}",
                String::from_utf8_lossy(&body)
            ),
        });
    }
    let resp: ListLabelsResponse = serde_json::from_slice(&body)?;
    let local_labels = state.store.list_labels().await?;

    let mut local_by_upstream: HashMap<String, StoredLabel> = HashMap::new();
    let mut local_ids: HashSet<String> = HashSet::new();
    for l in local_labels {
        local_ids.insert(l.id.clone());
        if let Some(ref up) = l.upstream_label_id {
            local_by_upstream.insert(up.clone(), l);
        }
    }

    let pending_local_deletes: HashSet<String> = if bidirectional {
        meta.labels
            .iter()
            .filter(|(local_id, rec)| {
                !local_ids.contains(*local_id)
                    && !local_by_upstream.contains_key(&rec.upstream_label_id)
            })
            .map(|(_, rec)| rec.upstream_label_id.clone())
            .collect()
    } else {
        HashSet::new()
    };

    let mut map = HashMap::new();
    for lbl in resp.labels {
        if is_system_label(&lbl.id) || lbl.label_type.as_deref() == Some("system") {
            map.insert(lbl.id.clone(), lbl.id);
            continue;
        }
        if bidirectional && pending_local_deletes.contains(&lbl.id) {
            debug!(
                upstream_label_id = %lbl.id,
                "Skipping pull of upstream label pending local deletion"
            );
            continue;
        }

        let up_name = if lbl.name.is_empty() {
            lbl.id.clone()
        } else {
            lbl.name.clone()
        };

        if bidirectional
            && let Some(existing) = local_by_upstream.get(&lbl.id)
            && let Some(prev) = meta.labels.get(&existing.id)
        {
            let upstream_changed = up_name != prev.name
                || lbl
                    .message_list_visibility
                    .as_ref()
                    .is_some_and(|v| prev.message_list_visibility.as_ref() != Some(v))
                || lbl
                    .label_list_visibility
                    .as_ref()
                    .is_some_and(|v| prev.label_list_visibility.as_ref() != Some(v))
                || lbl.color != prev.color;
            let local_changed = existing.name != prev.name
                || existing.message_list_visibility != prev.message_list_visibility
                || existing.label_list_visibility != prev.label_list_visibility
                || existing.color != prev.color;
            if local_changed && !upstream_changed {
                map.insert(lbl.id, existing.id.clone());
                continue;
            }
        }

        let stored = state
            .store
            .upsert_upstream_label(NewLabelInput {
                name: up_name,
                message_list_visibility: lbl.message_list_visibility,
                label_list_visibility: lbl.label_list_visibility,
                color: lbl.color,
                upstream_label_id: Some(lbl.id.clone()),
            })
            .await?;
        meta.labels.insert(
            stored.id.clone(),
            SyncedLabelRecord {
                upstream_label_id: lbl.id.clone(),
                name: stored.name.clone(),
                message_list_visibility: stored.message_list_visibility.clone(),
                label_list_visibility: stored.label_list_visibility.clone(),
                color: stored.color.clone(),
            },
        );
        map.insert(lbl.id, stored.id);
        report.labels_synced += 1;
    }
    Ok(map)
}

async fn push_create_draft(
    client: &Client,
    base: &str,
    user_id: &str,
    auth: &GmailAuth,
    raw_bytes: &[u8],
    upstream_thread_id: Option<&str>,
) -> AppResult<Draft> {
    let url = format!("{base}/gmail/v1/users/{user_id}/drafts");
    let mut msg_val = json!({
        "raw": crate::mime::encode_base64url(raw_bytes),
    });
    if let Some(tid) = upstream_thread_id.filter(|s| !s.trim().is_empty()) {
        msg_val["threadId"] = Value::String(tid.to_string());
    }
    let payload = serde_json::to_vec(&json!({ "message": msg_val }))?;
    let (status, body) =
        request_with_retry(client, Method::POST, &url, auth, Some(payload)).await?;
    if !status.is_success() {
        return Err(AppError::Upstream {
            status: status.as_u16(),
            message: format!(
                "Gmail drafts.create failed: {}",
                String::from_utf8_lossy(&body)
            ),
        });
    }
    Ok(serde_json::from_slice(&body)?)
}

async fn record_pushed_draft(
    state: &AppState,
    local: &StoredDraft,
    upstream: &Draft,
    content_hash: String,
    meta: &mut GmailSyncMeta,
) -> AppResult<()> {
    let up_msg_id = upstream
        .message
        .as_ref()
        .map(|m| m.id.clone())
        .unwrap_or_default();
    let up_tid = upstream
        .message
        .as_ref()
        .map(|m| m.thread_id.as_str())
        .filter(|s| !s.is_empty());
    if !up_msg_id.is_empty() {
        let _ = state
            .store
            .set_message_upstream_ids(&local.message.id, &up_msg_id, up_tid)
            .await?;
    }
    if !upstream.id.is_empty() {
        meta.drafts.insert(
            local.id.clone(),
            SyncedDraftRecord {
                upstream_draft_id: upstream.id.clone(),
                upstream_message_id: up_msg_id,
                content_hash,
            },
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn sync_drafts_pull(
    client: &Client,
    base: &str,
    user_id: &str,
    auth: &GmailAuth,
    label_map: &HashMap<String, String>,
    state: &AppState,
    bidirectional: bool,
    meta: &mut GmailSyncMeta,
    report: &mut PullReport,
) -> AppResult<()> {
    let mut page_token: Option<String> = None;
    let mut listed = Vec::new();
    let mut first_page = true;

    loop {
        let mut url = format!("{base}/gmail/v1/users/{user_id}/drafts?maxResults=500");
        if let Some(ref pt) = page_token {
            url.push_str("&pageToken=");
            url.push_str(&encode_path_segment(pt));
        }

        let (status, body) = get_with_retry(client, &url, auth).await?;
        if first_page && status == StatusCode::NOT_FOUND {
            debug!("Upstream Gmail drafts.list returned 404; skipping drafts pull");
            return Ok(());
        }
        first_page = false;
        if !status.is_success() {
            return Err(AppError::Upstream {
                status: status.as_u16(),
                message: format!(
                    "Gmail drafts.list failed: {}",
                    String::from_utf8_lossy(&body)
                ),
            });
        }
        let page: ListDraftsResponse = serde_json::from_slice(&body)?;
        for dref in page.drafts.unwrap_or_default() {
            if !dref.id.is_empty() {
                listed.push(dref);
            }
        }
        match page.next_page_token.filter(|s| !s.is_empty()) {
            Some(next) => page_token = Some(next),
            None => break,
        }
    }

    let local_drafts = list_all_local_drafts(state).await?;
    let local_draft_ids: HashSet<String> = local_drafts.iter().map(|d| d.id.clone()).collect();
    let mut local_draft_by_up_msg: HashMap<String, String> = HashMap::new();
    for d in &local_drafts {
        if let Some(ref up_mid) = d.message.upstream_gmail_id {
            local_draft_by_up_msg.insert(up_mid.clone(), d.id.clone());
        }
    }

    let pending_local_deleted_drafts: HashSet<String> = if bidirectional {
        meta.drafts
            .iter()
            .filter(|(local_id, _)| !local_draft_ids.contains(*local_id))
            .map(|(_, rec)| rec.upstream_draft_id.clone())
            .collect()
    } else {
        HashSet::new()
    };

    let mut seen_upstream_draft_ids = HashSet::new();
    for dref in listed {
        seen_upstream_draft_ids.insert(dref.id.clone());
        if bidirectional && pending_local_deleted_drafts.contains(&dref.id) {
            debug!(
                upstream_draft_id = %dref.id,
                "Skipping pull of upstream draft pending local deletion"
            );
            continue;
        }

        let url = format!(
            "{base}/gmail/v1/users/{user_id}/drafts/{}?format=raw",
            encode_path_segment(&dref.id)
        );
        let (status, body) = get_with_retry(client, &url, auth).await?;
        if status == StatusCode::NOT_FOUND {
            continue;
        }
        if !status.is_success() {
            return Err(AppError::Upstream {
                status: status.as_u16(),
                message: format!(
                    "Gmail drafts.get({}) failed: {}",
                    dref.id,
                    String::from_utf8_lossy(&body)
                ),
            });
        }

        let draft: Draft = serde_json::from_slice(&body)?;
        let Some(msg) = draft.message else {
            continue;
        };
        let raw_b64 = msg.raw.unwrap_or_default();
        let raw_bytes = decode_base64_tolerant(&raw_b64)?;
        let upstream_hash = sha256_hex(&raw_bytes);
        let up_msg_id = if msg.id.is_empty() {
            dref.message.id.clone()
        } else {
            msg.id
        };
        let up_tid = (!msg.thread_id.is_empty()).then_some(msg.thread_id);
        let internal_date_ms = msg
            .internal_date
            .as_deref()
            .and_then(|s| s.parse::<i64>().ok());
        let mut mapped_labels = map_labels(msg.label_ids.as_deref().unwrap_or(&[]), label_map);
        if !mapped_labels.iter().any(|l| l == LABEL_DRAFT) {
            mapped_labels.push(LABEL_DRAFT.to_string());
        }

        // Check if already tracked in `meta.drafts`.
        let existing_local_id = meta
            .drafts
            .iter()
            .find(|(_, rec)| rec.upstream_draft_id == dref.id)
            .map(|(lid, _)| lid.clone());

        if let Some(local_id) = existing_local_id
            && local_draft_ids.contains(&local_id)
        {
            if let Some(rec) = meta.drafts.get(&local_id)
                && rec.content_hash == upstream_hash
            {
                report.messages_deduplicated += 1;
                continue;
            }
            let input = parse_raw_to_new_message_input(
                raw_bytes,
                mapped_labels,
                internal_date_ms,
                "gmail_api",
                (!up_msg_id.is_empty()).then_some(up_msg_id.clone()),
                up_tid,
                false,
                false,
            );
            let updated = state.store.update_draft(&local_id, input).await?;
            state.post_store_message(&updated.message).await?;
            meta.drafts.insert(
                local_id,
                SyncedDraftRecord {
                    upstream_draft_id: dref.id,
                    upstream_message_id: up_msg_id,
                    content_hash: upstream_hash,
                },
            );
            report.messages_updated += 1;
            continue;
        }

        // Dedup against an existing local draft already linked to this upstream message ID.
        if !up_msg_id.is_empty()
            && let Some(local_id) = local_draft_by_up_msg.get(&up_msg_id).cloned()
        {
            meta.drafts.insert(
                local_id,
                SyncedDraftRecord {
                    upstream_draft_id: dref.id,
                    upstream_message_id: up_msg_id,
                    content_hash: upstream_hash,
                },
            );
            report.messages_deduplicated += 1;
            continue;
        }

        // If `messages.list` already ingested the bare draft message (without a drafts row),
        // remove that bare message so `create_draft` stores it cleanly as a draft without duplicating upstream_gmail_id.
        if !up_msg_id.is_empty()
            && state
                .store
                .find_message_by_upstream_id(&up_msg_id)
                .await?
                .is_some()
        {
            let _ = state
                .store
                .delete_message_by_upstream_id(&up_msg_id)
                .await?;
        }

        let input = parse_raw_to_new_message_input(
            raw_bytes,
            mapped_labels,
            internal_date_ms,
            "gmail_api",
            (!up_msg_id.is_empty()).then_some(up_msg_id.clone()),
            up_tid,
            false,
            false,
        );
        let created = state.store.create_draft(input).await?;
        state.post_store_message(&created.message).await?;
        meta.drafts.insert(
            created.id,
            SyncedDraftRecord {
                upstream_draft_id: dref.id,
                upstream_message_id: up_msg_id,
                content_hash: upstream_hash,
            },
        );
        report.messages_added += 1;
    }

    // Reconcile drafts deleted upstream (only when unmodified locally).
    let stale_local_ids: Vec<(String, String)> = meta
        .drafts
        .iter()
        .filter(|(_, rec)| !seen_upstream_draft_ids.contains(&rec.upstream_draft_id))
        .map(|(lid, rec)| (lid.clone(), rec.content_hash.clone()))
        .collect();

    for (local_id, prev_hash) in stale_local_ids {
        match state.store.get_draft(&local_id).await? {
            Some(local_draft) => {
                let current_raw = state.load_raw_rfc2822(&local_draft.message).await?;
                if sha256_hex(&current_raw) == prev_hash {
                    let att_ids = state
                        .collect_external_attachment_ids(&local_draft.message.id)
                        .await;
                    if state.store.delete_draft(&local_id).await? {
                        let _ = state
                            .post_delete_message(&local_draft.message.id, &att_ids)
                            .await;
                        report.messages_deleted += 1;
                    }
                    meta.drafts.remove(&local_id);
                }
            }
            None => {
                meta.drafts.remove(&local_id);
            }
        }
    }

    Ok(())
}

enum IncrementalOutcome {
    Applied { new_history_id: String },
    HistoryExpired,
}

#[allow(clippy::too_many_arguments)]
async fn run_incremental(
    client: &Client,
    base: &str,
    user_id: &str,
    auth: &GmailAuth,
    start_history_id: &str,
    label_map: &HashMap<String, String>,
    state: &AppState,
    report: &mut PullReport,
) -> AppResult<IncrementalOutcome> {
    let mut page_token: Option<String> = None;
    let mut latest_history_id: Option<String> = None;
    let mut to_fetch: HashSet<String> = HashSet::new();

    loop {
        let mut url = format!(
            "{base}/gmail/v1/users/{user_id}/history?startHistoryId={}&maxResults=500",
            encode_path_segment(start_history_id)
        );
        if let Some(ref pt) = page_token {
            url.push_str("&pageToken=");
            url.push_str(&encode_path_segment(pt));
        }

        let (status, body) = get_with_retry(client, &url, auth).await?;
        if status == StatusCode::NOT_FOUND {
            return Ok(IncrementalOutcome::HistoryExpired);
        }
        if !status.is_success() {
            return Err(AppError::Upstream {
                status: status.as_u16(),
                message: format!(
                    "Gmail history.list failed: {}",
                    String::from_utf8_lossy(&body)
                ),
            });
        }

        let page: ListHistoryResponse = serde_json::from_slice(&body)?;
        if !page.history_id.is_empty() {
            latest_history_id = Some(page.history_id);
        }

        for record in page.history.unwrap_or_default() {
            for added in record.messages_added.unwrap_or_default() {
                if !added.message.id.is_empty() {
                    to_fetch.insert(added.message.id);
                }
            }
            for deleted in record.messages_deleted.unwrap_or_default() {
                let uid = deleted.message.id;
                if uid.is_empty() {
                    continue;
                }
                to_fetch.remove(&uid);
                let att_ids = match state.store.find_message_by_upstream_id(&uid).await? {
                    Some(existing) => state.collect_external_attachment_ids(&existing.id).await,
                    None => Vec::new(),
                };
                if let Some(removed_msg) = state.store.delete_message_by_upstream_id(&uid).await? {
                    let _ = state.post_delete_message(&removed_msg.id, &att_ids).await;
                    report.messages_deleted += 1;
                    state.events.publish(
                        EventSource::GmailSync,
                        MailEvent::MessageDeleted {
                            message_id: removed_msg.id,
                            thread_id: removed_msg.thread_id,
                            labels: removed_msg.label_ids,
                        },
                    );
                }
            }
            for lbl_add in record.labels_added.unwrap_or_default() {
                let uid = lbl_add.message.id;
                if uid.is_empty() {
                    continue;
                }
                let mapped = map_labels(&lbl_add.label_ids, label_map);
                if let Some(local) = state.store.find_message_by_upstream_id(&uid).await? {
                    if !mapped.is_empty() {
                        let updated = state
                            .store
                            .modify_synced_message_labels(&local.id, &mapped, &[])
                            .await?;
                        report.messages_updated += 1;
                        state.events.publish(
                            EventSource::GmailSync,
                            MailEvent::MessageUpdated {
                                message_id: updated.id,
                                thread_id: updated.thread_id,
                                added_labels: mapped,
                                removed_labels: Vec::new(),
                            },
                        );
                    }
                } else {
                    to_fetch.insert(uid);
                }
            }
            for lbl_rem in record.labels_removed.unwrap_or_default() {
                let uid = lbl_rem.message.id;
                if uid.is_empty() {
                    continue;
                }
                let mapped = map_labels(&lbl_rem.label_ids, label_map);
                if let Some(local) = state.store.find_message_by_upstream_id(&uid).await? {
                    if !mapped.is_empty() {
                        let updated = state
                            .store
                            .modify_synced_message_labels(&local.id, &[], &mapped)
                            .await?;
                        report.messages_updated += 1;
                        state.events.publish(
                            EventSource::GmailSync,
                            MailEvent::MessageUpdated {
                                message_id: updated.id,
                                thread_id: updated.thread_id,
                                added_labels: Vec::new(),
                                removed_labels: mapped,
                            },
                        );
                    }
                } else {
                    to_fetch.insert(uid);
                }
            }
        }

        match page.next_page_token.filter(|s| !s.is_empty()) {
            Some(next) => page_token = Some(next),
            None => break,
        }
    }

    if !to_fetch.is_empty() {
        let ids: Vec<String> = to_fetch.into_iter().collect();
        fetch_and_upsert_messages(client, base, user_id, auth, ids, label_map, state, report)
            .await?;
    }

    Ok(IncrementalOutcome::Applied {
        new_history_id: latest_history_id.unwrap_or_else(|| start_history_id.to_string()),
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_full_backfill(
    client: &Client,
    base: &str,
    user_id: &str,
    auth: &GmailAuth,
    opts: &SyncRunOptions,
    label_map: &HashMap<String, String>,
    state: &AppState,
    report: &mut PullReport,
) -> AppResult<String> {
    // Capture baseline historyId BEFORE listing messages so concurrent changes aren't missed.
    let profile_url = format!("{base}/gmail/v1/users/{user_id}/profile");
    let (status, body) = get_with_retry(client, &profile_url, auth).await?;
    if !status.is_success() {
        return Err(AppError::Upstream {
            status: status.as_u16(),
            message: format!(
                "Gmail profile fetch failed: {}",
                String::from_utf8_lossy(&body)
            ),
        });
    }
    let profile: Profile = serde_json::from_slice(&body)?;
    let baseline_history_id = profile.history_id;

    let max_messages = opts.max_messages.or(state.config.sync_max_messages);
    let query = opts.query.as_deref().or(state.config.sync_query.as_deref());

    let mut page_token: Option<String> = None;
    let mut listed_ids: Vec<String> = Vec::new();

    loop {
        let mut url = format!(
            "{base}/gmail/v1/users/{user_id}/messages?maxResults=500&includeSpamTrash=true"
        );
        if let Some(q) = query
            && !q.trim().is_empty()
        {
            url.push_str("&q=");
            url.push_str(&encode_path_segment(q));
        }
        if let Some(ref pt) = page_token {
            url.push_str("&pageToken=");
            url.push_str(&encode_path_segment(pt));
        }

        let (status, body) = get_with_retry(client, &url, auth).await?;
        if !status.is_success() {
            return Err(AppError::Upstream {
                status: status.as_u16(),
                message: format!(
                    "Gmail messages.list failed: {}",
                    String::from_utf8_lossy(&body)
                ),
            });
        }
        let page: ListMessagesResponse = serde_json::from_slice(&body)?;
        for mref in page.messages.unwrap_or_default() {
            if !mref.id.is_empty() {
                listed_ids.push(mref.id);
                if let Some(cap) = max_messages
                    && listed_ids.len() >= cap
                {
                    break;
                }
            }
        }
        if let Some(cap) = max_messages
            && listed_ids.len() >= cap
        {
            break;
        }
        match page.next_page_token.filter(|s| !s.is_empty()) {
            Some(next) => page_token = Some(next),
            None => break,
        }
    }

    // Skip messages already present locally by upstream_gmail_id.
    let mut missing_ids = Vec::new();
    for id in listed_ids {
        if state
            .store
            .find_message_by_upstream_id(&id)
            .await?
            .is_some()
        {
            report.messages_deduplicated += 1;
        } else {
            missing_ids.push(id);
        }
    }

    info!(
        total_missing = missing_ids.len(),
        deduped = report.messages_deduplicated,
        baseline_history_id,
        "Gmail API backfill fetching messages"
    );

    fetch_and_upsert_messages(
        client,
        base,
        user_id,
        auth,
        missing_ids,
        label_map,
        state,
        report,
    )
    .await?;

    Ok(baseline_history_id)
}

#[allow(clippy::too_many_arguments)]
async fn fetch_and_upsert_messages(
    client: &Client,
    base: &str,
    user_id: &str,
    auth: &GmailAuth,
    ids: Vec<String>,
    label_map: &HashMap<String, String>,
    state: &AppState,
    report: &mut PullReport,
) -> AppResult<()> {
    let fetches = stream::iter(ids.into_iter().map(|id| {
        let client = client.clone();
        let url = format!(
            "{base}/gmail/v1/users/{user_id}/messages/{}?format=raw",
            encode_path_segment(&id)
        );
        let auth = auth.clone();
        async move {
            let res = get_with_retry(&client, &url, &auth).await;
            (id, res)
        }
    }))
    .buffer_unordered(FETCH_CONCURRENCY);

    futures_util::pin_mut!(fetches);

    while let Some((id, res)) = fetches.next().await {
        let (status, body) = res?;
        if status == StatusCode::NOT_FOUND {
            debug!(upstream_id = %id, "Gmail message disappeared (404), skipping");
            continue;
        }
        if !status.is_success() {
            return Err(AppError::Upstream {
                status: status.as_u16(),
                message: format!(
                    "Gmail messages.get({id}) failed: {}",
                    String::from_utf8_lossy(&body)
                ),
            });
        }
        let msg: Message = serde_json::from_slice(&body)?;
        let raw_b64 = msg.raw.unwrap_or_default();
        let raw_bytes = decode_base64_tolerant(&raw_b64)?;
        let internal_date_ms = msg
            .internal_date
            .as_deref()
            .and_then(|s| s.parse::<i64>().ok());
        let mapped_labels = map_labels(msg.label_ids.as_deref().unwrap_or(&[]), label_map);

        let upstream_id = if msg.id.is_empty() { id } else { msg.id };
        let upstream_tid = (!msg.thread_id.is_empty()).then_some(msg.thread_id);

        let input = parse_raw_to_new_message_input(
            raw_bytes,
            mapped_labels,
            internal_date_ms,
            "gmail_api",
            Some(upstream_id),
            upstream_tid,
            false,
            false,
        );

        let _ = ingest_synced_message(state, input, report).await?;
    }

    Ok(())
}

fn map_labels(raw: &[String], label_map: &HashMap<String, String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for id in raw {
        let local = label_map.get(id).cloned().unwrap_or_else(|| id.clone());
        if seen.insert(local.clone()) {
            out.push(local);
        }
    }
    out
}

fn map_local_to_upstream_labels(
    local_ids: &[String],
    reverse_map: &HashMap<String, String>,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for id in local_ids {
        let mapped = if is_system_label(id) {
            Some(id.clone())
        } else {
            reverse_map.get(id).cloned()
        };
        if let Some(up) = mapped {
            if seen.insert(up.clone()) {
                out.push(up);
            }
        } else {
            debug!(local_label_id = %id, "Skipping local-only label during Gmail API pushback");
        }
    }
    out.sort();
    out
}

async fn get_with_retry(
    client: &Client,
    url: &str,
    auth: &GmailAuth,
) -> AppResult<(StatusCode, Vec<u8>)> {
    request_with_retry(client, Method::GET, url, auth, None).await
}

async fn request_with_retry(
    client: &Client,
    method: Method,
    url: &str,
    auth: &GmailAuth,
    json_body: Option<Vec<u8>>,
) -> AppResult<(StatusCode, Vec<u8>)> {
    let mut delay = Duration::from_millis(100);
    let mut refreshed_on_401 = false;
    let mut attempt = 0u8;
    loop {
        let bearer_token = auth.token().await;
        let mut req = client
            .request(method.clone(), url)
            .bearer_auth(&bearer_token);
        if let Some(ref body) = json_body {
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.clone());
        }
        let resp = req.send().await;
        match resp {
            Ok(r) => {
                let status = r.status();
                let bytes = r.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
                if status == StatusCode::UNAUTHORIZED
                    && !refreshed_on_401
                    && auth
                        .refresh_after_401(client, &bearer_token)
                        .await?
                        .is_some()
                {
                    refreshed_on_401 = true;
                    debug!(url = %url, "Refreshed Gmail OAuth2 token after HTTP 401; retrying request");
                    continue;
                }
                let retryable = status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error();
                if retryable && attempt < 2 {
                    attempt += 1;
                    tokio::time::sleep(delay).await;
                    delay *= 3;
                    continue;
                }
                return Ok((status, bytes));
            }
            Err(err) => {
                if attempt < 2 {
                    attempt += 1;
                    tokio::time::sleep(delay).await;
                    delay *= 3;
                    continue;
                }
                return Err(err.into());
            }
        }
    }
}

/// Decode base64url (unpadded or padded) or standard base64 tolerantly.
pub fn decode_base64_tolerant(input: &str) -> AppResult<Vec<u8>> {
    let cleaned: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if cleaned.is_empty() {
        return Ok(Vec::new());
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&cleaned)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&cleaned))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&cleaned))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&cleaned))
        .map_err(|e| AppError::Mime(format!("Invalid base64url message payload: {e}")))
}
