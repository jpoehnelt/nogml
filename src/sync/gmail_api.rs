//! Upstream Gmail REST API v1 [`SyncSource`] (`SyncMode::Api`):
//! - OAuth2 refresh token exchange (with in-memory caching) or static access token
//! - Labels sync (`users.labels.list` -> `MailStore::upsert_upstream_label`)
//! - Full backfill (`profile` -> paginated `messages.list` -> bounded-concurrency `messages.get?format=raw`)
//! - Incremental sync (`history.list` with automatic HTTP 404 fallback to full backfill)
//! - Optional bidirectional pushback (`messages.modify`, `messages.trash`, `messages.delete`)

use std::{
    collections::{HashMap, HashSet},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use base64::Engine as _;
use chrono::Utc;
use futures_util::stream::{self, StreamExt};
use reqwest::{Client, Method, StatusCode};
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::{
    AppState,
    config::Config,
    error::{AppError, AppResult},
    events::{EventSource, MailEvent},
    imap::mime_fmt::parse_raw_to_new_message_input,
    models::{
        ListHistoryResponse, ListLabelsResponse, ListMessagesResponse, Message,
        ModifyMessageRequest, Profile, is_system_label,
    },
    storage::{NewLabelInput, SyncState},
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

#[derive(Debug, Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// Upstream Gmail REST API v1 [`SyncSource`] implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct GmailApiSyncSource;

#[async_trait]
impl SyncSource for GmailApiSyncSource {
    fn provider_name(&self) -> &'static str {
        "gmail_api"
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
        let token = acquire_access_token(&client, &state.config).await?;
        let base = state.config.gmail_api_base_url.trim_end_matches('/');
        let user_id = encode_path_segment(&state.config.gmail_user_id);

        let mut report = PullReport::default();

        // 1. Sync upstream user labels and build upstream_label_id -> local_label_id map.
        let label_map = sync_labels(&client, base, &user_id, &token, state, &mut report).await?;

        // 2. Attempt incremental sync if we have a checkpoint and `full` was not requested.
        let mut need_full = opts.full || sync_state.last_history_id.is_none();
        if !need_full && let Some(start_history_id) = sync_state.last_history_id.clone() {
            match run_incremental(
                &client,
                base,
                &user_id,
                &token,
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
                &token,
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
        if changes.is_empty() {
            return Ok(PushReport::default());
        }

        let client = build_http_client()?;
        let token = acquire_access_token(&client, &state.config).await?;
        let base = state.config.gmail_api_base_url.trim_end_matches('/');
        let user_id = encode_path_segment(&state.config.gmail_user_id);

        // Build local_label_id -> upstream_label_id reverse mapping.
        let mut reverse_labels: HashMap<String, String> = HashMap::new();
        for lbl in state.store.list_labels().await? {
            if is_system_label(&lbl.id) || lbl.label_type == "system" {
                reverse_labels.insert(lbl.id.clone(), lbl.id);
            } else if let Some(up_id) = lbl.upstream_label_id {
                reverse_labels.insert(lbl.id, up_id);
            }
        }

        let mut pushed = 0u64;

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
                        request_with_retry(&client, Method::POST, &url, &token, Some(payload))
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
                            &token,
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
                        request_with_retry(&client, Method::POST, &trash_url, &token, None).await?;
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
                        request_with_retry(&client, Method::DELETE, &delete_url, &token, None)
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
            }
        }

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

fn encode_path_segment(seg: &str) -> String {
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

async fn sync_labels(
    client: &Client,
    base: &str,
    user_id: &str,
    token: &str,
    state: &AppState,
    report: &mut PullReport,
) -> AppResult<HashMap<String, String>> {
    let url = format!("{base}/gmail/v1/users/{user_id}/labels");
    let (status, body) = get_with_retry(client, &url, token).await?;
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
    let mut map = HashMap::new();
    for lbl in resp.labels {
        if is_system_label(&lbl.id) || lbl.label_type.as_deref() == Some("system") {
            map.insert(lbl.id.clone(), lbl.id);
            continue;
        }
        let stored = state
            .store
            .upsert_upstream_label(NewLabelInput {
                name: if lbl.name.is_empty() {
                    lbl.id.clone()
                } else {
                    lbl.name
                },
                message_list_visibility: lbl.message_list_visibility,
                label_list_visibility: lbl.label_list_visibility,
                color: lbl.color,
                upstream_label_id: Some(lbl.id.clone()),
            })
            .await?;
        map.insert(lbl.id, stored.id);
        report.labels_synced += 1;
    }
    Ok(map)
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
    token: &str,
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

        let (status, body) = get_with_retry(client, &url, token).await?;
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
                if let Some(removed_msg) = state.store.delete_message_by_upstream_id(&uid).await? {
                    let _ = state.post_delete_message(&removed_msg.id, &[]).await;
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
                            .modify_message_labels(&local.id, &mapped, &[])
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
                            .modify_message_labels(&local.id, &[], &mapped)
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
        fetch_and_upsert_messages(client, base, user_id, token, ids, label_map, state, report)
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
    token: &str,
    opts: &SyncRunOptions,
    label_map: &HashMap<String, String>,
    state: &AppState,
    report: &mut PullReport,
) -> AppResult<String> {
    // Capture baseline historyId BEFORE listing messages so concurrent changes aren't missed.
    let profile_url = format!("{base}/gmail/v1/users/{user_id}/profile");
    let (status, body) = get_with_retry(client, &profile_url, token).await?;
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

        let (status, body) = get_with_retry(client, &url, token).await?;
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
        token,
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
    token: &str,
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
        let token = token.to_string();
        async move {
            let res = get_with_retry(&client, &url, &token).await;
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
    bearer_token: &str,
) -> AppResult<(StatusCode, Vec<u8>)> {
    request_with_retry(client, Method::GET, url, bearer_token, None).await
}

async fn request_with_retry(
    client: &Client,
    method: Method,
    url: &str,
    bearer_token: &str,
    json_body: Option<Vec<u8>>,
) -> AppResult<(StatusCode, Vec<u8>)> {
    let mut delay = Duration::from_millis(100);
    for attempt in 0..3 {
        let mut req = client
            .request(method.clone(), url)
            .bearer_auth(bearer_token);
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
                let retryable = status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error();
                if retryable && attempt < 2 {
                    tokio::time::sleep(delay).await;
                    delay *= 3;
                    continue;
                }
                return Ok((status, bytes));
            }
            Err(err) => {
                if attempt < 2 {
                    tokio::time::sleep(delay).await;
                    delay *= 3;
                    continue;
                }
                return Err(err.into());
            }
        }
    }
    unreachable!("loop always returns")
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
