//! Optional Gmail `/watch` push webhook forwarding listener.
//!
//! When `Config::watch_webhook_url` is configured and an active [`WatchSubscription`]
//! exists in `MailStore`, listens to [`crate::events::EventBus`] and POSTs Gmail
//! Pub/Sub-style notification payloads (`{emailAddress, historyId}` plus standard
//! base64 `message.data` envelope) whenever a matching mailbox event occurs.

use std::time::Duration;

use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use reqwest::Client;
use serde_json::json;
use tokio::sync::{broadcast::error::RecvError, watch};
use tracing::{debug, info, warn};

use crate::{AppState, events::MailEvent, storage::WatchSubscription};

fn event_labels(event: &MailEvent) -> Option<Vec<&str>> {
    match event {
        MailEvent::MessageReceived { labels, .. }
        | MailEvent::MessageSent { labels, .. }
        | MailEvent::MessageDeleted { labels, .. } => {
            Some(labels.iter().map(String::as_str).collect())
        }
        MailEvent::MessageUpdated {
            added_labels,
            removed_labels,
            ..
        } => Some(
            added_labels
                .iter()
                .chain(removed_labels.iter())
                .map(String::as_str)
                .collect(),
        ),
        MailEvent::DraftCreated { .. }
        | MailEvent::DeliveryStatus { .. }
        | MailEvent::SyncCompleted { .. }
        | MailEvent::ApprovalRequested { .. }
        | MailEvent::ApprovalResolved { .. } => None,
    }
}

/// Returns `true` if `event` satisfies the active [`WatchSubscription`]'s expiration and label filter.
pub fn watch_matches_event(sub: &WatchSubscription, event: &MailEvent, now_ms: i64) -> bool {
    if sub.expiration_ms <= now_ms {
        return false;
    }
    let Some(labels) = event_labels(event) else {
        return false;
    };
    if sub.label_ids.is_empty() {
        return true;
    }

    let any_match = labels
        .iter()
        .any(|lbl| sub.label_ids.iter().any(|wl| wl == lbl));
    if sub.label_filter_behavior.eq_ignore_ascii_case("exclude") {
        !any_match
    } else {
        any_match
    }
}

/// Run the background Gmail `/watch` push webhook forwarding loop until `shutdown` signals `true`.
pub async fn run_watch_webhook_listener(state: AppState, mut shutdown: watch::Receiver<bool>) {
    let Some(webhook_url) = state
        .config
        .watch_webhook_url
        .clone()
        .filter(|u| !u.trim().is_empty())
    else {
        return;
    };

    let client = match Client::builder().timeout(Duration::from_secs(10)).build() {
        Ok(c) => c,
        Err(err) => {
            warn!(%err, "Failed to construct HTTP client for watch webhook listener");
            return;
        }
    };

    let mut rx = state.events.subscribe();
    info!(%webhook_url, "Gmail /watch push webhook listener started");

    loop {
        tokio::select! {
            recv = rx.recv() => {
                match recv {
                    Ok(env) => {
                        let sub = match state.store.get_watch().await {
                            Ok(Some(sub)) => sub,
                            Ok(None) => continue,
                            Err(err) => {
                                warn!(%err, "Failed to query active watch subscription");
                                continue;
                            }
                        };

                        let now_ms = Utc::now().timestamp_millis();
                        if !watch_matches_event(&sub, &env.event, now_ms) {
                            continue;
                        }

                        let history_id = match state.store.current_history_id().await {
                            Ok(hid) => hid.to_string(),
                            Err(err) => {
                                warn!(%err, "Failed to read current_history_id for watch webhook");
                                continue;
                            }
                        };

                        let inner = json!({
                            "emailAddress": state.config.user_email,
                            "historyId": history_id,
                        });
                        let encoded_data = general_purpose::STANDARD.encode(inner.to_string().as_bytes());
                        let payload = json!({
                            "emailAddress": state.config.user_email,
                            "historyId": history_id,
                            "topicName": sub.topic_name,
                            "message": {
                                "data": encoded_data,
                                "messageId": env.id.to_string(),
                                "publishTime": env.timestamp.to_rfc3339(),
                            }
                        });

                        match client.post(&webhook_url).json(&payload).send().await {
                            Ok(resp) if resp.status().is_success() => {
                                debug!(status = %resp.status(), %history_id, "Delivered Gmail watch push notification");
                            }
                            Ok(resp) => {
                                warn!(status = %resp.status(), %webhook_url, "Gmail watch webhook returned non-2xx");
                            }
                            Err(err) => {
                                warn!(%err, %webhook_url, "Failed to deliver Gmail watch push notification");
                            }
                        }
                    }
                    Err(RecvError::Lagged(skipped)) => {
                        warn!(skipped, "Gmail watch webhook listener lagged on EventBus");
                    }
                    Err(RecvError::Closed) => break,
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    info!("Gmail /watch push webhook listener shutting down");
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_partial_json, method, path},
    };

    use super::*;
    use crate::{
        config::Config,
        events::EventSource,
        models::{LABEL_INBOX, LABEL_SPAM},
        resend::HttpResendClient,
        storage::{MailStore, MemoryStore},
    };

    #[tokio::test]
    async fn watch_webhook_listener_posts_matching_events_and_respects_filter() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/push"))
            .and(body_partial_json(json!({
                "emailAddress": "agent@example.com",
                "topicName": "projects/demo/topics/gmail"
            })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let mut cfg = Config::for_test();
        cfg.watch_webhook_url = Some(format!("{}/push", server.uri()));
        let store = Arc::new(MemoryStore::new(&cfg.user_email));
        let resend = Arc::new(HttpResendClient::from_config(&cfg));
        let state = AppState::with_backends(cfg, store.clone(), resend);

        store
            .set_watch(WatchSubscription {
                topic_name: "projects/demo/topics/gmail".to_string(),
                label_ids: vec![LABEL_INBOX.to_string()],
                label_filter_behavior: "include".to_string(),
                history_id: 1,
                expiration_ms: Utc::now().timestamp_millis() + 60_000,
            })
            .await
            .unwrap();

        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(run_watch_webhook_listener(state.clone(), rx));
        tokio::task::yield_now().await;

        // Non-matching label should NOT trigger webhook
        state.events.publish(
            EventSource::Api,
            MailEvent::MessageReceived {
                message_id: "m_spam".into(),
                thread_id: "t_spam".into(),
                from: "spammer@evil.test".into(),
                subject: "Spam".into(),
                snippet: "spam".into(),
                labels: vec![LABEL_SPAM.to_string()],
            },
        );

        // Matching INBOX label SHOULD trigger webhook once
        state.events.publish(
            EventSource::Api,
            MailEvent::MessageReceived {
                message_id: "m_inbox".into(),
                thread_id: "t_inbox".into(),
                from: "alice@example.com".into(),
                subject: "Hello".into(),
                snippet: "Hello".into(),
                labels: vec![LABEL_INBOX.to_string()],
            },
        );

        tokio::time::sleep(Duration::from_millis(150)).await;
        let _ = tx.send(true);
        handle.await.unwrap();
        // wiremock Drop asserts expect(1) was satisfied exactly once.
    }
}
