//! Optional Gmail `/watch` push webhook forwarding listener.
//!
//! When `Config::watch_webhook_url` is configured and an active [`WatchSubscription`]
//! exists in `MailStore`, listens to [`crate::events::EventBus`] and POSTs Gmail
//! Pub/Sub-style notification payloads (`{emailAddress, historyId}` plus standard
//! base64 `message.data` envelope) whenever a matching mailbox event occurs.

use std::{sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use reqwest::{Client, redirect::Policy};
use serde_json::json;
use tokio::{
    sync::{Semaphore, broadcast::error::RecvError, watch},
    task::JoinSet,
};
use tracing::{debug, info, warn};

use crate::{AppState, events::MailEvent, storage::WatchSubscription};

/// Maximum number of concurrent in-flight Gmail `/watch` push webhook POSTs.
const MAX_IN_FLIGHT_WATCH_WEBHOOKS: usize = 16;

/// Brief grace period for in-flight watch webhook requests during shutdown.
const WATCH_SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);

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

    let client = match Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(Policy::none())
        .no_proxy()
        .build()
    {
        Ok(c) => c,
        Err(err) => {
            warn!(%err, "Failed to construct HTTP client for watch webhook listener");
            return;
        }
    };

    let semaphore = Arc::new(Semaphore::new(MAX_IN_FLIGHT_WATCH_WEBHOOKS));
    let mut in_flight: JoinSet<()> = JoinSet::new();
    let mut rx = state.events.subscribe();
    info!(%webhook_url, "Gmail /watch push webhook listener started");

    loop {
        while in_flight.try_join_next().is_some() {}

        tokio::select! {
            recv = rx.recv() => {
                match recv {
                    Ok(env) => {
                        let mb_state = if env.mailbox_id.is_empty() {
                            state.clone()
                        } else {
                            state.for_mailbox(&env.mailbox_id)
                        };
                        let sub = match mb_state.store.get_watch().await {
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

                        let history_id = match mb_state.store.current_history_id().await {
                            Ok(hid) => hid.to_string(),
                            Err(err) => {
                                warn!(%err, "Failed to read current_history_id for watch webhook");
                                continue;
                            }
                        };

                        let inner = json!({
                            "emailAddress": mb_state.config.user_email,
                            "historyId": history_id,
                        });
                        let encoded_data = general_purpose::STANDARD.encode(inner.to_string().as_bytes());
                        let payload = json!({
                            "emailAddress": mb_state.config.user_email,
                            "historyId": history_id,
                            "topicName": sub.topic_name,
                            "message": {
                                "data": encoded_data,
                                "messageId": env.id.to_string(),
                                "publishTime": env.timestamp.to_rfc3339(),
                            }
                        });

                        let permit = match semaphore.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                warn!(
                                    max_in_flight = MAX_IN_FLIGHT_WATCH_WEBHOOKS,
                                    %history_id,
                                    "Gmail watch webhook concurrency limit reached; dropping notification"
                                );
                                continue;
                            }
                        };

                        let client = client.clone();
                        let webhook_url = webhook_url.clone();
                        in_flight.spawn(async move {
                            let _permit = permit;
                            match client.post(&webhook_url).json(&payload).send().await {
                                Ok(resp) if resp.status().is_success() => {
                                    debug!(
                                        status = %resp.status(),
                                        %history_id,
                                        "Delivered Gmail watch push notification"
                                    );
                                }
                                Ok(resp) => {
                                    warn!(
                                        status = %resp.status(),
                                        %webhook_url,
                                        "Gmail watch webhook returned non-2xx"
                                    );
                                }
                                Err(err) => {
                                    warn!(
                                        %err,
                                        %webhook_url,
                                        "Failed to deliver Gmail watch push notification"
                                    );
                                }
                            }
                        });
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

    if !in_flight.is_empty() {
        let _ = tokio::time::timeout(WATCH_SHUTDOWN_DRAIN_TIMEOUT, async {
            while in_flight.join_next().await.is_some() {}
        })
        .await;
        in_flight.abort_all();
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

    #[tokio::test]
    async fn watch_webhook_listener_dispatches_concurrently_without_following_redirects() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/slow"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(250)))
            .expect(4)
            .mount(&server)
            .await;

        let mut cfg = Config::for_test();
        cfg.watch_webhook_url = Some(format!("{}/slow", server.uri()));
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

        let started = std::time::Instant::now();
        for i in 0..4 {
            state.events.publish(
                EventSource::Api,
                MailEvent::MessageReceived {
                    message_id: format!("m_{i}"),
                    thread_id: format!("t_{i}"),
                    from: "alice@example.com".into(),
                    subject: format!("Hello {i}"),
                    snippet: "hi".into(),
                    labels: vec![LABEL_INBOX.to_string()],
                },
            );
        }

        // Wait enough for 1 concurrent wave (~250ms), well below 4 serial calls (1000ms).
        tokio::time::sleep(Duration::from_millis(450)).await;
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(900),
            "4 concurrent 250ms watch webhooks took too long: {elapsed:?}"
        );
        let _ = tx.send(true);
        handle.await.unwrap();

        // Also confirm redirects are never followed.
        let redirect_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/redirect"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/target", redirect_server.uri())),
            )
            .expect(1)
            .mount(&redirect_server)
            .await;
        Mock::given(path("/target"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&redirect_server)
            .await;

        let mut cfg2 = Config::for_test();
        cfg2.watch_webhook_url = Some(format!("{}/redirect", redirect_server.uri()));
        let store2 = Arc::new(MemoryStore::new(&cfg2.user_email));
        let resend2 = Arc::new(HttpResendClient::from_config(&cfg2));
        let state2 = AppState::with_backends(cfg2, store2.clone(), resend2);
        store2
            .set_watch(WatchSubscription {
                topic_name: "projects/demo/topics/gmail".to_string(),
                label_ids: vec![LABEL_INBOX.to_string()],
                label_filter_behavior: "include".to_string(),
                history_id: 1,
                expiration_ms: Utc::now().timestamp_millis() + 60_000,
            })
            .await
            .unwrap();

        let (tx2, rx2) = watch::channel(false);
        let handle2 = tokio::spawn(run_watch_webhook_listener(state2.clone(), rx2));
        tokio::task::yield_now().await;

        state2.events.publish(
            EventSource::Api,
            MailEvent::MessageReceived {
                message_id: "m_redir".into(),
                thread_id: "t_redir".into(),
                from: "alice@example.com".into(),
                subject: "Redirect test".into(),
                snippet: "hi".into(),
                labels: vec![LABEL_INBOX.to_string()],
            },
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
        let _ = tx2.send(true);
        handle2.await.unwrap();
    }
}
