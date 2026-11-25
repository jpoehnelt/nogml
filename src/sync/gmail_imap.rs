//! Upstream Gmail IMAP sync (`SyncMode::Imap`) using `async-imap` over `tokio-rustls`
//! (or plain TCP when `gmail_imap_tls == false`), with `X-GM-EXT-1` support and
//! incremental UID checkpointing.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_imap::types::Flag;
use chrono::Utc;
use futures_util::TryStreamExt;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use tracing::{info, warn};

use crate::{
    AppState, ensure_crypto_provider,
    error::{AppError, AppResult},
    events::{EventSource, MailEvent},
    imap::mime_fmt::parse_raw_to_new_message_input,
    models::{
        LABEL_DRAFT, LABEL_IMPORTANT, LABEL_INBOX, LABEL_SENT, LABEL_SPAM, LABEL_STARRED,
        LABEL_TRASH, LABEL_UNREAD,
    },
    storage::{NewLabelInput, SyncState, UpsertOutcomeKind},
    sync::{SyncRunOptions, SyncRunReport},
};

enum UpstreamImapStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl fmt::Debug for UpstreamImapStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(_) => f.write_str("UpstreamImapStream::Plain"),
            Self::Tls(_) => f.write_str("UpstreamImapStream::Tls"),
        }
    }
}

impl AsyncRead for UpstreamImapStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamImapStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Run one upstream Gmail IMAP sync pass (incremental via `UID > imap_last_uid`, or full on UIDVALIDITY change / `opts.full`).
pub async fn sync_gmail_imap(
    state: &AppState,
    opts: &SyncRunOptions,
    sync_state: &mut SyncState,
) -> AppResult<SyncRunReport> {
    ensure_crypto_provider();

    let user = state
        .config
        .gmail_imap_user
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::Config("Gmail IMAP sync requires gmail_imap_user".to_string())
        })?;
    let pass = state
        .config
        .gmail_imap_password
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::Config("Gmail IMAP sync requires gmail_imap_password".to_string())
        })?;

    let host = &state.config.gmail_imap_host;
    let port = state.config.gmail_imap_port;
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| AppError::Upstream {
            status: 502,
            message: format!("Failed to connect to IMAP server {host}:{port}: {e}"),
        })?;

    let stream = if state.config.gmail_imap_tls {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_cfg = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(tls_cfg));
        let server_name = ServerName::try_from(host.clone()).map_err(|e| {
            AppError::Config(format!("Invalid IMAP TLS hostname '{host}': {e}"))
        })?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| AppError::Upstream {
                status: 502,
                message: format!("IMAP TLS handshake failed with {host}:{port}: {e}"),
            })?;
        UpstreamImapStream::Tls(Box::new(tls))
    } else {
        UpstreamImapStream::Plain(tcp)
    };

    let mut client = async_imap::Client::new(stream);
    // Consume initial server greeting.
    client
        .read_response()
        .await
        .map_err(|e| AppError::Upstream {
            status: 502,
            message: format!("Failed reading IMAP greeting: {e}"),
        })?;

    let mut session = client
        .login(user, pass)
        .await
        .map_err(|(err, _)| AppError::Unauthorized(format!("IMAP login failed: {err}")))?;

    let has_xgm = match session.capabilities().await {
        Ok(caps) => caps.has_str("X-GM-EXT-1"),
        Err(err) => {
            warn!(%err, "Failed to query IMAP capabilities; disabling X-GM-EXT-1");
            false
        }
    };

    let configured_mbx = state.config.gmail_imap_mailbox.clone();
    let (selected_mailbox, mailbox) = match session.select(&configured_mbx).await {
        Ok(mbx) => (configured_mbx, mbx),
        Err(err) => {
            warn!(
                mailbox = %configured_mbx,
                %err,
                "Failed to select configured IMAP mailbox; falling back to INBOX"
            );
            let mbx = session
                .select("INBOX")
                .await
                .map_err(|e| AppError::Upstream {
                    status: 502,
                    message: format!("Failed to select INBOX: {e}"),
                })?;
            ("INBOX".to_string(), mbx)
        }
    };

    let mut report = SyncRunReport {
        provider: "gmail_imap".to_string(),
        ..Default::default()
    };

    let uid_validity = mailbox.uid_validity;
    let uid_validity_changed = sync_state.imap_uid_validity != uid_validity
        || sync_state.imap_mailbox.as_deref() != Some(selected_mailbox.as_str());
    let mut last_uid = if opts.full || uid_validity_changed || sync_state.imap_last_uid.is_none() {
        report.full_resync = true;
        0u32
    } else {
        sync_state.imap_last_uid.unwrap_or(0)
    };

    let mut user_label_cache: HashMap<String, String> = HashMap::new();
    for lbl in state.store.list_labels().await? {
        if lbl.label_type == "user" {
            user_label_cache.insert(lbl.name.clone(), lbl.id.clone());
        }
    }

    let should_fetch = mailbox.exists > 0
        && mailbox
            .uid_next
            .is_none_or(|uid_next| uid_next > last_uid.saturating_add(1));

    let max_messages = opts.max_messages.or(state.config.sync_max_messages);
    let mut fetched_count = 0usize;

    if should_fetch {
        let uid_range = format!("{}:*", last_uid.saturating_add(1));
        let query = if has_xgm {
            "(UID FLAGS INTERNALDATE BODY.PEEK[] X-GM-MSGID X-GM-THRID X-GM-LABELS)"
        } else {
            "(UID FLAGS INTERNALDATE BODY.PEEK[])"
        };

        info!(
            mailbox = %selected_mailbox,
            uid_range = %uid_range,
            has_xgm,
            "Fetching upstream IMAP messages"
        );

        let fetches_stream = session
            .uid_fetch(&uid_range, query)
            .await
            .map_err(|e| AppError::Upstream {
                status: 502,
                message: format!("IMAP UID FETCH failed: {e}"),
            })?;
        let fetches: Vec<_> = fetches_stream
            .try_collect()
            .await
            .map_err(|e| AppError::Upstream {
                status: 502,
                message: format!("IMAP UID FETCH stream error: {e}"),
            })?;

        for fetch in fetches {
            let Some(uid) = fetch.uid else {
                continue;
            };
            // RFC 3501: `N:*` returns the max UID even when max < N. Skip already-synced UIDs.
            if uid <= last_uid {
                continue;
            }
            if let Some(cap) = max_messages
                && fetched_count >= cap
            {
                break;
            }

            let raw_bytes = fetch.body().unwrap_or_default().to_vec();
            let internal_date_ms = fetch.internal_date().map(|dt| dt.timestamp_millis());

            let mut is_seen = false;
            let mut is_flagged = false;
            let mut is_draft = false;
            let mut is_answered = false;
            let mut is_deleted = false;
            for flag in fetch.flags() {
                match flag {
                    Flag::Seen => is_seen = true,
                    Flag::Flagged => is_flagged = true,
                    Flag::Draft => is_draft = true,
                    Flag::Answered => is_answered = true,
                    Flag::Deleted => is_deleted = true,
                    _ => {}
                }
            }

            let mut label_set: HashSet<String> = HashSet::new();
            if !is_seen {
                label_set.insert(LABEL_UNREAD.to_string());
            }
            if is_flagged {
                label_set.insert(LABEL_STARRED.to_string());
            }
            if is_draft {
                label_set.insert(LABEL_DRAFT.to_string());
            }

            if let Some(xgm_labels) = fetch.gmail_labels() {
                for raw_lbl in xgm_labels {
                    let s = raw_lbl.as_ref().trim();
                    if s.is_empty() {
                        continue;
                    }
                    match s {
                        "\\Inbox" => {
                            label_set.insert(LABEL_INBOX.to_string());
                        }
                        "\\Sent" => {
                            label_set.insert(LABEL_SENT.to_string());
                        }
                        "\\Draft" | "\\Drafts" => {
                            label_set.insert(LABEL_DRAFT.to_string());
                        }
                        "\\Trash" => {
                            label_set.insert(LABEL_TRASH.to_string());
                        }
                        "\\Junk" | "\\Spam" => {
                            label_set.insert(LABEL_SPAM.to_string());
                        }
                        "\\Important" => {
                            label_set.insert(LABEL_IMPORTANT.to_string());
                        }
                        "\\Starred" => {
                            label_set.insert(LABEL_STARRED.to_string());
                        }
                        "\\All" | "\\AllMail" => {}
                        other if other.starts_with('\\') => {}
                        user_name => {
                            let local_id = if let Some(existing) = user_label_cache.get(user_name) {
                                existing.clone()
                            } else {
                                let stored = state
                                    .store
                                    .upsert_upstream_label(NewLabelInput {
                                        name: user_name.to_string(),
                                        upstream_label_id: Some(format!("imap:{user_name}")),
                                        ..Default::default()
                                    })
                                    .await?;
                                report.labels_synced += 1;
                                user_label_cache.insert(user_name.to_string(), stored.id.clone());
                                stored.id
                            };
                            label_set.insert(local_id);
                        }
                    }
                }
            } else if selected_mailbox.eq_ignore_ascii_case("INBOX") {
                label_set.insert(LABEL_INBOX.to_string());
            }

            let upstream_gmail_id = match fetch.gmail_msg_id() {
                Some(&id) => Some(format!("{id:x}")),
                None => Some(format!(
                    "imap:{}:{}:{uid}",
                    selected_mailbox,
                    uid_validity.unwrap_or(0)
                )),
            };

            let mut input = parse_raw_to_new_message_input(
                raw_bytes,
                label_set.into_iter().collect(),
                internal_date_ms,
                "gmail_imap",
                upstream_gmail_id,
                None,
                is_answered,
                is_deleted,
            );

            if !crate::sync::apply_sync_inbound_filter(state, &mut input).await? {
                if uid > last_uid {
                    last_uid = uid;
                }
                fetched_count += 1;
                continue;
            }

            let outcome = state.store.upsert_synced_message(input).await?;
            match outcome.kind {
                UpsertOutcomeKind::Inserted => {
                    let _ = state.post_store_message(&outcome.message).await;
                    report.messages_added += 1;
                    state.events.publish(
                        EventSource::GmailSync,
                        MailEvent::MessageReceived {
                            message_id: outcome.message.id,
                            thread_id: outcome.message.thread_id,
                            from: outcome.message.from_addr,
                            subject: outcome.message.subject,
                            snippet: outcome.message.snippet,
                            labels: outcome.message.label_ids,
                        },
                    );
                }
                UpsertOutcomeKind::Updated => {
                    report.messages_updated += 1;
                }
                UpsertOutcomeKind::Deduplicated => {
                    report.messages_deduplicated += 1;
                }
            }

            if uid > last_uid {
                last_uid = uid;
            }
            fetched_count += 1;
        }
    }

    let _ = session.logout().await;

    sync_state.imap_mailbox = Some(selected_mailbox);
    sync_state.imap_uid_validity = uid_validity;
    sync_state.imap_last_uid = Some(last_uid);
    if report.full_resync {
        sync_state.last_full_sync_at = Some(Utc::now());
    }
    sync_state.messages_synced = sync_state
        .messages_synced
        .saturating_add(report.messages_added);

    Ok(report)
}
