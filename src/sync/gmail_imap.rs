//! Upstream Gmail IMAP [`SyncSource`] (`SyncMode::Imap`) using `async-imap` over `tokio-rustls`
//! (or plain TCP when `gmail_imap_tls == false`), with `X-GM-EXT-1` support, incremental UID
//! checkpointing, and optional bidirectional pushback (`UID STORE`, `UID MOVE`, `EXPUNGE`).

use std::{
    collections::{HashMap, HashSet},
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use async_imap::{
    Session,
    imap_proto::{AttributeValue, Response as ImapResponse, Status as ImapStatus},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::TryStreamExt;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use crate::{
    AppState,
    config::Config,
    ensure_crypto_provider,
    error::{AppError, AppResult},
    imap::mime_fmt::parse_raw_to_new_message_input,
    models::{
        LABEL_DRAFT, LABEL_IMPORTANT, LABEL_INBOX, LABEL_SENT, LABEL_SPAM, LABEL_STARRED,
        LABEL_TRASH, LABEL_UNREAD,
    },
    storage::{NewLabelInput, SyncState},
    sync::{
        LocalMutation, LocalMutationKind, PullReport, PushReport, SyncRunOptions, SyncSource,
        ingest_synced_message,
    },
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

#[derive(Debug, Default)]
struct FetchedImapMessage {
    uid: Option<u32>,
    raw_bytes: Vec<u8>,
    internal_date_ms: Option<i64>,
    is_seen: bool,
    is_flagged: bool,
    is_draft: bool,
    is_answered: bool,
    is_deleted: bool,
    gmail_labels: Option<Vec<String>>,
    gmail_msg_id: Option<u64>,
    gmail_thr_id: Option<u64>,
}

async fn uid_fetch_batch(
    session: &mut Session<UpstreamImapStream>,
    seq_set: &str,
    query: &str,
    command_timeout: Duration,
) -> AppResult<Vec<FetchedImapMessage>> {
    with_imap_timeout(
        command_timeout,
        "IMAP UID FETCH",
        async {
            let cmd_tag = session
                .run_command(&format!("UID FETCH {seq_set} {query}"))
                .await
                .map_err(|e| AppError::Upstream {
                    status: 502,
                    message: format!("IMAP UID FETCH send failed: {e}"),
                })?;

            let mut out = Vec::new();
            while let Some(resp) =
                session
                    .read_response()
                    .await
                    .map_err(|e| AppError::Upstream {
                        status: 502,
                        message: format!("IMAP UID FETCH read error: {e}"),
                    })?
            {
                match resp.parsed() {
                    ImapResponse::Fetch(_, attrs) => {
                        let mut item = FetchedImapMessage::default();
                        for attr in attrs {
                            match attr {
                                AttributeValue::Uid(u) => item.uid = Some(*u),
                                AttributeValue::Flags(raw_flags) => {
                                    for flag in raw_flags {
                                        let f = flag.as_ref();
                                        if f.eq_ignore_ascii_case("\\Seen") {
                                            item.is_seen = true;
                                        } else if f.eq_ignore_ascii_case("\\Flagged") {
                                            item.is_flagged = true;
                                        } else if f.eq_ignore_ascii_case("\\Draft") {
                                            item.is_draft = true;
                                        } else if f.eq_ignore_ascii_case("\\Answered") {
                                            item.is_answered = true;
                                        } else if f.eq_ignore_ascii_case("\\Deleted") {
                                            item.is_deleted = true;
                                        }
                                    }
                                }
                                AttributeValue::InternalDate(dt) => {
                                    item.internal_date_ms = DateTime::parse_from_str(
                                        dt.as_ref(),
                                        "%d-%b-%Y %H:%M:%S %z",
                                    )
                                    .ok()
                                    .map(|d| d.timestamp_millis());
                                }
                                AttributeValue::BodySection {
                                    section: None,
                                    data: Some(body),
                                    ..
                                }
                                | AttributeValue::Rfc822(Some(body)) => {
                                    item.raw_bytes = body.as_ref().to_vec();
                                }
                                AttributeValue::GmailLabels(labels) => {
                                    item.gmail_labels = Some(
                                        labels.iter().map(|s| s.as_ref().to_string()).collect(),
                                    );
                                }
                                AttributeValue::GmailMsgId(id) => item.gmail_msg_id = Some(*id),
                                AttributeValue::GmailThrId(id) => item.gmail_thr_id = Some(*id),
                                _ => {}
                            }
                        }
                        out.push(item);
                    }
                    ImapResponse::Done {
                        tag,
                        status,
                        outcome,
                        ..
                    } if tag == &cmd_tag => {
                        if matches!(status, ImapStatus::Ok) {
                            return Ok(out);
                        }
                        return Err(AppError::Upstream {
                            status: 502,
                            message: format!("IMAP UID FETCH rejected ({status:?}): {outcome:?}"),
                        });
                    }
                    _ => {}
                }
            }

            Err(AppError::Upstream {
                status: 502,
                message: "IMAP connection closed before UID FETCH completion".to_string(),
            })
        },
        |err| err,
    )
    .await
}

/// Default TCP + TLS connect timeout for upstream IMAP sync.
pub const IMAP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default per-command timeout for upstream IMAP sync operations.
pub const IMAP_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum number of UIDs fetched per `UID FETCH` batch to bound peak memory usage.
pub const IMAP_FETCH_BATCH_SIZE: usize = 25;

async fn with_imap_timeout<F, T, E>(
    timeout: Duration,
    op: &str,
    fut: F,
    map_err: impl FnOnce(E) -> AppError,
) -> AppResult<T>
where
    F: Future<Output = Result<T, E>>,
{
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(val)) => Ok(val),
        Ok(Err(err)) => Err(map_err(err)),
        Err(_) => Err(AppError::Upstream {
            status: 504,
            message: format!("{op} timed out after {}ms", timeout.as_millis()),
        }),
    }
}

/// Upstream Gmail IMAP [`SyncSource`] implementation.
#[derive(Debug, Clone, Copy)]
pub struct GmailImapSyncSource {
    connect_timeout: Duration,
    command_timeout: Duration,
}

impl Default for GmailImapSyncSource {
    fn default() -> Self {
        Self {
            connect_timeout: IMAP_CONNECT_TIMEOUT,
            command_timeout: IMAP_COMMAND_TIMEOUT,
        }
    }
}

impl GmailImapSyncSource {
    /// Construct a [`GmailImapSyncSource`] with custom connect and per-command timeouts.
    pub fn with_timeouts(connect_timeout: Duration, command_timeout: Duration) -> Self {
        Self {
            connect_timeout,
            command_timeout,
        }
    }
}

#[async_trait]
impl SyncSource for GmailImapSyncSource {
    fn provider_name(&self) -> &'static str {
        "gmail_imap"
    }

    fn account_key(&self, config: &Config) -> String {
        let user = config
            .gmail_imap_user
            .as_deref()
            .unwrap_or(&config.user_email);
        if config.is_multi_mailbox() {
            format!(
                "gmail_imap:{}:{user}",
                crate::config::normalize_mailbox_id(&config.user_email)
            )
        } else {
            format!("gmail_imap:{user}")
        }
    }

    async fn pull(
        &self,
        state: &AppState,
        sync_state: &mut SyncState,
        opts: &SyncRunOptions,
    ) -> AppResult<PullReport> {
        let connect_timeout = self.connect_timeout;
        let command_timeout = self.command_timeout;
        let mut session =
            connect_imap_session(&state.config, connect_timeout, command_timeout).await?;

        let has_xgm = match tokio::time::timeout(command_timeout, session.capabilities()).await {
            Ok(Ok(caps)) => caps.has_str("X-GM-EXT-1"),
            Ok(Err(err)) => {
                warn!(%err, "Failed to query IMAP capabilities; disabling X-GM-EXT-1");
                false
            }
            Err(_) => {
                return Err(AppError::Upstream {
                    status: 504,
                    message: format!(
                        "IMAP CAPABILITY timed out after {}ms",
                        command_timeout.as_millis()
                    ),
                });
            }
        };

        let (selected_mailbox, mailbox) = select_imap_mailbox(
            &mut session,
            &state.config.gmail_imap_mailbox,
            command_timeout,
        )
        .await?;

        let mut report = PullReport::default();

        let uid_validity = mailbox.uid_validity;
        let uid_validity_changed = sync_state.imap_uid_validity != uid_validity
            || sync_state.imap_mailbox.as_deref() != Some(selected_mailbox.as_str());
        let mut last_uid =
            if opts.full || uid_validity_changed || sync_state.imap_last_uid.is_none() {
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

        if should_fetch {
            let start_uid = last_uid.saturating_add(1);
            let search_query = format!("UID {start_uid}:*");
            let uid_set = with_imap_timeout(
                command_timeout,
                "IMAP UID SEARCH",
                session.uid_search(&search_query),
                |e| AppError::Upstream {
                    status: 502,
                    message: format!("IMAP UID SEARCH failed: {e}"),
                },
            )
            .await?;

            // RFC 3501: `N:*` can include the max UID even when max < N. Filter strictly > last_uid,
            // sort ascending so `last_uid` advances monotonically without skipping out-of-order UIDs,
            // and slice to `max_messages` before fetching any message bodies.
            let mut uids: Vec<u32> = uid_set.into_iter().filter(|&u| u > last_uid).collect();
            uids.sort_unstable();
            if let Some(cap) = max_messages {
                uids.truncate(cap);
            }

            let query = if has_xgm {
                "(UID FLAGS INTERNALDATE BODY.PEEK[] X-GM-MSGID X-GM-THRID X-GM-LABELS)"
            } else {
                "(UID FLAGS INTERNALDATE BODY.PEEK[])"
            };

            info!(
                mailbox = %selected_mailbox,
                uid_count = uids.len(),
                start_uid,
                has_xgm,
                "Fetching upstream IMAP messages in bounded batches"
            );

            for chunk in uids.chunks(IMAP_FETCH_BATCH_SIZE) {
                let seq_set = chunk
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(",");

                let mut fetches =
                    uid_fetch_batch(&mut session, &seq_set, query, command_timeout).await?;

                fetches.sort_by_key(|f| f.uid.unwrap_or(0));

                for fetch in fetches {
                    let Some(uid) = fetch.uid else {
                        continue;
                    };
                    if uid <= last_uid {
                        continue;
                    }

                    let mut label_set: HashSet<String> = HashSet::new();
                    if !fetch.is_seen {
                        label_set.insert(LABEL_UNREAD.to_string());
                    }
                    if fetch.is_flagged {
                        label_set.insert(LABEL_STARRED.to_string());
                    }
                    if fetch.is_draft {
                        label_set.insert(LABEL_DRAFT.to_string());
                    }

                    if let Some(xgm_labels) = fetch.gmail_labels {
                        for raw_lbl in xgm_labels {
                            let s = raw_lbl.trim();
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
                                    let local_id =
                                        if let Some(existing) = user_label_cache.get(user_name) {
                                            existing.clone()
                                        } else {
                                            let stored = state
                                                .store
                                                .upsert_upstream_label(NewLabelInput {
                                                    name: user_name.to_string(),
                                                    upstream_label_id: Some(format!(
                                                        "imap:{user_name}"
                                                    )),
                                                    ..Default::default()
                                                })
                                                .await?;
                                            report.labels_synced += 1;
                                            user_label_cache
                                                .insert(user_name.to_string(), stored.id.clone());
                                            stored.id
                                        };
                                    label_set.insert(local_id);
                                }
                            }
                        }
                    } else if selected_mailbox.eq_ignore_ascii_case("INBOX") {
                        label_set.insert(LABEL_INBOX.to_string());
                    }

                    let upstream_gmail_id = match fetch.gmail_msg_id {
                        Some(id) => Some(format!("{id:x}")),
                        None => Some(format!(
                            "imap:{}:{}:{uid}",
                            selected_mailbox,
                            uid_validity.unwrap_or(0)
                        )),
                    };
                    let upstream_thread_id = fetch.gmail_thr_id.map(|id| format!("{id:x}"));

                    let input = parse_raw_to_new_message_input(
                        fetch.raw_bytes,
                        label_set.into_iter().collect(),
                        fetch.internal_date_ms,
                        "gmail_imap",
                        upstream_gmail_id,
                        upstream_thread_id,
                        fetch.is_answered,
                        fetch.is_deleted,
                    );

                    let _ = ingest_synced_message(state, input, &mut report).await?;

                    if uid > last_uid {
                        last_uid = uid;
                    }
                }
            }
        }

        let _ = tokio::time::timeout(
            command_timeout.min(Duration::from_secs(5)),
            session.logout(),
        )
        .await;

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

    async fn push_changes(
        &self,
        state: &AppState,
        changes: &[LocalMutation],
    ) -> AppResult<PushReport> {
        if changes.is_empty() {
            return Ok(PushReport::default());
        }

        let connect_timeout = self.connect_timeout;
        let command_timeout = self.command_timeout;
        let mut session =
            connect_imap_session(&state.config, connect_timeout, command_timeout).await?;
        let (has_xgm, has_move, has_uidplus) =
            match tokio::time::timeout(command_timeout, session.capabilities()).await {
                Ok(Ok(caps)) => (
                    caps.has_str("X-GM-EXT-1"),
                    caps.has_str("MOVE"),
                    caps.has_str("UIDPLUS"),
                ),
                Ok(Err(err)) => {
                    warn!(%err, "Failed to query IMAP capabilities during pushback");
                    (false, false, false)
                }
                Err(_) => {
                    return Err(AppError::Upstream {
                        status: 504,
                        message: format!(
                            "IMAP CAPABILITY timed out after {}ms",
                            command_timeout.as_millis()
                        ),
                    });
                }
            };

        let preferred_mailbox = state
            .store
            .get_sync_state(&self.account_key(&state.config))
            .await?
            .and_then(|s| s.imap_mailbox)
            .unwrap_or_else(|| state.config.gmail_imap_mailbox.clone());

        let (selected_mailbox, mailbox) =
            select_imap_mailbox(&mut session, &preferred_mailbox, command_timeout).await?;
        let selected_uid_validity = mailbox.uid_validity.unwrap_or(0);

        let mut pushed = 0u64;

        for mutation in changes {
            let Some(uid) = resolve_imap_uid(
                &mut session,
                mutation,
                &selected_mailbox,
                selected_uid_validity,
                has_xgm,
                command_timeout,
            )
            .await?
            else {
                warn!(
                    upstream_id = %mutation.upstream_id,
                    mailbox = %selected_mailbox,
                    "Skipping upstream IMAP pushback: message UID not found"
                );
                continue;
            };

            let uid_str = uid.to_string();
            let mut performed_op = false;

            match &mutation.kind {
                LocalMutationKind::ModifyLabels {
                    add_labels,
                    remove_labels,
                } => {
                    performed_op |= apply_imap_flag_deltas(
                        &mut session,
                        &uid_str,
                        add_labels,
                        remove_labels,
                        command_timeout,
                    )
                    .await?;

                    // When operating directly on INBOX, removing INBOX archives the message to All Mail.
                    if remove_labels.iter().any(|l| l == LABEL_INBOX)
                        && selected_mailbox.eq_ignore_ascii_case("INBOX")
                        && has_move
                    {
                        match tokio::time::timeout(
                            command_timeout,
                            session.uid_mv(&uid_str, "[Gmail]/All Mail"),
                        )
                        .await
                        {
                            Ok(Ok(_)) => performed_op = true,
                            Ok(Err(err)) => {
                                debug!(%err, uid, "IMAP archive move to [Gmail]/All Mail skipped");
                            }
                            Err(_) => {
                                return Err(AppError::Upstream {
                                    status: 504,
                                    message: format!(
                                        "IMAP UID MOVE timed out after {}ms",
                                        command_timeout.as_millis()
                                    ),
                                });
                            }
                        }
                    }
                }
                LocalMutationKind::Trash {
                    add_labels,
                    remove_labels,
                } => {
                    let _ = apply_imap_flag_deltas(
                        &mut session,
                        &uid_str,
                        add_labels,
                        remove_labels,
                        command_timeout,
                    )
                    .await?;

                    if !selected_mailbox.eq_ignore_ascii_case("[Gmail]/Trash")
                        && !selected_mailbox.eq_ignore_ascii_case("Trash")
                    {
                        if has_move {
                            let moved_gmail = match tokio::time::timeout(
                                command_timeout,
                                session.uid_mv(&uid_str, "[Gmail]/Trash"),
                            )
                            .await
                            {
                                Ok(Ok(_)) => true,
                                Ok(Err(_)) => false,
                                Err(_) => {
                                    return Err(AppError::Upstream {
                                        status: 504,
                                        message: format!(
                                            "IMAP UID MOVE to Trash timed out after {}ms",
                                            command_timeout.as_millis()
                                        ),
                                    });
                                }
                            };
                            let moved = if moved_gmail {
                                true
                            } else {
                                match tokio::time::timeout(
                                    command_timeout,
                                    session.uid_mv(&uid_str, "Trash"),
                                )
                                .await
                                {
                                    Ok(Ok(_)) => true,
                                    Ok(Err(_)) => false,
                                    Err(_) => {
                                        return Err(AppError::Upstream {
                                            status: 504,
                                            message: format!(
                                                "IMAP UID MOVE to Trash timed out after {}ms",
                                                command_timeout.as_millis()
                                            ),
                                        });
                                    }
                                }
                            };
                            if !moved {
                                mark_deleted_and_expunge(
                                    &mut session,
                                    &uid_str,
                                    has_uidplus,
                                    command_timeout,
                                )
                                .await?;
                            }
                        } else {
                            mark_deleted_and_expunge(
                                &mut session,
                                &uid_str,
                                has_uidplus,
                                command_timeout,
                            )
                            .await?;
                        }
                    }
                    performed_op = true;
                }
                LocalMutationKind::Delete => {
                    mark_deleted_and_expunge(&mut session, &uid_str, has_uidplus, command_timeout)
                        .await?;
                    performed_op = true;
                }
            }

            if performed_op {
                pushed += 1;
            }
        }

        let _ = tokio::time::timeout(
            command_timeout.min(Duration::from_secs(5)),
            session.logout(),
        )
        .await;
        Ok(PushReport {
            messages_pushed: pushed,
        })
    }
}

async fn connect_imap_session(
    config: &Config,
    connect_timeout: Duration,
    command_timeout: Duration,
) -> AppResult<Session<UpstreamImapStream>> {
    ensure_crypto_provider();

    let user = config
        .gmail_imap_user
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Config("Gmail IMAP sync requires gmail_imap_user".to_string()))?;
    let pass = config
        .gmail_imap_password
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::Config("Gmail IMAP sync requires gmail_imap_password".to_string())
        })?;

    let host = &config.gmail_imap_host;
    let port = config.gmail_imap_port;
    let tcp = with_imap_timeout(
        connect_timeout,
        "IMAP TCP connect",
        TcpStream::connect((host.as_str(), port)),
        |e| AppError::Upstream {
            status: 502,
            message: format!("Failed to connect to IMAP server {host}:{port}: {e}"),
        },
    )
    .await?;

    let stream = if config.gmail_imap_tls {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_cfg = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(tls_cfg));
        let server_name = ServerName::try_from(host.clone())
            .map_err(|e| AppError::Config(format!("Invalid IMAP TLS hostname '{host}': {e}")))?;
        let tls = with_imap_timeout(
            connect_timeout,
            "IMAP TLS handshake",
            connector.connect(server_name, tcp),
            |e| AppError::Upstream {
                status: 502,
                message: format!("IMAP TLS handshake failed with {host}:{port}: {e}"),
            },
        )
        .await?;
        UpstreamImapStream::Tls(Box::new(tls))
    } else {
        UpstreamImapStream::Plain(tcp)
    };

    let mut client = async_imap::Client::new(stream);
    with_imap_timeout(
        command_timeout,
        "IMAP greeting",
        client.read_response(),
        |e| AppError::Upstream {
            status: 502,
            message: format!("Failed reading IMAP greeting: {e}"),
        },
    )
    .await?;

    with_imap_timeout(
        command_timeout,
        "IMAP LOGIN",
        client.login(user, pass),
        |(err, _)| AppError::Unauthorized(format!("IMAP login failed: {err}")),
    )
    .await
}

async fn select_imap_mailbox(
    session: &mut Session<UpstreamImapStream>,
    configured_mbx: &str,
    command_timeout: Duration,
) -> AppResult<(String, async_imap::types::Mailbox)> {
    match tokio::time::timeout(command_timeout, session.select(configured_mbx)).await {
        Ok(Ok(mbx)) => Ok((configured_mbx.to_string(), mbx)),
        Ok(Err(err)) => {
            warn!(
                mailbox = %configured_mbx,
                %err,
                "Failed to select configured IMAP mailbox; falling back to INBOX"
            );
            let mbx = with_imap_timeout(
                command_timeout,
                "IMAP SELECT INBOX",
                session.select("INBOX"),
                |e| AppError::Upstream {
                    status: 502,
                    message: format!("Failed to select INBOX: {e}"),
                },
            )
            .await?;
            Ok(("INBOX".to_string(), mbx))
        }
        Err(_) => Err(AppError::Upstream {
            status: 504,
            message: format!(
                "IMAP SELECT timed out after {}ms",
                command_timeout.as_millis()
            ),
        }),
    }
}

async fn resolve_imap_uid(
    session: &mut Session<UpstreamImapStream>,
    mutation: &LocalMutation,
    selected_mailbox: &str,
    selected_uid_validity: u32,
    has_xgm: bool,
    command_timeout: Duration,
) -> AppResult<Option<u32>> {
    // 1. Direct fallback format `imap:<mailbox>:<uidvalidity>:<uid>`.
    if let Some(rest) = mutation.upstream_id.strip_prefix("imap:")
        && let Some((prefix, uid_s)) = rest.rsplit_once(':')
        && let Some((mbx, uv_s)) = prefix.rsplit_once(':')
        && mbx == selected_mailbox
        && let (Ok(uv), Ok(uid)) = (uv_s.parse::<u32>(), uid_s.parse::<u32>())
        && (selected_uid_validity == 0 || uv == selected_uid_validity)
    {
        return Ok(Some(uid));
    }

    // 2. Gmail `X-GM-MSGID` search (hex upstream_id -> decimal u64).
    if has_xgm
        && let Ok(xgm_id) = u64::from_str_radix(mutation.upstream_id.trim(), 16)
        && xgm_id > 0
    {
        match tokio::time::timeout(
            command_timeout,
            session.uid_search(format!("X-GM-MSGID {xgm_id}")),
        )
        .await
        {
            Ok(Ok(uids)) => {
                if let Some(&uid) = uids.iter().min() {
                    return Ok(Some(uid));
                }
            }
            Ok(Err(err)) => {
                debug!(%err, xgm_id, "IMAP X-GM-MSGID search failed");
            }
            Err(_) => {
                return Err(AppError::Upstream {
                    status: 504,
                    message: format!(
                        "IMAP X-GM-MSGID search timed out after {}ms",
                        command_timeout.as_millis()
                    ),
                });
            }
        }
    }

    // 3. RFC 2822 Message-ID header search fallback.
    if let Some(ref mid) = mutation.rfc822_message_id {
        let safe_mid = mid.replace(['"', '\\', '\r', '\n'], "");
        if !safe_mid.is_empty() {
            match tokio::time::timeout(
                command_timeout,
                session.uid_search(format!("HEADER Message-ID \"{safe_mid}\"")),
            )
            .await
            {
                Ok(Ok(uids)) => {
                    if let Some(&uid) = uids.iter().min() {
                        return Ok(Some(uid));
                    }
                }
                Ok(Err(err)) => {
                    debug!(%err, message_id = %safe_mid, "IMAP HEADER Message-ID search failed");
                }
                Err(_) => {
                    return Err(AppError::Upstream {
                        status: 504,
                        message: format!(
                            "IMAP HEADER Message-ID search timed out after {}ms",
                            command_timeout.as_millis()
                        ),
                    });
                }
            }
        }
    }

    Ok(None)
}

async fn apply_imap_flag_deltas(
    session: &mut Session<UpstreamImapStream>,
    uid_str: &str,
    add_labels: &[String],
    remove_labels: &[String],
    command_timeout: Duration,
) -> AppResult<bool> {
    let mut add_flags: Vec<&'static str> = Vec::new();
    let mut remove_flags: Vec<&'static str> = Vec::new();

    if remove_labels.iter().any(|l| l == LABEL_UNREAD) {
        add_flags.push("\\Seen");
    }
    if add_labels.iter().any(|l| l == LABEL_UNREAD) {
        remove_flags.push("\\Seen");
    }
    if add_labels.iter().any(|l| l == LABEL_STARRED) {
        add_flags.push("\\Flagged");
    }
    if remove_labels.iter().any(|l| l == LABEL_STARRED) {
        remove_flags.push("\\Flagged");
    }
    if add_labels.iter().any(|l| l == LABEL_DRAFT) {
        add_flags.push("\\Draft");
    }
    if remove_labels.iter().any(|l| l == LABEL_DRAFT) {
        remove_flags.push("\\Draft");
    }

    let mut did_store = false;
    if !add_flags.is_empty() {
        let query = format!("+FLAGS ({})", add_flags.join(" "));
        let _: Vec<_> = with_imap_timeout(
            command_timeout,
            "IMAP UID STORE +FLAGS",
            async {
                let stream = session.uid_store(uid_str, query).await?;
                stream.try_collect().await
            },
            |e| AppError::Upstream {
                status: 502,
                message: format!("IMAP UID STORE +FLAGS failed: {e}"),
            },
        )
        .await?;
        did_store = true;
    }

    if !remove_flags.is_empty() {
        let query = format!("-FLAGS ({})", remove_flags.join(" "));
        let _: Vec<_> = with_imap_timeout(
            command_timeout,
            "IMAP UID STORE -FLAGS",
            async {
                let stream = session.uid_store(uid_str, query).await?;
                stream.try_collect().await
            },
            |e| AppError::Upstream {
                status: 502,
                message: format!("IMAP UID STORE -FLAGS failed: {e}"),
            },
        )
        .await?;
        did_store = true;
    }

    Ok(did_store)
}

async fn mark_deleted_and_expunge(
    session: &mut Session<UpstreamImapStream>,
    uid_str: &str,
    has_uidplus: bool,
    command_timeout: Duration,
) -> AppResult<()> {
    let _: Vec<_> = with_imap_timeout(
        command_timeout,
        "IMAP UID STORE (\\Deleted)",
        async {
            let stream = session.uid_store(uid_str, "+FLAGS (\\Deleted)").await?;
            stream.try_collect().await
        },
        |e| AppError::Upstream {
            status: 502,
            message: format!("IMAP UID STORE +FLAGS (\\Deleted) failed: {e}"),
        },
    )
    .await?;

    if has_uidplus {
        let _: Vec<_> = with_imap_timeout(
            command_timeout,
            "IMAP UID EXPUNGE",
            async {
                let exp = session.uid_expunge(uid_str).await?;
                exp.try_collect().await
            },
            |e| AppError::Upstream {
                status: 502,
                message: format!("IMAP UID EXPUNGE failed: {e}"),
            },
        )
        .await?;
    } else {
        let _: Vec<_> = with_imap_timeout(
            command_timeout,
            "IMAP EXPUNGE",
            async {
                let exp = session.expunge().await?;
                exp.try_collect().await
            },
            |e| AppError::Upstream {
                status: 502,
                message: format!("IMAP EXPUNGE failed: {e}"),
            },
        )
        .await?;
    }

    Ok(())
}
