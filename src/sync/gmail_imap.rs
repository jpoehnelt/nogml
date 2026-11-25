//! Upstream Gmail IMAP [`SyncSource`] (`SyncMode::Imap`) using `async-imap` over `tokio-rustls`
//! (or plain TCP when `gmail_imap_tls == false`), with `X-GM-EXT-1` support, incremental UID
//! checkpointing, and optional bidirectional pushback (`UID STORE`, `UID MOVE`, `EXPUNGE`).

use std::{
    collections::{HashMap, HashSet},
    fmt,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_imap::{Session, types::Flag};
use async_trait::async_trait;
use chrono::Utc;
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

/// Upstream Gmail IMAP [`SyncSource`] implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct GmailImapSyncSource;

#[async_trait]
impl SyncSource for GmailImapSyncSource {
    fn provider_name(&self) -> &'static str {
        "gmail_imap"
    }

    fn account_key(&self, config: &Config) -> String {
        format!(
            "gmail_imap:{}",
            config
                .gmail_imap_user
                .as_deref()
                .unwrap_or(&config.user_email)
        )
    }

    async fn pull(
        &self,
        state: &AppState,
        sync_state: &mut SyncState,
        opts: &SyncRunOptions,
    ) -> AppResult<PullReport> {
        let mut session = connect_imap_session(&state.config).await?;

        let has_xgm = match session.capabilities().await {
            Ok(caps) => caps.has_str("X-GM-EXT-1"),
            Err(err) => {
                warn!(%err, "Failed to query IMAP capabilities; disabling X-GM-EXT-1");
                false
            }
        };

        let (selected_mailbox, mailbox) =
            select_imap_mailbox(&mut session, &state.config.gmail_imap_mailbox).await?;

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

            let fetches_stream =
                session
                    .uid_fetch(&uid_range, query)
                    .await
                    .map_err(|e| AppError::Upstream {
                        status: 502,
                        message: format!("IMAP UID FETCH failed: {e}"),
                    })?;
            let fetches: Vec<_> =
                fetches_stream
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
                                let local_id = if let Some(existing) =
                                    user_label_cache.get(user_name)
                                {
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

                let upstream_gmail_id = match fetch.gmail_msg_id() {
                    Some(&id) => Some(format!("{id:x}")),
                    None => Some(format!(
                        "imap:{}:{}:{uid}",
                        selected_mailbox,
                        uid_validity.unwrap_or(0)
                    )),
                };

                let input = parse_raw_to_new_message_input(
                    raw_bytes,
                    label_set.into_iter().collect(),
                    internal_date_ms,
                    "gmail_imap",
                    upstream_gmail_id,
                    None,
                    is_answered,
                    is_deleted,
                );

                let _ = ingest_synced_message(state, input, &mut report).await?;

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

    async fn push_changes(
        &self,
        state: &AppState,
        changes: &[LocalMutation],
    ) -> AppResult<PushReport> {
        if changes.is_empty() {
            return Ok(PushReport::default());
        }

        let mut session = connect_imap_session(&state.config).await?;
        let (has_xgm, has_move, has_uidplus) = match session.capabilities().await {
            Ok(caps) => (
                caps.has_str("X-GM-EXT-1"),
                caps.has_str("MOVE"),
                caps.has_str("UIDPLUS"),
            ),
            Err(err) => {
                warn!(%err, "Failed to query IMAP capabilities during pushback");
                (false, false, false)
            }
        };

        let preferred_mailbox = state
            .store
            .get_sync_state(&self.account_key(&state.config))
            .await?
            .and_then(|s| s.imap_mailbox)
            .unwrap_or_else(|| state.config.gmail_imap_mailbox.clone());

        let (selected_mailbox, mailbox) =
            select_imap_mailbox(&mut session, &preferred_mailbox).await?;
        let selected_uid_validity = mailbox.uid_validity.unwrap_or(0);

        let mut pushed = 0u64;

        for mutation in changes {
            let Some(uid) = resolve_imap_uid(
                &mut session,
                mutation,
                &selected_mailbox,
                selected_uid_validity,
                has_xgm,
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
                    performed_op |=
                        apply_imap_flag_deltas(&mut session, &uid_str, add_labels, remove_labels)
                            .await?;

                    // When operating directly on INBOX, removing INBOX archives the message to All Mail.
                    if remove_labels.iter().any(|l| l == LABEL_INBOX)
                        && selected_mailbox.eq_ignore_ascii_case("INBOX")
                        && has_move
                    {
                        if let Err(err) = session.uid_mv(&uid_str, "[Gmail]/All Mail").await {
                            debug!(%err, uid, "IMAP archive move to [Gmail]/All Mail skipped");
                        } else {
                            performed_op = true;
                        }
                    }
                }
                LocalMutationKind::Trash {
                    add_labels,
                    remove_labels,
                } => {
                    let _ =
                        apply_imap_flag_deltas(&mut session, &uid_str, add_labels, remove_labels)
                            .await?;

                    if !selected_mailbox.eq_ignore_ascii_case("[Gmail]/Trash")
                        && !selected_mailbox.eq_ignore_ascii_case("Trash")
                    {
                        if has_move {
                            let moved = session.uid_mv(&uid_str, "[Gmail]/Trash").await.is_ok()
                                || session.uid_mv(&uid_str, "Trash").await.is_ok();
                            if !moved {
                                mark_deleted_and_expunge(&mut session, &uid_str, has_uidplus)
                                    .await?;
                            }
                        } else {
                            mark_deleted_and_expunge(&mut session, &uid_str, has_uidplus).await?;
                        }
                    }
                    performed_op = true;
                }
                LocalMutationKind::Delete => {
                    mark_deleted_and_expunge(&mut session, &uid_str, has_uidplus).await?;
                    performed_op = true;
                }
            }

            if performed_op {
                pushed += 1;
            }
        }

        let _ = session.logout().await;
        Ok(PushReport {
            messages_pushed: pushed,
        })
    }
}

async fn connect_imap_session(config: &Config) -> AppResult<Session<UpstreamImapStream>> {
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
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| AppError::Upstream {
            status: 502,
            message: format!("Failed to connect to IMAP server {host}:{port}: {e}"),
        })?;

    let stream = if config.gmail_imap_tls {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_cfg = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(tls_cfg));
        let server_name = ServerName::try_from(host.clone())
            .map_err(|e| AppError::Config(format!("Invalid IMAP TLS hostname '{host}': {e}")))?;
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
    client
        .read_response()
        .await
        .map_err(|e| AppError::Upstream {
            status: 502,
            message: format!("Failed reading IMAP greeting: {e}"),
        })?;

    client
        .login(user, pass)
        .await
        .map_err(|(err, _)| AppError::Unauthorized(format!("IMAP login failed: {err}")))
}

async fn select_imap_mailbox(
    session: &mut Session<UpstreamImapStream>,
    configured_mbx: &str,
) -> AppResult<(String, async_imap::types::Mailbox)> {
    match session.select(configured_mbx).await {
        Ok(mbx) => Ok((configured_mbx.to_string(), mbx)),
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
            Ok(("INBOX".to_string(), mbx))
        }
    }
}

async fn resolve_imap_uid(
    session: &mut Session<UpstreamImapStream>,
    mutation: &LocalMutation,
    selected_mailbox: &str,
    selected_uid_validity: u32,
    has_xgm: bool,
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
        match session.uid_search(format!("X-GM-MSGID {xgm_id}")).await {
            Ok(uids) => {
                if let Some(&uid) = uids.iter().min() {
                    return Ok(Some(uid));
                }
            }
            Err(err) => {
                debug!(%err, xgm_id, "IMAP X-GM-MSGID search failed");
            }
        }
    }

    // 3. RFC 2822 Message-ID header search fallback.
    if let Some(ref mid) = mutation.rfc822_message_id {
        let safe_mid = mid.replace(['"', '\\', '\r', '\n'], "");
        if !safe_mid.is_empty() {
            match session
                .uid_search(format!("HEADER Message-ID \"{safe_mid}\""))
                .await
            {
                Ok(uids) => {
                    if let Some(&uid) = uids.iter().min() {
                        return Ok(Some(uid));
                    }
                }
                Err(err) => {
                    debug!(%err, message_id = %safe_mid, "IMAP HEADER Message-ID search failed");
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
        let stream = session
            .uid_store(uid_str, query)
            .await
            .map_err(|e| AppError::Upstream {
                status: 502,
                message: format!("IMAP UID STORE +FLAGS failed: {e}"),
            })?;
        let _: Vec<_> = stream.try_collect().await.map_err(|e| AppError::Upstream {
            status: 502,
            message: format!("IMAP UID STORE +FLAGS stream error: {e}"),
        })?;
        did_store = true;
    }

    if !remove_flags.is_empty() {
        let query = format!("-FLAGS ({})", remove_flags.join(" "));
        let stream = session
            .uid_store(uid_str, query)
            .await
            .map_err(|e| AppError::Upstream {
                status: 502,
                message: format!("IMAP UID STORE -FLAGS failed: {e}"),
            })?;
        let _: Vec<_> = stream.try_collect().await.map_err(|e| AppError::Upstream {
            status: 502,
            message: format!("IMAP UID STORE -FLAGS stream error: {e}"),
        })?;
        did_store = true;
    }

    Ok(did_store)
}

async fn mark_deleted_and_expunge(
    session: &mut Session<UpstreamImapStream>,
    uid_str: &str,
    has_uidplus: bool,
) -> AppResult<()> {
    let stream = session
        .uid_store(uid_str, "+FLAGS (\\Deleted)")
        .await
        .map_err(|e| AppError::Upstream {
            status: 502,
            message: format!("IMAP UID STORE +FLAGS (\\Deleted) failed: {e}"),
        })?;
    let _: Vec<_> = stream.try_collect().await.map_err(|e| AppError::Upstream {
        status: 502,
        message: format!("IMAP UID STORE (\\Deleted) stream error: {e}"),
    })?;

    if has_uidplus {
        let exp = session
            .uid_expunge(uid_str)
            .await
            .map_err(|e| AppError::Upstream {
                status: 502,
                message: format!("IMAP UID EXPUNGE failed: {e}"),
            })?;
        let _: Vec<_> = exp.try_collect().await.map_err(|e| AppError::Upstream {
            status: 502,
            message: format!("IMAP UID EXPUNGE stream error: {e}"),
        })?;
    } else {
        let exp = session.expunge().await.map_err(|e| AppError::Upstream {
            status: 502,
            message: format!("IMAP EXPUNGE failed: {e}"),
        })?;
        let _: Vec<_> = exp.try_collect().await.map_err(|e| AppError::Upstream {
            status: 502,
            message: format!("IMAP EXPUNGE stream error: {e}"),
        })?;
    }

    Ok(())
}
