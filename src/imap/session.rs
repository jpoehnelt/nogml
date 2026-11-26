//! IMAP4rev1 connection session state machine and command handlers.

use std::{
    collections::{HashMap, HashSet},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use base64::Engine as _;
use chrono::{TimeZone, Utc};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf},
    net::TcpStream,
    sync::watch,
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};

use crate::{
    AppState,
    auth::{AuthScope, Principal},
    blob::is_external_blob_store,
    error::{AppError, AppResult},
    events::{EventSource, MailEvent},
    filter::{FilterDecision, InboundMessage, apply_filter_labels},
    imap::{
        mime_fmt::{
            extract_body_section, format_bodystructure, format_envelope, parse_body_section,
            parse_raw_to_new_message_input, split_raw_header_and_body,
        },
        parser::{
            ImapArg, ImapCommand, ReadCommandLimits, ReadCommandOutcome, append_literal,
            format_internal_date, format_sequence_set, imap_quote, imap_string,
            imap_wildcard_match, normalize_mailbox_name, parse_imap_date_time,
            parse_imap_search_date, parse_sequence_set, read_command_with_limits, read_crlf_line,
            read_crlf_line_into, sanitize_imap_text, seq_set_contains,
        },
        sort_thread::{
            SortMessageItem, ThreadAlgorithm, ThreadMessageItem, extract_base_subject,
            extract_base_subject_with_flag, extract_first_mailbox, extract_references_list,
            is_supported_charset, message_sent_date_ms, parse_sort_criteria,
            parse_thread_algorithm, sort_criteria_needs_full_message,
            sort_criteria_needs_raw_rfc2822, sort_messages, thread_ordered_subject,
            thread_references,
        },
    },
    mime::normalize_message_id,
    models::{
        LABEL_DRAFT, LABEL_IMPORTANT, LABEL_INBOX, LABEL_SENT, LABEL_SPAM, LABEL_STARRED,
        LABEL_TRASH, LABEL_UNREAD,
    },
    search::{
        SearchQuery, matches_message as matches_gmail_query, query_uses_filename,
        rewrite_query_labels, try_parse_query as try_parse_gmail_query,
    },
    storage::{
        ImapFlagAction, ImapFlagSet, ImapMailboxInfo, ImapMessageEntry, ImapStoreFlagsOutcome,
        NewLabelInput, StoredMessage, UpdateLabelInput,
    },
};

/// Maximum consecutive authentication failures permitted before closing the connection.
const MAX_FAILED_AUTH_ATTEMPTS: u32 = 5;
/// Maximum recursion depth for `SEARCH` criteria (`List`, `NOT`, `OR`).
const MAX_SEARCH_DEPTH: usize = 32;
/// Pre-authentication command read timeout (60s).
const IMAP_PRE_AUTH_READ_TIMEOUT: Duration = Duration::from_secs(60);
/// Post-authentication command idle timeout (30 min, RFC 3501 §5.4).
const IMAP_AUTH_READ_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Maximum duration of a single `IDLE` command without activity (30 min, RFC 2177).
const IMAP_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Maximum duration allowed for `STARTTLS` handshake negotiation.
const IMAP_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Underlying transport stream for an IMAP client connection (plain TCP or TLS).
pub enum ImapStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

impl ImapStream {
    pub fn is_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }
}

impl AsyncRead for ImapStream {
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

impl AsyncWrite for ImapStream {
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

#[derive(Debug, Clone)]
struct SelectedState {
    mailbox: String,
    read_only: bool,
    snapshot: Vec<ImapMessageEntry>,
}

#[derive(Debug, Clone)]
enum AuthState {
    NotAuthenticated,
    Authenticated,
    Selected(SelectedState),
}

struct ImapSession {
    base_state: AppState,
    state: AppState,
    auth: AuthState,
    principal: Option<Principal>,
    subscribed: HashSet<String>,
    tls_acceptor: Option<TlsAcceptor>,
    /// RFC 7162 `CONDSTORE` enabled for this connection (via `ENABLE` or any CONDSTORE command).
    condstore_enabled: bool,
    /// RFC 7162 `QRESYNC` enabled for this connection (via `ENABLE QRESYNC`).
    qresync_enabled: bool,
    /// Consecutive failed authentication attempts on this connection.
    failed_auth_attempts: u32,
}

/// Drive one client IMAP4rev1 connection to completion or shutdown.
pub async fn handle_connection(
    stream: ImapStream,
    state: AppState,
    tls_acceptor: Option<TlsAcceptor>,
    mut shutdown: watch::Receiver<bool>,
) {
    let _imap_conn_guard = state.metrics.track_imap_connection();
    let mut reader = BufReader::new(stream);
    let mut session = ImapSession {
        base_state: state.clone(),
        state,
        auth: AuthState::NotAuthenticated,
        principal: None,
        subscribed: HashSet::new(),
        tls_acceptor,
        condstore_enabled: false,
        qresync_enabled: false,
        failed_auth_attempts: 0,
    };

    let greeting = format!(
        "* OK [CAPABILITY {}] nogml IMAP4rev1 Service Ready\r\n",
        session.capability_string(reader.get_ref().is_tls())
    );
    if write_flush(&mut reader, greeting.as_bytes()).await.is_err() {
        return;
    }

    loop {
        let cmd_limits = if session.is_authenticated() {
            ReadCommandLimits::authenticated(session.state.config.max_body_bytes)
        } else {
            ReadCommandLimits::pre_auth(session.state.config.max_body_bytes)
        };
        let read_timeout = if session.is_authenticated() {
            IMAP_AUTH_READ_TIMEOUT
        } else {
            IMAP_PRE_AUTH_READ_TIMEOUT
        };

        let cmd_outcome = tokio::select! {
            res = tokio::time::timeout(read_timeout, read_command_with_limits(&mut reader, cmd_limits)) => {
                match res {
                    Ok(outcome) => outcome,
                    Err(_) => {
                        let _ = write_flush(
                            &mut reader,
                            b"* BYE Autologout; idle for too long\r\n",
                        )
                        .await;
                        break;
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    let _ = write_flush(&mut reader, b"* BYE nogml IMAP server shutting down\r\n").await;
                    break;
                }
                continue;
            }
        };

        let cmd = match cmd_outcome {
            Ok(ReadCommandOutcome::Command(c)) => c,
            Ok(ReadCommandOutcome::Empty) => continue,
            Ok(ReadCommandOutcome::Eof) => break,
            Ok(ReadCommandOutcome::LiteralTooLarge { tag, size }) => {
                let t = tag
                    .map(|s| sanitize_imap_text(&s))
                    .unwrap_or_else(|| "*".to_string());
                let resp = format!("{t} NO [TOOBIG] Literal size {size} exceeds limit\r\n");
                if write_flush(&mut reader, resp.as_bytes()).await.is_err() {
                    break;
                }
                continue;
            }
            Ok(ReadCommandOutcome::NonSyncLiteralTooLarge { tag, size }) => {
                let limit = cmd_limits.max_non_sync_literal_bytes;
                let detail = if size > limit {
                    format!("Literal exceeds {limit} bytes")
                } else {
                    format!("Literal size {size} exceeds command limit")
                };
                let resp = if let Some(t) = tag
                    .map(|s| sanitize_imap_text(&s))
                    .filter(|s| !s.is_empty())
                {
                    format!(
                        "{t} NO [TOOBIG] {detail}\r\n* BYE [TOOBIG] Closing connection after oversized non-synchronizing literal\r\n"
                    )
                } else {
                    format!("* BYE [TOOBIG] {detail}\r\n")
                };
                let _ = write_flush(&mut reader, resp.as_bytes()).await;
                break;
            }
            Err(err) => {
                debug!(%err, "IMAP command read/parse error");
                let safe_err = sanitize_imap_text(&err.to_string());
                let resp = format!("* BAD {safe_err}\r\n");
                let _ = write_flush(&mut reader, resp.as_bytes()).await;
                if matches!(err, AppError::PayloadTooLarge(_) | AppError::Internal(_)) {
                    break;
                }
                continue;
            }
        };

        // Special-case STARTTLS because it consumes and upgrades the transport stream.
        if cmd.name == "STARTTLS" {
            if session.is_authenticated() {
                let _ = write_flush(
                    &mut reader,
                    format!(
                        "{} BAD STARTTLS only valid before authentication\r\n",
                        cmd.tag
                    )
                    .as_bytes(),
                )
                .await;
                continue;
            }
            if reader.get_ref().is_tls() {
                let _ = write_flush(
                    &mut reader,
                    format!("{} BAD TLS already active\r\n", cmd.tag).as_bytes(),
                )
                .await;
                continue;
            }
            let Some(acceptor) = session.tls_acceptor.clone() else {
                let _ = write_flush(
                    &mut reader,
                    format!("{} NO STARTTLS not configured\r\n", cmd.tag).as_bytes(),
                )
                .await;
                continue;
            };
            if write_flush(
                &mut reader,
                format!("{} OK Begin TLS negotiation now\r\n", cmd.tag).as_bytes(),
            )
            .await
            .is_err()
            {
                break;
            }
            let inner = reader.into_inner();
            let tcp = match inner {
                ImapStream::Plain(tcp) => tcp,
                ImapStream::Tls(_) => break,
            };
            match tokio::time::timeout(IMAP_TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(tls_stream)) => {
                    reader = BufReader::new(ImapStream::Tls(Box::new(tls_stream)));
                    session.state = session.base_state.clone();
                    session.auth = AuthState::NotAuthenticated;
                    session.principal = None;
                    session.condstore_enabled = false;
                    session.qresync_enabled = false;
                }
                Ok(Err(err)) => {
                    warn!(%err, "IMAP STARTTLS handshake failed");
                    break;
                }
                Err(_) => {
                    warn!("IMAP STARTTLS handshake timed out");
                    break;
                }
            }
            continue;
        }

        // Special-case IDLE because it listens to both EventBus and client DONE line.
        if cmd.name == "IDLE" {
            if !matches!(
                session.auth,
                AuthState::Authenticated | AuthState::Selected(_)
            ) {
                let _ = write_flush(
                    &mut reader,
                    format!("{} NO Authenticate first\r\n", cmd.tag).as_bytes(),
                )
                .await;
                continue;
            }
            if !session.has_scope(AuthScope::Read) {
                let _ = write_flush(
                    &mut reader,
                    format!(
                        "{} NO [NOPERM] Insufficient scope: read scope required\r\n",
                        cmd.tag
                    )
                    .as_bytes(),
                )
                .await;
                continue;
            }
            match session
                .handle_idle(&cmd.tag, &mut reader, &mut shutdown)
                .await
            {
                Ok(true) => continue,
                Ok(false) | Err(_) => break,
            }
        }

        match session.dispatch(cmd, &mut reader).await {
            Ok(true) => {}
            Ok(false) => break, // LOGOUT
            Err(err) => {
                debug!(%err, "IMAP session error");
                break;
            }
        }
    }
}

impl ImapSession {
    fn capability_string(&self, is_tls: bool) -> String {
        let mut caps = vec!["IMAP4rev1"];
        match self.auth {
            AuthState::NotAuthenticated => {
                if !is_tls && self.tls_acceptor.is_some() {
                    caps.push("STARTTLS");
                    caps.push("LOGINDISABLED");
                } else {
                    caps.push("AUTH=PLAIN");
                    caps.push("AUTH=XOAUTH2");
                    caps.push("SASL-IR");
                }
            }
            AuthState::Authenticated | AuthState::Selected(_) => {
                caps.extend_from_slice(&["SASL-IR", "ENABLE", "CONDSTORE", "QRESYNC"]);
            }
        }
        caps.extend_from_slice(&[
            "LITERAL-",
            "IDLE",
            "MOVE",
            "UIDPLUS",
            "UNSELECT",
            "SPECIAL-USE",
            "LIST-EXTENDED",
            "LIST-STATUS",
            "NAMESPACE",
            "ID",
            "SORT",
            "THREAD=REFERENCES",
            "THREAD=ORDEREDSUBJECT",
            "ESEARCH",
            "X-GM-EXT-1",
        ]);
        caps.join(" ")
    }

    /// Returns `Ok(true)` to keep the connection open, `Ok(false)` to close (`LOGOUT`).
    async fn dispatch(
        &mut self,
        cmd: ImapCommand,
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<bool> {
        let tag = cmd.tag.clone();
        let name = cmd.name.as_str();

        match name {
            "CAPABILITY" => {
                let cap = self.capability_string(stream.get_ref().is_tls());
                let resp = format!("* CAPABILITY {cap}\r\n{tag} OK CAPABILITY completed\r\n");
                write_flush(stream, resp.as_bytes()).await?;
                Ok(true)
            }
            "NOOP" => {
                self.flush_selected_updates(stream).await?;
                write_flush(stream, format!("{tag} OK NOOP completed\r\n").as_bytes()).await?;
                Ok(true)
            }
            "LOGOUT" => {
                let resp = format!(
                    "* BYE nogml IMAP4rev1 Server logging out\r\n{tag} OK LOGOUT completed\r\n"
                );
                write_flush(stream, resp.as_bytes()).await?;
                Ok(false)
            }
            "ID" => {
                let resp = format!(
                    "* ID (\"name\" \"nogml\" \"version\" \"0.1.0\")\r\n{tag} OK ID completed\r\n"
                );
                write_flush(stream, resp.as_bytes()).await?;
                Ok(true)
            }
            "LOGIN" => self.handle_login(&tag, &cmd.args, stream).await,
            "AUTHENTICATE" => self.handle_authenticate(&tag, &cmd.args, stream).await,
            "ENABLE" => {
                self.handle_enable(&tag, &cmd.args, stream).await?;
                Ok(true)
            }
            "NAMESPACE" => {
                if !self.is_authenticated() {
                    write_flush(
                        stream,
                        format!("{tag} NO Authenticate first\r\n").as_bytes(),
                    )
                    .await?;
                    return Ok(true);
                }
                if !self
                    .require_scope_or_no(&tag, AuthScope::Read, stream)
                    .await?
                {
                    return Ok(true);
                }
                let resp = format!(
                    "* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n{tag} OK NAMESPACE completed\r\n"
                );
                write_flush(stream, resp.as_bytes()).await?;
                Ok(true)
            }
            "LIST" => {
                self.handle_list(&tag, &cmd.args, false, stream).await?;
                Ok(true)
            }
            "LSUB" => {
                self.handle_list(&tag, &cmd.args, true, stream).await?;
                Ok(true)
            }
            "STATUS" => {
                self.handle_status(&tag, &cmd.args, stream).await?;
                Ok(true)
            }
            "SELECT" => {
                self.handle_select(&tag, &cmd.args, false, stream).await?;
                Ok(true)
            }
            "EXAMINE" => {
                self.handle_select(&tag, &cmd.args, true, stream).await?;
                Ok(true)
            }
            "CREATE" => {
                self.handle_create(&tag, &cmd.args, stream).await?;
                Ok(true)
            }
            "DELETE" => {
                self.handle_delete(&tag, &cmd.args, stream).await?;
                Ok(true)
            }
            "RENAME" => {
                self.handle_rename(&tag, &cmd.args, stream).await?;
                Ok(true)
            }
            "SUBSCRIBE" => {
                self.handle_subscribe(&tag, &cmd.args, true, stream).await?;
                Ok(true)
            }
            "UNSUBSCRIBE" => {
                self.handle_subscribe(&tag, &cmd.args, false, stream)
                    .await?;
                Ok(true)
            }
            "APPEND" => {
                self.handle_append(&tag, &cmd.args, stream).await?;
                Ok(true)
            }
            "CHECK" => {
                if !self.is_selected() {
                    write_flush(
                        stream,
                        format!("{tag} NO Select a mailbox first\r\n").as_bytes(),
                    )
                    .await?;
                    return Ok(true);
                }
                self.flush_selected_updates(stream).await?;
                write_flush(stream, format!("{tag} OK CHECK completed\r\n").as_bytes()).await?;
                Ok(true)
            }
            "CLOSE" => {
                self.handle_close(&tag, stream).await?;
                Ok(true)
            }
            "UNSELECT" => {
                self.handle_unselect(&tag, stream).await?;
                Ok(true)
            }
            "EXPUNGE" => {
                self.handle_expunge(&tag, stream).await?;
                Ok(true)
            }
            "SEARCH" => {
                self.handle_search(&tag, &cmd.args, false, stream).await?;
                Ok(true)
            }
            "SORT" => {
                self.handle_sort(&tag, &cmd.args, false, stream).await?;
                Ok(true)
            }
            "THREAD" => {
                self.handle_thread(&tag, &cmd.args, false, stream).await?;
                Ok(true)
            }
            "FETCH" => {
                self.handle_fetch(&tag, &cmd.args, false, stream).await?;
                Ok(true)
            }
            "STORE" => {
                self.handle_store(&tag, &cmd.args, false, stream).await?;
                Ok(true)
            }
            "COPY" => {
                self.handle_copy_or_move(&tag, &cmd.args, false, false, stream)
                    .await?;
                Ok(true)
            }
            "MOVE" => {
                self.handle_copy_or_move(&tag, &cmd.args, false, true, stream)
                    .await?;
                Ok(true)
            }
            "UID" => {
                self.handle_uid(&tag, &cmd.args, stream).await?;
                Ok(true)
            }
            _ => {
                let safe_name = sanitize_imap_text(name);
                write_flush(
                    stream,
                    format!("{tag} BAD Unknown or unsupported command {safe_name}\r\n").as_bytes(),
                )
                .await?;
                Ok(true)
            }
        }
    }

    fn is_authenticated(&self) -> bool {
        !matches!(self.auth, AuthState::NotAuthenticated)
    }

    fn is_selected(&self) -> bool {
        matches!(self.auth, AuthState::Selected(_))
    }

    fn has_scope(&self, scope: AuthScope) -> bool {
        self.principal.as_ref().is_some_and(|p| p.has_scope(scope))
    }

    async fn require_scope_or_no(
        &self,
        tag: &str,
        scope: AuthScope,
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<bool> {
        if self.has_scope(scope) {
            return Ok(true);
        }
        write_flush(
            stream,
            format!(
                "{tag} NO [NOPERM] Insufficient scope: {} scope required\r\n",
                scope.as_str()
            )
            .as_bytes(),
        )
        .await?;
        Ok(false)
    }

    /// Record a failed authentication attempt; returns `Ok(false)` when the connection must close.
    async fn record_auth_failure(
        &mut self,
        tag: &str,
        code: &str,
        message: &str,
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<bool> {
        self.failed_auth_attempts = self.failed_auth_attempts.saturating_add(1);
        if self.failed_auth_attempts >= MAX_FAILED_AUTH_ATTEMPTS {
            write_flush(
                stream,
                format!("{tag} NO [{code}] {message}\r\n* BYE Too many failed login attempts\r\n")
                    .as_bytes(),
            )
            .await?;
            return Ok(false);
        }
        write_flush(
            stream,
            format!("{tag} NO [{code}] {message}\r\n").as_bytes(),
        )
        .await?;
        Ok(true)
    }

    async fn handle_login(
        &mut self,
        tag: &str,
        args: &[ImapArg],
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<bool> {
        if self.is_authenticated() {
            write_flush(
                stream,
                format!("{tag} BAD Already authenticated\r\n").as_bytes(),
            )
            .await?;
            return Ok(true);
        }
        if !stream.get_ref().is_tls() && self.tls_acceptor.is_some() {
            write_flush(
                stream,
                format!("{tag} NO [PRIVACYREQUIRED] STARTTLS required before authentication\r\n")
                    .as_bytes(),
            )
            .await?;
            return Ok(true);
        }
        if args.len() < 2 {
            write_flush(
                stream,
                format!("{tag} BAD LOGIN requires username and password\r\n").as_bytes(),
            )
            .await?;
            return Ok(true);
        }
        let user = args[0].as_str_lossy().unwrap_or_default();
        let pass = args[1].as_str_lossy().unwrap_or_default();
        match self.base_state.auth.authenticate_imap(&user, &pass).await {
            Ok(principal) => {
                self.failed_auth_attempts = 0;
                self.state = self.base_state.for_mailbox(&principal.mailbox_id);
                self.principal = Some(principal);
                self.auth = AuthState::Authenticated;
                let cap = self.capability_string(stream.get_ref().is_tls());
                write_flush(
                    stream,
                    format!("{tag} OK [CAPABILITY {cap}] LOGIN completed\r\n").as_bytes(),
                )
                .await?;
                Ok(true)
            }
            Err(_) => {
                self.record_auth_failure(tag, "AUTHENTICATIONFAILED", "Invalid credentials", stream)
                    .await
            }
        }
    }

    async fn handle_authenticate(
        &mut self,
        tag: &str,
        args: &[ImapArg],
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<bool> {
        if self.is_authenticated() {
            write_flush(
                stream,
                format!("{tag} BAD Already authenticated\r\n").as_bytes(),
            )
            .await?;
            return Ok(true);
        }
        if !stream.get_ref().is_tls() && self.tls_acceptor.is_some() {
            write_flush(
                stream,
                format!("{tag} NO [PRIVACYREQUIRED] STARTTLS required before authentication\r\n")
                    .as_bytes(),
            )
            .await?;
            return Ok(true);
        }
        let Some(mech) = args.first().and_then(ImapArg::as_str_lossy) else {
            write_flush(
                stream,
                format!("{tag} BAD AUTHENTICATE requires mechanism\r\n").as_bytes(),
            )
            .await?;
            return Ok(true);
        };
        let is_plain = mech.eq_ignore_ascii_case("PLAIN");
        let is_xoauth2 = mech.eq_ignore_ascii_case("XOAUTH2");
        if !is_plain && !is_xoauth2 {
            let safe_mech = sanitize_imap_text(&mech);
            write_flush(
                stream,
                format!("{tag} NO Unsupported SASL mechanism {safe_mech}\r\n").as_bytes(),
            )
            .await?;
            return Ok(true);
        }

        if args.len() > 2 {
            write_flush(
                stream,
                format!(
                    "{tag} BAD AUTHENTICATE accepts at most mechanism and initial response\r\n"
                )
                .as_bytes(),
            )
            .await?;
            return Ok(true);
        }

        // RFC 4959 SASL-IR: initial-resp = base64 / "=" (empty zero-length response).
        let b64_payload = if let Some(ir_arg) = args.get(1) {
            match ir_arg {
                ImapArg::Atom(initial) => {
                    if initial == "=" {
                        String::new()
                    } else {
                        initial.clone()
                    }
                }
                _ => {
                    write_flush(
                        stream,
                        format!("{tag} BAD Invalid SASL-IR initial response in AUTHENTICATE\r\n")
                            .as_bytes(),
                    )
                    .await?;
                    return Ok(true);
                }
            }
        } else {
            write_flush(stream, b"+ \r\n").await?;
            let line_opt = match tokio::time::timeout(
                IMAP_PRE_AUTH_READ_TIMEOUT,
                read_crlf_line(stream, 8192),
            )
            .await
            {
                Ok(res) => res?,
                Err(_) => {
                    let _ = write_flush(stream, b"* BYE Autologout; idle for too long\r\n").await;
                    return Ok(false);
                }
            };
            match line_opt {
                Some(line) if line.trim() == "*" => {
                    write_flush(
                        stream,
                        format!("{tag} BAD AUTHENTICATE cancelled\r\n").as_bytes(),
                    )
                    .await?;
                    return Ok(true);
                }
                Some(line) => line.trim().to_string(),
                None => return Err(AppError::BadRequest("EOF during AUTHENTICATE".to_string())),
            }
        };

        let decoded = match base64::engine::general_purpose::STANDARD.decode(b64_payload.as_bytes())
        {
            Ok(bytes) => bytes,
            Err(_) => {
                let mech_label = if is_xoauth2 { "XOAUTH2" } else { "PLAIN" };
                write_flush(
                    stream,
                    format!("{tag} BAD Invalid base64 in AUTHENTICATE {mech_label}\r\n").as_bytes(),
                )
                .await?;
                return Ok(true);
            }
        };

        let (auth_result, plain_authzid_check) = if is_xoauth2 {
            let Some((user, token)) = parse_xoauth2_payload(&decoded) else {
                write_flush(
                    stream,
                    format!("{tag} BAD Malformed XOAUTH2 SASL payload\r\n").as_bytes(),
                )
                .await?;
                return Ok(true);
            };
            (
                self.base_state
                    .auth
                    .authenticate_xoauth2(&user, &token)
                    .await,
                None,
            )
        } else {
            // Format: [authzid]\0authcid\0passwd
            let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
            if parts.len() != 3 {
                write_flush(
                    stream,
                    format!("{tag} BAD Malformed PLAIN SASL payload\r\n").as_bytes(),
                )
                .await?;
                return Ok(true);
            }
            let authzid = String::from_utf8_lossy(parts[0]).trim().to_string();
            let authcid = String::from_utf8_lossy(parts[1]).trim().to_string();
            let passwd = String::from_utf8_lossy(parts[2]);
            let res = self
                .base_state
                .auth
                .authenticate_imap(&authcid, &passwd)
                .await;
            (res, Some((authzid, authcid)))
        };

        match auth_result {
            Ok(mut principal) => {
                if let Some((authzid, authcid)) = plain_authzid_check
                    && !authzid.is_empty()
                    && !authzid.eq_ignore_ascii_case(&authcid)
                {
                    if principal.can_access_mailbox(&authzid) {
                        principal.mailbox_id = crate::config::normalize_mailbox_id(&authzid);
                    } else if !principal.has_scope(AuthScope::Admin) {
                        return self
                            .record_auth_failure(
                                tag,
                                "AUTHORIZATIONFAILED",
                                "Authorization identity does not match authentication identity",
                                stream,
                            )
                            .await;
                    }
                }
                self.failed_auth_attempts = 0;
                self.state = self.base_state.for_mailbox(&principal.mailbox_id);
                self.principal = Some(principal);
                self.auth = AuthState::Authenticated;
                let cap = self.capability_string(stream.get_ref().is_tls());
                write_flush(
                    stream,
                    format!("{tag} OK [CAPABILITY {cap}] AUTHENTICATE completed\r\n").as_bytes(),
                )
                .await?;
                Ok(true)
            }
            Err(_) => {
                self.record_auth_failure(tag, "AUTHENTICATIONFAILED", "Invalid credentials", stream)
                    .await
            }
        }
    }

    async fn handle_enable(
        &mut self,
        tag: &str,
        args: &[ImapArg],
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        match self.auth {
            AuthState::NotAuthenticated => {
                write_flush(
                    stream,
                    format!("{tag} NO Authenticate first\r\n").as_bytes(),
                )
                .await?;
                return Ok(());
            }
            AuthState::Selected(_) => {
                write_flush(
                    stream,
                    format!("{tag} BAD ENABLE is only valid in authenticated state\r\n").as_bytes(),
                )
                .await?;
                return Ok(());
            }
            AuthState::Authenticated => {}
        }
        if args.is_empty() {
            write_flush(
                stream,
                format!("{tag} BAD ENABLE requires at least one capability\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }

        let mut enabled: Vec<&'static str> = Vec::new();
        for arg in args {
            let Some(raw) = arg.as_str_lossy() else {
                continue;
            };
            match raw.to_ascii_uppercase().as_str() {
                "CONDSTORE" => {
                    self.condstore_enabled = true;
                    if !enabled.contains(&"CONDSTORE") {
                        enabled.push("CONDSTORE");
                    }
                }
                "QRESYNC" => {
                    // RFC 7162 Section 3.2.3: enabling QRESYNC implicitly enables CONDSTORE.
                    self.qresync_enabled = true;
                    self.condstore_enabled = true;
                    if !enabled.contains(&"QRESYNC") {
                        enabled.push("QRESYNC");
                    }
                }
                _ => {
                    // RFC 5161 Section 3.2.1: unsupported capabilities are ignored.
                }
            }
        }

        let mut out = String::new();
        if enabled.is_empty() {
            out.push_str("* ENABLED\r\n");
        } else {
            out.push_str(&format!("* ENABLED {}\r\n", enabled.join(" ")));
        }
        out.push_str(&format!("{tag} OK ENABLE completed\r\n"));
        write_flush(stream, out.as_bytes()).await?;
        Ok(())
    }

    async fn handle_list(
        &mut self,
        tag: &str,
        args: &[ImapArg],
        is_lsub: bool,
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        if !self.is_authenticated() {
            write_flush(
                stream,
                format!("{tag} NO Authenticate first\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        if !self
            .require_scope_or_no(tag, AuthScope::Read, stream)
            .await?
        {
            return Ok(());
        }
        let cmd_word = if is_lsub { "LSUB" } else { "LIST" };

        if is_lsub {
            if args.len() < 2 {
                write_flush(
                    stream,
                    format!("{tag} BAD LSUB requires reference and pattern\r\n").as_bytes(),
                )
                .await?;
                return Ok(());
            }
            let reference = args[0].as_str_lossy().unwrap_or_default();
            let pattern = args[1].as_str_lossy().unwrap_or_default();
            let full_pattern = combine_list_pattern(&reference, &pattern);
            let mailboxes = self.state.store.imap_list_mailboxes().await?;
            let mut out = String::new();

            let has_gmail_children = mailboxes.iter().any(|m| m.name.starts_with("[Gmail]/"));
            if has_gmail_children
                && imap_wildcard_match(&full_pattern, "[Gmail]", '/')
                && (self.subscribed.is_empty() || self.subscribed.contains("[Gmail]"))
            {
                out.push_str("* LSUB (\\Noselect \\HasChildren) \"/\" \"[Gmail]\"\r\n");
            }

            for mbx in &mailboxes {
                if !self.subscribed.is_empty() && !self.subscribed.contains(&mbx.name) {
                    continue;
                }
                if !imap_wildcard_match(&full_pattern, &mbx.name, '/') {
                    continue;
                }
                let has_children = mailboxes
                    .iter()
                    .any(|other| other.name.starts_with(&format!("{}/", mbx.name)));
                let mut attrs = Vec::new();
                attrs.push(if has_children {
                    "\\HasChildren".to_string()
                } else {
                    "\\HasNoChildren".to_string()
                });
                if let Some(ref su) = mbx.special_use {
                    attrs.push(su.clone());
                }
                out.push_str(&format!(
                    "* LSUB ({}) \"/\" {}\r\n",
                    attrs.join(" "),
                    imap_string(&mbx.name)
                ));
            }
            out.push_str(&format!("{tag} OK LSUB completed\r\n"));
            write_flush(stream, out.as_bytes()).await?;
            return Ok(());
        }

        // RFC 5258 LIST-EXTENDED + RFC 5819 LIST-STATUS + RFC 6154 SPECIAL-USE:
        // LIST [(<selection-opts>)] <reference> (<pattern> | (<pattern>...)) [RETURN (<return-opts>)]
        let parsed = match parse_list_extended_args(args) {
            Ok(p) => p,
            Err(err) => {
                let safe_err = sanitize_imap_text(&err.to_string());
                write_flush(stream, format!("{tag} BAD {safe_err}\r\n").as_bytes()).await?;
                return Ok(());
            }
        };

        // RFC 3501 Section 6.3.8: empty pattern queries hierarchy delimiter.
        if !parsed.has_selection_options
            && parsed.patterns.len() == 1
            && parsed.patterns[0].is_empty()
            && parsed.return_status_items.is_none()
        {
            let resp = format!("* LIST (\\Noselect) \"/\" \"\"\r\n{tag} OK LIST completed\r\n");
            write_flush(stream, resp.as_bytes()).await?;
            return Ok(());
        }

        let full_patterns: Vec<String> = parsed
            .patterns
            .iter()
            .map(|p| combine_list_pattern(&parsed.reference, p))
            .collect();

        let mailboxes = self.state.store.imap_list_mailboxes().await?;
        let highest_modseq = if parsed
            .return_status_items
            .as_ref()
            .is_some_and(|items| items.iter().any(|i| i == "HIGHESTMODSEQ"))
        {
            Some(self.state.store.current_history_id().await?.max(1))
        } else {
            None
        };

        let mut out = String::new();
        let emit_subscribed_attr = parsed.select_subscribed || parsed.return_subscribed;

        // Synthesize virtual "[Gmail]" container if it matches and is not filtered out by SPECIAL-USE.
        let has_gmail_children = mailboxes.iter().any(|m| m.name.starts_with("[Gmail]/"));
        if has_gmail_children
            && !parsed.select_special_use
            && full_patterns
                .iter()
                .any(|p| imap_wildcard_match(p, "[Gmail]", '/'))
            && (!parsed.select_subscribed || self.subscribed.contains("[Gmail]"))
        {
            let mut attrs = vec!["\\Noselect", "\\HasChildren"];
            if emit_subscribed_attr && self.subscribed.contains("[Gmail]") {
                attrs.push("\\Subscribed");
            }
            out.push_str(&format!(
                "* {cmd_word} ({}) \"/\" \"[Gmail]\"\r\n",
                attrs.join(" ")
            ));
            // RFC 5819 Section 2: never emit STATUS for \Noselect mailboxes.
        }

        for mbx in &mailboxes {
            if parsed.select_subscribed && !self.subscribed.contains(&mbx.name) {
                continue;
            }
            if parsed.select_special_use && mbx.special_use.is_none() {
                continue;
            }
            if !full_patterns
                .iter()
                .any(|p| imap_wildcard_match(p, &mbx.name, '/'))
            {
                continue;
            }
            let has_children = mailboxes
                .iter()
                .any(|other| other.name.starts_with(&format!("{}/", mbx.name)));
            let mut attrs = Vec::new();
            attrs.push(if has_children {
                "\\HasChildren".to_string()
            } else {
                "\\HasNoChildren".to_string()
            });
            if emit_subscribed_attr && self.subscribed.contains(&mbx.name) {
                attrs.push("\\Subscribed".to_string());
            }
            if let Some(ref su) = mbx.special_use {
                attrs.push(su.clone());
            }
            out.push_str(&format!(
                "* {cmd_word} ({}) \"/\" {}\r\n",
                attrs.join(" "),
                imap_string(&mbx.name)
            ));

            if let Some(ref status_items) = parsed.return_status_items {
                let pairs = format_status_pairs(mbx, status_items, highest_modseq);
                out.push_str(&format!(
                    "* STATUS {} ({})\r\n",
                    imap_string(&mbx.name),
                    pairs.join(" ")
                ));
            }
        }
        out.push_str(&format!("{tag} OK {cmd_word} completed\r\n"));
        write_flush(stream, out.as_bytes()).await?;
        Ok(())
    }

    async fn handle_status(
        &mut self,
        tag: &str,
        args: &[ImapArg],
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        if !self.is_authenticated() {
            write_flush(
                stream,
                format!("{tag} NO Authenticate first\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        if !self
            .require_scope_or_no(tag, AuthScope::Read, stream)
            .await?
        {
            return Ok(());
        }
        if args.len() < 2 {
            write_flush(
                stream,
                format!("{tag} BAD STATUS requires mailbox and status data items\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        let mailbox = normalize_mailbox_name(&args[0].as_str_lossy().unwrap_or_default());
        let Some(items) = args[1].as_list() else {
            write_flush(
                stream,
                format!("{tag} BAD STATUS items must be a parenthesized list\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        };

        let Some(info) = self.state.store.imap_mailbox_info(&mailbox).await? else {
            write_flush(
                stream,
                format!(
                    "{tag} NO Mailbox does not exist: {}\r\n",
                    imap_quote(&mailbox)
                )
                .as_bytes(),
            )
            .await?;
            return Ok(());
        };

        let mut pairs = Vec::new();
        let mut highest_modseq_cache: Option<u64> = None;
        for item in items {
            let Some(key) = item.as_str_lossy() else {
                continue;
            };
            match key.to_ascii_uppercase().as_str() {
                "MESSAGES" => pairs.push(format!("MESSAGES {}", info.messages)),
                "RECENT" => pairs.push("RECENT 0".to_string()),
                "UIDNEXT" => pairs.push(format!("UIDNEXT {}", info.uid_next)),
                "UIDVALIDITY" => pairs.push(format!("UIDVALIDITY {}", info.uid_validity)),
                "UNSEEN" => pairs.push(format!("UNSEEN {}", info.unseen)),
                "HIGHESTMODSEQ" => {
                    let hms = match highest_modseq_cache {
                        Some(v) => v,
                        None => {
                            let v = self.state.store.current_history_id().await?.max(1);
                            highest_modseq_cache = Some(v);
                            v
                        }
                    };
                    pairs.push(format!("HIGHESTMODSEQ {hms}"));
                }
                _ => {}
            }
        }
        let resp = format!(
            "* STATUS {} ({})\r\n{tag} OK STATUS completed\r\n",
            imap_string(&info.name),
            pairs.join(" ")
        );
        write_flush(stream, resp.as_bytes()).await?;
        Ok(())
    }

    async fn handle_select(
        &mut self,
        tag: &str,
        args: &[ImapArg],
        read_only: bool,
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        if !self.is_authenticated() {
            write_flush(
                stream,
                format!("{tag} NO Authenticate first\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        if !self
            .require_scope_or_no(tag, AuthScope::Read, stream)
            .await?
        {
            return Ok(());
        }
        let effective_read_only = read_only || !self.has_scope(AuthScope::Write);
        let Some(raw_mbx) = args.first().and_then(ImapArg::as_str_lossy) else {
            write_flush(
                stream,
                format!("{tag} BAD SELECT/EXAMINE requires mailbox name\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        };

        // Parse optional RFC 7162 SELECT/EXAMINE parameters: `(CONDSTORE)` and/or `(QRESYNC (...))`.
        let mut req_condstore = false;
        let mut qresync_param: Option<QresyncSelectParam> = None;
        if let Some(param_arg) = args.get(1) {
            let Some(params) = param_arg.as_list() else {
                write_flush(
                    stream,
                    format!("{tag} BAD SELECT/EXAMINE parameters must be a parenthesized list\r\n")
                        .as_bytes(),
                )
                .await?;
                return Ok(());
            };
            let mut i = 0usize;
            while i < params.len() {
                let Some(key) = params[i].as_str_lossy() else {
                    write_flush(
                        stream,
                        format!("{tag} BAD Invalid SELECT/EXAMINE parameter\r\n").as_bytes(),
                    )
                    .await?;
                    return Ok(());
                };
                match key.to_ascii_uppercase().as_str() {
                    "CONDSTORE" => {
                        req_condstore = true;
                        i += 1;
                    }
                    "QRESYNC" => {
                        if !self.qresync_enabled {
                            write_flush(
                                stream,
                                format!("{tag} BAD QRESYNC requires ENABLE QRESYNC first\r\n")
                                    .as_bytes(),
                            )
                            .await?;
                            return Ok(());
                        }
                        let Some(qlist) = params.get(i + 1).and_then(ImapArg::as_list) else {
                            write_flush(
                                stream,
                                format!(
                                    "{tag} BAD QRESYNC parameter requires (<uidvalidity> <modseq> ...)\r\n"
                                )
                                .as_bytes(),
                            )
                            .await?;
                            return Ok(());
                        };
                        match parse_qresync_select_param(qlist) {
                            Ok(parsed) => {
                                qresync_param = Some(parsed);
                                req_condstore = true;
                            }
                            Err(err) => {
                                let safe_err = sanitize_imap_text(&err.to_string());
                                write_flush(stream, format!("{tag} BAD {safe_err}\r\n").as_bytes())
                                    .await?;
                                return Ok(());
                            }
                        }
                        i += 2;
                    }
                    other => {
                        let safe_other = sanitize_imap_text(other);
                        write_flush(
                            stream,
                            format!(
                                "{tag} BAD Unsupported SELECT/EXAMINE parameter {safe_other}\r\n"
                            )
                            .as_bytes(),
                        )
                        .await?;
                        return Ok(());
                    }
                }
            }
        }

        // RFC 3501 Section 6.3.1 / 6.3.2: SELECT/EXAMINE always deselects any currently selected
        // mailbox before attempting the new selection, even if the new selection fails.
        let was_selected = self.is_selected();
        self.auth = AuthState::Authenticated;

        let mailbox = normalize_mailbox_name(&raw_mbx);
        let Some(info) = self.state.store.imap_mailbox_info(&mailbox).await? else {
            let mut resp = String::new();
            if was_selected && self.qresync_enabled {
                resp.push_str("* OK [CLOSED] Previous mailbox closed\r\n");
            }
            resp.push_str(&format!(
                "{tag} NO [TRYCREATE] Mailbox does not exist: {}\r\n",
                imap_quote(&mailbox)
            ));
            write_flush(stream, resp.as_bytes()).await?;
            return Ok(());
        };
        if req_condstore {
            self.condstore_enabled = true;
        }

        let entries = self.state.store.imap_list_messages(&info.name).await?;
        let highest_modseq = self.state.store.current_history_id().await?.max(1);
        let first_unseen = entries
            .iter()
            .find(|m| m.label_ids.iter().any(|l| l == LABEL_UNREAD))
            .map(|m| m.seq);

        let mut out = String::new();
        if was_selected && self.qresync_enabled {
            out.push_str("* OK [CLOSED] Previous mailbox closed\r\n");
        }
        out.push_str(&format!("* {} EXISTS\r\n", entries.len()));
        out.push_str("* 0 RECENT\r\n");
        if let Some(seq) = first_unseen {
            out.push_str(&format!(
                "* OK [UNSEEN {seq}] Message {seq} is first unseen\r\n"
            ));
        }
        out.push_str(&format!(
            "* OK [UIDVALIDITY {}] UIDs valid\r\n",
            info.uid_validity
        ));
        out.push_str(&format!(
            "* OK [UIDNEXT {}] Predicted next UID\r\n",
            info.uid_next
        ));
        out.push_str(&format!(
            "* OK [HIGHESTMODSEQ {highest_modseq}] Highest\r\n"
        ));
        out.push_str("* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n");
        if effective_read_only {
            out.push_str("* OK [PERMANENTFLAGS ()] Read-only mailbox\r\n");
        } else {
            out.push_str(
                "* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Flags permitted\r\n",
            );
        }

        // RFC 7162 Section 3.2.5.2: emit VANISHED (EARLIER) and changed FETCH updates
        // when QRESYNC UIDVALIDITY matches.
        if let Some(qresync) = qresync_param
            && qresync.uid_validity == info.uid_validity
        {
            let existing_uids: HashSet<u32> = entries.iter().map(|e| e.uid).collect();
            let mut vanished = self
                .state
                .store
                .imap_vanished_uids(&info.name, qresync.last_modseq)
                .await?;
            vanished.retain(|uid| {
                !existing_uids.contains(uid)
                    && qresync
                        .known_uids
                        .as_ref()
                        .is_none_or(|ranges| seq_set_contains(ranges, *uid))
            });
            if !vanished.is_empty() {
                let uid_set = format_sequence_set(&vanished);
                out.push_str(&format!("* VANISHED (EARLIER) {uid_set}\r\n"));
            }

            for entry in &entries {
                if entry.modseq() <= qresync.last_modseq {
                    continue;
                }
                if let Some(ref known_ranges) = qresync.known_uids
                    && !seq_set_contains(known_ranges, entry.uid)
                {
                    continue;
                }
                let flags_str = format_imap_flags(entry);
                out.push_str(&format!(
                    "* {} FETCH (UID {} FLAGS ({flags_str}) MODSEQ ({}))\r\n",
                    entry.seq,
                    entry.uid,
                    entry.modseq()
                ));
            }
        }

        if read_only {
            out.push_str(&format!("{tag} OK [READ-ONLY] EXAMINE completed\r\n"));
        } else if effective_read_only {
            out.push_str(&format!("{tag} OK [READ-ONLY] SELECT completed\r\n"));
        } else {
            out.push_str(&format!("{tag} OK [READ-WRITE] SELECT completed\r\n"));
        }

        self.auth = AuthState::Selected(SelectedState {
            mailbox: info.name,
            read_only: effective_read_only,
            snapshot: entries,
        });
        write_flush(stream, out.as_bytes()).await?;
        Ok(())
    }

    async fn handle_create(
        &mut self,
        tag: &str,
        args: &[ImapArg],
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        if !self.is_authenticated() {
            write_flush(
                stream,
                format!("{tag} NO Authenticate first\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        if !self
            .require_scope_or_no(tag, AuthScope::Write, stream)
            .await?
        {
            return Ok(());
        }
        let Some(name) = args.first().and_then(ImapArg::as_str_lossy) else {
            write_flush(
                stream,
                format!("{tag} BAD CREATE requires mailbox name\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        };
        if !is_valid_mailbox_name(&name) {
            write_flush(
                stream,
                format!("{tag} BAD Invalid mailbox name\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        if is_reserved_mailbox(&name) {
            write_flush(
                stream,
                format!(
                    "{tag} NO Cannot create reserved system mailbox {}\r\n",
                    imap_quote(&name)
                )
                .as_bytes(),
            )
            .await?;
            return Ok(());
        }
        match self
            .state
            .store
            .create_label(NewLabelInput {
                name: name.clone(),
                ..Default::default()
            })
            .await
        {
            Ok(_) => {
                write_flush(stream, format!("{tag} OK CREATE completed\r\n").as_bytes()).await?;
            }
            Err(err) => {
                let safe_err = sanitize_imap_text(&err.to_string());
                write_flush(stream, format!("{tag} NO {safe_err}\r\n").as_bytes()).await?;
            }
        }
        Ok(())
    }

    async fn handle_delete(
        &mut self,
        tag: &str,
        args: &[ImapArg],
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        if !self.is_authenticated() {
            write_flush(
                stream,
                format!("{tag} NO Authenticate first\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        if !self
            .require_scope_or_no(tag, AuthScope::Write, stream)
            .await?
        {
            return Ok(());
        }
        let Some(name) = args.first().and_then(ImapArg::as_str_lossy) else {
            write_flush(
                stream,
                format!("{tag} BAD DELETE requires mailbox name\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        };
        if is_reserved_mailbox(&name) {
            write_flush(
                stream,
                format!(
                    "{tag} NO Cannot delete system mailbox {}\r\n",
                    imap_quote(&name)
                )
                .as_bytes(),
            )
            .await?;
            return Ok(());
        }
        let labels = self.state.store.list_labels().await?;
        let Some(label) = labels
            .into_iter()
            .find(|l| l.label_type == "user" && l.name == name)
        else {
            write_flush(
                stream,
                format!("{tag} NO Mailbox does not exist: {}\r\n", imap_quote(&name)).as_bytes(),
            )
            .await?;
            return Ok(());
        };
        match self.state.store.delete_label(&label.id).await {
            Ok(()) => {
                self.subscribed.remove(&name);
                write_flush(stream, format!("{tag} OK DELETE completed\r\n").as_bytes()).await?;
            }
            Err(err) => {
                let safe_err = sanitize_imap_text(&err.to_string());
                write_flush(stream, format!("{tag} NO {safe_err}\r\n").as_bytes()).await?;
            }
        }
        Ok(())
    }

    async fn handle_rename(
        &mut self,
        tag: &str,
        args: &[ImapArg],
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        if !self.is_authenticated() {
            write_flush(
                stream,
                format!("{tag} NO Authenticate first\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        if !self
            .require_scope_or_no(tag, AuthScope::Write, stream)
            .await?
        {
            return Ok(());
        }
        if args.len() < 2 {
            write_flush(
                stream,
                format!("{tag} BAD RENAME requires old and new mailbox names\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        let old_name = args[0].as_str_lossy().unwrap_or_default();
        let new_name = args[1].as_str_lossy().unwrap_or_default();
        if !is_valid_mailbox_name(&new_name) {
            write_flush(
                stream,
                format!("{tag} BAD Invalid mailbox name\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        if is_reserved_mailbox(&old_name) || is_reserved_mailbox(&new_name) {
            write_flush(
                stream,
                format!("{tag} NO Cannot rename system mailbox\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        let labels = self.state.store.list_labels().await?;
        let Some(label) = labels
            .into_iter()
            .find(|l| l.label_type == "user" && l.name == old_name)
        else {
            write_flush(
                stream,
                format!(
                    "{tag} NO Mailbox does not exist: {}\r\n",
                    imap_quote(&old_name)
                )
                .as_bytes(),
            )
            .await?;
            return Ok(());
        };
        match self
            .state
            .store
            .update_label(
                &label.id,
                UpdateLabelInput {
                    name: Some(new_name.clone()),
                    ..Default::default()
                },
                false,
            )
            .await
        {
            Ok(_) => {
                if self.subscribed.remove(&old_name) {
                    self.subscribed.insert(new_name);
                }
                write_flush(stream, format!("{tag} OK RENAME completed\r\n").as_bytes()).await?;
            }
            Err(err) => {
                let safe_err = sanitize_imap_text(&err.to_string());
                write_flush(stream, format!("{tag} NO {safe_err}\r\n").as_bytes()).await?;
            }
        }
        Ok(())
    }

    async fn handle_subscribe(
        &mut self,
        tag: &str,
        args: &[ImapArg],
        subscribe: bool,
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        if !self.is_authenticated() {
            write_flush(
                stream,
                format!("{tag} NO Authenticate first\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        let Some(raw_name) = args.first().and_then(ImapArg::as_str_lossy) else {
            write_flush(
                stream,
                format!("{tag} BAD SUBSCRIBE/UNSUBSCRIBE requires mailbox name\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        };
        let name = normalize_mailbox_name(&raw_name);
        if subscribe {
            self.subscribed.insert(name);
            write_flush(
                stream,
                format!("{tag} OK SUBSCRIBE completed\r\n").as_bytes(),
            )
            .await?;
        } else {
            self.subscribed.remove(&name);
            write_flush(
                stream,
                format!("{tag} OK UNSUBSCRIBE completed\r\n").as_bytes(),
            )
            .await?;
        }
        Ok(())
    }

    async fn handle_append(
        &mut self,
        tag: &str,
        args: &[ImapArg],
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        if !self.is_authenticated() {
            write_flush(
                stream,
                format!("{tag} NO Authenticate first\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        if !self
            .require_scope_or_no(tag, AuthScope::Write, stream)
            .await?
        {
            return Ok(());
        }
        if args.len() < 2 {
            write_flush(
                stream,
                format!("{tag} BAD APPEND requires mailbox and message literal\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        let mailbox = normalize_mailbox_name(&args[0].as_str_lossy().unwrap_or_default());

        let mut idx = 1usize;
        let mut flags: Vec<String> = Vec::new();
        let mut internal_date_ms: Option<i64> = None;

        if let Some(ImapArg::List(flag_args)) = args.get(idx) {
            for f in flag_args {
                if let Some(s) = f.as_str_lossy() {
                    flags.push(s);
                }
            }
            idx += 1;
        }
        if idx + 1 < args.len()
            && let Some(date_str) = args.get(idx).and_then(ImapArg::as_str_lossy)
        {
            internal_date_ms = parse_imap_date_time(&date_str);
            idx += 1;
        }
        let Some(raw_bytes) = args.get(idx).and_then(ImapArg::as_bytes) else {
            write_flush(
                stream,
                format!("{tag} BAD APPEND missing message literal\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        };

        let is_seen = flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen"));
        let is_flagged = flags.iter().any(|f| f.eq_ignore_ascii_case("\\Flagged"));
        let is_draft = flags.iter().any(|f| f.eq_ignore_ascii_case("\\Draft"));
        let is_answered = flags.iter().any(|f| f.eq_ignore_ascii_case("\\Answered"));
        let is_deleted = flags.iter().any(|f| f.eq_ignore_ascii_case("\\Deleted"));

        let mut label_ids = Vec::new();
        if !is_seen {
            label_ids.push(LABEL_UNREAD.to_string());
        }
        if is_flagged {
            label_ids.push(LABEL_STARRED.to_string());
        }
        if is_draft {
            label_ids.push(LABEL_DRAFT.to_string());
        }

        let mut input = parse_raw_to_new_message_input(
            raw_bytes.to_vec(),
            label_ids,
            internal_date_ms,
            "imap_append",
            None,
            None,
            is_answered,
            is_deleted,
        );

        // Evaluate pluggable InboundFilter prior to storage.
        let parsed_headers: Vec<(String, String)> = crate::mime::parse_rfc2822(&input.raw_rfc2822)
            .map(|p| p.headers.into_iter().map(|h| (h.name, h.value)).collect())
            .unwrap_or_default();
        let auth_results = parsed_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Authentication-Results"))
            .map(|(_, v)| v.clone());
        let inbound_msg = InboundMessage {
            raw_rfc2822: input.raw_rfc2822.clone(),
            headers: parsed_headers,
            text_body: input.text_body.clone(),
            html_body: input.html_body.clone(),
            from: input.from_addr.clone(),
            to: input.to_addrs.clone(),
            subject: input.subject.clone(),
            authentication_results: auth_results,
            sender_ip: None,
            source: "imap_append".to_string(),
            provider_id: None,
        };

        let mut target_mailbox = mailbox;
        let decision = self.state.filter.evaluate(&inbound_msg).await?;
        self.state.metrics.record_filter_decision(&decision);
        match decision {
            FilterDecision::Reject { reason } => {
                let safe_reason = sanitize_imap_text(&reason);
                write_flush(
                    stream,
                    format!("{tag} NO [REJECTED] {safe_reason}\r\n").as_bytes(),
                )
                .await?;
                return Ok(());
            }
            decision @ FilterDecision::Spam { .. } => {
                input.label_ids = apply_filter_labels(input.label_ids, &decision);
                target_mailbox = "[Gmail]/Spam".to_string();
            }
            decision @ FilterDecision::Mutate { skip_inbox, .. } => {
                input.label_ids = apply_filter_labels(input.label_ids, &decision);
                if skip_inbox && target_mailbox.eq_ignore_ascii_case("INBOX") {
                    target_mailbox = "[Gmail]/All Mail".to_string();
                }
            }
            FilterDecision::Allow => {}
        }

        match self.state.store.imap_append(&target_mailbox, input).await {
            Ok((uid_validity, uid, stored)) => {
                self.state.metrics.inc_messages_received();
                self.state.events.publish(
                    EventSource::Imap,
                    MailEvent::MessageReceived {
                        message_id: stored.id.clone(),
                        thread_id: stored.thread_id.clone(),
                        from: stored.from_addr.clone(),
                        subject: stored.subject.clone(),
                        snippet: stored.snippet.clone(),
                        labels: stored.label_ids.clone(),
                    },
                );
                let webhook_policy =
                    crate::ai::rules::RuleWebhookPolicy::from_config(&self.state.config);
                let stored = crate::ai::rules::evaluate_inbox_rules_with_cipher(
                    self.state.store.as_ref(),
                    &self.state.events,
                    &stored,
                    self.state.config.untrusted_content_guard,
                    &webhook_policy,
                    self.state.cipher.as_ref(),
                )
                .await;
                let _ = self.state.post_store_message(&stored).await;
                write_flush(
                    stream,
                    format!("{tag} OK [APPENDUID {uid_validity} {uid}] APPEND completed\r\n")
                        .as_bytes(),
                )
                .await?;
            }
            Err(AppError::NotFound(msg)) => {
                let safe_msg = sanitize_imap_text(&msg);
                write_flush(
                    stream,
                    format!("{tag} NO [TRYCREATE] {safe_msg}\r\n").as_bytes(),
                )
                .await?;
            }
            Err(err) => {
                let safe_err = sanitize_imap_text(&err.to_string());
                write_flush(stream, format!("{tag} NO {safe_err}\r\n").as_bytes()).await?;
            }
        }
        Ok(())
    }

    async fn handle_close(
        &mut self,
        tag: &str,
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        let sel = match &self.auth {
            AuthState::Selected(s) => s.clone(),
            _ => {
                write_flush(
                    stream,
                    format!("{tag} NO No mailbox selected\r\n").as_bytes(),
                )
                .await?;
                return Ok(());
            }
        };
        if !sel.read_only && self.has_scope(AuthScope::Write) {
            let expunged = self
                .state
                .store
                .imap_expunge_uids(&sel.mailbox, None)
                .await?;
            for entry in &expunged {
                if entry.permanently_deleted {
                    let _ = self
                        .state
                        .post_delete_message(&entry.message_id, &entry.attachment_ids)
                        .await;
                }
                self.state.events.publish(
                    EventSource::Imap,
                    MailEvent::MessageDeleted {
                        message_id: entry.message_id.clone(),
                        thread_id: entry.thread_id.clone(),
                        labels: entry.label_ids.clone(),
                    },
                );
            }
        }
        self.auth = AuthState::Authenticated;
        write_flush(stream, format!("{tag} OK CLOSE completed\r\n").as_bytes()).await?;
        Ok(())
    }

    async fn handle_unselect(
        &mut self,
        tag: &str,
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        if !self.is_authenticated() {
            write_flush(
                stream,
                format!("{tag} NO Authenticate first\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        if !self.is_selected() {
            write_flush(
                stream,
                format!("{tag} NO No mailbox selected\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        // RFC 3691: UNSELECT deselects the current mailbox without expunging \Deleted messages.
        self.auth = AuthState::Authenticated;
        write_flush(
            stream,
            format!("{tag} OK UNSELECT completed\r\n").as_bytes(),
        )
        .await?;
        Ok(())
    }

    async fn handle_expunge(
        &mut self,
        tag: &str,
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        self.handle_expunge_inner(tag, None, stream).await
    }

    async fn handle_uid_expunge(
        &mut self,
        tag: &str,
        args: &[ImapArg],
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        let sel = match &self.auth {
            AuthState::Selected(s) => s.clone(),
            _ => {
                write_flush(
                    stream,
                    format!("{tag} NO No mailbox selected\r\n").as_bytes(),
                )
                .await?;
                return Ok(());
            }
        };
        let Some(uid_spec) = args.first().and_then(ImapArg::as_str_lossy) else {
            write_flush(
                stream,
                format!("{tag} BAD UID EXPUNGE requires a UID sequence set\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        };
        let snap_max_uid = sel.snapshot.last().map(|e| e.uid).unwrap_or(0);
        // If the client gave explicit UIDs without `*`, parse them even if snapshot was empty.
        let parse_max = if uid_spec.contains('*') {
            snap_max_uid
        } else {
            snap_max_uid.max(1)
        };
        let ranges = match parse_sequence_set(&uid_spec, parse_max) {
            Ok(r) => r,
            Err(err) => {
                let safe_err = sanitize_imap_text(&err.to_string());
                write_flush(stream, format!("{tag} BAD {safe_err}\r\n").as_bytes()).await?;
                return Ok(());
            }
        };
        self.handle_expunge_inner(tag, Some(&ranges), stream).await
    }

    async fn handle_expunge_inner(
        &mut self,
        tag: &str,
        uid_ranges: Option<&[(u32, u32)]>,
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        let sel = match &self.auth {
            AuthState::Selected(s) => s.clone(),
            _ => {
                write_flush(
                    stream,
                    format!("{tag} NO No mailbox selected\r\n").as_bytes(),
                )
                .await?;
                return Ok(());
            }
        };
        if !self
            .require_scope_or_no(tag, AuthScope::Write, stream)
            .await?
        {
            return Ok(());
        }
        if sel.read_only {
            write_flush(
                stream,
                format!("{tag} NO Mailbox is selected read-only\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }

        let expunged = self
            .state
            .store
            .imap_expunge_uids(&sel.mailbox, uid_ranges)
            .await?;
        for entry in &expunged {
            if entry.permanently_deleted {
                let _ = self
                    .state
                    .post_delete_message(&entry.message_id, &entry.attachment_ids)
                    .await;
            }
            self.state.events.publish(
                EventSource::Imap,
                MailEvent::MessageDeleted {
                    message_id: entry.message_id.clone(),
                    thread_id: entry.thread_id.clone(),
                    labels: entry.label_ids.clone(),
                },
            );
        }

        // Diff `sel.snapshot` against the fresh mailbox listing so every removed message
        // (including concurrent deletions) is reported in strict RFC 3501 sequence order.
        let new_entries = self.state.store.imap_list_messages(&sel.mailbox).await?;
        let remaining_ids: HashSet<&str> =
            new_entries.iter().map(|e| e.message_id.as_str()).collect();
        let mut removed_seqs: Vec<u32> = sel
            .snapshot
            .iter()
            .filter(|old| !remaining_ids.contains(old.message_id.as_str()))
            .map(|old| old.seq)
            .collect();
        let removed_uids: Vec<u32> = sel
            .snapshot
            .iter()
            .filter(|old| !remaining_ids.contains(old.message_id.as_str()))
            .map(|old| old.uid)
            .collect();
        removed_seqs.sort_unstable();

        let mut out = String::new();
        if self.qresync_enabled {
            // RFC 7162 Section 3.2.10: emit VANISHED instead of EXPUNGE when QRESYNC is enabled.
            if !removed_uids.is_empty() {
                let uid_set = format_sequence_set(&removed_uids);
                out.push_str(&format!("* VANISHED {uid_set}\r\n"));
            }
        } else {
            for (removed_so_far, pre_seq) in removed_seqs.iter().enumerate() {
                let adjusted = pre_seq.saturating_sub(removed_so_far as u32).max(1);
                out.push_str(&format!("* {adjusted} EXPUNGE\r\n"));
            }
        }
        let after_expunge_count = sel.snapshot.len().saturating_sub(removed_seqs.len());
        if new_entries.len() > after_expunge_count {
            out.push_str(&format!("* {} EXISTS\r\n", new_entries.len()));
        }
        if let AuthState::Selected(ref mut s) = self.auth {
            s.snapshot = new_entries;
        }

        out.push_str(&format!("{tag} OK EXPUNGE completed\r\n"));
        write_flush(stream, out.as_bytes()).await?;
        Ok(())
    }

    async fn handle_uid(
        &mut self,
        tag: &str,
        args: &[ImapArg],
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        let Some(subcmd) = args.first().and_then(ImapArg::as_str_lossy) else {
            write_flush(
                stream,
                format!("{tag} BAD UID requires a subcommand\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        };
        let rest = &args[1..];
        match subcmd.to_ascii_uppercase().as_str() {
            "FETCH" => self.handle_fetch(tag, rest, true, stream).await,
            "SEARCH" => self.handle_search(tag, rest, true, stream).await,
            "SORT" => self.handle_sort(tag, rest, true, stream).await,
            "THREAD" => self.handle_thread(tag, rest, true, stream).await,
            "STORE" => self.handle_store(tag, rest, true, stream).await,
            "COPY" => {
                self.handle_copy_or_move(tag, rest, true, false, stream)
                    .await
            }
            "MOVE" => {
                self.handle_copy_or_move(tag, rest, true, true, stream)
                    .await
            }
            "EXPUNGE" => self.handle_uid_expunge(tag, rest, stream).await,
            other => {
                let safe_other = sanitize_imap_text(other);
                write_flush(
                    stream,
                    format!("{tag} BAD Unsupported UID subcommand {safe_other}\r\n").as_bytes(),
                )
                .await
            }
        }
    }

    /// Load label name/ID lookup maps and rewrite `X-GM-RAW` queries inside `criteria`.
    async fn prepare_search_criteria(
        &self,
        criteria: &mut SearchKey,
    ) -> AppResult<HashMap<String, String>> {
        if !criteria_uses_label_lookup(criteria) {
            return Ok(HashMap::new());
        }
        let labels = self.state.store.list_labels().await?;
        let mut name_to_id = HashMap::with_capacity(labels.len() * 2);
        let mut id_to_name = HashMap::with_capacity(labels.len());
        for lbl in labels {
            let lower = lbl.name.to_ascii_lowercase();
            let hyphen = lower.replace('/', "-");
            name_to_id.insert(lower, lbl.id.clone());
            name_to_id.insert(hyphen, lbl.id.clone());
            id_to_name.insert(lbl.id, lbl.name);
        }
        rewrite_search_key_labels(criteria, &name_to_id);
        Ok(id_to_name)
    }

    async fn handle_search(
        &mut self,
        tag: &str,
        args: &[ImapArg],
        is_uid: bool,
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        let sel = match &self.auth {
            AuthState::Selected(s) => s.clone(),
            _ => {
                write_flush(
                    stream,
                    format!("{tag} NO No mailbox selected\r\n").as_bytes(),
                )
                .await?;
                return Ok(());
            }
        };

        // Optional RFC 4731 `RETURN (<return-opts>)`.
        let mut slice = args;
        let esearch_opts = if slice
            .first()
            .and_then(ImapArg::as_str_lossy)
            .is_some_and(|s| s.eq_ignore_ascii_case("RETURN"))
        {
            let Some(opt_list) = slice.get(1).and_then(ImapArg::as_list) else {
                write_flush(
                    stream,
                    format!("{tag} BAD SEARCH RETURN requires a parenthesized option list\r\n")
                        .as_bytes(),
                )
                .await?;
                return Ok(());
            };
            match parse_esearch_return_opts(opt_list) {
                Ok(opts) => {
                    slice = &slice[2..];
                    Some(opts)
                }
                Err(err) => {
                    let safe_err = sanitize_imap_text(&err.to_string());
                    write_flush(stream, format!("{tag} BAD {safe_err}\r\n").as_bytes()).await?;
                    return Ok(());
                }
            }
        } else {
            None
        };

        // Optional `CHARSET <charset>`.
        if slice
            .first()
            .and_then(ImapArg::as_str_lossy)
            .is_some_and(|s| s.eq_ignore_ascii_case("CHARSET"))
        {
            let Some(cs) = slice.get(1).and_then(ImapArg::as_str_lossy) else {
                write_flush(
                    stream,
                    format!("{tag} BAD CHARSET requires a charset name\r\n").as_bytes(),
                )
                .await?;
                return Ok(());
            };
            if !is_supported_charset(&cs) {
                write_flush(
                    stream,
                    format!("{tag} NO [BADCHARSET (UTF-8 US-ASCII)] Unsupported charset\r\n")
                        .as_bytes(),
                )
                .await?;
                return Ok(());
            }
            slice = &slice[2..];
        }

        // RFC 3501 §5.2: resolve sequence numbers strictly against `sel.snapshot` without
        // overwriting the snapshot or shifting sequence numbers of concurrently deleted messages.
        let max_seq = sel.snapshot.len() as u32;
        let max_uid = sel.snapshot.last().map(|e| e.uid).unwrap_or(0);
        let mut criteria = match parse_search_criteria(slice, max_seq, max_uid) {
            Ok(c) => c,
            Err(err) => {
                let safe_err = sanitize_imap_text(&err.to_string());
                write_flush(stream, format!("{tag} BAD {safe_err}\r\n").as_bytes()).await?;
                return Ok(());
            }
        };

        let label_id_to_name = self.prepare_search_criteria(&mut criteria).await?;
        let uses_modseq = criteria_uses_modseq(&criteria);
        if uses_modseq {
            self.condstore_enabled = true;
        }
        let needs_full_msg = criteria_needs_full_message(&criteria);
        let needs_raw = criteria_needs_raw_rfc2822(&criteria);

        // Look up live message state by message_id so flags/modseq are fresh and
        // concurrently deleted messages are skipped rather than shifting sequence numbers.
        let live_by_id: HashMap<String, ImapMessageEntry> = self
            .state
            .store
            .imap_list_messages(&sel.mailbox)
            .await?
            .into_iter()
            .map(|e| (e.message_id.clone(), e))
            .collect();

        let mut matched_ids = Vec::new();
        let mut max_matched_modseq: u64 = 0;

        for snap_entry in &sel.snapshot {
            let Some(live_entry) = live_by_id.get(&snap_entry.message_id) else {
                continue;
            };
            let mut effective = live_entry.clone();
            effective.seq = snap_entry.seq;
            effective.uid = snap_entry.uid;

            let full_msg = if needs_full_msg {
                let mut loaded = self.state.store.get_message(&snap_entry.message_id).await?;
                if needs_raw
                    && is_external_blob_store(self.state.blobs.as_ref())
                    && let Some(ref mut msg) = loaded
                {
                    msg.raw_rfc2822 = self.state.load_raw_rfc2822(msg).await?;
                }
                loaded
            } else {
                None
            };
            if eval_search_criteria(&criteria, &effective, full_msg.as_ref(), &label_id_to_name) {
                matched_ids.push(if is_uid { effective.uid } else { effective.seq });
                max_matched_modseq = max_matched_modseq.max(effective.modseq());
            }
        }

        let line = if let Some(opts) = esearch_opts {
            let mut resp = format!("* ESEARCH (TAG {})", imap_quote(tag));
            if is_uid {
                resp.push_str(" UID");
            }
            if opts.min
                && let Some(&first) = matched_ids.first()
            {
                resp.push_str(&format!(" MIN {first}"));
            }
            if opts.max
                && let Some(&last) = matched_ids.last()
            {
                resp.push_str(&format!(" MAX {last}"));
            }
            if opts.all && !matched_ids.is_empty() {
                resp.push_str(&format!(" ALL {}", format_sequence_set(&matched_ids)));
            }
            if opts.count {
                resp.push_str(&format!(" COUNT {}", matched_ids.len()));
            }
            if uses_modseq && !matched_ids.is_empty() {
                resp.push_str(&format!(" MODSEQ {max_matched_modseq}"));
            }
            resp.push_str(&format!("\r\n{tag} OK SEARCH completed\r\n"));
            resp
        } else {
            let nums: Vec<String> = matched_ids.into_iter().map(|n| n.to_string()).collect();
            if nums.is_empty() {
                format!("* SEARCH\r\n{tag} OK SEARCH completed\r\n")
            } else if uses_modseq {
                format!(
                    "* SEARCH {} (MODSEQ {max_matched_modseq})\r\n{tag} OK SEARCH completed\r\n",
                    nums.join(" ")
                )
            } else {
                format!(
                    "* SEARCH {}\r\n{tag} OK SEARCH completed\r\n",
                    nums.join(" ")
                )
            }
        };
        write_flush(stream, line.as_bytes()).await?;
        Ok(())
    }

    async fn handle_sort(
        &mut self,
        tag: &str,
        args: &[ImapArg],
        is_uid: bool,
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        let sel = match &self.auth {
            AuthState::Selected(s) => s.clone(),
            _ => {
                write_flush(
                    stream,
                    format!("{tag} NO No mailbox selected\r\n").as_bytes(),
                )
                .await?;
                return Ok(());
            }
        };
        if args.len() < 3 {
            write_flush(
                stream,
                format!("{tag} BAD SORT requires sort criteria, charset, and search criteria\r\n")
                    .as_bytes(),
            )
            .await?;
            return Ok(());
        }
        let Some(sort_list) = args[0].as_list() else {
            write_flush(
                stream,
                format!("{tag} BAD SORT criteria must be a parenthesized list\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        };
        let sort_criteria = match parse_sort_criteria(sort_list) {
            Ok(c) => c,
            Err(err) => {
                let safe_err = sanitize_imap_text(&err.to_string());
                write_flush(stream, format!("{tag} BAD {safe_err}\r\n").as_bytes()).await?;
                return Ok(());
            }
        };
        let Some(charset) = args[1].as_str_lossy() else {
            write_flush(
                stream,
                format!("{tag} BAD SORT requires a valid charset\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        };
        if !is_supported_charset(&charset) {
            write_flush(
                stream,
                format!("{tag} NO [BADCHARSET (UTF-8 US-ASCII)] Unsupported charset\r\n")
                    .as_bytes(),
            )
            .await?;
            return Ok(());
        }

        let max_seq = sel.snapshot.len() as u32;
        let max_uid = sel.snapshot.last().map(|e| e.uid).unwrap_or(0);
        let mut search_criteria = match parse_search_criteria(&args[2..], max_seq, max_uid) {
            Ok(c) => c,
            Err(err) => {
                let safe_err = sanitize_imap_text(&err.to_string());
                write_flush(stream, format!("{tag} BAD {safe_err}\r\n").as_bytes()).await?;
                return Ok(());
            }
        };

        let label_id_to_name = self.prepare_search_criteria(&mut search_criteria).await?;
        let needs_full_for_search = criteria_needs_full_message(&search_criteria);
        let needs_raw_for_search = criteria_needs_raw_rfc2822(&search_criteria);
        let needs_full_for_sort = sort_criteria_needs_full_message(&sort_criteria);
        let needs_raw_for_sort = sort_criteria_needs_raw_rfc2822(&sort_criteria);

        let live_by_id: HashMap<String, ImapMessageEntry> = self
            .state
            .store
            .imap_list_messages(&sel.mailbox)
            .await?
            .into_iter()
            .map(|e| (e.message_id.clone(), e))
            .collect();

        let mut matched_items: Vec<SortMessageItem> = Vec::new();
        for snap_entry in &sel.snapshot {
            let Some(live_entry) = live_by_id.get(&snap_entry.message_id) else {
                continue;
            };
            let mut effective = live_entry.clone();
            effective.seq = snap_entry.seq;
            effective.uid = snap_entry.uid;

            let mut full_msg = if needs_full_for_search {
                let mut loaded = self.state.store.get_message(&snap_entry.message_id).await?;
                if needs_raw_for_search
                    && is_external_blob_store(self.state.blobs.as_ref())
                    && let Some(ref mut msg) = loaded
                {
                    msg.raw_rfc2822 = self.state.load_raw_rfc2822(msg).await?;
                }
                loaded
            } else {
                None
            };

            if !eval_search_criteria(
                &search_criteria,
                &effective,
                full_msg.as_ref(),
                &label_id_to_name,
            ) {
                continue;
            }

            if needs_full_for_sort && full_msg.is_none() {
                full_msg = self.state.store.get_message(&snap_entry.message_id).await?;
            }
            if needs_raw_for_sort
                && is_external_blob_store(self.state.blobs.as_ref())
                && let Some(ref mut msg) = full_msg
                && msg.raw_rfc2822.is_empty()
            {
                msg.raw_rfc2822 = self.state.load_raw_rfc2822(msg).await?;
            }

            let sent_date_ms = if needs_raw_for_sort {
                message_sent_date_ms(full_msg.as_ref(), effective.internal_date_ms)
            } else {
                effective.internal_date_ms
            };
            let size = full_msg
                .as_ref()
                .filter(|m| !m.raw_rfc2822.is_empty())
                .map(|m| m.raw_rfc2822.len())
                .unwrap_or_else(|| effective.size_estimate.max(0) as usize);

            matched_items.push(SortMessageItem {
                out_id: if is_uid { effective.uid } else { effective.seq },
                seq: effective.seq,
                internal_date_ms: effective.internal_date_ms,
                sent_date_ms,
                size,
                from_mailbox: full_msg
                    .as_ref()
                    .map(|m| extract_first_mailbox(&m.from_addr))
                    .unwrap_or_default(),
                to_mailbox: full_msg
                    .as_ref()
                    .and_then(|m| m.to_addrs.first())
                    .map(|a| extract_first_mailbox(a))
                    .unwrap_or_default(),
                cc_mailbox: full_msg
                    .as_ref()
                    .and_then(|m| m.cc_addrs.first())
                    .map(|a| extract_first_mailbox(a))
                    .unwrap_or_default(),
                base_subject: full_msg
                    .as_ref()
                    .map(|m| extract_base_subject(&m.subject))
                    .unwrap_or_default(),
            });
        }

        let sorted_ids = sort_messages(matched_items, &sort_criteria);
        let line = if sorted_ids.is_empty() {
            format!("* SORT\r\n{tag} OK SORT completed\r\n")
        } else {
            let nums: Vec<String> = sorted_ids.into_iter().map(|n| n.to_string()).collect();
            format!("* SORT {}\r\n{tag} OK SORT completed\r\n", nums.join(" "))
        };
        write_flush(stream, line.as_bytes()).await?;
        Ok(())
    }

    async fn handle_thread(
        &mut self,
        tag: &str,
        args: &[ImapArg],
        is_uid: bool,
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        let sel = match &self.auth {
            AuthState::Selected(s) => s.clone(),
            _ => {
                write_flush(
                    stream,
                    format!("{tag} NO No mailbox selected\r\n").as_bytes(),
                )
                .await?;
                return Ok(());
            }
        };
        if args.len() < 3 {
            write_flush(
                stream,
                format!("{tag} BAD THREAD requires algorithm, charset, and search criteria\r\n")
                    .as_bytes(),
            )
            .await?;
            return Ok(());
        }
        let Some(algo_raw) = args[0].as_str_lossy() else {
            write_flush(
                stream,
                format!("{tag} BAD THREAD requires an algorithm name\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        };
        let algorithm = match parse_thread_algorithm(&algo_raw) {
            Ok(a) => a,
            Err(err) => {
                let safe_err = sanitize_imap_text(&err.to_string());
                write_flush(stream, format!("{tag} BAD {safe_err}\r\n").as_bytes()).await?;
                return Ok(());
            }
        };
        let Some(charset) = args[1].as_str_lossy() else {
            write_flush(
                stream,
                format!("{tag} BAD THREAD requires a valid charset\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        };
        if !is_supported_charset(&charset) {
            write_flush(
                stream,
                format!("{tag} NO [BADCHARSET (UTF-8 US-ASCII)] Unsupported charset\r\n")
                    .as_bytes(),
            )
            .await?;
            return Ok(());
        }

        let max_seq = sel.snapshot.len() as u32;
        let max_uid = sel.snapshot.last().map(|e| e.uid).unwrap_or(0);
        let mut search_criteria = match parse_search_criteria(&args[2..], max_seq, max_uid) {
            Ok(c) => c,
            Err(err) => {
                let safe_err = sanitize_imap_text(&err.to_string());
                write_flush(stream, format!("{tag} BAD {safe_err}\r\n").as_bytes()).await?;
                return Ok(());
            }
        };

        let label_id_to_name = self.prepare_search_criteria(&mut search_criteria).await?;
        let needs_full_for_search = criteria_needs_full_message(&search_criteria);
        let needs_raw_for_search = criteria_needs_raw_rfc2822(&search_criteria);

        let live_by_id: HashMap<String, ImapMessageEntry> = self
            .state
            .store
            .imap_list_messages(&sel.mailbox)
            .await?
            .into_iter()
            .map(|e| (e.message_id.clone(), e))
            .collect();

        let mut matched_items: Vec<ThreadMessageItem> = Vec::new();
        for snap_entry in &sel.snapshot {
            let Some(live_entry) = live_by_id.get(&snap_entry.message_id) else {
                continue;
            };
            let mut effective = live_entry.clone();
            effective.seq = snap_entry.seq;
            effective.uid = snap_entry.uid;

            let mut full_msg = if needs_full_for_search {
                let mut loaded = self.state.store.get_message(&snap_entry.message_id).await?;
                if needs_raw_for_search
                    && is_external_blob_store(self.state.blobs.as_ref())
                    && let Some(ref mut msg) = loaded
                {
                    msg.raw_rfc2822 = self.state.load_raw_rfc2822(msg).await?;
                }
                loaded
            } else {
                None
            };

            if !eval_search_criteria(
                &search_criteria,
                &effective,
                full_msg.as_ref(),
                &label_id_to_name,
            ) {
                continue;
            }

            if full_msg.is_none() {
                full_msg = self.state.store.get_message(&snap_entry.message_id).await?;
            }
            if is_external_blob_store(self.state.blobs.as_ref())
                && let Some(ref mut msg) = full_msg
                && msg.raw_rfc2822.is_empty()
            {
                msg.raw_rfc2822 = self.state.load_raw_rfc2822(msg).await?;
            }

            let sent_date_ms = message_sent_date_ms(full_msg.as_ref(), effective.internal_date_ms);
            let (base_subject, is_reply_or_fwd) = full_msg
                .as_ref()
                .map(|m| extract_base_subject_with_flag(&m.subject))
                .unwrap_or_default();
            let message_id = full_msg
                .as_ref()
                .and_then(|m| m.rfc822_message_id.as_deref())
                .and_then(normalize_message_id);
            let references = full_msg
                .as_ref()
                .map(extract_references_list)
                .unwrap_or_default();

            matched_items.push(ThreadMessageItem {
                out_id: if is_uid { effective.uid } else { effective.seq },
                seq: effective.seq,
                sent_date_ms,
                base_subject,
                is_reply_or_fwd,
                message_id,
                references,
                thread_id: effective.thread_id.clone(),
            });
        }

        let tree = match algorithm {
            ThreadAlgorithm::References => thread_references(&matched_items),
            ThreadAlgorithm::OrderedSubject => thread_ordered_subject(&matched_items),
        };
        let line = if tree.is_empty() {
            format!("* THREAD\r\n{tag} OK THREAD completed\r\n")
        } else {
            format!("* THREAD {tree}\r\n{tag} OK THREAD completed\r\n")
        };
        write_flush(stream, line.as_bytes()).await?;
        Ok(())
    }

    async fn handle_fetch(
        &mut self,
        tag: &str,
        args: &[ImapArg],
        is_uid: bool,
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        let sel = match &self.auth {
            AuthState::Selected(s) => s.clone(),
            _ => {
                write_flush(
                    stream,
                    format!("{tag} NO No mailbox selected\r\n").as_bytes(),
                )
                .await?;
                return Ok(());
            }
        };
        if args.len() < 2 {
            write_flush(
                stream,
                format!("{tag} BAD FETCH requires sequence set and data items\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }

        // Parse optional RFC 7162 FETCH modifiers: `(CHANGEDSINCE <n> [VANISHED])`.
        let modifiers = if let Some(mod_arg) = args.get(2) {
            match parse_fetch_modifiers(mod_arg, is_uid, self.qresync_enabled) {
                Ok(m) => m,
                Err(err) => {
                    let safe_err = sanitize_imap_text(&err.to_string());
                    write_flush(stream, format!("{tag} BAD {safe_err}\r\n").as_bytes()).await?;
                    return Ok(());
                }
            }
        } else {
            FetchModifiers::default()
        };

        // RFC 3501 §5.2: resolve client sequence numbers strictly against `sel.snapshot`.
        let seq_spec = args[0].as_str_lossy().unwrap_or_default();
        let max_val = if is_uid {
            sel.snapshot.last().map(|e| e.uid).unwrap_or(0)
        } else {
            sel.snapshot.len() as u32
        };
        let ranges = match parse_sequence_set(&seq_spec, max_val) {
            Ok(r) => r,
            Err(err) => {
                let safe_err = sanitize_imap_text(&err.to_string());
                write_flush(stream, format!("{tag} BAD {safe_err}\r\n").as_bytes()).await?;
                return Ok(());
            }
        };

        let mut items = expand_fetch_items(&args[1]);
        if is_uid && !items.iter().any(|i| i.eq_ignore_ascii_case("UID")) {
            items.insert(0, "UID".to_string());
        }
        if items.iter().any(|i| i.eq_ignore_ascii_case("MODSEQ"))
            || modifiers.changed_since.is_some()
        {
            self.condstore_enabled = true;
        }
        // RFC 7162 Section 3.1.4.1: CHANGEDSINCE implicitly includes MODSEQ in each FETCH response.
        if modifiers.changed_since.is_some()
            && !items.iter().any(|i| i.eq_ignore_ascii_case("MODSEQ"))
        {
            items.push("MODSEQ".to_string());
        }

        let live_entries = self.state.store.imap_list_messages(&sel.mailbox).await?;
        let live_by_id: HashMap<String, ImapMessageEntry> = live_entries
            .iter()
            .map(|e| (e.message_id.clone(), e.clone()))
            .collect();

        // RFC 7162 Section 3.2.6: UID FETCH ... (CHANGEDSINCE <n> VANISHED) emits
        // `* VANISHED (EARLIER) <uid_set>` for expunged UIDs matching the requested set.
        if modifiers.vanished
            && let Some(since) = modifiers.changed_since
        {
            let existing_uids: HashSet<u32> = live_entries.iter().map(|e| e.uid).collect();
            let mut vanished = self
                .state
                .store
                .imap_vanished_uids(&sel.mailbox, since)
                .await?;
            let vanished_max = max_val.max(vanished.last().copied().unwrap_or(0));
            let vanished_ranges =
                parse_sequence_set(&seq_spec, vanished_max).unwrap_or_else(|_| ranges.clone());
            vanished.retain(|uid| {
                !existing_uids.contains(uid) && seq_set_contains(&vanished_ranges, *uid)
            });
            if !vanished.is_empty() {
                let uid_set = format_sequence_set(&vanished);
                write_flush(
                    stream,
                    format!("* VANISHED (EARLIER) {uid_set}\r\n").as_bytes(),
                )
                .await?;
            }
        }

        let needs_labels_map = items.iter().any(|i| i.eq_ignore_ascii_case("X-GM-LABELS"));
        let label_name_map: HashMap<String, String> = if needs_labels_map {
            self.state
                .store
                .list_labels()
                .await?
                .into_iter()
                .map(|l| (l.id, l.name))
                .collect()
        } else {
            HashMap::new()
        };

        let needs_raw = items.iter().any(|i| fetch_item_needs_raw(i));
        let needs_msg = needs_raw || items.iter().any(|i| fetch_item_needs_stored_msg(i));
        let mark_seen = items.iter().any(|item| {
            let u = item.to_ascii_uppercase();
            u == "RFC822" || u == "RFC822.TEXT" || u.starts_with("BODY[")
        });

        let mut updated_snapshot = sel.snapshot.clone();

        for (idx, snap_entry) in sel.snapshot.iter().enumerate() {
            let key = if is_uid {
                snap_entry.uid
            } else {
                snap_entry.seq
            };
            if !seq_set_contains(&ranges, key) {
                continue;
            }
            let Some(live_entry) = live_by_id.get(&snap_entry.message_id) else {
                // Concurrently deleted: skip without shifting sequence numbers.
                continue;
            };
            let mut current_entry = live_entry.clone();
            current_entry.seq = snap_entry.seq;
            current_entry.uid = snap_entry.uid;

            if let Some(since) = modifiers.changed_since
                && current_entry.modseq() <= since
            {
                continue;
            }

            let msg_opt = if needs_msg {
                let Some(mut msg) = self
                    .state
                    .store
                    .get_message(&current_entry.message_id)
                    .await?
                else {
                    continue;
                };
                if needs_raw && is_external_blob_store(self.state.blobs.as_ref()) {
                    msg.raw_rfc2822 = self.state.load_raw_rfc2822(&msg).await?;
                }
                Some(msg)
            } else {
                None
            };

            let mut marked_seen_now = false;
            if mark_seen
                && !sel.read_only
                && current_entry.label_ids.iter().any(|l| l == LABEL_UNREAD)
                && let Ok(ImapStoreFlagsOutcome::Updated(updated)) = self
                    .state
                    .store
                    .imap_store_flags(
                        &current_entry.message_id,
                        ImapFlagAction::Add,
                        ImapFlagSet {
                            seen: true,
                            ..Default::default()
                        },
                        None,
                    )
                    .await
            {
                let updated = *updated;
                current_entry.label_ids = updated.label_ids;
                current_entry.history_id = updated.history_id.max(1);
                current_entry.is_answered = updated.is_answered;
                current_entry.is_deleted = updated.is_deleted;
                updated_snapshot[idx] = current_entry.clone();
                marked_seen_now = true;
            }

            let mut resp: Vec<u8> = Vec::new();
            resp.extend_from_slice(format!("* {} FETCH (", current_entry.seq).as_bytes());
            let mut first_item = true;
            let mut emitted_flags = false;
            let mut emitted_modseq = false;

            for item in &items {
                if !first_item {
                    resp.push(b' ');
                }
                first_item = false;
                if item.eq_ignore_ascii_case("FLAGS") {
                    emitted_flags = true;
                } else if item.eq_ignore_ascii_case("MODSEQ") {
                    emitted_modseq = true;
                }
                write_fetch_item(
                    &mut resp,
                    item,
                    &current_entry,
                    msg_opt.as_ref(),
                    &label_name_map,
                );
            }

            if mark_seen && !sel.read_only && !emitted_flags {
                if !first_item {
                    resp.push(b' ');
                }
                first_item = false;
                let flags_str = format_imap_flags(&current_entry);
                resp.extend_from_slice(format!("FLAGS ({flags_str})").as_bytes());
            }
            if marked_seen_now && self.condstore_enabled && !emitted_modseq {
                if !first_item {
                    resp.push(b' ');
                }
                resp.extend_from_slice(format!("MODSEQ ({})", current_entry.modseq()).as_bytes());
            }

            resp.extend_from_slice(b")\r\n");
            write_flush(stream, &resp).await?;
        }

        if let AuthState::Selected(ref mut s) = self.auth {
            s.snapshot = updated_snapshot;
        }

        write_flush(stream, format!("{tag} OK FETCH completed\r\n").as_bytes()).await?;
        Ok(())
    }

    async fn handle_store(
        &mut self,
        tag: &str,
        args: &[ImapArg],
        is_uid: bool,
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        let sel = match &self.auth {
            AuthState::Selected(s) => s.clone(),
            _ => {
                write_flush(
                    stream,
                    format!("{tag} NO No mailbox selected\r\n").as_bytes(),
                )
                .await?;
                return Ok(());
            }
        };
        if !self
            .require_scope_or_no(tag, AuthScope::Write, stream)
            .await?
        {
            return Ok(());
        }
        if sel.read_only {
            write_flush(
                stream,
                format!("{tag} NO Mailbox is selected read-only\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        if args.len() < 3 {
            write_flush(
                stream,
                format!("{tag} BAD STORE requires sequence set, action, and flags\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }

        // Optional RFC 7162 `(UNCHANGEDSINCE <modseq>)` modifier appears between seq-set and action.
        let (unchanged_since, action_idx) = if let Some(ImapArg::List(mods)) = args.get(1) {
            match parse_store_modifiers(mods) {
                Ok(us) => {
                    if us.is_some() {
                        self.condstore_enabled = true;
                    }
                    (us, 2usize)
                }
                Err(err) => {
                    let safe_err = sanitize_imap_text(&err.to_string());
                    write_flush(stream, format!("{tag} BAD {safe_err}\r\n").as_bytes()).await?;
                    return Ok(());
                }
            }
        } else {
            (None, 1usize)
        };

        if args.len() < action_idx + 2 {
            write_flush(
                stream,
                format!("{tag} BAD STORE requires sequence set, action, and flags\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }

        // RFC 3501 §5.2: resolve sequence numbers strictly against `sel.snapshot`.
        let seq_spec = args[0].as_str_lossy().unwrap_or_default();
        let max_val = if is_uid {
            sel.snapshot.last().map(|e| e.uid).unwrap_or(0)
        } else {
            sel.snapshot.len() as u32
        };
        let ranges = match parse_sequence_set(&seq_spec, max_val) {
            Ok(r) => r,
            Err(err) => {
                let safe_err = sanitize_imap_text(&err.to_string());
                write_flush(stream, format!("{tag} BAD {safe_err}\r\n").as_bytes()).await?;
                return Ok(());
            }
        };

        let action_raw = args[action_idx]
            .as_str_lossy()
            .unwrap_or_default()
            .to_ascii_uppercase();
        let silent = action_raw.ends_with(".SILENT");
        let base_action = action_raw.trim_end_matches(".SILENT");

        if matches!(base_action, "X-GM-LABELS" | "+X-GM-LABELS" | "-X-GM-LABELS") {
            let label_action = match base_action {
                "X-GM-LABELS" => ImapFlagAction::Replace,
                "+X-GM-LABELS" => ImapFlagAction::Add,
                "-X-GM-LABELS" => ImapFlagAction::Remove,
                _ => unreachable!(),
            };
            return self
                .handle_store_xgm_labels(
                    tag,
                    &sel,
                    &ranges,
                    label_action,
                    silent,
                    unchanged_since,
                    &args[action_idx + 1..],
                    is_uid,
                    stream,
                )
                .await;
        }

        let flag_action = match base_action {
            "FLAGS" => ImapFlagAction::Replace,
            "+FLAGS" => ImapFlagAction::Add,
            "-FLAGS" => ImapFlagAction::Remove,
            _ => {
                let safe_action = sanitize_imap_text(&action_raw);
                write_flush(
                    stream,
                    format!("{tag} BAD Unsupported STORE action {safe_action}\r\n").as_bytes(),
                )
                .await?;
                return Ok(());
            }
        };

        let flags_idx = action_idx + 1;
        let mut req_flags: Vec<String> = Vec::new();
        match &args[flags_idx] {
            ImapArg::List(list) => {
                for a in list {
                    if let Some(s) = a.as_str_lossy() {
                        req_flags.push(s);
                    }
                }
            }
            _ => {
                for a in &args[flags_idx..] {
                    if let Some(s) = a.as_str_lossy() {
                        req_flags.push(s);
                    }
                }
            }
        }

        let has_flag = |name: &str| req_flags.iter().any(|f| f.eq_ignore_ascii_case(name));
        let flag_set = ImapFlagSet {
            seen: has_flag("\\Seen"),
            flagged: has_flag("\\Flagged"),
            draft: has_flag("\\Draft"),
            answered: has_flag("\\Answered"),
            deleted: has_flag("\\Deleted"),
        };

        let mut updated_snapshot = sel.snapshot.clone();
        let mut modified_ids: Vec<u32> = Vec::new();

        for (idx, snap_entry) in sel.snapshot.iter().enumerate() {
            let key = if is_uid {
                snap_entry.uid
            } else {
                snap_entry.seq
            };
            if !seq_set_contains(&ranges, key) {
                continue;
            }

            // Atomic CAS against fresh DB `history_id` + skip concurrently deleted messages.
            let updated = match self
                .state
                .store
                .imap_store_flags(
                    &snap_entry.message_id,
                    flag_action,
                    flag_set,
                    unchanged_since,
                )
                .await?
            {
                ImapStoreFlagsOutcome::Updated(msg) => *msg,
                ImapStoreFlagsOutcome::Modified => {
                    modified_ids.push(key);
                    continue;
                }
                ImapStoreFlagsOutcome::NotFound => {
                    continue;
                }
            };

            let old_set: HashSet<&str> = snap_entry.label_ids.iter().map(String::as_str).collect();
            let new_set: HashSet<&str> = updated.label_ids.iter().map(String::as_str).collect();
            let added: Vec<String> = new_set
                .difference(&old_set)
                .map(|s| (*s).to_string())
                .collect();
            let removed: Vec<String> = old_set
                .difference(&new_set)
                .map(|s| (*s).to_string())
                .collect();
            if !added.is_empty() || !removed.is_empty() {
                self.state.events.publish(
                    EventSource::Imap,
                    MailEvent::MessageUpdated {
                        message_id: updated.id.clone(),
                        thread_id: updated.thread_id.clone(),
                        added_labels: added,
                        removed_labels: removed,
                    },
                );
            }

            let mut new_entry = snap_entry.clone();
            new_entry.label_ids = updated.label_ids;
            new_entry.history_id = updated.history_id.max(1);
            new_entry.is_answered = updated.is_answered;
            new_entry.is_deleted = updated.is_deleted;
            updated_snapshot[idx] = new_entry.clone();

            if !silent {
                let flags_str = format_imap_flags(&new_entry);
                let mut parts = Vec::new();
                if is_uid {
                    parts.push(format!("UID {}", new_entry.uid));
                }
                parts.push(format!("FLAGS ({flags_str})"));
                if self.condstore_enabled {
                    parts.push(format!("MODSEQ ({})", new_entry.modseq()));
                }
                let line = format!("* {} FETCH ({})\r\n", new_entry.seq, parts.join(" "));
                write_flush(stream, line.as_bytes()).await?;
            } else if unchanged_since.is_some() {
                // RFC 7162 Section 3.1.3: .SILENT with UNCHANGEDSINCE still reports new MODSEQ.
                let mut parts = Vec::new();
                if is_uid {
                    parts.push(format!("UID {}", new_entry.uid));
                }
                parts.push(format!("MODSEQ ({})", new_entry.modseq()));
                let line = format!("* {} FETCH ({})\r\n", new_entry.seq, parts.join(" "));
                write_flush(stream, line.as_bytes()).await?;
            }
        }

        if let AuthState::Selected(ref mut s) = self.auth {
            s.snapshot = updated_snapshot;
        }
        let ok_line = if !modified_ids.is_empty() {
            let mod_set = format_sequence_set(&modified_ids);
            format!("{tag} OK [MODIFIED {mod_set}] STORE completed\r\n")
        } else {
            format!("{tag} OK STORE completed\r\n")
        };
        write_flush(stream, ok_line.as_bytes()).await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_store_xgm_labels(
        &mut self,
        tag: &str,
        sel: &SelectedState,
        ranges: &[(u32, u32)],
        action: ImapFlagAction,
        silent: bool,
        unchanged_since: Option<u64>,
        value_args: &[ImapArg],
        is_uid: bool,
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        let mut req_labels: Vec<String> = Vec::new();
        match value_args.first() {
            Some(ImapArg::List(list)) => {
                for a in list {
                    if let Some(s) = a.as_str_lossy() {
                        req_labels.push(s);
                    }
                }
            }
            Some(_) => {
                for a in value_args {
                    if let Some(s) = a.as_str_lossy() {
                        req_labels.push(s);
                    }
                }
            }
            None => {}
        }

        let mut existing_labels = self.state.store.list_labels().await?;
        let mut target_label_ids: Vec<String> = Vec::new();
        let mut target_seen: HashSet<String> = HashSet::new();

        for raw in &req_labels {
            let trimmed = raw.trim();
            if trimmed.is_empty() || !is_valid_mailbox_name(trimmed) {
                write_flush(
                    stream,
                    format!("{tag} BAD Invalid X-GM-LABELS value\r\n").as_bytes(),
                )
                .await?;
                return Ok(());
            }

            if let Some(sys_id) = resolve_xgm_label_system_id(trimmed) {
                if target_seen.insert(sys_id.to_string()) {
                    target_label_ids.push(sys_id.to_string());
                }
                continue;
            }

            if trimmed.starts_with('\\') {
                let safe = sanitize_imap_text(trimmed);
                write_flush(
                    stream,
                    format!("{tag} NO Unsupported Gmail system label {safe}\r\n").as_bytes(),
                )
                .await?;
                return Ok(());
            }

            if existing_labels.iter().any(|l| {
                l.label_type != "user"
                    && (l.id.eq_ignore_ascii_case(trimmed) || l.name.eq_ignore_ascii_case(trimmed))
            }) {
                let safe = sanitize_imap_text(trimmed);
                write_flush(
                    stream,
                    format!("{tag} NO Unsupported Gmail system label {safe}\r\n").as_bytes(),
                )
                .await?;
                return Ok(());
            }

            // Custom user label: find existing by exact name, case-insensitive name, or user label ID.
            let found_id = existing_labels
                .iter()
                .find(|l| l.label_type == "user" && l.name == trimmed)
                .or_else(|| {
                    existing_labels
                        .iter()
                        .find(|l| l.label_type == "user" && l.name.eq_ignore_ascii_case(trimmed))
                })
                .or_else(|| {
                    existing_labels
                        .iter()
                        .find(|l| l.label_type == "user" && l.id == trimmed)
                })
                .map(|l| l.id.clone());

            let resolved_id = match found_id {
                Some(id) => Some(id),
                None if matches!(action, ImapFlagAction::Add | ImapFlagAction::Replace) => {
                    match self
                        .state
                        .store
                        .create_label(NewLabelInput {
                            name: trimmed.to_string(),
                            ..Default::default()
                        })
                        .await
                    {
                        Ok(created) => {
                            let id = created.id.clone();
                            existing_labels.push(created);
                            Some(id)
                        }
                        Err(AppError::Conflict(_)) => {
                            existing_labels = self.state.store.list_labels().await?;
                            existing_labels
                                .iter()
                                .find(|l| {
                                    l.label_type == "user" && l.name.eq_ignore_ascii_case(trimmed)
                                })
                                .map(|l| l.id.clone())
                        }
                        Err(err) => {
                            let safe_err = sanitize_imap_text(&err.to_string());
                            write_flush(stream, format!("{tag} NO {safe_err}\r\n").as_bytes())
                                .await?;
                            return Ok(());
                        }
                    }
                }
                None => None,
            };

            if let Some(id) = resolved_id
                && target_seen.insert(id.clone())
            {
                target_label_ids.push(id);
            }
        }

        let label_name_map: HashMap<String, String> = existing_labels
            .into_iter()
            .map(|l| (l.id, l.name))
            .collect();

        let mut updated_snapshot = sel.snapshot.clone();
        let mut modified_ids: Vec<u32> = Vec::new();

        for (idx, snap_entry) in sel.snapshot.iter().enumerate() {
            let key = if is_uid {
                snap_entry.uid
            } else {
                snap_entry.seq
            };
            if !seq_set_contains(ranges, key) {
                continue;
            }

            // Atomic CAS against fresh DB `history_id` + skip concurrently deleted messages.
            let updated = match self
                .state
                .store
                .imap_store_xgm_labels(
                    &snap_entry.message_id,
                    action,
                    &target_label_ids,
                    unchanged_since,
                )
                .await?
            {
                ImapStoreFlagsOutcome::Updated(msg) => *msg,
                ImapStoreFlagsOutcome::Modified => {
                    modified_ids.push(key);
                    continue;
                }
                ImapStoreFlagsOutcome::NotFound => {
                    continue;
                }
            };

            let old_set: HashSet<&str> = snap_entry.label_ids.iter().map(String::as_str).collect();
            let new_set: HashSet<&str> = updated.label_ids.iter().map(String::as_str).collect();
            let added: Vec<String> = new_set
                .difference(&old_set)
                .map(|s| (*s).to_string())
                .collect();
            let removed: Vec<String> = old_set
                .difference(&new_set)
                .map(|s| (*s).to_string())
                .collect();
            if !added.is_empty() || !removed.is_empty() {
                self.state.events.publish(
                    EventSource::Imap,
                    MailEvent::MessageUpdated {
                        message_id: updated.id.clone(),
                        thread_id: updated.thread_id.clone(),
                        added_labels: added,
                        removed_labels: removed,
                    },
                );
            }

            let mut new_entry = snap_entry.clone();
            new_entry.label_ids = updated.label_ids;
            new_entry.history_id = updated.history_id.max(1);
            new_entry.is_answered = updated.is_answered;
            new_entry.is_deleted = updated.is_deleted;
            updated_snapshot[idx] = new_entry.clone();

            if !silent {
                let labels_str = format_xgm_labels(&new_entry.label_ids, &label_name_map);
                let mut parts = Vec::new();
                if is_uid {
                    parts.push(format!("UID {}", new_entry.uid));
                }
                parts.push(format!("X-GM-LABELS ({labels_str})"));
                if self.condstore_enabled {
                    parts.push(format!("MODSEQ ({})", new_entry.modseq()));
                }
                let line = format!("* {} FETCH ({})\r\n", new_entry.seq, parts.join(" "));
                write_flush(stream, line.as_bytes()).await?;
            } else if unchanged_since.is_some() {
                // RFC 7162 Section 3.1.3: .SILENT with UNCHANGEDSINCE still reports new MODSEQ.
                let mut parts = Vec::new();
                if is_uid {
                    parts.push(format!("UID {}", new_entry.uid));
                }
                parts.push(format!("MODSEQ ({})", new_entry.modseq()));
                let line = format!("* {} FETCH ({})\r\n", new_entry.seq, parts.join(" "));
                write_flush(stream, line.as_bytes()).await?;
            }
        }

        if let AuthState::Selected(ref mut s) = self.auth {
            s.snapshot = updated_snapshot;
        }
        let ok_line = if !modified_ids.is_empty() {
            let mod_set = format_sequence_set(&modified_ids);
            format!("{tag} OK [MODIFIED {mod_set}] STORE completed\r\n")
        } else {
            format!("{tag} OK STORE completed\r\n")
        };
        write_flush(stream, ok_line.as_bytes()).await?;
        Ok(())
    }

    async fn handle_copy_or_move(
        &mut self,
        tag: &str,
        args: &[ImapArg],
        is_uid: bool,
        is_move: bool,
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        let sel = match &self.auth {
            AuthState::Selected(s) => s.clone(),
            _ => {
                write_flush(
                    stream,
                    format!("{tag} NO No mailbox selected\r\n").as_bytes(),
                )
                .await?;
                return Ok(());
            }
        };
        if !self
            .require_scope_or_no(tag, AuthScope::Write, stream)
            .await?
        {
            return Ok(());
        }
        if is_move && sel.read_only {
            write_flush(
                stream,
                format!("{tag} NO Mailbox is selected read-only\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        if args.len() < 2 {
            let cmd = if is_move { "MOVE" } else { "COPY" };
            write_flush(
                stream,
                format!("{tag} BAD {cmd} requires sequence set and destination mailbox\r\n")
                    .as_bytes(),
            )
            .await?;
            return Ok(());
        }

        // RFC 3501 §5.2: resolve sequence numbers strictly against `sel.snapshot`.
        let seq_spec = args[0].as_str_lossy().unwrap_or_default();
        let dst_mailbox = normalize_mailbox_name(&args[1].as_str_lossy().unwrap_or_default());
        let max_val = if is_uid {
            sel.snapshot.last().map(|e| e.uid).unwrap_or(0)
        } else {
            sel.snapshot.len() as u32
        };
        let ranges = match parse_sequence_set(&seq_spec, max_val) {
            Ok(r) => r,
            Err(err) => {
                let safe_err = sanitize_imap_text(&err.to_string());
                write_flush(stream, format!("{tag} BAD {safe_err}\r\n").as_bytes()).await?;
                return Ok(());
            }
        };

        let matched: Vec<&ImapMessageEntry> = sel
            .snapshot
            .iter()
            .filter(|e| seq_set_contains(&ranges, if is_uid { e.uid } else { e.seq }))
            .collect();
        let msg_ids: Vec<String> = matched.iter().map(|e| e.message_id.clone()).collect();

        let Some(dst_info) = self.state.store.imap_mailbox_info(&dst_mailbox).await? else {
            write_flush(
                stream,
                format!(
                    "{tag} NO [TRYCREATE] Mailbox does not exist: {}\r\n",
                    imap_quote(&dst_mailbox)
                )
                .as_bytes(),
            )
            .await?;
            return Ok(());
        };

        let pairs = self
            .state
            .store
            .imap_copy_or_move(&sel.mailbox, &dst_info.name, &msg_ids, is_move)
            .await?;

        let copyuid_code = if !pairs.is_empty() {
            let src_list: Vec<String> = pairs.iter().map(|(s, _)| s.to_string()).collect();
            let dst_list: Vec<String> = pairs.iter().map(|(_, d)| d.to_string()).collect();
            Some(format!(
                "[COPYUID {} {} {}]",
                dst_info.uid_validity,
                src_list.join(","),
                dst_list.join(",")
            ))
        } else {
            None
        };

        let moved_src_uids: HashSet<u32> = pairs.iter().map(|(s, _)| *s).collect();
        for entry in &matched {
            if !moved_src_uids.contains(&entry.uid) {
                continue;
            }
            self.state.events.publish(
                EventSource::Imap,
                MailEvent::MessageUpdated {
                    message_id: entry.message_id.clone(),
                    thread_id: entry.thread_id.clone(),
                    added_labels: dst_info.label_id.iter().cloned().collect(),
                    removed_labels: Vec::new(),
                },
            );
        }

        if is_move {
            let mut out = String::new();
            if let Some(code) = copyuid_code {
                out.push_str(&format!("* OK {code} Moved\r\n"));
            }
            let new_entries = self.state.store.imap_list_messages(&sel.mailbox).await?;
            let remaining: HashSet<&str> =
                new_entries.iter().map(|e| e.message_id.as_str()).collect();
            let mut removed_seqs: Vec<u32> = sel
                .snapshot
                .iter()
                .filter(|e| !remaining.contains(e.message_id.as_str()))
                .map(|e| e.seq)
                .collect();
            let removed_uids: Vec<u32> = sel
                .snapshot
                .iter()
                .filter(|e| !remaining.contains(e.message_id.as_str()))
                .map(|e| e.uid)
                .collect();
            removed_seqs.sort_unstable();
            if self.qresync_enabled {
                if !removed_uids.is_empty() {
                    let uid_set = format_sequence_set(&removed_uids);
                    out.push_str(&format!("* VANISHED {uid_set}\r\n"));
                }
            } else {
                for (idx, pre_seq) in removed_seqs.iter().enumerate() {
                    let adj = pre_seq.saturating_sub(idx as u32).max(1);
                    out.push_str(&format!("* {adj} EXPUNGE\r\n"));
                }
            }
            let after_expunge_count = sel.snapshot.len().saturating_sub(removed_seqs.len());
            if new_entries.len() > after_expunge_count {
                out.push_str(&format!("* {} EXISTS\r\n", new_entries.len()));
            }
            if let AuthState::Selected(ref mut s) = self.auth {
                s.snapshot = new_entries;
            }
            out.push_str(&format!("{tag} OK MOVE completed\r\n"));
            write_flush(stream, out.as_bytes()).await?;
        } else {
            let resp = match copyuid_code {
                Some(code) => format!("{tag} OK {code} COPY completed\r\n"),
                None => format!("{tag} OK COPY completed\r\n"),
            };
            write_flush(stream, resp.as_bytes()).await?;
        }
        Ok(())
    }

    async fn handle_idle(
        &mut self,
        tag: &str,
        stream: &mut BufReader<ImapStream>,
        shutdown: &mut watch::Receiver<bool>,
    ) -> AppResult<bool> {
        let mut event_rx = self.state.events.subscribe();
        write_flush(stream, b"+ idling\r\n").await?;

        // Flush any changes that occurred right before subscribing.
        self.flush_selected_updates(stream).await?;

        // Persistent buffer keeps partially received `DONE` bytes intact when `select!`
        // wakes on an `EventBus` update (cancel-safe framing).
        let mut line_buf: Vec<u8> = Vec::new();
        let idle_deadline = tokio::time::sleep(IMAP_IDLE_TIMEOUT);
        tokio::pin!(idle_deadline);

        loop {
            tokio::select! {
                line_res = read_crlf_line_into(stream, &mut line_buf, 4096) => {
                    match line_res {
                        Ok(Some(line)) if line.trim().eq_ignore_ascii_case("DONE") => {
                            write_flush(stream, format!("{tag} OK IDLE terminated\r\n").as_bytes()).await?;
                            return Ok(true);
                        }
                        Ok(Some(_)) => {
                            write_flush(stream, format!("{tag} BAD Expected DONE\r\n").as_bytes()).await?;
                            return Ok(true);
                        }
                        Ok(None) | Err(_) => return Ok(false),
                    }
                }
                ev = event_rx.recv() => {
                    match ev {
                        Ok(env) => {
                            let active_mb = self.state.mailbox_id();
                            if env.mailbox_id.is_empty()
                                || active_mb.is_empty()
                                || env.mailbox_id.eq_ignore_ascii_case(active_mb)
                            {
                                self.flush_selected_updates(stream).await?;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            self.flush_selected_updates(stream).await?;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            return Ok(false);
                        }
                    }
                }
                () = &mut idle_deadline => {
                    let _ = write_flush(stream, b"* BYE Autologout; idle for too long\r\n").await;
                    return Ok(false);
                }
                changed = shutdown.changed() => {
                    if changed.is_ok() && *shutdown.borrow() {
                        let _ = write_flush(stream, b"* BYE nogml IMAP server shutting down\r\n").await;
                        return Ok(false);
                    }
                }
            }
        }
    }

    /// Diff the selected mailbox against its cached snapshot and emit untagged `EXPUNGE`, `EXISTS`, and `FETCH (FLAGS ...)` responses.
    async fn flush_selected_updates(
        &mut self,
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        let sel = match &self.auth {
            AuthState::Selected(s) => s.clone(),
            _ => return Ok(()),
        };
        let new_entries = self.state.store.imap_list_messages(&sel.mailbox).await?;
        let mut out = String::new();

        // 1. Emit EXPUNGE for messages no longer in the mailbox.
        let new_by_id: HashMap<&str, &ImapMessageEntry> = new_entries
            .iter()
            .map(|e| (e.message_id.as_str(), e))
            .collect();
        let mut removed_seqs: Vec<u32> = sel
            .snapshot
            .iter()
            .filter(|old| !new_by_id.contains_key(old.message_id.as_str()))
            .map(|old| old.seq)
            .collect();
        let removed_uids: Vec<u32> = sel
            .snapshot
            .iter()
            .filter(|old| !new_by_id.contains_key(old.message_id.as_str()))
            .map(|old| old.uid)
            .collect();
        removed_seqs.sort_unstable();
        if self.qresync_enabled {
            if !removed_uids.is_empty() {
                let uid_set = format_sequence_set(&removed_uids);
                out.push_str(&format!("* VANISHED {uid_set}\r\n"));
            }
        } else {
            for (idx, pre_seq) in removed_seqs.iter().enumerate() {
                let adj = pre_seq.saturating_sub(idx as u32).max(1);
                out.push_str(&format!("* {adj} EXPUNGE\r\n"));
            }
        }

        let after_expunge_count = sel.snapshot.len().saturating_sub(removed_seqs.len());
        if new_entries.len() > after_expunge_count {
            out.push_str(&format!("* {} EXISTS\r\n", new_entries.len()));
        }

        // 2. Emit flag updates for existing messages whose flags changed.
        let old_by_id: HashMap<&str, &ImapMessageEntry> = sel
            .snapshot
            .iter()
            .map(|e| (e.message_id.as_str(), e))
            .collect();
        for entry in &new_entries {
            if let Some(old) = old_by_id.get(entry.message_id.as_str()) {
                let old_flags = format_imap_flags(old);
                let new_flags = format_imap_flags(entry);
                if old_flags != new_flags {
                    if self.qresync_enabled {
                        out.push_str(&format!(
                            "* {} FETCH (UID {} FLAGS ({new_flags}) MODSEQ ({}))\r\n",
                            entry.seq,
                            entry.uid,
                            entry.modseq()
                        ));
                    } else if self.condstore_enabled {
                        out.push_str(&format!(
                            "* {} FETCH (FLAGS ({new_flags}) MODSEQ ({}))\r\n",
                            entry.seq,
                            entry.modseq()
                        ));
                    } else {
                        out.push_str(&format!("* {} FETCH (FLAGS ({new_flags}))\r\n", entry.seq));
                    }
                }
            }
        }

        if let AuthState::Selected(ref mut s) = self.auth {
            s.snapshot = new_entries;
        }

        if !out.is_empty() {
            write_flush(stream, out.as_bytes()).await?;
        }
        Ok(())
    }
}

async fn write_flush<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> AppResult<()> {
    w.write_all(bytes)
        .await
        .map_err(|e| AppError::Internal(format!("IMAP write error: {e}")))?;
    w.flush()
        .await
        .map_err(|e| AppError::Internal(format!("IMAP flush error: {e}")))
}

/// Parse a decoded Google SASL `XOAUTH2` payload:
/// `user=<username>\x01auth=Bearer <access_token>\x01\x01`.
fn parse_xoauth2_payload(decoded: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(decoded).ok()?;
    let body = text.strip_suffix("\x01\x01")?;
    let mut user: Option<String> = None;
    let mut token: Option<String> = None;

    for part in body.split('\x01') {
        if let Some(u) = part.strip_prefix("user=") {
            let trimmed = u.trim();
            if !trimmed.is_empty() {
                user = Some(trimmed.to_string());
            }
        } else if let Some(auth) = part.strip_prefix("auth=") {
            let trimmed = auth.trim();
            if trimmed
                .get(..7)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("bearer "))
                && let Some(rest) = trimmed.get(7..)
            {
                let tok = rest.trim();
                if !tok.is_empty() {
                    token = Some(tok.to_string());
                }
            }
        }
    }

    match (user, token) {
        (Some(u), Some(t)) => Some((u, t)),
        _ => None,
    }
}

fn is_valid_mailbox_name(name: &str) -> bool {
    !name.is_empty() && !name.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

fn is_reserved_mailbox(name: &str) -> bool {
    name.eq_ignore_ascii_case("INBOX")
        || name.eq_ignore_ascii_case("[Gmail]")
        || name.starts_with("[Gmail]/")
        || name.starts_with("[gmail]/")
}

/// Format an `ImapMessageEntry`'s system flags (`\Seen`, `\Flagged`, `\Draft`, `\Answered`, `\Deleted`).
pub fn format_imap_flags(entry: &ImapMessageEntry) -> String {
    let mut flags = Vec::new();
    if !entry.label_ids.iter().any(|l| l == LABEL_UNREAD) {
        flags.push("\\Seen");
    }
    if entry.label_ids.iter().any(|l| l == LABEL_STARRED) {
        flags.push("\\Flagged");
    }
    if entry.label_ids.iter().any(|l| l == LABEL_DRAFT) {
        flags.push("\\Draft");
    }
    if entry.is_answered {
        flags.push("\\Answered");
    }
    if entry.is_deleted {
        flags.push("\\Deleted");
    }
    flags.join(" ")
}

fn expand_fetch_items(arg: &ImapArg) -> Vec<String> {
    let raw_items: Vec<String> = match arg {
        ImapArg::List(list) => list.iter().filter_map(ImapArg::as_str_lossy).collect(),
        other => other.as_str_lossy().into_iter().collect(),
    };
    let mut expanded = Vec::new();
    for item in raw_items {
        match item.to_ascii_uppercase().as_str() {
            "ALL" => expanded.extend(
                ["FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE"]
                    .into_iter()
                    .map(str::to_string),
            ),
            "FAST" => expanded.extend(
                ["FLAGS", "INTERNALDATE", "RFC822.SIZE"]
                    .into_iter()
                    .map(str::to_string),
            ),
            "FULL" => expanded.extend(
                ["FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", "BODY"]
                    .into_iter()
                    .map(str::to_string),
            ),
            _ => expanded.push(item),
        }
    }
    expanded
}

fn fetch_item_needs_raw(item: &str) -> bool {
    let upper = item.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "RFC822" | "RFC822.HEADER" | "RFC822.TEXT" | "ENVELOPE" | "BODYSTRUCTURE" | "BODY"
    ) || upper.starts_with("BODY[")
        || upper.starts_with("BODY.PEEK[")
}

fn fetch_item_needs_stored_msg(item: &str) -> bool {
    let upper = item.to_ascii_uppercase();
    fetch_item_needs_raw(item) || matches!(upper.as_str(), "X-GM-MSGID" | "X-GM-THRID")
}

fn write_fetch_item(
    out: &mut Vec<u8>,
    item: &str,
    entry: &ImapMessageEntry,
    msg: Option<&StoredMessage>,
    label_name_map: &HashMap<String, String>,
) {
    let upper = item.to_ascii_uppercase();
    let raw_bytes: &[u8] = msg.map(|m| m.raw_rfc2822.as_slice()).unwrap_or(&[]);
    match upper.as_str() {
        "UID" => {
            out.extend_from_slice(format!("UID {}", entry.uid).as_bytes());
        }
        "FLAGS" => {
            let flags = format_imap_flags(entry);
            out.extend_from_slice(format!("FLAGS ({flags})").as_bytes());
        }
        "MODSEQ" => {
            out.extend_from_slice(format!("MODSEQ ({})", entry.modseq()).as_bytes());
        }
        "INTERNALDATE" => {
            let ts = msg
                .map(|m| m.internal_date_ms)
                .unwrap_or(entry.internal_date_ms);
            let dt = format_internal_date(ts);
            out.extend_from_slice(format!("INTERNALDATE {}", imap_quote(&dt)).as_bytes());
        }
        "RFC822.SIZE" => {
            let size = if !raw_bytes.is_empty() {
                raw_bytes.len()
            } else {
                entry.size_estimate.max(0) as usize
            };
            out.extend_from_slice(format!("RFC822.SIZE {size}").as_bytes());
        }
        "RFC822" => {
            out.extend_from_slice(b"RFC822 ");
            append_literal(out, raw_bytes);
        }
        "RFC822.HEADER" => {
            let hdr = extract_body_section(raw_bytes, &parse_body_section("HEADER"), None);
            out.extend_from_slice(b"RFC822.HEADER ");
            append_literal(out, &hdr);
        }
        "RFC822.TEXT" => {
            let txt = extract_body_section(raw_bytes, &parse_body_section("TEXT"), None);
            out.extend_from_slice(b"RFC822.TEXT ");
            append_literal(out, &txt);
        }
        "ENVELOPE" => {
            let env = format_envelope(raw_bytes);
            out.extend_from_slice(format!("ENVELOPE {env}").as_bytes());
        }
        "BODYSTRUCTURE" => {
            let bs = format_bodystructure(raw_bytes, true);
            out.extend_from_slice(format!("BODYSTRUCTURE {bs}").as_bytes());
        }
        "BODY" => {
            let bs = format_bodystructure(raw_bytes, false);
            out.extend_from_slice(format!("BODY {bs}").as_bytes());
        }
        "X-GM-MSGID" => {
            let id = match msg {
                Some(m) => derive_xgm_u64(m.upstream_gmail_id.as_deref(), &m.id),
                None => derive_xgm_u64(None, &entry.message_id),
            };
            out.extend_from_slice(format!("X-GM-MSGID {id}").as_bytes());
        }
        "X-GM-THRID" => {
            let id = match msg {
                Some(m) => derive_xgm_u64(m.upstream_thread_id.as_deref(), &m.thread_id),
                None => derive_xgm_u64(None, &entry.thread_id),
            };
            out.extend_from_slice(format!("X-GM-THRID {id}").as_bytes());
        }
        "X-GM-LABELS" => {
            let labels = format_xgm_labels(&entry.label_ids, label_name_map);
            out.extend_from_slice(format!("X-GM-LABELS ({labels})").as_bytes());
        }
        _ => {
            // Handle BODY[...] and BODY.PEEK[...]<offset.count>
            if let Some((section_raw, partial)) = parse_body_fetch_item(item) {
                let section = parse_body_section(&section_raw);
                let data = extract_body_section(raw_bytes, &section, partial);
                let header_label = match partial {
                    Some((offset, _)) => format!("BODY[{section_raw}]<{offset}> "),
                    None => format!("BODY[{section_raw}] "),
                };
                out.extend_from_slice(header_label.as_bytes());
                append_literal(out, &data);
            } else {
                // Unknown item fallback
                out.extend_from_slice(format!("{upper} NIL").as_bytes());
            }
        }
    }
}

/// Parse `BODY[section]<off.len>` or `BODY.PEEK[section]<off.len>`.
fn parse_body_fetch_item(item: &str) -> Option<(String, Option<(usize, usize)>)> {
    let upper = item.to_ascii_uppercase();
    let rest = if upper.starts_with("BODY.PEEK[") {
        &item["BODY.PEEK[".len()..]
    } else if upper.starts_with("BODY[") {
        &item["BODY[".len()..]
    } else {
        return None;
    };
    let close_idx = rest.rfind(']')?;
    let section_raw = rest[..close_idx].to_string();
    let after = rest[close_idx + 1..].trim();
    let partial = if let Some(inner) = after.strip_prefix('<').and_then(|s| s.strip_suffix('>')) {
        let (off_s, len_s) = inner.split_once('.')?;
        let off = off_s.parse::<usize>().ok()?;
        let len = len_s.parse::<usize>().ok()?;
        Some((off, len))
    } else {
        None
    };
    Some((section_raw, partial))
}

/// Derive a deterministic 64-bit positive integer for `X-GM-MSGID` / `X-GM-THRID`.
pub fn derive_xgm_u64(upstream_hex: Option<&str>, fallback_id: &str) -> u64 {
    if let Some(hex) = upstream_hex
        && let Ok(v) = u64::from_str_radix(hex.trim(), 16)
        && v > 0
    {
        return v;
    }
    if let Ok(v) = u64::from_str_radix(fallback_id.trim(), 16)
        && v > 0
    {
        return v;
    }
    let digest = Sha256::digest(fallback_id.as_bytes());
    let raw = u64::from_be_bytes(digest[..8].try_into().unwrap_or([1; 8]));
    (raw & 0x7FFF_FFFF_FFFF_FFFF).max(1)
}

fn format_xgm_labels(label_ids: &[String], name_map: &HashMap<String, String>) -> String {
    let mut out = Vec::new();
    for id in label_ids {
        match id.as_str() {
            LABEL_UNREAD => continue,
            LABEL_INBOX => out.push("\\Inbox".to_string()),
            LABEL_SENT => out.push("\\Sent".to_string()),
            LABEL_DRAFT => out.push("\\Draft".to_string()),
            LABEL_TRASH => out.push("\\Trash".to_string()),
            LABEL_SPAM => out.push("\\Junk".to_string()),
            LABEL_STARRED => out.push("\\Starred".to_string()),
            LABEL_IMPORTANT => out.push("\\Important".to_string()),
            other => {
                let name = name_map.get(other).map(String::as_str).unwrap_or(other);
                out.push(imap_string(name));
            }
        }
    }
    out.join(" ")
}

/// Map a Gmail IMAP `X-GM-LABELS` system label token (`\Inbox`, `\Starred`, `\Important`,
/// `\Sent`, `\Draft`, `\Trash`, `\Spam`, `\Junk`) to its internal system label ID.
fn resolve_xgm_label_system_id(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "\\inbox" | "inbox" => Some(LABEL_INBOX),
        "\\starred" | "starred" => Some(LABEL_STARRED),
        "\\important" | "important" => Some(LABEL_IMPORTANT),
        "\\sent" | "sent" => Some(LABEL_SENT),
        "\\draft" | "\\drafts" | "draft" | "drafts" => Some(LABEL_DRAFT),
        "\\trash" | "trash" => Some(LABEL_TRASH),
        "\\spam" | "\\junk" | "spam" | "junk" => Some(LABEL_SPAM),
        _ => None,
    }
}

// ============================================================================
// RFC 5258 (`LIST-EXTENDED`), RFC 5819 (`LIST-STATUS`), RFC 4731 (`ESEARCH`)
// ============================================================================

#[derive(Debug, Default)]
struct ListExtendedArgs {
    has_selection_options: bool,
    select_subscribed: bool,
    select_special_use: bool,
    reference: String,
    patterns: Vec<String>,
    return_status_items: Option<Vec<String>>,
    return_subscribed: bool,
}

fn combine_list_pattern(reference: &str, pattern: &str) -> String {
    if reference.is_empty() {
        pattern.to_string()
    } else if reference.ends_with('/') || pattern.starts_with('/') {
        format!("{reference}{pattern}")
    } else {
        format!("{reference}/{pattern}")
    }
}

fn parse_list_extended_args(args: &[ImapArg]) -> AppResult<ListExtendedArgs> {
    if args.len() < 2 {
        return Err(AppError::BadRequest(
            "LIST requires reference and pattern".to_string(),
        ));
    }

    let mut parsed = ListExtendedArgs::default();
    let mut idx = 0usize;

    // Optional RFC 5258 leading selection options: `LIST (SUBSCRIBED ...) <ref> <pat>`
    if let Some(ImapArg::List(sel_opts)) = args.first() {
        parsed.has_selection_options = true;
        let mut has_recursivematch = false;
        let mut has_other_selector = false;
        for opt in sel_opts {
            let tok = opt
                .as_str_lossy()
                .ok_or_else(|| AppError::BadRequest("Invalid LIST selection option".to_string()))?;
            match tok.to_ascii_uppercase().as_str() {
                "SUBSCRIBED" => {
                    parsed.select_subscribed = true;
                    has_other_selector = true;
                }
                "SPECIAL-USE" => {
                    parsed.select_special_use = true;
                    has_other_selector = true;
                }
                "REMOTE" => {
                    has_other_selector = true;
                }
                "RECURSIVEMATCH" => {
                    has_recursivematch = true;
                }
                other => {
                    return Err(AppError::BadRequest(format!(
                        "Unsupported LIST selection option: {other}"
                    )));
                }
            }
        }
        if has_recursivematch && !has_other_selector {
            return Err(AppError::BadRequest(
                "LIST RECURSIVEMATCH requires another selection option".to_string(),
            ));
        }
        idx = 1;
    }

    if args.len() < idx + 2 {
        return Err(AppError::BadRequest(
            "LIST requires reference and pattern".to_string(),
        ));
    }

    parsed.reference = args[idx]
        .as_str_lossy()
        .ok_or_else(|| AppError::BadRequest("LIST reference must be a string".to_string()))?;

    match &args[idx + 1] {
        ImapArg::List(pats) => {
            if pats.is_empty() {
                return Err(AppError::BadRequest(
                    "LIST pattern list must not be empty".to_string(),
                ));
            }
            for pat in pats {
                let s = pat.as_str_lossy().ok_or_else(|| {
                    AppError::BadRequest("LIST pattern must be a string".to_string())
                })?;
                parsed.patterns.push(s);
            }
        }
        other => {
            let s = other
                .as_str_lossy()
                .ok_or_else(|| AppError::BadRequest("LIST pattern must be a string".to_string()))?;
            parsed.patterns.push(s);
        }
    }

    let rest = &args[idx + 2..];
    if !rest.is_empty() {
        let kw = rest[0].as_str_lossy().unwrap_or_default();
        if !kw.eq_ignore_ascii_case("RETURN") || rest.len() != 2 {
            return Err(AppError::BadRequest(
                "Expected RETURN (<options>) after LIST pattern".to_string(),
            ));
        }
        let ret_opts = rest[1].as_list().ok_or_else(|| {
            AppError::BadRequest("LIST RETURN options must be a parenthesized list".to_string())
        })?;
        let mut ri = 0usize;
        while ri < ret_opts.len() {
            let tok = ret_opts[ri]
                .as_str_lossy()
                .ok_or_else(|| AppError::BadRequest("Invalid LIST RETURN option".to_string()))?;
            match tok.to_ascii_uppercase().as_str() {
                "STATUS" => {
                    let status_list =
                        ret_opts
                            .get(ri + 1)
                            .and_then(ImapArg::as_list)
                            .ok_or_else(|| {
                                AppError::BadRequest(
                                    "LIST RETURN STATUS requires a parenthesized status item list"
                                        .to_string(),
                                )
                            })?;
                    if status_list.is_empty() {
                        return Err(AppError::BadRequest(
                            "LIST RETURN STATUS list must not be empty".to_string(),
                        ));
                    }
                    let mut items = Vec::with_capacity(status_list.len());
                    for item in status_list {
                        let key = item
                            .as_str_lossy()
                            .ok_or_else(|| {
                                AppError::BadRequest(
                                    "Invalid STATUS item in LIST RETURN".to_string(),
                                )
                            })?
                            .to_ascii_uppercase();
                        if !matches!(
                            key.as_str(),
                            "MESSAGES"
                                | "RECENT"
                                | "UIDNEXT"
                                | "UIDVALIDITY"
                                | "UNSEEN"
                                | "HIGHESTMODSEQ"
                        ) {
                            return Err(AppError::BadRequest(format!(
                                "Unsupported STATUS data item in LIST RETURN: {key}"
                            )));
                        }
                        items.push(key);
                    }
                    parsed.return_status_items = Some(items);
                    ri += 2;
                }
                "SPECIAL-USE" | "CHILDREN" => {
                    ri += 1;
                }
                "SUBSCRIBED" => {
                    parsed.return_subscribed = true;
                    ri += 1;
                }
                other => {
                    return Err(AppError::BadRequest(format!(
                        "Unsupported LIST RETURN option: {other}"
                    )));
                }
            }
        }
    }

    Ok(parsed)
}

fn format_status_pairs(
    info: &ImapMailboxInfo,
    items: &[String],
    highest_modseq: Option<u64>,
) -> Vec<String> {
    let mut pairs = Vec::with_capacity(items.len());
    for item in items {
        match item.as_str() {
            "MESSAGES" => pairs.push(format!("MESSAGES {}", info.messages)),
            "RECENT" => pairs.push("RECENT 0".to_string()),
            "UIDNEXT" => pairs.push(format!("UIDNEXT {}", info.uid_next)),
            "UIDVALIDITY" => pairs.push(format!("UIDVALIDITY {}", info.uid_validity)),
            "UNSEEN" => pairs.push(format!("UNSEEN {}", info.unseen)),
            "HIGHESTMODSEQ" => {
                pairs.push(format!("HIGHESTMODSEQ {}", highest_modseq.unwrap_or(1)));
            }
            _ => {}
        }
    }
    pairs
}

#[derive(Debug, Default, Clone, Copy)]
struct EsearchReturnOpts {
    min: bool,
    max: bool,
    all: bool,
    count: bool,
}

fn parse_esearch_return_opts(list: &[ImapArg]) -> AppResult<EsearchReturnOpts> {
    if list.is_empty() {
        // RFC 4731 Section 3.1: empty RETURN () is equivalent to RETURN (ALL).
        return Ok(EsearchReturnOpts {
            all: true,
            ..Default::default()
        });
    }
    let mut opts = EsearchReturnOpts::default();
    for item in list {
        let tok = item
            .as_str_lossy()
            .ok_or_else(|| AppError::BadRequest("Invalid SEARCH RETURN option".to_string()))?;
        match tok.to_ascii_uppercase().as_str() {
            "MIN" => opts.min = true,
            "MAX" => opts.max = true,
            "ALL" => opts.all = true,
            "COUNT" => opts.count = true,
            other => {
                return Err(AppError::BadRequest(format!(
                    "Unsupported SEARCH RETURN option: {other}"
                )));
            }
        }
    }
    Ok(opts)
}

// ============================================================================
// RFC 7162 (`CONDSTORE` / `QRESYNC`) Parameter & Modifier Parsers
// ============================================================================

#[derive(Debug, Clone)]
struct QresyncSelectParam {
    uid_validity: u32,
    last_modseq: u64,
    known_uids: Option<Vec<(u32, u32)>>,
}

/// Parse RFC 7162 `SELECT`/`EXAMINE` `QRESYNC (<uidvalidity> <modseq> [<known-uids> [<seq-match-data>]])`.
fn parse_qresync_select_param(list: &[ImapArg]) -> AppResult<QresyncSelectParam> {
    if list.len() < 2 || list.len() > 4 {
        return Err(AppError::BadRequest(
            "QRESYNC requires (<uidvalidity> <modseq> [<known-uids> [<seq-match-data>]])"
                .to_string(),
        ));
    }
    let uv_raw = list[0]
        .as_str_lossy()
        .ok_or_else(|| AppError::BadRequest("Invalid QRESYNC uidvalidity".to_string()))?;
    let uid_validity = uv_raw
        .parse::<u32>()
        .ok()
        .filter(|&v| v >= 1)
        .ok_or_else(|| AppError::BadRequest(format!("Invalid QRESYNC uidvalidity: {uv_raw}")))?;

    let modseq_raw = list[1]
        .as_str_lossy()
        .ok_or_else(|| AppError::BadRequest("Invalid QRESYNC modseq".to_string()))?;
    let last_modseq = modseq_raw
        .parse::<u64>()
        .map_err(|_| AppError::BadRequest(format!("Invalid QRESYNC modseq: {modseq_raw}")))?;

    let known_uids = if let Some(arg) = list.get(2) {
        if arg.as_list().is_some() {
            // Optional known-uids omitted; 3rd element is seq-match-data.
            None
        } else {
            let spec = arg
                .as_str_lossy()
                .ok_or_else(|| AppError::BadRequest("Invalid QRESYNC known-uids".to_string()))?;
            if spec.contains('*') {
                return Err(AppError::BadRequest(
                    "QRESYNC known-uids must not contain '*'".to_string(),
                ));
            }
            Some(parse_sequence_set(&spec, u32::MAX)?)
        }
    } else {
        None
    };

    Ok(QresyncSelectParam {
        uid_validity,
        last_modseq,
        known_uids,
    })
}

#[derive(Debug, Clone, Default)]
struct FetchModifiers {
    changed_since: Option<u64>,
    vanished: bool,
}

/// Parse RFC 7162 `FETCH` / `UID FETCH` modifiers: `(CHANGEDSINCE <modseq> [VANISHED])`.
fn parse_fetch_modifiers(
    arg: &ImapArg,
    is_uid: bool,
    qresync_enabled: bool,
) -> AppResult<FetchModifiers> {
    let list = arg
        .as_list()
        .ok_or_else(|| AppError::BadRequest("FETCH modifiers must be a list".to_string()))?;
    let mut out = FetchModifiers::default();
    let mut i = 0usize;
    while i < list.len() {
        let key = list[i]
            .as_str_lossy()
            .ok_or_else(|| AppError::BadRequest("Invalid FETCH modifier".to_string()))?;
        match key.to_ascii_uppercase().as_str() {
            "CHANGEDSINCE" => {
                let raw = list
                    .get(i + 1)
                    .and_then(ImapArg::as_str_lossy)
                    .ok_or_else(|| {
                        AppError::BadRequest("CHANGEDSINCE requires a modseq argument".to_string())
                    })?;
                let v = raw
                    .parse::<u64>()
                    .map_err(|_| AppError::BadRequest(format!("Invalid CHANGEDSINCE: {raw}")))?;
                out.changed_since = Some(v);
                i += 2;
            }
            "VANISHED" => {
                if !is_uid {
                    return Err(AppError::BadRequest(
                        "VANISHED modifier is only valid with UID FETCH".to_string(),
                    ));
                }
                if !qresync_enabled {
                    return Err(AppError::BadRequest(
                        "VANISHED modifier requires ENABLE QRESYNC first".to_string(),
                    ));
                }
                out.vanished = true;
                i += 1;
            }
            other => {
                return Err(AppError::BadRequest(format!(
                    "Unsupported FETCH modifier: {other}"
                )));
            }
        }
    }
    if out.vanished && out.changed_since.is_none() {
        return Err(AppError::BadRequest(
            "VANISHED modifier requires CHANGEDSINCE".to_string(),
        ));
    }
    Ok(out)
}

/// Parse RFC 7162 `STORE` / `UID STORE` modifiers: `(UNCHANGEDSINCE <modseq>)`.
fn parse_store_modifiers(list: &[ImapArg]) -> AppResult<Option<u64>> {
    let mut unchanged_since = None;
    let mut i = 0usize;
    while i < list.len() {
        let key = list[i]
            .as_str_lossy()
            .ok_or_else(|| AppError::BadRequest("Invalid STORE modifier".to_string()))?;
        match key.to_ascii_uppercase().as_str() {
            "UNCHANGEDSINCE" => {
                let raw = list
                    .get(i + 1)
                    .and_then(ImapArg::as_str_lossy)
                    .ok_or_else(|| {
                        AppError::BadRequest(
                            "UNCHANGEDSINCE requires a modseq argument".to_string(),
                        )
                    })?;
                let v = raw
                    .parse::<u64>()
                    .map_err(|_| AppError::BadRequest(format!("Invalid UNCHANGEDSINCE: {raw}")))?;
                unchanged_since = Some(v);
                i += 2;
            }
            other => {
                return Err(AppError::BadRequest(format!(
                    "Unsupported STORE modifier: {other}"
                )));
            }
        }
    }
    Ok(unchanged_since)
}

// ============================================================================
// IMAP SEARCH Criteria AST & Evaluator
// ============================================================================

#[derive(Debug, Clone)]
enum SearchKey {
    All,
    Seen,
    Unseen,
    Flagged,
    Unflagged,
    Deleted,
    Undeleted,
    Draft,
    Undraft,
    Answered,
    Unanswered,
    Recent,
    New,
    Old,
    SeqSet(Vec<(u32, u32)>),
    UidSet(Vec<(u32, u32)>),
    From(String),
    To(String),
    Cc(String),
    Bcc(String),
    Subject(String),
    Body(String),
    Text(String),
    Header(String, String),
    Since(chrono::NaiveDate),
    Before(chrono::NaiveDate),
    On(chrono::NaiveDate),
    SentSince(chrono::NaiveDate),
    SentBefore(chrono::NaiveDate),
    SentOn(chrono::NaiveDate),
    Larger(usize),
    Smaller(usize),
    Modseq(u64),
    XGmMsgId(u64),
    XGmThrId(u64),
    XGmRaw(SearchQuery),
    XGmLabels(String),
    Not(Box<SearchKey>),
    Or(Box<SearchKey>, Box<SearchKey>),
    And(Vec<SearchKey>),
}

fn parse_search_criteria(args: &[ImapArg], max_seq: u32, max_uid: u32) -> AppResult<SearchKey> {
    parse_search_criteria_depth(args, max_seq, max_uid, 0)
}

fn parse_search_criteria_depth(
    args: &[ImapArg],
    max_seq: u32,
    max_uid: u32,
    depth: usize,
) -> AppResult<SearchKey> {
    if depth > MAX_SEARCH_DEPTH {
        return Err(AppError::BadRequest(format!(
            "SEARCH criteria exceeds maximum nesting depth of {MAX_SEARCH_DEPTH}"
        )));
    }
    if args.is_empty() {
        return Ok(SearchKey::All);
    }
    let mut pos = 0usize;
    let mut keys = Vec::new();
    while pos < args.len() {
        keys.push(parse_one_search_key(
            args, &mut pos, max_seq, max_uid, depth,
        )?);
    }
    if keys.len() == 1 {
        Ok(keys.pop().unwrap())
    } else {
        Ok(SearchKey::And(keys))
    }
}

fn parse_one_search_key(
    args: &[ImapArg],
    pos: &mut usize,
    max_seq: u32,
    max_uid: u32,
    depth: usize,
) -> AppResult<SearchKey> {
    if depth > MAX_SEARCH_DEPTH {
        return Err(AppError::BadRequest(format!(
            "SEARCH criteria exceeds maximum nesting depth of {MAX_SEARCH_DEPTH}"
        )));
    }
    if *pos >= args.len() {
        return Err(AppError::BadRequest(
            "Unexpected end of SEARCH criteria".to_string(),
        ));
    }
    let arg = &args[*pos];
    *pos += 1;

    if let ImapArg::List(sub) = arg {
        return parse_search_criteria_depth(sub, max_seq, max_uid, depth + 1);
    }

    let tok = arg
        .as_str_lossy()
        .ok_or_else(|| AppError::BadRequest("Invalid SEARCH token".to_string()))?;
    let upper = tok.to_ascii_uppercase();

    let next_str = |args: &[ImapArg], pos: &mut usize, label: &str| -> AppResult<String> {
        let s = args
            .get(*pos)
            .and_then(ImapArg::as_str_lossy)
            .ok_or_else(|| AppError::BadRequest(format!("SEARCH {label} requires an argument")))?;
        *pos += 1;
        Ok(s)
    };

    match upper.as_str() {
        "ALL" => Ok(SearchKey::All),
        "SEEN" => Ok(SearchKey::Seen),
        "UNSEEN" => Ok(SearchKey::Unseen),
        "FLAGGED" => Ok(SearchKey::Flagged),
        "UNFLAGGED" => Ok(SearchKey::Unflagged),
        "DELETED" => Ok(SearchKey::Deleted),
        "UNDELETED" => Ok(SearchKey::Undeleted),
        "DRAFT" => Ok(SearchKey::Draft),
        "UNDRAFT" => Ok(SearchKey::Undraft),
        "ANSWERED" => Ok(SearchKey::Answered),
        "UNANSWERED" => Ok(SearchKey::Unanswered),
        "RECENT" => Ok(SearchKey::Recent),
        "NEW" => Ok(SearchKey::New),
        "OLD" => Ok(SearchKey::Old),
        "UID" => {
            let spec = next_str(args, pos, "UID")?;
            Ok(SearchKey::UidSet(parse_sequence_set(&spec, max_uid)?))
        }
        "FROM" => Ok(SearchKey::From(next_str(args, pos, "FROM")?)),
        "TO" => Ok(SearchKey::To(next_str(args, pos, "TO")?)),
        "CC" => Ok(SearchKey::Cc(next_str(args, pos, "CC")?)),
        "BCC" => Ok(SearchKey::Bcc(next_str(args, pos, "BCC")?)),
        "SUBJECT" => Ok(SearchKey::Subject(next_str(args, pos, "SUBJECT")?)),
        "BODY" => Ok(SearchKey::Body(next_str(args, pos, "BODY")?)),
        "TEXT" => Ok(SearchKey::Text(next_str(args, pos, "TEXT")?)),
        "X-GM-RAW" => {
            let raw = next_str(args, pos, "X-GM-RAW")?;
            let parsed = try_parse_gmail_query(&raw)?;
            Ok(SearchKey::XGmRaw(parsed))
        }
        "X-GM-LABELS" => {
            let Some(next_arg) = args.get(*pos) else {
                return Err(AppError::BadRequest(
                    "SEARCH X-GM-LABELS requires an argument".to_string(),
                ));
            };
            *pos += 1;
            match next_arg {
                ImapArg::List(items) => {
                    if items.is_empty() {
                        return Err(AppError::BadRequest(
                            "SEARCH X-GM-LABELS list must not be empty".to_string(),
                        ));
                    }
                    let mut keys = Vec::with_capacity(items.len());
                    for item in items {
                        let lbl = item.as_str_lossy().ok_or_else(|| {
                            AppError::BadRequest("Invalid X-GM-LABELS criterion".to_string())
                        })?;
                        keys.push(SearchKey::XGmLabels(lbl));
                    }
                    if keys.len() == 1 {
                        Ok(keys.pop().unwrap())
                    } else {
                        Ok(SearchKey::And(keys))
                    }
                }
                other => {
                    let lbl = other.as_str_lossy().ok_or_else(|| {
                        AppError::BadRequest("SEARCH X-GM-LABELS requires an argument".to_string())
                    })?;
                    Ok(SearchKey::XGmLabels(lbl))
                }
            }
        }
        "HEADER" => {
            let field = next_str(args, pos, "HEADER field")?;
            let val = next_str(args, pos, "HEADER value")?;
            Ok(SearchKey::Header(field, val))
        }
        "SINCE" => {
            let raw = next_str(args, pos, "SINCE")?;
            let d = parse_imap_search_date(&raw)
                .ok_or_else(|| AppError::BadRequest(format!("Invalid date: {raw}")))?;
            Ok(SearchKey::Since(d))
        }
        "BEFORE" => {
            let raw = next_str(args, pos, "BEFORE")?;
            let d = parse_imap_search_date(&raw)
                .ok_or_else(|| AppError::BadRequest(format!("Invalid date: {raw}")))?;
            Ok(SearchKey::Before(d))
        }
        "ON" => {
            let raw = next_str(args, pos, "ON")?;
            let d = parse_imap_search_date(&raw)
                .ok_or_else(|| AppError::BadRequest(format!("Invalid date: {raw}")))?;
            Ok(SearchKey::On(d))
        }
        "SENTSINCE" => {
            let raw = next_str(args, pos, "SENTSINCE")?;
            let d = parse_imap_search_date(&raw)
                .ok_or_else(|| AppError::BadRequest(format!("Invalid date: {raw}")))?;
            Ok(SearchKey::SentSince(d))
        }
        "SENTBEFORE" => {
            let raw = next_str(args, pos, "SENTBEFORE")?;
            let d = parse_imap_search_date(&raw)
                .ok_or_else(|| AppError::BadRequest(format!("Invalid date: {raw}")))?;
            Ok(SearchKey::SentBefore(d))
        }
        "SENTON" => {
            let raw = next_str(args, pos, "SENTON")?;
            let d = parse_imap_search_date(&raw)
                .ok_or_else(|| AppError::BadRequest(format!("Invalid date: {raw}")))?;
            Ok(SearchKey::SentOn(d))
        }
        "LARGER" => {
            let raw = next_str(args, pos, "LARGER")?;
            let n = raw
                .parse::<usize>()
                .map_err(|_| AppError::BadRequest(format!("Invalid LARGER size: {raw}")))?;
            Ok(SearchKey::Larger(n))
        }
        "SMALLER" => {
            let raw = next_str(args, pos, "SMALLER")?;
            let n = raw
                .parse::<usize>()
                .map_err(|_| AppError::BadRequest(format!("Invalid SMALLER size: {raw}")))?;
            Ok(SearchKey::Smaller(n))
        }
        "MODSEQ" => {
            // RFC 7162 Section 3.1.5: `MODSEQ [<entry-name> <entry-type-req>] <mod-sequence-valzer>`
            let first = next_str(args, pos, "MODSEQ")?;
            let raw = if let Ok(n) = first.parse::<u64>() {
                return Ok(SearchKey::Modseq(n));
            } else {
                // Skip optional entry-type-req ("shared" | "priv" | "all") then read modseq.
                let _entry_type = next_str(args, pos, "MODSEQ entry-type")?;
                next_str(args, pos, "MODSEQ value")?
            };
            let n = raw
                .parse::<u64>()
                .map_err(|_| AppError::BadRequest(format!("Invalid MODSEQ: {raw}")))?;
            Ok(SearchKey::Modseq(n))
        }
        "X-GM-MSGID" => {
            let raw = next_str(args, pos, "X-GM-MSGID")?;
            let n = raw
                .parse::<u64>()
                .map_err(|_| AppError::BadRequest(format!("Invalid X-GM-MSGID: {raw}")))?;
            Ok(SearchKey::XGmMsgId(n))
        }
        "X-GM-THRID" => {
            let raw = next_str(args, pos, "X-GM-THRID")?;
            let n = raw
                .parse::<u64>()
                .map_err(|_| AppError::BadRequest(format!("Invalid X-GM-THRID: {raw}")))?;
            Ok(SearchKey::XGmThrId(n))
        }
        "NOT" => {
            let inner = parse_one_search_key(args, pos, max_seq, max_uid, depth + 1)?;
            Ok(SearchKey::Not(Box::new(inner)))
        }
        "OR" => {
            let left = parse_one_search_key(args, pos, max_seq, max_uid, depth + 1)?;
            let right = parse_one_search_key(args, pos, max_seq, max_uid, depth + 1)?;
            Ok(SearchKey::Or(Box::new(left), Box::new(right)))
        }
        _ => {
            // Bare sequence set
            if tok
                .chars()
                .all(|c| c.is_ascii_digit() || c == ':' || c == ',' || c == '*')
            {
                Ok(SearchKey::SeqSet(parse_sequence_set(&tok, max_seq)?))
            } else {
                Err(AppError::BadRequest(format!(
                    "Unsupported SEARCH criterion: {tok}"
                )))
            }
        }
    }
}

fn criteria_uses_modseq(key: &SearchKey) -> bool {
    match key {
        SearchKey::Modseq(_) => true,
        SearchKey::Not(inner) => criteria_uses_modseq(inner),
        SearchKey::Or(a, b) => criteria_uses_modseq(a) || criteria_uses_modseq(b),
        SearchKey::And(list) => list.iter().any(criteria_uses_modseq),
        _ => false,
    }
}

fn criteria_uses_label_lookup(key: &SearchKey) -> bool {
    match key {
        SearchKey::XGmRaw(_) | SearchKey::XGmLabels(_) => true,
        SearchKey::Not(inner) => criteria_uses_label_lookup(inner),
        SearchKey::Or(a, b) => criteria_uses_label_lookup(a) || criteria_uses_label_lookup(b),
        SearchKey::And(list) => list.iter().any(criteria_uses_label_lookup),
        _ => false,
    }
}

fn rewrite_search_key_labels(key: &mut SearchKey, name_to_id: &HashMap<String, String>) {
    match key {
        SearchKey::XGmRaw(q) => {
            let owned = std::mem::take(q);
            *q = rewrite_query_labels(owned, name_to_id);
        }
        SearchKey::Not(inner) => rewrite_search_key_labels(inner, name_to_id),
        SearchKey::Or(a, b) => {
            rewrite_search_key_labels(a, name_to_id);
            rewrite_search_key_labels(b, name_to_id);
        }
        SearchKey::And(list) => {
            for item in list {
                rewrite_search_key_labels(item, name_to_id);
            }
        }
        _ => {}
    }
}

fn criteria_needs_full_message(key: &SearchKey) -> bool {
    match key {
        SearchKey::From(_)
        | SearchKey::To(_)
        | SearchKey::Cc(_)
        | SearchKey::Bcc(_)
        | SearchKey::Subject(_)
        | SearchKey::Body(_)
        | SearchKey::Text(_)
        | SearchKey::Header(_, _)
        | SearchKey::SentSince(_)
        | SearchKey::SentBefore(_)
        | SearchKey::SentOn(_)
        | SearchKey::XGmMsgId(_)
        | SearchKey::XGmThrId(_)
        | SearchKey::XGmRaw(_) => true,
        SearchKey::Not(inner) => criteria_needs_full_message(inner),
        SearchKey::Or(a, b) => criteria_needs_full_message(a) || criteria_needs_full_message(b),
        SearchKey::And(list) => list.iter().any(criteria_needs_full_message),
        _ => false,
    }
}

fn criteria_needs_raw_rfc2822(key: &SearchKey) -> bool {
    match key {
        SearchKey::Body(_)
        | SearchKey::Text(_)
        | SearchKey::Header(_, _)
        | SearchKey::SentSince(_)
        | SearchKey::SentBefore(_)
        | SearchKey::SentOn(_) => true,
        SearchKey::XGmRaw(q) => query_uses_filename(q),
        SearchKey::Not(inner) => criteria_needs_raw_rfc2822(inner),
        SearchKey::Or(a, b) => criteria_needs_raw_rfc2822(a) || criteria_needs_raw_rfc2822(b),
        SearchKey::And(list) => list.iter().any(criteria_needs_raw_rfc2822),
        _ => false,
    }
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

fn eval_search_criteria(
    key: &SearchKey,
    entry: &ImapMessageEntry,
    msg: Option<&StoredMessage>,
    label_id_to_name: &HashMap<String, String>,
) -> bool {
    let internal_date = Utc
        .timestamp_millis_opt(entry.internal_date_ms)
        .single()
        .map(|dt| dt.date_naive());

    match key {
        SearchKey::All => true,
        SearchKey::Seen => !entry.label_ids.iter().any(|l| l == LABEL_UNREAD),
        SearchKey::Unseen => entry.label_ids.iter().any(|l| l == LABEL_UNREAD),
        SearchKey::Flagged => entry.label_ids.iter().any(|l| l == LABEL_STARRED),
        SearchKey::Unflagged => !entry.label_ids.iter().any(|l| l == LABEL_STARRED),
        SearchKey::Deleted => entry.is_deleted,
        SearchKey::Undeleted => !entry.is_deleted,
        SearchKey::Draft => entry.label_ids.iter().any(|l| l == LABEL_DRAFT),
        SearchKey::Undraft => !entry.label_ids.iter().any(|l| l == LABEL_DRAFT),
        SearchKey::Answered => entry.is_answered,
        SearchKey::Unanswered => !entry.is_answered,
        SearchKey::Recent | SearchKey::New => false,
        SearchKey::Old => true,
        SearchKey::SeqSet(ranges) => seq_set_contains(ranges, entry.seq),
        SearchKey::UidSet(ranges) => seq_set_contains(ranges, entry.uid),
        SearchKey::From(s) => msg.is_some_and(|m| contains_ci(&m.from_addr, s)),
        SearchKey::To(s) => msg.is_some_and(|m| m.to_addrs.iter().any(|a| contains_ci(a, s))),
        SearchKey::Cc(s) => msg.is_some_and(|m| m.cc_addrs.iter().any(|a| contains_ci(a, s))),
        SearchKey::Bcc(s) => msg.is_some_and(|m| m.bcc_addrs.iter().any(|a| contains_ci(a, s))),
        SearchKey::Subject(s) => msg.is_some_and(|m| contains_ci(&m.subject, s)),
        SearchKey::Body(s) => msg.is_some_and(|m| {
            contains_ci(&m.text_body, s)
                || m.html_body.as_deref().is_some_and(|h| contains_ci(h, s))
                || (!m.raw_rfc2822.is_empty()
                    && contains_ci(
                        &String::from_utf8_lossy(split_raw_header_and_body(&m.raw_rfc2822).1),
                        s,
                    ))
        }),
        SearchKey::Text(s) => msg.is_some_and(|m| {
            let raw = String::from_utf8_lossy(&m.raw_rfc2822);
            contains_ci(&raw, s) || contains_ci(&m.subject, s) || contains_ci(&m.text_body, s)
        }),
        SearchKey::Header(field, val) => msg.is_some_and(|m| {
            let filtered = crate::imap::mime_fmt::filter_header_fields(
                crate::imap::mime_fmt::split_raw_header_and_body(&m.raw_rfc2822).0,
                std::slice::from_ref(field),
                false,
            );
            let txt = String::from_utf8_lossy(&filtered);
            if val.is_empty() {
                txt.trim().contains(':')
            } else {
                contains_ci(&txt, val)
            }
        }),
        SearchKey::Since(d) => internal_date.is_some_and(|md| md >= *d),
        SearchKey::Before(d) => internal_date.is_some_and(|md| md < *d),
        SearchKey::On(d) => internal_date.is_some_and(|md| md == *d),
        SearchKey::SentSince(d) => sent_date(msg).or(internal_date).is_some_and(|md| md >= *d),
        SearchKey::SentBefore(d) => sent_date(msg).or(internal_date).is_some_and(|md| md < *d),
        SearchKey::SentOn(d) => sent_date(msg).or(internal_date).is_some_and(|md| md == *d),
        SearchKey::Larger(n) => (entry.size_estimate as usize) > *n,
        SearchKey::Smaller(n) => (entry.size_estimate as usize) < *n,
        SearchKey::Modseq(n) => entry.modseq() >= *n,
        SearchKey::XGmMsgId(target) => {
            msg.is_some_and(|m| derive_xgm_u64(m.upstream_gmail_id.as_deref(), &m.id) == *target)
        }
        SearchKey::XGmThrId(target) => msg.is_some_and(|m| {
            derive_xgm_u64(m.upstream_thread_id.as_deref(), &m.thread_id) == *target
        }),
        SearchKey::XGmRaw(query) => msg.is_some_and(|m| matches_gmail_query(query, m)),
        SearchKey::XGmLabels(wanted) => {
            if let Some(sys_id) = resolve_xgm_label_system_id(wanted) {
                entry.label_ids.iter().any(|id| id == sys_id)
            } else {
                let wanted_trimmed = wanted.trim();
                entry.label_ids.iter().any(|id| {
                    id.eq_ignore_ascii_case(wanted_trimmed)
                        || label_id_to_name
                            .get(id)
                            .is_some_and(|name| name.eq_ignore_ascii_case(wanted_trimmed))
                })
            }
        }
        SearchKey::Not(inner) => !eval_search_criteria(inner, entry, msg, label_id_to_name),
        SearchKey::Or(a, b) => {
            eval_search_criteria(a, entry, msg, label_id_to_name)
                || eval_search_criteria(b, entry, msg, label_id_to_name)
        }
        SearchKey::And(list) => list
            .iter()
            .all(|item| eval_search_criteria(item, entry, msg, label_id_to_name)),
    }
}

fn sent_date(msg: Option<&StoredMessage>) -> Option<chrono::NaiveDate> {
    let m = msg?;
    let parsed = mail_parser::MessageParser::new().parse(&m.raw_rfc2822)?;
    let dt = parsed.date()?;
    chrono::NaiveDate::from_ymd_opt(dt.year as i32, dt.month as u32, dt.day as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xoauth2_parser_handles_multibyte_utf8_without_panicking() {
        let malformed = "user=alice@example.com\x01auth=éééé\x01\x01";
        assert_eq!(parse_xoauth2_payload(malformed.as_bytes()), None);

        let valid = "user=alice@example.com\x01auth=Bearer tok-123\x01\x01";
        assert_eq!(
            parse_xoauth2_payload(valid.as_bytes()),
            Some(("alice@example.com".to_string(), "tok-123".to_string()))
        );
    }

    #[test]
    fn parse_search_criteria_enforces_max_depth() {
        let mut deep_not: Vec<ImapArg> =
            (0..40).map(|_| ImapArg::Atom("NOT".to_string())).collect();
        deep_not.push(ImapArg::Atom("SEEN".to_string()));
        let err = parse_search_criteria(&deep_not, 10, 10)
            .expect_err("deep NOT nesting must be rejected");
        assert!(matches!(err, AppError::BadRequest(_)));

        let mut deep_or: Vec<ImapArg> = (0..40).map(|_| ImapArg::Atom("OR".to_string())).collect();
        for _ in 0..41 {
            deep_or.push(ImapArg::Atom("SEEN".to_string()));
        }
        let err =
            parse_search_criteria(&deep_or, 10, 10).expect_err("deep OR nesting must be rejected");
        assert!(matches!(err, AppError::BadRequest(_)));

        // Within depth limit (10 nested NOTs) succeeds cleanly.
        let mut ok_not: Vec<ImapArg> = (0..10).map(|_| ImapArg::Atom("NOT".to_string())).collect();
        ok_not.push(ImapArg::Atom("SEEN".to_string()));
        assert!(parse_search_criteria(&ok_not, 10, 10).is_ok());
    }

    #[test]
    fn format_xgm_labels_uses_literals_for_non_ascii_and_quotes_for_ascii() {
        let mut names = HashMap::new();
        names.insert("Label_ascii".to_string(), "Work/Urgent".to_string());
        names.insert("Label_utf8".to_string(), "Café/重要".to_string());
        names.insert("Label_jp".to_string(), "日本語".to_string());

        let formatted = format_xgm_labels(
            &[
                LABEL_UNREAD.to_string(),
                LABEL_INBOX.to_string(),
                "Label_ascii".to_string(),
                "Label_utf8".to_string(),
                "Label_jp".to_string(),
            ],
            &names,
        );
        let utf8_len = "Café/重要".len();
        let jp_len = "日本語".len();
        assert_eq!(
            formatted,
            format!("\\Inbox \"Work/Urgent\" {{{utf8_len}}}\r\nCafé/重要 {{{jp_len}}}\r\n日本語")
        );
        // Verify no quoted string contains non-ASCII bytes.
        assert!(!formatted.contains("\"Café/重要\""));
        assert!(!formatted.contains("\"日本語\""));
    }
}
