//! IMAP4rev1 connection session state machine and command handlers.

use std::{
    collections::{HashMap, HashSet},
    pin::Pin,
    task::{Context, Poll},
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
    blob::is_external_blob_store,
    error::{AppError, AppResult},
    events::{EventSource, MailEvent},
    filter::{FilterDecision, InboundMessage, apply_filter_labels},
    imap::{
        mime_fmt::{
            extract_body_section, format_bodystructure, format_envelope, parse_body_section,
            parse_raw_to_new_message_input,
        },
        parser::{
            ImapArg, ImapCommand, ReadCommandOutcome, append_literal, format_internal_date,
            imap_quote, imap_wildcard_match, normalize_mailbox_name, parse_imap_date_time,
            parse_imap_search_date, parse_sequence_set, read_command, read_crlf_line,
            seq_set_contains,
        },
    },
    models::{
        LABEL_DRAFT, LABEL_IMPORTANT, LABEL_INBOX, LABEL_SENT, LABEL_SPAM, LABEL_STARRED,
        LABEL_TRASH, LABEL_UNREAD,
    },
    storage::{ImapMessageEntry, NewLabelInput, StoredMessage, UpdateLabelInput},
};

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
    state: AppState,
    auth: AuthState,
    subscribed: HashSet<String>,
    tls_acceptor: Option<TlsAcceptor>,
}

/// Drive one client IMAP4rev1 connection to completion or shutdown.
pub async fn handle_connection(
    stream: ImapStream,
    state: AppState,
    tls_acceptor: Option<TlsAcceptor>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut reader = BufReader::new(stream);
    let mut session = ImapSession {
        state,
        auth: AuthState::NotAuthenticated,
        subscribed: HashSet::new(),
        tls_acceptor,
    };

    let greeting = format!(
        "* OK [CAPABILITY {}] nogml IMAP4rev1 Service Ready\r\n",
        session.capability_string(reader.get_ref().is_tls())
    );
    if write_flush(&mut reader, greeting.as_bytes()).await.is_err() {
        return;
    }

    let max_lit = session.state.config.max_body_bytes;

    loop {
        let cmd_outcome = tokio::select! {
            res = read_command(&mut reader, max_lit) => res,
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
                let t = tag.unwrap_or_else(|| "*".to_string());
                let resp = format!("{t} NO [TOOBIG] Literal size {size} exceeds limit\r\n");
                if write_flush(&mut reader, resp.as_bytes()).await.is_err() {
                    break;
                }
                continue;
            }
            Err(err) => {
                debug!(%err, "IMAP command read/parse error");
                let resp = format!("* BAD {err}\r\n");
                let _ = write_flush(&mut reader, resp.as_bytes()).await;
                if matches!(err, AppError::PayloadTooLarge(_) | AppError::Internal(_)) {
                    break;
                }
                continue;
            }
        };

        // Special-case STARTTLS because it consumes and upgrades the transport stream.
        if cmd.name == "STARTTLS" {
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
            match acceptor.accept(tcp).await {
                Ok(tls_stream) => {
                    reader = BufReader::new(ImapStream::Tls(Box::new(tls_stream)));
                    session.auth = AuthState::NotAuthenticated;
                }
                Err(err) => {
                    warn!(%err, "IMAP STARTTLS handshake failed");
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
                }
                caps.push("AUTH=PLAIN");
            }
            AuthState::Authenticated | AuthState::Selected(_) => {}
        }
        caps.extend_from_slice(&[
            "LITERAL+",
            "IDLE",
            "MOVE",
            "UIDPLUS",
            "SPECIAL-USE",
            "NAMESPACE",
            "ID",
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
            "LOGIN" => {
                self.handle_login(&tag, &cmd.args, stream).await?;
                Ok(true)
            }
            "AUTHENTICATE" => {
                self.handle_authenticate(&tag, &cmd.args, stream).await?;
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
            "EXPUNGE" => {
                self.handle_expunge(&tag, stream).await?;
                Ok(true)
            }
            "SEARCH" => {
                self.handle_search(&tag, &cmd.args, false, stream).await?;
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
                write_flush(
                    stream,
                    format!("{tag} BAD Unknown or unsupported command {name}\r\n").as_bytes(),
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

    async fn verify_credentials(&self, username: &str, password: &str) -> bool {
        self.state
            .auth
            .authenticate_imap(username, password)
            .await
            .is_ok()
    }

    async fn handle_login(
        &mut self,
        tag: &str,
        args: &[ImapArg],
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        if args.len() < 2 {
            write_flush(
                stream,
                format!("{tag} BAD LOGIN requires username and password\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        let user = args[0].as_str_lossy().unwrap_or_default();
        let pass = args[1].as_str_lossy().unwrap_or_default();
        if self.verify_credentials(&user, &pass).await {
            self.auth = AuthState::Authenticated;
            let cap = self.capability_string(stream.get_ref().is_tls());
            write_flush(
                stream,
                format!("{tag} OK [CAPABILITY {cap}] LOGIN completed\r\n").as_bytes(),
            )
            .await?;
        } else {
            write_flush(
                stream,
                format!("{tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n").as_bytes(),
            )
            .await?;
        }
        Ok(())
    }

    async fn handle_authenticate(
        &mut self,
        tag: &str,
        args: &[ImapArg],
        stream: &mut BufReader<ImapStream>,
    ) -> AppResult<()> {
        let Some(mech) = args.first().and_then(ImapArg::as_str_lossy) else {
            write_flush(
                stream,
                format!("{tag} BAD AUTHENTICATE requires mechanism\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        };
        if !mech.eq_ignore_ascii_case("PLAIN") {
            write_flush(
                stream,
                format!("{tag} NO Unsupported SASL mechanism {mech}\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }

        let b64_payload = if let Some(initial) = args.get(1).and_then(ImapArg::as_str_lossy) {
            if initial == "=" {
                String::new()
            } else {
                initial
            }
        } else {
            write_flush(stream, b"+ \r\n").await?;
            match read_crlf_line(stream, 8192).await? {
                Some(line) if line.trim() == "*" => {
                    write_flush(
                        stream,
                        format!("{tag} BAD AUTHENTICATE cancelled\r\n").as_bytes(),
                    )
                    .await?;
                    return Ok(());
                }
                Some(line) => line.trim().to_string(),
                None => return Err(AppError::BadRequest("EOF during AUTHENTICATE".to_string())),
            }
        };

        let decoded = match base64::engine::general_purpose::STANDARD.decode(b64_payload.as_bytes())
        {
            Ok(bytes) => bytes,
            Err(_) => {
                write_flush(
                    stream,
                    format!("{tag} BAD Invalid base64 in AUTHENTICATE PLAIN\r\n").as_bytes(),
                )
                .await?;
                return Ok(());
            }
        };

        // Format: [authzid]\0authcid\0passwd
        let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
        if parts.len() != 3 {
            write_flush(
                stream,
                format!("{tag} BAD Malformed PLAIN SASL payload\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        let authcid = String::from_utf8_lossy(parts[1]);
        let passwd = String::from_utf8_lossy(parts[2]);

        if self.verify_credentials(&authcid, &passwd).await {
            self.auth = AuthState::Authenticated;
            let cap = self.capability_string(stream.get_ref().is_tls());
            write_flush(
                stream,
                format!("{tag} OK [CAPABILITY {cap}] AUTHENTICATE completed\r\n").as_bytes(),
            )
            .await?;
        } else {
            write_flush(
                stream,
                format!("{tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n").as_bytes(),
            )
            .await?;
        }
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
        if args.len() < 2 {
            write_flush(
                stream,
                format!("{tag} BAD LIST requires reference and pattern\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        let reference = args[0].as_str_lossy().unwrap_or_default();
        let pattern = args[1].as_str_lossy().unwrap_or_default();
        let cmd_word = if is_lsub { "LSUB" } else { "LIST" };

        // RFC 3501 Section 6.3.8: empty pattern queries hierarchy delimiter.
        if pattern.is_empty() && !is_lsub {
            let resp = format!("* LIST (\\Noselect) \"/\" \"\"\r\n{tag} OK LIST completed\r\n");
            write_flush(stream, resp.as_bytes()).await?;
            return Ok(());
        }

        let full_pattern = if reference.is_empty() {
            pattern
        } else if reference.ends_with('/') || pattern.starts_with('/') {
            format!("{reference}{pattern}")
        } else {
            format!("{reference}/{pattern}")
        };

        let mailboxes = self.state.store.imap_list_mailboxes().await?;
        let mut out = String::new();

        // Synthesize virtual "[Gmail]" container if it matches the pattern.
        let has_gmail_children = mailboxes.iter().any(|m| m.name.starts_with("[Gmail]/"));
        if has_gmail_children
            && imap_wildcard_match(&full_pattern, "[Gmail]", '/')
            && (!is_lsub || self.subscribed.is_empty() || self.subscribed.contains("[Gmail]"))
        {
            out.push_str(&format!(
                "* {cmd_word} (\\Noselect \\HasChildren) \"/\" \"[Gmail]\"\r\n"
            ));
        }

        for mbx in &mailboxes {
            if is_lsub && !self.subscribed.is_empty() && !self.subscribed.contains(&mbx.name) {
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
                "* {cmd_word} ({}) \"/\" {}\r\n",
                attrs.join(" "),
                imap_quote(&mbx.name)
            ));
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
                format!("{tag} NO Mailbox does not exist: {mailbox}\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        };

        let mut pairs = Vec::new();
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
                _ => {}
            }
        }
        let resp = format!(
            "* STATUS {} ({})\r\n{tag} OK STATUS completed\r\n",
            imap_quote(&info.name),
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
        let Some(raw_mbx) = args.first().and_then(ImapArg::as_str_lossy) else {
            write_flush(
                stream,
                format!("{tag} BAD SELECT/EXAMINE requires mailbox name\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        };
        let mailbox = normalize_mailbox_name(&raw_mbx);
        let Some(info) = self.state.store.imap_mailbox_info(&mailbox).await? else {
            write_flush(
                stream,
                format!("{tag} NO [TRYCREATE] Mailbox does not exist: {mailbox}\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        };
        let entries = self.state.store.imap_list_messages(&info.name).await?;
        let first_unseen = entries
            .iter()
            .find(|m| m.label_ids.iter().any(|l| l == LABEL_UNREAD))
            .map(|m| m.seq);

        let mut out = String::new();
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
        out.push_str("* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n");
        if read_only {
            out.push_str("* OK [PERMANENTFLAGS ()] Read-only mailbox\r\n");
            out.push_str(&format!("{tag} OK [READ-ONLY] EXAMINE completed\r\n"));
        } else {
            out.push_str(
                "* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Flags permitted\r\n",
            );
            out.push_str(&format!("{tag} OK [READ-WRITE] SELECT completed\r\n"));
        }

        self.auth = AuthState::Selected(SelectedState {
            mailbox: info.name,
            read_only,
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
        let Some(name) = args.first().and_then(ImapArg::as_str_lossy) else {
            write_flush(
                stream,
                format!("{tag} BAD CREATE requires mailbox name\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        };
        if is_reserved_mailbox(&name) {
            write_flush(
                stream,
                format!("{tag} NO Cannot create reserved system mailbox {name}\r\n").as_bytes(),
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
                write_flush(stream, format!("{tag} NO {err}\r\n").as_bytes()).await?;
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
                format!("{tag} NO Cannot delete system mailbox {name}\r\n").as_bytes(),
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
                format!("{tag} NO Mailbox does not exist: {name}\r\n").as_bytes(),
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
                write_flush(stream, format!("{tag} NO {err}\r\n").as_bytes()).await?;
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
                format!("{tag} NO Mailbox does not exist: {old_name}\r\n").as_bytes(),
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
                write_flush(stream, format!("{tag} NO {err}\r\n").as_bytes()).await?;
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
        match self.state.filter.evaluate(&inbound_msg).await? {
            FilterDecision::Reject { reason } => {
                write_flush(
                    stream,
                    format!("{tag} NO [REJECTED] {reason}\r\n").as_bytes(),
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
                let _ = self.state.post_store_message(&stored).await;
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
                write_flush(
                    stream,
                    format!("{tag} OK [APPENDUID {uid_validity} {uid}] APPEND completed\r\n")
                        .as_bytes(),
                )
                .await?;
            }
            Err(AppError::NotFound(msg)) => {
                write_flush(stream, format!("{tag} NO [TRYCREATE] {msg}\r\n").as_bytes()).await?;
            }
            Err(err) => {
                write_flush(stream, format!("{tag} NO {err}\r\n").as_bytes()).await?;
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
        if !sel.read_only {
            let _ = self.state.store.imap_expunge(&sel.mailbox).await?;
        }
        self.auth = AuthState::Authenticated;
        write_flush(stream, format!("{tag} OK CLOSE completed\r\n").as_bytes()).await?;
        Ok(())
    }

    async fn handle_expunge(
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
        if sel.read_only {
            write_flush(
                stream,
                format!("{tag} NO Mailbox is selected read-only\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }
        let mut expunged_seqs = self.state.store.imap_expunge(&sel.mailbox).await?;
        expunged_seqs.sort_unstable();

        let mut out = String::new();
        for (removed_so_far, pre_seq) in expunged_seqs.iter().enumerate() {
            let adjusted = pre_seq.saturating_sub(removed_so_far as u32).max(1);
            out.push_str(&format!("* {adjusted} EXPUNGE\r\n"));
        }

        // Refresh snapshot & emit events for removed messages.
        let new_entries = self.state.store.imap_list_messages(&sel.mailbox).await?;
        let remaining_ids: HashSet<&str> =
            new_entries.iter().map(|e| e.message_id.as_str()).collect();
        for old in &sel.snapshot {
            if !remaining_ids.contains(old.message_id.as_str()) {
                self.state.events.publish(
                    EventSource::Imap,
                    MailEvent::MessageDeleted {
                        message_id: old.message_id.clone(),
                        thread_id: old.thread_id.clone(),
                        labels: old.label_ids.clone(),
                    },
                );
            }
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
            "STORE" => self.handle_store(tag, rest, true, stream).await,
            "COPY" => {
                self.handle_copy_or_move(tag, rest, true, false, stream)
                    .await
            }
            "MOVE" => {
                self.handle_copy_or_move(tag, rest, true, true, stream)
                    .await
            }
            "EXPUNGE" => self.handle_expunge(tag, stream).await,
            other => {
                write_flush(
                    stream,
                    format!("{tag} BAD Unsupported UID subcommand {other}\r\n").as_bytes(),
                )
                .await
            }
        }
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
        let entries = self.state.store.imap_list_messages(&sel.mailbox).await?;
        if let AuthState::Selected(ref mut s) = self.auth {
            s.snapshot = entries.clone();
        }

        // Skip optional CHARSET <charset>.
        let mut slice = args;
        if slice.len() >= 2
            && slice[0]
                .as_str_lossy()
                .is_some_and(|s| s.eq_ignore_ascii_case("CHARSET"))
        {
            slice = &slice[2..];
        }

        let max_seq = entries.len() as u32;
        let max_uid = entries.last().map(|e| e.uid).unwrap_or(0);
        let criteria = match parse_search_criteria(slice, max_seq, max_uid) {
            Ok(c) => c,
            Err(err) => {
                write_flush(stream, format!("{tag} BAD {err}\r\n").as_bytes()).await?;
                return Ok(());
            }
        };

        let needs_full_msg = criteria_needs_full_message(&criteria);
        let mut matched_ids = Vec::new();

        for entry in &entries {
            let full_msg = if needs_full_msg {
                self.state.store.get_message(&entry.message_id).await?
            } else {
                None
            };
            if eval_search_criteria(&criteria, entry, full_msg.as_ref()) {
                matched_ids.push(if is_uid { entry.uid } else { entry.seq });
            }
        }

        let nums: Vec<String> = matched_ids.into_iter().map(|n| n.to_string()).collect();
        let line = if nums.is_empty() {
            format!("* SEARCH\r\n{tag} OK SEARCH completed\r\n")
        } else {
            format!(
                "* SEARCH {}\r\n{tag} OK SEARCH completed\r\n",
                nums.join(" ")
            )
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

        let entries = self.state.store.imap_list_messages(&sel.mailbox).await?;
        if let AuthState::Selected(ref mut s) = self.auth {
            s.snapshot = entries.clone();
        }

        let seq_spec = args[0].as_str_lossy().unwrap_or_default();
        let max_val = if is_uid {
            entries.last().map(|e| e.uid).unwrap_or(0)
        } else {
            entries.len() as u32
        };
        let ranges = match parse_sequence_set(&seq_spec, max_val) {
            Ok(r) => r,
            Err(err) => {
                write_flush(stream, format!("{tag} BAD {err}\r\n").as_bytes()).await?;
                return Ok(());
            }
        };

        let mut items = expand_fetch_items(&args[1]);
        if is_uid && !items.iter().any(|i| i.eq_ignore_ascii_case("UID")) {
            items.insert(0, "UID".to_string());
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

        let mut updated_entries = entries.clone();

        for (idx, entry) in entries.iter().enumerate() {
            let key = if is_uid { entry.uid } else { entry.seq };
            if !seq_set_contains(&ranges, key) {
                continue;
            }
            let Some(mut msg) = self.state.store.get_message(&entry.message_id).await? else {
                continue;
            };
            if is_external_blob_store(self.state.blobs.as_ref()) {
                msg.raw_rfc2822 = self.state.load_raw_rfc2822(&msg).await?;
            }

            let mut current_entry = entry.clone();
            let mut mark_seen = false;
            for item in &items {
                let u = item.to_ascii_uppercase();
                if u == "RFC822" || u == "RFC822.TEXT" || (u.starts_with("BODY[")) {
                    mark_seen = true;
                }
            }
            if mark_seen
                && !sel.read_only
                && current_entry.label_ids.iter().any(|l| l == LABEL_UNREAD)
            {
                let is_flagged = current_entry.label_ids.iter().any(|l| l == LABEL_STARRED);
                let is_draft = current_entry.label_ids.iter().any(|l| l == LABEL_DRAFT);
                if let Ok(updated) = self
                    .state
                    .store
                    .imap_set_flags(
                        &current_entry.message_id,
                        true,
                        is_flagged,
                        is_draft,
                        current_entry.is_answered,
                        current_entry.is_deleted,
                    )
                    .await
                {
                    current_entry.label_ids = updated.label_ids;
                    updated_entries[idx] = current_entry.clone();
                }
            }

            let mut resp: Vec<u8> = Vec::new();
            resp.extend_from_slice(format!("* {} FETCH (", current_entry.seq).as_bytes());
            let mut first_item = true;
            let mut emitted_flags = false;

            for item in &items {
                if !first_item {
                    resp.push(b' ');
                }
                first_item = false;
                if item.eq_ignore_ascii_case("FLAGS") {
                    emitted_flags = true;
                }
                write_fetch_item(&mut resp, item, &current_entry, &msg, &label_name_map);
            }

            if mark_seen && !sel.read_only && !emitted_flags {
                if !first_item {
                    resp.push(b' ');
                }
                let flags_str = format_imap_flags(&current_entry);
                resp.extend_from_slice(format!("FLAGS ({flags_str})").as_bytes());
            }

            resp.extend_from_slice(b")\r\n");
            write_flush(stream, &resp).await?;
        }

        if let AuthState::Selected(ref mut s) = self.auth {
            s.snapshot = updated_entries;
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

        let entries = self.state.store.imap_list_messages(&sel.mailbox).await?;
        let seq_spec = args[0].as_str_lossy().unwrap_or_default();
        let max_val = if is_uid {
            entries.last().map(|e| e.uid).unwrap_or(0)
        } else {
            entries.len() as u32
        };
        let ranges = match parse_sequence_set(&seq_spec, max_val) {
            Ok(r) => r,
            Err(err) => {
                write_flush(stream, format!("{tag} BAD {err}\r\n").as_bytes()).await?;
                return Ok(());
            }
        };

        let action_raw = args[1]
            .as_str_lossy()
            .unwrap_or_default()
            .to_ascii_uppercase();
        let silent = action_raw.ends_with(".SILENT");
        let base_action = action_raw.trim_end_matches(".SILENT");
        if !matches!(base_action, "FLAGS" | "+FLAGS" | "-FLAGS") {
            write_flush(
                stream,
                format!("{tag} BAD Unsupported STORE action {action_raw}\r\n").as_bytes(),
            )
            .await?;
            return Ok(());
        }

        let mut req_flags: Vec<String> = Vec::new();
        match &args[2] {
            ImapArg::List(list) => {
                for a in list {
                    if let Some(s) = a.as_str_lossy() {
                        req_flags.push(s);
                    }
                }
            }
            _ => {
                for a in &args[2..] {
                    if let Some(s) = a.as_str_lossy() {
                        req_flags.push(s);
                    }
                }
            }
        }

        let has_flag = |name: &str| req_flags.iter().any(|f| f.eq_ignore_ascii_case(name));
        let mut updated_snapshot = entries.clone();

        for (idx, entry) in entries.iter().enumerate() {
            let key = if is_uid { entry.uid } else { entry.seq };
            if !seq_set_contains(&ranges, key) {
                continue;
            }
            let cur_seen = !entry.label_ids.iter().any(|l| l == LABEL_UNREAD);
            let cur_flagged = entry.label_ids.iter().any(|l| l == LABEL_STARRED);
            let cur_draft = entry.label_ids.iter().any(|l| l == LABEL_DRAFT);
            let cur_answered = entry.is_answered;
            let cur_deleted = entry.is_deleted;

            let (new_seen, new_flagged, new_draft, new_answered, new_deleted) = match base_action {
                "FLAGS" => (
                    has_flag("\\Seen"),
                    has_flag("\\Flagged"),
                    has_flag("\\Draft"),
                    has_flag("\\Answered"),
                    has_flag("\\Deleted"),
                ),
                "+FLAGS" => (
                    cur_seen || has_flag("\\Seen"),
                    cur_flagged || has_flag("\\Flagged"),
                    cur_draft || has_flag("\\Draft"),
                    cur_answered || has_flag("\\Answered"),
                    cur_deleted || has_flag("\\Deleted"),
                ),
                "-FLAGS" => (
                    cur_seen && !has_flag("\\Seen"),
                    cur_flagged && !has_flag("\\Flagged"),
                    cur_draft && !has_flag("\\Draft"),
                    cur_answered && !has_flag("\\Answered"),
                    cur_deleted && !has_flag("\\Deleted"),
                ),
                _ => unreachable!(),
            };

            let updated = self
                .state
                .store
                .imap_set_flags(
                    &entry.message_id,
                    new_seen,
                    new_flagged,
                    new_draft,
                    new_answered,
                    new_deleted,
                )
                .await?;

            let old_set: HashSet<&str> = entry.label_ids.iter().map(String::as_str).collect();
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

            let mut new_entry = entry.clone();
            new_entry.label_ids = updated.label_ids;
            new_entry.is_answered = updated.is_answered;
            new_entry.is_deleted = updated.is_deleted;
            updated_snapshot[idx] = new_entry.clone();

            if !silent {
                let flags_str = format_imap_flags(&new_entry);
                let line = if is_uid {
                    format!(
                        "* {} FETCH (UID {} FLAGS ({flags_str}))\r\n",
                        new_entry.seq, new_entry.uid
                    )
                } else {
                    format!("* {} FETCH (FLAGS ({flags_str}))\r\n", new_entry.seq)
                };
                write_flush(stream, line.as_bytes()).await?;
            }
        }

        if let AuthState::Selected(ref mut s) = self.auth {
            s.snapshot = updated_snapshot;
        }
        write_flush(stream, format!("{tag} OK STORE completed\r\n").as_bytes()).await?;
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

        let entries = self.state.store.imap_list_messages(&sel.mailbox).await?;
        let seq_spec = args[0].as_str_lossy().unwrap_or_default();
        let dst_mailbox = normalize_mailbox_name(&args[1].as_str_lossy().unwrap_or_default());
        let max_val = if is_uid {
            entries.last().map(|e| e.uid).unwrap_or(0)
        } else {
            entries.len() as u32
        };
        let ranges = match parse_sequence_set(&seq_spec, max_val) {
            Ok(r) => r,
            Err(err) => {
                write_flush(stream, format!("{tag} BAD {err}\r\n").as_bytes()).await?;
                return Ok(());
            }
        };

        let matched: Vec<&ImapMessageEntry> = entries
            .iter()
            .filter(|e| seq_set_contains(&ranges, if is_uid { e.uid } else { e.seq }))
            .collect();
        let msg_ids: Vec<String> = matched.iter().map(|e| e.message_id.clone()).collect();

        let Some(dst_info) = self.state.store.imap_mailbox_info(&dst_mailbox).await? else {
            write_flush(
                stream,
                format!("{tag} NO [TRYCREATE] Mailbox does not exist: {dst_mailbox}\r\n")
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

        for entry in &matched {
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
            let mut removed_seqs: Vec<u32> = entries
                .iter()
                .filter(|e| !remaining.contains(e.message_id.as_str()))
                .map(|e| e.seq)
                .collect();
            removed_seqs.sort_unstable();
            for (idx, pre_seq) in removed_seqs.iter().enumerate() {
                let adj = pre_seq.saturating_sub(idx as u32).max(1);
                out.push_str(&format!("* {adj} EXPUNGE\r\n"));
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

        loop {
            tokio::select! {
                line_res = read_crlf_line(stream, 4096) => {
                    match line_res {
                        Ok(Some(line)) if line.trim().eq_ignore_ascii_case("DONE") => {
                            write_flush(stream, format!("{tag} OK IDLE terminated\r\n").as_bytes()).await?;
                            return Ok(true);
                        }
                        Ok(Some(_)) => {
                            // Ignore stray empty/non-DONE lines while idling, or exit if malformed.
                            write_flush(stream, format!("{tag} BAD Expected DONE\r\n").as_bytes()).await?;
                            return Ok(true);
                        }
                        Ok(None) | Err(_) => return Ok(false),
                    }
                }
                ev = event_rx.recv() => {
                    match ev {
                        Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            self.flush_selected_updates(stream).await?;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            return Ok(false);
                        }
                    }
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
        removed_seqs.sort_unstable();
        for (idx, pre_seq) in removed_seqs.iter().enumerate() {
            let adj = pre_seq.saturating_sub(idx as u32).max(1);
            out.push_str(&format!("* {adj} EXPUNGE\r\n"));
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
                    out.push_str(&format!("* {} FETCH (FLAGS ({new_flags}))\r\n", entry.seq));
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

fn write_fetch_item(
    out: &mut Vec<u8>,
    item: &str,
    entry: &ImapMessageEntry,
    msg: &StoredMessage,
    label_name_map: &HashMap<String, String>,
) {
    let upper = item.to_ascii_uppercase();
    match upper.as_str() {
        "UID" => {
            out.extend_from_slice(format!("UID {}", entry.uid).as_bytes());
        }
        "FLAGS" => {
            let flags = format_imap_flags(entry);
            out.extend_from_slice(format!("FLAGS ({flags})").as_bytes());
        }
        "INTERNALDATE" => {
            let dt = format_internal_date(msg.internal_date_ms);
            out.extend_from_slice(format!("INTERNALDATE {}", imap_quote(&dt)).as_bytes());
        }
        "RFC822.SIZE" => {
            out.extend_from_slice(format!("RFC822.SIZE {}", msg.raw_rfc2822.len()).as_bytes());
        }
        "RFC822" => {
            out.extend_from_slice(b"RFC822 ");
            append_literal(out, &msg.raw_rfc2822);
        }
        "RFC822.HEADER" => {
            let hdr = extract_body_section(&msg.raw_rfc2822, &parse_body_section("HEADER"), None);
            out.extend_from_slice(b"RFC822.HEADER ");
            append_literal(out, &hdr);
        }
        "RFC822.TEXT" => {
            let txt = extract_body_section(&msg.raw_rfc2822, &parse_body_section("TEXT"), None);
            out.extend_from_slice(b"RFC822.TEXT ");
            append_literal(out, &txt);
        }
        "ENVELOPE" => {
            let env = format_envelope(&msg.raw_rfc2822);
            out.extend_from_slice(format!("ENVELOPE {env}").as_bytes());
        }
        "BODYSTRUCTURE" => {
            let bs = format_bodystructure(&msg.raw_rfc2822, true);
            out.extend_from_slice(format!("BODYSTRUCTURE {bs}").as_bytes());
        }
        "BODY" => {
            let bs = format_bodystructure(&msg.raw_rfc2822, false);
            out.extend_from_slice(format!("BODY {bs}").as_bytes());
        }
        "X-GM-MSGID" => {
            let id = derive_xgm_u64(msg.upstream_gmail_id.as_deref(), &msg.id);
            out.extend_from_slice(format!("X-GM-MSGID {id}").as_bytes());
        }
        "X-GM-THRID" => {
            let id = derive_xgm_u64(msg.upstream_thread_id.as_deref(), &msg.thread_id);
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
                let data = extract_body_section(&msg.raw_rfc2822, &section, partial);
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
                out.push(imap_quote(name));
            }
        }
    }
    out.join(" ")
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
    XGmMsgId(u64),
    XGmThrId(u64),
    Not(Box<SearchKey>),
    Or(Box<SearchKey>, Box<SearchKey>),
    And(Vec<SearchKey>),
}

fn parse_search_criteria(args: &[ImapArg], max_seq: u32, max_uid: u32) -> AppResult<SearchKey> {
    if args.is_empty() {
        return Ok(SearchKey::All);
    }
    let mut pos = 0usize;
    let mut keys = Vec::new();
    while pos < args.len() {
        keys.push(parse_one_search_key(args, &mut pos, max_seq, max_uid)?);
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
) -> AppResult<SearchKey> {
    if *pos >= args.len() {
        return Err(AppError::BadRequest(
            "Unexpected end of SEARCH criteria".to_string(),
        ));
    }
    let arg = &args[*pos];
    *pos += 1;

    if let ImapArg::List(sub) = arg {
        return parse_search_criteria(sub, max_seq, max_uid);
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
        "TEXT" | "X-GM-RAW" => Ok(SearchKey::Text(next_str(args, pos, &upper)?)),
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
            let inner = parse_one_search_key(args, pos, max_seq, max_uid)?;
            Ok(SearchKey::Not(Box::new(inner)))
        }
        "OR" => {
            let left = parse_one_search_key(args, pos, max_seq, max_uid)?;
            let right = parse_one_search_key(args, pos, max_seq, max_uid)?;
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
        | SearchKey::XGmThrId(_) => true,
        SearchKey::Not(inner) => criteria_needs_full_message(inner),
        SearchKey::Or(a, b) => criteria_needs_full_message(a) || criteria_needs_full_message(b),
        SearchKey::And(list) => list.iter().any(criteria_needs_full_message),
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
        SearchKey::XGmMsgId(target) => {
            msg.is_some_and(|m| derive_xgm_u64(m.upstream_gmail_id.as_deref(), &m.id) == *target)
        }
        SearchKey::XGmThrId(target) => msg.is_some_and(|m| {
            derive_xgm_u64(m.upstream_thread_id.as_deref(), &m.thread_id) == *target
        }),
        SearchKey::Not(inner) => !eval_search_criteria(inner, entry, msg),
        SearchKey::Or(a, b) => {
            eval_search_criteria(a, entry, msg) || eval_search_criteria(b, entry, msg)
        }
        SearchKey::And(list) => list
            .iter()
            .all(|item| eval_search_criteria(item, entry, msg)),
    }
}

fn sent_date(msg: Option<&StoredMessage>) -> Option<chrono::NaiveDate> {
    let m = msg?;
    let parsed = mail_parser::MessageParser::new().parse(&m.raw_rfc2822)?;
    let dt = parsed.date()?;
    chrono::NaiveDate::from_ymd_opt(dt.year as i32, dt.month as u32, dt.day as u32)
}
