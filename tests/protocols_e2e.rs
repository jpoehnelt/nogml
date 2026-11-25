use std::{
    net::SocketAddr,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_imap::types::Flag;
use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::Engine as _;
use futures_util::TryStreamExt;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, header, method, path, query_param},
};

use nogml::{
    AppState,
    ai::safety::{OutboundCheck, OutboundDecision, OutboundPolicy, PolicyCheck},
    auth::{AgentPolicyOverride, AuthProvider, AuthScope, Principal},
    blob::{BlobStore, FsBlobStore, attachment_blob_key, raw_message_blob_key},
    build_router,
    config::{BlobBackend, Config, StorageBackend, SyncMode},
    error::{AppError, AppResult},
    filter::{FilterChain, FilterDecision, InboundFilter, InboundMessage},
    imap::{mime_fmt::parse_raw_to_new_message_input, serve_imap},
    mcp::McpServer,
    mime::{ComposeEmailInput, build_rfc2822, encode_base64url},
    models::{
        LABEL_DRAFT, LABEL_INBOX, LABEL_SPAM, LABEL_STARRED, LABEL_TRASH, LABEL_UNREAD,
        ResendReceivedAttachment, ResendReceivedEmail, ResendSendEmailRequest,
        ResendSendEmailResponse,
    },
    resend::ResendClient,
    search_index::{SearchIndex, StoreSearchIndex},
    storage::{
        AiMessagePage, AiSearchQuery, HistoryListQuery, MailStore, MemoryStore, NewAttachmentInput,
        NewLabelInput, NewMessageInput, SqliteStore, StoredMessage, SyncState,
    },
    sync::{SyncRunOptions, get_sync_status, run_gmail_sync},
    transport::{
        InboundEnvelope, IngestOutcome, MailTransport, OutboundMessage, SendOutcome,
        TransportCapabilities, ingest_inbound_rfc2822,
    },
};

// ============================================================================
// Shared Test Helpers & Stubs
// ============================================================================

struct StubResendClient {
    fail_on_send: bool,
}

impl StubResendClient {
    fn noop() -> Self {
        Self {
            fail_on_send: false,
        }
    }

    fn forbid_send() -> Self {
        Self { fail_on_send: true }
    }
}

#[async_trait]
impl ResendClient for StubResendClient {
    async fn send_email(
        &self,
        _req: &ResendSendEmailRequest,
        _idempotency_key: Option<&str>,
    ) -> AppResult<ResendSendEmailResponse> {
        if self.fail_on_send {
            panic!(
                "ResendClient::send_email must NOT be called when a custom MailTransport or blocking OutboundPolicy is active"
            );
        }
        Ok(ResendSendEmailResponse {
            id: "re_stub_1".to_string(),
        })
    }

    async fn get_received_email(&self, _email_id: &str) -> AppResult<ResendReceivedEmail> {
        Err(AppError::NotFound("stub resend has no remote email".into()))
    }

    async fn list_received_attachments(
        &self,
        _email_id: &str,
    ) -> AppResult<Vec<ResendReceivedAttachment>> {
        Ok(Vec::new())
    }

    async fn download_bytes(&self, _url: &str) -> AppResult<Vec<u8>> {
        Ok(Vec::new())
    }
}

fn b64url(raw: &[u8]) -> String {
    encode_base64url(raw)
}

async fn pick_ephemeral_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap()
}

/// Spawn a live `serve_imap` listener on a free localhost port and wait until it accepts TCP.
async fn spawn_live_serve_imap(state: AppState) -> (SocketAddr, watch::Sender<bool>) {
    let addr = state
        .config
        .imap_bind
        .expect("config.imap_bind must be set before spawn_live_serve_imap");
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = serve_imap(state, rx).await;
    });

    // Wait briefly for `serve_imap` to bind the socket.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match TcpStream::connect(addr).await {
            Ok(mut s) => {
                // Consume greeting and cleanly close probe connection.
                let mut r = BufReader::new(&mut s);
                let mut line = String::new();
                let _ = r.read_line(&mut line).await;
                let _ = s.write_all(b"PROBE LOGOUT\r\n").await;
                break;
            }
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(e) => panic!("serve_imap did not bind {addr} in time: {e}"),
        }
    }

    (addr, tx)
}

/// Read lines from an IMAP TCP stream until the tagged completion line `<tag> ...` arrives.
async fn imap_cmd(reader: &mut BufReader<TcpStream>, tag: &str, cmd: &str) -> Vec<String> {
    reader
        .get_mut()
        .write_all(format!("{tag} {cmd}\r\n").as_bytes())
        .await
        .unwrap();
    imap_read_until_tag(reader, tag).await
}

/// Read lines (handling IMAP `{N}\r\n` literals safely) until a line starts with `<tag> `.
async fn imap_read_until_tag(reader: &mut BufReader<TcpStream>, tag: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let prefix = format!("{tag} ");
    loop {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .unwrap_or_else(|_| panic!("timeout waiting for IMAP tag {tag}; got so far: {lines:?}"))
            .unwrap();
        assert!(n > 0, "unexpected EOF waiting for IMAP tag {tag}");

        // If this line ends with a literal size marker `{N}\r\n`, consume the exact literal bytes
        // and append them so literal bodies containing newlines never confuse tag matching.
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if let Some(open) = trimmed.rfind('{')
            && trimmed.ends_with('}')
            && let Ok(lit_len) = trimmed[open + 1..trimmed.len() - 1].parse::<usize>()
        {
            let mut lit_buf = vec![0u8; lit_len];
            reader.read_exact(&mut lit_buf).await.unwrap();
            line.push_str(&String::from_utf8_lossy(&lit_buf));
            let mut rest = String::new();
            reader.read_line(&mut rest).await.unwrap();
            line.push_str(&rest);
        }

        let is_done = line.starts_with(&prefix);
        lines.push(line);
        if is_done {
            break;
        }
    }
    lines
}

async fn http_json(
    app: &axum::Router,
    method: &str,
    uri: &str,
    auth_header: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(auth) = auth_header {
        builder = builder.header("authorization", auth);
    }
    let req = match body {
        Some(v) => builder
            .header("content-type", "application/json")
            .body(Body::from(v.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({ "_raw": String::from_utf8_lossy(&bytes) }))
    };
    (status, json)
}

fn make_sqlite_config(dir: &Path, imap_addr: Option<SocketAddr>) -> Config {
    let mut cfg = Config::for_test();
    cfg.storage = StorageBackend::Sqlite;
    cfg.db_path = dir.join("nogml.db");
    cfg.imap_bind = imap_addr;
    cfg.imap_username = Some("agent@example.com".to_string());
    cfg.imap_password = Some("imap-secret".to_string());
    cfg
}

// ============================================================================
// 1. Embedded IMAP4rev1 Server: Full Lifecycle (`async-imap` + raw TCP)
// ============================================================================

#[tokio::test]
async fn e2e_imap_full_lifecycle_async_imap_and_raw_tcp() {
    let dir = TempDir::new().unwrap();
    let imap_addr = pick_ephemeral_addr().await;
    let cfg = make_sqlite_config(dir.path(), Some(imap_addr));
    let store = Arc::new(SqliteStore::open(&cfg.db_path, &cfg.user_email).unwrap());
    let state = AppState::with_backends(cfg, store.clone(), Arc::new(StubResendClient::noop()));

    let (addr, shutdown_tx) = spawn_live_serve_imap(state.clone()).await;

    // --- Part A: Raw TCP covering AUTHENTICATE PLAIN (continuation + SASL-IR), LOGIN error,
    // NAMESPACE, LIST SPECIAL-USE, CREATE, APPEND (sync & LITERAL+), STATUS, SELECT, SEARCH,
    // UID SEARCH, FETCH/UID FETCH (UID, FLAGS, ENVELOPE, BODYSTRUCTURE, BODY.PEEK[HEADER],
    // BODY.PEEK[TEXT], X-GM-MSGID, X-GM-THRID, X-GM-LABELS), STORE, COPY, MOVE, EXPUNGE. ---
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.unwrap();
    assert!(greeting.starts_with("* OK [CAPABILITY "));
    assert!(greeting.contains("IMAP4rev1"));
    assert!(greeting.contains("SPECIAL-USE"));
    assert!(greeting.contains("NAMESPACE"));
    assert!(greeting.contains("X-GM-EXT-1"));
    assert!(greeting.contains("IDLE"));
    assert!(greeting.contains("MOVE"));

    // Reject bad LOGIN
    let bad_login = imap_cmd(&mut reader, "L0", "LOGIN agent@example.com wrong-pass").await;
    assert!(
        bad_login
            .last()
            .unwrap()
            .contains("L0 NO [AUTHENTICATIONFAILED]")
    );

    // AUTHENTICATE PLAIN via server continuation `+ \r\n`
    reader
        .get_mut()
        .write_all(b"A1 AUTHENTICATE PLAIN\r\n")
        .await
        .unwrap();
    let mut cont = String::new();
    reader.read_line(&mut cont).await.unwrap();
    assert!(cont.starts_with("+ "), "expected continuation, got {cont}");
    let sasl = base64::engine::general_purpose::STANDARD.encode("\0agent@example.com\0imap-secret");
    reader
        .get_mut()
        .write_all(format!("{sasl}\r\n").as_bytes())
        .await
        .unwrap();
    let auth_done = imap_read_until_tag(&mut reader, "A1").await;
    assert!(auth_done.last().unwrap().starts_with("A1 OK"));

    // NAMESPACE
    let ns = imap_cmd(&mut reader, "A2", "NAMESPACE").await;
    assert!(
        ns.iter()
            .any(|l| l.contains(r#"* NAMESPACE (("" "/")) NIL NIL"#))
    );
    assert!(ns.last().unwrap().starts_with("A2 OK"));

    // LIST "" "*" — verify INBOX and all 6 [Gmail]/* SPECIAL-USE attributes
    let list = imap_cmd(&mut reader, "A3", r#"LIST "" "*""#).await;
    assert!(list.last().unwrap().starts_with("A3 OK"));
    let list_joined = list.join("");
    assert!(
        list_joined.contains(r#""INBOX""#),
        "missing INBOX: {list_joined}"
    );
    assert!(
        list.iter()
            .any(|l| l.contains(r#"\Noselect \HasChildren"#) && l.contains(r#""[Gmail]""#))
    );
    for (folder, attr) in [
        ("[Gmail]/All Mail", r"\All"),
        ("[Gmail]/Sent Mail", r"\Sent"),
        ("[Gmail]/Drafts", r"\Drafts"),
        ("[Gmail]/Trash", r"\Trash"),
        ("[Gmail]/Spam", r"\Junk"),
        ("[Gmail]/Starred", r"\Flagged"),
    ] {
        assert!(
            list.iter().any(|l| l.contains(folder) && l.contains(attr)),
            "expected LIST entry for {folder} with {attr}, got:\n{list_joined}"
        );
    }

    // CREATE custom label mailbox for COPY/MOVE
    let create = imap_cmd(&mut reader, "A4", r#"CREATE "ArchiveBox""#).await;
    assert!(create.last().unwrap().starts_with("A4 OK"));

    // APPEND message 1 (multipart text + HTML) using synchronizing literal `{N}`
    let raw_msg1 = concat!(
        "Date: Tue, 11 Feb 2025 14:30:00 +0000\r\n",
        "From: Alice Sender <alice@example.com>\r\n",
        "To: Agent <agent@example.com>\r\n",
        "Subject: IMAP Full Lifecycle Alpha\r\n",
        "Message-ID: <imap-alpha-1@example.com>\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/alternative; boundary=\"altbnd\"\r\n",
        "\r\n",
        "--altbnd\r\n",
        "Content-Type: text/plain; charset=\"utf-8\"\r\n",
        "\r\n",
        "Plain body for alpha verification.\r\n",
        "--altbnd\r\n",
        "Content-Type: text/html; charset=\"utf-8\"\r\n",
        "\r\n",
        "<p>HTML body for alpha verification.</p>\r\n",
        "--altbnd--\r\n"
    );
    reader
        .get_mut()
        .write_all(format!("A5 APPEND INBOX () {{{}}}\r\n", raw_msg1.len()).as_bytes())
        .await
        .unwrap();
    let mut ready = String::new();
    reader.read_line(&mut ready).await.unwrap();
    assert_eq!(ready, "+ Ready\r\n");
    reader
        .get_mut()
        .write_all(format!("{raw_msg1}\r\n").as_bytes())
        .await
        .unwrap();
    let app1 = imap_read_until_tag(&mut reader, "A5").await;
    assert!(app1.last().unwrap().starts_with("A5 OK [APPENDUID "));

    // APPEND message 2 using LITERAL+ `{N+}` with \Flagged
    let raw_msg2 = concat!(
        "Date: Wed, 12 Feb 2025 08:00:00 +0000\r\n",
        "From: Bob Sender <bob@example.com>\r\n",
        "To: Agent <agent@example.com>\r\n",
        "Subject: IMAP Full Lifecycle Beta\r\n",
        "Message-ID: <imap-beta-2@example.com>\r\n",
        "\r\n",
        "Beta payload text.\r\n"
    );
    let app2 = imap_cmd(
        &mut reader,
        "A6",
        &format!(
            "APPEND INBOX (\\Flagged) \"12-Feb-2025 08:00:00 +0000\" {{{}+}}\r\n{raw_msg2}",
            raw_msg2.len()
        ),
    )
    .await;
    assert!(app2.last().unwrap().starts_with("A6 OK [APPENDUID "));

    // STATUS INBOX
    let status = imap_cmd(
        &mut reader,
        "A7",
        "STATUS INBOX (MESSAGES UNSEEN UIDNEXT UIDVALIDITY)",
    )
    .await;
    assert!(
        status
            .iter()
            .any(|l| l.contains("MESSAGES 2") && l.contains("UNSEEN 2"))
    );
    assert!(status.last().unwrap().starts_with("A7 OK"));

    // SELECT INBOX
    let sel = imap_cmd(&mut reader, "A8", "SELECT INBOX").await;
    assert!(sel.iter().any(|l| l.trim() == "* 2 EXISTS"));
    assert!(sel.last().unwrap().contains("[READ-WRITE]"));

    // SEARCH & UID SEARCH
    let s_seq = imap_cmd(&mut reader, "A9", r#"SEARCH SUBJECT "Alpha""#).await;
    assert!(s_seq.iter().any(|l| l.trim() == "* SEARCH 1"));
    let s_uid = imap_cmd(
        &mut reader,
        "A10",
        r#"UID SEARCH FLAGGED FROM "bob@example.com""#,
    )
    .await;
    assert!(s_uid.iter().any(|l| l.trim() == "* SEARCH 2"));

    // Non-UID FETCH + UID FETCH: UID, FLAGS, ENVELOPE, BODYSTRUCTURE, BODY.PEEK[HEADER],
    // BODY.PEEK[TEXT], X-GM-MSGID, X-GM-THRID, X-GM-LABELS
    let seq_fetch = imap_cmd(
        &mut reader,
        "A11S",
        "FETCH 1 (UID FLAGS ENVELOPE BODYSTRUCTURE BODY.PEEK[HEADER] BODY.PEEK[TEXT] X-GM-MSGID X-GM-THRID X-GM-LABELS)",
    )
    .await;
    assert!(seq_fetch.last().unwrap().starts_with("A11S OK"));
    let seq_joined = seq_fetch.join("");
    assert!(seq_joined.contains("X-GM-MSGID "));
    assert!(seq_joined.contains("X-GM-THRID "));
    assert!(seq_joined.contains("FLAGS ()"));

    let fetch = imap_cmd(
        &mut reader,
        "A11",
        "UID FETCH 1 (UID FLAGS ENVELOPE BODYSTRUCTURE BODY.PEEK[HEADER] BODY.PEEK[TEXT] X-GM-MSGID X-GM-THRID X-GM-LABELS)",
    )
    .await;
    let fetch_joined = fetch.join("");
    assert!(fetch.last().unwrap().starts_with("A11 OK"));
    assert!(fetch_joined.contains("UID 1"));
    assert!(
        fetch_joined.contains("FLAGS ()"),
        "BODY.PEEK must not set \\Seen: {fetch_joined}"
    );
    assert!(fetch_joined.contains("ENVELOPE ("));
    assert!(fetch_joined.contains("\"IMAP Full Lifecycle Alpha\""));
    assert!(fetch_joined.contains("BODYSTRUCTURE ("));
    assert!(fetch_joined.contains("\"ALTERNATIVE\""));
    assert!(fetch_joined.contains("BODY[HEADER]"));
    assert!(fetch_joined.contains("Message-ID: <imap-alpha-1@example.com>"));
    assert!(fetch_joined.contains("BODY[TEXT]"));
    assert!(fetch_joined.contains("Plain body for alpha verification."));
    assert!(fetch_joined.contains("X-GM-MSGID "));
    assert!(fetch_joined.contains("X-GM-THRID "));
    assert!(fetch_joined.contains("X-GM-LABELS ("));
    assert!(fetch_joined.contains("\\Inbox"));

    // Verify BODY.PEEK did NOT remove UNREAD in MailStore
    let stored_m1 = store
        .find_message_by_rfc_message_id("<imap-alpha-1@example.com>")
        .await
        .unwrap()
        .unwrap();
    assert!(stored_m1.label_ids.contains(&LABEL_UNREAD.to_string()));
    assert!(!stored_m1.label_ids.contains(&LABEL_STARRED.to_string()));

    // STORE: \Seen <-> UNREAD and \Flagged <-> STARRED bidirectional verification
    let st1 = imap_cmd(&mut reader, "A12", r#"UID STORE 1 +FLAGS (\Seen \Flagged)"#).await;
    assert!(
        st1.iter()
            .any(|l| l.contains("\\Seen") && l.contains("\\Flagged"))
    );
    let m1_after_add = store.get_message(&stored_m1.id).await.unwrap().unwrap();
    assert!(!m1_after_add.label_ids.contains(&LABEL_UNREAD.to_string()));
    assert!(m1_after_add.label_ids.contains(&LABEL_STARRED.to_string()));

    let st2 = imap_cmd(&mut reader, "A13", r#"UID STORE 1 -FLAGS (\Seen \Flagged)"#).await;
    assert!(st2.last().unwrap().starts_with("A13 OK"));
    let m1_after_rem = store.get_message(&stored_m1.id).await.unwrap().unwrap();
    assert!(m1_after_rem.label_ids.contains(&LABEL_UNREAD.to_string()));
    assert!(!m1_after_rem.label_ids.contains(&LABEL_STARRED.to_string()));

    // UID COPY 1 -> ArchiveBox
    let copy = imap_cmd(&mut reader, "A14", r#"UID COPY 1 "ArchiveBox""#).await;
    assert!(copy.last().unwrap().contains("[COPYUID "));

    // Mark msg 2 \Deleted and EXPUNGE in INBOX -> moves to [Gmail]/Trash
    let _ = imap_cmd(
        &mut reader,
        "A15",
        r#"UID STORE 2 +FLAGS.SILENT (\Deleted)"#,
    )
    .await;
    let exp = imap_cmd(&mut reader, "A16", "EXPUNGE").await;
    assert!(exp.iter().any(|l| l.trim() == "* 2 EXPUNGE"));
    assert!(exp.last().unwrap().starts_with("A16 OK"));

    // Confirm msg 2 is now in [Gmail]/Trash and expunging inside [Gmail]/Trash permanently deletes it
    let stored_m2 = store
        .find_message_by_rfc_message_id("<imap-beta-2@example.com>")
        .await
        .unwrap()
        .unwrap();
    assert!(stored_m2.label_ids.contains(&LABEL_TRASH.to_string()));
    assert!(!stored_m2.label_ids.contains(&LABEL_INBOX.to_string()));

    // UID MOVE 1 from INBOX to ArchiveBox
    let mv = imap_cmd(&mut reader, "A17", r#"UID MOVE 1 "ArchiveBox""#).await;
    assert!(mv.iter().any(|l| l.contains("EXPUNGE")));
    assert!(mv.last().unwrap().starts_with("A17 OK"));

    let m1_after_move = store.get_message(&stored_m1.id).await.unwrap().unwrap();
    assert!(!m1_after_move.label_ids.contains(&LABEL_INBOX.to_string()));

    // Select [Gmail]/Trash, mark msg 2 \Deleted, EXPUNGE -> permanently deleted
    let sel_trash = imap_cmd(&mut reader, "A18", r#"SELECT "[Gmail]/Trash""#).await;
    assert!(sel_trash.iter().any(|l| l.trim() == "* 1 EXISTS"));
    let _ = imap_cmd(&mut reader, "A19", r#"STORE 1 +FLAGS.SILENT (\Deleted)"#).await;
    let exp_trash = imap_cmd(&mut reader, "A20", "EXPUNGE").await;
    assert!(exp_trash.iter().any(|l| l.trim() == "* 1 EXPUNGE"));
    assert!(store.get_message(&stored_m2.id).await.unwrap().is_none());

    let bye = imap_cmd(&mut reader, "A21", "LOGOUT").await;
    assert!(bye.iter().any(|l| l.starts_with("* BYE")));

    // --- Part B: Real `async-imap` client verification (`LOGIN`, `LIST`, `SELECT`, `APPEND`,
    // `UID SEARCH`, `UID FETCH`, `STORE`, `COPY`, `MV`, `EXPUNGE`) ---
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut client = async_imap::Client::new(tcp);
    let _ = client.read_response().await.unwrap();
    let mut session = client
        .login("agent@example.com", "imap-secret")
        .await
        .map_err(|(e, _)| e)
        .unwrap();

    let boxes: Vec<_> = session
        .list(Some(""), Some("*"))
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap();
    let box_names: Vec<&str> = boxes.iter().map(|b| b.name()).collect();
    assert!(box_names.contains(&"INBOX"));
    assert!(box_names.contains(&"[Gmail]/All Mail"));
    assert!(box_names.contains(&"[Gmail]/Sent Mail"));
    assert!(box_names.contains(&"[Gmail]/Drafts"));
    assert!(box_names.contains(&"[Gmail]/Trash"));
    assert!(box_names.contains(&"[Gmail]/Spam"));
    assert!(box_names.contains(&"[Gmail]/Starred"));
    assert!(box_names.contains(&"ArchiveBox"));

    let mbx = session.select("ArchiveBox").await.unwrap();
    assert_eq!(mbx.exists, 1);

    let uids = session.uid_search("SUBJECT \"Alpha\"").await.unwrap();
    assert_eq!(uids.len(), 1);
    let target_uid = *uids.iter().next().unwrap();

    let fetches: Vec<_> = session
        .uid_fetch(
            target_uid.to_string(),
            "(UID FLAGS ENVELOPE BODYSTRUCTURE BODY.PEEK[HEADER] BODY.PEEK[TEXT] X-GM-MSGID X-GM-THRID X-GM-LABELS)",
        )
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap();
    assert_eq!(fetches.len(), 1);
    let f = &fetches[0];
    assert_eq!(f.uid, Some(target_uid));
    assert!(f.envelope().is_some());
    assert!(f.bodystructure().is_some());
    assert!(f.header().is_some());
    assert!(f.text().is_some());
    assert!(f.gmail_msg_id().is_some());
    let gm_labels: Vec<String> = f
        .gmail_labels()
        .expect("X-GM-LABELS should be parsed")
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(gm_labels.iter().any(|l| l == "ArchiveBox"));

    // Mark Seen via async-imap uid_store and verify flag returned
    let stored_fetches: Vec<_> = session
        .uid_store(target_uid.to_string(), "+FLAGS (\\Seen)")
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap();
    assert!(
        stored_fetches
            .iter()
            .any(|sf| sf.flags().any(|fl| fl == Flag::Seen))
    );

    session.logout().await.unwrap();
    let _ = shutdown_tx.send(true);
}

// ============================================================================
// 2. Cross-Protocol Live `IDLE` (Gmail REST `messages.insert` + Resend Ingest)
// ============================================================================

#[tokio::test]
async fn e2e_imap_cross_protocol_live_idle_gmail_insert_and_resend_ingest() {
    let dir = TempDir::new().unwrap();
    let imap_addr = pick_ephemeral_addr().await;
    let cfg = make_sqlite_config(dir.path(), Some(imap_addr));
    let store = Arc::new(SqliteStore::open(&cfg.db_path, &cfg.user_email).unwrap());
    let state = AppState::with_backends(cfg, store, Arc::new(StubResendClient::noop()));
    let app = build_router(state.clone());

    let (addr, shutdown_tx) = spawn_live_serve_imap(state.clone()).await;

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.unwrap();

    let login = imap_cmd(&mut reader, "I1", "LOGIN agent@example.com imap-secret").await;
    assert!(login.last().unwrap().starts_with("I1 OK"));
    let sel = imap_cmd(&mut reader, "I2", "SELECT INBOX").await;
    assert!(sel.iter().any(|l| l.trim() == "* 0 EXISTS"));

    // Enter IDLE
    reader.get_mut().write_all(b"I3 IDLE\r\n").await.unwrap();
    let mut cont = String::new();
    reader.read_line(&mut cont).await.unwrap();
    assert!(
        cont.starts_with("+ idling"),
        "expected '+ idling', got {cont}"
    );

    // Event 1: Email arrives via Gmail REST API `messages.insert`
    let raw1 = b"From: gmail-api@example.com\r\nTo: agent@example.com\r\nSubject: Live via Gmail Insert\r\nMessage-ID: <idle-gmail-1@example.com>\r\n\r\nInserted via Gmail REST API.";
    let (status, inserted) = http_json(
        &app,
        "POST",
        "/gmail/v1/users/me/messages",
        None,
        Some(json!({
            "raw": b64url(raw1),
            "labelIds": ["INBOX", "UNREAD"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "insert failed: {inserted}");

    let mut push1 = String::new();
    tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut push1))
        .await
        .expect("timed out waiting for live * 1 EXISTS from Gmail messages.insert")
        .unwrap();
    assert_eq!(push1.trim(), "* 1 EXISTS");

    // Event 2: Email arrives via `ingest_inbound_rfc2822` (Resend inbound pipeline)
    let raw2 = b"From: resend-hook@example.com\r\nTo: agent@example.com\r\nSubject: Live via Resend Ingest\r\nMessage-ID: <idle-resend-2@example.com>\r\n\r\nIngested via Resend pipeline.".to_vec();
    let outcome = ingest_inbound_rfc2822(
        state.store.as_ref(),
        &state.events,
        state.filter.as_ref(),
        InboundEnvelope {
            raw_rfc2822: raw2,
            source: "resend_inbound".to_string(),
            provider_id: Some("re_live_2".to_string()),
            default_labels: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(matches!(outcome, IngestOutcome::Stored { .. }));

    let mut push2 = String::new();
    tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut push2))
        .await
        .expect("timed out waiting for live * 2 EXISTS from ingest_inbound_rfc2822")
        .unwrap();
    assert_eq!(push2.trim(), "* 2 EXISTS");

    // Event 3: Email arrives via HTTP `POST /webhooks/resend` (`email.received`)
    let (wh_status, wh_body) = http_json(
        &app,
        "POST",
        "/webhooks/resend",
        None,
        Some(json!({
            "type": "email.received",
            "created_at": "2025-02-15T10:00:00Z",
            "data": {
                "email_id": "re_live_3",
                "from": "webhook@example.com",
                "to": ["agent@example.com"],
                "subject": "Live via Resend Webhook",
                "message_id": "<idle-webhook-3@example.com>"
            }
        })),
    )
    .await;
    assert_eq!(wh_status, StatusCode::OK, "webhook failed: {wh_body}");

    let mut push3 = String::new();
    tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut push3))
        .await
        .expect("timed out waiting for live * 3 EXISTS from POST /webhooks/resend")
        .unwrap();
    assert_eq!(push3.trim(), "* 3 EXISTS");

    // Exit IDLE with DONE and fetch all three subjects over IMAP
    reader.get_mut().write_all(b"DONE\r\n").await.unwrap();
    let done = imap_read_until_tag(&mut reader, "I3").await;
    assert!(done.last().unwrap().starts_with("I3 OK"));

    let fetch = imap_cmd(&mut reader, "I4", "FETCH 1:3 (ENVELOPE)").await;
    let joined = fetch.join("");
    assert!(joined.contains("Live via Gmail Insert"));
    assert!(joined.contains("Live via Resend Ingest"));
    assert!(joined.contains("Live via Resend Webhook"));

    let _ = imap_cmd(&mut reader, "I5", "LOGOUT").await;
    let _ = shutdown_tx.send(true);
}

// ============================================================================
// 3. Upstream Gmail Sync (SyncMode::Api): OAuth2, Backfill, Incremental,
//    HTTP 404 Fallback, and Idempotent Resend Webhook Deduplication
// ============================================================================

#[tokio::test]
async fn e2e_gmail_api_sync_backfill_incremental_404_fallback_and_resend_dedup() {
    let dir = TempDir::new().unwrap();
    let mock = MockServer::start().await;

    // 1. OAuth2 token refresh endpoint
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("client_id=test-cid-e2e"))
        .and(body_string_contains("refresh_token=test-rtok-e2e"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "e2e-oauth-token-1",
            "expires_in": 3600,
            "token_type": "Bearer"
        })))
        .expect(1)
        .mount(&mock)
        .await;

    // 2. Upstream labels
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .and(header("authorization", "Bearer e2e-oauth-token-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "labels": [
                { "id": "INBOX", "name": "INBOX", "type": "system" },
                { "id": "Label_VIP", "name": "VIP", "type": "user" }
            ]
        })))
        .mount(&mock)
        .await;

    // 3. Initial profile (baseline historyId = 1000)
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/profile"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "emailAddress": "agent@example.com",
            "messagesTotal": 3,
            "threadsTotal": 3,
            "historyId": "1000"
        })))
        .mount(&mock)
        .await;

    // 4. Paginated messages.list (page 1 -> page 2)
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .and(query_param("pageToken", "pg2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [
                { "id": "18fa000000000002", "threadId": "18fa000000000002" },
                { "id": "18fa000000000003", "threadId": "18fa000000000003" }
            ],
            "resultSizeEstimate": 3
        })))
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [
                { "id": "18fa000000000001", "threadId": "18fa000000000001" }
            ],
            "nextPageToken": "pg2",
            "resultSizeEstimate": 3
        })))
        .mount(&mock)
        .await;

    let raw_m1 = b"From: alice@upstream.example\r\nTo: agent@example.com\r\nSubject: Backfill One\r\nMessage-ID: <sync-m1@upstream.example>\r\n\r\nHello backfill 1";
    let raw_m2 = b"From: bob@upstream.example\r\nTo: agent@example.com\r\nSubject: Backfill Two\r\nMessage-ID: <sync-m2@upstream.example>\r\n\r\nHello backfill 2";
    let raw_shared = b"From: carol@sender.example\r\nTo: agent@example.com\r\nSubject: Shared Resend And Gmail\r\nMessage-ID: <shared-dedup-42@sender.example>\r\n\r\nArrived via Resend first, then synced from Gmail.";

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/18fa000000000001"))
        .and(query_param("format", "raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "18fa000000000001",
            "threadId": "18fa000000000001",
            "labelIds": ["INBOX", "UNREAD", "Label_VIP"],
            "internalDate": "1736000000000",
            "raw": b64url(raw_m1)
        })))
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/18fa000000000002"))
        .and(query_param("format", "raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "18fa000000000002",
            "threadId": "18fa000000000002",
            "labelIds": ["INBOX"],
            "internalDate": "1736000060000",
            "raw": b64url(raw_m2)
        })))
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/18fa000000000003"))
        .and(query_param("format", "raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "18fa000000000003",
            "threadId": "18fa000000000003",
            "labelIds": ["INBOX", "STARRED", "Label_VIP"],
            "internalDate": "1736000120000",
            "raw": b64url(raw_shared)
        })))
        .mount(&mock)
        .await;

    let mut cfg = make_sqlite_config(dir.path(), None);
    cfg.sync_mode = SyncMode::Api;
    cfg.gmail_api_base_url = mock.uri();
    cfg.gmail_oauth_token_url = format!("{}/oauth/token", mock.uri());
    cfg.gmail_client_id = Some("test-cid-e2e".to_string());
    cfg.gmail_client_secret = Some("test-csec-e2e".to_string());
    cfg.gmail_refresh_token = Some("test-rtok-e2e".to_string());

    let store = Arc::new(SqliteStore::open(&cfg.db_path, &cfg.user_email).unwrap());
    let state = AppState::with_backends(cfg, store.clone(), Arc::new(StubResendClient::noop()));
    let app = build_router(state.clone());

    // Pre-ingest `<shared-dedup-42@sender.example>` via Resend webhook BEFORE running Gmail sync
    let (wh_status, wh_body) = http_json(
        &app,
        "POST",
        "/webhooks/resend",
        None,
        Some(json!({
            "type": "email.received",
            "created_at": "2025-01-04T12:00:00Z",
            "data": {
                "email_id": "re_shared_42",
                "from": "carol@sender.example",
                "to": ["agent@example.com"],
                "subject": "Shared Resend And Gmail",
                "message_id": "<shared-dedup-42@sender.example>"
            }
        })),
    )
    .await;
    assert_eq!(wh_status, StatusCode::OK, "webhook failed: {wh_body}");
    assert_eq!(wh_body["status"], "received");
    let local_shared_id = wh_body["message_id"].as_str().unwrap().to_string();

    // Run full backfill
    let r1 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r1.provider, "gmail_api");
    assert!(r1.full_resync);
    assert_eq!(r1.labels_synced, 1);
    assert_eq!(r1.messages_added, 2);
    assert_eq!(r1.messages_updated + r1.messages_deduplicated, 1);
    assert_eq!(r1.history_id.as_deref(), Some("1000"));

    // Verify idempotent deduplication: total messages is 3 (NOT 4), existing message updated in-place
    let all_msgs = store
        .list_messages(&nogml::storage::MessageListQuery {
            include_spam_trash: true,
            max_results: 50,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(all_msgs.messages.len(), 3, "duplicate message was created!");

    let deduped = store.get_message(&local_shared_id).await.unwrap().unwrap();
    assert_eq!(
        deduped.upstream_gmail_id.as_deref(),
        Some("18fa000000000003")
    );
    assert!(deduped.label_ids.contains(&LABEL_STARRED.to_string()));
    let vip_label = store
        .list_labels()
        .await
        .unwrap()
        .into_iter()
        .find(|l| l.name == "VIP")
        .expect("VIP label should be synced");
    assert!(deduped.label_ids.contains(&vip_label.id));

    // --- Incremental `history.list` (messageAdded, labelAdded, labelRemoved, messageDeleted) ---
    let raw_m4 = b"From: dave@upstream.example\r\nTo: agent@example.com\r\nSubject: Incremental Added\r\nMessage-ID: <sync-m4@upstream.example>\r\n\r\nAdded via history.list";
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/18fa000000000004"))
        .and(query_param("format", "raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "18fa000000000004",
            "threadId": "18fa000000000004",
            "labelIds": ["INBOX", "UNREAD"],
            "internalDate": "1736000200000",
            "raw": b64url(raw_m4)
        })))
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/history"))
        .and(query_param("startHistoryId", "1000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "historyId": "1050",
            "history": [
                {
                    "id": "1010",
                    "messagesAdded": [
                        { "message": { "id": "18fa000000000004", "threadId": "18fa000000000004" } }
                    ]
                },
                {
                    "id": "1020",
                    "labelsAdded": [
                        {
                            "message": { "id": "18fa000000000001", "threadId": "18fa000000000001" },
                            "labelIds": ["STARRED"]
                        }
                    ],
                    "labelsRemoved": [
                        {
                            "message": { "id": "18fa000000000001", "threadId": "18fa000000000001" },
                            "labelIds": ["UNREAD"]
                        }
                    ]
                },
                {
                    "id": "1030",
                    "messagesDeleted": [
                        { "message": { "id": "18fa000000000002", "threadId": "18fa000000000002" } }
                    ]
                }
            ]
        })))
        .mount(&mock)
        .await;

    let r2 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert!(!r2.full_resync);
    assert_eq!(r2.messages_added, 1);
    assert_eq!(r2.messages_deleted, 1);
    assert!(r2.messages_updated >= 2);
    assert_eq!(r2.history_id.as_deref(), Some("1050"));

    let m1_inc = store
        .find_message_by_upstream_id("18fa000000000001")
        .await
        .unwrap()
        .unwrap();
    assert!(m1_inc.label_ids.contains(&LABEL_STARRED.to_string()));
    assert!(!m1_inc.label_ids.contains(&LABEL_UNREAD.to_string()));
    assert!(
        store
            .find_message_by_upstream_id("18fa000000000002")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .find_message_by_upstream_id("18fa000000000004")
            .await
            .unwrap()
            .is_some()
    );

    // --- Expired historyId (HTTP 404) automatic fallback to full resync ---
    let mock_404 = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "labels": [] })))
        .mount(&mock_404)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/history"))
        .and(query_param("startHistoryId", "1050"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": { "code": 404, "message": "History ID expired" }
        })))
        .expect(1)
        .mount(&mock_404)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/profile"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "emailAddress": "agent@example.com",
            "messagesTotal": 4,
            "threadsTotal": 4,
            "historyId": "2000"
        })))
        .mount(&mock_404)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [
                { "id": "18fa000000000001", "threadId": "18fa000000000001" },
                { "id": "18fa000000000003", "threadId": "18fa000000000003" },
                { "id": "18fa000000000004", "threadId": "18fa000000000004" },
                { "id": "18fa000000000005", "threadId": "18fa000000000005" }
            ],
            "resultSizeEstimate": 4
        })))
        .mount(&mock_404)
        .await;
    let raw_m5 = b"From: eve@upstream.example\r\nTo: agent@example.com\r\nSubject: Recovered After 404\r\nMessage-ID: <sync-m5@upstream.example>\r\n\r\nRecovered via fallback resync.";
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/18fa000000000005"))
        .and(query_param("format", "raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "18fa000000000005",
            "threadId": "18fa000000000005",
            "labelIds": ["INBOX", "UNREAD"],
            "internalDate": "1736000300000",
            "raw": b64url(raw_m5)
        })))
        .mount(&mock_404)
        .await;

    let mut cfg_404 = (*state.config).clone();
    cfg_404.gmail_api_base_url = mock_404.uri();
    cfg_404.gmail_access_token = Some("e2e-fallback-token".to_string());
    let state_404 =
        AppState::with_backends(cfg_404, store.clone(), Arc::new(StubResendClient::noop()));

    let r3 = run_gmail_sync(&state_404, SyncRunOptions::default())
        .await
        .unwrap();
    assert!(
        r3.full_resync,
        "HTTP 404 on history.list must trigger full resync"
    );
    assert_eq!(r3.messages_deduplicated, 3);
    assert_eq!(r3.messages_added, 1);
    assert_eq!(r3.history_id.as_deref(), Some("2000"));

    let m5 = store
        .find_message_by_upstream_id("18fa000000000005")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(m5.subject, "Recovered After 404");

    let status = get_sync_status(&state_404).await.unwrap();
    assert_eq!(status.state, "idle");
    assert_eq!(status.last_history_id.as_deref(), Some("2000"));
}

// ============================================================================
// 4. Upstream Gmail Sync (SyncMode::Imap) against Second Live `nogml` IMAP Server
// ============================================================================

#[tokio::test]
async fn e2e_gmail_imap_sync_against_second_embedded_nogml_imap_server() {
    let up_dir = TempDir::new().unwrap();
    let up_addr = pick_ephemeral_addr().await;
    let up_cfg = make_sqlite_config(up_dir.path(), Some(up_addr));
    let up_store = Arc::new(SqliteStore::open(&up_cfg.db_path, &up_cfg.user_email).unwrap());
    let up_state =
        AppState::with_backends(up_cfg, up_store.clone(), Arc::new(StubResendClient::noop()));

    // Create a custom user label on upstream server and seed 2 initial messages
    let receipts_lbl = up_store
        .create_label(NewLabelInput {
            name: "Receipts".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();

    let raw1 = b"From: billing@shop.test\r\nTo: agent@example.com\r\nSubject: Order Receipt 1\r\nMessage-ID: <imap-up-1@shop.test>\r\n\r\nReceipt #1".to_vec();
    up_store
        .insert_message(parse_raw_to_new_message_input(
            raw1,
            vec![
                LABEL_INBOX.to_string(),
                LABEL_UNREAD.to_string(),
                LABEL_STARRED.to_string(),
                receipts_lbl.id.clone(),
            ],
            None,
            "local",
            Some("18fb000000000001".to_string()),
            None,
            false,
            false,
        ))
        .await
        .unwrap();

    let raw2 = b"From: team@shop.test\r\nTo: agent@example.com\r\nSubject: Welcome Note 2\r\nMessage-ID: <imap-up-2@shop.test>\r\n\r\nAlready read".to_vec();
    up_store
        .insert_message(parse_raw_to_new_message_input(
            raw2,
            vec![LABEL_INBOX.to_string()],
            None,
            "local",
            Some("18fb000000000002".to_string()),
            None,
            false,
            false,
        ))
        .await
        .unwrap();

    let (bound_addr, shutdown_tx) = spawn_live_serve_imap(up_state.clone()).await;

    // Configure local nogml instance to sync via SyncMode::Imap
    let local_dir = TempDir::new().unwrap();
    let mut local_cfg = make_sqlite_config(local_dir.path(), None);
    local_cfg.sync_mode = SyncMode::Imap;
    local_cfg.gmail_imap_host = bound_addr.ip().to_string();
    local_cfg.gmail_imap_port = bound_addr.port();
    local_cfg.gmail_imap_tls = false;
    local_cfg.gmail_imap_user = Some("agent@example.com".to_string());
    local_cfg.gmail_imap_password = Some("imap-secret".to_string());
    local_cfg.gmail_imap_mailbox = "[Gmail]/All Mail".to_string();

    let local_store =
        Arc::new(SqliteStore::open(&local_cfg.db_path, &local_cfg.user_email).unwrap());
    let local_state = AppState::with_backends(
        local_cfg,
        local_store.clone(),
        Arc::new(StubResendClient::noop()),
    );

    // 1. Initial full IMAP sync
    let r1 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r1.provider, "gmail_imap");
    assert!(r1.full_resync);
    assert_eq!(r1.messages_added, 2);

    let local_m1 = local_store
        .find_message_by_upstream_id("18fb000000000001")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(local_m1.subject, "Order Receipt 1");
    assert!(local_m1.label_ids.contains(&LABEL_INBOX.to_string()));
    assert!(local_m1.label_ids.contains(&LABEL_UNREAD.to_string()));
    assert!(local_m1.label_ids.contains(&LABEL_STARRED.to_string()));
    let local_receipts = local_store
        .list_labels()
        .await
        .unwrap()
        .into_iter()
        .find(|l| l.name == "Receipts")
        .expect("Receipts label should be synced from X-GM-LABELS");
    assert!(local_m1.label_ids.contains(&local_receipts.id));

    let local_m2 = local_store
        .find_message_by_upstream_id("18fb000000000002")
        .await
        .unwrap()
        .unwrap();
    assert!(!local_m2.label_ids.contains(&LABEL_UNREAD.to_string()));

    let state_after_r1 = local_store
        .get_sync_state("gmail_imap:agent@example.com")
        .await
        .unwrap()
        .unwrap();
    let uid_after_r1 = state_after_r1.imap_last_uid.unwrap();
    assert!(uid_after_r1 >= 2);

    // 2. No-op incremental sync -> 0 added
    let r2 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert!(!r2.full_resync);
    assert_eq!(r2.messages_added, 0);

    // 3. Insert a 3rd message upstream -> incremental `UID > last_uid` fetches ONLY msg 3
    let raw3 = b"From: updates@shop.test\r\nTo: agent@example.com\r\nSubject: Incremental IMAP Msg 3\r\nMessage-ID: <imap-up-3@shop.test>\r\n\r\nIncremental body".to_vec();
    up_store
        .insert_message(parse_raw_to_new_message_input(
            raw3,
            vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            None,
            "local",
            Some("18fb000000000003".to_string()),
            None,
            false,
            false,
        ))
        .await
        .unwrap();

    let r3 = run_gmail_sync(&local_state, SyncRunOptions::default())
        .await
        .unwrap();
    assert!(!r3.full_resync);
    assert_eq!(r3.messages_added, 1);

    let local_m3 = local_store
        .find_message_by_upstream_id("18fb000000000003")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(local_m3.subject, "Incremental IMAP Msg 3");

    let state_after_r3 = local_store
        .get_sync_state("gmail_imap:agent@example.com")
        .await
        .unwrap()
        .unwrap();
    assert!(state_after_r3.imap_last_uid.unwrap() > uid_after_r1);

    let _ = shutdown_tx.send(true);
}

// ============================================================================
// 5. Pluggable Trait #1: `MailStore` Parity + SQLite Persistence Across Reopen
// ============================================================================

async fn exercise_mail_store_roundtrip(store: &dyn MailStore) -> (String, String, String, u64) {
    let custom_lbl = store
        .create_label(NewLabelInput {
            name: "Finance".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();

    let start_hid = store.current_history_id().await.unwrap();

    let msg = store
        .insert_message(NewMessageInput {
            id: None,
            thread_id: None,
            label_ids: vec![
                LABEL_INBOX.to_string(),
                LABEL_UNREAD.to_string(),
                custom_lbl.id.clone(),
            ],
            raw_rfc2822: b"From: cfo@acme.test\r\nTo: agent@example.com\r\nSubject: Q4 Budget Forecast\r\nMessage-ID: <q4-budget@acme.test>\r\n\r\nQuarterly revenue projection attached.".to_vec(),
            snippet: "Quarterly revenue projection attached.".to_string(),
            internal_date_ms: 1_736_100_000_000,
            subject: "Q4 Budget Forecast".to_string(),
            from_addr: "cfo@acme.test".to_string(),
            to_addrs: vec!["agent@example.com".to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: "Quarterly revenue projection attached.".to_string(),
            html_body: None,
            rfc822_message_id: Some("<q4-budget@acme.test>".to_string()),
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "local".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: vec![NewAttachmentInput {
                part_id: "part-1".to_string(),
                filename: Some("forecast.csv".to_string()),
                content_type: "text/csv".to_string(),
                content_id: None,
                data: b"quarter,revenue\nQ4,99000\n".to_vec(),
            }],
        })
        .await
        .unwrap();

    // Modify labels to record history
    store
        .modify_message_labels(&msg.id, &[LABEL_STARRED.to_string()], &[])
        .await
        .unwrap();

    // Create a draft
    let draft = store
        .create_draft(NewMessageInput {
            id: None,
            thread_id: Some(msg.thread_id.clone()),
            label_ids: vec![LABEL_DRAFT.to_string()],
            raw_rfc2822: b"From: agent@example.com\r\nTo: cfo@acme.test\r\nSubject: Re: Q4 Budget Forecast\r\n\r\nLooks great!".to_vec(),
            snippet: "Looks great!".to_string(),
            internal_date_ms: 1_736_100_050_000,
            subject: "Re: Q4 Budget Forecast".to_string(),
            from_addr: "agent@example.com".to_string(),
            to_addrs: vec!["cfo@acme.test".to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: "Looks great!".to_string(),
            html_body: None,
            rfc822_message_id: Some("<q4-draft@example.com>".to_string()),
            in_reply_to: Some("<q4-budget@acme.test>".to_string()),
            references_header: Some("<q4-budget@acme.test>".to_string()),
            resend_id: None,
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "local".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: vec![],
        })
        .await
        .unwrap();

    // Save sync_state
    store
        .save_sync_state(SyncState {
            account_key: "gmail_api:me".to_string(),
            provider: "gmail_api".to_string(),
            last_history_id: Some("4242".to_string()),
            imap_mailbox: None,
            imap_uid_validity: None,
            imap_last_uid: None,
            last_sync_at: None,
            last_full_sync_at: None,
            status: "idle".to_string(),
            last_error: None,
            messages_synced: 7,
        })
        .await
        .unwrap();

    (msg.id, custom_lbl.id, draft.id, start_hid)
}

async fn verify_mail_store_state(
    store: &dyn MailStore,
    msg_id: &str,
    label_id: &str,
    draft_id: &str,
    start_hid: u64,
) {
    let msg = store.get_message(msg_id).await.unwrap().unwrap();
    assert_eq!(msg.subject, "Q4 Budget Forecast");
    assert!(msg.label_ids.contains(&label_id.to_string()));
    assert!(msg.label_ids.contains(&LABEL_STARRED.to_string()));
    assert!(msg.has_attachments);

    let atts = store.list_attachment_meta(msg_id).await.unwrap();
    assert_eq!(atts.len(), 1);
    let att_data = store
        .get_attachment(msg_id, &atts[0].id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(att_data.data, b"quarter,revenue\nQ4,99000\n");

    let lbl = store.get_label(label_id).await.unwrap().unwrap();
    assert_eq!(lbl.name, "Finance");

    let draft = store.get_draft(draft_id).await.unwrap().unwrap();
    assert_eq!(draft.message.subject, "Re: Q4 Budget Forecast");

    let history = store
        .list_history(&HistoryListQuery {
            start_history_id: start_hid,
            max_results: 50,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        !history.entries.is_empty(),
        "expected persisted history entries after start_hid={start_hid}"
    );

    let sync_state = store
        .get_sync_state("gmail_api:me")
        .await
        .unwrap()
        .expect("sync_state should persist");
    assert_eq!(sync_state.last_history_id.as_deref(), Some("4242"));
    assert_eq!(sync_state.messages_synced, 7);

    // FTS5 (SQLite) / token (Memory) search
    let found = store
        .search_messages_ai(&AiSearchQuery {
            q: Some("revenue".to_string()),
            limit: 10,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(found.messages.len(), 1);
    assert_eq!(found.messages[0].id, msg_id);
}

#[tokio::test]
async fn e2e_mail_store_sqlite_persistence_and_memory_parity() {
    // 1. SQLite persistence across drop + reopen
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("persist.db");

    let (msg_id, label_id, draft_id, start_hid) = {
        let sqlite = SqliteStore::open(&db_path, "agent@example.com").unwrap();
        assert_eq!(sqlite.backend_name(), "sqlite");
        exercise_mail_store_roundtrip(&sqlite).await
    }; // SqliteStore dropped here

    let reopened = SqliteStore::open(&db_path, "agent@example.com").unwrap();
    verify_mail_store_state(&reopened, &msg_id, &label_id, &draft_id, start_hid).await;

    // 2. MemoryStore parity on identical workload
    let memory = MemoryStore::new("agent@example.com");
    assert_eq!(memory.backend_name(), "memory");
    let (m_msg_id, m_label_id, m_draft_id, m_start_hid) =
        exercise_mail_store_roundtrip(&memory).await;
    verify_mail_store_state(&memory, &m_msg_id, &m_label_id, &m_draft_id, m_start_hid).await;
}

// ============================================================================
// 6. Pluggable Trait #2: `BlobStore` (`FsBlobStore` disk files, serving & cleanup)
// ============================================================================

#[tokio::test]
async fn e2e_fs_blob_store_lifecycle_disk_files_serving_and_delete_cleanup() {
    let dir = TempDir::new().unwrap();
    let blob_dir = dir.path().join("blobs");

    let mut cfg = make_sqlite_config(dir.path(), None);
    cfg.blob_backend = BlobBackend::Fs;
    cfg.blob_dir = blob_dir.clone();

    let store = Arc::new(SqliteStore::open(&cfg.db_path, &cfg.user_email).unwrap());
    let fs_blobs = Arc::new(FsBlobStore::open(&blob_dir).unwrap());
    assert_eq!(fs_blobs.backend_name(), "fs");

    let state = AppState::with_backends(cfg, store.clone(), Arc::new(StubResendClient::noop()))
        .with_blobs(fs_blobs.clone());
    let app = build_router(state.clone());

    // Build a real multipart RFC 2822 email with binary PNG payload
    let binary_payload: Vec<u8> = vec![
        0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x01, 0x02, 0xFF, 0xFE, 0x42,
    ];
    let raw_bytes = build_rfc2822(&ComposeEmailInput {
        from: "sender@example.com".to_string(),
        to: vec!["agent@example.com".to_string()],
        cc: vec![],
        bcc: vec![],
        reply_to: vec![],
        subject: "Binary Blob Attachment".to_string(),
        text: Some("See attached binary file.".to_string()),
        html: None,
        message_id: Some("<blob-test-1@example.com>".to_string()),
        in_reply_to: None,
        references: None,
        extra_headers: Default::default(),
        attachments: vec![NewAttachmentInput {
            part_id: "att-bin".to_string(),
            filename: Some("pixel.png".to_string()),
            content_type: "image/png".to_string(),
            content_id: None,
            data: binary_payload.clone(),
        }],
    })
    .unwrap();

    // Ingest via Gmail REST API `messages.insert`
    let (status, body) = http_json(
        &app,
        "POST",
        "/gmail/v1/users/me/messages",
        None,
        Some(json!({
            "raw": b64url(&raw_bytes),
            "labelIds": ["INBOX", "UNREAD"]
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "insert failed: {body}");
    let msg_id = body["id"].as_str().unwrap().to_string();

    let stored = store.get_message(&msg_id).await.unwrap().unwrap();
    let att_metas = store.list_attachment_meta(&msg_id).await.unwrap();
    assert_eq!(att_metas.len(), 1);
    let att_id = att_metas[0].id.clone();

    // 1. Verify blob files physically exist on disk inside `blob_dir`
    let raw_key = raw_message_blob_key(&msg_id);
    let att_key = attachment_blob_key(&msg_id, &att_id);
    let raw_disk_path = blob_dir.join(&raw_key);
    let att_disk_path = blob_dir.join(&att_key);
    assert!(
        raw_disk_path.exists(),
        "raw RFC 2822 blob file missing at {}",
        raw_disk_path.display()
    );
    assert!(
        att_disk_path.exists(),
        "attachment blob file missing at {}",
        att_disk_path.display()
    );
    assert_eq!(std::fs::read(&raw_disk_path).unwrap(), raw_bytes);
    assert_eq!(std::fs::read(&att_disk_path).unwrap(), binary_payload);

    // 2. Prove `AppState::load_raw_rfc2822` & `AppState::load_attachment_bytes` serve from `FsBlobStore`
    //    even when inline buffers are empty.
    let mut empty_raw_msg = stored.clone();
    empty_raw_msg.raw_rfc2822 = Vec::new();
    let loaded_raw = state.load_raw_rfc2822(&empty_raw_msg).await.unwrap();
    assert_eq!(loaded_raw, raw_bytes);

    let mut stored_att = store
        .get_attachment(&msg_id, &att_id)
        .await
        .unwrap()
        .unwrap();
    stored_att.data = Vec::new();
    let loaded_att = state.load_attachment_bytes(&stored_att).await.unwrap();
    assert_eq!(loaded_att, binary_payload);

    // 2b. Verify Gmail REST API serves the attachment bytes cleanly
    let (att_status, att_body) = http_json(
        &app,
        "GET",
        &format!("/gmail/v1/users/me/messages/{msg_id}/attachments/{att_id}"),
        None,
        None,
    )
    .await;
    assert_eq!(
        att_status,
        StatusCode::OK,
        "attachment GET failed: {att_body}"
    );
    let decoded_att = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(att_body["data"].as_str().unwrap())
        .unwrap();
    assert_eq!(decoded_att, binary_payload);

    // 3. Delete message via Gmail REST API and verify disk blobs are cleaned up
    let (del_status, _) = http_json(
        &app,
        "DELETE",
        &format!("/gmail/v1/users/me/messages/{msg_id}"),
        None,
        None,
    )
    .await;
    assert_eq!(del_status, StatusCode::NO_CONTENT);
    assert!(
        !raw_disk_path.exists(),
        "raw blob file should be removed on delete"
    );
    assert!(
        !att_disk_path.exists(),
        "attachment blob file should be removed on delete"
    );
    assert_eq!(fs_blobs.get(&raw_key).await.unwrap(), None);
    assert_eq!(fs_blobs.get(&att_key).await.unwrap(), None);
}

// ============================================================================
// 7. Pluggable Trait #3: `InboundFilter` (`FilterChain`) across ALL 4 Ingest Paths
// ============================================================================

struct RejectSubjectFilter;
#[async_trait]
impl InboundFilter for RejectSubjectFilter {
    async fn evaluate(&self, msg: &InboundMessage) -> AppResult<FilterDecision> {
        if msg.subject.contains("[REJECT-TEST]") {
            Ok(FilterDecision::Reject {
                reason: "rejected by chain rule".to_string(),
            })
        } else {
            Ok(FilterDecision::Allow)
        }
    }
}

struct SpamSubjectFilter;
#[async_trait]
impl InboundFilter for SpamSubjectFilter {
    async fn evaluate(&self, msg: &InboundMessage) -> AppResult<FilterDecision> {
        if msg.subject.contains("[SPAM-TEST]") {
            Ok(FilterDecision::Spam {
                score: 9.7,
                reason: "spam heuristic matched".to_string(),
            })
        } else {
            Ok(FilterDecision::Allow)
        }
    }
}

struct MutateSubjectFilter;
#[async_trait]
impl InboundFilter for MutateSubjectFilter {
    async fn evaluate(&self, msg: &InboundMessage) -> AppResult<FilterDecision> {
        if msg.subject.contains("[MUTATE-TEST]") {
            Ok(FilterDecision::Mutate {
                add_labels: vec!["TRIAGED_CUSTOM".to_string()],
                remove_labels: vec![],
                skip_inbox: false,
            })
        } else {
            Ok(FilterDecision::Allow)
        }
    }
}

#[tokio::test]
async fn e2e_inbound_filter_chain_across_all_four_ingest_paths() {
    let dir = TempDir::new().unwrap();
    let imap_addr = pick_ephemeral_addr().await;
    let mock = MockServer::start().await;

    let mut cfg = make_sqlite_config(dir.path(), Some(imap_addr));
    cfg.sync_mode = SyncMode::Api;
    cfg.gmail_api_base_url = mock.uri();
    cfg.gmail_access_token = Some("filter-sync-tok".to_string());

    let store = Arc::new(SqliteStore::open(&cfg.db_path, &cfg.user_email).unwrap());
    let chain = FilterChain::new(vec![
        Arc::new(RejectSubjectFilter),
        Arc::new(SpamSubjectFilter),
        Arc::new(MutateSubjectFilter),
    ]);
    let state = AppState::with_backends(cfg, store.clone(), Arc::new(StubResendClient::noop()))
        .with_filter(Arc::new(chain));
    let app = build_router(state.clone());

    // --- Path 1: Resend webhook `POST /webhooks/resend` ---
    let (s, b) = http_json(
        &app,
        "POST",
        "/webhooks/resend",
        None,
        Some(json!({
            "type": "email.received",
            "created_at": "2025-02-01T00:00:00Z",
            "data": {
                "email_id": "re_f_reject",
                "from": "bad@ext.test",
                "to": ["agent@example.com"],
                "subject": "[REJECT-TEST] webhook drop",
                "message_id": "<wh-reject@ext.test>"
            }
        })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["status"], "rejected");
    assert!(
        store
            .find_message_by_rfc_message_id("<wh-reject@ext.test>")
            .await
            .unwrap()
            .is_none()
    );

    let (s, b) = http_json(
        &app,
        "POST",
        "/webhooks/resend",
        None,
        Some(json!({
            "type": "email.received",
            "created_at": "2025-02-01T00:01:00Z",
            "data": {
                "email_id": "re_f_spam",
                "from": "spam@ext.test",
                "to": ["agent@example.com"],
                "subject": "[SPAM-TEST] webhook spam",
                "message_id": "<wh-spam@ext.test>"
            }
        })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["filter_decision"], "spam");
    let wh_spam = store
        .find_message_by_rfc_message_id("<wh-spam@ext.test>")
        .await
        .unwrap()
        .unwrap();
    assert!(wh_spam.label_ids.contains(&LABEL_SPAM.to_string()));
    assert!(!wh_spam.label_ids.contains(&LABEL_INBOX.to_string()));

    let (s, b) = http_json(
        &app,
        "POST",
        "/webhooks/resend",
        None,
        Some(json!({
            "type": "email.received",
            "created_at": "2025-02-01T00:02:00Z",
            "data": {
                "email_id": "re_f_mutate",
                "from": "vip@ext.test",
                "to": ["agent@example.com"],
                "subject": "[MUTATE-TEST] webhook mutate",
                "message_id": "<wh-mutate@ext.test>"
            }
        })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["filter_decision"], "mutate");
    let wh_mut = store
        .find_message_by_rfc_message_id("<wh-mutate@ext.test>")
        .await
        .unwrap()
        .unwrap();
    assert!(wh_mut.label_ids.contains(&"TRIAGED_CUSTOM".to_string()));
    assert!(wh_mut.label_ids.contains(&LABEL_INBOX.to_string()));

    // --- Path 2: Gmail REST `messages.import` ---
    let raw_imp_reject = b"From: bad@imp.test\r\nTo: agent@example.com\r\nSubject: [REJECT-TEST] import drop\r\nMessage-ID: <imp-reject@imp.test>\r\n\r\nDrop";
    let (s, _) = http_json(
        &app,
        "POST",
        "/gmail/v1/users/me/messages/import",
        None,
        Some(json!({ "raw": b64url(raw_imp_reject) })),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(
        store
            .find_message_by_rfc_message_id("<imp-reject@imp.test>")
            .await
            .unwrap()
            .is_none()
    );

    let raw_imp_spam = b"From: spam@imp.test\r\nTo: agent@example.com\r\nSubject: [SPAM-TEST] import spam\r\nMessage-ID: <imp-spam@imp.test>\r\n\r\nSpam";
    let (s, _) = http_json(
        &app,
        "POST",
        "/gmail/v1/users/me/messages/import",
        None,
        Some(json!({ "raw": b64url(raw_imp_spam) })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let imp_spam = store
        .find_message_by_rfc_message_id("<imp-spam@imp.test>")
        .await
        .unwrap()
        .unwrap();
    assert!(imp_spam.label_ids.contains(&LABEL_SPAM.to_string()));
    assert!(!imp_spam.label_ids.contains(&LABEL_INBOX.to_string()));

    let raw_imp_mut = b"From: vip@imp.test\r\nTo: agent@example.com\r\nSubject: [MUTATE-TEST] import mutate\r\nMessage-ID: <imp-mutate@imp.test>\r\n\r\nMutate";
    let (s, _) = http_json(
        &app,
        "POST",
        "/gmail/v1/users/me/messages/import",
        None,
        Some(json!({ "raw": b64url(raw_imp_mut) })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let imp_mut = store
        .find_message_by_rfc_message_id("<imp-mutate@imp.test>")
        .await
        .unwrap()
        .unwrap();
    assert!(imp_mut.label_ids.contains(&"TRIAGED_CUSTOM".to_string()));
    assert!(imp_mut.label_ids.contains(&LABEL_INBOX.to_string()));

    // --- Path 3: Upstream Gmail Sync (`SyncMode::Api`) ---
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "labels": [] })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/profile"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "emailAddress": "agent@example.com",
            "messagesTotal": 3,
            "threadsTotal": 3,
            "historyId": "900"
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [
                { "id": "sync_rej", "threadId": "t_r" },
                { "id": "sync_spm", "threadId": "t_s" },
                { "id": "sync_mut", "threadId": "t_m" }
            ],
            "resultSizeEstimate": 3
        })))
        .mount(&mock)
        .await;

    for (id, raw) in [
        (
            "sync_rej",
            b"From: bad@sync.test\r\nSubject: [REJECT-TEST] sync drop\r\nMessage-ID: <sync-reject@sync.test>\r\n\r\nNo".as_slice(),
        ),
        (
            "sync_spm",
            b"From: spam@sync.test\r\nSubject: [SPAM-TEST] sync spam\r\nMessage-ID: <sync-spam@sync.test>\r\n\r\nSpam".as_slice(),
        ),
        (
            "sync_mut",
            b"From: vip@sync.test\r\nSubject: [MUTATE-TEST] sync mutate\r\nMessage-ID: <sync-mutate@sync.test>\r\n\r\nMut".as_slice(),
        ),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/gmail/v1/users/me/messages/{id}")))
            .and(query_param("format", "raw"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": id,
                "threadId": format!("th_{id}"),
                "labelIds": ["INBOX", "UNREAD"],
                "raw": b64url(raw)
            })))
            .mount(&mock)
            .await;
    }

    let sync_report = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(
        sync_report.messages_added, 2,
        "rejected sync msg must not be stored"
    );
    assert!(
        store
            .find_message_by_upstream_id("sync_rej")
            .await
            .unwrap()
            .is_none()
    );
    let sync_spm = store
        .find_message_by_upstream_id("sync_spm")
        .await
        .unwrap()
        .unwrap();
    assert!(sync_spm.label_ids.contains(&LABEL_SPAM.to_string()));
    assert!(!sync_spm.label_ids.contains(&LABEL_INBOX.to_string()));
    let sync_mut = store
        .find_message_by_upstream_id("sync_mut")
        .await
        .unwrap()
        .unwrap();
    assert!(sync_mut.label_ids.contains(&"TRIAGED_CUSTOM".to_string()));
    assert!(sync_mut.label_ids.contains(&LABEL_INBOX.to_string()));

    // --- Path 4: Embedded IMAP `APPEND` ---
    let (addr, shutdown_tx) = spawn_live_serve_imap(state.clone()).await;
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.unwrap();
    let _ = imap_cmd(&mut reader, "F0", "LOGIN agent@example.com imap-secret").await;

    let raw_imap_rej = "From: bad@imap.test\r\nSubject: [REJECT-TEST] imap drop\r\nMessage-ID: <imap-reject@imap.test>\r\n\r\nDrop";
    let res_rej = imap_cmd(
        &mut reader,
        "F1",
        &format!("APPEND INBOX {{{}+}}\r\n{raw_imap_rej}", raw_imap_rej.len()),
    )
    .await;
    assert!(
        res_rej.last().unwrap().contains("F1 NO [REJECTED]"),
        "expected NO [REJECTED], got: {res_rej:?}"
    );
    assert!(
        store
            .find_message_by_rfc_message_id("<imap-reject@imap.test>")
            .await
            .unwrap()
            .is_none()
    );

    let raw_imap_spm = "From: spam@imap.test\r\nSubject: [SPAM-TEST] imap spam\r\nMessage-ID: <imap-spam@imap.test>\r\n\r\nSpam";
    let res_spm = imap_cmd(
        &mut reader,
        "F2",
        &format!("APPEND INBOX {{{}+}}\r\n{raw_imap_spm}", raw_imap_spm.len()),
    )
    .await;
    assert!(res_spm.last().unwrap().starts_with("F2 OK [APPENDUID "));
    let imap_spm = store
        .find_message_by_rfc_message_id("<imap-spam@imap.test>")
        .await
        .unwrap()
        .unwrap();
    assert!(imap_spm.label_ids.contains(&LABEL_SPAM.to_string()));
    assert!(!imap_spm.label_ids.contains(&LABEL_INBOX.to_string()));

    let raw_imap_mut = "From: vip@imap.test\r\nSubject: [MUTATE-TEST] imap mutate\r\nMessage-ID: <imap-mutate@imap.test>\r\n\r\nMut";
    let res_mut = imap_cmd(
        &mut reader,
        "F3",
        &format!("APPEND INBOX {{{}+}}\r\n{raw_imap_mut}", raw_imap_mut.len()),
    )
    .await;
    assert!(res_mut.last().unwrap().starts_with("F3 OK [APPENDUID "));
    let imap_mut = store
        .find_message_by_rfc_message_id("<imap-mutate@imap.test>")
        .await
        .unwrap()
        .unwrap();
    assert!(imap_mut.label_ids.contains(&"TRIAGED_CUSTOM".to_string()));
    assert!(imap_mut.label_ids.contains(&LABEL_INBOX.to_string()));

    let _ = imap_cmd(&mut reader, "F4", "LOGOUT").await;
    let _ = shutdown_tx.send(true);
}

// ============================================================================
// 8. Pluggable Trait #4: `OutboundPolicy` (`HoldForApproval` 202 + `Deny` 403)
// ============================================================================

struct RecordingMemoryTransport {
    sent: Arc<Mutex<Vec<OutboundMessage>>>,
}

impl RecordingMemoryTransport {
    fn new() -> (Self, Arc<Mutex<Vec<OutboundMessage>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (Self { sent: sent.clone() }, sent)
    }
}

#[async_trait]
impl MailTransport for RecordingMemoryTransport {
    fn name(&self) -> &'static str {
        "in_memory_transport"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            provider: "in_memory_transport".to_string(),
            supports_raw_mime: true,
            supports_scheduled_send: false,
            supports_idempotency_key: true,
            supports_inbound_webhooks: false,
            supports_delivery_webhooks: false,
            max_message_bytes: 25 * 1024 * 1024,
        }
    }

    async fn send(
        &self,
        msg: &OutboundMessage,
        _idempotency_key: Option<&str>,
    ) -> AppResult<SendOutcome> {
        let mut guard = self.sent.lock().unwrap();
        guard.push(msg.clone());
        let n = guard.len();
        Ok(SendOutcome {
            provider: "in_memory_transport".to_string(),
            provider_message_id: format!("mem_tx_{n}"),
        })
    }
}

struct SubjectGuardPolicy;

#[async_trait]
impl OutboundPolicy for SubjectGuardPolicy {
    async fn evaluate(&self, check: &OutboundCheck) -> AppResult<OutboundDecision> {
        if check.subject.contains("[HOLD]") {
            Ok(OutboundDecision::HoldForApproval {
                reason: "requires manager approval".to_string(),
            })
        } else if check.subject.contains("[DENY]") {
            Ok(OutboundDecision::Deny {
                code: "dlp_policy_denied".to_string(),
                reason: "outbound secret detected".to_string(),
                hint: Some("Remove secret markers before sending.".to_string()),
            })
        } else {
            Ok(OutboundDecision::Allow)
        }
    }

    fn policy_checks(&self, check: &OutboundCheck) -> Vec<PolicyCheck> {
        let blocked = check.subject.contains("[DENY]");
        vec![PolicyCheck {
            rule: "subject_dlp_guard".to_string(),
            passed: !blocked,
            detail: if blocked {
                "Denied by subject DLP guard".to_string()
            } else {
                "Subject passed DLP guard".to_string()
            },
        }]
    }

    fn backend_name(&self) -> &'static str {
        "subject_guard_policy"
    }
}

#[tokio::test]
async fn e2e_outbound_policy_hold_for_approval_202_and_deny_403_without_transport() {
    let cfg = Config::for_test();
    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let (transport, sent_log) = RecordingMemoryTransport::new();

    let state = AppState::with_backends(cfg, store, Arc::new(StubResendClient::forbid_send()))
        .with_transport(Arc::new(transport))
        .with_outbound_policy(Arc::new(SubjectGuardPolicy));
    let app = build_router(state);

    // 1. HoldForApproval -> HTTP 202 Accepted without calling MailTransport
    let (status, body) = http_json(
        &app,
        "POST",
        "/v1/messages/send",
        None,
        Some(json!({
            "to": ["partner@external.test"],
            "subject": "[HOLD] Wire transfer confirmation",
            "text": "Please approve this payment."
        })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "expected 202: {body}");
    assert_eq!(body["status"], "pending_approval");
    assert_eq!(body["held_for_approval"], true);
    assert_eq!(body["reason"], "requires manager approval");
    assert!(body["draft_id"].as_str().is_some());
    assert_eq!(
        sent_log.lock().unwrap().len(),
        0,
        "transport must NOT be called on HoldForApproval"
    );

    // 2. Deny -> HTTP 403 Forbidden without calling MailTransport
    let (status, body) = http_json(
        &app,
        "POST",
        "/v1/messages/send",
        None,
        Some(json!({
            "to": ["partner@external.test"],
            "subject": "[DENY] Export credentials",
            "text": "SECRET=xyz"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "expected 403: {body}");
    assert_eq!(body["error"]["code"], "dlp_policy_denied");
    assert_eq!(
        body["error"]["hint"],
        "Remove secret markers before sending."
    );
    assert_eq!(
        sent_log.lock().unwrap().len(),
        0,
        "transport must NOT be called on Deny"
    );

    // 3. Gmail REST `messages.send` also blocks Deny and HoldForApproval without calling transport
    let raw_denied = b"From: agent@example.com\r\nTo: partner@external.test\r\nSubject: [DENY] Gmail leak\r\n\r\nNope";
    let (g_status, _) = http_json(
        &app,
        "POST",
        "/gmail/v1/users/me/messages/send",
        None,
        Some(json!({ "raw": b64url(raw_denied) })),
    )
    .await;
    assert_eq!(g_status, StatusCode::FORBIDDEN);
    assert_eq!(sent_log.lock().unwrap().len(), 0);

    // 4. Allowed send invokes custom transport once
    let (ok_status, ok_body) = http_json(
        &app,
        "POST",
        "/v1/messages/send",
        None,
        Some(json!({
            "to": ["partner@external.test"],
            "subject": "Normal approved update",
            "text": "All good."
        })),
    )
    .await;
    assert_eq!(ok_status, StatusCode::OK, "expected 200: {ok_body}");
    assert_eq!(sent_log.lock().unwrap().len(), 1);
}

// ============================================================================
// 9. Pluggable Traits #5, #6, #7: `AuthProvider` + `MailTransport` + `SearchIndex`
// ============================================================================

struct ScopedCustomAuth {
    bearer_calls: Arc<AtomicUsize>,
    imap_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl AuthProvider for ScopedCustomAuth {
    async fn authenticate_bearer(&self, token: Option<&str>) -> AppResult<Principal> {
        self.bearer_calls.fetch_add(1, Ordering::SeqCst);
        match token {
            Some("scoped-agent-jwt") => Ok(Principal {
                mailbox_id: "agent@example.com".to_string(),
                scopes: vec![AuthScope::Read, AuthScope::Write, AuthScope::Send],
                agent_policy: Some(AgentPolicyOverride {
                    draft_only: Some(false),
                    allowed_recipients: None,
                    max_send_recipients: Some(10),
                }),
            }),
            _ => Err(AppError::Unauthorized(
                "invalid custom bearer token".to_string(),
            )),
        }
    }

    async fn authenticate_imap(&self, username: &str, password: &str) -> AppResult<Principal> {
        self.imap_calls.fetch_add(1, Ordering::SeqCst);
        if username == "custom-imap-user" && password == "custom-imap-pass" {
            Ok(Principal {
                mailbox_id: "agent@example.com".to_string(),
                scopes: vec![AuthScope::Read, AuthScope::Write],
                agent_policy: None,
            })
        } else {
            Err(AppError::Unauthorized(
                "invalid custom IMAP credentials".to_string(),
            ))
        }
    }

    fn backend_name(&self) -> &'static str {
        "scoped_oidc"
    }
}

struct TrackingSearchIndex {
    inner: StoreSearchIndex,
    indexed_ids: Arc<Mutex<Vec<String>>>,
    removed_ids: Arc<Mutex<Vec<String>>>,
    search_queries: Arc<Mutex<Vec<Option<String>>>>,
}

#[async_trait]
impl SearchIndex for TrackingSearchIndex {
    async fn index(&self, msg: &StoredMessage) -> AppResult<()> {
        self.indexed_ids.lock().unwrap().push(msg.id.clone());
        self.inner.index(msg).await
    }

    async fn remove(&self, message_id: &str) -> AppResult<()> {
        self.removed_ids
            .lock()
            .unwrap()
            .push(message_id.to_string());
        self.inner.remove(message_id).await
    }

    async fn search(&self, query: &AiSearchQuery) -> AppResult<AiMessagePage> {
        self.search_queries.lock().unwrap().push(query.q.clone());
        self.inner.search(query).await
    }

    fn backend_name(&self) -> &'static str {
        "custom_hybrid_index"
    }
}

#[tokio::test]
async fn e2e_custom_auth_provider_mail_transport_and_search_index_seams() {
    let dir = TempDir::new().unwrap();
    let imap_addr = pick_ephemeral_addr().await;
    let cfg = make_sqlite_config(dir.path(), Some(imap_addr));
    let store = Arc::new(SqliteStore::open(&cfg.db_path, &cfg.user_email).unwrap());

    let bearer_calls = Arc::new(AtomicUsize::new(0));
    let imap_calls = Arc::new(AtomicUsize::new(0));
    let (transport, sent_messages) = RecordingMemoryTransport::new();
    let indexed_ids = Arc::new(Mutex::new(Vec::new()));
    let removed_ids = Arc::new(Mutex::new(Vec::new()));
    let search_queries = Arc::new(Mutex::new(Vec::new()));

    let state = AppState::with_backends(
        cfg,
        store.clone(),
        // Panics if ResendClient::send_email is EVER invoked!
        Arc::new(StubResendClient::forbid_send()),
    )
    .with_auth(Arc::new(ScopedCustomAuth {
        bearer_calls: bearer_calls.clone(),
        imap_calls: imap_calls.clone(),
    }))
    .with_transport(Arc::new(transport))
    .with_search(Arc::new(TrackingSearchIndex {
        inner: StoreSearchIndex::new(store.clone()),
        indexed_ids: indexed_ids.clone(),
        removed_ids: removed_ids.clone(),
        search_queries: search_queries.clone(),
    }));

    let app = build_router(state.clone());

    // 1. Custom AuthProvider on HTTP: rejects missing/wrong token, accepts scoped bearer token
    let (unauth_status, _) = http_json(&app, "GET", "/v1/capabilities", None, None).await;
    assert_eq!(unauth_status, StatusCode::UNAUTHORIZED);

    let (ok_status, caps) = http_json(
        &app,
        "GET",
        "/v1/capabilities",
        Some("Bearer scoped-agent-jwt"),
        None,
    )
    .await;
    assert_eq!(ok_status, StatusCode::OK);
    assert_eq!(caps["backends"]["auth"], "scoped_oidc");
    assert_eq!(caps["backends"]["transport"], "in_memory_transport");
    assert_eq!(caps["backends"]["search"], "custom_hybrid_index");
    assert!(bearer_calls.load(Ordering::SeqCst) >= 2);

    // 2. Custom AuthProvider on live IMAP: rejects wrong creds, accepts custom creds
    let (addr, shutdown_tx) = spawn_live_serve_imap(state.clone()).await;
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.unwrap();

    let bad_imap = imap_cmd(&mut reader, "C1", "LOGIN agent@example.com imap-secret").await;
    assert!(
        bad_imap
            .last()
            .unwrap()
            .contains("C1 NO [AUTHENTICATIONFAILED]")
    );
    let good_imap = imap_cmd(&mut reader, "C2", "LOGIN custom-imap-user custom-imap-pass").await;
    assert!(good_imap.last().unwrap().starts_with("C2 OK"));
    let _ = imap_cmd(&mut reader, "C3", "LOGOUT").await;

    // Also verify AUTHENTICATE PLAIN (SASL-IR) routes through ScopedCustomAuth
    let stream2 = TcpStream::connect(addr).await.unwrap();
    let mut reader2 = BufReader::new(stream2);
    let mut g2 = String::new();
    reader2.read_line(&mut g2).await.unwrap();
    let sasl_ir =
        base64::engine::general_purpose::STANDARD.encode("\0custom-imap-user\0custom-imap-pass");
    let auth_ir = imap_cmd(&mut reader2, "C4", &format!("AUTHENTICATE PLAIN {sasl_ir}")).await;
    assert!(auth_ir.last().unwrap().starts_with("C4 OK"));
    let _ = imap_cmd(&mut reader2, "C5", "LOGOUT").await;

    let _ = shutdown_tx.send(true);
    assert_eq!(imap_calls.load(Ordering::SeqCst), 3);

    // 3. Custom MailTransport: BOTH AI `/v1/messages/send` AND Gmail `/gmail/v1/users/me/messages/send`
    //    deliver verbatim `raw_rfc2822` without touching Resend (`StubResendClient::forbid_send`)!
    let (ai_status, ai_body) = http_json(
        &app,
        "POST",
        "/v1/messages/send",
        Some("Bearer scoped-agent-jwt"),
        Some(json!({
            "to": ["alice@example.com"],
            "subject": "AI Verbatim Raw Check",
            "text": "Delivered by custom in-memory transport."
        })),
    )
    .await;
    assert_eq!(ai_status, StatusCode::OK, "ai send failed: {ai_body}");
    assert_eq!(ai_body["provider"], "in_memory_transport");
    let ai_msg_id = ai_body["message_id"].as_str().unwrap().to_string();

    let verbatim_gmail_raw = concat!(
        "From: agent@example.com\r\n",
        "To: bob@example.com\r\n",
        "Subject: Gmail Verbatim Raw Check\r\n",
        "X-Custom-Verbatim: exact-bytes-42\r\n",
        "\r\n",
        "Verbatim body via Gmail REST send.\r\n"
    )
    .as_bytes();
    let (gm_status, gm_body) = http_json(
        &app,
        "POST",
        "/gmail/v1/users/me/messages/send",
        Some("Bearer scoped-agent-jwt"),
        Some(json!({ "raw": b64url(verbatim_gmail_raw) })),
    )
    .await;
    assert_eq!(gm_status, StatusCode::OK, "gmail send failed: {gm_body}");
    let gm_msg_id = gm_body["id"].as_str().unwrap().to_string();

    {
        let sent = sent_messages.lock().unwrap();
        assert_eq!(sent.len(), 2);
        // AI send built valid RFC 2822 bytes
        let ai_raw_str = String::from_utf8_lossy(&sent[0].raw_rfc2822);
        assert!(ai_raw_str.contains("Subject: AI Verbatim Raw Check"));
        assert!(ai_raw_str.contains("Delivered by custom in-memory transport."));
        // Gmail send preserved verbatim `raw_rfc2822` byte-for-byte
        assert_eq!(sent[1].raw_rfc2822.as_slice(), verbatim_gmail_raw);
    }

    // 4. Custom SearchIndex: `index` called on both sends, `search` called via `/v1/search` & MCP,
    //    `remove` called on `DELETE /gmail/v1/users/me/messages/{id}`
    {
        let idx = indexed_ids.lock().unwrap();
        assert!(idx.contains(&ai_msg_id));
        assert!(idx.contains(&gm_msg_id));
    }

    let (search_status, search_body) = http_json(
        &app,
        "GET",
        "/v1/search?q=Verbatim",
        Some("Bearer scoped-agent-jwt"),
        None,
    )
    .await;
    assert_eq!(search_status, StatusCode::OK);
    assert_eq!(search_body["messages"].as_array().unwrap().len(), 2);

    let mcp = McpServer::new(state.clone());
    let mcp_resp = mcp
        .handle_request(json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "search_emails",
                "arguments": { "query": "Verbatim" }
            }
        }))
        .await
        .unwrap()
        .unwrap();
    assert!(mcp_resp.get("result").is_some());
    assert_eq!(search_queries.lock().unwrap().len(), 2);

    let (del_status, _) = http_json(
        &app,
        "DELETE",
        &format!("/gmail/v1/users/me/messages/{gm_msg_id}"),
        Some("Bearer scoped-agent-jwt"),
        None,
    )
    .await;
    assert_eq!(del_status, StatusCode::NO_CONTENT);
    assert!(removed_ids.lock().unwrap().contains(&gm_msg_id));
}
