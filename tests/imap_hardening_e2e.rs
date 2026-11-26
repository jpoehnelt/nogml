//! End-to-end regression tests for Issue #59 IMAP4rev1 hardening:
//! - `UID EXPUNGE <uid-set>` selective expunge & external `FsBlobStore` cleanup on `EXPUNGE`/`UID EXPUNGE`/`CLOSE`
//! - RFC 3501 §5.2 sequence-number stability under concurrent deletion
//! - Pre-auth DoS limits (16 KiB literal cap, nested `(` / `NOT` depth rejection)
//! - TLS `LOGINDISABLED` / `[PRIVACYREQUIRED]`, re-auth rejection, `AUTHENTICATE PLAIN` `authzid` validation, and 5-failure disconnect
//! - Cancel-safe `IDLE` `DONE` reading across concurrent `EventBus` pushes
//! - Lazy `FETCH` blob loading, external-blob `SEARCH`, failed `SELECT` deselection, atomic `UNCHANGEDSINCE` CAS, CRLF/mailbox escaping, embedded `message/rfc822` `BODY[n.HEADER]`/`BODY[n.TEXT]`, and concurrent connection cap

use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use base64::Engine as _;
use nogml::{
    AppState,
    auth::{AuthScope, ScopedTokenConfig},
    blob::{BlobStore, FsBlobStore, attachment_blob_key, raw_message_blob_key},
    config::Config,
    error::AppResult,
    events::{EventSource, MailEvent},
    imap::{
        build_tls_acceptor, mime_fmt::parse_raw_to_new_message_input, serve_plain_listener,
        serve_plain_listener_with_limit,
    },
    models::{
        LABEL_INBOX, LABEL_UNREAD, ResendReceivedAttachment, ResendReceivedEmail,
        ResendSendEmailRequest, ResendSendEmailResponse,
    },
    resend::ResendClient,
    storage::{MailStore, NewAttachmentInput, SqliteStore},
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::watch,
};

struct NoopResendClient;

#[async_trait]
impl ResendClient for NoopResendClient {
    async fn send_email(
        &self,
        _req: &ResendSendEmailRequest,
        _idempotency_key: Option<&str>,
    ) -> AppResult<ResendSendEmailResponse> {
        Ok(ResendSendEmailResponse {
            id: "re_noop".to_string(),
        })
    }

    async fn get_received_email(&self, _email_id: &str) -> AppResult<ResendReceivedEmail> {
        unimplemented!("not used in IMAP tests")
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

/// Wrapper around [`FsBlobStore`] that counts `get()` calls to prove lazy loading in `FETCH`.
struct CountingBlobStore {
    inner: FsBlobStore,
    gets: Arc<AtomicUsize>,
}

#[async_trait]
impl BlobStore for CountingBlobStore {
    async fn put(&self, key: &str, bytes: &[u8]) -> AppResult<()> {
        self.inner.put(key, bytes).await
    }

    async fn get(&self, key: &str) -> AppResult<Option<Vec<u8>>> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        self.inner.get(key).await
    }

    async fn delete(&self, key: &str) -> AppResult<()> {
        self.inner.delete(key).await
    }

    fn backend_name(&self) -> &'static str {
        "fs"
    }
}

fn make_test_config(dir: &Path) -> Config {
    let mut cfg = Config::for_test();
    cfg.db_path = dir.join("imap_hardening.db");
    cfg.blob_dir = dir.join("blobs");
    cfg.user_email = "agent@example.com".to_string();
    cfg.imap_password = Some("secret-admin-pass".to_string());
    cfg.scoped_tokens = vec![
        ScopedTokenConfig {
            token: "tok-rw".to_string(),
            mailbox_id: None,
            scopes: vec![AuthScope::Read, AuthScope::Write],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok-admin".to_string(),
            mailbox_id: None,
            scopes: vec![AuthScope::Admin],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
    ];
    cfg
}

fn make_ephemeral_tls(
    dir: &Path,
) -> (
    std::path::PathBuf,
    std::path::PathBuf,
    tokio_rustls::TlsConnector,
) {
    use rustls::RootCertStore;
    use rustls_pki_types::{CertificateDer, pem::PemObject};

    nogml::ensure_crypto_provider();
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .expect("generate ephemeral self-signed cert");
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();
    let cert_path = dir.join("imap-cert.pem");
    let key_path = dir.join("imap-key.pem");
    std::fs::write(&cert_path, cert_pem.as_bytes()).unwrap();
    std::fs::write(&key_path, key_pem.as_bytes()).unwrap();

    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    for cert in certs {
        roots.add(cert).unwrap();
    }
    let client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (
        cert_path,
        key_path,
        tokio_rustls::TlsConnector::from(Arc::new(client_cfg)),
    )
}

async fn read_line_timeout<S: AsyncRead + Unpin>(reader: &mut BufReader<S>) -> Option<String> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .expect("timed out reading IMAP line")
        .expect("IO error reading IMAP line");
    if n == 0 { None } else { Some(line) }
}

async fn send_cmd<S: AsyncRead + AsyncWrite + Unpin>(
    reader: &mut BufReader<S>,
    tag: &str,
    cmd: &str,
) -> Vec<String> {
    let wire = format!("{tag} {cmd}\r\n");
    reader.get_mut().write_all(wire.as_bytes()).await.unwrap();
    reader.get_mut().flush().await.unwrap();

    let prefix_ok = format!("{tag} OK");
    let prefix_no = format!("{tag} NO");
    let prefix_bad = format!("{tag} BAD");
    let mut lines = Vec::new();
    loop {
        let Some(line) = read_line_timeout(reader).await else {
            break;
        };
        let done = line.starts_with(&prefix_ok)
            || line.starts_with(&prefix_no)
            || line.starts_with(&prefix_bad);
        lines.push(line);
        if done {
            break;
        }
    }
    lines
}

async fn spawn_plain_imap(
    state: AppState,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
) -> (std::net::SocketAddr, watch::Sender<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = serve_plain_listener(listener, state, tls_acceptor, rx).await;
    });
    (addr, tx)
}

async fn seed_raw_message(
    state: &AppState,
    mailbox: &str,
    raw: &str,
    extra_att: Option<NewAttachmentInput>,
) -> nogml::storage::StoredMessage {
    let mut input = parse_raw_to_new_message_input(
        raw.as_bytes().to_vec(),
        vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
        None,
        "local",
        None,
        None,
        false,
        false,
    );
    if let Some(att) = extra_att {
        input.attachments.push(att);
    }
    let (_, _, stored) = state.store.imap_append(mailbox, input).await.unwrap();
    state.post_store_message(&stored).await.unwrap();
    stored
}

#[tokio::test]
async fn uid_expunge_preserves_unselected_deleted_uids_and_cleans_external_blobs() {
    let dir = TempDir::new().unwrap();
    let cfg = make_test_config(dir.path());
    let store = Arc::new(SqliteStore::open(&cfg.db_path, &cfg.user_email).unwrap());
    let blobs = Arc::new(FsBlobStore::open(&cfg.blob_dir).unwrap());
    let state = AppState::with_backends(cfg, store.clone(), Arc::new(NoopResendClient))
        .with_blobs(blobs.clone());

    let msg1 = seed_raw_message(
        &state,
        "INBOX",
        "From: a@example.com\r\nSubject: First\r\n\r\nFirst body\r\n",
        Some(NewAttachmentInput {
            part_id: "2".to_string(),
            filename: Some("doc1.txt".to_string()),
            content_type: "text/plain".to_string(),
            content_id: None,
            data: b"attachment-1-payload".to_vec(),
        }),
    )
    .await;
    let msg2 = seed_raw_message(
        &state,
        "INBOX",
        "From: b@example.com\r\nSubject: Second\r\n\r\nSecond body\r\n",
        Some(NewAttachmentInput {
            part_id: "2".to_string(),
            filename: Some("doc2.txt".to_string()),
            content_type: "text/plain".to_string(),
            content_id: None,
            data: b"attachment-2-payload".to_vec(),
        }),
    )
    .await;

    let msg1_atts = store.list_attachment_meta(&msg1.id).await.unwrap();
    let msg2_atts = store.list_attachment_meta(&msg2.id).await.unwrap();
    assert_eq!(msg1_atts.len(), 1);
    assert_eq!(msg2_atts.len(), 1);

    // Confirm external blobs exist for both messages before expunge.
    assert!(
        blobs
            .get(&raw_message_blob_key(&msg1.id))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        blobs
            .get(&attachment_blob_key(&msg1.id, &msg1_atts[0].id))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        blobs
            .get(&raw_message_blob_key(&msg2.id))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        blobs
            .get(&attachment_blob_key(&msg2.id, &msg2_atts[0].id))
            .await
            .unwrap()
            .is_some()
    );

    let (addr, shutdown_tx) = spawn_plain_imap(state.clone(), None).await;
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut reader = BufReader::new(tcp);
    let _greeting = read_line_timeout(&mut reader).await.unwrap();

    let login = send_cmd(
        &mut reader,
        "A1",
        r#"LOGIN "agent@example.com" "secret-admin-pass""#,
    )
    .await;
    assert!(login.last().unwrap().starts_with("A1 OK"));
    let sel = send_cmd(&mut reader, "A2", "SELECT INBOX").await;
    assert!(sel.last().unwrap().starts_with("A2 OK"));

    // Mark BOTH UID 1 and UID 2 as \Deleted.
    let st = send_cmd(&mut reader, "A3", r#"UID STORE 1:2 +FLAGS (\Deleted)"#).await;
    assert!(st.last().unwrap().starts_with("A3 OK"));

    // UID EXPUNGE 1 MUST expunge ONLY UID 1, preserving \Deleted UID 2!
    let uexp = send_cmd(&mut reader, "A4", "UID EXPUNGE 1").await;
    assert!(
        uexp.iter().any(|l| l.trim() == "* 1 EXPUNGE"),
        "got {uexp:?}"
    );
    assert!(uexp.last().unwrap().starts_with("A4 OK"));

    let remaining = store.imap_list_messages("INBOX").await.unwrap();
    assert_eq!(remaining.len(), 1, "UID 2 must remain in INBOX");
    assert_eq!(remaining[0].message_id, msg2.id);
    assert!(remaining[0].is_deleted, "UID 2 must retain \\Deleted flag");

    // Now SELECT [Gmail]/Trash, mark msg1 \Deleted, and UID EXPUNGE 1 -> permanently deletes msg1 + blobs!
    let sel_trash = send_cmd(&mut reader, "A5", r#"SELECT "[Gmail]/Trash""#).await;
    assert!(sel_trash.last().unwrap().starts_with("A5 OK"));
    let st_trash = send_cmd(&mut reader, "A6", r#"UID STORE 1 +FLAGS (\Deleted)"#).await;
    assert!(st_trash.last().unwrap().starts_with("A6 OK"));
    let exp_trash = send_cmd(&mut reader, "A7", "UID EXPUNGE 1").await;
    assert!(exp_trash.last().unwrap().starts_with("A7 OK"));

    assert!(store.get_message(&msg1.id).await.unwrap().is_none());
    assert!(
        blobs
            .get(&raw_message_blob_key(&msg1.id))
            .await
            .unwrap()
            .is_none(),
        "raw RFC 2822 blob must be deleted on Trash UID EXPUNGE"
    );
    assert!(
        blobs
            .get(&attachment_blob_key(&msg1.id, &msg1_atts[0].id))
            .await
            .unwrap()
            .is_none(),
        "attachment blob must be deleted on Trash UID EXPUNGE"
    );

    // Also verify CLOSE on [Gmail]/Trash cleans up external blobs for msg2!
    let sel_inbox = send_cmd(&mut reader, "A8", "SELECT INBOX").await;
    assert!(sel_inbox.last().unwrap().starts_with("A8 OK"));
    let exp2 = send_cmd(&mut reader, "A9", "EXPUNGE").await;
    assert!(exp2.last().unwrap().starts_with("A9 OK"));

    let sel_trash2 = send_cmd(&mut reader, "A10", r#"SELECT "[Gmail]/Trash""#).await;
    assert!(sel_trash2.last().unwrap().starts_with("A10 OK"));
    let st_trash2 = send_cmd(&mut reader, "A11", r#"STORE 1 +FLAGS (\Deleted)"#).await;
    assert!(st_trash2.last().unwrap().starts_with("A11 OK"));
    let close_resp = send_cmd(&mut reader, "A12", "CLOSE").await;
    assert!(close_resp.last().unwrap().starts_with("A12 OK"));

    assert!(store.get_message(&msg2.id).await.unwrap().is_none());
    assert!(
        blobs
            .get(&raw_message_blob_key(&msg2.id))
            .await
            .unwrap()
            .is_none(),
        "raw RFC 2822 blob must be deleted on Trash CLOSE"
    );
    assert!(
        blobs
            .get(&attachment_blob_key(&msg2.id, &msg2_atts[0].id))
            .await
            .unwrap()
            .is_none(),
        "attachment blob must be deleted on Trash CLOSE"
    );

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn sequence_number_stability_under_concurrent_deletion() {
    let dir = TempDir::new().unwrap();
    let cfg = make_test_config(dir.path());
    let store = Arc::new(SqliteStore::open(&cfg.db_path, &cfg.user_email).unwrap());
    let state = AppState::with_backends(cfg, store.clone(), Arc::new(NoopResendClient));

    let msg1 = seed_raw_message(
        &state,
        "INBOX",
        "From: a@example.com\r\nSubject: First Message\r\n\r\nBody one\r\n",
        None,
    )
    .await;
    let msg2 = seed_raw_message(
        &state,
        "INBOX",
        "From: b@example.com\r\nSubject: Second Message\r\n\r\nBody two\r\n",
        None,
    )
    .await;

    let (addr, shutdown_tx) = spawn_plain_imap(state.clone(), None).await;
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut reader = BufReader::new(tcp);
    let _greeting = read_line_timeout(&mut reader).await.unwrap();

    let _ = send_cmd(
        &mut reader,
        "A1",
        r#"LOGIN "agent@example.com" "secret-admin-pass""#,
    )
    .await;
    let sel = send_cmd(&mut reader, "A2", "SELECT INBOX").await;
    assert!(sel.iter().any(|l| l.trim() == "* 2 EXISTS"));

    // Concurrently delete msg1 behind the IMAP client's back (without delivering EXPUNGE yet).
    assert!(store.delete_message(&msg1.id).await.unwrap());

    // RFC 3501 §5.2: STORE 1 +FLAGS (\Deleted) MUST NOT shift onto msg2!
    let st1 = send_cmd(&mut reader, "A3", r#"STORE 1 +FLAGS (\Deleted)"#).await;
    assert!(st1.last().unwrap().starts_with("A3 OK"));
    assert!(
        !st1.iter().any(|l| l.contains(" FETCH (")),
        "STORE 1 on concurrently deleted msg1 must not emit FETCH for msg2: {st1:?}"
    );
    let msg2_fresh = store.get_message(&msg2.id).await.unwrap().unwrap();
    assert!(
        !msg2_fresh.is_deleted,
        "msg2 must NOT be marked \\Deleted when client ran STORE 1"
    );

    // FETCH 1 must not return msg2; FETCH 2 must still address msg2 at sequence number 2.
    let f1 = send_cmd(&mut reader, "A4", "FETCH 1 (UID FLAGS)").await;
    assert!(!f1.iter().any(|l| l.contains(" FETCH (")), "got {f1:?}");
    let f2 = send_cmd(&mut reader, "A5", "FETCH 2 (UID FLAGS)").await;
    assert!(
        f2.iter().any(|l| l.starts_with("* 2 FETCH (UID 2 ")),
        "FETCH 2 must still return msg2 as seq 2, got {f2:?}"
    );

    // SEARCH 1 must not match msg2; SEARCH 2 must match seq 2.
    let s1 = send_cmd(&mut reader, "A6", "SEARCH 1").await;
    assert!(s1.iter().any(|l| l.trim() == "* SEARCH"), "got {s1:?}");
    let s2 = send_cmd(&mut reader, "A7", "SEARCH 2").await;
    assert!(s2.iter().any(|l| l.trim() == "* SEARCH 2"), "got {s2:?}");

    // COPY 1 must not copy msg2.
    let cp1 = send_cmd(&mut reader, "A8", r#"COPY 1 "[Gmail]/Starred""#).await;
    assert!(cp1.last().unwrap().starts_with("A8 OK"));
    assert!(
        store
            .imap_list_messages("[Gmail]/Starred")
            .await
            .unwrap()
            .is_empty(),
        "COPY 1 must not copy msg2"
    );

    // NOOP now delivers `* 1 EXPUNGE`, shifting msg2 down to seq 1 cleanly.
    let noop = send_cmd(&mut reader, "A9", "NOOP").await;
    assert!(
        noop.iter().any(|l| l.trim() == "* 1 EXPUNGE"),
        "NOOP must deliver * 1 EXPUNGE, got {noop:?}"
    );
    let f1_after = send_cmd(&mut reader, "A10", "FETCH 1 (UID)").await;
    assert!(
        f1_after.iter().any(|l| l.starts_with("* 1 FETCH (UID 2)")),
        "after EXPUNGE, seq 1 must now be UID 2, got {f1_after:?}"
    );

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn pre_auth_dos_oversized_literal_and_nested_parens_and_search_depth_rejected() {
    let dir = TempDir::new().unwrap();
    let cfg = make_test_config(dir.path());
    let store = Arc::new(SqliteStore::open(&cfg.db_path, &cfg.user_email).unwrap());
    let state = AppState::with_backends(cfg, store, Arc::new(NoopResendClient));

    let (addr, shutdown_tx) = spawn_plain_imap(state, None).await;

    // 1. Pre-auth oversized synchronizing literal (> 16 KiB) rejected with NO [TOOBIG].
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut reader = BufReader::new(tcp);
    let _greeting = read_line_timeout(&mut reader).await.unwrap();
    let too_big = send_cmd(&mut reader, "P1", "LOGIN {20000}").await;
    assert!(
        too_big.iter().any(|l| l.contains("P1 NO [TOOBIG]")),
        "expected NO [TOOBIG] for pre-auth >16 KiB literal, got {too_big:?}"
    );

    // 2. Deeply nested parentheses rejected cleanly without crashing server.
    let nested = format!("{}ALL{}", "(".repeat(64), ")".repeat(64));
    reader
        .get_mut()
        .write_all(format!("P2 SEARCH {nested}\r\n").as_bytes())
        .await
        .unwrap();
    reader.get_mut().flush().await.unwrap();
    let bad_nest = read_line_timeout(&mut reader).await.unwrap();
    assert!(
        bad_nest.starts_with("* BAD"),
        "expected * BAD for deep parens, got {bad_nest:?}"
    );

    // 3. Pre-auth oversized LITERAL+ closes connection immediately without allocating.
    reader
        .get_mut()
        .write_all(b"P3 LOGIN {20000+}\r\n")
        .await
        .unwrap();
    reader.get_mut().flush().await.unwrap();
    let lit_plus_err = read_line_timeout(&mut reader).await.unwrap();
    assert!(lit_plus_err.starts_with("* BAD"), "got {lit_plus_err:?}");
    assert!(
        read_line_timeout(&mut reader).await.is_none(),
        "server must close connection after oversized LITERAL+"
    );

    // 4. Authenticated deeply nested SEARCH NOT chain rejected with BAD.
    let tcp2 = TcpStream::connect(addr).await.unwrap();
    let mut reader2 = BufReader::new(tcp2);
    let _ = read_line_timeout(&mut reader2).await.unwrap();
    let _ = send_cmd(
        &mut reader2,
        "B1",
        r#"LOGIN "agent@example.com" "secret-admin-pass""#,
    )
    .await;
    let _ = send_cmd(&mut reader2, "B2", "SELECT INBOX").await;
    let deep_not = format!("SEARCH {}SEEN", "NOT ".repeat(40));
    let search_bad = send_cmd(&mut reader2, "B3", &deep_not).await;
    assert!(
        search_bad.last().unwrap().starts_with("B3 BAD"),
        "expected B3 BAD for deep SEARCH NOT chain, got {search_bad:?}"
    );

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn tls_logindisabled_reauth_authzid_and_five_failure_disconnect() {
    use rustls_pki_types::ServerName;

    let dir = TempDir::new().unwrap();
    let cfg = make_test_config(dir.path());
    let (cert_path, key_path, tls_connector) = make_ephemeral_tls(dir.path());
    let acceptor = build_tls_acceptor(&cert_path, &key_path).unwrap();

    let store = Arc::new(SqliteStore::open(&cfg.db_path, &cfg.user_email).unwrap());
    let state = AppState::with_backends(cfg, store, Arc::new(NoopResendClient));

    // --- Part A: Plain listener with TLS acceptor configured ---
    let (tls_plain_addr, shutdown_tls) = spawn_plain_imap(state.clone(), Some(acceptor)).await;
    let tcp = TcpStream::connect(tls_plain_addr).await.unwrap();
    let mut reader = BufReader::new(tcp);
    let greeting = read_line_timeout(&mut reader).await.unwrap();
    assert!(
        greeting.contains("STARTTLS") && greeting.contains("LOGINDISABLED"),
        "greeting must advertise STARTTLS and LOGINDISABLED, got: {greeting}"
    );
    assert!(
        !greeting.contains("AUTH=PLAIN") && !greeting.contains("AUTH=XOAUTH2"),
        "pre-STARTTLS greeting must omit AUTH=PLAIN and AUTH=XOAUTH2, got: {greeting}"
    );

    // Plaintext LOGIN and AUTHENTICATE before STARTTLS must fail with NO [PRIVACYREQUIRED].
    let login_plain = send_cmd(
        &mut reader,
        "T1",
        r#"LOGIN "agent@example.com" "secret-admin-pass""#,
    )
    .await;
    assert!(
        login_plain
            .last()
            .unwrap()
            .contains("T1 NO [PRIVACYREQUIRED]"),
        "expected NO [PRIVACYREQUIRED] for plaintext LOGIN, got {login_plain:?}"
    );
    let auth_plain = send_cmd(&mut reader, "T2", "AUTHENTICATE PLAIN").await;
    assert!(
        auth_plain
            .last()
            .unwrap()
            .contains("T2 NO [PRIVACYREQUIRED]"),
        "expected NO [PRIVACYREQUIRED] for plaintext AUTHENTICATE, got {auth_plain:?}"
    );

    // Upgrade via STARTTLS.
    let stls = send_cmd(&mut reader, "T3", "STARTTLS").await;
    assert!(stls.last().unwrap().starts_with("T3 OK"));
    let tls_stream = tls_connector
        .connect(
            ServerName::try_from("localhost").unwrap(),
            reader.into_inner(),
        )
        .await
        .expect("STARTTLS handshake must succeed");
    let mut tls_reader = BufReader::new(tls_stream);

    // Post-STARTTLS CAPABILITY advertises AUTH=PLAIN/AUTH=XOAUTH2 and omits LOGINDISABLED/STARTTLS.
    let caps = send_cmd(&mut tls_reader, "T4", "CAPABILITY").await.join("");
    assert!(caps.contains("AUTH=PLAIN") && caps.contains("AUTH=XOAUTH2"));
    assert!(!caps.contains("LOGINDISABLED") && !caps.contains("STARTTLS"));

    // Non-admin AUTHENTICATE PLAIN with mismatched authzid must be rejected.
    let bad_authzid_b64 = base64::engine::general_purpose::STANDARD
        .encode("victim@example.com\0agent@example.com\0tok-rw");
    let az_fail = send_cmd(
        &mut tls_reader,
        "T5",
        &format!("AUTHENTICATE PLAIN {bad_authzid_b64}"),
    )
    .await;
    assert!(
        az_fail
            .last()
            .unwrap()
            .contains("T5 NO [AUTHORIZATIONFAILED]"),
        "mismatched non-admin authzid must fail, got {az_fail:?}"
    );

    // Matching case-insensitive authzid succeeds.
    let ok_authzid_b64 = base64::engine::general_purpose::STANDARD
        .encode("AGENT@example.com\0agent@example.com\0tok-rw");
    let az_ok = send_cmd(
        &mut tls_reader,
        "T6",
        &format!("AUTHENTICATE PLAIN {ok_authzid_b64}"),
    )
    .await;
    assert!(
        az_ok.last().unwrap().starts_with("T6 OK"),
        "matching case-insensitive authzid should succeed, got {az_ok:?}"
    );

    // Re-authentication while already authenticated must return BAD Already authenticated.
    let reauth_login = send_cmd(
        &mut tls_reader,
        "T7",
        r#"LOGIN "agent@example.com" "tok-rw""#,
    )
    .await;
    assert!(
        reauth_login
            .last()
            .unwrap()
            .contains("T7 BAD Already authenticated"),
        "re-auth LOGIN must fail with BAD, got {reauth_login:?}"
    );
    let reauth_sasl = send_cmd(&mut tls_reader, "T8", "AUTHENTICATE PLAIN").await;
    assert!(
        reauth_sasl
            .last()
            .unwrap()
            .contains("T8 BAD Already authenticated"),
        "re-auth AUTHENTICATE must fail with BAD, got {reauth_sasl:?}"
    );

    // --- Part B: Admin authzid override + 5 consecutive failed logins disconnect ---
    let (plain_addr, shutdown_plain) = spawn_plain_imap(state, None).await;

    // Admin token may specify a non-matching authzid.
    let tcp_adm = TcpStream::connect(plain_addr).await.unwrap();
    let mut r_adm = BufReader::new(tcp_adm);
    let _ = read_line_timeout(&mut r_adm).await.unwrap();
    let admin_az_b64 = base64::engine::general_purpose::STANDARD
        .encode("delegate@example.com\0agent@example.com\0tok-admin");
    let adm_ok = send_cmd(
        &mut r_adm,
        "AD1",
        &format!("AUTHENTICATE PLAIN {admin_az_b64}"),
    )
    .await;
    assert!(adm_ok.last().unwrap().starts_with("AD1 OK"));

    // 5 consecutive failed logins must disconnect with `* BYE Too many failed login attempts`.
    let tcp_bf = TcpStream::connect(plain_addr).await.unwrap();
    let mut r_bf = BufReader::new(tcp_bf);
    let _ = read_line_timeout(&mut r_bf).await.unwrap();
    for attempt in 1..=4 {
        let resp = send_cmd(
            &mut r_bf,
            &format!("F{attempt}"),
            r#"LOGIN "agent@example.com" "wrong-pass""#,
        )
        .await;
        assert!(
            resp.last().unwrap().contains("NO [AUTHENTICATIONFAILED]"),
            "attempt {attempt} should fail auth: {resp:?}"
        );
    }
    let fifth = send_cmd(&mut r_bf, "F5", r#"LOGIN "agent@example.com" "wrong-pass""#).await;
    assert!(
        fifth
            .iter()
            .any(|l| l.contains("F5 NO [AUTHENTICATIONFAILED]")),
        "5th failure must send tagged NO: {fifth:?}"
    );
    let bye_line = read_line_timeout(&mut r_bf).await.unwrap();
    assert!(
        bye_line.contains("* BYE Too many failed login attempts"),
        "5th failure must send * BYE, got: {bye_line:?}"
    );
    assert!(
        read_line_timeout(&mut r_bf).await.is_none(),
        "connection must close after 5 failed auth attempts"
    );

    let _ = shutdown_tls.send(true);
    let _ = shutdown_plain.send(true);
}

#[tokio::test]
async fn idle_done_is_cancel_safe_across_concurrent_event_bus_updates() {
    let dir = TempDir::new().unwrap();
    let cfg = make_test_config(dir.path());
    let store = Arc::new(SqliteStore::open(&cfg.db_path, &cfg.user_email).unwrap());
    let state = AppState::with_backends(cfg, store.clone(), Arc::new(NoopResendClient));

    seed_raw_message(
        &state,
        "INBOX",
        "From: a@example.com\r\nSubject: Initial\r\n\r\nFirst\r\n",
        None,
    )
    .await;

    let (addr, shutdown_tx) = spawn_plain_imap(state.clone(), None).await;
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut reader = BufReader::new(tcp);
    let _ = read_line_timeout(&mut reader).await.unwrap();

    let _ = send_cmd(
        &mut reader,
        "I1",
        r#"LOGIN "agent@example.com" "secret-admin-pass""#,
    )
    .await;
    let _ = send_cmd(&mut reader, "I2", "SELECT INBOX").await;

    // Enter IDLE and wait for `+ idling`.
    reader.get_mut().write_all(b"I3 IDLE\r\n").await.unwrap();
    reader.get_mut().flush().await.unwrap();
    let idling = read_line_timeout(&mut reader).await.unwrap();
    assert!(
        idling.starts_with("+ "),
        "expected + idling, got {idling:?}"
    );

    // Send ONLY the first half of `DONE\r\n`.
    reader.get_mut().write_all(b"DO").await.unwrap();
    reader.get_mut().flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(40)).await;

    // Trigger an EventBus update while `DO` is buffered on the server!
    let msg2 = seed_raw_message(
        &state,
        "INBOX",
        "From: b@example.com\r\nSubject: Live Arrival\r\n\r\nSecond\r\n",
        None,
    )
    .await;
    state.events.publish(
        EventSource::Imap,
        MailEvent::MessageReceived {
            message_id: msg2.id.clone(),
            thread_id: msg2.thread_id.clone(),
            from: msg2.from_addr.clone(),
            subject: msg2.subject.clone(),
            snippet: msg2.snippet.clone(),
            labels: msg2.label_ids.clone(),
        },
    );

    // Server must push `* 2 EXISTS` without losing the partial `DO` bytes!
    let pushed = read_line_timeout(&mut reader).await.unwrap();
    assert_eq!(pushed.trim(), "* 2 EXISTS");

    // Now send the remaining `NE\r\n`.
    reader.get_mut().write_all(b"NE\r\n").await.unwrap();
    reader.get_mut().flush().await.unwrap();

    let done_resp = read_line_timeout(&mut reader).await.unwrap();
    assert!(
        done_resp.starts_with("I3 OK IDLE terminated"),
        "expected clean IDLE termination after split DONE, got: {done_resp:?}"
    );

    // Session stays healthy for subsequent commands.
    let noop = send_cmd(&mut reader, "I4", "NOOP").await;
    assert!(noop.last().unwrap().starts_with("I4 OK"));

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn lazy_fetch_external_search_failed_select_cas_escaping_embedded_rfc822_and_conn_cap() {
    let dir = TempDir::new().unwrap();
    let cfg = make_test_config(dir.path());
    let store = Arc::new(SqliteStore::open(&cfg.db_path, &cfg.user_email).unwrap());
    let gets = Arc::new(AtomicUsize::new(0));
    let blobs = Arc::new(CountingBlobStore {
        inner: FsBlobStore::open(&cfg.blob_dir).unwrap(),
        gets: gets.clone(),
    });
    let state = AppState::with_backends(cfg, store.clone(), Arc::new(NoopResendClient))
        .with_blobs(blobs.clone());

    let embedded_raw = concat!(
        "From: outer@example.com\r\n",
        "To: agent@example.com\r\n",
        "Subject: Outer Container\r\n",
        "X-External-Needle: ext-blob-search-token-77\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=\"bnd-e2e\"\r\n",
        "\r\n",
        "--bnd-e2e\r\n",
        "Content-Type: text/plain\r\n",
        "\r\n",
        "Outer body text\r\n",
        "--bnd-e2e\r\n",
        "Content-Type: message/rfc822\r\n",
        "\r\n",
        "From: nested@example.com\r\n",
        "Subject: Nested Forwarded Mail\r\n",
        "\r\n",
        "Nested body content\r\n",
        "--bnd-e2e--\r\n"
    );
    let msg = seed_raw_message(&state, "INBOX", embedded_raw, None).await;
    let initial_modseq = msg.history_id.max(1);

    // Clear inline raw_rfc2822 in SQLite directly to simulate offloaded external blob storage!
    {
        let conn = rusqlite::Connection::open(&state.config.db_path).unwrap();
        conn.execute(
            "UPDATE messages SET raw_rfc2822 = X'' WHERE id = ?1",
            rusqlite::params![&msg.id],
        )
        .unwrap();
    }
    gets.store(0, Ordering::SeqCst);

    // Spawn with connection cap = 2 to verify Semaphore + JoinSet enforcement.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let srv_state = state.clone();
    tokio::spawn(async move {
        let _ = serve_plain_listener_with_limit(listener, srv_state, None, shutdown_rx, 2).await;
    });

    let tcp1 = TcpStream::connect(addr).await.unwrap();
    let mut r1 = BufReader::new(tcp1);
    let _ = read_line_timeout(&mut r1).await.unwrap();

    let _ = send_cmd(
        &mut r1,
        "C1",
        r#"LOGIN "agent@example.com" "secret-admin-pass""#,
    )
    .await;
    let _ = send_cmd(&mut r1, "C2", "SELECT INBOX").await;

    // 1. Metadata-only FETCH must NOT touch external BlobStore (`gets == 0`).
    let meta_fetch = send_cmd(
        &mut r1,
        "C3",
        "FETCH 1 (UID FLAGS INTERNALDATE RFC822.SIZE MODSEQ)",
    )
    .await;
    assert!(meta_fetch.last().unwrap().starts_with("C3 OK"));
    assert!(
        meta_fetch
            .iter()
            .any(|l| l.contains(&format!("RFC822.SIZE {}", embedded_raw.len()))),
        "RFC822.SIZE must match original size without blob read: {meta_fetch:?}"
    );
    assert_eq!(
        gets.load(Ordering::SeqCst),
        0,
        "metadata-only FETCH must skip external blob reads"
    );

    // 2. SEARCH HEADER on offloaded external blob loads via load_raw_rfc2822 and matches!
    let srch = send_cmd(
        &mut r1,
        "C4",
        r#"SEARCH HEADER X-External-Needle "ext-blob-search-token-77""#,
    )
    .await;
    assert!(
        srch.iter().any(|l| l.trim() == "* SEARCH 1"),
        "SEARCH HEADER must match offloaded external blob, got {srch:?}"
    );
    assert!(
        gets.load(Ordering::SeqCst) >= 1,
        "SEARCH HEADER must have read external blob"
    );

    // 3. Embedded message/rfc822 BODY[2.HEADER] and BODY[2.TEXT] inspect inner message!
    let emb = send_cmd(
        &mut r1,
        "C5",
        "FETCH 1 (BODY.PEEK[2.HEADER] BODY.PEEK[2.TEXT])",
    )
    .await;
    let emb_joined = emb.join("");
    assert!(
        emb_joined.contains("Subject: Nested Forwarded Mail"),
        "BODY[2.HEADER] must return embedded headers, got {emb_joined}"
    );
    assert!(
        emb_joined.contains("Nested body content"),
        "BODY[2.TEXT] must return embedded body, got {emb_joined}"
    );
    assert!(
        !emb_joined.contains("Outer Container"),
        "BODY[2.HEADER]/[2.TEXT] must not return outer message headers, got {emb_joined}"
    );

    // 4. Atomic UNCHANGEDSINCE CAS detects out-of-band DB change despite stale sel.snapshot!
    store
        .imap_set_flags(&msg.id, true, false, false, false, false)
        .await
        .unwrap();
    let stale_store = send_cmd(
        &mut r1,
        "C6",
        &format!(r#"STORE 1 (UNCHANGEDSINCE {initial_modseq}) +FLAGS (\Flagged)"#),
    )
    .await;
    assert!(
        stale_store.last().unwrap().contains("[MODIFIED 1]"),
        "atomic UNCHANGEDSINCE must detect fresh DB history_id bump, got {stale_store:?}"
    );
    let fresh_msg = store.get_message(&msg.id).await.unwrap().unwrap();
    assert!(
        !fresh_msg.label_ids.iter().any(|l| l == "STARRED"),
        "stale UNCHANGEDSINCE STORE must not overwrite flags"
    );

    // 5. Reject CR/LF in CREATE / RENAME and prevent CRLF response injection in STATUS.
    r1.get_mut()
        .write_all(b"C7 CREATE {9+}\r\nBad\r\nName\r\n")
        .await
        .unwrap();
    r1.get_mut().flush().await.unwrap();
    let bad_create = read_line_timeout(&mut r1).await.unwrap();
    assert!(
        bad_create.starts_with("C7 BAD"),
        "CREATE with CR/LF must be rejected, got {bad_create:?}"
    );

    r1.get_mut()
        .write_all(b"C8 STATUS {17+}\r\nNope\r\n* OK pwned (MESSAGES)\r\n")
        .await
        .unwrap();
    r1.get_mut().flush().await.unwrap();
    let status_resp = read_line_timeout(&mut r1).await.unwrap();
    assert!(
        status_resp.starts_with("C8 NO Mailbox does not exist:"),
        "STATUS must escape mailbox name on single line, got {status_resp:?}"
    );

    // 6. Failed SELECT clears previously selected mailbox (RFC 3501 §6.3.1).
    let fail_sel = send_cmd(&mut r1, "C9", r#"SELECT "DoesNotExist""#).await;
    assert!(fail_sel.last().unwrap().starts_with("C9 NO"));
    let fetch_after_fail = send_cmd(&mut r1, "C10", "FETCH 1 (UID)").await;
    assert!(
        fetch_after_fail
            .last()
            .unwrap()
            .contains("C10 NO No mailbox selected"),
        "failed SELECT must leave no mailbox selected, got {fetch_after_fail:?}"
    );

    // 7. Concurrent connection cap = 2: 2nd connection succeeds, 3rd gets `* BYE Server busy`.
    let tcp2 = TcpStream::connect(addr).await.unwrap();
    let mut r2 = BufReader::new(tcp2);
    let g2 = read_line_timeout(&mut r2).await.unwrap();
    assert!(g2.starts_with("* OK"));

    let tcp3 = TcpStream::connect(addr).await.unwrap();
    let mut r3 = BufReader::new(tcp3);
    let g3 = read_line_timeout(&mut r3).await.unwrap();
    assert!(
        g3.contains("* BYE Server busy"),
        "3rd concurrent connection over cap=2 must receive * BYE Server busy, got {g3:?}"
    );

    // Close 2nd connection -> permit released -> new connection succeeds!
    let _ = send_cmd(&mut r2, "L1", "LOGOUT").await;
    drop(r2);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let tcp4 = TcpStream::connect(addr).await.unwrap();
    let mut r4 = BufReader::new(tcp4);
    let g4 = read_line_timeout(&mut r4).await.unwrap();
    assert!(
        g4.starts_with("* OK"),
        "after closing one connection, new connection must succeed, got {g4:?}"
    );

    let _ = shutdown_tx.send(true);
}
