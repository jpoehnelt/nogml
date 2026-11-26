//! Gmail API conformance test suite modeled on real Google API client library
//! (`google-api-python-client` / `@googleapis/gmail`) and Superhuman client traffic patterns.
//!
//! Covers:
//! 1. Multi-chunk `uploadType=resumable` (`messages.send`) with a large binary attachment
//!    across 4 `PUT` chunks (`308` -> status probe `bytes */*` -> gap recovery -> `308` -> `200`),
//!    verifying byte-for-byte attachment integrity via `attachments.get`, outbound `MailTransport`,
//!    and parity with single-shot `uploadType=media`.
//! 2. `uploadType=resumable` across `drafts.create`, `drafts.update`, `drafts.send`,
//!    `messages.insert`, and `messages.import` (including query-option preservation, `?fields=`,
//!    unknown-total `bytes start-end/*`, single-chunk `PUT`, and session cancellation).
//! 3. Realistic Superhuman startup + incremental sync trace: `profile` -> `settings/sendAs` ->
//!    `labels.list` -> `threads.list?fields=...` -> `POST /batch/gmail/v1` fetching 10 threads
//!    with `?fields=` and `format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date`
//!    -> `watch` -> mailbox mutations -> `history.list?startHistoryId=...` -> `stop`.
//! 4. Google API client error envelope conformance (`400`, `401`, `404`, `413`).

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use reqwest::{Client, StatusCode, header};
use serde_json::{Value, json};
use tokio::{net::TcpListener, sync::watch, task::JoinHandle};

use nogml::{
    AppState, build_router,
    config::Config,
    error::AppResult,
    gmail::upload::parse_multipart_parts,
    mime::{self, ComposeEmailInput},
    models::{LABEL_DRAFT, LABEL_INBOX, LABEL_SENT, LABEL_STARRED, LABEL_TRASH, LABEL_UNREAD},
    resend::HttpResendClient,
    storage::{MemoryStore, NewAttachmentInput},
    transport::{MailTransport, OutboundMessage, SendOutcome, TransportCapabilities},
};

const CONFORMANCE_TOKEN: &str = "nogml-conformance-bearer-token";

/// Recording `MailTransport` capturing outbound payloads verbatim for byte-level assertions.
#[derive(Default)]
struct RecordingTransport {
    sent: Mutex<Vec<OutboundMessage>>,
}

impl RecordingTransport {
    fn snapshot(&self) -> Vec<OutboundMessage> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait]
impl MailTransport for RecordingTransport {
    fn name(&self) -> &'static str {
        "recording_conformance"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            provider: "recording_conformance".to_string(),
            supports_raw_mime: true,
            supports_scheduled_send: false,
            supports_idempotency_key: true,
            supports_inbound_webhooks: false,
            supports_delivery_webhooks: false,
            max_message_bytes: 40 * 1024 * 1024,
        }
    }

    async fn send(
        &self,
        msg: &OutboundMessage,
        _idempotency_key: Option<&str>,
    ) -> AppResult<SendOutcome> {
        let mut guard = self.sent.lock().unwrap();
        guard.push(msg.clone());
        Ok(SendOutcome {
            provider: "recording_conformance".to_string(),
            provider_message_id: format!("rec_msg_{}", guard.len()),
            provider_thread_id: None,
        })
    }
}

struct ConformanceServer {
    addr: SocketAddr,
    client: Client,
    transport: Arc<RecordingTransport>,
    shutdown_tx: watch::Sender<bool>,
    server_handle: JoinHandle<()>,
}

impl ConformanceServer {
    async fn start(mut config: Config) -> Self {
        config.auth_tokens = vec![CONFORMANCE_TOKEN.to_string()];
        let store = Arc::new(MemoryStore::new(&config.user_email));
        let resend = Arc::new(HttpResendClient::from_config(&config));
        let transport = Arc::new(RecordingTransport::default());
        let state =
            AppState::with_backends(config, store, resend).with_transport(transport.clone());

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let router = build_router(state);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");

        let server_handle = tokio::spawn(async move {
            let _ = axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.changed().await;
                })
                .await;
        });

        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("reqwest client");

        Self {
            addr,
            client,
            transport,
            shutdown_tx,
            server_handle,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(3), self.server_handle).await;
    }
}

fn deterministic_binary_payload(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state: u32 = 0x1357_9bdf;
    for i in 0..len {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push(((state >> 16) as u8) ^ ((i & 0xff) as u8));
    }
    out
}

fn compose_binary_attachment_rfc2822(
    from: &str,
    to: &str,
    subject: &str,
    text: &str,
    filename: &str,
    content_type: &str,
    attachment_bytes: &[u8],
) -> Vec<u8> {
    let mut input = ComposeEmailInput {
        from: from.to_string(),
        to: vec![to.to_string()],
        cc: Vec::new(),
        bcc: Vec::new(),
        reply_to: Vec::new(),
        subject: subject.to_string(),
        text: Some(text.to_string()),
        html: Some(format!("<p>{text}</p>")),
        message_id: None,
        in_reply_to: None,
        references: None,
        extra_headers: HashMap::new(),
        attachments: vec![NewAttachmentInput {
            part_id: "2".to_string(),
            filename: Some(filename.to_string()),
            content_type: content_type.to_string(),
            content_id: None,
            data: attachment_bytes.to_vec(),
        }],
    };
    input.extra_headers.insert(
        "X-Client-Suite".to_string(),
        "gmail-conformance".to_string(),
    );
    mime::build_rfc2822(&input).expect("compose RFC 2822 with binary attachment")
}

fn find_attachment_id(payload: &Value, expected_filename: &str) -> Option<String> {
    if payload.get("filename").and_then(Value::as_str) == Some(expected_filename)
        && let Some(att_id) = payload
            .get("body")
            .and_then(|b| b.get("attachmentId"))
            .and_then(Value::as_str)
    {
        return Some(att_id.to_string());
    }
    if let Some(parts) = payload.get("parts").and_then(Value::as_array) {
        for part in parts {
            if let Some(found) = find_attachment_id(part, expected_filename) {
                return Some(found);
            }
        }
    }
    None
}

fn parse_embedded_http_response(raw: &[u8]) -> (u16, HashMap<String, String>, Vec<u8>) {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, 4))
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2)))
        .expect("embedded HTTP response header separator");

    let head = String::from_utf8_lossy(&raw[..sep.0]);
    let body = raw[sep.0 + sep.1..].to_vec();

    let mut lines = head.lines();
    let status_line = lines.next().expect("HTTP status line").trim();
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .expect("HTTP status code token")
        .parse()
        .expect("numeric HTTP status code");

    let mut headers = HashMap::new();
    for line in lines {
        let line = line.trim_end_matches('\r');
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    (status_code, headers, body)
}

fn assert_google_error_envelope(
    body: &Value,
    expected_code: u16,
    expected_status: &str,
    expected_reason: &str,
) {
    let err = body
        .get("error")
        .expect("Google error response must have top-level 'error' object");
    assert_eq!(err["code"].as_u64(), Some(u64::from(expected_code)));
    assert_eq!(err["status"].as_str(), Some(expected_status));
    assert!(
        err["message"]
            .as_str()
            .is_some_and(|m| !m.trim().is_empty()),
        "error.message should be non-empty"
    );
    let errors = err["errors"]
        .as_array()
        .expect("error.errors must be an array");
    assert!(!errors.is_empty(), "error.errors must not be empty");
    assert_eq!(errors[0]["domain"].as_str(), Some("global"));
    assert_eq!(errors[0]["reason"].as_str(), Some(expected_reason));
    assert_eq!(errors[0]["message"].as_str(), err["message"].as_str());
}

// ============================================================================
// 1. Multi-chunk uploadType=resumable with large binary attachment
// ============================================================================

#[tokio::test]
async fn resumable_messages_send_multi_chunk_binary_attachment_conformance() {
    let srv = ConformanceServer::start(Config::for_test()).await;

    // Seed an existing thread so resumable metadata `{threadId, labelIds}` attaches cleanly.
    let seed_raw = b"From: partner@acme.org\r\nTo: agent@example.com\r\nSubject: Q4 Deck\r\n\r\nPlease send the deck.";
    let seed_resp = srv
        .client
        .post(srv.url("/upload/gmail/v1/users/me/messages/import?uploadType=media"))
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(header::CONTENT_TYPE, "message/rfc822")
        .body(seed_raw.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(seed_resp.status(), StatusCode::OK);
    let seeded: Value = seed_resp.json().await.unwrap();
    let target_thread_id = seeded["threadId"].as_str().unwrap().to_string();

    // Build a large RFC 2822 message carrying a 192 KiB binary attachment.
    let binary_blob = deterministic_binary_payload(192 * 1024);
    let raw_email = compose_binary_attachment_rfc2822(
        "agent@example.com",
        "partner@acme.org",
        "Re: Q4 Deck",
        "Attached is the Q4 report binary.",
        "q4-report.bin",
        "application/octet-stream",
        &binary_blob,
    );
    let total_len = raw_email.len();
    assert!(
        total_len > 200_000,
        "base64-encoded MIME should exceed 200 KiB"
    );

    // Step 1: Initiate resumable upload (`POST ...?uploadType=resumable`).
    let init_resp = srv
        .client
        .post(srv.url("/upload/gmail/v1/users/me/messages/send?uploadType=resumable"))
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(header::CONTENT_TYPE, "application/json; charset=UTF-8")
        .header("X-Upload-Content-Type", "message/rfc822")
        .header("X-Upload-Content-Length", total_len.to_string())
        .header("Idempotency-Key", "resumable-conformance-key-1")
        .json(&json!({
            "threadId": target_thread_id,
            "labelIds": [LABEL_STARRED],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(init_resp.status(), StatusCode::OK);
    let location = init_resp
        .headers()
        .get(header::LOCATION)
        .expect("resumable initiation must return Location header")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        location.starts_with(&format!(
            "http://{}/upload/gmail/v1/users/me/messages/send?",
            srv.addr
        )),
        "expected absolute Location derived from Host, got {location}"
    );
    assert!(location.contains("uploadType=resumable"));
    assert!(location.contains("upload_id="));

    // Step 2: Pre-upload status probe (`Content-Range: bytes */*`) returns 308 with no Range.
    let probe0 = srv
        .client
        .put(&location)
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(header::CONTENT_RANGE, "bytes */*")
        .send()
        .await
        .unwrap();
    assert_eq!(probe0.status(), StatusCode::PERMANENT_REDIRECT);
    assert!(probe0.headers().get(header::RANGE).is_none());
    assert!(probe0.headers().get(header::LOCATION).is_none());

    // Step 3: Split raw MIME into 4 chunks (matching Google SDK chunking pattern).
    let chunk_size = 64 * 1024;
    let chunks: Vec<(usize, usize, &[u8])> = raw_email
        .chunks(chunk_size)
        .enumerate()
        .map(|(i, slice)| {
            let start = i * chunk_size;
            let end = start + slice.len() - 1;
            (start, end, slice)
        })
        .collect();
    assert!(
        chunks.len() >= 4,
        "expected at least 4 chunks, got {}",
        chunks.len()
    );

    // Upload chunk 0 -> 308 with Range: bytes=0-<end0>
    let (s0, e0, c0) = chunks[0];
    let r0 = srv
        .client
        .put(&location)
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(header::CONTENT_TYPE, "message/rfc822")
        .header(
            header::CONTENT_RANGE,
            format!("bytes {s0}-{e0}/{total_len}"),
        )
        .body(c0.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(r0.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(
        r0.headers()
            .get(header::RANGE)
            .and_then(|v| v.to_str().ok()),
        Some(format!("bytes=0-{e0}").as_str())
    );

    // Mid-upload status probe (`bytes */*`) confirms received offset.
    let probe1 = srv
        .client
        .put(&location)
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(header::CONTENT_RANGE, "bytes */*")
        .send()
        .await
        .unwrap();
    assert_eq!(probe1.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(
        probe1
            .headers()
            .get(header::RANGE)
            .and_then(|v| v.to_str().ok()),
        Some(format!("bytes=0-{e0}").as_str())
    );

    // Out-of-order / non-contiguous chunk fails with 400 Gmail error envelope, leaving session intact.
    let (s2_bad, e2_bad, c2_bad) = chunks[2];
    let bad_chunk = srv
        .client
        .put(&location)
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(
            header::CONTENT_RANGE,
            format!("bytes {s2_bad}-{e2_bad}/{total_len}"),
        )
        .body(c2_bad.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(bad_chunk.status(), StatusCode::BAD_REQUEST);
    let bad_err: Value = bad_chunk.json().await.unwrap();
    assert_google_error_envelope(&bad_err, 400, "INVALID_ARGUMENT", "badRequest");

    // Upload remaining chunks in order; all intermediate chunks return 308, final returns 200 OK.
    let mut final_msg: Option<Value> = None;
    for (idx, &(start, end, slice)) in chunks.iter().enumerate().skip(1) {
        let resp = srv
            .client
            .put(&location)
            .bearer_auth(CONFORMANCE_TOKEN)
            .header(header::CONTENT_TYPE, "message/rfc822")
            .header(
                header::CONTENT_RANGE,
                format!("bytes {start}-{end}/{total_len}"),
            )
            .body(slice.to_vec())
            .send()
            .await
            .unwrap();
        if idx + 1 < chunks.len() {
            assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT);
            assert_eq!(
                resp.headers()
                    .get(header::RANGE)
                    .and_then(|v| v.to_str().ok()),
                Some(format!("bytes=0-{end}").as_str())
            );
        } else {
            assert_eq!(resp.status(), StatusCode::OK);
            final_msg = Some(resp.json().await.unwrap());
        }
    }

    let sent_msg = final_msg.expect("final chunk should return created Message JSON");
    let sent_id = sent_msg["id"].as_str().unwrap();
    assert_eq!(
        sent_msg["threadId"].as_str(),
        Some(target_thread_id.as_str())
    );
    let labels: Vec<&str> = sent_msg["labelIds"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(labels.contains(&LABEL_SENT));
    assert!(labels.contains(&LABEL_STARRED));

    // Re-probing a completed upload_id returns 404 Not Found.
    let after_done = srv
        .client
        .put(&location)
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(header::CONTENT_RANGE, "bytes */*")
        .send()
        .await
        .unwrap();
    assert_eq!(after_done.status(), StatusCode::NOT_FOUND);

    // Verify assembled attachment bytes match byte-for-byte via `messages.get?format=full` + `attachments.get`.
    let full_resp = srv
        .client
        .get(srv.url(&format!(
            "/gmail/v1/users/me/messages/{sent_id}?format=full"
        )))
        .bearer_auth(CONFORMANCE_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(full_resp.status(), StatusCode::OK);
    let full_msg: Value = full_resp.json().await.unwrap();
    let att_id = find_attachment_id(&full_msg["payload"], "q4-report.bin")
        .expect("attachmentId for q4-report.bin should be present");

    let att_resp = srv
        .client
        .get(srv.url(&format!(
            "/gmail/v1/users/me/messages/{sent_id}/attachments/{att_id}"
        )))
        .bearer_auth(CONFORMANCE_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(att_resp.status(), StatusCode::OK);
    let att_json: Value = att_resp.json().await.unwrap();
    let downloaded_bytes = mime::decode_base64url(att_json["data"].as_str().unwrap()).unwrap();
    assert_eq!(downloaded_bytes, binary_blob);
    assert_eq!(att_json["size"].as_u64(), Some(binary_blob.len() as u64));

    // Verify MailTransport received verbatim raw RFC 2822, exact attachment bytes, and Idempotency-Key.
    let sent_records = srv.transport.snapshot();
    assert_eq!(sent_records.len(), 1);
    assert_eq!(sent_records[0].raw_rfc2822, raw_email);
    assert_eq!(
        sent_records[0].idempotency_key.as_deref(),
        Some("resumable-conformance-key-1")
    );
    assert_eq!(sent_records[0].attachments.len(), 1);
    assert_eq!(sent_records[0].attachments[0].data, binary_blob);

    // Compare against single-shot `uploadType=media` to prove identical assembly.
    let single_resp = srv
        .client
        .post(srv.url("/upload/gmail/v1/users/me/messages/send?uploadType=media"))
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(header::CONTENT_TYPE, "message/rfc822")
        .body(raw_email.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(single_resp.status(), StatusCode::OK);
    let sent_records = srv.transport.snapshot();
    assert_eq!(sent_records.len(), 2);
    assert_eq!(sent_records[0].raw_rfc2822, sent_records[1].raw_rfc2822);
    assert_eq!(
        sent_records[0].attachments[0].data,
        sent_records[1].attachments[0].data
    );

    srv.shutdown().await;
}

// ============================================================================
// 2. uploadType=resumable across drafts.create, drafts.update, drafts.send,
//    messages.import, and messages.insert
// ============================================================================

#[tokio::test]
async fn resumable_drafts_and_messages_insert_import_conformance() {
    let srv = ConformanceServer::start(Config::for_test()).await;

    // --- 2a. drafts.create via multi-chunk unknown-total (`bytes start-end/*`) ---
    let draft_v1_att = deterministic_binary_payload(8192);
    let draft_v1_raw = compose_binary_attachment_rfc2822(
        "agent@example.com",
        "alice@example.com",
        "Draft Proposal v1",
        "First draft text.",
        "v1.bin",
        "application/octet-stream",
        &draft_v1_att,
    );

    let init_draft = srv
        .client
        .post(srv.url("/upload/gmail/v1/users/me/drafts?uploadType=resumable"))
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(header::CONTENT_TYPE, "application/json")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(init_draft.status(), StatusCode::OK);
    let draft_loc = init_draft
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let mid = draft_v1_raw.len() / 2;
    let part1 = &draft_v1_raw[..mid];
    let part2 = &draft_v1_raw[mid..];

    let r1 = srv
        .client
        .put(&draft_loc)
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(header::CONTENT_RANGE, format!("bytes 0-{}/*", mid - 1))
        .body(part1.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(
        r1.headers()
            .get(header::RANGE)
            .and_then(|v| v.to_str().ok()),
        Some(format!("bytes=0-{}", mid - 1).as_str())
    );

    let r2 = srv
        .client
        .put(&draft_loc)
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(
            header::CONTENT_RANGE,
            format!(
                "bytes {mid}-{}/{}",
                draft_v1_raw.len() - 1,
                draft_v1_raw.len()
            ),
        )
        .body(part2.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::OK);
    let created_draft: Value = r2.json().await.unwrap();
    let draft_id = created_draft["id"].as_str().unwrap().to_string();
    assert!(created_draft["message"]["id"].as_str().is_some());

    // --- 2b. drafts.update via PUT initiation (no upload_id) + multi-chunk PUT ---
    let draft_v2_att = deterministic_binary_payload(12_288);
    let draft_v2_raw = compose_binary_attachment_rfc2822(
        "agent@example.com",
        "alice@example.com",
        "Draft Proposal v2 (Updated)",
        "Updated draft body with larger attachment.",
        "v2.bin",
        "application/octet-stream",
        &draft_v2_att,
    );

    let init_update = srv
        .client
        .put(srv.url(&format!(
            "/upload/gmail/v1/users/me/drafts/{draft_id}?uploadType=resumable"
        )))
        .bearer_auth(CONFORMANCE_TOKEN)
        .header("X-Upload-Content-Type", "message/rfc822")
        .header("X-Upload-Content-Length", draft_v2_raw.len().to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(init_update.status(), StatusCode::OK);
    let update_loc = init_update
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let u_mid = draft_v2_raw.len() / 2;
    let u1 = srv
        .client
        .put(&update_loc)
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(
            header::CONTENT_RANGE,
            format!("bytes 0-{}/{}", u_mid - 1, draft_v2_raw.len()),
        )
        .body(draft_v2_raw[..u_mid].to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(u1.status(), StatusCode::PERMANENT_REDIRECT);

    let u2 = srv
        .client
        .put(&update_loc)
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(
            header::CONTENT_RANGE,
            format!(
                "bytes {u_mid}-{}/{}",
                draft_v2_raw.len() - 1,
                draft_v2_raw.len()
            ),
        )
        .body(draft_v2_raw[u_mid..].to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(u2.status(), StatusCode::OK);
    let updated_draft: Value = u2.json().await.unwrap();
    assert_eq!(updated_draft["id"].as_str(), Some(draft_id.as_str()));

    let fetched_draft: Value = srv
        .client
        .get(srv.url(&format!("/gmail/v1/users/me/drafts/{draft_id}?format=full")))
        .bearer_auth(CONFORMANCE_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let v2_msg_id = fetched_draft["message"]["id"].as_str().unwrap();
    let v2_att_id = find_attachment_id(&fetched_draft["message"]["payload"], "v2.bin")
        .expect("updated draft should carry v2.bin");
    let v2_att_json: Value = srv
        .client
        .get(srv.url(&format!(
            "/gmail/v1/users/me/messages/{v2_msg_id}/attachments/{v2_att_id}"
        )))
        .bearer_auth(CONFORMANCE_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        mime::decode_base64url(v2_att_json["data"].as_str().unwrap()).unwrap(),
        draft_v2_att
    );

    // --- 2c. drafts.send via single-chunk PUT (no Content-Range header) ---
    let init_draft_send = srv
        .client
        .post(srv.url("/upload/gmail/v1/users/me/drafts/send?uploadType=resumable"))
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(header::CONTENT_TYPE, "application/json")
        .json(&json!({ "id": draft_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(init_draft_send.status(), StatusCode::OK);
    let draft_send_loc = init_draft_send
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let sent_draft_resp = srv
        .client
        .put(&draft_send_loc)
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(header::CONTENT_TYPE, "message/rfc822")
        .body(draft_v2_raw.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(sent_draft_resp.status(), StatusCode::OK);
    let sent_draft_msg: Value = sent_draft_resp.json().await.unwrap();
    assert!(
        sent_draft_msg["labelIds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == LABEL_SENT)
    );
    assert_eq!(srv.transport.snapshot().len(), 1);

    // Draft should have been deleted after send.
    let gone_draft = srv
        .client
        .get(srv.url(&format!("/gmail/v1/users/me/drafts/{draft_id}")))
        .bearer_auth(CONFORMANCE_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(gone_draft.status(), StatusCode::NOT_FOUND);

    // --- 2d. messages.import via resumable upload preserving query parameters ---
    let import_raw = b"From: billing@vendor.io\r\nTo: agent@example.com\r\nDate: Tue, 15 Oct 2024 12:00:00 +0000\r\nSubject: Invoice #991\r\n\r\nTotal due: $100.";
    let init_import = srv
        .client
        .post(srv.url(
            "/upload/gmail/v1/users/me/messages/import?uploadType=resumable&internalDateSource=dateHeader&neverMarkSpam=true",
        ))
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(header::CONTENT_TYPE, "application/json")
        .json(&json!({ "labelIds": [LABEL_INBOX, LABEL_UNREAD, LABEL_STARRED] }))
        .send()
        .await
        .unwrap();
    assert_eq!(init_import.status(), StatusCode::OK);
    let import_loc = init_import
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let imp_split = 48;
    let imp1 = srv
        .client
        .put(&import_loc)
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(
            header::CONTENT_RANGE,
            format!("bytes 0-{}/{}", imp_split - 1, import_raw.len()),
        )
        .body(import_raw[..imp_split].to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(imp1.status(), StatusCode::PERMANENT_REDIRECT);

    let imp2 = srv
        .client
        .put(&import_loc)
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(
            header::CONTENT_RANGE,
            format!(
                "bytes {imp_split}-{}/{}",
                import_raw.len() - 1,
                import_raw.len()
            ),
        )
        .body(import_raw[imp_split..].to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(imp2.status(), StatusCode::OK);
    let imported: Value = imp2.json().await.unwrap();
    // 2024-10-15T12:00:00Z in milliseconds = 1728993600000
    assert_eq!(imported["internalDate"].as_str(), Some("1728993600000"));
    let imp_labels: Vec<&str> = imported["labelIds"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(imp_labels.contains(&LABEL_INBOX));
    assert!(imp_labels.contains(&LABEL_UNREAD));
    assert!(imp_labels.contains(&LABEL_STARRED));

    // --- 2e. messages.insert via resumable upload with `?fields=` preserved in Location ---
    let insert_raw = b"From: archive@example.com\r\nTo: agent@example.com\r\nSubject: Archived Note\r\n\r\nKept for audit.";
    let init_insert = srv
        .client
        .post(srv.url("/upload/gmail/v1/users/me/messages?uploadType=resumable&fields=id,threadId"))
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(header::CONTENT_TYPE, "application/json")
        .json(&json!({ "labelIds": [LABEL_INBOX] }))
        .send()
        .await
        .unwrap();
    assert_eq!(init_insert.status(), StatusCode::OK);
    let insert_loc = init_insert
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let ins_resp = srv
        .client
        .put(&insert_loc)
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(
            header::CONTENT_RANGE,
            format!("bytes 0-{}/{}", insert_raw.len() - 1, insert_raw.len()),
        )
        .body(insert_raw.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(ins_resp.status(), StatusCode::OK);
    let ins_json: Value = ins_resp.json().await.unwrap();
    let ins_obj = ins_json.as_object().unwrap();
    assert_eq!(
        ins_obj.len(),
        2,
        "fields=id,threadId should project only 2 keys: {ins_json}"
    );
    assert!(ins_obj.contains_key("id"));
    assert!(ins_obj.contains_key("threadId"));

    // --- 2f. Cancel in-flight resumable upload with DELETE ---
    let init_cancel = srv
        .client
        .post(srv.url("/upload/gmail/v1/users/me/drafts?uploadType=resumable"))
        .bearer_auth(CONFORMANCE_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(init_cancel.status(), StatusCode::OK);
    let cancel_loc = init_cancel
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let del_resp = srv
        .client
        .delete(&cancel_loc)
        .bearer_auth(CONFORMANCE_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);
    let probe_cancelled = srv
        .client
        .put(&cancel_loc)
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(header::CONTENT_RANGE, "bytes */*")
        .send()
        .await
        .unwrap();
    assert_eq!(probe_cancelled.status(), StatusCode::NOT_FOUND);

    srv.shutdown().await;
}

// ============================================================================
// 3. Realistic Superhuman startup + incremental sync trace
// ============================================================================

#[tokio::test]
async fn superhuman_startup_and_incremental_sync_trace_conformance() {
    let srv = ConformanceServer::start(Config::for_test()).await;

    // Seed 12 threads via messages.import so we have >10 threads for pagination + 10-item batching.
    let mut seeded_ids = Vec::new();
    for idx in 1..=12 {
        let raw = format!(
            "From: sender{idx}@company.com\r\n\
             To: agent@example.com\r\n\
             Date: Mon, {:02} Nov 2024 09:{:02}:00 +0000\r\n\
             Subject: Sync Thread #{idx}\r\n\
             X-Internal-Noise: should-be-filtered-out-{idx}\r\n\
             Message-ID: <sync-{idx}@company.com>\r\n\
             \r\n\
             Body content for thread {idx}.",
            idx, idx
        );
        let resp = srv
            .client
            .post(srv.url("/upload/gmail/v1/users/me/messages/import?uploadType=media"))
            .bearer_auth(CONFORMANCE_TOKEN)
            .header(header::CONTENT_TYPE, "message/rfc822")
            .body(raw)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let m: Value = resp.json().await.unwrap();
        seeded_ids.push((
            m["id"].as_str().unwrap().to_string(),
            m["threadId"].as_str().unwrap().to_string(),
        ));
    }

    // 1. GET /gmail/v1/users/me/profile?alt=json
    let profile: Value = srv
        .client
        .get(srv.url("/gmail/v1/users/me/profile?alt=json"))
        .bearer_auth(CONFORMANCE_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(profile["emailAddress"].as_str(), Some("agent@example.com"));
    assert_eq!(profile["messagesTotal"].as_u64(), Some(12));
    assert_eq!(profile["threadsTotal"].as_u64(), Some(12));
    let start_history_id = profile["historyId"].as_str().unwrap().to_string();

    // 2. GET /gmail/v1/users/me/settings/sendAs?alt=json
    let send_as: Value = srv
        .client
        .get(srv.url("/gmail/v1/users/me/settings/sendAs?alt=json"))
        .bearer_auth(CONFORMANCE_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let aliases = send_as["sendAs"].as_array().unwrap();
    assert!(!aliases.is_empty());
    assert_eq!(
        aliases[0]["sendAsEmail"].as_str(),
        Some("agent@example.com")
    );
    assert_eq!(aliases[0]["isPrimary"].as_bool(), Some(true));

    // 3. GET /gmail/v1/users/me/labels?alt=json
    let labels_resp: Value = srv
        .client
        .get(srv.url("/gmail/v1/users/me/labels?alt=json"))
        .bearer_auth(CONFORMANCE_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let label_ids: Vec<&str> = labels_resp["labels"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|l| l["id"].as_str())
        .collect();
    for expected in [
        LABEL_INBOX,
        LABEL_SENT,
        LABEL_DRAFT,
        LABEL_TRASH,
        LABEL_UNREAD,
    ] {
        assert!(
            label_ids.contains(&expected),
            "missing system label {expected}"
        );
    }

    // 4. GET /gmail/v1/users/me/threads?maxResults=10&fields=...
    let threads_list: Value = srv
        .client
        .get(srv.url(
            "/gmail/v1/users/me/threads?maxResults=10&fields=threads(id,snippet,historyId),nextPageToken,resultSizeEstimate&alt=json",
        ))
        .bearer_auth(CONFORMANCE_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let thread_refs = threads_list["threads"].as_array().unwrap();
    assert_eq!(thread_refs.len(), 10);
    assert!(threads_list["nextPageToken"].as_str().is_some());
    for tr in thread_refs {
        let obj = tr.as_object().unwrap();
        assert!(obj.contains_key("id"));
        assert!(obj.contains_key("snippet"));
        assert!(obj.contains_key("historyId"));
        assert_eq!(
            obj.len(),
            3,
            "unexpected extra fields in projected thread ref: {tr}"
        );
    }

    // 5. POST /batch/gmail/v1 fetching all 10 threads with `?fields=` and `format=metadata`
    let batch_boundary = "superhuman_batch_sync_001";
    let mut batch_body = String::new();
    for (idx, tr) in thread_refs.iter().enumerate() {
        let tid = tr["id"].as_str().unwrap();
        batch_body.push_str(&format!(
            "--{batch_boundary}\r\n\
             Content-Type: application/http\r\n\
             Content-ID: <thread-{idx}>\r\n\
             \r\n\
             GET /gmail/v1/users/me/threads/{tid}?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date&fields=id,historyId,messages(id,threadId,labelIds,snippet,internalDate,payload/headers) HTTP/1.1\r\n\
             \r\n"
        ));
    }
    batch_body.push_str(&format!("--{batch_boundary}--\r\n"));

    let batch_resp = srv
        .client
        .post(srv.url("/batch/gmail/v1"))
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(
            header::CONTENT_TYPE,
            format!("multipart/mixed; boundary={batch_boundary}"),
        )
        .body(batch_body)
        .send()
        .await
        .unwrap();
    assert_eq!(batch_resp.status(), StatusCode::OK);
    let batch_ct = batch_resp
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let batch_bytes = batch_resp.bytes().await.unwrap();
    let batch_parts = parse_multipart_parts(&batch_ct, &batch_bytes).unwrap();
    assert_eq!(batch_parts.len(), 10);

    for (idx, part) in batch_parts.iter().enumerate() {
        assert_eq!(
            part.header("content-id"),
            Some(format!("response-thread-{idx}").as_str())
        );
        let (sub_status, _, sub_body) = parse_embedded_http_response(&part.body);
        assert_eq!(sub_status, 200);
        let thread_json: Value = serde_json::from_slice(&sub_body).unwrap();
        let expected_tid = thread_refs[idx]["id"].as_str().unwrap();
        assert_eq!(thread_json["id"].as_str(), Some(expected_tid));
        assert!(
            thread_json.get("snippet").is_none(),
            "snippet was not requested in ?fields="
        );

        let msgs = thread_json["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 1);
        let msg = &msgs[0];
        assert!(
            msg.get("sizeEstimate").is_none(),
            "sizeEstimate was not requested in ?fields="
        );
        let hdrs = msg["payload"]["headers"].as_array().unwrap();
        let hdr_names: Vec<&str> = hdrs.iter().filter_map(|h| h["name"].as_str()).collect();
        assert!(hdr_names.iter().any(|h| h.eq_ignore_ascii_case("From")));
        assert!(hdr_names.iter().any(|h| h.eq_ignore_ascii_case("Subject")));
        assert!(hdr_names.iter().any(|h| h.eq_ignore_ascii_case("Date")));
        assert!(
            !hdr_names
                .iter()
                .any(|h| h.eq_ignore_ascii_case("X-Internal-Noise")),
            "metadataHeaders must exclude unrequested headers: {hdr_names:?}"
        );
        assert!(msg["payload"].get("body").is_none());
    }

    // 6. POST /gmail/v1/users/me/watch
    let watch_resp = srv
        .client
        .post(srv.url("/gmail/v1/users/me/watch?alt=json"))
        .bearer_auth(CONFORMANCE_TOKEN)
        .json(&json!({
            "topicName": "projects/nogml-test/topics/gmail-push",
            "labelIds": [LABEL_INBOX],
            "labelFilterBehavior": "include",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(watch_resp.status(), StatusCode::OK);
    let watch_json: Value = watch_resp.json().await.unwrap();
    assert_eq!(
        watch_json["historyId"].as_str(),
        Some(start_history_id.as_str())
    );
    assert!(
        watch_json["expiration"]
            .as_str()
            .and_then(|s| s.parse::<i64>().ok())
            .is_some_and(|ms| ms > 0)
    );

    // 7. Mutations: archive thread 0 (remove INBOX+UNREAD, add STARRED) + send a new message
    let (mut_msg_id, mut_thread_id) = &seeded_ids[0];
    let mod_resp = srv
        .client
        .post(srv.url(&format!(
            "/gmail/v1/users/me/threads/{mut_thread_id}/modify"
        )))
        .bearer_auth(CONFORMANCE_TOKEN)
        .json(&json!({
            "addLabelIds": [LABEL_STARRED],
            "removeLabelIds": [LABEL_INBOX, LABEL_UNREAD],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(mod_resp.status(), StatusCode::OK);

    let new_raw = mime::encode_base64url(
        b"From: agent@example.com\r\nTo: sender1@company.com\r\nSubject: Re: Sync Thread #1\r\n\r\nDone!",
    );
    let send_resp = srv
        .client
        .post(srv.url("/gmail/v1/users/me/messages/send"))
        .bearer_auth(CONFORMANCE_TOKEN)
        .json(&json!({ "raw": new_raw, "threadId": mut_thread_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(send_resp.status(), StatusCode::OK);
    let sent_msg: Value = send_resp.json().await.unwrap();
    let sent_msg_id = sent_msg["id"].as_str().unwrap();

    // 8. GET /gmail/v1/users/me/history?startHistoryId=<start_history_id>
    let hist_resp: Value = srv
        .client
        .get(srv.url(&format!(
            "/gmail/v1/users/me/history?startHistoryId={start_history_id}&alt=json"
        )))
        .bearer_auth(CONFORMANCE_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let records = hist_resp["history"]
        .as_array()
        .expect("history records should be present after mutations");
    assert!(!records.is_empty());

    let saw_label_added = records.iter().any(|r| {
        r.get("labelsAdded")
            .and_then(Value::as_array)
            .is_some_and(|arr| {
                arr.iter().any(|e| {
                    e["message"]["id"].as_str() == Some(mut_msg_id.as_str())
                        && e["labelIds"]
                            .as_array()
                            .is_some_and(|l| l.iter().any(|x| x == LABEL_STARRED))
                })
            })
    });
    let saw_label_removed = records.iter().any(|r| {
        r.get("labelsRemoved")
            .and_then(Value::as_array)
            .is_some_and(|arr| {
                arr.iter().any(|e| {
                    e["message"]["id"].as_str() == Some(mut_msg_id.as_str())
                        && e["labelIds"]
                            .as_array()
                            .is_some_and(|l| l.iter().any(|x| x == LABEL_INBOX))
                })
            })
    });
    let saw_msg_added = records.iter().any(|r| {
        r.get("messagesAdded")
            .and_then(Value::as_array)
            .is_some_and(|arr| {
                arr.iter()
                    .any(|e| e["message"]["id"].as_str() == Some(sent_msg_id))
            })
    });
    assert!(
        saw_label_added,
        "expected labelsAdded in history: {hist_resp}"
    );
    assert!(
        saw_label_removed,
        "expected labelsRemoved in history: {hist_resp}"
    );
    assert!(
        saw_msg_added,
        "expected messagesAdded in history: {hist_resp}"
    );

    let final_hid: u64 = hist_resp["historyId"].as_str().unwrap().parse().unwrap();
    let start_hid: u64 = start_history_id.parse().unwrap();
    assert!(final_hid > start_hid);

    // 9. POST /gmail/v1/users/me/stop
    let stop_resp = srv
        .client
        .post(srv.url("/gmail/v1/users/me/stop"))
        .bearer_auth(CONFORMANCE_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(stop_resp.status(), StatusCode::NO_CONTENT);

    srv.shutdown().await;
}

// ============================================================================
// 4. Google API client error envelope conformance (400, 401, 404, 413)
// ============================================================================

#[tokio::test]
async fn google_client_error_envelope_conformance() {
    let mut cfg = Config::for_test();
    cfg.max_body_bytes = 512;
    let srv = ConformanceServer::start(cfg).await;

    // --- 401 Unauthorized (missing and wrong bearer tokens) ---
    let unauth = srv
        .client
        .get(srv.url("/gmail/v1/users/me/profile"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);
    let unauth_body: Value = unauth.json().await.unwrap();
    assert_google_error_envelope(&unauth_body, 401, "UNAUTHENTICATED", "authError");

    let wrong_tok = srv
        .client
        .post(srv.url("/upload/gmail/v1/users/me/messages/send?uploadType=resumable"))
        .bearer_auth("wrong-token")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_tok.status(), StatusCode::UNAUTHORIZED);
    let wrong_tok_body: Value = wrong_tok.json().await.unwrap();
    assert_google_error_envelope(&wrong_tok_body, 401, "UNAUTHENTICATED", "authError");

    // --- 400 Bad Request (missing startHistoryId, invalid alt, bad X-Upload-Content-Length) ---
    let bad_hist = srv
        .client
        .get(srv.url("/gmail/v1/users/me/history"))
        .bearer_auth(CONFORMANCE_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(bad_hist.status(), StatusCode::BAD_REQUEST);
    let bad_hist_body: Value = bad_hist.json().await.unwrap();
    assert_google_error_envelope(&bad_hist_body, 400, "INVALID_ARGUMENT", "badRequest");

    let bad_alt = srv
        .client
        .get(srv.url("/gmail/v1/users/me/profile?alt=xml"))
        .bearer_auth(CONFORMANCE_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(bad_alt.status(), StatusCode::BAD_REQUEST);
    let bad_alt_body: Value = bad_alt.json().await.unwrap();
    assert_google_error_envelope(&bad_alt_body, 400, "INVALID_ARGUMENT", "badRequest");

    let bad_len = srv
        .client
        .post(srv.url("/upload/gmail/v1/users/me/messages/send?uploadType=resumable"))
        .bearer_auth(CONFORMANCE_TOKEN)
        .header("X-Upload-Content-Length", "not-a-number")
        .send()
        .await
        .unwrap();
    assert_eq!(bad_len.status(), StatusCode::BAD_REQUEST);
    let bad_len_body: Value = bad_len.json().await.unwrap();
    assert_google_error_envelope(&bad_len_body, 400, "INVALID_ARGUMENT", "badRequest");

    // --- 404 Not Found (missing message, unknown resumable upload_id) ---
    let missing_msg = srv
        .client
        .get(srv.url("/gmail/v1/users/me/messages/nonexistent_msg_id"))
        .bearer_auth(CONFORMANCE_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(missing_msg.status(), StatusCode::NOT_FOUND);
    let missing_msg_body: Value = missing_msg.json().await.unwrap();
    assert_google_error_envelope(&missing_msg_body, 404, "NOT_FOUND", "notFound");

    let missing_upload = srv
        .client
        .put(srv.url(
            "/upload/gmail/v1/users/me/messages/send?uploadType=resumable&upload_id=unknown_session_404",
        ))
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(header::CONTENT_RANGE, "bytes */*")
        .send()
        .await
        .unwrap();
    assert_eq!(missing_upload.status(), StatusCode::NOT_FOUND);
    let missing_upload_body: Value = missing_upload.json().await.unwrap();
    assert_google_error_envelope(&missing_upload_body, 404, "NOT_FOUND", "notFound");

    // --- 413 Payload Too Large (X-Upload-Content-Length > max_body_bytes) ---
    let oversize_init = srv
        .client
        .post(srv.url("/upload/gmail/v1/users/me/messages/send?uploadType=resumable"))
        .bearer_auth(CONFORMANCE_TOKEN)
        .header("X-Upload-Content-Length", "1024")
        .send()
        .await
        .unwrap();
    assert_eq!(oversize_init.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let oversize_init_body: Value = oversize_init.json().await.unwrap();
    assert_google_error_envelope(&oversize_init_body, 413, "INVALID_ARGUMENT", "badRequest");

    // --- 413 Payload Too Large (cumulative resumable chunks > max_body_bytes) ---
    let init_ok = srv
        .client
        .post(srv.url("/upload/gmail/v1/users/me/messages/send?uploadType=resumable"))
        .bearer_auth(CONFORMANCE_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(init_ok.status(), StatusCode::OK);
    let loc = init_ok
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let chunk1 = vec![b'A'; 300];
    let r1 = srv
        .client
        .put(&loc)
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(header::CONTENT_RANGE, "bytes 0-299/*")
        .body(chunk1)
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::PERMANENT_REDIRECT);

    let chunk2 = vec![b'B'; 300]; // cumulative 600 > 512
    let r2 = srv
        .client
        .put(&loc)
        .bearer_auth(CONFORMANCE_TOKEN)
        .header(header::CONTENT_RANGE, "bytes 300-599/600")
        .body(chunk2)
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let r2_body: Value = r2.json().await.unwrap();
    assert_google_error_envelope(&r2_body, 413, "INVALID_ARGUMENT", "badRequest");

    srv.shutdown().await;
}
