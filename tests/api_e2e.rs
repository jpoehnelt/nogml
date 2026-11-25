//! End-to-end integration tests for `nogml` covering:
//! 1. Superhuman-grade Gmail REST API v1 over a live Axum server + `wiremock` mock Resend
//! 2. Resend inbound & delivery webhooks (Svix HMAC-SHA256 verification, Receiving API, cross-protocol reads, SSE)
//! 3. AI-first `/v1/*` API, 7 pluggable backend capabilities, safety guardrails, reply auto-threading & live SSE
//! 4. MCP Server (Streamable HTTP + real `nogml mcp` stdio binary) & real `nogml` CLI (`schema`, `serve`, `mail --url`)

use std::{
    collections::HashMap,
    net::{SocketAddr, TcpListener as StdTcpListener},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    process::{Child, Command},
    sync::watch,
    task::JoinHandle,
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

use nogml::{
    AppState, build_router,
    config::{Config, DraftOnlyAction},
    gmail::{self, upload::parse_multipart_parts},
    mime::{self, ComposeEmailInput},
    models::{LABEL_DRAFT, LABEL_INBOX, LABEL_SENT, LABEL_SPAM, LABEL_STARRED, LABEL_UNREAD},
    resend::{HttpResendClient, sign_svix_payload},
    storage::{MemoryStore, NewAttachmentInput},
};

const TEST_WEBHOOK_SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
const TEST_RESEND_KEY: &str = "re_test_e2e_key";
const TEST_BEARER_TOKEN: &str = "nogml-e2e-bearer-token";

/// Live Axum HTTP server bound on an ephemeral loopback port (`127.0.0.1:0`),
/// optionally running the Gmail `/watch` push webhook listener.
struct LiveServer {
    addr: SocketAddr,
    state: AppState,
    client: Client,
    shutdown_tx: watch::Sender<bool>,
    server_handle: JoinHandle<()>,
    watch_handle: Option<JoinHandle<()>>,
}

impl LiveServer {
    async fn start(config: Config, start_watch_listener: bool) -> Self {
        let store = Arc::new(MemoryStore::new(&config.user_email));
        let resend = Arc::new(HttpResendClient::from_config(&config));
        let state = AppState::with_backends(config, store, resend);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let watch_handle = if start_watch_listener {
            let watch_state = state.clone();
            let watch_rx = shutdown_rx.clone();
            Some(tokio::spawn(async move {
                gmail::run_watch_webhook_listener(watch_state, watch_rx).await;
            }))
        } else {
            None
        };

        let router = build_router(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral HTTP port");
        let addr = listener.local_addr().expect("local addr");

        let mut http_shutdown_rx = shutdown_rx.clone();
        let server_handle = tokio::spawn(async move {
            let _ = axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = http_shutdown_rx.changed().await;
                })
                .await;
        });

        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("reqwest client");

        // Ensure watch listener task has subscribed to EventBus before returning.
        if start_watch_listener {
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        Self {
            addr,
            state,
            client,
            shutdown_tx,
            server_handle,
            watch_handle,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(3), self.server_handle).await;
        if let Some(h) = self.watch_handle {
            let _ = tokio::time::timeout(Duration::from_secs(3), h).await;
        }
    }
}

/// Guard that kills a spawned child process on drop so tests never leak background servers.
struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    async fn terminate(mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
        }
    }
}

fn test_config_with_resend(resend_base_url: &str, auth_token: Option<&str>) -> Config {
    let mut cfg = Config::for_test();
    cfg.resend_base_url = resend_base_url.to_string();
    cfg.resend_api_key = Some(TEST_RESEND_KEY.to_string());
    if let Some(tok) = auth_token {
        cfg.auth_tokens = vec![tok.to_string()];
    }
    cfg
}

fn pick_ephemeral_port() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral probe");
    listener.local_addr().expect("probe addr").port()
}

/// Read the next SSE event `(event_name, id, parsed_json_data)` from a streaming `reqwest::Response`.
async fn read_next_sse_event(
    resp: &mut reqwest::Response,
    buf: &mut String,
    timeout: Duration,
) -> (String, String, Value) {
    tokio::time::timeout(timeout, async {
        loop {
            while let Some(sep_idx) = buf.find("\n\n").or_else(|| buf.find("\r\n\r\n")) {
                let sep_len = if buf[sep_idx..].starts_with("\r\n\r\n") {
                    4
                } else {
                    2
                };
                let frame = buf[..sep_idx].to_string();
                buf.drain(..sep_idx + sep_len);

                let mut event_name = String::new();
                let mut event_id = String::new();
                let mut data_lines = Vec::new();
                for raw_line in frame.lines() {
                    let line = raw_line.trim_end_matches('\r');
                    if line.starts_with(':') || line.is_empty() {
                        continue;
                    }
                    if let Some(v) = line.strip_prefix("event:") {
                        event_name = v.trim().to_string();
                    } else if let Some(v) = line.strip_prefix("id:") {
                        event_id = v.trim().to_string();
                    } else if let Some(v) = line.strip_prefix("data:") {
                        data_lines.push(v.trim().to_string());
                    }
                }
                if !data_lines.is_empty() {
                    let data_str = data_lines.join("\n");
                    let parsed: Value = serde_json::from_str(&data_str)
                        .expect("SSE data payload should be valid JSON");
                    return (event_name, event_id, parsed);
                }
            }

            let chunk = resp
                .chunk()
                .await
                .expect("SSE chunk read")
                .expect("SSE stream ended before expected event");
            buf.push_str(&String::from_utf8_lossy(&chunk));
        }
    })
    .await
    .expect("timed out waiting for SSE event")
}

/// Parse an embedded HTTP/1.1 response inside a `POST /batch/gmail/v1` multipart part.
fn parse_embedded_http_response(raw: &[u8]) -> (u16, HashMap<String, String>, Vec<u8>) {
    let text_prefix_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, 4))
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2)))
        .expect("embedded HTTP response header separator");

    let head = String::from_utf8_lossy(&raw[..text_prefix_end.0]);
    let body = raw[text_prefix_end.0 + text_prefix_end.1..].to_vec();

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

fn build_rich_mime_email(
    from: &str,
    to: &str,
    subject: &str,
    text: &str,
    html: &str,
    extra_header: (&str, &str),
    attachment: (&str, &str, &[u8]),
) -> Vec<u8> {
    let mut extra_headers = HashMap::new();
    extra_headers.insert(extra_header.0.to_string(), extra_header.1.to_string());
    mime::build_rfc2822(&ComposeEmailInput {
        from: from.to_string(),
        to: vec![to.to_string()],
        cc: vec![],
        bcc: vec![],
        reply_to: vec![],
        subject: subject.to_string(),
        text: Some(text.to_string()),
        html: Some(html.to_string()),
        message_id: None,
        in_reply_to: None,
        references: None,
        extra_headers,
        attachments: vec![NewAttachmentInput {
            part_id: "att-1".to_string(),
            filename: Some(attachment.0.to_string()),
            content_type: attachment.1.to_string(),
            content_id: None,
            data: attachment.2.to_vec(),
        }],
    })
    .expect("build rich RFC 2822 email")
}

// ============================================================================
// 1. Superhuman-Grade Gmail REST API v1 E2E Tests
// ============================================================================

#[tokio::test]
async fn gmail_profile_and_send_variants_json_media_multipart() {
    let resend_mock = MockServer::start().await;
    let attachment_bytes = b"%PDF-1.4\nSuperhuman E2E Attachment Payload";
    let expected_att_b64 = general_purpose::STANDARD.encode(attachment_bytes);

    // 1) Expect JSON `raw` send with text, html, custom X-header, attachment, and Idempotency-Key
    Mock::given(method("POST"))
        .and(path("/emails"))
        .and(header("authorization", format!("Bearer {TEST_RESEND_KEY}")))
        .and(header("idempotency-key", "idem-json-send-1"))
        .and(body_partial_json(json!({
            "from": "agent@example.com",
            "to": ["alice@example.com"],
            "subject": "JSON Raw Send",
            "text": "Plain text version",
            "html": "<p>HTML version</p>",
            "headers": {
                "X-Campaign": "launch-2026"
            },
            "attachments": [
                {
                    "filename": "report.pdf",
                    "content": expected_att_b64
                }
            ]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "re_sent_json_1"
        })))
        .expect(1)
        .mount(&resend_mock)
        .await;

    // 2) Expect `uploadType=media` send
    Mock::given(method("POST"))
        .and(path("/emails"))
        .and(header("authorization", format!("Bearer {TEST_RESEND_KEY}")))
        .and(body_partial_json(json!({
            "from": "agent@example.com",
            "to": ["bob@example.com"],
            "subject": "Media Upload Send",
            "text": "Sent via uploadType=media",
            "headers": {
                "X-Upload-Kind": "media"
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "re_sent_media_2"
        })))
        .expect(1)
        .mount(&resend_mock)
        .await;

    // 3) Expect `uploadType=multipart` send
    Mock::given(method("POST"))
        .and(path("/emails"))
        .and(header("authorization", format!("Bearer {TEST_RESEND_KEY}")))
        .and(body_partial_json(json!({
            "from": "agent@example.com",
            "to": ["carol@example.com"],
            "subject": "Multipart Upload Send",
            "text": "Sent via uploadType=multipart",
            "headers": {
                "X-Upload-Kind": "multipart"
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "re_sent_multipart_3"
        })))
        .expect(1)
        .mount(&resend_mock)
        .await;

    let srv = LiveServer::start(
        test_config_with_resend(&resend_mock.uri(), Some(TEST_BEARER_TOKEN)),
        false,
    )
    .await;

    // Health/readiness are unauthenticated; Gmail endpoints require bearer auth
    assert_eq!(
        srv.client
            .get(srv.url("/healthz"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        srv.client
            .get(srv.url("/readyz"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        srv.client
            .get(srv.url("/gmail/v1/users/me/profile"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );

    // Initial profile
    let profile: Value = srv
        .client
        .get(srv.url("/gmail/v1/users/me/profile"))
        .bearer_auth(TEST_BEARER_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(profile["emailAddress"], "agent@example.com");
    assert_eq!(profile["messagesTotal"], 0);
    assert_eq!(profile["threadsTotal"], 0);
    assert!(profile["historyId"].as_str().is_some());

    // 1. POST /gmail/v1/users/me/messages/send (JSON `raw`)
    let raw_json_mime = build_rich_mime_email(
        "agent@example.com",
        "alice@example.com",
        "JSON Raw Send",
        "Plain text version",
        "<p>HTML version</p>",
        ("X-Campaign", "launch-2026"),
        ("report.pdf", "application/pdf", attachment_bytes),
    );
    let sent_json_resp = srv
        .client
        .post(srv.url("/gmail/v1/users/me/messages/send"))
        .bearer_auth(TEST_BEARER_TOKEN)
        .header("idempotency-key", "idem-json-send-1")
        .json(&json!({ "raw": mime::encode_base64url(&raw_json_mime) }))
        .send()
        .await
        .unwrap();
    assert_eq!(sent_json_resp.status(), StatusCode::OK);
    let sent_json: Value = sent_json_resp.json().await.unwrap();
    let first_thread_id = sent_json["threadId"].as_str().unwrap().to_string();
    assert!(
        sent_json["labelIds"]
            .as_array()
            .unwrap()
            .contains(&json!(LABEL_SENT))
    );

    // 2. POST /upload/gmail/v1/users/me/messages/send?uploadType=media
    let media_mime = b"From: agent@example.com\r\nTo: bob@example.com\r\nSubject: Media Upload Send\r\nX-Upload-Kind: media\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSent via uploadType=media";
    let sent_media_resp = srv
        .client
        .post(srv.url("/upload/gmail/v1/users/me/messages/send?uploadType=media"))
        .bearer_auth(TEST_BEARER_TOKEN)
        .header("content-type", "message/rfc822")
        .body(media_mime.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(sent_media_resp.status(), StatusCode::OK);
    let sent_media: Value = sent_media_resp.json().await.unwrap();
    assert!(sent_media["id"].as_str().is_some());

    // 3. POST /upload/gmail/v1/users/me/messages/send?uploadType=multipart (join first_thread_id)
    let multipart_mime = "From: agent@example.com\r\nTo: carol@example.com\r\nSubject: Multipart Upload Send\r\nX-Upload-Kind: multipart\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSent via uploadType=multipart";
    let metadata_part = json!({ "threadId": first_thread_id }).to_string();
    let boundary = "nogml_multipart_upload_boundary";
    let multipart_body = format!(
        "--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{metadata_part}\r\n--{boundary}\r\nContent-Type: message/rfc822\r\n\r\n{multipart_mime}\r\n--{boundary}--\r\n"
    );
    let sent_mp_resp = srv
        .client
        .post(srv.url("/upload/gmail/v1/users/me/messages/send?uploadType=multipart"))
        .bearer_auth(TEST_BEARER_TOKEN)
        .header(
            "content-type",
            format!("multipart/related; boundary={boundary}"),
        )
        .body(multipart_body)
        .send()
        .await
        .unwrap();
    assert_eq!(sent_mp_resp.status(), StatusCode::OK);
    let sent_mp: Value = sent_mp_resp.json().await.unwrap();
    assert_eq!(sent_mp["threadId"], first_thread_id);

    // Profile now reflects 3 messages across 2 threads
    let profile_after: Value = srv
        .client
        .get(srv.url("/gmail/v1/users/me/profile"))
        .bearer_auth(TEST_BEARER_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(profile_after["messagesTotal"], 3);
    assert_eq!(profile_after["threadsTotal"], 2);

    srv.shutdown().await;
}

#[tokio::test]
async fn gmail_message_formats_repeatable_metadata_headers_and_attachments() {
    let resend_mock = MockServer::start().await;
    let srv = LiveServer::start(test_config_with_resend(&resend_mock.uri(), None), false).await;

    let binary_payload: Vec<u8> = (0u8..=127).collect();
    let raw_mime = build_rich_mime_email(
        "Alice <alice@example.com>",
        "agent@example.com",
        "Quarterly Attachment",
        "See attached binary spec.",
        "<b>See attached binary spec.</b>",
        ("X-Priority-Code", "P1-URGENT"),
        ("spec.bin", "application/octet-stream", &binary_payload),
    );

    let inserted: Value = srv
        .client
        .post(srv.url("/gmail/v1/users/me/messages"))
        .json(&json!({
            "raw": mime::encode_base64url(&raw_mime),
            "labelIds": [LABEL_INBOX, LABEL_UNREAD]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let msg_id = inserted["id"].as_str().unwrap().to_string();

    // 1. format=full + attachment download
    let full: Value = srv
        .client
        .get(srv.url(&format!("/gmail/v1/users/me/messages/{msg_id}?format=full")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(full["id"], msg_id);
    assert!(full["raw"].is_null());
    assert!(full["payload"].is_object());

    fn find_attachment_id(part: &Value) -> Option<String> {
        if let Some(aid) = part
            .get("body")
            .and_then(|b| b.get("attachmentId"))
            .and_then(Value::as_str)
        {
            return Some(aid.to_string());
        }
        if let Some(parts) = part.get("parts").and_then(Value::as_array) {
            for p in parts {
                if let Some(found) = find_attachment_id(p) {
                    return Some(found);
                }
            }
        }
        None
    }

    let att_id = find_attachment_id(&full["payload"])
        .expect("format=full payload must contain attachmentId");
    let att_resp: Value = srv
        .client
        .get(srv.url(&format!(
            "/gmail/v1/users/me/messages/{msg_id}/attachments/{att_id}"
        )))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(att_resp["size"], binary_payload.len() as i64);
    let decoded = mime::decode_base64url(att_resp["data"].as_str().unwrap()).unwrap();
    assert_eq!(decoded, binary_payload);

    // 2. format=metadata with repeatable metadataHeaders
    let meta: Value = srv
        .client
        .get(srv.url(&format!(
            "/gmail/v1/users/me/messages/{msg_id}?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=X-Priority-Code"
        )))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(meta["raw"].is_null());
    let headers = meta["payload"]["headers"].as_array().unwrap();
    let header_names: Vec<String> = headers
        .iter()
        .map(|h| h["name"].as_str().unwrap().to_ascii_lowercase())
        .collect();
    assert!(header_names.contains(&"from".to_string()));
    assert!(header_names.contains(&"subject".to_string()));
    assert!(header_names.contains(&"x-priority-code".to_string()));
    assert!(
        !header_names.contains(&"to".to_string()),
        "metadataHeaders filter must exclude unrequested To header, got: {header_names:?}"
    );
    assert!(
        meta["payload"]["parts"].is_null(),
        "format=metadata must not include nested body parts"
    );

    // 3. format=minimal
    let minimal: Value = srv
        .client
        .get(srv.url(&format!("/gmail/v1/users/me/messages/{msg_id}?format=minimal")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(minimal["id"], msg_id);
    assert!(minimal["snippet"].as_str().is_some());
    assert!(minimal["payload"].is_null());
    assert!(minimal["raw"].is_null());

    // 4. format=raw
    let raw_resp: Value = srv
        .client
        .get(srv.url(&format!("/gmail/v1/users/me/messages/{msg_id}?format=raw")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(raw_resp["payload"].is_null());
    let decoded_raw = mime::decode_base64url(raw_resp["raw"].as_str().unwrap()).unwrap();
    assert_eq!(decoded_raw, raw_mime);

    srv.shutdown().await;
}

#[tokio::test]
async fn gmail_batch_multipart_mixed_and_partial_fields_projection() {
    let resend_mock = MockServer::start().await;
    let srv = LiveServer::start(
        test_config_with_resend(&resend_mock.uri(), Some(TEST_BEARER_TOKEN)),
        false,
    )
    .await;

    // Seed 3 messages so pagination produces `nextPageToken` with `maxResults=2`
    let mut ids = Vec::new();
    for idx in 1..=3 {
        let raw = format!(
            "From: sender{idx}@example.com\r\nTo: agent@example.com\r\nSubject: Batch Msg {idx}\r\n\r\nBody of batch message {idx}"
        );
        let resp: Value = srv
            .client
            .post(srv.url("/gmail/v1/users/me/messages"))
            .bearer_auth(TEST_BEARER_TOKEN)
            .json(&json!({
                "raw": mime::encode_base64url(raw.as_bytes()),
                "labelIds": [LABEL_INBOX, LABEL_UNREAD]
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        ids.push(resp["id"].as_str().unwrap().to_string());
    }

    // Partial response 1: `?fields=messages(id,threadId),nextPageToken`
    let list_partial: Value = srv
        .client
        .get(srv.url(
            "/gmail/v1/users/me/messages?maxResults=2&fields=messages(id,threadId),nextPageToken",
        ))
        .bearer_auth(TEST_BEARER_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let list_obj = list_partial.as_object().unwrap();
    assert!(list_obj.contains_key("messages"));
    assert!(list_obj.contains_key("nextPageToken"));
    assert!(
        !list_obj.contains_key("resultSizeEstimate"),
        "resultSizeEstimate should be stripped by ?fields="
    );
    let msgs = list_obj["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 2);
    for m in msgs {
        let obj = m.as_object().unwrap();
        assert_eq!(obj.len(), 2);
        assert!(obj.contains_key("id"));
        assert!(obj.contains_key("threadId"));
    }

    // Partial response 2: `?fields=id,snippet,payload/headers`
    let msg_partial: Value = srv
        .client
        .get(srv.url(&format!(
            "/gmail/v1/users/me/messages/{}?format=full&fields=id,snippet,payload/headers",
            ids[0]
        )))
        .bearer_auth(TEST_BEARER_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let msg_obj = msg_partial.as_object().unwrap();
    assert_eq!(msg_obj.len(), 3);
    assert_eq!(msg_obj["id"], ids[0]);
    assert!(msg_obj["snippet"].as_str().is_some());
    let payload_obj = msg_obj["payload"].as_object().unwrap();
    assert_eq!(
        payload_obj.len(),
        1,
        "payload should contain ONLY headers: {payload_obj:?}"
    );
    assert!(payload_obj["headers"].is_array());

    // Batch request: 4 subrequests (profile, filtered message get, 404 missing message, label modify)
    // Outer Authorization header MUST be inherited by subrequests without their own Authorization!
    let boundary = "batch_superhuman_e2e";
    let modify_body = json!({ "addLabelIds": [LABEL_STARRED] }).to_string();
    let batch_payload = format!(
        "--{boundary}\r\n\
Content-Type: application/http\r\n\
Content-ID: <req-profile>\r\n\
\r\n\
GET /gmail/v1/users/me/profile HTTP/1.1\r\n\
\r\n\
--{boundary}\r\n\
Content-Type: application/http\r\n\
Content-ID: <req-msg-0>\r\n\
\r\n\
GET /gmail/v1/users/me/messages/{m0}?format=minimal&fields=id,threadId HTTP/1.1\r\n\
\r\n\
--{boundary}\r\n\
Content-Type: application/http\r\n\
Content-ID: <req-missing>\r\n\
\r\n\
GET /gmail/v1/users/me/messages/nonexistent-message-404 HTTP/1.1\r\n\
\r\n\
--{boundary}\r\n\
Content-Type: application/http\r\n\
Content-ID: <req-modify>\r\n\
\r\n\
POST /gmail/v1/users/me/messages/{m1}/modify HTTP/1.1\r\n\
Content-Type: application/json\r\n\
\r\n\
{modify_body}\r\n\
--{boundary}--\r\n",
        m0 = ids[0],
        m1 = ids[1],
    );

    // Unauthenticated batch must fail 401
    let unauth = srv
        .client
        .post(srv.url("/batch/gmail/v1"))
        .header(
            "content-type",
            format!("multipart/mixed; boundary={boundary}"),
        )
        .body(batch_payload.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

    // Authenticated batch returns 200 OK multipart/mixed
    let batch_resp = srv
        .client
        .post(srv.url("/batch/gmail/v1"))
        .bearer_auth(TEST_BEARER_TOKEN)
        .header(
            "content-type",
            format!("multipart/mixed; boundary={boundary}"),
        )
        .body(batch_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(batch_resp.status(), StatusCode::OK);
    let resp_ct = batch_resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        resp_ct.starts_with("multipart/mixed; boundary="),
        "unexpected batch Content-Type: {resp_ct}"
    );
    let resp_bytes = batch_resp.bytes().await.unwrap();
    let parts = parse_multipart_parts(&resp_ct, &resp_bytes).expect("parse batch response parts");
    assert_eq!(parts.len(), 4);

    // Part 0: profile 200
    assert_eq!(parts[0].header("content-id"), Some("response-req-profile"));
    let (s0, _, b0) = parse_embedded_http_response(&parts[0].body);
    assert_eq!(s0, 200);
    let j0: Value = serde_json::from_slice(&b0).unwrap();
    assert_eq!(j0["emailAddress"], "agent@example.com");
    assert_eq!(j0["messagesTotal"], 3);

    // Part 1: partial fields message 200
    assert_eq!(parts[1].header("content-id"), Some("response-req-msg-0"));
    let (s1, _, b1) = parse_embedded_http_response(&parts[1].body);
    assert_eq!(s1, 200);
    let j1: Value = serde_json::from_slice(&b1).unwrap();
    assert_eq!(j1.as_object().unwrap().len(), 2);
    assert_eq!(j1["id"], ids[0]);

    // Part 2: 404 part inside 200 OK batch response
    assert_eq!(parts[2].header("content-id"), Some("response-req-missing"));
    let (s2, _, _) = parse_embedded_http_response(&parts[2].body);
    assert_eq!(s2, 404);

    // Part 3: modify 200
    assert_eq!(parts[3].header("content-id"), Some("response-req-modify"));
    let (s3, _, b3) = parse_embedded_http_response(&parts[3].body);
    assert_eq!(s3, 200);
    let j3: Value = serde_json::from_slice(&b3).unwrap();
    assert!(
        j3["labelIds"]
            .as_array()
            .unwrap()
            .contains(&json!(LABEL_STARRED))
    );

    srv.shutdown().await;
}

#[tokio::test]
async fn gmail_threads_labels_drafts_history_and_settings_lifecycle() {
    let resend_mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/emails"))
        .and(body_partial_json(json!({
            "from": "agent@example.com",
            "to": ["dana@example.com"],
            "subject": "Updated Draft Subject",
            "text": "Updated draft body ready to send"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "re_draft_sent_1"
        })))
        .expect(1)
        .mount(&resend_mock)
        .await;

    let srv = LiveServer::start(test_config_with_resend(&resend_mock.uri(), None), false).await;

    // --- Labels CRUD ---
    let initial_labels: Value = srv
        .client
        .get(srv.url("/gmail/v1/users/me/labels"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        initial_labels["labels"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l["id"] == LABEL_INBOX)
    );

    let created_label: Value = srv
        .client
        .post(srv.url("/gmail/v1/users/me/labels"))
        .json(&json!({
            "name": "Customers/VIP",
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show",
            "color": { "textColor": "#ffffff", "backgroundColor": "#16a765" }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let vip_label_id = created_label["id"].as_str().unwrap().to_string();
    assert_eq!(created_label["name"], "Customers/VIP");

    let patched_label: Value = srv
        .client
        .patch(srv.url(&format!("/gmail/v1/users/me/labels/{vip_label_id}")))
        .json(&json!({ "name": "Customers/Enterprise" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(patched_label["name"], "Customers/Enterprise");

    // Capture baseline historyId before message & thread mutations
    let base_profile: Value = srv
        .client
        .get(srv.url("/gmail/v1/users/me/profile"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let start_history_id = base_profile["historyId"].as_str().unwrap().to_string();

    // --- Threads lifecycle ---
    let m1_raw = b"From: ceo@example.com\r\nTo: agent@example.com\r\nSubject: Roadmap\r\nMessage-ID: <road-1@example.com>\r\n\r\nFirst message";
    let m1: Value = srv
        .client
        .post(srv.url("/gmail/v1/users/me/messages"))
        .json(&json!({
            "raw": mime::encode_base64url(m1_raw),
            "labelIds": [LABEL_INBOX, LABEL_UNREAD]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let m1_id = m1["id"].as_str().unwrap().to_string();
    let thread_id = m1["threadId"].as_str().unwrap().to_string();

    let m2_raw = b"From: cto@example.com\r\nTo: agent@example.com\r\nSubject: Re: Roadmap\r\nIn-Reply-To: <road-1@example.com>\r\n\r\nSecond message";
    let m2: Value = srv
        .client
        .post(srv.url("/gmail/v1/users/me/messages"))
        .json(&json!({
            "raw": mime::encode_base64url(m2_raw),
            "threadId": thread_id,
            "labelIds": [LABEL_INBOX, LABEL_UNREAD]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let m2_id = m2["id"].as_str().unwrap().to_string();

    let threads_list: Value = srv
        .client
        .get(srv.url("/gmail/v1/users/me/threads"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(threads_list["threads"].as_array().unwrap().len(), 1);

    // Modify thread labels (+VIP, -UNREAD)
    let modified_thread: Value = srv
        .client
        .post(srv.url(&format!("/gmail/v1/users/me/threads/{thread_id}/modify")))
        .json(&json!({
            "addLabelIds": [vip_label_id],
            "removeLabelIds": [LABEL_UNREAD]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(modified_thread["messages"].as_array().unwrap().len(), 2);
    for m in modified_thread["messages"].as_array().unwrap() {
        let lbls = m["labelIds"].as_array().unwrap();
        assert!(lbls.contains(&json!(vip_label_id)));
        assert!(!lbls.contains(&json!(LABEL_UNREAD)));
    }

    // Trash & untrash thread
    let trashed: Value = srv
        .client
        .post(srv.url(&format!("/gmail/v1/users/me/threads/{thread_id}/trash")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        trashed["messages"][0]["labelIds"]
            .as_array()
            .unwrap()
            .contains(&json!("TRASH"))
    );
    let untrashed: Value = srv
        .client
        .post(srv.url(&format!("/gmail/v1/users/me/threads/{thread_id}/untrash")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        !untrashed["messages"][0]["labelIds"]
            .as_array()
            .unwrap()
            .contains(&json!("TRASH"))
    );

    // Delete m2 so history records `messagesDeleted`
    let del_status = srv
        .client
        .delete(srv.url(&format!("/gmail/v1/users/me/messages/{m2_id}")))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(del_status, StatusCode::NO_CONTENT);

    // --- History incremental check ---
    let history: Value = srv
        .client
        .get(srv.url(&format!(
            "/gmail/v1/users/me/history?startHistoryId={start_history_id}"
        )))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let records = history["history"].as_array().expect("history records");
    assert!(
        records
            .iter()
            .any(|r| r.get("messagesAdded").and_then(Value::as_array).is_some()),
        "expected messagesAdded in history: {records:?}"
    );
    assert!(
        records
            .iter()
            .any(|r| r.get("labelsAdded").and_then(Value::as_array).is_some()),
        "expected labelsAdded in history: {records:?}"
    );
    assert!(
        records
            .iter()
            .any(|r| r.get("labelsRemoved").and_then(Value::as_array).is_some()),
        "expected labelsRemoved in history: {records:?}"
    );
    assert!(
        records.iter().any(|r| {
            r.get("messagesDeleted")
                .and_then(Value::as_array)
                .is_some_and(|arr| arr.iter().any(|d| d["message"]["id"] == m2_id))
        }),
        "expected messagesDeleted for {m2_id} in history: {records:?}"
    );
    assert!(!m1_id.is_empty());

    // Delete custom label
    let del_lbl = srv
        .client
        .delete(srv.url(&format!("/gmail/v1/users/me/labels/{vip_label_id}")))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(del_lbl, StatusCode::NO_CONTENT);

    // --- Drafts + drafts.send ---
    let draft_raw_v1 = b"From: agent@example.com\r\nTo: dana@example.com\r\nSubject: Draft v1\r\n\r\nInitial draft text";
    let draft_created: Value = srv
        .client
        .post(srv.url("/gmail/v1/users/me/drafts"))
        .json(&json!({
            "message": { "raw": mime::encode_base64url(draft_raw_v1) }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let draft_id = draft_created["id"].as_str().unwrap().to_string();
    assert!(
        draft_created["message"]["labelIds"]
            .as_array()
            .unwrap()
            .contains(&json!(LABEL_DRAFT))
    );

    let draft_list: Value = srv
        .client
        .get(srv.url("/gmail/v1/users/me/drafts"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(draft_list["drafts"].as_array().unwrap().len(), 1);

    // Update draft v2
    let draft_raw_v2 = b"From: agent@example.com\r\nTo: dana@example.com\r\nSubject: Updated Draft Subject\r\n\r\nUpdated draft body ready to send";
    let draft_updated: Value = srv
        .client
        .put(srv.url(&format!("/gmail/v1/users/me/drafts/{draft_id}")))
        .json(&json!({
            "id": draft_id,
            "message": { "raw": mime::encode_base64url(draft_raw_v2) }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(draft_updated["id"], draft_id);

    // Send draft via drafts.send
    let draft_sent: Value = srv
        .client
        .post(srv.url("/gmail/v1/users/me/drafts/send"))
        .json(&json!({ "id": draft_id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        draft_sent["labelIds"]
            .as_array()
            .unwrap()
            .contains(&json!(LABEL_SENT))
    );
    // Draft is removed after send
    assert_eq!(
        srv.client
            .get(srv.url(&format!("/gmail/v1/users/me/drafts/{draft_id}")))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );

    // --- Settings/* (`sendAs`, `vacation`, `autoForwarding`, `imap`, `pop`) ---
    let send_as_list: Value = srv
        .client
        .get(srv.url("/gmail/v1/users/me/settings/sendAs"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        send_as_list["sendAs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["sendAsEmail"] == "agent@example.com" && s["isPrimary"] == true)
    );

    let alias_created: Value = srv
        .client
        .post(srv.url("/gmail/v1/users/me/settings/sendAs"))
        .json(&json!({
            "sendAsEmail": "ops@example.com",
            "displayName": "Ops Bot",
            "signature": "<b>Ops</b>"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(alias_created["sendAsEmail"], "ops@example.com");
    assert_eq!(alias_created["verificationStatus"], "accepted");

    let alias_patched: Value = srv
        .client
        .patch(srv.url("/gmail/v1/users/me/settings/sendAs/ops@example.com"))
        .json(&json!({ "displayName": "Operations Team" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(alias_patched["displayName"], "Operations Team");
    assert_eq!(alias_patched["signature"], "<b>Ops</b>");

    assert_eq!(
        srv.client
            .delete(srv.url("/gmail/v1/users/me/settings/sendAs/ops@example.com"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );

    let vac: Value = srv
        .client
        .put(srv.url("/gmail/v1/users/me/settings/vacation"))
        .json(&json!({
            "enableAutoReply": true,
            "responseSubject": "Out of office",
            "responseBodyPlainText": "Back Monday"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(vac["enableAutoReply"], true);
    let vac_get: Value = srv
        .client
        .get(srv.url("/gmail/v1/users/me/settings/vacation"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(vac_get["responseSubject"], "Out of office");

    let fwd: Value = srv
        .client
        .put(srv.url("/gmail/v1/users/me/settings/autoForwarding"))
        .json(&json!({
            "enabled": true,
            "emailAddress": "archive@example.com",
            "disposition": "leaveInInbox"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fwd["enabled"], true);
    assert_eq!(fwd["emailAddress"], "archive@example.com");

    let imap_cfg: Value = srv
        .client
        .put(srv.url("/gmail/v1/users/me/settings/imap"))
        .json(&json!({
            "enabled": true,
            "autoExpunge": false,
            "expungeBehavior": "archive",
            "maxFolderSize": 10000
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(imap_cfg["enabled"], true);
    assert_eq!(imap_cfg["expungeBehavior"], "archive");

    let pop_cfg: Value = srv
        .client
        .put(srv.url("/gmail/v1/users/me/settings/pop"))
        .json(&json!({
            "accessWindow": "fromNowOn",
            "disposition": "markRead"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(pop_cfg["accessWindow"], "fromNowOn");
    assert_eq!(pop_cfg["disposition"], "markRead");

    srv.shutdown().await;
}

#[tokio::test]
async fn gmail_watch_stop_and_real_push_webhook_delivery() {
    let push_mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/gmail-push"))
        .and(body_partial_json(json!({
            "emailAddress": "agent@example.com",
            "topicName": "projects/nogml-e2e/topics/inbox-updates"
        })))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&push_mock)
        .await;

    let mut cfg = Config::for_test();
    cfg.watch_webhook_url = Some(format!("{}/gmail-push", push_mock.uri()));
    let srv = LiveServer::start(cfg, true).await;

    // 1. Activate watch on INBOX only
    let watch_resp: Value = srv
        .client
        .post(srv.url("/gmail/v1/users/me/watch"))
        .json(&json!({
            "topicName": "projects/nogml-e2e/topics/inbox-updates",
            "labelIds": [LABEL_INBOX],
            "labelFilterBehavior": "include"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(watch_resp["historyId"].as_str().is_some());
    let exp_ms: i64 = watch_resp["expiration"].as_str().unwrap().parse().unwrap();
    assert!(exp_ms > Utc::now().timestamp_millis());

    // 2. Non-matching SPAM message must NOT trigger push
    let spam_raw = b"From: spam@bad.test\r\nTo: agent@example.com\r\nSubject: Junk\r\n\r\nJunk";
    srv.client
        .post(srv.url("/gmail/v1/users/me/messages"))
        .json(&json!({
            "raw": mime::encode_base64url(spam_raw),
            "labelIds": [LABEL_SPAM]
        }))
        .send()
        .await
        .unwrap();

    // 3. Matching INBOX message MUST trigger push webhook
    let inbox_raw = b"From: partner@example.com\r\nTo: agent@example.com\r\nSubject: Deal Signed\r\n\r\nWe are live!";
    srv.client
        .post(srv.url("/gmail/v1/users/me/messages"))
        .json(&json!({
            "raw": mime::encode_base64url(inbox_raw),
            "labelIds": [LABEL_INBOX, LABEL_UNREAD]
        }))
        .send()
        .await
        .unwrap();

    // Wait for push delivery and inspect received payload
    let mut received = Vec::new();
    for _ in 0..30 {
        received = push_mock.received_requests().await.unwrap();
        if !received.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(received.len(), 1, "expected exactly 1 watch push webhook");
    let push_json: Value = serde_json::from_slice(&received[0].body).unwrap();
    let encoded_data = push_json["message"]["data"].as_str().unwrap();
    let decoded_inner: Value =
        serde_json::from_slice(&general_purpose::STANDARD.decode(encoded_data).unwrap()).unwrap();
    assert_eq!(decoded_inner["emailAddress"], "agent@example.com");
    assert_eq!(decoded_inner["historyId"], push_json["historyId"]);

    // 4. Stop watch -> subsequent INBOX arrival must NOT trigger push
    let stop_status = srv
        .client
        .post(srv.url("/gmail/v1/users/me/stop"))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(stop_status, StatusCode::NO_CONTENT);

    let after_stop_raw =
        b"From: partner@example.com\r\nTo: agent@example.com\r\nSubject: After stop\r\n\r\nQuiet";
    srv.client
        .post(srv.url("/gmail/v1/users/me/messages"))
        .json(&json!({
            "raw": mime::encode_base64url(after_stop_raw),
            "labelIds": [LABEL_INBOX, LABEL_UNREAD]
        }))
        .send()
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(120)).await;
    let final_received = push_mock.received_requests().await.unwrap();
    assert_eq!(
        final_received.len(),
        1,
        "watch/stop must halt subsequent push notifications"
    );

    srv.shutdown().await;
}

// ============================================================================
// 2. Resend Inbound & Delivery Webhooks E2E Test
// ============================================================================

#[tokio::test]
async fn resend_webhooks_svix_verification_inbound_cross_protocol_and_delivery_sse() {
    let resend_mock = MockServer::start().await;
    let attachment_data = b"Signed MSA PDF bytes 2026";

    // Mock Resend Receiving API for inbound email + attachment list + download
    Mock::given(method("GET"))
        .and(path("/emails/receiving/re_in_777"))
        .and(header("authorization", format!("Bearer {TEST_RESEND_KEY}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "email",
            "id": "re_in_777",
            "from": "Founder <founder@acme.test>",
            "to": ["agent@example.com"],
            "subject": "Inbound Resend Partnership",
            "text": "Hi Agent, please review the attached MSA.",
            "html": "<p>Hi Agent, please review the attached MSA.</p>",
            "message_id": "<inbound-777@acme.test>",
            "created_at": "2026-11-25T10:00:00Z",
            "headers": {
                "Authentication-Results": "mx.resend.com; spf=pass; dkim=pass"
            },
            "attachments": [
                {
                    "id": "att_777_1",
                    "filename": "msa.txt",
                    "content_type": "text/plain"
                }
            ]
        })))
        .expect(1)
        .mount(&resend_mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/emails/receiving/re_in_777/attachments"))
        .and(header("authorization", format!("Bearer {TEST_RESEND_KEY}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "has_more": false,
            "data": [
                {
                    "id": "att_777_1",
                    "filename": "msa.txt",
                    "size": attachment_data.len(),
                    "content_type": "text/plain",
                    "download_url": format!("{}/downloads/att_777_1", resend_mock.uri())
                }
            ]
        })))
        .expect(1)
        .mount(&resend_mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/downloads/att_777_1"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(attachment_data.to_vec()))
        .expect(1)
        .mount(&resend_mock)
        .await;

    // Mock Resend Outbound Send for delivery webhook correlation
    Mock::given(method("POST"))
        .and(path("/emails"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "re_out_888"
        })))
        .expect(1)
        .mount(&resend_mock)
        .await;

    let mut cfg = test_config_with_resend(&resend_mock.uri(), Some(TEST_BEARER_TOKEN));
    cfg.resend_webhook_secret = Some(TEST_WEBHOOK_SECRET.to_string());
    let srv = LiveServer::start(cfg, false).await;

    let inbound_payload = serde_json::to_vec(&json!({
        "type": "email.received",
        "created_at": "2026-11-25T10:00:01Z",
        "data": {
            "email_id": "re_in_777",
            "from": "Founder <founder@acme.test>",
            "to": ["agent@example.com"],
            "subject": "Inbound Resend Partnership",
            "message_id": "<inbound-777@acme.test>",
            "attachments": [{ "id": "att_777_1", "filename": "msa.txt" }]
        }
    }))
    .unwrap();
    let now_secs = Utc::now().timestamp();

    // 1. Invalid Svix signatures -> 401
    let bad_sig_status = srv
        .client
        .post(srv.url("/webhooks/resend"))
        .header("content-type", "application/json")
        .header("svix-id", "msg_bad_1")
        .header("svix-timestamp", now_secs.to_string())
        .header("svix-signature", "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        .body(inbound_payload.clone())
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(bad_sig_status, StatusCode::UNAUTHORIZED);

    let missing_sig_status = srv
        .client
        .post(srv.url("/webhooks/resend"))
        .header("content-type", "application/json")
        .body(inbound_payload.clone())
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(missing_sig_status, StatusCode::UNAUTHORIZED);

    // 2. Valid Svix-signed `email.received` (no Bearer auth needed on webhook route)
    let valid_sig =
        sign_svix_payload("msg_valid_in_1", now_secs, &inbound_payload, TEST_WEBHOOK_SECRET)
            .unwrap();
    let wh_resp = srv
        .client
        .post(srv.url("/webhooks/resend"))
        .header("content-type", "application/json")
        .header("svix-id", "msg_valid_in_1")
        .header("svix-timestamp", now_secs.to_string())
        .header("svix-signature", valid_sig)
        .body(inbound_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(wh_resp.status(), StatusCode::OK);
    let wh_json: Value = wh_resp.json().await.unwrap();
    assert_eq!(wh_json["status"], "received");
    let ingested_id = wh_json["message_id"].as_str().unwrap().to_string();
    let labels = wh_json["labels"].as_array().unwrap();
    assert!(labels.contains(&json!(LABEL_INBOX)));
    assert!(labels.contains(&json!(LABEL_UNREAD)));

    // 3a. Readable via Gmail REST API v1 (+ attachment)
    let gmail_msg: Value = srv
        .client
        .get(srv.url(&format!("/gmail/v1/users/me/messages/{ingested_id}?format=full")))
        .bearer_auth(TEST_BEARER_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(gmail_msg["id"], ingested_id);
    assert!(
        gmail_msg["labelIds"]
            .as_array()
            .unwrap()
            .contains(&json!(LABEL_INBOX))
    );
    assert!(
        gmail_msg["labelIds"]
            .as_array()
            .unwrap()
            .contains(&json!(LABEL_UNREAD))
    );

    // 3b. Readable via AI `/v1/messages` (+ attachment bytes)
    let ai_list: Value = srv
        .client
        .get(srv.url("/v1/messages?label=INBOX"))
        .bearer_auth(TEST_BEARER_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        ai_list["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["id"] == ingested_id)
    );

    let ai_msg: Value = srv
        .client
        .get(srv.url(&format!("/v1/messages/{ingested_id}")))
        .bearer_auth(TEST_BEARER_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ai_msg["subject"], "Inbound Resend Partnership");
    assert_eq!(ai_msg["unread"], true);
    assert_eq!(ai_msg["has_attachments"], true);
    assert_eq!(ai_msg["_meta"]["untrusted_external_content"], true);
    assert!(
        ai_msg["text"]
            .as_str()
            .unwrap()
            .contains("review the attached MSA")
    );
    let att_id = ai_msg["attachments_meta"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let ai_att_bytes = srv
        .client
        .get(srv.url(&format!(
            "/v1/messages/{ingested_id}/attachments/{att_id}"
        )))
        .bearer_auth(TEST_BEARER_TOKEN)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(ai_att_bytes.as_ref(), attachment_data);

    // 3c. Readable via MCP (`tools/call` `read_email` + `resources/read`)
    let mcp_tool_resp: Value = srv
        .client
        .post(srv.url("/mcp"))
        .bearer_auth(TEST_BEARER_TOKEN)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "read_email",
                "arguments": { "message_id": ingested_id }
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tool_inner: Value = serde_json::from_str(
        mcp_tool_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(tool_inner["id"], ingested_id);
    assert_eq!(tool_inner["subject"], "Inbound Resend Partnership");

    let mcp_res_resp: Value = srv
        .client
        .post(srv.url("/mcp"))
        .bearer_auth(TEST_BEARER_TOKEN)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "resources/read",
            "params": { "uri": format!("nogml://message/{ingested_id}") }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let res_inner: Value = serde_json::from_str(
        mcp_res_resp["result"]["contents"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(res_inner["id"], ingested_id);

    // 4. Outbound send + Delivery Webhooks (`email.delivered`, `email.bounced`) + Live SSE
    let out_sent: Value = srv
        .client
        .post(srv.url("/v1/messages/send"))
        .bearer_auth(TEST_BEARER_TOKEN)
        .json(&json!({
            "to": ["recipient@acme.test"],
            "subject": "Delivery Tracking Test",
            "text": "Tracking delivery state"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let out_msg_id = out_sent["message_id"].as_str().unwrap().to_string();
    assert_eq!(out_sent["resend_id"], "re_out_888");

    // Subscribe to live SSE filtered to `delivery_status`
    let sse_client = Client::new();
    let mut sse_resp = sse_client
        .get(srv.url("/v1/events?types=delivery_status"))
        .bearer_auth(TEST_BEARER_TOKEN)
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
    let mut sse_buf = String::new();

    // Send `email.delivered`
    let delivered_body = serde_json::to_vec(&json!({
        "type": "email.delivered",
        "created_at": "2026-11-25T10:01:00Z",
        "data": { "email_id": "re_out_888" }
    }))
    .unwrap();
    let delivered_sig =
        sign_svix_payload("msg_deliv_1", now_secs, &delivered_body, TEST_WEBHOOK_SECRET).unwrap();
    let deliv_resp: Value = srv
        .client
        .post(srv.url("/webhooks/resend"))
        .header("content-type", "application/json")
        .header("svix-id", "msg_deliv_1")
        .header("svix-timestamp", now_secs.to_string())
        .header("svix-signature", delivered_sig)
        .body(delivered_body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(deliv_resp["delivery_status"], "delivered");
    assert_eq!(deliv_resp["message_id"], out_msg_id);

    let stored_after_deliv = srv.state.store.get_message(&out_msg_id).await.unwrap().unwrap();
    assert_eq!(stored_after_deliv.delivery_status.as_deref(), Some("delivered"));

    let (ev1_name, _, ev1_data) =
        read_next_sse_event(&mut sse_resp, &mut sse_buf, Duration::from_secs(3)).await;
    assert_eq!(ev1_name, "delivery_status");
    assert_eq!(ev1_data["event"]["status"], "delivered");
    assert_eq!(ev1_data["event"]["resend_id"], "re_out_888");
    assert_eq!(ev1_data["event"]["message_id"], out_msg_id);

    // Send `email.bounced`
    let bounced_body = serde_json::to_vec(&json!({
        "type": "email.bounced",
        "created_at": "2026-11-25T10:02:00Z",
        "data": {
            "email_id": "re_out_888",
            "bounce": {
                "type": "Permanent",
                "subType": "Suppressed",
                "message": "Mailbox does not exist"
            }
        }
    }))
    .unwrap();
    let bounced_sig =
        sign_svix_payload("msg_bounce_1", now_secs, &bounced_body, TEST_WEBHOOK_SECRET).unwrap();
    let bounce_resp: Value = srv
        .client
        .post(srv.url("/webhooks/resend"))
        .header("content-type", "application/json")
        .header("svix-id", "msg_bounce_1")
        .header("svix-timestamp", now_secs.to_string())
        .header("svix-signature", bounced_sig)
        .body(bounced_body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(bounce_resp["delivery_status"], "bounced");

    let stored_after_bounce = srv.state.store.get_message(&out_msg_id).await.unwrap().unwrap();
    assert_eq!(stored_after_bounce.delivery_status.as_deref(), Some("bounced"));

    let (ev2_name, _, ev2_data) =
        read_next_sse_event(&mut sse_resp, &mut sse_buf, Duration::from_secs(3)).await;
    assert_eq!(ev2_name, "delivery_status");
    assert_eq!(ev2_data["event"]["status"], "bounced");
    assert!(
        ev2_data["event"]["detail"]
            .as_str()
            .unwrap()
            .contains("Mailbox does not exist")
    );

    srv.shutdown().await;
}

// ============================================================================
// 3. AI-First `/v1/*` API, Safety Guardrails & Live SSE E2E Tests
// ============================================================================

#[tokio::test]
async fn ai_v1_capabilities_dry_run_allowed_recipients_reply_threading_and_sse() {
    let resend_mock = MockServer::start().await;

    // Only the allowed reply send should hit Resend (NOT dry_run, NOT disallowed recipient)
    Mock::given(method("POST"))
        .and(path("/emails"))
        .and(body_partial_json(json!({
            "from": "agent@example.com",
            "to": ["Carol <carol@trusted.example>"],
            "subject": "Re: Project Helios",
            "text": "Confirmed, shipping today!",
            "headers": {
                "In-Reply-To": "<helios-root@trusted.example>",
                "References": "<helios-root@trusted.example>"
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "re_reply_901"
        })))
        .expect(1)
        .mount(&resend_mock)
        .await;

    let mut cfg = test_config_with_resend(&resend_mock.uri(), None);
    cfg.allowed_recipients = vec!["@trusted.example".to_string()];
    let srv = LiveServer::start(cfg, false).await;

    // 1. GET /v1/capabilities confirms all 7 pluggable backend names
    let caps: Value = srv
        .client
        .get(srv.url("/v1/capabilities"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let backends = caps["backends"].as_object().expect("backends object");
    assert_eq!(backends.len(), 7);
    assert_eq!(backends["storage"], "memory");
    assert_eq!(backends["blob"], "inline");
    assert_eq!(backends["transport"], "resend");
    assert_eq!(backends["filter"], "noop");
    assert_eq!(backends["auth"], "static_token");
    assert_eq!(backends["search"], "memory");
    assert_eq!(backends["outbound_policy"], "config");

    // 2. `/v1/messages/send` with `dry_run: true`: zero Resend calls, zero DB writes
    let dry_resp = srv
        .client
        .post(srv.url("/v1/messages/send"))
        .json(&json!({
            "to": ["carol@trusted.example"],
            "subject": "Dry Run Check",
            "text": "Should never be persisted or sent",
            "dry_run": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(dry_resp.status(), StatusCode::OK);
    let dry_json: Value = dry_resp.json().await.unwrap();
    assert_eq!(dry_json["dry_run"], true);
    assert_eq!(dry_json["would_succeed"], true);
    assert_eq!(dry_json["preview"]["from"], "agent@example.com");
    assert!(dry_json["policy_checks"].as_array().unwrap().len() >= 3);

    // Zero DB writes after dry_run
    let profile_after_dry: Value = srv
        .client
        .get(srv.url("/gmail/v1/users/me/profile"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(profile_after_dry["messagesTotal"], 0);
    assert!(resend_mock.received_requests().await.unwrap().is_empty());

    // 3. `allowed_recipients` blocks external domain with 403
    let blocked_resp = srv
        .client
        .post(srv.url("/v1/messages/send"))
        .json(&json!({
            "to": ["attacker@evil.invalid"],
            "subject": "Exfil",
            "text": "Nope"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(blocked_resp.status(), StatusCode::FORBIDDEN);
    let blocked_json: Value = blocked_resp.json().await.unwrap();
    assert_eq!(blocked_json["error"]["code"], "recipient_not_allowed");
    assert!(resend_mock.received_requests().await.unwrap().is_empty());

    // 4. Open live SSE `GET /v1/events` before ingesting & replying
    let sse_client = Client::new();
    let mut sse_resp = sse_client
        .get(srv.url("/v1/events"))
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
    let mut sse_buf = String::new();

    // Seed original inbound message
    let orig_raw = b"From: Carol <carol@trusted.example>\r\nTo: agent@example.com\r\nSubject: Project Helios\r\nMessage-ID: <helios-root@trusted.example>\r\n\r\nCan we ship today?";
    let orig_msg: Value = srv
        .client
        .post(srv.url("/gmail/v1/users/me/messages"))
        .json(&json!({
            "raw": mime::encode_base64url(orig_raw),
            "labelIds": [LABEL_INBOX, LABEL_UNREAD]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let orig_id = orig_msg["id"].as_str().unwrap().to_string();
    let orig_tid = orig_msg["threadId"].as_str().unwrap().to_string();

    // SSE receives `message_received`
    let (ev_rx_name, ev_rx_id, ev_rx_data) =
        read_next_sse_event(&mut sse_resp, &mut sse_buf, Duration::from_secs(3)).await;
    assert_eq!(ev_rx_name, "message_received");
    assert_eq!(ev_rx_data["event"]["message_id"], orig_id);

    // 5. `reply_to_message_id` auto-threading (omits `to` & `subject` -> auto-filled!)
    let reply_resp = srv
        .client
        .post(srv.url("/v1/messages/send"))
        .json(&json!({
            "reply_to_message_id": orig_id,
            "text": "Confirmed, shipping today!"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reply_resp.status(), StatusCode::OK);
    let reply_json: Value = reply_resp.json().await.unwrap();
    assert_eq!(reply_json["status"], "sent");
    assert_eq!(reply_json["thread_id"], orig_tid);
    assert_eq!(reply_json["subject"], "Re: Project Helios");
    assert_eq!(reply_json["to"], json!(["Carol <carol@trusted.example>"]));
    assert_eq!(reply_json["in_reply_to"], "<helios-root@trusted.example>");
    assert!(
        reply_json["references"]
            .as_str()
            .unwrap()
            .contains("<helios-root@trusted.example>")
    );

    // SSE receives `message_sent` with strictly higher event ID
    let (ev_tx_name, ev_tx_id, ev_tx_data) =
        read_next_sse_event(&mut sse_resp, &mut sse_buf, Duration::from_secs(3)).await;
    assert_eq!(ev_tx_name, "message_sent");
    assert_eq!(ev_tx_data["event"]["thread_id"], orig_tid);
    assert_eq!(ev_tx_data["event"]["resend_id"], "re_reply_901");
    assert!(
        ev_tx_id.parse::<u64>().unwrap() > ev_rx_id.parse::<u64>().unwrap(),
        "SSE event IDs must be strictly monotonic"
    );

    srv.shutdown().await;
}

#[tokio::test]
async fn ai_v1_draft_only_block_and_downgrade_modes() {
    let resend_mock = MockServer::start().await;
    // Resend MUST NOT be called in either draft_only mode.
    Mock::given(method("POST"))
        .and(path("/emails"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&resend_mock)
        .await;

    // 1. DraftOnlyAction::Block -> 403 `draft_only_mode`
    let mut block_cfg = test_config_with_resend(&resend_mock.uri(), None);
    block_cfg.draft_only = true;
    block_cfg.draft_only_action = DraftOnlyAction::Block;
    let block_srv = LiveServer::start(block_cfg, false).await;

    let block_resp = block_srv
        .client
        .post(block_srv.url("/v1/messages/send"))
        .json(&json!({
            "to": ["alice@example.com"],
            "subject": "Blocked Send",
            "text": "Should be rejected"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(block_resp.status(), StatusCode::FORBIDDEN);
    let block_body: Value = block_resp.json().await.unwrap();
    assert_eq!(block_body["error"]["code"], "draft_only_mode");
    assert!(block_body["error"]["hint"].as_str().is_some());
    block_srv.shutdown().await;

    // 2. DraftOnlyAction::Downgrade -> 200 creates draft instead of sending
    let mut down_cfg = test_config_with_resend(&resend_mock.uri(), None);
    down_cfg.draft_only = true;
    down_cfg.draft_only_action = DraftOnlyAction::Downgrade;
    let down_srv = LiveServer::start(down_cfg, false).await;

    let down_resp = down_srv
        .client
        .post(down_srv.url("/v1/messages/send"))
        .json(&json!({
            "to": ["alice@example.com"],
            "subject": "Downgraded to Draft",
            "text": "Saved for human review"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(down_resp.status(), StatusCode::OK);
    let down_body: Value = down_resp.json().await.unwrap();
    assert_eq!(down_body["status"], "draft_created");
    assert_eq!(down_body["downgraded_from_send"], true);
    let draft_id = down_body["draft_id"].as_str().unwrap();

    // Confirm the draft exists in `/v1/drafts`
    let drafts: Value = down_srv
        .client
        .get(down_srv.url("/v1/drafts"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        drafts["drafts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["id"] == draft_id)
    );

    down_srv.shutdown().await;
}

// ============================================================================
// 4. MCP Server (Streamable HTTP + Real Binary Stdio) & Real CLI E2E Tests
// ============================================================================

#[tokio::test]
async fn mcp_streamable_http_initialize_tools_and_resources() {
    let resend_mock = MockServer::start().await;
    let srv = LiveServer::start(
        test_config_with_resend(&resend_mock.uri(), Some(TEST_BEARER_TOKEN)),
        false,
    )
    .await;

    // Seed an email so MCP search/read/resources have data
    let raw = b"From: alice@example.com\r\nTo: agent@example.com\r\nSubject: MCP Streamable HTTP Check\r\n\r\nAgenda for Q4 review";
    let seeded: Value = srv
        .client
        .post(srv.url("/gmail/v1/users/me/messages"))
        .bearer_auth(TEST_BEARER_TOKEN)
        .json(&json!({
            "raw": mime::encode_base64url(raw),
            "labelIds": [LABEL_INBOX, LABEL_UNREAD]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let msg_id = seeded["id"].as_str().unwrap().to_string();
    let thread_id = seeded["threadId"].as_str().unwrap().to_string();

    // 1. `initialize` + Mcp-Session-Id echo
    let init_resp = srv
        .client
        .post(srv.url("/mcp"))
        .bearer_auth(TEST_BEARER_TOKEN)
        .header("mcp-session-id", "sess-e2e-42")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2025-03-26" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(init_resp.status(), StatusCode::OK);
    assert_eq!(
        init_resp
            .headers()
            .get("mcp-session-id")
            .unwrap()
            .to_str()
            .unwrap(),
        "sess-e2e-42"
    );
    let init_json: Value = init_resp.json().await.unwrap();
    assert_eq!(init_json["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(init_json["result"]["serverInfo"]["name"], "nogml");

    // 2. `notifications/initialized` -> 202 Accepted
    let notif_resp = srv
        .client
        .post(srv.url("/mcp"))
        .bearer_auth(TEST_BEARER_TOKEN)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(notif_resp.status(), StatusCode::ACCEPTED);

    // 3. `tools/list`
    let tools_json: Value = srv
        .client
        .post(srv.url("/mcp"))
        .bearer_auth(TEST_BEARER_TOKEN)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tool_names: Vec<&str> = tools_json["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    for required in [
        "search_emails",
        "list_threads",
        "read_thread",
        "read_email",
        "send_email",
        "create_draft",
        "triage_thread",
        "list_labels",
    ] {
        assert!(
            tool_names.contains(&required),
            "missing MCP tool {required} in {tool_names:?}"
        );
    }

    // 4. `tools/call` (`search_emails` + `triage_thread` + `send_email` dry_run)
    let search_resp: Value = srv
        .client
        .post(srv.url("/mcp"))
        .bearer_auth(TEST_BEARER_TOKEN)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "search_emails",
                "arguments": { "query": "Agenda" }
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(search_resp["result"]["isError"], false);
    let search_data: Value =
        serde_json::from_str(search_resp["result"]["content"][0]["text"].as_str().unwrap())
            .unwrap();
    assert_eq!(search_data["messages"][0]["id"], msg_id);

    let triage_resp: Value = srv
        .client
        .post(srv.url("/mcp"))
        .bearer_auth(TEST_BEARER_TOKEN)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "triage_thread",
                "arguments": {
                    "thread_id": thread_id,
                    "mark_read": true,
                    "star": true
                }
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(triage_resp["result"]["isError"], false);

    // 5. `resources/read` (`nogml://inbox`, `nogml://status`, `nogml://thread/{id}`)
    let inbox_res: Value = srv
        .client
        .post(srv.url("/mcp"))
        .bearer_auth(TEST_BEARER_TOKEN)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "resources/read",
            "params": { "uri": "nogml://inbox" }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        inbox_res["result"]["contents"][0]["mimeType"],
        "application/json"
    );
    let inbox_body: Value =
        serde_json::from_str(inbox_res["result"]["contents"][0]["text"].as_str().unwrap())
            .unwrap();
    assert_eq!(inbox_body["threads"][0]["id"], thread_id);
    assert_eq!(inbox_body["threads"][0]["unread"], false);

    let thread_res: Value = srv
        .client
        .post(srv.url("/mcp"))
        .bearer_auth(TEST_BEARER_TOKEN)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "resources/read",
            "params": { "uri": format!("nogml://thread/{thread_id}") }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let thread_body: Value =
        serde_json::from_str(thread_res["result"]["contents"][0]["text"].as_str().unwrap())
            .unwrap();
    assert_eq!(thread_body["id"], thread_id);
    assert_eq!(thread_body["messages"][0]["id"], msg_id);

    // 6. GET /mcp -> 405, DELETE /mcp -> 204
    assert_eq!(
        srv.client
            .get(srv.url("/mcp"))
            .bearer_auth(TEST_BEARER_TOKEN)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        srv.client
            .delete(srv.url("/mcp"))
            .bearer_auth(TEST_BEARER_TOKEN)
            .header("mcp-session-id", "sess-e2e-42")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );

    srv.shutdown().await;
}

#[tokio::test]
async fn real_binary_mcp_stdio_zero_log_pollution_and_schema() {
    let bin = env!("CARGO_BIN_EXE_nogml");

    // --- 1. `nogml mcp` over stdio with RUST_LOG=debug to prove zero log pollution on stdout ---
    let mut mcp_child = Command::new(bin)
        .args([
            "--storage",
            "memory",
            "--user-email",
            "stdio-bot@example.com",
            "mcp",
        ])
        .env("RUST_LOG", "debug")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn nogml mcp");

    {
        let mut stdin = mcp_child.stdin.take().expect("mcp stdin");
        let frames = [
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": { "protocolVersion": "2025-03-26" }
            }),
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "send_email",
                    "arguments": {
                        "to": ["alice@example.com"],
                        "subject": "Stdio Dry Run",
                        "text": "Preview via MCP stdio binary",
                        "dry_run": true
                    }
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "resources/read",
                "params": { "uri": "nogml://status" }
            }),
        ];
        for frame in frames {
            let line = format!("{}\n", serde_json::to_string(&frame).unwrap());
            stdin.write_all(line.as_bytes()).await.unwrap();
        }
        stdin.flush().await.unwrap();
        // Drop stdin to signal EOF so `nogml mcp` exits cleanly.
    }

    let output = tokio::time::timeout(Duration::from_secs(10), mcp_child.wait_with_output())
        .await
        .expect("nogml mcp timed out")
        .expect("nogml mcp wait");
    assert!(
        output.status.success(),
        "nogml mcp failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_str = String::from_utf8(output.stdout).expect("stdout must be valid UTF-8");
    let lines: Vec<&str> = stdout_str.lines().collect();
    assert_eq!(
        lines.len(),
        4,
        "expected strictly 4 JSON-RPC response lines (0 logs, 0 notification replies), got:\n{stdout_str}"
    );

    let parsed_frames: Vec<Value> = lines
        .iter()
        .map(|line| {
            serde_json::from_str::<Value>(line).unwrap_or_else(|err| {
                panic!("non-JSON pollution on MCP stdout line '{line}': {err}")
            })
        })
        .collect();

    assert_eq!(parsed_frames[0]["jsonrpc"], "2.0");
    assert_eq!(parsed_frames[0]["id"], 1);
    assert_eq!(parsed_frames[0]["result"]["serverInfo"]["name"], "nogml");

    assert_eq!(parsed_frames[1]["id"], 2);
    assert!(
        parsed_frames[1]["result"]["tools"]
            .as_array()
            .unwrap()
            .len()
            >= 10
    );

    assert_eq!(parsed_frames[2]["id"], 3);
    assert_eq!(parsed_frames[2]["result"]["isError"], false);
    let dry_run_tool_result: Value = serde_json::from_str(
        parsed_frames[2]["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(dry_run_tool_result["dry_run"], true);
    assert_eq!(dry_run_tool_result["would_succeed"], true);
    assert_eq!(
        dry_run_tool_result["preview"]["from"],
        "stdio-bot@example.com"
    );

    assert_eq!(parsed_frames[3]["id"], 4);
    let status_res: Value = serde_json::from_str(
        parsed_frames[3]["result"]["contents"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status_res["email_address"], "stdio-bot@example.com");

    // --- 2. `nogml schema` (and `--command send`) ---
    let schema_out = Command::new(bin)
        .arg("schema")
        .output()
        .await
        .expect("run nogml schema");
    assert!(schema_out.status.success());
    let schema_json: Value =
        serde_json::from_slice(&schema_out.stdout).expect("nogml schema must emit valid JSON");
    assert!(schema_json.is_object());

    let schema_send_out = Command::new(bin)
        .args(["schema", "--command", "send"])
        .output()
        .await
        .expect("run nogml schema --command send");
    assert!(schema_send_out.status.success());
    let schema_send_json: Value = serde_json::from_slice(&schema_send_out.stdout)
        .expect("nogml schema --command send must emit valid JSON");
    assert!(schema_send_json.is_object());
}

#[tokio::test]
async fn real_binary_live_serve_and_mail_remote_cli_commands() {
    let bin = env!("CARGO_BIN_EXE_nogml");
    let tmp = TempDir::new().expect("tempdir for sqlite db");
    let db_path = tmp.path().join("live_cli_e2e.db");
    let port = pick_ephemeral_port();
    let bind_addr = format!("127.0.0.1:{port}");
    let base_url = format!("http://{bind_addr}");

    let serve_child = Command::new(bin)
        .args([
            "--storage",
            "sqlite",
            "--db-path",
            db_path.to_str().unwrap(),
            "--user-email",
            "cli-live@example.com",
            "--auth-tokens",
            TEST_BEARER_TOKEN,
            "serve",
            "--bind",
            &bind_addr,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn nogml serve");
    let guard = ChildGuard::new(serve_child);

    // Poll `/healthz` until the live binary is ready
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let mut ready = false;
    for _ in 0..60 {
        if let Ok(resp) = client.get(format!("{base_url}/healthz")).send().await
            && resp.status() == StatusCode::OK
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "live `nogml serve` did not become ready on {base_url}");

    // 1. `nogml mail --url http://127.0.0.1:<port> labels`
    let labels_out = Command::new(bin)
        .args([
            "--auth-tokens",
            TEST_BEARER_TOKEN,
            "mail",
            "--url",
            &base_url,
            "labels",
        ])
        .output()
        .await
        .expect("run nogml mail --url ... labels");
    assert!(
        labels_out.status.success(),
        "nogml mail labels failed: stderr={}",
        String::from_utf8_lossy(&labels_out.stderr)
    );
    let labels_json: Value =
        serde_json::from_slice(&labels_out.stdout).expect("labels CLI output must be valid JSON");
    let label_ids: Vec<&str> = labels_json["labels"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|l| l["id"].as_str())
        .collect();
    assert!(label_ids.contains(&LABEL_INBOX));
    assert!(label_ids.contains(&LABEL_SENT));
    assert!(label_ids.contains(&LABEL_DRAFT));
    assert!(label_ids.contains(&LABEL_UNREAD));

    // 2. `nogml mail --url http://127.0.0.1:<port> send --dry-run ...`
    let send_dry_out = Command::new(bin)
        .args([
            "--auth-tokens",
            TEST_BEARER_TOKEN,
            "mail",
            "--url",
            &base_url,
            "send",
            "--to",
            "alice@example.com",
            "--subject",
            "CLI Live Dry Run",
            "--text",
            "Testing live nogml serve via CLI",
            "--dry-run",
        ])
        .output()
        .await
        .expect("run nogml mail --url ... send --dry-run");
    assert!(
        send_dry_out.status.success(),
        "nogml mail send --dry-run failed: stderr={}",
        String::from_utf8_lossy(&send_dry_out.stderr)
    );
    let send_dry_json: Value = serde_json::from_slice(&send_dry_out.stdout)
        .expect("send --dry-run CLI output must be valid JSON");
    assert_eq!(send_dry_json["dry_run"], true);
    assert_eq!(send_dry_json["would_succeed"], true);
    assert_eq!(send_dry_json["preview"]["from"], "cli-live@example.com");
    assert_eq!(send_dry_json["preview"]["to"], json!(["alice@example.com"]));
    assert_eq!(send_dry_json["preview"]["subject"], "CLI Live Dry Run");

    guard.terminate().await;
}
