//! End-to-end integration tests for Issue #28:
//! - HTML-to-Markdown conversion for HTML-only and thin `text/plain` emails across
//!   REST `/v1/messages/{id}`, `/v1/threads/{id}`, and MCP `read_email` / `read_thread`.
//! - Attachment text extraction (`.ics`, `.csv`, `.txt`, `.html`, `.pdf`, scanned PDF,
//!   unsupported binary, oversize) across `GET /v1/messages/{id}/attachments/{att_id}/text`,
//!   `GET /v1/messages/{id}?extract_attachment_text=true`, and MCP `read_attachment_text` /
//!   `read_email`.
//! - Enforcement of `max_chars` / `max_body_chars` ceilings and `untrusted_content_guard`.

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use nogml::{
    AppState, build_router,
    config::Config,
    mcp::McpServer,
    mime::{DEFAULT_ATTACHMENT_MAX_BYTES, parse_rfc2822},
    models::{LABEL_INBOX, LABEL_UNREAD},
    resend::HttpResendClient,
    storage::{MailStore, MemoryStore, NewAttachmentInput, NewMessageInput},
};

fn build_test_app(mut cfg: Config) -> (AppState, Arc<MemoryStore>, Router) {
    cfg.auth_tokens = Vec::new();
    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store.clone(), resend);
    let app = build_router(state.clone());
    (state, store, app)
}

async fn get_json(app: &Router, uri: &str) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let val = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, val)
}

async fn mcp_call(app: &Router, payload: Value) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let val = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, val)
}

#[tokio::test]
async fn html_only_and_thin_plain_emails_render_markdown_via_rest_and_mcp() {
    let (state, store, app) = build_test_app(Config::for_test());

    // 1. HTML-only email ingested via raw RFC 2822
    let raw_html_only = concat!(
        "From: receipts@acme.example\r\n",
        "To: agent@example.com\r\n",
        "Subject: Order #5512 Receipt\r\n",
        "Content-Type: text/html; charset=utf-8\r\n",
        "\r\n",
        "<html><head><style>.hide{display:none}</style></head><body>",
        "<h1>Order #5512</h1>",
        "<p>Thanks for your purchase! <a href=\"https://acme.example/orders/5512\">Track shipment</a>.</p>",
        "<table><tr><th>Item</th><th>Total</th></tr><tr><td>Widget</td><td>$49.00</td></tr></table>",
        "<a href=\"javascript:alert(1)\">Click</a>",
        "<script>evil()</script>",
        "</body></html>"
    );
    let parsed = parse_rfc2822(raw_html_only.as_bytes()).unwrap();
    assert!(parsed.text_body.contains("# Order #5512"));
    assert!(
        parsed
            .text_body
            .contains("[Track shipment](https://acme.example/orders/5512)")
    );
    assert!(!parsed.text_body.contains("javascript:"));
    assert!(!parsed.text_body.contains("evil()"));

    let stored_html_only = store
        .insert_message(NewMessageInput {
            id: Some("msg_html_only".to_string()),
            thread_id: Some("thr_md_1".to_string()),
            label_ids: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            raw_rfc2822: raw_html_only.as_bytes().to_vec(),
            snippet: parsed.snippet,
            internal_date_ms: 1_730_000_000_000,
            subject: parsed.subject,
            from_addr: parsed.from,
            to_addrs: parsed.to,
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: parsed.text_body,
            html_body: parsed.html_body,
            rfc822_message_id: Some("<html-only@acme.example>".to_string()),
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "resend_inbound".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: vec![],
        })
        .await
        .unwrap();

    // 2. Multipart email with thin text/plain stub + rich HTML (plus BiDi/control chars to test guard)
    let stored_thin = store
        .insert_message(NewMessageInput {
            id: Some("msg_thin_stub".to_string()),
            thread_id: Some("thr_md_1".to_string()),
            label_ids: vec![LABEL_INBOX.to_string()],
            raw_rfc2822: Vec::new(),
            snippet: "Please view this email in HTML".to_string(),
            internal_date_ms: 1_730_000_060_000,
            subject: "Weekly Digest".to_string(),
            from_addr: "digest@acme.example".to_string(),
            to_addrs: vec!["agent@example.com".to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: "Please view this email in HTML".to_string(),
            html_body: Some(
                "<h2>Top\u{202E} Updates</h2><ul><li><a href=\"https://acme.example/post/1\">Launch notes</a></li><li>All systems green\x00</li></ul><p>On Mon, Jan 1, Bob wrote:</p><blockquote><p>quoted line</p></blockquote>"
                    .to_string(),
            ),
            rfc822_message_id: Some("<thin-stub@acme.example>".to_string()),
            in_reply_to: Some("<html-only@acme.example>".to_string()),
            references_header: Some("<html-only@acme.example>".to_string()),
            resend_id: None,
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "resend_inbound".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: vec![],
        })
        .await
        .unwrap();

    // REST: GET /v1/messages/msg_thin_stub (with strip_quotes=true)
    let (status, msg_json) = get_json(&app, "/v1/messages/msg_thin_stub?strip_quotes=true").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(msg_json["id"], stored_thin.id);
    assert_eq!(msg_json["text_format"], "markdown");
    assert_eq!(msg_json["_meta"]["untrusted_external_content"], true);
    let body = msg_json["text"].as_str().unwrap();
    assert!(body.contains("## Top Updates"), "got:\n{body}");
    assert!(
        body.contains("- [Launch notes](https://acme.example/post/1)"),
        "got:\n{body}"
    );
    assert!(body.contains("- All systems green"), "got:\n{body}");
    assert!(!body.contains('\u{202E}'), "BiDi char must be stripped");
    assert!(!body.contains('\x00'), "NUL char must be stripped");
    assert!(!body.contains("quoted line"), "quote should be stripped");

    // REST: max_body_chars truncation on converted Markdown
    let (status, trunc_json) = get_json(&app, "/v1/messages/msg_thin_stub?max_body_chars=20").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(trunc_json["text_truncated"], true);
    assert_eq!(trunc_json["text"].as_str().unwrap().chars().count(), 20);
    assert!(trunc_json["text_total_chars"].as_u64().unwrap() > 20);

    // REST: GET /v1/threads/thr_md_1 includes Markdown for both messages
    let (status, thread_json) = get_json(&app, "/v1/threads/thr_md_1").await;
    assert_eq!(status, StatusCode::OK);
    let thread_msgs = thread_json["messages"].as_array().unwrap();
    assert_eq!(thread_msgs.len(), 2);
    assert_eq!(thread_msgs[0]["id"], stored_html_only.id);
    assert!(
        thread_msgs[0]["text"]
            .as_str()
            .unwrap()
            .contains("| Widget | $49.00 |")
    );
    assert_eq!(thread_msgs[1]["text_format"], "markdown");

    // MCP: read_email on thin-stub message returns sanitized Markdown
    let (status, mcp_resp) = mcp_call(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "read_email",
                "arguments": {
                    "message_id": "msg_thin_stub",
                    "strip_quotes": true,
                    "max_body_chars": 500
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mcp_resp["result"]["isError"], false);
    let sc = &mcp_resp["result"]["structuredContent"];
    assert_eq!(sc["text_format"], "markdown");
    assert!(
        sc["text"]
            .as_str()
            .unwrap()
            .contains("[Launch notes](https://acme.example/post/1)")
    );
    assert_eq!(sc["_meta"]["untrusted_external_content"], true);

    // Verify capabilities & MCP tools/list advertise new attachment text surfaces
    let (status, caps) = get_json(&app, "/v1/capabilities").await;
    assert_eq!(status, StatusCode::OK);
    let endpoints: Vec<&str> = caps["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(endpoints.contains(&"GET /v1/messages/{id}/attachments/{attachment_id}/text"));

    let server = McpServer::new(state);
    let tools = server
        .handle_request(json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }))
        .await
        .unwrap()
        .unwrap();
    let tool_names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(tool_names.contains(&"read_attachment_text"));
}

#[tokio::test]
async fn attachment_text_extraction_e2e_rest_and_mcp_with_ceilings_and_guard() {
    let (_state, store, app) = build_test_app(Config::for_test());

    let ics_payload = concat!(
        "BEGIN:VCALENDAR\r\n",
        "VERSION:2.0\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:sync-42@example.com\r\n",
        "SUMMARY:Architecture\r\n",
        "  Review\u{202E}\r\n",
        "DTSTART:20261201T160000Z\r\n",
        "DTEND:20261201T170000Z\r\n",
        "LOCATION:Zoom\r\n",
        "ORGANIZER;CN=Alice:mailto:alice@example.com\r\n",
        "ATTENDEE;CN=Bob:mailto:bob@example.com\r\n",
        "STATUS:CONFIRMED\r\n",
        "DESCRIPTION:Review attachment extraction.\r\n",
        "END:VEVENT\r\n",
        "END:VCALENDAR\r\n"
    )
    .as_bytes()
    .to_vec();

    let csv_payload = b"item,qty,amount\nServer,1,1200.00\nSupport,1,300.00\n".to_vec();
    let pdf_payload =
        b"%PDF-1.4\n1 0 obj << /Length 28 >>\nstream\nBT /F1 12 Tf (Hello PDF) Tj ET\nendstream\nendobj\n%%EOF"
            .to_vec();
    let scanned_pdf_payload =
        b"%PDF-1.4\n1 0 obj << /Subtype /Image >>\nstream\n\xFF\xD8\xFF\nendstream\nendobj\n%%EOF"
            .to_vec();
    let png_payload = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    store
        .insert_message(NewMessageInput {
            id: Some("msg_atts_1".to_string()),
            thread_id: Some("thr_atts_1".to_string()),
            label_ids: vec![LABEL_INBOX.to_string()],
            raw_rfc2822: Vec::new(),
            snippet: "See attached invite, invoice, and logo.".to_string(),
            internal_date_ms: 1_730_000_100_000,
            subject: "Meeting & Invoice Attachments".to_string(),
            from_addr: "ops@example.com".to_string(),
            to_addrs: vec!["agent@example.com".to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: "See attached invite, invoice, and logo.".to_string(),
            html_body: None,
            rfc822_message_id: Some("<atts-1@example.com>".to_string()),
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "resend_inbound".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: vec![
                NewAttachmentInput {
                    part_id: "1".to_string(),
                    filename: Some("invite.ics".to_string()),
                    content_type: "text/calendar".to_string(),
                    content_id: None,
                    data: ics_payload,
                },
                NewAttachmentInput {
                    part_id: "2".to_string(),
                    filename: Some("invoice.csv".to_string()),
                    content_type: "text/csv".to_string(),
                    content_id: None,
                    data: csv_payload,
                },
                NewAttachmentInput {
                    part_id: "3".to_string(),
                    filename: Some("receipt.pdf".to_string()),
                    content_type: "application/pdf".to_string(),
                    content_id: None,
                    data: pdf_payload,
                },
                NewAttachmentInput {
                    part_id: "4".to_string(),
                    filename: Some("scan.pdf".to_string()),
                    content_type: "application/pdf".to_string(),
                    content_id: None,
                    data: scanned_pdf_payload,
                },
                NewAttachmentInput {
                    part_id: "5".to_string(),
                    filename: Some("logo.png".to_string()),
                    content_type: "image/png".to_string(),
                    content_id: None,
                    data: png_payload,
                },
            ],
        })
        .await
        .unwrap();

    // 1. Default GET /v1/messages/msg_atts_1 omits attachments_text for backward compatibility
    let (status, msg_default) = get_json(&app, "/v1/messages/msg_atts_1").await;
    assert_eq!(status, StatusCode::OK);
    assert!(msg_default.get("attachments_text").is_none());
    let metas = msg_default["attachments_meta"].as_array().unwrap();
    assert_eq!(metas.len(), 5);

    let att_id = |name: &str| -> String {
        metas
            .iter()
            .find(|m| m["filename"].as_str() == Some(name))
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    };

    let ics_id = att_id("invite.ics");
    let csv_id = att_id("invoice.csv");
    let pdf_id = att_id("receipt.pdf");
    let scan_id = att_id("scan.pdf");
    let png_id = att_id("logo.png");

    // 2. GET /v1/messages/{id}?extract_attachment_text=true populates attachments_text
    let (status, msg_extracted) =
        get_json(&app, "/v1/messages/msg_atts_1?extract_attachment_text=true").await;
    assert_eq!(status, StatusCode::OK);
    let att_texts = msg_extracted["attachments_text"].as_array().unwrap();
    assert_eq!(att_texts.len(), 5);

    // 3. GET /v1/messages/{id}/attachments/{ics_id}/text returns parsed VEVENT + sanitized text
    let (status, ics_json) = get_json(
        &app,
        &format!("/v1/messages/msg_atts_1/attachments/{ics_id}/text"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ics_json["extracted"], true);
    assert_eq!(ics_json["format"], "calendar");
    assert_eq!(ics_json["_meta"]["untrusted_external_content"], true);
    assert_eq!(ics_json["structured"]["summary"], "Architecture Review");
    assert_eq!(
        ics_json["structured"]["organizer"],
        "Alice <alice@example.com>"
    );
    assert_eq!(
        ics_json["structured"]["attendees"],
        json!(["Bob <bob@example.com>"])
    );
    assert_eq!(ics_json["structured"]["dtstart"], "20261201T160000Z");
    assert!(!ics_json["text"].as_str().unwrap().contains('\u{202E}'));

    // 4. GET /v1/messages/{id}/attachments/{csv_id}/text?max_chars=18 enforces truncation
    let (status, csv_json) = get_json(
        &app,
        &format!("/v1/messages/msg_atts_1/attachments/{csv_id}/text?max_chars=18"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(csv_json["extracted"], true);
    assert_eq!(csv_json["truncated"], true);
    assert_eq!(csv_json["text"].as_str().unwrap().chars().count(), 18);
    assert!(csv_json["total_chars"].as_u64().unwrap() > 18);

    // 5. PDF extraction via REST
    let (status, pdf_json) = get_json(
        &app,
        &format!("/v1/messages/msg_atts_1/attachments/{pdf_id}/text"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(pdf_json["extracted"], true);
    assert_eq!(pdf_json["format"], "pdf");
    assert_eq!(pdf_json["text"], "Hello PDF");

    // 6. Scanned PDF and binary PNG return extracted=false with clean reasons (HTTP 200, not error)
    let (status, scan_json) = get_json(
        &app,
        &format!("/v1/messages/msg_atts_1/attachments/{scan_id}/text"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(scan_json["extracted"], false);
    assert_eq!(
        scan_json["reason"],
        "binary or scanned PDF without text stream"
    );

    let (status, png_json) = get_json(
        &app,
        &format!("/v1/messages/msg_atts_1/attachments/{png_id}/text"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(png_json["extracted"], false);
    assert_eq!(png_json["content_type"], "image/png");
    assert_eq!(png_json["reason"], "unsupported binary attachment type");

    // 7. MCP `read_attachment_text` enforces max_chars and untrusted_content_guard
    let (status, mcp_att) = mcp_call(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "read_attachment_text",
                "arguments": {
                    "message_id": "msg_atts_1",
                    "attachment_id": csv_id,
                    "max_chars": 12
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mcp_att["result"]["isError"], false);
    let sc = &mcp_att["result"]["structuredContent"];
    assert_eq!(sc["extracted"], true);
    assert_eq!(sc["truncated"], true);
    assert_eq!(sc["text"].as_str().unwrap().chars().count(), 12);
    assert_eq!(sc["_meta"]["untrusted_external_content"], true);

    // 8. MCP `read_email` with extract_attachment_text=true
    let (status, mcp_email) = mcp_call(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "read_email",
                "arguments": {
                    "message_id": "msg_atts_1",
                    "extract_attachment_text": true,
                    "attachment_max_chars": 50
                }
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(mcp_email["result"]["isError"], false);
    let email_atts = mcp_email["result"]["structuredContent"]["attachments_text"]
        .as_array()
        .unwrap();
    assert_eq!(email_atts.len(), 5);
}

#[tokio::test]
async fn attachment_extraction_respects_size_ceiling_and_guard_disabled_mode() {
    let mut cfg = Config::for_test();
    cfg.untrusted_content_guard = false;
    let (_state, store, app) = build_test_app(cfg);

    let oversize_bytes = vec![b'X'; DEFAULT_ATTACHMENT_MAX_BYTES + 16];
    let dirty_txt = "Raw\u{202E}Text".as_bytes().to_vec();

    store
        .insert_message(NewMessageInput {
            id: Some("msg_limits_1".to_string()),
            thread_id: Some("thr_limits_1".to_string()),
            label_ids: vec![LABEL_INBOX.to_string()],
            raw_rfc2822: Vec::new(),
            snippet: "limits test".to_string(),
            internal_date_ms: 1_730_000_200_000,
            subject: "Limits".to_string(),
            from_addr: "ops@example.com".to_string(),
            to_addrs: vec!["agent@example.com".to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: "limits test".to_string(),
            html_body: None,
            rfc822_message_id: None,
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "local".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: vec![
                NewAttachmentInput {
                    part_id: "1".to_string(),
                    filename: Some("huge.txt".to_string()),
                    content_type: "text/plain".to_string(),
                    content_id: None,
                    data: oversize_bytes,
                },
                NewAttachmentInput {
                    part_id: "2".to_string(),
                    filename: Some("raw.txt".to_string()),
                    content_type: "text/plain".to_string(),
                    content_id: None,
                    data: dirty_txt,
                },
            ],
        })
        .await
        .unwrap();

    let (_, msg) = get_json(&app, "/v1/messages/msg_limits_1").await;
    let metas = msg["attachments_meta"].as_array().unwrap();
    let huge_id = metas.iter().find(|m| m["filename"] == "huge.txt").unwrap()["id"]
        .as_str()
        .unwrap();
    let raw_id = metas.iter().find(|m| m["filename"] == "raw.txt").unwrap()["id"]
        .as_str()
        .unwrap();

    // Oversize returns extracted=false cleanly without dumping 5 MiB into JSON
    let (status, huge_json) = get_json(
        &app,
        &format!("/v1/messages/msg_limits_1/attachments/{huge_id}/text"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(huge_json["extracted"], false);
    assert!(
        huge_json["reason"]
            .as_str()
            .unwrap()
            .contains("exceeds maximum")
    );
    assert!(huge_json.get("_meta").is_none());

    // Guard disabled preserves raw text and omits `_meta`
    let (status, raw_json) = get_json(
        &app,
        &format!("/v1/messages/msg_limits_1/attachments/{raw_id}/text"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(raw_json["extracted"], true);
    assert_eq!(raw_json["text"], "Raw\u{202E}Text");
    assert!(raw_json.get("_meta").is_none());
}
