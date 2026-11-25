//! End-to-end integration tests for hybrid keyword + vector `SearchIndex`:
//! - `OpenAiEmbeddingProvider` against `wiremock` (`POST /embeddings`)
//! - Semantic retrieval with zero lexical keyword overlap via `GET /v1/search` and MCP `search_emails`
//! - Structured filters (`labels`, `unread`, `from`, `to`, `after`, `before`, `has_attachment`) & cursor pagination
//! - Fail-open ingestion and lexical fallback when the embedding endpoint errors
//! - `GET /v1/capabilities` reporting `"hybrid"` vs default store search backend
//! - `nogml search reindex` CLI backfill against persisted SQLite `message_embeddings`

use std::process::Command;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chrono::{TimeZone, Utc};
use http_body_util::BodyExt;
use nogml::{
    AppState, build_router,
    config::{Config, SearchBackend, StorageBackend},
    mcp::McpServer,
    models::{LABEL_INBOX, LABEL_UNREAD},
    storage::{MailStore, NewAttachmentInput, NewMessageInput, SqliteStore},
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, Request as WireRequest, Respond, ResponseTemplate,
    matchers::{header, method, path},
};

/// Deterministic topic-based mock embeddings responder for OpenAI `/embeddings`.
///
/// Maps conceptually related terms with zero lexical overlap onto matching unit directions:
/// - Axis 0 (infrastructure incidents): "outage", "downtime", "degraded", "cluster", "latency"
/// - Axis 1 (billing & finance): "invoice", "receipt", "billing", "payment", "reimbursement"
/// - Axis 2 (travel & itinerary): "flight", "boarding", "airline", "hotel", "itinerary"
#[derive(Clone)]
struct TopicEmbeddingsResponder {
    expected_api_key: Option<String>,
}

impl TopicEmbeddingsResponder {
    fn embed_text(text: &str) -> Vec<f32> {
        let lower = text.to_ascii_lowercase();
        let mut v = [0.0_f32; 3];
        if [
            "outage", "downtime", "degraded", "cluster", "latency", "offline",
        ]
        .iter()
        .any(|kw| lower.contains(kw))
        {
            v[0] = 1.0;
        }
        if [
            "invoice",
            "receipt",
            "billing",
            "payment",
            "reimbursement",
            "expenses",
        ]
        .iter()
        .any(|kw| lower.contains(kw))
        {
            v[1] = 1.0;
        }
        if [
            "flight",
            "boarding",
            "airline",
            "hotel",
            "itinerary",
            "departure",
        ]
        .iter()
        .any(|kw| lower.contains(kw))
        {
            v[2] = 1.0;
        }
        if v.iter().all(|&x| x == 0.0) {
            // Orthogonal small fallback direction so unrecognized inputs don't produce a zero vector
            return vec![0.0, 0.0, 0.0, 1.0];
        }
        vec![v[0], v[1], v[2], 0.0]
    }
}

impl Respond for TopicEmbeddingsResponder {
    fn respond(&self, request: &WireRequest) -> ResponseTemplate {
        if let Some(expected) = &self.expected_api_key {
            let auth = request
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok());
            if auth != Some(&format!("Bearer {expected}")) {
                return ResponseTemplate::new(401).set_body_string("missing or wrong bearer key");
            }
        }

        let body: Value = match serde_json::from_slice(&request.body) {
            Ok(v) => v,
            Err(err) => {
                return ResponseTemplate::new(400).set_body_string(format!("invalid json: {err}"));
            }
        };

        let inputs: Vec<String> = match body.get("input") {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            Some(Value::String(s)) => vec![s.clone()],
            _ => {
                return ResponseTemplate::new(400).set_body_string("missing input");
            }
        };

        // Intentionally return items in reverse order to verify index-based sorting.
        let mut data: Vec<Value> = inputs
            .iter()
            .enumerate()
            .map(|(idx, text)| {
                json!({
                    "object": "embedding",
                    "index": idx,
                    "embedding": Self::embed_text(text),
                })
            })
            .collect();
        data.reverse();

        ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "model": body.get("model").and_then(Value::as_str).unwrap_or("text-embedding-3-small"),
            "data": data,
        }))
    }
}

#[allow(clippy::too_many_arguments)]
fn make_message(
    id: &str,
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
    labels: Vec<&str>,
    internal_date_ms: i64,
    has_attachment: bool,
) -> NewMessageInput {
    let attachments = if has_attachment {
        vec![NewAttachmentInput {
            part_id: "1".to_string(),
            filename: Some("report.pdf".to_string()),
            content_type: "application/pdf".to_string(),
            content_id: None,
            data: b"%PDF-1.4\n".to_vec(),
        }]
    } else {
        Vec::new()
    };

    NewMessageInput {
        id: Some(id.to_string()),
        thread_id: None,
        label_ids: labels.into_iter().map(str::to_string).collect(),
        raw_rfc2822: format!("From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\n\r\n{body}")
            .into_bytes(),
        snippet: body.to_string(),
        internal_date_ms,
        subject: subject.to_string(),
        from_addr: from.to_string(),
        to_addrs: vec![to.to_string()],
        cc_addrs: vec![],
        bcc_addrs: vec![],
        text_body: body.to_string(),
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
        attachments,
    }
}

#[tokio::test]
async fn hybrid_search_semantic_retrieval_filters_and_capabilities_e2e() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(TopicEmbeddingsResponder {
            expected_api_key: Some("sk-embed-test".to_string()),
        })
        .mount(&mock)
        .await;

    // 1. Default Store backend requires zero external API keys.
    let default_cfg = Config::for_test();
    let default_state = AppState::from_config(default_cfg).unwrap();
    let default_app = build_router(default_state);
    let res = default_app
        .oneshot(
            Request::builder()
                .uri("/v1/capabilities")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let default_caps: Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(default_caps["backends"]["search"], "memory");

    // 2. Hybrid backend wired via Config -> AppState::from_config reports "hybrid".
    let mut cfg = Config::for_test();
    cfg.search_backend = SearchBackend::Hybrid;
    cfg.embedding_base_url = Some(format!("{}/v1", mock.uri()));
    cfg.embedding_api_key = Some("sk-embed-test".to_string());
    cfg.embedding_model = "text-embedding-3-small".to_string();

    let state = AppState::from_config(cfg).unwrap();
    let app = build_router(state.clone());

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/capabilities")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let caps: Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(caps["backends"]["search"], "hybrid");

    // Seed messages with completely distinct vocabulary from the semantic queries we will run.
    let ts_jan = Utc
        .with_ymd_and_hms(2026, 1, 10, 12, 0, 0)
        .unwrap()
        .timestamp_millis();
    let ts_feb = Utc
        .with_ymd_and_hms(2026, 2, 15, 12, 0, 0)
        .unwrap()
        .timestamp_millis();
    let ts_mar = Utc
        .with_ymd_and_hms(2026, 3, 20, 12, 0, 0)
        .unwrap()
        .timestamp_millis();

    let msg_outage_unread = state
        .store
        .insert_message(make_message(
            "m_outage_unread",
            "ops@infra.test",
            "agent@example.com",
            "Primary cluster degraded",
            "Elevated API latency observed across eu-west nodes.",
            vec![LABEL_INBOX, LABEL_UNREAD, "OPS"],
            ts_feb,
            true,
        ))
        .await
        .unwrap();
    state.post_store_message(&msg_outage_unread).await.unwrap();

    let msg_outage_read = state
        .store
        .insert_message(make_message(
            "m_outage_read",
            "oncall@infra.test",
            "agent@example.com",
            "Cluster offline postmortem",
            "Historical root cause analysis from January.",
            vec![LABEL_INBOX, "OPS"],
            ts_jan,
            false,
        ))
        .await
        .unwrap();
    state.post_store_message(&msg_outage_read).await.unwrap();

    let msg_billing = state
        .store
        .insert_message(make_message(
            "m_billing",
            "finance@vendor.test",
            "agent@example.com",
            "March invoice #99",
            "Attached billing statement for cloud usage.",
            vec![LABEL_INBOX, LABEL_UNREAD, "FINANCE"],
            ts_mar,
            true,
        ))
        .await
        .unwrap();
    state.post_store_message(&msg_billing).await.unwrap();

    let msg_travel = state
        .store
        .insert_message(make_message(
            "m_travel",
            "desk@airline.test",
            "agent@example.com",
            "Boarding pass ready",
            "Your departure gate is B12.",
            vec![LABEL_INBOX, LABEL_UNREAD, "TRAVEL"],
            ts_mar,
            false,
        ))
        .await
        .unwrap();
    state.post_store_message(&msg_travel).await.unwrap();

    // 3. Semantic query via GET /v1/search with ZERO lexical overlap:
    //    Query "downtime" does not appear in any message subject or body,
    //    yet matches both infrastructure messages semantically.
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/search?q=downtime")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let ids: Vec<&str> = body["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["m_outage_unread", "m_outage_read"]);

    // 4. Semantic query respecting `unread=true` structured filter via GET /v1/search
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/search?q=downtime&unread=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let ids: Vec<&str> = body["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["m_outage_unread"]);

    // 5. Semantic query respecting `unread=false` + `has_attachment=false` + `before=` date bound
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/search?q=downtime&unread=false&has_attachment=false&before=2026-02-01T00:00:00Z")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let ids: Vec<&str> = body["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["m_outage_read"]);

    // 6. Semantic query with label mismatch excludes non-matching messages
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/search?q=downtime&labels=FINANCE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(body["messages"].as_array().unwrap().is_empty());

    // 7. Semantic query via MCP `search_emails` with ZERO lexical overlap + structured filters
    //    Query "reimbursement" does not appear in "March invoice #99", yet matches `m_billing`.
    let mcp = McpServer::new(state.clone());
    let mcp_res = mcp
        .handle_request(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "search_emails",
                "arguments": {
                    "query": "reimbursement",
                    "labels": ["FINANCE"],
                    "unread": true
                }
            }
        }))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mcp_res["result"]["isError"], false);
    let mcp_msgs = mcp_res["result"]["structuredContent"]["messages"]
        .as_array()
        .unwrap();
    assert_eq!(mcp_msgs.len(), 1);
    assert_eq!(mcp_msgs[0]["id"], "m_billing");

    // MCP semantic query with unread=false returns 0 for unread-only billing email
    let mcp_res_read = mcp
        .handle_request(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "search_emails",
                "arguments": {
                    "query": "reimbursement",
                    "unread": false
                }
            }
        }))
        .await
        .unwrap()
        .unwrap();
    assert!(
        mcp_res_read["result"]["structuredContent"]["messages"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // 8. Cursor pagination across semantic results (`limit=1` -> page 1 + page 2)
    let page1_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/search?q=downtime&limit=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page1_res.status(), StatusCode::OK);
    let page1: Value =
        serde_json::from_slice(&page1_res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(page1["messages"].as_array().unwrap().len(), 1);
    assert_eq!(page1["has_more"], true);
    let next_cursor = page1["next_cursor"].as_str().unwrap();

    let page2_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/search?q=downtime&limit=1&cursor={next_cursor}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page2_res.status(), StatusCode::OK);
    let page2: Value =
        serde_json::from_slice(&page2_res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(page2["messages"].as_array().unwrap().len(), 1);
    assert_eq!(page2["has_more"], false);
    assert_ne!(page1["messages"][0]["id"], page2["messages"][0]["id"]);
}

#[tokio::test]
async fn hybrid_search_fails_open_on_ingest_and_falls_back_to_lexical_on_http_500() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/embeddings"))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream outage"))
        .mount(&mock)
        .await;

    let mut cfg = Config::for_test();
    cfg.search_backend = SearchBackend::Hybrid;
    cfg.embedding_base_url = Some(mock.uri());
    cfg.embedding_model = "nomic-embed-text".to_string();

    let state = AppState::from_config(cfg).unwrap();
    let msg = state
        .store
        .insert_message(make_message(
            "m_fallback",
            "alice@example.com",
            "agent@example.com",
            "Kubernetes rollout checklist",
            "Verify canary pods before promoting.",
            vec![LABEL_INBOX, LABEL_UNREAD],
            1_700_000_000_000,
            false,
        ))
        .await
        .unwrap();

    // Ingestion must succeed even when the embedding server returns HTTP 500.
    state.post_store_message(&msg).await.unwrap();

    // Search must fall back cleanly to lexical matching on HTTP 500.
    let app = build_router(state);
    let res = app
        .oneshot(
            Request::builder()
                .uri("/v1/search?q=canary")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["messages"].as_array().unwrap().len(), 1);
    assert_eq!(body["messages"][0]["id"], "m_fallback");
}

#[tokio::test]
async fn cli_search_reindex_backfills_sqlite_embeddings_and_enables_semantic_search() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("mailbox.db");

    // Pre-populate SQLite mailbox BEFORE enabling hybrid search (no embeddings exist yet).
    {
        let store = SqliteStore::open(&db_path, "agent@example.com").unwrap();
        store
            .insert_message(make_message(
                "m_sql_1",
                "ops@infra.test",
                "agent@example.com",
                "Database cluster degraded",
                "Write latency spiked in primary region.",
                vec![LABEL_INBOX, LABEL_UNREAD],
                1_700_000_010_000,
                false,
            ))
            .await
            .unwrap();
        store
            .insert_message(make_message(
                "m_sql_2",
                "travel@airline.test",
                "agent@example.com",
                "Flight departure update",
                "Your boarding group is 2.",
                vec![LABEL_INBOX],
                1_700_000_020_000,
                false,
            ))
            .await
            .unwrap();
    }

    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .and(header("content-type", "application/json"))
        .respond_with(TopicEmbeddingsResponder {
            expected_api_key: None,
        })
        .mount(&mock)
        .await;

    // Run `nogml search reindex` CLI against the SQLite DB with Ollama-style no-key endpoint.
    let bin = env!("CARGO_BIN_EXE_nogml");
    let output = Command::new(bin)
        .args([
            "search",
            "reindex",
            "--storage",
            "sqlite",
            "--db-path",
            db_path.to_str().unwrap(),
            "--search-backend",
            "hybrid",
        ])
        .env("NOGML_EMBEDDING_BASE_URL", format!("{}/v1", mock.uri()))
        .env("NOGML_EMBEDDING_MODEL", "nomic-embed-text")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "CLI search reindex failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["backend"], "hybrid");
    assert_eq!(report["indexed"], 2);
    assert_eq!(report["failed"], 0);

    // Now open a fresh AppState pointing at the same SQLite DB and verify semantic search works immediately!
    let mut cfg = Config {
        storage: StorageBackend::Sqlite,
        db_path: db_path.clone(),
        user_email: "agent@example.com".to_string(),
        search_backend: SearchBackend::Hybrid,
        embedding_base_url: Some(format!("{}/v1", mock.uri())),
        embedding_model: "nomic-embed-text".to_string(),
        ..Config::default()
    };
    cfg.embedding_api_key = None;

    let state = AppState::from_config(cfg).unwrap();
    let app = build_router(state);

    // Semantic query "itinerary" has zero lexical overlap with "Flight departure update".
    let res = app
        .oneshot(
            Request::builder()
                .uri("/v1/search?q=itinerary")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let ids: Vec<&str> = body["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["m_sql_2"]);

    // Verify `nogml search reindex` reports failed count when embedding server errors.
    let failing_mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
        .mount(&failing_mock)
        .await;

    let fail_output = Command::new(bin)
        .args([
            "search",
            "reindex",
            "--storage",
            "sqlite",
            "--db-path",
            db_path.to_str().unwrap(),
            "--search-backend",
            "hybrid",
        ])
        .env(
            "NOGML_EMBEDDING_BASE_URL",
            format!("{}/v1", failing_mock.uri()),
        )
        .env("NOGML_EMBEDDING_MODEL", "nomic-embed-text")
        .output()
        .unwrap();

    assert!(fail_output.status.success());
    let fail_report: Value = serde_json::from_slice(&fail_output.stdout).unwrap();
    assert_eq!(fail_report["indexed"], 0);
    assert_eq!(fail_report["failed"], 2);
}
