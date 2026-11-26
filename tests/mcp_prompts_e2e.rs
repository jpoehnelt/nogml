//! End-to-end tests for built-in MCP prompts (`prompts/list`, `prompts/get`) over
//! Streamable HTTP (`POST /mcp`) and the real `nogml mcp` stdio binary.

use std::{process::Stdio, sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::{io::AsyncWriteExt, process::Command};
use tower::ServiceExt;

use nogml::{
    AppState, build_router, config::Config, resend::HttpResendClient, storage::MemoryStore,
};

const PROMPT_NAMES: [&str; 4] = [
    "triage_inbox",
    "daily_briefing",
    "draft_reply",
    "find_followups",
];

fn http_app() -> Router {
    let config = Config::for_test();
    let store = Arc::new(MemoryStore::new(&config.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&config));
    build_router(AppState::with_backends(config, store, resend))
}

async fn http_rpc(app: &Router, id: u64, method: &str, params: Value) -> Value {
    let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "{method} over HTTP");
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Spawn `nogml mcp`, send each request as one stdio frame, and return the responses in order.
async fn stdio_rpc(requests: Vec<Value>) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nogml"))
        .args([
            "--storage",
            "memory",
            "--user-email",
            "prompts-bot@example.com",
            "mcp",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn nogml mcp");

    {
        let mut stdin = child.stdin.take().expect("stdin");
        for req in &requests {
            let line = format!("{}\n", serde_json::to_string(req).unwrap());
            stdin.write_all(line.as_bytes()).await.unwrap();
        }
        stdin.flush().await.unwrap();
    }

    let output = tokio::time::timeout(Duration::from_secs(15), child.wait_with_output())
        .await
        .expect("nogml mcp timed out")
        .expect("nogml mcp wait");
    assert!(
        output.status.success(),
        "nogml mcp failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad frame '{l}': {e}")))
        .collect()
}

fn assert_prompt_catalog(result: &Value) {
    let prompts = result["prompts"].as_array().expect("prompts array");
    let names: Vec<&str> = prompts
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, PROMPT_NAMES);

    let args_of = |name: &str| -> Vec<(String, bool)> {
        let p = prompts.iter().find(|p| p["name"] == name).unwrap();
        assert!(!p["description"].as_str().unwrap().is_empty());
        p["arguments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                assert!(!a["description"].as_str().unwrap().is_empty());
                (
                    a["name"].as_str().unwrap().to_string(),
                    a["required"].as_bool().unwrap(),
                )
            })
            .collect()
    };
    let arg = |n: &str, r: bool| (n.to_string(), r);
    assert_eq!(args_of("triage_inbox"), vec![arg("limit", false)]);
    assert_eq!(
        args_of("daily_briefing"),
        vec![arg("since", false), arg("followup_days", false)]
    );
    assert_eq!(
        args_of("draft_reply"),
        vec![arg("thread_id", true), arg("intent", false)]
    );
    assert_eq!(args_of("find_followups"), vec![arg("days", false)]);
}

fn prompt_text(result: &Value) -> &str {
    let messages = result["messages"].as_array().expect("messages");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["role"], "user");
    assert_eq!(messages[0]["content"]["type"], "text");
    assert!(!result["description"].as_str().unwrap().is_empty());
    messages[0]["content"]["text"].as_str().unwrap()
}

fn assert_prompt_texts(texts: &[(&str, String)]) {
    for (name, text) in texts {
        let required: &[&str] = match *name {
            "triage_inbox" => &[
                "list_threads",
                "lookup_contact",
                "batch_triage",
                "dry_run: true",
                "confirm",
            ],
            "daily_briefing" => &[
                "get_briefing",
                "VIP",
                "waiting_on: me",
                "snooze",
                "approvals",
            ],
            "draft_reply" => &[
                "thread-xyz-123",
                "get_reply_context",
                "style_samples",
                "create_draft",
                "dry_run: true",
                "untrusted",
                "accept and propose Tuesday",
            ],
            "find_followups" => &["get_briefing", "search_emails", "create_draft", "7 days"],
            other => panic!("unexpected prompt {other}"),
        };
        for needle in required {
            assert!(
                text.contains(needle),
                "{name} prompt missing {needle:?}: {text}"
            );
        }
    }
}

fn get_params(name: &str) -> Value {
    match name {
        "triage_inbox" => json!({ "name": name, "arguments": { "limit": "10" } }),
        "daily_briefing" => {
            json!({ "name": name, "arguments": { "since": "2025-01-01T00:00:00Z", "followup_days": "5" } })
        }
        "draft_reply" => json!({
            "name": name,
            "arguments": { "thread_id": "thread-xyz-123", "intent": "accept and propose Tuesday" }
        }),
        "find_followups" => json!({ "name": name, "arguments": { "days": 7 } }),
        other => panic!("unexpected prompt {other}"),
    }
}

#[tokio::test]
async fn http_initialize_advertises_prompts_and_serves_prompts() {
    let app = http_app();

    let init = http_rpc(
        &app,
        1,
        "initialize",
        json!({ "protocolVersion": "2025-03-26" }),
    )
    .await;
    assert!(init["result"]["capabilities"]["prompts"].is_object());
    assert!(init["result"]["capabilities"]["tools"].is_object());
    assert!(init["result"]["capabilities"]["resources"].is_object());

    let list = http_rpc(&app, 2, "prompts/list", json!({})).await;
    assert_prompt_catalog(&list["result"]);

    let mut texts = Vec::new();
    for (i, name) in PROMPT_NAMES.iter().enumerate() {
        let got = http_rpc(&app, 10 + i as u64, "prompts/get", get_params(name)).await;
        texts.push((*name, prompt_text(&got["result"]).to_string()));
    }
    assert_prompt_texts(&texts);

    // Defaults apply when optional arguments are omitted.
    let got = http_rpc(&app, 20, "prompts/get", json!({ "name": "find_followups" })).await;
    assert!(prompt_text(&got["result"]).contains("3 days"));
    let got = http_rpc(&app, 21, "prompts/get", json!({ "name": "triage_inbox" })).await;
    assert!(prompt_text(&got["result"]).contains("limit 25"));

    // Invalid params.
    for params in [
        json!({ "name": "draft_reply" }),
        json!({ "name": "draft_reply", "arguments": {} }),
        json!({ "name": "draft_reply", "arguments": { "thread_id": "  " } }),
        json!({ "name": "no_such_prompt" }),
        json!({ "name": "find_followups", "arguments": { "days": "soon" } }),
        json!({}),
    ] {
        let resp = http_rpc(&app, 30, "prompts/get", params.clone()).await;
        assert_eq!(resp["error"]["code"], -32602, "params {params}: {resp}");
        assert!(resp.get("result").is_none());
    }
}

#[tokio::test]
async fn stdio_binary_initialize_advertises_prompts_and_serves_prompts() {
    let mut requests = vec![
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-03-26" } }),
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "prompts/list" }),
    ];
    for (i, name) in PROMPT_NAMES.iter().enumerate() {
        requests.push(json!({
            "jsonrpc": "2.0", "id": 10 + i, "method": "prompts/get", "params": get_params(name)
        }));
    }
    requests.push(json!({
        "jsonrpc": "2.0", "id": 30, "method": "prompts/get", "params": { "name": "draft_reply" }
    }));
    requests.push(json!({
        "jsonrpc": "2.0", "id": 31, "method": "prompts/get", "params": { "name": "bogus" }
    }));

    let frames = stdio_rpc(requests).await;
    assert_eq!(frames.len(), 8, "{frames:?}");

    assert!(frames[0]["result"]["capabilities"]["prompts"].is_object());
    assert_prompt_catalog(&frames[1]["result"]);

    let texts: Vec<(&str, String)> = PROMPT_NAMES
        .iter()
        .enumerate()
        .map(|(i, name)| (*name, prompt_text(&frames[2 + i]["result"]).to_string()))
        .collect();
    assert_prompt_texts(&texts);

    assert_eq!(frames[6]["id"], 30);
    assert_eq!(frames[6]["error"]["code"], -32602);
    assert_eq!(frames[7]["id"], 31);
    assert_eq!(frames[7]["error"]["code"], -32602);
}
