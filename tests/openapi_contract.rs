//! Live response-vs-OpenAPI 3.1.0 contract tests for `/v1/*` endpoints.

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use nogml::{
    AppState, build_router,
    config::{Config, StorageBackend},
    models::{LABEL_INBOX, LABEL_UNREAD},
    storage::{DeliverabilityEventKind, NewDeliverabilityEvent, NewMessageInput, NewScheduledSend},
    transport::OutboundMessage,
};
use serde_json::{Value, json};
use tower::ServiceExt;

async fn http_call(
    app: &axum::Router,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = if let Some(b) = body {
        builder
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&b).unwrap()))
            .unwrap()
    } else {
        builder.body(Body::empty()).unwrap()
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("invalid JSON from {uri} ({status}): {e}"));
    (status, parsed)
}

fn resolve_schema<'a>(spec: &'a Value, schema: &'a Value) -> &'a Value {
    if let Some(r) = schema.get("$ref").and_then(Value::as_str) {
        let name = r
            .strip_prefix("#/components/schemas/")
            .unwrap_or_else(|| panic!("unexpected schema $ref: {r}"));
        let target = &spec["components"]["schemas"][name];
        assert!(!target.is_null(), "unresolved $ref: {r}");
        return resolve_schema(spec, target);
    }
    schema
}

fn type_matches(val: &Value, expected_type: &str) -> bool {
    match expected_type {
        "object" => val.is_object(),
        "array" => val.is_array(),
        "string" => val.is_string(),
        "boolean" => val.is_boolean(),
        "null" => val.is_null(),
        "integer" => val.as_i64().is_some() || val.as_u64().is_some(),
        "number" => val.is_number(),
        other => panic!("unsupported JSON schema type: {other}"),
    }
}

fn validate_value_against_schema(
    spec: &Value,
    schema: &Value,
    value: &Value,
    path: &str,
) -> Result<(), String> {
    let resolved = resolve_schema(spec, schema);

    if let Some(variants) = resolved.get("oneOf").and_then(Value::as_array) {
        let mut errs = Vec::new();
        for variant in variants {
            match validate_value_against_schema(spec, variant, value, path) {
                Ok(()) => return Ok(()),
                Err(e) => errs.push(e),
            }
        }
        return Err(format!(
            "{path}: value {value} matched none of oneOf variants: {}",
            errs.join(" | ")
        ));
    }

    if let Some(ty) = resolved.get("type") {
        let ok = match ty {
            Value::String(t) => type_matches(value, t),
            Value::Array(ts) => ts
                .iter()
                .filter_map(Value::as_str)
                .any(|t| type_matches(value, t)),
            _ => true,
        };
        if !ok {
            return Err(format!("{path}: expected type {ty}, got value {value}"));
        }
    }

    if let Some(enum_vals) = resolved.get("enum").and_then(Value::as_array)
        && !enum_vals.iter().any(|allowed| allowed == value)
    {
        return Err(format!("{path}: value {value} not in enum {enum_vals:?}"));
    }

    match value {
        Value::Object(obj) => {
            if let Some(required) = resolved.get("required").and_then(Value::as_array) {
                for req_key in required.iter().filter_map(Value::as_str) {
                    if !obj.contains_key(req_key) {
                        return Err(format!(
                            "{path}: missing required property '{req_key}' in {value}"
                        ));
                    }
                }
            }
            if let Some(props) = resolved.get("properties").and_then(Value::as_object) {
                for (k, v) in obj {
                    let Some(prop_schema) = props.get(k) else {
                        return Err(format!(
                            "{path}.{k}: undocumented property not declared in OpenAPI schema"
                        ));
                    };
                    validate_value_against_schema(spec, prop_schema, v, &format!("{path}.{k}"))?;
                }
            }
        }
        Value::Array(items) => {
            if let Some(item_schema) = resolved.get("items") {
                for (idx, item) in items.iter().enumerate() {
                    validate_value_against_schema(
                        spec,
                        item_schema,
                        item,
                        &format!("{path}[{idx}]"),
                    )?;
                }
            }
        }
        _ => {}
    }

    Ok(())
}

fn response_schema<'a>(spec: &'a Value, path: &str, method: &str, status: StatusCode) -> &'a Value {
    let code = status.as_u16().to_string();
    let schema =
        &spec["paths"][path][method]["responses"][&code]["content"]["application/json"]["schema"];
    assert!(
        !schema.is_null(),
        "missing OpenAPI response schema for {method} {path} ({code})"
    );
    schema
}

#[tokio::test]
async fn live_v1_responses_conform_to_openapi_3_1_schemas() {
    let mut cfg = Config::for_test();
    cfg.storage = StorageBackend::Memory;
    cfg.user_email = "agent@example.com".to_string();
    cfg.default_domain = "example.com".to_string();
    cfg.allow_private_endpoints = true;

    let state = AppState::from_config(cfg).unwrap();
    let now_ms = Utc::now().timestamp_millis();

    // Seed an inbound message + thread
    let seeded_msg = state
        .store
        .insert_message(NewMessageInput {
            id: None,
            thread_id: Some("thr_contract_1".to_string()),
            label_ids: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            from_addr: "Alice <alice@partner.example>".to_string(),
            to_addrs: vec!["agent@example.com".to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            subject: "Contract check thread".to_string(),
            snippet: "Hello from Alice".to_string(),
            text_body: "Hello from Alice".to_string(),
            html_body: None,
            raw_rfc2822: b"From: Alice <alice@partner.example>\r\nTo: agent@example.com\r\nSubject: Contract check thread\r\n\r\nHello from Alice".to_vec(),
            rfc822_message_id: Some("<contract-1@partner.example>".to_string()),
            in_reply_to: None,
            references_header: None,
            internal_date_ms: now_ms,
            attachments: vec![],
            upstream_gmail_id: None,
            upstream_thread_id: None,
            resend_id: None,
            source: "api".to_string(),
            is_answered: false,
            is_deleted: false,
        })
        .await
        .unwrap();

    // Seed a due snooze so GET /v1/briefing returns a live SnoozedThread
    state
        .store
        .snooze_thread(&seeded_msg.thread_id, now_ms - 60_000)
        .await
        .unwrap();

    // Seed a scheduled send so GET /v1/scheduled returns a live ScheduledSend
    state
        .store
        .create_scheduled_send(&NewScheduledSend {
            id: None,
            send_at_ms: (Utc::now() + Duration::hours(1)).timestamp_millis(),
            outbound_message: OutboundMessage {
                from: "agent@example.com".to_string(),
                to: vec!["alice@partner.example".to_string()],
                subject: "Scheduled follow-up".to_string(),
                text: Some("Checking in later".to_string()),
                ..Default::default()
            },
            reply_to_message_id: None,
            thread_id: Some(seeded_msg.thread_id.clone()),
            created_at_ms: now_ms,
        })
        .await
        .unwrap();

    // Seed a deliverability event so GET /v1/deliverability/stats returns live DomainDeliverabilityStats
    state
        .store
        .record_deliverability_event(NewDeliverabilityEvent {
            domain: "example.com".to_string(),
            mailbox_id: Some("agent@example.com".to_string()),
            kind: DeliverabilityEventKind::Sent,
            recipient: Some("alice@partner.example".to_string()),
            provider: Some("resend".to_string()),
            detail: None,
            created_at_ms: Some(now_ms),
        })
        .await
        .unwrap();

    let app = build_router(state);
    let mb_hdr = &[("x-nogml-mailbox", "agent@example.com")];

    // Fetch live OpenAPI 3.1.0 spec
    let (status, spec) = http_call(&app, Method::GET, "/v1/openapi.json", mb_hdr, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(spec["openapi"], "3.1.0");

    // 1. GET /v1/capabilities
    let (st, body) = http_call(&app, Method::GET, "/v1/capabilities", mb_hdr, None).await;
    assert_eq!(st, StatusCode::OK);
    validate_value_against_schema(
        &spec,
        response_schema(&spec, "/v1/capabilities", "get", st),
        &body,
        "GET /v1/capabilities",
    )
    .unwrap();

    // 2. GET /v1/scheduled (verifies `scheduled_sends` + `ScheduledSend` schema)
    let (st, body) = http_call(&app, Method::GET, "/v1/scheduled", mb_hdr, None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["count"], 1);
    validate_value_against_schema(
        &spec,
        response_schema(&spec, "/v1/scheduled", "get", st),
        &body,
        "GET /v1/scheduled",
    )
    .unwrap();

    // 3. GET /v1/briefing (verifies `SnoozedThread` with `snooze_until_ms` + `mailbox_id`)
    let (st, body) = http_call(&app, Method::GET, "/v1/briefing", mb_hdr, None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(!body["due_snoozes"].as_array().unwrap().is_empty());
    validate_value_against_schema(
        &spec,
        response_schema(&spec, "/v1/briefing", "get", st),
        &body,
        "GET /v1/briefing",
    )
    .unwrap();

    // 4. POST /v1/rules (with webhook_secret) + GET /v1/rules (verifies InboxRuleView / has_webhook_secret)
    let (st, created_rule) = http_call(
        &app,
        Method::POST,
        "/v1/rules",
        mb_hdr,
        Some(json!({
            "name": "Contract rule",
            "match_query": "from:partner.example",
            "actions": {
                "add_labels": ["STARRED"],
                "webhook_url": "https://hooks.example.com/events",
                "webhook_secret": "super-secret-rule-key"
            }
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(created_rule["actions"]["has_webhook_secret"], true);
    assert!(created_rule["actions"].get("webhook_secret").is_none());
    validate_value_against_schema(
        &spec,
        response_schema(&spec, "/v1/rules", "post", st),
        &created_rule,
        "POST /v1/rules",
    )
    .unwrap();

    let (st, rules_list) = http_call(&app, Method::GET, "/v1/rules", mb_hdr, None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(rules_list["count"], 1);
    validate_value_against_schema(
        &spec,
        response_schema(&spec, "/v1/rules", "get", st),
        &rules_list,
        "GET /v1/rules",
    )
    .unwrap();

    // 5. GET /v1/audit (verifies `AuditLogEntry.id` is string + `mailbox_id`)
    let (st, audit_body) = http_call(&app, Method::GET, "/v1/audit", mb_hdr, None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(audit_body["count"].as_u64().unwrap() >= 1);
    validate_value_against_schema(
        &spec,
        response_schema(&spec, "/v1/audit", "get", st),
        &audit_body,
        "GET /v1/audit",
    )
    .unwrap();

    // 6. POST /v1/drafts with `from` field + GET /v1/drafts
    let draft_req = json!({
        "from": "agent@example.com",
        "to": ["alice@partner.example"],
        "subject": "Draft with explicit from",
        "text": "Hello!"
    });
    validate_value_against_schema(
        &spec,
        &spec["components"]["schemas"]["AiCreateDraftRequest"],
        &draft_req,
        "POST /v1/drafts request",
    )
    .unwrap();
    let (st, _) = http_call(&app, Method::POST, "/v1/drafts", mb_hdr, Some(draft_req)).await;
    assert_eq!(st, StatusCode::OK);
    let (st, drafts_body) = http_call(&app, Method::GET, "/v1/drafts", mb_hdr, None).await;
    assert_eq!(st, StatusCode::OK);
    validate_value_against_schema(
        &spec,
        response_schema(&spec, "/v1/drafts", "get", st),
        &drafts_body,
        "GET /v1/drafts",
    )
    .unwrap();

    // 7. Validate AiSendEmailRequest with `from`
    let send_req = json!({
        "from": "agent@example.com",
        "to": ["alice@partner.example"],
        "subject": "Dry run with from",
        "text": "Preview body",
        "dry_run": true
    });
    validate_value_against_schema(
        &spec,
        &spec["components"]["schemas"]["AiSendEmailRequest"],
        &send_req,
        "POST /v1/messages/send request",
    )
    .unwrap();
    let (st, send_resp) = http_call(
        &app,
        Method::POST,
        "/v1/messages/send",
        mb_hdr,
        Some(send_req),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    validate_value_against_schema(
        &spec,
        response_schema(&spec, "/v1/messages/send", "post", st),
        &send_resp,
        "POST /v1/messages/send",
    )
    .unwrap();

    // 8. Threads, messages, labels
    let (st, body) = http_call(&app, Method::GET, "/v1/threads", mb_hdr, None).await;
    assert_eq!(st, StatusCode::OK);
    validate_value_against_schema(
        &spec,
        response_schema(&spec, "/v1/threads", "get", st),
        &body,
        "GET /v1/threads",
    )
    .unwrap();

    let (st, body) = http_call(
        &app,
        Method::GET,
        &format!("/v1/threads/{}", seeded_msg.thread_id),
        mb_hdr,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    validate_value_against_schema(
        &spec,
        response_schema(&spec, "/v1/threads/{id}", "get", st),
        &body,
        "GET /v1/threads/{id}",
    )
    .unwrap();

    let (st, body) = http_call(&app, Method::GET, "/v1/messages", mb_hdr, None).await;
    assert_eq!(st, StatusCode::OK);
    validate_value_against_schema(
        &spec,
        response_schema(&spec, "/v1/messages", "get", st),
        &body,
        "GET /v1/messages",
    )
    .unwrap();

    let (st, body) = http_call(
        &app,
        Method::GET,
        &format!("/v1/messages/{}", seeded_msg.id),
        mb_hdr,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    validate_value_against_schema(
        &spec,
        response_schema(&spec, "/v1/messages/{id}", "get", st),
        &body,
        "GET /v1/messages/{id}",
    )
    .unwrap();

    let (st, body) = http_call(&app, Method::GET, "/v1/labels", mb_hdr, None).await;
    assert_eq!(st, StatusCode::OK);
    validate_value_against_schema(
        &spec,
        response_schema(&spec, "/v1/labels", "get", st),
        &body,
        "GET /v1/labels",
    )
    .unwrap();

    // 9. Domains
    let (st, body) = http_call(
        &app,
        Method::POST,
        "/v1/domains",
        mb_hdr,
        Some(json!({ "domain": "contract.example", "provider": "manual" })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    validate_value_against_schema(
        &spec,
        response_schema(&spec, "/v1/domains", "post", st),
        &body,
        "POST /v1/domains",
    )
    .unwrap();

    let (st, body) = http_call(&app, Method::GET, "/v1/domains", mb_hdr, None).await;
    assert_eq!(st, StatusCode::OK);
    validate_value_against_schema(
        &spec,
        response_schema(&spec, "/v1/domains", "get", st),
        &body,
        "GET /v1/domains",
    )
    .unwrap();

    // 10. PR #87 Suppression & Deliverability endpoints
    let (st, body) = http_call(
        &app,
        Method::POST,
        "/v1/suppression",
        mb_hdr,
        Some(json!({
            "email": "bounced@partner.example",
            "reason": "hard_bounce",
            "source": "manual",
            "detail": "550 5.1.1 user unknown"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    validate_value_against_schema(
        &spec,
        response_schema(&spec, "/v1/suppression", "post", st),
        &body,
        "POST /v1/suppression",
    )
    .unwrap();

    let (st, body) = http_call(&app, Method::GET, "/v1/suppression", mb_hdr, None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["count"], 1);
    validate_value_against_schema(
        &spec,
        response_schema(&spec, "/v1/suppression", "get", st),
        &body,
        "GET /v1/suppression",
    )
    .unwrap();

    let (st, body) = http_call(&app, Method::GET, "/v1/deliverability/stats", mb_hdr, None).await;
    assert_eq!(st, StatusCode::OK);
    validate_value_against_schema(
        &spec,
        response_schema(&spec, "/v1/deliverability/stats", "get", st),
        &body,
        "GET /v1/deliverability/stats",
    )
    .unwrap();

    let (st, body) = http_call(
        &app,
        Method::POST,
        "/v1/deliverability/domains/example.com/pause",
        mb_hdr,
        Some(json!({ "reason": "contract pause check" })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    validate_value_against_schema(
        &spec,
        response_schema(
            &spec,
            "/v1/deliverability/domains/{domain}/pause",
            "post",
            st,
        ),
        &body,
        "POST /v1/deliverability/domains/{domain}/pause",
    )
    .unwrap();

    let (st, body) = http_call(
        &app,
        Method::POST,
        "/v1/deliverability/domains/example.com/resume",
        mb_hdr,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    validate_value_against_schema(
        &spec,
        response_schema(
            &spec,
            "/v1/deliverability/domains/{domain}/resume",
            "post",
            st,
        ),
        &body,
        "POST /v1/deliverability/domains/{domain}/resume",
    )
    .unwrap();

    let (st, body) = http_call(
        &app,
        Method::DELETE,
        "/v1/suppression/bounced@partner.example",
        mb_hdr,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    validate_value_against_schema(
        &spec,
        response_schema(&spec, "/v1/suppression/{email}", "delete", st),
        &body,
        "DELETE /v1/suppression/{email}",
    )
    .unwrap();
}
