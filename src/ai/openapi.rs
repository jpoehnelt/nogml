//! OpenAPI 3.1.0 specification for the AI-first `/v1/*` REST and SSE API.
//!
//! Served at `GET /v1/openapi.json` and printable via `nogml schema --openapi`.

use serde_json::{Map, Value, json};

/// Canonical list of every `(http_method, path)` registered in [`crate::ai::ai_router`].
pub const V1_OPENAPI_OPERATIONS: &[(&str, &str)] = &[
    ("get", "/v1/capabilities"),
    ("get", "/v1/openapi.json"),
    ("get", "/v1/briefing"),
    ("get", "/v1/threads"),
    ("post", "/v1/threads/batch_triage"),
    ("get", "/v1/threads/{id}"),
    ("post", "/v1/threads/{id}/triage"),
    ("get", "/v1/threads/{id}/reply-context"),
    ("post", "/v1/threads/{id}/snooze"),
    ("delete", "/v1/threads/{id}/snooze"),
    ("get", "/v1/threads/{id}/annotations"),
    ("put", "/v1/threads/{id}/annotations"),
    ("patch", "/v1/threads/{id}/annotations"),
    ("delete", "/v1/threads/{id}/annotations"),
    ("get", "/v1/scheduled"),
    ("delete", "/v1/scheduled/{id}"),
    ("get", "/v1/messages"),
    ("post", "/v1/messages/send"),
    ("post", "/v1/messages/modify"),
    ("get", "/v1/messages/{id}"),
    ("post", "/v1/messages/{id}/unsubscribe"),
    ("get", "/v1/messages/{id}/attachments/{attachment_id}"),
    ("get", "/v1/messages/{id}/attachments/{attachment_id}/text"),
    ("get", "/v1/drafts"),
    ("post", "/v1/drafts"),
    ("delete", "/v1/drafts/{id}"),
    ("post", "/v1/drafts/{id}/send"),
    ("get", "/v1/approvals"),
    ("get", "/v1/approvals/{id}"),
    ("post", "/v1/approvals/{id}/approve"),
    ("post", "/v1/approvals/{id}/reject"),
    ("get", "/v1/contacts"),
    ("get", "/v1/contacts/{email}"),
    ("patch", "/v1/contacts/{email}"),
    ("get", "/v1/rules"),
    ("post", "/v1/rules"),
    ("patch", "/v1/rules/{id}"),
    ("delete", "/v1/rules/{id}"),
    ("post", "/v1/rules/{id}/test"),
    ("get", "/v1/audit"),
    ("get", "/v1/labels"),
    ("get", "/v1/search"),
    ("get", "/v1/events"),
    ("post", "/v1/sync/gmail"),
    ("get", "/v1/sync/status"),
];

fn ref_schema(name: &str) -> Value {
    json!({ "$ref": format!("#/components/schemas/{name}") })
}

fn ref_param(name: &str) -> Value {
    json!({ "$ref": format!("#/components/parameters/{name}") })
}

fn ref_response(name: &str) -> Value {
    json!({ "$ref": format!("#/components/responses/{name}") })
}

fn json_content(schema: Value) -> Value {
    json!({
        "application/json": {
            "schema": schema
        }
    })
}

fn json_request_body(required: bool, schema: Value, description: &str) -> Value {
    json!({
        "description": description,
        "required": required,
        "content": json_content(schema)
    })
}

fn json_ok(description: &str, schema: Value) -> Value {
    json!({
        "description": description,
        "content": json_content(schema)
    })
}

fn error_responses(include_not_found: bool, include_conflict: bool) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("400".to_string(), ref_response("BadRequest"));
    map.insert("401".to_string(), ref_response("Unauthorized"));
    map.insert("403".to_string(), ref_response("Forbidden"));
    if include_not_found {
        map.insert("404".to_string(), ref_response("NotFound"));
    }
    if include_conflict {
        map.insert("409".to_string(), ref_response("Conflict"));
    }
    map.insert("500".to_string(), ref_response("InternalError"));
    map
}

fn query_param(name: &str, description: &str, schema: Value) -> Value {
    json!({
        "name": name,
        "in": "query",
        "required": false,
        "description": description,
        "schema": schema
    })
}

fn path_param(name: &str, description: &str) -> Value {
    json!({
        "name": name,
        "in": "path",
        "required": true,
        "description": description,
        "schema": { "type": "string" }
    })
}

fn header_param(name: &str, description: &str, schema: Value) -> Value {
    json!({
        "name": name,
        "in": "header",
        "required": false,
        "description": description,
        "schema": schema
    })
}

fn build_responses(
    ok_entries: Vec<(&str, Value)>,
    include_not_found: bool,
    include_conflict: bool,
) -> Value {
    let mut map = Map::new();
    for (code, val) in ok_entries {
        map.insert(code.to_string(), val);
    }
    for (code, val) in error_responses(include_not_found, include_conflict) {
        map.insert(code, val);
    }
    Value::Object(map)
}

fn build_paths() -> Value {
    let mut paths = Map::new();

    // /v1/capabilities
    paths.insert(
        "/v1/capabilities".to_string(),
        json!({
            "get": {
                "operationId": "getCapabilities",
                "summary": "Inspect server capabilities, safety guardrails, and active backends",
                "tags": ["Discovery"],
                "x-required-scope": "read",
                "parameters": [ref_param("Fields")],
                "responses": build_responses(
                    vec![("200", json_ok("Server capabilities and active backend names.", ref_schema("CapabilitiesResponse")))],
                    false,
                    false
                )
            }
        }),
    );

    // /v1/openapi.json
    paths.insert(
        "/v1/openapi.json".to_string(),
        json!({
            "get": {
                "operationId": "getOpenApiSpec",
                "summary": "Fetch the OpenAPI 3.1.0 JSON specification for /v1 endpoints",
                "tags": ["Discovery"],
                "x-required-scope": "read",
                "responses": build_responses(
                    vec![("200", json_ok("OpenAPI 3.1.0 specification document.", json!({ "type": "object" })))],
                    false,
                    false
                )
            }
        }),
    );

    // /v1/briefing
    paths.insert(
        "/v1/briefing".to_string(),
        json!({
            "get": {
                "operationId": "getBriefing",
                "summary": "Fetch a compact daily briefing across VIP unread, needs-reply, follow-ups, approvals, and snoozes",
                "tags": ["Briefing"],
                "x-required-scope": "read",
                "parameters": [
                    query_param("since", "Optional RFC 3339 timestamp or Unix epoch ms filtering unread VIP threads.", json!({ "type": "string" })),
                    query_param("followup_days", "Days without a reply before a sent thread appears in follow_up_due (default 3).", json!({ "type": "integer", "minimum": 0, "default": 3 })),
                    query_param("limit", "Maximum items per section (default 20, max 100).", json!({ "type": "integer", "minimum": 1, "maximum": 100, "default": 20 })),
                    ref_param("Fields")
                ],
                "responses": build_responses(
                    vec![("200", json_ok("Daily briefing summaries and counts.", ref_schema("BriefingResponse")))],
                    false,
                    false
                )
            }
        }),
    );

    // /v1/threads
    paths.insert(
        "/v1/threads".to_string(),
        json!({
            "get": {
                "operationId": "listThreads",
                "summary": "List conversation thread summaries",
                "tags": ["Threads"],
                "x-required-scope": "read",
                "parameters": [
                    query_param("q", "Optional Gmail search query filter.", json!({ "type": "string" })),
                    query_param("label", "Filter by label ID (e.g. INBOX).", json!({ "type": "string" })),
                    query_param("unread_only", "Only return threads containing unread messages.", json!({ "type": "boolean", "default": false })),
                    query_param("needs_reply", "Filter by thread annotation needs_reply flag.", json!({ "type": "boolean" })),
                    query_param("waiting_on", "Filter by thread annotation waiting_on value.", json!({ "type": "string", "enum": ["me", "them", "none"] })),
                    query_param("include_spam_trash", "Include SPAM and TRASH threads.", json!({ "type": "boolean", "default": false })),
                    query_param("limit", "Maximum threads to return (default 20, max 100).", json!({ "type": "integer", "minimum": 1, "maximum": 100, "default": 20 })),
                    query_param("cursor", "Pagination cursor from a previous response.", json!({ "type": "string" })),
                    ref_param("Fields")
                ],
                "responses": build_responses(
                    vec![("200", json_ok("Paginated list of thread summaries.", ref_schema("ThreadListResponse")))],
                    false,
                    false
                )
            }
        }),
    );

    // /v1/threads/batch_triage
    paths.insert(
        "/v1/threads/batch_triage".to_string(),
        json!({
            "post": {
                "operationId": "batchTriageThreads",
                "summary": "Preview or atomically apply bulk triage operations across multiple threads",
                "tags": ["Threads"],
                "x-required-scope": "write",
                "parameters": [ref_param("Fields")],
                "requestBody": json_request_body(
                    true,
                    ref_schema("AiBatchTriageRequest"),
                    "Batch triage specification via explicit operations, thread_ids, or Gmail query."
                ),
                "responses": build_responses(
                    vec![("200", json_ok("Batch triage dry-run preview or applied results.", json!({
                        "oneOf": [
                            ref_schema("BatchTriageDryRunResponse"),
                            ref_schema("BatchTriageApplyResponse")
                        ]
                    })))],
                    true,
                    false
                )
            }
        }),
    );

    // /v1/threads/{id}
    paths.insert(
        "/v1/threads/{id}".to_string(),
        json!({
            "get": {
                "operationId": "getThread",
                "summary": "Read a thread with compact messages, quote stripping, and annotation",
                "tags": ["Threads"],
                "x-required-scope": "read",
                "parameters": [
                    path_param("id", "Thread identifier."),
                    query_param("max_body_chars", "Maximum body characters per message (capped at 100000).", json!({ "type": "integer", "minimum": 0, "maximum": 100000 })),
                    query_param("strip_quotes", "Strip quoted reply chains (default true).", json!({ "type": "boolean", "default": true })),
                    query_param("include_html", "Include sanitized HTML body.", json!({ "type": "boolean", "default": false })),
                    query_param("include_attachments_meta", "Include attachment metadata list (default true).", json!({ "type": "boolean", "default": true })),
                    ref_param("Fields")
                ],
                "responses": build_responses(
                    vec![("200", json_ok("Thread detail with compact messages.", ref_schema("ThreadDetail")))],
                    true,
                    false
                )
            }
        }),
    );

    // /v1/threads/{id}/triage
    paths.insert(
        "/v1/threads/{id}/triage".to_string(),
        json!({
            "post": {
                "operationId": "triageThread",
                "summary": "Archive, mark read/unread, star, trash, or adjust labels on a thread",
                "tags": ["Threads"],
                "x-required-scope": "write",
                "parameters": [
                    path_param("id", "Thread identifier."),
                    ref_param("Fields")
                ],
                "requestBody": json_request_body(
                    true,
                    ref_schema("AiTriageRequest"),
                    "Triage actions to apply or preview with dry_run."
                ),
                "responses": build_responses(
                    vec![("200", json_ok("Triage result or dry-run preview.", json!({ "type": "object" })))],
                    true,
                    false
                )
            }
        }),
    );

    // /v1/threads/{id}/reply-context
    paths.insert(
        "/v1/threads/{id}/reply-context".to_string(),
        json!({
            "get": {
                "operationId": "getReplyContext",
                "summary": "Fetch quote-stripped thread, annotation, participant contacts, sent style samples, and related threads in one call",
                "tags": ["Threads"],
                "x-required-scope": "read",
                "parameters": [
                    path_param("id", "Thread identifier."),
                    query_param("max_body_chars", "Maximum body characters per message.", json!({ "type": "integer", "minimum": 0, "maximum": 100000 })),
                    query_param("max_style_samples", "Maximum recent sent messages to primary recipient (default 3, max 10).", json!({ "type": "integer", "minimum": 0, "maximum": 10, "default": 3 })),
                    query_param("max_related_threads", "Maximum related threads returned (default 5, max 20).", json!({ "type": "integer", "minimum": 0, "maximum": 20, "default": 5 })),
                    ref_param("Fields")
                ],
                "responses": build_responses(
                    vec![("200", json_ok("Aggregated reply context for drafting an in-voice reply.", ref_schema("ReplyContextResponse")))],
                    true,
                    false
                )
            }
        }),
    );

    // /v1/threads/{id}/snooze
    paths.insert(
        "/v1/threads/{id}/snooze".to_string(),
        json!({
            "post": {
                "operationId": "snoozeThread",
                "summary": "Snooze a thread until a future RFC 3339 timestamp",
                "tags": ["Threads"],
                "x-required-scope": "write",
                "parameters": [
                    path_param("id", "Thread identifier."),
                    ref_param("Fields")
                ],
                "requestBody": json_request_body(
                    true,
                    ref_schema("SnoozeThreadRequest"),
                    "Target wake timestamp for the snoozed thread."
                ),
                "responses": build_responses(
                    vec![("200", json_ok("Snooze confirmation.", json!({ "type": "object" })))],
                    true,
                    false
                )
            },
            "delete": {
                "operationId": "unsnoozeThread",
                "summary": "Unsnooze a thread immediately and return it to INBOX",
                "tags": ["Threads"],
                "x-required-scope": "write",
                "parameters": [
                    path_param("id", "Thread identifier."),
                    ref_param("Fields")
                ],
                "responses": build_responses(
                    vec![("200", json_ok("Unsnooze confirmation.", json!({ "type": "object" })))],
                    true,
                    false
                )
            }
        }),
    );

    // /v1/threads/{id}/annotations
    paths.insert(
        "/v1/threads/{id}/annotations".to_string(),
        json!({
            "get": {
                "operationId": "getThreadAnnotations",
                "summary": "Read persistent structured annotations on a thread",
                "tags": ["Threads"],
                "x-required-scope": "read",
                "parameters": [
                    path_param("id", "Thread identifier."),
                    ref_param("Fields")
                ],
                "responses": build_responses(
                    vec![("200", json_ok("Thread annotation envelope.", ref_schema("ThreadAnnotationEnvelope")))],
                    true,
                    false
                )
            },
            "put": {
                "operationId": "putThreadAnnotations",
                "summary": "Replace persistent structured annotations on a thread",
                "tags": ["Threads"],
                "x-required-scope": "write",
                "parameters": [
                    path_param("id", "Thread identifier."),
                    ref_param("Fields")
                ],
                "requestBody": json_request_body(
                    true,
                    ref_schema("UpsertThreadAnnotationRequest"),
                    "Full annotation object replacing existing state."
                ),
                "responses": build_responses(
                    vec![("200", json_ok("Saved thread annotation.", ref_schema("ThreadAnnotationEnvelope")))],
                    true,
                    false
                )
            },
            "patch": {
                "operationId": "patchThreadAnnotations",
                "summary": "Partially update thread annotations and shallow-merge extracted JSON",
                "tags": ["Threads"],
                "x-required-scope": "write",
                "parameters": [
                    path_param("id", "Thread identifier."),
                    ref_param("Fields")
                ],
                "requestBody": json_request_body(
                    true,
                    ref_schema("PatchThreadAnnotationRequest"),
                    "Partial annotation update."
                ),
                "responses": build_responses(
                    vec![("200", json_ok("Updated thread annotation.", ref_schema("ThreadAnnotationEnvelope")))],
                    true,
                    false
                )
            },
            "delete": {
                "operationId": "deleteThreadAnnotations",
                "summary": "Delete persistent annotations on a thread",
                "tags": ["Threads"],
                "x-required-scope": "write",
                "parameters": [
                    path_param("id", "Thread identifier."),
                    ref_param("Fields")
                ],
                "responses": build_responses(
                    vec![("200", json_ok("Deletion confirmation.", json!({
                        "type": "object",
                        "required": ["thread_id", "deleted"],
                        "properties": {
                            "thread_id": { "type": "string" },
                            "deleted": { "type": "boolean" }
                        }
                    })))],
                    true,
                    false
                )
            }
        }),
    );

    // /v1/scheduled
    paths.insert(
        "/v1/scheduled".to_string(),
        json!({
            "get": {
                "operationId": "listScheduledSends",
                "summary": "List scheduled outbound emails",
                "tags": ["Scheduled"],
                "x-required-scope": "read",
                "parameters": [
                    query_param("status", "Filter by scheduled send status.", json!({ "type": "string", "enum": ["pending", "sending", "sent", "canceled", "failed", "all"] })),
                    query_param("limit", "Maximum scheduled sends to return (default 20, max 100).", json!({ "type": "integer", "minimum": 1, "maximum": 100, "default": 20 })),
                    ref_param("Fields")
                ],
                "responses": build_responses(
                    vec![("200", json_ok("List of scheduled sends.", json!({
                        "type": "object",
                        "required": ["scheduled", "count"],
                        "properties": {
                            "scheduled": { "type": "array", "items": ref_schema("ScheduledSend") },
                            "count": { "type": "integer", "minimum": 0 }
                        }
                    })))],
                    false,
                    false
                )
            }
        }),
    );

    // /v1/scheduled/{id}
    paths.insert(
        "/v1/scheduled/{id}".to_string(),
        json!({
            "delete": {
                "operationId": "cancelScheduledSend",
                "summary": "Cancel a pending scheduled outbound email before dispatch",
                "tags": ["Scheduled"],
                "x-required-scope": "write",
                "parameters": [
                    path_param("id", "Scheduled send identifier."),
                    ref_param("Fields")
                ],
                "responses": build_responses(
                    vec![("200", json_ok("Canceled scheduled send summary.", json!({ "type": "object" })))],
                    true,
                    true
                )
            }
        }),
    );

    // /v1/messages
    paths.insert(
        "/v1/messages".to_string(),
        json!({
            "get": {
                "operationId": "listMessages",
                "summary": "List compact messages with optional filters",
                "tags": ["Messages"],
                "x-required-scope": "read",
                "parameters": [
                    query_param("q", "Optional Gmail search query.", json!({ "type": "string" })),
                    query_param("label", "Single label filter.", json!({ "type": "string" })),
                    query_param("labels", "Comma-separated label filters.", json!({ "type": "string" })),
                    query_param("thread_id", "Restrict to a specific thread ID.", json!({ "type": "string" })),
                    query_param("include_spam_trash", "Include SPAM and TRASH messages.", json!({ "type": "boolean", "default": false })),
                    query_param("limit", "Maximum messages to return (default 20, max 100).", json!({ "type": "integer", "minimum": 1, "maximum": 100, "default": 20 })),
                    query_param("cursor", "Pagination cursor.", json!({ "type": "string" })),
                    query_param("include_body", "Include truncated text body.", json!({ "type": "boolean", "default": false })),
                    query_param("max_body_chars", "Maximum body characters per message (default 1000, max 100000).", json!({ "type": "integer", "minimum": 0, "maximum": 100000, "default": 1000 })),
                    query_param("strip_quotes", "Strip quoted reply chains.", json!({ "type": "boolean", "default": false })),
                    query_param("include_html", "Include sanitized HTML body.", json!({ "type": "boolean", "default": false })),
                    ref_param("Fields")
                ],
                "responses": build_responses(
                    vec![("200", json_ok("Paginated list of compact messages.", ref_schema("MessageListResponse")))],
                    false,
                    false
                )
            }
        }),
    );

    // /v1/messages/send
    paths.insert(
        "/v1/messages/send".to_string(),
        json!({
            "post": {
                "operationId": "sendMessage",
                "summary": "Send, schedule, dry-run preview, or queue an outbound email through safety guardrails",
                "tags": ["Messages"],
                "x-required-scope": "send",
                "parameters": [
                    header_param("Idempotency-Key", "Optional deduplication key cached for 24h per mailbox.", json!({ "type": "string", "maxLength": 256 })),
                    ref_param("Fields")
                ],
                "requestBody": json_request_body(
                    true,
                    ref_schema("AiSendEmailRequest"),
                    "Outbound email payload with optional reply threading, dry_run, idempotency_key, and send_at."
                ),
                "responses": build_responses(
                    vec![
                        ("200", json_ok("Email sent, downgraded to draft, or dry-run evaluated.", json!({
                            "oneOf": [
                                ref_schema("DryRunResponse"),
                                json!({ "type": "object" })
                            ]
                        }))),
                        ("202", json_ok("Email held for human approval or scheduled for future delivery.", json!({ "type": "object" })))
                    ],
                    true,
                    false
                )
            }
        }),
    );

    // /v1/messages/modify
    paths.insert(
        "/v1/messages/modify".to_string(),
        json!({
            "post": {
                "operationId": "modifyMessages",
                "summary": "Modify labels across multiple message IDs and/or thread IDs",
                "tags": ["Messages"],
                "x-required-scope": "write",
                "parameters": [ref_param("Fields")],
                "requestBody": json_request_body(
                    true,
                    ref_schema("AiModifyLabelsRequest"),
                    "Target message/thread IDs and label mutations."
                ),
                "responses": build_responses(
                    vec![("200", json_ok("Label modification result or dry-run preview.", json!({ "type": "object" })))],
                    true,
                    false
                )
            }
        }),
    );

    // /v1/messages/{id}
    paths.insert(
        "/v1/messages/{id}".to_string(),
        json!({
            "get": {
                "operationId": "getMessage",
                "summary": "Read a single compact message with optional attachment text extraction",
                "tags": ["Messages"],
                "x-required-scope": "read",
                "parameters": [
                    path_param("id", "Message identifier."),
                    query_param("max_body_chars", "Maximum body characters (capped at 100000).", json!({ "type": "integer", "minimum": 0, "maximum": 100000 })),
                    query_param("strip_quotes", "Strip quoted reply chains.", json!({ "type": "boolean", "default": false })),
                    query_param("include_html", "Include sanitized HTML body.", json!({ "type": "boolean", "default": false })),
                    query_param("include_attachments_meta", "Include attachment metadata list (default true).", json!({ "type": "boolean", "default": true })),
                    query_param("extract_attachment_text", "Extract bounded text for attachments.", json!({ "type": "boolean", "default": false })),
                    query_param("attachment_max_chars", "Maximum extracted characters per attachment (default 20000, max 100000).", json!({ "type": "integer", "minimum": 0, "maximum": 100000, "default": 20000 })),
                    ref_param("Fields")
                ],
                "responses": build_responses(
                    vec![("200", json_ok("Compact message representation.", ref_schema("CompactMessage")))],
                    true,
                    false
                )
            }
        }),
    );

    // /v1/messages/{id}/unsubscribe
    paths.insert(
        "/v1/messages/{id}/unsubscribe".to_string(),
        json!({
            "post": {
                "operationId": "unsubscribeMessage",
                "summary": "Unsubscribe from a mailing list via RFC 8058 one-click HTTPS POST or mailto",
                "tags": ["Messages"],
                "x-required-scope": "write (dry_run) or send (execute)",
                "parameters": [
                    path_param("id", "Message identifier."),
                    ref_param("Fields")
                ],
                "requestBody": json_request_body(
                    false,
                    ref_schema("AiUnsubscribeRequest"),
                    "Optional unsubscribe execution options."
                ),
                "responses": build_responses(
                    vec![
                        ("200", json_ok("Unsubscribe executed or dry-run preview.", json!({ "type": "object" }))),
                        ("202", json_ok("Mailto unsubscribe held for human approval or scheduled.", json!({ "type": "object" })))
                    ],
                    true,
                    false
                )
            }
        }),
    );

    // /v1/messages/{id}/attachments/{attachment_id}
    paths.insert(
        "/v1/messages/{id}/attachments/{attachment_id}".to_string(),
        json!({
            "get": {
                "operationId": "downloadAttachment",
                "summary": "Download raw binary bytes for a message attachment",
                "tags": ["Messages"],
                "x-required-scope": "read",
                "parameters": [
                    path_param("id", "Message identifier."),
                    path_param("attachment_id", "Attachment identifier.")
                ],
                "responses": build_responses(
                    vec![("200", json!({
                        "description": "Raw attachment binary content with Content-Disposition: attachment.",
                        "content": {
                            "application/octet-stream": {
                                "schema": { "type": "string", "contentEncoding": "binary" }
                            }
                        }
                    }))],
                    true,
                    false
                )
            }
        }),
    );

    // /v1/messages/{id}/attachments/{attachment_id}/text
    paths.insert(
        "/v1/messages/{id}/attachments/{attachment_id}/text".to_string(),
        json!({
            "get": {
                "operationId": "getAttachmentText",
                "summary": "Extract bounded readable text or structured calendar data from a message attachment",
                "tags": ["Messages"],
                "x-required-scope": "read",
                "parameters": [
                    path_param("id", "Message identifier."),
                    path_param("attachment_id", "Attachment identifier."),
                    query_param("max_chars", "Maximum extracted characters (default 20000, max 100000).", json!({ "type": "integer", "minimum": 0, "maximum": 100000, "default": 20000 })),
                    ref_param("Fields")
                ],
                "responses": build_responses(
                    vec![("200", json_ok("Extracted attachment text and metadata.", ref_schema("AttachmentTextExtraction")))],
                    true,
                    false
                )
            }
        }),
    );

    // /v1/drafts
    paths.insert(
        "/v1/drafts".to_string(),
        json!({
            "get": {
                "operationId": "listDrafts",
                "summary": "List local email drafts",
                "tags": ["Drafts"],
                "x-required-scope": "read",
                "parameters": [
                    query_param("limit", "Maximum drafts to return (default 20, max 100).", json!({ "type": "integer", "minimum": 1, "maximum": 100, "default": 20 })),
                    query_param("page_token", "Pagination token from a previous response.", json!({ "type": "string" })),
                    ref_param("Fields")
                ],
                "responses": build_responses(
                    vec![("200", json_ok("Paginated list of drafts.", json!({
                        "type": "object",
                        "required": ["drafts", "has_more"],
                        "properties": {
                            "drafts": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["id", "updated_at", "message"],
                                    "properties": {
                                        "id": { "type": "string" },
                                        "updated_at": { "type": "string", "format": "date-time" },
                                        "message": ref_schema("CompactMessage")
                                    }
                                }
                            },
                            "next_cursor": { "type": ["string", "null"] },
                            "has_more": { "type": "boolean" }
                        }
                    })))],
                    false,
                    false
                )
            },
            "post": {
                "operationId": "createDraft",
                "summary": "Create a local email draft",
                "tags": ["Drafts"],
                "x-required-scope": "write",
                "parameters": [
                    header_param("Idempotency-Key", "Optional deduplication key cached for 24h per mailbox.", json!({ "type": "string", "maxLength": 256 })),
                    ref_param("Fields")
                ],
                "requestBody": json_request_body(
                    true,
                    ref_schema("AiCreateDraftRequest"),
                    "Draft email fields and optional reply threading."
                ),
                "responses": build_responses(
                    vec![("200", json_ok("Created draft metadata.", json!({ "type": "object" })))],
                    true,
                    false
                )
            }
        }),
    );

    // /v1/drafts/{id}
    paths.insert(
        "/v1/drafts/{id}".to_string(),
        json!({
            "delete": {
                "operationId": "deleteDraft",
                "summary": "Delete a draft by ID",
                "tags": ["Drafts"],
                "x-required-scope": "write",
                "parameters": [path_param("id", "Draft identifier.")],
                "responses": build_responses(
                    vec![("200", json_ok("Draft deletion confirmation.", json!({
                        "type": "object",
                        "required": ["deleted", "draft_id"],
                        "properties": {
                            "deleted": { "type": "boolean" },
                            "draft_id": { "type": "string" }
                        }
                    })))],
                    true,
                    false
                )
            }
        }),
    );

    // /v1/drafts/{id}/send
    paths.insert(
        "/v1/drafts/{id}/send".to_string(),
        json!({
            "post": {
                "operationId": "sendDraft",
                "summary": "Send an existing draft through outbound safety guardrails",
                "tags": ["Drafts"],
                "x-required-scope": "send",
                "parameters": [
                    path_param("id", "Draft identifier."),
                    ref_param("Fields")
                ],
                "requestBody": json_request_body(
                    false,
                    ref_schema("AiSendDraftRequest"),
                    "Optional send options such as dry_run."
                ),
                "responses": build_responses(
                    vec![
                        ("200", json_ok("Draft sent or dry-run evaluated.", json!({ "type": "object" }))),
                        ("202", json_ok("Draft held for human approval or scheduled.", json!({ "type": "object" })))
                    ],
                    true,
                    false
                )
            }
        }),
    );

    // /v1/approvals
    paths.insert(
        "/v1/approvals".to_string(),
        json!({
            "get": {
                "operationId": "listApprovals",
                "summary": "List pending or resolved human-in-the-loop outbound approvals",
                "tags": ["Approvals"],
                "x-required-scope": "admin",
                "parameters": [
                    query_param("status", "Filter by approval status.", json!({ "type": "string", "enum": ["pending", "approving", "approved", "rejected", "expired", "all"] })),
                    query_param("limit", "Maximum approvals to return (default 20, max 100).", json!({ "type": "integer", "minimum": 1, "maximum": 100, "default": 20 })),
                    ref_param("Fields")
                ],
                "responses": build_responses(
                    vec![("200", json_ok("List of approval requests.", json!({
                        "type": "object",
                        "required": ["approvals", "count"],
                        "properties": {
                            "approvals": { "type": "array", "items": ref_schema("PendingApproval") },
                            "count": { "type": "integer", "minimum": 0 }
                        }
                    })))],
                    false,
                    false
                )
            }
        }),
    );

    // /v1/approvals/{id}
    paths.insert(
        "/v1/approvals/{id}".to_string(),
        json!({
            "get": {
                "operationId": "getApproval",
                "summary": "Fetch a single outbound approval request by ID",
                "tags": ["Approvals"],
                "x-required-scope": "admin",
                "parameters": [
                    path_param("id", "Approval identifier."),
                    ref_param("Fields")
                ],
                "responses": build_responses(
                    vec![("200", json_ok("Approval record.", ref_schema("PendingApproval")))],
                    true,
                    false
                )
            }
        }),
    );

    // /v1/approvals/{id}/approve
    paths.insert(
        "/v1/approvals/{id}/approve".to_string(),
        json!({
            "post": {
                "operationId": "approveApproval",
                "summary": "Approve and dispatch a held outbound email exactly once",
                "tags": ["Approvals"],
                "x-required-scope": "admin",
                "parameters": [
                    path_param("id", "Approval identifier."),
                    ref_param("Fields")
                ],
                "requestBody": json_request_body(
                    false,
                    ref_schema("ApprovalDecisionRequest"),
                    "Optional reviewer identity and note."
                ),
                "responses": build_responses(
                    vec![("200", json_ok("Approval dispatched and resolved.", json!({ "type": "object" })))],
                    true,
                    true
                )
            }
        }),
    );

    // /v1/approvals/{id}/reject
    paths.insert(
        "/v1/approvals/{id}/reject".to_string(),
        json!({
            "post": {
                "operationId": "rejectApproval",
                "summary": "Reject a held outbound email without dispatching",
                "tags": ["Approvals"],
                "x-required-scope": "admin",
                "parameters": [
                    path_param("id", "Approval identifier."),
                    ref_param("Fields")
                ],
                "requestBody": json_request_body(
                    false,
                    ref_schema("ApprovalDecisionRequest"),
                    "Optional reviewer identity and rejection note."
                ),
                "responses": build_responses(
                    vec![("200", json_ok("Rejection recorded.", json!({ "type": "object" })))],
                    true,
                    true
                )
            }
        }),
    );

    // /v1/contacts
    paths.insert(
        "/v1/contacts".to_string(),
        json!({
            "get": {
                "operationId": "listContacts",
                "summary": "List per-mailbox contact profiles and VIP senders",
                "tags": ["Contacts"],
                "x-required-scope": "read",
                "parameters": [
                    query_param("q", "Substring filter on email, display name, domain, or notes.", json!({ "type": "string" })),
                    query_param("vip_only", "Only return contacts marked as VIP.", json!({ "type": "boolean", "default": false })),
                    query_param("replied_only", "Only return contacts the mailbox owner has replied to.", json!({ "type": "boolean", "default": false })),
                    query_param("domain", "Filter by sender domain.", json!({ "type": "string" })),
                    query_param("limit", "Maximum contacts to return (default 50, max 200).", json!({ "type": "integer", "minimum": 1, "maximum": 200, "default": 50 })),
                    ref_param("Fields")
                ],
                "responses": build_responses(
                    vec![("200", json_ok("Contact list.", json!({
                        "type": "object",
                        "required": ["contacts", "count"],
                        "properties": {
                            "contacts": { "type": "array", "items": ref_schema("ContactRecord") },
                            "count": { "type": "integer", "minimum": 0 }
                        }
                    })))],
                    false,
                    false
                )
            }
        }),
    );

    // /v1/contacts/{email}
    paths.insert(
        "/v1/contacts/{email}".to_string(),
        json!({
            "get": {
                "operationId": "getContact",
                "summary": "Look up a single contact profile by email address",
                "tags": ["Contacts"],
                "x-required-scope": "read",
                "parameters": [
                    path_param("email", "Contact email address."),
                    ref_param("Fields")
                ],
                "responses": build_responses(
                    vec![("200", json_ok("Contact record.", ref_schema("ContactRecord")))],
                    true,
                    false
                )
            },
            "patch": {
                "operationId": "patchContact",
                "summary": "Update VIP override, display name, or notes for a contact",
                "tags": ["Contacts"],
                "x-required-scope": "write",
                "parameters": [
                    path_param("email", "Contact email address."),
                    ref_param("Fields")
                ],
                "requestBody": json_request_body(
                    true,
                    ref_schema("ContactPatch"),
                    "Fields to update on the contact record."
                ),
                "responses": build_responses(
                    vec![("200", json_ok("Updated contact record.", ref_schema("ContactRecord")))],
                    true,
                    false
                )
            }
        }),
    );

    // /v1/rules
    paths.insert(
        "/v1/rules".to_string(),
        json!({
            "get": {
                "operationId": "listRules",
                "summary": "List per-mailbox event-driven inbox rules",
                "tags": ["Rules"],
                "x-required-scope": "read",
                "parameters": [ref_param("Fields")],
                "responses": build_responses(
                    vec![("200", json_ok("Inbox rules list.", json!({
                        "type": "object",
                        "required": ["rules", "count"],
                        "properties": {
                            "rules": { "type": "array", "items": ref_schema("InboxRule") },
                            "count": { "type": "integer", "minimum": 0 }
                        }
                    })))],
                    false,
                    false
                )
            },
            "post": {
                "operationId": "createRule",
                "summary": "Create an event-driven inbox rule with label mutations and optional signed webhook",
                "tags": ["Rules"],
                "x-required-scope": "write",
                "parameters": [ref_param("Fields")],
                "requestBody": json_request_body(
                    true,
                    ref_schema("NewInboxRule"),
                    "Inbox rule match criteria and actions."
                ),
                "responses": build_responses(
                    vec![("200", json_ok("Created inbox rule.", ref_schema("InboxRule")))],
                    false,
                    false
                )
            }
        }),
    );

    // /v1/rules/{id}
    paths.insert(
        "/v1/rules/{id}".to_string(),
        json!({
            "patch": {
                "operationId": "patchRule",
                "summary": "Update an existing inbox rule",
                "tags": ["Rules"],
                "x-required-scope": "write",
                "parameters": [
                    path_param("id", "Rule identifier."),
                    ref_param("Fields")
                ],
                "requestBody": json_request_body(
                    true,
                    ref_schema("InboxRulePatch"),
                    "Partial rule update."
                ),
                "responses": build_responses(
                    vec![("200", json_ok("Updated inbox rule.", ref_schema("InboxRule")))],
                    true,
                    false
                )
            },
            "delete": {
                "operationId": "deleteRule",
                "summary": "Delete an inbox rule by ID",
                "tags": ["Rules"],
                "x-required-scope": "write",
                "parameters": [
                    path_param("id", "Rule identifier."),
                    ref_param("Fields")
                ],
                "responses": build_responses(
                    vec![("200", json_ok("Rule deletion confirmation.", json!({
                        "type": "object",
                        "required": ["deleted", "id"],
                        "properties": {
                            "deleted": { "type": "boolean" },
                            "id": { "type": "string" }
                        }
                    })))],
                    true,
                    false
                )
            }
        }),
    );

    // /v1/rules/{id}/test
    paths.insert(
        "/v1/rules/{id}/test".to_string(),
        json!({
            "post": {
                "operationId": "testRule",
                "summary": "Dry-run an inbox rule against recent stored messages without mutations or webhooks",
                "tags": ["Rules"],
                "x-required-scope": "read",
                "parameters": [
                    path_param("id", "Rule identifier."),
                    query_param("limit", "Maximum recent messages to evaluate (default 20, max 100).", json!({ "type": "integer", "minimum": 1, "maximum": 100, "default": 20 })),
                    ref_param("Fields")
                ],
                "responses": build_responses(
                    vec![("200", json_ok("Rule dry-run matches.", json!({ "type": "object" })))],
                    true,
                    false
                )
            }
        }),
    );

    // /v1/audit
    paths.insert(
        "/v1/audit".to_string(),
        json!({
            "get": {
                "operationId": "listAuditLog",
                "summary": "Query the immutable append-only agent and API audit log",
                "tags": ["Audit"],
                "x-required-scope": "read",
                "parameters": [
                    query_param("action", "Filter by action (read, search, send, draft, triage, batch_triage, approve, reject, unsubscribe, modify, delete).", json!({ "type": "string" })),
                    query_param("actor", "Filter by actor identity.", json!({ "type": "string" })),
                    query_param("since", "Unix epoch milliseconds or RFC 3339 timestamp.", json!({ "type": "string" })),
                    query_param("limit", "Maximum entries to return (default 50, max 500).", json!({ "type": "integer", "minimum": 1, "maximum": 500, "default": 50 })),
                    ref_param("Fields")
                ],
                "responses": build_responses(
                    vec![("200", json_ok("Audit log entries (newest first).", json!({
                        "type": "object",
                        "required": ["entries", "count"],
                        "properties": {
                            "entries": { "type": "array", "items": ref_schema("AuditLogEntry") },
                            "count": { "type": "integer", "minimum": 0 }
                        }
                    })))],
                    false,
                    false
                )
            }
        }),
    );

    // /v1/labels
    paths.insert(
        "/v1/labels".to_string(),
        json!({
            "get": {
                "operationId": "listLabels",
                "summary": "List all system and user labels with message and thread counts",
                "tags": ["Labels"],
                "x-required-scope": "read",
                "parameters": [ref_param("Fields")],
                "responses": build_responses(
                    vec![("200", json_ok("Mailbox labels with counts.", json!({
                        "type": "object",
                        "required": ["labels"],
                        "properties": {
                            "labels": { "type": "array", "items": ref_schema("LabelSummary") }
                        }
                    })))],
                    false,
                    false
                )
            }
        }),
    );

    // /v1/search
    paths.insert(
        "/v1/search".to_string(),
        json!({
            "get": {
                "operationId": "searchMessages",
                "summary": "Search messages using full-text or hybrid semantic search and structured filters",
                "tags": ["Search"],
                "x-required-scope": "read",
                "parameters": [
                    query_param("q", "Full-text, Gmail operator, or hybrid semantic search query.", json!({ "type": "string" })),
                    query_param("label", "Single label ID filter.", json!({ "type": "string" })),
                    query_param("labels", "Comma-separated label ID filters.", json!({ "type": "string" })),
                    query_param("unread", "Filter by unread state.", json!({ "type": "boolean" })),
                    query_param("thread_id", "Restrict search to a single thread.", json!({ "type": "string" })),
                    query_param("from", "Filter by sender address or substring.", json!({ "type": "string" })),
                    query_param("to", "Filter by recipient address or substring.", json!({ "type": "string" })),
                    query_param("after", "RFC 3339 lower bound on message timestamp.", json!({ "type": "string", "format": "date-time" })),
                    query_param("before", "RFC 3339 upper bound on message timestamp.", json!({ "type": "string", "format": "date-time" })),
                    query_param("has_attachment", "Filter by attachment presence.", json!({ "type": "boolean" })),
                    query_param("include_spam_trash", "Include SPAM and TRASH messages.", json!({ "type": "boolean", "default": false })),
                    query_param("limit", "Maximum messages to return (default 20, max 100).", json!({ "type": "integer", "minimum": 1, "maximum": 100, "default": 20 })),
                    query_param("cursor", "Pagination cursor.", json!({ "type": "string" })),
                    query_param("include_body", "Include truncated text body.", json!({ "type": "boolean", "default": false })),
                    query_param("max_body_chars", "Maximum body characters per message (default 1000, max 100000).", json!({ "type": "integer", "minimum": 0, "maximum": 100000, "default": 1000 })),
                    query_param("strip_quotes", "Strip quoted reply chains.", json!({ "type": "boolean", "default": false })),
                    query_param("include_html", "Include sanitized HTML body.", json!({ "type": "boolean", "default": false })),
                    ref_param("Fields")
                ],
                "responses": build_responses(
                    vec![("200", json_ok("Search results page.", ref_schema("MessageListResponse")))],
                    false,
                    false
                )
            }
        }),
    );

    // /v1/events
    paths.insert(
        "/v1/events".to_string(),
        json!({
            "get": {
                "operationId": "streamEvents",
                "summary": "Stream real-time mail events over Server-Sent Events (SSE) with Last-Event-ID replay",
                "tags": ["Events"],
                "x-required-scope": "read",
                "parameters": [
                    header_param("Last-Event-ID", "Resume SSE stream after this event sequence ID.", json!({ "type": "string" })),
                    query_param("types", "Comma-separated event type filter.", json!({ "type": "string" })),
                    query_param("label", "Filter events affecting a specific label ID.", json!({ "type": "string" })),
                    query_param("thread_id", "Filter events for a specific thread ID.", json!({ "type": "string" })),
                    query_param("since_id", "Replay events with ID strictly greater than since_id.", json!({ "type": "integer", "minimum": 0 }))
                ],
                "responses": build_responses(
                    vec![("200", json!({
                        "description": "Server-Sent Events stream of JSON-encoded EventEnvelope frames.",
                        "content": {
                            "text/event-stream": {
                                "schema": { "type": "string" }
                            }
                        }
                    }))],
                    false,
                    false
                )
            }
        }),
    );

    // /v1/sync/gmail
    paths.insert(
        "/v1/sync/gmail".to_string(),
        json!({
            "post": {
                "operationId": "syncGmail",
                "summary": "Trigger an upstream Gmail sync pass (incremental or full)",
                "tags": ["Sync"],
                "x-required-scope": "write",
                "parameters": [ref_param("Fields")],
                "requestBody": json_request_body(
                    false,
                    ref_schema("SyncTriggerRequest"),
                    "Optional sync mode, provider, query, and bidirectional override."
                ),
                "responses": build_responses(
                    vec![("200", json_ok("Sync run report.", json!({ "type": "object" })))],
                    false,
                    false
                )
            }
        }),
    );

    // /v1/sync/status
    paths.insert(
        "/v1/sync/status".to_string(),
        json!({
            "get": {
                "operationId": "getSyncStatus",
                "summary": "Inspect upstream Gmail sync state, checkpoints, and pushback counts",
                "tags": ["Sync"],
                "x-required-scope": "read",
                "parameters": [ref_param("Fields")],
                "responses": build_responses(
                    vec![("200", json_ok("Current sync status.", json!({ "type": "object" })))],
                    false,
                    false
                )
            }
        }),
    );

    Value::Object(paths)
}

fn merge_json_object(target: &mut Map<String, Value>, source: Value) {
    if let Value::Object(map) = source {
        target.extend(map);
    }
}

fn build_schemas() -> Value {
    let mut schemas = Map::new();

    merge_json_object(
        &mut schemas,
        json!({
            "AiErrorBody": {
                "type": "object",
                "required": ["code", "message"],
                "properties": {
                    "code": { "type": "string", "description": "Machine-readable error code." },
                    "message": { "type": "string", "description": "Human-readable error summary." },
                    "hint": { "type": ["string", "null"], "description": "Optional remediation hint." },
                    "details": { "description": "Optional structured error details." }
                }
            },
            "AiErrorEnvelope": {
                "type": "object",
                "required": ["error"],
                "properties": {
                    "error": ref_schema("AiErrorBody")
                }
            },
            "EmailAddress": {
                "type": "object",
                "required": ["email"],
                "properties": {
                    "name": { "type": ["string", "null"] },
                    "email": { "type": "string", "format": "email" }
                }
            },
            "UntrustedMeta": {
                "type": "object",
                "required": ["untrusted_external_content"],
                "properties": {
                    "untrusted_external_content": { "type": "boolean" }
                }
            },
            "AttachmentMeta": {
                "type": "object",
                "required": ["id", "content_type", "size_bytes"],
                "properties": {
                    "id": { "type": "string" },
                    "part_id": { "type": ["string", "null"] },
                    "filename": { "type": ["string", "null"] },
                    "content_type": { "type": "string" },
                    "size_bytes": { "type": "integer", "minimum": 0 }
                }
            },
            "AttachmentTextExtraction": {
                "type": "object",
                "required": ["content_type", "size_bytes", "extracted", "truncated", "total_chars"],
                "properties": {
                    "attachment_id": { "type": ["string", "null"] },
                    "message_id": { "type": ["string", "null"] },
                    "filename": { "type": ["string", "null"] },
                    "content_type": { "type": "string" },
                    "size_bytes": { "type": "integer", "minimum": 0 },
                    "extracted": { "type": "boolean" },
                    "format": { "type": ["string", "null"] },
                    "text": { "type": ["string", "null"] },
                    "truncated": { "type": "boolean" },
                    "total_chars": { "type": "integer", "minimum": 0 },
                    "structured": {},
                    "reason": { "type": ["string", "null"] },
                    "_meta": ref_schema("UntrustedMeta")
                }
            },
            "ExtractedLink": {
                "type": "object",
                "required": ["display_text", "href", "domain_mismatch"],
                "properties": {
                    "display_text": { "type": "string" },
                    "href": { "type": "string" },
                    "domain_mismatch": { "type": "boolean" }
                }
            },
            "UnsubscribeInfo": {
                "type": "object",
                "required": ["one_click"],
                "properties": {
                    "https_url": { "type": ["string", "null"] },
                    "mailto": { "type": ["string", "null"] },
                    "one_click": { "type": "boolean" },
                    "post_body": { "type": ["string", "null"] }
                }
            },
            "ContactSummary": {
                "type": "object",
                "required": ["email", "domain", "sent_count", "received_count", "replied_by_me_count", "is_vip"],
                "properties": {
                    "email": { "type": "string" },
                    "display_name": { "type": ["string", "null"] },
                    "domain": { "type": "string" },
                    "sent_count": { "type": "integer", "minimum": 0 },
                    "received_count": { "type": "integer", "minimum": 0 },
                    "replied_by_me_count": { "type": "integer", "minimum": 0 },
                    "is_vip": { "type": "boolean" },
                    "last_replied_at_ms": { "type": ["integer", "null"] },
                    "notes": { "type": ["string", "null"] }
                }
            },
            "ContactRecord": {
                "type": "object",
                "required": ["email", "domain", "sent_count", "received_count", "replied_by_me_count", "is_vip"],
                "properties": {
                    "email": { "type": "string" },
                    "display_name": { "type": ["string", "null"] },
                    "domain": { "type": "string" },
                    "sent_count": { "type": "integer", "minimum": 0 },
                    "received_count": { "type": "integer", "minimum": 0 },
                    "replied_by_me_count": { "type": "integer", "minimum": 0 },
                    "is_vip": { "type": "boolean" },
                    "vip_override": { "type": ["boolean", "null"] },
                    "first_seen_at_ms": { "type": ["integer", "null"] },
                    "last_seen_at_ms": { "type": ["integer", "null"] },
                    "last_replied_at_ms": { "type": ["integer", "null"] },
                    "notes": { "type": ["string", "null"] }
                }
            },
            "ContactPatch": {
                "type": "object",
                "properties": {
                    "is_vip": { "type": ["boolean", "null"] },
                    "display_name": { "type": ["string", "null"] },
                    "notes": { "type": ["string", "null"] }
                }
            }
        }),
    );

    merge_json_object(
        &mut schemas,
        json!({
            "CompactMessage": {
                "type": "object",
                "required": [
                    "id", "thread_id", "date", "from", "to", "subject",
                    "snippet", "labels", "unread", "has_attachments",
                    "text_truncated", "text_total_chars"
                ],
                "properties": {
                    "id": { "type": "string" },
                    "thread_id": { "type": "string" },
                    "date": { "type": "string", "format": "date-time" },
                    "from": ref_schema("EmailAddress"),
                    "sender_contact": ref_schema("ContactSummary"),
                    "to": { "type": "array", "items": ref_schema("EmailAddress") },
                    "cc": { "type": "array", "items": ref_schema("EmailAddress") },
                    "subject": { "type": "string" },
                    "snippet": { "type": "string" },
                    "labels": { "type": "array", "items": { "type": "string" } },
                    "unread": { "type": "boolean" },
                    "has_attachments": { "type": "boolean" },
                    "attachments_meta": { "type": "array", "items": ref_schema("AttachmentMeta") },
                    "attachments_text": { "type": "array", "items": ref_schema("AttachmentTextExtraction") },
                    "text": { "type": ["string", "null"] },
                    "text_format": { "type": ["string", "null"] },
                    "text_truncated": { "type": "boolean" },
                    "text_total_chars": { "type": "integer", "minimum": 0 },
                    "html": { "type": ["string", "null"] },
                    "links": { "type": "array", "items": ref_schema("ExtractedLink") },
                    "in_reply_to": { "type": ["string", "null"] },
                    "rfc_message_id": { "type": ["string", "null"] },
                    "unsubscribe": ref_schema("UnsubscribeInfo"),
                    "_meta": ref_schema("UntrustedMeta")
                }
            },
            "MessageListResponse": {
                "type": "object",
                "required": ["messages", "has_more"],
                "properties": {
                    "messages": { "type": "array", "items": ref_schema("CompactMessage") },
                    "next_cursor": { "type": ["string", "null"] },
                    "has_more": { "type": "boolean" }
                }
            },
            "ThreadAnnotation": {
                "type": "object",
                "required": ["thread_id", "extracted", "updated_at"],
                "properties": {
                    "thread_id": { "type": "string" },
                    "summary": { "type": ["string", "null"] },
                    "needs_reply": { "type": ["boolean", "null"] },
                    "waiting_on": { "type": ["string", "null"], "enum": ["me", "them", "none", null] },
                    "priority": { "type": ["string", "null"] },
                    "due_at": { "type": ["string", "null"], "format": "date-time" },
                    "extracted": { "type": "object" },
                    "updated_by": { "type": ["string", "null"] },
                    "updated_at": { "type": "string", "format": "date-time" }
                }
            },
            "ThreadAnnotationEnvelope": {
                "type": "object",
                "required": ["thread_id", "annotation"],
                "properties": {
                    "thread_id": { "type": "string" },
                    "annotation": {
                        "oneOf": [
                            ref_schema("ThreadAnnotation"),
                            { "type": "null" }
                        ]
                    }
                }
            },
            "UpsertThreadAnnotationRequest": {
                "type": "object",
                "properties": {
                    "summary": { "type": ["string", "null"] },
                    "needs_reply": { "type": ["boolean", "null"] },
                    "waiting_on": { "type": ["string", "null"], "enum": ["me", "them", "none", null] },
                    "priority": { "type": ["string", "null"] },
                    "due_at": { "type": ["string", "null"], "format": "date-time" },
                    "extracted": { "type": "object" },
                    "updated_by": { "type": ["string", "null"] }
                }
            },
            "PatchThreadAnnotationRequest": {
                "type": "object",
                "properties": {
                    "summary": { "type": ["string", "null"] },
                    "needs_reply": { "type": ["boolean", "null"] },
                    "waiting_on": { "type": ["string", "null"], "enum": ["me", "them", "none", null] },
                    "priority": { "type": ["string", "null"] },
                    "due_at": { "type": ["string", "null"], "format": "date-time" },
                    "extracted": { "type": "object" },
                    "updated_by": { "type": ["string", "null"] }
                }
            },
            "ThreadSummary": {
                "type": "object",
                "required": [
                    "id", "subject", "participants", "snippet", "labels",
                    "unread", "has_attachments", "message_count", "last_message_at"
                ],
                "properties": {
                    "id": { "type": "string" },
                    "subject": { "type": "string" },
                    "participants": { "type": "array", "items": ref_schema("EmailAddress") },
                    "sender_contact": ref_schema("ContactSummary"),
                    "snippet": { "type": "string" },
                    "labels": { "type": "array", "items": { "type": "string" } },
                    "unread": { "type": "boolean" },
                    "has_attachments": { "type": "boolean" },
                    "message_count": { "type": "integer", "minimum": 0 },
                    "last_message_at": { "type": "string", "format": "date-time" },
                    "annotation": ref_schema("ThreadAnnotation")
                }
            },
            "ThreadListResponse": {
                "type": "object",
                "required": ["threads", "has_more"],
                "properties": {
                    "threads": { "type": "array", "items": ref_schema("ThreadSummary") },
                    "next_cursor": { "type": ["string", "null"] },
                    "has_more": { "type": "boolean" }
                }
            },
            "ThreadDetail": {
                "type": "object",
                "required": [
                    "id", "subject", "participants", "labels", "unread",
                    "message_count", "last_message_at", "messages"
                ],
                "properties": {
                    "id": { "type": "string" },
                    "subject": { "type": "string" },
                    "participants": { "type": "array", "items": ref_schema("EmailAddress") },
                    "labels": { "type": "array", "items": { "type": "string" } },
                    "unread": { "type": "boolean" },
                    "message_count": { "type": "integer", "minimum": 0 },
                    "last_message_at": { "type": "string", "format": "date-time" },
                    "messages": { "type": "array", "items": ref_schema("CompactMessage") },
                    "annotation": ref_schema("ThreadAnnotation"),
                    "_meta": ref_schema("UntrustedMeta")
                }
            },
            "ReplyContextResponse": {
                "type": "object",
                "required": ["thread", "participants", "style_samples", "related_threads"],
                "properties": {
                    "thread": ref_schema("ThreadDetail"),
                    "annotation": ref_schema("ThreadAnnotation"),
                    "participants": { "type": "array", "items": ref_schema("ContactRecord") },
                    "primary_recipient": { "type": ["string", "null"] },
                    "style_samples": { "type": "array", "items": ref_schema("CompactMessage") },
                    "related_threads": { "type": "array", "items": ref_schema("ThreadSummary") },
                    "_meta": ref_schema("UntrustedMeta")
                }
            }
        }),
    );

    merge_json_object(
        &mut schemas,
        json!({
            "BriefingCounts": {
                "type": "object",
                "required": [
                    "unread_total", "inbox_total", "pending_approvals_count",
                    "snoozed_count", "vip_unread_count", "followup_due_count"
                ],
                "properties": {
                    "unread_total": { "type": "integer", "minimum": 0 },
                    "inbox_total": { "type": "integer", "minimum": 0 },
                    "pending_approvals_count": { "type": "integer", "minimum": 0 },
                    "snoozed_count": { "type": "integer", "minimum": 0 },
                    "vip_unread_count": { "type": "integer", "minimum": 0 },
                    "followup_due_count": { "type": "integer", "minimum": 0 }
                }
            },
            "FollowUpCandidate": {
                "type": "object",
                "required": ["thread_id", "subject", "to", "last_sent_at", "days_since_sent", "snippet"],
                "properties": {
                    "thread_id": { "type": "string" },
                    "subject": { "type": "string" },
                    "to": { "type": "array", "items": { "type": "string" } },
                    "last_sent_at": { "type": "string", "format": "date-time" },
                    "days_since_sent": { "type": "integer" },
                    "snippet": { "type": "string" }
                }
            },
            "ApprovalBriefingItem": {
                "type": "object",
                "required": ["id", "reason", "to", "subject", "created_at", "expires_at"],
                "properties": {
                    "id": { "type": "string" },
                    "reason": { "type": "string" },
                    "to": { "type": "array", "items": { "type": "string" } },
                    "subject": { "type": "string" },
                    "created_at": { "type": "string", "format": "date-time" },
                    "expires_at": { "type": "string", "format": "date-time" }
                }
            },
            "SnoozedThread": {
                "type": "object",
                "required": ["thread_id", "snoozed_until_ms", "created_at_ms"],
                "properties": {
                    "thread_id": { "type": "string" },
                    "snoozed_until_ms": { "type": "integer" },
                    "created_at_ms": { "type": "integer" }
                }
            },
            "BriefingResponse": {
                "type": "object",
                "required": [
                    "generated_at", "counts", "vip_unread_threads", "needs_reply_threads",
                    "follow_up_due", "pending_approvals", "due_snoozes"
                ],
                "properties": {
                    "generated_at": { "type": "string", "format": "date-time" },
                    "counts": ref_schema("BriefingCounts"),
                    "vip_unread_threads": { "type": "array", "items": ref_schema("ThreadSummary") },
                    "needs_reply_threads": { "type": "array", "items": ref_schema("ThreadSummary") },
                    "follow_up_due": { "type": "array", "items": ref_schema("FollowUpCandidate") },
                    "pending_approvals": { "type": "array", "items": ref_schema("ApprovalBriefingItem") },
                    "due_snoozes": { "type": "array", "items": ref_schema("SnoozedThread") }
                }
            },
            "PolicyCheckResult": {
                "type": "object",
                "required": ["rule", "passed", "detail"],
                "properties": {
                    "rule": { "type": "string" },
                    "passed": { "type": "boolean" },
                    "detail": { "type": "string" }
                }
            },
            "DryRunPreview": {
                "type": "object",
                "required": ["from", "to", "subject", "estimated_bytes"],
                "properties": {
                    "from": { "type": "string" },
                    "to": { "type": "array", "items": { "type": "string" } },
                    "cc": { "type": "array", "items": { "type": "string" } },
                    "bcc": { "type": "array", "items": { "type": "string" } },
                    "subject": { "type": "string" },
                    "thread_id": { "type": ["string", "null"] },
                    "in_reply_to": { "type": ["string", "null"] },
                    "estimated_bytes": { "type": "integer", "minimum": 0 }
                }
            },
            "DryRunResponse": {
                "type": "object",
                "required": ["dry_run", "would_succeed", "policy_checks"],
                "properties": {
                    "dry_run": { "type": "boolean" },
                    "would_succeed": { "type": "boolean" },
                    "policy_checks": { "type": "array", "items": ref_schema("PolicyCheckResult") },
                    "preview": ref_schema("DryRunPreview"),
                    "warnings": { "type": "array", "items": { "type": "string" } }
                }
            },
            "AiSendEmailRequest": {
                "type": "object",
                "properties": {
                    "to": { "type": "array", "items": { "type": "string" } },
                    "cc": { "type": "array", "items": { "type": "string" } },
                    "bcc": { "type": "array", "items": { "type": "string" } },
                    "subject": { "type": ["string", "null"] },
                    "text": { "type": ["string", "null"] },
                    "html": { "type": ["string", "null"] },
                    "reply_to_message_id": { "type": ["string", "null"] },
                    "dry_run": { "type": "boolean", "default": false },
                    "idempotency_key": { "type": ["string", "null"] },
                    "send_at": { "type": ["string", "null"], "format": "date-time" }
                }
            },
            "AiCreateDraftRequest": {
                "type": "object",
                "properties": {
                    "to": { "type": "array", "items": { "type": "string" } },
                    "cc": { "type": "array", "items": { "type": "string" } },
                    "bcc": { "type": "array", "items": { "type": "string" } },
                    "subject": { "type": ["string", "null"] },
                    "text": { "type": ["string", "null"] },
                    "html": { "type": ["string", "null"] },
                    "reply_to_message_id": { "type": ["string", "null"] },
                    "idempotency_key": { "type": ["string", "null"] }
                }
            },
            "AiSendDraftRequest": {
                "type": "object",
                "properties": {
                    "dry_run": { "type": "boolean", "default": false }
                }
            },
            "AiUnsubscribeRequest": {
                "type": "object",
                "properties": {
                    "dry_run": { "type": "boolean", "default": false },
                    "prefer_mailto": { "type": "boolean", "default": false }
                }
            },
            "SnoozeThreadRequest": {
                "type": "object",
                "required": ["until"],
                "properties": {
                    "until": { "type": "string", "format": "date-time" }
                }
            }
        }),
    );

    merge_json_object(
        &mut schemas,
        json!({
            "AiTriageRequest": {
                "type": "object",
                "properties": {
                    "archive": { "type": ["boolean", "null"] },
                    "mark_read": { "type": ["boolean", "null"] },
                    "mark_unread": { "type": ["boolean", "null"] },
                    "star": { "type": ["boolean", "null"] },
                    "trash": { "type": ["boolean", "null"] },
                    "add_labels": { "type": "array", "items": { "type": "string" } },
                    "remove_labels": { "type": "array", "items": { "type": "string" } },
                    "dry_run": { "type": "boolean", "default": false }
                }
            },
            "AiBatchTriageOperation": {
                "type": "object",
                "required": ["thread_id"],
                "properties": {
                    "thread_id": { "type": "string" },
                    "archive": { "type": ["boolean", "null"] },
                    "mark_read": { "type": ["boolean", "null"] },
                    "mark_unread": { "type": ["boolean", "null"] },
                    "star": { "type": ["boolean", "null"] },
                    "trash": { "type": ["boolean", "null"] },
                    "add_labels": { "type": "array", "items": { "type": "string" } },
                    "remove_labels": { "type": "array", "items": { "type": "string" } }
                }
            },
            "AiBatchTriageRequest": {
                "type": "object",
                "properties": {
                    "operations": { "type": "array", "items": ref_schema("AiBatchTriageOperation") },
                    "thread_ids": { "type": "array", "items": { "type": "string" } },
                    "query": { "type": ["string", "null"] },
                    "include_spam_trash": { "type": "boolean", "default": false },
                    "action": ref_schema("AiTriageRequest"),
                    "archive": { "type": ["boolean", "null"] },
                    "mark_read": { "type": ["boolean", "null"] },
                    "mark_unread": { "type": ["boolean", "null"] },
                    "star": { "type": ["boolean", "null"] },
                    "trash": { "type": ["boolean", "null"] },
                    "add_labels": { "type": "array", "items": { "type": "string" } },
                    "remove_labels": { "type": "array", "items": { "type": "string" } },
                    "dry_run": { "type": "boolean", "default": false },
                    "max_threads": { "type": ["integer", "null"], "minimum": 1, "maximum": 500 }
                }
            },
            "BatchTriagePreviewItem": {
                "type": "object",
                "required": ["thread_id", "subject", "current_labels", "labels_to_add", "labels_to_remove", "would_change"],
                "properties": {
                    "thread_id": { "type": "string" },
                    "subject": { "type": "string" },
                    "current_labels": { "type": "array", "items": { "type": "string" } },
                    "labels_to_add": { "type": "array", "items": { "type": "string" } },
                    "labels_to_remove": { "type": "array", "items": { "type": "string" } },
                    "would_change": { "type": "boolean" }
                }
            },
            "BatchTriageDryRunResponse": {
                "type": "object",
                "required": ["dry_run", "total_threads", "would_change_count", "preview"],
                "properties": {
                    "dry_run": { "type": "boolean" },
                    "total_threads": { "type": "integer", "minimum": 0 },
                    "would_change_count": { "type": "integer", "minimum": 0 },
                    "preview": { "type": "array", "items": ref_schema("BatchTriagePreviewItem") }
                }
            },
            "BatchTriageThreadResult": {
                "type": "object",
                "required": ["thread_id", "subject", "changed", "affected_message_ids", "labels", "added_labels", "removed_labels"],
                "properties": {
                    "thread_id": { "type": "string" },
                    "subject": { "type": "string" },
                    "changed": { "type": "boolean" },
                    "affected_message_ids": { "type": "array", "items": { "type": "string" } },
                    "labels": { "type": "array", "items": { "type": "string" } },
                    "added_labels": { "type": "array", "items": { "type": "string" } },
                    "removed_labels": { "type": "array", "items": { "type": "string" } }
                }
            },
            "BatchTriageThreadError": {
                "type": "object",
                "required": ["thread_id", "code", "message"],
                "properties": {
                    "thread_id": { "type": "string" },
                    "code": { "type": "string" },
                    "message": { "type": "string" }
                }
            },
            "BatchTriageApplyResponse": {
                "type": "object",
                "required": ["dry_run", "total_threads", "applied_count", "skipped_count", "errors", "results"],
                "properties": {
                    "dry_run": { "type": "boolean" },
                    "total_threads": { "type": "integer", "minimum": 0 },
                    "applied_count": { "type": "integer", "minimum": 0 },
                    "skipped_count": { "type": "integer", "minimum": 0 },
                    "errors": { "type": "array", "items": ref_schema("BatchTriageThreadError") },
                    "results": { "type": "array", "items": ref_schema("BatchTriageThreadResult") }
                }
            },
            "AiModifyLabelsRequest": {
                "type": "object",
                "properties": {
                    "message_ids": { "type": "array", "items": { "type": "string" } },
                    "thread_ids": { "type": "array", "items": { "type": "string" } },
                    "add_labels": { "type": "array", "items": { "type": "string" } },
                    "remove_labels": { "type": "array", "items": { "type": "string" } },
                    "archive": { "type": ["boolean", "null"] },
                    "mark_read": { "type": ["boolean", "null"] },
                    "trash": { "type": ["boolean", "null"] },
                    "dry_run": { "type": "boolean", "default": false }
                }
            },
            "ScheduledSend": {
                "type": "object",
                "required": ["id", "status", "send_at_ms", "created_at_ms"],
                "properties": {
                    "id": { "type": "string" },
                    "status": { "type": "string", "enum": ["pending", "sending", "sent", "canceled", "failed"] },
                    "send_at_ms": { "type": "integer" },
                    "thread_id": { "type": ["string", "null"] },
                    "created_at_ms": { "type": "integer" },
                    "sent_message_id": { "type": ["string", "null"] },
                    "provider_message_id": { "type": ["string", "null"] },
                    "last_error": { "type": ["string", "null"] }
                }
            },
            "PendingApproval": {
                "type": "object",
                "required": ["id", "status", "reason", "created_at_ms", "expires_at_ms"],
                "properties": {
                    "id": { "type": "string" },
                    "status": { "type": "string", "enum": ["pending", "approving", "approved", "rejected", "expired"] },
                    "reason": { "type": "string" },
                    "thread_id": { "type": ["string", "null"] },
                    "draft_id": { "type": ["string", "null"] },
                    "created_at_ms": { "type": "integer" },
                    "expires_at_ms": { "type": "integer" },
                    "decided_by": { "type": ["string", "null"] },
                    "decision_note": { "type": ["string", "null"] },
                    "sent_message_id": { "type": ["string", "null"] }
                }
            },
            "ApprovalDecisionRequest": {
                "type": "object",
                "properties": {
                    "decided_by": { "type": ["string", "null"] },
                    "note": { "type": ["string", "null"] }
                }
            }
        }),
    );

    merge_json_object(
        &mut schemas,
        json!({
            "InboxRuleActions": {
                "type": "object",
                "properties": {
                    "add_labels": { "type": "array", "items": { "type": "string" } },
                    "remove_labels": { "type": "array", "items": { "type": "string" } },
                    "archive": { "type": "boolean", "default": false },
                    "mark_read": { "type": "boolean", "default": false },
                    "webhook_url": { "type": ["string", "null"] },
                    "webhook_secret": { "type": ["string", "null"] }
                }
            },
            "InboxRule": {
                "type": "object",
                "required": ["id", "name", "enabled", "vip_only", "actions"],
                "properties": {
                    "id": { "type": "string" },
                    "name": { "type": "string" },
                    "enabled": { "type": "boolean" },
                    "match_query": { "type": ["string", "null"] },
                    "vip_only": { "type": "boolean" },
                    "actions": ref_schema("InboxRuleActions"),
                    "created_at_ms": { "type": "integer" },
                    "updated_at_ms": { "type": "integer" }
                }
            },
            "NewInboxRule": {
                "type": "object",
                "required": ["name", "actions"],
                "properties": {
                    "name": { "type": "string" },
                    "enabled": { "type": "boolean", "default": true },
                    "match_query": { "type": ["string", "null"] },
                    "vip_only": { "type": "boolean", "default": false },
                    "actions": ref_schema("InboxRuleActions")
                }
            },
            "InboxRulePatch": {
                "type": "object",
                "properties": {
                    "name": { "type": ["string", "null"] },
                    "enabled": { "type": ["boolean", "null"] },
                    "match_query": { "type": ["string", "null"] },
                    "vip_only": { "type": ["boolean", "null"] },
                    "actions": ref_schema("InboxRuleActions")
                }
            },
            "AuditLogEntry": {
                "type": "object",
                "required": ["id", "timestamp_ms", "actor", "scopes", "channel", "action", "target_ids", "outcome"],
                "properties": {
                    "id": { "type": "integer" },
                    "timestamp_ms": { "type": "integer" },
                    "actor": { "type": "string" },
                    "scopes": { "type": "array", "items": { "type": "string" } },
                    "channel": { "type": "string" },
                    "action": { "type": "string" },
                    "target_ids": { "type": "array", "items": { "type": "string" } },
                    "outcome": { "type": "string" },
                    "detail": { "type": ["string", "null"] }
                }
            },
            "LabelSummary": {
                "type": "object",
                "required": ["id", "name", "kind", "messages_total", "messages_unread", "threads_total", "threads_unread"],
                "properties": {
                    "id": { "type": "string" },
                    "name": { "type": "string" },
                    "kind": { "type": "string" },
                    "messages_total": { "type": "integer", "minimum": 0 },
                    "messages_unread": { "type": "integer", "minimum": 0 },
                    "threads_total": { "type": "integer", "minimum": 0 },
                    "threads_unread": { "type": "integer", "minimum": 0 }
                }
            },
            "SyncTriggerRequest": {
                "type": "object",
                "properties": {
                    "mode": { "type": ["string", "null"], "enum": ["incremental", "full", null] },
                    "provider": { "type": ["string", "null"], "enum": ["api", "imap", null] },
                    "max_messages": { "type": ["integer", "null"], "minimum": 1 },
                    "query": { "type": ["string", "null"] },
                    "bidirectional": { "type": ["boolean", "null"] }
                }
            },
            "CapabilitiesResponse": {
                "type": "object",
                "required": ["service", "version", "user_email", "mcp_endpoint", "endpoints", "safety", "backends"],
                "properties": {
                    "service": { "type": "string" },
                    "version": { "type": "string" },
                    "user_email": { "type": "string" },
                    "mcp_endpoint": { "type": "string" },
                    "endpoints": { "type": "array", "items": { "type": "string" } },
                    "safety": { "type": "object" },
                    "search_operators": { "type": "array", "items": { "type": "string" } },
                    "sync_enabled": { "type": "boolean" },
                    "sync_mode": { "type": "string" },
                    "imap_enabled": { "type": "boolean" },
                    "oauth2_enabled": { "type": "boolean" },
                    "encryption_at_rest": { "type": "boolean" },
                    "active_filters": { "type": "array", "items": { "type": "string" } },
                    "active_outbound_policies": { "type": "array", "items": { "type": "string" } },
                    "backends": { "type": "object" }
                }
            }
        }),
    );

    Value::Object(schemas)
}

/// Build the complete OpenAPI 3.1.0 JSON specification for all `/v1/*` endpoints.
pub fn openapi_spec() -> Value {
    json!({
        "openapi": "3.1.0",
        "jsonSchemaDialect": "https://spec.openapis.org/oas/3.1/dialect/base",
        "info": {
            "title": "nogml AI REST API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "AI-first headless email REST and SSE API (/v1) with safety guardrails, approvals, annotations, reply context, daily briefings, inbox rules, and Gmail sync.",
            "license": {
                "name": "Apache-2.0"
            }
        },
        "servers": [
            {
                "url": "/",
                "description": "Current nogml server"
            }
        ],
        "security": [
            { "bearerAuth": [] },
            { "apiKeyHeader": [] },
            { "accessTokenQuery": [] },
            { "oauth2": ["read", "write", "send", "admin"] }
        ],
        "tags": [
            { "name": "Discovery", "description": "Server capabilities and OpenAPI specification." },
            { "name": "Briefing", "description": "Daily briefing and follow-up detector." },
            { "name": "Threads", "description": "Thread reading, triage, snooze, reply context, and annotations." },
            { "name": "Messages", "description": "Message reading, sending, attachments, label updates, and unsubscribe." },
            { "name": "Drafts", "description": "Draft creation, listing, sending, and deletion." },
            { "name": "Scheduled", "description": "Scheduled outbound send inspection and cancellation." },
            { "name": "Approvals", "description": "Human-in-the-loop outbound approval queue." },
            { "name": "Contacts", "description": "Per-mailbox contact graph and VIP overrides." },
            { "name": "Rules", "description": "Event-driven inbox rules and dry-run testing." },
            { "name": "Audit", "description": "Immutable append-only agent and API audit log." },
            { "name": "Labels", "description": "Mailbox system and user label metadata." },
            { "name": "Search", "description": "Full-text and hybrid semantic search." },
            { "name": "Events", "description": "Real-time Server-Sent Events stream." },
            { "name": "Sync", "description": "Upstream Gmail sync triggers and status." }
        ],
        "paths": build_paths(),
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "API token or HS256 JWT",
                    "description": "Static token, scoped API key, or local OAuth2 access token via Authorization: Bearer <token>."
                },
                "apiKeyHeader": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                    "description": "Static token or scoped API key passed in the X-API-Key request header."
                },
                "accessTokenQuery": {
                    "type": "apiKey",
                    "in": "query",
                    "name": "access_token",
                    "description": "Optional query parameter token for clients unable to send custom headers (such as browser EventSource)."
                },
                "oauth2": {
                    "type": "oauth2",
                    "description": "Local OAuth2 HS256 JWT authorization server (when enabled via NOGML_OAUTH2_CLIENT_ID and NOGML_OAUTH2_SIGNING_SECRET).",
                    "flows": {
                        "authorizationCode": {
                            "authorizationUrl": "/oauth2/authorize",
                            "tokenUrl": "/oauth2/token",
                            "refreshUrl": "/oauth2/token",
                            "scopes": {
                                "read": "Read threads, messages, labels, contacts, rules, audit log, briefings, and SSE events.",
                                "write": "Create or delete drafts, triage threads, snooze, annotate, manage rules, and trigger sync.",
                                "send": "Send outbound emails, send drafts, and execute mailto unsubscribes.",
                                "admin": "Inspect, approve, or reject human-in-the-loop outbound approvals and full administrative access."
                            }
                        },
                        "clientCredentials": {
                            "tokenUrl": "/oauth2/token",
                            "scopes": {
                                "read": "Read access.",
                                "write": "Write access.",
                                "send": "Outbound send access.",
                                "admin": "Full administrative access."
                            }
                        }
                    }
                }
            },
            "parameters": {
                "Fields": {
                    "name": "fields",
                    "in": "query",
                    "required": false,
                    "description": "Optional field projection mask (for example id,subject,messages(id,from)).",
                    "schema": { "type": "string" }
                }
            },
            "responses": {
                "BadRequest": {
                    "description": "Invalid request parameters, validation failure, or malformed JSON payload.",
                    "content": json_content(ref_schema("AiErrorEnvelope"))
                },
                "Unauthorized": {
                    "description": "Missing or invalid credentials.",
                    "content": json_content(ref_schema("AiErrorEnvelope"))
                },
                "Forbidden": {
                    "description": "Insufficient scope or outbound safety policy denial (draft_only, allowed_recipients, or DLP).",
                    "content": json_content(ref_schema("AiErrorEnvelope"))
                },
                "NotFound": {
                    "description": "Requested resource does not exist in the active mailbox.",
                    "content": json_content(ref_schema("AiErrorEnvelope"))
                },
                "Conflict": {
                    "description": "Resource state conflict (for example approval already resolved or in flight).",
                    "content": json_content(ref_schema("AiErrorEnvelope"))
                },
                "InternalError": {
                    "description": "Storage, upstream, or unexpected internal error.",
                    "content": json_content(ref_schema("AiErrorEnvelope"))
                }
            },
            "schemas": build_schemas()
        }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn collect_refs(val: &Value, out: &mut Vec<String>) {
        match val {
            Value::Object(map) => {
                if let Some(r) = map.get("$ref").and_then(Value::as_str) {
                    out.push(r.to_string());
                }
                for v in map.values() {
                    collect_refs(v, out);
                }
            }
            Value::Array(items) => {
                for item in items {
                    collect_refs(item, out);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn openapi_spec_is_valid_3_1_and_resolves_all_refs() {
        let spec = openapi_spec();
        assert_eq!(spec["openapi"], "3.1.0");
        assert!(spec["info"]["title"].is_string());
        assert!(spec["info"]["version"].is_string());

        let components = spec["components"].as_object().expect("components object");
        let schemas = components["schemas"].as_object().expect("schemas object");
        let parameters = components["parameters"]
            .as_object()
            .expect("parameters object");
        let responses = components["responses"]
            .as_object()
            .expect("responses object");
        let sec_schemes = components["securitySchemes"]
            .as_object()
            .expect("securitySchemes object");

        for required_scheme in ["bearerAuth", "apiKeyHeader", "oauth2"] {
            assert!(
                sec_schemes.contains_key(required_scheme),
                "missing securityScheme {required_scheme}"
            );
        }

        let mut refs = Vec::new();
        collect_refs(&spec, &mut refs);
        assert!(!refs.is_empty());
        for r in refs {
            if let Some(name) = r.strip_prefix("#/components/schemas/") {
                assert!(schemas.contains_key(name), "unresolved schema ref: {r}");
            } else if let Some(name) = r.strip_prefix("#/components/parameters/") {
                assert!(
                    parameters.contains_key(name),
                    "unresolved parameter ref: {r}"
                );
            } else if let Some(name) = r.strip_prefix("#/components/responses/") {
                assert!(responses.contains_key(name), "unresolved response ref: {r}");
            } else {
                panic!("unexpected $ref target: {r}");
            }
        }
    }

    #[test]
    fn openapi_paths_match_canonical_v1_operations_with_unique_operation_ids() {
        let spec = openapi_spec();
        let paths = spec["paths"].as_object().expect("paths object");

        let mut op_ids = HashSet::new();
        let mut documented = HashSet::new();
        for (path, item) in paths {
            let item_obj = item.as_object().expect("path item object");
            for (method, op) in item_obj {
                documented.insert((method.as_str(), path.as_str()));
                let op_id = op["operationId"]
                    .as_str()
                    .unwrap_or_else(|| panic!("missing operationId on {method} {path}"));
                assert!(
                    op_ids.insert(op_id.to_string()),
                    "duplicate operationId: {op_id}"
                );
            }
        }

        let expected: HashSet<(&str, &str)> = V1_OPENAPI_OPERATIONS.iter().copied().collect();
        assert_eq!(documented, expected);
    }
}
