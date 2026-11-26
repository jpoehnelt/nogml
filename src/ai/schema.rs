//! Runtime JSON Schema manifest for `nogml schema [--command <name>]`
//! and `GET /v1/capabilities`.

use serde_json::{Value, json};

/// Build a self-describing runtime schema manifest for CLI subcommands and `/v1/` endpoints.
pub fn runtime_schema(command: Option<&str>) -> Value {
    let mut commands = json!({
        "mail.search": {
            "endpoint": "GET /v1/search",
            "mcp_tool": "search_emails",
            "description": "Search messages using FTS5 full-text search and structured filters.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "q": { "type": "string", "description": "Full-text or semantic search query" },
                    "labels": { "type": "array", "items": { "type": "string" } },
                    "unread": { "type": "boolean" },
                    "from": { "type": "string" },
                    "to": { "type": "string" },
                    "after": { "type": "string", "format": "date-time" },
                    "before": { "type": "string", "format": "date-time" },
                    "has_attachment": { "type": "boolean" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 },
                    "cursor": { "type": "string" },
                    "include_body": { "type": "boolean", "default": false },
                    "max_body_chars": { "type": "integer", "minimum": 0, "maximum": 100000, "default": 1000 },
                    "fields": { "type": "string", "description": "Optional field projection mask" }
                }
            }
        },
        "mail.threads": {
            "endpoint": "GET /v1/threads",
            "mcp_tool": "list_threads",
            "description": "List conversation thread summaries, optionally filtered by annotation fields.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "q": { "type": "string" },
                    "label": { "type": "string" },
                    "unread_only": { "type": "boolean", "default": false },
                    "needs_reply": { "type": "boolean" },
                    "waiting_on": { "type": "string", "enum": ["me", "them", "none"] },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 },
                    "cursor": { "type": "string" },
                    "fields": { "type": "string" }
                }
            }
        },
        "mail.annotations": {
            "endpoint": "GET /v1/threads/{id}/annotations | PUT /v1/threads/{id}/annotations | PATCH /v1/threads/{id}/annotations | DELETE /v1/threads/{id}/annotations",
            "mcp_tool": "get_thread_annotations | annotate_thread",
            "description": "Read, replace, patch, or delete persistent structured annotations and extracted state on a thread.",
            "inputSchema": {
                "type": "object",
                "required": ["thread_id"],
                "properties": {
                    "thread_id": { "type": "string" },
                    "summary": { "type": "string" },
                    "needs_reply": { "type": "boolean" },
                    "waiting_on": { "type": "string", "enum": ["me", "them", "none"] },
                    "priority": { "type": "string" },
                    "due_at": { "type": "string", "format": "date-time" },
                    "extracted": { "type": "object" },
                    "updated_by": { "type": "string" }
                }
            }
        },
        "mail.reply_context": {
            "endpoint": "GET /v1/threads/{id}/reply-context",
            "mcp_tool": "get_reply_context",
            "description": "Fetch the quote-stripped thread, annotation, participant contacts, recent sent style samples to the primary recipient, and related threads in one call.",
            "inputSchema": {
                "type": "object",
                "required": ["thread_id"],
                "properties": {
                    "thread_id": { "type": "string" },
                    "max_body_chars": { "type": "integer", "minimum": 0, "maximum": 100000 },
                    "max_style_samples": { "type": "integer", "minimum": 0, "maximum": 10, "default": 3 },
                    "max_related_threads": { "type": "integer", "minimum": 0, "maximum": 20, "default": 5 },
                    "fields": { "type": "string" }
                }
            }
        },
        "mail.read": {
            "endpoint": "GET /v1/messages/{id} | GET /v1/threads/{id}",
            "mcp_tool": "read_email | read_thread",
            "description": "Read a compact message or full thread with body truncation and quote stripping.",
            "inputSchema": {
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": { "type": "string" },
                    "thread": { "type": "boolean", "default": false },
                    "max_body_chars": { "type": "integer", "minimum": 0, "maximum": 100000, "default": 4000 },
                    "strip_quotes": { "type": "boolean", "default": false },
                    "include_html": { "type": "boolean", "default": false },
                    "include_attachments_meta": { "type": "boolean", "default": true },
                    "extract_attachment_text": { "type": "boolean", "default": false },
                    "attachment_max_chars": { "type": "integer", "minimum": 0, "maximum": 100000, "default": 20000 },
                    "fields": { "type": "string" }
                }
            }
        },
        "mail.attachment_text": {
            "endpoint": "GET /v1/messages/{id}/attachments/{attachment_id}/text",
            "mcp_tool": "read_attachment_text",
            "description": "Extract readable text or structured calendar data from a message attachment with strict byte and character ceilings.",
            "inputSchema": {
                "type": "object",
                "required": ["message_id", "attachment_id"],
                "properties": {
                    "message_id": { "type": "string" },
                    "attachment_id": { "type": "string" },
                    "max_chars": { "type": "integer", "minimum": 0, "maximum": 100000, "default": 20000 },
                    "fields": { "type": "string" }
                }
            }
        },
        "mail.send": {
            "endpoint": "POST /v1/messages/send",
            "mcp_tool": "send_email",
            "description": "Send an email via Resend with safety guardrails, reply threading, and dry_run preview.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "to": { "type": "array", "items": { "type": "string" } },
                    "cc": { "type": "array", "items": { "type": "string" } },
                    "bcc": { "type": "array", "items": { "type": "string" } },
                    "subject": { "type": "string" },
                    "text": { "type": "string" },
                    "html": { "type": "string" },
                    "reply_to_message_id": { "type": "string" },
                    "dry_run": { "type": "boolean", "default": false },
                    "idempotency_key": { "type": "string", "description": "Optional deduplication key (or Idempotency-Key HTTP header) cached for 24h per mailbox" },
                    "send_at": { "type": "string", "format": "date-time", "description": "Optional future RFC 3339 timestamp to schedule outbound delivery" }
                }
            }
        },
        "mail.snooze": {
            "endpoint": "POST /v1/threads/{id}/snooze | DELETE /v1/threads/{id}/snooze",
            "mcp_tool": "snooze_thread",
            "description": "Snooze a thread until a future RFC 3339 timestamp or unsnooze it immediately.",
            "inputSchema": {
                "type": "object",
                "required": ["thread_id", "until"],
                "properties": {
                    "thread_id": { "type": "string" },
                    "until": { "type": "string", "format": "date-time" }
                }
            }
        },
        "mail.scheduled": {
            "endpoint": "GET /v1/scheduled | DELETE /v1/scheduled/{id}",
            "mcp_tool": "list_scheduled_sends | cancel_scheduled_send",
            "description": "List or cancel scheduled outbound emails before dispatch.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "scheduled_id": { "type": "string" },
                    "status": { "type": "string", "enum": ["pending", "sent", "canceled", "failed", "all"] },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 }
                }
            }
        },
        "mail.draft": {
            "endpoint": "POST /v1/drafts",
            "mcp_tool": "create_draft",
            "description": "Create a local email draft (permitted even when draft_only=true).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "to": { "type": "array", "items": { "type": "string" } },
                    "cc": { "type": "array", "items": { "type": "string" } },
                    "bcc": { "type": "array", "items": { "type": "string" } },
                    "subject": { "type": "string" },
                    "text": { "type": "string" },
                    "html": { "type": "string" },
                    "reply_to_message_id": { "type": "string" },
                    "idempotency_key": { "type": "string", "description": "Optional deduplication key (or Idempotency-Key HTTP header) cached for 24h per mailbox" }
                }
            }
        },
        "mail.send_draft": {
            "endpoint": "POST /v1/drafts/{id}/send",
            "mcp_tool": "send_draft",
            "description": "Send an existing draft through safety guardrails (supports dry_run).",
            "inputSchema": {
                "type": "object",
                "required": ["draft_id"],
                "properties": {
                    "draft_id": { "type": "string" },
                    "dry_run": { "type": "boolean", "default": false }
                }
            }
        },
        "mail.triage": {
            "endpoint": "POST /v1/threads/{id}/triage",
            "mcp_tool": "triage_thread",
            "description": "Archive, mark read/unread, star, trash, or adjust labels on a thread (supports dry_run).",
            "inputSchema": {
                "type": "object",
                "required": ["thread_id"],
                "properties": {
                    "thread_id": { "type": "string" },
                    "archive": { "type": "boolean" },
                    "mark_read": { "type": "boolean" },
                    "mark_unread": { "type": "boolean" },
                    "star": { "type": "boolean" },
                    "trash": { "type": "boolean" },
                    "add_labels": { "type": "array", "items": { "type": "string" } },
                    "remove_labels": { "type": "array", "items": { "type": "string" } },
                    "dry_run": { "type": "boolean", "default": false }
                }
            }
        },
        "mail.batch_triage": {
            "endpoint": "POST /v1/threads/batch_triage",
            "mcp_tool": "batch_triage",
            "description": "Preview (dry_run: true) or atomically apply bulk triage operations across multiple threads via explicit operations and/or thread_ids or Gmail q= query with a shared action, bounded by max_threads (default 100, ceiling 500).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "operations": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["thread_id"],
                            "properties": {
                                "thread_id": { "type": "string" },
                                "archive": { "type": "boolean" },
                                "mark_read": { "type": "boolean" },
                                "mark_unread": { "type": "boolean" },
                                "star": { "type": "boolean" },
                                "trash": { "type": "boolean" },
                                "add_labels": { "type": "array", "items": { "type": "string" } },
                                "remove_labels": { "type": "array", "items": { "type": "string" } }
                            }
                        }
                    },
                    "thread_ids": { "type": "array", "items": { "type": "string" } },
                    "query": { "type": "string" },
                    "include_spam_trash": { "type": "boolean", "default": false },
                    "action": {
                        "type": "object",
                        "properties": {
                            "archive": { "type": "boolean" },
                            "mark_read": { "type": "boolean" },
                            "mark_unread": { "type": "boolean" },
                            "star": { "type": "boolean" },
                            "trash": { "type": "boolean" },
                            "add_labels": { "type": "array", "items": { "type": "string" } },
                            "remove_labels": { "type": "array", "items": { "type": "string" } }
                        }
                    },
                    "archive": { "type": "boolean" },
                    "mark_read": { "type": "boolean" },
                    "mark_unread": { "type": "boolean" },
                    "star": { "type": "boolean" },
                    "trash": { "type": "boolean" },
                    "add_labels": { "type": "array", "items": { "type": "string" } },
                    "remove_labels": { "type": "array", "items": { "type": "string" } },
                    "dry_run": { "type": "boolean", "default": false },
                    "max_threads": { "type": "integer", "minimum": 1, "maximum": 500, "default": 100 },
                    "fields": { "type": "string" }
                }
            }
        },
        "mail.modify_labels": {
            "endpoint": "POST /v1/messages/modify",
            "mcp_tool": "modify_labels",
            "description": "Modify labels across multiple message_ids and/or thread_ids (supports dry_run).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "message_ids": { "type": "array", "items": { "type": "string" } },
                    "thread_ids": { "type": "array", "items": { "type": "string" } },
                    "add_labels": { "type": "array", "items": { "type": "string" } },
                    "remove_labels": { "type": "array", "items": { "type": "string" } },
                    "archive": { "type": "boolean" },
                    "mark_read": { "type": "boolean" },
                    "trash": { "type": "boolean" },
                    "dry_run": { "type": "boolean", "default": false }
                }
            }
        },
        "mail.unsubscribe": {
            "endpoint": "POST /v1/messages/{id}/unsubscribe",
            "mcp_tool": "unsubscribe",
            "description": "Unsubscribe from a mailing list via RFC 8058 one-click HTTPS POST or mailto: with SSRF protection, outbound policy enforcement, and dry_run preview.",
            "inputSchema": {
                "type": "object",
                "required": ["message_id"],
                "properties": {
                    "message_id": { "type": "string" },
                    "dry_run": { "type": "boolean", "default": false },
                    "prefer_mailto": { "type": "boolean", "default": false }
                }
            }
        },
        "mail.labels": {
            "endpoint": "GET /v1/labels",
            "mcp_tool": "list_labels",
            "description": "List all system and user labels with message/thread counts.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        "mail.contacts": {
            "endpoint": "GET /v1/contacts | GET /v1/contacts/{email} | PATCH /v1/contacts/{email}",
            "mcp_tool": "lookup_contact | list_vips",
            "description": "Inspect the local per-mailbox contact graph, filter contacts or VIPs, and update VIP overrides or notes.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "email": { "type": "string" },
                    "q": { "type": "string" },
                    "vip_only": { "type": "boolean", "default": false },
                    "replied_only": { "type": "boolean", "default": false },
                    "domain": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 50 },
                    "is_vip": { "type": "boolean" },
                    "display_name": { "type": "string" },
                    "notes": { "type": "string" }
                }
            }
        },
        "mail.rules": {
            "endpoint": "GET /v1/rules | POST /v1/rules | PATCH /v1/rules/{id} | DELETE /v1/rules/{id} | POST /v1/rules/{id}/test",
            "mcp_tool": "list_rules | create_rule | delete_rule",
            "description": "Manage per-mailbox event-driven inbox rules with automatic label mutations and HMAC-SHA256 signed webhook triggers.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "name": { "type": "string" },
                    "enabled": { "type": "boolean", "default": true },
                    "match_query": { "type": "string" },
                    "vip_only": { "type": "boolean", "default": false },
                    "actions": {
                        "type": "object",
                        "properties": {
                            "add_labels": { "type": "array", "items": { "type": "string" } },
                            "remove_labels": { "type": "array", "items": { "type": "string" } },
                            "archive": { "type": "boolean", "default": false },
                            "mark_read": { "type": "boolean", "default": false },
                            "webhook_url": { "type": "string" },
                            "webhook_secret": { "type": "string" }
                        }
                    },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 }
                }
            }
        },
        "mail.approvals": {
            "endpoint": "GET /v1/approvals | GET /v1/approvals/{id} | POST /v1/approvals/{id}/approve | POST /v1/approvals/{id}/reject",
            "description": "List, inspect, approve, or reject outbound emails held for human approval.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["list", "get", "approve", "reject"] },
                    "id": { "type": "string" },
                    "status": { "type": "string", "enum": ["pending", "approved", "rejected", "expired", "all"], "default": "pending" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 },
                    "decided_by": { "type": "string" },
                    "note": { "type": "string" }
                }
            }
        },
        "mail.audit": {
            "endpoint": "GET /v1/audit",
            "description": "Query the immutable append-only agent and API audit log (newest-first, scoped by mailbox).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "description": "Filter by action (read, search, send, draft, triage, batch_triage, approve, reject, unsubscribe, modify, delete)" },
                    "actor": { "type": "string", "description": "Filter by actor identity" },
                    "since": { "type": "string", "description": "Unix epoch milliseconds or RFC 3339 timestamp" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 500, "default": 50 },
                    "fields": { "type": "string" }
                }
            }
        },
        "mail.watch": {
            "endpoint": "GET /v1/events",
            "description": "Stream real-time mail events via SSE (HTTP) or NDJSON (CLI).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "types": { "type": "string", "description": "Comma-separated event types" },
                    "label": { "type": "string" },
                    "thread_id": { "type": "string" },
                    "since_id": { "type": "integer", "minimum": 0 }
                }
            }
        },
        "sync.gmail": {
            "endpoint": "POST /v1/sync/gmail",
            "mcp_tool": "sync_gmail",
            "description": "Trigger an upstream Gmail sync pass (incremental or full).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "mode": { "type": "string", "enum": ["incremental", "full"], "default": "incremental" },
                    "provider": { "type": "string", "enum": ["api", "imap"] },
                    "max_messages": { "type": "integer", "minimum": 1 },
                    "query": { "type": "string" },
                    "bidirectional": { "type": "boolean", "description": "Override NOGML_SYNC_BIDIRECTIONAL for this run" }
                }
            }
        },
        "sync.status": {
            "endpoint": "GET /v1/sync/status",
            "mcp_tool": "sync_status",
            "description": "Inspect upstream Gmail sync state and mailbox counts.",
            "inputSchema": { "type": "object", "properties": {} }
        }
    });
    if let Some(obj) = commands.as_object_mut() {
        obj.insert(
            "mail.briefing".to_string(),
            json!({
                "endpoint": "GET /v1/briefing",
                "mcp_tool": "get_briefing",
                "description": "One compact daily briefing: unread VIP threads, needs_reply or waiting_on=me threads, sent threads with no reply after followup_days, pending outbound approvals, due snoozes, and counts. Also available as the nogml://briefing MCP resource. Summaries only, never full bodies.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "since": { "type": "string", "description": "RFC 3339 timestamp filter for unread VIP threads." },
                        "followup_days": { "type": "integer", "minimum": 0, "default": 3 },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 }
                    }
                }
            }),
        );
    }

    if let Some(name) = command {
        let normalized = name.trim().to_ascii_lowercase();
        let aliased = match normalized.as_str() {
            "search" | "search_emails" => "mail.search",
            "threads" | "list_threads" => "mail.threads",
            "read" | "read_email" | "read_thread" => "mail.read",
            "attachment_text" | "read_attachment_text" => "mail.attachment_text",
            "send" | "send_email" => "mail.send",
            "draft" | "create_draft" => "mail.draft",
            "send_draft" => "mail.send_draft",
            "triage" | "triage_thread" => "mail.triage",
            "batch_triage" | "batch-triage" => "mail.batch_triage",
            "snooze" | "snooze_thread" => "mail.snooze",
            "scheduled" | "list_scheduled_sends" | "cancel_scheduled_send" => "mail.scheduled",
            "annotations" | "annotate_thread" | "get_thread_annotations" => "mail.annotations",
            "reply_context" | "reply-context" | "get_reply_context" => "mail.reply_context",
            "modify" | "modify_labels" => "mail.modify_labels",
            "unsubscribe" => "mail.unsubscribe",
            "labels" | "list_labels" => "mail.labels",
            "briefing" | "get_briefing" => "mail.briefing",
            "contacts" | "lookup_contact" | "list_vips" | "vips" => "mail.contacts",
            "rules" | "list_rules" | "create_rule" | "delete_rule" => "mail.rules",
            "approvals" | "approve" | "reject" => "mail.approvals",
            "audit" | "audit_log" => "mail.audit",
            "watch" | "events" => "mail.watch",
            "sync" | "sync_gmail" => "sync.gmail",
            "sync_status" | "status" => "sync.status",
            other => other,
        };
        if let Some(entry) = commands.get(aliased) {
            return json!({
                "service": "nogml",
                "version": env!("CARGO_PKG_VERSION"),
                "command": aliased,
                "schema": entry,
            });
        }
        return json!({
            "service": "nogml",
            "version": env!("CARGO_PKG_VERSION"),
            "error": format!("Unknown schema command '{name}'"),
            "available_commands": commands.as_object().map(|m| m.keys().cloned().collect::<Vec<_>>()).unwrap_or_default(),
        });
    }

    json!({
        "service": "nogml",
        "version": env!("CARGO_PKG_VERSION"),
        "endpoints": [
            "GET /v1/capabilities",
            "GET /v1/threads",
            "POST /v1/threads/batch_triage",
            "GET /v1/threads/{id}",
            "POST /v1/threads/{id}/triage",
            "POST /v1/threads/{id}/snooze",
            "DELETE /v1/threads/{id}/snooze",
            "GET /v1/threads/{id}/reply-context",
            "GET /v1/threads/{id}/annotations",
            "PUT /v1/threads/{id}/annotations",
            "PATCH /v1/threads/{id}/annotations",
            "DELETE /v1/threads/{id}/annotations",
            "GET /v1/scheduled",
            "DELETE /v1/scheduled/{id}",
            "GET /v1/messages",
            "GET /v1/messages/{id}",
            "POST /v1/messages/{id}/unsubscribe",
            "GET /v1/messages/{id}/attachments/{attachment_id}",
            "GET /v1/messages/{id}/attachments/{attachment_id}/text",
            "POST /v1/messages/send",
            "POST /v1/messages/modify",
            "GET /v1/drafts",
            "POST /v1/drafts",
            "POST /v1/drafts/{id}/send",
            "DELETE /v1/drafts/{id}",
            "GET /v1/approvals",
            "GET /v1/approvals/{id}",
            "POST /v1/approvals/{id}/approve",
            "POST /v1/approvals/{id}/reject",
            "GET /v1/contacts",
            "GET /v1/contacts/{email}",
            "PATCH /v1/contacts/{email}",
            "GET /v1/rules",
            "POST /v1/rules",
            "PATCH /v1/rules/{id}",
            "DELETE /v1/rules/{id}",
            "POST /v1/rules/{id}/test",
            "GET /v1/audit",
            "GET /v1/labels",
            "GET /v1/search",
            "GET /v1/events",
            "POST /v1/sync/gmail",
            "GET /v1/sync/status",
            "POST /mcp"
        ],
        "exit_codes": {
            "0": "success",
            "1": "general / storage / not_found error",
            "2": "validation / input_hardening / config error",
            "3": "safety policy block (draft_only / allowed_recipients / forbidden)",
            "4": "auth / rate_limit / upstream error"
        },
        "commands": commands,
    })
}
