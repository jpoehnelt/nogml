# nogml

**AI-first headless Rust email server** combining a built-in MCP server, a compact AI REST API (`/v1`), a Superhuman-grade Gmail REST API v1 surface (`/gmail/v1`, `/upload/gmail/v1`, `/batch/gmail/v1`), an embedded IMAP4rev1 server (with `IDLE`, `MOVE`, `UIDPLUS`, `SPECIAL-USE`, `STARTTLS`, and `X-GM-EXT-1`), Resend outbound delivery & Svix-verified inbound/delivery webhooks, and upstream Gmail sync (REST API + IMAP).

Built as a single Rust binary with zero required external infrastructure (embedded SQLite FTS5 by default) and seven clean pluggable async trait seams so every backend can be swapped without touching protocol code.

---

## Features

- **AI-First REST API (`/v1`) & SSE (`/v1/events`)**: Compact token-efficient JSON, quote stripping, body truncation ceilings, `?fields=` projection masks, `dry_run` policy previews, `draft_only` / `allowed_recipients` / `max_send_recipients` guardrails, untrusted-content sanitization, and replayable SSE via `Last-Event-ID`.
- **Built-in MCP Server (`nogml mcp` & `POST /mcp`)**: Native JSON-RPC 2.0 Model Context Protocol over both stdio (zero logs on stdout) and Streamable HTTP, exposing 12 tools (`search_emails`, `list_threads`, `read_thread`, `read_email`, `send_email`, `create_draft`, `send_draft`, `triage_thread`, `modify_labels`, `list_labels`, `sync_gmail`, `sync_status`) and `nogml://` resources.
- **Gmail REST API v1 Compatibility**: Full `messages`, `threads`, `labels`, `drafts`, `history`, `watch`/`stop` (with optional push webhook forwarding), `settings/*`, simple/multipart/resumable `/upload/gmail/v1/...`, `/batch/gmail/v1` HTTP batching, `?fields=` partial responses, and Gmail `q=` search operators.
- **Embedded IMAP4rev1 Server**: Connect Thunderbird, Apple Mail, mutt, or `async-imap` directly against the unified mailbox store, including `IDLE` real-time push, `STARTTLS` / implicit TLS, `[Gmail]/All Mail` virtual folder, and `X-GM-EXT-1` (`X-GM-MSGID`, `X-GM-THRID`, `X-GM-LABELS`).
- **Resend Delivery & Webhooks**: Outbound sending via Resend API with `Idempotency-Key`, Svix HMAC-SHA256 webhook verification (`POST /webhooks/resend`), `email.received` Receiving API fetch + attachment download, and delivery status tracking (`sent`, `delivered`, `bounced`, `complained`, `opened`, `clicked`, etc.).
- **Upstream Gmail Sync**: Pull existing Gmail accounts into `nogml` via Gmail REST API v1 (OAuth2 refresh, paginated backfill, incremental `history.list` with automatic 404 full resync) or Gmail IMAP (`X-GM-EXT-1`, UID checkpointing), on demand or on a background interval.
- **Agent-DX CLI (`nogml mail`)**: Local-store or remote (`--url`) operations with auto-JSON when piped, `--ndjson`, `--fields`, `--payload @-`, and deterministic exit codes (`0` ok, `2` validation/config, `3` policy block, `4` auth/upstream, `1` runtime).

---

## Pluggable Trait Architecture

Protocol mechanics (MIME parsing/building, threading, Gmail `q=` parser, `?fields=` mask, HTTP batching, IMAP wire codec, MCP JSON-RPC) are concrete and tested; every external or policy boundary lives behind a pluggable async trait on `AppState`:

```text
  HTTP (/v1, /gmail/v1, /mcp, /webhooks/resend)  |  IMAP4rev1  |  MCP stdio  |  CLI / Sync
  -----------------------------------------------------------------------------------------
                                         AppState
  +------------+ +-----------+ +---------------+ +---------------+ +--------------+ +-------------+ +----------------+
  | MailStore  | | BlobStore | | MailTransport | | InboundFilter | | AuthProvider | | SearchIndex | | OutboundPolicy |
  +------------+ +-----------+ +---------------+ +---------------+ +--------------+ +-------------+ +----------------+
  | SqliteStore| | Inline    | | ResendTransp. | | NoopFilter    | | StaticToken  | | StoreSearch | | ConfigPolicy   |
  | MemoryStore| | FsBlob    | | (SES / SMTP)  | | FilterChain   | | (JWT / OIDC) | | (Tantivy /  | | (Approval /    |
  | (Postgres) | | MemoryBlob| |               | | (Rspamd / AI) | |              | |  pgvector)  | |  DLP / Budget) |
  |            | | (S3 / R2) | |               | |               | |              | |             | |                |
  +------------+ +-----------+ +---------------+ +---------------+ +--------------+ +-------------+ +----------------+
```

| Trait | Module | Built-in Implementations | Purpose |
| --- | --- | --- | --- |
| `MailStore` | `src/storage/` | `SqliteStore` (WAL + FTS5), `MemoryStore` | Messages, threads, labels, drafts, history, IMAP UIDs, watch & sync state |
| `BlobStore` | `src/blob/` | `InlineBlobStore`, `FsBlobStore`, `MemoryBlobStore` | Raw RFC 2822 & attachment binary blobs (atomic temp+rename on FS; drop-in S3/R2 ready) |
| `MailTransport` | `src/transport/` | `ResendTransport` (`src/resend/`) | Provider-agnostic outbound delivery carrying structured fields + verbatim RFC 2822 |
| `InboundFilter` | `src/filter/` | `NoopFilter`, `FilterChain` | Pre-storage `Allow` / `Spam` / `Reject` / `Mutate` hook across Resend, Gmail import, IMAP `APPEND`, and Gmail sync |
| `AuthProvider` | `src/auth.rs` | `StaticTokenAuthProvider` | HTTP bearer (`Authorization`, `X-API-Key`, `?access_token=`) & IMAP auth returning `Principal` + scopes |
| `SearchIndex` | `src/search_index.rs` | `StoreSearchIndex` | Full-text / structured / semantic search powering `/v1/search`, MCP `search_emails`, and `nogml mail search` |
| `OutboundPolicy` | `src/ai/safety.rs` | `ConfigOutboundPolicy` | Agent send guardrails (`Allow`, `DowngradeToDraft`, `HoldForApproval` -> `202`, `Deny` -> `403`) + `dry_run` checks |

Inspect the active backends at runtime via `GET /v1/capabilities` (under `.backends`).

---

## Quickstart

### Build

```bash
cargo build --release
```

### 1. Start the server (`nogml serve`)

```bash
# Local dev mode (SQLite at ./nogml.db, unauthenticated dev mode, draft-only guardrail)
nogml serve \
  --bind 127.0.0.1:8080 \
  --user-email agent@example.com \
  --default-domain example.com \
  --draft-only

# Production with bearer auth, Resend delivery/webhooks, filesystem blobs, and embedded IMAP
RESEND_API_KEY=re_xxx \
RESEND_WEBHOOK_SECRET=whsec_xxx \
NOGML_AUTH_TOKENS=tok_secret_1 \
nogml serve \
  --bind 0.0.0.0:8080 \
  --db-path /var/lib/nogml/nogml.db \
  --blob-backend fs \
  --blob-dir /var/lib/nogml/blobs \
  --user-email agent@example.com \
  --imap-bind 127.0.0.1:1143 \
  --allowed-recipients @example.com,partner@acme.org
```

Verify health & capabilities:

```bash
curl -s http://127.0.0.1:8080/healthz
curl -s http://127.0.0.1:8080/v1/capabilities | jq .
```

### 2. Run the MCP server (`nogml mcp`)

```bash
# Stdio MCP transport (logs go strictly to stderr; stdout carries JSON-RPC 2.0 frames)
nogml mcp --db-path ./nogml.db --user-email agent@example.com --draft-only
```

Or connect any Streamable HTTP MCP client directly to `POST http://127.0.0.1:8080/mcp` (with `Authorization: Bearer <token>` when auth is enabled).

### 3. Use the Agent-DX CLI (`nogml mail`)

```bash
# Operate directly against local SQLite or target a running server with --url
nogml mail --url http://127.0.0.1:8080 threads --unread-only --limit 10
nogml mail --url http://127.0.0.1:8080 search --q "invoice" --fields "messages(id,subject,from)"
nogml mail --url http://127.0.0.1:8080 read <thread_id> --thread --strip-quotes
nogml mail --url http://127.0.0.1:8080 send --to alice@example.com --subject "Update" --text "Ready." --dry-run
nogml mail --url http://127.0.0.1:8080 triage <thread_id> --archive true --mark-read true
nogml mail --url http://127.0.0.1:8080 watch
nogml schema --command send
```

### 4. Sync an upstream Gmail account (`nogml sync gmail`)

```bash
# Mode A: Gmail REST API v1 (OAuth2 refresh token or static access token)
GMAIL_CLIENT_ID=... \
GMAIL_CLIENT_SECRET=... \
GMAIL_REFRESH_TOKEN=... \
nogml sync gmail --mode api --max-messages 500

# Mode B: Upstream Gmail IMAP (App Password)
GMAIL_IMAP_USER=you@gmail.com \
GMAIL_IMAP_PASSWORD=app-password \
nogml sync gmail --mode imap
```

Enable periodic background sync on `nogml serve` with `--sync-interval-secs 60`.

---

## Configuration & Environment Variables

All CLI flags accept environment variables:

| Variable | CLI Flag | Default | Description |
| --- | --- | --- | --- |
| `NOGML_BIND` | `--bind` | `127.0.0.1:8080` | HTTP server listen address |
| `NOGML_MAX_BODY_BYTES` | `--max-body-bytes` | `41943040` (40 MiB) | Max HTTP body & IMAP literal size |
| `NOGML_CORS_ORIGINS` | `--cors-origins` | *(any)* | Comma-separated allowed CORS origins |
| `NOGML_STORAGE` | `--storage` | `sqlite` | `MailStore` backend (`sqlite` or `memory`) |
| `NOGML_DB_PATH` | `--db-path` | `nogml.db` | SQLite database file path |
| `NOGML_BLOB_BACKEND` | `--blob-backend` | `inline` | `BlobStore` backend (`inline`, `fs`, or `memory`) |
| `NOGML_BLOB_DIR` | `--blob-dir` | `nogml-blobs` | Directory for `fs` blob backend |
| `NOGML_AUTH_TOKENS` | `--auth-tokens` | *(empty = dev mode)* | Comma-separated bearer/API tokens |
| `NOGML_USER_EMAIL` | `--user-email` | `me@localhost` | Primary mailbox address |
| `NOGML_DEFAULT_DOMAIN` | `--default-domain` | `localhost` | Default domain for generated `Message-ID`s |
| `RESEND_API_KEY` | `--resend-api-key` | *(none)* | Resend API key (`re_...`) for outbound & Receiving API |
| `RESEND_BASE_URL` | `--resend-base-url` | `https://api.resend.com` | Resend API base URL |
| `RESEND_WEBHOOK_SECRET` | `--resend-webhook-secret` | *(none)* | Svix signing secret (`whsec_...`) for `POST /webhooks/resend` |
| `NOGML_DRAFT_ONLY` | `--draft-only` | `false` | Prevent direct agent outbound sends |
| `NOGML_DRAFT_ONLY_ACTION` | `--draft-only-action` | `block` | Behavior when `draft_only=true` (`block` or `downgrade`) |
| `NOGML_ALLOWED_RECIPIENTS` | `--allowed-recipients` | *(unrestricted)* | Comma-separated allowlist (`a@b.com`, `@domain.com`, `*.domain.com`) |
| `NOGML_MAX_SEND_RECIPIENTS` | `--max-send-recipients` | `50` | Maximum recipients across `to`/`cc`/`bcc` |
| `NOGML_DEFAULT_MAX_BODY_CHARS` | `--default-max-body-chars` | `4000` | Default body char limit on AI/MCP reads (hard cap `100000`) |
| `NOGML_UNTRUSTED_CONTENT_GUARD` | `--untrusted-content-guard` | `true` | Strip control/BiDi smuggling chars and tag `_meta.untrusted_external_content` |
| `NOGML_IMAP_BIND` | `--imap-bind` | *(disabled)* | Embedded IMAP plain/STARTTLS listen address |
| `NOGML_IMAP_TLS_BIND` | `--imap-tls-bind` | *(disabled)* | Embedded IMAP implicit TLS listen address |
| `NOGML_IMAP_TLS_CERT` / `KEY` | `--imap-tls-cert` / `--imap-tls-key` | *(none)* | PEM cert chain & private key for IMAP TLS/STARTTLS |
| `NOGML_IMAP_USERNAME` / `PASSWORD` | `--imap-username` / `--imap-password` | *(user_email / first token)* | IMAP credentials override |
| `NOGML_SYNC_MODE` | `--sync-mode` | `api` | Upstream Gmail sync mode (`api` or `imap`) |
| `NOGML_SYNC_INTERVAL_SECS` | `--sync-interval-secs` | `0` | Background sync interval (`0` disables) |
| `GMAIL_CLIENT_ID` / `SECRET` / `REFRESH_TOKEN` / `ACCESS_TOKEN` | `--gmail-*` | *(none)* | Upstream Gmail REST API credentials |
| `GMAIL_IMAP_USER` / `PASSWORD` | `--gmail-imap-*` | *(none)* | Upstream Gmail IMAP credentials |
| `NOGML_WATCH_WEBHOOK_URL` | `--watch-webhook-url` | *(none)* | Optional push webhook URL for active Gmail `/watch` subscriptions |
| `NOGML_LOG_JSON` | `--log-json` | `false` | Emit structured JSON logs |

---

## Connecting Clients & Agents

### MCP Client (Claude Desktop / Cursor / Custom Agent)

```json
{
  "mcpServers": {
    "nogml": {
      "command": "nogml",
      "args": ["mcp", "--db-path", "/path/to/nogml.db", "--user-email", "agent@example.com", "--draft-only"]
    }
  }
}
```

Or over HTTP: point your Streamable HTTP MCP client at `http://127.0.0.1:8080/mcp`.

### Gmail API SDKs & Superhuman-Style Clients

Point your Gmail API client base URL at `http://127.0.0.1:8080` with `Authorization: Bearer <token>`:

- `GET /gmail/v1/users/me/profile`
- `GET /gmail/v1/users/me/messages?q=from:alice has:attachment`
- `GET /gmail/v1/users/me/messages/{id}?format=full&fields=id,snippet,payload/headers`
- `POST /upload/gmail/v1/users/me/messages/send?uploadType=multipart`
- `POST /batch/gmail/v1` (`multipart/mixed` batch requests)
- `GET /gmail/v1/users/me/history?startHistoryId=...`
- `POST /gmail/v1/users/me/watch` (pairs with `NOGML_WATCH_WEBHOOK_URL` to emit `{emailAddress, historyId}` push webhooks)

### IMAP Clients

Enable `--imap-bind 127.0.0.1:1143` (or `--imap-tls-bind 127.0.0.1:1993` with TLS cert/key) and log in with `--user-email` (or `NOGML_IMAP_USERNAME`) and your bearer token (or `NOGML_IMAP_PASSWORD`).

### Resend Webhooks

Configure your Resend webhook endpoint to `POST https://<your-host>/webhooks/resend` with `RESEND_WEBHOOK_SECRET=whsec_...`. `nogml` verifies Svix signatures in constant time, fetches full inbound emails + attachments from the Resend Receiving API, evaluates `InboundFilter`, threads replies via `In-Reply-To`/`References`, deduplicates by `Message-ID`, and tracks delivery status events (`email.sent`, `email.delivered`, `email.bounced`, etc.).

---

## Embedding as a Rust Library

Because every backend sits behind a trait object on `AppState`, you can embed `nogml` with custom implementations in a few lines:

```rust
use std::sync::Arc;
use nogml::{AppState, build_router, config::Config};

let state = AppState::from_config(Config::default())?
    .with_blobs(Arc::new(my_s3_blob_store))
    .with_transport(Arc::new(my_ses_transport))
    .with_filter(Arc::new(my_spam_filter_chain))
    .with_auth(Arc::new(my_jwt_auth_provider))
    .with_search(Arc::new(my_vector_search_index))
    .with_outbound_policy(Arc::new(my_human_approval_policy));

let router = build_router(state);
```

---

## License

Apache-2.0 — see [LICENSE](LICENSE).
