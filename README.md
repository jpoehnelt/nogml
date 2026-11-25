# nogml

`nogml` is a headless Rust email server built for AI agents and Gmail API clients. It runs as a single binary backed by embedded SQLite FTS5 by default.

It exposes four protocols against one mailbox store:

- An MCP server over stdio (`nogml mcp`) and Streamable HTTP (`POST /mcp`).
- A JSON REST API (`/v1`) with real-time Server-Sent Events (`/v1/events`) and outbound safety checks.
- A Gmail REST API v1 server (`/gmail/v1`, `/upload/gmail/v1`, `/batch/gmail/v1`) for clients such as Superhuman and official Google SDKs.
- An IMAP4rev1 server with `IDLE`, `MOVE`, `UIDPLUS`, `SPECIAL-USE`, `STARTTLS`, and Gmail `X-GM-EXT-1` extensions.

Outbound mail sends through Resend by default, and inbound mail arrives through Svix-verified Resend webhooks (`POST /webhooks/resend`) or upstream Gmail sync (REST API or IMAP).

## Features

- **AI REST API (`/v1`) and SSE (`/v1/events`)**: Returns parsed text and HTML bodies without base64 decoding. Supports quote stripping, body character limits, `?fields=` projection masks, `dry_run` send previews, `draft_only` and `allowed_recipients` guardrails, control and BiDi character stripping, and `Last-Event-ID` event replay.
- **Built-in MCP server (`nogml mcp` and `POST /mcp`)**: Implements JSON-RPC 2.0 over stdio (logging strictly to stderr) and Streamable HTTP. Exposes 12 tools (`search_emails`, `list_threads`, `read_thread`, `read_email`, `send_email`, `create_draft`, `send_draft`, `triage_thread`, `modify_labels`, `list_labels`, `sync_gmail`, `sync_status`) and `nogml://` resources.
- **Gmail REST API v1**: Implements `profile`, `messages`, `threads`, `labels`, `drafts`, `history`, `watch` and `stop` (with optional push webhook delivery), `settings/*` (`sendAs`, `vacation`, `autoForwarding`, `imap`, `pop`), `/upload/gmail/v1/...`, `POST /batch/gmail/v1` `multipart/mixed` batching, `?fields=` partial responses, and Gmail `q=` search operators.
- **Embedded IMAP4rev1 server**: Serves standard IMAP clients (Thunderbird, Apple Mail, mutt, `async-imap`) over TCP, `STARTTLS`, or implicit TLS. Maps Gmail labels to folders including `[Gmail]/All Mail`, syncs flags to labels, supports `X-GM-MSGID`, `X-GM-THRID`, and `X-GM-LABELS`, and pushes updates over `IDLE`.
- **Resend delivery and webhooks**: Sends outbound mail via `POST /emails` with `Idempotency-Key`. Verifies `POST /webhooks/resend` Svix HMAC-SHA256 signatures in constant time, fetches inbound messages and attachments from the Resend Receiving API, and records delivery status events (`sent`, `delivered`, `bounced`, `complained`, `opened`, `clicked`, `failed`).
- **Upstream Gmail sync**: Imports existing Gmail accounts via Gmail REST API v1 (OAuth2 refresh, paginated backfill, incremental `history.list` with automatic 404 full resync) or Gmail IMAP (`X-GM-EXT-1` and UID checkpointing). Deduplicates by upstream Gmail ID and RFC 2822 `Message-ID`.
- **CLI (`nogml mail`)**: Runs against the local store or a remote server (`--url`). Outputs JSON automatically when stdout is not a TTY, supports `--ndjson`, `--fields`, and `--payload @-`, and returns deterministic exit codes (`0` ok, `2` validation or config error, `3` policy block, `4` auth or upstream error, `1` runtime error).

## Pluggable traits

Protocol code (MIME parsing and building, threading, Gmail `q=` parsing, `?fields=` masking, HTTP batching, IMAP wire codec, and MCP JSON-RPC) is concrete. Backend storage, delivery, filtering, auth, search, and outbound policy sit behind seven async traits on `AppState`:

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

| Trait | Module | Built-in implementations | Role |
| --- | --- | --- | --- |
| `MailStore` | `src/storage/` | `SqliteStore` (WAL + FTS5), `MemoryStore` | Messages, threads, labels, drafts, history, IMAP UIDs, watch state, and sync state |
| `BlobStore` | `src/blob/` | `InlineBlobStore`, `FsBlobStore`, `MemoryBlobStore` | Raw RFC 2822 bytes and attachment blobs (atomic temp-file rename on disk; implement `BlobStore` for S3 or R2) |
| `MailTransport` | `src/transport/` | `ResendTransport` (`src/resend/`) | Outbound delivery carrying structured fields and verbatim RFC 2822 bytes |
| `InboundFilter` | `src/filter/` | `NoopFilter`, `FilterChain` | Pre-storage `Allow`, `Spam`, `Reject`, or `Mutate` hook on Resend webhooks, Gmail import, IMAP `APPEND`, and Gmail sync |
| `AuthProvider` | `src/auth.rs` | `StaticTokenAuthProvider` | HTTP (`Authorization`, `X-API-Key`, `?access_token=`) and IMAP authentication returning `Principal` and scopes |
| `SearchIndex` | `src/search_index.rs` | `StoreSearchIndex` | Search backend used by `/v1/search`, MCP `search_emails`, and `nogml mail search` |
| `OutboundPolicy` | `src/ai/safety.rs` | `ConfigOutboundPolicy` | Send guardrails (`Allow`, `DowngradeToDraft`, `HoldForApproval` returning 202, `Deny` returning 403) and `dry_run` checks |

Query `GET /v1/capabilities` to see the active backend names under `.backends`.

## Quickstart

### Build

```bash
cargo build --release
```

### 1. Start the server (`nogml serve`)

```bash
# Local dev mode (SQLite at ./nogml.db, no auth, draft-only guardrail)
nogml serve \
  --bind 127.0.0.1:8080 \
  --user-email agent@example.com \
  --default-domain example.com \
  --draft-only

# Production with bearer auth, Resend delivery and webhooks, filesystem blobs, and IMAP
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

Check health and active backends:

```bash
curl -s http://127.0.0.1:8080/healthz
curl -s http://127.0.0.1:8080/v1/capabilities | jq .
```

### 2. Run the MCP server (`nogml mcp`)

```bash
# Stdio MCP transport (logs go to stderr; stdout carries JSON-RPC 2.0 frames)
nogml mcp --db-path ./nogml.db --user-email agent@example.com --draft-only
```

For Streamable HTTP, point your MCP client at `POST http://127.0.0.1:8080/mcp` with `Authorization: Bearer <token>` when auth is enabled.

### 3. Use the CLI (`nogml mail`)

```bash
# Omit --url to read local SQLite directly, or pass --url to talk to a running server
nogml mail --url http://127.0.0.1:8080 threads --unread-only --limit 10
nogml mail --url http://127.0.0.1:8080 search --q "invoice" --fields "messages(id,subject,from)"
nogml mail --url http://127.0.0.1:8080 read <thread_id> --thread --strip-quotes
nogml mail --url http://127.0.0.1:8080 send --to alice@example.com --subject "Update" --text "Ready." --dry-run
nogml mail --url http://127.0.0.1:8080 triage <thread_id> --archive true --mark-read true
nogml mail --url http://127.0.0.1:8080 watch
nogml schema --command send
```

### 4. Sync a Gmail account (`nogml sync gmail`)

```bash
# Gmail REST API v1 (OAuth2 refresh token or static access token)
GMAIL_CLIENT_ID=... \
GMAIL_CLIENT_SECRET=... \
GMAIL_REFRESH_TOKEN=... \
nogml sync gmail --mode api --max-messages 500

# Upstream Gmail IMAP (App Password)
GMAIL_IMAP_USER=you@gmail.com \
GMAIL_IMAP_PASSWORD=app-password \
nogml sync gmail --mode imap
```

Pass `--sync-interval-secs 60` to `nogml serve` to run sync periodically in the background.

## Configuration

Every CLI flag has a matching environment variable:

| Variable | CLI flag | Default | Description |
| --- | --- | --- | --- |
| `NOGML_BIND` | `--bind` | `127.0.0.1:8080` | HTTP listen address |
| `NOGML_MAX_BODY_BYTES` | `--max-body-bytes` | `41943040` (40 MiB) | Max HTTP body and IMAP literal size |
| `NOGML_CORS_ORIGINS` | `--cors-origins` | *(any)* | Comma-separated allowed CORS origins |
| `NOGML_STORAGE` | `--storage` | `sqlite` | `MailStore` backend (`sqlite` or `memory`) |
| `NOGML_DB_PATH` | `--db-path` | `nogml.db` | SQLite database file path |
| `NOGML_BLOB_BACKEND` | `--blob-backend` | `inline` | `BlobStore` backend (`inline`, `fs`, or `memory`) |
| `NOGML_BLOB_DIR` | `--blob-dir` | `nogml-blobs` | Directory for the `fs` blob backend |
| `NOGML_AUTH_TOKENS` | `--auth-tokens` | *(empty = dev mode)* | Comma-separated bearer/API tokens |
| `NOGML_USER_EMAIL` | `--user-email` | `me@localhost` | Primary mailbox address |
| `NOGML_DEFAULT_DOMAIN` | `--default-domain` | `localhost` | Default domain for generated `Message-ID` headers |
| `RESEND_API_KEY` | `--resend-api-key` | *(none)* | Resend API key (`re_...`) for outbound sends and the Receiving API |
| `RESEND_BASE_URL` | `--resend-base-url` | `https://api.resend.com` | Resend API base URL |
| `RESEND_WEBHOOK_SECRET` | `--resend-webhook-secret` | *(none)* | Svix signing secret (`whsec_...`) for `POST /webhooks/resend` |
| `NOGML_DRAFT_ONLY` | `--draft-only` | `false` | Prevent direct outbound sends |
| `NOGML_DRAFT_ONLY_ACTION` | `--draft-only-action` | `block` | Action when `draft_only=true` (`block` or `downgrade`) |
| `NOGML_ALLOWED_RECIPIENTS` | `--allowed-recipients` | *(unrestricted)* | Comma-separated allowlist (`a@b.com`, `@domain.com`, `*.domain.com`) |
| `NOGML_MAX_SEND_RECIPIENTS` | `--max-send-recipients` | `50` | Maximum recipients across `to`, `cc`, and `bcc` |
| `NOGML_DEFAULT_MAX_BODY_CHARS` | `--default-max-body-chars` | `4000` | Default body character limit on AI and MCP reads (cap `100000`) |
| `NOGML_UNTRUSTED_CONTENT_GUARD` | `--untrusted-content-guard` | `true` | Strip control and BiDi chars and set `_meta.untrusted_external_content` |
| `NOGML_IMAP_BIND` | `--imap-bind` | *(disabled)* | Embedded IMAP plain and `STARTTLS` listen address |
| `NOGML_IMAP_TLS_BIND` | `--imap-tls-bind` | *(disabled)* | Embedded IMAP implicit TLS listen address |
| `NOGML_IMAP_TLS_CERT` / `KEY` | `--imap-tls-cert` / `--imap-tls-key` | *(none)* | PEM certificate chain and private key for IMAP TLS |
| `NOGML_IMAP_USERNAME` / `PASSWORD` | `--imap-username` / `--imap-password` | *(user_email / first token)* | IMAP login override |
| `NOGML_SYNC_MODE` | `--sync-mode` | `api` | Upstream Gmail sync mode (`api` or `imap`) |
| `NOGML_SYNC_INTERVAL_SECS` | `--sync-interval-secs` | `0` | Background sync interval in seconds (`0` disables) |
| `GMAIL_CLIENT_ID` / `SECRET` / `REFRESH_TOKEN` / `ACCESS_TOKEN` | `--gmail-*` | *(none)* | Upstream Gmail REST API credentials |
| `GMAIL_IMAP_USER` / `PASSWORD` | `--gmail-imap-*` | *(none)* | Upstream Gmail IMAP credentials |
| `NOGML_WATCH_WEBHOOK_URL` | `--watch-webhook-url` | *(none)* | Optional push webhook URL for active Gmail `/watch` subscriptions |
| `NOGML_LOG_JSON` | `--log-json` | `false` | Emit JSON logs |

## Connecting clients

### MCP client

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

For HTTP clients, connect to `http://127.0.0.1:8080/mcp`.

### Gmail API clients

Point the Gmail API base URL at `http://127.0.0.1:8080` with `Authorization: Bearer <token>`:

- `GET /gmail/v1/users/me/profile`
- `GET /gmail/v1/users/me/messages?q=from:alice has:attachment`
- `GET /gmail/v1/users/me/messages/{id}?format=full&fields=id,snippet,payload/headers`
- `POST /upload/gmail/v1/users/me/messages/send?uploadType=multipart`
- `POST /batch/gmail/v1` (`multipart/mixed` batch requests)
- `GET /gmail/v1/users/me/history?startHistoryId=...`
- `POST /gmail/v1/users/me/watch` (with `NOGML_WATCH_WEBHOOK_URL`, posts `{emailAddress, historyId}` notifications)

### IMAP clients

Set `--imap-bind 127.0.0.1:1143` (or `--imap-tls-bind 127.0.0.1:1993` with a TLS certificate and key). Log in with `--user-email` (or `NOGML_IMAP_USERNAME`) and your bearer token (or `NOGML_IMAP_PASSWORD`).

### Resend webhooks

Set your Resend webhook endpoint to `POST https://<your-host>/webhooks/resend` with `RESEND_WEBHOOK_SECRET=whsec_...`. On each request, `nogml` verifies the Svix signature in constant time, fetches the inbound message and attachments from the Resend Receiving API, runs `InboundFilter`, threads replies using `In-Reply-To` and `References`, deduplicates by `Message-ID`, and records delivery status events (`email.sent`, `email.delivered`, `email.bounced`, and others).

## Embedding as a Rust library

Pass custom trait implementations to `AppState` to embed `nogml` in your own Rust binary:

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

## License

Apache-2.0. See [LICENSE](LICENSE).
