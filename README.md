# nogml

`nogml` is a headless, pluggable Rust email server built for AI agents, Gmail API clients, and IMAP clients.

Start with a single binary backed by embedded SQLite FTS5, and swap any backend layer (storage, blobs, outbound transport, inbound filtering, authentication, search, outbound guardrails, custom domain provisioning, upstream sync, or cross-node events) through `nogml.toml` / environment variables or custom Rust trait implementations without touching protocol code.

Every backend feeds four protocols against one mailbox core:

- **MCP server** over stdio (`nogml mcp`) and Streamable HTTP (`POST /mcp`) with 27 tools, `nogml://` resources, and 4 built-in prompts.
- **AI JSON REST API (`/v1`)** with real-time Server-Sent Events (`/v1/events`), OpenAPI 3.1 (`GET /v1/openapi.json`), and composable outbound safety guardrails.
- **Gmail REST API v1** (`/gmail/v1`, `/upload/gmail/v1`, `/batch/gmail/v1`) for clients such as Superhuman and official Google SDKs.
- **IMAP4rev1 server** with `X-GM-EXT-1`, `COMPRESS=DEFLATE`, `UTF8=ACCEPT`, `QUOTA`, `XLIST`, `CHILDREN`, `CONDSTORE`/`QRESYNC`, `IDLE`, `SORT`, `THREAD`, `ESEARCH`, `LIST-STATUS`, `UNSELECT`, `APPENDLIMIT`, `STATUS=SIZE`, `WITHIN`, `STARTTLS`, `AUTH=XOAUTH2`, and `AUTH=OAUTHBEARER`.

## Pluggable architecture

All protocol mechanics (MIME parsing and building, RFC 5322 threading, Gmail `q=` query parsing, `?fields=` projection masks, HTTP batching, IMAP wire codec, and MCP JSON-RPC) are concrete and shared. Every infrastructure dependency sits behind async Rust traits on `AppState` so you can mix and match built-in backends by configuration or plug in your own implementations when embedding `nogml` as a crate.

```text
  HTTP (/v1, /gmail/v1, /mcp, /webhooks/resend, /webhooks/ses) | IMAP4rev1 | MCP stdio | CLI
  ==========================================================================================
                                     Protocol & MIME Core
  ------------------------------------------------------------------------------------------
                                           AppState
  +-------------+ +------------+ +---------------+ +---------------+ +--------------+
  | MailStore   | | BlobStore  | | MailTransport | | InboundFilter | | AuthProvider |
  +-------------+ +------------+ +---------------+ +---------------+ +--------------+
  | SqliteStore | | Inline     | | Resend        | | NoopFilter    | | StaticToken  |
  | MemoryStore | | FsBlob     | | AWS SESv2     | | FilterChain   | | Scoped Keys  |
  | Postgres*   | | MemoryBlob | | SMTP / XOAUTH2| | AuthResults   | | Local OAuth2 |
  +-------------+ | S3 / R2    | | Gmail API     | | Rspamd / LLM  | +--------------+
                  +------------+ +---------------+ +---------------+

  +-----------------+ +---------------------+ +----------------+ +--------------+ +-------------+
  | SearchIndex     | | OutboundPolicy      | | DomainProvider | | SyncSource   | | EventBridge |
  +-----------------+ +---------------------+ +----------------+ +--------------+ +-------------+
  | StoreSearch     | | ConfigPolicy        | | SesDomain      | | GmailApiSync | | In-process  |
  | HybridSearch    | | FirstContactPolicy  | | ResendDomain   | | GmailImapSync| | Postgres    |
  |  + Embedding    | | DlpOutboundPolicy   | | ManualDomain   | +--------------+ | LISTEN/     |
  |  + VectorStore  | | VerifiedFromDomain  | +----------------+                  | NOTIFY*     |
  +-----------------+ | Deliverability      |                                     +-------------+
                      +---------------------+           (* enabled with `--features postgres`)
```

### Core pluggable traits

| Trait | Module | Built-in implementations | Config selector | Role |
| --- | --- | --- | --- | --- |
| `MailStore` | `src/storage/` | `SqliteStore` (WAL + FTS5), `MemoryStore`, `PostgresStore` (`--features postgres`) | `NOGML_STORAGE` | Messages, threads, annotations, snoozes, scheduled sends, labels, drafts, contacts, rules, approvals, idempotency keys, audit log, history, IMAP UIDs, domains, suppressions, and sync state |
| `BlobStore` | `src/blob/` | `InlineBlobStore`, `FsBlobStore`, `MemoryBlobStore`, `S3BlobStore` | `NOGML_BLOB_BACKEND` | Raw RFC 2822 bytes and attachment binaries stored inline, atomically on local disk, in memory, or in AWS S3 / Cloudflare R2 / MinIO via SigV4 |
| `MailTransport` | `src/transport/` | `ResendTransport`, `SesTransport`, `SmtpTransport`, `GmailApiTransport` | `NOGML_TRANSPORT` | Outbound delivery via Resend, AWS SESv2 raw MIME, direct SMTP (`PLAIN`/`LOGIN`/`XOAUTH2`), or upstream Gmail REST API (`messages.send`) |
| `InboundFilter` | `src/filter/` | `NoopFilter`, `FilterChain`, `AuthResultsFilter`, `RspamdFilter`, `LlmTriageFilter` | `NOGML_FILTER_*`, `NOGML_RSPAMD_URL`, `NOGML_LLM_TRIAGE_*` | Composable pre-storage `Allow`, `Spam`, `Reject`, or `Mutate` pipeline across webhooks, Gmail import, IMAP `APPEND`, and upstream sync |
| `AuthProvider` | `src/auth.rs` | `StaticTokenAuthProvider` (global tokens, scoped per-mailbox keys, local OAuth2 HS256 JWTs) | `NOGML_AUTH_TOKENS`, `NOGML_SCOPED_TOKENS`, `NOGML_OAUTH2_*` | HTTP (`Authorization`, `X-API-Key`, `?access_token=`) and IMAP (`LOGIN`, `PLAIN`, `XOAUTH2`, `OAUTHBEARER`) auth returning `Principal`, scopes, `shared_mailboxes`, and per-agent guardrails |
| `SearchIndex` | `src/search_index/` | `StoreSearchIndex`, `HybridSearchIndex` (composable over `EmbeddingProvider` + `VectorStore`) | `NOGML_SEARCH_BACKEND`, `NOGML_EMBEDDING_*` | Lexical FTS5/`tsvector` search or hybrid keyword + cosine-similarity vector search fused with Reciprocal Rank Fusion (`OpenAiEmbeddingProvider` + `SqliteVectorStore` / `PostgresVectorStore` / `MemoryVectorStore`) |
| `OutboundPolicy` | `src/ai/safety.rs`, `src/deliverability.rs` | `OutboundPolicyChain`, `ConfigOutboundPolicy`, `FirstContactPolicy`, `DlpOutboundPolicy`, `VerifiedFromDomainPolicy`, `DeliverabilityPolicy` (`SuppressionListPolicy`, `DomainQuotaPolicy`, `DeliverabilityCircuitBreakerPolicy`) | `NOGML_DRAFT_ONLY`, `NOGML_REQUIRE_APPROVAL`, `NOGML_DLP_ACTION`, `NOGML_DAILY_SEND_LIMIT_PER_DOMAIN`, etc. | Composable outbound guardrails returning `Allow`, `DowngradeToDraft`, `HoldForApproval` (HTTP 202 queued to `/v1/approvals`), or `Deny` (HTTP 403), including `dry_run` previews |
| `DomainProvider` | `src/domains/` | `SesDomainProvider`, `ResendDomainProvider`, `ManualDomainProvider` | `/v1/domains` (`provider`) | Self-serve BYOD custom domain onboarding, DNS record provisioning (DKIM/SPF/DMARC/MX), live verification checks, and catch-all inbound routing |
| `SyncSource` | `src/sync/` | `GmailApiSyncSource`, `GmailImapSyncSource` | `NOGML_SYNC_MODE`, `[[sync.accounts]]` | Pluggable upstream pull and optional bidirectional pushback sharing per-mailbox locking, `SyncState` checkpoints, `InboundFilter`, and `EventBus` emission |
| `EventBridge` | `src/events.rs`, `src/storage/postgres.rs` | Local in-process `EventBus`, `PostgresEventBridge` (`LISTEN`/`NOTIFY`) | Automatic with `NOGML_STORAGE=postgres` | Real-time fan-out across SSE `/v1/events`, IMAP `IDLE`, and Gmail `/watch` webhooks on single or multi-node deployments |

Query `GET /v1/capabilities` at runtime to inspect every active backend under `.backends`.

### Swap backends with config (zero code changes)

The same binary scales from a local agent sandbox to a multi-node cluster by changing configuration:

| Profile | `MailStore` | `BlobStore` | `MailTransport` | `SearchIndex` | `InboundFilter` & `OutboundPolicy` |
| --- | --- | --- | --- | --- | --- |
| Local AI agent dev | `sqlite` | `inline` | `resend` or `gmail` | `store` (FTS5) | `draft_only`, `dry_run`, `first_contact_approval` |
| Single-VPS personal / team | `sqlite` | `fs` | `resend`, `ses`, `smtp`, or `gmail` | `hybrid` (Ollama / OpenAI) | `AuthResults` + `Rspamd` + `DlpOutboundPolicy` + `AES-256-GCM` |
| Multi-user / multi-node SaaS | `postgres` (`LISTEN`/`NOTIFY`) | `s3` (S3 / R2 / MinIO) | `ses` or `resend` + BYOD `DomainProvider` | `hybrid` (`PostgresVectorStore`) | `VerifiedFromDomain` + `DeliverabilityPolicy` + `NOGML_ENCRYPTION_STRICT` |

### Embed as a Rust library with custom traits

Swap any subset of traits directly in Rust while keeping the full HTTP, MCP, Gmail API, IMAP, and webhook surface:

```rust
use std::sync::Arc;
use nogml::{AppState, build_router, config::Config};

// Swap individual backends onto the config-built AppState:
let state = AppState::from_config(Config::default())?
    .with_blobs(Arc::new(my_s3_blob_store))
    .with_transport(Arc::new(my_ses_transport))
    .with_filter(Arc::new(my_spam_filter_chain))
    .with_auth(Arc::new(my_oidc_auth_provider))
    .with_search(Arc::new(my_vector_search_index))
    .with_outbound_policy(Arc::new(my_approval_policy))
    .with_domain_provider(Arc::new(my_dns_domain_provider))
    .with_cipher(Arc::new(my_secret_cipher));

// Or pass a custom MailStore implementation directly via AppState::with_backends(config, store, resend).
let router = build_router(state);
```

## Protocol and feature highlights

- **AI REST API (`/v1`) and SSE (`/v1/events`)**:
  - Clean agent-ready payloads: automatic HTML-to-Markdown conversion, quote stripping, body character limits, tracking-pixel stripping, extracted HTML link inspection (`links` with `domain_mismatch` flags), and bounded attachment text extraction (`.txt`, `.csv`, `.md`, `.json`, `.html`, `.ics`, `.pdf`).
  - Agent workflow primitives: persistent thread annotations (`/v1/threads/{id}/annotations`), single-call `GET /v1/threads/{id}/reply-context`, atomic `POST /v1/threads/batch_triage` (with `dry_run` label-diff previews), thread snoozing (`/v1/threads/{id}/snooze`), scheduled sends (`send_at` / `/v1/scheduled`), per-mailbox contact graph and VIP detection (`/v1/contacts`), event-driven inbox rules with HMAC-SHA256 signed webhooks (`/v1/rules`), and compact daily briefings (`GET /v1/briefing`).
  - Guardrails and compliance: composable `OutboundPolicyChain`, `dry_run` send previews, `draft_only`, `allowed_recipients`, `first_contact_approval`, outbound secret and PII DLP scanning (`dlp_action=off|hold|deny`), persistent human-in-the-loop approvals (`/v1/approvals`), 24-hour idempotency keys (`Idempotency-Key`), append-only audit log (`GET /v1/audit`), RFC 2369/8058 one-click unsubscribe with SSRF protection, BiDi/control character stripping, and SSE `Last-Event-ID` replay.
- **Built-in MCP server (`nogml mcp` and `POST /mcp`)**:
  - JSON-RPC 2.0 over stdio (logging strictly to stderr) and Streamable HTTP.
  - Exposes 27 tools (`search_emails`, `list_threads`, `read_thread`, `read_email`, `read_attachment_text`, `send_email`, `create_draft`, `send_draft`, `triage_thread`, `batch_triage`, `snooze_thread`, `list_scheduled_sends`, `cancel_scheduled_send`, `annotate_thread`, `get_thread_annotations`, `get_reply_context`, `modify_labels`, `unsubscribe`, `list_labels`, `lookup_contact`, `list_vips`, `get_briefing`, `list_rules`, `create_rule`, `delete_rule`, `sync_gmail`, `sync_status`), `nogml://` resources (including `nogml://briefing`), and 4 built-in prompts (`triage_inbox`, `daily_briefing`, `draft_reply`, `find_followups`).
- **Gmail REST API v1**:
  - Full surface for Superhuman and official Google SDKs: `profile`, `messages`, `threads`, `labels`, `drafts`, `history`, `watch`/`stop`, `settings/*` (`sendAs` with `PATCH`/`verify`, `filters` evaluated automatically on inbound mail, `forwardingAddresses`, `delegates`, `language`, `vacation`, `autoForwarding`, `imap`, `pop`), `/upload/gmail/v1/...` (`media`, `multipart`, and chunked `resumable` uploads), `POST /batch/gmail/v1` `multipart/mixed` batching, `?fields=` partial responses, `/oauth2/v2|v3/userinfo`, `/v1/people/me`, and Gmail `q=` search operators.
- **Embedded IMAP4rev1 server (`imap.gmail.com` parity)**:
  - Serves Thunderbird, Apple Mail, mutt, `himalaya`, and `async-imap` over TCP, `STARTTLS`, or implicit TLS.
  - Implements `X-GM-EXT-1` (`X-GM-MSGID`, `X-GM-THRID`, `X-GM-LABELS` fetch/search/store, `X-GM-RAW` backed by the Gmail query parser), `COMPRESS=DEFLATE` (with zip-bomb protection), `UTF8=ACCEPT`, `QUOTA` (`GETQUOTAROOT`/`GETQUOTA`), `XLIST`, `CHILDREN`, `CONDSTORE`/`QRESYNC`, `IDLE`, `SORT`, `THREAD` (`REFERENCES` and `ORDEREDSUBJECT`), `ESEARCH`, `LIST-EXTENDED`, `LIST-STATUS`, `UNSELECT`, `APPENDLIMIT`, `STATUS=SIZE`, `WITHIN` (`YOUNGER`/`OLDER`), `SASL-IR`, `LITERAL-`, `AUTH=XOAUTH2`, and `AUTH=OAUTHBEARER`.
- **Upstream Gmail and generic IMAP sync (`SyncSource`)**:
  - `GmailApiSyncSource`: OAuth2 refresh, paginated backfill, incremental `history.list` with 404 full-resync recovery, bidirectional drafts (`drafts.create`/`update`/`delete`), locally sent/imported message pushback (`messages.import`), and custom label pushback (`labels.create`/`patch`/`delete`).
  - `GmailImapSyncSource`: `X-GM-EXT-1` bidirectional `X-GM-LABELS` pushback (including `\Inbox` archive/unarchive from `[Gmail]/All Mail`), non-Gmail `UID COPY`/`UID MOVE`, `APPEND` + `APPENDUID` dedup for local Sent/Drafts, `CONDSTORE`/`QRESYNC` flag and deletion pull updates, outbound `XOAUTH2` + `UTF8=ACCEPT`, multi-folder sync (`gmail_imap_folders`), and optional background `IDLE` wakeup (`gmail_imap_idle`).
- **Multi-user, BYOD domains, encryption at rest, and deliverability**:
  - Multi-mailbox isolation (`NOGML_MAILBOXES`), aliases (`NOGML_MAILBOX_ALIASES`), `shared_mailboxes` team access, and per-mailbox `[[sync.accounts]]`.
  - BYOD custom domain onboarding (`/v1/domains`, `nogml domains`) for SES, Resend, and manual DNS with verified `From` anti-spoofing (`NOGML_REQUIRE_VERIFIED_FROM_DOMAIN`) and verified catch-all routing.
  - Persistent suppression lists auto-populated from Resend and AWS SES SNS bounce/complaint webhooks, per-domain daily send limits, and rolling bounce/complaint circuit breakers (`/v1/suppression`, `/v1/deliverability/stats`).
  - Pure-Rust `AES-256-GCM` encryption at rest (`src/crypto.rs`) with `zeroize` key handling, `NOGML_ENCRYPTION_STRICT`, and zero-downtime `nogml crypto rotate-key`.
- **CLI and operations (`nogml`)**:
  - `nogml mail`, `nogml config init|check`, `nogml doctor`, `nogml domains`, `nogml auth gmail|mint-token`, `nogml sync gmail`, `nogml storage migrate-blobs`, `nogml search reindex`, `nogml crypto generate-key|rotate-key`, `nogml schema`, and `nogml completions`.
  - Automatic JSON output when stdout is not a TTY, `--ndjson`, `--fields`, `--payload @-`, and deterministic exit codes (`0` ok, `2` validation/config, `3` policy block, `4` auth/upstream, `1` runtime).

## Quickstart

### Build

```bash
cargo build --release
```

### 1. Generate a config file and start the server (`nogml config`, `nogml serve`)

Create a starter `nogml.toml` (with a random bearer token saved to a mode `0600` file or printed once to stderr), validate it, and start the server:

```bash
# Generate starter nogml.toml and a mode 0600 bearer token file
nogml config init --output nogml.toml --token-file ./auth_token

# Validate syntax, secret sources, and TLS certificates (secrets are always redacted)
nogml config check --config nogml.toml

# Run live operational diagnostics (config, secret permissions, storage, blobs, IMAP TLS expiry, transport, security posture)
nogml doctor --config nogml.toml

# Start the server using nogml.toml (CLI flags and env vars override file settings)
nogml serve --config nogml.toml
```

For production deployments (Docker Compose with Caddy HTTPS, Linux `systemd` with `LoadCredential=`, PostgreSQL multi-node setup, Resend DNS/webhooks, IMAP TLS, and SQLite WAL backups), see the [Self-hosting guide](docs/self-hosting.md) and templates under [`deploy/`](deploy).

You can also pass all settings directly as CLI flags or environment variables without a config file:

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

Check health, readiness, active pluggable backends, OpenAPI 3.1 schema, and Prometheus metrics:

```bash
curl -s http://127.0.0.1:8080/healthz
curl -s http://127.0.0.1:8080/readyz
curl -s http://127.0.0.1:8080/v1/capabilities | jq .
curl -s http://127.0.0.1:8080/v1/openapi.json | jq .
curl -s -H "Authorization: Bearer <token>" http://127.0.0.1:8080/metrics
```

`GET /metrics` exports atomic Prometheus text metrics (`nogml_http_requests_total`, `nogml_messages_sent_total`, `nogml_messages_received_total`, `nogml_imap_active_connections`, `nogml_sse_active_connections`, `nogml_sync_runs_total`, `nogml_filter_decisions_total`, `nogml_policy_decisions_total`, `nogml_deliverability_events_total`, `nogml_deliverability_suppression_added_total`, and `nogml_deliverability_blocked_total`) and is protected by standard bearer authentication whenever auth tokens are configured. `GET /readyz` verifies `MailStore` and external `BlobStore` reachability and returns a sanitized `503` payload on failure without exposing internal error details.

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
nogml mail --url http://127.0.0.1:8080 send --to alice@example.com --subject "Update" --text "Ready." --idempotency-key send-001 --dry-run
nogml mail --url http://127.0.0.1:8080 briefing --followup-days 3 --limit 20
nogml mail --url http://127.0.0.1:8080 approvals list --status pending
nogml mail --url http://127.0.0.1:8080 approvals approve <approval_id> --note "Looks good"
nogml mail --url http://127.0.0.1:8080 audit --action send --limit 50
nogml mail --url http://127.0.0.1:8080 triage <thread_id> --archive true --mark-read true
nogml mail --url http://127.0.0.1:8080 batch-triage --query "newsletter" --archive true --mark-read true --dry-run
nogml mail --url http://127.0.0.1:8080 watch
nogml schema --command send
nogml schema --openapi
nogml completions zsh
```

### 4. Sync a Gmail or IMAP account (`nogml auth gmail`, `nogml sync gmail`)

Obtain an upstream Gmail OAuth2 refresh token using the loopback PKCE wizard (saved to a mode `0600` file, never logged), then run sync:

```bash
# Run loopback OAuth2 PKCE consent flow and save refresh token with mode 0600
# Pass --no-browser on headless or SSH machines to open the URL manually
GMAIL_CLIENT_ID=... \
GMAIL_CLIENT_SECRET=... \
nogml auth gmail --output-file ./secrets/gmail_refresh_token

# Gmail REST API v1 (OAuth2 refresh token or static access token)
GMAIL_CLIENT_ID=... \
GMAIL_CLIENT_SECRET=... \
GMAIL_REFRESH_TOKEN_FILE=./secrets/gmail_refresh_token \
nogml sync gmail --mode api --max-messages 500

# Upstream Gmail or generic IMAP (App Password or Gmail OAuth2 XOAUTH2)
GMAIL_IMAP_USER=you@gmail.com \
GMAIL_IMAP_PASSWORD=app-password \
nogml sync gmail --mode imap
```

Pass `--sync-interval-secs 60` to `nogml serve` to run sync periodically in the background (or enable `NOGML_GMAIL_IMAP_IDLE=true` for immediate IMAP push wakeups). Set `NOGML_SYNC_BIDIRECTIONAL=true` (or pass `--sync-bidirectional`) to push local read, star, archive, label, trash, delete, draft (`drafts.create`/`update`/`delete` or IMAP `APPEND`), locally created Sent or imported message (`messages.import` or IMAP `APPEND`), and custom label changes back upstream. Set `NOGML_TRANSPORT=gmail` (or `transport = "gmail"` in `nogml.toml`) to send outbound mail directly through the Gmail REST API reusing the same OAuth2 credentials, or set `NOGML_TRANSPORT=smtp` with `NOGML_SMTP_HOST=smtp.gmail.com` and `NOGML_SMTP_OAUTH_TOKEN` (or Gmail OAuth2 credentials) to authenticate over SMTP `XOAUTH2`. Pushback counts and status are exposed on `GET /v1/sync/status`.

### 5. Migrate blobs between backends (`nogml storage migrate-blobs`)

```bash
# Copy existing raw .eml messages and attachments from inline/fs storage into S3 or R2
NOGML_BLOB_S3_BUCKET=my-mail-blobs \
NOGML_BLOB_S3_REGION=auto \
NOGML_BLOB_S3_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com \
NOGML_BLOB_S3_ACCESS_KEY_ID=... \
NOGML_BLOB_S3_SECRET_ACCESS_KEY=... \
nogml storage migrate-blobs --db-path ./nogml.db --blob-backend inline --to s3
```

### 6. Enable hybrid semantic search (`nogml search reindex`)

Set `NOGML_SEARCH_BACKEND=hybrid` with an OpenAI-compatible embeddings endpoint (OpenAI, Ollama `/v1`, Voyage, or Mistral) to combine FTS5 keyword search with vector cosine similarity via Reciprocal Rank Fusion (RRF). Embeddings are stored as little-endian `f32` blobs in SQLite (`message_embeddings`) or PostgreSQL (`PostgresVectorStore`) with zero native extensions, and search falls back to lexical matching if the embedding endpoint is unavailable.

```bash
# Backfill embeddings for an existing SQLite mailbox (for example with local Ollama)
NOGML_SEARCH_BACKEND=hybrid \
NOGML_EMBEDDING_BASE_URL=http://127.0.0.1:11434/v1 \
NOGML_EMBEDDING_MODEL=nomic-embed-text \
nogml search reindex --db-path ./nogml.db
```

### 7. Multi-node deployment with PostgreSQL (`--features postgres`)

The default build stays a single binary with zero PostgreSQL dependencies. To run multiple `nogml` instances against one shared PostgreSQL database behind a load balancer, compile with `--features postgres` and select `NOGML_STORAGE=postgres` with `NOGML_DATABASE_URL`:

```bash
cargo build --release --features postgres

NOGML_STORAGE=postgres \
NOGML_DATABASE_URL=postgres://postgres:postgres@db.internal:5432/nogml \
nogml serve --bind 0.0.0.0:8080 --user-email agent@example.com
```

`PostgresStore` creates its schema idempotently on startup inside an advisory-locked transaction, maintains atomic `history_id` and IMAP `uid_next` counters in PostgreSQL transactions, and uses PostgreSQL full-text search (`to_tsvector` and `plainto_tsquery` with `ILIKE` fallback). When `NOGML_STORAGE=postgres` is active, `EventBus` bridges events across nodes via `PostgresEventBridge` (`LISTEN`/`NOTIFY` on `nogml_events`) so SSE `/v1/events`, IMAP `IDLE`, and Gmail `/watch` push hooks fan out across all replicas.

## Configuration

Load settings from a structured TOML file (`--config nogml.toml` / `NOGML_CONFIG`), environment variables, `*_FILE` secret files, or CLI flags with precedence `CLI flags > environment variables > nogml.toml > defaults`. Secret fields accept `file:///path/to/secret`, `file://$CREDENTIALS_DIRECTORY/secret`, `env://VAR_NAME`, and `*_FILE` environment variables, and are always redacted in `Debug` output and `nogml config check`. See [`deploy/nogml.example.toml`](deploy/nogml.example.toml) and the [Self-hosting guide](docs/self-hosting.md) for the full TOML schema and deployment templates.

Every CLI flag has a matching environment variable:

| Variable | CLI flag | Default | Description |
| --- | --- | --- | --- |
| `NOGML_CONFIG` | `--config` | *(none)* | Path to structured TOML configuration file (`nogml.toml`) |
| `NOGML_BIND` | `--bind` | `127.0.0.1:8080` | HTTP listen address |
| `NOGML_MAX_BODY_BYTES` | `--max-body-bytes` | `41943040` (40 MiB) | Max HTTP body and IMAP literal size |
| `NOGML_CORS_ORIGINS` | `--cors-origins` | *(any)* | Comma-separated allowed CORS origins |
| `NOGML_STORAGE` | `--storage` | `sqlite` | `MailStore` backend (`sqlite`, `memory`, or `postgres`) |
| `NOGML_DB_PATH` | `--db-path` | `nogml.db` | SQLite database file path |
| `NOGML_DATABASE_URL` | `--database-url` | *(none)* | PostgreSQL connection URL when `NOGML_STORAGE=postgres` (requires `--features postgres`) |
| `NOGML_BLOB_BACKEND` | `--blob-backend` | `inline` | `BlobStore` backend (`inline`, `fs`, `memory`, or `s3`) |
| `NOGML_BLOB_DIR` | `--blob-dir` | `nogml-blobs` | Directory for the `fs` blob backend |
| `NOGML_BLOB_S3_BUCKET` | `--blob-s3-bucket` | *(none)* | S3 bucket name for the `s3` blob backend |
| `NOGML_BLOB_S3_REGION` | `--blob-s3-region` | `us-east-1` | S3 region (use `auto` for Cloudflare R2) |
| `NOGML_BLOB_S3_ENDPOINT` | `--blob-s3-endpoint` | *(AWS default)* | Optional custom S3-compatible endpoint URL (Cloudflare R2, MinIO) |
| `NOGML_BLOB_S3_PREFIX` | `--blob-s3-prefix` | *(none)* | Optional key prefix prepended to all S3 object keys |
| `NOGML_BLOB_S3_ACCESS_KEY_ID` | `--blob-s3-access-key-id` | *(none)* | S3 access key ID |
| `NOGML_BLOB_S3_SECRET_ACCESS_KEY` | `--blob-s3-secret-access-key` | *(none)* | S3 secret access key |
| `NOGML_BLOB_S3_SESSION_TOKEN` | `--blob-s3-session-token` | *(none)* | Optional S3 STS session token |
| `NOGML_BLOB_S3_FORCE_PATH_STYLE` | `--blob-s3-force-path-style` | *(true with endpoint)* | Use path-style URLs (`/{bucket}/{key}`) instead of virtual-host URLs |
| `NOGML_AUTH_TOKENS` | `--auth-tokens` | *(empty = dev mode)* | Comma-separated bearer/API tokens with full global operator scopes |
| `NOGML_SCOPED_TOKENS` | `--scoped-tokens` | *(none)* | JSON array of scoped API keys (`token`, `mailbox_id`, `shared_mailboxes`, `scopes`, `draft_only`, `allowed_recipients`, `max_send_recipients`) |
| `NOGML_OAUTH2_CLIENT_ID` | `--oauth2-client-id` | *(disabled)* | Local OAuth2 client ID (enables `/oauth2/*` and `/.well-known/oauth-authorization-server` when paired with `NOGML_OAUTH2_SIGNING_SECRET`) |
| `NOGML_OAUTH2_CLIENT_SECRET` | `--oauth2-client-secret` | *(none)* | Optional local OAuth2 client secret verified on `POST /oauth2/token` |
| `NOGML_OAUTH2_SIGNING_SECRET` | `--oauth2-signing-secret` | *(disabled)* | HMAC-SHA256 signing secret for local OAuth2 JWT access and refresh tokens |
| `NOGML_USER_EMAIL` | `--user-email` | `me@localhost` | Primary mailbox address |
| `NOGML_MAILBOXES` | `--mailboxes` | *(empty)* | Comma-separated additional local mailboxes hosted by this instance |
| `NOGML_MAILBOX_ALIASES` | `--mailbox-aliases` | *(empty)* | Comma-separated alias mappings (`alias@example.com=target@example.com`) |
| `NOGML_DEFAULT_DOMAIN` | `--default-domain` | `localhost` | Default domain for generated `Message-ID` headers |
| `NOGML_TRANSPORT` | `--transport` | `resend` | `MailTransport` backend (`resend`, `ses`, `smtp`, or `gmail`) |
| `RESEND_API_KEY` | `--resend-api-key` | *(none)* | Resend API key (`re_...`) for outbound sends and the Receiving API |
| `RESEND_BASE_URL` | `--resend-base-url` | `https://api.resend.com` | Resend API base URL |
| `RESEND_WEBHOOK_SECRET` | `--resend-webhook-secret` | *(none)* | Svix signing secret (`whsec_...`) for `POST /webhooks/resend` |
| `NOGML_SES_REGION` | `--ses-region` | `us-east-1` | AWS region for SESv2 sends and S3 inbound downloads |
| `NOGML_SES_ENDPOINT` | `--ses-endpoint` | `https://email.<region>.amazonaws.com` | Custom AWS SESv2 endpoint URL |
| `NOGML_SES_ACCESS_KEY_ID` / `SECRET_ACCESS_KEY` / `SESSION_TOKEN` | `--ses-*` | *(none)* | AWS credentials for SigV4 signing of SES and S3 requests |
| `NOGML_SES_S3_ENDPOINT` | `--ses-s3-endpoint` | `https://s3.<region>.amazonaws.com` | Custom S3 endpoint URL for SES inbound S3 objects |
| `NOGML_SES_WEBHOOK_SECRET` | `--ses-webhook-secret` | *(none)* | Optional shared secret for `POST /webhooks/ses` (`X-Nogml-Webhook-Secret` header or `?secret=`) |
| `NOGML_SMTP_HOST` / `PORT` | `--smtp-host` / `--smtp-port` | `127.0.0.1` / `587` | Upstream SMTP submission host and TCP port |
| `NOGML_SMTP_TLS_MODE` | `--smtp-tls-mode` | `starttls` | SMTP TLS mode (`starttls`, `tls`, or `none`) |
| `NOGML_SMTP_USERNAME` / `PASSWORD` | `--smtp-username` / `--smtp-password` | *(none)* | Optional SMTP AUTH credentials (`PLAIN` or `LOGIN`) |
| `NOGML_SMTP_OAUTH_TOKEN` | `--smtp-oauth-token` | *(none)* | Optional static OAuth2 access token for SMTP `AUTH XOAUTH2` (falls back to Gmail OAuth2 credentials when unset and `smtp_password` is unset) |
| `NOGML_SMTP_HELO_DOMAIN` | `--smtp-helo-domain` | `NOGML_DEFAULT_DOMAIN` | Domain advertised in `EHLO` |
| `NOGML_DRAFT_ONLY` | `--draft-only` | `false` | Prevent direct outbound sends |
| `NOGML_DRAFT_ONLY_ACTION` | `--draft-only-action` | `block` | Action when `draft_only=true` (`block` or `downgrade`) |
| `NOGML_REQUIRE_APPROVAL` | `--require-approval` | `false` | Hold outbound sends in the persistent approval queue until approved via `/v1/approvals` or CLI |
| `NOGML_FIRST_CONTACT_APPROVAL` | `--first-contact-approval` | `false` | Hold outbound sends for human approval when any recipient has no prior sent history |
| `NOGML_REQUIRE_VERIFIED_FROM_DOMAIN` | `--require-verified-from-domain` | `false` | Reject outbound sends whose `From` domain is neither `default_domain` nor a `verified` BYOD domain owned by the sender's mailbox |
| `NOGML_DLP_ACTION` | `--dlp-action` | `off` | Outbound secret and PII DLP scanner action (`off`, `hold`, or `deny`) |
| `NOGML_DAILY_SEND_LIMIT_PER_DOMAIN` | `--daily-send-limit-per-domain` | `0` (unlimited) | Maximum outbound sends per UTC day per sender domain |
| `NOGML_MAX_BOUNCE_RATE` / `NOGML_MAX_COMPLAINT_RATE` | `--max-bounce-rate` / `--max-complaint-rate` | `0.05` / `0.001` | Rolling bounce and complaint thresholds that trip the per-domain circuit breaker |
| `NOGML_DELIVERABILITY_MIN_SAMPLES` / `WINDOW_SECS` | `--deliverability-min-samples` / `--deliverability-window-secs` | `20` / `86400` | Minimum sent sample count and rolling window in seconds for the circuit breaker |
| `NOGML_APPROVAL_TTL_SECS` | `--approval-ttl-secs` | `86400` | Time-to-live in seconds for pending outbound approval requests |
| `NOGML_APPROVAL_WEBHOOK_URL` | `--approval-webhook-url` | *(none)* | Optional HTTP POST webhook URL (generic JSON and Slack-compatible `text`) notified when a send enters approval |
| `NOGML_ALLOWED_RECIPIENTS` | `--allowed-recipients` | *(unrestricted)* | Comma-separated allowlist (`a@b.com`, `@domain.com`, `*.domain.com`) |
| `NOGML_MAX_SEND_RECIPIENTS` | `--max-send-recipients` | `50` | Maximum recipients across `to`, `cc`, and `bcc` |
| `NOGML_DEFAULT_MAX_BODY_CHARS` | `--default-max-body-chars` | `4000` | Default body character limit on AI and MCP reads (cap `100000`) |
| `NOGML_UNTRUSTED_CONTENT_GUARD` | `--untrusted-content-guard` | `true` | Strip control and BiDi chars and set `_meta.untrusted_external_content` |
| `NOGML_IMAP_BIND` | `--imap-bind` | *(disabled)* | Embedded IMAP plain and `STARTTLS` listen address |
| `NOGML_IMAP_TLS_BIND` | `--imap-tls-bind` | *(disabled)* | Embedded IMAP implicit TLS listen address |
| `NOGML_IMAP_TLS_CERT` / `KEY` | `--imap-tls-cert` / `--imap-tls-key` | *(none)* | PEM certificate chain and private key for IMAP TLS |
| `NOGML_IMAP_USERNAME` / `PASSWORD` | `--imap-username` / `--imap-password` | *(user_email / first token)* | IMAP login override |
| `NOGML_IMAP_QUOTA_BYTES` | `--imap-quota-bytes` | `16106127360` (15 GiB) | Storage quota ceiling advertised by RFC 2087 `GETQUOTAROOT` / `GETQUOTA` |
| `NOGML_SYNC_MODE` | `--sync-mode` | `api` | Upstream Gmail sync mode (`api` or `imap`) |
| `NOGML_SYNC_BIDIRECTIONAL` | `--sync-bidirectional` | `false` | Push local label, flag, draft, Sent, trash, and delete changes back to the upstream account |
| `NOGML_SYNC_INTERVAL_SECS` | `--sync-interval-secs` | `0` | Background sync interval in seconds (`0` disables) |
| `GMAIL_CLIENT_ID` / `SECRET` / `REFRESH_TOKEN` / `ACCESS_TOKEN` | `--gmail-*` | *(none)* | Upstream Gmail REST API and Gmail IMAP `XOAUTH2` credentials |
| `GMAIL_IMAP_USER` / `PASSWORD` | `--gmail-imap-*` | *(none)* | Upstream IMAP login credentials |
| `NOGML_GMAIL_IMAP_FOLDERS` / `ARCHIVE_MAILBOX` / `IDLE` | `--gmail-imap-folders` / `--gmail-imap-archive-mailbox` / `--gmail-imap-idle` | *(All Mail / Archive / `false`)* | Multi-folder IMAP sync list, non-Gmail archive target, and optional background `IDLE` wakeup |
| `NOGML_WATCH_WEBHOOK_URL` | `--watch-webhook-url` | *(none)* | Optional push webhook URL for active Gmail `/watch` subscriptions |
| `NOGML_FILTER_AUTH_RESULTS` | `--filter-auth-results` | `false` | Enable `AuthResultsFilter` to evaluate `Authentication-Results` headers (`spf`, `dkim`, `dmarc`) |
| `NOGML_FILTER_DMARC_FAIL_ACTION` | `--filter-dmarc-fail-action` | `spam` | Action on DMARC failure (`spam`, `reject`, `tag`, `allow`) |
| `NOGML_FILTER_SPF_FAIL_ACTION` | `--filter-spf-fail-action` | `tag` | Action on SPF failure (`spam`, `reject`, `tag`, `allow`; `softfail` downgrades to `tag`) |
| `NOGML_FILTER_DKIM_FAIL_ACTION` | `--filter-dkim-fail-action` | `tag` | Action on DKIM failure (`spam`, `reject`, `tag`, `allow`) |
| `NOGML_RSPAMD_URL` | `--rspamd-url` | *(disabled)* | Rspamd base URL (`{url}/checkv2`) to enable `RspamdFilter` |
| `NOGML_RSPAMD_PASSWORD` | `--rspamd-password` | *(none)* | Optional `Password` header sent to Rspamd |
| `NOGML_RSPAMD_TIMEOUT_MS` | `--rspamd-timeout-ms` | `5000` | Rspamd HTTP request timeout in milliseconds |
| `NOGML_RSPAMD_SPAM_THRESHOLD` | `--rspamd-spam-threshold` | *(Rspamd `required_score`)* | Optional score threshold override for `Spam` classification |
| `NOGML_RSPAMD_REJECT_ACTION` | `--rspamd-reject-action` | `reject` | Action on Rspamd `reject` or `soft reject` (`reject` or `spam`) |
| `NOGML_RSPAMD_FAIL_CLOSED` | `--rspamd-fail-closed` | `false` | Reject mail when Rspamd is unreachable or times out (default fails open to `Allow`) |
| `NOGML_LLM_TRIAGE_BASE_URL` | `--llm-triage-base-url` | *(disabled; `https://api.openai.com/v1` when key set)* | OpenAI-compatible base URL (`{url}/chat/completions`) to enable `LlmTriageFilter` |
| `NOGML_LLM_TRIAGE_API_KEY` | `--llm-triage-api-key` | *(none)* | Bearer token for the LLM triage endpoint (always fails open to `Allow` on errors) |
| `NOGML_LLM_TRIAGE_MODEL` | `--llm-triage-model` | `gpt-4o-mini` | Model name sent to `/chat/completions` |
| `NOGML_LLM_TRIAGE_TIMEOUT_MS` | `--llm-triage-timeout-ms` | `10000` | LLM triage HTTP timeout in milliseconds |
| `NOGML_LLM_TRIAGE_MAX_BODY_CHARS` | `--llm-triage-max-body-chars` | `2000` | Maximum sanitized plain-text body characters sent to the LLM classifier |
| `NOGML_SEARCH_BACKEND` | `--search-backend` | `store` | `SearchIndex` backend (`store` [default, zero API keys] or `hybrid`) |
| `NOGML_EMBEDDING_BASE_URL` | `--embedding-base-url` | *(OpenAI `/v1` when key set)* | OpenAI-compatible base URL (`{url}/embeddings`) for `hybrid` search |
| `NOGML_EMBEDDING_API_KEY` | `--embedding-api-key` | *(none)* | Optional Bearer API key for the embeddings endpoint |
| `NOGML_EMBEDDING_MODEL` | `--embedding-model` | `text-embedding-3-small` | Embedding model name sent to `/embeddings` |
| `NOGML_EMBEDDING_TIMEOUT_SECS` | `--embedding-timeout-secs` | `15` | HTTP timeout in seconds for embedding requests |
| `NOGML_ENCRYPTION_KEY` | `--encryption-key` | *(disabled)* | Master AES-256-GCM key (`<kid>:<base64_or_hex>` or bare 32-byte key) for encrypting stored secrets at rest (`NOGML_ENCRYPTION_KEY_FILE` supported) |
| `NOGML_ENCRYPTION_PREVIOUS_KEYS` | `--encryption-previous-keys` | *(empty)* | Comma-separated previous `<kid>:<key>` entries kept during zero-downtime key rotation (`NOGML_ENCRYPTION_PREVIOUS_KEYS_FILE` supported) |
| `NOGML_ENCRYPTION_STRICT` | `--encryption-strict` | `false` | When `true` with `NOGML_ENCRYPTION_KEY` set, reject unencrypted plaintext secrets on read (enable after running `nogml crypto rotate-key`) |
| `NOGML_LOG_JSON` | `--log-json` | `false` | Emit JSON logs |

## Connecting clients

For complete setup instructions, configuration templates (Superhuman, Google SDKs, Apple Mail, Thunderbird, `himalaya`, `mutt`, Claude Desktop, Cursor), known caveats, and running the opt-in live provider smoke tests (`cargo test --test live_smoke -- --ignored --nocapture`), see the [Client compatibility guide](docs/clients.md).

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
- `GET /oauth2/v2/userinfo`, `GET /oauth2/v3/userinfo`, and `GET /v1/people/me?personFields=names,emailAddresses`
- `GET /gmail/v1/users/me/messages?q=from:alice has:attachment`
- `GET /gmail/v1/users/me/messages/{id}?format=full&fields=id,snippet,payload/headers`
- `POST /upload/gmail/v1/users/me/messages/send?uploadType=multipart`
- `POST /upload/gmail/v1/users/me/messages/send?uploadType=resumable` (returns `Location` for `PUT` `Content-Range` chunks with `308` status probes and `200` completion across `messages/send`, `messages`, `messages/import`, `drafts`, `drafts/{id}`, and `drafts/send`)
- `POST /batch/gmail/v1` (`multipart/mixed` batch requests)
- `GET /gmail/v1/users/me/history?startHistoryId=...`
- `POST /gmail/v1/users/me/watch` (with `NOGML_WATCH_WEBHOOK_URL`, posts `{emailAddress, historyId}` notifications)

#### Official SDK and client base-URL overrides

Node.js (`@googleapis/gmail`):

```js
import { gmail } from "@googleapis/gmail";

const client = gmail({
  version: "v1",
  rootUrl: "http://127.0.0.1:8080/",
  headers: { Authorization: "Bearer tok_secret_1" },
});
```

Python (`google-api-python-client`):

```python
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

creds = Credentials(token="tok_secret_1")
service = build(
    "gmail",
    "v1",
    credentials=creds,
    client_options={"api_endpoint": "http://127.0.0.1:8080"},
)
```

Superhuman-style and custom HTTP clients: override the Gmail REST root from `https://gmail.googleapis.com` to `http://127.0.0.1:8080` (or your HTTPS reverse proxy URL). Keep the standard `/gmail/v1/...`, `/upload/gmail/v1/...`, and `/batch/gmail/v1` paths intact and pass your configured `NOGML_AUTH_TOKENS` value in `Authorization: Bearer <token>` (or `X-API-Key`). When serving behind TLS termination, forward `Host` and `X-Forwarded-Proto: https` so `uploadType=resumable` `Location` headers use your public HTTPS origin.

### Scoped API keys and local OAuth2

Use `nogml auth mint-token` or `NOGML_SCOPED_TOKENS` to issue least-privilege keys with explicit scopes (`read`, `write`, `send`, `admin`) and optional per-agent outbound overrides (`draft_only`, `allowed_recipients`, `max_send_recipients`). Scopes are enforced across `/v1`, `/gmail/v1`, `/upload/gmail/v1`, `/batch/gmail/v1`, `/mcp`, and IMAP (`STORE`, `COPY`, `MOVE`, `EXPUNGE`, `APPEND`, `CREATE`, `DELETE`, and `RENAME` require `write`). Legacy `NOGML_AUTH_TOKENS` entries keep global operator privileges.

```bash
# Mint a per-agent token stored in a mode 0600 file and emit a [[auth.scoped_tokens]] snippet
nogml auth mint-token \
  --mailbox agent@example.com \
  --scopes read,write \
  --draft-only \
  --allowed-recipients @example.com \
  --max-send-recipients 5 \
  --output-file ./secrets/agent_token >> nogml.toml

# Or emit JSON directly for NOGML_SCOPED_TOKENS
NOGML_SCOPED_TOKENS="$(nogml auth mint-token --mailbox agent@example.com --scopes read --draft-only --json)" \
nogml serve --user-email agent@example.com
```

To support Gmail API SDKs and IMAP clients that expect OAuth2 token exchange, set `NOGML_OAUTH2_CLIENT_ID`, `NOGML_OAUTH2_SIGNING_SECRET`, and optionally `NOGML_OAUTH2_CLIENT_SECRET`. `nogml` then exposes `GET /.well-known/oauth-authorization-server`, `GET /oauth2/authorize` (with PKCE `S256` and `plain`), and `POST /oauth2/token` (`authorization_code`, `refresh_token`, and `client_credentials`), minting HS256 JWT bearer tokens accepted on HTTP endpoints and IMAP `AUTHENTICATE XOAUTH2` / `OAUTHBEARER`.

### Multi-mailbox hosting

A single `nogml serve` process can host multiple isolated mailboxes by listing additional addresses in `NOGML_MAILBOXES` (or `--mailboxes`) and issuing per-mailbox credentials in `NOGML_SCOPED_TOKENS` (each entry carries a `mailbox_id`). Mailboxes are partitioned by `mailbox_id` across `MailStore` (`SqliteStore`, `MemoryStore`, and `PostgresStore`), `BlobStore` (`mailboxes/<sanitized_mailbox>/...`), `SearchIndex` (FTS5 and vector embeddings), `EventBus` (SSE `/v1/events`, IMAP `IDLE`, and Gmail `/watch`), `sync_state`, contacts, inbox rules, and approvals.

```bash
NOGML_USER_EMAIL=alice@example.com \
NOGML_MAILBOXES=bob@example.com \
NOGML_SCOPED_TOKENS='[{"token":"tok_alice","mailbox_id":"alice@example.com","scopes":["read","write","send","admin"]},{"token":"tok_bob","mailbox_id":"bob@example.com","scopes":["read","write","send","admin"]}]' \
nogml serve --imap-bind 127.0.0.1:1143
```

- **HTTP and MCP**: Authenticated requests are scoped automatically to `Principal.mailbox_id`. Scoped tokens with `shared_mailboxes` can also access authorized team mailboxes via `/gmail/v1/users/<shared>/...` or the `X-Nogml-Mailbox: <shared>` header on `/v1/*` and `POST /mcp`, while requests targeting any unauthorized mailbox return `403 Forbidden`.
- **Inbound webhooks and aliases**: When multiple mailboxes or `[mailboxes.aliases]` (`NOGML_MAILBOX_ALIASES`) are configured, `POST /webhooks/resend` and `POST /webhooks/ses` map alias envelope recipients to their target mailbox and deliver only to matching local mailboxes. Mailbox owners can also send from their configured aliases via `from` / `From:` and Gmail `settings/sendAs`.
- **IMAP**: Clients authenticate with `LOGIN <mailbox_id> <scoped_token>`, `AUTHENTICATE PLAIN`, `AUTHENTICATE XOAUTH2`, or `AUTHENTICATE OAUTHBEARER` for their own mailbox or any mailbox listed in their token's `shared_mailboxes`, and see only that mailbox's folders, UIDs, messages, and `IDLE` updates.
- **Multi-account upstream sync**: Configure multiple `[[sync.accounts]]` entries in `nogml.toml` to run independent per-mailbox background sync loops in `nogml serve`, or run `nogml sync gmail --mailbox bob@example.com` to select and sync a specific account with isolated `sync_state` checkpoints.

### IMAP clients

Set `--imap-bind 127.0.0.1:1143` (or `--imap-tls-bind 127.0.0.1:1993` with a TLS certificate and key). Authenticate with `--user-email` (or `NOGML_IMAP_USERNAME`) and your bearer token or `NOGML_IMAP_PASSWORD` via `LOGIN` or `AUTHENTICATE PLAIN`, or use `AUTHENTICATE XOAUTH2` / `AUTHENTICATE OAUTHBEARER` with a scoped API key or local OAuth2 access token. Configure the RFC 2087 `QUOTA` storage ceiling with `NOGML_IMAP_QUOTA_BYTES` (`[imap].quota_bytes`, default 15 GiB).

### Resend and AWS SES webhooks

Set your Resend webhook endpoint to `POST https://<your-host>/webhooks/resend` with `RESEND_WEBHOOK_SECRET=whsec_...`. On each request, `nogml` verifies the Svix signature in constant time, fetches the inbound message and attachments from the Resend Receiving API, runs `InboundFilter`, threads replies using `In-Reply-To` and `References`, deduplicates by `Message-ID`, and records delivery status events (`email.sent`, `email.delivered`, `email.bounced`, `email.complained`, and others) into the deliverability suppression and circuit-breaker store.

For AWS SES inbound mail, point an SNS HTTP(S) subscription at `POST https://<your-host>/webhooks/ses` (optionally adding `?secret=<token>` or `X-Nogml-Webhook-Secret` matching `NOGML_SES_WEBHOOK_SECRET`). `nogml` logs SNS `SubscriptionConfirmation` URLs, ingests `Received` notifications from either inline base64 `content` or SigV4-signed S3 `.eml` objects through the same `ingest_inbound_rfc2822` pipeline, and records SNS `Bounce` and `Complaint` notifications into the deliverability protection subsystem.

## License

Apache-2.0. See [LICENSE](LICENSE).
