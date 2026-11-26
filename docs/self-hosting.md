# Self-hosting nogml

This guide covers running `nogml` in production on a single host with Docker Compose or `systemd`, scaling across multiple nodes with PostgreSQL and S3/R2, configuring Resend DNS and webhooks, enabling IMAP TLS, backing up SQLite and blob data, and hardening your deployment.

Ready-to-use templates live in [`deploy/`](../deploy):

- [`deploy/nogml.example.toml`](../deploy/nogml.example.toml): complete annotated configuration reference
- [`deploy/docker-compose.yml`](../deploy/docker-compose.yml): single-node Docker Compose stack with Caddy and Docker secrets
- [`deploy/Caddyfile`](../deploy/Caddyfile): automatic HTTPS reverse proxy with unbuffered SSE/MCP streaming
- [`deploy/nogml.service`](../deploy/nogml.service): hardened Linux `systemd` unit using `DynamicUser=yes` and `LoadCredential=`

## Configuration and secret loading

`nogml` reads a structured TOML file via `--config <path>` or `NOGML_CONFIG` across all subcommands (`serve`, `mcp`, `sync`, `mail`, `storage`, `search`, `config`, `crypto`, `doctor`, `auth`).

Precedence from highest to lowest:

1. CLI flags (`--bind`, `--user-email`, `--draft-only`)
2. Direct environment variables (`NOGML_BIND`, `RESEND_API_KEY`)
3. `*_FILE` environment variables (`RESEND_API_KEY_FILE`, `NOGML_AUTH_TOKENS_FILE`)
4. Values in `nogml.toml`
5. Built-in defaults

### Generate and validate a config file

Generate a starter `nogml.toml` and a random bearer token:

```bash
# Writes nogml.toml without hardcoded secrets and prints one random bearer token to stderr
nogml config init --output nogml.toml

# Or write the generated bearer token directly to a mode 0600 file referenced via file://
nogml config init --output /etc/nogml/nogml.toml --token-file /etc/nogml/secrets/auth_tokens
```

Validate syntax, secret files, environment references, backend consistency, and IMAP TLS certificates before starting or reloading the server:

```bash
nogml config check --config /etc/nogml/nogml.toml
```

`nogml config check` prints a JSON report (`{ "ok", "config_file", "warnings", "errors", "effective_config" }`) with every secret, token, password, and database URL replaced by `"[REDACTED]"`. It exits `0` when valid and `2` on any configuration error.

Run live operational diagnostics with `nogml doctor`:

```bash
nogml doctor --config /etc/nogml/nogml.toml
```

`nogml doctor` checks config validation, secret file Unix permissions (`mode & 0o077 != 0`), live `MailStore` connectivity, `BlobStore` reachability and filesystem writability, IMAP TLS certificate validity and expiry (warning under 30 days remaining and failing when expired), active transport credentials, and production security posture (`auth_tokens`/`scoped_tokens`, `allow_insecure_webhooks`, `allow_private_endpoints`). It prints structured JSON (pretty on a TTY, compact when piped), never prints secret values, and exits `0` when no check fails or `2` if any check fails.

Generate shell completion scripts for `bash`, `zsh`, `fish`, `elvish`, or `powershell`:

```bash
nogml completions zsh > "${fpath[1]}/_nogml"
```

### Mint per-agent scoped tokens (`nogml auth mint-token`)

Generate a high-entropy scoped token for each agent without hand-editing TOML or JSON. Pass `--output-file` to store the raw secret in a mode `0600` file and emit a `file://` reference so no plaintext token enters `nogml.toml`:

```bash
# Write the raw token to a mode 0600 file and append the [[auth.scoped_tokens]] block to nogml.toml
nogml auth mint-token \
  --mailbox agent@example.com \
  --scopes read,write \
  --draft-only \
  --allowed-recipients @example.com,partner@acme.org \
  --max-send-recipients 5 \
  --output-file /etc/nogml/secrets/triage_agent_token >> /etc/nogml/nogml.toml

# Or emit a JSON array compatible with NOGML_SCOPED_TOKENS
nogml auth mint-token --mailbox agent@example.com --scopes read --json
```

Validate the updated config with `nogml config check --config /etc/nogml/nogml.toml`.

### Obtain a Gmail OAuth2 refresh token (`nogml auth gmail`)

For upstream Gmail API sync (`sync.mode = "api"`), run the loopback OAuth2 PKCE (`S256`) consent flow to obtain a refresh token and save it directly to a mode `0600` file:

```bash
GMAIL_CLIENT_ID="your-client-id.apps.googleusercontent.com" \
GMAIL_CLIENT_SECRET="your-client-secret" \
nogml auth gmail \
  --output-file /etc/nogml/secrets/gmail_refresh_token
```

Pass `--no-browser` on headless or SSH hosts to print the authorization URL to stderr without launching a local browser. `nogml auth gmail` binds an ephemeral loopback callback (`http://127.0.0.1:<port>/callback`), verifies the CSRF `state`, exchanges the authorization code with the PKCE `code_verifier`, writes the refresh token with mode `0600`, and prints a redacted JSON summary with the `[sync]` `gmail_refresh_token = "file://..."` snippet. Raw tokens are never written to logs or stdout.

### Native Gmail outbound transport and SMTP XOAUTH2

To send outbound mail directly through Gmail using the same OAuth2 credentials, set `NOGML_TRANSPORT=gmail` or `transport = "gmail"` (equivalently `[transport] backend = "gmail"`) in `nogml.toml`:

```toml
transport = "gmail"

[sync]
mode = "api"
bidirectional = true
gmail_client_id = "your-client-id.apps.googleusercontent.com"
gmail_client_secret = "file:///etc/nogml/secrets/gmail_client_secret"
gmail_refresh_token = "file:///etc/nogml/secrets/gmail_refresh_token"
```

`GmailApiTransport` posts base64url-encoded RFC 5322 MIME messages to `/gmail/v1/users/me/messages/send`, sets `threadId` when replying to synced Gmail threads, refreshes expired OAuth2 tokens automatically on HTTP 401, and stores the returned Gmail message ID as `upstream_gmail_id` so subsequent sync passes do not create duplicates.

If you prefer SMTP submission against `smtp.gmail.com:587` with OAuth2 instead of an App Password, set `transport = "smtp"` and provide `NOGML_SMTP_OAUTH_TOKEN` (`[smtp] oauth_token`) or leave `[smtp] password` unset while Gmail OAuth2 credentials are configured:

```toml
transport = "smtp"

[smtp]
host = "smtp.gmail.com"
port = 587
tls_mode = "starttls"
username = "you@gmail.com"
```

When `sync.bidirectional = true` in Gmail API mode, `nogml` syncs upstream drafts (`users.drafts.list`/`get`), pushes local draft create/update/delete changes (`drafts.create`/`update`/`delete`), imports locally sent or imported messages lacking an `upstream_gmail_id` (`messages.import`), and pushes local custom label create/rename/delete mutations (`labels.create`/`patch`/`delete`).

### Multi-account sync, mailbox aliases, and shared mailboxes

Configure multiple upstream Gmail sync accounts, inbound/outbound aliases, and shared team mailboxes in `nogml.toml` without separate cron jobs:

```toml
[mailboxes.aliases]
"j@example.com" = "justin@example.com"
"sales@example.com" = "team@example.com"

[[auth.scoped_tokens]]
token = "file:///etc/nogml/secrets/alice_token"
mailbox_id = "alice@example.com"
shared_mailboxes = ["team@example.com"]
scopes = ["read", "write", "send"]

[[sync.accounts]]
mailbox_id = "alice@example.com"
mode = "api"
interval_secs = 60
gmail_client_id = "alice-client.apps.googleusercontent.com"
gmail_client_secret = "env://ALICE_GMAIL_CLIENT_SECRET"
gmail_refresh_token = "file:///etc/nogml/secrets/alice_refresh"

[[sync.accounts]]
mailbox_id = "bob@example.com"
mode = "api"
interval_secs = 60
gmail_client_id = "bob-client.apps.googleusercontent.com"
gmail_client_secret = "env://BOB_GMAIL_CLIENT_SECRET"
gmail_refresh_token = "file:///etc/nogml/secrets/bob_refresh"
```

- `nogml serve` spawns an independent periodic background sync loop per `[[sync.accounts]]` entry (with per-mailbox locks so one slow account never blocks another), and `nogml sync gmail --mailbox <email>` selects the matching account automatically.
- `[mailboxes.aliases]` (or `NOGML_MAILBOX_ALIASES=j@example.com=justin@example.com,sales@example.com=team@example.com`) routes Resend and SES webhook recipients to their target mailbox and allows sending from configured aliases via `From` / Gmail `settings/sendAs`.
- Scoped tokens with `shared_mailboxes` can read and send in those mailboxes via `/gmail/v1/users/<shared>/...`, `X-Nogml-Mailbox: <shared>` on `/v1/*` and `POST /mcp`, and IMAP `LOGIN`, `AUTHENTICATE PLAIN`, or `AUTHENTICATE XOAUTH2`, while remaining blocked (`403`) from all other mailboxes.

### Bring-your-own-domain (BYOD) onboarding and verified From guard

Register custom sending and receiving domains dynamically without restarting `nogml` using `/v1/domains` or `nogml domains`. Domains are stored in the `domains` table across SQLite, Memory, and PostgreSQL and backed by a pluggable `DomainProvider` (`ses`, `resend`, or `manual`).

```bash
# Register a custom domain via REST (returns required DKIM, SPF, MX, and DMARC DNS records)
curl -fsS -X POST http://127.0.0.1:8080/v1/domains \
  -H "Authorization: Bearer ${NOGML_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"domain":"acme.io","provider":"ses","catch_all_mailbox":"team@example.com"}'

# Re-check live verification status against AWS SESv2 or Resend
curl -fsS -X POST http://127.0.0.1:8080/v1/domains/acme.io/verify \
  -H "Authorization: Bearer ${NOGML_TOKEN}"

# Or manage domains from the CLI
nogml domains add acme.io --provider resend --catch-all team@example.com
nogml domains verify acme.io
nogml domains list
```

- **Anti-spoofing (`require_verified_from_domain`)**: Set `[safety] require_verified_from_domain = true` (or `NOGML_REQUIRE_VERIFIED_FROM_DOMAIN=true` / `--require-verified-from-domain`) so outbound sends reject any `From` address whose domain is neither `default_domain` nor a `verified` domain owned by the sender's mailbox (returning HTTP `403` with error code `unverified_from_domain`).
- **Dynamic catch-all inbound routing**: When a Resend or SES inbound webhook delivers to an address with no explicit `mailbox_aliases` or local mailbox match, `nogml` checks whether the recipient domain is a `verified` BYOD domain with `catch_all_mailbox` configured and routes the message to that mailbox. Explicit aliases always take precedence, and unverified domains never trigger catch-all routing.
- **Tenant isolation**: Non-admin tokens can only list, inspect, verify, update, and delete domains owned by mailboxes they can access. Attempting to register a domain already owned by another mailbox returns `409 Conflict`, and manually overriding verification status on a `manual` domain requires `admin` scope.

### Deliverability protection, suppression lists, and circuit breakers

`nogml` protects shared Resend and AWS SES sender reputation with persistent suppression lists, optional per-domain daily send limits, and automatic bounce/complaint circuit breakers stored across SQLite, Memory, and PostgreSQL (`suppression_list`, `deliverability_events`, and `deliverability_domain_state`).

- **Automatic bounce and complaint ingestion**:
  - AWS SES SNS `Bounce` (`Permanent`) and `Complaint` notifications on `POST /webhooks/ses` automatically add bounced or complaining recipients to `suppression_list` and record `hard_bounce` or `complaint` events. `Transient` bounces record `soft_bounce` events without suppressing the recipient.
  - Svix-verified Resend `email.bounced` (hard bounce) and `email.complained` webhooks on `POST /webhooks/resend` automatically add recipients to `suppression_list` and record deliverability events.
- **Outbound enforcement**: Every send path (`/v1/messages/send`, `/v1/drafts/{id}/send`, `/gmail/v1`, approvals, scheduled sends, and mailto unsubscribe) checks `SuppressionListPolicy`, `DeliverabilityCircuitBreakerPolicy`, and `DomainQuotaPolicy` before calling `MailTransport`. Blocked sends return HTTP `403` with structured error codes (`recipient_suppressed`, `daily_send_limit_exceeded`, or `deliverability_circuit_open`).
- **Configuration** (`[safety]` in `nogml.toml`, CLI flags, or environment variables):
  - `daily_send_limit_per_domain` (`NOGML_DAILY_SEND_LIMIT_PER_DOMAIN` or `NOGML_DAILY_SEND_LIMIT`, default `0` / disabled)
  - `deliverability_max_bounce_rate` (`NOGML_MAX_BOUNCE_RATE`, default `0.05` = 5%)
  - `deliverability_max_complaint_rate` (`NOGML_MAX_COMPLAINT_RATE`, default `0.001` = 0.1%)
  - `deliverability_min_samples` (`NOGML_DELIVERABILITY_MIN_SAMPLES`, default `20`)
  - `deliverability_window_secs` (`NOGML_DELIVERABILITY_WINDOW_SECS`, default `86400` = 24 hours)
- **REST management API**:
  - `GET /v1/suppression` (`read` scope) and `POST /v1/suppression`, `DELETE /v1/suppression/{email}` (`admin` scope)
  - `GET /v1/deliverability/stats` (`read` scope) for per-domain sent, bounce, complaint counts, computed rates, daily quota usage, and circuit-breaker state
  - `POST /v1/deliverability/domains/{domain}/pause` and `POST /v1/deliverability/domains/{domain}/resume` (`admin` scope) to manually pause or reset a tripped domain circuit breaker

```bash
# Inspect per-domain deliverability health and circuit-breaker state
curl -fsS -H "Authorization: Bearer ${NOGML_TOKEN}" \
  "http://127.0.0.1:8080/v1/deliverability/stats"

# Resume a tripped domain after fixing DNS or list hygiene (admin scope)
curl -fsS -X POST -H "Authorization: Bearer ${NOGML_ADMIN_TOKEN}" \
  "http://127.0.0.1:8080/v1/deliverability/domains/example.com/resume"
```

### Secret reference formats

All secret fields support three non-plaintext mechanisms so secrets never need to be checked into `nogml.toml` or exposed in process command lines:

- `file:///path/to/secret`: reads a UTF-8 file and trims trailing `\r\n`. Relative `file://` paths resolve relative to the `nogml.toml` directory.
- `file://$CREDENTIALS_DIRECTORY/secret`: resolves against `systemd`'s `CREDENTIALS_DIRECTORY` environment variable set by `LoadCredential=`.
- `env://VAR_NAME`: reads the named environment variable and fails with exit code `2` if unset.
- `*_FILE` environment variables: standard Docker secrets, Kubernetes projected volume, and `systemd` convention (`RESEND_API_KEY_FILE`, `RESEND_WEBHOOK_SECRET_FILE`, `NOGML_AUTH_TOKENS_FILE`, `NOGML_SCOPED_TOKENS_FILE`, `NOGML_IMAP_PASSWORD_FILE`, `NOGML_DATABASE_URL_FILE`, `NOGML_BLOB_S3_SECRET_ACCESS_KEY_FILE`, `NOGML_SES_SECRET_ACCESS_KEY_FILE`, `NOGML_SES_WEBHOOK_SECRET_FILE`, `NOGML_SMTP_PASSWORD_FILE`, `NOGML_SMTP_OAUTH_TOKEN_FILE`, `NOGML_RSPAMD_PASSWORD_FILE`, `NOGML_LLM_TRIAGE_API_KEY_FILE`, `NOGML_EMBEDDING_API_KEY_FILE`, `NOGML_ENCRYPTION_KEY_FILE`, `NOGML_ENCRYPTION_PREVIOUS_KEYS_FILE`, `NOGML_OAUTH2_CLIENT_SECRET_FILE`, `NOGML_OAUTH2_SIGNING_SECRET_FILE`, `GMAIL_CLIENT_SECRET_FILE`, `GMAIL_REFRESH_TOKEN_FILE`, `GMAIL_ACCESS_TOKEN_FILE`, `GMAIL_IMAP_PASSWORD_FILE`).

On Unix, `nogml config check` warns if any `file://` secret, `*_FILE` target, or IMAP TLS private key is readable by group or other (`mode & 0o077 != 0`). Restrict secret files with `chmod 0600`.

### Encryption at rest and key rotation (`nogml crypto`)

Enable AES-256-GCM encryption at rest so stored `sendAs.smtp_msa.password` and `inbox_rules.webhook_secret` fields are written as `enc:v1:<kid>:<nonce>:<ciphertext>` envelopes instead of plaintext. Legacy plaintext rows continue to decrypt transparently until rotated.

Generate a 32-byte key stored in a mode `0600` file (raw key bytes are never printed to stdout or logs when `--output-file` is set):

```bash
nogml crypto generate-key --kid k1 --output-file /etc/nogml/secrets/encryption_key
```

Reference it in `nogml.toml` (or via `NOGML_ENCRYPTION_KEY` / `NOGML_ENCRYPTION_KEY_FILE`):

```toml
[security]
encryption_key = "file:///etc/nogml/secrets/encryption_key"
```

To rotate from `k1` to `k2` without downtime:

```bash
# 1. Generate the new primary key
nogml crypto generate-key --kid k2 --output-file /etc/nogml/secrets/encryption_key_k2

# 2. Point [security] encryption_key at k2 and keep k1 in encryption_previous_keys, then validate
nogml config check --config /etc/nogml/nogml.toml

# 3. Re-encrypt all stored secrets across every mailbox under k2
nogml crypto rotate-key --config /etc/nogml/nogml.toml

# 4. Reload nogml, remove k1 from encryption_previous_keys, and optionally set
#    encryption_strict = true (or NOGML_ENCRYPTION_STRICT=true) to reject any
#    unencrypted plaintext secrets on read
```

## Single-node Docker Compose with Caddy HTTPS

The root [`Dockerfile`](../Dockerfile) builds a stripped release binary into `debian:bookworm-slim`, runs as the non-root `nogml` user with `/var/lib/nogml` as the data volume, exposes ports `8080` (HTTP) and `1143` (IMAP), and uses `ENTRYPOINT ["nogml"]`.

1. Copy the deployment templates and create secret files:

```bash
cd deploy
cp nogml.example.toml nogml.toml
mkdir -p secrets
chmod 0700 secrets

# Generate a random bearer token and save provider secrets
printf 'nogml_%s\n' "$(openssl rand -hex 32)" > secrets/nogml_auth_tokens
printf '%s\n' "re_your_resend_api_key" > secrets/resend_api_key
printf '%s\n' "whsec_your_resend_webhook_secret" > secrets/resend_webhook_secret
chmod 0600 secrets/*
```

2. Edit `deploy/nogml.toml` for your domain and remove sections you do not use (for example `[ses]`, `[smtp]`, `[imap]`, or `[oauth2]` if you only use Resend and bearer tokens). Keep `[server] bind = "0.0.0.0:8080"`, `[storage] db_path = "/var/lib/nogml/nogml.db"`, and `[blob] dir = "/var/lib/nogml/blobs"`.

3. Point your DNS `A` and `AAAA` records for `mail.example.com` at the host, then start the stack:

```bash
export NOGML_DOMAIN=mail.example.com
docker compose up -d --build
```

4. Verify HTTPS, health, readiness, metrics, and authentication:

```bash
curl -fsS "https://${NOGML_DOMAIN}/healthz"
curl -fsS "https://${NOGML_DOMAIN}/readyz"
curl -fsS -H "Authorization: Bearer $(cat secrets/nogml_auth_tokens)" \
  "https://${NOGML_DOMAIN}/v1/capabilities"
curl -fsS -H "Authorization: Bearer $(cat secrets/nogml_auth_tokens)" \
  "https://${NOGML_DOMAIN}/metrics"
```

[`deploy/Caddyfile`](../deploy/Caddyfile) sets `flush_interval -1` so SSE (`/v1/events`) and MCP Streamable HTTP (`/mcp`) stream immediately, sets `request_body { max_size 40MB }` to match `nogml`'s 40 MiB attachment ceiling, and forwards `Host` and `X-Forwarded-Proto` so Gmail resumable upload `Location` headers use `https://`.

## Observability and readiness probes

- `GET /healthz` is unauthenticated and reports process liveness.
- `GET /readyz` is unauthenticated and probes `MailStore` plus external `BlobStore` reachability. On dependency errors, full diagnostics are logged server-side and the endpoint returns HTTP `503` with sanitized status flags (`{"status":"not_ready","store":"ok|error","blobs":"ok|error"}`).
- `GET /metrics` exposes Prometheus text format (`text/plain; version=0.0.4; charset=utf-8`) for `nogml_http_requests_total`, `nogml_messages_sent_total`, `nogml_messages_received_total`, `nogml_imap_active_connections`, `nogml_sse_active_connections`, `nogml_sync_runs_total`, `nogml_filter_decisions_total`, and `nogml_policy_decisions_total`. When auth tokens are configured, Prometheus scrapers must send a valid bearer token (a `read`-scoped token from `[[auth.scoped_tokens]]` is sufficient).
- `GET /v1/openapi.json` (also printable offline via `nogml schema --openapi`) serves the OpenAPI 3.1.0 specification covering all `/v1/*` endpoints, component schemas, error envelopes, and bearer, API key, and OAuth2 security schemes.
- On `SIGTERM` or `SIGINT`, `nogml serve` signals active `/v1/events` SSE streams to close cleanly so HTTP graceful shutdown completes promptly before draining background workers.

## Bare-metal Linux with systemd

[`deploy/nogml.service`](../deploy/nogml.service) runs `nogml` with `DynamicUser=yes`, `StateDirectory=nogml` (creating `/var/lib/nogml` with mode `0700`), and `LoadCredential=` so root-owned secrets in `/etc/nogml/secrets/` are mounted into a private tmpfs visible only to the service process at `%d` (`$CREDENTIALS_DIRECTORY`).

1. Install the binary:

```bash
cargo build --release
sudo install -m 0755 target/release/nogml /usr/local/bin/nogml
```

2. Create the configuration and root-only secret files:

```bash
sudo install -d -m 0755 /etc/nogml
sudo install -d -m 0700 /etc/nogml/secrets

sudo /usr/local/bin/nogml config init \
  --output /etc/nogml/nogml.toml \
  --token-file /etc/nogml/secrets/auth_tokens

printf '%s\n' "re_your_resend_api_key" | sudo tee /etc/nogml/secrets/resend_api_key >/dev/null
printf '%s\n' "whsec_your_resend_webhook_secret" | sudo tee /etc/nogml/secrets/resend_webhook_secret >/dev/null
sudo chown -R root:root /etc/nogml/secrets
sudo chmod 0600 /etc/nogml/secrets/*
```

In `/etc/nogml/nogml.toml`, set `[storage] db_path = "/var/lib/nogml/nogml.db"` and `[blob] dir = "/var/lib/nogml/blobs"`, and remove the static `tokens = ["file:///etc/nogml/secrets/auth_tokens"]` line if using `LoadCredential=` (the unit sets `NOGML_AUTH_TOKENS_FILE=%d/auth_tokens`, or you can write `tokens = ["file://$CREDENTIALS_DIRECTORY/auth_tokens"]` directly in `nogml.toml`).

3. Install and enable the service:

```bash
sudo install -m 0644 deploy/nogml.service /etc/systemd/system/nogml.service
sudo systemctl daemon-reload
sudo systemctl enable --now nogml.service
sudo systemctl status nogml.service
journalctl -u nogml.service -f
```

`ExecStartPre` runs `nogml config check --config /etc/nogml/nogml.toml` before every start or restart, blocking broken config changes before the process binds.

Put Caddy or nginx in front of `127.0.0.1:8080` for TLS termination, forwarding `Host` and `X-Forwarded-Proto: https` and disabling proxy buffering for `/v1/events` and `/mcp`.

## Multi-node deployment with PostgreSQL and S3/R2

SQLite is designed for a single writer node. To run multiple `nogml` replicas behind a load balancer, compile with `--features postgres`, point all replicas at one PostgreSQL database, and store raw `.eml` and attachment blobs in shared S3 or Cloudflare R2 object storage.

1. Build the PostgreSQL-enabled binary:

```bash
cargo build --release --features postgres
```

2. Configure `nogml.toml` on every replica:

```toml
[server]
bind = "0.0.0.0:8080"
log_json = true

[storage]
backend = "postgres"
database_url = "file:///run/secrets/nogml_database_url"

[blob]
backend = "s3"
s3_bucket = "nogml-mail-blobs"
s3_region = "auto"
s3_endpoint = "https://<account-id>.r2.cloudflarestorage.com"
s3_prefix = "prod"
s3_access_key_id = "<r2-access-key-id>"
s3_secret_access_key = "file:///run/secrets/nogml_s3_secret"
s3_force_path_style = true
```

3. Validate and run on each node:

```bash
nogml config check --config /etc/nogml/nogml.toml
nogml serve --config /etc/nogml/nogml.toml
```

What `PostgresStore` handles automatically across replicas:

- Schema creation runs idempotently on startup.
- `history_id` and IMAP `uid_next` counters increment atomically in PostgreSQL transactions.
- `EventBus` bridges events across replicas using PostgreSQL `LISTEN`/`NOTIFY` on the `nogml_events` channel (filtering each replica's own echoes via a per-node UUID), so SSE `/v1/events`, IMAP `IDLE`, and Gmail `/watch` push hooks stay synchronized regardless of which replica received the write or webhook.
- If migrating from an existing SQLite + `inline`/`fs` setup to S3/R2, run `nogml storage migrate-blobs --config /etc/nogml/nogml.toml --to s3`.

## Resend DNS and webhook setup

### Outbound sending DNS (SPF, DKIM, DMARC)

1. In the Resend dashboard, add your sending domain (for example `example.com` or a dedicated subdomain `mail.example.com`).
2. Publish the DNS records Resend generates:
   - **DKIM**: the `TXT` record(s) under `resend._domainkey.<domain>` (or the selector Resend assigns).
   - **SPF**: the `MX` and `TXT` (`v=spf1 include:amazonses.com ~all`) records on the bounce subdomain (`send.<domain>`).
   - **DMARC**: add a `TXT` record at `_dmarc.<domain>`, starting with monitoring and moving to quarantine or reject once verified:

```text
_dmarc.example.com.  300  IN  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; adkim=r; aspf=r"
```

3. Wait for Resend domain verification to pass before disabling `draft_only`.

### Inbound receiving DNS (MX) and Svix webhooks

1. In Resend, enable Inbound Receiving for your domain (or subdomain such as `inbound.example.com`) and add the `MX` record Resend provides.
2. Create a Resend webhook pointing at:

```text
https://mail.example.com/webhooks/resend
```

3. Subscribe to `email.received` (inbound mail) and optionally `email.sent`, `email.delivered`, `email.bounced`, `email.complained`, and `email.delivery_delayed` (delivery tracking).
4. Copy the webhook signing secret (`whsec_...`) into your secret file (`RESEND_WEBHOOK_SECRET_FILE` or `[resend] webhook_secret = "file://..."`), and ensure `RESEND_API_KEY` is configured so `nogml` can fetch the inbound raw message and attachments from the Resend Receiving API.
5. `POST /webhooks/resend` verifies the Svix `svix-id`, `svix-timestamp`, and `svix-signature` HMAC-SHA256 headers in constant time. Requests with missing or invalid signatures are rejected before touching `MailStore`.

## Embedded IMAP TLS and STARTTLS

Enable the embedded IMAP4rev1 server in `nogml.toml`:

```toml
[imap]
# Plain TCP with STARTTLS upgrade (standard IMAP submission/client port 143 or 1143)
bind = "0.0.0.0:1143"
# Implicit TLS (standard IMAPS port 993 or 1993)
tls_bind = "0.0.0.0:1993"
tls_cert = "/etc/nogml/tls/fullchain.pem"
tls_key = "/etc/nogml/tls/privkey.pem"
username = "agent@example.com"
password = "file:///etc/nogml/secrets/imap_password"
```

Notes:

- Both `imap.tls_cert` and `imap.tls_key` must be PEM files readable by the `nogml` process (`rustls` validates the chain and private key on startup and during `nogml config check`).
- Keep `tls_key` mode `0600` (owned by the `nogml` user, or loaded into `/etc/nogml/tls/` with tight group ownership when using a dedicated service user).
- **Certificate reload**: `nogml` loads the TLS certificate chain and private key once at startup. After Let's Encrypt or Certbot renews certificates, add a deploy hook to validate the new pair and gracefully restart `nogml` (existing connections drain on `SIGTERM`):

```bash
# Example /etc/letsencrypt/renewal-hooks/deploy/reload-nogml.sh
#!/bin/sh
set -eu
/usr/local/bin/nogml config check --config /etc/nogml/nogml.toml >/dev/null
systemctl restart nogml.service
```

## SQLite WAL backup and restore

`SqliteStore` runs SQLite in Write-Ahead Logging (`WAL`) mode. Never copy `nogml.db` with plain `cp` while `nogml` is running because active transactions in `nogml.db-wal` and `nogml.db-shm` can leave a raw file copy corrupt.

### Online snapshot backup with `sqlite3`

Use SQLite's online backup API (safe while `nogml` is serving traffic):

```bash
BACKUP_DIR=/var/backups/nogml/$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$BACKUP_DIR"

sqlite3 /var/lib/nogml/nogml.db ".timeout 5000" ".backup '${BACKUP_DIR}/nogml.db'"
sqlite3 "${BACKUP_DIR}/nogml.db" "PRAGMA integrity_check;"
```

If `[blob] backend = "fs"` is enabled, sync the blob directory right after the database snapshot (blobs are immutable per message and attachment ID):

```bash
rsync -a /var/lib/nogml/blobs/ "${BACKUP_DIR}/blobs/"
```

### Continuous WAL streaming with Litestream

For low RPO backups of a single-node SQLite instance to S3 or R2, run [Litestream](https://litestream.io/) alongside `nogml`:

```yaml
dbs:
  - path: /var/lib/nogml/nogml.db
    replicas:
      - type: s3
        bucket: nogml-backups
        path: sqlite/nogml.db
        region: us-east-1
```

### Restoring from backup

1. Stop `nogml` (`systemctl stop nogml.service` or `docker compose stop nogml`).
2. Remove stale WAL/SHM files before replacing the database:

```bash
rm -f /var/lib/nogml/nogml.db-wal /var/lib/nogml/nogml.db-shm
cp "${BACKUP_DIR}/nogml.db" /var/lib/nogml/nogml.db
```

3. If using `FsBlobStore`, restore `/var/lib/nogml/blobs/` with `rsync -a "${BACKUP_DIR}/blobs/" /var/lib/nogml/blobs/`. If using `S3BlobStore`, enable bucket versioning and lifecycle retention in S3/R2.
4. Start `nogml` and verify `GET /healthz` and `nogml mail labels`.

## Production security checklist

- **Require authentication**: configure `auth.tokens` or least-privilege `[[auth.scoped_tokens]]` (never leave auth empty on a network-reachable server). Issue separate read-only (`scopes = ["read"]`) and draft-only tokens for AI agents.
- **Guard outbound sends**: start with `safety.draft_only = true` or `safety.require_approval = true` (human-in-the-loop `/v1/approvals`) and restrict `safety.allowed_recipients` (for example `["@example.com"]`) and `safety.max_send_recipients`.
- **Keep prompt-injection guards on**: leave `safety.untrusted_content_guard = true` so control and BiDi override characters are stripped and external messages are tagged on AI/MCP reads.
- **Verify inbound webhooks**: always set `RESEND_WEBHOOK_SECRET` (or `NOGML_SES_WEBHOOK_SECRET`) so unsigned webhook payloads cannot inject messages into your store.
- **Enable inbound authentication filters**: set `[filters] auth_results = true` (with `dmarc_fail_action = "spam"` or `"reject"`) and optionally pair with Rspamd (`[filters.rspamd]`).
- **Protect secrets at rest**: store every secret in a mode `0600` file loaded via `file://`, `file://$CREDENTIALS_DIRECTORY/...`, or `*_FILE` environment variables. Run `nogml config check` to verify zero permission warnings and zero plaintext leaks.
- **Bind behind TLS**: bind HTTP to `127.0.0.1:8080` (or an internal Docker network) behind Caddy/nginx with HTTPS, and forward `Host` and `X-Forwarded-Proto: https` with response buffering disabled for `/v1/events` and `/mcp`.
- **Restrict CORS**: set `server.cors_allow_origins` to explicit origins if browser clients call `nogml` directly.
