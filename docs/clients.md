# Client compatibility guide

`nogml` serves one mailbox store over four interfaces: Gmail REST API v1, IMAP4rev1, MCP (stdio and Streamable HTTP), and the AI REST API (`/v1`). This guide gives verified client configurations, supported endpoints, known caveats, and instructions for running the opt-in live provider smoke tests.

## Superhuman and Gmail API SDKs

Point Gmail API clients at your `nogml` base URL instead of `https://gmail.googleapis.com` (for example `http://127.0.0.1:8080` locally or `https://mail.example.com` behind a reverse proxy).

### Supported endpoints and behaviors

- **OAuth2 discovery and token exchange**: When `NOGML_OAUTH2_CLIENT_ID` and `NOGML_OAUTH2_SIGNING_SECRET` are set, `nogml` exposes `GET /.well-known/oauth-authorization-server`, `GET /oauth2/authorize` (PKCE `S256` and `plain`), and `POST /oauth2/token` (`authorization_code`, `refresh_token`, and `client_credentials`). Accepted scopes include short names (`read`, `write`, `send`, `admin`), Gmail scope URLs (`https://mail.google.com/`, `gmail.readonly`, `gmail.modify`, `gmail.compose`, `gmail.send`), and Google identity scopes (`openid`, `email`, `profile`, `userinfo.email`, `userinfo.profile`).
- **Google identity probes**: `GET /oauth2/v2/userinfo`, `GET /oauth2/v3/userinfo`, and `GET /v1/people/me?personFields=names,emailAddresses` authenticate with standard Bearer tokens (`Authorization: Bearer <token>`, `X-API-Key`, or `?access_token=`) and return the authenticated mailbox's email address, verified status, `SendAs` aliases, and primary `SendAs` display name.
- **Core Gmail API v1**: `profile`, `messages`, `threads`, `labels`, `drafts`, `history`, `watch`, `stop`, and `settings/*` (`sendAs`, `vacation`, `autoForwarding`, `imap`, `pop`).
- **Batching and partial responses**: `POST /batch/gmail/v1` handles `multipart/mixed` sub-requests and applies `?fields=` projection masks and `alt=json` to each sub-response as well as top-level requests.
- **Uploads**: `/upload/gmail/v1/users/me/...` supports `uploadType=media`, `uploadType=multipart`, and chunked `uploadType=resumable` (`Location` with `PUT` `Content-Range` and `308 Resume Incomplete` probes).

### Local OAuth2 token example

```bash
curl -fsS -X POST http://127.0.0.1:8080/oauth2/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "client_credentials",
    "client_id": "nogml-client",
    "client_secret": "nogml-secret",
    "scope": "https://mail.google.com/ https://www.googleapis.com/auth/userinfo.email"
  }'
```

Verify the minted token against `userinfo`, People API, and Gmail `profile`:

```bash
TOKEN="<access_token>"
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/oauth2/v2/userinfo
curl -fsS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8080/v1/people/me?personFields=names,emailAddresses"
curl -fsS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8080/gmail/v1/users/me/profile?fields=emailAddress,historyId"
```

### Node.js (`@googleapis/gmail`)

```js
import { gmail } from "@googleapis/gmail";

const client = gmail({
  version: "v1",
  rootUrl: "http://127.0.0.1:8080/",
  headers: { Authorization: "Bearer tok_secret_1" },
});

const profile = await client.users.getProfile({ userId: "me" });
console.log(profile.data);
```

### Python (`google-api-python-client`)

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

print(service.users().getProfile(userId="me").execute())
```

### Gmail API caveats

- **Reverse proxy headers**: Forward `Host` and `X-Forwarded-Proto: https` from Caddy or nginx so `/.well-known/oauth-authorization-server` URLs and `uploadType=resumable` `Location` headers use your public HTTPS origin.
- **Display name**: Set your display name via `PATCH /gmail/v1/users/me/settings/sendAs/<email>` with `{"displayName": "Your Name"}`. If unset, `/oauth2/v2/userinfo`, `/oauth2/v3/userinfo`, and `/v1/people/me` fall back to the local part of the mailbox address.
- **People API scope**: `GET /v1/people/me` is a minimal profile stub (`resourceName`, `names`, `emailAddresses`). Contact directory endpoints (`/v1/people/me/connections`) are not implemented.
- **Delegation**: `{userId}` accepts `me` or the authenticated principal's own email address. Requests for another mailbox return `403 Forbidden`.

## IMAP mail clients (Apple Mail, Thunderbird, himalaya, mutt)

Start `nogml` with plain/STARTTLS and/or implicit TLS IMAP listeners:

```bash
nogml serve \
  --bind 127.0.0.1:8080 \
  --user-email agent@example.com \
  --auth-tokens tok_secret_1 \
  --imap-bind 0.0.0.0:1143 \
  --imap-tls-bind 0.0.0.0:1993 \
  --imap-tls-cert /etc/nogml/tls/fullchain.pem \
  --imap-tls-key /etc/nogml/tls/privkey.pem
```

### Connection matrix

| Setting | Local dev (plain) | STARTTLS | Implicit TLS (IMAPS) |
| --- | --- | --- | --- |
| Host | `127.0.0.1` | `mail.example.com` | `mail.example.com` |
| Port | `1143` (from `--imap-bind`) | `143` or `1143` (from `--imap-bind`) | `993` or `1993` (from `--imap-tls-bind`) |
| Security | None (loopback only) | `STARTTLS` | `SSL/TLS` (implicit TLS) |
| Auth mechanisms | `LOGIN`, `PLAIN`, `XOAUTH2` | `LOGIN`, `PLAIN`, `XOAUTH2` | `LOGIN`, `PLAIN`, `XOAUTH2` |
| Username | `NOGML_USER_EMAIL` or `NOGML_IMAP_USERNAME` | `NOGML_USER_EMAIL` or `NOGML_IMAP_USERNAME` | `NOGML_USER_EMAIL` or `NOGML_IMAP_USERNAME` |
| Password / token | `NOGML_IMAP_PASSWORD`, first `NOGML_AUTH_TOKENS`, scoped token, or OAuth2 JWT | Same | Same |

### Folder and flag mapping

`nogml` advertises `IMAP4rev1`, `LITERAL+`, `IDLE`, `MOVE`, `UIDPLUS`, `SPECIAL-USE`, `NAMESPACE`, `ID`, `X-GM-EXT-1`, `ENABLE`, `CONDSTORE`, and `QRESYNC` (after authentication). Gmail labels map to IMAP folders as follows:

| IMAP folder | Special-use attribute | Backing Gmail label |
| --- | --- | --- |
| `INBOX` | *(primary)* | `INBOX` |
| `[Gmail]/All Mail` | `\All` | All non-trash, non-spam messages |
| `[Gmail]/Sent Mail` | `\Sent` | `SENT` |
| `[Gmail]/Drafts` | `\Drafts` | `DRAFT` |
| `[Gmail]/Trash` | `\Trash` | `TRASH` |
| `[Gmail]/Spam` | `\Junk` | `SPAM` |
| `[Gmail]/Starred` | `\Flagged` | `STARRED` |
| `<Custom Label>` | *(none)* | User-defined Gmail label |

IMAP system flags sync directly with mailbox state: `\Seen` toggles `UNREAD`, `\Flagged` toggles `STARRED`, and `\Draft` toggles `DRAFT`. Real-time changes from webhooks, REST API calls, or sync push over `IDLE`.

### Apple Mail (macOS and iOS)

1. Open **Settings > Mail > Accounts > Add Account > Add Other Account > Mail Account**.
2. Enter your `NOGML_USER_EMAIL` address and password (your `NOGML_IMAP_PASSWORD` or bearer token).
3. On the manual server settings screen, choose **IMAP**:
   - **Incoming Mail Server**: `mail.example.com`
   - **Port**: `993` (or `1993` matching `--imap-tls-bind`) with **Use TLS/SSL** enabled, or `143`/`1143` with `STARTTLS`.
   - **Authentication**: Password (`PLAIN`/`LOGIN`).
4. Under **Mailbox Behaviors**, verify Apple Mail mapped `Drafts` to `[Gmail]/Drafts`, `Sent` to `[Gmail]/Sent Mail`, `Junk` to `[Gmail]/Spam`, and `Trash` to `[Gmail]/Trash` (auto-detected via `SPECIAL-USE`).
5. For **Outgoing Mail Server (SMTP)**, configure your Resend SMTP relay (`smtp.resend.com:465`), AWS SES SMTP endpoint, or your own submission server. `nogml` does not expose an inbound SMTP submission listener.

### Thunderbird

1. Open **Account Settings > Account Actions > Add Mail Account**.
2. Enter your name, `NOGML_USER_EMAIL`, and password, then click **Configure manually**.
3. Configure Incoming:
   - **Protocol**: IMAP
   - **Hostname**: `mail.example.com` (or `127.0.0.1` for local testing)
   - **Port**: `993` (or `1993`) with **SSL/TLS**, or `143` (or `1143`) with **STARTTLS**
   - **Authentication method**: Normal password (`LOGIN`/`PLAIN`) or OAuth2 (`XOAUTH2` when using local OAuth2 tokens)
4. Click **Re-test** and **Done**.
5. Thunderbird negotiates `CONDSTORE` and `IDLE` automatically and reads `SPECIAL-USE` folder roles on first `LIST`.

### himalaya

Add a `nogml` account to `~/.config/himalaya/config.toml`:

```toml
[accounts.nogml]
email = "agent@example.com"
display-name = "Agent"
default = true

backend.type = "imap"
backend.host = "mail.example.com"
backend.port = 1993
backend.encryption.type = "tls"
backend.login = "agent@example.com"
backend.auth.type = "password"
backend.auth.raw = "tok_secret_1"

# Use STARTTLS instead of implicit TLS on --imap-bind:
# backend.port = 1143
# backend.encryption.type = "start-tls"

# Map standard folder aliases to Gmail virtual folders:
folder.aliases.inbox = "INBOX"
folder.aliases.sent = "[Gmail]/Sent Mail"
folder.aliases.drafts = "[Gmail]/Drafts"
folder.aliases.trash = "[Gmail]/Trash"

# Outbound send via your SMTP provider (e.g. Resend SMTP or SES):
message.send.backend.type = "smtp"
message.send.backend.host = "smtp.resend.com"
message.send.backend.port = 465
message.send.backend.encryption.type = "tls"
message.send.backend.login = "resend"
message.send.backend.auth.type = "password"
message.send.backend.auth.raw = "re_your_resend_api_key"
```

Verify from the command line:

```bash
himalaya folder list --account nogml
himalaya envelope list --account nogml --page-size 10
```

### mutt and neomutt

Add the following to `~/.muttrc` (or `~/.config/neomutt/neomuttrc`):

```muttrc
set from = "agent@example.com"
set realname = "Agent"

# Implicit TLS (use imap:// for --imap-bind with STARTTLS)
set folder = "imaps://mail.example.com:1993/"
set imap_user = "agent@example.com"
set imap_pass = "tok_secret_1"
set imap_authenticators = "plain:login"

set spoolfile = "+INBOX"
set record = "+[Gmail]/Sent Mail"
set postponed = "+[Gmail]/Drafts"
set trash = "+[Gmail]/Trash"

set imap_idle = yes
set ssl_starttls = yes
set ssl_force_tls = yes
```

### IMAP caveats

- **No embedded SMTP server**: `nogml` implements IMAP4rev1 for reading, organizing, searching, and `APPEND`, while outbound sending happens through HTTP (`/v1/messages/send`, `/gmail/v1/.../send`), MCP (`send_email`), or CLI (`nogml mail send`). Point desktop IMAP clients' outgoing SMTP server at Resend SMTP (`smtp.resend.com`), SES SMTP, or your mail relay.
- **Scoped read-only tokens**: When a client authenticates with a `read`-only scoped token, `SELECT` opens mailboxes `[READ-ONLY]` and mutating commands (`STORE`, `COPY`, `MOVE`, `EXPUNGE`, `APPEND`, `CREATE`, `DELETE`, `RENAME`) return `NO [NOPERM]`.
- **Self-signed certificates**: Apple Mail and Thunderbird reject untrusted certificates by default. Use a Let's Encrypt certificate for remote hosts, or trust your local CA when testing on `127.0.0.1`.
- **Multi-mailbox login**: When `NOGML_MAILBOXES` is configured, log in with the target `mailbox_id` as the IMAP username and that mailbox's scoped token or OAuth2 JWT as the password/access token.

## MCP clients (Claude Desktop, Cursor, Streamable HTTP)

`nogml` supports two MCP transports:

- **Stdio (`nogml mcp`)**: Reads local SQLite directly with zero open ports. Logs go strictly to stderr; stdout carries JSON-RPC 2.0 frames. Best for single-user desktop clients on the same machine.
- **Streamable HTTP (`POST /mcp`)**: Served by `nogml serve` alongside the REST and IMAP endpoints, protected by `Authorization: Bearer <token>` and scoped token rules. Best for remote servers, multi-mailbox setups, and shared deployments.

### Claude Desktop (stdio)

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "nogml": {
      "command": "/usr/local/bin/nogml",
      "args": [
        "mcp",
        "--db-path",
        "/path/to/nogml.db",
        "--user-email",
        "agent@example.com",
        "--draft-only"
      ]
    }
  }
}
```

### Cursor (stdio or Streamable HTTP)

Add to `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global).

Local stdio mode:

```json
{
  "mcpServers": {
    "nogml": {
      "command": "/usr/local/bin/nogml",
      "args": [
        "mcp",
        "--db-path",
        "/path/to/nogml.db",
        "--user-email",
        "agent@example.com",
        "--draft-only"
      ]
    }
  }
}
```

Remote Streamable HTTP mode (connecting to `nogml serve`):

```json
{
  "mcpServers": {
    "nogml": {
      "url": "https://mail.example.com/mcp",
      "headers": {
        "Authorization": "Bearer tok_secret_1"
      }
    }
  }
}
```

### Verifying Streamable HTTP MCP with curl

```bash
curl -fsS -X POST http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer tok_secret_1" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | jq .
```

### MCP caveats

- **Agent safety**: Pass `--draft-only` or `--require-approval` (or issue a scoped token with `"draft_only": true` and `"allowed_recipients"`) so autonomous agents cannot send unreviewed external email.
- **Reverse proxy buffering**: When placing Caddy or nginx in front of `POST /mcp`, disable response buffering (`flush_interval -1` in Caddy, `proxy_buffering off;` in nginx).

## Opt-in live provider smoke tests

`tests/live_smoke.rs` contains two sets of tests:

1. **Default-CI tests** (always run with `cargo test`): verify `/oauth2/v2/userinfo`, `/oauth2/v3/userinfo`, `/v1/people/me`, and IMAP `BODYSTRUCTURE`, `ENVELOPE`, and `INTERNALDATE` client quirks locally without external network calls.
2. **Live provider smoke tests** (marked `#[ignore = "requires live provider credentials"]`): exercise real Resend outbound/receiving APIs, live Gmail REST API v1 sync, and live Gmail IMAP sync.

### Environment variables

| Test | Required environment variables | Optional environment variables |
| --- | --- | --- |
| `live_resend_send_and_receive` | `NOGML_LIVE_RESEND_API_KEY`, `NOGML_LIVE_FROM`, `NOGML_LIVE_TO` | `NOGML_LIVE_RESEND_BASE_URL` (default `https://api.resend.com`), `NOGML_LIVE_RESEND_RECEIVED_ID` |
| `live_gmail_api_sync` | `NOGML_LIVE_GMAIL_ACCESS_TOKEN` or (`NOGML_LIVE_GMAIL_REFRESH_TOKEN`, `NOGML_LIVE_GMAIL_CLIENT_ID`, `NOGML_LIVE_GMAIL_CLIENT_SECRET`) | `NOGML_LIVE_GMAIL_USER_ID` (default `me`) |
| `live_gmail_imap_sync` | `NOGML_LIVE_GMAIL_IMAP_USER`, `NOGML_LIVE_GMAIL_IMAP_PASSWORD` | `NOGML_LIVE_GMAIL_IMAP_HOST` (default `imap.gmail.com`), `NOGML_LIVE_GMAIL_IMAP_PORT` (default `993`), `NOGML_LIVE_GMAIL_IMAP_MAILBOX` (default `[Gmail]/All Mail`) |

By default, if credentials for one provider are omitted, that live test prints a `[skip]` line and returns cleanly so you can test a single provider at a time. Set `NOGML_LIVE_STRICT=1` to fail instead of skipping when any live env var is missing.

### Running the live smoke harness

Run all configured live smoke tests:

```bash
NOGML_LIVE_RESEND_API_KEY=re_xxx \
NOGML_LIVE_FROM=agent@yourdomain.com \
NOGML_LIVE_TO=you@yourdomain.com \
cargo test --test live_smoke -- --ignored --nocapture
```

Run a single provider test:

```bash
# Gmail REST API sync (fetches up to 5 messages into MemoryStore, read-only)
NOGML_LIVE_GMAIL_CLIENT_ID=... \
NOGML_LIVE_GMAIL_CLIENT_SECRET=... \
NOGML_LIVE_GMAIL_REFRESH_TOKEN=... \
cargo test --test live_smoke live_gmail_api_sync -- --ignored --nocapture

# Gmail IMAP sync (fetches up to 5 messages into MemoryStore, read-only)
NOGML_LIVE_GMAIL_IMAP_USER=you@gmail.com \
NOGML_LIVE_GMAIL_IMAP_PASSWORD=your-app-password \
cargo test --test live_smoke live_gmail_imap_sync -- --ignored --nocapture
```
