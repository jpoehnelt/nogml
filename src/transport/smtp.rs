//! Lightweight async Tokio SMTP submission transport (`SmtpTransport`).
//!
//! Supports plaintext TCP (local relays and tests), `STARTTLS`, and implicit TLS (SMTPS)
//! via `tokio-rustls` + `webpki-roots`, `EHLO`, `AUTH PLAIN` / `AUTH LOGIN`, `MAIL FROM`,
//! `RCPT TO` across `to`/`cc`/`bcc`, RFC 5321 dot-stuffed `DATA` preserving verbatim
//! `OutboundMessage.raw_rfc2822`, and `QUIT`.

use std::{collections::HashSet, sync::Arc, time::Duration};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use uuid::Uuid;

use crate::{
    config::{Config, SmtpTlsMode},
    error::{AppError, AppResult},
    storage::parse_simple_email_address,
    transport::{
        MailTransport, OutboundMessage, SendOutcome, TransportCapabilities, ensure_raw_rfc2822,
    },
};

const SMTP_MAX_MESSAGE_BYTES: usize = 40 * 1024 * 1024;
const SMTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const SMTP_IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SMTP_RESPONSE_LINES: usize = 128;
const MAX_SMTP_LINE_BYTES: usize = 64 * 1024;

/// Configuration for [`SmtpTransport`].
#[derive(Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub tls_mode: SmtpTlsMode,
    pub username: Option<String>,
    pub password: Option<String>,
    pub helo_domain: String,
    pub default_from: String,
}

impl std::fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls_mode", &self.tls_mode)
            .field("username", &self.username)
            .field(
                "password",
                &self
                    .password
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .map(|_| crate::secrets::REDACTED),
            )
            .field("helo_domain", &self.helo_domain)
            .field("default_from", &self.default_from)
            .finish()
    }
}

impl SmtpConfig {
    /// Build [`SmtpConfig`] from application [`Config`].
    pub fn from_config(config: &Config) -> AppResult<Self> {
        let host = config.smtp_host.trim().to_string();
        if host.is_empty() {
            return Err(AppError::Config(
                "NOGML_SMTP_HOST must not be empty when NOGML_TRANSPORT=smtp".to_string(),
            ));
        }
        if config.smtp_port == 0 {
            return Err(AppError::Config(
                "NOGML_SMTP_PORT must be a non-zero TCP port".to_string(),
            ));
        }

        let helo_domain = config
            .smtp_helo_domain
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                let d = config.default_domain.trim();
                (!d.is_empty()).then_some(d)
            })
            .unwrap_or("localhost")
            .to_string();

        if helo_domain.bytes().any(|b| b <= 0x20 || b == 0x7f) {
            return Err(AppError::Config(format!(
                "Invalid NOGML_SMTP_HELO_DOMAIN '{helo_domain}'"
            )));
        }

        Ok(Self {
            host,
            port: config.smtp_port,
            tls_mode: config.smtp_tls_mode,
            username: config
                .smtp_username
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string),
            password: config.smtp_password.clone(),
            helo_domain,
            default_from: config.user_email.clone(),
        })
    }
}

/// Async Tokio SMTP submission [`MailTransport`].
#[derive(Clone, Debug)]
pub struct SmtpTransport {
    config: SmtpConfig,
}

impl SmtpTransport {
    /// Construct an [`SmtpTransport`] from explicit [`SmtpConfig`].
    pub fn new(config: SmtpConfig) -> Self {
        Self { config }
    }

    /// Construct an [`SmtpTransport`] from application [`Config`].
    pub fn from_config(config: &Config) -> AppResult<Self> {
        Ok(Self::new(SmtpConfig::from_config(config)?))
    }

    /// Return the resolved [`SmtpConfig`].
    pub fn config(&self) -> &SmtpConfig {
        &self.config
    }
}

#[derive(Debug)]
struct SmtpResponse {
    code: u16,
    lines: Vec<String>,
}

impl SmtpResponse {
    fn summary(&self) -> String {
        self.lines.join(" / ")
    }
}

#[derive(Debug, Default)]
struct EhloCapabilities {
    starttls: bool,
    auth_plain: bool,
    auth_login: bool,
    auth_advertised: bool,
}

impl EhloCapabilities {
    fn from_response(resp: &SmtpResponse) -> Self {
        let mut caps = Self::default();
        for line in &resp.lines {
            let upper = line.trim().to_ascii_uppercase();
            if upper == "STARTTLS" || upper.starts_with("STARTTLS ") {
                caps.starttls = true;
            }
            if let Some(rest) = upper
                .strip_prefix("AUTH ")
                .or_else(|| upper.strip_prefix("AUTH="))
            {
                caps.auth_advertised = true;
                for mech in rest.split_whitespace() {
                    if mech == "PLAIN" {
                        caps.auth_plain = true;
                    } else if mech == "LOGIN" {
                        caps.auth_login = true;
                    }
                }
            }
        }
        caps
    }
}

enum SmtpStream {
    Plain(BufReader<TcpStream>),
    Tls(Box<BufReader<TlsStream<TcpStream>>>),
}

fn build_tls_connector() -> TlsConnector {
    crate::ensure_crypto_provider();
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_cfg = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(tls_cfg))
}

async fn connect_tls(tcp: TcpStream, host: &str) -> AppResult<TlsStream<TcpStream>> {
    let connector = build_tls_connector();
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| AppError::Config(format!("Invalid SMTP TLS hostname '{host}': {e}")))?;
    timeout(SMTP_CONNECT_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .map_err(|_| AppError::Upstream {
            status: 504,
            message: format!("SMTP TLS handshake timed out with {host}"),
        })?
        .map_err(|e| AppError::Upstream {
            status: 502,
            message: format!("SMTP TLS handshake failed with {host}: {e}"),
        })
}

impl SmtpStream {
    async fn connect(host: &str, port: u16, tls_mode: SmtpTlsMode) -> AppResult<Self> {
        let tcp = timeout(SMTP_CONNECT_TIMEOUT, TcpStream::connect((host, port)))
            .await
            .map_err(|_| AppError::Upstream {
                status: 504,
                message: format!("SMTP connection timed out to {host}:{port}"),
            })?
            .map_err(|e| AppError::Upstream {
                status: 502,
                message: format!("Failed to connect to SMTP server {host}:{port}: {e}"),
            })?;

        match tls_mode {
            SmtpTlsMode::Tls => {
                let tls = connect_tls(tcp, host).await?;
                Ok(Self::Tls(Box::new(BufReader::new(tls))))
            }
            SmtpTlsMode::Starttls | SmtpTlsMode::None => Ok(Self::Plain(BufReader::new(tcp))),
        }
    }

    async fn upgrade_starttls(self, host: &str) -> AppResult<Self> {
        match self {
            Self::Plain(reader) => {
                if !reader.buffer().is_empty() {
                    return Err(AppError::Upstream {
                        status: 502,
                        message: "SMTP server sent unexpected pipelined data before STARTTLS"
                            .to_string(),
                    });
                }
                let tcp = reader.into_inner();
                let tls = connect_tls(tcp, host).await?;
                Ok(Self::Tls(Box::new(BufReader::new(tls))))
            }
            Self::Tls(tls) => Ok(Self::Tls(tls)),
        }
    }

    async fn write_all_flush(&mut self, data: &[u8]) -> AppResult<()> {
        let fut = async {
            match self {
                Self::Plain(r) => {
                    let inner = r.get_mut();
                    inner.write_all(data).await?;
                    inner.flush().await
                }
                Self::Tls(r) => {
                    let inner = r.get_mut();
                    inner.write_all(data).await?;
                    inner.flush().await
                }
            }
        };
        timeout(SMTP_IO_TIMEOUT, fut)
            .await
            .map_err(|_| AppError::Upstream {
                status: 504,
                message: "SMTP write timed out".to_string(),
            })?
            .map_err(|e| AppError::Upstream {
                status: 502,
                message: format!("SMTP write failed: {e}"),
            })
    }

    async fn read_line(&mut self) -> AppResult<String> {
        let mut buf = Vec::new();
        let limit = (MAX_SMTP_LINE_BYTES as u64) + 1;
        let fut = async {
            match self {
                Self::Plain(r) => r.take(limit).read_until(b'\n', &mut buf).await,
                Self::Tls(r) => r.take(limit).read_until(b'\n', &mut buf).await,
            }
        };
        let n = timeout(SMTP_IO_TIMEOUT, fut)
            .await
            .map_err(|_| AppError::Upstream {
                status: 504,
                message: "SMTP read timed out".to_string(),
            })?
            .map_err(|e| AppError::Upstream {
                status: 502,
                message: format!("SMTP read failed: {e}"),
            })?;
        if n == 0 {
            return Err(AppError::Upstream {
                status: 502,
                message: "SMTP server closed connection unexpectedly".to_string(),
            });
        }
        if buf.len() > MAX_SMTP_LINE_BYTES {
            return Err(AppError::Upstream {
                status: 502,
                message: "SMTP server response line exceeded size limit".to_string(),
            });
        }
        let line = String::from_utf8_lossy(&buf)
            .trim_end_matches(['\r', '\n'])
            .to_string();
        Ok(line)
    }

    async fn read_response(&mut self) -> AppResult<SmtpResponse> {
        let mut lines = Vec::new();
        let mut final_code: Option<u16> = None;

        for _ in 0..MAX_SMTP_RESPONSE_LINES {
            let line = self.read_line().await?;
            let bytes = line.as_bytes();
            if bytes.len() < 3 || !bytes[..3].iter().all(u8::is_ascii_digit) {
                return Err(AppError::Upstream {
                    status: 502,
                    message: format!("Malformed SMTP response line: '{line}'"),
                });
            }
            let code: u16 = line[..3].parse().map_err(|_| AppError::Upstream {
                status: 502,
                message: format!("Invalid SMTP status code in '{line}'"),
            })?;
            let sep = bytes.get(3).copied();
            let text = if bytes.len() > 4 {
                line[4..].to_string()
            } else {
                String::new()
            };
            lines.push(text);

            match sep {
                Some(b'-') => continue,
                Some(b' ') | None => {
                    final_code = Some(code);
                    break;
                }
                Some(_) => {
                    return Err(AppError::Upstream {
                        status: 502,
                        message: format!("Malformed SMTP separator in '{line}'"),
                    });
                }
            }
        }

        let code = final_code.ok_or_else(|| AppError::Upstream {
            status: 502,
            message: "SMTP multiline response exceeded line limit".to_string(),
        })?;

        Ok(SmtpResponse { code, lines })
    }

    async fn command(&mut self, cmd: &str) -> AppResult<SmtpResponse> {
        let wire = format!("{cmd}\r\n");
        self.write_all_flush(wire.as_bytes()).await?;
        self.read_response().await
    }
}

fn expect_code(resp: &SmtpResponse, allowed: &[u16], stage: &str) -> AppResult<()> {
    if allowed.contains(&resp.code) {
        Ok(())
    } else {
        Err(AppError::Upstream {
            status: 502,
            message: format!("SMTP {stage} rejected ({}): {}", resp.code, resp.summary()),
        })
    }
}

fn sanitize_envelope_addr(raw: &str) -> AppResult<String> {
    let parsed = parse_simple_email_address(raw);
    let email = parsed.email.trim().to_string();
    if email.is_empty() || !email.contains('@') {
        return Err(AppError::BadRequest(format!(
            "Invalid SMTP envelope address '{raw}'"
        )));
    }
    if email
        .bytes()
        .any(|b| b <= 0x20 || b == 0x7f || matches!(b, b'<' | b'>'))
    {
        return Err(AppError::BadRequest(format!(
            "SMTP envelope address '{raw}' contains disallowed characters"
        )));
    }
    Ok(email)
}

/// Apply RFC 5321 Section 4.5.2 dot-stuffing to raw RFC 2822 bytes and append the
/// terminating `.\r\n` sequence.
///
/// Bare `\r` and bare `\n` line endings are normalized to `\r\n` BEFORE dot-stuffing so
/// bare-CR sequences such as `\r.\r\n` cannot smuggle SMTP `DATA` terminators or commands.
/// Any line starting with `.` has an extra `.` prepended.
pub fn dot_stuff_rfc5321(raw: &[u8]) -> Vec<u8> {
    // Normalize CRLF, bare CR, and bare LF to canonical CRLF first.
    let mut normalized = Vec::with_capacity(raw.len() + 16);
    let mut i = 0;
    while i < raw.len() {
        let b = raw[i];
        if b == b'\r' {
            normalized.push(b'\r');
            normalized.push(b'\n');
            if raw.get(i + 1) == Some(&b'\n') {
                i += 2;
            } else {
                i += 1;
            }
        } else if b == b'\n' {
            normalized.push(b'\r');
            normalized.push(b'\n');
            i += 1;
        } else {
            normalized.push(b);
            i += 1;
        }
    }

    let mut out = Vec::with_capacity(normalized.len() + 32);
    let mut at_line_start = true;
    let mut j = 0;
    while j < normalized.len() {
        let b = normalized[j];
        if at_line_start && b == b'.' {
            out.push(b'.');
        }
        if b == b'\r' && normalized.get(j + 1) == Some(&b'\n') {
            out.push(b'\r');
            out.push(b'\n');
            j += 2;
            at_line_start = true;
        } else {
            out.push(b);
            j += 1;
            at_line_start = false;
        }
    }

    if !at_line_start {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

fn extract_provider_message_id(
    data_resp: &SmtpResponse,
    msg: &OutboundMessage,
    raw_bytes: &[u8],
) -> String {
    // Try extracting a server queue ID (e.g. "2.0.0 Ok: queued as ABC123" or "OK id=ABC123").
    for line in &data_resp.lines {
        let lower = line.to_ascii_lowercase();
        if let Some(pos) = lower.find("queued as ") {
            let candidate = line[pos + "queued as ".len()..]
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches(['<', '>', ';', ',']);
            if !candidate.is_empty() {
                return candidate.to_string();
            }
        }
        if let Some(pos) = lower.find("id=") {
            let candidate = line[pos + 3..]
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches(['<', '>', ';', ',']);
            if !candidate.is_empty() {
                return candidate.to_string();
            }
        }
    }

    // Fall back to RFC 2822 Message-ID header.
    if let Some((_, mid)) = msg
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("message-id"))
        && !mid.trim().is_empty()
    {
        return mid.trim().to_string();
    }
    if let Ok(parsed) = crate::mime::parse_rfc2822(raw_bytes)
        && let Some(mid) = parsed.rfc822_message_id
        && !mid.trim().is_empty()
    {
        return mid;
    }

    format!("smtp_{}", Uuid::new_v4())
}

#[async_trait]
impl MailTransport for SmtpTransport {
    fn name(&self) -> &'static str {
        "smtp"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            provider: "smtp".to_string(),
            supports_raw_mime: true,
            supports_scheduled_send: false,
            supports_idempotency_key: false,
            supports_inbound_webhooks: false,
            supports_delivery_webhooks: false,
            max_message_bytes: SMTP_MAX_MESSAGE_BYTES,
        }
    }

    async fn send(
        &self,
        msg: &OutboundMessage,
        _idempotency_key: Option<&str>,
    ) -> AppResult<SendOutcome> {
        let raw_bytes = ensure_raw_rfc2822(msg, &self.config.default_from)?;

        let mut from_raw = if msg.from.trim().is_empty() {
            self.config.default_from.trim().to_string()
        } else {
            msg.from.trim().to_string()
        };

        let mut raw_recipients: Vec<String> = msg
            .to
            .iter()
            .chain(msg.cc.iter())
            .chain(msg.bcc.iter())
            .cloned()
            .collect();

        if (from_raw.is_empty() || raw_recipients.is_empty())
            && let Ok(parsed) = crate::mime::parse_rfc2822(&raw_bytes)
        {
            if from_raw.is_empty() && !parsed.from.trim().is_empty() {
                from_raw = parsed.from;
            }
            if raw_recipients.is_empty() {
                raw_recipients.extend(parsed.to);
                raw_recipients.extend(parsed.cc);
                raw_recipients.extend(parsed.bcc);
            }
        }

        let mail_from = sanitize_envelope_addr(&from_raw)?;

        let mut seen = HashSet::new();
        let mut rcpt_to = Vec::new();
        for raw_rcpt in &raw_recipients {
            let addr = sanitize_envelope_addr(raw_rcpt)?;
            if seen.insert(addr.to_ascii_lowercase()) {
                rcpt_to.push(addr);
            }
        }
        if rcpt_to.is_empty() {
            return Err(AppError::BadRequest(
                "Outbound message requires at least one recipient".to_string(),
            ));
        }

        let mut stream =
            SmtpStream::connect(&self.config.host, self.config.port, self.config.tls_mode).await?;

        // 1. Read server greeting (220).
        let greeting = stream.read_response().await?;
        expect_code(&greeting, &[220], "greeting")?;

        // 2. EHLO
        let ehlo_cmd = format!("EHLO {}", self.config.helo_domain);
        let ehlo_resp = stream.command(&ehlo_cmd).await?;
        expect_code(&ehlo_resp, &[250], "EHLO")?;
        let mut caps = EhloCapabilities::from_response(&ehlo_resp);

        // 3. Optional STARTTLS upgrade + second EHLO
        if self.config.tls_mode == SmtpTlsMode::Starttls {
            if !caps.starttls {
                return Err(AppError::Upstream {
                    status: 502,
                    message: format!(
                        "SMTP server {}:{} did not advertise STARTTLS",
                        self.config.host, self.config.port
                    ),
                });
            }
            let stls_resp = stream.command("STARTTLS").await?;
            expect_code(&stls_resp, &[220], "STARTTLS")?;
            stream = stream.upgrade_starttls(&self.config.host).await?;
            let ehlo_tls_resp = stream.command(&ehlo_cmd).await?;
            expect_code(&ehlo_tls_resp, &[250], "EHLO after STARTTLS")?;
            caps = EhloCapabilities::from_response(&ehlo_tls_resp);
        }

        // 4. Optional SMTP AUTH (PLAIN preferred, LOGIN fallback)
        if let Some(username) = self.config.username.as_deref() {
            let password = self.config.password.as_deref().unwrap_or("");
            let use_login = caps.auth_advertised && !caps.auth_plain && caps.auth_login;
            if use_login {
                let auth_start = stream.command("AUTH LOGIN").await?;
                expect_code(&auth_start, &[334], "AUTH LOGIN")?;
                let user_b64 = general_purpose::STANDARD.encode(username.as_bytes());
                let user_resp = stream.command(&user_b64).await?;
                expect_code(&user_resp, &[334], "AUTH LOGIN username")?;
                let pass_b64 = general_purpose::STANDARD.encode(password.as_bytes());
                let pass_resp = stream.command(&pass_b64).await?;
                expect_code(&pass_resp, &[235], "AUTH LOGIN password")?;
            } else {
                let mut plain_bytes = Vec::with_capacity(username.len() + password.len() + 2);
                plain_bytes.push(0);
                plain_bytes.extend_from_slice(username.as_bytes());
                plain_bytes.push(0);
                plain_bytes.extend_from_slice(password.as_bytes());
                let token = general_purpose::STANDARD.encode(&plain_bytes);
                let auth_resp = stream.command(&format!("AUTH PLAIN {token}")).await?;
                expect_code(&auth_resp, &[235], "AUTH PLAIN")?;
            }
        }

        // 5. MAIL FROM
        let mail_resp = stream.command(&format!("MAIL FROM:<{mail_from}>")).await?;
        expect_code(&mail_resp, &[250], "MAIL FROM")?;

        // 6. RCPT TO (all to / cc / bcc)
        for rcpt in &rcpt_to {
            let rcpt_resp = stream.command(&format!("RCPT TO:<{rcpt}>")).await?;
            expect_code(&rcpt_resp, &[250, 251], "RCPT TO")?;
        }

        // 7. DATA + RFC 5321 dot-stuffed raw_rfc2822
        let data_cmd_resp = stream.command("DATA").await?;
        expect_code(&data_cmd_resp, &[354], "DATA")?;

        let stuffed = dot_stuff_rfc5321(&raw_bytes);
        stream.write_all_flush(&stuffed).await?;
        let data_done_resp = stream.read_response().await?;
        expect_code(&data_done_resp, &[250], "DATA completion")?;

        // 8. QUIT (best-effort; message is already accepted by the server)
        if stream.write_all_flush(b"QUIT\r\n").await.is_ok() {
            let _ = stream.read_response().await;
        }

        let provider_message_id = extract_provider_message_id(&data_done_resp, msg, &raw_bytes);
        Ok(SendOutcome {
            provider: self.name().to_string(),
            provider_message_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::TcpListener,
        sync::oneshot,
    };

    use super::*;

    #[derive(Debug)]
    struct CapturedSmtpSession {
        commands: Vec<String>,
        raw_data_wire: Vec<u8>,
        unstuffed_data: Vec<u8>,
    }

    fn unstuff_rfc5321_lines(wire_lines: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for line in wire_lines {
            if line.starts_with(b"..") {
                out.extend_from_slice(&line[1..]);
            } else {
                out.extend_from_slice(line);
            }
        }
        out
    }

    async fn spawn_mock_smtp(
        auth_banner: &'static str,
    ) -> (u16, oneshot::Receiver<CapturedSmtpSession>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(socket);
            reader
                .get_mut()
                .write_all(b"220 mock.smtp.local ESMTP ready\r\n")
                .await
                .unwrap();

            let mut commands = Vec::new();
            let mut raw_data_wire = Vec::new();
            let mut data_lines: Vec<Vec<u8>> = Vec::new();
            let mut in_auth_login_step = 0u8;

            loop {
                let mut line = String::new();
                let n = reader.read_line(&mut line).await.unwrap();
                if n == 0 {
                    break;
                }
                let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
                commands.push(trimmed.clone());

                if in_auth_login_step == 1 {
                    in_auth_login_step = 2;
                    reader
                        .get_mut()
                        .write_all(b"334 UGFzc3dvcmQ6\r\n")
                        .await
                        .unwrap();
                    continue;
                } else if in_auth_login_step == 2 {
                    in_auth_login_step = 0;
                    reader
                        .get_mut()
                        .write_all(b"235 2.7.0 Authentication successful\r\n")
                        .await
                        .unwrap();
                    continue;
                }

                let upper = trimmed.to_ascii_uppercase();
                if upper.starts_with("EHLO ") {
                    let resp = format!(
                        "250-mock.smtp.local Hello\r\n250-SIZE 41943040\r\n250 {auth_banner}\r\n"
                    );
                    reader.get_mut().write_all(resp.as_bytes()).await.unwrap();
                } else if upper.starts_with("AUTH PLAIN ") {
                    reader
                        .get_mut()
                        .write_all(b"235 2.7.0 Authentication successful\r\n")
                        .await
                        .unwrap();
                } else if upper == "AUTH LOGIN" {
                    in_auth_login_step = 1;
                    reader
                        .get_mut()
                        .write_all(b"334 VXNlcm5hbWU6\r\n")
                        .await
                        .unwrap();
                } else if upper.starts_with("MAIL FROM:") || upper.starts_with("RCPT TO:") {
                    reader
                        .get_mut()
                        .write_all(b"250 2.1.0 Ok\r\n")
                        .await
                        .unwrap();
                } else if upper == "DATA" {
                    reader
                        .get_mut()
                        .write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                        .await
                        .unwrap();

                    loop {
                        let mut dline = Vec::new();
                        let dn = reader.read_until(b'\n', &mut dline).await.unwrap();
                        if dn == 0 {
                            break;
                        }
                        raw_data_wire.extend_from_slice(&dline);
                        if dline == b".\r\n" || dline == b".\n" {
                            break;
                        }
                        data_lines.push(dline);
                    }

                    reader
                        .get_mut()
                        .write_all(b"250 2.0.0 Ok: queued as Q-SMTP-999\r\n")
                        .await
                        .unwrap();
                } else if upper == "QUIT" {
                    reader
                        .get_mut()
                        .write_all(b"221 2.0.0 Bye\r\n")
                        .await
                        .unwrap();
                    break;
                } else {
                    reader
                        .get_mut()
                        .write_all(b"500 Unrecognized command\r\n")
                        .await
                        .unwrap();
                }
            }

            let unstuffed_data = unstuff_rfc5321_lines(&data_lines);
            let _ = tx.send(CapturedSmtpSession {
                commands,
                raw_data_wire,
                unstuffed_data,
            });
        });

        (port, rx)
    }

    #[test]
    fn dot_stuffing_preserves_leading_dots_and_terminates_cleanly() {
        let raw = b"From: a@b.com\r\nSubject: Dots\r\n\r\nHello\r\n.Single dot\r\n..Double dot\r\n.\r\nDone\r\n";
        let stuffed = dot_stuff_rfc5321(raw);
        assert_eq!(
            stuffed,
            b"From: a@b.com\r\nSubject: Dots\r\n\r\nHello\r\n..Single dot\r\n...Double dot\r\n..\r\nDone\r\n.\r\n"
        );

        // Input without trailing CRLF gets terminated properly.
        let no_crlf = b"Line1\n.DotLine";
        let stuffed2 = dot_stuff_rfc5321(no_crlf);
        assert_eq!(stuffed2, b"Line1\r\n..DotLine\r\n.\r\n");
    }

    #[tokio::test]
    async fn smtp_transport_executes_ehlo_auth_plain_mail_rcpt_dot_stuffed_data_quit() {
        let (port, rx) = spawn_mock_smtp("AUTH PLAIN LOGIN").await;

        let mut cfg = Config::for_test();
        cfg.smtp_host = "127.0.0.1".to_string();
        cfg.smtp_port = port;
        cfg.smtp_tls_mode = SmtpTlsMode::None;
        cfg.smtp_username = Some("smtp-user".to_string());
        cfg.smtp_password = Some("smtp-pass".to_string());
        cfg.smtp_helo_domain = Some("mail.example.com".to_string());

        let transport = SmtpTransport::from_config(&cfg).unwrap();
        assert_eq!(transport.name(), "smtp");
        let caps = transport.capabilities();
        assert_eq!(caps.provider, "smtp");
        assert!(caps.supports_raw_mime);
        assert!(!caps.supports_inbound_webhooks);

        let raw_mime = concat!(
            "From: Agent <agent@example.com>\r\n",
            "To: Alice <alice@example.com>\r\n",
            "Cc: Bob <bob@example.com>\r\n",
            "Subject: Dot stuffing test\r\n",
            "Message-ID: <smtp-verbatim-1@example.com>\r\n",
            "X-Preserve: exact-mime-header\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "First line\r\n",
            ".Leading dot line\r\n",
            "..Double dot line\r\n",
            ".\r\n",
            "Final line\r\n"
        )
        .as_bytes()
        .to_vec();

        let outcome = transport
            .send(
                &OutboundMessage {
                    from: "Agent <agent@example.com>".to_string(),
                    to: vec!["Alice <alice@example.com>".to_string()],
                    cc: vec!["Bob <bob@example.com>".to_string()],
                    bcc: vec!["audit@example.com".to_string()],
                    subject: "Dot stuffing test".to_string(),
                    raw_rfc2822: raw_mime.clone(),
                    ..Default::default()
                },
                None,
            )
            .await
            .expect("SMTP send should succeed");

        assert_eq!(outcome.provider, "smtp");
        assert_eq!(outcome.provider_message_id, "Q-SMTP-999");

        let captured = rx.await.unwrap();
        let expected_auth = format!(
            "AUTH PLAIN {}",
            general_purpose::STANDARD.encode(b"\0smtp-user\0smtp-pass")
        );
        assert_eq!(
            captured.commands,
            vec![
                "EHLO mail.example.com".to_string(),
                expected_auth,
                "MAIL FROM:<agent@example.com>".to_string(),
                "RCPT TO:<alice@example.com>".to_string(),
                "RCPT TO:<bob@example.com>".to_string(),
                "RCPT TO:<audit@example.com>".to_string(),
                "DATA".to_string(),
                "QUIT".to_string(),
            ]
        );

        // Verify dot-stuffing occurred on the wire.
        let wire_str = String::from_utf8(captured.raw_data_wire).unwrap();
        assert!(wire_str.contains("\r\n..Leading dot line\r\n"));
        assert!(wire_str.contains("\r\n...Double dot line\r\n"));
        assert!(wire_str.contains("\r\n..\r\n"));
        assert!(wire_str.ends_with("\r\n.\r\n"));

        // Verify verbatim raw_rfc2822 round-trip after RFC 5321 un-dot-stuffing.
        assert_eq!(captured.unstuffed_data, raw_mime);
    }

    #[tokio::test]
    async fn smtp_transport_falls_back_to_auth_login_when_plain_not_advertised() {
        let (port, rx) = spawn_mock_smtp("AUTH LOGIN").await;

        let mut cfg = Config::for_test();
        cfg.smtp_host = "127.0.0.1".to_string();
        cfg.smtp_port = port;
        cfg.smtp_tls_mode = SmtpTlsMode::None;
        cfg.smtp_username = Some("login-user".to_string());
        cfg.smtp_password = Some("login-pass".to_string());

        let transport = SmtpTransport::from_config(&cfg).unwrap();
        let raw_mime =
            b"From: agent@example.com\r\nTo: bob@example.com\r\nSubject: Login\r\n\r\nBody\r\n"
                .to_vec();

        let outcome = transport
            .send(
                &OutboundMessage {
                    from: "agent@example.com".to_string(),
                    to: vec!["bob@example.com".to_string()],
                    raw_rfc2822: raw_mime.clone(),
                    ..Default::default()
                },
                None,
            )
            .await
            .expect("SMTP AUTH LOGIN send should succeed");

        assert_eq!(outcome.provider, "smtp");

        let captured = rx.await.unwrap();
        assert_eq!(
            captured.commands,
            vec![
                "EHLO example.com".to_string(),
                "AUTH LOGIN".to_string(),
                general_purpose::STANDARD.encode("login-user"),
                general_purpose::STANDARD.encode("login-pass"),
                "MAIL FROM:<agent@example.com>".to_string(),
                "RCPT TO:<bob@example.com>".to_string(),
                "DATA".to_string(),
                "QUIT".to_string(),
            ]
        );
        assert_eq!(captured.unstuffed_data, raw_mime);
    }
}
