use std::{
    collections::HashMap,
    fs,
    io::{BufRead, BufReader},
    net::TcpListener,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use nogml::{auth_wizard::pkce_s256_challenge, secrets::REDACTED};
use serde_json::Value;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn nogml_bin() -> &'static str {
    env!("CARGO_BIN_EXE_nogml")
}

fn clean_nogml_cmd() -> Command {
    let mut cmd = Command::new(nogml_bin());
    for (k, _) in std::env::vars() {
        if k.starts_with("NOGML_")
            || k.starts_with("RESEND_")
            || k.starts_with("GMAIL_")
            || k == "CREDENTIALS_DIRECTORY"
        {
            cmd.env_remove(k);
        }
    }
    cmd
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_local_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr.to_string()
}

#[test]
fn mint_token_output_file_0600_toml_and_config_check_e2e() {
    let dir = tempfile::tempdir().unwrap();
    let token_path = dir.path().join("secrets").join("triage_agent_token");

    let out = clean_nogml_cmd()
        .args([
            "auth",
            "mint-token",
            "--mailbox",
            "agent@example.com",
            "--scopes",
            "read,write",
            "--draft-only",
            "--allowed-recipients",
            "@example.com,partner@acme.org",
            "--max-send-recipients",
            "5",
            "--output-file",
        ])
        .arg(&token_path)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );

    // Raw token is written to disk with 0600 permissions and never echoed in stdout/stderr.
    let raw_token = fs::read_to_string(&token_path).unwrap();
    let trimmed = raw_token.trim();
    assert!(trimmed.starts_with("nogml_"));
    assert_eq!(trimmed.len(), "nogml_".len() + 64);
    assert!(
        trimmed["nogml_".len()..]
            .chars()
            .all(|c| c.is_ascii_hexdigit()),
        "expected 64 lowercase hex chars after nogml_, got {trimmed}"
    );
    assert!(
        !stdout.contains(trimmed),
        "stdout must not leak plaintext token when --output-file is set"
    );
    assert!(
        !stderr.contains(trimmed),
        "stderr must not leak plaintext token when --output-file is set"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&token_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600 permissions, got {:04o}", mode);
    }

    assert!(stdout.contains("[[auth.scoped_tokens]]"));
    assert!(stdout.contains("token = \"file://"));
    assert!(stdout.contains("mailbox_id = \"agent@example.com\""));
    assert!(stdout.contains("scopes = [\"read\", \"write\"]"));
    assert!(stdout.contains("draft_only = true"));
    assert!(stdout.contains("allowed_recipients = [\"@example.com\", \"partner@acme.org\"]"));
    assert!(stdout.contains("max_send_recipients = 5"));

    // Refuses to overwrite existing token file without --force.
    let dup = clean_nogml_cmd()
        .args(["auth", "mint-token", "--output-file"])
        .arg(&token_path)
        .output()
        .unwrap();
    assert_eq!(dup.status.code(), Some(2));

    // Embed the emitted TOML snippet into a nogml.toml and validate with `nogml config check`.
    let config_path = dir.path().join("nogml.toml");
    fs::write(
        &config_path,
        format!(
            r#"
[storage]
backend = "memory"

[blob]
backend = "memory"

[auth]
user_email = "agent@example.com"
default_domain = "example.com"

{stdout}
"#
        ),
    )
    .unwrap();

    let check = clean_nogml_cmd()
        .args(["config", "check", "--config"])
        .arg(&config_path)
        .output()
        .unwrap();
    let check_stdout = String::from_utf8_lossy(&check.stdout);
    let check_stderr = String::from_utf8_lossy(&check.stderr);
    assert_eq!(
        check.status.code(),
        Some(0),
        "config check failed\nstdout: {check_stdout}\nstderr: {check_stderr}"
    );
    assert!(!check_stdout.contains(trimmed));

    let report: Value = serde_json::from_str(&check_stdout).unwrap();
    assert_eq!(report["ok"], true);
    assert!(report["errors"].as_array().unwrap().is_empty());
    assert!(
        !report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap_or_default().contains("permissive")),
        "0600 secret file should produce no permission warning: {:?}",
        report["warnings"]
    );
    let st = &report["effective_config"]["auth"]["scoped_tokens"][0];
    assert_eq!(st["token"], REDACTED);
    assert_eq!(st["mailbox_id"], "agent@example.com");
    assert_eq!(st["scopes"], serde_json::json!(["read", "write"]));
    assert_eq!(st["draft_only"], true);
    assert_eq!(
        st["allowed_recipients"],
        serde_json::json!(["@example.com", "partner@acme.org"])
    );
    assert_eq!(st["max_send_recipients"], 5);
}

#[tokio::test]
async fn mint_token_json_and_serve_enforcement_e2e() {
    let dir = tempfile::tempdir().unwrap();
    let token_path = dir.path().join("ro_agent_token");

    // 1. --json output works directly in NOGML_SCOPED_TOKENS and passes `nogml config check`.
    let out = clean_nogml_cmd()
        .args([
            "auth",
            "mint-token",
            "--user-email",
            "bot@example.com",
            "--scopes",
            "read",
            "--draft-only",
            "--json",
            "--output-file",
        ])
        .arg(&token_path)
        .output()
        .unwrap();
    let json_stdout = String::from_utf8_lossy(&out.stdout);
    let json_stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {json_stdout}\nstderr: {json_stderr}"
    );

    let parsed: Value = serde_json::from_str(json_stdout.trim()).unwrap();
    assert!(parsed.is_array());
    assert_eq!(parsed.as_array().unwrap().len(), 1);
    assert!(parsed[0]["token"].as_str().unwrap().starts_with("file://"));
    assert_eq!(parsed[0]["mailbox_id"], "bot@example.com");
    assert_eq!(parsed[0]["scopes"], serde_json::json!(["read"]));
    assert_eq!(parsed[0]["draft_only"], true);

    let raw_token = fs::read_to_string(&token_path).unwrap().trim().to_string();
    assert!(!json_stdout.contains(&raw_token));

    let check = clean_nogml_cmd()
        .env("NOGML_SCOPED_TOKENS", json_stdout.trim())
        .args([
            "config",
            "check",
            "--storage",
            "memory",
            "--blob-backend",
            "memory",
        ])
        .output()
        .unwrap();
    assert_eq!(check.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(report["ok"], true);
    assert_eq!(
        report["effective_config"]["auth"]["scoped_tokens"][0]["token"],
        REDACTED
    );

    // 2. Start `nogml serve` with the minted NOGML_SCOPED_TOKENS and verify read succeeds while send returns 403.
    let bind = free_local_addr();
    let child = clean_nogml_cmd()
        .env("NOGML_SCOPED_TOKENS", json_stdout.trim())
        .args([
            "serve",
            "--bind",
            &bind,
            "--storage",
            "memory",
            "--blob-backend",
            "memory",
            "--user-email",
            "bot@example.com",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _guard = ChildGuard(child);

    let client = reqwest::Client::new();
    let health_url = format!("http://{bind}/healthz");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(resp) = client.get(&health_url).send().await
            && resp.status().is_success()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "nogml serve did not become healthy at {health_url}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Unauthenticated request is rejected.
    let unauth = client
        .get(format!("http://{bind}/v1/capabilities"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status().as_u16(), 401);

    // Read-only minted token succeeds on GET /v1/capabilities.
    let caps = client
        .get(format!("http://{bind}/v1/capabilities"))
        .bearer_auth(&raw_token)
        .send()
        .await
        .unwrap();
    assert_eq!(caps.status().as_u16(), 200);

    // Read-only minted token is denied on POST /v1/messages/send.
    let send_resp = client
        .post(format!("http://{bind}/v1/messages/send"))
        .bearer_auth(&raw_token)
        .json(&serde_json::json!({
            "to": ["alice@example.com"],
            "subject": "Should be denied",
            "text": "hello"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(send_resp.status().as_u16(), 403);
}

#[tokio::test]
async fn gmail_oauth2_loopback_pkce_flow_e2e() {
    let mock_server = MockServer::start().await;
    let secret_refresh_token = "1//0g_mock_gmail_refresh_secret_987654";
    let secret_access_token = "ya29.mock_gmail_access_secret_123456";
    let client_secret = "GOCSPX-mock-client-secret-abc";

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": secret_access_token,
            "refresh_token": secret_refresh_token,
            "expires_in": 3599,
            "scope": "https://www.googleapis.com/auth/gmail.modify",
            "token_type": "Bearer"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let output_file = dir.path().join("secrets").join("gmail_refresh_token");
    let token_url = format!("{}/token", mock_server.uri());

    let mut child = clean_nogml_cmd()
        .args([
            "auth",
            "gmail",
            "--client-id",
            "test-client-id.apps.googleusercontent.com",
            "--client-secret",
            client_secret,
            "--token-url",
            &token_url,
            "--listen",
            "127.0.0.1:0",
            "--no-browser",
            "--timeout-secs",
            "30",
            "--output-file",
        ])
        .arg(&output_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let stderr_pipe = child.stderr.take().unwrap();
    let (url_tx, url_rx) = mpsc::channel::<String>();
    let stderr_thread = thread::spawn(move || {
        let reader = BufReader::new(stderr_pipe);
        let mut all_stderr = String::new();
        let mut sent = false;
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            all_stderr.push_str(&line);
            all_stderr.push('\n');
            if !sent && line.starts_with("https://") {
                let _ = url_tx.send(line);
                sent = true;
            }
        }
        all_stderr
    });

    let auth_url_str = url_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("nogml auth gmail should print authorization URL to stderr");

    let parsed_url = Url::parse(&auth_url_str).expect("valid authorization URL");
    let params: HashMap<String, String> = parsed_url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    assert_eq!(
        params.get("client_id").map(String::as_str),
        Some("test-client-id.apps.googleusercontent.com")
    );
    assert_eq!(
        params.get("response_type").map(String::as_str),
        Some("code")
    );
    assert_eq!(
        params.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    assert_eq!(
        params.get("access_type").map(String::as_str),
        Some("offline")
    );
    assert_eq!(params.get("prompt").map(String::as_str), Some("consent"));

    let redirect_uri = params
        .get("redirect_uri")
        .expect("redirect_uri param")
        .clone();
    let state = params.get("state").expect("state param").clone();
    let code_challenge = params
        .get("code_challenge")
        .expect("code_challenge param")
        .clone();

    assert!(redirect_uri.starts_with("http://127.0.0.1:"));
    assert!(redirect_uri.ends_with("/callback"));

    let http = reqwest::Client::new();

    // 1. Mismatched CSRF state is rejected with HTTP 400 and does not abort the flow.
    let bad_cb = http
        .get(&redirect_uri)
        .query(&[("code", "bad_code"), ("state", "wrong_csrf_state")])
        .send()
        .await
        .unwrap();
    assert_eq!(bad_cb.status().as_u16(), 400);

    // 2. Valid callback with matching state succeeds with HTTP 200.
    let ok_cb = http
        .get(&redirect_uri)
        .query(&[("code", "valid_auth_code_123"), ("state", state.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(ok_cb.status().as_u16(), 200);

    let output = child.wait_with_output().unwrap();
    let stderr_text = stderr_thread.join().unwrap();
    let stdout_text = String::from_utf8_lossy(&output.stdout);

    assert_eq!(
        output.status.code(),
        Some(0),
        "nogml auth gmail failed\nstdout: {stdout_text}\nstderr: {stderr_text}"
    );

    // Verify wiremock received the exact token exchange payload including valid PKCE code_verifier.
    let recorded = mock_server.received_requests().await.unwrap();
    assert_eq!(recorded.len(), 1);
    let form_params: HashMap<String, String> = url::form_urlencoded::parse(&recorded[0].body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert_eq!(
        form_params.get("grant_type").map(String::as_str),
        Some("authorization_code")
    );
    assert_eq!(
        form_params.get("code").map(String::as_str),
        Some("valid_auth_code_123")
    );
    assert_eq!(
        form_params.get("client_id").map(String::as_str),
        Some("test-client-id.apps.googleusercontent.com")
    );
    assert_eq!(
        form_params.get("client_secret").map(String::as_str),
        Some(client_secret)
    );
    assert_eq!(
        form_params.get("redirect_uri").map(String::as_str),
        Some(redirect_uri.as_str())
    );
    let code_verifier = form_params
        .get("code_verifier")
        .expect("PKCE code_verifier must be sent to token endpoint");
    assert_eq!(
        pkce_s256_challenge(code_verifier),
        code_challenge,
        "code_verifier must match S256 code_challenge from authorization URL"
    );

    // Verify refresh_token saved on disk with 0600 permissions.
    let saved_refresh = fs::read_to_string(&output_file).unwrap();
    assert_eq!(saved_refresh.trim(), secret_refresh_token);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&output_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600 permissions, got {:04o}", mode);
    }

    // Verify redacted JSON summary and zero secret leakage in stdout or stderr.
    let summary: Value = serde_json::from_str(&stdout_text).unwrap();
    assert_eq!(summary["ok"], true);
    assert_eq!(summary["token_type"], "Bearer");
    assert_eq!(
        summary["scope"],
        "https://www.googleapis.com/auth/gmail.modify"
    );
    assert_eq!(summary["expires_in"], 3599);
    let snippet = summary["config_snippet"].as_str().unwrap();
    assert!(
        snippet.contains("refresh_token = \"file://"),
        "unexpected config_snippet: {snippet}"
    );
    assert!(snippet.starts_with("gmail_refresh_token = \"file://"));

    for leaked in [
        secret_refresh_token,
        secret_access_token,
        client_secret,
        code_verifier.as_str(),
    ] {
        assert!(
            !stdout_text.contains(leaked),
            "stdout leaked secret '{leaked}': {stdout_text}"
        );
        assert!(
            !stderr_text.contains(leaked),
            "stderr leaked secret '{leaked}': {stderr_text}"
        );
    }

    // Verify config_snippet embeds cleanly under [sync] and passes `nogml config check`.
    let config_path = dir.path().join("nogml.toml");
    fs::write(
        &config_path,
        format!(
            r#"
[storage]
backend = "memory"

[blob]
backend = "memory"

[sync]
mode = "api"
gmail_client_id = "test-client-id.apps.googleusercontent.com"
{snippet}
"#
        ),
    )
    .unwrap();

    let check = clean_nogml_cmd()
        .args(["config", "check", "--config"])
        .arg(&config_path)
        .output()
        .unwrap();
    let check_stdout = String::from_utf8_lossy(&check.stdout);
    assert_eq!(check.status.code(), Some(0), "stdout: {check_stdout}");
    assert!(!check_stdout.contains(secret_refresh_token));
    let report: Value = serde_json::from_str(&check_stdout).unwrap();
    assert_eq!(report["ok"], true);
    assert_eq!(
        report["effective_config"]["sync"]["gmail_refresh_token"],
        REDACTED
    );
}

#[tokio::test]
async fn gmail_oauth2_public_client_without_secret_e2e() {
    let mock_server = MockServer::start().await;
    let secret_refresh_token = "1//0g_public_client_refresh_token";

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "ya29.public_access",
            "refresh_token": secret_refresh_token,
            "scope": "https://mail.google.com/",
            "token_type": "Bearer"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let output_file = dir.path().join("public_refresh_token");
    let token_url = format!("{}/token", mock_server.uri());

    let mut child = clean_nogml_cmd()
        .args([
            "auth",
            "gmail",
            "--client-id",
            "public-client-id",
            "--token-url",
            &token_url,
            "--scopes",
            "https://mail.google.com/",
            "--listen",
            "127.0.0.1:0",
            "--no-browser",
            "--timeout-secs",
            "30",
            "--output-file",
        ])
        .arg(&output_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let stderr_pipe = child.stderr.take().unwrap();
    let (url_tx, url_rx) = mpsc::channel::<String>();
    let stderr_thread = thread::spawn(move || {
        let reader = BufReader::new(stderr_pipe);
        let mut all_stderr = String::new();
        let mut sent = false;
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            all_stderr.push_str(&line);
            all_stderr.push('\n');
            if !sent && line.starts_with("https://") {
                let _ = url_tx.send(line);
                sent = true;
            }
        }
        all_stderr
    });

    let auth_url_str = url_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("authorization URL on stderr");
    let parsed_url = Url::parse(&auth_url_str).unwrap();
    let params: HashMap<String, String> = parsed_url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    let redirect_uri = params.get("redirect_uri").unwrap();
    let state = params.get("state").unwrap();

    let ok_cb = reqwest::Client::new()
        .get(redirect_uri)
        .query(&[("code", "pub_code_7"), ("state", state.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(ok_cb.status().as_u16(), 200);

    let output = child.wait_with_output().unwrap();
    let stderr_text = stderr_thread.join().unwrap();
    let stdout_text = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout_text}\nstderr: {stderr_text}"
    );

    let recorded = mock_server.received_requests().await.unwrap();
    let form_params: HashMap<String, String> = url::form_urlencoded::parse(&recorded[0].body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert!(!form_params.contains_key("client_secret"));
    assert!(form_params.contains_key("code_verifier"));
    assert_eq!(
        fs::read_to_string(&output_file).unwrap().trim(),
        secret_refresh_token
    );
    assert!(!stdout_text.contains(secret_refresh_token));
    assert!(!stderr_text.contains(secret_refresh_token));
}
