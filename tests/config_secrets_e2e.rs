use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use nogml::{
    config::{
        AuthFailAction, BlobBackend, Config, DraftOnlyAction, RspamdRejectAction, SearchBackend,
        SmtpTlsMode, StorageBackend, SyncMode, TomlConfig, TransportBackend,
    },
    secrets::{REDACTED, write_secret_file},
};
use serde_json::Value;

fn nogml_bin() -> &'static str {
    env!("CARGO_BIN_EXE_nogml")
}

/// Build a `Command` for the compiled `nogml` binary with all `NOGML_*`, `RESEND_*`, and `GMAIL_*`
/// environment variables cleared so host environment never contaminates tests.
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
fn deploy_example_toml_parses_cleanly() {
    let example_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy/nogml.example.toml");
    let parsed = TomlConfig::from_file(&example_path)
        .expect("deploy/nogml.example.toml must parse cleanly with deny_unknown_fields");

    let mut cfg = Config::default();
    let meta = parsed.apply_to(&mut cfg);
    assert!(meta.user_email_set);
    assert_eq!(meta.log_json, Some(true));
    assert_eq!(cfg.bind.to_string(), "0.0.0.0:8080");
    assert_eq!(cfg.storage, StorageBackend::Sqlite);
    assert_eq!(cfg.blob_backend, BlobBackend::Fs);
    assert_eq!(cfg.user_email, "agent@example.com");
    assert_eq!(cfg.mailboxes, vec!["support@example.com"]);
    assert_eq!(cfg.default_domain, "example.com");
    assert_eq!(cfg.scoped_tokens.len(), 1);
    assert_eq!(cfg.oauth2_client_id.as_deref(), Some("nogml-local-client"));
    assert_eq!(cfg.transport, TransportBackend::Resend);
    assert_eq!(cfg.smtp_port, 587);
    assert_eq!(cfg.smtp_tls_mode, SmtpTlsMode::Starttls);
    assert_eq!(cfg.draft_only_action, DraftOnlyAction::Block);
    assert_eq!(cfg.sync_mode, SyncMode::Api);
    assert!(cfg.filter_auth_results);
    assert_eq!(cfg.filter_dmarc_fail_action, AuthFailAction::Spam);
    assert_eq!(cfg.rspamd_reject_action, RspamdRejectAction::Reject);
    assert_eq!(cfg.search_backend, SearchBackend::Store);
}

#[test]
fn cli_env_toml_defaults_precedence_e2e() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("nogml.toml");
    let token_path = dir.path().join("auth_token");
    write_secret_file(&token_path, "tok_toml_secret", false).unwrap();

    fs::write(
        &config_path,
        format!(
            r#"
[server]
bind = "127.0.0.1:9101"
max_body_bytes = 1048576

[storage]
backend = "memory"

[blob]
backend = "memory"

[auth]
user_email = "toml@example.com"
default_domain = "toml.example"
tokens = ["file://{}"]

[smtp]
host = "smtp.toml.example"
port = 2525

[safety]
draft_only = true
max_send_recipients = 12

[filters]
auth_results = true
"#,
            token_path.display()
        ),
    )
    .unwrap();

    // 1. TOML beats defaults (no env or CLI overrides).
    let out = clean_nogml_cmd()
        .args(["config", "check", "--config"])
        .arg(&config_path)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["ok"], true);
    let eff = &report["effective_config"];
    assert_eq!(eff["server"]["bind"], "127.0.0.1:9101");
    assert_eq!(eff["server"]["max_body_bytes"], 1048576);
    assert_eq!(eff["storage"]["backend"], "memory");
    assert_eq!(eff["blob"]["backend"], "memory");
    assert_eq!(eff["auth"]["user_email"], "toml@example.com");
    assert_eq!(eff["auth"]["default_domain"], "toml.example");
    assert_eq!(eff["smtp"]["host"], "smtp.toml.example");
    assert_eq!(eff["smtp"]["port"], 2525);
    assert_eq!(eff["safety"]["draft_only"], true);
    assert_eq!(eff["safety"]["max_send_recipients"], 12);
    assert_eq!(eff["filters"]["auth_results"], true);
    // Unset field falls back to built-in default.
    assert_eq!(eff["safety"]["approval_ttl_secs"], 86400);

    // 2. Environment variables override nogml.toml, while untouched TOML keys stay intact.
    let out = clean_nogml_cmd()
        .env("NOGML_CONFIG", &config_path)
        .env("NOGML_BIND", "127.0.0.1:9102")
        .env("NOGML_USER_EMAIL", "env@example.com")
        .env("NOGML_MAX_SEND_RECIPIENTS", "25")
        .env("NOGML_DRAFT_ONLY", "false")
        .args(["config", "check"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    let eff = &report["effective_config"];
    assert_eq!(eff["server"]["bind"], "127.0.0.1:9102");
    assert_eq!(eff["auth"]["user_email"], "env@example.com");
    assert_eq!(eff["safety"]["max_send_recipients"], 25);
    assert_eq!(eff["safety"]["draft_only"], false);
    // Untouched TOML keys still win over defaults.
    assert_eq!(eff["auth"]["default_domain"], "toml.example");
    assert_eq!(eff["smtp"]["port"], 2525);
    assert_eq!(eff["filters"]["auth_results"], true);

    // 3. CLI flags override both environment variables and nogml.toml.
    let out = clean_nogml_cmd()
        .env("NOGML_CONFIG", &config_path)
        .env("NOGML_BIND", "127.0.0.1:9102")
        .env("NOGML_USER_EMAIL", "env@example.com")
        .env("NOGML_DEFAULT_DOMAIN", "env.example")
        .env("NOGML_MAX_SEND_RECIPIENTS", "25")
        .env("NOGML_DRAFT_ONLY", "false")
        .args([
            "config",
            "check",
            "--bind",
            "127.0.0.1:9103",
            "--user-email",
            "cli@example.com",
            "--max-send-recipients",
            "7",
            "--draft-only",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    let eff = &report["effective_config"];
    assert_eq!(eff["server"]["bind"], "127.0.0.1:9103");
    assert_eq!(eff["auth"]["user_email"], "cli@example.com");
    assert_eq!(eff["auth"]["default_domain"], "env.example");
    assert_eq!(eff["safety"]["max_send_recipients"], 7);
    assert_eq!(eff["safety"]["draft_only"], true);
    assert_eq!(eff["smtp"]["port"], 2525);
}

#[test]
fn secret_loaders_file_env_and_env_file_and_redaction_e2e() {
    let dir = tempfile::tempdir().unwrap();
    let creds_dir = dir.path().join("creds");
    fs::create_dir_all(&creds_dir).unwrap();

    let resend_key_file = dir.path().join("resend_api_key");
    let auth_tokens_file = dir.path().join("auth_tokens");
    let scoped_tokens_file = dir.path().join("scoped_tokens.json");
    let scoped_inner_token_file = dir.path().join("scoped_inner_token");
    let imap_pass_file = dir.path().join("imap_password");
    let oauth_sign_file = creds_dir.join("oauth_signing_secret");
    let smtp_pass_file = dir.path().join("smtp_password");

    write_secret_file(&resend_key_file, "super-secret-resend-api-key", false).unwrap();
    write_secret_file(
        &auth_tokens_file,
        "super-secret-bearer-one\nsuper-secret-bearer-two",
        false,
    )
    .unwrap();
    write_secret_file(&scoped_inner_token_file, "super-secret-scoped-inner", false).unwrap();
    write_secret_file(
        &scoped_tokens_file,
        &format!(
            r#"[{{"token":"file://{}","mailbox_id":"agent@example.com","scopes":["read"],"draft_only":true}}]"#,
            scoped_inner_token_file.display()
        ),
        false,
    )
    .unwrap();
    write_secret_file(&imap_pass_file, "super-secret-imap-password", false).unwrap();
    write_secret_file(&oauth_sign_file, "super-secret-oauth-signing", false).unwrap();
    write_secret_file(&smtp_pass_file, "super-secret-smtp-password", false).unwrap();

    let config_path = dir.path().join("nogml.toml");
    fs::write(
        &config_path,
        format!(
            r#"
[auth]
user_email = "agent@example.com"

[oauth2]
client_id = "nogml-client"
client_secret = "env://TEST_OAUTH_CLIENT_SECRET"
signing_secret = "file://$CREDENTIALS_DIRECTORY/oauth_signing_secret"

[resend]
webhook_secret = "env://TEST_RESEND_WHSEC"

[smtp]
password = "file://{}"
"#,
            smtp_pass_file.display()
        ),
    )
    .unwrap();

    let out = clean_nogml_cmd()
        .env("CREDENTIALS_DIRECTORY", &creds_dir)
        .env("TEST_OAUTH_CLIENT_SECRET", "super-secret-oauth-client")
        .env("TEST_RESEND_WHSEC", "super-secret-resend-whsec")
        .env("RESEND_API_KEY_FILE", &resend_key_file)
        .env("NOGML_AUTH_TOKENS_FILE", &auth_tokens_file)
        .env("NOGML_SCOPED_TOKENS_FILE", &scoped_tokens_file)
        .env("NOGML_IMAP_PASSWORD_FILE", &imap_pass_file)
        .args(["config", "check", "--config"])
        .arg(&config_path)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );

    let report: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["ok"], true);
    assert!(report["errors"].as_array().unwrap().is_empty());

    let eff = &report["effective_config"];
    assert_eq!(eff["resend"]["api_key"], REDACTED);
    assert_eq!(eff["resend"]["webhook_secret"], REDACTED);
    assert_eq!(
        eff["auth"]["tokens"],
        serde_json::json!([REDACTED, REDACTED])
    );
    assert_eq!(eff["auth"]["scoped_tokens"][0]["token"], REDACTED);
    assert_eq!(eff["oauth2"]["client_secret"], REDACTED);
    assert_eq!(eff["oauth2"]["signing_secret"], REDACTED);
    assert_eq!(eff["imap"]["password"], REDACTED);
    assert_eq!(eff["smtp"]["password"], REDACTED);

    for secret in [
        "super-secret-resend-api-key",
        "super-secret-bearer-one",
        "super-secret-bearer-two",
        "super-secret-scoped-inner",
        "super-secret-imap-password",
        "super-secret-oauth-signing",
        "super-secret-oauth-client",
        "super-secret-resend-whsec",
        "super-secret-smtp-password",
    ] {
        assert!(!stdout.contains(secret), "stdout leaked secret {secret}");
        assert!(!stderr.contains(secret), "stderr leaked secret {secret}");
    }

    // Missing file:// and unset env:// return exit code 2 with actionable errors.
    let bad_config = dir.path().join("bad.toml");
    fs::write(
        &bad_config,
        r#"
[resend]
api_key = "file:///nonexistent/nogml/secret/key"
webhook_secret = "env://DEFINITELY_UNSET_NOGML_TEST_VAR"
"#,
    )
    .unwrap();
    let bad_out = clean_nogml_cmd()
        .args(["config", "check", "--config"])
        .arg(&bad_config)
        .output()
        .unwrap();
    assert_eq!(bad_out.status.code(), Some(2));
    let bad_report: Value = serde_json::from_slice(&bad_out.stdout).unwrap();
    assert_eq!(bad_report["ok"], false);
    let errs = bad_report["errors"].as_array().unwrap();
    assert!(errs.len() >= 2, "expected both secret errors, got {errs:?}");
}

#[cfg(unix)]
#[test]
fn permissive_secret_file_emits_non_fatal_warning() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let open_tok = dir.path().join("open_tok");
    fs::write(&open_tok, "super-secret-open-token\n").unwrap();
    fs::set_permissions(&open_tok, fs::Permissions::from_mode(0o644)).unwrap();

    let out = clean_nogml_cmd()
        .env("NOGML_AUTH_TOKENS_FILE", &open_tok)
        .args(["config", "check"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0));
    assert!(!stdout.contains("super-secret-open-token"));
    let report: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["ok"], true);
    let warnings = report["warnings"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().unwrap_or("").contains("0644")),
        "expected 0644 permission warning, got {warnings:?}"
    );
}

#[test]
fn config_check_validates_tls_and_backend_consistency_e2e() {
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    fs::write(&cert_path, cert.cert.pem()).unwrap();
    write_secret_file(&key_path, &cert.key_pair.serialize_pem(), false).unwrap();

    // Valid TLS cert + key passes.
    let valid_toml = dir.path().join("valid_tls.toml");
    fs::write(
        &valid_toml,
        format!(
            r#"
[auth]
tokens = ["tok_tls_check"]

[imap]
tls_bind = "127.0.0.1:1993"
tls_cert = "{}"
tls_key = "{}"
"#,
            cert_path.display(),
            key_path.display()
        ),
    )
    .unwrap();
    let out = clean_nogml_cmd()
        .args(["config", "check", "--config"])
        .arg(&valid_toml)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    // Corrupt TLS key fails with exit 2.
    let bad_key = dir.path().join("bad_key.pem");
    write_secret_file(&bad_key, "not a pem private key", false).unwrap();
    let bad_tls_toml = dir.path().join("bad_tls.toml");
    fs::write(
        &bad_tls_toml,
        format!(
            r#"
[imap]
tls_bind = "127.0.0.1:1993"
tls_cert = "{}"
tls_key = "{}"
"#,
            cert_path.display(),
            bad_key.display()
        ),
    )
    .unwrap();
    let out = clean_nogml_cmd()
        .args(["config", "check", "--config"])
        .arg(&bad_tls_toml)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["ok"], false);

    // Inconsistent S3 + OAuth2 + Postgres fails with exit 2 and reports all errors.
    let inconsistent_toml = dir.path().join("inconsistent.toml");
    fs::write(
        &inconsistent_toml,
        r#"
[storage]
backend = "postgres"

[blob]
backend = "s3"

[oauth2]
client_id = "missing-signing-secret"
"#,
    )
    .unwrap();
    let out = clean_nogml_cmd()
        .args(["config", "check", "--config"])
        .arg(&inconsistent_toml)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["ok"], false);
    let errs = report["errors"].as_array().unwrap();
    assert!(
        errs.iter()
            .any(|e| e.as_str().unwrap_or("").contains("database_url")),
        "expected postgres database_url error: {errs:?}"
    );
    assert!(
        errs.iter()
            .any(|e| e.as_str().unwrap_or("").contains("NOGML_BLOB_S3_BUCKET")),
        "expected S3 bucket error: {errs:?}"
    );
    assert!(
        errs.iter()
            .any(|e| e.as_str().unwrap_or("").contains("oauth2.signing_secret")),
        "expected OAuth2 consistency error: {errs:?}"
    );
}

#[tokio::test]
async fn config_init_check_serve_full_lifecycle_e2e() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("nogml.toml");
    let token_path = dir.path().join("secrets").join("auth_token");
    let db_path = dir.path().join("mail.db");

    // 1. Run `nogml config init` with --token-file.
    let init_out = clean_nogml_cmd()
        .args([
            "config",
            "init",
            "--output",
            config_path.to_str().unwrap(),
            "--token-file",
            token_path.to_str().unwrap(),
            "--user-email",
            "selfhost@example.com",
        ])
        .output()
        .unwrap();
    assert_eq!(
        init_out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&init_out.stderr)
    );
    assert!(config_path.exists());
    assert!(token_path.exists());

    let token = fs::read_to_string(&token_path).unwrap().trim().to_string();
    assert!(token.starts_with("nogml_"));
    assert_eq!(token.len(), "nogml_".len() + 64);

    // Token must NOT be embedded in nogml.toml or stdout.
    let toml_text = fs::read_to_string(&config_path).unwrap();
    let init_stdout = String::from_utf8_lossy(&init_out.stdout);
    assert!(!toml_text.contains(&token));
    assert!(!init_stdout.contains(&token));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&token_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "token file must be mode 0600");
    }

    // Refuses overwrite without --force.
    let dup_out = clean_nogml_cmd()
        .args(["config", "init", "--output", config_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(dup_out.status.code(), Some(2));

    // Also test default init (no --token-file) prints generated token to stderr, not stdout or file.
    let no_file_cfg = dir.path().join("nogml-stderr.toml");
    let init_stderr_out = clean_nogml_cmd()
        .args(["config", "init", "--output", no_file_cfg.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(init_stderr_out.status.code(), Some(0));
    let stderr_str = String::from_utf8_lossy(&init_stderr_out.stderr);
    let stdout_str = String::from_utf8_lossy(&init_stderr_out.stdout);
    let generated_line = stderr_str
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("nogml_"))
        .expect("token printed to stderr");
    assert!(!stdout_str.contains(generated_line));
    assert!(
        !fs::read_to_string(&no_file_cfg)
            .unwrap()
            .contains(generated_line)
    );

    // 2. Run `nogml config check --config <path>`.
    let check_out = clean_nogml_cmd()
        .args(["config", "check", "--config"])
        .arg(&config_path)
        .output()
        .unwrap();
    let check_stdout = String::from_utf8_lossy(&check_out.stdout);
    assert_eq!(check_out.status.code(), Some(0), "stdout: {check_stdout}");
    assert!(!check_stdout.contains(&token));
    let check_report: Value = serde_json::from_str(&check_stdout).unwrap();
    assert_eq!(check_report["ok"], true);
    assert_eq!(
        check_report["effective_config"]["auth"]["user_email"],
        "selfhost@example.com"
    );
    assert_eq!(
        check_report["effective_config"]["auth"]["tokens"],
        serde_json::json!([REDACTED])
    );

    // 3. Boot real `nogml serve --config <path>` overriding bind + db_path via CLI.
    let bind_addr = free_local_addr();
    let child = clean_nogml_cmd()
        .args([
            "serve",
            "--config",
            config_path.to_str().unwrap(),
            "--bind",
            &bind_addr,
            "--db-path",
            db_path.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn nogml serve");
    let _guard = ChildGuard(child);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let base_url = format!("http://{bind_addr}");

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(resp) = client.get(format!("{base_url}/healthz")).send().await
            && resp.status().is_success()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "nogml serve did not become healthy within 10s on {base_url}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Unauthenticated request must be rejected (file:// bearer token from nogml.toml is active).
    let unauth = client
        .get(format!("{base_url}/v1/capabilities"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Authenticated request succeeds and reflects nogml.toml values.
    let authed = client
        .get(format!("{base_url}/v1/capabilities"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(authed.status(), reqwest::StatusCode::OK);
    let caps: Value = authed.json().await.unwrap();
    assert_eq!(caps["user_email"], "selfhost@example.com");
    assert_eq!(caps["safety"]["draft_only"], true);
    assert!(Path::new(&db_path).exists());
}
