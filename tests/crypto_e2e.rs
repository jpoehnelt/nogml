//! End-to-end tests for AES-256-GCM encryption at rest and key rotation CLI (`Issue #73`):
//! - Encrypts `sendAs.smtp_msa.password` and `inbox_rules.webhook_secret` in SQLite (`enc:v1:<kid>:...`)
//! - Decrypts `webhook_secret` right before computing HMAC-SHA256 `X-Nogml-Signature`
//! - Reports `encryption_at_rest` in `GET /v1/capabilities`
//! - `nogml crypto generate-key` writes mode 0600 key files and redacts stdout/stderr
//! - `nogml crypto rotate-key` re-encrypts legacy plaintext and `k1` rows under `k2` across all mailboxes
//! - After dropping `k1`, reads and webhook signatures continue to succeed with only `k2`
//! - Invalid keys fail fast in `AppState::from_config` and `nogml config check`; wrong keys fail closed on webhooks

use std::{fs, process::Command, time::Duration};

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use nogml::{
    AppState,
    ai::rules::{WEBHOOK_SIGNATURE_HEADER, compute_webhook_signature},
    build_router,
    config::{Config, StorageBackend},
    crypto::generate_formatted_key,
    error::AppError,
    mime::{ComposeEmailInput, build_rfc2822},
    models::{LABEL_INBOX, LABEL_UNREAD, SendAs, SmtpMsa},
    storage::{InboxRuleActions, NewInboxRule},
    transport::{InboundEnvelope, IngestOutcome, ingest_inbound_rfc2822_with_cipher},
};
use serde_json::{Value, json};
use tower::ServiceExt;
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

async fn send_json(
    router: &axum::Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let req_builder = Request::builder().method(method).uri(uri);
    let req = match body {
        Some(v) => req_builder
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&v).unwrap()))
            .unwrap(),
        None => req_builder.body(Body::empty()).unwrap(),
    };
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

async fn wait_for_webhook_requests(
    mock_server: &MockServer,
    expected_count: usize,
) -> Vec<wiremock::Request> {
    for _ in 0..80 {
        let reqs = mock_server.received_requests().await.unwrap_or_default();
        if reqs.len() >= expected_count {
            return reqs;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    mock_server.received_requests().await.unwrap_or_default()
}

#[tokio::test]
async fn sqlite_encrypts_send_as_and_inbox_rule_secrets_and_signs_webhooks() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("encrypted.db");
    let (_, k1) = generate_formatted_key("k1").unwrap();

    // First verify encryption_at_rest=false when disabled.
    let disabled_state = AppState::from_config(Config::for_test()).unwrap();
    let disabled_router = build_router(disabled_state);
    let (status, caps_off) =
        send_json(&disabled_router, Method::GET, "/v1/capabilities", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(caps_off["encryption_at_rest"], json!(false));

    // Now enable encryption at rest on SqliteStore.
    let mut cfg = Config {
        storage: StorageBackend::Sqlite,
        db_path: db_path.clone(),
        user_email: "agent@example.com".to_string(),
        default_domain: "example.com".to_string(),
        allow_private_endpoints: true,
        encryption_key: Some(k1),
        ..Config::default()
    };
    cfg.encryption_previous_keys.clear();

    let state = AppState::from_config(cfg).unwrap();
    let router = build_router(state.clone());

    let (status, caps_on) = send_json(&router, Method::GET, "/v1/capabilities", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(caps_on["encryption_at_rest"], json!(true));

    // 1. Create sendAs alias with SMTP password via Gmail REST API.
    let smtp_secret = "smtp-super-secret-password-991";
    let (status, created_sa) = send_json(
        &router,
        Method::POST,
        "/gmail/v1/users/me/settings/sendAs",
        Some(json!({
            "sendAsEmail": "billing@example.com",
            "displayName": "Billing",
            "smtpMsa": {
                "host": "smtp.example.com",
                "port": 587,
                "securityMode": "starttls",
                "username": "billing@example.com",
                "password": smtp_secret
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create sendAs: {created_sa}");
    assert!(created_sa["smtpMsa"].get("password").is_none());

    // 2. Create inbox rule with signed webhook via AI REST API.
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let webhook_url = format!("{}/hook", mock_server.uri());
    let webhook_secret = "whsec-rule-secret-456789";
    let (status, created_rule) = send_json(
        &router,
        Method::POST,
        "/v1/rules",
        Some(json!({
            "name": "Alert on invoices",
            "enabled": true,
            "match_query": "subject:invoice",
            "vip_only": false,
            "actions": {
                "add_labels": ["INVOICE"],
                "webhook_url": webhook_url,
                "webhook_secret": webhook_secret
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create rule: {created_rule}");
    assert_eq!(created_rule["actions"]["has_webhook_secret"], json!(true));
    assert!(created_rule["actions"].get("webhook_secret").is_none());

    // 3. Inspect raw SQLite rows directly and verify NO cleartext secrets exist on disk.
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let raw_send_as: String = conn
        .query_row(
            "SELECT value_json FROM settings WHERE mailbox_id = ?1 AND key = 'send_as'",
            ["agent@example.com"],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        raw_send_as.contains("enc:v1:k1:"),
        "raw send_as row must contain enc:v1:k1: envelope, got: {raw_send_as}"
    );
    assert!(
        !raw_send_as.contains(smtp_secret),
        "raw send_as row leaked plaintext password"
    );

    let raw_actions: String = conn
        .query_row(
            "SELECT actions_json FROM inbox_rules WHERE mailbox_id = ?1",
            ["agent@example.com"],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        raw_actions.contains("enc:v1:k1:"),
        "raw inbox_rules row must contain enc:v1:k1: envelope, got: {raw_actions}"
    );
    assert!(
        !raw_actions.contains(webhook_secret),
        "raw inbox_rules row leaked plaintext webhook_secret"
    );

    // 4. Verify decrypted settings helper recovers exact SMTP password.
    let decrypted_settings = state.get_decrypted_settings().await.unwrap();
    let billing = decrypted_settings
        .send_as
        .iter()
        .find(|s| s.send_as_email == "billing@example.com")
        .unwrap();
    assert_eq!(
        billing.smtp_msa.as_ref().unwrap().password.as_deref(),
        Some(smtp_secret)
    );

    // 5. Ingest inbound message matching the rule and prove HMAC-SHA256 matches plaintext secret.
    let raw_eml = build_rfc2822(&ComposeEmailInput {
        from: "vendor@acme.test".to_string(),
        to: vec!["agent@example.com".to_string()],
        subject: "Invoice #1042".to_string(),
        text: Some("Please pay invoice #1042.".to_string()),
        message_id: Some("<inv-1042@acme.test>".to_string()),
        ..Default::default()
    })
    .unwrap();

    let outcome = ingest_inbound_rfc2822_with_cipher(
        state.store.as_ref(),
        &state.events,
        state.filter.as_ref(),
        InboundEnvelope {
            raw_rfc2822: raw_eml,
            source: "resend_inbound".to_string(),
            default_labels: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            ..Default::default()
        },
        &state.config,
        state.cipher.as_ref(),
    )
    .await
    .unwrap();
    assert!(matches!(outcome, IngestOutcome::Stored { .. }));

    let reqs = wait_for_webhook_requests(&mock_server, 1).await;
    assert_eq!(reqs.len(), 1, "expected 1 signed webhook delivery");
    let got_sig = reqs[0]
        .headers
        .get(WEBHOOK_SIGNATURE_HEADER)
        .expect("missing X-Nogml-Signature header")
        .to_str()
        .unwrap();
    let expected_sig = compute_webhook_signature(webhook_secret, &reqs[0].body);
    assert_eq!(got_sig, expected_sig);
}

#[tokio::test]
async fn cli_generate_key_and_rotate_key_e2e_multi_mailbox() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("rotate.db");
    let k1_file = dir.path().join("key_k1");
    let k2_file = dir.path().join("key_k2");

    // 1. Generate k1 and k2 key files with `nogml crypto generate-key`.
    let out_k1 = clean_nogml_cmd()
        .args([
            "crypto",
            "generate-key",
            "--kid",
            "k1",
            "--output-file",
            k1_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out_k1.status.success(),
        "generate-key k1 failed: {}",
        String::from_utf8_lossy(&out_k1.stderr)
    );
    let stdout_k1 = String::from_utf8(out_k1.stdout).unwrap();
    let stderr_k1 = String::from_utf8(out_k1.stderr).unwrap();
    let json_k1: Value = serde_json::from_str(&stdout_k1).unwrap();
    assert_eq!(json_k1["ok"], json!(true));
    assert_eq!(json_k1["kid"], json!("k1"));
    assert!(json_k1["saved_to"].as_str().is_some());
    assert!(json_k1.get("key").is_none());

    let raw_k1 = fs::read_to_string(&k1_file).unwrap().trim().to_string();
    assert!(raw_k1.starts_with("k1:"));
    let raw_k1_secret = raw_k1.split_once(':').unwrap().1;
    assert!(!stdout_k1.contains(raw_k1_secret), "stdout leaked raw key");
    assert!(!stderr_k1.contains(raw_k1_secret), "stderr leaked raw key");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&k1_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "generated key file must have 0600 permissions");
    }

    let out_k2 = clean_nogml_cmd()
        .args([
            "crypto",
            "generate-key",
            "--kid",
            "k2",
            "--output-file",
            k2_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out_k2.status.success());
    let raw_k2 = fs::read_to_string(&k2_file).unwrap().trim().to_string();
    assert!(raw_k2.starts_with("k2:"));
    let raw_k2_secret = raw_k2.split_once(':').unwrap().1;

    // Also test generate-key without --output-file.
    let out_k3 = clean_nogml_cmd()
        .args(["crypto", "generate-key", "--kid", "k3"])
        .output()
        .unwrap();
    assert!(out_k3.status.success());
    let json_k3: Value = serde_json::from_slice(&out_k3.stdout).unwrap();
    assert_eq!(json_k3["ok"], json!(true));
    assert_eq!(json_k3["kid"], json!("k3"));
    assert!(json_k3["key"].as_str().unwrap().starts_with("k3:"));

    // 2. Seed two mailboxes in SQLite:
    //    - alice@example.com: secrets encrypted under k1
    //    - bob@example.com: legacy plaintext secrets (pre-encryption migration)
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/alice-hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/bob-hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let alice_smtp_pw = "alice-smtp-pw-001";
    let alice_wh_secret = "alice-webhook-secret-001";
    let bob_smtp_pw = "bob-legacy-smtp-pw-002";
    let bob_wh_secret = "bob-legacy-webhook-secret-002";

    {
        let cfg_k1 = Config {
            storage: StorageBackend::Sqlite,
            db_path: db_path.clone(),
            user_email: "alice@example.com".to_string(),
            mailboxes: vec!["bob@example.com".to_string()],
            default_domain: "example.com".to_string(),
            allow_private_endpoints: true,
            encryption_key: Some(raw_k1.clone()),
            ..Config::default()
        };
        let state_k1 = AppState::from_config(cfg_k1).unwrap();
        let router_k1 = build_router(state_k1.clone());

        // Write alice secrets through HTTP endpoints (encrypted under k1).
        let (st, _) = send_json(
            &router_k1,
            Method::POST,
            "/gmail/v1/users/me/settings/sendAs",
            Some(json!({
                "sendAsEmail": "alice-alias@example.com",
                "smtpMsa": {
                    "host": "smtp.example.com",
                    "port": 587,
                    "username": "alice",
                    "password": alice_smtp_pw
                }
            })),
        )
        .await;
        assert_eq!(st, StatusCode::OK);

        let (st, _) = send_json(
            &router_k1,
            Method::POST,
            "/v1/rules",
            Some(json!({
                "name": "Alice urgent",
                "enabled": true,
                "match_query": "subject:urgent",
                "vip_only": false,
                "actions": {
                    "webhook_url": format!("{}/alice-hook", mock_server.uri()),
                    "webhook_secret": alice_wh_secret
                }
            })),
        )
        .await;
        assert_eq!(st, StatusCode::OK);

        // Write bob secrets directly as legacy plaintext rows.
        let bob_state = state_k1.for_mailbox("bob@example.com");
        let mut bob_settings = bob_state.store.get_settings().await.unwrap();
        bob_settings.send_as.push(SendAs {
            send_as_email: "bob-alias@example.com".to_string(),
            smtp_msa: Some(SmtpMsa {
                host: "smtp.example.com".to_string(),
                port: 587,
                security_mode: Some("starttls".to_string()),
                username: Some("bob".to_string()),
                password: Some(bob_smtp_pw.to_string()),
            }),
            ..Default::default()
        });
        bob_state.store.save_settings(bob_settings).await.unwrap();
        bob_state
            .store
            .create_inbox_rule(&NewInboxRule {
                name: "Bob urgent".to_string(),
                enabled: true,
                match_query: "subject:urgent".to_string(),
                vip_only: false,
                actions: InboxRuleActions {
                    webhook_url: Some(format!("{}/bob-hook", mock_server.uri())),
                    webhook_secret: Some(bob_wh_secret.to_string()),
                    ..Default::default()
                },
            })
            .await
            .unwrap();
    }

    // 3. Create nogml.toml configured with primary = k2 and previous = [k1].
    let toml_path = dir.path().join("nogml.toml");
    let toml_content = format!(
        r#"
[storage]
backend = "sqlite"
db_path = "{}"

[auth]
user_email = "alice@example.com"
mailboxes = ["bob@example.com"]
default_domain = "example.com"

[safety]
allow_private_endpoints = true

[security]
encryption_key = "file://{}"
encryption_previous_keys = ["file://{}"]
"#,
        db_path.display(),
        k2_file.display(),
        k1_file.display()
    );
    fs::write(&toml_path, toml_content).unwrap();

    // 4. Verify `nogml config check` succeeds and redacts both encryption keys.
    let check_out = clean_nogml_cmd()
        .args(["config", "check", "--config", toml_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check_out.status.success(),
        "config check failed: {}",
        String::from_utf8_lossy(&check_out.stdout)
    );
    let check_stdout = String::from_utf8(check_out.stdout).unwrap();
    assert!(!check_stdout.contains(raw_k1_secret));
    assert!(!check_stdout.contains(raw_k2_secret));
    let check_json: Value = serde_json::from_str(&check_stdout).unwrap();
    assert_eq!(check_json["ok"], json!(true));
    assert_eq!(
        check_json["effective_config"]["security"]["encryption_at_rest"],
        json!(true)
    );
    assert_eq!(
        check_json["effective_config"]["security"]["encryption_key"],
        json!("[REDACTED]")
    );
    assert_eq!(
        check_json["effective_config"]["security"]["encryption_previous_keys"],
        json!(["[REDACTED]"])
    );

    // 5. Run `nogml crypto rotate-key --config <toml>`.
    let rotate_out = clean_nogml_cmd()
        .args([
            "crypto",
            "rotate-key",
            "--config",
            toml_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        rotate_out.status.success(),
        "rotate-key failed: {}",
        String::from_utf8_lossy(&rotate_out.stderr)
    );
    let rotate_json: Value = serde_json::from_slice(&rotate_out.stdout).unwrap();
    assert_eq!(rotate_json["ok"], json!(true));
    assert_eq!(rotate_json["primary_kid"], json!("k2"));
    assert_eq!(rotate_json["mailboxes_scanned"], json!(2));
    assert_eq!(rotate_json["send_as_rotated"], json!(2));
    assert_eq!(rotate_json["rules_rotated"], json!(2));

    // Re-running rotate-key should be a no-op (0 rotated).
    let rotate_again = clean_nogml_cmd()
        .args([
            "crypto",
            "rotate-key",
            "--config",
            toml_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(rotate_again.status.success());
    let rotate_again_json: Value = serde_json::from_slice(&rotate_again.stdout).unwrap();
    assert_eq!(rotate_again_json["send_as_rotated"], json!(0));
    assert_eq!(rotate_again_json["rules_rotated"], json!(0));

    // 6. Inspect raw SQLite rows: every row must now carry enc:v1:k2: (no k1, no plaintext).
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        for mb in ["alice@example.com", "bob@example.com"] {
            let raw_sa: String = conn
                .query_row(
                    "SELECT value_json FROM settings WHERE mailbox_id = ?1 AND key = 'send_as'",
                    [mb],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(
                raw_sa.contains("enc:v1:k2:"),
                "{mb} send_as not rotated to k2: {raw_sa}"
            );
            assert!(!raw_sa.contains("enc:v1:k1:"));
            assert!(!raw_sa.contains(alice_smtp_pw));
            assert!(!raw_sa.contains(bob_smtp_pw));

            let raw_rule: String = conn
                .query_row(
                    "SELECT actions_json FROM inbox_rules WHERE mailbox_id = ?1",
                    [mb],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(
                raw_rule.contains("enc:v1:k2:"),
                "{mb} inbox_rule not rotated to k2: {raw_rule}"
            );
            assert!(!raw_rule.contains("enc:v1:k1:"));
            assert!(!raw_rule.contains(alice_wh_secret));
            assert!(!raw_rule.contains(bob_wh_secret));
        }
    }

    // 7. Remove k1 completely and prove reads + signed webhooks succeed with ONLY k2!
    let cfg_k2_only = Config {
        storage: StorageBackend::Sqlite,
        db_path: db_path.clone(),
        user_email: "alice@example.com".to_string(),
        mailboxes: vec!["bob@example.com".to_string()],
        default_domain: "example.com".to_string(),
        allow_private_endpoints: true,
        encryption_key: Some(raw_k2),
        encryption_previous_keys: vec![],
        ..Config::default()
    };
    let state_k2 = AppState::from_config(cfg_k2_only).unwrap();

    let alice_decrypted = state_k2.get_decrypted_settings().await.unwrap();
    let alice_alias = alice_decrypted
        .send_as
        .iter()
        .find(|s| s.send_as_email == "alice-alias@example.com")
        .unwrap();
    assert_eq!(
        alice_alias.smtp_msa.as_ref().unwrap().password.as_deref(),
        Some(alice_smtp_pw)
    );

    let bob_state_k2 = state_k2.for_mailbox("bob@example.com");
    let bob_decrypted = bob_state_k2.get_decrypted_settings().await.unwrap();
    let bob_alias = bob_decrypted
        .send_as
        .iter()
        .find(|s| s.send_as_email == "bob-alias@example.com")
        .unwrap();
    assert_eq!(
        bob_alias.smtp_msa.as_ref().unwrap().password.as_deref(),
        Some(bob_smtp_pw)
    );

    // Trigger rules for both alice and bob and verify exact HMAC-SHA256 signatures.
    for (mb_state, recipient, msg_id) in [
        (&state_k2, "alice@example.com", "<urgent-a@acme.test>"),
        (&bob_state_k2, "bob@example.com", "<urgent-b@acme.test>"),
    ] {
        let raw_eml = build_rfc2822(&ComposeEmailInput {
            from: "ops@acme.test".to_string(),
            to: vec![recipient.to_string()],
            subject: "Urgent incident".to_string(),
            text: Some("Immediate action required.".to_string()),
            message_id: Some(msg_id.to_string()),
            ..Default::default()
        })
        .unwrap();

        let outcome = ingest_inbound_rfc2822_with_cipher(
            mb_state.store.as_ref(),
            &mb_state.events,
            mb_state.filter.as_ref(),
            InboundEnvelope {
                raw_rfc2822: raw_eml,
                source: "resend_inbound".to_string(),
                default_labels: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
                ..Default::default()
            },
            &mb_state.config,
            mb_state.cipher.as_ref(),
        )
        .await
        .unwrap();
        assert!(matches!(outcome, IngestOutcome::Stored { .. }));
    }

    let reqs = wait_for_webhook_requests(&mock_server, 2).await;
    assert_eq!(reqs.len(), 2, "expected webhooks for both mailboxes");
    for req in &reqs {
        let sig = req
            .headers
            .get(WEBHOOK_SIGNATURE_HEADER)
            .expect("missing signature")
            .to_str()
            .unwrap();
        let expected_secret = match req.url.path() {
            "/alice-hook" => alice_wh_secret,
            "/bob-hook" => bob_wh_secret,
            other => panic!("unexpected path {other}"),
        };
        assert_eq!(sig, compute_webhook_signature(expected_secret, &req.body));
    }
}

#[tokio::test]
async fn invalid_key_fails_fast_and_wrong_key_fails_closed_on_webhook() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("failclosed.db");

    // 1. AppState::from_config rejects invalid key material.
    let mut bad_cfg = Config::for_test();
    bad_cfg.encryption_key = Some("k1:not-32-bytes".to_string());
    let err = match AppState::from_config(bad_cfg) {
        Ok(_) => panic!("expected invalid encryption key error"),
        Err(e) => e,
    };
    assert!(matches!(err, AppError::Config(_)));

    // 2. `nogml config check` exits 2 on invalid key.
    let bad_check = clean_nogml_cmd()
        .env("NOGML_ENCRYPTION_KEY", "k1:short")
        .args(["config", "check"])
        .output()
        .unwrap();
    assert_eq!(bad_check.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&bad_check.stdout).unwrap();
    assert_eq!(report["ok"], json!(false));

    // 3. `nogml crypto rotate-key` exits 2 when encryption is disabled.
    let no_key_rotate = clean_nogml_cmd()
        .args([
            "crypto",
            "rotate-key",
            "--db-path",
            db_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(no_key_rotate.status.code(), Some(2));

    // 4. Rule encrypted under k1 must NOT fire an unsigned webhook when opened with only k2.
    let (_, k1) = generate_formatted_key("k1").unwrap();
    let (_, k2) = generate_formatted_key("k2").unwrap();
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/closed-hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    {
        let cfg1 = Config {
            storage: StorageBackend::Sqlite,
            db_path: db_path.clone(),
            user_email: "agent@example.com".to_string(),
            default_domain: "example.com".to_string(),
            allow_private_endpoints: true,
            encryption_key: Some(k1),
            ..Config::default()
        };
        let state1 = AppState::from_config(cfg1).unwrap();
        let router1 = build_router(state1);
        let (st, _) = send_json(
            &router1,
            Method::POST,
            "/v1/rules",
            Some(json!({
                "name": "Signed only",
                "enabled": true,
                "match_query": "subject:secret-test",
                "vip_only": false,
                "actions": {
                    "webhook_url": format!("{}/closed-hook", mock_server.uri()),
                    "webhook_secret": "must-not-downgrade-to-unsigned"
                }
            })),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
    }

    let cfg2 = Config {
        storage: StorageBackend::Sqlite,
        db_path: db_path.clone(),
        user_email: "agent@example.com".to_string(),
        default_domain: "example.com".to_string(),
        allow_private_endpoints: true,
        encryption_key: Some(k2),
        ..Config::default()
    };
    let state2 = AppState::from_config(cfg2).unwrap();
    let raw_eml = build_rfc2822(&ComposeEmailInput {
        from: "sender@acme.test".to_string(),
        to: vec!["agent@example.com".to_string()],
        subject: "secret-test payload".to_string(),
        text: Some("Body".to_string()),
        message_id: Some("<closed-1@acme.test>".to_string()),
        ..Default::default()
    })
    .unwrap();

    // Ingestion must still succeed, but webhook must NOT be delivered unsigned.
    let outcome = ingest_inbound_rfc2822_with_cipher(
        state2.store.as_ref(),
        &state2.events,
        state2.filter.as_ref(),
        InboundEnvelope {
            raw_rfc2822: raw_eml,
            source: "resend_inbound".to_string(),
            default_labels: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            ..Default::default()
        },
        &state2.config,
        state2.cipher.as_ref(),
    )
    .await
    .unwrap();
    assert!(matches!(outcome, IngestOutcome::Stored { .. }));

    tokio::time::sleep(Duration::from_millis(150)).await;
    let reqs = mock_server.received_requests().await.unwrap_or_default();
    assert!(
        reqs.is_empty(),
        "webhook must fail closed and not fire unsigned when secret decryption fails"
    );
}

#[tokio::test]
async fn put_patch_send_as_and_patch_rule_encrypt_updated_secrets_and_env_file_works() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("patch_enc.db");
    let (_, k1) = generate_formatted_key("k1").unwrap();
    let (_, k2) = generate_formatted_key("k2").unwrap();

    // Verify NOGML_ENCRYPTION_KEY_FILE and NOGML_ENCRYPTION_PREVIOUS_KEYS_FILE via `nogml config check`.
    let k1_file = dir.path().join("env_k1");
    let k2_file = dir.path().join("env_k2");
    nogml::secrets::write_secret_file(&k1_file, &k1, false).unwrap();
    nogml::secrets::write_secret_file(&k2_file, &k2, false).unwrap();

    let check_out = clean_nogml_cmd()
        .env("NOGML_ENCRYPTION_KEY_FILE", k2_file.to_str().unwrap())
        .env(
            "NOGML_ENCRYPTION_PREVIOUS_KEYS_FILE",
            k1_file.to_str().unwrap(),
        )
        .args(["config", "check"])
        .output()
        .unwrap();
    assert!(
        check_out.status.success(),
        "env-file config check failed: {}",
        String::from_utf8_lossy(&check_out.stdout)
    );
    let check_json: Value = serde_json::from_slice(&check_out.stdout).unwrap();
    assert_eq!(check_json["ok"], json!(true));
    assert_eq!(
        check_json["effective_config"]["security"]["encryption_at_rest"],
        json!(true)
    );
    assert_eq!(
        check_json["effective_config"]["security"]["encryption_key"],
        json!("[REDACTED]")
    );
    assert_eq!(
        check_json["effective_config"]["security"]["encryption_previous_keys"],
        json!(["[REDACTED]"])
    );

    // Test PUT and PATCH on sendAs + PATCH on inbox rule.
    let cfg = Config {
        storage: StorageBackend::Sqlite,
        db_path: db_path.clone(),
        user_email: "agent@example.com".to_string(),
        default_domain: "example.com".to_string(),
        allow_private_endpoints: true,
        encryption_key: Some(k1),
        ..Config::default()
    };
    let state = AppState::from_config(cfg).unwrap();
    let router = build_router(state.clone());

    // Create, PUT, and PATCH sendAs with distinct passwords.
    let (st, _) = send_json(
        &router,
        Method::POST,
        "/gmail/v1/users/me/settings/sendAs",
        Some(json!({
            "sendAsEmail": "ops@example.com",
            "smtpMsa": { "host": "smtp.example.com", "port": 587, "password": "pw-initial" }
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, _) = send_json(
        &router,
        Method::PUT,
        "/gmail/v1/users/me/settings/sendAs/ops@example.com",
        Some(json!({
            "sendAsEmail": "ops@example.com",
            "smtpMsa": { "host": "smtp.example.com", "port": 587, "password": "pw-after-put" }
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, _) = send_json(
        &router,
        Method::PATCH,
        "/gmail/v1/users/me/settings/sendAs/ops@example.com",
        Some(json!({
            "smtpMsa": { "host": "smtp.example.com", "port": 587, "password": "pw-after-patch" }
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // Create rule and PATCH its webhook_secret.
    let (st, created) = send_json(
        &router,
        Method::POST,
        "/v1/rules",
        Some(json!({
            "name": "Ops hook",
            "enabled": true,
            "match_query": "subject:ops",
            "vip_only": false,
            "actions": {
                "webhook_url": "http://127.0.0.1:19999/hook",
                "webhook_secret": "rule-sec-v1"
            }
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let rule_id = created["id"].as_str().unwrap();

    let (st, _) = send_json(
        &router,
        Method::PATCH,
        &format!("/v1/rules/{rule_id}"),
        Some(json!({
            "actions": {
                "webhook_url": "http://127.0.0.1:19999/hook",
                "webhook_secret": "rule-sec-v2"
            }
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // Raw SQLite must have enc:v1:k1: and zero plaintext.
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let raw_sa: String = conn
        .query_row(
            "SELECT value_json FROM settings WHERE mailbox_id = ?1 AND key = 'send_as'",
            ["agent@example.com"],
            |r| r.get(0),
        )
        .unwrap();
    assert!(raw_sa.contains("enc:v1:k1:"));
    assert!(!raw_sa.contains("pw-after-patch"));

    let raw_rule: String = conn
        .query_row(
            "SELECT actions_json FROM inbox_rules WHERE mailbox_id = ?1 AND id = ?2",
            ["agent@example.com", rule_id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(raw_rule.contains("enc:v1:k1:"));
    assert!(!raw_rule.contains("rule-sec-v2"));

    // Decrypted values match latest PATCHed secrets.
    let decrypted = state.get_decrypted_settings().await.unwrap();
    let ops = decrypted
        .send_as
        .iter()
        .find(|s| s.send_as_email == "ops@example.com")
        .unwrap();
    assert_eq!(
        ops.smtp_msa.as_ref().unwrap().password.as_deref(),
        Some("pw-after-patch")
    );
    let stored_rule = state.store.get_inbox_rule(rule_id).await.unwrap().unwrap();
    assert_eq!(
        state
            .cipher
            .decrypt(stored_rule.actions.webhook_secret.as_deref().unwrap())
            .unwrap(),
        "rule-sec-v2"
    );
}

#[tokio::test]
async fn strict_encryption_rejects_legacy_plaintext_until_rotated_and_disabled_rejects_enc_prefix()
{
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("strict.db");

    // 1. Disabled mode rejects creating a webhook_secret starting with reserved `enc:v1:` prefix
    {
        let cfg = Config {
            storage: StorageBackend::Sqlite,
            db_path: db_path.clone(),
            user_email: "agent@example.com".to_string(),
            default_domain: "example.com".to_string(),
            allow_private_endpoints: true,
            ..Config::default()
        };
        let state = AppState::from_config(cfg).unwrap();
        let router = build_router(state);
        let (st, _) = send_json(
            &router,
            Method::POST,
            "/v1/rules",
            Some(json!({
                "name": "bad-prefix",
                "match_query": "from:test@example.com",
                "actions": {
                    "webhook_url": "http://127.0.0.1:19999/hook",
                    "webhook_secret": "enc:v1:k1:forged:payload"
                }
            })),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    // 2. Seed a legacy plaintext send_as row in a non-meta mailbox directly in SQLite
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let send_as_json = serde_json::to_string(&vec![nogml::models::SendAs {
            send_as_email: "legacy@example.com".to_string(),
            display_name: None,
            reply_to_address: None,
            signature: None,
            is_primary: Some(true),
            is_default: Some(true),
            treat_as_alias: Some(false),
            verification_status: Some("accepted".to_string()),
            smtp_msa: Some(nogml::models::SmtpMsa {
                host: "smtp.example.com".to_string(),
                port: 587,
                security_mode: Some("starttls".to_string()),
                username: Some("legacy".to_string()),
                password: Some("legacy-unencrypted-pw".to_string()),
            }),
        }])
        .unwrap();
        conn.execute(
            "INSERT INTO settings (mailbox_id, key, value_json) VALUES (?1, 'send_as', ?2)",
            ["legacy@example.com", send_as_json.as_str()],
        )
        .unwrap();
    }

    let (_, k1) = generate_formatted_key("k1").unwrap();

    // 3. With encryption_strict = true BEFORE rotation, reading legacy plaintext fails
    {
        let cfg = Config {
            storage: StorageBackend::Sqlite,
            db_path: db_path.clone(),
            user_email: "agent@example.com".to_string(),
            default_domain: "example.com".to_string(),
            encryption_key: Some(k1.clone()),
            encryption_strict: true,
            ..Config::default()
        };
        let state = AppState::from_config(cfg).unwrap();
        let err = state
            .for_mailbox("legacy@example.com")
            .get_decrypted_settings()
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Config(_)));
        assert!(err.to_string().contains("encryption_strict"));
    }

    // 4. Run `nogml crypto rotate-key` (with strict=false); non-meta settings mailbox is discovered & rotated
    let rotate_out = clean_nogml_cmd()
        .env("NOGML_ENCRYPTION_KEY", &k1)
        .args([
            "crypto",
            "rotate-key",
            "--db-path",
            db_path.to_str().unwrap(),
            "--user-email",
            "agent@example.com",
        ])
        .output()
        .unwrap();
    assert!(
        rotate_out.status.success(),
        "rotate-key failed: {}",
        String::from_utf8_lossy(&rotate_out.stderr)
    );
    let report: Value = serde_json::from_slice(&rotate_out.stdout).unwrap();
    assert_eq!(report["ok"], json!(true));
    assert_eq!(report["send_as_rotated"], json!(1));

    // 5. Now with encryption_strict = true, reading succeeds
    {
        let cfg = Config {
            storage: StorageBackend::Sqlite,
            db_path: db_path.clone(),
            user_email: "agent@example.com".to_string(),
            default_domain: "example.com".to_string(),
            encryption_key: Some(k1.clone()),
            encryption_strict: true,
            ..Config::default()
        };
        let state = AppState::from_config(cfg).unwrap();
        let decrypted = state
            .for_mailbox("legacy@example.com")
            .get_decrypted_settings()
            .await
            .unwrap();
        assert_eq!(
            decrypted.send_as[0]
                .smtp_msa
                .as_ref()
                .unwrap()
                .password
                .as_deref(),
            Some("legacy-unencrypted-pw")
        );
    }

    // 6. `nogml config check` with NOGML_ENCRYPTION_STRICT=true and no key fails with exit 2
    let bad_strict = clean_nogml_cmd()
        .env("NOGML_ENCRYPTION_STRICT", "true")
        .args(["config", "check"])
        .output()
        .unwrap();
    assert_eq!(bad_strict.status.code(), Some(2));
    let check_json: Value = serde_json::from_slice(&bad_strict.stdout).unwrap();
    assert_eq!(check_json["ok"], json!(false));
}
