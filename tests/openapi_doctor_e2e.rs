//! End-to-end tests for:
//! - `GET /v1/openapi.json` and `nogml schema --openapi`
//! - `nogml doctor [--config <PATH>]`
//! - `nogml completions <bash|zsh|fish|elvish|powershell>`

use std::{fs, path::Path, process::Command};

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use chrono::{Datelike, Duration, Utc};
use http_body_util::BodyExt;
use rcgen::{CertificateParams, KeyPair, date_time_ymd};
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

use nogml::{
    AppState,
    ai::V1_OPENAPI_OPERATIONS,
    auth::{AuthScope, ScopedTokenConfig},
    build_router,
    config::Config,
    resend::HttpResendClient,
    secrets::write_secret_file,
    storage::MemoryStore,
};

fn nogml_bin() -> &'static str {
    env!("CARGO_BIN_EXE_nogml")
}

async fn http_json(
    app: &axum::Router,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(tok) = bearer {
        builder = builder.header("authorization", format!("Bearer {tok}"));
    }
    let req = builder.body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

fn write_self_signed_cert(
    dir: &Path,
    prefix: &str,
    days_from_now_start: i64,
    days_from_now_end: i64,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let now = Utc::now();
    let nb = now + Duration::days(days_from_now_start);
    let na = now + Duration::days(days_from_now_end);

    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.not_before = date_time_ymd(nb.year(), nb.month() as u8, nb.day() as u8);
    params.not_after = date_time_ymd(na.year(), na.month() as u8, na.day() as u8);
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();

    let cert_path = dir.join(format!("{prefix}.crt"));
    let key_path = dir.join(format!("{prefix}.key"));
    fs::write(&cert_path, cert.pem()).unwrap();
    write_secret_file(&key_path, &key_pair.serialize_pem(), true).unwrap();
    (cert_path, key_path)
}

#[tokio::test]
async fn openapi_endpoint_and_cli_cover_all_v1_routes() {
    let mut cfg = Config::for_test();
    cfg.scoped_tokens = vec![ScopedTokenConfig {
        token: "ro_openapi_token".to_string(),
        mailbox_id: Some(cfg.user_email.clone()),
        scopes: vec![AuthScope::Read],
        draft_only: None,
        allowed_recipients: None,
        max_send_recipients: None,
    }];
    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store, resend);
    let app = build_router(state);

    // 1. Unauthenticated request is rejected like /v1/capabilities.
    let (status, _) = http_json(&app, Method::GET, "/v1/openapi.json", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 2. Read-scoped token fetches OpenAPI 3.1.0 spec.
    let (status, spec) = http_json(
        &app,
        Method::GET,
        "/v1/openapi.json",
        Some("ro_openapi_token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(spec["openapi"], "3.1.0");
    assert!(spec["info"]["title"].is_string());

    let paths = spec["paths"].as_object().expect("paths object");
    let schemas = spec["components"]["schemas"]
        .as_object()
        .expect("components.schemas object");
    let security_schemes = spec["components"]["securitySchemes"]
        .as_object()
        .expect("components.securitySchemes object");

    for scheme in ["bearerAuth", "apiKeyHeader", "oauth2"] {
        assert!(
            security_schemes.contains_key(scheme),
            "missing securityScheme '{scheme}'"
        );
    }

    for schema_name in [
        "AiErrorEnvelope",
        "CompactMessage",
        "ThreadSummary",
        "ThreadDetail",
        "BriefingResponse",
        "ReplyContextResponse",
    ] {
        assert!(
            schemas.contains_key(schema_name),
            "missing component schema '{schema_name}'"
        );
    }

    // 3. Every endpoint advertised by GET /v1/capabilities is present in OpenAPI paths.
    let (caps_status, caps) = http_json(
        &app,
        Method::GET,
        "/v1/capabilities",
        Some("ro_openapi_token"),
    )
    .await;
    assert_eq!(caps_status, StatusCode::OK);
    let advertised = caps["endpoints"].as_array().expect("endpoints array");
    assert!(
        advertised
            .iter()
            .any(|v| v.as_str() == Some("GET /v1/openapi.json")),
        "GET /v1/openapi.json should be listed in /v1/capabilities"
    );
    for entry in advertised {
        let s = entry.as_str().expect("endpoint string");
        let (method, path) = s.split_once(' ').expect("METHOD /path");
        let lower_method = method.to_ascii_lowercase();
        let path_obj = paths
            .get(path)
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("OpenAPI missing path '{path}' from /v1/capabilities"));
        assert!(
            path_obj.contains_key(&lower_method),
            "OpenAPI missing method '{lower_method}' on path '{path}'"
        );
    }

    // 4. Every canonical /v1/* operation is present.
    for &(method, path) in V1_OPENAPI_OPERATIONS {
        assert!(
            paths.get(path).and_then(|p| p.get(method)).is_some(),
            "OpenAPI missing {method} {path}"
        );
    }

    // 5. `nogml schema --openapi` prints the identical OpenAPI 3.1.0 document.
    let output = Command::new(nogml_bin())
        .args(["schema", "--openapi"])
        .output()
        .expect("run nogml schema --openapi");
    assert!(
        output.status.success(),
        "nogml schema --openapi failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cli_spec: Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON from nogml schema --openapi");
    assert_eq!(cli_spec, spec);
}

#[test]
fn doctor_healthy_sqlite_fs_config_exits_0_and_never_leaks_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("nogml.db");
    let blob_dir = dir.path().join("blobs");
    let auth_secret_path = dir.path().join("auth_token");
    let resend_secret_path = dir.path().join("resend_key");

    let auth_secret = "nogml_doctor_auth_secret_value_abc123";
    let resend_secret = "re_doctor_resend_secret_value_xyz789";
    write_secret_file(&auth_secret_path, auth_secret, true).unwrap();
    write_secret_file(&resend_secret_path, resend_secret, true).unwrap();
    let (cert_path, key_path) = write_self_signed_cert(dir.path(), "valid", -1, 180);

    let config_path = dir.path().join("nogml.toml");
    let toml_body = format!(
        r#"[storage]
backend = "sqlite"
db_path = "{}"

[blob]
backend = "fs"
dir = "{}"

[auth]
user_email = "agent@example.com"
default_domain = "example.com"
tokens = ["file://{}"]

[transport]
backend = "resend"

[resend]
api_key = "file://{}"

[imap]
tls_cert = "{}"
tls_key = "{}"
"#,
        db_path.display(),
        blob_dir.display(),
        auth_secret_path.display(),
        resend_secret_path.display(),
        cert_path.display(),
        key_path.display(),
    );
    fs::write(&config_path, toml_body).unwrap();

    let output = Command::new(nogml_bin())
        .args(["doctor", "--config", config_path.to_str().unwrap()])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .output()
        .expect("run nogml doctor");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "expected exit 0, stdout={stdout}, stderr={stderr}"
    );
    assert!(
        !stdout.contains(auth_secret),
        "auth secret leaked to stdout"
    );
    assert!(
        !stderr.contains(auth_secret),
        "auth secret leaked to stderr"
    );
    assert!(
        !stdout.contains(resend_secret),
        "resend secret leaked to stdout"
    );
    assert!(
        !stderr.contains(resend_secret),
        "resend secret leaked to stderr"
    );

    let report: Value = serde_json::from_str(&stdout).expect("valid JSON report");
    assert_eq!(report["ok"], true);
    assert_eq!(report["summary"]["fail"], 0);
    assert_eq!(report["summary"]["warn"], 0);
    assert_eq!(report["summary"]["pass"], 7);

    let checks = report["checks"].as_array().expect("checks array");
    for expected_name in [
        "config",
        "secret_permissions",
        "storage",
        "blobs",
        "imap_tls",
        "transport",
        "security_posture",
    ] {
        let check = checks
            .iter()
            .find(|c| c["name"] == expected_name)
            .unwrap_or_else(|| panic!("missing check '{expected_name}'"));
        assert_eq!(check["status"], "pass", "check '{expected_name}': {check}");
    }
}

#[cfg(unix)]
#[test]
fn doctor_warns_on_open_dev_mode_permissive_secret_and_expiring_tls_cert() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("nogml.db");
    let blob_dir = dir.path().join("blobs");
    let resend_secret_path = dir.path().join("resend_open_key");
    let resend_secret = "re_open_mode_secret_should_never_print";
    fs::write(&resend_secret_path, format!("{resend_secret}\n")).unwrap();
    fs::set_permissions(&resend_secret_path, fs::Permissions::from_mode(0o644)).unwrap();

    // Cert expiring in 10 days (< 30 day threshold -> warn)
    let (cert_path, key_path) = write_self_signed_cert(dir.path(), "expiring", -1, 10);

    let config_path = dir.path().join("nogml.toml");
    let toml_body = format!(
        r#"[storage]
backend = "sqlite"
db_path = "{}"

[blob]
backend = "fs"
dir = "{}"

[auth]
user_email = "dev@example.com"

[resend]
api_key = "file://{}"

[safety]
allow_insecure_webhooks = true
allow_private_endpoints = true

[imap]
tls_cert = "{}"
tls_key = "{}"
"#,
        db_path.display(),
        blob_dir.display(),
        resend_secret_path.display(),
        cert_path.display(),
        key_path.display(),
    );
    fs::write(&config_path, toml_body).unwrap();

    let output = Command::new(nogml_bin())
        .args(["doctor", "--config", config_path.to_str().unwrap()])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .output()
        .expect("run nogml doctor");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "warnings alone must exit 0; stdout={stdout}, stderr={stderr}"
    );
    assert!(!stdout.contains(resend_secret));
    assert!(!stderr.contains(resend_secret));

    let report: Value = serde_json::from_str(&stdout).expect("valid JSON report");
    assert_eq!(report["ok"], true);
    assert_eq!(report["summary"]["fail"], 0);
    assert!(report["summary"]["warn"].as_u64().unwrap() >= 3);

    let checks = report["checks"].as_array().unwrap();
    let find = |name: &str| checks.iter().find(|c| c["name"] == name).unwrap();

    assert_eq!(find("secret_permissions")["status"], "warn");
    assert!(
        find("secret_permissions")["detail"]
            .as_str()
            .unwrap()
            .contains("0644")
    );
    assert_eq!(find("security_posture")["status"], "warn");
    let posture_detail = find("security_posture")["detail"].as_str().unwrap();
    assert!(posture_detail.contains("Open dev mode"));
    assert!(posture_detail.contains("allow_insecure_webhooks"));
    assert!(posture_detail.contains("allow_private_endpoints"));

    assert_eq!(find("imap_tls")["status"], "warn");
    assert!(
        find("imap_tls")["detail"]
            .as_str()
            .unwrap()
            .contains("expires in")
    );
}

#[test]
fn doctor_exits_2_on_invalid_tls_cert_expired_cert_and_broken_toml() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("nogml.db");

    // 1. Non-existent TLS cert path -> exit 2 with imap_tls=fail
    let missing_cert_cfg = dir.path().join("bad_tls.toml");
    fs::write(
        &missing_cert_cfg,
        format!(
            r#"[storage]
backend = "sqlite"
db_path = "{}"

[imap]
tls_cert = "{}"
tls_key = "{}"
"#,
            db_path.display(),
            dir.path().join("missing.crt").display(),
            dir.path().join("missing.key").display(),
        ),
    )
    .unwrap();

    let output = Command::new(nogml_bin())
        .args(["doctor", "--config", missing_cert_cfg.to_str().unwrap()])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .output()
        .expect("run nogml doctor on invalid TLS cert");
    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(report["ok"], false);
    assert!(report["summary"]["fail"].as_u64().unwrap() >= 1);
    let imap_check = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "imap_tls")
        .unwrap();
    assert_eq!(imap_check["status"], "fail");

    // 2. Expired TLS cert -> exit 2 with imap_tls=fail
    let (exp_cert, exp_key) = write_self_signed_cert(dir.path(), "expired", -30, -2);
    let expired_cfg = dir.path().join("expired_tls.toml");
    fs::write(
        &expired_cfg,
        format!(
            r#"[storage]
backend = "sqlite"
db_path = "{}"

[imap]
tls_cert = "{}"
tls_key = "{}"
"#,
            db_path.display(),
            exp_cert.display(),
            exp_key.display(),
        ),
    )
    .unwrap();

    let output = Command::new(nogml_bin())
        .args(["doctor", "--config", expired_cfg.to_str().unwrap()])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .output()
        .expect("run nogml doctor on expired TLS cert");
    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(report["ok"], false);
    let imap_check = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "imap_tls")
        .unwrap();
    assert_eq!(imap_check["status"], "fail");
    assert!(imap_check["detail"].as_str().unwrap().contains("expired"));

    // 3. Syntactically invalid TOML -> exit 2 with config=fail
    let bad_toml = dir.path().join("broken.toml");
    fs::write(&bad_toml, "[storage\nbackend = \"sqlite\"").unwrap();
    let output = Command::new(nogml_bin())
        .args(["doctor", "--config", bad_toml.to_str().unwrap()])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .output()
        .expect("run nogml doctor on broken TOML");
    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(report["ok"], false);
    assert_eq!(report["checks"][0]["name"], "config");
    assert_eq!(report["checks"][0]["status"], "fail");
}

#[test]
fn completions_outputs_valid_scripts_for_all_supported_shells() {
    for shell in ["zsh", "bash", "fish", "elvish", "powershell"] {
        let output = Command::new(nogml_bin())
            .args(["completions", shell])
            .output()
            .unwrap_or_else(|e| panic!("failed to run nogml completions {shell}: {e}"));
        assert!(
            output.status.success(),
            "nogml completions {shell} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let script = String::from_utf8(output.stdout).expect("valid UTF-8 completion script");
        assert!(
            !script.trim().is_empty(),
            "completion script for {shell} must not be empty"
        );
        assert!(
            script.contains("nogml"),
            "completion script for {shell} should mention nogml"
        );
        assert!(
            script.contains("doctor") && script.contains("completions"),
            "completion script for {shell} should include new subcommands"
        );
    }
}
