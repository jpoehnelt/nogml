use std::{
    collections::HashMap,
    process::Command,
    sync::{Arc, RwLock},
};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use nogml::{
    AppState,
    blob::{
        BlobStore, FsBlobStore, InlineBlobStore, S3BlobConfig, S3BlobStore, attachment_blob_key,
        migrate_blobs, raw_message_blob_key,
    },
    build_router,
    config::{BlobBackend, Config},
    mime,
    models::{LABEL_INBOX, LABEL_TRASH},
    storage::{MailStore, NewAttachmentInput, NewMessageInput, SqliteStore},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, Request as WireRequest, Respond, ResponseTemplate,
    matchers::{any, header_exists, method, path},
};

fn sha256_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Stateful in-memory S3 mock responder for `wiremock` that enforces SigV4 headers
/// and handles `PUT`, `GET`, and `DELETE` on any object path.
#[derive(Clone, Default)]
struct MockS3Responder {
    objects: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    auth_headers: Arc<RwLock<Vec<String>>>,
}

impl MockS3Responder {
    fn new() -> Self {
        Self::default()
    }

    fn snapshot(&self) -> HashMap<String, Vec<u8>> {
        self.objects.read().unwrap().clone()
    }

    fn auth_headers(&self) -> Vec<String> {
        self.auth_headers.read().unwrap().clone()
    }
}

impl Respond for MockS3Responder {
    fn respond(&self, request: &WireRequest) -> ResponseTemplate {
        // Every S3 request must carry valid SigV4 headers.
        let Some(auth) = request
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
        else {
            return ResponseTemplate::new(403).set_body_string("Missing Authorization header");
        };
        if !auth.starts_with("AWS4-HMAC-SHA256 Credential=")
            || !auth.contains("/s3/aws4_request, SignedHeaders=")
            || !auth.contains(", Signature=")
        {
            return ResponseTemplate::new(403)
                .set_body_string(format!("Invalid SigV4 Authorization header: {auth}"));
        }

        let Some(payload_hash) = request
            .headers
            .get("x-amz-content-sha256")
            .and_then(|v| v.to_str().ok())
        else {
            return ResponseTemplate::new(400).set_body_string("Missing x-amz-content-sha256");
        };
        let expected_hash = sha256_hex(&request.body);
        if payload_hash != expected_hash {
            return ResponseTemplate::new(400).set_body_string(format!(
                "Payload hash mismatch: header={payload_hash} actual={expected_hash}"
            ));
        }

        if request.headers.get("x-amz-date").is_none() {
            return ResponseTemplate::new(400).set_body_string("Missing x-amz-date");
        }

        self.auth_headers.write().unwrap().push(auth.to_string());

        let key = request.url.path().to_string();
        match request.method.as_str() {
            "PUT" => {
                self.objects
                    .write()
                    .unwrap()
                    .insert(key, request.body.clone());
                ResponseTemplate::new(200)
            }
            "GET" => match self.objects.read().unwrap().get(&key).cloned() {
                Some(bytes) => ResponseTemplate::new(200).set_body_bytes(bytes),
                None => ResponseTemplate::new(404).set_body_string("NoSuchKey"),
            },
            "DELETE" => {
                self.objects.write().unwrap().remove(&key);
                ResponseTemplate::new(204)
            }
            other => ResponseTemplate::new(405).set_body_string(format!("Unsupported {other}")),
        }
    }
}

#[tokio::test]
async fn s3_blob_store_put_get_delete_404_and_sigv4_headers() {
    let server = MockServer::start().await;
    let payload = b"raw-rfc2822-email-content";
    let payload_hash = sha256_hex(payload);
    let empty_hash = sha256_hex(b"");

    // PUT returns 200 and verifies SigV4 headers + session token
    Mock::given(method("PUT"))
        .and(path("/mail-bucket/prod/messages/msg_1/raw.eml"))
        .and(header_exists("authorization"))
        .and(header_exists("x-amz-date"))
        .and(wiremock::matchers::header(
            "x-amz-content-sha256",
            payload_hash.as_str(),
        ))
        .and(wiremock::matchers::header(
            "x-amz-security-token",
            "temp-sts-token",
        ))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    // GET existing returns 200 with bytes
    Mock::given(method("GET"))
        .and(path("/mail-bucket/prod/messages/msg_1/raw.eml"))
        .and(wiremock::matchers::header(
            "x-amz-content-sha256",
            empty_hash.as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(payload.to_vec()))
        .expect(1)
        .mount(&server)
        .await;

    // GET missing returns 404 -> Ok(None)
    Mock::given(method("GET"))
        .and(path("/mail-bucket/prod/messages/missing/raw.eml"))
        .respond_with(ResponseTemplate::new(404).set_body_string("NoSuchKey"))
        .expect(1)
        .mount(&server)
        .await;

    // DELETE existing returns 204 -> Ok(())
    Mock::given(method("DELETE"))
        .and(path("/mail-bucket/prod/messages/msg_1/raw.eml"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    // DELETE missing returns 404 -> Ok(())
    Mock::given(method("DELETE"))
        .and(path("/mail-bucket/prod/messages/missing/raw.eml"))
        .respond_with(ResponseTemplate::new(404).set_body_string("NoSuchKey"))
        .expect(1)
        .mount(&server)
        .await;

    // GET server error returns 500 -> Err
    Mock::given(method("GET"))
        .and(path("/mail-bucket/prod/messages/err/raw.eml"))
        .respond_with(ResponseTemplate::new(500).set_body_string("InternalError"))
        .expect(1)
        .mount(&server)
        .await;

    let store = S3BlobStore::new(S3BlobConfig {
        bucket: "mail-bucket".to_string(),
        region: "auto".to_string(),
        endpoint_url: Some(server.uri()),
        key_prefix: Some("prod".to_string()),
        access_key_id: "AKIA_TEST_KEY".to_string(),
        secret_access_key: "SECRET_TEST_KEY".to_string(),
        session_token: Some("temp-sts-token".to_string()),
        force_path_style: true,
    })
    .unwrap();

    assert_eq!(store.backend_name(), "s3");

    let key = raw_message_blob_key("msg_1");
    store.put(&key, payload).await.unwrap();
    assert_eq!(store.get(&key).await.unwrap(), Some(payload.to_vec()));
    assert_eq!(
        store.get(&raw_message_blob_key("missing")).await.unwrap(),
        None
    );

    store.delete(&key).await.unwrap();
    store
        .delete(&raw_message_blob_key("missing"))
        .await
        .unwrap();

    assert!(store.get(&raw_message_blob_key("err")).await.is_err());

    // Inspect recorded requests to assert full SigV4 Authorization header format.
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 6);
    for req in &received {
        let auth = req.headers.get("authorization").unwrap().to_str().unwrap();
        assert!(
            auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIA_TEST_KEY/"),
            "unexpected auth header: {auth}"
        );
        assert!(
            auth.contains("/auto/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature="),
            "unexpected signed headers/scope: {auth}"
        );
        let sig = auth.rsplit("Signature=").next().unwrap();
        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

#[tokio::test]
async fn app_state_s3_capabilities_ingest_retrieve_and_delete_lifecycle() {
    let server = MockServer::start().await;
    let s3_mock = MockS3Responder::new();
    Mock::given(any())
        .respond_with(s3_mock.clone())
        .mount(&server)
        .await;

    let mut cfg = Config::for_test();
    cfg.blob_backend = BlobBackend::S3;
    cfg.blob_s3_bucket = Some("nogml-blobs".to_string());
    cfg.blob_s3_region = "auto".to_string();
    cfg.blob_s3_endpoint = Some(server.uri());
    cfg.blob_s3_prefix = Some("tenant1".to_string());
    cfg.blob_s3_access_key_id = Some("AKIA_APP".to_string());
    cfg.blob_s3_secret_access_key = Some("SECRET_APP".to_string());

    let state = AppState::from_config(cfg).unwrap();
    assert_eq!(state.blobs.backend_name(), "s3");

    let app = build_router(state.clone());

    // 1. GET /v1/capabilities reports .backends.blob == "s3"
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/capabilities")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let caps: Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(caps["backends"]["blob"], "s3");

    // 2. Import a MIME message with an attachment via Gmail API
    let raw_eml = concat!(
        "From: sender@example.com\r\n",
        "To: agent@example.com\r\n",
        "Subject: S3 Offload Test\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=\"BOUND123\"\r\n",
        "\r\n",
        "--BOUND123\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "Hello from S3 blob test.\r\n",
        "--BOUND123\r\n",
        "Content-Type: text/plain; name=\"report.txt\"\r\n",
        "Content-Disposition: attachment; filename=\"report.txt\"\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "QVRUQUNITUVOVF9QQVlMT0FE\r\n",
        "--BOUND123--\r\n"
    )
    .as_bytes();

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/gmail/v1/users/me/messages/import")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "raw": mime::encode_base64url(raw_eml) }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let imported: Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let msg_id = imported["id"].as_str().unwrap().to_string();

    // Verify both raw .eml and attachment were uploaded to S3 mock
    let metas = state.store.list_attachment_meta(&msg_id).await.unwrap();
    assert_eq!(metas.len(), 1);
    let att_id = metas[0].id.clone();

    let expected_raw_path = format!("/nogml-blobs/tenant1/{}", raw_message_blob_key(&msg_id));
    let expected_att_path = format!(
        "/nogml-blobs/tenant1/{}",
        attachment_blob_key(&msg_id, &att_id)
    );
    {
        let snap = s3_mock.snapshot();
        assert_eq!(
            snap.get(&expected_raw_path).map(Vec::as_slice),
            Some(raw_eml)
        );
        assert_eq!(
            snap.get(&expected_att_path).map(Vec::as_slice),
            Some(b"ATTACHMENT_PAYLOAD".as_slice())
        );
    }

    // 3. Overwrite S3 objects directly to prove reads come from S3 BlobStore (not inline store)
    {
        let mut guard = s3_mock.objects.write().unwrap();
        guard.insert(expected_raw_path.clone(), b"SERVED_FROM_S3_RAW".to_vec());
        guard.insert(expected_att_path.clone(), b"SERVED_FROM_S3_ATT".to_vec());
    }

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/gmail/v1/users/me/messages/{msg_id}?format=raw"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let raw_json: Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let fetched_raw = mime::decode_base64url(raw_json["raw"].as_str().unwrap()).unwrap();
    assert_eq!(fetched_raw, b"SERVED_FROM_S3_RAW");

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/messages/{msg_id}/attachments/{att_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let fetched_att = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(fetched_att.as_ref(), b"SERVED_FROM_S3_ATT");

    // 4. Permanently delete message -> removes raw .eml and attachment from S3
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/gmail/v1/users/me/messages/{msg_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let snap = s3_mock.snapshot();
    assert!(!snap.contains_key(&expected_raw_path));
    assert!(!snap.contains_key(&expected_att_path));
    assert!(!s3_mock.auth_headers().is_empty());
}

#[tokio::test]
async fn migrate_blobs_from_fs_and_inline_via_library_and_cli_into_s3() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("mail.db");
    let fs_blob_dir = dir.path().join("fs-blobs");

    // Seed SQLite store with 2 messages (one in INBOX with attachment, one in TRASH)
    let store = SqliteStore::open(&db_path, "agent@example.com").unwrap();
    let msg1 = store
        .insert_message(NewMessageInput {
            id: Some("msg_migrate_1".to_string()),
            thread_id: None,
            label_ids: vec![LABEL_INBOX.to_string()],
            raw_rfc2822: b"From: a@example.com\r\nSubject: One\r\n\r\nBody one".to_vec(),
            snippet: "Body one".to_string(),
            internal_date_ms: 1_700_000_001_000,
            subject: "One".to_string(),
            from_addr: "a@example.com".to_string(),
            to_addrs: vec!["agent@example.com".to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: "Body one".to_string(),
            html_body: None,
            rfc822_message_id: Some("<m1@example.com>".to_string()),
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "local".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: vec![NewAttachmentInput {
                part_id: "2".to_string(),
                filename: Some("doc.pdf".to_string()),
                content_type: "application/pdf".to_string(),
                content_id: None,
                data: b"%PDF-1.7-fake-bytes".to_vec(),
            }],
        })
        .await
        .unwrap();

    let msg2 = store
        .insert_message(NewMessageInput {
            id: Some("msg_migrate_2".to_string()),
            thread_id: None,
            label_ids: vec![LABEL_TRASH.to_string()],
            raw_rfc2822: b"From: b@example.com\r\nSubject: Trashed\r\n\r\nStill migrate".to_vec(),
            snippet: "Still migrate".to_string(),
            internal_date_ms: 1_700_000_002_000,
            subject: "Trashed".to_string(),
            from_addr: "b@example.com".to_string(),
            to_addrs: vec!["agent@example.com".to_string()],
            cc_addrs: vec![],
            bcc_addrs: vec![],
            text_body: "Still migrate".to_string(),
            html_body: None,
            rfc822_message_id: Some("<m2@example.com>".to_string()),
            in_reply_to: None,
            references_header: None,
            resend_id: None,
            upstream_gmail_id: None,
            upstream_thread_id: None,
            source: "local".to_string(),
            is_answered: false,
            is_deleted: false,
            attachments: vec![],
        })
        .await
        .unwrap();

    let metas = store.list_attachment_meta(&msg1.id).await.unwrap();
    assert_eq!(metas.len(), 1);
    let att_id = metas[0].id.clone();

    // Step 1: Migrate inline -> fs via library helper
    let fs_blobs = FsBlobStore::open(&fs_blob_dir).unwrap();
    let inline_to_fs = migrate_blobs(&store, &InlineBlobStore, &fs_blobs)
        .await
        .unwrap();
    let expected_bytes =
        (msg1.raw_rfc2822.len() + msg2.raw_rfc2822.len() + b"%PDF-1.7-fake-bytes".len()) as u64;
    assert_eq!(inline_to_fs.source_backend, "inline");
    assert_eq!(inline_to_fs.target_backend, "fs");
    assert_eq!(inline_to_fs.messages_migrated, 2);
    assert_eq!(inline_to_fs.attachments_migrated, 1);
    assert_eq!(inline_to_fs.bytes_copied, expected_bytes);

    // Step 2: Run CLI `nogml storage migrate-blobs --to s3` migrating from `fs` -> `s3`
    let server = MockServer::start().await;
    let s3_mock = MockS3Responder::new();
    Mock::given(any())
        .respond_with(s3_mock.clone())
        .mount(&server)
        .await;

    let bin = env!("CARGO_BIN_EXE_nogml");
    let output = Command::new(bin)
        .args([
            "storage",
            "migrate-blobs",
            "--to",
            "s3",
            "--db-path",
            db_path.to_str().unwrap(),
            "--blob-backend",
            "fs",
            "--blob-dir",
            fs_blob_dir.to_str().unwrap(),
        ])
        .env("NOGML_BLOB_S3_BUCKET", "migrated-bucket")
        .env("NOGML_BLOB_S3_REGION", "auto")
        .env("NOGML_BLOB_S3_ENDPOINT", server.uri())
        .env("NOGML_BLOB_S3_PREFIX", "archive")
        .env("NOGML_BLOB_S3_ACCESS_KEY_ID", "AKIA_CLI")
        .env("NOGML_BLOB_S3_SECRET_ACCESS_KEY", "SECRET_CLI")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "CLI migrate-blobs failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["source_backend"], "fs");
    assert_eq!(report["target_backend"], "s3");
    assert_eq!(report["messages_migrated"], 2);
    assert_eq!(report["attachments_migrated"], 1);
    assert_eq!(report["bytes_copied"], expected_bytes);

    let snap = s3_mock.snapshot();
    assert_eq!(
        snap.get(&format!(
            "/migrated-bucket/archive/{}",
            raw_message_blob_key(&msg1.id)
        ))
        .map(Vec::as_slice),
        Some(msg1.raw_rfc2822.as_slice())
    );
    assert_eq!(
        snap.get(&format!(
            "/migrated-bucket/archive/{}",
            raw_message_blob_key(&msg2.id)
        ))
        .map(Vec::as_slice),
        Some(msg2.raw_rfc2822.as_slice())
    );
    assert_eq!(
        snap.get(&format!(
            "/migrated-bucket/archive/{}",
            attachment_blob_key(&msg1.id, &att_id)
        ))
        .map(Vec::as_slice),
        Some(b"%PDF-1.7-fake-bytes".as_slice())
    );
}
