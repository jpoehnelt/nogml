//! End-to-end tests for BYOD custom domain onboarding (Issue #71):
//! - AWS SESv2 `SesDomainProvider` (SigV4 signing, `CreateEmailIdentity`, `GetEmailIdentity`, `DeleteEmailIdentity`)
//! - Resend `ResendDomainProvider` (`POST /domains`, `POST /domains/{id}/verify`, `GET /domains/{id}`, `DELETE /domains/{id}`)
//! - Manual `ManualDomainProvider` and admin-only `PATCH` overrides
//! - Multi-tenant scope enforcement and cross-tenant anti-hijacking
//! - `require_verified_from_domain=true` anti-spoofing guard in `OutboundPolicy`
//! - Dynamic catch-all inbound routing for verified BYOD domains across Resend and SES webhooks
//! - `nogml domains` CLI subcommands

use std::{
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, header_exists, method, path},
};

use nogml::{
    AppState,
    auth::{AuthScope, ScopedTokenConfig},
    build_router,
    config::Config,
    domains::{DomainProviderKind, DomainStatus, DomainUpdate, NewDomainInput},
    models::SendAs,
    resend::HttpResendClient,
    storage::{MailStore, MemoryStore},
    transport::{MailTransport, OutboundMessage, SendOutcome, TransportCapabilities},
};

struct RecordingTransport {
    sent: Arc<AtomicUsize>,
}

#[async_trait]
impl MailTransport for RecordingTransport {
    fn name(&self) -> &'static str {
        "recording"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            provider: "recording".to_string(),
            supports_raw_mime: true,
            supports_scheduled_send: false,
            supports_idempotency_key: true,
            supports_inbound_webhooks: false,
            supports_delivery_webhooks: false,
            max_message_bytes: 25 * 1024 * 1024,
        }
    }

    async fn send(
        &self,
        _msg: &OutboundMessage,
        _idempotency_key: Option<&str>,
    ) -> nogml::error::AppResult<SendOutcome> {
        let n = self.sent.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(SendOutcome {
            provider: "recording".to_string(),
            provider_message_id: format!("rec_{n}"),
            provider_thread_id: None,
        })
    }
}

async fn http_req(
    app: &axum::Router,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(tok) = bearer {
        builder = builder.header("authorization", format!("Bearer {tok}"));
    }
    let req = match body {
        Some(val) => builder
            .header("content-type", "application/json")
            .body(Body::from(val.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

#[tokio::test]
async fn ses_domain_lifecycle_wiremock_sigv4_create_verify_delete() {
    let ses_mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v2/email/identities"))
        .and(header_exists("authorization"))
        .and(header_exists("x-amz-date"))
        .and(header_exists("x-amz-content-sha256"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "IdentityType": "DOMAIN",
            "VerifiedForSendingStatus": false,
            "DkimAttributes": {
                "SigningEnabled": true,
                "Status": "PENDING",
                "Tokens": ["tok1", "tok2", "tok3"]
            }
        })))
        .expect(1)
        .mount(&ses_mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/email/identities/acme.io"))
        .and(header_exists("authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "IdentityType": "DOMAIN",
            "VerifiedForSendingStatus": true,
            "VerificationStatus": "SUCCESS",
            "DkimAttributes": {
                "SigningEnabled": true,
                "Status": "SUCCESS",
                "Tokens": ["tok1", "tok2", "tok3"]
            },
            "MailFromAttributes": {
                "MailFromDomain": "mail.acme.io",
                "MailFromDomainStatus": "SUCCESS"
            }
        })))
        .expect(1)
        .mount(&ses_mock)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/v2/email/identities/acme.io"))
        .and(header_exists("authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&ses_mock)
        .await;

    let mut cfg = Config::for_test();
    cfg.ses_region = "us-west-2".to_string();
    cfg.ses_endpoint = Some(ses_mock.uri());
    cfg.ses_access_key_id = Some("AKIAIOSFODNN7EXAMPLE".to_string());
    cfg.ses_secret_access_key = Some("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string());

    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store, resend);
    let app = build_router(state);

    // 1. Register SES domain (mixed case + trailing dot normalizes to acme.io).
    let (status, created) = http_req(
        &app,
        Method::POST,
        "/v1/domains",
        None,
        Some(json!({
            "domain": "ACME.IO.",
            "provider": "ses"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["domain"], "acme.io");
    assert_eq!(created["provider"], "ses");
    assert_eq!(created["status"], "pending");
    assert_eq!(created["dkim_verified"], false);
    let records = created["dns_records"].as_array().expect("dns_records");
    assert_eq!(
        records
            .iter()
            .filter(|r| r["purpose"] == "dkim" && r["type"] == "CNAME")
            .count(),
        3
    );
    assert!(records.iter().any(|r| {
        r["purpose"] == "mx"
            && r["type"] == "MX"
            && r["value"] == "inbound-smtp.us-west-2.amazonaws.com"
            && r["priority"] == 10
    }));
    assert!(records.iter().any(|r| r["purpose"] == "spf"));
    assert!(records.iter().any(|r| r["purpose"] == "dmarc"));

    // Inspect recorded SigV4 header on wiremock.
    let received = ses_mock.received_requests().await.unwrap();
    let auth_hdr = received[0]
        .headers
        .get("authorization")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        auth_hdr.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"),
        "expected SigV4 header, got: {auth_hdr}"
    );
    assert!(auth_hdr.contains("/us-west-2/ses/aws4_request"));

    // 2. Verify domain via POST /v1/domains/acme.io/verify.
    let (status, verified) =
        http_req(&app, Method::POST, "/v1/domains/acme.io/verify", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(verified["status"], "verified");
    assert_eq!(verified["dkim_verified"], true);
    assert_eq!(verified["spf_verified"], true);
    assert_eq!(verified["mx_verified"], true);
    assert!(verified["verified_at"].is_string());
    assert!(verified["last_checked_at"].is_string());
    assert!(
        verified["dns_records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["purpose"] == "mail_from" && r["name"] == "mail.acme.io")
    );

    // 3. GET /v1/domains/acme.io returns the verified state.
    let (status, fetched) = http_req(&app, Method::GET, "/v1/domains/acme.io", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fetched["status"], "verified");

    // 4. DELETE /v1/domains/acme.io calls SES DeleteEmailIdentity and removes locally.
    let (status, deleted) = http_req(&app, Method::DELETE, "/v1/domains/acme.io", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(deleted["deleted"], true);
    assert_eq!(deleted["domain"], "acme.io");

    let (status, _) = http_req(&app, Method::GET, "/v1/domains/acme.io", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn resend_domain_lifecycle_wiremock_create_verify_delete() {
    let resend_mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/domains"))
        .and(header("authorization", "Bearer re_test_domain_key"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "dom_re_42",
            "name": "brand.dev",
            "status": "not_started",
            "records": [
                {
                    "record": "SPF",
                    "name": "send.brand.dev",
                    "type": "MX",
                    "value": "feedback-smtp.us-east-1.amazonses.com",
                    "priority": 10,
                    "status": "not_started"
                },
                {
                    "record": "SPF",
                    "name": "send.brand.dev",
                    "type": "TXT",
                    "value": "v=spf1 include:amazonses.com ~all",
                    "status": "not_started"
                },
                {
                    "record": "DKIM",
                    "name": "resend._domainkey.brand.dev",
                    "type": "TXT",
                    "value": "p=MIGfMA0GCSqGSIb3DQEBAQUAA4...",
                    "status": "not_started"
                }
            ]
        })))
        .expect(1)
        .mount(&resend_mock)
        .await;

    Mock::given(method("POST"))
        .and(path("/domains/dom_re_42/verify"))
        .and(header("authorization", "Bearer re_test_domain_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "domain",
            "id": "dom_re_42"
        })))
        .expect(1)
        .mount(&resend_mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/domains/dom_re_42"))
        .and(header("authorization", "Bearer re_test_domain_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "dom_re_42",
            "name": "brand.dev",
            "status": "verified",
            "records": [
                {
                    "record": "SPF",
                    "name": "send.brand.dev",
                    "type": "MX",
                    "value": "feedback-smtp.us-east-1.amazonses.com",
                    "priority": 10,
                    "status": "verified"
                },
                {
                    "record": "SPF",
                    "name": "send.brand.dev",
                    "type": "TXT",
                    "value": "v=spf1 include:amazonses.com ~all",
                    "status": "verified"
                },
                {
                    "record": "DKIM",
                    "name": "resend._domainkey.brand.dev",
                    "type": "TXT",
                    "value": "p=MIGfMA0GCSqGSIb3DQEBAQUAA4...",
                    "status": "verified"
                }
            ]
        })))
        .expect(1)
        .mount(&resend_mock)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/domains/dom_re_42"))
        .and(header("authorization", "Bearer re_test_domain_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "domain",
            "id": "dom_re_42",
            "deleted": true
        })))
        .expect(1)
        .mount(&resend_mock)
        .await;

    let mut cfg = Config::for_test();
    cfg.resend_base_url = resend_mock.uri();
    cfg.resend_api_key = Some("re_test_domain_key".to_string());

    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store, resend);
    let app = build_router(state);

    let (status, created) = http_req(
        &app,
        Method::POST,
        "/v1/domains",
        None,
        Some(json!({
            "domain": "brand.dev",
            "provider": "resend"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["provider"], "resend");
    assert_eq!(created["provider_domain_id"], "dom_re_42");
    assert_eq!(created["status"], "pending");
    assert_eq!(created["dns_records"].as_array().unwrap().len(), 3);

    let (status, verified) = http_req(
        &app,
        Method::POST,
        "/v1/domains/brand.dev/verify",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(verified["status"], "verified");
    assert_eq!(verified["dkim_verified"], true);
    assert_eq!(verified["spf_verified"], true);
    assert!(verified["verified_at"].is_string());

    let (status, deleted) =
        http_req(&app, Method::DELETE, "/v1/domains/brand.dev", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(deleted["deleted"], true);
}

#[tokio::test]
async fn domains_auth_scopes_tenant_isolation_and_validation() {
    let mut cfg = Config::for_test();
    cfg.user_email = "alice@example.com".to_string();
    cfg.mailboxes = vec!["bob@example.com".to_string()];
    cfg.auth_tokens = vec!["tok_admin".to_string()];
    cfg.scoped_tokens = vec![
        ScopedTokenConfig {
            token: "tok_alice_admin".to_string(),
            mailbox_id: Some("alice@example.com".to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Admin],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_alice_read".to_string(),
            mailbox_id: Some("alice@example.com".to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_alice_write".to_string(),
            mailbox_id: Some("alice@example.com".to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read, AuthScope::Write],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok_bob_write".to_string(),
            mailbox_id: Some("bob@example.com".to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read, AuthScope::Write],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
    ];

    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store, resend);
    let app = build_router(state);

    // 1. Read-only token cannot register domains.
    let (status, _) = http_req(
        &app,
        Method::POST,
        "/v1/domains",
        Some("tok_alice_read"),
        Some(json!({ "domain": "alice.io", "provider": "manual" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 2. Invalid domain syntax is rejected with 400.
    for bad in ["*.wild.com", "127.0.0.1", "localhost", "user@example.com"] {
        let (status, body) = http_req(
            &app,
            Method::POST,
            "/v1/domains",
            Some("tok_alice_write"),
            Some(json!({ "domain": bad, "provider": "manual" })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "expected 400 for {bad}");
        assert_eq!(body["error"]["code"], "validation_error");
    }

    // 3. Alice registers a punycode/IDN manual domain for herself.
    let (status, alice_dom) = http_req(
        &app,
        Method::POST,
        "/v1/domains",
        Some("tok_alice_write"),
        Some(json!({ "domain": "münchen.de", "provider": "manual" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(alice_dom["domain"], "xn--mnchen-3ya.de");
    assert_eq!(alice_dom["mailbox_id"], "alice@example.com");

    // 4. Non-admin Alice cannot self-verify a manual domain (prevents anti-spoofing bypass).
    let (status, _) = http_req(
        &app,
        Method::PATCH,
        "/v1/domains/xn--mnchen-3ya.de",
        Some("tok_alice_write"),
        Some(json!({ "status": "verified" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 5. Bob cannot hijack Alice's domain (409 Conflict), read it (403), verify it (403), or delete it (403).
    let (status, _) = http_req(
        &app,
        Method::POST,
        "/v1/domains",
        Some("tok_bob_write"),
        Some(json!({ "domain": "xn--mnchen-3ya.de", "provider": "manual" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    for (m, uri) in [
        (Method::GET, "/v1/domains/xn--mnchen-3ya.de"),
        (Method::POST, "/v1/domains/xn--mnchen-3ya.de/verify"),
        (Method::DELETE, "/v1/domains/xn--mnchen-3ya.de"),
    ] {
        let (status, _) = http_req(&app, m, uri, Some("tok_bob_write"), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    // 6. Bob cannot register a domain with catch_all_mailbox pointing to Alice's mailbox.
    let (status, _) = http_req(
        &app,
        Method::POST,
        "/v1/domains",
        Some("tok_bob_write"),
        Some(json!({
            "domain": "bob.io",
            "provider": "manual",
            "catch_all_mailbox": "alice@example.com"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 7. Bob registers his own domain; non-admin listing is strictly tenant-scoped; admin sees both.
    let (status, _) = http_req(
        &app,
        Method::POST,
        "/v1/domains",
        Some("tok_bob_write"),
        Some(json!({ "domain": "bob.io", "provider": "manual" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, bob_list) = http_req(
        &app,
        Method::GET,
        "/v1/domains",
        Some("tok_bob_write"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bob_list["count"], 1);
    assert_eq!(bob_list["domains"][0]["domain"], "bob.io");

    // Non-admin asking for another mailbox via ?mailbox_id= gets 403.
    let (status, _) = http_req(
        &app,
        Method::GET,
        "/v1/domains?mailbox_id=alice@example.com",
        Some("tok_bob_write"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Mailbox-scoped Admin token for Alice MUST NOT list Bob's domain, hijack/delete Bob's domain,
    // or manually self-verify her own manual domain.
    let (status, alice_admin_list) = http_req(
        &app,
        Method::GET,
        "/v1/domains",
        Some("tok_alice_admin"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(alice_admin_list["count"], 1);
    assert_eq!(
        alice_admin_list["domains"][0]["domain"],
        "xn--mnchen-3ya.de"
    );

    let (status, _) = http_req(
        &app,
        Method::GET,
        "/v1/domains?mailbox_id=bob@example.com",
        Some("tok_alice_admin"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = http_req(
        &app,
        Method::PATCH,
        "/v1/domains/bob.io",
        Some("tok_alice_admin"),
        Some(json!({ "catch_all_mailbox": "alice@example.com" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = http_req(
        &app,
        Method::DELETE,
        "/v1/domains/bob.io",
        Some("tok_alice_admin"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = http_req(
        &app,
        Method::PATCH,
        "/v1/domains/xn--mnchen-3ya.de",
        Some("tok_alice_admin"),
        Some(json!({ "status": "verified" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Global admin sees all domains across all mailboxes.
    let (status, admin_list) =
        http_req(&app, Method::GET, "/v1/domains", Some("tok_admin"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(admin_list["count"], 2);

    // Admin can manually mark a manual domain verified and configure catch_all_mailbox.
    let (status, patched) = http_req(
        &app,
        Method::PATCH,
        "/v1/domains/bob.io",
        Some("tok_admin"),
        Some(json!({
            "status": "verified",
            "dkim_verified": true,
            "catch_all_mailbox": "bob@example.com"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(patched["status"], "verified");
    assert_eq!(patched["dkim_verified"], true);
    assert_eq!(patched["catch_all_mailbox"], "bob@example.com");
    assert!(patched["verified_at"].is_string());
}

#[tokio::test]
async fn verified_from_domain_guard_rejects_spoofing_and_allows_verified_owner() {
    let mut cfg = Config::for_test();
    cfg.user_email = "alice@primary.example".to_string();
    cfg.default_domain = "primary.example".to_string();
    cfg.mailboxes = vec!["bob@primary.example".to_string()];
    cfg.require_verified_from_domain = true;

    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    // Add a SendAs alias on an unverified domain so we prove OutboundPolicy blocks it even
    // when SendAs exists!
    let mut settings = store.get_settings().await.unwrap();
    settings.send_as.push(SendAs {
        send_as_email: "alias@unverified-sendas.example".to_string(),
        display_name: None,
        reply_to_address: None,
        signature: None,
        is_primary: Some(false),
        is_default: Some(false),
        treat_as_alias: Some(true),
        smtp_msa: None,
        verification_status: Some("accepted".to_string()),
    });
    store.save_settings(settings).await.unwrap();

    // Seed:
    // - pending.example owned by alice (Pending)
    // - bobs-verified.example owned by bob (Verified)
    store
        .create_domain(NewDomainInput {
            id: None,
            domain: "pending.example".to_string(),
            mailbox_id: "alice@primary.example".to_string(),
            provider: DomainProviderKind::Manual,
            provider_domain_id: None,
            status: DomainStatus::Pending,
            dns_records: Vec::new(),
            dkim_verified: false,
            spf_verified: false,
            dmarc_verified: false,
            mx_verified: false,
            catch_all_mailbox: None,
            last_error: None,
        })
        .await
        .unwrap();
    store
        .create_domain(NewDomainInput {
            id: None,
            domain: "bobs-verified.example".to_string(),
            mailbox_id: "bob@primary.example".to_string(),
            provider: DomainProviderKind::Manual,
            provider_domain_id: None,
            status: DomainStatus::Verified,
            dns_records: Vec::new(),
            dkim_verified: true,
            spf_verified: true,
            dmarc_verified: false,
            mx_verified: false,
            catch_all_mailbox: None,
            last_error: None,
        })
        .await
        .unwrap();

    let sent_calls = Arc::new(AtomicUsize::new(0));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store.clone(), resend).with_transport(Arc::new(
        RecordingTransport {
            sent: sent_calls.clone(),
        },
    ));
    let app = build_router(state);

    // 1. Default primary domain succeeds.
    let (status, _) = http_req(
        &app,
        Method::POST,
        "/v1/messages/send",
        None,
        Some(json!({
            "to": ["rcpt@external.example"],
            "subject": "Primary ok",
            "text": "Hello"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sent_calls.load(Ordering::SeqCst), 1);

    // 2. Spoofed unregistered domain, pending owned domain, SendAs on unverified domain,
    //    and another tenant's verified domain are ALL rejected with 403 unverified_from_domain.
    for spoof_from in [
        "ceo@evil.example",
        "sales@pending.example",
        "alias@unverified-sendas.example",
        "spoof@bobs-verified.example",
    ] {
        let (status, body) = http_req(
            &app,
            Method::POST,
            "/v1/messages/send",
            None,
            Some(json!({
                "from": spoof_from,
                "to": ["rcpt@external.example"],
                "subject": "Spoof attempt",
                "text": "Blocked"
            })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "expected 403 for from={spoof_from}, body={body}"
        );
        assert_eq!(
            body["error"]["code"], "unverified_from_domain",
            "expected unverified_from_domain for from={spoof_from}, body={body}"
        );
    }
    assert_eq!(sent_calls.load(Ordering::SeqCst), 1);

    // 3. Once pending.example is verified for Alice, sending from sales@pending.example succeeds!
    store
        .update_domain(
            "pending.example",
            &DomainUpdate {
                status: Some(DomainStatus::Verified),
                dkim_verified: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let (status, sent) = http_req(
        &app,
        Method::POST,
        "/v1/messages/send",
        None,
        Some(json!({
            "from": "sales@pending.example",
            "to": ["rcpt@external.example"],
            "subject": "Verified BYOD ok",
            "text": "Hello from custom domain"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={sent}");
    assert_eq!(sent_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn catch_all_inbound_routing_works_for_resend_and_ses_webhooks() {
    let mut cfg = Config::for_test();
    cfg.user_email = "alice@example.com".to_string();
    cfg.mailboxes = vec!["catchall@example.com".to_string()];
    cfg.mailbox_aliases
        .insert("vip@custom.io".to_string(), "alice@example.com".to_string());
    cfg.allow_insecure_webhooks = true;

    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    // Verified BYOD domain with catch_all_mailbox = catchall@example.com
    store
        .create_domain(NewDomainInput {
            id: None,
            domain: "custom.io".to_string(),
            mailbox_id: "catchall@example.com".to_string(),
            provider: DomainProviderKind::Manual,
            provider_domain_id: None,
            status: DomainStatus::Verified,
            dns_records: Vec::new(),
            dkim_verified: true,
            spf_verified: true,
            dmarc_verified: true,
            mx_verified: true,
            catch_all_mailbox: Some("catchall@example.com".to_string()),
            last_error: None,
        })
        .await
        .unwrap();
    // Unverified BYOD domain with catch_all_mailbox set — MUST NOT route!
    store
        .create_domain(NewDomainInput {
            id: None,
            domain: "unverified.io".to_string(),
            mailbox_id: "catchall@example.com".to_string(),
            provider: DomainProviderKind::Manual,
            provider_domain_id: None,
            status: DomainStatus::Pending,
            dns_records: Vec::new(),
            dkim_verified: false,
            spf_verified: false,
            dmarc_verified: false,
            mx_verified: false,
            catch_all_mailbox: Some("catchall@example.com".to_string()),
            last_error: None,
        })
        .await
        .unwrap();

    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store.clone(), resend);
    let app = build_router(state);

    // 1. Resend webhook to unmatched address on verified custom.io -> routes to catchall@example.com.
    let (status, body) = http_req(
        &app,
        Method::POST,
        "/webhooks/resend",
        None,
        Some(json!({
            "type": "email.received",
            "created_at": "2026-11-26T12:00:00Z",
            "data": {
                "email_id": "re_in_catchall_1",
                "from": "sender@outside.example",
                "to": ["anything@custom.io"],
                "subject": "Resend catch-all test",
                "message_id": "<catchall-resend-1@outside.example>"
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["status"], "received");
    assert_eq!(body["mailbox_id"], "catchall@example.com");

    // 2. Explicit alias vip@custom.io takes precedence over catch-all -> routes to alice@example.com.
    let (status, body) = http_req(
        &app,
        Method::POST,
        "/webhooks/resend",
        None,
        Some(json!({
            "type": "email.received",
            "created_at": "2026-11-26T12:01:00Z",
            "data": {
                "email_id": "re_in_alias_1",
                "from": "sender@outside.example",
                "to": ["vip@custom.io"],
                "subject": "Explicit alias wins",
                "message_id": "<alias-resend-1@outside.example>"
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["status"], "received");
    assert_eq!(body["mailbox_id"], "alice@example.com");

    // 3. Unverified domain with catch_all_mailbox is ignored cleanly.
    let (status, body) = http_req(
        &app,
        Method::POST,
        "/webhooks/resend",
        None,
        Some(json!({
            "type": "email.received",
            "created_at": "2026-11-26T12:02:00Z",
            "data": {
                "email_id": "re_in_unverified_1",
                "from": "sender@outside.example",
                "to": ["anyone@unverified.io"],
                "subject": "Should ignore",
                "message_id": "<unverified-1@outside.example>"
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["status"], "ignored");
    assert_eq!(body["reason"], "no_matching_local_mailbox");

    // 4. SES inbound webhook to random@custom.io -> routes to catchall@example.com.
    let raw_eml = b"From: partner@outside.example\r\nTo: random@custom.io\r\nSubject: SES catch-all\r\nMessage-ID: <ses-catchall-1@outside.example>\r\n\r\nHello via SES";
    let ses_notification = json!({
        "notificationType": "Received",
        "mail": {
            "timestamp": "2026-11-26T12:03:00Z",
            "source": "partner@outside.example",
            "messageId": "ses-msg-1",
            "destination": ["random@custom.io"]
        },
        "receipt": {
            "timestamp": "2026-11-26T12:03:00Z",
            "recipients": ["random@custom.io"],
            "action": {
                "type": "SNS",
                "encoding": "BASE64"
            }
        },
        "content": general_purpose::STANDARD.encode(raw_eml)
    });
    let sns_envelope = json!({
        "Type": "Notification",
        "MessageId": "sns-id-1",
        "TopicArn": "arn:aws:sns:us-east-1:123456789012:ses-inbound",
        "Message": ses_notification.to_string(),
        "Timestamp": "2026-11-26T12:03:00Z"
    });
    let (status, body) = http_req(
        &app,
        Method::POST,
        "/webhooks/ses",
        None,
        Some(sns_envelope),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["status"], "received");
    assert_eq!(body["mailbox_id"], "catchall@example.com");

    // Verify catchall@example.com received both Resend and SES catch-all messages.
    let catchall_msgs = store
        .for_mailbox("catchall@example.com")
        .list_messages(&Default::default())
        .await
        .unwrap();
    assert_eq!(catchall_msgs.messages.len(), 2);
}

#[test]
fn cli_domains_add_list_get_verify_delete_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("domains.db");
    let bin = env!("CARGO_BIN_EXE_nogml");

    let run = |args: &[&str]| -> Value {
        let mut full = vec![
            "--storage",
            "sqlite",
            "--db-path",
            db_path.to_str().unwrap(),
            "--user-email",
            "owner@example.com",
        ];
        full.extend_from_slice(args);
        let output = Command::new(bin)
            .args(&full)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .output()
            .expect("run nogml domains");
        assert!(
            output.status.success(),
            "command {:?} failed: stdout={} stderr={}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("valid JSON output")
    };

    let added = run(&[
        "domains",
        "add",
        "cli-test.io",
        "--provider",
        "manual",
        "--catch-all",
        "owner@example.com",
    ]);
    assert_eq!(added["domain"], "cli-test.io");
    assert_eq!(added["provider"], "manual");
    assert_eq!(added["status"], "pending");
    assert_eq!(added["catch_all_mailbox"], "owner@example.com");

    let listed = run(&["domains", "list"]);
    assert_eq!(listed["count"], 1);

    let fetched = run(&["domains", "get", "cli-test.io"]);
    assert_eq!(fetched["domain"], "cli-test.io");

    let verified = run(&["domains", "verify", "cli-test.io"]);
    assert!(verified["last_checked_at"].is_string());

    let deleted = run(&["domains", "delete", "cli-test.io"]);
    assert_eq!(deleted["deleted"], true);
}
