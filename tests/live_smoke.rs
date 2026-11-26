//! Opt-in live provider smoke tests (`#[ignore = "requires live provider credentials"]`)
//! plus default-CI integration tests for Google client compatibility endpoints
//! (`/oauth2/v2/userinfo`, `/oauth2/v3/userinfo`, `/v1/people/me`) and IMAP
//! `BODYSTRUCTURE` / `ENVELOPE` / `INTERNALDATE` client edge cases.
//!
//! Run live provider tests explicitly:
//! ```bash
//! cargo test --test live_smoke -- --ignored --nocapture
//! ```

use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::Utc;
use futures_util::TryStreamExt;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tower::ServiceExt;
use uuid::Uuid;

use nogml::{
    AppState,
    auth::{AuthScope, ScopedTokenConfig},
    build_router,
    config::{Config, SyncMode},
    imap::{
        mime_fmt::{format_bodystructure, format_envelope, parse_raw_to_new_message_input},
        parser::format_internal_date,
        serve_plain_listener,
    },
    models::{LABEL_INBOX, LABEL_UNREAD},
    resend::{HttpResendClient, ResendClient, ResendTransport},
    storage::{MailStore, MemoryStore, MessageListQuery},
    sync::{SyncRunOptions, run_gmail_sync},
    transport::{MailTransport, OutboundMessage},
};

fn live_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn live_strict_mode() -> bool {
    live_env("NOGML_LIVE_STRICT")
        .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
}

fn skip_or_fail_missing(test_name: &str, missing_hint: &str) {
    let msg = format!("[skip] {test_name}: missing required env var(s): {missing_hint}");
    if live_strict_mode() {
        panic!("{msg}");
    } else {
        eprintln!("{msg}");
    }
}

async fn http_json(
    app: &Router,
    method: &str,
    uri: &str,
    auth: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(a) = auth {
        builder = builder.header(header::AUTHORIZATION, a);
    }
    let req = if let Some(payload) = body {
        builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap()
    } else {
        builder.body(Body::empty()).unwrap()
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let val = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, val)
}

// ============================================================================
// Opt-in Live Provider Smoke Tests (`--ignored`)
// ============================================================================

/// Live smoke test for Resend outbound delivery via `ResendTransport` and optional
/// Resend Receiving API lookup (`NOGML_LIVE_RESEND_RECEIVED_ID`).
///
/// Required env vars:
/// - `NOGML_LIVE_RESEND_API_KEY`
/// - `NOGML_LIVE_FROM`
/// - `NOGML_LIVE_TO`
///
/// Optional env vars:
/// - `NOGML_LIVE_RESEND_BASE_URL` (defaults to `https://api.resend.com`)
/// - `NOGML_LIVE_RESEND_RECEIVED_ID` (if set, verifies `get_received_email`)
#[tokio::test]
#[ignore = "requires live provider credentials"]
async fn live_resend_send_and_receive() {
    let (Some(api_key), Some(from), Some(to)) = (
        live_env("NOGML_LIVE_RESEND_API_KEY"),
        live_env("NOGML_LIVE_FROM"),
        live_env("NOGML_LIVE_TO"),
    ) else {
        skip_or_fail_missing(
            "live_resend_send_and_receive",
            "NOGML_LIVE_RESEND_API_KEY, NOGML_LIVE_FROM, NOGML_LIVE_TO",
        );
        return;
    };

    let base_url =
        live_env("NOGML_LIVE_RESEND_BASE_URL").unwrap_or_else(|| "https://api.resend.com".into());
    let client: Arc<dyn ResendClient> = Arc::new(HttpResendClient::new(base_url, Some(api_key)));
    let transport = ResendTransport::new(client.clone(), from.clone());

    let run_id = Uuid::new_v4();
    let now = Utc::now().to_rfc3339();
    let msg = OutboundMessage {
        from,
        to: vec![to],
        subject: format!("nogml live smoke test ({run_id})"),
        text: Some(format!(
            "nogml live Resend smoke test executed at {now} (run_id={run_id})."
        )),
        html: Some(format!(
            "<p>nogml live Resend smoke test executed at <code>{now}</code> (run_id={run_id}).</p>"
        )),
        idempotency_key: Some(format!("nogml-live-smoke-{run_id}")),
        ..Default::default()
    };

    let outcome = transport
        .send(&msg, None)
        .await
        .expect("live ResendTransport::send should succeed");
    assert_eq!(outcome.provider, "resend");
    assert!(
        !outcome.provider_message_id.trim().is_empty(),
        "Resend should return a non-empty message id"
    );
    eprintln!(
        "[ok] live_resend_send_and_receive: sent resend id={}",
        outcome.provider_message_id
    );

    if let Some(received_id) = live_env("NOGML_LIVE_RESEND_RECEIVED_ID") {
        let received = client
            .get_received_email(&received_id)
            .await
            .expect("live Resend get_received_email should succeed");
        assert_eq!(received.id, received_id);
        eprintln!(
            "[ok] live_resend_send_and_receive: fetched received id={} subject={:?}",
            received.id, received.subject
        );
    }
}

/// Live smoke test for upstream Gmail REST API v1 sync (`SyncMode::Api`) into `MemoryStore`.
///
/// Required env vars (either option):
/// - `NOGML_LIVE_GMAIL_ACCESS_TOKEN`, OR
/// - `NOGML_LIVE_GMAIL_REFRESH_TOKEN`, `NOGML_LIVE_GMAIL_CLIENT_ID`, `NOGML_LIVE_GMAIL_CLIENT_SECRET`
///
/// Optional env vars:
/// - `NOGML_LIVE_GMAIL_USER_ID` (defaults to `me`)
#[tokio::test]
#[ignore = "requires live provider credentials"]
async fn live_gmail_api_sync() {
    let access_token = live_env("NOGML_LIVE_GMAIL_ACCESS_TOKEN");
    let refresh_token = live_env("NOGML_LIVE_GMAIL_REFRESH_TOKEN");
    let client_id = live_env("NOGML_LIVE_GMAIL_CLIENT_ID");
    let client_secret = live_env("NOGML_LIVE_GMAIL_CLIENT_SECRET");

    let has_refresh_pair =
        refresh_token.is_some() && client_id.is_some() && client_secret.is_some();
    if access_token.is_none() && !has_refresh_pair {
        skip_or_fail_missing(
            "live_gmail_api_sync",
            "NOGML_LIVE_GMAIL_ACCESS_TOKEN or (NOGML_LIVE_GMAIL_REFRESH_TOKEN + NOGML_LIVE_GMAIL_CLIENT_ID + NOGML_LIVE_GMAIL_CLIENT_SECRET)",
        );
        return;
    }

    let mut cfg = Config::for_test();
    cfg.sync_mode = SyncMode::Api;
    cfg.gmail_access_token = access_token;
    cfg.gmail_refresh_token = refresh_token;
    cfg.gmail_client_id = client_id;
    cfg.gmail_client_secret = client_secret;
    if let Some(uid) = live_env("NOGML_LIVE_GMAIL_USER_ID") {
        cfg.gmail_user_id = uid;
    }

    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store.clone(), resend);

    let report = run_gmail_sync(
        &state,
        SyncRunOptions {
            mode: Some(SyncMode::Api),
            full: true,
            max_messages: Some(5),
            query: None,
            bidirectional: Some(false),
        },
    )
    .await
    .expect("live Gmail API sync should succeed");

    assert_eq!(report.provider, "gmail_api");
    assert!(
        report.history_id.is_some(),
        "live Gmail API sync should record upstream history_id"
    );

    let labels = store
        .list_labels()
        .await
        .expect("list_labels should succeed");
    assert!(
        !labels.is_empty(),
        "store should contain system and synced Gmail labels"
    );

    let page = store
        .list_messages(&MessageListQuery {
            max_results: 10,
            include_spam_trash: true,
            ..Default::default()
        })
        .await
        .expect("list_messages should succeed");
    assert!(
        page.messages.len() <= 5,
        "max_messages=5 cap should be respected"
    );
    eprintln!(
        "[ok] live_gmail_api_sync: added={} labels_synced={} stored_messages={} history_id={:?}",
        report.messages_added,
        report.labels_synced,
        page.messages.len(),
        report.history_id
    );
}

/// Live smoke test for upstream Gmail IMAP sync (`SyncMode::Imap`) into `MemoryStore`.
///
/// Required env vars:
/// - `NOGML_LIVE_GMAIL_IMAP_USER`
/// - `NOGML_LIVE_GMAIL_IMAP_PASSWORD`
///
/// Optional env vars:
/// - `NOGML_LIVE_GMAIL_IMAP_HOST` (defaults to `imap.gmail.com`)
/// - `NOGML_LIVE_GMAIL_IMAP_PORT` (defaults to `993`)
/// - `NOGML_LIVE_GMAIL_IMAP_MAILBOX` (defaults to `[Gmail]/All Mail`)
#[tokio::test]
#[ignore = "requires live provider credentials"]
async fn live_gmail_imap_sync() {
    let (Some(user), Some(password)) = (
        live_env("NOGML_LIVE_GMAIL_IMAP_USER"),
        live_env("NOGML_LIVE_GMAIL_IMAP_PASSWORD"),
    ) else {
        skip_or_fail_missing(
            "live_gmail_imap_sync",
            "NOGML_LIVE_GMAIL_IMAP_USER, NOGML_LIVE_GMAIL_IMAP_PASSWORD",
        );
        return;
    };

    let mut cfg = Config::for_test();
    cfg.sync_mode = SyncMode::Imap;
    cfg.gmail_imap_user = Some(user);
    cfg.gmail_imap_password = Some(password);
    cfg.gmail_imap_tls = true;
    if let Some(host) = live_env("NOGML_LIVE_GMAIL_IMAP_HOST") {
        cfg.gmail_imap_host = host;
    }
    if let Some(port) = live_env("NOGML_LIVE_GMAIL_IMAP_PORT").and_then(|p| p.parse::<u16>().ok()) {
        cfg.gmail_imap_port = port;
    }
    if let Some(mailbox) = live_env("NOGML_LIVE_GMAIL_IMAP_MAILBOX") {
        cfg.gmail_imap_mailbox = mailbox;
    }

    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store.clone(), resend);

    let report = run_gmail_sync(
        &state,
        SyncRunOptions {
            mode: Some(SyncMode::Imap),
            full: true,
            max_messages: Some(5),
            query: None,
            bidirectional: Some(false),
        },
    )
    .await
    .expect("live Gmail IMAP sync should succeed");

    assert_eq!(report.provider, "gmail_imap");

    let page = store
        .list_messages(&MessageListQuery {
            max_results: 10,
            include_spam_trash: true,
            ..Default::default()
        })
        .await
        .expect("list_messages should succeed");
    assert!(
        page.messages.len() <= 5,
        "max_messages=5 cap should be respected"
    );
    eprintln!(
        "[ok] live_gmail_imap_sync: added={} stored_messages={}",
        report.messages_added,
        page.messages.len()
    );
}

// ============================================================================
// Default-CI Compatibility Tests (Google userinfo, People API, IMAP quirks)
// ============================================================================

#[tokio::test]
async fn userinfo_v2_v3_and_oauth2_discovery_compatibility() {
    let mut cfg = Config::for_test();
    cfg.user_email = "alice@example.com".to_string();
    cfg.mailboxes = vec!["bob@example.com".to_string()];
    cfg.auth_tokens = vec!["tok-alice-static".to_string()];
    cfg.scoped_tokens = vec![
        ScopedTokenConfig {
            token: "tok-alice-read".to_string(),
            mailbox_id: Some("alice@example.com".to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Read],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
        ScopedTokenConfig {
            token: "tok-bob-admin".to_string(),
            mailbox_id: Some("bob@example.com".to_string()),
            shared_mailboxes: Vec::new(),
            scopes: vec![AuthScope::Admin],
            draft_only: None,
            allowed_recipients: None,
            max_send_recipients: None,
        },
    ];
    cfg.oauth2_client_id = Some("nogml-client".to_string());
    cfg.oauth2_client_secret = Some("nogml-secret".to_string());
    cfg.oauth2_signing_secret = Some("signing-key-for-userinfo-tests-32b!".to_string());

    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store, resend);
    let app = build_router(state);

    // 1. OAuth2 discovery advertises userinfo_endpoint
    let (status, meta) = http_json(
        &app,
        "GET",
        "/.well-known/oauth-authorization-server",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        meta["userinfo_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/oauth2/v3/userinfo")
    );

    // 2. Unauthenticated requests to userinfo v2 and v3 return 401
    let (s, _) = http_json(&app, "GET", "/oauth2/v2/userinfo", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = http_json(&app, "GET", "/oauth2/v3/userinfo", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // 3. Before SendAs display_name is configured, name falls back to email local-part
    let (s, v2) = http_json(
        &app,
        "GET",
        "/oauth2/v2/userinfo",
        Some("Bearer tok-alice-read"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v2["sub"], "alice@example.com");
    assert_eq!(v2["id"], "alice@example.com");
    assert_eq!(v2["email"], "alice@example.com");
    assert_eq!(v2["email_verified"], true);
    assert_eq!(v2["verified_email"], true);
    assert_eq!(v2["name"], "alice");

    // 4. Update primary SendAs display name for Alice and verify v2/v3 reflect it
    let (s, _) = http_json(
        &app,
        "PATCH",
        "/gmail/v1/users/me/settings/sendAs/alice@example.com",
        Some("Bearer tok-alice-static"),
        Some(json!({ "displayName": "Alice Example" })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let (s, v3) = http_json(
        &app,
        "GET",
        "/oauth2/v3/userinfo",
        Some("Bearer tok-alice-read"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v3["sub"], "alice@example.com");
    assert_eq!(v3["email"], "alice@example.com");
    assert_eq!(v3["email_verified"], true);
    assert_eq!(v3["name"], "Alice Example");

    // 5. Partial response ?fields= projection works on userinfo
    let (s, partial) = http_json(
        &app,
        "GET",
        "/oauth2/v3/userinfo?fields=email,name",
        Some("Bearer tok-alice-read"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        partial,
        json!({ "email": "alice@example.com", "name": "Alice Example" })
    );

    // 6. Multi-mailbox isolation: Bob's SendAs display name is independent from Alice's
    let (s, _) = http_json(
        &app,
        "PATCH",
        "/gmail/v1/users/me/settings/sendAs/bob@example.com",
        Some("Bearer tok-bob-admin"),
        Some(json!({ "displayName": "Bob Builder" })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // 7. Mint an OAuth2 access token with Google userinfo + Gmail scopes for Bob
    let (s, tok_resp) = http_json(
        &app,
        "POST",
        "/oauth2/token",
        None,
        Some(json!({
            "grant_type": "client_credentials",
            "client_id": "nogml-client",
            "client_secret": "nogml-secret",
            "mailbox": "bob@example.com",
            "scope": "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile"
        })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let bob_jwt = tok_resp["access_token"].as_str().unwrap();

    let (s, bob_v2) = http_json(
        &app,
        "GET",
        "/oauth2/v2/userinfo",
        Some(&format!("Bearer {bob_jwt}")),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(bob_v2["sub"], "bob@example.com");
    assert_eq!(bob_v2["email"], "bob@example.com");
    assert_eq!(bob_v2["email_verified"], true);
    assert_eq!(bob_v2["name"], "Bob Builder");
}

#[tokio::test]
async fn people_me_endpoint_and_person_fields_filtering() {
    let mut cfg = Config::for_test();
    cfg.user_email = "alice@example.com".to_string();
    cfg.mailboxes = vec!["bob@example.com".to_string()];
    cfg.auth_tokens = vec!["tok-admin".to_string()];
    cfg.scoped_tokens = vec![ScopedTokenConfig {
        token: "tok-bob".to_string(),
        mailbox_id: Some("bob@example.com".to_string()),
        shared_mailboxes: Vec::new(),
        scopes: vec![AuthScope::Read, AuthScope::Admin],
        draft_only: None,
        allowed_recipients: None,
        max_send_recipients: None,
    }];

    let store = Arc::new(MemoryStore::new(&cfg.user_email));
    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store, resend);
    let app = build_router(state);

    // Unauthenticated rejected with 401
    let (s, _) = http_json(&app, "GET", "/v1/people/me", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Configure primary display name and an extra SendAs alias for Alice
    let (s, _) = http_json(
        &app,
        "PATCH",
        "/gmail/v1/users/me/settings/sendAs/alice@example.com",
        Some("Bearer tok-admin"),
        Some(json!({ "displayName": "Alice Smith" })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let (s, _) = http_json(
        &app,
        "POST",
        "/gmail/v1/users/me/settings/sendAs",
        Some("Bearer tok-admin"),
        Some(json!({
            "sendAsEmail": "billing@example.com",
            "displayName": "Alice Billing"
        })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // Default /v1/people/me returns resourceName, names, and emailAddresses (primary + alias)
    let (s, person) = http_json(
        &app,
        "GET",
        "/v1/people/me?personFields=names,emailAddresses,photos",
        Some("Bearer tok-admin"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(person["resourceName"], "people/me");
    assert_eq!(person["names"][0]["displayName"], "Alice Smith");
    assert_eq!(person["names"][0]["metadata"]["primary"], true);
    let emails = person["emailAddresses"].as_array().unwrap();
    assert_eq!(emails.len(), 2);
    assert_eq!(emails[0]["value"], "alice@example.com");
    assert_eq!(emails[0]["metadata"]["primary"], true);
    assert_eq!(emails[1]["value"], "billing@example.com");
    assert_eq!(emails[1]["metadata"]["primary"], false);

    // personFields=names returns only resourceName + names
    let (s, only_names) = http_json(
        &app,
        "GET",
        "/v1/people/me?personFields=names",
        Some("Bearer tok-admin"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(only_names["resourceName"], "people/me");
    assert!(only_names.get("names").is_some());
    assert!(only_names.get("emailAddresses").is_none());

    // personFields=emailAddresses returns only resourceName + emailAddresses
    let (s, only_emails) = http_json(
        &app,
        "GET",
        "/v1/people/me?personFields=emailAddresses",
        Some("Bearer tok-admin"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(only_emails["resourceName"], "people/me");
    assert!(only_emails.get("names").is_none());
    assert!(only_emails.get("emailAddresses").is_some());

    // Multi-mailbox isolation on /v1/people/me
    let (s, bob_person) = http_json(
        &app,
        "GET",
        "/v1/people/me?personFields=names,emailAddresses",
        Some("Bearer tok-bob"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(bob_person["names"][0]["displayName"], "bob");
    assert_eq!(bob_person["emailAddresses"].as_array().unwrap().len(), 1);
    assert_eq!(bob_person["emailAddresses"][0]["value"], "bob@example.com");

    // Existing AI /v1 routes have no conflict with /v1/people/me
    let (s, caps) = http_json(
        &app,
        "GET",
        "/v1/capabilities",
        Some("Bearer tok-admin"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(caps.get("backends").is_some());
}

#[tokio::test]
async fn imap_bodystructure_envelope_and_internaldate_client_quirks() {
    // 1. Non-multipart message without explicit Content-Type and without trailing newline
    let plain_no_ct =
        b"From: alice@example.com\r\nTo: agent@example.com\r\nSubject: Plain\r\n\r\nHello world";
    let bs_plain = format_bodystructure(plain_no_ct, true);
    assert!(
        bs_plain.starts_with(r#"("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 11 1 "#),
        "unexpected non-multipart BODYSTRUCTURE: {bs_plain}"
    );
    let body_plain = format_bodystructure(plain_no_ct, false);
    assert_eq!(
        body_plain,
        r#"("TEXT" "PLAIN" ("CHARSET" "US-ASCII") NIL NIL "7BIT" 11 1)"#
    );
    let env_plain = format_envelope(plain_no_ct);
    // Empty display name -> NIL; absent Sender/Reply-To -> mirrors From; absent Date/Message-ID -> NIL
    assert!(
        env_plain.starts_with(
            r#"(NIL "Plain" ((NIL NIL "alice" "example.com")) ((NIL NIL "alice" "example.com")) ((NIL NIL "alice" "example.com")) ((NIL NIL "agent" "example.com")) NIL NIL NIL NIL)"#
        ),
        "unexpected ENVELOPE: {env_plain}"
    );

    // 2. Empty Sender and Reply-To headers must fall back to From (RFC 3501 Section 7.4.2)
    let empty_sender_raw = concat!(
        "Date:   \r\n",
        "From: \"\" <alice@example.com>\r\n",
        "Sender: \r\n",
        "Reply-To: \r\n",
        "To: bob@example.com\r\n",
        "Message-ID: \r\n",
        "In-Reply-To: \r\n",
        "\r\n",
        "Body\r\n",
    )
    .as_bytes();
    let env_fallback = format_envelope(empty_sender_raw);
    assert!(
        env_fallback.starts_with(
            r#"(NIL NIL ((NIL NIL "alice" "example.com")) ((NIL NIL "alice" "example.com")) ((NIL NIL "alice" "example.com")) ((NIL NIL "bob" "example.com")) NIL NIL NIL NIL)"#
        ),
        "empty Sender/Reply-To/Date/Message-ID should normalize cleanly: {env_fallback}"
    );

    // 3. Malformed multipart with zero child parts still satisfies RFC 3501 `1*body`
    let empty_multipart = concat!(
        "From: alice@example.com\r\n",
        "To: agent@example.com\r\n",
        "Subject: Empty Multipart\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=\"empty_bnd\"\r\n",
        "\r\n",
        "--empty_bnd--\r\n",
    )
    .as_bytes();
    let bs_empty_mp = format_bodystructure(empty_multipart, true);
    assert!(
        bs_empty_mp.starts_with(r#"(("TEXT" "PLAIN""#) && bs_empty_mp.contains(r#""MIXED""#),
        "empty multipart must synthesize a valid 1*body child: {bs_empty_mp}"
    );

    // 4. Multipart mixed with attachment + disposition + UTF-8 subject
    let multipart_att = concat!(
        "Date: Thu, 05 Mar 2026 08:07:06 +0000\r\n",
        "From: =?UTF-8?Q?Ren=C3=A9?= <rene@example.com>\r\n",
        "To: agent@example.com\r\n",
        "Subject: =?UTF-8?Q?Caf=C3=A9_report?=\r\n",
        "Message-ID: <cafe-1@example.com>\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=\"mix1\"\r\n",
        "\r\n",
        "--mix1\r\n",
        "Content-Type: text/plain; charset=\"utf-8\"\r\n",
        "\r\n",
        "See attached.\r\n",
        "--mix1\r\n",
        "Content-Type: application/pdf; name=\"report.pdf\"\r\n",
        "Content-Disposition: attachment; filename=\"report.pdf\"\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "JVBERi0xLjQK\r\n",
        "--mix1--\r\n",
    )
    .as_bytes();
    let bs_att = format_bodystructure(multipart_att, true);
    assert!(bs_att.contains(r#""APPLICATION" "PDF""#));
    assert!(bs_att.contains(r#"("ATTACHMENT" ("FILENAME" "report.pdf"))"#));

    // 5. Embedded message/rfc822 part
    let nested_rfc822 = concat!(
        "From: fwd@example.com\r\n",
        "To: agent@example.com\r\n",
        "Subject: Fwd: Inner\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=\"fwd1\"\r\n",
        "\r\n",
        "--fwd1\r\n",
        "Content-Type: text/plain\r\n",
        "\r\n",
        "Forwarded below.\r\n",
        "--fwd1\r\n",
        "Content-Type: message/rfc822\r\n",
        "\r\n",
        "From: inner@example.com\r\n",
        "To: fwd@example.com\r\n",
        "Subject: Inner Message\r\n",
        "\r\n",
        "Inner body line.\r\n",
        "--fwd1--\r\n",
    )
    .as_bytes();
    let bs_nested = format_bodystructure(nested_rfc822, true);
    assert!(bs_nested.contains(r#""MESSAGE" "RFC822""#));
    assert!(bs_nested.contains(r#""Inner Message""#));

    // 6. INTERNALDATE RFC 3501 format check (single-digit day & epoch 0)
    // 2026-03-05T08:07:06Z == 1772698026000 ms
    assert_eq!(
        format_internal_date(1_772_698_026_000),
        "05-Mar-2026 08:07:06 +0000"
    );
    assert_eq!(format_internal_date(0), "01-Jan-1970 00:00:00 +0000");

    // 7. End-to-end IMAP FETCH parsed by real `async-imap` (`imap-proto`, same parser used by `himalaya`)
    let mut cfg = Config::for_test();
    cfg.auth_tokens = vec!["imap-test-pass".to_string()];
    let store = Arc::new(MemoryStore::new(&cfg.user_email));

    for (raw, ts) in [
        (plain_no_ct.to_vec(), 1_772_698_026_000i64),
        (empty_sender_raw.to_vec(), 0i64),
        (empty_multipart.to_vec(), 1_700_000_000_000i64),
        (multipart_att.to_vec(), 1_772_698_026_000i64),
        (nested_rfc822.to_vec(), 1_772_698_026_000i64),
    ] {
        let input = parse_raw_to_new_message_input(
            raw,
            vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            Some(ts),
            "local",
            None,
            None,
            false,
            false,
        );
        store.insert_message(input).await.unwrap();
    }

    let resend = Arc::new(HttpResendClient::from_config(&cfg));
    let state = AppState::with_backends(cfg, store, resend);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = serve_plain_listener(listener, state, None, shutdown_rx).await;
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut client = async_imap::Client::new(tcp);
    let _ = client.read_response().await.unwrap();
    let mut session = client
        .login("agent@example.com", "imap-test-pass")
        .await
        .map_err(|(e, _)| e)
        .unwrap();

    let mbx = session.select("INBOX").await.unwrap();
    assert_eq!(mbx.exists, 5);

    let fetches: Vec<_> = session
        .uid_fetch(
            "1:*",
            "(UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODYSTRUCTURE)",
        )
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap();
    assert_eq!(fetches.len(), 5);

    for f in &fetches {
        assert!(f.uid.is_some(), "every message must have a UID");
        assert!(
            f.internal_date().is_some(),
            "INTERNALDATE must parse cleanly via imap-proto"
        );
        assert!(
            f.envelope().is_some(),
            "ENVELOPE must parse cleanly via imap-proto"
        );
        assert!(
            f.bodystructure().is_some(),
            "BODYSTRUCTURE must parse cleanly via imap-proto"
        );
    }

    session.logout().await.unwrap();
    let _ = shutdown_tx.send(true);
}
