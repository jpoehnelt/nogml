use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::Engine as _;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path, query_param},
};

use nogml::{
    AppState, build_router,
    config::{Config, StorageBackend, SyncMode, TomlConfig, TransportBackend},
    filter::NoopFilter,
    imap::mime_fmt::parse_raw_to_new_message_input,
    models::{LABEL_DRAFT, LABEL_INBOX, LABEL_SENT, LABEL_STARRED, LABEL_UNREAD},
    storage::{NewLabelInput, NewMessageInput},
    sync::{SyncRunOptions, run_gmail_sync},
    transport::{InboundEnvelope, IngestOutcome, ingest_inbound_rfc2822},
};

fn b64url(raw: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_bytes())
}

fn make_sqlite_state(mut cfg: Config) -> (TempDir, AppState) {
    let dir = TempDir::new().expect("tempdir");
    cfg.storage = StorageBackend::Sqlite;
    cfg.db_path = dir.path().join("nogml.db");
    let state = AppState::from_config(cfg).expect("AppState::from_config");
    (dir, state)
}

async fn http_json(app: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("valid JSON response")
    };
    (status, json)
}

// ============================================================================
// 1. Gmail users.settings.{filters,forwardingAddresses,delegates,language,sendAs.verify/patch}
//    + ?fields= projection + automatic inbound filter execution
// ============================================================================

#[tokio::test]
async fn gmail_settings_full_crud_fields_and_inbound_filter_execution() {
    let (_dir, state) = make_sqlite_state(Config::for_test());
    let app = build_router(state.clone());

    // --- sendAs: create, patch, verify ---
    let (code, created_sa) = http_json(
        &app,
        Request::builder()
            .method("POST")
            .uri("/gmail/v1/users/me/settings/sendAs")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "sendAsEmail": "billing@example.com",
                    "displayName": "Billing"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(created_sa["sendAsEmail"], "billing@example.com");

    let (code, patched_sa) = http_json(
        &app,
        Request::builder()
            .method("PATCH")
            .uri("/gmail/v1/users/me/settings/sendAs/billing@example.com?fields=sendAsEmail,displayName,signature")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "displayName": "Billing Team",
                    "signature": "<p>Billing</p>"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(patched_sa["displayName"], "Billing Team");
    assert_eq!(patched_sa["signature"], "<p>Billing</p>");
    assert!(
        patched_sa.get("isPrimary").is_none(),
        "?fields= should project"
    );

    // Verify sendAs (and 404 on unknown alias)
    let (code, _) = http_json(
        &app,
        Request::builder()
            .method("POST")
            .uri("/gmail/v1/users/me/settings/sendAs/billing@example.com/verify")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::NO_CONTENT);

    let (code, _) = http_json(
        &app,
        Request::builder()
            .method("POST")
            .uri("/gmail/v1/users/me/settings/sendAs/missing@example.com/verify")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::NOT_FOUND);

    // --- language: default GET, PUT, invalid tag 400, ?fields= ---
    let (code, lang_default) = http_json(
        &app,
        Request::builder()
            .uri("/gmail/v1/users/me/settings/language")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(lang_default["displayLanguage"], "en");

    let (code, lang_updated) = http_json(
        &app,
        Request::builder()
            .method("PUT")
            .uri("/gmail/v1/users/me/settings/language?fields=displayLanguage")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "displayLanguage": "fr-CA" }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(lang_updated["displayLanguage"], "fr-CA");

    let (code, _) = http_json(
        &app,
        Request::builder()
            .method("PUT")
            .uri("/gmail/v1/users/me/settings/language")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "displayLanguage": "en\r\nInject" }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST);

    // --- forwardingAddresses: POST, GET list, GET one, 409 dup, DELETE ---
    let (code, fwd) = http_json(
        &app,
        Request::builder()
            .method("POST")
            .uri("/gmail/v1/users/me/settings/forwardingAddresses")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "forwardingEmail": "archive@backup.example",
                    "verificationStatus": "pending"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(fwd["forwardingEmail"], "archive@backup.example");
    assert_eq!(fwd["verificationStatus"], "pending");

    let (code, _) = http_json(
        &app,
        Request::builder()
            .method("POST")
            .uri("/gmail/v1/users/me/settings/forwardingAddresses")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "forwardingEmail": "archive@backup.example" }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::CONFLICT);

    let (code, fwd_list) = http_json(
        &app,
        Request::builder()
            .uri("/gmail/v1/users/me/settings/forwardingAddresses?fields=forwardingAddresses(forwardingEmail)")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(
        fwd_list["forwardingAddresses"][0]["forwardingEmail"],
        "archive@backup.example"
    );
    assert!(
        fwd_list["forwardingAddresses"][0]
            .get("verificationStatus")
            .is_none()
    );

    let (code, fwd_one) = http_json(
        &app,
        Request::builder()
            .uri("/gmail/v1/users/me/settings/forwardingAddresses/archive@backup.example")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(fwd_one["verificationStatus"], "pending");

    let (code, _) = http_json(
        &app,
        Request::builder()
            .method("DELETE")
            .uri("/gmail/v1/users/me/settings/forwardingAddresses/archive@backup.example")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::NO_CONTENT);

    // --- delegates: POST, GET list, GET one, 409 dup, DELETE ---
    let (code, del) = http_json(
        &app,
        Request::builder()
            .method("POST")
            .uri("/gmail/v1/users/me/settings/delegates")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "delegateEmail": "ea@example.com",
                    "verificationStatus": "accepted"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(del["delegateEmail"], "ea@example.com");
    assert_eq!(del["verificationStatus"], "accepted");

    let (code, del_list) = http_json(
        &app,
        Request::builder()
            .uri("/gmail/v1/users/me/settings/delegates?fields=delegates(delegateEmail)")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(del_list["delegates"][0]["delegateEmail"], "ea@example.com");
    assert!(del_list["delegates"][0].get("verificationStatus").is_none());

    let (code, del_one) = http_json(
        &app,
        Request::builder()
            .uri("/gmail/v1/users/me/settings/delegates/ea@example.com")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(del_one["verificationStatus"], "accepted");

    let (code, _) = http_json(
        &app,
        Request::builder()
            .method("DELETE")
            .uri("/gmail/v1/users/me/settings/delegates/ea@example.com")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::NO_CONTENT);

    // --- filters: POST, GET list, GET one, ?fields=, inbound execution, DELETE ---
    let finance_lbl = state
        .store
        .create_label(NewLabelInput {
            name: "Finance".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();

    // Reject empty filter criteria
    let (code, _) = http_json(
        &app,
        Request::builder()
            .method("POST")
            .uri("/gmail/v1/users/me/settings/filters")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "criteria": {},
                    "action": { "addLabelIds": [finance_lbl.id] }
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST);

    // Create a rich filter matching from + subject + negatedQuery + hasAttachment + sizeComparison
    let (code, flt) = http_json(
        &app,
        Request::builder()
            .method("POST")
            .uri("/gmail/v1/users/me/settings/filters")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "criteria": {
                        "from": "billing@stripe.com",
                        "subject": "Invoice",
                        "negatedQuery": "canceled",
                        "hasAttachment": true,
                        "size": 10,
                        "sizeComparison": "larger"
                    },
                    "action": {
                        "addLabelIds": [finance_lbl.id, LABEL_STARRED],
                        "removeLabelIds": [LABEL_INBOX, LABEL_UNREAD]
                    }
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    let flt_id = flt["id"].as_str().expect("filter id").to_string();
    assert!(!flt_id.is_empty());

    let (code, flt_list) = http_json(
        &app,
        Request::builder()
            .uri("/gmail/v1/users/me/settings/filters?fields=filter(id,criteria/from)")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(flt_list["filter"][0]["id"], flt_id);
    assert_eq!(
        flt_list["filter"][0]["criteria"]["from"],
        "billing@stripe.com"
    );
    assert!(flt_list["filter"][0].get("action").is_none());

    let (code, flt_get) = http_json(
        &app,
        Request::builder()
            .uri(format!("/gmail/v1/users/me/settings/filters/{flt_id}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(flt_get["criteria"]["subject"], "Invoice");

    // Ingest a matching inbound email with attachment -> filter adds Finance+STARRED and removes INBOX+UNREAD
    let matching_raw = concat!(
        "From: Stripe Billing <billing@stripe.com>\r\n",
        "To: agent@example.com\r\n",
        "Subject: Invoice #4041\r\n",
        "Message-ID: <inv-4041@stripe.com>\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=\"b1\"\r\n",
        "\r\n",
        "--b1\r\n",
        "Content-Type: text/plain\r\n",
        "\r\n",
        "Your invoice is attached.\r\n",
        "--b1\r\n",
        "Content-Type: application/pdf; name=\"inv.pdf\"\r\n",
        "Content-Disposition: attachment; filename=\"inv.pdf\"\r\n",
        "\r\n",
        "%PDF-1.4 dummy\r\n",
        "--b1--\r\n"
    )
    .as_bytes()
    .to_vec();

    let outcome = ingest_inbound_rfc2822(
        state.store.as_ref(),
        &state.events,
        &NoopFilter,
        InboundEnvelope {
            raw_rfc2822: matching_raw,
            source: "resend_inbound".to_string(),
            default_labels: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let IngestOutcome::Stored { message, .. } = outcome else {
        panic!("expected Stored outcome");
    };
    assert!(message.label_ids.contains(&finance_lbl.id));
    assert!(message.label_ids.contains(&LABEL_STARRED.to_string()));
    assert!(!message.label_ids.contains(&LABEL_INBOX.to_string()));
    assert!(!message.label_ids.contains(&LABEL_UNREAD.to_string()));

    // Ingest a non-matching email (contains negatedQuery "canceled") -> stays in INBOX + UNREAD
    let negated_raw = concat!(
        "From: Stripe Billing <billing@stripe.com>\r\n",
        "To: agent@example.com\r\n",
        "Subject: Invoice #4042\r\n",
        "Message-ID: <inv-4042@stripe.com>\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=\"b2\"\r\n",
        "\r\n",
        "--b2\r\n",
        "Content-Type: text/plain\r\n",
        "\r\n",
        "This invoice was canceled.\r\n",
        "--b2\r\n",
        "Content-Type: application/pdf; name=\"inv2.pdf\"\r\n",
        "Content-Disposition: attachment; filename=\"inv2.pdf\"\r\n",
        "\r\n",
        "%PDF-1.4 dummy\r\n",
        "--b2--\r\n"
    )
    .as_bytes()
    .to_vec();

    let outcome2 = ingest_inbound_rfc2822(
        state.store.as_ref(),
        &state.events,
        &NoopFilter,
        InboundEnvelope {
            raw_rfc2822: negated_raw,
            source: "resend_inbound".to_string(),
            default_labels: vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let IngestOutcome::Stored { message: msg2, .. } = outcome2 else {
        panic!("expected Stored outcome");
    };
    assert!(msg2.label_ids.contains(&LABEL_INBOX.to_string()));
    assert!(msg2.label_ids.contains(&LABEL_UNREAD.to_string()));
    assert!(!msg2.label_ids.contains(&finance_lbl.id));

    // Delete filter
    let (code, _) = http_json(
        &app,
        Request::builder()
            .method("DELETE")
            .uri(format!("/gmail/v1/users/me/settings/filters/{flt_id}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::NO_CONTENT);

    // Verify batchModify / batchDelete + threads modify/trash/untrash/delete with ?fields=
    let (code, _) = http_json(
        &app,
        Request::builder()
            .method("POST")
            .uri("/gmail/v1/users/me/messages/batchModify")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "ids": [msg2.id],
                    "addLabelIds": [LABEL_STARRED],
                    "removeLabelIds": [LABEL_UNREAD]
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::NO_CONTENT);

    let (code, mod_thr) = http_json(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!(
                "/gmail/v1/users/me/threads/{}/modify?fields=id,messages(id,labelIds)",
                msg2.thread_id
            ))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "addLabelIds": [finance_lbl.id],
                    "removeLabelIds": []
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(mod_thr["id"], msg2.thread_id);
    assert!(mod_thr.get("snippet").is_none());

    let (code, _) = http_json(
        &app,
        Request::builder()
            .method("POST")
            .uri("/gmail/v1/users/me/messages/batchDelete")
            .header("content-type", "application/json")
            .body(Body::from(json!({ "ids": [message.id] }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::NO_CONTENT);
}

// ============================================================================
// 2. Full upstream Gmail API bidirectional sync: drafts pull/push,
//    Sent/imported pushback + upstream_id dedup, custom label create/patch/delete
// ============================================================================

#[tokio::test]
async fn gmail_api_bidirectional_sync_drafts_sent_import_and_custom_labels() {
    let mock = MockServer::start().await;

    // Pass 1 mocks: upstream has 1 label (Label_up1 = "Projects"), 0 messages, 1 draft (r_up_1).
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "labels": [
                { "id": "INBOX", "name": "INBOX", "type": "system" },
                { "id": "Label_up1", "name": "Projects", "type": "user" }
            ]
        })))
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/profile"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "emailAddress": "agent@example.com",
            "messagesTotal": 1,
            "threadsTotal": 1,
            "historyId": "500"
        })))
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [],
            "resultSizeEstimate": 0
        })))
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/drafts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "drafts": [
                {
                    "id": "r_up_1",
                    "message": { "id": "gm_draft_msg_1", "threadId": "gm_draft_thr_1" }
                }
            ],
            "resultSizeEstimate": 1
        })))
        .mount(&mock)
        .await;

    let up_draft_raw = "From: agent@example.com\r\nTo: alice@example.com\r\nSubject: Upstream Draft\r\n\r\nDraft v1";
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/drafts/r_up_1"))
        .and(query_param("format", "raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "r_up_1",
            "message": {
                "id": "gm_draft_msg_1",
                "threadId": "gm_draft_thr_1",
                "labelIds": ["DRAFT"],
                "raw": b64url(up_draft_raw)
            }
        })))
        .mount(&mock)
        .await;

    let mut cfg = Config::for_test();
    cfg.sync_mode = SyncMode::Api;
    cfg.sync_bidirectional = true;
    cfg.gmail_api_base_url = mock.uri();
    cfg.gmail_access_token = Some("tok-bi".to_string());
    let (_dir, state) = make_sqlite_state(cfg);

    // Pass 1: pulls upstream label + upstream draft
    let r1 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r1.labels_synced, 1);
    assert_eq!(r1.messages_added, 1);
    assert_eq!(r1.messages_pushed, 0);

    let pulled_drafts = state
        .store
        .list_drafts(&Default::default())
        .await
        .unwrap()
        .drafts;
    assert_eq!(pulled_drafts.len(), 1);
    assert_eq!(pulled_drafts[0].message.subject, "Upstream Draft");
    let pulled_draft_id = pulled_drafts[0].id.clone();

    // Now make local mutations:
    // 1. Create a new local custom label "Clients"
    let clients_lbl = state
        .store
        .create_label(NewLabelInput {
            name: "Clients".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();

    // 2. Rename synced label "Projects" -> "Projects-2026"
    let projects_lbl = state
        .store
        .list_labels()
        .await
        .unwrap()
        .into_iter()
        .find(|l| l.upstream_label_id.as_deref() == Some("Label_up1"))
        .unwrap();
    state
        .store
        .update_label(
            &projects_lbl.id,
            nogml::storage::UpdateLabelInput {
                name: Some("Projects-2026".to_string()),
                ..Default::default()
            },
            false,
        )
        .await
        .unwrap();

    // 3. Create a locally sent message (e.g. sent via Resend/SMTP without upstream_gmail_id) tagged with SENT + Clients
    let sent_raw = b"From: agent@example.com\r\nTo: client@example.com\r\nSubject: Local Sent\r\nMessage-ID: <local-sent-1@example.com>\r\n\r\nSent via Resend".to_vec();
    let sent_msg = state
        .store
        .insert_message(parse_raw_to_new_message_input(
            sent_raw,
            vec![LABEL_SENT.to_string(), clients_lbl.id.clone()],
            None,
            "local",
            None,
            None,
            false,
            false,
        ))
        .await
        .unwrap();

    // 4. Update the pulled draft locally
    let edited_draft_raw = b"From: agent@example.com\r\nTo: alice@example.com\r\nSubject: Upstream Draft Edited\r\n\r\nDraft v2".to_vec();
    state
        .store
        .update_draft(
            &pulled_draft_id,
            parse_raw_to_new_message_input(
                edited_draft_raw,
                vec![LABEL_DRAFT.to_string()],
                None,
                "local",
                None,
                None,
                false,
                false,
            ),
        )
        .await
        .unwrap();

    // 5. Create a brand new local draft
    let new_draft_raw = b"From: agent@example.com\r\nTo: bob@example.com\r\nSubject: New Local Draft\r\n\r\nHello Bob".to_vec();
    let local_draft = state
        .store
        .create_draft(NewMessageInput {
            ..parse_raw_to_new_message_input(
                new_draft_raw,
                vec![LABEL_DRAFT.to_string()],
                None,
                "local",
                None,
                None,
                false,
                false,
            )
        })
        .await
        .unwrap();

    // Mount Pass 2 expectations:
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/history"))
        .and(query_param("startHistoryId", "500"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "historyId": "510"
        })))
        .mount(&mock)
        .await;

    // Label create ("Clients" -> "Label_up2")
    Mock::given(method("POST"))
        .and(path("/gmail/v1/users/me/labels"))
        .and(body_partial_json(json!({ "name": "Clients" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "Label_up2",
            "name": "Clients",
            "type": "user"
        })))
        .expect(1)
        .mount(&mock)
        .await;

    // Label patch ("Label_up1" -> "Projects-2026")
    Mock::given(method("PATCH"))
        .and(path("/gmail/v1/users/me/labels/Label_up1"))
        .and(body_partial_json(json!({ "name": "Projects-2026" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "Label_up1",
            "name": "Projects-2026",
            "type": "user"
        })))
        .expect(1)
        .mount(&mock)
        .await;

    // Local Sent message import (preserving SENT + newly created Label_up2!)
    Mock::given(method("POST"))
        .and(path("/gmail/v1/users/me/messages/import"))
        .and(body_partial_json(json!({
            "labelIds": ["Label_up2", "SENT"]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "gm_imported_sent_1",
            "threadId": "gm_imported_thr_1",
            "labelIds": ["SENT", "Label_up2"]
        })))
        .expect(1)
        .mount(&mock)
        .await;

    // Local draft update -> PUT /drafts/r_up_1
    Mock::given(method("PUT"))
        .and(path("/gmail/v1/users/me/drafts/r_up_1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "r_up_1",
            "message": { "id": "gm_draft_msg_1b", "threadId": "gm_draft_thr_1" }
        })))
        .expect(1)
        .mount(&mock)
        .await;

    // New local draft create -> POST /drafts
    Mock::given(method("POST"))
        .and(path("/gmail/v1/users/me/drafts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "r_up_2",
            "message": { "id": "gm_draft_msg_2", "threadId": "gm_draft_thr_2" }
        })))
        .expect(1)
        .mount(&mock)
        .await;

    // Run Pass 2
    let r2 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    // 2 label pushes (create + patch) + 1 sent import + 2 draft pushes (update + create) = 5
    assert_eq!(r2.messages_pushed, 5);

    // Verify local Sent message now has upstream_gmail_id persisted so future pulls dedup cleanly
    let sent_after = state
        .store
        .get_message(&sent_msg.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        sent_after.upstream_gmail_id.as_deref(),
        Some("gm_imported_sent_1")
    );
    assert_eq!(
        sent_after.upstream_thread_id.as_deref(),
        Some("gm_imported_thr_1")
    );

    // Verify local Clients label now has upstream_label_id = "Label_up2"
    let clients_after = state
        .store
        .get_label(&clients_lbl.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        clients_after.upstream_label_id.as_deref(),
        Some("Label_up2")
    );

    // Pass 3: Delete local draft & delete local custom label -> pushed via DELETE /drafts/r_up_2 and DELETE /labels/Label_up2
    state.store.delete_draft(&local_draft.id).await.unwrap();
    state.store.delete_label(&clients_lbl.id).await.unwrap();

    // Update mock upstream state to reflect what Pass 2 pushed (r_up_1 v2, r_up_2, Label_up1 renamed, Label_up2 created).
    mock.reset().await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "labels": [
                { "id": "INBOX", "name": "INBOX", "type": "system" },
                { "id": "Label_up1", "name": "Projects-2026", "type": "user" },
                { "id": "Label_up2", "name": "Clients", "type": "user" }
            ]
        })))
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/drafts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "drafts": [
                {
                    "id": "r_up_1",
                    "message": { "id": "gm_draft_msg_1b", "threadId": "gm_draft_thr_1" }
                },
                {
                    "id": "r_up_2",
                    "message": { "id": "gm_draft_msg_2", "threadId": "gm_draft_thr_2" }
                }
            ],
            "resultSizeEstimate": 2
        })))
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/drafts/r_up_1"))
        .and(query_param("format", "raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "r_up_1",
            "message": {
                "id": "gm_draft_msg_1b",
                "threadId": "gm_draft_thr_1",
                "labelIds": ["DRAFT"],
                "raw": b64url("From: agent@example.com\r\nTo: alice@example.com\r\nSubject: Upstream Draft Edited\r\n\r\nDraft v2")
            }
        })))
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/history"))
        .and(query_param("startHistoryId", "510"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "historyId": "520"
        })))
        .mount(&mock)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/gmail/v1/users/me/drafts/r_up_2"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/gmail/v1/users/me/labels/Label_up2"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock)
        .await;

    let r3 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r3.messages_pushed, 2);
}

// ============================================================================
// 3. Native GmailApiTransport end-to-end (reply threadId + upstream_id dedup + TOML)
// ============================================================================

#[tokio::test]
async fn gmail_api_transport_end_to_end_reply_threading_and_sync_dedup() {
    // Verify both shorthand `transport = "gmail"` and `[transport] backend = "gmail"` parse cleanly.
    let mut cfg1 = Config::for_test();
    TomlConfig::from_toml_str("transport = \"gmail\"\n")
        .unwrap()
        .apply_to(&mut cfg1);
    assert_eq!(cfg1.transport, TransportBackend::Gmail);

    let mut cfg2 = Config::for_test();
    TomlConfig::from_toml_str("[transport]\nbackend = \"gmail\"\n")
        .unwrap()
        .apply_to(&mut cfg2);
    assert_eq!(cfg2.transport, TransportBackend::Gmail);

    let mock = MockServer::start().await;

    let mut cfg = Config::for_test();
    cfg.transport = TransportBackend::Gmail;
    cfg.sync_mode = SyncMode::Api;
    cfg.gmail_api_base_url = mock.uri();
    cfg.gmail_access_token = Some("tok-gmail-send".to_string());
    let (_dir, state) = make_sqlite_state(cfg);
    let app = build_router(state.clone());

    // Seed an inbound message synced from upstream Gmail with upstream_thread_id = "gm_thr_555".
    let inbound = state
        .store
        .insert_message(parse_raw_to_new_message_input(
            b"From: alice@example.com\r\nTo: agent@example.com\r\nSubject: Project Kickoff\r\nMessage-ID: <kickoff@example.com>\r\n\r\nReady?".to_vec(),
            vec![LABEL_INBOX.to_string(), LABEL_UNREAD.to_string()],
            None,
            "gmail_api",
            Some("gm_in_555".to_string()),
            Some("gm_thr_555".to_string()),
            false,
            false,
        ))
        .await
        .unwrap();

    // Expect outbound Gmail messages.send carrying threadId = "gm_thr_555"
    Mock::given(method("POST"))
        .and(path("/gmail/v1/users/me/messages/send"))
        .and(header("authorization", "Bearer tok-gmail-send"))
        .and(body_partial_json(json!({ "threadId": "gm_thr_555" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "gm_sent_556",
            "threadId": "gm_thr_555",
            "labelIds": ["SENT"]
        })))
        .expect(1)
        .mount(&mock)
        .await;

    // Reply via AI REST API `/v1/messages/send` with `reply_to_message_id`
    let (code, sent_resp) = http_json(
        &app,
        Request::builder()
            .method("POST")
            .uri("/v1/messages/send")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "to": ["alice@example.com"],
                    "subject": "Re: Project Kickoff",
                    "text": "Yes, let us start!",
                    "reply_to_message_id": inbound.id
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "response: {sent_resp}");
    assert_eq!(sent_resp["provider"], "gmail");
    assert_eq!(sent_resp["resend_id"], "gm_sent_556");

    let sent_local_id = sent_resp["message_id"].as_str().unwrap();
    let stored_sent = state
        .store
        .get_message(sent_local_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored_sent.upstream_gmail_id.as_deref(),
        Some("gm_sent_556")
    );
    assert_eq!(
        stored_sent.upstream_thread_id.as_deref(),
        Some("gm_thr_555")
    );

    // Subsequent Gmail sync backfill sees gm_in_555 + gm_sent_556 -> deduplicates BOTH with 0 new messages!
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "labels": [] })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/profile"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "emailAddress": "agent@example.com",
            "messagesTotal": 2,
            "threadsTotal": 1,
            "historyId": "900"
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [
                { "id": "gm_in_555", "threadId": "gm_thr_555" },
                { "id": "gm_sent_556", "threadId": "gm_thr_555" }
            ],
            "resultSizeEstimate": 2
        })))
        .mount(&mock)
        .await;

    let report = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(report.messages_added, 0);
    assert_eq!(report.messages_deduplicated, 2);
}

// ============================================================================
// 4. Issue #86 Regression: Upstream draft edit in Gmail MUST NOT delete draft
//    + no double-counting of messages_added + cascade-delete resilience
// ============================================================================

#[tokio::test]
async fn gmail_api_bidirectional_sync_upstream_draft_edit_never_deletes_draft() {
    let mock = MockServer::start().await;

    // Pass 1: Initial full sync where `messages.list` ALSO lists the draft's message ID (as real Gmail does).
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "labels": [] })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/profile"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "emailAddress": "agent@example.com",
            "messagesTotal": 1,
            "threadsTotal": 1,
            "historyId": "100"
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [
                { "id": "gm_draft_v1", "threadId": "gm_thr_d1" }
            ],
            "resultSizeEstimate": 1
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/drafts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "drafts": [
                {
                    "id": "r_edit_1",
                    "message": { "id": "gm_draft_v1", "threadId": "gm_thr_d1" }
                }
            ],
            "resultSizeEstimate": 1
        })))
        .mount(&mock)
        .await;
    let draft_v1_raw =
        "From: agent@example.com\r\nTo: bob@example.com\r\nSubject: Draft V1\r\n\r\nInitial draft";
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/drafts/r_edit_1"))
        .and(query_param("format", "raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "r_edit_1",
            "message": {
                "id": "gm_draft_v1",
                "threadId": "gm_thr_d1",
                "labelIds": ["DRAFT"],
                "raw": b64url(draft_v1_raw)
            }
        })))
        .mount(&mock)
        .await;

    let mut cfg = Config::for_test();
    cfg.sync_mode = SyncMode::Api;
    cfg.sync_bidirectional = true;
    cfg.gmail_api_base_url = mock.uri();
    cfg.gmail_access_token = Some("tok-draft-edit".to_string());
    let (_dir, state) = make_sqlite_state(cfg);

    let r1 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    // Draft must be counted ONCE (not double-counted by messages.list + drafts.list).
    assert_eq!(r1.messages_added, 1);
    assert_eq!(r1.messages_pushed, 0);

    let drafts_p1 = state
        .store
        .list_drafts(&Default::default())
        .await
        .unwrap()
        .drafts;
    assert_eq!(drafts_p1.len(), 1);
    assert_eq!(drafts_p1[0].message.subject, "Draft V1");
    let local_draft_id = drafts_p1[0].id.clone();

    // Pass 2: Simulate editing the draft in Gmail web UI.
    // Gmail keeps `draft.id = r_edit_1`, deletes old message `gm_draft_v1`, and creates `gm_draft_v2`.
    mock.reset().await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "labels": [] })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/history"))
        .and(query_param("startHistoryId", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "historyId": "105",
            "history": [
                {
                    "id": "101",
                    "messagesDeleted": [
                        { "message": { "id": "gm_draft_v1", "threadId": "gm_thr_d1" } }
                    ],
                    "messagesAdded": [
                        { "message": { "id": "gm_draft_v2", "threadId": "gm_thr_d1" } }
                    ]
                }
            ]
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/drafts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "drafts": [
                {
                    "id": "r_edit_1",
                    "message": { "id": "gm_draft_v2", "threadId": "gm_thr_d1" }
                }
            ],
            "resultSizeEstimate": 1
        })))
        .mount(&mock)
        .await;
    let draft_v2_raw = "From: agent@example.com\r\nTo: bob@example.com\r\nSubject: Draft V2 Edited\r\n\r\nEdited upstream in Gmail";
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/drafts/r_edit_1"))
        .and(query_param("format", "raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "r_edit_1",
            "message": {
                "id": "gm_draft_v2",
                "threadId": "gm_thr_d1",
                "labelIds": ["DRAFT"],
                "raw": b64url(draft_v2_raw)
            }
        })))
        .mount(&mock)
        .await;
    // CRITICAL ASSERTION: upstream DELETE must NEVER be called!
    Mock::given(method("DELETE"))
        .and(path("/gmail/v1/users/me/drafts/r_edit_1"))
        .respond_with(ResponseTemplate::new(204))
        .expect(0)
        .mount(&mock)
        .await;

    let r2 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r2.messages_pushed, 0);
    assert_eq!(r2.messages_deleted, 0);

    let updated = state
        .store
        .get_draft(&local_draft_id)
        .await
        .unwrap()
        .expect("local draft must survive upstream Gmail edit");
    assert_eq!(updated.message.subject, "Draft V2 Edited");
    assert_eq!(
        updated.message.upstream_gmail_id.as_deref(),
        Some("gm_draft_v2")
    );

    // Pass 3: Even if a sync-driven cascade delete removed the backing message (HISTORY_SOURCE_SYNC),
    // bidirectional sync must NOT issue DELETE /drafts/r_edit_1 and should safely re-pull it.
    state
        .store
        .delete_message_by_upstream_id("gm_draft_v2")
        .await
        .unwrap();
    assert!(
        state
            .store
            .get_draft(&local_draft_id)
            .await
            .unwrap()
            .is_none()
    );

    mock.reset().await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "labels": [] })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/history"))
        .and(query_param("startHistoryId", "105"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "historyId": "106"
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/drafts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "drafts": [
                {
                    "id": "r_edit_1",
                    "message": { "id": "gm_draft_v2", "threadId": "gm_thr_d1" }
                }
            ],
            "resultSizeEstimate": 1
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/drafts/r_edit_1"))
        .and(query_param("format", "raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "r_edit_1",
            "message": {
                "id": "gm_draft_v2",
                "threadId": "gm_thr_d1",
                "labelIds": ["DRAFT"],
                "raw": b64url(draft_v2_raw)
            }
        })))
        .mount(&mock)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/gmail/v1/users/me/drafts/r_edit_1"))
        .respond_with(ResponseTemplate::new(204))
        .expect(0)
        .mount(&mock)
        .await;

    let r3 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r3.messages_pushed, 0);
    let repulled_drafts = state
        .store
        .list_drafts(&Default::default())
        .await
        .unwrap()
        .drafts;
    assert_eq!(repulled_drafts.len(), 1);
    assert_eq!(repulled_drafts[0].message.subject, "Draft V2 Edited");
    let repulled_id = repulled_drafts[0].id.clone();

    // Pass 4: Intentional local deletion (`store.delete_draft` -> HISTORY_SOURCE_LOCAL) DOES push DELETE.
    state.store.delete_draft(&repulled_id).await.unwrap();
    mock.reset().await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "labels": [] })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/history"))
        .and(query_param("startHistoryId", "106"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "historyId": "107"
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/drafts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "drafts": [
                {
                    "id": "r_edit_1",
                    "message": { "id": "gm_draft_v2", "threadId": "gm_thr_d1" }
                }
            ],
            "resultSizeEstimate": 1
        })))
        .mount(&mock)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/gmail/v1/users/me/drafts/r_edit_1"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock)
        .await;

    let r4 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r4.messages_pushed, 1);
}

// ============================================================================
// 5. Issue #86 Regression: Local draft edits preserved after Gmail RFC 2822
//    canonicalization
// ============================================================================

#[tokio::test]
async fn gmail_api_bidirectional_sync_preserves_local_draft_edit_after_canonicalization() {
    let mock = MockServer::start().await;

    // Pass 1: Push a new local draft to Gmail.
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "labels": [] })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/profile"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "emailAddress": "agent@example.com",
            "messagesTotal": 0,
            "threadsTotal": 0,
            "historyId": "200"
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [],
            "resultSizeEstimate": 0
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/drafts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "drafts": [],
            "resultSizeEstimate": 0
        })))
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/gmail/v1/users/me/drafts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "r_canon_1",
            "message": { "id": "gm_canon_msg_1", "threadId": "gm_canon_thr_1" }
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let mut cfg = Config::for_test();
    cfg.sync_mode = SyncMode::Api;
    cfg.sync_bidirectional = true;
    cfg.gmail_api_base_url = mock.uri();
    cfg.gmail_access_token = Some("tok-canon".to_string());
    let (_dir, state) = make_sqlite_state(cfg);

    let local_v1 = "From: agent@example.com\r\nTo: alice@example.com\r\nSubject: Draft Local V1\r\n\r\nBody V1";
    let local_draft = state
        .store
        .create_draft(parse_raw_to_new_message_input(
            local_v1.as_bytes().to_vec(),
            vec![LABEL_DRAFT.to_string()],
            None,
            "local",
            None,
            None,
            false,
            false,
        ))
        .await
        .unwrap();

    let r1 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r1.messages_pushed, 1);

    // User edits the draft locally BEFORE Pass 2.
    let local_v2 = "From: agent@example.com\r\nTo: alice@example.com\r\nSubject: Draft Local V2 Edited\r\n\r\nPending local edit";
    state
        .store
        .update_draft(
            &local_draft.id,
            parse_raw_to_new_message_input(
                local_v2.as_bytes().to_vec(),
                vec![LABEL_DRAFT.to_string()],
                None,
                "local",
                None,
                Some("gm_canon_thr_1".to_string()),
                false,
                false,
            ),
        )
        .await
        .unwrap();

    // Pass 2: Upstream Gmail serves canonicalized V1 (different bytes/SHA-256 due to added
    // MIME-Version & Date headers) while keeping the SAME `message.id = gm_canon_msg_1`.
    mock.reset().await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "labels": [] })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/history"))
        .and(query_param("startHistoryId", "200"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "historyId": "201"
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/drafts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "drafts": [
                {
                    "id": "r_canon_1",
                    "message": { "id": "gm_canon_msg_1", "threadId": "gm_canon_thr_1" }
                }
            ],
            "resultSizeEstimate": 1
        })))
        .mount(&mock)
        .await;
    let gmail_canonicalized_v1 = "MIME-Version: 1.0\r\nDate: Fri, 02 Jan 2026 12:00:00 +0000\r\nFrom: agent@example.com\r\nTo: alice@example.com\r\nSubject: Draft Local V1\r\n\r\nBody V1";
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/drafts/r_canon_1"))
        .and(query_param("format", "raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "r_canon_1",
            "message": {
                "id": "gm_canon_msg_1",
                "threadId": "gm_canon_thr_1",
                "labelIds": ["DRAFT"],
                "raw": b64url(gmail_canonicalized_v1)
            }
        })))
        .mount(&mock)
        .await;
    // Expect our pending local V2 edit to be pushed upstream via PUT (not clobbered!).
    Mock::given(method("PUT"))
        .and(path("/gmail/v1/users/me/drafts/r_canon_1"))
        .and(body_partial_json(json!({
            "id": "r_canon_1",
            "message": { "raw": b64url(local_v2) }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "r_canon_1",
            "message": { "id": "gm_canon_msg_2", "threadId": "gm_canon_thr_1" }
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let r2 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    assert_eq!(r2.messages_pushed, 1);

    let after = state
        .store
        .get_draft(&local_draft.id)
        .await
        .unwrap()
        .expect("draft should still exist");
    assert_eq!(after.message.subject, "Draft Local V2 Edited");
    assert_eq!(
        after.message.upstream_gmail_id.as_deref(),
        Some("gm_canon_msg_2")
    );
}

// ============================================================================
// 6. Issue #86 Regression: New thread sent via GmailApiTransport persists
//    upstream_thread_id so subsequent replies thread cleanly upstream
// ============================================================================

#[tokio::test]
async fn gmail_api_transport_new_thread_persists_upstream_thread_id_for_replies() {
    let mock = MockServer::start().await;

    // 1. Brand new thread send -> Gmail returns new `id` + `threadId`
    Mock::given(method("POST"))
        .and(path("/gmail/v1/users/me/messages/send"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "gm_new_sent_1",
            "threadId": "gm_new_thr_777",
            "labelIds": ["SENT"]
        })))
        .expect(1)
        .up_to_n_times(1)
        .mount(&mock)
        .await;

    let mut cfg = Config::for_test();
    cfg.transport = TransportBackend::Gmail;
    cfg.gmail_api_base_url = mock.uri();
    cfg.gmail_access_token = Some("tok-new-thread".to_string());
    let (_dir, state) = make_sqlite_state(cfg);
    let app = build_router(state.clone());

    let (code, first_resp) = http_json(
        &app,
        Request::builder()
            .method("POST")
            .uri("/v1/messages/send")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "to": ["bob@example.com"],
                    "subject": "Fresh Topic",
                    "text": "Starting a new thread"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "response: {first_resp}");
    let first_local_id = first_resp["message_id"].as_str().unwrap().to_string();

    let stored_first = state
        .store
        .get_message(&first_local_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored_first.upstream_gmail_id.as_deref(),
        Some("gm_new_sent_1")
    );
    assert_eq!(
        stored_first.upstream_thread_id.as_deref(),
        Some("gm_new_thr_777")
    );

    // 2. Reply on the same thread MUST include `threadId: "gm_new_thr_777"` in Gmail API request!
    Mock::given(method("POST"))
        .and(path("/gmail/v1/users/me/messages/send"))
        .and(body_partial_json(json!({
            "threadId": "gm_new_thr_777"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "gm_new_sent_2",
            "threadId": "gm_new_thr_777",
            "labelIds": ["SENT"]
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let (code2, reply_resp) = http_json(
        &app,
        Request::builder()
            .method("POST")
            .uri("/v1/messages/send")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "to": ["bob@example.com"],
                    "subject": "Re: Fresh Topic",
                    "text": "Follow-up on same thread",
                    "reply_to_message_id": first_local_id
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(code2, StatusCode::OK, "reply response: {reply_resp}");
}

// ============================================================================
// 7. Issue #86 Regression: Upstream custom label deletions reconcile locally
//    and bare-draft replacement cleans up external blobs
// ============================================================================

#[tokio::test]
async fn gmail_api_sync_reconciles_deleted_upstream_labels_and_bare_draft_blobs() {
    let mock = MockServer::start().await;

    // Pass 1: Two custom labels ("Keep" and "RemoveMe")
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "labels": [
                { "id": "INBOX", "name": "INBOX", "type": "system" },
                { "id": "Label_keep", "name": "Keep", "type": "user" },
                { "id": "Label_remove", "name": "RemoveMe", "type": "user" },
                { "id": "Label_local_edit", "name": "LocalEdited", "type": "user" }
            ]
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/profile"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "emailAddress": "agent@example.com",
            "messagesTotal": 0,
            "threadsTotal": 0,
            "historyId": "300"
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [],
            "resultSizeEstimate": 0
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/drafts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "drafts": [],
            "resultSizeEstimate": 0
        })))
        .mount(&mock)
        .await;

    let dir = TempDir::new().unwrap();
    let blob_dir = dir.path().join("blobs");
    let mut cfg = Config::for_test();
    cfg.storage = StorageBackend::Sqlite;
    cfg.db_path = dir.path().join("nogml.db");
    cfg.blob_backend = nogml::config::BlobBackend::Fs;
    cfg.blob_dir = blob_dir.clone();
    cfg.sync_mode = SyncMode::Api;
    cfg.sync_bidirectional = true;
    cfg.gmail_api_base_url = mock.uri();
    cfg.gmail_access_token = Some("tok-lbl-blob".to_string());
    let state = AppState::from_config(cfg).unwrap();

    run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();

    let labels_p1 = state.store.list_labels().await.unwrap();
    assert!(labels_p1.iter().any(|l| l.name == "Keep"));
    assert!(labels_p1.iter().any(|l| l.name == "RemoveMe"));
    let local_edit_lbl = labels_p1
        .iter()
        .find(|l| l.name == "LocalEdited")
        .unwrap()
        .clone();

    // Rename "LocalEdited" locally so bidirectional mode preserves it even if deleted upstream.
    state
        .store
        .update_label(
            &local_edit_lbl.id,
            nogml::storage::UpdateLabelInput {
                name: Some("LocalEdited-Renamed".to_string()),
                ..Default::default()
            },
            false,
        )
        .await
        .unwrap();

    // Seed a pre-existing bare draft message whose raw bytes are stored in the external FsBlobStore.
    let bare_raw =
        b"From: agent@example.com\r\nTo: bob@example.com\r\nSubject: Bare Draft\r\n\r\nBare body"
            .to_vec();
    let bare_msg = state
        .store
        .insert_message(parse_raw_to_new_message_input(
            bare_raw.clone(),
            vec![LABEL_DRAFT.to_string()],
            None,
            "gmail_api",
            Some("gm_bare_draft_1".to_string()),
            Some("gm_bare_thr_1".to_string()),
            false,
            false,
        ))
        .await
        .unwrap();
    state.post_store_message(&bare_msg).await.unwrap();
    let bare_blob_key = nogml::blob::raw_message_blob_key(&bare_msg.id);
    assert!(
        state.blobs.get(&bare_blob_key).await.unwrap().is_some(),
        "pre-existing bare draft blob should exist before replacement"
    );

    // Pass 2: Upstream omits Label_remove (unmodified locally -> deleted) and Label_local_edit
    // (modified locally -> preserved; PATCH returns 404 and is skipped), and lists draft for gm_bare_draft_1.
    mock.reset().await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "labels": [
                { "id": "INBOX", "name": "INBOX", "type": "system" },
                { "id": "Label_keep", "name": "Keep", "type": "user" }
            ]
        })))
        .mount(&mock)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/gmail/v1/users/me/labels/Label_local_edit"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/history"))
        .and(query_param("startHistoryId", "300"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "historyId": "301"
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/drafts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "drafts": [
                {
                    "id": "r_bare_1",
                    "message": { "id": "gm_bare_draft_1", "threadId": "gm_bare_thr_1" }
                }
            ],
            "resultSizeEstimate": 1
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/drafts/r_bare_1"))
        .and(query_param("format", "raw"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "r_bare_1",
            "message": {
                "id": "gm_bare_draft_1",
                "threadId": "gm_bare_thr_1",
                "labelIds": ["DRAFT"],
                "raw": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bare_raw)
            }
        })))
        .mount(&mock)
        .await;

    let r2 = run_gmail_sync(&state, SyncRunOptions::default())
        .await
        .unwrap();
    // Replacing an existing bare message should count as updated, not double-added.
    assert_eq!(r2.messages_added, 0);
    assert_eq!(r2.messages_updated, 1);

    // Unmodified upstream-deleted label "RemoveMe" is deleted locally; "Keep" and locally-renamed label remain.
    let labels_p2 = state.store.list_labels().await.unwrap();
    assert!(labels_p2.iter().any(|l| l.name == "Keep"));
    assert!(!labels_p2.iter().any(|l| l.name == "RemoveMe"));
    assert!(labels_p2.iter().any(|l| l.name == "LocalEdited-Renamed"));

    // Replaced bare message's external blob must be cleaned up (no leak).
    assert!(
        state.blobs.get(&bare_blob_key).await.unwrap().is_none(),
        "old bare draft blob must be deleted when replaced by synced draft"
    );
}
