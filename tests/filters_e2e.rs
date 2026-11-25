//! Integration tests for built-in `InboundFilter` backends:
//! - `AuthResultsFilter`
//! - `RspamdFilter` (via `wiremock`)
//! - `LlmTriageFilter` (via `wiremock`)
//! - `FilterChain` ordering, short-circuiting, mutation accumulation, and `/v1/capabilities`

use std::time::Duration;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, header, method, path},
};

use nogml::{
    AppState, build_router,
    config::{AuthFailAction, Config, RspamdRejectAction},
    filter::{
        FilterDecision, InboundFilter, InboundMessage, LABEL_AUTH_FAIL, LlmTriageConfig,
        LlmTriageFilter, RspamdConfig, RspamdFilter, open_filter,
    },
};

fn sample_inbound(raw: &[u8]) -> InboundMessage {
    InboundMessage {
        raw_rfc2822: raw.to_vec(),
        headers: vec![],
        text_body: "Hello, your invoice #42 is ready for review.".to_string(),
        html_body: None,
        from: "billing@vendor.example".to_string(),
        to: vec!["agent@example.com".to_string()],
        subject: "Invoice #42".to_string(),
        authentication_results: None,
        sender_ip: Some("203.0.113.10".to_string()),
        source: "resend_inbound".to_string(),
        provider_id: Some("re_1".to_string()),
    }
}

#[tokio::test]
async fn rspamd_filter_allow_spam_score_add_header_reject_and_headers() {
    let mock = MockServer::start().await;
    let raw = b"From: billing@vendor.example\r\nSubject: Invoice\r\n\r\nBody";

    // 1. Allow (`no action`, low score) + verifies Password & IP headers
    Mock::given(method("POST"))
        .and(path("/checkv2"))
        .and(header("Password", "rspamd-secret"))
        .and(header("IP", "203.0.113.10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "score": 1.25,
            "required_score": 15.0,
            "action": "no action",
            "symbols": {
                "R_SPF_ALLOW": { "name": "R_SPF_ALLOW", "score": -0.2 }
            }
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let mut cfg = RspamdConfig::new(mock.uri());
    cfg.password = Some("rspamd-secret".to_string());
    let filter = RspamdFilter::new(cfg.clone());
    assert_eq!(filter.backend_name(), "rspamd");

    let decision = filter.evaluate(&sample_inbound(raw)).await.unwrap();
    assert_eq!(decision, FilterDecision::Allow);
    mock.reset().await;

    // 2. Spam via `add header` action
    Mock::given(method("POST"))
        .and(path("/checkv2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "score": 7.4,
            "required_score": 15.0,
            "action": "add header",
            "symbols": {
                "BAYES_SPAM": { "name": "BAYES_SPAM", "score": 5.1 },
                "FORGED_SENDER": { "name": "FORGED_SENDER", "score": 2.3 }
            }
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let decision = filter.evaluate(&sample_inbound(raw)).await.unwrap();
    match decision {
        FilterDecision::Spam { score, reason } => {
            assert!((score - 7.4).abs() < 0.01);
            assert!(reason.contains("BAYES_SPAM"));
            assert!(reason.contains("add header"));
        }
        other => panic!("expected Spam, got {other:?}"),
    }
    mock.reset().await;

    // 3. Spam via configurable `spam_threshold` even when Rspamd says `no action`
    Mock::given(method("POST"))
        .and(path("/checkv2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "score": 6.5,
            "required_score": 15.0,
            "action": "no action",
            "symbols": {
                "SUSPICIOUS_LINK": { "name": "SUSPICIOUS_LINK", "score": 6.5 }
            }
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let mut threshold_cfg = cfg.clone();
    threshold_cfg.spam_threshold = Some(6.0);
    let threshold_filter = RspamdFilter::new(threshold_cfg);
    let decision = threshold_filter
        .evaluate(&sample_inbound(raw))
        .await
        .unwrap();
    assert!(matches!(
        decision,
        FilterDecision::Spam { score, .. } if (score - 6.5).abs() < 0.01
    ));
    mock.reset().await;

    // 4. Reject action (default Reject, and configurable Spam override)
    Mock::given(method("POST"))
        .and(path("/checkv2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "score": 18.0,
            "required_score": 15.0,
            "action": "reject",
            "symbols": {
                "RBL_SPAMHAUS": { "name": "RBL_SPAMHAUS", "score": 10.0 }
            }
        })))
        .expect(2)
        .mount(&mock)
        .await;

    let decision = filter.evaluate(&sample_inbound(raw)).await.unwrap();
    assert!(matches!(
        decision,
        FilterDecision::Reject { ref reason } if reason.contains("RBL_SPAMHAUS")
    ));

    let mut spam_on_reject_cfg = cfg.clone();
    spam_on_reject_cfg.reject_action = RspamdRejectAction::Spam;
    let spam_on_reject_filter = RspamdFilter::new(spam_on_reject_cfg);
    let decision = spam_on_reject_filter
        .evaluate(&sample_inbound(raw))
        .await
        .unwrap();
    assert!(matches!(decision, FilterDecision::Spam { score, .. } if score >= 18.0));
}

#[tokio::test]
async fn rspamd_filter_timeout_fails_open_by_default_and_rejects_when_fail_closed() {
    let mock = MockServer::start().await;
    let raw = b"From: a@example.com\r\nSubject: Slow\r\n\r\nHi";

    Mock::given(method("POST"))
        .and(path("/checkv2"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(350))
                .set_body_json(json!({
                    "score": 25.0,
                    "action": "reject"
                })),
        )
        .mount(&mock)
        .await;

    let mut open_cfg = RspamdConfig::new(mock.uri());
    open_cfg.timeout = Duration::from_millis(75);
    open_cfg.fail_closed = false;
    let open_filter = RspamdFilter::new(open_cfg);
    assert_eq!(
        open_filter.evaluate(&sample_inbound(raw)).await.unwrap(),
        FilterDecision::Allow
    );

    let mut closed_cfg = RspamdConfig::new(mock.uri());
    closed_cfg.timeout = Duration::from_millis(75);
    closed_cfg.fail_closed = true;
    let closed_filter = RspamdFilter::new(closed_cfg);
    assert!(matches!(
        closed_filter.evaluate(&sample_inbound(raw)).await.unwrap(),
        FilterDecision::Reject { ref reason } if reason.contains("fail_closed")
    ));
}

#[tokio::test]
async fn llm_triage_filter_mutate_spam_sanitizes_labels_and_fails_open() {
    let mock = MockServer::start().await;
    let mut msg = sample_inbound(b"From: promo@shop.example\r\nSubject: Sale\r\n\r\nSave 50%!");
    // Include BiDi override & control chars to verify sanitization before sending to LLM.
    msg.subject = "50% off\u{202E}now\x07!".to_string();
    msg.text_body = "A".repeat(500);

    // 1. Mutate with labels + skip_inbox + drops unsafe labels
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(header("authorization", "Bearer llm-test-key"))
        .and(body_string_contains("gpt-4o-mini"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{
                "message": {
                    "content": json!({
                        "action": "mutate",
                        "add_labels": [
                            "CATEGORY_PROMOTIONS",
                            "Deals-2026",
                            "../etc/passwd",
                            "SENT",
                            "bad\nlabel"
                        ],
                        "remove_labels": ["UNREAD", "bad/slash"],
                        "skip_inbox": true,
                        "reason": "marketing newsletter"
                    }).to_string()
                }
            }]
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let mut cfg = LlmTriageConfig::new(mock.uri(), "gpt-4o-mini");
    cfg.api_key = Some("llm-test-key".to_string());
    cfg.max_body_chars = 120;
    let filter = LlmTriageFilter::new(cfg.clone());
    assert_eq!(filter.backend_name(), "llm_triage");

    let decision = filter.evaluate(&msg).await.unwrap();
    assert_eq!(
        decision,
        FilterDecision::Mutate {
            add_labels: vec!["CATEGORY_PROMOTIONS".to_string(), "Deals-2026".to_string()],
            remove_labels: vec!["UNREAD".to_string()],
            skip_inbox: true,
        }
    );
    mock.reset().await;

    // 2. Spam classification (also verifies markdown fenced JSON tolerance)
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{
                "message": {
                    "content": "```json\n{\"action\":\"spam\",\"add_labels\":[],\"remove_labels\":[],\"skip_inbox\":false,\"reason\":\"phishing lure\"}\n```"
                }
            }]
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let decision = filter.evaluate(&msg).await.unwrap();
    assert!(matches!(
        decision,
        FilterDecision::Spam { ref reason, .. } if reason == "phishing lure"
    ));
    mock.reset().await;

    // 3. Invalid JSON from LLM fails open to Allow
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{
                "message": {
                    "content": "Sorry, I cannot classify this email."
                }
            }]
        })))
        .expect(1)
        .mount(&mock)
        .await;

    assert_eq!(filter.evaluate(&msg).await.unwrap(), FilterDecision::Allow);
    mock.reset().await;

    // 4. Timeout fails open to Allow (never drops inbound mail)
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(350))
                .set_body_json(json!({
                    "choices": [{
                        "message": {
                            "content": "{\"action\":\"spam\",\"reason\":\"late\"}"
                        }
                    }]
                })),
        )
        .mount(&mock)
        .await;

    let mut fast_timeout_cfg = cfg;
    fast_timeout_cfg.timeout = Duration::from_millis(75);
    let timeout_filter = LlmTriageFilter::new(fast_timeout_cfg);
    assert_eq!(
        timeout_filter.evaluate(&msg).await.unwrap(),
        FilterDecision::Allow
    );
}

#[tokio::test]
async fn configured_filter_chain_orders_short_circuits_and_reports_capabilities() {
    let rspamd_mock = MockServer::start().await;
    let llm_mock = MockServer::start().await;

    let mut cfg = Config::for_test();
    cfg.filter_auth_results = true;
    cfg.filter_dmarc_fail_action = AuthFailAction::Reject;
    cfg.filter_spf_fail_action = AuthFailAction::Tag;
    cfg.filter_dkim_fail_action = AuthFailAction::Tag;
    cfg.rspamd_url = Some(rspamd_mock.uri());
    cfg.llm_triage_base_url = Some(llm_mock.uri());
    cfg.llm_triage_model = "triage-model".to_string();

    // 1. Verify deterministic order in open_filter and GET /v1/capabilities
    let chain = open_filter(&cfg);
    assert_eq!(
        chain.active_filters(),
        vec!["auth_results", "rspamd", "llm_triage"]
    );

    let state = AppState::from_config(cfg.clone()).unwrap();
    let app = build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/capabilities")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let caps: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(caps["backends"]["filter"], "auth_results,rspamd,llm_triage");
    assert_eq!(
        caps["active_filters"],
        json!(["auth_results", "rspamd", "llm_triage"])
    );

    // 2. Short-circuit at AuthResultsFilter (Reject): neither Rspamd nor LLM is called!
    Mock::given(method("POST"))
        .and(path("/checkv2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "score": 0.0,
            "action": "no action"
        })))
        .expect(0)
        .mount(&rspamd_mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{ "message": { "content": "{\"action\":\"allow\"}" } }]
        })))
        .expect(0)
        .mount(&llm_mock)
        .await;

    let mut dmarc_fail_msg = sample_inbound(b"From: spoof@evil.example\r\n\r\nHi");
    dmarc_fail_msg.authentication_results =
        Some("mx.example.com; spf=pass; dkim=pass; dmarc=fail".to_string());

    let decision = chain.evaluate(&dmarc_fail_msg).await.unwrap();
    assert!(matches!(decision, FilterDecision::Reject { .. }));
    rspamd_mock.verify().await;
    llm_mock.verify().await;
    rspamd_mock.reset().await;
    llm_mock.reset().await;

    // 3. Short-circuit at RspamdFilter (Spam): AuthResults tags, Rspamd marks Spam, LLM is NOT called!
    Mock::given(method("POST"))
        .and(path("/checkv2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "score": 11.2,
            "required_score": 10.0,
            "action": "add header",
            "symbols": { "BAYES_SPAM": { "score": 6.0 } }
        })))
        .expect(1)
        .mount(&rspamd_mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{ "message": { "content": "{\"action\":\"allow\"}" } }]
        })))
        .expect(0)
        .mount(&llm_mock)
        .await;

    let mut spf_fail_msg = sample_inbound(b"From: spam@bad.example\r\n\r\nBuy now");
    spf_fail_msg.authentication_results =
        Some("mx.example.com; spf=fail; dkim=pass; dmarc=pass".to_string());

    let decision = chain.evaluate(&spf_fail_msg).await.unwrap();
    assert!(matches!(decision, FilterDecision::Spam { score, .. } if score >= 11.0));
    rspamd_mock.verify().await;
    llm_mock.verify().await;
    rspamd_mock.reset().await;
    llm_mock.reset().await;

    // 4. Full pipeline accumulation: AuthResults tags AUTH_FAIL, Rspamd allows, LLM adds CATEGORY_UPDATES + skip_inbox
    Mock::given(method("POST"))
        .and(path("/checkv2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "score": 0.5,
            "required_score": 15.0,
            "action": "no action",
            "symbols": {}
        })))
        .expect(1)
        .mount(&rspamd_mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{
                "message": {
                    "content": "{\"action\":\"mutate\",\"add_labels\":[\"CATEGORY_UPDATES\"],\"remove_labels\":[],\"skip_inbox\":true,\"reason\":\"automated receipt\"}"
                }
            }]
        })))
        .expect(1)
        .mount(&llm_mock)
        .await;

    let decision = chain.evaluate(&spf_fail_msg).await.unwrap();
    assert_eq!(
        decision,
        FilterDecision::Mutate {
            add_labels: vec![LABEL_AUTH_FAIL.to_string(), "CATEGORY_UPDATES".to_string()],
            remove_labels: vec![],
            skip_inbox: true,
        }
    );
    rspamd_mock.verify().await;
    llm_mock.verify().await;
}
