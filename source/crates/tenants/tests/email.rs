//! `ResendEmailSender` against a wiremock Resend — validates the request shape
//! (path, Bearer auth, JSON body) without touching the real API.

use wardnet_common::contract::CodePurpose;
use wardnet_tenants::email::{EmailSender, ResendEmailSender};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn resend_posts_the_code_with_auth() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/emails"))
        .and(header("authorization", "Bearer re_test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "e_1"})))
        .expect(1)
        .mount(&server)
        .await;

    let sender = ResendEmailSender::with_base_url(
        "re_test_key",
        "wardnet <noreply@wardnet.io>",
        &server.uri(),
    )
    .unwrap();
    sender
        .send_code(
            "user@example.com",
            "abcdef123456",
            CodePurpose::PasswordReset,
        )
        .await
        .unwrap();
    assert!(sender.delivers());

    // The wiremock `.expect(1)` is asserted on drop — the single POST landed.
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let body: serde_json::Value = received[0].body_json().unwrap();
    assert_eq!(body["to"][0], "user@example.com");
    assert!(body["text"].as_str().unwrap().contains("abcdef123456"));
    // The subject/body match the purpose (a reset code is not labelled "enrollment").
    assert_eq!(body["subject"], "Your wardnet password-reset code");
    assert!(body["text"].as_str().unwrap().contains("password-reset"));
}

#[tokio::test]
async fn resend_surfaces_provider_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/emails"))
        .respond_with(
            ResponseTemplate::new(422).set_body_json(serde_json::json!({"message": "bad"})),
        )
        .mount(&server)
        .await;

    let sender = ResendEmailSender::with_base_url("re_x", "from@x.io", &server.uri()).unwrap();
    assert!(
        sender
            .send_code("u@e.com", "code", CodePurpose::Enrollment)
            .await
            .is_err()
    );
}
