//! `StripeClient` (the reqwest gateway) against a wiremock Stripe — validates the
//! request shape (path, Bearer auth, form body) for checkout / billing-portal sessions
//! and that a Stripe API error surfaces only its `type`/`code`, never the raw response
//! body (invariant #9). No real Stripe API is touched.

use wardnet_billing::gateway::{StripeClient, StripeGateway};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A client pointed at the wiremock `base`.
fn client(base: &str) -> StripeClient {
    StripeClient::from_url(
        base,
        "sk_test",
        "whsec_test",
        "https://account.example.test/",
    )
}

/// The form body of the (single) request wiremock received, as a UTF-8 string.
async fn received_body(server: &MockServer) -> String {
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    String::from_utf8(received[0].body.clone()).unwrap()
}

#[tokio::test]
async fn checkout_session_for_new_customer_posts_expected_form() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/checkout/sessions"))
        .and(header("authorization", "Bearer sk_test"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "url": "https://checkout.stripe.test/c/sess_1",
            "customer": "cus_new"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let session = client(&server.uri())
        .create_checkout_session(None, "user@example.com", "price_1", "tnt_1")
        .await
        .unwrap();
    assert_eq!(session.url, "https://checkout.stripe.test/c/sess_1");
    assert_eq!(session.customer_id.as_deref(), Some("cus_new"));

    let body = received_body(&server).await;
    assert!(body.contains("mode=subscription"));
    // No customer id known → collect one via email; never sent a `customer=` id.
    assert!(body.contains("customer_email"));
    assert!(!body.contains("customer=cus"));
    assert!(body.contains("price_1")); // line_items[0][price]
    assert!(body.contains("tnt_1")); // subscription_data[metadata][tenant_id]
}

#[tokio::test]
async fn checkout_session_for_existing_customer_sends_customer_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/checkout/sessions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "url": "https://checkout.stripe.test/c/sess_2"
        })))
        .mount(&server)
        .await;

    let session = client(&server.uri())
        .create_checkout_session(Some("cus_existing"), "user@example.com", "price_1", "tnt_1")
        .await
        .unwrap();
    assert_eq!(session.url, "https://checkout.stripe.test/c/sess_2");
    // The response carried no `customer`, so none surfaces.
    assert!(session.customer_id.is_none());

    let body = received_body(&server).await;
    assert!(body.contains("customer=cus_existing"));
    assert!(!body.contains("customer_email"));
}

#[tokio::test]
async fn checkout_session_without_url_is_an_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/checkout/sessions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&server)
        .await;

    assert!(
        client(&server.uri())
            .create_checkout_session(None, "u@e.com", "price_1", "tnt_1")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn malformed_success_response_is_an_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/checkout/sessions"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<<not json>>"))
        .mount(&server)
        .await;

    let err = client(&server.uri())
        .create_checkout_session(None, "u@e.com", "price_1", "tnt_1")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("malformed Stripe response"));
}

#[tokio::test]
async fn billing_portal_session_returns_url() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/billing_portal/sessions"))
        .and(header("authorization", "Bearer sk_test"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "url": "https://billing.stripe.test/p/sess_1"
        })))
        .mount(&server)
        .await;

    let url = client(&server.uri())
        .create_billing_portal_session("cus_1")
        .await
        .unwrap();
    assert_eq!(url, "https://billing.stripe.test/p/sess_1");

    let body = received_body(&server).await;
    assert!(body.contains("customer=cus_1"));
    assert!(body.contains("return_url"));
}

#[tokio::test]
async fn billing_portal_session_without_url_is_an_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/billing_portal/sessions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&server)
        .await;

    assert!(
        client(&server.uri())
            .create_billing_portal_session("cus_1")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn stripe_api_error_surfaces_code_not_raw_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/billing_portal/sessions"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": {
                "type": "invalid_request_error",
                "code": "resource_missing",
                "message": "No such customer: cus_secret_pii"
            }
        })))
        .mount(&server)
        .await;

    let err = client(&server.uri())
        .create_billing_portal_session("cus_x")
        .await
        .unwrap_err();
    let msg = err.to_string();
    // The machine-readable type/code are surfaced…
    assert!(msg.contains("type=invalid_request_error"));
    assert!(msg.contains("code=resource_missing"));
    // …but Stripe's free-text message (which can carry PII) is never logged.
    assert!(!msg.contains("cus_secret_pii"));
    assert!(!msg.contains("No such customer"));
}

#[tokio::test]
async fn stripe_error_with_unparseable_body_falls_back_to_status() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/billing_portal/sessions"))
        .respond_with(ResponseTemplate::new(503).set_body_string("upstream down"))
        .mount(&server)
        .await;

    let err = client(&server.uri())
        .create_billing_portal_session("cus_x")
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("503"));
    // Raw body is not interpolated when it isn't a Stripe error envelope.
    assert!(!msg.contains("upstream down"));
}
