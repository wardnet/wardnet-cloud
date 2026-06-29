//! `StripeClient` (the reqwest gateway) against a wiremock Stripe — validates the
//! request shape (path, Bearer auth, form body) for checkout / billing-portal sessions
//! and that a Stripe API error surfaces only its `type`/`code`, never the raw response
//! body (invariant #9). No real Stripe API is touched.

use wardnet_billing::gateway::{StripeClient, StripeGateway};
use wardnet_common::contract::InvoiceStatus;
use wiremock::matchers::{header, method, path, query_param};
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

#[tokio::test]
async fn default_payment_method_maps_expanded_card() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/customers/cus_1"))
        .and(header("authorization", "Bearer sk_test"))
        // The customer is retrieved with the default PM expanded (single call).
        .and(query_param(
            "expand[]",
            "invoice_settings.default_payment_method",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "cus_1",
            "invoice_settings": {
                "default_payment_method": {
                    "id": "pm_1",
                    "card": { "brand": "visa", "last4": "4242", "exp_month": 8, "exp_year": 2027 }
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let pm = client(&server.uri())
        .default_payment_method("cus_1")
        .await
        .unwrap()
        .expect("a default payment method");
    assert_eq!(pm.brand, "visa");
    assert_eq!(pm.last4, "4242");
    assert_eq!(pm.exp_month, 8);
    assert_eq!(pm.exp_year, 2027);
}

#[tokio::test]
async fn default_payment_method_is_none_without_default() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/customers/cus_1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "cus_1",
            "invoice_settings": { "default_payment_method": null }
        })))
        .mount(&server)
        .await;

    let pm = client(&server.uri())
        .default_payment_method("cus_1")
        .await
        .unwrap();
    assert!(pm.is_none());
}

#[tokio::test]
async fn list_invoices_maps_rows_newest_first() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/invoices"))
        .and(header("authorization", "Bearer sk_test"))
        .and(query_param("customer", "cus_1"))
        // The page is bounded (INVOICE_PAGE_LIMIT) — assert the cap is actually sent.
        .and(query_param("limit", "24"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "list",
            "data": [
                {
                    // 2026-06-01T00:00:00Z
                    "created": 1_780_272_000,
                    "total": 800,
                    "currency": "usd",
                    "status": "paid",
                    "hosted_invoice_url": "https://invoice.stripe.test/i/1"
                },
                {
                    // A draft is not yet issued → skipped.
                    "created": 1_777_593_600,
                    "total": 800,
                    "currency": "usd",
                    "status": "draft",
                    "hosted_invoice_url": null
                }
            ]
        })))
        .mount(&server)
        .await;

    let invoices = client(&server.uri()).list_invoices("cus_1").await.unwrap();
    // The draft was dropped; only the issued invoice remains.
    assert_eq!(invoices.len(), 1);
    let inv = &invoices[0];
    assert_eq!(inv.date, "2026-06-01");
    assert_eq!(inv.amount_cents, 800);
    assert_eq!(inv.currency, "usd");
    assert_eq!(inv.status, InvoiceStatus::Paid);
    assert_eq!(
        inv.hosted_url.as_deref(),
        Some("https://invoice.stripe.test/i/1")
    );
}

#[tokio::test]
async fn invoice_read_error_surfaces_code_not_raw_body() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/invoices"))
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
        .list_invoices("cus_x")
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("type=invalid_request_error"));
    assert!(msg.contains("code=resource_missing"));
    // Stripe's free-text message (which can carry PII) is never surfaced.
    assert!(!msg.contains("cus_secret_pii"));
    assert!(!msg.contains("No such customer"));
}
