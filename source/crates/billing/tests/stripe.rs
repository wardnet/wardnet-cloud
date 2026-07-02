//! `StripeClient` (the reqwest gateway) against a wiremock Stripe — validates the
//! request shape (path, Bearer auth, form body) for checkout / billing-portal sessions
//! and that a Stripe API error surfaces only its `type`/`code`, never the raw response
//! body (invariant #9). No real Stripe API is touched.

use chrono::{TimeZone, Utc};
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
        .create_checkout_session(None, "user@example.com", "price_1", "tnt_1", None, None)
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
        .create_checkout_session(
            Some("cus_existing"),
            "user@example.com",
            "price_1",
            "tnt_1",
            None,
            None,
        )
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
            .create_checkout_session(None, "u@e.com", "price_1", "tnt_1", None, None)
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
        .create_checkout_session(None, "u@e.com", "price_1", "tnt_1", None, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("malformed Stripe response"));
}

#[tokio::test]
async fn setup_session_returns_url() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/checkout/sessions"))
        .and(header("authorization", "Bearer sk_test"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "url": "https://checkout.stripe.test/c/setup_1"
        })))
        .mount(&server)
        .await;

    let url = client(&server.uri())
        .create_setup_checkout_session("cus_1", "usd")
        .await
        .unwrap();
    assert_eq!(url, "https://checkout.stripe.test/c/setup_1");

    let body = received_body(&server).await;
    // A setup-mode session (collect a card, no purchase) for the known customer.
    assert!(body.contains("mode=setup"));
    assert!(body.contains("customer=cus_1"));
    // Setup mode has no line items to infer currency from, so Stripe requires it
    // explicitly — omitting it is a 400 `parameter_missing` (regression guard).
    assert!(body.contains("currency=usd"));
}

#[tokio::test]
async fn setup_session_without_url_is_an_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/checkout/sessions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&server)
        .await;

    assert!(
        client(&server.uri())
            .create_setup_checkout_session("cus_1", "usd")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn stripe_api_error_surfaces_code_not_raw_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/checkout/sessions"))
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
        .create_setup_checkout_session("cus_x", "usd")
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
        .and(path("/v1/checkout/sessions"))
        .respond_with(ResponseTemplate::new(503).set_body_string("upstream down"))
        .mount(&server)
        .await;

    let err = client(&server.uri())
        .create_setup_checkout_session("cus_x", "usd")
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("503"));
    // Raw body is not interpolated when it isn't a Stripe error envelope.
    assert!(!msg.contains("upstream down"));
}

#[tokio::test]
async fn checkout_session_with_coupon_sends_discount_and_maps_rejection() {
    // A coupon-bearing checkout sends `discounts[0][coupon]`; a Stripe 400 on that call
    // surfaces as the typed `CouponRejected` marker (→ PromoUnavailable upstream).
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/checkout/sessions"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": { "type": "invalid_request_error", "code": "coupon_expired" }
        })))
        .mount(&server)
        .await;

    let err = client(&server.uri())
        .create_checkout_session(None, "u@e.com", "price_1", "tnt_1", Some("co_xmas"), None)
        .await
        .unwrap_err();
    assert!(
        err.downcast_ref::<wardnet_billing::gateway::CouponRejected>()
            .is_some()
    );

    let body = received_body(&server).await;
    assert!(body.contains("co_xmas")); // discounts[0][coupon]
}

#[tokio::test]
async fn checkout_coupon_unrelated_400_is_not_a_coupon_rejection() {
    // A coupon is applied, but the 400 is about the price (archived), not the coupon —
    // it must surface as a normal error, never the CouponRejected marker (which would
    // misreport it to the user as a lapsed promotion).
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/checkout/sessions"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": {
                "type": "invalid_request_error",
                "code": "resource_missing",
                "param": "line_items[0][price]"
            }
        })))
        .mount(&server)
        .await;

    let err = client(&server.uri())
        .create_checkout_session(
            None,
            "u@e.com",
            "price_dead",
            "tnt_1",
            Some("co_xmas"),
            None,
        )
        .await
        .unwrap_err();
    assert!(
        err.downcast_ref::<wardnet_billing::gateway::CouponRejected>()
            .is_none()
    );
    assert!(err.to_string().contains("code=resource_missing"));
}

#[tokio::test]
async fn list_plans_maps_price_and_product() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/prices"))
        .and(query_param("active", "true"))
        .and(query_param("expand[]", "data.product"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "list",
            "data": [{
                "id": "price_pro",
                "unit_amount": 800,
                "currency": "usd",
                "active": true,
                "recurring": { "interval": "month" },
                "product": { "id": "prod_pro", "name": "Pro" },
                "metadata": { "level": "2", "max_networks": "3", "max_daemons": "25" }
            }]
        })))
        .mount(&server)
        .await;

    let plans = client(&server.uri()).list_plans().await.unwrap();
    assert_eq!(plans.len(), 1);
    let p = &plans[0];
    assert_eq!(p.price_id, "price_pro");
    assert_eq!(p.product_id, "prod_pro");
    assert_eq!(p.name, "Pro");
    assert_eq!(p.level, Some(2));
    assert_eq!(p.amount_cents, 800);
    assert_eq!(p.interval, "month");
    let ent = p.entitlement.unwrap();
    assert_eq!(ent.max_networks, 3);
    assert_eq!(ent.max_daemons, 25);
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

#[tokio::test]
async fn checkout_forwards_trial_end_when_set() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/checkout/sessions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "url": "https://checkout.stripe.test/c/sess_t"
        })))
        .mount(&server)
        .await;

    client(&server.uri())
        .create_checkout_session(
            None,
            "u@e.com",
            "price_1",
            "tnt_1",
            None,
            Some(1_788_000_000),
        )
        .await
        .unwrap();

    let body = received_body(&server).await;
    // subscription_data[trial_end]=<ts> defers the first charge (ADR-0012 trial-preserving).
    assert!(body.contains("trial_end"));
    assert!(body.contains("1788000000"));
}

#[tokio::test]
async fn upgrade_ending_trial_sends_trial_end_now() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/subscriptions/sub_1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&server)
        .await;

    client(&server.uri())
        .upgrade_subscription("sub_1", "si_1", "price_2", None, true)
        .await
        .unwrap();

    let body = received_body(&server).await;
    // Ending the honored trial on upgrade charges immediately (ADR-0012).
    assert!(body.contains("trial_end=now"));
}

#[tokio::test]
async fn get_subscription_maps_items_and_period_end() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/subscriptions/sub_1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "sub_1",
            "customer": "cus_1",
            "status": "active",
            "current_period_end": 1_788_000_000i64,
            "items": { "data": [ { "id": "si_1", "price": { "id": "price_1" } } ] }
        })))
        .mount(&server)
        .await;

    let details = client(&server.uri())
        .get_subscription("sub_1")
        .await
        .unwrap();
    assert_eq!(details.item_id, "si_1");
    assert_eq!(details.price_id, "price_1");
    assert_eq!(details.current_period_end.timestamp(), 1_788_000_000);
    assert!(details.schedule_id.is_none());
    assert!(!details.trialing);
}

#[tokio::test]
async fn get_subscription_flags_a_stripe_trial() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/subscriptions/sub_2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "sub_2",
            "customer": "cus_2",
            "status": "trialing",
            "current_period_end": 1_788_000_000i64,
            "items": { "data": [ { "id": "si_2", "price": { "id": "price_2" } } ] }
        })))
        .mount(&server)
        .await;

    let details = client(&server.uri())
        .get_subscription("sub_2")
        .await
        .unwrap();
    assert!(details.trialing);
}

#[tokio::test]
async fn pending_scheduled_change_reads_the_future_phase() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/subscription_schedules/sched_1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "sched_1",
            "phases": [ { "start_date": 1_788_000_000i64, "items": [ { "price": "price_home" } ] } ]
        })))
        .mount(&server)
        .await;

    let cpe = Utc.timestamp_opt(1_788_000_000, 0).single().unwrap();
    let change = client(&server.uri())
        .pending_scheduled_change("sched_1", cpe)
        .await
        .unwrap()
        .expect("a future phase");
    assert_eq!(change.price_id, "price_home");
    assert_eq!(change.effective_at.timestamp(), 1_788_000_000);
}

#[tokio::test]
async fn release_schedule_posts_to_the_release_endpoint() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/subscription_schedules/sched_1/release"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "id": "sched_1" })),
        )
        .mount(&server)
        .await;

    client(&server.uri())
        .release_schedule("sched_1")
        .await
        .unwrap();
}
