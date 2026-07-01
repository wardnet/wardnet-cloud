//! HTTP-level integration tests over the mock-backed router: the full daemon
//! enrollment flow and the caller-type auth enforcement, driven with `oneshot`.

use std::net::SocketAddr;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use wardnet_billing::gateway::{
    StripeEvent, StripeEventKind, SubscriptionData, SubscriptionDetails,
};
use wardnet_billing::repository::{BillingRepository, CatalogPlan};
use wardnet_common::contract::{
    Entitlement, InvoiceStatus, InvoiceView, PaymentMethodView, SubscriptionStatus,
};
use wardnet_common::token::{ClaimsSpec, PrincipalType, canonical_request_payload};
use wardnet_tenants::api;
use wardnet_tenants::repository::tenant::Tenant;
mod common;
use common::{build_harness, build_state, daemon_keypair, test_signer};

const SEED: u8 = 5;

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn app() -> Router {
    let (state, _store) = build_state(SEED);
    api::router(state)
}

fn sign(key: &SigningKey, method: &str, path_and_query: &str, ts: i64, body: &[u8]) -> String {
    let hash = hex::encode(Sha256::digest(body));
    let payload = canonical_request_payload(method, path_and_query, ts, &hash);
    base64::engine::general_purpose::STANDARD.encode(key.sign(payload.as_bytes()).to_bytes())
}

/// A daemon-signed request with optional bearer JWT.
fn daemon_request(
    method: &str,
    path: &str,
    body: &[u8],
    key: &SigningKey,
    bearer: Option<&str>,
) -> Request<Body> {
    let ts = now();
    let sig = sign(key, method, path, ts, body);
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("X-Wardnet-Timestamp", ts.to_string())
        .header("X-Wardnet-Signature", sig);
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    builder.body(Body::from(body.to_vec())).unwrap()
}

fn user_token(tenant_id: &str) -> String {
    test_signer(SEED)
        .sign(
            &ClaimsSpec {
                tenant_id,
                principal_type: PrincipalType::User,
                subject: "user-1",
                network: None,
                cnf_ed25519_b64: None,
                audience: vec!["tenants"],
            },
            now(),
            300,
        )
        .unwrap()
}

async fn json_body(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn health_is_open() {
    let resp = app()
        .oneshot(
            Request::builder()
                .uri("/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn full_daemon_flow() {
    // The full flow needs the trial subscription, which the subscription reactor opens
    // on `TenantCreated`; drive the reactors deterministically with the harness pump.
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    let (key, cnf) = daemon_keypair(11);

    // 1. signup code (public; needs the PROXY-derived ConnectInfo).
    let mut signup = Request::builder()
        .method("POST")
        .uri("/v1/verification-codes")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"email": "a@b.com", "purpose": "enrollment"})).unwrap(),
        ))
        .unwrap();
    signup
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9999))));
    let resp = app.clone().oneshot(signup).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let code = json_body(resp).await["code"].as_str().unwrap().to_string();

    // 2. enroll (bootstrap; no PoP).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/enroll")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"code": code, "public_key": cnf})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let tenant_id = json_body(resp).await["tenant_id"]
        .as_str()
        .unwrap()
        .to_string();
    // The subscription reactor opens the trial so the daemon can mint a token.
    h.pump().await;

    // 3. token (key PoP) → tenant-scoped JWT.
    let body = serde_json::to_vec(&json!({"public_key": cnf})).unwrap();
    let resp = app
        .clone()
        .oneshot(daemon_request("POST", "/v1/token", &body, &key, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let token = json_body(resp).await["token"].as_str().unwrap().to_string();

    // 4. register-network (daemon JWT + PoP).
    let body = serde_json::to_vec(&json!({"slug": "happy-einstein", "region": "use1"})).unwrap();
    let resp = app
        .clone()
        .oneshot(daemon_request(
            "POST",
            "/v1/networks",
            &body,
            &key,
            Some(&token),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 5. availability via a USER token now reads the slug as taken.
    let utoken = user_token(&tenant_id);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/availability?slug=happy-einstein")
                .header(header::AUTHORIZATION, format!("Bearer {utoken}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["available"], json!(false));

    // 6. user lists their tenant's networks.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/tenants/{tenant_id}/networks"))
                .header(header::AUTHORIZATION, format!("Bearer {utoken}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn register_network_rejects_user_token() {
    let utoken = user_token("some-tenant");
    let body = serde_json::to_vec(&json!({"slug": "x", "region": "use1"})).unwrap();
    let resp = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/networks")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {utoken}"))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn register_network_without_auth_is_unauthorized() {
    let body = serde_json::to_vec(&json!({"slug": "x", "region": "use1"})).unwrap();
    let resp = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/networks")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn delete_tenant_is_owner_scoped_and_idempotent() {
    let app = app();
    let (key, cnf) = daemon_keypair(11);

    // Enroll a tenant via the full bootstrap flow so it exists in the store.
    let mut signup = Request::builder()
        .method("POST")
        .uri("/v1/verification-codes")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"email": "del@b.com", "purpose": "enrollment"})).unwrap(),
        ))
        .unwrap();
    signup
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9999))));
    let code = json_body(app.clone().oneshot(signup).await.unwrap()).await["code"]
        .as_str()
        .unwrap()
        .to_string();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/enroll")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"code": code, "public_key": cnf})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let tenant_id = json_body(resp).await["tenant_id"]
        .as_str()
        .unwrap()
        .to_string();
    let _ = key;

    // A different tenant's user cannot delete this account.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/tenants/{tenant_id}"))
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", user_token("other")),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // The owner deregisters → 202.
    let utoken = user_token(&tenant_id);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/tenants/{tenant_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {utoken}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // Idempotent: a repeat delete still returns 202.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/tenants/{tenant_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {utoken}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn delete_tenant_without_auth_is_unauthorized() {
    let resp = app()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/tenants/some-tenant")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn user_cannot_read_another_tenant() {
    let utoken = user_token("tenant-a");
    let resp = app()
        .oneshot(
            Request::builder()
                .uri("/v1/tenants/tenant-b/networks")
                .header(header::AUTHORIZATION, format!("Bearer {utoken}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn checkout_session_returns_stripe_url() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    h.store.seed_tenant(Tenant {
        id: "tb".to_string(),
        email: "owner@b.com".to_string(),
        created_at: chrono::Utc::now(),
        deregistered_at: None,
    });
    let token = user_token("tb");

    let body = serde_json::to_vec(&json!({"price_id": "price_pro"})).unwrap();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/tenants/tb/billing/checkout-session")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        json_body(resp).await["url"],
        json!("https://checkout.stripe.test/session")
    );
    // The service forwarded email + price + tenant to the gateway.
    let checkouts = h.stripe.checkouts.lock().unwrap();
    assert_eq!(checkouts.len(), 1);
    assert_eq!(checkouts[0].1, "owner@b.com");
    assert_eq!(checkouts[0].2, "price_pro");
    assert_eq!(checkouts[0].3, "tb");
}

/// GET the billing read endpoint at `path` for `tenant`, authenticated as `token`'s owner.
async fn billing_get(app: &Router, path: &str, token: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn payment_method_returns_card_for_tenant_with_customer() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    h.store.seed_billing_customer("tb", "cus_b");
    h.stripe.set_payment_method(PaymentMethodView {
        brand: "visa".to_string(),
        last4: "4242".to_string(),
        exp_month: 8,
        exp_year: 2027,
    });

    let resp = billing_get(
        &app,
        "/v1/tenants/tb/billing/payment-method",
        &user_token("tb"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["brand"], json!("visa"));
    assert_eq!(body["last4"], json!("4242"));
    assert_eq!(body["exp_month"], json!(8));
    assert_eq!(body["exp_year"], json!(2027));
}

#[tokio::test]
async fn payment_method_is_null_for_trial_tenant_without_customer() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    // No billing_customer seeded → no provider customer; must be null, never a 5xx.
    let resp = billing_get(
        &app,
        "/v1/tenants/tt/billing/payment-method",
        &user_token("tt"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await, Value::Null);
}

#[tokio::test]
async fn invoices_returns_rows_for_tenant_with_customer() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    h.store.seed_billing_customer("tb", "cus_b");
    h.stripe.set_invoices(vec![InvoiceView {
        date: "2026-06-01".to_string(),
        amount_cents: 800,
        currency: "usd".to_string(),
        status: InvoiceStatus::Paid,
        hosted_url: Some("https://invoice.stripe.test/i/1".to_string()),
    }]);

    let resp = billing_get(&app, "/v1/tenants/tb/billing/invoices", &user_token("tb")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["date"], json!("2026-06-01"));
    assert_eq!(body[0]["amount_cents"], json!(800));
    assert_eq!(body[0]["currency"], json!("usd"));
    assert_eq!(body[0]["status"], json!("paid"));
    assert_eq!(
        body[0]["hosted_url"],
        json!("https://invoice.stripe.test/i/1")
    );
}

#[tokio::test]
async fn invoices_is_empty_for_trial_tenant_without_customer() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    let resp = billing_get(&app, "/v1/tenants/tt/billing/invoices", &user_token("tt")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await, json!([]));
}

#[tokio::test]
async fn billing_reads_reject_other_tenants_token() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    h.store.seed_billing_customer("tb", "cus_b");
    // A USER token for a different tenant must not read tb's billing data.
    let other = user_token("other");
    let pm = billing_get(&app, "/v1/tenants/tb/billing/payment-method", &other).await;
    assert_eq!(pm.status(), StatusCode::FORBIDDEN);
    let inv = billing_get(&app, "/v1/tenants/tb/billing/invoices", &other).await;
    assert_eq!(inv.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn stripe_webhook_converts_trial_to_paid() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    h.store.seed_tenant(Tenant {
        id: "tw".to_string(),
        email: "w@b.com".to_string(),
        created_at: chrono::Utc::now(),
        deregistered_at: None,
    });
    h.subscriptions.create_trial("tw").await.unwrap();

    // The mock gateway returns this verified event regardless of the raw body/sig.
    h.stripe.set_event(StripeEvent {
        id: "evt_1".to_string(),
        kind: StripeEventKind::SubscriptionUpsert(SubscriptionData {
            tenant_id: Some("tw".to_string()),
            stripe_subscription_id: "sub_w".to_string(),
            stripe_customer_id: "cus_w".to_string(),
            price_id: Some("price_pro".to_string()),
            entitlement: Some(wardnet_common::contract::Entitlement {
                max_networks: 5,
                max_daemons: 20,
            }),
            status: SubscriptionStatus::Active,
            current_period_end: Some(chrono::Utc::now()),
        }),
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/billing/stripe/webhook")
                .header("Stripe-Signature", "t=1,v1=deadbeef")
                .body(Body::from(b"{}".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let current = h.store.current_subscription("tw").unwrap();
    assert_eq!(current.status, SubscriptionStatus::Active);
    assert_eq!(current.entitlement.max_networks, 5);
    // The Billing-side provider ref is recorded, so subsequent webhooks for this
    // subscription resolve the tenant via the mapping (not just checkout metadata).
    assert_eq!(
        h.store.billing_tenant_for_subscription("sub_w").as_deref(),
        Some("tw")
    );
    assert_eq!(h.store.billing_customer_id("tw").as_deref(), Some("cus_w"));
    // Trial→paid *replaced* the live row (cancel trial + insert paid), never mutated it
    // in place: two rows total, exactly one non-canceled (the `uq_subscriptions_live`
    // invariant).
    assert_eq!(h.store.subscription_count("tw"), 2);
}

/// POST a (mock-verified) Stripe webhook through the real router; returns the status.
async fn post_webhook(state: &wardnet_tenants::state::AppState) -> StatusCode {
    api::router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/billing/stripe/webhook")
                .header("Stripe-Signature", "t=1,v1=deadbeef")
                .body(Body::from(b"{}".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn stripe_webhook_without_price_metadata_declines_and_records_nothing() {
    // A misconfigured plan (price has no max_networks/max_daemons metadata) → the
    // webhook declines to grant (safe-closed) AND records no provider ref, so a later
    // delete for the same subscription cannot resolve — and cancel — the tenant's trial.
    let h = build_harness(SEED);
    h.store.seed_tenant(Tenant {
        id: "tm".to_string(),
        email: "m@b.com".to_string(),
        created_at: chrono::Utc::now(),
        deregistered_at: None,
    });
    h.subscriptions.create_trial("tm").await.unwrap();

    h.stripe.set_event(StripeEvent {
        id: "evt_nometa".to_string(),
        kind: StripeEventKind::SubscriptionUpsert(SubscriptionData {
            tenant_id: Some("tm".to_string()),
            stripe_subscription_id: "sub_m".to_string(),
            stripe_customer_id: "cus_m".to_string(),
            price_id: Some("price_broken".to_string()),
            entitlement: None, // <-- no price metadata
            status: SubscriptionStatus::Active,
            current_period_end: Some(chrono::Utc::now()),
        }),
    });
    assert_eq!(post_webhook(&h.state).await, StatusCode::OK);

    // Declined: still on the trial, and NOTHING recorded on the Billing side.
    assert_eq!(
        h.store.current_subscription("tm").unwrap().status,
        SubscriptionStatus::Trialing
    );
    assert_eq!(h.store.billing_tenant_for_subscription("sub_m"), None);

    // Now a `customer.subscription.deleted` for that never-granted subscription must be
    // a no-op — it must NOT cancel the tenant's live trial.
    h.stripe.set_event(StripeEvent {
        id: "evt_del".to_string(),
        kind: StripeEventKind::SubscriptionDeleted {
            stripe_subscription_id: "sub_m".to_string(),
        },
    });
    assert_eq!(post_webhook(&h.state).await, StatusCode::OK);
    assert_eq!(
        h.store.current_subscription("tm").unwrap().status,
        SubscriptionStatus::Trialing
    );
}

#[tokio::test]
async fn stripe_webhook_deleted_cancels_via_recorded_mapping() {
    // Convert (records the mapping), then a delete resolves the tenant via
    // tenant_for_subscription and cancels the paid license.
    let h = build_harness(SEED);
    h.store.seed_tenant(Tenant {
        id: "td".to_string(),
        email: "d@b.com".to_string(),
        created_at: chrono::Utc::now(),
        deregistered_at: None,
    });
    h.subscriptions.create_trial("td").await.unwrap();

    h.stripe.set_event(StripeEvent {
        id: "evt_c".to_string(),
        kind: StripeEventKind::SubscriptionUpsert(SubscriptionData {
            tenant_id: Some("td".to_string()),
            stripe_subscription_id: "sub_d".to_string(),
            stripe_customer_id: "cus_d".to_string(),
            price_id: Some("price_pro".to_string()),
            entitlement: Some(wardnet_common::contract::Entitlement {
                max_networks: 3,
                max_daemons: 9,
            }),
            status: SubscriptionStatus::Active,
            current_period_end: Some(chrono::Utc::now()),
        }),
    });
    assert_eq!(post_webhook(&h.state).await, StatusCode::OK);
    assert_eq!(
        h.store.current_subscription("td").unwrap().status,
        SubscriptionStatus::Active
    );

    // The delete carries no checkout metadata — resolution is purely via the mapping.
    h.stripe.set_event(StripeEvent {
        id: "evt_d".to_string(),
        kind: StripeEventKind::SubscriptionDeleted {
            stripe_subscription_id: "sub_d".to_string(),
        },
    });
    assert_eq!(post_webhook(&h.state).await, StatusCode::OK);
    assert!(h.store.current_subscription("td").is_none());
}

#[tokio::test]
async fn stripe_webhook_is_idempotent_on_redelivery() {
    // The same event id delivered twice applies once (the ledger dedupes the second).
    let h = build_harness(SEED);
    h.store.seed_tenant(Tenant {
        id: "ti".to_string(),
        email: "i@b.com".to_string(),
        created_at: chrono::Utc::now(),
        deregistered_at: None,
    });
    h.subscriptions.create_trial("ti").await.unwrap();

    h.stripe.set_event(StripeEvent {
        id: "evt_dup".to_string(),
        kind: StripeEventKind::SubscriptionUpsert(SubscriptionData {
            tenant_id: Some("ti".to_string()),
            stripe_subscription_id: "sub_i".to_string(),
            stripe_customer_id: "cus_i".to_string(),
            price_id: Some("price_pro".to_string()),
            entitlement: Some(wardnet_common::contract::Entitlement {
                max_networks: 2,
                max_daemons: 4,
            }),
            status: SubscriptionStatus::Active,
            current_period_end: Some(chrono::Utc::now()),
        }),
    });
    assert_eq!(post_webhook(&h.state).await, StatusCode::OK);
    assert_eq!(post_webhook(&h.state).await, StatusCode::OK); // redelivery, same id

    // Applied exactly once: the conversion produced one trial + one paid row, not two
    // paid rows from a double-apply.
    assert_eq!(h.store.subscription_count("ti"), 2);
    assert_eq!(
        h.store.current_subscription("ti").unwrap().status,
        SubscriptionStatus::Active
    );
}

#[tokio::test]
async fn stripe_webhook_without_signature_is_bad_request() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/billing/stripe/webhook")
                .body(Body::from(b"{}".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── HTTP contract tests for the plan-change / card-update / subscription-read /
//    public-plans endpoints added in this PR (previously only service-tested). ──

/// Seed `tenant` as an active Home subscriber with a Stripe billing ref, plus the
/// Home/Pro catalog, so the plan-change, card-update and subscription-read endpoints
/// have the data their handlers read.
async fn seed_paid_http(h: &common::Harness, tenant: &str) {
    let now = chrono::Utc::now();
    let plan =
        |price: &str, prod: &str, name: &str, level: u32, nets: u32, daemons: u32| CatalogPlan {
            price_id: price.to_string(),
            product_id: prod.to_string(),
            name: name.to_string(),
            level,
            entitlement: Entitlement {
                max_networks: nets,
                max_daemons: daemons,
            },
            amount_cents: 100,
            currency: "usd".to_string(),
            interval: "month".to_string(),
        };
    h.store
        .replace_catalog(
            &[
                plan("price_home", "prod_home", "Home", 1, 1, 1),
                plan("price_pro", "prod_pro", "Pro", 3, 3, 6),
            ],
            &[],
            now,
        )
        .await
        .unwrap();
    h.store
        .upsert_subscription(tenant, "cus_x", "sub_x", Some("price_home"))
        .await
        .unwrap();
    h.stripe.set_subscription(SubscriptionDetails {
        item_id: "si_x".to_string(),
        price_id: "price_home".to_string(),
        current_period_end: now + chrono::Duration::days(30),
        schedule_id: None,
        trialing: false,
    });
}

fn post_json(path: &str, token: Option<&str>, body: &Value) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

#[tokio::test]
async fn change_plan_upgrade_returns_202_and_the_new_price() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    seed_paid_http(&h, "tb").await;

    let resp = app
        .oneshot(post_json(
            "/v1/tenants/tb/billing/change-plan",
            Some(&user_token("tb")),
            &json!({"price_id": "price_pro", "accept_full_price": false}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let b = json_body(resp).await;
    assert_eq!(b["effect"], json!("upgraded"));
    assert_eq!(b["current_price_id"], json!("price_pro"));
}

#[tokio::test]
async fn change_plan_without_a_paid_subscription_is_400() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    // "tt" has no billing ref → the service rejects → 400 (never a 5xx).
    let resp = app
        .oneshot(post_json(
            "/v1/tenants/tt/billing/change-plan",
            Some(&user_token("tt")),
            &json!({"price_id": "price_pro", "accept_full_price": false}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn change_plan_rejects_another_tenants_token() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    seed_paid_http(&h, "tb").await;
    let resp = app
        .oneshot(post_json(
            "/v1/tenants/tb/billing/change-plan",
            Some(&user_token("other")),
            &json!({"price_id": "price_pro", "accept_full_price": false}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn get_billing_subscription_returns_the_current_plan() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    seed_paid_http(&h, "tb").await;
    let resp = billing_get(
        &app,
        "/v1/tenants/tb/billing/subscription",
        &user_token("tb"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let b = json_body(resp).await;
    assert_eq!(b["current_price_id"], json!("price_home"));
    assert_eq!(b["trialing"], json!(false));
    assert_eq!(b["pending_change"], Value::Null);
}

#[tokio::test]
async fn get_billing_subscription_is_empty_without_a_ref() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    let resp = billing_get(
        &app,
        "/v1/tenants/tt/billing/subscription",
        &user_token("tt"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json_body(resp).await["current_price_id"], Value::Null);
}

#[tokio::test]
async fn get_billing_subscription_rejects_another_tenants_token() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    seed_paid_http(&h, "tb").await;
    let resp = billing_get(
        &app,
        "/v1/tenants/tb/billing/subscription",
        &user_token("other"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn card_update_returns_a_setup_session_url() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    seed_paid_http(&h, "tb").await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/tenants/tb/billing/card-update")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", user_token("tb")),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(json_body(resp).await["url"].is_string());
}

#[tokio::test]
async fn plans_endpoint_is_public_and_lists_the_catalog() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    seed_paid_http(&h, "tb").await;
    // Public bootstrap route — no Authorization header.
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/plans")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let arr = json_body(resp).await;
    let arr = arr.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert!(arr.iter().any(|p| p["price_id"] == json!("price_pro")));
}

// ── HTTP contract tests for the remaining account-plane handlers (me / add-daemon
//    code / daemon lists / cancel / delete-network) — previously only ~46% covered. ──

/// Enroll a tenant and register one network (with its first daemon) via the real HTTP
/// flow; returns `(tenant_id, network_id, slug)` for the daemon-list / delete tests.
async fn enroll_with_network(h: &common::Harness) -> (String, String, String) {
    let app = api::router(h.state.clone());
    let (key, cnf) = daemon_keypair(11);

    let mut signup = Request::builder()
        .method("POST")
        .uri("/v1/verification-codes")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"email": "net@b.com", "purpose": "enrollment"})).unwrap(),
        ))
        .unwrap();
    signup
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9999))));
    let code = json_body(app.clone().oneshot(signup).await.unwrap()).await["code"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/enroll")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"code": code, "public_key": cnf})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let tenant_id = json_body(resp).await["tenant_id"]
        .as_str()
        .unwrap()
        .to_string();
    h.pump().await;

    let body = serde_json::to_vec(&json!({"public_key": cnf})).unwrap();
    let token = json_body(
        app.clone()
            .oneshot(daemon_request("POST", "/v1/token", &body, &key, None))
            .await
            .unwrap(),
    )
    .await["token"]
        .as_str()
        .unwrap()
        .to_string();

    let body = serde_json::to_vec(&json!({"slug": "happy-cat", "region": "use1"})).unwrap();
    app.clone()
        .oneshot(daemon_request(
            "POST",
            "/v1/networks",
            &body,
            &key,
            Some(&token),
        ))
        .await
        .unwrap();

    // Recover the network id from the tenant's network list (NetworkView.id).
    let nets = billing_get(
        &app,
        &format!("/v1/tenants/{tenant_id}/networks"),
        &user_token(&tenant_id),
    )
    .await;
    let network_id = json_body(nets).await[0]["id"].as_str().unwrap().to_string();
    (tenant_id, network_id, "happy-cat".to_string())
}

#[tokio::test]
async fn me_returns_the_account_profile() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    h.store.seed_tenant(Tenant {
        id: "tm".to_string(),
        email: "me@b.com".to_string(),
        created_at: chrono::Utc::now(),
        deregistered_at: None,
    });
    h.subscriptions.create_trial("tm").await.unwrap();

    let resp = billing_get(&app, "/v1/me", &user_token("tm")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let b = json_body(resp).await;
    assert_eq!(b["tenant_id"], json!("tm"));
    assert_eq!(b["email"], json!("me@b.com"));
    assert_eq!(b["subscription"]["status"], json!("trialing"));
}

#[tokio::test]
async fn me_is_404_for_a_missing_tenant() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    // A validly-signed token for a tenant that was never created.
    let resp = billing_get(&app, "/v1/me", &user_token("ghost")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn issue_tenant_code_returns_a_code_for_the_owner() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    h.store.seed_tenant(Tenant {
        id: "tc".to_string(),
        email: "c@b.com".to_string(),
        created_at: chrono::Utc::now(),
        deregistered_at: None,
    });

    let resp = app
        .oneshot(post_json(
            "/v1/tenants/tc/codes",
            Some(&user_token("tc")),
            &json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Dev email sender doesn't deliver, so the code is returned in-band.
    assert!(json_body(resp).await["code"].is_string());
}

#[tokio::test]
async fn issue_tenant_code_rejects_another_tenant() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    let resp = app
        .oneshot(post_json(
            "/v1/tenants/tc/codes",
            Some(&user_token("other")),
            &json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn update_tenant_cancels_the_subscription() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    h.store.seed_tenant(Tenant {
        id: "tu".to_string(),
        email: "u@b.com".to_string(),
        created_at: chrono::Utc::now(),
        deregistered_at: None,
    });
    h.subscriptions.create_trial("tu").await.unwrap();

    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/tenants/tu")
        .header("content-type", "application/json")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", user_token("tu")),
        )
        .body(Body::from(
            serde_json::to_vec(&json!({"subscription_status": "canceled"})).unwrap(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    // The subscription is no longer live.
    assert!(h.subscriptions.current("tu").await.unwrap().is_none());
}

#[tokio::test]
async fn update_tenant_rejects_an_unsupported_field() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    h.store.seed_tenant(Tenant {
        id: "tu".to_string(),
        email: "u@b.com".to_string(),
        created_at: chrono::Utc::now(),
        deregistered_at: None,
    });
    let req = Request::builder()
        .method("PATCH")
        .uri("/v1/tenants/tu")
        .header("content-type", "application/json")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", user_token("tu")),
        )
        .body(Body::from(
            serde_json::to_vec(&json!({"subscription_status": "active"})).unwrap(),
        ))
        .unwrap();
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn tenant_and_network_daemon_lists_and_delete_network() {
    let h = build_harness(SEED);
    let app = api::router(h.state.clone());
    let (tenant_id, network_id, slug) = enroll_with_network(&h).await;
    let token = user_token(&tenant_id);

    // The tenant has exactly its one enrolled daemon.
    let td = billing_get(&app, &format!("/v1/tenants/{tenant_id}/daemons"), &token).await;
    assert_eq!(td.status(), StatusCode::OK);
    assert_eq!(json_body(td).await.as_array().unwrap().len(), 1);

    // …reachable via the network too.
    let nd = billing_get(&app, &format!("/v1/networks/{network_id}/daemons"), &token).await;
    assert_eq!(nd.status(), StatusCode::OK);
    assert_eq!(json_body(nd).await.as_array().unwrap().len(), 1);

    // Deleting the network is accepted (marks it deprovisioning).
    let del = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/tenants/{tenant_id}/networks/{slug}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del.status(), StatusCode::ACCEPTED);
}
