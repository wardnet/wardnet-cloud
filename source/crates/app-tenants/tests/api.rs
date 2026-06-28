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

use wardnet_billing::gateway::{StripeEvent, StripeEventKind, SubscriptionData};
use wardnet_common::contract::SubscriptionStatus;
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
        .uri("/v1/enrollment-codes")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"email": "a@b.com"})).unwrap(),
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
        .uri("/v1/enrollment-codes")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"email": "del@b.com"})).unwrap(),
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
