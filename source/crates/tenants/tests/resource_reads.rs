//! Service-level tests for the mesh-plane resource reads (`GET /v1/networks/{id}`,
//! `GET /v1/tenants/{id}`). The `SERVICE` caller is simulated by stamping a
//! `ServiceIdentity` extension (what the mesh-mTLS handshake does in production), so
//! these run without TLS via `oneshot`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

use wardnet_common::auth::ServiceIdentity;
use wardnet_tenants::api::{network, tenant};
use wardnet_tenants::repository::tenant::{Entitlement, SubscriptionStatus, Tenant};
use wardnet_tenants::state::AppState;
use wardnet_tenants::test_helpers::{build_state, daemon_keypair};

const SEED: u8 = 5;
const REGION: &str = "use1";

/// A state with tenant `t1` and one network it owns; returns `(state, network_id)`.
async fn seeded() -> (AppState, String) {
    let (state, store) = build_state(SEED);
    store.seed_tenant(Tenant {
        id: "t1".to_string(),
        email: "t1@example.com".to_string(),
        entitlement: Entitlement {
            max_networks: 5,
            max_daemons: 5,
        },
        subscription_status: SubscriptionStatus::Active,
        subscription_id: None,
        created_at: chrono::Utc::now(),
    });
    let (_key, cnf) = daemon_keypair(11);
    let network = state
        .tenants()
        .register_network("t1", &cnf, "happy-einstein", None, REGION)
        .await
        .unwrap();
    (state, network.id)
}

fn service_request(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .extension(ServiceIdentity {
            subject: String::new(),
        })
        .body(Body::empty())
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn get_network_returns_full_view() {
    let (state, network_id) = seeded().await;
    let app = network::router(state);

    let resp = app
        .oneshot(service_request(&format!("/v1/networks/{network_id}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["id"], serde_json::json!(network_id));
    assert_eq!(body["slug"], "happy-einstein");
    assert_eq!(body["tenant_id"], "t1");
    assert_eq!(body["provisioning_state"], "provisioning");
}

#[tokio::test]
async fn get_network_404_for_unknown() {
    let (state, _id) = seeded().await;
    let app = network::router(state);
    let resp = app
        .oneshot(service_request("/v1/networks/does-not-exist"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_tenant_returns_full_view() {
    let (state, _id) = seeded().await;
    let app = tenant::router(state);

    let resp = app
        .oneshot(service_request("/v1/tenants/t1"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["id"], "t1");
    assert_eq!(body["email"], "t1@example.com");
    assert_eq!(body["subscription_status"], "active");
}

#[tokio::test]
async fn get_tenant_404_for_unknown() {
    let (state, _id) = seeded().await;
    let app = tenant::router(state);
    let resp = app
        .oneshot(service_request("/v1/tenants/nope"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
