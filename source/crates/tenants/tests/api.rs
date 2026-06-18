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

use wardnet_common::token::{ClaimsSpec, PrincipalType, canonical_request_payload};
use wardnet_tenants::api;
use wardnet_tenants::test_helpers::{build_harness, build_state, daemon_keypair, test_signer};

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
