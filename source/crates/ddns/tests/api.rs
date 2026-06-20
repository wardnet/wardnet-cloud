//! HTTP-level integration tests over the mock-backed router: the daemon
//! report-IP + ACME surface and caller-type / network-scope auth enforcement,
//! driven with `oneshot`.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use wardnet_common::token::{ClaimsSpec, PrincipalType, canonical_request_payload};
use wardnet_ddns::api;
use wardnet_ddns::test_helpers::{
    InMemoryOperational, MockDnsProvider, build_state, daemon_keypair, test_signer,
};

const SEED: u8 = 7;
const TENANT: &str = "tenant-1";
const NETWORK: &str = "net-1";

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Mint a daemon JWT. `network` is the `net` claim (None ⇒ tenant-scoped). `aud`
/// follows the lifecycle (ADR-0008): tenant-scoped → `[tenants]` (rejected here, as
/// `ddns` is absent), network-scoped → the full mesh.
fn daemon_token(cnf: &str, network: Option<&str>) -> String {
    let audience = if network.is_some() {
        vec!["tenants", "ddns", "tunneller"]
    } else {
        vec!["tenants"]
    };
    test_signer(SEED)
        .sign(
            &ClaimsSpec {
                tenant_id: TENANT,
                principal_type: PrincipalType::Daemon,
                subject: cnf,
                network,
                cnf_ed25519_b64: Some(cnf),
                audience,
            },
            now(),
            300,
        )
        .unwrap()
}

fn sign(key: &SigningKey, method: &str, path_and_query: &str, ts: i64, body: &[u8]) -> String {
    let hash = hex::encode(Sha256::digest(body));
    let payload = canonical_request_payload(method, path_and_query, ts, &hash);
    base64::engine::general_purpose::STANDARD.encode(key.sign(payload.as_bytes()).to_bytes())
}

/// A daemon-signed request with an optional bearer JWT.
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

fn app_with(op: InMemoryOperational, dns: MockDnsProvider) -> Router {
    api::router(build_state(SEED, op, dns))
}

#[tokio::test]
async fn health_is_open() {
    let app = app_with(InMemoryOperational::new(), MockDnsProvider::new());
    let resp = app
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
async fn report_ip_with_network_scoped_token_succeeds() {
    let op = InMemoryOperational::new();
    let dns = MockDnsProvider::new();
    let app = app_with(op.clone(), dns.clone());

    let (key, cnf) = daemon_keypair(11);
    let token = daemon_token(&cnf, Some(NETWORK));
    let body = serde_json::to_vec(&json!({ "ip": "203.0.114.42" })).unwrap();
    let req = daemon_request("PUT", "/v1/ip", &body, &key, Some(&token));

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(op.get(NETWORK).unwrap().ip.as_deref(), Some("203.0.114.42"));
}

#[tokio::test]
async fn report_ip_rejects_reserved_address() {
    let app = app_with(InMemoryOperational::new(), MockDnsProvider::new());
    let (key, cnf) = daemon_keypair(11);
    let token = daemon_token(&cnf, Some(NETWORK));
    let body = serde_json::to_vec(&json!({ "ip": "10.0.0.1" })).unwrap();
    let req = daemon_request("PUT", "/v1/ip", &body, &key, Some(&token));

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn report_ip_with_tenant_scoped_token_is_rejected() {
    let app = app_with(InMemoryOperational::new(), MockDnsProvider::new());
    let (key, cnf) = daemon_keypair(11);
    // No `net` claim → tenant-scoped → `aud = [tenants]`, which omits `ddns`, so the
    // verifier rejects it (401) before any handler-level network-scope check (ADR-0008).
    let token = daemon_token(&cnf, None);
    let body = serde_json::to_vec(&json!({ "ip": "203.0.113.42" })).unwrap();
    let req = daemon_request("PUT", "/v1/ip", &body, &key, Some(&token));

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn report_ip_without_auth_is_unauthorized() {
    let app = app_with(InMemoryOperational::new(), MockDnsProvider::new());
    let body = serde_json::to_vec(&json!({ "ip": "203.0.113.42" })).unwrap();
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/ip")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn acme_challenge_before_active_is_conflict() {
    // Fresh network: no stored fqdn ⇒ not yet active ⇒ 409.
    let app = app_with(InMemoryOperational::new(), MockDnsProvider::new());
    let (key, cnf) = daemon_keypair(11);
    let token = daemon_token(&cnf, Some(NETWORK));
    let body = serde_json::to_vec(&json!({ "values": ["challenge-token"] })).unwrap();
    let req = daemon_request("PUT", "/v1/acme-challenge", &body, &key, Some(&token));

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn acme_challenge_when_active_succeeds() {
    let op = InMemoryOperational::new();
    // Simulate an active network (provisioner stored the A-record fqdn).
    op.seed_claimed(NETWORK, "happy.my.wardnet.services", "a-rid");
    let dns = MockDnsProvider::new();
    let app = app_with(op.clone(), dns.clone());

    let (key, cnf) = daemon_keypair(11);
    let token = daemon_token(&cnf, Some(NETWORK));
    let body = serde_json::to_vec(&json!({ "values": ["challenge-token"] })).unwrap();
    let req = daemon_request("PUT", "/v1/acme-challenge", &body, &key, Some(&token));

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(op.get(NETWORK).unwrap().cf_acme_record_ids.len(), 1);
}

#[tokio::test]
async fn delete_acme_challenge_is_idempotent() {
    let op = InMemoryOperational::new();
    op.seed_claimed(NETWORK, "happy.my.wardnet.services", "a-rid");
    let app = app_with(op, MockDnsProvider::new());

    let (key, cnf) = daemon_keypair(11);
    let token = daemon_token(&cnf, Some(NETWORK));
    let req = daemon_request("DELETE", "/v1/acme-challenge", &[], &key, Some(&token));

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}
