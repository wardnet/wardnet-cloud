//! Full-stack integration tests for the cloud (DDNS + Tunneller) HTTP API.
//!
//! These tests build the cloud Axum router with a mock operational repository and
//! a `MockDnsProvider`, then drive requests through
//! [`tower::ServiceExt::oneshot`] (or a real listener for the WebSocket tunnel).
//!
//! # Auth model (JWT-only)
//!
//! The cloud service holds **no identity DB** — the global identity table lives in
//! the Tenants service. So these endpoints authenticate the external daemon by its
//! Tenants-signed **identity JWT**, verified offline with `cnf` proof-of-possession.
//! The opaque bearer token is rejected with `401`. Every authenticated request here
//! therefore carries a JWT in the `Authorization` header (minted by
//! [`auth_jwt`]) and an Ed25519 request signature from [`test_signing_key`] (whose
//! public key is the JWT's `cnf`).
//!
//! # Other conventions
//!
//! - Every test creates its own isolated state via `test_state()`.
//! - The loopback peer (`127.0.0.1`) is injected via `MockConnectInfo`.

mod common;

use std::future::IntoFuture;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt as _, StreamExt as _};
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tower::ServiceExt as _;
use uuid::Uuid;

use common::{MockDnsProvider, MockOperationalRepository, jwt_keypair_pem};
use wardnet_cloud::config::Config;
use wardnet_cloud::repository::OperationalRepository;
use wardnet_cloud::service::DdnsService;
use wardnet_cloud::state::AppState;
use wardnet_cloud::tunnel::TunnelRegistry;
use wardnet_common::dns_provider::DnsProvider;
use wardnet_common::token;

/// Seed for the deterministic JWT signing keypair the test harness uses. The
/// `AppState` verifier is built from `jwt_keypair_pem(JWT_TEST_SEED).1`; the JWTs
/// these tests present are minted from `.0`.
const JWT_TEST_SEED: u8 = 7;

/// Mock handles, retained by a test so it can seed operational fixtures directly.
struct Mocks {
    operational: Arc<MockOperationalRepository>,
}

// ── Shared test fixtures ─────────────────────────────────────────────────────

fn test_config() -> Config {
    Config {
        api_listen_addr: "127.0.0.1:0".to_string(),
        https_listen_addr: "127.0.0.1:0".to_string(),
        dot_listen_addr: "127.0.0.1:0".to_string(),
        database_url: "postgres://ignored".to_string(),
        cloudflare_api_token: "test-cf-token".to_string(),
        cloudflare_zone_id: "test-cf-zone".to_string(),
        region: "test".to_string(),
        subdomain_parent: "test.wardnet.local".to_string(),
    }
}

/// Build an `AppState` whose DDNS service wraps a fresh mock operational repo + the
/// given DNS provider, returning the [`Mocks`] handles for direct fixture seeding.
fn build_state(dns_provider: Arc<dyn DnsProvider>) -> (AppState, Mocks) {
    let operational = Arc::new(MockOperationalRepository::new());
    let config = test_config();
    let ddns = Arc::new(DdnsService::new(
        Arc::clone(&operational) as Arc<dyn OperationalRepository>,
        dns_provider,
    ));
    let state = AppState::new(
        config,
        ddns,
        test_jwt_verifier(),
        Arc::new(TunnelRegistry::new()),
    );
    (state, Mocks { operational })
}

/// JWT verifier matching the harness signer (`jwt_keypair_pem(JWT_TEST_SEED)`).
fn test_jwt_verifier() -> token::Verifier {
    token::Verifier::from_pem(jwt_keypair_pem(JWT_TEST_SEED).1.as_bytes()).unwrap()
}

/// Mint a Tenants-signed identity JWT with the harness signing key. `cnf` is the
/// daemon's public key (`test_pub_key().1`) so `PoP` verifies against a
/// `test_signing_key()`-signed request. This is the cloud credential.
fn auth_jwt(install_id: &str, vanity: &str) -> String {
    test_identity_jwt(install_id, vanity, 3600)
}

/// Like [`auth_jwt`] but with an explicit TTL (negative TTL → already expired).
fn test_identity_jwt(install_id: &str, vanity: &str, ttl_secs: i64) -> String {
    let signer =
        token::Signer::from_pem(jwt_keypair_pem(JWT_TEST_SEED).0.as_bytes(), None).unwrap();
    let (_, cnf_b64) = test_pub_key();
    signer
        .sign(
            install_id,
            vanity,
            &cnf_b64,
            Utc::now().timestamp(),
            ttl_secs,
        )
        .unwrap()
}

fn test_state() -> (AppState, Arc<MockDnsProvider>, Mocks) {
    let dns = Arc::new(MockDnsProvider::new());
    let (state, mocks) = build_state(Arc::clone(&dns) as Arc<dyn DnsProvider>);
    (state, dns, mocks)
}

/// Build an `AppState` backed by the given DNS mock, returning the mock handles so a
/// test can seed an install before exercising a DNS failure.
fn test_state_dns(dns: Arc<MockDnsProvider>) -> (AppState, Mocks) {
    build_state(dns as Arc<dyn DnsProvider>)
}

/// Build the cloud router under test with a fixed loopback peer address.
fn test_app(state: AppState) -> axum::Router {
    wardnet_cloud::api::router(state)
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345))))
}

/// Ed25519 signing key for tests — deterministic, derived from `[1u8; 32]`. Its
/// public key is the `cnf` of every JWT minted by [`auth_jwt`].
fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[1u8; 32])
}

/// Return the verifying-key bytes and their base64 encoding for the test key.
fn test_pub_key() -> ([u8; 32], String) {
    let key = test_signing_key();
    let bytes = key.verifying_key().to_bytes();
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    (bytes, b64)
}

/// Build a signed request for an authenticated endpoint.
fn signed_request(
    method: &str,
    path: &str,
    body: &[u8],
    bearer: &str,
    signing_key: &SigningKey,
) -> Request<Body> {
    signed_request_at(
        method,
        path,
        body,
        bearer,
        signing_key,
        Utc::now().timestamp(),
    )
}

/// Like `signed_request` but with a caller-supplied timestamp.
fn signed_request_at(
    method: &str,
    path: &str,
    body: &[u8],
    bearer: &str,
    signing_key: &SigningKey,
    timestamp: i64,
) -> Request<Body> {
    let body_hash = hex::encode(Sha256::digest(body));
    let payload = format!("{method}\n{path}\n{timestamp}\n{body_hash}");
    let signature = signing_key.sign(payload.as_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

    Request::builder()
        .method(method)
        .uri(path)
        .header("Authorization", format!("Bearer {bearer}"))
        .header("X-Wardnet-Timestamp", timestamp.to_string())
        .header("X-Wardnet-Signature", sig_b64)
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_vec()))
        .unwrap()
}

/// Collect the response body into a UTF-8 string.
async fn body_string(body: axum::body::Body) -> String {
    let bytes = body.collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// ── Health endpoint ──────────────────────────────────────────────────────────

#[tokio::test]
async fn health_returns_200() {
    let (state, _dns, _mocks) = test_state();
    let app = test_app(state);
    let req = Request::builder()
        .uri("/v1/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── Auth middleware (JWT-only) ───────────────────────────────────────────────

#[tokio::test]
async fn auth_rejects_body_over_1_mib() {
    let (state, _dns, _mocks) = test_state();
    let id = Uuid::new_v4().to_string();
    let jwt = auth_jwt(&id, "test-node");

    let app = test_app(state);
    let oversized = vec![b'x'; 1024 * 1024 + 1];
    let timestamp = Utc::now().timestamp();
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/v1/installs/{id}/ip"))
        .header("Authorization", format!("Bearer {jwt}"))
        .header("X-Wardnet-Timestamp", timestamp.to_string())
        .header("X-Wardnet-Signature", "dGVzdA==")
        .header("Content-Type", "application/json")
        .body(Body::from(oversized))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert!(json["error"].as_str().unwrap().contains("1 MiB"));
}

#[tokio::test]
async fn auth_passes_unauthenticated_endpoints_without_header() {
    let (state, _dns, _mocks) = test_state();
    let app = test_app(state);
    let req = Request::builder()
        .uri("/v1/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn auth_returns_401_when_bearer_prefix_is_missing() {
    let (state, _dns, _mocks) = test_state();
    let id = Uuid::new_v4().to_string();

    let app = test_app(state);
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/v1/installs/{id}/ip"))
        .header("Authorization", "Token not-bearer")
        .header("X-Wardnet-Timestamp", Utc::now().timestamp().to_string())
        .header("X-Wardnet-Signature", "dGVzdA==")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"ip":"203.0.113.1"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("Authorization header")
    );
}

#[tokio::test]
async fn auth_rejects_opaque_bearer_token() {
    // Cloud is JWT-only: an opaque (non-JWT-shaped) bearer is a hard 401 here — only
    // the Tenants service holds the table to resolve it.
    let (state, _dns, _mocks) = test_state();
    let id = Uuid::new_v4().to_string();

    let app = test_app(state);
    let opaque = hex::encode([42u8; 32]); // hex, no dots → not JWT-shaped
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/v1/installs/{id}/ip"))
        .header("Authorization", format!("Bearer {opaque}"))
        .header("X-Wardnet-Timestamp", Utc::now().timestamp().to_string())
        .header("X-Wardnet-Signature", "dGVzdA==")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"ip":"203.0.113.1"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert!(
        json["error"].as_str().unwrap().contains("identity JWT"),
        "the rejection must point the daemon at the JWT path"
    );
}

#[tokio::test]
async fn auth_returns_401_when_timestamp_header_is_absent() {
    let (state, _dns, _mocks) = test_state();
    let id = Uuid::new_v4().to_string();
    let jwt = auth_jwt(&id, "test-node");

    let app = test_app(state);
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/v1/installs/{id}/ip"))
        .header("Authorization", format!("Bearer {jwt}"))
        .header("X-Wardnet-Signature", "dGVzdA==")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"ip":"203.0.113.1"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert!(json["error"].as_str().unwrap().contains("Timestamp"));
}

#[tokio::test]
async fn auth_returns_401_when_timestamp_is_stale() {
    let (state, _dns, _mocks) = test_state();
    let id = Uuid::new_v4().to_string();
    let jwt = auth_jwt(&id, "test-node");

    let app = test_app(state);
    let past_ts = Utc::now().timestamp() - 120;
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/v1/installs/{id}/ip"))
        .header("Authorization", format!("Bearer {jwt}"))
        .header("X-Wardnet-Timestamp", past_ts.to_string())
        .header("X-Wardnet-Signature", "dGVzdA==")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"ip":"203.0.113.1"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert!(json["error"].as_str().unwrap().contains("window"));
}

#[tokio::test]
async fn auth_returns_401_for_invalid_signature() {
    let (state, _dns, _mocks) = test_state();
    let id = Uuid::new_v4().to_string();
    let jwt = auth_jwt(&id, "test-node");

    let app = test_app(state);
    let bad_sig = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/v1/installs/{id}/ip"))
        .header("Authorization", format!("Bearer {jwt}"))
        .header("X-Wardnet-Timestamp", Utc::now().timestamp().to_string())
        .header("X-Wardnet-Signature", bad_sig)
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"ip":"203.0.113.1"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert!(json["error"].as_str().unwrap().contains("signature"));
}

#[tokio::test]
async fn auth_returns_401_on_replayed_request() {
    let (state, _dns, _mocks) = test_state();
    let id = Uuid::new_v4().to_string();
    let jwt = auth_jwt(&id, "test-node");
    let signing_key = test_signing_key();

    let timestamp = Utc::now().timestamp();
    let body = br#"{"ip":"8.8.8.8"}"#;
    let path = format!("/v1/installs/{id}/ip");

    let app = test_app(state);

    let req1 = signed_request_at("PUT", &path, body, &jwt, &signing_key, timestamp);
    let resp1 = app.clone().oneshot(req1).await.unwrap();
    assert_eq!(
        resp1.status(),
        StatusCode::NO_CONTENT,
        "first signed request should succeed"
    );

    let req2 = signed_request_at("PUT", &path, body, &jwt, &signing_key, timestamp);
    let resp2 = app.oneshot(req2).await.unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::UNAUTHORIZED,
        "replayed request should be rejected"
    );
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp2.into_body()).await).unwrap();
    assert!(json["error"].as_str().unwrap().contains("replay"));
}

#[tokio::test]
async fn jwt_path_accepts_valid_token_with_pop_and_no_db_lookup() {
    // No operational row is seeded — the JWT path authenticates OFFLINE (no DB).
    let (state, _dns, _mocks) = test_state();
    let id = "inst-jwt-1";
    let jwt = auth_jwt(id, "happy-node");
    let signing_key = test_signing_key(); // its public key == the JWT's `cnf`

    let body = br#"{"ip":"8.8.8.8"}"#;
    let req = signed_request(
        "PUT",
        "/v1/installs/inst-jwt-1/ip",
        body,
        &jwt,
        &signing_key,
    );
    let resp = test_app(state).oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "a valid JWT + PoP should authenticate with no DB lookup"
    );
}

#[tokio::test]
async fn jwt_path_rejects_expired_token() {
    let (state, _dns, _mocks) = test_state();
    let jwt = test_identity_jwt("inst-jwt-2", "happy-node", -120); // exp in the past
    let body = br#"{"ip":"8.8.8.8"}"#;
    let req = signed_request(
        "PUT",
        "/v1/installs/inst-jwt-2/ip",
        body,
        &jwt,
        &test_signing_key(),
    );
    let resp = test_app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert!(json["error"].as_str().unwrap().contains("identity token"));
}

#[tokio::test]
async fn jwt_path_rejects_token_from_a_foreign_signer() {
    // A JWT signed by a key the AppState verifier does not trust.
    let (state, _dns, _mocks) = test_state();
    let foreign = token::Signer::from_pem(jwt_keypair_pem(99).0.as_bytes(), None).unwrap();
    let (_, cnf_b64) = test_pub_key();
    let jwt = foreign
        .sign(
            "inst-jwt-4",
            "happy-node",
            &cnf_b64,
            Utc::now().timestamp(),
            3600,
        )
        .unwrap();
    let body = br#"{"ip":"8.8.8.8"}"#;
    let req = signed_request(
        "PUT",
        "/v1/installs/inst-jwt-4/ip",
        body,
        &jwt,
        &test_signing_key(),
    );
    let resp = test_app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_path_rejects_pop_signed_by_the_wrong_key() {
    // Valid JWT (cnf = the daemon key), but the request is signed by a DIFFERENT
    // key: a stolen token is inert without the daemon's private key.
    let (state, _dns, _mocks) = test_state();
    let jwt = auth_jwt("inst-jwt-5", "happy-node");
    let attacker_key = SigningKey::from_bytes(&[9u8; 32]);
    let body = br#"{"ip":"8.8.8.8"}"#;
    let req = signed_request(
        "PUT",
        "/v1/installs/inst-jwt-5/ip",
        body,
        &jwt,
        &attacker_key,
    );
    let resp = test_app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert!(json["error"].as_str().unwrap().contains("signature"));
}

#[tokio::test]
async fn auth_missing_from_authenticated_endpoint_returns_401() {
    let (state, _dns, _mocks) = test_state();
    let id = Uuid::new_v4().to_string();

    let app = test_app(state);
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/v1/installs/{id}/ip"))
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"ip":"203.0.113.1"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── IP-update endpoint ───────────────────────────────────────────────────────

#[tokio::test]
async fn update_ip_success() {
    let (state, dns, _mocks) = test_state();
    let id = Uuid::new_v4().to_string();
    let jwt = auth_jwt(&id, "test-node");
    let signing_key = test_signing_key();

    let body = br#"{"ip":"8.8.8.8"}"#;
    let path = format!("/v1/installs/{id}/ip");
    let req = signed_request("PUT", &path, body, &jwt, &signing_key);

    let app = test_app(state);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        dns.call_count(),
        1,
        "one DNS upsert-A should have been made"
    );
}

#[tokio::test]
async fn update_ip_returns_400_for_invalid_ip_string() {
    let (state, _dns, _mocks) = test_state();
    let id = Uuid::new_v4().to_string();
    let jwt = auth_jwt(&id, "test-node");
    let signing_key = test_signing_key();

    let body = br#"{"ip":"not-an-ip"}"#;
    let path = format!("/v1/installs/{id}/ip");
    let req = signed_request("PUT", &path, body, &jwt, &signing_key);

    let app = test_app(state);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert!(json["error"].as_str().unwrap().contains("valid IPv4"));
}

#[tokio::test]
async fn update_ip_returns_400_for_private_addresses() {
    let (state, _dns, _mocks) = test_state();
    let id = Uuid::new_v4().to_string();
    let jwt = auth_jwt(&id, "test-node");
    let signing_key = test_signing_key();

    for private in &[
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "127.0.0.1",
        "169.254.0.1",
    ] {
        let body = format!(r#"{{"ip":"{private}"}}"#).into_bytes();
        let path = format!("/v1/installs/{id}/ip");
        let req = signed_request("PUT", &path, &body, &jwt, &signing_key);

        let app = test_app(state.clone());
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "expected 400 for private IP {private}"
        );
        let json: serde_json::Value =
            serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
        assert!(
            json["error"].as_str().unwrap().contains("private"),
            "error should mention private for {private}"
        );
    }
}

#[tokio::test]
async fn update_ip_returns_403_when_install_id_does_not_match_token() {
    let (state, _dns, _mocks) = test_state();
    let id = Uuid::new_v4().to_string();
    let jwt = auth_jwt(&id, "test-node");
    let signing_key = test_signing_key();

    let other_id = Uuid::new_v4().to_string();
    let body = br#"{"ip":"203.0.113.1"}"#;
    let path = format!("/v1/installs/{other_id}/ip");
    let req = signed_request("PUT", &path, body, &jwt, &signing_key);

    let app = test_app(state);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn update_ip_returns_500_when_dns_fails() {
    let dns = Arc::new(MockDnsProvider::with_error("cloudflare unavailable"));
    let (state, _mocks) = test_state_dns(dns);
    let id = Uuid::new_v4().to_string();
    let jwt = auth_jwt(&id, "test-node");
    let signing_key = test_signing_key();

    let body = br#"{"ip":"8.8.8.8"}"#;
    let path = format!("/v1/installs/{id}/ip");
    let req = signed_request("PUT", &path, body, &jwt, &signing_key);

    let app = test_app(state);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// ── ACME-challenge endpoint ──────────────────────────────────────────────────

#[tokio::test]
async fn set_acme_challenge_success() {
    let (state, _dns, mocks) = test_state();
    let id = Uuid::new_v4().to_string();
    let jwt = auth_jwt(&id, "test-node");
    let signing_key = test_signing_key();

    let body = br#"{"values":["acme-apex","acme-wildcard"]}"#;
    let path = format!("/v1/installs/{id}/acme-challenge");
    let req = signed_request("PUT", &path, body, &jwt, &signing_key);

    let app = test_app(state);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Both TXT record IDs are persisted on the operational row.
    let updated = mocks.operational.find_by_id(&id).await.unwrap().unwrap();
    assert_eq!(updated.cf_acme_record_ids.len(), 2);
}

#[tokio::test]
async fn set_acme_challenge_returns_403_on_id_mismatch() {
    let (state, _dns, _mocks) = test_state();
    let id = Uuid::new_v4().to_string();
    let jwt = auth_jwt(&id, "test-node");
    let signing_key = test_signing_key();

    let other_id = Uuid::new_v4().to_string();
    let body = br#"{"values":["my-acme-token"]}"#;
    let path = format!("/v1/installs/{other_id}/acme-challenge");
    let req = signed_request("PUT", &path, body, &jwt, &signing_key);

    let resp = test_app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn set_acme_challenge_returns_500_when_dns_fails() {
    let dns = Arc::new(MockDnsProvider::with_error("cloudflare unavailable"));
    let (state, _mocks) = test_state_dns(dns);
    let id = Uuid::new_v4().to_string();
    let jwt = auth_jwt(&id, "test-node");
    let signing_key = test_signing_key();

    let body = br#"{"values":["my-acme-token"]}"#;
    let path = format!("/v1/installs/{id}/acme-challenge");
    let req = signed_request("PUT", &path, body, &jwt, &signing_key);

    let resp = test_app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn set_acme_challenge_rejects_oversized_value_list() {
    let (state, _dns, _mocks) = test_state();
    let id = Uuid::new_v4().to_string();
    let jwt = auth_jwt(&id, "test-node");
    let signing_key = test_signing_key();

    let values: Vec<String> = (0..100).map(|i| format!("acme-{i}")).collect();
    let body = serde_json::to_vec(&serde_json::json!({ "values": values })).unwrap();
    let path = format!("/v1/installs/{id}/acme-challenge");
    let req = signed_request("PUT", &path, &body, &jwt, &signing_key);

    let resp = test_app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn set_acme_challenge_rejects_empty_value_list() {
    let (state, _dns, _mocks) = test_state();
    let id = Uuid::new_v4().to_string();
    let jwt = auth_jwt(&id, "test-node");
    let signing_key = test_signing_key();

    let body = br#"{"values":[]}"#;
    let path = format!("/v1/installs/{id}/acme-challenge");
    let req = signed_request("PUT", &path, body, &jwt, &signing_key);

    let resp = test_app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_acme_challenge_deletes_dns_record_when_present() {
    let (state, dns, mocks) = test_state();
    let id = Uuid::new_v4().to_string();
    let jwt = auth_jwt(&id, "test-node");
    let signing_key = test_signing_key();

    // Two live records (apex + wildcard SAN) → both must be deleted.
    mocks
        .operational
        .cas_acme_records(
            &id,
            &[],
            &["cf-txt-apex".to_string(), "cf-txt-wildcard".to_string()],
            Utc::now(),
        )
        .await
        .unwrap();

    let body = b"";
    let path = format!("/v1/installs/{id}/acme-challenge");
    let req = signed_request("DELETE", &path, body, &jwt, &signing_key);

    let app = test_app(state);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(dns.call_count(), 2, "one DNS delete per live record");
}

#[tokio::test]
async fn delete_acme_challenge_is_noop_when_no_record_set() {
    let (state, dns, _mocks) = test_state();
    let id = Uuid::new_v4().to_string();
    let jwt = auth_jwt(&id, "test-node");
    let signing_key = test_signing_key();

    let body = b"";
    let path = format!("/v1/installs/{id}/acme-challenge");
    let req = signed_request("DELETE", &path, body, &jwt, &signing_key);

    let app = test_app(state);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(dns.call_count(), 0, "no DNS calls when no records are set");
}

#[tokio::test]
async fn delete_acme_challenge_returns_403_on_id_mismatch() {
    let (state, _dns, _mocks) = test_state();
    let id = Uuid::new_v4().to_string();
    let jwt = auth_jwt(&id, "test-node");
    let signing_key = test_signing_key();

    let other_id = Uuid::new_v4().to_string();
    let path = format!("/v1/installs/{other_id}/acme-challenge");
    let req = signed_request("DELETE", &path, b"", &jwt, &signing_key);

    let resp = test_app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn delete_acme_challenge_returns_500_when_dns_fails() {
    let dns = Arc::new(MockDnsProvider::with_error("cloudflare unavailable"));
    let (state, mocks) = test_state_dns(dns);
    let id = Uuid::new_v4().to_string();
    let jwt = auth_jwt(&id, "test-node");
    let signing_key = test_signing_key();

    mocks
        .operational
        .cas_acme_records(&id, &[], &["cf-txt-id".to_string()], Utc::now())
        .await
        .unwrap();

    let body = b"";
    let path = format!("/v1/installs/{id}/acme-challenge");
    let req = signed_request("DELETE", &path, body, &jwt, &signing_key);

    let resp = test_app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// ── State accessors ──────────────────────────────────────────────────────────

#[tokio::test]
async fn config_accessors_return_expected_values() {
    let (state, _dns, _mocks) = test_state();
    let cfg = state.config();
    assert_eq!(cfg.region, "test");
    assert_eq!(cfg.subdomain_parent, "test.wardnet.local");
    assert_eq!(cfg.install_fqdn("mynode"), "mynode.test.wardnet.local");
    assert_eq!(
        cfg.acme_fqdn("mynode"),
        "_acme-challenge.mynode.test.wardnet.local"
    );
}

#[tokio::test]
async fn state_tunnel_registry_returns_same_instance() {
    let (state, _dns, _mocks) = test_state();
    let r1 = state.tunnel_registry();
    let r2 = state.tunnel_registry();
    // Both arcs should point to the same allocation.
    assert!(Arc::ptr_eq(&r1, &r2));
}

// ── Tunnel WebSocket endpoint ─────────────────────────────────────────────────

#[tokio::test]
async fn tunnel_connect_returns_401_without_auth() {
    let (state, _dns, _mocks) = test_state();
    let app = test_app(state);
    let req = Request::builder()
        .method("GET")
        .uri("/v1/installs/some-id/tunnel")
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn tunnel_connect_returns_403_when_install_id_does_not_match() {
    use tokio::net::TcpListener as StdTcpListener;
    use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest};

    let (state, _dns, _mocks) = test_state();
    let id = Uuid::new_v4().to_string();
    let jwt = auth_jwt(&id, "test-node");
    let signing_key = test_signing_key();

    // Spin up a real server so WebSocketUpgrade extraction succeeds.
    let listener = StdTcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let router = wardnet_cloud::api::router(state)
        .into_make_service_with_connect_info::<std::net::SocketAddr>();
    tokio::spawn(axum::serve(listener, router).into_future());

    // Sign for a different install id — auth passes (valid token) but handler
    // rejects because the install id in the path doesn't match the token.
    let other_id = Uuid::new_v4().to_string();
    let path = format!("/v1/installs/{other_id}/tunnel");
    let dummy_req = signed_request("GET", &path, b"", &jwt, &signing_key);
    let ts = dummy_req
        .headers()
        .get("X-Wardnet-Timestamp")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let sig = dummy_req
        .headers()
        .get("X-Wardnet-Signature")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    let url = format!("ws://127.0.0.1:{port}{path}");
    let mut req = url.into_client_request().unwrap();
    req.headers_mut()
        .insert("Authorization", format!("Bearer {jwt}").parse().unwrap());
    req.headers_mut()
        .insert("X-Wardnet-Timestamp", ts.parse().unwrap());
    req.headers_mut()
        .insert("X-Wardnet-Signature", sig.parse().unwrap());

    // Should be rejected with 403 — handler checks install.id != path id.
    let result = connect_async(req).await;
    match result {
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            assert_eq!(resp.status(), 403);
        }
        other => panic!("expected HTTP 403 error, got: {other:?}"),
    }
}

#[tokio::test]
async fn tunnel_connect_establishes_websocket_and_handler_runs() {
    use tokio::net::TcpListener as StdTcpListener;
    use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest};

    let (state, _dns, _mocks) = test_state();
    let id = Uuid::new_v4().to_string();
    let jwt = auth_jwt(&id, "test-node");
    let signing_key = test_signing_key();

    // Spin up a real server (needed for actual WS upgrade handshake).
    let listener = StdTcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let router = wardnet_cloud::api::router(state)
        .into_make_service_with_connect_info::<std::net::SocketAddr>();
    tokio::spawn(axum::serve(listener, router).into_future());

    // Build the signed request headers.
    let path = format!("/v1/installs/{id}/tunnel");
    let dummy_req = signed_request("GET", &path, b"", &jwt, &signing_key);
    let ts = dummy_req
        .headers()
        .get("X-Wardnet-Timestamp")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let sig = dummy_req
        .headers()
        .get("X-Wardnet-Signature")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    let url = format!("ws://127.0.0.1:{port}{path}");
    let mut req = url.into_client_request().unwrap();
    req.headers_mut()
        .insert("Authorization", format!("Bearer {jwt}").parse().unwrap());
    req.headers_mut()
        .insert("X-Wardnet-Timestamp", ts.parse().unwrap());
    req.headers_mut()
        .insert("X-Wardnet-Signature", sig.parse().unwrap());

    // Connect — should get 101 and a live WebSocket.
    let (mut ws, response) = connect_async(req).await.expect("WS connect failed");
    assert_eq!(response.status(), 101);

    // Send a custom PING frame (conn_id=0) and the handler echoes PONG.
    ws.send(WsMessage::Binary(vec![0x05u8, 0, 0, 0, 0].into()))
        .await
        .unwrap();

    // Receive the PONG (first message back from handler).
    if let Some(Ok(WsMessage::Binary(bytes))) = ws.next().await {
        assert_eq!(bytes[0], 0x06); // FRAME_PONG
    }

    ws.close(None).await.ok();
}

/// Exercises `handler::run()`'s `forward_rx` arm (inbound TCP from SNI demuxer)
/// and `tcp_out_rx` arms (DATA and EOF from the active TCP connection).
#[tokio::test]
async fn tunnel_handler_forward_and_tcp_data_flow() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener as StdTcpListener;
    use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest};
    use wardnet_cloud::tunnel::ForwardRequest;

    let (state, _dns, _mocks) = test_state();
    let id = Uuid::new_v4().to_string();
    let name = "test-node";
    let jwt = auth_jwt(&id, name);
    let signing_key = test_signing_key();
    let registry = state.tunnel_registry();

    let server_listener = StdTcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = server_listener.local_addr().unwrap().port();
    let router = wardnet_cloud::api::router(state)
        .into_make_service_with_connect_info::<std::net::SocketAddr>();
    tokio::spawn(axum::serve(server_listener, router).into_future());

    // Connect Pi via WebSocket.
    let path = format!("/v1/installs/{id}/tunnel");
    let dummy_req = signed_request("GET", &path, b"", &jwt, &signing_key);
    let ts = dummy_req
        .headers()
        .get("X-Wardnet-Timestamp")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let sig = dummy_req
        .headers()
        .get("X-Wardnet-Signature")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    let url = format!("ws://127.0.0.1:{port}{path}");
    let mut req = url.into_client_request().unwrap();
    req.headers_mut()
        .insert("Authorization", format!("Bearer {jwt}").parse().unwrap());
    req.headers_mut()
        .insert("X-Wardnet-Timestamp", ts.parse().unwrap());
    req.headers_mut()
        .insert("X-Wardnet-Signature", sig.parse().unwrap());

    let (mut ws, _) = connect_async(req).await.expect("WS connect failed");

    // Wait for handler::run() to call registry.register().
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Set up a "Pi-local server" that the Pi will connect to when it gets READY.
    let pi_local = StdTcpListener::bind("127.0.0.1:0").await.unwrap();
    let pi_local_addr = pi_local.local_addr().unwrap();

    // Forward a fake inbound TCP stream to the Pi — exercises the forward_rx arm.
    let inbound = tokio::net::TcpStream::connect(pi_local_addr).await.unwrap();
    let _ = registry.forward(
        name,
        ForwardRequest {
            stream: inbound,
            dest_port: 443,
        },
    );

    // Pi receives CONNECT frame.
    let conn_id = if let Some(Ok(WsMessage::Binary(bytes))) = ws.next().await {
        assert_eq!(bytes[0], 0x01, "expected FRAME_CONNECT");
        u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]])
    } else {
        panic!("expected CONNECT frame");
    };

    // Pi sends READY — exercises handle_pi_frame READY branch and spawns tcp tasks.
    let mut ready = vec![0x02u8, 0, 0, 0, 0];
    ready[1..5].copy_from_slice(&conn_id.to_be_bytes());
    ws.send(WsMessage::Binary(ready.into())).await.unwrap();

    // Accept the Pi-side TCP connection and write some data + close.
    let (mut pi_conn, _) = pi_local.accept().await.unwrap();
    pi_conn.write_all(b"hello").await.unwrap();
    drop(pi_conn); // EOF → tcp_reader sends empty Bytes → bridge sends CLOSE

    // Pi receives DATA frame then CLOSE frame — exercises the tcp_out_rx arms.
    let mut saw_data = false;
    let mut saw_close = false;
    while let Ok(Some(Ok(WsMessage::Binary(bytes)))) =
        tokio::time::timeout(std::time::Duration::from_secs(2), ws.next()).await
    {
        match bytes[0] {
            0x03 => saw_data = true,
            0x04 => {
                saw_close = true;
                break;
            }
            _ => {}
        }
    }
    assert!(saw_data, "expected DATA frame from bridge");
    assert!(saw_close, "expected CLOSE frame from bridge");

    ws.close(None).await.ok();
}
