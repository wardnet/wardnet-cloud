//! Full-stack integration tests for the Tenants public HTTP API.
//!
//! These tests build the public Tenants Axum router with mock in-memory
//! repositories, then drive requests through [`tower::ServiceExt::oneshot`].
//!
//! # Test conventions
//!
//! - Every test creates its own isolated state via `test_state()`.
//! - Challenges are inserted directly with `difficulty = 0` so no real `PoW`
//!   computation is needed.
//! - Ed25519 signing uses a deterministic test key derived from `[1u8; 32]`.
//! - The loopback peer (`127.0.0.1`) is injected via `MockConnectInfo` so
//!   handlers that call `client_ip()` see a non-forwarded address.
//! - Tenants accepts **both** credential paths: the opaque bearer token (a DB
//!   lookup) and the identity JWT (offline verify). Both are exercised here.

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use tower::ServiceExt as _;
use uuid::Uuid;

use common::{ChallengeStore, MockChallengeRepository, MockIdentityRepository, jwt_keypair_pem};
use wardnet_common::token;
use wardnet_tenants::config::Config;
use wardnet_tenants::repository::{
    ChallengeRepository, Identity, IdentityRepository, RegistrationChallenge, Status,
};
use wardnet_tenants::service::TenantsService;
use wardnet_tenants::state::AppState;

/// Seed for the deterministic JWT signing keypair the test harness uses. The
/// `Signer` is built from `jwt_keypair_pem(JWT_TEST_SEED).0`; tests verifying a
/// minted JWT use `.1` (the matching public key).
const JWT_TEST_SEED: u8 = 7;

/// Mock repository handles, retained by a test so it can seed fixtures directly
/// while the production code path under test reaches them only through the
/// service that wraps them.
struct Mocks {
    identity: Arc<MockIdentityRepository>,
    challenges: Arc<MockChallengeRepository>,
}

// ── Shared test fixtures ─────────────────────────────────────────────────────

fn test_config() -> Config {
    Config {
        global_database_url: "postgres://ignored-global".to_string(),
        region: "test".to_string(),
        subdomain_parent: "test.wardnet.local".to_string(),
        api_listen_addr: "127.0.0.1:0".to_string(),
        introspect_listen_addr: "127.0.0.1:0".to_string(),
        mesh_ca_path: "/dev/null".to_string(),
        mesh_cert_path: "/dev/null".to_string(),
        mesh_key_path: "/dev/null".to_string(),
    }
}

/// Build an `AppState` whose service wraps a fresh set of mock repos, returning the
/// [`Mocks`] handles for direct fixture seeding.
fn build_state() -> (AppState, Mocks) {
    // Identity and challenge mocks share one challenge store so the identity
    // mock's atomic `register` burns the same challenge the challenge mock issued.
    let store: ChallengeStore = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let identity = Arc::new(MockIdentityRepository::new(Arc::clone(&store)));
    let challenges = Arc::new(MockChallengeRepository::new(Arc::clone(&store)));

    let config = test_config();
    let signer =
        token::Signer::from_pem(jwt_keypair_pem(JWT_TEST_SEED).0.as_bytes(), None).unwrap();
    let tenants = Arc::new(TenantsService::new(
        Arc::clone(&identity) as Arc<dyn IdentityRepository>,
        Arc::clone(&challenges) as Arc<dyn ChallengeRepository>,
        signer,
    ));
    let state = AppState::new(config, tenants, test_jwt_verifier());
    (
        state,
        Mocks {
            identity,
            challenges,
        },
    )
}

/// JWT verifier matching the harness signer (`jwt_keypair_pem(JWT_TEST_SEED)`).
fn test_jwt_verifier() -> token::Verifier {
    token::Verifier::from_pem(jwt_keypair_pem(JWT_TEST_SEED).1.as_bytes()).unwrap()
}

/// Mint a Tenants-signed identity JWT with the harness signing key. `cnf` is the
/// daemon's public key (`test_pub_key().1`) so `PoP` verifies against a
/// `test_signing_key()`-signed request.
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

fn test_state() -> (AppState, Mocks) {
    build_state()
}

/// Build the public Tenants router under test with a fixed loopback peer address.
fn test_app(state: AppState) -> axum::Router {
    wardnet_tenants::api::router(state)
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345))))
}

/// Ed25519 signing key for tests — deterministic, derived from `[1u8; 32]`.
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

/// Return a deterministic `(raw_token_hex, token_hash_hex)` pair.
fn test_bearer_token() -> (String, String) {
    let raw = hex::encode([42u8; 32]);
    let hash = hex::encode(Sha256::digest(raw.as_bytes()));
    (raw, hash)
}

/// Seed a test identity directly into the mock and return it and its raw token.
/// The identity is what the bearer auth path resolves the token to.
#[allow(clippy::unused_async)]
async fn insert_test_install(mocks: &Mocks, name: &str) -> (Identity, String) {
    let (raw_token, token_hash) = test_bearer_token();
    let (pub_key_bytes, public_key) = test_pub_key();
    let identity = Identity {
        id: Uuid::new_v4().to_string(),
        name: name.to_string(),
        region: "test".to_string(),
        public_key,
        pub_key_bytes,
        token_hash,
        status: Status::Active,
        created_at: Utc::now(),
    };
    mocks.identity.seed(identity.clone());
    (identity, raw_token)
}

/// Claim a name by seeding an identity that already holds it — simulating a name
/// taken by a prior registration (availability + registration both consult the
/// global identity table).
#[allow(clippy::unused_async)]
async fn claim_name(mocks: &Mocks, name: &str) {
    let (pub_key_bytes, public_key) = test_pub_key();
    mocks.identity.seed(Identity {
        id: Uuid::new_v4().to_string(),
        name: name.to_string(),
        region: "test".to_string(),
        public_key,
        pub_key_bytes,
        token_hash: hex::encode(Sha256::digest(name.as_bytes())),
        status: Status::Active,
        created_at: Utc::now(),
    });
}

/// Insert a challenge with `difficulty = 0` (any `proof` satisfies it).
async fn insert_easy_challenge(mocks: &Mocks, remote_ip: &str) -> RegistrationChallenge {
    let now = Utc::now();
    let challenge = RegistrationChallenge {
        id: Uuid::new_v4().to_string(),
        nonce: hex::encode([7u8; 32]),
        difficulty: 0,
        remote_ip: remote_ip.to_string(),
        created_at: now,
        expires_at: now + chrono::Duration::minutes(5),
        used_at: None,
    };
    mocks.challenges.insert(&challenge).await.unwrap();
    challenge
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
    let (state, _mocks) = test_state();
    let app = test_app(state);
    let req = Request::builder()
        .uri("/v1/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── Challenge endpoint ───────────────────────────────────────────────────────

#[tokio::test]
async fn get_challenge_returns_200_with_fields() {
    let (state, _mocks) = test_state();
    let app = test_app(state);
    let req = Request::builder()
        .uri("/v1/register/challenge")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert!(json["challenge_id"].as_str().is_some());
    assert!(json["nonce"].as_str().is_some());
    assert!(json["difficulty"].as_u64().is_some());
    assert!(json["expires_at"].as_str().is_some());
}

#[tokio::test]
async fn get_challenge_rate_limited_at_20_per_hour() {
    let (state, mocks) = test_state();

    for _ in 0..20 {
        let c = RegistrationChallenge {
            id: Uuid::new_v4().to_string(),
            nonce: hex::encode([0u8; 32]),
            difficulty: 0,
            remote_ip: "127.0.0.1".to_string(),
            created_at: Utc::now() - chrono::Duration::minutes(10),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            used_at: None,
        };
        mocks.challenges.insert(&c).await.unwrap();
    }

    let app = test_app(state);
    let req = Request::builder()
        .uri("/v1/register/challenge")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

// ── Name-availability endpoint ───────────────────────────────────────────────

#[tokio::test]
async fn name_available_for_fresh_name() {
    let (state, _mocks) = test_state();
    let app = test_app(state);
    let req = Request::builder()
        .uri("/v1/names/happy-einstein/available")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(json["available"], true);
}

#[tokio::test]
async fn name_unavailable_when_already_registered() {
    let (state, mocks) = test_state();
    claim_name(&mocks, "happy-einstein").await;

    let app = test_app(state);
    let req = Request::builder()
        .uri("/v1/names/happy-einstein/available")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(json["available"], false);
}

#[tokio::test]
async fn name_unavailable_when_held_by_an_identity() {
    // A name allocated to a registered identity reads as taken.
    let (state, mocks) = test_state();
    claim_name(&mocks, "happy-einstein").await;

    let app = test_app(state);
    let req = Request::builder()
        .uri("/v1/names/happy-einstein/available")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(json["available"], false);
}

#[tokio::test]
async fn name_unavailable_for_reserved_slug() {
    let (state, _mocks) = test_state();
    let app = test_app(state);
    for reserved in &["www", "admin", "us", "api"] {
        let req = Request::builder()
            .uri(format!("/v1/names/{reserved}/available"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let json: serde_json::Value =
            serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
        assert_eq!(
            json["available"], false,
            "expected {reserved} to be unavailable"
        );
    }
}

#[tokio::test]
async fn name_unavailable_for_syntactically_invalid_name() {
    let (state, _mocks) = test_state();
    let app = test_app(state);
    for invalid in &["-bad", "bad-", "ab", "ALLCAPS", "has space"] {
        let encoded = invalid.replace(' ', "%20");
        let req = Request::builder()
            .uri(format!("/v1/names/{encoded}/available"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let json: serde_json::Value =
            serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
        assert_eq!(
            json["available"], false,
            "expected '{invalid}' to be unavailable"
        );
    }
}

// ── Register endpoint ────────────────────────────────────────────────────────

fn register_body(
    name: &str,
    pub_key_b64: &str,
    challenge_id: &str,
    proof: u64,
) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "public_key": pub_key_b64,
        "challenge_id": challenge_id,
        "proof": proof,
    })
}

#[tokio::test]
async fn register_success_creates_install_and_returns_token() {
    let (state, mocks) = test_state();
    let challenge = insert_easy_challenge(&mocks, "127.0.0.1").await;
    let (_, pub_key_b64) = test_pub_key();

    let body = register_body("happy-einstein", &pub_key_b64, &challenge.id, 0);
    let app = test_app(state);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/register")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert!(json["id"].as_str().is_some(), "must return an id");
    assert!(
        json["bearer_token"].as_str().is_some(),
        "must return a bearer_token"
    );
    assert_eq!(json["region"], "test");
    assert!(
        json["subdomain"]
            .as_str()
            .unwrap()
            .ends_with(".test.wardnet.local"),
        "subdomain should end with subdomain_parent"
    );
}

#[tokio::test]
async fn register_returns_a_verifiable_identity_jwt() {
    let (state, mocks) = test_state();
    let challenge = insert_easy_challenge(&mocks, "127.0.0.1").await;
    let (_, pub_key_b64) = test_pub_key();

    let body = register_body("happy-einstein", &pub_key_b64, &challenge.id, 0);
    let app = test_app(state);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/register")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();

    let jwt = json["identity_jwt"]
        .as_str()
        .expect("must return an identity_jwt");
    let id = json["id"].as_str().unwrap();

    // The minted JWT verifies against the matching Tenants public key and carries
    // the right identity claims (sub = install id, vanity = name, cnf = daemon key).
    let verifier = token::Verifier::from_pem(jwt_keypair_pem(JWT_TEST_SEED).1.as_bytes()).unwrap();
    let claims = verifier.verify(jwt).expect("identity JWT must verify");
    assert_eq!(claims.iss, "tenants");
    assert_eq!(claims.sub, id);
    assert_eq!(claims.vanity, "happy-einstein");
    assert_eq!(
        claims.cnf.ed25519, pub_key_b64,
        "cnf must be the daemon's own public key (sender-constrained)"
    );
}

#[tokio::test]
async fn register_returns_400_for_invalid_name() {
    let (state, mocks) = test_state();
    let challenge = insert_easy_challenge(&mocks, "127.0.0.1").await;
    let (_, pub_key_b64) = test_pub_key();

    for bad_name in &["AB", "-foo", "foo-", "a b", "CAPS"] {
        let body = register_body(bad_name, &pub_key_b64, &challenge.id, 0);
        let app = test_app(state.clone());
        let req = Request::builder()
            .method("POST")
            .uri("/v1/register")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "expected 400 for name '{bad_name}'"
        );
    }
}

#[tokio::test]
async fn register_returns_400_for_reserved_name() {
    let (state, mocks) = test_state();
    let challenge = insert_easy_challenge(&mocks, "127.0.0.1").await;
    let (_, pub_key_b64) = test_pub_key();

    let body = register_body("www", &pub_key_b64, &challenge.id, 0);
    let app = test_app(state);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/register")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn register_returns_400_for_invalid_public_key() {
    let (state, mocks) = test_state();
    let challenge = insert_easy_challenge(&mocks, "127.0.0.1").await;

    let body = register_body("test-name", "not!valid!base64", &challenge.id, 0);
    let app = test_app(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/v1/register")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let short_key = base64::engine::general_purpose::STANDARD.encode([0u8; 31]);
    let body2 = register_body("test-name", &short_key, &challenge.id, 0);
    let app2 = test_app(state);
    let req2 = Request::builder()
        .method("POST")
        .uri("/v1/register")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body2).unwrap()))
        .unwrap();
    let resp2 = app2.oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn register_returns_400_for_unknown_challenge() {
    let (state, _mocks) = test_state();
    let (_, pub_key_b64) = test_pub_key();

    let body = register_body("test-name", &pub_key_b64, &Uuid::new_v4().to_string(), 0);
    let app = test_app(state);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/register")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("unknown challenge_id")
    );
}

#[tokio::test]
async fn register_returns_400_for_expired_challenge() {
    let (state, mocks) = test_state();
    let (_, pub_key_b64) = test_pub_key();

    let now = Utc::now();
    let expired = RegistrationChallenge {
        id: Uuid::new_v4().to_string(),
        nonce: hex::encode([1u8; 32]),
        difficulty: 0,
        remote_ip: "127.0.0.1".to_string(),
        created_at: now - chrono::Duration::minutes(10),
        expires_at: now - chrono::Duration::minutes(1),
        used_at: None,
    };
    mocks.challenges.insert(&expired).await.unwrap();

    let body = register_body("test-name", &pub_key_b64, &expired.id, 0);
    let app = test_app(state);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/register")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert!(json["error"].as_str().unwrap().contains("expired"));
}

#[tokio::test]
async fn register_returns_400_when_challenge_issued_to_different_ip() {
    let (state, mocks) = test_state();
    let (_, pub_key_b64) = test_pub_key();

    let now = Utc::now();
    let challenge = RegistrationChallenge {
        id: Uuid::new_v4().to_string(),
        nonce: hex::encode([2u8; 32]),
        difficulty: 0,
        remote_ip: "9.9.9.9".to_string(),
        created_at: now,
        expires_at: now + chrono::Duration::minutes(5),
        used_at: None,
    };
    mocks.challenges.insert(&challenge).await.unwrap();

    let body = register_body("test-name", &pub_key_b64, &challenge.id, 0);
    let app = test_app(state);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/register")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert!(
        json["error"].as_str().unwrap().contains("IP"),
        "error should mention IP address"
    );
}

#[tokio::test]
async fn register_returns_400_for_failing_pow_proof() {
    let (state, mocks) = test_state();
    let (_, pub_key_b64) = test_pub_key();

    let now = Utc::now();
    let challenge = RegistrationChallenge {
        id: Uuid::new_v4().to_string(),
        nonce: hex::encode([3u8; 32]),
        difficulty: 24,
        remote_ip: "127.0.0.1".to_string(),
        created_at: now,
        expires_at: now + chrono::Duration::minutes(5),
        used_at: None,
    };
    mocks.challenges.insert(&challenge).await.unwrap();

    let body = register_body("test-name", &pub_key_b64, &challenge.id, 0);
    let app = test_app(state);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/register")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert!(json["error"].as_str().unwrap().contains("proof-of-work"));
}

#[tokio::test]
async fn register_returns_409_when_name_is_taken() {
    let (state, mocks) = test_state();
    claim_name(&mocks, "happy-einstein").await;
    let challenge = insert_easy_challenge(&mocks, "127.0.0.1").await;
    let (_, pub_key_b64) = test_pub_key();

    let body = register_body("happy-einstein", &pub_key_b64, &challenge.id, 0);
    let app = test_app(state);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/register")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert!(json["error"].as_str().unwrap().contains("taken"));
}

#[tokio::test]
async fn register_rolls_back_challenge_when_insert_fails() {
    // The registration transaction inserts the identity AND burns the challenge.
    // If the insert fails, the burn must roll back so the challenge stays usable —
    // there is no compensating saga, it's one atomic transaction.
    let store: ChallengeStore = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let identity = Arc::new(MockIdentityRepository::failing_register(Arc::clone(&store)));
    let challenges = Arc::new(MockChallengeRepository::new(Arc::clone(&store)));
    let config = test_config();
    let signer =
        token::Signer::from_pem(jwt_keypair_pem(JWT_TEST_SEED).0.as_bytes(), None).unwrap();
    let tenants = Arc::new(TenantsService::new(
        Arc::clone(&identity) as Arc<dyn IdentityRepository>,
        Arc::clone(&challenges) as Arc<dyn ChallengeRepository>,
        signer,
    ));
    let state = AppState::new(config, tenants, test_jwt_verifier());

    let now = Utc::now();
    let challenge = RegistrationChallenge {
        id: Uuid::new_v4().to_string(),
        nonce: hex::encode([7u8; 32]),
        difficulty: 0,
        remote_ip: "127.0.0.1".to_string(),
        created_at: now,
        expires_at: now + chrono::Duration::minutes(5),
        used_at: None,
    };
    challenges.insert(&challenge).await.unwrap();
    let (_, pub_key_b64) = test_pub_key();
    let body = register_body("happy-einstein", &pub_key_b64, &challenge.id, 0);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/register")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = test_app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // The challenge must be un-burned (the transaction rolled back).
    assert!(
        challenges
            .find_by_id(&challenge.id)
            .await
            .unwrap()
            .unwrap()
            .used_at
            .is_none(),
        "a failed insert must roll back the challenge burn"
    );
}

#[tokio::test]
async fn register_returns_400_when_challenge_already_used() {
    let (state, mocks) = test_state();
    let challenge = insert_easy_challenge(&mocks, "127.0.0.1").await;
    let (_, pub_key_b64) = test_pub_key();

    // First registration burns the challenge.
    let first = register_body("first-name", &pub_key_b64, &challenge.id, 0);
    let resp = test_app(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/register")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&first).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Reusing it (with a different name) is rejected as already-used.
    let second = register_body("second-name", &pub_key_b64, &challenge.id, 0);
    let resp = test_app(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/register")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&second).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("already been used")
    );
    // The losing name was never allocated.
    assert!(!mocks.identity.is_name_taken("second-name").await.unwrap());
}

#[tokio::test]
async fn register_returns_429_when_rate_limit_reached() {
    let (state, mocks) = test_state();

    for _ in 0..3 {
        mocks
            .identity
            .log_registration("127.0.0.1", Utc::now())
            .await
            .unwrap();
    }

    let challenge = insert_easy_challenge(&mocks, "127.0.0.1").await;
    let (_, pub_key_b64) = test_pub_key();
    let body = register_body("test-name", &pub_key_b64, &challenge.id, 0);

    let app = test_app(state);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/register")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

// ── Auth middleware ──────────────────────────────────────────────────────────
//
// Tenants accepts BOTH credential paths. The opaque-bearer tests below exercise
// the DB-lookup path; the `jwt_path_*` tests exercise the offline-verify path.

#[tokio::test]
async fn auth_rejects_body_over_1_mib() {
    let (state, mocks) = test_state();
    let (install, raw_token) = insert_test_install(&mocks, "test-node").await;

    let app = test_app(state);
    let oversized = vec![b'x'; 1024 * 1024 + 1];
    let timestamp = Utc::now().timestamp();
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/installs/{}/token", install.id))
        .header("Authorization", format!("Bearer {raw_token}"))
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
    let (state, _mocks) = test_state();
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
    let (state, mocks) = test_state();
    let (install, _raw_token) = insert_test_install(&mocks, "test-node").await;

    let app = test_app(state);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/installs/{}/token", install.id))
        .header("Authorization", "Token not-bearer")
        .header("X-Wardnet-Timestamp", Utc::now().timestamp().to_string())
        .header("X-Wardnet-Signature", "dGVzdA==")
        .header("Content-Type", "application/json")
        .body(Body::empty())
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
async fn auth_returns_401_for_unknown_bearer_token() {
    let (state, mocks) = test_state();
    let (install, _) = insert_test_install(&mocks, "test-node").await;

    let app = test_app(state);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/installs/{}/token", install.id))
        .header("Authorization", "Bearer unknowntoken")
        .header("X-Wardnet-Timestamp", Utc::now().timestamp().to_string())
        .header("X-Wardnet-Signature", "dGVzdA==")
        .header("Content-Type", "application/json")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert_eq!(json["error"], "unknown bearer token");
}

#[tokio::test]
async fn auth_returns_401_when_timestamp_header_is_absent() {
    let (state, mocks) = test_state();
    let (install, raw_token) = insert_test_install(&mocks, "test-node").await;

    let app = test_app(state);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/installs/{}/token", install.id))
        .header("Authorization", format!("Bearer {raw_token}"))
        .header("X-Wardnet-Signature", "dGVzdA==")
        .header("Content-Type", "application/json")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert!(json["error"].as_str().unwrap().contains("Timestamp"));
}

#[tokio::test]
async fn auth_returns_401_when_timestamp_is_not_a_number() {
    let (state, mocks) = test_state();
    let (install, raw_token) = insert_test_install(&mocks, "test-node").await;

    let app = test_app(state);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/installs/{}/token", install.id))
        .header("Authorization", format!("Bearer {raw_token}"))
        .header("X-Wardnet-Timestamp", "not-a-number")
        .header("X-Wardnet-Signature", "dGVzdA==")
        .header("Content-Type", "application/json")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_returns_401_when_timestamp_is_stale() {
    let (state, mocks) = test_state();
    let (install, raw_token) = insert_test_install(&mocks, "test-node").await;

    let app = test_app(state);
    let past_ts = Utc::now().timestamp() - 120;
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/installs/{}/token", install.id))
        .header("Authorization", format!("Bearer {raw_token}"))
        .header("X-Wardnet-Timestamp", past_ts.to_string())
        .header("X-Wardnet-Signature", "dGVzdA==")
        .header("Content-Type", "application/json")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert!(json["error"].as_str().unwrap().contains("window"));
}

#[tokio::test]
async fn auth_returns_401_for_invalid_signature() {
    let (state, mocks) = test_state();
    let (install, raw_token) = insert_test_install(&mocks, "test-node").await;

    let app = test_app(state);
    let bad_sig = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/installs/{}/token", install.id))
        .header("Authorization", format!("Bearer {raw_token}"))
        .header("X-Wardnet-Timestamp", Utc::now().timestamp().to_string())
        .header("X-Wardnet-Signature", bad_sig)
        .header("Content-Type", "application/json")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    assert!(json["error"].as_str().unwrap().contains("signature"));
}

#[tokio::test]
async fn auth_returns_401_when_signature_base64_is_invalid() {
    let (state, mocks) = test_state();
    let (install, raw_token) = insert_test_install(&mocks, "test-node").await;

    let app = test_app(state);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/installs/{}/token", install.id))
        .header("Authorization", format!("Bearer {raw_token}"))
        .header("X-Wardnet-Timestamp", Utc::now().timestamp().to_string())
        .header("X-Wardnet-Signature", "not!valid!base64!!!")
        .header("Content-Type", "application/json")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_returns_401_on_replayed_request() {
    let (state, mocks) = test_state();
    let (install, raw_token) = insert_test_install(&mocks, "test-node").await;
    let signing_key = test_signing_key();

    let timestamp = Utc::now().timestamp();
    let body = b"";
    let path = format!("/v1/installs/{}/token", install.id);

    let app = test_app(state);

    let req1 = signed_request_at("POST", &path, body, &raw_token, &signing_key, timestamp);
    let resp1 = app.clone().oneshot(req1).await.unwrap();
    assert_eq!(
        resp1.status(),
        StatusCode::OK,
        "first signed request should succeed"
    );

    let req2 = signed_request_at("POST", &path, body, &raw_token, &signing_key, timestamp);
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

// ── Identity-JWT credential path ───────────────────────────────────────────────
// The opaque-bearer path above keeps working unchanged; these cover the JWT path,
// which Tenants also accepts.

#[tokio::test]
async fn jwt_path_accepts_valid_token_with_pop_and_no_db_lookup() {
    // The identity must be active for `refresh_token` to mint a fresh JWT, but the
    // JWT path authenticates OFFLINE (the auth layer does no DB lookup).
    let (state, mocks) = test_state();
    let (install, _raw_token) = insert_test_install(&mocks, "happy-node").await;
    let jwt = test_identity_jwt(&install.id, "happy-node", 3600);
    let signing_key = test_signing_key(); // its public key == the JWT's `cnf`

    let path = format!("/v1/installs/{}/token", install.id);
    let req = signed_request("POST", &path, b"", &jwt, &signing_key);
    let resp = test_app(state).oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a valid JWT + PoP should authenticate with no DB lookup"
    );
}

#[tokio::test]
async fn jwt_path_rejects_expired_token() {
    let (state, _mocks) = test_state();
    let jwt = test_identity_jwt("inst-jwt-2", "happy-node", -120); // exp in the past
    let req = signed_request(
        "POST",
        "/v1/installs/inst-jwt-2/token",
        b"",
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
async fn jwt_path_rejects_tampered_token() {
    let (state, _mocks) = test_state();
    let mut jwt = test_identity_jwt("inst-jwt-3", "happy-node", 3600);
    // Flip the last character of the signature segment.
    let last = jwt.pop().unwrap();
    jwt.push(if last == 'A' { 'B' } else { 'A' });
    let req = signed_request(
        "POST",
        "/v1/installs/inst-jwt-3/token",
        b"",
        &jwt,
        &test_signing_key(),
    );
    let resp = test_app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_path_rejects_token_from_a_foreign_signer() {
    // A JWT signed by a key the AppState verifier does not trust.
    let (state, _mocks) = test_state();
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
    let req = signed_request(
        "POST",
        "/v1/installs/inst-jwt-4/token",
        b"",
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
    let (state, _mocks) = test_state();
    let jwt = test_identity_jwt("inst-jwt-5", "happy-node", 3600);
    let attacker_key = SigningKey::from_bytes(&[9u8; 32]);
    let req = signed_request(
        "POST",
        "/v1/installs/inst-jwt-5/token",
        b"",
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
async fn jwt_path_enforces_replay() {
    let (state, mocks) = test_state();
    let (install, _raw_token) = insert_test_install(&mocks, "happy-node").await;
    let jwt = test_identity_jwt(&install.id, "happy-node", 3600);
    let signing_key = test_signing_key();
    let ts = Utc::now().timestamp();
    let path = format!("/v1/installs/{}/token", install.id);
    let app = test_app(state);

    let req1 = signed_request_at("POST", &path, b"", &jwt, &signing_key, ts);
    assert_eq!(
        app.clone().oneshot(req1).await.unwrap().status(),
        StatusCode::OK
    );
    let req2 = signed_request_at("POST", &path, b"", &jwt, &signing_key, ts);
    let resp2 = app.oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::UNAUTHORIZED);
    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp2.into_body()).await).unwrap();
    assert!(json["error"].as_str().unwrap().contains("replay"));
}

#[tokio::test]
async fn auth_missing_from_authenticated_endpoint_returns_401() {
    let (state, mocks) = test_state();
    let (install, _) = insert_test_install(&mocks, "test-node").await;

    let app = test_app(state);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/installs/{}/token", install.id))
        .header("Content-Type", "application/json")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn deregistered_identity_cannot_authenticate() {
    // The `status = 'active'` filter in find_by_token_hash must reject a
    // tombstoned identity on the opaque-bearer path.
    let (state, mocks) = test_state();
    let (raw_token, token_hash) = test_bearer_token();
    let (pub_key_bytes, public_key) = test_pub_key();
    mocks.identity.seed(Identity {
        id: Uuid::new_v4().to_string(),
        name: "gone-node".to_string(),
        region: "test".to_string(),
        public_key,
        pub_key_bytes,
        token_hash,
        status: Status::Deregistered,
        created_at: Utc::now(),
    });
    let signing_key = test_signing_key();
    let req = signed_request(
        "POST",
        "/v1/installs/whatever/token",
        b"",
        &raw_token,
        &signing_key,
    );
    let resp = test_app(state).oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "a deregistered (tombstoned) identity must not authenticate"
    );
}

// ── Token refresh endpoint ───────────────────────────────────────────────────

#[tokio::test]
async fn refresh_token_returns_a_fresh_verifiable_jwt() {
    let (state, mocks) = test_state();
    let (install, raw_token) = insert_test_install(&mocks, "fresh-node").await;
    let signing_key = test_signing_key();
    let (_, pub_key_b64) = test_pub_key();

    let path = format!("/v1/installs/{}/token", install.id);
    let req = signed_request("POST", &path, b"", &raw_token, &signing_key);
    let resp = test_app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json: serde_json::Value =
        serde_json::from_str(&body_string(resp.into_body()).await).unwrap();
    let jwt = json["identity_jwt"]
        .as_str()
        .expect("must return an identity_jwt");

    // The refreshed JWT verifies against the Tenants key and re-asserts identity.
    let claims = test_jwt_verifier()
        .verify(jwt)
        .expect("refreshed JWT must verify");
    assert_eq!(claims.iss, "tenants");
    assert_eq!(claims.sub, install.id);
    assert_eq!(claims.vanity, "fresh-node");
    assert_eq!(
        claims.cnf.ed25519, pub_key_b64,
        "cnf stays the daemon's own public key (sender-constrained)"
    );
}

#[tokio::test]
async fn refresh_token_returns_401_without_credentials() {
    let (state, mocks) = test_state();
    let (install, _raw_token) = insert_test_install(&mocks, "noauth-node").await;

    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/installs/{}/token", install.id))
        .body(Body::empty())
        .unwrap();
    let resp = test_app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_token_returns_403_when_install_id_does_not_match() {
    let (state, mocks) = test_state();
    let (_, raw_token) = insert_test_install(&mocks, "owner-node").await;
    let signing_key = test_signing_key();

    let other_id = Uuid::new_v4().to_string();
    let path = format!("/v1/installs/{other_id}/token");
    let req = signed_request("POST", &path, b"", &raw_token, &signing_key);
    let resp = test_app(state).oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a credential may only refresh its own install's token"
    );
}

#[tokio::test]
async fn refresh_token_returns_403_for_a_tombstoned_install() {
    // The revocation-completion path: a deregistered install may still hold an
    // unexpired identity JWT, so it authenticates OFFLINE (no DB lookup). The
    // refresh handler re-checks liveness by loading the active identity by id —
    // the tombstone fails that check, so no fresh token is issued and access
    // ends when the held JWT expires.
    let (state, mocks) = test_state();
    let id = "tombstoned-inst";
    let (pub_key_bytes, public_key) = test_pub_key();
    mocks.identity.seed(Identity {
        id: id.to_string(),
        name: "gone-node".to_string(),
        region: "test".to_string(),
        public_key,
        pub_key_bytes,
        token_hash: "unused".to_string(),
        status: Status::Deregistered,
        created_at: Utc::now(),
    });

    // Authenticate with a still-valid JWT (offline verify ignores the tombstone).
    let jwt = test_identity_jwt(id, "gone-node", 3600);
    let path = format!("/v1/installs/{id}/token");
    let req = signed_request("POST", &path, b"", &jwt, &test_signing_key());
    let resp = test_app(state).oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a tombstoned install must not be able to refresh its token"
    );
}

// ── Deregister endpoint (tombstone-only) ─────────────────────────────────────
//
// Deregistration is now tombstone-only: it flips the identity status to
// `deregistered` and performs NO DNS work (regional DNS teardown is the DDNS
// reaper's job, driven off the mesh introspect endpoint). The tests below assert
// the identity is gone from the active view and reported inactive — never DNS.

#[tokio::test]
async fn deregister_returns_204_and_tombstones_identity() {
    let (state, mocks) = test_state();
    let (install, raw_token) = insert_test_install(&mocks, "test-node").await;
    let signing_key = test_signing_key();

    let path = format!("/v1/installs/{}", install.id);
    let req = signed_request("DELETE", &path, b"", &raw_token, &signing_key);

    let resp = test_app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // The identity is tombstoned: it no longer resolves through the active filter.
    assert!(
        mocks
            .identity
            .find_by_id(&install.id)
            .await
            .unwrap()
            .is_none(),
        "a tombstoned identity must not resolve through the active filter"
    );
}

#[tokio::test]
async fn deregister_returns_403_when_install_id_does_not_match() {
    let (state, mocks) = test_state();
    let (_, raw_token) = insert_test_install(&mocks, "test-node").await;
    let signing_key = test_signing_key();

    let other_id = Uuid::new_v4().to_string();
    let path = format!("/v1/installs/{other_id}");
    let req = signed_request("DELETE", &path, b"", &raw_token, &signing_key);

    let resp = test_app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn deregister_tombstones_the_identity_but_keeps_the_name() {
    // Deregister flips the identity to a tombstone (status → deregistered): the
    // find_by_id active filter no longer returns it, yet the row and its UNIQUE
    // name allocation survive (find_inactive/introspection still see it). No DNS
    // work happens here — that is the DDNS reaper's job.
    let (state, mocks) = test_state();
    let (install, raw_token) = insert_test_install(&mocks, "test-node").await;
    let signing_key = test_signing_key();

    let path = format!("/v1/installs/{}", install.id);
    let req = signed_request("DELETE", &path, b"", &raw_token, &signing_key);
    let resp = test_app(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    assert!(
        mocks
            .identity
            .find_by_id(&install.id)
            .await
            .unwrap()
            .is_none(),
        "a tombstoned identity must not resolve through the active filter"
    );
    assert!(
        mocks.identity.is_name_taken("test-node").await.unwrap(),
        "the name allocation survives the tombstone"
    );
    let inactive = mocks
        .identity
        .find_inactive(std::slice::from_ref(&install.id))
        .await
        .unwrap();
    assert_eq!(
        inactive,
        vec![install.id],
        "the tombstone is reported inactive"
    );
}
