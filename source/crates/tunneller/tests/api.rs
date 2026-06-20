//! HTTP-level integration tests against a live, mock-backed server: the daemon
//! tunnel upgrade and caller-type / network-scope / routing-policy enforcement.
//!
//! These run against a real bound `axum::serve` listener (not bare `oneshot`)
//! because the `WebSocketUpgrade` extractor needs a genuine connection to upgrade —
//! so the eligible case can return `101`, proving the upgrade survives the
//! `authenticate(DAEMON)` middleware **and** the routing policy. Requests are spoken
//! as raw HTTP/1.1 so a custom signature + WS handshake headers can be attached.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use wardnet_common::contract::{ProvisioningState, SubscriptionStatus};
use wardnet_common::token::{ClaimsSpec, PrincipalType, canonical_request_payload};
use wardnet_tunneller::api;
use wardnet_tunneller::mesh::TenantsResolver;
use wardnet_tunneller::repository::TunnelRouteRepository;
use wardnet_tunneller::test_helpers::{
    InMemoryRoutes, MockTenants, build_state, daemon_keypair, network_view, tenant_view,
    test_signer,
};
use wardnet_tunneller::tunnel::TunnelRegistry;

const SEED: u8 = 7;
const TENANT: &str = "tenant-1";
const NETWORK: &str = "net-1";
const SLUG: &str = "alice";

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Mint a daemon JWT. `network` is the `net` claim (None ⇒ tenant-scoped). `aud`
/// follows the lifecycle (ADR-0008): tenant-scoped → `[tenants]` (rejected here, as
/// `tunneller` is absent), network-scoped → the full mesh.
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

fn sign(key: &SigningKey, ts: i64) -> String {
    let hash = hex::encode(Sha256::digest(b""));
    let payload = canonical_request_payload("GET", "/v1/tunnel", ts, &hash);
    base64::engine::general_purpose::STANDARD.encode(key.sign(payload.as_bytes()).to_bytes())
}

fn app_with(tenants: MockTenants) -> Router {
    let registry = Arc::new(TunnelRegistry::new());
    let routes: Arc<dyn TunnelRouteRepository> = Arc::new(InMemoryRoutes::new());
    let tenants: Arc<dyn TenantsResolver> = Arc::new(tenants);
    api::router(build_state(SEED, registry, routes, tenants))
}

/// Serve `app` on an ephemeral port and return its address.
async fn spawn(app: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Send a raw HTTP/1.1 GET and return the response status code.
async fn get_status(addr: SocketAddr, path: &str, headers: &[(&str, String)]) -> u16 {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: tunneller.test\r\n");
    for (k, v) in headers {
        req.push_str(k);
        req.push_str(": ");
        req.push_str(v);
        req.push_str("\r\n");
    }
    req.push_str("Content-Length: 0\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let status_line = std::str::from_utf8(&buf[..n])
        .unwrap()
        .lines()
        .next()
        .unwrap();
    status_line
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

/// The signed WebSocket-upgrade headers for `GET /v1/tunnel`.
fn tunnel_headers(key: &SigningKey, bearer: Option<&str>) -> Vec<(&'static str, String)> {
    let ts = now();
    let mut h = vec![
        ("X-Wardnet-Timestamp", ts.to_string()),
        ("X-Wardnet-Signature", sign(key, ts)),
        ("Connection", "upgrade".to_string()),
        ("Upgrade", "websocket".to_string()),
        ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==".to_string()),
        ("Sec-WebSocket-Version", "13".to_string()),
    ];
    if let Some(token) = bearer {
        h.push(("Authorization", format!("Bearer {token}")));
    }
    h
}

/// A `MockTenants` with an active network + tenant for the happy path.
fn eligible_tenants() -> MockTenants {
    let t = MockTenants::new();
    t.seed_network(network_view(
        NETWORK,
        SLUG,
        TENANT,
        ProvisioningState::Active,
    ));
    t.seed_tenant(tenant_view(TENANT, SubscriptionStatus::Active));
    t
}

#[tokio::test]
async fn health_is_open() {
    let addr = spawn(app_with(MockTenants::new())).await;
    assert_eq!(get_status(addr, "/v1/health", &[]).await, 200);
}

#[tokio::test]
async fn tunnel_requires_auth() {
    let addr = spawn(app_with(MockTenants::new())).await;
    // No bearer / signature → the auth middleware rejects before extraction.
    assert_eq!(get_status(addr, "/v1/tunnel", &[]).await, 401);
}

#[tokio::test]
async fn tunnel_rejects_tenant_scoped_token() {
    let addr = spawn(app_with(eligible_tenants())).await;
    let (key, cnf) = daemon_keypair(11);
    let token = daemon_token(&cnf, None); // no `net` → aud = [tenants], omits `tunneller`
    // `aud` closes it at the verifier (401) before the handler's network-scope check
    // (ADR-0008): a not-yet-network-bound daemon has no reach into the data plane.
    assert_eq!(
        get_status(addr, "/v1/tunnel", &tunnel_headers(&key, Some(&token))).await,
        401
    );
}

#[tokio::test]
async fn tunnel_rejects_unknown_network() {
    let addr = spawn(app_with(MockTenants::new())).await; // nothing seeded
    let (key, cnf) = daemon_keypair(11);
    let token = daemon_token(&cnf, Some(NETWORK));
    assert_eq!(
        get_status(addr, "/v1/tunnel", &tunnel_headers(&key, Some(&token))).await,
        403
    );
}

#[tokio::test]
async fn tunnel_rejects_deprovisioning_network() {
    let t = MockTenants::new();
    t.seed_network(network_view(
        NETWORK,
        SLUG,
        TENANT,
        ProvisioningState::Deprovisioning,
    ));
    t.seed_tenant(tenant_view(TENANT, SubscriptionStatus::Active));
    let addr = spawn(app_with(t)).await;

    let (key, cnf) = daemon_keypair(11);
    let token = daemon_token(&cnf, Some(NETWORK));
    assert_eq!(
        get_status(addr, "/v1/tunnel", &tunnel_headers(&key, Some(&token))).await,
        403
    );
}

#[tokio::test]
async fn tunnel_rejects_inactive_subscription() {
    let t = MockTenants::new();
    t.seed_network(network_view(
        NETWORK,
        SLUG,
        TENANT,
        ProvisioningState::Active,
    ));
    t.seed_tenant(tenant_view(TENANT, SubscriptionStatus::Canceled));
    let addr = spawn(app_with(t)).await;

    let (key, cnf) = daemon_keypair(11);
    let token = daemon_token(&cnf, Some(NETWORK));
    assert_eq!(
        get_status(addr, "/v1/tunnel", &tunnel_headers(&key, Some(&token))).await,
        403
    );
}

#[tokio::test]
async fn tunnel_upgrades_for_eligible_network() {
    let addr = spawn(app_with(eligible_tenants())).await;
    let (key, cnf) = daemon_keypair(11);
    let token = daemon_token(&cnf, Some(NETWORK));
    // The WebSocket upgrade survives the auth middleware + routing policy → 101.
    assert_eq!(
        get_status(addr, "/v1/tunnel", &tunnel_headers(&key, Some(&token))).await,
        101
    );
}
