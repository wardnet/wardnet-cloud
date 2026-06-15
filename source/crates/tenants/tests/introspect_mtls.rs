//! Mutual-TLS round-trip test for the mesh introspect listener.
//!
//! `POST /v1/introspect` is served over mutual TLS on the internal mesh listener
//! and carries **no** auth layer — mTLS *is* the authentication. These tests mint a
//! throwaway mesh CA with `rcgen` (a self-signed CA plus `server_auth` /
//! `client_auth` leaves), wrap [`wardnet_tenants::mesh::introspect_router`] in a
//! `tokio_rustls::TlsAcceptor` built from
//! [`wardnet_common::mtls::server_config_from_pem`], and drive it with a `reqwest`
//! client configured for client-certificate auth.
//!
//! - Test 1 (happy path): a client cert chained to the same CA completes the
//!   handshake and the endpoint returns the expected `inactive` set.
//! - Test 2 (foreign cert rejected): a client cert from a *different* CA fails the
//!   handshake — the request errors rather than returning a `200`.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use common::{ChallengeStore, MockChallengeRepository, MockIdentityRepository, jwt_keypair_pem};
use wardnet_common::{mtls, serve, token};
use wardnet_tenants::config::Config;
use wardnet_tenants::repository::{ChallengeRepository, Identity, IdentityRepository, Status};
use wardnet_tenants::service::TenantsService;
use wardnet_tenants::state::AppState;

const JWT_TEST_SEED: u8 = 7;

// ── Throwaway mesh PKI (local rcgen equivalent of common's `TestMeshCa`) ───────

/// A self-signed CA that signs `server_auth` / `client_auth` leaves. A leaf from a
/// *different* `MeshCa` is the foreign-cert rejection case. `TestMeshCa` in
/// `wardnet_common::test_helpers` is `cfg(test)`-private, so this is a small local
/// reimplementation over `rcgen`.
struct MeshCa {
    issuer: Issuer<'static, KeyPair>,
    root_pem: String,
}

/// A leaf certificate + its private key, in PEM.
struct Leaf {
    cert_pem: String,
    key_pem: String,
}

impl MeshCa {
    fn new() -> Self {
        let key = KeyPair::generate().expect("generate CA key");
        let mut params = CertificateParams::new(Vec::new()).expect("CA params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let root = params.self_signed(&key).expect("self-sign CA root");
        let root_pem = root.pem();
        Self {
            issuer: Issuer::new(params, key),
            root_pem,
        }
    }

    fn root_pem(&self) -> &str {
        &self.root_pem
    }

    fn leaf(&self, fqdn: &str, eku: ExtendedKeyUsagePurpose) -> Leaf {
        let key = KeyPair::generate().expect("generate leaf key");
        let mut params = CertificateParams::new(vec![fqdn.to_owned()]).expect("leaf params");
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![eku];
        let cert = params.signed_by(&key, &self.issuer).expect("sign leaf");
        Leaf {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }
}

// ── Tenants state fixture (identity mock reports some ids inactive) ────────────

/// Build a Tenants `AppState` and seed an active + a tombstoned identity; returns
/// the state plus `(active_id, dead_id)`.
fn build_state() -> (AppState, String, String) {
    let store: ChallengeStore = Arc::new(Mutex::new(HashMap::new()));
    let identity = Arc::new(MockIdentityRepository::new(Arc::clone(&store)));
    let challenges = Arc::new(MockChallengeRepository::new(Arc::clone(&store)));

    let active_id = "active-install".to_string();
    let dead_id = "dead-install".to_string();
    identity.seed(seed_identity(&active_id, "live-node", Status::Active));
    identity.seed(seed_identity(&dead_id, "dead-node", Status::Deregistered));

    let signer =
        token::Signer::from_pem(jwt_keypair_pem(JWT_TEST_SEED).0.as_bytes(), None).unwrap();
    let verifier = token::Verifier::from_pem(jwt_keypair_pem(JWT_TEST_SEED).1.as_bytes()).unwrap();
    let tenants = Arc::new(TenantsService::new(
        Arc::clone(&identity) as Arc<dyn IdentityRepository>,
        Arc::clone(&challenges) as Arc<dyn ChallengeRepository>,
        signer,
    ));
    let state = AppState::new(test_config(), tenants, verifier);
    (state, active_id, dead_id)
}

fn seed_identity(id: &str, name: &str, status: Status) -> Identity {
    Identity {
        id: id.to_string(),
        name: name.to_string(),
        region: "test".to_string(),
        public_key: String::new(),
        pub_key_bytes: [0u8; 32],
        token_hash: format!("hash-{id}"),
        status,
        created_at: chrono::Utc::now(),
    }
}

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

/// Spawn the mesh introspect router behind a `TlsAcceptor` bound to an ephemeral
/// port, accepting exactly one connection. Returns the bound address. This mirrors
/// `serve_introspect` without the file-path PEM constraint (it wraps
/// `introspect_router` directly, as the task suggests).
async fn spawn_introspect_once(
    state: AppState,
    server: &Leaf,
    ca_pem: &str,
) -> std::net::SocketAddr {
    let server_config = mtls::server_config_from_pem(
        server.cert_pem.as_bytes(),
        server.key_pem.as_bytes(),
        ca_pem.as_bytes(),
    )
    .expect("build mesh server config");
    let acceptor = TlsAcceptor::from(server_config);
    let router = wardnet_tenants::mesh::introspect_router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.expect("accept introspect conn");
        match acceptor.accept(stream).await {
            Ok(tls) => {
                let _ = serve::connection(tls, router, peer).await;
            }
            Err(e) => {
                // A foreign / missing client cert is rejected here at the handshake —
                // the mesh authentication boundary.
                tracing::debug!(error = %e, "introspect mTLS handshake rejected");
            }
        }
    });

    addr
}

/// SAN both leaves use; `reqwest` verifies the server cert against this name, so the
/// client addresses the server by it (resolved to the ephemeral `addr`).
const SERVER_NAME: &str = "tenants.mesh.local";

/// Build a `reqwest` client that presents `client` as its identity, trusts only
/// `ca_pem`, and resolves [`SERVER_NAME`] to `addr` (so the URL host can be the
/// cert's SAN while the socket connects to the ephemeral test port).
fn mesh_client(client: &Leaf, ca_pem: &str, addr: std::net::SocketAddr) -> reqwest::Client {
    let mut identity_pem = client.cert_pem.clone();
    identity_pem.push_str(&client.key_pem);
    let identity =
        reqwest::Identity::from_pem(identity_pem.as_bytes()).expect("build client identity");
    let ca = reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("parse CA");

    reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .identity(identity)
        .resolve(SERVER_NAME, addr)
        .build()
        .expect("build mesh reqwest client")
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn introspect_over_mtls_returns_inactive_subset() {
    mtls::install_crypto_provider();
    let ca = MeshCa::new();
    let server = ca.leaf(SERVER_NAME, ExtendedKeyUsagePurpose::ServerAuth);
    let client = ca.leaf("reaper.mesh.local", ExtendedKeyUsagePurpose::ClientAuth);

    let (state, active_id, dead_id) = build_state();
    let addr = spawn_introspect_once(state, &server, ca.root_pem()).await;

    let http = mesh_client(&client, ca.root_pem(), addr);
    let url = format!("https://{SERVER_NAME}/v1/introspect");
    let body = serde_json::json!({
        "install_ids": [active_id, dead_id, "never-registered"],
    });

    let resp = http
        .post(&url)
        .json(&body)
        .send()
        .await
        .expect("introspect request should complete over mTLS");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let json: serde_json::Value = resp.json().await.unwrap();
    let inactive: Vec<String> = json["inactive"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    assert!(!inactive.contains(&active_id), "active id must be excluded");
    assert!(
        inactive.contains(&dead_id),
        "tombstoned id must be inactive"
    );
    assert!(
        inactive.contains(&"never-registered".to_string()),
        "absent id must be inactive"
    );
    assert_eq!(inactive.len(), 2);
}

#[tokio::test]
async fn introspect_rejects_client_cert_from_a_foreign_ca() {
    mtls::install_crypto_provider();
    let server_ca = MeshCa::new();
    let foreign_ca = MeshCa::new();

    let server = server_ca.leaf(SERVER_NAME, ExtendedKeyUsagePurpose::ServerAuth);
    // Client identity minted by a DIFFERENT CA — must fail the handshake.
    let foreign_client =
        foreign_ca.leaf("attacker.mesh.local", ExtendedKeyUsagePurpose::ClientAuth);

    let (state, _active, _dead) = build_state();
    let addr = spawn_introspect_once(state, &server, server_ca.root_pem()).await;

    // The client trusts the (correct) server CA so the *server* cert verifies, but
    // it presents a foreign client identity the server's verifier rejects.
    let http = mesh_client(&foreign_client, server_ca.root_pem(), addr);
    let url = format!("https://{SERVER_NAME}/v1/introspect");
    let body = serde_json::json!({ "install_ids": ["whatever"] });

    let result = http.post(&url).json(&body).send().await;

    assert!(
        result.is_err(),
        "a client cert from a foreign CA must fail the mTLS handshake, not return a response"
    );
}
